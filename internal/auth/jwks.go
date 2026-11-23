package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwksCacheTTL          = 1 * time.Hour
	jwksUnknownKidCooloff = 60 * time.Second
	jwksMaxRespBytes      = 256 << 10
	jwksHTTPTimeout       = 10 * time.Second
	maxJWTBytes           = 8 << 10
	minRSABits            = 2048
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksRefreshCall struct {
	done chan struct{}
	err  error
}

type JWKSCache struct {
	url    string
	client *http.Client

	mu                 sync.RWMutex
	keys               map[string]any
	fetchedAt          time.Time
	lastRefreshAttempt time.Time
	inflight           *jwksRefreshCall
}

func NewJWKSCache(jwksURL string, client *http.Client) *JWKSCache {
	if client == nil {
		client = &http.Client{Timeout: jwksHTTPTimeout}
	}
	return &JWKSCache{
		url:    jwksURL,
		client: client,
		keys:   make(map[string]any),
	}
}

func (c *JWKSCache) GetKey(ctx context.Context, kid string) (any, error) {
	if kid == "" {
		return nil, errors.New("jwt missing kid header")
	}

	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < jwksCacheTTL
	c.mu.RUnlock()

	if ok && fresh {
		return k, nil
	}

	// Throttle repeated refreshes triggered by unknown kids OR post-failure retries,
	// regardless of whether the cache is currently fresh or stale/empty.
	throttled := !ok
	if err := c.refresh(ctx, throttled); err != nil {
		if ok {
			return k, nil
		}
		return nil, err
	}

	c.mu.RLock()
	k, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("signing key %q not found in JWKS", kid)
	}
	return k, nil
}

func (c *JWKSCache) refresh(ctx context.Context, applyCooldown bool) error {
	c.mu.Lock()
	if call := c.inflight; call != nil {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if applyCooldown && !c.lastRefreshAttempt.IsZero() && time.Since(c.lastRefreshAttempt) < jwksUnknownKidCooloff {
		c.mu.Unlock()
		return errors.New("JWKS refresh throttled")
	}
	c.lastRefreshAttempt = time.Now()
	call := &jwksRefreshCall{done: make(chan struct{})}
	c.inflight = call
	c.mu.Unlock()

	go func() {
		// Use an independent bounded context so one caller canceling cannot poison
		// all coalesced waiters sharing this refresh.
		fetchCtx, cancel := context.WithTimeout(context.Background(), jwksHTTPTimeout)
		defer cancel()
		err := c.fetchOnce(fetchCtx)

		c.mu.Lock()
		call.err = err
		c.inflight = nil
		close(call.done)
		c.mu.Unlock()
	}()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *JWKSCache) fetchOnce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxRespBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	parsed := make(map[string]any, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		pub, err := parseJWKPublicKey(k)
		if err != nil {
			continue
		}
		parsed[k.Kid] = pub
	}
	if len(parsed) == 0 {
		return errors.New("JWKS contained no usable signing keys")
	}

	c.mu.Lock()
	c.keys = parsed
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *JWKSCache) VerifyJWT(ctx context.Context, rawToken string, allowedAlgs []string) (jwt.MapClaims, error) {
	if len(rawToken) == 0 || len(rawToken) > maxJWTBytes {
		return nil, errors.New("invalid JWT length")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithLeeway(10*time.Second),
		jwt.WithExpirationRequired(),
	)
	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
		for _, bad := range []string{"jku", "x5u", "jwk"} {
			if _, exists := t.Header[bad]; exists {
				return nil, fmt.Errorf("forbidden JWT header %q", bad)
			}
		}
		kid, _ := t.Header["kid"].(string)
		return c.GetKey(ctx, kid)
	})
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}
	return claims, nil
}

func parseJWKPublicKey(k jwkKey) (any, error) {
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("unsupported JWK use %q", k.Use)
	}
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(nb) == 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		n := new(big.Int).SetBytes(nb)
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key modulus too small (%d bits)", n.BitLen())
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e < 3 || e%2 == 0 {
			return nil, errors.New("invalid RSA exponent value")
		}
		return &rsa.PublicKey{N: n, E: e}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC key point not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}
