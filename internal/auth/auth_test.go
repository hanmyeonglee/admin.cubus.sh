package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/store"
)

func generateRSAJWK(t *testing.T, kid string) (*rsa.PrivateKey, map[string]any) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return priv, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, extraHdr map[string]any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	for k, v := range extraHdr {
		tok.Header[k] = v
	}
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCloudflareAccessJWTAndSecurityInvariants(t *testing.T) {
	priv, jwksDoc := generateRSAJWK(t, "cf-kid-1")
	var jwksHits atomic.Int32
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksHits.Add(1)
		_ = json.NewEncoder(w).Encode(jwksDoc)
	}))
	defer jwksSrv.Close()

	st := store.NewMemoryStore()
	cfg := config.Config{
		PublicBaseURL:      "https://admin.cubus.sh",
		PublicIsHTTPS:      true,
		AuthMode:           config.AuthModeCloudflare,
		AllowedEmails:      map[string]struct{}{"owner@cubus.sh": {}},
		CFAccessTeamDomain: "https://myteam.cloudflareaccess.com",
		CFAccessAUD:        "aud-expected",
	}
	authenticator, err := NewAuthenticator(context.Background(), cfg, st, AuthenticatorOptions{
		CFJWKSURLOverride: jwksSrv.URL,
		HTTPClient:        jwksSrv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	validJWT := signRS256(t, priv, "cf-kid-1", nil, jwt.MapClaims{
		"iss":   "https://myteam.cloudflareaccess.com",
		"aud":   []string{"aud-expected"},
		"email": "owner@cubus.sh",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	})

	// 1. Valid CF JWT succeeds and issues HMAC-bound __Host-admin_csrf cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", validJWT)
	p, _, err := authenticator.Authenticate(rec, req)
	if err != nil || p.Email != "owner@cubus.sh" || p.AuthMethod != "cloudflare" || p.CSRFToken == "" {
		t.Fatalf("expected valid CF auth, got p=%+v err=%v", p, err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "__Host-admin_csrf" {
		t.Fatalf("expected __Host-admin_csrf cookie, got %+v", cookies)
	}
	// Verify CSRF passes with cookie + matching token, fails without cookie.
	reqWithCookie := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	reqWithCookie.AddCookie(cookies[0])
	if !authenticator.VerifyCSRF(reqWithCookie, p, p.CSRFToken) {
		t.Fatal("expected valid HMAC CSRF verification")
	}
	if authenticator.VerifyCSRF(httptest.NewRequest(http.MethodPost, "/api/test", nil), p, p.CSRFToken) {
		t.Fatal("expected CSRF verification to fail without cookie")
	}

	// 2. Reject wrong audience, wrong issuer, expired, disallowed email, jku header, and alg=none.
	badTokens := []string{
		signRS256(t, priv, "cf-kid-1", nil, jwt.MapClaims{"iss": "https://myteam.cloudflareaccess.com", "aud": []string{"wrong"}, "email": "owner@cubus.sh", "exp": now.Add(time.Hour).Unix()}),
		signRS256(t, priv, "cf-kid-1", nil, jwt.MapClaims{"iss": "https://other.cloudflareaccess.com", "aud": []string{"aud-expected"}, "email": "owner@cubus.sh", "exp": now.Add(time.Hour).Unix()}),
		signRS256(t, priv, "cf-kid-1", nil, jwt.MapClaims{"iss": "https://myteam.cloudflareaccess.com", "aud": []string{"aud-expected"}, "email": "owner@cubus.sh", "exp": now.Add(-time.Hour).Unix()}),
		signRS256(t, priv, "cf-kid-1", nil, jwt.MapClaims{"iss": "https://myteam.cloudflareaccess.com", "aud": []string{"aud-expected"}, "email": "evil@cubus.sh", "exp": now.Add(time.Hour).Unix()}),
		signRS256(t, priv, "cf-kid-1", map[string]any{"jku": "https://evil.example/jwks.json"}, jwt.MapClaims{"iss": "https://myteam.cloudflareaccess.com", "aud": []string{"aud-expected"}, "email": "owner@cubus.sh", "exp": now.Add(time.Hour).Unix()}),
		"eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im93bmVyQGN1YnVzLnNoIiwiZXhwIjo5OTk5OTk5OTk5fQ.",
	}
	for i, bad := range badTokens {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Cf-Access-Jwt-Assertion", bad)
		if _, _, err := authenticator.Authenticate(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("bad token #%d unexpectedly accepted", i)
		}
	}

	// 3. Unknown kid spam is rate-limited (at most 1 extra JWKS fetch within cooldown).
	hitsBefore := jwksHits.Load()
	for range 5 {
		unk := signRS256(t, priv, "unknown-kid-spam", nil, jwt.MapClaims{
			"iss": "https://myteam.cloudflareaccess.com", "aud": []string{"aud-expected"}, "email": "owner@cubus.sh", "exp": now.Add(time.Hour).Unix(),
		})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Cf-Access-Jwt-Assertion", unk)
		_, _, _ = authenticator.Authenticate(httptest.NewRecorder(), r)
	}
	if jwksHits.Load()-hitsBefore > 1 {
		t.Fatalf("unknown-kid refresh cooldown failed: extra fetches=%d", jwksHits.Load()-hitsBefore)
	}
}

func TestGoogleOIDCFlowReplayProtectionAndAllowlistRevocation(t *testing.T) {
	priv, jwksDoc := generateRSAJWK(t, "g-kid-1")
	var lastNonce string
	var emailVerified = true

	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/certs":
			_ = json.NewEncoder(w).Encode(jwksDoc)
		case "/token":
			now := time.Now().UTC()
			idTok := signRS256(t, priv, "g-kid-1", nil, jwt.MapClaims{
				"iss":            "https://accounts.google.com",
				"aud":            "google-cid",
				"email":          "owner@cubus.sh",
				"email_verified": emailVerified,
				"name":           "Owner",
				"nonce":          lastNonce,
				"exp":            now.Add(time.Hour).Unix(),
			})
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idTok})
		default:
			http.NotFound(w, r)
		}
	}))
	defer oidcSrv.Close()

	st := store.NewMemoryStore()
	cfg := config.Config{
		PublicBaseURL:      "http://127.0.0.1:8000",
		PublicIsHTTPS:      false,
		PublicIsLoopback:   true,
		AuthMode:           config.AuthModeGoogle,
		AllowedEmails:      map[string]struct{}{"owner@cubus.sh": {}},
		GoogleClientID:     "google-cid",
		GoogleClientSecret: "google-secret",
	}
	authenticator, err := NewAuthenticator(context.Background(), cfg, st, AuthenticatorOptions{
		GoogleAuthEndpoint:    oidcSrv.URL + "/auth",
		GoogleTokenEndpoint:   oidcSrv.URL + "/token",
		GoogleJWKSURLOverride: oidcSrv.URL + "/certs",
		HTTPClient:            oidcSrv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. StartLogin redirects to Google auth endpoint with PKCE & single-use oidc cookie.
	startRec := httptest.NewRecorder()
	authenticator.Google().StartLogin(startRec, httptest.NewRequest(http.MethodGet, "/auth/google/start?next=/logs", nil))
	if startRec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", startRec.Code)
	}
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	lastNonce = loc.Query().Get("nonce")
	oidcCookie := startRec.Result().Cookies()[0]

	// 2. Callback succeeds once.
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state="+url.QueryEscape(state), nil)
	cbReq.AddCookie(oidcCookie)
	id, nextPath, err := authenticator.Google().CompleteCallback(context.Background(), httptest.NewRecorder(), cbReq)
	if err != nil || id.Email != "owner@cubus.sh" || nextPath != "/logs" {
		t.Fatalf("CompleteCallback failed: id=%+v next=%q err=%v", id, nextPath, err)
	}

	// 3. Replaying the exact same callback MUST fail (single-use DB transaction).
	cbReq2 := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state="+url.QueryEscape(state), nil)
	cbReq2.AddCookie(oidcCookie)
	if _, _, err := authenticator.Google().CompleteCallback(context.Background(), httptest.NewRecorder(), cbReq2); err == nil {
		t.Fatal("expected OIDC callback replay to fail")
	}

	// 4. Active session is immediately revoked if email is removed from ADMIN_ALLOWED_EMAILS.
	sessRec := httptest.NewRecorder()
	if _, err := authenticator.CreateSession(context.Background(), sessRec, id.Email, id.Name); err != nil {
		t.Fatal(err)
	}
	sessCookie := sessRec.Result().Cookies()[0]
	authReq := httptest.NewRequest(http.MethodGet, "/", nil)
	authReq.AddCookie(sessCookie)
	if _, _, err := authenticator.Authenticate(httptest.NewRecorder(), authReq); err != nil {
		t.Fatalf("expected active session to authenticate: %v", err)
	}
	delete(cfg.AllowedEmails, "owner@cubus.sh")
	if _, _, err := authenticator.Authenticate(httptest.NewRecorder(), authReq); err == nil {
		t.Fatal("expected immediate revocation after removing email from allowlist")
	}

	// 5. SafeNextPath blocks open redirects.
	for _, bad := range []string{"//evil.com", `/\evil.com`, "https://evil.com", "/auth/google/callback"} {
		if got := SafeNextPath(bad); got != "/" {
			t.Fatalf("SafeNextPath(%q) = %q, want /", bad, got)
		}
	}
	if !strings.HasPrefix(SafeNextPath("/services/artifact"), "/services/artifact") {
		t.Fatal("expected /services/artifact allowed")
	}
}
