package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"cubus.sh/admin/internal/store"
)

const (
	defaultGoogleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultGoogleTokenEndpoint = "https://oauth2.googleapis.com/token"
	defaultGoogleJWKSURL       = "https://www.googleapis.com/oauth2/v3/certs"

	oidcTxTTL        = 10 * time.Minute
	googleHTTPExpiry = 10 * time.Second
)

type GoogleOIDCConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	AuthEndpoint  string
	TokenEndpoint string
	JWKSURL       string
	HTTPClient    *http.Client
}

type GoogleOIDC struct {
	cfg        GoogleOIDCConfig
	store      store.Store
	jwks       *JWKSCache
	client     *http.Client
	secure     bool
	oidcCookie string
}

type GoogleIdentity struct {
	Email string
	Name  string
}

func NewGoogleOIDC(st store.Store, cfg GoogleOIDCConfig, secure bool) *GoogleOIDC {
	if cfg.AuthEndpoint == "" {
		cfg.AuthEndpoint = defaultGoogleAuthEndpoint
	}
	if cfg.TokenEndpoint == "" {
		cfg.TokenEndpoint = defaultGoogleTokenEndpoint
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = defaultGoogleJWKSURL
	}
	cli := cfg.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: googleHTTPExpiry}
	}
	cookieName := "admin_oidc"
	if secure {
		cookieName = "__Host-admin_oidc"
	}
	return &GoogleOIDC{
		cfg:        cfg,
		store:      st,
		jwks:       NewJWKSCache(cfg.JWKSURL, cli),
		client:     cli,
		secure:     secure,
		oidcCookie: cookieName,
	}
}

func (g *GoogleOIDC) StartLogin(w http.ResponseWriter, r *http.Request) {
	txID, err := RandomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := RandomToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := RandomToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier, err := RandomToken(48)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	nextPath := SafeNextPath(r.URL.Query().Get("next"))
	tx := store.OIDCTransaction{
		TxHash:       SHA256Bytes(txID),
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		NextPath:     nextPath,
		ExpiresAt:    time.Now().UTC().Add(oidcTxTTL),
	}
	if err := g.store.CreateOIDCTransaction(r.Context(), tx); err != nil {
		http.Error(w, "failed to start sign-in", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     g.oidcCookie,
		Value:    txID,
		Path:     "/",
		MaxAge:   int(oidcTxTTL.Seconds()),
		HttpOnly: true,
		Secure:   g.secure,
		SameSite: http.SameSiteLaxMode,
	})

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"client_id":             {g.cfg.ClientID},
		"redirect_uri":          {g.cfg.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	http.Redirect(w, r, g.cfg.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (g *GoogleOIDC) CompleteCallback(ctx context.Context, w http.ResponseWriter, r *http.Request) (GoogleIdentity, string, error) {
	// Always clear the single-use OIDC transaction cookie.
	defer http.SetCookie(w, &http.Cookie{
		Name:     g.oidcCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   g.secure,
		SameSite: http.SameSiteLaxMode,
	})

	if errCode := strings.TrimSpace(r.URL.Query().Get("error")); errCode != "" {
		return GoogleIdentity{}, "", fmt.Errorf("google sign-in cancelled (%s)", errCode)
	}

	c, err := r.Cookie(g.oidcCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return GoogleIdentity{}, "", errors.New("missing OIDC login cookie")
	}

	tx, err := g.store.ConsumeOIDCTransaction(ctx, SHA256Bytes(c.Value))
	if err != nil {
		return GoogleIdentity{}, "", errors.New("invalid, expired, or already-used OIDC login transaction")
	}

	gotState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(gotState), []byte(tx.State)) != 1 {
		return GoogleIdentity{}, "", errors.New("OIDC state mismatch")
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		return GoogleIdentity{}, "", errors.New("missing authorization code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"redirect_uri":  {g.cfg.RedirectURL},
		"code":          {code},
		"code_verifier": {tx.CodeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return GoogleIdentity{}, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client.Do(req)
	if err != nil {
		return GoogleIdentity{}, "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return GoogleIdentity{}, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return GoogleIdentity{}, "", fmt.Errorf("google token endpoint returned status %d", resp.StatusCode)
	}

	var tokResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil || tokResp.IDToken == "" {
		return GoogleIdentity{}, "", errors.New("google token response missing id_token")
	}

	claims, err := g.jwks.VerifyJWT(ctx, tokResp.IDToken, []string{"RS256"})
	if err != nil {
		return GoogleIdentity{}, "", fmt.Errorf("verify google id_token: %w", err)
	}

	iss, _ := claims.GetIssuer()
	if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
		return GoogleIdentity{}, "", fmt.Errorf("unexpected google id_token issuer %q", iss)
	}
	auds, err := claims.GetAudience()
	if err != nil || !slices.Contains(auds, g.cfg.ClientID) {
		return GoogleIdentity{}, "", errors.New("google id_token audience mismatch")
	}
	gotNonce, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(gotNonce), []byte(tx.Nonce)) != 1 {
		return GoogleIdentity{}, "", errors.New("google id_token nonce mismatch")
	}
	verified, _ := claims["email_verified"].(bool)
	if !verified {
		return GoogleIdentity{}, "", errors.New("google account email is not verified")
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return GoogleIdentity{}, "", errors.New("google id_token missing email")
	}
	name, _ := claims["name"].(string)
	return GoogleIdentity{Email: email, Name: strings.TrimSpace(name)}, SafeNextPath(tx.NextPath), nil
}
