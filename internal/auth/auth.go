package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/store"
)

const (
	SessionTTL    = 12 * time.Hour
	cfCSRFCookieTTL = 12 * time.Hour
	csrfKVKey     = "csrf_hmac_key"
)

var trustedProxyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

type Principal struct {
	Email      string
	Name       string
	AuthMethod string // "cloudflare", "google", "cloudflare+google", "dev"
	CSRFToken  string
}

type principalCtxKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(Principal)
	return p, ok
}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

type Authenticator struct {
	cfg           config.Config
	store         store.Store
	cf            *CloudflareVerifier
	google        *GoogleOIDC
	csrfKey       []byte
	sessionCookie string
	cfCSRFCookie  string
}

type AuthenticatorOptions struct {
	CFJWKSURLOverride     string
	GoogleAuthEndpoint    string
	GoogleTokenEndpoint   string
	GoogleJWKSURLOverride string
	HTTPClient            *http.Client
}

func NewAuthenticator(ctx context.Context, cfg config.Config, st store.Store, opts AuthenticatorOptions) (*Authenticator, error) {
	rawKey, err := st.GetOrCreateKV(ctx, csrfKVKey, func() (string, error) {
		return RandomToken(32)
	})
	if err != nil {
		return nil, err
	}

	sessName := "admin_session"
	cfCSRFName := "admin_csrf"
	if cfg.PublicIsHTTPS {
		sessName = "__Host-admin_session"
		cfCSRFName = "__Host-admin_csrf"
	}

	a := &Authenticator{
		cfg:           cfg,
		store:         st,
		csrfKey:       []byte(rawKey),
		sessionCookie: sessName,
		cfCSRFCookie:  cfCSRFName,
	}

	if cfg.AuthMode == config.AuthModeCloudflare || cfg.AuthMode == config.AuthModeCloudflareOrGoogle || cfg.AuthMode == config.AuthModeCloudflareAndGoogle {
		a.cf = NewCloudflareVerifier(cfg.CFAccessTeamDomain, cfg.CFAccessAUD, opts.CFJWKSURLOverride, opts.HTTPClient)
	}
	if cfg.AuthMode == config.AuthModeGoogle || cfg.AuthMode == config.AuthModeCloudflareOrGoogle || cfg.AuthMode == config.AuthModeCloudflareAndGoogle {
		a.google = NewGoogleOIDC(st, GoogleOIDCConfig{
			ClientID:      cfg.GoogleClientID,
			ClientSecret:  cfg.GoogleClientSecret,
			RedirectURL:   cfg.PublicBaseURL + "/auth/google/callback",
			AuthEndpoint:  opts.GoogleAuthEndpoint,
			TokenEndpoint: opts.GoogleTokenEndpoint,
			JWKSURL:       opts.GoogleJWKSURLOverride,
			HTTPClient:    opts.HTTPClient,
		}, cfg.PublicIsHTTPS)
	}

	return a, nil
}

func (a *Authenticator) Google() *GoogleOIDC {
	return a.google
}

func (a *Authenticator) HasGoogle() bool {
	return a.google != nil
}

func (a *Authenticator) HasCloudflare() bool {
	return a.cf != nil
}

func (a *Authenticator) CloudflareLogoutURL() string {
	if a.cfg.CFAccessTeamDomain == "" {
		return ""
	}
	return a.cfg.CFAccessTeamDomain + "/cdn-cgi/access/logout"
}

func (a *Authenticator) CreateSession(ctx context.Context, w http.ResponseWriter, email, name string) (store.AdminSession, error) {
	rawToken, err := RandomToken(32)
	if err != nil {
		return store.AdminSession{}, err
	}
	csrfTok, err := RandomToken(24)
	if err != nil {
		return store.AdminSession{}, err
	}
	sess := store.AdminSession{
		TokenHash: SHA256Bytes(rawToken),
		Email:     strings.ToLower(strings.TrimSpace(email)),
		Name:      strings.TrimSpace(name),
		CSRFToken: csrfTok,
		ExpiresAt: time.Now().UTC().Add(SessionTTL),
	}
	if err := a.store.CreateSession(ctx, sess); err != nil {
		return store.AdminSession{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookie,
		Value:    rawToken,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		MaxAge:   int(SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.cfg.PublicIsHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

func (a *Authenticator) DestroySession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.sessionCookie); err == nil && c.Value != "" {
		_ = a.store.DeleteSession(ctx, SHA256Bytes(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.PublicIsHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) currentSession(ctx context.Context, r *http.Request) (store.AdminSession, bool) {
	c, err := r.Cookie(a.sessionCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return store.AdminSession{}, false
	}
	sess, err := a.store.GetSession(ctx, SHA256Bytes(c.Value))
	if err != nil {
		return store.AdminSession{}, false
	}
	// Re-check allowlist on EVERY request for immediate revocation on removal.
	if !a.cfg.IsEmailAllowed(sess.Email) {
		return store.AdminSession{}, false
	}
	return sess, true
}

// Authenticate validates the caller according to AUTH_MODE and ADMIN_ALLOWED_EMAILS.
// Returns (principal, needsLoginRedirect, err).
func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (Principal, bool, error) {
	ctx := r.Context()

	switch a.cfg.AuthMode {
	case config.AuthModeDev:
		peer := ExtractTCPPeerIP(r)
		if !a.cfg.PublicIsLoopback || !peer.IsLoopback() {
			return Principal{}, false, errors.New("dev auth restricted to loopback")
		}
		tok := a.ensureStatelessCSRF(w, r, a.cfg.DevAuthEmail)
		return Principal{
			Email:      a.cfg.DevAuthEmail,
			Name:       "Local Dev Admin",
			AuthMethod: "dev",
			CSRFToken:  tok,
		}, false, nil

	case config.AuthModeCloudflare:
		email, err := a.verifyCF(ctx, r)
		if err != nil {
			return Principal{}, false, err
		}
		tok := a.ensureStatelessCSRF(w, r, email)
		return Principal{
			Email:      email,
			AuthMethod: "cloudflare",
			CSRFToken:  tok,
		}, false, nil

	case config.AuthModeGoogle:
		sess, ok := a.currentSession(ctx, r)
		if !ok {
			return Principal{}, true, errors.New("sign-in required")
		}
		return Principal{
			Email:      sess.Email,
			Name:       sess.Name,
			AuthMethod: "google",
			CSRFToken:  sess.CSRFToken,
		}, false, nil

	case config.AuthModeCloudflareOrGoogle:
		if a.cf != nil && a.cf.HasToken(r) {
			email, err := a.verifyCF(ctx, r)
			if err != nil {
				return Principal{}, false, err
			}
			tok := a.ensureStatelessCSRF(w, r, email)
			return Principal{
				Email:      email,
				AuthMethod: "cloudflare",
				CSRFToken:  tok,
			}, false, nil
		}
		sess, ok := a.currentSession(ctx, r)
		if !ok {
			return Principal{}, true, errors.New("sign-in required")
		}
		return Principal{
			Email:      sess.Email,
			Name:       sess.Name,
			AuthMethod: "google",
			CSRFToken:  sess.CSRFToken,
		}, false, nil

	case config.AuthModeCloudflareAndGoogle:
		cfEmail, err := a.verifyCF(ctx, r)
		if err != nil {
			return Principal{}, false, err
		}
		sess, ok := a.currentSession(ctx, r)
		if !ok {
			return Principal{}, true, errors.New("google sign-in required in addition to Cloudflare Access")
		}
		if sess.Email != cfEmail {
			return Principal{}, false, errors.New("Cloudflare Access email does not match Google session email")
		}
		return Principal{
			Email:      sess.Email,
			Name:       sess.Name,
			AuthMethod: "cloudflare+google",
			CSRFToken:  sess.CSRFToken,
		}, false, nil

	default:
		return Principal{}, false, errors.New("unsupported auth mode")
	}
}

func (a *Authenticator) verifyCF(ctx context.Context, r *http.Request) (string, error) {
	if a.cf == nil {
		return "", errors.New("cloudflare verifier not initialized")
	}
	email, err := a.cf.VerifyRequest(ctx, r)
	if err != nil {
		return "", err
	}
	if !a.cfg.IsEmailAllowed(email) {
		return "", errors.New("email not in ADMIN_ALLOWED_EMAILS")
	}
	return email, nil
}

// ensureStatelessCSRF binds an HMAC-signed CSRF token to email in an HttpOnly cookie
// for stateless auth modes (Cloudflare Access / dev).
func (a *Authenticator) ensureStatelessCSRF(w http.ResponseWriter, r *http.Request, email string) string {
	if c, err := r.Cookie(a.cfCSRFCookie); err == nil && a.verifyHMACCSRF(email, c.Value) {
		return c.Value
	}
	nonce, err := RandomToken(24)
	if err != nil {
		return ""
	}
	tok := a.signHMACCSRF(email, nonce)
	if w != nil {
		http.SetCookie(w, &http.Cookie{
			Name:     a.cfCSRFCookie,
			Value:    tok,
			Path:     "/",
			MaxAge:   int(cfCSRFCookieTTL.Seconds()),
			HttpOnly: true,
			Secure:   a.cfg.PublicIsHTTPS,
			SameSite: http.SameSiteLaxMode,
		})
	}
	return tok
}

func (a *Authenticator) VerifyCSRF(r *http.Request, p Principal, provided string) bool {
	provided = strings.TrimSpace(provided)
	if provided == "" || p.CSRFToken == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(p.CSRFToken), []byte(provided)) != 1 {
		return false
	}
	if p.AuthMethod == "cloudflare" || p.AuthMethod == "dev" {
		c, err := r.Cookie(a.cfCSRFCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(provided)) != 1 {
			return false
		}
		return a.verifyHMACCSRF(p.Email, provided)
	}
	return true
}

func (a *Authenticator) signHMACCSRF(email, nonce string) string {
	mac := hmac.New(sha256.New, a.csrfKey)
	mac.Write([]byte(strings.ToLower(email)))
	mac.Write([]byte(":"))
	mac.Write([]byte(nonce))
	return nonce + "." + hex.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) verifyHMACCSRF(email, token string) bool {
	nonce, sigHex, ok := strings.Cut(token, ".")
	if !ok || len(nonce) < 16 || len(sigHex) != 64 {
		return false
	}
	expected := a.signHMACCSRF(email, nonce)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

// SafeNextPath strictly limits post-login redirects to known admin paths.
func SafeNextPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "/"
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	switch {
	case u.Path == "/", u.Path == "/logs", u.Path == "/audit", strings.HasPrefix(u.Path, "/services/"):
		return u.RequestURI()
	default:
		return "/"
	}
}

func ExtractTCPPeerIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// ExtractClientIP trusts X-Real-IP strictly when RemoteAddr is a trusted private/loopback proxy.
func ExtractClientIP(r *http.Request) string {
	remote := ExtractTCPPeerIP(r)
	if !remote.IsValid() {
		return ""
	}
	if isTrustedProxy(remote) {
		if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
			if addr, err := netip.ParseAddr(raw); err == nil {
				return addr.Unmap().String()
			}
		}
	}
	return remote.String()
}

func isTrustedProxy(addr netip.Addr) bool {
	for _, pfx := range trustedProxyPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func SHA256Bytes(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
