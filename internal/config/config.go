package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	DefaultListenAddr = ":8000"
	DefaultPublicBase = "http://127.0.0.1:8000"

	AuthModeCloudflare          = "cloudflare"
	AuthModeGoogle              = "google"
	AuthModeCloudflareOrGoogle  = "cloudflare_or_google"
	AuthModeCloudflareAndGoogle = "cloudflare_and_google"
	AuthModeDev                 = "dev"
)

var cfTeamDomainPattern = regexp.MustCompile(`^https://[a-z0-9-]+\.cloudflareaccess\.com$`)

type Config struct {
	ListenAddr         string
	PublicBaseURL      string
	PublicIsHTTPS      bool
	PublicIsLoopback   bool
	DBBrokerURL        string
	DatabaseURL        string
	DBStatsURL         string
	OpsAgentURL        string
	AdminNetworkCIDR   *netip.Prefix
	AuthMode           string
	AllowedEmails      map[string]struct{}
	CFAccessTeamDomain string
	CFAccessAUD        string
	GoogleClientID     string
	GoogleClientSecret string
	DevAuthEmail       string
	ServiceTokens      map[string]string
	StaticServices     map[string]string
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen_addr", c.ListenAddr),
		slog.String("public_base_url", c.PublicBaseURL),
		slog.String("auth_mode", c.AuthMode),
		slog.Int("allowed_emails_count", len(c.AllowedEmails)),
		slog.String("cf_access_team_domain", c.CFAccessTeamDomain),
		slog.Bool("cf_access_aud_set", c.CFAccessAUD != ""),
		slog.Bool("google_client_id_set", c.GoogleClientID != ""),
		slog.String("google_client_secret", "[redacted]"),
		slog.Int("service_tokens_count", len(c.ServiceTokens)),
		slog.String("ops_agent_url", c.OpsAgentURL),
		slog.String("db_stats_url", c.DBStatsURL),
	)
}

func (c Config) String() string {
	return fmt.Sprintf("Config{ListenAddr:%q PublicBaseURL:%q AuthMode:%q AllowedEmails:%d ServiceTokens:%d}",
		c.ListenAddr, c.PublicBaseURL, c.AuthMode, len(c.AllowedEmails), len(c.ServiceTokens))
}

func (c Config) IsEmailAllowed(email string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" {
		return false
	}
	_, ok := c.AllowedEmails[e]
	return ok
}

func (c Config) TokenForService(service string) string {
	return c.ServiceTokens[NormalizeServiceKey(service)]
}

func NormalizeServiceKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.ReplaceAll(n, "-", "_")
}

func LoadFromEnv() (Config, error) {
	return Load(os.Getenv, os.Environ)
}

func Load(getenv func(string) string, environ func() []string) (Config, error) {
	cfg := Config{
		ListenAddr:         envOrDefault(getenv, "LISTEN_ADDR", DefaultListenAddr),
		PublicBaseURL:      envOrDefault(getenv, "PUBLIC_BASE_URL", DefaultPublicBase),
		DBBrokerURL:        strings.TrimSpace(getenv("DB_BROKER_URL")),
		DatabaseURL:        strings.TrimSpace(getenv("DATABASE_URL")),
		DBStatsURL:         strings.TrimRight(strings.TrimSpace(getenv("DB_STATS_URL")), "/"),
		OpsAgentURL:        strings.TrimRight(strings.TrimSpace(getenv("OPS_AGENT_URL")), "/"),
		AuthMode:           strings.ToLower(strings.TrimSpace(getenv("AUTH_MODE"))),
		CFAccessTeamDomain: strings.TrimRight(strings.ToLower(strings.TrimSpace(getenv("CF_ACCESS_TEAM_DOMAIN"))), "/"),
		CFAccessAUD:        strings.TrimSpace(getenv("CF_ACCESS_AUD")),
		GoogleClientID:     strings.TrimSpace(getenv("GOOGLE_CLIENT_ID")),
		GoogleClientSecret: strings.TrimSpace(getenv("GOOGLE_CLIENT_SECRET")),
		DevAuthEmail:       strings.ToLower(strings.TrimSpace(getenv("DEV_AUTH_EMAIL"))),
		AllowedEmails:      make(map[string]struct{}),
		ServiceTokens:      make(map[string]string),
		StaticServices:     make(map[string]string),
	}

	if _, port, err := net.SplitHostPort(cfg.ListenAddr); err != nil || port == "" {
		return Config{}, fmt.Errorf("invalid LISTEN_ADDR %q: %w", cfg.ListenAddr, err)
	}

	normBase, isHTTPS, isLoopback, err := NormalizePublicBaseURL(cfg.PublicBaseURL)
	if err != nil {
		return Config{}, err
	}
	cfg.PublicBaseURL = normBase
	cfg.PublicIsHTTPS = isHTTPS
	cfg.PublicIsLoopback = isLoopback

	if cfg.DBBrokerURL == "" && cfg.DatabaseURL == "" {
		return Config{}, errors.New("set DB_BROKER_URL or DATABASE_URL")
	}

	if rawCIDR := strings.TrimSpace(getenv("ADMIN_NETWORK_CIDR")); rawCIDR != "" {
		pfx, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ADMIN_NETWORK_CIDR %q: %w", rawCIDR, err)
		}
		if pfx.Bits() == 0 {
			return Config{}, fmt.Errorf("ADMIN_NETWORK_CIDR %q must not be /0", rawCIDR)
		}
		pfx = pfx.Masked()
		cfg.AdminNetworkCIDR = &pfx
	}

	// DEV_AUTH_EMAIL is strictly forbidden on non-loopback PUBLIC_BASE_URL.
	if cfg.DevAuthEmail != "" {
		if !cfg.PublicIsLoopback {
			return Config{}, errors.New("DEV_AUTH_EMAIL is forbidden when PUBLIC_BASE_URL is non-loopback")
		}
		if !strings.Contains(cfg.DevAuthEmail, "@") {
			return Config{}, fmt.Errorf("invalid DEV_AUTH_EMAIL %q", cfg.DevAuthEmail)
		}
		if cfg.AuthMode == "" {
			cfg.AuthMode = AuthModeDev
		}
	}

	for _, raw := range strings.Split(getenv("ADMIN_ALLOWED_EMAILS"), ",") {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if !strings.Contains(e, "@") || IsPlaceholder(e) {
			return Config{}, fmt.Errorf("invalid email %q in ADMIN_ALLOWED_EMAILS", raw)
		}
		cfg.AllowedEmails[e] = struct{}{}
	}
	if cfg.AuthMode == AuthModeDev && cfg.DevAuthEmail != "" {
		cfg.AllowedEmails[cfg.DevAuthEmail] = struct{}{}
	}
	if len(cfg.AllowedEmails) == 0 {
		return Config{}, errors.New("ADMIN_ALLOWED_EMAILS must contain at least one email address")
	}

	if cfg.AuthMode == "" {
		return Config{}, errors.New("AUTH_MODE must be explicitly set (cloudflare, google, cloudflare_or_google, or cloudflare_and_google)")
	}

	switch cfg.AuthMode {
	case AuthModeCloudflare:
		if err := validateCFConfig(cfg); err != nil {
			return Config{}, err
		}
	case AuthModeGoogle:
		if err := validateGoogleConfig(cfg); err != nil {
			return Config{}, err
		}
	case AuthModeCloudflareOrGoogle, AuthModeCloudflareAndGoogle:
		if err := validateCFConfig(cfg); err != nil {
			return Config{}, err
		}
		if err := validateGoogleConfig(cfg); err != nil {
			return Config{}, err
		}
	case AuthModeDev:
		if !cfg.PublicIsLoopback || cfg.DevAuthEmail == "" {
			return Config{}, errors.New("AUTH_MODE=dev requires loopback PUBLIC_BASE_URL and DEV_AUTH_EMAIL")
		}
	default:
		return Config{}, fmt.Errorf("unsupported AUTH_MODE %q (expected cloudflare, google, cloudflare_or_google, or cloudflare_and_google)", cfg.AuthMode)
	}

	// Scan ADMIN_TOKEN_<SERVICE> environment variables.
	if environ != nil {
		for _, kv := range environ() {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || !strings.HasPrefix(k, "ADMIN_TOKEN_") {
				continue
			}
			svcKey := NormalizeServiceKey(strings.TrimPrefix(k, "ADMIN_TOKEN_"))
			val := strings.TrimSpace(v)
			if svcKey == "" || val == "" || IsPlaceholder(val) {
				continue
			}
			cfg.ServiceTokens[svcKey] = val
		}
	}

	// Optional static service URLs for standalone local dev: "artifact=http://127.0.0.1:9090"
	for _, entry := range strings.Split(getenv("ADMIN_STATIC_SERVICES"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, rawURL, ok := strings.Cut(entry, "=")
		if !ok {
			return Config{}, fmt.Errorf("invalid ADMIN_STATIC_SERVICES entry %q (expected name=http://host:port)", entry)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		rawURL = strings.TrimRight(strings.TrimSpace(rawURL), "/")
		u, err := url.Parse(rawURL)
		if err != nil || name == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Config{}, fmt.Errorf("invalid ADMIN_STATIC_SERVICES entry %q", entry)
		}
		cfg.StaticServices[name] = rawURL
	}

	return cfg, nil
}

func validateCFConfig(cfg Config) error {
	if !cfTeamDomainPattern.MatchString(cfg.CFAccessTeamDomain) || IsPlaceholder(cfg.CFAccessTeamDomain) {
		return fmt.Errorf("CF_ACCESS_TEAM_DOMAIN must match https://<team>.cloudflareaccess.com (got %q)", cfg.CFAccessTeamDomain)
	}
	if cfg.CFAccessAUD == "" || IsPlaceholder(cfg.CFAccessAUD) {
		return errors.New("CF_ACCESS_AUD must be set and not a placeholder")
	}
	return nil
}

func validateGoogleConfig(cfg Config) error {
	if cfg.GoogleClientID == "" || IsPlaceholder(cfg.GoogleClientID) {
		return errors.New("GOOGLE_CLIENT_ID must be set and not a placeholder")
	}
	if cfg.GoogleClientSecret == "" || IsPlaceholder(cfg.GoogleClientSecret) {
		return errors.New("GOOGLE_CLIENT_SECRET must be set and not a placeholder")
	}
	return nil
}

func NormalizePublicBaseURL(raw string) (canonical string, isHTTPS bool, isLoopback bool, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false, false, fmt.Errorf("invalid PUBLIC_BASE_URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false, false, fmt.Errorf("PUBLIC_BASE_URL %q must not contain userinfo, query, or fragment", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	loopback := isLoopbackHost(host)
	switch scheme {
	case "https":
		u.Scheme = "https"
	case "http":
		if !loopback {
			return "", false, false, fmt.Errorf("PUBLIC_BASE_URL %q must use https:// for non-loopback hosts", raw)
		}
		u.Scheme = "http"
	default:
		return "", false, false, fmt.Errorf("unsupported PUBLIC_BASE_URL scheme %q", u.Scheme)
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = host
	} else if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path != "" {
		return "", false, false, fmt.Errorf("PUBLIC_BASE_URL %q must not include a path prefix", raw)
	}
	return u.String(), scheme == "https", loopback, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func IsPlaceholder(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	return strings.Contains(low, "replace-with-") || low == "changeme" || low == "change-me"
}

func HealthcheckURL(listenAddr string) (string, error) {
	if strings.TrimSpace(listenAddr) == "" {
		listenAddr = DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid LISTEN_ADDR %q", listenAddr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func envOrDefault(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}
