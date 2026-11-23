package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func loadMap(m map[string]string) (Config, error) {
	envSlice := make([]string, 0, len(m))
	for k, v := range m {
		envSlice = append(envSlice, k+"="+v)
	}
	return Load(func(k string) string { return m[k] }, func() []string { return envSlice })
}

func TestLoadCloudflareAndGoogleModes(t *testing.T) {
	cfg, err := loadMap(map[string]string{
		"PUBLIC_BASE_URL":       "https://admin.cubus.sh",
		"DB_BROKER_URL":         "http://db-broker:8080/v1/database",
		"AUTH_MODE":             "cloudflare_and_google",
		"ADMIN_ALLOWED_EMAILS":  "Owner@Cubus.sh, backup@cubus.sh",
		"CF_ACCESS_TEAM_DOMAIN": "https://cubus-team.cloudflareaccess.com/",
		"CF_ACCESS_AUD":         "aud-tag-1234567890",
		"GOOGLE_CLIENT_ID":      "123.apps.googleusercontent.com",
		"GOOGLE_CLIENT_SECRET":  "super-secret-google-key",
		"ADMIN_TOKEN_ARTIFACT":  "tok-artifact-real-secret",
		"ADMIN_TOKEN_MY_APP":    "tok-myapp-secret",
		"ADMIN_TOKEN_IGNORED":   "replace-with-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsEmailAllowed("owner@cubus.sh") || cfg.IsEmailAllowed("stranger@cubus.sh") {
		t.Fatalf("unexpected allowlist behavior")
	}
	if cfg.TokenForService("artifact") != "tok-artifact-real-secret" ||
		cfg.TokenForService("my-app") != "tok-myapp-secret" ||
		cfg.TokenForService("ignored") != "" {
		t.Fatalf("unexpected service tokens: %+v", cfg.ServiceTokens)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "cfg", cfg)
	logged := buf.String() + cfg.String()
	for _, secret := range []string{"super-secret-google-key", "tok-artifact-real-secret", "tok-myapp-secret"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("secret %q leaked into logs", secret)
		}
	}
}

func TestLoadRejectsInsecureConfigurations(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "missing auth mode",
			env: map[string]string{
				"PUBLIC_BASE_URL":      "https://admin.cubus.sh",
				"DATABASE_URL":         "postgres://u:p@localhost/db",
				"ADMIN_ALLOWED_EMAILS": "me@cubus.sh",
			},
		},
		{
			name: "dev auth on non-loopback",
			env: map[string]string{
				"PUBLIC_BASE_URL": "https://admin.cubus.sh",
				"DATABASE_URL":    "postgres://u:p@localhost/db",
				"DEV_AUTH_EMAIL":  "dev@cubus.sh",
			},
		},
		{
			name: "non-cloudflareaccess team domain",
			env: map[string]string{
				"PUBLIC_BASE_URL":       "https://admin.cubus.sh",
				"DATABASE_URL":          "postgres://u:p@localhost/db",
				"AUTH_MODE":             "cloudflare",
				"ADMIN_ALLOWED_EMAILS":  "me@cubus.sh",
				"CF_ACCESS_TEAM_DOMAIN": "https://evil.example.com",
				"CF_ACCESS_AUD":         "aud123",
			},
		},
		{
			name: "missing allowed emails",
			env: map[string]string{
				"PUBLIC_BASE_URL":      "https://admin.cubus.sh",
				"DATABASE_URL":         "postgres://u:p@localhost/db",
				"AUTH_MODE":            "google",
				"GOOGLE_CLIENT_ID":     "cid",
				"GOOGLE_CLIENT_SECRET": "csec",
			},
		},
		{
			name: "placeholder google secret",
			env: map[string]string{
				"PUBLIC_BASE_URL":      "https://admin.cubus.sh",
				"DATABASE_URL":         "postgres://u:p@localhost/db",
				"AUTH_MODE":            "google",
				"ADMIN_ALLOWED_EMAILS": "me@cubus.sh",
				"GOOGLE_CLIENT_ID":     "cid",
				"GOOGLE_CLIENT_SECRET": "replace-with-google-client-secret",
			},
		},
		{
			name: "dev private bridge on non-loopback",
			env: map[string]string{
				"PUBLIC_BASE_URL":          "https://admin.cubus.sh",
				"DATABASE_URL":             "postgres://u:p@localhost/db",
				"AUTH_MODE":                "google",
				"ADMIN_ALLOWED_EMAILS":     "me@cubus.sh",
				"GOOGLE_CLIENT_ID":         "cid",
				"GOOGLE_CLIENT_SECRET":     "real-secret",
				"DEV_ALLOW_PRIVATE_BRIDGE": "true",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadMap(tc.env); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// IPv6 loopback URL retains brackets when default port is omitted.
	got, _, isLoop, err := NormalizePublicBaseURL("http://[::1]:80")
	if err != nil || !isLoop || got != "http://[::1]" {
		t.Fatalf("expected http://[::1], got (%q, loop=%v, err=%v)", got, isLoop, err)
	}
}
