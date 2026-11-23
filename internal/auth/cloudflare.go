package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

const cfAccessJWTHeader = "Cf-Access-Jwt-Assertion"

type CloudflareVerifier struct {
	teamDomain string
	aud        string
	jwks       *JWKSCache
}

func NewCloudflareVerifier(teamDomain, aud string, jwksURLOverride string, client *http.Client) *CloudflareVerifier {
	jwksURL := strings.TrimRight(teamDomain, "/") + "/cdn-cgi/access/certs"
	if jwksURLOverride != "" {
		jwksURL = jwksURLOverride
	}
	return &CloudflareVerifier{
		teamDomain: strings.TrimRight(teamDomain, "/"),
		aud:        aud,
		jwks:       NewJWKSCache(jwksURL, client),
	}
}

func (v *CloudflareVerifier) HasToken(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get(cfAccessJWTHeader)) != ""
}

func (v *CloudflareVerifier) VerifyRequest(ctx context.Context, r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.Header.Get(cfAccessJWTHeader))
	if raw == "" {
		return "", errors.New("missing Cf-Access-Jwt-Assertion header")
	}

	claims, err := v.jwks.VerifyJWT(ctx, raw, []string{"RS256", "ES256"})
	if err != nil {
		return "", err
	}

	iss, _ := claims.GetIssuer()
	if strings.TrimRight(strings.ToLower(iss), "/") != strings.ToLower(v.teamDomain) {
		return "", fmt.Errorf("unexpected Cloudflare Access issuer %q", iss)
	}

	auds, err := claims.GetAudience()
	if err != nil || !slices.Contains(auds, v.aud) {
		return "", errors.New("Cloudflare Access JWT audience mismatch")
	}

	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return "", errors.New("Cloudflare Access JWT missing email claim")
	}
	return email, nil
}
