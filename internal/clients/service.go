package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cubus.sh/admin/internal/config"
)

const (
	serviceCallTimeout = 10 * time.Second
	serviceMaxResp     = 2 << 20
)

var (
	ErrServiceNotFound   = errors.New("managed service not found")
	ErrServiceUnauth     = errors.New("service admin token not configured")
	ErrInvalidResourceID = errors.New("invalid resource identifier")

	safeServiceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	safeIDPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type ServiceSummary struct {
	Service         string   `json:"service"`
	Name            string   `json:"name"`
	State           string   `json:"state"`
	Health          string   `json:"health,omitempty"`
	TokenConfigured bool     `json:"token_configured"`
	Reachable       bool     `json:"reachable"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type resolvedTarget struct {
	Service string
	Name    string
	BaseURL string
	Token   string
	State   string
	Health  string
}

type ServiceClient struct {
	cfg    config.Config
	ops    *OpsClient
	client *http.Client
}

func NewServiceClient(cfg config.Config, ops *OpsClient) *ServiceClient {
	return &ServiceClient{
		cfg: cfg,
		ops: ops,
		client: &http.Client{
			Timeout: serviceCallTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func ValidateResourceID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return "", ErrInvalidResourceID
	}
	return id, nil
}

func (c *ServiceClient) discoverTargets(ctx context.Context) map[string]resolvedTarget {
	targets := make(map[string]resolvedTarget)

	// 1. Static services (local dev / explicit overrides)
	for name, baseURL := range c.cfg.StaticServices {
		if !safeServiceNamePattern.MatchString(name) {
			continue
		}
		targets[name] = resolvedTarget{
			Service: name,
			Name:    name,
			BaseURL: strings.TrimRight(baseURL, "/"),
			Token:   c.cfg.TokenForService(name),
			State:   "static",
		}
	}

	// 2. Dynamic services discovered via ops-agent over admin network (dial verified admin_ip directly!)
	if c.ops != nil && c.ops.Configured() {
		if discovered, err := c.ops.GetServices(ctx); err == nil {
			for _, d := range discovered {
				svc := strings.ToLower(strings.TrimSpace(d.Service))
				if !safeServiceNamePattern.MatchString(svc) || d.Port < 1 || d.Port > 65535 {
					continue
				}
				ip, err := netip.ParseAddr(strings.TrimSpace(d.AdminIP))
				if err != nil {
					continue
				}
				ip = ip.Unmap()
				if c.cfg.AdminNetworkCIDR != nil && !c.cfg.AdminNetworkCIDR.Contains(ip) {
					continue
				}
				name := strings.TrimSpace(d.Name)
				if name == "" {
					name = svc
				}
				targets[svc] = resolvedTarget{
					Service: svc,
					Name:    name,
					BaseURL: "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(d.Port)),
					Token:   c.cfg.TokenForService(svc),
					State:   d.State,
					Health:  d.Health,
				}
			}
		}
	}

	return targets
}

func (c *ServiceClient) ListServices(ctx context.Context) []ServiceSummary {
	targets := c.discoverTargets(ctx)
	out := make([]ServiceSummary, 0, len(targets))
	for _, t := range targets {
		sum := ServiceSummary{
			Service:         t.Service,
			Name:            t.Name,
			State:           t.State,
			Health:          t.Health,
			TokenConfigured: t.Token != "",
		}
		if t.Token == "" {
			sum.Error = fmt.Sprintf("Set ADMIN_TOKEN_%s in admin .env (and matching ADMIN_API_TOKEN in %s .env)", strings.ToUpper(config.NormalizeServiceKey(t.Service)), t.Service)
			out = append(out, sum)
			continue
		}
		raw, status, err := c.callTarget(ctx, t, http.MethodGet, "/admin/v1/manifest", nil, nil)
		if err != nil {
			sum.Error = "admin API unreachable (ensure ADMIN_API_TOKEN is enabled on the service)"
		} else if status != http.StatusOK {
			sum.Error = fmt.Sprintf("manifest returned HTTP %d", status)
		} else {
			var man struct {
				Capabilities []string `json:"capabilities"`
			}
			if json.Unmarshal(raw, &man) == nil {
				sum.Reachable = true
				sum.Capabilities = man.Capabilities
			}
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

func (c *ServiceClient) Proxy(ctx context.Context, service, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	svc := strings.ToLower(strings.TrimSpace(service))
	if !safeServiceNamePattern.MatchString(svc) {
		return nil, http.StatusBadRequest, ErrServiceNotFound
	}
	if !strings.HasPrefix(relPath, "/admin/v1/") || strings.Contains(relPath, "..") {
		return nil, http.StatusBadRequest, errors.New("disallowed admin API path")
	}
	targets := c.discoverTargets(ctx)
	t, ok := targets[svc]
	if !ok {
		return nil, http.StatusNotFound, ErrServiceNotFound
	}
	if t.Token == "" {
		return nil, http.StatusPreconditionFailed, ErrServiceUnauth
	}
	return c.callTarget(ctx, t, method, relPath, query, body)
}

func (c *ServiceClient) callTarget(ctx context.Context, t resolvedTarget, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	fullURL := t.BaseURL + relPath
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, serviceMaxResp))
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	return json.RawMessage(respBody), resp.StatusCode, nil
}
