package clients

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cubus.sh/admin/internal/config"
)

const (
	serviceCallTimeout   = 10 * time.Second
	manifestProbeTimeout = 2 * time.Second
	serviceMaxResp       = 2 << 20
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
	Model           string   `json:"model,omitempty"`
	State           string   `json:"state"`
	Health          string   `json:"health,omitempty"`
	TokenConfigured bool     `json:"token_configured"`
	Reachable       bool     `json:"reachable"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type AmberClassifierStatus struct {
	Available bool   `json:"available"`
	Service   string `json:"service,omitempty"`
	Model     string `json:"model"`
	Error     string `json:"error,omitempty"`
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
	cfg       config.Config
	ops       *OpsClient
	transport *http.Transport
	client    *http.Client
	localIPs  map[netip.Addr]struct{}
}

func NewServiceClient(cfg config.Config, ops *OpsClient) *ServiceClient {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	// Never inherit HTTP_PROXY/HTTPS_PROXY for internal admin API traffic carrying bearer tokens.
	tr.Proxy = nil
	return &ServiceClient{
		cfg:       cfg,
		ops:       ops,
		transport: tr,
		client:    newServiceHTTPClient(tr, serviceCallTimeout),
		localIPs:  collectLocalInterfaceIPs(),
	}
}

func collectLocalInterfaceIPs() map[netip.Addr]struct{} {
	ips := make(map[netip.Addr]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			ips[addr.Unmap()] = struct{}{}
		}
	}
	return ips
}

func isAllowedDynamicAdminIP(ip netip.Addr, pfx netip.Prefix, localIPs map[netip.Addr]struct{}) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !pfx.IsValid() {
		return false
	}
	pfx = pfx.Masked()
	if !pfx.Contains(ip) {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if pfx.Bits() < ip.BitLen() {
		// Reject network address (.0) and bridge gateway (first host .1).
		if ip == pfx.Addr() || ip == pfx.Addr().Next() {
			return false
		}
	}
	if ip.Is4() && pfx.Bits() < 31 {
		b := pfx.Addr().As4()
		hostMask := ^uint32(0) >> uint(pfx.Bits())
		v := binary.BigEndian.Uint32(b[:]) | hostMask
		var bcast [4]byte
		binary.BigEndian.PutUint32(bcast[:], v)
		if ip == netip.AddrFrom4(bcast) {
			return false
		}
	}
	if _, isSelf := localIPs[ip]; isSelf {
		return false
	}
	return true
}

func validateAdminRelPath(relPath string) error {
	if relPath == "" || !strings.HasPrefix(relPath, "/admin/v1/") || len(relPath) <= len("/admin/v1/") {
		return errors.New("disallowed admin API path")
	}
	if strings.ContainsAny(relPath, "?#\\") || strings.Contains(relPath, "..") {
		return errors.New("disallowed admin API path")
	}
	for i := 0; i < len(relPath); i++ {
		if relPath[i] < 0x20 || relPath[i] == 0x7f {
			return errors.New("disallowed admin API path")
		}
	}
	low := strings.ToLower(relPath)
	if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") {
		return errors.New("disallowed admin API path")
	}
	cleaned := path.Clean(relPath)
	if cleaned != relPath || !strings.HasPrefix(cleaned, "/admin/v1/") {
		return errors.New("disallowed admin API path")
	}
	return nil
}

func newServiceHTTPClient(tr *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
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
	// Fail CLOSED if AdminNetworkCIDR is not configured.
	if c.ops != nil && c.ops.Configured() && c.cfg.AdminNetworkCIDR != nil {
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
				if !isAllowedDynamicAdminIP(ip, *c.cfg.AdminNetworkCIDR, c.localIPs) {
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
	list := make([]resolvedTarget, 0, len(targets))
	for _, t := range targets {
		list = append(list, t)
	}
	out := make([]ServiceSummary, len(list))
	var wg sync.WaitGroup
	for i, t := range list {
		wg.Add(1)
		go func(idx int, target resolvedTarget) {
			defer wg.Done()
			sum := ServiceSummary{
				Service:         target.Service,
				Name:            target.Name,
				State:           target.State,
				Health:          target.Health,
				TokenConfigured: target.Token != "",
			}
			if target.Token == "" {
				sum.Error = fmt.Sprintf("Set ADMIN_TOKEN_%s in admin .env (and matching ADMIN_API_TOKEN in %s .env)", strings.ToUpper(config.NormalizeServiceKey(target.Service)), target.Service)
				out[idx] = sum
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, manifestProbeTimeout)
			defer cancel()
			raw, status, err := c.callTarget(probeCtx, target, http.MethodGet, "/admin/v1/manifest", nil, nil)
			if err != nil {
				sum.Error = "admin API unreachable (ensure ADMIN_API_TOKEN is enabled on the service)"
			} else if status != http.StatusOK {
				sum.Error = fmt.Sprintf("manifest returned HTTP %d", status)
			} else {
				var man struct {
					Model        string   `json:"model"`
					Capabilities []string `json:"capabilities"`
				}
				if json.Unmarshal(raw, &man) == nil {
					sum.Reachable = true
					sum.Model = strings.TrimSpace(man.Model)
					sum.Capabilities = man.Capabilities
				}
			}
			out[idx] = sum
		}(i, t)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// AmberStatus probes internal services and reports whether an Amber classifier service is reachable.
func (c *ServiceClient) AmberStatus(ctx context.Context) AmberClassifierStatus {
	services := c.ListServices(ctx)
	var fallback *ServiceSummary
	var choiceCandidate *ServiceSummary
	for i := range services {
		s := services[i]
		if s.Service == "choice" {
			choiceCandidate = &s
		}
		if !s.Reachable || !slices.Contains(s.Capabilities, "classify") {
			continue
		}
		if s.Service == "choice" {
			model := s.Model
			if model == "" {
				model = "amber-150m"
			}
			return AmberClassifierStatus{
				Available: true,
				Service:   s.Service,
				Model:     model,
			}
		}
		if fallback == nil {
			fallback = &s
		}
	}
	if fallback != nil {
		model := fallback.Model
		if model == "" {
			model = "amber-150m"
		}
		return AmberClassifierStatus{
			Available: true,
			Service:   fallback.Service,
			Model:     model,
		}
	}
	if choiceCandidate != nil {
		errMsg := choiceCandidate.Error
		if errMsg == "" {
			errMsg = "choice service does not advertise classify capability"
		}
		model := choiceCandidate.Model
		if model == "" {
			model = "amber-150m"
		}
		return AmberClassifierStatus{
			Available: false,
			Service:   choiceCandidate.Service,
			Model:     model,
			Error:     errMsg,
		}
	}
	return AmberClassifierStatus{
		Available: false,
		Model:     "amber-150m",
		Error:     "no reachable service with classify capability discovered",
	}
}

func (c *ServiceClient) resolveValidatedTarget(ctx context.Context, service, relPath string) (resolvedTarget, int, error) {
	svc := strings.ToLower(strings.TrimSpace(service))
	if !safeServiceNamePattern.MatchString(svc) {
		return resolvedTarget{}, http.StatusBadRequest, ErrServiceNotFound
	}
	if err := validateAdminRelPath(relPath); err != nil {
		return resolvedTarget{}, http.StatusBadRequest, err
	}
	targets := c.discoverTargets(ctx)
	t, ok := targets[svc]
	if !ok {
		return resolvedTarget{}, http.StatusNotFound, ErrServiceNotFound
	}
	if t.Token == "" {
		return resolvedTarget{}, http.StatusPreconditionFailed, ErrServiceUnauth
	}
	return t, 0, nil
}

func (c *ServiceClient) Proxy(ctx context.Context, service, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	return c.ProxyWithTimeout(ctx, service, method, relPath, query, body, serviceCallTimeout)
}

func (c *ServiceClient) ProxyWithTimeout(ctx context.Context, service, method, relPath string, query url.Values, body []byte, timeout time.Duration) (json.RawMessage, int, error) {
	t, status, err := c.resolveValidatedTarget(ctx, service, relPath)
	if err != nil {
		return nil, status, err
	}
	if timeout <= 0 {
		timeout = serviceCallTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := c.client
	if timeout != serviceCallTimeout {
		client = newServiceHTTPClient(c.transport, timeout)
	}
	return c.callTargetWithClient(callCtx, client, t, method, relPath, query, body)
}

func (c *ServiceClient) callTarget(ctx context.Context, t resolvedTarget, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	return c.callTargetWithClient(ctx, c.client, t, method, relPath, query, body)
}

func (c *ServiceClient) callTargetWithClient(ctx context.Context, client *http.Client, t resolvedTarget, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, serviceMaxResp))
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	if len(respBody) > 0 && !json.Valid(respBody) {
		return nil, http.StatusBadGateway, errors.New("service admin API returned invalid JSON")
	}
	return json.RawMessage(respBody), resp.StatusCode, nil
}
