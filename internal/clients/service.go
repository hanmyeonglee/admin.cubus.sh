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
	serviceCallTimeout    = 10 * time.Second
	manifestProbeTimeout  = 2 * time.Second
	accessOverviewTimeout = 6 * time.Second
	accessDomainTimeout   = 4 * time.Second
	serviceMaxResp        = 2 << 20
)

var (
	ErrServiceNotFound       = errors.New("managed service not found")
	ErrInvalidServiceName    = errors.New("invalid service name")
	ErrServiceUnauth         = errors.New("service admin token not configured")
	ErrInvalidResourceID     = errors.New("invalid resource identifier")
	ErrCapabilityUnsupported = errors.New("service does not support requested capability")

	safeServiceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	safeIDPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type UserColumnSpec struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Format string `json:"format,omitempty"`
}

type ServiceManifest struct {
	Service          string            `json:"service"`
	Version          string            `json:"version,omitempty"`
	Model            string            `json:"model,omitempty"`
	Capabilities     []string          `json:"capabilities,omitempty"`
	UserCapabilities map[string]bool   `json:"user_capabilities,omitempty"`
	UserColumns      []UserColumnSpec  `json:"user_columns,omitempty"`
	Endpoints        map[string]string `json:"endpoints,omitempty"`
	SettingsSchema   json.RawMessage   `json:"settings_schema,omitempty"`
}

func (m ServiceManifest) HasCapability(cap string) bool {
	return slices.Contains(m.Capabilities, cap)
}

func (m ServiceManifest) SupportsUserAction(action string) bool {
	if !m.HasCapability("users") {
		return false
	}
	if m.UserCapabilities == nil {
		// Backward compatibility for legacy manifests (e.g., artifact) that advertise
		// "users" without a "user_capabilities" object: approve/deny only.
		return action == "approve" || action == "deny"
	}
	if action == "deny" {
		if v, ok := m.UserCapabilities["deny"]; ok {
			return v
		}
		return m.UserCapabilities["approve"]
	}
	return m.UserCapabilities[action]
}

type ServiceSummary struct {
	Service          string           `json:"service"`
	Name             string           `json:"name"`
	Model            string           `json:"model,omitempty"`
	State            string           `json:"state"`
	Health           string           `json:"health,omitempty"`
	TokenConfigured  bool             `json:"token_configured"`
	Reachable        bool             `json:"reachable"`
	Capabilities     []string         `json:"capabilities,omitempty"`
	UserCapabilities map[string]bool  `json:"user_capabilities,omitempty"`
	UserColumns      []UserColumnSpec `json:"user_columns,omitempty"`
	Error            string           `json:"error,omitempty"`
}

type AccessOverviewSummary struct {
	TotalUsers       int `json:"total_users"`
	ActiveUsers      int `json:"active_users"`
	PendingApprovals int `json:"pending_approvals"`
	DisabledUsers    int `json:"disabled_users"`
	TotalInvites     int `json:"total_invites"`
	PendingInvites   int `json:"pending_invites"`
	TotalAPIKeys     int `json:"total_api_keys"`
	ActiveAPIKeys    int `json:"active_api_keys"`
	DegradedServices int `json:"degraded_services"`
}

type AccessServiceSection struct {
	Service          string            `json:"service"`
	Name             string            `json:"name"`
	Reachable        bool              `json:"reachable"`
	Capabilities     []string          `json:"capabilities,omitempty"`
	UserCapabilities map[string]bool   `json:"user_capabilities"`
	UserColumns      []UserColumnSpec  `json:"user_columns"`
	Users            []json.RawMessage `json:"users,omitempty"`
	UsersError       string            `json:"users_error,omitempty"`
	Invites          []json.RawMessage `json:"invites,omitempty"`
	InvitesError     string            `json:"invites_error,omitempty"`
	APIKeys          []json.RawMessage `json:"api_keys,omitempty"`
	APIKeysError     string            `json:"api_keys_error,omitempty"`
	Error            string            `json:"error,omitempty"`
}

type AccessOverview struct {
	Summary        AccessOverviewSummary  `json:"summary"`
	Services       []AccessServiceSection `json:"services"`
	DiscoveryError string                 `json:"discovery_error,omitempty"`
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

func ValidateServiceName(name string) (string, error) {
	if name == "" {
		return "", ErrInvalidServiceName
	}
	for i := 0; i < len(name); i++ {
		if name[i] <= 0x20 || name[i] == 0x7f {
			return "", ErrInvalidServiceName
		}
	}
	svc := strings.ToLower(name)
	if !safeServiceNamePattern.MatchString(svc) {
		return "", ErrInvalidServiceName
	}
	return svc, nil
}

func ValidateResourceID(id string) (string, error) {
	if !safeIDPattern.MatchString(id) {
		return "", ErrInvalidResourceID
	}
	return id, nil
}

func (c *ServiceClient) discoverTargets(ctx context.Context) map[string]resolvedTarget {
	targets, _ := c.discoverTargetsWithErr(ctx)
	return targets
}

func (c *ServiceClient) discoverTargetsWithErr(ctx context.Context) (map[string]resolvedTarget, error) {
	targets := make(map[string]resolvedTarget)
	var discoveryErr error

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
		discovered, err := c.ops.GetServices(ctx)
		if err != nil {
			discoveryErr = err
		} else {
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

	return targets, discoveryErr
}

func (c *ServiceClient) probeTarget(ctx context.Context, target resolvedTarget) (ServiceSummary, ServiceManifest) {
	sum := ServiceSummary{
		Service:         target.Service,
		Name:            target.Name,
		State:           target.State,
		Health:          target.Health,
		TokenConfigured: target.Token != "",
	}
	if target.Token == "" {
		sum.Error = fmt.Sprintf("Set ADMIN_TOKEN_%s in admin .env (and matching ADMIN_API_TOKEN in %s .env)", strings.ToUpper(config.NormalizeServiceKey(target.Service)), target.Service)
		return sum, ServiceManifest{}
	}
	probeCtx, cancel := context.WithTimeout(ctx, manifestProbeTimeout)
	defer cancel()
	raw, status, err := c.callTarget(probeCtx, target, http.MethodGet, "/admin/v1/manifest", nil, nil)
	if err != nil {
		sum.Error = "admin API unreachable (ensure ADMIN_API_TOKEN is enabled on the service)"
		return sum, ServiceManifest{}
	}
	if status != http.StatusOK {
		sum.Error = fmt.Sprintf("manifest returned HTTP %d", status)
		return sum, ServiceManifest{}
	}
	var man ServiceManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		sum.Error = "manifest returned invalid JSON"
		return sum, ServiceManifest{}
	}
	sum.Reachable = true
	sum.Model = strings.TrimSpace(man.Model)
	sum.Capabilities = man.Capabilities
	sum.UserCapabilities = man.UserCapabilities
	sum.UserColumns = man.UserColumns
	return sum, man
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
			sum, _ := c.probeTarget(ctx, target)
			out[idx] = sum
		}(i, t)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

func (c *ServiceClient) fetchManifestForTarget(ctx context.Context, target resolvedTarget) (ServiceManifest, int, error) {
	probeCtx, cancel := context.WithTimeout(ctx, manifestProbeTimeout)
	defer cancel()
	raw, status, err := c.callTarget(probeCtx, target, http.MethodGet, "/admin/v1/manifest", nil, nil)
	if err != nil {
		return ServiceManifest{}, status, err
	}
	if status != http.StatusOK {
		return ServiceManifest{}, http.StatusBadGateway, fmt.Errorf("manifest returned HTTP %d", status)
	}
	var man ServiceManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return ServiceManifest{}, http.StatusBadGateway, errors.New("service manifest returned invalid JSON")
	}
	return man, http.StatusOK, nil
}

func (c *ServiceClient) FetchManifest(ctx context.Context, service string) (ServiceManifest, int, error) {
	t, status, err := c.resolveValidatedTarget(ctx, service, "/admin/v1/manifest")
	if err != nil {
		return ServiceManifest{}, status, err
	}
	return c.fetchManifestForTarget(ctx, t)
}

func extractServiceError(raw json.RawMessage, status int, err error) string {
	if len(raw) > 0 {
		var body struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &body) == nil && strings.TrimSpace(body.Error) != "" {
			return strings.TrimSpace(body.Error)
		}
	}
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("returned HTTP %d", status)
}

func (c *ServiceClient) FetchAccessOverview(ctx context.Context) AccessOverview {
	overviewCtx, cancel := context.WithTimeout(ctx, accessOverviewTimeout)
	defer cancel()

	targets, discoveryErr := c.discoverTargetsWithErr(overviewCtx)
	list := make([]resolvedTarget, 0, len(targets))
	for _, t := range targets {
		list = append(list, t)
	}

	type probed struct {
		target   resolvedTarget
		summary  ServiceSummary
		manifest ServiceManifest
	}
	probedList := make([]probed, len(list))
	var probeWG sync.WaitGroup
	for i, t := range list {
		probeWG.Add(1)
		go func(idx int, target resolvedTarget) {
			defer probeWG.Done()
			sum, man := c.probeTarget(overviewCtx, target)
			probedList[idx] = probed{target: target, summary: sum, manifest: man}
		}(i, t)
	}
	probeWG.Wait()

	sections := make([]AccessServiceSection, 0, len(probedList))
	var secMu sync.Mutex
	var fetchWG sync.WaitGroup

	for _, p := range probedList {
		if !p.summary.Reachable {
			errMsg := p.summary.Error
			if errMsg == "" {
				errMsg = "service unreachable"
			}
			secMu.Lock()
			sections = append(sections, AccessServiceSection{
				Service:   p.summary.Service,
				Name:      p.summary.Name,
				Reachable: false,
				Error:     errMsg,
			})
			secMu.Unlock()
			continue
		}

		hasUsers := p.manifest.HasCapability("users")
		hasInvites := p.manifest.HasCapability("invites")
		hasAPIKeys := p.manifest.HasCapability("api_keys")
		if !hasUsers && !hasInvites && !hasAPIKeys {
			continue
		}

		fetchWG.Add(1)
		go func(item probed, wantUsers, wantInvites, wantAPIKeys bool) {
			defer fetchWG.Done()
			sec := AccessServiceSection{
				Service:          item.summary.Service,
				Name:             item.summary.Name,
				Reachable:        true,
				Capabilities:     item.manifest.Capabilities,
				UserCapabilities: item.manifest.UserCapabilities,
				UserColumns:      item.manifest.UserColumns,
			}

			var domWG sync.WaitGroup
			var domMu sync.Mutex
			var errs []string

			if wantUsers {
				domWG.Add(1)
				go func() {
					defer domWG.Done()
					callCtx, callCancel := context.WithTimeout(overviewCtx, accessDomainTimeout)
					defer callCancel()
					raw, status, err := c.callTarget(callCtx, item.target, http.MethodGet, "/admin/v1/users", nil, nil)
					if err != nil || status != http.StatusOK {
						msg := "users: " + extractServiceError(raw, status, err)
						domMu.Lock()
						sec.UsersError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					var env struct {
						Users []json.RawMessage `json:"users"`
					}
					if err := json.Unmarshal(raw, &env); err != nil {
						msg := "users: invalid JSON response"
						domMu.Lock()
						sec.UsersError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					if env.Users == nil {
						env.Users = []json.RawMessage{}
					}
					domMu.Lock()
					sec.Users = env.Users
					domMu.Unlock()
				}()
			}

			if wantInvites {
				domWG.Add(1)
				go func() {
					defer domWG.Done()
					callCtx, callCancel := context.WithTimeout(overviewCtx, accessDomainTimeout)
					defer callCancel()
					raw, status, err := c.callTarget(callCtx, item.target, http.MethodGet, "/admin/v1/invites", nil, nil)
					if err != nil || status != http.StatusOK {
						msg := "invites: " + extractServiceError(raw, status, err)
						domMu.Lock()
						sec.InvitesError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					var env struct {
						Invites []json.RawMessage `json:"invites"`
					}
					if err := json.Unmarshal(raw, &env); err != nil {
						msg := "invites: invalid JSON response"
						domMu.Lock()
						sec.InvitesError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					if env.Invites == nil {
						env.Invites = []json.RawMessage{}
					}
					domMu.Lock()
					sec.Invites = env.Invites
					domMu.Unlock()
				}()
			}

			if wantAPIKeys {
				domWG.Add(1)
				go func() {
					defer domWG.Done()
					callCtx, callCancel := context.WithTimeout(overviewCtx, accessDomainTimeout)
					defer callCancel()
					raw, status, err := c.callTarget(callCtx, item.target, http.MethodGet, "/admin/v1/api-keys", nil, nil)
					if err != nil || status != http.StatusOK {
						msg := "api_keys: " + extractServiceError(raw, status, err)
						domMu.Lock()
						sec.APIKeysError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					var env struct {
						APIKeys []json.RawMessage `json:"api_keys"`
					}
					if err := json.Unmarshal(raw, &env); err != nil {
						msg := "api_keys: invalid JSON response"
						domMu.Lock()
						sec.APIKeysError = msg
						errs = append(errs, msg)
						domMu.Unlock()
						return
					}
					if env.APIKeys == nil {
						env.APIKeys = []json.RawMessage{}
					}
					domMu.Lock()
					sec.APIKeys = env.APIKeys
					domMu.Unlock()
				}()
			}

			domWG.Wait()
			if len(errs) > 0 {
				sort.Strings(errs)
				sec.Error = strings.Join(errs, "; ")
			}

			secMu.Lock()
			sections = append(sections, sec)
			secMu.Unlock()
		}(p, hasUsers, hasInvites, hasAPIKeys)
	}
	fetchWG.Wait()

	sort.Slice(sections, func(i, j int) bool { return sections[i].Service < sections[j].Service })

	var summary AccessOverviewSummary
	for _, sec := range sections {
		if !sec.Reachable || sec.Error != "" {
			summary.DegradedServices++
		}
		for _, raw := range sec.Users {
			summary.TotalUsers++
			var item struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(raw, &item) == nil {
				switch strings.ToLower(strings.TrimSpace(item.Status)) {
				case "active":
					summary.ActiveUsers++
				case "pending":
					summary.PendingApprovals++
				case "disabled", "denied":
					summary.DisabledUsers++
				}
			}
		}
		for _, raw := range sec.Invites {
			summary.TotalInvites++
			var item struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(raw, &item) == nil && strings.EqualFold(strings.TrimSpace(item.Status), "pending") {
				summary.PendingInvites++
			}
		}
		for _, raw := range sec.APIKeys {
			summary.TotalAPIKeys++
			var item struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(raw, &item) == nil && strings.EqualFold(strings.TrimSpace(item.Status), "active") {
				summary.ActiveAPIKeys++
			}
		}
	}

	discoveryErrMsg := ""
	if discoveryErr != nil {
		discoveryErrMsg = "ops-agent service discovery failed: " + discoveryErr.Error()
		summary.DegradedServices++
	}

	return AccessOverview{
		Summary:        summary,
		Services:       sections,
		DiscoveryError: discoveryErrMsg,
	}
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
	svc, err := ValidateServiceName(service)
	if err != nil {
		return resolvedTarget{}, http.StatusBadRequest, ErrInvalidServiceName
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

func (c *ServiceClient) proxyChecked(
	ctx context.Context,
	service, method, relPath string,
	query url.Values,
	body []byte,
	check func(ServiceManifest) (bool, string),
) (json.RawMessage, int, error) {
	t, status, err := c.resolveValidatedTarget(ctx, service, relPath)
	if err != nil {
		return nil, status, err
	}
	man, mStatus, mErr := c.fetchManifestForTarget(ctx, t)
	if mErr != nil {
		return nil, mStatus, mErr
	}
	if ok, reason := check(man); !ok {
		return nil, http.StatusForbidden, fmt.Errorf("%w: %s", ErrCapabilityUnsupported, reason)
	}
	callCtx, cancel := context.WithTimeout(ctx, serviceCallTimeout)
	defer cancel()
	return c.callTarget(callCtx, t, method, relPath, query, body)
}

func (c *ServiceClient) ProxyWithCapability(ctx context.Context, service, requiredCap, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	return c.proxyChecked(ctx, service, method, relPath, query, body, func(m ServiceManifest) (bool, string) {
		if m.HasCapability(requiredCap) {
			return true, ""
		}
		return false, fmt.Sprintf("service %q does not advertise %q capability", service, requiredCap)
	})
}

func (c *ServiceClient) ProxyWithUserAction(ctx context.Context, service, userAction, method, relPath string, query url.Values, body []byte) (json.RawMessage, int, error) {
	return c.proxyChecked(ctx, service, method, relPath, query, body, func(m ServiceManifest) (bool, string) {
		if m.SupportsUserAction(userAction) {
			return true, ""
		}
		return false, fmt.Sprintf("service %q does not support user action %q", service, userAction)
	})
}

func (c *ServiceClient) ListUsers(ctx context.Context, service string, query url.Values) (json.RawMessage, int, error) {
	return c.ProxyWithCapability(ctx, service, "users", http.MethodGet, "/admin/v1/users", query, nil)
}

func (c *ServiceClient) ApproveUser(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithUserAction(ctx, service, "approve", http.MethodPost, "/admin/v1/users/"+url.PathEscape(validID)+"/approve", nil, nil)
}

func (c *ServiceClient) DenyUser(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithUserAction(ctx, service, "deny", http.MethodPost, "/admin/v1/users/"+url.PathEscape(validID)+"/deny", nil, nil)
}

func (c *ServiceClient) UpdateUserStatus(ctx context.Context, service, id string, body []byte) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithUserAction(ctx, service, "toggle_status", http.MethodPatch, "/admin/v1/users/"+url.PathEscape(validID), nil, body)
}

func (c *ServiceClient) DeleteUser(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithUserAction(ctx, service, "delete", http.MethodDelete, "/admin/v1/users/"+url.PathEscape(validID), nil, nil)
}

func (c *ServiceClient) RevokeUserSessions(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithUserAction(ctx, service, "sessions", http.MethodDelete, "/admin/v1/users/"+url.PathEscape(validID)+"/sessions", nil, nil)
}

func (c *ServiceClient) ListInvites(ctx context.Context, service string) (json.RawMessage, int, error) {
	return c.ProxyWithCapability(ctx, service, "invites", http.MethodGet, "/admin/v1/invites", nil, nil)
}

func (c *ServiceClient) CreateInvite(ctx context.Context, service string, body []byte) (json.RawMessage, int, error) {
	return c.ProxyWithCapability(ctx, service, "invites", http.MethodPost, "/admin/v1/invites", nil, body)
}

func (c *ServiceClient) DeleteInvite(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithCapability(ctx, service, "invites", http.MethodDelete, "/admin/v1/invites/"+url.PathEscape(validID), nil, nil)
}

func (c *ServiceClient) ListAPIKeys(ctx context.Context, service string) (json.RawMessage, int, error) {
	return c.ProxyWithCapability(ctx, service, "api_keys", http.MethodGet, "/admin/v1/api-keys", nil, nil)
}

func (c *ServiceClient) CreateAPIKey(ctx context.Context, service string, body []byte) (json.RawMessage, int, error) {
	return c.ProxyWithCapability(ctx, service, "api_keys", http.MethodPost, "/admin/v1/api-keys", nil, body)
}

func (c *ServiceClient) RevokeAPIKey(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithCapability(ctx, service, "api_keys", http.MethodPost, "/admin/v1/api-keys/"+url.PathEscape(validID)+"/revoke", nil, nil)
}

func (c *ServiceClient) DeleteAPIKey(ctx context.Context, service, id string) (json.RawMessage, int, error) {
	validID, err := ValidateResourceID(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return c.ProxyWithCapability(ctx, service, "api_keys", http.MethodDelete, "/admin/v1/api-keys/"+url.PathEscape(validID), nil, nil)
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
