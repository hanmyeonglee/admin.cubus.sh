package clients

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"cubus.sh/admin/internal/config"
)

func TestServiceClientSSRFProxyAndRelPathHardening(t *testing.T) {
	// 1. tr.Proxy must be nil so HTTP_PROXY never diverts internal admin traffic.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	staticSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/manifest" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "artifact",
				"capabilities": []string{"settings"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer staticSrv.Close()

	// Mock ops-agent returning a discovered container IP.
	opsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ops/v1/services" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"services": []map[string]any{
					{"service": "choice", "name": "choice", "admin_ip": "172.31.0.129", "port": 9090, "state": "running"},
					{"service": "gw", "name": "gw", "admin_ip": "172.31.0.1", "port": 9090, "state": "running"},
					{"service": "self", "name": "self", "admin_ip": "172.31.0.2", "port": 9090, "state": "running"},
					{"service": "loop", "name": "loop", "admin_ip": "127.0.0.1", "port": 9090, "state": "running"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer opsSrv.Close()

	// 2. When AdminNetworkCIDR is nil, dynamic discovery must FAIL CLOSED, while StaticServices still works.
	cfgNilCIDR := config.Config{
		AdminNetworkCIDR: nil,
		OpsAgentURL:      opsSrv.URL,
		ServiceTokens:    map[string]string{"artifact": "tok-art", "choice": "tok-ch"},
		StaticServices:   map[string]string{"artifact": staticSrv.URL},
	}
	opsCli := NewOpsClient(opsSrv.URL, "")
	svcCli := NewServiceClient(cfgNilCIDR, opsCli)
	if svcCli.transport.Proxy != nil {
		t.Fatalf("expected ServiceClient transport Proxy to be nil")
	}

	targets := svcCli.discoverTargets(context.Background())
	if _, ok := targets["choice"]; ok {
		t.Fatalf("expected dynamic discovery to fail closed when AdminNetworkCIDR == nil, got %+v", targets)
	}
	if _, ok := targets["artifact"]; !ok {
		t.Fatalf("expected StaticServices to remain available when AdminNetworkCIDR == nil")
	}

	// Verify static service call succeeds despite HTTP_PROXY=http://127.0.0.1:1.
	svcs := svcCli.ListServices(context.Background())
	if len(svcs) != 1 || !svcs[0].Reachable || svcs[0].Service != "artifact" {
		t.Fatalf("expected static service reachable bypassing HTTP_PROXY, got %+v", svcs)
	}

	// 3. Verify dynamic admin IP filtering rejects special/gateway/self/out-of-prefix IPs and allows valid peer.
	pfx := netip.MustParsePrefix("172.31.0.0/24")
	localIPs := map[netip.Addr]struct{}{
		netip.MustParseAddr("172.31.0.2"): {},
	}
	rejectedIPs := []string{
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"169.254.169.254",
		"172.31.0.0",   // network
		"172.31.0.1",   // gateway (.1)
		"172.31.0.2",   // self
		"172.31.0.255", // broadcast
		"172.30.0.10",  // outside prefix
	}
	for _, raw := range rejectedIPs {
		addr := netip.MustParseAddr(raw)
		if isAllowedDynamicAdminIP(addr, pfx, localIPs) {
			t.Fatalf("expected dynamic admin IP %s to be rejected", raw)
		}
	}
	if !isAllowedDynamicAdminIP(netip.MustParseAddr("172.31.0.129"), pfx, localIPs) {
		t.Fatalf("expected valid admin peer 172.31.0.129 to be allowed")
	}

	// Also verify loopback/link-local are rejected even if prefix were misconfigured to contain them.
	loopPfx := netip.MustParsePrefix("127.0.0.0/8")
	if isAllowedDynamicAdminIP(netip.MustParseAddr("127.0.0.5"), loopPfx, nil) {
		t.Fatalf("expected loopback IP to be rejected for dynamic discovery even inside prefix")
	}
	llPfx := netip.MustParsePrefix("169.254.0.0/16")
	if isAllowedDynamicAdminIP(netip.MustParseAddr("169.254.169.254"), llPfx, nil) {
		t.Fatalf("expected link-local IP to be rejected for dynamic discovery even inside prefix")
	}

	// Verify discoverTargets with AdminNetworkCIDR set keeps only valid peer ("choice") and drops gw/self/loop.
	cfgWithCIDR := cfgNilCIDR
	cfgWithCIDR.AdminNetworkCIDR = &pfx
	svcCliCIDR := NewServiceClient(cfgWithCIDR, opsCli)
	svcCliCIDR.localIPs = localIPs
	dynTargets := svcCliCIDR.discoverTargets(context.Background())
	if _, ok := dynTargets["choice"]; !ok {
		t.Fatalf("expected valid dynamic peer choice to be discovered")
	}
	for _, bad := range []string{"gw", "self", "loop"} {
		if _, ok := dynTargets[bad]; ok {
			t.Fatalf("expected disallowed dynamic peer %s to be rejected", bad)
		}
	}

	// 4. Verify relPath hardening.
	badPaths := []string{
		"",
		"/admin/v1/",
		"/admin/v2/settings",
		"/ops/v1/system",
		"/admin/v1/../ops/v1/system",
		"/admin/v1/%2e%2e/ops/v1/system",
		"/admin/v1/%2E%2e/secret",
		"/admin/v1/users/%2fsecret",
		"/admin/v1/users/%5csecret",
		"/admin/v1/settings?foo=bar",
		"/admin/v1/settings#frag",
		`/admin/v1/settings\bad`,
		"/admin/v1//settings",
		"/admin/v1/./settings",
		"/admin/v1/settings\r\n",
	}
	for _, p := range badPaths {
		if err := validateAdminRelPath(p); err == nil {
			t.Fatalf("expected validateAdminRelPath(%q) to fail", p)
		}
		if _, status, err := svcCli.Proxy(context.Background(), "artifact", http.MethodGet, p, nil, nil); err == nil || status != http.StatusBadRequest {
			t.Fatalf("expected 400 on disallowed relPath %q, got status=%d err=%v", p, status, err)
		}
	}

	goodPaths := []string{
		"/admin/v1/manifest",
		"/admin/v1/settings",
		"/admin/v1/classify/batch",
		"/admin/v1/users/u-123/approve",
		"/admin/v1/artifacts/art-99",
	}
	for _, p := range goodPaths {
		if err := validateAdminRelPath(p); err != nil {
			t.Fatalf("expected validateAdminRelPath(%q) to pass, got %v", p, err)
		}
	}
}

func TestServiceClientAccessManifestCapabilitiesAndOverview(t *testing.T) {
	// ValidateServiceName & ValidateResourceID strict checks
	for _, badSvc := range []string{"", " ", "../admin", "audown\n", "audown ", "foo/bar", strings.Repeat("a", 65), "-bad"} {
		if _, err := ValidateServiceName(badSvc); !errors.Is(err, ErrInvalidServiceName) {
			t.Fatalf("expected ErrInvalidServiceName for %q, got %v", badSvc, err)
		}
	}
	if got, err := ValidateServiceName("Artifact"); err != nil || got != "artifact" {
		t.Fatalf("expected normalized artifact, got %q err=%v", got, err)
	}
	for _, badID := range []string{"", " ", "u-1\n", " u-1 ", "../x", "a/b", "a%2fb", strings.Repeat("x", 65)} {
		if _, err := ValidateResourceID(badID); !errors.Is(err, ErrInvalidResourceID) {
			t.Fatalf("expected ErrInvalidResourceID for %q, got %v", badID, err)
		}
	}
	if got, err := ValidateResourceID("550e8400-e29b-41d4-a716-446655440000"); err != nil || got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("expected valid UUID, got %q err=%v", got, err)
	}

	var unexpectedActionCalls atomic.Int32
	var audownInvitesFail atomic.Bool

	// 1. Mock artifact (legacy manifest WITHOUT user_capabilities / user_columns)
	artSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "artifact",
				"version":      "0.2.0",
				"capabilities": []string{"users", "settings", "artifacts"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "u-1", "username": "alice", "role": "admin", "status": "active"},
					{"id": "u-2", "username": "bob", "role": "user", "status": "pending"},
				},
			})
		default:
			unexpectedActionCalls.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer artSrv.Close()

	// 2. Mock audown (explicit user_capabilities + user_columns + invites)
	audownSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "audown",
				"version":      "0.2.0",
				"capabilities": []string{"settings", "users", "invites"},
				"user_capabilities": map[string]bool{
					"create":        false,
					"approve":       false,
					"toggle_status": true,
					"delete":        true,
					"sessions":      true,
					"invites":       true,
				},
				"user_columns": []map[string]any{
					{"key": "active_sessions", "label": "Sessions"},
					{"key": "last_login_at", "label": "Last Login", "format": "datetime"},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "11111111-1111-1111-1111-111111111111", "display_name": "Carol", "username": "Carol", "status": "active", "active_sessions": 2},
					{"id": "22222222-2222-2222-2222-222222222222", "display_name": "Dave", "username": "Dave", "status": "disabled", "active_sessions": 0},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/invites":
			if audownInvitesFail.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "database store unavailable"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invites": []map[string]any{
					{"id": "inv-1", "display_name": "Eve", "status": "pending"},
					{"id": "inv-2", "display_name": "Frank", "status": "used"},
				},
			})
		default:
			unexpectedActionCalls.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer audownSrv.Close()

	// 3. Mock choice (api_keys only)
	choiceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "choice",
				"version":      "0.1.0",
				"model":        "amber-150m",
				"capabilities": []string{"settings", "classify", "api_keys"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/api-keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_keys": []map[string]any{
					{"id": "k-1", "name": "CI", "key_prefix": "chk_12345678", "status": "active"},
					{"id": "k-2", "name": "Old", "key_prefix": "chk_87654321", "status": "revoked"},
				},
			})
		default:
			unexpectedActionCalls.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer choiceSrv.Close()

	// 4. Mock settings-only service (should be excluded from access overview)
	settingsOnlySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/manifest" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "misc",
				"capabilities": []string{"settings"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer settingsOnlySrv.Close()

	// 5. Offline service (closed listener)
	offlineSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	offlineURL := offlineSrv.URL
	offlineSrv.Close()

	cfg := config.Config{
		ServiceTokens: map[string]string{
			"artifact": "tok-art",
			"audown":   "tok-aud",
			"choice":   "tok-ch",
			"misc":     "tok-misc",
			"offline":  "tok-off",
		},
		StaticServices: map[string]string{
			"artifact": artSrv.URL,
			"audown":   audownSrv.URL,
			"choice":   choiceSrv.URL,
			"misc":     settingsOnlySrv.URL,
			"offline":  offlineURL,
		},
	}
	cli := NewServiceClient(cfg, nil)

	// Verify FetchManifest parses user_capabilities & user_columns cleanly
	audMan, status, err := cli.FetchManifest(context.Background(), "audown")
	if err != nil || status != http.StatusOK {
		t.Fatalf("FetchManifest(audown) failed: status=%d err=%v", status, err)
	}
	if !audMan.SupportsUserAction("toggle_status") || !audMan.SupportsUserAction("delete") || !audMan.SupportsUserAction("sessions") {
		t.Fatalf("expected audown user actions to be supported: %+v", audMan.UserCapabilities)
	}
	if audMan.SupportsUserAction("approve") || audMan.SupportsUserAction("deny") {
		t.Fatalf("expected audown approve/deny to be unsupported")
	}
	if len(audMan.UserColumns) != 2 || audMan.UserColumns[1].Format != "datetime" {
		t.Fatalf("unexpected audown user_columns: %+v", audMan.UserColumns)
	}

	// Verify legacy artifact manifest backward compatibility
	artMan, status, err := cli.FetchManifest(context.Background(), "artifact")
	if err != nil || status != http.StatusOK {
		t.Fatalf("FetchManifest(artifact) failed: status=%d err=%v", status, err)
	}
	if !artMan.SupportsUserAction("approve") || !artMan.SupportsUserAction("deny") {
		t.Fatalf("expected legacy artifact approve/deny to be supported")
	}
	if artMan.SupportsUserAction("toggle_status") || artMan.SupportsUserAction("delete") || artMan.SupportsUserAction("sessions") {
		t.Fatalf("expected legacy artifact toggle_status/delete/sessions to be unsupported")
	}

	// Verify capability enforcement blocks disallowed actions BEFORE hitting upstream endpoint
	if _, st, err := cli.UpdateUserStatus(context.Background(), "artifact", "u-1", []byte(`{"status":"disabled"}`)); st != http.StatusForbidden || !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("expected 403 ErrCapabilityUnsupported for artifact toggle_status, got status=%d err=%v", st, err)
	}
	if _, st, err := cli.ApproveUser(context.Background(), "audown", "11111111-1111-1111-1111-111111111111"); st != http.StatusForbidden || !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("expected 403 ErrCapabilityUnsupported for audown approve, got status=%d err=%v", st, err)
	}
	if _, st, err := cli.ListInvites(context.Background(), "choice"); st != http.StatusForbidden || !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("expected 403 ErrCapabilityUnsupported for choice invites, got status=%d err=%v", st, err)
	}
	if _, st, err := cli.ListAPIKeys(context.Background(), "audown"); st != http.StatusForbidden || !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("expected 403 ErrCapabilityUnsupported for audown api-keys, got status=%d err=%v", st, err)
	}
	if unexpectedActionCalls.Load() != 0 {
		t.Fatalf("capability enforcement failed to block upstream call; got %d unexpected calls", unexpectedActionCalls.Load())
	}

	// Verify FetchAccessOverview aggregates all access services + reports offline degradation
	ov := cli.FetchAccessOverview(context.Background())
	if ov.Summary.TotalUsers != 4 || ov.Summary.ActiveUsers != 2 || ov.Summary.PendingApprovals != 1 || ov.Summary.DisabledUsers != 1 {
		t.Fatalf("unexpected user summary: %+v", ov.Summary)
	}
	if ov.Summary.TotalInvites != 2 || ov.Summary.PendingInvites != 1 {
		t.Fatalf("unexpected invite summary: %+v", ov.Summary)
	}
	if ov.Summary.TotalAPIKeys != 2 || ov.Summary.ActiveAPIKeys != 1 {
		t.Fatalf("unexpected api key summary: %+v", ov.Summary)
	}
	if ov.Summary.DegradedServices != 1 {
		t.Fatalf("expected 1 degraded service (offline), got %d", ov.Summary.DegradedServices)
	}
	// Expect artifact, audown, choice, offline (NOT misc)
	if len(ov.Services) != 4 {
		t.Fatalf("expected 4 services in access overview, got %d: %+v", len(ov.Services), ov.Services)
	}
	for _, s := range ov.Services {
		if s.Service == "misc" {
			t.Fatalf("settings-only service misc should not appear in access overview")
		}
		if s.Service == "offline" && (s.Reachable || s.Error == "") {
			t.Fatalf("expected offline service to report Reachable=false and Error, got %+v", s)
		}
	}

	// Verify partial domain failure inside a reachable service degrades gracefully
	audownInvitesFail.Store(true)
	ovPartial := cli.FetchAccessOverview(context.Background())
	if ovPartial.Summary.DegradedServices != 2 {
		t.Fatalf("expected 2 degraded services (offline + audown invites 503), got %d", ovPartial.Summary.DegradedServices)
	}
	if ovPartial.Summary.TotalUsers != 4 {
		t.Fatalf("expected audown users to still load despite invites 503, got total_users=%d", ovPartial.Summary.TotalUsers)
	}
	var foundAudown bool
	for _, s := range ovPartial.Services {
		if s.Service == "audown" {
			foundAudown = true
			if !strings.Contains(s.InvitesError, "database store unavailable") || len(s.Users) != 2 {
				t.Fatalf("unexpected audown partial degradation state: %+v", s)
			}
		}
	}
	if !foundAudown {
		t.Fatalf("audown missing from partial overview")
	}

	// Verify ops-agent discovery errors are surfaced as discovery_error and count toward degraded_services.
	failingOps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"ops unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer failingOps.Close()

	pfx := netip.MustParsePrefix("172.31.0.0/24")
	cfgOpsFail := config.Config{
		AdminNetworkCIDR: &pfx,
		OpsAgentURL:      failingOps.URL,
	}
	opsFailCli := NewServiceClient(cfgOpsFail, NewOpsClient(failingOps.URL, ""))
	ovOpsFail := opsFailCli.FetchAccessOverview(context.Background())
	if ovOpsFail.DiscoveryError == "" || ovOpsFail.Summary.DegradedServices != 1 {
		t.Fatalf("expected discovery_error and degraded_services=1 when ops-agent fails, got %+v", ovOpsFail)
	}

	// Verify modern manifest with explicit empty user_capabilities:{} and user_columns:[] serializes as {} and [] (not null).
	emptyModernSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/manifest":
			_, _ = w.Write([]byte(`{"service":"modern","capabilities":["users"],"user_capabilities":{},"user_columns":[]}`))
		case "/admin/v1/users":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer emptyModernSrv.Close()

	modernCli := NewServiceClient(config.Config{
		ServiceTokens:  map[string]string{"modern": "tok-mod", "artifact": "tok-art"},
		StaticServices: map[string]string{"modern": emptyModernSrv.URL, "artifact": artSrv.URL},
	}, nil)
	ovModern := modernCli.FetchAccessOverview(context.Background())
	rawModern, err := json.Marshal(ovModern)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawModern), `"service":"modern"`) || !strings.Contains(string(rawModern), `"user_capabilities":{},"user_columns":[]`) {
		t.Fatalf("expected explicit empty user_capabilities/user_columns to be preserved in JSON, got %s", string(rawModern))
	}
	if !strings.Contains(string(rawModern), `"service":"artifact"`) || !strings.Contains(string(rawModern), `"user_capabilities":null,"user_columns":null`) {
		t.Fatalf("expected legacy artifact manifest to serialize null user_capabilities/user_columns, got %s", string(rawModern))
	}
}
