package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
