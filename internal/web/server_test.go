package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"cubus.sh/admin/internal/auth"
	"cubus.sh/admin/internal/clients"
	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/store"
)

func TestAdminWebEndToEndProxyAuditCSRFAndSSE(t *testing.T) {
	// Mock artifact internal :9090 Admin API
	var deletedID string
	artSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-artifact-secret" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "artifact",
				"version":      "0.2.0",
				"capabilities": []string{"users", "settings", "artifacts"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/users/u-123/approve":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u-123", "status": "active"})
		case r.Method == http.MethodPatch && r.URL.Path == "/admin/v1/settings":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		case r.Method == http.MethodDelete && r.URL.Path == "/admin/v1/artifacts/art-99":
			deletedID = "art-99"
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true, "id": "art-99"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer artSrv.Close()

	// Mock ops-agent
	opsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ops/v1/system":
			_ = json.NewEncoder(w).Encode(map[string]any{"cpu": map[string]any{"usage_pct": 14.2}, "history": []any{}})
		case "/ops/v1/containers":
			_ = json.NewEncoder(w).Encode(map[string]any{"containers": []map[string]any{{"service": "artifact", "state": "running"}}})
		case "/ops/v1/services":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{}})
		case "/ops/v1/logs/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": []map[string]any{{"service": "artifact", "level": "info", "message": "boot ok"}}, "count": 1})
		case "/ops/v1/logs/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"service\":\"artifact\",\"message\":\"live line\"}\n\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer opsSrv.Close()

	// Mock db-broker read-only stats
	dbStatsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"server_version": "18.7", "databases": []any{}})
	}))
	defer dbStatsSrv.Close()

	pfx := netip.MustParsePrefix("127.0.0.0/8")
	cfg := config.Config{
		PublicBaseURL:    "http://127.0.0.1:8000",
		PublicIsLoopback: true,
		AuthMode:         config.AuthModeDev,
		DevAuthEmail:     "owner@cubus.sh",
		AllowedEmails:    map[string]struct{}{"owner@cubus.sh": {}},
		AdminNetworkCIDR: &pfx,
		OpsAgentURL:      opsSrv.URL,
		DBStatsURL:       dbStatsSrv.URL,
		ServiceTokens:    map[string]string{"artifact": "tok-artifact-secret"},
		StaticServices:   map[string]string{"artifact": artSrv.URL},
	}

	st := store.NewMemoryStore()
	authenticator, err := auth.NewAuthenticator(context.Background(), cfg, st, auth.AuthenticatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	opsCli := clients.NewOpsClient(cfg.OpsAgentURL, "")
	dbStatsCli := clients.NewDBStatsClient(cfg.DBStatsURL)
	svcCli := clients.NewServiceClient(cfg, opsCli)
	srv, err := New(cfg, st, authenticator, opsCli, dbStatsCli, svcCli, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// 1. Non-loopback peer rejected in dev mode.
	badPeer := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	badPeer.RemoteAddr = "203.0.113.5:50000"
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badPeer)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback dev peer, got %d", badRec.Code)
	}

	// 2. GET / returns SSR page with strict CSP, X-Frame-Options: DENY, and CSRF cookie.
	homeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	homeReq.RemoteAddr = "127.0.0.1:50001"
	homeRec := httptest.NewRecorder()
	h.ServeHTTP(homeRec, homeReq)
	if homeRec.Code != http.StatusOK || homeRec.Header().Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(homeRec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("unexpected home response: %d headers=%v", homeRec.Code, homeRec.Header())
	}
	csrfCookie := homeRec.Result().Cookies()[0]

	// 3. GET /api/overview combines system, containers, db_stats, and discovered services.
	ovReq := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	ovReq.RemoteAddr = "127.0.0.1:50002"
	ovRec := httptest.NewRecorder()
	h.ServeHTTP(ovRec, ovReq)
	if ovRec.Code != http.StatusOK || !strings.Contains(ovRec.Body.String(), `"server_version":"18.7"`) {
		t.Fatalf("unexpected overview: %d %s", ovRec.Code, ovRec.Body.String())
	}

	// 4. Write without CSRF fails with 403 and MUST NOT emit Set-Cookie (no CSRF cookie desync);
	//    cross-site write fails with 403.
	noCSRF := httptest.NewRequest(http.MethodPost, "/api/services/artifact/users/u-123/approve", nil)
	noCSRF.RemoteAddr = "127.0.0.1:50003"
	noCSRFRec := httptest.NewRecorder()
	h.ServeHTTP(noCSRFRec, noCSRF)
	if noCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", noCSRFRec.Code)
	}
	if len(noCSRFRec.Result().Cookies()) != 0 {
		t.Fatalf("rejected 403 write unexpectedly mutated cookies: %+v", noCSRFRec.Result().Cookies())
	}

	xSite := httptest.NewRequest(http.MethodPost, "/api/services/artifact/users/u-123/approve", nil)
	xSite.RemoteAddr = "127.0.0.1:50003"
	xSite.AddCookie(csrfCookie)
	xSite.Header.Set("X-CSRF-Token", csrfCookie.Value)
	xSite.Header.Set("Origin", "https://evil.example")
	xSite.Header.Set("Sec-Fetch-Site", "cross-site")
	xSiteRec := httptest.NewRecorder()
	h.ServeHTTP(xSiteRec, xSite)
	if xSiteRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-site write, got %d", xSiteRec.Code)
	}

	// Form-body csrf_token fallback is restricted strictly to POST /logout, not /api/* writes.
	formAPIBypass := httptest.NewRequest(http.MethodPost, "/api/services/artifact/users/u-123/approve", strings.NewReader("csrf_token="+url.QueryEscape(csrfCookie.Value)))
	formAPIBypass.RemoteAddr = "127.0.0.1:50003"
	formAPIBypass.AddCookie(csrfCookie)
	formAPIBypass.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formAPIBypass.Header.Set("Origin", "http://127.0.0.1:8000")
	formAPIBypassRec := httptest.NewRecorder()
	h.ServeHTTP(formAPIBypassRec, formAPIBypass)
	if formAPIBypassRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when /api write omits X-CSRF-Token header, got %d", formAPIBypassRec.Code)
	}

	// 5. Valid mutations succeed and append audit_logs rows.
	doWrite := func(method, path string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.RemoteAddr = "127.0.0.1:50004"
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		req.Header.Set("Origin", "http://127.0.0.1:8000")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := doWrite(http.MethodPost, "/api/services/artifact/users/u-123/approve", ""); rec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doWrite(http.MethodPatch, "/api/services/artifact/settings", `{"max_upload_mb":25}`); rec.Code != http.StatusOK {
		t.Fatalf("settings patch failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doWrite(http.MethodDelete, "/api/services/artifact/artifacts/art-99", ""); rec.Code != http.StatusOK || deletedID != "art-99" {
		t.Fatalf("artifact delete failed: %d %s", rec.Code, rec.Body.String())
	}

	// Traversal ID rejected with 400.
	if rec := doWrite(http.MethodDelete, "/api/services/artifact/artifacts/bad%2Fid", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad artifact ID, got %d", rec.Code)
	}

	// Audit log contains all 3 mutations.
	audReq := httptest.NewRequest(http.MethodGet, "/api/audit?service=artifact", nil)
	audReq.RemoteAddr = "127.0.0.1:50005"
	audRec := httptest.NewRecorder()
	h.ServeHTTP(audRec, audReq)
	var audResp struct {
		AuditLogs []store.AuditLog `json:"audit_logs"`
	}
	if err := json.Unmarshal(audRec.Body.Bytes(), &audResp); err != nil || len(audResp.AuditLogs) != 3 {
		t.Fatalf("expected 3 audit log entries, got %d err=%v body=%s", len(audResp.AuditLogs), err, audRec.Body.String())
	}

	// 6. SSE log stream proxy forwards upstream data frames cleanly.
	streamReq := httptest.NewRequest(http.MethodGet, "/api/logs/stream?service=artifact", nil)
	streamReq.RemoteAddr = "127.0.0.1:50006"
	streamRec := httptest.NewRecorder()
	h.ServeHTTP(streamRec, streamReq)
	if streamRec.Code != http.StatusOK || !strings.Contains(streamRec.Body.String(), "live line") ||
		streamRec.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected SSE stream response: %d headers=%v body=%q", streamRec.Code, streamRec.Header(), streamRec.Body.String())
	}

	// 7. SSE metrics stream returns 200 text/event-stream and closes cleanly on client cancel.
	mCtx, mCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer mCancel()
	mReq := httptest.NewRequest(http.MethodGet, "/api/stream/metrics", nil).WithContext(mCtx)
	mReq.RemoteAddr = "127.0.0.1:50007"
	mRec := httptest.NewRecorder()
	h.ServeHTTP(mRec, mReq)
	if mRec.Code != http.StatusOK || !strings.Contains(mRec.Header().Get("Content-Type"), "text/event-stream") ||
		mRec.Header().Get("X-Accel-Buffering") != "no" || !strings.Contains(mRec.Body.String(), ": connected") {
		t.Fatalf("unexpected metrics SSE response: %d headers=%v body=%q", mRec.Code, mRec.Header(), mRec.Body.String())
	}

	// 8. POST /logout rejects missing CSRF token and succeeds with valid form-encoded csrf_token.
	badLogout := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=invalid"))
	badLogout.RemoteAddr = "127.0.0.1:50008"
	badLogout.AddCookie(csrfCookie)
	badLogout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badLogout.Header.Set("Origin", "http://127.0.0.1:8000")
	badLogoutRec := httptest.NewRecorder()
	h.ServeHTTP(badLogoutRec, badLogout)
	if badLogoutRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid logout CSRF, got %d", badLogoutRec.Code)
	}

	form := url.Values{"csrf_token": {csrfCookie.Value}}.Encode()
	okLogout := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form))
	okLogout.RemoteAddr = "127.0.0.1:50008"
	okLogout.AddCookie(csrfCookie)
	okLogout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okLogout.Header.Set("Origin", "http://127.0.0.1:8000")
	okLogoutRec := httptest.NewRecorder()
	h.ServeHTTP(okLogoutRec, okLogout)
	if okLogoutRec.Code != http.StatusSeeOther || okLogoutRec.Header().Get("Location") != "/login?logged_out=1" {
		t.Fatalf("unexpected logout response: %d loc=%q", okLogoutRec.Code, okLogoutRec.Header().Get("Location"))
	}
}

func TestTablerStaticVendoringAndStrictCSP(t *testing.T) {
	artSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":      "artifact",
			"version":      "0.2.0",
			"capabilities": []string{"users", "settings", "artifacts"},
		})
	}))
	defer artSrv.Close()

	pfx := netip.MustParsePrefix("127.0.0.0/8")
	devCfg := config.Config{
		PublicBaseURL:    "http://127.0.0.1:8000",
		PublicIsLoopback: true,
		AuthMode:         config.AuthModeDev,
		DevAuthEmail:     "owner@cubus.sh",
		AllowedEmails:    map[string]struct{}{"owner@cubus.sh": {}},
		AdminNetworkCIDR: &pfx,
		ServiceTokens:    map[string]string{"artifact": "tok-artifact-secret"},
		StaticServices:   map[string]string{"artifact": artSrv.URL},
	}

	devStore := store.NewMemoryStore()
	devAuth, err := auth.NewAuthenticator(context.Background(), devCfg, devStore, auth.AuthenticatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	devSrv, err := New(devCfg, devStore, devAuth, nil, nil, clients.NewServiceClient(devCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := devSrv.Handler()

	// 1. Vendored static assets are served with expected headers and non-empty payloads; directories return 404.
	staticFiles := []struct {
		path       string
		wantCTPref string
	}{
		{"/static/vendor/tabler.min.css", "text/css"},
		{"/static/vendor/tabler.min.js", "text/javascript"},
		{"/static/vendor/chart.umd.min.js", "text/javascript"},
		{"/static/vendor/LICENSES.txt", "text/plain"},
		{"/static/admin.css", "text/css"},
		{"/static/admin.js", "text/javascript"},
	}
	if len(devSrv.assetVersion) != 12 {
		t.Fatalf("expected 12-char assetVersion, got %q", devSrv.assetVersion)
	}
	fetchedAssets := make(map[string]string, len(staticFiles))
	for _, sf := range staticFiles {
		// Without ?v or with stale ?v: must serve Cache-Control: no-cache
		for _, reqPath := range []string{sf.path, sf.path + "?v=stale0000000"} {
			req := httptest.NewRequest(http.MethodGet, reqPath, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
				t.Fatalf("GET %s failed: status=%d len=%d", reqPath, rec.Code, rec.Body.Len())
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
				t.Fatalf("GET %s expected Cache-Control=no-cache, got %q", reqPath, cc)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, sf.wantCTPref) && !(sf.wantCTPref == "text/javascript" && strings.Contains(ct, "javascript")) {
				t.Fatalf("GET %s unexpected Content-Type %q", reqPath, ct)
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("GET %s missing nosniff header", reqPath)
			}
			if reqPath == sf.path {
				fetchedAssets[sf.path] = rec.Body.String()
			}
		}

		// With matching ?v=<assetVersion>: must serve immutable long-lived Cache-Control
		vPath := sf.path + "?v=" + devSrv.assetVersion
		vReq := httptest.NewRequest(http.MethodGet, vPath, nil)
		vRec := httptest.NewRecorder()
		h.ServeHTTP(vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d", vPath, vRec.Code)
		}
		if cc := vRec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
			t.Fatalf("GET %s expected immutable Cache-Control, got %q", vPath, cc)
		}
	}
	for _, dirPath := range []string{"/static/", "/static/vendor/"} {
		req := httptest.NewRequest(http.MethodGet, dirPath, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for static directory %s, got %d", dirPath, rec.Code)
		}
	}

	// 2. Vendored & custom CSS contain zero external network URLs, @import, @font-face, or sourceMappingURL;
	//    admin.css stays minimal and free of legacy custom widget overrides.
	externalCSSRef := regexp.MustCompile(`(?i)(@import|@font-face|url\(\s*["']?(?:https?:)?//|sourceMappingURL)`)
	for _, cssPath := range []string{"/static/vendor/tabler.min.css", "/static/admin.css"} {
		if m := externalCSSRef.FindString(fetchedAssets[cssPath]); m != "" {
			t.Fatalf("%s contains forbidden external or map reference: %q", cssPath, m)
		}
	}
	adminCSS := fetchedAssets["/static/admin.css"]
	if lines := len(strings.Split(strings.TrimSpace(adminCSS), "\n")); lines > 35 {
		t.Fatalf("admin.css exceeded minimal 35-line budget: got %d lines", lines)
	}
	for _, legacy := range []string{".grid-cards", ".panel", ".pill", ".admin-modal", ".admin-backdrop"} {
		if strings.Contains(adminCSS, legacy) {
			t.Fatalf("admin.css contains legacy custom class %q", legacy)
		}
	}
	if !strings.Contains(fetchedAssets["/static/vendor/LICENSES.txt"], "@tabler/core") ||
		!strings.Contains(fetchedAssets["/static/vendor/LICENSES.txt"], "chart.js") ||
		!strings.Contains(fetchedAssets["/static/vendor/LICENSES.txt"], "MIT License") {
		t.Fatalf("LICENSES.txt missing expected library or MIT License text")
	}

	// 3. Vendored JS and admin.js are strictly CSP-clean and free of dangerous sinks.
	styleElemPattern := regexp.MustCompile(`createElement\s*\(\s*["']style["']`)
	evalPattern := regexp.MustCompile(`\beval\s*\(`)
	newFuncPattern := regexp.MustCompile(`new\s+Function\s*\(`)
	for _, jsPath := range []string{"/static/vendor/tabler.min.js", "/static/vendor/chart.umd.min.js", "/static/admin.js"} {
		body := fetchedAssets[jsPath]
		if strings.Contains(body, "sourceMappingURL") {
			t.Fatalf("%s contains sourceMappingURL", jsPath)
		}
		if evalPattern.MatchString(body) || newFuncPattern.MatchString(body) {
			t.Fatalf("%s contains eval or new Function", jsPath)
		}
		if styleElemPattern.MatchString(body) || strings.Contains(body, "insertAdjacentHTML") || strings.Contains(body, "document.write") {
			t.Fatalf("%s contains style injection or document.write/insertAdjacentHTML", jsPath)
		}
	}
	chartJS := fetchedAssets["/static/vendor/chart.umd.min.js"]
	for _, forbidden := range []string{"innerHTML", "outerHTML", `setAttribute("style"`, `setAttribute('style'`} {
		if strings.Contains(chartJS, forbidden) {
			t.Fatalf("chart.umd.min.js contains forbidden DOM sink %q", forbidden)
		}
	}
	jsBody := fetchedAssets["/static/admin.js"]
	for _, forbidden := range []string{
		"innerHTML",
		"outerHTML",
		"insertAdjacentHTML",
		"document.write",
		"setAttribute(\"style\"",
		"setAttribute('style'",
		"eval(",
		"new Function(",
		".grid-cards",
		"admin-modal",
		"admin-backdrop",
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("admin.js contains forbidden pattern %q", forbidden)
		}
	}
	for _, required := range []string{
		"AbortController",
		"WeakMap",
		"safeViewerURL",
		"pageshow",
		"packClassifyBatches",
		"CLASSIFY_MAX_BYTES",
		"tailClassifyPending",
		"autoTailScanRunning",
		"tailReconnecting",
		"clearTailReconnectTimer",
		"resetTailDedup",
	} {
		if !strings.Contains(jsBody, required) {
			t.Fatalf("admin.js missing required safety/lifecycle pattern %q", required)
		}
	}

	// 4. SSR app pages render with Tabler CSS+JS, Chart.js (overview), ?v=<hash>, strict CSP, zero modal-backdrop,
	//    zero inline style=/on*=/scripts, and zero external refs.
	inlineStyleAttr := regexp.MustCompile(`(?i)\sstyle\s*=`)
	inlineEventAttr := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	inlineStyleTag := regexp.MustCompile(`(?i)<style[\s>]`)
	externalHTMLRef := regexp.MustCompile(`(?i)<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["']?\s*(?:https?:)?//`)
	scriptTagPattern := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

	assertPageSecure := func(t *testing.T, handler http.Handler, path, assetVer string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:50100"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", path, rec.Code, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp != adminCSP {
			t.Fatalf("GET %s unexpected CSP %q (want %q)", path, csp, adminCSP)
		}
		body := rec.Body.String()
		for _, want := range []string{
			`href="/static/vendor/tabler.min.css?v=` + assetVer + `"`,
			`href="/static/admin.css?v=` + assetVer + `"`,
			`src="/static/vendor/tabler.min.js?v=` + assetVer + `"`,
			`src="/static/admin.js?v=` + assetVer + `"`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("GET %s missing %s", path, want)
			}
		}
		for _, forbiddenHTML := range []string{"modal-backdrop", "admin-modal", "admin-backdrop", "grid-cards"} {
			if strings.Contains(body, forbiddenHTML) {
				t.Fatalf("GET %s contains forbidden legacy/backdrop markup %q", path, forbiddenHTML)
			}
		}
		if m := inlineStyleAttr.FindString(body); m != "" {
			t.Fatalf("GET %s contains inline style attribute %q", path, m)
		}
		if m := inlineEventAttr.FindString(body); m != "" {
			t.Fatalf("GET %s contains inline event attribute %q", path, m)
		}
		if inlineStyleTag.MatchString(body) {
			t.Fatalf("GET %s contains inline <style> tag", path)
		}
		if m := externalHTMLRef.FindString(body); m != "" {
			t.Fatalf("GET %s contains external <link>/<script> reference %q", path, m)
		}
		for _, sm := range scriptTagPattern.FindAllStringSubmatch(body, -1) {
			attrs, inner := sm[1], strings.TrimSpace(sm[2])
			if !strings.Contains(attrs, `src="/static/`) || inner != "" {
				t.Fatalf("GET %s contains disallowed/inline <script attrs=%q inner=%q>", path, attrs, inner)
			}
		}
		return body
	}

	ovBody := assertPageSecure(t, h, "/", devSrv.assetVersion)
	if !strings.Contains(ovBody, `src="/static/vendor/chart.umd.min.js?v=`+devSrv.assetVersion+`"`) {
		t.Fatalf("GET / missing versioned chart.umd.min.js script tag")
	}
	for _, p := range []string{"/", "/logs", "/audit", "/services/artifact"} {
		body := assertPageSecure(t, h, p, devSrv.assetVersion)
		for _, marker := range []string{
			"data-theme-toggle",
			`data-bs-toggle="collapse" data-bs-target="#sidebar-menu"`,
			`id="confirm-modal"`,
			`id="toast"`,
			`name="csrf_token"`,
			"align-items-center d-lg-none",
		} {
			if !strings.Contains(body, marker) {
				t.Fatalf("GET %s missing expected UI element %q", p, marker)
			}
		}
	}
	if logsBody := assertPageSecure(t, h, "/logs", devSrv.assetVersion); !strings.Contains(logsBody, `role="switch"`) ||
		!strings.Contains(logsBody, `id="log-scan-rules-btn"`) ||
		!strings.Contains(logsBody, `id="log-scan-amber-btn"`) ||
		!strings.Contains(logsBody, `id="log-scan-both-btn"`) ||
		!strings.Contains(logsBody, `id="log-auto-rules"`) ||
		!strings.Contains(logsBody, `id="log-class-filter"`) ||
		!strings.Contains(logsBody, `id="log-detail-modal"`) {
		t.Fatalf("GET /logs missing expected classification UI controls")
	}
	if auditBody := assertPageSecure(t, h, "/audit", devSrv.assetVersion); !strings.Contains(auditBody, `id="audit-older-btn"`) ||
		!strings.Contains(auditBody, `id="audit-footer"`) {
		t.Fatalf("GET /audit missing pagination footer/button")
	}
	if svcUpperBody := assertPageSecure(t, h, "/services/Artifact", devSrv.assetVersion); !strings.Contains(svcUpperBody, `class="nav-item active" data-nav-service="artifact"`) ||
		!strings.Contains(svcUpperBody, `role="tabpanel"`) {
		t.Fatalf("GET /services/Artifact did not normalize active sidebar state or tabpanel role")
	}

	// Unconfigured ops-agent cleanly returns 503 on metrics SSE endpoint.
	unconfStreamReq := httptest.NewRequest(http.MethodGet, "/api/stream/metrics", nil)
	unconfStreamReq.RemoteAddr = "127.0.0.1:50101"
	unconfStreamRec := httptest.NewRecorder()
	h.ServeHTTP(unconfStreamRec, unconfStreamReq)
	if unconfStreamRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when ops-agent unconfigured, got %d", unconfStreamRec.Code)
	}

	// 5. Login page in Google auth mode and Cloudflare-only mode both use Tabler + strict CSP + cache busting.
	googleCfg := config.Config{
		PublicBaseURL:      "https://admin.cubus.sh",
		PublicIsHTTPS:      true,
		AuthMode:           config.AuthModeGoogle,
		AllowedEmails:      map[string]struct{}{"owner@cubus.sh": {}},
		GoogleClientID:     "client-id",
		GoogleClientSecret: "client-secret",
	}
	googleStore := store.NewMemoryStore()
	googleAuth, err := auth.NewAuthenticator(context.Background(), googleCfg, googleStore, auth.AuthenticatorOptions{
		GoogleAuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
		GoogleTokenEndpoint: "https://oauth2.googleapis.com/token",
		GoogleJWKSURLOverride: "https://www.googleapis.com/oauth2/v3/certs",
	})
	if err != nil {
		t.Fatal(err)
	}
	googleSrv, err := New(googleCfg, googleStore, googleAuth, nil, nil, clients.NewServiceClient(googleCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	loginBody := assertPageSecure(t, googleSrv.Handler(), "/login", googleSrv.assetVersion)
	if !strings.Contains(loginBody, "Sign in with Google") || !strings.Contains(loginBody, "data-theme-toggle") {
		t.Fatalf("GET /login missing expected login UI controls")
	}

	cfCfg := config.Config{
		PublicBaseURL:      "https://admin.cubus.sh",
		PublicIsHTTPS:      true,
		AuthMode:           config.AuthModeCloudflare,
		CFAccessTeamDomain: "https://cubus.cloudflareaccess.com",
		CFAccessAUD:        "aud-test",
		AllowedEmails:      map[string]struct{}{"owner@cubus.sh": {}},
	}
	cfStore := store.NewMemoryStore()
	cfAuth, err := auth.NewAuthenticator(context.Background(), cfCfg, cfStore, auth.AuthenticatorOptions{
		CFJWKSURLOverride: "https://cubus.cloudflareaccess.com/cdn-cgi/access/certs",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfSrv, err := New(cfCfg, cfStore, cfAuth, nil, nil, clients.NewServiceClient(cfCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cfLoginBody := assertPageSecure(t, cfSrv.Handler(), "/login", cfSrv.assetVersion)
	if !strings.Contains(cfLoginBody, "Cf-Access-Jwt-Assertion") || strings.Contains(cfLoginBody, "Sign in with Google") ||
		!strings.Contains(cfLoginBody, "https://cubus.cloudflareaccess.com/cdn-cgi/access/logout") {
		t.Fatalf("GET /login in CloudflareOnly mode missing expected content: %s", cfLoginBody)
	}
}

func TestLogClassifyAPIAndAmberFallback(t *testing.T) {
	var choiceFail bool
	var choiceBatchCalls int
	var lastBatchItems int

	choiceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-choice-secret" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "choice",
				"version":      "0.1.0",
				"model":        "amber-150m",
				"capabilities": []string{"settings", "classify"},
				"endpoints": map[string]string{
					"classify_batch": "POST /admin/v1/classify/batch",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/classify/batch":
			if choiceFail {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "GPU worker warming up"})
				return
			}
			choiceBatchCalls++
			var req struct {
				Prompt string            `json:"prompt"`
				Labels map[string]string `json:"labels"`
				Items  []struct {
					ID   string `json:"id"`
					Text string `json:"text"`
				} `json:"items"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			lastBatchItems = len(req.Items)
			results := make([]map[string]any, 0, len(req.Items))
			for _, it := range req.Items {
				choice := "normal"
				probs := map[string]float64{
					"normal":            0.90,
					"operational_error": 0.05,
					"suspicious_recon":  0.03,
					"malicious_attack":  0.02,
				}
				if strings.Contains(it.Text, "UNION") || strings.Contains(it.Text, "sqlmap") {
					choice = "malicious_attack"
					probs = map[string]float64{
						"normal":            0.01,
						"operational_error": 0.02,
						"suspicious_recon":  0.12,
						"malicious_attack":  0.85,
					}
				} else if strings.Contains(it.Text, ".env") {
					choice = "suspicious_recon"
					probs = map[string]float64{
						"normal":            0.05,
						"operational_error": 0.05,
						"suspicious_recon":  0.80,
						"malicious_attack":  0.10,
					}
				}
				results = append(results, map[string]any{
					"id":            it.ID,
					"choice":        choice,
					"probabilities": probs,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model":   "amber-150m",
				"results": results,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer choiceSrv.Close()

	pfx := netip.MustParsePrefix("127.0.0.0/8")
	cfg := config.Config{
		PublicBaseURL:    "http://127.0.0.1:8000",
		PublicIsLoopback: true,
		AuthMode:         config.AuthModeDev,
		DevAuthEmail:     "owner@cubus.sh",
		AllowedEmails:    map[string]struct{}{"owner@cubus.sh": {}},
		AdminNetworkCIDR: &pfx,
		ServiceTokens:    map[string]string{"choice": "tok-choice-secret"},
		StaticServices:   map[string]string{"choice": choiceSrv.URL},
	}

	st := store.NewMemoryStore()
	authenticator, err := auth.NewAuthenticator(context.Background(), cfg, st, auth.AuthenticatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	svcCli := clients.NewServiceClient(cfg, nil)
	srv, err := New(cfg, st, authenticator, nil, nil, svcCli, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Obtain CSRF cookie from /logs
	logsReq := httptest.NewRequest(http.MethodGet, "/logs", nil)
	logsReq.RemoteAddr = "127.0.0.1:50200"
	logsRec := httptest.NewRecorder()
	h.ServeHTTP(logsRec, logsReq)
	if logsRec.Code != http.StatusOK {
		t.Fatalf("GET /logs failed: %d", logsRec.Code)
	}
	csrfCookie := logsRec.Result().Cookies()[0]

	// 1. GET /api/logs/classifier-info reports CRS + Sigma + reachable Amber-150M.
	infoReq := httptest.NewRequest(http.MethodGet, "/api/logs/classifier-info", nil)
	infoReq.RemoteAddr = "127.0.0.1:50201"
	infoRec := httptest.NewRecorder()
	h.ServeHTTP(infoRec, infoReq)
	if infoRec.Code != http.StatusOK {
		t.Fatalf("GET /api/logs/classifier-info failed: %d %s", infoRec.Code, infoRec.Body.String())
	}
	var infoResp struct {
		RuleEngine struct {
			CorazaVersion string `json:"coraza_version"`
			CRSVersion    string `json:"crs_version"`
			SigmaRules    int    `json:"sigma_rules"`
		} `json:"rule_engine"`
		Amber struct {
			Available bool   `json:"available"`
			Service   string `json:"service"`
			Model     string `json:"model"`
		} `json:"amber"`
	}
	if err := json.Unmarshal(infoRec.Body.Bytes(), &infoResp); err != nil {
		t.Fatal(err)
	}
	if !infoResp.Amber.Available || infoResp.Amber.Service != "choice" || infoResp.Amber.Model != "amber-150m" || infoResp.RuleEngine.SigmaRules < 9 {
		t.Fatalf("unexpected classifier-info: %+v", infoResp)
	}

	postClassify := func(body string, withCSRF bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(body))
		req.RemoteAddr = "127.0.0.1:50202"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://127.0.0.1:8000")
		if withCSRF {
			req.AddCookie(csrfCookie)
			req.Header.Set("X-CSRF-Token", csrfCookie.Value)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 2. Auth, CSRF enforcement, and input validation.
	unauthInfo := httptest.NewRequest(http.MethodGet, "/api/logs/classifier-info", nil)
	unauthInfo.RemoteAddr = "203.0.113.5:50201"
	unauthInfoRec := httptest.NewRecorder()
	h.ServeHTTP(unauthInfoRec, unauthInfo)
	if unauthInfoRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback classifier-info, got %d", unauthInfoRec.Code)
	}

	unauthClassify := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(`{"mode":"rules","entries":[{"service":"admin","message":"ok"}]}`))
	unauthClassify.RemoteAddr = "203.0.113.5:50202"
	unauthClassify.AddCookie(csrfCookie)
	unauthClassify.Header.Set("X-CSRF-Token", csrfCookie.Value)
	unauthClassify.Header.Set("Origin", "http://127.0.0.1:8000")
	unauthClassifyRec := httptest.NewRecorder()
	h.ServeHTTP(unauthClassifyRec, unauthClassify)
	if unauthClassifyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback classify, got %d", unauthClassifyRec.Code)
	}

	xSiteClassify := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(`{"mode":"rules","entries":[{"service":"admin","message":"ok"}]}`))
	xSiteClassify.RemoteAddr = "127.0.0.1:50202"
	xSiteClassify.AddCookie(csrfCookie)
	xSiteClassify.Header.Set("X-CSRF-Token", csrfCookie.Value)
	xSiteClassify.Header.Set("Origin", "https://evil.example")
	xSiteClassify.Header.Set("Sec-Fetch-Site", "cross-site")
	xSiteClassifyRec := httptest.NewRecorder()
	h.ServeHTTP(xSiteClassifyRec, xSiteClassify)
	if xSiteClassifyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-site classify, got %d", xSiteClassifyRec.Code)
	}

	formBypassClassify := httptest.NewRequest(http.MethodPost, "/api/logs/classify", strings.NewReader("csrf_token="+url.QueryEscape(csrfCookie.Value)))
	formBypassClassify.RemoteAddr = "127.0.0.1:50202"
	formBypassClassify.AddCookie(csrfCookie)
	formBypassClassify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formBypassClassify.Header.Set("Origin", "http://127.0.0.1:8000")
	formBypassClassifyRec := httptest.NewRecorder()
	h.ServeHTTP(formBypassClassifyRec, formBypassClassify)
	if formBypassClassifyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when classify omits X-CSRF-Token header, got %d", formBypassClassifyRec.Code)
	}

	if rec := postClassify(`{"mode":"rules","entries":[{"service":"admin","message":"ok"}]}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", rec.Code)
	}
	if rec := postClassify(`{"mode":"rules"`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", rec.Code)
	}
	if rec := postClassify(`{"mode":"invalid","entries":[{"service":"admin","message":"ok"}]}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid mode, got %d", rec.Code)
	}
	if rec := postClassify(`{"mode":"rules","entries":[]}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty entries, got %d", rec.Code)
	}

	tooMany := make([]map[string]any, 201)
	for i := range tooMany {
		tooMany[i] = map[string]any{"service": "admin", "message": "ok"}
	}
	tooManyRaw, _ := json.Marshal(map[string]any{"mode": "rules", "entries": tooMany})
	if rec := postClassify(string(tooManyRaw), true); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for >200 entries, got %d", rec.Code)
	}

	oversized := `{"mode":"rules","entries":[{"service":"admin","message":"` + strings.Repeat("A", (512<<10)+1024) + `"}]}`
	if rec := postClassify(oversized, true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for >512KiB body, got %d", rec.Code)
	}

	// 3. mode=rules detects SQLi and clean entries.
	rulesPayload := `{
		"mode":"rules",
		"entries":[
			{"ts":"2026-11-26T00:00:00Z","service":"nginx-proxy","level":"info","message":"200 cubus.sh GET / HTTP/2","structured":{"host":"cubus.sh","status":200,"request":"GET / HTTP/2","client_ip":"203.0.113.10","user_agent":"Mozilla/5.0"}},
			{"ts":"2026-11-26T00:00:01Z","service":"nginx-proxy","level":"warn","message":"400 cubus.sh GET /?id=1%20UNION%20SELECT%201,2 HTTP/2","structured":{"host":"cubus.sh","status":400,"request":"GET /?id=1%20UNION%20SELECT%201,2 HTTP/2","client_ip":"198.51.100.5","user_agent":"Mozilla/5.0"}}
		]
	}`
	rec := postClassify(rulesPayload, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("mode=rules failed: %d %s", rec.Code, rec.Body.String())
	}
	var rulesResp struct {
		Summary struct {
			Total       int `json:"total"`
			RuleFlagged int `json:"rule_flagged"`
		} `json:"summary"`
		Results []struct {
			Rule struct {
				Verdict  string `json:"verdict"`
				Category string `json:"category"`
			} `json:"rule"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rulesResp); err != nil {
		t.Fatal(err)
	}
	if rulesResp.Summary.Total != 2 || rulesResp.Summary.RuleFlagged != 1 ||
		rulesResp.Results[0].Rule.Verdict != "clean" || rulesResp.Results[1].Rule.Category != "sqli" {
		t.Fatalf("unexpected mode=rules response: %+v", rulesResp)
	}

	// 4. mode=amber classifies via choice Admin API.
	amberRec := postClassify(`{"mode":"amber","entries":[{"service":"nginx-proxy","message":"404 /.env","structured":{"status":404,"request":"GET /.env HTTP/2"}}]}`, true)
	if amberRec.Code != http.StatusOK || choiceBatchCalls != 1 || !strings.Contains(amberRec.Body.String(), `"choice":"suspicious_recon"`) {
		t.Fatalf("mode=amber failed: %d %s", amberRec.Code, amberRec.Body.String())
	}

	// 5. mode=both on 60 entries caps Amber at 50 and prioritizes rule-flagged entries.
	sixty := make([]map[string]any, 60)
	for i := range sixty {
		sixty[i] = map[string]any{
			"ts":      "2026-11-26T00:00:00Z",
			"service": "nginx-proxy",
			"level":   "info",
			"message": "200 cubus.sh GET / HTTP/2",
			"structured": map[string]any{
				"host": "cubus.sh", "status": 200, "request": "GET / HTTP/2", "user_agent": "Mozilla/5.0",
			},
		}
	}
	sixty[3] = map[string]any{
		"ts":      "2026-11-26T00:00:01Z",
		"service": "nginx-proxy",
		"level":   "warn",
		"message": "404 cubus.sh GET /.env HTTP/2",
		"structured": map[string]any{
			"host": "cubus.sh", "status": 404, "request": "GET /.env HTTP/2", "user_agent": "sqlmap/1.8",
		},
	}
	sixtyRaw, _ := json.Marshal(map[string]any{"mode": "both", "entries": sixty})
	bothRec := postClassify(string(sixtyRaw), true)
	if bothRec.Code != http.StatusOK || lastBatchItems != 50 {
		t.Fatalf("mode=both failed: code=%d lastBatchItems=%d body=%s", bothRec.Code, lastBatchItems, bothRec.Body.String())
	}
	var bothResp struct {
		AmberEvaluated int `json:"amber_evaluated"`
		Results        []struct {
			Rule  any `json:"rule"`
			Amber *struct {
				Evaluated bool   `json:"evaluated"`
				Choice    string `json:"choice"`
			} `json:"amber"`
		} `json:"results"`
	}
	if err := json.Unmarshal(bothRec.Body.Bytes(), &bothResp); err != nil {
		t.Fatal(err)
	}
	if bothResp.AmberEvaluated != 50 || len(bothResp.Results) != 60 || bothResp.Results[3].Amber == nil || bothResp.Results[3].Amber.Choice != "malicious_attack" {
		t.Fatalf("unexpected mode=both response: evaluated=%d len=%d item3=%+v", bothResp.AmberEvaluated, len(bothResp.Results), bothResp.Results[3])
	}
	if bothResp.Results[59].Amber == nil || bothResp.Results[59].Amber.Evaluated {
		t.Fatalf("expected non-nil Amber{Evaluated:false} for unselected entry, got %+v", bothResp.Results[59].Amber)
	}

	// 6. Upstream choice failure: mode=amber returns 502; mode=both returns 200 with rules + amber_error.
	choiceFail = true
	if failAmber := postClassify(`{"mode":"amber","entries":[{"service":"admin","message":"ok"}]}`, true); failAmber.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on choice upstream failure in mode=amber, got %d", failAmber.Code)
	}
	bothRulesPayload := strings.Replace(rulesPayload, `"mode":"rules"`, `"mode":"both"`, 1)
	bothFallback := postClassify(bothRulesPayload, true)
	if bothFallback.Code != http.StatusOK || !strings.Contains(bothFallback.Body.String(), "GPU worker warming up") ||
		!strings.Contains(bothFallback.Body.String(), `"category":"sqli"`) {
		t.Fatalf("expected 200 with rules + amber_error in mode=both, got %d %s", bothFallback.Code, bothFallback.Body.String())
	}

	// 7. Unconfigured / unavailable classifier service returns 503 for mode=amber and 200+amber_error for mode=both.
	noChoiceCfg := cfg
	noChoiceCfg.StaticServices = nil
	noChoiceCfg.ServiceTokens = nil
	noChoiceSrv, err := New(noChoiceCfg, st, authenticator, nil, nil, clients.NewServiceClient(noChoiceCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	noChoiceReq := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(`{"mode":"amber","entries":[{"service":"admin","message":"ok"}]}`))
	noChoiceReq.RemoteAddr = "127.0.0.1:50203"
	noChoiceReq.AddCookie(csrfCookie)
	noChoiceReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	noChoiceReq.Header.Set("Origin", "http://127.0.0.1:8000")
	noChoiceReq.Header.Set("Content-Type", "application/json")
	noChoiceRec := httptest.NewRecorder()
	noChoiceSrv.Handler().ServeHTTP(noChoiceRec, noChoiceReq)
	if noChoiceRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when classifier unavailable, got %d %s", noChoiceRec.Code, noChoiceRec.Body.String())
	}

	noChoiceBothReq := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(bothRulesPayload))
	noChoiceBothReq.RemoteAddr = "127.0.0.1:50204"
	noChoiceBothReq.AddCookie(csrfCookie)
	noChoiceBothReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	noChoiceBothReq.Header.Set("Origin", "http://127.0.0.1:8000")
	noChoiceBothReq.Header.Set("Content-Type", "application/json")
	noChoiceBothRec := httptest.NewRecorder()
	noChoiceSrv.Handler().ServeHTTP(noChoiceBothRec, noChoiceBothReq)
	if noChoiceBothRec.Code != http.StatusOK || !strings.Contains(noChoiceBothRec.Body.String(), `"category":"sqli"`) || !strings.Contains(noChoiceBothRec.Body.String(), `"amber_error":"no reachable service`) {
		t.Fatalf("expected 200 with rules + amber_error when classifier unavailable in mode=both, got %d %s", noChoiceBothRec.Code, noChoiceBothRec.Body.String())
	}

	// 8. Service without "classify" capability is not treated as an Amber classifier; bogus/empty choice results trigger 502 / amber_error.
	noCapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":      "choice",
				"version":      "0.1.0",
				"capabilities": []string{"settings"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer noCapSrv.Close()

	noCapCfg := cfg
	noCapCfg.StaticServices = map[string]string{"choice": noCapSrv.URL}
	noCapWeb, err := New(noCapCfg, st, authenticator, nil, nil, clients.NewServiceClient(noCapCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	noCapInfoReq := httptest.NewRequest(http.MethodGet, "/api/logs/classifier-info", nil)
	noCapInfoReq.RemoteAddr = "127.0.0.1:50205"
	noCapInfoRec := httptest.NewRecorder()
	noCapWeb.Handler().ServeHTTP(noCapInfoRec, noCapInfoReq)
	if noCapInfoRec.Code != http.StatusOK || !strings.Contains(noCapInfoRec.Body.String(), `"available":false`) {
		t.Fatalf("expected available=false when choice lacks classify capability, got %d %s", noCapInfoRec.Code, noCapInfoRec.Body.String())
	}

	bogusResultsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/manifest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service": "choice", "model": "amber-150m", "capabilities": []string{"classify"},
			})
		case "/admin/v1/classify/batch":
			_ = json.NewEncoder(w).Encode(map[string]any{"model": "amber-150m", "results": []any{}})
		}
	}))
	defer bogusResultsSrv.Close()

	bogusCfg := cfg
	bogusCfg.StaticServices = map[string]string{"choice": bogusResultsSrv.URL}
	bogusWeb, err := New(bogusCfg, st, authenticator, nil, nil, clients.NewServiceClient(bogusCfg, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	bogusReq := httptest.NewRequest(http.MethodPost, "/api/logs/classify", bytes.NewBufferString(`{"mode":"amber","entries":[{"service":"admin","message":"ok"}]}`))
	bogusReq.RemoteAddr = "127.0.0.1:50206"
	bogusReq.AddCookie(csrfCookie)
	bogusReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	bogusReq.Header.Set("Origin", "http://127.0.0.1:8000")
	bogusReq.Header.Set("Content-Type", "application/json")
	bogusRec := httptest.NewRecorder()
	bogusWeb.Handler().ServeHTTP(bogusRec, bogusReq)
	if bogusRec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on empty amber results, got %d %s", bogusRec.Code, bogusRec.Body.String())
	}

	// 9. Concurrency semaphore saturation returns 503 + Retry-After.
	for i := 0; i < cap(srv.classifySem); i++ {
		srv.classifySem <- struct{}{}
	}
	satRec := postClassify(`{"mode":"rules","entries":[{"service":"admin","message":"ok"}]}`, true)
	for i := 0; i < cap(srv.classifySem); i++ {
		<-srv.classifySem
	}
	if satRec.Code != http.StatusServiceUnavailable || satRec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 503 with Retry-After when classifySem is saturated, got %d headers=%v", satRec.Code, satRec.Header())
	}
}

func TestSSESessionRevocationClosesStreamsOnHeartbeat(t *testing.T) {
	// Mock ops-agent that streams metrics and holds a live log stream open until client disconnects.
	opsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ops/v1/system":
			_ = json.NewEncoder(w).Encode(map[string]any{"cpu": map[string]any{"usage_pct": 10.0}, "history": []any{}})
		case "/ops/v1/containers":
			_ = json.NewEncoder(w).Encode(map[string]any{"containers": []any{}})
		case "/ops/v1/logs/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			_, _ = w.Write([]byte("data: {\"service\":\"artifact\",\"message\":\"hello\"}\n\n"))
			if fl != nil {
				fl.Flush()
			}
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer opsSrv.Close()

	cfg := config.Config{
		PublicBaseURL:      "http://127.0.0.1:8000",
		PublicIsLoopback:   true,
		AuthMode:           config.AuthModeGoogle,
		AllowedEmails:      map[string]struct{}{"owner@cubus.sh": {}},
		GoogleClientID:     "client-id",
		GoogleClientSecret: "client-secret",
		OpsAgentURL:        opsSrv.URL,
	}
	st := store.NewMemoryStore()
	authenticator, err := auth.NewAuthenticator(context.Background(), cfg, st, auth.AuthenticatorOptions{
		GoogleAuthEndpoint:    "https://accounts.google.com/o/oauth2/v2/auth",
		GoogleTokenEndpoint:   "https://oauth2.googleapis.com/token",
		GoogleJWKSURLOverride: "https://www.googleapis.com/oauth2/v3/certs",
	})
	if err != nil {
		t.Fatal(err)
	}
	opsCli := clients.NewOpsClient(cfg.OpsAgentURL, "")
	srv, err := New(cfg, st, authenticator, opsCli, nil, clients.NewServiceClient(cfg, opsCli), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.sseHeartbeatOverride = 20 * time.Millisecond
	h := srv.Handler()

	for _, path := range []string{"/api/stream/metrics", "/api/logs/stream?service=artifact"} {
		t.Run(path, func(t *testing.T) {
			cookieRec := httptest.NewRecorder()
			sess, err := authenticator.CreateSession(context.Background(), cookieRec, "owner@cubus.sh", "Owner")
			if err != nil {
				t.Fatal(err)
			}
			var sessCookie *http.Cookie
			for _, c := range cookieRec.Result().Cookies() {
				if c.Name == "admin_session" {
					sessCookie = c
				}
			}
			if sessCookie == nil {
				t.Fatalf("expected admin_session cookie")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
			req.AddCookie(sessCookie)
			rec := httptest.NewRecorder()

			done := make(chan struct{})
			go func() {
				defer close(done)
				h.ServeHTTP(rec, req)
			}()

			// Revoke session shortly after stream opens; next 20ms heartbeat must close stream promptly.
			time.Sleep(30 * time.Millisecond)
			if err := st.DeleteSession(context.Background(), sess.TokenHash); err != nil {
				t.Fatal(err)
			}

			select {
			case <-done:
			case <-time.After(1 * time.Second):
				t.Fatalf("SSE stream %s did not terminate after session revocation", path)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("expected initial 200 for %s, got %d", path, rec.Code)
			}
		})
	}
}
