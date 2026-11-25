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
		{"/static/vendor/LICENSES.txt", "text/plain"},
		{"/static/admin.css", "text/css"},
		{"/static/admin.js", "text/javascript"},
	}
	fetchedAssets := make(map[string]string, len(staticFiles))
	for _, sf := range staticFiles {
		req := httptest.NewRequest(http.MethodGet, sf.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("GET %s failed: status=%d len=%d", sf.path, rec.Code, rec.Body.Len())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, sf.wantCTPref) && !(sf.wantCTPref == "text/javascript" && strings.Contains(ct, "javascript")) {
			t.Fatalf("GET %s unexpected Content-Type %q", sf.path, ct)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("GET %s missing nosniff header", sf.path)
		}
		fetchedAssets[sf.path] = rec.Body.String()
	}
	for _, dirPath := range []string{"/static/", "/static/vendor/"} {
		req := httptest.NewRequest(http.MethodGet, dirPath, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for static directory %s, got %d", dirPath, rec.Code)
		}
	}

	// 2. Vendored & custom CSS contain zero external network URLs, @import, @font-face, or sourceMappingURL.
	externalCSSRef := regexp.MustCompile(`(?i)(@import|@font-face|url\(\s*["']?(?:https?:)?//|sourceMappingURL)`)
	for _, cssPath := range []string{"/static/vendor/tabler.min.css", "/static/admin.css"} {
		if m := externalCSSRef.FindString(fetchedAssets[cssPath]); m != "" {
			t.Fatalf("%s contains forbidden external or map reference: %q", cssPath, m)
		}
	}
	if !strings.Contains(fetchedAssets["/static/vendor/LICENSES.txt"], "MIT License") {
		t.Fatalf("LICENSES.txt missing MIT License text")
	}
	if !strings.Contains(fetchedAssets["/static/admin.css"], "color: var(--tblr-body-color);") {
		t.Fatalf("admin.css missing light/dark readable color on .audit-details-pre")
	}

	// 3. admin.js contains zero HTML/eval injection sinks or setAttribute("style", ...).
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
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("admin.js contains forbidden pattern %q", forbidden)
		}
	}

	// 4. SSR app pages render with Tabler CSS, strict CSP, zero inline style=/on*=/scripts, and zero external refs.
	inlineStyleAttr := regexp.MustCompile(`(?i)\sstyle\s*=`)
	inlineEventAttr := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	inlineStyleTag := regexp.MustCompile(`(?i)<style[\s>]`)
	externalHTMLRef := regexp.MustCompile(`(?i)<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["']?\s*(?:https?:)?//`)
	scriptTagPattern := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

	assertPageSecure := func(t *testing.T, handler http.Handler, path string) string {
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
		for _, want := range []string{`href="/static/vendor/tabler.min.css"`, `href="/static/admin.css"`, `src="/static/admin.js"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("GET %s missing %s", path, want)
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

	for _, p := range []string{"/", "/logs", "/audit", "/services/artifact"} {
		body := assertPageSecure(t, h, p)
		for _, marker := range []string{"data-theme-toggle", `id="confirm-modal"`, `id="toast"`, `name="csrf_token"`, "align-items-center d-lg-none"} {
			if !strings.Contains(body, marker) {
				t.Fatalf("GET %s missing expected UI element %q", p, marker)
			}
		}
	}
	if logsBody := assertPageSecure(t, h, "/logs"); !strings.Contains(logsBody, `role="switch"`) {
		t.Fatalf("GET /logs missing role=switch on regex toggle")
	}
	if svcUpperBody := assertPageSecure(t, h, "/services/Artifact"); !strings.Contains(svcUpperBody, `class="nav-item active" data-nav-service="artifact"`) ||
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

	// 5. Login page in Google auth mode and Cloudflare-only mode both use Tabler + strict CSP.
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
	loginBody := assertPageSecure(t, googleSrv.Handler(), "/login")
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
	cfLoginBody := assertPageSecure(t, cfSrv.Handler(), "/login")
	if !strings.Contains(cfLoginBody, "Cf-Access-Jwt-Assertion") || strings.Contains(cfLoginBody, "Sign in with Google") ||
		!strings.Contains(cfLoginBody, "https://cubus.cloudflareaccess.com/cdn-cgi/access/logout") {
		t.Fatalf("GET /login in CloudflareOnly mode missing expected content: %s", cfLoginBody)
	}
}
