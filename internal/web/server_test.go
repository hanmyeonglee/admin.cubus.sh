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
	"strings"
	"testing"

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

	// 4. Write without CSRF fails with 403; cross-site write fails with 403.
	noCSRF := httptest.NewRequest(http.MethodPost, "/api/services/artifact/users/u-123/approve", nil)
	noCSRF.RemoteAddr = "127.0.0.1:50003"
	noCSRFRec := httptest.NewRecorder()
	h.ServeHTTP(noCSRFRec, noCSRF)
	if noCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", noCSRFRec.Code)
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
}
