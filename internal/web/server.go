package web

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cubus.sh/admin/internal/auth"
	"cubus.sh/admin/internal/clients"
	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/store"
)

//go:embed templates/*.html static
var embeddedFS embed.FS

const (
	adminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

	healthPingTimeout = 1500 * time.Millisecond
	maxMutationBody   = 32 << 10
	sseMaxLifetime    = 30 * time.Minute
	sseMetricsTick    = 5 * time.Second
	sseHeartbeat      = 15 * time.Second
	sseWriteExtend    = 30 * time.Second
	maxConcurrentSSE  = 8
)

type Server struct {
	cfg      config.Config
	store    store.Store
	auth     *auth.Authenticator
	ops      *clients.OpsClient
	dbStats  *clients.DBStatsClient
	services *clients.ServiceClient
	logger   *slog.Logger

	templates     *template.Template
	staticHandler http.Handler
	csrfProtect   *http.CrossOriginProtection
	sseSem        chan struct{}
}

func New(
	cfg config.Config,
	st store.Store,
	authenticator *auth.Authenticator,
	ops *clients.OpsClient,
	dbStats *clients.DBStatsClient,
	services *clients.ServiceClient,
	logger *slog.Logger,
) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tmpl, err := template.ParseFS(embeddedFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	staticSub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		return nil, fmt.Errorf("open static fs: %w", err)
	}

	csrf := http.NewCrossOriginProtection()
	if cfg.PublicBaseURL != "" {
		if err := csrf.AddTrustedOrigin(cfg.PublicBaseURL); err != nil {
			return nil, fmt.Errorf("trust public origin: %w", err)
		}
	}

	return &Server{
		cfg:           cfg,
		store:         st,
		auth:          authenticator,
		ops:           ops,
		dbStats:       dbStats,
		services:      services,
		logger:        logger,
		templates:     tmpl,
		staticHandler: http.StripPrefix("/static/", http.FileServer(http.FS(noDirListingFS{fsys: staticSub}))),
		csrfProtect:   csrf,
		sseSem:        make(chan struct{}, maxConcurrentSSE),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated health & static assets
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		s.staticHandler.ServeHTTP(w, r)
	}))

	// Authentication routes
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /auth/google/start", s.handleGoogleStart)
	mux.HandleFunc("GET /auth/google/callback", s.handleGoogleCallback)
	mux.Handle("POST /logout", s.requireAuthWrite(http.HandlerFunc(s.handleLogout)))

	// Authenticated SSR pages
	mux.Handle("GET /{$}", s.requireAuthPage(http.HandlerFunc(s.handleOverviewPage)))
	mux.Handle("GET /logs", s.requireAuthPage(http.HandlerFunc(s.handleLogsPage)))
	mux.Handle("GET /services/{name}", s.requireAuthPage(http.HandlerFunc(s.handleServicePage)))
	mux.Handle("GET /audit", s.requireAuthPage(http.HandlerFunc(s.handleAuditPage)))

	// Authenticated Read APIs & SSE
	mux.Handle("GET /api/overview", s.requireAuthAPI(http.HandlerFunc(s.handleAPIOverview)))
	mux.Handle("GET /api/stream/metrics", s.requireAuthAPI(http.HandlerFunc(s.handleStreamMetrics)))
	mux.Handle("GET /api/logs/search", s.requireAuthAPI(http.HandlerFunc(s.handleAPILogsSearch)))
	mux.Handle("GET /api/logs/stream", s.requireAuthAPI(http.HandlerFunc(s.handleStreamLogs)))
	mux.Handle("GET /api/services", s.requireAuthAPI(http.HandlerFunc(s.handleAPIServices)))
	mux.Handle("GET /api/services/{name}/manifest", s.requireAuthAPI(http.HandlerFunc(s.handleServiceManifest)))
	mux.Handle("GET /api/services/{name}/users", s.requireAuthAPI(http.HandlerFunc(s.handleServiceUsers)))
	mux.Handle("GET /api/services/{name}/settings", s.requireAuthAPI(http.HandlerFunc(s.handleServiceSettingsGet)))
	mux.Handle("GET /api/services/{name}/artifacts", s.requireAuthAPI(http.HandlerFunc(s.handleServiceArtifactsList)))
	mux.Handle("GET /api/audit", s.requireAuthAPI(http.HandlerFunc(s.handleAPIAudit)))

	// Authenticated Mutating APIs (CrossOriginProtection + CSRF token + Audit Log)
	mux.Handle("POST /api/services/{name}/users/{id}/approve", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserApprove)))
	mux.Handle("POST /api/services/{name}/users/{id}/deny", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserDeny)))
	mux.Handle("PATCH /api/services/{name}/settings", s.requireAuthWrite(http.HandlerFunc(s.handleServiceSettingsPatch)))
	mux.Handle("DELETE /api/services/{name}/artifacts/{id}", s.requireAuthWrite(http.HandlerFunc(s.handleServiceArtifactDelete)))

	return mux
}

func (s *Server) requireAuthPage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		p, needsRedirect, err := s.auth.Authenticate(w, r)
		if err != nil {
			if needsRedirect && s.auth.HasGoogle() {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(auth.SafeNextPath(r.URL.RequestURI())), http.StatusFound)
				return
			}
			s.renderLogin(w, http.StatusForbidden, r.URL.RequestURI(), "Access denied: "+err.Error(), "")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

func (s *Server) requireAuthAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		p, needsRedirect, err := s.auth.Authenticate(nil, r)
		if err != nil {
			code := http.StatusForbidden
			if needsRedirect {
				code = http.StatusUnauthorized
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

func (s *Server) requireAuthWrite(next http.Handler) http.Handler {
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		// Pass nil for ResponseWriter so rejected writes never mutate the CSRF cookie.
		p, needsRedirect, err := s.auth.Authenticate(nil, r)
		if err != nil {
			code := http.StatusForbidden
			if needsRedirect {
				code = http.StatusUnauthorized
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}

		csrfVal := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if csrfVal == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			r.Body = http.MaxBytesReader(w, r.Body, maxMutationBody)
			if err := r.ParseForm(); err == nil {
				csrfVal = r.PostForm.Get("csrf_token")
			}
		}
		if !s.auth.VerifyCSRF(r, p, csrfVal) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
	return s.csrfProtect.Handler(guarded)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), healthPingTimeout)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type loginViewData struct {
	GoogleEnabled       bool
	CloudflareOnly      bool
	CloudflareLogoutURL string
	Next                string
	Error               string
	Notice              string
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, nextPath, errMsg, notice string) {
	setSecurityHeaders(w)
	s.renderTemplate(w, status, "login.html", loginViewData{
		GoogleEnabled:       s.auth.HasGoogle(),
		CloudflareOnly:      s.cfg.AuthMode == config.AuthModeCloudflare,
		CloudflareLogoutURL: s.auth.CloudflareLogoutURL(),
		Next:                auth.SafeNextPath(nextPath),
		Error:               errMsg,
		Notice:              notice,
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.auth.Authenticate(w, r); err == nil {
		http.Redirect(w, r, auth.SafeNextPath(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	notice := ""
	if r.URL.Query().Get("logged_out") == "1" {
		notice = "Signed out of local session."
	}
	s.renderLogin(w, http.StatusOK, r.URL.Query().Get("next"), "", notice)
}

func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !s.auth.HasGoogle() {
		http.Error(w, "Google sign-in is disabled", http.StatusNotFound)
		return
	}
	s.auth.Google().StartLogin(w, r)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !s.auth.HasGoogle() {
		http.Error(w, "Google sign-in is disabled", http.StatusNotFound)
		return
	}
	id, nextPath, err := s.auth.Google().CompleteCallback(r.Context(), w, r)
	if err != nil {
		s.renderLogin(w, http.StatusUnauthorized, "/", err.Error(), "")
		return
	}
	if !s.cfg.IsEmailAllowed(id.Email) {
		s.logger.Warn("rejected unauthorized google login", "email", id.Email, "ip", auth.ExtractClientIP(r))
		s.renderLogin(w, http.StatusForbidden, "/", "Your Google account is not authorized to access admin.cubus.sh.", "")
		return
	}
	if s.cfg.AuthMode == config.AuthModeCloudflareAndGoogle {
		cfEmail, cfErr := s.auth.VerifyCloudflareEmail(r.Context(), r)
		if cfErr != nil || cfEmail != id.Email {
			s.logger.Warn("rejected google login mismatched with cloudflare access", "google_email", id.Email, "cf_err", cfErr)
			s.renderLogin(w, http.StatusForbidden, "/", "Google account email must match your Cloudflare Access identity.", "")
			return
		}
	}
	s.auth.DestroySession(r.Context(), w, r)
	if _, err := s.auth.CreateSession(r.Context(), w, id.Email, id.Name); err != nil {
		s.logger.Error("create admin session failed", "err", err)
		s.renderLogin(w, http.StatusInternalServerError, "/", "Failed to create session.", "")
		return
	}
	s.recordAudit(r.Context(), auth.Principal{Email: id.Email, AuthMethod: "google"}, r, "login", "admin", "", nil)
	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFromContext(r.Context())
	s.auth.DestroySession(r.Context(), w, r)
	s.recordAudit(r.Context(), p, r, "logout", "admin", "", nil)
	http.Redirect(w, r, "/login?logged_out=1", http.StatusSeeOther)
}

type appViewData struct {
	Page                string
	PageTitle           string
	ActiveService       string
	Principal           auth.Principal
	CSRFToken           string
	Services            []clients.ServiceSummary
	CloudflareLogoutURL string
}

func (s *Server) renderApp(w http.ResponseWriter, r *http.Request, page, title, activeSvc string) {
	p, _ := auth.PrincipalFromContext(r.Context())
	svcs := s.services.ListServices(r.Context())
	s.renderTemplate(w, http.StatusOK, "app.html", appViewData{
		Page:                page,
		PageTitle:           title,
		ActiveService:       activeSvc,
		Principal:           p,
		CSRFToken:           p.CSRFToken,
		Services:            svcs,
		CloudflareLogoutURL: s.auth.CloudflareLogoutURL(),
	})
}

func (s *Server) handleOverviewPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, "overview", "Overview & Hardware", "")
}

func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, "logs", "Log Explorer", "")
}

func (s *Server) handleServicePage(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	s.renderApp(w, r, "service", "Service · "+name, name)
}

func (s *Server) handleAuditPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, "audit", "Audit Log", "")
}

func (s *Server) handleAPIOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp := map[string]any{
		"services": s.services.ListServices(ctx),
	}
	if s.ops != nil && s.ops.Configured() {
		if sys, err := s.ops.GetSystemRaw(ctx); err == nil {
			resp["system"] = sys
		} else {
			resp["system_error"] = err.Error()
		}
		if cnt, err := s.ops.GetContainersRaw(ctx); err == nil {
			resp["containers"] = cnt
		} else {
			resp["containers_error"] = err.Error()
		}
	}
	if s.dbStats != nil && s.dbStats.Configured() {
		if dbs, err := s.dbStats.GetRaw(ctx); err == nil {
			resp["db_stats"] = dbs
		} else {
			resp["db_stats_error"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStreamMetrics(w http.ResponseWriter, r *http.Request) {
	if s.ops == nil || !s.ops.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ops-agent not configured"})
		return
	}
	select {
	case s.sseSem <- struct{}{}:
		defer func() { <-s.sseSem }()
	default:
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "too many concurrent streams"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	respCtrl := http.NewResponseController(w)
	streamCtx, cancel := context.WithTimeout(r.Context(), sseMaxLifetime)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	tick := time.NewTicker(sseMetricsTick)
	defer tick.Stop()
	hb := time.NewTicker(sseHeartbeat)
	defer hb.Stop()

	for {
		select {
		case <-streamCtx.Done():
			return
		case <-hb.C:
			_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-tick.C:
			tickCtx, cancelTick := context.WithTimeout(streamCtx, 3*time.Second)
			payload := map[string]any{}
			if sys, err := s.ops.GetSystemRaw(tickCtx); err == nil {
				payload["system"] = sys
			}
			if cnt, err := s.ops.GetContainersRaw(tickCtx); err == nil {
				payload["containers"] = cnt
			}
			cancelTick()
			if len(payload) == 0 {
				continue
			}
			data, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleAPILogsSearch(w http.ResponseWriter, r *http.Request) {
	if s.ops == nil || !s.ops.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ops-agent not configured"})
		return
	}
	raw, status, err := s.ops.SearchLogsRaw(r.Context(), r.URL.Query())
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleStreamLogs(w http.ResponseWriter, r *http.Request) {
	if s.ops == nil || !s.ops.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ops-agent not configured"})
		return
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	if service == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service is required"})
		return
	}
	select {
	case s.sseSem <- struct{}{}:
		defer func() { <-s.sseSem }()
	default:
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "too many concurrent streams"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	respCtrl := http.NewResponseController(w)
	streamCtx, cancel := context.WithTimeout(r.Context(), sseMaxLifetime)
	defer cancel()

	upResp, err := s.ops.OpenLogStream(streamCtx, service, r.URL.Query().Get("tail"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to connect to log stream"})
		return
	}
	defer upResp.Body.Close()
	if upResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(upResp.Body, 4096))
		writeRawJSON(w, upResp.StatusCode, body)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		br := bufio.NewReaderSize(upResp.Body, 16<<10)
		for {
			line, err := br.ReadString('\n')
			if strings.HasPrefix(line, "data:") {
				select {
				case lines <- strings.TrimRight(line, "\r\n"):
				case <-streamCtx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	hb := time.NewTicker(sseHeartbeat)
	defer hb.Stop()
	for {
		select {
		case <-streamCtx.Done():
			return
		case <-hb.C:
			_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case line, open := <-lines:
			if !open {
				return
			}
			_ = respCtrl.SetWriteDeadline(time.Now().Add(sseWriteExtend))
			if _, err := fmt.Fprintf(w, "%s\n\n", line); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleAPIServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"services": s.services.ListServices(r.Context())})
}

func (s *Server) handleServiceManifest(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/manifest", nil)
}

func (s *Server) handleServiceUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/users", r.URL.Query())
}

func (s *Server) handleServiceSettingsGet(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/settings", nil)
}

func (s *Server) handleServiceArtifactsList(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/artifacts", r.URL.Query())
}

func (s *Server) proxyServiceRead(w http.ResponseWriter, r *http.Request, relPath string, q url.Values) {
	svc := r.PathValue("name")
	raw, status, err := s.services.Proxy(r.Context(), svc, http.MethodGet, relPath, q, nil)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceUserApprove(w http.ResponseWriter, r *http.Request) {
	s.handleServiceUserDecision(w, r, "approve")
}

func (s *Server) handleServiceUserDeny(w http.ResponseWriter, r *http.Request) {
	s.handleServiceUserDecision(w, r, "deny")
}

func (s *Server) handleServiceUserDecision(w http.ResponseWriter, r *http.Request, action string) {
	svc := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	raw, status, err := s.services.Proxy(r.Context(), svc, http.MethodPost, "/admin/v1/users/"+url.PathEscape(id)+"/"+action, nil, nil)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "user_"+action, svc, id, nil)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceSettingsPatch(w http.ResponseWriter, r *http.Request) {
	svc := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	r.Body = http.MaxBytesReader(w, r.Body, maxMutationBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !json.Valid(body) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON"})
		return
	}
	raw, status, err := s.services.Proxy(r.Context(), svc, http.MethodPatch, "/admin/v1/settings", nil, body)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "settings_update", svc, "", json.RawMessage(body))
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceArtifactDelete(w http.ResponseWriter, r *http.Request) {
	svc := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid artifact id"})
		return
	}
	raw, status, err := s.services.Proxy(r.Context(), svc, http.MethodDelete, "/admin/v1/artifacts/"+url.PathEscape(id), nil, nil)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "artifact_delete", svc, id, nil)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 200 {
			limit = n
		}
	}
	offset := 0
	if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			offset = n
		}
	}
	rows, err := s.store.ListAuditLogs(r.Context(), store.AuditFilter{
		Service: strings.TrimSpace(q.Get("service")),
		Action:  strings.TrimSpace(q.Get("action")),
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load audit logs"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": rows})
}

func (s *Server) recordAudit(ctx context.Context, p auth.Principal, r *http.Request, action, service, targetID string, details json.RawMessage) {
	entry := store.AuditLog{
		ActorEmail:    p.Email,
		AuthMethod:    p.AuthMethod,
		Action:        action,
		TargetService: strings.ToLower(strings.TrimSpace(service)),
		TargetID:      targetID,
		Details:       details,
		ClientIP:      auth.ExtractClientIP(r),
	}
	// Detach from request cancellation so a browser closing immediately after a 2xx
	// mutation cannot drop the audit record.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.store.AppendAuditLog(auditCtx, entry); err != nil {
		// Structured fallback so audit trail survives transient DB write failures.
		s.logger.Error("audit_log_fallback",
			"err", err,
			"actor", entry.ActorEmail,
			"auth_method", entry.AuthMethod,
			"action", entry.Action,
			"target_service", entry.TargetService,
			"target_id", entry.TargetID,
			"client_ip", entry.ClientIP,
		)
	}
}

func (s *Server) renderTemplate(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		s.logger.Error("render template failed", "template", name, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type noDirListingFS struct {
	fsys fs.FS
}

func (f noDirListingFS) Open(name string) (fs.File, error) {
	file, err := f.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", adminCSP)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeRawJSON(w http.ResponseWriter, status int, raw json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(raw) == 0 {
		_, _ = w.Write([]byte(`{}`))
		return
	}
	_, _ = w.Write(raw)
}
