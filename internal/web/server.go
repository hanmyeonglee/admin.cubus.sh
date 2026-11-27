package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"cubus.sh/admin/internal/auth"
	"cubus.sh/admin/internal/clients"
	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/logclassify"
	"cubus.sh/admin/internal/store"
)

//go:embed templates/*.html static
var embeddedFS embed.FS

const (
	adminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

	healthPingTimeout     = 1500 * time.Millisecond
	maxMutationBody       = 32 << 10
	maxClassifyBody       = 512 << 10
	maxClassifyEntries    = 200
	classifierInfoTimeout = 3 * time.Second
	amberClassifyTimeout  = 30 * time.Second
	classifyWriteExtend   = 45 * time.Second
	sseMaxLifetime        = 30 * time.Minute
	sseMetricsTick        = 5 * time.Second
	sseHeartbeat          = 15 * time.Second
	sseWriteExtend        = 30 * time.Second
	maxConcurrentSSE      = 8
	maxConcurrentClassify = 4
)

type Server struct {
	cfg        config.Config
	store      store.Store
	auth       *auth.Authenticator
	ops        *clients.OpsClient
	dbStats    *clients.DBStatsClient
	services   *clients.ServiceClient
	classifier *logclassify.Engine
	logger     *slog.Logger

	templates            *template.Template
	staticHandler        http.Handler
	assetVersion         string
	csrfProtect          *http.CrossOriginProtection
	sseSem               chan struct{}
	classifySem          chan struct{}
	sseHeartbeatOverride time.Duration
}

func computeStaticAssetVersion(staticFS fs.FS) (string, error) {
	var paths []string
	if err := fs.WalkDir(staticFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		data, err := fs.ReadFile(staticFS, p)
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", p, len(data))
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)[:6]), nil
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
	assetVer, err := computeStaticAssetVersion(staticSub)
	if err != nil {
		return nil, fmt.Errorf("hash static assets: %w", err)
	}

	csrf := http.NewCrossOriginProtection()
	if cfg.PublicBaseURL != "" {
		if err := csrf.AddTrustedOrigin(cfg.PublicBaseURL); err != nil {
			return nil, fmt.Errorf("trust public origin: %w", err)
		}
	}

	classifier, err := logclassify.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("initialize log classifier: %w", err)
	}

	return &Server{
		cfg:           cfg,
		store:         st,
		auth:          authenticator,
		ops:           ops,
		dbStats:       dbStats,
		services:      services,
		classifier:    classifier,
		logger:        logger,
		templates:     tmpl,
		staticHandler: http.StripPrefix("/static/", http.FileServer(http.FS(noDirListingFS{fsys: staticSub}))),
		assetVersion:  assetVer,
		csrfProtect:   csrf,
		sseSem:        make(chan struct{}, maxConcurrentSSE),
		classifySem:   make(chan struct{}, maxConcurrentClassify),
	}, nil
}

func (s *Server) sseHeartbeatInterval() time.Duration {
	if s.sseHeartbeatOverride > 0 {
		return s.sseHeartbeatOverride
	}
	return sseHeartbeat
}

func (s *Server) recheckStreamAuth(ctx context.Context, r *http.Request) bool {
	authCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err := s.auth.Authenticate(nil, r.WithContext(authCtx))
	return err == nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated health & static assets
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if v := r.URL.Query().Get("v"); s.assetVersion != "" && v == s.assetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		s.staticHandler.ServeHTTP(w, r)
	}))

	// Authentication routes
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /auth/google/start", s.handleGoogleStart)
	mux.HandleFunc("GET /auth/google/callback", s.handleGoogleCallback)
	mux.Handle("POST /logout", s.requireAuthWrite(http.HandlerFunc(s.handleLogout)))

	// Authenticated SSR pages
	mux.Handle("GET /{$}", s.requireAuthPage(http.HandlerFunc(s.handleOverviewPage)))
	mux.Handle("GET /access", s.requireAuthPage(http.HandlerFunc(s.handleAccessPage)))
	mux.Handle("GET /logs", s.requireAuthPage(http.HandlerFunc(s.handleLogsPage)))
	mux.Handle("GET /services/{name}", s.requireAuthPage(http.HandlerFunc(s.handleServicePage)))
	mux.Handle("GET /audit", s.requireAuthPage(http.HandlerFunc(s.handleAuditPage)))

	// Authenticated Read APIs & SSE
	mux.Handle("GET /api/overview", s.requireAuthAPI(http.HandlerFunc(s.handleAPIOverview)))
	mux.Handle("GET /api/access/overview", s.requireAuthAPI(http.HandlerFunc(s.handleAPIAccessOverview)))
	mux.Handle("GET /api/stream/metrics", s.requireAuthAPI(http.HandlerFunc(s.handleStreamMetrics)))
	mux.Handle("GET /api/logs/search", s.requireAuthAPI(http.HandlerFunc(s.handleAPILogsSearch)))
	mux.Handle("GET /api/logs/stream", s.requireAuthAPI(http.HandlerFunc(s.handleStreamLogs)))
	mux.Handle("GET /api/logs/classifier-info", s.requireAuthAPI(http.HandlerFunc(s.handleAPILogsClassifierInfo)))
	mux.Handle("GET /api/services", s.requireAuthAPI(http.HandlerFunc(s.handleAPIServices)))
	mux.Handle("GET /api/services/{name}/manifest", s.requireAuthAPI(http.HandlerFunc(s.handleServiceManifest)))
	mux.Handle("GET /api/services/{name}/users", s.requireAuthAPI(http.HandlerFunc(s.handleServiceUsers)))
	mux.Handle("GET /api/services/{name}/invites", s.requireAuthAPI(http.HandlerFunc(s.handleServiceInvitesList)))
	mux.Handle("GET /api/services/{name}/api-keys", s.requireAuthAPI(http.HandlerFunc(s.handleServiceAPIKeysList)))
	mux.Handle("GET /api/services/{name}/settings", s.requireAuthAPI(http.HandlerFunc(s.handleServiceSettingsGet)))
	mux.Handle("GET /api/services/{name}/artifacts", s.requireAuthAPI(http.HandlerFunc(s.handleServiceArtifactsList)))
	mux.Handle("GET /api/audit", s.requireAuthAPI(http.HandlerFunc(s.handleAPIAudit)))

	// Authenticated Mutating APIs (CrossOriginProtection + CSRF token + Audit Log)
	mux.Handle("POST /api/logs/classify", s.requireAuthWrite(http.HandlerFunc(s.handleAPILogsClassify)))
	mux.Handle("POST /api/services/{name}/users/{id}/approve", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserApprove)))
	mux.Handle("POST /api/services/{name}/users/{id}/deny", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserDeny)))
	mux.Handle("PATCH /api/services/{name}/users/{id}", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserPatch)))
	mux.Handle("DELETE /api/services/{name}/users/{id}", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserDelete)))
	mux.Handle("DELETE /api/services/{name}/users/{id}/sessions", s.requireAuthWrite(http.HandlerFunc(s.handleServiceUserSessionsDelete)))
	mux.Handle("POST /api/services/{name}/invites", s.requireAuthWrite(http.HandlerFunc(s.handleServiceInviteCreate)))
	mux.Handle("DELETE /api/services/{name}/invites/{id}", s.requireAuthWrite(http.HandlerFunc(s.handleServiceInviteDelete)))
	mux.Handle("POST /api/services/{name}/api-keys", s.requireAuthWrite(http.HandlerFunc(s.handleServiceAPIKeyCreate)))
	mux.Handle("POST /api/services/{name}/api-keys/{id}/revoke", s.requireAuthWrite(http.HandlerFunc(s.handleServiceAPIKeyRevoke)))
	mux.Handle("DELETE /api/services/{name}/api-keys/{id}", s.requireAuthWrite(http.HandlerFunc(s.handleServiceAPIKeyDelete)))
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
		if csrfVal == "" && r.URL.Path == "/logout" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
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
	AssetVersion        string
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
		AssetVersion:        s.assetVersion,
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
	AssetVersion        string
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
		AssetVersion:        s.assetVersion,
	})
}

func (s *Server) handleOverviewPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, "overview", "Overview & Hardware", "")
}

func (s *Server) handleAccessPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, "access", "Users & Access", "")
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
	hb := time.NewTicker(s.sseHeartbeatInterval())
	defer hb.Stop()

	for {
		select {
		case <-streamCtx.Done():
			return
		case <-hb.C:
			if !s.recheckStreamAuth(streamCtx, r) {
				return
			}
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

func (s *Server) handleAPILogsClassifierInfo(w http.ResponseWriter, r *http.Request) {
	amberStatus := clients.AmberClassifierStatus{
		Available: false,
		Model:     "amber-150m",
		Error:     "service discovery not configured",
	}
	if s.services != nil {
		probeCtx, cancel := context.WithTimeout(r.Context(), classifierInfoTimeout)
		amberStatus = s.services.AmberStatus(probeCtx)
		cancel()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rule_engine": s.classifier.Info(),
		"amber":       amberStatus,
	})
}

func (s *Server) handleAPILogsClassify(w http.ResponseWriter, r *http.Request) {
	select {
	case s.classifySem <- struct{}{}:
		defer func() { <-s.classifySem }()
	default:
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "too many concurrent classification requests"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClassifyBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "classification payload exceeds 512 KiB limit"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var req struct {
		Mode    string                 `json:"mode"`
		Entries []logclassify.LogEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON"})
		return
	}
	mode, err := logclassify.FormatClassificationMode(strings.ToLower(strings.TrimSpace(req.Mode)))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(req.Entries) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entries must contain at least 1 log entry"})
		return
	}
	if len(req.Entries) > maxClassifyEntries {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("entries exceeds maximum batch limit of %d", maxClassifyEntries)})
		return
	}

	start := time.Now()
	var ruleResults []logclassify.RuleResult
	if mode == "rules" || mode == "both" {
		var clsErr error
		ruleResults, clsErr = s.classifier.ClassifyBatch(r.Context(), req.Entries)
		if clsErr != nil {
			if r.Context().Err() != nil {
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "classification canceled"})
			return
		}
	}
	if r.Context().Err() != nil {
		return
	}

	amberModel := logclassify.AmberDefaultModel
	amberEvaluated := 0
	amberErr := ""
	var amberMap map[int]logclassify.AmberResult
	var amberUsage *logclassify.AmberUsage

	if mode == "amber" || mode == "both" {
		// Extend the HTTP server write deadline so cold GPU startup on choice does not time out.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(classifyWriteExtend))

		if s.services == nil {
			amberErr = "service discovery not configured"
			if mode == "amber" {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": amberErr})
				return
			}
		} else {
			probeCtx, cancelProbe := context.WithTimeout(r.Context(), classifierInfoTimeout)
			status := s.services.AmberStatus(probeCtx)
			cancelProbe()
			if status.Model != "" {
				amberModel = status.Model
			}
			if !status.Available {
				amberErr = status.Error
				if amberErr == "" {
					amberErr = "amber classifier service unavailable"
				}
				if mode == "amber" {
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": amberErr})
					return
				}
			} else {
				selected := logclassify.SelectAmberIndices(req.Entries, ruleResults, logclassify.MaxAmberBatch)
				payload, buildErr := logclassify.BuildAmberClassifyRequest(req.Entries, selected, amberModel)
				if buildErr != nil {
					amberErr = buildErr.Error()
					if mode == "amber" {
						writeJSON(w, http.StatusBadRequest, map[string]string{"error": amberErr})
						return
					}
				} else {
					raw, upStatus, callErr := s.services.ProxyWithTimeout(
						r.Context(),
						status.Service,
						http.MethodPost,
						"/admin/v1/classify",
						nil,
						payload,
						amberClassifyTimeout,
					)
					if callErr != nil || upStatus != http.StatusOK {
						amberErr = extractUpstreamError(raw, upStatus, callErr)
						if mode == "amber" {
							writeJSON(w, http.StatusBadGateway, map[string]string{"error": amberErr})
							return
						}
					} else {
						parsed, parseErr := logclassify.ParseAmberClassifyResponse(raw, selected)
						if parseErr != nil {
							amberErr = parseErr.Error()
							if mode == "amber" {
								writeJSON(w, http.StatusBadGateway, map[string]string{"error": amberErr})
								return
							}
						} else {
							if parsed.Model != "" {
								amberModel = parsed.Model
							}
							amberUsage = parsed.Usage
							amberMap = parsed.Results
							for _, res := range parsed.Results {
								if res.Evaluated {
									amberEvaluated++
								}
							}
						}
					}
				}
			}
		}
	}

	results := make([]logclassify.EntryClassification, len(req.Entries))
	for i := range req.Entries {
		ec := logclassify.EntryClassification{Index: i}
		if ruleResults != nil {
			rr := ruleResults[i]
			ec.Rule = &rr
		}
		if ar, ok := amberMap[i]; ok {
			arCopy := ar
			ec.Amber = &arCopy
		} else if (mode == "amber" || mode == "both") && amberErr == "" {
			ec.Amber = &logclassify.AmberResult{Evaluated: false}
		}
		results[i] = ec
	}

	respPayload := map[string]any{
		"mode":            mode,
		"duration_ms":     time.Since(start).Milliseconds(),
		"rule_engine":     s.classifier.Info(),
		"amber_model":     amberModel,
		"amber_evaluated": amberEvaluated,
		"amber_error":     amberErr,
		"summary":         logclassify.BuildSummary(results),
		"results":         results,
	}
	if amberUsage != nil {
		respPayload["amber_usage"] = amberUsage
	}
	writeJSON(w, http.StatusOK, respPayload)
}

const maxUpstreamErrorRunes = 256

func sanitizeUpstreamError(s string) string {
	var b strings.Builder
	b.Grow(min(len(s), maxUpstreamErrorRunes))
	lastSpace := false
	runes := 0
	truncated := false
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if r == '\r' || r == '\n' || r == '\t' || unicode.IsControl(r) || unicode.IsSpace(r) {
			if !lastSpace && b.Len() > 0 {
				if runes >= maxUpstreamErrorRunes {
					truncated = true
					break
				}
				b.WriteByte(' ')
				runes++
				lastSpace = true
			}
			continue
		}
		if runes >= maxUpstreamErrorRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		runes++
		lastSpace = false
	}
	out := strings.TrimSpace(b.String())
	if truncated && out != "" {
		// Trim to make room for "..." within maxUpstreamErrorRunes.
		rs := []rune(out)
		if len(rs) > maxUpstreamErrorRunes-3 {
			out = strings.TrimSpace(string(rs[:maxUpstreamErrorRunes-3])) + "..."
		} else {
			out += "..."
		}
	}
	return out
}

func extractUpstreamError(raw json.RawMessage, status int, err error) string {
	if len(raw) > 0 {
		var body struct {
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(raw, &body) == nil && len(body.Error) > 0 {
			var flat string
			if json.Unmarshal(body.Error, &flat) == nil {
				if msg := sanitizeUpstreamError(flat); msg != "" {
					return msg
				}
			}
			var nested struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(body.Error, &nested) == nil {
				if msg := sanitizeUpstreamError(nested.Message); msg != "" {
					return msg
				}
			}
		}
	}
	if err != nil {
		if msg := sanitizeUpstreamError(err.Error()); msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("classifier returned HTTP %d", status)
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

	hb := time.NewTicker(s.sseHeartbeatInterval())
	defer hb.Stop()
	for {
		select {
		case <-streamCtx.Done():
			return
		case <-hb.C:
			if !s.recheckStreamAuth(streamCtx, r) {
				return
			}
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

func (s *Server) handleAPIAccessOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.services.FetchAccessOverview(r.Context()))
}

func (s *Server) handleServiceManifest(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/manifest", nil)
}

func (s *Server) handleServiceUsers(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	raw, status, err := s.services.ListUsers(r.Context(), svc, r.URL.Query())
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceInvitesList(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	raw, status, err := s.services.ListInvites(r.Context(), svc)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceAPIKeysList(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	raw, status, err := s.services.ListAPIKeys(r.Context(), svc)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceSettingsGet(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/settings", nil)
}

func (s *Server) handleServiceArtifactsList(w http.ResponseWriter, r *http.Request) {
	s.proxyServiceRead(w, r, "/admin/v1/artifacts", r.URL.Query())
}

func (s *Server) proxyServiceRead(w http.ResponseWriter, r *http.Request, relPath string, q url.Values) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	raw, status, err := s.services.Proxy(r.Context(), svc, http.MethodGet, relPath, q, nil)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeRawJSON(w, status, raw)
}

func decodeStrictJSONObject(w http.ResponseWriter, r *http.Request, dst any) (int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMutationBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return http.StatusRequestEntityTooLarge, errors.New("request body too large")
		}
		return http.StatusBadRequest, errors.New("invalid request body")
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return http.StatusBadRequest, errors.New("malformed JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, errors.New("trailing JSON tokens in request body")
	}
	return 0, nil
}

func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.Is(unicode.Cc, r) {
			return true
		}
	}
	return false
}

func sanitizeOperatorCreatedBy(email string, maxRunes int) string {
	var b strings.Builder
	count := 0
	for _, r := range strings.TrimSpace(email) {
		if r < 0x20 || r == 0x7f || unicode.Is(unicode.Cc, r) {
			continue
		}
		if count >= maxRunes {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func marshalAuditDetails(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return json.RawMessage(data)
}

func (s *Server) handleServiceUserApprove(w http.ResponseWriter, r *http.Request) {
	s.handleServiceUserDecision(w, r, "approve")
}

func (s *Server) handleServiceUserDeny(w http.ResponseWriter, r *http.Request) {
	s.handleServiceUserDecision(w, r, "deny")
}

func (s *Server) handleServiceUserDecision(w http.ResponseWriter, r *http.Request, action string) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	var (
		raw    json.RawMessage
		status int
	)
	if action == "approve" {
		raw, status, err = s.services.ApproveUser(r.Context(), svc, id)
	} else {
		raw, status, err = s.services.DenyUser(r.Context(), svc, id)
	}
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

func (s *Server) handleServiceUserPatch(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if code, err := decodeStrictJSONObject(w, r, &req); err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	nextStatus := strings.TrimSpace(req.Status)
	if nextStatus != "active" && nextStatus != "disabled" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be active or disabled"})
		return
	}
	forwardBody, err := json.Marshal(map[string]string{"status": nextStatus})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode request"})
		return
	}
	raw, status, err := s.services.UpdateUserStatus(r.Context(), svc, id, forwardBody)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "user.status_update", svc, id, marshalAuditDetails(map[string]any{
			"status": nextStatus,
		}))
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceUserDelete(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	raw, status, err := s.services.DeleteUser(r.Context(), svc, id)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "user.delete", svc, id, nil)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceUserSessionsDelete(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	raw, status, err := s.services.RevokeUserSessions(r.Context(), svc, id)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		var details json.RawMessage
		var respMeta struct {
			Revoked *int64 `json:"revoked"`
		}
		if json.Unmarshal(raw, &respMeta) == nil && respMeta.Revoked != nil {
			details = marshalAuditDetails(map[string]any{"revoked": *respMeta.Revoked})
		}
		s.recordAudit(r.Context(), p, r, "user.sessions_revoke", svc, id, details)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceInviteCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
		TTLHours    *int   `json:"ttl_hours"`
		CreatedBy   string `json:"created_by"`
	}
	if code, err := decodeStrictJSONObject(w, r, &req); err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" || utf8.RuneCountInString(displayName) > 64 || containsControlChar(displayName) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "display_name must be 1..64 printable characters"})
		return
	}
	if req.TTLHours != nil && (*req.TTLHours < 1 || *req.TTLHours > 720) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl_hours must be between 1 and 720"})
		return
	}

	p, _ := auth.PrincipalFromContext(r.Context())
	// Always inject created_by from the authenticated operator email (never trust client input).
	createdBy := sanitizeOperatorCreatedBy(p.Email, 64)

	forwardPayload := struct {
		DisplayName string `json:"display_name"`
		TTLHours    *int   `json:"ttl_hours,omitempty"`
		CreatedBy   string `json:"created_by"`
	}{
		DisplayName: displayName,
		TTLHours:    req.TTLHours,
		CreatedBy:   createdBy,
	}
	forwardBody, err := json.Marshal(forwardPayload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode request"})
		return
	}

	raw, status, err := s.services.CreateInvite(r.Context(), svc, forwardBody)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		// SECURITY: Parse ONLY non-secret metadata for audit_logs; never log invite_url or raw token.
		var meta struct {
			Invite struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
				Status      string `json:"status"`
			} `json:"invite"`
		}
		_ = json.Unmarshal(raw, &meta)
		auditMeta := map[string]any{
			"display_name": displayName,
		}
		if meta.Invite.DisplayName != "" {
			auditMeta["display_name"] = meta.Invite.DisplayName
		}
		if req.TTLHours != nil {
			auditMeta["ttl_hours"] = *req.TTLHours
		}
		if meta.Invite.Status != "" {
			auditMeta["status"] = meta.Invite.Status
		}
		s.recordAudit(r.Context(), p, r, "invite.create", svc, meta.Invite.ID, marshalAuditDetails(auditMeta))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceInviteDelete(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invite id"})
		return
	}
	raw, status, err := s.services.DeleteInvite(r.Context(), svc, id)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "invite.delete", svc, id, nil)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	var req struct {
		Name          string `json:"name"`
		Owner         string `json:"owner"`
		ExpiresInDays *int   `json:"expires_in_days"`
		CreatedBy     string `json:"created_by"`
	}
	if code, err := decodeStrictJSONObject(w, r, &req); err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || utf8.RuneCountInString(name) > 120 || containsControlChar(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be 1..120 printable characters"})
		return
	}
	owner := strings.TrimSpace(req.Owner)
	if utf8.RuneCountInString(owner) > 120 || containsControlChar(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "owner must be at most 120 printable characters"})
		return
	}
	if req.ExpiresInDays != nil {
		switch *req.ExpiresInDays {
		case 30, 90, 365:
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_in_days must be one of 30, 90, 365, or null"})
			return
		}
	}

	p, _ := auth.PrincipalFromContext(r.Context())
	// Always inject created_by from the authenticated operator email (never trust client input).
	createdBy := sanitizeOperatorCreatedBy(p.Email, 120)

	forwardPayload := struct {
		Name          string `json:"name"`
		Owner         string `json:"owner"`
		ExpiresInDays *int   `json:"expires_in_days,omitempty"`
		CreatedBy     string `json:"created_by"`
	}{
		Name:          name,
		Owner:         owner,
		ExpiresInDays: req.ExpiresInDays,
		CreatedBy:     createdBy,
	}
	forwardBody, err := json.Marshal(forwardPayload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode request"})
		return
	}

	raw, status, err := s.services.CreateAPIKey(r.Context(), svc, forwardBody)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		// SECURITY: Parse ONLY non-secret metadata for audit_logs; never log plaintext api_key.
		var meta struct {
			Record struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Owner     string `json:"owner"`
				KeyPrefix string `json:"key_prefix"`
				Status    string `json:"status"`
			} `json:"record"`
		}
		_ = json.Unmarshal(raw, &meta)
		auditMeta := map[string]any{
			"name": name,
		}
		if meta.Record.Name != "" {
			auditMeta["name"] = meta.Record.Name
		}
		if meta.Record.Owner != "" {
			auditMeta["owner"] = meta.Record.Owner
		} else if owner != "" {
			auditMeta["owner"] = owner
		}
		if meta.Record.KeyPrefix != "" {
			auditMeta["key_prefix"] = meta.Record.KeyPrefix
		}
		if meta.Record.Status != "" {
			auditMeta["status"] = meta.Record.Status
		}
		if req.ExpiresInDays != nil {
			auditMeta["expires_in_days"] = *req.ExpiresInDays
		}
		s.recordAudit(r.Context(), p, r, "api_key.create", svc, meta.Record.ID, marshalAuditDetails(auditMeta))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid api key id"})
		return
	}
	raw, status, err := s.services.RevokeAPIKey(r.Context(), svc, id)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		var meta struct {
			Name      string `json:"name"`
			Owner     string `json:"owner"`
			KeyPrefix string `json:"key_prefix"`
			Status    string `json:"status"`
		}
		var details json.RawMessage
		if json.Unmarshal(raw, &meta) == nil {
			auditMeta := map[string]any{}
			if meta.Name != "" {
				auditMeta["name"] = meta.Name
			}
			if meta.Owner != "" {
				auditMeta["owner"] = meta.Owner
			}
			if meta.KeyPrefix != "" {
				auditMeta["key_prefix"] = meta.KeyPrefix
			}
			if meta.Status != "" {
				auditMeta["status"] = meta.Status
			}
			if len(auditMeta) > 0 {
				details = marshalAuditDetails(auditMeta)
			}
		}
		s.recordAudit(r.Context(), p, r, "api_key.revoke", svc, id, details)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
	id, err := clients.ValidateResourceID(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid api key id"})
		return
	}
	raw, status, err := s.services.DeleteAPIKey(r.Context(), svc, id)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if status >= 200 && status < 300 {
		p, _ := auth.PrincipalFromContext(r.Context())
		s.recordAudit(r.Context(), p, r, "api_key.delete", svc, id, nil)
	}
	writeRawJSON(w, status, raw)
}

func (s *Server) handleServiceSettingsPatch(w http.ResponseWriter, r *http.Request) {
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
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
	svc, err := clients.ValidateServiceName(r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service name"})
		return
	}
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
