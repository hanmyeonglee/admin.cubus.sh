package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"cubus.sh/admin/internal/auth"
	"cubus.sh/admin/internal/clients"
	"cubus.sh/admin/internal/config"
	"cubus.sh/admin/internal/db"
	"cubus.sh/admin/internal/store"
	"cubus.sh/admin/internal/web"
)

const (
	startupTimeout    = 45 * time.Second
	shutdownTimeout   = 12 * time.Second
	reaperInterval    = 15 * time.Minute
	reaperPassTimeout = 20 * time.Second
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe local /healthz endpoint and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("admin server exited with error", "err", err)
		os.Exit(1)
	}
}

func runHealthcheck() int {
	target, err := config.HealthcheckURL(os.Getenv("LISTEN_ADDR"))
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(logger *slog.Logger) error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger.Info("starting admin.cubus.sh", "config", cfg)

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(sigCtx, startupTimeout)
	defer cancelStartup()

	dsn, err := db.ResolveDatabaseURL(startupCtx, cfg, nil)
	if err != nil {
		return fmt.Errorf("resolve database URL: %w", err)
	}

	pool, err := db.OpenPool(startupCtx, dsn)
	if err != nil {
		return fmt.Errorf("open database pool: %w", err)
	}
	defer pool.Close()

	if err := db.Migrate(startupCtx, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	pgStore := store.NewPGStore(pool)
	authenticator, err := auth.NewAuthenticator(startupCtx, cfg, pgStore, auth.AuthenticatorOptions{})
	if err != nil {
		return fmt.Errorf("initialize authenticator: %w", err)
	}

	opsCli := clients.NewOpsClient(cfg.OpsAgentURL, os.Getenv("OPS_DEV_TOKEN"))
	dbStatsCli := clients.NewDBStatsClient(cfg.DBStatsURL)
	svcCli := clients.NewServiceClient(cfg, opsCli)

	webSrv, err := web.New(cfg, pgStore, authenticator, opsCli, dbStatsCli, svcCli, logger)
	if err != nil {
		return fmt.Errorf("initialize web server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           webSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second, // Extended per-event for SSE via ResponseController
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	bgCtx, cancelBg := context.WithCancel(context.Background())
	var bgWG sync.WaitGroup
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		ticker := time.NewTicker(reaperInterval)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				passCtx, cancel := context.WithTimeout(bgCtx, reaperPassTimeout)
				if err := pgStore.ReapExpired(passCtx); err != nil && !errors.Is(err, context.Canceled) {
					logger.Warn("session reaper failed", "err", err)
				}
				cancel()
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("admin HTTP server listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin HTTP server failed: %w", err)
		}
	}()

	var runErr error
	select {
	case <-sigCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		runErr = err
	}

	cancelBg()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	_ = httpSrv.Shutdown(shutdownCtx)
	bgWG.Wait()
	return runErr
}
