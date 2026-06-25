package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httplog/v3"
	"github.com/uc-cdis/workspace-proxy/config"
	"github.com/uc-cdis/workspace-proxy/jeg"
	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/version"
	"github.com/uc-cdis/workspace-proxy/workspace"
)

func service(cfg config.Config, logger *slog.Logger, k8s *kubernetes.Client, jeg *jeg.JEG, proxy *workspace.HTTPServer) http.Handler {
	logFormat := httplog.SchemaOTEL

	// Start GC goroutine to evict stale in-memory state and prevent OOMKill over time.
	// Runs every 15 minutes; evicts entries not touched for 4 hours.
	jeg.StartStateGC(15*time.Minute, 4*time.Hour)

	logger.Info("workspace-proxy starting",
		slog.String("listen", cfg.ListenAddr),
		slog.Bool("k8s_discovery", k8s != nil),
	)

	r := chi.NewRouter()

	r.Use(httplog.RequestLogger(logger, &httplog.Options{
		Level:         slog.LevelInfo,
		Schema:        logFormat,
		RecoverPanics: true,
		Skip: func(req *http.Request, status int) bool {
			return req.URL.Path == "/healthz"
		},
		LogRequestHeaders:  []string{"Content-Type", "Origin"},
		LogResponseHeaders: []string{"Content-Type"},
		LogRequestBody:     isDebugHeaderSet,
		LogResponseBody:    isDebugHeaderSet,
	}))

	// Set request log attribute from within middleware.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// httplog.SetAttrs(ctx, slog.String("user", "user1"))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Health endpoint for liveness/readiness probes.
	r.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"commit":  version.GitCommit,
			"version": version.GitVersion,
		})
	})

	r.Get("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.Write(fmt.Appendf(nil, "all done.\n"))
	})

	// JEG ghost-gateway: intercept JupyterLab's GatewayClient traffic and apply billing gate.
	if cfg.JEG.GatewayURL != "" {
		r.HandleFunc("/jeg-proxy", jeg.ProxyHandler)
		r.HandleFunc("/jeg-proxy/*", jeg.ProxyHandler)

		panel := http.StripPrefix("/jeg-panel", http.HandlerFunc(jeg.PanelHandler))
		r.Handle("/jeg-panel", panel)
		r.Handle("/jeg-panel/*", panel)

		logger.Info("JEG ghost gateway + panel API enabled",
			slog.String("jeg_gateway_url", cfg.JEG.GatewayURL),
		)
	}

	// All workspace traffic — authenticated and routed by REMOTE_USER.
	r.HandleFunc("/*", proxy.ProxyHandler)

	return r
}

func main() {
	logFormat := httplog.SchemaOTEL
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: logFormat.ReplaceAttr,
	})).With(
		slog.String("app", "multihead-workspace-proxy"),
		slog.String("version", "v0.0.1"),
		slog.String("env", "qa"),
	)
	slog.SetDefault(logger)

	cfg := config.Load()
	k8s := kubernetes.New()
	jeg := jeg.New(logger, k8s, cfg.JEG.GatewayURL, cfg.JEG.KernelSpecPolicy)
	proxy := workspace.NewHTTPClientProxy(logger, k8s)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           service(cfg, logger, k8s, jeg, proxy),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	// Create context that listens for the interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run server in the background
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited",
				slog.String("error", err.Error()),
			)
		}
	}()

	// Listen for the interrupt signal
	<-ctx.Done()

	// Create shutdown context with 30-second timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Trigger graceful shutdown
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown timed out",
			slog.String("error", err.Error()),
		)
	}

	logger.Info("workspace-proxy stopped cleanly")
}

func isDebugHeaderSet(r *http.Request) bool {
	return r.Header.Get("X-DEBUG") == "reveal-the-logs"
}
