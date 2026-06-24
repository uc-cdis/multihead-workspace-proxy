package main

import (
	"context"
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
	"github.com/uc-cdis/workspace-proxy/workspace"
)

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

	proxy := workspace.NewHTTPClientProxy(k8s)

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

	// Health endpoint for liveness/readiness probes.
	r.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
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

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: on SIGTERM/SIGINT drain in-flight requests for up to 30s
	// before exiting.
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(quit)

		<-quit

		logger.Info("shutdown signal received")

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown timed out",
				slog.String("error", err.Error()),
			)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited",
			slog.String("error", err.Error()),
		)
	}

	logger.Info("workspace-proxy stopped cleanly")
}

func isDebugHeaderSet(r *http.Request) bool {
	return r.Header.Get("DEBUG") == "reveal-the-logs"
}
