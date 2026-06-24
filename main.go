package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httplog/v3"
	"github.com/uc-cdis/workspace-proxy/config"
	"github.com/uc-cdis/workspace-proxy/jeg"
	"github.com/uc-cdis/workspace-proxy/kubernetes"
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

	r.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})
	http.ListenAndServe(cfg.ListenAddr, r)
}

func isDebugHeaderSet(r *http.Request) bool {
	return r.Header.Get("DEBUG") == "reveal-the-logs"
}
