package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httplog/v3"
	"github.com/uc-cdis/workspace-proxy/config"
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

	logger.Info("workspace-proxy starting",
		slog.String("listen", cfg.ListenAddr),
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
