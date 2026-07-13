package jeg

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/uc-cdis/workspace-proxy/internal/identity"
)

func (jeg *JEG) panelHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	id, ok := identity.FromContext(r.Context())
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		jeg.logger.InfoContext(
			r.Context(),
			"access79",
			slog.String("user_hash", ""),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}
	remoteUser := id.Username
	userHash := identity.Hash(id)

	panelPath := strings.TrimPrefix(r.URL.Path, "/jeg-panel")
	if panelPath == "" {
		panelPath = "/"
	}

	method := r.Method

	forwardHeaders := func(req *http.Request) {
		identity.SetUpstreamHeaders(req.Header, id)
		req.Header.Del("Connection")
		req.Header.Del("Upgrade")
	}

	w.Header().Set("Cache-Control", "no-store")

	// GET /api/status — pre-flight used by useGatewayConnection on panel mount.
	if method == http.MethodGet && panelPath == "/api/status" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"enabled":true}`))
		jeg.logger.InfoContext(
			r.Context(),
			"access80",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernelspecs — panel-filtered: all specs when no policy, allowed when policy set.
	if method == http.MethodGet && panelPath == "/api/kernelspecs" {
		upstream := jeg.gatewayURL + "/api/kernelspecs"
		req, _ := http.NewRequest(http.MethodGet, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernelspecs unavailable", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access81",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "JEG kernelspecs unavailable", resp.StatusCode)
			jeg.logger.InfoContext(
				r.Context(),
				"access82",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", resp.StatusCode),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		rawBody, _ := io.ReadAll(resp.Body)
		filtered := jeg.filterJEGKernelspecsForPanel(rawBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(filtered)
		jeg.logger.InfoContext(
			r.Context(),
			"access83",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernels — user's active JEG kernels.
	if method == http.MethodGet && panelPath == "/api/kernels" {
		upstream := jeg.gatewayURL + "/api/kernels"
		req, _ := http.NewRequest(http.MethodGet, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernels unavailable", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access84",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		jeg.logger.InfoContext(
			r.Context(),
			"access85",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// POST /api/kernels — billing gate: validate spec name then forward to JEG.
	if method == http.MethodPost && panelPath == "/api/kernels" {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var launchReq struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &launchReq); err != nil || launchReq.Name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"Invalid kernel launch request — name is required."}`))
			jeg.logger.InfoContext(
				r.Context(),
				"access86",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// Billing gate: when a policy is configured, only allowedSpecs may be launched.
		if jeg.kernelSpecPolicy != nil && len(jeg.kernelSpecPolicy.AllowedSpecs) > 0 {
			allowed := false
			for _, s := range jeg.kernelSpecPolicy.AllowedSpecs {
				if s == launchReq.Name {
					allowed = true
					break
				}
			}
			if !allowed {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"Kernel spec not authorized for this deployment."}`))
				log.Printf(`{"msg":"panel kernel launch blocked — spec not in allowedSpecs","user_hash":%q,"spec":%q}`, userHash, launchReq.Name)
				jeg.logger.InfoContext(
					r.Context(),
					"access87",
					slog.String("user_hash", userHash),
					slog.String("gateway_url", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusForbidden),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}
		}

		// JEG 3.x uses KERNEL_USERNAME from the request env dict for user isolation
		// and pod naming. Inject it from REMOTE_USER if the client didn't supply it.
		var launchFull map[string]interface{}
		if err := json.Unmarshal(body, &launchFull); err == nil {
			env, _ := launchFull["env"].(map[string]interface{})
			if env == nil {
				env = map[string]interface{}{}
			}
			if _, ok := env["KERNEL_USERNAME"]; !ok {
				env["KERNEL_USERNAME"] = remoteUser
			}
			launchFull["env"] = env
			if enriched, err2 := json.Marshal(launchFull); err2 == nil {
				body = enriched
			}
		}

		// Forward the launch request to JEG.
		upstream := jeg.gatewayURL + "/api/kernels"
		req, _ := http.NewRequest(http.MethodPost, upstream, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernel launch failed", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access88",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			log.Printf(`{"msg":"JEG kernel launch error","user_hash":%q,"spec":%q,"status":%d,"body":%q}`,
				userHash, launchReq.Name, resp.StatusCode, string(respBody))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		jeg.logger.InfoContext(
			r.Context(),
			"access89",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// DELETE /api/kernels/{id} — force-terminate; passed through unconditionally.
	if method == http.MethodDelete && strings.HasPrefix(panelPath, "/api/kernels/") {
		kernelID := chi.URLParam(r, "kernelID")
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access90",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		upstream := jeg.gatewayURL + "/api/kernels/" + kernelID
		req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG delete failed", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access92",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(resp.StatusCode)
		}
		jeg.logger.InfoContext(
			r.Context(),
			"access95",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	jeg.logger.InfoContext(
		r.Context(),
		"access93",
		slog.String("user_hash", userHash),
		slog.String("gateway_url", jeg.gatewayURL),
		slog.String("method", method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusNotFound),
		slog.Duration("duration", time.Since(start)),
	)
}
