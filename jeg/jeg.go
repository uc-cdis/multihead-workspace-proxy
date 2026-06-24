package jeg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/proxy"
	"github.com/uc-cdis/workspace-proxy/workspace"
)

// ---- JEG ghost-gateway ----
//
// /jeg-proxy/* is pointed at by JupyterLab's --GatewayClient.url inside the
// micro-container pod. It acts as a merged gateway:
//
//   - GET  /api/kernelspecs        — merged: local container specs + JEG filtered specs
//   - POST /api/kernels            — local spec name → forward to container;
//                                    JEG spec name → 403 billing gate (use Vectis panel)
//   - GET  /api/kernels            — merged: container running kernels + JEG running kernels
//   - DELETE /api/kernels/{id}     — local ID → container; JEG ID → JEG
//   - WS   /api/kernels/{id}/channels — local ID → container WS; JEG ID → JEG WS
//   - GET/POST/PATCH/DELETE /api/sessions  — routed to JEG
//   - GET/POST/PUT/DELETE /api/contents    — always routed to micro-container
//   - All other paths              — 404
//
// Security: REMOTE_USER is forwarded on every upstream request so JEG enforces
// per-user isolation. The handler is only registered when JEG_GATEWAY_URL is set.

type sessionKernelOverride struct {
	KernelID   string
	KernelName string
	Path       string
	Name       string
	Type       string
	UpdatedAt  time.Time
}

type jegKernelPolicy struct {
	AllowedSpecs []string           `json:"allowedSpecs"`
	CostPerHour  map[string]float64 `json:"costPerHour"`
	DisplayNames map[string]string  `json:"displayNames"`
	NodeType     map[string]string  `json:"nodeType"`
}

// sessionKernelOverrides tracks notebook session -> JEG kernel bindings per user
// so polling GET /api/sessions does not revert the client back to local kernels.
// parsedJEGPolicy is parsed once at startup from JEG_KERNEL_SPEC_POLICY env var.
type JEG struct {
	logger                 *slog.Logger
	K8s                    *kubernetes.Client
	gatewayURL             string
	kernelSpecPolicy       *jegKernelPolicy
	sessionKernelOverrides sync.Map
	knownJEGKernelIDs      sync.Map
	knownJEGKernelIDsAge   sync.Map
}

func parseKernelSpecPolicy(raw string) (*jegKernelPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return &jegKernelPolicy{}, nil
	}

	var p jegKernelPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("parse JEG_KERNEL_SPEC_POLICY: %w", err)
	}

	return &p, nil
}

func New(logger *slog.Logger, k8s *kubernetes.Client, gatewayURL string, jegKernelSpecPolicy string) *JEG {
	policy, err := parseKernelSpecPolicy(jegKernelSpecPolicy)
	if err != nil {
		// logger.Printf(
		// 	`{"msg":"JEG_KERNEL_SPEC_POLICY parse error; ghost gateway will return empty specs","error":%q}`,
		// 	err.Error(),
		// )

		policy = &jegKernelPolicy{}
	}

	return &JEG{
		logger:           logger,
		gatewayURL:       gatewayURL,
		K8s:              k8s,
		kernelSpecPolicy: policy,
	}
}

func sessionOverrideKey(remoteUser, sessionID string) string {
	return strings.TrimSpace(remoteUser) + "|" + strings.TrimSpace(sessionID)
}

func (jeg *JEG) setSessionKernelOverride(remoteUser, sessionID, kernelID, kernelName, path, name, sessionType string) {
	if strings.TrimSpace(remoteUser) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(kernelID) == "" {
		return
	}
	if strings.TrimSpace(sessionType) == "" {
		sessionType = "notebook"
	}
	jeg.sessionKernelOverrides.Store(sessionOverrideKey(remoteUser, sessionID), sessionKernelOverride{
		KernelID:   strings.TrimSpace(kernelID),
		KernelName: strings.TrimSpace(kernelName),
		Path:       strings.TrimSpace(path),
		Name:       strings.TrimSpace(name),
		Type:       strings.TrimSpace(sessionType),
		UpdatedAt:  time.Now(),
	})
}
func (jeg *JEG) clearSessionKernelOverride(remoteUser, sessionID string) {
	if strings.TrimSpace(remoteUser) == "" || strings.TrimSpace(sessionID) == "" {
		return
	}
	jeg.sessionKernelOverrides.Delete(sessionOverrideKey(remoteUser, sessionID))
}

func (jeg *JEG) getSessionKernelOverride(remoteUser, sessionID string) (sessionKernelOverride, bool) {
	v, ok := jeg.sessionKernelOverrides.Load(sessionOverrideKey(remoteUser, sessionID))
	if !ok {
		return sessionKernelOverride{}, false
	}
	ov, castOK := v.(sessionKernelOverride)
	if !castOK {
		return sessionKernelOverride{}, false
	}
	return ov, true
}

type jegKernelInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	LastActivity   string `json:"last_activity"`
	ExecutionState string `json:"execution_state"`
	Connections    int    `json:"connections"`
}

func buildSessionCompatResponse(sessionID string, override sessionKernelOverride, live *jegKernelInfo) []byte {
	sessionType := strings.TrimSpace(override.Type)
	if sessionType == "" {
		sessionType = "notebook"
	}
	execState := "idle"
	activity := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	conns := 1
	if live != nil {
		if live.ExecutionState != "" {
			execState = live.ExecutionState
		}
		if live.LastActivity != "" {
			activity = live.LastActivity
		}
		conns = live.Connections
	}
	compat := map[string]interface{}{
		"id":   sessionID,
		"path": override.Path,
		"name": override.Name,
		"type": sessionType,
		"kernel": map[string]interface{}{
			"id":              override.KernelID,
			"name":            override.KernelName,
			"execution_state": execState,
			"last_activity":   activity,
			"connections":     conns,
		},
		"notebook": map[string]string{
			"path": override.Path,
			"name": override.Name,
		},
	}
	out, _ := json.Marshal(compat)
	return out
}

func extractSessionKernelFromBody(body []byte) (string, string) {
	if len(body) == 0 {
		return "", ""
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err != nil {
		return "", ""
	}
	kernel, _ := generic["kernel"].(map[string]interface{})
	if kernel == nil {
		return "", ""
	}
	kid, _ := kernel["id"].(string)
	kname, _ := kernel["name"].(string)
	return strings.TrimSpace(kid), strings.TrimSpace(kname)
}

func (jeg *JEG) rememberJEGKernelID(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	jeg.knownJEGKernelIDs.Store(id, struct{}{})
	jeg.knownJEGKernelIDsAge.Store(id, time.Now())
}

func (jeg *JEG) forgetJEGKernelID(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	jeg.knownJEGKernelIDs.Delete(id)
	jeg.knownJEGKernelIDsAge.Delete(id)
}

func (jeg *JEG) isKnownJEGKernelID(id string) bool {
	_, ok := jeg.knownJEGKernelIDs.Load(strings.TrimSpace(id))
	return ok
}

// jegHasKernel asks JEG directly whether the kernel ID exists for this user.
// Used as a routing discriminator because container /api/kernels/{id} may proxy
// through GatewayClient and return JEG-owned kernels as 200.
func (jeg *JEG) jegHasKernel(kernelID, remoteUser string) bool {
	if jeg.gatewayURL == "" {
		return false
	}
	upstream := strings.TrimRight(jeg.gatewayURL, "/") + "/api/kernels/" + kernelID
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return false
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	req.Header.Set("remote_user", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		jeg.rememberJEGKernelID(kernelID)
	}
	return resp.StatusCode == http.StatusOK
}

// findJEGKernelIDByName returns the first active JEG kernel ID that matches the
// requested kernel name for this user.
func (jeg *JEG) findJEGKernelIDByName(remoteUser, kernelName string) string {
	if jeg.gatewayURL == "" || strings.TrimSpace(kernelName) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jeg.gatewayURL, "/")+"/api/kernels", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	req.Header.Set("remote_user", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var kernels []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if b, err := io.ReadAll(resp.Body); err == nil {
		if json.Unmarshal(b, &kernels) == nil {
			for _, k := range kernels {
				if strings.EqualFold(strings.TrimSpace(k.Name), strings.TrimSpace(kernelName)) {
					jeg.rememberJEGKernelID(k.ID)
					return k.ID
				}
			}
		}
	}
	return ""
}

// findJEGKernelNameByID resolves a running JEG kernel name by ID.
func (jeg *JEG) findJEGKernelNameByID(remoteUser, kernelID string) string {
	if jeg.gatewayURL == "" {
		return ""
	}
	kernelID = strings.TrimSpace(kernelID)
	if kernelID == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jeg.gatewayURL, "/")+"/api/kernels/"+kernelID, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	req.Header.Set("remote_user", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		jeg.forgetJEGKernelID(kernelID)
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var kernel struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if b, err := io.ReadAll(resp.Body); err == nil {
		if json.Unmarshal(b, &kernel) == nil {
			if strings.TrimSpace(kernel.ID) != "" {
				jeg.rememberJEGKernelID(kernel.ID)
			}
			return strings.TrimSpace(kernel.Name)
		}
	}
	return ""
}

func (jeg *JEG) listJEGKernels(remoteUser string) []jegKernelInfo {
	if jeg.gatewayURL == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jeg.gatewayURL, "/")+"/api/kernels", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	req.Header.Set("remote_user", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var kernels []jegKernelInfo
	if b, err := io.ReadAll(resp.Body); err == nil {
		if json.Unmarshal(b, &kernels) == nil {
			for _, k := range kernels {
				if strings.TrimSpace(k.ID) != "" {
					jeg.rememberJEGKernelID(k.ID)
				}
			}
			return kernels
		}
	}
	return nil
}

// fetchLocalKernelspecs fetches kernelspecs from the user's micro-container Jupyter server.
// microBase is the resolved upstream, e.g. "http://h-user-s.ns.svc.cluster.local:80".
// Returns raw JSON body or an error.
func fetchLocalKernelspecs(microBase, remoteUser string) ([]byte, error) {
	upstream := strings.TrimRight(microBase, "/") + proxy.UpstreamPrefix + "/api/kernelspecs"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("container kernelspecs HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// filterJEGKernelspecs applies the kernel spec policy to the raw JEG response body,
// returning a filtered JSON byte slice. Spec names not in allowedSpecs are dropped.
// If no policy is configured, returns an empty kernelspecs object to prevent
// JupyterLab from launching kernels directly without going through the billing panel.
func (jeg *JEG) filterJEGKernelspecs(rawBody []byte) []byte {
	if jeg.kernelSpecPolicy == nil || len(jeg.kernelSpecPolicy.AllowedSpecs) == 0 {
		// No policy: return empty spec list. JupyterLab sees "no kernels" in its picker.
		return []byte(`{"default":"","kernelspecs":{}}`)
	}

	var raw struct {
		Default     string                     `json:"default"`
		Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
	}
	if err := json.Unmarshal(rawBody, &raw); err != nil {
		return []byte(`{"default":"","kernelspecs":{}}`)
	}

	filtered := make(map[string]json.RawMessage, len(jeg.kernelSpecPolicy.AllowedSpecs))
	for _, name := range jeg.kernelSpecPolicy.AllowedSpecs {
		if spec, ok := raw.Kernelspecs[name]; ok {
			// Inject cost/nodeType metadata into the spec.
			// We do a minimal JSON merge: parse, add fields, re-encode.
			var specObj map[string]interface{}
			if err := json.Unmarshal(spec, &specObj); err == nil {
				inner, _ := specObj["spec"].(map[string]interface{})
				if inner == nil {
					inner = map[string]interface{}{}
					specObj["spec"] = inner
				}
				meta, _ := inner["metadata"].(map[string]interface{})
				if meta == nil {
					meta = map[string]interface{}{}
					inner["metadata"] = meta
				}
				meta["costPerHour"] = jeg.kernelSpecPolicy.CostPerHour[name]
				meta["nodeType"] = jeg.kernelSpecPolicy.NodeType[name]
				if dn, ok := jeg.kernelSpecPolicy.DisplayNames[name]; ok {
					inner["display_name"] = dn
				}
				if b, err := json.Marshal(specObj); err == nil {
					filtered[name] = b
					continue
				}
			}
			filtered[name] = spec // fallback: raw spec unchanged
		}
	}

	defaultSpec := raw.Default
	if _, ok := filtered[defaultSpec]; !ok {
		defaultSpec = ""
		if len(jeg.kernelSpecPolicy.AllowedSpecs) > 0 {
			if _, ok := filtered[jeg.kernelSpecPolicy.AllowedSpecs[0]]; ok {
				defaultSpec = jeg.kernelSpecPolicy.AllowedSpecs[0]
			}
		}
	}

	result := map[string]interface{}{
		"default":     defaultSpec,
		"kernelspecs": filtered,
	}
	b, err := json.Marshal(result)
	if err != nil {
		return []byte(`{"default":"","kernelspecs":{}}`)
	}
	return b
}

// isLocalContainerSpec does a stateless live lookup: asks the container whether
// the given kernelspec name exists in its /api/kernelspecs. Returns true if found.
// Replaces the old in-memory localSpecNames sync.Map.
func isLocalContainerSpec(microBase, specName, remoteUser string) bool {
	raw, err := fetchLocalKernelspecs(microBase, remoteUser)
	if err != nil {
		return false
	}
	var envelope struct {
		Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return false
	}
	_, ok := envelope.Kernelspecs[specName]
	return ok
}

// containerHasKernel does a stateless live lookup: asks the container whether it
// owns the given kernel ID. Returns true if the container responds 200, false on
// 404 or any error. This replaces the old in-memory localKernelIDs sync.Map so
// the proxy remains stateless across restarts and multiple replicas.
func containerHasKernel(microBase, kernelID, remoteUser string) bool {
	upstream := strings.TrimRight(microBase, "/") + proxy.UpstreamPrefix + "/api/kernels/" + kernelID
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return false
	}
	req.Header.Set("REMOTE_USER", remoteUser)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// mergeKernelspecs merges local (micro-container) kernelspecs with JEG filtered kernelspecs.
// Local specs always win on name collision. The default spec is set to the first local spec.
func mergeKernelspecs(localRaw, jegFiltered []byte) []byte {
	type specsEnvelope struct {
		Default     string                     `json:"default"`
		Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
	}
	var local, jeg specsEnvelope
	_ = json.Unmarshal(localRaw, &local)
	_ = json.Unmarshal(jegFiltered, &jeg)

	merged := make(map[string]json.RawMessage)
	for k, v := range jeg.Kernelspecs {
		merged[k] = v
	}
	for k, v := range local.Kernelspecs {
		merged[k] = v // local wins on collision
	}

	defaultSpec := local.Default
	if _, ok := merged[defaultSpec]; !ok {
		defaultSpec = ""
		for k := range local.Kernelspecs {
			defaultSpec = k
			break
		}
	}

	out, err := json.Marshal(map[string]interface{}{
		"default":     defaultSpec,
		"kernelspecs": merged,
	})
	if err != nil {
		return jegFiltered
	}
	return out
}

func isValidKernelID(s string) bool {
	if len(s) < 8 || len(s) > 36 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
func (jeg *JEG) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Auth: REMOTE_USER must be present (set by revproxy auth_request).
	// All requests arrive from the browser via remoteKernelsBaseUrl → revproxy.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := workspace.NormalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = workspace.NormalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		// logAccess("", jegGatewayURL, r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}
	userHash := workspace.HashUser(remoteUser)

	// Strip the /jeg-proxy prefix to get the kernel-API-relative path.
	jegPath := strings.TrimPrefix(r.URL.Path, "/jeg-proxy")
	if jegPath == "" {
		jegPath = "/"
	}

	jegBase, _ := url.Parse(jeg.gatewayURL)

	// Common upstream headers forwarded to JEG.
	forwardJEGHeaders := func(req *http.Request) {
		req.Header.Set("REMOTE_USER", remoteUser)
		req.Header.Set("remote_user", remoteUser)
		req.Header.Del("Connection")
		req.Header.Del("Upgrade")
	}

	method := r.Method

	// Resolve the user's micro-container upstream (soft-fail: empty string if not running).
	// Used to fetch local kernelspecs, route local kernel launches, and proxy contents/sessions.
	microUpstream, _ := workspace.LookupUpstreamWithFallback(ctx, jeg.K8s, remoteUser, identityRaw, remoteUserRaw)

	// ---- Route dispatch ----

	// /api/sessions — simplified now that the browser talks directly to ghost gateway
	// (no more GatewayClient middleman creating shadow sessions).
	// Container handles local kernel sessions; JEG has no session API, so we
	// synthesize session entries from the session-override map for JEG kernels.
	//   - GET  (list):  merge container sessions + synthesized JEG sessions
	//   - GET  (by id): try container, fall back to override map
	//   - POST:         route by kernel name (local -> container, JEG -> synthesize)
	//   - PATCH:        route by kernel in body (local -> container, JEG -> synthesize)
	//   - DELETE:       try container, clear override if present
	if strings.HasPrefix(jegPath, "/api/sessions") {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		proxySessionToContainerBuffered := func() (int, http.Header, []byte, error) {
			if microUpstream == "" {
				return http.StatusBadGateway, nil, nil, fmt.Errorf("workspace not running")
			}
			upstream := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + jegPath
			req, _ := http.NewRequest(method, upstream, bytes.NewReader(body))
			for key := range r.Header {
				switch strings.ToLower(key) {
				case "connection", "upgrade", "te", "trailers", "transfer-encoding":
					continue
				}
				req.Header[key] = r.Header[key]
			}
			req.Header.Set("REMOTE_USER", remoteUser)
			if r.URL.RawQuery != "" {
				req.URL.RawQuery = r.URL.RawQuery
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return http.StatusBadGateway, nil, nil, err
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, resp.Header, respBody, nil
		}

		writeResponse := func(status int, header http.Header, respBody []byte) {
			for key, vals := range header {
				switch strings.ToLower(key) {
				case "connection", "transfer-encoding", "content-length":
					continue
				}
				for _, v := range vals {
					w.Header().Add(key, v)
				}
			}
			w.WriteHeader(status)
			_, _ = w.Write(respBody)
		}

		// GET /api/sessions — merge container sessions + synthesized JEG sessions.
		if method == http.MethodGet {
			// Single session by ID: try container, then override map.
			if strings.HasPrefix(jegPath, "/api/sessions/") {
				sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
				sessionID = strings.SplitN(sessionID, "/", 2)[0]
				sessionID = strings.SplitN(sessionID, "?", 2)[0]

				if microUpstream != "" {
					cStatus, cHdr, cBody, cErr := proxySessionToContainerBuffered()
					if cErr == nil && cStatus == http.StatusOK {
						writeResponse(cStatus, cHdr, cBody)
						jeg.logger.InfoContext(ctx, "access",
							slog.String("user", userHash),
							slog.String("microsupstream", microUpstream),
							slog.String("method", method),
							slog.String("path", r.URL.Path),
							slog.Int("status", cStatus),
							slog.Duration("time", time.Since(start)))
						return
					}
				}
				// Container didn't have it — check override map (JEG synthetic session).
				if override, ok := jeg.getSessionKernelOverride(remoteUser, sessionID); ok {
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					jeg.logger.InfoContext(r.Context(), "access",
						slog.String("user_hash", userHash),
						slog.String("action", "override"),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", http.StatusOK),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
				http.Error(w, "session not found", http.StatusNotFound)
				jeg.logger.InfoContext(r.Context(), "access",
					slog.String("user_hash", userHash),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusNotFound),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// Session list: merge container sessions + JEG kernel-backed overrides.
			var merged []json.RawMessage
			containerIDs := map[string]struct{}{}

			if microUpstream != "" {
				cStatus, _, cBody, cErr := proxySessionToContainerBuffered()
				if cErr == nil && cStatus == http.StatusOK {
					var sessions []json.RawMessage
					if json.Unmarshal(cBody, &sessions) == nil {
						for _, s := range sessions {
							var sess struct {
								ID string `json:"id"`
							}
							if json.Unmarshal(s, &sess) == nil && strings.TrimSpace(sess.ID) != "" {
								containerIDs[strings.TrimSpace(sess.ID)] = struct{}{}
							}
							merged = append(merged, s)
						}
					}
				}
			}

			// Fetch live JEG kernel data once for enriching synthesized sessions.
			jegKernels := jeg.listJEGKernels(remoteUser)
			jegKernelMap := map[string]*jegKernelInfo{}
			for i := range jegKernels {
				jegKernelMap[strings.TrimSpace(jegKernels[i].ID)] = &jegKernels[i]
			}

			// Synthesize session entries for active JEG kernels from override map.
			prefix := strings.TrimSpace(remoteUser) + "|"
			jeg.sessionKernelOverrides.Range(func(k, v interface{}) bool {
				key, ok := k.(string)
				if !ok || !strings.HasPrefix(key, prefix) {
					return true
				}
				override, ok := v.(sessionKernelOverride)
				if !ok || strings.TrimSpace(override.KernelID) == "" {
					return true
				}
				sid := strings.TrimPrefix(key, prefix)
				if _, dup := containerIDs[sid]; dup {
					return true // skip if container already has a session with this ID
				}
				// Only include if JEG still has the kernel running.
				live, ok := jegKernelMap[strings.TrimSpace(override.KernelID)]
				if !ok {
					jeg.clearSessionKernelOverride(remoteUser, sid)
					return true
				}
				out := buildSessionCompatResponse(sid, override, live)
				merged = append(merged, json.RawMessage(out))
				return true
			})

			if merged == nil {
				merged = []json.RawMessage{}
			}
			result, _ := json.Marshal(merged)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(result)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("upstream", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusOK),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// POST /api/sessions — route by kernel name.
		if method == http.MethodPost {
			_, postKernelName := extractSessionKernelFromBody(body)
			postKernelName = strings.TrimSpace(postKernelName)

			var postReq struct {
				ID     string `json:"id"`
				Path   string `json:"path"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Kernel struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"kernel"`
			}
			_ = json.Unmarshal(body, &postReq)

			// Determine if this is a local or JEG spec.
			localSpec := false
			if microUpstream != "" && postKernelName != "" {
				localSpec = isLocalContainerSpec(microUpstream, postKernelName, remoteUser)
			}

			// Local kernel — forward to container.
			if localSpec {
				if microUpstream != "" {
					status, hdr, respBody, err := proxySessionToContainerBuffered()
					if err == nil && status < 400 {
						writeResponse(status, hdr, respBody)
						jeg.logger.InfoContext(r.Context(), "access",
							slog.String("user_hash", userHash),
							slog.String("upstream", microUpstream),
							slog.String("method", method),
							slog.String("path", r.URL.Path),
							slog.Int("status", status),
							slog.Duration("duration", time.Since(start)),
						)
						return
					}
				}
			}

			// JEG kernel — JEG has no session API, so we synthesize a session.
			// The kernel must already be running (launched via billing panel).
			jegKernelID := strings.TrimSpace(postReq.Kernel.ID)
			if jegKernelID == "" && postKernelName != "" {
				jegKernelID = jeg.findJEGKernelIDByName(remoteUser, postKernelName)
			}

			if jegKernelID != "" && (jeg.isKnownJEGKernelID(jegKernelID) || jeg.jegHasKernel(jegKernelID, remoteUser)) {
				jeg.rememberJEGKernelID(jegKernelID)
				kernelName := strings.TrimSpace(postReq.Kernel.Name)
				if kernelName == "" {
					kernelName = postKernelName
				}
				if kernelName == "" {
					kernelName = jeg.findJEGKernelNameByID(remoteUser, jegKernelID)
				}
				sessType := strings.TrimSpace(postReq.Type)
				if sessType == "" {
					sessType = "notebook"
				}
				newSessionID := strings.TrimSpace(postReq.ID)
				if newSessionID == "" {
					h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", jegKernelID, time.Now().UnixNano())))
					newSessionID = fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
				}
				jeg.setSessionKernelOverride(remoteUser, newSessionID, jegKernelID, kernelName, strings.TrimSpace(postReq.Path), strings.TrimSpace(postReq.Name), sessType)
				out := buildSessionCompatResponse(newSessionID, sessionKernelOverride{
					KernelID: jegKernelID, KernelName: kernelName,
					Path: strings.TrimSpace(postReq.Path), Name: strings.TrimSpace(postReq.Name), Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session post synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, newSessionID, jegKernelID)
				jeg.logger.InfoContext(r.Context(), "access",
					slog.String("user_hash", userHash),
					slog.String("upstream", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusCreated),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// Unknown spec — try container as default.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}

			http.Error(w, "session creation failed", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// PATCH /api/sessions/{id} — kernel switch.
		if method == http.MethodPatch && strings.HasPrefix(jegPath, "/api/sessions/") {
			sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
			sessionID = strings.SplitN(sessionID, "/", 2)[0]

			var patchReq struct {
				Path   string `json:"path"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Kernel struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"kernel"`
			}
			_ = json.Unmarshal(body, &patchReq)

			patchKernelID := strings.TrimSpace(patchReq.Kernel.ID)
			patchKernelName := strings.TrimSpace(patchReq.Kernel.Name)

			// If switching to a JEG kernel, synthesize the response.
			if patchKernelID == "" && patchKernelName != "" {
				patchKernelID = jeg.findJEGKernelIDByName(remoteUser, patchKernelName)
			}
			if patchKernelID != "" && (jeg.isKnownJEGKernelID(patchKernelID) || jeg.jegHasKernel(patchKernelID, remoteUser)) {
				jeg.rememberJEGKernelID(patchKernelID)
				if patchKernelName == "" {
					patchKernelName = jeg.findJEGKernelNameByID(remoteUser, patchKernelID)
				}
				sessPath := strings.TrimSpace(patchReq.Path)
				sessName := strings.TrimSpace(patchReq.Name)
				sessType := strings.TrimSpace(patchReq.Type)
				if sessType == "" {
					sessType = "notebook"
				}
				jeg.setSessionKernelOverride(remoteUser, sessionID, patchKernelID, patchKernelName, sessPath, sessName, sessType)
				out := buildSessionCompatResponse(sessionID, sessionKernelOverride{
					KernelID: patchKernelID, KernelName: patchKernelName,
					Path: sessPath, Name: sessName, Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session patch synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, sessionID, patchKernelID)
				jeg.logger.InfoContext(r.Context(), "access",
					slog.String("user_hash", userHash),
					slog.String("upstream", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusOK),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// If the session is a JEG override with no kernel change, update metadata.
			if patchKernelID == "" && patchKernelName == "" {
				if override, ok := jeg.getSessionKernelOverride(remoteUser, sessionID); ok {
					if strings.TrimSpace(patchReq.Path) != "" {
						override.Path = strings.TrimSpace(patchReq.Path)
					}
					if strings.TrimSpace(patchReq.Name) != "" {
						override.Name = strings.TrimSpace(patchReq.Name)
					}
					if strings.TrimSpace(patchReq.Type) != "" {
						override.Type = strings.TrimSpace(patchReq.Type)
					}
					jeg.setSessionKernelOverride(remoteUser, sessionID, override.KernelID, override.KernelName, override.Path, override.Name, override.Type)
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					jeg.logger.InfoContext(r.Context(), "access",
						slog.String("user_hash", userHash),
						slog.String("upstream", "override"),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", http.StatusOK),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}

			// Local kernel switch or unknown — forward to container.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					// Switching away from JEG — clear override if present.
					jeg.clearSessionKernelOverride(remoteUser, sessionID)
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
				// Container 404 on synthetic session — create new local session.
				if status == http.StatusNotFound && patchKernelName != "" &&
					isLocalContainerSpec(microUpstream, patchKernelName, remoteUser) {
					jeg.clearSessionKernelOverride(remoteUser, sessionID)
					sessType := strings.TrimSpace(patchReq.Type)
					if sessType == "" {
						sessType = "notebook"
					}
					postPayload, _ := json.Marshal(map[string]interface{}{
						"path":   patchReq.Path,
						"name":   patchReq.Name,
						"type":   sessType,
						"kernel": map[string]string{"name": patchKernelName},
					})
					up := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + "/api/sessions"
					pReq, _ := http.NewRequest(http.MethodPost, up, bytes.NewReader(postPayload))
					pReq.Header.Set("Content-Type", "application/json")
					pReq.Header.Set("REMOTE_USER", remoteUser)
					pResp, pErr := http.DefaultClient.Do(pReq)
					if pErr == nil {
						defer pResp.Body.Close()
						pBody, _ := io.ReadAll(pResp.Body)
						pStatus := pResp.StatusCode
						if pStatus == http.StatusCreated {
							pStatus = http.StatusOK
						}
						if pStatus < 400 {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(pStatus)
							_, _ = w.Write(pBody)
							log.Printf(`{"msg":"session patch created local session","user_hash":%q,"kernel":%q}`, userHash, patchKernelName)
							jeg.logger.InfoContext(r.Context(), "access",
								slog.String("user_hash", userHash),
								slog.String("upstream", microUpstream),
								slog.String("method", method),
								slog.String("path", r.URL.Path),
								slog.Int("status", pStatus),
								slog.Duration("duration", time.Since(start)),
							)
							return
						}
					}
				}
			}

			http.Error(w, "session patch failed", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// DELETE /api/sessions/{id}
		if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/sessions/") {
			sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
			sessionID = strings.SplitN(sessionID, "/", 2)[0]
			jeg.clearSessionKernelOverride(remoteUser, sessionID)

			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}
			// Not in container — 204 regardless (override already cleared).
			w.WriteHeader(http.StatusNoContent)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusNoContent),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// Other session methods — proxy to container.
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(r.Context(), "access",
			slog.String("user_hash", userHash),
			slog.String("upstream", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// /api/contents — always routed to the micro-container (file system is local).
	if strings.HasPrefix(jegPath, "/api/contents") {
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(r.Context(), "access",
			slog.String("user_hash", userHash),
			slog.String("upstream", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// WS /api/kernels/{id}/channels — stateless routing with JEG precedence:
	// if JEG owns the kernel ID, always tunnel to JEG; otherwise try container.
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if sid := strings.TrimSpace(r.URL.Query().Get("session_id")); sid != "" {
			if override, ok := jeg.getSessionKernelOverride(remoteUser, sid); ok {
				overrideKernelID := strings.TrimSpace(override.KernelID)
				if overrideKernelID != "" && overrideKernelID != kernelID {
					log.Printf(`{"msg":"jeg channels session override reroute","user_hash":%q,"session_id":%q,"from_kernel_id":%q,"to_kernel_id":%q}`, userHash, sid, kernelID, overrideKernelID)
					kernelID = overrideKernelID
					jeg.rememberJEGKernelID(kernelID)
					jegPath = "/api/kernels/" + kernelID + "/channels"
				}
			}
		}
		jegKnown := jeg.isKnownJEGKernelID(kernelID)
		jegOwns := false
		if kernelID != "" {
			jegOwns = jeg.jegHasKernel(kernelID, remoteUser)
			if jegKnown && !jegOwns {
				jeg.forgetJEGKernelID(kernelID)
				jegKnown = false
			}
		}
		if jegKnown || jegOwns {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"jeg","known_jeg_kernel":%t,"jeg_has_kernel":%t}`, userHash, kernelID, jegKnown, jegOwns)
			// JEG kernel — tunnel WS to JEG.
			target := *jegBase
			target.Path = jegPath
			target.RawQuery = r.URL.RawQuery
			// Set user identity headers; do NOT call forwardJEGHeaders here because
			// it deletes Connection and Upgrade from r.Header, which our proxyWebSocket
			// needs to forward in the WS handshake (Sec-WebSocket-Key etc. are in
			// r.Header; Connection/Upgrade are written explicitly by proxyWebSocket).
			r.Header.Set("REMOTE_USER", remoteUser)
			r.Header.Set("remote_user", remoteUser)
			status := proxy.ProxyWebSocket(w, r, &target)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("upstream", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		} else if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"container"}`, userHash, kernelID)
			// Container owns this kernel — tunnel WS to the container.
			containerWS, _ := url.Parse(microUpstream)
			containerWS.Path = proxy.UpstreamPrefix + jegPath
			containerWS.RawQuery = r.URL.RawQuery
			r.Header.Set("REMOTE_USER", remoteUser)
			status := proxy.ProxyWebSocket(w, r, containerWS)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("upstream", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		} else {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"jeg-default"}`, userHash, kernelID)
			// Default to JEG when ownership is ambiguous.
			target := *jegBase
			target.Path = jegPath
			target.RawQuery = r.URL.RawQuery
			// Set user identity headers; do NOT call forwardJEGHeaders here because
			// it deletes Connection and Upgrade from r.Header, which our proxyWebSocket
			// needs to forward in the WS handshake (Sec-WebSocket-Key etc. are in
			// r.Header; Connection/Upgrade are written explicitly by proxyWebSocket).
			r.Header.Set("REMOTE_USER", remoteUser)
			r.Header.Set("remote_user", remoteUser)
			status := proxy.ProxyWebSocket(w, r, &target)
			jeg.logger.InfoContext(r.Context(), "access",
				slog.String("user_hash", userHash),
				slog.String("upstream", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		}
		return
	}

	// GET /api/kernelspecs — merge local container specs + JEG filtered specs.
	if method == http.MethodGet && jegPath == "/api/kernelspecs" {
		// Fetch JEG specs (may be empty when no policy — that's fine, local fills it).
		jegReq, _ := http.NewRequest(http.MethodGet, jeg.gatewayURL+"/api/kernelspecs", nil)
		forwardJEGHeaders(jegReq)
		jegResp, jegErr := http.DefaultClient.Do(jegReq)
		var jegFiltered []byte
		if jegErr == nil && jegResp.StatusCode == http.StatusOK {
			rawJEG, _ := io.ReadAll(jegResp.Body)
			jegResp.Body.Close()
			jegFiltered = jeg.filterJEGKernelspecs(rawJEG)

			// Ensure kernelspecs for currently running JEG kernels are
			// included even when the policy filters them out, so JupyterLab
			// can display proper kernel names for active sessions.
			runningKernels := jeg.listJEGKernels(remoteUser)
			log.Printf(`{"msg":"kernelspec merge debug","user_hash":%q,"running_kernel_count":%d,"raw_jeg_len":%d,"filtered_len":%d}`, userHash, len(runningKernels), len(rawJEG), len(jegFiltered))
			if len(runningKernels) > 0 {
				var filteredEnv struct {
					Default     string                     `json:"default"`
					Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
				}
				var rawEnv struct {
					Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
				}
				if json.Unmarshal(jegFiltered, &filteredEnv) == nil && json.Unmarshal(rawJEG, &rawEnv) == nil {
					runningNames := make(map[string]bool)
					for _, k := range runningKernels {
						if n := strings.TrimSpace(k.Name); n != "" {
							runningNames[n] = true
						}
					}
					changed := false
					for specName, specJSON := range rawEnv.Kernelspecs {
						if runningNames[specName] {
							if _, exists := filteredEnv.Kernelspecs[specName]; !exists {
								if filteredEnv.Kernelspecs == nil {
									filteredEnv.Kernelspecs = make(map[string]json.RawMessage)
								}
								filteredEnv.Kernelspecs[specName] = specJSON
								changed = true
							}
						}
					}
					if changed {
						if out, err := json.Marshal(filteredEnv); err == nil {
							jegFiltered = out
							log.Printf(`{"msg":"kernelspec merge added running specs","user_hash":%q,"spec_count":%d}`, userHash, len(filteredEnv.Kernelspecs))
						}
					}
				}
			}
		} else {
			if jegResp != nil {
				jegResp.Body.Close()
			}
			jegFiltered = []byte(`{"default":"","kernelspecs":{}}`)
		}

		// Fetch local container specs and merge.
		var result []byte
		if microUpstream != "" {
			localRaw, localErr := fetchLocalKernelspecs(microUpstream, remoteUser)
			if localErr == nil {
				result = mergeKernelspecs(localRaw, jegFiltered)
			} else {
				log.Printf(`{"msg":"local kernelspecs fetch failed","error":%q}`, localErr.Error())
				result = jegFiltered
			}
		} else {
			result = jegFiltered
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(result)
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// POST /api/kernels — stateless routing: ask the container if it knows the spec.
	// Local spec → forward to container; JEG spec → 403 billing gate.
	if method == http.MethodPost && jegPath == "/api/kernels" {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var launchReq struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(body, &launchReq)

		if microUpstream != "" && isLocalContainerSpec(microUpstream, launchReq.Name, remoteUser) {
			// Container owns this spec — forward launch to the container's Jupyter.
			r.Body = io.NopCloser(bytes.NewReader(body))
			status := proxy.ProxyToContainer(w, r, "/api/kernels", microUpstream, remoteUser)
			log.Printf(`{"msg":"local kernel launched","spec":%q,"status":%d}`, launchReq.Name, status)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// JEG spec (or unknown spec) — billing gate: not allowed via this route.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"GPU kernel launch requires the Vectis Kernel Panel. Select a kernel type there to launch with billing authorization."}`))
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodGet && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if jeg.jegHasKernel(kernelID, remoteUser) {
			// JEG-owned kernel ID.
			upstreamURL := jeg.gatewayURL + jegPath
			req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				http.Error(w, "kernel not found", http.StatusBadGateway)
				jeg.logger.InfoContext(
					r.Context(),
					"access",
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
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", resp.StatusCode),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		// Not in container — try JEG.
		upstreamURL := jeg.gatewayURL + jegPath
		req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "kernel not found", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
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
		if resp.StatusCode == http.StatusNotFound {
			jeg.forgetJEGKernelID(kernelID)
		}
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernels — merge container running kernels + JEG running kernels.
	if method == http.MethodGet && jegPath == "/api/kernels" {
		type kernelEntry = json.RawMessage
		var merged []kernelEntry
		jegIDs := map[string]struct{}{}

		// Fetch from JEG.
		jegReq, _ := http.NewRequest(http.MethodGet, jeg.gatewayURL+"/api/kernels", nil)
		forwardJEGHeaders(jegReq)
		if jegResp, err := http.DefaultClient.Do(jegReq); err == nil {
			defer jegResp.Body.Close()
			var jegKernels []kernelEntry
			if jegBody, err := io.ReadAll(jegResp.Body); err == nil {
				_ = json.Unmarshal(jegBody, &jegKernels)
				for _, entry := range jegKernels {
					var k struct {
						ID string `json:"id"`
					}
					if json.Unmarshal(entry, &k) == nil {
						jeg.rememberJEGKernelID(k.ID)
						if strings.TrimSpace(k.ID) != "" {
							jegIDs[strings.TrimSpace(k.ID)] = struct{}{}
						}
					}
				}
				merged = append(merged, jegKernels...)
			}
		}

		// Fetch from container.
		if microUpstream != "" {
			containerURL := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + "/api/kernels"
			contReq, _ := http.NewRequest(http.MethodGet, containerURL, nil)
			contReq.Header.Set("REMOTE_USER", remoteUser)
			if contResp, err := http.DefaultClient.Do(contReq); err == nil {
				defer contResp.Body.Close()
				var localKernels []kernelEntry
				if contBody, err := io.ReadAll(contResp.Body); err == nil {
					if json.Unmarshal(contBody, &localKernels) == nil {
						for _, entry := range localKernels {
							var k struct {
								ID string `json:"id"`
							}
							if json.Unmarshal(entry, &k) != nil {
								continue
							}
							// Skip local kernels whose IDs duplicate a JEG kernel (GatewayClient proxy-through)
							if _, ok := jegIDs[strings.TrimSpace(k.ID)]; ok {
								continue
							}
							merged = append(merged, entry)
						}
						log.Printf(`{"msg":"jeg kernels list merged local","user_hash":%q,"jeg_kernel_count":%d,"local_kernel_count":%d,"merged_total":%d}`, userHash, len(jegIDs), len(localKernels), len(merged))
					}
				}
			}
		}

		if merged == nil {
			merged = []kernelEntry{}
		}
		out, _ := json.Marshal(merged)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// DELETE /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if jeg.jegHasKernel(kernelID, remoteUser) {
			// JEG kernel.
			upstream := jeg.gatewayURL + "/api/kernels/" + kernelID
			req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			status := http.StatusNoContent
			if err != nil {
				status = http.StatusBadGateway
				http.Error(w, "JEG delete failed", status)
				jeg.logger.InfoContext(
					r.Context(),
					"access",
					slog.String("user_hash", userHash),
					slog.String("gateway_url", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", status),
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
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxy.ProxyToContainer(w, r, "/api/kernels/"+kernelID, microUpstream, remoteUser)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		// JEG kernel.
		upstream := jeg.gatewayURL + "/api/kernels/" + kernelID
		req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		status := http.StatusNoContent
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "JEG delete failed", status)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
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
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// /lw-workspace/proxy/... — resource URLs (kernelspec logos, static assets) whose
	// absolute form was embedded in our GET /api/kernelspecs response. JupyterLite
	// constructs fetch URLs as remoteKernelsBaseUrl + resource_url, where resource_url
	// already contains /lw-workspace/proxy/, producing a double-prefix. Strip the
	// extra prefix and proxy the resource to the container.
	if strings.HasPrefix(jegPath, proxy.UpstreamPrefix+"/") {
		containerPath := strings.TrimPrefix(jegPath, proxy.UpstreamPrefix)
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		status := proxy.ProxyToContainer(w, r, containerPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// All other paths: not supported by this gateway.
	http.Error(w, "Not found", http.StatusNotFound)
	jeg.logger.InfoContext(
		r.Context(),
		"access",
		slog.String("user_hash", userHash),
		slog.String("gateway_url", jeg.gatewayURL),
		slog.String("method", method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusNotFound),
		slog.Duration("duration", time.Since(start)),
	)
}

// ---- JEG kernel panel API (/jeg-panel/) ----
//
// Serves the Vectis KernelLifecyclePanel. Unlike /jeg-proxy/ (which is pointed at
// by JupyterLab's GatewayClient and hides kernelspecs to force panel-driven launches),
// this route is designed to be queried by the React panel directly:
//
//   - GET  /api/status              → {"enabled":true} — pre-flight for useGatewayConnection
//   - GET  /api/kernelspecs         → filtered by allowedSpecs; all specs when no policy (dev)
//   - GET  /api/kernels             → user's active JEG kernels (passed through)
//   - POST /api/kernels             → billing gate: allowedSpecs check → 403 if not allowed → forward
//   - DELETE /api/kernels/{id}      → force-terminate (passed through)
//
// Billing gate: if JEG_KERNEL_SPEC_POLICY.allowedSpecs is non-empty, any POST
// requesting a spec name not in the list is rejected 403. Empty policy = allow all (dev).

// filterJEGKernelspecsForPanel is the panel-side spec filter:
// unlike the ghost gateway (which returns empty when no policy to prevent direct launches)
// the panel ALWAYS shows available specs so the user can pick one.
func (jeg *JEG) filterJEGKernelspecsForPanel(rawBody []byte) []byte {
	if jeg.kernelSpecPolicy == nil || len(jeg.kernelSpecPolicy.AllowedSpecs) == 0 {
		// No policy: return all specs from JEG so the panel can show everything.
		return rawBody
	}

	var raw struct {
		Default     string                     `json:"default"`
		Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
	}
	if err := json.Unmarshal(rawBody, &raw); err != nil {
		return rawBody
	}

	filtered := make(map[string]json.RawMessage, len(jeg.kernelSpecPolicy.AllowedSpecs))
	for _, name := range jeg.kernelSpecPolicy.AllowedSpecs {
		spec, ok := raw.Kernelspecs[name]
		if !ok {
			continue
		}
		// Inject cost/nodeType/displayName metadata.
		var specObj map[string]interface{}
		if err := json.Unmarshal(spec, &specObj); err == nil {
			inner, _ := specObj["spec"].(map[string]interface{})
			if inner == nil {
				inner = map[string]interface{}{}
				specObj["spec"] = inner
			}
			meta, _ := inner["metadata"].(map[string]interface{})
			if meta == nil {
				meta = map[string]interface{}{}
				inner["metadata"] = meta
			}
			meta["costPerHour"] = jeg.kernelSpecPolicy.CostPerHour[name]
			meta["nodeType"] = jeg.kernelSpecPolicy.NodeType[name]
			if dn, ok := jeg.kernelSpecPolicy.DisplayNames[name]; ok {
				inner["display_name"] = dn
			}
			if b, err := json.Marshal(specObj); err == nil {
				filtered[name] = b
				continue
			}
		}
		filtered[name] = spec
	}

	defaultSpec := raw.Default
	if _, ok := filtered[defaultSpec]; !ok {
		defaultSpec = ""
		for _, name := range jeg.kernelSpecPolicy.AllowedSpecs {
			if _, ok := filtered[name]; ok {
				defaultSpec = name
				break
			}
		}
	}

	result := map[string]interface{}{
		"default":     defaultSpec,
		"kernelspecs": filtered,
	}
	b, err := json.Marshal(result)
	if err != nil {
		return rawBody
	}
	return b
}

func (jeg *JEG) PanelHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Auth: REMOTE_USER is set by revproxy auth_request on /lw-workspace/proxy/*.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := workspace.NormalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = workspace.NormalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		jeg.logger.InfoContext(
			r.Context(),
			"access",
			slog.String("user_hash", ""),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}
	userHash := workspace.HashUser(remoteUser)

	// /jeg-panel prefix is already stripped by http.StripPrefix in main().
	panelPath := r.URL.Path
	if panelPath == "" {
		panelPath = "/"
	}

	method := r.Method

	forwardHeaders := func(req *http.Request) {
		req.Header.Set("REMOTE_USER", remoteUser)
		req.Header.Set("remote_user", remoteUser)
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
			"access",
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
				"access",
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
				"access",
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
			"access",
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
				"access",
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
			"access",
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
				"access",
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
					"access",
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
				"access",
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
			"access",
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
		kernelID := strings.TrimPrefix(panelPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access",
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
				"access",
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
			"access",
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
		"access",
		slog.String("user_hash", userHash),
		slog.String("gateway_url", jeg.gatewayURL),
		slog.String("method", method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusNotFound),
		slog.Duration("duration", time.Since(start)),
	)
}

// StartStateGC starts a background goroutine that periodically evicts stale entries
// from the in-memory state maps to prevent unbounded memory growth.
//
// Without this, any workspace session that ends without a clean DELETE
// (e.g. browser crash, closed laptop) leaks entries forever, eventually causing
// the proxy pod to hit its 256Mi memory limit and be OOMKilled by Kubernetes.
//
//   - sessionKernelOverrides: evicted when UpdatedAt is older than maxAge
//   - knownJEGKernelIDs/Age:  evicted when last observed time is older than maxAge
//
// maxAge=4h means a kernel orphaned at midnight is cleaned up by 4am at the latest.
func (jeg *JEG) StartStateGC(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-maxAge)
			var evictedSessions, evictedKernels int

			jeg.sessionKernelOverrides.Range(func(key, value any) bool {
				ov, ok := value.(sessionKernelOverride)
				if ok && ov.UpdatedAt.Before(cutoff) {
					jeg.sessionKernelOverrides.Delete(key)
					evictedSessions++
				}
				return true
			})

			jeg.knownJEGKernelIDsAge.Range(func(key, value any) bool {
				t, ok := value.(time.Time)
				if ok && t.Before(cutoff) {
					jeg.knownJEGKernelIDsAge.Delete(key)
					jeg.knownJEGKernelIDs.Delete(key)
					evictedKernels++
				}
				return true
			})

			if evictedSessions > 0 || evictedKernels > 0 {
				log.Printf(`{"msg":"state GC cycle","evicted_sessions":%d,"evicted_kernel_ids":%d}`,
					evictedSessions, evictedKernels)
			}
		}
	}()
}
