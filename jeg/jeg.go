package jeg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/uc-cdis/workspace-proxy/internal/identity"
	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/proxy"
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

type sessionMetadata struct {
	Path string
	Name string
	Type string
}

func metadataFromOverride(override sessionKernelOverride) sessionMetadata {
	return sessionMetadata{
		Path: strings.TrimSpace(override.Path),
		Name: strings.TrimSpace(override.Name),
		Type: strings.TrimSpace(override.Type),
	}
}

// fillMissingSessionMetadata keeps metadata already associated with the active
// session and fills any gaps from another representation of that session.
func fillMissingSessionMetadata(current, fallback sessionMetadata) sessionMetadata {
	if current.Path == "" {
		current.Path = strings.TrimSpace(fallback.Path)
	}
	if current.Name == "" {
		current.Name = strings.TrimSpace(fallback.Name)
	}
	if current.Type == "" {
		current.Type = strings.TrimSpace(fallback.Type)
	}
	return current
}

// applySessionMetadataPatch follows PATCH semantics: an omitted property keeps
// its old value, while an explicitly supplied property (including "") replaces
// it. JupyterLab normally sends only kernel during a kernel switch.
func applySessionMetadataPatch(current sessionMetadata, path, name, sessionType *string) sessionMetadata {
	if path != nil {
		current.Path = strings.TrimSpace(*path)
	}
	if name != nil {
		current.Name = strings.TrimSpace(*name)
	}
	if sessionType != nil {
		current.Type = strings.TrimSpace(*sessionType)
	}
	if current.Type == "" {
		current.Type = "notebook"
	}
	return current
}

// fetchContainerSessionMetadata gets the notebook identity before a local
// session is replaced by a synthetic JEG session. Kernel-only PATCH requests do
// not carry these fields, but JupyterLab still requires them in the response.
func fetchContainerSessionMetadata(ctx context.Context, microBase, sessionID string, id identity.Identity) (sessionMetadata, bool) {
	if strings.TrimSpace(microBase) == "" || strings.TrimSpace(sessionID) == "" {
		return sessionMetadata{}, false
	}

	upstream := strings.TrimRight(microBase, "/") + proxy.UpstreamPrefix + "/api/sessions/" + strings.TrimSpace(sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return sessionMetadata{}, false
	}
	identity.SetUpstreamHeaders(req.Header, id)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sessionMetadata{}, false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log the error or otherwise handle it.
			log.Printf("failed to close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return sessionMetadata{}, false
	}

	var session struct {
		Path     string `json:"path"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Notebook struct {
			Path string `json:"path"`
			Name string `json:"name"`
		} `json:"notebook"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return sessionMetadata{}, false
	}
	metadata := sessionMetadata{
		Path: strings.TrimSpace(session.Path),
		Name: strings.TrimSpace(session.Name),
		Type: strings.TrimSpace(session.Type),
	}
	metadata = fillMissingSessionMetadata(metadata, sessionMetadata{
		Path: session.Notebook.Path,
		Name: session.Notebook.Name,
		Type: "notebook",
	})
	return metadata, true
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
	workspaceNamespace     string
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

func New(logger *slog.Logger, k8s *kubernetes.Client, workspaceNamespace, gatewayURL string, jegKernelSpecPolicy string) *JEG {
	policy, err := parseKernelSpecPolicy(jegKernelSpecPolicy)
	if err != nil {
		// logger.Printf(
		// 	`{"msg":"JEG_KERNEL_SPEC_POLICY parse error; ghost gateway will return empty specs","error":%q}`,
		// 	err.Error(),
		// )

		policy = &jegKernelPolicy{}
	}

	return &JEG{
		logger:             logger,
		gatewayURL:         gatewayURL,
		K8s:                k8s,
		workspaceNamespace: workspaceNamespace,
		kernelSpecPolicy:   policy,
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

// jegHasKernel verifies kernel ownership for this user using JEG's filtered
// list endpoint (/api/kernels), avoiding reliance on direct ID lookups.
// Used as a routing discriminator because container /api/kernels/{id} may proxy
// through GatewayClient and return JEG-owned kernels as 200.
func (jeg *JEG) jegHasKernel(kernelID, remoteUser string) bool {
	kernelID = strings.TrimSpace(kernelID)
	if jeg.gatewayURL == "" || kernelID == "" {
		return false
	}
	for _, k := range jeg.listJEGKernels(remoteUser) {
		if strings.TrimSpace(k.ID) == kernelID {
			jeg.rememberJEGKernelID(kernelID)
			return true
		}
	}
	return false
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

// findJEGKernelNameByID resolves a running JEG kernel name by ID, scoped to
// kernels visible to the current user.
func (jeg *JEG) findJEGKernelNameByID(remoteUser, kernelID string) string {
	if jeg.gatewayURL == "" {
		return ""
	}
	kernelID = strings.TrimSpace(kernelID)
	if kernelID == "" {
		return ""
	}
	for _, kernel := range jeg.listJEGKernels(remoteUser) {
		if strings.TrimSpace(kernel.ID) == kernelID {
			jeg.rememberJEGKernelID(kernelID)
			return strings.TrimSpace(kernel.Name)
		}
	}
	jeg.forgetJEGKernelID(kernelID)
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
