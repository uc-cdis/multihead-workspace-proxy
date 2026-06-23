// workspace-proxy — per-user workspace routing service for Gen3.
//
// Receives authenticated requests from revproxy (nginx) with REMOTE_USER header
// already set by the upstream auth_request (Arborist). Derives the per-user
// Hatchery Service name via escapism(), then queries the Kubernetes API to
// resolve the actual upstream host:port from the Service's getambassador.io/config
// annotation — capturing local pods, external-cluster nodes, ECS/Fargate ALBs,
// and GPU nodes that use non-standard ports, without hardcoding port 80.
//
// Security properties:
//   - Fail-closed: returns 403 if REMOTE_USER is absent or empty.
//   - Fail-closed: returns 502 if workspace Service not found (pod not running).
//   - User isolation: upstream derived solely from REMOTE_USER; K8s lookup uses
//     only the service name keyed to that user — cannot be manipulated by the client.
//   - PII-safe logs: username is SHA-256 hashed before logging.
//   - WebSocket: handled via raw TCP tunnel (kernel connections, noVNC).
//
// Environment variables:
//   LISTEN_ADDR         — listen address (default: :8080)
//   WORKSPACE_NAMESPACE — namespace where Hatchery creates user Services (default: jupyter-pods)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---- config ----

var (
	listenAddr  = envOrDefault("LISTEN_ADDR", ":8080")
	workspaceNS = envOrDefault("WORKSPACE_NAMESPACE", "jupyter-pods")

	// JEG ghost-gateway: when set, workspace-proxy exposes /jeg-proxy/* which
	// acts as a gating reverse proxy to Jupyter Enterprise Gateway.
	// JupyterLab inside the micro-container points --GatewayClient.url at this route
	// so kernel launch requests can be intercepted and blocked (forcing users through
	// the Vectis billing panel), while GET /api/kernels and WS /api/kernels/*/channels
	// are passed through for native kernel discovery and comms.
	jegGatewayURL        = envOrDefault("JEG_GATEWAY_URL", "")
	jegKernelSpecPolicy  = envOrDefault("JEG_KERNEL_SPEC_POLICY", "")
)

// upstreamPrefix is the base URL path that nginx strips before forwarding to this service.
// The revproxy rewrite rule is: `rewrite ^/lw-workspace/proxy/(.*) /$1 break;`
// Jupyter is started with --NotebookApp.base_url=/lw-workspace/proxy/ and expects this prefix.
// We restore it before forwarding, mirroring Ambassador's `rewrite: /lw-workspace/proxy/`.
const upstreamPrefix = "/lw-workspace/proxy"

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---- escapism — exact replica of Hatchery's algorithm ----
//
// Non-[a-z0-9] characters are encoded as -{2-char-hex} using fmt.Sprintf("%2x", ch),
// which matches Hatchery's: hexCode := fmt.Sprintf("%2x", v) / escaped += "-" + hexCode
func escapism(input string) string {
	const safe = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for _, ch := range input {
		if strings.ContainsRune(safe, ch) {
			sb.WriteRune(ch)
		} else {
			sb.WriteString(fmt.Sprintf("-%2x", ch))
		}
	}
	return sb.String()
}

// userToServiceName derives the Hatchery per-user ClusterIP service name.
// Matches pods.go: fmt.Sprintf("h-%s-s", escapism(userName))
func userToServiceName(username string) string {
	return fmt.Sprintf("h-%s-s", escapism(username))
}

// hashUser returns a truncated SHA-256 hex digest of the username for PII-safe logging.
func hashUser(username string) string {
	sum := sha256.Sum256([]byte(username))
	return fmt.Sprintf("%x", sum[:8])
}

// normalizeRemoteUser converts Gen3 authz REMOTE_USER formats into a plain username.
// Example: "uid:4,test" -> "test".
func normalizeRemoteUser(remoteUser string) string {
	v := strings.TrimSpace(remoteUser)
	if strings.HasPrefix(v, "uid:") {
		parts := strings.SplitN(v, ",", 2)
		if len(parts) == 2 {
			if username := strings.TrimSpace(parts[1]); username != "" {
				return username
			}
		}
	}
	return v
}

// parseRemoteUserID extracts the numeric uid from REMOTE_USER formats like "uid:4,test".
func parseRemoteUserID(remoteUser string) string {
	v := strings.TrimSpace(remoteUser)
	if !strings.HasPrefix(v, "uid:") {
		return ""
	}
	v = strings.TrimPrefix(v, "uid:")
	parts := strings.SplitN(v, ",", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

// parseAmbassadorRemoteUserField scans Hatchery's getambassador.io/config YAML blob
// for the "remote_user:" line inside headers and returns the value.
func parseAmbassadorRemoteUserField(annotYAML string) string {
	for _, line := range strings.Split(annotYAML, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "remote_user:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "remote_user:"))
		if value == "" {
			continue
		}
		return value
	}
	return ""
}

func annotationRemoteUserMatches(annotationRemoteUser, normalizedUser, identityRaw, remoteUserHeader string) bool {
	annot := strings.TrimSpace(annotationRemoteUser)
	if annot == "" {
		return false
	}

	candidates := []string{
		strings.TrimSpace(normalizedUser),
		strings.TrimSpace(identityRaw),
		strings.TrimSpace(remoteUserHeader),
	}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if annot == c || strings.EqualFold(annot, c) {
			return true
		}
	}

	uid := parseRemoteUserID(identityRaw)
	if uid == "" {
		uid = parseRemoteUserID(remoteUserHeader)
	}
	if uid != "" {
		if annot == uid || strings.EqualFold(annot, uid) {
			return true
		}
		uidCandidate := fmt.Sprintf("%s, %s", uid, uid)
		if annot == uidCandidate || strings.EqualFold(annot, uidCandidate) {
			return true
		}
	}

	return false
}

// ---- Kubernetes service discovery ----
//
// workspace-proxy queries the K8s API at request time (with per-user caching) to
// resolve the actual upstream host:port for each user's workspace Service.
//
// Hatchery writes the routing target into the getambassador.io/config annotation:
//   - Local cluster pod:   service: {svcName}.{namespace}.svc.cluster.local:80
//   - External node/GPU:   service: {nodeIP}:{nodePort}  (random NodePort)
//   - ECS/Fargate:         service: {albDNS}:{port}
//
// We extract that "service:" field so we never assume port 80 — GPU nodes,
// external clusters, and ECS all have different ports assigned at launch time.

// k8sClient wraps in-cluster credentials for Kubernetes API calls.
// tokenPath is stored rather than the token itself so that Bound Service Account
// Token rotation (EKS/GKE default — tokens expire every 1h) is picked up on every
// API call without requiring a pod restart.
type k8sClient struct {
	httpClient *http.Client
	tokenPath  string // re-read on every request — never cached in memory
	apiBase    string
}

// bearerToken reads the current service account token from disk.
// Returns an error if the token cannot be read so callers can return 502 rather
// than silently forwarding an expired credential.
func (c *k8sClient) bearerToken() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading SA token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// k8s is the global in-cluster client; nil when running outside a cluster.
var k8s *k8sClient

func initK8sClient() *k8sClient {
	const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	const caPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// Verify the token file exists at startup so we can log clearly if not in-cluster.
	if _, err := os.ReadFile(tokenPath); err != nil {
		log.Printf(`{"msg":"no SA token — falling back to plain DNS (not in-cluster?)","detail":%q}`, err.Error())
		return nil
	}

	tlsCfg := &tls.Config{}
	if caBytes, err := os.ReadFile(caPath); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caBytes)
		tlsCfg.RootCAs = pool
	}

	return &k8sClient{
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   5 * time.Second,
		},
		tokenPath: tokenPath,
		apiBase:   "https://kubernetes.default.svc",
	}
}

// upstreamEntry is a cached upstream URL with an expiry time.
type upstreamEntry struct {
	upstream string
	expires  time.Time
}

// upstreamCache caches the resolved upstream per username.
// TTL is 30s — short enough to pick up pod-restart port changes, long enough
// to avoid K8s API calls on every WebSocket frame heartbeat.
var upstreamCache sync.Map // map[string]*upstreamEntry

const upstreamCacheTTL = 30 * time.Second

// ---- K8s service-list TTL cache ----
//
// lookupByAnnotationRemoteUser does a full LIST of all Services in the workspace
// namespace. Without caching, any auth mismatch or fallback path would hit the
// K8s API once per request, which at scale is an accidental DoS on the control plane.
// We cache the list for svcListCacheTTL and forcibly evict it in proxy.ErrorHandler
// so pod restarts are picked up promptly.

type svcListItem struct {
	Name        string
	Annotations map[string]string
	Ports       []int32
}

type svcListCacheEntry struct {
	items   []svcListItem
	expires time.Time
}

// svcListCache is an atomic.Value holding *svcListCacheEntry; nil when empty.
var svcListCacheVal atomic.Value

const svcListCacheTTL = 10 * time.Second

func loadSvcListCache() *svcListCacheEntry {
	v := svcListCacheVal.Load()
	if v == nil {
		return nil
	}
	return v.(*svcListCacheEntry)
}

func storeSvcListCache(items []svcListItem) {
	svcListCacheVal.Store(&svcListCacheEntry{
		items:   items,
		expires: time.Now().Add(svcListCacheTTL),
	})
}

// evictSvcListCache forces the next lookupByAnnotationRemoteUser call to re-list.
func evictSvcListCache() {
	svcListCacheVal.Store((*svcListCacheEntry)(nil))
}

// lookupUpstream returns the HTTP upstream base URL for the given username,
// using the cache when valid and querying K8s when not.
func lookupUpstream(username string) (string, error) {
	if v, ok := upstreamCache.Load(username); ok {
		entry := v.(*upstreamEntry)
		if time.Now().Before(entry.expires) {
			return entry.upstream, nil
		}
		upstreamCache.Delete(username)
	}

	svcName := userToServiceName(username)
	upstream, err := resolveUpstream(svcName)
	if err != nil {
		return "", err
	}

	upstreamCache.Store(username, &upstreamEntry{
		upstream: upstream,
		expires:  time.Now().Add(upstreamCacheTTL),
	})
	return upstream, nil
}

// lookupUpstreamWithFallback resolves upstream first by username-derived service name,
// then by scanning workspace services for a matching REMOTE_USER uid annotation.
func listWorkspaceServices() ([]svcListItem, error) {
	// Return cached list if still fresh.
	if entry := loadSvcListCache(); entry != nil && time.Now().Before(entry.expires) {
		return entry.items, nil
	}

	token, err := k8s.bearerToken()
	if err != nil {
		return nil, fmt.Errorf("sa token unavailable: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v1/namespaces/%s/services", k8s.apiBase, workspaceNS)
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := k8s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("k8s API returned HTTP %d while listing services", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading k8s service list response: %w", err)
	}

	var raw struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Ports []struct {
					Port int32 `json:"port"`
				} `json:"ports"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing k8s service list response: %w", err)
	}

	items := make([]svcListItem, 0, len(raw.Items))
	for _, s := range raw.Items {
		ports := make([]int32, 0, len(s.Spec.Ports))
		for _, p := range s.Spec.Ports {
			ports = append(ports, p.Port)
		}
		items = append(items, svcListItem{
			Name:        s.Metadata.Name,
			Annotations: s.Metadata.Annotations,
			Ports:       ports,
		})
	}

	storeSvcListCache(items)
	return items, nil
}

func lookupByAnnotationRemoteUser(username, identityRaw, remoteUserHeader string) (string, error) {
	if k8s == nil {
		return "", fmt.Errorf("k8s discovery unavailable")
	}

	svcs, err := listWorkspaceServices()
	if err != nil {
		return "", err
	}

	annotatedServiceCount := 0
	soleAnnotatedUpstream := ""

	for _, svc := range svcs {
		annotYAML := svc.Annotations["getambassador.io/config"]
		if annotYAML == "" {
			continue
		}

		annotatedServiceCount++
		if soleAnnotatedUpstream == "" {
			if hostPort := parseAmbassadorServiceField(annotYAML); hostPort != "" {
				soleAnnotatedUpstream = "http://" + hostPort
			} else {
				port := int32(80)
				if len(svc.Ports) > 0 {
					port = svc.Ports[0]
				}
				soleAnnotatedUpstream = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svc.Name, workspaceNS, port)
			}
		}

		annotationRemoteUser := parseAmbassadorRemoteUserField(annotYAML)
		if !annotationRemoteUserMatches(annotationRemoteUser, username, identityRaw, remoteUserHeader) {
			continue
		}

		if hostPort := parseAmbassadorServiceField(annotYAML); hostPort != "" {
			return "http://" + hostPort, nil
		}

		port := int32(80)
		if len(svc.Ports) > 0 {
			port = svc.Ports[0]
		}
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svc.Name, workspaceNS, port), nil
	}

	if annotatedServiceCount == 1 && soleAnnotatedUpstream != "" {
		return soleAnnotatedUpstream, nil
	}

	return "", fmt.Errorf("no service annotation matched remote_user for %q", username)
}

func lookupUpstreamWithFallback(username string, identityRaw string, remoteUserHeader string) (string, error) {
	upstream, err := lookupUpstream(username)
	if err == nil {
		return upstream, nil
	}

	uid := parseRemoteUserID(identityRaw)
	if uid == "" {
		uid = parseRemoteUserID(remoteUserHeader)
	}
	if uid == "" {
		return lookupByAnnotationRemoteUser(username, identityRaw, remoteUserHeader)
	}
	// Hatchery can derive service names from "<uid>, <uid>" (e.g. "4, 4" -> h-4-2c-204-s).
	uidHatcheryUser := fmt.Sprintf("%s, %s", uid, uid)
	upstreamByUID, uidErr := lookupUpstream(uidHatcheryUser)
	if uidErr != nil {
		annotationUpstream, annotErr := lookupByAnnotationRemoteUser(username, identityRaw, remoteUserHeader)
		if annotErr != nil {
			return "", err
		}

		upstreamCache.Store(username, &upstreamEntry{
			upstream: annotationUpstream,
			expires:  time.Now().Add(upstreamCacheTTL),
		})
		return annotationUpstream, nil
	}

	upstreamCache.Store(username, &upstreamEntry{
		upstream: upstreamByUID,
		expires:  time.Now().Add(upstreamCacheTTL),
	})

	return upstreamByUID, nil
}

// resolveUpstream fetches the K8s Service object and returns the upstream URL,
// preferring the host:port from the getambassador.io/config annotation.
func resolveUpstream(svcName string) (string, error) {
	if k8s == nil {
		// Not in-cluster (local dev without service account) — plain DNS + port 80.
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:80", svcName, workspaceNS), nil
	}

	token, err := k8s.bearerToken()
	if err != nil {
		return "", fmt.Errorf("sa token unavailable: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v1/namespaces/%s/services/%s", k8s.apiBase, workspaceNS, svcName)
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := k8s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("k8s API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("workspace service %q not found — pod not running", svcName)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("k8s API returned HTTP %d for service %q", resp.StatusCode, svcName)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading k8s response: %w", err)
	}

	// Minimal parse — only the fields we need.
	var svc struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Ports []struct {
				Port int32 `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &svc); err != nil {
		return "", fmt.Errorf("parsing k8s Service response: %w", err)
	}

	// Prefer the Ambassador annotation's service field — it contains the real
	// host:port for external-cluster nodes, ECS/Fargate ALBs, GPU NodePorts, etc.
	if annotYAML, ok := svc.Metadata.Annotations["getambassador.io/config"]; ok {
		if hostPort := parseAmbassadorServiceField(annotYAML); hostPort != "" {
			return "http://" + hostPort, nil
		}
	}

	// Fallback: K8s Service DNS + spec port (always correct for same-cluster pods).
	port := int32(80)
	if len(svc.Spec.Ports) > 0 {
		port = svc.Spec.Ports[0].Port
	}
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, workspaceNS, port), nil
}

// parseAmbassadorServiceField scans Hatchery's getambassador.io/config YAML blob
// for the "service: host:port" line and returns the value.
// The format is controlled by Hatchery's fmt.Sprintf so simple line scanning is safe.
// Returns "" if not found or malformed.
func parseAmbassadorServiceField(annotYAML string) string {
	for _, line := range strings.Split(annotYAML, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "service:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "service:"))
		// Must contain ":" to be a valid host:port.
		if value == "" || !strings.Contains(value, ":") {
			continue
		}
		return value
	}
	return ""
}

// ---- structured JSON access log ----

type accessLog struct {
	Time       string `json:"time"`
	UserHash   string `json:"user_hash,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"duration_ms"`
}

func logAccess(userHash, upstream, method, path string, status int, dur time.Duration) {
	entry := accessLog{
		Time:       time.Now().UTC().Format(time.RFC3339),
		UserHash:   userHash,
		Upstream:   upstream,
		Method:     method,
		Path:       path,
		Status:     status,
		DurationMs: dur.Milliseconds(),
	}
	b, _ := json.Marshal(entry)
	log.Println(string(b))
}

func ensureUpstreamPrefix(path string) string {
	if path == "" {
		return upstreamPrefix
	}
	if strings.HasPrefix(path, upstreamPrefix+"/") || path == upstreamPrefix {
		return path
	}
	return upstreamPrefix + path
}

// ---- WebSocket proxy — raw TCP tunnel ----
//
// httputil.ReverseProxy does not support WebSocket upgrade in all Go versions.
// We use a raw TCP dial + hijack approach which works unconditionally and
// provides proper bidirectional streaming for kernel connections.

// idleDeadlineConn wraps a net.Conn and bumps its read/write deadline on every
// successful Read so the connection is culled if it goes fully silent for idleTimeout.
// This prevents io.Copy goroutines from hanging forever when the upstream JEG process
// hangs or deadlocks (TCP Keep-Alives only detect OS-level liveness, not app-level).
type idleDeadlineConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *idleDeadlineConn) Read(b []byte) (int, error) {
	// Bump the deadline before each read; a successful transfer keeps the pipe alive.
	_ = c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
	return c.Conn.Read(b)
}

func (c *idleDeadlineConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
	return c.Conn.Write(b)
}

// wsIdleTimeout is the maximum time a WebSocket pipe can be fully silent before
// the proxy considers the upstream dead and closes the connection.
// Set well above the 60s React heartbeat and 30s TCP Keep-Alive period so healthy
// long-running kernel executions are never interrupted.
const wsIdleTimeout = 10 * time.Minute

func proxyWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL) int {
	port := target.Port()
	if port == "" {
		port = "80"
	}
	addr := net.JoinHostPort(target.Hostname(), port)

	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway: workspace unavailable", http.StatusBadGateway)
		return http.StatusBadGateway
	}
	defer upstream.Close()
	if tcpUp, ok := upstream.(*net.TCPConn); ok {
		_ = tcpUp.SetKeepAlive(true)
		_ = tcpUp.SetKeepAlivePeriod(30 * time.Second)
	}

	// Compute the path the upstream expects.
	// Use target.Path when the caller already resolved the correct path (e.g.
	// stripped /jeg-proxy/ for container kernels, bare /api/... for JEG).
	// Fall back to the incoming browser path with upstreamPrefix ensured.
	reqPath := target.Path
	if reqPath == "" {
		reqPath = ensureUpstreamPrefix(r.URL.Path)
	}
	if r.URL.RawQuery != "" {
		reqPath += "?" + r.URL.RawQuery
	}

	upstreamHost := target.Host
	if upstreamHost == "" {
		upstreamHost = addr
	}

	// Write the HTTP/1.1 Upgrade request manually rather than using r.Write().
	// r.Write() uses the stale r.RequestURI field (set by the HTTP server from
	// the original browser URL) as the request-line path, and it omits hop-by-hop
	// headers (Connection, Upgrade) per RFC 7230. Both are incorrect for WS proxying:
	// we need the caller-resolved path and we must forward the WS handshake headers.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", r.Method, reqPath)
	fmt.Fprintf(&buf, "Host: %s\r\n", upstreamHost)
	// Rewrite Origin: browser Origin points at the revproxy host, which Jupyter may
	// reject on same-origin checks. Use the upstream host instead.
	fmt.Fprintf(&buf, "Origin: http://%s\r\n", upstreamHost)
	// Always emit WS upgrade headers explicitly.
	buf.WriteString("Connection: Upgrade\r\n")
	buf.WriteString("Upgrade: websocket\r\n")
	// Forward all remaining headers except the ones we already wrote.
	for key, vals := range r.Header {
		switch strings.ToLower(key) {
		case "host", "origin", "connection", "upgrade":
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, v)
		}
	}
	buf.WriteString("\r\n")
	if _, err := upstream.Write(buf.Bytes()); err != nil {
		return http.StatusBadGateway
	}

	// Read the upstream response status line before hijacking so we can log
	// whether the WebSocket upgrade was accepted (101) or rejected.
	upReader := bufio.NewReader(upstream)
	statusLine, _ := upReader.ReadString('\n')
	wsStatusCode := ""
	wsStatus := http.StatusSwitchingProtocols
	if fields := strings.Fields(statusLine); len(fields) >= 2 {
		wsStatusCode = fields[1]
		if parsed, err := strconv.Atoi(wsStatusCode); err == nil {
			wsStatus = parsed
		}
	}
	log.Printf(`{"msg":"jeg ws upstream status","target":%q,"status":%q,"line":%q}`, target.String(), wsStatusCode, strings.TrimSpace(statusLine))

	// Hijack the downstream client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Internal Server Error: websocket hijack unsupported", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	client, clientRW, err := hj.Hijack()
	if err != nil {
		return http.StatusInternalServerError
	}
	defer client.Close()
	if tcpCli, ok := client.(*net.TCPConn); ok {
		_ = tcpCli.SetKeepAlive(true)
		_ = tcpCli.SetKeepAlivePeriod(30 * time.Second)
	}

	// Wrap both sides with idle deadline tracking so goroutines exit within
	// wsIdleTimeout if the upstream hangs or deadlocks at the application layer.
	// TCP Keep-Alives alone do not catch this condition.
	upstreamIdle := &idleDeadlineConn{Conn: upstream, idleTimeout: wsIdleTimeout}
	clientIdle := &idleDeadlineConn{Conn: client, idleTimeout: wsIdleTimeout}

	// Bidirectional copy until either side closes or errors.
	// Replay the status line already buffered from upReader before piping the rest.
	// Wait for BOTH directions to finish so a slow response does not kill an
	// active channel prematurely. Half-close the write side when one direction
	// ends so the peer gets a clean EOF.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstreamIdle, clientRW)
		// Client→upstream finished: half-close upstream so the kernel sees EOF.
		if tcpUp, ok := upstream.(*net.TCPConn); ok {
			_ = tcpUp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientIdle, io.MultiReader(strings.NewReader(statusLine), upReader))
		// Upstream→client finished: half-close client so the browser sees EOF.
		if tcpCli, ok := client.(*net.TCPConn); ok {
			_ = tcpCli.CloseWrite()
		}
		done <- struct{}{}
	}()
	// Wait for BOTH goroutines (not just the first) so we don't close
	// connections while the other direction still has data in flight.
	<-done
	<-done
	log.Printf(`{"msg":"ws proxy closed","target":%q,"status":%d}`, target.String(), wsStatus)

	return wsStatus
}

// ---- response status recorder ----

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	return sr.ResponseWriter.Write(b)
}

// ---- main proxy handler ----

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Enforce authentication: REMOTE_USER must be set by revproxy auth_request.
	// Clients cannot forge it — revproxy strips any client-supplied REMOTE_USER.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := normalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = normalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logAccess("", "", r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}

	userHash := hashUser(remoteUser)

	// Resolve the upstream by querying the K8s Service object (cached 30s).
	// The Service's getambassador.io/config annotation contains the real host:port
	// that Hatchery set at launch time — accounts for external nodes, ECS ALBs,
	// GPU NodePorts, etc. Falls back to DNS+80 when annotation is absent.
	upstreamStr, err := lookupUpstreamWithFallback(remoteUser, identityRaw, remoteUserRaw)
	if err != nil {
		uid := parseRemoteUserID(identityRaw)
		if uid == "" {
			uid = parseRemoteUserID(remoteUserRaw)
		}
		uidCandidate := ""
		if uid != "" {
			uidCandidate = fmt.Sprintf("%s, %s", uid, uid)
		}
		log.Printf(`{"time":%q,"msg":"upstream resolution failed","remote_user_header":%q,"identity_raw":%q,"remote_user_normalized":%q,"uid_candidate":%q,"error":%q}`,
			time.Now().UTC().Format(time.RFC3339), remoteUserRaw, identityRaw, remoteUser, uidCandidate, err.Error())
		http.Error(w, "Bad Gateway: workspace not running", http.StatusBadGateway)
		logAccess(userHash, "", r.Method, r.URL.Path, http.StatusBadGateway, time.Since(start))
		return
	}

	target, _ := url.Parse(upstreamStr)

	// With remoteKernelsBaseUrl active, all kernel/session API requests from the
	// browser go to /jeg-proxy/ (jegProxyHandler). This handler only proxies
	// container-local traffic: files, terminals, static assets, etc.

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		status := proxyWebSocket(w, r, target)
		logAccess(userHash, upstreamStr, r.Method, r.URL.Path, status, time.Since(start))
		return
	}

	// Cap non-WebSocket request bodies to 2 MiB to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Restore prefix: nginx strips it, Jupyter expects it as its base URL.
			req.URL.Path = ensureUpstreamPrefix(req.URL.Path)
			if req.URL.RawPath != "" {
				req.URL.RawPath = ensureUpstreamPrefix(req.URL.RawPath)
			}
		},
		FlushInterval: 100 * time.Millisecond,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Evict both caches so the next request re-queries K8s — pod may have restarted,
		// moved to a different node, or been replaced with a different port.
		upstreamCache.Delete(remoteUser)
		evictSvcListCache()
		http.Error(w, "Bad Gateway: workspace unavailable", http.StatusBadGateway)
		logAccess(userHash, upstreamStr, r.Method, r.URL.Path, http.StatusBadGateway, time.Since(start))
	}
	proxy.ServeHTTP(sr, r)
	logAccess(userHash, upstreamStr, r.Method, r.URL.Path, sr.status, time.Since(start))
}

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

type jegKernelPolicy struct {
	AllowedSpecs []string            `json:"allowedSpecs"`
	CostPerHour  map[string]float64  `json:"costPerHour"`
	DisplayNames map[string]string   `json:"displayNames"`
	NodeType     map[string]string   `json:"nodeType"`
}

// parsedJEGPolicy is parsed once at startup from JEG_KERNEL_SPEC_POLICY env var.
var parsedJEGPolicy *jegKernelPolicy

// knownJEGKernelIDs remembers kernel IDs observed/confirmed on JEG so websocket
// channel routing can prefer JEG even when container kernel lookup proxies through.
var knownJEGKernelIDs sync.Map // map[string]struct{}

// knownJEGKernelIDsAge tracks the time each kernel ID was last observed.
// Used by the GC goroutine to evict stale entries and prevent unbounded growth.
var knownJEGKernelIDsAge sync.Map // map[string]time.Time

type sessionKernelOverride struct {
	KernelID   string
	KernelName string
	Path       string
	Name       string
	Type       string
	UpdatedAt  time.Time
}

// sessionKernelOverrides tracks notebook session -> JEG kernel bindings per user
// so polling GET /api/sessions does not revert the client back to local kernels.
var sessionKernelOverrides sync.Map // map[string]sessionKernelOverride, key=user|sessionID

func sessionOverrideKey(remoteUser, sessionID string) string {
	return strings.TrimSpace(remoteUser) + "|" + strings.TrimSpace(sessionID)
}

func setSessionKernelOverride(remoteUser, sessionID, kernelID, kernelName, path, name, sessionType string) {
	if strings.TrimSpace(remoteUser) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(kernelID) == "" {
		return
	}
	if strings.TrimSpace(sessionType) == "" {
		sessionType = "notebook"
	}
	sessionKernelOverrides.Store(sessionOverrideKey(remoteUser, sessionID), sessionKernelOverride{
		KernelID:   strings.TrimSpace(kernelID),
		KernelName: strings.TrimSpace(kernelName),
		Path:       strings.TrimSpace(path),
		Name:       strings.TrimSpace(name),
		Type:       strings.TrimSpace(sessionType),
		UpdatedAt:  time.Now(),
	})
}

func clearSessionKernelOverride(remoteUser, sessionID string) {
	if strings.TrimSpace(remoteUser) == "" || strings.TrimSpace(sessionID) == "" {
		return
	}
	sessionKernelOverrides.Delete(sessionOverrideKey(remoteUser, sessionID))
}

func getSessionKernelOverride(remoteUser, sessionID string) (sessionKernelOverride, bool) {
	v, ok := sessionKernelOverrides.Load(sessionOverrideKey(remoteUser, sessionID))
	if !ok {
		return sessionKernelOverride{}, false
	}
	ov, castOK := v.(sessionKernelOverride)
	if !castOK {
		return sessionKernelOverride{}, false
	}
	return ov, true
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

func rememberJEGKernelID(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	knownJEGKernelIDs.Store(id, struct{}{})
	knownJEGKernelIDsAge.Store(id, time.Now())
}

func forgetJEGKernelID(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	knownJEGKernelIDs.Delete(id)
	knownJEGKernelIDsAge.Delete(id)
}

func isKnownJEGKernelID(id string) bool {
	_, ok := knownJEGKernelIDs.Load(strings.TrimSpace(id))
	return ok
}

// containerHasKernel does a stateless live lookup: asks the container whether it
// owns the given kernel ID. Returns true if the container responds 200, false on
// 404 or any error. This replaces the old in-memory localKernelIDs sync.Map so
// the proxy remains stateless across restarts and multiple replicas.
func containerHasKernel(microBase, kernelID, remoteUser string) bool {
	upstream := strings.TrimRight(microBase, "/") + upstreamPrefix + "/api/kernels/" + kernelID
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

// jegHasKernel asks JEG directly whether the kernel ID exists for this user.
// Used as a routing discriminator because container /api/kernels/{id} may proxy
// through GatewayClient and return JEG-owned kernels as 200.
func jegHasKernel(kernelID, remoteUser string) bool {
	if jegGatewayURL == "" {
		return false
	}
	upstream := strings.TrimRight(jegGatewayURL, "/") + "/api/kernels/" + kernelID
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
		rememberJEGKernelID(kernelID)
	}
	return resp.StatusCode == http.StatusOK
}

// findJEGKernelIDByName returns the first active JEG kernel ID that matches the
// requested kernel name for this user.
func findJEGKernelIDByName(remoteUser, kernelName string) string {
	if jegGatewayURL == "" || strings.TrimSpace(kernelName) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jegGatewayURL, "/")+"/api/kernels", nil)
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
					rememberJEGKernelID(k.ID)
					return k.ID
				}
			}
		}
	}
	return ""
}

// findJEGKernelNameByID resolves a running JEG kernel name by ID.
func findJEGKernelNameByID(remoteUser, kernelID string) string {
	if jegGatewayURL == "" {
		return ""
	}
	kernelID = strings.TrimSpace(kernelID)
	if kernelID == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jegGatewayURL, "/")+"/api/kernels/"+kernelID, nil)
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
		forgetJEGKernelID(kernelID)
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
				rememberJEGKernelID(kernel.ID)
			}
			return strings.TrimSpace(kernel.Name)
		}
	}
	return ""
}

type jegKernelInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	LastActivity   string `json:"last_activity"`
	ExecutionState string `json:"execution_state"`
	Connections    int    `json:"connections"`
}

func listJEGKernels(remoteUser string) []jegKernelInfo {
	if jegGatewayURL == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(jegGatewayURL, "/")+"/api/kernels", nil)
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
					rememberJEGKernelID(k.ID)
				}
			}
			return kernels
		}
	}
	return nil
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

func initJEGPolicy() {
	if jegKernelSpecPolicy == "" {
		return
	}
	p := &jegKernelPolicy{}
	if err := json.Unmarshal([]byte(jegKernelSpecPolicy), p); err != nil {
		log.Printf(`{"msg":"JEG_KERNEL_SPEC_POLICY parse error — ghost gateway will return empty specs","error":%q}`, err.Error())
		return
	}
	parsedJEGPolicy = p
	log.Printf(`{"msg":"JEG kernel spec policy loaded","allowed_specs":%d}`, len(p.AllowedSpecs))
}

// filterJEGKernelspecs applies the kernel spec policy to the raw JEG response body,
// returning a filtered JSON byte slice. Spec names not in allowedSpecs are dropped.
// If no policy is configured, returns an empty kernelspecs object to prevent
// JupyterLab from launching kernels directly without going through the billing panel.
func filterJEGKernelspecs(rawBody []byte) []byte {
	if parsedJEGPolicy == nil || len(parsedJEGPolicy.AllowedSpecs) == 0 {
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

	filtered := make(map[string]json.RawMessage, len(parsedJEGPolicy.AllowedSpecs))
	for _, name := range parsedJEGPolicy.AllowedSpecs {
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
				meta["costPerHour"] = parsedJEGPolicy.CostPerHour[name]
				meta["nodeType"] = parsedJEGPolicy.NodeType[name]
				if dn, ok := parsedJEGPolicy.DisplayNames[name]; ok {
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
		if len(parsedJEGPolicy.AllowedSpecs) > 0 {
			if _, ok := filtered[parsedJEGPolicy.AllowedSpecs[0]]; ok {
				defaultSpec = parsedJEGPolicy.AllowedSpecs[0]
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

// fetchLocalKernelspecs fetches kernelspecs from the user's micro-container Jupyter server.
// microBase is the resolved upstream, e.g. "http://h-user-s.ns.svc.cluster.local:80".
// Returns raw JSON body or an error.
func fetchLocalKernelspecs(microBase, remoteUser string) ([]byte, error) {
	upstream := strings.TrimRight(microBase, "/") + upstreamPrefix + "/api/kernelspecs"
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

// proxyToContainer forwards any HTTP request to the micro-container at
// {microBase}/lw-workspace/proxy{path} with the REMOTE_USER header set.
// It streams the response directly to w and returns the HTTP status code.
func proxyToContainer(w http.ResponseWriter, r *http.Request, containerPath, microBase, remoteUser string) int {
	upstream := strings.TrimRight(microBase, "/") + upstreamPrefix + containerPath
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	req, err := http.NewRequest(r.Method, upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	// Forward safe headers.
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
		http.Error(w, "container unavailable", http.StatusBadGateway)
		return http.StatusBadGateway
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	for key, vals := range resp.Header {
		switch strings.ToLower(key) {
		case "connection", "transfer-encoding":
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	return resp.StatusCode
}

// proxyToContainerRecorded is like proxyToContainer but writes to a statusRecorder
// so the caller can inspect the HTTP status code after the call.
func proxyToContainerRecorded(rec *statusRecorder, r *http.Request, containerPath, microBase, remoteUser string) int {
	return proxyToContainer(rec, r, containerPath, microBase, remoteUser)
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

func jegProxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Auth: REMOTE_USER must be present (set by revproxy auth_request).
	// All requests arrive from the browser via remoteKernelsBaseUrl → revproxy.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := normalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = normalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logAccess("", jegGatewayURL, r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}
	userHash := hashUser(remoteUser)

	// Strip the /jeg-proxy prefix to get the kernel-API-relative path.
	jegPath := strings.TrimPrefix(r.URL.Path, "/jeg-proxy")
	if jegPath == "" {
		jegPath = "/"
	}

	jegBase, _ := url.Parse(jegGatewayURL)

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
	microUpstream, _ := lookupUpstreamWithFallback(remoteUser, identityRaw, remoteUserRaw)

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
			upstream := strings.TrimRight(microUpstream, "/") + upstreamPrefix + jegPath
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
						logAccess(userHash, microUpstream, method, r.URL.Path, cStatus, time.Since(start))
						return
					}
				}
				// Container didn't have it — check override map (JEG synthetic session).
				if override, ok := getSessionKernelOverride(remoteUser, sessionID); ok {
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					logAccess(userHash, "override", method, r.URL.Path, http.StatusOK, time.Since(start))
					return
				}
				http.Error(w, "session not found", http.StatusNotFound)
				logAccess(userHash, "", method, r.URL.Path, http.StatusNotFound, time.Since(start))
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
							var sess struct{ ID string `json:"id"` }
							if json.Unmarshal(s, &sess) == nil && strings.TrimSpace(sess.ID) != "" {
								containerIDs[strings.TrimSpace(sess.ID)] = struct{}{}
							}
							merged = append(merged, s)
						}
					}
				}
			}

			// Fetch live JEG kernel data once for enriching synthesized sessions.
			jegKernels := listJEGKernels(remoteUser)
			jegKernelMap := map[string]*jegKernelInfo{}
			for i := range jegKernels {
				jegKernelMap[strings.TrimSpace(jegKernels[i].ID)] = &jegKernels[i]
			}

			// Synthesize session entries for active JEG kernels from override map.
			prefix := strings.TrimSpace(remoteUser) + "|"
			sessionKernelOverrides.Range(func(k, v interface{}) bool {
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
					clearSessionKernelOverride(remoteUser, sid)
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
			logAccess(userHash, microUpstream, method, r.URL.Path, http.StatusOK, time.Since(start))
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
						logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
						return
					}
				}
			}

			// JEG kernel — JEG has no session API, so we synthesize a session.
			// The kernel must already be running (launched via billing panel).
			jegKernelID := strings.TrimSpace(postReq.Kernel.ID)
			if jegKernelID == "" && postKernelName != "" {
				jegKernelID = findJEGKernelIDByName(remoteUser, postKernelName)
			}

			if jegKernelID != "" && (isKnownJEGKernelID(jegKernelID) || jegHasKernel(jegKernelID, remoteUser)) {
				rememberJEGKernelID(jegKernelID)
				kernelName := strings.TrimSpace(postReq.Kernel.Name)
				if kernelName == "" {
					kernelName = postKernelName
				}
				if kernelName == "" {
					kernelName = findJEGKernelNameByID(remoteUser, jegKernelID)
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
				setSessionKernelOverride(remoteUser, newSessionID, jegKernelID, kernelName, strings.TrimSpace(postReq.Path), strings.TrimSpace(postReq.Name), sessType)
				out := buildSessionCompatResponse(newSessionID, sessionKernelOverride{
					KernelID: jegKernelID, KernelName: kernelName,
					Path: strings.TrimSpace(postReq.Path), Name: strings.TrimSpace(postReq.Name), Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session post synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, newSessionID, jegKernelID)
				logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusCreated, time.Since(start))
				return
			}

			// Unknown spec — try container as default.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
					return
				}
			}

			http.Error(w, "session creation failed", http.StatusBadGateway)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadGateway, time.Since(start))
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
				patchKernelID = findJEGKernelIDByName(remoteUser, patchKernelName)
			}
			if patchKernelID != "" && (isKnownJEGKernelID(patchKernelID) || jegHasKernel(patchKernelID, remoteUser)) {
				rememberJEGKernelID(patchKernelID)
				if patchKernelName == "" {
					patchKernelName = findJEGKernelNameByID(remoteUser, patchKernelID)
				}
				sessPath := strings.TrimSpace(patchReq.Path)
				sessName := strings.TrimSpace(patchReq.Name)
				sessType := strings.TrimSpace(patchReq.Type)
				if sessType == "" {
					sessType = "notebook"
				}
				setSessionKernelOverride(remoteUser, sessionID, patchKernelID, patchKernelName, sessPath, sessName, sessType)
				out := buildSessionCompatResponse(sessionID, sessionKernelOverride{
					KernelID: patchKernelID, KernelName: patchKernelName,
					Path: sessPath, Name: sessName, Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session patch synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, sessionID, patchKernelID)
				logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusOK, time.Since(start))
				return
			}

			// If the session is a JEG override with no kernel change, update metadata.
			if patchKernelID == "" && patchKernelName == "" {
				if override, ok := getSessionKernelOverride(remoteUser, sessionID); ok {
					if strings.TrimSpace(patchReq.Path) != "" {
						override.Path = strings.TrimSpace(patchReq.Path)
					}
					if strings.TrimSpace(patchReq.Name) != "" {
						override.Name = strings.TrimSpace(patchReq.Name)
					}
					if strings.TrimSpace(patchReq.Type) != "" {
						override.Type = strings.TrimSpace(patchReq.Type)
					}
					setSessionKernelOverride(remoteUser, sessionID, override.KernelID, override.KernelName, override.Path, override.Name, override.Type)
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					logAccess(userHash, "override", method, r.URL.Path, http.StatusOK, time.Since(start))
					return
				}
			}

			// Local kernel switch or unknown — forward to container.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					// Switching away from JEG — clear override if present.
					clearSessionKernelOverride(remoteUser, sessionID)
					writeResponse(status, hdr, respBody)
					logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
					return
				}
				// Container 404 on synthetic session — create new local session.
				if status == http.StatusNotFound && patchKernelName != "" &&
					isLocalContainerSpec(microUpstream, patchKernelName, remoteUser) {
					clearSessionKernelOverride(remoteUser, sessionID)
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
					up := strings.TrimRight(microUpstream, "/") + upstreamPrefix + "/api/sessions"
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
							logAccess(userHash, microUpstream, method, r.URL.Path, pStatus, time.Since(start))
							return
						}
					}
				}
			}

			http.Error(w, "session patch failed", http.StatusBadGateway)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}

		// DELETE /api/sessions/{id}
		if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/sessions/") {
			sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
			sessionID = strings.SplitN(sessionID, "/", 2)[0]
			clearSessionKernelOverride(remoteUser, sessionID)

			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
					return
				}
			}
			// Not in container — 204 regardless (override already cleared).
			w.WriteHeader(http.StatusNoContent)
			logAccess(userHash, "", method, r.URL.Path, http.StatusNoContent, time.Since(start))
			return
		}

		// Other session methods — proxy to container.
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		status := proxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
		return
	}

	// /api/contents — always routed to the micro-container (file system is local).
	if strings.HasPrefix(jegPath, "/api/contents") {
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		status := proxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
		return
	}

	// WS /api/kernels/{id}/channels — stateless routing with JEG precedence:
	// if JEG owns the kernel ID, always tunnel to JEG; otherwise try container.
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if sid := strings.TrimSpace(r.URL.Query().Get("session_id")); sid != "" {
			if override, ok := getSessionKernelOverride(remoteUser, sid); ok {
				overrideKernelID := strings.TrimSpace(override.KernelID)
				if overrideKernelID != "" && overrideKernelID != kernelID {
					log.Printf(`{"msg":"jeg channels session override reroute","user_hash":%q,"session_id":%q,"from_kernel_id":%q,"to_kernel_id":%q}`, userHash, sid, kernelID, overrideKernelID)
					kernelID = overrideKernelID
					rememberJEGKernelID(kernelID)
					jegPath = "/api/kernels/" + kernelID + "/channels"
				}
			}
		}
		jegKnown := isKnownJEGKernelID(kernelID)
		jegOwns := false
		if kernelID != "" {
			jegOwns = jegHasKernel(kernelID, remoteUser)
			if jegKnown && !jegOwns {
				forgetJEGKernelID(kernelID)
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
			status := proxyWebSocket(w, r, &target)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
		} else if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"container"}`, userHash, kernelID)
			// Container owns this kernel — tunnel WS to the container.
			containerWS, _ := url.Parse(microUpstream)
			containerWS.Path = upstreamPrefix + jegPath
			containerWS.RawQuery = r.URL.RawQuery
			r.Header.Set("REMOTE_USER", remoteUser)
			status := proxyWebSocket(w, r, containerWS)
			logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
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
			status := proxyWebSocket(w, r, &target)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
		}
		return
	}

	// GET /api/kernelspecs — merge local container specs + JEG filtered specs.
	if method == http.MethodGet && jegPath == "/api/kernelspecs" {
		// Fetch JEG specs (may be empty when no policy — that's fine, local fills it).
		jegReq, _ := http.NewRequest(http.MethodGet, jegGatewayURL+"/api/kernelspecs", nil)
		forwardJEGHeaders(jegReq)
		jegResp, jegErr := http.DefaultClient.Do(jegReq)
		var jegFiltered []byte
		if jegErr == nil && jegResp.StatusCode == http.StatusOK {
			rawJEG, _ := io.ReadAll(jegResp.Body)
			jegResp.Body.Close()
			jegFiltered = filterJEGKernelspecs(rawJEG)

			// Ensure kernelspecs for currently running JEG kernels are
			// included even when the policy filters them out, so JupyterLab
			// can display proper kernel names for active sessions.
			runningKernels := listJEGKernels(remoteUser)
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
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusOK, time.Since(start))
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
			status := proxyToContainer(w, r, "/api/kernels", microUpstream, remoteUser)
			log.Printf(`{"msg":"local kernel launched","spec":%q,"status":%d}`, launchReq.Name, status)
			logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
			return
		}

		// JEG spec (or unknown spec) — billing gate: not allowed via this route.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"GPU kernel launch requires the Vectis Kernel Panel. Select a kernel type there to launch with billing authorization."}`))
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}

	// GET /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodGet && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return
		}
		if jegHasKernel(kernelID, remoteUser) {
			// JEG-owned kernel ID.
			upstreamURL := jegGatewayURL + jegPath
			req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				http.Error(w, "kernel not found", http.StatusBadGateway)
				logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxyToContainer(w, r, jegPath, microUpstream, remoteUser)
			logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
			return
		}
		// Not in container — try JEG.
		upstreamURL := jegGatewayURL + jegPath
		req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "kernel not found", http.StatusBadGateway)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			forgetJEGKernelID(kernelID)
		}
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
		return
	}

	// GET /api/kernels — merge container running kernels + JEG running kernels.
	if method == http.MethodGet && jegPath == "/api/kernels" {
		type kernelEntry = json.RawMessage
		var merged []kernelEntry
		jegIDs := map[string]struct{}{}

		// Fetch from JEG.
		jegReq, _ := http.NewRequest(http.MethodGet, jegGatewayURL+"/api/kernels", nil)
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
						rememberJEGKernelID(k.ID)
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
			containerURL := strings.TrimRight(microUpstream, "/") + upstreamPrefix + "/api/kernels"
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
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// DELETE /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return
		}
		if jegHasKernel(kernelID, remoteUser) {
			// JEG kernel.
			upstream := jegGatewayURL + "/api/kernels/" + kernelID
			req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			status := http.StatusNoContent
			if err != nil {
				status = http.StatusBadGateway
				http.Error(w, "JEG delete failed", status)
				logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(resp.StatusCode)
			}
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxyToContainer(w, r, "/api/kernels/"+kernelID, microUpstream, remoteUser)
			logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
			return
		}
		// JEG kernel.
		upstream := jegGatewayURL + "/api/kernels/" + kernelID
		req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		status := http.StatusNoContent
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "JEG delete failed", status)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(resp.StatusCode)
		}
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, status, time.Since(start))
		return
	}

	// /lw-workspace/proxy/... — resource URLs (kernelspec logos, static assets) whose
	// absolute form was embedded in our GET /api/kernelspecs response. JupyterLite
	// constructs fetch URLs as remoteKernelsBaseUrl + resource_url, where resource_url
	// already contains /lw-workspace/proxy/, producing a double-prefix. Strip the
	// extra prefix and proxy the resource to the container.
	if strings.HasPrefix(jegPath, upstreamPrefix+"/") {
		containerPath := strings.TrimPrefix(jegPath, upstreamPrefix)
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			logAccess(userHash, "", method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		status := proxyToContainer(w, r, containerPath, microUpstream, remoteUser)
		logAccess(userHash, microUpstream, method, r.URL.Path, status, time.Since(start))
		return
	}

	// All other paths: not supported by this gateway.
	http.Error(w, "Not found", http.StatusNotFound)
	logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusNotFound, time.Since(start))
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
func filterJEGKernelspecsForPanel(rawBody []byte) []byte {
	if parsedJEGPolicy == nil || len(parsedJEGPolicy.AllowedSpecs) == 0 {
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

	filtered := make(map[string]json.RawMessage, len(parsedJEGPolicy.AllowedSpecs))
	for _, name := range parsedJEGPolicy.AllowedSpecs {
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
			meta["costPerHour"] = parsedJEGPolicy.CostPerHour[name]
			meta["nodeType"] = parsedJEGPolicy.NodeType[name]
			if dn, ok := parsedJEGPolicy.DisplayNames[name]; ok {
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
		for _, name := range parsedJEGPolicy.AllowedSpecs {
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

func jegPanelHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Auth: REMOTE_USER is set by revproxy auth_request on /lw-workspace/proxy/*.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := normalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = normalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logAccess("", jegGatewayURL, r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}
	userHash := hashUser(remoteUser)

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
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// GET /api/kernelspecs — panel-filtered: all specs when no policy, allowed when policy set.
	if method == http.MethodGet && panelPath == "/api/kernelspecs" {
		upstream := jegGatewayURL + "/api/kernelspecs"
		req, _ := http.NewRequest(http.MethodGet, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernelspecs unavailable", http.StatusBadGateway)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "JEG kernelspecs unavailable", resp.StatusCode)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
			return
		}
		rawBody, _ := io.ReadAll(resp.Body)
		filtered := filterJEGKernelspecsForPanel(rawBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(filtered)
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// GET /api/kernels — user's active JEG kernels.
	if method == http.MethodGet && panelPath == "/api/kernels" {
		upstream := jegGatewayURL + "/api/kernels"
		req, _ := http.NewRequest(http.MethodGet, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernels unavailable", http.StatusBadGateway)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
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
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return
		}

		// Billing gate: when a policy is configured, only allowedSpecs may be launched.
		if parsedJEGPolicy != nil && len(parsedJEGPolicy.AllowedSpecs) > 0 {
			allowed := false
			for _, s := range parsedJEGPolicy.AllowedSpecs {
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
				logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusForbidden, time.Since(start))
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
		upstream := jegGatewayURL + "/api/kernels"
		req, _ := http.NewRequest(http.MethodPost, upstream, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG kernel launch failed", http.StatusBadGateway)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
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
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
		return
	}

	// DELETE /api/kernels/{id} — force-terminate; passed through unconditionally.
	if method == http.MethodDelete && strings.HasPrefix(panelPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(panelPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return
		}
		upstream := jegGatewayURL + "/api/kernels/" + kernelID
		req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
		forwardHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "JEG delete failed", http.StatusBadGateway)
			logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusBadGateway, time.Since(start))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(resp.StatusCode)
		}
		logAccess(userHash, jegGatewayURL, method, r.URL.Path, resp.StatusCode, time.Since(start))
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	logAccess(userHash, jegGatewayURL, method, r.URL.Path, http.StatusNotFound, time.Since(start))
}

// ---- entrypoint ----

// startStateGC starts a background goroutine that periodically evicts stale entries
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
func startStateGC(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-maxAge)
			var evictedSessions, evictedKernels int

			sessionKernelOverrides.Range(func(key, value any) bool {
				ov, ok := value.(sessionKernelOverride)
				if ok && ov.UpdatedAt.Before(cutoff) {
					sessionKernelOverrides.Delete(key)
					evictedSessions++
				}
				return true
			})

			knownJEGKernelIDsAge.Range(func(key, value any) bool {
				t, ok := value.(time.Time)
				if ok && t.Before(cutoff) {
					knownJEGKernelIDsAge.Delete(key)
					knownJEGKernelIDs.Delete(key)
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

func main() {
	log.SetFlags(0) // disable stdlib timestamp prefix — entries are self-timestamped JSON

	k8s = initK8sClient()

	// Start GC goroutine to evict stale in-memory state and prevent OOMKill over time.
	// Runs every 15 minutes; evicts entries not touched for 4 hours.
	startStateGC(15*time.Minute, 4*time.Hour)

	log.Printf(`{"time":%q,"msg":"workspace-proxy starting","listen":%q,"namespace":%q,"k8s_discovery":%v}`,
		time.Now().UTC().Format(time.RFC3339), listenAddr, workspaceNS, k8s != nil)

	mux := http.NewServeMux()

	// Health endpoint for liveness/readiness probes.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// JEG ghost-gateway: intercept JupyterLab's GatewayClient traffic and apply billing gate.
	if jegGatewayURL != "" {
		initJEGPolicy()
		mux.HandleFunc("/jeg-proxy/", jegProxyHandler)
		mux.Handle("/jeg-panel/", http.StripPrefix("/jeg-panel", http.HandlerFunc(jegPanelHandler)))
		log.Printf(`{"msg":"JEG ghost gateway + panel API enabled","jeg_gateway_url":%q}`, jegGatewayURL)
	}

	// All workspace traffic — authenticated and routed by REMOTE_USER.
	mux.HandleFunc("/", proxyHandler)

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		// ReadHeaderTimeout guards against slow-loris: attacker sends one byte at a time
		// to hold a goroutine indefinitely. 10s is generous for any legitimate client.
		ReadHeaderTimeout: 10 * time.Second,
		// No read/write timeout: kernel connections are long-lived (notebook execution,
		// noVNC sessions). The workspace pod timeout (36000s) is enforced by revproxy.
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown: on SIGTERM/SIGINT drain in-flight requests for up to 30s
	// before exiting. Matches the default EKS pod termination grace period so WS
	// kernel channels get a clean close rather than an abrupt TCP RST.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Printf(`{"time":%q,"msg":"shutdown signal received — draining connections"}`,
			time.Now().UTC().Format(time.RFC3339))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf(`{"msg":"graceful shutdown timed out","error":%q}`, err.Error())
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf(`{"msg":"server exited","error":%q}`, err.Error())
	}
	log.Printf(`{"time":%q,"msg":"workspace-proxy stopped cleanly"}`,
		time.Now().UTC().Format(time.RFC3339))
}
