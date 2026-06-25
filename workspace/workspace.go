package workspace

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/proxy"
)

const upstreamCacheTTL = 30 * time.Second
const svcListCacheTTL = 10 * time.Second

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var workspaceNS = envOrDefault("WORKSPACE_NAMESPACE", "jupyter-pods")

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

// HashUser returns a truncated SHA-256 hex digest of the username for PII-safe logging.
func HashUser(username string) string {
	sum := sha256.Sum256([]byte(username))
	return fmt.Sprintf("%x", sum[:8])
}

// NormalizeRemoteUser converts Gen3 authz REMOTE_USER formats into a plain username.
// Example: "uid:4,test" -> "test".
func NormalizeRemoteUser(remoteUser string) string {
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

// ParseRemoteUserID extracts the numeric uid from REMOTE_USER formats like "uid:4,test".
func ParseRemoteUserID(remoteUser string) string {
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

	uid := ParseRemoteUserID(identityRaw)
	if uid == "" {
		uid = ParseRemoteUserID(remoteUserHeader)
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

// ParseAmbassadorServiceField scans Hatchery's getambassador.io/config YAML blob
// for the "service: host:port" line and returns the value.
// The format is controlled by Hatchery's fmt.Sprintf so simple line scanning is safe.
// Returns "" if not found or malformed.
func ParseAmbassadorServiceField(annotYAML string) string {
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

// upstreamEntry is a cached upstream URL with an expiry time.
type upstreamEntry struct {
	upstream string
	expires  time.Time
}

// upstreamCache caches the resolved upstream per username.
// TTL is 30s — short enough to pick up pod-restart port changes, long enough
// to avoid K8s API calls on every WebSocket frame heartbeat.
var upstreamCache sync.Map // map[string]*upstreamEntry
type svcListItem struct {
	Name        string
	Annotations map[string]string
	Ports       []int32
}

type svcListCacheEntry struct {
	items   []kubernetes.K8sService
	expires time.Time
}

// svcListCache is an atomic.Value holding *svcListCacheEntry; nil when empty.
var svcListCacheVal atomic.Value

func loadSvcListCache() *svcListCacheEntry {
	v := svcListCacheVal.Load()
	if v == nil {
		return nil
	}
	return v.(*svcListCacheEntry)
}

func storeSvcListCache(items []kubernetes.K8sService) {
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
func lookupUpstream(ctx context.Context, k8s *kubernetes.Client, username string) (string, error) {
	if v, ok := upstreamCache.Load(username); ok {
		entry := v.(*upstreamEntry)
		if time.Now().Before(entry.expires) {
			return entry.upstream, nil
		}
		upstreamCache.Delete(username)
	}

	svcName := userToServiceName(username)
	upstream, err := resolveUpstream(ctx, k8s, svcName)
	if err != nil {
		return "", err
	}

	upstreamCache.Store(username, &upstreamEntry{
		upstream: upstream,
		expires:  time.Now().Add(upstreamCacheTTL),
	})
	return upstream, nil
}

// lookupByAnnotationRemoteUser does a full LIST of all Services in the workspace
// namespace. Without caching, any auth mismatch or fallback path would hit the
// K8s API once per request, which at scale is an accidental DoS on the control plane.
// We cache the list for svcListCacheTTL and forcibly evict it in proxy.ErrorHandler
// so pod restarts are picked up promptly.
func lookupByAnnotationRemoteUser(k8s *kubernetes.Client, username, identityRaw, remoteUserHeader string) (string, error) {
	if k8s == nil {
		return "", fmt.Errorf("k8s discovery unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	svcs, err := listWorkspaceServices(ctx, k8s)
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
			if hostPort := ParseAmbassadorServiceField(annotYAML); hostPort != "" {
				soleAnnotatedUpstream = "http://" + hostPort
			} else {
				soleAnnotatedUpstream = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, svc.Port)
			}
		}

		annotationRemoteUser := parseAmbassadorRemoteUserField(annotYAML)
		if !annotationRemoteUserMatches(annotationRemoteUser, username, identityRaw, remoteUserHeader) {
			continue
		}

		if hostPort := ParseAmbassadorServiceField(annotYAML); hostPort != "" {
			return "http://" + hostPort, nil
		}

		return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, svc.Port), nil
	}

	if annotatedServiceCount == 1 && soleAnnotatedUpstream != "" {
		return soleAnnotatedUpstream, nil
	}

	return "", fmt.Errorf("no service annotation matched remote_user for %q", username)
}

func LookupUpstreamWithFallback(ctx context.Context, k8s *kubernetes.Client, username string, identityRaw string, remoteUserHeader string) (string, error) {
	upstream, err := lookupUpstream(ctx, k8s, username)
	if err == nil {
		return upstream, nil
	}

	uid := ParseRemoteUserID(identityRaw)
	if uid == "" {
		uid = ParseRemoteUserID(remoteUserHeader)
	}
	if uid == "" {
		return lookupByAnnotationRemoteUser(k8s, username, identityRaw, remoteUserHeader)
	}
	// Hatchery can derive service names from "<uid>, <uid>" (e.g. "4, 4" -> h-4-2c-204-s).
	uidHatcheryUser := fmt.Sprintf("%s, %s", uid, uid)
	upstreamByUID, uidErr := lookupUpstream(ctx, k8s, uidHatcheryUser)
	if uidErr != nil {
		annotationUpstream, annotErr := lookupByAnnotationRemoteUser(k8s, username, identityRaw, remoteUserHeader)
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
func resolveUpstream(ctx context.Context, k8s *kubernetes.Client, serviceName string) (string, error) {
	if k8s == nil {
		// Not in-cluster (local dev without service account) — plain DNS + port 80.
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:80", serviceName, workspaceNS), nil
	}

	service, _ := k8s.GetWorkspaceService(ctx, serviceName)

	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", service.Name, service.Namespace, service.Port), nil
}

// lookupUpstreamWithFallback resolves upstream first by username-derived service name,
// then by scanning workspace services for a matching REMOTE_USER uid annotation.
func listWorkspaceServices(ctx context.Context, k8s *kubernetes.Client) ([]kubernetes.K8sService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Return cached list if still fresh.
	if entry := loadSvcListCache(); entry != nil && time.Now().Before(entry.expires) {
		return entry.items, nil
	}

	services, err := k8s.ListWorkspaceServices(ctx)
	if err != nil {
		return []kubernetes.K8sService{}, err
	}

	storeSvcListCache(services)
	return services, nil
}

const upstreamPrefix = proxy.UpstreamPrefix

func ensureUpstreamPrefix(path string) string {
	if path == "" {
		return upstreamPrefix
	}
	if strings.HasPrefix(path, upstreamPrefix+"/") || path == upstreamPrefix {
		return path
	}
	return upstreamPrefix + path
}

type HTTPServer struct {
	logger *slog.Logger
	K8s    *kubernetes.Client
}

func NewHTTPClientProxy(logger *slog.Logger, k8s *kubernetes.Client) *HTTPServer {
	return &HTTPServer{
		logger: logger,
		K8s:    k8s,
	}
}

func (server *HTTPServer) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce authentication: REMOTE_USER must be set by revproxy auth_request.
	// Clients cannot forge it — revproxy strips any client-supplied REMOTE_USER.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := NormalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = NormalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		server.logger.WarnContext(r.Context(), "access",
			slog.String("user_hash", ""),
			slog.String("upstream", ""),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
		)
		return
	}

	userHash := HashUser(remoteUser)

	// Resolve the upstream by querying the K8s Service object (cached 30s).
	// The Service's getambassador.io/config annotation contains the real host:port
	// that Hatchery set at launch time — accounts for external nodes, ECS ALBs,
	// GPU NodePorts, etc. Falls back to DNS+80 when annotation is absent.
	upstreamStr, err := LookupUpstreamWithFallback(ctx, server.K8s, remoteUser, identityRaw, remoteUserRaw)
	if err != nil {
		uid := ParseRemoteUserID(identityRaw)
		if uid == "" {
			uid = ParseRemoteUserID(remoteUserRaw)
		}
		uidCandidate := ""
		if uid != "" {
			uidCandidate = fmt.Sprintf("%s, %s", uid, uid)
		}
		log.Printf(`{"time":%q,"msg":"upstream resolution failed","remote_user_header":%q,"identity_raw":%q,"remote_user_normalized":%q,"uid_candidate":%q,"error":%q}`,
			time.Now().UTC().Format(time.RFC3339), remoteUserRaw, identityRaw, remoteUser, uidCandidate, err.Error())
		http.Error(w, "Bad Gateway: workspace not running", http.StatusBadGateway)

		server.logger.ErrorContext(r.Context(), "access",
			slog.String("user_hash", userHash),
			slog.String("upstream", ""),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusBadGateway),
		)
		return
	}

	target, _ := url.Parse(upstreamStr)

	// With remoteKernelsBaseUrl active, all kernel/session API requests from the
	// browser go to /jeg-proxy/ (jegProxyHandler). This handler only proxies
	// container-local traffic: files, terminals, static assets, etc.

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		status := proxy.ProxyWebSocket(w, r, target)
		fmt.Print(status)
		server.logger.InfoContext(r.Context(), "access",
			slog.String("user_hash", userHash),
			slog.String("upstream", upstreamStr),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
		)
		return
	}

	// Cap non-WebSocket request bodies to 2 MiB to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	sr := &proxy.StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
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
		server.logger.ErrorContext(r.Context(), "access",
			slog.String("user_hash", userHash),
			slog.String("upstream", upstreamStr),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusBadGateway),
		)
	}
	proxy.ServeHTTP(sr, r)
	server.logger.InfoContext(r.Context(), "access",
		slog.String("user_hash", userHash),
		slog.String("upstream", upstreamStr),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", sr.Status),
	)
}
