package workspace

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uc-cdis/workspace-proxy/internal/identity"
	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/proxy"
)

const upstreamCacheTTL = 30 * time.Second
const svcListCacheTTL = 10 * time.Second

func escapism(input string) string {
	const safe = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for _, ch := range input {
		if strings.ContainsRune(safe, ch) {
			sb.WriteRune(ch)
		} else {
			fmt.Fprintf(&sb, "-%2x", ch)
		}
	}
	return sb.String()
}

// userToServiceName derives the Hatchery per-user ClusterIP service name.
// Matches pods.go: fmt.Sprintf("h-%s-s", escapism(userName))
func userToServiceName(username string) string {
	return fmt.Sprintf("h-%s-s", escapism(username))
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

func annotationRemoteUserMatches(annotationRemoteUser string, id identity.Identity) bool {
	annot := strings.TrimSpace(annotationRemoteUser)
	if annot == "" {
		return false
	}

	candidates := []string{
		strings.TrimSpace(id.Username),
		strings.TrimSpace(id.UID),
	}
	if id.UID != "" {
		candidates = append(candidates, fmt.Sprintf("uid:%s,%s", id.UID, id.Username))
	}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if annot == c || strings.EqualFold(annot, c) {
			return true
		}
	}

	if id.UID != "" {
		uidCandidate := fmt.Sprintf("%s, %s", id.UID, id.UID)
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
func lookupUpstream(ctx context.Context, k8s *kubernetes.Client, namespace, username string) (string, error) {

	log.Printf("%+v", username)
	log.Printf("%+v", &upstreamCache)

	if v, ok := upstreamCache.Load(username); ok {
		entry := v.(*upstreamEntry)
		if time.Now().Before(entry.expires) {
			return entry.upstream, nil
		}
		upstreamCache.Delete(username)
	}

	svcName := userToServiceName(username)

	log.Printf("!!!2%+v", svcName)

	upstream, err := resolveUpstream(ctx, k8s, namespace, svcName)
	log.Printf("!!!3a%+v", upstream)
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
func lookupByAnnotationRemoteUser(k8s *kubernetes.Client, id identity.Identity) (string, error) {
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

	log.Printf("%+v", svcs)

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
		if !annotationRemoteUserMatches(annotationRemoteUser, id) {
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

	return "", fmt.Errorf("no service annotation matched remote_user for %q", id.Username)
}

func LookupUpstreamWithFallback(ctx context.Context, k8s *kubernetes.Client, namespace string, id identity.Identity) (string, error) {
	upstream, err := lookupUpstream(ctx, k8s, namespace, id.Username)
	if err == nil {
		return upstream, nil
	}

	if id.UID == "" {
		return lookupByAnnotationRemoteUser(k8s, id)
	}
	// Hatchery can derive service names from "<uid>, <uid>" (e.g. "4, 4" -> h-4-2c-204-s).
	uidHatcheryUser := fmt.Sprintf("%s, %s", id.UID, id.UID)
	upstreamByUID, uidErr := lookupUpstream(ctx, k8s, namespace, uidHatcheryUser)

	log.Printf("\t%+v\n", uidHatcheryUser)
	log.Printf("\t%+v\n", upstreamByUID)
	if uidErr != nil {
		annotationUpstream, annotErr := lookupByAnnotationRemoteUser(k8s, id)
		if annotErr != nil {
			return "", err
		}

		upstreamCache.Store(id.Username, &upstreamEntry{
			upstream: annotationUpstream,
			expires:  time.Now().Add(upstreamCacheTTL),
		})
		return annotationUpstream, nil
	}

	upstreamCache.Store(id.Username, &upstreamEntry{
		upstream: upstreamByUID,
		expires:  time.Now().Add(upstreamCacheTTL),
	})

	return upstreamByUID, nil
}

// resolveUpstream fetches the K8s Service object and returns the upstream URL,
// preferring the host:port from the getambassador.io/config annotation.
func resolveUpstream(ctx context.Context, k8s *kubernetes.Client, namespace, serviceName string) (string, error) {
	log.Printf("!!!3b%+v", serviceName)
	log.Printf("!!!3c%+v", namespace)
	if k8s == nil {
		// Not in-cluster (local dev without service account) — plain DNS + port 80.
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:80", serviceName, namespace), nil
	}

	service, err := k8s.GetWorkspaceService(ctx, serviceName)
	if err != nil {
		log.Printf("!!!3d %+v", err)
	}

	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", service.Name, service.Namespace, service.Port), nil
}

// lookupUpstreamWithFallback resolves upstream first by username-derived service name,
// then by scanning workspace services for a matching REMOTE_USER uid annotation.
func listWorkspaceServices(ctx context.Context, k8s *kubernetes.Client) ([]kubernetes.K8sService, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Return cached list if still fresh.
	if entry := loadSvcListCache(); entry != nil && time.Now().Before(entry.expires) {
		return entry.items, nil
	}

	log.Printf("listWorkspaceServices")

	services, err := k8s.ListWorkspaceServices(ctx)
	if err != nil {
		return []kubernetes.K8sService{}, err
	}

	log.Printf("%+v", services)

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
	logger    *slog.Logger
	K8s       *kubernetes.Client
	namespace string
}

func NewHTTPClientProxy(logger *slog.Logger, k8s *kubernetes.Client, namespace string) *HTTPServer {
	return &HTTPServer{
		logger:    logger,
		K8s:       k8s,
		namespace: namespace,
	}
}

func (server *HTTPServer) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := identity.FromContext(ctx)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		server.logger.WarnContext(r.Context(), "access27",
			slog.String("user_hash", ""),
			slog.String("upstream", ""),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
		)
		return
	}
	remoteUser := id.Username
	userHash := identity.Hash(id)

	// Resolve the upstream by querying the K8s Service object (cached 30s).
	// The Service's getambassador.io/config annotation contains the real host:port
	// that Hatchery set at launch time — accounts for external nodes, ECS ALBs,
	// GPU NodePorts, etc. Falls back to DNS+80 when annotation is absent.
	upstreamStr, err := LookupUpstreamWithFallback(ctx, server.K8s, server.namespace, id)
	if err != nil {
		uidCandidate := ""
		if id.UID != "" {
			uidCandidate = fmt.Sprintf("%s, %s", id.UID, id.UID)
		}
		log.Printf(`{"time":%q,"msg":"upstream resolution failed","user_hash":%q,"uid_candidate":%q,"error":%q}`,
			time.Now().UTC().Format(time.RFC3339), userHash, uidCandidate, err.Error())
		http.Error(w, "Bad Gateway: workspace not running", http.StatusBadGateway)

		server.logger.ErrorContext(r.Context(), "access28",
			slog.String("user_hash", userHash),
			slog.String("upstream", ""),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusBadGateway),
		)
		return
	}

	target, err := url.Parse(upstreamStr)
	if err != nil || target.Scheme == "" || target.Host == "" {
		http.Error(w, "Bad Gateway: invalid workspace upstream", http.StatusBadGateway)
		server.logger.ErrorContext(r.Context(), "access30",
			slog.String("user_hash", userHash),
			slog.String("upstream", upstreamStr),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusBadGateway),
			slog.Any("error", err),
		)
		return
	}

	// With remoteKernelsBaseUrl active, all kernel/session API requests from the
	// browser go through the routes mounted at /jeg-proxy. This handler only proxies
	// container-local traffic: files, terminals, static assets, etc.

	requestTarget := *target
	requestTarget.Path = ensureUpstreamPrefix(r.URL.Path)
	if r.URL.RawPath != "" {
		requestTarget.RawPath = ensureUpstreamPrefix(r.URL.RawPath)
	}
	requestTarget.RawQuery = r.URL.RawQuery
	status := proxy.Proxy(w, r, &requestTarget)
	if status == http.StatusBadGateway {
		// The workspace may have restarted or moved since it was discovered.
		upstreamCache.Delete(remoteUser)
		evictSvcListCache()
	}
	server.logger.InfoContext(r.Context(), "access31",
		slog.String("user_hash", userHash),
		slog.String("upstream", upstreamStr),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
	)
}
