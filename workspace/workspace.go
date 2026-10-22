package workspace

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uc-cdis/workspace-proxy/internal/identity"
	"github.com/uc-cdis/workspace-proxy/kubernetes"
	"github.com/uc-cdis/workspace-proxy/proxy"
)

const upstreamCacheTTL = 30 * time.Second

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

// upstreamEntry is a cached upstream URL with an expiry time.
type upstreamEntry struct {
	upstream string
	expires  time.Time
}

// upstreamCache caches the resolved upstream per username.
// TTL is 30s — short enough to pick up pod-restart port changes, long enough
// to avoid K8s API calls on every WebSocket frame heartbeat.
var upstreamCache sync.Map // map[string]*upstreamEntry

// LookupUpstream returns the HTTP upstream base URL of the given user's
// workspace, using the cache when valid and querying K8s when not. It returns
// an error (and caches nothing) when the user's workspace service is not found.
func LookupUpstream(ctx context.Context, k8s *kubernetes.Client, namespace, username string) (string, error) {
	if v, ok := upstreamCache.Load(username); ok {
		entry := v.(*upstreamEntry)
		if time.Now().Before(entry.expires) {
			return entry.upstream, nil
		}
		upstreamCache.Delete(username)
	}

	svcName := userToServiceName(username)

	upstream, err := resolveUpstream(ctx, k8s, namespace, svcName)
	if err != nil {
		return "", err
	}

	upstreamCache.Store(username, &upstreamEntry{
		upstream: upstream,
		expires:  time.Now().Add(upstreamCacheTTL),
	})
	return upstream, nil
}

// resolveUpstream fetches the user's K8s Service object and returns its
// upstream URL, preferring the routing target in Hatchery's
// getambassador.io/config annotation over the Service's cluster-local DNS name.
func resolveUpstream(ctx context.Context, k8s *kubernetes.Client, namespace, serviceName string) (string, error) {
	if k8s == nil {
		// Not in-cluster (local dev without service account) — plain DNS + port 80.
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:80", serviceName, namespace), nil
	}

	service, err := k8s.GetWorkspaceService(ctx, serviceName)
	if err != nil {
		return "", err
	}

	return upstreamForService(service), nil
}

// upstreamForService returns the routing target from the Service's
// getambassador.io/config annotation when present and valid, and otherwise the
// Service's cluster-local DNS name and first port.
func upstreamForService(service kubernetes.K8sService) string {
	if upstream, ok := upstreamFromAmbassadorConfig(service.Annotations[ambassadorConfigAnnotation]); ok {
		return upstream
	}
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", service.Name, service.Namespace, service.Port)
}

const ambassadorConfigAnnotation = "getambassador.io/config"

// upstreamFromAmbassadorConfig returns the upstream URL described by Hatchery's
// getambassador.io/config annotation: the top-level "service: host:port" key,
// with an https scheme when the top-level "tls" key is true. Hatchery renders
// the annotation from a fixed template (see hatchery pods.go ambassadorYaml),
// so scanning top-level lines is sufficient. Returns false when the annotation
// is absent or has no valid service target.
func upstreamFromAmbassadorConfig(annotYAML string) (string, bool) {
	var hostPort string
	scheme := "http"
	for _, line := range strings.Split(annotYAML, "\n") {
		key, value, found := strings.Cut(strings.TrimRight(line, " \t\r"), ":")
		if !found {
			continue
		}
		switch key {
		case "service":
			hostPort = strings.TrimSpace(value)
		case "tls":
			if useTLS, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil && useTLS {
				scheme = "https"
			}
		}
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" || strings.ContainsAny(host, "/?#@") {
		return "", false
	}
	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return "", false
	}
	return scheme + "://" + net.JoinHostPort(host, port), true
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

	// Resolve the upstream by querying the user's K8s Service object (cached 30s).
	upstreamStr, err := LookupUpstream(ctx, server.K8s, server.namespace, remoteUser)
	if err != nil {
		http.Error(w, "Bad Gateway: workspace not running", http.StatusBadGateway)

		server.logger.ErrorContext(r.Context(), "access28",
			slog.String("user_hash", userHash),
			slog.String("upstream", ""),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusBadGateway),
			slog.String("error", err.Error()),
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
	}
	server.logger.InfoContext(r.Context(), "access31",
		slog.String("user_hash", userHash),
		slog.String("upstream", upstreamStr),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
	)
}
