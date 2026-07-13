// Package proxy provides streaming reverse-proxy helpers shared by workspace
// and JEG routes.
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/uc-cdis/workspace-proxy/internal/identity"
)

// UpstreamPrefix is the base URL path that nginx strips before forwarding to
// this service. Jupyter is configured with this base URL, so container-bound
// requests must restore it.
const UpstreamPrefix = "/lw-workspace/proxy"

// Proxy streams an HTTP request to target. ReverseProxy handles ordinary HTTP,
// streaming responses, and protocol upgrades (including WebSockets) without
// buffering or manually hijacking either connection.
func Proxy(w http.ResponseWriter, r *http.Request, target *url.URL) int {
	if target == nil || target.Scheme == "" || target.Host == "" {
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	status := http.StatusOK
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The callers resolve the complete upstream path. Assign it directly
			// instead of joining it with the public /jeg-proxy path.
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = target.Path
			pr.Out.URL.RawPath = target.RawPath
			pr.Out.URL.RawQuery = target.RawQuery
			pr.Out.Host = target.Host
			pr.SetXForwarded()

			// Browsers send the public host as the WebSocket Origin. Jupyter
			// validates it against the upstream host.
			if strings.EqualFold(pr.In.Header.Get("Upgrade"), "websocket") && pr.Out.Header.Get("Origin") != "" {
				pr.Out.Header.Set("Origin", target.Scheme+"://"+target.Host)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			status = http.StatusBadGateway
			http.Error(w, "Bad Gateway: upstream unavailable", status)
		},
	}
	rp.ServeHTTP(w, r)
	return status
}

// ProxyToContainer forwards a request to the Jupyter server in a user's
// workspace. The request and response bodies are streamed by ReverseProxy.
func ProxyToContainer(w http.ResponseWriter, r *http.Request, containerPath, microBase string, id identity.Identity) int {
	target, err := url.Parse(strings.TrimRight(microBase, "/"))
	if err != nil || target.Scheme == "" || target.Host == "" {
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	target.Path = strings.TrimRight(target.Path, "/") + UpstreamPrefix + containerPath
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery

	identity.SetUpstreamHeaders(r.Header, id)

	return Proxy(w, r, target)
}
