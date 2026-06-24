package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uc-cdis/workspace-proxy/transport"
)

// wsIdleTimeout is the maximum time a WebSocket pipe can be fully silent before
// the proxy considers the upstream dead and closes the connection.
// Set well above the 60s React heartbeat and 30s TCP Keep-Alive period so healthy
// long-running kernel executions are never interrupted.
const wsIdleTimeout = 10 * time.Minute

// upstreamPrefix is the base URL path that nginx strips before forwarding to this service.
// The revproxy rewrite rule is: `rewrite ^/lw-workspace/proxy/(.*) /$1 break;`
// Jupyter is started with --NotebookApp.base_url=/lw-workspace/proxy/ and expects this prefix.
// We restore it before forwarding, mirroring Ambassador's `rewrite: /lw-workspace/proxy/`.
const UpstreamPrefix = "/lw-workspace/proxy"

const upstreamPrefix = UpstreamPrefix

type StatusRecorder struct {
	http.ResponseWriter
	Status int
}

func (sr *StatusRecorder) WriteHeader(code int) {
	sr.Status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *StatusRecorder) Write(b []byte) (int, error) {
	return sr.ResponseWriter.Write(b)
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
func ProxyWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL) int {
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
	upstreamIdle := &transport.IdleDeadlineConn{Conn: upstream, Timeout: wsIdleTimeout}
	clientIdle := &transport.IdleDeadlineConn{Conn: client, Timeout: wsIdleTimeout}

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

// ProxyToContainer forwards any HTTP request to the micro-container at
// {microBase}/lw-workspace/proxy{path} with the REMOTE_USER header set.
// It streams the response directly to w and returns the HTTP status code.
func ProxyToContainer(w http.ResponseWriter, r *http.Request, containerPath, microBase, remoteUser string) int {
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
