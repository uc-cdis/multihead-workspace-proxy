package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestUpstreamHost(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{target: "http://internal-alb.example.com:80", want: "internal-alb.example.com"},
		{target: "https://internal-alb.example.com:443", want: "internal-alb.example.com"},
		{target: "http://internal-alb.example.com", want: "internal-alb.example.com"},
		{target: "http://10.0.12.34:31234", want: "10.0.12.34:31234"},
		{target: "https://internal-alb.example.com:80", want: "internal-alb.example.com:80"},
		{target: "http://h-user-s.jupyter-pods.svc.cluster.local:8888", want: "h-user-s.jupyter-pods.svc.cluster.local:8888"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			target, err := url.Parse(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			if got := upstreamHost(target); got != tt.want {
				t.Fatalf("upstreamHost(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestProxyRewritesHostAndWebsocketOrigin(t *testing.T) {
	var gotHost, gotOrigin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotOrigin = r.Header.Get("Origin")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL + UpstreamPrefix + "/api/kernels")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://commons.example.org/lw-workspace/proxy/api/kernels", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://commons.example.org")
	rec := httptest.NewRecorder()

	if status := Proxy(rec, req, target); status != http.StatusNoContent {
		t.Fatalf("Proxy() status = %d, want %d", status, http.StatusNoContent)
	}
	if gotHost != target.Host {
		t.Fatalf("upstream Host = %q, want %q", gotHost, target.Host)
	}
	if want := "http://" + target.Host; gotOrigin != want {
		t.Fatalf("upstream Origin = %q, want %q", gotOrigin, want)
	}
}
