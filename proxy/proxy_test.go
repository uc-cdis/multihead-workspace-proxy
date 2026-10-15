package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Jupyter rejects non-GET requests whose Origin host differs from Host, so the
// proxy must make them agree for every method, not only WebSocket upgrades.
func TestProxyRewritesOriginToUpstreamHost(t *testing.T) {
	var gotOrigin, gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin, gotHost = r.Header.Get("Origin"), r.Host
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL + "/x")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete} {
		gotOrigin, gotHost = "", ""
		req := httptest.NewRequest(method, "http://public.example.com/x", strings.NewReader("{}"))
		req.Header.Set("Origin", "https://public.example.com")
		Proxy(httptest.NewRecorder(), req, target)
		if want := "http://" + target.Host; gotOrigin != want || gotHost != target.Host {
			t.Errorf("%s: origin=%q host=%q, want origin=%q host=%q", method, gotOrigin, gotHost, want, target.Host)
		}
	}
}

func TestProxyLeavesAbsentOriginAlone(t *testing.T) {
	var gotOrigin string
	var has bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, has = r.Header["Origin"]
		gotOrigin = r.Header.Get("Origin")
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	Proxy(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil), target)
	if has {
		t.Errorf("Origin header should not be added, got %q", gotOrigin)
	}
}
