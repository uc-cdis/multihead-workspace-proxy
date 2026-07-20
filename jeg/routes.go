package jeg

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/uc-cdis/workspace-proxy/proxy"
)

// ProxyRoutes returns the routes used by JupyterLab's gateway client. Keeping
// the route table here prevents similarly-prefixed paths from entering the JEG
// handler and lets chi return 405 for unsupported methods.
func (jeg *JEG) ProxyRoutes() http.Handler {
	r := chi.NewRouter()

	r.Get("/api/kernelspecs", jeg.proxyHandler)
	r.Get("/api/kernels", jeg.proxyHandler)
	r.Post("/api/kernels", jeg.proxyHandler)
	r.Get("/api/kernels/{kernelID}", jeg.proxyHandler)
	r.Delete("/api/kernels/{kernelID}", jeg.proxyHandler)
	r.Get("/api/kernels/{kernelID}/channels", jeg.proxyHandler)

	r.Get("/api/sessions", jeg.proxyHandler)
	r.Post("/api/sessions", jeg.proxyHandler)
	r.Get("/api/sessions/{sessionID}", jeg.proxyHandler)
	r.Patch("/api/sessions/{sessionID}", jeg.proxyHandler)
	r.Delete("/api/sessions/{sessionID}", jeg.proxyHandler)

	for _, method := range []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	} {
		r.Method(method, "/api/contents", http.HandlerFunc(jeg.proxyHandler))
		r.Method(method, "/api/contents/*", http.HandlerFunc(jeg.proxyHandler))
	}

	// Kernelspec resources contain this prefix in URLs returned to JupyterLab.
	resourcePath := proxy.UpstreamPrefix + "/*"
	r.Get(resourcePath, jeg.proxyHandler)
	r.Head(resourcePath, jeg.proxyHandler)

	return r
}

// PanelRoutes returns the billing-panel API routes.
func (jeg *JEG) PanelRoutes() http.Handler {
	r := chi.NewRouter()
	r.Get("/api/status", jeg.panelHandler)
	r.Get("/api/kernelspecs", jeg.panelHandler)
	r.Get("/api/kernels", jeg.panelHandler)
	r.Post("/api/kernels", jeg.panelHandler)
	r.Delete("/api/kernels/{kernelID}", jeg.panelHandler)
	return r
}
