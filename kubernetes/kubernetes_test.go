package kubernetes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGetWorkspaceServiceReturnsAnnotations(t *testing.T) {
	const annotation = "service: internal-alb.example.com:80\n"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/jupyter-pods/services/h-user-s" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"metadata": {
				"name": "h-user-s",
				"annotations": {"getambassador.io/config": "service: internal-alb.example.com:80\n"}
			},
			"spec": {"ports": [{"port": 80}]}
		}`))
	}))
	defer api.Close()

	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &Client{http: api.Client(), tokenPath: token, apiBase: api.URL, namespace: "jupyter-pods"}

	svc, err := client.GetWorkspaceService(context.Background(), "h-user-s")
	if err != nil {
		t.Fatalf("GetWorkspaceService() error = %v", err)
	}
	if svc.Name != "h-user-s" || svc.Namespace != "jupyter-pods" || svc.Port != 80 {
		t.Fatalf("GetWorkspaceService() = %+v, want name h-user-s, namespace jupyter-pods, port 80", svc)
	}
	if got := svc.Annotations["getambassador.io/config"]; got != annotation {
		t.Fatalf("annotation = %q, want %q", got, annotation)
	}
}
