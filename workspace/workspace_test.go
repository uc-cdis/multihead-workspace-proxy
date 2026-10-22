package workspace

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/uc-cdis/workspace-proxy/kubernetes"
)

// hatcheryAnnotation renders the getambassador.io/config template Hatchery
// writes on workspace Services (hatchery pods.go ambassadorYaml and
// localAmbassadorYaml).
func hatcheryAnnotation(service, useTLS string) string {
	return fmt.Sprintf(`---
apiVersion: ambassador/v1
kind:  Mapping
name:  h-user-40example-2eorg-mapping
prefix: /
headers:
  remote_user: user@example.org
service: %s
bypass_auth: true
timeout_ms: 300000
use_websocket: true
rewrite: /lw-workspace/proxy/
tls: %s
`, service, useTLS)
}

func TestUpstreamFromAmbassadorConfig(t *testing.T) {
	tests := []struct {
		name       string
		annotation string
		want       string
		wantOK     bool
		wantErr    bool
	}{
		{
			name:       "local pod",
			annotation: hatcheryAnnotation("h-user-40example-2eorg-s.jupyter-pods.svc.cluster.local:80", "false"),
			want:       "http://h-user-40example-2eorg-s.jupyter-pods.svc.cluster.local:80",
			wantOK:     true,
		},
		{
			name:       "ECS internal ALB",
			annotation: hatcheryAnnotation("internal-h-user-s-123.us-east-1.elb.amazonaws.com:80", "false"),
			want:       "http://internal-h-user-s-123.us-east-1.elb.amazonaws.com:80",
			wantOK:     true,
		},
		{
			name:       "external node NodePort",
			annotation: hatcheryAnnotation("10.0.12.34:31234", "false"),
			want:       "http://10.0.12.34:31234",
			wantOK:     true,
		},
		{
			name:       "tls true uses https",
			annotation: hatcheryAnnotation("internal-alb.example.com:443", "true"),
			want:       "https://internal-alb.example.com:443",
			wantOK:     true,
		},
		{
			name:       "empty tls uses http",
			annotation: hatcheryAnnotation("internal-alb.example.com:80", ""),
			want:       "http://internal-alb.example.com:80",
			wantOK:     true,
		},
		{
			name:       "CRLF line endings",
			annotation: "service: internal-alb.example.com:80\r\ntls: false\r\n",
			want:       "http://internal-alb.example.com:80",
			wantOK:     true,
		},
		{
			name:       "nested service key is ignored",
			annotation: "headers:\n  service: evil.example.com:80\n",
			wantOK:     false,
		},
		{name: "empty annotation", annotation: "", wantOK: false},
		{name: "missing port", annotation: hatcheryAnnotation("internal-alb.example.com", "false"), wantOK: false},
		{name: "non-numeric port", annotation: hatcheryAnnotation("internal-alb.example.com:http", "false"), wantOK: false},
		{name: "port out of range", annotation: hatcheryAnnotation("internal-alb.example.com:0", "false"), wantOK: false},
		{name: "empty host", annotation: hatcheryAnnotation(":80", "false"), wantOK: false},
		{name: "path in host", annotation: hatcheryAnnotation("evil.example.com/x:80", "false"), wantOK: false},
		{name: "userinfo in host", annotation: hatcheryAnnotation("user@evil.example.com:80", "false"), wantOK: false},
		{name: "space in host", annotation: hatcheryAnnotation("a b.example.com:80", "false"), wantOK: false},
		{name: "percent in host", annotation: hatcheryAnnotation("a%2Fb.example.com:80", "false"), wantOK: false},
		{name: "backslash in host", annotation: hatcheryAnnotation("a\\b.example.com:80", "false"), wantOK: false},
		{name: "signed port", annotation: hatcheryAnnotation("internal-alb.example.com:+80", "false"), wantOK: false},

		// TLS must never be silently downgraded to plain HTTP.
		{name: "tls true without service is an error", annotation: "tls: true\n", wantErr: true},
		{name: "tls true with invalid service is an error", annotation: hatcheryAnnotation("no-port", "true"), wantErr: true},
		{name: "tls true with bad host is an error", annotation: hatcheryAnnotation("a b.example.com:443", "true"), wantErr: true},
		{name: "tls yes is an error", annotation: hatcheryAnnotation("internal-alb.example.com:443", "yes"), wantErr: true},
		{name: "tls on is an error", annotation: hatcheryAnnotation("internal-alb.example.com:443", "on"), wantErr: true},
		{name: "tls 1 is an error", annotation: hatcheryAnnotation("internal-alb.example.com:443", "1"), wantErr: true},
		{name: "quoted tls is an error", annotation: hatcheryAnnotation("internal-alb.example.com:443", `"true"`), wantErr: true},
		{name: "unrecognized tls errors even without service", annotation: "tls: yes\n", wantErr: true},
		{
			name:       "tls TRUE is accepted",
			annotation: hatcheryAnnotation("internal-alb.example.com:443", "TRUE"),
			want:       "https://internal-alb.example.com:443",
			wantOK:     true,
		},
		{
			name:       "later tls false does not downgrade",
			annotation: "service: internal-alb.example.com:443\ntls: true\ntls: false\n",
			want:       "https://internal-alb.example.com:443",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := upstreamFromAmbassadorConfig(tt.annotation)
			if (err != nil) != tt.wantErr {
				t.Fatalf("upstreamFromAmbassadorConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("upstreamFromAmbassadorConfig() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestUpstreamForService(t *testing.T) {
	tests := []struct {
		name    string
		service kubernetes.K8sService
		want    string
		wantErr error
	}{
		{
			name: "ECS annotation routes to ALB",
			service: kubernetes.K8sService{
				Name:      "h-user-40example-2eorg-s",
				Namespace: "jupyter-pods",
				Port:      80,
				Annotations: map[string]string{
					ambassadorConfigAnnotation: hatcheryAnnotation("internal-alb.example.com:80", "false"),
				},
			},
			want: "http://internal-alb.example.com:80",
		},
		{
			name: "no annotation falls back to cluster DNS",
			service: kubernetes.K8sService{
				Name:      "h-user-40example-2eorg-s",
				Namespace: "jupyter-pods",
				Port:      8888,
			},
			want: "http://h-user-40example-2eorg-s.jupyter-pods.svc.cluster.local:8888",
		},
		{
			name: "invalid annotation falls back to cluster DNS",
			service: kubernetes.K8sService{
				Name:      "h-user-40example-2eorg-s",
				Namespace: "jupyter-pods",
				Port:      80,
				Annotations: map[string]string{
					ambassadorConfigAnnotation: hatcheryAnnotation("no-port", "false"),
				},
			},
			want: "http://h-user-40example-2eorg-s.jupyter-pods.svc.cluster.local:80",
		},
		{
			name: "tls true with invalid annotation does not fall back to http",
			service: kubernetes.K8sService{
				Name:      "h-user-40example-2eorg-s",
				Namespace: "jupyter-pods",
				Port:      80,
				Annotations: map[string]string{
					ambassadorConfigAnnotation: hatcheryAnnotation("no-port", "true"),
				},
			},
			wantErr: errTLSWithoutTarget,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := upstreamForService(tt.service)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("upstreamForService() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("upstreamForService() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Errors from upstreamForService are logged, so they must not contain the
// Service name, which is derived from the username.
func TestUpstreamForServiceErrorOmitsServiceName(t *testing.T) {
	for _, annotation := range []string{
		hatcheryAnnotation("no-port", "true"),
		hatcheryAnnotation("internal-alb.example.com:443", "yes"),
	} {
		_, err := upstreamForService(kubernetes.K8sService{
			Name:        "h-user-40example-2eorg-s",
			Namespace:   "jupyter-pods",
			Port:        80,
			Annotations: map[string]string{ambassadorConfigAnnotation: annotation},
		})
		if err == nil {
			t.Fatalf("upstreamForService() error = nil, want an error for %q", annotation)
		}
		if strings.Contains(err.Error(), "h-user") || strings.Contains(err.Error(), "example-2eorg") {
			t.Fatalf("error %q contains the username-derived Service name", err)
		}
	}
}
