package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---- Kubernetes service discovery ----
//
// workspace-proxy queries the K8s API at request time (with per-user caching) to
// resolve the actual upstream host:port for each user's workspace Service.
//
// Hatchery writes the routing target into the getambassador.io/config annotation:
//   - Local cluster pod:   service: {svcName}.{namespace}.svc.cluster.local:80
//   - External node/GPU:   service: {nodeIP}:{nodePort}  (random NodePort)
//   - ECS/Fargate:         service: {albDNS}:{port}
//
// We extract that "service:" field so we never assume port 80 — GPU nodes,
// external clusters, and ECS all have different ports assigned at launch time.

const (
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	apiBase   = "https://kubernetes.default.svc"
)

// Client wraps in-cluster credentials for Kubernetes API calls.
// TokenPath is stored rather than the token itself so that Bound Service Account
// Token rotation (EKS/GKE default — tokens expire every 1h) is picked up on every
// API call without requiring a pod restart.
type Client struct {
	http      *http.Client
	tokenPath string // re-read on every request — never cached in memory
	apiBase   string
	namespace string
}

type K8sService struct {
	Name        string
	Port        int32
	Namespace   string
	Annotations map[string]string
}

func (k8s *Client) ListWorkspaceServices(ctx context.Context) ([]K8sService, error) {
	token, err := k8s.bearerToken()
	if err != nil {
		return nil, fmt.Errorf("sa token unavailable: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v1/namespaces/%s/services", k8s.apiBase, k8s.namespace)
	log.Printf("%+v", apiURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	log.Printf("%+v", req)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes services request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := k8s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("k8s API returned HTTP %d while listing services", resp.StatusCode)
	}

	var raw struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Ports []struct {
					Port int32 `json:"port"`
				} `json:"ports"`
			} `json:"spec"`
		} `json:"items"`
	}

	log.Printf("%+v", resp.Body)

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode Kubernetes services response: %w", err)
	}

	log.Printf("%+v", raw)

	services := make([]K8sService, 0, len(raw.Items))
	for _, item := range raw.Items {
		var port int32
		if len(item.Spec.Ports) > 0 {
			port = item.Spec.Ports[0].Port
		}

		services = append(services, K8sService{
			Name:        item.Metadata.Name,
			Port:        port,
			Namespace:   k8s.namespace,
			Annotations: item.Metadata.Annotations,
		})
	}

	log.Printf("%+v", services)

	return services, nil
}

func (k8s *Client) GetWorkspaceService(ctx context.Context, name string) (K8sService, error) {
	token, err := k8s.bearerToken()
	if err != nil {
		return K8sService{}, fmt.Errorf("sa token unavailable: %w", err)
	}

	log.Printf("!!!4%+v", name)

	apiURL := fmt.Sprintf(
		"%s/api/v1/namespaces/%s/services/%s",
		k8s.apiBase,
		k8s.namespace,
		name,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return K8sService{}, fmt.Errorf("create Kubernetes service request: %w", err)
	}

	log.Printf("!!!5%+v", name)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := k8s.http.Do(req)
	if err != nil {
		return K8sService{}, fmt.Errorf("k8s API unreachable: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("!!!6%+v", resp.Body)
	log.Printf("!!!7%+v", resp.StatusCode)
	log.Printf("!!!8%+v", resp.Status)

	if resp.StatusCode == http.StatusNotFound {
		return K8sService{}, fmt.Errorf("workspace service %q not found — pod not running", name)
	}
	if resp.StatusCode != http.StatusOK {
		return K8sService{}, fmt.Errorf("k8s API returned HTTP %d for service %q", resp.StatusCode, name)
	}

	var raw struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Ports []struct {
				Port int32 `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return K8sService{}, fmt.Errorf("decode Kubernetes service response: %w", err)
	}

	log.Printf("!!!9%+v", raw)

	var port int32
	if len(raw.Spec.Ports) > 0 {
		port = raw.Spec.Ports[0].Port
	}

	return K8sService{
		Name:        raw.Metadata.Name,
		Port:        port,
		Namespace:   k8s.namespace,
		Annotations: raw.Metadata.Annotations,
	}, nil
}

// BearerToken reads the current service account token from disk.
// Returns an error if the token cannot be read so callers can return 502 rather
// than silently forwarding an expired credential.
func (c *Client) bearerToken() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading SA token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func New() *Client {
	// Verify the token file exists at startup so we can log clearly if not in-cluster.
	if _, err := os.ReadFile(tokenPath); err != nil {
		log.Printf(`{"msg":"no SA token — falling back to plain DNS (not in-cluster?)","detail":%q}`, err.Error())
		return nil
	}
	tlsCfg := &tls.Config{}
	if caBytes, err := os.ReadFile(caPath); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caBytes)
		tlsCfg.RootCAs = pool
	}

	return &Client{
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   5 * time.Second,
		},
		tokenPath: tokenPath,
		apiBase:   apiBase,
	}
}
