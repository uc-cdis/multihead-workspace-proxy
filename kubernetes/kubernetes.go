package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

type k8sServiceListResponse struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`

	Items []k8sServiceItem `json:"items"`
}

type k8sServiceItem struct {
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

func serviceFromK8sItem(item k8sServiceItem, namespace string) K8sService {
	var port int32
	if len(item.Spec.Ports) > 0 {
		port = item.Spec.Ports[0].Port
	}

	return K8sService{
		Name:        item.Metadata.Name,
		Port:        port,
		Namespace:   namespace,
		Annotations: item.Metadata.Annotations,
	}
}

func (k8s *Client) getJSON(ctx context.Context, apiURL string, out any) (*http.Response, error) {
	token, err := k8s.bearerToken()
	if err != nil {
		return nil, fmt.Errorf("service account token unavailable: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := k8s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call Kubernetes API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp, k8sAPIStatusError(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp, fmt.Errorf("decode Kubernetes response: %w", err)
	}

	return resp, nil
}

func k8sAPIStatusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	return fmt.Errorf(
		"k8s API returned %s: %s",
		resp.Status,
		strings.TrimSpace(string(body)),
	)
}

func (k8s *Client) ListWorkspaceServices(ctx context.Context) ([]K8sService, error) {
	const pageLimit = 500

	baseURL, err := url.JoinPath(
		k8s.apiBase,
		"api",
		"v1",
		"namespaces",
		k8s.namespace,
		"services",
	)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes services URL: %w", err)
	}

	services := make([]K8sService, 0)
	continueToken := ""

	for {
		pageURL, err := url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("parse Kubernetes services URL: %w", err)
		}

		query := pageURL.Query()
		query.Set("limit", strconv.Itoa(pageLimit))
		if continueToken != "" {
			query.Set("continue", continueToken)
		}
		pageURL.RawQuery = query.Encode()

		var raw k8sServiceListResponse
		if _, err := k8s.getJSON(ctx, pageURL.String(), &raw); err != nil {
			return nil, fmt.Errorf("list Kubernetes services: %w", err)
		}

		for _, item := range raw.Items {
			services = append(services, serviceFromK8sItem(item, k8s.namespace))
		}

		if raw.Metadata.Continue == "" {
			break
		}
		continueToken = raw.Metadata.Continue
	}

	return services, nil
}

func (k8s *Client) GetWorkspaceService(ctx context.Context, name string) (K8sService, error) {
	if strings.TrimSpace(name) == "" {
		return K8sService{}, fmt.Errorf("workspace service name is required")
	}

	apiURL, err := url.JoinPath(
		k8s.apiBase,
		"api",
		"v1",
		"namespaces",
		k8s.namespace,
		"services",
		name,
	)
	if err != nil {
		return K8sService{}, fmt.Errorf("build Kubernetes service URL: %w", err)
	}

	var raw k8sServiceItem
	resp, err := k8s.getJSON(ctx, apiURL, &raw)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return K8sService{}, fmt.Errorf("workspace service %q not found", name)
		}

		return K8sService{}, fmt.Errorf("get Kubernetes service %q: %w", name, err)
	}

	return serviceFromK8sItem(raw, k8s.namespace), nil
}

// BearerToken reads the current service account token from disk.
// Returns an error if the token cannot be read so callers can return 502 rather
// than silently forwarding an expired credential.
func (c *Client) bearerToken() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read service account token from %q: %w", c.tokenPath, err)
	}
	token := strings.TrimRight(string(b), "\r\n")
	if token == "" {
		return "", fmt.Errorf("service account token file %q is empty", c.tokenPath)
	}
	return token, nil
}

var ErrNotInCluster = errors.New("not running in-cluster")

func New(namespace string) (*Client, error) {
	// Check presence only; bearerToken reads the file later so rotated tokens are picked up.
	if _, err := os.Stat(tokenPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInCluster
		}
		return nil, fmt.Errorf("checking service account token at %q: %w", tokenPath, err)
	}

	var tlsCfg *tls.Config

	caBytes, err := os.ReadFile(caPath)
	if err == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("parsing Kubernetes CA cert at %q: no PEM certificates found", caPath)
		}

		tlsCfg = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading Kubernetes CA cert at %q: %w", caPath, err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg

	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
		tokenPath: tokenPath,
		apiBase:   apiBase,
		namespace: namespace,
	}, nil
}
