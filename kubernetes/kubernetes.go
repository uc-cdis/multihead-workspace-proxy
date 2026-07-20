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

	"github.com/uc-cdis/workspace-proxy/internal/validation"
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

type apiStatusError struct {
	statusCode int
	status     string
	body       string
}

func (e *apiStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("Kubernetes API returned %s", e.status)
	}
	return fmt.Sprintf("Kubernetes API returned %s: %s", e.status, e.body)
}

func (k8s *Client) getJSON(ctx context.Context, apiURL string, out any) error {
	token, err := k8s.bearerToken()
	if err != nil {
		return fmt.Errorf("service account token unavailable: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("create Kubernetes request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := k8s.http.Do(req)
	if err != nil {
		return fmt.Errorf("call Kubernetes API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newAPIStatusError(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode Kubernetes response: %w", err)
	}

	return nil
}

func newAPIStatusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return &apiStatusError{
		statusCode: resp.StatusCode,
		status:     resp.Status,
		body:       strings.TrimSpace(string(body)),
	}
}

func (k8s *Client) ListWorkspaceServices(ctx context.Context) ([]K8sService, error) {
	const pageLimit = 500
	if err := requireDNS1123Label("namespace", k8s.namespace); err != nil {
		return nil, err
	}

	baseURL, err := url.JoinPath(k8s.apiBase, "api", "v1", "namespaces", k8s.namespace, "services")
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes services URL: %w", err)
	}

	services := make([]K8sService, 0)
	continueToken := ""
	seenContinueTokens := make(map[string]struct{})

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
		if err := k8s.getJSON(ctx, pageURL.String(), &raw); err != nil {
			return nil, fmt.Errorf("list Kubernetes services: %w", err)
		}

		for _, item := range raw.Items {
			services = append(services, serviceFromK8sItem(item, k8s.namespace))
		}

		if raw.Metadata.Continue == "" {
			break
		}
		if _, seen := seenContinueTokens[raw.Metadata.Continue]; seen {
			return nil, fmt.Errorf("list Kubernetes services: API repeated continue token")
		}
		seenContinueTokens[raw.Metadata.Continue] = struct{}{}
		continueToken = raw.Metadata.Continue
	}

	return services, nil
}

func (k8s *Client) GetWorkspaceService(ctx context.Context, name string) (K8sService, error) {
	if err := requireDNS1123Label("namespace", k8s.namespace); err != nil {
		return K8sService{}, err
	}
	if err := requireDNS1123Label("workspace service name", name); err != nil {
		return K8sService{}, err
	}

	apiURL, err := url.JoinPath(k8s.apiBase, "api", "v1", "namespaces", k8s.namespace, "services", name)
	if err != nil {
		return K8sService{}, fmt.Errorf("build Kubernetes service URL: %w", err)
	}

	var raw k8sServiceItem
	err = k8s.getJSON(ctx, apiURL, &raw)
	if err != nil {
		var statusErr *apiStatusError
		if errors.As(err, &statusErr) && statusErr.statusCode == http.StatusNotFound {
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
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("service account token file %q is empty", c.tokenPath)
	}
	return token, nil
}

var ErrNotInCluster = errors.New("not running in-cluster")

func New(namespace string) (*Client, error) {
	if err := requireDNS1123Label("namespace", namespace); err != nil {
		return nil, err
	}

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

func requireDNS1123Label(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !validation.IsDNS1123Label(value) {
		return fmt.Errorf("%s %q must be a valid DNS-1123 label", field, value)
	}
	return nil
}
