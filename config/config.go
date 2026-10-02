package config

import (
	"os"
	"strconv"

	"github.com/uc-cdis/workspace-proxy/internal/validation"
)

func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}

	return n >= 0 && n <= 65535
}

type Config struct {
	ListenAddr         string
	WorkspaceNamespace string
	JEG                JEGConfig
	Authz              AuthzConfig
}

// AuthzConfig configures the arborist authentication/authorization check
// applied to every workspace request.
type AuthzConfig struct {
	// ArboristURL is the base URL of the arborist service (e.g.
	// http://arborist-service).
	ArboristURL string
	// Resource, Method and Service are the arborist authz check applied to
	// every workspace request.
	Resource string
	Method   string
	Service  string
}

type JEGConfig struct {
	GatewayURL       string
	KernelSpecPolicy string
}

func Load() Config {
	return Config{
		ListenAddr:         ":" + envOrDefaultWithValidation("LISTEN_ADDR", "8080", validPort),
		WorkspaceNamespace: envOrDefaultWithValidation("WORKSPACE_NAMESPACE", "jupyter-pods", validation.IsDNS1123Label),
		Authz: AuthzConfig{
			ArboristURL: envOrDefault("ARBORIST_URL", "http://arborist-service"),
			Resource:    envOrDefault("AUTHZ_RESOURCE", "/workspace"),
			Method:      envOrDefault("AUTHZ_METHOD", "access"),
			Service:     envOrDefault("AUTHZ_SERVICE", "jupyterhub2"),
		},
		JEG: JEGConfig{
			GatewayURL:       envOrDefault("JEG_GATEWAY_URL", ""),
			KernelSpecPolicy: envOrDefault("JEG_KERNEL_SPEC_POLICY", ""),
		},
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultWithValidation(key, fallback string, valid func(string) bool) string {
	v := os.Getenv(key)
	if v == "" || !valid(v) {
		return fallback
	}
	return v
}
