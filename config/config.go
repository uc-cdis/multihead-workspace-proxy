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
}

type JEGConfig struct {
	GatewayURL       string
	KernelSpecPolicy string
}

func Load() Config {
	return Config{
		ListenAddr:         ":" + envOrDefaultWithValidation("LISTEN_ADDR", "8080", validPort),
		WorkspaceNamespace: envOrDefaultWithValidation("WORKSPACE_NAMESPACE", "jupyter-pods", validation.IsDNS1123Label),
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
