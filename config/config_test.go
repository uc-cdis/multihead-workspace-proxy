package config

import "testing"

// TestLoadValidatesWorkspaceNamespace verifies that WORKSPACE_NAMESPACE is used
// when it is a valid label and falls back to "jupyter-pods" when it
// is unset or invalid.
//
// Why: the namespace is passed straight to Kubernetes API calls. An invalid
// value would make every pod lookup fail, so the loader replaces it with a
// known-good default.
func TestLoadValidatesWorkspaceNamespace(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "unset", value: "", expected: "jupyter-pods"},
		{name: "valid", value: "workspace-ns", expected: "workspace-ns"},
		{name: "invalid", value: "Workspace/Namespace", expected: "jupyter-pods"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("WORKSPACE_NAMESPACE", test.value)
			if got := Load().WorkspaceNamespace; got != test.expected {
				t.Errorf("WorkspaceNamespace = %q, want %q", got, test.expected)
			}
		})
	}
}

// TestLoadValidatesListenAddr verifies that LISTEN_ADDR becomes ":<port>" for a
// valid port and falls back to ":8080" for unset, non-numeric, negative, or
// out-of-range values.
//
// Why: a bad port would make the server fail to bind at startup and crash-loop
// the pod. Covering both ends of the range check keeps validPort from being
// loosened by accident.
func TestLoadValidatesListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "unset", value: "", expected: ":8080"},
		{name: "valid", value: "9090", expected: ":9090"},
		{name: "not a number", value: "http", expected: ":8080"},
		{name: "out of range", value: "70000", expected: ":8080"},
		{name: "negative", value: "-1", expected: ":8080"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("LISTEN_ADDR", test.value)
			if got := Load().ListenAddr; got != test.expected {
				t.Errorf("ListenAddr = %q, want %q", got, test.expected)
			}
		})
	}
}

// TestLoadAuthzDefaults verifies the arborist settings used when no
// ARBORIST_URL / AUTHZ_* environment variables are set.
//
// Why: most deployments will run on these defaults, so they define the actual
// security policy in production: which arborist instance is asked, and which
// resource/method/service is checked. Changing any of them silently would
// change who can reach workspaces, so the test makes that change explicit.
func TestLoadAuthzDefaults(t *testing.T) {
	for _, key := range []string{"ARBORIST_URL", "AUTHZ_RESOURCE", "AUTHZ_METHOD", "AUTHZ_SERVICE"} {
		t.Setenv(key, "")
	}

	want := AuthzConfig{
		ArboristURL: "http://arborist-service",
		Resource:    "/workspace",
		Method:      "access",
		Service:     "jupyterhub",
	}
	if got := Load().Authz; got != want {
		t.Errorf("Authz = %#v, want %#v", got, want)
	}
}

// TestLoadAuthzFromEnv verifies that each ARBORIST_URL / AUTHZ_* variable
// overrides its corresponding AuthzConfig field.
//
// Why: operators need to point the proxy at a different arborist or a narrower
// resource per environment. A field wired to the wrong variable, such as a
// copy-paste error between AUTHZ_METHOD and AUTHZ_SERVICE, would compile fine
// and only show up as unexpected allows or denies in production.
func TestLoadAuthzFromEnv(t *testing.T) {
	t.Setenv("ARBORIST_URL", "http://arborist.example:8080")
	t.Setenv("AUTHZ_RESOURCE", "/programs/foo")
	t.Setenv("AUTHZ_METHOD", "read")
	t.Setenv("AUTHZ_SERVICE", "workspace")

	want := AuthzConfig{
		ArboristURL: "http://arborist.example:8080",
		Resource:    "/programs/foo",
		Method:      "read",
		Service:     "workspace",
	}
	if got := Load().Authz; got != want {
		t.Errorf("Authz = %#v, want %#v", got, want)
	}
}

// TestLoadJEGFromEnv verifies that JEG_GATEWAY_URL and JEG_KERNEL_SPEC_POLICY
// are read into the JEG config.
func TestLoadJEGFromEnv(t *testing.T) {
	t.Setenv("JEG_GATEWAY_URL", "http://jeg:8888")
	t.Setenv("JEG_KERNEL_SPEC_POLICY", "allow-all")

	got := Load().JEG
	if got.GatewayURL != "http://jeg:8888" || got.KernelSpecPolicy != "allow-all" {
		t.Errorf("JEG = %#v, want gateway http://jeg:8888 and policy allow-all", got)
	}
}
