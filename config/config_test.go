package config

import "testing"

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
