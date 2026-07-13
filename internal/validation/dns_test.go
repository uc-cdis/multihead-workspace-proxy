package validation

import (
	"strings"
	"testing"
)

func TestIsDNS1123Label(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "simple", value: "workspace", want: true},
		{name: "hyphenated", value: "workspace-ns-1", want: true},
		{name: "empty", value: "", want: false},
		{name: "uppercase", value: "Workspace", want: false},
		{name: "leading hyphen", value: "-workspace", want: false},
		{name: "trailing hyphen", value: "workspace-", want: false},
		{name: "dot", value: "workspace.ns", want: false},
		{name: "too long", value: strings.Repeat("a", 64), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsDNS1123Label(test.value); got != test.want {
				t.Errorf("IsDNS1123Label(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}
