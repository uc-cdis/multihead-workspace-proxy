package validation

import "regexp"

var dns1123Label = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

// IsDNS1123Label reports whether value is a valid Kubernetes DNS-1123 label.
func IsDNS1123Label(value string) bool {
	return len(value) > 0 && len(value) <= 63 && dns1123Label.MatchString(value)
}
