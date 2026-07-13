// Package identity defines the trusted user identity established by the edge proxy.
package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

// Identity is the canonical user identity for an authenticated request.
type Identity struct {
	Username string
	UID      string
}

type contextKey struct{}

// Require validates the trusted identity headers and stores their canonical form
// in the request context. X-Gen3-User-ID takes precedence over REMOTE_USER.
func Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
		remoteUser := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
		if assertion == "" {
			assertion = remoteUser
		}

		id := Identity{
			Username: normalizeUsername(assertion),
			UID:      parseUID(assertion),
		}
		if id.Username == "" {
			id.Username = normalizeUsername(remoteUser)
		}
		if id.UID == "" {
			id.UID = parseUID(remoteUser)
		}
		if id.Username == "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Replace trusted headers with canonical values before any handler can
		// forward them. The edge proxy must strip client-supplied versions.
		SetUpstreamHeaders(r.Header, id)
		ctx := context.WithValue(r.Context(), contextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext returns the authenticated identity established by Require.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// SetUpstreamHeaders overwrites the identity headers sent to upstream services.
func SetUpstreamHeaders(h http.Header, id Identity) {
	h.Set("REMOTE_USER", id.Username)
	h.Set("remote_user", id.Username)
	h.Set("X-Remote-User", id.Username)
	h.Set("KERNEL_USERNAME", id.Username)
	if id.UID != "" {
		h.Set("X-Gen3-User-ID", id.UID)
	} else {
		h.Del("X-Gen3-User-ID")
	}
}

// Hash returns a short digest suitable for PII-safe logs.
func Hash(id Identity) string {
	sum := sha256.Sum256([]byte(id.Username))
	return fmt.Sprintf("%x", sum[:8])
}

func normalizeUsername(assertion string) string {
	v := strings.TrimSpace(assertion)
	if strings.HasPrefix(v, "uid:") {
		parts := strings.SplitN(v, ",", 2)
		if len(parts) == 2 {
			if username := strings.TrimSpace(parts[1]); username != "" {
				return username
			}
		}
	}
	return v
}

func parseUID(assertion string) string {
	v := strings.TrimSpace(assertion)
	if !strings.HasPrefix(v, "uid:") {
		return ""
	}
	v = strings.TrimPrefix(v, "uid:")
	parts := strings.SplitN(v, ",", 2)
	return strings.TrimSpace(parts[0])
}
