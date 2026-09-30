// Package identity authenticates users from fence access tokens.
package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
)

// Identity is the canonical user identity for an authenticated request.
type Identity struct {
	Username string
	UID      string
}

type contextKey struct{}

// FromContext returns the authenticated identity established by Verifier.Require.
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
