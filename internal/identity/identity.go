// Package identity defines the canonical user identity for an authenticated
// request and the Require middleware that establishes it. Require delegates
// security to an Authorizer (see authorizer.go).
package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
)

// Identity is the canonical user identity for an authenticated request.
type Identity struct {
	Username string
	UID      string
}

type contextKey struct{}

type authorizer interface {
	authorize(ctx context.Context, token string) (Identity, error)
}

// defaultAuthorizer is set once at startup by Configure and used by Require.
var defaultAuthorizer authorizer

// Configure sets the Authorizer that Require delegates to. It must be called
// once, before the server starts handling requests.
func Configure(a *Authorizer) {
	defaultAuthorizer = a
}

// Require authenticates and authorizes, stores the
// resolved identity in the request context, and overwrites the upstream
// identity headers.
// It fails closed: a missing/unconfigured authorizer, a missing token,
// an authorizer error... all reject the request.
func Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if defaultAuthorizer == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		token := tokenFromRequest(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := defaultAuthorizer.authorize(r.Context(), token)
		if err != nil {
			slog.Error("authz failed", "err", err)
			// Do not distinguish "unauthenticated", "unauthorized" and
			// "arborist unreachable" to the client; all fail closed.
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

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

// SetUpstreamHeaders sets/overwrites some request headers
// with given identity.
func SetUpstreamHeaders(h http.Header, id Identity) {
	h.Set("REMOTE_USER", id.Username)
	h.Set("remote_user", id.Username)
	h.Set("X-Remote-User", id.Username)
	h.Set("KERNEL_USERNAME", id.Username)
}

// Hash returns a short digest suitable for PII-safe logs.
func Hash(id Identity) string {
	sum := sha256.Sum256([]byte(id.Username))
	return fmt.Sprintf("%x", sum[:8])
}
