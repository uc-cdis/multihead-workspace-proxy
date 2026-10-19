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
	"strings"
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

// SetUpstreamHeaders sets/overwrites the identity headers sent to upstream
// services and strips the user's Gen3 credentials (see StripCredentials).
//
// Require calls this on the inbound request right after authorization, so no
// handler, log statement or upstream ever sees the user's access token.
func SetUpstreamHeaders(h http.Header, id Identity) {
	StripCredentials(h)
	h.Set("REMOTE_USER", id.Username)
	h.Set("remote_user", id.Username)
	h.Set("X-Remote-User", id.Username)
	h.Set("KERNEL_USERNAME", id.Username)
}

// StripCredentials removes the Fence access token from h: the access_token
// cookie and any "Authorization: Bearer ..." header. The token is only needed
// to authorize against arborist; forwarding it would hand a user's Gen3
// credential to their workspace container and to JEG.
//
// Other cookies (e.g. Jupyter's _xsrf) and non-Bearer Authorization schemes
// (e.g. Jupyter's "token ...") are left untouched.
func StripCredentials(h http.Header) {
	if scheme, _, _ := strings.Cut(h.Get("Authorization"), " "); strings.EqualFold(scheme, "Bearer") {
		h.Del("Authorization")
	}

	// HTTP/2 clients may send cookies in several Cookie header lines, so
	// filter every line and keep the remaining pairs byte-for-byte.
	var kept []string
	for _, line := range h.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, _, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(name) == AccessTokenCookie {
				continue
			}
			kept = append(kept, pair)
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// Hash returns a short digest suitable for PII-safe logs.
func Hash(id Identity) string {
	sum := sha256.Sum256([]byte(id.Username))
	return fmt.Sprintf("%x", sum[:8])
}
