// Package identity defines the canonical user identity for an authenticated
// request and the Require middleware that establishes it. Require delegates to
// an Authorizer (see authorizer.go) that is configured once at startup and
// checks each request against arborist.
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

// defaultAuthorizer is set once at startup by Configure and used by Require.
var defaultAuthorizer *Authorizer

var pkgLogger = slog.Default()

func SetLogger(l *slog.Logger) {
	if l != nil {
		pkgLogger = l
	}
}

// Configure sets the Authorizer that Require delegates to. It must be called
// once, before the server starts handling requests.
func Configure(a *Authorizer) {
	defaultAuthorizer = a
}

// Require authenticates and authorizes the request via arborist, stores the
// resolved identity in the request context, and overwrites the upstream
// identity headers with the verified values before any handler can forward
// them. It fails closed: a missing/unconfigured authorizer, a missing token,
// an arborist error, a non-200 response, or an empty username all reject the
// request.
func Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if defaultAuthorizer == nil {
			pkgLogger.Error("workspace authz: authorizer not configured; rejecting",
				slog.String("path", r.URL.Path))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		token := tokenFromRequest(r)
		if token == "" {
			// Distinguish *why* there is no token: cookie vs bearer header.
			// This is the single most useful line for debugging "works in the
			// browser page but API calls 401" — it shows whether the request
			// actually carried the access_token cookie.
			_, cookieErr := r.Cookie(AccessTokenCookie)
			pkgLogger.Warn("workspace authz: no token on request",
				slog.String("path", r.URL.Path),
				slog.Bool("has_access_token_cookie", cookieErr == nil),
				slog.Bool("has_authorization_header", r.Header.Get("Authorization") != ""))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		id, err := defaultAuthorizer.authorize(r.Context(), token)
		if err != nil {
			// Do not distinguish the failure modes to the *client* (all fail
			// closed), but always log the real reason server-side. err carries
			// the arborist detail, e.g. "arborist denied request: status 403".
			pkgLogger.Warn("workspace authz: denied",
				slog.String("path", r.URL.Path),
				slog.String("reason", err.Error()))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		pkgLogger.Debug("workspace authz: allowed",
			slog.String("path", r.URL.Path))

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

// SetUpstreamHeaders overwrites the identity headers sent to upstream services
// with the verified identity. Any client-supplied values are replaced.
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
