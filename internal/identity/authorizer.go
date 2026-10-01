// Authorizer authenticates and authorizes requests by delegating to arborist,
// the Gen3 policy engine. The user's fence access token (from the access_token
// cookie or an Authorization bearer header) is forwarded to arborist's
// /auth/proxy endpoint, which verifies the token signature against fence's
// JWKS and evaluates policy. On allow (HTTP 200) arborist returns the resolved
// username in the REMOTE_USER response header; that single trusted answer is
// used as the request identity by Require (see identity.go).
//
// This replaces trusting REMOTE_USER / X-Gen3-User-ID request headers, which
// let any caller able to reach this service assert an arbitrary identity.
package identity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AccessTokenCookie is the cookie in which the Gen3 portal stores the fence
// access token.
const AccessTokenCookie = "access_token"

// Authorizer authenticates and authorizes requests against arborist.
type Authorizer struct {
	// authURL is the fully-formed arborist auth endpoint, e.g.
	// http://arborist-service/auth/proxy
	authURL  string
	resource string
	method   string
	service  string
	client   *http.Client
}

// NewAuthorizer builds an Authorizer that checks `method` access on `resource`
// for `service` by calling arborist at arboristURL (the service base URL, e.g.
// http://arborist-service).
func NewAuthorizer(arboristURL, resource, method, service string) *Authorizer {
	return &Authorizer{
		authURL:  strings.TrimRight(arboristURL, "/") + "/auth/proxy",
		resource: resource,
		method:   method,
		service:  service,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// authorize asks arborist whether the bearer token is allowed `method` on
// `resource` for `service`. On allow (HTTP 200) arborist returns the verified
// username in the REMOTE_USER response header, which becomes the identity.
func (a *Authorizer) authorize(ctx context.Context, token string) (Identity, error) {
	q := url.Values{}
	q.Set("resource", a.resource)
	q.Set("method", a.method)
	q.Set("service", a.service)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.authURL+"?"+q.Encode(), nil)
	if err != nil {
		return Identity{}, err
	}
	// arborist reads the token from the Authorization header and verifies its
	// signature against fence's JWKS.
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("arborist auth request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
		_ = resp.Body.Close()
	}()

	// arborist returns 200 on allow, 403 on deny, 401 on a missing/invalid
	// token, and 400 on a malformed request. Anything other than 200 is a deny.
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("arborist denied request: status %d", resp.StatusCode)
	}

	username := strings.TrimSpace(resp.Header.Get("REMOTE_USER"))
	if username == "" {
		return Identity{}, fmt.Errorf("arborist returned no REMOTE_USER")
	}
	return Identity{Username: username}, nil
}

// tokenFromRequest extracts the fence access token from the access_token cookie
// or, failing that, an "Authorization: Bearer <token>" header.
func tokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(AccessTokenCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(token)
	}
	return ""
}
