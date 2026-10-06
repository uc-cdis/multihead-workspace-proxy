package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// arboristCall records what the fake arborist received.
type arboristCall struct {
	Path          string
	Resource      string
	Method        string
	Service       string
	Authorization string
}

// fakeArborist is an httptest server standing in for arborist's /auth/proxy.
type fakeArborist struct {
	*httptest.Server

	mu    sync.Mutex
	calls []arboristCall
}

// newFakeArborist starts a fake arborist that responds with status and, when
// remoteUser is non-empty, sets the REMOTE_USER response header.
func newFakeArborist(t *testing.T, status int, remoteUser string) *fakeArborist {
	t.Helper()
	fa := &fakeArborist{}
	fa.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		fa.mu.Lock()
		fa.calls = append(fa.calls, arboristCall{
			Path:          r.URL.Path,
			Resource:      q.Get("resource"),
			Method:        q.Get("method"),
			Service:       q.Get("service"),
			Authorization: r.Header.Get("Authorization"),
		})
		fa.mu.Unlock()

		w.Header().Set("REMOTE_USER", remoteUser)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("body that should be drained"))
	}))
	t.Cleanup(fa.Close)
	return fa
}

func (fa *fakeArborist) Calls() []arboristCall {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return append([]arboristCall(nil), fa.calls...)
}

// TestNewAuthorizerBuildsAuthURL verifies that NewAuthorizer joins the arborist
// base URL and "/auth/proxy" correctly regardless of trailing slashes, stores
// the resource/method/service triple as given, and configures an HTTP client
// with a timeout.
//
// Why: ARBORIST_URL comes from deployment config and operators may or may not
// include a trailing slash. A doubled slash ("//auth/proxy") can 404 or be
// routed differently by an ingress, which would deny every request. The
// timeout check guards against someone swapping in http.DefaultClient, which
// has no timeout and would let a hung arborist hang every workspace request.
func TestNewAuthorizerBuildsAuthURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		want string
	}{
		{name: "no trailing slash", base: "http://arborist-service", want: "http://arborist-service/auth/proxy"},
		{name: "trailing slash", base: "http://arborist-service/", want: "http://arborist-service/auth/proxy"},
		{name: "multiple trailing slashes", base: "http://arborist-service///", want: "http://arborist-service/auth/proxy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := NewAuthorizer(test.base, "/workspace", "access", "jupyterhub")
			if a.authURL != test.want {
				t.Errorf("authURL = %q, want %q", a.authURL, test.want)
			}
			if a.resource != "/workspace" || a.method != "access" || a.service != "jupyterhub" {
				t.Errorf("authz check = (%q, %q, %q), want (/workspace, access, jupyterhub)", a.resource, a.method, a.service)
			}
			if a.client == nil || a.client.Timeout <= 0 {
				t.Errorf("client must be non-nil with a timeout, got %#v", a.client)
			}
		})
	}
}

// TestAuthorizeAllowReturnsIdentity is the happy path: arborist answers 200 with
// a REMOTE_USER header, and authorize returns that username (whitespace
// trimmed) as the identity. It also asserts the exact request sent to arborist:
// path, resource/method/service query parameters, and the bearer token.
//
// Why: this pins down the contract with arborist.
func TestAuthorizeAllowReturnsIdentity(t *testing.T) {
	fa := newFakeArborist(t, http.StatusOK, "  alice@example.com  ")
	// Trailing slash ensures the request path is not "//auth/proxy".
	a := NewAuthorizer(fa.URL+"/", "/workspace", "access", "jupyterhub")

	id, err := a.authorize(context.Background(), "tok-123")
	if err != nil {
		t.Fatalf("authorize returned error: %v", err)
	}
	if id != (Identity{Username: "alice@example.com"}) {
		t.Errorf("identity = %#v, want username alice@example.com (trimmed) and no UID", id)
	}

	calls := fa.Calls()
	if len(calls) != 1 {
		t.Fatalf("arborist called %d times, want 1", len(calls))
	}
	want := arboristCall{
		Path:          "/auth/proxy",
		Resource:      "/workspace",
		Method:        "access",
		Service:       "jupyterhub",
		Authorization: "Bearer tok-123",
	}
	if calls[0] != want {
		t.Errorf("arborist request = %#v, want %#v", calls[0], want)
	}
}

// TestAuthorizeEncodesQueryParameters uses resource/service values containing
// '&', '?', '=' and spaces and verifies arborist receives them intact.
//
// Why: resource paths are configurable (AUTHZ_RESOURCE). If authorize ever
// built the query string by naive concatenation, a value like "/a&method=x"
// could inject or override parameters and change which policy arborist
// evaluates. This locks in proper url.Values encoding.
func TestAuthorizeEncodesQueryParameters(t *testing.T) {
	fa := newFakeArborist(t, http.StatusOK, "alice")
	resource := "/programs/a&b/projects/c d?x=1"
	a := NewAuthorizer(fa.URL, resource, "read", "svc&name")

	if _, err := a.authorize(context.Background(), "tok"); err != nil {
		t.Fatalf("authorize returned error: %v", err)
	}
	got := fa.Calls()[0]
	if got.Resource != resource || got.Method != "read" || got.Service != "svc&name" {
		t.Errorf("query = (%q, %q, %q), want (%q, read, svc&name)", got.Resource, got.Method, got.Service, resource)
	}
}

// TestAuthorizeRejectsNonOKStatus verifies that every status other than 200,
// including other 2xx codes like 204, is treated as a deny and returns a zero
// Identity, even when arborist also sends a REMOTE_USER header.
func TestAuthorizeRejectsNonOKStatus(t *testing.T) {
	statuses := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
		// Non-200 success codes are still a deny.
		http.StatusNoContent,
	}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// REMOTE_USER is set to prove it is ignored unless the status is 200.
			fa := newFakeArborist(t, status, "mallory")
			a := NewAuthorizer(fa.URL, "/workspace", "access", "jupyterhub")

			id, err := a.authorize(context.Background(), "tok")
			if err == nil {
				t.Fatalf("authorize succeeded with status %d, want error", status)
			}
			if id != (Identity{}) {
				t.Errorf("identity = %#v, want zero value", id)
			}
		})
	}
}

// TestAuthorizeRejectsMissingRemoteUser covers arborist returning 200 but with
// an empty or whitespace-only REMOTE_USER header, which must be an error.
//
// Why: an allow with no username cannot be routed to a workspace and would
// otherwise produce an Identity{Username: ""}.
func TestAuthorizeRejectsMissingRemoteUser(t *testing.T) { //pa
	for _, remoteUser := range []string{"", "   "} {
		t.Run("remote_user="+remoteUser, func(t *testing.T) {
			fa := newFakeArborist(t, http.StatusOK, remoteUser)
			a := NewAuthorizer(fa.URL, "/workspace", "access", "jupyterhub")

			id, err := a.authorize(context.Background(), "tok")
			if err == nil || !strings.Contains(err.Error(), "REMOTE_USER") {
				t.Fatalf("err = %v, want REMOTE_USER error", err)
			}
			if id != (Identity{}) {
				t.Errorf("identity = %#v, want zero value", id)
			}
		})
	}
}

// TestAuthorizeArboristUnreachable points the authorizer at a server that has
// already been shut down and expects an error.
//
// Why: arborist being down or unreachable (DNS failure, network policy, pod
// restart) is a realistic production failure. This confirms a transport error
// surfaces as an error, which Require turns into a deny, rather than being
// mistaken for an allow.
func TestAuthorizeArboristUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing is listening any more

	a := NewAuthorizer(url, "/workspace", "access", "jupyterhub")
	if _, err := a.authorize(context.Background(), "tok"); err == nil {
		t.Fatal("authorize succeeded against a closed server, want error")
	}
}

// TestAuthorizeInvalidURL configures an arborist URL that cannot be parsed and
// expects authorize to return an error instead of panicking.
//
// Why: a typo in ARBORIST_URL is not validated at startup, so the first place
// it shows up is here.
func TestAuthorizeInvalidURL(t *testing.T) {
	a := NewAuthorizer("http://bad host", "/workspace", "access", "jupyterhub")
	if _, err := a.authorize(context.Background(), "tok"); err == nil {
		t.Fatal("authorize succeeded with an invalid URL, want error")
	}
}
