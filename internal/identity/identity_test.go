package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeAuthorizer struct{ err error }

func (f fakeAuthorizer) authorize(context.Context, string) (Identity, error) {
	return Identity{Username: "user"}, f.err
}

// TestRequire checks the status Require returns for each outcome.
func TestRequire(t *testing.T) {
	tests := []struct {
		name       string
		authorizer authorizer
		token      string
		want       int
	}{
		{name: "allowed", authorizer: fakeAuthorizer{}, token: "tok", want: http.StatusOK},
		{name: "no authorizer", authorizer: nil, token: "tok", want: http.StatusForbidden},
		{name: "no token", authorizer: fakeAuthorizer{}, want: http.StatusUnauthorized},
		{name: "authorize fails", authorizer: fakeAuthorizer{err: errors.New("denied")}, token: "tok", want: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prev := defaultAuthorizer
			// set/overwrite the internal global defaultAuthorizer of identiy.go for this test's purpose:
			defaultAuthorizer = test.authorizer
			t.Cleanup(func() { defaultAuthorizer = prev })

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.token != "" {
				req.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: test.token})
			}
			rec := httptest.NewRecorder()

			Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

			if rec.Code != test.want {
				t.Errorf("status = %d, want %d", rec.Code, test.want)
			}
		})
	}
}

// TestStripCredentials checks that only the Fence token is removed: the
// access_token cookie and Bearer Authorization. Other cookies (Jupyter's
// _xsrf) and other Authorization schemes must survive.
func TestStripCredentials(t *testing.T) {
	tests := []struct {
		name       string
		cookies    []string // one entry per Cookie header line
		auth       string
		wantCookie string // "" means no Cookie header
		wantAuth   string
	}{
		{name: "only access_token", cookies: []string{"access_token=secret"}, wantCookie: ""},
		{name: "access_token among others", cookies: []string{"_xsrf=abc; access_token=secret; other=1"}, wantCookie: "_xsrf=abc; other=1"},
		{name: "split cookie lines (HTTP/2)", cookies: []string{"_xsrf=abc", "access_token=secret", "other=1"}, wantCookie: "_xsrf=abc; other=1"},
		{name: "similar names kept", cookies: []string{"access_token_x=1; xaccess_token=2"}, wantCookie: "access_token_x=1; xaccess_token=2"},
		{name: "bearer removed", auth: "Bearer secret", wantAuth: ""},
		{name: "bearer case-insensitive", auth: "bearer secret", wantAuth: ""},
		{name: "jupyter token kept", auth: "token jupyter", wantAuth: "token jupyter"},
		{name: "nothing to strip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := http.Header{}
			for _, c := range test.cookies {
				h.Add("Cookie", c)
			}
			if test.auth != "" {
				h.Set("Authorization", test.auth)
			}

			StripCredentials(h)

			if got := strings.Join(h.Values("Cookie"), "|"); got != test.wantCookie {
				t.Errorf("Cookie = %q, want %q", got, test.wantCookie)
			}
			if got := h.Get("Authorization"); got != test.wantAuth {
				t.Errorf("Authorization = %q, want %q", got, test.wantAuth)
			}
		})
	}
}

// TestRequireStripsCredentials checks that once Require has authorized the
// request, downstream handlers can no longer see (and so cannot log or
// forward) the user's token.
func TestRequireStripsCredentials(t *testing.T) {
	prev := defaultAuthorizer
	defaultAuthorizer = fakeAuthorizer{}
	t.Cleanup(func() { defaultAuthorizer = prev })

	for _, viaCookie := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if viaCookie {
			req.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "secret"})
			req.AddCookie(&http.Cookie{Name: "_xsrf", Value: "abc"})
		} else {
			req.Header.Set("Authorization", "Bearer secret")
		}

		var seen http.Header
		Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
		})).ServeHTTP(httptest.NewRecorder(), req)

		if seen == nil {
			t.Fatalf("viaCookie=%v: handler not called", viaCookie)
		}
		for key, vals := range seen {
			for _, v := range vals {
				if strings.Contains(v, "secret") {
					t.Errorf("viaCookie=%v: token leaked downstream in %s: %q", viaCookie, key, v)
				}
			}
		}
		if viaCookie && seen.Get("Cookie") != "_xsrf=abc" {
			t.Errorf("Cookie = %q, want other cookies preserved", seen.Get("Cookie"))
		}
		if seen.Get("REMOTE_USER") != "user" {
			t.Errorf("REMOTE_USER = %q, want %q", seen.Get("REMOTE_USER"), "user")
		}
	}
}
