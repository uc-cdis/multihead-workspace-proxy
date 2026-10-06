package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
