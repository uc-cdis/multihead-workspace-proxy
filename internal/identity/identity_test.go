package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireCanonicalizesIdentity(t *testing.T) {
	var got Identity
	handler := Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		got, ok = FromContext(r.Context())
		if !ok {
			t.Fatal("identity missing from context")
		}
		if value := r.Header.Get("REMOTE_USER"); value != "alice" {
			t.Errorf("REMOTE_USER = %q, want alice", value)
		}
		if value := r.Header.Get("X-Gen3-User-ID"); value != "42" {
			t.Errorf("X-Gen3-User-ID = %q, want 42", value)
		}
		for _, header := range []string{"remote_user", "X-Remote-User", "KERNEL_USERNAME"} {
			if value := r.Header.Get(header); value != "alice" {
				t.Errorf("%s = %q, want alice", header, value)
			}
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Gen3-User-ID", "uid:42, alice")
	req.Header.Set("REMOTE_USER", "ignored")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got != (Identity{Username: "alice", UID: "42"}) {
		t.Fatalf("identity = %#v", got)
	}
}

func TestRequireFallsBackToRemoteUser(t *testing.T) {
	called := false
	handler := Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id, _ := FromContext(r.Context())
		if id.Username != "alice" {
			t.Errorf("username = %q, want alice", id.Username)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("REMOTE_USER", "alice")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("next handler was not called")
	}
}

func TestRequireRejectsMissingIdentity(t *testing.T) {
	called := false
	handler := Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if called {
		t.Fatal("next handler was called")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
