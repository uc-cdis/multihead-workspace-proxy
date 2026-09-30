package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://example.org/user"

// fence serves a JWKS and signs access tokens like fence does.
type fence struct {
	t      *testing.T
	server *httptest.Server

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

func newFence(t *testing.T) *fence {
	f := &fence{t: t, keys: map[string]*rsa.PrivateKey{}}
	f.addKey("key-1")
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		type jwk struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		var set struct {
			Keys []jwk `json:"keys"`
		}
		for kid, k := range f.keys {
			set.Keys = append(set.Keys, jwk{
				Kty: "RSA",
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fence) addKey(kid string) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.keys[kid] = k
	f.mu.Unlock()
	return k
}

func (f *fence) verifier() *Verifier {
	return NewVerifier(f.server.URL, testIssuer)
}

func accessClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":     testIssuer,
		"sub":     "42",
		"pur":     "access",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"context": map[string]any{"user": map[string]any{"name": "alice"}},
	}
}

func (f *fence) sign(kid string, claims jwt.MapClaims) string {
	f.mu.Lock()
	key := f.keys[kid]
	f.mu.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func serve(v *Verifier, req *http.Request) (Identity, http.Header, int) {
	var got Identity
	var headers http.Header
	handler := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = FromContext(r.Context())
		headers = r.Header.Clone()
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return got, headers, recorder.Code
}

func requestWithCookie(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: token})
	return req
}

func TestRequireAcceptsAccessTokenCookie(t *testing.T) {
	f := newFence(t)
	req := requestWithCookie(f.sign("key-1", accessClaims()))
	// Client-supplied identity headers must be overwritten with the token's identity.
	req.Header.Set("X-Gen3-User-ID", "uid:1, mallory")
	req.Header.Set("REMOTE_USER", "mallory")

	got, headers, code := serve(f.verifier(), req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
	if got != (Identity{Username: "alice", UID: "42"}) {
		t.Fatalf("identity = %#v", got)
	}
	if value := headers.Get("X-Gen3-User-ID"); value != "42" {
		t.Errorf("X-Gen3-User-ID = %q, want 42", value)
	}
	for _, header := range []string{"REMOTE_USER", "remote_user", "X-Remote-User", "KERNEL_USERNAME"} {
		if value := headers.Get(header); value != "alice" {
			t.Errorf("%s = %q, want alice", header, value)
		}
	}
}

func TestRequireAcceptsBearerToken(t *testing.T) {
	f := newFence(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+f.sign("key-1", accessClaims()))

	got, _, code := serve(f.verifier(), req)
	if code != http.StatusOK || got.Username != "alice" {
		t.Fatalf("status = %d, identity = %#v", code, got)
	}
}

func TestRequireRefetchesJWKSForRotatedKey(t *testing.T) {
	f := newFence(t)
	v := f.verifier()
	if _, _, code := serve(v, requestWithCookie(f.sign("key-1", accessClaims()))); code != http.StatusOK {
		t.Fatalf("status = %d before rotation", code)
	}

	f.addKey("key-2")
	v.fetchedAt = time.Time{} // skip the refresh rate limit
	if _, _, code := serve(v, requestWithCookie(f.sign("key-2", accessClaims()))); code != http.StatusOK {
		t.Fatalf("status = %d after rotation", code)
	}
}

func TestRequireRejectsInvalidTokens(t *testing.T) {
	f := newFence(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims())
	forged.Header["kid"] = "key-1"
	forgedToken, _ := forged.SignedString(other)

	unsigned, _ := jwt.NewWithClaims(jwt.SigningMethodNone, accessClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)

	with := func(key string, value any) jwt.MapClaims {
		c := accessClaims()
		if value == nil {
			delete(c, key)
		} else {
			c[key] = value
		}
		return c
	}

	tests := map[string]*http.Request{
		"no token":         httptest.NewRequest(http.MethodGet, "/", nil),
		"forged signature": requestWithCookie(forgedToken),
		"alg none":         requestWithCookie(unsigned),
		"malformed":        requestWithCookie("not-a-jwt"),
		"expired":          requestWithCookie(f.sign("key-1", with("exp", time.Now().Add(-time.Minute).Unix()))),
		"missing exp":      requestWithCookie(f.sign("key-1", with("exp", nil))),
		"wrong issuer":     requestWithCookie(f.sign("key-1", with("iss", "https://evil.example/user"))),
		"refresh token":    requestWithCookie(f.sign("key-1", with("pur", "refresh"))),
		"missing username": requestWithCookie(f.sign("key-1", with("context", map[string]any{}))),
		"header-only spoof": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Gen3-User-ID", "uid:42, alice")
			return r
		}(),
		"non-bearer scheme": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", "Basic "+f.sign("key-1", accessClaims()))
			return r
		}(),
	}
	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, code := serve(f.verifier(), req)
			if code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", code, http.StatusUnauthorized)
			}
		})
	}
}
