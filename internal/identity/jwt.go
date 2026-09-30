package identity

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenCookie is the cookie in which the Gen3 portal stores the fence access token.
const AccessTokenCookie = "access_token"

// jwksRefreshInterval bounds how often an unknown key ID can trigger a JWKS refetch.
const jwksRefreshInterval = 30 * time.Second

// fenceClaims is the subset of fence access token claims used to derive an Identity.
type fenceClaims struct {
	jwt.RegisteredClaims
	Purpose string `json:"pur"`
	Context struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	} `json:"context"`
}

// Verifier validates fence access tokens against fence's published JWKS.
type Verifier struct {
	jwksURL string
	issuer  string
	client  *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchMu   sync.Mutex
	fetchedAt time.Time
}

// NewVerifier returns a Verifier that loads signing keys from jwksURL. If issuer
// is non-empty, tokens must carry a matching iss claim.
func NewVerifier(jwksURL, issuer string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		issuer:  issuer,
		client:  &http.Client{Timeout: 5 * time.Second},
		keys:    map[string]*rsa.PublicKey{},
	}
}

// Require authenticates the request from the access_token cookie (or an
// Authorization bearer token), stores the identity in the request context and
// overwrites the upstream identity headers with the verified values.
func (v *Verifier) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := tokenFromRequest(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := v.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Replace client-supplied identity headers before any handler can forward them.
		SetUpstreamHeaders(r.Header, id)
		ctx := context.WithValue(r.Context(), contextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Verify checks the token signature, expiry, issuer and purpose and returns the
// identity it asserts.
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}

	var claims fenceClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	}, opts...)
	if err != nil {
		return Identity{}, err
	}
	if claims.Purpose != "access" {
		return Identity{}, fmt.Errorf("token purpose %q is not access", claims.Purpose)
	}

	id := Identity{
		Username: strings.TrimSpace(claims.Context.User.Name),
		UID:      strings.TrimSpace(claims.Subject),
	}
	if id.Username == "" {
		return Identity{}, errors.New("token has no username")
	}
	return id, nil
}

func tokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(AccessTokenCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(token)
	}
	return ""
}

// key returns the signing key for kid, refetching the JWKS when kid is unknown.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if k := v.cachedKey(kid); k != nil {
		return k, nil
	}

	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	// Another request may have refreshed the keys while we waited.
	if k := v.cachedKey(kid); k != nil {
		return k, nil
	}
	if time.Since(v.fetchedAt) < jwksRefreshInterval {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}

	keys, err := v.fetchJWKS(ctx)
	v.fetchedAt = time.Now()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()

	if k := v.cachedKey(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Verifier) cachedKey(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

func (v *Verifier) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	}
	return keys, nil
}
