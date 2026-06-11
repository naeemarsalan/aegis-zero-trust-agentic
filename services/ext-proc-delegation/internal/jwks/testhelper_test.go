package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// signer bundles an RSA key pair and its kid for signing test tokens and
// serving the matching JWKS.
type signer struct {
	priv *rsa.PrivateKey
	kid  string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &signer{priv: priv, kid: kid}
}

// jwkSet returns the public JWKS JSON for this signer (plus any extras).
func jwkSet(t *testing.T, signers ...*signer) []byte {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for _, s := range signers {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       s.priv.Public(),
			KeyID:     s.kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// jwksServer serves the given JWKS bytes and counts requests so tests can
// assert caching / refresh behavior.
type jwksServer struct {
	*httptest.Server
	hits int
}

func newJWKSServer(t *testing.T, body func() []byte) *jwksServer {
	t.Helper()
	js := &jwksServer{}
	js.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body())
	}))
	t.Cleanup(js.Close)
	return js
}

// signToken signs a JWT with the signer's key and kid.
func (s *signer) signToken(t *testing.T, claims jwt.Claims, custom map[string]interface{}) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.priv}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	tok, err := jwt.Signed(sig).Claims(claims).Claims(custom).Serialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return tok
}

// validClaims builds a set of standard claims valid at the current time.
func validClaims(iss, sub, aud string) jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  jwt.Audience{aud},
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
	}
}
