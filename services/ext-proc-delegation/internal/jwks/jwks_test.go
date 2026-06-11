package jwks_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
)

const (
	testIssuer = "https://keycloak.example/realms/agentic"
	testAud    = "mcp-gateway"
)

func newVerifier(t *testing.T, jwksURL string) *jwks.Verifier {
	t.Helper()
	v, err := jwks.New(jwks.Config{
		JWKSURL:          jwksURL,
		Issuer:           testIssuer,
		ExpectedAudience: testAud,
	})
	if err != nil {
		t.Fatalf("jwks.New: %v", err)
	}
	return v
}

func TestVerify_Good(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	tok := s.signToken(t, validClaims(testIssuer, "user-1", testAud),
		map[string]interface{}{"preferred_username": "alice", "groups": []string{"mcp-users"}})

	vt, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify good token: %v", err)
	}
	if vt.Sub != "user-1" {
		t.Errorf("Sub=%q want user-1", vt.Sub)
	}
	if vt.PreferredUsername != "alice" {
		t.Errorf("PreferredUsername=%q want alice", vt.PreferredUsername)
	}
	if len(vt.Groups) != 1 || vt.Groups[0] != "mcp-users" {
		t.Errorf("Groups=%v want [mcp-users]", vt.Groups)
	}
	if vt.Raw != tok {
		t.Error("Raw should be the verified token verbatim")
	}
}

func TestVerify_BadSignature(t *testing.T) {
	// Token signed by a DIFFERENT key than the JWKS advertises (same kid).
	advertised := newSigner(t, "key-1")
	attacker := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, advertised) })
	v := newVerifier(t, srv.URL)

	tok := attacker.signToken(t, validClaims(testIssuer, "user-1", testAud), nil)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for bad signature")
	}
}

func TestVerify_AlgNoneRejected(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	// Hand-craft an alg=none token (header.payload.) — must be rejected at parse.
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmV4YW1wbGUvcmVhbG1zL2FnZW50aWMifQ."
	if _, err := v.Verify(context.Background(), none); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	tok := s.signToken(t, validClaims("https://evil.example/realms/agentic", "user-1", testAud), nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for wrong issuer")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	tok := s.signToken(t, validClaims(testIssuer, "user-1", "some-other-aud"), nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for wrong audience")
	}
}

func TestVerify_Expired(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   testIssuer,
		Subject:  "user-1",
		Audience: jwt.Audience{testAud},
		Expiry:   jwt.NewNumericDate(now.Add(-10 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(now.Add(-20 * time.Minute)),
	}
	tok := s.signToken(t, claims, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for expired token")
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    testIssuer,
		Subject:   "user-1",
		Audience:  jwt.Audience{testAud},
		Expiry:    jwt.NewNumericDate(now.Add(30 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	tok := s.signToken(t, claims, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for not-yet-valid token")
	}
}

func TestVerify_EmptyToken(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)
	if _, err := v.Verify(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestVerify_EmptySubRejected(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	// Valid signature/iss/aud but no subject.
	tok := s.signToken(t, validClaims(testIssuer, "", testAud), nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected verification failure for empty sub")
	}
}

// TestVerify_UnknownKidRefreshes verifies that an unknown kid triggers a JWKS
// refresh (key rotation) and then succeeds once the new key is published.
func TestVerify_UnknownKidRefreshes(t *testing.T) {
	oldKey := newSigner(t, "key-old")
	newKey := newSigner(t, "key-new")

	// Server starts advertising only the old key; flip to the new key later.
	current := oldKey
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, current) })
	v := newVerifier(t, srv.URL)

	// Warm the cache with the old key.
	tokOld := oldKey.signToken(t, validClaims(testIssuer, "user-1", testAud), nil)
	if _, err := v.Verify(context.Background(), tokOld); err != nil {
		t.Fatalf("warm cache with old key: %v", err)
	}
	hitsAfterWarm := srv.hits

	// Rotate: server now advertises the new key, token signed by the new key.
	current = newKey
	tokNew := newKey.signToken(t, validClaims(testIssuer, "user-2", testAud), nil)
	vt, err := v.Verify(context.Background(), tokNew)
	if err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if vt.Sub != "user-2" {
		t.Errorf("Sub=%q want user-2", vt.Sub)
	}
	if srv.hits <= hitsAfterWarm {
		t.Error("expected a JWKS refresh on unknown kid")
	}
}

// TestVerify_CachesKeys ensures keys are cached within the TTL (no refetch per
// verification).
func TestVerify_CachesKeys(t *testing.T) {
	s := newSigner(t, "key-1")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v, err := jwks.New(jwks.Config{
		JWKSURL:          srv.URL,
		Issuer:           testIssuer,
		ExpectedAudience: testAud,
		TTL:              time.Hour,
	})
	if err != nil {
		t.Fatalf("jwks.New: %v", err)
	}

	tok := s.signToken(t, validClaims(testIssuer, "user-1", testAud), nil)
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if srv.hits != 1 {
		t.Errorf("expected exactly 1 JWKS fetch (cached), got %d", srv.hits)
	}
}

func TestNew_RequiresConfig(t *testing.T) {
	cases := []jwks.Config{
		{Issuer: testIssuer, ExpectedAudience: testAud},                 // missing URL
		{JWKSURL: "http://x", ExpectedAudience: testAud},                // missing issuer
		{JWKSURL: "http://x", Issuer: testIssuer},                       // missing audience
	}
	for i, c := range cases {
		if _, err := jwks.New(c); err == nil {
			t.Errorf("case %d: expected error for incomplete config", i)
		}
	}
}

func TestVerify_UnknownKidStillFailsClosed(t *testing.T) {
	// kid present in token but never in JWKS -> fail closed after refresh.
	s := newSigner(t, "key-1")
	other := newSigner(t, "key-2")
	srv := newJWKSServer(t, func() []byte { return jwkSet(t, s) })
	v := newVerifier(t, srv.URL)

	tok := other.signToken(t, validClaims(testIssuer, "user-1", testAud), nil)
	_, err := v.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("expected fail-closed for kid not in JWKS")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}
