package spire_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/spire"
)

const (
	testSpireIssuer = "https://spire-oidc.apps.ocp-dev.na-launch.com"
	testSpireAud    = "mcp-gateway"
	testTrustDomain = "spiffe://anaeem.na-launch.com/"
)

// --- helpers ---

func newRSASigner(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	jwk := jose.JSONWebKey{
		Key:       priv.Public(),
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return priv, jwk
}

func newECSigner(t *testing.T, kid string) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	jwk := jose.JSONWebKey{
		Key:       priv.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return priv, jwk
}

func serveJWKS(t *testing.T, keys ...jose.JSONWebKey) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: keys}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func validSpireClaims(sub string) jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		Issuer:    testSpireIssuer,
		Subject:   sub,
		Audience:  jwt.Audience{testSpireAud},
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
	}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.Claims, custom map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, opts)
	if err != nil {
		t.Fatalf("new rsa signer: %v", err)
	}
	tok, err := jwt.Signed(sig).Claims(claims).Claims(custom).Serialize()
	if err != nil {
		t.Fatalf("serialize rsa token: %v", err)
	}
	return tok
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims jwt.Claims, custom map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, opts)
	if err != nil {
		t.Fatalf("new ec signer: %v", err)
	}
	tok, err := jwt.Signed(sig).Claims(claims).Claims(custom).Serialize()
	if err != nil {
		t.Fatalf("serialize ec token: %v", err)
	}
	return tok
}

func newVerifier(t *testing.T, jwksURL string) *spire.Verifier {
	t.Helper()
	v, err := spire.New(jwks.Config{
		JWKSURL:          jwksURL,
		Issuer:           testSpireIssuer,
		ExpectedAudience: testSpireAud,
	})
	if err != nil {
		t.Fatalf("spire.New: %v", err)
	}
	return v
}

// --- sandbox sub-path: happy paths ---

// TestVerifySVID_RS256_SandboxSubPath verifies that a valid RS256 SVID with
// a sandbox UUID in the sub path produces the correct SandboxUID.
func TestVerifySVID_RS256_SandboxSubPath(t *testing.T) {
	priv, jwk := newRSASigner(t, "spire-rsa-1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	const uuid = "550e8400-e29b-41d4-a716-446655440000"
	sub := testTrustDomain + "ns/openshell/sandbox/" + uuid

	tok := signRS256(t, priv, "spire-rsa-1", validSpireClaims(sub), nil)

	claims, err := v.VerifySVID(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifySVID RS256 sandbox path: %v", err)
	}
	if claims.SpiffeID != sub {
		t.Errorf("SpiffeID=%q want %q", claims.SpiffeID, sub)
	}
	if claims.SandboxUID != uuid {
		t.Errorf("SandboxUID=%q want %q", claims.SandboxUID, uuid)
	}
	// SandboxNonce is always empty — real SVIDs cannot carry custom claims.
	if claims.SandboxNonce != "" {
		t.Errorf("SandboxNonce=%q want empty (vestigial field)", claims.SandboxNonce)
	}
}

// TestVerifySVID_ES256_SandboxSubPath verifies ES256-signed SVIDs are also accepted.
func TestVerifySVID_ES256_SandboxSubPath(t *testing.T) {
	priv, jwk := newECSigner(t, "spire-ec-1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	const uuid = "ec-uuid-abc-456"
	sub := testTrustDomain + "ns/openshell/sandbox/" + uuid

	tok := signES256(t, priv, "spire-ec-1", validSpireClaims(sub), nil)

	claims, err := v.VerifySVID(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifySVID ES256 sandbox path: %v", err)
	}
	if claims.SandboxUID != uuid {
		t.Errorf("SandboxUID=%q want %q", claims.SandboxUID, uuid)
	}
}

// TestVerifySVID_SandboxSubPath_NoCustomClaims confirms that even when the
// token carries no extra claims (as real SPIRE SVIDs don't), VerifySVID still
// extracts the UUID from the sub path successfully.
func TestVerifySVID_SandboxSubPath_NoCustomClaims(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	sub := testTrustDomain + "ns/openshell/sandbox/" + uuid

	// Sign with NO custom claims map at all — simulates real SPIRE behaviour.
	tok := signRS256(t, priv, "k1", validSpireClaims(sub), nil)

	claims, err := v.VerifySVID(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifySVID with no custom claims: %v", err)
	}
	if claims.SandboxUID != uuid {
		t.Errorf("SandboxUID=%q want %q", claims.SandboxUID, uuid)
	}
}

// --- sandbox sub-path: fail-closed paths ---

// TestVerifySVID_NoSandboxSegment_FailsClosed ensures a generic workload SVID
// (e.g. ns/agent-sandbox/sa/agent) without a "/sandbox/" segment is rejected.
func TestVerifySVID_NoSandboxSegment_FailsClosed(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	// This is a valid SPIFFE URI within the trust domain but has no /sandbox/ segment.
	sub := testTrustDomain + "ns/agent-sandbox/sa/agent"
	tok := signRS256(t, priv, "k1", validSpireClaims(sub), nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for sub without /sandbox/ segment — generic SVID must be rejected")
	}
	if !strings.Contains(err.Error(), "/sandbox/") {
		t.Errorf("expected error to mention /sandbox/, got: %v", err)
	}
}

// TestVerifySVID_EmptySandboxUUID_FailsClosed ensures a sub ending in
// "/sandbox/" with no UUID following it is rejected.
func TestVerifySVID_EmptySandboxUUID_FailsClosed(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	// Trailing slash with no UUID.
	sub := testTrustDomain + "ns/openshell/sandbox/"
	tok := signRS256(t, priv, "k1", validSpireClaims(sub), nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for empty sandbox UUID after /sandbox/")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error to mention 'empty', got: %v", err)
	}
}

// TestVerifySVID_WrongTrustDomain rejects SVIDs from a different trust domain.
func TestVerifySVID_WrongTrustDomain(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	// sub is a SPIFFE URI from a DIFFERENT trust domain (has /sandbox/ but wrong domain).
	tok := signRS256(t, priv, "k1",
		validSpireClaims("spiffe://evil.example.com/ns/openshell/sandbox/uid-abc"), nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for wrong trust domain")
	}
	if !strings.Contains(err.Error(), "trust domain") {
		t.Errorf("expected trust domain error, got: %v", err)
	}
}

// TestVerifySVID_ExpiredToken ensures expired tokens are rejected before path parsing.
func TestVerifySVID_ExpiredToken(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    testSpireIssuer,
		Subject:   testTrustDomain + "ns/openshell/sandbox/some-uuid",
		Audience:  jwt.Audience{testSpireAud},
		Expiry:    jwt.NewNumericDate(now.Add(-10 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now.Add(-20 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-20 * time.Minute)),
	}
	tok := signRS256(t, priv, "k1", claims, nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// TestVerifySVID_WrongIssuer ensures wrong issuer is rejected.
func TestVerifySVID_WrongIssuer(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	claims := validSpireClaims(testTrustDomain + "ns/openshell/sandbox/some-uuid")
	claims.Issuer = "https://evil-oidc.example.com"
	tok := signRS256(t, priv, "k1", claims, nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

// TestVerifySVID_WrongAudience ensures wrong audience is rejected.
func TestVerifySVID_WrongAudience(t *testing.T) {
	priv, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)

	claims := validSpireClaims(testTrustDomain + "ns/openshell/sandbox/some-uuid")
	claims.Audience = jwt.Audience{"wrong-aud"}
	tok := signRS256(t, priv, "k1", claims, nil)

	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

// TestVerifySVID_BadSignature ensures a token signed with the wrong key is rejected.
func TestVerifySVID_BadSignature(t *testing.T) {
	privA, jwkA := newRSASigner(t, "k1")
	privB, _ := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwkA)
	v := newVerifier(t, srv.URL)
	_ = privA

	tok := signRS256(t, privB, "k1",
		validSpireClaims(testTrustDomain+"ns/openshell/sandbox/some-uuid"), nil)
	_, err := v.VerifySVID(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

// --- IsSPIRESVID ---

func TestIsSPIRESVID_TrueForSpireToken(t *testing.T) {
	priv, _ := newRSASigner(t, "k1")
	tok := signRS256(t, priv, "k1",
		validSpireClaims(testTrustDomain+"ns/openshell/sandbox/some-uuid"), nil)

	if !spire.IsSPIRESVID(tok, testSpireIssuer) {
		t.Error("expected IsSPIRESVID=true for SPIRE-issued token")
	}
}

func TestIsSPIRESVID_FalseForKeycloakToken(t *testing.T) {
	priv, _ := newRSASigner(t, "k1")
	claims := jwt.Claims{
		Issuer:    "https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic",
		Subject:   "user-alice",
		Audience:  jwt.Audience{testSpireAud},
		Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}
	tok := signRS256(t, priv, "k1", claims, nil)

	if spire.IsSPIRESVID(tok, testSpireIssuer) {
		t.Error("expected IsSPIRESVID=false for Keycloak token")
	}
}

func TestIsSPIRESVID_FalseForEmpty(t *testing.T) {
	if spire.IsSPIRESVID("", testSpireIssuer) {
		t.Error("expected false for empty token")
	}
}

func TestIsSPIRESVID_FalseForGarbage(t *testing.T) {
	if spire.IsSPIRESVID("garbage", testSpireIssuer) {
		t.Error("expected false for single-part garbage")
	}
}

// TestIsSPIRESVID_ForgeryDoesNotBypassCrypto documents that a forged "iss"
// claim in the payload does not bypass the VerifySVID cryptographic check.
// The attacker can craft a token whose payload says iss=spire-oidc, but
// VerifySVID will reject it because the signature is invalid.
func TestIsSPIRESVID_ForgeryDoesNotBypassCrypto(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + testSpireIssuer + `","sub":"` + testTrustDomain +
			`ns/openshell/sandbox/forged-uid","aud":["mcp-gateway"],"exp":9999999999}`))
	forged := header + "." + payload + ".badsig"

	if !spire.IsSPIRESVID(forged, testSpireIssuer) {
		t.Log("IsSPIRESVID=false for forged token (routing evaded, crypto check would catch it)")
		return
	}

	// VerifySVID MUST reject it — the signature is invalid.
	_, jwk := newRSASigner(t, "k1")
	srv := serveJWKS(t, jwk)
	v := newVerifier(t, srv.URL)
	_, err := v.VerifySVID(context.Background(), forged)
	if err == nil {
		t.Fatal("SECURITY: VerifySVID accepted a forged token with bad signature")
	}
}
