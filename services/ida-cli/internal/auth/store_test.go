package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// redirectHome makes os.UserHomeDir() return dir for the duration of the test
// by setting HOME. Automatically restored via t.Cleanup.
func redirectHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
}

// writeFreshToken writes a valid access_token+refresh_token pair into
// ~/.config/ida/token.json under dir with mode 0600.
func writeFreshToken(t *testing.T, dir string, expiry time.Time, refreshToken string) {
	t.Helper()
	tokenDir := filepath.Join(dir, ".config", "ida")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tok := &oauth2.Token{
		AccessToken:  "access-tok",
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       expiry,
	}
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir, tokenFileName), data, tokenFileMode); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// NewTokenStore
// ---------------------------------------------------------------------------

func TestNewTokenStore_NoTokenFile_ReturnsNilToken(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatalf("NewTokenStore() error = %v", err)
	}
	if ts.Token() != nil {
		t.Errorf("Token() = %v; want nil when no file exists", ts.Token())
	}
}

func TestNewTokenStore_ExistingTokenFile_LoadsToken(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	expiry := time.Now().Add(1 * time.Hour)
	writeFreshToken(t, dir, expiry, "refresh-tok")

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatalf("NewTokenStore() error = %v", err)
	}
	tok := ts.Token()
	if tok == nil {
		t.Fatal("Token() = nil; want loaded token")
	}
	if tok.AccessToken != "access-tok" {
		t.Errorf("AccessToken = %q; want access-tok", tok.AccessToken)
	}
}

// TestNewTokenStore_StoresNonNilHTTPClient verifies that NewTokenStore always
// sets a non-nil httpClient, even when caFile and insecure are at their zero
// values (system-root defaults). This is the minimal structural invariant that
// proves the TLS plumbing path was executed.
func TestNewTokenStore_StoresNonNilHTTPClient(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatalf("NewTokenStore() error = %v", err)
	}
	if ts.HTTPClient() == nil {
		t.Error("NewTokenStore() must store a non-nil *http.Client")
	}
}

// TestNewTokenStore_WithCAFile_StoresHTTPClientWithCustomPool verifies that
// when a caFile is provided the resulting TokenStore holds a non-nil client
// (the custom CA is loaded without error).
func TestNewTokenStore_WithCAFile_StoresHTTPClientWithCustomPool(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	// Generate a self-signed CA and write it to a temp file.
	caPEM, _ := storeSelfSignedCA(t)
	caFile := storeTempCAFile(t, caPEM)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", caFile, false)
	if err != nil {
		t.Fatalf("NewTokenStore(caFile) error = %v", err)
	}
	if ts.HTTPClient() == nil {
		t.Error("NewTokenStore(caFile) must store a non-nil *http.Client")
	}
}

// TestNewTokenStore_BadCAFile_ReturnsError verifies that an invalid CA file
// causes NewTokenStore to return an error rather than silently ignoring it.
func TestNewTokenStore_BadCAFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	_, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "/nonexistent/ca.pem", false)
	if err == nil {
		t.Fatal("NewTokenStore with nonexistent caFile must return an error")
	}
}

// ---------------------------------------------------------------------------
// Save / Token
// ---------------------------------------------------------------------------

func TestSave_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}

	tok := &oauth2.Token{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	if err := ts.Save(tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Read back from disk.
	path := filepath.Join(dir, ".config", "ida", tokenFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var stored oauth2.Token
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if stored.AccessToken != "new-access" {
		t.Errorf("stored AccessToken = %q; want new-access", stored.AccessToken)
	}
}

func TestSave_FileMode0600(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	tok := &oauth2.Token{
		AccessToken: "tok",
		Expiry:      time.Now().Add(time.Hour),
	}
	if err := ts.Save(tok); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, ".config", "ida", tokenFileName)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != tokenFileMode {
		t.Errorf("file perm = %o; want %o", perm, tokenFileMode)
	}
}

// ---------------------------------------------------------------------------
// AccessToken — valid in-memory token
// ---------------------------------------------------------------------------

func TestAccessToken_ValidToken_ReturnsWithoutRefresh(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Inject a token that is valid well beyond the safety pad.
	tok := &oauth2.Token{
		AccessToken: "valid-access",
		Expiry:      time.Now().Add(10 * time.Minute),
	}
	ts.token = tok

	got, err := ts.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}
	if got != "valid-access" {
		t.Errorf("AccessToken() = %q; want valid-access", got)
	}
}

// ---------------------------------------------------------------------------
// AccessToken — no token stored
// ---------------------------------------------------------------------------

func TestAccessToken_NoToken_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// No token has been set.
	_, err = ts.AccessToken(context.Background())
	if err == nil {
		t.Fatal("AccessToken() expected error when no token stored, got nil")
	}
}

// ---------------------------------------------------------------------------
// AccessToken — expired token refreshed via mock token server
// ---------------------------------------------------------------------------

func TestAccessToken_ExpiredToken_RefreshesSuccessfully(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	// Stand up a mock Keycloak token endpoint that returns a new token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			http.NotFound(w, r)
			return
		}
		resp := map[string]any{
			"access_token":  "refreshed-access",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ts, err := NewTokenStore(srv.URL, "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Inject an expired token with a refresh token.
	ts.token = &oauth2.Token{
		AccessToken:  "expired-access",
		RefreshToken: "old-refresh",
		Expiry:       time.Now().Add(-5 * time.Minute), // already expired
	}

	got, err := ts.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}
	if got != "refreshed-access" {
		t.Errorf("AccessToken() = %q; want refreshed-access", got)
	}
	// Confirm in-memory token was updated.
	if ts.Token().AccessToken != "refreshed-access" {
		t.Errorf("in-memory token not updated after refresh")
	}
}

// TestAccessToken_ExpiredToken_RefreshOverTLS verifies that the token store
// correctly uses the injected TLS client to refresh against a TLS-only server
// when a CAFile is provided.
func TestAccessToken_ExpiredToken_RefreshOverTLS(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	// Generate a self-signed CA + server cert.
	caPEM, srvCert := storeSelfSignedCA(t)

	// Start a TLS-only mock token endpoint signed by our CA.
	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token":  "tls-refreshed",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "tls-refresh",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	defer srv.Close()

	caFile := storeTempCAFile(t, caPEM)

	ts, err := NewTokenStore(srv.URL, "ida-cli", caFile, false)
	if err != nil {
		t.Fatalf("NewTokenStore(caFile) error = %v", err)
	}

	// Inject an expired token so a refresh is triggered.
	ts.token = &oauth2.Token{
		AccessToken:  "expired-access",
		RefreshToken: "old-refresh",
		Expiry:       time.Now().Add(-5 * time.Minute),
	}

	got, err := ts.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("AccessToken() over TLS with custom CA error = %v", err)
	}
	if got != "tls-refreshed" {
		t.Errorf("AccessToken() = %q; want tls-refreshed", got)
	}
}

// TestAccessToken_ExpiredToken_RefreshOverTLS_FailsWithoutCA verifies the
// fail-closed behaviour: refreshing against a custom-CA TLS server FAILS when
// the CA is NOT provided (system roots don't trust the self-signed cert).
func TestAccessToken_ExpiredToken_RefreshOverTLS_FailsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	_, srvCert := storeSelfSignedCA(t)

	// TLS server using the self-signed cert — no CA given to the store.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "should-not-reach",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	defer srv.Close()

	// No caFile — system roots will not trust the self-signed cert.
	ts, err := NewTokenStore(srv.URL, "ida-cli", "", false)
	if err != nil {
		t.Fatalf("NewTokenStore() error = %v", err)
	}
	ts.token = &oauth2.Token{
		AccessToken:  "expired",
		RefreshToken: "bad",
		Expiry:       time.Now().Add(-5 * time.Minute),
	}

	_, err = ts.AccessToken(context.Background())
	if err == nil {
		t.Fatal("AccessToken() must fail when server CA is not trusted (fail-closed)")
	}
}

// ---------------------------------------------------------------------------
// load() — permission enforcement
// ---------------------------------------------------------------------------

// TestLoad_LoosePermissions_Rejected verifies that load() refuses to read the
// token when the file has group- or world-readable bits set.
func TestLoad_LoosePermissions_Rejected(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	expiry := time.Now().Add(1 * time.Hour)
	writeFreshToken(t, dir, expiry, "refresh-tok")

	// Widen the permissions to simulate a mis-configured file.
	tokenPath := filepath.Join(dir, ".config", "ida", tokenFileName)
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// load() is called by NewTokenStore; with loose perms it should have been
	// rejected, leaving ts.token as nil.
	if ts.Token() != nil {
		t.Errorf("Token() = %+v; want nil when file has loose permissions", ts.Token())
	}
}

// TestSave_PreexistingLoosePermissions_TightenedAfterSave verifies that save()
// tightens the mode even when the file already existed with loose permissions
// (os.WriteFile alone does not re-chmod pre-existing files on all platforms).
func TestSave_PreexistingLoosePermissions_TightenedAfterSave(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	// Create the directory and write a file with loose permissions first.
	tokenDir := filepath.Join(dir, ".config", "ida")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(tokenDir, tokenFileName)
	if err := os.WriteFile(tokenPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	ts, err := NewTokenStore("http://kc.example.com/realms/r", "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}

	tok := &oauth2.Token{
		AccessToken: "new-tok",
		Expiry:      time.Now().Add(time.Hour),
	}
	if err := ts.Save(tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	fi, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != tokenFileMode {
		t.Errorf("after Save on pre-existing loose file: perm = %04o; want %04o", perm, tokenFileMode)
	}
}

func TestAccessToken_ExpiredToken_RefreshFails_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	redirectHome(t, dir)

	// Mock server always returns 400 (refresh rejected).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	ts, err := NewTokenStore(srv.URL, "ida-cli", "", false)
	if err != nil {
		t.Fatal(err)
	}
	ts.token = &oauth2.Token{
		AccessToken:  "expired",
		RefreshToken: "bad-refresh",
		Expiry:       time.Now().Add(-1 * time.Minute),
	}

	_, err = ts.AccessToken(context.Background())
	if err == nil {
		t.Fatal("AccessToken() expected error when refresh is rejected, got nil")
	}
}

// ---------------------------------------------------------------------------
// TLS helper utilities (store_test-local; analogous to api/http_client_test.go)
// ---------------------------------------------------------------------------

// storeSelfSignedCA generates a self-signed CA certificate and a server cert
// signed by that CA. Returns (caPEM, serverTLSCert).
func storeSelfSignedCA(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "store-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}),
	)
	if err != nil {
		t.Fatalf("build server tls.Certificate: %v", err)
	}
	return caPEM, srvCert
}

// storeTempCAFile writes caPEM to a temp file and returns its path.
func storeTempCAFile(t *testing.T, caPEM []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatalf("create temp CA file: %v", err)
	}
	if _, err := f.Write(caPEM); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}
	f.Close()
	return f.Name()
}
