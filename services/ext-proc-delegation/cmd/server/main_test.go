package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
)

// In the default case buildSpireHTTPClient now uses system root CAs (RootCAs:
// nil), so no workload API socket is needed to exercise that path. The two
// explicit-config branches (insecure + CA file) and the default branch are all
// covered by unit tests below without any live cluster dependency.

// selfSignedCA generates a minimal self-signed CA certificate and returns
// both the DER bytes and the parsed *x509.Certificate.
func selfSignedCA(t *testing.T) (derBytes []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return der, parsed
}

// writePEMFile writes a PEM-encoded certificate to a temp file and returns
// the path. The file is automatically cleaned up when t ends.
func writePEMFile(t *testing.T, derBytes []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create PEM file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("encode PEM: %v", err)
	}
	return path
}

// TestBuildSpireHTTPClient_Insecure verifies that SPIRE_TLS_INSECURE=true
// produces a client with InsecureSkipVerify set and does not fail-close.
func TestBuildSpireHTTPClient_Insecure(t *testing.T) {
	cfg := &config.Config{SpireTLSInsecure: true}
	client, err := buildSpireHTTPClient(cfg, nil) // src unused in insecure branch
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil http.Client")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify { //nolint:gosec // test assertion only
		t.Error("expected InsecureSkipVerify=true in insecure mode")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", client.Timeout)
	}
}

// TestBuildSpireHTTPClient_CAFile_HappyPath verifies that a valid PEM CA file
// produces a client pinned to that CA (not system roots, not insecure).
func TestBuildSpireHTTPClient_CAFile_HappyPath(t *testing.T) {
	der, _ := selfSignedCA(t)
	caPath := writePEMFile(t, der)

	cfg := &config.Config{SpireCAFile: caPath}
	client, err := buildSpireHTTPClient(cfg, nil) // src unused in CA-file branch
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil http.Client")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	tlsCfg := tr.TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if tlsCfg.InsecureSkipVerify { //nolint:gosec // test assertion only
		t.Error("InsecureSkipVerify must be false in CA-file mode")
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs pool in CA-file mode")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS1.2, got %v", tlsCfg.MinVersion)
	}
}

// TestBuildSpireHTTPClient_CAFile_Missing verifies that a non-existent CA file
// causes a fail-closed error (not a silent fall-through to system roots).
func TestBuildSpireHTTPClient_CAFile_Missing(t *testing.T) {
	cfg := &config.Config{SpireCAFile: "/nonexistent/path/ca.pem"}
	client, err := buildSpireHTTPClient(cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing CA file, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

// TestBuildSpireHTTPClient_CAFile_InvalidPEM verifies that a file containing
// no valid PEM certificates causes a fail-closed error.
func TestBuildSpireHTTPClient_CAFile_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a valid pem block\n"), 0o600); err != nil {
		t.Fatalf("write bad PEM: %v", err)
	}

	cfg := &config.Config{SpireCAFile: badPath}
	client, err := buildSpireHTTPClient(cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

// TestBuildSpireHTTPClient_Default_SystemRoots verifies that when neither
// SPIRE_TLS_INSECURE nor SPIRE_CA_FILE is set, the returned client uses
// system root CAs (RootCAs == nil) with InsecureSkipVerify == false and
// MinVersion == TLS 1.2. This is the correct configuration for the LE-fronted
// OpenShift reencrypt Route (*.apps.anaeem.na-launch.com). No workload API
// socket is required; src may be nil.
func TestBuildSpireHTTPClient_Default_SystemRoots(t *testing.T) {
	cfg := &config.Config{} // neither SpireTLSInsecure nor SpireCAFile set
	client, err := buildSpireHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error in default branch: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil http.Client")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	tlsCfg := tr.TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLSClientConfig in default branch")
	}
	if tlsCfg.InsecureSkipVerify { //nolint:gosec // test assertion only
		t.Error("InsecureSkipVerify must be false in default (system-roots) mode")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("RootCAs must be nil in default mode (system roots via Go TLS default)")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS1.2, got %v", tlsCfg.MinVersion)
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", client.Timeout)
	}
}

// TestBuildSpireHTTPClient_InsecureTakesPrecedenceOverCAFile verifies that
// SpireTLSInsecure=true wins even if SpireCAFile is also set, ensuring the
// switch-case ordering is intentional and tested.
func TestBuildSpireHTTPClient_InsecureTakesPrecedenceOverCAFile(t *testing.T) {
	der, _ := selfSignedCA(t)
	caPath := writePEMFile(t, der)

	cfg := &config.Config{SpireTLSInsecure: true, SpireCAFile: caPath}
	client, err := buildSpireHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := client.Transport.(*http.Transport)
	if !tr.TLSClientConfig.InsecureSkipVerify { //nolint:gosec // test assertion only
		t.Error("expected InsecureSkipVerify=true: insecure flag must take precedence over CA file")
	}
}
