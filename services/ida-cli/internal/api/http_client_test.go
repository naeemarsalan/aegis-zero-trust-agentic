package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewHTTPClient — system roots (no CA file, no insecure)
// ---------------------------------------------------------------------------

func TestNewHTTPClient_DefaultReturnsClient(t *testing.T) {
	hc, err := NewHTTPClient("", false, 5*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient('', false, ...) error = %v", err)
	}
	if hc == nil {
		t.Fatal("NewHTTPClient returned nil client")
	}
	if hc.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v; want 5s", hc.Timeout)
	}
}

// ---------------------------------------------------------------------------
// NewHTTPClient — insecure flag
// ---------------------------------------------------------------------------

func TestNewHTTPClient_InsecureTrue_SetsInsecureSkipVerify(t *testing.T) {
	hc, err := NewHTTPClient("", true, 5*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient insecure=true error = %v", err)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T; want *http.Transport", hc.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when insecure=true")
	}
}

func TestNewHTTPClient_InsecureFalse_DoesNotSetInsecureSkipVerify(t *testing.T) {
	hc, err := NewHTTPClient("", false, 5*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient insecure=false error = %v", err)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T; want *http.Transport", hc.Transport)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false when insecure=false")
	}
}

// TestNewHTTPClient_Insecure_CanReachTLSServer verifies that insecure=true
// allows connections to servers with self-signed certificates.
func TestNewHTTPClient_Insecure_CanReachTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hc, err := NewHTTPClient("", true, 5*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient error = %v", err)
	}
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s error = %v; want nil (insecure should allow self-signed)", srv.URL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// NewHTTPClient — caFile loading
// ---------------------------------------------------------------------------

// selfSignedCA generates a minimal self-signed CA certificate and returns the
// PEM-encoded certificate bytes and the tls.Certificate for use in a test server.
func selfSignedCA(t *testing.T) (caPEM []byte, serverCert tls.Certificate) {
	t.Helper()

	// Generate CA key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
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
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server key + cert signed by our CA.
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

	serverCert, err = tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}),
	)
	if err != nil {
		t.Fatalf("build server tls.Certificate: %v", err)
	}
	return caPEM, serverCert
}

func TestNewHTTPClient_CAFile_LoadsAndTrusts(t *testing.T) {
	caPEM, srvCert := selfSignedCA(t)

	// Start a TLS server using our test CA-signed cert.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	defer srv.Close()

	// Write the CA PEM to a temp file.
	caFile := writeTempPEM(t, caPEM)

	hc, err := NewHTTPClient(caFile, false, 5*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient(caFile) error = %v", err)
	}

	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with custom CA error = %v; want nil", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
}

func TestNewHTTPClient_CAFile_NotExist_ReturnsError(t *testing.T) {
	_, err := NewHTTPClient("/nonexistent/path/ca.pem", false, 5*time.Second)
	if err == nil {
		t.Fatal("NewHTTPClient with nonexistent caFile should return an error")
	}
}

func TestNewHTTPClient_CAFile_Empty_ReturnsError(t *testing.T) {
	// Write an empty file — no valid PEM certs.
	f, err := os.CreateTemp(t.TempDir(), "empty-ca-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()

	_, err = NewHTTPClient(f.Name(), false, 5*time.Second)
	if err == nil {
		t.Fatal("NewHTTPClient with empty caFile should return an error (no valid PEM)")
	}
}

func TestNewHTTPClient_CAFile_InvalidPEM_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.pem"
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad PEM: %v", err)
	}
	_, err := NewHTTPClient(path, false, 5*time.Second)
	if err == nil {
		t.Fatal("NewHTTPClient with non-PEM content should return an error")
	}
}

// writeTempPEM writes the given PEM bytes to a temp file and returns its path.
func writeTempPEM(t *testing.T, pem []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatalf("create temp PEM file: %v", err)
	}
	if _, err := f.Write(pem); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
	f.Close()
	return f.Name()
}
