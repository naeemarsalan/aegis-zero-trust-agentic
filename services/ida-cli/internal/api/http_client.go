package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// NewHTTPClient builds an *http.Client with TLS settings controlled by caFile
// and insecure.
//
//   - If caFile is non-empty the PEM bundle is loaded and appended to a clone of
//     the system cert pool. An error is returned if the file cannot be read or
//     contains no valid PEM certificates.
//   - If insecure is true, TLS certificate verification is disabled. A one-time
//     slog.Warn is emitted so the condition is never silent in logs. This flag
//     MUST only be set in PoC/dev environments; it is false by default.
//   - If neither flag is set the client uses the system cert pool with full TLS
//     verification (the safe default).
//
// The provided timeout is applied to the http.Client.Timeout field and governs
// the full round-trip duration of each request.
func NewHTTPClient(caFile string, insecure bool, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("api: load CA file %q: %w", caFile, err)
		}
		tlsCfg.RootCAs = pool
	}

	if insecure {
		// Single, non-repeating warning so the operator is aware.
		slog.Warn("TLS verification disabled — PoC only")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional PoC escape hatch; gated by explicit config
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// loadCertPool reads the PEM file at path and appends its certificates to a
// clone of the system cert pool. An error is returned if the file is unreadable
// or if no certificates could be parsed from it.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		// On some platforms (e.g. Windows) SystemCertPool may fail; fall back to
		// an empty pool so the custom CA can still be used.
		pool = x509.NewCertPool()
	}

	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", path)
	}
	return pool, nil
}
