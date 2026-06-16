package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockDeviceServer returns an httptest.Server that implements the two
// Keycloak device-code endpoints. deviceCode and userCode are the values
// the server will return. pollResp controls what the token endpoint returns.
func mockDeviceServer(t *testing.T, deviceCode, userCode, accessToken string) *httptest.Server {
	t.Helper()
	// State: "pending" until a single poll, then we return the token.
	first := true

	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/auth/device", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Return device auth response.
		resp := map[string]any{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          "http://kc.example.com/activate",
			"verification_uri_complete": "http://kc.example.com/activate?user_code=" + userCode,
			"expires_in":                600,
			"interval":                  1, // poll every 1s
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if first {
			// First poll: still pending (authorization_pending).
			first = false
			http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
			return
		}
		// Second poll: access granted.
		resp := map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-value",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

// mockTLSDeviceServer is like mockDeviceServer but uses a TLS server
// signed by the provided tls.Certificate.
func mockTLSDeviceServer(t *testing.T, srvCert tls.Certificate, accessToken string) *httptest.Server {
	t.Helper()
	first := true

	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/auth/device", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"device_code":               "dc-tls",
			"user_code":                 "TTTT-1234",
			"verification_uri":          "https://kc.example.com/activate",
			"verification_uri_complete": "https://kc.example.com/activate?user_code=TTTT-1234",
			"expires_in":                600,
			"interval":                  1,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-tls",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	return srv
}

// TestLogin_HappyPath drives the device-code flow to completion against
// the mock server. The golang.org/x/oauth2 library polls in-process so
// we use a background context with a generous deadline.
func TestLogin_HappyPath(t *testing.T) {
	srv := mockDeviceServer(t, "DC-123", "WXYZ-1234", "happy-access-tok")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := DeviceFlowConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}

	tok, err := Login(ctx, cfg)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if tok == nil {
		t.Fatal("Login() returned nil token")
	}
	if tok.AccessToken != "happy-access-tok" {
		t.Errorf("AccessToken = %q; want happy-access-tok", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-value" {
		t.Errorf("RefreshToken = %q; want rt-value", tok.RefreshToken)
	}
}

// TestLogin_ContextCancelled verifies that cancelling the context stops the
// polling loop and returns an error.
func TestLogin_ContextCancelled(t *testing.T) {
	// Server always responds with authorization_pending so polling never ends.
	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/auth/device", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"device_code":               "dc",
			"user_code":                 "AAAA-BBBB",
			"verification_uri":          "http://kc.example.com/activate",
			"verification_uri_complete": "http://kc.example.com/activate?user_code=AAAA-BBBB",
			"expires_in":                600,
			"interval":                  1,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	cfg := DeviceFlowConfig{RealmURL: srv.URL, ClientID: "ida-cli"}
	_, err := Login(ctx, cfg)
	if err == nil {
		t.Fatal("Login() expected error when context is cancelled, got nil")
	}
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "timeout") {
		t.Logf("error message: %v (acceptable — context or timeout)", err)
	}
}

// TestLogin_DeviceAuthFails verifies that a bad device-auth endpoint
// (returns 500) propagates as an error.
func TestLogin_DeviceAuthFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DeviceFlowConfig{RealmURL: srv.URL, ClientID: "ida-cli"}
	_, err := Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("Login() expected error when device auth endpoint returns 500, got nil")
	}
}

// ---------------------------------------------------------------------------
// TLS-specific tests
// ---------------------------------------------------------------------------

// TestLogin_TLSServer_WithCAFile_Succeeds verifies that Login completes
// successfully against a TLS server when cfg.CAFile points to the server's CA.
func TestLogin_TLSServer_WithCAFile_Succeeds(t *testing.T) {
	caPEM, srvCert := storeSelfSignedCA(t)
	caFile := storeTempCAFile(t, caPEM)

	srv := mockTLSDeviceServer(t, srvCert, "tls-device-tok")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := DeviceFlowConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
		CAFile:   caFile,
	}

	tok, err := Login(ctx, cfg)
	if err != nil {
		t.Fatalf("Login() with CAFile error = %v", err)
	}
	if tok.AccessToken != "tls-device-tok" {
		t.Errorf("AccessToken = %q; want tls-device-tok", tok.AccessToken)
	}
}

// TestLogin_TLSServer_WithoutCAFile_Fails verifies the fail-closed path: Login
// MUST fail when the server uses a self-signed cert and no CA is provided.
func TestLogin_TLSServer_WithoutCAFile_Fails(t *testing.T) {
	_, srvCert := storeSelfSignedCA(t)

	srv := mockTLSDeviceServer(t, srvCert, "should-not-arrive")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No CAFile — system roots will not trust the self-signed cert.
	cfg := DeviceFlowConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}

	_, err := Login(ctx, cfg)
	if err == nil {
		t.Fatal("Login() must fail when server CA is not trusted (fail-closed)")
	}
}

// TestNewDeviceHTTPClient_NonNilForEmptyConfig verifies that the package-level
// helper builds a non-nil client even when both fields are at their zero values.
func TestNewDeviceHTTPClient_NonNilForEmptyConfig(t *testing.T) {
	client, err := newDeviceHTTPClient("", false)
	if err != nil {
		t.Fatalf("newDeviceHTTPClient('', false) error = %v", err)
	}
	if client == nil {
		t.Error("newDeviceHTTPClient must return a non-nil *http.Client")
	}
}
