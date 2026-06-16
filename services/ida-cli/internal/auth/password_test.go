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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// passwordTokenServer builds an httptest.Server that accepts ROPC token
// requests and returns the supplied response payload with the given status.
func passwordTokenServer(t *testing.T, statusCode int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Verify grant_type without logging credential fields.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "password" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(payload)
	}))
}

// passwordTLSTokenServer builds an httptest TLS server using the provided
// tls.Certificate that accepts ROPC token requests.
func passwordTLSTokenServer(t *testing.T, srvCert tls.Certificate, payload any) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(payload)
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	return srv
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_HappyPath — valid credentials, server returns 200.
// ---------------------------------------------------------------------------

func TestPasswordLogin_HappyPath(t *testing.T) {
	srv := passwordTokenServer(t, http.StatusOK, map[string]any{
		"access_token":  "at-abc123",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "rt-xyz789",
		"scope":         "openid profile",
	})
	defer srv.Close()

	cfg := PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}

	result, err := PasswordLogin(context.Background(), cfg, "alice", "s3cr3t")
	if err != nil {
		t.Fatalf("PasswordLogin() error = %v", err)
	}
	if result == nil {
		t.Fatal("PasswordLogin() returned nil result")
	}
	if result.AccessToken != "at-abc123" {
		t.Errorf("AccessToken = %q; want at-abc123", result.AccessToken)
	}
	if result.RefreshToken != "rt-xyz789" {
		t.Errorf("RefreshToken = %q; want rt-xyz789", result.RefreshToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType = %q; want Bearer", result.TokenType)
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_ExpiryComputedFromExpiresIn
// ---------------------------------------------------------------------------

func TestPasswordLogin_ExpiryComputedFromExpiresIn(t *testing.T) {
	srv := passwordTokenServer(t, http.StatusOK, map[string]any{
		"access_token": "tok",
		"expires_in":   7200,
		"token_type":   "Bearer",
	})
	defer srv.Close()

	before := time.Now()
	result, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "bob", "pass")
	after := time.Now()

	if err != nil {
		t.Fatalf("PasswordLogin() error = %v", err)
	}

	want := 7200 * time.Second
	// Allow 2s of clock skew.
	lower := before.Add(want - 2*time.Second)
	upper := after.Add(want + 2*time.Second)
	if result.Expiry.Before(lower) || result.Expiry.After(upper) {
		t.Errorf("Expiry = %v; want ~%v from now", result.Expiry, want)
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_ClientSecret — secret included when non-empty.
// ---------------------------------------------------------------------------

func TestPasswordLogin_ClientSecret_IncludedInRequest(t *testing.T) {
	var receivedSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedSecret = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL:     srv.URL,
		ClientID:     "ida-cli",
		ClientSecret: "super-secret",
	}, "carol", "pw")
	if err != nil {
		t.Fatalf("PasswordLogin() error = %v", err)
	}
	if receivedSecret != "super-secret" {
		t.Errorf("client_secret in request = %q; want super-secret", receivedSecret)
	}
}

func TestPasswordLogin_NoClientSecret_NotInRequest(t *testing.T) {
	var secretPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, secretPresent = r.Form["client_secret"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
		// ClientSecret intentionally omitted
	}, "dave", "pw")
	if err != nil {
		t.Fatalf("PasswordLogin() error = %v", err)
	}
	if secretPresent {
		t.Error("client_secret must not be sent when ClientSecret is empty")
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_InvalidCredentials — Keycloak returns 401.
// ---------------------------------------------------------------------------

func TestPasswordLogin_InvalidCredentials_ReturnsError(t *testing.T) {
	srv := passwordTokenServer(t, http.StatusUnauthorized, map[string]any{
		"error":             "invalid_grant",
		"error_description": "Invalid user credentials",
	})
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "alice", "wrongpass")
	if err == nil {
		t.Fatal("PasswordLogin() must return error on 401")
	}
	// The error must not echo back the password or the raw error_description
	// value verbatim in a security-visible way; but the test verifies the error
	// is non-nil.  We do check that it contains the error code for usability.
	if !strings.Contains(err.Error(), "invalid_grant") &&
		!strings.Contains(err.Error(), "Invalid user credentials") &&
		!strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q; expected it to mention the failure reason", err)
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_ServerDown — connection refused.
// ---------------------------------------------------------------------------

func TestPasswordLogin_ServerDown_ReturnsError(t *testing.T) {
	// Use an address that is certain to be unreachable within the test.
	cfg := PasswordGrantConfig{
		RealmURL: "http://127.0.0.1:1", // port 1 is always refused
		ClientID: "ida-cli",
	}
	_, err := PasswordLogin(context.Background(), cfg, "user", "pw")
	if err == nil {
		t.Fatal("PasswordLogin() must return error when server is unreachable")
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_MalformedResponse — server returns garbage JSON.
// ---------------------------------------------------------------------------

func TestPasswordLogin_MalformedResponse_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "user", "pw")
	if err == nil {
		t.Fatal("PasswordLogin() must return error on malformed JSON response")
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_MissingAccessToken — server returns 200 but no token.
// ---------------------------------------------------------------------------

func TestPasswordLogin_MissingAccessToken_ReturnsError(t *testing.T) {
	srv := passwordTokenServer(t, http.StatusOK, map[string]any{
		// access_token deliberately absent
		"token_type": "Bearer",
		"expires_in": 3600,
	})
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "user", "pw")
	if err == nil {
		t.Fatal("PasswordLogin() must return error when access_token is absent")
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_ContextCancelled — cancelled ctx propagates.
// ---------------------------------------------------------------------------

func TestPasswordLogin_ContextCancelled_ReturnsError(t *testing.T) {
	// Slow server — takes longer than the cancelled context allows.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until client disconnects.
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err := PasswordLogin(ctx, PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "user", "pw")
	if err == nil {
		t.Fatal("PasswordLogin() must return error when context is cancelled")
	}
}

// ---------------------------------------------------------------------------
// TestPasswordLogin_ContentTypeSet — verifies request has correct Content-Type.
// ---------------------------------------------------------------------------

func TestPasswordLogin_ContentTypeSet(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
	}, "user", "pw")
	if err != nil {
		t.Fatalf("PasswordLogin() error = %v", err)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q; want application/x-www-form-urlencoded", gotCT)
	}
}

// ---------------------------------------------------------------------------
// TLS-specific tests
// ---------------------------------------------------------------------------

// TestPasswordLogin_TLSServer_WithCAFile_Succeeds verifies that PasswordLogin
// succeeds against a TLS server when cfg.CAFile points to that server's CA.
func TestPasswordLogin_TLSServer_WithCAFile_Succeeds(t *testing.T) {
	caPEM, srvCert := storeSelfSignedCA(t)
	caFile := storeTempCAFile(t, caPEM)

	srv := passwordTLSTokenServer(t, srvCert, map[string]any{
		"access_token":  "tls-at-abc",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "tls-rt-xyz",
	})
	defer srv.Close()

	result, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
		CAFile:   caFile,
	}, "alice", "s3cr3t")
	if err != nil {
		t.Fatalf("PasswordLogin() with CAFile against TLS server error = %v", err)
	}
	if result.AccessToken != "tls-at-abc" {
		t.Errorf("AccessToken = %q; want tls-at-abc", result.AccessToken)
	}
}

// TestPasswordLogin_TLSServer_WithoutCAFile_Fails verifies fail-closed
// behaviour: PasswordLogin MUST fail when the server uses a self-signed cert
// and no CA file is provided (system roots do not trust the cert).
func TestPasswordLogin_TLSServer_WithoutCAFile_Fails(t *testing.T) {
	_, srvCert := storeSelfSignedCA(t)

	srv := passwordTLSTokenServer(t, srvCert, map[string]any{
		"access_token": "should-not-reach",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
	defer srv.Close()

	_, err := PasswordLogin(context.Background(), PasswordGrantConfig{
		RealmURL: srv.URL,
		ClientID: "ida-cli",
		// No CAFile — system roots should not trust the self-signed cert.
	}, "alice", "pw")
	if err == nil {
		t.Fatal("PasswordLogin() must fail when server CA is not trusted (fail-closed)")
	}
}
