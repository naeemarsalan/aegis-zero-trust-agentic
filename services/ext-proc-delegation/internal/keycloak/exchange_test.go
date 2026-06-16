package keycloak_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/keycloak"
)

func writeSecretFile(t *testing.T, secret string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(f, []byte(secret), 0600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return f
}

func TestExchange_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			http.Error(w, "wrong grant_type", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"downstream-tok","token_type":"bearer"}`))
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "my-secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "client-id", secretFile, srv.Client())

	tok, err := client.Exchange(context.Background(), "caller-jwt", "mcp-downstream")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "downstream-tok" {
		t.Errorf("token=%q want downstream-tok", tok)
	}
}

func TestExchange_401_NoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "cid", secretFile, srv.Client())

	_, err := client.Exchange(context.Background(), "tok", "aud")
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 call for 401, got %d", calls.Load())
	}
}

func TestExchange_5xx_Retry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"retry-tok"}`))
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "cid", secretFile, srv.Client())

	tok, err := client.Exchange(context.Background(), "tok", "aud")
	if err != nil {
		t.Fatalf("expected success after retry; got: %v", err)
	}
	if tok != "retry-tok" {
		t.Errorf("token=%q want retry-tok", tok)
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 calls for 5xx retry, got %d", calls.Load())
	}
}

func TestExchange_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until client disconnects.
		<-r.Context().Done()
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "secret")

	// Use a client with a very short timeout.
	hc := &http.Client{Timeout: 1} // 1 nanosecond — will always time out
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "cid", secretFile, hc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := client.Exchange(ctx, "tok", "aud")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestExchange_LegacyMode(t *testing.T) {
	var capturedForm map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = map[string]string{
			"grant_type":       r.FormValue("grant_type"),
			"requested_subject": r.FormValue("requested_subject"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"legacy-tok"}`))
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeLegacy, "cid", secretFile, srv.Client())

	tok, err := client.Exchange(context.Background(), "caller-tok", "aud")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "legacy-tok" {
		t.Errorf("token=%q want legacy-tok", tok)
	}
	if capturedForm["grant_type"] != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type=%q", capturedForm["grant_type"])
	}
}

func TestExchange_MissingSecretFile(t *testing.T) {
	client := keycloak.NewClientWithHTTP("http://localhost", config.ModeStandard, "cid", "/nonexistent/secret", http.DefaultClient)
	_, err := client.Exchange(context.Background(), "tok", "aud")
	if err == nil {
		t.Fatal("expected error for missing secret file")
	}
}

// TestExchangeOnBehalf_HappyPath verifies that ExchangeOnBehalf sends
// requested_subject=user and NO subject_token to Keycloak.
func TestExchangeOnBehalf_HappyPath(t *testing.T) {
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		capturedForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"on-behalf-tok","token_type":"bearer"}`))
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "my-secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "client-id", secretFile, srv.Client())

	tok, err := client.ExchangeOnBehalf(context.Background(), "arsalan", "mcp-downstream")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "on-behalf-tok" {
		t.Errorf("token=%q want on-behalf-tok", tok)
	}
	// Verify the form has requested_subject but NO subject_token.
	if capturedForm.Get("requested_subject") != "arsalan" {
		t.Errorf("requested_subject=%q want arsalan", capturedForm.Get("requested_subject"))
	}
	if capturedForm.Get("subject_token") != "" {
		t.Errorf("subject_token must be absent in on-behalf exchange, got %q", capturedForm.Get("subject_token"))
	}
	if capturedForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type=%q want token-exchange", capturedForm.Get("grant_type"))
	}
}

// TestExchangeOnBehalf_EmptyUser_Errors ensures an empty user is rejected
// before any network call.
func TestExchangeOnBehalf_EmptyUser_Errors(t *testing.T) {
	secretFile := writeSecretFile(t, "secret")
	client := keycloak.NewClientWithHTTP("http://localhost", config.ModeStandard, "cid", secretFile, http.DefaultClient)
	_, err := client.ExchangeOnBehalf(context.Background(), "", "mcp-downstream")
	if err == nil {
		t.Fatal("expected error for empty user")
	}
}

// TestExchangeOnBehalf_5xx_Retry verifies retry on 5xx.
func TestExchangeOnBehalf_5xx_Retry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"retry-on-behalf-tok"}`))
	}))
	defer srv.Close()

	secretFile := writeSecretFile(t, "secret")
	client := keycloak.NewClientWithHTTP(srv.URL, config.ModeStandard, "cid", secretFile, srv.Client())

	tok, err := client.ExchangeOnBehalf(context.Background(), "arsalan", "mcp-downstream")
	if err != nil {
		t.Fatalf("expected success after retry; got: %v", err)
	}
	if tok != "retry-on-behalf-tok" {
		t.Errorf("token=%q want retry-on-behalf-tok", tok)
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 calls for 5xx retry, got %d", calls.Load())
	}
}
