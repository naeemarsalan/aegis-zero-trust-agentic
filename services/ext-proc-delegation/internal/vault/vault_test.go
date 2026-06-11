package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/vault"
)

// vaultServerStub is a mock Vault HTTP server for unit testing.
type vaultServerStub struct {
	loginCalls  atomic.Int32
	secretCalls atomic.Int32

	loginStatus  int
	secretStatus int
	secretData   map[string]interface{}
	loginToken   string
	loginTTL     int
}

func (v *vaultServerStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		v.loginCalls.Add(1)
		if v.loginStatus != 0 && v.loginStatus != http.StatusOK {
			http.Error(w, "login error", v.loginStatus)
			return
		}
		tok := v.loginToken
		if tok == "" {
			tok = "vault-client-token"
		}
		ttl := v.loginTTL
		if ttl == 0 {
			ttl = 300
		}
		resp := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   tok,
				"lease_duration": ttl,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		v.secretCalls.Add(1)
		if v.secretStatus != 0 && v.secretStatus != http.StatusOK {
			http.Error(w, "secret error", v.secretStatus)
			return
		}
		data := v.secretData
		if data == nil {
			data = map[string]interface{}{"api_key": "secret-value"}
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": data,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func newTestVaultClient(t *testing.T, stub *vaultServerStub, secretPfx string) *vault.TestableClient {
	t.Helper()
	srv := httptest.NewServer(stub.handler())
	t.Cleanup(srv.Close)
	return vault.NewTestableClient(srv.URL, "test-role", "vault", secretPfx, srv.Client())
}

func TestVault_FetchToolSecret_Success(t *testing.T) {
	stub := &vaultServerStub{
		secretData: map[string]interface{}{"api_key": "abc123"},
	}
	client := newTestVaultClient(t, stub, "secret/data/mcp-tools/")

	data, err := client.FetchToolSecret(context.Background(), "list-routes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, ok := data["api_key"]; !ok || v != "abc123" {
		t.Errorf("expected api_key=abc123, got %v", data)
	}
}

func TestVault_Login_Failure(t *testing.T) {
	stub := &vaultServerStub{loginStatus: http.StatusForbidden}
	client := newTestVaultClient(t, stub, "secret/data/mcp-tools/")

	_, err := client.FetchToolSecret(context.Background(), "tool")
	if err == nil {
		t.Fatal("expected error for login failure")
	}
}

func TestVault_SecretFetch_404(t *testing.T) {
	stub := &vaultServerStub{secretStatus: http.StatusNotFound}
	client := newTestVaultClient(t, stub, "secret/data/mcp-tools/")

	_, err := client.FetchToolSecret(context.Background(), "missing-tool")
	if err == nil {
		t.Fatal("expected error for 404 secret")
	}
}

func TestVault_TokenCache(t *testing.T) {
	stub := &vaultServerStub{loginTTL: 300}
	client := newTestVaultClient(t, stub, "secret/data/mcp-tools/")

	// First call should login.
	_, err := client.FetchToolSecret(context.Background(), "tool1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call should use cached token.
	_, err = client.FetchToolSecret(context.Background(), "tool2")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if stub.loginCalls.Load() != 1 {
		t.Errorf("expected 1 login (token cached), got %d", stub.loginCalls.Load())
	}
}

func TestVault_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	hc := &http.Client{Timeout: 1} // 1 nanosecond — always times out
	client := vault.NewTestableClient(srv.URL, "role", "vault", "secret/data/mcp-tools/", hc)

	_, err := client.FetchToolSecret(context.Background(), "tool")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
