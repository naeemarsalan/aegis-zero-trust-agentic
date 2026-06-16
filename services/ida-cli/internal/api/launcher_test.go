package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validLaunchRequest() LaunchRequest {
	return LaunchRequest{
		Goal:         "Deploy service",
		Capabilities: []string{"echo"},
		Mode:         "task",
		Scope:        "read-only",
		UserRef:      "alice",
		Confirmed:    true,
		TTLMinutes:   60,
	}
}

// serveLaunch sets up an httptest.Server whose /launch endpoint returns the
// given status code and body JSON. Use status == 0 to close the server
// immediately (to simulate a network error).
func serveLaunch(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/launch" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
}

// ---------------------------------------------------------------------------
// NewLauncherClient
// ---------------------------------------------------------------------------

func TestNewLauncherClient_NotNil(t *testing.T) {
	c, err := NewLauncherClient("http://example.com", "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	if c == nil {
		t.Fatal("NewLauncherClient() returned nil")
	}
}

// ---------------------------------------------------------------------------
// Launch — confirmed guard
// ---------------------------------------------------------------------------

func TestLaunch_ConfirmedFalse_ReturnsError(t *testing.T) {
	c, err := NewLauncherClient("http://unused.example.com", "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	req := validLaunchRequest()
	req.Confirmed = false

	_, err = c.Launch(context.Background(), req, "tok")
	if err == nil {
		t.Fatal("Launch() expected error when Confirmed=false, got nil")
	}
}

// ---------------------------------------------------------------------------
// Launch — happy path (202)
// ---------------------------------------------------------------------------

func TestLaunch_202_ReturnsResponse(t *testing.T) {
	want := LaunchResponse{
		SandboxName:     "sb-abc",
		SandboxID:       "id-123",
		Namespace:       "openshell",
		Phase:           "Pending",
		ConversationURL: "",
		AccessHint:      "kubectl exec ...",
		Owner:           "alice",
	}

	srv := serveLaunch(t, http.StatusAccepted, want)
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	got, err := c.Launch(context.Background(), validLaunchRequest(), "bearer-tok")
	if err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	if got != want {
		t.Errorf("Launch() = %+v; want %+v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Launch — bearer token is forwarded
// ---------------------------------------------------------------------------

func TestLaunch_ForwardsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(LaunchResponse{SandboxName: "sb-x"})
	}))
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "my-secret-token")
	if err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("Authorization header = %q; want %q", gotAuth, "Bearer my-secret-token")
	}
}

// ---------------------------------------------------------------------------
// Launch — non-202 status
// ---------------------------------------------------------------------------

func TestLaunch_400_ReturnsError(t *testing.T) {
	srv := serveLaunch(t, http.StatusBadRequest, map[string]string{"error": "confirmed must be true"})
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "tok")
	if err == nil {
		t.Fatal("Launch() expected error on 400, got nil")
	}
}

func TestLaunch_401_ReturnsError(t *testing.T) {
	srv := serveLaunch(t, http.StatusUnauthorized, nil)
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "bad-tok")
	if err == nil {
		t.Fatal("Launch() expected error on 401, got nil")
	}
}

func TestLaunch_403_ReturnsError(t *testing.T) {
	srv := serveLaunch(t, http.StatusForbidden, nil)
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "tok")
	if err == nil {
		t.Fatal("Launch() expected error on 403, got nil")
	}
}

// ---------------------------------------------------------------------------
// Launch — network error
// ---------------------------------------------------------------------------

func TestLaunch_NetworkError_ReturnsError(t *testing.T) {
	// Use a port that's not listening.
	c, err := NewLauncherClient("http://127.0.0.1:0", "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "tok")
	if err == nil {
		t.Fatal("Launch() expected error on network failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Launch — bad JSON response
// ---------------------------------------------------------------------------

func TestLaunch_BadJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("not json {{{"))
	}))
	defer srv.Close()

	c, err := NewLauncherClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewLauncherClient() error = %v", err)
	}
	_, err = c.Launch(context.Background(), validLaunchRequest(), "tok")
	if err == nil {
		t.Fatal("Launch() expected error on bad JSON response, got nil")
	}
}
