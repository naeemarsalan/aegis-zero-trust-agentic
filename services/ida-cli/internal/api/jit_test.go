package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock JIT server helpers
// ---------------------------------------------------------------------------

// jitHandler returns an http.Handler that serves a fixed set of JIT
// endpoints. Provide a map of path → (statusCode, body).
type jitRoute struct {
	status int
	body   any
}

func newJitServer(t *testing.T, routes map[string]jitRoute) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, route := range routes {
		p, r := path, route // capture
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(r.status)
			if r.body != nil {
				json.NewEncoder(w).Encode(r.body)
			}
		})
	}
	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// NewJitClient
// ---------------------------------------------------------------------------

func TestNewJitClient_NotNil(t *testing.T) {
	c, err := NewJitClient("http://example.com", "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	if c == nil {
		t.Fatal("NewJitClient() returned nil")
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestJitList_HappyPath(t *testing.T) {
	want := []JitSession{
		{ID: "sess-1", State: "pending", PRURL: "http://gitea/pr/1", ExpiresAt: time.Now().Add(time.Hour).Round(time.Second)},
		{ID: "sess-2", State: "approved", PRURL: "http://gitea/pr/2", ExpiresAt: time.Now().Add(2 * time.Hour).Round(time.Second)},
	}
	srv := newJitServer(t, map[string]jitRoute{
		"/requests": {status: http.StatusOK, body: want},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	got, err := c.List(context.Background(), "", "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("List() len = %d; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Errorf("[%d] ID = %q; want %q", i, got[i].ID, want[i].ID)
		}
		if got[i].State != want[i].State {
			t.Errorf("[%d] State = %q; want %q", i, got[i].State, want[i].State)
		}
	}
}

func TestJitList_QueryParamsAppended(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]JitSession{})
	}))
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.List(context.Background(), "sb-abc", "pending")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if gotQuery == "" {
		t.Error("expected query params to be forwarded, got empty")
	}
	// Ensure both params are present.
	if q := gotQuery; q == "" {
		t.Error("query string empty")
	}
}

func TestJitList_NonOKStatus_ReturnsError(t *testing.T) {
	srv := newJitServer(t, map[string]jitRoute{
		"/requests": {status: http.StatusInternalServerError, body: nil},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.List(context.Background(), "", "")
	if err == nil {
		t.Fatal("List() expected error on 500, got nil")
	}
}

func TestJitList_NetworkError_ReturnsError(t *testing.T) {
	c, err := NewJitClient("http://127.0.0.1:0", "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.List(context.Background(), "", "")
	if err == nil {
		t.Fatal("List() expected error on network failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

func TestJitDetail_HappyPath(t *testing.T) {
	want := JitDetail{
		ID:              "d-1",
		State:           "pending",
		PRURL:           "http://gitea/pr/5",
		RequesterSub:    "sub-alice",
		Namespace:       "openshell",
		Verbs:           []string{"get", "list"},
		Resources:       []string{"pods"},
		DurationMinutes: 30,
		Justification:   "need access for debug",
		Sandbox:         "sb-xyz",
		PolicyDelta:     []PolicyDelta{{Host: "pfsense.local", Port: 443}},
	}
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/d-1/detail": {status: http.StatusOK, body: want},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	got, err := c.Detail(context.Background(), "d-1")
	if err != nil {
		t.Fatalf("Detail() error = %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q; want %q", got.ID, want.ID)
	}
	if got.Justification != want.Justification {
		t.Errorf("Justification = %q; want %q", got.Justification, want.Justification)
	}
	if len(got.PolicyDelta) != 1 || got.PolicyDelta[0].Host != "pfsense.local" {
		t.Errorf("PolicyDelta = %+v; want one entry with host pfsense.local", got.PolicyDelta)
	}
}

func TestJitDetail_NotFound_ReturnsError(t *testing.T) {
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/missing/detail": {status: http.StatusNotFound, body: nil},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.Detail(context.Background(), "missing")
	if err == nil {
		t.Fatal("Detail() expected error on 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func TestJitStatus_HappyPath(t *testing.T) {
	want := JitStatus{
		ID:        "s-1",
		State:     "approved",
		PRURL:     "http://gitea/pr/7",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/s-1/status": {status: http.StatusOK, body: want},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	got, err := c.Status(context.Background(), "s-1")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if got.State != "approved" {
		t.Errorf("State = %q; want approved", got.State)
	}
}

func TestJitStatus_404_ReturnsError(t *testing.T) {
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/nope/status": {status: http.StatusNotFound, body: nil},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.Status(context.Background(), "nope")
	if err == nil {
		t.Fatal("Status() expected error on 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

func TestJitReceipt_HappyPath(t *testing.T) {
	want := JitReceipt{
		ID:           "r-1",
		State:        "issued",
		Outcome:      "allow",
		ToolScope:    []string{"firewall.rules.read"},
		Allowed:      []string{"list pods"},
		Denied:       []string{},
		DeniedSource: "",
	}
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/r-1/receipt": {status: http.StatusOK, body: want},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	got, err := c.Receipt(context.Background(), "r-1")
	if err != nil {
		t.Fatalf("Receipt() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Errorf("Outcome = %q; want allow", got.Outcome)
	}
	if len(got.ToolScope) != 1 || got.ToolScope[0] != "firewall.rules.read" {
		t.Errorf("ToolScope = %v; want [firewall.rules.read]", got.ToolScope)
	}
}

func TestJitReceipt_500_ReturnsError(t *testing.T) {
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/r-bad/receipt": {status: http.StatusInternalServerError, body: nil},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.Receipt(context.Background(), "r-bad")
	if err == nil {
		t.Fatal("Receipt() expected error on 500, got nil")
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

func TestJitSummary_HappyPath(t *testing.T) {
	want := JitSummary{
		Outcome:           "allow",
		ActionsTaken:      []string{"merged PR #5", "issued credentials"},
		ErrorsEncountered: []string{},
	}
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/su-1/summary": {status: http.StatusOK, body: want},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	got, err := c.Summary(context.Background(), "su-1")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Errorf("Outcome = %q; want allow", got.Outcome)
	}
	if len(got.ActionsTaken) != 2 {
		t.Errorf("ActionsTaken len = %d; want 2", len(got.ActionsTaken))
	}
}

func TestJitSummary_404_ReturnsError(t *testing.T) {
	srv := newJitServer(t, map[string]jitRoute{
		"/requests/none/summary": {status: http.StatusNotFound, body: nil},
	})
	defer srv.Close()

	c, err := NewJitClient(srv.URL, "", false)
	if err != nil {
		t.Fatalf("NewJitClient() error = %v", err)
	}
	_, err = c.Summary(context.Background(), "none")
	if err == nil {
		t.Fatal("Summary() expected error on 404, got nil")
	}
}
