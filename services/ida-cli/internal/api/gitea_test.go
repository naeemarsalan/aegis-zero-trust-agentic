package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// parsePRURL
// ---------------------------------------------------------------------------

func TestParsePRURL_Happy(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantIndex int
	}{
		{
			name:      "https URL",
			url:       "https://gitea.example.com/alice/myrepo/pulls/42",
			wantOwner: "alice",
			wantRepo:  "myrepo",
			wantIndex: 42,
		},
		{
			name:      "http URL",
			url:       "http://gitea.local/org/repo/pulls/1",
			wantOwner: "org",
			wantRepo:  "repo",
			wantIndex: 1,
		},
		{
			name:      "index 100",
			url:       "https://g.io/u/r/pulls/100",
			wantOwner: "u",
			wantRepo:  "r",
			wantIndex: 100,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo, index, err := parsePRURL(tc.url)
			if err != nil {
				t.Fatalf("parsePRURL(%q) error = %v", tc.url, err)
			}
			if owner != tc.wantOwner {
				t.Errorf("owner = %q; want %q", owner, tc.wantOwner)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo = %q; want %q", repo, tc.wantRepo)
			}
			if index != tc.wantIndex {
				t.Errorf("index = %d; want %d", index, tc.wantIndex)
			}
		})
	}
}

func TestParsePRURL_Errors(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "missing_path_segments", url: "https://gitea.example.com/alice/repo"},
		{name: "wrong_segment_name", url: "https://gitea.example.com/alice/repo/issues/5"},
		{name: "non_integer_index", url: "https://gitea.example.com/alice/repo/pulls/abc"},
		{name: "invalid_url", url: "://bad url"},
		{name: "empty", url: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parsePRURL(tc.url)
			if err == nil {
				t.Errorf("parsePRURL(%q) expected error, got nil", tc.url)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewGiteaClient
// ---------------------------------------------------------------------------

func TestNewGiteaClient_NotNil(t *testing.T) {
	c, err := NewGiteaClient("http://gitea.example.com", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	if c == nil {
		t.Fatal("NewGiteaClient() returned nil")
	}
}

func TestNewGiteaClient_StripsTrailingSlash(t *testing.T) {
	c, err := NewGiteaClient("http://gitea.example.com/", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	// The base URL should not end in / — confirmed by checking MergePR does not
	// produce a double-slash. We exercise this by checking the field directly.
	if c.baseURL[len(c.baseURL)-1] == '/' {
		t.Errorf("baseURL ends with /; should be stripped")
	}
}

// ---------------------------------------------------------------------------
// MergePR
// ---------------------------------------------------------------------------

// serveMerge returns a server whose merge endpoint returns the given status.
func serveMerge(t *testing.T, wantPath string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(status)
	}))
}

func TestMergePR_200_Succeeds(t *testing.T) {
	srv := serveMerge(t, "/api/v1/repos/alice/myrepo/pulls/7/merge", http.StatusOK)
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "giteatok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/alice/myrepo/pulls/7"
	if err := c.MergePR(context.Background(), prURL); err != nil {
		t.Fatalf("MergePR() error = %v", err)
	}
}

func TestMergePR_204_Succeeds(t *testing.T) {
	srv := serveMerge(t, "/api/v1/repos/org/repo/pulls/42/merge", http.StatusNoContent)
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "giteatok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/org/repo/pulls/42"
	if err := c.MergePR(context.Background(), prURL); err != nil {
		t.Fatalf("MergePR() error = %v", err)
	}
}

func TestMergePR_409Conflict_ReturnsError(t *testing.T) {
	srv := serveMerge(t, "/api/v1/repos/alice/repo/pulls/3/merge", http.StatusConflict)
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "giteatok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/alice/repo/pulls/3"
	err = c.MergePR(context.Background(), prURL)
	if err == nil {
		t.Fatal("MergePR() expected error on 409, got nil")
	}
}

func TestMergePR_403_ReturnsError(t *testing.T) {
	srv := serveMerge(t, "/api/v1/repos/alice/repo/pulls/1/merge", http.StatusForbidden)
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "giteatok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/alice/repo/pulls/1"
	err = c.MergePR(context.Background(), prURL)
	if err == nil {
		t.Fatal("MergePR() expected error on 403, got nil")
	}
}

func TestMergePR_InvalidPRURL_ReturnsError(t *testing.T) {
	c, err := NewGiteaClient("http://gitea.example.com", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	err = c.MergePR(context.Background(), "http://gitea.example.com/notapr")
	if err == nil {
		t.Fatal("MergePR() expected error on bad PR URL, got nil")
	}
}

func TestMergePR_NetworkError_ReturnsError(t *testing.T) {
	c, err := NewGiteaClient("http://127.0.0.1:0", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	err = c.MergePR(context.Background(), "http://127.0.0.1:0/alice/repo/pulls/1")
	if err == nil {
		t.Fatal("MergePR() expected error on network failure, got nil")
	}
}

func TestMergePR_AuthHeaderForwarded(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "secret-gitea-token", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/u/r/pulls/5"
	if err := c.MergePR(context.Background(), prURL); err != nil {
		t.Fatalf("MergePR() error = %v", err)
	}
	if gotAuth != "token secret-gitea-token" {
		t.Errorf("Authorization = %q; want %q", gotAuth, "token secret-gitea-token")
	}
}

// ---------------------------------------------------------------------------
// MergePR — host validation (credential-exfiltration guard)
// ---------------------------------------------------------------------------

// TestMergePR_ForeignHost_Rejected verifies that MergePR refuses to send the
// PAT when prURL points at a different host than the configured Gitea base.
// This prevents a compromised jit-approver from exfiltrating the user's token.
func TestMergePR_ForeignHost_Rejected(t *testing.T) {
	// Attacker-controlled server — must never receive a request.
	attackerHit := false
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	// Client is configured to talk to a trusted Gitea instance.
	c, err := NewGiteaClient("https://gitea.trusted.example.com", "super-secret-pat", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}

	// prURL claims to be on the trusted host path but points at the attacker host.
	prURL := attacker.URL + "/alice/repo/pulls/1"

	err = c.MergePR(context.Background(), prURL)
	if err == nil {
		t.Fatal("MergePR() expected error when prURL host differs from configured base, got nil")
	}
	if attackerHit {
		t.Error("attacker server received a request — credential may have been exfiltrated")
	}
}

// TestMergePR_SchemeMismatch_Rejected verifies that an https-configured client
// rejects a prURL that downgrades to http (potential interception path).
func TestMergePR_SchemeMismatch_Rejected(t *testing.T) {
	// Client configured with https.
	c, err := NewGiteaClient("https://gitea.example.com", "pat", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}

	// prURL uses http on the same hostname.
	err = c.MergePR(context.Background(), "http://gitea.example.com/u/r/pulls/1")
	if err == nil {
		t.Fatal("MergePR() expected error when scheme downgrades from https to http, got nil")
	}
}

// TestMergePR_SameHostAndScheme_Succeeds verifies that a matching host+scheme passes.
func TestMergePR_SameHostAndScheme_Succeeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewGiteaClient(srv.URL, "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	prURL := srv.URL + "/owner/repo/pulls/3"
	if err := c.MergePR(context.Background(), prURL); err != nil {
		t.Fatalf("MergePR() error = %v; want nil for matching host", err)
	}
}

// ---------------------------------------------------------------------------
// assertSameHost
// ---------------------------------------------------------------------------

func TestAssertSameHost_Match(t *testing.T) {
	c, err := NewGiteaClient("https://git.example.com", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	if err := c.assertSameHost("https://git.example.com/o/r/pulls/1"); err != nil {
		t.Errorf("assertSameHost() error = %v; want nil", err)
	}
}

func TestAssertSameHost_DifferentHost(t *testing.T) {
	c, err := NewGiteaClient("https://git.example.com", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	err = c.assertSameHost("https://evil.example.com/o/r/pulls/1")
	if err == nil {
		t.Error("assertSameHost() expected error on host mismatch, got nil")
	}
}

func TestAssertSameHost_DifferentScheme(t *testing.T) {
	c, err := NewGiteaClient("https://git.example.com", "tok", "", false)
	if err != nil {
		t.Fatalf("NewGiteaClient() error = %v", err)
	}
	err = c.assertSameHost("http://git.example.com/o/r/pulls/1")
	if err == nil {
		t.Error("assertSameHost() expected error on scheme mismatch, got nil")
	}
}
