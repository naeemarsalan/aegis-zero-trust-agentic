package cli

// Unit tests for the internal/cli package.
//
// Rules enforced:
//   - No network calls to live services (all HTTP via httptest.Server).
//   - No live cluster (kubeconfig pointed at a nonexistent path).
//   - No credential values logged or asserted in plain text.
//   - One happy-path and one error-path per handler.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
)

// ---------------------------------------------------------------------------
// Test-environment helpers
// ---------------------------------------------------------------------------

// withTempHome redirects $HOME to a t.TempDir() for the duration of the test
// so that config/token files are isolated.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// writeConfig writes a minimal valid config.yaml into dir/.config/ida/.
func writeConfig(t *testing.T, home string, cfg *config.Config) {
	t.Helper()
	cfgDir := filepath.Join(home, ".config", "ida")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	f, err := os.OpenFile(filepath.Join(cfgDir, "config.yaml"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	require.NoError(t, err)
	defer f.Close()
	// Serialise manually to avoid importing yaml here.
	lines := []string{
		"launcher_url: " + cfg.LauncherURL,
		"jit_url: " + cfg.JitURL,
		"gitea_url: " + cfg.GiteaURL,
		"gitea_token: " + cfg.GiteaToken,
		"keycloak_realm_url: " + cfg.KeycloakRealmURL,
		"keycloak_client_id: " + cfg.KeycloakClientID,
		"sandbox_namespace: " + cfg.SandboxNamespace,
		"owner: " + cfg.Owner,
	}
	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	require.NoError(t, err)
}

// writeToken writes a fresh OAuth2 token into the token store location.
func writeToken(t *testing.T, home string, tok *oauth2.Token) {
	t.Helper()
	tokenDir := filepath.Join(home, ".config", "ida")
	require.NoError(t, os.MkdirAll(tokenDir, 0o700))
	data, err := json.Marshal(tok)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tokenDir, "token.json"), data, 0o600))
}

// runCmd executes a cobra command tree with the given args, capturing stdout.
// It sets up a fresh cobra command tree using the exported command builders.
func buildRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "ida", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
	root.AddCommand(loginCmd())
	root.AddCommand(agentCmd())
	root.AddCommand(jitCmd())
	root.AddCommand(catalogCmd())
	return root
}

func execCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// noKubeEnv disables kubeconfig discovery so kube.NewClient() always fails
// without touching any cluster.
func noKubeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "nonexistent"))
}

// ---------------------------------------------------------------------------
// redirectLogsForTUI
// ---------------------------------------------------------------------------

// TestRedirectLogsForTUI_WritesToLogFile verifies that calling redirectLogsForTUI
// with a writable HOME creates the log file and redirects slog output to it.
// The test restores the previous slog default after completion so it does not
// pollute other tests.
func TestRedirectLogsForTUI_WritesToLogFile(t *testing.T) {
	home := withTempHome(t)

	// Capture the original slog default so we can restore it.
	origDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origDefault) })

	redirectLogsForTUI()

	// After redirect, emitting a log line must go to the file, not stderr.
	slog.Info("test-redirect-marker", "key", "value")

	logPath := filepath.Join(home, ".config", "ida", "ida.log")
	data, err := os.ReadFile(logPath)
	require.NoError(t, err, "ida.log should have been created by redirectLogsForTUI")
	if !strings.Contains(string(data), "test-redirect-marker") {
		t.Errorf("ida.log should contain the test log line; got:\n%s", string(data))
	}
}

// TestRedirectLogsForTUI_UnwritableHome_DoesNotPanic verifies that if $HOME
// is set to a path that cannot be written to, redirectLogsForTUI falls back
// to io.Discard without panicking and without writing to stderr.
func TestRedirectLogsForTUI_UnwritableHome_DoesNotPanic(t *testing.T) {
	// Point HOME at a nonexistent, unwritable path.
	t.Setenv("HOME", filepath.Join(t.TempDir(), "nonexistent-dir"))

	origDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origDefault) })

	// Must not panic.
	redirectLogsForTUI()

	// Logging after the redirect must not panic either.
	slog.Info("silent-after-discard")
}

// ---------------------------------------------------------------------------
// terminalJitStates map
// ---------------------------------------------------------------------------

func TestTerminalJitStates_ContainsExpectedStates(t *testing.T) {
	expected := []string{"approved", "issued", "expired", "denied"}
	for _, s := range expected {
		assert.True(t, terminalJitStates[s], "state %q should be terminal", s)
	}
}

func TestTerminalJitStates_PendingIsNotTerminal(t *testing.T) {
	assert.False(t, terminalJitStates["pending"], "pending must not be a terminal state")
}

func TestTerminalJitStates_EmptyStringIsNotTerminal(t *testing.T) {
	assert.False(t, terminalJitStates[""], "empty string must not be terminal")
}

// ---------------------------------------------------------------------------
// loadCfgAndBearer
// ---------------------------------------------------------------------------

func TestLoadCfgAndBearer_NoConfig_NoToken_ReturnsError(t *testing.T) {
	withTempHome(t) // no config file written, no token file written
	_, _, err := loadCfgAndBearer(context.Background())
	// config.Load() succeeds with zero-value defaults even without a file,
	// but AccessToken() must fail because no token is stored — fail-closed.
	require.Error(t, err, "loadCfgAndBearer must fail when no token is stored")
	assert.Contains(t, err.Error(), "token")
}

func TestLoadCfgAndBearer_NoToken_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
	})
	// No token file — AccessToken must return an error.
	_, _, err := loadCfgAndBearer(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestLoadCfgAndBearer_ValidToken_ReturnsBearer(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{
		LauncherURL:      "http://launcher.local",
		JitURL:           "http://jit.local",
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-access-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	cfg, bearer, err := loadCfgAndBearer(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", bearer)
	assert.Equal(t, "alice", cfg.Owner)
}

// ---------------------------------------------------------------------------
// Command tree structure
// ---------------------------------------------------------------------------

func TestCommandTree_AgentSubcommands(t *testing.T) {
	cmd := agentCmd()
	names := make([]string, 0)
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	expected := []string{"attach", "launch", "list", "logs", "rm", "status"}
	for _, e := range expected {
		assert.Contains(t, names, e, "agent should have subcommand %q", e)
	}
}

func TestCommandTree_JitSubcommands(t *testing.T) {
	cmd := jitCmd()
	names := make([]string, 0)
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	expected := []string{"list", "show", "watch", "receipt"}
	for _, e := range expected {
		assert.Contains(t, names, e, "jit should have subcommand %q", e)
	}
}

func TestCommandTree_CatalogSubcommands(t *testing.T) {
	cmd := catalogCmd()
	names := make([]string, 0)
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "list")
}

// ---------------------------------------------------------------------------
// Flag registration checks
// ---------------------------------------------------------------------------

func TestAgentLaunch_HasRequiredFlags(t *testing.T) {
	cmd := agentLaunchCmd()
	assert.NotNil(t, cmd.Flags().Lookup("goal"), "--goal flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("scope"), "--scope flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("mode"), "--mode flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("cap"), "--cap flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("ttl"), "--ttl flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("json"), "--json flag must exist")
	assert.NotNil(t, cmd.Flags().Lookup("yes"), "--yes flag must exist")
}

func TestAgentList_HasJSONFlag(t *testing.T) {
	cmd := agentListCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

func TestAgentStatus_HasJSONFlag(t *testing.T) {
	cmd := agentStatusCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

func TestAgentLogs_HasFollowFlag(t *testing.T) {
	cmd := agentLogsCmd()
	assert.NotNil(t, cmd.Flags().Lookup("follow"))
}

func TestAgentRm_HasForceFlag(t *testing.T) {
	cmd := agentRmCmd()
	assert.NotNil(t, cmd.Flags().Lookup("force"))
}

func TestJitList_HasJSONAndFilterFlags(t *testing.T) {
	cmd := jitListCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
	assert.NotNil(t, cmd.Flags().Lookup("sandbox"))
	assert.NotNil(t, cmd.Flags().Lookup("state"))
}

func TestJitShow_HasJSONFlag(t *testing.T) {
	cmd := jitShowCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

func TestJitWatch_HasIntervalFlag(t *testing.T) {
	cmd := jitWatchCmd()
	assert.NotNil(t, cmd.Flags().Lookup("interval"))
}

func TestJitReceipt_HasJSONFlag(t *testing.T) {
	cmd := jitReceiptCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

func TestCatalogList_HasJSONFlag(t *testing.T) {
	cmd := catalogListCmd()
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

// ---------------------------------------------------------------------------
// catalog list — happy path (no network needed; static data)
// ---------------------------------------------------------------------------

func TestCatalogList_HappyPath_TextOutput(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"catalog", "list"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "mcp-pfsense", "output should contain mcp-pfsense")
}

func TestCatalogList_HappyPath_JSONOutput(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"catalog", "list", "--json"})
	err := root.Execute()
	require.NoError(t, err)

	var servers []api.MCPServer
	err = json.NewDecoder(buf).Decode(&servers)
	require.NoError(t, err, "catalog list --json must produce valid JSON")
	assert.NotEmpty(t, servers)
}

// ---------------------------------------------------------------------------
// jit list — happy path via httptest.Server
// ---------------------------------------------------------------------------

func newJITServerWithSessions(t *testing.T, sessions []api.JitSession) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/requests") {
			http.NotFound(w, r)
			return
		}
		// Ignore sub-paths like /requests/{id}/detail for this helper.
		if strings.Count(r.URL.Path, "/") > 1 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	}))
}

func TestJitList_HappyPath_TextOutput(t *testing.T) {
	home := withTempHome(t)
	sessions := []api.JitSession{
		{ID: "sess-1", State: "pending", PRURL: "http://gitea/pr/1", ExpiresAt: time.Now().Add(time.Hour)},
	}
	srv := newJITServerWithSessions(t, sessions)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "list"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "sess-1")
	assert.Contains(t, out, "pending")
}

func TestJitList_HappyPath_JSONOutput(t *testing.T) {
	home := withTempHome(t)
	sessions := []api.JitSession{
		{ID: "sess-2", State: "approved", PRURL: "http://gitea/pr/2", ExpiresAt: time.Now().Add(time.Hour)},
	}
	srv := newJITServerWithSessions(t, sessions)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "list", "--json"})
	err := root.Execute()
	require.NoError(t, err)

	var got []api.JitSession
	err = json.NewDecoder(buf).Decode(&got)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "sess-2", got[0].ID)
}

func TestJitList_MissingJitURL_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{JitURL: ""}) // no jit_url

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "list"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestJitList_ServerError_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "list"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// jit show — happy path + error path
// ---------------------------------------------------------------------------

func newJITDetailServer(t *testing.T, id string, detail api.JitDetail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/requests/" + id + "/detail"
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(detail)
	}))
}

func TestJitShow_HappyPath_TextOutput(t *testing.T) {
	home := withTempHome(t)
	detail := api.JitDetail{
		ID:            "d-1",
		State:         "pending",
		PRURL:         "http://gitea/pr/5",
		RequesterSub:  "alice",
		Namespace:     "openshell",
		Justification: "need debug access",
		Sandbox:       "sb-abc",
	}
	srv := newJITDetailServer(t, "d-1", detail)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "show", "d-1"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "d-1")
	assert.Contains(t, out, "need debug access")
}

func TestJitShow_HappyPath_JSONOutput(t *testing.T) {
	home := withTempHome(t)
	detail := api.JitDetail{
		ID:    "d-2",
		State: "approved",
	}
	srv := newJITDetailServer(t, "d-2", detail)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "show", "d-2", "--json"})
	err := root.Execute()
	require.NoError(t, err)

	var got api.JitDetail
	err = json.NewDecoder(buf).Decode(&got)
	require.NoError(t, err)
	assert.Equal(t, "d-2", got.ID)
}

func TestJitShow_NotFound_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "show", "missing-id"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestJitShow_RequiresExactlyOneArg(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "show"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// jit receipt — happy path + error path
// ---------------------------------------------------------------------------

func newJITReceiptServer(t *testing.T, id string, receipt api.JitReceipt) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/requests/" + id + "/receipt"
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(receipt)
	}))
}

func TestJitReceipt_HappyPath_TextOutput(t *testing.T) {
	home := withTempHome(t)
	receipt := api.JitReceipt{
		ID:      "r-1",
		State:   "issued",
		Outcome: "allow",
		Allowed: []string{"list pods"},
		Denied:  []string{},
	}
	srv := newJITReceiptServer(t, "r-1", receipt)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "receipt", "r-1"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "allow")
	assert.Contains(t, out, "r-1")
}

func TestJitReceipt_HappyPath_JSONOutput(t *testing.T) {
	home := withTempHome(t)
	receipt := api.JitReceipt{
		ID:      "r-2",
		Outcome: "deny",
	}
	srv := newJITReceiptServer(t, "r-2", receipt)
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "receipt", "r-2", "--json"})
	err := root.Execute()
	require.NoError(t, err)

	var got api.JitReceipt
	err = json.NewDecoder(buf).Decode(&got)
	require.NoError(t, err)
	assert.Equal(t, "r-2", got.ID)
	assert.Equal(t, "deny", got.Outcome)
}

func TestJitReceipt_ServerError_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "receipt", "r-bad"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// jit watch — terminal state detection
// ---------------------------------------------------------------------------

func TestJitWatch_TerminatesOnApproved(t *testing.T) {
	home := withTempHome(t)

	// Server returns "approved" immediately on first poll.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		status := api.JitStatus{
			ID:        "w-1",
			State:     "approved",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "w-1", "--interval", "0"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Watch done.")
	assert.Equal(t, 1, callCount, "should stop polling after first terminal response")
}

func TestJitWatch_TerminatesOnDenied(t *testing.T) {
	home := withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := api.JitStatus{
			ID:        "w-2",
			State:     "denied",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "w-2", "--interval", "0"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Watch done.")
}

func TestJitWatch_TerminatesOnExpired(t *testing.T) {
	home := withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := api.JitStatus{
			ID:    "w-3",
			State: "expired",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "w-3", "--interval", "0"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Watch done.")
}

func TestJitWatch_TerminatesOnIssued(t *testing.T) {
	home := withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := api.JitStatus{
			ID:    "w-4",
			State: "issued",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "w-4", "--interval", "0"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Watch done.")
}

func TestJitWatch_PendingDoesNotStopImmediately(t *testing.T) {
	home := withTempHome(t)

	// First response is "pending"; subsequent responses are "approved".
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		state := "approved"
		if calls == 1 {
			state = "pending"
		}
		status := api.JitStatus{
			ID:        "w-5",
			State:     state,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "w-5", "--interval", "0"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Watch done.")
	assert.GreaterOrEqual(t, calls, 2, "watch should poll at least twice when first response is pending")
}

func TestJitWatch_ServerError_ReturnsError(t *testing.T) {
	home := withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"jit", "watch", "bad-id", "--interval", "0"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestJitWatch_ContextCancelled_ReturnsError(t *testing.T) {
	home := withTempHome(t)

	// Server always returns pending — watch would block without ctx cancel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := api.JitStatus{ID: "w-cancel", State: "pending", ExpiresAt: time.Now().Add(time.Hour)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{JitURL: srv.URL})

	// Build command manually so we can pass a cancelled context.
	cmd := jitWatchCmd()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	cmd.SetContext(ctx)

	err := cmd.RunE(cmd, []string{"w-cancel"})
	// The command should return context.Canceled or the jit HTTP call may fail —
	// either is an error, not nil.
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// agent list — requires kube access; verify it fails cleanly without cluster
// ---------------------------------------------------------------------------

func TestAgentList_NoKubeConfig_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	noKubeEnv(t)
	writeConfig(t, home, &config.Config{SandboxNamespace: "openshell", Owner: "alice"})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "list"})
	err := root.Execute()
	assert.Error(t, err, "agent list without kubeconfig must return an error")
}

// ---------------------------------------------------------------------------
// agent status — requires kube access
// ---------------------------------------------------------------------------

func TestAgentStatus_NoKubeConfig_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	noKubeEnv(t)
	writeConfig(t, home, &config.Config{SandboxNamespace: "openshell"})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "status", "any-sandbox"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentStatus_RequiresExactlyOneArg(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "status"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// agent attach — requires kube access
// ---------------------------------------------------------------------------

func TestAgentAttach_NoKubeConfig_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	noKubeEnv(t)
	writeConfig(t, home, &config.Config{SandboxNamespace: "openshell"})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "attach", "sb-x"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentAttach_RequiresExactlyOneArg(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "attach"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// agent logs — requires kube access
// ---------------------------------------------------------------------------

func TestAgentLogs_NoKubeConfig_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	noKubeEnv(t)
	writeConfig(t, home, &config.Config{SandboxNamespace: "openshell"})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "logs", "sb-x"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentLogs_RequiresExactlyOneArg(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "logs"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// agent rm — force flag skips confirmation; no cluster needed to hit prompt
// ---------------------------------------------------------------------------

func TestAgentRm_RequiresExactlyOneArg(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "rm"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentRm_NoKubeConfig_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	noKubeEnv(t)
	writeConfig(t, home, &config.Config{SandboxNamespace: "openshell"})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "rm", "--force", "sb-del"})
	err := root.Execute()
	assert.Error(t, err, "rm with --force and no kubeconfig must fail trying to build kube client")
}

// ---------------------------------------------------------------------------
// agent launch — happy path via httptest.Server
// ---------------------------------------------------------------------------

func newLauncherServer(t *testing.T, resp api.LaunchResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/launch" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestAgentLaunch_HappyPath_TextOutput(t *testing.T) {
	home := withTempHome(t)
	launchResp := api.LaunchResponse{
		SandboxName: "sb-launch-1",
		SandboxID:   "id-001",
		Namespace:   "openshell",
		Phase:       "Pending",
		Owner:       "alice",
	}
	srv := newLauncherServer(t, launchResp)
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "test deployment", "--scope", "read-only", "--yes"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "sb-launch-1")
}

func TestAgentLaunch_HappyPath_JSONOutput(t *testing.T) {
	home := withTempHome(t)
	launchResp := api.LaunchResponse{
		SandboxName: "sb-launch-2",
		SandboxID:   "id-002",
		Namespace:   "openshell",
		Phase:       "Pending",
		Owner:       "alice",
	}
	srv := newLauncherServer(t, launchResp)
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "json test", "--json", "--yes"})
	err := root.Execute()
	require.NoError(t, err)

	var got api.LaunchResponse
	err = json.NewDecoder(buf).Decode(&got)
	require.NoError(t, err)
	assert.Equal(t, "sb-launch-2", got.SandboxName)
}

func TestAgentLaunch_MissingGoal_ReturnsError(t *testing.T) {
	withTempHome(t)
	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch"}) // --goal is required
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentLaunch_NoToken_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{
		LauncherURL:      "http://launcher.local",
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
	})
	// No token file written — loadCfgAndBearer should fail.

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "test", "--yes"})
	err := root.Execute()
	assert.Error(t, err)
}

func TestAgentLaunch_LauncherError_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "test", "--yes"})
	err := root.Execute()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// newJitClient helper
// ---------------------------------------------------------------------------

func TestNewJitClient_EmptyURL_ReturnsError(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{JitURL: ""})

	_, err := newJitClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jit_url")
}

func TestNewJitClient_WithURL_ReturnsClient(t *testing.T) {
	home := withTempHome(t)
	writeConfig(t, home, &config.Config{JitURL: "http://jit.example.com"})

	c, err := newJitClient()
	require.NoError(t, err)
	assert.NotNil(t, c)
}

// ---------------------------------------------------------------------------
// validateLaunchInputs — unit tests (Finding 3)
// ---------------------------------------------------------------------------

func TestValidateLaunchInputs_HappyPath(t *testing.T) {
	err := validateLaunchInputs("deploy to prod", []string{"echo", "firewall.read"}, "task", "read-only", 60)
	require.NoError(t, err)
}

func TestValidateLaunchInputs_EmptyGoal_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("", []string{"echo"}, "task", "read-only", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "goal must not be empty")
}

func TestValidateLaunchInputs_GoalTooLong_ReturnsError(t *testing.T) {
	longGoal := strings.Repeat("x", 501)
	err := validateLaunchInputs(longGoal, []string{"echo"}, "task", "read-only", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
}

func TestValidateLaunchInputs_GoalExactly500Chars_OK(t *testing.T) {
	goal := strings.Repeat("a", 500)
	err := validateLaunchInputs(goal, []string{"echo"}, "task", "read-only", 60)
	require.NoError(t, err)
}

func TestValidateLaunchInputs_EmptyCapabilities_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("goal", []string{}, "task", "read-only", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capability")
}

func TestValidateLaunchInputs_TooManyCapabilities_ReturnsError(t *testing.T) {
	caps := make([]string, 21)
	for i := range caps {
		caps[i] = "cap"
	}
	err := validateLaunchInputs("goal", caps, "task", "read-only", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "21")
}

func TestValidateLaunchInputs_ExactlyTwentyCaps_OK(t *testing.T) {
	caps := make([]string, 20)
	for i := range caps {
		caps[i] = "cap"
	}
	err := validateLaunchInputs("goal", caps, "task", "read-only", 60)
	require.NoError(t, err)
}

func TestValidateLaunchInputs_InvalidMode_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("goal", []string{"echo"}, "batch", "read-only", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
	assert.Contains(t, err.Error(), "batch")
}

func TestValidateLaunchInputs_AllValidModes(t *testing.T) {
	for _, mode := range []string{"task", "project"} {
		err := validateLaunchInputs("goal", []string{"echo"}, mode, "read-only", 60)
		require.NoError(t, err, "mode %q should be valid", mode)
	}
}

func TestValidateLaunchInputs_InvalidScope_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("goal", []string{"echo"}, "task", "superadmin", 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope")
	assert.Contains(t, err.Error(), "superadmin")
}

func TestValidateLaunchInputs_AllValidScopes(t *testing.T) {
	for _, scope := range []string{"read-only", "read-write", "admin"} {
		err := validateLaunchInputs("goal", []string{"echo"}, "task", scope, 60)
		require.NoError(t, err, "scope %q should be valid", scope)
	}
}

func TestValidateLaunchInputs_TTLTooLow_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("goal", []string{"echo"}, "task", "read-only", 4)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl")
}

func TestValidateLaunchInputs_TTLTooHigh_ReturnsError(t *testing.T) {
	err := validateLaunchInputs("goal", []string{"echo"}, "task", "read-only", 481)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl")
}

func TestValidateLaunchInputs_TTLBoundaryValid(t *testing.T) {
	require.NoError(t, validateLaunchInputs("g", []string{"echo"}, "task", "read-only", 5))
	require.NoError(t, validateLaunchInputs("g", []string{"echo"}, "task", "read-only", 480))
}

func TestValidateLaunchInputs_MultipleErrors_ReportedTogether(t *testing.T) {
	// Empty goal + bad mode + bad scope + bad ttl: all errors should appear.
	err := validateLaunchInputs("", []string{}, "bogus", "bogus", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "goal")
	assert.Contains(t, err.Error(), "capability")
	assert.Contains(t, err.Error(), "mode")
	assert.Contains(t, err.Error(), "scope")
	assert.Contains(t, err.Error(), "ttl")
}

// ---------------------------------------------------------------------------
// agent launch --yes flag integration (Finding 3)
// ---------------------------------------------------------------------------

func TestAgentLaunch_YesFlagSkipsPrompt(t *testing.T) {
	home := withTempHome(t)
	launchResp := api.LaunchResponse{
		SandboxName: "sb-yes-flag",
		SandboxID:   "id-yes",
		Namespace:   "openshell",
		Phase:       "Pending",
	}
	srv := newLauncherServer(t, launchResp)
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "deploy service", "--yes"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "sb-yes-flag", "--yes must skip prompt and reach the backend")
	// The confirmation prompt must NOT appear in output when --yes is set.
	assert.NotContains(t, out, "Confirm?")
}

func TestAgentLaunch_InvalidGoalLength_ReturnsErrorBeforeNetwork(t *testing.T) {
	home := withTempHome(t)
	// Server would panic if called — validation should prevent it reaching network.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("network should not be reached when validation fails")
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	// Goal is 501 chars — should fail validation before any network call.
	root.SetArgs([]string{"agent", "launch", "--goal", strings.Repeat("x", 501), "--yes"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
}

func TestAgentLaunch_InvalidScope_ReturnsErrorBeforeNetwork(t *testing.T) {
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("network should not be reached when validation fails")
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		LauncherURL:      srv.URL,
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
		Owner:            "alice",
	})
	writeToken(t, home, &oauth2.Token{
		AccessToken: "test-tok",
		Expiry:      time.Now().Add(time.Hour),
	})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"agent", "launch", "--goal", "test", "--scope", "superuser", "--yes"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope")
}

// ---------------------------------------------------------------------------
// loginCmd — flag and ROPC path tests (CHANGE 1)
// ---------------------------------------------------------------------------

func TestLoginCmd_HasUserFlag(t *testing.T) {
	cmd := loginCmd()
	assert.NotNil(t, cmd.Flags().Lookup("user"), "--user / -u flag must exist on login command")
}

func TestLoginCmd_UserFlagShorthand(t *testing.T) {
	cmd := loginCmd()
	f := cmd.Flags().ShorthandLookup("u")
	assert.NotNil(t, f, "-u shorthand must exist on login command")
}

// TestLogin_PasswordGrant_HappyPath_ViaEnvVar drives the ROPC path end-to-end
// through a mock Keycloak token server, supplying the password via IDA_PASSWORD
// (the non-TTY path that is testable without a real terminal).
func TestLogin_PasswordGrant_HappyPath_ViaEnvVar(t *testing.T) {
	home := withTempHome(t)

	// Stand up a minimal Keycloak-like token server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// Verify grant_type without logging credentials.
		if r.FormValue("grant_type") != "password" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "ropc-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "ropc-refresh-token",
		})
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		KeycloakRealmURL: srv.URL,
		KeycloakClientID: "ida-cli",
	})

	// Provide the password via env var (non-TTY path; no terminal needed).
	t.Setenv("IDA_PASSWORD", "test-password-value")

	root := buildRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"login", "--user", "alice"})
	err := root.Execute()
	require.NoError(t, err, "ROPC login should succeed against mock server")

	out := buf.String()
	assert.Contains(t, out, "Login successful", "success message must appear")
	// Token must NOT appear in any output — security invariant.
	assert.NotContains(t, out, "ropc-access-token", "access token must not be printed")
	assert.NotContains(t, out, "test-password-value", "password must not be printed")
}

// TestLogin_PasswordGrant_ServerError_ReturnsError verifies that a 401 from
// the token server surfaces as a non-nil error (fail-closed).
func TestLogin_PasswordGrant_ServerError_ReturnsError(t *testing.T) {
	home := withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "Invalid user credentials",
		})
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		KeycloakRealmURL: srv.URL,
		KeycloakClientID: "ida-cli",
	})

	t.Setenv("IDA_PASSWORD", "wrong-password")

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"login", "--user", "alice"})
	err := root.Execute()
	assert.Error(t, err, "ROPC login must fail on 401 (fail-closed)")
}

// TestLogin_PasswordGrant_NoPassword_NonTTY_ReturnsError verifies that if
// IDA_PASSWORD is not set and stdin is not a TTY (test environment) the
// command returns an error rather than blocking.
func TestLogin_PasswordGrant_NoPassword_NonTTY_ReturnsError(t *testing.T) {
	home := withTempHome(t)

	writeConfig(t, home, &config.Config{
		KeycloakRealmURL: "http://kc.example.com/realms/r",
		KeycloakClientID: "ida-cli",
	})

	// Ensure IDA_PASSWORD is not set.
	t.Setenv("IDA_PASSWORD", "")

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"login", "--user", "bob"})
	err := root.Execute()
	assert.Error(t, err, "login --user without IDA_PASSWORD and without TTY must fail")
}

// TestLogin_DeviceFlow_NoUserFlag_IsDefault verifies that omitting --user
// invokes the device-code flow (here the server responds with an error that
// identifies it as a device-auth attempt, not a token POST).
func TestLogin_DeviceFlow_NoUserFlag_IsDefault(t *testing.T) {
	home := withTempHome(t)

	deviceFlowCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protocol/openid-connect/auth/device" {
			deviceFlowCalled = true
		}
		// Return an error so the flow terminates quickly.
		http.Error(w, `{"error":"access_denied"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	writeConfig(t, home, &config.Config{
		KeycloakRealmURL: srv.URL,
		KeycloakClientID: "ida-cli",
	})

	root := buildRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"login"}) // no --user flag
	_ = root.Execute()              // error is expected; we only care that device endpoint was hit

	assert.True(t, deviceFlowCalled, "omitting --user must trigger the device-code flow")
}
