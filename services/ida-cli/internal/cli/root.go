// Package cli defines the cobra command tree for ida-cli.
package cli

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/auth"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/kube"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui"
)

// rootCmd is the top-level cobra command. With no subcommand it launches the TUI.
var rootCmd = &cobra.Command{
	Use:   "ida",
	Short: "IDA — interactive agent dashboard for the nvidia-ida platform",
	Long: `ida is the developer CLI for the nvidia-ida zero-trust agentic platform.

With no subcommand it opens the interactive TUI dashboard.
Use 'ida --help' to see available subcommands.`,
	RunE: runTUI,
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(agentCmd())
	rootCmd.AddCommand(jitCmd())
	rootCmd.AddCommand(catalogCmd())
}

// redirectLogsForTUI opens $HOME/.config/ida/ida.log and redirects both the
// default slog handler and the standard library log package to that file for
// the lifetime of the process. This prevents structured-log output from
// corrupting the Bubble Tea alt-screen, which shares stderr with the process.
//
// If the log file cannot be opened (e.g. a read-only filesystem) the function
// falls back to io.Discard so the TUI is never corrupted. It never falls back
// to stderr.
//
// The caller does not need to close the file; it lives until process exit.
func redirectLogsForTUI() {
	w := tuiLogWriter()

	// Redirect slog (structured) and the stdlib log package.
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	log.SetOutput(w)

	// client-go / Kubernetes libraries log via klog directly to os.Stderr, which
	// shares the terminal with the Bubble Tea alt-screen and corrupts the frame
	// (e.g. kubeconfig-load warnings). klog is not controlled by slog/log, so it
	// must be redirected separately.
	klog.LogToStderr(false)
	klog.SetOutput(w)
}

// tuiLogWriter returns a writer for $HOME/.config/ida/ida.log, or io.Discard if
// the file cannot be opened. It NEVER returns stderr, so the TUI alt-screen can
// never be corrupted by log output.
func tuiLogWriter() io.Writer {
	home, err := os.UserHomeDir()
	if err != nil {
		return io.Discard
	}
	logDir := filepath.Join(home, ".config", "ida")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return io.Discard
	}
	f, err := os.OpenFile(filepath.Join(logDir, "ida.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}

// runTUI is the default action when 'ida' is invoked with no subcommand.
//
// Resilience contract (opencode-style):
//   - A missing or invalid token does NOT prevent the TUI from starting.
//     The App renders a "not logged in" banner in the main pane.
//   - An openshell client that cannot be initialised does NOT prevent the TUI
//     from starting. The App renders a "cluster unreachable" message in the sidebar.
//   - In both degraded states the UI is fully interactive (q quits, tab
//     switches tabs, n opens the wizard if a token is present).
//   - When both auth and gateway are healthy the TUI operates normally.
//
// Auth separation (ADR-0010 / SECURITY-OPEN):
//   - ida's Keycloak token (bearer) is used ONLY for `agent launch` (launcher REST)
//     and the TUI inline login. It is NOT forwarded to openshell.
//   - openshell manages its own credentials under ~/.config/openshell/ (populated
//     by `openshell gateway login` or `gateway add`). ida does not read or pass
//     those credentials.
func runTUI(cmd *cobra.Command, _ []string) error {
	// Redirect all log output away from stderr before starting the Bubble Tea
	// alt-screen. Any slog or stdlib log call made after this point goes to
	// $HOME/.config/ida/ida.log (or io.Discard on failure), never to the
	// terminal. Non-TUI subcommands are unaffected because they never call this.
	redirectLogsForTUI()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("root: load config: %w", err)
	}

	// --- Auth: best-effort; failures become an in-UI banner ---
	store, storeErr := auth.NewTokenStore(cfg.KeycloakRealmURL, cfg.KeycloakClientID, cfg.CAFile, cfg.InsecureSkipVerify)
	var bearer, authErrMsg string
	if storeErr != nil {
		authErrMsg = fmt.Sprintf("token store unavailable: %v", storeErr)
		slog.Warn("runTUI: token store error", "error", storeErr)
	} else {
		var tokErr error
		bearer, tokErr = store.AccessToken(cmd.Context())
		if tokErr != nil {
			authErrMsg = fmt.Sprintf("no valid token — run 'ida login' first (%v)", tokErr)
			slog.Info("runTUI: no valid token; launching TUI in unauthenticated state")
		}
	}

	// --- OpenShell client: best-effort; failures become a sidebar banner ---
	// Auth note: openshell uses its own credentials from ~/.config/openshell/.
	// ida does NOT forward the Keycloak bearer token to openshell.
	gw := openshell.GatewayConfig{
		Endpoint: cfg.OpenShellGatewayEndpoint,
		Name:     cfg.OpenShellGateway,
		Insecure: cfg.OpenShellGatewayInsecure,
	}
	oshCli := openshell.New(cfg.OpenShellBin, gw, cfg.SandboxNamespace, openshell.NewExecRunner())
	// oshCli is always non-nil (the gateway may still be unreachable at runtime;
	// List errors flow to sandboxesLoadedMsg.err → footer status, not a hard exit).
	var clusterErrMsg string

	jitCli, err := api.NewJitClient(cfg.JitURL, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("root: jit client: %w", err)
	}
	launcher, err := api.NewLauncherClient(cfg.LauncherURL, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("root: launcher client: %w", err)
	}
	giteaCli, err := api.NewGiteaClient(cfg.GiteaURL, cfg.GiteaToken, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("root: gitea client: %w", err)
	}

	// --- Kube client: best-effort; failures degrade the Logs tab, never abort ---
	// The kube client is used only for streaming harness pod logs in the Logs tab.
	// If kubeconfig is absent or invalid, kubeCli is nil and the Logs tab shows
	// a "kube unavailable" error banner rather than panicking.
	kubeCli, kubeErr := kube.NewClient(cfg.HarnessNamespace, cfg.Kubeconfig)
	if kubeErr != nil {
		slog.Warn("runTUI: kube client unavailable; Logs tab will show error", "error", kubeErr)
		kubeCli = nil
	}

	// store is nil when storeErr != nil; NewApp handles nil gracefully (inline
	// login is skipped and the footer cue remains).
	var tuiStore *auth.TokenStore
	if storeErr == nil {
		tuiStore = store
	}
	app := tui.NewApp(cfg, oshCli, jitCli, launcher, giteaCli, kubeCli, bearer, authErrMsg, clusterErrMsg, tuiStore)

	// No mouse capture: the TUI handles no MouseMsg, and WithMouseCellMotion only
	// steals the terminal's native click-drag selection/copy. Keep AltScreen.
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("root: tui: %w", err)
	}
	return nil
}
