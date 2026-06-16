package tui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/oauth2"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/auth"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// Tab indices.
const (
	TabOverview  = 0
	TabApprovals = 1
	TabReceipt   = 2
	TabLogs      = 3
	TabShell     = 4

	tabCount = 5
)

var tabNames = [tabCount]string{"Overview", "Approvals", "Receipt", "Logs", "Shell"}

// refreshInterval controls how often sandboxes and JIT sessions are re-fetched.
const refreshInterval = 30 * time.Second

// App is the root bubbletea model. It owns the sidebar, all tab models, and
// coordinates async data loading.
//
// Design note (opencode-style resilience):
//   - osh and bearer may both be nil/empty when the TUI is launched without
//     a valid token or reachable gateway. The App renders a clear in-UI banner
//     in those cases instead of refusing to start.
//   - All backend calls check their dependencies before executing and return a
//     friendly error message rather than panicking.
type App struct {
	cfg        *config.Config
	osh        *openshell.Client // nil when gateway is unreachable or not configured
	jitCli     *api.JitClient
	launcher   *api.LauncherClient
	giteaCli   *api.GiteaClient
	bearer     string          // current Keycloak access token; may be empty
	tokenStore *auth.TokenStore // nil when store could not be built

	// authStatus is non-empty when there is no valid token.
	authStatus string
	// clusterStatus is non-empty when the openshell gateway could not be reached.
	clusterStatus string

	// layout
	width  int
	height int

	// child models
	sidebar   Sidebar
	overview  Overview
	approvals ApprovalsTab
	receipt   ReceiptTab
	logs      LogsTab
	shellTab  ShellTab
	wizard    *Wizard
	login     *LoginForm
	spinner   spinner.Model

	// state
	activeTab    int
	loading      bool
	statusMsg    string
	statusIsErr  bool
	selectedName string // name of the currently selected sandbox
}

// NewApp constructs the root App model. It does not perform any I/O.
//
// osh may be nil (gateway unreachable or not yet initialised).
// bearer may be empty (user not authenticated).
// clusterErr is an optional human-readable reason the openshell client could not be
// created; it is shown in the sidebar.
// authErr is an optional human-readable reason the token is unavailable; it is
// shown as a banner in the main pane.
// tokenStore may be nil when the store could not be constructed; in that case
// inline login is disabled (the "ida login" footer cue remains).
func NewApp(
	cfg *config.Config,
	osh *openshell.Client,
	jitCli *api.JitClient,
	launcher *api.LauncherClient,
	giteaCli *api.GiteaClient,
	bearer string,
	authErr string,
	clusterErr string,
	tokenStore *auth.TokenStore,
) App {
	sp := spinner.New()
	sp.Spinner = spinner.Dot

	lf := newLoginForm()

	// Open the inline login form at startup when:
	//   - there is no valid token (bearer is empty), AND
	//   - Keycloak is configured (so an ROPC grant is possible), AND
	//   - the token store is available (so the resulting token can be persisted).
	keycloakConfigured := cfg != nil && cfg.KeycloakRealmURL != "" && cfg.KeycloakClientID != ""
	if bearer == "" && keycloakConfigured && tokenStore != nil {
		lf.Open()
	}

	return App{
		cfg:           cfg,
		osh:           osh,
		jitCli:        jitCli,
		launcher:      launcher,
		giteaCli:      giteaCli,
		bearer:        bearer,
		tokenStore:    tokenStore,
		authStatus:    authErr,
		clusterStatus: clusterErr,
		sidebar:       NewSidebar(28, 20),
		overview:      NewOverview(60, 20),
		approvals:     NewApprovalsTab(60, 20),
		receipt:       NewReceiptTab(60, 20),
		logs:          NewLogsTab(60, 20),
		shellTab:      NewShellTab(60, 20),
		wizard:        NewWizard(),
		login:         lf,
		spinner:       sp,
		activeTab:     TabOverview,
	}
}

// Init implements tea.Model. It kicks off the first sandbox list load and the
// periodic refresh timer. When the openshell client is nil the sandbox load command
// returns an error message immediately rather than panicking.
func (a App) Init() tea.Cmd {
	return tea.Batch(
		a.loadSandboxesCmd(),
		tickCmd(refreshInterval),
		a.spinner.Tick,
	)
}

// Update implements tea.Model.
func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// Login form takes precedence over everything else at startup.
	// Route ALL messages to the login form while it is active so keystrokes
	// never leak to the sidebar/shell/wizard.
	if a.login.Active() {
		cmd := a.login.Update(msg)
		cmds = append(cmds, cmd)
		return a, tea.Batch(cmds...)
	}

	// Handle messages produced by the login sub-model (emitted after the form
	// closes so the login field is no longer active when we process them).
	switch m := msg.(type) {
	case loginSubmittedMsg:
		// User submitted credentials — fire off the ROPC login cmd.
		cmds = append(cmds, a.doLoginCmd(m.username, m.password))
		return a, tea.Batch(cmds...)

	case loginAbortedMsg:
		// User pressed Esc — skip login and show the dashboard with the
		// existing footer cue (authStatus is unchanged).
		return a, nil

	case loginResultMsg:
		if m.err != nil {
			// Login failed: show error in form description and reopen.
			a.login.SetError(m.err.Error())
			a.login.Open()
			return a, nil
		}
		// Login succeeded: persist token, update bearer, clear auth status.
		tok := &oauth2.Token{
			AccessToken:  m.tok.accessToken,
			RefreshToken: m.tok.refreshToken,
			Expiry:       m.tok.expiry,
			TokenType:    m.tok.tokenType,
		}
		if a.tokenStore != nil {
			if saveErr := a.tokenStore.Save(tok); saveErr != nil {
				slog.Warn("tui: failed to persist login token", "error", saveErr)
			}
		}
		a.bearer = tok.AccessToken
		a.authStatus = ""
		a.setStatus("logged in", false)
		return a, nil
	}

	// Wizard intercepts all input when active.
	if a.wizard.Active() {
		cmd := a.wizard.Update(msg)
		cmds = append(cmds, cmd)
		return a, tea.Batch(cmds...)
	}

	switch m := msg.(type) {

	case tea.WindowSizeMsg:
		a.width = m.Width
		a.height = m.Height
		a.reflow()

	case tea.KeyMsg:
		// When the Shell tab is active, route all keystrokes to the embedded
		// terminal EXCEPT ctrl+b (escape back to dashboard).
		if a.activeTab == TabShell {
			if escape := a.shellTab.HandleKey(m); escape {
				// ctrl+b: stop the session and return to Overview.
				prev := TabShell
				a.activeTab = TabOverview
				cmds = append(cmds, a.onTabSwitch(prev)...)
			}
			// Do not fall through to the global handler while Shell is active.
			return a, tea.Batch(cmds...)
		}
		cmds = append(cmds, a.handleKey(m)...)

	case tickMsg:
		cmds = append(cmds, a.loadSandboxesCmd(), tickCmd(refreshInterval))

	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spinner, cmd = a.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case sandboxesLoadedMsg:
		a.loading = false
		if m.err != nil {
			a.setStatus("Failed to load sandboxes: "+m.err.Error(), true)
		} else {
			a.sidebar.SetSandboxes(m.sandboxes)
			a.setStatus(fmt.Sprintf("Loaded %d sandbox(es)", len(m.sandboxes)), false)
			a.syncSelectedSandbox()
		}

	case jitLoadedMsg:
		if m.err != nil {
			a.approvals.SetError(m.err)
		} else {
			a.approvals.SetSessions(m.sessions)
		}

	case jitDetailLoadedMsg:
		if m.err != nil {
			// Fail-closed: if the scope cannot be loaded, do not open the merge
			// dialog. Surface the error in the approvals tab and status bar.
			a.approvals.SetError(m.err)
			a.setStatus("Cannot load JIT scope; merge blocked: "+m.err.Error(), true)
		} else {
			// Only open the confirm dialog once we have verified scope data.
			a.approvals.RequestMerge(m.detail.PRURL, m.detail)
		}

	case receiptLoadedMsg:
		if m.err != nil {
			a.receipt.SetError(m.err)
		} else {
			a.receipt.SetReceipt(&m.receipt)
		}

	case launchedMsg:
		a.loading = false
		if m.err != nil {
			a.setStatus("Launch failed: "+m.err.Error(), true)
		} else {
			a.setStatus("Sandbox "+m.response.SandboxName+" launched", false)
			// Reload sandbox list.
			cmds = append(cmds, a.loadSandboxesCmd())
		}

	case mergedMsg:
		if m.err != nil {
			a.setStatus("Merge failed: "+m.err.Error(), true)
		} else {
			a.setStatus("PR merged successfully", false)
			cmds = append(cmds, a.loadJitCmd())
		}

	case wizardDoneMsg:
		if m.confirmed {
			cmds = append(cmds, a.launchCmd(m.req))
		}

	case attachFinishedMsg:
		if m.err != nil {
			a.setStatus(fmt.Sprintf("attach to %s failed: %s", m.name, m.err.Error()), true)
		} else {
			a.setStatus(fmt.Sprintf("detached from %s", m.name), false)
		}
		// Force a full repaint so the dashboard redraws cleanly after the
		// terminal was taken over by the exec session.
		cmds = append(cmds, tea.ClearScreen)

	case shellRedrawMsg:
		// Only flip connected for the CURRENT session (ignore stale-gen output
		// from a session that was Stop()'d when switching tabs).
		if m.gen == a.shellTab.gen {
			a.shellTab.connected = true
		}
		// Re-issue the wait Cmd on the SAME channel the event came from — this
		// keeps each session's reader alive until that session's exit is
		// delivered, even after we've moved on to a newer session.
		if m.ch != nil {
			cmds = append(cmds, waitForShellRedraw(m.ch))
		}

	case shellExitMsg:
		// Ignore exits from stale sessions (an old goroutine ending after the
		// user switched away and a new session started). Only the current
		// session's exit updates state / status.
		if m.gen == a.shellTab.gen {
			a.shellTab.HandleExitMsg(m)
			if m.err != nil && !isContextCanceled(m.err) {
				a.setStatus(fmt.Sprintf("shell %s: %s", m.name, m.err.Error()), true)
			} else if m.err == nil {
				a.setStatus(fmt.Sprintf("shell session for %s ended", m.name), false)
			}
		}

	case logLineMsg:
		a.logs.AppendLine(m.line)

	case errMsg:
		a.setStatus(m.Error(), true)
	}

	// Forward relevant messages to tab models.
	switch msg.(type) {
	case tea.KeyMsg:
		cmd := a.sidebar.Update(msg)
		cmds = append(cmds, cmd)
		a.syncSelectedSandbox()
	}

	// Approvals tab gets key events.
	if a.activeTab == TabApprovals {
		cmd, mergeResult := a.approvals.Update(msg)
		cmds = append(cmds, cmd)
		if mergeResult != nil {
			if mergeResult.confirmed {
				cmds = append(cmds, a.mergeCmd(mergeResult.prURL))
			}
		}
	}

	// Logs tab gets key events.
	if a.activeTab == TabLogs {
		cmd := a.logs.Update(msg)
		cmds = append(cmds, cmd)
	}

	return a, tea.Batch(cmds...)
}

// View implements tea.Model.
func (a App) View() string {
	// Login form takes over the entire screen while active (like the wizard).
	if a.login.Active() {
		return a.login.View()
	}

	if a.wizard.Active() {
		return a.wizard.View()
	}

	header := a.renderHeader()
	footer := a.renderFooter()
	body := a.renderBody()

	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

func (a *App) reflow() {
	sideW := 30
	mainW := a.width - sideW - 4
	bodyH := a.height - 4

	a.sidebar.SetSize(sideW, bodyH)
	a.overview.SetSize(mainW, bodyH)
	a.approvals.SetSize(mainW, bodyH)
	a.receipt.SetSize(mainW, bodyH)
	a.logs.SetSize(mainW, bodyH)
	a.shellTab.SetSize(mainW, bodyH)
}

func (a App) renderHeader() string {
	title := theme.TitleStyle.Render(" IDA ")
	tabs := a.renderTabs()
	spacer := strings.Repeat(" ", max(0, a.width-lipgloss.Width(title)-lipgloss.Width(tabs)-2))
	return lipgloss.JoinHorizontal(lipgloss.Top, title, spacer, tabs)
}

func (a App) renderTabs() string {
	var parts []string
	for i, name := range tabNames {
		if i == a.activeTab {
			parts = append(parts, theme.TabActiveStyle.Render(name))
		} else {
			parts = append(parts, theme.TabInactiveStyle.Render(name))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (a App) renderBody() string {
	sideW := 30
	mainW := a.width - sideW - 4

	_ = mainW
	sidebar := a.renderSidebar()
	main := a.renderMainPane()
	return lipgloss.JoinHorizontal(lipgloss.Top, sidebar, "  ", main)
}

// renderSidebar renders the sidebar. A cluster-unreachable condition is NOT
// stacked as an extra banner here (that would push the total layout past the
// terminal height and scroll the header off-screen); it is surfaced in the
// footer status line instead. The sidebar box is always exactly bodyH tall.
func (a App) renderSidebar() string {
	return a.sidebar.View()
}

// renderMainPane renders the active tab content. When the user is not
// authenticated it shows a prominent, centered, bordered "not logged in"
// banner in the main pane instead of the tab content.
// renderMainPane renders the active tab. The gateway- and jit-backed tabs
// (Overview/Approvals/Receipt/Logs/Shell) do NOT require a Keycloak token, so a
// missing token must NOT mask them — the not-logged-in cue is shown in the
// footer instead (only `agent launch` needs a token).
func (a App) renderMainPane() string {
	return a.renderActiveTab()
}

func (a App) renderActiveTab() string {
	switch a.activeTab {
	case TabOverview:
		return a.overview.View()
	case TabApprovals:
		return a.approvals.View()
	case TabReceipt:
		return a.receipt.View()
	case TabLogs:
		return a.logs.View()
	case TabShell:
		return a.shellTab.View()
	default:
		return ""
	}
}

func (a App) renderFooter() string {
	var parts []string
	if a.loading {
		parts = append(parts, a.spinner.View()+" loading")
	}
	status := a.statusMsg
	if a.statusIsErr {
		status = theme.ErrorStyle.Render(status)
	} else {
		status = theme.MutedStyle.Render(status)
	}
	parts = append(parts, status)

	// Non-blocking not-logged-in cue (only `launch` needs a token).
	if a.authStatus != "" {
		parts = append(parts, theme.WarningStyle.Render("⚠ not logged in — run 'ida login'"))
	}

	keys := theme.KeyStyle.Render("n") + theme.MutedStyle.Render(":new  ") +
		theme.KeyStyle.Render("5") + theme.MutedStyle.Render(":shell  ") +
		theme.KeyStyle.Render("ctrl+b") + theme.MutedStyle.Render(":back  ") +
		theme.KeyStyle.Render("tab") + theme.MutedStyle.Render(":switch  ") +
		theme.KeyStyle.Render("q") + theme.MutedStyle.Render(":quit")

	left := strings.Join(parts, "  ")
	spacer := strings.Repeat(" ", max(0, a.width-lipgloss.Width(left)-lipgloss.Width(keys)-2))
	return theme.FooterStyle.
		Width(a.width).
		Render(lipgloss.JoinHorizontal(lipgloss.Bottom, left, spacer, keys))
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

func (a *App) handleKey(m tea.KeyMsg) []tea.Cmd {
	switch m.String() {
	case "q", "ctrl+c":
		// Ensure any active shell session is cleaned up before quitting.
		a.shellTab.Stop()
		return []tea.Cmd{tea.Quit}
	case "tab":
		prev := a.activeTab
		a.activeTab = (a.activeTab + 1) % tabCount
		return a.onTabSwitch(prev)
	case "shift+tab":
		prev := a.activeTab
		a.activeTab = (a.activeTab - 1 + tabCount) % tabCount
		return a.onTabSwitch(prev)
	case "1":
		prev := a.activeTab
		a.activeTab = TabOverview
		return a.onTabSwitch(prev)
	case "2":
		prev := a.activeTab
		a.activeTab = TabApprovals
		return a.onTabSwitch(prev)
	case "3":
		prev := a.activeTab
		a.activeTab = TabReceipt
		return a.onTabSwitch(prev)
	case "4":
		prev := a.activeTab
		a.activeTab = TabLogs
		return a.onTabSwitch(prev)
	case "5":
		prev := a.activeTab
		a.activeTab = TabShell
		return a.onTabSwitch(prev)
	case "n":
		a.wizard.Open()
	case "enter":
		if a.activeTab == TabApprovals {
			if s := a.approvals.SelectedSession(); s != nil && s.PRURL != "" && s.ID != "" {
				// Fetch the full JIT detail first; RequestMerge is called only after
				// the detail arrives (fail-closed: if detail load fails, no dialog opens).
				return []tea.Cmd{a.loadJitDetailCmd(s.ID)}
			}
		}
	case "s":
		// 's' now jumps to the Shell tab (the old full-screen tea.Exec path has
		// been replaced by the embedded terminal in TabShell).
		prev := a.activeTab
		a.activeTab = TabShell
		return a.onTabSwitch(prev)
	case "r":
		return []tea.Cmd{a.loadSandboxesCmd()}
	}
	return nil
}

// onTabSwitch is called whenever the active tab changes. prev is the tab index
// that was active before the switch. It returns any tea.Cmd needed to kick off
// async work for the newly active tab.
func (a *App) onTabSwitch(prev int) []tea.Cmd {
	var cmds []tea.Cmd

	// Leaving the Shell tab — stop the session only if switching to a different tab.
	if prev == TabShell && a.activeTab != TabShell {
		a.shellTab.Stop()
	}

	switch a.activeTab {
	case TabApprovals:
		// Trigger JIT load.

	case TabReceipt:
		if s := a.approvals.SelectedSession(); s != nil {
			a.receipt.SetLoading(true)
		}

	case TabShell:
		// Start (or resume) the embedded terminal session for the selected sandbox.
		if a.osh != nil {
			sb := a.sidebar.Selected()
			if sb != nil {
				cmd := a.shellTab.Start(a.osh, sb.Name)
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
			} else {
				a.shellTab.err = nil // clear prior errors; View will show "select a sandbox"
			}
		} else {
			a.shellTab.err = fmt.Errorf("gateway unreachable: no openshell client")
		}
	}

	return cmds
}

// ---------------------------------------------------------------------------
// State sync helpers
// ---------------------------------------------------------------------------

func (a *App) syncSelectedSandbox() {
	sb := a.sidebar.Selected()
	a.overview.SetSandbox(sb)
	if sb != nil && sb.Name != a.selectedName {
		a.selectedName = sb.Name
		a.logs.SetSandbox(sb.Name)
	}
}

func (a *App) setStatus(msg string, isErr bool) {
	a.statusMsg = msg
	a.statusIsErr = isErr
}

// ---------------------------------------------------------------------------
// Async tea.Cmd constructors
// ---------------------------------------------------------------------------

// loadSandboxesCmd returns a Cmd that lists sandboxes. When the openshell client
// is nil (gateway unreachable or not configured) it returns a sandboxesLoadedMsg
// carrying a friendly error instead of panicking.
func (a App) loadSandboxesCmd() tea.Cmd {
	if a.osh == nil {
		return func() tea.Msg {
			return sandboxesLoadedMsg{err: fmt.Errorf("cluster unreachable: no kube client")}
		}
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var owner string
		if a.cfg != nil {
			owner = a.cfg.Owner
		}
		sandboxes, err := a.osh.List(ctx, owner)
		return sandboxesLoadedMsg{sandboxes: sandboxes, err: err}
	}
}

func (a App) loadJitCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		sessions, err := a.jitCli.List(ctx, a.selectedName, "")
		return jitLoadedMsg{sessions: sessions, err: err}
	}
}

func (a App) launchCmd(req api.LaunchRequest) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := a.launcher.Launch(ctx, req, a.bearer)
		return launchedMsg{response: resp, err: err}
	}
}

func (a App) mergeCmd(prURL string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err := a.giteaCli.MergePR(ctx, prURL)
		return mergedMsg{prURL: prURL, err: err}
	}
}

// loadJitDetailCmd fetches the full JIT detail for sessionID so that the merge
// confirm dialog can display the concrete scope before the user confirms.
// On any error the returned message carries a non-nil err and the caller MUST
// NOT open the dialog (fail-closed).
func (a App) loadJitDetailCmd(sessionID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		detail, err := a.jitCli.Detail(ctx, sessionID)
		return jitDetailLoadedMsg{detail: detail, err: err}
	}
}

// doLoginCmd performs an ROPC token grant using the credentials entered in the
// login form. It never logs the password — only a sanitised error is returned.
// If cfg or the required Keycloak fields are absent the cmd returns a
// loginResultMsg with an error immediately (fail-closed).
func (a App) doLoginCmd(username, password string) tea.Cmd {
	cfg := a.cfg
	return func() tea.Msg {
		if cfg == nil || cfg.KeycloakRealmURL == "" || cfg.KeycloakClientID == "" {
			return loginResultMsg{err: fmt.Errorf("keycloak not configured")}
		}
		pgCfg := auth.PasswordGrantConfig{
			RealmURL: cfg.KeycloakRealmURL,
			ClientID: cfg.KeycloakClientID,
			CAFile:   cfg.CAFile,
			Insecure: cfg.InsecureSkipVerify,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := auth.PasswordLogin(ctx, pgCfg, username, password)
		if err != nil {
			slog.Warn("tui: inline login failed", "error", err)
			return loginResultMsg{err: err}
		}
		expiry := result.Expiry
		if expiry.IsZero() {
			expiry = time.Now().Add(5 * time.Minute)
		}
		return loginResultMsg{
			tok: &loginResultToken{
				accessToken:  result.AccessToken,
				refreshToken: result.RefreshToken,
				expiry:       expiry,
				tokenType:    result.TokenType,
			},
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
