// Package tui contains all bubbletea model implementations and message types
// for the ida-cli interactive TUI.
package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
)

// ---------------------------------------------------------------------------
// tea.Msg types — all async results and signals flow through these.
// ---------------------------------------------------------------------------

// sandboxesLoadedMsg carries the result of listing sandboxes via openshell CLI.
type sandboxesLoadedMsg struct {
	sandboxes []openshell.Sandbox
	err       error
}

// sandboxDeletedMsg signals that a sandbox has been deleted.
type sandboxDeletedMsg struct {
	name string
	err  error
}

// jitLoadedMsg carries the result of listing JIT sessions for the selected sandbox.
type jitLoadedMsg struct {
	sessions []api.JitSession
	err      error
}

// jitDetailLoadedMsg carries the detail for a single JIT session.
type jitDetailLoadedMsg struct {
	detail api.JitDetail
	err    error
}

// receiptLoadedMsg carries the receipt for a completed JIT session.
type receiptLoadedMsg struct {
	receipt api.JitReceipt
	err     error
}

// summaryLoadedMsg carries the summary for a JIT session.
type summaryLoadedMsg struct {
	summary api.JitSummary
	err     error
}

// launchedMsg signals that a new sandbox was successfully launched.
type launchedMsg struct {
	response api.LaunchResponse
	err      error
}

// mergedMsg signals the outcome of a Gitea PR merge attempt.
type mergedMsg struct {
	prURL string
	err   error
}

// errMsg wraps a generic error for display in the UI.
type errMsg struct {
	err error
}

func (e errMsg) Error() string { return e.err.Error() }

// tickMsg is emitted by the periodic refresh timer.
type tickMsg struct {
	t time.Time
}

// logLineMsg carries a single log line from a streaming pod log. gen tags the
// stream generation so a stale goroutine's messages (after a tab switch) are
// ignored rather than corrupting a newer stream (mirrors shellExitMsg.gen).
type logLineMsg struct {
	line string
	gen  int
}

// logEOFMsg signals the end of a pod log stream. gen tags the stream generation.
type logEOFMsg struct {
	err error
	gen int
}

// tabChangedMsg signals that the user switched to a different tab.
type tabChangedMsg struct {
	tab int
}

// sidebarSelectionMsg signals that the user selected a different sandbox in the sidebar.
type sidebarSelectionMsg struct {
	sandbox openshell.Sandbox
}

// wizardDoneMsg signals that the launch wizard has completed (confirm or cancel).
type wizardDoneMsg struct {
	req       api.LaunchRequest
	confirmed bool
}

// attachFinishedMsg is returned by the tea.Exec shell command when the user
// exits the interactive session. err is nil on a clean exit.
type attachFinishedMsg struct {
	name string
	err  error
}

// confirmMergeMsg signals that the user confirmed (or cancelled) the PR merge dialog.
type confirmMergeMsg struct {
	prURL     string
	confirmed bool
}

// loginResultMsg carries the outcome of an attempted ROPC login.
// On success tok is non-nil and err is nil.
// On failure tok is nil and err describes the problem.
type loginResultMsg struct {
	tok *loginResultToken
	err error
}

// loginResultToken holds the access token fields returned by a successful ROPC
// grant. Using a dedicated struct avoids importing golang.org/x/oauth2 into the
// messages package while keeping all fields strongly typed.
type loginResultToken struct {
	accessToken  string
	refreshToken string
	expiry       time.Time
	tokenType    string
}

// ---------------------------------------------------------------------------
// Constructors for async tea.Cmd helpers
// ---------------------------------------------------------------------------

// tickCmd emits a tickMsg after d duration.
func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{t: t}
	})
}
