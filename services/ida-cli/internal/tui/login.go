package tui

import (
	"github.com/charmbracelet/huh"
	tea "github.com/charmbracelet/bubbletea"
)

// LoginForm is an inline huh form that collects a username and password for
// an ROPC (Resource Owner Password Credentials) login without leaving the TUI.
//
// Design mirrors Wizard: an active bool guards all methods; Open() resets
// state and rebuilds the form; Update() delegates to huh and emits result
// messages when the form completes or is aborted.
type LoginForm struct {
	form     *huh.Form
	active   bool
	errMsg   string // non-empty when a previous login attempt failed

	// bound form values
	username string
	password string
}

// newLoginForm constructs a LoginForm in the inactive state.
func newLoginForm() *LoginForm {
	lf := &LoginForm{}
	lf.buildForm()
	return lf
}

// buildForm (re)constructs the huh form. Call on Open() or after an error to
// give the user a fresh form with the error message injected as a description.
func (lf *LoginForm) buildForm() {
	desc := "Enter your Keycloak credentials to authenticate."
	if lf.errMsg != "" {
		desc = "Login failed: " + lf.errMsg + "\n\nEnter your credentials to retry."
	}

	lf.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Username").
				Description(desc).
				Placeholder("alice").
				Value(&lf.username),
			huh.NewInput().
				Title("Password").
				EchoMode(huh.EchoModePassword).
				Value(&lf.password),
		),
	)
}

// Active returns true when the login form is open and should intercept input.
func (lf *LoginForm) Active() bool {
	if lf == nil {
		return false
	}
	return lf.active
}

// Open resets state and opens the login form. Any prior error message is kept
// so the user can see why they need to retry; call SetError before Open to set
// a new one.
func (lf *LoginForm) Open() {
	lf.username = ""
	lf.password = ""
	lf.buildForm()
	lf.active = true
}

// Close hides the form without emitting a result (used on Esc/abort).
func (lf *LoginForm) Close() {
	lf.active = false
	lf.errMsg = ""
}

// SetError stores an error message that will appear as form description on the
// next Open()/buildForm() call, giving the user context for why they need to
// retry.
func (lf *LoginForm) SetError(msg string) {
	lf.errMsg = msg
}

// Username returns the currently entered username (only meaningful after the
// form completes).
func (lf *LoginForm) Username() string { return lf.username }

// Password returns the currently entered password (only meaningful after the
// form completes).
func (lf *LoginForm) Password() string { return lf.password }

// Update forwards bubbletea messages to the underlying huh form.
//
// When the form completes (submitted) it returns a loginSubmittedMsg carrying
// the entered credentials so the caller can run the ROPC cmd.
// When the form is aborted (Esc) it closes the form and returns a
// loginAbortedMsg so the caller can fall through to the dashboard.
func (lf *LoginForm) Update(msg tea.Msg) tea.Cmd {
	if !lf.active || lf.form == nil {
		return nil
	}

	form, cmd := lf.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		lf.form = f
	}

	if lf.form.State == huh.StateCompleted {
		lf.active = false
		u, p := lf.username, lf.password
		return tea.Batch(cmd, func() tea.Msg {
			return loginSubmittedMsg{username: u, password: p}
		})
	}
	if lf.form.State == huh.StateAborted {
		lf.active = false
		lf.errMsg = ""
		return tea.Batch(cmd, func() tea.Msg {
			return loginAbortedMsg{}
		})
	}
	return cmd
}

// View renders the login form. Returns empty string when inactive.
func (lf *LoginForm) View() string {
	if !lf.active || lf.form == nil {
		return ""
	}
	return lf.form.View()
}

// ---------------------------------------------------------------------------
// Internal message types produced by LoginForm
// ---------------------------------------------------------------------------

// loginSubmittedMsg is emitted when the user submits the login form.
type loginSubmittedMsg struct {
	username string
	password string
}

// loginAbortedMsg is emitted when the user presses Esc to skip the login form.
type loginAbortedMsg struct{}
