package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	tea "github.com/charmbracelet/bubbletea"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// ApprovalsTab manages the approvals list and the inline PR-merge confirm dialog.
type ApprovalsTab struct {
	sessions       []api.JitSession
	selected       int
	showForm       bool
	mergeForm      *huh.Form
	pendingPR      string
	mergeConfirmed bool // bound to the huh Confirm widget; stored as field to outlive RequestMerge call
	lastErr        error
	width          int
	height         int
}

// NewApprovalsTab constructs an ApprovalsTab.
func NewApprovalsTab(width, height int) ApprovalsTab {
	return ApprovalsTab{width: width, height: height}
}

// SetSessions replaces the displayed JIT sessions.
func (a *ApprovalsTab) SetSessions(sessions []api.JitSession) {
	a.sessions = sessions
	if a.selected >= len(sessions) {
		a.selected = 0
	}
}

// SetSize updates the dimensions.
func (a *ApprovalsTab) SetSize(width, height int) {
	a.width = width
	a.height = height
}

// SetError stores a display error (cleared on next SetSessions call).
func (a *ApprovalsTab) SetError(err error) {
	a.lastErr = err
}

// SelectedSession returns the currently highlighted JIT session or nil.
func (a *ApprovalsTab) SelectedSession() *api.JitSession {
	if len(a.sessions) == 0 || a.selected >= len(a.sessions) {
		return nil
	}
	s := a.sessions[a.selected]
	return &s
}

// RequestMerge opens the huh confirm dialog for the selected session's PR, showing
// the concrete JIT scope from detail so the approver gives informed consent.
// detail MUST be fetched successfully before calling this method; if scope
// loading failed, the caller must NOT call RequestMerge (fail-closed).
func (a *ApprovalsTab) RequestMerge(prURL string, detail api.JitDetail) {
	a.pendingPR = prURL
	a.mergeConfirmed = false
	a.showForm = true

	desc := buildScopeDescription(prURL, detail)

	a.mergeForm = huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Approve JIT PR").
				Description(desc).
				Affirmative("Merge PR").
				Negative("Cancel").
				Value(&a.mergeConfirmed),
		),
	)
}

// buildScopeDescription formats the confirmed JIT scope into the dialog body
// so the approver sees the exact access being granted before confirming.
func buildScopeDescription(prURL string, d api.JitDetail) string {
	var b strings.Builder
	b.WriteString("PR: " + prURL + "\n\n")
	b.WriteString(fmt.Sprintf("Namespace:  %s\n", d.Namespace))
	b.WriteString(fmt.Sprintf("Verbs:      %s\n", strings.Join(d.Verbs, ", ")))
	b.WriteString(fmt.Sprintf("Resources:  %s\n", strings.Join(d.Resources, ", ")))
	b.WriteString(fmt.Sprintf("Duration:   %d min\n", d.DurationMinutes))
	if len(d.PolicyDelta) > 0 {
		b.WriteString("PolicyDelta:\n")
		for _, pd := range d.PolicyDelta {
			b.WriteString(fmt.Sprintf("  %s:%d\n", pd.Host, pd.Port))
		}
	}
	if d.Justification != "" {
		b.WriteString(fmt.Sprintf("Reason:     %s\n", d.Justification))
	}
	b.WriteString("\nThis action is irreversible.")
	return b.String()
}

// FormActive returns true when the confirm dialog is visible.
func (a *ApprovalsTab) FormActive() bool {
	return a.showForm
}

// Update handles key events for list navigation and form interaction.
// Returns a tea.Cmd and a bool indicating whether a merge was confirmed.
func (a *ApprovalsTab) Update(msg tea.Msg) (tea.Cmd, *confirmMergeMsg) {
	if a.showForm && a.mergeForm != nil {
		form, cmd := a.mergeForm.Update(msg)
		if f, ok := form.(*huh.Form); ok {
			a.mergeForm = f
		}
		if a.mergeForm.State == huh.StateCompleted {
			a.showForm = false
			// mergeConfirmed is bound to the huh Confirm widget via &a.mergeConfirmed
			// so its value reflects the user's choice at form completion.
			result := &confirmMergeMsg{
				prURL:     a.pendingPR,
				confirmed: a.mergeConfirmed,
			}
			a.pendingPR = ""
			a.mergeForm = nil
			return cmd, result
		}
		if a.mergeForm.State == huh.StateAborted {
			a.showForm = false
			a.mergeForm = nil
			a.pendingPR = ""
		}
		return cmd, nil
	}

	if kMsg, ok := msg.(tea.KeyMsg); ok && !a.showForm {
		switch kMsg.String() {
		case "up", "k":
			if a.selected > 0 {
				a.selected--
			}
		case "down", "j":
			if a.selected < len(a.sessions)-1 {
				a.selected++
			}
		}
	}
	return nil, nil
}

// View renders the approvals tab.
func (a ApprovalsTab) View() string {
	if a.showForm && a.mergeForm != nil {
		return theme.MainPanelStyle.
			Width(a.width).
			Height(a.height).
			Render(a.mergeForm.View())
	}

	var b strings.Builder
	b.WriteString(theme.SectionTitleStyle.Render("JIT Approvals") + "\n\n")

	if a.lastErr != nil {
		b.WriteString(theme.ErrorStyle.Render("Error: "+a.lastErr.Error()) + "\n\n")
	}

	if len(a.sessions) == 0 {
		b.WriteString(theme.MutedStyle.Render("  No pending JIT sessions.\n"))
	} else {
		for i, s := range a.sessions {
			prefix := "  "
			style := theme.NormalItemStyle
			if i == a.selected {
				prefix = "> "
				style = theme.SelectedItemStyle
			}
			expires := s.ExpiresAt.Format(time.RFC3339)
			line := fmt.Sprintf("%s[%s] %s  expires: %s", prefix, s.State, s.ID, expires)
			b.WriteString(style.Render(line) + "\n")
			if s.PRURL != "" {
				b.WriteString(theme.MutedStyle.Render("       PR: "+s.PRURL) + "\n")
			}
		}
	}

	b.WriteString("\n" + theme.MutedStyle.Render("enter: merge PR  •  j/k: navigate"))

	return theme.MainPanelStyle.
		Width(a.width).
		Height(a.height).
		Render(b.String())
}
