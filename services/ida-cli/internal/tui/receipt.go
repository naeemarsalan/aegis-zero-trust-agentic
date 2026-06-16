package tui

import (
	"fmt"
	"strings"
	"time"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// ReceiptTab displays the outcome receipt for the selected JIT session.
type ReceiptTab struct {
	receipt *api.JitReceipt
	loading bool
	err     error
	width   int
	height  int
}

// NewReceiptTab constructs a ReceiptTab.
func NewReceiptTab(width, height int) ReceiptTab {
	return ReceiptTab{width: width, height: height}
}

// SetReceipt stores the receipt for display.
func (r *ReceiptTab) SetReceipt(receipt *api.JitReceipt) {
	r.receipt = receipt
	r.loading = false
	r.err = nil
}

// SetLoading marks the tab as loading.
func (r *ReceiptTab) SetLoading(v bool) {
	r.loading = v
}

// SetError stores a display error.
func (r *ReceiptTab) SetError(err error) {
	r.err = err
	r.loading = false
}

// SetSize updates the dimensions.
func (r *ReceiptTab) SetSize(width, height int) {
	r.width = width
	r.height = height
}

// View renders the receipt panel.
func (r ReceiptTab) View() string {
	var b strings.Builder
	b.WriteString(theme.SectionTitleStyle.Render("JIT Receipt") + "\n\n")

	switch {
	case r.loading:
		b.WriteString(theme.MutedStyle.Render("  Loading receipt..."))
	case r.err != nil:
		b.WriteString(theme.ErrorStyle.Render("Error: " + r.err.Error()))
	case r.receipt == nil:
		b.WriteString(theme.MutedStyle.Render("  Select a JIT session to view its receipt."))
	default:
		rc := r.receipt
		row := func(label, value string) {
			b.WriteString(fmt.Sprintf("  %-18s %s\n",
				theme.MutedStyle.Render(label+":"),
				theme.NormalItemStyle.Render(value),
			))
		}

		row("ID", rc.ID)
		row("State", rc.State)
		row("Outcome", outcomeStyle(rc.Outcome))
		row("Expires At", rc.ExpiresAt.Format(time.RFC3339))
		row("Denied Source", rc.DeniedSource)

		if len(rc.ToolScope) > 0 {
			b.WriteString("\n" + theme.SectionTitleStyle.Render("Tool Scope") + "\n")
			for _, t := range rc.ToolScope {
				b.WriteString(theme.MutedStyle.Render("  • ") + t + "\n")
			}
		}

		if len(rc.Allowed) > 0 {
			b.WriteString("\n" + theme.SuccessStyle.Render("Allowed") + "\n")
			for _, a := range rc.Allowed {
				b.WriteString(theme.SuccessStyle.Render("  ✓ ") + a + "\n")
			}
		}

		if len(rc.Denied) > 0 {
			b.WriteString("\n" + theme.ErrorStyle.Render("Denied") + "\n")
			for _, d := range rc.Denied {
				b.WriteString(theme.ErrorStyle.Render("  ✗ ") + d + "\n")
			}
		}

		if len(rc.Errors) > 0 {
			b.WriteString("\n" + theme.WarningStyle.Render("Errors") + "\n")
			for _, e := range rc.Errors {
				b.WriteString(theme.WarningStyle.Render("  ! ") + e + "\n")
			}
		}
	}

	return theme.MainPanelStyle.
		Width(r.width).
		Height(r.height).
		Render(b.String())
}

func outcomeStyle(outcome string) string {
	switch outcome {
	case "allow":
		return theme.SuccessStyle.Render(outcome)
	case "deny":
		return theme.ErrorStyle.Render(outcome)
	default:
		return theme.WarningStyle.Render(outcome)
	}
}
