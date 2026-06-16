// Package theme defines the lipgloss colour palette and reusable styles for
// the ida-cli TUI. The palette uses a dark background with the NVIDIA green
// accent (#76B900).
package theme

import "github.com/charmbracelet/lipgloss"

// Colours — defined once; referenced by all styles below.
const (
	ColorBackground  = lipgloss.Color("#1A1A1A")
	ColorSurface     = lipgloss.Color("#242424")
	ColorBorder      = lipgloss.Color("#3A3A3A")
	ColorAccent      = lipgloss.Color("#76B900") // NVIDIA green
	ColorAccentDim   = lipgloss.Color("#4A7400")
	ColorTextPrimary = lipgloss.Color("#E8E8E8")
	ColorTextMuted   = lipgloss.Color("#808080")
	ColorSuccess     = lipgloss.Color("#76B900")
	ColorWarning     = lipgloss.Color("#F5A623")
	ColorError       = lipgloss.Color("#E05252")
	ColorInfo        = lipgloss.Color("#4FC3F7")
)

// Phase glyph map — used by sidebar to show Sandbox status.
var PhaseGlyph = map[string]string{
	// OpenShell Sandbox phases are derived from status.conditions[type=Ready].
	"Ready":        "●",
	"NotReady":     "○",
	"Provisioning": "◐",
	"Terminating":  "◐",
	// Generic pod-style phases (kept for completeness / other resources).
	"Pending":   "○",
	"Running":   "●",
	"Succeeded": "✓",
	"Failed":    "✗",
	"Unknown":   "?",
}

// PhaseColor returns the lipgloss colour for a given sandbox phase.
func PhaseColor(phase string) lipgloss.Color {
	switch phase {
	case "Ready", "Running":
		return ColorAccent
	case "Succeeded":
		return ColorSuccess
	case "Failed":
		return ColorError
	case "Pending", "Provisioning", "NotReady", "Terminating":
		return ColorWarning
	default:
		return ColorTextMuted
	}
}

// ---------------------------------------------------------------------------
// Reusable lipgloss styles
// ---------------------------------------------------------------------------

// AppStyle is the outermost container style.
var AppStyle = lipgloss.NewStyle().
	Background(ColorBackground)

// SidebarStyle frames the sandbox list panel.
var SidebarStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(ColorBorder).
	Padding(0, 1)

// MainPanelStyle frames the main content area.
var MainPanelStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(ColorBorder).
	Padding(0, 1)

// TitleStyle renders the application title.
var TitleStyle = lipgloss.NewStyle().
	Foreground(ColorAccent).
	Bold(true).
	Padding(0, 1)

// SectionTitleStyle renders section headings inside a panel.
var SectionTitleStyle = lipgloss.NewStyle().
	Foreground(ColorAccent).
	Bold(true).
	Underline(true)

// SelectedItemStyle highlights the focused item in a list.
var SelectedItemStyle = lipgloss.NewStyle().
	Foreground(ColorBackground).
	Background(ColorAccent).
	Padding(0, 1)

// NormalItemStyle is the un-focused list item.
var NormalItemStyle = lipgloss.NewStyle().
	Foreground(ColorTextPrimary).
	Padding(0, 1)

// MutedStyle renders secondary information.
var MutedStyle = lipgloss.NewStyle().
	Foreground(ColorTextMuted)

// SuccessStyle renders success messages.
var SuccessStyle = lipgloss.NewStyle().
	Foreground(ColorSuccess).
	Bold(true)

// ErrorStyle renders error messages.
var ErrorStyle = lipgloss.NewStyle().
	Foreground(ColorError).
	Bold(true)

// WarningStyle renders warnings.
var WarningStyle = lipgloss.NewStyle().
	Foreground(ColorWarning)

// InfoStyle renders informational text.
var InfoStyle = lipgloss.NewStyle().
	Foreground(ColorInfo)

// FooterStyle renders the help bar at the bottom of the screen.
var FooterStyle = lipgloss.NewStyle().
	Foreground(ColorTextMuted).
	Background(ColorSurface).
	Padding(0, 1)

// TabActiveStyle renders the currently selected tab label.
var TabActiveStyle = lipgloss.NewStyle().
	Foreground(ColorBackground).
	Background(ColorAccent).
	Bold(true).
	Padding(0, 2)

// TabInactiveStyle renders non-selected tab labels.
var TabInactiveStyle = lipgloss.NewStyle().
	Foreground(ColorTextMuted).
	Padding(0, 2)

// KeyStyle renders key bindings in the footer.
var KeyStyle = lipgloss.NewStyle().
	Foreground(ColorAccent).
	Bold(true)

// AuthBannerStyle renders the "not logged in" banner in the main pane. It uses
// a visible rounded border in the error colour so it stands out even on the
// initial (blank) screen.
var AuthBannerStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(ColorError).
	Foreground(ColorError).
	Bold(true).
	Padding(1, 4)

// BadgeStyle renders small inline status badges (e.g. phase, scope).
var BadgeStyle = lipgloss.NewStyle().
	Padding(0, 1).
	Bold(true)

// BadgeForPhase returns a styled phase badge.
func BadgeForPhase(phase string) string {
	glyph, ok := PhaseGlyph[phase]
	if !ok {
		glyph = "?"
	}
	return BadgeStyle.
		Foreground(PhaseColor(phase)).
		Render(glyph + " " + phase)
}

// BadgeForScope returns a styled scope badge.
func BadgeForScope(scope string) string {
	var color lipgloss.Color
	switch scope {
	case "admin":
		color = ColorError
	case "read-write":
		color = ColorWarning
	default:
		color = ColorInfo
	}
	return BadgeStyle.Foreground(color).Render(scope)
}
