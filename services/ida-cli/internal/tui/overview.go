package tui

import (
	"fmt"
	"sort"
	"strings"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// Overview renders the Overview tab for the selected sandbox.
type Overview struct {
	sandbox *openshell.Sandbox
	width   int
	height  int
}

// NewOverview constructs an Overview model.
func NewOverview(width, height int) Overview {
	return Overview{width: width, height: height}
}

// SetSandbox updates the sandbox displayed by the Overview.
func (o *Overview) SetSandbox(sb *openshell.Sandbox) {
	o.sandbox = sb
}

// SetSize updates the dimensions of the overview panel.
func (o *Overview) SetSize(width, height int) {
	o.width = width
	o.height = height
}

// View renders the overview panel as a string.
//
// Two invariants are enforced:
//  1. Labels are rendered in deterministic sorted-key order so that the output
//     is stable across re-renders (prevents the TUI scrolling on every tick).
//  2. The rendered content is clamped to the panel's configured height: if
//     there are more label lines than available space, a "… (+N more)" trailer
//     replaces the excess rows so the panel never overflows its allotted height.
func (o Overview) View() string {
	if o.sandbox == nil {
		return theme.MutedStyle.Render("  Select a sandbox from the list on the left.")
	}

	sb := o.sandbox

	row := func(label, value string) string {
		return fmt.Sprintf("  %-16s %s",
			theme.MutedStyle.Render(label+":"),
			theme.NormalItemStyle.Render(value),
		)
	}

	// Build all lines before clamping.
	var lines []string

	lines = append(lines, theme.SectionTitleStyle.Render("Sandbox Overview"), "")
	lines = append(lines, row("Name", sb.Name))
	lines = append(lines, row("Namespace", sb.Namespace))
	lines = append(lines, row("Phase", theme.BadgeForPhase(sb.Phase)))
	lines = append(lines, row("Scope", theme.BadgeForScope(sb.Scope)))
	lines = append(lines, row("TTL (min)", sb.TTLMinutes))
	lines = append(lines, row("Owner", sb.Owner))

	if sb.Selector != "" {
		lines = append(lines, row("Selector", sb.Selector))
	}

	if hint := sb.AccessHint; hint != "" {
		lines = append(lines, "", theme.SectionTitleStyle.Render("Access Hint"), "")
		lines = append(lines, theme.InfoStyle.Render("  "+hint))
	}

	if len(sb.Labels) > 0 {
		lines = append(lines, "", theme.SectionTitleStyle.Render("Labels"), "")

		// Sort keys for deterministic output.
		keys := make([]string, 0, len(sb.Labels))
		for k := range sb.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Determine how many label rows fit in the remaining height.
		// o.height is the total pane height; subtract lines already accumulated
		// plus 1 for the lipgloss border/padding allocation.
		usedLines := len(lines)
		// Reserve at least 1 line for potential "… (+N more)" trailer.
		const trailerReserve = 1
		available := o.height - usedLines - trailerReserve
		if available < 1 {
			available = 1
		}

		shown := 0
		for _, k := range keys {
			if shown >= available && available < len(keys) {
				remaining := len(keys) - shown
				lines = append(lines, fmt.Sprintf("  … (+%d more)", remaining))
				break
			}
			lines = append(lines, fmt.Sprintf("  %s = %s",
				theme.MutedStyle.Render(k),
				theme.NormalItemStyle.Render(sb.Labels[k]),
			))
			shown++
		}
	}

	content := strings.Join(lines, "\n")

	return theme.MainPanelStyle.
		Width(o.width).
		Height(o.height).
		Render(content)
}
