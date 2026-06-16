package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// ---------------------------------------------------------------------------
// sandboxItem — implements bubbles/list.Item
// ---------------------------------------------------------------------------

// sandboxItem wraps an openshell.Sandbox for display in a bubbles list.
type sandboxItem struct {
	sb openshell.Sandbox
}

func (i sandboxItem) Title() string {
	glyph, ok := theme.PhaseGlyph[i.sb.Phase]
	if !ok {
		glyph = "?"
	}
	return lipgloss.NewStyle().
		Foreground(theme.PhaseColor(i.sb.Phase)).
		Render(glyph) + " " + i.sb.Name
}

func (i sandboxItem) Description() string {
	ttl := i.sb.TTLMinutes
	if ttl == "" {
		ttl = "?"
	}
	return fmt.Sprintf("%s  TTL: %sm", i.sb.Scope, ttl)
}

func (i sandboxItem) FilterValue() string { return i.sb.Name }

// ---------------------------------------------------------------------------
// Sidebar model
// ---------------------------------------------------------------------------

// Sidebar holds the bubbles list widget for the sandbox panel.
type Sidebar struct {
	list      list.Model
	sandboxes []openshell.Sandbox
	width     int
	height    int
}

// NewSidebar creates an empty Sidebar ready to receive sandbox data.
func NewSidebar(width, height int) Sidebar {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = theme.SelectedItemStyle
	delegate.Styles.SelectedDesc = theme.MutedStyle.Copy().
		Background(theme.ColorAccentDim).
		Foreground(theme.ColorBackground)

	l := list.New(nil, delegate, width, height)
	l.Title = "Sandboxes"
	l.Styles.Title = theme.TitleStyle
	l.SetShowHelp(false)
	l.SetFilteringEnabled(true)

	return Sidebar{list: l, width: width, height: height}
}

// SetSandboxes replaces the list contents with new data.
func (s *Sidebar) SetSandboxes(sandboxes []openshell.Sandbox) {
	s.sandboxes = sandboxes
	items := make([]list.Item, len(sandboxes))
	for i, sb := range sandboxes {
		items[i] = sandboxItem{sb: sb}
	}
	s.list.SetItems(items)
}

// Selected returns the currently highlighted Sandbox, or nil if the list is empty.
func (s *Sidebar) Selected() *openshell.Sandbox {
	if item := s.list.SelectedItem(); item != nil {
		if si, ok := item.(sandboxItem); ok {
			sb := si.sb
			return &sb
		}
	}
	return nil
}

// SetSize updates the sidebar dimensions.
func (s *Sidebar) SetSize(width, height int) {
	s.width = width
	s.height = height
	s.list.SetWidth(width)
	s.list.SetHeight(height)
}

// Update forwards bubbletea messages to the list widget.
func (s *Sidebar) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return cmd
}

// View renders the sidebar.
func (s Sidebar) View() string {
	return theme.SidebarStyle.
		Width(s.width).
		Height(s.height).
		Render(s.list.View())
}
