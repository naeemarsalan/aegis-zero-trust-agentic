package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// LogsTab streams and displays pod log output.
//
// Each incoming line is parsed via ParseAgentLine (jsonl.go). Lines that match
// the frozen agent JSONL contract (jsonlSchema stream 2) are rendered as
// structured panels; raw/non-JSON lines are displayed as muted text. The
// viewport shows the accumulated panel stream, newest at the bottom.
type LogsTab struct {
	viewport    viewport.Model
	rendered    strings.Builder // accumulates rendered (lipgloss) strings
	streaming   bool
	err         error
	width       int
	height      int
	sandboxName string
}

// NewLogsTab constructs a LogsTab with the given dimensions.
func NewLogsTab(width, height int) LogsTab {
	vp := viewport.New(width, height-3)
	vp.Style = theme.MainPanelStyle
	return LogsTab{
		viewport: vp,
		width:    width,
		height:   height,
	}
}

// SetSandbox resets the log buffer for a new sandbox.
func (l *LogsTab) SetSandbox(name string) {
	if l.sandboxName == name {
		return
	}
	l.sandboxName = name
	l.rendered.Reset()
	l.viewport.SetContent("")
	l.streaming = false
	l.err = nil
}

// SetStreaming marks whether a log stream is active.
func (l *LogsTab) SetStreaming(v bool) {
	l.streaming = v
}

// SetError stores a display error.
func (l *LogsTab) SetError(err error) {
	l.err = err
	l.streaming = false
}

// AppendLine adds a single log line to the viewport buffer.
//
// If the line is valid agent JSONL it is parsed and rendered as a structured
// panel block. Non-JSON lines and empty lines are rendered as muted raw text.
// Lines that violate the no-credential invariant are rendered as redaction
// warnings; the raw content is discarded.
func (l *LogsTab) AppendLine(line string) {
	parsed := ParseAgentLine(line)

	var entry string
	if parsed.Rendered != "" {
		entry = parsed.Rendered
	} else {
		entry = theme.MutedStyle.Render(line)
	}

	l.rendered.WriteString(entry + "\n")
	l.viewport.SetContent(l.rendered.String())
	l.viewport.GotoBottom()
}

// SetSize updates the dimensions.
func (l *LogsTab) SetSize(width, height int) {
	l.width = width
	l.height = height
	l.viewport.Width = width - 4
	l.viewport.Height = height - 4
}

// Update forwards bubbletea messages to the viewport.
func (l *LogsTab) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	l.viewport, cmd = l.viewport.Update(msg)
	return cmd
}

// View renders the logs tab.
func (l LogsTab) View() string {
	var b strings.Builder

	title := "Agent Logs"
	if l.sandboxName != "" {
		title += " — " + l.sandboxName
	}
	if l.streaming {
		title += " (live)"
	}
	b.WriteString(theme.SectionTitleStyle.Render(title) + "\n\n")

	if l.err != nil {
		b.WriteString(theme.ErrorStyle.Render("Error: "+l.err.Error()) + "\n")
	} else if l.rendered.Len() == 0 {
		b.WriteString(theme.MutedStyle.Render("  No logs yet. Select a sandbox to stream logs.") + "\n")
	} else {
		b.WriteString(l.viewport.View())
	}

	b.WriteString("\n" + theme.MutedStyle.Render("up/down: scroll  •  g: top  •  G: bottom"))

	return theme.MainPanelStyle.
		Width(l.width).
		Height(l.height).
		Render(b.String())
}
