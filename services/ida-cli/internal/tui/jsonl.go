package tui

// jsonl.go — parse the agent->TUI JSONL stream (contract: jsonlSchema stream 2)
// and render each line as a formatted panel entry.
//
// Contract reference (frozen):
//
//	{ "type": "assistant|tool_use|tool_result|result|system", "ts": "RFC3339",
//	  "session_id": "string", ...type-specific payload }
//
// SECURITY INVARIANT: if any line contains the string "authorization" or
// "bearer" (case-insensitive) after JSON decode, it is treated as a redaction
// violation and rendered as a warning, not displayed raw. The raw line is
// NEVER forwarded to the viewport.
//
// Non-JSON lines are passed through as raw text.

import (
	"encoding/json"
	"fmt"
	"strings"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
	"github.com/charmbracelet/lipgloss"
)

// agentLineType enumerates the known JSONL line types from the agent harness.
type agentLineType string

const (
	lineTypeAssistant  agentLineType = "assistant"
	lineTypeToolUse    agentLineType = "tool_use"
	lineTypeToolResult agentLineType = "tool_result"
	lineTypeResult     agentLineType = "result"
	lineTypeSystem     agentLineType = "system"
)

// agentLine is the common envelope parsed from every JSONL line.
type agentLine struct {
	Type      agentLineType      `json:"type"`
	TS        string             `json:"ts"`
	SessionID string             `json:"session_id"`
	Raw       map[string]any     `json:"-"` // full decoded map for type-specific extraction
}

// agentLineParsed is what ParseAgentLine returns to the caller.
// It carries both the line type and a pre-rendered display string.
type agentLineParsed struct {
	// LineType is the parsed type field; empty string when the line is not JSON.
	LineType agentLineType
	// Rendered is the lipgloss-styled string ready to append to the viewport.
	// It never contains raw credential values.
	Rendered string
	// IsRedactionViolation is true when the line appeared to contain a
	// credential field. The line is blocked and a warning is rendered instead.
	IsRedactionViolation bool
}

// credentialKeys are JSON key names that must never appear in agent output.
// If any decoded map key matches (case-insensitive prefix), the line is blocked.
var credentialKeys = []string{
	"authorization",
	"bearer",
	"mcp_servers",
	"server_config",
	"access_token",
	"client_secret",
}

// ParseAgentLine parses a single line from the agent stdout JSONL stream and
// returns a rendered panel string suitable for the Logs viewport.
//
// Rules:
//   - Non-JSON input -> raw pass-through (no styling).
//   - JSON with a credential key present -> redaction warning, line blocked.
//   - Known type fields -> type-specific formatted panel.
//   - Unknown JSON type -> render as a muted JSON envelope.
func ParseAgentLine(line string) agentLineParsed {
	trimmed := strings.TrimSpace(line)

	// Fast-path: not JSON.
	if trimmed == "" || trimmed[0] != '{' {
		return agentLineParsed{
			Rendered: theme.MutedStyle.Render(line),
		}
	}

	// Decode into a generic map first so we can inspect all keys.
	var raw map[string]any
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		// Malformed JSON — pass through as raw muted text.
		return agentLineParsed{
			Rendered: theme.MutedStyle.Render(line),
		}
	}

	// Security gate: scan all top-level keys for credential indicators.
	if violated, badKey := checkCredentialKeys(raw); violated {
		warning := theme.ErrorStyle.Render(
			fmt.Sprintf("[REDACTION VIOLATION: key %q blocked — credential in agent output]", badKey),
		)
		return agentLineParsed{
			IsRedactionViolation: true,
			Rendered:             warning,
		}
	}

	// Extract common envelope fields.
	lineType := agentLineType(stringField(raw, "type"))
	ts := stringField(raw, "ts")
	sessionID := stringField(raw, "session_id")

	tsLabel := ""
	if ts != "" {
		// Trim to HH:MM:SS for readability.
		if len(ts) >= 19 {
			tsLabel = ts[11:19]
		} else {
			tsLabel = ts
		}
	}

	switch lineType {
	case lineTypeAssistant:
		return renderAssistant(raw, tsLabel, sessionID)
	case lineTypeToolUse:
		return renderToolUse(raw, tsLabel, sessionID)
	case lineTypeToolResult:
		return renderToolResult(raw, tsLabel, sessionID)
	case lineTypeResult:
		return renderResult(raw, tsLabel, sessionID)
	case lineTypeSystem:
		return renderSystem(raw, tsLabel, sessionID)
	default:
		// Unknown JSON type — render compactly.
		compact, _ := json.Marshal(raw)
		return agentLineParsed{
			LineType: lineType,
			Rendered: theme.MutedStyle.Render(string(compact)),
		}
	}
}

// ---------------------------------------------------------------------------
// Per-type renderers
// ---------------------------------------------------------------------------

func renderAssistant(raw map[string]any, ts, _ string) agentLineParsed {
	text := stringField(raw, "text")
	if text == "" {
		text = "(no text)"
	}

	prefix := lipgloss.NewStyle().
		Foreground(theme.ColorAccent).
		Bold(true).
		Render("  model")
	timeLabel := theme.MutedStyle.Render(ts)
	header := lipgloss.JoinHorizontal(lipgloss.Left, prefix, "  ", timeLabel)

	body := lipgloss.NewStyle().
		Foreground(theme.ColorTextPrimary).
		PaddingLeft(4).
		Render(wrapText(text, 80))

	return agentLineParsed{
		LineType: lineTypeAssistant,
		Rendered: header + "\n" + body,
	}
}

func renderToolUse(raw map[string]any, ts, _ string) agentLineParsed {
	tool := stringField(raw, "tool")
	if tool == "" {
		tool = "(unknown tool)"
	}

	// args may be a map or a JSON string; render compactly but never include
	// credential-adjacent fields (already blocked at the envelope level, but
	// belt-and-suspenders: omit keys matching credentialKeys from args map).
	argsRendered := renderArgs(raw["args"])

	prefix := lipgloss.NewStyle().
		Foreground(theme.ColorInfo).
		Bold(true).
		Render("  tool")
	timeLabel := theme.MutedStyle.Render(ts)
	header := lipgloss.JoinHorizontal(lipgloss.Left, prefix, "  ", timeLabel)

	toolLine := lipgloss.NewStyle().
		Foreground(theme.ColorInfo).
		PaddingLeft(4).
		Render("call: " + tool)

	argsLine := theme.MutedStyle.Copy().PaddingLeft(4).Render("args: " + argsRendered)

	return agentLineParsed{
		LineType: lineTypeToolUse,
		Rendered: header + "\n" + toolLine + "\n" + argsLine,
	}
}

func renderToolResult(raw map[string]any, ts, _ string) agentLineParsed {
	tool := stringField(raw, "tool")
	if tool == "" {
		tool = "(unknown tool)"
	}
	ok := boolField(raw, "ok")
	content := stringField(raw, "content")
	if content == "" {
		if raw["content"] != nil {
			b, _ := json.Marshal(raw["content"])
			content = string(b)
		}
	}
	// Truncate very long content for display.
	const maxContent = 300
	if len(content) > maxContent {
		content = content[:maxContent] + " … [truncated]"
	}

	statusStyle := theme.SuccessStyle
	statusGlyph := "ok"
	if !ok {
		statusStyle = theme.ErrorStyle
		statusGlyph = "err"
	}

	prefix := lipgloss.NewStyle().
		Foreground(theme.ColorInfo).
		Bold(true).
		Render("result")
	timeLabel := theme.MutedStyle.Render(ts)
	header := lipgloss.JoinHorizontal(lipgloss.Left, prefix, "  ", timeLabel)

	toolLine := lipgloss.NewStyle().
		Foreground(theme.ColorInfo).
		PaddingLeft(4).
		Render(tool + "  " + statusStyle.Render("["+statusGlyph+"]"))

	var contentLine string
	if content != "" {
		contentLine = "\n" + theme.MutedStyle.Copy().PaddingLeft(4).Render(content)
	}

	return agentLineParsed{
		LineType: lineTypeToolResult,
		Rendered: header + "\n" + toolLine + contentLine,
	}
}

func renderResult(raw map[string]any, ts, _ string) agentLineParsed {
	status := stringField(raw, "status")
	summary := stringField(raw, "summary")
	if summary == "" {
		summary = "(no summary)"
	}

	var statusStyle lipgloss.Style
	switch status {
	case "success":
		statusStyle = theme.SuccessStyle
	case "error":
		statusStyle = theme.ErrorStyle
	default:
		statusStyle = theme.MutedStyle
		if status == "" {
			status = "unknown"
		}
	}

	prefix := statusStyle.Copy().Bold(true).Render("  done")
	timeLabel := theme.MutedStyle.Render(ts)
	header := lipgloss.JoinHorizontal(lipgloss.Left, prefix, "  ", timeLabel)

	statusLine := lipgloss.NewStyle().PaddingLeft(4).Render(
		statusStyle.Render(status) + "  " + theme.MutedStyle.Render(summary),
	)

	return agentLineParsed{
		LineType: lineTypeResult,
		Rendered: header + "\n" + statusLine,
	}
}

func renderSystem(raw map[string]any, ts, _ string) agentLineParsed {
	subtype := stringField(raw, "subtype")
	message := stringField(raw, "message")
	if message == "" {
		message = "(no message)"
	}

	label := "system"
	if subtype != "" {
		label = "system/" + subtype
	}

	prefix := theme.WarningStyle.Copy().Bold(true).Render(" " + label)
	timeLabel := theme.MutedStyle.Render(ts)
	header := lipgloss.JoinHorizontal(lipgloss.Left, prefix, "  ", timeLabel)

	msgLine := theme.MutedStyle.Copy().PaddingLeft(4).Render(message)

	return agentLineParsed{
		LineType: lineTypeSystem,
		Rendered: header + "\n" + msgLine,
	}
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

// checkCredentialKeys returns (true, key) if any top-level key in m has a
// name that matches a credential indicator (case-insensitive prefix check).
func checkCredentialKeys(m map[string]any) (bool, string) {
	for k := range m {
		lower := strings.ToLower(k)
		for _, banned := range credentialKeys {
			if strings.HasPrefix(lower, banned) {
				return true, k
			}
		}
	}
	return false, ""
}

// stringField extracts a string value from a raw decoded map, returning ""
// if the key is absent or the value is not a string.
func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// boolField extracts a bool value, returning false if absent or not a bool.
func boolField(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

// renderArgs converts the args field to a compact human-readable string,
// filtering any credential-adjacent keys.
func renderArgs(args any) string {
	if args == nil {
		return "{}"
	}
	switch v := args.(type) {
	case map[string]any:
		// Filter credential keys before rendering.
		filtered := make(map[string]any, len(v))
		for k, val := range v {
			lower := strings.ToLower(k)
			blocked := false
			for _, banned := range credentialKeys {
				if strings.HasPrefix(lower, banned) {
					blocked = true
					break
				}
			}
			if !blocked {
				filtered[k] = val
			}
		}
		b, err := json.Marshal(filtered)
		if err != nil {
			return "{}"
		}
		return string(b)
	case string:
		return v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "{}"
		}
		return string(b)
	}
}

// wrapText is a simple soft-wrap: break on word boundaries at maxWidth.
// It does not handle ANSI sequences; the viewport handles terminal wrapping,
// so this is only used to avoid extremely long single-line text.
func wrapText(text string, maxWidth int) string {
	if len(text) <= maxWidth {
		return text
	}
	var b strings.Builder
	words := strings.Fields(text)
	lineLen := 0
	for i, w := range words {
		if i > 0 && lineLen+1+len(w) > maxWidth {
			b.WriteByte('\n')
			lineLen = 0
		} else if i > 0 {
			b.WriteByte(' ')
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}
