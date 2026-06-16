package tui

import (
	"fmt"

	"github.com/charmbracelet/huh"
	tea "github.com/charmbracelet/bubbletea"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
)

// Wizard is a multi-step huh form that collects sandbox launch parameters.
type Wizard struct {
	form     *huh.Form
	active   bool
	// bound form values
	goal         string
	scope        string
	mode         string
	capabilities string // comma-separated; parsed on submit
	ttl          string // string input, converted to int
	confirmed    bool
}

// NewWizard constructs a Wizard and builds the huh form.
func NewWizard() *Wizard {
	w := &Wizard{
		scope: "read-only",
		mode:  "task",
		ttl:   "60",
	}
	w.buildForm()
	return w
}

// buildForm constructs the huh form with all steps.
func (w *Wizard) buildForm() {
	w.form = huh.NewForm(
		// Step 1: goal
		huh.NewGroup(
			huh.NewText().
				Title("Sandbox Goal").
				Description("Describe what the agent should accomplish (1-500 chars).").
				CharLimit(500).
				Placeholder("e.g. Audit firewall rules and create a report").
				Value(&w.goal),
		),
		// Step 2: scope + mode
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Access Scope").
				Description("Minimum necessary access for the goal.").
				Options(
					huh.NewOption("Read Only", "read-only"),
					huh.NewOption("Read + Write", "read-write"),
					huh.NewOption("Admin", "admin"),
				).
				Value(&w.scope),
			huh.NewSelect[string]().
				Title("Session Mode").
				Options(
					huh.NewOption("Task (short lived)", "task"),
					huh.NewOption("Project (long lived)", "project"),
				).
				Value(&w.mode),
		),
		// Step 3: capabilities + TTL
		huh.NewGroup(
			huh.NewInput().
				Title("Capabilities").
				Description("Comma-separated MCP capability names (1-20).").
				Placeholder("firewall.rules.read,nat.read").
				Value(&w.capabilities),
			huh.NewInput().
				Title("TTL (minutes)").
				Description("Session duration 5-480 minutes.").
				Placeholder("60").
				Value(&w.ttl),
		),
		// Step 4: confirm
		huh.NewGroup(
			huh.NewConfirm().
				Title("Launch Sandbox?").
				Description("Review your selections and confirm launch.").
				Affirmative("Launch").
				Negative("Cancel").
				Value(&w.confirmed),
		),
	)
}

// Active returns true if the wizard is currently open.
func (w *Wizard) Active() bool { return w.active }

// Init returns the huh form's init command, which focuses the first field so it
// can receive keystrokes. It MUST be run whenever the wizard is opened — huh only
// focuses a field via Form.Init(); without it the form renders but silently drops
// all typed input (the operator can't type the sandbox goal).
func (w *Wizard) Init() tea.Cmd {
	if w == nil || w.form == nil {
		return nil
	}
	return w.form.Init()
}

// Open resets and opens the wizard.
func (w *Wizard) Open() {
	w.goal = ""
	w.scope = "read-only"
	w.mode = "task"
	w.capabilities = ""
	w.ttl = "60"
	w.confirmed = false
	w.buildForm()
	w.active = true
}

// Close hides the wizard without emitting a result.
func (w *Wizard) Close() { w.active = false }

// Update forwards bubbletea messages to the form.
// When the form completes it returns a wizardDoneMsg cmd.
func (w *Wizard) Update(msg tea.Msg) tea.Cmd {
	if !w.active {
		return nil
	}
	form, cmd := w.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		w.form = f
	}

	if w.form.State == huh.StateCompleted {
		w.active = false
		req := w.buildRequest()
		done := wizardDoneMsg{req: req, confirmed: w.confirmed}
		return tea.Batch(cmd, func() tea.Msg { return done })
	}
	if w.form.State == huh.StateAborted {
		w.active = false
		done := wizardDoneMsg{confirmed: false}
		return tea.Batch(cmd, func() tea.Msg { return done })
	}
	return cmd
}

// View renders the wizard form.
func (w *Wizard) View() string {
	if !w.active || w.form == nil {
		return ""
	}
	return w.form.View()
}

// buildRequest assembles a LaunchRequest from the current form state.
func (w *Wizard) buildRequest() api.LaunchRequest {
	caps := parseCaps(w.capabilities)
	ttl := parseTTL(w.ttl)

	return api.LaunchRequest{
		Goal:         w.goal,
		Capabilities: caps,
		Mode:         w.mode,
		Scope:        w.scope,
		Confirmed:    w.confirmed,
		TTLMinutes:   ttl,
	}
}

// parseCaps splits a comma-separated capability string into a slice.
func parseCaps(raw string) []string {
	var caps []string
	for _, c := range splitTrim(raw, ",") {
		if c != "" {
			caps = append(caps, c)
		}
	}
	if len(caps) == 0 {
		caps = []string{"echo"} // safe default
	}
	return caps
}

// parseTTL converts a string to an int TTL, defaulting to 60.
func parseTTL(raw string) int {
	var v int
	if _, err := fmt.Sscan(raw, &v); err != nil || v < 5 || v > 480 {
		return 60
	}
	return v
}

// splitTrim splits s by sep and trims whitespace from each element.
func splitTrim(s, sep string) []string {
	var out []string
	start := 0
	sepLen := len(sep)
	for i := 0; i <= len(s)-sepLen; i++ {
		if s[i:i+sepLen] == sep {
			out = append(out, trim(s[start:i]))
			start = i + sepLen
		}
	}
	out = append(out, trim(s[start:]))
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
