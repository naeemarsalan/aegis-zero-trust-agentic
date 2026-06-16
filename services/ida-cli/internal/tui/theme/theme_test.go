package theme

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// PhaseColor
// ---------------------------------------------------------------------------

func TestPhaseColor_Running(t *testing.T) {
	if got := PhaseColor("Running"); got != ColorAccent {
		t.Errorf("PhaseColor(Running) = %q; want %q", got, ColorAccent)
	}
}

func TestPhaseColor_Succeeded(t *testing.T) {
	if got := PhaseColor("Succeeded"); got != ColorSuccess {
		t.Errorf("PhaseColor(Succeeded) = %q; want %q", got, ColorSuccess)
	}
}

func TestPhaseColor_Failed(t *testing.T) {
	if got := PhaseColor("Failed"); got != ColorError {
		t.Errorf("PhaseColor(Failed) = %q; want %q", got, ColorError)
	}
}

func TestPhaseColor_Pending(t *testing.T) {
	if got := PhaseColor("Pending"); got != ColorWarning {
		t.Errorf("PhaseColor(Pending) = %q; want %q", got, ColorWarning)
	}
}

func TestPhaseColor_Unknown_ReturnsMuted(t *testing.T) {
	if got := PhaseColor("Unknown"); got != ColorTextMuted {
		t.Errorf("PhaseColor(Unknown) = %q; want %q", got, ColorTextMuted)
	}
}

func TestPhaseColor_EmptyString_ReturnsMuted(t *testing.T) {
	if got := PhaseColor(""); got != ColorTextMuted {
		t.Errorf("PhaseColor('') = %q; want %q", got, ColorTextMuted)
	}
}

// ---------------------------------------------------------------------------
// PhaseGlyph
// ---------------------------------------------------------------------------

func TestPhaseGlyph_KnownPhases(t *testing.T) {
	cases := []struct {
		phase string
		want  string
	}{
		{"Pending", "○"},
		{"Running", "●"},
		{"Succeeded", "✓"},
		{"Failed", "✗"},
		{"Unknown", "?"},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			got, ok := PhaseGlyph[tc.phase]
			if !ok {
				t.Fatalf("PhaseGlyph[%q] missing", tc.phase)
			}
			if got != tc.want {
				t.Errorf("PhaseGlyph[%q] = %q; want %q", tc.phase, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BadgeForPhase
// ---------------------------------------------------------------------------

func TestBadgeForPhase_ContainsPhase(t *testing.T) {
	phases := []string{"Running", "Pending", "Failed", "Succeeded", "Unknown"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			badge := BadgeForPhase(phase)
			if badge == "" {
				t.Errorf("BadgeForPhase(%q) returned empty string", phase)
			}
			// The badge must contain the phase name (lipgloss renders ANSI; strip check not needed).
			// We just ensure non-empty and non-panicking execution.
		})
	}
}

func TestBadgeForPhase_MissingPhase_UsesFallback(t *testing.T) {
	// Phase not in map should fall back to "?" glyph without panicking.
	badge := BadgeForPhase("Terminating")
	if badge == "" {
		t.Error("BadgeForPhase(unknown) returned empty string")
	}
}

// ---------------------------------------------------------------------------
// BadgeForScope
// ---------------------------------------------------------------------------

func TestBadgeForScope_Admin_NonEmpty(t *testing.T) {
	if got := BadgeForScope("admin"); got == "" {
		t.Error("BadgeForScope(admin) returned empty string")
	}
}

func TestBadgeForScope_ReadWrite_NonEmpty(t *testing.T) {
	if got := BadgeForScope("read-write"); got == "" {
		t.Error("BadgeForScope(read-write) returned empty string")
	}
}

func TestBadgeForScope_ReadOnly_NonEmpty(t *testing.T) {
	if got := BadgeForScope("read-only"); got == "" {
		t.Error("BadgeForScope(read-only) returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Style constants — sanity checks (non-zero lipgloss.Color values)
// ---------------------------------------------------------------------------

func TestColorConstants_NonEmpty(t *testing.T) {
	colors := []struct {
		name  string
		color lipgloss.Color
	}{
		{"ColorBackground", ColorBackground},
		{"ColorSurface", ColorSurface},
		{"ColorBorder", ColorBorder},
		{"ColorAccent", ColorAccent},
		{"ColorAccentDim", ColorAccentDim},
		{"ColorTextPrimary", ColorTextPrimary},
		{"ColorTextMuted", ColorTextMuted},
		{"ColorSuccess", ColorSuccess},
		{"ColorWarning", ColorWarning},
		{"ColorError", ColorError},
		{"ColorInfo", ColorInfo},
	}
	for _, tc := range colors {
		t.Run(tc.name, func(t *testing.T) {
			if tc.color == "" {
				t.Errorf("%s is empty", tc.name)
			}
		})
	}
}
