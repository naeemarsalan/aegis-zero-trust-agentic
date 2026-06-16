package openshell

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Sandbox is a TUI-facing view of an OpenShell sandbox, mapped from
// `openshell sandbox list/get -o json`. Field names match the legacy
// kube.Sandbox so existing TUI/CLI render code is reused unchanged with only
// a package-level type swap.
//
// Fields with no openshell CLI source are populated from labels or left zero;
// AccessHint is always "" because the gateway ObjectMeta has no annotations.
type Sandbox struct {
	ID          string            // gateway object id (openshell "id")
	Name        string            // openshell "name"
	Namespace   string            // not in CLI JSON; set to configured ns for display
	Phase       string            // normalised from openshell "phase" (see normalisePhase)
	Selector    string            // not in CLI JSON; "" (pod resolution no longer needed)
	Scope       string            // labels["nvidia-ida/scope"]
	TTLMinutes  string            // labels["nvidia-ida/ttl-minutes"]
	Owner       string            // labels["nvidia-ida/owner"]
	AccessHint  string            // not available via CLI (annotation absent); always ""
	CreatedAt   string            // openshell "created_at"
	Labels      map[string]string // openshell "labels" (never nil)
	Annotations map[string]string // always empty map (CLI exposes no annotations)
}

// wireSandbox is the internal JSON DTO produced by `openshell sandbox list/get
// -o json`. It matches sandbox_to_json in the openshell crate source.
type wireSandbox struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	ResourceVersion uint64            `json:"resource_version"`
	CreatedAt       string            `json:"created_at"`
	Phase           string            `json:"phase"`
	CurrentPolicy   int64             `json:"current_policy_version"`
}

// GatewayConfig holds optional gateway flags forwarded to every openshell
// invocation. When all fields are zero the CLI uses its own active gateway
// from ~/.config/openshell/active_gateway.
type GatewayConfig struct {
	Endpoint string // --gateway-endpoint / OPENSHELL_GATEWAY_ENDPOINT
	Name     string // -g/--gateway / OPENSHELL_GATEWAY
	Insecure bool   // --gateway-insecure
}

// Client wraps the openshell CLI for sandbox lifecycle operations.
type Client struct {
	runner    Runner
	bin       string        // "openshell" or an absolute path
	gateway   GatewayConfig
	namespace string // display-only namespace string
}

// New constructs a Client. bin="" resolves to "openshell" on PATH. r may not
// be nil — use NewExecRunner() for production.
func New(bin string, gw GatewayConfig, namespace string, r Runner) *Client {
	if bin == "" {
		bin = "openshell"
	}
	return &Client{
		runner:    r,
		bin:       bin,
		gateway:   gw,
		namespace: namespace,
	}
}

// gatewayArgs returns the ordered CLI flags that represent the gateway
// configuration. They are prepended to every sub-command invocation so the
// result is deterministic and testable (env vars would also work but are harder
// to assert in unit tests).
func (c *Client) gatewayArgs() []string {
	var args []string
	if c.gateway.Endpoint != "" {
		args = append(args, "--gateway-endpoint", c.gateway.Endpoint)
	}
	if c.gateway.Name != "" {
		args = append(args, "-g", c.gateway.Name)
	}
	if c.gateway.Insecure {
		args = append(args, "--gateway-insecure")
	}
	return args
}

// List returns all sandboxes visible to the configured gateway. When owner is
// non-empty, a server-side label filter `--selector nvidia-ida/owner=<owner>`
// is applied (convenience; the gateway enforces its own per-RPC authz).
func (c *Client) List(ctx context.Context, owner string) ([]Sandbox, error) {
	args := append(c.gatewayArgs(), "sandbox", "list", "-o", "json")
	if owner != "" {
		args = append(args, "--selector", "nvidia-ida/owner="+owner)
	}
	out, err := c.runner.Run(ctx, c.bin, args...)
	if err != nil {
		slog.ErrorContext(ctx, "openshell: list sandboxes failed", "owner", owner, "error", err)
		return nil, fmt.Errorf("openshell: list: %w", err)
	}
	var wires []wireSandbox
	if err := json.Unmarshal(out, &wires); err != nil {
		return nil, fmt.Errorf("openshell: parse list json: %w", err)
	}
	result := make([]Sandbox, 0, len(wires))
	for i := range wires {
		result = append(result, toSandbox(&wires[i], c.namespace))
	}
	return result, nil
}

// Get returns a single sandbox by name.
func (c *Client) Get(ctx context.Context, name string) (Sandbox, error) {
	args := append(c.gatewayArgs(), "sandbox", "get", name, "-o", "json")
	out, err := c.runner.Run(ctx, c.bin, args...)
	if err != nil {
		slog.ErrorContext(ctx, "openshell: get sandbox failed", "name", name, "error", err)
		return Sandbox{}, fmt.Errorf("openshell: get %q: %w", name, err)
	}
	var w wireSandbox
	if err := json.Unmarshal(out, &w); err != nil {
		return Sandbox{}, fmt.Errorf("openshell: parse get json for %q: %w", name, err)
	}
	return toSandbox(&w, c.namespace), nil
}

// Delete deletes the named sandbox.
func (c *Client) Delete(ctx context.Context, name string) error {
	args := append(c.gatewayArgs(), "sandbox", "delete", name)
	if _, err := c.runner.Run(ctx, c.bin, args...); err != nil {
		slog.ErrorContext(ctx, "openshell: delete sandbox failed", "name", name, "error", err)
		return fmt.Errorf("openshell: delete %q: %w", name, err)
	}
	slog.InfoContext(ctx, "openshell: sandbox deleted", "name", name)
	return nil
}

// toSandbox maps a wire DTO to the TUI-facing Sandbox struct. Phase is
// normalised into the vocabulary used by the theme package so existing phase
// glyphs and colours apply without modification.
func toSandbox(w *wireSandbox, ns string) Sandbox {
	labels := w.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return Sandbox{
		ID:          w.ID,
		Name:        w.Name,
		Namespace:   ns,
		Phase:       normalisePhase(w.Phase),
		Selector:    "", // not available via CLI
		Scope:       labels["nvidia-ida/scope"],
		TTLMinutes:  labels["nvidia-ida/ttl-minutes"],
		Owner:       labels["nvidia-ida/owner"],
		AccessHint:  "", // annotation not in gateway ObjectMeta
		CreatedAt:   w.CreatedAt,
		Labels:      labels,
		Annotations: map[string]string{}, // CLI exposes no annotations
	}
}

// normalisePhase maps OpenShell phase strings into the vocabulary expected by
// internal/tui/theme (PhaseGlyph / PhaseColor). This keeps the theme unchanged
// and tests green.
//
// Mapping:
//
//	Ready        → "Ready"
//	Provisioning → "Provisioning"
//	Error        → "Failed"
//	Deleting     → "Terminating"
//	Unspecified  → "Unknown"
//	Unknown      → "Unknown"
//	""           → "Unknown"
func normalisePhase(phase string) string {
	switch phase {
	case "Ready":
		return "Ready"
	case "Provisioning":
		return "Provisioning"
	case "Error":
		return "Failed"
	case "Deleting":
		return "Terminating"
	default:
		// Covers "Unknown", "Unspecified", and any unexpected value.
		return "Unknown"
	}
}
