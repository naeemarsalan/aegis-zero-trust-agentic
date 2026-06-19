// Package audit emits structured JSON audit events to stdout (scraped by Loki)
// and increments Prometheus metrics counters/histograms.
package audit

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// --- Prometheus metrics ---

var (
	mcpCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_mcp_calls_total",
		Help: "Total MCP tool calls processed by ext-proc-delegation.",
	}, []string{"tool", "decision"})

	authzDenialsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_authz_denials_total",
		Help: "Total authorization denials by ext-proc-delegation.",
	}, []string{"tool", "reason"})

	extProcLatencyMs = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ext_proc_latency_ms",
		Help:    "End-to-end latency in milliseconds for ext-proc-delegation processing.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
	}, []string{"tool", "decision"})
)

// --- Event schema ---

// AgentInfo carries SPIFFE and OIDC identity of the calling agent.
type AgentInfo struct {
	SPIFFEID string `json:"spiffe_id"`
	Sub      string `json:"sub"`
}

// CallerUserInfo carries the end-user identity forwarded by the agent.
type CallerUserInfo struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// MCPInfo carries the MCP tool call details.
type MCPInfo struct {
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	ArgsHash string `json:"args_hash"` // sha256 of canonical JSON args — never raw args
}

// KeycloakExchangeInfo records the outcome of the token exchange leg.
type KeycloakExchangeInfo struct {
	Mode     string `json:"mode"`
	Audience string `json:"audience"`
	Result   string `json:"result"` // "success" | "error:<reason>"
}

// VaultInfo records the outcome of the Vault secret retrieval leg.
type VaultInfo struct {
	Auth       string `json:"auth"`        // "success" | "error:<reason>"
	SecretPath string `json:"secret_path"` // path, not value
	Result     string `json:"result"`      // "success" | "error:<reason>"
}

// ExchangeInfo groups both exchange legs.
type ExchangeInfo struct {
	Keycloak KeycloakExchangeInfo `json:"keycloak"`
	Vault    VaultInfo            `json:"vault"`
}

// GrantInfo carries sandbox consent grant fields for audit.
// grant_nonce_present is logged (bool) instead of the nonce value itself —
// the nonce is a security binding material and must never be logged.
type GrantInfo struct {
	SandboxUID   string `json:"grant_sandbox_uid,omitempty"`
	Scope        string `json:"grant_scope,omitempty"`
	NoncePresent bool   `json:"grant_nonce_present"`
	Result       string `json:"grant_result,omitempty"` // "valid"|"expired"|"absent"|"nonce_mismatch"|"scope_denied"|"malformed"
}

// Event is the canonical audit record emitted as a single JSON log line.
type Event struct {
	TS                             string         `json:"ts"`
	Event                          string         `json:"event"` // always "credential_delegation"
	SessionID                      string         `json:"session_id"`
	TraceID                        string         `json:"trace_id,omitempty"`
	SpanID                         string         `json:"span_id,omitempty"`
	Agent                          AgentInfo      `json:"agent"`
	CallerUser                     CallerUserInfo `json:"caller_user"`
	MCP                            MCPInfo        `json:"mcp"`
	Exchange                       ExchangeInfo   `json:"exchange"`
	Grant                          GrantInfo      `json:"grant,omitempty"`
	JITElevated                    bool           `json:"jit_elevated"`              // true when a sandbox-bound JIT session JWT lifted the read-only baseline
	JITSessionID                   string         `json:"jit_session_id,omitempty"` // jit-approver session id that authorised the elevation
	WriteIdentity                  bool           `json:"write_identity"`            // true when the write-capable pfSense token was injected (JIT-elevated path)
	Decision                       string         `json:"decision"`  // "allow" | "deny"
	Reason                         string         `json:"reason,omitempty"`
	CredentialInjected             bool           `json:"credential_injected"`
	CredentialStrippedFromResponse bool           `json:"credential_stripped_from_response"`
	LatencyMs                      float64        `json:"latency_ms"`
}

var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

// Emitter records timing start and accumulates event fields.
type Emitter struct {
	start time.Time
	ev    Event
}

// NewEmitter creates an Emitter stamped at the current time.
func NewEmitter(sessionID, traceID, spanID string) *Emitter {
	return &Emitter{
		start: time.Now(),
		ev: Event{
			Event:     "credential_delegation",
			SessionID: sessionID,
			TraceID:   traceID,
			SpanID:    spanID,
		},
	}
}

// SetAgent records the agent identity.
func (e *Emitter) SetAgent(spiffeID, sub string) {
	e.ev.Agent = AgentInfo{SPIFFEID: spiffeID, Sub: sub}
}

// SetCallerUser records the end-user identity.
func (e *Emitter) SetCallerUser(sub, preferredUsername string, groups []string) {
	if groups == nil {
		groups = []string{}
	}
	e.ev.CallerUser = CallerUserInfo{Sub: sub, PreferredUsername: preferredUsername, Groups: groups}
}

// SetMCP records MCP call details.
func (e *Emitter) SetMCP(server, tool, argsHash string) {
	e.ev.MCP = MCPInfo{Server: server, Tool: tool, ArgsHash: argsHash}
}

// SetKeycloakExchange records the Keycloak exchange outcome.
func (e *Emitter) SetKeycloakExchange(mode, audience, result string) {
	e.ev.Exchange.Keycloak = KeycloakExchangeInfo{Mode: mode, Audience: audience, Result: result}
}

// SetVault records the Vault outcome.
func (e *Emitter) SetVault(auth, secretPath, result string) {
	e.ev.Exchange.Vault = VaultInfo{Auth: auth, SecretPath: secretPath, Result: result}
}

// SetGrant records consent grant audit fields.
// noncePresent should be true when the grant has a nonce (the value itself is
// NEVER logged — it is security binding material).
func (e *Emitter) SetGrant(sandboxUID, scope, result string, noncePresent bool) {
	e.ev.Grant = GrantInfo{
		SandboxUID:   sandboxUID,
		Scope:        scope,
		NoncePresent: noncePresent,
		Result:       result,
	}
}

// SetJIT records that a sandbox-bound JIT session JWT elevated this call, and
// the jit-approver session id that authorised it. Recorded so a dangerous-tool
// allow on the sandbox-agent path is self-explanatory in the audit trail.
func (e *Emitter) SetJIT(elevated bool, sessionID string) {
	e.ev.JITElevated = elevated
	e.ev.JITSessionID = sessionID
}

// SetWriteIdentity records whether the write-capable pfSense token was injected
// on this request (true = JIT-elevated write identity; false = read-only identity).
// Never logs the token value — only the boolean selection fact.
func (e *Emitter) SetWriteIdentity(writeIdentity bool) {
	e.ev.WriteIdentity = writeIdentity
}

// Emit finalizes the event (decision + credential flags + latency) and writes
// it to stdout via slog.  Also updates Prometheus metrics.
func (e *Emitter) Emit(_ context.Context, decision, reason string, credInjected, credStripped bool) {
	e.ev.TS = time.Now().UTC().Format(time.RFC3339Nano)
	e.ev.LatencyMs = float64(time.Since(e.start).Nanoseconds()) / 1e6
	e.ev.Decision = decision
	e.ev.Reason = reason
	e.ev.CredentialInjected = credInjected
	e.ev.CredentialStrippedFromResponse = credStripped

	tool := e.ev.MCP.Tool
	if tool == "" {
		tool = "unknown"
	}

	logger.Info("credential_delegation",
		slog.String("ts", e.ev.TS),
		slog.String("event", e.ev.Event),
		slog.String("session_id", e.ev.SessionID),
		slog.String("trace_id", e.ev.TraceID),
		slog.String("span_id", e.ev.SpanID),
		slog.String("agent_spiffe_id", e.ev.Agent.SPIFFEID),
		slog.String("agent_sub", e.ev.Agent.Sub),
		slog.String("caller_sub", e.ev.CallerUser.Sub),
		slog.String("caller_username", e.ev.CallerUser.PreferredUsername),
		slog.Any("caller_groups", e.ev.CallerUser.Groups),
		slog.String("mcp_server", e.ev.MCP.Server),
		slog.String("mcp_tool", e.ev.MCP.Tool),
		slog.String("mcp_args_hash", e.ev.MCP.ArgsHash),
		slog.String("keycloak_mode", e.ev.Exchange.Keycloak.Mode),
		slog.String("keycloak_audience", e.ev.Exchange.Keycloak.Audience),
		slog.String("keycloak_result", e.ev.Exchange.Keycloak.Result),
		slog.String("vault_auth", e.ev.Exchange.Vault.Auth),
		slog.String("vault_secret_path", e.ev.Exchange.Vault.SecretPath),
		slog.String("vault_result", e.ev.Exchange.Vault.Result),
		// Grant fields (sandbox agent path only; empty on legacy path).
		slog.String("grant_sandbox_uid", e.ev.Grant.SandboxUID),
		slog.String("grant_scope", e.ev.Grant.Scope),
		slog.Bool("grant_nonce_present", e.ev.Grant.NoncePresent),
		slog.String("grant_result", e.ev.Grant.Result),
		slog.Bool("jit_elevated", e.ev.JITElevated),
		slog.String("jit_session_id", e.ev.JITSessionID),
		slog.Bool("write_identity", e.ev.WriteIdentity),
		slog.String("decision", decision),
		slog.String("reason", reason),
		slog.Bool("credential_injected", credInjected),
		slog.Bool("credential_stripped_from_response", credStripped),
		slog.Float64("latency_ms", e.ev.LatencyMs),
	)

	// Prometheus.
	mcpCallsTotal.WithLabelValues(tool, decision).Inc()
	extProcLatencyMs.WithLabelValues(tool, decision).Observe(e.ev.LatencyMs)
	if decision == "deny" {
		authzDenialsTotal.WithLabelValues(tool, reason).Inc()
	}
}
