// Package grant defines and validates the sandbox consent grant document
// written by sandbox-launcher and read by ext-proc-delegation.
//
// SECURITY MODEL:
//
// The grant is a CONSENT RECORD stored in Vault KV-v2 at
//
//	secret/data/sandbox-grants/<sandbox-uid>
//
// It is NOT a credential. No token, password, client secret, or SVID may ever
// appear in this document. The ext-proc reader enforces this invariant by
// checking only the fields defined in Grant and rejecting any document whose
// Vault path is absent (404) or whose fields fail validation.
//
// Validation is FAIL-CLOSED: any missing required field, TTL expiry, nonce
// mismatch, or scope violation returns a typed ValidationError that the caller
// maps to a 403 ImmediateResponse. There is no default-allow path.
package grant

import (
	"errors"
	"fmt"
	"time"
)

// Grant is the frozen consent record schema (version=1).
// Fields map directly to the Vault KV-v2 data envelope for
// secret/data/sandbox-grants/<sandbox-uid>.
type Grant struct {
	// User is the verified Keycloak preferred_username the agent acts on behalf
	// of. ext-proc uses this as the RFC 8693 requested_subject in Phase-1
	// impersonation. REQUIRED.
	User string `json:"user"`

	// Scope is one of "read-only", "read-write", or "admin". The slice freeze
	// is "read-only". REQUIRED.
	Scope string `json:"scope"`

	// TTL is the grant validity window in seconds. REQUIRED.
	TTL int `json:"ttl"`

	// Nonce is a server-generated random (uuid4 hex) written by the launcher.
	// The agent's SPIRE JWT-SVID carries the same nonce in a custom claim so
	// ext-proc can bind the SVID to this specific grant without relying on
	// any spoofable header. REQUIRED.
	Nonce string `json:"nonce"`

	// Created is the RFC3339Nano UTC issue time. Expiry = Created + TTL. REQUIRED.
	Created time.Time `json:"created"`

	// SandboxUID echoes the k8s Sandbox CR uid from the path key (cross-check). REQUIRED.
	SandboxUID string `json:"sandbox_uid"`

	// Version is the schema version; must be 1. REQUIRED.
	Version int `json:"version"`
}

// Valid scope values.
const (
	ScopeReadOnly  = "read-only"
	ScopeReadWrite = "read-write"
	ScopeAdmin     = "admin"
)

// MaxGrantTTLSeconds is the platform-wide upper bound on grant validity (3600s = 60min).
// This matches the JIT approver's 60-minute session ceiling. Any grant whose TTL
// field exceeds this value is rejected by CheckTTLCap (fail-closed).
const MaxGrantTTLSeconds = 3600

// ValidationResult enumerates the outcome of grant validation, used in audit
// logs as grant_result.
type ValidationResult string

const (
	ResultValid         ValidationResult = "valid"
	ResultAbsent        ValidationResult = "absent"
	ResultExpired       ValidationResult = "grant_expired"
	ResultNonceMismatch ValidationResult = "nonce_mismatch"
	ResultScopeDenied   ValidationResult = "scope_denied"
	ResultMalformed     ValidationResult = "malformed"
)

// ValidationError carries a typed reason so server.go can emit the right
// audit grant_result without an extra string-match step.
type ValidationError struct {
	Result  ValidationResult
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("grant validation %s: %s", e.Result, e.Message)
}

// errGrant constructs a ValidationError.
func errGrant(r ValidationResult, msg string) error {
	return &ValidationError{Result: r, Message: msg}
}

// ErrAbsent is a sentinel to detect 404-style "grant not found" separately
// from field validation errors. Callers may use errors.As.
var ErrAbsent = &ValidationError{Result: ResultAbsent, Message: "grant not found in Vault"}

// Validate checks all required fields and structural invariants.
// It does NOT check nonce or scope — those require caller-supplied context.
// Returns a *ValidationError on any failure (fail-closed).
func (g *Grant) Validate() error {
	if g.Version != 1 {
		return errGrant(ResultMalformed, fmt.Sprintf("unsupported grant version %d (want 1)", g.Version))
	}
	if g.User == "" {
		return errGrant(ResultMalformed, "missing required field: user")
	}
	if g.Scope == "" {
		return errGrant(ResultMalformed, "missing required field: scope")
	}
	switch g.Scope {
	case ScopeReadOnly, ScopeReadWrite, ScopeAdmin:
		// valid
	default:
		return errGrant(ResultMalformed, fmt.Sprintf("unknown scope %q", g.Scope))
	}
	if g.TTL <= 0 {
		return errGrant(ResultMalformed, "ttl must be positive")
	}
	if g.Nonce == "" {
		return errGrant(ResultMalformed, "missing required field: nonce")
	}
	if g.Created.IsZero() {
		return errGrant(ResultMalformed, "missing required field: created")
	}
	if g.SandboxUID == "" {
		return errGrant(ResultMalformed, "missing required field: sandbox_uid")
	}
	return nil
}

// CheckTTL fails closed if the grant has expired relative to now.
func (g *Grant) CheckTTL(now time.Time) error {
	expiry := g.Created.Add(time.Duration(g.TTL) * time.Second)
	if now.After(expiry) {
		return errGrant(ResultExpired, fmt.Sprintf("grant expired at %s", expiry.UTC().Format(time.RFC3339Nano)))
	}
	return nil
}

// CheckTTLCap fails closed if the grant's TTL field exceeds MaxGrantTTLSeconds.
// This is a defense-in-depth check: the launcher is expected to clamp TTL
// server-side, but ext-proc enforces the same ceiling independently so a
// rogue or stale grant document cannot extend its validity beyond the platform
// maximum (Finding 3).
func (g *Grant) CheckTTLCap() error {
	if g.TTL > MaxGrantTTLSeconds {
		return errGrant(ResultMalformed,
			fmt.Sprintf("grant TTL %d exceeds platform maximum %d seconds", g.TTL, MaxGrantTTLSeconds))
	}
	return nil
}

// CheckNonce fails closed if the SVID nonce does not match the grant nonce.
// Both the sandbox UID and nonce must match — a stolen UID alone is not enough.
func (g *Grant) CheckNonce(svidSandboxUID, svidNonce string) error {
	if g.SandboxUID != svidSandboxUID {
		return errGrant(ResultNonceMismatch,
			"sandbox_uid mismatch between SVID claim and grant document")
	}
	if g.Nonce != svidNonce {
		return errGrant(ResultNonceMismatch,
			"nonce mismatch between SVID claim and grant document")
	}
	return nil
}

// CheckScope returns a scope error if the tool is not permitted under the
// grant scope.  readOnlyPrefixes is the same list as config.ReadOnlyToolPrefixes.
// Fail-closed: if the tool is non-empty and the scope is read-only but the tool
// does not match any read-only prefix, deny.
func (g *Grant) CheckScope(tool string, readOnlyPrefixes []string) error {
	if g.Scope == ScopeAdmin || g.Scope == ScopeReadWrite {
		// read-write and admin scopes permit all tools (RBAC still applies independently).
		return nil
	}
	// read-only scope: tool must match a read-only prefix.
	if g.Scope == ScopeReadOnly {
		if tool == "" {
			// Not a tool call (MCP handshake / tools/list) — allow.
			return nil
		}
		for _, pfx := range readOnlyPrefixes {
			if pfx != "" && len(tool) >= len(pfx) && tool[:len(pfx)] == pfx {
				return nil
			}
		}
		return errGrant(ResultScopeDenied,
			fmt.Sprintf("tool %q not permitted under read-only grant scope", tool))
	}
	return errGrant(ResultScopeDenied, fmt.Sprintf("unknown scope %q in grant", g.Scope))
}

// FromVaultData decodes a grant from the map returned by vault.FetchToolSecret
// (KV-v2 resp.data.data). Returns ErrAbsent if the map is nil/empty, or a
// *ValidationError on parse/validation failure.
func FromVaultData(data map[string]any) (*Grant, error) {
	if len(data) == 0 {
		return nil, ErrAbsent
	}

	g := &Grant{}

	// user
	if v, ok := data["user"].(string); ok {
		g.User = v
	}
	// scope
	if v, ok := data["scope"].(string); ok {
		g.Scope = v
	}
	// ttl — Vault JSON numbers deserialize as float64 via interface{}
	switch v := data["ttl"].(type) {
	case float64:
		g.TTL = int(v)
	case int:
		g.TTL = v
	}
	// nonce
	if v, ok := data["nonce"].(string); ok {
		g.Nonce = v
	}
	// created — RFC3339Nano string
	if v, ok := data["created"].(string); ok {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			// Fallback: try plain RFC3339.
			t, err = time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, errGrant(ResultMalformed, fmt.Sprintf("created parse error: %v", err))
			}
		}
		g.Created = t
	}
	// sandbox_uid
	if v, ok := data["sandbox_uid"].(string); ok {
		g.SandboxUID = v
	}
	// version
	switch v := data["version"].(type) {
	case float64:
		g.Version = int(v)
	case int:
		g.Version = v
	}

	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}

// IsValidationError reports whether err is a *ValidationError with result r.
func IsValidationError(err error, r ValidationResult) bool {
	var ve *ValidationError
	return errors.As(err, &ve) && ve.Result == r
}
