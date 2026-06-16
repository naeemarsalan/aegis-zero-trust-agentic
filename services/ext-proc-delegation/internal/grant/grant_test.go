package grant_test

import (
	"testing"
	"time"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/grant"
)

// baseGrant returns a valid grant for use in table-driven tests.
func baseGrant() *grant.Grant {
	return &grant.Grant{
		User:       "arsalan",
		Scope:      grant.ScopeReadOnly,
		TTL:        3600,
		Nonce:      "abc123nonce",
		Created:    time.Now().UTC().Add(-1 * time.Minute),
		SandboxUID: "uid-abc-123",
		Version:    1,
	}
}

// --- Validate ---

func TestGrant_Validate_HappyPath(t *testing.T) {
	if err := baseGrant().Validate(); err != nil {
		t.Fatalf("expected valid grant, got: %v", err)
	}
}

func TestGrant_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*grant.Grant)
	}{
		{"missing user", func(g *grant.Grant) { g.User = "" }},
		{"missing scope", func(g *grant.Grant) { g.Scope = "" }},
		{"missing nonce", func(g *grant.Grant) { g.Nonce = "" }},
		{"zero created", func(g *grant.Grant) { g.Created = time.Time{} }},
		{"missing sandbox_uid", func(g *grant.Grant) { g.SandboxUID = "" }},
		{"zero ttl", func(g *grant.Grant) { g.TTL = 0 }},
		{"negative ttl", func(g *grant.Grant) { g.TTL = -1 }},
		{"bad scope", func(g *grant.Grant) { g.Scope = "superuser" }},
		{"wrong version", func(g *grant.Grant) { g.Version = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := baseGrant()
			tc.mutate(g)
			if err := g.Validate(); err == nil {
				t.Errorf("expected validation error for %q, got nil", tc.name)
			}
		})
	}
}

// --- CheckTTL ---

func TestGrant_CheckTTL_NotExpired(t *testing.T) {
	g := baseGrant()
	g.TTL = 3600
	if err := g.CheckTTL(time.Now()); err != nil {
		t.Fatalf("expected not expired, got: %v", err)
	}
}

func TestGrant_CheckTTL_Expired(t *testing.T) {
	g := baseGrant()
	g.TTL = 60
	g.Created = time.Now().UTC().Add(-10 * time.Minute) // 10 min ago, TTL=60s -> expired
	err := g.CheckTTL(time.Now())
	if err == nil {
		t.Fatal("expected expired error, got nil")
	}
	if !grant.IsValidationError(err, grant.ResultExpired) {
		t.Errorf("expected ResultExpired, got: %v", err)
	}
}

// --- CheckNonce ---

func TestGrant_CheckNonce_Match(t *testing.T) {
	g := baseGrant()
	if err := g.CheckNonce("uid-abc-123", "abc123nonce"); err != nil {
		t.Fatalf("expected nonce match, got: %v", err)
	}
}

func TestGrant_CheckNonce_UIDMismatch(t *testing.T) {
	g := baseGrant()
	err := g.CheckNonce("uid-DIFFERENT", "abc123nonce")
	if err == nil {
		t.Fatal("expected nonce mismatch for UID, got nil")
	}
	if !grant.IsValidationError(err, grant.ResultNonceMismatch) {
		t.Errorf("expected ResultNonceMismatch, got: %v", err)
	}
}

func TestGrant_CheckNonce_NonceMismatch(t *testing.T) {
	g := baseGrant()
	err := g.CheckNonce("uid-abc-123", "wrong-nonce")
	if err == nil {
		t.Fatal("expected nonce mismatch, got nil")
	}
	if !grant.IsValidationError(err, grant.ResultNonceMismatch) {
		t.Errorf("expected ResultNonceMismatch, got: %v", err)
	}
}

// --- CheckScope ---

var readOnlyPrefixes = []string{"get_", "list_", "search_", "find_", "show_"}

func TestGrant_CheckScope_ReadOnlyAllowed(t *testing.T) {
	g := baseGrant()
	g.Scope = grant.ScopeReadOnly
	if err := g.CheckScope("search_firewall_rules", readOnlyPrefixes); err != nil {
		t.Fatalf("expected allowed, got: %v", err)
	}
}

func TestGrant_CheckScope_ReadOnlyDenied(t *testing.T) {
	g := baseGrant()
	g.Scope = grant.ScopeReadOnly
	err := g.CheckScope("delete_firewall_rule", readOnlyPrefixes)
	if err == nil {
		t.Fatal("expected scope denied for write tool under read-only grant")
	}
	if !grant.IsValidationError(err, grant.ResultScopeDenied) {
		t.Errorf("expected ResultScopeDenied, got: %v", err)
	}
}

func TestGrant_CheckScope_ReadOnlyNoTool(t *testing.T) {
	// Empty tool (MCP handshake) is always allowed.
	g := baseGrant()
	g.Scope = grant.ScopeReadOnly
	if err := g.CheckScope("", readOnlyPrefixes); err != nil {
		t.Fatalf("expected handshake allowed, got: %v", err)
	}
}

func TestGrant_CheckScope_ReadWritePermitsWrite(t *testing.T) {
	g := baseGrant()
	g.Scope = grant.ScopeReadWrite
	if err := g.CheckScope("delete_firewall_rule", readOnlyPrefixes); err != nil {
		t.Fatalf("expected read-write grant to allow write tool, got: %v", err)
	}
}

func TestGrant_CheckScope_AdminPermitsAll(t *testing.T) {
	g := baseGrant()
	g.Scope = grant.ScopeAdmin
	if err := g.CheckScope("delete_firewall_rule", readOnlyPrefixes); err != nil {
		t.Fatalf("expected admin grant to allow any tool, got: %v", err)
	}
}

// --- FromVaultData ---

func TestFromVaultData_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	data := map[string]any{
		"user":        "arsalan",
		"scope":       "read-only",
		"ttl":         float64(3600),
		"nonce":       "deadbeef",
		"created":     now.Format(time.RFC3339Nano),
		"sandbox_uid": "k8s-uid-xyz",
		"version":     float64(1),
	}
	g, err := grant.FromVaultData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.User != "arsalan" {
		t.Errorf("user=%q want arsalan", g.User)
	}
	if g.Nonce != "deadbeef" {
		t.Errorf("nonce=%q want deadbeef", g.Nonce)
	}
	if g.TTL != 3600 {
		t.Errorf("ttl=%d want 3600", g.TTL)
	}
	if g.SandboxUID != "k8s-uid-xyz" {
		t.Errorf("sandbox_uid=%q want k8s-uid-xyz", g.SandboxUID)
	}
}

func TestFromVaultData_Absent(t *testing.T) {
	_, err := grant.FromVaultData(nil)
	if err == nil {
		t.Fatal("expected error for nil map")
	}
	if !grant.IsValidationError(err, grant.ResultAbsent) {
		t.Errorf("expected ResultAbsent, got: %v", err)
	}
}

func TestFromVaultData_Empty(t *testing.T) {
	_, err := grant.FromVaultData(map[string]any{})
	if err == nil {
		t.Fatal("expected error for empty map")
	}
	if !grant.IsValidationError(err, grant.ResultAbsent) {
		t.Errorf("expected ResultAbsent, got: %v", err)
	}
}

func TestFromVaultData_BadCreated(t *testing.T) {
	data := map[string]any{
		"user":        "arsalan",
		"scope":       "read-only",
		"ttl":         float64(3600),
		"nonce":       "deadbeef",
		"created":     "not-a-timestamp",
		"sandbox_uid": "k8s-uid-xyz",
		"version":     float64(1),
	}
	_, err := grant.FromVaultData(data)
	if err == nil {
		t.Fatal("expected error for bad created timestamp")
	}
	if !grant.IsValidationError(err, grant.ResultMalformed) {
		t.Errorf("expected ResultMalformed, got: %v", err)
	}
}

func TestFromVaultData_MissingUser(t *testing.T) {
	now := time.Now().UTC()
	data := map[string]any{
		"scope":       "read-only",
		"ttl":         float64(3600),
		"nonce":       "deadbeef",
		"created":     now.Format(time.RFC3339Nano),
		"sandbox_uid": "k8s-uid-xyz",
		"version":     float64(1),
	}
	_, err := grant.FromVaultData(data)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

// --- CheckTTLCap (Finding 3) ---

func TestGrant_CheckTTLCap_WithinCap(t *testing.T) {
	g := baseGrant()
	g.TTL = 3600 // exactly at cap — must not be rejected
	if err := g.CheckTTLCap(); err != nil {
		t.Fatalf("expected TTL at cap to be accepted, got: %v", err)
	}
}

func TestGrant_CheckTTLCap_BelowCap(t *testing.T) {
	g := baseGrant()
	g.TTL = 60
	if err := g.CheckTTLCap(); err != nil {
		t.Fatalf("expected TTL below cap to be accepted, got: %v", err)
	}
}

func TestGrant_CheckTTLCap_ExceedsCap(t *testing.T) {
	g := baseGrant()
	g.TTL = grant.MaxGrantTTLSeconds + 1
	err := g.CheckTTLCap()
	if err == nil {
		t.Fatal("expected error for TTL exceeding platform cap, got nil")
	}
	if !grant.IsValidationError(err, grant.ResultMalformed) {
		t.Errorf("expected ResultMalformed for oversized TTL, got: %v", err)
	}
}

func TestGrant_CheckTTLCap_FarExceedsCap(t *testing.T) {
	g := baseGrant()
	g.TTL = 86400 // 24 hours — well above 3600s cap
	err := g.CheckTTLCap()
	if err == nil {
		t.Fatal("expected error for TTL=86400 exceeding platform cap, got nil")
	}
}

// TestFromVaultData_ProhibitedFields ensures no credential field bleeds through.
// The grant schema only defines safe fields; any extra key in the Vault doc is
// silently ignored by FromVaultData, so a write that accidentally included a
// credential would NOT be returned in Grant. This test documents that invariant.
func TestFromVaultData_ProhibitedFieldsIgnored(t *testing.T) {
	now := time.Now().UTC()
	data := map[string]any{
		"user":         "arsalan",
		"scope":        "read-only",
		"ttl":          float64(3600),
		"nonce":        "deadbeef",
		"created":      now.Format(time.RFC3339Nano),
		"sandbox_uid":  "k8s-uid-xyz",
		"version":      float64(1),
		"access_token": "should-never-appear",
		"bearer":       "should-never-appear",
		"password":     "should-never-appear",
	}
	g, err := grant.FromVaultData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify the returned grant struct has no credential field.
	// (Grant has no such fields; this is a compile-time guarantee,
	// but we document it here explicitly.)
	_ = g
}
