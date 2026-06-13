// Package rbac implements ext-proc tool-level authorization — the enforcement
// the three Kyverno authz policies describe, moved into ext-proc because this
// agentgateway alpha forwards no JWT claims to the ext_authz hop and the
// deployed kyverno-envoy-plugin lacks the `mcp` CEL library.
//
//	tool-allowlist-mcp-users   -> mcp-users may only call read-only tools
//	dangerous-tools-admins-only-> dangerous tools require mcp-admins AND a valid
//	                              jit-approver session JWT whose tool_scope covers
//	                              the tool (UC2)
//	deny-restricted-group      -> the "restricted" group is denied everything
//
// Decisions are driven by prefix tables so they stay declarative/config-driven.
package rbac

import "strings"

// Policy holds the (config-driven) classification tables.
type Policy struct {
	ReadOnlyPrefixes  []string
	DangerousPrefixes []string
	RestrictedGroup   string
	AdminGroup        string
	UserGroup         string
}

func hasGroup(groups []string, g string) bool {
	for _, x := range groups {
		if x == g {
			return true
		}
	}
	return false
}

func hasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Decide authorizes a single MCP tool call. Returns ("", true) to allow, or
// (reason, false) to deny. tool=="" means the request is not a tool call (MCP
// session handshake, tools/list, etc.) and is always allowed — RBAC gates only
// tools/call. jitValid/jitToolScope come from verifying the X-JIT-Session-JWT.
func (p Policy) Decide(groups []string, tool string, jitValid bool, jitToolScope []string) (string, bool) {
	// Restricted group is denied everything, unconditionally.
	if hasGroup(groups, p.RestrictedGroup) {
		return "restricted_group", false
	}

	if tool == "" {
		return "", true // not a tool call
	}

	if hasPrefix(tool, p.DangerousPrefixes) {
		if !hasGroup(groups, p.AdminGroup) {
			return "dangerous_requires_admin", false
		}
		if !jitValid {
			return "dangerous_requires_jit_session", false
		}
		for _, s := range jitToolScope {
			if s == tool {
				return "", true
			}
		}
		return "tool_not_in_jit_scope", false
	}

	// Non-dangerous tool.
	if hasGroup(groups, p.AdminGroup) {
		return "", true
	}
	if hasGroup(groups, p.UserGroup) {
		if hasPrefix(tool, p.ReadOnlyPrefixes) {
			return "", true
		}
		return "mcp_users_readonly_only", false
	}
	return "no_authorized_group", false
}
