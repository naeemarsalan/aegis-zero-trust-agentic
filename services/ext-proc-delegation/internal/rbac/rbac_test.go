package rbac

import "testing"

func testPolicy() Policy {
	return Policy{
		ReadOnlyPrefixes:  []string{"get_", "list_", "search_"},
		DangerousPrefixes: []string{"create_", "delete_", "set_"},
		RestrictedGroup:   "restricted",
		AdminGroup:        "mcp-admins",
		UserGroup:         "mcp-users",
	}
}

func TestDecide(t *testing.T) {
	p := testPolicy()
	admin := []string{"mcp-admins", "mcp-users"}
	user := []string{"mcp-users"}
	restricted := []string{"mcp-users", "restricted"}

	cases := []struct {
		name      string
		groups    []string
		tool      string
		jitValid  bool
		jitScope  []string
		wantAllow bool
	}{
		{"non-tool always allowed", user, "", false, nil, true},
		{"restricted denied everything", restricted, "get_x", false, nil, false},
		{"mcp-user read allowed", user, "get_system_version", false, nil, true},
		{"mcp-user write denied", user, "create_alias", false, nil, false},
		{"mcp-user non-read non-dangerous denied", user, "reload_config_unknownverb", false, nil, false},
		{"admin non-dangerous allowed", admin, "whoami", false, nil, true},
		{"dangerous without admin denied", user, "create_alias", true, []string{"create_alias"}, false},
		{"dangerous admin without jit denied", admin, "create_alias", false, nil, false},
		{"dangerous admin jit out-of-scope denied", admin, "create_alias", true, []string{"delete_alias"}, false},
		{"dangerous admin jit in-scope allowed", admin, "create_alias", true, []string{"create_alias"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, allow := p.Decide(c.groups, c.tool, c.jitValid, c.jitScope)
			if allow != c.wantAllow {
				t.Fatalf("Decide(%v,%q,%v,%v) = (%q,%v), want allow=%v", c.groups, c.tool, c.jitValid, c.jitScope, reason, allow, c.wantAllow)
			}
		})
	}
}
