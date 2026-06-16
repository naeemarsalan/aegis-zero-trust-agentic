package api

import (
	"testing"
)

func TestNewCatalog_NotNil(t *testing.T) {
	c := NewCatalog()
	if c == nil {
		t.Fatal("NewCatalog() returned nil")
	}
}

func TestCatalogList_NonEmpty(t *testing.T) {
	c := NewCatalog()
	servers := c.List()
	if len(servers) == 0 {
		t.Fatal("List() returned empty slice; at least one MCP server expected")
	}
}

func TestCatalogList_AllFieldsPopulated(t *testing.T) {
	c := NewCatalog()
	servers := c.List()
	for i, s := range servers {
		if s.Name == "" {
			t.Errorf("[%d] Name is empty", i)
		}
		if s.Description == "" {
			t.Errorf("[%d] Description is empty", i)
		}
		if s.Address == "" {
			t.Errorf("[%d] Address is empty", i)
		}
		if s.Protocol == "" {
			t.Errorf("[%d] Protocol is empty", i)
		}
		if len(s.Capabilities) == 0 {
			t.Errorf("[%d] Capabilities is empty", i)
		}
	}
}

func TestCatalogList_ContainsPfsense(t *testing.T) {
	c := NewCatalog()
	servers := c.List()
	for _, s := range servers {
		if s.Name == "mcp-pfsense" {
			return
		}
	}
	t.Errorf("List() does not contain mcp-pfsense; got %v", serverNames(servers))
}

func TestCatalogList_StableMultipleCalls(t *testing.T) {
	c := NewCatalog()
	first := c.List()
	second := c.List()
	if len(first) != len(second) {
		t.Errorf("List() returned different lengths on consecutive calls: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Name != second[i].Name {
			t.Errorf("[%d] Name changed between calls: %q vs %q", i, first[i].Name, second[i].Name)
		}
	}
}

// serverNames is a helper for readable error messages.
func serverNames(servers []MCPServer) []string {
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = s.Name
	}
	return out
}
