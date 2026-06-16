package api

// Catalog provides a static list of known MCP servers.
// The downstream agents will extend this with dynamic discovery.
type Catalog struct{}

// NewCatalog constructs a Catalog.
func NewCatalog() *Catalog { return &Catalog{} }

// List returns the static set of MCP servers known at build time.
func (c *Catalog) List() []MCPServer {
	return []MCPServer{
		{
			Name:        "mcp-pfsense",
			Description: "pfSense firewall management via REST API v2",
			Address:     "pfsense-mcp.agentic-mcp.svc.cluster.local:8000",
			Protocol:    "StreamableHTTP",
			Capabilities: []string{
				"firewall.rules.read",
				"firewall.rules.write",
				"firewall.aliases.read",
				"firewall.aliases.write",
				"nat.read",
				"nat.write",
			},
		},
		{
			Name:        "mcp-echo",
			Description: "Echo MCP server for testing and development",
			Address:     "echo-mcp.agentic-mcp.svc.cluster.local:8000",
			Protocol:    "StreamableHTTP",
			Capabilities: []string{
				"echo",
				"ping",
			},
		},
	}
}
