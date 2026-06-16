// Package api provides typed clients and request/response structs for the
// sandbox-launcher, jit-approver, Gitea, and catalog endpoints.
package api

import "time"

// ---------------------------------------------------------------------------
// sandbox-launcher types
// ---------------------------------------------------------------------------

// LaunchRequest is the POST /launch body sent to sandbox-launcher.
type LaunchRequest struct {
	Goal         string   `json:"goal"`
	Capabilities []string `json:"capabilities"`
	Mode         string   `json:"mode"`         // "task" | "project"
	Scope        string   `json:"scope"`        // "read-only" | "read-write" | "admin"
	UserRef      string   `json:"userRef"`
	Confirmed    bool     `json:"confirmed"` // must be true
	TTLMinutes   int      `json:"ttlMinutes"` // 5-480
}

// LaunchResponse is the 202 body returned by POST /launch.
type LaunchResponse struct {
	SandboxName     string `json:"sandbox_name"`
	SandboxID       string `json:"sandbox_id"`
	Namespace       string `json:"namespace"`
	Phase           string `json:"phase"`
	ConversationURL string `json:"conversation_url"` // nullable
	AccessHint      string `json:"access_hint"`
	Owner           string `json:"owner"`
}

// ---------------------------------------------------------------------------
// jit-approver types
// ---------------------------------------------------------------------------

// JitSession is one entry from GET /requests.
type JitSession struct {
	ID        string    `json:"id"`
	State     string    `json:"state"` // pending|approved|issued|expired|denied
	PRURL     string    `json:"pr_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PolicyDelta is one host:port entry in a JIT detail.
type PolicyDelta struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// JitDetail is the response from GET /requests/{id}/detail.
type JitDetail struct {
	ID              string        `json:"id"`
	State           string        `json:"state"`
	ExpiresAt       time.Time     `json:"expires_at"`
	PRURL           string        `json:"pr_url"`
	RequesterSub    string        `json:"requester_sub"`
	Namespace       string        `json:"namespace"`
	Verbs           []string      `json:"verbs"`
	Resources       []string      `json:"resources"`
	DurationMinutes int           `json:"duration_minutes"`
	Justification   string        `json:"justification"`
	Sandbox         string        `json:"sandbox"`
	PolicyDelta     []PolicyDelta `json:"policy_delta"`
}

// JitStatus is the response from GET /requests/{id}/status.
// Credential fields are only present over SVID-mTLS; the CLI treats them as absent.
type JitStatus struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	PRURL     string    `json:"pr_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JitReceipt is the response from GET /requests/{id}/receipt.
type JitReceipt struct {
	ID           string   `json:"id"`
	State        string   `json:"state"`
	ExpiresAt    time.Time `json:"expires_at"`
	ToolScope    []string `json:"tool_scope"`
	Outcome      string   `json:"outcome"`
	Allowed      []string `json:"allowed"`
	Errors       []string `json:"errors"`
	Denied       []string `json:"denied"`
	DeniedSource string   `json:"denied_source"`
}

// JitSummary is the response from GET /requests/{id}/summary.
type JitSummary struct {
	Outcome         string   `json:"outcome"`
	ActionsTaken    []string `json:"actions_taken"`
	ErrorsEncountered []string `json:"errors_encountered"`
}

// ---------------------------------------------------------------------------
// catalog types
// ---------------------------------------------------------------------------

// MCPServer describes a registered MCP server in the catalog.
type MCPServer struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Address     string `json:"address"`
	Protocol    string `json:"protocol"` // "StreamableHTTP" | "gRPC"
	Capabilities []string `json:"capabilities"`
}
