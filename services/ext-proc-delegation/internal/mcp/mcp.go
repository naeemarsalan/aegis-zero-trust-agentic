// Package mcp parses JSON-RPC 2.0 bodies used by MCP tool calls and provides
// a stable SHA-256 hash of the tool arguments for audit logging.
package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// Request represents the fields of an MCP JSON-RPC tool-call body that we care about.
type Request struct {
	// Method is the JSON-RPC method (e.g. "tools/call").
	Method string
	// Tool is params.name — the tool being called.
	Tool string
	// Arguments is the raw params.arguments object (kept as json.RawMessage for hashing).
	Arguments json.RawMessage
	// ArgsHash is the stable Sha256Hex of the canonical JSON arguments.
	ArgsHash string
}

// jsonrpcBody is used for unmarshalling the incoming body.
type jsonrpcBody struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type mcpParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ErrNotMCPToolCall is returned when the body is valid JSON-RPC but not a tool call.
var ErrNotMCPToolCall = errors.New("not an MCP tool call (method != tools/call)")

// Parse parses a raw JSON-RPC body and returns the MCP tool request.
// It returns ErrNotMCPToolCall if the method is not "tools/call".
func Parse(body []byte) (*Request, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}

	var rpc jsonrpcBody
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, fmt.Errorf("JSON-RPC parse: %w", err)
	}

	req := &Request{Method: rpc.Method}

	if rpc.Method != "tools/call" {
		return req, ErrNotMCPToolCall
	}

	if rpc.Params == nil {
		return req, nil
	}

	var p mcpParams
	if err := json.Unmarshal(rpc.Params, &p); err != nil {
		return req, fmt.Errorf("MCP params parse: %w", err)
	}
	req.Tool = p.Name
	req.Arguments = p.Arguments

	hash, err := Sha256Hex(p.Arguments)
	if err != nil {
		return req, fmt.Errorf("args hash: %w", err)
	}
	req.ArgsHash = hash

	return req, nil
}

// Sha256Hex returns the lowercase hex SHA-256 of the canonical (re-serialized) JSON.
// If raw is nil or empty, it hashes the empty object "{}".
func Sha256Hex(raw json.RawMessage) (string, error) {
	canonical, err := canonicalize(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum), nil
}

// canonicalize re-marshals JSON to get a deterministic byte representation.
// Keys in objects are sorted by encoding/json's default marshal order (alphabetical
// for map[string]interface{}).
func canonicalize(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("canonicalize unmarshal: %w", err)
	}
	// Re-serialize; encoding/json sorts map keys alphabetically.
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize marshal: %w", err)
	}
	return out, nil
}
