package mcp_test

import (
	"encoding/json"
	"testing"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/mcp"
)

func TestParse_ToolCall(t *testing.T) {
	body := []byte(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"tools/call",
		"params":{
			"name":"list-routes",
			"arguments":{"cidr":"10.0.0.0/8","limit":100}
		}
	}`)

	req, err := mcp.Parse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "tools/call" {
		t.Errorf("Method=%q want tools/call", req.Method)
	}
	if req.Tool != "list-routes" {
		t.Errorf("Tool=%q want list-routes", req.Tool)
	}
	if req.ArgsHash == "" {
		t.Error("ArgsHash should not be empty")
	}
}

func TestParse_NotToolCall(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req, err := mcp.Parse(body)
	if err != mcp.ErrNotMCPToolCall {
		t.Errorf("expected ErrNotMCPToolCall, got %v", err)
	}
	if req.Method != "initialize" {
		t.Errorf("Method=%q want initialize", req.Method)
	}
}

func TestParse_Empty(t *testing.T) {
	_, err := mcp.Parse(nil)
	if err == nil {
		t.Fatal("expected error for nil body")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := mcp.Parse([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSha256Hex_Stable(t *testing.T) {
	// Same logical content, different key order -> same hash.
	a := json.RawMessage(`{"b":2,"a":1}`)
	b := json.RawMessage(`{"a":1,"b":2}`)

	ha, err := mcp.Sha256Hex(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := mcp.Sha256Hex(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Errorf("hashes differ for equivalent JSON: %q vs %q", ha, hb)
	}
}

func TestSha256Hex_NilArgs(t *testing.T) {
	h, err := mcp.Sha256Hex(nil)
	if err != nil {
		t.Fatal(err)
	}
	if h == "" {
		t.Error("expected non-empty hash for nil args")
	}
	// Hash of "{}" — deterministic.
	h2, _ := mcp.Sha256Hex(json.RawMessage(`{}`))
	if h != h2 {
		t.Errorf("nil and {} should produce same hash; got %q vs %q", h, h2)
	}
}

func TestSha256Hex_Distinct(t *testing.T) {
	a := json.RawMessage(`{"cidr":"10.0.0.0/8"}`)
	b := json.RawMessage(`{"cidr":"192.168.0.0/16"}`)
	ha, _ := mcp.Sha256Hex(a)
	hb, _ := mcp.Sha256Hex(b)
	if ha == hb {
		t.Error("different args should produce different hashes")
	}
}
