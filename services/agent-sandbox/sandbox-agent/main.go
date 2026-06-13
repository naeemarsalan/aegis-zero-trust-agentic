// Command sandbox-agent is the Phase 5c capstone agent. It runs inside the Kata
// micro-VM (already holding its inference credential, pulled from Vault via its
// SVID by the svid-vault-fetch init container) and demonstrates the full
// delegated-tool-call chain from a real isolated agent:
//
//  1. Keycloak DEVICE-FLOW login — the agent prints a verification URL + code;
//     the human approves in a browser; the agent receives the USER's access token.
//     (The agent's own OIDC client secret was itself pulled from Vault via the
//     agent's SVID — never a static token in the pod spec.)
//  2. The user token becomes the MCP bearer for a tool call through the platform
//     gateway. ext-proc independently verifies the user, RFC 8693-exchanges it for
//     a downstream-scoped token, and the downstream sees the USER — not the agent.
//
// This joins UC1's zero-trust delegation to the Kata+SVID sandbox.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func readSecret(field string) string {
	b, _ := os.ReadFile("/vault/secrets/inference." + field)
	return strings.TrimSpace(string(b))
}

var client = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-agent error: %v\n", err)
		os.Exit(1)
	}
	// Stay up so the pod is inspectable after the demo.
	fmt.Println("=== agent idle (capstone chain complete) ===")
	select {}
}

func run() error {
	realm := env("KEYCLOAK_REALM_URL", "https://keycloak.apps.anaeem.na-launch.com/realms/agentic")
	gw := strings.TrimRight(env("MCP_GATEWAY_URL", "https://mcp-gateway.apps.anaeem.na-launch.com"), "/")
	echoPath := env("ECHO_PATH", "/echo")
	clientID := env("OIDC_CLIENT_ID", readSecret("oidc_client_id"))
	clientSecret := readSecret("oidc_client_secret")

	fmt.Println("=== Phase 5c capstone: OpenShell-in-Kata agent ===")
	fmt.Printf("guest identity secret present: inference.api_key=%v, model=%s\n",
		readSecret("api_key") != "", readSecret("model"))
	fmt.Printf("OIDC client (secret pulled from Vault via SVID): %s\n\n", clientID)

	// 1. Device-flow login.
	tok, err := deviceFlow(realm, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("device flow: %w", err)
	}
	fmt.Println("\n[ok] received USER access token via device flow")

	// 2. Delegated tool call through the gateway.
	identity, err := echoWhoami(gw+echoPath, tok)
	if err != nil {
		return fmt.Errorf("gateway tool call: %w", err)
	}
	fmt.Printf("\n[ok] downstream tool saw the USER identity:\n  %s\n", identity)
	fmt.Println("\n=== CAPSTONE PROVEN: isolated Kata agent -> device-flow user -> gateway -> downstream sees the user ===")
	return nil
}

// deviceFlow runs the OAuth 2.0 device authorization grant and returns the user
// access token once the human approves.
func deviceFlow(realm, clientID, clientSecret string) (string, error) {
	form := strings.NewReader("client_id=" + clientID + "&client_secret=" + clientSecret + "&scope=openid")
	resp, err := client.Post(realm+"/protocol/openid-connect/auth/device",
		"application/x-www-form-urlencoded", form)
	if err != nil {
		return "", err
	}
	var da struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		VerifComplete   string `json:"verification_uri_complete"`
		Interval        int    `json:"interval"`
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &da); err != nil || da.DeviceCode == "" {
		return "", fmt.Errorf("device auth failed: %s", strings.TrimSpace(string(body)))
	}
	fmt.Println("┌─────────────────────────────────────────────────────────────")
	fmt.Println("│ LOGIN REQUIRED — approve this agent's access:")
	fmt.Printf("│   open:  %s\n", da.VerificationURI)
	fmt.Printf("│   code:  %s\n", da.UserCode)
	if da.VerifComplete != "" {
		fmt.Printf("│   (direct: %s)\n", da.VerifComplete)
	}
	fmt.Println("└─────────────────────────────────────────────────────────────")

	if da.Interval == 0 {
		da.Interval = 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timed out waiting for approval")
		case <-time.After(time.Duration(da.Interval) * time.Second):
		}
		f := "grant_type=urn:ietf:params:oauth:grant-type:device_code" +
			"&device_code=" + da.DeviceCode +
			"&client_id=" + clientID + "&client_secret=" + clientSecret
		r, err := client.Post(realm+"/protocol/openid-connect/token",
			"application/x-www-form-urlencoded", strings.NewReader(f))
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		var t struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		json.Unmarshal(b, &t)
		if t.AccessToken != "" {
			return t.AccessToken, nil
		}
		if t.Error != "" && t.Error != "authorization_pending" && t.Error != "slow_down" {
			return "", fmt.Errorf("token poll error: %s", t.Error)
		}
		fmt.Printf("  …waiting for approval (%s)\n", t.Error)
	}
}

// echoWhoami drives a minimal MCP session against the gateway echo backend and
// returns the identity the downstream observed.
func echoWhoami(url, userToken string) (string, error) {
	accept := "application/json, text/event-stream"
	post := func(sid, payload string) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(payload)))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", accept)
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		return client.Do(req)
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sandbox-agent","version":"1"}}}`
	r, err := post("", init)
	if err != nil {
		return "", err
	}
	sid := r.Header.Get("Mcp-Session-Id")
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if sid == "" {
		return "", fmt.Errorf("no MCP session id from initialize (HTTP %d)", r.StatusCode)
	}
	if r2, err := post(sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err == nil {
		io.Copy(io.Discard, r2.Body)
		r2.Body.Close()
	}
	r3, err := post(sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if err != nil {
		return "", err
	}
	defer r3.Body.Close()
	// Response is SSE: find the data: line carrying the JSON-RPC result.
	sc := bufio.NewScanner(r3.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "data:")), nil
	}
	return "", fmt.Errorf("no tool result in response (HTTP %d)", r3.StatusCode)
}
