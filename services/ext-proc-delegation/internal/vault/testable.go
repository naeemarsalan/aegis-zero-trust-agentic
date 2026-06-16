package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TestableClient is a Vault client for unit tests that bypasses SPIFFE JWTSVID
// by posting a pre-baked JWT string directly, avoiding the SPIFFE workload API.
type TestableClient struct {
	addr       string
	jwtRole    string
	secretPfx  string
	httpClient *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewTestableClient creates a vault client suitable for tests (no SPIFFE dependency).
// The jwtAud parameter is accepted but unused (matches production signature).
func NewTestableClient(addr, jwtRole, _ /* jwtAud */, secretPfx string, hc *http.Client) *TestableClient {
	return &TestableClient{
		addr:       addr,
		jwtRole:    jwtRole,
		secretPfx:  secretPfx,
		httpClient: hc,
	}
}

// login authenticates to the test Vault server using a stub JWT.
func (c *TestableClient) login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	payload := map[string]string{
		"role": c.jwtRole,
		"jwt":  "test-jwt-svid",
	}
	body, _ := json.Marshal(payload)

	url := strings.TrimRight(c.addr, "/") + "/v1/auth/jwt/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault: login HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("vault: login HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return fmt.Errorf("vault: parse login response: %w", err)
	}
	if lr.Auth.ClientToken == "" {
		return errors.New("vault: empty client_token in login response")
	}

	c.token = lr.Auth.ClientToken
	ttl := time.Duration(lr.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c.tokenExpiry = time.Now().Add(time.Duration(float64(ttl) * 0.8))
	return nil
}

// FetchGrant fetches the KV data map for a sandbox consent grant.
// Returns nil data when the Vault path returns 404.
func (c *TestableClient) FetchGrant(ctx context.Context, grantPathPrefix, sandboxUID string) (map[string]interface{}, error) {
	if err := c.login(ctx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()

	path := strings.TrimRight(grantPathPrefix, "/") + "/" + sandboxUID
	url := strings.TrimRight(c.addr, "/") + "/v1/" + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build grant request: %w", err)
	}
	req.Header.Set("X-Vault-Token", tok)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: grant HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // grant absent
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vault: grant HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var kv kvResponse
	if err := json.NewDecoder(resp.Body).Decode(&kv); err != nil {
		return nil, fmt.Errorf("vault: parse grant response: %w", err)
	}
	return kv.Data.Data, nil
}

// FetchToolSecret fetches the KV secret for the named tool.
func (c *TestableClient) FetchToolSecret(ctx context.Context, tool string) (map[string]interface{}, error) {
	if err := c.login(ctx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()

	path := strings.TrimRight(c.secretPfx, "/") + "/" + tool
	url := strings.TrimRight(c.addr, "/") + "/v1/" + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build secret request: %w", err)
	}
	req.Header.Set("X-Vault-Token", tok)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: secret HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vault: secret HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var kv kvResponse
	if err := json.NewDecoder(resp.Body).Decode(&kv); err != nil {
		return nil, fmt.Errorf("vault: parse secret response: %w", err)
	}
	return kv.Data.Data, nil
}
