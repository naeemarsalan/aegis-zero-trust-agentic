// Package vault implements Vault JWT-auth login and KV secret retrieval.
// The SVID JWT is fetched from the SPIFFE JWTSource on each login; the
// client_token is cached until ~80% of its TTL expires.
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

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
)

// JWTSourcer can fetch a JWT-SVID for a given audience.
// Implemented by *workloadapi.JWTSource for production and a stub in tests.
type JWTSourcer interface {
	FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
}

// Client handles Vault authentication and KV secret reads.
type Client struct {
	addr      string
	jwtRole   string
	jwtAud    string
	secretPfx string
	jwtSource JWTSourcer
	httpClient *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// loginResponse is the minimal shape of Vault's auth response.
type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"` // seconds
	} `json:"auth"`
}

// kvResponse wraps a Vault KV v2 secret.
type kvResponse struct {
	Data struct {
		Data map[string]interface{} `json:"data"`
	} `json:"data"`
}

// NewClient creates a Vault client.
func NewClient(cfg *config.Config, jwtSource JWTSourcer) *Client {
	return &Client{
		addr:      cfg.VaultAddr,
		jwtRole:   cfg.VaultJWTRole,
		jwtAud:    cfg.VaultJWTAudience,
		secretPfx: cfg.ToolSecretPathPrefix,
		jwtSource: jwtSource,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// NewClientWithHTTP creates a Vault client with a custom HTTP client (for testing).
func NewClientWithHTTP(addr, jwtRole, jwtAud, secretPfx string, jwtSource JWTSourcer, hc *http.Client) *Client {
	return &Client{
		addr:       addr,
		jwtRole:    jwtRole,
		jwtAud:     jwtAud,
		secretPfx:  secretPfx,
		jwtSource:  jwtSource,
		httpClient: hc,
	}
}

// Login authenticates to Vault using a JWT-SVID and caches the resulting token.
// It is safe for concurrent use — only one login is in flight at a time.
func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return nil // cached token still valid
	}

	svid, err := c.jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: c.jwtAud,
	})
	if err != nil {
		return fmt.Errorf("vault: fetch JWT-SVID: %w", err)
	}

	// Always name the role EXPLICITLY (c.jwtRole, e.g. "ext-proc-delegation").
	// We do NOT rely on any Vault auth/jwt default_role — the role is explicit
	// per login so a server-side default_role change cannot silently re-scope us.
	payload := map[string]string{
		"role": c.jwtRole,
		"jwt":  svid.Marshal(),
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
	// Cache until 80% of TTL.
	c.tokenExpiry = time.Now().Add(time.Duration(float64(ttl) * 0.8))
	return nil
}

// FetchToolSecret returns the KV data map for the named tool.
// Automatically re-logins if the cached token has expired.
func (c *Client) FetchToolSecret(ctx context.Context, tool string) (map[string]interface{}, error) {
	if err := c.Login(ctx); err != nil {
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
