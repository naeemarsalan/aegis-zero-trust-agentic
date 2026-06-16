// Package keycloak implements RFC8693 token exchange (and a legacy impersonation
// variant) against a Keycloak OIDC token endpoint.
package keycloak

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"encoding/json"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
)

// Client exchanges tokens against a Keycloak token endpoint.
type Client struct {
	tokenURL   string
	mode       config.ExchangeMode
	clientID   string
	secretFile string
	httpClient *http.Client
}

// tokenResponse is the successful JSON response from Keycloak.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

// NewClient creates a new Keycloak token-exchange client.
//
// The token-exchange MUST hit Keycloak's public route so the request's issuer
// context matches the subject token's `iss` (the in-cluster Service derives a
// different issuer and rejects the token as "Invalid token"). The route serves
// the OpenShift service-ca cert (wrong SAN for the public hostname), so set
// KEYCLOAK_TLS_INSECURE=true to skip verification of that hop. PoC-only.
func NewClient(cfg *config.Config) *Client {
	hc := &http.Client{Timeout: 5 * time.Second}
	if os.Getenv("KEYCLOAK_TLS_INSECURE") == "true" {
		hc.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // PoC: route serves a mismatched service-ca cert
		}
	}
	return &Client{
		tokenURL:   cfg.KeycloakTokenURL,
		mode:       cfg.ExchangeMode,
		clientID:   cfg.ExchangeClientID,
		secretFile: cfg.ExchangeSecretFile,
		httpClient: hc,
	}
}

// NewClientWithHTTP creates a client with a custom HTTP transport (for testing).
func NewClientWithHTTP(tokenURL string, mode config.ExchangeMode, clientID, secretFile string, hc *http.Client) *Client {
	return &Client{
		tokenURL:   tokenURL,
		mode:       mode,
		clientID:   clientID,
		secretFile: secretFile,
		httpClient: hc,
	}
}

// Exchange performs a token exchange returning the downstream access token.
// callerToken is the subject_token; audience is the target audience.
// Retries once on 5xx. Never logs token values.
func (c *Client) Exchange(ctx context.Context, callerToken, audience string) (string, error) {
	secret, err := c.readSecret()
	if err != nil {
		return "", fmt.Errorf("keycloak: read client secret: %w", err)
	}

	form := c.buildForm(callerToken, audience)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.doExchange(ctx, form, secret)
		if err != nil {
			var exchangeErr *ExchangeError
			if errors.As(err, &exchangeErr) && exchangeErr.StatusCode >= 500 {
				lastErr = err
				continue // retry once on 5xx
			}
			return "", err
		}
		return token, nil
	}
	return "", lastErr
}

// ExchangeOnBehalf performs RFC 8693 Phase-1 impersonation: the ext-proc
// service authenticates AS itself (client_id=mcp-gateway, using the confidential
// client secret from EXCHANGE_SECRET_FILE) and presents requested_subject=user
// to obtain a downstream token whose sub=user.
//
// SECURITY CONTRACT (Option D):
//   - There is NO subject_token (the user's original JWT was discarded at the
//     launcher; the agent never held it). The user identity comes exclusively
//     from the Vault consent grant.
//   - requested_subject MUST be a Keycloak preferred_username that is a member
//     of the mcp-users group (enforced by the Keycloak impersonation policy).
//   - This method MUST NOT be called when the inbound token is a Keycloak user
//     token — it is only for the SPIRE SVID / sandbox agent path.
//   - Never log user or the returned token.
func (c *Client) ExchangeOnBehalf(ctx context.Context, user, audience string) (string, error) {
	if user == "" {
		return "", errors.New("keycloak: ExchangeOnBehalf: user (requested_subject) is required")
	}
	if audience == "" {
		return "", errors.New("keycloak: ExchangeOnBehalf: audience is required")
	}

	secret, err := c.readSecret()
	if err != nil {
		return "", fmt.Errorf("keycloak: read client secret: %w", err)
	}

	form := c.buildOnBehalfForm(user, audience)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.doExchange(ctx, form, secret)
		if err != nil {
			var exchangeErr *ExchangeError
			if errors.As(err, &exchangeErr) && exchangeErr.StatusCode >= 500 {
				lastErr = err
				continue // retry once on 5xx
			}
			return "", err
		}
		return token, nil
	}
	return "", lastErr
}

// ExchangeError carries the HTTP status code from a failed exchange.
type ExchangeError struct {
	StatusCode int
	Message    string
}

func (e *ExchangeError) Error() string {
	return fmt.Sprintf("keycloak exchange: HTTP %d: %s", e.StatusCode, e.Message)
}

func (c *Client) buildForm(callerToken, audience string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", callerToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", audience)

	if c.mode == config.ModeLegacy {
		// Legacy impersonation: also set requested_subject
		form.Set("requested_subject", "")
	}
	return form
}

// buildOnBehalfForm builds the RFC 8693 token-exchange form for Phase-1
// impersonation: NO subject_token (the user JWT was discarded); only
// requested_subject carrying the user's Keycloak preferred_username.
// The service authenticates as itself via HTTP Basic Auth (client_id + secret).
func (c *Client) buildOnBehalfForm(user, audience string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("requested_subject", user)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", audience)
	// subject_token is intentionally absent — we are impersonating via
	// requested_subject only (Phase-1 impersonation). The service's identity is
	// proved by HTTP Basic Auth with the confidential client credentials.
	return form
}

func (c *Client) doExchange(ctx context.Context, form url.Values, clientSecret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusUnauthorized {
		return "", &ExchangeError{StatusCode: resp.StatusCode, Message: "unauthorized"}
	}
	if resp.StatusCode >= 400 {
		return "", &ExchangeError{StatusCode: resp.StatusCode, Message: "upstream error"}
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("keycloak: parse response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("keycloak: empty access_token in response")
	}
	return tr.AccessToken, nil
}

func (c *Client) readSecret() (string, error) {
	if c.secretFile == "" {
		return "", errors.New("EXCHANGE_SECRET_FILE not configured")
	}
	data, err := os.ReadFile(c.secretFile)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", c.secretFile, err)
	}
	return strings.TrimSpace(string(data)), nil
}
