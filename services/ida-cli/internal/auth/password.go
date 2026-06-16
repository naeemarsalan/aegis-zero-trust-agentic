// Package auth — Resource Owner Password Credentials (ROPC) grant.
//
// This flow is provided for browserless / CI environments where the device-code
// flow is impractical. The caller is responsible for obtaining the password
// securely (e.g. via golang.org/x/term ReadPassword); this file never touches
// credentials beyond the single HTTP call and MUST NOT log them.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
)

// PasswordGrantConfig holds the parameters for an ROPC token request.
type PasswordGrantConfig struct {
	RealmURL     string // e.g. https://keycloak.example.com/realms/myrealm
	ClientID     string
	ClientSecret string // optional; omit (empty) for public clients
	// CAFile is the path to a PEM CA bundle appended to the system trust roots.
	// Leave empty to use only the system cert pool (the safe default).
	CAFile string
	// Insecure disables TLS certificate verification. MUST only be set in
	// PoC/dev environments; default false (full verification).
	Insecure bool
}

// passwordTokenResponse is the JSON shape returned by the Keycloak token endpoint.
type passwordTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	// Error fields — set when the grant fails.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// PasswordLogin performs an OAuth2 Resource Owner Password Credentials grant
// against the Keycloak token endpoint and returns a *TokenResult on success.
//
// Security invariants:
//   - The password is NEVER logged, stored beyond this call, or included in any
//     returned struct.
//   - The returned TokenResult contains only the access/refresh tokens and expiry.
//   - On any error the function returns a non-nil error and nil token.
//
// TLS behaviour: cfg.CAFile and cfg.Insecure mirror the semantics of
// api.NewHTTPClient — see that function's doc for details. The 15-second
// timeout is preserved regardless of TLS configuration.
func PasswordLogin(ctx context.Context, cfg PasswordGrantConfig, username, password string) (*TokenResult, error) {
	tokenURL := cfg.RealmURL + "/protocol/openid-connect/token"

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", cfg.ClientID)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid profile email")
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.ErrorContext(ctx, "auth.password: failed to build token request", "error", err)
		return nil, fmt.Errorf("auth: password grant: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Build a TLS-configured HTTP client. The 15-second timeout is preserved.
	// An empty caFile + insecure=false is identical to the previous hard-coded
	// &http.Client{Timeout: 15s} with system roots.
	client, err := api.NewHTTPClient(cfg.CAFile, cfg.Insecure, 15*time.Second)
	if err != nil {
		slog.ErrorContext(ctx, "auth.password: failed to build TLS HTTP client", "error", err)
		return nil, fmt.Errorf("auth: password grant: build http client: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "auth.password: token request failed", "error", err)
		return nil, fmt.Errorf("auth: password grant: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		slog.ErrorContext(ctx, "auth.password: failed to read token response", "error", err)
		return nil, fmt.Errorf("auth: password grant: read response: %w", err)
	}

	var tok passwordTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		slog.ErrorContext(ctx, "auth.password: failed to parse token response", "error", err)
		return nil, fmt.Errorf("auth: password grant: parse response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Never log tok.ErrorDescription — it may echo back user input.
		slog.ErrorContext(ctx, "auth.password: token endpoint returned non-200",
			"status", resp.StatusCode,
			"error_code", tok.Error,
		)
		desc := tok.ErrorDescription
		if desc == "" {
			desc = tok.Error
		}
		if desc == "" {
			desc = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("auth: password grant: %s", desc)
	}

	if tok.AccessToken == "" {
		slog.ErrorContext(ctx, "auth.password: token response missing access_token")
		return nil, fmt.Errorf("auth: password grant: response missing access_token")
	}

	expiry := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)

	slog.InfoContext(ctx, "auth.password: login successful", "username", username)
	return &TokenResult{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       expiry,
		TokenType:    tok.TokenType,
	}, nil
}

// TokenResult carries the token fields returned by PasswordLogin.
// It intentionally does not embed oauth2.Token to keep the password package
// self-contained and avoid leaking scope strings into callers.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	TokenType    string
}
