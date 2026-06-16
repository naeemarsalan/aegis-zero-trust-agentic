// Package auth provides Keycloak OAuth2 device-code flow and token persistence.
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
)

// DeviceFlowConfig holds the parameters needed to run a device-code flow.
type DeviceFlowConfig struct {
	RealmURL string // e.g. https://keycloak.example.com/realms/myrealm
	ClientID string
	// CAFile is the path to a PEM CA bundle appended to the system trust roots.
	// Leave empty to use only the system cert pool (the safe default).
	CAFile string
	// Insecure disables TLS certificate verification. MUST only be set in
	// PoC/dev environments; default false (full verification).
	Insecure bool
}

// oauth2Config builds an *oauth2.Config for device flow against the given realm.
func (d DeviceFlowConfig) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID: d.ClientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: d.RealmURL + "/protocol/openid-connect/auth/device",
			TokenURL:      d.RealmURL + "/protocol/openid-connect/token",
		},
		Scopes: []string{"openid", "profile", "email"},
	}
}

// Login initiates the Keycloak OAuth2 device-code flow. It prints the
// device-code URL and user-code to stdout, then blocks until the user
// completes the flow or ctx is cancelled.
//
// On success the returned *oauth2.Token includes a refresh token.
//
// TLS behaviour: if cfg.CAFile is set the PEM bundle is loaded and added to
// the system trust roots. If cfg.Insecure is true TLS verification is
// disabled (a slog.Warn is emitted). An empty/zero cfg defaults to full TLS
// verification using the system cert pool, identical to the previous behaviour.
func Login(ctx context.Context, cfg DeviceFlowConfig) (*oauth2.Token, error) {
	// Build a TLS-configured HTTP client and inject it into the context so that
	// the golang.org/x/oauth2 device-code library uses it for all requests
	// (device auth and token polling). A nil caFile + insecure=false falls
	// through to system roots with no behavioural change vs. the old code.
	httpClient, err := api.NewHTTPClient(cfg.CAFile, cfg.Insecure, 30*time.Second)
	if err != nil {
		slog.ErrorContext(ctx, "auth.device: failed to build TLS HTTP client", "error", err)
		return nil, fmt.Errorf("auth: device flow: build http client: %w", err)
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	oc := cfg.oauth2Config()

	resp, err := oc.DeviceAuth(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "auth.device: device auth request failed", "error", err)
		return nil, fmt.Errorf("auth: device auth: %w", err)
	}

	fmt.Printf("\n  Open this URL in your browser:\n\n    %s\n\n", resp.VerificationURIComplete)
	fmt.Printf("  User code: %s\n\n  Waiting for authorization...\n", resp.UserCode)

	tok, err := oc.DeviceAccessToken(ctx, resp)
	if err != nil {
		slog.ErrorContext(ctx, "auth.device: token exchange failed", "error", err)
		return nil, fmt.Errorf("auth: device access token: %w", err)
	}

	slog.InfoContext(ctx, "auth.device: login successful")
	return tok, nil
}

// newDeviceHTTPClient is a package-internal helper used by tests to verify
// that a non-nil *http.Client is built for the given TLS parameters without
// running a full device flow.
func newDeviceHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	return api.NewHTTPClient(caFile, insecure, 30*time.Second)
}
