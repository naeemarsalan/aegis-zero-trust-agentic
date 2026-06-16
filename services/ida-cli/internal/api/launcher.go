package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// LauncherClient calls the sandbox-launcher service.
type LauncherClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewLauncherClient constructs a LauncherClient pointed at baseURL.
// caFile and insecure are forwarded to NewHTTPClient to configure TLS; pass
// ("", false) to use system roots with full verification (the safe default).
func NewLauncherClient(baseURL, caFile string, insecure bool) (*LauncherClient, error) {
	hc, err := NewHTTPClient(caFile, insecure, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("launcher: build http client: %w", err)
	}
	return &LauncherClient{
		baseURL:    baseURL,
		httpClient: hc,
	}, nil
}

// Launch sends POST /launch. bearer is the Keycloak access token for the user.
// Returns the 202 response or a typed error.
func (c *LauncherClient) Launch(ctx context.Context, req LaunchRequest, bearer string) (LaunchResponse, error) {
	if !req.Confirmed {
		return LaunchResponse{}, fmt.Errorf("launcher: confirmed must be true before calling Launch")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return LaunchResponse{}, fmt.Errorf("launcher: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/launch", bytes.NewReader(body))
	if err != nil {
		return LaunchResponse{}, fmt.Errorf("launcher: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearer)

	start := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		slog.ErrorContext(ctx, "launcher.launch: http error",
			"event", "launch.sandbox",
			"latency_ms", latency,
			"outcome", "error",
			"error", err,
		)
		return LaunchResponse{}, fmt.Errorf("launcher: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		slog.WarnContext(ctx, "launcher.launch: non-202 response",
			"event", "launch.sandbox",
			"status", resp.StatusCode,
			"latency_ms", latency,
			"outcome", "deny",
		)
		return LaunchResponse{}, fmt.Errorf("launcher: unexpected status %d", resp.StatusCode)
	}

	var out LaunchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return LaunchResponse{}, fmt.Errorf("launcher: decode response: %w", err)
	}

	slog.InfoContext(ctx, "launcher.launch: success",
		"event", "launch.sandbox",
		"sandbox_name", out.SandboxName,
		"latency_ms", latency,
		"outcome", "allow",
	)
	return out, nil
}
