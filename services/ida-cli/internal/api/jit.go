package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// JitClient calls the jit-approver service.
type JitClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewJitClient constructs a JitClient pointed at baseURL.
// caFile and insecure are forwarded to NewHTTPClient to configure TLS; pass
// ("", false) to use system roots with full verification (the safe default).
func NewJitClient(baseURL, caFile string, insecure bool) (*JitClient, error) {
	hc, err := NewHTTPClient(caFile, insecure, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("jit: build http client: %w", err)
	}
	return &JitClient{
		baseURL:    baseURL,
		httpClient: hc,
	}, nil
}

// List fetches JIT sessions filtered by sandbox name and/or state.
// Either argument may be empty to omit the corresponding filter.
func (c *JitClient) List(ctx context.Context, sandbox, state string) ([]JitSession, error) {
	q := url.Values{}
	if sandbox != "" {
		q.Set("sandbox", sandbox)
	}
	if state != "" {
		q.Set("state", state)
	}
	endpoint := c.baseURL + "/requests"
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	var out []JitSession
	if err := c.get(ctx, endpoint, "jit.list", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Detail fetches full detail for a JIT request by ID.
func (c *JitClient) Detail(ctx context.Context, id string) (JitDetail, error) {
	var out JitDetail
	if err := c.get(ctx, c.baseURL+"/requests/"+id+"/detail", "jit.detail", &out); err != nil {
		return JitDetail{}, err
	}
	return out, nil
}

// Status fetches the current state of a JIT request. Credential fields are
// absent (SVID-mTLS required, which the CLI does not have).
func (c *JitClient) Status(ctx context.Context, id string) (JitStatus, error) {
	var out JitStatus
	if err := c.get(ctx, c.baseURL+"/requests/"+id+"/status", "jit.status", &out); err != nil {
		return JitStatus{}, err
	}
	return out, nil
}

// Receipt fetches the outcome receipt for a completed JIT request.
func (c *JitClient) Receipt(ctx context.Context, id string) (JitReceipt, error) {
	var out JitReceipt
	if err := c.get(ctx, c.baseURL+"/requests/"+id+"/receipt", "jit.receipt", &out); err != nil {
		return JitReceipt{}, err
	}
	return out, nil
}

// Summary fetches the action summary for a JIT request. Returns a
// (JitSummary{}, ErrNotFound) if none exists (404).
func (c *JitClient) Summary(ctx context.Context, id string) (JitSummary, error) {
	var out JitSummary
	if err := c.get(ctx, c.baseURL+"/requests/"+id+"/summary", "jit.summary", &out); err != nil {
		return JitSummary{}, err
	}
	return out, nil
}

// get is a shared helper that issues a GET, checks the status, and decodes JSON.
func (c *JitClient) get(ctx context.Context, endpoint, event string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("jit: build request: %w", err)
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		slog.ErrorContext(ctx, "jit.get: http error",
			"event", event,
			"latency_ms", latency,
			"outcome", "error",
			"error", err,
		)
		return fmt.Errorf("jit: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		slog.WarnContext(ctx, "jit.get: not found",
			"event", event,
			"endpoint", endpoint,
			"latency_ms", latency,
			"outcome", "deny",
		)
		return fmt.Errorf("jit: %s: not found (404)", event)
	}
	if resp.StatusCode != http.StatusOK {
		slog.WarnContext(ctx, "jit.get: unexpected status",
			"event", event,
			"status", resp.StatusCode,
			"latency_ms", latency,
			"outcome", "error",
		)
		return fmt.Errorf("jit: %s: unexpected status %d", event, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("jit: %s: decode: %w", event, err)
	}
	slog.InfoContext(ctx, "jit.get: ok",
		"event", event,
		"latency_ms", latency,
		"outcome", "allow",
	)
	return nil
}
