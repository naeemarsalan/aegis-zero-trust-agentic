package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GiteaClient calls the Gitea API.
type GiteaClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewGiteaClient constructs a GiteaClient.
// baseURL should be the root of the Gitea instance (e.g. https://gitea.example.com).
// token is the personal access token stored in config.
// caFile and insecure are forwarded to NewHTTPClient to configure TLS; pass
// ("", false) to use system roots with full verification (the safe default).
func NewGiteaClient(baseURL, token, caFile string, insecure bool) (*GiteaClient, error) {
	hc, err := NewHTTPClient(caFile, insecure, 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("gitea: build http client: %w", err)
	}
	return &GiteaClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: hc,
	}, nil
}

// mergePRBody is the body for the Gitea merge endpoint.
type mergePRBody struct {
	Do string `json:"Do"`
}

// MergePR merges the Gitea pull request identified by prURL.
// prURL must follow the pattern {giteaBase}/{owner}/{repo}/pulls/{index}.
// The host in prURL MUST match the configured Gitea base host; if it does not,
// MergePR returns an error and does not send the credential to a third party.
// The caller MUST obtain explicit user confirmation before calling this method.
func (c *GiteaClient) MergePR(ctx context.Context, prURL string) error {
	// Validate that prURL points at the same host as the configured base.
	// This prevents a compromised jit-approver from returning a foreign URL that
	// would cause the CLI to POST the user's Gitea PAT to an attacker-controlled host.
	if err := c.assertSameHost(prURL); err != nil {
		slog.ErrorContext(ctx, "gitea.merge: host mismatch — refusing to send credential",
			"event", "gitea.merge_pr",
			"outcome", "deny",
			"error", err,
		)
		return fmt.Errorf("gitea: host validation: %w", err)
	}

	owner, repo, index, err := parsePRURL(prURL)
	if err != nil {
		return fmt.Errorf("gitea: parse pr_url: %w", err)
	}

	// Build the endpoint from the trusted configured baseURL only — never from
	// the host embedded in prURL.
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/pulls/%d/merge",
		c.baseURL, owner, repo, index)

	body, err := json.Marshal(mergePRBody{Do: "merge"})
	if err != nil {
		return fmt.Errorf("gitea: marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gitea: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+c.token)

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		slog.ErrorContext(ctx, "gitea.merge: http error",
			"event", "gitea.merge_pr",
			"pr_url", prURL,
			"latency_ms", latency,
			"outcome", "error",
			"error", err,
		)
		return fmt.Errorf("gitea: http: %w", err)
	}
	defer resp.Body.Close()

	// Gitea returns 200 or 204 on success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		slog.WarnContext(ctx, "gitea.merge: unexpected status",
			"event", "gitea.merge_pr",
			"pr_url", prURL,
			"status", resp.StatusCode,
			"latency_ms", latency,
			"outcome", "error",
		)
		return fmt.Errorf("gitea: merge PR: unexpected status %d", resp.StatusCode)
	}

	slog.InfoContext(ctx, "gitea.merge: PR merged",
		"event", "gitea.merge_pr",
		"owner", owner,
		"repo", repo,
		"index", index,
		"latency_ms", latency,
		"outcome", "allow",
	)
	return nil
}

// parsePRURL extracts owner, repo, and PR index from a Gitea PR URL of the
// form https://{host}/{owner}/{repo}/pulls/{index}.
func parsePRURL(prURL string) (owner, repo string, index int, err error) {
	u, err := url.Parse(prURL)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", "", 0, fmt.Errorf("URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", "", 0, fmt.Errorf("URL has no host: %q", prURL)
	}
	// Path: /{owner}/{repo}/pulls/{index}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "pulls" {
		return "", "", 0, fmt.Errorf("URL path must be /{owner}/{repo}/pulls/{index}, got %q", u.Path)
	}
	owner = parts[0]
	repo = parts[1]
	idx, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", "", 0, fmt.Errorf("PR index is not an integer: %q", parts[3])
	}
	return owner, repo, idx, nil
}

// assertSameHost verifies that the scheme+host in prURL matches the scheme+host
// in the client's configured baseURL. Returns an error if they differ.
// This is a security invariant: we must never send c.token to a third-party host.
func (c *GiteaClient) assertSameHost(prURL string) error {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("client baseURL is invalid: %w", err)
	}
	pr, err := url.Parse(prURL)
	if err != nil {
		return fmt.Errorf("pr_url is invalid: %w", err)
	}
	// Compare scheme and host (host includes port if non-standard).
	if !strings.EqualFold(pr.Scheme, base.Scheme) || !strings.EqualFold(pr.Host, base.Host) {
		return fmt.Errorf("pr_url host %q does not match configured Gitea host %q",
			pr.Scheme+"://"+pr.Host, base.Scheme+"://"+base.Host)
	}
	return nil
}
