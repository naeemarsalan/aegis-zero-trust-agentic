package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
)

const (
	tokenFileName        = "token.json"
	tokenFileMode        = 0o600
	tokenExpirySafetyPad = 30 * time.Second
)

// TokenStore persists an OAuth2 token to ~/.config/ida/token.json and handles
// transparent refresh.
type TokenStore struct {
	mu         sync.Mutex
	path       string
	cfg        *oauth2.Config
	token      *oauth2.Token
	httpClient *http.Client // TLS-configured client for refresh requests
}

// NewTokenStore constructs a TokenStore. realmURL and clientID are used for
// refresh requests. caFile and insecure control TLS verification for those
// refresh HTTP calls in the same way as api.NewHTTPClient:
//   - caFile non-empty: PEM bundle appended to system trust roots.
//   - insecure true: TLS verification disabled (slog.Warn emitted).
//   - both empty/false: system roots with full verification (safe default).
func NewTokenStore(realmURL, clientID, caFile string, insecure bool) (*TokenStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("tokenstore: home dir: %w", err)
	}
	path := filepath.Join(home, ".config", "ida", tokenFileName)

	oc := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: realmURL + "/protocol/openid-connect/token",
		},
	}

	// Build the TLS-configured HTTP client once and reuse it for all refresh
	// calls. An empty caFile + insecure=false produces system-root behaviour,
	// identical to the previous (implicit) default.
	httpClient, err := api.NewHTTPClient(caFile, insecure, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tokenstore: build http client: %w", err)
	}

	ts := &TokenStore{path: path, cfg: oc, httpClient: httpClient}
	// Best-effort load; callers must call Login() if nil.
	_ = ts.load()
	return ts, nil
}

// AccessToken returns a valid access token string, refreshing if necessary.
// Returns an error if no token is stored or the refresh fails.
//
// The TLS-configured http.Client stored in ts.httpClient is injected into the
// context via the oauth2.HTTPClient key so that the oauth2 TokenSource uses it
// for the refresh HTTP request.
func (ts *TokenStore) AccessToken(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token == nil {
		return "", fmt.Errorf("tokenstore: no token stored; run 'ida login'")
	}

	if ts.token.Valid() && time.Until(ts.token.Expiry) > tokenExpirySafetyPad {
		return ts.token.AccessToken, nil
	}

	// Inject the TLS-configured HTTP client so the oauth2 library uses it for
	// the refresh request instead of http.DefaultClient.
	refreshCtx := context.WithValue(ctx, oauth2.HTTPClient, ts.httpClient)

	// Attempt refresh.
	src := ts.cfg.TokenSource(refreshCtx, ts.token)
	refreshed, err := src.Token()
	if err != nil {
		slog.ErrorContext(ctx, "tokenstore: refresh failed", "error", err)
		return "", fmt.Errorf("tokenstore: refresh: %w", err)
	}

	ts.token = refreshed
	if err := ts.save(); err != nil {
		// Non-fatal: we still have the token in memory for this session.
		slog.WarnContext(ctx, "tokenstore: failed to persist refreshed token", "error", err)
	}
	return ts.token.AccessToken, nil
}

// Save persists the given token to disk. Call this after a successful Login().
func (ts *TokenStore) Save(tok *oauth2.Token) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.token = tok
	return ts.save()
}

// Token returns the raw *oauth2.Token (may be nil if no login has occurred).
func (ts *TokenStore) Token() *oauth2.Token {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.token
}

// HTTPClient returns the TLS-configured *http.Client used for refresh requests.
// It is never nil (NewTokenStore always builds one).
func (ts *TokenStore) HTTPClient() *http.Client {
	return ts.httpClient
}

// load reads the token from disk without holding mu (callers must hold mu).
// It refuses to load the token if the file's group or world permission bits are
// set (mode & 0o077 != 0), because the file contains a long-lived refresh token.
// If the file exists but has loose permissions, load returns an error; the
// caller can re-login to create a fresh file at the correct mode.
func (ts *TokenStore) load() error {
	fi, err := os.Stat(ts.path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		slog.Warn("tokenstore: token file has loose permissions; refusing to load",
			"path", ts.path,
			"perm", fmt.Sprintf("%04o", perm),
		)
		return fmt.Errorf("tokenstore: %s has permission %04o; want 0600 — run 'ida login' to recreate it",
			ts.path, perm)
	}

	data, err := os.ReadFile(ts.path)
	if err != nil {
		return err
	}
	var tok oauth2.Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return fmt.Errorf("tokenstore: parse %s: %w", ts.path, err)
	}
	ts.token = &tok
	return nil
}

// save writes the current token to disk (callers must hold mu).
// It explicitly calls os.Chmod after writing so that pre-existing files with
// looser permissions are tightened to 0600 even if os.WriteFile preserved the
// old mode bits.
func (ts *TokenStore) save() error {
	if err := os.MkdirAll(filepath.Dir(ts.path), 0o700); err != nil {
		return fmt.Errorf("tokenstore: mkdir: %w", err)
	}
	data, err := json.Marshal(ts.token)
	if err != nil {
		return fmt.Errorf("tokenstore: marshal: %w", err)
	}
	if err := os.WriteFile(ts.path, data, tokenFileMode); err != nil {
		return fmt.Errorf("tokenstore: write: %w", err)
	}
	// Explicitly chmod to guarantee the mode even when the file pre-existed.
	if err := os.Chmod(ts.path, tokenFileMode); err != nil {
		return fmt.Errorf("tokenstore: chmod: %w", err)
	}
	return nil
}
