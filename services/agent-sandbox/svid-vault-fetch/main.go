// Command svid-vault-fetch is the zero-trust secret-bootstrap for the sandboxed
// agent (Phase 5 capstone). It runs as an init container in the Kata micro-VM.
//
// It proves the design invariant: the agent is NEVER handed a credential. Instead
// it presents its own cryptographic identity — a SPIRE JWT-SVID minted for
// audience "vault" — to Vault's JWT auth, receives a short-lived Vault token
// scoped by the openshell-agent policy, reads ONLY secret/agent-sandbox/inference,
// and writes the inference credential to a tmpfs file for the agent process. The
// Vault token lives in memory here and is never persisted; the pod has no
// Kubernetes ServiceAccount token (automountServiceAccountToken: false).
//
// Fail-closed: any error (no SVID, login rejected, secret missing) exits non-zero
// so the agent container never starts without its credential.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// insecureTLS skips Vault cert verification. The Vault route is served by the
// router's wildcard cert, which is not in the agent image trust store; the SVID
// login itself is the security boundary, not the channel cert. Matches the
// VAULT_SKIP_VERIFY pattern used elsewhere in the platform PoC.
func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	if err := run(); err != nil {
		slog.Error("svid-vault-fetch failed (fail-closed)", "err", err)
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run() error {
	var (
		socket    = getenv("SPIFFE_ENDPOINT_SOCKET", "unix:///spiffe-workload-api/spire-agent.sock")
		vaultAddr = strings.TrimRight(getenv("VAULT_ADDR", "https://vault.apps.anaeem.na-launch.com"), "/")
		vaultRole = getenv("VAULT_JWT_ROLE", "openshell-agent")
		audience  = getenv("VAULT_JWT_AUDIENCE", "vault")
		secretAPI = getenv("VAULT_SECRET_PATH", "secret/data/agent-sandbox/inference")
		outDir    = getenv("OUTPUT_DIR", "/vault/secrets")
		skipTLS   = getenv("VAULT_SKIP_VERIFY", "true") == "true"
		// Daemon mode: when WRITE_SVID_PATH is set, run as a sidecar that keeps a
		// fresh JWT-SVID (audience=vault) written to that file for another process
		// in the pod to present to Vault (jit-approver's mint path reads it from
		// SVID_JWT_PATH). No Vault calls in this mode — it only mints identity.
		writeSVIDPath = os.Getenv("WRITE_SVID_PATH")
	)

	if writeSVIDPath != "" {
		return runSVIDWriter(socket, audience, writeSVIDPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Fetch our JWT-SVID (audience=vault) from the SPIRE workload API. The pod
	//    is selected by the agent-sandbox-workloads ClusterSPIFFEID, so SPIRE
	//    issues spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/openshell-agent.
	slog.Info("fetching JWT-SVID", "socket", socket, "audience", audience)
	jwtSrc, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return fmt.Errorf("workload API: %w", err)
	}
	defer jwtSrc.Close()

	svid, err := jwtSrc.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return fmt.Errorf("fetch JWT-SVID: %w", err)
	}
	slog.Info("got JWT-SVID", "spiffe_id", svid.ID.String())

	// 2. Exchange the SVID for a Vault token via auth/jwt. Vault verifies the SVID
	//    against the SPIRE OIDC issuer and checks bound_subject + bound_audiences.
	client := &http.Client{Timeout: 10 * time.Second}
	if skipTLS {
		client.Transport = &http.Transport{TLSClientConfig: insecureTLS()}
	}
	token, err := vaultLogin(ctx, client, vaultAddr, vaultRole, svid.Marshal())
	if err != nil {
		return fmt.Errorf("vault jwt login: %w", err)
	}
	slog.Info("vault login ok (token held in memory only, never written)")

	// 3. Read the inference credential with that token.
	data, err := vaultReadKV(ctx, client, vaultAddr, secretAPI, token)
	if err != nil {
		return fmt.Errorf("read %s: %w", secretAPI, err)
	}

	// 4. Write the credential fields to tmpfs for the agent process. The Vault
	//    token itself is intentionally NOT written to disk.
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	written := 0
	for field, raw := range data {
		v, ok := raw.(string)
		if !ok {
			continue
		}
		path := outDir + "/inference." + field
		if err := os.WriteFile(path, []byte(v), 0o400); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		written++
	}
	if written == 0 {
		return fmt.Errorf("secret %s had no string fields to materialize", secretAPI)
	}
	slog.Info("inference credential materialized to tmpfs", "dir", outDir, "fields", written)
	return nil
}

// runSVIDWriter runs as a long-lived sidecar: it keeps a current JWT-SVID
// (audience=vault) written atomically to path, refreshing before each SVID
// expires. The consumer (e.g. jit-approver vault.py) reads it from SVID_JWT_PATH
// and presents it to Vault auth/jwt. This is how a non-SPIFFE-aware service still
// authenticates to Vault by identity rather than a long-lived token.
func runSVIDWriter(socket, audience, path string) error {
	ctx := context.Background()
	src, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return fmt.Errorf("workload API: %w", err)
	}
	defer src.Close()
	slog.Info("svid-writer started", "path", path, "audience", audience)
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		svid, err := src.FetchJWTSVID(fetchCtx, jwtsvid.Params{Audience: audience})
		cancel()
		if err != nil {
			slog.Error("fetch JWT-SVID", "err", err)
			time.Sleep(5 * time.Second)
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(svid.Marshal()), 0o400); err != nil {
			return fmt.Errorf("write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("rename %s: %w", path, err)
		}
		// Refresh at half the remaining lifetime (min 30s, cap 5m).
		sleep := 5 * time.Minute
		if exp := svid.Expiry; !exp.IsZero() {
			if half := time.Until(exp) / 2; half > 0 && half < sleep {
				sleep = half
			}
		}
		if sleep < 30*time.Second {
			sleep = 30 * time.Second
		}
		slog.Info("svid written", "spiffe_id", svid.ID.String(), "next_refresh_s", int(sleep.Seconds()))
		time.Sleep(sleep)
	}
}

func vaultLogin(ctx context.Context, c *http.Client, addr, role, jwt string) (string, error) {
	body, _ := json.Marshal(map[string]string{"role": role, "jwt": jwt})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, addr+"/v1/auth/jwt/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("login returned empty token")
	}
	return out.Auth.ClientToken, nil
}

func vaultReadKV(ctx context.Context, c *http.Client, addr, path, token string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/v1/"+path, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Data.Data, nil
}
