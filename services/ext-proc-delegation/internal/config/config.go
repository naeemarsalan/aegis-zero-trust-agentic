package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ExchangeMode controls RFC8693 vs legacy token-exchange semantics.
type ExchangeMode string

const (
	ModeStandard ExchangeMode = "standard"
	ModeLegacy   ExchangeMode = "legacy"
)

// Config holds all runtime configuration for ext-proc-delegation.
type Config struct {
	// Keycloak / token exchange
	KeycloakTokenURL   string
	ExchangeMode       ExchangeMode
	ExchangeClientID   string
	ExchangeSecretFile string // path; value read at runtime, never logged
	DownstreamAudience string

	// Inbound JWT verification (defense in depth — ext-proc independently
	// verifies the caller token, it does NOT trust the gateway).
	KeycloakJWKSURL  string // Keycloak realm JWKS endpoint
	KeycloakIssuer   string // expected "iss" claim
	ExpectedAudience string // audience that the inbound caller token must contain

	// Vault
	VaultAddr          string
	VaultJWTRole       string
	VaultJWTAudience   string
	ToolSecretPathPrefix string

	// Downstream credential injection. Requests whose :path begins with one of
	// StaticAuthPaths get the caller's PRE-PROVISIONED static token injected
	// (read from the StaticTokenSecret KV by preferred_username) instead of the
	// RFC 8693 exchanged JWT — for off-the-shelf MCP servers (e.g. pfsense-mcp)
	// that validate a static bearer list, not JWTs. The exchange still runs for
	// audit. JWT-aware downstreams (echo-mcp on /echo) get the exchanged token.
	StaticAuthPaths        []string
	StaticTokenSecret      string // KV tool name holding per-user read tokens (default "mcp-tokens")
	// StaticTokenSecretWrite is the KV tool name holding per-user WRITE-capable
	// pfSense tokens. It is fetched ONLY when the request is JIT-elevated (a valid,
	// sandbox-bound, tool-scoped jit-approver capability JWT is present). If the
	// request is JIT-elevated but the write token cannot be fetched or is absent for
	// the user, the call is DENIED fail-closed — never silently falls back to the
	// read token (an approved write must never go out under the read identity).
	// Env: STATIC_TOKEN_SECRET_WRITE. Default: "mcp-tokens-write".
	StaticTokenSecretWrite string

	// Tool-level RBAC (enforces the kyverno authz policies in ext-proc).
	ReadOnlyToolPrefixes  []string
	DangerousToolPrefixes []string
	RestrictedGroup       string
	AdminGroup            string
	UserGroup             string

	// jit-approver session JWT (gates dangerous tools — UC2). Empty JITJWKSURL
	// disables the JIT gate (dangerous tools then require admin only).
	JITJWKSURL  string
	JITIssuer   string
	JITAudience string

	// SPIRE OIDC JWT-SVID verification (sandbox agent path — Option D).
	// SpireJWKSURL is the SPIRE OIDC discovery provider JWKS endpoint.
	// When non-empty, ext-proc recognises inbound tokens whose iss matches
	// SpireIssuer and routes them through the grant-read + RFC8693
	// impersonation path instead of the legacy Keycloak user-token path.
	SpireJWKSURL  string // e.g. https://spire-oidc.apps.ocp-dev.na-launch.com/keys
	SpireIssuer   string // must match spire-oidc jwtIssuer config field
	SpireAudience string // must be "mcp-gateway"
	// SpireTLSInsecure skips TLS verification when fetching the SPIRE OIDC JWKS.
	// This is an explicit, default-off escape hatch for environments where the
	// SPIRE OIDC route cert cannot be verified (e.g. local PoC without a CA
	// bundle). Set SPIRE_TLS_INSECURE=true only when strictly necessary.
	// In production, set SPIRE_CA_FILE instead to pin the trust anchor.
	SpireTLSInsecure bool

	// SpireCAFile is the path to a PEM-encoded CA certificate file used to
	// verify the SPIRE OIDC JWKS endpoint TLS certificate. When set, the JWKS
	// HTTP client uses this CA as the sole trust anchor instead of the in-pod
	// SPIFFE bundle. Mutually exclusive with SpireTLSInsecure (insecure wins if
	// both are set). Set via env SPIRE_CA_FILE.
	SpireCAFile string

	// SandboxGrantPathPrefix is the Vault KV-v2 path prefix for consent grants
	// written by sandbox-launcher.
	// Default: "secret/data/sandbox-grants/".
	// Full path = SandboxGrantPathPrefix + <sandbox-uid>
	SandboxGrantPathPrefix string

	// Safety invariant — only valid value is "closed".
	FailMode string

	// Body size limit in bytes.
	MaxBodyBytes int64

	// gRPC listen address.
	GRPCAddr string

	// Prometheus metrics address.
	MetricsAddr string
}

// Load reads config from environment variables, returning an error if required
// values are missing or invalid.
func Load() (*Config, error) {
	c := &Config{
		KeycloakTokenURL:     getEnv("KEYCLOAK_TOKEN_URL", "https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic/protocol/openid-connect/token"),
		ExchangeMode:         ExchangeMode(getEnv("EXCHANGE_MODE", string(ModeStandard))),
		ExchangeClientID:     getEnv("EXCHANGE_CLIENT_ID", ""),
		ExchangeSecretFile:   getEnv("EXCHANGE_SECRET_FILE", ""),
		DownstreamAudience:   getEnv("DOWNSTREAM_AUDIENCE", "mcp-downstream"),
		KeycloakJWKSURL:      getEnv("KEYCLOAK_JWKS_URL", "https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic/protocol/openid-connect/certs"),
		KeycloakIssuer:       getEnv("KEYCLOAK_ISSUER", "https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic"),
		ExpectedAudience:     getEnv("EXPECTED_AUDIENCE", "mcp-gateway"),
		VaultAddr:            getEnv("VAULT_ADDR", "https://vault.apps.ocp-dev.na-launch.com"),
		VaultJWTRole:         getEnv("VAULT_JWT_ROLE", "ext-proc-delegation"),
		VaultJWTAudience:     getEnv("VAULT_JWT_AUDIENCE", "vault"),
		ToolSecretPathPrefix: getEnv("TOOL_SECRET_PATH_PREFIX", "secret/data/mcp-tools/"),
		StaticAuthPaths:        splitNonEmpty(getEnv("STATIC_AUTH_PATHS", "/mcp")),
		StaticTokenSecret:      getEnv("STATIC_TOKEN_SECRET", "mcp-tokens"),
		StaticTokenSecretWrite: getEnv("STATIC_TOKEN_SECRET_WRITE", "mcp-tokens-write"),
		ReadOnlyToolPrefixes:  splitNonEmpty(getEnv("READONLY_TOOL_PREFIXES", "get_,search_,list_,find_,diagnose_,show_,export_,follow_,check_,test_")),
		DangerousToolPrefixes: splitNonEmpty(getEnv("DANGEROUS_TOOL_PREFIXES", "add_,set_,delete_,update_,create_,remove_,apply_,reload_,manage_,issue_,renew_,restore_,halt_,reboot_,disconnect_,send_,bulk_,move_,register_,control_,generate_,update_")),
		RestrictedGroup:       getEnv("RESTRICTED_GROUP", "restricted"),
		AdminGroup:            getEnv("ADMIN_GROUP", "mcp-admins"),
		UserGroup:             getEnv("USER_GROUP", "mcp-users"),
		JITJWKSURL:             getEnv("JIT_JWKS_URL", "http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks"),
		JITIssuer:              getEnv("JIT_ISSUER", "https://jit-approver.mcp-gateway.svc.cluster.local:8080"),
		JITAudience:            getEnv("JIT_AUDIENCE", "kyverno-authz"),
		SpireJWKSURL:           getEnv("SPIRE_JWKS_URL", ""),
		SpireIssuer:            getEnv("SPIRE_ISSUER", "https://spire-oidc.apps.ocp-dev.na-launch.com"),
		SpireAudience:          getEnv("SPIRE_AUDIENCE", "mcp-gateway"),
		SpireTLSInsecure:       getEnv("SPIRE_TLS_INSECURE", "") == "true",
		SpireCAFile:            getEnv("SPIRE_CA_FILE", ""),
		SandboxGrantPathPrefix: getEnv("SANDBOX_GRANT_PATH_PREFIX", "secret/data/sandbox-grants/"),
		FailMode:               getEnv("FAIL_MODE", "closed"),
		GRPCAddr:             getEnv("GRPC_ADDR", ":9000"),
		MetricsAddr:          getEnv("METRICS_ADDR", ":9090"),
	}

	if maxBytes := os.Getenv("MAX_BODY_BYTES"); maxBytes != "" {
		n, err := strconv.ParseInt(maxBytes, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MAX_BODY_BYTES: %w", err)
		}
		c.MaxBodyBytes = n
	} else {
		c.MaxBodyBytes = 262144
	}

	// Validate exchange mode.
	switch c.ExchangeMode {
	case ModeStandard, ModeLegacy:
		// ok
	default:
		return nil, fmt.Errorf("invalid EXCHANGE_MODE %q: must be standard or legacy", c.ExchangeMode)
	}

	// FAIL_MODE invariant.
	if c.FailMode != "closed" {
		return nil, fmt.Errorf("FAIL_MODE must be 'closed', got %q", c.FailMode)
	}

	// Inbound verification config is mandatory — without it ext-proc cannot
	// independently verify caller identity and must not start (fail closed).
	if c.KeycloakJWKSURL == "" {
		return nil, fmt.Errorf("KEYCLOAK_JWKS_URL is required")
	}
	if c.KeycloakIssuer == "" {
		return nil, fmt.Errorf("KEYCLOAK_ISSUER is required")
	}
	if c.ExpectedAudience == "" {
		return nil, fmt.Errorf("EXPECTED_AUDIENCE is required")
	}

	return c, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func splitNonEmpty(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsStaticAuthPath reports whether reqPath should use per-user static-token
// injection (matched by prefix against StaticAuthPaths).
func (c *Config) IsStaticAuthPath(reqPath string) bool {
	for _, p := range c.StaticAuthPaths {
		if strings.HasPrefix(reqPath, p) {
			return true
		}
	}
	return false
}
