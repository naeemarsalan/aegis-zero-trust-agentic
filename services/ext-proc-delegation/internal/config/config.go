package config

import (
	"fmt"
	"os"
	"strconv"
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
		KeycloakTokenURL:     getEnv("KEYCLOAK_TOKEN_URL", "https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token"),
		ExchangeMode:         ExchangeMode(getEnv("EXCHANGE_MODE", string(ModeStandard))),
		ExchangeClientID:     getEnv("EXCHANGE_CLIENT_ID", ""),
		ExchangeSecretFile:   getEnv("EXCHANGE_SECRET_FILE", ""),
		DownstreamAudience:   getEnv("DOWNSTREAM_AUDIENCE", "mcp-downstream"),
		KeycloakJWKSURL:      getEnv("KEYCLOAK_JWKS_URL", "https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/certs"),
		KeycloakIssuer:       getEnv("KEYCLOAK_ISSUER", "https://keycloak.apps.anaeem.na-launch.com/realms/agentic"),
		ExpectedAudience:     getEnv("EXPECTED_AUDIENCE", "mcp-gateway"),
		VaultAddr:            getEnv("VAULT_ADDR", "https://vault.apps.anaeem.na-launch.com"),
		VaultJWTRole:         getEnv("VAULT_JWT_ROLE", "ext-proc-delegation"),
		VaultJWTAudience:     getEnv("VAULT_JWT_AUDIENCE", "vault"),
		ToolSecretPathPrefix: getEnv("TOOL_SECRET_PATH_PREFIX", "secret/data/mcp-tools/"),
		FailMode:             getEnv("FAIL_MODE", "closed"),
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
