// Package config loads and saves the ida-cli configuration from
// ~/.config/ida/config.yaml with IDA_* environment variable overrides.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDir       = ".config/ida"
	defaultConfigFile      = "config.yaml"
	defaultSandboxNS       = "openshell"
	envPrefix              = "IDA_"
)

// Config holds all runtime configuration for the ida-cli.
type Config struct {
	LauncherURL        string `yaml:"launcher_url"`
	JitURL             string `yaml:"jit_url"`
	GiteaURL           string `yaml:"gitea_url"`
	GiteaToken         string `yaml:"gitea_token"`
	KeycloakRealmURL   string `yaml:"keycloak_realm_url"`
	KeycloakClientID   string `yaml:"keycloak_client_id"`
	SandboxNamespace   string `yaml:"sandbox_namespace"`
	Owner              string `yaml:"owner"`
	// CAFile is the path to a PEM CA bundle to add to the TLS trust roots for
	// all HTTP clients (jit-approver, sandbox-launcher, gitea). Leave empty to
	// use only the system cert pool.
	CAFile             string `yaml:"ca_file"`
	// InsecureSkipVerify disables TLS certificate verification for all HTTP
	// clients. MUST only be enabled for PoC/dev environments; never in
	// production. Defaults to false (full verification).
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// Kubeconfig is an explicit kubeconfig path for Sandbox CR / pod access
	// (agent list/status/attach/logs/rm and the TUI sidebar). Empty = default
	// kubeconfig discovery (KUBECONFIG / ~/.kube/config).
	Kubeconfig string `yaml:"kubeconfig"`

	// OpenShell CLI integration (ADR-0010).
	// OpenShellBin is the path to the openshell binary. Empty = "openshell" resolved via PATH.
	OpenShellBin string `yaml:"openshell_bin"`
	// OpenShellGatewayEndpoint is the --gateway-endpoint flag value passed to every openshell invocation.
	// When empty, openshell uses its own active gateway from ~/.config/openshell/.
	OpenShellGatewayEndpoint string `yaml:"openshell_gateway_endpoint"`
	// OpenShellGateway is the -g/--gateway (named gateway) flag value.
	OpenShellGateway string `yaml:"openshell_gateway"`
	// OpenShellGatewayInsecure passes --gateway-insecure to openshell. For PoC/dev only.
	OpenShellGatewayInsecure bool `yaml:"openshell_gateway_insecure"`
}

// configPath returns the default path to the config file.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, defaultConfigDir, defaultConfigFile), nil
}

// Load reads the config file from disk and applies IDA_* environment variable
// overrides. Missing keys are left at zero-value; callers must validate.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		SandboxNamespace: defaultSandboxNS,
	}

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	// Environment variable overrides (IDA_LAUNCHER_URL, etc.)
	applyEnvOverrides(cfg)

	return cfg, nil
}

// Save writes the config to disk at the default path with mode 0600.
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

// applyEnvOverrides maps IDA_<FIELD> env vars onto cfg fields.
func applyEnvOverrides(cfg *Config) {
	overrideString(&cfg.LauncherURL, "IDA_LAUNCHER_URL")
	overrideString(&cfg.JitURL, "IDA_JIT_URL")
	overrideString(&cfg.GiteaURL, "IDA_GITEA_URL")
	overrideString(&cfg.GiteaToken, "IDA_GITEA_TOKEN")
	overrideString(&cfg.KeycloakRealmURL, "IDA_KEYCLOAK_REALM_URL")
	overrideString(&cfg.KeycloakClientID, "IDA_KEYCLOAK_CLIENT_ID")
	overrideString(&cfg.SandboxNamespace, "IDA_SANDBOX_NAMESPACE")
	overrideString(&cfg.Owner, "IDA_OWNER")
	overrideString(&cfg.CAFile, "IDA_CA_FILE")
	overrideBool(&cfg.InsecureSkipVerify, "IDA_INSECURE_SKIP_VERIFY")
	overrideString(&cfg.Kubeconfig, "IDA_KUBECONFIG")
	overrideString(&cfg.OpenShellBin, "IDA_OPENSHELL_BIN")
	overrideString(&cfg.OpenShellGatewayEndpoint, "IDA_OPENSHELL_GATEWAY_ENDPOINT")
	overrideString(&cfg.OpenShellGateway, "IDA_OPENSHELL_GATEWAY")
	overrideBool(&cfg.OpenShellGatewayInsecure, "IDA_OPENSHELL_GATEWAY_INSECURE")
}

func overrideString(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		*dst = v
	}
}

// overrideBool sets *dst to true when the named environment variable is present
// and its value is "true" or "1" (case-insensitive). Any other non-empty value
// is treated as false — callers must opt in explicitly; there is no implicit
// default-true path.
func overrideBool(dst *bool, key string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1":
			*dst = true
		default:
			*dst = false
		}
	}
}
