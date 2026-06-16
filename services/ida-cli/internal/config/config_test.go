package config

import (
	"os"
	"path/filepath"
	"testing"
)

// setHomeEnv redirects the HOME so that configPath() resolves inside t.TempDir().
// It returns a cleanup function. Call t.Cleanup(cleanup).
func setHomeEnv(t *testing.T, dir string) {
	t.Helper()
	orig, set := os.LookupEnv("HOME")
	t.Setenv("HOME", dir)
	if !set {
		t.Cleanup(func() { os.Unsetenv("HOME") })
	} else {
		t.Cleanup(func() { os.Setenv("HOME", orig) })
	}
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

func TestLoad_NoFile_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SandboxNamespace != defaultSandboxNS {
		t.Errorf("SandboxNamespace = %q; want %q", cfg.SandboxNamespace, defaultSandboxNS)
	}
}

func TestLoad_ValidFile_ParsesFields(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	cfgDir := filepath.Join(dir, defaultConfigDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `
launcher_url: http://launcher.example.com
jit_url: http://jit.example.com
gitea_url: http://gitea.example.com
gitea_token: giteatok123
keycloak_realm_url: http://kc.example.com/realms/test
keycloak_client_id: ida-cli
sandbox_namespace: myns
owner: alice
`
	if err := os.WriteFile(filepath.Join(cfgDir, defaultConfigFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LauncherURL != "http://launcher.example.com" {
		t.Errorf("LauncherURL = %q", cfg.LauncherURL)
	}
	if cfg.JitURL != "http://jit.example.com" {
		t.Errorf("JitURL = %q", cfg.JitURL)
	}
	if cfg.GiteaURL != "http://gitea.example.com" {
		t.Errorf("GiteaURL = %q", cfg.GiteaURL)
	}
	if cfg.GiteaToken != "giteatok123" {
		t.Errorf("GiteaToken = %q", cfg.GiteaToken)
	}
	if cfg.KeycloakRealmURL != "http://kc.example.com/realms/test" {
		t.Errorf("KeycloakRealmURL = %q", cfg.KeycloakRealmURL)
	}
	if cfg.KeycloakClientID != "ida-cli" {
		t.Errorf("KeycloakClientID = %q", cfg.KeycloakClientID)
	}
	if cfg.SandboxNamespace != "myns" {
		t.Errorf("SandboxNamespace = %q", cfg.SandboxNamespace)
	}
	if cfg.Owner != "alice" {
		t.Errorf("Owner = %q", cfg.Owner)
	}
}

func TestLoad_BadYAML_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	cfgDir := filepath.Join(dir, defaultConfigDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Invalid YAML — tab character where mapping value expected.
	bad := "launcher_url: [\x00bad yaml"
	if err := os.WriteFile(filepath.Join(cfgDir, defaultConfigFile), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for bad YAML, got nil")
	}
}

func TestLoad_EnvOverride_TakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	// Write a file with one value.
	cfgDir := filepath.Join(dir, defaultConfigDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "launcher_url: http://from-file.example.com\n"
	if err := os.WriteFile(filepath.Join(cfgDir, defaultConfigFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Override via env.
	t.Setenv("IDA_LAUNCHER_URL", "http://from-env.example.com")
	t.Setenv("IDA_OWNER", "bob")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LauncherURL != "http://from-env.example.com" {
		t.Errorf("LauncherURL = %q; want env value", cfg.LauncherURL)
	}
	if cfg.Owner != "bob" {
		t.Errorf("Owner = %q; want \"bob\"", cfg.Owner)
	}
}

func TestLoad_EmptyEnvVar_DoesNotOverride(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	cfgDir := filepath.Join(dir, defaultConfigDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "owner: charlie\n"
	if err := os.WriteFile(filepath.Join(cfgDir, defaultConfigFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set env var to empty string — should NOT override.
	t.Setenv("IDA_OWNER", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Owner != "charlie" {
		t.Errorf("Owner = %q; empty env should not override file value", cfg.Owner)
	}
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	orig := &Config{
		LauncherURL:      "http://launcher.local",
		JitURL:           "http://jit.local",
		GiteaURL:         "http://gitea.local",
		GiteaToken:       "tok",
		KeycloakRealmURL: "http://kc.local/realms/r",
		KeycloakClientID: "cli",
		SandboxNamespace: "ns1",
		Owner:            "dave",
	}

	if err := Save(orig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() after Save() error = %v", err)
	}
	if *loaded != *orig {
		t.Errorf("Round-trip mismatch:\n  got  %+v\n  want %+v", *loaded, *orig)
	}
}

func TestSave_FileMode0600(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	if err := Save(&Config{Owner: "test"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path := filepath.Join(dir, defaultConfigDir, defaultConfigFile)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o; want 0600", mode)
	}
}

func TestSave_CreatesMissingDirs(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)
	// Config dir does not exist yet.

	if err := Save(&Config{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path := filepath.Join(dir, defaultConfigDir, defaultConfigFile)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// overrideBool
// ---------------------------------------------------------------------------

func TestOverrideBool_TrueString_SetsTrue(t *testing.T) {
	for _, val := range []string{"true", "TRUE", "True", "1"} {
		t.Run(val, func(t *testing.T) {
			dst := false
			t.Setenv("IDA_TEST_BOOL", val)
			overrideBool(&dst, "IDA_TEST_BOOL")
			if !dst {
				t.Errorf("overrideBool(%q) did not set dst to true", val)
			}
		})
	}
}

func TestOverrideBool_FalseString_SetsFalse(t *testing.T) {
	for _, val := range []string{"false", "FALSE", "False", "0", "no"} {
		t.Run(val, func(t *testing.T) {
			dst := true // start true so we verify it flips
			t.Setenv("IDA_TEST_BOOL", val)
			overrideBool(&dst, "IDA_TEST_BOOL")
			if dst {
				t.Errorf("overrideBool(%q) did not set dst to false", val)
			}
		})
	}
}

func TestOverrideBool_EnvNotSet_DoesNotChange(t *testing.T) {
	os.Unsetenv("IDA_TEST_BOOL_NOTSET")
	dst := true // should remain unchanged
	overrideBool(&dst, "IDA_TEST_BOOL_NOTSET")
	if !dst {
		t.Error("overrideBool: unset env var should not change dst")
	}
}

func TestOverrideBool_EmptyString_DoesNotChange(t *testing.T) {
	t.Setenv("IDA_TEST_BOOL_EMPTY", "")
	dst := true // empty env var should not override
	overrideBool(&dst, "IDA_TEST_BOOL_EMPTY")
	if !dst {
		t.Error("overrideBool: empty env var should not change dst")
	}
}

// ---------------------------------------------------------------------------
// CAFile / InsecureSkipVerify env overrides
// ---------------------------------------------------------------------------

func TestLoad_CAFileEnvOverride(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	t.Setenv("IDA_CA_FILE", "/tmp/custom-ca.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.CAFile != "/tmp/custom-ca.pem" {
		t.Errorf("CAFile = %q; want /tmp/custom-ca.pem", cfg.CAFile)
	}
}

func TestLoad_InsecureSkipVerifyEnvTrue(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	t.Setenv("IDA_INSECURE_SKIP_VERIFY", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when IDA_INSECURE_SKIP_VERIFY=true")
	}
}

func TestLoad_InsecureSkipVerifyDefault_IsFalse(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)
	// Explicitly unset so we test the default.
	os.Unsetenv("IDA_INSECURE_SKIP_VERIFY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must default to false")
	}
}

func TestLoad_InsecureSkipVerifyEnv1(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	t.Setenv("IDA_INSECURE_SKIP_VERIFY", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when IDA_INSECURE_SKIP_VERIFY=1")
	}
}

func TestLoad_CAFileAndInsecureSkipVerify_YAMLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	setHomeEnv(t, dir)

	orig := &Config{
		LauncherURL:        "http://launcher.local",
		JitURL:             "http://jit.local",
		GiteaURL:           "http://gitea.local",
		GiteaToken:         "tok",
		KeycloakRealmURL:   "http://kc.local/realms/r",
		KeycloakClientID:   "cli",
		SandboxNamespace:   "ns1",
		Owner:              "dave",
		CAFile:             "/etc/ssl/custom-ca.pem",
		InsecureSkipVerify: true,
	}

	if err := Save(orig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() after Save() error = %v", err)
	}
	if *loaded != *orig {
		t.Errorf("Round-trip mismatch:\n  got  %+v\n  want %+v", *loaded, *orig)
	}
}
