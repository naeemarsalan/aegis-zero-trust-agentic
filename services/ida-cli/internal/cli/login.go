package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/term"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/auth"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
)

// loginCmd returns the 'ida login' cobra command.
//
// Default (no --user flag): OAuth2 device-code flow — opens a browser URL.
// With --user <name>:        ROPC (password) grant — reads the password from
//
//	the terminal without echoing (if stdin is a TTY) or
//	from the IDA_PASSWORD environment variable (non-TTY /
//	CI). This flow is browserless and suitable for scripts.
func loginCmd() *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Keycloak (device-code flow by default; --user for ROPC)",
		Long: `Authenticate with Keycloak and save the resulting token to
~/.config/ida/token.json (mode 0600).

Default — OAuth2 device-code flow:
  ida login
  Open the printed URL in a browser to complete authentication.

Browserless — Resource Owner Password Credentials (ROPC) grant:
  ida login --user alice
  The password is read from the terminal without echoing (TTY) or from the
  IDA_PASSWORD environment variable (non-TTY / CI).

The IDA_PASSWORD environment variable is NEVER logged or stored.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd, username)
		},
	}

	cmd.Flags().StringVarP(&username, "user", "u", "", "Username for ROPC (password) grant; omit to use device-code flow")

	return cmd
}

// runLogin dispatches to either the device-code or the ROPC path depending
// on whether --user was supplied.
func runLogin(cmd *cobra.Command, username string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("login: load config: %w", err)
	}
	if cfg.KeycloakRealmURL == "" {
		return fmt.Errorf("login: keycloak_realm_url is not set in config")
	}
	if cfg.KeycloakClientID == "" {
		return fmt.Errorf("login: keycloak_client_id is not set in config")
	}

	if username != "" {
		return runPasswordLogin(cmd, cfg, username)
	}
	return runDeviceLogin(cmd, cfg)
}

// runDeviceLogin performs the existing device-code flow (default).
func runDeviceLogin(cmd *cobra.Command, cfg *config.Config) error {
	dcCfg := auth.DeviceFlowConfig{
		RealmURL: cfg.KeycloakRealmURL,
		ClientID: cfg.KeycloakClientID,
		CAFile:   cfg.CAFile,
		Insecure: cfg.InsecureSkipVerify,
	}

	tok, err := auth.Login(cmd.Context(), dcCfg)
	if err != nil {
		return fmt.Errorf("login: device flow: %w", err)
	}

	store, err := auth.NewTokenStore(cfg.KeycloakRealmURL, cfg.KeycloakClientID, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("login: token store: %w", err)
	}
	if err := store.Save(tok); err != nil {
		return fmt.Errorf("login: save token: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Login successful. Token saved to ~/.config/ida/token.json")
	return nil
}

// runPasswordLogin performs the ROPC grant. The password is obtained from the
// terminal (without echoing) when stdin is a TTY, or from IDA_PASSWORD
// otherwise. The password is NEVER logged or stored.
func runPasswordLogin(cmd *cobra.Command, cfg *config.Config, username string) error {
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("login: read password: %w", err)
	}

	pgCfg := auth.PasswordGrantConfig{
		RealmURL: cfg.KeycloakRealmURL,
		ClientID: cfg.KeycloakClientID,
		// ClientSecret is intentionally left empty for public clients.
		// If a confidential client secret is needed, it can be added here
		// via a future --client-secret flag or a dedicated env var.
		CAFile:   cfg.CAFile,
		Insecure: cfg.InsecureSkipVerify,
	}

	result, err := auth.PasswordLogin(cmd.Context(), pgCfg, username, password)
	if err != nil {
		return fmt.Errorf("login: password grant: %w", err)
	}

	// Convert TokenResult → *oauth2.Token for the existing store.
	tok := &oauth2.Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		Expiry:       result.Expiry,
		TokenType:    result.TokenType,
	}
	// Ensure zero Expiry is not treated as "already expired".
	if tok.Expiry.IsZero() {
		tok.Expiry = time.Now().Add(5 * time.Minute)
	}

	store, err := auth.NewTokenStore(cfg.KeycloakRealmURL, cfg.KeycloakClientID, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("login: token store: %w", err)
	}
	if err := store.Save(tok); err != nil {
		return fmt.Errorf("login: save token: %w", err)
	}

	// Print only a success message — never print the token.
	fmt.Fprintln(cmd.OutOrStdout(), "Login successful. Token saved to ~/.config/ida/token.json")
	return nil
}

// readPassword returns the user's password from the terminal (no echo) when
// stdin is a TTY, or from the IDA_PASSWORD environment variable otherwise.
// It returns an error if neither source yields a non-empty value.
func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // newline after the hidden input
		if err != nil {
			return "", fmt.Errorf("reading password from terminal: %w", err)
		}
		if len(raw) == 0 {
			return "", fmt.Errorf("password must not be empty")
		}
		return string(raw), nil
	}

	// Non-TTY path: read from environment variable.
	pw := os.Getenv("IDA_PASSWORD")
	if pw == "" {
		return "", fmt.Errorf("IDA_PASSWORD is not set and stdin is not a TTY; cannot read password")
	}
	return pw, nil
}
