package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/auth"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
)

// agentCmd returns the 'ida agent' command group.
func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage agent sandboxes",
	}
	cmd.AddCommand(agentLaunchCmd())
	cmd.AddCommand(agentListCmd())
	cmd.AddCommand(agentStatusCmd())
	cmd.AddCommand(agentAttachCmd())
	cmd.AddCommand(agentLogsCmd())
	cmd.AddCommand(agentRmCmd())
	return cmd
}

// validScopes is the set of permitted scope values for agent launch.
var validScopes = map[string]bool{
	"read-only":  true,
	"read-write": true,
	"admin":      true,
}

// validModes is the set of permitted mode values for agent launch.
var validModes = map[string]bool{
	"task":    true,
	"project": true,
}

// validateLaunchInputs performs client-side validation of agent launch parameters
// before the request is sent to the backend. All constraint errors are returned
// as a single descriptive error so the caller sees every violation at once.
// entityRefFromBearer reads the preferred_username claim from a JWT access token
// (WITHOUT verifying it — the launcher does the real verification) and returns the
// Backstage entity ref "user:default/<preferred_username>". Returns "" if the token
// can't be parsed or the claim is absent, so the caller can fall back.
func entityRefFromBearer(bearer string) string {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.PreferredUsername == "" {
		return ""
	}
	return "user:default/" + claims.PreferredUsername
}

func validateLaunchInputs(goal string, capabilities []string, mode, scope string, ttl int) error {
	var errs []string

	goalLen := len(goal)
	if goalLen == 0 {
		errs = append(errs, "goal must not be empty")
	} else if goalLen > 500 {
		errs = append(errs, fmt.Sprintf("goal must be <=500 chars (got %d)", goalLen))
	}

	if len(capabilities) == 0 {
		errs = append(errs, "at least one capability is required (--cap)")
	} else if len(capabilities) > 20 {
		errs = append(errs, fmt.Sprintf("at most 20 capabilities allowed (got %d)", len(capabilities)))
	}

	if !validModes[mode] {
		errs = append(errs, fmt.Sprintf("mode must be one of {task, project} (got %q)", mode))
	}

	if !validScopes[scope] {
		errs = append(errs, fmt.Sprintf("scope must be one of {read-only, read-write, admin} (got %q)", scope))
	}

	if ttl < 5 || ttl > 480 {
		errs = append(errs, fmt.Sprintf("ttl must be in [5, 480] minutes (got %d)", ttl))
	}

	if len(errs) > 0 {
		return fmt.Errorf("agent launch: validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// agentLaunchCmd implements 'ida agent launch'.
func agentLaunchCmd() *cobra.Command {
	var (
		goal         string
		scope        string
		mode         string
		capabilities []string
		ttl          int
		jsonOut      bool
		yes          bool
	)

	cmd := &cobra.Command{
		Use:   "launch",
		Short: "Launch a new agent sandbox",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Client-side validation before any network call.
			if err := validateLaunchInputs(goal, capabilities, mode, scope, ttl); err != nil {
				return err
			}

			// Require explicit confirmation unless --yes / --confirm was supplied.
			if !yes {
				w := cmd.OutOrStdout()
				fmt.Fprintf(w, "Launch sandbox?\n")
				fmt.Fprintf(w, "  Goal:         %s\n", goal)
				fmt.Fprintf(w, "  Capabilities: %s\n", strings.Join(capabilities, ", "))
				fmt.Fprintf(w, "  Mode:         %s\n", mode)
				fmt.Fprintf(w, "  Scope:        %s\n", scope)
				fmt.Fprintf(w, "  TTL:          %d min\n", ttl)
				fmt.Fprintf(w, "Confirm? [y/N] ")
				var answer string
				fmt.Fscan(os.Stdin, &answer)
				if !strings.EqualFold(answer, "y") {
					fmt.Fprintln(w, "Aborted.")
					return nil
				}
			}

			cfg, bearer, err := loadCfgAndBearer(cmd.Context())
			if err != nil {
				return err
			}

			// The launcher derives the caller identity from the token
			// (Keycloak preferred_username -> user:default/<name>) and cross-checks
			// it against body.userRef. Derive userRef from the SAME claim so they
			// always match; fall back to cfg.Owner only if the token can't be read.
			userRef := entityRefFromBearer(bearer)
			if userRef == "" {
				userRef = cfg.Owner
			}

			req := api.LaunchRequest{
				Goal:         goal,
				Capabilities: capabilities,
				Mode:         mode,
				Scope:        scope,
				UserRef:      userRef,
				Confirmed:    true,
				TTLMinutes:   ttl,
			}

			launcher, err := api.NewLauncherClient(cfg.LauncherURL, cfg.CAFile, cfg.InsecureSkipVerify)
			if err != nil {
				return fmt.Errorf("agent launch: %w", err)
			}
			resp, err := launcher.Launch(cmd.Context(), req, bearer)
			if err != nil {
				return fmt.Errorf("agent launch: %w", err)
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(resp)
			}

			fmt.Fprintf(w, "Launched sandbox: %s\n", resp.SandboxName)
			fmt.Fprintf(w, "  ID:        %s\n", resp.SandboxID)
			fmt.Fprintf(w, "  Namespace: %s\n", resp.Namespace)
			fmt.Fprintf(w, "  Phase:     %s\n", resp.Phase)
			if resp.ConversationURL != "" {
				fmt.Fprintf(w, "  Chat URL:  %s\n", resp.ConversationURL)
			}
			if resp.AccessHint != "" {
				fmt.Fprintf(w, "  Hint:      %s\n", resp.AccessHint)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&goal, "goal", "", "Goal description (required, 1-500 chars)")
	cmd.Flags().StringVar(&scope, "scope", "read-only", "Access scope: read-only|read-write|admin")
	cmd.Flags().StringVar(&mode, "mode", "task", "Session mode: task|project")
	cmd.Flags().StringSliceVar(&capabilities, "cap", []string{"echo"}, "MCP capabilities (repeatable)")
	cmd.Flags().IntVar(&ttl, "ttl", 60, "TTL in minutes (5-480)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip interactive confirmation prompt")
	_ = cmd.MarkFlagRequired("goal")
	return cmd
}

// agentListCmd implements 'ida agent list'.
func agentListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List agent sandboxes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, oshCli, err := loadCfgAndOpenShell()
			if err != nil {
				return err
			}
			sandboxes, err := oshCli.List(cmd.Context(), cfg.Owner)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(sandboxes)
			}

			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tPHASE\tSCOPE\tTTL\tOWNER")
			for _, sb := range sandboxes {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					sb.Name, sb.Phase, sb.Scope, sb.TTLMinutes, sb.Owner)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

// agentStatusCmd implements 'ida agent status <name>'.
func agentStatusCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status <name>",
		Short: "Show status of a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, oshCli, err := loadCfgAndOpenShell()
			if err != nil {
				return err
			}
			sb, err := oshCli.Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(sb)
			}

			fmt.Fprintf(w, "Name:       %s\n", sb.Name)
			fmt.Fprintf(w, "Namespace:  %s\n", sb.Namespace)
			fmt.Fprintf(w, "Phase:      %s\n", sb.Phase)
			fmt.Fprintf(w, "Scope:      %s\n", sb.Scope)
			fmt.Fprintf(w, "TTL:        %s min\n", sb.TTLMinutes)
			fmt.Fprintf(w, "Owner:      %s\n", sb.Owner)
			if sb.Selector != "" {
				fmt.Fprintf(w, "Selector:   %s\n", sb.Selector)
			}
			if sb.AccessHint != "" {
				fmt.Fprintf(w, "Hint:       %s\n", sb.AccessHint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

// agentAttachCmd implements 'ida agent attach <name>'.
// The CLI owns a real TTY so we exec openshell directly with inherited stdio
// (no vt10x emulation needed; that is the TUI's job).
func agentAttachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attach <name>",
		Short: "Attach an interactive shell to the agent container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, oshCli, err := loadCfgAndOpenShell()
			if err != nil {
				return err
			}
			// The gateway authorises the connect RPC per-user; no client-side
			// ownership check is needed (gateway provides the security boundary).
			return oshCli.ConnectInteractiveTTY(cmd.Context(), args[0])
		},
	}
}

// agentLogsCmd implements 'ida agent logs <name>'.
func agentLogsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Stream logs from the agent container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, oshCli, err := loadCfgAndOpenShell()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if follow {
				return oshCli.StreamLogs(cmd.Context(), args[0], out)
			}
			data, err := oshCli.Logs(cmd.Context(), args[0], 200, "")
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, strings.NewReader(string(data)))
			return copyErr
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	return cmd
}

// agentRmCmd implements 'ida agent rm <name>'.
func agentRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, oshCli, err := loadCfgAndOpenShell()
			if err != nil {
				return err
			}
			if !force {
				fmt.Fprintf(cmd.OutOrStdout(), "Delete sandbox %q? [y/N] ", args[0])
				var answer string
				fmt.Fscan(os.Stdin, &answer)
				if !strings.EqualFold(answer, "y") {
					fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
					return nil
				}
			}
			if err := oshCli.Delete(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %q deleted.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
	return cmd
}

// loadCfgAndBearer is a shared helper that loads config and returns a valid bearer token.
func loadCfgAndBearer(ctx context.Context) (*config.Config, string, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, "", fmt.Errorf("config: %w", err)
	}
	store, err := auth.NewTokenStore(cfg.KeycloakRealmURL, cfg.KeycloakClientID, cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return nil, "", fmt.Errorf("token store: %w", err)
	}
	bearer, err := store.AccessToken(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("no valid token — run 'ida login' first: %w", err)
	}
	return cfg, bearer, nil
}

// loadCfgAndOpenShell loads the config and constructs an openshell.Client.
// It is the parallel of loadCfgAndBearer for the sandbox lifecycle sub-commands.
func loadCfgAndOpenShell() (*config.Config, *openshell.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	gw := openshell.GatewayConfig{
		Endpoint: cfg.OpenShellGatewayEndpoint,
		Name:     cfg.OpenShellGateway,
		Insecure: cfg.OpenShellGatewayInsecure,
	}
	oshCli := openshell.New(cfg.OpenShellBin, gw, cfg.SandboxNamespace, openshell.NewExecRunner())
	return cfg, oshCli, nil
}
