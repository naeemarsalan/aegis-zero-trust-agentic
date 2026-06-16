package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/config"
)

// terminalJitStates is the set of JIT states that are considered final.
// A watch loop stops when the session reaches any of these states.
var terminalJitStates = map[string]bool{
	"approved": true,
	"issued":   true,
	"expired":  true,
	"denied":   true,
}

// jitCmd returns the 'ida jit' command group.
func jitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jit",
		Short: "Inspect JIT approval requests",
	}
	cmd.AddCommand(jitListCmd())
	cmd.AddCommand(jitShowCmd())
	cmd.AddCommand(jitWatchCmd())
	cmd.AddCommand(jitReceiptCmd())
	return cmd
}

func newJitClient() (*api.JitClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if cfg.JitURL == "" {
		return nil, fmt.Errorf("jit: jit_url is not set in config")
	}
	return api.NewJitClient(cfg.JitURL, cfg.CAFile, cfg.InsecureSkipVerify)
}

// jitListCmd implements 'ida jit list'.
func jitListCmd() *cobra.Command {
	var (
		sandbox string
		state   string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List JIT sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := newJitClient()
			if err != nil {
				return err
			}
			sessions, err := cli.List(cmd.Context(), sandbox, state)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(sessions)
			}

			fmt.Fprintln(w, "ID\tSTATE\tEXPIRES\tPR_URL")
			for _, s := range sessions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					s.ID, s.State, s.ExpiresAt.Format(time.RFC3339), s.PRURL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sandbox, "sandbox", "", "Filter by sandbox name")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state (pending|approved|issued|expired|denied)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

// jitShowCmd implements 'ida jit show <id>'.
func jitShowCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show detail for a JIT session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := newJitClient()
			if err != nil {
				return err
			}
			d, err := cli.Detail(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(d)
			}

			fmt.Fprintf(w, "ID:              %s\n", d.ID)
			fmt.Fprintf(w, "State:           %s\n", d.State)
			fmt.Fprintf(w, "Expires:         %s\n", d.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintf(w, "Requester:       %s\n", d.RequesterSub)
			fmt.Fprintf(w, "Namespace:       %s\n", d.Namespace)
			fmt.Fprintf(w, "Sandbox:         %s\n", d.Sandbox)
			fmt.Fprintf(w, "Duration:        %d min\n", d.DurationMinutes)
			fmt.Fprintf(w, "Justification:   %s\n", d.Justification)
			fmt.Fprintf(w, "Verbs:           %v\n", d.Verbs)
			fmt.Fprintf(w, "Resources:       %v\n", d.Resources)
			fmt.Fprintf(w, "PR URL:          %s\n", d.PRURL)
			for _, p := range d.PolicyDelta {
				fmt.Fprintf(w, "  Policy:        %s:%d\n", p.Host, p.Port)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

// jitWatchCmd implements 'ida jit watch <id>' — polls until state reaches a
// terminal value (approved, issued, expired, or denied).
func jitWatchCmd() *cobra.Command {
	var interval int
	cmd := &cobra.Command{
		Use:   "watch <id>",
		Short: "Poll a JIT session until its state reaches a terminal value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := newJitClient()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			id := args[0]
			fmt.Fprintf(w, "Watching JIT session %s (interval: %ds)...\n", id, interval)
			prev := ""
			for {
				status, err := cli.Status(cmd.Context(), id)
				if err != nil {
					return err
				}
				if status.State != prev {
					prev = status.State
					fmt.Fprintf(w, "[%s] state: %s  expires: %s\n",
						time.Now().Format(time.RFC3339), status.State,
						status.ExpiresAt.Format(time.RFC3339))
				}
				if terminalJitStates[status.State] {
					fmt.Fprintln(w, "Watch done.")
					return nil
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(time.Duration(interval) * time.Second):
				}
			}
		},
	}
	cmd.Flags().IntVar(&interval, "interval", 5, "Poll interval in seconds")
	return cmd
}

// jitReceiptCmd implements 'ida jit receipt <id>'.
func jitReceiptCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "receipt <id>",
		Short: "Show the outcome receipt for a JIT session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := newJitClient()
			if err != nil {
				return err
			}
			rc, err := cli.Receipt(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(rc)
			}

			fmt.Fprintf(w, "ID:           %s\n", rc.ID)
			fmt.Fprintf(w, "State:        %s\n", rc.State)
			fmt.Fprintf(w, "Outcome:      %s\n", rc.Outcome)
			fmt.Fprintf(w, "Expires:      %s\n", rc.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintf(w, "DeniedSource: %s\n", rc.DeniedSource)
			fmt.Fprintf(w, "Allowed:      %v\n", rc.Allowed)
			fmt.Fprintf(w, "Denied:       %v\n", rc.Denied)
			fmt.Fprintf(w, "Errors:       %v\n", rc.Errors)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}
