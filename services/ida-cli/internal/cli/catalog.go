package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/api"
)

// catalogCmd returns the 'ida catalog' command group.
func catalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Browse the MCP server catalog",
	}
	cmd.AddCommand(catalogListCmd())
	return cmd
}

// catalogListCmd implements 'ida catalog list'.
func catalogListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available MCP servers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat := api.NewCatalog()
			servers := cat.List()

			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(servers)
			}

			for _, s := range servers {
				fmt.Fprintf(w, "%-20s  %s\n", s.Name, s.Description)
				fmt.Fprintf(w, "  Address:  %s  (%s)\n", s.Address, s.Protocol)
				if len(s.Capabilities) > 0 {
					fmt.Fprintf(w, "  Caps:     %s\n", strings.Join(s.Capabilities, ", "))
				}
				fmt.Fprintln(w)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}
