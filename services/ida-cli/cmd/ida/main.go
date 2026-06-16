// Command ida is the developer CLI for the nvidia-ida zero-trust agentic platform.
//
// With no arguments it launches the interactive TUI dashboard.
// Use 'ida --help' to see available subcommands.
package main

import (
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/cli"
)

func main() {
	cli.Execute()
}
