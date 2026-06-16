package openshell

import (
	"context"
	"fmt"
	"io"
)

// StreamLogs runs `openshell logs <name> --tail` and copies stdout to w until
// ctx is cancelled or the child exits. It is the streaming variant used by the
// CLI `agent logs --follow` and the TUI Logs tab.
func (c *Client) StreamLogs(ctx context.Context, name string, w io.Writer) error {
	if name == "" {
		return fmt.Errorf("openshell: StreamLogs: name must not be empty")
	}
	args := append(c.gatewayArgs(), "logs", name, "--tail")
	return c.runner.RunStream(ctx, c.bin, w, args...)
}

// Logs runs `openshell logs <name> -n <tail>` (no follow) and returns the
// captured bytes. When since is non-empty it is passed as `--since <since>`.
func (c *Client) Logs(ctx context.Context, name string, tail int, since string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("openshell: Logs: name must not be empty")
	}
	args := append(c.gatewayArgs(), "logs", name, "-n", fmt.Sprintf("%d", tail))
	if since != "" {
		args = append(args, "--since", since)
	}
	out, err := c.runner.Run(ctx, c.bin, args...)
	if err != nil {
		return nil, fmt.Errorf("openshell: logs %q: %w", name, err)
	}
	return out, nil
}
