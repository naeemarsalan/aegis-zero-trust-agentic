package openshell

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// Connect launches `openshell sandbox connect <name>` under a PTY and wires
// stdin/stdout/resize into the caller-supplied streams. It is the openshell
// analogue of kube.ExecSession.
//
// This function is designed for embedded use inside the TUI ShellTab: it does
// NOT touch os.Stdin and does NOT call term.MakeRaw. The ShellTab owns the
// real terminal and is responsible for raw-mode management.
//
// resize carries {cols, rows} pairs. A nil resize channel is safe: the resize
// goroutine simply never runs.
//
// Returns when the child process exits or ctx is cancelled. A cancellation
// returns ctx.Err() so the ShellTab isContextCanceled check treats it as a
// clean stop rather than an error.
func (c *Client) Connect(ctx context.Context, name string,
	stdin io.Reader, stdout io.Writer, resize <-chan [2]uint16) error {
	if name == "" {
		return fmt.Errorf("openshell: Connect: name must not be empty")
	}
	args := append(c.gatewayArgs(), "sandbox", "connect", name)
	cmd := exec.CommandContext(ctx, c.bin, args...)

	// pty.Start creates a PTY pair, forks the child attached to the slave end,
	// and returns the master end as an *os.File.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("openshell: pty start: %w", err)
	}
	defer func() { _ = ptmx.Close() }() // closing master signals EOF to child

	// resize → pty.Setsize: maps {cols, rows} events to TIOCSWINSZ on the PTY.
	if resize != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case sz, ok := <-resize:
					if !ok {
						return
					}
					// sz = {cols, rows} — matching the ShellTab contract.
					_ = pty.Setsize(ptmx, &pty.Winsize{
						Cols: sz[0],
						Rows: sz[1],
					})
				}
			}
		}()
	}

	// stdin → ptmx: keystrokes from HandleKey reach the remote shell.
	go func() { _, _ = io.Copy(ptmx, stdin) }()

	// ptmx → vtWriter (stdout): PTY output drives the vt10x redraw loop.
	// This is the blocking read loop; it exits when the child closes the PTY.
	_, copyErr := io.Copy(stdout, ptmx)

	// Wait for the child to finish so we get a proper exit code.
	waitErr := cmd.Wait()

	// A context cancellation is a clean stop, not a real error.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		return waitErr
	}
	return copyErr
}

// ConnectInteractiveTTY runs `openshell sandbox connect <name>` with the
// process's own os.Stdin/Stdout/Stderr, inheriting the calling terminal
// directly. This is the non-embedded CLI path (`ida agent attach`) where the
// caller owns a real TTY and no vt10x emulation is needed.
func (c *Client) ConnectInteractiveTTY(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("openshell: ConnectInteractiveTTY: name must not be empty")
	}
	args := append(c.gatewayArgs(), "sandbox", "connect", name)
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
