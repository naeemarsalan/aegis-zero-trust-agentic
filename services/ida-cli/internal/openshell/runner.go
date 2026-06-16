// Package openshell provides a thin wrapper around the openshell CLI for
// sandbox lifecycle management (ADR-0010). All calls are routed through the
// Runner interface so unit tests need no live gateway or binary.
package openshell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"os/exec"
)

// Runner abstracts the execution of the openshell binary. The production
// implementation (execRunner) shells out; tests inject a fakeRunner.
type Runner interface {
	// Run executes bin with args and returns combined stdout. On non-zero exit,
	// stderr is folded into the returned error.
	Run(ctx context.Context, bin string, args ...string) ([]byte, error)

	// RunStream executes bin with args and streams stdout to w until the child
	// exits or ctx is cancelled. It is used for log-streaming sub-commands.
	RunStream(ctx context.Context, bin string, w io.Writer, args ...string) error
}

// InteractiveParams bundles all parameters for a PTY-attached subprocess.
// It is defined here (rather than in shell.go) so the Runner interface can
// reference it without a circular dependency.
type InteractiveParams struct {
	Bin    string
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	// Resize carries {cols, rows} pairs forwarded to the child PTY.
	Resize <-chan [2]uint16
}

// NewExecRunner returns the production Runner implementation.
func NewExecRunner() Runner {
	return execRunner{}
}

// execRunner is the production implementation of Runner that shells out via
// os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s",
			bin, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (execRunner) RunStream(ctx context.Context, bin string, w io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s %s: %w: %s",
			bin, strings.Join(args, " "), err, stderr.String())
	}
	return nil
}
