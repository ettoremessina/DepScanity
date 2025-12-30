package exec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// Result holds the execution result.
type Result struct {
	Stdout   string
	Stderr   string
	Duration time.Duration
	ExitCode int
}

// Run executes a command with context/timeout, capturing output and duration.
// It returns specific exit codes for timeout (124) and not found (127).
func Run(ctx context.Context, name string, args []string, dir string) (Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	res := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
		ExitCode: 0,
	}

	if err != nil {
		// Exit code handling
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			// Other errors (e.g. not found, context cancelled)
			res.ExitCode = 1 // Default fallback
		}

		// Check for context timeout/deadline exceeded
		if ctx.Err() == context.DeadlineExceeded {
			res.ExitCode = 124
			// Wrap the error to indicate timeout clearly if desired, or just return as is.
			// The caller can check ExitCode 124.
		} else if errors.Is(err, exec.ErrNotFound) {
			res.ExitCode = 127
		}
	}

	return res, err
}
