package exec

import (
	"context"
	"testing"
	"time"
)

func TestRun_Success(t *testing.T) {
	ctx := context.Background()
	// "go env" should be available and safe
	res, err := Run(ctx, "go", []string{"env", "GOHOSTOS"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout == "" {
		t.Error("expected stdout output, got empty")
	}
}

func TestRun_NotFound(t *testing.T) {
	ctx := context.Background()
	res, _ := Run(ctx, "nonexistentcommand12345", nil, "")
	if res.ExitCode != 127 {
		t.Errorf("expected exit code 127 for missing command, got %d", res.ExitCode)
	}
}

func TestRun_Timeout(t *testing.T) {
	// Attempt to find a command that sleeps. Unix "sleep" is common.
	// If not present, this test might fail or skip.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try running "sleep 2" which should timeout
	res, _ := Run(ctx, "sleep", []string{"2"}, "")

	// If sleep is not found (e.g. Windows without sleep), we might get 127.
	// In a controlled dev env (Mac/Linux), sleep usually exists.
	// For robustness, we check if it was 127, and skip if so.
	if res.ExitCode == 127 {
		t.Skip("sleep command not found, skipping timeout test")
	}

	if res.ExitCode != 124 {
		t.Errorf("expected exit code 124 for timeout, got %d", res.ExitCode)
	}
}
