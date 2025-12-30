package bun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	depExec "depscanity/internal/exec"
	"depscanity/internal/model"
)

// ScanBun executes bun audit and parses the results.
func ScanBun(ctx context.Context, lockPath string, timeoutSec int, outDir string) ([]model.Finding, error) {
	// 1. Setup paths
	workDir := filepath.Dir(lockPath)
	rawOutDir := filepath.Join(outDir, "raw")
	if err := os.MkdirAll(rawOutDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create raw output dir: %w", err)
	}

	// 2. Check bun existence
	if _, err := exec.LookPath("bun"); err != nil {
		return nil, fmt.Errorf("bun executable not found in PATH")
	}

	// 3. Execution (bun audit --json)
	// Note: bun audit requires bun.lock or package-lock.json (handled by caller detection)
	// We run directly in workDir

	args := []string{"audit", "--json"}

	res, err := depExec.Run(ctx, "bun", args, workDir)

	// bun audit returns non-zero exit code if vulnerabilities are found?
	// Verified behavior: exit code 1 if vulnerabilities found.
	if res.ExitCode == 127 || res.ExitCode == 124 {
		return nil, fmt.Errorf("bun audit failed execution (code %d): %v", res.ExitCode, err)
	}

	// 4. Save raw output
	sanitizedName := sanitizePath(workDir)
	rawFile := filepath.Join(rawOutDir, fmt.Sprintf("bun-%s.json", sanitizedName))
	if err := os.WriteFile(rawFile, []byte(res.Stdout), 0644); err != nil {
		return nil, fmt.Errorf("failed to write raw output: %w", err)
	}

	// 5. Parse
	findings, err := ParseBunOutput(res.Stdout, lockPath)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return findings, nil
}

func sanitizePath(path string) string {
	s := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == ' ' {
			return '_'
		}
		return r
	}, path)
	return strings.Trim(s, "_")
}
