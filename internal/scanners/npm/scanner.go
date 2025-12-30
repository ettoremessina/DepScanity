package npm

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

// ScanNpm executes npm audit and parses the results.
func ScanNpm(ctx context.Context, lockPath string, timeoutSec int, outDir string) ([]model.Finding, error) {
	// 1. Setup paths
	workDir := filepath.Dir(lockPath)
	rawOutDir := filepath.Join(outDir, "raw")
	if err := os.MkdirAll(rawOutDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create raw output dir: %w", err)
	}

	// 2. Check npm existence
	if _, err := exec.LookPath("npm"); err != nil {
		return nil, fmt.Errorf("npm executable not found in PATH")
	}

	// 3. Execution (npm ci + npm audit)
	// Optionally run npm ci (best effort)
	// We use value of context or default timeout
	// But Scan function accepts timeoutSec, so let's stick to ctx passed by caller which should have timeout
	// However, we need to respect individual timeouts if we were managing it here.
	// The prompt says "ScanNpm(ctx, lockPath, timeoutSec, outDir)".
	// We will use the passed ctx primarily.

	// Attempt npm ci (ignore error)
	// Use a shorter timeout for ci? Or share the deadline?
	// Let's assume ctx covers the whole operation.
	depExec.Run(ctx, "npm", []string{"ci", "--ignore-scripts"}, workDir)

	// Run npm audit
	// We don't track duration specifically here as internal/exec does, but if we wanted to log it we could.
	// For now, remove unused variable
	res, err := depExec.Run(ctx, "npm", []string{"audit", "--json"}, workDir)
	// npm audit returns non-zero if vulnerabilities found, so we must proceed unless it's a critical error (like missing executable or timeout)
	if res.ExitCode == 127 || res.ExitCode == 124 {
		return nil, fmt.Errorf("npm audit failed execution (code %d): %v", res.ExitCode, err)
	}

	// 4. Save raw output
	sanitizedName := sanitizePath(workDir)
	rawFile := filepath.Join(rawOutDir, fmt.Sprintf("npm-%s.json", sanitizedName))
	if err := os.WriteFile(rawFile, []byte(res.Stdout), 0644); err != nil {
		// Just log/warn? For now we just return error as per requirements usually implies strictness,
		// but failure to write raw shouldn't stop reporting if parsing works.
		// Let's return error to be safe.
		return nil, fmt.Errorf("failed to write raw output: %w", err)
	}

	// 5. Parse
	findings, err := ParseNpmAudit(res.Stdout, lockPath)
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
