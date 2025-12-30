package trivy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	depExec "depscanity/internal/exec"
	"depscanity/internal/model"
	"depscanity/internal/report"
)

// ScanTrivy executes trivy image and parses the results.
func ScanTrivy(ctx context.Context, imageRef string, timeoutSec int, outDir string) ([]model.Finding, []report.ScannerError) {
	var findings []model.Finding
	var scannerErrors []report.ScannerError

	// 1. Check trivy existence
	if _, err := exec.LookPath("trivy"); err != nil {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "trivy",
			Location: imageRef,
			Message:  "trivy executable not found in PATH",
		})
		return findings, scannerErrors
	}

	rawOutDir := filepath.Join(outDir, "raw")
	if err := os.MkdirAll(rawOutDir, 0755); err != nil {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "trivy",
			Location: imageRef,
			Message:  fmt.Sprintf("failed to create raw output dir: %v", err),
		})
		return findings, scannerErrors
	}

	// 2. Run Trivy
	// trivy image --format json --no-progress <imageRef>
	args := []string{"image", "--format", "json", "--no-progress", imageRef}

	// We run it with a timeout context
	res, err := depExec.Run(ctx, "trivy", args, ".")

	// Save runner output (stdout/stderr) for debugging
	sanitized := sanitizePath(imageRef)
	runFile := filepath.Join(rawOutDir, fmt.Sprintf("trivy-run-%s.txt", sanitized))
	_ = os.WriteFile(runFile, []byte(fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s\nEXIT: %d\nERROR: %v", res.Stdout, res.Stderr, res.ExitCode, err)), 0644)

	if res.ExitCode == 127 || res.ExitCode == 124 {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "trivy",
			Location: imageRef,
			Message:  fmt.Sprintf("trivy execution failed (code %d): %v", res.ExitCode, err),
		})
		return findings, scannerErrors
	}

	// 3. Save raw JSON
	jsonFile := filepath.Join(rawOutDir, fmt.Sprintf("trivy-image-%s.json", sanitized))
	_ = os.WriteFile(jsonFile, []byte(res.Stdout), 0644)

	// 4. Parse
	findings, err = ParseTrivyOutput(res.Stdout)
	if err != nil {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "trivy",
			Location: imageRef,
			Message:  fmt.Sprintf("parse error: %v", err),
		})
	}

	return findings, scannerErrors
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
