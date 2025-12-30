package dotnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"depscanity/internal/detect"
	depExec "depscanity/internal/exec"
	"depscanity/internal/model"
	"depscanity/internal/report"
)

const MaxDotnetSolutions = 5

// ScanDotnet executes dotnet list package --vulnerable and parses the results.
func ScanDotnet(ctx context.Context, rootPath string, detection detect.DetectionResult, timeoutSec int, outDir string) ([]model.Finding, []report.ScannerError) {
	var findings []model.Finding
	var scannerErrors []report.ScannerError

	// 1. Check dotnet existence
	if _, err := exec.LookPath("dotnet"); err != nil {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "dotnet",
			Location: rootPath,
			Message:  "dotnet executable not found in PATH",
		})
		return findings, scannerErrors
	}

	targets := detection.Dotnet
	// If no solutions found, try scanning the root (fallback)
	if len(targets) == 0 {
		targets = []string{rootPath}
	} else if len(targets) > MaxDotnetSolutions {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "dotnet",
			Location: rootPath,
			Message:  fmt.Sprintf("More than %d solutions found; scanning limited subset", MaxDotnetSolutions),
		})
		targets = targets[:MaxDotnetSolutions]
	}

	rawOutDir := filepath.Join(outDir, "raw")
	if err := os.MkdirAll(rawOutDir, 0755); err != nil {
		scannerErrors = append(scannerErrors, report.ScannerError{
			Source:   "dotnet",
			Location: rootPath,
			Message:  fmt.Sprintf("failed to create raw output dir: %v", err),
		})
		return findings, scannerErrors
	}

	for _, target := range targets {
		// Try to restore first (best-effort, but usually required for accurate results)
		// We use the same timeout? Or a shorter one? Restore can be slow.
		// Let's deduce WD
		wd := target
		info, err := os.Stat(target)
		if err == nil && !info.IsDir() {
			wd = filepath.Dir(target)
		}

		restoreArgs := []string{"restore"}
		if err == nil && !info.IsDir() {
			restoreArgs = append(restoreArgs, target)
		}

		// Run restore
		// We treat it as best-effort. If it fails, we still try to list (it might fail too, but we let it handle that).
		// We don't want to abort if restore fails (maybe user has private feeds or auth issues, but local cache is enough?)
		// Actually user said "I had to do before dotnet restore", implying it's needed.
		_, restoreErr := depExec.Run(ctx, "dotnet", restoreArgs, wd)
		if restoreErr != nil {
			// Just log to stdout for now or capture as non-fatal error?
			// Provide visibility in stdout
			fmt.Printf("  [Dotnet] Restore failed for %s (attempting scan anyway): %v\n", target, restoreErr)
		}

		args := []string{"list"}
		// If target is a file (sln/csproj), pass it. If directory (root fallback), pass nothing (implies CWD or we pass dir)
		if err == nil && !info.IsDir() {
			args = append(args, target)
		}

		args = append(args, "package", "--vulnerable", "--include-transitive")

		// wd is already calculated above for restore

		res, err := depExec.Run(ctx, "dotnet", args, wd)
		if res.ExitCode == 127 || res.ExitCode == 124 {
			scannerErrors = append(scannerErrors, report.ScannerError{
				Source:   "dotnet",
				Location: target,
				Message:  fmt.Sprintf("dotnet execution failed (code %d): %v", res.ExitCode, err),
			})
			continue
		}

		// Save raw output
		sanitized := sanitizePath(target)
		rawFile := filepath.Join(rawOutDir, fmt.Sprintf("dotnet-%s.txt", sanitized))
		_ = os.WriteFile(rawFile, []byte(res.Stdout), 0644)

		// Parse
		f, err := ParseDotnetOutput(res.Stdout, target)
		if err != nil {
			scannerErrors = append(scannerErrors, report.ScannerError{
				Source:   "dotnet",
				Location: target,
				Message:  fmt.Sprintf("parse error: %v", err),
			})
		}
		findings = append(findings, f...)
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
