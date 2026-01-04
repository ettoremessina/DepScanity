package main

import (
	"bufio"
	"context"
	depExec "depscanity/internal/exec"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"depscanity/internal/aggregate"
	"depscanity/internal/detect"
	"depscanity/internal/model"
	"depscanity/internal/report"
	"depscanity/internal/scanners/bun"
	"depscanity/internal/scanners/dotnet"
	"depscanity/internal/scanners/npm"
	"depscanity/internal/scanners/trivy"
)

type Config struct {
	OutDir      string
	FailOn      string
	TimeoutSec  int
	NoOSV       bool
	NoContainer bool
	Image       string
	DockerBuild bool
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	if command != "scan" {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	// Parse flags for "scan" subcommand
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	config := Config{}

	scanCmd.StringVar(&config.OutDir, "out", "depscanity_out", "Output directory")
	scanCmd.StringVar(&config.FailOn, "fail-on", "high", "Fail on severity (low, medium, high, critical)")
	scanCmd.IntVar(&config.TimeoutSec, "timeout", 600, "Timeout in seconds")
	scanCmd.BoolVar(&config.NoOSV, "no-osv", false, "Disable OSV scanner")
	scanCmd.BoolVar(&config.NoContainer, "no-container", false, "Disable container scanning")
	scanCmd.StringVar(&config.Image, "image", "", "Docker image to scan directly")
	scanCmd.BoolVar(&config.DockerBuild, "docker-build", false, "Build docker image before scanning")

	// Custom argument parsing to allow flags after positional arguments
	// The standard flag package stops parsing at the first non-flag argument.
	// We will manually identify flags and move them to the front.

	rawArgs := os.Args[2:]
	var flagArgs []string
	var posArgs []string

	// Map of flags that take arguments (copied from definitions below)
	// We need to know this to properly consume the next argument as value.
	takesValue := map[string]bool{
		"-out": true, "--out": true,
		"-fail-on": true, "--fail-on": true,
		"-timeout": true, "--timeout": true,
		"-image": true, "--image": true,
	}

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if strings.HasPrefix(arg, "-") {
			// It's a flag
			flagArgs = append(flagArgs, arg)

			// Check if it takes a value
			baseFlag := strings.Split(arg, "=")[0] // Handle --flag=value case (std flag supports it)
			// If contains =, value is attached, no need to consume next.
			if !strings.Contains(arg, "=") && takesValue[baseFlag] {
				// Consume next arg as value if available
				if i+1 < len(rawArgs) {
					flagArgs = append(flagArgs, rawArgs[i+1])
					i++
				}
			}
		} else {
			// Positional argument
			posArgs = append(posArgs, arg)
		}
	}

	// Parse the separable flags
	if err := scanCmd.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Treat detected positional args as the remaining args
	targetPath := "."
	if len(posArgs) > 0 {
		targetPath = posArgs[0]
	}

	// Validate target path
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid target path: %v\n", err)
		os.Exit(1)
	}

	// Validate FailOn
	if _, err := model.ParseSeverity(config.FailOn); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid fail-on value: %v\n", err)
		os.Exit(1)
	}

	// Run Detection
	fmt.Printf("Analyzing %s ...\n", absPath)
	detRes, err := detect.DetectStacks(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Detection failed: %v\n", err)
		os.Exit(1)
	}

	// Print Plan Summary
	fmt.Println("\n=== DepScanity Plan ===")
	fmt.Printf("Target:     %s\n", absPath)
	fmt.Printf("Output:     %s\n", config.OutDir)
	fmt.Printf("Timeout:    %ds\n", config.TimeoutSec)
	fmt.Printf("Fail On:    %s\n", config.FailOn)

	fmt.Println("\n[Detected Stacks]")
	printStack("Dotnet", detRes.Dotnet)
	printStack("NPM", detRes.Npm)
	printStack("Bun", detRes.Bun)
	printStack("Docker", detRes.Docker)

	fmt.Println("\n[Execution]")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TimeoutSec)*time.Second)
	defer cancel()

	var allFindings []model.Finding
	var scannerErrors []report.ScannerError
	toolsRun := make(map[string]bool)

	// NPM Scanning
	if len(detRes.Npm) > 0 {
		fmt.Printf("Scanning %d NPM lockfiles...\n", len(detRes.Npm))
		toolsRun["npm"] = true
		limit := 10
		if len(detRes.Npm) < limit {
			limit = len(detRes.Npm)
		}
		for i, lockFile := range detRes.Npm[:limit] {
			fmt.Printf("  [%d/%d] Scanning %s ... ", i+1, limit, lockFile)
			findings, err := npm.ScanNpm(ctx, lockFile, config.TimeoutSec, config.OutDir)
			if err != nil {
				fmt.Printf("Failed: %v\n", err)
				scannerErrors = append(scannerErrors, report.ScannerError{
					Source:   "npm",
					Location: lockFile,
					Message:  err.Error(),
				})
			} else {
				fmt.Printf("OK (%d findings)\n", len(findings))
				allFindings = append(allFindings, findings...)
			}
		}
		if len(detRes.Npm) > limit {
			fmt.Printf("  ... skipped %d remaining lockfiles (limit 10)\n", len(detRes.Npm)-limit)
		}
	} else {
		toolsRun["npm"] = false
	}

	// Bun Scanning (New)
	if len(detRes.Bun) > 0 {
		fmt.Printf("Scanning %d Bun lockfiles...\n", len(detRes.Bun))
		toolsRun["bun"] = true
		limit := 10
		if len(detRes.Bun) < limit {
			limit = len(detRes.Bun)
		}
		for i, lockFile := range detRes.Bun[:limit] {
			fmt.Printf("  [%d/%d] Scanning %s ... ", i+1, limit, lockFile)
			findings, err := bun.ScanBun(ctx, lockFile, config.TimeoutSec, config.OutDir)
			if err != nil {
				fmt.Printf("Failed: %v\n", err)
				scannerErrors = append(scannerErrors, report.ScannerError{
					Source:   "bun",
					Location: lockFile,
					Message:  err.Error(),
				})
			} else {
				fmt.Printf("OK (%d findings)\n", len(findings))
				allFindings = append(allFindings, findings...)
			}
		}
		if len(detRes.Bun) > limit {
			fmt.Printf("  ... skipped %d remaining lockfiles (limit 10)\n", len(detRes.Bun)-limit)
		}
	} else {
		toolsRun["bun"] = false
	}

	// Dotnet Scanning
	shouldScanDotnet := len(detRes.Dotnet) > 0
	if !shouldScanDotnet {
		// Heuristic: check if obj folder exists (implies dotnet project might exist without recognized project files?)
		// Used to be: } else if _, err := os.Stat(filepath.Join(absPath, "obj")); err == nil {
		if _, err := os.Stat(filepath.Join(absPath, "obj")); err == nil {
			shouldScanDotnet = true
		}
	}

	if shouldScanDotnet {
		toolsRun["dotnet"] = true
		fmt.Printf("Scanning Dotnet (found %d files)...\n", len(detRes.Dotnet))

		// Filter targets
		var finalTargets []string
		var slns []string
		for _, f := range detRes.Dotnet {
			if strings.HasSuffix(f, ".sln") {
				slns = append(slns, f)
			}
		}
		// Fallback: If no SLNs, use project files (csproj) if available
		if len(slns) > 0 {
			// Scan solutions
			finalTargets = append(finalTargets, slns...)

			// Detect orphans
			includedProjects, err := getProjectsInSolutions(slns)
			if err != nil {
				// Warn but proceed with just solutions?
				fmt.Printf("Warning: Failed to parse solutions for orphan detection: %v\n", err)
			} else {
				// Find orphans
				orphanCount := 0
				for _, projPath := range detRes.Dotnet {
					// Skip if it's a solution
					if strings.HasSuffix(projPath, ".sln") {
						continue
					}
					// Check if included
					if !includedProjects[projPath] {
						finalTargets = append(finalTargets, projPath)
						orphanCount++
					}
				}
				if orphanCount > 0 {
					fmt.Printf("  Found %d orphan projects (not in solution).\n", orphanCount)
				}
			}

			fmt.Printf("  Targeting %d items (%d solutions + orphans).\n", len(finalTargets), len(slns))
		} else if len(detRes.Dotnet) > 0 {
			// If no SLNs but we have other dotnet files (which are csproj per detect logic)
			// we target them directly.
			finalTargets = detRes.Dotnet
			fmt.Printf("  Targeting %d projects (no solution found).\n", len(finalTargets))
		} else {
			// Fallback to root scan (Scanner handles empty targets list by scanning root)
			// This path is technically redundant if detRes.Dotnet was empty (shouldScanDotnet logic handles it),
			// but kep for safety.
			finalTargets = []string{}
			fmt.Printf("  No solutions or projects found, scanning repository root.\n")
		}

		detOverride := detRes
		detOverride.Dotnet = finalTargets

		findings, errs := dotnet.ScanDotnet(ctx, absPath, detOverride, config.TimeoutSec, config.OutDir)

		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Printf("  Dotnet error: %s: %s\n", e.Location, e.Message)
			}
			scannerErrors = append(scannerErrors, errs...)
		}
		fmt.Printf("  Dotnet OK (%d findings)\n", len(findings))
		allFindings = append(allFindings, findings...)
	} else {
		toolsRun["dotnet"] = false
	}
	// Container / Trivy Scanning
	// Should run if: !NoContainer AND (Image provided OR (DockerBuild AND Dockerfile detected))
	hasDockerfile := len(detRes.Docker) > 0 // Simplification: assume if "Docker" stack detected, it implies Dockerfile or similar.
	// Actually detRes.Docker contains files. Check if any "Dockerfile" is in the list or we just trust the stack detection presence.
	// Stack detection detects Dockerfile, docker-compose.yml etc.
	// The requirement for "DockerBuild" implies a Dockerfile at root usually, or we build the root context.

	shouldScanContainer := !config.NoContainer
	if shouldScanContainer {
		targetImage := config.Image

		// Logic: if no image provided, but DockerBuild is requested and we detected Docker stack (or just trust user wants to build context?),
		// we verify if we can build.
		// Requirement: "a) --image <ref> is provided b) --docker-build is set AND a Dockerfile is detected"

		if targetImage == "" && config.DockerBuild && hasDockerfile {
			fmt.Println("Building local Docker image (depscanity:local)...")
			// Build
			// docker build -t depscanity:local <absPath>
			// We need a timeout for build too? Reuse config.TimeoutSec? Or larger?
			// Use context.

			// Check docker existence
			buildArgs := []string{"build", "-t", "depscanity:local", absPath}
			buildRes, err := depExec.Run(ctx, "docker", buildArgs, absPath)

			// Save raw build logs? "out/raw/docker-build.txt"
			rawOutDir := filepath.Join(config.OutDir, "raw")
			_ = os.MkdirAll(rawOutDir, 0755)
			_ = os.WriteFile(filepath.Join(rawOutDir, "docker-build.txt"), []byte(fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s\nEXIT: %d\nERROR: %v", buildRes.Stdout, buildRes.Stderr, buildRes.ExitCode, err)), 0644)

			if err != nil || buildRes.ExitCode != 0 {
				fmt.Printf("Docker build failed. code=%d err=%v. See report for details.\n", buildRes.ExitCode, err)
				scannerErrors = append(scannerErrors, report.ScannerError{
					Source:   "trivy-build",
					Location: absPath,
					Message:  fmt.Sprintf("Docker build failed: %v\nStderr: %s", err, buildRes.Stderr),
				})
				// If build failed, can't scan
				shouldScanContainer = false
			} else {
				fmt.Println("Docker build successful.")
				targetImage = "depscanity:local"
			}
		} else if targetImage == "" {
			// No image provided, and conditions for auto-build not met
			shouldScanContainer = false
		}

		if shouldScanContainer {
			fmt.Printf("Scanning container image: %s ...\n", targetImage)
			toolsRun["trivy"] = true

			findings, errs := trivy.ScanTrivy(ctx, targetImage, config.TimeoutSec, config.OutDir)
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Printf("  Trivy error: %s\n", e.Message)
				}
				scannerErrors = append(scannerErrors, errs...)
			}
			fmt.Printf("  Trivy OK (%d findings)\n", len(findings))
			allFindings = append(allFindings, findings...)
		} else {
			toolsRun["trivy"] = false
		}
	} else {
		toolsRun["trivy"] = false
	}

	// Aggregation
	uniqueFindings := aggregate.AggregateFindings(allFindings)
	fmt.Printf("\nTotal unique findings: %d\n", len(uniqueFindings))

	// Reporting
	meta := report.ReportMeta{
		ScannedPath:   absPath,
		Timestamp:     time.Now().Format(time.RFC3339),
		FailOn:        config.FailOn,
		Detected:      detRes,
		Tools:         toolsRun,
		ScannerErrors: scannerErrors,
	}

	if err := report.Generate(config.OutDir, meta, uniqueFindings); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate report: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Reports saved to %s/\n", config.OutDir)

	// Exit Code Logic
	failSev, _ := model.ParseSeverity(config.FailOn)
	maxSevRank := 0
	for _, f := range uniqueFindings {
		r := f.Severity.Rank()
		if r > maxSevRank {
			maxSevRank = r
		}
	}

	// Priority 1: Threshold failure (Exit Code 2)
	if maxSevRank >= failSev.Rank() {
		fmt.Printf("FAILURE: Found severity level %s or higher.\n", failSev)
		os.Exit(2)
	}

	// Priority 2: Runtime/Scanner errors (Exit Code 3)
	// If requested operations (like docker build) failed, we shouldn't return 0.
	if len(scannerErrors) > 0 {
		fmt.Printf("COMPLETED WITH ERRORS: %d error(s) occurred during scanning.\n", len(scannerErrors))
		for _, e := range scannerErrors {
			fmt.Printf(" - [%s] %s\n", e.Source, e.Message)
		}
		os.Exit(3)
	}

	fmt.Println("SUCCESS")

	fmt.Println("\n[Options]")
	fmt.Printf("OSV Scanner:       %v\n", !config.NoOSV)
	fmt.Printf("Container Scan:    %v\n", !config.NoContainer)
	if config.Image != "" {
		fmt.Printf("Target Image:      %s\n", config.Image)
	}
	if config.DockerBuild {
		fmt.Printf("Docker Build:      Enabled\n")
	}
}

func printStack(name string, files []string) {
	if len(files) == 0 {
		return
	}
	fmt.Printf("- %s (%d files)\n", name, len(files))
	// Sort just in case detection didn't (it should have)
	sort.Strings(files)
	for _, f := range files {
		fmt.Printf("  * %s\n", f)
	}
}

func printUsage() {
	fmt.Println("Usage: depscanity scan <path> [flags]")
	fmt.Println("Flags:")
	fmt.Println("  --out          Output directory (default: depscanity_out)")
	fmt.Println("  --fail-on      Fail severity threshold (default: high)")
	fmt.Println("  --timeout      Timeout in seconds (default: 600)")
	fmt.Println("  --no-osv       Disable OSV scanner")
	fmt.Println("  --no-container Disable container scanning")
	fmt.Println("  --image        Scan specific docker image")
	fmt.Println("  --docker-build Build docker image before scanning")
}

// getProjectsInSolutions parses .sln files to find included projects.
// Returns a map of absolute paths to projects that are PART of a solution.
func getProjectsInSolutions(slnPaths []string) (map[string]bool, error) {
	included := make(map[string]bool)

	for _, slnPath := range slnPaths {
		file, err := os.Open(slnPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		baseDir := filepath.Dir(slnPath)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Format: Project("{GUID}") = "Name", "Path\To\Project.csproj", "{GUID}"
			if strings.HasPrefix(line, "Project(") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					// valid project line
					// split by comma to get the path (2nd quoted string)
					segments := strings.Split(parts[1], ",")
					if len(segments) >= 3 {
						// The path is in the second segment, quoted.
						rawPath := strings.TrimSpace(segments[1])
						rawPath = strings.Trim(rawPath, "\"")

						// Convert Windows path separators to OS specific if needed, but standard library handles / usually
						// However SLN uses backslashes
						cleanPath := strings.ReplaceAll(rawPath, "\\", string(os.PathSeparator))

						absPath := filepath.Join(baseDir, cleanPath)

						// Normalize path
						absPath, _ = filepath.Abs(absPath)
						included[absPath] = true
					}
				}
			}
		}
	}
	return included, nil
}
