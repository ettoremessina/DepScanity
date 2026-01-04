package bun

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"depscanity/internal/model"
)

type BunAdvisory struct {
	ID                 any    `json:"id"` // Can be int or string
	URL                string `json:"url"`
	Title              string `json:"title"`
	Severity           string `json:"severity"`
	VulnerableVersions string `json:"vulnerable_versions"`
}

// ParseBunOutput parses JSON output from `bun audit --json`
func ParseBunOutput(jsonOutput string, lockPath string) ([]model.Finding, error) {
	var results []model.Finding
	if strings.TrimSpace(jsonOutput) == "" {
		return results, nil
	}

	// 1. Parse lockfile to get installed versions
	installedMap, err := parseBunLock(lockPath)
	if err != nil {
		fmt.Printf("Warning: failed to parse bun.lock: %v\n", err)
	}

	// Format is map[package_name][]Advisory
	var report map[string][]BunAdvisory
	if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil {
		if strings.Contains(jsonOutput, "No vulnerabilities found") {
			return results, nil
		}
		return nil, fmt.Errorf("failed to parse bun audit json: %v", err)
	}

	for pkgName, advisories := range report {
		for _, adv := range advisories {
			sev, err := model.ParseSeverity(adv.Severity)
			if err != nil {
				sev = model.SeverityLow
			}

			// Handle ID which might be int or string
			vulnID := fmt.Sprintf("%v", adv.ID)

			// Try to extract GHSA from URL if ID is just a number
			if strings.Contains(adv.URL, "GHSA-") {
				parts := strings.Split(adv.URL, "/")
				if len(parts) > 0 {
					last := parts[len(parts)-1]
					if strings.HasPrefix(last, "GHSA-") {
						vulnID = last
					}
				}
			}

			// Resolve installed version
			ver := "unknown"
			if v, ok := installedMap[pkgName]; ok {
				ver = v
			}

			f := model.Finding{
				Source:           "bun",
				Ecosystem:        "npm",
				Package:          pkgName,
				InstalledVersion: ver,
				VulnerabilityID:  vulnID,
				Severity:         sev,
				Location:         lockPath,
				Title:            &adv.Title,
				URL:              &adv.URL,
				Metadata: map[string]any{
					"vulnerable_versions": adv.VulnerableVersions,
				},
			}
			results = append(results, f)
		}
	}

	return results, nil
}

// parseBunLock parses bun.lock text file to map package names to versions.
// Format is JSON-like:
//
//	"packages": {
//	   "axios": ["axios@0.21.1", ...],
//	}
func parseBunLock(lockPath string) (map[string]string, error) {
	result := make(map[string]string)

	// Check if file exists
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	// Identify format: check if it starts with { (JSON-like v1)
	// Bun lockfiles (yarn-like or json-like) often have trailing commas which standard JSON lib hates.
	// Simple sanitize: remove ", }" and ", ]" -> "}" / "]"?
	// Or use regex.
	strContent := string(content)
	// Remove trailing comma before closing brace/bracket
	// regex: `,\s*([}\]])` -> `$1`
	re := regexp.MustCompile(`,\s*([}\]])`)
	strContent = re.ReplaceAllString(strContent, "$1")

	// Partial struct for just retrieving packages
	type BunLock struct {
		Packages map[string][]any `json:"packages"`
	}

	var lock BunLock
	if err := json.Unmarshal([]byte(strContent), &lock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bun.lock: %w", err)
	}

	for pkg, val := range lock.Packages {
		if len(val) > 0 {
			// First element is string "pkg@version"
			if str, ok := val[0].(string); ok {
				parts := strings.Split(str, "@")
				if len(parts) >= 2 {
					// Last part is version (handle scoped packages @scope/pkg@ver)
					version := parts[len(parts)-1]
					result[pkg] = version
				}
			}
		}
	}

	return result, nil
}
