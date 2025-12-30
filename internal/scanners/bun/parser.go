package bun

import (
	"encoding/json"
	"fmt"
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

			f := model.Finding{
				Source:           "bun",
				Ecosystem:        "npm",
				Package:          pkgName,
				InstalledVersion: "unknown", // Bun audit output doesn't seem to explicitly list the installed version in this view, strictly the range.
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
