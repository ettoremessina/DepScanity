package npm

import (
	"encoding/json"
	"fmt"

	"depscanity/internal/model"
)

// AuditReportV7 represents the structure of npm v7+ audit report.
type AuditReportV7 struct {
	Vulnerabilities map[string]AuditVuln `json:"vulnerabilities"`
}

type AuditVuln struct {
	Name         string          `json:"name"`
	Severity     string          `json:"severity"` // "moderate"|"high" etc.
	Via          json.RawMessage `json:"via"`      // Can be []string or []detailObject
	IsDirect     bool            `json:"isDirect"`
	Effects      []string        `json:"effects"`
	Range        string          `json:"range"`
	Nodes        []string        `json:"nodes"`
	FixAvailable any             `json:"fixAvailable"` // bool or object
}

// Struct for object in "via" array
type ViaDetail struct {
	Source     any    `json:"source"` // Can be a number (advisory ID) or useful string? Actually in v7 it's usually id (int) or string url
	Name       string `json:"name"`
	Dependency string `json:"dependency"`
	Title      string `json:"title"`
	Url        string `json:"url"`
	Severity   string `json:"severity"`
	Range      string `json:"range"`
}

// Actually, via objects have specific fields.
// "via": [{"source": 1084, "name": "minimist", "dependency": "minimist", "title": "Prototype Pollution", "url": "https://...", "severity": "low", "range": "<0.2.1"}]
// Or "via": ["some-package"]

func ParseNpmAudit(jsonOutput string, lockPath string) ([]model.Finding, error) {
	// Try parsing as v7+
	var report AuditReportV7
	if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal npm audit json: %w", err)
	}

	var findings []model.Finding

	for pkgName, vuln := range report.Vulnerabilities {
		// Determine installed version if possible.
		// `npm audit` v7 doesn't explicitly list "installed version" in the top-level vuln object easily,
		// it often implies it via `nodes` or we have to guess.
		// However, typical usage is that the vuln object applies to the installed instance.
		// We will set InstalledVersion to "?" if not found, or try to parse from `range` if it helps? No, range is vulnerable range.

		// Wait, `nodes` contains ["node_modules/package"].
		// Ideally we would look up the version in package-lock, but we don't satisfy that requirement here.
		// Use "Unknown" for installed version if not readily available in audit json.
		// Actually, sometimes "via" contains info.

		// Let's stick to simple parsing.
		installedVer := "Unknown"

		sev, _ := model.ParseSeverity(vuln.Severity)

		fixVer := parseFixAvailable(vuln.FixAvailable)

		// Parse "via" to get IDs
		// via can be:
		// 1. Array of strings (names of causing packages) -> transitive
		// 2. Array of objects (direct advisories)

		var viaDetails []ViaDetail
		var viaStrings []string

		// Try to unmarshal as []ViaDetail first
		// IMPORTANT: If we unmarshal ["string"] into []Struct, it might result in mixed garbage or error.
		// Safe approach: unmarshal into []json.RawMessage, then inspect each.

		var rawVia []json.RawMessage
		if err := json.Unmarshal(vuln.Via, &rawVia); err == nil {
			for _, rv := range rawVia {
				// Try string first
				var s string
				if err := json.Unmarshal(rv, &s); err == nil {
					viaStrings = append(viaStrings, s)
					continue
				}
				// Try object
				var d ViaDetail
				if err := json.Unmarshal(rv, &d); err == nil {
					viaDetails = append(viaDetails, d)
				}
			}
		}

		if len(viaDetails) > 0 {
			for _, d := range viaDetails {
				// Each detail is a distinct vulnerability
				// ID selection: Use source ID if possible
				var vulnID string
				if id, ok := d.Source.(float64); ok {
					vulnID = fmt.Sprintf("NPM-%d", int(id))
				} else if idStr, ok := d.Source.(string); ok {
					vulnID = fmt.Sprintf("NPM-%s", idStr)
				} else {
					vulnID = "NPM-Unknown"
				}

				title := d.Title
				url := d.Url
				detailSev, _ := model.ParseSeverity(d.Severity)

				f := model.Finding{
					Source:           "npm",
					Ecosystem:        "npm",
					Package:          pkgName,
					InstalledVersion: installedVer,
					FixedVersion:     fixVer,
					VulnerabilityID:  vulnID,
					Severity:         detailSev,
					Title:            &title,
					URL:              &url,
					Location:         lockPath,
					Metadata: map[string]any{
						"range": d.Range,
						"via":   d.Name,
					},
				}
				findings = append(findings, f)
			}
		} else if len(viaStrings) > 0 {
			// Transitive vulnerability caused by others.
			for _, viaStr := range viaStrings {
				f := model.Finding{
					Source:           "npm",
					Ecosystem:        "npm",
					Package:          pkgName,
					InstalledVersion: installedVer,
					FixedVersion:     fixVer,
					VulnerabilityID:  fmt.Sprintf("Transitive-%s", viaStr),
					Severity:         sev,
					Location:         lockPath,
					Metadata: map[string]any{
						"via": viaStr,
					},
				}
				findings = append(findings, f)
			}
		} else {
			// Fallback finding if via is empty or malformed
			f := model.Finding{
				Source:           "npm",
				Ecosystem:        "npm",
				Package:          pkgName,
				InstalledVersion: installedVer,
				FixedVersion:     fixVer,
				VulnerabilityID:  "Unknown",
				Severity:         sev,
				Location:         lockPath,
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func parseFixAvailable(raw any) *string {
	// fixAvailable can be boolean (false/true) or object { "name": "pkg", "version": "1.2.3", "isSemVerMajor": true }
	if b, ok := raw.(bool); ok {
		if !b {
			return nil
		}
		// If true, but no version, we don't know the version
		return nil
	}

	if m, ok := raw.(map[string]any); ok {
		if v, ok := m["version"].(string); ok {
			return &v
		}
	}
	return nil
}
