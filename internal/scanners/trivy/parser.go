package trivy

import (
	"encoding/json"
	"fmt"

	"depscanity/internal/model"
)

type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

func ParseTrivyOutput(jsonOutput string) ([]model.Finding, error) {
	var report TrivyReport
	if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil {
		// Sometimes trivy outputs nothing if no vulnerabilities? Or empty JSON?
		// Ensure it's valid JSON
		return nil, fmt.Errorf("failed to unmarshal trivy json: %w", err)
	}

	var findings []model.Finding

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			// Normalize fields

			// Severity
			sev, _ := model.ParseSeverity(v.Severity)

			// URL
			url := v.PrimaryURL
			if url == "" && len(v.References) > 0 {
				url = v.References[0]
			}

			title := v.Title
			if title == "" {
				// Fallback to ID if no title
				title = v.VulnerabilityID
			}

			fixed := v.FixedVersion
			var fixedPtr *string
			if fixed != "" {
				fixedPtr = &fixed
			}

			var urlPtr *string
			if url != "" {
				urlPtr = &url
			}

			var titlePtr *string
			if title != "" {
				titlePtr = &title
			}

			f := model.Finding{
				Source:           "trivy",
				Ecosystem:        "container", // Default to container for now
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     fixedPtr,
				VulnerabilityID:  v.VulnerabilityID,
				Severity:         sev,
				Title:            titlePtr,
				URL:              urlPtr,
				Location:         result.Target,
				Metadata: map[string]any{
					"description": v.Description,
				},
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}
