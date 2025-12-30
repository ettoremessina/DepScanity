package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"depscanity/internal/detect"
	"depscanity/internal/model"
)

type ReportMeta struct {
	ScannedPath   string                 `json:"scanned_path"`
	Timestamp     string                 `json:"timestamp"`
	FailOn        string                 `json:"fail_on"`
	Detected      detect.DetectionResult `json:"detected"`
	Tools         map[string]bool        `json:"tools"`
	ScannerErrors []ScannerError         `json:"scanner_errors"`
}

type ScannerError struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

type Report struct {
	Meta     ReportMeta      `json:"meta"`
	Findings []model.Finding `json:"findings"`
}

func Generate(outDir string, meta ReportMeta, findings []model.Finding) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// 1. JSON Report
	rep := Report{
		Meta:     meta,
		Findings: findings,
	}

	jsonBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "report.json"), jsonBytes, 0644); err != nil {
		return err
	}

	// 2. Markdown Report
	md := generateMarkdown(meta, findings)
	if err := os.WriteFile(filepath.Join(outDir, "report.md"), []byte(md), 0644); err != nil {
		return err
	}

	return nil
}

func generateMarkdown(meta ReportMeta, findings []model.Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# DepScanity Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", meta.ScannedPath))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n", meta.Timestamp))
	sb.WriteString(fmt.Sprintf("**Fail On:** %s\n\n", meta.FailOn))

	// Counts
	counts := make(map[model.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", counts[model.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", counts[model.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", counts[model.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", counts[model.SeverityLow]))
	sb.WriteString("\n")

	// Top Findings (Limit 30)
	sb.WriteString("## Top Findings\n\n")
	if len(findings) == 0 {
		sb.WriteString("_No findings._\n")
	} else {
		sb.WriteString("| Sev | Package | Installed | Fixed | VulnID | Title | Location |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

		limit := 30
		if len(findings) < limit {
			limit = len(findings)
		}

		for _, f := range findings[:limit] {
			title := ""
			if f.Title != nil {
				title = *f.Title
			}
			fixed := ""
			if f.FixedVersion != nil {
				fixed = *f.FixedVersion
			}
			// Sanitize title for table
			title = strings.ReplaceAll(title, "|", "\\|")

			// Relative location if possible
			loc := f.Location
			if rel, err := filepath.Rel(meta.ScannedPath, f.Location); err == nil {
				loc = rel
			}

			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.Package, f.InstalledVersion, fixed, f.VulnerabilityID, title, loc))
		}
		if len(findings) > 30 {
			sb.WriteString(fmt.Sprintf("\n*...and %d more findings inside report.json*\n", len(findings)-30))
		}
	}

	sb.WriteString("\n## Findings by Source\n\n")

	// NPM specific	// Findings by source
	// NPM
	var npmFindings []model.Finding
	for _, f := range findings {
		if f.Source == "npm" {
			npmFindings = append(npmFindings, f)
		}
	}
	if len(npmFindings) > 0 {
		fmt.Fprintf(&sb, "\n## NPM Findings (%d)\n\n", len(npmFindings))
		fmt.Fprintf(&sb, "| Severity | Package | Version | Vuln ID |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|\n")
		for _, f := range npmFindings {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", f.Severity, f.Package, f.InstalledVersion, f.VulnerabilityID)
		}
	}

	// Dotnet
	var dotnetFindings []model.Finding
	for _, f := range findings {
		if f.Source == "dotnet" {
			dotnetFindings = append(dotnetFindings, f)
		}
	}
	if len(dotnetFindings) > 0 {
		fmt.Fprintf(&sb, "\n## Dotnet / NuGet Findings (%d)\n\n", len(dotnetFindings))
		fmt.Fprintf(&sb, "| Severity | Package | Version | Vuln ID |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|\n")
		for _, f := range dotnetFindings {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", f.Severity, f.Package, f.InstalledVersion, f.VulnerabilityID)
		}
	}

	// Bun
	var bunFindings []model.Finding
	for _, f := range findings {
		if f.Source == "bun" {
			bunFindings = append(bunFindings, f)
		}
	}
	if len(bunFindings) > 0 {
		fmt.Fprintf(&sb, "\n## Bun / NPM Findings (%d)\n\n", len(bunFindings))
		fmt.Fprintf(&sb, "| Severity | Package | Version | Vuln ID |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|\n")
		for _, f := range bunFindings {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", f.Severity, f.Package, f.InstalledVersion, f.VulnerabilityID)
		}
	}

	// Trivy / Container
	var containerFindings []model.Finding
	for _, f := range findings {
		if f.Source == "trivy" {
			containerFindings = append(containerFindings, f)
		}
	}
	if len(containerFindings) > 0 {
		fmt.Fprintf(&sb, "\n## Container / OS Findings (%d)\n\n", len(containerFindings))
		fmt.Fprintf(&sb, "| Severity | Package | Version | Vuln ID |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|\n")
		for _, f := range containerFindings {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", f.Severity, f.Package, f.InstalledVersion, f.VulnerabilityID)
		}
	}
	// Scanner Errors Section
	if len(meta.ScannerErrors) > 0 {
		fmt.Fprintf(&sb, "\n## ⚠️ Scanner Errors (%d)\n\n", len(meta.ScannerErrors))
		fmt.Fprintf(&sb, "> [!WARNING]\n")
		fmt.Fprintf(&sb, "> The following errors occurred during the scan. Some components may not have been scanned correctly.\n\n")

		fmt.Fprintf(&sb, "| Source | Location | Message |\n")
		fmt.Fprintf(&sb, "|---|---|---|\n")
		for _, e := range meta.ScannerErrors {
			// Sanitize message for table
			msg := strings.ReplaceAll(e.Message, "|", "\\|")
			msg = strings.ReplaceAll(msg, "\n", " ")
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", e.Source, e.Location, msg)
		}
	}

	return sb.String()
}
