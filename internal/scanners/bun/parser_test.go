package bun

import (
	"testing"

	"depscanity/internal/model"
)

func TestParseBunOutput_MapFormat(t *testing.T) {
	// Sample output reflecting the map[string][]Advisory format
	jsonOutput := `{
		"elysia": [
			{
				"id": 1111308,
				"url": "https://github.com/advisories/GHSA-8vch-m3f4-q8jf",
				"title": "Elysia affected by arbitrary code injection through cookie config",
				"severity": "high",
				"vulnerable_versions": "<1.4.18"
			},
			{
				"id": "GHSA-hxj9-33pp-j2cc",
				"url": "https://github.com/advisories/GHSA-hxj9-33pp-j2cc",
				"title": "Elysia vulnerable to prototype pollution",
				"severity": "critical",
				"vulnerable_versions": ">=1.4.0 <1.4.17"
			}
		],
		"esbuild": [
			{
				"id": 1102341,
				"url": "https://github.com/advisories/GHSA-67mh-4wv8-2f99",
				"title": "esbuild enables any website to send any requests",
				"severity": "moderate",
				"vulnerable_versions": "<=0.24.2"
			}
		]
	}`

	findings, err := ParseBunOutput(jsonOutput, "bun.lock")
	if err != nil {
		t.Fatalf("ParseBunOutput failed: %v", err)
	}

	if len(findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings))
	}

	// Verify findings
	foundCritical := false
	foundHigh := false
	foundModerate := false

	for _, f := range findings {
		if f.Package == "elysia" && f.Severity == model.SeverityCritical {
			foundCritical = true
			if f.VulnerabilityID != "GHSA-hxj9-33pp-j2cc" {
				t.Errorf("Expected VulnID GHSA-hxj9-33pp-j2cc, got %s", f.VulnerabilityID)
			}
		}
		if f.Package == "elysia" && f.Severity == model.SeverityHigh {
			foundHigh = true
			// Check ID extraction from URL for numeric ID case
			if f.VulnerabilityID != "GHSA-8vch-m3f4-q8jf" {
				t.Errorf("Expected VulnID GHSA-8vch-m3f4-q8jf (from URL), got %s", f.VulnerabilityID)
			}
		}
		if f.Package == "esbuild" && f.Severity == model.SeverityMedium { // moderate -> medium
			foundModerate = true
		}
	}

	if !foundCritical {
		t.Error("Did not find expected Critical finding for elysia")
	}
	if !foundHigh {
		t.Error("Did not find expected High finding for elysia")
	}
	if !foundModerate {
		t.Error("Did not find expected Moderate (Medium) finding for esbuild")
	}
}

func TestParseBunOutput_NoFindings(t *testing.T) {
	jsonOutput := `
	No vulnerabilities found
	`
	// Or empty map
	jsonOutput2 := `{}`

	findings, err := ParseBunOutput(jsonOutput, "bun.lock")
	if err != nil {
		// It might not error if we handle the text check, or it might error if strict json.
		// Our parser checks `strings.Contains(jsonOutput, "No vulnerabilities found")`
	} else if len(findings) != 0 {
		t.Errorf("Expected 0 findings for 'No vulnerabilities found', got %d", len(findings))
	}

	findings2, err2 := ParseBunOutput(jsonOutput2, "bun.lock")
	if err2 != nil {
		t.Fatalf("Failed to parse empty map: %v", err2)
	}
	if len(findings2) != 0 {
		t.Errorf("Expected 0 findings for empty map, got %d", len(findings2))
	}
}
