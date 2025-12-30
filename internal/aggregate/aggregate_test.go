package aggregate

import (
	"testing"

	"depscanity/internal/model"
)

func TestAggregateFindings(t *testing.T) {
	f1 := model.Finding{
		Source:           "npm",
		Ecosystem:        "npm",
		Package:          "pkg A",
		InstalledVersion: "1.0.0",
		VulnerabilityID:  "CVE-2023-0001",
		Severity:         model.SeverityHigh,
	}
	f2 := f1 // Duplicate

	f3 := model.Finding{
		Source:           "npm",
		Ecosystem:        "npm",
		Package:          "pkg B",
		InstalledVersion: "2.0.0",
		VulnerabilityID:  "CVE-2023-0002",
		Severity:         model.SeverityCritical,
	}

	f4 := model.Finding{
		Source:           "npm",
		Ecosystem:        "npm",
		Package:          "pkg C",
		InstalledVersion: "3.0.0",
		VulnerabilityID:  "CVE-2023-0003",
		Severity:         model.SeverityLow,
	}

	input := []model.Finding{f1, f4, f2, f3}
	result := AggregateFindings(input)

	if len(result) != 3 {
		t.Errorf("expected 3 findings after dedup, got %d", len(result))
	}

	// Check Order: Critical -> High -> Low
	if result[0].Severity != model.SeverityCritical {
		t.Errorf("expected first finding to be Critical, got %s", result[0].Severity)
	}
	if result[1].Severity != model.SeverityHigh {
		t.Errorf("expected second finding to be High, got %s", result[1].Severity)
	}
	if result[2].Severity != model.SeverityLow {
		t.Errorf("expected third finding to be Low, got %s", result[2].Severity)
	}
}
