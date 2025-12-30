package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"depscanity/internal/model"
)

func TestParseTrivyOutput(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "trivy_output.json"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseTrivyOutput(string(data))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.VulnerabilityID != "CVE-2021-36159" {
		t.Errorf("expected CVE-2021-36159, got %s", f1.VulnerabilityID)
	}
	if f1.Severity != model.SeverityCritical {
		t.Errorf("expected Critical, got %s", f1.Severity)
	}
	if f1.FixedVersion == nil || *f1.FixedVersion != "2.33.2" {
		t.Errorf("expected fixed version 2.33.2")
	}
	if f1.URL == nil || *f1.URL != "https://avd.aquasec.com/nvd/cve-2021-36159" {
		t.Errorf("expected URL check failed")
	}

	f2 := findings[1]
	if f2.VulnerabilityID != "CVE-2021-9999" {
		t.Errorf("expected CVE-2021-9999, got %s", f2.VulnerabilityID)
	}
	if f2.Severity != model.SeverityMedium {
		t.Errorf("expected Medium, got %s", f2.Severity)
	}
	if f2.URL == nil || *f2.URL != "http://example.com" {
		t.Errorf("expected fallback URL check failed")
	}
}
