package dotnet

import (
	"os"
	"path/filepath"
	"testing"

	"depscanity/internal/model"
)

func TestParseDotnetOutput_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dotnet_output_simple.txt"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseDotnetOutput(string(data), "test.sln")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	} else {
		f := findings[0]
		if f.Package != "Newtonsoft.Json" {
			t.Errorf("expected package Newtonsoft.Json, got %s", f.Package)
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("expected severity High, got %s", f.Severity)
		}
		if f.InstalledVersion != "12.0.1" {
			t.Errorf("expected version 12.0.1, got %s", f.InstalledVersion)
		}
	}
}

func TestParseDotnetOutput_Mixed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dotnet_output_mixed_severity.txt"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseDotnetOutput(string(data), "test.sln")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}

	severities := make(map[model.Severity]int)
	for _, f := range findings {
		severities[f.Severity]++
	}

	if severities[model.SeverityCritical] != 1 {
		t.Error("expected 1 Critical")
	}
	if severities[model.SeverityMedium] != 1 { // Moderate -> Medium
		t.Error("expected 1 Medium (from Moderate)")
	}
	if severities[model.SeverityLow] != 1 {
		t.Error("expected 1 Low")
	}
}
