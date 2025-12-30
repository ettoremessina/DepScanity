package npm

import (
	"os"
	"path/filepath"
	"testing"

	"depscanity/internal/model"
)

func TestParseNpmAudit_Modern(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "npm_audit_modern.json"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseNpmAudit(string(data), "/path/to/package-lock.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	} else {
		f := findings[0]
		if f.Package != "minimist" {
			t.Errorf("expected package minimist, got %s", f.Package)
		}
		if f.Severity != model.SeverityLow {
			t.Errorf("expected severity low, got %s", f.Severity)
		}
		if f.VulnerabilityID != "NPM-1084" {
			t.Errorf("expected vuln ID NPM-1084, got %s", f.VulnerabilityID)
		}
		if f.FixedVersion == nil || *f.FixedVersion != "1.2.5" {
			t.Errorf("expected fixed version 1.2.5, got %v", f.FixedVersion)
		}
		if f.Title == nil || *f.Title != "Prototype Pollution" {
			t.Errorf("incorrect title: %v", f.Title)
		}
	}
}

func TestParseNpmAudit_Mixed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "npm_audit_via_mixed.json"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseNpmAudit(string(data), "lock")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should have 1 finding for bar-pkg (direct advisory) and 1 for foo-pkg (transitive)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}

	var foo, bar model.Finding
	for _, f := range findings {
		if f.Package == "foo-pkg" {
			foo = f
		} else if f.Package == "bar-pkg" {
			bar = f
		}
	}

	if foo.VulnerabilityID != "Transitive-bar-pkg" {
		t.Errorf("expected foo vuln ID Transitive-bar-pkg, got %s", foo.VulnerabilityID)
	}

	if bar.VulnerabilityID != "NPM-9999" {
		t.Errorf("expected bar vuln ID NPM-9999, got %s", bar.VulnerabilityID)
	}
}
