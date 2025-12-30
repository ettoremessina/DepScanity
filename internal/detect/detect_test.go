package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectStacks(t *testing.T) {
	// Create a temp directory structure
	tmpDir, err := os.MkdirTemp("", "depscanity_detect_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create files
	files := []string{
		"root.sln",
		"backend/app.csproj",
		"frontend/package-lock.json",
		"Dockerfile",
		"deploy/compose.yml",
		"node_modules/ignored-package/package.json", // Should be ignored
		".git/config",    // Should be ignored
		"bin/output.dll", // Should be ignored
		"nested/node_modules/stuff/package-lock.json", // Should be ignored
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		err := os.MkdirAll(filepath.Dir(path), 0755)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := DetectStacks(tmpDir)
	if err != nil {
		t.Fatalf("DetectStacks failed: %v", err)
	}

	// Verify Dotnet
	if len(res.Dotnet) != 2 {
		t.Errorf("expected 2 dotnet files, got %d", len(res.Dotnet))
	}
	// Verify Npm
	if len(res.Npm) != 1 {
		t.Errorf("expected 1 npm file, got %d", len(res.Npm))
	}
	// Verify Docker
	if len(res.Docker) != 2 {
		t.Errorf("expected 2 docker files, got %d", len(res.Docker))
	}

	// Check ignored paths specifically
	for _, path := range res.Npm {
		if filepath.Base(filepath.Dir(path)) == "ignored-package" {
			t.Error("found file in node_modules that should be ignored")
		}
	}
}
