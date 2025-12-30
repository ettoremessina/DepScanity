package detect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DetectionResult struct {
	Dotnet []string
	Npm    []string
	Bun    []string
	Docker []string
}

// Ignored directories (exact match on folder name)
var ignoredDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"bin":          {},
	"obj":          {},
	".venv":        {},
	"venv":         {},
}

// DetectStacks scans the root directory for relevant files.
// It skips ignored directories and returns sorted absolute paths.
func DetectStacks(root string) (DetectionResult, error) {
	var res DetectionResult
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return res, err
	}

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Handle directory skipping
		if info.IsDir() {
			if _, ok := ignoredDirs[info.Name()]; ok {
				return filepath.SkipDir
			}
			return nil
		}

		// File detection
		filename := strings.ToLower(info.Name())
		// Dotnet: *.sln, *.csproj
		if strings.HasSuffix(filename, ".sln") || strings.HasSuffix(filename, ".csproj") {
			res.Dotnet = append(res.Dotnet, path)
		}

		// Npm: package-lock.json (exact match, though we use lower for case-insensitive check)
		if filename == "package-lock.json" {
			res.Npm = append(res.Npm, path)
		}

		// Bun: bun.lock (exact match)
		if filename == "bun.lock" {
			res.Bun = append(res.Bun, path)
		}

		// Docker: Dockerfile, docker-compose.yml|yaml, compose.yml|yaml
		if filename == "dockerfile" ||
			filename == "docker-compose.yml" || filename == "docker-compose.yaml" ||
			filename == "compose.yml" || filename == "compose.yaml" {
			res.Docker = append(res.Docker, path)
		}

		return nil
	})

	if err != nil {
		return res, err
	}

	// Ensure deterministic order
	sort.Strings(res.Dotnet)
	sort.Strings(res.Npm)
	sort.Strings(res.Bun)
	sort.Strings(res.Docker)

	return res, nil
}
