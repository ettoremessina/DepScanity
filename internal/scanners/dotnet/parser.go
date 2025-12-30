package dotnet

import (
	"bufio"
	"regexp"
	"strings"

	"depscanity/internal/model"
)

var (
	severityKeywords = []string{"Critical", "High", "Moderate", "Medium", "Low"}
	urlRegex         = regexp.MustCompile(`https?://[^\s>]+`)
)

func ParseDotnetOutput(output string, sourcePath string) ([]model.Finding, error) {
	var findings []model.Finding
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Regex for strict severity detection (word boundary)
	sevRegex := regexp.MustCompile(`(?i)\b(Critical|High|Moderate|Medium|Low)\b`)

	var lastPkg, lastVer string

	for scanner.Scan() {
		line := scanner.Text()
		lineLower := strings.ToLower(line)

		// 1. Skip known header/noise lines
		if strings.Contains(lineLower, "the following") ||
			strings.Contains(lineLower, "top-level package") ||
			strings.Contains(lineLower, "transitive package") ||
			strings.Contains(lineLower, "project `") {
			continue
		}

		// 2. Find severity
		sevMatch := sevRegex.FindString(line)
		if sevMatch == "" {
			continue
		}

		// Map severity
		var sev model.Severity
		if strings.EqualFold(sevMatch, "moderate") {
			sev = model.SeverityMedium
		} else {
			s, err := model.ParseSeverity(sevMatch)
			if err != nil {
				continue // Should not happen due to regex
			}
			sev = s
		}

		// 3. Tokenize
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		var currentPkg, currentVer string
		isContinuation := false

		// Check if line starts with severity (Continuation)
		// e.g. "High https://..." -> parts[0] == "High"
		if strings.EqualFold(parts[0], sevMatch) {
			isContinuation = true
		} else if parts[0] == ">" && len(parts) >= 3 {
			// New package line: > Package Version ...
			// Identify where severity is to locate package/version
			// But simpler: parts[1] is package.
			// Version is usually parts[2], but could be Requested/Resolved.
			// Transitive: > Pkg Resolved Sev ... (Sev is at index 3)
			// Top-level: > Pkg Requested Resolved Sev ... (Sev is at index 4)

			currentPkg = parts[1]

			// Heuristic for version: finding the token BEFORE severity
			// Locate severity token index
			sevIdx := -1
			for i, p := range parts {
				if strings.EqualFold(p, sevMatch) {
					sevIdx = i
					break
				}
			}

			if sevIdx > 1 {
				// The token immediately before severity is likely the resolved version
				currentVer = parts[sevIdx-1]
			} else {
				// Fallback
				currentVer = parts[2]
			}
		} else {
			// Unrecognized line format containing severity (maybe header?)
			continue
		}

		if !isContinuation {
			lastPkg = currentPkg
			lastVer = currentVer
		} else {
			if lastPkg == "" {
				continue // Orphan continuation, skip
			}
			currentPkg = lastPkg
			currentVer = lastVer
		}

		// URL detection
		url := urlRegex.FindString(line)
		vulnID := "dotnet-advisory"
		if url != "" {
			vulnID = url
		}

		f := model.Finding{
			Source:           "dotnet",
			Ecosystem:        "nuget",
			Package:          currentPkg,
			InstalledVersion: currentVer,
			VulnerabilityID:  vulnID,
			Severity:         sev,
			Location:         sourcePath,
			Metadata: map[string]any{
				"raw_line": line,
			},
		}
		if url != "" {
			f.URL = &url
		}

		findings = append(findings, f)
	}

	return findings, nil
}
