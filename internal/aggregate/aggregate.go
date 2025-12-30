package aggregate

import (
	"fmt"
	"sort"

	"depscanity/internal/model"
)

// AggregateFindings deduplicates and sorts findings.
func AggregateFindings(findings []model.Finding) []model.Finding {
	unique := make(map[string]model.Finding)

	for _, f := range findings {
		key := dedupeKey(f)
		if _, exists := unique[key]; !exists {
			unique[key] = f
		} else {
			// If duplicate exists, we could merge metadata, but for now just skip
		}
	}

	result := make([]model.Finding, 0, len(unique))
	for _, f := range unique {
		result = append(result, f)
	}

	// Sort
	sort.Slice(result, func(i, j int) bool {
		fi, fj := result[i], result[j]

		// Severity DESC (Critical > High ...)
		ri := fi.Severity.Rank()
		rj := fj.Severity.Rank()
		if ri != rj {
			return ri > rj
		}

		// Source ASC
		if fi.Source != fj.Source {
			return fi.Source < fj.Source
		}

		// Ecosystem ASC
		if fi.Ecosystem != fj.Ecosystem {
			return fi.Ecosystem < fj.Ecosystem
		}

		// Package ASC
		if fi.Package != fj.Package {
			return fi.Package < fj.Package
		}

		// VulnerabilityID ASC
		return fi.VulnerabilityID < fj.VulnerabilityID
	})

	return result
}

func dedupeKey(f model.Finding) string {
	// source|ecosystem|package|version|vulnID|severity
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		f.Source, f.Ecosystem, f.Package, f.InstalledVersion, f.VulnerabilityID, f.Severity)
}
