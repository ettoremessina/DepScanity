package model

// Finding represents a normalized security finding.
type Finding struct {
	Source           string         `json:"Source"`
	Ecosystem        string         `json:"Ecosystem"`
	Package          string         `json:"Package"`
	InstalledVersion string         `json:"InstalledVersion"`
	FixedVersion     *string        `json:"FixedVersion"`
	VulnerabilityID  string         `json:"VulnerabilityID"`
	Severity         Severity       `json:"Severity"`
	Title            *string        `json:"Title"`
	URL              *string        `json:"URL"`
	Location         string         `json:"Location"`
	Metadata         map[string]any `json:"Metadata"`
}
