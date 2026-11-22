package report

import (
	"encoding/json"
	"io"

	"github.com/hsynkmk/leakscan/internal/detect"
)

// SARIF 2.1.0 is the standard interchange format for static analysis results.
// GitLab, GitHub code scanning and DefectDojo can all ingest it, which is how a
// platform normalizes the output of many different scanners into one model.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string       `json:"id"`
	ShortDescription     sarifMessage `json:"shortDescription"`
	DefaultConfiguration sarifConfig  `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// sarifLevel maps our severities onto SARIF's three result levels.
func sarifLevel(s detect.Severity) string {
	switch s {
	case detect.Critical, detect.High:
		return "error"
	case detect.Medium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes the findings as a SARIF 2.1.0 log.
func WriteSARIF(w io.Writer, r Report, rules []detect.Rule) error {
	driver := sarifDriver{
		Name:           "leakscan",
		Version:        Version,
		InformationURI: "https://github.com/hsynkmk/leakscan",
	}
	for _, rule := range rules {
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   rule.ID,
			ShortDescription:     sarifMessage{Text: rule.Description},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(rule.Severity)},
		})
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Description + ": " + f.Masked},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Column},
			}}},
			PartialFingerprints: map[string]string{"leakscanFingerprint/v1": f.Fingerprint},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
