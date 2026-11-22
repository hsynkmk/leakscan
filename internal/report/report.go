// Package report renders scan results as text, JSON or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hsynkmk/leakscan/internal/detect"
	"github.com/hsynkmk/leakscan/internal/scan"
	"github.com/hsynkmk/leakscan/internal/score"
)

// Version is the tool version reported in outputs.
const Version = "0.1.0"

// Report is the full, JSON-serializable result of one scan.
type Report struct {
	Tool         string           `json:"tool"`
	Version      string           `json:"version"`
	Target       string           `json:"target"`
	StartedAt    time.Time        `json:"started_at"`
	DurationMs   int64            `json:"duration_ms"`
	FilesScanned int              `json:"files_scanned"`
	FilesSkipped int              `json:"files_skipped"`
	Incomplete   bool             `json:"incomplete"`
	Score        score.Score      `json:"score"`
	Findings     []detect.Finding `json:"findings"`
	Errors       []scan.FileError `json:"errors"`
}

// New builds a Report from a scan result.
func New(target string, started time.Time, res scan.Result) Report {
	findings := res.Findings
	if findings == nil {
		findings = []detect.Finding{} // encode as [] rather than null
	}
	errs := res.Errors
	if errs == nil {
		errs = []scan.FileError{}
	}
	return Report{
		Tool:         "leakscan",
		Version:      Version,
		Target:       target,
		StartedAt:    started.UTC(),
		DurationMs:   res.Duration.Milliseconds(),
		FilesScanned: res.FilesScanned,
		FilesSkipped: res.FilesSkipped,
		Incomplete:   res.Incomplete(),
		Score:        score.Compute(res.Findings),
		Findings:     findings,
		Errors:       errs,
	}
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable summary, most severe findings first.
func WriteText(w io.Writer, r Report) error {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%-9s %-18s %s:%d:%d  %s\n",
			strings.ToUpper(string(f.Severity)), f.RuleID, f.File, f.Line, f.Column, f.Masked)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "ERROR     could not scan %s: %s\n", e.File, e.Error)
	}
	if len(r.Findings) > 0 || len(r.Errors) > 0 {
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%d findings in %d files (%d skipped) in %dms\n",
		len(r.Findings), r.FilesScanned, r.FilesSkipped, r.DurationMs)
	fmt.Fprintf(&b, "Score: %d/100  Grade: %s", r.Score.Value, r.Score.Grade)
	if r.Score.Capped {
		fmt.Fprintf(&b, "  (%s)", r.Score.Reason)
	}
	b.WriteString("\n")
	if r.Incomplete {
		b.WriteString("WARNING: scan incomplete, some files could not be read\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
