package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hsynkmk/leakscan/internal/detect"
	"github.com/hsynkmk/leakscan/internal/scan"
)

func sampleReport() Report {
	res := scan.Result{
		FilesScanned: 3,
		Findings: []detect.Finding{{
			RuleID: "github-token", Description: "GitHub token", Severity: detect.Critical,
			File: "deploy.sh", Line: 2, Column: 8, Masked: "ghp_********", Fingerprint: "abc123",
		}},
	}
	return New("repo", time.Unix(0, 0), res)
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleReport(), detect.DefaultRules()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: %+v", log)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != len(detect.DefaultRules()) {
		t.Errorf("rules = %d, want %d", len(run.Tool.Driver.Rules), len(detect.DefaultRules()))
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	r := run.Results[0]
	if r.Level != "error" || r.Locations[0].PhysicalLocation.Region.StartLine != 2 ||
		r.PartialFingerprints["leakscanFingerprint/v1"] != "abc123" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestJSONEncodesEmptyListsAsArrays(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, New("repo", time.Now(), scan.Result{})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) || !strings.Contains(buf.String(), `"errors": []`) {
		t.Errorf("empty lists should be [], got:\n%s", buf.String())
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"CRITICAL", "deploy.sh:2:8", "ghp_********", "Grade: D"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}
