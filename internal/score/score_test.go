package score

import (
	"testing"

	"github.com/hsynkmk/leakscan/internal/detect"
)

func findings(sevs ...detect.Severity) []detect.Finding {
	out := make([]detect.Finding, len(sevs))
	for i, s := range sevs {
		out[i] = detect.Finding{Severity: s}
	}
	return out
}

func TestCompute(t *testing.T) {
	tests := []struct {
		name       string
		in         []detect.Finding
		wantValue  int
		wantGrade  string
		wantCapped bool
	}{
		{"clean", nil, 100, "A", false},
		{"one low", findings(detect.Low), 99, "A", false},
		{"two highs", findings(detect.High, detect.High), 80, "B", false},
		{"one critical is capped", findings(detect.Critical), 75, "D", true},
		{"many lows", findings(detect.Low, detect.Low, detect.Low, detect.Low, detect.Medium), 92, "A", false},
		{"floor at zero", findings(detect.Critical, detect.Critical, detect.Critical, detect.Critical, detect.Critical), 0, "F", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compute(tt.in)
			if got.Value != tt.wantValue || got.Grade != tt.wantGrade || got.Capped != tt.wantCapped {
				t.Errorf("got %d/%s capped=%v, want %d/%s capped=%v",
					got.Value, got.Grade, got.Capped, tt.wantValue, tt.wantGrade, tt.wantCapped)
			}
		})
	}
}

func TestBreakdownExplainsScore(t *testing.T) {
	s := Compute(findings(detect.Critical, detect.High, detect.High, detect.Low))
	total := 0
	for _, c := range s.Breakdown {
		total += c.Penalty
	}
	if 100-total != s.Value {
		t.Errorf("breakdown penalties (%d) do not explain the score %d", total, s.Value)
	}
	if s.Breakdown[0].Severity != detect.Critical {
		t.Errorf("breakdown should list the most severe level first")
	}
}
