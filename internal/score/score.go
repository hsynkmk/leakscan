// Package score turns findings into an explainable 0–100 score and an A–F grade.
package score

import "github.com/hsynkmk/leakscan/internal/detect"

// weights is the penalty per finding. One critical costs more than many lows,
// because a single live credential is already an incident.
var weights = map[detect.Severity]int{
	detect.Critical: 25,
	detect.High:     10,
	detect.Medium:   4,
	detect.Low:      1,
}

// Contribution explains how much one severity level lowered the score.
type Contribution struct {
	Severity detect.Severity `json:"severity"`
	Count    int             `json:"count"`
	Weight   int             `json:"weight"`
	Penalty  int             `json:"penalty"`
}

// Score is the result. Every lost point traces back to a Contribution.
type Score struct {
	Value     int            `json:"value"`
	Grade     string         `json:"grade"`
	Capped    bool           `json:"capped"`
	Reason    string         `json:"reason,omitempty"`
	Breakdown []Contribution `json:"breakdown"`
}

// Compute scores a set of findings.
func Compute(findings []detect.Finding) Score {
	counts := map[detect.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	s := Score{Breakdown: []Contribution{}}
	penalty := 0
	for _, sev := range []detect.Severity{detect.Critical, detect.High, detect.Medium, detect.Low} {
		if counts[sev] == 0 {
			continue
		}
		p := counts[sev] * weights[sev]
		penalty += p
		s.Breakdown = append(s.Breakdown, Contribution{Severity: sev, Count: counts[sev], Weight: weights[sev], Penalty: p})
	}

	s.Value = 100 - min(100, penalty)
	s.Grade = grade(s.Value)

	// Hard cap: any critical finding limits the grade to D, however few there are.
	if counts[detect.Critical] > 0 && s.Grade < "D" {
		s.Grade = "D"
		s.Capped = true
		s.Reason = "critical findings cap the grade at D"
	}
	return s
}

func grade(v int) string {
	switch {
	case v >= 90:
		return "A"
	case v >= 75:
		return "B"
	case v >= 60:
		return "C"
	case v >= 40:
		return "D"
	default:
		return "F"
	}
}
