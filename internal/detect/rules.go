// Package detect finds hardcoded secrets in text, line by line.
package detect

import "regexp"

// Severity of a finding. Ordered from least to most severe.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Rank orders severities so findings can be sorted and thresholds compared.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a user-supplied string into a Severity.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(s)
	return sev, sev.Rank() > 0
}

// Rule describes one kind of secret.
type Rule struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Severity    Severity       `json:"severity"`
	Pattern     *regexp.Regexp `json:"-"`
	// SecretGroup is the capture group that holds the secret itself (0 = whole match).
	SecretGroup int `json:"-"`
	// MinEntropy rejects low-randomness matches like "password = aaaaaaaa".
	// 0 disables the check. Used for generic rules that would otherwise be noisy.
	MinEntropy float64 `json:"-"`
}

// DefaultRules returns the built-in rule set. Specific, high-confidence rules
// come first; the generic assignment rule is entropy-gated to limit false positives.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "aws-access-key-id",
			Description: "AWS access key ID",
			Severity:    Critical,
			Pattern:     regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
			SecretGroup: 1,
		},
		{
			ID:          "github-token",
			Description: "GitHub personal access or app token",
			Severity:    Critical,
			Pattern:     regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`),
			SecretGroup: 1,
		},
		{
			ID:          "gitlab-pat",
			Description: "GitLab personal access token",
			Severity:    Critical,
			Pattern:     regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,})`),
			SecretGroup: 1,
		},
		{
			ID:          "private-key",
			Description: "Private key block",
			Severity:    Critical,
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`),
		},
		{
			ID:          "slack-token",
			Description: "Slack token",
			Severity:    High,
			Pattern:     regexp.MustCompile(`\b(xox[abprs]-[A-Za-z0-9-]{10,})\b`),
			SecretGroup: 1,
		},
		{
			ID:          "jwt",
			Description: "JSON Web Token",
			Severity:    Medium,
			Pattern:     regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
			SecretGroup: 1,
		},
		{
			ID:          "generic-secret",
			Description: "Hardcoded password or secret assignment",
			Severity:    High,
			Pattern: regexp.MustCompile(
				`(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[\w-]*["']?\s*[:=]\s*["']([^"'\s]{8,})["']`),
			SecretGroup: 1,
			MinEntropy:  3.0,
		},
	}
}
