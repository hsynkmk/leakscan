package detect

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strings"
)

// IgnoreMarker on a line suppresses findings on that line (an explicit,
// reviewable decision in the code, instead of a silent global exclusion).
const IgnoreMarker = "leakscan:ignore"

// maxLineLength bounds memory per line; minified files can have huge lines.
const maxLineLength = 1 << 20

// Finding is one detected secret. The plaintext secret is never stored.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Masked      string   `json:"masked"`
	Fingerprint string   `json:"fingerprint"`
}

// placeholders are values that look like secrets but are documentation or test data.
var placeholders = []string{"example", "changeme", "placeholder", "dummy", "xxxxxxxx", "your_", "your-", "<", "${", "{{"}

// dummyValues are whole values commonly used in docs and tests, e.g. https://user:pass@host.
var dummyValues = map[string]bool{"pass": true, "password": true, "passwd": true, "secret": true, "token": true, "test": true}

// Detector applies a rule set to text. It is safe for concurrent use:
// it holds no mutable state and regexp.Regexp is goroutine-safe.
type Detector struct {
	rules []Rule
}

// New returns a Detector with the given rules, or the default rules if none are given.
func New(rules ...Rule) *Detector {
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	return &Detector{rules: rules}
}

// Rules returns the active rule set.
func (d *Detector) Rules() []Rule { return d.rules }

// Scan reads r line by line and returns all findings for the given file name.
func (d *Detector) Scan(file string, r io.Reader) ([]Finding, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineLength)

	var out []Finding
	for lineNo := 1; sc.Scan(); lineNo++ {
		out = append(out, d.ScanLine(file, lineNo, sc.Text())...)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("read %s: %w", file, err)
	}
	return out, nil
}

// ScanLine checks a single line against every rule.
func (d *Detector) ScanLine(file string, lineNo int, line string) []Finding {
	if strings.Contains(line, IgnoreMarker) {
		return nil
	}
	var out []Finding
	for _, rule := range d.rules {
		if rule.Context != nil && !rule.Context.MatchString(line) {
			continue
		}
		for _, m := range rule.Pattern.FindAllStringSubmatchIndex(line, -1) {
			start, end := m[2*rule.SecretGroup], m[2*rule.SecretGroup+1]
			if start < 0 {
				continue
			}
			secret := line[start:end]
			if isPlaceholder(secret) {
				continue
			}
			if rule.MinEntropy > 0 && ShannonEntropy(secret) < rule.MinEntropy {
				continue
			}
			out = append(out, Finding{
				RuleID:      rule.ID,
				Description: rule.Description,
				Severity:    rule.Severity,
				File:        file,
				Line:        lineNo,
				Column:      start + 1,
				Masked:      Mask(secret),
				Fingerprint: Fingerprint(rule.ID, file, secret),
			})
		}
	}
	return out
}

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	if dummyValues[lower] {
		return true
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// Mask hides a secret so it is safe to print, log and store.
// Only the first 4 characters (usually the token type prefix) are kept.
func Mask(secret string) string {
	if len(secret) <= 8 {
		return "********"
	}
	return secret[:4] + strings.Repeat("*", 8)
}

// Fingerprint is a stable identifier for a finding. It deliberately excludes the
// line number: when code above moves, the same secret keeps the same fingerprint,
// so deduplication and triage decisions survive. The secret is hashed, never kept.
func Fingerprint(ruleID, file, secret string) string {
	secretHash := sha256.Sum256([]byte(secret))
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0}) // separator: avoids ambiguity between fields
	h.Write([]byte(file))
	h.Write([]byte{0})
	h.Write(secretHash[:])
	return hex.EncodeToString(h.Sum(nil))
}

// ShannonEntropy returns the entropy of s in bits per character.
// Random tokens score high (~4–6); words and repeated characters score low.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
