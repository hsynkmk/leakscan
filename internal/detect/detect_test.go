package detect

import (
	"strings"
	"testing"

	"github.com/hsynkmk/leakscan/internal/demo"
)

func TestScanLine(t *testing.T) {
	d := New()
	tests := []struct {
		name     string
		line     string
		wantRule string // "" means no finding expected
	}{
		{"aws key", "aws_key = " + demo.AWSKey, "aws-access-key-id"},
		{"github token", "token: " + demo.GitHubToken, "github-token"},
		{"gitlab token", "export T=" + demo.GitLabToken, "gitlab-pat"},
		{"slack token", `SLACK="` + demo.SlackToken + `"`, "slack-token"},
		{"jwt", `const s = "` + demo.JWT + `"`, "jwt"},
		{"private key", demo.KeyHeader, "private-key"},
		{"generic password", `password: "` + demo.DBPassword + `"`, "generic-secret"},
		{"prefixed name", `db_password = "` + demo.DBPassword + `"`, "generic-secret"},
		// Regression: ADO.NET connection string hardcoded in C# (missed by the first version).
		{"connection string pwd", `new SqlConnection("data source=x.example.org;user id=app;pwd=` + demo.ConnPwd + `;initial catalog=Db")`, "connection-string-password"},
		{"connection string Password", `"Default": "Server=db;Database=Shop;User Id=sa;Password=` + demo.ConnPwd + `;"`, "connection-string-password"},
		{"url credentials", "DATABASE_URL=postgres://app:" + demo.URLPassword + "@db:5432/app", "url-credentials"},

		// False-positive controls.
		{"placeholder", `password = "changeme123"`, ""},
		{"documentation example", "AKIA" + "IOSFODNN7" + "EXAMPLE", ""},
		{"low entropy", `api_key = "aaaaaaaaaaaa"`, ""},
		{"too short", `password = "abc"`, ""},
		{"template variable", `password = "${DB_PASSWORD}"`, ""},
		{"inline ignore", "t = " + demo.GitHubToken + " // leakscan:ignore", ""},
		{"plain code", "for i := 0; i < n; i++ {", ""},
		{"pwd outside a connection string", "pwd=/home/user/project", ""},
		{"connection string from env", `"Server=db;User Id=sa;Password=${DB_PASSWORD};"`, ""},
		{"url without credentials", "https://github.com/owner/repo", ""},
		{"url with username only", "ssh://git@github.com/owner/repo", ""},
		{"url with dummy password", "https://user:pass@github.com/owner/repo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.ScanLine("f.txt", 1, tt.line)
			if tt.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("expected no finding, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
			}
			if got[0].RuleID != tt.wantRule {
				t.Errorf("rule = %q, want %q", got[0].RuleID, tt.wantRule)
			}
		})
	}
}

func TestFindingNeverContainsSecret(t *testing.T) {
	d := New()
	for _, secret := range []string{demo.AWSKey, demo.GitHubToken, demo.GitLabToken, demo.SlackToken, demo.JWT} {
		for _, f := range d.ScanLine("f.txt", 1, "x = "+secret) {
			if strings.Contains(f.Masked, secret) || strings.Contains(f.Fingerprint, secret) {
				t.Errorf("finding leaks the secret: %+v", f)
			}
		}
	}
}

func TestFingerprintIgnoresLineNumber(t *testing.T) {
	d := New()
	line := "key = " + demo.AWSKey
	a := d.ScanLine("app.env", 3, line)
	b := d.ScanLine("app.env", 40, line) // same secret, code moved down
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected one finding each, got %d and %d", len(a), len(b))
	}
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Error("fingerprint changed when only the line number changed")
	}
	if c := d.ScanLine("other.env", 3, line); c[0].Fingerprint == a[0].Fingerprint {
		t.Error("fingerprint should differ for a different file")
	}
}

func TestColumn(t *testing.T) {
	got := New().ScanLine("f", 1, "key="+demo.AWSKey)
	if len(got) != 1 || got[0].Column != 5 {
		t.Fatalf("want column 5, got %+v", got)
	}
}

func TestMask(t *testing.T) {
	tests := map[string]string{
		"":             "********",
		"short":        "********",
		"ghp_abcdefgh": "ghp_********",
	}
	for in, want := range tests {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Errorf("empty: got %v", got)
	}
	if got := ShannonEntropy("aaaaaaaa"); got != 0 {
		t.Errorf("repeated char: got %v, want 0", got)
	}
	if got := ShannonEntropy("abcd"); got != 2 {
		t.Errorf("4 distinct chars: got %v, want 2", got)
	}
	if got := ShannonEntropy(demo.GitHubToken); got < 4 {
		t.Errorf("random token should have high entropy, got %v", got)
	}
}

func TestScanReader(t *testing.T) {
	text := "line one\nkey = " + demo.AWSKey + "\nline three\n"
	got, err := New().Scan("cfg", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 2 {
		t.Fatalf("want one finding on line 2, got %+v", got)
	}
}

func TestParseSeverity(t *testing.T) {
	if s, ok := ParseSeverity("high"); !ok || s != High {
		t.Errorf("high: got %v %v", s, ok)
	}
	if _, ok := ParseSeverity("severe"); ok {
		t.Error("unknown severity should be rejected")
	}
}

// FuzzScanLine checks that arbitrary input never panics and never leaks a full secret.
func FuzzScanLine(f *testing.F) {
	f.Add("password = \"" + demo.DBPassword + "\"")
	f.Add(demo.KeyHeader)
	f.Add("")
	d := New()
	f.Fuzz(func(t *testing.T, line string) {
		for _, fd := range d.ScanLine("fuzz", 1, line) {
			if len(fd.Masked) > 12 {
				t.Fatalf("masked value too long: %q", fd.Masked)
			}
		}
	})
}
