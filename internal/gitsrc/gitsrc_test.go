package gitsrc

import (
	"errors"
	"testing"
)

func TestValidateURL(t *testing.T) {
	allowed := []string{"gitlab.com", "github.com"}
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{"https gitlab", "https://gitlab.com/group/project.git", true},
		{"https github", "https://github.com/owner/repo", true},
		{"host is case-insensitive", "https://GitHub.com/owner/repo", true},

		{"plain http", "http://github.com/owner/repo", false},
		{"ssh", "ssh://git@github.com/owner/repo", false},
		{"file transport", "file:///etc/passwd", false},
		{"ext transport", "ext::sh -c touch% /tmp/pwned", false},
		{"option injection", "--upload-pack=touch /tmp/pwned", false},
		{"host not allowed (SSRF)", "https://169.254.169.254/latest/meta-data", false},
		{"internal host", "https://gitlab.internal.corp/x/y", false},
		{"lookalike host", "https://github.com.evil.io/owner/repo", false},
		{"credentials in url", "https://user:pass@github.com/owner/repo", false},
		{"custom port", "https://github.com:8443/owner/repo", false},
		{"no path", "https://github.com", false},
		{"query string", "https://github.com/owner/repo?x=1", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateURL(tt.url, allowed)
			if tt.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !errors.Is(err, ErrInvalidURL) {
					t.Fatalf("error should wrap ErrInvalidURL, got %v", err)
				}
			}
		})
	}
}
