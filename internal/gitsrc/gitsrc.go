// Package gitsrc safely clones a remote repository so it can be scanned.
//
// A repository URL is attacker-controlled input, so it is validated against an
// allowlist and passed to git as a separate argument, never through a shell.
package gitsrc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrInvalidURL is returned for URLs that are not allowed to be cloned.
var ErrInvalidURL = errors.New("invalid repository url")

// ValidateURL accepts only https URLs on an allowlisted host, without credentials.
// This blocks command/option injection, SSRF to internal hosts, and dangerous git
// transports such as file:// and ext::.
func ValidateURL(raw string, allowedHosts []string) (*url.URL, error) {
	if strings.HasPrefix(raw, "-") {
		return nil, fmt.Errorf("%w: must not start with '-'", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: only https is allowed", ErrInvalidURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials in url are not allowed", ErrInvalidURL)
	}
	host := strings.ToLower(u.Hostname())
	allowed := false
	for _, h := range allowedHosts {
		if host == strings.ToLower(h) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("%w: host %q is not allowed", ErrInvalidURL, host)
	}
	if u.Port() != "" || strings.Trim(u.Path, "/") == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: expected https://host/owner/repo", ErrInvalidURL)
	}
	return u, nil
}

// Clone makes a shallow clone of rawURL into a new temporary directory.
// The caller must call cleanup when done, even if scanning fails.
func Clone(ctx context.Context, rawURL string, allowedHosts []string) (dir string, cleanup func(), err error) {
	u, err := ValidateURL(rawURL, allowedHosts)
	if err != nil {
		return "", nil, err
	}

	tmp, err := os.MkdirTemp("", "leakscan-*") // unique per scan: no collisions between parallel scans
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(tmp) }
	dir = filepath.Join(tmp, "repo")

	// No shell: every argument is passed separately. "--" ends option parsing.
	// protocol.allow=never + https.allow=always forbids file://, ext:: and other transports.
	cmd := exec.CommandContext(ctx, "git",
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"clone", "--depth", "1", "--single-branch", "--no-tags",
		"--", u.String(), dir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never hang waiting for a password

	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone failed: %w: %s", err, truncate(string(out), 300))
	}
	return dir, cleanup, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
