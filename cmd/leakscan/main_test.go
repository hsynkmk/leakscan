package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hsynkmk/leakscan/internal/demo"
)

func TestScanExitCodes(t *testing.T) {
	dirty := t.TempDir()
	if err := demo.WriteRepo(dirty); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean repo passes", []string{"scan", clean}, exitOK},
		{"secrets fail the build", []string{"scan", dirty}, exitFindings},
		{"threshold above all findings passes", []string{"scan", "--fail-on", "critical", clean}, exitOK},
		{"json format", []string{"scan", "--format", "json", dirty}, exitFindings},
		{"sarif format", []string{"scan", "--format", "sarif", dirty}, exitFindings},
		{"missing dir is an error", []string{"scan", filepath.Join(clean, "nope")}, exitError},
		{"bad severity", []string{"scan", "--fail-on", "severe", clean}, exitError},
		{"bad format", []string{"scan", "--format", "xml", clean}, exitError},
		{"no args", nil, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tt.args, &out, &errOut); got != tt.want {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tt.want, out.String(), errOut.String())
			}
		})
	}
}

func TestScanOutputIsMasked(t *testing.T) {
	dir := t.TempDir()
	if err := demo.WriteRepo(dir); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	run([]string{"scan", "--format", "json", dir}, &out, &errOut)
	for _, secret := range []string{demo.AWSKey, demo.GitHubToken, demo.SlackToken, demo.DBPassword} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("output contains a plaintext secret")
		}
	}
}
