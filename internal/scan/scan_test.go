package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hsynkmk/leakscan/internal/demo"
	"github.com/hsynkmk/leakscan/internal/detect"
)

func TestDirFindsDemoSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := demo.WriteRepo(dir); err != nil {
		t.Fatal(err)
	}

	res, err := Dir(context.Background(), dir, detect.New(), Options{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]int{
		"aws-access-key-id": 1,
		"generic-secret":    1,
		"gitlab-pat":        1,
		"github-token":      1, // deploy.sh only: client.ts is ignored inline, node_modules is skipped
		"slack-token":       1,
		"jwt":               1,
		"private-key":       1,
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID]++
		if filepath.Base(f.File) == "index.js" || filepath.Ext(f.File) == ".bin" {
			t.Errorf("file should have been skipped: %s", f.File)
		}
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("rule %s: got %d findings, want %d (all: %v)", rule, got[rule], n, got)
		}
	}
	if len(res.Findings) != 7 {
		t.Errorf("total findings = %d, want 7", len(res.Findings))
	}
	if res.FilesSkipped != 1 { // the binary file; node_modules is never walked
		t.Errorf("files skipped = %d, want 1", res.FilesSkipped)
	}
	if res.Incomplete() {
		t.Errorf("unexpected errors: %+v", res.Errors)
	}
	// Most severe first.
	if res.Findings[0].Severity != detect.Critical {
		t.Errorf("first finding should be critical, got %s", res.Findings[0].Severity)
	}
}

func TestDirDeduplicates(t *testing.T) {
	dir := t.TempDir()
	content := "a = " + demo.AWSKey + "\nb = " + demo.AWSKey + "\n" // same secret twice in one file
	if err := os.WriteFile(filepath.Join(dir, "x.env"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Dir(context.Background(), dir, detect.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 deduplicated finding, got %d", len(res.Findings))
	}
}

func TestDirSkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, 2048)
	copy(big, "k = "+demo.AWSKey)
	for i := len(demo.AWSKey) + 4; i < len(big); i++ {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Dir(context.Background(), dir, detect.New(), Options{MaxFileSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkipped != 1 || len(res.Findings) != 0 {
		t.Fatalf("large file should be skipped: %+v", res)
	}
}

func TestDirCancelled(t *testing.T) {
	dir := t.TempDir()
	if err := demo.WriteRepo(dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: must return an error, not a "clean" result
	if _, err := Dir(ctx, dir, detect.New(), Options{}); err == nil {
		t.Fatal("expected an error for a cancelled scan")
	}
}

func TestDirMissingRoot(t *testing.T) {
	if _, err := Dir(context.Background(), filepath.Join(t.TempDir(), "nope"), detect.New(), Options{}); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}
