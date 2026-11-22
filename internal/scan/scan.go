// Package scan walks a directory and runs the detector over every file
// using a bounded pool of worker goroutines.
package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/hsynkmk/leakscan/internal/detect"
)

// skipDirs are never scanned: VCS metadata and third-party dependencies.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "__pycache__": true,
}

// Options configures a scan.
type Options struct {
	Workers     int   // concurrent file readers; defaults to the number of CPUs
	MaxFileSize int64 // larger files are skipped; defaults to 1 MiB
}

// FileError records a file that could not be scanned. A scan with file errors
// is reported as incomplete: an unreadable file must never look "clean".
type FileError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// Result is the outcome of scanning one directory.
type Result struct {
	FilesScanned int              `json:"files_scanned"`
	FilesSkipped int              `json:"files_skipped"`
	Findings     []detect.Finding `json:"findings"`
	Errors       []FileError      `json:"errors"`
	Duration     time.Duration    `json:"-"`
}

// Incomplete reports whether some files could not be scanned.
func (r Result) Incomplete() bool { return len(r.Errors) > 0 }

type fileResult struct {
	path     string
	findings []detect.Finding
	skipped  bool
	err      error
}

// Dir scans every regular file under root.
//
// Pipeline: one producer goroutine walks the tree and sends paths on `jobs`;
// N workers read and scan files and send on `results`; this goroutine collects.
// Cancelling ctx stops the walk and the workers.
func Dir(ctx context.Context, root string, det *detect.Detector, opts Options) (Result, error) {
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 1 << 20
	}
	start := time.Now()

	jobs := make(chan string)
	results := make(chan fileResult)

	// Producer: walk the tree. Only the producer closes jobs.
	var walkErr error
	go func() {
		defer close(jobs)
		walkErr = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			// Only regular files: never follow symlinks out of the repository.
			if !d.Type().IsRegular() {
				return nil
			}
			select {
			case jobs <- path:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()

	// Workers: bounded concurrency.
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				res := scanFile(root, path, det, opts.MaxFileSize)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Close results once every worker has finished, so the collector loop ends.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collector: the only goroutine touching these variables, so no mutex is needed.
	var out Result
	seen := make(map[string]struct{})
	for res := range results {
		switch {
		case res.err != nil:
			out.Errors = append(out.Errors, FileError{File: res.path, Error: res.err.Error()})
		case res.skipped:
			out.FilesSkipped++
		default:
			out.FilesScanned++
			for _, f := range res.findings {
				if _, dup := seen[f.Fingerprint]; dup {
					continue
				}
				seen[f.Fingerprint] = struct{}{}
				out.Findings = append(out.Findings, f)
			}
		}
	}

	// results is closed only after all workers exited, and workers exit only after
	// jobs is closed or ctx is done, so walkErr is safe to read here.
	if err := ctx.Err(); err != nil {
		return out, fmt.Errorf("scan cancelled: %w", err)
	}
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", root, walkErr)
	}

	sortFindings(out.Findings)
	sort.Slice(out.Errors, func(i, j int) bool { return out.Errors[i].File < out.Errors[j].File })
	out.Duration = time.Since(start)
	return out, nil
}

// scanFile reads one file and returns its findings, or marks it skipped.
func scanFile(root, path string, det *detect.Detector, maxSize int64) fileResult {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)

	f, err := os.Open(path)
	if err != nil {
		return fileResult{path: rel, err: err}
	}
	defer f.Close()

	// Read at most maxSize+1 bytes, so an oversized file is detected without
	// reading it fully into memory.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return fileResult{path: rel, err: err}
	}
	if int64(len(data)) > maxSize || isBinary(data) {
		return fileResult{path: rel, skipped: true}
	}

	findings, err := det.Scan(rel, bytes.NewReader(data))
	if err != nil {
		return fileResult{path: rel, err: err}
	}
	return fileResult{path: rel, findings: findings}
}

// isBinary uses the same heuristic as git: a NUL byte in the first 8000 bytes.
func isBinary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0
}

// sortFindings orders by severity (most severe first), then file and line,
// so output is deterministic and the most important findings come first.
func sortFindings(fs []detect.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}
