// Command leakscan finds hardcoded secrets in source code.
//
//	leakscan scan [flags] <dir>   scan a directory (CI gate / pre-commit)
//	leakscan serve [flags]        run the HTTP API and web UI
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hsynkmk/leakscan/internal/api"
	"github.com/hsynkmk/leakscan/internal/detect"
	"github.com/hsynkmk/leakscan/internal/report"
	"github.com/hsynkmk/leakscan/internal/scan"
	"github.com/hsynkmk/leakscan/internal/ui"
)

// Exit codes, so CI can tell "found secrets" apart from "the scan itself failed".
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stderr)
	case "version":
		fmt.Fprintln(stdout, "leakscan", report.Version)
		return exitOK
	default:
		usage(stderr)
		return exitError
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  leakscan scan [--format text|json|sarif] [--fail-on low|medium|high|critical] [--workers N] <dir>
  leakscan serve [--addr :8080] [--allow-hosts github.com,gitlab.com]
  leakscan version`)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json or sarif")
	failOn := fs.String("fail-on", "low", "exit 1 if a finding has at least this severity")
	workers := fs.Int("workers", 0, "concurrent workers (default: number of CPUs)")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum scan duration")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		usage(stderr)
		return exitError
	}
	threshold, ok := detect.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "invalid --fail-on %q\n", *failOn)
		return exitError
	}
	root := fs.Arg(0)
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "not a directory: %s\n", root)
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	det := detect.New()
	started := time.Now()
	res, err := scan.Dir(ctx, root, det, scan.Options{Workers: *workers})
	if err != nil {
		fmt.Fprintln(stderr, "scan failed:", err)
		return exitError
	}
	rep := report.New(root, started, res)

	switch *format {
	case "text":
		err = report.WriteText(stdout, rep)
	case "json":
		err = report.WriteJSON(stdout, rep)
	case "sarif":
		err = report.WriteSARIF(stdout, rep, det.Rules())
	default:
		fmt.Fprintf(stderr, "invalid --format %q\n", *format)
		return exitError
	}
	if err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return exitError
	}

	// Fail closed: an incomplete scan is an error, never a silent pass.
	if rep.Incomplete {
		return exitError
	}
	for _, f := range rep.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			return exitFindings
		}
	}
	return exitOK
}

func runServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddr(), "listen address (default :$PORT or :8080)")
	hosts := fs.String("allow-hosts", "github.com,gitlab.com", "comma-separated hosts that may be cloned")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	srv := api.New(api.Config{
		AllowedHosts: splitList(*hosts),
		Static:       ui.FS(),
		Logger:       logger,
	}, detect.New())

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      3 * time.Minute, // a scan can take a while
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *addr)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			return exitError
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown", "err", err)
			return exitError
		}
	}
	return exitOK
}

// defaultAddr honors $PORT, which hosting platforms (Render, Cloud Run, Koyeb) set.
func defaultAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return ":8080"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
