// Package api exposes scanning over HTTP and serves the embedded web UI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hsynkmk/leakscan/internal/demo"
	"github.com/hsynkmk/leakscan/internal/detect"
	"github.com/hsynkmk/leakscan/internal/gitsrc"
	"github.com/hsynkmk/leakscan/internal/report"
	"github.com/hsynkmk/leakscan/internal/scan"
)

// Config configures the server.
type Config struct {
	AllowedHosts []string      // hosts that may be cloned, e.g. gitlab.com
	ScanTimeout  time.Duration // upper bound for clone + scan
	MaxParallel  int           // concurrent scans; extra requests get 429
	ScanOptions  scan.Options
	Static       fs.FS // built frontend; may be empty
	Logger       *slog.Logger
}

// Server handles HTTP requests.
type Server struct {
	cfg   Config
	det   *detect.Detector
	slots chan struct{} // semaphore limiting concurrent scans
}

// New creates a Server.
func New(cfg Config, det *detect.Detector) *Server {
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = 2 * time.Minute
	}
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 2
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, det: det, slots: make(chan struct{}, cfg.MaxParallel)}
}

// Handler returns the HTTP handler with all routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/rules", s.rules)
	mux.HandleFunc("POST /api/scans", s.createScan)
	if s.cfg.Static != nil {
		mux.Handle("GET /", http.FileServerFS(s.cfg.Static))
	}
	return s.recoverer(securityHeaders(s.logRequests(mux)))
}

type scanRequest struct {
	RepoURL string `json:"repo_url"`
	Demo    bool   `json:"demo"`
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // a scan request is tiny
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req scanRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Demo == (req.RepoURL != "") {
		writeError(w, http.StatusBadRequest, `provide either "repo_url" or "demo": true`)
		return
	}
	if req.RepoURL != "" {
		if _, err := gitsrc.ValidateURL(req.RepoURL, s.cfg.AllowedHosts); err != nil {
			writeError(w, http.StatusBadRequest, err.Error()) // validation messages are safe to show
			return
		}
	}

	// Bounded concurrency: scans are expensive, so refuse instead of queueing forever.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many scans in progress, try again shortly")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout)
	defer cancel()

	dir, target, cleanup, err := s.prepare(ctx, req)
	if err != nil {
		s.cfg.Logger.Error("prepare scan", "err", err)
		writeError(w, http.StatusUnprocessableEntity, "could not fetch the repository")
		return
	}
	defer cleanup()

	started := time.Now()
	res, err := scan.Dir(ctx, dir, s.det, s.cfg.ScanOptions)
	if err != nil {
		s.cfg.Logger.Error("scan", "err", err, "target", target)
		writeError(w, http.StatusInternalServerError, "scan failed") // details stay in the logs
		return
	}
	writeJSON(w, http.StatusOK, report.New(target, started, res))
}

// prepare returns a directory to scan: a fresh clone or a generated demo repository.
func (s *Server) prepare(ctx context.Context, req scanRequest) (dir, target string, cleanup func(), err error) {
	if req.Demo {
		tmp, err := os.MkdirTemp("", "leakscan-demo-*")
		if err != nil {
			return "", "", nil, err
		}
		cleanup = func() { os.RemoveAll(tmp) }
		if err := demo.WriteRepo(tmp); err != nil {
			cleanup()
			return "", "", nil, err
		}
		return tmp, "demo repository", cleanup, nil
	}
	dir, cleanup, err = gitsrc.Clone(ctx, req.RepoURL, s.cfg.AllowedHosts)
	return dir, req.RepoURL, cleanup, err
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": report.Version})
}

func (s *Server) rules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.det.Rules())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// securityHeaders sets defensive browser headers. The CSP only allows our own
// scripts, which limits the impact of any injected markup.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.cfg.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start))
	})
}

// recoverer turns a panic in a handler into a 500 instead of crashing the server.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				s.cfg.Logger.Error("panic", "value", v, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
