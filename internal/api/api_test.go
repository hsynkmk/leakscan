package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hsynkmk/leakscan/internal/demo"
	"github.com/hsynkmk/leakscan/internal/detect"
	"github.com/hsynkmk/leakscan/internal/report"
)

func newTestServer() *httptest.Server {
	srv := New(Config{
		AllowedHosts: []string{"gitlab.com"},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, detect.New())
	return httptest.NewServer(srv.Handler())
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url+"/api/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestHealth(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing")
	}
}

func TestDemoScan(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := post(t, ts.URL, `{"demo": true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var rep report.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 || rep.Score.Grade == "A" {
		t.Errorf("demo scan should find secrets, got %d findings, grade %s", len(rep.Findings), rep.Score.Grade)
	}
	// The API response must never contain a plaintext secret.
	for _, secret := range []string{demo.AWSKey, demo.GitHubToken, demo.GitLabToken, demo.DBPassword} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("response leaks a plaintext secret")
		}
	}
}

func TestScanRejectsBadRequests(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	tests := map[string]string{
		"invalid json":      `{`,
		"unknown field":     `{"demo": true, "admin": true}`,
		"neither option":    `{}`,
		"both options":      `{"demo": true, "repo_url": "https://gitlab.com/a/b"}`,
		"host not allowed":  `{"repo_url": "https://169.254.169.254/latest"}`,
		"file transport":    `{"repo_url": "file:///etc/passwd"}`,
		"oversized payload": `{"repo_url": "https://gitlab.com/` + strings.Repeat("a", 5000) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if resp := post(t, ts.URL, body); resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestRules(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/rules")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rules []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(detect.DefaultRules()) {
		t.Errorf("rules = %d, want %d", len(rules), len(detect.DefaultRules()))
	}
}
