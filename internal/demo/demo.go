// Package demo builds a small fake repository full of fake secrets.
//
// The secrets are generated at runtime instead of being written as literals,
// so this repository itself contains no secret-looking strings: it passes its
// own scan and GitHub/GitLab push protection.
package demo

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// fake returns a deterministic pseudo-random string of length n drawn from alphabet.
func fake(seed uint32, n int, alphabet string) string {
	var b strings.Builder
	x := seed
	for i := 0; i < n; i++ {
		x = x*1664525 + 1013904223 // linear congruential generator
		b.WriteByte(alphabet[int(x>>24)%len(alphabet)])
	}
	return b.String()
}

// Fake credential values, assembled from a prefix plus generated characters.
var (
	AWSKey      = "AK" + "IA" + fake(1, 16, upperDigits)
	GitHubToken = "gh" + "p_" + fake(2, 36, alnum)
	GitLabToken = "gl" + "pat-" + fake(3, 20, alnum)
	SlackToken  = "xo" + "xb-" + fake(4, 24, alnum)
	JWT         = "ey" + "J" + fake(5, 20, alnum) + ".ey" + "J" + fake(6, 24, alnum) + "." + fake(7, 32, alnum)
	DBPassword  = fake(8, 18, alnum+"!#%")
	ConnPwd     = fake(10, 12, alnum)
	URLPassword = fake(11, 16, alnum)
	KeyHeader   = "-----BEGIN " + "RSA PRIVATE KEY-----"
)

// Files returns the fake repository as path -> content.
func Files() map[string]string {
	return map[string]string{
		"config/settings.yaml": strings.Join([]string{
			"database:",
			"  host: db.internal",
			`  password: "` + DBPassword + `"`,
			"aws:",
			"  access_key_id: " + AWSKey,
			"",
		}, "\n"),
		"scripts/deploy.sh": strings.Join([]string{
			"#!/bin/sh",
			"export GITLAB_TOKEN=" + GitLabToken,
			`curl -H "Authorization: token ` + GitHubToken + `" https://api.github.com/user`,
			"",
		}, "\n"),
		"src/notify.py": strings.Join([]string{
			"import requests",
			`SLACK = "` + SlackToken + `"`,
			`password = "changeme123"  # placeholder: must NOT be reported`,
			`api_key = "aaaaaaaaaaaa"   # low entropy: must NOT be reported`,
			"",
		}, "\n"),
		"src/client.ts": strings.Join([]string{
			`const session = "` + JWT + `"`,
			`const reviewed = "` + GitHubToken + `" // leakscan:ignore  (test fixture, reviewed)`,
			"",
		}, "\n"),
		"src/Data/Db.cs": strings.Join([]string{
			"public static class Db {",
			`    public static SqlConnection Conn = new SqlConnection("data source=sql.internal;user id=app;pwd=` + ConnPwd + `;initial catalog=Shop");`,
			"}",
			"",
		}, "\n"),
		"docker-compose.yml": strings.Join([]string{
			"services:",
			"  api:",
			"    environment:",
			"      DATABASE_URL: postgres://app:" + URLPassword + "@db:5432/app",
			"",
		}, "\n"),
		"keys/deploy_key": KeyHeader + "\n" + fake(9, 64, alnum) + "\n",
		"README.md":       "# Demo service\nNothing secret here.\n",
		// Skipped by the scanner: dependency folder and binary file.
		"node_modules/lib/index.js": "const t = \"" + GitHubToken + "\"\n",
		"assets/logo.bin":           "PNG\x00\x01\x02" + AWSKey,
	}
}

// WriteRepo writes the fake repository into dir.
func WriteRepo(dir string) error {
	for name, content := range Files() {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
