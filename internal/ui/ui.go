// Package ui embeds the built Vue frontend into the Go binary.
// `npm run build` in web/ writes into ./dist; until then only .gitkeep is embedded.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var files embed.FS

// FS returns the frontend files rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err) // cannot happen: "dist" is embedded at compile time
	}
	return sub
}
