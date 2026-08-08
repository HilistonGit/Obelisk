// Package web carries Obelisk's browser interface.
//
// The files are embedded into the binary rather than installed alongside it, so
// that deploying Obelisk stays a matter of copying one executable — on a router
// there is no web server to configure and no document root to get wrong.
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html app.js style.css
var files embed.FS

// FS returns the interface's static files.
func FS() fs.FS { return files }
