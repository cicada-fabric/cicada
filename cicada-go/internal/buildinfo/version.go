// Package buildinfo contains the public Cicada release identity shared by the
// CLI, HTTP API, and Codex app-server adapter.
package buildinfo

const (
	// Version is the current protocol-compatible Cicada release. Keep this in
	// one package so health responses and app-server client metadata cannot
	// silently drift apart.
	Version = "0.4.0-dev"
	Stage   = "codex-supervisor"
)
