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

// These values are set by the repository Docker build helper. A binary built
// directly with `go build` keeps the explicit unknown values rather than
// implying that its source revision is known.
var (
	Revision          = "unknown"
	Dirty             = "unknown"
	SourceFingerprint = "unknown"
)

// Provenance is the source identity embedded in a Cicada binary. Dirty is
// nil when the binary was built without provenance metadata.
type Provenance struct {
	Revision          string `json:"revision"`
	Dirty             *bool  `json:"dirty"`
	SourceFingerprint string `json:"source_fingerprint"`
}

func CurrentProvenance() Provenance {
	result := Provenance{Revision: Revision, SourceFingerprint: SourceFingerprint}
	switch Dirty {
	case "true":
		dirty := true
		result.Dirty = &dirty
	case "false":
		dirty := false
		result.Dirty = &dirty
	}
	return result
}
