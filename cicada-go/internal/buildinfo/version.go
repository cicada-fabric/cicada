// Package buildinfo contains the public Cicada release identity shared by the
// CLI, HTTP API, and Codex app-server adapter.
package buildinfo

// Version is the current software release label. Keep it in one package so
// health responses and app-server client metadata cannot silently drift apart.
// It is a variable so scripts/build-release.sh can embed a selected tag with
// the Go linker; source builds use VERSION's current development line.
var Version = "0.1.0-dev"

const Stage = "codex-supervisor"

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
