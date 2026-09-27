package buildinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionMatchesRepositoryMetadata(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate buildinfo test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	versionBytes, err := os.ReadFile(filepath.Join(repositoryRoot, "VERSION"))
	if err != nil {
		t.Fatal("read root VERSION")
	}
	version := strings.TrimSpace(string(versionBytes))
	if version == "" || version != Version {
		t.Fatalf("root VERSION = %q, buildinfo.Version = %q", version, Version)
	}
	for _, path := range []string{
		".agents/plugins/cicada/plugin.json",
		".agents/plugins/cicada/.codex-plugin/plugin.json",
	} {
		data, err := os.ReadFile(filepath.Join(repositoryRoot, path))
		if err != nil {
			t.Fatalf("read %s", path)
		}
		var metadata struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &metadata); err != nil {
			t.Fatalf("parse %s", path)
		}
		if metadata.Version != version {
			t.Errorf("%s version = %q, root VERSION = %q", path, metadata.Version, version)
		}
	}
}

func TestCurrentProvenanceLeavesManualBuildUnknown(t *testing.T) {
	previousRevision, previousDirty, previousFingerprint := Revision, Dirty, SourceFingerprint
	t.Cleanup(func() {
		Revision, Dirty, SourceFingerprint = previousRevision, previousDirty, previousFingerprint
	})
	Revision, Dirty, SourceFingerprint = "unknown", "unknown", "unknown"

	got := CurrentProvenance()
	if got.Revision != "unknown" || got.Dirty != nil || got.SourceFingerprint != "unknown" {
		t.Fatalf("manual build provenance = %#v, want explicit unknown fields", got)
	}
}

func TestCurrentProvenanceUsesEmbeddedMetadata(t *testing.T) {
	previousRevision, previousDirty, previousFingerprint := Revision, Dirty, SourceFingerprint
	t.Cleanup(func() {
		Revision, Dirty, SourceFingerprint = previousRevision, previousDirty, previousFingerprint
	})
	Revision, Dirty, SourceFingerprint = "7c0efc4df6209785df4fc4694792ff5c9163141a", "true", "sha256:source"

	got := CurrentProvenance()
	if got.Revision != Revision || got.Dirty == nil || !*got.Dirty || got.SourceFingerprint != SourceFingerprint {
		t.Fatalf("embedded provenance = %#v", got)
	}

	Dirty = "false"
	got = CurrentProvenance()
	if got.Dirty == nil || *got.Dirty {
		t.Fatalf("clean embedded provenance = %#v", got)
	}
}
