package buildinfo

import "testing"

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
