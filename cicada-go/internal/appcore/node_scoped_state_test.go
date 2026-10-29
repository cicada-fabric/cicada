package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"reflect"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/appvault"
)

func TestScopedOriginalFrameRoundTripAndRejectsEmbeddedBody(t *testing.T) {
	p := &scopedOriginal{Format: scopedFrameFormat, NodeID: "SYNTHETIC-frame", Body: []byte(`{"synthetic":"body"}`), Packet: []byte("SYNTHETIC exact request"), Response: []byte("SYNTHETIC exact response")}
	raw, err := encodeScopedOriginal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeScopedOriginal(raw)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("persisted frame cannot restore exact original", err)
	}
	h := scopedFrameHeader{Original: *p, BodyBytes: len(p.Body), PacketBytes: len(p.Packet), ResponseBytes: len(p.Response)}
	h.Original.Packet, h.Original.Response = nil, nil
	bad, err := encodeThreadGroupFrame("CNS1", h, p.Body, p.Packet, p.Response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeScopedOriginal(bad); err == nil {
		t.Fatal("embedded header body accepted")
	}
	if !bytes.Equal(got.Packet, p.Packet) || !bytes.Equal(got.Response, p.Response) {
		t.Fatal("frame changed exact packets")
	}
}

func TestScopedNodeNamespaceRetainsFullDigestAndFitsExistingVault(t *testing.T) {
	f := newNodeActorFixture(t)
	ids := []string{"SYNTHETIC-Node-A", "SYNTHETIC-Node-B", "SYNTHETIC-电脑-甲"}
	seen := map[string]bool{}
	for _, id := range ids {
		name := scopedNodeNamespace(id)
		if len(name) > 64 || seen[name] {
			t.Fatal("namespace bound/collision")
		}
		seen[name] = true
		digest, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(name, "app.ns."), ".v1")))
		want := sha256.Sum256([]byte(id))
		if err != nil || string(digest) != string(want[:]) {
			t.Fatal("namespace truncated/changed digest")
		}
		v, err := f.c.vault.CompareAndSwapState(name, 0, []byte("SYNTHETIC local scope marker"))
		if err != nil {
			t.Fatal("real vault rejected Node namespace", err)
		}
		raw, loaded, found, err := f.c.vault.LoadState(name)
		if err != nil || !found || loaded != v || string(raw) != "SYNTHETIC local scope marker" {
			t.Fatal("Node namespace did not round trip")
		}
	}
}

func TestScopedWorkspaceTombstonesRetainCASGenerationAfterColdLoad(t *testing.T) {
	f := newNodeActorFixture(t)
	if err := f.c.ensureScopedNodesLoaded(); err != nil {
		t.Fatal(err)
	}
	for _, name := range scopedWorkspaces {
		if _, err := f.c.vault.CompareAndSwapState(name, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	f.c.clearScopedRuntime()
	if err := f.c.ensureScopedNodesLoaded(); err != nil {
		t.Fatal(err)
	}
	if f.c.scopedPending() || f.c.scopedBusy() {
		t.Fatal("empty tombstone became pending")
	}
	for i, v := range f.c.scoped.versions {
		if v != 1 {
			t.Fatal("cold load reset CAS generation", i, v)
		}
	}
	if err := f.c.persistScopedFrame(scopedOriginalSlot, nil); err != nil {
		t.Fatal(err)
	}
	if f.c.scoped.versions[scopedOriginalSlot] != 2 {
		t.Fatal("tombstone overwrite lost CAS generation")
	}
}

func TestScopedMissingSelectedRecordNeverFallsBackToLegacyBinding(t *testing.T) {
	f := newNodeActorFixture(t)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	legacy := f.c.nodeConfirmation.Binding.NodeID
	f.c.node.Targets = f.c.localTargets()
	f.c.node.Targets.Nodes = append(f.c.node.Targets.Nodes, savedNodeReference{NodeID: "SYNTHETIC-missing-scoped", ScopeVersion: 2})
	f.c.node.Targets.SelectedNodeID = "SYNTHETIC-missing-scoped"
	if f.c.selectedNodeBinding() != nil {
		t.Fatal("missing scoped selection borrowed legacy binding", legacy)
	}
	if err := f.c.validateLegacyTargetSelection(); err != appvault.ErrScopeMismatch {
		t.Fatal("missing selected record accepted", err)
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &NodeStatusTarget{NodeID: legacy}}); err == nil {
		t.Fatal("automatic read used legacy authority under missing scoped selection")
	}
}
