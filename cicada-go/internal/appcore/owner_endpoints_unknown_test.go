package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (a *ownerEndpointActor) parkAction() Action {
	return Action{Kind: ActionParkOwnerEndpoints, OwnerEndpoints: OwnerEndpointReadAction{ReviewID: a.node.c.Snapshot().OwnerEndpoints.ParkReviewID, ConfirmPark: true}}
}

func TestOwnerEndpointsParkOnlyExpiredReadonlyOriginalAndFencesStaleGesture(t *testing.T) {
	a := newOwnerEndpointActor(t)
	c := a.node.c
	a.fault = "drop"
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || !c.hasOwnerEndpointPending() {
		t.Fatal("fixture did not retain read")
	}
	original, proof := bytes.Clone(c.node.Pending.Request), bytes.Clone(c.node.Pending.OwnerEndpointRead.OwnerProof)
	version := c.nodeVer
	live := Action{Kind: ActionParkOwnerEndpoints, OwnerEndpoints: OwnerEndpointReadAction{ReviewID: c.ownerEndpointParkReviewID(), ConfirmPark: true}}
	if live.OwnerEndpoints.ReviewID == "" || c.Dispatch(context.Background(), live) == nil || c.nodeVer != version || c.Snapshot().OwnerEndpoints.ParkReviewID != "" {
		t.Fatal("live proof was parked")
	}
	if end := parseExpiry(c.Snapshot().OwnerEndpoints.ParkAfter); end.IsZero() {
		t.Fatal("pending proof lost its redraw deadline")
	} else {
		a.node.n2.now = end.Add(-time.Nanosecond)
		if c.Snapshot().OwnerEndpoints.ParkReviewID != "" || containsAction(c.Snapshot().AvailableActions, ActionParkOwnerEndpoints) {
			t.Fatal("local retention appeared before proof expiry")
		}
		a.node.n2.now = end
	}
	stale := a.parkAction()
	if stale.OwnerEndpoints.ReviewID == "" {
		t.Fatal("expired readonly original not reviewable")
	}
	if !containsAction(c.Snapshot().AvailableActions, ActionParkOwnerEndpoints) || c.nodeVer != version || len(a.posts) != 1 {
		t.Fatal("clock-only read expiry did not expose local retention without I/O")
	}
	wrong := stale
	wrong.OwnerEndpoints.ReviewID = "synthetic_wrong_original"
	if c.Dispatch(context.Background(), wrong) == nil || c.nodeVer != version || len(c.node.OwnerDirectoryUnknown) != 0 {
		t.Fatal("changed gesture disposed of original")
	}
	operation := c.node.Pending.Operation
	c.node.Pending.Operation = wire.OperationAppNodeComplete
	if c.Dispatch(context.Background(), stale) == nil || c.node.Pending == nil || len(c.node.OwnerDirectoryUnknown) != 0 {
		t.Fatal("local park accepted a mutating operation")
	}
	c.node.Pending.Operation = operation
	if err := c.Dispatch(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if c.node.Pending != nil || len(c.node.OwnerDirectoryUnknown) != 1 || len(a.posts) != 1 {
		t.Fatal("local retention used network or kept active slot")
	}
	r := c.node.OwnerDirectoryUnknown[0]
	if r.Outcome != "UNKNOWN" || r.Original.Applied || !bytes.Equal(r.Original.Request, original) || !bytes.Equal(r.Original.OwnerEndpointRead.OwnerProof, proof) || c.Snapshot().Management == ManagementAuthorized {
		t.Fatal("local retention rewrote or falsely settled the original")
	}
	a.fault = "drop"
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || !c.hasOwnerEndpointPending() {
		t.Fatal("fresh independent read not created")
	}
	second := bytes.Clone(c.node.Pending.Request)
	a.node.n2.now = a.node.n2.now.Add(61 * time.Second)
	if c.Dispatch(context.Background(), stale) == nil || !bytes.Equal(c.node.Pending.Request, second) || len(c.node.OwnerDirectoryUnknown) != 1 {
		t.Fatal("old click parked a later original")
	}
}

func TestOwnerEndpointsParkCASFailurePreservesPendingAndHistory(t *testing.T) {
	a := newOwnerEndpointActor(t)
	c := a.node.c
	a.fault = "drop"
	if c.Dispatch(context.Background(), a.readAction(false)) == nil {
		t.Fatal("fixture response was not lost")
	}
	a.node.n2.now = a.node.n2.now.Add(61 * time.Second)
	action := a.parkAction()
	path, err := scopeVaultPath(a.node.root, cardScope(c.connection))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, packet := c.node.Pending, bytes.Clone(c.node.Pending.Request)
	c.nodeVer++ // An actual failed vault CAS; no product fault hook.
	if c.Dispatch(context.Background(), action) == nil || c.node.Pending != pending || !bytes.Equal(c.node.Pending.Request, packet) || len(c.node.OwnerDirectoryUnknown) != 0 || len(a.posts) != 1 {
		t.Fatal("failed CAS changed original/history or sent traffic")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed CAS changed encrypted vault", err)
	}
}

func TestOwnerEndpointsUnknownHistoryIsBoundedAndRestoresOriginalEpochs(t *testing.T) {
	a := newOwnerEndpointActor(t)
	c := a.node.c
	for attempt := 0; attempt < ownerEndpointUnknownMax; attempt++ {
		action := a.readAction(false)
		if action.OwnerEndpoints.ReviewID == "" {
			break
		}
		a.fault = "drop"
		if c.Dispatch(context.Background(), action) == nil {
			t.Fatal("fixture response was not lost")
		}
		if !c.hasOwnerEndpointPending() {
			if c.ownerEndpointError != "APP_OWNER_DIRECTORY_HISTORY_FULL" {
				t.Fatal("new request failed for another reason")
			}
			break
		}
		a.node.n2.now = a.node.n2.now.Add(61 * time.Second)
		if err := c.Dispatch(context.Background(), a.parkAction()); err != nil {
			t.Fatal(err)
		}
	}
	count := len(c.node.OwnerDirectoryUnknown)
	if count < 1 || count > ownerEndpointUnknownMax || c.node.Pending != nil {
		t.Fatal("history count or slot is invalid")
	}
	raw, err := json.Marshal(c.node.OwnerDirectoryUnknown)
	if err != nil || len(raw) > ownerEndpointUnknownMaxBytes {
		t.Fatal("history exceeds byte bound")
	}
	for i, entry := range c.node.OwnerDirectoryUnknown {
		if !bytes.Equal(entry.Original.Request, a.posts[i]) || entry.Outcome != "UNKNOWN" || entry.Original.Applied {
			t.Fatal("unknown original was evicted/settled/rewritten")
		}
	}
	version, posts := c.nodeVer, len(a.posts)
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || c.nodeVer != version || len(a.posts) != posts {
		t.Fatal("full history allowed a new original/write")
	}
	if !containsAction(c.Snapshot().AvailableActions, ActionRefreshNode) {
		t.Fatal("retained readonly history blocked independent Node operations")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	a.node.c = a.node.n2.controller(t, a.node.root).(*nativeController)
	a.node.c.cfg.HTTP = a
	c = a.node.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("profile lost")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	restored, err := json.Marshal(c.node.OwnerDirectoryUnknown)
	if err != nil || !bytes.Equal(raw, restored) {
		t.Fatal("restart rewrote original proof/session epochs or history")
	}
	if c.Snapshot().OwnerEndpoints.RetainedUnknown != 0 || len(c.Snapshot().OwnerEndpoints.Endpoints) != 0 || c.Snapshot().OwnerEndpoints.NodeID != "" {
		t.Fatal("logged-out view exposed retained history or Node")
	}
}
