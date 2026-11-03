package appcore

import (
	"bytes"
	"context"
	"testing"
)

func TestCurrentPairingRejectsLegacyEnrollmentWithoutPOST(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	owner, device, counters := c.owner.Public().ID, c.device.Public().ID, c.node.Client
	pending, scoped, pairing, posts := c.node.Pending, c.scoped.original, c.node.PairTrust, len(f.requests)
	for _, a := range []Action{
		{Kind: ActionReviewNodePairing, DevicePairingCode: f.code},
		{Kind: ActionPreviewNode, NodeCode: f.n.code},
		{Kind: ActionApproveNode, ConfirmNodeIdentity: true, ConfirmNodeAccess: true},
		{Kind: ActionApproveNodePairing, ConfirmNodePairing: true},
		{Kind: ActionReauthorizeNodeStatus},
	} {
		if c.Dispatch(context.Background(), a) == nil {
			t.Fatal("public API permitted a legacy enrollment action", a.Kind)
		}
	}
	if len(f.requests) != posts || c.scoped.original != scoped || c.node.Pending != pending || c.node.PairTrust != pairing || owner != c.owner.Public().ID || device != c.device.Public().ID || counters != c.node.Client {
		t.Fatal("legacy refusal sent or persisted authorization / changed identity")
	}
	// Arrange an old persisted review privately. Product actions may observe/end
	// its retained operation, never grant a new legacy approval.
	f.review()
	s := c.Snapshot()
	if containsAction(s.AvailableActions, ActionApproveNodePairing) || containsAction(s.AvailableActions, ActionPreviewNode) || containsAction(s.AvailableActions, ActionApproveNode) {
		t.Fatal("public snapshot advertised a legacy grant")
	}
	old := bytes.Clone(c.node.PairTrust.Pending.Request)
	count := len(f.requests)
	if c.Dispatch(context.Background(), Action{Kind: ActionApproveNodePairing, NodePairingReviewID: c.nodePairingReviewID(), ConfirmNodePairing: true}) == nil || count != len(f.requests) || !bytes.Equal(old, c.node.PairTrust.Pending.Request) {
		t.Fatal("old review gained new consent or replaced its retained packet")
	}
}
