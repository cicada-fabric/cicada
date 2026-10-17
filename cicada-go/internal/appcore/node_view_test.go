package appcore

import (
	"testing"
	"time"
)

func TestNodeConnectionRequiresCurrentIndependentEvidence(t *testing.T) {
	base := NodeSetupSnapshot{
		Candidate:    &NodeCandidateSnapshot{NodeID: "synthetic-node"},
		Access:       NodeAccessSnapshot{State: "ACTIVE", Confirmed: true},
		Binding:      &NodeBindingSnapshot{ID: "synthetic-binding", NodeID: "synthetic-node", Authorized: true},
		Connectivity: NodeConnectivitySnapshot{State: "connected", Current: true, Known: true},
	}
	for _, tt := range []struct {
		name   string
		change func(*NodeSetupSnapshot)
		want   NodeConnectionState
	}{
		{"current", func(*NodeSetupSnapshot) {}, NodeOnline},
		{"approval-only", func(n *NodeSetupSnapshot) { n.Connectivity = NodeConnectivitySnapshot{} }, NodeUnknown},
		{"historical-receipt", func(n *NodeSetupSnapshot) { n.Connectivity.Current = false }, NodeUnknown},
		{"access-expired", func(n *NodeSetupSnapshot) { n.Access.Confirmed = false; n.Access.State = "EXPIRED" }, NodeUnknown},
		{"binding-revoked", func(n *NodeSetupSnapshot) { n.Binding.Authorized = false }, NodeUnknown},
		{"foreign-node", func(n *NodeSetupSnapshot) { n.Binding.NodeID = "other-node" }, NodeUnknown},
		{"uncertain", func(n *NodeSetupSnapshot) { n.Pending = true }, NodeUnknown},
		{"stale", func(n *NodeSetupSnapshot) { n.Connectivity.Stale = true }, NodeStale},
		{"offline", func(n *NodeSetupSnapshot) { n.Connectivity.State = "offline" }, NodeOffline},
		{"explicit-offline-old-heartbeat", func(n *NodeSetupSnapshot) { n.Connectivity.State = "offline"; n.Connectivity.Stale = true }, NodeOffline},
		{"runtime-not-node", func(n *NodeSetupSnapshot) { n.Connectivity.State = "runtime-online" }, NodeUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := cloneNodeSnapshot(base)
			tt.change(&n)
			if got := n.ConnectionState(); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNodeClockDecayPreservesBindingAndN2AndBlocksNewApproval(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	stamp := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	s := Snapshot{Hub: HubSnapshot{Verified: true},
		Account:          AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, SessionExpiresAt: stamp(now.Add(time.Hour))},
		Authorization:    AuthorizationSnapshot{State: "EXPIRED", ExpiresAt: stamp(now.Add(-time.Hour))},
		AvailableActions: []ActionKind{ActionApproveNode, ActionRefreshNode, ActionRecoverNode},
		Node: NodeSetupSnapshot{Available: true,
			Candidate:    &NodeCandidateSnapshot{ReviewID: "synthetic-review", NodeID: "synthetic-node", ExpiresAt: stamp(now.Add(30 * time.Second)), AuthorizationExpiresAt: stamp(now.Add(2 * time.Minute))},
			Access:       NodeAccessSnapshot{State: "ACTIVE", Confirmed: true, ExpiresAt: stamp(now.Add(2 * time.Minute))},
			Binding:      &NodeBindingSnapshot{ID: "synthetic-binding", NodeID: "synthetic-node", Authorized: true},
			Connectivity: NodeConnectivitySnapshot{State: "connected", Known: true, Current: true, ObservedAt: stamp(now), LastHeartbeatAt: stamp(now), FreshUntil: stamp(now.Add(time.Minute))},
		},
	}
	expireNodeView(&s, now)
	if s.Node.ConnectionState() != NodeOnline {
		t.Fatal("independent Node permission depended on expired N2 lease")
	}
	// A repeated status observation with the same heartbeat cannot reset TTL.
	s.Node.Connectivity.ObservedAt = stamp(now.Add(time.Minute))
	expireNodeView(&s, now.Add(time.Minute))
	if s.Node.ConnectionState() != NodeStale {
		t.Fatal("idle desktop kept a permanent connected label")
	}
	for _, a := range s.AvailableActions {
		if a == ActionApproveNode {
			t.Fatal("expired candidate remained approvable")
		}
	}
	expireNodeView(&s, now.Add(2*time.Minute))
	if s.Node.Access.State != "EXPIRED" || s.Node.Access.Confirmed || s.Node.ConnectionState() != NodeUnknown {
		t.Fatal("expired Node access retained current liveness")
	}
	if s.Authorization.State != "EXPIRED" || s.Node.Binding.ID != "synthetic-binding" {
		t.Fatal("clock decay changed N2 or discarded the binding")
	}
	foundRecovery := false
	for _, action := range s.AvailableActions {
		if action == ActionRecoverNode {
			foundRecovery = true
		}
		if action != ActionRecoverNode && action != ActionRefreshNode {
			t.Fatal("clock decay retained a new authority operation")
		}
	}
	if !foundRecovery {
		t.Fatal("clock decay removed recovery")
	}
}

func TestNodeActionAndSnapshotNeverExposeConnectionCode(t *testing.T) {
	a := Action{Kind: ActionPreviewNode, NodeCode: "SYNTHETIC-SECRET-CODE"}
	if a.String() != "Action(REVIEW_NODE_CONNECTION)" || a.GoString() != a.String() {
		t.Fatal("action formatting exposed Node code")
	}
	s := Snapshot{Node: NodeSetupSnapshot{Candidate: &NodeCandidateSnapshot{ReviewID: "synthetic-review"}, Binding: &NodeBindingSnapshot{ID: "synthetic-binding"}}}
	c := cloneSnapshot(s)
	c.Node.Candidate.ReviewID, c.Node.Binding.ID = "changed", "changed"
	if s.Node.Candidate.ReviewID != "synthetic-review" || s.Node.Binding.ID != "synthetic-binding" {
		t.Fatal("renderer can mutate core Node evidence")
	}
}

func TestExpiredProposalRetainsOnlySafeDiagnosticRefresh(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := Snapshot{Hub: HubSnapshot{Verified: true}, Account: AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, SessionExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano)},
		Node:             NodeSetupSnapshot{Available: true, Candidate: &NodeCandidateSnapshot{ReviewID: "synthetic-expired", ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}},
		AvailableActions: []ActionKind{ActionApproveNode, ActionCancelNodeAccess, ActionReauthorizeNodeStatus, ActionRefreshNode}}
	expireNodeView(&s, now)
	if len(s.AvailableActions) != 1 || s.AvailableActions[0] != ActionRefreshNode {
		t.Fatal("expiry removed diagnostics or retained conflicting new authority")
	}
}
