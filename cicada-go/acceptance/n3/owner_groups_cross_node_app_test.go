package n3_test

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Only the frozen public Core gestures are used. The parent neither opens the
// App vault nor signs enrollment, Group or policy requests on its behalf.
func (f *ownerGroupsCrossNodeFixture) freshSession(t *testing.T) {
	t.Helper()
	s := f.current
	deadline, err := time.Parse(time.RFC3339Nano, s.Account.SessionExpiresAt)
	if err == nil && time.Now().Add(time.Minute).Before(deadline) && s.Account.State == appcore.AccountStateOwnerReady {
		return
	}
	if s.ThreadGroups.Pending || s.ThreadGroups.Review != nil || s.LocalCollaboration.Pending || s.Targets.Locked {
		t.Fatal("account reauthentication cannot displace an original pending operation or Owner review")
	}
	if err == nil && time.Now().Before(deadline) {
		f.action(t, appcore.Action{Kind: appcore.ActionLogout})
	}
	after := f.action(t, appcore.Action{Kind: appcore.ActionLogin, Username: f.original.Account.Username, Password: syntheticPassword})
	end, parseErr := time.Parse(time.RFC3339Nano, after.Account.SessionExpiresAt)
	if parseErr != nil || !time.Now().Add(time.Minute).Before(end) || after.Account.State != appcore.AccountStateOwnerReady ||
		after.Account.RootState != f.original.Account.RootState || after.Account.OwnerFingerprint != f.original.Account.OwnerFingerprint ||
		after.Targets.SelectedNodeID != s.Targets.SelectedNodeID {
		t.Fatal("actual account login changed Root, Owner or the selected original Node")
	}
}

func (f *ownerGroupsCrossNodeFixture) enroll(t *testing.T, n *ownerGroupsCrossNode, additional bool) {
	t.Helper()
	f.freshSession(t)
	if additional {
		if !f.current.Targets.CanAdd || f.current.Targets.Locked || f.current.Targets.SelectedNodeID != f.nodes[0].id {
			t.Fatal("actual App does not offer adding the second Node from the original first Node")
		}
		s := f.action(t, appcore.Action{Kind: appcore.ActionBeginAddNode})
		if !s.Targets.Adding {
			t.Fatal("actual App did not explicitly begin an additional Node enrollment")
		}
	}
	n.start(t)
	n.readScopedCode(t)
	s := f.action(t, appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: n.code})
	if s.Node.Pairing == nil || s.Node.Pairing.State != "REVIEW" || s.Node.Pairing.ReviewID == "" || s.Node.Pairing.NodeID != n.id {
		t.Fatal("actual App lacks an exact scoped private-device-code review")
	}
	s = f.action(t, appcore.Action{Kind: appcore.ActionApproveNodePairing,
		NodePairingReviewID: s.Node.Pairing.ReviewID, ConfirmNodePairing: true})
	// Only the original running Node may ACK with its private key. Refreshing
	// reads this result; it never replaces the enrollment with a legacy flow.
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); {
		if s.Node.Pairing != nil && s.Node.Pairing.State == wire.NodePairTrustACKed {
			break
		}
		if !n.process.running() || !f.hub.hub.running() {
			t.Fatal("actual Node or Hub stopped before the private enrollment ACK")
		}
		s = f.action(t, appcore.Action{Kind: appcore.ActionRefreshNodePairing})
	}
	if s.Targets.SelectedNodeID != n.id || s.Targets.Adding || s.Targets.Locked || s.Targets.AdditionalNodesPending {
		t.Fatal("actual App did not select and settle the exact enabled scoped Node")
	}
	n.retainACK(t, s)
}

func (f *ownerGroupsCrossNodeFixture) activatePolicy(t *testing.T, n *ownerGroupsCrossNode, network string) appcore.LocalCollaborationSnapshot {
	t.Helper()
	f.freshSession(t)
	initial := f.action(t, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.AvailabilityKnown || !initial.Available || !initial.Current || initial.Pending || initial.State != "UNCONFIGURED" || initial.NodeID != n.id {
		t.Fatal("actual scoped Node lacks a fresh unconfigured local policy card")
	}
	input := appcore.LocalCollaborationAction{GroupName: "SYNTHETIC independent default " + n.id}
	if network == "" {
		input.NewNetworkName = "SYNTHETIC cross-Node existing Network"
	} else {
		found := 0
		for _, card := range f.current.Targets.Networks {
			if card.NetworkID == network && card.SourceNodeID == f.nodes[0].id && card.SourcePolicyID == f.nodes[0].actors.active.PolicyID && card.Name != "" {
				found++
				input.NetworkID = card.NetworkID
			}
		}
		if found != 1 || input.NewNetworkName != "" {
			t.Fatal("second Node policy did not use the authenticated saved existing Network card")
		}
	}
	preview := f.action(t, appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration, LocalCollaboration: input}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.State != wire.LocalDomainPrepared || preview.NodeID != n.id ||
		preview.PolicyID == "" || preview.PolicyEpoch == 0 || preview.ReviewID == "" || preview.LocalUserScope != "uid:1000" ||
		preview.NetworkID == "" || network != "" && preview.NetworkID != network || preview.GroupID == "" ||
		preview.GroupName != input.GroupName || preview.ExpiresAt != "" {
		t.Fatal("actual Owner policy review changed its exact Node, OS user or existing Network")
	}
	active := f.action(t, appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if !active.Current || active.Pending || active.State != wire.LocalDomainActive {
		t.Fatal("actual Owner did not activate this exact independent Node policy")
	}
	return active
}

// Always an explicit native gesture, including selecting B after App restart.
func (f *ownerGroupsCrossNodeFixture) selectNode(t *testing.T, n *ownerGroupsCrossNode) {
	t.Helper()
	f.freshSession(t)
	s := f.current
	found := 0
	for _, card := range s.Targets.Nodes {
		if card.NodeID == n.id && card.CanSelect {
			found++
		}
	}
	if found != 1 || s.Targets.Locked || s.Targets.Adding || s.Targets.GestureID == "" {
		t.Fatal("actual App lacks one selectable saved Node card")
	}
	s = f.action(t, appcore.Action{Kind: appcore.ActionSelectSavedNode,
		NodeSelection: appcore.NodeSelectionAction{NodeID: n.id, GestureID: s.Targets.GestureID}})
	if s.Targets.SelectedNodeID != n.id || s.Node.Binding == nil || s.Node.Binding.NodeID != n.id ||
		s.Node.Binding.ID != n.bound.BindingID || s.Node.Binding.Version != n.bound.BindingVersion ||
		s.ThreadGroups.Current || s.LocalCollaboration.Current {
		t.Fatal("explicit saved Node selection reused a different binding or current card")
	}
	p := f.action(t, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !p.Current || p.Pending || p.State != wire.LocalDomainActive || p.NodeID != n.id ||
		p.PolicyID != n.actors.active.PolicyID || p.NetworkID != n.actors.active.NetworkID || p.GroupID != n.actors.active.GroupID {
		t.Fatal("selected Node did not freshly authenticate its own original independent policy")
	}
}

func (f *ownerGroupsCrossNodeFixture) currentPanel(t *testing.T, n *ownerGroupsCrossNode, p ownerGroupsPanel) {
	t.Helper()
	end, err := time.Parse(time.RFC3339Nano, p.FreshUntil)
	start, startErr := time.Parse(time.RFC3339Nano, p.CapturedAt)
	if !p.AvailabilityKnown || !p.Available || !p.Current || p.Pending || p.ErrorCode != "" || p.GestureID == "" ||
		p.NodeID != n.id || p.NetworkID != n.actors.active.NetworkID || err != nil || startErr != nil ||
		!time.Now().Before(end) || start.After(time.Now().Add(30*time.Second)) ||
		f.current.Targets.SelectedNodeID != n.id || f.current.Node.Binding == nil || f.current.Node.Binding.ID != n.bound.BindingID {
		t.Fatal("actual App Group card is stale or belongs to another Node, binding or Network")
	}
}

func (f *ownerGroupsCrossNodeFixture) groupGesture(t *testing.T, n *ownerGroupsCrossNode, kind appcore.ActionKind, input ownerGroupsGesture) ownerGroupsPanel {
	t.Helper()
	s := f.action(t, actualOwnerGroupsAction(t, kind, input))
	if s.Targets.SelectedNodeID != n.id || s.Node.Binding == nil || s.Node.Binding.ID != n.bound.BindingID ||
		s.ThreadGroups.NodeID != n.id || s.ThreadGroups.NetworkID != n.actors.active.NetworkID {
		t.Fatal("actual Group gesture escaped its explicitly selected original Node/Network")
	}
	return s.ThreadGroups
}

func (f *ownerGroupsCrossNodeFixture) thread(t *testing.T, actor ownerGroupsCrossActor, candidates bool) ownerGroupsPanel {
	t.Helper()
	n := actor.node
	f.freshSession(t)
	if f.current.Targets.SelectedNodeID != n.id {
		f.selectNode(t, n)
	}
	p := f.current.ThreadGroups
	if p.Pending || p.Review != nil || p.GestureID == "" {
		t.Fatal("fresh Group read would replace an unresolved original or Owner review")
	}
	var card *ownerGroupsThreadCard
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 8; page++ {
		p = f.groupGesture(t, n, appcore.ActionReadThreadGroups, ownerGroupsGesture{GestureID: p.GestureID, Cursor: cursor})
		f.currentPanel(t, n, p)
		for i := range p.Threads {
			if p.Threads[i].EndpointID == actor.identity.Endpoint {
				if card != nil {
					t.Fatal("actual Thread pages repeated the original Endpoint")
				}
				copy := p.Threads[i]
				card = &copy
			}
		}
		cursor = p.ThreadsNextCursor
		if cursor == "" {
			break
		}
		if seen[cursor] || page == 7 {
			t.Fatal("actual Thread read repeated or exceeded its page bound")
		}
		seen[cursor] = true
	}
	if card == nil || card.Workspace != actor.identity.Workspace || card.Harness != "codex" || card.GestureID == "" {
		t.Fatal("actual App card does not identify the exact original native Endpoint/workspace")
	}
	seen, cursor = map[string]bool{}, ""
	for page := 0; page < 8; page++ {
		p = f.groupGesture(t, n, appcore.ActionReadThreadRelations, ownerGroupsGesture{GestureID: card.GestureID, EndpointID: card.EndpointID, Cursor: cursor})
		f.currentPanel(t, n, p)
		if p.Selected == nil || p.Selected.EndpointID != actor.identity.Endpoint || p.Selected.Workspace != actor.identity.Workspace {
			t.Fatal("actual relation card changed the exact original native Endpoint")
		}
		card, cursor = p.Selected, p.Selected.RelationsCursor
		if cursor == "" {
			if !card.RelationsComplete {
				t.Fatal("actual relation card is incomplete without a continuation")
			}
			break
		}
		if card.RelationsComplete || seen[cursor] || page == 7 {
			t.Fatal("actual relation read repeated or exceeded its page bound")
		}
		seen[cursor] = true
	}
	if !candidates {
		return p
	}
	seen, cursor = map[string]bool{}, ""
	for page := 0; page < 8; page++ {
		p = f.groupGesture(t, n, appcore.ActionReadGroupCandidates, ownerGroupsGesture{GestureID: p.Selected.GestureID, EndpointID: actor.identity.Endpoint, Cursor: cursor})
		f.currentPanel(t, n, p)
		if !p.CandidatesLoaded || p.Selected == nil || p.Selected.EndpointID != actor.identity.Endpoint || p.Selected.Workspace != actor.identity.Workspace {
			t.Fatal("actual candidate read changed its exact original native Endpoint")
		}
		cursor = p.CandidatesCursor
		if cursor == "" {
			return p
		}
		if seen[cursor] || page == 7 {
			t.Fatal("actual candidate read repeated or exceeded its page bound")
		}
		seen[cursor] = true
	}
	t.Fatal("actual candidate read did not complete")
	return ownerGroupsPanel{}
}

func (f *ownerGroupsCrossNodeFixture) change(t *testing.T, actor ownerGroupsCrossActor, change, group, name string) string {
	t.Helper()
	p := f.thread(t, actor, change != wire.OwnerEndpointGroupsRemoveEndpoint)
	f.currentPanel(t, actor.node, p)
	input := ownerGroupsGesture{Change: change, GroupID: group}
	threadName, workspace, userScope, groupName, outcome := "", "", "", name, "GROUP_CREATED"
	switch change {
	case wire.OwnerEndpointGroupsCreateGroup:
		if !p.CanCreate || name == "" || group != "" {
			t.Fatal("actual Core does not offer this explicit Group create")
		}
		input.Name, input.GestureID = name, p.GestureID
	case wire.OwnerEndpointGroupsAddEndpoint, wire.OwnerEndpointGroupsRemoveEndpoint:
		if name != "" || group == "" {
			t.Fatal("actual Group mutation lacks an exact existing Group")
		}
		input.EndpointID, threadName, workspace = actor.identity.Endpoint, p.Selected.Name, p.Selected.Workspace
		userScope = actor.node.actors.active.LocalUserScope
		if change == wire.OwnerEndpointGroupsAddEndpoint {
			input.Duration, outcome = "until_revoked", "ADD_SUBMITTED"
			for _, c := range p.Candidates {
				if c.GroupID == group && c.CanAdd {
					if input.GestureID != "" {
						t.Fatal("actual candidate duplicated the exact Group")
					}
					input.GestureID, groupName = c.GestureID, c.Name
				}
			}
		} else {
			outcome = "REMOVED"
			for _, r := range p.Selected.Relations {
				if r.GroupID == group && r.CanRemove {
					if input.GestureID != "" {
						t.Fatal("actual relations duplicated the exact Group")
					}
					input.GestureID, groupName = r.GestureID, r.Name
				}
			}
		}
	default:
		t.Fatal("unreviewed cross-Node Group change")
	}
	if input.GestureID == "" || groupName == "" || p.Review != nil {
		t.Fatal("exact Core change gesture is absent or a prior review remains")
	}
	p = f.groupGesture(t, actor.node, appcore.ActionPrepareThreadGroup, input)
	r := p.Review
	if r == nil || r.GestureID == "" || !p.Current || p.Pending || r.Action != change || r.NodeID != actor.node.id ||
		r.NetworkID != actor.node.actors.active.NetworkID || r.GroupID == "" || group != "" && r.GroupID != group || r.EndpointID != input.EndpointID ||
		r.ThreadName != threadName || r.Workspace != workspace || r.GroupName != groupName || r.Duration != input.Duration ||
		r.LocalUserScope != userScope || r.PolicyExpiresAt != "" {
		t.Fatal("actual Owner review changed its exact Node, Endpoint, Group or lifetime")
	}
	end, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || !time.Now().Before(end) || end.After(time.Now().Add(5*time.Minute+30*time.Second)) {
		t.Fatal("actual explicit Owner review has no bounded live consent")
	}
	p = f.groupGesture(t, actor.node, appcore.ActionApplyThreadGroup, ownerGroupsGesture{GestureID: r.GestureID, Confirm: true})
	if p.Pending || p.Current || p.Review != nil || p.ErrorCode != "" || p.Outcome != outcome {
		t.Fatal("actual App did not retain the exact reviewed Group mutation as a historical result")
	}
	return r.GroupID
}

func (f *ownerGroupsCrossNodeFixture) relation(t *testing.T, actor ownerGroupsCrossActor, group, state string) {
	t.Helper()
	for end := time.Now().Add(75 * time.Second); time.Now().Before(end); {
		p := f.thread(t, actor, false)
		found := 0
		for _, r := range p.Selected.Relations {
			if r.GroupID != group {
				continue
			}
			found++
			if found > 1 {
				t.Fatal("actual relation card repeated the exact Group")
			}
			if r.State == state && r.OwnerMode == "OWNER" && (state != "ACTIVE" || r.KeyState == "CURRENT") {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("exact original Endpoint/Group did not settle through the actual Node key barrier")
}
