package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestSavedNodeSelectionPreservesLegacyConfirmationAndCounters(t *testing.T) {
	f := newLocalCollaborationActor(t)
	f.prepare()
	f.activate()
	before := f.c.nodeConfirmation
	confirmation, _ := json.Marshal(before)
	client, grant := f.c.node.Client, f.c.node.Grant
	owner, device := f.c.owner.Public().ID, f.c.device.Public().ID
	posts, _ := json.Marshal([]any{f.posts, f.n.posts})
	s := f.c.Snapshot()
	if len(s.Targets.Nodes) != 1 || !s.Targets.AdditionalNodesPending {
		t.Fatal("legacy selection or pending scope missing")
	}
	action := Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: s.Targets.SelectedNodeID, GestureID: s.Targets.GestureID}}
	if err := f.c.Dispatch(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.c.nodeConfirmation)
	nowPosts, _ := json.Marshal([]any{f.posts, f.n.posts})
	if !bytes.Equal(confirmation, after) || client != f.c.node.Client || !reflect.DeepEqual(grant, f.c.node.Grant) || !bytes.Equal(posts, nowPosts) || owner != f.c.owner.Public().ID || device != f.c.device.Public().ID {
		t.Fatal("local selection changed confirmation, counters, grant, keys or HTTP")
	}
	raw, _ := json.Marshal(f.c.node.Targets)
	state, _ := json.Marshal(f.c.node)
	t.Logf("synthetic local_directory_bytes=%d vault_base64_directory_bytes=%d node_state_bytes=%d additional_namespaces=0", len(raw), 4*((len(raw)+2)/3), len(state))
	if err := f.c.Dispatch(context.Background(), action); err == nil {
		t.Fatal("stale selection gesture accepted")
	}
	f.reopen()
	after, _ = json.Marshal(f.c.nodeConfirmation)
	if !bytes.Equal(confirmation, after) || f.c.node.Targets == nil || f.c.node.Targets.SelectedNodeID != before.Binding.NodeID || len(f.c.node.Targets.Networks) != 1 {
		t.Fatal("restart lost saved choice or changed legacy proof")
	}
}

func TestSavedNodeSelectionCannotBorrowLegacyAuthority(t *testing.T) {
	f := newLocalCollaborationActor(t)
	s := f.c.Snapshot()
	version := f.c.nodeVer
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: "synthetic-other-node", GestureID: s.Targets.GestureID}}); err == nil || version != f.c.nodeVer {
		t.Fatal("foreign remembered label borrowed legacy authority or wrote state")
	}
	d := f.c.localTargets()
	d.Nodes = append(d.Nodes, savedNodeReference{NodeID: "synthetic-other-node", Name: "Same display name", ConfirmationDigest: strings.Repeat("1", 64)})
	f.c.node.Targets = d
	f.c.publish()
	for _, n := range f.c.Snapshot().Targets.Nodes {
		if n.NodeID == "synthetic-other-node" && n.CanSelect {
			t.Fatal("unconnected scope offered as usable")
		}
	}
	d.SelectedNodeID = "synthetic-other-node"
	if err := f.c.validateLegacyTargetSelection(); err == nil {
		t.Fatal("saved choice redirected legacy confirmation")
	}
	d.SelectedNodeID = f.c.nodeConfirmation.Binding.NodeID
	d.Nodes[0].ConfirmationDigest = strings.Repeat("2", 64)
	if err := f.c.validateLegacyTargetSelection(); err == nil {
		t.Fatal("saved label substituted a legacy confirmation")
	}
}

func TestSavedNodeSelectionRetainsUncertainGroupOriginal(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("missing original uncertainty")
	}
	original := bytes.Clone(a.c.threadGroups.original.Packet)
	s := a.c.Snapshot()
	version := a.c.nodeVer
	if !s.Targets.Locked {
		t.Fatal("uncertain Group request did not lock targets")
	}
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: s.Targets.SelectedNodeID, GestureID: s.Targets.GestureID}}); err == nil || version != a.c.nodeVer || !bytes.Equal(original, a.c.threadGroups.original.Packet) {
		t.Fatal("selection overwrote or bypassed uncertain original")
	}
}

func TestTargetSelectionLocksEveryOriginalFamily(t *testing.T) {
	for name, setup := range map[string]func(*nativeController){
		"account":          func(c *nativeController) { c.state.Pending = &pendingOperation{Request: []byte("synthetic")} },
		"account-recovery": func(c *nativeController) { c.state.Recovery = &pendingOperation{} },
		"node":             func(c *nativeController) { c.node.Pending = &nodeOperation{} },
		"node-recovery":    func(c *nativeController) { c.nodeRecovery = &nodeOperation{} },
		"pair":             func(c *nativeController) { c.pairOriginal = &pairRequestRecord{} },
		"domain":           func(c *nativeController) { c.localDomain.original = &localDomainRecord{} },
		"groups":           func(c *nativeController) { c.threadGroups.original = &threadGroupRecord{} },
		"parked-read":      func(c *nativeController) { c.node.OwnerDirectoryUnknown = make([]ownerEndpointUnknownRecord, 1) },
		"node-prepared":    func(c *nativeController) { c.node.Proposal = new(nodeProposal) },
		"pair-prepared":    func(c *nativeController) { c.pairReview = new(pairReviewRecord) },
		"domain-prepared":  func(c *nativeController) { c.localDomain.state.View.State = wire.LocalDomainPrepared },
		"groups-prepared":  func(c *nativeController) { c.threadGroups.review = new(wire.OwnerEndpointGroupsReview) },
		"scoped-original":  func(c *nativeController) { c.scoped.original = new(scopedOriginal) },
		"scoped-recovery":  func(c *nativeController) { c.scoped.recovery = new(scopedOriginal) },
		"scoped-prepared": func(c *nativeController) {
			c.scoped.nodes = map[string]*scopedNodeRecord{"SYNTHETIC": {ReadProposal: new(scopedReadProposal)}}
		},
		"scoped-reserved": func(c *nativeController) {
			c.scoped.flow = &scopedPairFlow{Stage: "APPROVING", Confirmation: new(scopedConfirmation)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := new(nativeController)
			setup(c)
			if !c.targetSelectionLocked() {
				t.Fatal("target switch allowed with retained uncertainty")
			}
		})
	}
}

func TestLocalTargetDirectoryBoundsAndEncodedBudget(t *testing.T) {
	d := &localTargetDirectory{Format: localTargetsFormat, SelectedNodeID: "synthetic-node-0"}
	for i := 0; i < maxLocalNodes; i++ {
		d.Nodes = append(d.Nodes, savedNodeReference{NodeID: fmt.Sprintf("synthetic-node-%d", i), Name: strings.Repeat("中文", 32), ConfirmationDigest: strings.Repeat("a", 64)})
	}
	for i := 0; i < maxLocalNetworks; i++ {
		d.Networks = append(d.Networks, SavedNetworkView{NetworkID: fmt.Sprintf("synthetic-network-%d", i), Name: strings.Repeat("组", 32), SourceNodeID: d.Nodes[i%len(d.Nodes)].NodeID, SourcePolicyID: fmt.Sprintf("synthetic-policy-%d", i)})
	}
	if err := validateLocalTargets(d); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	t.Logf("synthetic eight_node_sixteen_network_labels_bytes=%d vault_base64_bytes=%d record_cap=%d", len(raw), 4*((len(raw)+2)/3), maxLocalTargetsBytes)
	d.Nodes = append(d.Nodes, d.Nodes[0])
	if validateLocalTargets(d) == nil {
		t.Fatal("overflow/duplicate accepted")
	}
	d.Nodes = d.Nodes[:maxLocalNodes]
	d.Networks[0].SourceNodeID = "foreign"
	if validateLocalTargets(d) == nil {
		t.Fatal("foreign source accepted")
	}
	d.Networks[0].SourceNodeID = d.Nodes[0].NodeID
	d.Nodes[0].Name = strings.Repeat("x", 257)
	if validateLocalTargets(d) == nil {
		t.Fatal("oversized label accepted")
	}
	for i := range d.Nodes {
		d.Nodes[i].Name = strings.Repeat("<", 256)
	}
	for i := range d.Networks {
		d.Networks[i].Name = strings.Repeat("<", 256)
	}
	if validateLocalTargets(d) == nil {
		t.Fatal("JSON escaping bypassed aggregate directory budget")
	}
}

func TestLocalNetworkChoiceRefusesUnofferedIDBeforeHTTP(t *testing.T) {
	f := newLocalCollaborationActor(t)
	count := len(f.posts[wire.OperationLocalDomainPrepare])
	err := f.c.Dispatch(context.Background(), Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NetworkID: "unoffered-network", GroupName: "Synthetic Group"}})
	if err == nil || len(f.posts[wire.OperationLocalDomainPrepare]) != count {
		t.Fatal("unoffered Network reached HTTP")
	}
}

func TestLocalNetworkChoiceRechecksSavedReferenceAndKeepsUnauthenticatedFailure(t *testing.T) {
	f := newLocalCollaborationActor(t)
	f.prepare()
	f.activate()
	f.descriptions[0].State = wire.LocalDomainRevoked
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err != nil {
		t.Fatal(err)
	}
	known := f.c.Snapshot().Targets.Networks
	if len(known) != 1 {
		t.Fatal("settled authenticated Network reference missing")
	}
	posts := 0
	f.c.cfg.HTTP = nodeAutoHTTPFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != wire.LocalDomainHTTPPath(wire.OperationLocalDomainPrepare) {
			return f.Do(req)
		}
		posts++
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	input := LocalCollaborationAction{NetworkID: known[0].NetworkID, GroupName: "Separate default Group", ExpiresInHours: 24}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: input}); err == nil || posts != 1 || !f.c.hasLocalDomainPending() {
		t.Fatal("saved label granted authority or raw HTTP rejected an uncertain original")
	}
	original := f.c.localDomain.original
	body, err := f.c.localDomainDTO(original, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := body.(wire.LocalDomainPrepare)
	claims, err := e2ee.VerifyOwnerLocalDomainRequest(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerLocalDomainPreparePurpose, time.Time{})
	if err != nil || claims.Target == nil || claims.Target.NetworkID != known[0].NetworkID || claims.Target.NewNetworkName != "" || claims.Target.GroupName != input.GroupName {
		t.Fatal("fresh signed preview lost exact saved Network or reused a Group", err)
	}
	packet := bytes.Clone(original.Packet)
	s := f.c.Snapshot()
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: s.Targets.SelectedNodeID, GestureID: s.Targets.GestureID}}); err == nil || !bytes.Equal(packet, f.c.localDomain.original.Packet) {
		t.Fatal("raw HTTP failure allowed replacing the original target")
	}
}
