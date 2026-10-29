package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	ActionBeginAddNode ActionKind = "BEGIN_ADD_NODE"
	ActionEndAddNode   ActionKind = "END_ADD_NODE_DRAFT"
)

func (c *nativeController) selectedScopedNode() *scopedNodeRecord {
	d := c.node.Targets
	if d == nil || d.SelectedNodeID == "" {
		return nil
	}
	for _, r := range d.Nodes {
		if r.NodeID == d.SelectedNodeID && r.ScopeVersion == 2 {
			return c.scopedNode(r.NodeID)
		}
	}
	return nil
}

func (c *nativeController) selectedNodeBinding() *e2ee.OwnerAppNodeBinding {
	if d := c.node.Targets; d != nil {
		for _, r := range d.Nodes {
			if r.NodeID == d.SelectedNodeID && r.ScopeVersion == 2 && c.scopedNode(r.NodeID) == nil {
				return nil
			}
		}
	}
	if n := c.selectedScopedNode(); n != nil {
		if n.CountersCommitted && n.Trust != nil && n.Binding != nil && n.Binding.NodeID == n.NodeID {
			return n.Binding
		}
		return nil
	}
	if c.nodeConfirmation == nil {
		return nil
	}
	if d := c.node.Targets; d != nil && d.SelectedNodeID != "" && d.SelectedNodeID != c.nodeConfirmation.Binding.NodeID {
		return nil
	}
	return &c.nodeConfirmation.Binding
}

func scopedReference(n *scopedNodeRecord) savedNodeReference {
	r := savedNodeReference{NodeID: n.NodeID, ScopeVersion: 2}
	if n.Binding != nil {
		r.Name = n.Binding.NodeName
	}
	if n.Trust != nil && n.Trust.Original != nil && n.CountersCommitted {
		packet := n.Trust.Original.Response
		if n.Confirmation != nil {
			packet = n.Confirmation.Response
		}
		digest := sha256.Sum256(packet)
		r.ConfirmationDigest = hex.EncodeToString(digest[:])
	}
	return r
}

func (c *nativeController) indexScopedNode(n *scopedNodeRecord, selectNode bool) error {
	d := c.localTargets()
	i := slices.IndexFunc(d.Nodes, func(r savedNodeReference) bool { return r.NodeID == n.NodeID })
	if i < 0 {
		if len(d.Nodes) >= maxLocalNodes {
			return wire.ErrInvalid
		}
		d.Nodes = append(d.Nodes, scopedReference(n))
	} else if d.Nodes[i].ScopeVersion == 2 {
		d.Nodes[i] = scopedReference(n)
	}
	if selectNode {
		d.SelectedNodeID = n.NodeID
	}
	if err := validateLocalTargets(d); err != nil {
		return err
	}
	next := c.node
	next.Targets = d
	if err := c.persistNodeRecord(nodeStateNamespace, &c.nodeVer, next); err != nil {
		return err
	}
	c.node = next
	return nil
}

func (c *nativeController) registerScopedSelection(n *scopedNodeRecord) error {
	if n.Binding == nil || n.Trust == nil || !n.CountersCommitted {
		return wire.ErrInvalid
	}
	if err := c.indexScopedNode(n, true); err != nil {
		return err
	}
	c.invalidateSelectedNodeViews()
	return nil
}

func (c *nativeController) invalidateSelectedNodeViews() {
	c.nodeChecked = false
	c.localDomain.checkedTarget = ""
	c.localDomain.state.View.Current = false
	c.threadGroups.view.Current = false
	c.threadGroups.viewSessionDigest = ""
	c.threadGroups.review = nil
	c.threadGroups.selected = nil
	c.threadGroups.candidates = nil
	c.ownerEndpointResult = nil
	if c.scoped.fresh != nil {
		delete(c.scoped.fresh, c.localCollaborationNodeID())
		delete(c.scoped.fresh, c.localCollaborationNodeID()+"/grant")
	}
}

func (c *nativeController) beginAddNode(ctx context.Context) error {
	if !c.nodeAccountReady() || c.targetSelectionLocked() {
		return ErrInvalidAction
	}
	if err := c.ensureScopedNodesLoaded(); err != nil {
		return err
	}
	if err := c.discoverScopedNodes(ctx); err != nil {
		return c.scopedFailure("APP_NODE_PAIRING_UNAVAILABLE")
	}
	c.scoped.adding = true
	c.publish()
	return nil
}

func (c *nativeController) scopedOwnerActor(ctx context.Context) (e2ee.OwnerAppNodeScope, error) {
	n := c.selectedScopedNode()
	if n == nil || c.selectedNodeBinding() == nil {
		return e2ee.OwnerAppNodeScope{}, ErrInvalidAction
	}
	if c.scopedBusy() {
		return e2ee.OwnerAppNodeScope{}, ErrInvalidAction
	}
	if c.scoped.fresh[n.NodeID] != sessionTokenDigest(c.session.SessionToken) || n.Context == nil || !c.scopedScopeMatches(n.Context.Authority.Scope, true) {
		if !c.scoped.available {
			if err := c.discoverScopedNodes(ctx); err != nil {
				return e2ee.OwnerAppNodeScope{}, err
			}
		}
		if err := c.refreshScopedContext(ctx, n.NodeID); err != nil {
			return e2ee.OwnerAppNodeScope{}, err
		}
	}
	if n.Context == nil || !c.scopedScopeMatches(n.Context.Authority.Scope, true) {
		return e2ee.OwnerAppNodeScope{}, wire.ErrInvalid
	}
	return wire.AppNodeScopedOwnerActor(n.Context.Authority.Scope, c.hub)
}

func (c *nativeController) populateScopedNode(view *Snapshot) {
	n := c.selectedScopedNode()
	if n != nil {
		view.Pair = PairSetupSnapshot{}
		view.OwnerEndpoints = OwnerEndpointSnapshot{}
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(a ActionKind) bool { return pairActionKind(a) || ownerEndpointActionKind(a) })
		v := NodeSetupSnapshot{Available: c.scoped.available, Pending: c.scopedPending(), ErrorCode: c.scoped.errorCode}
		if n.Binding != nil {
			b := n.Binding
			v.Binding = &NodeBindingSnapshot{ID: b.OwnerBindingID, NodeID: b.NodeID, Name: b.NodeName, Version: b.BindingVersion}
		}
		if n.Current != nil {
			r := n.Current
			v.Access = NodeAccessSnapshot{State: r.Authority.State, ExpiresAt: r.Authority.LeaseExpiresAt}
			if n.Grant != nil {
				v.Access.ReviewID = wire.AppNodeScopedClaimsDigest(n.Grant.Claims)
				v.Access.Confirmed = c.session != nil && n.HighestHead == n.Grant.Claims.Scope.HeadVersion && n.LatestGrantID == n.Grant.Claims.GrantID && c.scoped.fresh[n.NodeID+"/grant"] == sessionTokenDigest(c.session.SessionToken) && wire.ValidateAppNodeScopedLiveResult(*r, n.Grant.Claims, c.hub, c.cfg.Now().UTC()) == nil
			}
			if o := r.Node; o != nil && v.Access.Confirmed && v.Binding != nil && o.NodeID == n.NodeID && o.BindingID == v.Binding.ID {
				v.Binding.Authorized = o.Authorized && o.BindingState == "ACTIVE"
				v.Connectivity = NodeConnectivitySnapshot{State: strings.ToLower(o.Connectivity), Known: o.Known, Stale: o.Stale, Current: true, ObservedAt: o.ObservedAt, LastHeartbeatAt: o.LastHeartbeatAt, FreshUntil: o.FreshUntil}
			}
		}
		if p := n.ReadProposal; p != nil && p.Challenge != nil {
			g := p.Challenge.Claims
			b := g.Binding
			v.Candidate = &NodeCandidateSnapshot{ReviewID: wire.AppNodeScopedClaimsDigest(g), NodeID: n.NodeID, Name: b.NodeName, NodeFingerprint: b.NodeKeyFingerprint, HubControlFingerprint: b.HubNodeControlFingerprint, NodeKeyEpoch: b.NodeKeyEpoch, CandidateVersion: b.BindingVersion, ExpiresAt: g.ProofExpiresAt, AuthorizationExpiresAt: g.LeaseExpiresAt, StatusOnly: true}
		}
		view.Node = v
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(a ActionKind) bool { return nodeActionKind(a) })
		if c.nodeAccountReady() && !c.scopedBusy() {
			view.AvailableActions = append(view.AvailableActions, ActionRefreshNode)
			if n.Grant != nil && n.ProvenanceID != "" {
				view.AvailableActions = append(view.AvailableActions, ActionCancelNodeAccess)
				if c.scopedStatusReauthorizationAvailable(n) {
					view.AvailableActions = append(view.AvailableActions, ActionReauthorizeNodeStatus)
				}
			}
		}
		if n.ReadProposal != nil && !c.scopedPending() && c.nodeAccountReady() {
			view.AvailableActions = append(view.AvailableActions, ActionApproveNode, ActionCancelNodeAccess)
		}
	}
	if c.scoped.adding {
		view.Node.Pairing = &NodePairingSnapshot{Available: c.scoped.available, Availability: c.scoped.availability, State: "CODE"}
	} else if f := c.scoped.flow; f != nil && (c.scopedBusy() || n != nil && f.NodeID == n.NodeID) {
		p := &NodePairingSnapshot{Available: c.scoped.available, Availability: c.scoped.availability, State: f.Stage, NodeID: f.NodeID, ReviewID: c.scopedReviewID(), ExpiresAt: earlierNodeDeadline(f.Code.ExpiresAt, f.Scope.AccountSessionExpiresAt), ErrorCode: f.LastError}
		if f.Context != nil {
			if x := f.Context.Candidate; x != nil {
				p.Name = x.NodeName
			}
			if x := f.Context.Binding; x != nil {
				p.Name = x.NodeName
			}
		}
		if f.Challenge != nil {
			p.ExpiresAt = earlierNodeDeadline(p.ExpiresAt, f.Challenge.Claims.ProofExpiresAt)
		}
		if f.Approval != nil {
			p.ExpiresAt = earlierNodeDeadline(p.ExpiresAt, f.Approval.AcceptBefore)
		}
		if c.scopedPending() {
			p.State = "UNKNOWN"
		}
		view.Node.Pairing = p
	} else if n != nil && n.Binding != nil {
		view.Node.Pairing = &NodePairingSnapshot{Available: c.scoped.available, Availability: c.scoped.availability, State: wire.NodePairTrustScopedACKed, NodeID: n.NodeID, Name: n.Binding.NodeName}
	}
	if c.scopedBusy() || c.scoped.adding || n != nil {
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(a ActionKind) bool {
			return a == ActionReviewNodePairing || a == ActionApproveNodePairing || a == ActionRefreshNodePairing || a == ActionRecoverNodePairing || a == ActionCancelNodePairing
		})
		if c.scopedPending() {
			view.AvailableActions = append(view.AvailableActions, ActionRecoverNodePairing)
		} else if c.nodeAccountReady() {
			if c.scoped.adding {
				view.AvailableActions = append(view.AvailableActions, ActionReviewNodePairing, ActionEndAddNode)
			} else if f := c.scoped.flow; f != nil && c.scopedBusy() {
				view.AvailableActions = append(view.AvailableActions, ActionRefreshNodePairing, ActionCancelNodePairing)
				if f.Stage == "REVIEW" && c.scoped.available && c.scopedScopeSessionMatches(f.Scope) {
					view.AvailableActions = append(view.AvailableActions, ActionApproveNodePairing)
				}
			}
		}
	}
}
