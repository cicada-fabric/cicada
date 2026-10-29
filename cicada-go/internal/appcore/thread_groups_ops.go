package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) threadGroupScope() (string, string) {
	if c.selectedNodeBinding() == nil {
		return "", ""
	}
	node := c.selectedNodeBinding().NodeID
	if c.hasThreadGroupPending() && c.threadGroups.original.NodeID == node {
		return node, c.threadGroups.original.NetworkID
	}
	if c.localDomain.state.Description != nil && c.localDomain.state.Description.Policy.Node.NodeID == node {
		return node, c.localDomain.state.Description.Policy.NetworkID
	}
	return node, ""
}

func (c *nativeController) threadGroupGesture(value any) string {
	if !c.ownerAccountReady() {
		return ""
	}
	node, network := c.threadGroupScope()
	raw, err := json.Marshal(struct {
		Node, Network, SessionDigest string
		AccountEpoch, DeviceEpoch    uint64
		Value                        any
	}{node, network, sessionTokenDigest(c.session.SessionToken), c.session.AccountEpoch, c.session.DeviceEpoch, value})
	if err != nil || network == "" {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cicada/app/thread-groups/gesture/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func (c *nativeController) initializeThreadGroups(ctx context.Context) {
	if c.scopedBusy() {
		return
	}
	if c.vault == nil || c.device == nil || c.owner == nil || !c.ownerAccountReady() || c.nodePairTrustBusy() {
		return
	}
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		_ = c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
		return
	}
	if c.hasThreadGroupPending() {
		c.publish()
		return
	}
	if _, network := c.threadGroupScope(); network == "" {
		return
	}
	if !c.threadGroups.discoveryTried {
		if err := c.discoverThreadGroups(ctx); err != nil {
			c.threadGroups.view.ErrorCode = "UNSUPPORTED_PROFILE"
		}
	}
	c.publish()
}

func (c *nativeController) threadGroupsReady(ctx context.Context) error {
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	if c.hasThreadGroupPending() || !c.ownerOperationCanStart() || c.nodePairTrustBusy() {
		return ErrInvalidAction
	}
	_, network := c.threadGroupScope()
	if network == "" {
		return ErrInvalidAction
	}
	if !c.threadGroups.discoveryTried {
		if err := c.discoverThreadGroups(ctx); err != nil {
			return c.failThreadGroups("UNSUPPORTED_PROFILE", err)
		}
	}
	if !c.threadGroups.available {
		return c.failThreadGroups("UNSUPPORTED_PROFILE", ErrInvalidAction)
	}
	return nil
}

func (c *nativeController) readThreadGroups(ctx context.Context, kind ActionKind, input ThreadGroupAction) error {
	if err := c.threadGroupsReady(ctx); err != nil {
		return err
	}
	node, network := c.threadGroupScope()
	body := wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: node, NetworkID: network, Limit: 64, Cursor: input.Cursor}
	seed := &threadGroupRecord{NodeID: node, NetworkID: network}
	view := c.Snapshot().ThreadGroups
	switch kind {
	case ActionReadThreadGroups:
		if input.GestureID != c.threadGroupGesture("read") || input.Cursor != "" && input.Cursor != view.ThreadsNextCursor {
			return ErrInvalidAction
		}
	case ActionReadThreadRelations, ActionReadGroupCandidates:
		var thread *wire.OwnerEndpointGroupsThreadCard
		for i := range c.threadGroups.threads {
			t := &c.threadGroups.threads[i]
			if t.EndpointID == input.EndpointID && c.threadGroupGesture(*t) == input.GestureID {
				thread = t
			}
		}
		if t := c.threadGroups.selected; t != nil && t.EndpointID == input.EndpointID && c.threadGroupGesture(*t) == input.GestureID {
			thread = t
		}
		if thread == nil || !view.Current {
			return ErrInvalidAction
		}
		body.EndpointID, seed.Thread = thread.EndpointID, thread
		body.View = "RELATIONS"
		if kind == ActionReadGroupCandidates {
			body.View = "CANDIDATE_GROUPS"
			if c.threadGroups.selected == nil || c.threadGroups.selected.EndpointID != input.EndpointID || input.Cursor != "" && input.Cursor != view.CandidatesCursor {
				return ErrInvalidAction
			}
		} else if input.Cursor != "" && (view.Selected == nil || input.Cursor != view.Selected.RelationsCursor) {
			return ErrInvalidAction
		}
	default:
		return ErrInvalidAction
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewOwnerEndpointGroupsRead(c.nodeSession(), scope, body, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendThreadGroup(ctx, request, seed)
}

func (c *nativeController) prepareThreadGroup(ctx context.Context, input ThreadGroupAction) error {
	if err := c.threadGroupsReady(ctx); err != nil {
		return err
	}
	view := c.Snapshot().ThreadGroups
	if !view.Current || c.threadGroups.review != nil {
		return ErrInvalidAction
	}
	node, network := c.threadGroupScope()
	body := wire.OwnerEndpointGroupsPrepareBody{Action: input.Change, NodeID: node, NetworkID: network}
	binding := *c.selectedNodeBinding()
	seed := &threadGroupRecord{NodeID: node, NetworkID: network, Binding: &binding}
	if policy := c.localDomain.state.Description; policy != nil {
		seed.LocalUserScope = policy.Policy.LocalUserScope
		seed.NetworkName = policy.Policy.NetworkName
	}
	switch input.Change {
	case wire.OwnerEndpointGroupsCreateGroup:
		if !view.CanCreate || input.GestureID != view.GestureID {
			return ErrInvalidAction
		}
		body.Name = input.Name
	case wire.OwnerEndpointGroupsAddEndpoint, wire.OwnerEndpointGroupsRemoveEndpoint:
		t := c.threadGroups.selected
		if t == nil || t.EndpointID != input.EndpointID {
			return ErrInvalidAction
		}
		seed.Thread, body.EndpointID, body.GroupID = t, t.EndpointID, input.GroupID
		if input.Change == wire.OwnerEndpointGroupsAddEndpoint {
			body.Duration = input.Duration
			if body.Duration == "" {
				body.Duration = "until_revoked"
			}
			for i := range c.threadGroups.candidates {
				g := &c.threadGroups.candidates[i]
				if g.GroupID == input.GroupID && c.threadGroupGesture(g) == input.GestureID && slices.Contains(g.AllowedActions, input.Change) {
					seed.Group = g
				}
			}
			if seed.Group == nil {
				return ErrInvalidAction
			}
		} else {
			for i := range c.threadGroups.selectedRelations {
				r := &c.threadGroups.selectedRelations[i]
				if r.GroupID == input.GroupID && c.threadGroupGesture(r) == input.GestureID && slices.Contains(r.AllowedActions, input.Change) {
					seed.Relation = r
					head := r.OwnerControl
					seed.ExpectedHead = &head
				}
			}
			if seed.Relation == nil {
				return ErrInvalidAction
			}
		}
	default:
		return ErrInvalidAction
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewOwnerEndpointGroupsPrepare(c.nodeSession(), scope, body, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendThreadGroup(ctx, request, seed)
}

func (c *nativeController) applyThreadGroup(ctx context.Context, input ThreadGroupAction) error {
	if err := c.threadGroupsReady(ctx); err != nil {
		return err
	}
	r := c.threadGroups.reviewOriginal
	if !input.Confirm || !c.threadGroupReviewCurrent(r) || input.GestureID != c.threadGroupGesture(c.threadGroups.review) || c.verifyThreadGroupReviewTarget(r, *c.threadGroups.review) != nil || !threadGroupReviewCASMatches(r, *c.threadGroups.review) {
		return ErrInvalidAction
	}
	original, err := c.threadGroupDTO(r, nil)
	prepare, ok := original.(wire.OwnerEndpointGroupsPrepareRequest)
	if err != nil || !ok {
		return wire.ErrInvalid
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewOwnerEndpointGroupsApply(c.nodeSession(), scope, prepare, r.Packet, *c.threadGroups.review, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	seed := *r
	seed.Review = c.threadGroups.review
	return c.sendThreadGroup(ctx, request, &seed)
}

func (c *nativeController) dismissThreadGroup(input ThreadGroupAction) error {
	if c.hasThreadGroupPending() || c.threadGroups.review == nil || input.GestureID != c.threadGroupGesture(c.threadGroups.review) {
		return ErrInvalidAction
	}
	if err := c.persistThreadGroupReview(nil, nil); err != nil {
		return err
	}
	c.threadGroups.review, c.threadGroups.view.Review = nil, nil
	c.publish()
	return nil
}

func (c *nativeController) failThreadGroups(code string, err error) error {
	c.threadGroups.view.ErrorCode = code
	c.publish()
	return err
}
