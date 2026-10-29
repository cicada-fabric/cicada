package appcore

import (
	"context"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Automatic reads use the selected immutable binding and an already live scoped
// grant. They never discover, prepare, complete, recover or select another Node.
func (c *nativeController) refreshScopedNodeAutomatically(ctx context.Context, target NodeStatusTarget) error {
	n := c.selectedScopedNode()
	c.snapshotMu.RLock()
	globalError := c.snapshot.ErrorCode
	c.snapshotMu.RUnlock()
	if n == nil || n.Binding == nil || n.Grant == nil || n.Current == nil || n.Current.Node == nil || !n.CountersCommitted || n.Trust == nil ||
		!c.scoped.available || c.scopedBusy() || !c.scopedOperationAllowed(n.NodeID) || c.storageFault || globalError != "" || c.scoped.errorCode != "" ||
		!c.nodeAccountReady() || ctx.Err() != nil || n.HighestHead != n.Grant.Claims.Scope.HeadVersion || n.LatestGrantID != n.Grant.Claims.GrantID || c.scoped.fresh[n.NodeID+"/grant"] != sessionTokenDigest(c.session.SessionToken) ||
		!c.scopedScopeMatches(n.Current.Authority.Scope, true) || wire.ValidateAppNodeScopedLiveResult(*n.Current, n.Grant.Claims, c.hub, c.cfg.Now().UTC()) != nil {
		return ErrInvalidAction
	}
	b, observation := n.Binding, n.Current.Node
	want := NodeStatusTarget{Origin: c.connection.Origin, HubID: c.connection.HubID, AccountID: c.connection.AccountID,
		OwnerID: c.connection.OwnerID, DeviceID: c.state.DeviceID, BindingID: b.OwnerBindingID, NodeID: b.NodeID,
		BindingVersion: b.BindingVersion, ReviewID: wire.AppNodeScopedClaimsDigest(n.Grant.Claims)}
	if target != want || b.State != "ACTIVE" || !observation.Authorized || observation.BindingState != "ACTIVE" ||
		observation.NodeID != b.NodeID || observation.BindingID != b.OwnerBindingID || observation.BindingVersion != b.BindingVersion ||
		observation.CredentialVersion != b.CredentialVersion || observation.NodeKeyID != b.NodePublic.ID ||
		observation.NodeKeyFingerprint != b.NodeKeyFingerprint || observation.NodeKeyEpoch != b.NodeKeyEpoch ||
		n.ProvenanceID == "" || n.Current.Authority.ConfirmationProvenanceID != n.ProvenanceID {
		return ErrInvalidAction
	}
	expires := parseExpiry(earlierNodeDeadline(n.Grant.Claims.LeaseExpiresAt, n.Grant.Claims.Scope.AccountSessionExpiresAt, c.session.ExpiresAt))
	remaining := expires.Sub(c.cfg.Now().UTC())
	if remaining <= 0 {
		return ErrInvalidAction
	}
	if remaining > 10*time.Second {
		remaining = 10 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	q, err := wire.NewAppNodeScopedStatus(c.nodeSession(), wire.AppNodeScopedStatusTarget{NodeID: n.NodeID}, n.Grant.Claims.GrantID, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	err = c.sendScopedNew(readCtx, q, n.NodeID, false)
	if readCtx.Err() != nil || !c.cfg.Now().UTC().Before(expires) {
		delete(c.scoped.fresh, n.NodeID+"/grant")
		c.publish()
		if err == nil {
			err = readCtx.Err()
			if err == nil {
				err = context.DeadlineExceeded
			}
		}
	}
	return err
}

func (c *nativeController) initializeScopedNode(ctx context.Context) {
	n := c.selectedScopedNode()
	if n == nil || !c.nodeAccountReady() || c.scopedBusy() || c.hasNodePending() || c.hasPairPending() || c.hasLocalDomainPending() || c.hasThreadGroupPending() {
		return
	}
	if c.scoped.fresh[n.NodeID] == sessionTokenDigest(c.session.SessionToken) {
		return
	}
	_ = c.refreshScopedNodeStatus(ctx)
}

func (c *nativeController) refreshScopedNodeStatus(ctx context.Context) error {
	n := c.selectedScopedNode()
	if n == nil || !c.scopedOperationAllowed(n.NodeID) {
		return ErrInvalidAction
	}
	if !c.scoped.available {
		if err := c.discoverScopedNodes(ctx); err != nil {
			return c.scopedFailure("APP_NODE_UNAVAILABLE")
		}
	}
	if err := c.refreshScopedContext(ctx, n.NodeID); err != nil {
		return err
	}
	if n.Grant != nil {
		q, err := wire.NewAppNodeScopedStatus(c.nodeSession(), wire.AppNodeScopedStatusTarget{NodeID: n.NodeID}, n.Grant.Claims.GrantID, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		if err := c.sendScopedNew(ctx, q, n.NodeID, false); err != nil {
			return err
		}
	}
	c.publish()
	return nil
}

func (c *nativeController) prepareScopedStatusAccess(ctx context.Context) error {
	n := c.selectedScopedNode()
	if n == nil || n.Binding == nil || c.targetSelectionLocked() || !c.scopedOperationAllowed(n.NodeID) {
		return ErrInvalidAction
	}
	if !c.scoped.available {
		if err := c.discoverScopedNodes(ctx); err != nil {
			return err
		}
	}
	if err := c.refreshScopedNodeStatus(ctx); err != nil {
		return err
	}
	if !c.scopedStatusReauthorizationAvailable(n) {
		return ErrInvalidAction
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	q, err := wire.NewAppNodeScopedPrepare(c.nodeSession(), n.Context.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetPrevious, PreviousGrantID: n.LatestGrantID}, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendScopedNew(ctx, q, n.NodeID, false)
}

func (c *nativeController) scopedStatusReauthorizationAvailable(n *scopedNodeRecord) bool {
	if n == nil || n.Grant == nil || n.Context == nil || n.Current == nil || n.ProvenanceID == "" || n.LatestGrantID != n.Grant.Claims.GrantID || n.Current.Authority.GrantID != n.Grant.Claims.GrantID || n.Context.Authority.RootState != wire.RootActiveState || !c.nodeAccountReady() || c.scoped.fresh[n.NodeID] != sessionTokenDigest(c.session.SessionToken) {
		return false
	}
	switch n.Current.Authority.State {
	case wire.AppNodeScopedExpired, wire.AppNodeScopedSessionEnded:
		return true
	case wire.AppNodeScopedCancelled:
		return n.SelfCancelledGrantID == n.LatestGrantID
	case wire.AppNodeScopedActive:
		return n.Grant.Claims.Scope.AccountSessionID != n.Context.Authority.Scope.AccountSessionID
	default:
		return false
	}
}

func (c *nativeController) approveScopedStatusAccess(ctx context.Context, a Action) error {
	n := c.selectedScopedNode()
	if n == nil || n.ReadProposal == nil || n.ReadProposal.Challenge == nil || !a.ConfirmNodeAccess || a.NodeReviewID == "" || a.NodeReviewID != wire.AppNodeScopedClaimsDigest(n.ReadProposal.Challenge.Claims) || c.scopedPending() {
		return ErrInvalidAction
	}
	p := n.ReadProposal
	if !c.scopedScopeSessionMatches(p.Challenge.Claims.Scope) {
		return ErrInvalidAction
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	q, err := wire.NewAppNodeScopedComplete(c.nodeSession(), p.Prepare, p.Packet, *p.Challenge, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	if err := c.sendScopedNew(ctx, q, n.NodeID, false); err != nil {
		return err
	}
	return c.refreshScopedNodeStatus(ctx)
}

func (c *nativeController) cancelScopedStatusAccess(ctx context.Context, review string) error {
	n := c.selectedScopedNode()
	if n == nil || c.scopedPending() || !c.scopedOperationAllowed(n.NodeID) {
		return ErrInvalidAction
	}
	var id string
	var head uint64
	if p := n.ReadProposal; p != nil && p.Challenge != nil {
		if review != wire.AppNodeScopedClaimsDigest(p.Challenge.Claims) {
			return ErrInvalidAction
		}
		id, head = p.Challenge.Claims.GrantID, p.Challenge.Claims.ExpectedHeadVersion
	} else if n.Grant != nil {
		if review != wire.AppNodeScopedClaimsDigest(n.Grant.Claims) {
			return ErrInvalidAction
		}
		id, head = n.Grant.Claims.GrantID, n.Grant.Claims.Scope.HeadVersion
	} else {
		return ErrInvalidAction
	}
	q, err := wire.NewAppNodeScopedCancel(c.nodeSession(), n.NodeID, id, head, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendScopedNew(ctx, q, n.NodeID, false)
}
