package appcore

import (
	"context"
	"strings"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) dispatchScopedNode(ctx context.Context, a Action) (bool, error) {
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifetime, cancel)
	defer func() { stop(); cancel() }()
	ctx = op
	switch a.Kind {
	case ActionBeginAddNode:
		return true, c.beginAddNode(ctx)
	case ActionEndAddNode:
		if !c.scoped.adding || c.scopedBusy() {
			return true, ErrInvalidAction
		}
		c.scoped.adding = false
		c.publish()
		return true, nil
	case ActionReviewNodePairing:
		if strings.HasPrefix(strings.TrimSpace(a.DevicePairingCode), wire.NodePairTrustScopedCodePrefix) {
			return true, c.reviewScopedNodePairing(ctx, a.DevicePairingCode)
		}
		// An explicit scoped draft never silently downgrades to legacy trust.
		if c.scoped.adding || c.scopedBusy() {
			return true, ErrInvalidAction
		}
	case ActionRecoverNodePairing, ActionRecoverNode:
		if c.scopedPending() {
			return true, c.recoverScopedNode(ctx)
		}
	case ActionApproveNodePairing:
		if c.scopedBusy() {
			return true, c.approveScopedPairing(ctx, a.NodePairingReviewID, a.ConfirmNodePairing)
		}
	case ActionRefreshNodePairing:
		if c.scopedBusy() {
			err := c.refreshScopedPairing(ctx)
			if err == nil {
				err = c.completeScopedAction(ctx)
			}
			return true, err
		}
	case ActionCancelNodePairing:
		if c.scopedBusy() {
			err := c.cancelScopedPairing(ctx, a.NodePairingReviewID)
			if err == nil {
				err = c.completeScopedAction(ctx)
			}
			return true, err
		}
	}
	if c.selectedScopedNode() != nil {
		switch a.Kind {
		case ActionRefreshNode:
			return true, c.refreshScopedNodeStatus(ctx)
		case ActionReauthorizeNodeStatus:
			return true, c.prepareScopedStatusAccess(ctx)
		case ActionApproveNode:
			return true, c.approveScopedStatusAccess(ctx, a)
		case ActionCancelNodeAccess:
			return true, c.cancelScopedStatusAccess(ctx, a.NodeReviewID)
		}
		// The finite legacy Pair and old inventory contracts retain their own
		// original Node. Scope2 never borrows their legacy authority.
		if nodeActionKind(a.Kind) || pairActionKind(a.Kind) || ownerEndpointActionKind(a.Kind) {
			return true, ErrInvalidAction
		}
	}
	return false, nil
}
