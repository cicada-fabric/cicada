package appcore

import (
	"bytes"
	"context"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) observeFencedNodePairing(ctx context.Context) error {
	t := c.node.PairTrust
	op := t.FencedOperation
	if op == "" || c.nodePairTrustPending() || !c.nodeAccountReady() {
		return ErrInvalidAction
	}
	if t.Context == nil {
		scope, err := c.nodePairingObservationScope(ctx)
		if err != nil {
			return err
		}
		q := wire.NodePairTrustOwnerLookup{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: scope,
			Selector: t.Code.Selector, ContextDigest: t.Code.ContextDigest, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
		if err := c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustLookup, q); err != nil {
			return err
		}
	} else if err := c.observeNodePairing(ctx); err != nil {
		return err
	}
	if t.Pending == nil || !t.Pending.Applied {
		return ErrInvalidAction
	}
	result, err := c.openNodePairTrustResponse(t.Pending, t.Pending.Response)
	if err != nil || !c.freshObservation(result.ObservedAt) || (result.ErrorCode != "" && !pairTrustDefiniteRejection(result)) {
		return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
	}
	if pairTrustTerminal(t.Stage) {
		t.FencedOperation = ""
		if err := c.persistNode(); err != nil {
			return err
		}
		return c.finishTerminalNodePairing(ctx)
	}
	if t.Stage == wire.NodePairTrustACKed || (t.Stage == wire.NodePairTrustOwnerApproved && op != wire.OperationOwnerNodePairTrustCancel) {
		t.FencedOperation = ""
		return c.persistNode()
	}
	// A known no-effect mutation may be sent again only under the original
	// consent/deadlines. Existing S, proof, E and reserved packet stay identical.
	t.FencedOperation = ""
	if op == wire.OperationOwnerNodePairTrustPrepare || op == wire.OperationOwnerNodePairTrustComplete {
		t.Stage = "APPROVING"
	} else if op == wire.OperationOwnerNodePairTrustLookup {
		t.Stage = "LOOKUP"
	}
	if err := c.persistNode(); err != nil {
		return err
	}
	if op == wire.OperationOwnerNodePairTrustCancel {
		return c.cancelNodePairing(ctx, c.nodePairingReviewID())
	}
	if t.Stage == "LOOKUP" || t.Stage == "APPROVING" {
		return c.refreshNodePairing(ctx)
	}
	c.publish()
	return nil
}

// Close only this failed INITIAL ceremony. A terminal side-state never settles
// Client counters; its exact authenticated negative receipt must be applied
// first. Existing/confirmed grants and other Node bindings are never cancelled.
func (c *nativeController) finishTerminalNodePairing(ctx context.Context) error {
	if !c.nodePairTrustNeedsCleanup() {
		c.publish()
		return nil
	}
	t := c.node.PairTrust
	if t.Confirmation != nil && !t.Confirmation.Applied {
		if err := c.recoverReservedNodeConfirmation(ctx); err != nil {
			return err
		}
	}
	if !c.nodeAccountReady() || c.hasNodePending() || c.nodePairTrustPending() {
		c.publish()
		return nil
	}
	if c.nodeConfirmation != nil || c.node.ProvenanceID != "" {
		return wire.ErrInvalid
	}
	var challenge *wire.AppNodeChallenge
	if c.node.Proposal != nil {
		challenge = c.node.Proposal.Challenge
	}
	if c.node.Grant != nil {
		if challenge != nil && challenge.Claims.GrantID != c.node.Grant.Claims.GrantID {
			return wire.ErrInvalid
		}
		challenge = c.node.Grant
	}
	if challenge == nil {
		t.CleanupComplete = true
		return c.persistNode()
	}
	g := challenge.Claims
	if g.Profile != wire.AppNodeProfileInitial || !reflect.DeepEqual(g.Candidate, t.Context.Candidate) || !reflect.DeepEqual(g.Scope, t.Scope) ||
		(t.Confirmation != nil && t.Confirmation.GrantID != g.GrantID) || (t.Approval != nil && t.Approval.GrantID != g.GrantID) {
		return wire.ErrInvalid
	}
	if err := c.refreshNodePairingContext(ctx); err != nil {
		return err
	}
	if err := c.refreshNode(ctx); err != nil {
		return err
	}
	r := c.node.Current
	settled := r != nil && r.Authority.GrantID == g.GrantID && (r.Authority.State == wire.AppNodeExpired || r.Authority.State == wire.AppNodeCancelled || r.Authority.State == wire.AppNodeSessionEnded)
	if !settled {
		if err := c.cancelNodeAccess(ctx, wire.AppNodeClaimsDigest(g)); err != nil {
			return err
		}
		if err := c.refreshNodePairingContext(ctx); err != nil {
			return err
		}
		if err := c.refreshNode(ctx); err != nil {
			return err
		}
	}
	if !c.nodeContextChecked || !c.nodeCanStartInitial() {
		return ErrInvalidAction
	}
	t.CleanupComplete = true
	if err := c.persistNode(); err != nil {
		return err
	}
	c.publish()
	return nil
}
