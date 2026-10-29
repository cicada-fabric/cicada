package appcore

import (
	"context"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) pairAccountReady() bool {
	return c.selectedScopedNode() == nil && c.nodeConfirmation != nil && c.ownerAccountReady()
}

func (c *nativeController) ownerAccountReady() bool {
	b := c.selectedNodeBinding()
	return c.nodeAccountReady() && b != nil && b.State == "ACTIVE"
}

func (c *nativeController) pairCanStart() bool {
	return c.selectedScopedNode() == nil && c.ownerOperationCanStart()
}

func (c *nativeController) ownerOperationCanStart() bool {
	return c.ownerAccountReady() && !c.storageFault && !c.scopedBusy() && !c.hasPairPending() && !c.hasNodePending() && !c.hasLocalDomainPending() && !c.hasThreadGroupPending() &&
		canBeginOperation(c.state.Pending) && c.state.Recovery == nil
}

func (c *nativeController) pairActor(ctx context.Context) (e2ee.OwnerAppNodeScope, error) {
	if !c.pairAccountReady() || c.selectedScopedNode() != nil {
		return e2ee.OwnerAppNodeScope{}, ErrInvalidAction
	}
	if !c.nodeContextChecked || c.node.Context == nil || c.node.Context.Authority.Scope.AccountSessionExpiresAt != c.session.ExpiresAt {
		if !c.nodeAvailable {
			if err := c.discoverNodeAvailability(ctx); err != nil {
				return e2ee.OwnerAppNodeScope{}, err
			}
		}
		if err := c.refreshNodeContext(ctx); err != nil {
			return e2ee.OwnerAppNodeScope{}, err
		}
	}
	a := c.node.Context.Authority.Scope
	a.HeadVersion = 0 // Pair authority never borrows a Node grant head.
	if wire.ValidateAppNodeScope(a, c.hub) != nil || a.Origin != c.connection.Origin || a.AccountID != c.state.AccountID || a.OwnerID != c.state.OwnerID ||
		a.DeviceID != c.state.DeviceID || a.AccountEpoch != c.session.AccountEpoch || a.DeviceEpoch != c.session.DeviceEpoch ||
		a.AccountSessionExpiresAt != c.session.ExpiresAt || !reflect.DeepEqual(a.OwnerPublic, c.owner.Public()) || !reflect.DeepEqual(a.DevicePublic, c.device.Public()) {
		return e2ee.OwnerAppNodeScope{}, wire.ErrInvalid
	}
	return a, nil
}

func (c *nativeController) pairBootstrapScope(ctx context.Context) (e2ee.OwnerNativePairScope, error) {
	a, err := c.pairActor(ctx)
	if err != nil {
		return e2ee.OwnerNativePairScope{}, err
	}
	scope := e2ee.OwnerNativePairScope{Actor: a, Node: c.nodeConfirmation.Binding}
	if wire.ValidateNativePairBootstrapPreviewScope(scope, c.hub) != nil {
		return e2ee.OwnerNativePairScope{}, wire.ErrInvalid
	}
	return scope, nil
}

func (c *nativeController) pairFullScope(ctx context.Context) (e2ee.OwnerNativePairScope, error) {
	a, err := c.pairActor(ctx)
	if err != nil {
		return e2ee.OwnerNativePairScope{}, err
	}
	var scope e2ee.OwnerNativePairScope
	if len(c.pair.BootstrapProof) != 0 {
		proof, err := e2ee.VerifyOwnerNativePair(c.owner.Public(), c.pair.BootstrapProof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
		if err != nil {
			return scope, err
		}
		scope = proof.Scope
	} else if c.pairReview != nil && c.pairReview.Original.Route.Operation == wire.OperationNativePairBootstrapPrepare {
		receipt, err := c.openPairReceipt(&c.pairReview.Original, c.pairReview.Response.Packet, nil)
		if err != nil || receipt.Bootstrap == nil {
			return scope, wire.ErrInvalid
		}
		scope = receipt.Bootstrap.Scope
	} else {
		return scope, ErrInvalidAction
	}
	if !reflect.DeepEqual(scope.Node, c.nodeConfirmation.Binding) {
		return scope, wire.ErrInvalid
	}
	scope.Actor = a
	if wire.ValidateNativePairScope(scope, c.hub) != nil {
		return scope, wire.ErrInvalid
	}
	return scope, nil
}

func (c *nativeController) pairScopeCurrent(scope e2ee.OwnerNativePairScope) bool {
	if !c.pairAccountReady() || !c.nodeContextChecked || c.node.Context == nil {
		return false
	}
	a := c.node.Context.Authority.Scope
	a.HeadVersion = 0
	return reflect.DeepEqual(scope.Actor, a) && reflect.DeepEqual(scope.Node, c.nodeConfirmation.Binding) &&
		scope.Actor.AccountSessionExpiresAt == c.session.ExpiresAt && scope.Actor.AccountEpoch == c.session.AccountEpoch && scope.Actor.DeviceEpoch == c.session.DeviceEpoch
}

func (c *nativeController) pairClaims(scope e2ee.OwnerNativePairScope, purpose string, end time.Time) (e2ee.OwnerNativePairClaims, wire.NativePairRequestContext, error) {
	now := c.cfg.Now().UTC()
	ctx, err := c.pairRequestContext(scope, now)
	if err != nil {
		return e2ee.OwnerNativePairClaims{}, ctx, err
	}
	if end.IsZero() {
		end = now.Add(time.Minute)
	}
	if session := parseExpiry(scope.Actor.AccountSessionExpiresAt); session.Before(end) {
		end = session
	}
	if !now.Before(end) {
		return e2ee.OwnerNativePairClaims{}, ctx, ErrInvalidAction
	}
	return e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: scope, RequestID: ctx.RequestID,
		Nonce: hex.EncodeToString(ctx.ClientNonce), IssuedAt: ctx.IssuedAt, ExpiresAt: end.UTC().Format(time.RFC3339Nano)}, ctx, nil
}
