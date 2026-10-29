package appcore

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Reconcile/status cannot execute the business original. An independently
// verified new login may therefore replace only this read-only observation.
// Its original ciphertext/ID/review remain immutable and pending throughout.
func (c *nativeController) refreshThreadGroupQuerySession(ctx context.Context) error {
	g := &c.threadGroups
	if g.recovery == nil || g.recoveryResponse != nil {
		return nil
	}
	request, err := c.threadGroupDTO(g.recovery, g.original)
	if err != nil {
		return err
	}
	var token []byte
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReconcileRequest:
		token = q.SessionToken
	case wire.OwnerEndpointGroupsStatusRequest:
		token = q.SessionToken
	default:
		return ErrInvalidAction
	}
	if bytes.Equal(token, c.session.SessionToken) {
		return nil // No local timeout or HTTP error can manufacture a new login.
	}
	if !c.ownerAccountReady() || !c.sessionInspected || c.sessionNeedsCheck {
		return ErrInvalidAction
	}
	_, proof := threadGroupRequestParts(request)
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(g.recovery.Route.Operation), time.Time{})
	if err != nil {
		return err
	}
	// Always authenticate a current authority scope, even if two logins happen
	// to have the same deadline. Only session ID and expiry may differ here.
	if c.selectedScopedNode() == nil {
		if !c.nodeAvailable {
			if err := c.discoverNodeAvailability(ctx); err != nil {
				return err
			}
		}
		if err := c.refreshNodeContext(ctx); err != nil {
			return err
		}
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	prior := claims.Scope
	if prior.AccountSessionID == scope.AccountSessionID {
		return ErrInvalidAction
	}
	prior.AccountSessionID, prior.AccountSessionExpiresAt = scope.AccountSessionID, scope.AccountSessionExpiresAt
	if !reflect.DeepEqual(prior, scope) {
		return ErrInvalidAction
	}
	var next *threadGroupRecord
	if g.recovery.Route.Operation == wire.OperationOwnerEndpointGroupsStatus {
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		q, err := wire.NewOwnerEndpointGroupsStatus(c.nodeSession(), scope, g.original.Packet, owner, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		next, err = c.newThreadGroupRecord(q, g.original)
		if err != nil {
			return err
		}
	} else {
		next, err = c.makeThreadGroupRecovery(g.original, scope)
		if err != nil {
			return err
		}
	}
	if err = c.validateThreadGroupRecord(next, g.original); err == nil {
		err = c.threadGroupBudget(g.original, next)
	}
	if err == nil {
		err = c.persistThreadGroupRecord(threadGroupRecovery, next)
	}
	if err != nil {
		clear(next.Packet)
		clear(next.DTO)
		return err
	}
	clear(g.recovery.Packet)
	clear(g.recovery.DTO)
	g.recovery = next
	c.publish()
	return nil
}
