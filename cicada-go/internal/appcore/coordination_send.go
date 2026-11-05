package appcore

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func coordinationResultSettles(result *wire.ThreadCollaborationOwnerResult) bool {
	return result != nil && (result.State == "COMPLETED" || result.State == "REJECTED" || result.State == "ORIGINAL_NOT_APPLIED")
}

func coordinationResponseRecord(request *coordinationRecord, raw []byte, now time.Time) *coordinationRecord {
	return &coordinationRecord{Format: "cicada.app-thread-collaboration.response.v1", Vault: request.Vault, DeviceKeyID: request.DeviceKeyID, OwnerKeyID: request.OwnerKeyID, Route: request.Route, ParentDigest: request.Digest, Digest: wire.ThreadCollaborationOwnerPacketDigest(raw), CreatedAt: now.UTC().Format(time.RFC3339Nano), Packet: append([]byte(nil), raw...)}
}

// Check every future durable carrier before the first POST, including a maximum
// receipt and an independently sealed reconcile wrapper. No reserve is sent.
func (c *nativeController) coordinationBudget(ctx context.Context, record *coordinationRecord) error {
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	query, err := wire.NewThreadCollaborationOwnerReconcile(c.nodeSession(), scope, record.Packet, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	reserve, err := c.newCoordinationRecord(query, nil)
	if err != nil {
		return err
	}
	defer clearCoordinationRecord(reserve)
	response := coordinationResponseRecord(record, make([]byte, wire.MaxThreadCollaborationOwnerPacketBytes), c.cfg.Now().UTC())
	defer clearCoordinationRecord(response)
	response.Digest = strings.Repeat("0", 64)
	queryResponse := coordinationResponseRecord(reserve, make([]byte, wire.MaxThreadCollaborationReconcilePacketBytes), c.cfg.Now().UTC())
	defer clearCoordinationRecord(queryResponse)
	updates := map[string][]byte{}
	defer func() {
		for _, raw := range updates {
			clear(raw)
		}
	}()
	for _, pair := range []struct {
		index  int
		record *coordinationRecord
	}{{coordinationOriginal, record}, {coordinationResponse, response}, {coordinationQuery, reserve}, {coordinationQueryResponse, queryResponse}} {
		raw, err := encodeCoordinationRecord(pair.record)
		if err != nil {
			return err
		}
		updates[coordinationNamespaces[pair.index]] = raw
	}
	// A future login may lengthen canonical epoch/time fields in the query.
	updates[coordinationNamespaces[coordinationQuery]] = append(updates[coordinationNamespaces[coordinationQuery]], make([]byte, 4096)...)
	if record.Route.Operation == wire.OperationThreadCollaborationOwnerPrepare {
		raw, err := encodeCoordinationReview(record, response)
		if err != nil {
			return err
		}
		updates[coordinationNamespaces[coordinationReview]] = raw
	} else if record.Route.Operation == wire.OperationThreadCollaborationOwnerApply {
		updates[coordinationNamespaces[coordinationReview]] = nil
	}
	if err := c.vault.CheckStateUpdates(updates); err != nil {
		return err
	}
	clear(updates[coordinationNamespaces[coordinationReview]])
	delete(updates, coordinationNamespaces[coordinationReview])
	return c.vault.CheckStateUpdates(updates)
}

func (c *nativeController) sendCoordination(ctx context.Context, request any, review *wire.ThreadCollaborationOwnerReview) error {
	r, err := c.newCoordinationRecord(request, review)
	if err != nil {
		return err
	}
	if c.hasCoordinationPending() || c.validateCoordinationRecord(r) != nil {
		clearCoordinationRecord(r)
		return ErrInvalidAction
	}
	if err := c.coordinationBudget(ctx, r); err != nil {
		clearCoordinationRecord(r)
		return c.failCoordination("APP_COORDINATION_STORAGE_BUDGET", err)
	}
	// Retire old observations first; no uncertain business original exists yet.
	for _, index := range []int{coordinationResponse, coordinationQueryResponse, coordinationQuery} {
		if err := c.persistCoordinationRecord(index, nil); err != nil {
			clearCoordinationRecord(r)
			return err
		}
	}
	if err := c.persistCoordinationRecord(coordinationOriginal, r); err != nil {
		clearCoordinationRecord(r)
		return err
	}
	g := &c.coordination
	for _, old := range []*coordinationRecord{g.original, g.response, g.query, g.queryResponse} {
		clearCoordinationRecord(old)
	}
	g.original, g.response, g.query = r, nil, nil
	g.queryResponse = nil
	g.view.ErrorCode, g.view.Outcome = "", ""
	if r.Route.Operation != wire.OperationThreadCollaborationOwnerRead {
		g.observations = nil
	}
	if r.Route.Operation == wire.OperationThreadCollaborationOwnerApply {
		if err := c.dismissCoordinationReview(); err != nil {
			return err
		}
	}
	c.publish()
	raw, err := c.postCoordinationPacket(ctx, r)
	if err != nil {
		return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", err)
	}
	defer clear(raw)
	return c.acceptCoordinationReceipt(r, raw, true)
}

func (c *nativeController) acceptCoordinationReceipt(record *coordinationRecord, raw []byte, fresh bool) error {
	result, err := c.openCoordinationResult(record, raw)
	if err != nil || !coordinationResultSettles(result) {
		return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", errCoordinationUnconfirmed)
	}
	response := coordinationResponseRecord(record, raw, c.cfg.Now().UTC())
	if err := c.persistCoordinationRecord(coordinationResponse, response); err != nil {
		clearCoordinationRecord(response)
		return err
	}
	clearCoordinationRecord(c.coordination.response)
	c.coordination.response = response
	if err := c.applyCoordinationResult(record, result, fresh); err != nil {
		return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", err)
	}
	copy := *record
	copy.Applied = true
	if err := c.persistCoordinationRecord(coordinationOriginal, &copy); err != nil {
		return err
	}
	record.Applied = true
	// Queries may be replaced only after this exact original has settled.
	if err := c.persistCoordinationRecord(coordinationQueryResponse, nil); err != nil {
		return err
	}
	clearCoordinationRecord(c.coordination.queryResponse)
	c.coordination.queryResponse = nil
	if err := c.persistCoordinationRecord(coordinationQuery, nil); err != nil {
		return err
	}
	clearCoordinationRecord(c.coordination.query)
	c.coordination.query = nil
	c.publish()
	if result.ErrorCode != "" {
		return errCoordinationUnconfirmed
	}
	return nil
}

func (c *nativeController) applyCoordinationResult(record *coordinationRecord, result *wire.ThreadCollaborationOwnerResult, fresh bool) error {
	g := &c.coordination
	g.view.ErrorCode = result.ErrorCode
	if result.ErrorCode != "" {
		g.observations = nil
		return nil
	}
	request, err := c.coordinationDTO(record)
	if err != nil {
		return err
	}
	switch q := request.(type) {
	case wire.ThreadCollaborationOwnerReadRequest:
		_, token, proof := coordinationParts(q)
		claims, err := e2eeCoordinationClaims(c, proof, record.Route.Operation)
		observed := parseExpiry(result.ObservedAt)
		if err != nil || result.Read == nil {
			return wire.ErrInvalid
		}
		if !fresh || !bytes.Equal(token, c.session.SessionToken) || !c.cfg.Now().UTC().Before(parseExpiry(claims.ExpiresAt)) {
			return nil
		}
		lower, upper := parseExpiry(q.Context.IssuedAt).Add(-30*time.Second), c.cfg.Now().UTC().Add(30*time.Second)
		readObserved := parseExpiry(result.Read.ObservedAt)
		if observed.Before(lower) || observed.After(upper) || readObserved.Before(lower) || readObserved.After(upper) {
			return wire.ErrInvalid
		}
		end := minCoordinationTime(c.cfg.Now().UTC().Add(30*time.Second), parseExpiry(claims.ExpiresAt))
		kept := g.observations[:0]
		for _, prior := range g.observations {
			same := prior.Read.View == result.Read.View && prior.TargetEndpoint == q.Body.EndpointID && (prior.Read.Group == nil && result.Read.Group == nil || prior.Read.Group != nil && result.Read.Group != nil && prior.Read.Group.GroupID == result.Read.Group.GroupID)
			if c.coordinationReadCurrent(prior) && !same {
				kept = append(kept, prior)
			}
		}
		g.observations = append(kept, coordinationObservation{Read: *result.Read, SessionDigest: sessionTokenDigest(token), FreshUntil: end.Format(time.RFC3339Nano), TargetEndpoint: q.Body.EndpointID})
	case wire.ThreadCollaborationOwnerPrepareRequest:
		if result.Review == nil || g.response == nil {
			return wire.ErrInvalid
		}
		// The shared verifier checks prepared bytes, review lifetime and exact
		// original packet before the UI can offer a confirmation.
		if fresh && wire.ValidateThreadCollaborationOwnerReview(q, record.Packet, *result.Review, c.hub, c.cfg.Now().UTC()) != nil {
			return wire.ErrInvalid
		}
		raw, err := encodeCoordinationReview(record, g.response)
		if err != nil {
			return err
		}
		defer clear(raw)
		if err := c.persistCoordinationSlot(coordinationReview, raw); err != nil {
			return err
		}
		original, response, err := decodeCoordinationReview(raw)
		if err != nil {
			return err
		}
		clearCoordinationRecord(g.reviewOriginal)
		clearCoordinationRecord(g.reviewResponse)
		g.reviewOriginal, g.reviewResponse, g.review = original, response, result.Review
	case wire.ThreadCollaborationOwnerApplyRequest:
		// A confirmed mutation is not a fresh directory or ownership read.
		if result.State == "COMPLETED" && record.Review != nil {
			g.view.Outcome = record.Review.Action
		}
		g.observations = nil
	}
	return nil
}

func minCoordinationTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (c *nativeController) dismissCoordinationReview() error {
	if err := c.persistCoordinationSlot(coordinationReview, nil); err != nil {
		return err
	}
	g := &c.coordination
	clearCoordinationRecord(g.reviewOriginal)
	clearCoordinationRecord(g.reviewResponse)
	g.reviewOriginal, g.reviewResponse, g.review = nil, nil, nil
	return nil
}

func (c *nativeController) failCoordination(code string, err error) error {
	if code == "ORIGINAL_OUTCOME_UNCERTAIN" {
		c.coordination.observations = nil
	}
	c.coordination.view.ErrorCode = code
	c.publish()
	return err
}

func (c *nativeController) recoverCoordination(ctx context.Context) error {
	if !c.hasCoordinationPending() || !c.ownerAccountReady() || c.storageFault || c.hasNodePending() || c.hasThreadGroupPending() || !canBeginOperation(c.state.Pending) {
		return ErrInvalidAction
	}
	g := &c.coordination
	if g.queryResponse != nil {
		result, err := c.openCoordinationResult(g.query, g.queryResponse.Packet)
		if err != nil {
			return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", err)
		}
		return c.finishCoordinationFence(result)
	}
	if err := c.refreshCoordinationQueryLogin(ctx); err != nil {
		return err
	}
	if g.response != nil {
		return c.acceptCoordinationReceipt(g.original, g.response.Packet, false)
	}
	raw, err := c.postCoordinationPacket(ctx, g.original)
	if err == nil {
		defer clear(raw)
		if result, e := c.openCoordinationResult(g.original, raw); e == nil && coordinationResultSettles(result) {
			return c.acceptCoordinationReceipt(g.original, raw, false)
		}
	}
	if g.query == nil {
		scope, err := c.localCollaborationActor(ctx)
		if err != nil {
			return err
		}
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		q, err := wire.NewThreadCollaborationOwnerReconcile(c.nodeSession(), scope, g.original.Packet, owner, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		r, err := c.newCoordinationRecord(q, nil)
		if err != nil {
			return err
		}
		if err := c.persistCoordinationRecord(coordinationQuery, r); err != nil {
			clearCoordinationRecord(r)
			return err
		}
		g.query = r
	}
	raw, err = c.postCoordinationPacket(ctx, g.query)
	if err != nil {
		return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", err)
	}
	defer clear(raw)
	result, err := c.openCoordinationResult(g.query, raw)
	if err != nil {
		return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", errCoordinationUnconfirmed)
	}
	if result.State == "ORIGINAL_RECEIPT" {
		return c.acceptCoordinationReceipt(g.original, result.ReceiptPacket, false)
	}
	if result.State == "ORIGINAL_NOT_APPLIED" {
		// The authenticated common contract's permanent no-effect fence names
		// this exact original. It is not an unsigned HTTP failure.
		response := coordinationResponseRecord(g.query, raw, c.cfg.Now().UTC())
		if err := c.persistCoordinationRecord(coordinationQueryResponse, response); err != nil {
			clearCoordinationRecord(response)
			return err
		}
		g.queryResponse = response
		return c.finishCoordinationFence(result)
	}
	return c.failCoordination("ORIGINAL_OUTCOME_UNCERTAIN", errCoordinationUnconfirmed)
}

// A newly verified login may replace only its read-only reconcile wrapper.
// Timeouts or HTTP errors never reseal the original or manufacture new scope.
func (c *nativeController) refreshCoordinationQueryLogin(ctx context.Context) error {
	g := &c.coordination
	if g.query == nil {
		return nil
	}
	q, err := c.coordinationDTO(g.query)
	if err != nil {
		return err
	}
	_, token, proof := coordinationParts(q)
	if bytes.Equal(token, c.session.SessionToken) {
		return nil
	}
	if !c.ownerAccountReady() || !c.sessionInspected || c.sessionNeedsCheck {
		return ErrInvalidAction
	}
	claims, err := e2eeCoordinationClaims(c, proof, g.query.Route.Operation)
	if err != nil {
		return err
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
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewThreadCollaborationOwnerReconcile(c.nodeSession(), scope, g.original.Packet, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	next, err := c.newCoordinationRecord(request, nil)
	if err != nil {
		return err
	}
	if err := c.persistCoordinationRecord(coordinationQuery, next); err != nil {
		clearCoordinationRecord(next)
		return err
	}
	clearCoordinationRecord(g.query)
	g.query = next
	return nil
}

func (c *nativeController) finishCoordinationFence(result *wire.ThreadCollaborationOwnerResult) error {
	if result.State != "ORIGINAL_NOT_APPLIED" {
		return wire.ErrInvalid
	}
	g := &c.coordination
	copy := *g.original
	copy.Applied = true
	if err := c.persistCoordinationRecord(coordinationOriginal, &copy); err != nil {
		return err
	}
	g.original.Applied = true
	g.view.ErrorCode = result.ErrorCode
	c.publish()
	return errCoordinationUnconfirmed
}
