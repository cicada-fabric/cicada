package appcore

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func threadGroupResultSettles(record *threadGroupRecord, r *wire.OwnerEndpointGroupsResult) bool {
	if r == nil || r.ErrorCode == "OUTCOME_UNCERTAIN" {
		return false
	}
	if record.Route.Operation == wire.OperationOwnerEndpointGroupsApply {
		return r.Operation != nil && (r.Operation.State == "COMPLETED" || r.Operation.State == "REJECTED_FENCED") || r.State == "REJECTED_FENCED"
	}
	return r.State == "COMPLETED" || r.State == "REJECTED_FENCED" || r.State == "READ_EXPIRED" || r.State == "PREPARED" && r.Review != nil
}

func threadGroupResponseRecord(request *threadGroupRecord, packet []byte) *threadGroupRecord {
	return &threadGroupRecord{Format: "cicada.app-endpoint-groups.response.v1", Vault: request.Vault, DeviceKeyID: request.DeviceKeyID, OwnerKeyID: request.OwnerKeyID,
		NodeID: request.NodeID, NetworkID: request.NetworkID, Route: request.Route, ParentDigest: request.Digest, Digest: strings.Repeat("0", 64),
		CreatedAt: "2026-10-26T00:00:00.999999999Z", Packet: packet}
}

// Reserve space for the exact original, its largest legal response and a real
// PQ recovery request plus the bounded recovery response. Reserve bytes carry
// no credentials/authority and are never persisted as protocol responses.
func (c *nativeController) threadGroupBudget(record, recovery *threadGroupRecord) error {
	updates := make(map[int][]byte)
	defer func() {
		for _, raw := range updates {
			clear(raw)
		}
	}()
	var err error
	updates[threadGroupOriginal], err = encodeThreadGroupRecord(record)
	if err != nil {
		return err
	}
	responseReserve := threadGroupResponseRecord(record, make([]byte, wire.MaxOwnerEndpointGroupsPacketBytes))
	defer clear(responseReserve.Packet)
	updates[threadGroupResponse], err = encodeThreadGroupRecord(responseReserve)
	if err != nil {
		return err
	}
	updates[threadGroupRecovery], err = encodeThreadGroupRecord(recovery)
	if err != nil {
		return err
	}
	// The retained target/keys are fixed. This bounds growth of canonical UTC
	// strings and uint64 authority coordinates in a later fresh login wrapper;
	// no authorization bytes from this reservation are written or transmitted.
	updates[threadGroupRecovery] = append(updates[threadGroupRecovery], make([]byte, 4096)...)
	recoveryReserve := threadGroupResponseRecord(recovery, make([]byte, wire.MaxOwnerEndpointGroupsReconcilePacketBytes))
	defer clear(recoveryReserve.Packet)
	updates[threadGroupRecoveryResponse], err = encodeThreadGroupRecord(recoveryReserve)
	if err != nil {
		return err
	}
	if record.Route.Operation == wire.OperationOwnerEndpointGroupsPrepare {
		updates[threadGroupState], err = c.threadGroupReviewBytes(record, responseReserve)
	} else if record.Route.Operation == wire.OperationOwnerEndpointGroupsApply {
		// The exact verified review is already embedded in the new apply
		// record. Its settled prepare packets can be released after that
		// apply record commits, before any POST.
		updates[threadGroupState], err = c.threadGroupReviewBytes(nil, nil)
	} else {
		updates[threadGroupState], err = c.threadGroupReviewBytes(c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse)
	}
	if err != nil {
		return err
	}
	return c.preflightThreadGroups(updates)
}

func (c *nativeController) makeThreadGroupRecovery(record *threadGroupRecord, scope e2ee.OwnerAppNodeScope) (*threadGroupRecord, error) {
	owner, err := c.owner.E2EE()
	if err != nil {
		return nil, err
	}
	request, err := wire.NewOwnerEndpointGroupsReconcile(c.nodeSession(), scope, record.Packet, owner, c.cfg.Now().UTC())
	if err != nil {
		return nil, err
	}
	return c.newThreadGroupRecord(request, record)
}

func (c *nativeController) beginThreadGroupOriginal(record *threadGroupRecord) error {
	if c.hasThreadGroupPending() || c.validateThreadGroupRecord(record, nil) != nil {
		return ErrInvalidAction
	}
	// The budget wrapper is constructed before I/O, and does not replace the
	// wrapper that will be persisted with the then-current login for recovery.
	request, err := c.threadGroupDTO(record, nil)
	if err != nil {
		return err
	}
	_, proof := threadGroupRequestParts(request)
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(record.Route.Operation), time.Time{})
	if err != nil {
		return err
	}
	recovery, err := c.makeThreadGroupRecovery(record, claims.Scope)
	if err != nil {
		return err
	}
	defer clear(recovery.Packet)
	defer clear(recovery.DTO)
	if err := c.threadGroupBudget(record, recovery); err != nil {
		return c.failThreadGroups("APP_THREAD_GROUP_STORAGE_BUDGET", err)
	}
	for _, index := range []int{threadGroupRecoveryResponse, threadGroupRecovery, threadGroupResponse} {
		if err := c.persistThreadGroupRecord(index, nil); err != nil {
			return err
		}
	}
	if err := c.persistThreadGroupRecord(threadGroupOriginal, record); err != nil {
		return err
	}
	for _, old := range []*threadGroupRecord{c.threadGroups.original, c.threadGroups.response, c.threadGroups.recovery, c.threadGroups.recoveryResponse} {
		if old != nil {
			clear(old.Packet)
			clear(old.DTO)
		}
	}
	c.threadGroups.original, c.threadGroups.response, c.threadGroups.recovery, c.threadGroups.recoveryResponse = record, nil, nil, nil
	if record.Route.Operation == wire.OperationOwnerEndpointGroupsApply {
		if err := c.persistThreadGroupReview(nil, nil); err != nil {
			return err
		}
		c.threadGroups.review, c.threadGroups.view.Review = nil, nil
	}
	c.threadGroups.view.Current = false
	c.threadGroups.view.ErrorCode, c.threadGroups.view.Outcome = "", ""
	c.publish()
	return nil
}

func (c *nativeController) sendThreadGroup(ctx context.Context, request any, seed *threadGroupRecord) error {
	record, err := c.newThreadGroupRecord(request, seed)
	if err != nil {
		return err
	}
	if err := c.beginThreadGroupOriginal(record); err != nil {
		clear(record.Packet)
		clear(record.DTO)
		return err
	}
	raw, err := c.postThreadGroupPacket(ctx, record)
	if err != nil {
		return c.failThreadGroups("OUTCOME_UNCERTAIN", err)
	}
	defer clear(raw)
	result, err := c.openThreadGroupResult(record, raw, nil)
	if err != nil {
		return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
	}
	response, err := c.saveThreadGroupResponse(threadGroupResponse, record, raw)
	if err != nil {
		return err
	}
	c.threadGroups.response = response
	return c.finishThreadGroup(record, result, true)
}

func (c *nativeController) finishThreadGroup(record *threadGroupRecord, result *wire.OwnerEndpointGroupsResult, fresh bool) error {
	if !threadGroupResultSettles(record, result) {
		return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
	}
	if err := c.applyThreadGroupReceipt(record, result, fresh); err != nil {
		return err
	}
	copy := *record
	copy.Applied = true
	if err := c.persistThreadGroupRecord(threadGroupOriginal, &copy); err != nil {
		return err
	}
	c.threadGroups.original = &copy
	c.publish()
	if result.ErrorCode != "" {
		return c.failThreadGroups(result.ErrorCode, ErrInvalidAction)
	}
	if c.threadGroups.view.ErrorCode != "" {
		return ErrInvalidAction
	}
	return nil
}

func (c *nativeController) threadGroupRequestCurrent(record *threadGroupRecord) bool {
	if !c.pairAccountReady() || record.NodeID != c.nodeConfirmation.Binding.NodeID {
		return false
	}
	request, err := c.threadGroupDTO(record, nil)
	if err != nil {
		return false
	}
	qctx, proof := threadGroupRequestParts(request)
	var token []byte
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		token = q.SessionToken
	case wire.OwnerEndpointGroupsPrepareRequest:
		token = q.SessionToken
	default:
		return false
	}
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(record.Route.Operation), time.Time{})
	return err == nil && qctx.AccountEpoch == c.session.AccountEpoch && qctx.DeviceEpoch == c.session.DeviceEpoch &&
		bytes.Equal(token, c.session.SessionToken) && claims.Scope.AccountSessionExpiresAt == c.session.ExpiresAt && c.cfg.Now().UTC().Before(parseExpiry(claims.ExpiresAt))
}

// A historical prepare is verified at its original observation time on load;
// live use additionally needs the original account session and short deadline.
func (c *nativeController) threadGroupReviewCurrent(record *threadGroupRecord) bool {
	node, network := c.threadGroupScope()
	return record != nil && record.NodeID == node && record.NetworkID == network && c.threadGroups.review != nil && c.threadGroupRequestCurrent(record) && c.cfg.Now().UTC().Before(parseExpiry(c.threadGroups.review.ExpiresAt))
}
