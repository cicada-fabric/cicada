package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type HubEndpointGroupsInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Body              any
	At                time.Time
	Now               func() time.Time
	Original          *HubEndpointGroupsInput
	OriginalSeal      HubEndpointGroupsSeal
}

type HubEndpointGroupsSeal func(any) ([]byte, error)

const endpointGroupsOwnerReadLifetime = 5 * time.Minute

var ErrHubEndpointGroupsOutcomeUncertain = errors.New("OUTCOME_UNCERTAIN")

var errEndpointGroupsOwnerUncertain = ErrHubEndpointGroupsOutcomeUncertain

type endpointGroupsOwnerReceipt struct {
	packet    []byte
	state     string
	operation *wire.OwnerEndpointGroupsOperation
	durable   bool
	noEffects bool
}

type endpointGroupsOwnerRequest struct {
	op     string
	c      wire.AppNodeRequestContext
	token  []byte
	proof  []byte
	claims e2ee.OwnerEndpointGroupsRequestClaims
	digest string
	nonce  string
}

func endpointGroupsOwnerFields(body any) (op string, c wire.AppNodeRequestContext, token, proof []byte, err error) {
	switch q := body.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		return wire.OperationOwnerEndpointGroupsRead, q.Context, q.SessionToken, q.OwnerProof, nil
	case wire.OwnerEndpointGroupsPrepareRequest:
		return wire.OperationOwnerEndpointGroupsPrepare, q.Context, q.SessionToken, q.OwnerProof, nil
	case wire.OwnerEndpointGroupsApplyRequest:
		return wire.OperationOwnerEndpointGroupsApply, q.Context, q.SessionToken, q.OwnerProof, nil
	case wire.OwnerEndpointGroupsStatusRequest:
		return wire.OperationOwnerEndpointGroupsStatus, q.Context, q.SessionToken, q.OwnerProof, nil
	case wire.OwnerEndpointGroupsReconcileRequest:
		return wire.OperationOwnerEndpointGroupsReconcile, q.Context, q.SessionToken, q.OwnerProof, nil
	}
	return "", c, nil, nil, ErrHubAccountRejected
}

// The Hub service has already opened the envelope. The Store repeats all
// public route/body/proof checks and resolves the signer from retained records.
func endpointGroupsOwnerInput(tx *sql.Tx, in HubEndpointGroupsInput) (endpointGroupsOwnerRequest, error) {
	op, c, token, proof, err := endpointGroupsOwnerFields(in.Body)
	if err != nil || in.At.IsZero() || wire.ValidateOwnerEndpointGroupsRequest(in.Body, in.Hub, time.Time{}) != nil {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	packet, err := wire.PreflightRequest(in.Packet, op)
	_, route, re := wire.RequestRoute(in.Hub, c.OwnerID, c.DeviceID, c.RequestID, op, wire.HandshakeEpoch, in.Device)
	if err != nil || re != nil || packet.Packet.Route != route || !reflect.DeepEqual(packet.SenderPublicIdentity, in.Device) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	var p e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(proof, &p) != nil || p.Claims.Scope.OwnerID != c.OwnerID || p.Claims.Scope.AccountID != c.AccountID || !reflect.DeepEqual(p.Claims.Scope.DevicePublic, in.Device) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, c.OwnerID, p.Claims.Scope.OwnerPublic.ID))
	if err != nil || !reflect.DeepEqual(key.Public, p.Claims.Scope.OwnerPublic) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(key.Public, proof, wire.OwnerEndpointGroupsOwnerPurpose(op), time.Time{})
	if err != nil {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	return endpointGroupsOwnerRequest{op: op, c: c, token: token, proof: proof, claims: claims, digest: wire.OwnerEndpointGroupsPacketDigest(in.Packet), nonce: AccountDigest("owner-endpoint-groups-nonce", c.ClientNonce)}, nil
}

// This deliberately does not require current Root authority: status and
// reconciliation may recover old encrypted receipts after Root revocation.
// It still requires the actual currently active, enrolled account/device.
func endpointGroupsOwnerAccountCurrentTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerEndpointGroupsRequestClaims, at time.Time) bool {
	if a == nil || a.session == nil || !appNodeSameSecurity(a.scope, claims.Scope) || a.session.ID != claims.Scope.AccountSessionID || a.session.ExpiresAt != claims.Scope.AccountSessionExpiresAt ||
		e2ee.ValidateOwnerEndpointGroupsRequest(claims, at) != nil {
		return false
	}
	var state string
	if tx.QueryRow(`SELECT status FROM hub_account_devices_v1 WHERE account_id=? AND owner_id=? AND device_id=? AND epoch=?`, a.scope.AccountID, a.scope.OwnerID, a.scope.DeviceID, a.scope.DeviceEpoch).Scan(&state) != nil || state != "ACTIVE" {
		return false
	}
	client, err := scanClientDevice(tx.QueryRow(clientDeviceSelect+` WHERE owner_id=? AND device_id=?`, a.scope.OwnerID, a.scope.DeviceID))
	return err == nil && client.State == ClientDeviceActive && client.KeyVersion == 1 && client.SessionEpoch == a.scope.ClientSessionEpoch && reflect.DeepEqual(client.Public, a.scope.DevicePublic)
}

func (s *Store) ProcessHubEndpointGroups(in HubEndpointGroupsInput, seal HubEndpointGroupsSeal) ([]byte, error) {
	if seal == nil || s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	lock, err := tx.Exec(`UPDATE hub_endpoint_groups_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := lock.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	request, err := endpointGroupsOwnerInput(tx, in)
	if err != nil {
		return nil, err
	}
	a, err := appNodeActor(tx, in.Hub, request.c.DeviceID, in.Device, request.token, in.At)
	if err != nil || a.scope.OwnerID != request.c.OwnerID || a.scope.AccountID != request.c.AccountID || a.scope.Origin != request.c.Origin || a.scope.DeviceID != request.c.DeviceID {
		return nil, ErrHubAccountRejected
	}
	if err = endpointGroupsOwnerRateTx(tx, a.scope, in.At); err != nil {
		return nil, err
	}
	receipt, err := endpointGroupsOwnerProcessTx(tx, a, in, request, seal, false)
	if err != nil {
		// A rejection reached before any business helper may still consume its
		// rate budget. Never commit an error after business/credential writes.
		if receipt.noEffects {
			if commitErr := tx.Commit(); commitErr != nil {
				return nil, commitErr
			}
		}
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return receipt.packet, nil
}

func endpointGroupsOwnerRateTx(tx *sql.Tx, scope e2ee.OwnerAppNodeScope, at time.Time) error {
	var stamp string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_endpoint_groups_owner_rates_v1 WHERE owner_id=? AND device_id=? AND account_epoch=? AND device_epoch=? AND owner_key_version=?`, scope.OwnerID, scope.DeviceID, scope.AccountEpoch, scope.DeviceEpoch, scope.OwnerKeyVersion).Scan(&stamp, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	start, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || !at.Before(start.Add(time.Minute)) {
		stamp, count = appNodeStamp(at), 0
	}
	if count >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_owner_rates_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(owner_id,device_id,account_epoch,device_epoch,owner_key_version) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, scope.OwnerID, scope.DeviceID, scope.AccountEpoch, scope.DeviceEpoch, scope.OwnerKeyVersion, stamp, count+1)
	return err
}

func endpointGroupsOwnerResult(in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, state, code string) wire.OwnerEndpointGroupsResult {
	r := wire.OwnerEndpointGroupsResult{Format: wire.OwnerEndpointGroupsResultFormat, ContractRevision: wire.OwnerEndpointGroupsContractRevision, RequestID: request.c.RequestID, RequestPacketDigest: request.digest, HubID: request.c.HubID, OwnerID: request.c.OwnerID, DeviceID: request.c.DeviceID, State: state, ErrorCode: code, CapturedAt: appNodeStamp(in.At), Freshness: "SNAPSHOT_ONLY"}
	switch q := in.Body.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		r.NodeID = q.Body.NodeID
	case wire.OwnerEndpointGroupsPrepareRequest:
		r.NodeID = q.Body.NodeID
	}
	return r
}

func endpointGroupsOwnerProcessTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, seal HubEndpointGroupsSeal, fence bool) (endpointGroupsOwnerReceipt, error) {
	history, err := endpointGroupsOwnerHistoryTx(tx, request, in.At)
	if errors.Is(err, errEndpointGroupsOwnerPacketConflict) {
		return endpointGroupsOwnerReceipt{noEffects: true}, ErrHubEndpointGroupsPacketConflict
	}
	if errors.Is(err, errEndpointGroupsOwnerUncertain) {
		return endpointGroupsOwnerSealOnly(in, request, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if len(history.receipt.packet) != 0 {
		return history.receipt, nil
	}
	if history.floor {
		// The lightweight floor survives payload eviction. A stale original is
		// never a new read, even if a later login has fresh authority.
		return endpointGroupsOwnerFenceTx(tx, in, request, "READ_EXPIRED", "", nil, seal)
	}
	if fence {
		if request.op == wire.OperationOwnerEndpointGroupsRead || request.op == wire.OperationOwnerEndpointGroupsPrepare || request.op == wire.OperationOwnerEndpointGroupsStatus {
			return endpointGroupsOwnerFenceTx(tx, in, request, "READ_EXPIRED", "", nil, seal)
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", wire.OwnerEndpointGroupsOriginalNotAdmitted, nil, seal)
	}
	used, err := endpointGroupsOwnerNonceUsedTx(tx, request)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if used {
		// Preserve the conflicting request's ID/digest fence without claiming
		// the already consumed nonce a second time.
		request.nonce = ""
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "ORIGINAL_PACKET_CONFLICT", nil, seal)
	}
	accountCurrent := endpointGroupsOwnerAccountCurrentTx(tx, a, request.claims, in.At)
	if request.op == wire.OperationOwnerEndpointGroupsStatus || request.op == wire.OperationOwnerEndpointGroupsReconcile {
		if !accountCurrent {
			return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
		}
		if request.op == wire.OperationOwnerEndpointGroupsStatus {
			return endpointGroupsOwnerStatusTx(tx, a, in, request, seal)
		}
		return endpointGroupsOwnerReconcileTx(tx, a, in, request, seal)
	}
	if !accountCurrent || !appNodeScopeCurrent(a, request.claims.Scope) || a.root != wire.RootActiveState {
		code := "OWNER_AUTHORITY_REQUIRED"
		if e2ee.ValidateOwnerEndpointGroupsRequest(request.claims, in.At) != nil {
			code = "REVIEW_EXPIRED"
		}
		if request.op == wire.OperationOwnerEndpointGroupsRead {
			return endpointGroupsOwnerFenceTx(tx, in, request, "READ_EXPIRED", "", nil, seal)
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", code, nil, seal)
	}
	switch q := in.Body.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		return endpointGroupsOwnerReadTx(tx, a, in, request, q, seal)
	case wire.OwnerEndpointGroupsPrepareRequest:
		return endpointGroupsOwnerPrepareTx(tx, a, in, request, q, seal)
	case wire.OwnerEndpointGroupsApplyRequest:
		return endpointGroupsOwnerApplyTx(tx, a, in, request, q, seal)
	}
	return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
}

func endpointGroupsOwnerSealOnly(in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, state, code string, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	if request.op == wire.OperationOwnerEndpointGroupsApply && code == "OUTCOME_UNCERTAIN" {
		return endpointGroupsOwnerReceipt{noEffects: true}, ErrHubEndpointGroupsOutcomeUncertain
	}
	body := endpointGroupsOwnerResult(in, request, state, code)
	packet, err := seal(body)
	return endpointGroupsOwnerReceipt{packet: packet, state: state}, err
}
