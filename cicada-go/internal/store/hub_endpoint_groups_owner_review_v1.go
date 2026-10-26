package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type endpointGroupsOwnerReview struct {
	review                                     wire.OwnerEndpointGroupsReview
	owner, account, device                     string
	accountEpoch, deviceEpoch, ownerKeyVersion uint64
	prepareProof                               []byte
	state, consumed                            string
}

func endpointGroupsOwnerReviewTx(tx *sql.Tx, id string) (*endpointGroupsOwnerReview, error) {
	var r endpointGroupsOwnerReview
	var raw, prepareID, prepareDigest, expires string
	err := tx.QueryRow(`SELECT owner_id,account_id,device_id,account_epoch,device_epoch,owner_key_version,prepare_request_id,prepare_packet_digest,prepare_proof,review_json,expires_at,state,consumed_operation_id FROM hub_endpoint_groups_reviews_v1 WHERE review_id=?`, id).Scan(&r.owner, &r.account, &r.device, &r.accountEpoch, &r.deviceEpoch, &r.ownerKeyVersion, &prepareID, &prepareDigest, &r.prepareProof, &raw, &expires, &r.state, &r.consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(raw), &r.review) != nil {
		return nil, errEndpointGroupsOwnerUncertain
	}
	canonical, err := json.Marshal(r.review)
	if err != nil || !bytes.Equal(canonical, []byte(raw)) || r.review.ReviewID != id || r.review.RequestID != prepareID || r.review.RequestPacketDigest != prepareDigest || r.review.ExpiresAt != expires || r.review.Target.OwnerID != r.owner {
		return nil, errEndpointGroupsOwnerUncertain
	}
	digest, err := wire.OwnerEndpointGroupsReviewDigest(r.review)
	if err != nil || digest != r.review.ReviewDigest {
		return nil, errEndpointGroupsOwnerUncertain
	}
	return &r, nil
}

func endpointGroupsOwnerReviewOwned(r *endpointGroupsOwnerReview, request endpointGroupsOwnerRequest) bool {
	return r != nil && r.owner == request.c.OwnerID && r.account == request.c.AccountID && r.device == request.c.DeviceID
}

func endpointGroupsOwnerReviewCapacityTx(tx *sql.Tx, request endpointGroupsOwnerRequest, at time.Time) error {
	rows, err := tx.Query(`SELECT review_id,account_epoch,device_epoch,owner_key_version,expires_at FROM hub_endpoint_groups_reviews_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED'`, request.c.OwnerID, request.c.DeviceID)
	if err != nil {
		return err
	}
	var expired []string
	live := 0
	s := request.claims.Scope
	for rows.Next() {
		var id, end string
		var ae, de, ov uint64
		if err = rows.Scan(&id, &ae, &de, &ov, &end); err != nil {
			break
		}
		expires, e := time.Parse(time.RFC3339Nano, end)
		if e != nil {
			err = errEndpointGroupsOwnerUncertain
			break
		}
		if !at.Before(expires) {
			expired = append(expired, id)
		} else if ae == s.AccountEpoch && de == s.DeviceEpoch && ov == s.OwnerKeyVersion {
			live++
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, id := range expired {
		if _, err = tx.Exec(`UPDATE hub_endpoint_groups_reviews_v1 SET state='EXPIRED' WHERE review_id=? AND state='PREPARED'`, id); err != nil {
			return err
		}
	}
	if live >= 64 {
		return ErrHubOwnerDiagnosticsFull
	}
	return nil
}

func endpointGroupsOwnerBindResult(in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, r *wire.OwnerEndpointGroupsResult) {
	b := endpointGroupsOwnerResult(in, request, r.State, r.ErrorCode)
	r.Format, r.ContractRevision, r.RequestID, r.RequestPacketDigest = b.Format, b.ContractRevision, b.RequestID, b.RequestPacketDigest
	r.HubID, r.OwnerID, r.DeviceID = b.HubID, b.OwnerID, b.DeviceID
	r.CapturedAt, r.Freshness = b.CapturedAt, b.Freshness
}

func endpointGroupsOwnerReadTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, q wire.OwnerEndpointGroupsReadRequest, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	if _, err := tx.Exec(`SAVEPOINT endpoint_groups_owner_read`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	r, code, err := endpointGroupsReadTx(tx, in, a, q)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if code != "" {
		if _, err = tx.Exec(`ROLLBACK TO endpoint_groups_owner_read`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		if _, err = tx.Exec(`RELEASE endpoint_groups_owner_read`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", code, nil, seal)
	}
	if _, err = tx.Exec(`RELEASE endpoint_groups_owner_read`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	r.State, r.ErrorCode, r.NodeID = "COMPLETED", "", q.Body.NodeID
	endpointGroupsOwnerBindResult(in, request, &r)
	packet, err := seal(r)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	return endpointGroupsOwnerSaveReadTx(tx, in, request, r, packet)
}

func endpointGroupsOwnerPrepareTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, q wire.OwnerEndpointGroupsPrepareRequest, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	if err := endpointGroupsOwnerReviewCapacityTx(tx, request, in.At); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if _, err := tx.Exec(`SAVEPOINT endpoint_groups_owner_prepare`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	review, code, err := endpointGroupsPrepareTx(tx, in, a, q)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if code != "" {
		if _, err = tx.Exec(`ROLLBACK TO endpoint_groups_owner_prepare`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		if _, err = tx.Exec(`RELEASE endpoint_groups_owner_prepare`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", code, nil, seal)
	}
	if wire.ValidateOwnerEndpointGroupsReview(q, in.Packet, review, in.Hub, in.At) != nil {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	raw, err := json.Marshal(review)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	s := request.claims.Scope
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_reviews_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, review.ReviewID, request.c.OwnerID, request.c.AccountID, request.c.DeviceID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, request.c.RequestID, request.digest, request.proof, string(raw), review.ExpiresAt, "PREPARED", "", appNodeStamp(in.At))
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if _, err = tx.Exec(`RELEASE endpoint_groups_owner_prepare`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	r := endpointGroupsOwnerResult(in, request, "PREPARED", "")
	r.Review = &review
	packet, err := seal(r)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	return endpointGroupsOwnerSavePermanentTx(tx, in, request, r, packet, false)
}

func endpointGroupsOwnerApplyTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, q wire.OwnerEndpointGroupsApplyRequest, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	r, err := endpointGroupsOwnerReviewTx(tx, q.Body.ReviewID)
	if errors.Is(err, errEndpointGroupsOwnerUncertain) {
		return endpointGroupsOwnerSealOnly(in, request, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if !endpointGroupsOwnerReviewOwned(r, request) {
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", wire.OwnerEndpointGroupsOriginalNotAdmitted, nil, seal)
	}
	if r.review.ReviewDigest != q.Body.ReviewDigest || r.review.RequestPacketDigest != q.Body.PreparePacketDigest {
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "ORIGINAL_PACKET_CONFLICT", &r.review, seal)
	}
	if r.state != "PREPARED" {
		code := "CAS_CONFLICT"
		if r.state == "EXPIRED" {
			code = "REVIEW_EXPIRED"
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", code, &r.review, seal)
	}
	if !appNodeBefore(in.At, r.review.ExpiresAt) {
		if _, err = tx.Exec(`UPDATE hub_endpoint_groups_reviews_v1 SET state='EXPIRED' WHERE review_id=? AND state='PREPARED'`, r.review.ReviewID); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "REVIEW_EXPIRED", &r.review, seal)
	}
	prepareClaims, err := e2ee.VerifyOwnerEndpointGroupsRequest(a.scope.OwnerPublic, r.prepareProof, wire.OwnerEndpointGroupsOwnerPurpose(wire.OperationOwnerEndpointGroupsPrepare), time.Time{})
	if err != nil || !appNodeSameSecurity(a.scope, prepareClaims.Scope) || r.accountEpoch != a.scope.AccountEpoch || r.deviceEpoch != a.scope.DeviceEpoch || r.ownerKeyVersion != a.scope.OwnerKeyVersion || prepareClaims.RequestID != r.review.RequestID ||
		prepareClaims.Scope.AccountID != r.account || prepareClaims.Scope.OwnerID != r.owner || prepareClaims.Scope.DeviceID != r.device || prepareClaims.Scope.AccountEpoch != r.accountEpoch || prepareClaims.Scope.DeviceEpoch != r.deviceEpoch || prepareClaims.Scope.OwnerKeyVersion != r.ownerKeyVersion {
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "CAS_CONFLICT", &r.review, seal)
	}
	prepareBody := wire.OwnerEndpointGroupsPrepareBody{Action: r.review.Action, NodeID: r.review.Target.NodeID, NetworkID: r.review.Target.NetworkID}
	switch r.review.Action {
	case wire.OwnerEndpointGroupsCreateGroup:
		prepareBody.Name = r.review.Target.Name
	case wire.OwnerEndpointGroupsAddEndpoint:
		prepareBody.GroupID = r.review.Target.GroupID
		prepareBody.EndpointID = r.review.Target.EndpointID
		prepareBody.Duration = r.review.Projection.Duration
	case wire.OwnerEndpointGroupsRemoveEndpoint:
		prepareBody.GroupID = r.review.Target.GroupID
		prepareBody.EndpointID = r.review.Target.EndpointID
	default:
		return endpointGroupsOwnerReceipt{}, errEndpointGroupsOwnerUncertain
	}
	digest, err := wire.OwnerEndpointGroupsBodyDigest(prepareBody)
	if err != nil || digest != prepareClaims.BodyDigest {
		return endpointGroupsOwnerReceipt{}, errEndpointGroupsOwnerUncertain
	}
	end, err := time.Parse(time.RFC3339Nano, prepareClaims.ExpiresAt)
	reviewEnd, re := time.Parse(time.RFC3339Nano, r.review.ExpiresAt)
	if err != nil || re != nil || reviewEnd.After(end) {
		return endpointGroupsOwnerReceipt{}, errEndpointGroupsOwnerUncertain
	}
	if r.review.Action == wire.OwnerEndpointGroupsAddEndpoint {
		policy, err := e2ee.VerifyOwnerEndpointGroupPolicy(a.scope.OwnerPublic, q.Body.PolicyProof, in.At)
		if err != nil || r.review.Policy == nil || !reflect.DeepEqual(policy, *r.review.Policy) {
			return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "TARGET_NOT_AUTHORIZED", &r.review, seal)
		}
	} else if len(q.Body.PolicyProof) != 0 {
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", "TARGET_NOT_AUTHORIZED", &r.review, seal)
	}
	claim, err := tx.Exec(`UPDATE hub_endpoint_groups_reviews_v1 SET state='CONSUMED',consumed_operation_id=? WHERE review_id=? AND state='PREPARED'`, request.c.RequestID, r.review.ReviewID)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if n, e := claim.RowsAffected(); e != nil || n != 1 {
		return endpointGroupsOwnerReceipt{}, errEndpointGroupsOwnerUncertain
	}
	if _, err = tx.Exec(`SAVEPOINT endpoint_groups_owner_apply_effect`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	operation, code, err := endpointGroupsApplyTx(tx, in, a, q, r.review)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if code != "" {
		if _, err = tx.Exec(`ROLLBACK TO endpoint_groups_owner_apply_effect`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		if _, err = tx.Exec(`RELEASE endpoint_groups_owner_apply_effect`); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
		return endpointGroupsOwnerFenceTx(tx, in, request, "REJECTED_FENCED", code, &r.review, seal)
	}
	if _, err = tx.Exec(`RELEASE endpoint_groups_owner_apply_effect`); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if operation.OperationID != request.c.RequestID || operation.OriginalPacketDigest != request.digest || operation.ReviewID != r.review.ReviewID || operation.Action != r.review.Action || operation.State != "COMPLETED" || operation.ErrorCode != "" || !reflect.DeepEqual(operation.Target, r.review.Target) {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	result := endpointGroupsOwnerResult(in, request, "COMPLETED", "")
	result.NodeID = operation.Target.NodeID
	result.Operation = &operation
	if err = endpointGroupsOwnerCurrentTx(tx, a, in, request, &result); err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	packet, err := seal(result)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	return endpointGroupsOwnerSavePermanentTx(tx, in, request, result, packet, false)
}

func endpointGroupsOwnerFenceTx(tx *sql.Tx, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, state, code string, review *wire.OwnerEndpointGroupsReview, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	r := endpointGroupsOwnerResult(in, request, state, code)
	if request.op == wire.OperationOwnerEndpointGroupsApply {
		if code != wire.OwnerEndpointGroupsOriginalNotAdmitted && review == nil {
			q, ok := in.Body.(wire.OwnerEndpointGroupsApplyRequest)
			if !ok {
				return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
			}
			stored, err := endpointGroupsOwnerReviewTx(tx, q.Body.ReviewID)
			if err != nil {
				return endpointGroupsOwnerReceipt{}, err
			}
			if endpointGroupsOwnerReviewOwned(stored, request) {
				review = &stored.review
			}
		}
		if code == wire.OwnerEndpointGroupsOriginalNotAdmitted || review == nil {
			r.State, r.ErrorCode, r.NodeID = "REJECTED_FENCED", wire.OwnerEndpointGroupsOriginalNotAdmitted, ""
		} else {
			r.NodeID = review.Target.NodeID
			r.Operation = &wire.OwnerEndpointGroupsOperation{OperationID: request.c.RequestID, OriginalPacketDigest: request.digest, Action: review.Action, State: "REJECTED_FENCED", ErrorCode: code, ReviewID: review.ReviewID, Target: review.Target, CommittedAt: appNodeStamp(in.At)}
		}
	}
	packet, err := seal(r)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	return endpointGroupsOwnerSavePermanentTx(tx, in, request, r, packet, true)
}
