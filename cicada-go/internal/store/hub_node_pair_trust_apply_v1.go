package store

import (
	"database/sql"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nodePairRequestContext(body any) (*wire.NodePairTrustContext, string) {
	switch b := body.(type) {
	case wire.NodePairTrustCommit:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustACK:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustOwnerPrepare:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustOwnerComplete:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustOwnerStatus:
		return &b.Context, b.OOBCommitment
	}
	return nil, ""
}
func nodePairApply(tx *sql.Tx, in HubNodePairTrustInput, r *nodePairTrustRecord) (wire.NodePairTrustResult, error) {
	op := in.Header.Operation
	if c, o := nodePairRequestContext(in.Body); c != nil {
		if !reflect.DeepEqual(*c, r.Context) || (r.OOB != "" && r.OOB != o) {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Candidate != nil && !reflect.DeepEqual(in.NodeControlPublic, r.Context.Candidate.HubNodeControlPublic) {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
	}
	var scope e2ee.OwnerAppNodeScope
	var token []byte
	switch b := in.Body.(type) {
	case wire.NodePairTrustOwnerLookup:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustOwnerPrepare:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustOwnerComplete:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustOwnerStatus:
		scope, token = b.Scope, b.SessionToken
	}
	if token != nil {
		if _, err := nodePairOwner(tx, in, scope, token); err != nil {
			return wire.NodePairTrustResult{}, err
		}
		if r.Approval != nil && (r.Approval.Scope.OwnerID != scope.OwnerID || r.Approval.Scope.DeviceID != scope.DeviceID) {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Binding != nil && (r.Context.Binding.OwnerID != scope.OwnerID || r.Context.Binding.OwnerKeyID != scope.OwnerPublic.ID) {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
	}
	terminal := r.State != wire.NodePairTrustPending && r.State != wire.NodePairTrustOwnerApproved
	switch op {
	case wire.OperationNodePairTrustStart, wire.OperationNodePairTrustExisting:
		out := nodePairResult(in, r)
		out.Selector = in.Selector
		return out, nil
	case wire.OperationNodePairTrustCommit:
		if r.State != wire.NodePairTrustPending || r.Approval != nil {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		r.OOB = in.Body.(wire.NodePairTrustCommit).OOBCommitment
		if err := nodePairSave(tx, r, in.At); err != nil {
			return wire.NodePairTrustResult{}, err
		}
	case wire.OperationNodePairTrustPoll:
		if r.OOB == "" {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
	case wire.OperationOwnerNodePairTrustLookup:
		b := in.Body.(wire.NodePairTrustOwnerLookup)
		d, _ := wire.NodePairTrustContextDigest(r.Context)
		if b.ContextDigest != d || r.OOB == "" {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Candidate != nil {
			code, e := wire.AppNodeCodeDigest(in.Hub.HubID, b.Selector)
			if e != nil || code != r.Context.Candidate.CodeDigest {
				return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
			}
		} else if b.Selector != "" {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
	case wire.OperationOwnerNodePairTrustPrepare:
		if terminal || r.State != wire.NodePairTrustPending || r.OOB == "" || r.Approval != nil {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		if err := nodePairPrepare(tx, in, r); err != nil {
			return wire.NodePairTrustResult{}, err
		}
		out := nodePairResult(in, r)
		out.Approval = r.Approval
		return out, nil
	case wire.OperationOwnerNodePairTrustComplete:
		b := in.Body.(wire.NodePairTrustOwnerComplete)
		if terminal || r.State != wire.NodePairTrustPending || r.Approval == nil {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		claims, err := wire.VerifyNodePairTrustOwnerProof(scope.OwnerPublic, r.Context, r.OOB, b.OwnerProof, in.At)
		if err != nil || !reflect.DeepEqual(claims.Approval, *r.Approval) || claims.CapsuleDigest != wire.NodePairTrustCapsuleDigest(b.TrustCapsule) {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		r.OwnerProof = append([]byte(nil), b.OwnerProof...)
		r.Capsule = append([]byte(nil), b.TrustCapsule...)
		r.State = wire.NodePairTrustOwnerApproved
		if err = nodePairSave(tx, r, in.At); err != nil {
			return wire.NodePairTrustResult{}, err
		}
	case wire.OperationNodePairTrustACK:
		if terminal || r.State != wire.NodePairTrustOwnerApproved {
			return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
		}
		if err := nodePairACK(tx, in, r); err != nil {
			return wire.NodePairTrustResult{}, err
		}
	case wire.OperationOwnerNodePairTrustStatus:
	case wire.OperationNodePairTrustCancel, wire.OperationOwnerNodePairTrustCancel:
		if terminal {
			break // Observe the immutable terminal result without renewing it.
		}
		if err := nodePairExpire(tx, r, wire.NodePairTrustCancelled, in.At); err != nil {
			return wire.NodePairTrustResult{}, err
		}
	default:
		return wire.NodePairTrustResult{}, ErrNodePairTrustRejected
	}
	return nodePairResult(in, r), nil
}

func nodePairPrepare(tx *sql.Tx, in HubNodePairTrustInput, r *nodePairTrustRecord) error {
	b := in.Body.(wire.NodePairTrustOwnerPrepare)
	if r.Context.Mode == wire.NodePairTrustExisting {
		if err := nodePairExisting(tx, r.Context); err != nil {
			return err
		}
	}
	end := in.At.Add(5 * time.Minute)
	for _, text := range []string{r.Context.ExpiresAt, b.Scope.AccountSessionExpiresAt} {
		limit, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return err
		}
		if limit.Before(end) {
			end = limit
		}
	}
	grantID, proofDigest, confirmDigest := "", "", ""
	if r.Context.Mode == wire.NodePairTrustInitial {
		if in.OpenConfirmation == nil {
			return ErrNodePairTrustRejected
		}
		g, err := e2ee.VerifyOwnerAppNodeGrant(b.Scope.OwnerPublic, b.GrantProof, in.At)
		if err != nil || wire.ValidateAppNodeGrantClaims(g, in.Hub, in.At) != nil || !reflect.DeepEqual(g.Scope, b.Scope) || !reflect.DeepEqual(g.Candidate, r.Context.Candidate) {
			return ErrNodePairTrustRejected
		}
		stored, err := appNodeGrant(tx, b.Scope.OwnerID, b.Scope.DeviceID, g.GrantID)
		if err != nil || stored == nil || stored.state != wire.AppNodeActive || stored.remaining != 1 || stored.provenance != "" || !reflect.DeepEqual(stored.claims, g) {
			return ErrNodePairTrustRejected
		}
		candidate, err := appNodeCandidate(tx, g.Candidate.CodeDigest, in.Hub, in.NodeControlPublic, in.At)
		if err != nil || !reflect.DeepEqual(candidate, r.Context.Candidate) {
			return ErrNodePairTrustRejected
		}
		confirm, err := in.OpenConfirmation(b.ConfirmationPacket, b.Scope.DevicePublic)
		if err != nil {
			return err
		}
		a, err := appNodeActor(tx, in.Hub, b.Scope.DeviceID, b.Scope.DevicePublic, b.SessionToken, in.At)
		if err != nil || a.counters.SessionEpoch != confirm.Route.SessionEpoch || confirm.Route.Sequence != a.counters.LastRequestSequence+1 || a.counters.NextResponseSequence == 0 {
			return ErrNodePairTrustRejected
		}
		grantID = g.GrantID
		proofDigest = wire.AppNodeProofDigest(b.GrantProof)
		confirmDigest = wire.AppNodePacketDigest(b.ConfirmationPacket)
		for _, text := range []string{g.ProofExpiresAt, g.LeaseExpiresAt} {
			limit, _ := time.Parse(time.RFC3339Nano, text)
			if limit.Before(end) {
				end = limit
			}
		}
		if _, err = tx.Exec(`INSERT INTO hub_node_pair_trust_slots_v1(attempt_id,owner_id,device_id,session_epoch,request_sequence,response_sequence,operation_id,packet_digest,state,created_at) VALUES(?,?,?,?,?,?,?,?,'RESERVED',?)`, r.Context.AttemptID, b.Scope.OwnerID, b.Scope.DeviceID, confirm.Route.SessionEpoch, confirm.Route.Sequence, a.counters.NextResponseSequence, confirm.Route.OperationID, confirmDigest, appNodeStamp(in.At)); err != nil {
			return err
		}
		r.Grant = append([]byte(nil), b.GrantProof...)
		r.Confirmation = append([]byte(nil), b.ConfirmationPacket...)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		return err
	}
	d, _ := wire.NodePairTrustContextDigest(r.Context)
	a := wire.NodePairTrustApproval{Format: wire.NodePairTrustFormat, ContextDigest: d, OOBCommitment: r.OOB, Scope: b.Scope, GrantID: grantID, GrantProofDigest: proofDigest, ConfirmationPacketDigest: confirmDigest, PrepareRequestID: in.Header.RequestID, PreparePacketDigest: wire.NodePairTrustPacketDigest(in.Packet), ServerNonce: hex.EncodeToString(nonce), PreparedAt: appNodeStamp(in.At), AcceptBefore: appNodeStamp(end)}
	clear(nonce)
	if wire.ValidateNodePairTrustInitialAuthorization(r.Context, a, b.GrantProof, b.ConfirmationPacket, in.At) != nil {
		return ErrNodePairTrustRejected
	}
	r.Approval = &a
	if err = nodePairSave(tx, r, in.At); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE hub_node_pair_trust_v1 SET reserved_bytes=? WHERE attempt_id=?`, nodePairTrustApprovalReserveBytes, r.Context.AttemptID)
	return err
}

func nodePairACK(tx *sql.Tx, in HubNodePairTrustInput, r *nodePairTrustRecord) error {
	b := in.Body.(wire.NodePairTrustACK)
	if wire.VerifyNodePairTrustACK(r.Context, r.OOB, r.OwnerProof, r.Capsule, b, in.At) != nil {
		return ErrNodePairTrustRejected
	}
	var poll []byte
	if err := tx.QueryRow(`SELECT response_packet FROM hub_node_pair_trust_receipts_v1 WHERE sender_key_id=? AND attempt_id=? AND operation=? AND request_digest=? AND state='OWNER_APPROVED'`, in.Header.SenderPublic.ID, r.Context.AttemptID, wire.OperationNodePairTrustPoll, b.PollPacketDigest).Scan(&poll); err != nil || wire.NodePairTrustPacketDigest(poll) != b.PollReceiptDigest {
		return ErrNodePairTrustRejected
	}
	a, err := nodePairCurrentApproved(tx, in, r)
	if err != nil {
		return err
	}
	if r.Context.Mode == wire.NodePairTrustExisting {
		if err = nodePairExisting(tx, r.Context); err != nil {
			return err
		}
		binding := *r.Context.Binding
		r.Binding = &binding
	} else {
		if in.OpenConfirmation == nil {
			return ErrNodePairTrustRejected
		}
		confirm, err := in.OpenConfirmation(r.Confirmation, r.Approval.Scope.DevicePublic)
		if err != nil {
			return err
		}
		confirm.At = in.At
		confirm.Now = nil
		var req, resp, epoch uint64
		var digest, op, state string
		if tx.QueryRow(`SELECT session_epoch,request_sequence,response_sequence,packet_digest,operation_id,state FROM hub_node_pair_trust_slots_v1 WHERE attempt_id=?`, r.Context.AttemptID).Scan(&epoch, &req, &resp, &digest, &op, &state) != nil || state != "RESERVED" || epoch != a.counters.SessionEpoch || req != a.counters.LastRequestSequence+1 || resp != a.counters.NextResponseSequence || confirm.Route.Sequence != req || confirm.Route.OperationID != op || wire.AppNodePacketDigest(confirm.Packet) != digest {
			return ErrNodePairTrustRejected
		}
		r.State = "ACKING"
		if err = nodePairSave(tx, r, in.At); err != nil {
			return err
		}
		receipt, outcome, err := appNodeClient(tx, a, confirm, false)
		if err != nil || outcome != wire.AppNodeCompleted {
			return ErrNodePairTrustRejected
		}
		binding, err := nodeControlCurrentBindingTx(tx, confirmCredentialDigest(tx, r), r.Context.Candidate.NodeID)
		if err != nil {
			return err
		}
		public := appNodeBindingPublic(*binding)
		if wire.ValidateNodePairTrustAccepted(r.Context, *r.Approval, public) != nil {
			return ErrNodePairTrustRejected
		}
		r.Binding = &public
		r.ConfirmationResponse = receipt
		if _, err = tx.Exec(`UPDATE hub_node_pair_trust_slots_v1 SET state='DONE' WHERE attempt_id=? AND state='RESERVED'`, r.Context.AttemptID); err != nil {
			return err
		}
	}
	r.State = wire.NodePairTrustACKed
	return nodePairSave(tx, r, in.At)
}

func confirmCredentialDigest(tx *sql.Tx, r *nodePairTrustRecord) string {
	var digest string
	if r.Context.Candidate != nil {
		_ = tx.QueryRow(`SELECT node_credential_digest FROM node_control_key_requests_v1 WHERE id=?`, r.Context.Candidate.RequestID).Scan(&digest)
	}
	return digest
}

func nodePairReconcile(tx *sql.Tx, in HubNodePairTrustInput) ([]byte, error) {
	b := in.Body.(wire.NodePairTrustReconcile)
	if in.Original == nil || in.Original.Seal == nil || !reflect.DeepEqual(in.Original.Packet, b.OriginalPacket) || !reflect.DeepEqual(in.Header.SenderPublic, in.Original.Header.SenderPublic) {
		return nil, ErrNodePairTrustRejected
	}
	old := *in.Original
	old.At = in.At
	original, err := nodePairCached(tx, old.Header, b.OriginalPacketDigest)
	if err != nil {
		return nil, err
	}
	result := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: in.Header.Operation, RequestID: in.Header.RequestID, AttemptID: in.Header.AttemptID, RequestPacketDigest: wire.NodePairTrustPacketDigest(in.Packet), State: wire.NodePairTrustFenced, ErrorCode: "FENCED", ObservedAt: appNodeStamp(in.At)}
	if original != nil {
		result.State = wire.NodePairTrustRecovered
		result.ErrorCode = ""
		result.OriginalPacketDigest = b.OriginalPacketDigest
		result.OriginalReceipt = original
	} else {
		// Authentication alone accepts historical bytes. A bounded fence must
		// never cover a far-future packet which could become fresh after GC.
		issued := nodePairOriginalIssued(old.Body)
		at, err := time.Parse(time.RFC3339Nano, issued)
		if err != nil || at.After(in.At.Add(30*time.Second)) || wire.ValidateNodePairTrustRequestBody(old.Header, old.Body, in.Hub, at) != nil {
			return nil, ErrNodePairTrustRejected
		}
		fence := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: old.Header.Operation, RequestID: old.Header.RequestID, AttemptID: old.Header.AttemptID, RequestPacketDigest: b.OriginalPacketDigest, State: wire.NodePairTrustFenced, ErrorCode: "FENCED", ObservedAt: appNodeStamp(in.At)}
		if _, err = nodePairReceipt(tx, old, fence); err != nil {
			return nil, err
		}
	}
	packet, err := nodePairReceipt(tx, in, result)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func nodePairOriginalIssued(body any) string {
	switch b := body.(type) {
	case wire.NodePairTrustStart:
		return b.IssuedAt
	case wire.NodePairTrustExistingStart:
		return b.IssuedAt
	case wire.NodePairTrustCommit:
		return b.IssuedAt
	case wire.NodePairTrustACK:
		return b.IssuedAt
	case wire.NodePairTrustOwnerLookup:
		return b.IssuedAt
	case wire.NodePairTrustOwnerPrepare:
		return b.IssuedAt
	case wire.NodePairTrustOwnerComplete:
		return b.IssuedAt
	case wire.NodePairTrustOwnerStatus:
		return b.IssuedAt
	}
	return ""
}
