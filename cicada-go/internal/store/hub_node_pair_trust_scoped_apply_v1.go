package store

import (
	"database/sql"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nodePairScopedRequestContext(body any) (*wire.NodePairTrustScopedContext, string) {
	switch b := body.(type) {
	case wire.NodePairTrustScopedCommit:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustScopedACK:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustScopedOwnerPrepare:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustScopedOwnerComplete:
		return &b.Context, b.OOBCommitment
	case wire.NodePairTrustScopedOwnerStatus:
		return &b.Context, b.OOBCommitment
	}
	return nil, ""
}
func nodePairScopedApply(tx *sql.Tx, in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) (wire.NodePairTrustScopedResult, error) {
	op := in.Header.Operation
	if c, o := nodePairScopedRequestContext(in.Body); c != nil {
		if !reflect.DeepEqual(*c, r.Context) || (r.OOB != "" && r.OOB != o) {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Candidate != nil && !reflect.DeepEqual(in.NodeControlPublic, r.Context.Candidate.HubNodeControlPublic) {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
	}
	var scope e2ee.OwnerAppNodeScopedScope
	var token []byte
	switch b := in.Body.(type) {
	case wire.NodePairTrustScopedOwnerLookup:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustScopedOwnerPrepare:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustScopedOwnerComplete:
		scope, token = b.Scope, b.SessionToken
	case wire.NodePairTrustScopedOwnerStatus:
		scope, token = b.Scope, b.SessionToken
	}
	if token != nil {
		if scope.Version != 2 || scope.AuthorityNodeID != r.Context.AuthorityNodeID {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if _, err := nodePairScopedOwner(tx, in, scope, token); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
		if r.Approval != nil && (r.Approval.Scope.OwnerID != scope.OwnerID || r.Approval.Scope.DeviceID != scope.DeviceID) {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Binding != nil && (r.Context.Binding.OwnerID != scope.OwnerID || r.Context.Binding.OwnerKeyID != scope.OwnerPublic.ID) {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
	}
	terminal := r.State != wire.NodePairTrustScopedPending && r.State != wire.NodePairTrustScopedOwnerApproved
	switch op {
	case wire.OperationNodePairTrustScopedStart, wire.OperationNodePairTrustScopedExisting:
		out := nodePairScopedResult(in, r)
		out.Selector = in.Selector
		return out, nil
	case wire.OperationNodePairTrustScopedCommit:
		if r.State != wire.NodePairTrustScopedPending || r.Approval != nil {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		r.OOB = in.Body.(wire.NodePairTrustScopedCommit).OOBCommitment
		if err := nodePairScopedSave(tx, r, in.At); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
	case wire.OperationNodePairTrustScopedPoll:
		if r.OOB == "" && !terminal {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
	case wire.OperationOwnerNodePairTrustScopedLookup:
		b := in.Body.(wire.NodePairTrustScopedOwnerLookup)
		d, _ := wire.NodePairTrustScopedContextDigest(r.Context)
		if b.ContextDigest != d || r.OOB == "" {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if r.Context.Candidate != nil {
			code, e := wire.AppNodeCodeDigest(in.Hub.HubID, b.Selector)
			if e != nil || code != r.Context.Candidate.CodeDigest {
				return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
			}
		} else if b.Selector != "" {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
	case wire.OperationOwnerNodePairTrustScopedPrepare:
		if terminal || r.State != wire.NodePairTrustScopedPending || r.OOB == "" || r.Approval != nil {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if err := nodePairScopedPrepare(tx, in, r); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
		out := nodePairScopedResult(in, r)
		out.Approval = r.Approval
		return out, nil
	case wire.OperationOwnerNodePairTrustScopedComplete:
		b := in.Body.(wire.NodePairTrustScopedOwnerComplete)
		if terminal || r.State != wire.NodePairTrustScopedPending || r.Approval == nil {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		claims, err := wire.VerifyNodePairTrustScopedOwnerProof(scope.OwnerPublic, r.Context, r.OOB, b.OwnerProof, in.At)
		if err != nil || !reflect.DeepEqual(claims.Approval, *r.Approval) || claims.CapsuleDigest != wire.NodePairTrustScopedCapsuleDigest(b.TrustCapsule) {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		r.OwnerProof = append([]byte(nil), b.OwnerProof...)
		r.Capsule = append([]byte(nil), b.TrustCapsule...)
		r.State = wire.NodePairTrustScopedOwnerApproved
		if err = nodePairScopedSave(tx, r, in.At); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
	case wire.OperationNodePairTrustScopedACK:
		if terminal || r.State != wire.NodePairTrustScopedOwnerApproved {
			return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
		}
		if err := nodePairScopedACK(tx, in, r); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
	case wire.OperationOwnerNodePairTrustScopedStatus:
	case wire.OperationNodePairTrustScopedCancel, wire.OperationOwnerNodePairTrustScopedCancel:
		if terminal {
			break // Observe the immutable terminal result without renewing it.
		}
		if err := nodePairScopedExpire(tx, r, wire.NodePairTrustScopedCancelled, in.At); err != nil {
			return wire.NodePairTrustScopedResult{}, err
		}
	default:
		return wire.NodePairTrustScopedResult{}, ErrNodePairTrustRejected
	}
	return nodePairScopedResult(in, r), nil
}

func nodePairScopedPrepare(tx *sql.Tx, in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) error {
	b := in.Body.(wire.NodePairTrustScopedOwnerPrepare)
	actor, err := appNodeActor(tx, in.Hub, b.Scope.DeviceID, b.Scope.DevicePublic, b.SessionToken, in.At)
	if err != nil {
		return ErrNodePairTrustRejected
	}
	if err := appNodeRefresh(tx, actor, in.At); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED'`, b.Scope.OwnerID, b.Scope.DeviceID).Scan(&pending); err != nil {
		return err
	}
	if pending != 0 {
		return ErrNodePairTrustACKRequired
	}
	if r.Context.Mode == wire.NodePairTrustScopedExisting {
		if err := nodePairScopedExisting(tx, r.Context); err != nil {
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
	if r.Context.Mode == wire.NodePairTrustScopedInitial {
		if in.OpenConfirmation == nil {
			return ErrNodePairTrustRejected
		}
		g, err := e2ee.VerifyOwnerAppNodeScopedGrant(b.Scope.OwnerPublic, b.GrantProof, in.At)
		if err != nil || wire.ValidateAppNodeScopedGrantClaims(g, in.Hub, in.At) != nil || !reflect.DeepEqual(g.Scope, b.Scope) || !reflect.DeepEqual(g.Candidate, r.Context.Candidate) {
			return ErrNodePairTrustRejected
		}
		stored, err := appNodeScopedGrant(tx, b.Scope.OwnerID, b.Scope.DeviceID, b.Scope.AuthorityNodeID, g.GrantID)
		if err != nil || stored == nil || stored.state != wire.AppNodeScopedActive || stored.remaining != 1 || stored.provenance != "" || !reflect.DeepEqual(stored.claims, g) {
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
		proofDigest = wire.AppNodeScopedProofDigest(b.GrantProof)
		confirmDigest = wire.AppNodeScopedPacketDigest(b.ConfirmationPacket)
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
	d, _ := wire.NodePairTrustScopedContextDigest(r.Context)
	a := wire.NodePairTrustScopedApproval{Format: wire.NodePairTrustScopedFormat, ContextDigest: d, OOBCommitment: r.OOB, Scope: b.Scope, GrantID: grantID, GrantProofDigest: proofDigest, ConfirmationPacketDigest: confirmDigest, PrepareRequestID: in.Header.RequestID, PreparePacketDigest: wire.NodePairTrustScopedPacketDigest(in.Packet), ServerNonce: hex.EncodeToString(nonce), PreparedAt: appNodeStamp(in.At), AcceptBefore: appNodeStamp(end)}
	clear(nonce)
	if wire.ValidateNodePairTrustScopedInitialAuthorization(r.Context, a, b.GrantProof, b.ConfirmationPacket, in.At) != nil {
		return ErrNodePairTrustRejected
	}
	r.Approval = &a
	if err = nodePairScopedSave(tx, r, in.At); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE hub_node_pair_trust_v1 SET reserved_bytes=? WHERE attempt_id=?`, nodePairTrustApprovalReserveBytes, r.Context.AttemptID)
	return err
}

func nodePairScopedACK(tx *sql.Tx, in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) error {
	b := in.Body.(wire.NodePairTrustScopedACK)
	if wire.VerifyNodePairTrustScopedACK(r.Context, r.OOB, r.OwnerProof, r.Capsule, b, in.At) != nil {
		return ErrNodePairTrustRejected
	}
	var poll []byte
	if err := tx.QueryRow(`SELECT response_packet FROM hub_node_pair_trust_receipts_v1 WHERE sender_key_id=? AND attempt_id=? AND operation=? AND request_digest=? AND state='OWNER_APPROVED'`, in.Header.SenderPublic.ID, r.Context.AttemptID, wire.OperationNodePairTrustScopedPoll, b.PollPacketDigest).Scan(&poll); err != nil || wire.NodePairTrustScopedPacketDigest(poll) != b.PollReceiptDigest {
		return ErrNodePairTrustRejected
	}
	a, err := nodePairScopedCurrentApproved(tx, in, r)
	if err != nil {
		return err
	}
	if r.Context.Mode == wire.NodePairTrustScopedExisting {
		if err = nodePairScopedExisting(tx, r.Context); err != nil {
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
		if tx.QueryRow(`SELECT session_epoch,request_sequence,response_sequence,packet_digest,operation_id,state FROM hub_node_pair_trust_slots_v1 WHERE attempt_id=?`, r.Context.AttemptID).Scan(&epoch, &req, &resp, &digest, &op, &state) != nil || state != "RESERVED" || epoch != a.counters.SessionEpoch || req != a.counters.LastRequestSequence+1 || resp != a.counters.NextResponseSequence || confirm.Route.Sequence != req || confirm.Route.OperationID != op || wire.AppNodeScopedPacketDigest(confirm.Packet) != digest {
			return ErrNodePairTrustRejected
		}
		r.State = "ACKING"
		if err = nodePairScopedSave(tx, r, in.At); err != nil {
			return err
		}
		receipt, outcome, err := appNodeScopedClient(tx, a, confirm, false)
		if err != nil || outcome != wire.AppNodeScopedCompleted {
			return ErrNodePairTrustRejected
		}
		binding, err := nodeControlCurrentBindingTx(tx, confirmScopedCredentialDigest(tx, r), r.Context.Candidate.NodeID)
		if err != nil {
			return err
		}
		public := appNodeBindingPublic(*binding)
		if wire.ValidateNodePairTrustScopedAccepted(r.Context, *r.Approval, public) != nil {
			return ErrNodePairTrustRejected
		}
		r.Binding = &public
		r.ConfirmationResponse = receipt
		if _, err = tx.Exec(`UPDATE hub_node_pair_trust_slots_v1 SET state='DONE' WHERE attempt_id=? AND state='RESERVED'`, r.Context.AttemptID); err != nil {
			return err
		}
	}
	r.State = wire.NodePairTrustScopedACKed
	return nodePairScopedSave(tx, r, in.At)
}

func confirmScopedCredentialDigest(tx *sql.Tx, r *nodePairTrustScopedRecord) string {
	var digest string
	if r.Context.Candidate != nil {
		_ = tx.QueryRow(`SELECT node_credential_digest FROM node_control_key_requests_v1 WHERE id=?`, r.Context.Candidate.RequestID).Scan(&digest)
	}
	return digest
}

func nodePairScopedReconcile(tx *sql.Tx, in HubNodePairTrustScopedInput) ([]byte, error) {
	b := in.Body.(wire.NodePairTrustScopedReconcile)
	if in.Original == nil || in.Original.Seal == nil || !reflect.DeepEqual(in.Original.Packet, b.OriginalPacket) || !reflect.DeepEqual(in.Header.SenderPublic, in.Original.Header.SenderPublic) {
		return nil, ErrNodePairTrustRejected
	}
	old := *in.Original
	old.At = in.At
	original, err := nodePairScopedCached(tx, old.Header, b.OriginalPacketDigest)
	if err != nil {
		return nil, err
	}
	result := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: in.Header.Operation, RequestID: in.Header.RequestID, AttemptID: in.Header.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(in.Packet), State: wire.NodePairTrustScopedFenced, ErrorCode: "FENCED", ObservedAt: appNodeStamp(in.At)}
	if original != nil {
		result.State = wire.NodePairTrustScopedRecovered
		result.ErrorCode = ""
		result.OriginalPacketDigest = b.OriginalPacketDigest
		result.OriginalReceipt = original
	} else {
		// Authentication alone accepts historical bytes. A bounded fence must
		// never cover a far-future packet which could become fresh after GC.
		issued := nodePairScopedOriginalIssued(old.Body)
		at, err := time.Parse(time.RFC3339Nano, issued)
		if err != nil || at.After(in.At.Add(30*time.Second)) || wire.ValidateNodePairTrustScopedRequestBody(old.Header, old.Body, in.Hub, at) != nil {
			return nil, ErrNodePairTrustRejected
		}
		fence := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: old.Header.Operation, RequestID: old.Header.RequestID, AttemptID: old.Header.AttemptID, RequestPacketDigest: b.OriginalPacketDigest, State: wire.NodePairTrustScopedFenced, ErrorCode: "FENCED", ObservedAt: appNodeStamp(in.At)}
		if _, err = nodePairScopedReceipt(tx, old, fence); err != nil {
			return nil, err
		}
	}
	packet, err := nodePairScopedReceipt(tx, in, result)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func nodePairScopedOriginalIssued(body any) string {
	switch b := body.(type) {
	case wire.NodePairTrustScopedStart:
		return b.IssuedAt
	case wire.NodePairTrustScopedExistingStart:
		return b.IssuedAt
	case wire.NodePairTrustScopedCommit:
		return b.IssuedAt
	case wire.NodePairTrustScopedACK:
		return b.IssuedAt
	case wire.NodePairTrustScopedOwnerLookup:
		return b.IssuedAt
	case wire.NodePairTrustScopedOwnerPrepare:
		return b.IssuedAt
	case wire.NodePairTrustScopedOwnerComplete:
		return b.IssuedAt
	case wire.NodePairTrustScopedOwnerStatus:
		return b.IssuedAt
	}
	return ""
}
