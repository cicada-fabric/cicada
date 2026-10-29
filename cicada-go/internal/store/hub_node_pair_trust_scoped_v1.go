package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type HubNodePairTrustScopedSeal func(wire.NodePairTrustScopedResult) ([]byte, error)
type HubNodePairTrustScopedInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Header            wire.NodePairTrustScopedPacket
	Body              any
	Packet            []byte
	At                time.Time
	Now               func() time.Time
	Start             *NodeControlKeyRequestInput
	Selector          string
	Seal              HubNodePairTrustScopedSeal
	OpenConfirmation  func([]byte, e2ee.PublicIdentity) (HubAppNodeClientInput, error)
	Original          *HubNodePairTrustScopedInput
}

// No plaintext S, bearer or App session token is retained in this record.
type nodePairTrustScopedRecord struct {
	Context              wire.NodePairTrustScopedContext   `json:"context"`
	OOB                  string                            `json:"oob_commitment"`
	State                string                            `json:"state"`
	Approval             *wire.NodePairTrustScopedApproval `json:"approval,omitempty"`
	Grant                []byte                            `json:"grant,omitempty"`
	Confirmation         []byte                            `json:"confirmation,omitempty"`
	OwnerProof           []byte                            `json:"owner_proof,omitempty"`
	Capsule              []byte                            `json:"capsule,omitempty"`
	Binding              *e2ee.OwnerAppNodeBinding         `json:"binding,omitempty"`
	ConfirmationResponse []byte                            `json:"confirmation_response,omitempty"`
}

func nodePairScopedLoad(tx *sql.Tx, id string) (*nodePairTrustScopedRecord, error) {
	var raw, node, key, digest, context, state string
	err := tx.QueryRow(`SELECT record_json,node_id,node_key_id,context_digest,context_json,state FROM hub_node_pair_trust_v1 WHERE authority_kind='NODE_V1' AND attempt_id=?`, id).Scan(&raw, &node, &key, &digest, &context, &state)
	if err != nil {
		return nil, err
	}
	var r nodePairTrustScopedRecord
	if json.Unmarshal([]byte(raw), &r) != nil {
		return nil, ErrNodePairTrustRejected
	}
	actual, err := wire.NodePairTrustScopedContextDigest(r.Context)
	canonical, encodeErr := json.Marshal(r.Context)
	if err != nil || encodeErr != nil || actual != digest || string(canonical) != context || r.Context.AttemptID != id || r.Context.AuthorityNodeID != node || r.State != state {
		return nil, ErrNodePairTrustRejected
	}
	var public e2ee.PublicIdentity
	if r.Context.Candidate != nil {
		public = r.Context.Candidate.NodePublic
	} else if r.Context.Binding != nil {
		public = r.Context.Binding.NodePublic
	}
	if public.ID != key || (r.Approval != nil && wire.ValidateNodePairTrustScopedApproval(*r.Approval, r.Context, r.OOB, time.Time{}) != nil) {
		return nil, ErrNodePairTrustRejected
	}
	return &r, nil
}
func nodePairScopedSave(tx *sql.Tx, r *nodePairTrustScopedRecord, at time.Time) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return nodePairScopedSaveRecordBudget(tx, r, raw, at)
}
func nodePairScopedCached(tx *sql.Tx, h wire.NodePairTrustScopedPacket, digest string) ([]byte, error) {
	var oldDigest, op, attempt string
	var packet []byte
	err := tx.QueryRow(`SELECT request_digest,operation,attempt_id,response_packet FROM hub_node_pair_trust_receipts_v1 WHERE sender_key_id=? AND request_id=? UNION ALL SELECT request_digest,operation,attempt_id,response_packet FROM hub_node_pair_trust_reads_v1 WHERE sender_key_id=? AND request_id=?`, h.SenderPublic.ID, h.RequestID, h.SenderPublic.ID, h.RequestID).Scan(&oldDigest, &op, &attempt, &packet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if oldDigest != digest || op != h.Operation || attempt != h.AttemptID {
		return nil, ErrNodePairTrustRejected
	}
	return packet, nil
}
func nodePairScopedReceipt(tx *sql.Tx, in HubNodePairTrustScopedInput, result wire.NodePairTrustScopedResult) ([]byte, error) {
	critical := nodePairScopedCritical(tx, in, result)
	if !critical {
		if err := nodePairScopedReadRate(tx, in.Header, in.At); err != nil {
			return nil, err
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_reads_v1 WHERE attempt_id=?`, in.Header.AttemptID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 64 {
			return nil, ErrNodePairTrustCapacity
		}
	}
	packet, err := in.Seal(result)
	if err != nil {
		return nil, err
	}
	if len(packet) == 0 || len(packet) > wire.MaxNodePairTrustReconcileResponsePacketBytes {
		return nil, ErrNodePairTrustCapacity
	}
	if critical {
		if in.Header.Operation == wire.OperationNodePairTrustScopedPoll {
			var count, total int
			if tx.QueryRow(`SELECT count(*),COALESCE(sum(length(response_packet)),0) FROM hub_node_pair_trust_receipts_v1 WHERE attempt_id=? AND operation=?`, in.Header.AttemptID, wire.OperationNodePairTrustScopedPoll).Scan(&count, &total) != nil || count >= 64 || total+len(packet) > 10<<20 {
				return nil, ErrNodePairTrustCapacity
			}
		}
		if _, err = tx.Exec(`UPDATE hub_node_pair_trust_v1 SET reserved_bytes=max(0,reserved_bytes-?) WHERE attempt_id=?`, len(packet), in.Header.AttemptID); err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_receipts_v1(sender_key_id,request_id,attempt_id,operation,request_digest,state,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?)`, in.Header.SenderPublic.ID, in.Header.RequestID, in.Header.AttemptID, in.Header.Operation, wire.NodePairTrustScopedPacketDigest(in.Packet), result.State, packet, appNodeStamp(in.At))
	} else {
		_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_reads_v1(sender_key_id,request_id,attempt_id,operation,request_digest,state,response_packet,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, in.Header.SenderPublic.ID, in.Header.RequestID, in.Header.AttemptID, in.Header.Operation, wire.NodePairTrustScopedPacketDigest(in.Packet), result.State, packet, appNodeStamp(in.At), nodePairScopedReadExpiry(tx, in))
	}
	return packet, err
}

func nodePairScopedResult(in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) wire.NodePairTrustScopedResult {
	out := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: in.Header.Operation, RequestID: in.Header.RequestID, AttemptID: in.Header.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(in.Packet), State: r.State, Context: &r.Context, OOBCommitment: r.OOB, ObservedAt: appNodeStamp(in.At)}
	if r.OOB == "" && (in.Header.Operation == wire.OperationNodePairTrustScopedPoll || in.Header.Operation == wire.OperationNodePairTrustScopedCancel) && (r.State == wire.NodePairTrustScopedExpired || r.State == wire.NodePairTrustScopedCancelled || r.State == wire.NodePairTrustScopedRevoked) {
		out.Context = nil
		out.ErrorCode = r.State
		return out // Exact original Node only; never invent an uncommitted O.
	}
	if r.State == wire.NodePairTrustScopedACKed {
		out.Binding = r.Binding
	}
	if in.Header.Operation == wire.OperationNodePairTrustScopedPoll && r.State == wire.NodePairTrustScopedOwnerApproved {
		out.OwnerProof = r.OwnerProof
		out.TrustCapsule = r.Capsule
	}
	if (in.Header.Operation == wire.OperationOwnerNodePairTrustScopedStatus || in.Header.Operation == wire.OperationOwnerNodePairTrustScopedCancel) && r.State == wire.NodePairTrustScopedACKed && r.Context.Mode == wire.NodePairTrustScopedInitial {
		out.ConfirmationResponse = r.ConfirmationResponse
	}
	return out
}

// This is the sole effect gate for every original Node confirmation writer.
// ACKING exists only within the authenticated ACK's uncommitted transaction.
func nodePairScopedOwner(tx *sql.Tx, in HubNodePairTrustScopedInput, scope e2ee.OwnerAppNodeScopedScope, token []byte) (*hubAppNodeScopedActor, error) {
	base, err := appNodeActor(tx, in.Hub, scope.DeviceID, in.Header.SenderPublic, token, in.At)
	if err != nil {
		return nil, ErrNodePairTrustRejected
	}
	a := appNodeScopedActorFromBase(base, scope.AuthorityNodeID)
	if !appNodeScopedScopeCurrent(a, scope) {
		return nil, ErrNodePairTrustRejected
	}
	h, err := appNodeScopedHead(tx, scope.OwnerID, scope.DeviceID, scope.AuthorityNodeID)
	if err != nil || h.version != scope.HeadVersion {
		return nil, ErrNodePairTrustRejected
	}
	return a, nil
}
func nodePairScopedCurrentApproved(tx *sql.Tx, in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) (*hubAppNodeScopedActor, error) {
	if r.Approval == nil {
		return nil, ErrNodePairTrustRejected
	}
	a := r.Approval.Scope
	base, err := appNodeActor(tx, in.Hub, a.DeviceID, a.DevicePublic, nil, in.At)
	if err != nil {
		return nil, ErrNodePairTrustRejected
	}
	actor := appNodeScopedActorFromBase(base, a.AuthorityNodeID)
	if !actor.source || !appNodeScopedSameSecurity(actor.scope, a) {
		return nil, ErrNodePairTrustRejected
	}
	session, err := appNodeSession(tx, appNodeScopedIdentity(a), a.AccountSessionID, in.At)
	if err != nil || session.ExpiresAt != a.AccountSessionExpiresAt {
		return nil, ErrNodePairTrustRejected
	}
	h, err := appNodeScopedHead(tx, a.OwnerID, a.DeviceID, a.AuthorityNodeID)
	if err != nil || h.version != a.HeadVersion {
		return nil, ErrNodePairTrustRejected
	}
	actor.session = session
	actor.scope.AccountSessionID = session.ID
	actor.scope.AccountSessionExpiresAt = session.ExpiresAt
	return actor, nil
}

func nodePairScopedExpire(tx *sql.Tx, r *nodePairTrustScopedRecord, state string, at time.Time) error {
	if r.State != wire.NodePairTrustScopedPending && r.State != wire.NodePairTrustScopedOwnerApproved {
		return nil
	}
	r.State = state
	if r.Context.Candidate != nil {
		candidateState := "CANCELLED"
		if state == wire.NodePairTrustScopedExpired {
			candidateState = "EXPIRED"
		}
		// Retire the actual original candidate as well as the side attempt.
		// Its independent RequireACK marker remains 1 permanently. A fresh
		// explicit attempt must not wait on this already terminal candidate.
		if _, err := tx.Exec(`UPDATE node_control_key_requests_v1 SET state=?,version=version+1 WHERE id=? AND require_pair_trust_ack=1 AND state='PENDING'`, candidateState, r.Context.Candidate.RequestID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE hub_node_pair_trust_slots_v1 SET state='DONE' WHERE attempt_id=? AND state='RESERVED'`, r.Context.AttemptID); err != nil {
		return err
	}
	return nodePairScopedSave(tx, r, at)
}
func nodePairScopedRefresh(tx *sql.Tx, in HubNodePairTrustScopedInput, r *nodePairTrustScopedRecord) error {
	if r.State != wire.NodePairTrustScopedPending && r.State != wire.NodePairTrustScopedOwnerApproved {
		return nil
	}
	if !appNodeBefore(in.At, r.Context.ExpiresAt) || (r.Approval != nil && !appNodeBefore(in.At, r.Approval.AcceptBefore)) {
		return nodePairScopedExpire(tx, r, wire.NodePairTrustScopedExpired, in.At)
	}
	if r.Approval != nil {
		if _, err := nodePairScopedCurrentApproved(tx, in, r); err != nil {
			return nodePairScopedExpire(tx, r, wire.NodePairTrustScopedRevoked, in.At)
		}
	}
	return nil
}

func nodePairScopedExisting(tx *sql.Tx, c wire.NodePairTrustScopedContext) error {
	if c.Binding == nil {
		return ErrNodePairTrustRejected
	}
	var hash string
	if err := tx.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=? AND node_id=? AND owner_id=? AND state='ACTIVE'`, c.Binding.OwnerBindingID, c.Binding.NodeID, c.Binding.OwnerID).Scan(&hash); err != nil {
		return ErrNodePairTrustRejected
	}
	b, err := nodeControlCurrentBindingTx(tx, hash, c.Binding.NodeID)
	if err != nil || !reflect.DeepEqual(appNodeBindingPublic(*b), *c.Binding) {
		return ErrNodePairTrustRejected
	}
	return nil
}

func (s *Store) ProcessHubNodePairTrustScoped(in HubNodePairTrustScopedInput) (packet []byte, err error) {
	defer func() {
		if err != nil && strings.Contains(err.Error(), "node_pair_budget") {
			err = ErrNodePairTrustCapacity
		}
	}()
	if s.requireOwnerSetupStartupAllowed() != nil || in.Seal == nil || in.Header.Operation == "" || len(in.Packet) == 0 {
		return nil, ErrNodePairTrustRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = appNodeScopedWriterLock(tx); err != nil {
		return nil, err
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	if in.At.IsZero() {
		return nil, ErrNodePairTrustRejected
	}
	if err = nodePairGC(tx, in.At); err != nil {
		return nil, err
	}
	digest := wire.NodePairTrustScopedPacketDigest(in.Packet)
	if cached, e := nodePairScopedCached(tx, in.Header, digest); e != nil || cached != nil {
		return cached, e
	}
	if wire.ValidateNodePairTrustScopedRequestBody(in.Header, in.Body, in.Hub, in.At) != nil {
		return nil, ErrNodePairTrustRejected
	}
	if in.Header.Operation == wire.OperationNodePairTrustScopedReconcile {
		return nodePairScopedReconcile(tx, in)
	}
	var record *nodePairTrustScopedRecord
	if in.Header.Operation == wire.OperationNodePairTrustScopedStart || in.Header.Operation == wire.OperationNodePairTrustScopedExisting {
		record, err = nodePairScopedStart(tx, in)
	} else {
		record, err = nodePairScopedLoad(tx, in.Header.AttemptID)
	}
	if err != nil {
		return nil, err
	}
	if err = nodePairScopedRefresh(tx, in, record); err != nil {
		return nil, err
	}
	result, err := nodePairScopedApply(tx, in, record)
	if err != nil {
		return nil, err
	}
	packet, err = nodePairScopedReceipt(tx, in, result)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func nodePairScopedStart(tx *sql.Tx, in HubNodePairTrustScopedInput) (*nodePairTrustScopedRecord, error) {
	if existing, err := nodePairScopedLoad(tx, in.Header.AttemptID); err == nil || !errors.Is(err, sql.ErrNoRows) {
		_ = existing
		return nil, ErrNodePairTrustRejected
	}
	var c wire.NodePairTrustScopedContext
	candidateID := ""
	switch b := in.Body.(type) {
	case wire.NodePairTrustScopedStart:
		if in.Start == nil || in.Selector == "" || !reflect.DeepEqual(in.Start.NodePublicIdentity, in.Header.SenderPublic) || !reflect.DeepEqual(in.Start.HubPublicIdentity, in.NodeControlPublic) {
			return nil, ErrNodePairTrustRejected
		}
		n, err := startNodeControlKeyRequestTx(tx, *in.Start, in.At)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE node_control_key_requests_v1 SET require_pair_trust_ack=1 WHERE id=? AND require_pair_trust_ack=0`, n.RequestID); err != nil {
			return nil, err
		}
		candidate := e2ee.OwnerAppNodeCandidate{RequestID: n.RequestID, Version: uint64(n.Version), Mode: n.Mode, State: n.State, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, NodePublic: in.Start.NodePublicIdentity, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: in.Start.HubPublicIdentity, HubNodeControlKeyVersion: n.HubNodeControlKeyVersion, HubNodeControlFingerprint: n.HubNodeControlFingerprint, CandidateDigest: n.CandidateDigest, CodeDigest: in.Start.CodeDigest, ExpiresAt: n.ExpiresAt}
		c = wire.NodePairTrustScopedContext{ScopeVersion: 2, AuthorityNodeID: b.NodeID, Format: wire.NodePairTrustScopedFormat, AttemptID: in.Header.AttemptID, Hub: in.Hub, Origin: b.Origin, DescriptorDigest: b.DescriptorDigest, NodeNonce: hex.EncodeToString(b.RequestNonce), Mode: wire.NodePairTrustScopedInitial, Candidate: &candidate, IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt}
		candidateID = n.RequestID
	case wire.NodePairTrustScopedExistingStart:
		c = b.Context
		if b.RetainedBinding != nil {
			r := *b.RetainedBinding
			binding, err := nodeControlCurrentBindingTx(tx, r.CredentialDigest, r.NodeID)
			if err != nil {
				return nil, ErrNodePairTrustRejected
			}
			public := appNodeBindingPublic(*binding)
			if wire.MatchNodePairTrustRetainedBinding(r, public, in.Header.SenderPublic) != nil {
				return nil, ErrNodePairTrustRejected
			}
			c.Binding = &public
		}
		if c.Binding == nil || !reflect.DeepEqual(c.Binding.HubNodeControlPublic, in.NodeControlPublic) || wire.ValidateNodePairTrustScopedContext(c, in.At) != nil {
			return nil, ErrNodePairTrustRejected
		}
		if err := nodePairScopedExisting(tx, c); err != nil {
			return nil, err
		}
	default:
		return nil, ErrNodePairTrustRejected
	}
	d, err := wire.NodePairTrustScopedContextDigest(c)
	if err != nil {
		return nil, err
	}
	r := &nodePairTrustScopedRecord{Context: c, State: wire.NodePairTrustScopedPending}
	raw, _ := json.Marshal(r)
	ctxRaw, _ := json.Marshal(c)
	var node string
	if c.Candidate != nil {
		node = c.Candidate.NodeID
	} else {
		node = c.Binding.NodeID
	}
	if _, err = tx.Exec(`INSERT INTO hub_node_pair_trust_v1(attempt_id,node_id,node_key_id,mode,candidate_request_id,context_digest,context_json,gc_after,state,record_json,created_at,updated_at,authority_kind) VALUES(?,?,?,?,?,?,?,?,'PENDING',?,?,?,'NODE_V1')`, c.AttemptID, node, in.Header.SenderPublic.ID, c.Mode, candidateID, d, string(ctxRaw), appNodeStamp(nodePairScopedContextExpiry(c).Add(10*time.Minute)), string(raw), appNodeStamp(in.At), appNodeStamp(in.At)); err != nil {
		return nil, err
	}
	return r, nil
}
