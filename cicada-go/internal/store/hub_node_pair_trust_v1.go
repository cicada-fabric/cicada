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

var ErrNodePairTrustACKRequired = errors.New("ACK_REQUIRED")
var ErrNodePairTrustRejected = errors.New("Node pairing trust request rejected")
var ErrNodePairTrustCapacity = errors.New("Node pairing trust capacity exhausted")

type HubNodePairTrustSeal func(wire.NodePairTrustResult) ([]byte, error)
type HubNodePairTrustInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Header            wire.NodePairTrustPacket
	Body              any
	Packet            []byte
	At                time.Time
	Now               func() time.Time
	Start             *NodeControlKeyRequestInput
	Selector          string
	Seal              HubNodePairTrustSeal
	OpenConfirmation  func([]byte, e2ee.PublicIdentity) (HubAppNodeClientInput, error)
	Original          *HubNodePairTrustInput
}

// No plaintext S, bearer or App session token is retained in this record.
type nodePairTrustRecord struct {
	Context              wire.NodePairTrustContext   `json:"context"`
	OOB                  string                      `json:"oob_commitment"`
	State                string                      `json:"state"`
	Approval             *wire.NodePairTrustApproval `json:"approval,omitempty"`
	Grant                []byte                      `json:"grant,omitempty"`
	Confirmation         []byte                      `json:"confirmation,omitempty"`
	OwnerProof           []byte                      `json:"owner_proof,omitempty"`
	Capsule              []byte                      `json:"capsule,omitempty"`
	Binding              *e2ee.OwnerAppNodeBinding   `json:"binding,omitempty"`
	ConfirmationResponse []byte                      `json:"confirmation_response,omitempty"`
}

func nodePairLoad(tx *sql.Tx, id string) (*nodePairTrustRecord, error) {
	var raw string
	err := tx.QueryRow(`SELECT record_json FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, id).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var r nodePairTrustRecord
	if json.Unmarshal([]byte(raw), &r) != nil {
		return nil, ErrNodePairTrustRejected
	}
	return &r, nil
}
func nodePairSave(tx *sql.Tx, r *nodePairTrustRecord, at time.Time) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return nodePairSaveRecordBudget(tx, r, raw, at)
}
func nodePairCached(tx *sql.Tx, h wire.NodePairTrustPacket, digest string) ([]byte, error) {
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
func nodePairReceipt(tx *sql.Tx, in HubNodePairTrustInput, result wire.NodePairTrustResult) ([]byte, error) {
	critical := nodePairCritical(tx, in, result)
	if !critical {
		if err := nodePairReadRate(tx, in.Header, in.At); err != nil {
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
		if in.Header.Operation == wire.OperationNodePairTrustPoll {
			var count, total int
			if tx.QueryRow(`SELECT count(*),COALESCE(sum(length(response_packet)),0) FROM hub_node_pair_trust_receipts_v1 WHERE attempt_id=? AND operation=?`, in.Header.AttemptID, wire.OperationNodePairTrustPoll).Scan(&count, &total) != nil || count >= 64 || total+len(packet) > 10<<20 {
				return nil, ErrNodePairTrustCapacity
			}
		}
		if _, err = tx.Exec(`UPDATE hub_node_pair_trust_v1 SET reserved_bytes=max(0,reserved_bytes-?) WHERE attempt_id=?`, len(packet), in.Header.AttemptID); err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_receipts_v1(sender_key_id,request_id,attempt_id,operation,request_digest,state,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?)`, in.Header.SenderPublic.ID, in.Header.RequestID, in.Header.AttemptID, in.Header.Operation, wire.NodePairTrustPacketDigest(in.Packet), result.State, packet, appNodeStamp(in.At))
	} else {
		_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_reads_v1(sender_key_id,request_id,attempt_id,operation,request_digest,state,response_packet,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, in.Header.SenderPublic.ID, in.Header.RequestID, in.Header.AttemptID, in.Header.Operation, wire.NodePairTrustPacketDigest(in.Packet), result.State, packet, appNodeStamp(in.At), nodePairReadExpiry(tx, in))
	}
	return packet, err
}

func nodePairResult(in HubNodePairTrustInput, r *nodePairTrustRecord) wire.NodePairTrustResult {
	out := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: in.Header.Operation, RequestID: in.Header.RequestID, AttemptID: in.Header.AttemptID, RequestPacketDigest: wire.NodePairTrustPacketDigest(in.Packet), State: r.State, Context: &r.Context, OOBCommitment: r.OOB, ObservedAt: appNodeStamp(in.At)}
	if r.State == wire.NodePairTrustACKed {
		out.Binding = r.Binding
	}
	if in.Header.Operation == wire.OperationNodePairTrustPoll && r.State == wire.NodePairTrustOwnerApproved {
		out.OwnerProof = r.OwnerProof
		out.TrustCapsule = r.Capsule
	}
	if (in.Header.Operation == wire.OperationOwnerNodePairTrustStatus || in.Header.Operation == wire.OperationOwnerNodePairTrustCancel) && r.State == wire.NodePairTrustACKed && r.Context.Mode == wire.NodePairTrustInitial {
		out.ConfirmationResponse = r.ConfirmationResponse
	}
	return out
}

// This is the sole effect gate for every original Node confirmation writer.
// ACKING exists only within the authenticated ACK's uncommitted transaction.
func nodePairConfirmGuardTx(tx *sql.Tx, requestID string) error {
	var required int
	if err := tx.QueryRow(`SELECT require_pair_trust_ack FROM node_control_key_requests_v1 WHERE id=?`, requestID).Scan(&required); err != nil {
		return err
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM hub_node_pair_trust_v1 WHERE candidate_request_id=?`, requestID).Scan(&state)
	if required == 0 && errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || required != 1 {
		return ErrNodePairTrustRejected
	}
	if state == "ACKING" {
		return nil
	}
	if state == wire.NodePairTrustPending || state == wire.NodePairTrustOwnerApproved {
		return ErrNodePairTrustACKRequired
	}
	return ErrNodeControlPairingNotFound
}
func nodePairClientSlotGuardTx(tx *sql.Tx, owner, device string, epoch uint64) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_slots_v1 slot JOIN hub_node_pair_trust_v1 attempt ON attempt.attempt_id=slot.attempt_id WHERE slot.owner_id=? AND slot.device_id=? AND slot.session_epoch=? AND slot.state='RESERVED' AND attempt.state!='ACKING'`, owner, device, epoch).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrNodePairTrustACKRequired
	}
	return nil
}

func nodePairOriginalClientGuardTx(tx *sql.Tx, in HubAppNodeClientInput, fence bool) error {
	var required int
	var request string
	err := tx.QueryRow(`SELECT id,require_pair_trust_ack FROM node_control_key_requests_v1 WHERE candidate_digest=?`, in.CandidateDigest).Scan(&request, &required)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if required == 0 {
		return nil
	}
	var state string
	if tx.QueryRow(`SELECT state FROM hub_node_pair_trust_v1 WHERE candidate_request_id=?`, request).Scan(&state) != nil {
		return ErrNodePairTrustRejected
	}
	if fence && state != "ACKING" {
		var attempt string
		if err := tx.QueryRow(`SELECT attempt_id FROM hub_node_pair_trust_v1 WHERE candidate_request_id=?`, request).Scan(&attempt); err != nil {
			return ErrNodePairTrustRejected
		}
		r, err := nodePairLoad(tx, attempt)
		if err != nil {
			return err
		}
		if err = nodePairRefresh(tx, HubNodePairTrustInput{Hub: in.Hub, At: in.At}, r); err != nil {
			return err
		}
		state = r.State
	}
	if state == "ACKING" {
		return nil
	}
	if state == wire.NodePairTrustPending || state == wire.NodePairTrustOwnerApproved || !fence {
		return ErrNodePairTrustACKRequired
	}
	return nil // Only the authenticated original reconcile may seal no effect.
}

func nodePairOwner(tx *sql.Tx, in HubNodePairTrustInput, scope e2ee.OwnerAppNodeScope, token []byte) (*hubAppNodeActor, error) {
	a, err := appNodeActor(tx, in.Hub, scope.DeviceID, in.Header.SenderPublic, token, in.At)
	if err != nil || !appNodeScopeCurrent(a, scope) {
		return nil, ErrNodePairTrustRejected
	}
	h, err := appNodeHead(tx, scope.OwnerID, scope.DeviceID)
	if err != nil || h.version != scope.HeadVersion {
		return nil, ErrNodePairTrustRejected
	}
	return a, nil
}
func nodePairCurrentApproved(tx *sql.Tx, in HubNodePairTrustInput, r *nodePairTrustRecord) (*hubAppNodeActor, error) {
	if r.Approval == nil {
		return nil, ErrNodePairTrustRejected
	}
	a := r.Approval.Scope
	actor, err := appNodeActor(tx, in.Hub, a.DeviceID, a.DevicePublic, nil, in.At)
	if err != nil || !actor.source || !appNodeSameSecurity(actor.scope, a) {
		return nil, ErrNodePairTrustRejected
	}
	session, err := appNodeSession(tx, a, a.AccountSessionID, in.At)
	if err != nil || session.ExpiresAt != a.AccountSessionExpiresAt {
		return nil, ErrNodePairTrustRejected
	}
	h, err := appNodeHead(tx, a.OwnerID, a.DeviceID)
	if err != nil || h.version != a.HeadVersion {
		return nil, ErrNodePairTrustRejected
	}
	actor.session = session
	actor.scope.AccountSessionID = session.ID
	actor.scope.AccountSessionExpiresAt = session.ExpiresAt
	return actor, nil
}

func nodePairExpire(tx *sql.Tx, r *nodePairTrustRecord, state string, at time.Time) error {
	if r.State != wire.NodePairTrustPending && r.State != wire.NodePairTrustOwnerApproved {
		return nil
	}
	r.State = state
	if _, err := tx.Exec(`UPDATE hub_node_pair_trust_slots_v1 SET state='DONE' WHERE attempt_id=? AND state='RESERVED'`, r.Context.AttemptID); err != nil {
		return err
	}
	return nodePairSave(tx, r, at)
}
func nodePairRefresh(tx *sql.Tx, in HubNodePairTrustInput, r *nodePairTrustRecord) error {
	if r.State != wire.NodePairTrustPending && r.State != wire.NodePairTrustOwnerApproved {
		return nil
	}
	if !appNodeBefore(in.At, r.Context.ExpiresAt) || (r.Approval != nil && !appNodeBefore(in.At, r.Approval.AcceptBefore)) {
		return nodePairExpire(tx, r, wire.NodePairTrustExpired, in.At)
	}
	if r.Approval != nil {
		if _, err := nodePairCurrentApproved(tx, in, r); err != nil {
			return nodePairExpire(tx, r, wire.NodePairTrustRevoked, in.At)
		}
	}
	return nil
}

func nodePairExisting(tx *sql.Tx, c wire.NodePairTrustContext) error {
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

func (s *Store) ProcessHubNodePairTrust(in HubNodePairTrustInput) (packet []byte, err error) {
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
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	if in.At.IsZero() {
		return nil, ErrNodePairTrustRejected
	}
	if err = nodePairGC(tx, in.At); err != nil {
		return nil, err
	}
	digest := wire.NodePairTrustPacketDigest(in.Packet)
	if cached, e := nodePairCached(tx, in.Header, digest); e != nil || cached != nil {
		return cached, e
	}
	if wire.ValidateNodePairTrustRequestBody(in.Header, in.Body, in.Hub, in.At) != nil {
		return nil, ErrNodePairTrustRejected
	}
	if in.Header.Operation == wire.OperationNodePairTrustReconcile {
		return nodePairReconcile(tx, in)
	}
	var record *nodePairTrustRecord
	if in.Header.Operation == wire.OperationNodePairTrustStart || in.Header.Operation == wire.OperationNodePairTrustExisting {
		record, err = nodePairStart(tx, in)
	} else {
		record, err = nodePairLoad(tx, in.Header.AttemptID)
	}
	if err != nil {
		return nil, err
	}
	if err = nodePairRefresh(tx, in, record); err != nil {
		return nil, err
	}
	result, err := nodePairApply(tx, in, record)
	if err != nil {
		return nil, err
	}
	packet, err = nodePairReceipt(tx, in, result)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func nodePairStart(tx *sql.Tx, in HubNodePairTrustInput) (*nodePairTrustRecord, error) {
	if existing, err := nodePairLoad(tx, in.Header.AttemptID); err == nil || !errors.Is(err, sql.ErrNoRows) {
		_ = existing
		return nil, ErrNodePairTrustRejected
	}
	var c wire.NodePairTrustContext
	candidateID := ""
	switch b := in.Body.(type) {
	case wire.NodePairTrustStart:
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
		c = wire.NodePairTrustContext{Format: wire.NodePairTrustFormat, AttemptID: in.Header.AttemptID, Hub: in.Hub, Origin: b.Origin, DescriptorDigest: b.DescriptorDigest, NodeNonce: hex.EncodeToString(b.RequestNonce), Mode: wire.NodePairTrustInitial, Candidate: &candidate, IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt}
		candidateID = n.RequestID
	case wire.NodePairTrustExistingStart:
		c = b.Context
		if err := nodePairExisting(tx, c); err != nil {
			return nil, err
		}
	default:
		return nil, ErrNodePairTrustRejected
	}
	d, err := wire.NodePairTrustContextDigest(c)
	if err != nil {
		return nil, err
	}
	r := &nodePairTrustRecord{Context: c, State: wire.NodePairTrustPending}
	raw, _ := json.Marshal(r)
	ctxRaw, _ := json.Marshal(c)
	var node string
	if c.Candidate != nil {
		node = c.Candidate.NodeID
	} else {
		node = c.Binding.NodeID
	}
	if _, err = tx.Exec(`INSERT INTO hub_node_pair_trust_v1(attempt_id,node_id,node_key_id,mode,candidate_request_id,context_digest,context_json,gc_after,state,record_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'PENDING',?,?,?)`, c.AttemptID, node, in.Header.SenderPublic.ID, c.Mode, candidateID, d, string(ctxRaw), appNodeStamp(nodePairContextExpiry(c).Add(10*time.Minute)), string(raw), appNodeStamp(in.At), appNodeStamp(in.At)); err != nil {
		return nil, err
	}
	return r, nil
}
