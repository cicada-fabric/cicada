package nodekeys

import (
	"bytes"
	"context"
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

var (
	ErrNativePairPolicy   = errors.New("Node native pair policy is missing or differs from the independently trusted target")
	ErrNativePairBudget   = errors.New("Node native pair budget does not admit this operation")
	ErrNativePairConflict = errors.New("Node native pair immutable operation conflicts with retained state")
)

func initializeNativePairSchema(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS node_native_pair_nodes (
 hub_id TEXT NOT NULL, node_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 owner_key_id TEXT NOT NULL, tuple_digest TEXT NOT NULL,
 credential_version INTEGER NOT NULL CHECK(credential_version>0),
 control_binding_version INTEGER NOT NULL CHECK(control_binding_version>0),
 PRIMARY KEY(hub_id,node_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS node_native_pair_policies (
 pair_id TEXT PRIMARY KEY, hub_id TEXT NOT NULL, node_id TEXT NOT NULL,
 group_id TEXT NOT NULL UNIQUE, network_id TEXT NOT NULL,
 tuple_digest TEXT NOT NULL, bootstrap_digest TEXT NOT NULL,
 bootstrap_proof BLOB NOT NULL, hub_identity BLOB NOT NULL,
 join_until TEXT NOT NULL, peer_expires_at TEXT NOT NULL,
 UNIQUE(hub_id,node_id,pair_id)
);
CREATE TABLE IF NOT EXISTS node_native_pair_messages (
 pair_id TEXT NOT NULL, message_id TEXT NOT NULL, request_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('ASK','REPLY')),
 sender TEXT NOT NULL, receiver TEXT NOT NULL, digest TEXT NOT NULL,
 plaintext_bytes INTEGER NOT NULL CHECK(plaintext_bytes>=0),
 ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>0),
 state TEXT NOT NULL CHECK(state IN ('RESERVED','ADMITTED')),
 terminal TEXT NOT NULL DEFAULT '' CHECK(terminal IN ('','REPLIED','CANCELLED','EXPIRED')),
 PRIMARY KEY(pair_id,message_id), UNIQUE(pair_id,kind,request_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS node_native_pair_submissions (
 pair_id TEXT NOT NULL, message_id TEXT NOT NULL, receiver TEXT NOT NULL,
 native_session_id TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(pair_id,message_id,receiver,native_session_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS node_native_pair_local_keys (
 endpoint_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, public_identity BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS node_native_pair_attestations (
 pair_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, group_id TEXT NOT NULL,
 principal_id TEXT NOT NULL, node_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 binding_id TEXT NOT NULL, binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),
 fingerprint TEXT NOT NULL, proof_digest TEXT NOT NULL, proof BLOB NOT NULL,
 candidate_version INTEGER NOT NULL DEFAULT 0 CHECK(candidate_version>=0),
 PRIMARY KEY(endpoint_id,binding_id,binding_epoch)
) WITHOUT ROWID;
`)
	return err
}

// NativePairPolicy is public signed metadata, never a bearer or private key.
type NativePairPolicy struct {
	PairID, GroupID, NetworkID, NodeID string
	NodeTupleDigest, BootstrapDigest   string
	BootstrapProof                     []byte
	HubIdentity                        wire.HubIdentity
	JoinUntil, PeerExpiresAt           string
}

// RequireNativePairPolicy is called after the agent matches known local Node,
// Hub-control and actual credential-commitment fields. expected is that checked
// full scope, not a model's input. The independently installed Owner pin is
// rechecked within the transaction. The two first versions, original proof and
// required-policy marker commit together before a Join can leave the Node.
func (s *CryptoState) RequireNativePairPolicy(ctx context.Context, hub wire.HubIdentity, expected e2ee.OwnerNativePairScope, proof []byte, now time.Time) (*NativePairPolicy, error) {
	if ctx == nil || now.IsZero() || wire.ValidateNativePairScope(expected, hub) != nil || len(proof) == 0 || len(proof) > e2ee.MaxOwnerNativePairProofBytes {
		return nil, ErrNativePairPolicy
	}
	hubJSON, err := json.Marshal(hub)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var result *NativePairPolicy
	err = s.writeTx(ctx, func(conn *sql.Conn) error {
		trust, err := loadNodeOwnerKeyTrust(ctx, conn, expected.Actor.OwnerID, expected.Actor.OwnerPublic.ID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive || !samePublicIdentity(trust.PublicIdentity, expected.Actor.OwnerPublic) {
			return ErrNativePairPolicy
		}
		claims, err := e2ee.VerifyOwnerNativePair(trust.PublicIdentity, proof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
		if err != nil || !reflect.DeepEqual(claims.Scope, expected) {
			return ErrNativePairPolicy
		}
		b := claims.Bootstrap
		if b == nil {
			return ErrNativePairPolicy
		}
		result = &NativePairPolicy{PairID: b.PairID, GroupID: b.GroupID, NetworkID: b.NetworkID, NodeID: expected.Node.NodeID, NodeTupleDigest: expected.NodeTupleDigest, BootstrapDigest: wire.NativePairProofDigest(proof), BootstrapProof: bytes.Clone(proof), HubIdentity: hub, JoinUntil: b.JoinUntil, PeerExpiresAt: b.PeerExpiresAt}
		old, err := loadNativePairPolicy(ctx, conn, b.PairID)
		if err == nil {
			if old.BootstrapDigest != result.BootstrapDigest || !reflect.DeepEqual(*old, *result) {
				return ErrNativePairConflict
			}
			result = old
			return nil // Historical lookup never renews Join or peer time.
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		join, err := time.Parse(time.RFC3339Nano, b.JoinUntil)
		prepared, preparedErr := time.Parse(time.RFC3339Nano, b.PreparedAt)
		if err != nil || preparedErr != nil || now.Before(prepared) || !now.Before(join) {
			return ErrNativePairPolicy
		}
		var owner, key, tuple string
		var credential, control uint64
		err = conn.QueryRowContext(ctx, `SELECT owner_id,owner_key_id,tuple_digest,credential_version,control_binding_version FROM node_native_pair_nodes WHERE hub_id=? AND node_id=?`, hub.HubID, expected.Node.NodeID).Scan(&owner, &key, &tuple, &credential, &control)
		if err == nil {
			if owner != expected.Actor.OwnerID || key != expected.Actor.OwnerPublic.ID || tuple != expected.NodeTupleDigest || credential != expected.Node.CredentialVersion || control != expected.NodeControlBindingVersion {
				return ErrNativePairConflict
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			_, err = conn.ExecContext(ctx, `INSERT INTO node_native_pair_nodes VALUES(?,?,?,?,?,?,?)`, hub.HubID, expected.Node.NodeID, expected.Actor.OwnerID, expected.Actor.OwnerPublic.ID, expected.NodeTupleDigest, expected.Node.CredentialVersion, expected.NodeControlBindingVersion)
			if err != nil {
				return err
			}
		} else {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_native_pair_policies VALUES(?,?,?,?,?,?,?,?,?,?,?)`, b.PairID, hub.HubID, expected.Node.NodeID, b.GroupID, b.NetworkID, expected.NodeTupleDigest, result.BootstrapDigest, proof, hubJSON, b.JoinUntil, b.PeerExpiresAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func loadNativePairPolicy(ctx context.Context, conn *sql.Conn, pairID string) (*NativePairPolicy, error) {
	p := new(NativePairPolicy)
	var hub []byte
	err := conn.QueryRowContext(ctx, `SELECT pair_id,group_id,network_id,node_id,tuple_digest,bootstrap_digest,bootstrap_proof,hub_identity,join_until,peer_expires_at FROM node_native_pair_policies WHERE pair_id=?`, pairID).Scan(&p.PairID, &p.GroupID, &p.NetworkID, &p.NodeID, &p.NodeTupleDigest, &p.BootstrapDigest, &p.BootstrapProof, &hub, &p.JoinUntil, &p.PeerExpiresAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(hub, &p.HubIdentity) != nil {
		return nil, ErrNativePairPolicy
	}
	return p, nil
}

// NativePairPolicyRequired never infers legacy eligibility from missing peer
// evidence. A marker exists before that Pair's dedicated Join request is sent.
func (s *CryptoState) NativePairPolicyRequired(ctx context.Context, groupID string) (bool, error) {
	if ctx == nil || validateCryptoToken("Group ID", groupID) != nil {
		return false, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM node_native_pair_policies WHERE group_id=?`, groupID).Scan(&count)
	return count == 1, err
}

// NativePairPolicyForGroup is local recovery metadata, not live eligibility.
func (s *CryptoState) NativePairPolicyForGroup(ctx context.Context, groupID string) (*NativePairPolicy, error) {
	if ctx == nil || validateCryptoToken("Group ID", groupID) != nil {
		return nil, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.configureConnection(ctx, conn); err != nil {
		return nil, err
	}
	var id string
	if err := conn.QueryRowContext(ctx, `SELECT pair_id FROM node_native_pair_policies WHERE group_id=?`, groupID).Scan(&id); err != nil {
		return nil, err
	}
	return loadNativePairPolicy(ctx, conn, id)
}

// NativePairMessage records only immutable routing, byte counts and ciphertext
// digest. RESERVED includes UNKNOWN; it is never refunded or reset on reopen.
type NativePairMessage struct {
	MessageID, RequestID, Kind, ParentRequestID  string
	SenderEndpointID, ReceiverEndpointID, Digest string
	PlaintextBytes, CiphertextBytes              uint64
}

func validateNativePairMessage(m NativePairMessage) error {
	for _, v := range []string{m.MessageID, m.RequestID, m.SenderEndpointID, m.ReceiverEndpointID} {
		if validateCryptoToken("Pair message identity", v) != nil {
			return ErrNativePairBudget
		}
	}
	d, err := hex.DecodeString(m.Digest)
	if err != nil || len(d) != 32 || strings.ToLower(m.Digest) != m.Digest || m.ParentRequestID != "" || (m.Kind != "ASK" && m.Kind != "REPLY") || m.SenderEndpointID == m.ReceiverEndpointID || m.PlaintextBytes > 8192 || m.CiphertextBytes == 0 || m.CiphertextBytes > 128*1024 {
		return ErrNativePairBudget
	}
	return nil
}

// ReserveNativePairMessage counts one message once across sender and receiver.
// existing=true is diagnostic/recovery only, not permission to reinject it.
func (s *CryptoState) ReserveNativePairMessage(ctx context.Context, evidence wire.NativePairPeerEvidence, m NativePairMessage, now time.Time) (existing bool, result error) {
	if ctx == nil || now.IsZero() || validateNativePairMessage(m) != nil {
		return false, ErrNativePairBudget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadNativePairPolicy(ctx, conn, evidence.Plan.PairID)
		if err != nil {
			return ErrNativePairPolicy
		}
		var old NativePairMessage
		err = conn.QueryRowContext(ctx, `SELECT message_id,request_id,kind,sender,receiver,digest,plaintext_bytes,ciphertext_bytes FROM node_native_pair_messages WHERE pair_id=? AND message_id=?`, p.PairID, m.MessageID).Scan(&old.MessageID, &old.RequestID, &old.Kind, &old.SenderEndpointID, &old.ReceiverEndpointID, &old.Digest, &old.PlaintextBytes, &old.CiphertextBytes)
		if err == nil {
			if old != m {
				return ErrNativePairConflict
			}
			existing = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := verifyNativePairEvidence(ctx, conn, *p, evidence, now); err != nil {
			return err
		}
		a, b := evidence.Plan.SlotA, evidence.Plan.SlotB
		if !((m.SenderEndpointID == a.EndpointID && m.ReceiverEndpointID == b.EndpointID) || (m.SenderEndpointID == b.EndpointID && m.ReceiverEndpointID == a.EndpointID)) {
			return ErrNativePairPolicy
		}
		var asks, replies, total, plain, cipher, outstanding int64
		if err := conn.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(plaintext_bytes),0),coalesce(sum(ciphertext_bytes),0),coalesce(sum(kind='ASK'),0),coalesce(sum(kind='REPLY'),0),coalesce(sum(kind='ASK' AND terminal=''),0) FROM node_native_pair_messages WHERE pair_id=?`, p.PairID).Scan(&total, &plain, &cipher, &asks, &replies, &outstanding); err != nil {
			return err
		}
		if total >= 8 || plain+int64(m.PlaintextBytes) > 64*1024 || cipher+int64(m.CiphertextBytes) > 1024*1024 {
			return ErrNativePairBudget
		}
		if m.Kind == "ASK" {
			if asks >= 4 || outstanding != 0 {
				return ErrNativePairBudget
			}
		} else {
			if replies >= 4 {
				return ErrNativePairBudget
			}
			var sender, receiver, terminal string
			if err := conn.QueryRowContext(ctx, `SELECT sender,receiver,terminal FROM node_native_pair_messages WHERE pair_id=? AND request_id=? AND kind='ASK'`, p.PairID, m.RequestID).Scan(&sender, &receiver, &terminal); err != nil || sender != m.ReceiverEndpointID || receiver != m.SenderEndpointID || terminal != "" {
				return ErrNativePairBudget
			}
		}
		var duplicate int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM node_native_pair_messages WHERE pair_id=? AND kind=? AND request_id=?`, p.PairID, m.Kind, m.RequestID).Scan(&duplicate); err != nil {
			return err
		}
		if duplicate != 0 {
			return ErrNativePairConflict
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_native_pair_messages(pair_id,message_id,request_id,kind,sender,receiver,digest,plaintext_bytes,ciphertext_bytes,state) VALUES(?,?,?,?,?,?,?,?,?,'RESERVED')`, p.PairID, m.MessageID, m.RequestID, m.Kind, m.SenderEndpointID, m.ReceiverEndpointID, m.Digest, m.PlaintextBytes, m.CiphertextBytes)
		return err
	})
	return existing, err
}

func verifyNativePairEvidence(ctx context.Context, conn *sql.Conn, p NativePairPolicy, e wire.NativePairPeerEvidence, now time.Time) error {
	if e.Plan.GroupID != p.GroupID || e.Plan.NetworkID != p.NetworkID || e.Plan.BootstrapProofDigest != p.BootstrapDigest || !bytes.Equal(e.BootstrapOwnerProof, p.BootstrapProof) {
		return ErrNativePairPolicy
	}
	t, err := loadNodeOwnerKeyTrust(ctx, conn, e.Plan.Scope.Actor.OwnerID, e.Plan.Scope.Actor.OwnerPublic.ID)
	if err != nil || t.State != NodeOwnerKeyTrustActive || wire.VerifyNativePairPeerEvidence(e, p.HubIdentity, t.PublicIdentity, p.NodeTupleDigest, now) != nil {
		return ErrNativePairPolicy
	}
	return nil
}

// VerifyNativePairGroupEvidence checks the actual routed Group, not a Group
// selected by the bundle. Pair-required absence is never a legacy fallback.
func (s *CryptoState) VerifyNativePairGroupEvidence(ctx context.Context, groupID string, e *wire.NativePairPeerEvidence, now time.Time) (required bool, result error) {
	if ctx == nil || now.IsZero() || validateCryptoToken("Group ID", groupID) != nil {
		return false, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		var id string
		err := conn.QueryRowContext(ctx, `SELECT pair_id FROM node_native_pair_policies WHERE group_id=?`, groupID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			if e != nil {
				return ErrNativePairPolicy
			}
			return nil
		}
		if err != nil {
			return err
		}
		required = true
		if e == nil || e.Plan.PairID != id {
			return ErrNativePairPolicy
		}
		p, err := loadNativePairPolicy(ctx, conn, id)
		if err != nil {
			return err
		}
		return verifyNativePairEvidence(ctx, conn, *p, *e, now)
	})
	return required, err
}

// VerifyNativePairGroupAuthorization adds the independent live Current carrier
// to the retained Owner policy. The routed Group selects required, never a flag
// or a Group copied out of the peer's bundle. Legacy Groups need both absent.
func (s *CryptoState) VerifyNativePairGroupAuthorization(ctx context.Context, groupID string, evidence *wire.NativePairPeerEvidence, current *wire.NativePairPeerCurrent, sender, receiver string, now time.Time) (required bool, result error) {
	if ctx == nil || now.IsZero() || validateCryptoToken("Group ID", groupID) != nil {
		return false, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		var id string
		err := conn.QueryRowContext(ctx, `SELECT pair_id FROM node_native_pair_policies WHERE group_id=?`, groupID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			if evidence != nil || current != nil {
				return ErrNativePairPolicy
			}
			return nil
		}
		if err != nil {
			return err
		}
		required = true
		if evidence == nil || current == nil || evidence.Plan.PairID != id {
			return ErrNativePairPolicy
		}
		p, err := loadNativePairPolicy(ctx, conn, id)
		if err != nil {
			return err
		}
		if evidence.Plan.GroupID != groupID || evidence.Plan.NetworkID != p.NetworkID || evidence.Plan.BootstrapProofDigest != p.BootstrapDigest || !bytes.Equal(evidence.BootstrapOwnerProof, p.BootstrapProof) {
			return ErrNativePairPolicy
		}
		trust, err := loadNodeOwnerKeyTrust(ctx, conn, evidence.Plan.Scope.Actor.OwnerID, evidence.Plan.Scope.Actor.OwnerPublic.ID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive || wire.VerifyNativePairPeerAuthorization(true, evidence, current, p.HubIdentity, trust.PublicIdentity, p.NodeTupleDigest, sender, receiver, now) != nil {
			return ErrNativePairPolicy
		}
		return nil
	})
	return required, err
}

// ConfirmNativePairAdmission is called only after an authenticated matching Hub
// receipt/current delivery authorization. A reserved reply alone cannot free an
// outstanding ask. This does not refund any message or byte reservation.
func (s *CryptoState) ConfirmNativePairAdmission(ctx context.Context, pairID, messageID, digest string) error {
	if ctx == nil {
		return ErrNativePairBudget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		var kind, request, stored string
		if err := conn.QueryRowContext(ctx, `SELECT kind,request_id,digest FROM node_native_pair_messages WHERE pair_id=? AND message_id=?`, pairID, messageID).Scan(&kind, &request, &stored); err != nil || stored != digest {
			return ErrNativePairConflict
		}
		if _, err := conn.ExecContext(ctx, `UPDATE node_native_pair_messages SET state='ADMITTED' WHERE pair_id=? AND message_id=?`, pairID, messageID); err != nil {
			return err
		}
		if kind == "REPLY" {
			_, err := conn.ExecContext(ctx, `UPDATE node_native_pair_messages SET terminal='REPLIED' WHERE pair_id=? AND request_id=? AND kind='ASK' AND terminal=''`, pairID, request)
			return err
		}
		return nil
	})
}

// CloseNativePairRequest requires an already authenticated caller-scoped Hub
// cancellation/expiry outcome. Reservations remain charged. A reply closes its
// ask through ConfirmNativePairAdmission instead of this control path.
func (s *CryptoState) CloseNativePairRequest(ctx context.Context, pairID, requestID, sender, terminal string) error {
	if ctx == nil || (terminal != "CANCELLED" && terminal != "EXPIRED") {
		return ErrNativePairBudget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		var original, done string
		if err := conn.QueryRowContext(ctx, `SELECT sender,terminal FROM node_native_pair_messages WHERE pair_id=? AND request_id=? AND kind='ASK'`, pairID, requestID).Scan(&original, &done); err != nil || original != sender {
			return ErrNativePairConflict
		}
		if done != "" {
			if done == terminal {
				return nil
			}
			return ErrNativePairConflict
		}
		_, err := conn.ExecContext(ctx, `UPDATE node_native_pair_messages SET terminal=? WHERE pair_id=? AND request_id=? AND kind='ASK' AND terminal=''`, terminal, pairID, requestID)
		return err
	})
}

// ReserveNativePairSubmission must precede provider/queue admission. Repeated
// reservations return existing=true and require the retained writer ledger;
// they never authorize another native invocation, including after expiry.
func (s *CryptoState) ReserveNativePairSubmission(ctx context.Context, e wire.NativePairPeerEvidence, m NativePairMessage, nativeID string, now time.Time) (existing bool, result error) {
	if ctx == nil || now.IsZero() || validateNativePairMessage(m) != nil {
		return false, ErrNativePairBudget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadNativePairPolicy(ctx, conn, e.Plan.PairID)
		if err != nil {
			return ErrNativePairPolicy
		}
		var stored NativePairMessage
		var state string
		err = conn.QueryRowContext(ctx, `SELECT message_id,request_id,kind,sender,receiver,digest,plaintext_bytes,ciphertext_bytes,state FROM node_native_pair_messages WHERE pair_id=? AND message_id=?`, p.PairID, m.MessageID).Scan(&stored.MessageID, &stored.RequestID, &stored.Kind, &stored.SenderEndpointID, &stored.ReceiverEndpointID, &stored.Digest, &stored.PlaintextBytes, &stored.CiphertextBytes, &state)
		if err != nil || stored != m || state != "ADMITTED" {
			return ErrNativePairConflict
		}
		var digest string
		err = conn.QueryRowContext(ctx, `SELECT digest FROM node_native_pair_submissions WHERE pair_id=? AND message_id=? AND receiver=? AND native_session_id=?`, p.PairID, m.MessageID, m.ReceiverEndpointID, nativeID).Scan(&digest)
		if err == nil {
			if digest != m.Digest {
				return ErrNativePairConflict
			}
			existing = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := verifyNativePairEvidence(ctx, conn, *p, e, now); err != nil {
			return err
		}
		receiver := e.Plan.SlotA
		if receiver.EndpointID != m.ReceiverEndpointID {
			receiver = e.Plan.SlotB
		}
		if receiver.EndpointID != m.ReceiverEndpointID || receiver.NativeSessionID != nativeID {
			return ErrNativePairPolicy
		}
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM node_native_pair_messages WHERE pair_id=? AND message_id=? AND receiver=? AND digest=? AND state='ADMITTED'`, p.PairID, m.MessageID, m.ReceiverEndpointID, m.Digest).Scan(&count); err != nil || count != 1 {
			return ErrNativePairBudget
		}
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM node_native_pair_submissions WHERE pair_id=?`, p.PairID).Scan(&count); err != nil {
			return err
		}
		if count >= 8 {
			return ErrNativePairBudget
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_native_pair_submissions VALUES(?,?,?,?,?)`, p.PairID, m.MessageID, m.ReceiverEndpointID, nativeID, m.Digest)
		return err
	})
	return existing, err
}
