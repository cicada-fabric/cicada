package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

var ErrNetworkDirectKeyUnavailable = errors.New("Network direct Endpoint key is unavailable")

// NetworkDirectNativeBinding is a Hub-side registration of one existing native
// Thread and its Node. The Node Agent remains the sole native writer, shared
// with all Group routes to that same Thread. This binding is never an access
// session and renewing Network directory access does not rotate its epoch.
type NetworkDirectNativeBinding struct {
	ID              string `json:"binding_id"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
	NodeID          string `json:"node_id"`
	NativeSessionID string `json:"native_session_id"`
	Epoch           uint64 `json:"epoch"`
	Status          string `json:"status"`
	// Passive observation of the existing Group writer generation. This is not
	// a second native lease and is not exposed to the Network access client.
	LastGroupLeaseOwner string `json:"-"`
}

type NetworkDirectKeyCandidate struct {
	NetworkID    string              `json:"network_id"`
	EndpointID   string              `json:"endpoint_id"`
	PrincipalID  string              `json:"principal_id"`
	OwnerID      string              `json:"owner_id"`
	NodeID       string              `json:"node_id"`
	BindingID    string              `json:"binding_id"`
	BindingEpoch uint64              `json:"binding_epoch"`
	Public       e2ee.PublicIdentity `json:"public_identity"`
	Fingerprint  string              `json:"fingerprint"`
	Attestation  []byte              `json:"attestation"`
	Version      int64               `json:"version"`
}

// The digest is computed only from current Store authority and the exact
// self-attested candidate. It never trusts a caller-supplied fingerprint.
type NetworkDirectKeyManifest struct {
	Version     int    `json:"version"`
	HubID       string `json:"hub_id"`
	NetworkID   string `json:"network_id"`
	EndpointID  string `json:"endpoint_id"`
	PrincipalID string `json:"principal_id"`
	OwnerID     string `json:"owner_id"`
	NodeID      string `json:"node_id"`
	// NativeSessionID is returned only by the Owner preview method. Peer key
	// evidence clears it; the digest is signed instead of disclosing the locator.
	NativeSessionID            string                    `json:"native_session_id,omitempty"`
	NativeSessionDigest        string                    `json:"native_session_digest"`
	BindingID                  string                    `json:"binding_id"`
	BindingEpoch               uint64                    `json:"binding_epoch"`
	MembershipRevision         int64                     `json:"membership_revision"`
	EndpointEnrollmentRevision int64                     `json:"endpoint_enrollment_revision"`
	Candidate                  NetworkDirectKeyCandidate `json:"candidate"`
	Digest                     string                    `json:"digest"`
}

// CanonicalDigest is shared by Hub persistence and the Node command's peer
// evidence verification. The Owner-only raw native locator is absent from
// signed public claims through omitempty; the digest field is encoded as an
// empty string so every signer hashes the same production JSON shape.
func (manifest NetworkDirectKeyManifest) CanonicalDigest() (string, error) {
	encoded, err := manifest.CanonicalClaims()
	if err != nil {
		return "", err
	}
	return e2ee.NetworkDirectManifestDigest(encoded), nil
}

func (manifest NetworkDirectKeyManifest) CanonicalClaims() ([]byte, error) {
	manifest.NativeSessionID = ""
	manifest.Digest = ""
	return json.Marshal(manifest)
}

type OwnerNetworkDirectKeyGrant struct {
	NetworkID      string `json:"network_id"`
	EndpointID     string `json:"endpoint_id"`
	OwnerID        string `json:"owner_id"`
	OwnerKeyID     string `json:"owner_key_id"`
	ManifestDigest string `json:"manifest_digest"`
	ProofDigest    string `json:"proof_digest"`
	Nonce          string `json:"nonce"`
	State          string `json:"state"`
	Revision       int64  `json:"revision"`
	AcceptedAt     string `json:"accepted_at"`
}

func (s *Store) initializeNetworkDirectSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS network_direct_native_bindings_v2 (
  id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL, node_id TEXT NOT NULL, native_session_id TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch>0), status TEXT NOT NULL CHECK(status IN ('active','revoked')),
  last_group_lease_owner TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS network_direct_native_bindings_v2_node_idx
  ON network_direct_native_bindings_v2(node_id,status,endpoint_id);
CREATE TRIGGER IF NOT EXISTS network_direct_group_writer_insert_v2
AFTER INSERT ON session_bindings WHEN NEW.lease_owner!=''
BEGIN
  UPDATE network_direct_native_bindings_v2
  SET epoch=epoch+CASE WHEN last_group_lease_owner!='' AND last_group_lease_owner!=NEW.lease_owner THEN 1 ELSE 0 END,
      last_group_lease_owner=NEW.lease_owner,updated_at=NEW.updated_at
  WHERE endpoint_id=NEW.endpoint_id AND principal_id=NEW.principal_id
    AND node_id=NEW.node_id AND native_session_id=NEW.native_session_id AND status='active';
END;
CREATE TRIGGER IF NOT EXISTS network_direct_group_writer_update_v2
AFTER UPDATE OF lease_owner ON session_bindings
WHEN NEW.lease_owner!='' AND NEW.lease_owner!=OLD.lease_owner
BEGIN
  UPDATE network_direct_native_bindings_v2
  SET epoch=epoch+CASE WHEN last_group_lease_owner!='' AND last_group_lease_owner!=NEW.lease_owner THEN 1 ELSE 0 END,
      last_group_lease_owner=NEW.lease_owner,updated_at=NEW.updated_at
  WHERE endpoint_id=NEW.endpoint_id AND principal_id=NEW.principal_id
    AND node_id=NEW.node_id AND native_session_id=NEW.native_session_id AND status='active';
END;
CREATE TABLE IF NOT EXISTS network_direct_key_candidates_v2 (
  network_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, principal_id TEXT NOT NULL,
  owner_id TEXT NOT NULL, node_id TEXT NOT NULL, binding_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0), public_identity_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL, attestation BLOB NOT NULL, version INTEGER NOT NULL CHECK(version>0),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(network_id,endpoint_id),
  FOREIGN KEY(network_id) REFERENCES networks_v2(id),
  FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE TABLE IF NOT EXISTS network_direct_key_grants_v2 (
  network_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, owner_id TEXT NOT NULL,
  owner_key_id TEXT NOT NULL, manifest_digest TEXT NOT NULL, proof_digest TEXT NOT NULL,
  proof BLOB NOT NULL, nonce TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN ('active','revoked')),
  revision INTEGER NOT NULL CHECK(revision>0), accepted_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(network_id,endpoint_id),
  FOREIGN KEY(network_id,endpoint_id) REFERENCES network_direct_key_candidates_v2(network_id,endpoint_id)
);
CREATE TABLE IF NOT EXISTS network_direct_key_grant_nonces_v2 (
  nonce TEXT PRIMARY KEY, network_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
  proof_digest TEXT NOT NULL, accepted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS network_direct_message_routes_v2 (
  message_id TEXT PRIMARY KEY, network_id TEXT NOT NULL,
  sender_endpoint_id TEXT NOT NULL, sender_principal_id TEXT NOT NULL,
  receiver_endpoint_id TEXT NOT NULL, receiver_principal_id TEXT NOT NULL,
  sender_membership_revision INTEGER NOT NULL CHECK(sender_membership_revision>0),
  sender_enrollment_revision INTEGER NOT NULL CHECK(sender_enrollment_revision>0),
  receiver_membership_revision INTEGER NOT NULL CHECK(receiver_membership_revision>0),
  receiver_enrollment_revision INTEGER NOT NULL CHECK(receiver_enrollment_revision>0),
  sender_binding_id TEXT NOT NULL, sender_binding_epoch INTEGER NOT NULL CHECK(sender_binding_epoch>0),
  receiver_binding_id TEXT NOT NULL, receiver_binding_epoch INTEGER NOT NULL CHECK(receiver_binding_epoch>0),
  sender_key_grant_revision INTEGER NOT NULL CHECK(sender_key_grant_revision>0),
  receiver_key_grant_revision INTEGER NOT NULL CHECK(receiver_key_grant_revision>0),
  sender_key_id TEXT NOT NULL, receiver_key_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id),
  FOREIGN KEY(network_id) REFERENCES networks_v2(id)
);
CREATE INDEX IF NOT EXISTS network_direct_message_routes_v2_receiver_idx
  ON network_direct_message_routes_v2(network_id,receiver_endpoint_id,message_id);
CREATE INDEX IF NOT EXISTS network_direct_message_routes_v2_endpoint_idx
  ON network_direct_message_routes_v2(receiver_endpoint_id,message_id);
CREATE INDEX IF NOT EXISTS network_direct_message_routes_v2_sender_idx
  ON network_direct_message_routes_v2(sender_endpoint_id,network_id,message_id);
`)
	if err != nil {
		return fmt.Errorf("initialize Network direct sealed schema: %w", err)
	}
	return nil
}

func readNetworkDirectNativeBindingTx(tx *sql.Tx, endpointID string) (*NetworkDirectNativeBinding, error) {
	var binding NetworkDirectNativeBinding
	err := tx.QueryRow(`SELECT id,endpoint_id,principal_id,node_id,native_session_id,epoch,status,last_group_lease_owner
FROM network_direct_native_bindings_v2 WHERE endpoint_id=?`, endpointID).Scan(
		&binding.ID, &binding.EndpointID, &binding.PrincipalID, &binding.NodeID,
		&binding.NativeSessionID, &binding.Epoch, &binding.Status, &binding.LastGroupLeaseOwner)
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

func networkGuardDirectAccessTx(tx *sql.Tx, scope NetworkAccessScope, at time.Time) error {
	if err := networkGuardAccessTx(tx, scope, "direct.send", at); err == nil {
		return nil
	}
	return networkGuardAccessTx(tx, scope, "direct.receive", at)
}

// EnsureNetworkDirectNativeBinding registers a real native destination after
// rechecking the current access session, owner-bound Node and enrollment in
// this transaction. It does not grant a second writer to the Node process.
func (s *Store) EnsureNetworkDirectNativeBinding(scope NetworkAccessScope) (*NetworkDirectNativeBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkGuardDirectAccessTx(tx, scope, time.Now().UTC()); err != nil {
		return nil, err
	}
	var principalID, nodeID, nativeID string
	if err := tx.QueryRow(`SELECT e.principal_id,e.machine_id,e.native_session_id
FROM fabric_endpoints e WHERE e.id=? AND e.status!='left'`, scope.EndpointID).Scan(
		&principalID, &nodeID, &nativeID); err != nil || principalID != scope.PrincipalID || nodeID == "" || nativeID == "" {
		return nil, ErrNetworkPermission
	}
	binding, err := readNetworkDirectNativeBindingTx(tx, scope.EndpointID)
	if errors.Is(err, sql.ErrNoRows) {
		stamp := now()
		var groupLeaseOwner string
		if err := tx.QueryRow(`SELECT COALESCE((SELECT b.lease_owner FROM fabric_endpoints e
JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id
WHERE e.id=? AND b.status IN ('active','leased','online','ready','acquired')), '')`,
			scope.EndpointID).Scan(&groupLeaseOwner); err != nil {
			return nil, err
		}
		binding = &NetworkDirectNativeBinding{ID: NewID("native"), EndpointID: scope.EndpointID,
			PrincipalID: principalID, NodeID: nodeID, NativeSessionID: nativeID, Epoch: 1,
			Status: "active", LastGroupLeaseOwner: groupLeaseOwner}
		if _, err := tx.Exec(`INSERT INTO network_direct_native_bindings_v2
(id,endpoint_id,principal_id,node_id,native_session_id,epoch,status,last_group_lease_owner,created_at,updated_at)
VALUES(?,?,?,?,?,1,'active',?,?,?)`, binding.ID, binding.EndpointID, binding.PrincipalID,
			binding.NodeID, binding.NativeSessionID, groupLeaseOwner, stamp, stamp); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if binding.PrincipalID != principalID || binding.NodeID != nodeID ||
		binding.NativeSessionID != nativeID || binding.Status != "active" {
		return nil, ErrNetworkPermission
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return binding, nil
}

func readNetworkDirectKeyCandidateTx(tx *sql.Tx, networkID, endpointID string) (*NetworkDirectKeyCandidate, error) {
	var candidate NetworkDirectKeyCandidate
	var publicJSON string
	err := tx.QueryRow(`SELECT network_id,endpoint_id,principal_id,owner_id,node_id,
binding_id,binding_epoch,public_identity_json,fingerprint,attestation,version
FROM network_direct_key_candidates_v2 WHERE network_id=? AND endpoint_id=?`, networkID, endpointID).Scan(
		&candidate.NetworkID, &candidate.EndpointID, &candidate.PrincipalID, &candidate.OwnerID,
		&candidate.NodeID, &candidate.BindingID, &candidate.BindingEpoch, &publicJSON,
		&candidate.Fingerprint, &candidate.Attestation, &candidate.Version)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(publicJSON), &candidate.Public); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	return &candidate, nil
}

// RegisterNetworkDirectKeyCandidate accepts only a self-attested public key.
// It remains unroutable until its owner signs and accepts the current manifest.
func (s *Store) RegisterNetworkDirectKeyCandidate(scope NetworkAccessScope, proof []byte) (*NetworkDirectKeyCandidate, error) {
	if len(proof) == 0 || len(proof) > 32*1024 {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkGuardDirectAccessTx(tx, scope, time.Now().UTC()); err != nil {
		return nil, err
	}
	binding, err := readNetworkDirectNativeBindingTx(tx, scope.EndpointID)
	if err != nil || binding.PrincipalID != scope.PrincipalID || binding.Status != "active" {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	var hubID, ownerID string
	if err := tx.QueryRow(`SELECT n.hub_id,e.owner FROM networks_v2 n
JOIN fabric_endpoints e ON e.id=? AND e.machine_id=? AND e.native_session_id=?
WHERE n.id=? AND n.state='ACTIVE'`, scope.EndpointID, binding.NodeID,
		binding.NativeSessionID, scope.NetworkID).Scan(&hubID, &ownerID); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	expected := e2ee.NetworkDirectKeyAttestation{HubID: hubID, NetworkID: scope.NetworkID,
		EndpointID: scope.EndpointID, PrincipalID: scope.PrincipalID, NodeID: binding.NodeID,
		BindingID: binding.ID, BindingEpoch: binding.Epoch}
	public, err := e2ee.VerifyNetworkDirectKeyAttestation(proof, expected)
	if err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return nil, err
	}
	current, err := readNetworkDirectKeyCandidateTx(tx, scope.NetworkID, scope.EndpointID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	stamp := now()
	var version int64 = 1
	if current == nil {
		_, err = tx.Exec(`INSERT INTO network_direct_key_candidates_v2
(network_id,endpoint_id,principal_id,owner_id,node_id,binding_id,binding_epoch,
public_identity_json,fingerprint,attestation,version,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)`, scope.NetworkID, scope.EndpointID, scope.PrincipalID,
			ownerID, binding.NodeID, binding.ID, binding.Epoch, string(publicJSON), fingerprint, proof,
			stamp, stamp)
	} else {
		if current.Public.ID != public.ID || current.Fingerprint != fingerprint ||
			current.OwnerID != ownerID || current.PrincipalID != scope.PrincipalID {
			return nil, ErrNetworkDirectKeyUnavailable
		}
		version = current.Version
		if current.BindingID != binding.ID || current.BindingEpoch != binding.Epoch {
			version++
			_, err = tx.Exec(`UPDATE network_direct_key_candidates_v2 SET binding_id=?,binding_epoch=?,
attestation=?,version=?,updated_at=? WHERE network_id=? AND endpoint_id=?`, binding.ID,
				binding.Epoch, proof, version, stamp, scope.NetworkID, scope.EndpointID)
		} else {
			proof = current.Attestation
		}
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NetworkDirectKeyCandidate{NetworkID: scope.NetworkID, EndpointID: scope.EndpointID,
		PrincipalID: scope.PrincipalID, OwnerID: ownerID, NodeID: binding.NodeID,
		BindingID: binding.ID, BindingEpoch: binding.Epoch, Public: public,
		Fingerprint: fingerprint, Attestation: append([]byte(nil), proof...), Version: version}, nil
}

func readNetworkDirectKeyManifestTx(tx *sql.Tx, ownerID, networkID, endpointID string,
	at time.Time) (*NetworkDirectKeyManifest, error) {
	var manifest NetworkDirectKeyManifest
	manifest.Version, manifest.NetworkID, manifest.EndpointID = 1, networkID, endpointID
	var networkState, endpointStatus, principalStatus, memberStatus, enrollmentStatus, memberExpiry string
	var grantsJSON string
	err := tx.QueryRow(`SELECT n.hub_id,n.state,e.principal_id,e.owner,e.machine_id,e.native_session_id,e.status,
p.status,m.status,m.expires_at,m.grants_json,m.revision,en.status,en.revision
FROM networks_v2 n
JOIN fabric_endpoints e ON e.id=?
JOIN principals p ON p.id=e.principal_id
JOIN network_memberships_v2 m ON m.network_id=n.id AND m.principal_id=e.principal_id
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=e.id
WHERE n.id=?`, endpointID, networkID).Scan(&manifest.HubID, &networkState,
		&manifest.PrincipalID, &manifest.OwnerID, &manifest.NodeID, &manifest.NativeSessionID,
		&endpointStatus, &principalStatus, &memberStatus, &memberExpiry, &grantsJSON,
		&manifest.MembershipRevision, &enrollmentStatus, &manifest.EndpointEnrollmentRevision)
	if err != nil || manifest.OwnerID != ownerID || networkState != NetworkStateActive ||
		endpointStatus == "left" || principalStatus != PrincipalStatusActive ||
		memberStatus != "active" || enrollmentStatus != "active" {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	if memberExpiry != "" {
		deadline, err := time.Parse(time.RFC3339Nano, memberExpiry)
		if err != nil || !deadline.After(at) {
			return nil, ErrNetworkDirectKeyUnavailable
		}
	}
	if err := requireCurrentOwnerBoundGroupNodeTx(tx, manifest.NodeID, ownerID, manifest.HubID); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	var grants []string
	if err := json.Unmarshal([]byte(grantsJSON), &grants); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	if !containsNetworkDirectGrant(grants) {
		return nil, ErrNetworkPermission
	}
	binding, err := readNetworkDirectNativeBindingTx(tx, endpointID)
	if err != nil || binding.Status != "active" || binding.PrincipalID != manifest.PrincipalID ||
		binding.NodeID != manifest.NodeID || binding.NativeSessionID != manifest.NativeSessionID {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	manifest.BindingID, manifest.BindingEpoch = binding.ID, binding.Epoch
	manifest.NativeSessionDigest = e2ee.NetworkDirectNativeSessionDigest(manifest.NativeSessionID)
	candidate, err := readNetworkDirectKeyCandidateTx(tx, networkID, endpointID)
	if err != nil || candidate.OwnerID != ownerID || candidate.PrincipalID != manifest.PrincipalID ||
		candidate.NodeID != manifest.NodeID || candidate.BindingID != binding.ID ||
		candidate.BindingEpoch != binding.Epoch {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	manifest.Candidate = *candidate
	manifest.Digest, err = manifest.CanonicalDigest()
	if err != nil {
		return nil, err
	}
	return &manifest, nil
}

func containsNetworkDirectGrant(grants []string) bool {
	for _, grant := range grants {
		if grant == "direct.send" || grant == "direct.receive" {
			return true
		}
	}
	return false
}

func (s *Store) PreviewNetworkDirectKeyGrant(ownerID, networkID, endpointID, ownerKeyID string) (*NetworkDirectKeyManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var state string
	if err := tx.QueryRow(`SELECT state FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, ownerID, ownerKeyID).Scan(&state); err != nil || state != OwnerApprovalKeyActive {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	manifest, err := readNetworkDirectKeyManifestTx(tx, ownerID, networkID, endpointID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return manifest, nil
}

func readOwnerNetworkDirectKeyGrantTx(tx *sql.Tx, networkID, endpointID string) (*OwnerNetworkDirectKeyGrant, []byte, error) {
	var grant OwnerNetworkDirectKeyGrant
	var proof []byte
	err := tx.QueryRow(`SELECT network_id,endpoint_id,owner_id,owner_key_id,manifest_digest,
proof_digest,proof,nonce,state,revision,accepted_at FROM network_direct_key_grants_v2
WHERE network_id=? AND endpoint_id=?`, networkID, endpointID).Scan(&grant.NetworkID,
		&grant.EndpointID, &grant.OwnerID, &grant.OwnerKeyID, &grant.ManifestDigest,
		&grant.ProofDigest, &proof, &grant.Nonce, &grant.State, &grant.Revision,
		&grant.AcceptedAt)
	if err != nil {
		return nil, nil, err
	}
	return &grant, proof, nil
}

func (s *Store) AcceptNetworkDirectKeyGrant(authenticatedOwnerID, networkID, endpointID string,
	proof []byte) (*OwnerNetworkDirectKeyGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	grant, err := acceptNetworkDirectKeyGrantTx(tx, authenticatedOwnerID, networkID,
		endpointID, proof, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// acceptNetworkDirectKeyGrantTx is shared with the encrypted Client request
// wrapper, which verifies the current device/request before calling it in the
// same write transaction. The caller owns commit and Store.mu.
func acceptNetworkDirectKeyGrantTx(tx *sql.Tx, authenticatedOwnerID, networkID,
	endpointID string, proof []byte, at time.Time) (*OwnerNetworkDirectKeyGrant, error) {
	if len(proof) == 0 || len(proof) > 32*1024 || at.IsZero() {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	manifest, err := readNetworkDirectKeyManifestTx(tx, authenticatedOwnerID, networkID, endpointID, at)
	if err != nil {
		return nil, err
	}
	var proposed e2ee.OwnerNetworkDirectKeyGrant
	if err := json.Unmarshal(proof, &proposed); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	var state, publicJSON string
	if err := tx.QueryRow(`SELECT state,public_identity_json FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, authenticatedOwnerID, proposed.OwnerKeyID).Scan(
		&state, &publicJSON); err != nil || state != OwnerApprovalKeyActive {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	var public e2ee.PublicIdentity
	if err := json.Unmarshal([]byte(publicJSON), &public); err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	expected := e2ee.OwnerNetworkDirectKeyGrant{HubID: manifest.HubID, NetworkID: networkID,
		EndpointID: endpointID, OwnerID: authenticatedOwnerID, ManifestDigest: manifest.Digest}
	verified, err := e2ee.VerifyOwnerNetworkDirectKeyGrant(proof, public, expected, at)
	if err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	proofHash := sha256.Sum256(proof)
	proofDigest := hex.EncodeToString(proofHash[:])
	var oldNetwork, oldEndpoint, oldDigest string
	err = tx.QueryRow(`SELECT network_id,endpoint_id,proof_digest FROM network_direct_key_grant_nonces_v2
WHERE nonce=?`, verified.Nonce).Scan(&oldNetwork, &oldEndpoint, &oldDigest)
	if err == nil && (oldNetwork != networkID || oldEndpoint != endpointID || oldDigest != proofDigest) {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	current, _, err := readOwnerNetworkDirectKeyGrantTx(tx, networkID, endpointID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if oldNetwork != "" {
		if current == nil || current.ProofDigest != proofDigest || current.State != "active" {
			return nil, ErrNetworkDirectKeyUnavailable
		}
		return current, nil
	}
	stamp := now()
	if _, err := tx.Exec(`INSERT INTO network_direct_key_grant_nonces_v2
(nonce,network_id,endpoint_id,proof_digest,accepted_at) VALUES(?,?,?,?,?)`, verified.Nonce,
		networkID, endpointID, proofDigest, stamp); err != nil {
		return nil, err
	}
	var revision int64 = 1
	if current == nil {
		_, err = tx.Exec(`INSERT INTO network_direct_key_grants_v2
(network_id,endpoint_id,owner_id,owner_key_id,manifest_digest,proof_digest,proof,nonce,
state,revision,accepted_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'active',1,?,?)`,
			networkID, endpointID, authenticatedOwnerID, verified.OwnerKeyID, manifest.Digest,
			proofDigest, proof, verified.Nonce, stamp, stamp)
	} else {
		revision = current.Revision + 1
		_, err = tx.Exec(`UPDATE network_direct_key_grants_v2 SET owner_key_id=?,manifest_digest=?,
proof_digest=?,proof=?,nonce=?,state='active',revision=?,accepted_at=?,updated_at=?
WHERE network_id=? AND endpoint_id=?`, verified.OwnerKeyID, manifest.Digest, proofDigest,
			proof, verified.Nonce, revision, stamp, stamp, networkID, endpointID)
	}
	if err != nil {
		return nil, err
	}
	return &OwnerNetworkDirectKeyGrant{NetworkID: networkID, EndpointID: endpointID,
		OwnerID: authenticatedOwnerID, OwnerKeyID: verified.OwnerKeyID,
		ManifestDigest: manifest.Digest, ProofDigest: proofDigest, Nonce: verified.Nonce,
		State: "active", Revision: revision, AcceptedAt: stamp}, nil
}

func (s *Store) GetNetworkDirectKeyGrant(ownerID, networkID, endpointID string) (*OwnerNetworkDirectKeyGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	grant, _, err := readOwnerNetworkDirectKeyGrantTx(tx, networkID, endpointID)
	if err != nil || grant.OwnerID != ownerID {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	manifest, err := readNetworkDirectKeyManifestTx(tx, ownerID, networkID, endpointID, time.Now().UTC())
	if err != nil || manifest.Digest != grant.ManifestDigest {
		grant.State = "stale"
	} else {
		var keyState string
		if err := tx.QueryRow(`SELECT state FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`,
			ownerID, grant.OwnerKeyID).Scan(&keyState); err != nil || keyState != OwnerApprovalKeyActive {
			grant.State = "stale"
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}
