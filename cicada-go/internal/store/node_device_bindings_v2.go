package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	NodeDeviceBindingPending   = "PENDING"
	NodeDeviceBindingConfirmed = "CONFIRMED"
	NodeDeviceBindingExpired   = "EXPIRED"
	NodeDeviceBindingRevoked   = "REVOKED"

	nodeDeviceBindingMaxPending          = 256
	nodeDeviceBindingCreateWindow        = 10 * time.Minute
	nodeDeviceBindingMaxCreatesPerWindow = 256
	nodeDeviceBindingReissueCooldown     = 5 * time.Second
)

var (
	ErrNodeDeviceBindingNotFound     = errors.New("Node device binding was not found")
	ErrNodeDeviceBindingConflict     = errors.New("Node device binding conflicts with an existing request or binding")
	ErrNodeDeviceBindingUnauthorized = errors.New("active owner-authorized Client device is required")
	ErrNodeDeviceBindingExpired      = errors.New("Node device code is expired or already consumed")
	ErrNodeDeviceBindingVersion      = errors.New("Node device binding version conflict")
	ErrNodeDeviceBindingRateLimited  = errors.New("Node device-code request rate limit exceeded")
)

// NodeDeviceBindingRequest contains only the one-time code digest and the
// candidate Node credential digest. Plaintext codes and bearer credentials
// never enter Store.
type NodeDeviceBindingRequest struct {
	ID                   string `json:"id"`
	HubID                string `json:"hub_id"`
	NodeID               string `json:"node_id"`
	NodeName             string `json:"node_name"`
	NodeCredentialDigest string `json:"-"`
	CodeDigest           string `json:"-"`
	State                string `json:"state"`
	Version              int64  `json:"version"`
	ExpiresAt            string `json:"expires_at"`
	CreatedAt            string `json:"created_at"`
	ConfirmedAt          string `json:"confirmed_at,omitempty"`
}

// NodeDeviceBinding is the owner-visible, revocable association between one
// Node identity and the digest-backed credential currently authorized for it.
type NodeDeviceBinding struct {
	ID                    string `json:"id"`
	OwnerID               string `json:"owner_id"`
	HubID                 string `json:"hub_id"`
	NodeID                string `json:"node_id"`
	NodeName              string `json:"node_name"`
	ClientDeviceID        string `json:"client_device_id"`
	OwnerKeyID            string `json:"owner_key_id"`
	NodeCredentialVersion int64  `json:"node_credential_version"`
	State                 string `json:"state"`
	Authorized            bool   `json:"authorized"`
	Version               int64  `json:"version"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
	RevokedAt             string `json:"revoked_at,omitempty"`
	credentialDigest      string
}

func (s *Store) initializeNodeDeviceBindingV2Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS node_device_binding_requests_v2 (
  id TEXT PRIMARY KEY,
  hub_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  node_credential_digest TEXT NOT NULL CHECK(length(node_credential_digest) <= 64),
  code_digest TEXT NOT NULL UNIQUE CHECK(length(code_digest) = 64),
  state TEXT NOT NULL CHECK(state IN ('PENDING', 'CONFIRMED', 'EXPIRED')),
  version INTEGER NOT NULL CHECK(version > 0),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  confirmed_at TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS node_device_binding_requests_v2_pending_node_idx
  ON node_device_binding_requests_v2(node_id) WHERE state = 'PENDING';
CREATE UNIQUE INDEX IF NOT EXISTS node_device_binding_requests_v2_pending_credential_idx
  ON node_device_binding_requests_v2(node_credential_digest)
  WHERE state = 'PENDING' AND node_credential_digest <> '';
CREATE INDEX IF NOT EXISTS node_device_binding_requests_v2_expiry_idx
  ON node_device_binding_requests_v2(state, expires_at);
CREATE TABLE IF NOT EXISTS node_owner_bindings_v2 (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  hub_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  client_device_id TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  node_credential_digest TEXT NOT NULL CHECK(length(node_credential_digest) <= 64),
  node_credential_version INTEGER NOT NULL CHECK(node_credential_version > 0),
  state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
  version INTEGER NOT NULL CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(node_id) REFERENCES fabric_node_credentials(node_id),
  FOREIGN KEY(owner_id, client_device_id) REFERENCES client_devices_v2(owner_id, device_id),
  FOREIGN KEY(owner_id, owner_key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS node_owner_bindings_v2_active_node_idx
  ON node_owner_bindings_v2(node_id) WHERE state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS node_owner_bindings_v2_owner_state_idx
  ON node_owner_bindings_v2(owner_id, state, node_id);
CREATE TRIGGER IF NOT EXISTS node_owner_binding_credential_fence_v2
AFTER UPDATE ON fabric_node_credentials
WHEN EXISTS (
  SELECT 1 FROM node_owner_bindings_v2 binding
  WHERE binding.node_id=NEW.node_id AND binding.state='ACTIVE'
    AND (NEW.status!='active' OR NEW.version!=binding.node_credential_version
      OR NEW.credential_hash!=binding.node_credential_digest)
)
BEGIN
  UPDATE node_owner_bindings_v2 SET state='REVOKED', version=version+1,
    updated_at=NEW.updated_at, revoked_at=NEW.updated_at
  WHERE node_id=NEW.node_id AND state='ACTIVE';
  UPDATE fabric_node_credentials SET status='revoked', version=version+1,
    updated_at=NEW.updated_at
  WHERE node_id=NEW.node_id AND version=NEW.version;
END;
`)
	if err != nil {
		return fmt.Errorf("initialize Node device-code binding schema: %w", err)
	}
	return nil
}

// CreatePendingNodeDeviceBinding stores no plaintext verification code or
// Node bearer. The Node generates and keeps its own bearer, sending only its
// digest. Confirmation is the only transition that activates that digest.
func (s *Store) CreatePendingNodeDeviceBinding(nodeID, nodeName, credentialDigest, codeDigest string, expiresAt time.Time) (*NodeDeviceBindingRequest, error) {
	nodeID = strings.TrimSpace(nodeID)
	nodeName = strings.TrimSpace(nodeName)
	credentialDigest = strings.TrimSpace(credentialDigest)
	codeDigest = strings.ToLower(strings.TrimSpace(codeDigest))
	if !validNodeBindingID(nodeID) || len(nodeName) == 0 || len(nodeName) > 128 ||
		!validNodeCredentialDigest(credentialDigest) || !validSHA256Digest(codeDigest) {
		return nil, errors.New("valid node_id, node name, Node credential digest, and code digest are required")
	}
	nowTime := time.Now().UTC()
	if expiresAt.Before(nowTime.Add(time.Minute)) || expiresAt.After(nowTime.Add(15*time.Minute)) {
		return nil, errors.New("Node device code expiry must be between one and fifteen minutes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id = 1`).Scan(&hubID); err != nil {
		return nil, fmt.Errorf("read stable Hub identity: %w", err)
	}
	preciseNow := time.Now().UTC()
	stamp := preciseNow.Format(time.RFC3339Nano)
	_, err = tx.Exec(`UPDATE node_device_binding_requests_v2 SET state='EXPIRED', version=version+1,
node_credential_digest=''
WHERE state='PENDING' AND expires_at <= ?`, stamp)
	if err != nil {
		return nil, err
	}
	// Device-code ingress is unauthenticated. Limit reissue churn per Node and
	// cap both active requests and total recent writes; the HTTP server should
	// also enforce source-level request limits.
	cooldownStart := preciseNow.Add(-nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano)
	var recentNodeRequests int
	if err := tx.QueryRow(`SELECT count(*) FROM node_device_binding_requests_v2
WHERE node_id=? AND created_at>=?`, nodeID, cooldownStart).Scan(&recentNodeRequests); err != nil {
		return nil, err
	}
	if recentNodeRequests > 0 {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	windowStart := preciseNow.Add(-nodeDeviceBindingCreateWindow).Format(time.RFC3339Nano)
	var recentCreates int
	if err := tx.QueryRow(`SELECT count(*) FROM node_device_binding_requests_v2 WHERE created_at>=?`, windowStart).Scan(&recentCreates); err != nil {
		return nil, err
	}
	if recentCreates >= nodeDeviceBindingMaxCreatesPerWindow {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	// The Node has the only copy of its bearer. Repeating the same pending
	// request after a lost response rotates the short code and invalidates the
	// previous one, allowing recovery without storing the plaintext code.
	_, err = tx.Exec(`UPDATE node_device_binding_requests_v2 SET state='EXPIRED', version=version+1,
node_credential_digest='' WHERE state='PENDING' AND node_id=? AND node_credential_digest=?`,
		nodeID, credentialDigest)
	if err != nil {
		return nil, err
	}
	var active int
	if err := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=? AND state='ACTIVE'`, nodeID).Scan(&active); err != nil {
		return nil, err
	}
	if active != 0 {
		return nil, ErrNodeDeviceBindingConflict
	}
	var pending int
	if err := tx.QueryRow(`SELECT count(*) FROM node_device_binding_requests_v2
WHERE state='PENDING' AND expires_at>?`, stamp).Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= nodeDeviceBindingMaxPending {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	request := &NodeDeviceBindingRequest{
		ID: NewID("nbreq"), HubID: hubID, NodeID: nodeID, NodeName: nodeName,
		NodeCredentialDigest: credentialDigest, CodeDigest: codeDigest,
		State: NodeDeviceBindingPending, Version: 1,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), CreatedAt: stamp,
	}
	_, err = tx.Exec(`INSERT INTO node_device_binding_requests_v2
(id, hub_id, node_id, node_name, node_credential_digest, code_digest, state, version, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 1, ?, ?)`, request.ID, request.HubID, request.NodeID,
		request.NodeName, request.NodeCredentialDigest, request.CodeDigest, request.ExpiresAt, request.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, ErrNodeDeviceBindingConflict
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// PreviewPendingNodeDeviceBinding returns only the candidate Node metadata
// needed for an owner to verify what the short code would authorize. It does
// not consume the code or activate the candidate credential.
func (s *Store) PreviewPendingNodeDeviceBinding(ownerID, clientDeviceID, codeDigest string) (*NodeDeviceBindingRequest, error) {
	ownerID = strings.TrimSpace(ownerID)
	clientDeviceID = strings.TrimSpace(clientDeviceID)
	codeDigest = strings.ToLower(strings.TrimSpace(codeDigest))
	if err := validateOwnerApprovalID(ownerID); err != nil || clientDeviceID == "" || !validSHA256Digest(codeDigest) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var hubID string
	err := s.db.QueryRow(`SELECT config.hub_id FROM client_device_hub_config_v2 config
JOIN client_devices_v2 device ON device.owner_id=? AND device.device_id=? AND device.state='ACTIVE'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=device.owner_id
  AND owner_key.key_id=device.owner_key_id AND owner_key.state='ACTIVE'
WHERE config.id=1`, ownerID, clientDeviceID).Scan(&hubID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	if err != nil {
		return nil, err
	}
	var request NodeDeviceBindingRequest
	err = s.db.QueryRow(`SELECT id, hub_id, node_id, node_name, state, version, expires_at, created_at
FROM node_device_binding_requests_v2 WHERE code_digest=?`, codeDigest).Scan(
		&request.ID, &request.HubID, &request.NodeID, &request.NodeName, &request.State,
		&request.Version, &request.ExpiresAt, &request.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if request.State != NodeDeviceBindingPending || request.HubID != hubID ||
		request.ExpiresAt <= time.Now().UTC().Format(time.RFC3339Nano) {
		return nil, ErrNodeDeviceBindingExpired
	}
	return &request, nil
}

// ConfirmPendingNodeDeviceBinding requires an active Client device whose
// owner grant key is still active. The caller must pass owner/device IDs from
// the authenticated v2 Client RPC binding, never from request JSON.
func (s *Store) ConfirmPendingNodeDeviceBinding(ownerID, clientDeviceID, codeDigest string) (*NodeDeviceBinding, error) {
	ownerID = strings.TrimSpace(ownerID)
	clientDeviceID = strings.TrimSpace(clientDeviceID)
	codeDigest = strings.ToLower(strings.TrimSpace(codeDigest))
	if err := validateOwnerApprovalID(ownerID); err != nil || clientDeviceID == "" || !validSHA256Digest(codeDigest) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hubID, ownerKeyID string
	err = tx.QueryRow(`SELECT config.hub_id, device.owner_key_id
FROM client_device_hub_config_v2 config
JOIN client_devices_v2 device ON device.owner_id=? AND device.device_id=? AND device.state='ACTIVE'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=device.owner_id
  AND owner_key.key_id=device.owner_key_id AND owner_key.state='ACTIVE'
WHERE config.id=1`, ownerID, clientDeviceID).Scan(&hubID, &ownerKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	if err != nil {
		return nil, err
	}
	var request NodeDeviceBindingRequest
	err = tx.QueryRow(`SELECT id, hub_id, node_id, node_name, node_credential_digest,
code_digest, state, version, expires_at, created_at, confirmed_at
FROM node_device_binding_requests_v2 WHERE code_digest=?`, codeDigest).Scan(
		&request.ID, &request.HubID, &request.NodeID, &request.NodeName,
		&request.NodeCredentialDigest, &request.CodeDigest, &request.State, &request.Version,
		&request.ExpiresAt, &request.CreatedAt, &request.ConfirmedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingNotFound
	}
	if err != nil {
		return nil, err
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if request.State != NodeDeviceBindingPending || request.HubID != hubID || request.ExpiresAt <= stamp {
		if request.State == NodeDeviceBindingPending && request.ExpiresAt <= stamp {
			_, _ = tx.Exec(`UPDATE node_device_binding_requests_v2 SET state='EXPIRED', version=version+1,
node_credential_digest='' WHERE id=? AND state='PENDING' AND version=?`, request.ID, request.Version)
			if err := tx.Commit(); err != nil {
				return nil, err
			}
		}
		return nil, ErrNodeDeviceBindingExpired
	}
	var active int
	if err := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=? AND state='ACTIVE'`, request.NodeID).Scan(&active); err != nil {
		return nil, err
	}
	if active != 0 {
		return nil, ErrNodeDeviceBindingConflict
	}
	result, err := tx.Exec(`UPDATE node_device_binding_requests_v2 SET state='CONFIRMED', version=version+1,
confirmed_at=?, node_credential_digest=''
WHERE id=? AND state='PENDING' AND version=? AND expires_at>?`, stamp, request.ID, request.Version, stamp)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrNodeDeviceBindingExpired
	}
	credentialVersion := int64(1)
	var currentVersion int64
	err = tx.QueryRow(`SELECT version FROM fabric_node_credentials WHERE node_id=?`, request.NodeID).Scan(&currentVersion)
	if err == nil {
		credentialVersion = currentVersion + 1
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO fabric_node_credentials
(node_id, credential_hash, version, status, created_at, updated_at)
VALUES (?, ?, ?, 'active', ?, ?)
ON CONFLICT(node_id) DO UPDATE SET credential_hash=excluded.credential_hash,
version=excluded.version, status='active', updated_at=excluded.updated_at`,
		request.NodeID, request.NodeCredentialDigest, credentialVersion, stamp, stamp)
	if err != nil {
		return nil, err
	}
	binding := &NodeDeviceBinding{
		ID: NewID("nbind"), OwnerID: ownerID, HubID: hubID, NodeID: request.NodeID,
		NodeName: request.NodeName, ClientDeviceID: clientDeviceID, OwnerKeyID: ownerKeyID,
		NodeCredentialVersion: credentialVersion, State: "ACTIVE", Authorized: true, Version: 1,
		CreatedAt: stamp, UpdatedAt: stamp, credentialDigest: request.NodeCredentialDigest,
	}
	_, err = tx.Exec(`INSERT INTO node_owner_bindings_v2
(id, owner_id, hub_id, node_id, node_name, client_device_id, owner_key_id,
 node_credential_digest, node_credential_version, state, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?)`,
		binding.ID, binding.OwnerID, binding.HubID, binding.NodeID, binding.NodeName,
		binding.ClientDeviceID, binding.OwnerKeyID, binding.credentialDigest,
		binding.NodeCredentialVersion, stamp, stamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, ErrNodeDeviceBindingConflict
		}
		return nil, err
	}
	// The explicit Client confirmation establishes the Node's machine owner.
	// Never adopt an old machine row whose ownership is unknown, and never
	// transfer a Node ID across owners implicitly.
	var machineOwnerID string
	err = tx.QueryRow(`SELECT owner_id FROM machines WHERE id=?`, request.NodeID).Scan(&machineOwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		capabilities, _ := json.Marshal(map[string]any{})
		_, err = tx.Exec(`INSERT INTO machines
(id, name, status, capabilities_json, last_seen, created_at, owner_id)
VALUES (?, ?, 'offline', ?, '', ?, ?)`, request.NodeID, request.NodeName,
			string(capabilities), stamp, ownerID)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if machineOwnerID != ownerID {
		return nil, ErrNodeMachineOwnershipConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return binding, nil
}

func (s *Store) ListNodeDeviceBindings(ownerID string) ([]NodeDeviceBinding, error) {
	ownerID = strings.TrimSpace(ownerID)
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT binding.id, binding.owner_id, binding.hub_id,
binding.node_id, binding.node_name, binding.client_device_id, binding.owner_key_id,
binding.node_credential_version, binding.state,
CASE WHEN binding.state='ACTIVE' AND EXISTS (
  SELECT 1 FROM fabric_node_credentials credential
  JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
  JOIN principals principal ON principal.id=binding.owner_id
    AND principal.kind='human' AND principal.status='active'
  JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
    AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
  WHERE credential.node_id=binding.node_id AND credential.status='active'
    AND credential.version=binding.node_credential_version
    AND credential.credential_hash=binding.node_credential_digest
) THEN 1 ELSE 0 END,
binding.version, binding.created_at, binding.updated_at, binding.revoked_at
FROM node_owner_bindings_v2 binding WHERE binding.owner_id=?
ORDER BY binding.created_at DESC, binding.id`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]NodeDeviceBinding, 0)
	for rows.Next() {
		var binding NodeDeviceBinding
		if err := rows.Scan(&binding.ID, &binding.OwnerID, &binding.HubID, &binding.NodeID,
			&binding.NodeName, &binding.ClientDeviceID, &binding.OwnerKeyID,
			&binding.NodeCredentialVersion, &binding.State, &binding.Authorized, &binding.Version,
			&binding.CreatedAt, &binding.UpdatedAt, &binding.RevokedAt); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

// GetOwnerBoundNodeCredentialByHash is the authorization check Relay should
// use for authenticated Node calls. GetNodeCredentialByHash remains available
// for legacy inspection, but an active bearer is accepted by the v2 Node path
// only when its exact digest and version match an active owner/Hub binding.
func (s *Store) GetOwnerBoundNodeCredentialByHash(credentialDigest string) (*NodeCredential, *NodeDeviceBinding, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	if !validNodeCredentialDigest(credentialDigest) {
		return nil, nil, ErrNodeCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var credential NodeCredential
	var binding NodeDeviceBinding
	err := s.db.QueryRow(`SELECT credential.node_id, credential.credential_hash,
credential.version, credential.status, credential.created_at, credential.updated_at,
binding.id, binding.owner_id, binding.hub_id, binding.node_id, binding.node_name,
binding.client_device_id, binding.owner_key_id, binding.node_credential_version,
binding.state, binding.version, binding.created_at, binding.updated_at, binding.revoked_at
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).Scan(
		&credential.NodeID, &credential.CredentialHash, &credential.Version,
		&credential.Status, &credential.CreatedAt, &credential.UpdatedAt,
		&binding.ID, &binding.OwnerID, &binding.HubID, &binding.NodeID, &binding.NodeName,
		&binding.ClientDeviceID, &binding.OwnerKeyID, &binding.NodeCredentialVersion,
		&binding.State, &binding.Version, &binding.CreatedAt, &binding.UpdatedAt, &binding.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNodeCredentialNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	binding.credentialDigest = credentialDigest
	return &credential, &binding, nil
}

// RecordBoundNodeHeartbeat updates the Manager's Node liveness projection only
// for a currently owner-bound Relay credential. The authorization check and
// machine timestamp update share a transaction, so revocation cannot race a
// separate status write into the Client snapshot.
func (s *Store) RecordBoundNodeHeartbeat(credentialDigest string) error {
	credentialDigest = strings.TrimSpace(credentialDigest)
	if !validNodeCredentialDigest(credentialDigest) {
		return ErrNodeCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var nodeID, nodeName, ownerID, machineOwnerID string
	err = tx.QueryRow(`SELECT binding.node_id, binding.node_name, binding.owner_id, machine.owner_id
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
JOIN machines machine ON machine.id=binding.node_id
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).
		Scan(&nodeID, &nodeName, &ownerID, &machineOwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeCredentialNotFound
	}
	if err != nil {
		return err
	}
	if machineOwnerID != ownerID {
		return ErrNodeMachineOwnershipConflict
	}
	stamp := now()
	_, err = tx.Exec(`UPDATE machines SET name=?, last_seen=?
WHERE id=? AND owner_id=?`, nodeName, stamp, nodeID, ownerID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeNodeDeviceBinding(ownerID, bindingID string, expectedVersion int64) (*NodeDeviceBinding, error) {
	ownerID = strings.TrimSpace(ownerID)
	bindingID = strings.TrimSpace(bindingID)
	if err := validateOwnerApprovalID(ownerID); err != nil || bindingID == "" {
		return nil, ErrNodeDeviceBindingNotFound
	}
	if expectedVersion < 1 {
		return nil, ErrNodeDeviceBindingVersion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var binding NodeDeviceBinding
	err = tx.QueryRow(`SELECT id, owner_id, hub_id, node_id, node_name, client_device_id,
owner_key_id, node_credential_digest, node_credential_version, state, version,
created_at, updated_at, revoked_at FROM node_owner_bindings_v2
WHERE owner_id=? AND id=?`, ownerID, bindingID).Scan(
		&binding.ID, &binding.OwnerID, &binding.HubID, &binding.NodeID, &binding.NodeName,
		&binding.ClientDeviceID, &binding.OwnerKeyID, &binding.credentialDigest,
		&binding.NodeCredentialVersion, &binding.State, &binding.Version,
		&binding.CreatedAt, &binding.UpdatedAt, &binding.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if binding.State != "ACTIVE" || binding.Version != expectedVersion {
		return nil, ErrNodeDeviceBindingVersion
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED', version=version+1,
updated_at=?, revoked_at=? WHERE id=? AND owner_id=? AND state='ACTIVE' AND version=?`,
		stamp, stamp, binding.ID, ownerID, expectedVersion)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrNodeDeviceBindingVersion
	}
	// Revoke whatever credential is current for this Node ID. This also fences
	// a token that was rotated through a legacy management path after binding.
	_, err = tx.Exec(`UPDATE fabric_node_credentials SET status='revoked', version=version+1,
updated_at=? WHERE node_id=? AND status='active'`, stamp, binding.NodeID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE machines SET status='offline' WHERE id=? AND owner_id=?`, binding.NodeID, ownerID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE approvals SET status='cancelled', resolved_at=?
WHERE source_node_id=? AND status='pending'`, stamp, binding.NodeID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	binding.State = "REVOKED"
	binding.Authorized = false
	binding.Version++
	binding.UpdatedAt = stamp
	binding.RevokedAt = stamp
	binding.credentialDigest = ""
	return &binding, nil
}

func validNodeBindingID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	switch strings.ToLower(value) {
	case "control-local", "worker-local":
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validNodeCredentialDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validSHA256Digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
