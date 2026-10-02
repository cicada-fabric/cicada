package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const (
	NodeControlPairingInitial   = "INITIAL"
	NodeControlPairingUpgrade   = "UPGRADE"
	NodeControlPairingPending   = "PENDING"
	NodeControlPairingConfirmed = "CONFIRMED"
	NodeControlPairingExpired   = "EXPIRED"
	NodeControlPairingCancelled = "CANCELLED"
	NodeControlKeyActive        = "ACTIVE"
	NodeControlKeyRevoked       = "REVOKED"
	NodeControlRPCProcessing    = "PROCESSING"
	NodeControlRPCComplete      = "COMPLETE"
	NodeControlRPCUncertain     = "UNCERTAIN"
	// Keep durable inbox bounds identical to the Node wire contract. A 2MiB
	// sealed response expands through the inner ciphertext encoding and the
	// outer JSON Envelope encoding, so a 3MiB Store cap rejects legal packets.
	nodeControlMaxPacketBytes       = nodewire.MaxPacketBytes
	nodeControlMaxRequestBytes      = nodewire.MaxRequestPacketBytes
	nodeControlMaxProofBytes        = 64 << 10
	nodeControlResponseMaxCount     = 2048
	nodeControlResponseMaxBytes     = 32 << 20
	nodeControlResponseKeepFor      = 24 * time.Hour
	nodeControlActionTombstoneLimit = 100000
)

var (
	ErrNodeControlPairingNotFound  = errors.New("Node-Control pairing was not found")
	ErrNodeControlPairingConflict  = errors.New("Node-Control pairing conflicts with current binding state")
	ErrNodeControlPairingChanged   = errors.New("Node-Control pairing candidate or version changed")
	ErrNodeControlMigrationBlocked = errors.New("Node management channel requires Owner-approved PQ key binding")
	ErrNodeControlKeyUnauthorized  = errors.New("Node-Control key is not authorized")
	ErrNodeControlRPCConflict      = errors.New("Node-Control operation or sequence conflicts with a prior packet")
	ErrNodeControlRPCUncertain     = errors.New("Node-Control operation outcome is uncertain")
	ErrNodeControlRPCBackpressure  = errors.New("Node-Control action ledger reached its safe epoch capacity")
)

// NodeControlKeyRequestInput is public key material plus the locally held
// Node credential digest. ProofPacket is signed/encrypted evidence, never a
// plaintext RPC or bearer credential.
type NodeControlKeyRequestInput struct {
	Mode               string
	NodeID             string
	NodeName           string
	CredentialDigest   string
	CodeDigest         string
	NodePublicIdentity e2ee.PublicIdentity
	NodeFingerprint    string
	ProofPacket        []byte
	HubPublicIdentity  e2ee.PublicIdentity
	HubKeyVersion      uint64
	HubFingerprint     string
	TargetBindingID    string
	ExpiresAt          time.Time
}

// NodeControlKeyCandidate is safe to return only through the authenticated
// Client-Control RPC. The digest commits the exact Node and Hub public keys.
type NodeControlKeyCandidate struct {
	RequestID                 string `json:"request_id"`
	Version                   int64  `json:"version"`
	Mode                      string `json:"mode"`
	HubID                     string `json:"hub_id"`
	NodeID                    string `json:"node_id"`
	NodeName                  string `json:"node_name"`
	NodeKeyID                 string `json:"node_key_id"`
	NodeKeyFingerprint        string `json:"node_key_fingerprint"`
	HubNodeControlKeyID       string `json:"hub_node_control_key_id"`
	HubNodeControlKeyVersion  uint64 `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string `json:"hub_node_control_fingerprint"`
	NodeKeyEpoch              uint64 `json:"node_key_epoch"`
	CandidateDigest           string `json:"candidate_digest"`
	ExpiresAt                 string `json:"expires_at"`
	State                     string `json:"state"`
	BindingID                 string `json:"binding_id,omitempty"`
	BindingVersion            uint64 `json:"binding_version,omitempty"`
}

// NodeControlKeyBinding is the active Owner-approved Node application key.
// Public identities and authorization evidence are intentionally separate
// from Endpoint keys and Client device keys.
type NodeControlKeyBinding struct {
	OwnerBindingID          string              `json:"owner_binding_id"`
	OwnerID                 string              `json:"owner_id"`
	HubID                   string              `json:"hub_id"`
	NodeID                  string              `json:"node_id"`
	NodeName                string              `json:"node_name"`
	ClientDeviceID          string              `json:"client_device_id"`
	OwnerKeyID              string              `json:"owner_key_id"`
	NodeCredentialVersion   uint64              `json:"node_credential_version"`
	BindingVersion          uint64              `json:"binding_version"`
	NodeKeyID               string              `json:"node_key_id"`
	NodePublicIdentity      e2ee.PublicIdentity `json:"node_public_identity"`
	NodeKeyFingerprint      string              `json:"node_key_fingerprint"`
	NodeKeyVersion          uint64              `json:"node_key_version"`
	NodeKeyEpoch            uint64              `json:"node_key_epoch"`
	HubKeyID                string              `json:"hub_key_id"`
	HubPublicIdentity       e2ee.PublicIdentity `json:"hub_public_identity"`
	HubKeyFingerprint       string              `json:"hub_key_fingerprint"`
	HubKeyVersion           uint64              `json:"hub_key_version"`
	ApprovedRequestID       string              `json:"approved_request_id"`
	ApprovedRequestVersion  int64               `json:"approved_request_version"`
	ApprovedCandidateDigest string              `json:"approved_candidate_digest"`
	ApprovedOwnerDeviceID   string              `json:"approved_owner_device_id"`
	ApprovedOwnerKeyID      string              `json:"approved_owner_key_id"`
	ApprovedAt              string              `json:"approved_at"`
	State                   string              `json:"state"`
	Version                 uint64              `json:"version"`
	RevokedAt               string              `json:"revoked_at,omitempty"`
	CredentialDigest        string              `json:"-"`
}

type NodeControlRPCInput struct {
	CredentialDigest string
	NodeID           string
	BindingID        string
	BindingVersion   uint64
	NodeKeyID        string
	NodeKeyEpoch     uint64
	Sequence         uint64
	OperationID      string
	Operation        string
	RequestDigest    string
}

type NodeControlRPCRecord struct {
	BindingID      string
	NodeKeyEpoch   uint64
	Sequence       uint64
	OperationID    string
	Operation      string
	RequestDigest  string
	ResponsePacket []byte
	State          string
}

type NodeControlRPCCompletion struct {
	NodeControlRPCInput
	ResponsePacket       []byte
	SnapshotRequestRoute *nodewire.Route
	SnapshotManifest     *nodewire.SnapshotManifest
	SnapshotErrorCode    string
}

// NodeControlSnapshotRPCResponseProjection is Hub-owned metadata committed
// beside the sealed download response. It lets exact retries stream the same
// CAS object without decrypting a response whose recipient is the Node.
type NodeControlSnapshotRPCResponseProjection struct {
	Manifest  *nodewire.SnapshotManifest
	ErrorCode string
}

type nodeControlCandidateBasis struct {
	RequestID          string              `json:"request_id"`
	Version            int64               `json:"version"`
	Mode               string              `json:"mode"`
	HubID              string              `json:"hub_id"`
	NodeID             string              `json:"node_id"`
	NodeName           string              `json:"node_name"`
	CredentialDigest   string              `json:"credential_digest"`
	CodeDigest         string              `json:"code_digest"`
	NodePublicIdentity e2ee.PublicIdentity `json:"node_public_identity"`
	NodeFingerprint    string              `json:"node_fingerprint"`
	HubPublicIdentity  e2ee.PublicIdentity `json:"hub_public_identity"`
	HubKeyVersion      uint64              `json:"hub_key_version"`
	HubFingerprint     string              `json:"hub_fingerprint"`
	NodeKeyEpoch       uint64              `json:"node_key_epoch"`
	TargetBindingID    string              `json:"target_binding_id"`
	ExpiresAt          string              `json:"expires_at"`
}

func nodeControlFingerprint(identity e2ee.PublicIdentity) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cicada/node-control/key-fingerprint/v1\x00"))
	_, _ = hash.Write(identity.KEMPublic)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(identity.SigningPublic)
	return hex.EncodeToString(hash.Sum(nil))
}

func nodeControlCandidateDigest(basis nodeControlCandidateBasis) (string, error) {
	encoded, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("cicada/node-control/candidate/v1\x00"), encoded...))
	return hex.EncodeToString(hash[:]), nil
}

func validateNodeControlOperation(operation string) bool {
	switch operation {
	case "node.binding.status", "node.heartbeat", "node.jobs.list", "node.jobs.claim",
		"node.jobs.result", "node.approvals.create", "node.approvals.status",
		nodewire.SnapshotUploadOperation, nodewire.SnapshotDownloadOperation:
		return true
	default:
		return false
	}
}

func nodeControlActionOperation(operation string) bool {
	switch operation {
	case "node.jobs.claim", "node.jobs.result", "node.approvals.create":
		return true
	case nodewire.SnapshotUploadOperation:
		return true
	default:
		return false
	}
}

func (s *Store) StartNodeControlKeyRequest(input NodeControlKeyRequestInput) (*NodeControlKeyCandidate, error) {
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.NodeName = strings.TrimSpace(input.NodeName)
	// Fabric.HashSessionCredential uses case-sensitive base64url. Never fold
	// this digest's case or it will no longer identify the active Node token.
	input.CredentialDigest = strings.TrimSpace(input.CredentialDigest)
	input.CodeDigest = strings.ToLower(strings.TrimSpace(input.CodeDigest))
	input.Mode = strings.ToUpper(strings.TrimSpace(input.Mode))
	input.NodeFingerprint = strings.ToLower(strings.TrimSpace(input.NodeFingerprint))
	input.HubFingerprint = strings.ToLower(strings.TrimSpace(input.HubFingerprint))
	if input.Mode != NodeControlPairingInitial && input.Mode != NodeControlPairingUpgrade ||
		!validNodeBindingID(input.NodeID) || input.NodeName == "" || len(input.NodeName) > 128 ||
		!validNodeCredentialDigest(input.CredentialDigest) || !validSHA256Digest(input.CodeDigest) ||
		len(input.ProofPacket) == 0 || len(input.ProofPacket) > nodeControlMaxProofBytes ||
		input.HubKeyVersion == 0 || !validSHA256Digest(input.NodeFingerprint) ||
		!validSHA256Digest(input.HubFingerprint) || e2ee.ValidatePublicIdentity(input.NodePublicIdentity) != nil ||
		e2ee.ValidatePublicIdentity(input.HubPublicIdentity) != nil ||
		input.NodePublicIdentity.ID != strings.TrimSpace(input.NodePublicIdentity.ID) ||
		input.HubPublicIdentity.ID != strings.TrimSpace(input.HubPublicIdentity.ID) ||
		input.NodeFingerprint != nodeControlFingerprint(input.NodePublicIdentity) ||
		input.HubFingerprint != nodeControlFingerprint(input.HubPublicIdentity) {
		return nil, errors.New("valid Node-Control pairing material is required")
	}
	if input.ExpiresAt.IsZero() {
		return nil, errors.New("Node-Control pairing expiry is required")
	}
	now := time.Now().UTC()
	if input.ExpiresAt.Before(now.Add(time.Minute)) || input.ExpiresAt.After(now.Add(15*time.Minute)) {
		return nil, errors.New("Node-Control pairing expiry must be between one and fifteen minutes")
	}
	expiresAt := input.ExpiresAt.UTC().Format(time.RFC3339Nano)
	nowStamp := now.Format(time.RFC3339Nano)
	nodePublicJSON, err := json.Marshal(input.NodePublicIdentity)
	if err != nil {
		return nil, err
	}
	hubPublicJSON, err := json.Marshal(input.HubPublicIdentity)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil {
		return nil, fmt.Errorf("read stable Hub identity: %w", err)
	}
	if hubID == "" {
		return nil, errors.New("stable Hub identity is unavailable")
	}
	if _, err := tx.Exec(`UPDATE node_control_key_requests_v1 SET state='EXPIRED',version=version+1
WHERE state='PENDING' AND (expires_at='' OR cicada_network_expiry_allows(expires_at,?)=0)`, nowStamp); err != nil {
		return nil, err
	}
	// Keep the unauthenticated bootstrap within the existing Node device-code
	// service's global and per-Node churn limits; random Node IDs cannot turn
	// signed proof packets into an unbounded database write surface.
	cooldownStart := now.Add(-nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano)
	var recentNodeRequests int
	if err := tx.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1
WHERE node_id=? AND created_at>=?`, input.NodeID, cooldownStart).Scan(&recentNodeRequests); err != nil {
		return nil, err
	}
	if recentNodeRequests > 0 {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	windowStart := now.Add(-nodeDeviceBindingCreateWindow).Format(time.RFC3339Nano)
	var recentCreates int
	if err := tx.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE created_at>=?`, windowStart).Scan(&recentCreates); err != nil {
		return nil, err
	}
	if recentCreates >= nodeDeviceBindingMaxCreatesPerWindow {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	var pendingCount int
	if err := tx.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1
WHERE state='PENDING' AND cicada_network_expiry_allows(expires_at,?)=1`, nowStamp).Scan(&pendingCount); err != nil {
		return nil, err
	}
	if pendingCount >= nodeDeviceBindingMaxPending {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	var existing int
	if err := tx.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1
WHERE node_id=? AND state='PENDING' AND cicada_network_expiry_allows(expires_at,?)=1`, input.NodeID, nowStamp).Scan(&existing); err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, ErrNodeControlPairingConflict
	}
	requestID := NewID("nctrlreq")
	nodeEpoch := uint64(1)
	var maxNodeEpoch sql.NullInt64
	if err := tx.QueryRow(`SELECT max(node_key_epoch) FROM node_control_key_bindings_v1 WHERE node_id=?`, input.NodeID).Scan(&maxNodeEpoch); err != nil {
		return nil, err
	}
	if maxNodeEpoch.Valid {
		if maxNodeEpoch.Int64 < 1 || maxNodeEpoch.Int64 >= int64(^uint64(0)>>1) {
			return nil, ErrNodeControlPairingConflict
		}
		nodeEpoch = uint64(maxNodeEpoch.Int64 + 1)
	}
	targetBindingID := ""
	if input.Mode == NodeControlPairingInitial {
		var active int
		if err := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=? AND state='ACTIVE'`, input.NodeID).Scan(&active); err != nil {
			return nil, err
		}
		if active != 0 {
			return nil, ErrNodeControlMigrationBlocked
		}
		// An active legacy credential without Owner binding is also a migration
		// case; never overwrite or adopt it through the unauthenticated path.
		var activeCredential int
		if err := tx.QueryRow(`SELECT count(*) FROM fabric_node_credentials
WHERE node_id=? AND status='active'`, input.NodeID).Scan(&activeCredential); err != nil {
			return nil, err
		}
		if activeCredential != 0 {
			return nil, ErrNodeControlMigrationBlocked
		}
	} else {
		targetBindingID = strings.TrimSpace(input.TargetBindingID)
		var bindingVersion, credentialVersion int64
		var boundDigest, boundHubID string
		err := tx.QueryRow(`SELECT binding.id,binding.version,binding.node_credential_digest,
binding.node_credential_version,binding.hub_id
FROM node_owner_bindings_v2 binding
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id
  AND credential.status='active' AND credential.version=binding.node_credential_version
  AND credential.credential_hash=binding.node_credential_digest
WHERE binding.id=? AND binding.node_id=? AND binding.state='ACTIVE'`,
			targetBindingID, input.NodeID).Scan(&targetBindingID, &bindingVersion, &boundDigest, &credentialVersion, &boundHubID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (boundDigest != input.CredentialDigest || boundHubID != hubID) {
			return nil, ErrNodeControlKeyUnauthorized
		}
		if err != nil {
			return nil, err
		}
		_ = bindingVersion
		_ = credentialVersion
	}
	var recent int
	window := now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	if err := tx.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE node_id=? AND created_at>=?`, input.NodeID, window).Scan(&recent); err != nil {
		return nil, err
	}
	if recent >= 12 {
		return nil, ErrNodeDeviceBindingRateLimited
	}
	basis := nodeControlCandidateBasis{
		RequestID: requestID, Version: 1, Mode: input.Mode, HubID: hubID, NodeID: input.NodeID,
		NodeName: input.NodeName, CredentialDigest: input.CredentialDigest, CodeDigest: input.CodeDigest,
		NodePublicIdentity: input.NodePublicIdentity, NodeFingerprint: input.NodeFingerprint,
		HubPublicIdentity: input.HubPublicIdentity, HubKeyVersion: input.HubKeyVersion,
		HubFingerprint: input.HubFingerprint, NodeKeyEpoch: nodeEpoch,
		TargetBindingID: targetBindingID, ExpiresAt: expiresAt,
	}
	candidateDigest, err := nodeControlCandidateDigest(basis)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO node_control_key_requests_v1
(id,mode,hub_id,node_id,node_name,node_credential_digest,code_digest,node_key_id,
 node_public_identity_json,node_fingerprint,node_proof_packet,hub_key_id,hub_public_identity_json,
 hub_key_version,hub_fingerprint,candidate_digest,target_binding_id,node_key_epoch,state,version,
 expires_at,created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',1,?,?)`,
		requestID, input.Mode, hubID, input.NodeID, input.NodeName, input.CredentialDigest,
		input.CodeDigest, input.NodePublicIdentity.ID, string(nodePublicJSON), input.NodeFingerprint,
		input.ProofPacket, input.HubPublicIdentity.ID, string(hubPublicJSON), input.HubKeyVersion,
		input.HubFingerprint, candidateDigest, targetBindingID, nodeEpoch, expiresAt, nowStamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, ErrNodeControlPairingConflict
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NodeControlKeyCandidate{RequestID: requestID, Version: 1, Mode: input.Mode,
		HubID: hubID, NodeID: input.NodeID, NodeName: input.NodeName,
		NodeKeyID: input.NodePublicIdentity.ID, NodeKeyFingerprint: input.NodeFingerprint,
		HubNodeControlKeyID: input.HubPublicIdentity.ID, HubNodeControlKeyVersion: input.HubKeyVersion,
		HubNodeControlFingerprint: input.HubFingerprint, NodeKeyEpoch: nodeEpoch,
		CandidateDigest: candidateDigest, ExpiresAt: expiresAt, State: NodeControlPairingPending}, nil
}

func (s *Store) PreviewNodeControlKeyRequest(ownerID, clientDeviceID, codeDigest string) (*NodeControlKeyCandidate, error) {
	ownerID, clientDeviceID = strings.TrimSpace(ownerID), strings.TrimSpace(clientDeviceID)
	codeDigest = strings.ToLower(strings.TrimSpace(codeDigest))
	if validateOwnerApprovalID(ownerID) != nil || clientDeviceID == "" || !validSHA256Digest(codeDigest) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var candidate NodeControlKeyCandidate
	var requestBasis nodeControlCandidateBasis
	var nodePublicJSON, hubPublicJSON string
	err = tx.QueryRow(`SELECT request.id,request.version,request.mode,request.hub_id,request.node_id,
request.node_name,request.node_key_id,request.node_fingerprint,request.hub_key_id,
request.hub_key_version,request.hub_fingerprint,request.node_key_epoch,request.candidate_digest,
request.expires_at,request.state,request.node_public_identity_json,request.hub_public_identity_json,
request.node_credential_digest,request.code_digest,request.target_binding_id
FROM node_control_key_requests_v1 request
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=request.hub_id
JOIN client_devices_v2 device ON device.owner_id=? AND device.device_id=? AND device.state='ACTIVE'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=device.owner_id
 AND owner_key.key_id=device.owner_key_id AND owner_key.state='ACTIVE'
JOIN principals principal ON principal.id=device.owner_id AND principal.kind='human' AND principal.status='active'
WHERE request.code_digest=?`, ownerID, clientDeviceID, codeDigest).Scan(
		&candidate.RequestID, &candidate.Version, &candidate.Mode, &candidate.HubID, &candidate.NodeID,
		&candidate.NodeName, &candidate.NodeKeyID, &candidate.NodeKeyFingerprint,
		&candidate.HubNodeControlKeyID, &candidate.HubNodeControlKeyVersion,
		&candidate.HubNodeControlFingerprint, &candidate.NodeKeyEpoch, &candidate.CandidateDigest,
		&candidate.ExpiresAt, &candidate.State, &nodePublicJSON, &hubPublicJSON,
		&requestBasis.CredentialDigest, &requestBasis.CodeDigest, &requestBasis.TargetBindingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeControlPairingNotFound
	}
	if err != nil {
		return nil, err
	}
	requestBasis.RequestID, requestBasis.Version, requestBasis.Mode = candidate.RequestID, candidate.Version, candidate.Mode
	requestBasis.HubID, requestBasis.NodeID, requestBasis.NodeName = candidate.HubID, candidate.NodeID, candidate.NodeName
	requestBasis.NodeFingerprint, requestBasis.HubKeyVersion = candidate.NodeKeyFingerprint, candidate.HubNodeControlKeyVersion
	requestBasis.HubFingerprint, requestBasis.NodeKeyEpoch, requestBasis.ExpiresAt = candidate.HubNodeControlFingerprint, candidate.NodeKeyEpoch, candidate.ExpiresAt
	if err := json.Unmarshal([]byte(nodePublicJSON), &requestBasis.NodePublicIdentity); err != nil {
		return nil, errors.New("stored Node-Control public identity is invalid")
	}
	if err := json.Unmarshal([]byte(hubPublicJSON), &requestBasis.HubPublicIdentity); err != nil {
		return nil, errors.New("stored Hub Node-Control public identity is invalid")
	}
	computed, err := nodeControlCandidateDigest(requestBasis)
	if err != nil || computed != candidate.CandidateDigest {
		return nil, ErrNodeControlPairingChanged
	}
	if candidate.State != NodeControlPairingPending || !networkFutureExpiry(candidate.ExpiresAt, time.Now().UTC()) {
		if candidate.State == NodeControlPairingPending {
			_, _ = tx.Exec(`UPDATE node_control_key_requests_v1 SET state='EXPIRED',version=version+1
WHERE id=? AND state='PENDING' AND version=?`, candidate.RequestID, candidate.Version)
			if err := tx.Commit(); err != nil {
				return nil, err
			}
		}
		return nil, ErrNodeControlPairingNotFound
	}
	return &candidate, nil
}

func (s *Store) ConfirmNodeControlKeyRequest(ownerID, clientDeviceID, codeDigest string,
	expectedVersion int64, expectedCandidateDigest, currentHubKeyID, currentHubFingerprint string) (*NodeControlKeyBinding, error) {
	ownerID, clientDeviceID = strings.TrimSpace(ownerID), strings.TrimSpace(clientDeviceID)
	codeDigest = strings.ToLower(strings.TrimSpace(codeDigest))
	expectedCandidateDigest = strings.ToLower(strings.TrimSpace(expectedCandidateDigest))
	currentHubKeyID = strings.TrimSpace(currentHubKeyID)
	currentHubFingerprint = strings.ToLower(strings.TrimSpace(currentHubFingerprint))
	if validateOwnerApprovalID(ownerID) != nil || clientDeviceID == "" || !validSHA256Digest(codeDigest) ||
		expectedVersion <= 0 || !validSHA256Digest(expectedCandidateDigest) || currentHubKeyID == "" ||
		!validSHA256Digest(currentHubFingerprint) {
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
	err = tx.QueryRow(`SELECT hub.hub_id,device.owner_key_id
FROM client_device_hub_config_v2 hub
JOIN client_devices_v2 device ON device.owner_id=? AND device.device_id=? AND device.state='ACTIVE'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=device.owner_id
 AND owner_key.key_id=device.owner_key_id AND owner_key.state='ACTIVE'
JOIN principals principal ON principal.id=device.owner_id AND principal.kind='human' AND principal.status='active'
WHERE hub.id=1`, ownerID, clientDeviceID).Scan(&hubID, &ownerKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeDeviceBindingUnauthorized
	}
	if err != nil {
		return nil, err
	}
	var candidate NodeControlKeyCandidate
	var credentialDigest, nodePublicJSON, hubPublicJSON, targetBindingID string
	err = tx.QueryRow(`SELECT id,version,mode,hub_id,node_id,node_name,node_key_id,node_fingerprint,
hub_key_id,hub_key_version,hub_fingerprint,node_key_epoch,candidate_digest,expires_at,state,
node_credential_digest,node_public_identity_json,hub_public_identity_json,target_binding_id
FROM node_control_key_requests_v1 WHERE code_digest=?`, codeDigest).Scan(
		&candidate.RequestID, &candidate.Version, &candidate.Mode, &candidate.HubID, &candidate.NodeID,
		&candidate.NodeName, &candidate.NodeKeyID, &candidate.NodeKeyFingerprint,
		&candidate.HubNodeControlKeyID, &candidate.HubNodeControlKeyVersion,
		&candidate.HubNodeControlFingerprint, &candidate.NodeKeyEpoch, &candidate.CandidateDigest,
		&candidate.ExpiresAt, &candidate.State, &credentialDigest, &nodePublicJSON, &hubPublicJSON,
		&targetBindingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeControlPairingNotFound
	}
	if err != nil {
		return nil, err
	}
	if candidate.Version != expectedVersion || candidate.CandidateDigest != expectedCandidateDigest ||
		candidate.HubID != hubID || candidate.HubNodeControlKeyID != currentHubKeyID ||
		candidate.HubNodeControlFingerprint != currentHubFingerprint {
		return nil, ErrNodeControlPairingChanged
	}
	if candidate.State != NodeControlPairingPending || !networkFutureExpiry(candidate.ExpiresAt, time.Now().UTC()) {
		return nil, ErrNodeControlPairingNotFound
	}
	var nodePublic, hubPublic e2ee.PublicIdentity
	if json.Unmarshal([]byte(nodePublicJSON), &nodePublic) != nil ||
		json.Unmarshal([]byte(hubPublicJSON), &hubPublic) != nil ||
		e2ee.ValidatePublicIdentity(nodePublic) != nil || e2ee.ValidatePublicIdentity(hubPublic) != nil ||
		nodePublic.ID != candidate.NodeKeyID || hubPublic.ID != candidate.HubNodeControlKeyID ||
		nodeControlFingerprint(nodePublic) != candidate.NodeKeyFingerprint ||
		nodeControlFingerprint(hubPublic) != candidate.HubNodeControlFingerprint {
		return nil, ErrNodeControlPairingChanged
	}
	var basis nodeControlCandidateBasis
	basis.RequestID, basis.Version, basis.Mode = candidate.RequestID, candidate.Version, candidate.Mode
	basis.HubID, basis.NodeID, basis.NodeName = candidate.HubID, candidate.NodeID, candidate.NodeName
	basis.CredentialDigest, basis.CodeDigest, basis.NodePublicIdentity = credentialDigest, codeDigest, nodePublic
	basis.NodeFingerprint, basis.HubPublicIdentity = candidate.NodeKeyFingerprint, hubPublic
	basis.HubKeyVersion, basis.HubFingerprint = candidate.HubNodeControlKeyVersion, candidate.HubNodeControlFingerprint
	basis.NodeKeyEpoch, basis.TargetBindingID, basis.ExpiresAt = candidate.NodeKeyEpoch, targetBindingID, candidate.ExpiresAt
	computedCandidate, err := nodeControlCandidateDigest(basis)
	if err != nil || computedCandidate != expectedCandidateDigest {
		return nil, ErrNodeControlPairingChanged
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	var bindingID string
	var credentialVersion int64
	if candidate.Mode == NodeControlPairingInitial {
		var activeBindingCount, activeCredentialCount int
		if err := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=? AND state='ACTIVE'`, candidate.NodeID).Scan(&activeBindingCount); err != nil {
			return nil, err
		}
		if err := tx.QueryRow(`SELECT count(*) FROM fabric_node_credentials WHERE node_id=? AND status='active'`, candidate.NodeID).Scan(&activeCredentialCount); err != nil {
			return nil, err
		}
		if activeBindingCount != 0 || activeCredentialCount != 0 {
			return nil, ErrNodeControlMigrationBlocked
		}
		credentialVersion = 1
		var previousVersion int64
		err := tx.QueryRow(`SELECT version FROM fabric_node_credentials WHERE node_id=?`, candidate.NodeID).Scan(&previousVersion)
		if err == nil {
			if previousVersion < 1 || previousVersion >= int64(^uint64(0)>>1) {
				return nil, ErrNodeControlPairingConflict
			}
			credentialVersion = previousVersion + 1
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO fabric_node_credentials
(node_id,credential_hash,version,status,created_at,updated_at)
VALUES (?,?,?,'active',?,?)
ON CONFLICT(node_id) DO UPDATE SET credential_hash=excluded.credential_hash,
version=excluded.version,status='active',updated_at=excluded.updated_at`,
			candidate.NodeID, credentialDigest, credentialVersion, stamp, stamp); err != nil {
			return nil, err
		}
		bindingID = NewID("nbind")
		if _, err := tx.Exec(`INSERT INTO node_owner_bindings_v2
(id,owner_id,hub_id,node_id,node_name,client_device_id,owner_key_id,node_credential_digest,
node_credential_version,state,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,'ACTIVE',1,?,?)`, bindingID, ownerID, hubID, candidate.NodeID,
			candidate.NodeName, clientDeviceID, ownerKeyID, credentialDigest, credentialVersion, stamp, stamp); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return nil, ErrNodeControlPairingConflict
			}
			return nil, err
		}
		var machineOwnerID string
		err = tx.QueryRow(`SELECT owner_id FROM machines WHERE id=?`, candidate.NodeID).Scan(&machineOwnerID)
		if errors.Is(err, sql.ErrNoRows) {
			capabilities, _ := json.Marshal(map[string]any{})
			if _, err := tx.Exec(`INSERT INTO machines(id,name,status,capabilities_json,last_seen,created_at,owner_id)
VALUES (?,?,'offline',?,'',?,?)`, candidate.NodeID, candidate.NodeName, string(capabilities), stamp, ownerID); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else if machineOwnerID != ownerID {
			return nil, ErrNodeMachineOwnershipConflict
		}
	} else if candidate.Mode == NodeControlPairingUpgrade {
		var currentDigest, currentHubID string
		err := tx.QueryRow(`SELECT id,node_credential_version,node_credential_digest,hub_id
FROM node_owner_bindings_v2 WHERE id=? AND node_id=? AND owner_id=? AND state='ACTIVE'`,
			targetBindingID, candidate.NodeID, ownerID).Scan(&bindingID, &credentialVersion, &currentDigest, &currentHubID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (currentDigest != credentialDigest || currentHubID != hubID) {
			return nil, ErrNodeControlPairingChanged
		}
		if err != nil {
			return nil, err
		}
		// The explicit current Owner approval transfers the binding's live
		// Owner-key association to the approving active device without rotating
		// the existing Node bearer or resetting any counter.
		if _, err := tx.Exec(`UPDATE node_owner_bindings_v2 SET client_device_id=?,owner_key_id=?,
version=version+1,updated_at=? WHERE id=? AND state='ACTIVE'`, clientDeviceID, ownerKeyID, stamp, bindingID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE node_control_key_bindings_v1 SET state='REVOKED',version=version+1,
updated_at=?,revoked_at=? WHERE owner_binding_id=? AND state='ACTIVE'`, stamp, stamp, bindingID); err != nil {
			return nil, err
		}
	} else {
		return nil, ErrNodeControlPairingChanged
	}
	requestResult, err := tx.Exec(`UPDATE node_control_key_requests_v1 SET state='CONFIRMED',version=version+1,
confirmed_at=?,approved_owner_id=?,approved_client_device_id=?,approved_owner_key_id=?,approved_binding_id=?
WHERE id=? AND state='PENDING' AND version=? AND candidate_digest=?`, stamp, ownerID, clientDeviceID,
		ownerKeyID, bindingID, candidate.RequestID, candidate.Version, expectedCandidateDigest)
	if err != nil {
		return nil, err
	}
	changed, err := requestResult.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrNodeControlPairingChanged
	}
	bindingVersion := int64(1)
	if candidate.Mode == NodeControlPairingUpgrade {
		if err := tx.QueryRow(`SELECT version FROM node_owner_bindings_v2 WHERE id=?`, bindingID).Scan(&bindingVersion); err != nil {
			return nil, err
		}
	}
	_, err = tx.Exec(`INSERT INTO node_control_key_bindings_v1
(id,owner_binding_id,owner_id,hub_id,node_id,node_credential_digest,node_credential_version,
 client_device_id,owner_key_id,node_key_id,node_public_identity_json,node_fingerprint,node_key_version,
 node_key_epoch,hub_key_id,hub_public_identity_json,hub_fingerprint,hub_key_version,
 approved_request_id,approved_request_version,approved_candidate_digest,approved_owner_device_id,
 approved_owner_key_id,approved_at,state,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'ACTIVE',1,?,?)`,
		NewID("nctrlkey"), bindingID, ownerID, hubID, candidate.NodeID, credentialDigest,
		credentialVersion, clientDeviceID, ownerKeyID, nodePublic.ID, string(nodePublicJSON),
		candidate.NodeKeyFingerprint, 1, candidate.NodeKeyEpoch, hubPublic.ID, string(hubPublicJSON),
		candidate.HubNodeControlFingerprint, candidate.HubNodeControlKeyVersion, candidate.RequestID,
		candidate.Version, expectedCandidateDigest, clientDeviceID, ownerKeyID, stamp, stamp, stamp)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.NodeControlKeyForCredential(credentialDigest, candidate.NodeID)
}

func (s *Store) NodeControlKeyForCredential(credentialDigest, nodeID string) (*NodeControlKeyBinding, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	nodeID = strings.TrimSpace(nodeID)
	if !validNodeCredentialDigest(credentialDigest) || !validNodeBindingID(nodeID) {
		return nil, ErrNodeControlKeyUnauthorized
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	binding, err := nodeControlCurrentBindingTx(tx, credentialDigest, nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if lookupErr := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=? AND node_credential_digest=? AND state='ACTIVE'`, nodeID, credentialDigest).Scan(&count); lookupErr != nil {
			return nil, lookupErr
		}
		if count > 0 {
			return nil, ErrNodeControlMigrationBlocked
		}
		return nil, ErrNodeControlKeyUnauthorized
	}
	return binding, err
}

func (s *Store) BeginNodeControlRPC(input NodeControlRPCInput) (*NodeControlRPCRecord, bool, error) {
	input.CredentialDigest = strings.TrimSpace(input.CredentialDigest)
	input.NodeID, input.BindingID = strings.TrimSpace(input.NodeID), strings.TrimSpace(input.BindingID)
	input.NodeKeyID = strings.TrimSpace(input.NodeKeyID)
	input.OperationID, input.Operation = strings.TrimSpace(input.OperationID), strings.TrimSpace(input.Operation)
	input.RequestDigest = strings.ToLower(strings.TrimSpace(input.RequestDigest))
	if !validNodeCredentialDigest(input.CredentialDigest) || !validNodeBindingID(input.NodeID) ||
		input.BindingID == "" || input.BindingVersion == 0 || input.NodeKeyID == "" ||
		input.NodeKeyEpoch == 0 || input.Sequence == 0 || input.OperationID == "" || len(input.OperationID) > 256 ||
		!validateNodeControlOperation(input.Operation) || !validSHA256Digest(input.RequestDigest) {
		return nil, false, ErrNodeControlRPCConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if err := pruneNodeControlRPCResponsesTx(tx, time.Now().UTC()); err != nil {
		return nil, false, err
	}
	var activeBindingID, activeNodeKeyID string
	var activeBindingVersion, activeKeyEpoch int64
	err = tx.QueryRow(`SELECT owner_binding.id,owner_binding.version,node_key.node_key_id,node_key.node_key_epoch
FROM node_owner_bindings_v2 owner_binding
JOIN fabric_node_credentials credential ON credential.node_id=owner_binding.node_id
 AND credential.status='active' AND credential.version=owner_binding.node_credential_version
 AND credential.credential_hash=owner_binding.node_credential_digest
JOIN principals principal ON principal.id=owner_binding.owner_id AND principal.kind='human' AND principal.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=owner_binding.hub_id
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=owner_binding.owner_id
 AND owner_key.key_id=owner_binding.owner_key_id AND owner_key.state='ACTIVE'
JOIN client_devices_v2 device ON device.owner_id=owner_binding.owner_id
 AND device.device_id=owner_binding.client_device_id AND device.state='ACTIVE'
JOIN node_control_key_bindings_v1 node_key ON node_key.owner_binding_id=owner_binding.id AND node_key.state='ACTIVE'
WHERE owner_binding.node_credential_digest=? AND owner_binding.node_id=? AND owner_binding.state='ACTIVE'`,
		input.CredentialDigest, input.NodeID).Scan(&activeBindingID, &activeBindingVersion, &activeNodeKeyID, &activeKeyEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		var activeOwnerBinding int
		if lookupErr := tx.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2
WHERE node_id=? AND node_credential_digest=? AND state='ACTIVE'`, input.NodeID, input.CredentialDigest).Scan(&activeOwnerBinding); lookupErr != nil {
			return nil, false, lookupErr
		}
		if activeOwnerBinding == 1 {
			return nil, false, ErrNodeControlMigrationBlocked
		}
		return nil, false, ErrNodeControlKeyUnauthorized
	}
	if err != nil {
		return nil, false, err
	}
	if activeBindingID != input.BindingID || uint64(activeBindingVersion) != input.BindingVersion ||
		activeNodeKeyID != input.NodeKeyID || uint64(activeKeyEpoch) != input.NodeKeyEpoch {
		return nil, false, ErrNodeControlKeyUnauthorized
	}
	var prior NodeControlRPCRecord
	err = tx.QueryRow(`SELECT owner_binding_id,node_key_epoch,sequence,operation_id,operation,
request_digest,response_packet,state FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=?`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence).Scan(&prior.BindingID, &prior.NodeKeyEpoch,
		&prior.Sequence, &prior.OperationID, &prior.Operation, &prior.RequestDigest, &prior.ResponsePacket, &prior.State)
	if err == nil {
		if prior.OperationID != input.OperationID || prior.Operation != input.Operation || prior.RequestDigest != input.RequestDigest {
			return nil, false, ErrNodeControlRPCConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return &prior, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	// Reusing an operation ID under a different sequence or packet is denied.
	err = tx.QueryRow(`SELECT owner_binding_id,node_key_epoch,sequence,operation_id,operation,
request_digest,response_packet,state FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`,
		input.BindingID, input.NodeKeyEpoch, input.OperationID).Scan(&prior.BindingID, &prior.NodeKeyEpoch,
		&prior.Sequence, &prior.OperationID, &prior.Operation, &prior.RequestDigest, &prior.ResponsePacket, &prior.State)
	if err == nil {
		return nil, false, ErrNodeControlRPCConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	if nodeControlActionOperation(input.Operation) {
		var actionCount int
		if err := tx.QueryRow(`SELECT count(*) FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=?
	 AND operation IN ('node.jobs.claim','node.jobs.result','node.approvals.create',?)`,
			input.BindingID, input.NodeKeyEpoch, nodewire.SnapshotUploadOperation).Scan(&actionCount); err != nil {
			return nil, false, err
		}
		if actionCount >= nodeControlActionTombstoneLimit {
			return nil, false, ErrNodeControlRPCBackpressure
		}
	}
	var lastSequence int64
	err = tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1
WHERE owner_binding_id=? AND node_key_epoch=?`, input.BindingID, input.NodeKeyEpoch).Scan(&lastSequence)
	if errors.Is(err, sql.ErrNoRows) {
		lastSequence = 0
	} else if err != nil {
		return nil, false, err
	}
	if input.Sequence <= uint64(lastSequence) || input.Sequence > uint64(^uint64(0)>>1) {
		return nil, false, ErrNodeControlRPCConflict
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO node_control_rpc_sequences_v1(owner_binding_id,node_key_epoch,last_sequence)
VALUES (?,?,?) ON CONFLICT(owner_binding_id,node_key_epoch) DO UPDATE SET last_sequence=excluded.last_sequence`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence); err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`INSERT INTO node_control_rpc_inbox_v1
(owner_binding_id,node_key_epoch,sequence,operation_id,operation,request_digest,state,created_at,updated_at)
VALUES (?,?,?,?,?,?,'PROCESSING',?,?)`, input.BindingID, input.NodeKeyEpoch, input.Sequence,
		input.OperationID, input.Operation, input.RequestDigest, stamp, stamp); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, false, ErrNodeControlRPCConflict
		}
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &NodeControlRPCRecord{BindingID: input.BindingID, NodeKeyEpoch: input.NodeKeyEpoch,
		Sequence: input.Sequence, OperationID: input.OperationID, Operation: input.Operation,
		RequestDigest: input.RequestDigest, State: NodeControlRPCProcessing}, false, nil
}

func (s *Store) CompleteNodeControlRPC(input NodeControlRPCCompletion) error {
	input.RequestDigest = strings.ToLower(strings.TrimSpace(input.RequestDigest))
	if len(input.ResponsePacket) == 0 || len(input.ResponsePacket) > nodeControlMaxPacketBytes ||
		!validSHA256Digest(input.RequestDigest) || !validateNodeControlOperation(input.Operation) ||
		input.Sequence == 0 || input.OperationID == "" {
		return ErrNodeControlRPCConflict
	}
	manifestJSON := ""
	requestRouteDigest := ""
	if input.Operation == nodewire.SnapshotDownloadOperation {
		if input.SnapshotRequestRoute == nil || (input.SnapshotManifest == nil) == (input.SnapshotErrorCode == "") {
			return ErrNodeControlRPCConflict
		}
		if !validNodeControlSnapshotRequestRoute(*input.SnapshotRequestRoute, input.NodeControlRPCInput) {
			return ErrNodeControlRPCConflict
		}
		var routeErr error
		requestRouteDigest, routeErr = nodeControlSnapshotRouteDigest(*input.SnapshotRequestRoute)
		if routeErr != nil {
			return ErrNodeControlRPCConflict
		}
		if input.SnapshotManifest != nil {
			if input.SnapshotManifest.Validate(false) != nil ||
				input.SnapshotManifest.Direction != nodewire.SnapshotDirectionDownload {
				return ErrNodeControlRPCConflict
			}
			encoded, err := json.Marshal(input.SnapshotManifest)
			if err != nil {
				return ErrNodeControlRPCConflict
			}
			manifestJSON = string(encoded)
		} else if !validNodeControlSnapshotErrorCode(input.SnapshotErrorCode) {
			return ErrNodeControlRPCConflict
		}
	} else if input.SnapshotRequestRoute != nil || input.SnapshotManifest != nil || input.SnapshotErrorCode != "" {
		return ErrNodeControlRPCConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := verifyNodeControlBindingTx(tx, input.NodeControlRPCInput); err != nil {
		return err
	}
	var priorOperation, priorDigest, priorState string
	var priorPacket []byte
	err = tx.QueryRow(`SELECT operation,request_digest,state,response_packet FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID).Scan(&priorOperation, &priorDigest, &priorState, &priorPacket)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeControlRPCConflict
	}
	if err != nil {
		return err
	}
	if priorOperation != input.Operation || priorDigest != input.RequestDigest {
		return ErrNodeControlRPCConflict
	}
	if priorState == NodeControlRPCComplete {
		if string(priorPacket) != string(input.ResponsePacket) {
			return ErrNodeControlRPCConflict
		}
		if input.Operation == nodewire.SnapshotDownloadOperation {
			var priorRequestDigest, priorRouteDigest, priorManifest, priorError string
			if err := tx.QueryRow(`SELECT request_digest,request_route_digest,manifest_json,error_code FROM node_control_snapshot_rpc_responses_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
				input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID).
				Scan(&priorRequestDigest, &priorRouteDigest, &priorManifest, &priorError); err != nil {
				return err
			}
			if priorRequestDigest != input.RequestDigest || priorRouteDigest != requestRouteDigest ||
				priorManifest != manifestJSON || priorError != input.SnapshotErrorCode {
				return ErrNodeControlRPCConflict
			}
		}
		return tx.Commit()
	}
	if priorState != NodeControlRPCProcessing {
		return ErrNodeControlRPCUncertain
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=?,updated_at=?
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=? AND request_digest=? AND state='PROCESSING'`,
		input.ResponsePacket, stamp, input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID, input.RequestDigest)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrNodeControlRPCConflict
	}
	if input.Operation == nodewire.SnapshotDownloadOperation {
		if _, err := tx.Exec(`INSERT INTO node_control_snapshot_rpc_responses_v1
(owner_binding_id,node_key_epoch,sequence,operation_id,request_digest,request_route_digest,manifest_json,error_code)
VALUES (?,?,?,?,?,?,?,?)`,
			input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID,
			input.RequestDigest, requestRouteDigest, manifestJSON, input.SnapshotErrorCode); err != nil {
			return err
		}
	}
	if err := pruneNodeControlRPCResponsesTx(tx, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func validNodeControlSnapshotErrorCode(code string) bool {
	switch code {
	case "SNAPSHOT_INVALID", "SNAPSHOT_DIGEST_MISMATCH", "SNAPSHOT_UNAVAILABLE":
		return true
	default:
		return false
	}
}

func validNodeControlSnapshotRequestRoute(route nodewire.Route, input NodeControlRPCInput) bool {
	return route.Version == nodewire.Version && route.Direction == nodewire.DirectionRequest &&
		route.HubID != "" && route.NodeID == input.NodeID && route.BindingID == input.BindingID &&
		route.BindingVersion == input.BindingVersion && route.NodeKeyEpoch == input.NodeKeyEpoch &&
		route.Sequence == input.Sequence && route.OperationID == input.OperationID &&
		route.Operation == input.Operation && route.SenderKeyID == input.NodeKeyID &&
		route.SenderKeyVersion > 0 && route.ReceiverKeyID != "" && route.ReceiverKeyVersion > 0
}

func nodeControlSnapshotRouteDigest(route nodewire.Route) (string, error) {
	encoded, err := json.Marshal(route)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// NodeControlSnapshotRPCResponseProjection returns only Hub-owned response
// metadata for the exact current request. The encrypted packet remains
// opaque; route and request identity are still fenced by this input.
func (s *Store) NodeControlSnapshotRPCResponseProjection(input NodeControlRPCInput,
	requestRoute nodewire.Route) (*NodeControlSnapshotRPCResponseProjection, error) {
	input.RequestDigest = strings.ToLower(strings.TrimSpace(input.RequestDigest))
	if input.Operation != nodewire.SnapshotDownloadOperation || input.Sequence == 0 || input.OperationID == "" ||
		!validSHA256Digest(input.RequestDigest) || !validNodeControlSnapshotRequestRoute(requestRoute, input) {
		return nil, ErrNodeControlRPCConflict
	}
	requestRouteDigest, err := nodeControlSnapshotRouteDigest(requestRoute)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := verifyNodeControlBindingTx(tx, input); err != nil {
		return nil, err
	}
	var manifestJSON, errorCode string
	err = tx.QueryRow(`SELECT projection.manifest_json,projection.error_code
FROM node_control_snapshot_rpc_responses_v1 AS projection
JOIN node_control_rpc_inbox_v1 AS inbox
  ON inbox.owner_binding_id=projection.owner_binding_id
 AND inbox.node_key_epoch=projection.node_key_epoch
 AND inbox.sequence=projection.sequence
 AND inbox.operation_id=projection.operation_id
WHERE projection.owner_binding_id=? AND projection.node_key_epoch=? AND projection.sequence=?
	AND projection.operation_id=? AND projection.request_digest=? AND projection.request_route_digest=?
	AND inbox.operation=? AND inbox.request_digest=? AND inbox.state='COMPLETE'`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID,
		input.RequestDigest, requestRouteDigest, input.Operation, input.RequestDigest).Scan(&manifestJSON, &errorCode)
	if err != nil {
		return nil, err
	}
	projection := &NodeControlSnapshotRPCResponseProjection{ErrorCode: errorCode}
	if manifestJSON != "" {
		var manifest nodewire.SnapshotManifest
		if json.Unmarshal([]byte(manifestJSON), &manifest) != nil || manifest.Validate(false) != nil ||
			manifest.Direction != nodewire.SnapshotDirectionDownload {
			return nil, ErrNodeControlRPCConflict
		}
		projection.Manifest = &manifest
	} else if !validNodeControlSnapshotErrorCode(errorCode) {
		return nil, ErrNodeControlRPCConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return projection, nil
}

func (s *Store) MarkNodeControlRPCUncertain(input NodeControlRPCInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='UNCERTAIN',updated_at=?
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=? AND state='PROCESSING'`,
		stamp, input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return ErrNodeControlRPCConflict
	}
	return nil
}

func verifyNodeControlBindingTx(tx *sql.Tx, input NodeControlRPCInput) error {
	var bindingID, keyID string
	var bindingVersion, epoch int64
	err := tx.QueryRow(`SELECT owner_binding.id,owner_binding.version,node_key.node_key_id,node_key.node_key_epoch
FROM node_owner_bindings_v2 owner_binding
JOIN fabric_node_credentials credential ON credential.node_id=owner_binding.node_id
 AND credential.status='active' AND credential.version=owner_binding.node_credential_version
 AND credential.credential_hash=owner_binding.node_credential_digest
JOIN principals principal ON principal.id=owner_binding.owner_id AND principal.kind='human' AND principal.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=owner_binding.hub_id
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=owner_binding.owner_id
 AND owner_key.key_id=owner_binding.owner_key_id AND owner_key.state='ACTIVE'
JOIN client_devices_v2 device ON device.owner_id=owner_binding.owner_id
 AND device.device_id=owner_binding.client_device_id AND device.state='ACTIVE'
JOIN node_control_key_bindings_v1 node_key ON node_key.owner_binding_id=owner_binding.id AND node_key.state='ACTIVE'
WHERE owner_binding.id=? AND owner_binding.node_id=? AND owner_binding.node_credential_digest=?
 AND owner_binding.state='ACTIVE'`, input.BindingID, input.NodeID, input.CredentialDigest).
		Scan(&bindingID, &bindingVersion, &keyID, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeControlKeyUnauthorized
	}
	if err != nil {
		return err
	}
	if bindingID != input.BindingID || uint64(bindingVersion) != input.BindingVersion ||
		keyID != input.NodeKeyID || uint64(epoch) != input.NodeKeyEpoch {
		return ErrNodeControlKeyUnauthorized
	}
	return nil
}

// verifyNodeControlRPCProcessingTx is the mutation-time fence. It repeats the
// live Owner binding and key epoch check in the same SQLite transaction as a
// Node-originated state change and proves that this exact encrypted request is
// still the one admitted by BeginNodeControlRPC. A key upgrade between Begin
// and dispatch therefore invalidates the request before any side effect.
func verifyNodeControlRPCProcessingTx(tx *sql.Tx, input NodeControlRPCInput) error {
	if err := verifyNodeControlBindingTx(tx, input); err != nil {
		return err
	}
	var operation, digest, state string
	err := tx.QueryRow(`SELECT operation,request_digest,state FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID).
		Scan(&operation, &digest, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeControlRPCConflict
	}
	if err != nil {
		return err
	}
	if operation != input.Operation || digest != input.RequestDigest || state != NodeControlRPCProcessing {
		return ErrNodeControlRPCConflict
	}
	return nil
}

func pruneNodeControlRPCResponsesTx(tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-nodeControlResponseKeepFor).Format(time.RFC3339Nano)
	// Read/idempotent tombstones can age out after the exact retry window. The
	// per-epoch highwater is never removed, so expired sequence numbers remain
	// permanently unusable even after their small inbox metadata is reclaimed.
	if _, err := tx.Exec(`DELETE FROM node_control_rpc_inbox_v1
WHERE operation IN ('node.binding.status','node.heartbeat','node.jobs.list','node.approvals.status',?)
	 AND created_at<?`, nodewire.SnapshotDownloadOperation, cutoff); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET response_packet=X''
WHERE state='COMPLETE' AND response_packet<>X'' AND created_at<?`, cutoff); err != nil {
		return err
	}
	// Bound the expensive part before reading sizes. The partial cache index
	// yields the newest 2048 entries; any older packets are evicted immediately.
	if _, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET response_packet=X''
WHERE state='COMPLETE' AND response_packet<>X'' AND rowid NOT IN (
 SELECT rowid FROM node_control_rpc_inbox_v1
 WHERE state='COMPLETE' AND response_packet<>X''
 ORDER BY created_at DESC,owner_binding_id,node_key_epoch,sequence LIMIT ?
)`, nodeControlResponseMaxCount); err != nil {
		return err
	}
	type cachedResponse struct {
		bindingID string
		epoch     int64
		sequence  int64
		length    int64
	}
	rows, err := tx.Query(`SELECT owner_binding_id,node_key_epoch,sequence,length(response_packet)
FROM node_control_rpc_inbox_v1 WHERE state='COMPLETE' AND response_packet<>X''
ORDER BY created_at DESC,owner_binding_id,node_key_epoch,sequence LIMIT ?`, nodeControlResponseMaxCount)
	if err != nil {
		return err
	}
	var discarded []cachedResponse
	var retainedBytes int64
	for rows.Next() {
		var item cachedResponse
		if err := rows.Scan(&item.bindingID, &item.epoch, &item.sequence, &item.length); err != nil {
			rows.Close()
			return err
		}
		if retainedBytes+item.length <= nodeControlResponseMaxBytes {
			retainedBytes += item.length
		} else {
			discarded = append(discarded, item)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range discarded {
		if _, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET response_packet=X''
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND state='COMPLETE'`,
			item.bindingID, item.epoch, item.sequence); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) NodeControlPairingStatus(credentialDigest, nodeID, requestID string) (*NodeControlKeyCandidate, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	nodeID = strings.TrimSpace(nodeID)
	requestID = strings.TrimSpace(requestID)
	if !validNodeCredentialDigest(credentialDigest) || !validNodeBindingID(nodeID) || requestID == "" {
		return nil, ErrNodeControlPairingNotFound
	}
	var candidate NodeControlKeyCandidate
	var bindingVersion int64
	err := s.db.QueryRow(`SELECT request.id,node_key.approved_request_version,request.mode,request.hub_id,request.node_id,
request.node_name,request.node_key_id,request.node_fingerprint,request.hub_key_id,
request.hub_key_version,request.hub_fingerprint,request.node_key_epoch,request.candidate_digest,
request.expires_at,request.state,owner_binding.id,owner_binding.version
FROM node_control_key_requests_v1 request
JOIN node_control_key_bindings_v1 node_key ON node_key.approved_request_id=request.id AND node_key.state='ACTIVE'
JOIN node_owner_bindings_v2 owner_binding ON owner_binding.id=node_key.owner_binding_id
 AND owner_binding.state='ACTIVE' AND owner_binding.node_credential_digest=?
JOIN fabric_node_credentials credential ON credential.node_id=owner_binding.node_id
 AND credential.status='active' AND credential.version=owner_binding.node_credential_version
 AND credential.credential_hash=owner_binding.node_credential_digest
JOIN principals principal ON principal.id=owner_binding.owner_id AND principal.kind='human' AND principal.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=owner_binding.hub_id
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=owner_binding.owner_id
 AND owner_key.key_id=owner_binding.owner_key_id AND owner_key.state='ACTIVE'
JOIN client_devices_v2 device ON device.owner_id=owner_binding.owner_id
 AND device.device_id=owner_binding.client_device_id AND device.state='ACTIVE'
WHERE request.id=? AND request.node_id=? AND request.state='CONFIRMED'`, credentialDigest, requestID, nodeID).Scan(
		&candidate.RequestID, &candidate.Version, &candidate.Mode, &candidate.HubID, &candidate.NodeID,
		&candidate.NodeName, &candidate.NodeKeyID, &candidate.NodeKeyFingerprint,
		&candidate.HubNodeControlKeyID, &candidate.HubNodeControlKeyVersion,
		&candidate.HubNodeControlFingerprint, &candidate.NodeKeyEpoch, &candidate.CandidateDigest,
		&candidate.ExpiresAt, &candidate.State, &candidate.BindingID, &bindingVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeControlPairingNotFound
	}
	if err != nil {
		return nil, err
	}
	if bindingVersion < 1 {
		return nil, ErrNodeControlPairingNotFound
	}
	candidate.BindingVersion = uint64(bindingVersion)
	return &candidate, nil
}
