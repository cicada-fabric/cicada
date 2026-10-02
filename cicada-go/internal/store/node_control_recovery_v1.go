package store

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// NodeControlRecoveryStatus never admits a sequence or dispatches work. Authentication
// runs against this transaction's current Owner/device/credential/key binding.
func (s *Store) NodeControlRecoveryStatus(credentialDigest, nodeID string, authenticate func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error)) (*NodeControlKeyBinding, nodewire.RecoveryRequest, nodewire.RecoveryStatus, error) {
	var q nodewire.RecoveryRequest
	var status nodewire.RecoveryStatus
	if !validNodeCredentialDigest(credentialDigest) || !validNodeBindingID(nodeID) || authenticate == nil {
		return nil, q, status, ErrNodeControlKeyUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, q, status, err
	}
	defer tx.Rollback()
	b, err := nodeControlCurrentBindingTx(tx, credentialDigest, nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNodeControlKeyUnauthorized
	}
	if err != nil {
		return nil, q, status, err
	}
	q, err = authenticate(b)
	if err != nil || nodewire.ValidateRecoveryRequest(q) != nil || q.CredentialDigest != credentialDigest {
		return nil, q, status, ErrNodeControlKeyUnauthorized
	}
	status = nodewire.RecoveryStatus{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKeyID, NodeKeyVersion: b.NodeKeyVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyID: b.HubKeyID, HubKeyVersion: b.HubKeyVersion, CredentialVersion: b.NodeCredentialVersion, Operations: make([]nodewire.RecoveryOperationStatus, 0, len(q.Operations))}
	var high int64
	err = tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, b.OwnerBindingID, b.NodeKeyEpoch).Scan(&high)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, q, status, err
	}
	if high < 0 {
		return nil, q, status, ErrNodeControlRPCConflict
	}
	status.AcceptedHighwater = uint64(high)
	var recorded int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, b.OwnerBindingID, b.NodeKeyEpoch).Scan(&recorded); err != nil {
		return nil, q, status, err
	}
	if recorded > high {
		return nil, q, status, ErrNodeControlRPCConflict
	}
	for _, op := range q.Operations {
		var seq int64
		var digest, state string
		err = tx.QueryRow(`SELECT sequence,request_digest,state FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, b.OwnerBindingID, b.NodeKeyEpoch, op.OperationID).Scan(&seq, &digest, &state)
		if errors.Is(err, sql.ErrNoRows) {
			state = "NOT_RECORDED"
			var count int
			if err = tx.QueryRow(`SELECT count(*) FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=?`, b.OwnerBindingID, b.NodeKeyEpoch, op.Sequence).Scan(&count); err != nil {
				return nil, q, status, err
			}
			if count != 0 {
				return nil, q, status, ErrNodeControlRPCConflict
			}
		} else if err != nil {
			return nil, q, status, err
		} else if seq <= 0 || uint64(seq) != op.Sequence || digest != op.RequestDigest {
			return nil, q, status, ErrNodeControlRPCConflict
		}
		if state != "NOT_RECORDED" && state != NodeControlRPCComplete && state != NodeControlRPCProcessing && state != NodeControlRPCUncertain {
			return nil, q, status, ErrNodeControlRPCConflict
		}
		status.Operations = append(status.Operations, nodewire.RecoveryOperationStatus{RecoveryOperationQuery: op, State: state})
	}
	// End a read-only snapshot without committing any admission/counter changes.
	if err = tx.Rollback(); err != nil {
		return nil, q, status, err
	}
	return b, q, status, nil
}
func nodeControlCurrentBindingTx(tx *sql.Tx, credentialDigest, nodeID string) (*NodeControlKeyBinding, error) {
	var binding NodeControlKeyBinding
	var nodePublicJSON, hubPublicJSON string
	err := tx.QueryRow(`SELECT owner_binding.id,owner_binding.owner_id,owner_binding.hub_id,
owner_binding.node_id,owner_binding.node_name,owner_binding.client_device_id,owner_binding.owner_key_id,
owner_binding.node_credential_version,owner_binding.version,owner_binding.node_credential_digest,
node_key.node_key_id,node_key.node_public_identity_json,node_key.node_fingerprint,node_key.node_key_version,
node_key.node_key_epoch,node_key.hub_key_id,node_key.hub_public_identity_json,node_key.hub_fingerprint,
node_key.hub_key_version,node_key.approved_request_id,node_key.approved_request_version,
node_key.approved_candidate_digest,node_key.approved_owner_device_id,node_key.approved_owner_key_id,
node_key.approved_at,node_key.state,node_key.version,node_key.revoked_at
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
		credentialDigest, nodeID).Scan(&binding.OwnerBindingID, &binding.OwnerID, &binding.HubID,
		&binding.NodeID, &binding.NodeName, &binding.ClientDeviceID, &binding.OwnerKeyID,
		&binding.NodeCredentialVersion, &binding.BindingVersion, &binding.CredentialDigest,
		&binding.NodeKeyID, &nodePublicJSON, &binding.NodeKeyFingerprint, &binding.NodeKeyVersion,
		&binding.NodeKeyEpoch, &binding.HubKeyID, &hubPublicJSON, &binding.HubKeyFingerprint,
		&binding.HubKeyVersion, &binding.ApprovedRequestID, &binding.ApprovedRequestVersion,
		&binding.ApprovedCandidateDigest, &binding.ApprovedOwnerDeviceID, &binding.ApprovedOwnerKeyID,
		&binding.ApprovedAt, &binding.State, &binding.Version, &binding.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(nodePublicJSON), &binding.NodePublicIdentity) != nil ||
		json.Unmarshal([]byte(hubPublicJSON), &binding.HubPublicIdentity) != nil ||
		e2ee.ValidatePublicIdentity(binding.NodePublicIdentity) != nil ||
		e2ee.ValidatePublicIdentity(binding.HubPublicIdentity) != nil ||
		binding.NodePublicIdentity.ID != binding.NodeKeyID || binding.HubPublicIdentity.ID != binding.HubKeyID ||
		nodeControlFingerprint(binding.NodePublicIdentity) != binding.NodeKeyFingerprint ||
		nodeControlFingerprint(binding.HubPublicIdentity) != binding.HubKeyFingerprint ||
		binding.NodeKeyVersion == 0 || binding.NodeKeyEpoch == 0 || binding.HubKeyVersion == 0 {
		return nil, ErrNodeControlKeyUnauthorized
	}
	return &binding, nil
}
