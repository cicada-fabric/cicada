package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const localSealedTaskHandoffTransport = "LOCAL_NODE"

// LocalSealedTaskHandoffRoute is the exact current same-Node route snapshot.
// It contains no ciphertext, body, native session ID, or local filesystem path.
type LocalSealedTaskHandoffRoute struct {
	NodeID                 string `json:"node_id"`
	FromBindingID          string `json:"from_binding_id"`
	FromBindingEpoch       uint64 `json:"from_binding_epoch"`
	FromMembershipRevision int64  `json:"from_membership_revision"`
	FromJoinRevision       int64  `json:"from_join_revision"`
	FromKeyID              string `json:"from_key_id"`
	FromKeyVersion         int64  `json:"from_key_version"`
	ToBindingID            string `json:"to_binding_id"`
	ToBindingEpoch         uint64 `json:"to_binding_epoch"`
	ToMembershipRevision   int64  `json:"to_membership_revision"`
	ToJoinRevision         int64  `json:"to_join_revision"`
	ToKeyID                string `json:"to_key_id"`
	ToKeyVersion           int64  `json:"to_key_version"`
	SenderProofDigest      string `json:"sender_proof_digest"`
}

type LocalSealedSharedTaskHandoffProposal struct {
	HandoffID            string                         `json:"handoff_id"`
	TaskID               string                         `json:"task_id"`
	TargetEndpointID     string                         `json:"target_endpoint_id"`
	ExpectedRevision     int64                          `json:"expected_revision"`
	OwnerEpoch           int64                          `json:"owner_epoch"`
	MessageID            string                         `json:"message_id"`
	MessageDigest        string                         `json:"message_digest"`
	ExpiresAt            string                         `json:"expires_at"`
	RequiredArtifactRefs []SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
	SenderProof          []byte                         `json:"sender_proof"`
}

type localSealedTaskHandoffEvidence struct {
	NodeID                 string
	FromBindingID          string
	FromBindingEpoch       uint64
	FromMembershipRevision int64
	FromJoinRevision       int64
	FromKeyID              string
	FromKeyVersion         int64
	ToBindingID            string
	ToBindingEpoch         uint64
	ToMembershipRevision   int64
	ToJoinRevision         int64
	ToKeyID                string
	ToKeyVersion           int64
	SenderProofDigest      string
	SenderProof            []byte
}

func (s *Store) initializeLocalSealedTaskHandoffSchemaV2() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS shared_task_local_handoff_routes_v54 (
 handoff_id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 from_binding_id TEXT NOT NULL,
 from_binding_epoch INTEGER NOT NULL CHECK(from_binding_epoch>0),
 from_membership_revision INTEGER NOT NULL CHECK(from_membership_revision>0),
 from_join_revision INTEGER NOT NULL CHECK(from_join_revision>0),
 from_key_id TEXT NOT NULL,
 from_key_version INTEGER NOT NULL CHECK(from_key_version>0),
 to_binding_id TEXT NOT NULL,
 to_binding_epoch INTEGER NOT NULL CHECK(to_binding_epoch>0),
 to_membership_revision INTEGER NOT NULL CHECK(to_membership_revision>0),
 to_join_revision INTEGER NOT NULL CHECK(to_join_revision>0),
 to_key_id TEXT NOT NULL,
 to_key_version INTEGER NOT NULL CHECK(to_key_version>0),
 sender_proof_digest TEXT NOT NULL CHECK(length(sender_proof_digest)=64),
 sender_proof BLOB NOT NULL CHECK(length(sender_proof)>0),
 created_at TEXT NOT NULL,
 FOREIGN KEY(handoff_id) REFERENCES shared_task_sealed_handoffs_v2(id)
);
CREATE INDEX IF NOT EXISTS shared_task_local_handoff_route_target_v54_idx
 ON shared_task_local_handoff_routes_v54(node_id,to_binding_id,to_binding_epoch,handoff_id);
CREATE TRIGGER IF NOT EXISTS shared_task_local_handoff_route_immutable_v54
BEFORE UPDATE ON shared_task_local_handoff_routes_v54
BEGIN
 SELECT RAISE(ABORT,'local sealed Task handoff route evidence is immutable');
END;`)
	return err
}

// SealedTaskHandoffArtifactRefsDigest returns the domain-separated digest of
// the canonical bounded opaque Artifact reference set used in the signed local
// delivery proof. It never hashes any Artifact prose or path.
func SealedTaskHandoffArtifactRefsDigest(refs []SealedTaskHandoffArtifactRef) (string, error) {
	normalized, err := normalizeSealedTaskHandoffRefs(refs)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return localTaskHandoffArtifactRefsDigest(encoded), nil
}

func localTaskHandoffArtifactRefsDigest(canonicalJSON []byte) string {
	digest := sha256.Sum256(append([]byte("cicada/fabric/local-task-handoff-artifacts/v1\x00"), canonicalJSON...))
	return hex.EncodeToString(digest[:])
}

func (s *Store) ProposeLocalSealedSharedTaskHandoffForActor(scope NativeActorScope,
	input LocalSealedSharedTaskHandoffProposal) (*SealedSharedTaskHandoff, error) {
	input.HandoffID = strings.TrimSpace(input.HandoffID)
	input.TaskID = strings.TrimSpace(input.TaskID)
	input.TargetEndpointID = strings.TrimSpace(input.TargetEndpointID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.MessageDigest = strings.ToLower(strings.TrimSpace(input.MessageDigest))
	if !validSameGroupSealedV1Token(input.HandoffID) || strings.Contains(input.HandoffID, ":") ||
		!validSameGroupSealedV1Token(input.TaskID) || !validSameGroupSealedV1Token(input.TargetEndpointID) ||
		input.ExpectedRevision <= 0 || input.OwnerEpoch <= 0 || !validSHA256Digest(input.MessageDigest) ||
		len(input.SenderProof) == 0 || len(input.SenderProof) > 16*1024 {
		return nil, ErrSealedTaskHandoffConflict
	}
	refs, err := normalizeSealedTaskHandoffRefs(input.RequiredArtifactRefs)
	if err != nil {
		return nil, err
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	refsDigest := localTaskHandoffArtifactRefsDigest(refsJSON)
	at := time.Now().UTC()
	expiresText, expiresAt, err := normalizeSealedTaskHandoffExpiry(input.ExpiresAt, at)
	if err != nil {
		return nil, err
	}
	if input.MessageID != sealedTaskHandoffMessageID(expiresAt, input.HandoffID) || len(input.MessageID) > 256 {
		return nil, ErrSealedTaskHandoffConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	if existing, existingErr := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=?`, input.HandoffID)); existingErr == nil {
		storedEvidence, evidenceErr := readLocalTaskHandoffEvidenceTx(tx, existing.ID)
		refsExistingJSON, _ := json.Marshal(existing.RequiredArtifactRefs)
		refsInputJSON, _ := json.Marshal(refs)
		proofHash := sha256.Sum256(input.SenderProof)
		if evidenceErr != nil || storedEvidence == nil ||
			existing.TaskID != input.TaskID || existing.GroupID != scope.GroupID ||
			existing.FromPrincipalID != scope.PrincipalID || existing.FromEndpointID != scope.EndpointID ||
			existing.ToEndpointID != input.TargetEndpointID || existing.TaskRevision != input.ExpectedRevision ||
			existing.FromOwnerEpoch != input.OwnerEpoch || existing.MessageID != input.MessageID ||
			existing.MessageDigest != input.MessageDigest || existing.ExpiresAt != expiresText ||
			string(refsExistingJSON) != string(refsInputJSON) ||
			hex.EncodeToString(proofHash[:]) != storedEvidence.SenderProofDigest {
			return nil, ErrSealedTaskHandoffConflict
		}
		if err := guardNativeActorTx(tx, scope, "task.read", at); err != nil {
			return nil, err
		}
		stamp := at.Format(time.RFC3339Nano)
		source, sourceErr := readLocalDeliveryEndpointByIDTx(tx, scope.GroupID, scope.EndpointID, stamp)
		target, targetErr := readLocalDeliveryEndpointByIDTx(tx, scope.GroupID, input.TargetEndpointID, stamp)
		if sourceErr != nil || targetErr != nil ||
			validateLocalDeliveryEndpointSnapshot(source, scope.GroupID, at) != nil ||
			validateLocalDeliveryEndpointSnapshot(target, scope.GroupID, at) != nil ||
			source.BindingID != storedEvidence.FromBindingID || source.BindingEpoch != storedEvidence.FromBindingEpoch ||
			source.MembershipRevision != storedEvidence.FromMembershipRevision || source.GroupJoinRevision != storedEvidence.FromJoinRevision ||
			target.BindingID != storedEvidence.ToBindingID || target.BindingEpoch != storedEvidence.ToBindingEpoch ||
			target.MembershipRevision != storedEvidence.ToMembershipRevision || target.GroupJoinRevision != storedEvidence.ToJoinRevision {
			return nil, ErrSealedTaskHandoffConflict
		}
		sourceKey, sourceKeyErr := readCurrentLocalDeliveryKeyTx(tx, source)
		targetKey, targetKeyErr := readCurrentLocalDeliveryKeyTx(tx, target)
		if sourceKeyErr != nil || targetKeyErr != nil || sourceKey == nil || targetKey == nil || sourceKey.KeyID != storedEvidence.FromKeyID ||
			sourceKey.Version != storedEvidence.FromKeyVersion || targetKey.KeyID != storedEvidence.ToKeyID ||
			targetKey.Version != storedEvidence.ToKeyVersion ||
			localTaskHandoffPairGuardTx(tx, scope.GroupID, source, target, at, false) != nil {
			return nil, ErrSealedTaskHandoffConflict
		}
		existing.Transport = localSealedTaskHandoffTransport
		existing.LocalRoute = localTaskHandoffRouteDTO(*storedEvidence)
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	} else if !errors.Is(existingErr, ErrSealedTaskHandoffNotFound) {
		return nil, existingErr
	}
	if err := guardNativeActorTx(tx, scope, "task.submit", at); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, input.TaskID)
	if err != nil || task.GroupID != scope.GroupID || task.Revision != input.ExpectedRevision ||
		task.OwnerEpoch != input.OwnerEpoch || task.OwnerPrincipalID != scope.PrincipalID ||
		task.OwnerEndpointID != scope.EndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSealedTaskHandoffConflict
	}
	stamp := at.Format(time.RFC3339Nano)
	source, err := readLocalDeliveryEndpointByIDTx(tx, scope.GroupID, scope.EndpointID, stamp)
	if err != nil || validateLocalDeliveryEndpointSnapshot(source, scope.GroupID, at) != nil ||
		source.PrincipalID != scope.PrincipalID || source.BindingID != scope.BindingID ||
		source.BindingEpoch != scope.BindingEpoch || source.MembershipRevision != scope.MembershipRevision {
		return nil, ErrSealedTaskHandoffConflict
	}
	target, err := readLocalDeliveryEndpointByIDTx(tx, scope.GroupID, input.TargetEndpointID, stamp)
	if err != nil || validateLocalDeliveryEndpointSnapshot(target, scope.GroupID, at) != nil ||
		target.EndpointID == source.EndpointID || target.NodeID != source.NodeID ||
		target.PrincipalOwnerID != source.PrincipalOwnerID || target.EndpointOwnerID != source.EndpointOwnerID {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := localTaskHandoffPairGuardTx(tx, scope.GroupID, source, target, at, true); err != nil {
		return nil, ErrSealedTaskHandoffConflict
	}
	sourceKey, err := readCurrentLocalDeliveryKeyTx(tx, source)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	targetKey, err := readCurrentLocalDeliveryKeyTx(tx, target)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil || hubID == "" {
		return nil, ErrSealedTaskHandoffConflict
	}
	proofClaims := localTaskHandoffProofClaims(input, expiresText, refsDigest,
		hubID, scope.GroupID, task, source, target, sourceKey, targetKey)
	proof, err := e2ee.VerifyLocalTaskHandoffProof(input.SenderProof, sourceKey.Public, proofClaims, at)
	if err != nil || proof.KeyID != sourceKey.KeyID {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, scope.PrincipalID, scope.GroupID, refs, at); err != nil {
		return nil, ErrSealedTaskHandoffMissingArtifact
	}
	proofHash := sha256.Sum256(input.SenderProof)
	evidence := localSealedTaskHandoffEvidence{NodeID: source.NodeID,
		FromBindingID: source.BindingID, FromBindingEpoch: source.BindingEpoch,
		FromMembershipRevision: source.MembershipRevision, FromJoinRevision: source.GroupJoinRevision,
		FromKeyID: sourceKey.KeyID, FromKeyVersion: sourceKey.Version,
		ToBindingID: target.BindingID, ToBindingEpoch: target.BindingEpoch,
		ToMembershipRevision: target.MembershipRevision, ToJoinRevision: target.GroupJoinRevision,
		ToKeyID: targetKey.KeyID, ToKeyVersion: targetKey.Version,
		SenderProofDigest: hex.EncodeToString(proofHash[:]), SenderProof: append([]byte(nil), input.SenderProof...)}

	if existing, getErr := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=?`, input.HandoffID)); getErr == nil {
		storedEvidence, evidenceErr := readLocalTaskHandoffEvidenceTx(tx, existing.ID)
		if evidenceErr == nil && storedEvidence != nil && existing.Status == SealedTaskHandoffProposed &&
			sealedTaskHandoffEquivalent(*existing, task, target.PrincipalID, target.EndpointID,
				SealedSharedTaskHandoffProposal{HandoffID: input.HandoffID, TaskID: input.TaskID,
					ExpectedTargetEndpointID: input.TargetEndpointID, ExpectedRevision: input.ExpectedRevision,
					OwnerEpoch: input.OwnerEpoch, MessageID: input.MessageID, MessageDigest: input.MessageDigest,
					ExpiresAt: expiresText, RequiredArtifactRefs: refs}, refs, expiresText) &&
			localTaskHandoffEvidenceMatches(*storedEvidence, evidence) {
			if err := tx.QueryRow(`SELECT machine_id FROM fabric_endpoints WHERE id=? AND status!='left'`, existing.ToEndpointID).Scan(&existing.NotifyNodeID); err != nil {
				return nil, ErrSealedTaskHandoffConflict
			}
			existing.Transport = localSealedTaskHandoffTransport
			existing.LocalRoute = localTaskHandoffRouteDTO(*storedEvidence)
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return existing, nil
		}
		return nil, ErrSealedTaskHandoffConflict
	} else if !errors.Is(getErr, ErrSealedTaskHandoffNotFound) {
		return nil, getErr
	}
	var competing int
	if err := tx.QueryRow(`SELECT count(*) FROM shared_task_sealed_handoffs_v2 WHERE task_id=? AND status=?`,
		task.ID, SealedTaskHandoffProposed).Scan(&competing); err != nil {
		return nil, err
	}
	if competing != 0 {
		return nil, ErrSealedTaskHandoffConflict
	}
	_, err = tx.Exec(`INSERT INTO shared_task_sealed_handoffs_v2
(id,task_id,group_id,from_principal_id,from_endpoint_id,to_principal_id,to_endpoint_id,
 task_revision,from_owner_epoch,message_id,message_digest,required_artifact_refs_json,
 expires_at,status,version,accepted_at,transferred_at,terminal_reason,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'','','',?,?)`, input.HandoffID, task.ID, task.GroupID,
		scope.PrincipalID, scope.EndpointID, target.PrincipalID, target.EndpointID,
		task.Revision, task.OwnerEpoch, input.MessageID, input.MessageDigest, string(refsJSON),
		expiresText, SealedTaskHandoffProposed, stamp, stamp)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO shared_task_local_handoff_routes_v54
(handoff_id,node_id,from_binding_id,from_binding_epoch,from_membership_revision,from_join_revision,
 from_key_id,from_key_version,to_binding_id,to_binding_epoch,to_membership_revision,to_join_revision,
 to_key_id,to_key_version,sender_proof_digest,sender_proof,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.HandoffID, evidence.NodeID,
		evidence.FromBindingID, evidence.FromBindingEpoch, evidence.FromMembershipRevision, evidence.FromJoinRevision,
		evidence.FromKeyID, evidence.FromKeyVersion, evidence.ToBindingID, evidence.ToBindingEpoch,
		evidence.ToMembershipRevision, evidence.ToJoinRevision, evidence.ToKeyID, evidence.ToKeyVersion,
		evidence.SenderProofDigest, evidence.SenderProof, stamp)
	if err != nil {
		return nil, err
	}
	if err := sharedTaskEvent(tx, task, "SEALED_HANDOFF_PROPOSED", scope.PrincipalID,
		map[string]string{"handoff_id": input.HandoffID, "to_endpoint_id": target.EndpointID, "transport": localSealedTaskHandoffTransport}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &SealedSharedTaskHandoff{ID: input.HandoffID, TaskID: task.ID, GroupID: task.GroupID,
		FromPrincipalID: scope.PrincipalID, FromEndpointID: scope.EndpointID,
		ToPrincipalID: target.PrincipalID, ToEndpointID: target.EndpointID,
		TaskRevision: task.Revision, FromOwnerEpoch: task.OwnerEpoch, MessageID: input.MessageID,
		MessageDigest: input.MessageDigest, RequiredArtifactRefs: refs, ExpiresAt: expiresText,
		Status: SealedTaskHandoffProposed, Transport: localSealedTaskHandoffTransport,
		Version: 1, CreatedAt: stamp, UpdatedAt: stamp,
		NotifyNodeID: target.NodeID, LocalRoute: localTaskHandoffRouteDTO(evidence)}, nil
}

func localTaskHandoffProofClaims(input LocalSealedSharedTaskHandoffProposal, expiresAt, refsDigest,
	hubID, groupID string, task *SharedTask, source, target localDeliveryEndpointSnapshot,
	sourceKey, targetKey *LocalDeliveryKeyCandidate) e2ee.LocalTaskHandoffProofClaims {
	return e2ee.LocalTaskHandoffProofClaims{Version: 1, Purpose: "LOCAL_NODE",
		HandoffID: input.HandoffID, TaskID: input.TaskID, HubID: hubID, GroupID: groupID,
		FromPrincipalID: source.PrincipalID, FromOwnerID: source.PrincipalOwnerID,
		FromEndpointID: source.EndpointID, FromBindingID: source.BindingID,
		FromBindingEpoch: source.BindingEpoch, FromMembershipRevision: source.MembershipRevision,
		FromJoinRevision: source.GroupJoinRevision, FromKeyID: sourceKey.KeyID, FromKeyVersion: sourceKey.Version,
		ToPrincipalID: target.PrincipalID, ToOwnerID: target.PrincipalOwnerID,
		ToEndpointID: target.EndpointID, ToBindingID: target.BindingID,
		ToBindingEpoch: target.BindingEpoch, ToMembershipRevision: target.MembershipRevision,
		ToJoinRevision: target.GroupJoinRevision, ToKeyID: targetKey.KeyID, ToKeyVersion: targetKey.Version,
		TaskRevision: task.Revision, FromOwnerEpoch: task.OwnerEpoch,
		MessageID: input.MessageID, MessageDigest: input.MessageDigest,
		ExpiresAt: expiresAt, RequiredArtifactRefsHash: refsDigest}
}

func localTaskHandoffPairGuardTx(tx *sql.Tx, groupID string, source, target localDeliveryEndpointSnapshot,
	at time.Time, requireSenderTaskGrant bool) error {
	if source.EndpointID == target.EndpointID || source.GroupID != groupID || target.GroupID != groupID ||
		source.NodeID == "" || source.NodeID != target.NodeID || source.PrincipalOwnerID == "" ||
		source.PrincipalOwnerID != target.PrincipalOwnerID || source.EndpointOwnerID != target.EndpointOwnerID {
		return ErrLocalDeliveryNotAuthorized
	}
	if err := networkGuardRelaySecurityTx(tx, &RelayMessageSecurity{
		SenderPrincipalID: source.PrincipalID, SenderEndpointID: source.EndpointID,
		SenderGroupID: groupID, ReceiverPrincipalID: target.PrincipalID,
		ReceiverEndpointID: target.EndpointID, ReceiverGroupID: groupID,
	}, groupID, at); err != nil {
		return ErrLocalDeliveryNotAuthorized
	}
	nowText := at.Format(time.RFC3339Nano)
	if requireSenderTaskGrant {
		allowed, err := localDeliveryMembershipAllows(tx, source.PrincipalID, groupID, "task.submit", nowText)
		if err != nil || !allowed {
			return ErrNetworkPermission
		}
	}
	allowed, err := localDeliveryMembershipAllows(tx, target.PrincipalID, groupID, "task.claim", nowText)
	if err != nil || !allowed {
		return ErrNetworkPermission
	}
	return nil
}

func readLocalTaskHandoffEvidenceTx(tx *sql.Tx, handoffID string) (*localSealedTaskHandoffEvidence, error) {
	var evidence localSealedTaskHandoffEvidence
	err := tx.QueryRow(`SELECT node_id,from_binding_id,from_binding_epoch,from_membership_revision,
from_join_revision,from_key_id,from_key_version,to_binding_id,to_binding_epoch,
to_membership_revision,to_join_revision,to_key_id,to_key_version,sender_proof_digest,sender_proof
FROM shared_task_local_handoff_routes_v54 WHERE handoff_id=?`, handoffID).Scan(
		&evidence.NodeID, &evidence.FromBindingID, &evidence.FromBindingEpoch,
		&evidence.FromMembershipRevision, &evidence.FromJoinRevision, &evidence.FromKeyID,
		&evidence.FromKeyVersion, &evidence.ToBindingID, &evidence.ToBindingEpoch,
		&evidence.ToMembershipRevision, &evidence.ToJoinRevision, &evidence.ToKeyID,
		&evidence.ToKeyVersion, &evidence.SenderProofDigest, &evidence.SenderProof)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	proofHash := sha256.Sum256(evidence.SenderProof)
	if !validSHA256Digest(evidence.SenderProofDigest) || hex.EncodeToString(proofHash[:]) != evidence.SenderProofDigest {
		return nil, ErrSealedTaskHandoffConflict
	}
	return &evidence, nil
}

func localTaskHandoffEvidenceMatches(a, b localSealedTaskHandoffEvidence) bool {
	return a.NodeID == b.NodeID && a.FromBindingID == b.FromBindingID &&
		a.FromBindingEpoch == b.FromBindingEpoch && a.FromMembershipRevision == b.FromMembershipRevision &&
		a.FromJoinRevision == b.FromJoinRevision && a.FromKeyID == b.FromKeyID && a.FromKeyVersion == b.FromKeyVersion &&
		a.ToBindingID == b.ToBindingID && a.ToBindingEpoch == b.ToBindingEpoch &&
		a.ToMembershipRevision == b.ToMembershipRevision && a.ToJoinRevision == b.ToJoinRevision &&
		a.ToKeyID == b.ToKeyID && a.ToKeyVersion == b.ToKeyVersion
}

func localTaskHandoffRouteDTO(evidence localSealedTaskHandoffEvidence) *LocalSealedTaskHandoffRoute {
	return &LocalSealedTaskHandoffRoute{NodeID: evidence.NodeID,
		FromBindingID: evidence.FromBindingID, FromBindingEpoch: evidence.FromBindingEpoch,
		FromMembershipRevision: evidence.FromMembershipRevision, FromJoinRevision: evidence.FromJoinRevision,
		FromKeyID: evidence.FromKeyID, FromKeyVersion: evidence.FromKeyVersion,
		ToBindingID: evidence.ToBindingID, ToBindingEpoch: evidence.ToBindingEpoch,
		ToMembershipRevision: evidence.ToMembershipRevision, ToJoinRevision: evidence.ToJoinRevision,
		ToKeyID: evidence.ToKeyID, ToKeyVersion: evidence.ToKeyVersion,
		SenderProofDigest: evidence.SenderProofDigest}
}

func cloneLocalTaskHandoffRoute(route *LocalSealedTaskHandoffRoute) *LocalSealedTaskHandoffRoute {
	if route == nil {
		return nil
	}
	copy := *route
	return &copy
}

func enrichSealedTaskHandoffTransportTx(tx *sql.Tx, handoff *SealedSharedTaskHandoff) error {
	if handoff == nil {
		return ErrSealedTaskHandoffConflict
	}
	evidence, err := readLocalTaskHandoffEvidenceTx(tx, handoff.ID)
	if err != nil {
		return err
	}
	if evidence == nil {
		handoff.Transport = "RELAY"
		handoff.LocalRoute = nil
		return nil
	}
	handoff.Transport = localSealedTaskHandoffTransport
	handoff.LocalRoute = localTaskHandoffRouteDTO(*evidence)
	return nil
}

func authorizeLocalSealedTaskHandoffDeliveryTx(tx *sql.Tx, input LocalDeliveryRevalidationInput,
	source, target localDeliveryEndpointSnapshot, sourceKey, targetKey *LocalDeliveryKeyCandidate,
	at time.Time) (*SealedTaskHandoffDeliveryAuthorization, error) {
	handoffID, deadline, ok := parseSealedTaskHandoffMessageID(input.MessageID)
	if !ok || input.Action != "message.send" || !validSHA256Digest(input.MessageDigest) {
		return nil, ErrSealedTaskHandoffConflict
	}
	if !deadline.After(at) {
		return nil, ErrSealedTaskHandoffExpired
	}
	handoff, err := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=?`, handoffID))
	if errors.Is(err, ErrSealedTaskHandoffNotFound) {
		return nil, ErrSealedTaskHandoffPending
	}
	if err != nil {
		return nil, err
	}
	if handoff.Status != SealedTaskHandoffProposed || handoff.MessageID != input.MessageID ||
		handoff.MessageDigest != input.MessageDigest || handoff.ToEndpointID != target.EndpointID ||
		handoff.FromEndpointID != source.EndpointID || handoff.GroupID != source.GroupID ||
		handoff.ExpiresAt != deadline.Format(time.RFC3339Nano) ||
		!parseRFC3339OrZero(handoff.ExpiresAt).After(at) {
		return nil, ErrSealedTaskHandoffConflict
	}
	evidence, err := readLocalTaskHandoffEvidenceTx(tx, handoff.ID)
	if err != nil {
		return nil, err
	}
	if evidence == nil {
		// Reserved local routes may never fall back to the Hub Relay handoff
		// route; a missing local record remains retryable only while uncommitted.
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := validateLocalTaskHandoffCurrentRouteTx(tx, handoff, evidence, source, target,
		sourceKey, targetKey, at, false); err != nil {
		return nil, err
	}
	if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, handoff.ToPrincipalID,
		handoff.GroupID, handoff.RequiredArtifactRefs, at); err != nil {
		return nil, ErrSealedTaskHandoffMissingArtifact
	}
	if err := enrichSealedTaskHandoffTransportTx(tx, handoff); err != nil {
		return nil, err
	}
	return sealedTaskHandoffDeliveryAuthorization(handoff), nil
}

func validateLocalTaskHandoffCurrentRouteTx(tx *sql.Tx, handoff *SealedSharedTaskHandoff,
	evidence *localSealedTaskHandoffEvidence, source, target localDeliveryEndpointSnapshot,
	sourceKey, targetKey *LocalDeliveryKeyCandidate, at time.Time, requireSenderTaskGrant bool) error {
	if handoff == nil || evidence == nil || sourceKey == nil || targetKey == nil ||
		evidence.NodeID != source.NodeID || evidence.NodeID != target.NodeID ||
		evidence.FromBindingID != source.BindingID || evidence.FromBindingEpoch != source.BindingEpoch ||
		evidence.FromMembershipRevision != source.MembershipRevision || evidence.FromJoinRevision != source.GroupJoinRevision ||
		evidence.FromKeyID != sourceKey.KeyID || evidence.FromKeyVersion != sourceKey.Version ||
		evidence.ToBindingID != target.BindingID || evidence.ToBindingEpoch != target.BindingEpoch ||
		evidence.ToMembershipRevision != target.MembershipRevision || evidence.ToJoinRevision != target.GroupJoinRevision ||
		evidence.ToKeyID != targetKey.KeyID || evidence.ToKeyVersion != targetKey.Version {
		return ErrSealedTaskHandoffConflict
	}
	if err := localTaskHandoffPairGuardTx(tx, handoff.GroupID, source, target, at, requireSenderTaskGrant); err != nil {
		return ErrSealedTaskHandoffConflict
	}
	refsJSON, err := json.Marshal(handoff.RequiredArtifactRefs)
	if err != nil {
		return ErrSealedTaskHandoffConflict
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil || hubID == "" {
		return ErrSealedTaskHandoffConflict
	}
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil || task.GroupID != handoff.GroupID || task.Revision != handoff.TaskRevision ||
		task.OwnerEpoch != handoff.FromOwnerEpoch || task.OwnerPrincipalID != handoff.FromPrincipalID ||
		task.OwnerEndpointID != handoff.FromEndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return ErrSealedTaskHandoffConflict
	}
	claims := e2ee.LocalTaskHandoffProofClaims{Version: 1, Purpose: "LOCAL_NODE",
		HandoffID: handoff.ID, TaskID: handoff.TaskID, HubID: hubID, GroupID: handoff.GroupID,
		FromPrincipalID: source.PrincipalID, FromOwnerID: source.PrincipalOwnerID,
		FromEndpointID: source.EndpointID, FromBindingID: source.BindingID,
		FromBindingEpoch: source.BindingEpoch, FromMembershipRevision: source.MembershipRevision,
		FromJoinRevision: source.GroupJoinRevision, FromKeyID: sourceKey.KeyID, FromKeyVersion: sourceKey.Version,
		ToPrincipalID: target.PrincipalID, ToOwnerID: target.PrincipalOwnerID,
		ToEndpointID: target.EndpointID, ToBindingID: target.BindingID,
		ToBindingEpoch: target.BindingEpoch, ToMembershipRevision: target.MembershipRevision,
		ToJoinRevision: target.GroupJoinRevision, ToKeyID: targetKey.KeyID, ToKeyVersion: targetKey.Version,
		TaskRevision: handoff.TaskRevision, FromOwnerEpoch: handoff.FromOwnerEpoch,
		MessageID: handoff.MessageID, MessageDigest: handoff.MessageDigest,
		ExpiresAt: handoff.ExpiresAt, RequiredArtifactRefsHash: localTaskHandoffArtifactRefsDigest(refsJSON)}
	if _, err := e2ee.VerifyLocalTaskHandoffProof(evidence.SenderProof, sourceKey.Public, claims, at); err != nil {
		return ErrSealedTaskHandoffConflict
	}
	return nil
}

func (s *Store) acceptLocalSealedSharedTaskHandoffForActor(scope NativeActorScope,
	id string, expectedVersion int64, leaseSeconds int) (*SharedTask, error) {
	if expectedVersion <= 0 {
		return nil, ErrSealedTaskHandoffConflict
	}
	if leaseSeconds <= 0 {
		leaseSeconds = 300
	}
	if leaseSeconds > 3600 {
		leaseSeconds = 3600
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	handoff, err := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=? AND group_id=?`, id, scope.GroupID))
	if err != nil {
		return nil, err
	}
	evidence, err := readLocalTaskHandoffEvidenceTx(tx, handoff.ID)
	if err != nil || evidence == nil {
		return nil, ErrSealedTaskHandoffConflict
	}
	if handoff.Status == SealedTaskHandoffTransferred && handoff.Version == expectedVersion+1 &&
		scope.PrincipalID == handoff.ToPrincipalID && scope.EndpointID == handoff.ToEndpointID {
		if err := guardNativeActorTx(tx, scope, "task.claim", at); err != nil {
			return nil, err
		}
		target, targetKey, err := currentLocalTaskHandoffEndpointTx(tx, handoff.GroupID, handoff.ToEndpointID, at)
		if err != nil || evidence.NodeID != target.NodeID || evidence.ToBindingID != target.BindingID ||
			evidence.ToBindingEpoch != target.BindingEpoch || evidence.ToMembershipRevision != target.MembershipRevision ||
			evidence.ToJoinRevision != target.GroupJoinRevision || evidence.ToKeyID != targetKey.KeyID || evidence.ToKeyVersion != targetKey.Version {
			return nil, ErrSealedTaskHandoffConflict
		}
		task, taskErr := loadSharedTaskTx(tx, handoff.TaskID)
		if taskErr != nil || task.OwnerPrincipalID != handoff.ToPrincipalID ||
			task.OwnerEndpointID != handoff.ToEndpointID || task.OwnerEpoch != handoff.FromOwnerEpoch+1 ||
			task.Revision != handoff.TaskRevision+1 || task.Status != SharedTaskClaimed ||
			!sharedTaskLeaseActive(task.LeaseExpiresAt) {
			return nil, ErrSealedTaskHandoffConflict
		}
		if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, scope.PrincipalID, scope.GroupID,
			handoff.RequiredArtifactRefs, at); err != nil {
			return nil, ErrSealedTaskHandoffMissingArtifact
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return task, nil
	}
	if handoff.Status != SealedTaskHandoffProposed || handoff.Version != expectedVersion ||
		scope.PrincipalID != handoff.ToPrincipalID || scope.EndpointID != handoff.ToEndpointID {
		return nil, ErrSealedTaskHandoffConflict
	}
	if !at.Before(parseRFC3339OrZero(handoff.ExpiresAt)) {
		_, _ = tx.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET status=?,version=version+1,
 terminal_reason=?,updated_at=? WHERE id=? AND status=? AND version=?`,
			SealedTaskHandoffExpired, "handoff expired before acceptance", at.Format(time.RFC3339Nano),
			handoff.ID, SealedTaskHandoffProposed, handoff.Version)
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrSealedTaskHandoffExpired
	}
	if err := guardNativeActorTx(tx, scope, "task.claim", at); err != nil {
		return nil, err
	}
	source, sourceKey, err := currentLocalTaskHandoffEndpointTx(tx, handoff.GroupID, handoff.FromEndpointID, at)
	if err != nil {
		return nil, ErrSealedTaskHandoffConflict
	}
	target, targetKey, err := currentLocalTaskHandoffEndpointTx(tx, handoff.GroupID, handoff.ToEndpointID, at)
	if err != nil {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := validateLocalTaskHandoffCurrentRouteTx(tx, handoff, evidence, source, target,
		sourceKey, targetKey, at, true); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil || task.GroupID != handoff.GroupID || task.Revision != handoff.TaskRevision ||
		task.OwnerEpoch != handoff.FromOwnerEpoch || task.OwnerPrincipalID != handoff.FromPrincipalID ||
		task.OwnerEndpointID != handoff.FromEndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, scope.PrincipalID, scope.GroupID,
		handoff.RequiredArtifactRefs, at); err != nil {
		return nil, ErrSealedTaskHandoffMissingArtifact
	}
	updated := at.Format(time.RFC3339Nano)
	until := at.Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET owner_principal_id=?,owner_endpoint_id=?,
 owner_epoch=owner_epoch+1,claim_key=?,lease_expires_at=?,status=?,revision=revision+1,updated_at=?
 WHERE id=? AND revision=? AND owner_epoch=? AND owner_principal_id=? AND owner_endpoint_id=?`,
		scope.PrincipalID, scope.EndpointID, "sealed-handoff:"+handoff.ID, until, SharedTaskClaimed,
		updated, task.ID, handoff.TaskRevision, handoff.FromOwnerEpoch, handoff.FromPrincipalID, handoff.FromEndpointID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrSealedTaskHandoffConflict
	}
	result, err = tx.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET status=?,version=version+1,
 accepted_at=?,transferred_at=?,updated_at=? WHERE id=? AND status=? AND version=?`,
		SealedTaskHandoffTransferred, updated, updated, updated, handoff.ID,
		SealedTaskHandoffProposed, handoff.Version)
	if err != nil {
		return nil, err
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrSealedTaskHandoffConflict
	}
	task, err = loadSharedTaskTx(tx, task.ID)
	if err != nil {
		return nil, err
	}
	if err := sharedTaskEvent(tx, task, "SEALED_HANDOFF_ACCEPTED", scope.PrincipalID,
		map[string]string{"handoff_id": handoff.ID, "transport": localSealedTaskHandoffTransport}); err != nil {
		return nil, err
	}
	if err := sharedTaskEvent(tx, task, "SEALED_HANDOFF_TRANSFERRED", scope.PrincipalID,
		map[string]string{"handoff_id": handoff.ID, "transport": localSealedTaskHandoffTransport}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) isLocalSealedTaskHandoff(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var present int
	err := s.db.QueryRow(`SELECT 1 FROM shared_task_local_handoff_routes_v54 WHERE handoff_id=?`, id).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func currentLocalTaskHandoffEndpointTx(tx *sql.Tx, groupID, endpointID string,
	at time.Time) (localDeliveryEndpointSnapshot, *LocalDeliveryKeyCandidate, error) {
	nowText := at.Format(time.RFC3339Nano)
	endpoint, err := readLocalDeliveryEndpointByIDTx(tx, groupID, endpointID, nowText)
	if err != nil || validateLocalDeliveryEndpointSnapshot(endpoint, groupID, at) != nil {
		return localDeliveryEndpointSnapshot{}, nil, ErrSealedTaskHandoffConflict
	}
	key, err := readCurrentLocalDeliveryKeyTx(tx, endpoint)
	if err != nil {
		return localDeliveryEndpointSnapshot{}, nil, err
	}
	return endpoint, key, nil
}
