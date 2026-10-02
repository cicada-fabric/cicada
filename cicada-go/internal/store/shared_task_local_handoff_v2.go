package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// ProposeLocalSealedSharedTaskHandoffForActor is compatibility history only.
// Missing history cannot authorize a new local delivery or responsibility change.
func (s *Store) ProposeLocalSealedSharedTaskHandoffForActor(scope NativeActorScope,
	input LocalSealedSharedTaskHandoffProposal) (*SealedSharedTaskHandoff, error) {
	handoff, err := s.GetSealedSharedTaskHandoffForActor(scope, input.HandoffID, "task.read")
	if err != nil {
		return nil, err
	}
	refs, err := normalizeSealedTaskHandoffRefs(input.RequiredArtifactRefs)
	if err != nil {
		return nil, err
	}
	left, _ := json.Marshal(refs)
	right, _ := json.Marshal(handoff.RequiredArtifactRefs)
	digest := sha256.Sum256(input.SenderProof)
	if handoff.Transport != localSealedTaskHandoffTransport || handoff.LocalRoute == nil ||
		handoff.FromPrincipalID != scope.PrincipalID || handoff.FromEndpointID != scope.EndpointID ||
		handoff.TaskID != input.TaskID || handoff.ToEndpointID != input.TargetEndpointID ||
		handoff.TaskRevision != input.ExpectedRevision || handoff.FromOwnerEpoch != input.OwnerEpoch ||
		handoff.MessageID != input.MessageID || handoff.MessageDigest != input.MessageDigest ||
		handoff.ExpiresAt != input.ExpiresAt || string(left) != string(right) ||
		hex.EncodeToString(digest[:]) != handoff.LocalRoute.SenderProofDigest {
		return nil, ErrSealedTaskHandoffConflict
	}
	return handoff, nil
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
	// Old LOCAL_NODE Task history is never a current delivery authorization.
	return nil, ErrSealedTaskHandoffConflict
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
	if expectedVersion <= 0 || leaseSeconds < 0 || leaseSeconds > 3600 {
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
		if err := networkGuardRelaySecurityTx(tx, &RelayMessageSecurity{SenderPrincipalID: handoff.FromPrincipalID,
			SenderEndpointID: handoff.FromEndpointID, SenderGroupID: handoff.GroupID, ReceiverPrincipalID: handoff.ToPrincipalID,
			ReceiverEndpointID: handoff.ToEndpointID, ReceiverGroupID: handoff.GroupID}, handoff.GroupID, at); err != nil {
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
		if task.ClaimKey != "sealed-handoff:"+handoff.ID ||
			parseRFC3339OrZero(task.LeaseExpiresAt).Sub(parseRFC3339OrZero(handoff.TransferredAt)) != time.Duration(leaseSeconds)*time.Second {
			return nil, ErrSealedTaskHandoffConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return task, nil
	}
	return nil, ErrSealedTaskHandoffConflict
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
