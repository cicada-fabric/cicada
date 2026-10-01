package store

// Sealed SharedTask handoffs keep peer responsibility prose inside the
// existing endpoint-to-endpoint sealed SEND. The Hub stores only the route,
// epoch/CAS coordinates and bounded opaque Artifact references needed to
// enforce transfer and access checks.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sealedTaskHandoffMessagePrefix = "shared-task-handoff.v1:"
	sealedTaskHandoffMaxLifetime   = 24 * time.Hour
	sealedTaskHandoffMaxRefs       = 32

	SealedTaskHandoffProposed    = "PROPOSED"
	SealedTaskHandoffTransferred = "TRANSFERRED"
	SealedTaskHandoffExpired     = "EXPIRED"
	SealedTaskHandoffCancelled   = "CANCELLED"
)

var (
	ErrSealedTaskHandoffNotFound        = errors.New("sealed task handoff not found")
	ErrSealedTaskHandoffConflict        = errors.New("sealed task handoff conflicts with current task or route")
	ErrSealedTaskHandoffPending         = errors.New("sealed task handoff metadata is not committed yet")
	ErrSealedTaskHandoffExpired         = errors.New("sealed task handoff has expired")
	ErrSealedTaskHandoffMissingArtifact = errors.New("receiver cannot access a required current Artifact reference")
)

// SealedTaskHandoffArtifactRef is deliberately opaque: it carries no path,
// name, summary, evidence prose, or content. Version and digest bind the
// exact immutable Artifact version required by the sealed handoff packet.
type SealedTaskHandoffArtifactRef struct {
	ArtifactRefID string `json:"artifact_ref_id"`
	Version       int64  `json:"version"`
	Digest        string `json:"digest"`
}

// SealedSharedTaskHandoff contains Hub-visible responsibility metadata only.
// The task packet and all prose remain in the endpoint-sealed Relay body.
type SealedSharedTaskHandoff struct {
	ID                   string                         `json:"handoff_id"`
	TaskID               string                         `json:"task_id"`
	GroupID              string                         `json:"group_id"`
	FromPrincipalID      string                         `json:"from_principal_id"`
	FromEndpointID       string                         `json:"from_endpoint_id"`
	ToPrincipalID        string                         `json:"to_principal_id"`
	ToEndpointID         string                         `json:"to_endpoint_id"`
	TaskRevision         int64                          `json:"task_revision"`
	FromOwnerEpoch       int64                          `json:"from_owner_epoch"`
	MessageID            string                         `json:"message_id"`
	MessageDigest        string                         `json:"message_digest"`
	RequiredArtifactRefs []SealedTaskHandoffArtifactRef `json:"required_artifact_refs"`
	ExpiresAt            string                         `json:"expires_at"`
	Status               string                         `json:"status"`
	Transport            string                         `json:"transport"`
	Version              int64                          `json:"version"`
	AcceptedAt           string                         `json:"accepted_at,omitempty"`
	TransferredAt        string                         `json:"transferred_at,omitempty"`
	TerminalReason       string                         `json:"terminal_reason,omitempty"`
	CreatedAt            string                         `json:"created_at"`
	UpdatedAt            string                         `json:"updated_at"`

	NotifyNodeID string                       `json:"-"`
	LocalRoute   *LocalSealedTaskHandoffRoute `json:"local_route,omitempty"`
}

// SealedSharedTaskHandoffProposal is an Actor-scoped Store input. Sender
// identity is derived from scope; receiver identity is derived from the
// authenticated route and checked against ExpectedTargetEndpointID.
type SealedSharedTaskHandoffProposal struct {
	HandoffID                string                         `json:"handoff_id"`
	TaskID                   string                         `json:"task_id"`
	ExpectedTargetEndpointID string                         `json:"target_endpoint_id"`
	ExpectedRevision         int64                          `json:"expected_revision"`
	OwnerEpoch               int64                          `json:"owner_epoch"`
	MessageID                string                         `json:"message_id"`
	MessageDigest            string                         `json:"message_digest"`
	ExpiresAt                string                         `json:"expires_at"`
	RequiredArtifactRefs     []SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
}

// SealedTaskHandoffDeliveryAuthorization contains only data an authenticated
// receiver Node needs to bind the decrypted packet to its durable route.
type SealedTaskHandoffDeliveryAuthorization struct {
	HandoffID            string                         `json:"handoff_id"`
	TaskID               string                         `json:"task_id"`
	GroupID              string                         `json:"group_id"`
	FromPrincipalID      string                         `json:"from_principal_id"`
	FromEndpointID       string                         `json:"from_endpoint_id"`
	ToPrincipalID        string                         `json:"to_principal_id"`
	ToEndpointID         string                         `json:"to_endpoint_id"`
	TaskRevision         int64                          `json:"task_revision"`
	FromOwnerEpoch       int64                          `json:"from_owner_epoch"`
	MessageID            string                         `json:"message_id"`
	MessageDigest        string                         `json:"message_digest"`
	RequiredArtifactRefs []SealedTaskHandoffArtifactRef `json:"required_artifact_refs"`
	ExpiresAt            string                         `json:"expires_at"`
	Status               string                         `json:"status"`
	Transport            string                         `json:"transport"`
	Version              int64                          `json:"version"`
	LocalRoute           *LocalSealedTaskHandoffRoute   `json:"local_route,omitempty"`
}

const sealedSharedTaskHandoffColumns = `id,task_id,group_id,from_principal_id,from_endpoint_id,
to_principal_id,to_endpoint_id,task_revision,from_owner_epoch,message_id,message_digest,
required_artifact_refs_json,expires_at,status,version,accepted_at,transferred_at,
terminal_reason,created_at,updated_at`

func (s *Store) initializeSealedSharedTaskHandoffSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS shared_task_sealed_handoffs_v2 (
 id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL,
 group_id TEXT NOT NULL,
 from_principal_id TEXT NOT NULL,
 from_endpoint_id TEXT NOT NULL,
 to_principal_id TEXT NOT NULL,
 to_endpoint_id TEXT NOT NULL,
 task_revision INTEGER NOT NULL,
 from_owner_epoch INTEGER NOT NULL,
 message_id TEXT NOT NULL UNIQUE,
 message_digest TEXT NOT NULL,
 required_artifact_refs_json TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 status TEXT NOT NULL,
 version INTEGER NOT NULL,
 accepted_at TEXT NOT NULL DEFAULT '',
 transferred_at TEXT NOT NULL DEFAULT '',
 terminal_reason TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id)
);
CREATE INDEX IF NOT EXISTS shared_task_sealed_handoff_task_status_v2
 ON shared_task_sealed_handoffs_v2(task_id,status,created_at);
CREATE INDEX IF NOT EXISTS shared_task_sealed_handoff_expiry_v2
 ON shared_task_sealed_handoffs_v2(status,expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS shared_task_sealed_handoff_one_pending_v2
 ON shared_task_sealed_handoffs_v2(task_id) WHERE status='PROPOSED';`)
	return err
}

func scanSealedSharedTaskHandoff(row interface{ Scan(...any) error }) (*SealedSharedTaskHandoff, error) {
	var value SealedSharedTaskHandoff
	var refsJSON string
	err := row.Scan(&value.ID, &value.TaskID, &value.GroupID, &value.FromPrincipalID,
		&value.FromEndpointID, &value.ToPrincipalID, &value.ToEndpointID,
		&value.TaskRevision, &value.FromOwnerEpoch, &value.MessageID, &value.MessageDigest,
		&refsJSON, &value.ExpiresAt, &value.Status, &value.Version, &value.AcceptedAt,
		&value.TransferredAt, &value.TerminalReason, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSealedTaskHandoffNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(refsJSON), &value.RequiredArtifactRefs); err != nil {
		return nil, err
	}
	if value.RequiredArtifactRefs == nil {
		value.RequiredArtifactRefs = []SealedTaskHandoffArtifactRef{}
	}
	return &value, nil
}

func normalizeSealedTaskHandoffRefs(refs []SealedTaskHandoffArtifactRef) ([]SealedTaskHandoffArtifactRef, error) {
	if len(refs) > sealedTaskHandoffMaxRefs {
		return nil, ErrSealedTaskHandoffConflict
	}
	result := append([]SealedTaskHandoffArtifactRef(nil), refs...)
	for i := range result {
		result[i].ArtifactRefID = strings.TrimSpace(result[i].ArtifactRefID)
		result[i].Digest = strings.ToLower(strings.TrimSpace(result[i].Digest))
		if !validSameGroupSealedV1Token(result[i].ArtifactRefID) || result[i].Version <= 0 || !validSHA256Digest(result[i].Digest) {
			return nil, ErrSealedTaskHandoffConflict
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ArtifactRefID < result[j].ArtifactRefID })
	for i := 1; i < len(result); i++ {
		if result[i-1].ArtifactRefID == result[i].ArtifactRefID {
			return nil, ErrSealedTaskHandoffConflict
		}
	}
	if result == nil {
		result = []SealedTaskHandoffArtifactRef{}
	}
	return result, nil
}

func sealedTaskHandoffMessageID(expiresAt time.Time, handoffID string) string {
	return sealedTaskHandoffMessagePrefix + strconv.FormatInt(expiresAt.UnixMilli(), 10) + ":" + handoffID
}

func parseSealedTaskHandoffMessageID(messageID string) (handoffID string, expiresAt time.Time, ok bool) {
	suffix, found := strings.CutPrefix(messageID, sealedTaskHandoffMessagePrefix)
	if !found {
		return "", time.Time{}, false
	}
	millisRaw, handoffID, found := strings.Cut(suffix, ":")
	if !found || handoffID == "" || strings.Contains(handoffID, ":") || !validSameGroupSealedV1Token(handoffID) {
		return "", time.Time{}, false
	}
	millis, err := strconv.ParseInt(millisRaw, 10, 64)
	if err != nil || millis <= 0 || strconv.FormatInt(millis, 10) != millisRaw {
		return "", time.Time{}, false
	}
	return handoffID, time.UnixMilli(millis).UTC(), true
}

func normalizeSealedTaskHandoffExpiry(raw string, at time.Time) (string, time.Time, error) {
	expiresAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return "", time.Time{}, ErrSealedTaskHandoffConflict
	}
	expiresAt = time.UnixMilli(expiresAt.UnixMilli()).UTC()
	if !expiresAt.After(at) || expiresAt.Sub(at) > sealedTaskHandoffMaxLifetime {
		return "", time.Time{}, ErrSealedTaskHandoffExpired
	}
	return expiresAt.Format(time.RFC3339Nano), expiresAt, nil
}

// ProposeSealedSharedTaskHandoffForActor binds an already-durable signed
// same-Group SEND to the current Task owner and an exact target Endpoint. A
// missing proposal leaves the reserved Relay message unclaimable until its
// signed route deadline.
func (s *Store) ProposeSealedSharedTaskHandoffForActor(scope NativeActorScope,
	input SealedSharedTaskHandoffProposal) (*SealedSharedTaskHandoff, error) {
	input.HandoffID = strings.TrimSpace(input.HandoffID)
	input.TaskID = strings.TrimSpace(input.TaskID)
	input.ExpectedTargetEndpointID = strings.TrimSpace(input.ExpectedTargetEndpointID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.MessageDigest = strings.ToLower(strings.TrimSpace(input.MessageDigest))
	if !validSameGroupSealedV1Token(input.HandoffID) || strings.Contains(input.HandoffID, ":") ||
		!validSameGroupSealedV1Token(input.TaskID) || !validSameGroupSealedV1Token(input.ExpectedTargetEndpointID) ||
		input.ExpectedRevision <= 0 || input.OwnerEpoch <= 0 || !validSHA256Digest(input.MessageDigest) {
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
	startedAt := time.Now().UTC()
	expiresText, expiresAt, err := normalizeSealedTaskHandoffExpiry(input.ExpiresAt, startedAt)
	if err != nil {
		return nil, err
	}
	wantMessageID := sealedTaskHandoffMessageID(expiresAt, input.HandoffID)
	if input.MessageID != wantMessageID || len(wantMessageID) > 256 {
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
	if err := guardNativeActorTx(tx, scope, "task.submit", startedAt); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, input.TaskID)
	if err != nil || task.GroupID != scope.GroupID || task.Revision != input.ExpectedRevision ||
		task.OwnerEpoch != input.OwnerEpoch || task.OwnerPrincipalID != scope.PrincipalID ||
		task.OwnerEndpointID != scope.EndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSealedTaskHandoffConflict
	}
	record, err := relaySealedV1RecordTx(tx, input.MessageID)
	if err != nil || record == nil || record.Route.Kind != "send" || record.Route.RequestID != "" ||
		record.Route.ReplyTo != "" || record.Security.Digest != input.MessageDigest ||
		record.Route.ReceiverEndpointID != input.ExpectedTargetEndpointID ||
		record.Route.MessageID != input.MessageID ||
		record.Security.AuthorizationRef != sameGroupSealedV1AuthorizationRef(task.GroupID) {
		return nil, ErrSealedTaskHandoffConflict
	}
	pair, _, err := validateQueuedSameGroupSealedV1Tx(tx, record, startedAt)
	if err != nil || pair.groupID != task.GroupID || pair.sender.EndpointID != scope.EndpointID ||
		pair.sender.PrincipalID != scope.PrincipalID || pair.receiver.EndpointID != input.ExpectedTargetEndpointID {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, scope.PrincipalID, scope.GroupID, refs, startedAt); err != nil {
		return nil, ErrSealedTaskHandoffMissingArtifact
	}
	if existing, getErr := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=?`, input.HandoffID)); getErr == nil {
		if sealedTaskHandoffEquivalent(*existing, task, pair.receiver.PrincipalID, pair.receiver.EndpointID,
			input, refs, expiresText) && existing.Status == SealedTaskHandoffProposed {
			if err := tx.QueryRow(`SELECT machine_id FROM fabric_endpoints WHERE id=? AND status!='left'`,
				existing.ToEndpointID).Scan(&existing.NotifyNodeID); err != nil {
				return nil, ErrSealedTaskHandoffConflict
			}
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
	timestamp := startedAt.Format(time.RFC3339Nano)
	_, err = tx.Exec(`INSERT INTO shared_task_sealed_handoffs_v2
(id,task_id,group_id,from_principal_id,from_endpoint_id,to_principal_id,to_endpoint_id,
 task_revision,from_owner_epoch,message_id,message_digest,required_artifact_refs_json,
 expires_at,status,version,accepted_at,transferred_at,terminal_reason,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'','','',?,?)`, input.HandoffID, task.ID, task.GroupID,
		scope.PrincipalID, scope.EndpointID, pair.receiver.PrincipalID, pair.receiver.EndpointID,
		task.Revision, task.OwnerEpoch, input.MessageID, input.MessageDigest, string(refsJSON),
		expiresText, SealedTaskHandoffProposed, timestamp, timestamp)
	if err != nil {
		return nil, err
	}
	if err := sharedTaskEvent(tx, task, "SEALED_HANDOFF_PROPOSED", scope.PrincipalID,
		map[string]string{"handoff_id": input.HandoffID, "to_endpoint_id": pair.receiver.EndpointID}); err != nil {
		return nil, err
	}
	var nodeID string
	if err := tx.QueryRow(`SELECT machine_id FROM fabric_endpoints WHERE id=? AND status!='left'`, pair.receiver.EndpointID).Scan(&nodeID); err != nil {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &SealedSharedTaskHandoff{ID: input.HandoffID, TaskID: task.ID, GroupID: task.GroupID,
		FromPrincipalID: scope.PrincipalID, FromEndpointID: scope.EndpointID,
		ToPrincipalID: pair.receiver.PrincipalID, ToEndpointID: pair.receiver.EndpointID,
		TaskRevision: task.Revision, FromOwnerEpoch: task.OwnerEpoch, MessageID: input.MessageID,
		MessageDigest: input.MessageDigest, RequiredArtifactRefs: refs, ExpiresAt: expiresText,
		Status: SealedTaskHandoffProposed, Version: 1, CreatedAt: timestamp, UpdatedAt: timestamp,
		NotifyNodeID: nodeID}, nil
}

func sealedTaskHandoffEquivalent(existing SealedSharedTaskHandoff, task *SharedTask,
	toPrincipalID, toEndpointID string, input SealedSharedTaskHandoffProposal,
	refs []SealedTaskHandoffArtifactRef, expiresAt string) bool {
	if task == nil || existing.TaskID != task.ID || existing.GroupID != task.GroupID ||
		existing.FromPrincipalID != task.OwnerPrincipalID || existing.FromEndpointID != task.OwnerEndpointID ||
		existing.ToPrincipalID != toPrincipalID || existing.ToEndpointID != toEndpointID ||
		existing.TaskRevision != task.Revision || existing.FromOwnerEpoch != task.OwnerEpoch ||
		existing.MessageID != input.MessageID || existing.MessageDigest != input.MessageDigest || existing.ExpiresAt != expiresAt {
		return false
	}
	left, _ := json.Marshal(existing.RequiredArtifactRefs)
	right, _ := json.Marshal(refs)
	return string(left) == string(right)
}

func (s *Store) GetSealedSharedTaskHandoffForActor(scope NativeActorScope,
	id, action string) (*SealedSharedTaskHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := guardNativeActorTx(tx, scope, action, time.Now().UTC()); err != nil {
		return nil, err
	}
	handoff, err := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=? AND group_id=?`, id, scope.GroupID))
	if err != nil {
		return nil, err
	}
	if err := enrichSealedTaskHandoffTransportTx(tx, handoff); err != nil {
		return nil, err
	}
	if scope.EndpointID != handoff.FromEndpointID && scope.EndpointID != handoff.ToEndpointID {
		return nil, ErrSealedTaskHandoffNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return handoff, nil
}

// AcceptSealedSharedTaskHandoffForActor performs receiver ACL/version checks,
// acceptance status CAS and SharedTask owner/revision/epoch transfer in one
// Store transaction. Direct HTTP callers therefore cannot skip Artifact ACL.
func (s *Store) AcceptSealedSharedTaskHandoffForActor(scope NativeActorScope,
	id string, expectedVersion int64, leaseSeconds int) (*SharedTask, error) {
	local, err := s.isLocalSealedTaskHandoff(id)
	if err != nil {
		return nil, err
	}
	if local {
		return s.acceptLocalSealedSharedTaskHandoffForActor(scope, id, expectedVersion, leaseSeconds)
	}
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
	if handoff.Status == SealedTaskHandoffTransferred && handoff.Version == expectedVersion+1 &&
		scope.PrincipalID == handoff.ToPrincipalID && scope.EndpointID == handoff.ToEndpointID {
		if err := guardNativeActorTx(tx, scope, "task.claim", at); err != nil {
			return nil, err
		}
		task, taskErr := loadSharedTaskTx(tx, handoff.TaskID)
		if taskErr != nil || task.OwnerPrincipalID != handoff.ToPrincipalID ||
			task.OwnerEndpointID != handoff.ToEndpointID || task.OwnerEpoch != handoff.FromOwnerEpoch+1 ||
			(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
			return nil, ErrSealedTaskHandoffConflict
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
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil || task.GroupID != handoff.GroupID || task.Revision != handoff.TaskRevision ||
		task.OwnerEpoch != handoff.FromOwnerEpoch || task.OwnerPrincipalID != handoff.FromPrincipalID ||
		task.OwnerEndpointID != handoff.FromEndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSealedTaskHandoffConflict
	}
	record, err := relaySealedV1RecordTx(tx, handoff.MessageID)
	if err != nil || record.Security.Digest != handoff.MessageDigest ||
		record.Route.Kind != "send" || record.Route.SenderEndpointID != handoff.FromEndpointID ||
		record.Route.ReceiverEndpointID != handoff.ToEndpointID ||
		record.Security.AuthorizationRef != sameGroupSealedV1AuthorizationRef(handoff.GroupID) {
		return nil, ErrSealedTaskHandoffConflict
	}
	pair, _, err := validateQueuedSameGroupSealedV1Tx(tx, record, at)
	if err != nil || pair.groupID != handoff.GroupID ||
		pair.sender.PrincipalID != handoff.FromPrincipalID || pair.sender.EndpointID != handoff.FromEndpointID ||
		pair.receiver.PrincipalID != handoff.ToPrincipalID || pair.receiver.EndpointID != handoff.ToEndpointID {
		return nil, ErrSealedTaskHandoffConflict
	}
	if err := authorizeSealedTaskHandoffArtifactRefsTx(tx, scope.PrincipalID, scope.GroupID,
		handoff.RequiredArtifactRefs, at); err != nil {
		return nil, ErrSealedTaskHandoffMissingArtifact
	}
	until := at.Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	updated := at.Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET owner_principal_id=?,owner_endpoint_id=?,
 owner_epoch=owner_epoch+1,claim_key=?,lease_expires_at=?,status=?,revision=revision+1,updated_at=?
 WHERE id=? AND revision=? AND owner_epoch=? AND owner_principal_id=? AND owner_endpoint_id=?`,
		scope.PrincipalID, scope.EndpointID, "sealed-handoff:"+handoff.ID, until, SharedTaskClaimed,
		updated, task.ID, handoff.TaskRevision, handoff.FromOwnerEpoch,
		handoff.FromPrincipalID, handoff.FromEndpointID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
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
		map[string]string{"handoff_id": handoff.ID}); err != nil {
		return nil, err
	}
	if err := sharedTaskEvent(tx, task, "SEALED_HANDOFF_TRANSFERRED", scope.PrincipalID,
		map[string]string{"handoff_id": handoff.ID}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func authorizeSealedTaskHandoffArtifactRefsTx(tx *sql.Tx, principalID, groupID string,
	refs []SealedTaskHandoffArtifactRef, at time.Time) error {
	if len(refs) > sealedTaskHandoffMaxRefs {
		return ErrSealedTaskHandoffMissingArtifact
	}
	requested := []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary, ArtifactRefV2ScopeDigest}
	for _, expected := range refs {
		actual, err := authorizeArtifactRefV2Tx(tx, principalID, groupID, expected.ArtifactRefID, requested, at)
		if err != nil || actual == nil || actual.Version != expected.Version || actual.Digest != expected.Digest {
			return ErrSealedTaskHandoffMissingArtifact
		}
		var latest int64
		if err := tx.QueryRow(`SELECT MAX(version) FROM artifact_v2_refs WHERE artifact_id=?`, actual.ArtifactID).Scan(&latest); err != nil || latest != expected.Version {
			return ErrSealedTaskHandoffMissingArtifact
		}
	}
	return nil
}

func loadSealedTaskHandoffByMessageTx(tx *sql.Tx,
	messageID string) (*SealedSharedTaskHandoff, error) {
	id, routeExpiry, ok := parseSealedTaskHandoffMessageID(messageID)
	if !ok {
		return nil, ErrSealedTaskHandoffConflict
	}
	handoff, err := scanSealedSharedTaskHandoff(tx.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+
		` FROM shared_task_sealed_handoffs_v2 WHERE id=? AND message_id=?`, id, messageID))
	if errors.Is(err, ErrSealedTaskHandoffNotFound) {
		return nil, ErrSealedTaskHandoffPending
	}
	if err != nil {
		return nil, err
	}
	if handoff.ID != id || !parseRFC3339OrZero(handoff.ExpiresAt).Equal(routeExpiry) ||
		handoff.MessageID != messageID {
		return nil, ErrSealedTaskHandoffConflict
	}
	return handoff, nil
}

func parseRFC3339OrZero(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func sealedTaskHandoffTaskMatchesTx(tx *sql.Tx, handoff *SealedSharedTaskHandoff,
	at time.Time) error {
	if handoff == nil {
		return ErrSealedTaskHandoffConflict
	}
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil || task.GroupID != handoff.GroupID || !sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return ErrSealedTaskHandoffConflict
	}
	switch handoff.Status {
	case SealedTaskHandoffProposed:
		if task.Revision != handoff.TaskRevision || task.OwnerEpoch != handoff.FromOwnerEpoch ||
			task.OwnerPrincipalID != handoff.FromPrincipalID || task.OwnerEndpointID != handoff.FromEndpointID ||
			(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
			return ErrSealedTaskHandoffConflict
		}
	case SealedTaskHandoffTransferred:
		if task.Revision != handoff.TaskRevision+1 || task.OwnerEpoch != handoff.FromOwnerEpoch+1 ||
			task.OwnerPrincipalID != handoff.ToPrincipalID || task.OwnerEndpointID != handoff.ToEndpointID ||
			task.Status != SharedTaskClaimed {
			return ErrSealedTaskHandoffConflict
		}
	default:
		return ErrSealedTaskHandoffConflict
	}
	if !parseRFC3339OrZero(handoff.ExpiresAt).After(at) {
		return ErrSealedTaskHandoffExpired
	}
	return authorizeSealedTaskHandoffArtifactRefsTx(tx, handoff.ToPrincipalID,
		handoff.GroupID, handoff.RequiredArtifactRefs, at)
}

func sealedTaskHandoffDeliveryAuthorization(handoff *SealedSharedTaskHandoff) *SealedTaskHandoffDeliveryAuthorization {
	if handoff == nil {
		return nil
	}
	transport := handoff.Transport
	if transport == "" {
		transport = "RELAY"
	}
	return &SealedTaskHandoffDeliveryAuthorization{HandoffID: handoff.ID, TaskID: handoff.TaskID,
		GroupID: handoff.GroupID, FromPrincipalID: handoff.FromPrincipalID,
		FromEndpointID: handoff.FromEndpointID, ToPrincipalID: handoff.ToPrincipalID,
		ToEndpointID: handoff.ToEndpointID, TaskRevision: handoff.TaskRevision,
		FromOwnerEpoch: handoff.FromOwnerEpoch, MessageID: handoff.MessageID,
		MessageDigest:        handoff.MessageDigest,
		RequiredArtifactRefs: append([]SealedTaskHandoffArtifactRef(nil), handoff.RequiredArtifactRefs...),
		ExpiresAt:            handoff.ExpiresAt, Status: handoff.Status,
		Transport: transport, Version: handoff.Version, LocalRoute: cloneLocalTaskHandoffRoute(handoff.LocalRoute)}
}

func sealedTaskHandoffMessageIDExpired(messageID string, at time.Time) bool {
	_, expiresAt, ok := parseSealedTaskHandoffMessageID(messageID)
	return !ok || !expiresAt.After(at)
}

func markSealedTaskHandoffTerminalTx(tx *sql.Tx, handoff *SealedSharedTaskHandoff,
	status, reason, at string) error {
	if handoff == nil || (status != SealedTaskHandoffExpired && status != SealedTaskHandoffCancelled) {
		return ErrSealedTaskHandoffConflict
	}
	_, err := tx.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET status=?,version=version+1,
 terminal_reason=?,updated_at=? WHERE id=? AND status=? AND version=?`,
		status, reason, at, handoff.ID, handoff.Status, handoff.Version)
	return err
}

func sealedTaskHandoffFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrSealedTaskHandoffExpired):
		return "sealed task handoff expired"
	case errors.Is(err, ErrSealedTaskHandoffMissingArtifact):
		return "required Artifact reference access is no longer current"
	default:
		return "sealed task handoff no longer matches current task ownership"
	}
}

func sealedTaskHandoffTargetNodeTx(tx *sql.Tx, handoff *SealedSharedTaskHandoff) (string, error) {
	var nodeID string
	if handoff == nil || handoff.ToEndpointID == "" {
		return "", ErrSealedTaskHandoffConflict
	}
	if err := tx.QueryRow(`SELECT machine_id FROM fabric_endpoints WHERE id=? AND status!='left'`, handoff.ToEndpointID).Scan(&nodeID); err != nil {
		return "", fmt.Errorf("load handoff recipient Node: %w", err)
	}
	return nodeID, nil
}
