package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"reflect"
	"sort"
	"strings"
	"time"
)

var ErrSharedTaskPeerPlaintext = errors.New("plaintext peer Task results are retired; register an authorized sealed Group SEND reference")

// SharedTaskPeerView is the body-free peer boundary. Control's management
// record remains independent and may contain authorized management plaintext.
type SharedTaskPeerView struct {
	ID               string                    `json:"task_id"`
	GroupID          string                    `json:"group_id"`
	GoalID           string                    `json:"goal_id,omitempty"`
	Priority         int                       `json:"priority"`
	Status           string                    `json:"status"`
	OwnerPrincipalID string                    `json:"owner_principal_id,omitempty"`
	OwnerEndpointID  string                    `json:"owner_endpoint_id,omitempty"`
	Revision         int64                     `json:"revision"`
	OwnerEpoch       int64                     `json:"owner_epoch"`
	LeaseExpiresAt   string                    `json:"lease_expires_at,omitempty"`
	AcceptedResultID string                    `json:"accepted_result_id,omitempty"`
	CreatedAt        string                    `json:"created_at"`
	UpdatedAt        string                    `json:"updated_at"`
	DefinitionStatus string                    `json:"definition_status"`
	Assignment       *SharedTaskPeerAssignment `json:"assignment,omitempty"`
	DefinitionRefs   []SharedTaskSealedRef     `json:"definition_refs,omitempty"`
	ResultRefs       []SharedTaskSealedRef     `json:"result_refs,omitempty"`
}

func ProjectSharedTaskPeer(task *SharedTask) *SharedTaskPeerView {
	if task == nil {
		return nil
	}
	return &SharedTaskPeerView{ID: task.ID, GroupID: task.GroupID, GoalID: task.GoalID,
		Priority: task.Priority, Status: task.Status, OwnerPrincipalID: task.OwnerPrincipalID,
		OwnerEndpointID: task.OwnerEndpointID, Revision: task.Revision, OwnerEpoch: task.OwnerEpoch,
		LeaseExpiresAt: task.LeaseExpiresAt, AcceptedResultID: task.AcceptedResultID,
		CreatedAt: task.CreatedAt, UpdatedAt: task.UpdatedAt, DefinitionStatus: "SEALED_BODY_UNAVAILABLE"}
}

// Denial retains the current actor and old-owner fences without recording a
// plaintext CANDIDATE or touching the Task write guard/events.
func (s *Store) rejectPlainSharedTaskResultForActor(scope NativeActorScope, taskID string,
	ownerEpoch, expectedRevision int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := guardNativeActorTx(tx, scope, "task.submit", time.Now().UTC()); err != nil {
		return err
	}
	task, err := loadSharedTaskTx(tx, taskID)
	if err != nil || task.GroupID != scope.GroupID {
		return ErrSharedTaskNotFound
	}
	if task.OwnerEpoch != ownerEpoch || task.Revision != expectedRevision ||
		task.OwnerEndpointID != scope.EndpointID || task.OwnerPrincipalID != scope.PrincipalID ||
		!sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return ErrSharedTaskStaleOwner
	}
	return ErrSharedTaskPeerPlaintext
}

const (
	SharedTaskDefinitionPurpose = "TASK_DEFINITION_V1"
	SharedTaskResultPurpose     = "TASK_RESULT_V1"
)

var ErrSharedTaskSealedReference = errors.New("Task sealed reference is unavailable or conflicts with current authority")

// The management delegation records exact current identities, never an inferred
// Manager role. Versions change only through the separate trusted Control API.
type SharedTaskPeerAssignment struct {
	TaskID                    string `json:"task_id"`
	GroupID                   string `json:"group_id"`
	Version                   int64  `json:"version"`
	ContentVersion            int64  `json:"content_version"`
	PublisherEndpointID       string `json:"publisher_endpoint_id"`
	ResultRecipientEndpointID string `json:"result_recipient_endpoint_id"`
}
type SharedTaskPeerAssignmentInput struct {
	ExpectedRevision          int64  `json:"expected_revision"`
	ExpectedAssignmentVersion int64  `json:"expected_assignment_version"`
	PublisherEndpointID       string `json:"publisher_endpoint_id"`
	ResultRecipientEndpointID string `json:"result_recipient_endpoint_id"`
}
type SharedTaskPeerShellInput struct {
	GoalID                    string `json:"goal_id,omitempty"`
	Priority                  int    `json:"priority"`
	PublisherEndpointID       string `json:"publisher_endpoint_id"`
	ResultRecipientEndpointID string `json:"result_recipient_endpoint_id"`
}
type SharedTaskArtifactRef struct {
	ArtifactRefID string   `json:"artifact_ref_id"`
	Version       int64    `json:"version"`
	Digest        string   `json:"digest"`
	Scopes        []string `json:"scopes"`
}
type SharedTaskSealedRef struct {
	TaskID            string                      `json:"task_id"`
	GroupID           string                      `json:"group_id"`
	Purpose           string                      `json:"purpose"`
	AssignmentVersion int64                       `json:"assignment_version"`
	ContentVersion    int64                       `json:"content_version"`
	TaskRevision      int64                       `json:"task_revision"`
	OwnerEpoch        int64                       `json:"owner_epoch"`
	MessageID         string                      `json:"message_id"`
	MessageDigest     string                      `json:"message_digest"`
	SenderEndpointID  string                      `json:"sender_endpoint_id"`
	ReaderEndpointID  string                      `json:"reader_endpoint_id"`
	ArtifactRefs      []SharedTaskArtifactRef     `json:"artifact_refs"`
	ResultID          string                      `json:"result_id,omitempty"`
	SealedRoute       e2ee.EndpointMessageContext `json:"sealed_route"`
}

// All body, caller identity and recipient selection fields are absent. The
// current assignment and the persisted cryptographic route supply authority.
type SharedTaskSealedRefInput struct {
	TaskID            string                  `json:"task_id"`
	Purpose           string                  `json:"purpose"`
	AssignmentVersion int64                   `json:"assignment_version"`
	ContentVersion    int64                   `json:"content_version"`
	ExpectedRevision  int64                   `json:"expected_revision"`
	OwnerEpoch        int64                   `json:"owner_epoch"`
	MessageID         string                  `json:"message_id"`
	MessageDigest     string                  `json:"message_digest"`
	ArtifactRefs      []SharedTaskArtifactRef `json:"artifact_refs,omitempty"`
}
type taskPeerEndpointPin struct {
	EndpointID           string `json:"endpoint_id"`
	PrincipalID          string `json:"principal_id"`
	OwnerID              string `json:"owner_id"`
	NodeID               string `json:"node_id"`
	BindingID            string `json:"binding_id"`
	BindingEpoch         uint64 `json:"binding_epoch"`
	KeyID                string `json:"key_id"`
	KeyVersion           int64  `json:"key_version"`
	ProofDigest          string `json:"proof_digest"`
	GroupRevision        int64  `json:"group_revision"`
	MembershipRevision   int64  `json:"membership_revision"`
	EndpointJoinRevision int64  `json:"endpoint_join_revision"`
}

func taskPeerPin(e SameGroupSealedV1EndpointEvidence) taskPeerEndpointPin {
	return taskPeerEndpointPin{e.EndpointID, e.PrincipalID, e.OwnerID, e.NodeID, e.BindingID, e.BindingEpoch, e.Candidate.KeyID, e.Candidate.Version, e.Candidate.ProofDigest, e.GroupRevision, e.MembershipRevision, e.EndpointJoinRevision}
}
func (s *Store) initializeSharedTaskPeerPrivacySchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS shared_task_peer_assignments_v57 (
 task_id TEXT PRIMARY KEY, group_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0),
 content_version INTEGER NOT NULL CHECK(content_version>0), publisher_endpoint_id TEXT NOT NULL,
 result_recipient_endpoint_id TEXT NOT NULL, publisher_pin_json TEXT NOT NULL,
 recipient_pin_json TEXT NOT NULL, manager_principal_id TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id));
 CREATE TABLE IF NOT EXISTS shared_task_peer_refs_v57 (
 message_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, purpose TEXT NOT NULL,
 reader_endpoint_id TEXT NOT NULL, content_version INTEGER NOT NULL,
 assignment_version INTEGER NOT NULL, result_id TEXT NOT NULL DEFAULT '', ref_json TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id));
 CREATE INDEX IF NOT EXISTS shared_task_peer_refs_task_v57 ON shared_task_peer_refs_v57(task_id,purpose,reader_endpoint_id);
 CREATE UNIQUE INDEX IF NOT EXISTS shared_task_peer_definition_one_v57 ON shared_task_peer_refs_v57(task_id,reader_endpoint_id,assignment_version,content_version) WHERE purpose='TASK_DEFINITION_V1';
 CREATE TRIGGER IF NOT EXISTS shared_task_peer_refs_immutable_v57 BEFORE UPDATE ON shared_task_peer_refs_v57 BEGIN SELECT RAISE(ABORT,'Task sealed reference is immutable'); END;
 CREATE TRIGGER IF NOT EXISTS shared_task_peer_refs_no_delete_v57 BEFORE DELETE ON shared_task_peer_refs_v57 BEGIN SELECT RAISE(ABORT,'Task sealed reference history is retained'); END;`)
	return err
}
func taskPeerScopeTx(tx *sql.Tx, groupID string, e SameGroupSealedV1EndpointEvidence, action string, at time.Time) (NativeActorScope, error) {
	scope := NativeActorScope{PrincipalID: e.PrincipalID, EndpointID: e.EndpointID, GroupID: groupID, BindingID: e.BindingID, BindingEpoch: e.BindingEpoch}
	err := tx.QueryRow(`SELECT g.network_id,m.id,m.revision,b.lease_owner FROM groups g JOIN memberships m ON m.group_id=g.id AND m.principal_id=? AND m.status='active' JOIN session_bindings b ON b.id=? WHERE g.id=?`, e.PrincipalID, e.BindingID, groupID).Scan(&scope.NetworkID, &scope.MembershipID, &scope.MembershipRevision, &scope.LeaseOwner)
	if err != nil {
		return scope, ErrSharedTaskSealedReference
	}
	return scope, guardNativeActorTx(tx, scope, action, at)
}
func loadTaskPeerAssignmentTx(tx *sql.Tx, taskID string, at time.Time) (*SharedTaskPeerAssignment, error) {
	var a SharedTaskPeerAssignment
	var publisherJSON, recipientJSON string
	err := tx.QueryRow(`SELECT task_id,group_id,version,content_version,publisher_endpoint_id,result_recipient_endpoint_id,publisher_pin_json,recipient_pin_json FROM shared_task_peer_assignments_v57 WHERE task_id=?`, taskID).Scan(&a.TaskID, &a.GroupID, &a.Version, &a.ContentVersion, &a.PublisherEndpointID, &a.ResultRecipientEndpointID, &publisherJSON, &recipientJSON)
	if err != nil {
		return nil, ErrSharedTaskSealedReference
	}
	for _, side := range []struct{ id, pin, action string }{{a.PublisherEndpointID, publisherJSON, "task.read"}, {a.ResultRecipientEndpointID, recipientJSON, "task.verify"}} {
		current, err := readSameGroupSealedV1EndpointTx(tx, a.GroupID, side.id, at)
		var pin taskPeerEndpointPin
		if err != nil || json.Unmarshal([]byte(side.pin), &pin) != nil || pin != taskPeerPin(current) {
			return nil, ErrSharedTaskSealedReference
		}
		if _, err := taskPeerScopeTx(tx, a.GroupID, current, side.action, at); err != nil {
			return nil, ErrSharedTaskSealedReference
		}
	}
	return &a, nil
}
func setTaskPeerAssignmentTx(tx *sql.Tx, task *SharedTask, input SharedTaskPeerAssignmentInput, managerID string, at time.Time) (*SharedTaskPeerAssignment, error) {
	if managerID == "" || !validSameGroupSealedV1Token(input.PublisherEndpointID) || !validSameGroupSealedV1Token(input.ResultRecipientEndpointID) || task.Revision != input.ExpectedRevision {
		return nil, ErrSharedTaskConflict
	}
	var previous, content int64
	err := tx.QueryRow(`SELECT version,content_version FROM shared_task_peer_assignments_v57 WHERE task_id=?`, task.ID).Scan(&previous, &content)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if previous != input.ExpectedAssignmentVersion || input.ExpectedAssignmentVersion < 0 {
		return nil, ErrSharedTaskConflict
	}
	publisher, err := readSameGroupSealedV1EndpointTx(tx, task.GroupID, input.PublisherEndpointID, at)
	if err != nil {
		return nil, ErrSharedTaskSealedReference
	}
	recipient, err := readSameGroupSealedV1EndpointTx(tx, task.GroupID, input.ResultRecipientEndpointID, at)
	if err != nil {
		return nil, ErrSharedTaskSealedReference
	}
	if _, err = taskPeerScopeTx(tx, task.GroupID, publisher, "task.read", at); err != nil {
		return nil, err
	}
	if _, err = taskPeerScopeTx(tx, task.GroupID, recipient, "task.verify", at); err != nil {
		return nil, err
	}
	p, _ := json.Marshal(taskPeerPin(publisher))
	r, _ := json.Marshal(taskPeerPin(recipient))
	a := &SharedTaskPeerAssignment{task.ID, task.GroupID, previous + 1, content + 1, input.PublisherEndpointID, input.ResultRecipientEndpointID}
	_, err = tx.Exec(`INSERT INTO shared_task_peer_assignments_v57(task_id,group_id,version,content_version,publisher_endpoint_id,result_recipient_endpoint_id,publisher_pin_json,recipient_pin_json,manager_principal_id) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET version=excluded.version,content_version=excluded.content_version,publisher_endpoint_id=excluded.publisher_endpoint_id,result_recipient_endpoint_id=excluded.result_recipient_endpoint_id,publisher_pin_json=excluded.publisher_pin_json,recipient_pin_json=excluded.recipient_pin_json,manager_principal_id=excluded.manager_principal_id`, a.TaskID, a.GroupID, a.Version, a.ContentVersion, a.PublisherEndpointID, a.ResultRecipientEndpointID, string(p), string(r), managerID)
	return a, err
}

// Management-only API. No Actor/peer path invokes this method or chooses its
// manager identity; Control supplies that identity after bearer authorization.
func (s *Store) AssignSharedTaskPeerBody(groupID, taskID, managerID string, input SharedTaskPeerAssignmentInput) (*SharedTaskPeerAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, taskID)
	if err != nil || task.GroupID != groupID {
		return nil, ErrSharedTaskNotFound
	}
	a, err := setTaskPeerAssignmentTx(tx, task, input, managerID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "PEER_BODY_ASSIGNED", managerID, map[string]int64{"assignment_version": a.Version}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return a, nil
}
func (s *Store) CreateSharedTaskPeerShell(groupID, managerID string, input SharedTaskPeerShellInput) (*SharedTask, error) {
	if input.Priority < 0 || input.Priority > 1000000 || (input.GoalID != "" && !validSameGroupSealedV1Token(input.GoalID)) {
		return nil, ErrSharedTaskConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	task := &SharedTask{ID: NewID("task"), GroupID: groupID, GoalID: input.GoalID, Priority: input.Priority, Status: SharedTaskDraft, Revision: 1, CreatedAt: now()}
	task.UpdatedAt = task.CreatedAt
	_, err = tx.Exec(`INSERT INTO shared_tasks_v2 (`+sharedTaskColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, task.ID, task.GroupID, task.GoalID, "", "", task.Priority, task.Status, "", "", 1, 0, "", "", "", task.CreatedAt, task.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_, err = setTaskPeerAssignmentTx(tx, task, SharedTaskPeerAssignmentInput{ExpectedRevision: 1, PublisherEndpointID: input.PublisherEndpointID, ResultRecipientEndpointID: input.ResultRecipientEndpointID}, managerID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "PEER_SHELL_CREATED", managerID, map[string]string{}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}
func canonicalTaskPeerArtifacts(refs []SharedTaskArtifactRef) ([]SharedTaskArtifactRef, error) {
	if len(refs) > 32 {
		return nil, ErrSharedTaskSealedReference
	}
	result := make([]SharedTaskArtifactRef, len(refs))
	copy(result, refs)
	seen := map[string]bool{}
	for i := range result {
		r := &result[i]
		if !validSameGroupSealedV1Token(r.ArtifactRefID) || r.Version <= 0 || !validSealedTaskDigest(r.Digest) || seen[r.ArtifactRefID] {
			return nil, ErrSharedTaskSealedReference
		}
		seen[r.ArtifactRefID] = true
		scopes := append([]string(nil), r.Scopes...)
		sort.Strings(scopes)
		foundMeta, foundDigest := false, false
		for j, scope := range scopes {
			if j > 0 && scopes[j-1] == scope {
				return nil, ErrSharedTaskSealedReference
			}
			switch scope {
			case ArtifactRefV2ScopeMetadata:
				foundMeta = true
			case ArtifactRefV2ScopeDigest:
				foundDigest = true
			case ArtifactRefV2ScopeContent:
			default:
				return nil, ErrSharedTaskSealedReference
			}
		}
		if !foundMeta || !foundDigest {
			return nil, ErrSharedTaskSealedReference
		}
		r.Scopes = scopes
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ArtifactRefID < result[j].ArtifactRefID })
	return result, nil
}
func authorizeTaskPeerArtifactsTx(tx *sql.Tx, principalID, groupID string, refs []SharedTaskArtifactRef, at time.Time) error {
	for _, ref := range refs {
		actual, err := authorizeArtifactRefV2Tx(tx, principalID, groupID, ref.ArtifactRefID, ref.Scopes, at)
		if err != nil || actual == nil || actual.Version != ref.Version || actual.Digest != ref.Digest {
			return ErrSharedTaskSealedReference
		}
		var latest int64
		if err = tx.QueryRow(`SELECT MAX(version) FROM artifact_v2_refs WHERE artifact_id=?`, actual.ArtifactID).Scan(&latest); err != nil || latest != ref.Version {
			return ErrSharedTaskSealedReference
		}
	}
	return nil
}
func validSealedTaskDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func loadTaskPeerRefTx(tx *sql.Tx, messageID string) (*SharedTaskSealedRef, error) {
	var encoded string
	err := tx.QueryRow(`SELECT ref_json FROM shared_task_peer_refs_v57 WHERE message_id=?`, messageID).Scan(&encoded)
	if err != nil {
		return nil, err
	}
	var ref SharedTaskSealedRef
	if json.Unmarshal([]byte(encoded), &ref) != nil {
		return nil, ErrSharedTaskSealedReference
	}
	return &ref, nil
}

// Validation is shared by registration, peer reads and acceptance. The actual
// sealed record is authenticated anew; a caller's purpose/digest is insufficient.
func validateTaskPeerRefTx(tx *sql.Tx, task *SharedTask, a *SharedTaskPeerAssignment, ref *SharedTaskSealedRef, at time.Time) error {
	if ref.TaskID != task.ID || ref.GroupID != task.GroupID || ref.AssignmentVersion != a.Version || ref.ContentVersion != a.ContentVersion {
		return ErrSharedTaskSealedReference
	}
	record, err := relaySealedV1RecordTx(tx, ref.MessageID)
	if err != nil || record == nil || record.Security.Digest != ref.MessageDigest || strings.HasPrefix(ref.MessageID, sealedTaskHandoffMessagePrefix) {
		return ErrSharedTaskSealedReference
	}
	pair, _, err := validateQueuedSameGroupSealedV1Tx(tx, record, at)
	if err != nil || record.Route.Kind != "send" || pair.groupID != task.GroupID || pair.sender.EndpointID != ref.SenderEndpointID || pair.receiver.EndpointID != ref.ReaderEndpointID || ref.SealedRoute != sameGroupSealedV1Context(pair, ref.MessageID, "SEND", "", "") {
		return ErrSharedTaskSealedReference
	}
	if _, err = taskPeerScopeTx(tx, task.GroupID, pair.sender, "task.read", at); err != nil {
		return ErrSharedTaskSealedReference
	}
	if _, err = taskPeerScopeTx(tx, task.GroupID, pair.receiver, "task.read", at); err != nil {
		return ErrSharedTaskSealedReference
	}
	switch ref.Purpose {
	case SharedTaskDefinitionPurpose:
		if ref.SenderEndpointID != a.PublisherEndpointID {
			return ErrSharedTaskSealedReference
		}
	case SharedTaskResultPurpose:
		if _, err = taskPeerScopeTx(tx, task.GroupID, pair.sender, "task.submit", at); err != nil {
			return ErrSharedTaskSealedReference
		}
		if ref.ReaderEndpointID != a.ResultRecipientEndpointID || ref.SenderEndpointID != task.OwnerEndpointID || ref.OwnerEpoch != task.OwnerEpoch {
			return ErrSharedTaskSealedReference
		}
	default:
		return ErrSharedTaskSealedReference
	}
	for _, principal := range []string{pair.sender.PrincipalID, pair.receiver.PrincipalID} {
		if err = authorizeTaskPeerArtifactsTx(tx, principal, task.GroupID, ref.ArtifactRefs, at); err != nil {
			return err
		}
	}
	return nil
}
func taskPeerDefinitionAvailableTx(tx *sql.Tx, task *SharedTask, a *SharedTaskPeerAssignment, endpointID string, at time.Time) bool {
	rows, err := tx.Query(`SELECT message_id FROM shared_task_peer_refs_v57 WHERE task_id=? AND purpose=? AND reader_endpoint_id=? AND assignment_version=? AND content_version=? LIMIT 1`, task.ID, SharedTaskDefinitionPurpose, endpointID, a.Version, a.ContentVersion)
	if err != nil {
		return false
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return false
		}
		ids = append(ids, id)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return false
	}
	for _, id := range ids {
		ref, err := loadTaskPeerRefTx(tx, id)
		if err == nil && validateTaskPeerRefTx(tx, task, a, ref, at) == nil {
			return true
		}
	}
	return false
}
func (s *Store) RegisterSharedTaskSealedRefForActor(scope NativeActorScope, input SharedTaskSealedRefInput) (*SharedTaskSealedRef, error) {
	if input.Purpose != SharedTaskDefinitionPurpose && input.Purpose != SharedTaskResultPurpose || !validSameGroupSealedV1Token(input.MessageID) || !validSealedTaskDigest(input.MessageDigest) || input.ExpectedRevision <= 0 || input.OwnerEpoch < 0 {
		return nil, ErrSharedTaskSealedReference
	}
	refs, err := canonicalTaskPeerArtifacts(input.ArtifactRefs)
	if err != nil {
		return nil, err
	}
	action := "task.read"
	if input.Purpose == SharedTaskResultPurpose {
		action = "task.submit"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if err = guardNativeActorTx(tx, scope, action, at); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, input.TaskID)
	if err != nil || task.GroupID != scope.GroupID {
		return nil, ErrSharedTaskNotFound
	}
	a, err := loadTaskPeerAssignmentTx(tx, task.ID, at)
	if err != nil {
		return nil, err
	}
	record, err := relaySealedV1RecordTx(tx, input.MessageID)
	if err != nil || record == nil {
		return nil, ErrSharedTaskSealedReference
	}
	pair, _, err := validateQueuedSameGroupSealedV1Tx(tx, record, at)
	if err != nil || record.Route.Kind != "send" {
		return nil, ErrSharedTaskSealedReference
	}
	ref := &SharedTaskSealedRef{TaskID: task.ID, GroupID: task.GroupID, Purpose: input.Purpose, AssignmentVersion: input.AssignmentVersion, ContentVersion: input.ContentVersion, TaskRevision: input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch, MessageID: input.MessageID, MessageDigest: input.MessageDigest, SenderEndpointID: scope.EndpointID, ReaderEndpointID: record.Route.ReceiverEndpointID, ArtifactRefs: refs}
	ref.SealedRoute = sameGroupSealedV1Context(pair, ref.MessageID, "SEND", "", "")
	if err = validateTaskPeerRefTx(tx, task, a, ref, at); err != nil {
		return nil, err
	}
	existing, findErr := loadTaskPeerRefTx(tx, input.MessageID)
	if findErr == nil {
		ref.ResultID = existing.ResultID
		if !reflect.DeepEqual(existing, ref) {
			return nil, ErrSharedTaskSealedReference
		}
		if ref.Purpose == SharedTaskResultPurpose {
			var authority string
			if tx.QueryRow(`SELECT authority FROM shared_task_v2_results WHERE id=? AND task_id=?`, ref.ResultID, task.ID).Scan(&authority) != nil || authority != "PENDING" && authority != "ACCEPTED" {
				return nil, ErrSharedTaskSealedReference
			}
		}
		// Read-only idempotent retry. Rollback the write guard touched in this tx.
		return existing, nil
	}
	if !errors.Is(findErr, sql.ErrNoRows) {
		return nil, findErr
	}
	if task.Revision != input.ExpectedRevision || task.OwnerEpoch != input.OwnerEpoch {
		return nil, ErrSharedTaskStaleOwner
	}
	if ref.Purpose == SharedTaskResultPurpose {
		if task.OwnerPrincipalID != scope.PrincipalID || task.OwnerEndpointID != scope.EndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) || !taskPeerDefinitionAvailableTx(tx, task, a, scope.EndpointID, at) || len(ref.ArtifactRefs) == 0 {
			return nil, ErrSharedTaskStaleOwner
		}
		ref.ResultID = NewID("result")
		_, err = tx.Exec(`INSERT INTO shared_task_v2_results(id,task_id,submitter_principal_id,submitter_endpoint_id,owner_epoch,summary,evidence_json,authority,created_at) VALUES(?,?,?,?,?,'','[]','PENDING',?)`, ref.ResultID, task.ID, scope.PrincipalID, scope.EndpointID, task.OwnerEpoch, now())
		if err != nil {
			return nil, err
		}
		update, err := tx.Exec(`UPDATE shared_tasks_v2 SET status=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=?`, SharedTaskResultSubmitted, now(), task.ID, input.ExpectedRevision, input.OwnerEpoch)
		if err != nil {
			return nil, err
		}
		n, _ := update.RowsAffected()
		if n != 1 {
			return nil, ErrSharedTaskConflict
		}
		task.Revision++
		task.Status = SharedTaskResultSubmitted
	}
	if ref.Purpose == SharedTaskDefinitionPurpose {
		var occupied string
		findErr := tx.QueryRow(`SELECT message_id FROM shared_task_peer_refs_v57 WHERE task_id=? AND purpose=? AND reader_endpoint_id=? AND assignment_version=? AND content_version=?`, task.ID, ref.Purpose, ref.ReaderEndpointID, ref.AssignmentVersion, ref.ContentVersion).Scan(&occupied)
		if findErr == nil {
			return nil, ErrSharedTaskSealedReference
		}
		if !errors.Is(findErr, sql.ErrNoRows) {
			return nil, findErr
		}
	}
	encoded, _ := json.Marshal(ref)
	_, err = tx.Exec(`INSERT INTO shared_task_peer_refs_v57(message_id,task_id,purpose,reader_endpoint_id,content_version,assignment_version,result_id,ref_json) VALUES(?,?,?,?,?,?,?,?)`, ref.MessageID, ref.TaskID, ref.Purpose, ref.ReaderEndpointID, ref.ContentVersion, ref.AssignmentVersion, ref.ResultID, string(encoded))
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "SEALED_BODY_REGISTERED", scope.PrincipalID, map[string]string{"purpose": ref.Purpose, "message_id": ref.MessageID, "result_id": ref.ResultID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return ref, nil
}
func authorizeTaskPeerAcceptanceTx(tx *sql.Tx, task *SharedTask, resultID string, scope NativeActorScope, at time.Time) error {
	a, err := loadTaskPeerAssignmentTx(tx, task.ID, at)
	if err != nil {
		return err
	}
	if scope.EndpointID != a.ResultRecipientEndpointID {
		return ErrSharedTaskSealedReference
	}
	var messageID string
	if tx.QueryRow(`SELECT message_id FROM shared_task_peer_refs_v57 WHERE task_id=? AND result_id=? AND purpose=?`, task.ID, resultID, SharedTaskResultPurpose).Scan(&messageID) != nil {
		return ErrSharedTaskSealedReference
	}
	ref, err := loadTaskPeerRefTx(tx, messageID)
	if err != nil {
		return ErrSharedTaskSealedReference
	}
	if err = validateTaskPeerRefTx(tx, task, a, ref, at); err != nil {
		return err
	}
	if len(ref.ArtifactRefs) == 0 {
		return ErrSharedTaskSealedReference
	}
	return authorizeTaskPeerArtifactsTx(tx, scope.PrincipalID, task.GroupID, ref.ArtifactRefs, at)
}
func (s *Store) GetSharedTaskPeerForActor(scope NativeActorScope, taskID, action string) (*SharedTaskPeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err = guardNativeActorTx(tx, scope, action, at); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, taskID)
	if err != nil || task.GroupID != scope.GroupID {
		return nil, ErrSharedTaskNotFound
	}
	view := ProjectSharedTaskPeer(task)
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM shared_task_peer_assignments_v57 WHERE task_id=?`, taskID).Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		view.DefinitionStatus = "MANAGEMENT_ONLY"
		return view, nil
	}
	a, err := loadTaskPeerAssignmentTx(tx, taskID, at)
	if err != nil {
		return view, nil
	}
	view.Assignment = a
	if guardNativeActorTx(tx, scope, "task.read", at) != nil {
		return view, nil
	}
	rows, err := tx.Query(`SELECT message_id FROM shared_task_peer_refs_v57 WHERE task_id=? AND reader_endpoint_id=? AND assignment_version=? AND content_version=? ORDER BY message_id LIMIT 33`, taskID, scope.EndpointID, a.Version, a.ContentVersion)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		ref, err := loadTaskPeerRefTx(tx, id)
		if err != nil || validateTaskPeerRefTx(tx, task, a, ref, at) != nil {
			continue
		}
		if ref.Purpose == SharedTaskDefinitionPurpose {
			view.DefinitionRefs = append(view.DefinitionRefs, *ref)
			view.DefinitionStatus = "REGISTERED"
		} else {
			view.ResultRefs = append(view.ResultRefs, *ref)
		}
	}
	return view, nil
}
