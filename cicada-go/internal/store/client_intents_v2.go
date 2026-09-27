package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	ClientIntentQueued    = "QUEUED"
	ClientIntentRunning   = "RUNNING"
	ClientIntentDone      = "DONE"
	ClientIntentUncertain = "UNCERTAIN"
)

var (
	ErrClientIntentNotFound = errors.New("Client intent not found")
	ErrClientIntentConflict = errors.New("Client request ID was already used for a different intent")
	ErrClientIntentState    = errors.New("invalid Client intent state transition")
)

// ClientIntent is the durable asynchronous acceptance record. Input is stored
// by Hub Control for later execution and deliberately omitted from generic JSON
// responses because it can contain user text and Goal details.
type ClientIntent struct {
	IntentID        string          `json:"intent_id"`
	OwnerID         string          `json:"-"`
	ClientRequestID string          `json:"client_request_id"`
	Input           json.RawMessage `json:"-"`
	State           string          `json:"state"`
	Error           string          `json:"error,omitempty"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
	StartedAt       string          `json:"started_at,omitempty"`
	FinishedAt      string          `json:"finished_at,omitempty"`
}

func (s *Store) initializeClientControlIntentsV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS client_control_intents_v2 (
  client_request_id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL UNIQUE,
  input_json BLOB NOT NULL CHECK(length(input_json) > 0),
  state TEXT NOT NULL CHECK(state IN ('QUEUED', 'RUNNING', 'DONE', 'UNCERTAIN')),
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  FOREIGN KEY(intent_id) REFERENCES intents(id)
);
CREATE INDEX IF NOT EXISTS client_control_intents_v2_state_idx
  ON client_control_intents_v2(state, created_at, intent_id);`)
	if err != nil {
		return fmt.Errorf("initialize durable Client Control intents: %w", err)
	}
	return nil
}

// AcceptClientIntent creates the normal durable Intent and its full Client
// input in the same transaction. Reusing a request ID with the same input
// returns the original Intent; reusing it with different content is rejected.
// The bool reports whether this call created a new accepted operation.
func (s *Store) AcceptClientIntent(
	clientRequestID, text, requestedKind, targetID string,
	attachments []string, inputJSON []byte,
) (*Intent, bool, error) {
	return s.acceptClientIntent("", clientRequestID, text, requestedKind, targetID, attachments, inputJSON)
}

// AcceptClientIntentForOwner is used only after the Hub has authenticated an
// encrypted Client device session. The owner is supplied by that session,
// never by request JSON.
func (s *Store) AcceptClientIntentForOwner(
	ownerID, clientRequestID, text, requestedKind, targetID string,
	attachments []string, inputJSON []byte,
) (*Intent, bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, false, errors.New("authenticated Client owner is required")
	}
	return s.acceptClientIntent(ownerID, clientRequestID, text, requestedKind, targetID, attachments, inputJSON)
}

func (s *Store) acceptClientIntent(
	ownerID, clientRequestID, text, requestedKind, targetID string,
	attachments []string, inputJSON []byte,
) (*Intent, bool, error) {
	clientRequestID = strings.TrimSpace(clientRequestID)
	text = strings.TrimSpace(text)
	if clientRequestID == "" || len(clientRequestID) > 256 || text == "" || len(inputJSON) == 0 || len(inputJSON) > 256*1024 || !json.Valid(inputJSON) {
		return nil, false, errors.New("Client intent acceptance is invalid")
	}
	if requestedKind == "" {
		requestedKind = "auto"
	}
	encodedAttachments, err := json.Marshal(attachments)
	if err != nil {
		return nil, false, fmt.Errorf("encode Client intent attachments: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	stamp := now()
	intentID := NewID("intent")
	if _, err := tx.Exec(`INSERT INTO intents
(id, text, requested_kind, resolved_kind, status, target_id, attachments_json, result_json, question, error, created_at, updated_at)
VALUES (?, ?, ?, '', 'pending', ?, ?, '{}', '', '', ?, ?)`, intentID, text,
		requestedKind, strings.TrimSpace(targetID), string(encodedAttachments), stamp, stamp); err != nil {
		return nil, false, fmt.Errorf("create accepted Client intent: %w", err)
	}
	inserted, err := tx.Exec(`INSERT INTO client_control_intents_v2
(client_request_id, intent_id, input_json, state, error, created_at, updated_at, owner_id)
VALUES (?, ?, ?, 'QUEUED', '', ?, ?, ?)
ON CONFLICT(client_request_id) DO NOTHING`, clientRequestID, intentID, inputJSON, stamp, stamp, ownerID)
	if err != nil {
		return nil, false, fmt.Errorf("persist accepted Client intent: %w", err)
	}
	created, err := inserted.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if created == 0 {
		// Roll back the unused normal Intent before reading the prior operation,
		// so an idempotent retry cannot leave an orphan row in intents.
		if err := tx.Rollback(); err != nil {
			return nil, false, err
		}
		prior, err := readClientIntent(s.db.QueryRow(`SELECT client_request_id, intent_id,
input_json, state, error, created_at, updated_at, started_at, finished_at, owner_id
FROM client_control_intents_v2 WHERE client_request_id = ?`, clientRequestID))
		if err != nil {
			return nil, false, err
		}
		if prior.OwnerID != ownerID || !equalClientIntentInput(prior.Input, inputJSON) {
			return nil, false, ErrClientIntentConflict
		}
		intent, err := s.getIntentLocked(prior.IntentID)
		if err != nil {
			return nil, false, err
		}
		if intent == nil {
			return nil, false, ErrClientIntentNotFound
		}
		return intent, false, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	intent, err := s.getIntentLocked(intentID)
	if err != nil {
		return nil, false, err
	}
	if intent == nil {
		return nil, false, ErrClientIntentNotFound
	}
	return intent, true, nil
}

func (s *Store) GetClientIntent(intentID string) (*ClientIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readClientIntent(s.db.QueryRow(`SELECT client_request_id, intent_id,
input_json, state, error, created_at, updated_at, started_at, finished_at, owner_id
FROM client_control_intents_v2 WHERE intent_id = ?`, strings.TrimSpace(intentID)))
}

func (s *Store) GetClientIntentForOwner(ownerID, intentID string) (*Intent, error) {
	ownerID = strings.TrimSpace(ownerID)
	intentID = strings.TrimSpace(intentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	var intentOwnerID string
	err := s.db.QueryRow(`SELECT owner_id FROM client_control_intents_v2 WHERE intent_id=?`, intentID).Scan(&intentOwnerID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (intentOwnerID == "" || intentOwnerID != ownerID)) {
		return nil, ErrClientIntentNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.getIntentLocked(intentID)
}

func (s *Store) ListClientIntentsForOwner(ownerID, status string) ([]Intent, error) {
	ownerID = strings.TrimSpace(ownerID)
	status = strings.TrimSpace(status)
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT intent.id FROM client_control_intents_v2 client_job
JOIN intents intent ON intent.id=client_job.intent_id
WHERE client_job.owner_id=? AND client_job.owner_id<>''`
	args := []any{ownerID}
	if status != "" {
		query += ` AND intent.status=?`
		args = append(args, status)
	}
	query += ` ORDER BY intent.created_at DESC, intent.id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	intents := make([]Intent, 0, len(ids))
	for _, id := range ids {
		intent, err := s.getIntentLocked(id)
		if err != nil {
			return nil, err
		}
		if intent != nil {
			intents = append(intents, *intent)
		}
	}
	return intents, nil
}

// ClaimClientIntent atomically gives one dispatcher ownership of a QUEUED
// operation. A concurrent or repeated claim observes the existing state and
// receives claimed=false.
func (s *Store) ClaimClientIntent(intentID string) (*ClientIntent, bool, error) {
	intentID = strings.TrimSpace(intentID)
	if intentID == "" {
		return nil, false, ErrClientIntentNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := now()
	result, err := s.db.Exec(`UPDATE client_control_intents_v2 SET state = 'RUNNING',
started_at = ?, updated_at = ? WHERE intent_id = ? AND state = 'QUEUED'`, stamp, stamp, intentID)
	if err != nil {
		return nil, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	intent, err := readClientIntent(s.db.QueryRow(`SELECT client_request_id, intent_id,
input_json, state, error, created_at, updated_at, started_at, finished_at, owner_id
FROM client_control_intents_v2 WHERE intent_id = ?`, intentID))
	if err != nil {
		return nil, false, err
	}
	return intent, changed == 1, nil
}

func (s *Store) CompleteClientIntent(intentID string) error {
	return s.transitionClientIntent(intentID, ClientIntentDone, "")
}

func (s *Store) MarkClientIntentUncertain(intentID, reason string) error {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	return s.transitionClientIntent(intentID, ClientIntentUncertain, reason)
}

func (s *Store) transitionClientIntent(intentID, nextState, reason string) error {
	if nextState != ClientIntentDone && nextState != ClientIntentUncertain {
		return ErrClientIntentState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := now()
	result, err := s.db.Exec(`UPDATE client_control_intents_v2 SET state = ?, error = ?,
finished_at = ?, updated_at = ? WHERE intent_id = ? AND state = 'RUNNING'`,
		nextState, reason, stamp, stamp, strings.TrimSpace(intentID))
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return ErrClientIntentState
	}
	return nil
}

// RecoverClientIntents fences operations left RUNNING by a prior process. A
// terminal legacy Intent is sufficient evidence that Control durably recorded
// its result, so it is reconciled to DONE. A still-pending Intent stays
// UNCERTAIN because its side effect may have happened before the crash. Only
// QUEUED work is returned for dispatch.
func (s *Store) RecoverClientIntents() ([]ClientIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now()
	if _, err := tx.Exec(`UPDATE client_control_intents_v2 SET state = 'DONE',
finished_at = ?, updated_at = ? WHERE state = 'RUNNING' AND intent_id IN
(SELECT id FROM intents WHERE status IN ('resolved', 'needs_input', 'failed'))`, stamp, stamp); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE client_control_intents_v2 SET state = 'UNCERTAIN',
error = 'Control restarted while the intent outcome was not durably recorded',
finished_at = ?, updated_at = ? WHERE state = 'RUNNING'`, stamp, stamp); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT client_request_id, intent_id, input_json, state, error,
created_at, updated_at, started_at, finished_at, owner_id FROM client_control_intents_v2
WHERE state = 'QUEUED' ORDER BY created_at, intent_id`)
	if err != nil {
		return nil, err
	}
	queued, scanErr := readClientIntentRows(rows)
	closeErr := rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return queued, nil
}

func readClientIntent(row interface{ Scan(...any) error }) (*ClientIntent, error) {
	var intent ClientIntent
	var input []byte
	var startedAt, finishedAt sql.NullString
	err := row.Scan(&intent.ClientRequestID, &intent.IntentID, &input, &intent.State,
		&intent.Error, &intent.CreatedAt, &intent.UpdatedAt, &startedAt, &finishedAt, &intent.OwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientIntentNotFound
	}
	if err != nil {
		return nil, err
	}
	intent.Input = append(json.RawMessage(nil), input...)
	if startedAt.Valid {
		intent.StartedAt = startedAt.String
	}
	if finishedAt.Valid {
		intent.FinishedAt = finishedAt.String
	}
	return &intent, nil
}

func readClientIntentRows(rows *sql.Rows) ([]ClientIntent, error) {
	items := make([]ClientIntent, 0)
	for rows.Next() {
		intent, err := readClientIntent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *intent)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func equalClientIntentInput(left, right []byte) bool {
	var leftJSON, rightJSON any
	if json.Unmarshal(left, &leftJSON) != nil || json.Unmarshal(right, &rightJSON) != nil {
		return false
	}
	leftCanonical, leftErr := json.Marshal(leftJSON)
	rightCanonical, rightErr := json.Marshal(rightJSON)
	return leftErr == nil && rightErr == nil && string(leftCanonical) == string(rightCanonical)
}
