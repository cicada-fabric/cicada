package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ClientStatusChangePresent   = "present"
	ClientStatusChangeUpdated   = "updated"
	ClientStatusChangeRemoved   = "removed"
	maxClientStatusObservations = 5000
	maxClientStatusStateBytes   = 16 * 1024
)

var (
	ErrClientStatusOwnerRequired = errors.New("client status owner is required")
	ErrClientStatusCursorRange   = errors.New("client status cursor is beyond this owner's event stream")
)

// ClientStatusObservation contains only a Control-generated, allowlisted
// status/topology projection. It must never contain arbitrary legacy event
// payloads, prompts, logs, credentials, or peer message bodies.
type ClientStatusObservation struct {
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	StateJSON  json.RawMessage `json:"state"`
}

// ClientStatusChangeEvent is a durable, owner-filtered metadata delta. State
// is produced by Control from its typed status snapshot, not copied from the
// older free-form events table.
type ClientStatusChangeEvent struct {
	ID         int64           `json:"id"`
	ChangeType string          `json:"change_type"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	StateJSON  json.RawMessage `json:"state"`
	ObservedAt string          `json:"observed_at"`
	CreatedAt  string          `json:"created_at"`
}

var clientStatusEntityTypes = map[string]struct{}{
	"node": {}, "endpoint": {}, "worker": {}, "goal": {}, "group": {}, "task": {},
}

// initializeClientStatusEventsV2Schema is registered by the v2.21 migration.
// It creates a compact latest-state index and an append-only change stream;
// legacy event history is intentionally not imported because its JSON payload
// can contain prompts, results, errors, or peer message content.
func (s *Store) initializeClientStatusEventsV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS client_status_state_v2 (
  owner_principal_id TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK(entity_type IN ('node','endpoint','worker','goal','group','task')),
  entity_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  present INTEGER NOT NULL CHECK(present IN (0,1)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY(owner_principal_id, entity_type, entity_id)
);
CREATE TABLE IF NOT EXISTS client_status_streams_v2 (
  owner_principal_id TEXT PRIMARY KEY,
  last_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_sequence >= 0)
);
CREATE TABLE IF NOT EXISTS client_status_change_events_v2 (
	  id INTEGER NOT NULL CHECK(id > 0),
  owner_principal_id TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK(change_type IN ('present','updated','removed')),
  entity_type TEXT NOT NULL CHECK(entity_type IN ('node','endpoint','worker','goal','group','task')),
  entity_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
	  created_at TEXT NOT NULL,
	  PRIMARY KEY(owner_principal_id,id)
);
`)
	return err
}

// RecordClientStatusObservations reconciles one full observation of the
// supplied entity types. The whole diff and latest-state update commit
// atomically, so a process restart can resume from the returned event ID.
// observedAt is the stable capture time from Control's typed snapshot.
func (s *Store) RecordClientStatusObservations(ownerID, observedAt string, coveredTypes []string, observations []ClientStatusObservation) error {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return ErrClientStatusOwnerRequired
	}
	captured, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(observedAt))
	if err != nil {
		return errors.New("client status observed_at must be RFC3339Nano")
	}
	observedAt = captured.UTC().Format(time.RFC3339Nano)
	covered := make(map[string]struct{}, len(coveredTypes))
	for _, entityType := range coveredTypes {
		entityType = strings.TrimSpace(entityType)
		if _, allowed := clientStatusEntityTypes[entityType]; !allowed {
			return fmt.Errorf("unsupported Client status entity type %q", entityType)
		}
		covered[entityType] = struct{}{}
	}
	if len(covered) == 0 {
		return errors.New("at least one Client status entity type must be covered")
	}
	if len(observations) > maxClientStatusObservations {
		return fmt.Errorf("Client status observation count exceeds %d", maxClientStatusObservations)
	}
	current := make(map[string]ClientStatusObservation, len(observations))
	for _, observation := range observations {
		observation.EntityType = strings.TrimSpace(observation.EntityType)
		observation.EntityID = strings.TrimSpace(observation.EntityID)
		if _, allowed := covered[observation.EntityType]; !allowed || observation.EntityID == "" {
			return errors.New("Client status observation is outside the covered entity set")
		}
		if len(observation.StateJSON) == 0 || len(observation.StateJSON) > maxClientStatusStateBytes || !json.Valid(observation.StateJSON) {
			return errors.New("Client status state must be valid bounded JSON")
		}
		key := observation.EntityType + "\x00" + observation.EntityID
		if _, duplicate := current[key]; duplicate {
			return errors.New("duplicate Client status entity observation")
		}
		observation.StateJSON = append(json.RawMessage(nil), observation.StateJSON...)
		current[key] = observation
	}

	keys := make([]string, 0, len(current))
	for key := range current {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	for _, key := range keys {
		observation := current[key]
		var previousJSON, previousObserved string
		var previousPresent int
		readErr := tx.QueryRow(`SELECT state_json,present,observed_at FROM client_status_state_v2
WHERE owner_principal_id=? AND entity_type=? AND entity_id=?`, ownerID, observation.EntityType, observation.EntityID).
			Scan(&previousJSON, &previousPresent, &previousObserved)
		changeType := ClientStatusChangePresent
		if errors.Is(readErr, sql.ErrNoRows) {
			if _, err := tx.Exec(`INSERT INTO client_status_state_v2
(owner_principal_id,entity_type,entity_id,state_json,present,observed_at) VALUES(?,?,?,?,1,?)`,
				ownerID, observation.EntityType, observation.EntityID, string(observation.StateJSON), observedAt); err != nil {
				return rollback(err)
			}
		} else if readErr != nil {
			return rollback(readErr)
		} else {
			previousTime, parseErr := time.Parse(time.RFC3339Nano, previousObserved)
			if parseErr != nil {
				return rollback(fmt.Errorf("read stored Client status observed_at: %w", parseErr))
			}
			if captured.Before(previousTime) || captured.Equal(previousTime) {
				// A stale or same-time concurrent snapshot cannot overwrite a
				// newer observation with an ambiguous read order.
				continue
			}
			if previousPresent == 0 {
				changeType = ClientStatusChangePresent
			} else if previousJSON == string(observation.StateJSON) {
				if _, err := tx.Exec(`UPDATE client_status_state_v2 SET observed_at=?
WHERE owner_principal_id=? AND entity_type=? AND entity_id=?`, observedAt, ownerID, observation.EntityType, observation.EntityID); err != nil {
					return rollback(err)
				}
				continue
			} else {
				changeType = ClientStatusChangeUpdated
			}
			if _, err := tx.Exec(`UPDATE client_status_state_v2 SET state_json=?,present=1,observed_at=?
WHERE owner_principal_id=? AND entity_type=? AND entity_id=?`, string(observation.StateJSON), observedAt, ownerID, observation.EntityType, observation.EntityID); err != nil {
				return rollback(err)
			}
		}
		if err := appendClientStatusChangeTx(tx, ownerID, changeType, observation.EntityType, observation.EntityID, observation.StateJSON, observedAt); err != nil {
			return rollback(err)
		}
	}

	coveredList := make([]string, 0, len(covered))
	for entityType := range covered {
		coveredList = append(coveredList, entityType)
	}
	sort.Strings(coveredList)
	for _, entityType := range coveredList {
		rows, err := tx.Query(`SELECT entity_id,observed_at FROM client_status_state_v2
WHERE owner_principal_id=? AND entity_type=? AND present=1`, ownerID, entityType)
		if err != nil {
			return rollback(err)
		}
		type stateRow struct{ id, observedAt string }
		stale := make([]stateRow, 0)
		for rows.Next() {
			var row stateRow
			if err := rows.Scan(&row.id, &row.observedAt); err != nil {
				_ = rows.Close()
				return rollback(err)
			}
			if _, present := current[entityType+"\x00"+row.id]; !present {
				previousTime, parseErr := time.Parse(time.RFC3339Nano, row.observedAt)
				if parseErr != nil {
					_ = rows.Close()
					return rollback(fmt.Errorf("read stored Client status observed_at: %w", parseErr))
				}
				if !captured.Before(previousTime) && !captured.Equal(previousTime) {
					stale = append(stale, row)
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		if err := rows.Close(); err != nil {
			return rollback(err)
		}
		for _, row := range stale {
			state := json.RawMessage(`{}`)
			if _, err := tx.Exec(`UPDATE client_status_state_v2 SET state_json='{}',present=0,observed_at=?
WHERE owner_principal_id=? AND entity_type=? AND entity_id=? AND present=1`, observedAt, ownerID, entityType, row.id); err != nil {
				return rollback(err)
			}
			if err := appendClientStatusChangeTx(tx, ownerID, ClientStatusChangeRemoved, entityType, row.id, state, observedAt); err != nil {
				return rollback(err)
			}
		}
	}
	return tx.Commit()
}

func appendClientStatusChangeTx(tx *sql.Tx, ownerID, changeType, entityType, entityID string, state json.RawMessage, observedAt string) error {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO client_status_streams_v2(owner_principal_id,last_sequence) VALUES(?,0)`, ownerID); err != nil {
		return err
	}
	var previous int64
	if err := tx.QueryRow(`SELECT last_sequence FROM client_status_streams_v2 WHERE owner_principal_id=?`, ownerID).Scan(&previous); err != nil {
		return err
	}
	next := previous + 1
	result, err := tx.Exec(`UPDATE client_status_streams_v2 SET last_sequence=? WHERE owner_principal_id=? AND last_sequence=?`, next, ownerID, previous)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return errors.New("Client status owner sequence changed concurrently")
	}
	_, err = tx.Exec(`INSERT INTO client_status_change_events_v2
(id,owner_principal_id,change_type,entity_type,entity_id,state_json,observed_at,created_at)
VALUES(?,?,?,?,?,?,?,?)`, next, ownerID, changeType, entityType, entityID, string(state), observedAt, now())
	return err
}

func (s *Store) LatestClientStatusChangeID(ownerID string) (int64, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return 0, ErrClientStatusOwnerRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest int64
	err := s.db.QueryRow(`SELECT COALESCE((SELECT last_sequence FROM client_status_streams_v2 WHERE owner_principal_id=?),0)`, ownerID).Scan(&latest)
	return latest, err
}

func (s *Store) ListClientStatusChanges(ownerID string, afterID int64, limit int) ([]ClientStatusChangeEvent, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, ErrClientStatusOwnerRequired
	}
	if afterID < 0 {
		return nil, errors.New("Client status cursor id cannot be negative")
	}
	if limit <= 0 || limit > 500 {
		return nil, errors.New("Client status change limit must be between 1 and 500")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,change_type,entity_type,entity_id,state_json,observed_at,created_at
FROM client_status_change_events_v2 WHERE owner_principal_id=? AND id>? ORDER BY id LIMIT ?`, ownerID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]ClientStatusChangeEvent, 0)
	for rows.Next() {
		var event ClientStatusChangeEvent
		var state string
		if err := rows.Scan(&event.ID, &event.ChangeType, &event.EntityType, &event.EntityID, &state, &event.ObservedAt, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.StateJSON = json.RawMessage(state)
		events = append(events, event)
	}
	return events, rows.Err()
}
