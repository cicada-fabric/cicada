package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

func (s *Store) CreateExternalEvent(event ExternalEvent) (*ExternalEvent, error) {
	if event.ID == "" {
		event.ID = NewID("event")
	}
	if event.Connector == "" || event.ExternalID == "" || event.EventType == "" {
		return nil, errors.New("connector, external_id, and event_type are required")
	}
	if !json.Valid(event.Payload) {
		return nil, errors.New("external event payload must be valid JSON")
	}
	if event.Status == "" {
		event.Status = "received"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO external_events
(id, connector, external_id, event_type, payload_json, signature, status, goal_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, event.ID, event.Connector, event.ExternalID, event.EventType,
		string(event.Payload), event.Signature, event.Status, nullableString(event.GoalID), timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create external event: %w", err)
	}
	return s.getExternalEventLocked(event.ID)
}

func (s *Store) GetExternalEvent(id string) (*ExternalEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getExternalEventLocked(id)
}

func (s *Store) GetExternalEventByKey(connector, externalID string) (*ExternalEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(`SELECT id FROM external_events WHERE connector = ? AND external_id = ?`, connector, externalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getExternalEventLocked(id)
}

func (s *Store) ListExternalEvents(connector string) ([]ExternalEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM external_events ORDER BY created_at DESC`
	args := []any{}
	if connector != "" {
		query = `SELECT id FROM external_events WHERE connector = ? ORDER BY created_at DESC`
		args = append(args, connector)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var result []ExternalEvent
	for _, id := range ids {
		event, err := s.getExternalEventLocked(id)
		if err != nil {
			return nil, err
		}
		if event != nil {
			result = append(result, *event)
		}
	}
	return result, rows.Err()
}

func (s *Store) UpdateExternalEventStatus(id, status string) (*ExternalEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE external_events SET status = ?, updated_at = ? WHERE id = ?`, status, now(), id)
	if err != nil {
		return nil, err
	}
	return s.getExternalEventLocked(id)
}

func (s *Store) getExternalEventLocked(id string) (*ExternalEvent, error) {
	var event ExternalEvent
	var payload, signature, goalID sql.NullString
	err := s.db.QueryRow(`SELECT id, connector, external_id, event_type, payload_json, signature, status, goal_id, created_at, updated_at
FROM external_events WHERE id = ?`, id).Scan(&event.ID, &event.Connector, &event.ExternalID, &event.EventType,
		&payload, &signature, &event.Status, &goalID, &event.CreatedAt, &event.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	event.Payload = json.RawMessage(payload.String)
	event.Signature, event.GoalID = signature.String, goalID.String
	return &event, nil
}
