package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type EndpointFilter struct {
	Status    string
	MachineID string
	Owner     string
	Harness   string
	Limit     int
}

func (s *Store) UpsertEndpoint(endpoint Endpoint) (*Endpoint, error) {
	endpoint.ID = strings.TrimSpace(endpoint.ID)
	endpoint.Name = strings.TrimSpace(endpoint.Name)
	endpoint.Harness = strings.TrimSpace(endpoint.Harness)
	endpoint.NativeSessionID = strings.TrimSpace(endpoint.NativeSessionID)
	if endpoint.ID == "" {
		endpoint.ID = NewID("ep")
	}
	if endpoint.Name == "" || endpoint.Harness == "" {
		return nil, errors.New("endpoint name and harness are required")
	}
	if endpoint.Role == "" {
		endpoint.Role = "thread"
	}
	if endpoint.Status == "" {
		endpoint.Status = "online"
	}
	if endpoint.Visibility == "" {
		endpoint.Visibility = "private"
	}
	if endpoint.Capabilities == nil {
		endpoint.Capabilities = map[string]any{}
	}
	if endpoint.Tags == nil {
		endpoint.Tags = []string{}
	}
	capabilitiesJSON, err := json.Marshal(endpoint.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint capabilities: %w", err)
	}
	tagsJSON, err := json.Marshal(endpoint.Tags)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint tags: %w", err)
	}
	timestamp := now()
	if endpoint.JoinedAt == "" {
		endpoint.JoinedAt = timestamp
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// A native session can rejoin without learning its old endpoint ID. Resolve
	// that binding first so the endpoint identity remains stable.
	if endpoint.NativeSessionID != "" {
		var existingID string
		err := s.db.QueryRow(`SELECT id FROM fabric_endpoints WHERE harness = ? AND native_session_id = ?`, endpoint.Harness, endpoint.NativeSessionID).Scan(&existingID)
		if err == nil {
			endpoint.ID = existingID
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	_, err = s.db.Exec(`INSERT INTO fabric_endpoints
(id, name, role, harness, native_session_id, machine_id, workspace, goal_id, status,
 capabilities_json, tags_json, owner, visibility, joined_at, last_seen, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
 name=excluded.name, role=excluded.role, harness=excluded.harness,
 native_session_id=excluded.native_session_id, machine_id=excluded.machine_id,
 workspace=excluded.workspace, goal_id=excluded.goal_id, status=excluded.status,
 capabilities_json=excluded.capabilities_json, tags_json=excluded.tags_json,
 owner=excluded.owner, visibility=excluded.visibility, last_seen=excluded.last_seen,
 updated_at=excluded.updated_at`, endpoint.ID, endpoint.Name, endpoint.Role,
		endpoint.Harness, endpoint.NativeSessionID, endpoint.MachineID, endpoint.Workspace,
		endpoint.GoalID, endpoint.Status, string(capabilitiesJSON), string(tagsJSON),
		endpoint.Owner, endpoint.Visibility, endpoint.JoinedAt, timestamp, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert fabric endpoint: %w", err)
	}
	return s.getEndpointLocked(endpoint.ID)
}

func scanEndpoint(scanner interface{ Scan(...any) error }) (*Endpoint, error) {
	var endpoint Endpoint
	var capabilitiesJSON, tagsJSON string
	err := scanner.Scan(&endpoint.ID, &endpoint.Name, &endpoint.Role, &endpoint.Harness,
		&endpoint.NativeSessionID, &endpoint.MachineID, &endpoint.Workspace, &endpoint.GoalID,
		&endpoint.Status, &capabilitiesJSON, &tagsJSON, &endpoint.Owner, &endpoint.Visibility,
		&endpoint.JoinedAt, &endpoint.LastSeen, &endpoint.CreatedAt, &endpoint.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(capabilitiesJSON), &endpoint.Capabilities); err != nil {
		return nil, fmt.Errorf("decode endpoint capabilities: %w", err)
	}
	if err := json.Unmarshal([]byte(tagsJSON), &endpoint.Tags); err != nil {
		return nil, fmt.Errorf("decode endpoint tags: %w", err)
	}
	return &endpoint, nil
}

const endpointColumns = `id, name, role, harness, native_session_id, machine_id,
workspace, goal_id, status, capabilities_json, tags_json, owner, visibility,
joined_at, last_seen, created_at, updated_at`

func (s *Store) getEndpointLocked(id string) (*Endpoint, error) {
	return scanEndpoint(s.db.QueryRow(`SELECT `+endpointColumns+` FROM fabric_endpoints WHERE id = ?`, id))
}

func (s *Store) GetEndpoint(id string) (*Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getEndpointLocked(strings.TrimSpace(id))
}

func (s *Store) GetEndpointBySession(harness, nativeSessionID string) (*Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanEndpoint(s.db.QueryRow(`SELECT `+endpointColumns+` FROM fabric_endpoints
WHERE harness = ? AND native_session_id = ?`, strings.TrimSpace(harness), strings.TrimSpace(nativeSessionID)))
}

func (s *Store) ListEndpoints(filter EndpointFilter) ([]Endpoint, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT ` + endpointColumns + ` FROM fabric_endpoints WHERE 1=1`
	args := make([]any, 0, 5)
	for _, item := range []struct {
		value  string
		column string
	}{{filter.Status, "status"}, {filter.MachineID, "machine_id"}, {filter.Owner, "owner"}, {filter.Harness, "harness"}} {
		if value := strings.TrimSpace(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Endpoint, 0)
	for rows.Next() {
		endpoint, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *endpoint)
	}
	return result, rows.Err()
}

func (s *Store) TouchEndpoint(id, status string) (*Endpoint, error) {
	id = strings.TrimSpace(id)
	status = strings.TrimSpace(status)
	if status == "" {
		status = "online"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	result, err := s.db.Exec(`UPDATE fabric_endpoints SET status = ?, last_seen = ?, updated_at = ? WHERE id = ?`, status, timestamp, timestamp, id)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return nil, nil
	}
	return s.getEndpointLocked(id)
}

func (s *Store) MarkStaleEndpoints(cutoff string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM fabric_endpoints WHERE last_seen < ? AND status NOT IN ('offline', 'left')`, cutoff)
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
	_, err = s.db.Exec(`UPDATE fabric_endpoints SET status = 'offline', updated_at = ?
WHERE last_seen < ? AND status NOT IN ('offline', 'left')`, now(), cutoff)
	return ids, err
}

func (s *Store) FindWorkerByThreadID(threadID string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(`SELECT id FROM workers WHERE thread_id = ? ORDER BY updated_at DESC LIMIT 1`, strings.TrimSpace(threadID)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getWorkerLocked(id)
}

func (s *Store) CreateFabricMessage(message FabricMessage) (*FabricMessage, error) {
	if strings.TrimSpace(message.ID) == "" {
		message.ID = NewID("msg")
	}
	if message.FromEndpointID == "" || message.ToEndpointID == "" || message.Kind == "" || message.Body == "" {
		return nil, errors.New("fabric message endpoints, kind, and body are required")
	}
	if message.Metadata == nil {
		message.Metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(message.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode fabric message metadata: %w", err)
	}
	if message.Status == "" {
		message.Status = "queued"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO fabric_messages
(id, request_id, reply_to, from_endpoint_id, to_endpoint_id, kind, body,
 metadata_json, status, error, created_at, delivered_at, replied_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, message.ID, message.RequestID,
		message.ReplyTo, message.FromEndpointID, message.ToEndpointID, message.Kind,
		message.Body, string(metadataJSON), message.Status, message.Error, timestamp,
		nullableString(message.DeliveredAt), nullableString(message.RepliedAt))
	if err != nil {
		return nil, fmt.Errorf("create fabric message: %w", err)
	}
	return s.getFabricMessageLocked(message.ID)
}

func scanFabricMessage(scanner interface{ Scan(...any) error }) (*FabricMessage, error) {
	var message FabricMessage
	var metadataJSON string
	var deliveredAt, repliedAt sql.NullString
	err := scanner.Scan(&message.ID, &message.RequestID, &message.ReplyTo,
		&message.FromEndpointID, &message.ToEndpointID, &message.Kind, &message.Body,
		&metadataJSON, &message.Status, &message.Error, &message.CreatedAt, &deliveredAt, &repliedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(metadataJSON), &message.Metadata); err != nil {
		return nil, err
	}
	message.DeliveredAt, message.RepliedAt = deliveredAt.String, repliedAt.String
	return &message, nil
}

const fabricMessageColumns = `id, request_id, reply_to, from_endpoint_id,
to_endpoint_id, kind, body, metadata_json, status, error, created_at,
delivered_at, replied_at`

func (s *Store) getFabricMessageLocked(id string) (*FabricMessage, error) {
	return scanFabricMessage(s.db.QueryRow(`SELECT `+fabricMessageColumns+` FROM fabric_messages WHERE id = ?`, id))
}

func (s *Store) GetFabricMessage(id string) (*FabricMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getFabricMessageLocked(strings.TrimSpace(id))
}

func (s *Store) GetFabricRequest(requestID string) (*FabricMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanFabricMessage(s.db.QueryRow(`SELECT `+fabricMessageColumns+` FROM fabric_messages
WHERE request_id = ? AND kind = 'ask' ORDER BY created_at LIMIT 1`, strings.TrimSpace(requestID)))
}

func (s *Store) ListFabricMessages(endpointID, status string, limit int) ([]FabricMessage, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT ` + fabricMessageColumns + ` FROM fabric_messages WHERE 1=1`
	args := make([]any, 0, 3)
	if endpointID = strings.TrimSpace(endpointID); endpointID != "" {
		query += ` AND (from_endpoint_id = ? OR to_endpoint_id = ?)`
		args = append(args, endpointID, endpointID)
	}
	if status = strings.TrimSpace(status); status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]FabricMessage, 0)
	for rows.Next() {
		message, err := scanFabricMessage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *message)
	}
	return result, rows.Err()
}

func (s *Store) UpdateFabricMessage(id, status, messageError string) (*FabricMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deliveredAt, repliedAt := "", ""
	if status == "delivered" || status == "received" || status == "replied" {
		deliveredAt = now()
	}
	if status == "replied" {
		repliedAt = now()
	}
	_, err := s.db.Exec(`UPDATE fabric_messages SET status = ?, error = ?,
delivered_at = COALESCE(delivered_at, ?), replied_at = COALESCE(replied_at, ?)
WHERE id = ?`, status, messageError, nullableString(deliveredAt), nullableString(repliedAt), id)
	if err != nil {
		return nil, err
	}
	return s.getFabricMessageLocked(id)
}

// ClaimFabricMessages atomically moves queued messages for one endpoint to
// received. Repeated polling cannot consume the same envelope twice.
func (s *Store) ClaimFabricMessages(endpointID string, limit int) ([]FabricMessage, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM fabric_messages
WHERE to_endpoint_id = ? AND status = 'queued' ORDER BY created_at LIMIT ?`, strings.TrimSpace(endpointID), limit)
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
	timestamp := now()
	result := make([]FabricMessage, 0, len(ids))
	for _, id := range ids {
		updated, err := tx.Exec(`UPDATE fabric_messages SET status = 'received', delivered_at = ?
WHERE id = ? AND status = 'queued'`, timestamp, id)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil || changed == 0 {
			continue
		}
		message, err := scanFabricMessage(tx.QueryRow(`SELECT `+fabricMessageColumns+` FROM fabric_messages WHERE id = ?`, id))
		if err != nil {
			return nil, err
		}
		result = append(result, *message)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// ClaimFabricMessagesForMachine assigns queued envelopes to the machine agent
// that can reach the target native session. The agent reports success or puts
// the envelope back in the queue with a bounded error for retry.
func (s *Store) ClaimFabricMessagesForMachine(machineID string, limit int) ([]FabricMessage, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT m.id FROM fabric_messages m
JOIN fabric_endpoints e ON e.id = m.to_endpoint_id
WHERE e.machine_id = ? AND e.status NOT IN ('offline', 'left') AND m.status = 'queued'
ORDER BY m.created_at LIMIT ?`, strings.TrimSpace(machineID), limit)
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
	result := make([]FabricMessage, 0, len(ids))
	for _, id := range ids {
		updated, err := tx.Exec(`UPDATE fabric_messages SET status = 'dispatching' WHERE id = ? AND status = 'queued'`, id)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil || changed == 0 {
			continue
		}
		message, err := scanFabricMessage(tx.QueryRow(`SELECT `+fabricMessageColumns+` FROM fabric_messages WHERE id = ?`, id))
		if err != nil {
			return nil, err
		}
		result = append(result, *message)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) RequeueDispatchingFabricMessages(machineID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE fabric_messages SET status = 'queued', error = 'machine delivery resumed'
WHERE status = 'dispatching' AND to_endpoint_id IN (
  SELECT id FROM fabric_endpoints WHERE machine_id = ?
)`, strings.TrimSpace(machineID))
	return err
}

func (s *Store) AppendFabricEvent(endpointID, eventType string, payload any) (*FabricEvent, error) {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return nil, errors.New("fabric event type is required")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode fabric event: %w", err)
	}
	if len(encoded) > 64*1024 {
		return nil, errors.New("fabric event payload is limited to 64 KiB")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`INSERT INTO fabric_events (endpoint_id, type, payload_json, created_at)
VALUES (?, ?, ?, ?)`, strings.TrimSpace(endpointID), eventType, string(encoded), now())
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.getFabricEventLocked(id)
}

func (s *Store) getFabricEventLocked(id int64) (*FabricEvent, error) {
	var event FabricEvent
	var payload string
	err := s.db.QueryRow(`SELECT id, endpoint_id, type, payload_json, created_at
FROM fabric_events WHERE id = ?`, id).Scan(&event.ID, &event.EndpointID, &event.Type, &payload, &event.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	event.Payload = json.RawMessage(payload)
	return &event, nil
}

func (s *Store) ListFabricEvents(endpointID string, after int64, limit int) ([]FabricEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id, endpoint_id, type, payload_json, created_at FROM fabric_events WHERE id > ?`
	args := []any{after}
	if endpointID = strings.TrimSpace(endpointID); endpointID != "" {
		query += ` AND endpoint_id = ?`
		args = append(args, endpointID)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]FabricEvent, 0)
	for rows.Next() {
		var event FabricEvent
		var payload string
		if err := rows.Scan(&event.ID, &event.EndpointID, &event.Type, &payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Payload = json.RawMessage(payload)
		result = append(result, event)
	}
	return result, rows.Err()
}
