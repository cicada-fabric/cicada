package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ThreadSession identifies a manually opened Codex TUI thread. It is separate
// from Worker because the operator owns the interactive process lifecycle.
type ThreadSession struct {
	ID        string `json:"id"`
	ThreadID  string `json:"thread_id"`
	Label     string `json:"label"`
	Workspace string `json:"workspace,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ThreadDelivery is the durable audit record for an official `codex queue`
// invocation between two manually opened TUI sessions.
type ThreadDelivery struct {
	ID           string `json:"id"`
	FromThreadID string `json:"from_thread_id"`
	ToThreadID   string `json:"to_thread_id"`
	Message      string `json:"message"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	CreatedAt    string `json:"created_at"`
	DeliveredAt  string `json:"delivered_at,omitempty"`
}

func (s *Store) UpsertThreadSession(threadID, label, workspace, status string) (*ThreadSession, error) {
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return nil, errors.New("thread id is required")
	}
	if label == "" {
		label = threadID
	}
	if status == "" {
		status = "active"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
INSERT INTO thread_sessions (id, thread_id, label, workspace, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(thread_id) DO UPDATE SET label=excluded.label, workspace=excluded.workspace,
  status=excluded.status, updated_at=excluded.updated_at`,
		NewID("thread"), threadID, label, workspace, status, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert thread session: %w", err)
	}
	return s.getThreadSessionLocked(threadID)
}

func (s *Store) getThreadSessionLocked(threadID string) (*ThreadSession, error) {
	var session ThreadSession
	err := s.db.QueryRow(`SELECT id, thread_id, label, workspace, status, created_at, updated_at
FROM thread_sessions WHERE thread_id = ?`, threadID).Scan(
		&session.ID, &session.ThreadID, &session.Label, &session.Workspace,
		&session.Status, &session.CreatedAt, &session.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *Store) GetThreadSession(threadID string) (*ThreadSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getThreadSessionLocked(strings.TrimSpace(threadID))
}

func (s *Store) ListThreadSessions() ([]ThreadSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT thread_id FROM thread_sessions ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var threadID string
		if err := rows.Scan(&threadID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, threadID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]ThreadSession, 0, len(ids))
	for _, threadID := range ids {
		session, err := s.getThreadSessionLocked(threadID)
		if err != nil {
			return nil, err
		}
		if session != nil {
			result = append(result, *session)
		}
	}
	return result, nil
}

func (s *Store) CreateThreadDelivery(delivery ThreadDelivery) (*ThreadDelivery, error) {
	delivery.ID = strings.TrimSpace(delivery.ID)
	if delivery.ID == "" {
		delivery.ID = NewID("thread_delivery")
	}
	if delivery.FromThreadID == "" || delivery.ToThreadID == "" || delivery.Message == "" {
		return nil, errors.New("thread delivery endpoints and message are required")
	}
	if delivery.Status == "" {
		delivery.Status = "queued"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO thread_deliveries
(id, from_thread_id, to_thread_id, message, status, error, created_at, delivered_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, delivery.ID, delivery.FromThreadID,
		delivery.ToThreadID, delivery.Message, delivery.Status, delivery.Error,
		timestamp, nullableString(delivery.DeliveredAt))
	if err != nil {
		return nil, fmt.Errorf("create thread delivery: %w", err)
	}
	return s.getThreadDeliveryLocked(delivery.ID)
}

func (s *Store) getThreadDeliveryLocked(id string) (*ThreadDelivery, error) {
	var delivery ThreadDelivery
	var deliveredAt sql.NullString
	err := s.db.QueryRow(`SELECT id, from_thread_id, to_thread_id, message, status, error,
created_at, delivered_at FROM thread_deliveries WHERE id = ?`, id).Scan(
		&delivery.ID, &delivery.FromThreadID, &delivery.ToThreadID, &delivery.Message,
		&delivery.Status, &delivery.Error, &delivery.CreatedAt, &deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	delivery.DeliveredAt = deliveredAt.String
	return &delivery, nil
}

func (s *Store) UpdateThreadDelivery(id, status, deliveryError string) (*ThreadDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deliveredAt := ""
	if status == "delivered" {
		deliveredAt = now()
	}
	_, err := s.db.Exec(`UPDATE thread_deliveries SET status = ?, error = ?, delivered_at = ?
WHERE id = ?`, status, deliveryError, nullableString(deliveredAt), id)
	if err != nil {
		return nil, err
	}
	return s.getThreadDeliveryLocked(id)
}

func (s *Store) ListThreadDeliveries(limit int) ([]ThreadDelivery, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM thread_deliveries ORDER BY created_at DESC LIMIT ?`, limit)
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
	result := make([]ThreadDelivery, 0, len(ids))
	for _, id := range ids {
		delivery, err := s.getThreadDeliveryLocked(id)
		if err != nil {
			return nil, err
		}
		if delivery != nil {
			result = append(result, *delivery)
		}
	}
	return result, nil
}
