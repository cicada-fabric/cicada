package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Intent is a durable record of one natural-language input and the Control
// object or action it was routed to.
type Intent struct {
	ID            string          `json:"id"`
	Text          string          `json:"text"`
	RequestedKind string          `json:"requested_kind"`
	ResolvedKind  string          `json:"resolved_kind,omitempty"`
	Status        string          `json:"status"`
	TargetID      string          `json:"target_id,omitempty"`
	Attachments   []string        `json:"attachments,omitempty"`
	Result        json.RawMessage `json:"result"`
	Question      string          `json:"question,omitempty"`
	Error         string          `json:"error,omitempty"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
}

func (s *Store) CreateIntent(text, requestedKind, targetID string, attachments []string) (*Intent, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("intent text is required")
	}
	if requestedKind == "" {
		requestedKind = "auto"
	}
	intent := Intent{
		ID: NewID("intent"), Text: text, RequestedKind: requestedKind,
		Status: "pending", TargetID: strings.TrimSpace(targetID), Attachments: append([]string(nil), attachments...), Result: json.RawMessage(`{}`),
	}
	encodedAttachments, err := json.Marshal(intent.Attachments)
	if err != nil {
		return nil, fmt.Errorf("encode intent attachments: %w", err)
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO intents
(id, text, requested_kind, resolved_kind, status, target_id, attachments_json, result_json, question, error, created_at, updated_at)
VALUES (?, ?, ?, '', 'pending', ?, ?, '{}', '', '', ?, ?)`, intent.ID, intent.Text,
		intent.RequestedKind, intent.TargetID, string(encodedAttachments), timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create intent: %w", err)
	}
	return s.getIntentLocked(intent.ID)
}

func (s *Store) ResolveIntent(id, kind, status string, result any, question, intentError string) (*Intent, error) {
	if status != "resolved" && status != "needs_input" && status != "failed" {
		return nil, fmt.Errorf("unsupported intent status: %s", status)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode intent result: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	update, err := s.db.Exec(`UPDATE intents SET resolved_kind = ?, status = ?, result_json = ?,
question = ?, error = ?, updated_at = ? WHERE id = ?`, kind, status, string(encoded),
		question, intentError, now(), id)
	if err != nil {
		return nil, fmt.Errorf("resolve intent: %w", err)
	}
	changed, err := update.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return nil, nil
	}
	return s.getIntentLocked(id)
}

func (s *Store) GetIntent(id string) (*Intent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getIntentLocked(id)
}

func (s *Store) ListIntents(status string) ([]Intent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query, args := `SELECT id FROM intents ORDER BY created_at DESC LIMIT 200`, []any{}
	if status != "" {
		query = `SELECT id FROM intents WHERE status = ? ORDER BY created_at DESC LIMIT 200`
		args = append(args, status)
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
	result := make([]Intent, 0, len(ids))
	for _, id := range ids {
		intent, err := s.getIntentLocked(id)
		if err != nil {
			return nil, err
		}
		if intent != nil {
			result = append(result, *intent)
		}
	}
	return result, nil
}

func (s *Store) getIntentLocked(id string) (*Intent, error) {
	var intent Intent
	var result string
	var attachments string
	err := s.db.QueryRow(`SELECT id, text, requested_kind, resolved_kind, status, target_id,
attachments_json, result_json, question, error, created_at, updated_at FROM intents WHERE id = ?`, id).
		Scan(&intent.ID, &intent.Text, &intent.RequestedKind, &intent.ResolvedKind, &intent.Status,
			&intent.TargetID, &attachments, &result, &intent.Question, &intent.Error, &intent.CreatedAt, &intent.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	intent.Result = json.RawMessage(result)
	if err := json.Unmarshal([]byte(attachments), &intent.Attachments); err != nil {
		return nil, fmt.Errorf("decode intent attachments: %w", err)
	}
	return &intent, nil
}
