package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func (s *Store) UpsertDirectoryRecord(record DirectoryRecord) (*DirectoryRecord, error) {
	if record.ID == "" {
		record.ID = NewID("directory")
	}
	if record.RemoteID == "" || record.Label == "" || len(record.Endpoints) == 0 || record.ExpiresAt == "" || !json.Valid(record.Announcement) {
		return nil, errors.New("directory record fields are required")
	}
	identityJSON, err := json.Marshal(record.Identity)
	if err != nil {
		return nil, err
	}
	endpointsJSON, err := json.Marshal(record.Endpoints)
	if err != nil {
		return nil, err
	}
	if record.Status == "" {
		record.Status = "active"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var created string
	_ = s.db.QueryRow(`SELECT created_at FROM directory_records WHERE remote_id = ?`, record.RemoteID).Scan(&created)
	if created == "" {
		created = timestamp
	}
	_, err = s.db.Exec(`INSERT INTO directory_records
(id, remote_id, label, identity_json, endpoints_json, announcement_json, expires_at, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(remote_id) DO UPDATE SET id=excluded.id, label=excluded.label,
identity_json=excluded.identity_json, endpoints_json=excluded.endpoints_json,
announcement_json=excluded.announcement_json, expires_at=excluded.expires_at,
status=excluded.status, updated_at=excluded.updated_at`, record.ID, record.RemoteID,
		record.Label, string(identityJSON), string(endpointsJSON), string(record.Announcement), record.ExpiresAt, record.Status, created, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert directory record: %w", err)
	}
	return s.getDirectoryRecordLocked(record.RemoteID)
}

func (s *Store) GetDirectoryRecord(id string) (*DirectoryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDirectoryRecordLocked(id)
}

func (s *Store) GetDirectoryRecordByRemoteID(remoteID string) (*DirectoryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDirectoryRecordLocked(strings.TrimSpace(remoteID))
}

func (s *Store) ListDirectoryRecords(activeOnly bool) ([]DirectoryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM directory_records ORDER BY updated_at DESC`
	if activeOnly {
		query = `SELECT id FROM directory_records WHERE status = 'active' ORDER BY updated_at DESC`
	}
	rows, err := s.db.Query(query)
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
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var result []DirectoryRecord
	for _, id := range ids {
		record, err := s.getDirectoryRecordLocked(id)
		if err != nil {
			return nil, err
		}
		if record != nil {
			result = append(result, *record)
		}
	}
	return result, nil
}

func (s *Store) ReapExpiredDirectoryRecords(nowValue string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE directory_records SET status = 'expired', updated_at = ? WHERE status = 'active' AND expires_at <= ?`, now(), nowValue)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) getDirectoryRecordLocked(id string) (*DirectoryRecord, error) {
	var record DirectoryRecord
	var identityJSON, endpointsJSON, announcement string
	err := s.db.QueryRow(`SELECT id, remote_id, label, identity_json, endpoints_json, announcement_json,
expires_at, status, created_at, updated_at FROM directory_records WHERE id = ? OR remote_id = ? LIMIT 1`, id, id).Scan(
		&record.ID, &record.RemoteID, &record.Label, &identityJSON, &endpointsJSON, &announcement,
		&record.ExpiresAt, &record.Status, &record.CreatedAt, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(identityJSON), &record.Identity); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(endpointsJSON), &record.Endpoints); err != nil {
		return nil, err
	}
	record.Announcement = json.RawMessage(announcement)
	return &record, nil
}
