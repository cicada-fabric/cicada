package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func (s *Store) CreateDiscoveryRequest(request DiscoveryRequest) (*DiscoveryRequest, error) {
	if request.ID == "" {
		request.ID = NewID("discovery")
	}
	if request.RemoteID == "" || request.Label == "" {
		return nil, errors.New("remote_id and label are required")
	}
	if err := e2ee.ValidatePublicIdentity(request.Identity); err != nil {
		return nil, fmt.Errorf("validate discovery identity: %w", err)
	}
	if request.RemoteID != request.Identity.ID {
		return nil, errors.New("discovery remote_id does not match identity")
	}
	if !json.Valid(request.Announcement) {
		return nil, errors.New("discovery announcement must be valid JSON")
	}
	if request.Status == "" {
		request.Status = "pending"
	}
	identityJSON, err := json.Marshal(request.Identity)
	if err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO contact_discovery_requests
(id, remote_id, label, identity_json, announcement_json, status, contact_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, request.ID, request.RemoteID, request.Label,
		string(identityJSON), string(request.Announcement), request.Status,
		nullableString(request.ContactID), timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}
	return s.getDiscoveryRequestLocked(request.ID)
}

func (s *Store) GetDiscoveryRequest(id string) (*DiscoveryRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDiscoveryRequestLocked(id)
}

func (s *Store) GetDiscoveryRequestByRemoteID(remoteID string) (*DiscoveryRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(`SELECT id FROM contact_discovery_requests WHERE remote_id = ?`, remoteID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getDiscoveryRequestLocked(id)
}

func (s *Store) ListDiscoveryRequests(status string) ([]DiscoveryRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM contact_discovery_requests ORDER BY created_at DESC`
	args := []any{}
	if status != "" {
		query = `SELECT id FROM contact_discovery_requests WHERE status = ? ORDER BY created_at DESC`
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
	result := make([]DiscoveryRequest, 0, len(ids))
	for _, id := range ids {
		request, err := s.getDiscoveryRequestLocked(id)
		if err != nil {
			return nil, err
		}
		if request != nil {
			result = append(result, *request)
		}
	}
	return result, nil
}

func (s *Store) ResolveDiscoveryRequest(id, status, contactID string) (*DiscoveryRequest, error) {
	if status != "accepted" && status != "rejected" {
		return nil, fmt.Errorf("unsupported discovery status: %s", status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE contact_discovery_requests SET status = ?, contact_id = ?, updated_at = ?
WHERE id = ? AND status = 'pending'`, status, nullableString(contactID), now(), id)
	if err != nil {
		return nil, err
	}
	return s.getDiscoveryRequestLocked(id)
}

// AcceptDiscoveryRequest atomically creates the pending Contact and links it
// to the discovery request. The boolean is true only for the first acceptance.
func (s *Store) AcceptDiscoveryRequest(id string) (*DiscoveryRequest, *Contact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, false, err
	}
	defer tx.Rollback()
	request, err := scanDiscoveryRequest(tx.QueryRow(`SELECT id, remote_id, label, identity_json, announcement_json, status,
contact_id, created_at, updated_at FROM contact_discovery_requests WHERE id = ?`, id))
	if err != nil {
		return nil, nil, false, err
	}
	if request == nil {
		return nil, nil, false, nil
	}
	if request.Status != "pending" {
		if err := tx.Commit(); err != nil {
			return nil, nil, false, err
		}
		var contact *Contact
		if request.ContactID != "" {
			contact, err = s.getContactLocked(request.ContactID)
		}
		return request, contact, false, err
	}
	contactID := NewID("contact")
	identityJSON, err := json.Marshal(request.Identity)
	if err != nil {
		return nil, nil, false, err
	}
	timestamp := now()
	var existingContactID string
	err = tx.QueryRow(`SELECT id FROM contacts WHERE remote_id = ? ORDER BY created_at LIMIT 1`, request.RemoteID).Scan(&existingContactID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, err
	}
	if existingContactID != "" {
		contactID = existingContactID
	} else if _, err := tx.Exec(`INSERT INTO contacts
(id, remote_id, label, identity_json, status, send_sequence, received_sequences_json, created_at, updated_at)
VALUES (?, ?, ?, ?, 'pending', 0, '[]', ?, ?)`, contactID, request.RemoteID, request.Label, string(identityJSON), timestamp, timestamp); err != nil {
		return nil, nil, false, fmt.Errorf("create discovered contact: %w", err)
	}
	result, err := tx.Exec(`UPDATE contact_discovery_requests SET status = 'accepted', contact_id = ?, updated_at = ?
WHERE id = ? AND status = 'pending'`, contactID, timestamp, id)
	if err != nil {
		return nil, nil, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, nil, false, err
	}
	if changed != 1 {
		return nil, nil, false, errors.New("discovery request changed during acceptance")
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	request, err = s.getDiscoveryRequestLocked(id)
	if err != nil {
		return nil, nil, false, err
	}
	contact, err := s.getContactLocked(contactID)
	return request, contact, true, err
}

func (s *Store) getDiscoveryRequestLocked(id string) (*DiscoveryRequest, error) {
	return scanDiscoveryRequest(s.db.QueryRow(`SELECT id, remote_id, label, identity_json, announcement_json, status,
contact_id, created_at, updated_at FROM contact_discovery_requests WHERE id = ?`, id))
}

type discoveryScanner interface {
	Scan(dest ...any) error
}

func scanDiscoveryRequest(row discoveryScanner) (*DiscoveryRequest, error) {
	var request DiscoveryRequest
	var identityJSON, announcement, contactID sql.NullString
	err := row.Scan(
		&request.ID, &request.RemoteID, &request.Label, &identityJSON, &announcement,
		&request.Status, &contactID, &request.CreatedAt, &request.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(identityJSON.String), &request.Identity); err != nil {
		return nil, fmt.Errorf("decode discovery identity: %w", err)
	}
	request.Announcement = json.RawMessage(announcement.String)
	request.ContactID = contactID.String
	return &request, nil
}
