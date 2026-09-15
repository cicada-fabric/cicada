package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type contactScanner interface {
	Scan(dest ...any) error
}

func scanContact(row contactScanner) (*Contact, error) {
	var contact Contact
	var identityJSON, receivedJSON string
	err := row.Scan(&contact.ID, &contact.Label, &identityJSON, &contact.Status,
		&contact.SendSequence, &receivedJSON, &contact.CreatedAt, &contact.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(identityJSON), &contact.Identity); err != nil {
		return nil, fmt.Errorf("decode contact identity: %w", err)
	}
	if receivedJSON != "" {
		if err := json.Unmarshal([]byte(receivedJSON), &contact.ReceivedSequences); err != nil {
			return nil, fmt.Errorf("decode contact replay state: %w", err)
		}
	}
	return &contact, nil
}

func (s *Store) GetContactByRemoteID(remoteID string) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getContactByRemoteIDLocked(strings.TrimSpace(remoteID))
}

func (s *Store) getContactByRemoteIDLocked(remoteID string) (*Contact, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM contacts WHERE remote_id = ? ORDER BY created_at LIMIT 1`, remoteID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getContactLocked(id)
}

type peerMessageScanner interface {
	Scan(dest ...any) error
}

func scanPeerMessage(row peerMessageScanner) (*PeerMessage, error) {
	var message PeerMessage
	var envelope, aad, deliveredAt sql.NullString
	err := row.Scan(&message.ID, &message.TransportID, &message.ContactID,
		&message.Direction, &message.SenderID, &message.RecipientID,
		&message.Sequence, &envelope, &aad, &message.Status, &message.CreatedAt,
		&deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	message.Envelope = json.RawMessage(envelope.String)
	message.AAD = aad.String
	message.DeliveredAt = deliveredAt.String
	return &message, nil
}

func (s *Store) GetPeerMessageByTransportID(senderID, transportID string) (*PeerMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanPeerMessage(s.db.QueryRow(`SELECT id, transport_id, contact_id, direction,
sender_id, recipient_id, sequence, envelope_json, aad, status, created_at, delivered_at
FROM peer_messages WHERE sender_id = ? AND transport_id = ?`,
		strings.TrimSpace(senderID), strings.TrimSpace(transportID)))
}

// AcceptInboundPeerMessage atomically records the replay sequence and opaque
// envelope. A repeated transport ID returns the original row without emitting
// a second message; a reused sequence under a different ID is rejected.
func (s *Store) AcceptInboundPeerMessage(message PeerMessage) (*PeerMessage, bool, error) {
	message.TransportID = strings.TrimSpace(message.TransportID)
	message.ContactID = strings.TrimSpace(message.ContactID)
	message.SenderID = strings.TrimSpace(message.SenderID)
	message.RecipientID = strings.TrimSpace(message.RecipientID)
	if message.ContactID == "" || message.SenderID == "" || message.RecipientID == "" || len(message.Envelope) == 0 {
		return nil, false, errors.New("inbound peer message routing and envelope are required")
	}
	if !json.Valid(message.Envelope) {
		return nil, false, errors.New("inbound peer envelope must be valid JSON")
	}
	if len(message.TransportID) > 200 {
		return nil, false, errors.New("peer transport id exceeds 200 characters")
	}
	message.Direction = "inbound"
	message.Status = "received"
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if message.TransportID != "" {
		existing, err := scanPeerMessage(tx.QueryRow(`SELECT id, transport_id, contact_id, direction,
sender_id, recipient_id, sequence, envelope_json, aad, status, created_at, delivered_at
FROM peer_messages WHERE sender_id = ? AND transport_id = ?`, message.SenderID, message.TransportID))
		if err != nil {
			return nil, false, err
		}
		if existing != nil {
			if existing.ContactID != message.ContactID || existing.RecipientID != message.RecipientID ||
				existing.Sequence != message.Sequence || existing.AAD != message.AAD {
				return nil, false, errors.New("peer transport id was reused with different content")
			}
			if err := tx.Commit(); err != nil {
				return nil, false, err
			}
			return existing, false, nil
		}
	}
	contact, err := scanContact(tx.QueryRow(`SELECT id, label, identity_json, status, send_sequence,
received_sequences_json, created_at, updated_at FROM contacts WHERE id = ?`, message.ContactID))
	if err != nil {
		return nil, false, err
	}
	if contact == nil {
		return nil, false, os.ErrNotExist
	}
	if contact.Status != "trusted" {
		return nil, false, fmt.Errorf("contact is not trusted: %s", contact.Status)
	}
	if contact.Identity.ID != message.SenderID {
		return nil, false, errors.New("inbound sender does not match contact identity")
	}
	for _, seen := range contact.ReceivedSequences {
		if seen == message.Sequence {
			return nil, false, ErrPeerReplay
		}
	}
	if len(contact.ReceivedSequences) >= 4096 {
		contact.ReceivedSequences = contact.ReceivedSequences[1:]
	}
	contact.ReceivedSequences = append(contact.ReceivedSequences, message.Sequence)
	receivedJSON, err := json.Marshal(contact.ReceivedSequences)
	if err != nil {
		return nil, false, err
	}
	message.ID = NewID("peer_message")
	timestamp := now()
	if _, err := tx.Exec(`INSERT INTO peer_messages
(id, transport_id, contact_id, direction, sender_id, recipient_id, sequence,
 envelope_json, aad, status, created_at, delivered_at)
VALUES (?, ?, ?, 'inbound', ?, ?, ?, ?, ?, 'received', ?, NULL)`,
		message.ID, message.TransportID, message.ContactID, message.SenderID,
		message.RecipientID, message.Sequence, string(message.Envelope), message.AAD,
		timestamp); err != nil {
		return nil, false, fmt.Errorf("store inbound peer message: %w", err)
	}
	result, err := tx.Exec(`UPDATE contacts SET received_sequences_json = ?, updated_at = ? WHERE id = ?`,
		string(receivedJSON), timestamp, message.ContactID)
	if err != nil {
		return nil, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if changed != 1 {
		return nil, false, os.ErrNotExist
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	stored, err := s.getPeerMessageLocked(message.ID)
	return stored, true, err
}
