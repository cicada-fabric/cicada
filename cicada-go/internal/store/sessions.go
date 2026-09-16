package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
)

func (s *Store) GetPeerSession(contactID string) (*PeerSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanPeerSession(s.db.QueryRow(`SELECT contact_id, epoch, root_key, send_chain_key,
receive_chain_key, send_count, receive_count, pending_offer, status, created_at, updated_at
FROM peer_sessions WHERE contact_id = ?`, contactID))
}

// SavePeerSession atomically replaces the protected ratchet state. It is
// intentionally separate from Contact JSON so API responses cannot expose
// chain keys.
func (s *Store) SavePeerSession(session PeerSession) error {
	if session.ContactID == "" || session.Epoch == 0 || len(session.RootKey) < 32 || len(session.SendChainKey) < 32 || len(session.ReceiveChainKey) < 32 {
		return errors.New("invalid peer session state")
	}
	if session.Status == "" {
		session.Status = "active"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var created string
	_ = s.db.QueryRow(`SELECT created_at FROM peer_sessions WHERE contact_id = ?`, session.ContactID).Scan(&created)
	if created == "" {
		created = timestamp
	}
	_, err := s.db.Exec(`INSERT INTO peer_sessions
(contact_id, epoch, root_key, send_chain_key, receive_chain_key, send_count, receive_count, pending_offer, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(contact_id) DO UPDATE SET epoch=excluded.epoch, root_key=excluded.root_key,
send_chain_key=excluded.send_chain_key, receive_chain_key=excluded.receive_chain_key,
send_count=excluded.send_count, receive_count=excluded.receive_count,
pending_offer=excluded.pending_offer, status=excluded.status, updated_at=excluded.updated_at`,
		session.ContactID, session.Epoch, session.RootKey, session.SendChainKey, session.ReceiveChainKey,
		session.SendCount, session.ReceiveCount, nullableBytes(session.PendingOffer), session.Status, created, timestamp)
	if err != nil {
		return fmt.Errorf("save peer session: %w", err)
	}
	return nil
}

func (s *Store) DeletePeerSession(contactID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM peer_sessions WHERE contact_id = ?`, contactID)
	return err
}

type peerSessionScanner interface {
	Scan(dest ...any) error
}

func scanPeerSession(row peerSessionScanner) (*PeerSession, error) {
	var session PeerSession
	var root, sendChain, receiveChain, pending []byte
	var pendingValue []byte
	err := row.Scan(&session.ContactID, &session.Epoch, &root, &sendChain, &receiveChain,
		&session.SendCount, &session.ReceiveCount, &pendingValue, &session.Status, &session.CreatedAt, &session.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	session.RootKey = append([]byte(nil), root...)
	session.SendChainKey = append([]byte(nil), sendChain...)
	session.ReceiveChainKey = append([]byte(nil), receiveChain...)
	pending = pendingValue
	session.PendingOffer = append([]byte(nil), pending...)
	return &session, nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func ensurePeerSessionExists(s *Store, contactID string) error {
	if session, err := s.GetPeerSession(contactID); err != nil {
		return err
	} else if session == nil {
		return os.ErrNotExist
	}
	return nil
}
