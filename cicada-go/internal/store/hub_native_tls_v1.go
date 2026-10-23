package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func (s *Store) initializeHubNativeTLSSchema() error {
	_, err := s.db.Exec(`CREATE TABLE hub_native_tls_v1(
id INTEGER PRIMARY KEY CHECK(id=1), descriptor_text TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TRIGGER hub_native_tls_v1_no_delete BEFORE DELETE ON hub_native_tls_v1 BEGIN SELECT RAISE(ABORT,'native TLS binding is permanent'); END;
CREATE TRIGGER hub_native_tls_v1_no_update BEFORE UPDATE ON hub_native_tls_v1 BEGIN SELECT RAISE(ABORT,'native TLS binding is immutable'); END;`)
	return err
}

func nativeTLSDescriptor(q hubOwnerQuerier) (string, error) {
	var text string
	err := q.QueryRow(`SELECT descriptor_text FROM hub_native_tls_v1 WHERE id=1`).Scan(&text)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return text, err
}

// HubNativeTLSDescriptor is a permanent public pin, separate from key files.
// Losing all private profile files therefore cannot reopen initialization or
// turn a previously native StateDir into implicit legacy plaintext service.
func (s *Store) HubNativeTLSDescriptor() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nativeTLSDescriptor(s.db)
}

// BindHubNativeTLSLocal is deployment-channel transport configuration only.
// The caller must match both retained application keys before invoking it.
// Repeating exactly the same binding recovers a lost local response.
func (s *Store) BindHubNativeTLSLocal(text string) error {
	if s.requireOwnerSetupStartupAllowed() != nil {
		return ErrHubOwnerSetupConflict
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil || hubtransport.ValidateDescriptor(d, time.Now()) != nil {
		return ErrHubOwnerSetupConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	setup, err := hubOwnerSetup(tx)
	if err != nil || setup == nil || setup.State != HubOwnerReady || setup.HubID != d.Claims.Hub.HubID || setup.Origin != d.Claims.Origin || !activeSelfOwnedHuman(tx, setup.OwnerID) {
		return ErrHubOwnerSetupConflict
	}
	previous, err := nativeTLSDescriptor(tx)
	if err != nil {
		return err
	}
	if previous != "" {
		if previous != text {
			return ErrHubOwnerSetupConflict
		}
		return nil
	}
	if _, err = tx.Exec(`INSERT INTO hub_native_tls_v1 VALUES(1,?,?)`, text, now()); err != nil {
		return err
	}
	return tx.Commit()
}
