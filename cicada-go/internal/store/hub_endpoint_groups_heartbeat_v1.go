package store

import (
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The original native token may renew only its still-live registration. An
// expired lease requires the independent signed Node renewal, and neither path
// installs or restores a Group contribution. Now is sampled after the writer.
func (s *Store) RenewEndpointGroupsHeartbeat(credential string, now func() time.Time) (wire.EndpointGroupsRegistrationAnchor, bool, error) {
	var empty wire.EndpointGroupsRegistrationAnchor
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	present, err := endpointGroupsSchemaPresent(tx)
	if err != nil || !present {
		return empty, false, err
	}
	lock, err := tx.Exec(`UPDATE hub_endpoint_groups_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return empty, true, err
	}
	if n, e := lock.RowsAffected(); e != nil || n != 1 {
		return empty, true, ErrNetworkPermission
	}
	var endpoint string
	err = tx.QueryRow(`SELECT r.endpoint_id FROM hub_endpoint_groups_registrations_v1 r JOIN session_bindings b ON b.id=r.binding_id AND b.endpoint_id=r.endpoint_id WHERE b.credential_hash=?`, credential).Scan(&endpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	r, err := endpointGroupsRegistrationTx(tx, endpoint)
	if err != nil || r == nil || endpointGroupsRegistrationLeaseTx(tx, r, at) != nil {
		return empty, true, ErrNetworkPermission
	}
	if err = endpointGroupsRenewRegistrationTx(tx, r, at); err != nil {
		return empty, true, err
	}
	if err = tx.Commit(); err != nil {
		return empty, true, err
	}
	return r.anchor, true, nil
}
