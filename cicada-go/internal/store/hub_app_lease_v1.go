package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type HubAppLease struct {
	Binding       wire.ActivationBinding
	State         string
	LoginRequired bool
}

func appLease(q hubOwnerQuerier, owner, device string) (*HubAppLease, error) {
	return appLeaseAt(q, owner, device, time.Now().UTC())
}
func appLeaseAt(q hubOwnerQuerier, owner, device string, at time.Time) (*HubAppLease, error) {
	var raw, state string
	var epoch, de int64
	var account, keyID, expires string
	err := q.QueryRow(`SELECT binding_json,state,account_epoch,device_epoch,account_id,owner_key_id,expires_at FROM hub_app_leases_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&raw, &state, &epoch, &de, &account, &keyID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l := &HubAppLease{State: state, LoginRequired: true}
	if json.Unmarshal([]byte(raw), &l.Binding) != nil {
		return nil, ErrHubAccountRejected
	}
	current, err := accountEpoch(q)
	if err != nil {
		return nil, err
	}
	var deviceState, rootState, clientState string
	var deviceEpoch int64
	if q.QueryRow(`SELECT status,epoch FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, account, device).Scan(&deviceState, &deviceEpoch) != nil || q.QueryRow(`SELECT state FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, owner, keyID).Scan(&rootState) != nil || q.QueryRow(`SELECT state FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&clientState) != nil || epoch != current || de != deviceEpoch || deviceState != "ACTIVE" || rootState != "ACTIVE" || clientState != "ACTIVE" || state != "ACTIVE" {
		l.State = wire.ActivationLeaseRevoked
		return l, nil
	}
	leaseExpiryTime, parseErr := time.Parse(time.RFC3339Nano, expires)
	if parseErr != nil || !leaseExpiryTime.After(at) {
		l.State = wire.ActivationLeaseExpired
		return l, nil
	}
	var sessionID string
	err = q.QueryRow(`SELECT s.session_id FROM hub_account_sessions_v1 s JOIN hub_account_credentials_v1 c ON c.account_id=s.account_id AND c.version=s.credential_version WHERE s.account_id=? AND s.owner_id=? AND s.device_id=? AND s.epoch=? AND s.device_epoch=? AND s.state='ACTIVE' ORDER BY s.rowid DESC LIMIT 1`, account, owner, device, current, deviceEpoch).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var expiry string
	if q.QueryRow(`SELECT expires_at FROM hub_account_sessions_v1 WHERE session_id=?`, sessionID).Scan(&expiry) != nil {
		return nil, ErrHubAccountRejected
	}
	sessionExpiry, parseErr := time.Parse(time.RFC3339Nano, expiry)
	l.LoginRequired = parseErr != nil || !sessionExpiry.After(at)
	return l, nil
}
func appLeaseAllowed(q hubOwnerQuerier, owner, device, operation string) error {
	l, err := appLease(q, owner, device)
	if err != nil {
		return err
	}
	if l == nil {
		return nil
	}
	if l.State != wire.ActivationLeaseActive || l.LoginRequired {
		return ErrClientDeviceRevoked
	}
	for _, op := range wire.ActivationAllowedOperations() {
		if operation == op {
			return nil
		}
	}
	return ErrClientDeviceRevoked
}
func (s *Store) CheckAppLease(owner, device, operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return appLeaseAllowed(s.db, owner, device, operation)
}
func (s *Store) HubAppLease(owner, device string) (*HubAppLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return appLease(s.db, owner, device)
}
func (s *Store) FilterAppLeaseOperations(owner, device string, operations []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := appLease(s.db, owner, device)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return operations, nil
	}
	if l.State != wire.ActivationLeaseActive || l.LoginRequired {
		return []string{}, nil
	}
	result := []string{}
	for _, op := range operations {
		for _, allowed := range wire.ActivationAllowedOperations() {
			if op == allowed {
				result = append(result, op)
			}
		}
	}
	return result, nil
}
