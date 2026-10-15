package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Diagnostics authenticate a persisted exact key even when its login authority
// is revoked. The returned key is usable only for sealed reconciliation.
func (s *Store) HubAccountDiagnosticDevice(account, device string) (*HubAccountDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := accountSetup(s.db, false)
	if err != nil || r.AccountID != account {
		return nil, ErrHubAccountRejected
	}
	var raw string
	var d HubAccountDevice
	err = s.db.QueryRow(`SELECT account_id,owner_id,device_id,public_identity_json,epoch,status,created_at FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, account, device).Scan(&d.AccountID, &d.OwnerID, &d.DeviceID, &raw, &d.Epoch, &d.State, &d.CreatedAt)
	if err != nil || json.Unmarshal([]byte(raw), &d.Public) != nil || e2ee.ValidatePublicIdentity(d.Public) != nil {
		return nil, ErrHubAccountRejected
	}
	return &d, nil
}
func hubAccountOperationUnfenced(q hubOwnerQuerier, account, device, id string) error {
	o, err := ownerOperation(q, account, device, id)
	if err != nil {
		return err
	}
	if o != nil {
		return ErrHubAccountRejected
	}
	return nil
}

type HubAccountReconcileInput struct {
	AccountID, OwnerID, DeviceID, Operation, RequestID, RequestDigest string
	Epoch                                                             int64
}

// ReconcileHubAccountOriginal is serialized with the ordinary account writers.
// A nil packet means a durable rejection fence, never an observational ABSENT.
func (s *Store) ReconcileHubAccountOriginal(in HubAccountReconcileInput) ([]byte, error) {
	if !wire.AccountReconcileOperationAllowed(in.Operation) || !accountIDValid(in.RequestID) || !accountHashValid(in.RequestDigest) {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := accountSetup(tx, false)
	if err != nil || r.AccountID != in.AccountID || r.OwnerID != in.OwnerID {
		return nil, ErrHubAccountRejected
	}
	prior, err := ownerOperation(tx, in.AccountID, in.DeviceID, in.RequestID)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.Operation != in.Operation || prior.Digest != in.RequestDigest || prior.State != wire.ActivationRejected {
			return nil, ErrHubAccountRejected
		}
		return nil, nil
	}
	var packet []byte
	var digest string
	switch in.Operation {
	case wire.OperationLoginPrepare:
		err = tx.QueryRow(`SELECT prepare_digest,challenge_packet FROM hub_account_attempts_v1 WHERE account_id=? AND device_id=? AND purpose='LOGIN' AND prepare_id=?`, in.AccountID, in.DeviceID, in.RequestID).Scan(&digest, &packet)
	case wire.OperationLoginComplete:
		err = tx.QueryRow(`SELECT request_digest,response_packet FROM hub_account_attempts_v1 WHERE account_id=? AND device_id=? AND purpose='LOGIN' AND state='CONSUMED' AND complete_id=?`, in.AccountID, in.DeviceID, in.RequestID).Scan(&digest, &packet)
	default:
		err = tx.QueryRow(`SELECT r.request_digest,r.response_packet FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id WHERE s.account_id=? AND s.device_id=? AND r.operation_id=? AND r.operation=?`, in.AccountID, in.DeviceID, in.RequestID, in.Operation).Scan(&digest, &packet)
	}
	if err == nil {
		if digest != in.RequestDigest || len(packet) == 0 {
			return nil, ErrHubAccountRejected
		}
		return packet, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	o := HubOwnerOperation{AccountID: in.AccountID, OwnerID: in.OwnerID, DeviceID: in.DeviceID, Operation: in.Operation, ID: in.RequestID, Digest: in.RequestDigest, State: wire.ActivationRejected, Epoch: in.Epoch}
	if err = insertOwnerOperation(tx, o); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return nil, nil
}
