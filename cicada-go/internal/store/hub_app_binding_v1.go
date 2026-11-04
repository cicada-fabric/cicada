package store

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// Body and Packet must already have been authenticated together by the Hub.
// These callbacks are trusted process operations, never remotely selected.
// Now is sampled after the SQLite writer lock. Seal and all effects commit in
// one transaction; no authority is created if crypto, SQL or commit fails.
type HubAppBindingInput struct {
	Hub          wire.HubIdentity
	DevicePublic e2ee.PublicIdentity
	Operation    string
	Body         any
	Packet       []byte
	At           time.Time
	Now          func() time.Time
	Challenge    func(wire.AppBinding, []byte, time.Time) (wire.AppBindingChallenge, string, error)
	VerifyProof  func(ownerbootstrap.PairingFile, []byte, time.Time) (string, error)
	Seal         func(any) ([]byte, error)
}

type appBindingRequest struct {
	account, owner, device, id, origin, hub, issued string
	nonce                                           []byte
	ownerPublic                                     e2ee.PublicIdentity
}

func appBindingFields(body any) (r appBindingRequest, err error) {
	switch v := body.(type) {
	case wire.AppUnbindPrepare:
		r = appBindingRequest{v.AccountID, v.OwnerID, v.DeviceID, v.RequestID, v.Origin, v.HubID, v.IssuedAt, v.ClientNonce, v.OwnerPublic}
	case wire.AppRebindPrepare:
		r = appBindingRequest{v.AccountID, v.OwnerID, v.DeviceID, v.RequestID, v.Origin, v.HubID, v.IssuedAt, v.ClientNonce, v.OwnerPublic}
	case wire.AppBindingComplete:
		b := v.Binding
		r = appBindingRequest{b.AccountID, b.OwnerID, b.DeviceID, v.RequestID, b.Origin, b.HubID, v.IssuedAt, v.ClientNonce, b.OwnerPublic}
	default:
		return r, ErrHubAccountRejected
	}
	return r, nil
}

func appBindingFresh(issued string, at time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, issued)
	return err == nil && appNodeStamp(t) == issued && !t.After(at.Add(30*time.Second)) && at.Before(t.Add(wire.MaxSessionRequestLifetime))
}

func appBindingCollectPrepares(tx *sql.Tx, at time.Time) error {
	rows, err := tx.Query(`SELECT owner_id,device_id,prepare_id,expires_at FROM hub_app_binding_prepares_v1`)
	if err != nil {
		return err
	}
	type key struct{ owner, device, id string }
	var expired []key
	for rows.Next() {
		var k key
		var text string
		if err = rows.Scan(&k.owner, &k.device, &k.id, &text); err != nil {
			break
		}
		end, e := time.Parse(time.RFC3339Nano, text)
		if e != nil || !at.Before(end) {
			expired = append(expired, k)
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, k := range expired {
		if _, err = tx.Exec(`DELETE FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND prepare_id=?`, k.owner, k.device, k.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ProcessHubAppBinding(in HubAppBindingInput) ([]byte, error) {
	r, err := appBindingFields(in.Body)
	if err != nil || in.Seal == nil || in.Challenge == nil || in.VerifyProof == nil || len(in.Packet) == 0 {
		return nil, ErrHubAccountRejected
	}
	p, err := wire.PreflightRequest(in.Packet, in.Operation)
	if err != nil {
		return nil, ErrHubAccountRejected
	}
	_, route, err := wire.RequestRoute(in.Hub, r.owner, r.device, r.id, in.Operation, wire.HandshakeEpoch, in.DevicePublic)
	if err != nil || route != p.Packet.Route || !reflect.DeepEqual(p.SenderPublicIdentity, in.DevicePublic) {
		return nil, ErrHubAccountRejected
	}
	digest := wire.AppBindingPacketDigest(in.Packet)
	public, _ := json.Marshal(in.DevicePublic)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := tx.Exec(`UPDATE hub_app_binding_guard_v1 SET touched=touched WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := guard.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	at := in.At.UTC()
	if in.Now != nil {
		at = in.Now().UTC()
	}
	if at.IsZero() {
		return nil, ErrHubAccountRejected
	}
	// Exact historical receipts are diagnostic only, and intentionally require
	// neither the now-revoked device nor a new session. Never redispatch them.
	var oldOp, oldDigest, oldPublic string
	var cached []byte
	err = tx.QueryRow(`SELECT operation,request_digest,device_public_json,response_packet FROM hub_app_binding_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, r.owner, r.device, r.id).Scan(&oldOp, &oldDigest, &oldPublic, &cached)
	if err == nil {
		if oldOp != in.Operation || oldDigest != digest || oldPublic != string(public) {
			return nil, ErrHubAccountRejected
		}
		return append([]byte(nil), cached...), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	setup, err := hubOwnerSetup(tx)
	if err != nil || setup == nil || setup.State != HubOwnerReady || setup.AccountID != r.account || setup.OwnerID != r.owner || setup.HubID != r.hub || setup.HubID != in.Hub.HubID || setup.Origin != r.origin {
		return nil, ErrHubAccountRejected
	}
	var localHub string
	if tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&localHub) != nil || localHub != in.Hub.HubID {
		return nil, ErrHubAccountRejected
	}
	var epoch int64
	var restore string
	if err = tx.QueryRow(`SELECT epoch,restore_receipt FROM hub_account_config_v1 WHERE id=1`).Scan(&epoch, &restore); err != nil {
		return nil, err
	}
	credential, err := accountCredential(tx, r.account)
	if err != nil {
		return nil, err
	}
	fp, err := wire.HubFingerprint(in.Hub)
	if err != nil {
		return nil, err
	}
	switch q := in.Body.(type) {
	case wire.AppUnbindPrepare:
		if in.Operation != wire.OperationAppUnbindPrepare {
			return nil, ErrHubAccountRejected
		}
		return appBindingPrepare(tx, in, r, setup, epoch, restore, credential, fp, public, digest, at, q)
	case wire.AppRebindPrepare:
		if in.Operation != wire.OperationAppRebindPrepare {
			return nil, ErrHubAccountRejected
		}
		return appBindingPrepare(tx, in, r, setup, epoch, restore, credential, fp, public, digest, at, q)
	case wire.AppBindingComplete:
		want := wire.OperationAppUnbindComplete
		if q.Binding.Purpose == wire.AppBindingPurposeRebind {
			want = wire.OperationAppRebindComplete
		}
		if in.Operation != want {
			return nil, ErrHubAccountRejected
		}
		return appBindingComplete(tx, in, r, setup, epoch, restore, credential, fp, public, digest, at, q)
	}
	return nil, ErrHubAccountRejected
}

func appBindingRoot(tx *sql.Tx, owner string, public e2ee.PublicIdentity) (*OwnerApprovalKey, error) {
	k, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, owner, public.ID))
	if err != nil || !reflect.DeepEqual(k.Public, public) || k.State != OwnerApprovalKeyActive || !activeSelfOwnedHuman(tx, owner) {
		return nil, ErrHubAccountRejected
	}
	return k, nil
}

func appBindingSelf(tx *sql.Tx, b wire.AppBinding, at time.Time) error {
	var ad HubAccountDevice
	var raw string
	err := tx.QueryRow(`SELECT public_identity_json,epoch,status FROM hub_account_devices_v1 WHERE account_id=? AND owner_id=? AND device_id=?`, b.AccountID, b.OwnerID, b.DeviceID).Scan(&raw, &ad.Epoch, &ad.State)
	if err != nil || json.Unmarshal([]byte(raw), &ad.Public) != nil || !reflect.DeepEqual(ad.Public, b.DevicePublic) || ad.State != "ACTIVE" || uint64(ad.Epoch) != b.DeviceEpoch {
		return ErrHubAccountRejected
	}
	client, err := scanClientDevice(tx.QueryRow(clientDeviceSelect+` WHERE owner_id=? AND device_id=?`, b.OwnerID, b.DeviceID))
	if err != nil || client.State != ClientDeviceActive || !reflect.DeepEqual(client.Public, b.DevicePublic) || client.OwnerKeyID != b.OwnerPublic.ID || uint64(client.Version) != b.ClientDeviceVersion || client.SessionEpoch != b.ClientSessionEpoch {
		return ErrHubAccountRejected
	}
	var session HubAccountSession
	err = tx.QueryRow(`SELECT session_id,account_id,owner_id,device_id,epoch,device_epoch,credential_version,token_digest,state,expires_at FROM hub_account_sessions_v1 WHERE session_id=?`, b.SessionID).Scan(&session.ID, &session.AccountID, &session.OwnerID, &session.DeviceID, &session.Epoch, &session.DeviceEpoch, &session.CredentialVersion, &session.TokenDigest, &session.State, &session.ExpiresAt)
	if err != nil || session.State != "ACTIVE" || session.AccountID != b.AccountID || session.OwnerID != b.OwnerID || session.DeviceID != b.DeviceID || uint64(session.Epoch) != b.AccountEpoch || uint64(session.DeviceEpoch) != b.DeviceEpoch || uint64(session.CredentialVersion) != b.CredentialVersion || !appNodeBefore(at, session.ExpiresAt) {
		return ErrHubAccountRejected
	}
	return nil
}

func appBindingFreshDevice(tx *sql.Tx, b wire.AppBinding) bool {
	var count int
	// Include all retained keys, including revoked identities. A retired ID or
	// public key can never be recycled through the replacement path.
	raw, _ := json.Marshal(b.DevicePublic)
	return tx.QueryRow(`SELECT (SELECT count(*) FROM client_devices_v2 WHERE device_id=? OR key_id=? OR public_identity_json=?)+(SELECT count(*) FROM hub_account_devices_v1 WHERE device_id=? OR public_identity_json=?)+(SELECT count(*) FROM owner_approval_keys_v2 WHERE key_id=? OR public_identity_json=?)`, b.DeviceID, b.DevicePublic.ID, string(raw), b.DeviceID, string(raw), b.DevicePublic.ID, string(raw)).Scan(&count) == nil && count == 0
}

type appUnbound struct {
	binding                     wire.AppBinding
	state, replacement, restore string
	deviceEpoch, version, epoch uint64
}

func appBindingUnbound(tx *sql.Tx, owner, device string) (*appUnbound, error) {
	var u appUnbound
	var raw string
	err := tx.QueryRow(`SELECT binding_json,state,replacement_device_id,restore_receipt,post_device_epoch,post_client_version,post_client_epoch FROM hub_app_unbound_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&raw, &u.state, &u.replacement, &u.restore, &u.deviceEpoch, &u.version, &u.epoch)
	if err != nil || json.Unmarshal([]byte(raw), &u.binding) != nil {
		return nil, ErrHubAccountRejected
	}
	return &u, nil
}
func appBindingPrevious(tx *sql.Tx, b wire.AppBinding, restore string) (*appUnbound, error) {
	u, err := appBindingUnbound(tx, b.OwnerID, b.PreviousDeviceID)
	if err != nil || u.state != "UNBOUND" || u.restore != restore || u.binding.Digest() != b.UnbindBindingDigest || u.binding.HubID != b.HubID || u.binding.HubFingerprint != b.HubFingerprint || u.binding.Origin != b.Origin || u.binding.AccountID != b.AccountID || u.binding.OwnerID != b.OwnerID || !reflect.DeepEqual(u.binding.OwnerPublic, b.OwnerPublic) || u.binding.OwnerKeyVersion != b.OwnerKeyVersion || u.binding.AccountEpoch != b.AccountEpoch || u.binding.CredentialVersion != b.CredentialVersion || !appBindingHistoricalSource(tx, u.binding.OwnerID, u.binding.DeviceID, u.binding.OwnerPublic.ID, b.HubID) {
		return nil, ErrHubAccountRejected
	}
	return u, nil
}

func appBindingPrepare(tx *sql.Tx, in HubAppBindingInput, r appBindingRequest, setup *HubOwnerSetup, epoch int64, restore string, c *HubAccountCredential, fp string, public []byte, digest string, at time.Time, body any) ([]byte, error) {
	var oldOp, oldDigest, oldPublic string
	var cached []byte
	err := tx.QueryRow(`SELECT operation,request_digest,device_public_json,response_packet FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND prepare_id=?`, r.owner, r.device, r.id).Scan(&oldOp, &oldDigest, &oldPublic, &cached)
	if err == nil {
		if oldOp != in.Operation || oldDigest != digest || oldPublic != string(public) || len(cached) == 0 {
			return nil, ErrHubAccountRejected
		}
		return append([]byte(nil), cached...), nil
	}
	if !errors.Is(err, sql.ErrNoRows) || !appBindingFresh(r.issued, at) {
		return nil, ErrHubAccountRejected
	}
	key, err := appBindingRoot(tx, r.owner, r.ownerPublic)
	if err != nil {
		return nil, err
	}
	b := wire.AppBinding{Format: wire.AppBindingFormat, Origin: setup.Origin, HubID: setup.HubID, HubFingerprint: fp, AccountID: setup.AccountID, OwnerID: setup.OwnerID, OwnerPublic: r.ownerPublic, OwnerKeyVersion: uint64(key.Version), AccountEpoch: uint64(epoch), CredentialVersion: uint64(c.Version), DeviceID: r.device, DevicePublic: in.DevicePublic, PrepareRequestID: r.id, PreparePacketDigest: digest, IssuedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(at.Add(wire.MaxAppBindingChallengeLifetime))}
	switch q := body.(type) {
	case wire.AppUnbindPrepare:
		b.Purpose = wire.AppBindingPurposeUnbind
		b.DeviceEpoch = q.DeviceEpoch
		if q.AccountEpoch != uint64(epoch) {
			return nil, ErrHubAccountRejected
		}
		client, err := scanClientDevice(tx.QueryRow(clientDeviceSelect+` WHERE owner_id=? AND device_id=?`, r.owner, r.device))
		if err != nil {
			return nil, ErrHubAccountRejected
		}
		b.ClientDeviceVersion, b.ClientSessionEpoch = uint64(client.Version), client.SessionEpoch
		var expiry string
		if tx.QueryRow(`SELECT session_id,expires_at FROM hub_account_sessions_v1 WHERE token_digest=?`, AccountDigest("session-token", q.SessionToken)).Scan(&b.SessionID, &expiry) != nil || appBindingSelf(tx, b, at) != nil {
			return nil, ErrHubAccountRejected
		}
		end, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil {
			return nil, ErrHubAccountRejected
		}
		if end.Before(at.Add(wire.MaxAppBindingChallengeLifetime)) {
			b.ExpiresAt = appNodeStamp(end)
		}
	case wire.AppRebindPrepare:
		b.Purpose = wire.AppBindingPurposeRebind
		b.DeviceEpoch, b.ClientDeviceVersion, b.ClientSessionEpoch = 1, 1, 1
		b.PreviousDeviceID, b.UnbindBindingDigest = q.PreviousDeviceID, q.UnbindBindingDigest
		u, err := appBindingPrevious(tx, b, restore)
		if err != nil || u.replacement != "" || !appBindingFreshDevice(tx, b) {
			return nil, ErrHubAccountRejected
		}
	default:
		return nil, ErrHubAccountRejected
	}
	if wire.ValidateAppBinding(b, at) != nil {
		return nil, ErrHubAccountRejected
	}
	// Unproved candidates may consume only a finite challenge cache. Its TTL
	// outlasts request freshness (or the unbind session itself). An evicted
	// prepare can never authorize complete; completion floors are permanent.
	if err = appBindingCollectPrepares(tx, at); err != nil {
		return nil, err
	}
	var live int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1`).Scan(&live); err != nil {
		return nil, err
	}
	if live >= 256 {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	if err = tx.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED'`, r.owner, r.device).Scan(&live); err != nil {
		return nil, err
	}
	if live >= 4 {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	if b.PreviousDeviceID != "" {
		if err = tx.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1 WHERE operation=? AND state='PREPARED' AND json_extract(binding_json,'$.previous_device_id')=?`, wire.OperationAppRebindPrepare, b.PreviousDeviceID).Scan(&live); err != nil {
			return nil, err
		}
		if live >= 8 {
			return nil, ErrHubOwnerDiagnosticsFull
		}
	}
	challenge, ownerNonce, err := in.Challenge(b, r.nonce, at)
	if err != nil || !reflect.DeepEqual(challenge.Binding, b) || wire.ValidateAppBindingChallenge(challenge, in.Hub, at) != nil {
		return nil, ErrHubAccountRejected
	}
	packet, err := in.Seal(challenge)
	if err != nil {
		return nil, err
	}
	bindJSON, _ := json.Marshal(b)
	pairJSON, _ := json.Marshal(challenge.Proof)
	_, err = tx.Exec(`INSERT INTO hub_app_binding_prepares_v1(owner_id,device_id,prepare_id,operation,request_digest,nonce_digest,device_public_json,binding_digest,binding_json,pairing_json,owner_nonce_digest,device_nonce_digest,response_packet,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PREPARED')`, r.owner, r.device, r.id, in.Operation, digest, AccountDigest("app-binding-nonce", r.nonce), string(public), b.Digest(), string(bindJSON), string(pairJSON), ownerNonce, AccountDigest("app-binding-server-nonce", challenge.ServerNonce), packet, b.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func appBindingPair(b wire.AppBinding, hub wire.HubIdentity, allow bool) ownerbootstrap.PairingFile {
	return ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: b.Origin, AllowLoopbackHTTP: allow, Hub: hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: b.AccountID, OwnerID: b.OwnerID, HubID: b.HubID, AuthorityID: b.PrepareRequestID, OperationID: b.Digest(), CandidatePublic: b.OwnerPublic, CandidateFingerprint: ownerbootstrap.Fingerprint(b.OwnerPublic), ExpiresAt: b.ExpiresAt}}
}

func appBindingComplete(tx *sql.Tx, in HubAppBindingInput, r appBindingRequest, setup *HubOwnerSetup, epoch int64, restore string, c *HubAccountCredential, fp string, public []byte, digest string, at time.Time, q wire.AppBindingComplete) ([]byte, error) {
	b := q.Binding
	if wire.ValidateAppBinding(b, time.Time{}) != nil || !reflect.DeepEqual(b.DevicePublic, in.DevicePublic) || b.PreparePacketDigest != wire.AppBindingPacketDigest(q.PreparePacket) || b.HubFingerprint != fp {
		return nil, ErrHubAccountRejected
	}
	var terminal, prepareIDCollision int
	if err := tx.QueryRow(`SELECT count(*) FROM hub_app_binding_operations_v1 WHERE binding_digest=?`, b.Digest()).Scan(&terminal); err != nil {
		return nil, err
	}
	if terminal != 0 {
		return nil, ErrHubAccountRejected
	}
	if err := tx.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND prepare_id=?`, r.owner, r.device, r.id).Scan(&prepareIDCollision); err != nil {
		return nil, err
	}
	if prepareIDCollision != 0 {
		return nil, ErrHubAccountRejected
	}
	var bindingJSON, pairingJSON, ownerNonce, deviceNonce, state string
	err := tx.QueryRow(`SELECT binding_json,pairing_json,owner_nonce_digest,device_nonce_digest,state FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND prepare_id=? AND request_digest=?`, r.owner, r.device, b.PrepareRequestID, b.PreparePacketDigest).Scan(&bindingJSON, &pairingJSON, &ownerNonce, &deviceNonce, &state)
	admitted := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	// Without a retained pending admission, a restored database cannot prove
	// that an absent historical action had no effect. Never invent a floor.
	if (!admitted && b.AccountEpoch != uint64(epoch) && restore != "") || (admitted && state != "PREPARED") {
		return nil, ErrHubAccountRejected
	}
	var saved wire.AppBinding
	if admitted && (json.Unmarshal([]byte(bindingJSON), &saved) != nil || !reflect.DeepEqual(saved, b) || subtle.ConstantTimeCompare([]byte(deviceNonce), []byte(AccountDigest("app-binding-server-nonce", q.ServerNonce))) != 1) {
		return nil, ErrHubAccountRejected
	}
	pair := appBindingPair(b, in.Hub, setup.AllowLoopbackHTTP)
	if admitted && pairingJSON != "" && json.Unmarshal([]byte(pairingJSON), &pair) != nil {
		return nil, ErrHubAccountRejected
	}
	if !admitted {
		// A self-signed caller-chosen fake Owner is not an account actor and
		// cannot allocate permanent refusal floors, even if its proof opens.
		trusted, err := appBindingRoot(tx, r.owner, b.OwnerPublic)
		if err != nil || uint64(trusted.Version) != b.OwnerKeyVersion || b.AccountEpoch != uint64(epoch) || b.CredentialVersion != uint64(c.Version) {
			return nil, ErrHubAccountRejected
		}
	}
	// Historical proof verification authenticates a refusal only. Actual
	// eligibility uses the trusted writer time below, never the caller clock.
	proofAt, _ := time.Parse(time.RFC3339Nano, b.IssuedAt)
	nonce, err := in.VerifyProof(pair, q.OwnerProof, proofAt)
	if err != nil || (admitted && subtle.ConstantTimeCompare([]byte(nonce), []byte(ownerNonce)) != 1) {
		return nil, ErrHubAccountRejected
	}
	code := ""
	if !admitted {
		code = "NOT_ADMITTED"
	} else if b.AccountEpoch != uint64(epoch) && restore != "" {
		code = "RESTORE_FENCED"
	} else if !appNodeBefore(at, b.ExpiresAt) || !appBindingFresh(r.issued, at) {
		code = "EXPIRED"
	}
	key, keyErr := appBindingRoot(tx, r.owner, b.OwnerPublic)
	if code == "" && keyErr != nil {
		code = "OWNER_REVOKED"
	}
	if code == "" && (b.AccountEpoch != uint64(epoch) || b.CredentialVersion != uint64(c.Version) || uint64(key.Version) != b.OwnerKeyVersion) {
		code = "STALE_SCOPE"
	}
	if code == "" {
		if b.Purpose == wire.AppBindingPurposeUnbind {
			if appBindingSelf(tx, b, at) != nil {
				code = "DEVICE_INACTIVE"
			}
		} else {
			u, e := appBindingPrevious(tx, b, restore)
			if e != nil {
				code = "STALE_SCOPE"
			} else if u.replacement != "" {
				code = "ALREADY_REPLACED"
			} else if !appBindingFreshDevice(tx, b) {
				code = "DEVICE_INACTIVE"
			}
		}
	}
	var usedNonce int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_app_binding_operations_v1 WHERE owner_id=? AND device_id=? AND nonce_digest=?`, r.owner, r.device, AccountDigest("app-binding-nonce", r.nonce)).Scan(&usedNonce); err != nil {
		return nil, err
	}
	if code == "" && usedNonce != 0 {
		code = "STALE_SCOPE"
	}
	// Only an authenticated current/retained Owner reaches this permanent
	// ledger. Bound total records/bytes before either effect or refusal.
	var receiptCount, receiptBytes int64
	if err = tx.QueryRow(`SELECT count(*),coalesce(sum(length(response_packet)+length(device_public_json)),0) FROM hub_app_binding_operations_v1`).Scan(&receiptCount, &receiptBytes); err != nil {
		return nil, err
	}
	if receiptCount >= 16384 || receiptBytes >= 64<<20 {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	result := wire.AppBindingResult{Format: wire.AppBindingResultFormat, Operation: in.Operation, RequestID: r.id, RequestPacketDigest: digest, State: wire.AppBindingRejected, ErrorCode: code, BindingDigest: b.Digest(), DeviceID: b.DeviceID, ObservedAt: appNodeStamp(at)}
	if code == "" {
		result.State = wire.AppBindingUnbound
		result.DeviceEpoch, result.ClientDeviceVersion, result.ClientSessionEpoch = b.DeviceEpoch+1, b.ClientDeviceVersion+1, b.ClientSessionEpoch+1
		if b.Purpose == wire.AppBindingPurposeRebind {
			result.State = wire.AppBindingBoundZero
			result.DeviceEpoch, result.ClientDeviceVersion, result.ClientSessionEpoch = 1, 1, 1
		}
	}
	if code == "" {
		if b.Purpose == wire.AppBindingPurposeUnbind {
			err = appBindingApplyUnbind(tx, b, q.OwnerProof, restore, at)
		} else {
			err = appBindingApplyRebind(tx, b, q.OwnerProof, restore, at)
		}
		if err != nil {
			return nil, err
		}
	}
	packet, err := in.Seal(result)
	if err != nil {
		return nil, err
	}
	if len(packet) == 0 || len(packet) > wire.MaxPacketBytes || receiptBytes+int64(len(packet)+len(public)) > 64<<20 {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	// Refusal does not consume a reused nonce as authority, but its exact ID
	// remains fenced. Give each refused original a distinct digest-domain floor.
	nd := AccountDigest("app-binding-nonce", r.nonce)
	if code != "" {
		nd = AccountDigest("app-binding-rejected-original", in.Packet)
	}
	_, err = tx.Exec(`INSERT INTO hub_app_binding_operations_v1(owner_id,device_id,operation_id,operation,request_digest,nonce_digest,device_public_json,binding_digest,state,response_packet) VALUES(?,?,?,?,?,?,?,?,?,?)`, r.owner, r.device, r.id, in.Operation, digest, nd, string(public), b.Digest(), result.State, packet)
	if err != nil {
		return nil, err
	}
	if admitted && state == "PREPARED" {
		next := "CONSUMED"
		if code != "" {
			next = "REJECTED"
		}
		if _, err = tx.Exec(`UPDATE hub_app_binding_prepares_v1 SET state=? WHERE owner_id=? AND device_id=? AND prepare_id=? AND state='PREPARED'`, next, r.owner, r.device, b.PrepareRequestID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func appBindingApplyUnbind(tx *sql.Tx, b wire.AppBinding, proof []byte, restore string, at time.Time) error {
	stamp := appNodeStamp(at)
	accountResult, err := tx.Exec(`UPDATE hub_account_devices_v1 SET status='REVOKED',epoch=epoch+1 WHERE account_id=? AND device_id=? AND status='ACTIVE' AND epoch=?`, b.AccountID, b.DeviceID, b.DeviceEpoch)
	if err != nil {
		return err
	}
	if n, e := accountResult.RowsAffected(); e != nil || n != 1 {
		return ErrVersionConflict
	}
	result, err := tx.Exec(`UPDATE client_devices_v2 SET state='REVOKED',version=version+1,session_epoch=session_epoch+1,updated_at=?,revoked_at=? WHERE owner_id=? AND device_id=? AND state='ACTIVE' AND version=? AND session_epoch=?`, stamp, stamp, b.OwnerID, b.DeviceID, b.ClientDeviceVersion, b.ClientSessionEpoch)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrVersionConflict
	}
	for _, v := range []struct {
		query string
		args  []any
	}{
		{`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE account_id=? AND device_id=? AND state='ACTIVE'`, []any{b.AccountID, b.DeviceID}},
		{`UPDATE hub_account_attempts_v1 SET state='CANCELLED' WHERE account_id=? AND device_id=? AND state='PENDING'`, []any{b.AccountID, b.DeviceID}},
		{`UPDATE hub_owner_activation_v1 SET state='CANCELLED' WHERE account_id=? AND state='PREPARED' AND json_extract(binding_json,'$.device_id')=?`, []any{b.AccountID, b.DeviceID}},
		{`UPDATE hub_app_leases_v1 SET state='REVOKED' WHERE owner_id=? AND device_id=? AND state='ACTIVE'`, []any{b.OwnerID, b.DeviceID}},
		{`UPDATE hub_app_node_grants_v1 SET state='REVOKED',reason='VOLUNTARY_APP_UNBIND' WHERE owner_id=? AND device_id=? AND state IN('PREPARED','ACTIVE')`, []any{b.OwnerID, b.DeviceID}},
	} {
		if _, err = tx.Exec(v.query, v.args...); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(b)
	_, err = tx.Exec(`INSERT INTO hub_app_unbound_v1(owner_id,device_id,binding_digest,binding_json,owner_proof,restore_receipt,post_device_epoch,post_client_version,post_client_epoch,state) VALUES(?,?,?,?,?,?,?,?,?,'UNBOUND')`, b.OwnerID, b.DeviceID, b.Digest(), string(raw), proof, restore, b.DeviceEpoch+1, b.ClientDeviceVersion+1, b.ClientSessionEpoch+1)
	return err
}

func appBindingApplyRebind(tx *sql.Tx, b wire.AppBinding, proof []byte, restore string, at time.Time) error {
	result, err := tx.Exec(`UPDATE hub_app_unbound_v1 SET replacement_device_id=? WHERE owner_id=? AND device_id=? AND binding_digest=? AND state='UNBOUND' AND replacement_device_id=''`, b.DeviceID, b.OwnerID, b.PreviousDeviceID, b.UnbindBindingDigest)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrVersionConflict
	}
	public, _ := json.Marshal(b.DevicePublic)
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(b.DevicePublic)
	if err != nil {
		return err
	}
	stamp := appNodeStamp(at)
	if _, err = tx.Exec(`INSERT INTO hub_account_devices_v1(account_id,owner_id,device_id,public_identity_json,epoch,status,created_at) VALUES(?,?,?,?,1,'ACTIVE',?)`, b.AccountID, b.OwnerID, b.DeviceID, string(public), stamp); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO client_devices_v2(owner_id,device_id,public_identity_json,key_id,key_fingerprint,key_version,owner_key_id,state,version,session_epoch,last_request_sequence,next_response_sequence,created_at,updated_at) VALUES(?,?,?,?,?,1,?,'ACTIVE',1,1,0,1,?,?)`, b.OwnerID, b.DeviceID, string(public), b.DevicePublic.ID, fingerprint, b.OwnerPublic.ID, stamp, stamp); err != nil {
		return err
	}
	raw, _ := json.Marshal(b)
	_, err = tx.Exec(`INSERT INTO hub_app_rebound_v1(owner_id,device_id,unbind_binding_digest,binding_json,owner_proof,restore_receipt) VALUES(?,?,?,?,?,?)`, b.OwnerID, b.DeviceID, b.UnbindBindingDigest, string(raw), proof, restore)
	return err
}
