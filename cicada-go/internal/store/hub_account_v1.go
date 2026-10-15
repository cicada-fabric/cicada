package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

var ErrHubAccountRejected = errors.New("Hub account authentication rejected")

// Account auth is independent of approval keys and Client management devices.
// All tokens/nonces/passwords are supplied as digests or salted verifiers.
type HubAccountClaim struct {
	ID, AccountID, OwnerID, HubID, Origin, HubPin, CodeDigest, State, ExpiresAt string
	Epoch                                                                       int64
	AttemptID                                                                   string
}
type HubAccountDevice struct {
	AccountID, OwnerID, DeviceID, State, CreatedAt string
	Public                                         e2ee.PublicIdentity
	Epoch                                          int64
}
type HubAccountAttempt struct {
	ID, Purpose, ClaimID, AccountID, OwnerID, DeviceID, PrepareID, PrepareDigest, ChallengeDigest, ExpiresAt, State, CompleteID, CompleteDigest, SessionID string
	PrepareNonceDigest, CompleteNonceDigest                                                                                                                string
	Epoch, DeviceEpoch                                                                                                                                     int64
	DevicePublic                                                                                                                                           e2ee.PublicIdentity
	ChallengePacket, ReceiptPacket                                                                                                                         []byte
}
type HubAccountCredential struct {
	AccountID, OwnerID, Username, Algorithm string
	Salt, Verifier                          []byte
	Version                                 int64
}
type HubAccountSession struct {
	ID, AccountID, OwnerID, DeviceID, TokenDigest, State, ExpiresAt string
	Epoch, DeviceEpoch, CredentialVersion                           int64
}

func (s *Store) initializeHubAccountSchema() error {
	_, e := s.db.Exec(`
CREATE TABLE hub_account_config_v1(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL CHECK(epoch>0),restore_receipt TEXT NOT NULL DEFAULT '');
INSERT INTO hub_account_config_v1 VALUES(1,1,'');
CREATE TABLE hub_account_claims_v1(claim_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,owner_id TEXT NOT NULL,hub_id TEXT NOT NULL,origin TEXT NOT NULL,hub_pin TEXT NOT NULL,code_digest TEXT NOT NULL CHECK(length(code_digest)=64),epoch INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('ISSUED','PREPARED','CONSUMED','CANCELLED')),expires_at TEXT NOT NULL,attempt_id TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX hub_account_claims_v1_one_pending ON hub_account_claims_v1(account_id) WHERE state IN('ISSUED','PREPARED');
CREATE TABLE hub_account_credentials_v1(account_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,username TEXT NOT NULL UNIQUE,algorithm TEXT NOT NULL,salt BLOB NOT NULL CHECK(length(salt)=32),verifier BLOB NOT NULL CHECK(length(verifier)=32),version INTEGER NOT NULL CHECK(version>0));
CREATE TABLE hub_account_devices_v1(account_id TEXT NOT NULL,owner_id TEXT NOT NULL,device_id TEXT NOT NULL,public_identity_json TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>0),status TEXT NOT NULL CHECK(status IN('ACTIVE','REVOKED')),created_at TEXT NOT NULL,PRIMARY KEY(account_id,device_id));
CREATE TABLE hub_account_public_association_v1(account_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,public_identity_json TEXT NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL CHECK(state='PENDING_PROOF'));
CREATE TABLE hub_account_attempts_v1(attempt_id TEXT PRIMARY KEY,purpose TEXT NOT NULL CHECK(purpose IN('CLAIM','LOGIN')),claim_id TEXT NOT NULL,account_id TEXT NOT NULL,owner_id TEXT NOT NULL,device_id TEXT NOT NULL,public_identity_json TEXT NOT NULL,epoch INTEGER NOT NULL,device_epoch INTEGER NOT NULL,prepare_id TEXT NOT NULL UNIQUE,prepare_digest TEXT NOT NULL,challenge_digest TEXT NOT NULL,challenge_packet BLOB NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PENDING','CONSUMED','CANCELLED')),complete_id TEXT NOT NULL DEFAULT '',request_digest TEXT NOT NULL DEFAULT '',response_packet BLOB,session_id TEXT NOT NULL DEFAULT '',prepare_nonce_digest TEXT NOT NULL CHECK(length(prepare_nonce_digest)=64),complete_nonce_digest TEXT NOT NULL DEFAULT '' CHECK(complete_nonce_digest='' OR length(complete_nonce_digest)=64));
CREATE UNIQUE INDEX hub_account_attempts_v1_one_pending ON hub_account_attempts_v1(account_id,device_id,purpose) WHERE state='PENDING';
CREATE UNIQUE INDEX hub_account_attempts_v1_prepare_nonce ON hub_account_attempts_v1(account_id,device_id,prepare_nonce_digest);
CREATE UNIQUE INDEX hub_account_attempts_v1_complete_nonce ON hub_account_attempts_v1(account_id,device_id,complete_nonce_digest) WHERE complete_nonce_digest!='';
CREATE INDEX hub_account_attempts_v1_completion_replay ON hub_account_attempts_v1(complete_id,request_digest) WHERE purpose='LOGIN' AND state='CONSUMED';
CREATE TABLE hub_account_sessions_v1(session_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,owner_id TEXT NOT NULL,device_id TEXT NOT NULL,epoch INTEGER NOT NULL,device_epoch INTEGER NOT NULL,credential_version INTEGER NOT NULL,token_digest TEXT NOT NULL CHECK(length(token_digest)=64),state TEXT NOT NULL CHECK(state IN('ACTIVE','REVOKED')),expires_at TEXT NOT NULL);
CREATE UNIQUE INDEX hub_account_sessions_v1_token_digest ON hub_account_sessions_v1(token_digest);
CREATE INDEX hub_account_sessions_v1_account_device_state ON hub_account_sessions_v1(account_id,device_id,state);
CREATE TABLE hub_account_requests_v1(session_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,response_packet BLOB NOT NULL,nonce_digest TEXT NOT NULL CHECK(length(nonce_digest)=64),PRIMARY KEY(session_id,operation_id));
CREATE UNIQUE INDEX hub_account_requests_v1_nonce ON hub_account_requests_v1(session_id,nonce_digest);
CREATE INDEX hub_account_requests_v1_operation_replay ON hub_account_requests_v1(operation_id,operation,request_digest,session_id);
CREATE TRIGGER hub_account_config_v1_no_delete BEFORE DELETE ON hub_account_config_v1 BEGIN SELECT RAISE(ABORT,'Account epoch is permanent'); END;
CREATE TRIGGER hub_account_config_v1_monotone BEFORE UPDATE ON hub_account_config_v1 WHEN NEW.epoch<OLD.epoch BEGIN SELECT RAISE(ABORT,'Account epoch cannot decrease'); END;
CREATE TRIGGER hub_account_claims_v1_no_delete BEFORE DELETE ON hub_account_claims_v1 BEGIN SELECT RAISE(ABORT,'Claim history is permanent'); END;
CREATE TRIGGER hub_account_claims_v1_coordinates BEFORE UPDATE ON hub_account_claims_v1 WHEN NEW.claim_id!=OLD.claim_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.code_digest!=OLD.code_digest OR NEW.epoch!=OLD.epoch OR NEW.hub_id!=OLD.hub_id OR NEW.origin!=OLD.origin OR NEW.hub_pin!=OLD.hub_pin OR NEW.expires_at!=OLD.expires_at OR (OLD.state IN('CONSUMED','CANCELLED') AND NEW.state!=OLD.state) BEGIN SELECT RAISE(ABORT,'Claim authority is immutable'); END;
CREATE TRIGGER hub_account_devices_v1_coordinates BEFORE UPDATE ON hub_account_devices_v1 WHEN NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.public_identity_json!=OLD.public_identity_json OR NEW.epoch<OLD.epoch OR (OLD.status='REVOKED' AND NEW.status!='REVOKED') BEGIN SELECT RAISE(ABORT,'Account device identity is immutable'); END;
CREATE TRIGGER hub_account_public_association_v1_no_update BEFORE UPDATE ON hub_account_public_association_v1 BEGIN SELECT RAISE(ABORT,'Public association is immutable'); END;
CREATE TRIGGER hub_account_public_association_v1_no_delete BEFORE DELETE ON hub_account_public_association_v1 BEGIN SELECT RAISE(ABORT,'Public association is permanent'); END;
CREATE TRIGGER hub_account_credentials_v1_coordinates BEFORE UPDATE ON hub_account_credentials_v1 WHEN NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.version<OLD.version BEGIN SELECT RAISE(ABORT,'Account coordinates are immutable'); END;
CREATE TRIGGER hub_account_attempts_v1_coordinates BEFORE UPDATE ON hub_account_attempts_v1 WHEN NEW.attempt_id!=OLD.attempt_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.public_identity_json!=OLD.public_identity_json OR NEW.epoch!=OLD.epoch OR NEW.device_epoch!=OLD.device_epoch OR NEW.prepare_id!=OLD.prepare_id OR NEW.prepare_digest!=OLD.prepare_digest OR NEW.challenge_digest!=OLD.challenge_digest OR NEW.challenge_packet!=OLD.challenge_packet OR NEW.expires_at!=OLD.expires_at OR NEW.prepare_nonce_digest!=OLD.prepare_nonce_digest OR (OLD.complete_nonce_digest!='' AND NEW.complete_nonce_digest!=OLD.complete_nonce_digest) OR OLD.state!='PENDING' BEGIN SELECT RAISE(ABORT,'Account challenge is immutable'); END;
CREATE TRIGGER hub_account_requests_v1_no_update BEFORE UPDATE ON hub_account_requests_v1 BEGIN SELECT RAISE(ABORT,'Account response is immutable'); END;
CREATE TRIGGER hub_account_requests_v1_no_delete BEFORE DELETE ON hub_account_requests_v1 BEGIN SELECT RAISE(ABORT,'Account replay history is permanent'); END;
`)
	return e
}
func accountStampValid(stamp string) bool {
	at, e := time.Parse(time.RFC3339Nano, stamp)
	return e == nil && time.Now().UTC().Before(at)
}
func accountHashValid(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && strings.ToLower(v) == v
}
func accountIDValid(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 16 && strings.ToLower(v) == v
}
func AccountDigest(domain string, data []byte) string {
	h := sha256.New()
	h.Write([]byte("cicada/hub-account/" + domain + "/v1\x00"))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
func hubAccountNonceUsed(q hubOwnerQuerier, account, device, digest string) (bool, error) {
	var used int
	e := q.QueryRow(`SELECT EXISTS(
 SELECT 1 FROM hub_owner_operations_v1 WHERE account_id=? AND device_id=? AND nonce_digest=? UNION ALL
		SELECT 1 FROM hub_account_attempts_v1 WHERE account_id=? AND device_id=? AND (prepare_nonce_digest=? OR complete_nonce_digest=?)
		UNION ALL
		SELECT 1 FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id WHERE s.account_id=? AND s.device_id=? AND r.nonce_digest=?
	)`, account, device, digest, account, device, digest, digest, account, device, digest).Scan(&used)
	return used != 0, e
}
func accountEpoch(q hubOwnerQuerier) (int64, error) {
	var epoch int64
	e := q.QueryRow(`SELECT epoch FROM hub_account_config_v1 WHERE id=1`).Scan(&epoch)
	return epoch, e
}
func accountSetup(q hubOwnerQuerier, rootAbsent bool) (*HubOwnerSetup, error) {
	r, e := hubOwnerSetup(q)
	if e != nil {
		return nil, e
	}
	if r == nil || r.State != HubOwnerReady || !activeSelfOwnedHuman(q, r.OwnerID) {
		return nil, ErrHubAccountRejected
	}
	var id string
	if q.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&id) != nil || id != r.HubID {
		return nil, ErrHubAccountRejected
	}
	if rootAbsent && r.RootEverEstablished {
		return nil, ErrHubAccountRejected
	}
	return r, nil
}

// ReconcileHubAccountRestore fences runtime authority after a verified handover.
// No archived credentials, pending public keys, IDs or Root history are erased.
func (s *Store) ReconcileHubAccountRestore() error {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return e
	}
	state := s.maintenance.lock.Path()
	p := hubRestoreTargetLocatorPath(state)
	if _, e := os.Lstat(p); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	path, e := hubRestoreLocate(state)
	if e != nil {
		return e
	}
	a, e := hubRestoreReadAuthority(path)
	if e != nil {
		return e
	}
	if e = hubRestoreVerifyStartupAuthority(state, a, path); e != nil {
		return e
	}
	return s.fenceHubAccountRestore(a.ActivationReceiptSHA256)
}
func (s *Store) fenceHubAccountRestore(receipt string) error {
	if !accountHashValid(receipt) {
		return ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var prior string
	if e = tx.QueryRow(`SELECT restore_receipt FROM hub_account_config_v1 WHERE id=1`).Scan(&prior); e != nil {
		return e
	}
	if prior == receipt {
		return nil
	}
	for _, statement := range []string{`UPDATE hub_account_config_v1 SET epoch=epoch+1,restore_receipt=? WHERE id=1`, `UPDATE hub_account_claims_v1 SET state='CANCELLED' WHERE state IN('ISSUED','PREPARED')`, `UPDATE hub_account_attempts_v1 SET state='CANCELLED' WHERE state='PENDING'`, `UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE state='ACTIVE'`, `UPDATE hub_owner_activation_v1 SET state='CANCELLED' WHERE state IN('ISSUED','PREPARED')`, `UPDATE hub_app_leases_v1 SET state='REVOKED' WHERE state='ACTIVE'`} {
		if strings.Contains(statement, "restore_receipt") {
			_, e = tx.Exec(statement, receipt)
		} else {
			_, e = tx.Exec(statement)
		}
		if e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) HubAccountSetup() (*HubOwnerSetup, int64, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, 0, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil {
		return nil, 0, e
	}
	epoch, e := accountEpoch(s.db)
	return r, epoch, e
}
func (s *Store) IssueHubAccountClaimLocal(c HubAccountClaim, cancel bool) error {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return e
	}
	if !accountIDValid(c.ID) || !accountHashValid(c.CodeDigest) || !accountHashValid(c.HubPin) || !accountStampValid(c.ExpiresAt) {
		return ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := accountSetup(tx, true)
	if e != nil {
		return e
	}
	epoch, e := accountEpoch(tx)
	if e != nil {
		return e
	}
	if c.AccountID != r.AccountID || c.OwnerID != r.OwnerID || c.HubID != r.HubID || c.Origin != r.Origin || c.Epoch != epoch {
		return ErrHubAccountRejected
	}
	var n int
	if e = tx.QueryRow(`SELECT count(*) FROM hub_account_credentials_v1 WHERE account_id=?`, r.AccountID).Scan(&n); e != nil || n != 0 {
		return ErrHubAccountRejected
	}
	var n2 int
	if tx.QueryRow(`SELECT count(*) FROM hub_owner_activation_v1 WHERE account_id=? AND state IN('ISSUED','PREPARED')`, r.AccountID).Scan(&n2) != nil || n2 != 0 {
		return ErrHubAccountRejected
	}
	if cancel {
		if _, e = tx.Exec(`UPDATE hub_account_claims_v1 SET state='CANCELLED' WHERE account_id=? AND state IN('ISSUED','PREPARED')`, r.AccountID); e != nil {
			return e
		}
		if _, e = tx.Exec(`UPDATE hub_account_attempts_v1 SET state='CANCELLED' WHERE account_id=? AND purpose='CLAIM' AND state='PENDING'`, r.AccountID); e != nil {
			return e
		}
	}
	_, e = tx.Exec(`INSERT INTO hub_account_claims_v1(claim_id,account_id,owner_id,hub_id,origin,hub_pin,code_digest,epoch,state,expires_at) VALUES(?,?,?,?,?,?,?,?,'ISSUED',?)`, c.ID, c.AccountID, c.OwnerID, c.HubID, c.Origin, c.HubPin, c.CodeDigest, c.Epoch, c.ExpiresAt)
	if e != nil {
		return ErrHubAccountRejected
	}
	return tx.Commit()
}
func accountClaim(q hubOwnerQuerier, id string) (*HubAccountClaim, error) {
	var c HubAccountClaim
	e := q.QueryRow(`SELECT claim_id,account_id,owner_id,hub_id,origin,hub_pin,code_digest,epoch,state,expires_at,attempt_id FROM hub_account_claims_v1 WHERE claim_id=?`, id).Scan(&c.ID, &c.AccountID, &c.OwnerID, &c.HubID, &c.Origin, &c.HubPin, &c.CodeDigest, &c.Epoch, &c.State, &c.ExpiresAt, &c.AttemptID)
	if e != nil {
		return nil, ErrHubAccountRejected
	}
	return &c, nil
}
func (s *Store) HubAccountClaim(id string) (*HubAccountClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, true)
	if e != nil {
		return nil, e
	}
	c, e := accountClaim(s.db, id)
	if e != nil {
		return nil, e
	}
	epoch, e := accountEpoch(s.db)
	if e != nil || c.AccountID != r.AccountID || c.Epoch != epoch || c.State == "CANCELLED" {
		return nil, ErrHubAccountRejected
	}
	if c.State != "CONSUMED" && !accountStampValid(c.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	return c, nil
}
func accountDevice(q hubOwnerQuerier, account, device string) (*HubAccountDevice, error) {
	var d HubAccountDevice
	var raw string
	e := q.QueryRow(`SELECT account_id,owner_id,device_id,public_identity_json,epoch,status,created_at FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, account, device).Scan(&d.AccountID, &d.OwnerID, &d.DeviceID, &raw, &d.Epoch, &d.State, &d.CreatedAt)
	if e != nil || json.Unmarshal([]byte(raw), &d.Public) != nil || e2ee.ValidatePublicIdentity(d.Public) != nil || d.State != "ACTIVE" {
		return nil, ErrHubAccountRejected
	}
	return &d, nil
}
func (s *Store) HubAccountDevice(account, device string) (*HubAccountDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil || r.AccountID != account {
		return nil, ErrHubAccountRejected
	}
	return accountDevice(s.db, account, device)
}
func accountCredential(q hubOwnerQuerier, account string) (*HubAccountCredential, error) {
	var c HubAccountCredential
	e := q.QueryRow(`SELECT account_id,owner_id,username,algorithm,salt,verifier,version FROM hub_account_credentials_v1 WHERE account_id=?`, account).Scan(&c.AccountID, &c.OwnerID, &c.Username, &c.Algorithm, &c.Salt, &c.Verifier, &c.Version)
	if e != nil {
		return nil, ErrHubAccountRejected
	}
	return &c, nil
}
func (s *Store) HubAccountCredential(account string) (*HubAccountCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil || r.AccountID != account {
		return nil, ErrHubAccountRejected
	}
	return accountCredential(s.db, account)
}
func accountAttempt(q hubOwnerQuerier, id string) (*HubAccountAttempt, error) {
	var a HubAccountAttempt
	var raw string
	e := q.QueryRow(`SELECT attempt_id,purpose,claim_id,account_id,owner_id,device_id,public_identity_json,epoch,device_epoch,prepare_id,prepare_digest,challenge_digest,challenge_packet,expires_at,state,complete_id,request_digest,response_packet,session_id,prepare_nonce_digest,complete_nonce_digest FROM hub_account_attempts_v1 WHERE attempt_id=?`, id).Scan(&a.ID, &a.Purpose, &a.ClaimID, &a.AccountID, &a.OwnerID, &a.DeviceID, &raw, &a.Epoch, &a.DeviceEpoch, &a.PrepareID, &a.PrepareDigest, &a.ChallengeDigest, &a.ChallengePacket, &a.ExpiresAt, &a.State, &a.CompleteID, &a.CompleteDigest, &a.ReceiptPacket, &a.SessionID, &a.PrepareNonceDigest, &a.CompleteNonceDigest)
	if e != nil || json.Unmarshal([]byte(raw), &a.DevicePublic) != nil {
		return nil, ErrHubAccountRejected
	}
	return &a, nil
}
func (s *Store) HubAccountAttempt(id string) (*HubAccountAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil {
		return nil, e
	}
	a, e := accountAttempt(s.db, id)
	if e != nil {
		return nil, e
	}
	epoch, e := accountEpoch(s.db)
	if e != nil || a.AccountID != r.AccountID || a.OwnerID != r.OwnerID || a.Epoch != epoch || a.State == "CANCELLED" {
		return nil, ErrHubAccountRejected
	}
	if a.State == "PENDING" && !accountStampValid(a.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	return a, nil
}
func (s *Store) SaveHubAccountAttempt(a HubAccountAttempt) error {
	if !accountIDValid(a.ID) || !accountIDValid(a.PrepareID) || !accountHashValid(a.PrepareDigest) || !accountHashValid(a.PrepareNonceDigest) || !accountHashValid(a.ChallengeDigest) || e2ee.ValidatePublicIdentity(a.DevicePublic) != nil || !accountStampValid(a.ExpiresAt) || len(a.ChallengePacket) == 0 || len(a.ChallengePacket) > 384*1024 {
		return ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := accountSetup(tx, a.Purpose == "CLAIM")
	if e != nil {
		return e
	}
	epoch, e := accountEpoch(tx)
	if e != nil || a.Epoch != epoch || a.AccountID != r.AccountID || a.OwnerID != r.OwnerID {
		return ErrHubAccountRejected
	}
	if e = hubAccountOperationUnfenced(tx, a.AccountID, a.DeviceID, a.PrepareID); e != nil {
		return e
	}
	if a.Purpose == "CLAIM" {
		c, e := accountClaim(tx, a.ClaimID)
		if e != nil || c.State != "ISSUED" || c.Epoch != epoch || !accountStampValid(c.ExpiresAt) {
			return ErrHubAccountRejected
		}
		if _, e = tx.Exec(`UPDATE hub_account_claims_v1 SET state='PREPARED',attempt_id=? WHERE claim_id=?`, a.ID, a.ClaimID); e != nil {
			return e
		}
	} else if a.Purpose == "LOGIN" {
		d, e := accountDevice(tx, a.AccountID, a.DeviceID)
		if e != nil || d.Epoch != a.DeviceEpoch {
			return ErrHubAccountRejected
		}
		pub, _ := json.Marshal(d.Public)
		candidate, _ := json.Marshal(a.DevicePublic)
		if string(pub) != string(candidate) {
			return ErrHubAccountRejected
		}
		if _, e = tx.Exec(`UPDATE hub_account_attempts_v1 SET state='CANCELLED' WHERE account_id=? AND device_id=? AND purpose='LOGIN' AND state='PENDING' AND expires_at<=?`, a.AccountID, a.DeviceID, now()); e != nil {
			return e
		}
	} else {
		return ErrHubAccountRejected
	}
	used, e := hubAccountNonceUsed(tx, a.AccountID, a.DeviceID, a.PrepareNonceDigest)
	if e != nil || used {
		return ErrHubAccountRejected
	}
	raw, _ := json.Marshal(a.DevicePublic)
	_, e = tx.Exec(`INSERT INTO hub_account_attempts_v1(attempt_id,purpose,claim_id,account_id,owner_id,device_id,public_identity_json,epoch,device_epoch,prepare_id,prepare_digest,challenge_digest,challenge_packet,expires_at,state,prepare_nonce_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?)`, a.ID, a.Purpose, a.ClaimID, a.AccountID, a.OwnerID, a.DeviceID, string(raw), a.Epoch, a.DeviceEpoch, a.PrepareID, a.PrepareDigest, a.ChallengeDigest, a.ChallengePacket, a.ExpiresAt, a.PrepareNonceDigest)
	if e != nil {
		return ErrHubAccountRejected
	}
	return tx.Commit()
}
func (s *Store) HubAccountAttemptByPrepare(id string) (*HubAccountAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var aID string
	if s.db.QueryRow(`SELECT attempt_id FROM hub_account_attempts_v1 WHERE prepare_id=?`, id).Scan(&aID) != nil {
		return nil, ErrHubAccountRejected
	}
	return accountAttempt(s.db, aID)
}

type HubAccountCompleteInput struct {
	AttemptID, ChallengeDigest, RequestID, RequestDigest string
	CompleteNonceDigest                                  string
	Credential                                           HubAccountCredential
	OwnerPublic                                          e2ee.PublicIdentity
	OwnerFingerprint                                     string
	Receipt                                              []byte
}

func (s *Store) CompleteHubAccountClaim(in HubAccountCompleteInput) ([]byte, error) {
	fp, fpErr := e2ee.OwnerDevicePublicKeyFingerprint(in.OwnerPublic)
	if fpErr != nil || fp != in.OwnerFingerprint {
		return nil, ErrHubAccountRejected
	}
	if len(in.Credential.Salt) != 32 || len(in.Credential.Verifier) != 32 || in.Credential.Algorithm != "PBKDF2-SHA256-600000-v1" || e2ee.ValidatePublicIdentity(in.OwnerPublic) != nil || !accountHashValid(in.OwnerFingerprint) || !accountHashValid(in.RequestDigest) || !accountHashValid(in.CompleteNonceDigest) || len(in.Receipt) == 0 || len(in.Receipt) > 384*1024 {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := accountSetup(tx, true)
	if e != nil {
		return nil, e
	}
	epoch, e := accountEpoch(tx)
	if e != nil {
		return nil, e
	}
	a, e := accountAttempt(tx, in.AttemptID)
	if e != nil || a.Purpose != "CLAIM" || a.Epoch != epoch || a.AccountID != r.AccountID {
		return nil, ErrHubAccountRejected
	}
	if a.State == "CONSUMED" {
		d, e := accountDevice(tx, a.AccountID, a.DeviceID)
		if e != nil || d.Epoch != a.DeviceEpoch || a.CompleteID != in.RequestID || a.CompleteDigest != in.RequestDigest {
			return nil, ErrHubAccountRejected
		}
		return a.ReceiptPacket, nil
	}
	c, e := accountClaim(tx, a.ClaimID)
	if e != nil || c.State != "PREPARED" || c.Epoch != epoch || c.AttemptID != a.ID || !accountStampValid(c.ExpiresAt) || a.State != "PENDING" || !accountStampValid(a.ExpiresAt) || a.ChallengeDigest != in.ChallengeDigest {
		return nil, ErrHubAccountRejected
	}
	if in.Credential.AccountID != r.AccountID || in.Credential.OwnerID != r.OwnerID || in.Credential.Version != 1 {
		return nil, ErrHubAccountRejected
	}
	used, e := hubAccountNonceUsed(tx, a.AccountID, a.DeviceID, in.CompleteNonceDigest)
	if e != nil || used {
		return nil, ErrHubAccountRejected
	}
	if in.OwnerPublic.ID == a.DevicePublic.ID {
		return nil, ErrHubAccountRejected
	}
	raw, _ := json.Marshal(a.DevicePublic)
	pub, _ := json.Marshal(in.OwnerPublic)
	statements := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO hub_account_credentials_v1 VALUES(?,?,?,?,?,?,1)`, []any{r.AccountID, r.OwnerID, in.Credential.Username, in.Credential.Algorithm, in.Credential.Salt, in.Credential.Verifier}},
		{`INSERT INTO hub_account_devices_v1 VALUES(?,?,?,?,1,'ACTIVE',?)`, []any{r.AccountID, r.OwnerID, a.DeviceID, string(raw), now()}},
		{`INSERT INTO hub_account_public_association_v1 VALUES(?,?,?,?,'PENDING_PROOF')`, []any{r.AccountID, r.OwnerID, string(pub), in.OwnerFingerprint}},
		{`UPDATE hub_account_claims_v1 SET state='CONSUMED' WHERE claim_id=?`, []any{a.ClaimID}},
		{`UPDATE hub_account_attempts_v1 SET state='CONSUMED',complete_id=?,request_digest=?,response_packet=?,complete_nonce_digest=? WHERE attempt_id=?`, []any{in.RequestID, in.RequestDigest, in.Receipt, in.CompleteNonceDigest, a.ID}},
	}
	for _, v := range statements {
		if _, e = tx.Exec(v.q, v.args...); e != nil {
			return nil, ErrHubAccountRejected
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return in.Receipt, nil
}
func accountSession(q hubOwnerQuerier, id string) (*HubAccountSession, error) {
	var a HubAccountSession
	e := q.QueryRow(`SELECT session_id,account_id,owner_id,device_id,epoch,device_epoch,credential_version,token_digest,state,expires_at FROM hub_account_sessions_v1 WHERE session_id=?`, id).Scan(&a.ID, &a.AccountID, &a.OwnerID, &a.DeviceID, &a.Epoch, &a.DeviceEpoch, &a.CredentialVersion, &a.TokenDigest, &a.State, &a.ExpiresAt)
	if e != nil {
		return nil, ErrHubAccountRejected
	}
	epoch, e := accountEpoch(q)
	if e != nil || a.Epoch != epoch || a.State != "ACTIVE" || !accountStampValid(a.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	d, e := accountDevice(q, a.AccountID, a.DeviceID)
	if e != nil || d.Epoch != a.DeviceEpoch {
		return nil, ErrHubAccountRejected
	}
	c, e := accountCredential(q, a.AccountID)
	if e != nil || c.Version != a.CredentialVersion {
		return nil, ErrHubAccountRejected
	}
	return &a, nil
}

// accountSessionReceiptRecovery validates the durable coordinates of a
// consumed login response without reactivating its session. A later login or
// explicit logout may revoke that session before the client retries a lost
// receipt, but only the exact response remains recoverable while the account
// epoch, registered device and credential version are still current.
func accountSessionReceiptRecovery(q hubOwnerQuerier, attempt *HubAccountAttempt) error {
	var session HubAccountSession
	e := q.QueryRow(`SELECT session_id,account_id,owner_id,device_id,epoch,device_epoch,credential_version,token_digest,state,expires_at FROM hub_account_sessions_v1 WHERE session_id=?`, attempt.SessionID).
		Scan(&session.ID, &session.AccountID, &session.OwnerID, &session.DeviceID, &session.Epoch, &session.DeviceEpoch, &session.CredentialVersion, &session.TokenDigest, &session.State, &session.ExpiresAt)
	if e != nil || session.AccountID != attempt.AccountID || session.OwnerID != attempt.OwnerID || session.DeviceID != attempt.DeviceID || session.Epoch != attempt.Epoch || session.DeviceEpoch != attempt.DeviceEpoch || (session.State != "ACTIVE" && session.State != "REVOKED") || !accountHashValid(session.TokenDigest) {
		return ErrHubAccountRejected
	}
	epoch, e := accountEpoch(q)
	if e != nil || epoch != attempt.Epoch {
		return ErrHubAccountRejected
	}
	d, e := accountDevice(q, attempt.AccountID, attempt.DeviceID)
	if e != nil || d.Epoch != attempt.DeviceEpoch {
		return ErrHubAccountRejected
	}
	c, e := accountCredential(q, attempt.AccountID)
	if e != nil || c.Version != session.CredentialVersion {
		return ErrHubAccountRejected
	}
	return nil
}
func (s *Store) HubAccountSession(id string) (*HubAccountSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil {
		return nil, e
	}
	a, e := accountSession(s.db, id)
	if e != nil || a.AccountID != r.AccountID {
		return nil, ErrHubAccountRejected
	}
	return a, nil
}
func (s *Store) CompleteHubAccountLogin(attempt, challenge, id, digest, nonceDigest string, session HubAccountSession, receipt []byte) ([]byte, error) {
	if !accountHashValid(digest) || !accountHashValid(nonceDigest) {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := accountSetup(tx, false)
	if e != nil {
		return nil, e
	}
	a, e := accountAttempt(tx, attempt)
	epoch, ee := accountEpoch(tx)
	if e != nil || ee != nil || a.Purpose != "LOGIN" || a.AccountID != r.AccountID || a.Epoch != epoch {
		return nil, ErrHubAccountRejected
	}
	if e = hubAccountOperationUnfenced(tx, a.AccountID, a.DeviceID, id); e != nil {
		return nil, e
	}
	if a.State == "CONSUMED" {
		if a.CompleteID != id || a.CompleteDigest != digest {
			return nil, ErrHubAccountRejected
		}
		if e = accountSessionReceiptRecovery(tx, a); e != nil {
			return nil, e
		}
		return a.ReceiptPacket, nil
	}
	if a.State != "PENDING" || a.ChallengeDigest != challenge || !accountStampValid(a.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	d, e := accountDevice(tx, a.AccountID, a.DeviceID)
	c, ce := accountCredential(tx, a.AccountID)
	if e != nil || ce != nil || d.Epoch != a.DeviceEpoch || session.DeviceEpoch != d.Epoch || session.CredentialVersion != c.Version || session.AccountID != a.AccountID || session.OwnerID != a.OwnerID || session.DeviceID != a.DeviceID || session.Epoch != epoch || !accountHashValid(session.TokenDigest) || !accountStampValid(session.ExpiresAt) || len(receipt) == 0 {
		return nil, ErrHubAccountRejected
	}
	used, e := hubAccountNonceUsed(tx, a.AccountID, a.DeviceID, nonceDigest)
	if e != nil || used {
		return nil, ErrHubAccountRejected
	}
	if _, e = tx.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE account_id=? AND device_id=? AND state='ACTIVE'`, a.AccountID, a.DeviceID); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,?,?,?,?,'ACTIVE',?)`, session.ID, session.AccountID, session.OwnerID, session.DeviceID, session.Epoch, session.DeviceEpoch, session.CredentialVersion, session.TokenDigest, session.ExpiresAt); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(`UPDATE hub_account_attempts_v1 SET state='CONSUMED',complete_id=?,request_digest=?,response_packet=?,session_id=?,complete_nonce_digest=? WHERE attempt_id=?`, id, digest, receipt, session.ID, nonceDigest, a.ID); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return receipt, nil
}
func (s *Store) HubAccountCachedRequest(session, id, operation, digest string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := accountSetup(s.db, false); e != nil {
		return nil, e
	}
	if _, e := accountSession(s.db, session); e != nil {
		return nil, e
	}
	var op, got string
	var packet []byte
	e := s.db.QueryRow(`SELECT operation,request_digest,response_packet FROM hub_account_requests_v1 WHERE session_id=? AND operation_id=?`, session, id).Scan(&op, &got, &packet)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil || op != operation || got != digest {
		return nil, ErrHubAccountRejected
	}
	return packet, nil
}
func (s *Store) CompleteHubAccountRequest(session, id, operation, digest, nonceDigest string, response []byte, logout bool) ([]byte, error) {
	if !accountHashValid(digest) || !accountHashValid(nonceDigest) {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = accountSetup(tx, false); e != nil {
		return nil, e
	}
	if _, e = accountSession(tx, session); e != nil {
		return nil, e
	}
	var op, got string
	var prior []byte
	e = tx.QueryRow(`SELECT operation,request_digest,response_packet FROM hub_account_requests_v1 WHERE session_id=? AND operation_id=?`, session, id).Scan(&op, &got, &prior)
	if e == nil {
		if op != operation || got != digest {
			return nil, ErrHubAccountRejected
		}
		return prior, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	var n int
	if e = tx.QueryRow(`SELECT count(*) FROM hub_account_requests_v1 WHERE session_id=?`, session).Scan(&n); e != nil || n >= 128 {
		return nil, ErrHubAccountRejected
	}
	var accountID, deviceID string
	if e = tx.QueryRow(`SELECT account_id,device_id FROM hub_account_sessions_v1 WHERE session_id=?`, session).Scan(&accountID, &deviceID); e != nil {
		return nil, ErrHubAccountRejected
	}
	if e = hubAccountOperationUnfenced(tx, accountID, deviceID, id); e != nil {
		return nil, e
	}
	used, e := hubAccountNonceUsed(tx, accountID, deviceID, nonceDigest)
	if e != nil || used {
		return nil, ErrHubAccountRejected
	}
	if _, e = tx.Exec(`INSERT INTO hub_account_requests_v1(session_id,operation_id,operation,request_digest,response_packet,nonce_digest) VALUES(?,?,?,?,?,?)`, session, id, operation, digest, response, nonceDigest); e != nil {
		return nil, e
	}
	if logout {
		if _, e = tx.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, session); e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return response, nil
}

// CachedHubAccountCompletion is a cheap exact-request recovery preflight.
// Completion methods still recheck all authority in their write transaction.
func (s *Store) CachedHubAccountCompletion(attempt, id, digest string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil {
		return nil, e
	}
	a, e := accountAttempt(s.db, attempt)
	epoch, ee := accountEpoch(s.db)
	if e != nil || ee != nil || a.AccountID != r.AccountID || a.Epoch != epoch || a.State == "CANCELLED" {
		return nil, ErrHubAccountRejected
	}
	if a.State != "CONSUMED" {
		if !accountStampValid(a.ExpiresAt) {
			return nil, ErrHubAccountRejected
		}
		return nil, nil
	}
	if a.CompleteID != id || a.CompleteDigest != digest {
		return nil, ErrHubAccountRejected
	}
	d, e := accountDevice(s.db, a.AccountID, a.DeviceID)
	if e != nil || d.Epoch != a.DeviceEpoch {
		return nil, ErrHubAccountRejected
	}
	if a.Purpose == "LOGIN" {
		if e = accountSessionReceiptRecovery(s.db, a); e != nil {
			return nil, e
		}
	} else {
		if _, e = accountCredential(s.db, a.AccountID); e != nil {
			return nil, e
		}
	}
	return a.ReceiptPacket, nil
}

// HubAccountLoginCompletionReplayCandidate identifies an exact already-saved
// login packet before its signed timestamp is checked. The caller must still
// decrypt and verify device proof before returning the cached response.
func (s *Store) HubAccountLoginCompletionReplayCandidate(account, device, operationID, digest string, epoch, deviceEpoch int64) (bool, error) {
	if account == "" || !accountIDValid(operationID) || !accountHashValid(digest) || epoch <= 0 || deviceEpoch <= 0 {
		return false, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	setup, e := accountSetup(s.db, false)
	if e != nil || setup.AccountID != account {
		return false, ErrHubAccountRejected
	}
	current, e := accountEpoch(s.db)
	if e != nil || current != epoch {
		return false, ErrHubAccountRejected
	}
	d, e := accountDevice(s.db, account, device)
	if e != nil || d.Epoch != deviceEpoch {
		return false, ErrHubAccountRejected
	}
	var matches int
	e = s.db.QueryRow(`SELECT count(*) FROM hub_account_attempts_v1 WHERE purpose='LOGIN' AND state='CONSUMED' AND account_id=? AND device_id=? AND epoch=? AND device_epoch=? AND complete_id=? AND request_digest=?`, account, device, epoch, deviceEpoch, operationID, digest).Scan(&matches)
	if e != nil {
		return false, ErrHubAccountRejected
	}
	if matches == 0 {
		return false, nil
	}
	if matches != 1 {
		return false, ErrHubAccountRejected
	}
	a, e := accountAttemptByCompletionReplay(s.db, account, device, operationID, digest, epoch, deviceEpoch)
	if e != nil || a.Purpose != "LOGIN" || a.State != "CONSUMED" {
		return false, ErrHubAccountRejected
	}
	if e = accountSessionReceiptRecovery(s.db, a); e != nil {
		return false, ErrHubAccountRejected
	}
	return true, nil
}

func accountAttemptByCompletionReplay(q hubOwnerQuerier, account, device, operationID, digest string, epoch, deviceEpoch int64) (*HubAccountAttempt, error) {
	var id string
	e := q.QueryRow(`SELECT attempt_id FROM hub_account_attempts_v1 WHERE purpose='LOGIN' AND state='CONSUMED' AND account_id=? AND device_id=? AND epoch=? AND device_epoch=? AND complete_id=? AND request_digest=? LIMIT 2`, account, device, epoch, deviceEpoch, operationID, digest).Scan(&id)
	if e != nil {
		return nil, e
	}
	return accountAttempt(q, id)
}

// HubAccountSessionRequestReplayCandidate permits freshness bypass only for
// the exact digest of a cached request whose session still matches current
// account, device and credential authority. Device proof is verified later.
func (s *Store) HubAccountSessionRequestReplayCandidate(account, device, operation, operationID, digest string, epoch, deviceEpoch int64) (bool, error) {
	if account == "" || !accountIDValid(operationID) || !accountHashValid(digest) || epoch <= 0 || deviceEpoch <= 0 ||
		(operation != "owner.account.session.inspect" && operation != "owner.account.session.logout") {
		return false, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	setup, e := accountSetup(s.db, false)
	if e != nil || setup.AccountID != account {
		return false, ErrHubAccountRejected
	}
	current, e := accountEpoch(s.db)
	if e != nil || current != epoch {
		return false, ErrHubAccountRejected
	}
	d, e := accountDevice(s.db, account, device)
	if e != nil || d.Epoch != deviceEpoch {
		return false, ErrHubAccountRejected
	}
	c, e := accountCredential(s.db, account)
	if e != nil {
		return false, ErrHubAccountRejected
	}
	var matches int
	e = s.db.QueryRow(`SELECT count(*) FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id
		WHERE r.operation_id=? AND r.operation=? AND r.request_digest=? AND s.account_id=? AND s.owner_id=? AND s.device_id=?`, operationID, operation, digest, account, setup.OwnerID, device).Scan(&matches)
	if e != nil {
		return false, ErrHubAccountRejected
	}
	if matches == 0 {
		return false, nil
	}
	if matches != 1 {
		return false, ErrHubAccountRejected
	}
	var sessionID, state string
	var sessionEpoch, sessionDeviceEpoch, credentialVersion int64
	e = s.db.QueryRow(`SELECT s.session_id,s.state,s.epoch,s.device_epoch,s.credential_version
		FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id
		WHERE r.operation_id=? AND r.operation=? AND r.request_digest=? AND s.account_id=? AND s.owner_id=? AND s.device_id=?
		LIMIT 1`, operationID, operation, digest, account, setup.OwnerID, device).Scan(&sessionID, &state, &sessionEpoch, &sessionDeviceEpoch, &credentialVersion)
	if e != nil || sessionEpoch != epoch || sessionDeviceEpoch != deviceEpoch || credentialVersion != c.Version {
		return false, ErrHubAccountRejected
	}
	wantState := "ACTIVE"
	if operation == "owner.account.session.logout" {
		wantState = "REVOKED"
	}
	if state != wantState {
		return false, nil
	}
	if operation == "owner.account.session.inspect" {
		if _, e = accountSession(s.db, sessionID); e != nil {
			return false, nil
		}
	}
	return true, nil
}

type HubAccountPublicStatus struct {
	AccountID        string                   `json:"account_id"`
	OwnerID          string                   `json:"owner_id"`
	Username         string                   `json:"username"`
	State            string                   `json:"state"`
	RootState        string                   `json:"root_state"`
	RootActive       bool                     `json:"root_active"`
	OwnerPublic      e2ee.PublicIdentity      `json:"owner_public_identity"`
	OwnerFingerprint string                   `json:"owner_fingerprint"`
	Devices          []HubAccountDeviceStatus `json:"devices"`
}
type HubAccountDeviceStatus struct {
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	DeviceID    string `json:"device_id"`
	KeyID       string `json:"key_id"`
	Epoch       int64  `json:"device_epoch"`
	State       string `json:"state"`
}

func (s *Store) HubAccountStatus(account string) (*HubAccountPublicStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	setup, e := accountSetup(s.db, false)
	if e != nil || setup.AccountID != account {
		return nil, ErrHubAccountRejected
	}
	c, e := accountCredential(s.db, account)
	if e != nil {
		return nil, e
	}
	r := &HubAccountPublicStatus{AccountID: account, OwnerID: setup.OwnerID, Username: c.Username, State: "ACCOUNT_READY_OWNER_SIGNER_PENDING", RootState: "PENDING_PROOF", Devices: []HubAccountDeviceStatus{}}
	var raw string
	if e = s.db.QueryRow(`SELECT public_identity_json,fingerprint FROM hub_account_public_association_v1 WHERE account_id=?`, account).Scan(&raw, &r.OwnerFingerprint); e != nil || json.Unmarshal([]byte(raw), &r.OwnerPublic) != nil {
		return nil, ErrHubAccountRejected
	}
	var approvalRaw string
	if e = s.db.QueryRow(`SELECT public_identity_json FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=? AND state='ACTIVE'`, setup.OwnerID, r.OwnerPublic.ID).Scan(&approvalRaw); e == nil {
		var current e2ee.PublicIdentity
		if json.Unmarshal([]byte(approvalRaw), &current) == nil {
			want, _ := json.Marshal(r.OwnerPublic)
			got, _ := json.Marshal(current)
			if string(want) == string(got) {
				r.RootState = "ROOT_ACTIVE"
				r.RootActive = true
				r.State = "ACCOUNT_READY"
			}
		}
	}
	if !r.RootActive && setup.RootEverEstablished {
		r.RootState = "ROOT_UNAVAILABLE"
	}

	rows, e := s.db.Query(`SELECT device_id,public_identity_json,epoch,status,created_at FROM hub_account_devices_v1 WHERE account_id=? AND status='ACTIVE' ORDER BY device_id LIMIT 64`, account)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var d HubAccountDeviceStatus
		var p e2ee.PublicIdentity
		if e = rows.Scan(&d.DeviceID, &raw, &d.Epoch, &d.State, &d.CreatedAt); e != nil {
			return nil, e
		}
		if json.Unmarshal([]byte(raw), &p) != nil {
			return nil, ErrHubAccountRejected
		}
		d.KeyID = p.ID
		d.Fingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(p)
		r.Devices = append(r.Devices, d)
	}
	return r, rows.Err()
}

func (s *Store) HubAccountAttemptForDevice(account, device, purpose string) (*HubAccountAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	e := s.db.QueryRow(`SELECT attempt_id FROM hub_account_attempts_v1 WHERE account_id=? AND device_id=? AND purpose=? ORDER BY rowid DESC LIMIT 1`, account, device, purpose).Scan(&id)
	if e != nil {
		return nil, ErrHubAccountRejected
	}
	return accountAttempt(s.db, id)
}
func (s *Store) HubAccountSessionByTokenDigest(digest string) (*HubAccountSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	if s.db.QueryRow(`SELECT session_id FROM hub_account_sessions_v1 WHERE token_digest=?`, digest).Scan(&id) != nil {
		return nil, ErrHubAccountRejected
	}
	return accountSession(s.db, id)
}

// HubAccountRevokedLogoutReceipt recovers only the exact request receipt that
// committed the session's revocation. The caller must first open and verify
// the original device-signed request. Current account/device epochs and the
// active registered device are checked here so an archived or restored token
// cannot recover a receipt after its authority has been fenced.
func (s *Store) HubAccountRevokedLogoutReceipt(tokenDigest, account, device string, epoch, deviceEpoch int64, operationID, requestDigest string) ([]byte, error) {
	if !accountHashValid(tokenDigest) || !accountIDValid(operationID) || !accountHashValid(requestDigest) {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := accountSetup(s.db, false)
	if e != nil || r.AccountID != account {
		return nil, ErrHubAccountRejected
	}
	currentEpoch, e := accountEpoch(s.db)
	if e != nil || epoch != currentEpoch {
		return nil, ErrHubAccountRejected
	}
	d, e := accountDevice(s.db, account, device)
	if e != nil || d.Epoch != deviceEpoch {
		return nil, ErrHubAccountRejected
	}
	c, e := accountCredential(s.db, account)
	if e != nil {
		return nil, ErrHubAccountRejected
	}
	var sessionID, ownerID, deviceID, state, expires string
	var sessionEpoch, sessionDeviceEpoch, credentialVersion int64
	e = s.db.QueryRow(`SELECT session_id,owner_id,device_id,epoch,device_epoch,credential_version,state,expires_at FROM hub_account_sessions_v1 WHERE token_digest=? AND account_id=?`, tokenDigest, account).Scan(&sessionID, &ownerID, &deviceID, &sessionEpoch, &sessionDeviceEpoch, &credentialVersion, &state, &expires)
	if e != nil || ownerID != r.OwnerID || deviceID != device || sessionEpoch != currentEpoch || sessionDeviceEpoch != d.Epoch || credentialVersion != c.Version || state != "REVOKED" {
		return nil, ErrHubAccountRejected
	}
	var operation, savedDigest string
	var response []byte
	e = s.db.QueryRow(`SELECT operation,request_digest,response_packet FROM hub_account_requests_v1 WHERE session_id=? AND operation_id=?`, sessionID, operationID).Scan(&operation, &savedDigest, &response)
	if e != nil || operation != "owner.account.session.logout" || savedDigest != requestDigest || len(response) == 0 {
		return nil, ErrHubAccountRejected
	}
	return response, nil
}
