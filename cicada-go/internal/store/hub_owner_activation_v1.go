package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

type HubActivation struct {
	Material                                                wire.ActivationMaterial
	CodeDigest, State                                       string
	Binding                                                 *wire.ActivationBinding
	Pairing                                                 *ownerbootstrap.PairingFile
	Grant, ChallengePacket                                  []byte
	OwnerNonceDigest, DeviceNonceDigest, PrepareNonceDigest string
}
type HubOwnerOperation struct {
	AccountID, OwnerID, DeviceID, Operation, ID, Digest, State, NonceDigest string
	Epoch                                                                   int64
	Response                                                                []byte
}

var ErrHubOwnerDiagnosticsFull = errors.New("Hub Owner diagnostic receipt limit reached")

func (s *Store) initializeHubActivationSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_owner_activation_v1(activation_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,owner_id TEXT NOT NULL,material_json TEXT NOT NULL,code_digest TEXT NOT NULL CHECK(length(code_digest)=64),epoch INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('ISSUED','PREPARED','COMPLETED','CANCELLED')),binding_json TEXT NOT NULL DEFAULT '',pairing_json TEXT NOT NULL DEFAULT '',grant_bytes BLOB,challenge_packet BLOB,owner_nonce_digest TEXT NOT NULL DEFAULT '',device_nonce_digest TEXT NOT NULL DEFAULT '',prepare_nonce_digest TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);
CREATE UNIQUE INDEX hub_owner_activation_v1_pending ON hub_owner_activation_v1(account_id) WHERE state IN('ISSUED','PREPARED');
CREATE TABLE hub_owner_operations_v1(account_id TEXT NOT NULL,owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED','CANCELLED')),response_packet BLOB,nonce_digest TEXT NOT NULL,epoch INTEGER NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(account_id,device_id,operation_id));
CREATE UNIQUE INDEX hub_owner_operations_v1_nonce ON hub_owner_operations_v1(account_id,device_id,nonce_digest) WHERE nonce_digest!='';
CREATE TABLE hub_app_leases_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,account_id TEXT NOT NULL,activation_id TEXT NOT NULL UNIQUE,binding_json TEXT NOT NULL,account_epoch INTEGER NOT NULL,device_epoch INTEGER NOT NULL,owner_key_id TEXT NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('ACTIVE','REVOKED')),PRIMARY KEY(owner_id,device_id));
CREATE TRIGGER hub_owner_activation_v1_no_delete BEFORE DELETE ON hub_owner_activation_v1 BEGIN SELECT RAISE(ABORT,'Activation history is permanent');END;
CREATE TRIGGER hub_owner_activation_v1_immutable BEFORE UPDATE ON hub_owner_activation_v1 WHEN NEW.activation_id!=OLD.activation_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.material_json!=OLD.material_json OR NEW.code_digest!=OLD.code_digest OR NEW.epoch!=OLD.epoch OR OLD.state NOT IN('ISSUED','PREPARED') OR (OLD.state='PREPARED' AND (NEW.binding_json!=OLD.binding_json OR NEW.pairing_json!=OLD.pairing_json OR NEW.grant_bytes!=OLD.grant_bytes OR NEW.challenge_packet!=OLD.challenge_packet OR NEW.owner_nonce_digest!=OLD.owner_nonce_digest OR NEW.device_nonce_digest!=OLD.device_nonce_digest OR NEW.prepare_nonce_digest!=OLD.prepare_nonce_digest)) BEGIN SELECT RAISE(ABORT,'Activation coordinates are immutable');END;
CREATE TRIGGER hub_owner_operations_v1_no_delete BEFORE DELETE ON hub_owner_operations_v1 BEGIN SELECT RAISE(ABORT,'Owner operation history is permanent');END;
CREATE TRIGGER hub_owner_operations_v1_no_update BEFORE UPDATE ON hub_owner_operations_v1 BEGIN SELECT RAISE(ABORT,'Owner operation receipt is immutable');END;
CREATE TRIGGER hub_app_leases_v1_no_delete BEFORE DELETE ON hub_app_leases_v1 BEGIN SELECT RAISE(ABORT,'App lease history is permanent');END;
CREATE TRIGGER hub_app_leases_v1_immutable BEFORE UPDATE ON hub_app_leases_v1 WHEN NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.account_id!=OLD.account_id OR NEW.activation_id!=OLD.activation_id OR NEW.binding_json!=OLD.binding_json OR NEW.account_epoch!=OLD.account_epoch OR NEW.device_epoch!=OLD.device_epoch OR NEW.owner_key_id!=OLD.owner_key_id OR NEW.expires_at!=OLD.expires_at OR OLD.state!='ACTIVE' OR NEW.state!='REVOKED' BEGIN SELECT RAISE(ABORT,'App lease is finite and immutable');END;`)
	return err
}
func activation(q hubOwnerQuerier, id string) (*HubActivation, error) {
	var a HubActivation
	var material, binding, pairing string
	err := q.QueryRow(`SELECT material_json,code_digest,state,binding_json,pairing_json,grant_bytes,challenge_packet,owner_nonce_digest,device_nonce_digest,prepare_nonce_digest FROM hub_owner_activation_v1 WHERE activation_id=?`, id).Scan(&material, &a.CodeDigest, &a.State, &binding, &pairing, &a.Grant, &a.ChallengePacket, &a.OwnerNonceDigest, &a.DeviceNonceDigest, &a.PrepareNonceDigest)
	if err != nil || json.Unmarshal([]byte(material), &a.Material) != nil {
		return nil, ErrHubAccountRejected
	}
	if binding != "" {
		a.Binding = &wire.ActivationBinding{}
		a.Pairing = &ownerbootstrap.PairingFile{}
		if json.Unmarshal([]byte(binding), a.Binding) != nil || json.Unmarshal([]byte(pairing), a.Pairing) != nil {
			return nil, ErrHubAccountRejected
		}
	}
	return &a, nil
}
func (s *Store) HubActivation(id string) (*HubActivation, error) {
	if s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return activation(s.db, id)
}
func activationIssueScope(q hubOwnerQuerier, purpose, keyID, fingerprint string) (*HubOwnerSetup, int64, *e2ee.PublicIdentity, error) {
	r, err := accountSetup(q, true)
	if err != nil {
		return nil, 0, nil, err
	}
	var keys int
	if q.QueryRow(`SELECT count(*) FROM owner_approval_keys_v2 WHERE owner_id=?`, r.OwnerID).Scan(&keys) != nil || keys != 0 {
		return nil, 0, nil, ErrHubAccountRejected
	}
	epoch, err := accountEpoch(q)
	if err != nil {
		return nil, 0, nil, err
	}
	var cred, association int
	if q.QueryRow(`SELECT count(*) FROM hub_account_credentials_v1 WHERE account_id=?`, r.AccountID).Scan(&cred) != nil || q.QueryRow(`SELECT count(*) FROM hub_account_public_association_v1 WHERE account_id=?`, r.AccountID).Scan(&association) != nil {
		return nil, 0, nil, ErrHubAccountRejected
	}
	if purpose == wire.PurposeInitialActivation {
		if r.Provenance != "LOCAL_SETUP" || cred != 0 || association != 0 || keyID != "" || fingerprint != "" {
			return nil, 0, nil, ErrHubAccountRejected
		}
		var clients, bootstrap int
		if q.QueryRow(`SELECT count(*) FROM client_devices_v2 WHERE owner_id=?`, r.OwnerID).Scan(&clients) != nil || q.QueryRow(`SELECT count(*) FROM owner_bootstrap_authority_v1 WHERE owner_id=?`, r.OwnerID).Scan(&bootstrap) != nil || clients != 0 || bootstrap != 0 {
			return nil, 0, nil, ErrHubAccountRejected
		}
		return r, epoch, nil, nil
	}
	if purpose != wire.PurposeLegacyContinuation || cred != 1 || association != 1 {
		return nil, 0, nil, ErrHubAccountRejected
	}
	var raw, fp string
	var pub e2ee.PublicIdentity
	if q.QueryRow(`SELECT public_identity_json,fingerprint FROM hub_account_public_association_v1 WHERE account_id=? AND owner_id=? AND state='PENDING_PROOF'`, r.AccountID, r.OwnerID).Scan(&raw, &fp) != nil || json.Unmarshal([]byte(raw), &pub) != nil || e2ee.ValidatePublicIdentity(pub) != nil || pub.ID != keyID || fp != fingerprint || ownerbootstrap.Fingerprint(pub) != fp {
		return nil, 0, nil, ErrHubAccountRejected
	}
	return r, epoch, &pub, nil
}
func (s *Store) HubActivationIssueScopeLocal(purpose, keyID, fp string) (*HubOwnerSetup, int64, *e2ee.PublicIdentity, error) {
	if s.requireOwnerSetupStartupAllowed() != nil {
		return nil, 0, nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return activationIssueScope(s.db, purpose, keyID, fp)
}
func (s *Store) IssueHubActivationLocal(m wire.ActivationMaterial, digest string, cancel bool) error {
	if s.requireOwnerSetupStartupAllowed() != nil || wire.ValidateActivationMaterial(m, time.Now().UTC()) != nil || !accountHashValid(digest) {
		return ErrHubAccountRejected
	}
	keyID, fp := "", ""
	if m.ExpectedOwnerPublic != nil {
		keyID = m.ExpectedOwnerPublic.ID
		fp = ownerbootstrap.Fingerprint(*m.ExpectedOwnerPublic)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, epoch, pub, err := activationIssueScope(tx, m.Purpose, keyID, fp)
	if err != nil {
		return err
	}
	if r.HubID != m.HubID || r.AccountID != m.AccountID || r.OwnerID != m.OwnerID || r.Origin != m.Origin || r.AllowLoopbackHTTP != m.AllowLoopbackHTTP || uint64(r.Version) != m.SetupEpoch || uint64(epoch) != m.AccountEpoch || !reflect.DeepEqual(pub, m.ExpectedOwnerPublic) {
		return ErrHubAccountRejected
	}
	if cancel {
		for _, stmt := range []string{`UPDATE hub_owner_activation_v1 SET state='CANCELLED' WHERE state IN('ISSUED','PREPARED')`, `UPDATE owner_bootstrap_authority_v1 SET state='CANCELLED' WHERE state='PENDING'`, `UPDATE hub_account_claims_v1 SET state='CANCELLED' WHERE state IN('ISSUED','PREPARED')`, `UPDATE hub_account_attempts_v1 SET state='CANCELLED' WHERE purpose='CLAIM' AND state='PENDING'`} {
			if _, err = tx.Exec(stmt); err != nil {
				return err
			}
		}
	}
	var old int
	if tx.QueryRow(`SELECT count(*) FROM hub_account_claims_v1 WHERE state IN('ISSUED','PREPARED')`).Scan(&old) != nil || old != 0 {
		return ErrHubAccountRejected
	}
	if tx.QueryRow(`SELECT count(*) FROM owner_bootstrap_authority_v1 WHERE account_id=? AND state='PENDING'`, r.AccountID).Scan(&old) != nil || old != 0 {
		return ErrHubAccountRejected
	}
	m.Code = ""
	raw, _ := json.Marshal(m)
	_, err = tx.Exec(`INSERT INTO hub_owner_activation_v1(activation_id,account_id,owner_id,material_json,code_digest,epoch,state,created_at) VALUES(?,?,?,?,?,?,'ISSUED',?)`, m.ActivationID, m.AccountID, m.OwnerID, string(raw), digest, epoch, now())
	if err != nil {
		return ErrHubAccountRejected
	}
	return tx.Commit()
}
func ownerOperation(q hubOwnerQuerier, account, device, id string) (*HubOwnerOperation, error) {
	var o HubOwnerOperation
	err := q.QueryRow(`SELECT account_id,owner_id,device_id,operation_id,operation,request_digest,state,response_packet,nonce_digest,epoch FROM hub_owner_operations_v1 WHERE account_id=? AND device_id=? AND operation_id=?`, account, device, id).Scan(&o.AccountID, &o.OwnerID, &o.DeviceID, &o.ID, &o.Operation, &o.Digest, &o.State, &o.Response, &o.NonceDigest, &o.Epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}
func (s *Store) HubOwnerOperation(account, device, id string) (*HubOwnerOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ownerOperation(s.db, account, device, id)
}

// Cached activation bytes are historical observations. They are withheld after
// restore/account fencing or revocation; lease expiry alone permits recovery.
func activationReplayAllowed(q hubOwnerQuerier, a *HubActivation, o *HubOwnerOperation) error {
	r, err := accountSetup(q, false)
	if err != nil {
		return err
	}
	epoch, err := accountEpoch(q)
	if err != nil || o.Epoch != epoch || a.Material.AccountEpoch != uint64(epoch) || a.State == wire.ActivationCancelled || r.AccountID != o.AccountID || r.OwnerID != o.OwnerID {
		return ErrHubAccountRejected
	}
	if a.Binding != nil {
		b := a.Binding
		if b.DeviceID != o.DeviceID {
			return ErrHubAccountRejected
		}
		var raw, status string
		var de int64
		err = q.QueryRow(`SELECT public_identity_json,status,epoch FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, o.AccountID, o.DeviceID).Scan(&raw, &status, &de)
		expected, _ := json.Marshal(b.DevicePublic)
		if err == nil && (raw != string(expected) || status != "ACTIVE" || uint64(de) != b.DeviceEpoch) {
			return ErrHubAccountRejected
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if a.State == wire.ActivationCompleted {
			var public, state, clientState string
			var version int64
			err = q.QueryRow(`SELECT public_identity_json,state,version FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, b.OwnerID, b.OwnerPublic.ID).Scan(&public, &state, &version)
			owner, _ := json.Marshal(b.OwnerPublic)
			if err != nil || public != string(owner) || state != "ACTIVE" || version != 1 || q.QueryRow(`SELECT state FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, b.OwnerID, b.DeviceID).Scan(&clientState) != nil || clientState != "ACTIVE" {
				return ErrHubAccountRejected
			}
		} else if r.RootEverEstablished {
			return ErrHubAccountRejected
		}
	}
	return nil
}
func (s *Store) ReplayHubActivationOperation(activationID, account, device, id, digest string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := activation(tx, activationID)
	if err != nil {
		return nil, err
	}
	o, err := ownerOperation(tx, account, device, id)
	if err != nil || o == nil || o.Digest != digest || activationReplayAllowed(tx, a, o) != nil {
		return nil, ErrHubAccountRejected
	}
	return o.Response, nil
}
func insertOwnerOperation(tx *sql.Tx, o HubOwnerOperation) error {
	if !accountIDValid(o.ID) || !accountHashValid(o.Digest) || len(o.Response) > 384*1024 || o.Epoch <= 0 || (o.NonceDigest != "" && !accountHashValid(o.NonceDigest)) {
		return ErrHubAccountRejected
	}
	if o.Operation == wire.OperationActivationStatus || o.Operation == wire.OperationAccountReconcile {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM hub_owner_operations_v1 WHERE account_id=? AND device_id=? AND epoch=? AND operation IN('owner.activation.status','owner.account.reconcile')`, o.AccountID, o.DeviceID, o.Epoch).Scan(&count); err != nil {
			return err
		}
		if count >= 128 {
			return ErrHubOwnerDiagnosticsFull
		}
	}
	if o.NonceDigest != "" {
		used, err := hubAccountNonceUsed(tx, o.AccountID, o.DeviceID, o.NonceDigest)
		if err != nil || used {
			return ErrHubAccountRejected
		}
	}
	_, err := tx.Exec(`INSERT INTO hub_owner_operations_v1(account_id,owner_id,device_id,operation_id,operation,request_digest,state,response_packet,nonce_digest,epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, o.AccountID, o.OwnerID, o.DeviceID, o.ID, o.Operation, o.Digest, o.State, o.Response, o.NonceDigest, o.Epoch, now())
	if err != nil {
		return ErrHubAccountRejected
	}
	return nil
}
func activationEligible(q hubOwnerQuerier, a *HubActivation) error {
	r, err := accountSetup(q, true)
	if err != nil {
		return err
	}
	var keys int
	if q.QueryRow(`SELECT count(*) FROM owner_approval_keys_v2 WHERE owner_id=?`, r.OwnerID).Scan(&keys) != nil || keys != 0 {
		return ErrHubAccountRejected
	}
	m := a.Material
	epoch, err := accountEpoch(q)
	if err != nil || r.HubID != m.HubID || r.AccountID != m.AccountID || r.OwnerID != m.OwnerID || r.Origin != m.Origin || uint64(r.Version) != m.SetupEpoch || uint64(epoch) != m.AccountEpoch || !accountStampValid(m.ExpiresAt) || (a.State != wire.ActivationIssued && a.State != wire.ActivationPrepared) {
		return ErrHubAccountRejected
	}
	return nil
}

type HubActivationPreparation struct {
	ID                                                      string
	Binding                                                 wire.ActivationBinding
	Pairing                                                 ownerbootstrap.PairingFile
	Grant, Packet                                           []byte
	OwnerNonceDigest, DeviceNonceDigest, PrepareNonceDigest string
	Operation                                               HubOwnerOperation
}

func (s *Store) PrepareHubActivation(in HubActivationPreparation) ([]byte, error) {
	if len(in.Packet) == 0 || len(in.Packet) > wire.MaxActivationReceiptBytes {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	prior, err := ownerOperation(tx, in.Operation.AccountID, in.Operation.DeviceID, in.Operation.ID)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.Digest != in.Operation.Digest || prior.Operation != in.Operation.Operation {
			return nil, ErrHubAccountRejected
		}
		a, e := activation(tx, in.ID)
		if e != nil || activationReplayAllowed(tx, a, prior) != nil {
			return nil, ErrHubAccountRejected
		}
		return prior.Response, nil
	}
	a, err := activation(tx, in.ID)
	if err != nil || activationEligible(tx, a) != nil || a.State != wire.ActivationIssued || !accountStampValid(in.Pairing.Manifest.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	b := in.Binding
	m := a.Material
	if b.ActivationID != m.ActivationID || b.AccountID != m.AccountID || b.OwnerID != m.OwnerID || b.HubID != m.HubID || b.Purpose != m.Purpose || b.Origin != m.Origin || b.SetupEpoch != m.SetupEpoch || b.AccountEpoch != m.AccountEpoch || b.PreparePacketDigest != in.Operation.Digest || b.PrepareRequestID != in.Operation.ID || b.DeviceID != in.Operation.DeviceID || b.GrantDigest != wire.ActivationGrantDigest(in.Grant) || in.Pairing.Manifest.OperationID != b.Digest() || !accountHashValid(in.OwnerNonceDigest) || !accountHashValid(in.DeviceNonceDigest) || !accountHashValid(in.PrepareNonceDigest) {
		return nil, ErrHubAccountRejected
	}
	if m.ExpectedOwnerPublic != nil && !reflect.DeepEqual(*m.ExpectedOwnerPublic, b.OwnerPublic) {
		return nil, ErrHubAccountRejected
	}
	// A local code replacement preserves the already reserved identity tuple.
	// Timeouts and cancellation cannot be used to swap in regenerated keys.
	var historical string
	err = tx.QueryRow(`SELECT binding_json FROM hub_owner_activation_v1 WHERE account_id=? AND activation_id!=? AND binding_json!='' ORDER BY rowid DESC LIMIT 1`, b.AccountID, b.ActivationID).Scan(&historical)
	if err == nil {
		var old wire.ActivationBinding
		if json.Unmarshal([]byte(historical), &old) != nil || !reflect.DeepEqual(old.OwnerPublic, b.OwnerPublic) || !reflect.DeepEqual(old.DevicePublic, b.DevicePublic) || old.DeviceID != b.DeviceID {
			return nil, ErrHubAccountRejected
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var credentialCount int
	if tx.QueryRow(`SELECT count(*) FROM hub_account_credentials_v1 WHERE account_id=?`, m.AccountID).Scan(&credentialCount) != nil {
		return nil, ErrHubAccountRejected
	}
	if (m.Purpose == wire.PurposeInitialActivation && credentialCount != 0) || (m.Purpose == wire.PurposeLegacyContinuation && credentialCount != 1) {
		return nil, ErrHubAccountRejected
	}
	// A known revoked or rebound account device cannot be resurrected by a code.
	var existingPublic, status string
	var deviceEpoch int64
	err = tx.QueryRow(`SELECT public_identity_json,status,epoch FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, m.AccountID, b.DeviceID).Scan(&existingPublic, &status, &deviceEpoch)
	pub, _ := json.Marshal(b.DevicePublic)
	if err == nil && (existingPublic != string(pub) || status != "ACTIVE" || uint64(deviceEpoch) != b.DeviceEpoch) {
		return nil, ErrHubAccountRejected
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	bind, _ := json.Marshal(b)
	pair, _ := json.Marshal(in.Pairing)
	_, err = tx.Exec(`UPDATE hub_owner_activation_v1 SET state='PREPARED',binding_json=?,pairing_json=?,grant_bytes=?,challenge_packet=?,owner_nonce_digest=?,device_nonce_digest=?,prepare_nonce_digest=? WHERE activation_id=? AND state='ISSUED'`, string(bind), string(pair), in.Grant, in.Packet, in.OwnerNonceDigest, in.DeviceNonceDigest, in.PrepareNonceDigest, in.ID)
	if err != nil {
		return nil, err
	}
	if err = insertOwnerOperation(tx, in.Operation); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return in.Packet, nil
}

type HubActivationCompletion struct {
	ID, BindingDigest, OwnerNonceDigest, DeviceNonceDigest string
	Credential                                             *HubAccountCredential
	Operation                                              HubOwnerOperation
}

func (s *Store) CompleteHubActivation(in HubActivationCompletion) ([]byte, error) {
	if len(in.Operation.Response) == 0 || len(in.Operation.Response) > wire.MaxActivationReceiptBytes {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	prior, err := ownerOperation(tx, in.Operation.AccountID, in.Operation.DeviceID, in.Operation.ID)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.Digest != in.Operation.Digest || prior.Operation != in.Operation.Operation {
			return nil, ErrHubAccountRejected
		}
		a, e := activation(tx, in.ID)
		if e != nil || activationReplayAllowed(tx, a, prior) != nil {
			return nil, ErrHubAccountRejected
		}
		return prior.Response, nil
	}
	a, err := activation(tx, in.ID)
	if err != nil || activationEligible(tx, a) != nil || a.State != wire.ActivationPrepared || a.Binding == nil || a.Pairing == nil || !accountStampValid(a.Pairing.Manifest.ExpiresAt) {
		return nil, ErrHubAccountRejected
	}
	b := a.Binding
	m := a.Material
	if in.BindingDigest != b.Digest() || in.OwnerNonceDigest != a.OwnerNonceDigest || in.DeviceNonceDigest != a.DeviceNonceDigest || in.Operation.AccountID != b.AccountID || in.Operation.OwnerID != b.OwnerID || in.Operation.DeviceID != b.DeviceID || uint64(in.Operation.Epoch) != b.AccountEpoch {
		return nil, ErrHubAccountRejected
	}
	pub, _ := json.Marshal(b.OwnerPublic)
	device, _ := json.Marshal(b.DevicePublic)
	if m.Purpose == wire.PurposeInitialActivation {
		c := in.Credential
		if c == nil || c.AccountID != b.AccountID || c.OwnerID != b.OwnerID || c.Version != 1 || len(c.Salt) != 32 || len(c.Verifier) != 32 || c.Algorithm != "PBKDF2-SHA256-600000-v1" {
			return nil, ErrHubAccountRejected
		}
		if _, err = tx.Exec(`INSERT INTO hub_account_credentials_v1 VALUES(?,?,?,?,?,?,1)`, c.AccountID, c.OwnerID, c.Username, c.Algorithm, c.Salt, c.Verifier); err != nil {
			return nil, ErrHubAccountRejected
		}
		if _, err = tx.Exec(`INSERT INTO hub_account_public_association_v1 VALUES(?,?,?,?,'PENDING_PROOF')`, b.AccountID, b.OwnerID, string(pub), ownerbootstrap.Fingerprint(b.OwnerPublic)); err != nil {
			return nil, ErrHubAccountRejected
		}
	} else {
		var expected string
		if in.Credential != nil || tx.QueryRow(`SELECT public_identity_json FROM hub_account_public_association_v1 WHERE account_id=? AND owner_id=? AND state='PENDING_PROOF'`, b.AccountID, b.OwnerID).Scan(&expected) != nil || expected != string(pub) {
			return nil, ErrHubAccountRejected
		}
		if _, err = accountCredential(tx, b.AccountID); err != nil {
			return nil, err
		}
	}
	var devicePublic, state string
	var de int64
	err = tx.QueryRow(`SELECT public_identity_json,status,epoch FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, b.AccountID, b.DeviceID).Scan(&devicePublic, &state, &de)
	if errors.Is(err, sql.ErrNoRows) {
		if b.DeviceEpoch != 1 {
			return nil, ErrHubAccountRejected
		}
		_, err = tx.Exec(`INSERT INTO hub_account_devices_v1 VALUES(?,?,?,?,1,'ACTIVE',?)`, b.AccountID, b.OwnerID, b.DeviceID, string(device), now())
	} else if err == nil && (devicePublic != string(device) || state != "ACTIVE" || uint64(de) != b.DeviceEpoch) {
		return nil, ErrHubAccountRejected
	}
	if err != nil {
		return nil, ErrHubAccountRejected
	}
	if _, err = tx.Exec(`INSERT INTO owner_approval_keys_v2(owner_id,key_id,public_identity_json,state,version,created_at,updated_at) VALUES(?,?,?,'ACTIVE',1,?,?)`, b.OwnerID, b.OwnerPublic.ID, string(pub), now(), now()); err != nil {
		return nil, ErrHubAccountRejected
	}
	if _, err = registerClientDeviceFromOwnerGrantTx(tx, RegisterClientDeviceInput{OwnerID: b.OwnerID, OwnerKeyID: b.OwnerPublic.ID, DeviceID: b.DeviceID, DevicePublic: b.DevicePublic, OwnerDeviceGrant: a.Grant}); err != nil {
		return nil, err
	}
	bind, _ := json.Marshal(b)
	if _, err = tx.Exec(`INSERT INTO hub_app_leases_v1 VALUES(?,?,?,?,?,?,?,?,?,'ACTIVE')`, b.OwnerID, b.DeviceID, b.AccountID, b.ActivationID, string(bind), b.AccountEpoch, b.DeviceEpoch, b.OwnerPublic.ID, b.LeaseExpiresAt); err != nil {
		return nil, ErrHubAccountRejected
	}
	if _, err = tx.Exec(`UPDATE hub_owner_activation_v1 SET state='COMPLETED' WHERE activation_id=? AND state='PREPARED'`, in.ID); err != nil {
		return nil, err
	}
	if err = insertOwnerOperation(tx, in.Operation); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return in.Operation.Response, nil
}

// RejectHubOwnerOperation fences one exact operation before sending its sealed
// refusal. A completion racing this write either committed first or is blocked.
func (s *Store) RejectHubOwnerOperation(o HubOwnerOperation) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	prior, err := ownerOperation(tx, o.AccountID, o.DeviceID, o.ID)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.Digest != o.Digest || prior.Operation != o.Operation {
			return nil, ErrHubAccountRejected
		}
		return prior.Response, nil
	}
	if err = insertOwnerOperation(tx, o); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return o.Response, nil
}
