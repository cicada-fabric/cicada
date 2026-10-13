package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const HubOwnerReady = "HUB_READY"
const HubOwnerLegacyCompat = "LEGACY_COMPAT"

var ErrHubOwnerSetupConflict = errors.New("Hub Owner setup conflicts with existing authority")
var ErrOwnerBootstrapRejected = errors.New("Owner bootstrap authority is unavailable")

type HubOwnerSetup struct {
	HubID               string `json:"hub_id"`
	AccountID           string `json:"account_id"`
	OwnerID             string `json:"owner_id"`
	Name                string `json:"name"`
	Origin              string `json:"origin"`
	AllowLoopbackHTTP   bool   `json:"allow_loopback_http"`
	State               string `json:"state"`
	Provenance          string `json:"provenance"`
	Version             int64  `json:"version"`
	SignerState         string `json:"signer_state"`
	RootEverEstablished bool   `json:"root_ever_established"`
}

func (s *Store) initializeHubOwnerSetupSchema() error {
	_, e := s.db.Exec(`CREATE TABLE hub_owner_setup_v1 (
id INTEGER PRIMARY KEY CHECK(id=1), hub_id TEXT NOT NULL, account_id TEXT NOT NULL UNIQUE,
owner_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, origin TEXT NOT NULL,
allow_loopback_http INTEGER NOT NULL CHECK(allow_loopback_http IN (0,1)),
state TEXT NOT NULL CHECK(state IN ('HUB_READY','LEGACY_COMPAT')),
provenance TEXT NOT NULL CHECK(provenance IN ('LOCAL_SETUP','EXISTING_LEGACY','GENERATED_COMPAT')),
version INTEGER NOT NULL CHECK(version>0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE owner_root_history_v1(owner_id TEXT PRIMARY KEY, established_at TEXT NOT NULL);
INSERT INTO owner_root_history_v1 SELECT owner_id,min(created_at) FROM owner_approval_keys_v2 GROUP BY owner_id;
CREATE TRIGGER owner_root_history_v1_no_delete BEFORE DELETE ON owner_root_history_v1 BEGIN SELECT RAISE(ABORT,'Owner root history is permanent'); END;
CREATE TRIGGER owner_root_history_v1_no_update BEFORE UPDATE ON owner_root_history_v1 BEGIN SELECT RAISE(ABORT,'Owner root history is immutable'); END;
CREATE TRIGGER owner_approval_keys_v2_root_history AFTER INSERT ON owner_approval_keys_v2 BEGIN
INSERT OR IGNORE INTO owner_root_history_v1(owner_id,established_at) VALUES(NEW.owner_id,NEW.created_at); END;
CREATE TRIGGER hub_owner_setup_v1_coordinates BEFORE UPDATE ON hub_owner_setup_v1
WHEN NEW.hub_id!=OLD.hub_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.provenance!=OLD.provenance
BEGIN SELECT RAISE(ABORT,'Hub Owner coordinates are immutable'); END;
CREATE TRIGGER hub_owner_setup_v1_no_delete BEFORE DELETE ON hub_owner_setup_v1 BEGIN SELECT RAISE(ABORT,'Hub Owner setup is permanent'); END;
CREATE TRIGGER hub_owner_setup_v1_ready_immutable BEFORE UPDATE ON hub_owner_setup_v1
WHEN OLD.state='HUB_READY' AND (NEW.state!='HUB_READY' OR NEW.origin!=OLD.origin OR NEW.allow_loopback_http!=OLD.allow_loopback_http)
BEGIN SELECT RAISE(ABORT,'Hub setup origin and policy are immutable'); END;
CREATE TABLE owner_bootstrap_authority_v1(
authority_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, owner_id TEXT NOT NULL,
manifest_digest TEXT NOT NULL UNIQUE, pairing_json TEXT NOT NULL, nonce_digest TEXT NOT NULL,
state TEXT NOT NULL CHECK(state IN ('PENDING','CONSUMED','EXPIRED','CANCELLED')),
expires_at TEXT NOT NULL, proof_digest TEXT NOT NULL DEFAULT '', receipt_packet BLOB,
created_at TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT '',
CHECK((state='CONSUMED' AND length(proof_digest)=64 AND receipt_packet IS NOT NULL) OR (state!='CONSUMED' AND proof_digest='' AND receipt_packet IS NULL)));
CREATE UNIQUE INDEX owner_bootstrap_authority_v1_pending ON owner_bootstrap_authority_v1(account_id) WHERE state='PENDING';
CREATE TRIGGER owner_bootstrap_authority_v1_no_delete BEFORE DELETE ON owner_bootstrap_authority_v1 BEGIN SELECT RAISE(ABORT,'Owner bootstrap history is permanent'); END;
CREATE TRIGGER owner_bootstrap_authority_v1_immutable BEFORE UPDATE ON owner_bootstrap_authority_v1
WHEN NEW.authority_id!=OLD.authority_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.manifest_digest!=OLD.manifest_digest OR NEW.pairing_json!=OLD.pairing_json OR NEW.nonce_digest!=OLD.nonce_digest OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at OR OLD.state!='PENDING'
BEGIN SELECT RAISE(ABORT,'Owner bootstrap authority is immutable'); END;`)
	return e
}

type hubOwnerQuerier interface{ QueryRow(string, ...any) *sql.Row }

func hubOwnerSetup(q hubOwnerQuerier) (*HubOwnerSetup, error) {
	var r HubOwnerSetup
	var allow int
	e := q.QueryRow(`SELECT hub_id,account_id,owner_id,name,origin,allow_loopback_http,state,provenance,version FROM hub_owner_setup_v1 WHERE id=1`).Scan(&r.HubID, &r.AccountID, &r.OwnerID, &r.Name, &r.Origin, &allow, &r.State, &r.Provenance, &r.Version)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	r.AllowLoopbackHTTP = allow == 1
	var history, active int
	if e = q.QueryRow(`SELECT count(*) FROM owner_root_history_v1 WHERE owner_id=?`, r.OwnerID).Scan(&history); e != nil {
		return nil, e
	}
	if e = q.QueryRow(`SELECT count(*) FROM owner_approval_keys_v2 WHERE owner_id=? AND state='ACTIVE'`, r.OwnerID).Scan(&active); e != nil {
		return nil, e
	}
	r.RootEverEstablished = history > 0
	r.SignerState = "NEEDS_OWNER_SIGNER"
	if active > 0 {
		r.SignerState = "OWNER_SIGNER_READY"
	}
	return &r, nil
}

func (s *Store) GetHubOwnerSetup() (*HubOwnerSetup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hubOwnerSetup(s.db)
}

// CheckOwnerBootstrapIssueLocal performs no identity or manager creation. It
// lets a local issuer reject an unconfigured StateDir before constructing
// Control, whose compatibility startup otherwise creates legacy coordinates.
func (s *Store) CheckOwnerBootstrapIssueLocal() (*HubOwnerSetup, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := hubOwnerSetup(tx)
	if e != nil {
		return nil, e
	}
	if r == nil || r.State != HubOwnerReady || r.RootEverEstablished || !activeSelfOwnedHuman(tx, r.OwnerID) {
		return nil, ErrOwnerBootstrapRejected
	}
	var hubID string
	if e = tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); e != nil || r.HubID != hubID {
		return nil, ErrOwnerBootstrapRejected
	}
	return r, nil
}

// CheckHubServeSetupLocal prevents an unconfigured fresh production server
// from fabricating compatibility evidence. A preexisting exact legacy human
// may continue to serve while its explicit setup remains pending.
func (s *Store) CheckHubServeSetupLocal(expectedLegacyID string) error {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := hubOwnerSetup(s.db)
	if e != nil {
		return e
	}
	if r != nil {
		if r.Provenance == "GENERATED_COMPAT" || !activeSelfOwnedHuman(s.db, r.OwnerID) {
			return ErrHubOwnerSetupConflict
		}
		return nil
	}
	if expectedLegacyID == "" || !activeSelfOwnedHuman(s.db, expectedLegacyID) {
		return ErrHubOwnerSetupConflict
	}
	return nil
}

func (s *Store) requireOwnerSetupStartupAllowed() error {
	if s == nil || s.maintenance == nil || s.maintenance.lock == nil {
		return ErrHubOwnerSetupConflict
	}
	return RequireStateRestoreStartupAllowed(s.maintenance.lock.Path())
}

func setupCoordinates(name, origin string, allow bool) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
		return "", "", ErrHubOwnerSetupConflict
	}
	origin, e := ownerbootstrap.CanonicalOrigin(origin, allow)
	return name, origin, e
}

func activeSelfOwnedHuman(q hubOwnerQuerier, id string) bool {
	var kind, owner, domain, status string
	e := q.QueryRow(`SELECT kind,owner_id,trust_domain_id,status FROM principals WHERE id=?`, id).Scan(&kind, &owner, &domain, &status)
	return e == nil && kind == PrincipalKindHuman && owner == id && (domain == "" || domain == id) && status == PrincipalStatusActive
}

// InitializeHubOwnerLocal is an independent deployment-channel operation.
// Call before serving a pristine Hub. It accepts no device or signing key.
func (s *Store) InitializeHubOwnerLocal(name, origin string, allow bool) (*HubOwnerSetup, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	name, origin, e := setupCoordinates(name, origin, allow)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	existing, e := hubOwnerSetup(tx)
	if e != nil {
		return nil, e
	}
	if existing != nil {
		if existing.State == HubOwnerReady && existing.Provenance == "LOCAL_SETUP" && existing.Name == name && existing.Origin == origin && existing.AllowLoopbackHTTP == allow && activeSelfOwnedHuman(tx, existing.OwnerID) {
			return existing, nil
		}
		return nil, ErrHubOwnerSetupConflict
	}
	// Any preexisting authority requires the explicit legacy path, never signup.
	tables := []string{"principals", "owner_approval_keys_v2", "owner_root_history_v1", "client_devices_v2", "node_owner_bindings_v2", "groups", "fabric_endpoints", "networks_v2", "fabric_node_credentials", "node_device_binding_requests_v2"}
	for table := range legacyInventoryColumns {
		tables = append(tables, table)
	}
	for _, table := range tables {
		var n int
		if e = tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); e != nil {
			return nil, e
		}
		if n != 0 {
			return nil, ErrHubOwnerSetupConflict
		}
	}
	var hubID string
	if e = tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); e != nil {
		return nil, e
	}
	ownerID, accountID, stamp := NewID("human"), NewID("account"), now()
	_, e = tx.Exec(`INSERT INTO principals(id,kind,owner_id,trust_domain_id,name,display_name,status,credential_hash,version,created_at,updated_at) VALUES(?,?,?,?,?,?,'active','',1,?,?)`, ownerID, PrincipalKindHuman, ownerID, ownerID, name, name, stamp, stamp)
	if e != nil {
		return nil, e
	}
	_, e = tx.Exec(`INSERT INTO hub_owner_setup_v1 VALUES(1,?,?,?,?,?,?,'HUB_READY','LOCAL_SETUP',1,?,?)`, hubID, accountID, ownerID, name, origin, allow, stamp, stamp)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return hubOwnerSetup(s.db)
}

// EnsureHubManagerLocal preserves the exact legacy manager association. A
// generated compatibility Principal is recorded distinctly and cannot be
// adopted as evidence of a preexisting installation or issue root authority.
func (s *Store) EnsureHubManagerLocal(legacyID string) (*HubOwnerSetup, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	if e := validateOwnerApprovalID(legacyID); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := hubOwnerSetup(tx)
	if e != nil {
		return nil, e
	}
	if r != nil {
		if !activeSelfOwnedHuman(tx, r.OwnerID) {
			return nil, ErrHubOwnerSetupConflict
		}
		var currentHub string
		if e = tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&currentHub); e != nil || r.HubID != currentHub {
			return nil, ErrHubOwnerSetupConflict
		}
		return r, nil
	}
	var count int
	if e = tx.QueryRow(`SELECT count(*) FROM principals WHERE id=?`, legacyID).Scan(&count); e != nil {
		return nil, e
	}
	provenance := "EXISTING_LEGACY"
	stamp := now()
	if count == 0 {
		provenance = "GENERATED_COMPAT"
		_, e = tx.Exec(`INSERT INTO principals(id,kind,owner_id,trust_domain_id,name,display_name,status,credential_hash,version,created_at,updated_at) VALUES(?,?,?,?, 'owner','Cicada owner','active','',1,?,?)`, legacyID, PrincipalKindHuman, legacyID, legacyID, stamp, stamp)
		if e != nil {
			return nil, e
		}
	}
	if !activeSelfOwnedHuman(tx, legacyID) {
		return nil, ErrHubOwnerSetupConflict
	}
	var hubID string
	if e = tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); e != nil {
		return nil, e
	}
	_, e = tx.Exec(`INSERT INTO hub_owner_setup_v1 VALUES(1,?,?,?,'Cicada owner','',0,'LEGACY_COMPAT',?,1,?,?)`, hubID, NewID("account"), legacyID, provenance, stamp, stamp)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return hubOwnerSetup(s.db)
}

// AdoptLegacyHubOwnerLocal adds setup metadata to the previously established
// manager, preserving all signed Owner IDs. It never selects a guest human.
func (s *Store) AdoptLegacyHubOwnerLocal(expectedOwnerID, name, origin string, allow bool) (*HubOwnerSetup, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	name, origin, e := setupCoordinates(name, origin, allow)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := hubOwnerSetup(tx)
	if e != nil {
		return nil, e
	}
	if r == nil || r.Provenance != "EXISTING_LEGACY" || r.OwnerID != expectedOwnerID || !activeSelfOwnedHuman(tx, r.OwnerID) {
		return nil, ErrHubOwnerSetupConflict
	}
	if r.State == HubOwnerReady {
		if r.Name == name && r.Origin == origin && r.AllowLoopbackHTTP == allow {
			return r, nil
		}
		return nil, ErrHubOwnerSetupConflict
	}
	_, e = tx.Exec(`UPDATE hub_owner_setup_v1 SET name=?,origin=?,allow_loopback_http=?,state='HUB_READY',version=version+1,updated_at=? WHERE id=1 AND state='LEGACY_COMPAT'`, name, origin, allow, now())
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return hubOwnerSetup(s.db)
}

func (s *Store) CurrentOwnerBootstrapPairing() (*ownerbootstrap.PairingFile, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var encoded string
	e := s.db.QueryRow(`SELECT pairing_json FROM owner_bootstrap_authority_v1 WHERE state='PENDING' AND expires_at>?`, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&encoded)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var p ownerbootstrap.PairingFile
	if e = json.Unmarshal([]byte(encoded), &p); e != nil {
		return nil, e
	}
	return &p, nil
}

// IssueOwnerBootstrapLocal only persists independently reviewed exact public
// material. There is intentionally no online issuer or candidate upload route.
func (s *Store) IssueOwnerBootstrapLocal(p ownerbootstrap.PairingFile, nonceDigest string) (*ownerbootstrap.PairingFile, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	at := time.Now().UTC()
	if p.Validate(at) != nil || len(p.Challenge) == 0 || len(nonceDigest) != 64 {
		return nil, ErrOwnerBootstrapRejected
	}
	expires, _ := time.Parse(time.RFC3339Nano, p.Manifest.ExpiresAt)
	if expires.After(at.Add(ownerbootstrap.MaxLifetime)) {
		return nil, ErrOwnerBootstrapRejected
	}
	encoded, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := hubOwnerSetup(tx)
	if e != nil {
		return nil, e
	}
	m := p.Manifest
	if r == nil || r.State != HubOwnerReady || r.RootEverEstablished || !activeSelfOwnedHuman(tx, r.OwnerID) || r.AccountID != m.AccountID || r.OwnerID != m.OwnerID || r.HubID != m.HubID || r.Origin != p.Origin || r.AllowLoopbackHTTP != p.AllowLoopbackHTTP {
		return nil, ErrOwnerBootstrapRejected
	}
	_, e = tx.Exec(`UPDATE owner_bootstrap_authority_v1 SET state='EXPIRED' WHERE state='PENDING' AND expires_at<=?`, at.Format(time.RFC3339Nano))
	if e != nil {
		return nil, e
	}
	var old string
	e = tx.QueryRow(`SELECT pairing_json FROM owner_bootstrap_authority_v1 WHERE account_id=? AND state='PENDING'`, r.AccountID).Scan(&old)
	if e == nil {
		var current ownerbootstrap.PairingFile
		if json.Unmarshal([]byte(old), &current) != nil || current.Manifest.CandidateFingerprint != m.CandidateFingerprint {
			return nil, ErrOwnerBootstrapRejected
		}
		return &current, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	_, e = tx.Exec(`INSERT INTO owner_bootstrap_authority_v1(authority_id,account_id,owner_id,manifest_digest,pairing_json,nonce_digest,state,expires_at,created_at) VALUES(?,?,?,?,?,?,'PENDING',?,?)`, m.AuthorityID, m.AccountID, m.OwnerID, m.Digest(), string(encoded), nonceDigest, m.ExpiresAt, at.Format(time.RFC3339Nano))
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &p, nil
}

func (s *Store) OwnerBootstrapPairing(authorityID string) (*ownerbootstrap.PairingFile, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var encoded string
	if e := s.db.QueryRow(`SELECT pairing_json FROM owner_bootstrap_authority_v1 WHERE authority_id=?`, authorityID).Scan(&encoded); e != nil {
		return nil, ErrOwnerBootstrapRejected
	}
	var p ownerbootstrap.PairingFile
	if json.Unmarshal([]byte(encoded), &p) != nil {
		return nil, ErrOwnerBootstrapRejected
	}
	return &p, nil
}

// OwnerBootstrapPreflight is a bounded eligibility snapshot, not permission to
// register a key. Completion must recheck the same state in its write transaction.
// A cached receipt is already committed, and is released only for exact bytes
// authenticated by the original accepted proof digest and current root state.
type OwnerBootstrapPreflight struct {
	Pairing       *ownerbootstrap.PairingFile
	CachedReceipt []byte
}

func ownerBootstrapEligibleTx(q hubOwnerQuerier, p ownerbootstrap.PairingFile, state, expires, storedProof, proofDigest string) error {
	r, e := hubOwnerSetup(q)
	if e != nil {
		return e
	}
	m := p.Manifest
	if r == nil || r.State != HubOwnerReady || r.AccountID != m.AccountID || r.OwnerID != m.OwnerID || r.HubID != m.HubID || r.Origin != p.Origin || r.AllowLoopbackHTTP != p.AllowLoopbackHTTP || !activeSelfOwnedHuman(q, r.OwnerID) {
		return ErrOwnerBootstrapRejected
	}
	var hubID string
	if e = q.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); e != nil || hubID != m.HubID {
		return ErrOwnerBootstrapRejected
	}
	if state == "CONSUMED" {
		if !r.RootEverEstablished || storedProof != proofDigest {
			return ErrOwnerBootstrapRejected
		}
		var public string
		e = q.QueryRow(`SELECT public_identity_json FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=? AND state='ACTIVE' AND version=1`, m.OwnerID, m.CandidatePublic.ID).Scan(&public)
		expected, _ := json.Marshal(m.CandidatePublic)
		if e != nil || public != string(expected) {
			return ErrOwnerBootstrapRejected
		}
		return nil
	}
	expiry, e := time.Parse(time.RFC3339Nano, expires)
	if e != nil || state != "PENDING" || !expiry.After(time.Now().UTC()) || r.RootEverEstablished {
		return ErrOwnerBootstrapRejected
	}
	return nil
}

// PreflightOwnerBootstrap rejects expired, revoked, changed and unknown
// authority before cryptographic verification; it does not consume anything.
func (s *Store) PreflightOwnerBootstrap(route clientwire.Route, proofDigest string) (*OwnerBootstrapPreflight, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	if len(proofDigest) != 64 || !strings.HasPrefix(route.DeviceID, "bootstrap_") || len(route.DeviceID) > 138 {
		return nil, ErrOwnerBootstrapRejected
	}
	authorityID := strings.TrimPrefix(route.DeviceID, "bootstrap_")
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var encoded, state, expires, storedProof string
	var cached []byte
	e = tx.QueryRow(`SELECT pairing_json,state,expires_at,proof_digest,receipt_packet FROM owner_bootstrap_authority_v1 WHERE authority_id=?`, authorityID).Scan(&encoded, &state, &expires, &storedProof, &cached)
	if e != nil {
		return nil, ErrOwnerBootstrapRejected
	}
	var p ownerbootstrap.PairingFile
	if json.Unmarshal([]byte(encoded), &p) != nil || route != p.Route(clientwire.DirectionRequest, 1) {
		return nil, ErrOwnerBootstrapRejected
	}
	if e = ownerBootstrapEligibleTx(tx, p, state, expires, storedProof, proofDigest); e != nil {
		return nil, e
	}
	result := &OwnerBootstrapPreflight{Pairing: &p}
	if state == "CONSUMED" {
		if len(cached) == 0 || len(cached) > 262144 {
			return nil, ErrOwnerBootstrapRejected
		}
		result.CachedReceipt = append([]byte(nil), cached...)
	}
	return result, nil
}

// CompleteOwnerBootstrap atomically consumes finite authority, persists only
// public root material and caches the exact encrypted receipt for lost responses.
func (s *Store) CompleteOwnerBootstrap(authorityID, nonceDigest, proofDigest string, receipt []byte) ([]byte, error) {
	if e := s.requireOwnerSetupStartupAllowed(); e != nil {
		return nil, e
	}
	if len(proofDigest) != 64 || len(nonceDigest) != 64 || len(receipt) == 0 || len(receipt) > 262144 {
		return nil, ErrOwnerBootstrapRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var encoded, storedNonce, state, expires, storedProof string
	var cached []byte
	e = tx.QueryRow(`SELECT pairing_json,nonce_digest,state,expires_at,proof_digest,receipt_packet FROM owner_bootstrap_authority_v1 WHERE authority_id=?`, authorityID).Scan(&encoded, &storedNonce, &state, &expires, &storedProof, &cached)
	if e != nil {
		return nil, ErrOwnerBootstrapRejected
	}
	var p ownerbootstrap.PairingFile
	if json.Unmarshal([]byte(encoded), &p) != nil || storedNonce != nonceDigest {
		return nil, ErrOwnerBootstrapRejected
	}
	if e = ownerBootstrapEligibleTx(tx, p, state, expires, storedProof, proofDigest); e != nil {
		return nil, e
	}
	m := p.Manifest
	if state == "CONSUMED" {
		return cached, nil
	}
	public, e := json.Marshal(m.CandidatePublic)
	if e != nil {
		return nil, e
	}
	stamp := now()
	_, e = tx.Exec(`INSERT INTO owner_approval_keys_v2(owner_id,key_id,public_identity_json,state,version,created_at,updated_at) VALUES(?,?,?,'ACTIVE',1,?,?)`, m.OwnerID, m.CandidatePublic.ID, string(public), stamp, stamp)
	if e != nil {
		return nil, fmt.Errorf("%w: root registration conflict", ErrOwnerBootstrapRejected)
	}
	_, e = tx.Exec(`UPDATE owner_bootstrap_authority_v1 SET state='CONSUMED',proof_digest=?,receipt_packet=?,consumed_at=? WHERE authority_id=? AND state='PENDING'`, proofDigest, receipt, stamp, authorityID)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return receipt, nil
}
