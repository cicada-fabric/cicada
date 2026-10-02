package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

const (
	NodeTLSReserved                        = "RESERVED"
	NodeTLSIssuing                         = "ISSUING"
	NodeTLSSigned                          = "SIGNED"
	NodeTLSInstalled                       = "INSTALLED"
	NodeTLSActive                          = "ACTIVE"
	NodeTLSCancelled                       = "CANCELLED"
	NodeTLSRevoked                         = "REVOKED"
	NodeTLSUncertain                       = "UNCERTAIN"
	NodeTLSAuthorityReservationCapacity    = 100000
	NodeTLSAuthorityNonceCapacity          = 300000
	NodeTLSAuthorityApplicationKeyCapacity = 1024
	NodeTLSAuthorityInventoryRowCapacity   = 8192
	NodeTLSAuthorityInventoryByteCapacity  = 64 << 20
)

var (
	ErrNodeTLSAuthorityDenied    = errors.New("Node TLS authority is not current or approved")
	ErrNodeTLSAuthorityConflict  = errors.New("Node TLS authority candidate or version conflicts")
	ErrNodeTLSAuthorityCapacity  = errors.New("Node TLS authority permanent ledger reached its safe capacity")
	ErrNodeTLSAuthorityUncertain = errors.New("Node TLS issuance is uncertain; reservation cannot be reused")
)

// These APIs are trusted offline library entry points. Do not expose reservation
// behind a Node bearer, CSR upload, model tool, general RPC or manager API.
// All materials below are public; issuer and TLS private keys never enter Store.
type NodeTLSCandidateInput struct {
	RequestID, NodeID, CredentialDigest                                string
	CSRPEM, IssuerChainPEM, TrustAnchorPEM                             []byte
	Parameters                                                         pqtls.TLSCSRParameters
	Issuer                                                             pqtls.TLSIssuerProfile
	IssuerGeneration                                                   string
	NotBefore, NotAfter                                                time.Time
	ExpectedTLSEpochFloor                                              uint64
	HubSPKIHash, HubTrustAnchorDERHash, HubPQOrigin, ApplicationOrigin string
	GrantIssuedAt, GrantExpiresAt                                      time.Time
	GrantNonce                                                         string
}

type NodeTLSAuthoritySnapshot struct {
	State              string                       `json:"state"`
	RowVersion         uint64                       `json:"row_version"`
	ReservationVersion uint64                       `json:"reservation_version"`
	Claims             e2ee.OwnerTLSLeafGrantClaims `json:"claims"`
	Grant              []byte                       `json:"grant"`
	CSRPEM             []byte                       `json:"csr_pem"`
	IssuerChainPEM     []byte                       `json:"issuer_chain_pem"`
	TrustAnchorPEM     []byte                       `json:"trust_anchor_pem"`
	LeafCertificatePEM []byte                       `json:"leaf_certificate_pem"`
	LeafDERHash        string                       `json:"leaf_der_hash"`
	InstallAck         []byte                       `json:"install_ack"`
	Activation         []byte                       `json:"activation"`
}

type NodeTLSAuthorityActionInput struct {
	RequestID, NodeID, CredentialDigest string
	ExpectedVersion                     uint64
}

type NodeTLSLeafIssueInput struct {
	NodeTLSAuthorityActionInput
	Grant []byte
}

type NodeTLSInstallAckInput struct {
	NodeTLSAuthorityActionInput
	InstallAck []byte
}

type NodeTLSActivationInput struct {
	NodeTLSAuthorityActionInput
	Activation []byte
}

func (s *Store) initializeNodeTLSAuthorityV1Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS node_tls_authority_v1 (
 request_id TEXT PRIMARY KEY, hub_id TEXT NOT NULL, node_id TEXT NOT NULL,
 issuer_spki_hash TEXT NOT NULL CHECK(length(issuer_spki_hash)=64),
 serial TEXT NOT NULL CHECK(length(serial)=32), tls_epoch INTEGER NOT NULL CHECK(tls_epoch>0),
 candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64), claims_json TEXT NOT NULL,
 csr_pem BLOB NOT NULL, issuer_chain_pem BLOB NOT NULL, trust_anchor_pem BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('RESERVED','ISSUING','SIGNED','INSTALLED','ACTIVE','CANCELLED','REVOKED','UNCERTAIN')),
 version INTEGER NOT NULL CHECK(version>0), reservation_version INTEGER NOT NULL CHECK(reservation_version=1),
 grant BLOB NOT NULL DEFAULT X'', leaf_pem BLOB NOT NULL DEFAULT X'', leaf_der_hash TEXT NOT NULL DEFAULT '',
 install_ack BLOB NOT NULL DEFAULT X'', activation BLOB NOT NULL DEFAULT X'', updated_at TEXT NOT NULL,
 UNIQUE(hub_id,node_id,tls_epoch), UNIQUE(issuer_spki_hash,serial),
 CHECK(state NOT IN ('ISSUING','SIGNED','INSTALLED','ACTIVE') OR length(grant)>0),
 CHECK(state NOT IN ('SIGNED','INSTALLED','ACTIVE') OR (length(leaf_pem)>0 AND length(leaf_der_hash)=64)),
 CHECK(state NOT IN ('INSTALLED','ACTIVE') OR length(install_ack)>0),
 CHECK(state!='ACTIVE' OR length(activation)>0)
);
CREATE UNIQUE INDEX IF NOT EXISTS node_tls_authority_v1_one_active ON node_tls_authority_v1(hub_id,node_id) WHERE state='ACTIVE';
CREATE TABLE IF NOT EXISTS node_tls_epoch_floors_v1 (
 hub_id TEXT NOT NULL, node_id TEXT NOT NULL, floor INTEGER NOT NULL CHECK(floor>0), PRIMARY KEY(hub_id,node_id)
);
CREATE TABLE IF NOT EXISTS node_tls_issuer_serial_floors_v1 (
 issuer_spki_hash TEXT PRIMARY KEY CHECK(length(issuer_spki_hash)=64), floor TEXT NOT NULL CHECK(length(floor)=32)
);
CREATE TABLE IF NOT EXISTS node_tls_proof_nonces_v1 (
 nonce TEXT PRIMARY KEY CHECK(length(nonce)=64), purpose TEXT NOT NULL CHECK(purpose IN ('GRANT','INSTALL','ACTIVATION')),
 request_id TEXT NOT NULL, proof_digest TEXT NOT NULL, FOREIGN KEY(request_id) REFERENCES node_tls_authority_v1(request_id)
);
CREATE TABLE IF NOT EXISTS node_tls_application_keys_v1 (
 signing_public BLOB PRIMARY KEY CHECK(length(signing_public)=1952)
);
CREATE TRIGGER IF NOT EXISTS node_tls_authority_v1_candidate_immutable BEFORE UPDATE OF
 request_id,hub_id,node_id,issuer_spki_hash,serial,tls_epoch,candidate_digest,claims_json,csr_pem,issuer_chain_pem,trust_anchor_pem,reservation_version
 ON node_tls_authority_v1 BEGIN SELECT RAISE(ABORT,'immutable Node TLS candidate'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_authority_v1_no_delete BEFORE DELETE ON node_tls_authority_v1
 BEGIN SELECT RAISE(ABORT,'permanent Node TLS reservation'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_proof_nonces_v1_no_delete BEFORE DELETE ON node_tls_proof_nonces_v1
 BEGIN SELECT RAISE(ABORT,'permanent Node TLS nonce'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_proof_nonces_v1_no_update BEFORE UPDATE ON node_tls_proof_nonces_v1
 BEGIN SELECT RAISE(ABORT,'immutable Node TLS nonce'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_authority_v1_evidence_immutable BEFORE UPDATE OF grant,leaf_pem,leaf_der_hash,install_ack,activation ON node_tls_authority_v1
 WHEN (length(OLD.grant)>0 AND NEW.grant!=OLD.grant) OR
 (length(OLD.leaf_pem)>0 AND (NEW.leaf_pem!=OLD.leaf_pem OR NEW.leaf_der_hash!=OLD.leaf_der_hash)) OR
 (length(OLD.install_ack)>0 AND NEW.install_ack!=OLD.install_ack) OR
 (length(OLD.activation)>0 AND NEW.activation!=OLD.activation)
 BEGIN SELECT RAISE(ABORT,'immutable Node TLS evidence'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_epoch_floors_v1_no_delete BEFORE DELETE ON node_tls_epoch_floors_v1
 BEGIN SELECT RAISE(ABORT,'permanent Node TLS epoch floor'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_issuer_serial_floors_v1_no_delete BEFORE DELETE ON node_tls_issuer_serial_floors_v1
 BEGIN SELECT RAISE(ABORT,'permanent Node TLS serial floor'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_application_keys_v1_no_delete BEFORE DELETE ON node_tls_application_keys_v1
 BEGIN SELECT RAISE(ABORT,'permanent Node TLS application key'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_application_keys_v1_no_update BEFORE UPDATE ON node_tls_application_keys_v1
 BEGIN SELECT RAISE(ABORT,'immutable Node TLS application key'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_epoch_floors_v1_monotone BEFORE UPDATE ON node_tls_epoch_floors_v1
 WHEN NEW.hub_id!=OLD.hub_id OR NEW.node_id!=OLD.node_id OR NEW.floor<=OLD.floor
 BEGIN SELECT RAISE(ABORT,'Node TLS epoch floor rollback'); END;
CREATE TRIGGER IF NOT EXISTS node_tls_issuer_serial_floors_v1_monotone BEFORE UPDATE ON node_tls_issuer_serial_floors_v1
 WHEN NEW.issuer_spki_hash!=OLD.issuer_spki_hash OR NEW.floor<=OLD.floor
 BEGIN SELECT RAISE(ABORT,'Node TLS serial floor rollback'); END;
`)
	return err
}

func nodeTLSStamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
func nodeTLSNow() time.Time           { return time.Now().UTC().Truncate(time.Second) }
func nodeTLSHash(h [32]byte) string   { return hex.EncodeToString(h[:]) }

func nodeTLSIssuerMaterial(chain, root []byte) (spki, issuerDER, rootDER string, err error) {
	actual, err := pqtls.TLSIssuerSigningSPKIHash(chain)
	if err != nil {
		return "", "", "", err
	}
	var blocks [][]byte
	rest := bytes.TrimSpace(chain)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > pqtls.MaxTLSCertificatePEMBytes {
			return "", "", "", ErrNodeTLSAuthorityDenied
		}
		blocks = append(blocks, block.Bytes)
		rest = bytes.TrimSpace(next)
	}
	trusted, trailing := pem.Decode(bytes.TrimSpace(root))
	if len(blocks) < 2 || len(blocks) > pqtls.MaxTLSIssuerChainLength || trusted == nil || trusted.Type != "CERTIFICATE" || len(trusted.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 || !bytes.Equal(trusted.Bytes, blocks[len(blocks)-1]) {
		return "", "", "", ErrNodeTLSAuthorityDenied
	}
	return nodeTLSHash(actual), nodeTLSHash(sha256.Sum256(blocks[0])), nodeTLSHash(sha256.Sum256(trusted.Bytes)), nil
}

func nodeTLSCurrentAuthorityTx(tx *sql.Tx, credential, nodeID string) (*NodeControlKeyBinding, *OwnerApprovalKey, uint64, error) {
	b, err := nodeControlCurrentBindingTx(tx, credential, nodeID)
	if err != nil {
		return nil, nil, 0, ErrNodeTLSAuthorityDenied
	}
	owner, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at
FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=? AND state='ACTIVE'`, b.OwnerID, b.OwnerKeyID))
	if err != nil || owner.Version <= 0 {
		return nil, nil, 0, ErrNodeTLSAuthorityDenied
	}
	var deviceVersion int64
	err = tx.QueryRow(`SELECT version FROM client_devices_v2 WHERE owner_id=? AND device_id=? AND owner_key_id=? AND state='ACTIVE'`, b.OwnerID, b.ClientDeviceID, b.OwnerKeyID).Scan(&deviceVersion)
	if err != nil || deviceVersion <= 0 {
		return nil, nil, 0, ErrNodeTLSAuthorityDenied
	}
	return b, owner, uint64(deviceVersion), nil
}

func nodeTLSMatchesAuthority(c e2ee.OwnerTLSLeafGrantClaims, b *NodeControlKeyBinding, owner *OwnerApprovalKey, deviceVersion uint64) bool {
	return c.HubID == b.HubID && c.NodeID == b.NodeID && c.OwnerID == b.OwnerID && c.OwnerKeyID == b.OwnerKeyID && c.OwnerKeyVersion == uint64(owner.Version) &&
		c.ClientDeviceID == b.ClientDeviceID && c.ClientDeviceVersion == deviceVersion && c.OwnerBindingID == b.OwnerBindingID && c.OwnerBindingVersion == b.BindingVersion &&
		c.CredentialDigest == b.CredentialDigest && c.CredentialVersion == b.NodeCredentialVersion && c.NodeControlKeyID == b.NodeKeyID &&
		c.NodeControlKeyVersion == b.NodeKeyVersion && c.NodeControlKeyEpoch == b.NodeKeyEpoch && c.NodeControlBindingVersion == b.Version && c.HubControlKeyID == b.HubKeyID && c.HubControlKeyVersion == b.HubKeyVersion
}

// Retained historical, revoked, pending and current public keys all count. This
// inventory cannot recover keys already deleted before this checkpoint, or keys
// never disclosed to this Hub. The dedicated tombstone table retains keys seen
// during authority mutations. No caller-provided inventory is trusted.
func nodeTLSApplicationKeysTx(tx *sql.Tx, retain bool) ([][]byte, error) {
	queries := []struct {
		sql  string
		kind int
	}{
		{`SELECT public_identity_json FROM owner_approval_keys_v2`, 0},
		{`SELECT public_identity_json FROM client_devices_v2`, 0},
		{`SELECT public_identity_json FROM endpoint_key_candidates_v2`, 0},
		{`SELECT public_identity_json FROM network_direct_key_candidates_v2`, 0},
		{`SELECT node_public_identity_json FROM node_control_key_requests_v1 UNION ALL SELECT hub_public_identity_json FROM node_control_key_requests_v1`, 0},
		{`SELECT node_public_identity_json FROM node_control_key_bindings_v1 UNION ALL SELECT hub_public_identity_json FROM node_control_key_bindings_v1`, 0},
		{`SELECT source_public_identity_json FROM group_broadcast_v2_snapshots UNION ALL SELECT public_identity_json FROM group_broadcast_v2_snapshot_recipients`, 0},
		{`SELECT identity_json FROM contacts UNION ALL SELECT identity_json FROM contact_discovery_requests UNION ALL SELECT identity_json FROM directory_records`, 0},
		{`SELECT manifest_json FROM group_endpoint_key_grants_v2`, 1},
		{`SELECT manifest_json FROM cross_owner_group_key_proofs_v2`, 2},
		{`SELECT snapshot_json FROM group_space_records_v2`, 3},
		{`SELECT recipient_json FROM group_space_history_manifests_v2 UNION ALL SELECT resharer_json FROM group_space_history_manifests_v2 UNION ALL SELECT resharer_json FROM group_space_history_grants_v2`, 4},
	}
	keys := make(map[string][]byte)
	var inventoryRows, inventoryBytes int
	add := func(raw []byte) error {
		if len(raw) != 1952 {
			return ErrNodeTLSAuthorityDenied
		}
		keys[string(raw)] = bytes.Clone(raw)
		if len(keys) > NodeTLSAuthorityApplicationKeyCapacity {
			return ErrNodeTLSAuthorityCapacity
		}
		return nil
	}
	addPublic := func(public e2ee.PublicIdentity, optional bool) error {
		if optional && public.ID == "" && len(public.KEMPublic) == 0 && len(public.SigningPublic) == 0 {
			return nil
		}
		if e2ee.ValidatePublicIdentity(public) != nil {
			return ErrNodeTLSAuthorityDenied
		}
		return add(public.SigningPublic)
	}
	addEvidence := func(e GroupSpaceEndpointEvidence) error {
		if err := addPublic(e.PublicIdentity, false); err != nil {
			return err
		}
		if err := addPublic(e.Candidate.Public, true); err != nil {
			return err
		}
		if err := addPublic(e.Grant.Manifest.CandidatePublicIdentity, true); err != nil {
			return err
		}
		if e.CrossOwnerKeyStatus != nil {
			return addPublic(e.CrossOwnerKeyStatus.Manifest.CandidatePublicIdentity, false)
		}
		return nil
	}
	rows, err := tx.Query(`SELECT signing_public FROM node_tls_application_keys_v1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err = add(raw); err != nil {
			rows.Close()
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, q := range queries {
		rows, err = tx.Query(q.sql)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var encoded string
			if err = rows.Scan(&encoded); err != nil {
				rows.Close()
				return nil, err
			}
			inventoryRows++
			inventoryBytes += len(encoded)
			if inventoryRows > NodeTLSAuthorityInventoryRowCapacity || inventoryBytes > NodeTLSAuthorityInventoryByteCapacity || len(encoded) > 4<<20 {
				rows.Close()
				return nil, ErrNodeTLSAuthorityCapacity
			}
			switch q.kind {
			case 0:
				var public e2ee.PublicIdentity
				if json.Unmarshal([]byte(encoded), &public) != nil {
					err = ErrNodeTLSAuthorityDenied
				} else {
					err = addPublic(public, false)
				}
			case 1:
				var m GroupEndpointKeyGrantManifest
				if json.Unmarshal([]byte(encoded), &m) != nil {
					err = ErrNodeTLSAuthorityDenied
				} else {
					err = addPublic(m.CandidatePublicIdentity, false)
				}
			case 2:
				var m CrossOwnerGroupKeyManifest
				if json.Unmarshal([]byte(encoded), &m) != nil {
					err = ErrNodeTLSAuthorityDenied
				} else {
					err = addPublic(m.CandidatePublicIdentity, false)
				}
			case 3:
				var m GroupSpaceSnapshot
				if json.Unmarshal([]byte(encoded), &m) != nil {
					err = ErrNodeTLSAuthorityDenied
				} else if len(m.Readers) > 32 {
					err = ErrNodeTLSAuthorityCapacity
				} else {
					err = addEvidence(m.Producer)
					if err == nil {
						for _, e := range m.Readers {
							if err = addEvidence(e); err != nil {
								break
							}
						}
					}
				}
			case 4:
				var e GroupSpaceEndpointEvidence
				if json.Unmarshal([]byte(encoded), &e) != nil {
					err = ErrNodeTLSAuthorityDenied
				} else {
					err = addEvidence(e)
				}
			default:
				err = ErrNodeTLSAuthorityDenied
			}
			if err != nil {
				rows.Close()
				return nil, err
			}
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	if len(keys) == 0 {
		return nil, ErrNodeTLSAuthorityDenied
	}
	list := make([][]byte, 0, len(keys))
	for _, raw := range keys {
		list = append(list, raw)
		if retain {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO node_tls_application_keys_v1(signing_public) VALUES(?)`, raw); err != nil {
				return nil, err
			}
		}
	}
	return list, nil
}

func nodeTLSKeySeparationTx(tx *sql.Tx, csr []byte, p pqtls.TLSCSRParameters, retain bool) error {
	keys, err := nodeTLSApplicationKeysTx(tx, retain)
	if err != nil {
		return err
	}
	return pqtls.CheckTLSCSRApplicationKeySeparation(csr, p, keys)
}

func nodeTLSNextSerial(floor string) (string, error) {
	var serial [16]byte
	if floor != "" {
		raw, err := hex.DecodeString(floor)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != floor {
			return "", ErrNodeTLSAuthorityDenied
		}
		copy(serial[:], raw)
	}
	for i := len(serial) - 1; i >= 0; i-- {
		serial[i]++
		if serial[i] != 0 {
			return hex.EncodeToString(serial[:]), nil
		}
	}
	return "", ErrNodeTLSAuthorityCapacity
}

func readNodeTLSAuthorityTx(tx *sql.Tx, requestID string) (*NodeTLSAuthoritySnapshot, error) {
	var r NodeTLSAuthoritySnapshot
	var encoded, hubID, nodeID, issuerSPKI, serial, candidateDigest string
	var tlsEpoch uint64
	err := tx.QueryRow(`SELECT state,version,reservation_version,claims_json,grant,csr_pem,issuer_chain_pem,trust_anchor_pem,leaf_pem,leaf_der_hash,install_ack,activation
 ,hub_id,node_id,issuer_spki_hash,serial,tls_epoch,candidate_digest
FROM node_tls_authority_v1 WHERE request_id=?`, requestID).Scan(&r.State, &r.RowVersion, &r.ReservationVersion, &encoded, &r.Grant, &r.CSRPEM, &r.IssuerChainPEM, &r.TrustAnchorPEM, &r.LeafCertificatePEM, &r.LeafDERHash, &r.InstallAck, &r.Activation, &hubID, &nodeID, &issuerSPKI, &serial, &tlsEpoch, &candidateDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(encoded), &r.Claims) != nil || e2ee.ValidateOwnerTLSLeafGrantClaims(r.Claims) != nil || r.Claims.RequestID != requestID || r.ReservationVersion != 1 || r.RowVersion == 0 || r.RowVersion > math.MaxInt64 || r.Claims.HubID != hubID || r.Claims.NodeID != nodeID || r.Claims.IssuerSPKIHash != issuerSPKI || r.Claims.Serial != serial || r.Claims.TLSEpoch != tlsEpoch || nodeTLSCandidateDigest(r.Claims, r.CSRPEM, r.IssuerChainPEM, r.TrustAnchorPEM) != candidateDigest {
		return nil, ErrNodeTLSAuthorityDenied
	}
	var floor uint64
	var serialFloor string
	if err := tx.QueryRow(`SELECT floor FROM node_tls_epoch_floors_v1 WHERE hub_id=? AND node_id=?`, hubID, nodeID).Scan(&floor); err != nil || floor < tlsEpoch {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if err := tx.QueryRow(`SELECT floor FROM node_tls_issuer_serial_floors_v1 WHERE issuer_spki_hash=?`, issuerSPKI).Scan(&serialFloor); err != nil || len(serialFloor) != 32 || serialFloor < serial {
		return nil, ErrNodeTLSAuthorityDenied
	}
	var nonceCount int
	if err := tx.QueryRow(`SELECT count(*) FROM node_tls_proof_nonces_v1 WHERE nonce=? AND purpose='GRANT' AND request_id=? AND proof_digest=?`, r.Claims.Nonce, requestID, candidateDigest).Scan(&nonceCount); err != nil || nonceCount != 1 {
		return nil, ErrNodeTLSAuthorityDenied
	}
	return &r, nil
}

func nodeTLSPermanentCapacityTx(tx *sql.Tx, table string, capacity int) error {
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
		return err
	}
	if count >= capacity {
		return ErrNodeTLSAuthorityCapacity
	}
	return nil
}

func nodeTLSConsumeNonceTx(tx *sql.Tx, nonce, purpose, requestID, digest string) error {
	if err := nodeTLSPermanentCapacityTx(tx, "node_tls_proof_nonces_v1", NodeTLSAuthorityNonceCapacity); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM node_tls_proof_nonces_v1 WHERE nonce=?`, nonce).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return ErrNodeTLSAuthorityConflict
	}
	_, err := tx.Exec(`INSERT INTO node_tls_proof_nonces_v1(nonce,purpose,request_id,proof_digest) VALUES(?,?,?,?)`, nonce, purpose, requestID, digest)
	return err
}

func nodeTLSCandidateDigest(c e2ee.OwnerTLSLeafGrantClaims, csr, chain, root []byte) string {
	data, _ := json.Marshal(c)
	for _, material := range [][]byte{csr, chain, root} {
		h := sha256.Sum256(material)
		data = append(data, h[:]...)
	}
	return e2ee.NodeTLSAuthorityDigest(data)
}

func (s *Store) ReserveNodeTLSCandidate(input NodeTLSCandidateInput) (*NodeTLSAuthoritySnapshot, error) {
	if input.ExpectedTLSEpochFloor >= math.MaxInt64 {
		return nil, ErrNodeTLSAuthorityCapacity
	}
	if input.RequestID == "" || input.NodeID == "" || !validNodeCredentialDigest(input.CredentialDigest) || input.Parameters.Role != "node" || input.Issuer.Role != "node" {
		return nil, ErrNodeTLSAuthorityDenied
	}
	csr, err := pqtls.InspectTLSCSR(input.CSRPEM, input.Parameters)
	if err != nil {
		return nil, err
	}
	if len(input.IssuerChainPEM) == 0 || len(input.IssuerChainPEM) > pqtls.MaxTLSCertificatePEMBytes*pqtls.MaxTLSIssuerChainLength || len(input.TrustAnchorPEM) == 0 || len(input.TrustAnchorPEM) > pqtls.MaxTLSCertificatePEMBytes {
		return nil, ErrNodeTLSAuthorityDenied
	}
	actualIssuerSPKI, actualIssuerDER, actualRootDER, err := nodeTLSIssuerMaterial(input.IssuerChainPEM, input.TrustAnchorPEM)
	if err != nil {
		return nil, err
	}
	if actualIssuerSPKI != nodeTLSHash(input.Issuer.SPKIDERHash) || actualIssuerDER != nodeTLSHash(input.Issuer.CertificateDERHash) || actualRootDER != nodeTLSHash(input.Issuer.TrustAnchorDERHash) || input.NotBefore.Before(input.Issuer.VerifiedNotBefore) || input.NotAfter.After(input.Issuer.VerifiedNotAfter) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, owner, dv, err := nodeTLSCurrentAuthorityTx(tx, input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, err
	}
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 1, RequestID: input.RequestID, HubID: b.HubID, NodeID: b.NodeID, OwnerID: b.OwnerID, OwnerKeyID: b.OwnerKeyID, OwnerKeyVersion: uint64(owner.Version), ClientDeviceID: b.ClientDeviceID, ClientDeviceVersion: dv,
		OwnerBindingID: b.OwnerBindingID, OwnerBindingVersion: b.BindingVersion, CredentialDigest: b.CredentialDigest, CredentialVersion: b.NodeCredentialVersion, NodeControlKeyID: b.NodeKeyID, NodeControlKeyVersion: b.NodeKeyVersion, NodeControlKeyEpoch: b.NodeKeyEpoch, NodeControlBindingVersion: b.Version, HubControlKeyID: b.HubKeyID, HubControlKeyVersion: b.HubKeyVersion,
		CSRDERHash: nodeTLSHash(csr.CSRDERHash), SPKIDERHash: nodeTLSHash(csr.SPKIDERHash), IssuerSPKIHash: nodeTLSHash(input.Issuer.SPKIDERHash), IssuerDERHash: nodeTLSHash(input.Issuer.CertificateDERHash), RootDERHash: nodeTLSHash(input.Issuer.TrustAnchorDERHash), IssuerGeneration: input.IssuerGeneration, Role: input.Parameters.Role, DNSName: input.Parameters.DNSName,
		ExpectedTLSEpochFloor: input.ExpectedTLSEpochFloor, TLSEpoch: input.ExpectedTLSEpochFloor + 1, NotBefore: nodeTLSStamp(input.NotBefore), NotAfter: nodeTLSStamp(input.NotAfter), HubSPKIHash: input.HubSPKIHash, HubTrustAnchorDERHash: input.HubTrustAnchorDERHash, HubPQOrigin: input.HubPQOrigin, ApplicationOrigin: input.ApplicationOrigin, ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: nodeTLSStamp(input.GrantIssuedAt), ExpiresAt: nodeTLSStamp(input.GrantExpiresAt), Nonce: input.GrantNonce}
	var floor uint64
	err = tx.QueryRow(`SELECT floor FROM node_tls_epoch_floors_v1 WHERE hub_id=? AND node_id=?`, b.HubID, b.NodeID).Scan(&floor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var serialFloor string
	err = tx.QueryRow(`SELECT floor FROM node_tls_issuer_serial_floors_v1 WHERE issuer_spki_hash=?`, c.IssuerSPKIHash).Scan(&serialFloor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	previous, previousErr := readNodeTLSAuthorityTx(tx, input.RequestID)
	if previousErr == nil {
		c.Serial = previous.Claims.Serial
	} else {
		if !errors.Is(previousErr, ErrNodeTLSAuthorityDenied) {
			return nil, previousErr
		}
		c.Serial, err = nodeTLSNextSerial(serialFloor)
		if err != nil {
			return nil, err
		}
	}
	if e2ee.ValidateOwnerTLSLeafGrantClaims(c) != nil || !input.NotBefore.Equal(input.NotBefore.UTC().Truncate(time.Second)) || !input.NotAfter.Equal(input.NotAfter.UTC().Truncate(time.Second)) || !input.GrantIssuedAt.Equal(input.GrantIssuedAt.UTC().Truncate(time.Second)) || !input.GrantExpiresAt.Equal(input.GrantExpiresAt.UTC().Truncate(time.Second)) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	digest := nodeTLSCandidateDigest(c, csr.CSRPEM, input.IssuerChainPEM, input.TrustAnchorPEM)
	if previousErr == nil {
		if nodeTLSCandidateDigest(previous.Claims, previous.CSRPEM, previous.IssuerChainPEM, previous.TrustAnchorPEM) != digest || previous.State == NodeTLSCancelled || previous.State == NodeTLSRevoked || previous.State == NodeTLSUncertain {
			return nil, ErrNodeTLSAuthorityConflict
		}
		if err = nodeTLSKeySeparationTx(tx, csr.CSRPEM, input.Parameters, true); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if floor != input.ExpectedTLSEpochFloor {
		return nil, ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSPermanentCapacityTx(tx, "node_tls_authority_v1", NodeTLSAuthorityReservationCapacity); err != nil {
		return nil, err
	}
	if err = nodeTLSKeySeparationTx(tx, csr.CSRPEM, input.Parameters, true); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(c)
	_, err = tx.Exec(`INSERT INTO node_tls_authority_v1(request_id,hub_id,node_id,issuer_spki_hash,serial,tls_epoch,candidate_digest,claims_json,csr_pem,issuer_chain_pem,trust_anchor_pem,state,version,reservation_version,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'RESERVED',1,1,?)`, c.RequestID, c.HubID, c.NodeID, c.IssuerSPKIHash, c.Serial, c.TLSEpoch, digest, string(encoded), csr.CSRPEM, input.IssuerChainPEM, input.TrustAnchorPEM, nodeTLSStamp(nodeTLSNow()))
	if err != nil {
		return nil, ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSConsumeNonceTx(tx, c.Nonce, "GRANT", c.RequestID, digest); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO node_tls_epoch_floors_v1(hub_id,node_id,floor) VALUES(?,?,?) ON CONFLICT(hub_id,node_id) DO UPDATE SET floor=excluded.floor`, c.HubID, c.NodeID, c.TLSEpoch)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO node_tls_issuer_serial_floors_v1(issuer_spki_hash,floor) VALUES(?,?) ON CONFLICT(issuer_spki_hash) DO UPDATE SET floor=excluded.floor`, c.IssuerSPKIHash, c.Serial)
	if err != nil {
		return nil, err
	}
	r, err := readNodeTLSAuthorityTx(tx, c.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func NodeTLSLeafParameters(claims e2ee.OwnerTLSLeafGrantClaims) (pqtls.TLSLeafParameters, error) {
	if e2ee.ValidateOwnerTLSLeafGrantClaims(claims) != nil {
		return pqtls.TLSLeafParameters{}, ErrNodeTLSAuthorityDenied
	}
	nb, err := time.Parse(time.RFC3339, claims.NotBefore)
	if err != nil {
		return pqtls.TLSLeafParameters{}, ErrNodeTLSAuthorityDenied
	}
	na, err := time.Parse(time.RFC3339, claims.NotAfter)
	if err != nil {
		return pqtls.TLSLeafParameters{}, ErrNodeTLSAuthorityDenied
	}
	p := pqtls.TLSLeafParameters{TLSCSRParameters: pqtls.TLSCSRParameters{Role: claims.Role, DNSName: claims.DNSName}, NotBefore: nb.UTC(), NotAfter: na.UTC()}
	serial, _ := hex.DecodeString(claims.Serial)
	copy(p.Serial[:], serial)
	spki, _ := hex.DecodeString(claims.SPKIDERHash)
	copy(p.ExpectedSPKIHash[:], spki)
	return p, nil
}

func nodeTLSValidateSnapshotTx(tx *sql.Tx, r *NodeTLSAuthoritySnapshot, credential, nodeID string, at time.Time, retain bool) (*NodeControlKeyBinding, error) {
	b, owner, dv, err := nodeTLSCurrentAuthorityTx(tx, credential, nodeID)
	if err != nil || !nodeTLSMatchesAuthority(r.Claims, b, owner, dv) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	grant, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public, at, r.Grant)
	if err != nil || grant != r.Claims {
		return nil, ErrNodeTLSAuthorityDenied
	}
	p, err := NodeTLSLeafParameters(r.Claims)
	if err != nil {
		return nil, err
	}
	actualIssuerSPKI, actualIssuerDER, actualRootDER, err := nodeTLSIssuerMaterial(r.IssuerChainPEM, r.TrustAnchorPEM)
	if err != nil {
		return nil, err
	}
	if actualIssuerSPKI != r.Claims.IssuerSPKIHash || actualIssuerDER != r.Claims.IssuerDERHash || actualRootDER != r.Claims.RootDERHash {
		return nil, ErrNodeTLSAuthorityDenied
	}
	csr, err := pqtls.InspectTLSCSR(r.CSRPEM, p.TLSCSRParameters)
	if err != nil {
		return nil, err
	}
	if nodeTLSHash(csr.CSRDERHash) != r.Claims.CSRDERHash || nodeTLSHash(csr.SPKIDERHash) != r.Claims.SPKIDERHash {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if err = nodeTLSKeySeparationTx(tx, r.CSRPEM, p.TLSCSRParameters, retain); err != nil {
		return nil, err
	}
	if len(r.LeafCertificatePEM) > 0 {
		leaf, err := pqtls.InspectTLSLeaf(r.LeafCertificatePEM, r.IssuerChainPEM, r.TrustAnchorPEM, p, at)
		if err != nil {
			return nil, err
		}
		if nodeTLSHash(leaf.CertificateDERHash) != r.LeafDERHash || nodeTLSHash(leaf.SPKIDERHash) != r.Claims.SPKIDERHash || nodeTLSHash(leaf.IssuerCertificateHash) != r.Claims.IssuerDERHash || nodeTLSHash(leaf.TrustAnchorDERHash) != r.Claims.RootDERHash {
			return nil, ErrNodeTLSAuthorityDenied
		}
	}
	return b, nil
}

func nodeTLSCASStateTx(tx *sql.Tx, requestID, from, to string, version uint64) error {
	if version == 0 || version >= math.MaxInt64 {
		return ErrNodeTLSAuthorityConflict
	}
	result, err := tx.Exec(`UPDATE node_tls_authority_v1 SET state=?,version=version+1,updated_at=? WHERE request_id=? AND state=? AND version=?`, to, nodeTLSStamp(nodeTLSNow()), requestID, from, version)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrNodeTLSAuthorityConflict
	}
	return nil
}

// Begin records ISSUING before any signing. An interrupted ISSUING operation
// must be burned as UNCERTAIN, never signed again with its serial and epoch.
func (s *Store) BeginNodeTLSLeafIssue(input NodeTLSLeafIssueInput) (*NodeTLSAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if r.State == NodeTLSIssuing || r.State == NodeTLSUncertain {
		return nil, ErrNodeTLSAuthorityUncertain
	}
	if len(r.Grant) > 0 && !bytes.Equal(r.Grant, input.Grant) {
		return nil, ErrNodeTLSAuthorityConflict
	}
	r.Grant = bytes.Clone(input.Grant)
	if _, err = nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), true); err != nil {
		return nil, err
	}
	if r.State == NodeTLSSigned || r.State == NodeTLSInstalled || r.State == NodeTLSActive {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if r.State != NodeTLSReserved || r.RowVersion != input.ExpectedVersion {
		return nil, ErrNodeTLSAuthorityConflict
	}
	_, err = tx.Exec(`UPDATE node_tls_authority_v1 SET grant=? WHERE request_id=?`, input.Grant, r.Claims.RequestID)
	if err != nil {
		return nil, err
	}
	if err = nodeTLSCASStateTx(tx, r.Claims.RequestID, NodeTLSReserved, NodeTLSIssuing, r.RowVersion); err != nil {
		return nil, err
	}
	r, err = readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// Commit accepts only strict C-verified public material for an ISSUING row. It
// rechecks every current authority in the commit transaction. Same DER retries
// return persisted bytes; an independently re-signed certificate conflicts.
func (s *Store) CommitNodeTLSLeaf(input NodeTLSAuthorityActionInput, leafPEM []byte) (*NodeTLSAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if r.State == NodeTLSUncertain {
		return nil, ErrNodeTLSAuthorityUncertain
	}
	if len(leafPEM) == 0 || len(leafPEM) > pqtls.MaxTLSCertificatePEMBytes {
		return nil, ErrNodeTLSAuthorityDenied
	}
	p, err := NodeTLSLeafParameters(r.Claims)
	if err != nil {
		return nil, err
	}
	leaf, err := pqtls.InspectTLSLeaf(leafPEM, r.IssuerChainPEM, r.TrustAnchorPEM, p, nodeTLSNow())
	if err != nil {
		return nil, err
	}
	if len(r.LeafCertificatePEM) > 0 {
		if r.LeafDERHash != nodeTLSHash(leaf.CertificateDERHash) || !bytes.Equal(r.LeafCertificatePEM, leaf.CertificatePEM) {
			return nil, ErrNodeTLSAuthorityConflict
		}
		if _, err = nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), true); err != nil {
			return nil, err
		}
		if r.State != NodeTLSSigned && r.State != NodeTLSInstalled && r.State != NodeTLSActive {
			return nil, ErrNodeTLSAuthorityConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if r.State != NodeTLSIssuing || r.RowVersion != input.ExpectedVersion {
		return nil, ErrNodeTLSAuthorityConflict
	}
	r.LeafCertificatePEM = leaf.CertificatePEM
	r.LeafDERHash = nodeTLSHash(leaf.CertificateDERHash)
	if _, err = nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), true); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE node_tls_authority_v1 SET leaf_pem=?,leaf_der_hash=? WHERE request_id=?`, r.LeafCertificatePEM, r.LeafDERHash, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = nodeTLSCASStateTx(tx, input.RequestID, NodeTLSIssuing, NodeTLSSigned, r.RowVersion); err != nil {
		return nil, err
	}
	r, err = readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// Issue wraps Begin -> C signing outside a transaction -> Commit. It owns no
// issuer key and never returns an uncommitted leaf. All failed signing or commit
// outcomes burn the in-flight row; an already persisted leaf is returned as is.
func (s *Store) IssueNodeTLSLeaf(input NodeTLSLeafIssueInput, issuer pqtls.TLSIssuer) (*NodeTLSAuthoritySnapshot, error) {
	reserved, err := s.GetNodeTLSAuthorityReservationLocal(input.RequestID)
	if err != nil {
		return nil, err
	}
	if reserved.State == NodeTLSIssuing || reserved.State == NodeTLSUncertain {
		_ = s.MarkNodeTLSLeafUncertainLocal(input.RequestID)
		return nil, ErrNodeTLSAuthorityUncertain
	}
	if reserved.State == NodeTLSReserved {
		profile, err := issuer.Profile(nodeTLSNow())
		if err != nil {
			return nil, err
		}
		parameters, err := NodeTLSLeafParameters(reserved.Claims)
		if err != nil {
			return nil, err
		}
		if profile.Role != "node" || nodeTLSHash(profile.SPKIDERHash) != reserved.Claims.IssuerSPKIHash || nodeTLSHash(profile.CertificateDERHash) != reserved.Claims.IssuerDERHash || nodeTLSHash(profile.TrustAnchorDERHash) != reserved.Claims.RootDERHash || parameters.NotBefore.Before(profile.VerifiedNotBefore) || parameters.NotAfter.After(profile.VerifiedNotAfter) {
			return nil, ErrNodeTLSAuthorityDenied
		}
	}
	r, err := s.BeginNodeTLSLeafIssue(input)
	if err != nil {
		if errors.Is(err, ErrNodeTLSAuthorityUncertain) {
			_ = s.MarkNodeTLSLeafUncertainLocal(input.RequestID)
		}
		return nil, err
	}
	if r.State != NodeTLSIssuing {
		return r, nil
	}
	p, err := NodeTLSLeafParameters(r.Claims)
	if err != nil {
		_ = s.MarkNodeTLSLeafUncertainLocal(input.RequestID)
		return nil, err
	}
	leaf, err := issuer.IssueTLSLeaf(r.CSRPEM, p, nodeTLSNow())
	if err != nil {
		_ = s.MarkNodeTLSLeafUncertainLocal(input.RequestID)
		return nil, err
	}
	action := input.NodeTLSAuthorityActionInput
	action.ExpectedVersion = r.RowVersion
	committed, err := s.CommitNodeTLSLeaf(action, leaf.CertificatePEM)
	if err != nil {
		_ = s.MarkNodeTLSLeafUncertainLocal(input.RequestID)
		return nil, err
	}
	return committed, nil
}

func (s *Store) RecordNodeTLSInstallAck(input NodeTLSInstallAckInput) (*NodeTLSAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	b, err := nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), true)
	if err != nil {
		return nil, err
	}
	ack, err := e2ee.VerifyNodeTLSInstallAck(b.NodePublicIdentity, nodeTLSNow(), input.InstallAck)
	if err != nil || ack.GrantClaims != r.Claims || ack.GrantDigest != e2ee.NodeTLSAuthorityDigest(r.Grant) || ack.ReservationVersion != r.ReservationVersion || ack.LeafDERHash != r.LeafDERHash {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if r.State == NodeTLSInstalled || r.State == NodeTLSActive {
		if !bytes.Equal(r.InstallAck, input.InstallAck) {
			return nil, ErrNodeTLSAuthorityConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if r.State != NodeTLSSigned || r.RowVersion != input.ExpectedVersion {
		return nil, ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSConsumeNonceTx(tx, ack.Nonce, "INSTALL", input.RequestID, e2ee.NodeTLSAuthorityDigest(input.InstallAck)); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE node_tls_authority_v1 SET install_ack=? WHERE request_id=?`, input.InstallAck, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = nodeTLSCASStateTx(tx, input.RequestID, NodeTLSSigned, NodeTLSInstalled, r.RowVersion); err != nil {
		return nil, err
	}
	r, err = readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) PrepareNodeTLSActivation(input NodeTLSAuthorityActionInput, nonce string) (e2ee.NodeTLSActivationClaims, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return e2ee.NodeTLSActivationClaims{}, err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return e2ee.NodeTLSActivationClaims{}, err
	}
	b, err := nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), false)
	if err != nil {
		return e2ee.NodeTLSActivationClaims{}, err
	}
	if r.State != NodeTLSInstalled || r.RowVersion != input.ExpectedVersion || r.RowVersion >= math.MaxInt64 {
		return e2ee.NodeTLSActivationClaims{}, ErrNodeTLSAuthorityConflict
	}
	ack, err := e2ee.VerifyNodeTLSInstallAck(b.NodePublicIdentity, nodeTLSNow(), r.InstallAck)
	if err != nil {
		return e2ee.NodeTLSActivationClaims{}, ErrNodeTLSAuthorityDenied
	}
	return e2ee.NodeTLSActivationClaims{Version: 1, InstallAckClaims: ack, InstallAckDigest: e2ee.NodeTLSAuthorityDigest(r.InstallAck), ActivationVersion: r.RowVersion + 1, IssuedAt: nodeTLSStamp(nodeTLSNow()), ExpiresAt: ack.ExpiresAt, Nonce: nonce}, nil
}

func (s *Store) ActivateNodeTLSGrant(input NodeTLSActivationInput) (*NodeTLSAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	b, err := nodeTLSValidateSnapshotTx(tx, r, input.CredentialDigest, input.NodeID, nodeTLSNow(), true)
	if err != nil {
		return nil, err
	}
	activation, err := e2ee.VerifyNodeTLSActivation(b.HubPublicIdentity, nodeTLSNow(), input.Activation)
	if err != nil || activation.InstallAckClaims.GrantClaims != r.Claims || activation.InstallAckDigest != e2ee.NodeTLSAuthorityDigest(r.InstallAck) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	ack, err := e2ee.VerifyNodeTLSInstallAck(b.NodePublicIdentity, nodeTLSNow(), r.InstallAck)
	if err != nil || ack != activation.InstallAckClaims || ack.GrantDigest != e2ee.NodeTLSAuthorityDigest(r.Grant) || ack.LeafDERHash != r.LeafDERHash || ack.ReservationVersion != r.ReservationVersion {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if r.State == NodeTLSActive {
		if !bytes.Equal(r.Activation, input.Activation) || activation.ActivationVersion != r.RowVersion {
			return nil, ErrNodeTLSAuthorityConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if r.State != NodeTLSInstalled || r.RowVersion != input.ExpectedVersion || activation.ActivationVersion != r.RowVersion+1 {
		return nil, ErrNodeTLSAuthorityConflict
	}
	var maxActiveEpoch uint64
	if err = tx.QueryRow(`SELECT COALESCE(max(tls_epoch),0) FROM node_tls_authority_v1 WHERE hub_id=? AND node_id=? AND state IN ('ACTIVE','REVOKED')`, r.Claims.HubID, r.Claims.NodeID).Scan(&maxActiveEpoch); err != nil {
		return nil, err
	}
	if r.Claims.TLSEpoch <= maxActiveEpoch {
		return nil, ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSConsumeNonceTx(tx, activation.Nonce, "ACTIVATION", input.RequestID, e2ee.NodeTLSAuthorityDigest(input.Activation)); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE node_tls_authority_v1 SET state='REVOKED',version=version+1,updated_at=? WHERE hub_id=? AND node_id=? AND state='ACTIVE' AND version<?`, nodeTLSStamp(nodeTLSNow()), r.Claims.HubID, r.Claims.NodeID, int64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE node_tls_authority_v1 SET activation=? WHERE request_id=?`, input.Activation, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = nodeTLSCASStateTx(tx, input.RequestID, NodeTLSInstalled, NodeTLSActive, r.RowVersion); err != nil {
		return nil, err
	}
	r, err = readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) MarkNodeTLSLeafUncertainLocal(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE node_tls_authority_v1 SET state='UNCERTAIN',version=version+1,updated_at=? WHERE request_id=? AND state='ISSUING' AND version<?`, nodeTLSStamp(nodeTLSNow()), requestID, int64(math.MaxInt64))
	return err
}

func (s *Store) RevokeNodeTLSGrantLocal(requestID string, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := readNodeTLSAuthorityTx(tx, requestID)
	if err != nil {
		return err
	}
	if r.RowVersion != expectedVersion {
		return ErrNodeTLSAuthorityConflict
	}
	to := NodeTLSRevoked
	if r.State == NodeTLSReserved {
		to = NodeTLSCancelled
	}
	if r.State == NodeTLSUncertain || r.State == NodeTLSCancelled || r.State == NodeTLSRevoked {
		return ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSCASStateTx(tx, requestID, r.State, to, r.RowVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetNodeTLSAuthorityReservationLocal(requestID string) (*NodeTLSAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readNodeTLSAuthorityTx(tx, requestID)
}

func currentNodeTLSAuthorityTx(tx *sql.Tx, nodeID, credential string) (*NodeTLSAuthoritySnapshot, error) {
	var requestID string
	err := tx.QueryRow(`SELECT request_id FROM node_tls_authority_v1 WHERE node_id=? AND state='ACTIVE'`, nodeID).Scan(&requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, err := readNodeTLSAuthorityTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	b, err := nodeTLSValidateSnapshotTx(tx, r, credential, nodeID, nodeTLSNow(), false)
	if err != nil {
		return nil, err
	}
	ack, err := e2ee.VerifyNodeTLSInstallAck(b.NodePublicIdentity, nodeTLSNow(), r.InstallAck)
	if err != nil || ack.GrantClaims != r.Claims || ack.GrantDigest != e2ee.NodeTLSAuthorityDigest(r.Grant) || ack.LeafDERHash != r.LeafDERHash || ack.ReservationVersion != r.ReservationVersion {
		return nil, ErrNodeTLSAuthorityDenied
	}
	active, err := e2ee.VerifyNodeTLSActivation(b.HubPublicIdentity, nodeTLSNow(), r.Activation)
	if err != nil || active.InstallAckClaims != ack || active.InstallAckDigest != e2ee.NodeTLSAuthorityDigest(r.InstallAck) || active.ActivationVersion != r.RowVersion {
		return nil, ErrNodeTLSAuthorityDenied
	}
	for _, proof := range []struct {
		nonce, purpose string
		wire           []byte
	}{{ack.Nonce, "INSTALL", r.InstallAck}, {active.Nonce, "ACTIVATION", r.Activation}} {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM node_tls_proof_nonces_v1 WHERE nonce=? AND purpose=? AND request_id=? AND proof_digest=?`, proof.nonce, proof.purpose, r.Claims.RequestID, e2ee.NodeTLSAuthorityDigest(proof.wire)).Scan(&count); err != nil || count != 1 {
			return nil, ErrNodeTLSAuthorityDenied
		}
	}
	return r, nil
}

// Keep database failures distinct internally, without exposing inventory/key
// details to a remote caller. The ordinary transport binding stays optional.
func nodeTLSUnavailableSnapshotError(err error) bool {
	var native *pqtls.Error
	return errors.Is(err, ErrNodeTLSAuthorityDenied) || errors.Is(err, ErrNodeTLSAuthorityCapacity) || errors.Is(err, e2ee.ErrInvalidEnvelope) || errors.As(err, &native)
}
