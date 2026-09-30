package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	CrossOwnerGroupKeyOperation = "group-endpoint-key-grant:v2:cross-owner"
	CrossOwnerKeyConsentRoute   = "space.key_consent_v2"
	CrossOwnerKeyAdmissionRoute = "space.key_admission_v2"
	crossOwnerKeyManifestDomain = "cicada/group/cross-owner-key-manifest/v2\x00"
	crossOwnerKeyBindingDomain  = "cicada/group/cross-owner-key-binding/v2\x00"
	CrossOwnerKeySideEndpoint   = "ENDPOINT"
	CrossOwnerKeySideGroup      = "GROUP"
)

// CrossOwnerGroupKeyManifest is the identical public statement reviewed by
// two different Owners. It explicitly warns that joining a Group shares the
// current Group context with the added reader; no history is implicit.
type CrossOwnerGroupKeyManifest struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	NetworkID               string              `json:"network_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	PrincipalID             string              `json:"principal_id"`
	EndpointOwnerID         string              `json:"endpoint_owner_id"`
	GroupOwnerID            string              `json:"group_owner_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	CandidateAttestation    []byte              `json:"candidate_attestation"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	Capabilities            []string            `json:"capabilities"`
	CrossOwnerContextShared bool                `json:"cross_owner_context_shared"`
	HistoryIncluded         bool                `json:"history_included"`
	ExpiresAt               string              `json:"expires_at"`
	Digest                  string              `json:"digest"`
}

type CrossOwnerGroupKeyProof struct {
	ID             string `json:"proof_id"`
	GroupID        string `json:"group_id"`
	EndpointID     string `json:"endpoint_id"`
	SignerOwnerID  string `json:"signer_owner_id"`
	SignerSide     string `json:"signer_side"`
	OwnerKeyID     string `json:"owner_key_id"`
	ManifestDigest string `json:"manifest_digest"`
	AcceptedAt     string `json:"accepted_at"`
	CurrentStatus  string `json:"current_status"`
	SignedProof    []byte `json:"signed_proof,omitempty"`
}

type CrossOwnerGroupKeyStatus struct {
	Manifest        CrossOwnerGroupKeyManifest `json:"manifest"`
	EndpointConsent *CrossOwnerGroupKeyProof   `json:"endpoint_consent,omitempty"`
	GroupAdmission  *CrossOwnerGroupKeyProof   `json:"group_admission,omitempty"`
	Current         bool                       `json:"current"`
}

func crossOwnerKeyDigest(manifest CrossOwnerGroupKeyManifest) string {
	manifest.Digest = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(append([]byte(crossOwnerKeyManifestDomain), encoded...))
	return hex.EncodeToString(hash[:])
}

func currentCrossOwnerKeyManifestTx(tx *sql.Tx, groupID, endpointID string, at time.Time) (*CrossOwnerGroupKeyManifest, error) {
	a, err := scanCrossOwnerAdmission(tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+` FROM cross_owner_group_admissions_v2
WHERE group_id=? AND endpoint_id=? AND state='ACTIVE' ORDER BY created_at DESC LIMIT 1`, groupID, endpointID))
	if err != nil || crossOwnerAdmissionCurrentTx(tx, a, at) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	var ownerID, nodeID, bindingID, nativeID, bindingStatus, joinStatus string
	var bindingEpoch uint64
	var joinRevision int64
	err = tx.QueryRow(`SELECT e.owner,e.machine_id,e.binding_id,e.native_session_id,b.status,b.epoch,
eg.status,eg.revision FROM fabric_endpoints e
JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id AND b.principal_id=e.principal_id
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=?
WHERE e.id=? AND e.principal_id=? AND e.status!='left' AND e.migration_state='READY'`,
		groupID, endpointID, a.PrincipalID).Scan(&ownerID, &nodeID, &bindingID, &nativeID,
		&bindingStatus, &bindingEpoch, &joinStatus, &joinRevision)
	if err != nil || ownerID != a.EndpointOwnerID || nodeID == "" || nativeID == "" ||
		!isActiveBindingStatus(bindingStatus) || bindingEpoch == 0 || joinStatus != "active" || joinRevision <= 0 ||
		requireCurrentOwnerBoundGroupNodeTx(tx, nodeID, ownerID, a.HubID) != nil ||
		networkGuardGroupEndpointTx(tx, a.PrincipalID, endpointID, groupID, at) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	var hasRead int
	if tx.QueryRow(`SELECT 1 FROM memberships m WHERE m.id=? AND m.status='active'
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value='space.read')`, a.MembershipID).Scan(&hasRead) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	side, err := readCommunicationLinkKeySide(tx, endpointID, groupID, a.PrincipalID,
		ownerID, nodeID, bindingID, bindingEpoch)
	if err != nil || side.CandidateVersion <= 0 {
		return nil, ErrCrossOwnerGroupDenied
	}
	bindingClaims, err := json.Marshal(struct {
		HubID            string `json:"hub_id"`
		NetworkID        string `json:"network_id"`
		GroupID          string `json:"group_id"`
		EndpointID       string `json:"endpoint_id"`
		BindingID        string `json:"binding_id"`
		BindingEpoch     uint64 `json:"binding_epoch"`
		CandidateKeyID   string `json:"candidate_key_id"`
		CandidateVersion int64  `json:"candidate_version"`
		Fingerprint      string `json:"fingerprint"`
		ProofDigest      string `json:"proof_digest"`
	}{a.HubID, a.NetworkID, groupID, endpointID, bindingID, bindingEpoch, side.KeyID, side.CandidateVersion, side.KeyFingerprint, side.ProofDigest})
	if err != nil {
		return nil, err
	}
	bindingHash := sha256.Sum256(append([]byte(crossOwnerKeyBindingDomain), bindingClaims...))
	m := &CrossOwnerGroupKeyManifest{Version: 2, Operation: CrossOwnerGroupKeyOperation,
		HubID: a.HubID, NetworkID: a.NetworkID, GroupID: groupID, GroupRevision: a.GroupRevision,
		EndpointID: endpointID, PrincipalID: a.PrincipalID, EndpointOwnerID: a.EndpointOwnerID,
		GroupOwnerID: a.GroupOwnerID, NodeID: nodeID, BindingID: bindingID, BindingEpoch: bindingEpoch,
		MembershipRevision: a.MembershipRevision, EndpointJoinRevision: joinRevision,
		CandidateVersion: side.CandidateVersion, CandidateKeyID: side.KeyID,
		CandidateFingerprint: side.KeyFingerprint, CandidateProofDigest: side.ProofDigest,
		CandidatePublicIdentity: side.PublicIdentity, CandidateAttestation: append([]byte(nil), side.Attestation...),
		CandidateBindingDigest: hex.EncodeToString(bindingHash[:]), Capabilities: append([]string(nil), a.Grants...),
		CrossOwnerContextShared: true, HistoryIncluded: false, ExpiresAt: a.ExpiresAt}
	m.Digest = crossOwnerKeyDigest(*m)
	return m, nil
}

// PreviewCrossOwnerGroupKeyManifestForClientRequest exposes only the caller's
// own Endpoint or Group. A public capability is never approval authority.
func (s *Store) PreviewCrossOwnerGroupKeyManifestForClientRequest(requestID, ownerID,
	groupID, endpointID string) (*CrossOwnerGroupKeyManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, "space.key_manifest_v2")
	if err != nil {
		return nil, err
	}
	m, err := currentCrossOwnerKeyManifestTx(tx, groupID, endpointID, time.Now().UTC())
	if err != nil || m.HubID != actor.HubID || ownerID != m.EndpointOwnerID && ownerID != m.GroupOwnerID {
		return nil, ErrCrossOwnerGroupDenied
	}
	return m, tx.Commit()
}

// AcceptCrossOwnerGroupKeyProofForClientRequest reconstructs the exact current
// manifest and verifies one human Owner's ML-DSA proof. The second side must
// independently accept the same digest before any reader snapshot can use it.
func (s *Store) AcceptCrossOwnerGroupKeyProofForClientRequest(requestID, ownerID,
	groupID, endpointID, ownerKeyID, side string, signedProof []byte) (*CrossOwnerGroupKeyProof, error) {
	if len(signedProof) == 0 || len(signedProof) > 16*1024 {
		return nil, ErrCrossOwnerGroupDenied
	}
	operation := CrossOwnerKeyConsentRoute
	wireSide := e2ee.OwnerLinkGrantSideSource
	if side == CrossOwnerKeySideGroup {
		operation = CrossOwnerKeyAdmissionRoute
		wireSide = e2ee.OwnerLinkGrantSideTarget
	} else if side != CrossOwnerKeySideEndpoint {
		return nil, ErrCrossOwnerGroupDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, operation)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	m, err := currentCrossOwnerKeyManifestTx(tx, groupID, endpointID, at)
	if err != nil || m.HubID != actor.HubID || side == CrossOwnerKeySideEndpoint && ownerID != m.EndpointOwnerID ||
		side == CrossOwnerKeySideGroup && ownerID != m.GroupOwnerID {
		return nil, ErrCrossOwnerGroupDenied
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at
FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, ownerID, ownerKeyID))
	if err != nil || key.State != OwnerApprovalKeyActive {
		return nil, ErrCrossOwnerGroupDenied
	}
	verified, err := e2ee.VerifyOwnerLinkKeyGrant(signedProof, key.Public, ownerID, CrossOwnerGroupKeyOperation,
		m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), wireSide, at)
	if err != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	proofExpiry, err := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	manifestExpiry, _ := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil || proofExpiry.After(manifestExpiry) {
		return nil, ErrCrossOwnerGroupDenied
	}
	var prior CrossOwnerGroupKeyProof
	var priorProof []byte
	if err := tx.QueryRow(`SELECT id,group_id,endpoint_id,signer_owner_id,signer_side,owner_key_id,manifest_digest,proof,accepted_at
FROM cross_owner_group_key_proofs_v2 WHERE client_request_id=?`, requestID).Scan(&prior.ID, &prior.GroupID,
		&prior.EndpointID, &prior.SignerOwnerID, &prior.SignerSide, &prior.OwnerKeyID,
		&prior.ManifestDigest, &priorProof, &prior.AcceptedAt); err == nil {
		if prior.GroupID != groupID || prior.EndpointID != endpointID || prior.SignerOwnerID != ownerID ||
			prior.SignerSide != side || prior.OwnerKeyID != ownerKeyID || prior.ManifestDigest != m.Digest || string(priorProof) != string(signedProof) {
			return nil, ErrCrossOwnerGroupConflict
		}
		prior.CurrentStatus = "CURRENT"
		return &prior, tx.Commit()
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	var count int
	if tx.QueryRow(`SELECT COUNT(*) FROM cross_owner_group_key_proofs_v2`).Scan(&count) != nil || count >= 2*crossOwnerAdmissionQuota {
		return nil, ErrGroupSpaceLimit
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	p := &CrossOwnerGroupKeyProof{ID: NewID("cokey"), GroupID: groupID, EndpointID: endpointID,
		SignerOwnerID: ownerID, SignerSide: side, OwnerKeyID: ownerKeyID, ManifestDigest: m.Digest,
		AcceptedAt: at.Format(time.RFC3339Nano), CurrentStatus: "CURRENT"}
	_, err = tx.Exec(`INSERT INTO cross_owner_group_key_proofs_v2
(id,client_request_id,group_id,endpoint_id,signer_owner_id,signer_side,owner_key_id,manifest_digest,
manifest_json,proof,proof_nonce,state,accepted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',?)`,
		p.ID, requestID, groupID, endpointID, ownerID, side, ownerKeyID, m.Digest, string(encoded), signedProof, verified.Nonce, p.AcceptedAt)
	if err != nil {
		return nil, ErrCrossOwnerGroupConflict
	}
	return p, tx.Commit()
}

func currentCrossOwnerProofTx(tx *sql.Tx, m *CrossOwnerGroupKeyManifest, ownerID, side string,
	at time.Time) (*CrossOwnerGroupKeyProof, error) {
	var p CrossOwnerGroupKeyProof
	var proof []byte
	var state string
	err := tx.QueryRow(`SELECT id,group_id,endpoint_id,signer_owner_id,signer_side,owner_key_id,manifest_digest,
proof,state,accepted_at FROM cross_owner_group_key_proofs_v2
WHERE group_id=? AND endpoint_id=? AND signer_owner_id=? AND signer_side=?
ORDER BY accepted_at DESC,id DESC LIMIT 1`, m.GroupID, m.EndpointID, ownerID, side).Scan(&p.ID, &p.GroupID,
		&p.EndpointID, &p.SignerOwnerID, &p.SignerSide, &p.OwnerKeyID, &p.ManifestDigest, &proof, &state, &p.AcceptedAt)
	if err != nil || state != "ACTIVE" || p.ManifestDigest != m.Digest {
		return nil, ErrCrossOwnerGroupDenied
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at
FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, ownerID, p.OwnerKeyID))
	if err != nil || key.State != OwnerApprovalKeyActive {
		return nil, ErrCrossOwnerGroupDenied
	}
	wireSide := e2ee.OwnerLinkGrantSideSource
	if side == CrossOwnerKeySideGroup {
		wireSide = e2ee.OwnerLinkGrantSideTarget
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(proof, key.Public, ownerID, CrossOwnerGroupKeyOperation, m.Digest,
		m.CandidateBindingDigest, uint64(m.CandidateVersion), wireSide, at); err != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	p.CurrentStatus = "CURRENT"
	p.SignedProof = append([]byte(nil), proof...)
	return &p, nil
}

func crossOwnerGroupKeyStatusTx(tx *sql.Tx, groupID, endpointID string, at time.Time) (*CrossOwnerGroupKeyStatus, error) {
	m, err := currentCrossOwnerKeyManifestTx(tx, groupID, endpointID, at)
	if err != nil {
		return nil, err
	}
	status := &CrossOwnerGroupKeyStatus{Manifest: *m}
	status.EndpointConsent, _ = currentCrossOwnerProofTx(tx, m, m.EndpointOwnerID, CrossOwnerKeySideEndpoint, at)
	status.GroupAdmission, _ = currentCrossOwnerProofTx(tx, m, m.GroupOwnerID, CrossOwnerKeySideGroup, at)
	status.Current = status.EndpointConsent != nil && status.GroupAdmission != nil
	return status, nil
}

func (s *Store) GetCrossOwnerGroupKeyStatusForClientRequest(requestID, ownerID, groupID, endpointID string) (*CrossOwnerGroupKeyStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, "space.key_status_v2")
	if err != nil {
		return nil, err
	}
	status, err := crossOwnerGroupKeyStatusTx(tx, groupID, endpointID, time.Now().UTC())
	if err != nil || status.Manifest.HubID != actor.HubID || ownerID != status.Manifest.GroupOwnerID && ownerID != status.Manifest.EndpointOwnerID {
		return nil, ErrCrossOwnerGroupDenied
	}
	return status, tx.Commit()
}

func crossOwnerGroupSpaceEndpointEvidenceTx(tx *sql.Tx, groupID, endpointID string, at time.Time) (GroupSpaceEndpointEvidence, error) {
	status, err := crossOwnerGroupKeyStatusTx(tx, groupID, endpointID, at)
	if err != nil || !status.Current {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	m := status.Manifest
	side, err := readCommunicationLinkKeySide(tx, endpointID, groupID, m.PrincipalID, m.EndpointOwnerID,
		m.NodeID, m.BindingID, m.BindingEpoch)
	if err != nil {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	candidate := EndpointKeyCandidate{EndpointID: side.EndpointID, PrincipalID: side.PrincipalID, OwnerID: side.OwnerID,
		NodeID: side.NodeID, Public: side.PublicIdentity, KeyID: side.KeyID, BindingID: side.BindingID,
		BindingEpoch: side.BindingEpoch, Proof: side.Attestation, ProofDigest: side.ProofDigest,
		State: EndpointKeyCandidateStateCandidate, Version: side.CandidateVersion}
	return GroupSpaceEndpointEvidence{EndpointID: endpointID, PrincipalID: m.PrincipalID, OwnerID: m.EndpointOwnerID,
		NodeID: m.NodeID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch,
		MembershipRevision: m.MembershipRevision, JoinRevision: m.EndpointJoinRevision,
		KeyID: m.CandidateKeyID, PublicIdentity: m.CandidatePublicIdentity, Candidate: candidate,
		EvidenceProtocol: "cross-owner-group-key-v2", CrossOwnerKeyStatus: status}, nil
}

func crossOwnerEvidenceDigest(e GroupSpaceEndpointEvidence) string {
	if e.CrossOwnerKeyStatus == nil || !e.CrossOwnerKeyStatus.Current {
		return ""
	}
	return e.CrossOwnerKeyStatus.Manifest.Digest
}
