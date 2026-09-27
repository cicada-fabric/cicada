package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	CommunicationLinkGrantSource = string(e2ee.OwnerLinkGrantSideSource)
	CommunicationLinkGrantTarget = string(e2ee.OwnerLinkGrantSideTarget)

	CommunicationLinkGrantMissing        = "MISSING"
	CommunicationLinkGrantAccepted       = "ACCEPTED"
	CommunicationLinkGrantLinkRevoked    = "LINK_REVOKED"
	CommunicationLinkGrantLinkExpired    = "LINK_EXPIRED"
	CommunicationLinkGrantScopeStale     = "SCOPE_STALE"
	CommunicationLinkGrantKeyRevoked     = "KEY_REVOKED"
	CommunicationLinkGrantKeyUnavailable = "KEY_UNAVAILABLE"
	CommunicationLinkGrantProofExpired   = "PROOF_EXPIRED"
	CommunicationLinkGrantInvalid        = "INVALID"
)

var (
	ErrCommunicationLinkGrantConflict = errors.New("communication link side already has a different owner grant")
	ErrCommunicationLinkGrantReplay   = errors.New("communication link owner grant nonce was already used")
)

// CommunicationLinkOwnerGrantStatus reports the durable acceptance record
// separately from whether it is still current. Even two current grants do not
// activate a CommunicationLink or create a message route.
type CommunicationLinkOwnerGrantStatus struct {
	LinkID        string `json:"link_id"`
	LinkState     string `json:"link_state"`
	LinkVersion   int64  `json:"link_version"`
	Side          string `json:"side"`
	OwnerID       string `json:"owner_id,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
	Accepted      bool   `json:"accepted"`
	AcceptedAt    string `json:"accepted_at,omitempty"`
	CurrentStatus string `json:"current_status"`
}

type storedCommunicationLinkOwnerGrant struct {
	linkID             string
	side               string
	ownerID            string
	keyID              string
	linkVersion        int64
	contractDigest     string
	sourceBindingID    string
	sourceBindingEpoch uint64
	targetBindingID    string
	targetBindingEpoch uint64
	nonce              string
	signedProof        []byte
	acceptedAt         string
}

type communicationLinkGrantBindingSnapshot struct {
	sourceBindingID    string
	sourceBindingEpoch uint64
	targetBindingID    string
	targetBindingEpoch uint64
}

func (s *Store) initializeCommunicationLinkGrantsV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS communication_link_grants_v2 (
  link_id TEXT NOT NULL,
  side TEXT NOT NULL CHECK(side IN ('SOURCE', 'TARGET')),
  owner_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  link_version INTEGER NOT NULL CHECK(link_version > 0),
  contract_digest TEXT NOT NULL,
  source_binding_id TEXT NOT NULL,
  source_binding_epoch INTEGER NOT NULL CHECK(source_binding_epoch > 0),
  target_binding_id TEXT NOT NULL,
  target_binding_epoch INTEGER NOT NULL CHECK(target_binding_epoch > 0),
  nonce TEXT NOT NULL,
  signed_proof BLOB NOT NULL CHECK(length(signed_proof) > 0),
  accepted_at TEXT NOT NULL,
  PRIMARY KEY(link_id, side),
  UNIQUE(owner_id, key_id, nonce),
  FOREIGN KEY(link_id) REFERENCES communication_links_v2(id),
  FOREIGN KEY(owner_id, key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS communication_link_grants_v2_owner_idx
  ON communication_link_grants_v2(owner_id, accepted_at, link_id);`)
	if err != nil {
		return fmt.Errorf("initialize communication link grants: %w", err)
	}
	return nil
}

// RecordCommunicationLinkOwnerGrant accepts one signed approval for the
// proposal's source or target side. Side ownership comes from the persisted
// link, and the signing public key comes only from the local owner-key trust
// table. This method records consent; it never changes the link state.
func (s *Store) RecordCommunicationLinkOwnerGrant(
	linkID, side, keyID string,
	signedProof []byte,
) (*CommunicationLinkOwnerGrantStatus, error) {
	if linkID == "" || len(linkID) > 256 || strings.TrimSpace(linkID) != linkID ||
		keyID == "" || len(keyID) > 256 || strings.TrimSpace(keyID) != keyID ||
		(side != CommunicationLinkGrantSource && side != CommunicationLinkGrantTarget) ||
		len(signedProof) == 0 {
		return nil, errors.New("communication link grant request is invalid")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	currentTime := time.Now().UTC()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ?`, linkID))
	if err != nil {
		return nil, err
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, currentTime); err != nil {
		return nil, err
	}
	bindings, err := readCommunicationLinkGrantBindingSnapshot(tx, *link, currentTime)
	if err != nil {
		return nil, err
	}
	ownerID := communicationLinkGrantOwner(*link, side)
	if ownerID == "" {
		return nil, ErrCommunicationLinkNotFound
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, keyID))
	if err != nil {
		return nil, err
	}
	if key.State != OwnerApprovalKeyActive {
		return nil, ErrOwnerApprovalKeyConflict
	}
	if link.Version <= 0 {
		return nil, ErrCommunicationLinkScope
	}
	verified, err := e2ee.VerifyOwnerLinkGrant(
		signedProof, key.Public, ownerID, link.ID, link.ContractDigest,
		uint64(link.Version), e2ee.OwnerLinkGrantSide(side), currentTime,
	)
	if err != nil {
		return nil, fmt.Errorf("verify communication link owner grant: %w", err)
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		return nil, ErrCommunicationLinkScope
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	if err != nil || grantExpiry.After(linkExpiry) {
		return nil, errors.New("communication link owner grant exceeds link expiry")
	}

	prior, priorErr := readStoredCommunicationLinkOwnerGrant(tx, linkID, side)
	if priorErr == nil {
		if prior.ownerID == ownerID && prior.keyID == keyID &&
			prior.linkVersion == link.Version && prior.contractDigest == link.ContractDigest &&
			prior.sourceBindingID == bindings.sourceBindingID &&
			prior.sourceBindingEpoch == bindings.sourceBindingEpoch &&
			prior.targetBindingID == bindings.targetBindingID &&
			prior.targetBindingEpoch == bindings.targetBindingEpoch &&
			prior.nonce == verified.Nonce && bytes.Equal(prior.signedProof, signedProof) {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return statusFromStoredCommunicationLinkOwnerGrant(*link, prior, CommunicationLinkGrantAccepted), nil
		}
		return nil, ErrCommunicationLinkGrantConflict
	}
	if !errors.Is(priorErr, sql.ErrNoRows) {
		return nil, priorErr
	}
	var used int
	err = tx.QueryRow(`SELECT 1 FROM communication_link_grants_v2
WHERE owner_id = ? AND key_id = ? AND nonce = ?`, ownerID, keyID, verified.Nonce).Scan(&used)
	if err == nil {
		return nil, ErrCommunicationLinkGrantReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	stamp := currentTime.Format(time.RFC3339Nano)
	_, err = tx.Exec(`INSERT INTO communication_link_grants_v2
(link_id, side, owner_id, key_id, link_version, contract_digest,
 source_binding_id, source_binding_epoch, target_binding_id, target_binding_epoch,
 nonce, signed_proof, accepted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, linkID, side, ownerID, keyID, link.Version,
		link.ContractDigest, bindings.sourceBindingID, bindings.sourceBindingEpoch,
		bindings.targetBindingID, bindings.targetBindingEpoch, verified.Nonce,
		append([]byte(nil), signedProof...), stamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return nil, ErrCommunicationLinkGrantReplay
		}
		return nil, fmt.Errorf("persist communication link owner grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &CommunicationLinkOwnerGrantStatus{
		LinkID: link.ID, LinkState: link.State, LinkVersion: link.Version,
		Side: side, OwnerID: ownerID, KeyID: keyID, Accepted: true,
		AcceptedAt: stamp, CurrentStatus: CommunicationLinkGrantAccepted,
	}, nil
}

// GetCommunicationLinkOwnerGrantStatuses returns both independent side
// records to one of the link's owners. CurrentStatus rechecks current link
// state, endpoint and membership revisions, key revocation, signature, and
// grant expiry. It intentionally has no ACTIVE or routable state.
func (s *Store) GetCommunicationLinkOwnerGrantStatuses(
	linkID, requesterOwnerID string,
) ([]CommunicationLinkOwnerGrantStatus, error) {
	if linkID == "" || len(linkID) > 256 || strings.TrimSpace(linkID) != linkID ||
		validateOwnerApprovalID(requesterOwnerID) != nil {
		return nil, ErrCommunicationLinkNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ?`, linkID))
	if err != nil {
		return nil, err
	}
	if requesterOwnerID != link.SourceOwnerID && requesterOwnerID != link.TargetOwnerID {
		return nil, ErrCommunicationLinkNotFound
	}

	now := time.Now().UTC()
	linkStatus := communicationLinkCurrentStatus(tx, link, now)
	if strings.HasPrefix(linkStatus, "ERROR:") {
		return nil, errors.New(strings.TrimPrefix(linkStatus, "ERROR:"))
	}
	statuses := make([]CommunicationLinkOwnerGrantStatus, 0, 2)
	for _, side := range []string{CommunicationLinkGrantSource, CommunicationLinkGrantTarget} {
		ownerID := communicationLinkGrantOwner(*link, side)
		status := CommunicationLinkOwnerGrantStatus{
			LinkID: link.ID, LinkState: link.State, LinkVersion: link.Version,
			Side: side, OwnerID: ownerID, CurrentStatus: CommunicationLinkGrantMissing,
		}
		grant, err := readStoredCommunicationLinkOwnerGrant(tx, link.ID, side)
		if errors.Is(err, sql.ErrNoRows) {
			statuses = append(statuses, status)
			continue
		}
		if err != nil {
			return nil, err
		}
		status.Accepted, status.AcceptedAt, status.KeyID = true, grant.acceptedAt, grant.keyID
		if linkStatus != CommunicationLinkGrantAccepted {
			status.CurrentStatus = linkStatus
			statuses = append(statuses, status)
			continue
		}
		bindings, err := readCommunicationLinkGrantBindingSnapshot(tx, *link, now)
		if errors.Is(err, ErrCommunicationLinkScope) || errors.Is(err, ErrSessionBindingInactive) ||
			errors.Is(err, ErrSessionBindingLeaseExpired) || errors.Is(err, ErrSessionBindingNotFound) {
			status.CurrentStatus = CommunicationLinkGrantScopeStale
			statuses = append(statuses, status)
			continue
		}
		if err != nil {
			return nil, err
		}
		if grant.sourceBindingID != bindings.sourceBindingID ||
			grant.sourceBindingEpoch != bindings.sourceBindingEpoch ||
			grant.targetBindingID != bindings.targetBindingID ||
			grant.targetBindingEpoch != bindings.targetBindingEpoch {
			status.CurrentStatus = CommunicationLinkGrantScopeStale
			statuses = append(statuses, status)
			continue
		}
		key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, grant.ownerID, grant.keyID))
		if errors.Is(err, ErrOwnerApprovalKeyNotFound) {
			status.CurrentStatus = CommunicationLinkGrantKeyUnavailable
			statuses = append(statuses, status)
			continue
		}
		if err != nil {
			return nil, err
		}
		if key.State != OwnerApprovalKeyActive {
			status.CurrentStatus = CommunicationLinkGrantKeyRevoked
			statuses = append(statuses, status)
			continue
		}
		grantExpiry := parsedGrantExpiry(grant.signedProof)
		linkExpiry, expiryErr := time.Parse(time.RFC3339, link.ExpiresAt)
		if expiryErr != nil || grantExpiry.After(linkExpiry) {
			status.CurrentStatus = CommunicationLinkGrantInvalid
			statuses = append(statuses, status)
			continue
		}
		if !now.Before(grantExpiry) {
			status.CurrentStatus = CommunicationLinkGrantProofExpired
			statuses = append(statuses, status)
			continue
		}
		if _, err := e2ee.VerifyOwnerLinkGrant(grant.signedProof, key.Public,
			ownerID, link.ID, link.ContractDigest, uint64(link.Version),
			e2ee.OwnerLinkGrantSide(side), now); err != nil {
			status.CurrentStatus = CommunicationLinkGrantInvalid
			statuses = append(statuses, status)
			continue
		}
		status.CurrentStatus = CommunicationLinkGrantAccepted
		statuses = append(statuses, status)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return statuses, nil
}

func communicationLinkGrantOwner(link CommunicationLink, side string) string {
	switch side {
	case CommunicationLinkGrantSource:
		return link.SourceOwnerID
	case CommunicationLinkGrantTarget:
		return link.TargetOwnerID
	default:
		return ""
	}
}

func readStoredCommunicationLinkOwnerGrant(tx *sql.Tx, linkID, side string) (storedCommunicationLinkOwnerGrant, error) {
	var grant storedCommunicationLinkOwnerGrant
	err := tx.QueryRow(`SELECT link_id, side, owner_id, key_id, link_version,
contract_digest, source_binding_id, source_binding_epoch, target_binding_id,
target_binding_epoch, nonce, signed_proof, accepted_at FROM communication_link_grants_v2
WHERE link_id = ? AND side = ?`, linkID, side).Scan(
		&grant.linkID, &grant.side, &grant.ownerID, &grant.keyID, &grant.linkVersion,
		&grant.contractDigest, &grant.sourceBindingID, &grant.sourceBindingEpoch,
		&grant.targetBindingID, &grant.targetBindingEpoch, &grant.nonce,
		&grant.signedProof, &grant.acceptedAt)
	return grant, err
}

func statusFromStoredCommunicationLinkOwnerGrant(
	link CommunicationLink,
	grant storedCommunicationLinkOwnerGrant,
	currentStatus string,
) *CommunicationLinkOwnerGrantStatus {
	return &CommunicationLinkOwnerGrantStatus{
		LinkID: link.ID, LinkState: link.State, LinkVersion: link.Version,
		Side: grant.side, OwnerID: grant.ownerID, KeyID: grant.keyID,
		Accepted: true, AcceptedAt: grant.acceptedAt, CurrentStatus: currentStatus,
	}
}

func validateCurrentCommunicationLinkScope(tx *sql.Tx, link *CommunicationLink, at time.Time) error {
	status := communicationLinkCurrentStatus(tx, link, at)
	switch status {
	case CommunicationLinkGrantAccepted:
		return nil
	case CommunicationLinkGrantLinkRevoked:
		return ErrCommunicationLinkNotFound
	case CommunicationLinkGrantLinkExpired, CommunicationLinkGrantScopeStale:
		return ErrCommunicationLinkScope
	default:
		if strings.HasPrefix(status, "ERROR:") {
			return errors.New(strings.TrimPrefix(status, "ERROR:"))
		}
		return ErrCommunicationLinkScope
	}
}

func readCommunicationLinkGrantBindingSnapshot(
	tx *sql.Tx,
	link CommunicationLink,
	at time.Time,
) (communicationLinkGrantBindingSnapshot, error) {
	source, err := readCommunicationLinkGrantBinding(tx, link.SourceEndpointID,
		link.SourcePrincipalID, link.SourceNodeID, at)
	if err != nil {
		return communicationLinkGrantBindingSnapshot{}, err
	}
	target, err := readCommunicationLinkGrantBinding(tx, link.TargetEndpointID,
		link.TargetPrincipalID, link.TargetNodeID, at)
	if err != nil {
		return communicationLinkGrantBindingSnapshot{}, err
	}
	return communicationLinkGrantBindingSnapshot{
		sourceBindingID: source.ID, sourceBindingEpoch: source.Epoch,
		targetBindingID: target.ID, targetBindingEpoch: target.Epoch,
	}, nil
}

func readCommunicationLinkGrantBinding(
	tx *sql.Tx,
	endpointID, principalID, nodeID string,
	at time.Time,
) (*SessionBinding, error) {
	binding, err := scanSessionBinding(tx.QueryRow(`SELECT `+sessionBindingColumns+`
FROM session_bindings WHERE id = (SELECT binding_id FROM fabric_endpoints WHERE id = ?)
AND endpoint_id = ? AND status = ?`, endpointID, endpointID, SessionBindingStatusLeased))
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrSessionBindingNotFound) || (err == nil && binding == nil) {
		return nil, ErrSessionBindingNotFound
	}
	if err != nil {
		return nil, err
	}
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, binding.LeaseExpiresAt)
	if binding.Status != SessionBindingStatusLeased || binding.LeaseOwner == "" ||
		binding.EndpointID != endpointID || binding.PrincipalID != principalID || binding.NodeID != nodeID ||
		binding.Epoch == 0 || expiryErr != nil || !expiresAt.After(at) {
		return nil, ErrSessionBindingLeaseExpired
	}
	var endpointNativeSession string
	if err := tx.QueryRow(`SELECT native_session_id FROM fabric_endpoints WHERE id = ?`, endpointID).Scan(&endpointNativeSession); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionBindingNotFound
		}
		return nil, err
	}
	if endpointNativeSession == "" || endpointNativeSession != binding.NativeSessionID {
		return nil, ErrCommunicationLinkScope
	}
	return binding, nil
}

func communicationLinkCurrentStatus(tx *sql.Tx, link *CommunicationLink, at time.Time) string {
	if err := networkGuardCommunicationLinkTx(tx, link, at); err != nil {
		return CommunicationLinkGrantScopeStale
	}
	if link.State != CommunicationLinkProposed {
		return CommunicationLinkGrantLinkRevoked
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil || !linkExpiry.After(at) {
		return CommunicationLinkGrantLinkExpired
	}
	if link.Version <= 0 || link.ContractDigest == "" {
		return CommunicationLinkGrantScopeStale
	}
	source, err := readLinkEndpointScope(tx, link.SourceEndpointID, link.SourceGroupID, at)
	if errors.Is(err, ErrCommunicationLinkScope) {
		return CommunicationLinkGrantScopeStale
	}
	if err != nil {
		return "ERROR:" + err.Error()
	}
	target, err := readLinkEndpointScope(tx, link.TargetEndpointID, link.TargetGroupID, at)
	if errors.Is(err, ErrCommunicationLinkScope) {
		return CommunicationLinkGrantScopeStale
	}
	if err != nil {
		return "ERROR:" + err.Error()
	}
	currentSnapshot := CommunicationLinkScopeSnapshot{
		SourceMembershipRevision: source.membershipRevision,
		SourceJoinRevision:       source.joinRevision,
		SourceGroupVersion:       source.groupVersion,
		TargetMembershipRevision: target.membershipRevision,
		TargetJoinRevision:       target.joinRevision,
		TargetGroupVersion:       target.groupVersion,
	}
	if source.principalID != link.SourcePrincipalID || source.ownerID != link.SourceOwnerID ||
		source.nodeID != link.SourceNodeID || target.principalID != link.TargetPrincipalID ||
		target.ownerID != link.TargetOwnerID || target.nodeID != link.TargetNodeID ||
		currentSnapshot != link.ScopeSnapshot {
		return CommunicationLinkGrantScopeStale
	}
	digest, err := communicationLinkContractDigest(*link)
	if err != nil {
		return "ERROR:" + err.Error()
	}
	if digest != link.ContractDigest {
		return CommunicationLinkGrantScopeStale
	}
	return CommunicationLinkGrantAccepted
}

// communicationLinkContractDigest mirrors the canonical field order used by
// ProposeCommunicationLink. Recomputing it prevents a modified stored field
// or digest from becoming the contract the owner is asked to approve.
func communicationLinkContractDigest(link CommunicationLink) (string, error) {
	contract, err := canonicalCommunicationLinkContract(link)
	if err != nil {
		return "", err
	}
	return digestCommunicationLinkContract(contract), nil
}

func canonicalCommunicationLinkContract(link CommunicationLink) ([]byte, error) {
	return json.Marshal(struct {
		LinkID            string                         `json:"link_id"`
		SourceEndpointID  string                         `json:"source_endpoint_id"`
		SourcePrincipalID string                         `json:"source_principal_id"`
		SourceGroupID     string                         `json:"source_group_id"`
		SourceOwnerID     string                         `json:"source_owner_id"`
		SourceNodeID      string                         `json:"source_node_id"`
		TargetEndpointID  string                         `json:"target_endpoint_id"`
		TargetPrincipalID string                         `json:"target_principal_id"`
		TargetGroupID     string                         `json:"target_group_id"`
		TargetOwnerID     string                         `json:"target_owner_id"`
		TargetNodeID      string                         `json:"target_node_id"`
		Direction         string                         `json:"direction"`
		Actions           []string                       `json:"actions"`
		DataScopes        []string                       `json:"data_scopes"`
		TransportHubID    string                         `json:"transport_hub_id"`
		ExpiresAt         string                         `json:"expires_at"`
		ScopeSnapshot     CommunicationLinkScopeSnapshot `json:"scope_snapshot"`
	}{link.ID, link.SourceEndpointID, link.SourcePrincipalID, link.SourceGroupID,
		link.SourceOwnerID, link.SourceNodeID, link.TargetEndpointID,
		link.TargetPrincipalID, link.TargetGroupID, link.TargetOwnerID, link.TargetNodeID,
		link.Direction, link.Actions, link.DataScopes, link.TransportHubID, link.ExpiresAt,
		link.ScopeSnapshot})
}

func digestCommunicationLinkContract(canonicalContract []byte) string {
	// This is kept local so grant validation remains additive to the existing
	// proposal API while using its same domain separator and canonical bytes.
	sum := sha256.Sum256(append([]byte("cicada/communication-link/proposal/v1\x00"), canonicalContract...))
	return hex.EncodeToString(sum[:])
}

func parsedGrantExpiry(signedProof []byte) time.Time {
	var grant e2ee.OwnerLinkGrant
	if err := json.Unmarshal(signedProof, &grant); err != nil {
		return time.Time{}
	}
	expires, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		return time.Time{}
	}
	return expires
}
