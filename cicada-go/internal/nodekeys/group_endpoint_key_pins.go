package nodekeys

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	groupEndpointKeyGrantVersion   = 1
	groupEndpointKeyGrantOperation = "group-endpoint-key-grant:v1"
	groupEndpointKeyManifestDomain = "cicada/group/endpoint-key-grant-manifest/v1\x00"
	groupEndpointKeyBindingDomain  = "cicada/group/endpoint-key-binding/v1\x00"
	groupEndpointKeyGrantCurrent   = "CURRENT"
	groupEndpointKeyGrantStale     = "STALE"
	groupEndpointKeyGrantExpired   = "PROOF_EXPIRED"
	groupEndpointKeyGrantRevoked   = "OWNER_KEY_REVOKED"
	groupEndpointKeyGrantInvalid   = "INVALID"
)

var (
	ErrGroupEndpointKeyGrantInvalid = errors.New("Group Endpoint key grant evidence is invalid")
	ErrGroupEndpointKeyGrantExpired = errors.New("Group Endpoint key grant has expired")
	ErrGroupEndpointKeyGrantStale   = errors.New("Group Endpoint key grant does not match the current route snapshot")
	ErrGroupEndpointKeyGrantRevoked = errors.New("Group Endpoint key grant or its owner key is revoked")
)

// GroupEndpointKeyGrantManifest mirrors the Store manifest without importing
// Store. The Node recomputes its digest from every claims field before use.
type GroupEndpointKeyGrantManifest struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	// Informational proof bytes bound by CandidateProofDigest; excluded from
	// the signed claims so existing grants retain their digest.
	CandidateAttestation []byte `json:"candidate_attestation"`
	OwnerKeyID           string `json:"owner_key_id"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Digest               string `json:"digest"`
}

// GroupEndpointKeyGrant is the public Store record consumed by a Node. Its
// CurrentStatus is only a stale/revocation hint: the Node also checks its own
// route snapshot, local OwnerKeyTrust, all digests, and both signatures.
type GroupEndpointKeyGrant struct {
	ID            string                        `json:"grant_id"`
	OwnerID       string                        `json:"owner_id"`
	GroupID       string                        `json:"group_id"`
	EndpointID    string                        `json:"endpoint_id"`
	OwnerKeyID    string                        `json:"owner_key_id"`
	Manifest      GroupEndpointKeyGrantManifest `json:"manifest"`
	SignedProof   []byte                        `json:"signed_proof"`
	AcceptedAt    string                        `json:"accepted_at"`
	CurrentStatus string                        `json:"current_status"`
}

// GroupEndpointKeyCandidate mirrors the public Endpoint key projection used
// to make the owner grant. Candidate values are untrusted until they match the
// owner-signed manifest and their Endpoint attestation verifies locally.
type GroupEndpointKeyCandidate struct {
	EndpointID       string              `json:"endpoint_id"`
	GroupID          string              `json:"group_id"`
	PrincipalID      string              `json:"principal_id"`
	OwnerID          string              `json:"owner_id"`
	NodeID           string              `json:"node_id"`
	BindingID        string              `json:"binding_id"`
	BindingEpoch     uint64              `json:"binding_epoch"`
	CandidateVersion int64               `json:"candidate_version"`
	KeyID            string              `json:"key_id"`
	KeyFingerprint   string              `json:"key_fingerprint"`
	ProofDigest      string              `json:"proof_digest"`
	PublicIdentity   e2ee.PublicIdentity `json:"public_identity"`
	Attestation      []byte              `json:"attestation"`
}

// GroupEndpointKeyRouteSnapshot is the caller's current, authenticated route
// view. It binds the grant to the expected Hub and current peer binding and
// candidate revisions, so the Store status field alone never establishes
// freshness.
type GroupEndpointKeyRouteSnapshot struct {
	HubID                string `json:"hub_id"`
	GroupID              string `json:"group_id"`
	GroupRevision        int64  `json:"group_revision"`
	MembershipRevision   int64  `json:"membership_revision"`
	EndpointJoinRevision int64  `json:"endpoint_join_revision"`
	ExpectedOwnerKeyID   string `json:"expected_owner_key_id"`
	PeerNodeID           string `json:"peer_node_id"`
	PeerBindingID        string `json:"peer_binding_id"`
	PeerBindingEpoch     uint64 `json:"peer_binding_epoch"`
	CandidateVersion     int64  `json:"candidate_version"`
	CandidateKeyID       string `json:"candidate_key_id"`
	CandidateFingerprint string `json:"candidate_fingerprint"`
	CandidateProofDigest string `json:"candidate_proof_digest"`
}

// GroupEndpointKeyPinEvidence combines a Store grant with the separately
// fetched public candidate and local current-route expectations. It contains
// no route authorization; callers must still run their current Guard check
// for each message.
type GroupEndpointKeyPinEvidence struct {
	Scope     PeerPinScope                  `json:"scope"`
	Local     PeerPinLocalEndpoint          `json:"local_endpoint"`
	Peer      PeerPinIdentity               `json:"peer"`
	Route     GroupEndpointKeyRouteSnapshot `json:"route"`
	Grant     GroupEndpointKeyGrant         `json:"grant"`
	Candidate GroupEndpointKeyCandidate     `json:"candidate"`
}

type groupEndpointKeyGrantManifestClaims struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
}

type groupEndpointKeyBindingClaims struct {
	Operation            string              `json:"operation"`
	OwnerID              string              `json:"owner_id"`
	PrincipalID          string              `json:"principal_id"`
	GroupID              string              `json:"group_id"`
	EndpointID           string              `json:"endpoint_id"`
	NodeID               string              `json:"node_id"`
	BindingID            string              `json:"binding_id"`
	BindingEpoch         uint64              `json:"binding_epoch"`
	MembershipRevision   int64               `json:"membership_revision"`
	EndpointJoinRevision int64               `json:"endpoint_join_revision"`
	CandidateVersion     int64               `json:"candidate_version"`
	CandidateKeyID       string              `json:"candidate_key_id"`
	Fingerprint          string              `json:"candidate_fingerprint"`
	ProofDigest          string              `json:"candidate_proof_digest"`
	PublicIdentity       e2ee.PublicIdentity `json:"candidate_public_identity"`
}

// VerifyGroupEndpointKeyGrant verifies the public grant and candidate against
// this Node's preinstalled OwnerKeyTrust and the supplied current route view.
// Its returned key is verified pin evidence only; it does not authorize a route.
func (s *CryptoState) VerifyGroupEndpointKeyGrant(ctx context.Context,
	evidence GroupEndpointKeyPinEvidence) (PeerKeyCandidate, error) {
	if ctx == nil {
		return PeerKeyCandidate{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return PeerKeyCandidate{}, err
	}
	trust, err := s.nodeOwnerTrustForGroupEndpointGrant(evidence.Peer.OwnerID,
		evidence.Route.ExpectedOwnerKeyID)
	if err != nil {
		return PeerKeyCandidate{}, err
	}
	return verifyGroupEndpointKeyGrantEvidence(evidence, trust, time.Now().UTC())
}

// PinOwnerGrantedGroupEndpointPeerKey persists verified same-Group key trust
// with an OwnerKeyTrust recheck in the same SQLite transaction. This does not
// authorize message routing; callers continue to evaluate the current Guard
// policy for every message.
func (s *CryptoState) PinOwnerGrantedGroupEndpointPeerKey(ctx context.Context,
	evidence GroupEndpointKeyPinEvidence) (*PeerKeyPin, error) {
	candidate, err := s.VerifyGroupEndpointKeyGrant(ctx, evidence)
	if err != nil {
		return nil, err
	}
	trust, err := s.nodeOwnerTrustForGroupEndpointGrant(evidence.Peer.OwnerID,
		evidence.Route.ExpectedOwnerKeyID)
	if err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, evidence.Grant.Manifest.ExpiresAt)
	if err != nil {
		return nil, ErrGroupEndpointKeyGrantInvalid
	}
	return s.pinGroupEndpointPeerKeyWithOwnerTrust(ctx, evidence.Scope, evidence.Peer,
		candidate.Public.ID, evidence.Route.CandidateFingerprint, candidate, trust, expiresAt)
}

// pinGroupEndpointPeerKeyWithOwnerTrust keeps the same active-pin, conflict,
// and terminal-revocation behavior as PinVerifiedPeerKey while checking the
// signing Owner key in the write transaction that stores the pin.
func (s *CryptoState) pinGroupEndpointPeerKeyWithOwnerTrust(ctx context.Context,
	scope PeerPinScope, expectedPeer PeerPinIdentity, expectedKeyID, expectedFingerprint string,
	candidate PeerKeyCandidate, ownerTrust OwnerKeyTrust, grantExpiry time.Time) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return nil, err
	}
	if scope.LocalGroupID != scope.PeerGroupID || scope.CommunicationLinkID != "" {
		return nil, ErrPeerPinCrossGroupGrantRequired
	}
	if err := validateCryptoToken("expected peer key ID", expectedKeyID); err != nil {
		return nil, err
	}
	if err := validateFingerprint(expectedFingerprint); err != nil {
		return nil, err
	}
	if candidate.EndpointID != expectedPeer.EndpointID || candidate.PrincipalID != expectedPeer.PrincipalID ||
		candidate.OwnerID != expectedPeer.OwnerID {
		return nil, ErrPeerPinIdentityMismatch
	}
	for label, value := range map[string]string{
		"candidate Endpoint ID": candidate.EndpointID, "candidate Principal ID": candidate.PrincipalID,
		"candidate Owner ID": candidate.OwnerID, "candidate Node ID": candidate.NodeID,
		"candidate Binding ID": candidate.BindingID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return nil, err
		}
	}
	if candidate.BindingEpoch == 0 || candidate.BindingEpoch > uint64(maxSQLiteSequence) {
		return nil, errors.New("candidate binding epoch must be positive and fit SQLite state")
	}
	if candidate.Public.ID != expectedKeyID {
		return nil, ErrPeerPinApprovalMismatch
	}
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		return nil, fmt.Errorf("validate candidate peer key: %w", err)
	}
	if fingerprint != expectedFingerprint {
		return nil, ErrPeerPinApprovalMismatch
	}
	verifiedPublic, err := e2ee.VerifyEndpointKeyAttestation(candidate.Attestation,
		candidate.EndpointID, candidate.PrincipalID, candidate.NodeID,
		candidate.BindingID, candidate.BindingEpoch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerPinUnverified, err)
	}
	if !samePublicIdentity(verifiedPublic, candidate.Public) {
		return nil, fmt.Errorf("%w: attested key differs from candidate public identity", ErrPeerPinUnverified)
	}
	if grantExpiry.IsZero() || !time.Now().UTC().Before(grantExpiry) {
		return nil, ErrGroupEndpointKeyGrantExpired
	}
	publicJSON, err := json.Marshal(candidate.Public)
	if err != nil {
		return nil, fmt.Errorf("encode candidate peer public identity: %w", err)
	}
	proofDigest := sha256.Sum256(candidate.Attestation)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var result *PeerKeyPin
	err = s.writeTx(ctx, func(conn *sql.Conn) error {
		if !time.Now().UTC().Before(grantExpiry) {
			return ErrGroupEndpointKeyGrantExpired
		}
		if err := ownerKeyTrustStillCurrent(ctx, conn, ownerTrust); err != nil {
			current, loadErr := loadNodeOwnerKeyTrust(ctx, conn, ownerTrust.OwnerID, ownerTrust.KeyID)
			if loadErr == nil && current.State == NodeOwnerKeyTrustRevoked {
				return ErrNodeOwnerKeyTrustRevoked
			}
			return err
		}
		current, err := loadPeerPin(ctx, conn, scope)
		if err == nil {
			if current.RevokedAt == "" {
				if samePeerIdentity(current.Peer, expectedPeer) &&
					current.KeyID == candidate.Public.ID && current.Fingerprint == fingerprint &&
					samePublicIdentity(current.Public, candidate.Public) {
					result = current
					return nil
				}
				return ErrPeerPinConflict
			}
			return ErrPeerPinRevoked
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO node_crypto_peer_pins
(local_endpoint_id, local_group_id, peer_endpoint_id, peer_group_id,
 communication_link_id, peer_principal_id, peer_owner_id, peer_key_id,
 peer_fingerprint, public_identity_json, peer_node_id, binding_id, binding_epoch,
 attestation_digest, version, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, '')`,
			scope.LocalEndpointID, scope.LocalGroupID, scope.PeerEndpointID, scope.PeerGroupID,
			scope.CommunicationLinkID, expectedPeer.PrincipalID, expectedPeer.OwnerID,
			candidate.Public.ID, fingerprint, string(publicJSON), candidate.NodeID,
			candidate.BindingID, int64(candidate.BindingEpoch), hex.EncodeToString(proofDigest[:]),
			timestamp, timestamp); err != nil {
			return fmt.Errorf("persist Owner-authorized Group peer pin: %w", err)
		}
		result, err = loadPeerPin(ctx, conn, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *CryptoState) nodeOwnerTrustForGroupEndpointGrant(ownerID, keyID string) (OwnerKeyTrust, error) {
	if err := validateCryptoToken("Owner ID", ownerID); err != nil {
		return OwnerKeyTrust{}, ErrGroupEndpointKeyGrantInvalid
	}
	if err := validateCryptoToken("Owner key ID", keyID); err != nil {
		return OwnerKeyTrust{}, ErrGroupEndpointKeyGrantInvalid
	}
	trust, err := s.GetNodeOwnerKeyTrustLocal(ownerID, keyID)
	if errors.Is(err, ErrNodeOwnerKeyTrustNotFound) {
		return OwnerKeyTrust{}, ErrPeerPinOwnerTrustRequired
	}
	if err != nil {
		return OwnerKeyTrust{}, err
	}
	if trust.State == NodeOwnerKeyTrustRevoked {
		return OwnerKeyTrust{}, ErrNodeOwnerKeyTrustRevoked
	}
	if trust.State != NodeOwnerKeyTrustActive {
		return OwnerKeyTrust{}, ErrPeerPinOwnerTrustRequired
	}
	return *trust, nil
}

func verifyGroupEndpointKeyGrantEvidence(evidence GroupEndpointKeyPinEvidence,
	trust OwnerKeyTrust, now time.Time) (PeerKeyCandidate, error) {
	invalid := func(cause error) (PeerKeyCandidate, error) {
		if cause == nil {
			return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantInvalid
		}
		return PeerKeyCandidate{}, fmt.Errorf("%w: %v", ErrGroupEndpointKeyGrantInvalid, cause)
	}
	if now.IsZero() {
		return invalid(errors.New("trusted verification time is required"))
	}
	if err := validatePeerPinRequest(evidence.Scope, evidence.Peer); err != nil {
		return invalid(err)
	}
	if evidence.Scope.LocalGroupID != evidence.Scope.PeerGroupID || evidence.Scope.CommunicationLinkID != "" {
		return invalid(errors.New("Group Endpoint grants require an unlinked same-Group pin scope"))
	}
	if err := validateLocalPinEndpoint(evidence.Local, evidence.Scope); err != nil {
		return invalid(err)
	}
	if evidence.Local.OwnerID != evidence.Peer.OwnerID {
		return PeerKeyCandidate{}, ErrPeerPinIdentityMismatch
	}

	grant, manifest, route, candidate := evidence.Grant, evidence.Grant.Manifest,
		evidence.Route, evidence.Candidate
	if grant.ID == "" || validateCryptoToken("Group Endpoint grant ID", grant.ID) != nil ||
		grant.OwnerID != manifest.OwnerID || grant.GroupID != manifest.GroupID ||
		grant.EndpointID != manifest.EndpointID || grant.OwnerKeyID != manifest.OwnerKeyID {
		return invalid(errors.New("grant record fields do not match its manifest"))
	}
	switch grant.CurrentStatus {
	case groupEndpointKeyGrantCurrent:
	case groupEndpointKeyGrantExpired:
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantExpired
	case groupEndpointKeyGrantRevoked:
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantRevoked
	case groupEndpointKeyGrantStale:
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantStale
	case groupEndpointKeyGrantInvalid:
		return invalid(errors.New("Store marked grant invalid"))
	default:
		return invalid(errors.New("grant status is absent or unknown"))
	}
	if manifest.Version != groupEndpointKeyGrantVersion || manifest.Operation != groupEndpointKeyGrantOperation {
		return invalid(errors.New("Group Endpoint grant operation or version is invalid"))
	}
	if trust.State != NodeOwnerKeyTrustActive || trust.OwnerID != manifest.OwnerID ||
		trust.KeyID != manifest.OwnerKeyID || trust.PublicIdentity.ID != trust.KeyID {
		return PeerKeyCandidate{}, ErrPeerPinOwnerTrustRequired
	}
	if err := e2ee.ValidatePublicIdentity(trust.PublicIdentity); err != nil {
		return invalid(fmt.Errorf("validate Node-local Owner trust: %w", err))
	}
	if err := validateFingerprint(trust.ExpectedFingerprint); err != nil {
		return invalid(fmt.Errorf("validate Node-local Owner fingerprint: %w", err))
	}
	ownerFingerprint, err := PeerKeyFingerprint(trust.PublicIdentity)
	if err != nil || ownerFingerprint != trust.ExpectedFingerprint {
		return PeerKeyCandidate{}, ErrPeerPinOwnerTrustRequired
	}
	if len(grant.SignedProof) == 0 {
		return invalid(errors.New("owner proof is empty"))
	}

	for label, value := range map[string]string{
		"expected Hub ID": route.HubID, "route Group ID": route.GroupID,
		"expected Owner key ID": route.ExpectedOwnerKeyID,
		"manifest Hub ID":       manifest.HubID, "manifest Owner ID": manifest.OwnerID,
		"manifest Principal ID": manifest.PrincipalID, "manifest Group ID": manifest.GroupID,
		"manifest Endpoint ID": manifest.EndpointID, "manifest Node ID": manifest.NodeID,
		"manifest Binding ID": manifest.BindingID, "manifest candidate key ID": manifest.CandidateKeyID,
		"manifest Owner key ID": manifest.OwnerKeyID,
		"candidate Endpoint ID": candidate.EndpointID, "candidate Group ID": candidate.GroupID,
		"candidate Principal ID": candidate.PrincipalID, "candidate Owner ID": candidate.OwnerID,
		"candidate Node ID": candidate.NodeID, "candidate Binding ID": candidate.BindingID,
		"candidate key ID":   candidate.KeyID,
		"route peer Node ID": route.PeerNodeID, "route peer Binding ID": route.PeerBindingID,
		"route candidate key ID": route.CandidateKeyID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return invalid(err)
		}
	}
	if manifest.HubID != route.HubID || manifest.GroupID != evidence.Scope.PeerGroupID ||
		manifest.GroupID != route.GroupID || manifest.OwnerID != evidence.Peer.OwnerID ||
		manifest.OwnerID != evidence.Local.OwnerID || manifest.EndpointID != evidence.Peer.EndpointID ||
		manifest.PrincipalID != evidence.Peer.PrincipalID || manifest.OwnerKeyID != route.ExpectedOwnerKeyID ||
		manifest.OwnerKeyID != trust.KeyID {
		return PeerKeyCandidate{}, ErrPeerPinIdentityMismatch
	}
	if evidence.Local.EndpointID == manifest.EndpointID || evidence.Local.NodeID == manifest.NodeID {
		return invalid(errors.New("Group Endpoint grant must pin a different Endpoint on another Node"))
	}
	if route.GroupRevision <= 0 || route.GroupRevision > maxSQLiteSequence ||
		route.MembershipRevision <= 0 || route.MembershipRevision > maxSQLiteSequence ||
		route.EndpointJoinRevision <= 0 || route.EndpointJoinRevision > maxSQLiteSequence ||
		route.PeerBindingEpoch == 0 || route.PeerBindingEpoch > uint64(maxSQLiteSequence) ||
		route.CandidateVersion <= 0 || route.CandidateVersion > maxSQLiteSequence ||
		manifest.GroupRevision <= 0 || manifest.GroupRevision > maxSQLiteSequence ||
		manifest.MembershipRevision <= 0 || manifest.MembershipRevision > maxSQLiteSequence ||
		manifest.EndpointJoinRevision <= 0 || manifest.EndpointJoinRevision > maxSQLiteSequence ||
		manifest.BindingEpoch == 0 || manifest.BindingEpoch > uint64(maxSQLiteSequence) ||
		manifest.CandidateVersion <= 0 || manifest.CandidateVersion > maxSQLiteSequence ||
		trust.Version <= 0 || trust.Version > maxSQLiteSequence {
		return invalid(errors.New("revision, binding epoch, candidate version or Owner key version is invalid"))
	}
	if manifest.GroupRevision != route.GroupRevision ||
		manifest.MembershipRevision != route.MembershipRevision ||
		manifest.EndpointJoinRevision != route.EndpointJoinRevision ||
		manifest.NodeID != route.PeerNodeID || manifest.BindingID != route.PeerBindingID ||
		manifest.BindingEpoch != route.PeerBindingEpoch || manifest.CandidateVersion != route.CandidateVersion ||
		manifest.CandidateKeyID != route.CandidateKeyID ||
		manifest.CandidateFingerprint != route.CandidateFingerprint ||
		manifest.CandidateProofDigest != route.CandidateProofDigest {
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantStale
	}
	if candidate.EndpointID != manifest.EndpointID || candidate.GroupID != manifest.GroupID ||
		candidate.PrincipalID != manifest.PrincipalID || candidate.OwnerID != manifest.OwnerID ||
		candidate.NodeID != manifest.NodeID || candidate.BindingID != manifest.BindingID ||
		candidate.BindingEpoch != manifest.BindingEpoch ||
		candidate.CandidateVersion != manifest.CandidateVersion || candidate.KeyID != manifest.CandidateKeyID ||
		candidate.KeyFingerprint != manifest.CandidateFingerprint ||
		candidate.ProofDigest != manifest.CandidateProofDigest ||
		!samePublicIdentity(candidate.PublicIdentity, manifest.CandidatePublicIdentity) {
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantStale
	}
	if !canonicalHash(manifest.Digest) || !canonicalHash(manifest.CandidateBindingDigest) ||
		!canonicalHash(manifest.CandidateProofDigest) ||
		validateFingerprint(manifest.CandidateFingerprint) != nil {
		return invalid(errors.New("manifest contains a malformed digest or fingerprint"))
	}
	if got := groupEndpointKeyBindingDigest(manifest); got == "" || got != manifest.CandidateBindingDigest {
		return invalid(errors.New("candidate binding digest mismatch"))
	}
	if got := groupEndpointKeyManifestDigest(manifest); got == "" || got != manifest.Digest {
		return invalid(errors.New("manifest digest mismatch"))
	}
	fingerprint, err := PeerKeyFingerprint(candidate.PublicIdentity)
	if err != nil || fingerprint != manifest.CandidateFingerprint ||
		candidate.PublicIdentity.ID != manifest.CandidateKeyID {
		return invalid(errors.New("candidate public identity or fingerprint mismatch"))
	}
	proofDigest := sha256.Sum256(candidate.Attestation)
	if len(candidate.Attestation) == 0 || hex.EncodeToString(proofDigest[:]) != manifest.CandidateProofDigest {
		return invalid(errors.New("candidate attestation digest mismatch"))
	}
	verifiedPublic, err := e2ee.VerifyEndpointKeyAttestation(candidate.Attestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID, manifest.BindingID,
		manifest.BindingEpoch)
	if err != nil || !samePublicIdentity(verifiedPublic, candidate.PublicIdentity) {
		return PeerKeyCandidate{}, fmt.Errorf("%w: Endpoint attestation does not match the signed candidate", ErrPeerPinUnverified)
	}
	issued, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil || issued.UTC().Format(time.RFC3339Nano) != manifest.IssuedAt || issued.After(now) {
		return invalid(errors.New("manifest issue time is invalid"))
	}
	expires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != manifest.ExpiresAt || !expires.After(issued) {
		return invalid(errors.New("manifest expiry is invalid"))
	}
	if !now.Before(expires) {
		return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantExpired
	}
	ownerGrant, err := e2ee.VerifyOwnerLinkKeyGrant(grant.SignedProof,
		trust.PublicIdentity, manifest.OwnerID, groupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, now)
	if err != nil {
		var claims e2ee.OwnerLinkKeyGrant
		if json.Unmarshal(grant.SignedProof, &claims) == nil {
			if proofExpiry, parseErr := time.Parse(time.RFC3339Nano, claims.ExpiresAt); parseErr == nil && !now.Before(proofExpiry) {
				return PeerKeyCandidate{}, ErrGroupEndpointKeyGrantExpired
			}
		}
		return PeerKeyCandidate{}, fmt.Errorf("%w: Owner proof verification failed: %v", ErrGroupEndpointKeyGrantInvalid, err)
	}
	if ownerGrant.IssuedAt != manifest.IssuedAt || ownerGrant.ExpiresAt != manifest.ExpiresAt {
		return invalid(errors.New("Owner proof validity interval differs from the signed manifest"))
	}
	return PeerKeyCandidate{
		EndpointID: manifest.EndpointID, PrincipalID: manifest.PrincipalID,
		OwnerID: manifest.OwnerID, NodeID: manifest.NodeID,
		Public: candidate.PublicIdentity, BindingID: manifest.BindingID,
		BindingEpoch: manifest.BindingEpoch, Attestation: append([]byte(nil), candidate.Attestation...),
	}, nil
}

func groupEndpointKeyManifestDigest(manifest GroupEndpointKeyGrantManifest) string {
	claims := groupEndpointKeyGrantManifestClaims{
		Version: manifest.Version, Operation: manifest.Operation, HubID: manifest.HubID,
		OwnerID: manifest.OwnerID, PrincipalID: manifest.PrincipalID,
		GroupID: manifest.GroupID, GroupRevision: manifest.GroupRevision,
		EndpointID: manifest.EndpointID, NodeID: manifest.NodeID,
		BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
		MembershipRevision:   manifest.MembershipRevision,
		EndpointJoinRevision: manifest.EndpointJoinRevision,
		CandidateVersion:     manifest.CandidateVersion, CandidateKeyID: manifest.CandidateKeyID,
		CandidateFingerprint:    manifest.CandidateFingerprint,
		CandidateProofDigest:    manifest.CandidateProofDigest,
		CandidateBindingDigest:  manifest.CandidateBindingDigest,
		CandidatePublicIdentity: manifest.CandidatePublicIdentity,
		OwnerKeyID:              manifest.OwnerKeyID, IssuedAt: manifest.IssuedAt,
		ExpiresAt: manifest.ExpiresAt,
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(groupEndpointKeyManifestDomain), encoded...))
	return hex.EncodeToString(sum[:])
}

func groupEndpointKeyBindingDigest(manifest GroupEndpointKeyGrantManifest) string {
	claims := groupEndpointKeyBindingClaims{
		Operation: manifest.Operation, OwnerID: manifest.OwnerID,
		PrincipalID: manifest.PrincipalID, GroupID: manifest.GroupID,
		EndpointID: manifest.EndpointID, NodeID: manifest.NodeID,
		BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
		MembershipRevision:   manifest.MembershipRevision,
		EndpointJoinRevision: manifest.EndpointJoinRevision,
		CandidateVersion:     manifest.CandidateVersion,
		CandidateKeyID:       manifest.CandidateKeyID,
		Fingerprint:          manifest.CandidateFingerprint,
		ProofDigest:          manifest.CandidateProofDigest,
		PublicIdentity:       manifest.CandidatePublicIdentity,
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(groupEndpointKeyBindingDomain), encoded...))
	return hex.EncodeToString(sum[:])
}
