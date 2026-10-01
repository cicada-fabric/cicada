package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	peerKeyManifestVersion = 2
	peerKeyManifestDomain  = "cicada/communication-link/key-manifest/v2\x00"
	peerLinkContractDomain = "cicada/communication-link/proposal/v1\x00"
)

var (
	ErrPeerPinOwnerTrustRequired = errors.New("independent Node-local owner key trust is required")
	ErrPeerPinGrantInvalid       = errors.New("cross-Group owner key-grant bundle is invalid")
	ErrPeerPinGrantExpired       = errors.New("cross-Group owner key-grant authorization has expired")
	ErrPeerPinGrantStale         = errors.New("cross-Group owner key-grant authorization is stale")
)

// PeerKeyManifestSide mirrors the public Store manifest DTO without importing
// Store. The Node checks every field itself before using it as pin evidence.
type PeerKeyManifestSide struct {
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

// PeerKeyAuthorizationManifest mirrors store.CommunicationLinkKeyManifest.
// Its Digest is recomputed from the claims fields and never trusted as a Hub
// assertion.
type PeerKeyAuthorizationManifest struct {
	Version           int                 `json:"version"`
	LinkID            string              `json:"link_id"`
	LinkVersion       int64               `json:"link_version"`
	ContractDigest    string              `json:"contract_digest"`
	ContractCanonical []byte              `json:"contract_canonical"`
	Source            PeerKeyManifestSide `json:"source"`
	Target            PeerKeyManifestSide `json:"target"`
	Digest            string              `json:"digest"`
}

// PeerOwnerKeyGrantEvidence mirrors the Store export DTO. These public keys
// are candidates only: the verifier requires a separate OwnerKeyTrust for
// both owners, supplied from Node-local/out-of-band trusted state.
type PeerOwnerKeyGrantEvidence struct {
	Side                string              `json:"side"`
	OwnerID             string              `json:"owner_id"`
	OwnerKeyID          string              `json:"owner_key_id"`
	OwnerPublicIdentity e2ee.PublicIdentity `json:"owner_public_identity"`
	OwnerKeyState       string              `json:"owner_key_state"`
	OwnerKeyVersion     int64               `json:"owner_key_version"`
	CurrentStatus       string              `json:"current_status"`
	SignedProof         []byte              `json:"signed_proof"`
}

// PeerNativeContextScope mirrors the current Store scope projection without
// importing Store. It is Hub authorization metadata, not part of the signed
// Owner key grant and never a source of native identity.
type PeerNativeContextScope struct {
	HubID                string `json:"hub_id"`
	NetworkID            string `json:"network_id,omitempty"`
	GroupID              string `json:"group_id,omitempty"`
	GroupContextPolicy   string `json:"group_context_policy,omitempty"`
	NetworkContextPolicy string `json:"network_context_policy,omitempty"`
}

// PeerKeyAuthorizationBundle mirrors the Store's
// CommunicationLinkAuthorizationBundle while avoiding a Store import cycle.
// LinkState is informational. PROPOSED means the link is not a route grant.
type PeerKeyAuthorizationBundle struct {
	Manifest           PeerKeyAuthorizationManifest `json:"manifest"`
	SourceGrant        PeerOwnerKeyGrantEvidence    `json:"source_grant"`
	TargetGrant        PeerOwnerKeyGrantEvidence    `json:"target_grant"`
	LinkState          string                       `json:"link_state"`
	SourceContextScope PeerNativeContextScope       `json:"source_context_scope"`
	TargetContextScope PeerNativeContextScope       `json:"target_context_scope"`
}

// OwnerKeyTrust is the independently expected Owner signing key known to this
// Node. At least the public identity and fingerprint must be obtained outside
// the authorization Bundle; Bundle-provided public keys never establish trust.
type OwnerKeyTrust struct {
	OwnerID             string
	KeyID               string
	PublicIdentity      e2ee.PublicIdentity
	ExpectedFingerprint string
	State               string
	Version             int64
	CreatedAt           string
	UpdatedAt           string
	RevokedAt           string
}

// PeerPinLocalEndpoint is the Node-local expectation for its Endpoint side of
// the Link. Supplying this separately prevents a Hub response from replacing
// the local Endpoint's current Group, Binding, or key candidate.
type PeerPinLocalEndpoint struct {
	EndpointID   string
	GroupID      string
	PrincipalID  string
	OwnerID      string
	NodeID       string
	BindingID    string
	BindingEpoch uint64
	KeyID        string
	Public       e2ee.PublicIdentity
}

type verifiedOwnerKeyBundle struct {
	manifest      PeerKeyAuthorizationManifest
	peerCandidate PeerKeyCandidate
	sourceTrust   OwnerKeyTrust
	targetTrust   OwnerKeyTrust
	linkExpiry    time.Time
	sourceExpiry  time.Time
	targetExpiry  time.Time
}

type peerLinkContract struct {
	LinkID            string                `json:"link_id"`
	SourceEndpointID  string                `json:"source_endpoint_id"`
	SourcePrincipalID string                `json:"source_principal_id"`
	SourceGroupID     string                `json:"source_group_id"`
	SourceOwnerID     string                `json:"source_owner_id"`
	SourceNodeID      string                `json:"source_node_id"`
	TargetEndpointID  string                `json:"target_endpoint_id"`
	TargetPrincipalID string                `json:"target_principal_id"`
	TargetGroupID     string                `json:"target_group_id"`
	TargetOwnerID     string                `json:"target_owner_id"`
	TargetNodeID      string                `json:"target_node_id"`
	Direction         string                `json:"direction"`
	Actions           []string              `json:"actions"`
	DataScopes        []string              `json:"data_scopes"`
	TransportHubID    string                `json:"transport_hub_id"`
	ExpiresAt         string                `json:"expires_at"`
	ScopeSnapshot     peerLinkScopeSnapshot `json:"scope_snapshot"`
}

type peerLinkScopeSnapshot struct {
	SourceMembershipRevision int64 `json:"source_membership_revision"`
	SourceJoinRevision       int64 `json:"source_join_revision"`
	SourceGroupVersion       int64 `json:"source_group_version"`
	TargetMembershipRevision int64 `json:"target_membership_revision"`
	TargetJoinRevision       int64 `json:"target_join_revision"`
	TargetGroupVersion       int64 `json:"target_group_version"`
}

type peerKeyManifestClaims struct {
	Version           int                 `json:"version"`
	LinkID            string              `json:"link_id"`
	LinkVersion       int64               `json:"link_version"`
	ContractDigest    string              `json:"contract_digest"`
	ContractCanonical []byte              `json:"contract_canonical"`
	Source            PeerKeyManifestSide `json:"source"`
	Target            PeerKeyManifestSide `json:"target"`
}

// PinOwnerGrantedCrossGroupPeerKey pins a cross-Group Endpoint key only after
// the Node has independently validated both v2 ML-DSA Owner grants, the exact
// current Link manifest/candidate binding, the local Endpoint expectation,
// and independently trusted signing keys for both Owners. This records key
// trust only; it does not activate a route or bypass a current Guard decision.
func (s *CryptoState) PinOwnerGrantedCrossGroupPeerKey(ctx context.Context,
	scope PeerPinScope, local PeerPinLocalEndpoint, expectedPeer PeerPinIdentity,
	bundle PeerKeyAuthorizationBundle) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	now := time.Now().UTC()
	sourceTrust, targetTrust, err := s.trustedOwnerKeysForBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}
	verified, err := verifyPeerOwnerKeyBundle(scope, local, expectedPeer, bundle, sourceTrust, targetTrust, now)
	if err != nil {
		return nil, err
	}
	candidate := verified.peerCandidate
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		return nil, err
	}
	publicJSON, err := json.Marshal(candidate.Public)
	if err != nil {
		return nil, fmt.Errorf("encode candidate peer public identity: %w", err)
	}
	proofDigest := sha256.Sum256(candidate.Attestation)
	timestamp := now.UTC().Format(time.RFC3339Nano)
	linkExpiry := verified.linkExpiry.UTC().Format(time.RFC3339Nano)
	sourceExpiry := verified.sourceExpiry.UTC().Format(time.RFC3339Nano)
	targetExpiry := verified.targetExpiry.UTC().Format(time.RFC3339Nano)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var result *PeerKeyPin
	err = s.writeTx(ctx, func(conn *sql.Conn) error {
		if currentTime := time.Now().UTC(); !currentTime.Before(verified.linkExpiry) ||
			!currentTime.Before(verified.sourceExpiry) || !currentTime.Before(verified.targetExpiry) {
			return ErrPeerPinGrantExpired
		}
		if err := ownerKeyTrustStillCurrent(ctx, conn, verified.sourceTrust); err != nil {
			return err
		}
		if err := ownerKeyTrustStillCurrent(ctx, conn, verified.targetTrust); err != nil {
			return err
		}
		current, err := loadPeerPin(ctx, conn, scope)
		if err == nil {
			if current.RevokedAt != "" {
				return ErrPeerPinRevoked
			}
			if samePeerIdentity(current.Peer, expectedPeer) &&
				current.KeyID == candidate.Public.ID && current.Fingerprint == fingerprint &&
				samePublicIdentity(current.Public, candidate.Public) &&
				current.LinkVersion == verified.manifest.LinkVersion &&
				current.ManifestDigest == verified.manifest.Digest &&
				current.LinkExpiresAt == linkExpiry &&
				current.SourceGrantExpiry == sourceExpiry &&
				current.TargetGrantExpiry == targetExpiry {
				result = current
				return nil
			}
			return ErrPeerPinConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_crypto_peer_pins
(local_endpoint_id, local_group_id, peer_endpoint_id, peer_group_id,
 communication_link_id, peer_principal_id, peer_owner_id, peer_key_id,
 peer_fingerprint, public_identity_json, peer_node_id, binding_id, binding_epoch,
 attestation_digest, link_version, manifest_digest, link_expires_at,
 source_grant_expires_at, target_grant_expires_at, version, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, '')`,
			scope.LocalEndpointID, scope.LocalGroupID, scope.PeerEndpointID, scope.PeerGroupID,
			scope.CommunicationLinkID, expectedPeer.PrincipalID, expectedPeer.OwnerID,
			candidate.Public.ID, fingerprint, string(publicJSON), candidate.NodeID,
			candidate.BindingID, int64(candidate.BindingEpoch), hex.EncodeToString(proofDigest[:]),
			verified.manifest.LinkVersion, verified.manifest.Digest, linkExpiry,
			sourceExpiry, targetExpiry, timestamp, timestamp)
		if err != nil {
			return fmt.Errorf("persist owner-granted cross-Group peer pin: %w", err)
		}
		result, err = loadPeerPin(ctx, conn, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetOwnerGrantedCrossGroupPeerPin revalidates a freshly fetched authorization
// Bundle before returning the exact locally pinned key. Callers must fetch the
// Bundle through the authenticated current Store/Node path and still perform
// the route's current Guard check. The legacy GetPeerPin API deliberately
// never returns cross-Group pins.
func (s *CryptoState) GetOwnerGrantedCrossGroupPeerPin(ctx context.Context,
	scope PeerPinScope, local PeerPinLocalEndpoint, expectedPeer PeerPinIdentity,
	bundle PeerKeyAuthorizationBundle) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	now := time.Now().UTC()
	sourceTrust, targetTrust, err := s.trustedOwnerKeysForBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}
	verified, err := verifyPeerOwnerKeyBundle(scope, local, expectedPeer, bundle, sourceTrust, targetTrust, now)
	if err != nil {
		return nil, err
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return nil, err
	}
	if scope.LocalGroupID == scope.PeerGroupID {
		return nil, ErrPeerPinGrantInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var pin *PeerKeyPin
	err = s.writeTx(ctx, func(conn *sql.Conn) error {
		if currentTime := time.Now().UTC(); !currentTime.Before(verified.linkExpiry) ||
			!currentTime.Before(verified.sourceExpiry) || !currentTime.Before(verified.targetExpiry) {
			return ErrPeerPinGrantExpired
		}
		if err := ownerKeyTrustStillCurrent(ctx, conn, verified.sourceTrust); err != nil {
			return err
		}
		if err := ownerKeyTrustStillCurrent(ctx, conn, verified.targetTrust); err != nil {
			return err
		}
		current, err := loadPeerPin(ctx, conn, scope)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerPinNotFound
		}
		if err != nil {
			return err
		}
		if !samePeerIdentity(current.Peer, expectedPeer) {
			return ErrPeerPinIdentityMismatch
		}
		if current.RevokedAt != "" {
			return ErrPeerPinRevoked
		}
		if current.LinkVersion != verified.manifest.LinkVersion || current.ManifestDigest != verified.manifest.Digest {
			return ErrPeerPinGrantStale
		}
		fingerprint, fingerprintErr := PeerKeyFingerprint(verified.peerCandidate.Public)
		if fingerprintErr != nil || current.Public.ID != verified.peerCandidate.Public.ID ||
			current.Fingerprint != fingerprint ||
			!samePublicIdentity(current.Public, verified.peerCandidate.Public) ||
			current.BindingID != verified.peerCandidate.BindingID ||
			current.BindingEpoch != verified.peerCandidate.BindingEpoch ||
			current.AttestationDigest != sha256Hex(verified.peerCandidate.Attestation) {
			return ErrPeerPinApprovalMismatch
		}
		linkExpiry := verified.linkExpiry.UTC().Format(time.RFC3339Nano)
		sourceExpiry := verified.sourceExpiry.UTC().Format(time.RFC3339Nano)
		targetExpiry := verified.targetExpiry.UTC().Format(time.RFC3339Nano)
		if current.LinkExpiresAt != linkExpiry || current.SourceGrantExpiry != sourceExpiry ||
			current.TargetGrantExpiry != targetExpiry {
			return ErrPeerPinGrantStale
		}
		pin = current
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pin, nil
}

func verifyPeerOwnerKeyBundle(scope PeerPinScope, local PeerPinLocalEndpoint,
	expectedPeer PeerPinIdentity, bundle PeerKeyAuthorizationBundle,
	sourceTrust, targetTrust OwnerKeyTrust, now time.Time) (verifiedOwnerKeyBundle, error) {
	if now.IsZero() {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: trusted verification time is required", ErrPeerPinGrantInvalid)
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return verifiedOwnerKeyBundle{}, err
	}
	if scope.LocalGroupID == scope.PeerGroupID || scope.CommunicationLinkID == "" {
		return verifiedOwnerKeyBundle{}, ErrPeerPinGrantInvalid
	}
	if err := validateLocalPinEndpoint(local, scope); err != nil {
		return verifiedOwnerKeyBundle{}, err
	}
	manifest := bundle.Manifest
	if bundle.LinkState != "PROPOSED" && bundle.LinkState != "ACTIVE" {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: Link is absent or revoked", ErrPeerPinGrantInvalid)
	}
	if manifest.Version != peerKeyManifestVersion || manifest.LinkID != scope.CommunicationLinkID || manifest.LinkVersion <= 0 ||
		manifest.LinkVersion > maxSQLiteSequence || !canonicalHash(manifest.ContractDigest) || !canonicalHash(manifest.Digest) {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: malformed Link manifest", ErrPeerPinGrantInvalid)
	}
	contract, contractExpiry, err := verifyPeerLinkContract(manifest)
	if err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: %v", ErrPeerPinGrantInvalid, err)
	}
	if !now.Before(contractExpiry) {
		return verifiedOwnerKeyBundle{}, ErrPeerPinGrantExpired
	}
	if err := verifyPeerKeyManifest(manifest); err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: %v", ErrPeerPinGrantInvalid, err)
	}
	if err := matchManifestSidesToContract(manifest, contract); err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: %v", ErrPeerPinGrantInvalid, err)
	}
	if err := validatePeerContextScopes(bundle.SourceContextScope, bundle.TargetContextScope,
		manifest.Source, manifest.Target, contract.TransportHubID); err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: %v", ErrPeerPinGrantInvalid, err)
	}
	localSide, peerSide, err := matchExpectedSides(manifest, local, expectedPeer, scope)
	if err != nil {
		return verifiedOwnerKeyBundle{}, err
	}
	if bundle.SourceGrant.OwnerID != manifest.Source.OwnerID ||
		bundle.TargetGrant.OwnerID != manifest.Target.OwnerID {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: Owner grants do not match Link sides", ErrPeerPinGrantInvalid)
	}
	if err := verifyEndpointManifestSide(localSide); err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: local Endpoint proof: %v", ErrPeerPinGrantInvalid, err)
	}
	if err := verifyEndpointManifestSide(peerSide); err != nil {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: peer Endpoint proof: %v", ErrPeerPinGrantInvalid, err)
	}

	sourceExpiry, err := verifyOwnerKeyGrant(bundle.SourceGrant, sourceTrust,
		manifest, e2ee.OwnerLinkGrantSideSource, now)
	if err != nil {
		if errors.Is(err, ErrPeerPinGrantExpired) || errors.Is(err, ErrPeerPinOwnerTrustRequired) {
			return verifiedOwnerKeyBundle{}, err
		}
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: source grant: %v", ErrPeerPinGrantInvalid, err)
	}
	targetExpiry, err := verifyOwnerKeyGrant(bundle.TargetGrant, targetTrust,
		manifest, e2ee.OwnerLinkGrantSideTarget, now)
	if err != nil {
		if errors.Is(err, ErrPeerPinGrantExpired) || errors.Is(err, ErrPeerPinOwnerTrustRequired) {
			return verifiedOwnerKeyBundle{}, err
		}
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: target grant: %v", ErrPeerPinGrantInvalid, err)
	}
	if sourceExpiry.After(contractExpiry) || targetExpiry.After(contractExpiry) {
		return verifiedOwnerKeyBundle{}, fmt.Errorf("%w: Owner grant exceeds Link expiry", ErrPeerPinGrantInvalid)
	}
	peerCandidate := PeerKeyCandidate{
		EndpointID: peerSide.EndpointID, PrincipalID: peerSide.PrincipalID,
		OwnerID: peerSide.OwnerID, NodeID: peerSide.NodeID,
		Public: peerSide.PublicIdentity, BindingID: peerSide.BindingID,
		BindingEpoch: peerSide.BindingEpoch, Attestation: append([]byte(nil), peerSide.Attestation...),
	}
	return verifiedOwnerKeyBundle{manifest: manifest, peerCandidate: peerCandidate,
		sourceTrust: sourceTrust, targetTrust: targetTrust,
		linkExpiry: contractExpiry, sourceExpiry: sourceExpiry, targetExpiry: targetExpiry}, nil
}

func validatePeerContextScopes(source, target PeerNativeContextScope,
	sourceSide, targetSide PeerKeyManifestSide, transportHubID string) error {
	if transportHubID == "" || source.HubID == "" || source.HubID != target.HubID ||
		source.HubID != transportHubID || target.HubID != transportHubID ||
		source.GroupID != sourceSide.GroupID || target.GroupID != targetSide.GroupID ||
		!validPeerContextScope(source) || !validPeerContextScope(target) {
		return errors.New("current Link context scope does not match Hub and manifest sides")
	}
	return nil
}

func validPeerContextScope(scope PeerNativeContextScope) bool {
	if scope.HubID == "" || scope.GroupID == "" ||
		(scope.NetworkID != "" && validateCryptoToken("context Network ID", scope.NetworkID) != nil) {
		return false
	}
	return (scope.GroupContextPolicy == "" || scope.GroupContextPolicy == "group_scoped" || scope.GroupContextPolicy == "dedicated_thread") &&
		(scope.NetworkContextPolicy == "" || scope.NetworkContextPolicy == "dedicated_thread")
}

func validateLocalPinEndpoint(local PeerPinLocalEndpoint, scope PeerPinScope) error {
	for label, value := range map[string]string{
		"local Endpoint ID": local.EndpointID, "local Group ID": local.GroupID,
		"local Principal ID": local.PrincipalID, "local Owner ID": local.OwnerID,
		"local Node ID": local.NodeID, "local Binding ID": local.BindingID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return err
		}
	}
	if local.EndpointID != scope.LocalEndpointID || local.GroupID != scope.LocalGroupID ||
		local.BindingEpoch == 0 || local.BindingEpoch > uint64(maxSQLiteSequence) || local.KeyID == "" ||
		local.Public.ID != local.KeyID {
		return ErrPeerPinIdentityMismatch
	}
	if err := e2ee.ValidatePublicIdentity(local.Public); err != nil {
		return fmt.Errorf("validate local Endpoint public identity: %w", err)
	}
	return nil
}

func verifyPeerLinkContract(manifest PeerKeyAuthorizationManifest) (peerLinkContract, time.Time, error) {
	var contract peerLinkContract
	if err := decodeCanonicalJSON(manifest.ContractCanonical, &contract); err != nil {
		return peerLinkContract{}, time.Time{}, fmt.Errorf("decode canonical Link contract: %w", err)
	}
	if contract.LinkID != manifest.LinkID || contract.Direction != "forward" && contract.Direction != "bidirectional" ||
		len(contract.Actions) == 0 || len(contract.Actions) > 3 || len(contract.DataScopes) == 0 || len(contract.DataScopes) > 16 {
		return peerLinkContract{}, time.Time{}, errors.New("Link contract claims are incomplete")
	}
	contractDigest := sha256.Sum256(append([]byte(peerLinkContractDomain), manifest.ContractCanonical...))
	if hex.EncodeToString(contractDigest[:]) != manifest.ContractDigest {
		return peerLinkContract{}, time.Time{}, errors.New("Link contract digest mismatch")
	}
	for _, value := range []string{contract.SourceEndpointID, contract.SourcePrincipalID, contract.SourceGroupID,
		contract.SourceOwnerID, contract.SourceNodeID, contract.TargetEndpointID, contract.TargetPrincipalID,
		contract.TargetGroupID, contract.TargetOwnerID, contract.TargetNodeID} {
		if validateCryptoToken("Link contract identity", value) != nil {
			return peerLinkContract{}, time.Time{}, errors.New("Link contract contains an invalid identity")
		}
	}
	if contract.SourceGroupID == contract.TargetGroupID {
		return peerLinkContract{}, time.Time{}, errors.New("cross-Group Link contract names only one Group")
	}
	if !validSortedContractWords(contract.Actions, map[string]bool{"send": true, "ask": true, "reply": true}) ||
		(len(contract.Actions) == 1 && contract.Actions[0] == "reply") ||
		!validSortedContractWords(contract.DataScopes, nil) {
		return peerLinkContract{}, time.Time{}, errors.New("Link actions or data scope are not canonical")
	}
	snapshot := contract.ScopeSnapshot
	if snapshot.SourceMembershipRevision <= 0 || snapshot.SourceJoinRevision <= 0 || snapshot.SourceGroupVersion <= 0 ||
		snapshot.TargetMembershipRevision <= 0 || snapshot.TargetJoinRevision <= 0 || snapshot.TargetGroupVersion <= 0 {
		return peerLinkContract{}, time.Time{}, errors.New("Link scope snapshot is incomplete")
	}
	expiry, err := time.Parse(time.RFC3339, contract.ExpiresAt)
	if err != nil || expiry.UTC().Format(time.RFC3339) != contract.ExpiresAt {
		return peerLinkContract{}, time.Time{}, errors.New("Link expiry is not canonical UTC RFC3339")
	}
	return contract, expiry, nil
}

func validSortedContractWords(values []string, allowed map[string]bool) bool {
	previous := ""
	for _, value := range values {
		if value == "" || value != strings.ToLower(strings.TrimSpace(value)) ||
			strings.ContainsAny(value, " \t\n\r") || value == "*" || (allowed != nil && !allowed[value]) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func matchManifestSidesToContract(manifest PeerKeyAuthorizationManifest, contract peerLinkContract) error {
	source, target := manifest.Source, manifest.Target
	if source.EndpointID != contract.SourceEndpointID || source.PrincipalID != contract.SourcePrincipalID ||
		source.GroupID != contract.SourceGroupID || source.OwnerID != contract.SourceOwnerID || source.NodeID != contract.SourceNodeID ||
		target.EndpointID != contract.TargetEndpointID || target.PrincipalID != contract.TargetPrincipalID ||
		target.GroupID != contract.TargetGroupID || target.OwnerID != contract.TargetOwnerID || target.NodeID != contract.TargetNodeID {
		return errors.New("manifest sides do not match Link contract")
	}
	return nil
}

func matchExpectedSides(manifest PeerKeyAuthorizationManifest, local PeerPinLocalEndpoint,
	peer PeerPinIdentity, scope PeerPinScope) (PeerKeyManifestSide, PeerKeyManifestSide, error) {
	matchLocal := func(side PeerKeyManifestSide) bool {
		return side.EndpointID == local.EndpointID && side.GroupID == local.GroupID &&
			side.PrincipalID == local.PrincipalID && side.OwnerID == local.OwnerID &&
			side.NodeID == local.NodeID && side.BindingID == local.BindingID &&
			side.BindingEpoch == local.BindingEpoch && side.KeyID == local.KeyID &&
			samePublicIdentity(side.PublicIdentity, local.Public)
	}
	matchPeer := func(side PeerKeyManifestSide) bool {
		return side.EndpointID == peer.EndpointID && side.GroupID == peer.GroupID &&
			side.PrincipalID == peer.PrincipalID && side.OwnerID == peer.OwnerID &&
			side.EndpointID == scope.PeerEndpointID && side.GroupID == scope.PeerGroupID
	}
	if matchLocal(manifest.Source) && matchPeer(manifest.Target) {
		return manifest.Source, manifest.Target, nil
	}
	if matchLocal(manifest.Target) && matchPeer(manifest.Source) {
		return manifest.Target, manifest.Source, nil
	}
	return PeerKeyManifestSide{}, PeerKeyManifestSide{}, ErrPeerPinIdentityMismatch
}

func verifyEndpointManifestSide(side PeerKeyManifestSide) error {
	for label, value := range map[string]string{
		"manifest Endpoint ID": side.EndpointID, "manifest Group ID": side.GroupID,
		"manifest Principal ID": side.PrincipalID, "manifest Owner ID": side.OwnerID,
		"manifest Node ID": side.NodeID, "manifest Binding ID": side.BindingID,
		"manifest key ID": side.KeyID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return err
		}
	}
	if side.BindingEpoch == 0 || side.BindingEpoch > uint64(maxSQLiteSequence) ||
		side.CandidateVersion <= 0 || side.PublicIdentity.ID != side.KeyID {
		return errors.New("manifest Endpoint binding or key version is invalid")
	}
	fingerprint, err := PeerKeyFingerprint(side.PublicIdentity)
	if err != nil || fingerprint != side.KeyFingerprint {
		return errors.New("manifest Endpoint key fingerprint mismatch")
	}
	proofDigest := sha256.Sum256(side.Attestation)
	if hex.EncodeToString(proofDigest[:]) != side.ProofDigest {
		return errors.New("manifest Endpoint attestation digest mismatch")
	}
	verifiedPublic, err := e2ee.VerifyEndpointKeyAttestation(side.Attestation, side.EndpointID,
		side.PrincipalID, side.NodeID, side.BindingID, side.BindingEpoch)
	if err != nil {
		return err
	}
	if !samePublicIdentity(verifiedPublic, side.PublicIdentity) {
		return errors.New("manifest Endpoint attestation signs another public key")
	}
	return nil
}

func verifyPeerKeyManifest(manifest PeerKeyAuthorizationManifest) error {
	claims := peerKeyManifestClaims{
		Version: manifest.Version, LinkID: manifest.LinkID, LinkVersion: manifest.LinkVersion,
		ContractDigest: manifest.ContractDigest, ContractCanonical: manifest.ContractCanonical,
		Source: manifest.Source, Target: manifest.Target,
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte(peerKeyManifestDomain), encoded...))
	if hex.EncodeToString(sum[:]) != manifest.Digest {
		return errors.New("key manifest digest mismatch")
	}
	return nil
}

func verifyOwnerKeyGrant(evidence PeerOwnerKeyGrantEvidence, trust OwnerKeyTrust,
	manifest PeerKeyAuthorizationManifest, side e2ee.OwnerLinkGrantSide, now time.Time) (time.Time, error) {
	expectedSide := string(side)
	if evidence.Side != expectedSide || evidence.OwnerID != trust.OwnerID || trust.OwnerID == "" ||
		evidence.OwnerKeyID == "" || evidence.OwnerKeyID != trust.KeyID ||
		evidence.OwnerKeyState != "ACTIVE" || trust.State != "ACTIVE" ||
		evidence.OwnerKeyVersion <= 0 || trust.Version <= 0 || evidence.OwnerKeyVersion != trust.Version ||
		evidence.CurrentStatus != "ACCEPTED" {
		return time.Time{}, ErrPeerPinOwnerTrustRequired
	}
	if len(evidence.SignedProof) == 0 {
		return time.Time{}, ErrPeerPinGrantInvalid
	}
	if err := e2ee.ValidatePublicIdentity(trust.PublicIdentity); err != nil {
		return time.Time{}, fmt.Errorf("validate Node-local Owner trust: %w", err)
	}
	if trust.PublicIdentity.ID != trust.KeyID || evidence.OwnerPublicIdentity.ID != trust.KeyID ||
		!samePublicIdentity(evidence.OwnerPublicIdentity, trust.PublicIdentity) {
		return time.Time{}, ErrPeerPinOwnerTrustRequired
	}
	if err := validateFingerprint(trust.ExpectedFingerprint); err != nil {
		return time.Time{}, fmt.Errorf("validate independently expected Owner key fingerprint: %w", err)
	}
	fingerprint, err := PeerKeyFingerprint(trust.PublicIdentity)
	if err != nil || fingerprint != trust.ExpectedFingerprint {
		return time.Time{}, ErrPeerPinOwnerTrustRequired
	}
	grant, err := e2ee.VerifyOwnerLinkKeyGrant(evidence.SignedProof, trust.PublicIdentity,
		trust.OwnerID, manifest.LinkID, manifest.ContractDigest, manifest.Digest,
		uint64(manifest.LinkVersion), side, now)
	if err != nil {
		var claims e2ee.OwnerLinkKeyGrant
		if json.Unmarshal(evidence.SignedProof, &claims) == nil {
			if expires, parseErr := time.Parse(time.RFC3339Nano, claims.ExpiresAt); parseErr == nil && !now.Before(expires) {
				return time.Time{}, ErrPeerPinGrantExpired
			}
		}
		return time.Time{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

func decodeCanonicalJSON(data []byte, target any) error {
	if len(data) == 0 {
		return errors.New("empty JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("JSON is not canonical")
	}
	return nil
}

func canonicalHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ownerKeyTrustStillCurrent(ctx context.Context, conn *sql.Conn, expected OwnerKeyTrust) error {
	current, err := loadNodeOwnerKeyTrust(ctx, conn, expected.OwnerID, expected.KeyID)
	if err != nil || current.State != NodeOwnerKeyTrustActive || !compareOwnerKeyTrust(expected, *current) {
		return ErrPeerPinOwnerTrustRequired
	}
	return nil
}
