package nodekeys

import (
	"context"
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

var (
	ErrPeerPinNotFound                = errors.New("verified peer pin not found")
	ErrPeerPinRevoked                 = errors.New("verified peer pin is revoked")
	ErrPeerPinConflict                = errors.New("verified peer pin conflicts with the active pin")
	ErrPeerPinVersionConflict         = errors.New("verified peer pin version does not match")
	ErrPeerPinIdentityMismatch        = errors.New("peer identity does not match the requested pin scope")
	ErrPeerPinApprovalMismatch        = errors.New("peer key does not match the independently approved key")
	ErrPeerPinUnverified              = errors.New("peer key candidate attestation is invalid")
	ErrPeerPinVersionExhausted        = errors.New("verified peer pin version is exhausted")
	ErrPeerPinCrossGroupLinkRequired  = errors.New("cross-Group peer pin requires a CommunicationLink ID")
	ErrPeerPinCrossGroupGrantRequired = errors.New("cross-Group peer pin requires bilateral owner key grants")
)

const peerKeyFingerprintDomain = "cicada/nodekeys/peer-key-fingerprint/v1\x00"

// PeerPinScope identifies one local trust decision. An empty CommunicationLinkID
// is allowed when both Endpoints are in the same Group. A cross-Group pin must
// name its CommunicationLink explicitly.
type PeerPinScope struct {
	LocalEndpointID     string
	LocalGroupID        string
	PeerEndpointID      string
	PeerGroupID         string
	CommunicationLinkID string
}

// PeerPinIdentity is the independently expected identity for the peer in a
// scope. EndpointID and GroupID must exactly match the scope; PrincipalID and
// OwnerID bind the pin to the expected peer identity as well as its key.
type PeerPinIdentity struct {
	EndpointID  string
	GroupID     string
	PrincipalID string
	OwnerID     string
}

// PeerKeyCandidate contains the peer's published public identity and its
// Endpoint self-attestation. Principal and Owner must be compared with values
// obtained from the caller's independently authenticated approval or trust
// context; the self-attestation itself does not prove Owner authorization.
type PeerKeyCandidate struct {
	EndpointID   string
	PrincipalID  string
	OwnerID      string
	NodeID       string
	Public       e2ee.PublicIdentity
	BindingID    string
	BindingEpoch uint64
	Attestation  []byte
}

// PeerKeyPin is the Node-local result of a verified pin decision. A revoked
// record is retained as a terminal tombstone with a higher Version.
type PeerKeyPin struct {
	Scope             PeerPinScope
	Peer              PeerPinIdentity
	Public            e2ee.PublicIdentity
	KeyID             string
	Fingerprint       string
	NodeID            string
	BindingID         string
	BindingEpoch      uint64
	AttestationDigest string
	LinkVersion       int64
	ManifestDigest    string
	LinkExpiresAt     string
	SourceGrantExpiry string
	TargetGrantExpiry string
	Version           int64
	CreatedAt         string
	UpdatedAt         string
	RevokedAt         string
}

// PeerKeyFingerprint returns a full SHA-256 fingerprint over the validated
// public KEM and signing keys. It is encoded as "sha256:" followed by 64
// lowercase hexadecimal characters. The caller must obtain the expected value
// used for pinning from an independently authenticated approval; computing a
// fingerprint from a candidate does not make that candidate trusted.
func PeerKeyFingerprint(public e2ee.PublicIdentity) (string, error) {
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return "", fmt.Errorf("validate peer public identity for fingerprint: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(peerKeyFingerprintDomain))
	_, _ = hash.Write(public.KEMPublic)
	_, _ = hash.Write(public.SigningPublic)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// PinVerifiedPeerKey stores a peer key only after matching the caller-supplied
// expected key ID and fingerprint and verifying the candidate's self-attested
// Endpoint, Principal, Node, Binding ID and epoch claims. The expected key ID,
// fingerprint and PeerPinIdentity must come from an independently authenticated
// approval or trust context. This local pin does not itself grant route
// authorization and is not user approval.
//
// One active pin is allowed per exact scope. Repeating the same active peer
// identity and public key is idempotent. A different key or peer identity
// conflicts. Revocation is terminal through this API; reapproval requires a
// distinct explicit flow.
func (s *CryptoState) PinVerifiedPeerKey(ctx context.Context, scope PeerPinScope, expectedPeer PeerPinIdentity,
	expectedKeyID, expectedFingerprint string, candidate PeerKeyCandidate) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return nil, err
	}
	if scope.LocalGroupID != scope.PeerGroupID {
		return nil, ErrPeerPinCrossGroupGrantRequired
	}
	if err := validateCryptoToken("expected peer key ID", expectedKeyID); err != nil {
		return nil, err
	}
	if err := validateFingerprint(expectedFingerprint); err != nil {
		return nil, err
	}
	if candidate.EndpointID != expectedPeer.EndpointID || candidate.PrincipalID != expectedPeer.PrincipalID || candidate.OwnerID != expectedPeer.OwnerID {
		return nil, ErrPeerPinIdentityMismatch
	}
	for label, value := range map[string]string{
		"candidate Endpoint ID":  candidate.EndpointID,
		"candidate Principal ID": candidate.PrincipalID,
		"candidate Owner ID":     candidate.OwnerID,
		"candidate Node ID":      candidate.NodeID,
		"candidate Binding ID":   candidate.BindingID,
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
			return fmt.Errorf("persist verified peer pin: %w", err)
		}
		result, err = loadPeerPin(ctx, conn, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetPeerPin returns only the active pin at the exact supplied scope and only
// when the caller's expected peer Endpoint, Group, Principal and Owner match.
func (s *CryptoState) GetPeerPin(ctx context.Context, scope PeerPinScope, expectedPeer PeerPinIdentity) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return nil, err
	}
	if scope.LocalGroupID != scope.PeerGroupID {
		return nil, ErrPeerPinCrossGroupGrantRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return nil, err
	}
	pin, err := loadPeerPin(ctx, conn, scope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPeerPinNotFound
	}
	if err != nil {
		return nil, err
	}
	if !samePeerIdentity(pin.Peer, expectedPeer) {
		return nil, ErrPeerPinIdentityMismatch
	}
	if pin.RevokedAt != "" {
		return nil, ErrPeerPinRevoked
	}
	return pin, nil
}

// VerifyPeerPin additionally checks the exact key ID and fingerprint expected
// by the caller. The expected identity still must match the exact scope.
func (s *CryptoState) VerifyPeerPin(ctx context.Context, scope PeerPinScope, expectedPeer PeerPinIdentity,
	expectedKeyID, expectedFingerprint string) (*PeerKeyPin, error) {
	if err := validateCryptoToken("expected peer key ID", expectedKeyID); err != nil {
		return nil, err
	}
	if err := validateFingerprint(expectedFingerprint); err != nil {
		return nil, err
	}
	pin, err := s.GetPeerPin(ctx, scope, expectedPeer)
	if err != nil {
		return nil, err
	}
	if pin.KeyID != expectedKeyID || pin.Fingerprint != expectedFingerprint {
		return nil, ErrPeerPinApprovalMismatch
	}
	return pin, nil
}

// RevokePeerPin revokes the active pin only when expectedVersion matches its
// current version. The tombstone increments Version and remains terminal
// through this API.
func (s *CryptoState) RevokePeerPin(ctx context.Context, scope PeerPinScope, expectedPeer PeerPinIdentity,
	expectedVersion int64) (*PeerKeyPin, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return nil, err
	}
	if expectedVersion <= 0 {
		return nil, errors.New("expected peer pin version must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var revoked *PeerKeyPin
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		pin, err := loadPeerPin(ctx, conn, scope)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerPinNotFound
		}
		if err != nil {
			return err
		}
		if !samePeerIdentity(pin.Peer, expectedPeer) {
			return ErrPeerPinIdentityMismatch
		}
		if pin.RevokedAt != "" {
			return ErrPeerPinRevoked
		}
		if pin.Version != expectedVersion {
			return ErrPeerPinVersionConflict
		}
		if pin.Version >= maxSQLiteSequence {
			return ErrPeerPinVersionExhausted
		}
		timestamp := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := conn.ExecContext(ctx, `UPDATE node_crypto_peer_pins
SET version = version + 1, updated_at = ?, revoked_at = ?
WHERE local_endpoint_id = ? AND local_group_id = ? AND peer_endpoint_id = ?
  AND peer_group_id = ? AND communication_link_id = ? AND version = ? AND revoked_at = ''`,
			timestamp, timestamp, scope.LocalEndpointID, scope.LocalGroupID,
			scope.PeerEndpointID, scope.PeerGroupID, scope.CommunicationLinkID, expectedVersion)
		if err != nil {
			return fmt.Errorf("revoke verified peer pin: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("confirm peer pin revocation: %w", err)
		}
		if changed != 1 {
			return ErrPeerPinVersionConflict
		}
		revoked, err = loadPeerPin(ctx, conn, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

func validatePeerPinRequest(scope PeerPinScope, peer PeerPinIdentity) error {
	for label, value := range map[string]string{
		"local Endpoint ID": scope.LocalEndpointID,
		"local Group ID":    scope.LocalGroupID,
		"peer Endpoint ID":  scope.PeerEndpointID,
		"peer Group ID":     scope.PeerGroupID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return err
		}
	}
	if scope.CommunicationLinkID != "" {
		if err := validateCryptoToken("CommunicationLink ID", scope.CommunicationLinkID); err != nil {
			return err
		}
	} else if scope.LocalGroupID != scope.PeerGroupID {
		return ErrPeerPinCrossGroupLinkRequired
	}
	for label, value := range map[string]string{
		"expected peer Endpoint ID":  peer.EndpointID,
		"expected peer Group ID":     peer.GroupID,
		"expected peer Principal ID": peer.PrincipalID,
		"expected peer Owner ID":     peer.OwnerID,
	} {
		if err := validateCryptoToken(label, value); err != nil {
			return err
		}
	}
	if peer.EndpointID != scope.PeerEndpointID || peer.GroupID != scope.PeerGroupID {
		return ErrPeerPinIdentityMismatch
	}
	return nil
}

func validateFingerprint(fingerprint string) error {
	if !strings.HasPrefix(fingerprint, "sha256:") || len(fingerprint) != len("sha256:")+sha256.Size*2 {
		return errors.New("peer key fingerprint must use sha256:<64 lowercase hexadecimal characters>")
	}
	encoded := strings.TrimPrefix(fingerprint, "sha256:")
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != encoded {
		return errors.New("peer key fingerprint must use sha256:<64 lowercase hexadecimal characters>")
	}
	return nil
}

func samePublicIdentity(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && string(left.KEMPublic) == string(right.KEMPublic) &&
		string(left.SigningPublic) == string(right.SigningPublic)
}

func samePeerIdentity(left, right PeerPinIdentity) bool {
	return left.EndpointID == right.EndpointID && left.GroupID == right.GroupID &&
		left.PrincipalID == right.PrincipalID && left.OwnerID == right.OwnerID
}

type peerPinScanner interface {
	Scan(dest ...any) error
}

const peerPinColumns = `local_endpoint_id, local_group_id, peer_endpoint_id,
peer_group_id, communication_link_id, peer_principal_id, peer_owner_id,
peer_key_id, peer_fingerprint, public_identity_json, peer_node_id, binding_id,
binding_epoch, attestation_digest, link_version, manifest_digest, link_expires_at,
source_grant_expires_at, target_grant_expires_at, version, created_at, updated_at, revoked_at`

func loadPeerPin(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, scope PeerPinScope) (*PeerKeyPin, error) {
	return scanPeerPin(queryer.QueryRowContext(ctx, `SELECT `+peerPinColumns+`
FROM node_crypto_peer_pins WHERE local_endpoint_id = ? AND local_group_id = ?
AND peer_endpoint_id = ? AND peer_group_id = ? AND communication_link_id = ?`,
		scope.LocalEndpointID, scope.LocalGroupID, scope.PeerEndpointID,
		scope.PeerGroupID, scope.CommunicationLinkID))
}

func scanPeerPin(row peerPinScanner) (*PeerKeyPin, error) {
	var pin PeerKeyPin
	var publicJSON string
	err := row.Scan(&pin.Scope.LocalEndpointID, &pin.Scope.LocalGroupID,
		&pin.Scope.PeerEndpointID, &pin.Scope.PeerGroupID, &pin.Scope.CommunicationLinkID,
		&pin.Peer.PrincipalID, &pin.Peer.OwnerID, &pin.KeyID, &pin.Fingerprint,
		&publicJSON, &pin.NodeID, &pin.BindingID, &pin.BindingEpoch,
		&pin.AttestationDigest, &pin.LinkVersion, &pin.ManifestDigest, &pin.LinkExpiresAt,
		&pin.SourceGrantExpiry, &pin.TargetGrantExpiry,
		&pin.Version, &pin.CreatedAt, &pin.UpdatedAt, &pin.RevokedAt)
	if err != nil {
		return nil, err
	}
	pin.Peer.EndpointID = pin.Scope.PeerEndpointID
	pin.Peer.GroupID = pin.Scope.PeerGroupID
	if err := json.Unmarshal([]byte(publicJSON), &pin.Public); err != nil {
		return nil, fmt.Errorf("decode pinned peer public identity: %w", err)
	}
	if pin.Public.ID != pin.KeyID {
		return nil, errors.New("pinned peer public identity does not match key ID")
	}
	if err := e2ee.ValidatePublicIdentity(pin.Public); err != nil {
		return nil, fmt.Errorf("validate pinned peer public identity: %w", err)
	}
	fingerprint, err := PeerKeyFingerprint(pin.Public)
	if err != nil {
		return nil, err
	}
	if fingerprint != pin.Fingerprint {
		return nil, errors.New("pinned peer public identity fingerprint mismatch")
	}
	return &pin, nil
}
