package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// CommunicationLinkAuthorizationProof is public verification material, not a
// route grant by itself. The receiving Node must independently trust the owner
// keys and verify both proofs against the manifest before pinning a peer key.
type CommunicationLinkAuthorizationProof struct {
	Side                string              `json:"side"`
	OwnerID             string              `json:"owner_id"`
	OwnerKeyID          string              `json:"owner_key_id"`
	OwnerPublicIdentity e2ee.PublicIdentity `json:"owner_public_identity"`
	OwnerKeyState       string              `json:"owner_key_state"`
	OwnerKeyVersion     int64               `json:"owner_key_version"`
	CurrentStatus       string              `json:"current_status"`
	SignedProof         []byte              `json:"signed_proof"`
}

type CommunicationLinkAuthorizationBundle struct {
	Manifest           CommunicationLinkKeyManifest        `json:"manifest"`
	SourceGrant        CommunicationLinkAuthorizationProof `json:"source_grant"`
	TargetGrant        CommunicationLinkAuthorizationProof `json:"target_grant"`
	LinkState          string                              `json:"link_state"`
	SourceContextScope NativeContextScopeMetadata          `json:"source_context_scope"`
	TargetContextScope NativeContextScopeMetadata          `json:"target_context_scope"`
}

// getCommunicationLinkAuthorizationBundleForNodeScope is only for internal
// trusted scope inspection. HTTP callers must use the credential-bound method.
func (s *Store) getCommunicationLinkAuthorizationBundleForNodeScope(nodeID, ownerID, linkID string) (*CommunicationLinkAuthorizationBundle, error) {
	if nodeID == "" || len(nodeID) > 256 || strings.TrimSpace(nodeID) != nodeID ||
		validateOwnerApprovalID(ownerID) != nil ||
		linkID == "" || len(linkID) > 256 || strings.TrimSpace(linkID) != linkID {
		return nil, ErrCommunicationLinkNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	bundle, err := readCommunicationLinkAuthorizationBundle(tx, nodeID, ownerID, linkID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// GetCommunicationLinkAuthorizationBundleForNodeCredential exposes current,
// bilateral, key-bound public evidence only to a currently owner-bound Node.
// The credential and owner scope are read with the Link/Grant state in one
// transaction, so a revoked or reassigned Node credential cannot race the
// authorization read. The Bundle is not an independent Node trust root.
func (s *Store) GetCommunicationLinkAuthorizationBundleForNodeCredential(credentialDigest, linkID string) (*CommunicationLinkAuthorizationBundle, error) {
	if !validNodeCredentialDigest(credentialDigest) || linkID == "" ||
		len(linkID) > 256 || strings.TrimSpace(linkID) != linkID {
		return nil, ErrCommunicationLinkNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var nodeID, ownerID string
	err = tx.QueryRow(`SELECT credential.node_id, binding.owner_id
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
 AND binding.node_credential_digest=credential.credential_hash
 AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
 AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
 AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).Scan(&nodeID, &ownerID)
	if err != nil {
		return nil, ErrCommunicationLinkNotFound
	}
	bundle, err := readCommunicationLinkAuthorizationBundle(tx, nodeID, ownerID, linkID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return bundle, nil
}

func readCommunicationLinkAuthorizationBundle(tx *sql.Tx, nodeID, ownerID, linkID string) (*CommunicationLinkAuthorizationBundle, error) {
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=? AND
 ((source_node_id=? AND source_owner_id=?) OR (target_node_id=? AND target_owner_id=?))`,
		linkID, nodeID, ownerID, nodeID, ownerID))
	if err != nil {
		return nil, ErrCommunicationLinkNotFound
	}
	if link.SourceNodeID != link.TargetNodeID {
		var hubID string
		if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil {
			return nil, ErrCommunicationLinkScope
		}
		if link.TransportHubID != hubID {
			return nil, ErrCommunicationLinkScope
		}
	}
	now := time.Now().UTC()
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, now)
	if err != nil {
		return nil, err
	}
	source, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest, CommunicationLinkGrantSource, now)
	if err != nil {
		return nil, err
	}
	target, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest, CommunicationLinkGrantTarget, now)
	if err != nil {
		return nil, err
	}
	sourceScope, err := readNativeContextScopeForEndpointTx(tx, link.SourceEndpointID, link.SourceGroupID)
	if err != nil {
		return nil, ErrCommunicationLinkScope
	}
	targetScope, err := readNativeContextScopeForEndpointTx(tx, link.TargetEndpointID, link.TargetGroupID)
	if err != nil {
		return nil, ErrCommunicationLinkScope
	}
	return &CommunicationLinkAuthorizationBundle{
		Manifest: *manifest, SourceGrant: source, TargetGrant: target,
		LinkState: link.State, SourceContextScope: sourceScope, TargetContextScope: targetScope,
	}, nil
}

func readCurrentCommunicationLinkAuthorizationProof(tx *sql.Tx, link CommunicationLink,
	manifest CommunicationLinkKeyManifest, side string, at time.Time) (CommunicationLinkAuthorizationProof, error) {
	grant, err := readStoredCommunicationLinkKeyGrant(tx, link.ID, side)
	if errors.Is(err, sql.ErrNoRows) {
		return CommunicationLinkAuthorizationProof{}, ErrCommunicationLinkGrantConflict
	}
	if err != nil {
		return CommunicationLinkAuthorizationProof{}, err
	}
	ownerID := communicationLinkGrantOwner(link, side)
	if grant.ownerID != ownerID || grant.side != side || grant.linkVersion != link.Version ||
		grant.contractDigest != link.ContractDigest || grant.manifestDigest != manifest.Digest {
		return CommunicationLinkAuthorizationProof{}, ErrCommunicationLinkGrantConflict
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, grant.keyID))
	if err != nil || key.State != OwnerApprovalKeyActive {
		return CommunicationLinkAuthorizationProof{}, ErrOwnerApprovalKeyConflict
	}
	verified, err := e2ee.VerifyOwnerLinkKeyGrant(grant.proof, key.Public, ownerID,
		link.ID, link.ContractDigest, manifest.Digest, uint64(link.Version),
		e2ee.OwnerLinkGrantSide(side), at)
	if err != nil {
		return CommunicationLinkAuthorizationProof{}, ErrCommunicationLinkGrantConflict
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	linkExpiry, linkErr := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil || linkErr != nil || grantExpiry.After(linkExpiry) {
		return CommunicationLinkAuthorizationProof{}, ErrCommunicationLinkGrantConflict
	}
	return CommunicationLinkAuthorizationProof{
		Side: side, OwnerID: ownerID, OwnerKeyID: key.KeyID,
		OwnerPublicIdentity: key.Public, OwnerKeyState: key.State,
		OwnerKeyVersion: key.Version, CurrentStatus: CommunicationLinkKeyGrantAccepted,
		SignedProof: append([]byte(nil), grant.proof...),
	}, nil
}
