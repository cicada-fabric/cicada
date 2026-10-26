package nodekeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsPeerManifest(source wire.EndpointGroupPeerSource) (wire.LocalDomainKeyManifest, error) {
	if (source.LocalDomainGrant == nil) == (source.EndpointGroupGrant == nil) {
		return wire.LocalDomainKeyManifest{}, ErrEndpointGroupsPolicy
	}
	if source.EndpointGroupGrant != nil {
		return source.EndpointGroupGrant.Manifest, nil
	}
	return source.LocalDomainGrant.Manifest, nil
}

func endpointGroupsAnchorRelationMatches(a wire.EndpointGroupsRegistrationAnchor, r wire.EndpointGroupRelation) bool {
	x := a.Registration
	return r.HubID == x.HubID && r.OwnerID == x.OwnerID && r.NodeID == x.NodeID && r.LocalUserScope == a.LocalUserScope && r.NetworkID == a.NetworkID && r.EndpointID == x.EndpointID && r.PrincipalID == x.PrincipalID && r.RegistrationDigest == a.RegistrationDigest && r.RegistrationRevision == a.RegistrationRevision &&
		r.BindingID == a.BindingID && r.BindingEpoch == a.BindingEpoch && r.CandidateVersion == a.CandidateVersion && r.CandidateKeyID == a.CandidateKeyID && r.CandidateFingerprint == a.CandidateFingerprint && r.CandidateProofDigest == a.CandidateProofDigest
}

func endpointGroupsPolicyExpectedHead(ctx context.Context, q endpointGroupsQuery, p e2ee.EndpointGroupPolicy, head e2ee.EndpointGroupOwnerControl) error {
	var raw []byte
	var digest string
	err := q.QueryRowContext(ctx, `SELECT head_json,head_digest FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, p.HubID, p.NetworkID, p.GroupID, p.EndpointID).Scan(&raw, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var old e2ee.EndpointGroupOwnerControl
	if json.Unmarshal(raw, &old) != nil || compareEndpointGroupHead(old, head) != nil {
		return ErrEndpointGroupsConflict
	}
	if head.Revision > old.Revision && (p.ExpectedDecisionRevision < old.Revision || p.ExpectedDecisionRevision == old.Revision && p.ExpectedOwnerControlDigest != digest) {
		return ErrEndpointGroupsConflict
	}
	return nil
}

func endpointGroupsOwnHead(ctx context.Context, q endpointGroupsQuery, a wire.EndpointGroupsRegistrationAnchor, snap wire.EndpointGroupCurrentEndpoint) error {
	if !endpointGroupsAnchorRelationMatches(a, snap.Relation) {
		return ErrEndpointGroupsConflict
	}
	native, err := endpointGroupsNativeDigest(a)
	if err != nil {
		return ErrEndpointGroupsPolicy
	}
	digest, err := e2ee.EndpointGroupOwnerControlDigest(native, snap.Relation.GroupID, snap.OwnerControl)
	if err != nil || digest != snap.Relation.OwnerControlDigest {
		return ErrEndpointGroupsConflict
	}
	return endpointGroupSnapshotNotOlder(ctx, q, snap)
}

// Policy/key signatures authenticate delegation, not current Hub state. The
// caller must separately obtain fresh authenticated Current before business use.
func (s *CryptoState) RememberEndpointGroupGrant(ctx context.Context, hub wire.HubIdentity, a wire.EndpointGroupsRegistrationAnchor, grant wire.EndpointGroupDelegatedGrant, head e2ee.EndpointGroupOwnerControl, now time.Time) error {
	if ctx == nil || now.IsZero() {
		return ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		original, err := checkEndpointGroupsRegistration(ctx, conn, hub, a)
		if err != nil {
			return err
		}
		trust, err := loadNodeOwnerKeyTrust(ctx, conn, a.Registration.OwnerID, original.OwnerKeyID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive {
			return ErrEndpointGroupsPolicy
		}
		p, err := wire.VerifyEndpointGroupDelegatedGrant(grant, hub, a.Registration.OwnerID, trust.PublicIdentity, now)
		if err != nil || !samePublicIdentity(p.EndpointPublic, a.CandidatePublic) || p.Node.NodeKeyEpoch != a.NodeKeyEpoch {
			return ErrEndpointGroupsPolicy
		}
		snap := wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: grant.Relation}
		if err := endpointGroupsOwnHead(ctx, conn, a, snap); err != nil {
			return err
		}
		if err := endpointGroupsPolicyExpectedHead(ctx, conn, p, head); err != nil {
			return err
		}
		if p.ExpectedDecisionRevision == 0 {
			native, err := endpointGroupsNativeDigest(a)
			if err != nil {
				return err
			}
			digest, err := e2ee.EndpointGroupOwnerControlDigest(native, p.GroupID, e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"})
			if err != nil || digest != p.ExpectedOwnerControlDigest {
				return ErrEndpointGroupsConflict
			}
		}
		if _, err := wire.VerifyEndpointGroupPeerSource(wire.EndpointGroupPeerSource{EndpointGroupGrant: &grant}, snap, hub, p.OwnerID, trust.PublicIdentity, now); err != nil {
			return ErrEndpointGroupsPolicy
		}
		if err := rememberEndpointGroupPolicy(ctx, conn, endpointGroupPolicyRecord{p, grant.PolicyProof, hub}); err != nil {
			return err
		}
		if err := rememberEndpointGroupSnapshot(ctx, conn, snap, *trust); err != nil {
			return err
		}
		return rememberEndpointGroupsRequired(ctx, conn, grant.Relation)
	})
}

type endpointGroupsPeerAuthorization struct {
	Registration endpointGroupsRegistrationRecord
	Sources      [2]wire.EndpointGroupPeerSource
	Snapshots    [2]wire.EndpointGroupCurrentEndpoint
	Manifests    [2]wire.LocalDomainKeyManifest
	Trusts       [2]OwnerKeyTrust
}

func endpointGroupsVerifyPeer(ctx context.Context, q endpointGroupsQuery, local, group string, sender, receiver wire.EndpointGroupPeerSource, current *wire.EndpointGroupCurrent, operation, attempt string, now time.Time) (*endpointGroupsPeerAuthorization, error) {
	if current == nil || wire.ValidateEndpointGroupCurrent(*current, operation, attempt, now) != nil || current.GroupID != group {
		return nil, ErrEndpointGroupsPolicy
	}
	own := current.Sender
	if current.Receiver.Relation.EndpointID == local {
		own = current.Receiver
	} else if current.Sender.Relation.EndpointID != local {
		return nil, ErrEndpointGroupsPolicy
	}
	a, err := loadEndpointGroupsRegistration(ctx, q, current.HubID, local)
	if err != nil {
		return nil, ErrEndpointGroupsPolicy
	}
	if _, err := checkEndpointGroupsRegistration(ctx, q, a.Hub, a.Anchor); err != nil {
		return nil, err
	}
	if current.HubID != a.Hub.HubID || current.Sender.Relation.NetworkID != a.Anchor.NetworkID || current.Receiver.Relation.NetworkID != a.Anchor.NetworkID {
		return nil, ErrEndpointGroupsPolicy
	}
	if err := endpointGroupsOwnHead(ctx, q, a.Anchor, own); err != nil {
		return nil, err
	}
	result := &endpointGroupsPeerAuthorization{Registration: *a, Sources: [2]wire.EndpointGroupPeerSource{sender, receiver}, Snapshots: [2]wire.EndpointGroupCurrentEndpoint{current.Sender, current.Receiver}}
	for i, source := range result.Sources {
		m, err := endpointGroupsPeerManifest(source)
		if err != nil {
			return nil, err
		}
		snap := result.Snapshots[i]
		if m.EndpointID != snap.Relation.EndpointID || m.OwnerID != snap.Relation.OwnerID || m.OwnerID != a.Anchor.Registration.OwnerID || m.GroupID != group {
			return nil, ErrEndpointGroupsPolicy
		}
		trust, err := loadNodeOwnerKeyTrust(ctx, q, m.OwnerID, m.OwnerKeyID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive {
			return nil, ErrEndpointGroupsPolicy
		}
		public, err := wire.VerifyEndpointGroupPeerSource(source, snap, a.Hub, m.OwnerID, trust.PublicIdentity, now)
		if err != nil || !samePublicIdentity(public, m.CandidatePublicIdentity) {
			return nil, ErrEndpointGroupsPolicy
		}
		if err := endpointGroupSnapshotNotOlder(ctx, q, snap); err != nil {
			return nil, err
		}
		if source.EndpointGroupGrant != nil {
			p, err := wire.VerifyEndpointGroupDelegatedGrant(*source.EndpointGroupGrant, a.Hub, m.OwnerID, trust.PublicIdentity, now)
			if err != nil {
				return nil, ErrEndpointGroupsPolicy
			}
			if err := endpointGroupsPolicyExpectedHead(ctx, q, p, snap.OwnerControl); err != nil {
				return nil, err
			}
		}
		result.Manifests[i] = m
		result.Trusts[i] = *trust
	}
	return result, nil
}

// Current must come from the authenticated Hub response for this exact native
// operation/attempt. This preliminary read never replaces the writer pin fence.
func (s *CryptoState) VerifyEndpointGroupsGroupAuthorization(ctx context.Context, local, group string, sender, receiver wire.EndpointGroupPeerSource, current *wire.EndpointGroupCurrent, operation, attempt string, now time.Time) (bool, error) {
	if ctx == nil || now.IsZero() || validateEndpointID(local) != nil || validateCryptoToken("Group", group) != nil {
		return true, ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return true, err
	}
	required, err := endpointGroupsRequired(ctx, s.db, local, group)
	if err != nil {
		return true, err
	}
	if current == nil && sender.LocalDomainGrant == nil && sender.EndpointGroupGrant == nil && receiver.LocalDomainGrant == nil && receiver.EndpointGroupGrant == nil {
		if !required {
			return false, nil
		}
		return true, ErrEndpointGroupsPolicy
	}
	_, err = endpointGroupsVerifyPeer(ctx, s.db, local, group, sender, receiver, current, operation, attempt, now)
	return true, err
}

// Each endpoint source and original Owner pin is checked independently. Their
// policies need not be the same; a default sender may address a manual receiver.
func (s *CryptoState) PinEndpointGroupsPeer(ctx context.Context, local string, sender, receiver wire.EndpointGroupPeerSource, current wire.EndpointGroupCurrent, operation, attempt string, now time.Time) (*PeerKeyPin, error) {
	if ctx == nil || now.IsZero() || validateEndpointID(local) != nil {
		return nil, ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var result *PeerKeyPin
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		verified, err := endpointGroupsVerifyPeer(ctx, conn, local, current.GroupID, sender, receiver, &current, operation, attempt, now)
		if err != nil {
			return err
		}
		for i, snap := range verified.Snapshots {
			source := verified.Sources[i]
			if source.EndpointGroupGrant != nil {
				var proof e2ee.OwnerEndpointGroupPolicyProof
				if json.Unmarshal(source.EndpointGroupGrant.PolicyProof, &proof) != nil {
					return ErrEndpointGroupsPolicy
				}
				if err := rememberEndpointGroupPolicy(ctx, conn, endpointGroupPolicyRecord{proof.Policy, source.EndpointGroupGrant.PolicyProof, verified.Registration.Hub}); err != nil {
					return err
				}
			}
			if err := rememberEndpointGroupSnapshot(ctx, conn, snap, verified.Trusts[i]); err != nil {
				return err
			}
			if snap.OwnerControl.Mode == "OWNER" {
				if err := rememberEndpointGroupsRequired(ctx, conn, snap.Relation); err != nil {
					return err
				}
			}
		}
		peer := 1
		if current.Receiver.Relation.EndpointID == local {
			peer = 0
		}
		m := verified.Manifests[peer]
		scope := PeerPinScope{LocalEndpointID: local, LocalGroupID: m.GroupID, PeerEndpointID: m.EndpointID, PeerGroupID: m.GroupID}
		oldPin, oldErr := loadPeerPin(ctx, conn, scope)
		if oldErr != nil && !errors.Is(oldErr, sql.ErrNoRows) {
			return oldErr
		}
		result, err = pinEndpointGroupsPeer(ctx, conn, local, m, verified.Sources[peer].EndpointGroupGrant != nil, now)
		if err == nil && (verified.Snapshots[0].OwnerControl.Mode == "OWNER" || verified.Snapshots[1].OwnerControl.Mode == "OWNER") {
			result, err = bindEndpointGroupsPeerAuthority(ctx, conn, result, oldPin, verified.Snapshots[1-peer], verified.Snapshots[peer], now)
		}
		return err
	})
	return result, err
}

func pinEndpointGroupsPeer(ctx context.Context, conn *sql.Conn, local string, k wire.LocalDomainKeyManifest, manual bool, now time.Time) (*PeerKeyPin, error) {
	scope := PeerPinScope{LocalEndpointID: local, LocalGroupID: k.GroupID, PeerEndpointID: k.EndpointID, PeerGroupID: k.GroupID}
	expected := PeerPinIdentity{EndpointID: k.EndpointID, GroupID: k.GroupID, PrincipalID: k.PrincipalID, OwnerID: k.OwnerID}
	if validatePeerPinRequest(scope, expected) != nil {
		return nil, ErrEndpointGroupsPolicy
	}
	pin, err := loadPeerPin(ctx, conn, scope)
	stamp := now.UTC().Format(time.RFC3339Nano)
	if err == nil {
		if pin.RevokedAt != "" {
			return nil, ErrPeerPinRevoked
		}
		if !samePeerIdentity(pin.Peer, expected) || pin.KeyID != k.CandidateKeyID || pin.Fingerprint != k.CandidateFingerprint || !samePublicIdentity(pin.Public, k.CandidatePublicIdentity) || pin.NodeID != k.NodeID || pin.BindingEpoch > k.BindingEpoch {
			return nil, ErrPeerPinConflict
		}
		if pin.BindingEpoch == k.BindingEpoch && (pin.BindingID != k.BindingID || pin.AttestationDigest != k.CandidateProofDigest) {
			return nil, ErrPeerPinConflict
		}
		if pin.BindingEpoch < k.BindingEpoch {
			if !manual {
				return nil, ErrPeerPinConflict
			}
			r, err := conn.ExecContext(ctx, `UPDATE node_crypto_peer_pins SET binding_id=?,binding_epoch=?,attestation_digest=?,version=version+1,updated_at=? WHERE local_endpoint_id=? AND local_group_id=? AND peer_endpoint_id=? AND peer_group_id=? AND communication_link_id='' AND revoked_at='' AND version=?`, k.BindingID, k.BindingEpoch, k.CandidateProofDigest, stamp, local, k.GroupID, k.EndpointID, k.GroupID, pin.Version)
			if err != nil {
				return nil, err
			}
			n, err := r.RowsAffected()
			if err != nil || n != 1 {
				return nil, ErrPeerPinConflict
			}
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		public, err := json.Marshal(k.CandidatePublicIdentity)
		if err != nil {
			return nil, err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_crypto_peer_pins(local_endpoint_id,local_group_id,peer_endpoint_id,peer_group_id,communication_link_id,peer_principal_id,peer_owner_id,peer_key_id,peer_fingerprint,public_identity_json,peer_node_id,binding_id,binding_epoch,attestation_digest,version,created_at,updated_at,revoked_at) VALUES(?,?,?,?,'',?,?,?,?,?,?,?,?,?,1,?,?,'')`, local, k.GroupID, k.EndpointID, k.GroupID, k.PrincipalID, k.OwnerID, k.CandidateKeyID, k.CandidateFingerprint, string(public), k.NodeID, k.BindingID, k.BindingEpoch, k.CandidateProofDigest, stamp, stamp)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	return loadPeerPin(ctx, conn, scope)
}

// No legacy route may regain the default authority of a participant whose
// permanent Owner control is already known locally. Unrelated peers are intact.
func endpointGroupsLegacyAllowed(ctx context.Context, q endpointGroupsQuery, group string, endpoints ...string) error {
	for _, endpoint := range endpoints {
		required, err := endpointGroupsRequired(ctx, q, endpoint, group)
		if err != nil {
			return err
		}
		if required {
			return ErrEndpointGroupsPolicy
		}
	}
	return nil
}
