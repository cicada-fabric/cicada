package nodekeys

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type endpointGroupsRegistrationRecord struct {
	Anchor       wire.EndpointGroupsRegistrationAnchor
	Hub          wire.HubIdentity
	OwnerKeyID   string
	NativeDigest string
}

func endpointGroupsNativeDigest(a wire.EndpointGroupsRegistrationAnchor) (string, error) {
	r := a.Registration
	return e2ee.EndpointGroupNativeIdentityDigest(e2ee.EndpointGroupNativeIdentity{HubID: r.HubID, OwnerID: r.OwnerID, NodeID: r.NodeID, LocalUserScope: a.LocalUserScope, Harness: r.Harness, NativeSessionID: r.NativeSessionID, Workspace: r.Workspace})
}

func loadEndpointGroupsRegistration(ctx context.Context, q endpointGroupsQuery, hub, endpoint string) (*endpointGroupsRegistrationRecord, error) {
	var r endpointGroupsRegistrationRecord
	var anchor, pin []byte
	err := q.QueryRowContext(ctx, `SELECT native_identity_digest,owner_key_id,anchor_json,hub_identity FROM node_endpoint_group_registrations_v1 WHERE hub_id=? AND endpoint_id=?`, hub, endpoint).Scan(&r.NativeDigest, &r.OwnerKeyID, &anchor, &pin)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(anchor, &r.Anchor) != nil || json.Unmarshal(pin, &r.Hub) != nil || wire.ValidateEndpointGroupsRegistrationAnchor(r.Anchor, r.Hub) != nil {
		return nil, ErrEndpointGroupsPolicy
	}
	digest, err := endpointGroupsNativeDigest(r.Anchor)
	if err != nil || digest != r.NativeDigest || r.Hub.HubID != hub || r.Anchor.Registration.EndpointID != endpoint {
		return nil, ErrEndpointGroupsConflict
	}
	return &r, nil
}

func endpointGroupsRegistrationTrust(ctx context.Context, q endpointGroupsQuery, r endpointGroupsRegistrationRecord) error {
	trust, err := loadNodeOwnerKeyTrust(ctx, q, r.Anchor.Registration.OwnerID, r.OwnerKeyID)
	if err != nil || trust.State != NodeOwnerKeyTrustActive {
		return ErrEndpointGroupsPolicy
	}
	return nil
}

// The caller has already matched its protected original Node join receipt and
// actual native record. This verifies the independent original Owner pin and
// locally retained key/attestation; it does not use current default permission.
func endpointGroupsOriginalRegistration(ctx context.Context, q endpointGroupsQuery, hub wire.HubIdentity, a wire.EndpointGroupsRegistrationAnchor) (string, error) {
	if wire.ValidateEndpointGroupsRegistrationAnchor(a, hub) != nil || a.Profile != "OWNER_ENDPOINT_GROUPS_V1" || a.RegistrationSource != "CODEX_LOCAL_DOMAIN" {
		return "", ErrEndpointGroupsPolicy
	}
	r := a.Registration
	var key, candidate []byte
	var policyID string
	if err := q.QueryRowContext(ctx, `SELECT public_identity FROM node_local_domain_local_keys_v1 WHERE endpoint_id=?`, r.EndpointID).Scan(&key); err != nil {
		return "", ErrEndpointGroupsPolicy
	}
	var original e2ee.PublicIdentity
	if json.Unmarshal(key, &original) != nil || !samePublicIdentity(original, a.CandidatePublic) || original.ID != a.CandidateKeyID {
		return "", ErrEndpointGroupsConflict
	}
	if err := q.QueryRowContext(ctx, `SELECT policy_id,candidate_json FROM node_local_domain_attestations_v1 WHERE endpoint_id=? AND binding_id=? AND binding_epoch=?`, r.EndpointID, a.BindingID, a.BindingEpoch).Scan(&policyID, &candidate); err != nil {
		return "", ErrEndpointGroupsPolicy
	}
	var c GroupEndpointKeyCandidate
	if json.Unmarshal(candidate, &c) != nil || validateNativePairLocalCandidate(c) != nil || c.EndpointID != r.EndpointID || c.PrincipalID != r.PrincipalID || c.OwnerID != r.OwnerID || c.NodeID != r.NodeID || c.BindingID != a.BindingID || c.BindingEpoch != a.BindingEpoch ||
		c.KeyID != a.CandidateKeyID || c.KeyFingerprint != a.CandidateFingerprint || c.ProofDigest != a.CandidateProofDigest || !samePublicIdentity(c.PublicIdentity, a.CandidatePublic) {
		return "", ErrEndpointGroupsConflict
	}
	var raw, proof, pin []byte
	if err := q.QueryRowContext(ctx, `SELECT policy_json,policy_proof,hub_identity FROM node_local_domain_policies_v1 WHERE policy_id=? AND group_id=?`, policyID, c.GroupID).Scan(&raw, &proof, &pin); err != nil {
		return "", ErrEndpointGroupsPolicy
	}
	var p e2ee.LocalDomainPolicy
	var oldHub wire.HubIdentity
	if json.Unmarshal(raw, &p) != nil || json.Unmarshal(pin, &oldHub) != nil || !reflect.DeepEqual(oldHub, hub) || p.PolicyID != policyID || p.OwnerID != r.OwnerID || p.HubID != r.HubID || p.Node.NodeID != r.NodeID || p.Node.NodeKeyEpoch != a.NodeKeyEpoch || p.NetworkID != a.NetworkID || p.LocalUserScope != a.LocalUserScope {
		return "", ErrEndpointGroupsConflict
	}
	trust, err := loadNodeOwnerKeyTrust(ctx, q, p.OwnerID, p.OwnerPublic.ID)
	if err != nil || trust.State != NodeOwnerKeyTrustActive || !samePublicIdentity(trust.PublicIdentity, p.OwnerPublic) {
		return "", ErrEndpointGroupsPolicy
	}
	// The old delegation is registration provenance only. Zero-time signature
	// verification deliberately does not renew its Group business permission.
	verified, err := e2ee.VerifyOwnerLocalDomainPolicy(trust.PublicIdentity, proof, time.Time{})
	if err != nil || !reflect.DeepEqual(verified, p) || wire.ValidateLocalDomainPolicy(p, hub, time.Time{}) != nil {
		return "", ErrEndpointGroupsPolicy
	}
	var memberJSON []byte
	err = q.QueryRowContext(ctx, `SELECT member_json FROM node_local_domain_members_v1 WHERE group_id=? AND endpoint_id=?`, p.GroupID, r.EndpointID).Scan(&memberJSON)
	if err == nil {
		var m wire.LocalDomainMember
		if json.Unmarshal(memberJSON, &m) != nil || m.EndpointID != r.EndpointID || m.PrincipalID != r.PrincipalID || m.NodeID != r.NodeID || m.Runtime != r.Harness || m.NativeSessionID != r.NativeSessionID || m.Workspace != r.Workspace || m.LocalUserScope != a.LocalUserScope ||
			m.BindingID != a.BindingID || m.BindingEpoch != a.BindingEpoch || m.LeaseOwner != a.LeaseOwner || m.NetworkAccessBindingID != a.NetworkAccessBindingID || m.NetworkAccessEpoch != a.NetworkAccessEpoch || m.CandidateVersion != a.CandidateVersion || m.CandidateKeyID != a.CandidateKeyID || m.CandidateFingerprint != a.CandidateFingerprint || m.CandidateProofDigest != a.CandidateProofDigest {
			return "", ErrEndpointGroupsConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	return p.OwnerPublic.ID, nil
}

func sameEndpointGroupsRegistration(old, next wire.EndpointGroupsRegistrationAnchor) bool {
	old.State, next.State = "", ""
	old.LeaseExpiresAt, next.LeaseExpiresAt = "", ""
	return reflect.DeepEqual(old, next)
}

func checkEndpointGroupsRegistration(ctx context.Context, q endpointGroupsQuery, hub wire.HubIdentity, a wire.EndpointGroupsRegistrationAnchor) (*endpointGroupsRegistrationRecord, error) {
	old, err := loadEndpointGroupsRegistration(ctx, q, hub.HubID, a.Registration.EndpointID)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(old.Hub, hub) || !sameEndpointGroupsRegistration(old.Anchor, a) || old.Anchor.State == "REVOKED" && a.State != "REVOKED" {
		return nil, ErrEndpointGroupsConflict
	}
	if err := endpointGroupsRegistrationTrust(ctx, q, *old); err != nil {
		return nil, err
	}
	if a.State == "REVOKED" {
		return nil, ErrEndpointGroupsPolicy
	}
	return old, nil
}

// Registration has zero business rights. A cold/expired lease may still be
// checked before exact renewal, but a different key/binding cannot replace it.
// Existing-only read guards never initialize or mutate registration state.
func (s *CryptoState) CheckEndpointGroupsRegistration(ctx context.Context, hub wire.HubIdentity, a wire.EndpointGroupsRegistrationAnchor, now time.Time) error {
	if ctx == nil || now.IsZero() || wire.ValidateEndpointGroupsRegistrationAnchor(a, hub) != nil || a.State == "REVOKED" {
		return ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	if s.existingOnly {
		_, err := checkEndpointGroupsRegistration(ctx, s.db, hub, a)
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		_, err := checkEndpointGroupsRegistration(ctx, conn, hub, a)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		ownerKey, err := endpointGroupsOriginalRegistration(ctx, conn, hub, a)
		if err != nil {
			return err
		}
		digest, err := endpointGroupsNativeDigest(a)
		if err != nil {
			return ErrEndpointGroupsPolicy
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		pin, err := json.Marshal(hub)
		if err != nil {
			return err
		}
		var existing string
		if e := conn.QueryRowContext(ctx, `SELECT endpoint_id FROM node_endpoint_group_registrations_v1 WHERE native_identity_digest=?`, digest).Scan(&existing); e == nil && existing != a.Registration.EndpointID {
			return ErrEndpointGroupsConflict
		} else if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_registrations_v1 VALUES(?,?,?,?,?,?)`, hub.HubID, a.Registration.EndpointID, digest, ownerKey, raw, pin)
		return err
	})
}

func endpointGroupsRelationForAnchor(a wire.EndpointGroupsRegistrationAnchor, group string, head e2ee.EndpointGroupOwnerControl) (wire.EndpointGroupRelation, error) {
	native, err := endpointGroupsNativeDigest(a)
	if err != nil {
		return wire.EndpointGroupRelation{}, err
	}
	digest, err := e2ee.EndpointGroupOwnerControlDigest(native, group, head)
	if err != nil {
		return wire.EndpointGroupRelation{}, err
	}
	r := a.Registration
	return wire.EndpointGroupRelation{HubID: r.HubID, OwnerID: r.OwnerID, NodeID: r.NodeID, LocalUserScope: a.LocalUserScope, NetworkID: a.NetworkID, GroupID: group, EndpointID: r.EndpointID, PrincipalID: r.PrincipalID, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, State: head.DenyReason, DecisionRevision: head.Revision, OwnerControlDigest: digest, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, CandidateVersion: a.CandidateVersion, CandidateKeyID: a.CandidateKeyID, CandidateFingerprint: a.CandidateFingerprint, CandidateProofDigest: a.CandidateProofDigest}, nil
}

// Only fresh authenticated deny observations are accepted. This never installs
// ACTIVE permission or clears a deny; Owner re-add requires a verified grant.
func (s *CryptoState) ObserveEndpointGroupOwnerControl(ctx context.Context, a wire.EndpointGroupsRegistrationAnchor, group string, head e2ee.EndpointGroupOwnerControl, now time.Time) error {
	if ctx == nil || now.IsZero() || validateCryptoToken("Group", group) != nil || e2ee.ValidateEndpointGroupOwnerControl(head) != nil || head.Mode != "OWNER" || (head.DenyReason != "REMOVED" && head.DenyReason != "EXPIRED") {
		return ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		old, err := loadEndpointGroupsRegistration(ctx, conn, a.Registration.HubID, a.Registration.EndpointID)
		if err != nil {
			return err
		}
		if _, err := checkEndpointGroupsRegistration(ctx, conn, old.Hub, a); err != nil {
			return err
		}
		r, err := endpointGroupsRelationForAnchor(a, group, head)
		if err != nil {
			return err
		}
		var oldHead, oldIdentity []byte
		var oldDigest string
		err = conn.QueryRowContext(ctx, `SELECT head_json,head_digest,identity_json FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID).Scan(&oldHead, &oldDigest, &oldIdentity)
		if err == nil {
			var h e2ee.EndpointGroupOwnerControl
			if json.Unmarshal(oldHead, &h) != nil || compareEndpointGroupHead(h, head) != nil || h.Revision == head.Revision && oldDigest != r.OwnerControlDigest {
				return ErrEndpointGroupsConflict
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		h, err := json.Marshal(head)
		if err != nil {
			return err
		}
		identity, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(oldIdentity) > 0 {
			identity = bytes.Clone(oldIdentity)
		}
		if _, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_heads_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(hub_id,network_id,group_id,endpoint_id) DO UPDATE SET head_json=excluded.head_json,head_digest=excluded.head_digest`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID, h, r.OwnerControlDigest, identity); err != nil {
			return err
		}
		return rememberEndpointGroupsRequired(ctx, conn, r)
	})
}
