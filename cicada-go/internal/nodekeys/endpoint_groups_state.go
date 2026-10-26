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

var ErrEndpointGroupsPolicy = errors.New("Node Endpoint Group authorization requires original registration, independent Owner trust and current exact source")
var ErrEndpointGroupsConflict = errors.New("Node Endpoint Group evidence conflicts with retained identity or authority highwater")

func initializeEndpointGroupsSchema(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
CREATE TABLE node_endpoint_group_registrations_v1(
 hub_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,native_identity_digest TEXT NOT NULL UNIQUE,
 owner_key_id TEXT NOT NULL,anchor_json BLOB NOT NULL,hub_identity BLOB NOT NULL,
 PRIMARY KEY(hub_id,endpoint_id));
CREATE TRIGGER node_endpoint_group_registrations_v1_no_delete BEFORE DELETE ON node_endpoint_group_registrations_v1 BEGIN SELECT RAISE(ABORT,'original managed registration is retained');END;
CREATE TABLE node_endpoint_group_policies_v1(
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,group_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,
 policy_id TEXT NOT NULL,policy_json BLOB NOT NULL,policy_proof BLOB NOT NULL,hub_identity BLOB NOT NULL,
 PRIMARY KEY(hub_id,network_id,group_id,endpoint_id,policy_id));
CREATE TRIGGER node_endpoint_group_policies_v1_no_update BEFORE UPDATE ON node_endpoint_group_policies_v1 BEGIN SELECT RAISE(ABORT,'exact Owner delegation is immutable');END;
CREATE TRIGGER node_endpoint_group_policies_v1_no_delete BEFORE DELETE ON node_endpoint_group_policies_v1 BEGIN SELECT RAISE(ABORT,'Owner delegation history is retained');END;
CREATE TABLE node_endpoint_group_heads_v1(
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,group_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,
 head_json BLOB NOT NULL,head_digest TEXT NOT NULL,identity_json BLOB NOT NULL,
 PRIMARY KEY(hub_id,network_id,group_id,endpoint_id));
CREATE TRIGGER node_endpoint_group_heads_v1_no_delete BEFORE DELETE ON node_endpoint_group_heads_v1 BEGIN SELECT RAISE(ABORT,'Owner control history is retained');END;
CREATE TABLE node_endpoint_group_sources_v1(
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,group_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,
 source TEXT NOT NULL CHECK(source IN ('DEFAULT_POLICY','OWNER_EXPLICIT')),relation_json BLOB NOT NULL,
 owner_key_id TEXT NOT NULL,owner_trust_version INTEGER NOT NULL CHECK(owner_trust_version>0),owner_public_identity BLOB NOT NULL,
 PRIMARY KEY(hub_id,network_id,group_id,endpoint_id,source));
CREATE TRIGGER node_endpoint_group_sources_v1_no_delete BEFORE DELETE ON node_endpoint_group_sources_v1 BEGIN SELECT RAISE(ABORT,'source highwater history is retained');END;
CREATE TABLE node_endpoint_group_required_v1(
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,group_id TEXT NOT NULL,local_endpoint_id TEXT NOT NULL,
 PRIMARY KEY(hub_id,network_id,group_id,local_endpoint_id));
CREATE TRIGGER node_endpoint_group_required_v1_no_update BEFORE UPDATE ON node_endpoint_group_required_v1 BEGIN SELECT RAISE(ABORT,'Owner control marker is permanent');END;
CREATE TRIGGER node_endpoint_group_required_v1_no_delete BEFORE DELETE ON node_endpoint_group_required_v1 BEGIN SELECT RAISE(ABORT,'Owner control marker is permanent');END;
CREATE TABLE node_endpoint_group_peer_bindings_v1(
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,local_endpoint_id TEXT NOT NULL,group_id TEXT NOT NULL,peer_endpoint_id TEXT NOT NULL,
 authority_json BLOB NOT NULL,pin_version INTEGER NOT NULL CHECK(pin_version>0),
 PRIMARY KEY(hub_id,network_id,local_endpoint_id,group_id,peer_endpoint_id));
CREATE TRIGGER node_endpoint_group_peer_bindings_v1_no_delete BEFORE DELETE ON node_endpoint_group_peer_bindings_v1 BEGIN SELECT RAISE(ABORT,'managed peer authority history is retained');END;
`)
	return err
}

type endpointGroupsQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type endpointGroupPolicyRecord struct {
	Policy e2ee.EndpointGroupPolicy
	Proof  []byte
	Hub    wire.HubIdentity
}

func endpointGroupsPolicyTrust(ctx context.Context, q endpointGroupsQuery, p endpointGroupPolicyRecord, now time.Time) (*OwnerKeyTrust, error) {
	if now.IsZero() {
		return nil, ErrEndpointGroupsPolicy
	}
	trust, err := loadNodeOwnerKeyTrust(ctx, q, p.Policy.OwnerID, p.Policy.OwnerPublic.ID)
	if err != nil || trust.State != NodeOwnerKeyTrustActive || !samePublicIdentity(trust.PublicIdentity, p.Policy.OwnerPublic) {
		return nil, ErrEndpointGroupsPolicy
	}
	policy, err := e2ee.VerifyOwnerEndpointGroupPolicy(trust.PublicIdentity, p.Proof, now)
	if err != nil || !reflect.DeepEqual(policy, p.Policy) || wire.ValidateOwnerEndpointGroupsPolicy(policy, p.Hub, now) != nil {
		return nil, ErrEndpointGroupsPolicy
	}
	return trust, nil
}

// A valid pending policy is retained without taking over the default source.
// Only observed OWNER control installs the permanent downgrade marker.
func (s *CryptoState) RequireEndpointGroupPolicy(ctx context.Context, hub wire.HubIdentity, expected e2ee.EndpointGroupPolicy, proof []byte, now time.Time) error {
	if ctx == nil || now.IsZero() || wire.ValidateOwnerEndpointGroupsPolicy(expected, hub, now) != nil || len(proof) == 0 || len(proof) > e2ee.MaxEndpointGroupProofBytes {
		return ErrEndpointGroupsPolicy
	}
	p := endpointGroupPolicyRecord{expected, bytes.Clone(proof), hub}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		if _, err := endpointGroupsPolicyTrust(ctx, conn, p, now); err != nil {
			return err
		}
		return rememberEndpointGroupPolicy(ctx, conn, p)
	})
}

func rememberEndpointGroupPolicy(ctx context.Context, conn *sql.Conn, p endpointGroupPolicyRecord) error {
	raw, err := json.Marshal(p.Policy)
	if err != nil {
		return err
	}
	hub, err := json.Marshal(p.Hub)
	if err != nil {
		return err
	}
	var oldPolicy, oldProof, oldHub []byte
	err = conn.QueryRowContext(ctx, `SELECT policy_json,policy_proof,hub_identity FROM node_endpoint_group_policies_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=? AND policy_id=?`, p.Policy.HubID, p.Policy.NetworkID, p.Policy.GroupID, p.Policy.EndpointID, p.Policy.PolicyID).Scan(&oldPolicy, &oldProof, &oldHub)
	if err == nil {
		if !bytes.Equal(raw, oldPolicy) || !bytes.Equal(p.Proof, oldProof) || !bytes.Equal(hub, oldHub) {
			return ErrEndpointGroupsConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_policies_v1 VALUES(?,?,?,?,?,?,?,?)`, p.Policy.HubID, p.Policy.NetworkID, p.Policy.GroupID, p.Policy.EndpointID, p.Policy.PolicyID, raw, p.Proof, hub)
	return err
}

func endpointGroupsRequired(ctx context.Context, q endpointGroupsQuery, local, group string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM node_endpoint_group_required_v1 WHERE local_endpoint_id=? AND group_id=?`, local, group).Scan(&n)
	return n > 0, err
}

func (s *CryptoState) EndpointGroupsRequired(ctx context.Context, local, group string) (bool, error) {
	if ctx == nil || validateEndpointID(local) != nil || validateCryptoToken("Group", group) != nil {
		return true, ErrEndpointGroupsPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return true, err
	}
	return endpointGroupsRequired(ctx, s.db, local, group)
}

func compareEndpointGroupHead(old, next e2ee.EndpointGroupOwnerControl) error {
	if e2ee.ValidateEndpointGroupOwnerControl(old) != nil || e2ee.ValidateEndpointGroupOwnerControl(next) != nil || next.Revision < old.Revision ||
		old.Mode == "OWNER" && next.Mode != "OWNER" || next.Revision == old.Revision && old != next {
		return ErrEndpointGroupsConflict
	}
	return nil
}

func compareEndpointGroupRelation(old, next wire.EndpointGroupRelation, oldHead, nextHead e2ee.EndpointGroupOwnerControl) error {
	if old.HubID != next.HubID || old.OwnerID != next.OwnerID || old.NodeID != next.NodeID || old.LocalUserScope != next.LocalUserScope || old.NetworkID != next.NetworkID || old.GroupID != next.GroupID || old.EndpointID != next.EndpointID || old.PrincipalID != next.PrincipalID ||
		old.RegistrationDigest != next.RegistrationDigest || next.RegistrationRevision < old.RegistrationRevision || old.CandidateKeyID != next.CandidateKeyID || old.CandidateFingerprint != next.CandidateFingerprint || next.BindingEpoch < old.BindingEpoch {
		return ErrEndpointGroupsConflict
	}
	if next.BindingEpoch == old.BindingEpoch && (next.BindingID != old.BindingID || next.CandidateProofDigest != old.CandidateProofDigest || next.CandidateVersion != old.CandidateVersion) {
		return ErrEndpointGroupsConflict
	}
	if next.BindingEpoch > old.BindingEpoch && (next.Source != "OWNER_EXPLICIT" || nextHead.Mode != "OWNER" || nextHead.Revision <= oldHead.Revision || next.RegistrationRevision <= old.RegistrationRevision) {
		return ErrEndpointGroupsConflict
	}
	if old.Source != next.Source {
		return nil
	}
	// Each immutable authority owns its contribution counter. A newly signed
	// Owner policy starts a fresh counter only after its higher Endpoint head
	// and epoch have independently passed the caller's proof/current checks.
	if next.AuthorityID != old.AuthorityID {
		if next.AuthorityEpoch <= old.AuthorityEpoch || nextHead.Mode != "OWNER" || nextHead.Revision <= oldHead.Revision {
			return ErrEndpointGroupsConflict
		}
		return nil
	}
	if next.AuthorityEpoch != old.AuthorityEpoch || next.ContributionRevision < old.ContributionRevision {
		return ErrEndpointGroupsConflict
	}
	if next.ContributionRevision == old.ContributionRevision && !reflect.DeepEqual(old, next) {
		return ErrEndpointGroupsConflict
	}
	return nil
}

func endpointGroupSnapshotNotOlder(ctx context.Context, q endpointGroupsQuery, snap wire.EndpointGroupCurrentEndpoint) error {
	r := snap.Relation
	var oldHeadRaw, identityRaw []byte
	var oldDigest string
	err := q.QueryRowContext(ctx, `SELECT head_json,head_digest,identity_json FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID).Scan(&oldHeadRaw, &oldDigest, &identityRaw)
	oldHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	if err == nil {
		var previous wire.EndpointGroupRelation
		if json.Unmarshal(oldHeadRaw, &oldHead) != nil || json.Unmarshal(identityRaw, &previous) != nil || compareEndpointGroupHead(oldHead, snap.OwnerControl) != nil || compareEndpointGroupRelation(previous, r, oldHead, snap.OwnerControl) != nil || oldHead.Revision == snap.OwnerControl.Revision && oldDigest != r.OwnerControlDigest {
			return ErrEndpointGroupsConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var oldRelationRaw []byte
	err = q.QueryRowContext(ctx, `SELECT relation_json FROM node_endpoint_group_sources_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=? AND source=?`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID, r.Source).Scan(&oldRelationRaw)
	if err == nil {
		var old wire.EndpointGroupRelation
		if json.Unmarshal(oldRelationRaw, &old) != nil || compareEndpointGroupRelation(old, r, oldHead, snap.OwnerControl) != nil {
			return ErrEndpointGroupsConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func rememberEndpointGroupSnapshot(ctx context.Context, conn *sql.Conn, snap wire.EndpointGroupCurrentEndpoint, trust OwnerKeyTrust) error {
	if trust.State != NodeOwnerKeyTrustActive || trust.OwnerID != snap.Relation.OwnerID || trust.Version <= 0 {
		return ErrEndpointGroupsPolicy
	}
	if err := endpointGroupSnapshotNotOlder(ctx, conn, snap); err != nil {
		return err
	}
	r := snap.Relation
	head, err := json.Marshal(snap.OwnerControl)
	if err != nil {
		return err
	}
	relation, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_heads_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(hub_id,network_id,group_id,endpoint_id) DO UPDATE SET head_json=excluded.head_json,head_digest=excluded.head_digest,identity_json=excluded.identity_json`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID, head, r.OwnerControlDigest, relation); err != nil {
		return err
	}
	public, err := json.Marshal(trust.PublicIdentity)
	if err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_sources_v1 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(hub_id,network_id,group_id,endpoint_id,source) DO UPDATE SET relation_json=excluded.relation_json,owner_key_id=excluded.owner_key_id,owner_trust_version=excluded.owner_trust_version,owner_public_identity=excluded.owner_public_identity`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID, r.Source, relation, trust.KeyID, trust.Version, public)
	return err
}

func rememberEndpointGroupsRequired(ctx context.Context, conn *sql.Conn, r wire.EndpointGroupRelation) error {
	_, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO node_endpoint_group_required_v1 VALUES(?,?,?,?)`, r.HubID, r.NetworkID, r.GroupID, r.EndpointID)
	return err
}
