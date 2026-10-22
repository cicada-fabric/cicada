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

var ErrLocalDomainPolicy = errors.New("Node local collaboration policy requires the original independent Owner trust and exact scope")
var ErrLocalDomainConflict = errors.New("Node local collaboration evidence conflicts with retained identity or epoch")

func initializeLocalDomainSchema(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
CREATE TABLE node_local_domain_policies_v1(policy_id TEXT PRIMARY KEY,group_id TEXT NOT NULL UNIQUE,policy_json BLOB NOT NULL,policy_proof BLOB NOT NULL,hub_identity BLOB NOT NULL);
CREATE TRIGGER node_local_domain_policies_v1_no_update BEFORE UPDATE ON node_local_domain_policies_v1 BEGIN SELECT RAISE(ABORT,'local domain original policy is immutable');END;
CREATE TRIGGER node_local_domain_policies_v1_no_delete BEFORE DELETE ON node_local_domain_policies_v1 BEGIN SELECT RAISE(ABORT,'local domain required marker is retained');END;
CREATE TABLE node_local_domain_members_v1(group_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,member_json BLOB NOT NULL,grant_json BLOB NOT NULL,PRIMARY KEY(group_id,endpoint_id));
CREATE TABLE node_local_domain_local_keys_v1(endpoint_id TEXT PRIMARY KEY,key_id TEXT NOT NULL,public_identity BLOB NOT NULL);
CREATE TABLE node_local_domain_attestations_v1(policy_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,binding_id TEXT NOT NULL,binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),candidate_json BLOB NOT NULL,PRIMARY KEY(endpoint_id,binding_id,binding_epoch));
CREATE TRIGGER node_local_domain_local_keys_v1_no_update BEFORE UPDATE ON node_local_domain_local_keys_v1 BEGIN SELECT RAISE(ABORT,'local domain Endpoint key cannot be replaced');END;
CREATE TRIGGER node_local_domain_local_keys_v1_no_delete BEFORE DELETE ON node_local_domain_local_keys_v1 BEGIN SELECT RAISE(ABORT,'local domain Endpoint key history is retained');END;
`)
	return err
}

type LocalDomainPolicy struct {
	Policy e2ee.LocalDomainPolicy
	Proof  []byte
	Hub    wire.HubIdentity
}

func loadLocalDomainPolicy(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, group string) (*LocalDomainPolicy, error) {
	var p LocalDomainPolicy
	var raw, hub []byte
	var id string
	err := q.QueryRowContext(ctx, `SELECT policy_id,policy_json,policy_proof,hub_identity FROM node_local_domain_policies_v1 WHERE group_id=?`, group).Scan(&id, &raw, &p.Proof, &hub)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &p.Policy) != nil || json.Unmarshal(hub, &p.Hub) != nil || p.Policy.PolicyID != id || p.Policy.GroupID != group || wire.ValidateLocalDomainPolicy(p.Policy, p.Hub, time.Time{}) != nil {
		return nil, ErrLocalDomainPolicy
	}
	return &p, nil
}

func localDomainTrust(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, p LocalDomainPolicy, now time.Time) (*OwnerKeyTrust, error) {
	trust, err := loadNodeOwnerKeyTrust(ctx, q, p.Policy.OwnerID, p.Policy.OwnerPublic.ID)
	if err != nil || trust.State != NodeOwnerKeyTrustActive || !samePublicIdentity(trust.PublicIdentity, p.Policy.OwnerPublic) {
		return nil, ErrLocalDomainPolicy
	}
	policy, err := e2ee.VerifyOwnerLocalDomainPolicy(trust.PublicIdentity, p.Proof, now)
	if err != nil || !reflect.DeepEqual(policy, p.Policy) || wire.ValidateLocalDomainPolicy(policy, p.Hub, now) != nil {
		return nil, ErrLocalDomainPolicy
	}
	return trust, nil
}

// expected is a complete policy independently matched to the actual local
// Node, original credential and Hub pins by the agent. A policy response never
// installs an Owner pin. The existing pin is checked in this same writer Tx.
func (s *CryptoState) RequireLocalDomainPolicy(ctx context.Context, hub wire.HubIdentity, expected e2ee.LocalDomainPolicy, proof []byte, now time.Time) (*LocalDomainPolicy, error) {
	if ctx == nil || now.IsZero() || wire.ValidateLocalDomainPolicy(expected, hub, now) != nil || len(proof) == 0 || len(proof) > e2ee.MaxLocalDomainProofBytes {
		return nil, ErrLocalDomainPolicy
	}
	p := &LocalDomainPolicy{Policy: expected, Proof: bytes.Clone(proof), Hub: hub}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		if _, err := localDomainTrust(ctx, conn, *p, now); err != nil {
			return err
		}
		old, err := loadLocalDomainPolicy(ctx, conn, expected.GroupID)
		if err == nil {
			if !reflect.DeepEqual(*old, *p) {
				return ErrLocalDomainConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// A Group may never silently switch between explicit Pair and domain.
		var count int
		if conn.QueryRowContext(ctx, `SELECT count(*) FROM node_native_pair_policies WHERE group_id=?`, expected.GroupID).Scan(&count) != nil || count != 0 {
			return ErrLocalDomainConflict
		}
		raw, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		hubJSON, err := json.Marshal(hub)
		if err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_local_domain_policies_v1 VALUES(?,?,?,?,?)`, expected.PolicyID, expected.GroupID, raw, proof, hubJSON)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Historical metadata is readable without renewing authority. Callers which
// issue context or perform work must use CheckLocalDomainPolicy with now.
func (s *CryptoState) LocalDomainPolicyForGroup(ctx context.Context, group string) (*LocalDomainPolicy, error) {
	if ctx == nil {
		return nil, ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	p, err := loadLocalDomainPolicy(ctx, s.db, group)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCryptoStateNotFound
	}
	return p, err
}

func (s *CryptoState) CheckLocalDomainPolicy(ctx context.Context, p LocalDomainPolicy, now time.Time) error {
	if ctx == nil || now.IsZero() {
		return ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	old, err := loadLocalDomainPolicy(ctx, s.db, p.Policy.GroupID)
	if err != nil || !reflect.DeepEqual(*old, p) {
		return ErrLocalDomainPolicy
	}
	_, err = localDomainTrust(ctx, s.db, p, now)
	return err
}

func (s *CryptoState) LocalDomainPolicyRequired(ctx context.Context, group string) (bool, error) {
	if ctx == nil || validateCryptoToken("Group", group) != nil {
		return false, ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM node_local_domain_policies_v1 WHERE group_id=?`, group).Scan(&n)
	return n == 1, err
}

// Full cryptographic chain plus exact, fresh Hub observation. The persisted
// marker decides whether omission is a downgrade. Current never authorizes a
// different operation/attempt and its 30-second bound is not a reusable lease.
func (s *CryptoState) VerifyLocalDomainGroupAuthorization(ctx context.Context, group string, sender, receiver *wire.LocalDomainEndpointKeyGrant, current *wire.LocalDomainCurrent, operation, attempt string, now time.Time) (bool, error) {
	if ctx == nil || now.IsZero() {
		return true, ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return true, err
	}
	p, err := loadLocalDomainPolicy(ctx, s.db, group)
	if errors.Is(err, sql.ErrNoRows) {
		if sender == nil && receiver == nil && current == nil {
			return false, nil
		}
		return true, ErrLocalDomainPolicy
	}
	if err != nil {
		return true, err
	}
	if sender == nil || receiver == nil || current == nil {
		return true, ErrLocalDomainPolicy
	}
	trust, err := localDomainTrust(ctx, s.db, *p, now)
	if err != nil {
		return true, err
	}
	for _, g := range []*wire.LocalDomainEndpointKeyGrant{sender, receiver} {
		policy, e := wire.VerifyLocalDomainEndpointKeyGrant(*g, p.Hub, p.Policy.OwnerID, trust.PublicIdentity, now)
		if e != nil || !reflect.DeepEqual(policy, p.Policy) || !bytes.Equal(g.PolicyProof, p.Proof) {
			return true, ErrLocalDomainPolicy
		}
		if err := localDomainMemberNotOlder(ctx, s.db, p.Policy.GroupID, g.Member); err != nil {
			return true, err
		}
	}
	if wire.ValidateLocalDomainCurrent(*current, p.Policy, sender.Member, receiver.Member, operation, attempt, now) != nil {
		return true, ErrLocalDomainPolicy
	}
	return true, nil
}

func localDomainMemberNotOlder(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, group string, m wire.LocalDomainMember) error {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT member_json FROM node_local_domain_members_v1 WHERE group_id=? AND endpoint_id=?`, group, m.EndpointID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var old wire.LocalDomainMember
	if json.Unmarshal(raw, &old) != nil {
		return ErrLocalDomainPolicy
	}
	return compareLocalDomainMember(old, m)
}

func compareLocalDomainMember(old, m wire.LocalDomainMember) error {
	if old.Selection != m.Selection || old.EndpointID != m.EndpointID || old.PrincipalID != m.PrincipalID || old.NodeID != m.NodeID || old.NativeSessionID != m.NativeSessionID || old.Runtime != m.Runtime || old.Workspace != m.Workspace || old.LocalUserScope != m.LocalUserScope || m.BindingEpoch < old.BindingEpoch {
		return ErrLocalDomainConflict
	}
	if m.BindingEpoch == old.BindingEpoch && (m.MemberID != old.MemberID || m.BindingID != old.BindingID || m.NetworkAccessBindingID != old.NetworkAccessBindingID || m.NetworkAccessEpoch != old.NetworkAccessEpoch || m.Revision < old.Revision || (m.Revision == old.Revision && m != old)) {
		return ErrLocalDomainConflict
	}
	if m.BindingEpoch > old.BindingEpoch && (m.MemberID == old.MemberID || m.BindingID == old.BindingID || m.NetworkAccessBindingID != old.NetworkAccessBindingID || m.NetworkAccessEpoch <= old.NetworkAccessEpoch || m.CandidateKeyID != old.CandidateKeyID || m.CandidateFingerprint != old.CandidateFingerprint) {
		return ErrLocalDomainConflict
	}
	return nil
}
