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

// A new domain grant may advance the same trusted Endpoint key to a newer
// binding. It never revives a revoked peer pin or replaces the key identity.
// Both delegated chains, required marker, member highwater and independent
// Owner pin are rechecked under this same SQLite writer transaction.
func (s *CryptoState) PinLocalDomainPeer(ctx context.Context, local string, sender, receiver wire.LocalDomainEndpointKeyGrant, current wire.LocalDomainCurrent, operation, attempt string, now time.Time) (*PeerKeyPin, error) {
	if ctx == nil || now.IsZero() {
		return nil, ErrLocalDomainPolicy
	}
	group := sender.Manifest.GroupID
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var result *PeerKeyPin
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadLocalDomainPolicy(ctx, conn, group)
		if err != nil {
			return ErrLocalDomainPolicy
		}
		trust, err := localDomainTrust(ctx, conn, *p, now)
		if err != nil {
			return err
		}
		if wire.ValidateLocalDomainCurrent(current, p.Policy, sender.Member, receiver.Member, operation, attempt, now) != nil {
			return ErrLocalDomainPolicy
		}
		for _, g := range []wire.LocalDomainEndpointKeyGrant{sender, receiver} {
			policy, e := wire.VerifyLocalDomainEndpointKeyGrant(g, p.Hub, p.Policy.OwnerID, trust.PublicIdentity, now)
			if e != nil || !reflect.DeepEqual(policy, p.Policy) || !bytes.Equal(g.PolicyProof, p.Proof) {
				return ErrLocalDomainPolicy
			}
			if e = rememberLocalDomainMember(ctx, conn, group, g); e != nil {
				return e
			}
		}
		peer, own := receiver, sender
		if local == receiver.Member.EndpointID {
			peer, own = sender, receiver
		} else if local != sender.Member.EndpointID {
			return ErrLocalDomainPolicy
		}
		k := peer.Manifest
		scope := PeerPinScope{LocalEndpointID: local, LocalGroupID: group, PeerEndpointID: k.EndpointID, PeerGroupID: group}
		expected := PeerPinIdentity{EndpointID: k.EndpointID, GroupID: group, PrincipalID: k.PrincipalID, OwnerID: k.OwnerID}
		if own.Manifest.GroupID != group || validatePeerPinRequest(scope, expected) != nil {
			return ErrLocalDomainPolicy
		}
		pin, err := loadPeerPin(ctx, conn, scope)
		stamp := now.UTC().Format(time.RFC3339Nano)
		if err == nil {
			if pin.RevokedAt != "" {
				return ErrPeerPinRevoked
			}
			if !samePeerIdentity(pin.Peer, expected) || pin.KeyID != k.CandidateKeyID || pin.Fingerprint != k.CandidateFingerprint || !samePublicIdentity(pin.Public, k.CandidatePublicIdentity) || pin.NodeID != k.NodeID || pin.BindingEpoch > k.BindingEpoch {
				return ErrPeerPinConflict
			}
			if pin.BindingEpoch == k.BindingEpoch && (pin.BindingID != k.BindingID || pin.AttestationDigest != k.CandidateProofDigest) {
				return ErrPeerPinConflict
			}
			if pin.BindingEpoch < k.BindingEpoch {
				_, err = conn.ExecContext(ctx, `UPDATE node_crypto_peer_pins SET binding_id=?,binding_epoch=?,attestation_digest=?,version=version+1,updated_at=? WHERE local_endpoint_id=? AND local_group_id=? AND peer_endpoint_id=? AND peer_group_id=? AND communication_link_id='' AND revoked_at='' AND version=?`, k.BindingID, k.BindingEpoch, k.CandidateProofDigest, stamp, local, group, k.EndpointID, group, pin.Version)
				if err != nil {
					return err
				}
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			public, e := json.Marshal(k.CandidatePublicIdentity)
			if e != nil {
				return e
			}
			_, err = conn.ExecContext(ctx, `INSERT INTO node_crypto_peer_pins(local_endpoint_id,local_group_id,peer_endpoint_id,peer_group_id,communication_link_id,peer_principal_id,peer_owner_id,peer_key_id,peer_fingerprint,public_identity_json,peer_node_id,binding_id,binding_epoch,attestation_digest,version,created_at,updated_at,revoked_at) VALUES(?,?,?,?,'',?,?,?,?,?,?,?,?,?,1,?,?,'')`, local, group, k.EndpointID, group, k.PrincipalID, k.OwnerID, k.CandidateKeyID, k.CandidateFingerprint, string(public), k.NodeID, k.BindingID, k.BindingEpoch, k.CandidateProofDigest, stamp, stamp)
			if err != nil {
				return err
			}
		} else {
			return err
		}
		result, err = loadPeerPin(ctx, conn, scope)
		return err
	})
	return result, err
}

func rememberLocalDomainMember(ctx context.Context, conn *sql.Conn, group string, g wire.LocalDomainEndpointKeyGrant) error {
	var oldRaw, oldGrant []byte
	err := conn.QueryRowContext(ctx, `SELECT member_json,grant_json FROM node_local_domain_members_v1 WHERE group_id=? AND endpoint_id=?`, group, g.Member.EndpointID).Scan(&oldRaw, &oldGrant)
	raw, e := json.Marshal(g.Member)
	if e != nil {
		return e
	}
	grant, e := json.Marshal(g)
	if e != nil {
		return e
	}
	if err == nil {
		var old wire.LocalDomainMember
		if json.Unmarshal(oldRaw, &old) != nil {
			return ErrLocalDomainPolicy
		}
		if e = compareLocalDomainMember(old, g.Member); e != nil {
			return e
		}
		if old == g.Member && !bytes.Equal(oldGrant, grant) {
			return ErrLocalDomainConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO node_local_domain_members_v1 VALUES(?,?,?,?) ON CONFLICT(group_id,endpoint_id) DO UPDATE SET member_json=excluded.member_json,grant_json=excluded.grant_json`, group, g.Member.EndpointID, raw, grant)
	return err
}

func (s *CryptoState) RememberLocalDomainGrant(ctx context.Context, g wire.LocalDomainEndpointKeyGrant, now time.Time) error {
	if ctx == nil || now.IsZero() {
		return ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadLocalDomainPolicy(ctx, conn, g.Manifest.GroupID)
		if err != nil {
			return ErrLocalDomainPolicy
		}
		trust, err := localDomainTrust(ctx, conn, *p, now)
		if err != nil {
			return err
		}
		policy, err := wire.VerifyLocalDomainEndpointKeyGrant(g, p.Hub, p.Policy.OwnerID, trust.PublicIdentity, now)
		if err != nil || !reflect.DeepEqual(policy, p.Policy) || !bytes.Equal(g.PolicyProof, p.Proof) {
			return ErrLocalDomainPolicy
		}
		return rememberLocalDomainMember(ctx, conn, p.Policy.GroupID, g)
	})
}

func (s *CryptoState) LocalDomainOriginalLocalKey(ctx context.Context, endpoint string) (e2ee.PublicIdentity, error) {
	var pub e2ee.PublicIdentity
	if ctx == nil || validateEndpointID(endpoint) != nil {
		return pub, ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return pub, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT public_identity FROM node_local_domain_local_keys_v1 WHERE endpoint_id=?`, endpoint).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// Explicit rejoin after an old Pair must preserve its original key too.
		err = s.db.QueryRowContext(ctx, `SELECT public_identity FROM node_native_pair_local_keys WHERE endpoint_id=?`, endpoint).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return pub, ErrCryptoStateNotFound
	}
	if err != nil {
		return pub, err
	}
	if json.Unmarshal(raw, &pub) != nil || e2ee.ValidatePublicIdentity(pub) != nil {
		return pub, ErrLocalDomainPolicy
	}
	return pub, nil
}

func (s *CryptoState) LocalDomainLocalAttestation(ctx context.Context, endpoint, binding string, epoch uint64) (GroupEndpointKeyCandidate, error) {
	var c GroupEndpointKeyCandidate
	if ctx == nil {
		return c, ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return c, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT candidate_json FROM node_local_domain_attestations_v1 WHERE endpoint_id=? AND binding_id=? AND binding_epoch=?`, endpoint, binding, epoch).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrCryptoStateNotFound
	}
	if err != nil {
		return c, err
	}
	if json.Unmarshal(raw, &c) != nil || validateNativePairLocalCandidate(c) != nil {
		return c, ErrLocalDomainPolicy
	}
	return c, nil
}

func (s *CryptoState) RememberLocalDomainLocalAttestation(ctx context.Context, policy string, c GroupEndpointKeyCandidate, now time.Time) error {
	if ctx == nil || now.IsZero() || c.CandidateVersion != 0 || validateNativePairLocalCandidate(c) != nil {
		return ErrLocalDomainPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadLocalDomainPolicy(ctx, conn, c.GroupID)
		if err != nil || p.Policy.PolicyID != policy || p.Policy.Node.NodeID != c.NodeID || p.Policy.OwnerID != c.OwnerID {
			return ErrLocalDomainPolicy
		}
		if _, err = localDomainTrust(ctx, conn, *p, now); err != nil {
			return err
		}
		for _, table := range []string{"node_local_domain_attestations_v1", "node_native_pair_attestations"} {
			var binding string
			var epoch uint64
			err = conn.QueryRowContext(ctx, `SELECT binding_id,binding_epoch FROM `+table+` WHERE endpoint_id=? ORDER BY binding_epoch DESC LIMIT 1`, c.EndpointID).Scan(&binding, &epoch)
			if err == nil && (c.BindingEpoch < epoch || (c.BindingEpoch == epoch && c.BindingID != binding)) {
				return ErrLocalDomainConflict
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		public, err := json.Marshal(c.PublicIdentity)
		if err != nil {
			return err
		}
		for _, table := range []string{"node_local_domain_local_keys_v1", "node_native_pair_local_keys"} {
			var old []byte
			err = conn.QueryRowContext(ctx, `SELECT public_identity FROM `+table+` WHERE endpoint_id=?`, c.EndpointID).Scan(&old)
			if err == nil && !bytes.Equal(old, public) {
				return ErrLocalDomainConflict
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if _, err = conn.ExecContext(ctx, `INSERT OR IGNORE INTO node_local_domain_local_keys_v1 VALUES(?,?,?)`, c.EndpointID, c.KeyID, public); err != nil {
			return err
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		var old []byte
		err = conn.QueryRowContext(ctx, `SELECT candidate_json FROM node_local_domain_attestations_v1 WHERE endpoint_id=? AND binding_id=? AND binding_epoch=?`, c.EndpointID, c.BindingID, c.BindingEpoch).Scan(&old)
		if err == nil {
			if !bytes.Equal(old, raw) {
				return ErrLocalDomainConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_local_domain_attestations_v1 VALUES(?,?,?,?,?)`, policy, c.EndpointID, c.BindingID, c.BindingEpoch, raw)
		return err
	})
}
