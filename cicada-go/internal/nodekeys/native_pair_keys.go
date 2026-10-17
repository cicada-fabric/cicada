package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// NativePairOriginalLocalKey identifies the original key even if its private
// file later disappears. A caller must LoadExisting once this marker exists.
func (s *CryptoState) NativePairOriginalLocalKey(ctx context.Context, endpointID string) (e2ee.PublicIdentity, error) {
	var public e2ee.PublicIdentity
	if ctx == nil || validateEndpointID(endpointID) != nil {
		return public, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return public, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT public_identity FROM node_native_pair_local_keys WHERE endpoint_id=?`, endpointID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return public, ErrCryptoStateNotFound
	}
	if err != nil {
		return public, err
	}
	if json.Unmarshal(raw, &public) != nil || e2ee.ValidatePublicIdentity(public) != nil {
		return public, ErrNativePairPolicy
	}
	return public, nil
}

// NativePairLocalAttestation returns the exact original publication target and
// bytes. Version zero means durable publication pending, not CandidateReady.
func (s *CryptoState) NativePairLocalAttestation(ctx context.Context, pairID, endpointID, bindingID string, epoch uint64) (GroupEndpointKeyCandidate, error) {
	var out GroupEndpointKeyCandidate
	if ctx == nil {
		return out, ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return out, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	return loadNativePairAttestation(ctx, conn, pairID, endpointID, bindingID, epoch)
}

func loadNativePairAttestation(ctx context.Context, conn *sql.Conn, pairID, endpointID, bindingID string, epoch uint64) (GroupEndpointKeyCandidate, error) {
	var c GroupEndpointKeyCandidate
	var raw []byte
	err := conn.QueryRowContext(ctx, `SELECT a.endpoint_id,a.group_id,a.principal_id,a.node_id,a.owner_id,a.binding_id,a.binding_epoch,a.fingerprint,a.proof_digest,a.proof,a.candidate_version,k.key_id,k.public_identity FROM node_native_pair_attestations a JOIN node_native_pair_local_keys k ON k.endpoint_id=a.endpoint_id WHERE a.pair_id=? AND a.endpoint_id=? AND a.binding_id=? AND a.binding_epoch=?`, pairID, endpointID, bindingID, epoch).Scan(&c.EndpointID, &c.GroupID, &c.PrincipalID, &c.NodeID, &c.OwnerID, &c.BindingID, &c.BindingEpoch, &c.KeyFingerprint, &c.ProofDigest, &c.Attestation, &c.CandidateVersion, &c.KeyID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrCryptoStateNotFound
	}
	if err != nil {
		return c, err
	}
	if json.Unmarshal(raw, &c.PublicIdentity) != nil || validateNativePairLocalCandidate(c) != nil {
		return c, ErrNativePairPolicy
	}
	return c, nil
}

func validateNativePairLocalCandidate(c GroupEndpointKeyCandidate) error {
	for _, v := range []string{c.EndpointID, c.GroupID, c.PrincipalID, c.NodeID, c.OwnerID, c.BindingID} {
		if validateCryptoToken("Pair candidate scope", v) != nil {
			return ErrNativePairPolicy
		}
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(c.Attestation, c.EndpointID, c.PrincipalID, c.NodeID, c.BindingID, c.BindingEpoch)
	fp, fpErr := PeerKeyFingerprint(c.PublicIdentity)
	hash := sha256.Sum256(c.Attestation)
	if err != nil || fpErr != nil || !samePublicIdentity(verified, c.PublicIdentity) || c.KeyID != c.PublicIdentity.ID || fp != c.KeyFingerprint || c.ProofDigest != hex.EncodeToString(hash[:]) {
		return ErrNativePairPolicy
	}
	return nil
}

// RememberNativePairLocalAttestation commits original public identity and exact
// signed publication bytes together before POST. It never stores a private key.
func (s *CryptoState) RememberNativePairLocalAttestation(ctx context.Context, pairID string, c GroupEndpointKeyCandidate) error {
	if ctx == nil || c.CandidateVersion != 0 || validateNativePairLocalCandidate(c) != nil {
		return ErrNativePairPolicy
	}
	public, err := json.Marshal(c.PublicIdentity)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		p, err := loadNativePairPolicy(ctx, conn, pairID)
		if err != nil || p.GroupID != c.GroupID || p.NodeID != c.NodeID {
			return ErrNativePairPolicy
		}
		var ownerProof e2ee.OwnerNativePairProof
		if json.Unmarshal(p.BootstrapProof, &ownerProof) != nil || ownerProof.Claims.Scope.Actor.OwnerID != c.OwnerID {
			return ErrNativePairPolicy
		}
		trust, err := loadNodeOwnerKeyTrust(ctx, conn, c.OwnerID, ownerProof.Claims.Scope.Actor.OwnerPublic.ID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive {
			return ErrNativePairPolicy
		}
		var original []byte
		err = conn.QueryRowContext(ctx, `SELECT public_identity FROM node_native_pair_local_keys WHERE endpoint_id=?`, c.EndpointID).Scan(&original)
		if err == nil {
			if !bytes.Equal(original, public) {
				return ErrNativePairConflict
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			if _, err := conn.ExecContext(ctx, `INSERT INTO node_native_pair_local_keys VALUES(?,?,?)`, c.EndpointID, c.KeyID, public); err != nil {
				return err
			}
		} else {
			return err
		}
		old, err := loadNativePairAttestation(ctx, conn, pairID, c.EndpointID, c.BindingID, c.BindingEpoch)
		if err == nil {
			old.CandidateVersion = 0
			if !reflect.DeepEqual(old, c) {
				return ErrNativePairConflict
			}
			return nil
		}
		if !errors.Is(err, ErrCryptoStateNotFound) {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO node_native_pair_attestations(pair_id,endpoint_id,group_id,principal_id,node_id,owner_id,binding_id,binding_epoch,fingerprint,proof_digest,proof) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, pairID, c.EndpointID, c.GroupID, c.PrincipalID, c.NodeID, c.OwnerID, c.BindingID, c.BindingEpoch, c.KeyFingerprint, c.ProofDigest, c.Attestation)
		return err
	})
}

// ConfirmNativePairLocalCandidate follows authenticated current Hub acceptance
// and full target comparison. An absent acknowledgement leaves version zero.
func (s *CryptoState) ConfirmNativePairLocalCandidate(ctx context.Context, pairID string, c GroupEndpointKeyCandidate) error {
	if ctx == nil || c.CandidateVersion <= 0 || validateNativePairLocalCandidate(c) != nil {
		return ErrNativePairPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.writeTx(ctx, func(conn *sql.Conn) error {
		old, err := loadNativePairAttestation(ctx, conn, pairID, c.EndpointID, c.BindingID, c.BindingEpoch)
		if err != nil {
			return err
		}
		if old.CandidateVersion != 0 && old.CandidateVersion != c.CandidateVersion {
			return ErrNativePairConflict
		}
		old.CandidateVersion = c.CandidateVersion
		if !reflect.DeepEqual(old, c) {
			return ErrNativePairConflict
		}
		_, err = conn.ExecContext(ctx, `UPDATE node_native_pair_attestations SET candidate_version=? WHERE pair_id=? AND endpoint_id=? AND binding_id=? AND binding_epoch=?`, c.CandidateVersion, pairID, c.EndpointID, c.BindingID, c.BindingEpoch)
		return err
	})
}
