package nodekeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	NodeOwnerKeyTrustActive  = "ACTIVE"
	NodeOwnerKeyTrustRevoked = "REVOKED"
)

var (
	ErrNodeOwnerKeyTrustNotFound = errors.New("Node-local owner key trust not found")
	ErrNodeOwnerKeyTrustConflict = errors.New("Node-local owner key trust conflicts with an existing or revoked key")
	ErrNodeOwnerKeyTrustRevoked  = errors.New("Node-local owner key trust is revoked")
)

// TrustOwnerApprovalKeyLocal installs public Owner key trust into this Node's
// private crypto state. expectedPublic and expectedFingerprint must come from
// an independent local trust ceremony or configuration, never the same Hub
// authorization response later supplied to a cross-Group pin operation.
// This operation stores no private key and cannot reactivate a revoked key.
func (s *CryptoState) TrustOwnerApprovalKeyLocal(ownerID, keyID string,
	expectedPublic e2ee.PublicIdentity, expectedFingerprint string) (*OwnerKeyTrust, error) {
	if err := validateCryptoToken("Owner ID", ownerID); err != nil {
		return nil, err
	}
	if err := validateCryptoToken("Owner key ID", keyID); err != nil {
		return nil, err
	}
	if err := e2ee.ValidatePublicIdentity(expectedPublic); err != nil {
		return nil, fmt.Errorf("validate expected Node-local Owner key: %w", err)
	}
	if expectedPublic.ID != keyID {
		return nil, ErrPeerPinOwnerTrustRequired
	}
	if err := validateFingerprint(expectedFingerprint); err != nil {
		return nil, err
	}
	fingerprint, err := PeerKeyFingerprint(expectedPublic)
	if err != nil || fingerprint != expectedFingerprint {
		return nil, ErrPeerPinOwnerTrustRequired
	}
	publicJSON, err := json.Marshal(expectedPublic)
	if err != nil {
		return nil, fmt.Errorf("encode Node-local Owner public key: %w", err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var trust *OwnerKeyTrust
	err = s.writeTx(context.Background(), func(conn *sql.Conn) error {
		current, err := loadNodeOwnerKeyTrust(context.Background(), conn, ownerID, keyID)
		if err == nil {
			if current.State == NodeOwnerKeyTrustRevoked {
				return ErrNodeOwnerKeyTrustRevoked
			}
			if current.ExpectedFingerprint != expectedFingerprint || !samePublicIdentity(current.PublicIdentity, expectedPublic) {
				return ErrNodeOwnerKeyTrustConflict
			}
			trust = current
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := conn.ExecContext(context.Background(), `INSERT INTO node_crypto_owner_key_trust
(owner_id, key_id, public_identity_json, fingerprint, state, version, created_at, updated_at, revoked_at)
VALUES (?, ?, ?, ?, 'ACTIVE', 1, ?, ?, '')`, ownerID, keyID, string(publicJSON), expectedFingerprint,
			timestamp, timestamp); err != nil {
			return fmt.Errorf("persist Node-local Owner key trust: %w", err)
		}
		trust, err = loadNodeOwnerKeyTrust(context.Background(), conn, ownerID, keyID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return trust, nil
}

// GetNodeOwnerKeyTrustLocal returns one locally installed Owner public-key
// trust record. It never falls back to a public key supplied by a Hub.
func (s *CryptoState) GetNodeOwnerKeyTrustLocal(ownerID, keyID string) (*OwnerKeyTrust, error) {
	if err := validateCryptoToken("Owner ID", ownerID); err != nil {
		return nil, err
	}
	if err := validateCryptoToken("Owner key ID", keyID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(context.Background(), conn); err != nil {
		return nil, err
	}
	trust, err := loadNodeOwnerKeyTrust(context.Background(), conn, ownerID, keyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeOwnerKeyTrustNotFound
	}
	return trust, err
}

// RevokeNodeOwnerKeyTrustLocal permanently revokes one Node-local Owner key
// trust after an expected-version check. The tombstone blocks stale Bundle
// replay and key reinstallation under the same identity.
func (s *CryptoState) RevokeNodeOwnerKeyTrustLocal(ownerID, keyID string,
	expectedVersion int64) (*OwnerKeyTrust, error) {
	if err := validateCryptoToken("Owner ID", ownerID); err != nil {
		return nil, err
	}
	if err := validateCryptoToken("Owner key ID", keyID); err != nil {
		return nil, err
	}
	if expectedVersion <= 0 {
		return nil, ErrNodeOwnerKeyTrustNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	var revoked *OwnerKeyTrust
	err := s.writeTx(context.Background(), func(conn *sql.Conn) error {
		current, err := loadNodeOwnerKeyTrust(context.Background(), conn, ownerID, keyID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNodeOwnerKeyTrustNotFound
		}
		if err != nil {
			return err
		}
		if current.State == NodeOwnerKeyTrustRevoked {
			return ErrNodeOwnerKeyTrustRevoked
		}
		if current.Version != expectedVersion {
			return ErrPeerPinVersionConflict
		}
		if current.Version >= maxSQLiteSequence {
			return ErrPeerPinVersionExhausted
		}
		timestamp := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := conn.ExecContext(context.Background(), `UPDATE node_crypto_owner_key_trust
SET state='REVOKED', version=version+1, updated_at=?, revoked_at=?
WHERE owner_id=? AND key_id=? AND version=? AND state='ACTIVE'`,
			timestamp, timestamp, ownerID, keyID, expectedVersion)
		if err != nil {
			return fmt.Errorf("revoke Node-local Owner key trust: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			if err != nil {
				return err
			}
			return ErrPeerPinVersionConflict
		}
		revoked, err = loadNodeOwnerKeyTrust(context.Background(), conn, ownerID, keyID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

func (s *CryptoState) trustedOwnerKeysForBundle(ctx context.Context,
	bundle PeerKeyAuthorizationBundle) (OwnerKeyTrust, OwnerKeyTrust, error) {
	if ctx == nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, errors.New("context is required")
	}
	if bundle.SourceGrant.OwnerID == "" || bundle.SourceGrant.OwnerKeyID == "" ||
		bundle.TargetGrant.OwnerID == "" || bundle.TargetGrant.OwnerKeyID == "" {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, ErrPeerPinOwnerTrustRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, err
	}
	source, err := loadNodeOwnerKeyTrust(ctx, conn, bundle.SourceGrant.OwnerID, bundle.SourceGrant.OwnerKeyID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && source.State != NodeOwnerKeyTrustActive {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, ErrPeerPinOwnerTrustRequired
	}
	if err != nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, err
	}
	target, err := loadNodeOwnerKeyTrust(ctx, conn, bundle.TargetGrant.OwnerID, bundle.TargetGrant.OwnerKeyID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && target.State != NodeOwnerKeyTrustActive {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, ErrPeerPinOwnerTrustRequired
	}
	if err != nil {
		return OwnerKeyTrust{}, OwnerKeyTrust{}, err
	}
	return *source, *target, nil
}

func loadNodeOwnerKeyTrust(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, ownerID, keyID string) (*OwnerKeyTrust, error) {
	var trust OwnerKeyTrust
	var publicJSON string
	err := queryer.QueryRowContext(ctx, `SELECT owner_id, key_id, public_identity_json, fingerprint,
state, version, created_at, updated_at, revoked_at FROM node_crypto_owner_key_trust
WHERE owner_id=? AND key_id=?`, ownerID, keyID).Scan(&trust.OwnerID, &trust.KeyID,
		&publicJSON, &trust.ExpectedFingerprint, &trust.State, &trust.Version,
		&trust.CreatedAt, &trust.UpdatedAt, &trust.RevokedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(publicJSON), &trust.PublicIdentity); err != nil {
		return nil, fmt.Errorf("decode Node-local Owner key trust: %w", err)
	}
	if trust.PublicIdentity.ID != trust.KeyID || trust.Version <= 0 {
		return nil, errors.New("Node-local Owner key trust is internally inconsistent")
	}
	fingerprint, err := PeerKeyFingerprint(trust.PublicIdentity)
	if err != nil || fingerprint != trust.ExpectedFingerprint {
		return nil, errors.New("Node-local Owner key trust fingerprint mismatch")
	}
	return &trust, nil
}

func compareOwnerKeyTrust(expected, current OwnerKeyTrust) bool {
	return expected.OwnerID == current.OwnerID && expected.KeyID == current.KeyID &&
		expected.State == current.State && expected.Version == current.Version &&
		expected.ExpectedFingerprint == current.ExpectedFingerprint &&
		samePublicIdentity(expected.PublicIdentity, current.PublicIdentity)
}
