package store

import (
	"errors"
	"fmt"
)

// EnsureLocalOwnerPrincipal records an independently established local owner
// identity as a Human without creating any Group or Endpoint membership. The
// caller must verify the owner/key association through a trusted local path.
// Existing principals are never updated: in particular, a revoked owner must not be
// reactivated by a process restart.
func (s *Store) EnsureLocalOwnerPrincipal(identityID string) error {
	if err := validateOwnerApprovalID(identityID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := now()
	_, err := s.db.Exec(`INSERT OR IGNORE INTO principals
(id, kind, owner_id, trust_domain_id, name, display_name, status, credential_hash, version, created_at, updated_at)
VALUES (?, ?, ?, ?, 'owner', 'Cicada owner', ?, '', 1, ?, ?)`,
		identityID, PrincipalKindHuman, identityID, identityID, PrincipalStatusActive, stamp, stamp)
	if err != nil {
		return fmt.Errorf("bootstrap local owner Principal: %w", err)
	}
	principal, err := scanPrincipal(s.db.QueryRow(`SELECT `+principalColumns+` FROM principals WHERE id = ?`, identityID))
	if err != nil {
		return err
	}
	if principal == nil || principal.OwnerID != identityID || principal.Kind != PrincipalKindHuman ||
		(principal.TrustDomainID != "" && principal.TrustDomainID != identityID) ||
		principal.Status != PrincipalStatusActive {
		return errors.New("local owner Principal conflicts with Control identity or is revoked")
	}
	return nil
}
