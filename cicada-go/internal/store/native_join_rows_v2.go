package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Shared row builders only. Legacy invitation/admission and explicit Owner-pair
// callers establish their different authority before calling in their own Tx.
func insertNetworkNativeEndpointTx(tx *sql.Tx, owner, trust, name, harness, sid, node, workspace string, at time.Time) (string, string, error) {
	principal, endpoint := NewID("principal"), NewID("ep")
	stamp := at.UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`INSERT INTO principals(id,kind,owner_id,trust_domain_id,name,display_name,status,version,created_at,updated_at) VALUES(?,'agent',?,?,?,?,'active',1,?,?)`, principal, owner, trust, name, name, stamp, stamp); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`INSERT INTO fabric_endpoints(id,name,role,harness,native_session_id,machine_id,workspace,goal_id,status,capabilities_json,tags_json,owner,visibility,joined_at,last_seen,created_at,updated_at,principal_id,migration_state) VALUES(?,?,'thread',?,?,?,?,'','online','{}','[]',?,'private',?,?,?,?,?,'MIGRATION_PENDING_GROUP')`, endpoint, name, harness, sid, node, workspace, owner, stamp, stamp, stamp, stamp, principal); err != nil {
		return "", "", err
	}
	return endpoint, principal, nil
}

func insertZeroGroupAdmissionTx(tx *sql.Tx, principal, group, endpoint, expiry string, at time.Time) (Membership, error) {
	stamp := at.UTC().Format(time.RFC3339)
	member, roles, grants, auth, err := normalizeMembership(Membership{PrincipalID: principal, GroupID: group, Role: "member", Roles: []string{"member"}, Grants: []string{}, Status: MembershipStatusActive, EffectiveAt: stamp, ExpiresAt: expiry})
	if err != nil {
		return Membership{}, err
	}
	if _, err = tx.Exec(`INSERT INTO memberships(id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,effective_at,expires_at,revoked_at,revocation_reason,revision,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'','',1,1,?,?)`, member.ID, member.PrincipalID, member.GroupID, member.Role, roles, grants, auth, member.Status, member.EffectiveAt, member.ExpiresAt, stamp, stamp); err != nil {
		return Membership{}, ErrVersionConflict
	}
	if _, err = tx.Exec(`INSERT INTO endpoint_group_memberships(endpoint_id,group_id,status,revision,created_at,updated_at) VALUES(?,?,'active',1,?,?)`, endpoint, group, stamp, stamp); err != nil {
		return Membership{}, err
	}
	member.CreatedAt, member.UpdatedAt = stamp, stamp
	return member, nil
}

func insertSessionBindingRowTx(tx *sql.Tx, binding SessionBinding, capabilitiesJSON, stamp string) error {
	_, err := tx.Exec(`INSERT INTO session_bindings
(id,endpoint_id,principal_id,group_id,native_session_id,node_id,workspace_id,epoch,lease_owner,lease_expires_at,status,credential_hash,credential_hash_version,version,mode,context_continuity,capabilities_json,replaces_binding_id,revocation_reason,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, binding.ID, binding.EndpointID, binding.PrincipalID, binding.GroupID, binding.NativeSessionID, binding.NodeID, binding.WorkspaceID, binding.Epoch, binding.LeaseOwner, binding.LeaseExpiresAt, binding.Status, binding.CredentialHash, binding.CredentialHashVersion, binding.Version, binding.Mode, binding.ContextContinuity, capabilitiesJSON, binding.ReplacesBindingID, binding.RevocationReason, stamp, stamp)
	if err != nil {
		if isSQLiteConstraint(err) {
			return ErrSessionBindingConflict
		}
		return fmt.Errorf("create session binding: %w", err)
	}
	return nil
}
