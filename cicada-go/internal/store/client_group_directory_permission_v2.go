package store

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

// SetClientGroupDirectoryPermissionForClientRequest changes only directory.read
// for one Principal's Group Membership. All of that Principal's joined
// Endpoints use this Membership. No role, peer action, history, key or binding
// is granted. The request ID must come from the accepted encrypted Client RPC.
func (s *Store) SetClientGroupDirectoryPermissionForClientRequest(requestID, ownerID, groupID, membershipID string,
	enabled bool, expectedVersion int64) (*Membership, string, error) {
	requestID, ownerID = strings.TrimSpace(requestID), strings.TrimSpace(ownerID)
	groupID, membershipID = strings.TrimSpace(groupID), strings.TrimSpace(membershipID)
	if requestID == "" || ownerID == "" || groupID == "" || membershipID == "" ||
		len(groupID) > 256 || len(membershipID) > 256 || expectedVersion <= 0 || expectedVersion == math.MaxInt64 {
		return nil, "", ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	// Take SQLite's writer lock before reading mutable authority, including
	// changes made through another Store handle. This no-op changes no version.
	if _, err := tx.Exec(`UPDATE memberships SET version=version WHERE id=?`, membershipID); err != nil {
		return nil, "", err
	}
	actor, err := trustedClientRequestTx(tx, requestID)
	if err != nil || actor.OwnerID != ownerID {
		return nil, "", ErrNetworkPermission
	}
	var operation string
	if tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`, requestID).Scan(&operation) != nil || operation != "topology.apply" {
		return nil, "", ErrNetworkPermission
	}
	var displayName string
	err = tx.QueryRow(`SELECT p.display_name FROM memberships m
JOIN principals p ON p.id=m.principal_id AND p.owner_id=? AND p.status='active'
JOIN groups g ON g.id=m.group_id AND g.owner_principal_id=? AND g.state='ACTIVE'
JOIN networks_v2 n ON n.id=g.network_id AND n.owner_id=? AND n.state='ACTIVE' AND n.hub_id=?
WHERE m.id=? AND m.group_id=?`, ownerID, ownerID, ownerID, actor.HubID, membershipID, groupID).Scan(&displayName)
	if err != nil {
		return nil, "", ErrNetworkPermission
	}
	member, err := scanMembership(tx.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id=?`, membershipID))
	if err != nil {
		return nil, "", err
	}
	at := time.Now().UTC()
	if member == nil || member.Status != MembershipStatusActive ||
		!networkEffectiveAllows(member.EffectiveAt, at) || !networkExpiryAllows(member.ExpiresAt, at) {
		return nil, "", ErrMembershipNotActive
	}
	if member.Version != expectedVersion || member.Revision <= 0 || member.Revision == math.MaxInt64 {
		return nil, "", ErrVersionConflict
	}
	grants := make([]string, 0, len(member.Grants)+1)
	for _, grant := range member.Grants {
		if grant != "directory.read" {
			grants = append(grants, grant)
		}
	}
	if enabled {
		grants = append(grants, "directory.read")
	}
	// MembershipAllows accepts either a grant or a true authorization entry.
	// Remove the exact entry in both directions; preserve every other value.
	delete(member.Authorization, "directory.read")
	grantsJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, "", err
	}
	authorizationJSON, err := json.Marshal(member.Authorization)
	if err != nil {
		return nil, "", err
	}
	result, err := tx.Exec(`UPDATE memberships SET grants_json=?,authorization_json=?,
revision=revision+1,version=version+1,updated_at=? WHERE id=? AND version=?`,
		string(grantsJSON), string(authorizationJSON), at.Format(time.RFC3339Nano), membershipID, expectedVersion)
	if err != nil {
		return nil, "", err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return nil, "", ErrVersionConflict
	}
	updated, err := scanMembership(tx.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id=?`, membershipID))
	if err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return updated, displayName, nil
}
