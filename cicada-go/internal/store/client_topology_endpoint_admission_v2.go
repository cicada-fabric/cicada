package store

import (
	"database/sql"
	"strings"
	"time"
)

const ClientTopologyEndpointAdmissionPreviewOperation = "topology.endpoint_admission_preview"

// ClientTopologyEndpointAdmissionPreview is the exact same-Owner admission
// review shown before an Owner attaches one of their enrolled Endpoints to a
// Group. It contains only the CAS coordinates needed by topology.apply; it
// never returns Node credentials, native session IDs, keys, or workspace data.
type ClientTopologyEndpointAdmissionPreview struct {
	OwnerPrincipalID             string   `json:"owner_principal_id"`
	NetworkID                    string   `json:"network_id"`
	NetworkName                  string   `json:"network_name"`
	NetworkVersion               int64    `json:"network_version"`
	GroupID                      string   `json:"group_id"`
	GroupName                    string   `json:"group_name"`
	GroupVersion                 int64    `json:"group_version"`
	GroupContextPolicy           string   `json:"group_context_policy"`
	EndpointID                   string   `json:"endpoint_id"`
	EndpointName                 string   `json:"endpoint_name"`
	EndpointPrincipalID          string   `json:"endpoint_principal_id"`
	EndpointMigrationState       string   `json:"endpoint_migration_state"`
	NetworkMembershipRevision    int64    `json:"network_membership_revision"`
	EndpointNetworkRevision      int64    `json:"endpoint_network_revision"`
	NetworkAccessBindingID       string   `json:"network_access_binding_id"`
	NetworkAccessEpoch           uint64   `json:"network_access_epoch"`
	NativeBindingID              string   `json:"native_binding_id"`
	NativeBindingEpoch           uint64   `json:"native_binding_epoch"`
	ExistingGroupBindingID       string   `json:"existing_group_binding_id,omitempty"`
	ExistingGroupBindingEpoch    uint64   `json:"existing_group_binding_epoch,omitempty"`
	MembershipStatus             string   `json:"membership_status,omitempty"`
	MembershipRevision           int64    `json:"membership_revision"`
	EndpointGroupStatus          string   `json:"endpoint_group_status,omitempty"`
	EndpointGroupRevision        int64    `json:"endpoint_group_revision"`
	AdmissionRoles               []string `json:"admission_roles"`
	AdmissionGrants              []string `json:"admission_grants"`
	HistoryIncluded              bool     `json:"history_included"`
	KeyGrantCreated              bool     `json:"key_grant_created"`
	ExistingThreadMemoryRetained bool     `json:"existing_thread_memory_retained"`
}

// ClientTopologyEndpointAdmissionInput is supplied only inside the accepted
// topology.apply request. Its coordinates are copied from the exact preview
// and checked again in the same transaction that inserts both authority rows.
type ClientTopologyEndpointAdmissionInput struct {
	NetworkID                      string `json:"network_id"`
	GroupID                        string `json:"group_id"`
	EndpointID                     string `json:"endpoint_id"`
	ExpectedEndpointMigrationState string `json:"expected_endpoint_migration_state"`
	ExpectedNetworkVersion         int64  `json:"expected_network_version"`
	ExpectedGroupVersion           int64  `json:"expected_group_version"`
	ExpectedNetworkMembership      int64  `json:"expected_network_membership_revision"`
	ExpectedEndpointNetwork        int64  `json:"expected_endpoint_network_revision"`
	NetworkAccessBindingID         string `json:"network_access_binding_id"`
	NetworkAccessEpoch             uint64 `json:"network_access_epoch"`
	NativeBindingID                string `json:"native_binding_id"`
	NativeBindingEpoch             uint64 `json:"native_binding_epoch"`
	ExistingGroupBindingID         string `json:"existing_group_binding_id,omitempty"`
	ExistingGroupBindingEpoch      uint64 `json:"existing_group_binding_epoch,omitempty"`
	ExpectedMembership             int64  `json:"expected_membership_revision"`
	ExpectedEndpointGroup          int64  `json:"expected_endpoint_group_revision"`
}

type clientTopologyEndpointAdmissionState struct {
	preview                 ClientTopologyEndpointAdmissionPreview
	hubID                   string
	groupState              string
	groupNetworkID          string
	groupOwnerID            string
	networkOwnerID          string
	networkState            string
	endpointOwnerID         string
	endpointState           string
	endpointMigrationState  string
	endpointNativeSessionID string
	endpointNodeID          string
	existingGroupBindingID  string
	endpointLegacyGroupID   string
	networkMembershipStatus string
	principalOwnerID        string
	principalKind           string
	principalStatus         string
	networkMembershipExpiry string
	endpointNetworkStatus   string
	accessLeaseExpiry       string
	accessStatus            string
	nodeID                  string
	accessNativeSessionID   string
	accessLeaseOwner        string
	accessCredentialHash    string
	accessOwnerKeyID        string
	nodeBindingOwnerID      string
	nodeBindingHubID        string
	nodeBindingDigest       string
	nodeBindingVersion      int64
	nodeBindingOwnerKeyID   string
	nodeBindingState        string
	nodeCredentialHash      string
	nodeCredentialVersion   int64
	nodeCredentialStatus    string
	clientOwnerKeyStatus    string
	nodeOwnerKeyStatus      string
	accessOwnerKeyStatus    string
}

func clientTopologyEndpointAdmissionRequestTx(tx *sql.Tx, requestID, ownerID, operation string) (trustedClientRequest, error) {
	actor, err := trustedTopologyGroupCreateRequestTx(tx, requestID)
	if err != nil || actor.OwnerID != strings.TrimSpace(ownerID) {
		return actor, ErrNetworkPermission
	}
	var route string
	if tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`, requestID).Scan(&route) != nil || route != operation {
		return actor, ErrNetworkPermission
	}
	return actor, nil
}

func readClientTopologyEndpointAdmissionStateTx(tx *sql.Tx, actor trustedClientRequest,
	networkID, groupID, endpointID string, at time.Time) (*clientTopologyEndpointAdmissionState, error) {
	state := &clientTopologyEndpointAdmissionState{}
	err := tx.QueryRow(`SELECT n.id,n.name,n.owner_id,n.state,n.version,n.hub_id,
g.id,g.name,g.owner_principal_id,g.state,g.version,g.context_policy,g.network_id,
e.id,e.name,e.owner,e.status,e.migration_state,e.principal_id,e.machine_id,e.native_session_id,e.binding_id,e.group_id,
p.owner_id,p.kind,p.status,
nm.id,nm.status,nm.revision,nm.expires_at,
en.status,en.revision,
a.id,a.epoch,a.status,a.lease_owner,a.lease_expires_at,a.node_id,a.native_session_id,a.credential_hash,a.owner_key_id,
b.owner_id,b.hub_id,b.node_credential_digest,b.node_credential_version,b.owner_key_id,b.state,
c.credential_hash,c.version,c.status,
COALESCE(gm.status,''),COALESCE(gm.revision,0),COALESCE(egm.status,''),COALESCE(egm.revision,0),
client_key.state,node_key.state,access_key.state
FROM networks_v2 n
JOIN groups g ON g.network_id=n.id AND g.id=?
JOIN principals network_owner ON network_owner.id=n.owner_id
  AND network_owner.kind='human' AND network_owner.status='active'
JOIN fabric_endpoints e ON e.id=?
JOIN principals p ON p.id=e.principal_id
JOIN network_memberships_v2 nm ON nm.network_id=n.id AND nm.principal_id=p.id
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=e.id
JOIN network_access_sessions_v2 a ON a.network_id=n.id AND a.endpoint_id=e.id AND a.principal_id=p.id
JOIN node_owner_bindings_v2 b ON b.node_id=a.node_id
JOIN fabric_node_credentials c ON c.node_id=b.node_id
LEFT JOIN memberships gm ON gm.principal_id=e.principal_id AND gm.group_id=g.id
LEFT JOIN endpoint_group_memberships egm ON egm.endpoint_id=e.id AND egm.group_id=g.id
JOIN owner_approval_keys_v2 client_key ON client_key.owner_id=? AND client_key.key_id=(
  SELECT d.owner_key_id FROM client_devices_v2 d WHERE d.owner_id=? AND d.device_id=?
)
JOIN owner_approval_keys_v2 node_key ON node_key.owner_id=b.owner_id AND node_key.key_id=b.owner_key_id
JOIN owner_approval_keys_v2 access_key ON access_key.owner_id=e.owner AND access_key.key_id=a.owner_key_id
WHERE n.id=?`, groupID, endpointID, actor.OwnerID, actor.OwnerID, actor.DeviceID, networkID).Scan(
		&state.preview.NetworkID, &state.preview.NetworkName, &state.networkOwnerID,
		&state.networkState, &state.preview.NetworkVersion, &state.hubID,
		&state.preview.GroupID, &state.preview.GroupName, &state.groupOwnerID, &state.groupState,
		&state.preview.GroupVersion, &state.preview.GroupContextPolicy, &state.groupNetworkID,
		&state.preview.EndpointID, &state.preview.EndpointName, &state.endpointOwnerID, &state.endpointState,
		&state.endpointMigrationState, &state.preview.EndpointPrincipalID, &state.endpointNodeID,
		&state.endpointNativeSessionID, &state.existingGroupBindingID, &state.endpointLegacyGroupID,
		&state.principalOwnerID, &state.principalKind, &state.principalStatus,
		new(string), &state.networkMembershipStatus, &state.preview.NetworkMembershipRevision, &state.networkMembershipExpiry,
		&state.endpointNetworkStatus, &state.preview.EndpointNetworkRevision,
		&state.preview.NetworkAccessBindingID, &state.preview.NetworkAccessEpoch, &state.accessStatus,
		&state.accessLeaseOwner, &state.accessLeaseExpiry, &state.nodeID, &state.accessNativeSessionID,
		&state.accessCredentialHash, &state.accessOwnerKeyID,
		&state.nodeBindingOwnerID, &state.nodeBindingHubID, &state.nodeBindingDigest,
		&state.nodeBindingVersion, &state.nodeBindingOwnerKeyID, &state.nodeBindingState,
		&state.nodeCredentialHash, &state.nodeCredentialVersion, &state.nodeCredentialStatus,
		&state.preview.MembershipStatus, &state.preview.MembershipRevision,
		&state.preview.EndpointGroupStatus, &state.preview.EndpointGroupRevision,
		&state.clientOwnerKeyStatus, &state.nodeOwnerKeyStatus, &state.accessOwnerKeyStatus)
	if err != nil {
		return nil, err
	}
	if state.preview.NetworkID != networkID || state.preview.GroupID != groupID ||
		state.preview.EndpointID != endpointID ||
		state.networkOwnerID == "" || state.groupOwnerID != actor.OwnerID ||
		state.endpointOwnerID != actor.OwnerID || state.principalOwnerID != actor.OwnerID ||
		state.principalKind != PrincipalKindAgent || state.principalStatus != PrincipalStatusActive ||
		state.networkState != NetworkStateActive || state.groupState != GroupStateActive ||
		!validGroupContextPolicy(state.preview.GroupContextPolicy) || state.networkMembershipStatus != "active" ||
		state.groupNetworkID != networkID || state.endpointState == "left" ||
		(state.endpointMigrationState != EndpointMigrationReady &&
			(state.endpointMigrationState != EndpointMigrationPendingGroup || state.endpointLegacyGroupID != "" || state.existingGroupBindingID != "")) ||
		state.endpointNodeID == "" ||
		state.endpointNetworkStatus != "active" ||
		state.accessStatus != "active" || state.accessLeaseOwner == "" ||
		state.preview.NetworkAccessEpoch == 0 || state.preview.NetworkAccessBindingID == "" ||
		state.accessNativeSessionID == "" || state.endpointNodeID != state.nodeID ||
		state.endpointNativeSessionID != state.accessNativeSessionID || state.accessCredentialHash == "" ||
		state.accessOwnerKeyID != state.nodeBindingOwnerKeyID ||
		state.nodeID == "" ||
		state.nodeBindingOwnerID != actor.OwnerID || state.nodeBindingHubID != actor.HubID || state.hubID != actor.HubID ||
		state.nodeBindingState != "ACTIVE" || state.nodeCredentialHash != state.nodeBindingDigest ||
		state.nodeCredentialVersion != state.nodeBindingVersion || state.nodeCredentialStatus != "active" ||
		state.clientOwnerKeyStatus != OwnerApprovalKeyActive || state.nodeOwnerKeyStatus != OwnerApprovalKeyActive ||
		state.accessOwnerKeyStatus != OwnerApprovalKeyActive {
		return nil, ErrNetworkPermission
	}
	if !networkExpiryAllows(state.networkMembershipExpiry, at) || !networkExpiryAllows(state.accessLeaseExpiry, at) {
		return nil, ErrNetworkPermission
	}
	nativeBinding, err := readNetworkDirectNativeBindingTx(tx, endpointID)
	if err != nil || nativeBinding.EndpointID != endpointID || nativeBinding.PrincipalID != state.preview.EndpointPrincipalID ||
		nativeBinding.NodeID != state.nodeID || nativeBinding.NativeSessionID != state.endpointNativeSessionID ||
		nativeBinding.Status != "active" || nativeBinding.Epoch == 0 {
		return nil, ErrNetworkPermission
	}
	if err := guardDedicatedThreadGroupEndpointTx(tx, endpointID, groupID, at); err != nil {
		return nil, err
	}
	state.preview.NativeBindingID = nativeBinding.ID
	state.preview.NativeBindingEpoch = nativeBinding.Epoch
	state.preview.EndpointMigrationState = state.endpointMigrationState
	if state.existingGroupBindingID != "" {
		var binding SessionBinding
		var capabilitiesJSON string
		err := tx.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE id=? AND endpoint_id=?`,
			state.existingGroupBindingID, endpointID).Scan(
			&binding.ID, &binding.EndpointID, &binding.PrincipalID, &binding.GroupID,
			&binding.NativeSessionID, &binding.NodeID, &binding.WorkspaceID,
			&binding.Epoch, &binding.LeaseOwner, &binding.LeaseExpiresAt,
			&binding.Status, &binding.CredentialHash, &binding.CredentialHashVersion,
			&binding.Version, &binding.Mode, &binding.ContextContinuity,
			&capabilitiesJSON, &binding.ReplacesBindingID, &binding.RevocationReason,
			&binding.CreatedAt, &binding.UpdatedAt)
		if err != nil || binding.PrincipalID != state.preview.EndpointPrincipalID ||
			binding.NativeSessionID != state.endpointNativeSessionID || binding.NodeID != state.nodeID ||
			!isActiveBindingStatus(binding.Status) || !networkExpiryAllows(binding.LeaseExpiresAt, at) {
			return nil, ErrNetworkPermission
		}
		state.preview.ExistingGroupBindingID = binding.ID
		state.preview.ExistingGroupBindingEpoch = binding.Epoch
	}
	ownerCanManage, err := localDeliveryMembershipAllows(tx, actor.OwnerID, groupID,
		"group.manage", at.UTC().Format(time.RFC3339Nano))
	if err != nil || !ownerCanManage {
		return nil, ErrNetworkPermission
	}
	state.preview.OwnerPrincipalID = actor.OwnerID
	state.preview.AdmissionRoles = []string{"member"}
	state.preview.AdmissionGrants = []string{}
	state.preview.HistoryIncluded = false
	state.preview.KeyGrantCreated = false
	state.preview.ExistingThreadMemoryRetained = true
	return state, nil
}

// PreviewClientTopologyEndpointAdmissionForClientRequest returns one exact
// same-Owner candidate for the authenticated Client's current Hub. It does
// not create a Membership, join the Endpoint, or grant a key.
func (s *Store) PreviewClientTopologyEndpointAdmissionForClientRequest(requestID, ownerID,
	networkID, groupID, endpointID string) (*ClientTopologyEndpointAdmissionPreview, error) {
	ownerID = strings.TrimSpace(ownerID)
	networkID, groupID, endpointID = strings.TrimSpace(networkID), strings.TrimSpace(groupID), strings.TrimSpace(endpointID)
	if ownerID == "" || networkID == "" || groupID == "" || endpointID == "" {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := clientTopologyEndpointAdmissionRequestTx(tx, requestID, ownerID, ClientTopologyEndpointAdmissionPreviewOperation)
	if err != nil {
		return nil, err
	}
	state, err := readClientTopologyEndpointAdmissionStateTx(tx, actor, networkID, groupID, endpointID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &state.preview, nil
}

// AdmitClientTopologyEndpointForClientRequest atomically inserts the minimum
// Group member authority and Endpoint reference for an already enrolled,
// same-Owner Agent. It deliberately creates no Worker/Monitor grant, history
// access, or Group key grant. Revoked or pre-existing Memberships require a
// separate explicit repair path and cannot be silently reactivated here.
func (s *Store) AdmitClientTopologyEndpointForClientRequest(requestID, authenticatedOwnerID string,
	in ClientTopologyEndpointAdmissionInput) (*Membership, *EndpointGroupMembership, error) {
	ownerID := strings.TrimSpace(authenticatedOwnerID)
	if ownerID == "" || strings.TrimSpace(in.NetworkID) == "" || strings.TrimSpace(in.GroupID) == "" ||
		strings.TrimSpace(in.EndpointID) == "" || in.ExpectedEndpointMigrationState == "" || in.ExpectedNetworkVersion <= 0 ||
		in.ExpectedGroupVersion <= 0 || in.ExpectedNetworkMembership <= 0 ||
		in.ExpectedEndpointNetwork <= 0 || strings.TrimSpace(in.NetworkAccessBindingID) == "" ||
		in.NetworkAccessEpoch == 0 || strings.TrimSpace(in.NativeBindingID) == "" ||
		in.NativeBindingEpoch == 0 || in.ExpectedMembership != 0 || in.ExpectedEndpointGroup != 0 {
		return nil, nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	rollback := func(cause error) (*Membership, *EndpointGroupMembership, error) {
		_ = tx.Rollback()
		return nil, nil, cause
	}
	actor, err := clientTopologyEndpointAdmissionRequestTx(tx, requestID, ownerID, "topology.apply")
	if err != nil {
		return rollback(err)
	}
	guard, err := tx.Exec(`UPDATE groups SET updated_at=updated_at WHERE id=?`, in.GroupID)
	if err != nil {
		return rollback(err)
	}
	if changed, err := guard.RowsAffected(); err != nil || changed != 1 {
		return rollback(ErrNetworkPermission)
	}
	state, err := readClientTopologyEndpointAdmissionStateTx(tx, actor, in.NetworkID, in.GroupID, in.EndpointID, time.Now().UTC())
	if err != nil {
		return rollback(err)
	}
	p := state.preview
	if p.NetworkVersion != in.ExpectedNetworkVersion || p.GroupVersion != in.ExpectedGroupVersion ||
		p.EndpointMigrationState != in.ExpectedEndpointMigrationState ||
		p.NetworkMembershipRevision != in.ExpectedNetworkMembership || p.EndpointNetworkRevision != in.ExpectedEndpointNetwork ||
		p.NetworkAccessBindingID != in.NetworkAccessBindingID || p.NetworkAccessEpoch != in.NetworkAccessEpoch ||
		p.NativeBindingID != in.NativeBindingID || p.NativeBindingEpoch != in.NativeBindingEpoch ||
		p.ExistingGroupBindingID != in.ExistingGroupBindingID || p.ExistingGroupBindingEpoch != in.ExistingGroupBindingEpoch {
		return rollback(ErrVersionConflict)
	}
	if p.MembershipStatus != "" || p.MembershipRevision != in.ExpectedMembership ||
		p.EndpointGroupStatus != "" || p.EndpointGroupRevision != in.ExpectedEndpointGroup {
		return rollback(ErrVersionConflict)
	}
	var groupState string
	if err := tx.QueryRow(`SELECT state FROM groups WHERE id=? AND owner_principal_id=? AND network_id=? AND version=?`,
		in.GroupID, ownerID, in.NetworkID, in.ExpectedGroupVersion).Scan(&groupState); err != nil || groupState != GroupStateActive {
		return rollback(ErrVersionConflict)
	}
	member, rolesJSON, grantsJSON, authJSON, err := normalizeMembership(Membership{
		PrincipalID: p.EndpointPrincipalID, GroupID: in.GroupID, Role: "member", Roles: []string{"member"},
		Grants: []string{}, Status: MembershipStatusActive,
	})
	if err != nil {
		return rollback(err)
	}
	timestamp := now()
	if p.EndpointMigrationState == EndpointMigrationPendingGroup {
		result, err := tx.Exec(`UPDATE fabric_endpoints SET migration_state=?,updated_at=?
WHERE id=? AND principal_id=? AND owner=? AND machine_id=? AND group_id='' AND binding_id=''
AND migration_state=?`, EndpointMigrationReady, timestamp, in.EndpointID, p.EndpointPrincipalID,
			ownerID, state.nodeID, EndpointMigrationPendingGroup)
		if err != nil {
			return rollback(err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return rollback(ErrVersionConflict)
		}
	}
	if _, err := tx.Exec(`INSERT INTO memberships
(id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,
 effective_at,expires_at,revoked_at,revocation_reason,revision,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,'','','',1,1,?,?)`,
		member.ID, member.PrincipalID, member.GroupID, member.Role, rolesJSON, grantsJSON, authJSON,
		member.Status, member.EffectiveAt, timestamp, timestamp); err != nil {
		return rollback(ErrVersionConflict)
	}
	if _, err := tx.Exec(`INSERT INTO endpoint_group_memberships
(endpoint_id,group_id,status,revision,created_at,updated_at) VALUES(?,?,'active',1,?,?)`,
		in.EndpointID, in.GroupID, timestamp, timestamp); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	endpointGroup, err := scanEndpointGroupMembership(s.db.QueryRow(`SELECT `+endpointGroupColumns+
		` FROM endpoint_group_memberships WHERE endpoint_id=? AND group_id=?`, in.EndpointID, in.GroupID))
	if err != nil {
		return nil, nil, err
	}
	return &member, endpointGroup, nil
}
