package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairZeroJoinTx(tx *sql.Tx, p *hubNativePair, q wire.NativePairNodeJoin, token string, at time.Time) (*HubNativePairZeroJoin, error) {
	var generation uint64
	var state string
	err := tx.QueryRow(`SELECT generation,state FROM hub_native_pair_slots_v1 WHERE pair_id=? AND slot=? AND state!='REJECTED'`, p.id, q.Slot).Scan(&generation, &state)
	if err != nil || state != "RESERVED" || generation != q.ExpectedGeneration {
		return nil, ErrHubAccountRejected
	}
	// A terminal/unrelated SID is retained. This first version cannot move it,
	// rotate its epoch or create a replacement Endpoint to bypass old scope.
	var existing int
	if err = tx.QueryRow(`SELECT count(*) FROM fabric_endpoints WHERE harness=? AND native_session_id=?`, q.Runtime, q.NativeSessionID).Scan(&existing); err != nil {
		return nil, err
	}
	if existing != 0 {
		return nil, ErrSessionBindingConflict
	}
	group, err := scanGroup(tx.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id=?`, p.group))
	if err != nil || group == nil || group.NetworkID != p.network || group.OwnerPrincipalID != p.owner || group.State != GroupStateActive || group.Version != 1 || group.Revision != 1 || group.ContextPolicy != "group_scoped" {
		return nil, ErrHubAccountRejected
	}
	var network int
	if tx.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE' AND version=1`, p.network, p.hub, p.owner).Scan(&network) != nil || network != 1 {
		return nil, ErrHubAccountRejected
	}
	if token == "" || len(token) > 256 || strings.TrimSpace(token) != token {
		return nil, ErrHubAccountRejected
	}
	raw, err := hex.DecodeString(wire.NativePairCredentialCommitment(token))
	if err != nil {
		return nil, err
	}
	credential := base64.RawURLEncoding.EncodeToString(raw)
	name := q.EndpointName
	if name == "" {
		name = "Thread " + q.Slot
	}
	endpoint, principal, err := insertNetworkNativeEndpointTx(tx, p.owner, group.TrustDomainID, name, q.Runtime, q.NativeSessionID, p.node, q.Workspace, at)
	if err != nil {
		return nil, err
	}
	stamp := at.UTC().Format(time.RFC3339)
	if _, err = tx.Exec(`INSERT INTO network_memberships_v2(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at) VALUES(?,?,?,'[]','active',?,1,?,?)`, NewID("netmem"), p.network, principal, p.peerExpires, stamp, stamp); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO endpoint_network_memberships_v2(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at) VALUES(?,?,'active',1,?,0,?,?)`, p.network, endpoint, name, stamp, stamp); err != nil {
		return nil, err
	}
	end := at.Add(5 * time.Minute)
	peer, err := time.Parse(time.RFC3339Nano, p.peerExpires)
	if err != nil {
		return nil, err
	}
	if peer.Before(end) {
		end = peer
	}
	lease := NewID("adapter")
	leaseEnd := appNodeStamp(end)
	access := NewID("netaccess")
	if _, err = tx.Exec(`INSERT INTO network_access_sessions_v2(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?,'active',?,?,?,?)`, access, p.network, endpoint, principal, q.NativeSessionID, p.node, lease, leaseEnd, credential, p.scope.Actor.OwnerPublic.ID, stamp, stamp); err != nil {
		return nil, err
	}
	if _, err = insertZeroGroupAdmissionTx(tx, principal, p.group, endpoint, p.peerExpires, at); err != nil {
		return nil, err
	}
	binding, capabilities, err := normalizeBinding(SessionBinding{EndpointID: endpoint, PrincipalID: principal, GroupID: p.group, NativeSessionID: q.NativeSessionID, NodeID: p.node, WorkspaceID: q.Workspace, Epoch: 1, LeaseOwner: lease, LeaseExpiresAt: leaseEnd, Status: SessionBindingStatusLeased, CredentialHash: credential, Mode: "adopted", ContextContinuity: "NATIVE_RESUME"})
	if err != nil {
		return nil, err
	}
	// The verified Node supplies this opaque local path. Do not rewrite it using
	// the Hub OS, trim a real directory name or clear the original native context.
	binding.WorkspaceID, binding.Workspace = q.Workspace, q.Workspace
	if err = insertSessionBindingRowTx(tx, binding, capabilities, stamp); err != nil {
		return nil, err
	}
	endpointUpdate, err := tx.Exec(`UPDATE fabric_endpoints SET group_id=?,binding_id=?,migration_state='READY',updated_at=? WHERE id=? AND principal_id=? AND migration_state='MIGRATION_PENDING_GROUP'`, p.group, binding.ID, stamp, endpoint, principal)
	if err != nil {
		return nil, err
	}
	if n, e := endpointUpdate.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	attempt, err := wire.NewRequestID()
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE hub_native_pair_slots_v1 SET state='JOINED_ZERO',attempt_id=?,native_session_id=?,endpoint_id=?,principal_id=?,network_access_binding_id=?,binding_id=?,lease_owner=? WHERE pair_id=? AND slot=? AND generation=? AND state='RESERVED' AND attempt_id=''`, attempt, q.NativeSessionID, endpoint, principal, access, binding.ID, lease, p.id, q.Slot, q.ExpectedGeneration)
	if err != nil {
		return nil, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	result, err = tx.Exec(`UPDATE hub_native_pairs_v1 SET state=CASE WHEN (SELECT count(*) FROM hub_native_pair_slots_v1 WHERE pair_id=? AND state IN('JOINED_ZERO','ACTIVE'))=2 THEN 'WAITING_CONSENT' ELSE 'WAITING_JOIN' END,control_revision=control_revision+1 WHERE pair_id=? AND control_revision=? AND state IN('WAITING_JOIN','WAITING_CONSENT')`, p.id, p.id, p.revision)
	if err != nil {
		return nil, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	row, err := scanEndpointV2(tx.QueryRow(`SELECT `+endpointV2Columns+` FROM fabric_endpoints WHERE id=?`, endpoint))
	if err != nil {
		return nil, err
	}
	current, err := scanSessionBinding(tx.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE id=?`, binding.ID))
	if err != nil {
		return nil, err
	}
	scope, err := readNativeContextScopeForGroupTx(tx, p.group)
	if err != nil {
		return nil, err
	}
	return &HubNativePairZeroJoin{Endpoint: *row, Binding: *current, SessionToken: token, NativeContextScope: scope}, nil
}
