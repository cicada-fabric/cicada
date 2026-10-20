package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

// RegisterNodeEndpoint adds no enrollment, binding, lease, key or grant. An
// existing native identity is read, never adopted, revived or rewritten.
func (s *Store) RegisterNodeEndpoint(rpc NodeControlRPCInput, in nodewire.EndpointRegistration) (*nodewire.EndpointRegistrationResult, error) {
	if rpc.Operation != nodewire.EndpointRegisterOperation || in.Validate() != nil {
		return nil, nodewire.ErrEndpointContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	owner, trust, err := nodeEndpointWriterTx(tx, rpc)
	if err != nil {
		return nil, err
	}
	endpoint, err := nodeEndpointForSessionTx(tx, owner, rpc.NodeID, in.Harness, in.NativeSessionID)
	reused := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		at := time.Now().UTC()
		id, _, insertErr := insertNetworkNativeEndpointTx(tx, owner, trust, in.Name, in.Harness, in.NativeSessionID, rpc.NodeID, in.Workspace, at)
		if insertErr != nil {
			return nil, insertErr
		}
		// Registration is metadata, not proof of an online native writer.
		if _, err = tx.Exec(`UPDATE fabric_endpoints SET status='offline' WHERE id=?`, id); err != nil {
			return nil, err
		}
		endpoint, err = nodeEndpointForSessionTx(tx, owner, rpc.NodeID, in.Harness, in.NativeSessionID)
	}
	if err != nil {
		return nil, err
	}
	if endpoint.Workspace != in.Workspace {
		return nil, nodewire.ErrEndpointConflict
	}
	result, err := nodeEndpointResultTx(tx, endpoint, reused)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// LeaveNodeEndpoint uses the same all-scope withdrawal as Fabric Leave, under
// the current Node request fence and a digest of the exact authorization state.
// Network-only and zero-rights Endpoints need no fabricated Group binding.
func (s *Store) LeaveNodeEndpoint(rpc NodeControlRPCInput, in nodewire.EndpointLeave) (*nodewire.EndpointRegistrationResult, error) {
	if rpc.Operation != nodewire.EndpointLeaveOperation || in.Validate() != nil {
		return nil, nodewire.ErrEndpointContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	owner, _, err := nodeEndpointWriterTx(tx, rpc)
	if err != nil {
		return nil, err
	}
	endpoint, err := nodeEndpointForSessionTx(tx, owner, rpc.NodeID, in.Harness, in.NativeSessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nodewire.ErrEndpointUnavailable
	}
	if err != nil {
		return nil, err
	}
	current, err := nodeEndpointResultTx(tx, endpoint, true)
	if err != nil {
		return nil, err
	}
	if current.StateDigest != in.StateDigest {
		return nil, nodewire.ErrEndpointConflict
	}
	if err = withdrawEndpointAllScopesTx(tx, endpoint.ID, "explicit current-thread leave", now()); err != nil {
		return nil, err
	}
	endpoint.Status = "left"
	result, err := nodeEndpointResultTx(tx, endpoint, true)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func nodeEndpointWriterTx(tx *sql.Tx, rpc NodeControlRPCInput) (string, string, error) {
	// Take the SQLite writer before checking authority. Another Store handle
	// cannot commit revocation between this check and the Endpoint mutation.
	if _, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state=state
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID); err != nil {
		return "", "", err
	}
	if err := verifyNodeControlRPCProcessingTx(tx, rpc); err != nil {
		return "", "", err
	}
	var owner, trust string
	err := tx.QueryRow(`SELECT p.id,p.trust_domain_id FROM node_owner_bindings_v2 b
JOIN principals p ON p.id=b.owner_id AND p.kind='human' AND p.status='active'
WHERE b.id=? AND b.node_id=? AND b.state='ACTIVE'`, rpc.BindingID, rpc.NodeID).Scan(&owner, &trust)
	return owner, trust, err
}

func nodeEndpointForSessionTx(tx *sql.Tx, owner, node, harness, sid string) (*Endpoint, error) {
	endpoint, err := scanEndpointV2(tx.QueryRow(`SELECT `+endpointV2Columns+` FROM fabric_endpoints
WHERE harness=? AND native_session_id=?`, harness, sid))
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, sql.ErrNoRows
	}
	var principalOwner, kind, status string
	err = tx.QueryRow(`SELECT owner_id,kind,status FROM principals WHERE id=?`, endpoint.PrincipalID).Scan(&principalOwner, &kind, &status)
	if err != nil || endpoint.Owner != owner || principalOwner != owner || kind != PrincipalKindAgent ||
		status != PrincipalStatusActive || endpoint.MachineID != node {
		return nil, nodewire.ErrEndpointUnavailable
	}
	return endpoint, nil
}

func nodeEndpointResultTx(tx *sql.Tx, endpoint *Endpoint, reused bool) (*nodewire.EndpointRegistrationResult, error) {
	hash := sha256.New()
	fmt.Fprintln(hash, "cicada/endpoint-state/v1")
	// No timestamps, last_seen, lease expiry or counters that heartbeat changes.
	// Native and Owner coordinates are private inputs to the opaque CAS digest.
	queries := []struct{ tag, query string }{
		{"endpoint", `SELECT json_array(id,owner,principal_id,machine_id,harness,native_session_id,name,workspace,status,migration_state) FROM fabric_endpoints WHERE id=?`},
		{"group", `SELECT json_array(eg.group_id,eg.status,eg.revision,m.status,m.revision,g.state,g.version,g.revision,g.context_policy) FROM endpoint_group_memberships eg LEFT JOIN groups g ON g.id=eg.group_id LEFT JOIN memberships m ON m.principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=eg.endpoint_id) AND m.group_id=eg.group_id WHERE eg.endpoint_id=? ORDER BY eg.group_id`},
		{"network", `SELECT json_array(en.network_id,en.status,en.revision,nm.status,nm.revision,n.state,n.version) FROM endpoint_network_memberships_v2 en LEFT JOIN networks_v2 n ON n.id=en.network_id LEFT JOIN network_memberships_v2 nm ON nm.principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=en.endpoint_id) AND nm.network_id=en.network_id WHERE en.endpoint_id=? ORDER BY en.network_id`},
		{"binding", `SELECT json_array(id,epoch,status,group_id) FROM session_bindings WHERE endpoint_id=? ORDER BY id`},
		{"access", `SELECT json_array(id,epoch,status,network_id) FROM network_access_sessions_v2 WHERE endpoint_id=? ORDER BY id`},
	}
	for _, q := range queries {
		rows, err := tx.Query(q.query, endpoint.ID)
		if err != nil {
			return nil, err
		}
		count := 0
		for rows.Next() {
			var tuple string
			if err = rows.Scan(&tuple); err != nil {
				rows.Close()
				return nil, err
			}
			count++
			if count > 10000 {
				rows.Close()
				return nil, nodewire.ErrEndpointConflict
			}
			fmt.Fprintln(hash, q.tag, tuple)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return &nodewire.EndpointRegistrationResult{EndpointID: endpoint.ID, Name: endpoint.Name,
		Workspace: endpoint.Workspace, Presence: endpoint.Status, Reused: reused, StateDigest: hex.EncodeToString(hash.Sum(nil))}, nil
}
