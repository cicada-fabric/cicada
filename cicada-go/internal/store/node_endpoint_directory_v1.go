package store

import (
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

// ListNodeEndpoints is a Node-operator read. No Fabric actor or directory grant
// is synthesized; models never receive this Node credential through MCP.
func (s *Store) ListNodeEndpoints(rpc NodeControlRPCInput, q nodewire.EndpointDirectoryRequest) (*nodewire.EndpointDirectoryResult, error) {
	if rpc.Operation != nodewire.EndpointDirectoryOperation || q.Validate() != nil {
		return nil, nodewire.ErrEndpointContext
	}
	limit := q.Limit
	if limit == 0 {
		limit = 64
	}
	if q.Harness != "" {
		limit = 1
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
	at := time.Now().UTC()
	stamp := appNodeStamp(at)
	if q.Cursor != "" {
		var exists int
		if tx.QueryRow(`SELECT 1 FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id
WHERE e.id=? AND e.owner=? AND e.machine_id=? AND p.owner_id=e.owner AND p.kind='agent' AND p.status='active'`, q.Cursor, owner, rpc.NodeID).Scan(&exists) != nil {
			return nil, nodewire.ErrEndpointUnavailable
		}
	}
	query := `SELECT e.id,e.name,e.workspace,e.harness,e.native_session_id,
CASE WHEN e.status='left' THEN 'left' WHEN e.status='offline' THEN 'offline'
 WHEN EXISTS(SELECT 1 FROM session_bindings b WHERE b.endpoint_id=e.id
  AND b.status IN ('active','leased','online','ready','acquired') AND b.lease_expires_at!=''
  AND cicada_network_expiry_allows(b.lease_expires_at,?)=1)
 OR EXISTS(SELECT 1 FROM network_access_sessions_v2 a WHERE a.endpoint_id=e.id AND a.status='active'
  AND a.lease_expires_at!='' AND cicada_network_expiry_allows(a.lease_expires_at,?)=1)
 THEN 'LEASE_RECENT' ELSE 'UNKNOWN' END
FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id AND p.owner_id=e.owner AND p.kind='agent' AND p.status='active'
WHERE e.owner=? AND e.machine_id=? AND e.id>?`
	args := []any{stamp, stamp, owner, rpc.NodeID, q.Cursor}
	if q.Harness != "" {
		query += ` AND e.harness=? AND e.native_session_id=?`
		args = append(args, q.Harness, q.NativeSessionID)
	}
	query += ` ORDER BY e.id LIMIT ?`
	args = append(args, limit+1)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var cards []nodewire.EndpointDirectoryCard
	for rows.Next() {
		var c nodewire.EndpointDirectoryCard
		if err = rows.Scan(&c.EndpointID, &c.Name, &c.Workspace, &c.Harness, &c.NativeSessionID, &c.Presence); err != nil {
			rows.Close()
			return nil, err
		}
		cards = append(cards, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := &nodewire.EndpointDirectoryResult{NodeID: rpc.NodeID, CapturedAt: stamp, Freshness: "SNAPSHOT_ONLY", Endpoints: []nodewire.EndpointDirectoryCard{}}
	for i, c := range cards {
		if i == limit {
			result.NextCursor = result.Endpoints[len(result.Endpoints)-1].EndpointID
			break
		}
		state, err := nodeEndpointResultTx(tx, &Endpoint{ID: c.EndpointID, Name: c.Name, Workspace: c.Workspace, Status: c.Presence}, true)
		if err != nil {
			return nil, err
		}
		c.StateDigest = state.StateDigest
		result.Endpoints = append(result.Endpoints, c)
		result.NextCursor = c.EndpointID
		raw, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		if len(raw) > nodewire.MaxEndpointDirectoryBytes-512 {
			result.Endpoints = result.Endpoints[:len(result.Endpoints)-1]
			if len(result.Endpoints) == 0 {
				return nil, nodewire.ErrEndpointContext
			}
			result.NextCursor = result.Endpoints[len(result.Endpoints)-1].EndpointID
			break
		}
		result.NextCursor = ""
	}
	return result, nil
}
