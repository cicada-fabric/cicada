package store

import (
	"database/sql"
	"strings"
	"time"
)

// trustedClientRequestTx binds a mutation to one accepted encrypted Client
// request and the currently active device, owner key, epoch, and Hub. The ID
// comes from Server's accepted request record, never from Client JSON.
type trustedClientRequest struct {
	OwnerID  string
	DeviceID string
	HubID    string
}

// AcceptNetworkDirectKeyGrantForClientRequest consumes Owner consent only for
// the still-current encrypted device request. The device and owner scope are
// rechecked in the same write transaction as the signed grant and nonce.
func (s *Store) AcceptNetworkDirectKeyGrantForClientRequest(clientRequestID, authenticatedOwnerID, networkID, endpointID string, proof []byte) (*OwnerNetworkDirectKeyGrant, error) {
	if len(proof) == 0 || len(proof) > 32*1024 {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := trustedClientRequestTx(tx, clientRequestID)
	if err != nil || actor.OwnerID != authenticatedOwnerID {
		return nil, ErrNetworkPermission
	}
	grant, err := acceptNetworkDirectKeyGrantTx(tx, actor.OwnerID, networkID, endpointID, proof, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

func trustedClientRequestTx(tx *sql.Tx, requestID string) (trustedClientRequest, error) {
	var actor trustedClientRequest
	if strings.TrimSpace(requestID) == "" {
		return actor, ErrNetworkPermission
	}
	err := tx.QueryRow(`SELECT r.owner_id,r.device_id,h.hub_id
FROM client_device_requests_v2 r
JOIN client_devices_v2 d ON d.owner_id=r.owner_id AND d.device_id=r.device_id
  AND d.session_epoch=r.session_epoch AND d.state='ACTIVE'
JOIN owner_approval_keys_v2 k ON k.owner_id=d.owner_id AND k.key_id=d.owner_key_id AND k.state='ACTIVE'
JOIN principals p ON p.id=r.owner_id AND p.owner_id=p.id AND p.kind='human' AND p.status='active'
  AND (p.trust_domain_id='' OR p.trust_domain_id=p.id)
JOIN client_device_hub_config_v2 h ON h.id=1
WHERE r.id=? AND r.status='PROCESSING'`, requestID).Scan(&actor.OwnerID, &actor.DeviceID, &actor.HubID)
	if err == sql.ErrNoRows {
		return actor, ErrNetworkPermission
	}
	return actor, err
}

// OwnerNetworkEndpointEnrollment is a metadata-only relation used by the
// encrypted owner's topology view. It does not grant directory or peer access.
type OwnerNetworkEndpointEnrollment struct {
	NetworkID       string
	EndpointID      string
	Name            string
	PrincipalID     string
	NodeID          string
	Harness         string
	NativeSessionID string
	Status          string
}

type OwnerNetworkTopologyCard struct {
	NetworkID string
	Name      string
	OwnerID   string
	State     string
	Version   int64
}

// ListOwnerNetworkTopology selects only Networks this Owner owns or where one
// of their currently enrolled Endpoints participates. It never scans all
// Network records into the Client projection, and reports a bounded cutoff.
func (s *Store) ListOwnerNetworkTopology(ownerID string, limit int) ([]OwnerNetworkTopologyCard, bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" || limit <= 0 || limit > 100 {
		return nil, false, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT n.id,n.name,n.owner_id,n.state,n.version FROM networks_v2 n
WHERE n.owner_id=? OR EXISTS (
  SELECT 1 FROM endpoint_network_memberships_v2 en
  JOIN fabric_endpoints e ON e.id=en.endpoint_id AND e.status!='left'
  JOIN principals p ON p.id=e.principal_id AND p.owner_id=? AND p.status='active' AND e.owner=p.owner_id
  JOIN network_memberships_v2 m ON m.network_id=en.network_id AND m.principal_id=p.id
  WHERE en.network_id=n.id AND en.status='active' AND m.status='active'
    AND cicada_network_expiry_allows(m.expires_at,?)=1)
ORDER BY n.id LIMIT ?`, ownerID, ownerID, now(), limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := make([]OwnerNetworkTopologyCard, 0, limit)
	for rows.Next() {
		var card OwnerNetworkTopologyCard
		if err := rows.Scan(&card.NetworkID, &card.Name, &card.OwnerID, &card.State, &card.Version); err != nil {
			return nil, false, err
		}
		result = append(result, card)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(result) > limit
	if truncated {
		result = result[:limit]
	}
	return result, truncated, nil
}

// ListOwnerNetworkEndpointEnrollments includes Network-only Endpoints, whose
// legacy Group association is deliberately empty. Every row is restricted to
// a current self-owned Endpoint Principal and active Network enrollment.
func (s *Store) ListOwnerNetworkEndpointEnrollments(ownerID string, limit int) ([]OwnerNetworkEndpointEnrollment, bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" || limit <= 0 || limit > 1000 {
		return nil, false, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT en.network_id,e.id,e.name,e.principal_id,e.machine_id,e.harness,e.native_session_id,e.status
FROM endpoint_network_memberships_v2 en
JOIN networks_v2 n ON n.id=en.network_id
JOIN fabric_endpoints e ON e.id=en.endpoint_id AND e.status!='left'
JOIN principals p ON p.id=e.principal_id AND p.owner_id=? AND p.status='active' AND e.owner=p.owner_id
JOIN network_memberships_v2 m ON m.network_id=en.network_id AND m.principal_id=p.id
WHERE en.status='active' AND m.status='active' AND cicada_network_expiry_allows(m.expires_at,?)=1
ORDER BY en.network_id,en.endpoint_id LIMIT ?`, ownerID, now(), limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := make([]OwnerNetworkEndpointEnrollment, 0)
	for rows.Next() {
		var enrollment OwnerNetworkEndpointEnrollment
		if err := rows.Scan(&enrollment.NetworkID, &enrollment.EndpointID, &enrollment.Name,
			&enrollment.PrincipalID, &enrollment.NodeID, &enrollment.Harness,
			&enrollment.NativeSessionID, &enrollment.Status); err != nil {
			return nil, false, err
		}
		result = append(result, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(result) > limit
	if truncated {
		result = result[:limit]
	}
	return result, truncated, nil
}
