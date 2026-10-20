package store

import (
	"database/sql"
	"strings"
)

const OwnerEndpointDirectoryLimit = 1000

// ListOwnerEndpointMetadata is an internal authenticated-Owner projection.
// The encrypted Server path must use the request-bound variant below.
func (s *Store) ListOwnerEndpointMetadata(owner string, limit int) ([]Endpoint, bool, error) {
	return s.listOwnerEndpointMetadata(owner, "", limit)
}

func (s *Store) ListClientOwnerEndpointMetadata(owner, requestID string, limit int) ([]Endpoint, bool, error) {
	if strings.TrimSpace(requestID) == "" {
		return nil, false, ErrNetworkPermission
	}
	return s.listOwnerEndpointMetadata(owner, requestID, limit)
}

func guardOwnerEndpointDirectoryTx(tx *sql.Tx, owner, requestID string) error {
	actor, err := trustedClientRequestTx(tx, requestID)
	if err != nil || actor.OwnerID != owner {
		return ErrNetworkPermission
	}
	var operation string
	if err = tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`, requestID).Scan(&operation); err != nil || operation != "topology.snapshot" {
		return ErrNetworkPermission
	}
	return appLeaseAllowed(tx, actor.OwnerID, actor.DeviceID, operation)
}

func (s *Store) CheckClientOwnerEndpointDirectory(owner, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return guardOwnerEndpointDirectoryTx(tx, owner, requestID)
}

func (s *Store) listOwnerEndpointMetadata(owner, requestID string, limit int) ([]Endpoint, bool, error) {
	if owner == "" || strings.TrimSpace(owner) != owner || limit <= 0 || limit > OwnerEndpointDirectoryLimit {
		return nil, false, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if requestID != "" {
		if err = guardOwnerEndpointDirectoryTx(tx, owner, requestID); err != nil {
			return nil, false, err
		}
	}
	// Both Endpoint and Principal must belong to this actual Owner. Apply the
	// restriction before LIMIT so foreign records cannot crowd out own entries.
	rows, err := tx.Query(`SELECT `+endpointV2Columns+` FROM fabric_endpoints
WHERE owner=? AND EXISTS(SELECT 1 FROM principals p
 WHERE p.id=fabric_endpoints.principal_id AND p.owner_id=? AND p.kind='agent' AND p.status='active')
 AND EXISTS(SELECT 1 FROM principals o WHERE o.id=? AND o.owner_id=o.id AND o.kind='human' AND o.status='active')
ORDER BY id LIMIT ?`, owner, owner, owner, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := make([]Endpoint, 0)
	for rows.Next() {
		endpoint, err := scanEndpointV2(rows)
		if err != nil {
			return nil, false, err
		}
		result = append(result, *endpoint)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(result) > limit
	if truncated {
		result = result[:limit]
	}
	return result, truncated, nil
}
