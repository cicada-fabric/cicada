package store

import "time"

const ClientNetworkCollaborationKeyGrantOperation = "network.collaboration_key_grant"

// AcceptNetworkCollaborationKeyGrantForClientRequest consumes a purpose-scoped
// Owner proof only for the exact still-processing encrypted Client operation.
// The trusted device/Owner/Hub binding and route operation are checked in the
// same transaction as proof verification, nonce reservation, and grant write.
func (s *Store) AcceptNetworkCollaborationKeyGrantForClientRequest(clientRequestID,
	authenticatedOwnerID, networkID, endpointID, purpose string, proof []byte) (*OwnerNetworkCollaborationKeyGrant, error) {
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
	var routeOperation string
	if err := tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?
AND status='PROCESSING'`, clientRequestID).Scan(&routeOperation); err != nil ||
		routeOperation != ClientNetworkCollaborationKeyGrantOperation {
		return nil, ErrNetworkPermission
	}
	grant, err := acceptNetworkCollaborationKeyGrantTx(tx, actor.OwnerID,
		networkID, endpointID, purpose, proof, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}
