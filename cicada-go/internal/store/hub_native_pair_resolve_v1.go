package store

import "time"

// The established resolver receives only the exact current peer of a pair
// actor, read under the same snapshot as both original bindings and proofs.
// Nil Endpoint and nil error means an ordinary legacy Group.
func (s *Store) GetHubNativePairResolvePeerForActor(scope NativeActorScope) (*Endpoint, *SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	p, err := nativePairForGroupTx(tx, scope.GroupID)
	if err != nil || p == nil {
		return nil, nil, err
	}
	at := time.Now().UTC()
	if guardNativeSelfTx(tx, scope, at) != nil {
		return nil, nil, ErrNetworkPermission
	}
	var peer string
	if tx.QueryRow(`SELECT endpoint_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND endpoint_id!=? AND state='ACTIVE'`, p.id, scope.EndpointID).Scan(&peer) != nil {
		return nil, nil, ErrNetworkPermission
	}
	if _, err = readSameGroupSealedV1PairTx(tx, p.group, scope.EndpointID, peer, at); err != nil {
		return nil, nil, ErrNetworkPermission
	}
	endpoint, err := scanEndpointV2(tx.QueryRow(`SELECT `+endpointV2Columns+` FROM fabric_endpoints WHERE id=?`, peer))
	if err != nil {
		return nil, nil, err
	}
	binding, err := getSessionBindingLeaseTx(tx, endpoint.BindingID)
	if err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}
	return endpoint, binding, nil
}
