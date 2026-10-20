package store

import (
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// AvailableNodeNativePairs is discovery, never a Join or a slot reservation.
// It exposes only current Owner-created Pair slots for this exact approved
// Node. The live Thread still makes the existing authenticated explicit Join.
func (s *Store) AvailableNodeNativePairs(rpc NodeControlRPCInput, controlPublic e2ee.PublicIdentity) (*nodewire.AvailableNativePairs, error) {
	if rpc.Operation != nodewire.NativePairAvailableOperation {
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
	at := time.Now().UTC()
	rows, err := tx.Query(`SELECT p.pair_id FROM hub_native_pairs_v1 p
WHERE p.owner_id=? AND p.node_id=? AND p.state IN('WAITING_JOIN','WAITING_CONSENT')
 AND cicada_network_expiry_allows(p.join_until,?)=1
 AND cicada_network_expiry_allows(p.peer_expires_at,?)=1
 AND EXISTS(SELECT 1 FROM hub_native_pair_slots_v1 slot WHERE slot.pair_id=p.pair_id
   AND slot.state='RESERVED' AND slot.attempt_id='')
 AND NOT EXISTS(SELECT 1 FROM hub_native_pair_slots_v1 joined
   LEFT JOIN session_bindings binding ON binding.id=joined.binding_id
   LEFT JOIN fabric_endpoints endpoint ON endpoint.id=joined.endpoint_id
   WHERE joined.pair_id=p.pair_id AND joined.state IN('JOINED_ZERO','ACTIVE')
   AND (endpoint.id IS NULL OR endpoint.status='left' OR binding.id IS NULL
    OR binding.status NOT IN ('active','leased','online','ready','acquired')
    OR cicada_network_expiry_allows(binding.lease_expires_at,?)=0))
ORDER BY p.pair_id LIMIT 65`, owner, rpc.NodeID, appNodeStamp(at), appNodeStamp(at), appNodeStamp(at))
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := &nodewire.AvailableNativePairs{Pairs: []nodewire.AvailableNativePair{}, Truncated: len(ids) > 64}
	if len(ids) > 64 {
		ids = ids[:64]
	}
	for _, id := range ids {
		p, err := readNativePair(tx, id)
		if err != nil {
			return nil, err
		}
		if p == nil || !appNodeBefore(at, p.joinUntil) || !appNodeBefore(at, p.peerExpires) {
			continue
		}
		if nativePairNodeCurrentTx(tx, p, HubNativePairNodeInput{Hub: p.accountHub, NodeControlPublic: controlPublic, At: at}, rpc) != nil {
			continue
		}
		card := nodewire.AvailableNativePair{PairID: p.id, Label: p.bootstrap.GroupLabel, JoinUntil: p.joinUntil, Slots: []nodewire.AvailableNativePairSlot{}}
		slots, err := tx.Query(`SELECT slot,generation FROM hub_native_pair_slots_v1 WHERE pair_id=? AND state='RESERVED' AND attempt_id='' ORDER BY slot`, id)
		if err != nil {
			return nil, err
		}
		for slots.Next() {
			var v nodewire.AvailableNativePairSlot
			if err = slots.Scan(&v.Slot, &v.Generation); err != nil {
				slots.Close()
				return nil, err
			}
			card.Slots = append(card.Slots, v)
		}
		err = slots.Err()
		slots.Close()
		if err != nil {
			return nil, err
		}
		if len(card.Slots) > 0 {
			result.Pairs = append(result.Pairs, card)
		}
	}
	return result, nil
}
