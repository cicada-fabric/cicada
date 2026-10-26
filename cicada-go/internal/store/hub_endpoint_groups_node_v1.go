package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// The transport authenticates and decrypts the exact packet before calling the
// Store. Historical authentication is deliberately separate from admission.
type HubEndpointGroupsNodeInput = HubLocalDomainNodeInput
type HubEndpointGroupsNodeOutput = HubLocalDomainNodeOutput
type HubEndpointGroupsNodeSeal = HubLocalDomainNodeSeal

const endpointGroupsNodeReadLifetime = 5 * time.Minute

func endpointGroupsNodeInput(in HubEndpointGroupsNodeInput) (NodeControlRPCInput, error) {
	p, err := wire.DecodeEndpointGroupsNodePacket(in.Packet)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest || in.At.IsZero() || p.Route.HubID != in.Hub.HubID {
		return NodeControlRPCInput{}, ErrHubAccountRejected
	}
	raw, err := json.Marshal(in.Body)
	if err != nil {
		return NodeControlRPCInput{}, err
	}
	body, err := wire.DecodeEndpointGroupsNodeRequest(p.Route.Operation, raw)
	if err != nil || !reflect.DeepEqual(body, in.Body) {
		return NodeControlRPCInput{}, ErrHubAccountRejected
	}
	r := p.Route
	digest := sha256.Sum256(in.Packet)
	return NodeControlRPCInput{CredentialDigest: in.CredentialDigest, NodeID: r.NodeID, BindingID: r.BindingID, BindingVersion: r.BindingVersion, NodeKeyID: r.SenderKeyID, NodeKeyEpoch: r.NodeKeyEpoch, Sequence: r.Sequence, OperationID: r.OperationID, Operation: r.Operation, RequestDigest: hex.EncodeToString(digest[:])}, nil
}

func (s *Store) ProcessHubEndpointGroupsNode(in HubEndpointGroupsNodeInput, seal HubEndpointGroupsNodeSeal) ([]byte, error) {
	if seal == nil || s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	g, err := tx.Exec(`UPDATE hub_endpoint_groups_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := g.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	// Sample time only after the SQLite writer fence as well as the Go mutex.
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	rpc, err := endpointGroupsNodeInput(in)
	if err != nil {
		return nil, err
	}
	p, err := wire.DecodeEndpointGroupsNodePacket(in.Packet)
	if err != nil {
		return nil, err
	}
	if _, err = localDomainRetainedNodeTx(tx, in.CredentialDigest, p.Route, in.Hub, in.NodeControlPublic); err != nil {
		return nil, err
	}
	var out localDomainReceipt
	if rpc.Operation == wire.OperationEndpointGroupsNodeReconcile {
		out, err = endpointGroupsNodeReconcileTx(tx, in, rpc, seal)
	} else {
		out, err = endpointGroupsNodeBusinessTx(tx, in, rpc, seal, false)
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out.packet, nil
}

func endpointGroupsNodeReadOperation(op string) bool {
	return op == wire.OperationEndpointGroupsNodeDescribe || op == wire.OperationEndpointGroupsNodeKeyPrepare || op == wire.OperationEndpointGroupsNodeReconcile
}

func endpointGroupsNodeCachedTx(tx *sql.Tx, rpc NodeControlRPCInput, at time.Time) (localDomainReceipt, error) {
	for _, table := range []string{"hub_endpoint_groups_node_operations_v1", "hub_endpoint_groups_node_reads_v1"} {
		var op, id, digest, created string
		var seq uint64
		var r localDomainReceipt
		predicate := "(operation_id=? OR sequence=?)"
		args := []any{rpc.BindingID, rpc.NodeKeyEpoch, rpc.OperationID, rpc.Sequence}
		if table == "hub_endpoint_groups_node_reads_v1" || rpc.Operation == wire.OperationEndpointGroupsNodeReconcile {
			predicate = "operation_id=?"
			args = args[:3]
		}
		err := tx.QueryRow(`SELECT sequence,operation_id,operation,request_digest,state,response_packet,created_at FROM `+table+` WHERE owner_binding_id=? AND node_key_epoch=? AND `+predicate, args...).Scan(&seq, &id, &op, &digest, &r.state, &r.packet, &created)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return r, err
		}
		if seq != rpc.Sequence || id != rpc.OperationID || op != rpc.Operation || digest != rpc.RequestDigest {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		if table == "hub_endpoint_groups_node_operations_v1" {
			return r, nil
		}
		start, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		if at.Before(start.Add(endpointGroupsNodeReadLifetime)) {
			return r, nil
		}
	}
	return localDomainReceipt{}, nil
}

func endpointGroupsNodeRateTx(tx *sql.Tx, rpc NodeControlRPCInput, at time.Time) error {
	var start string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_endpoint_groups_node_rates_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, rpc.BindingID, rpc.NodeKeyEpoch).Scan(&start, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		then, e := time.Parse(time.RFC3339Nano, start)
		if e != nil || at.Before(then) {
			return ErrHubAccountRejected
		}
		if at.Before(then.Add(time.Minute)) {
			if count >= 128 {
				return ErrHubOwnerDiagnosticsFull
			}
			count++
		} else {
			count = 1
			start = appNodeStamp(at)
		}
	} else {
		count = 1
		start = appNodeStamp(at)
	}
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_node_rates_v1 VALUES(?,?,?,?) ON CONFLICT(owner_binding_id,node_key_epoch) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, rpc.BindingID, rpc.NodeKeyEpoch, start, count)
	return err
}

func endpointGroupsNodeSaveTx(tx *sql.Tx, rpc NodeControlRPCInput, state string, packet []byte, at time.Time, admitted bool) error {
	limit := wire.MaxEndpointGroupsNodeReceiptBytes
	if rpc.Operation == wire.OperationEndpointGroupsNodeReconcile {
		limit = wire.MaxEndpointGroupsNodeReconcilePacketBytes
	}
	if len(packet) == 0 || len(packet) > limit {
		return ErrHubAccountRejected
	}
	if endpointGroupsNodeReadOperation(rpc.Operation) {
		rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_endpoint_groups_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, rpc.BindingID, rpc.NodeKeyEpoch)
		if err != nil {
			return err
		}
		var drop []string
		kept := 0
		for rows.Next() {
			var id, created string
			if err = rows.Scan(&id, &created); err != nil {
				break
			}
			start, e := time.Parse(time.RFC3339Nano, created)
			if e != nil {
				err = ErrHubAccountRejected
				break
			}
			if !at.Before(start.Add(endpointGroupsNodeReadLifetime)) || id == rpc.OperationID {
				drop = append(drop, id)
			} else {
				kept++
			}
		}
		re := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if re != nil {
			return re
		}
		if kept >= 128 {
			return ErrHubOwnerDiagnosticsFull
		}
		for _, id := range drop {
			if _, err = tx.Exec(`DELETE FROM hub_endpoint_groups_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, rpc.BindingID, rpc.NodeKeyEpoch, id); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO hub_endpoint_groups_node_reads_v1 VALUES(?,?,?,?,?,?,?,?,?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest, state, packet, appNodeStamp(at)); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO hub_endpoint_groups_node_operations_v1 VALUES(?,?,?,?,?,?,?,?,?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest, state, packet, appNodeStamp(at)); err != nil {
			return err
		}
	}
	if admitted {
		r, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=X'',updated_at=? WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=? AND operation=? AND request_digest=? AND state='PROCESSING'`, appNodeStamp(at), rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest)
		if err != nil {
			return err
		}
		if n, e := r.RowsAffected(); e != nil || n != 1 {
			return ErrNodeControlRPCConflict
		}
	}
	// Only read metadata is reclaimed. Shared sequence highwater and mutations
	// remain permanent, including rejected mutations and unseen-original fences.
	_, err := tx.Exec(`DELETE FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation IN('node.endpoint_groups.describe','node.endpoint_groups.key_prepare') AND state='COMPLETE' AND julianday(created_at)<julianday(?)`, rpc.BindingID, rpc.NodeKeyEpoch, appNodeStamp(at.Add(-endpointGroupsNodeReadLifetime)))
	return err
}

func endpointGroupsNodeBusinessTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, rpc NodeControlRPCInput, seal HubEndpointGroupsNodeSeal, fence bool) (localDomainReceipt, error) {
	old, err := endpointGroupsNodeCachedTx(tx, rpc, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if err = endpointGroupsNodeRateTx(tx, rpc, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	var high uint64
	err = tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, rpc.BindingID, rpc.NodeKeyEpoch).Scan(&high)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return localDomainReceipt{}, err
	}
	if rpc.Sequence <= high {
		if !endpointGroupsNodeReadOperation(rpc.Operation) {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		packet, e := seal(HubEndpointGroupsNodeOutput{ErrorCode: "READ_EXPIRED"})
		if e != nil {
			return localDomainReceipt{}, e
		}
		if e = endpointGroupsNodeSaveTx(tx, rpc, wire.AppNodeReadExpired, packet, in.At, false); e != nil {
			return localDomainReceipt{}, e
		}
		return localDomainReceipt{packet: packet, state: wire.AppNodeReadExpired}, nil
	}
	if rpc.Sequence != high+1 {
		return localDomainReceipt{}, ErrNodeControlRPCConflict
	}
	if err = nativePairNodeAdmitTx(tx, rpc, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	state := wire.AppNodeCompleted
	out := HubEndpointGroupsNodeOutput{}
	if fence {
		out.ErrorCode = "TARGET_NOT_AUTHORIZED"
		state = wire.AppNodeRejectedFenced
		if endpointGroupsNodeReadOperation(rpc.Operation) {
			out.ErrorCode = "READ_EXPIRED"
			state = wire.AppNodeReadExpired
		}
	} else {
		if _, err = tx.Exec(`SAVEPOINT endpoint_groups_node_effect`); err != nil {
			return localDomainReceipt{}, err
		}
		out.Result, err = endpointGroupsNodeEffectTx(tx, in, rpc)
		if err != nil {
			if _, e := tx.Exec(`ROLLBACK TO endpoint_groups_node_effect`); e != nil {
				return localDomainReceipt{}, e
			}
			out = HubEndpointGroupsNodeOutput{ErrorCode: "TARGET_NOT_AUTHORIZED"}
			state = wire.AppNodeRejectedFenced
		}
		if _, err = tx.Exec(`RELEASE endpoint_groups_node_effect`); err != nil {
			return localDomainReceipt{}, err
		}
	}
	packet, err := seal(out)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = endpointGroupsNodeSaveTx(tx, rpc, state, packet, in.At, true); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: state}, nil
}

func endpointGroupsNodeReconcileTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, rpc NodeControlRPCInput, seal HubEndpointGroupsNodeSeal) (localDomainReceipt, error) {
	old, err := endpointGroupsNodeCachedTx(tx, rpc, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if err = endpointGroupsNodeRateTx(tx, rpc, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	q, ok := in.Body.(wire.EndpointGroupsNodeReconcile)
	if !ok || in.Original == nil || in.OriginalSeal == nil {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	original := *in.Original
	original.At = in.At
	original.Now = nil
	orpc, err := endpointGroupsNodeInput(original)
	if err != nil || orpc.Operation == wire.OperationEndpointGroupsNodeReconcile || orpc.BindingID != rpc.BindingID || orpc.NodeKeyEpoch != rpc.NodeKeyEpoch || orpc.NodeID != rpc.NodeID || original.CredentialDigest != in.CredentialDigest || !reflect.DeepEqual(original.Hub, in.Hub) || !reflect.DeepEqual(original.NodeControlPublic, in.NodeControlPublic) || !bytes.Equal(q.OriginalPacket, original.Packet) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	op, err := wire.DecodeEndpointGroupsNodePacket(original.Packet)
	if err != nil {
		return localDomainReceipt{}, err
	}
	wrapper, _ := wire.DecodeEndpointGroupsNodePacket(in.Packet)
	expectedRoute := op.Route
	expectedRoute.Operation = wrapper.Route.Operation
	expectedRoute.OperationID = wrapper.Route.OperationID
	if !reflect.DeepEqual(expectedRoute, wrapper.Route) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	if _, err = localDomainRetainedNodeTx(tx, original.CredentialDigest, op.Route, in.Hub, in.NodeControlPublic); err != nil {
		return localDomainReceipt{}, err
	}
	// Reconcile has its own request identity but consumes only the original's
	// next sequence. It never invokes original business, even when unseen.
	r, err := endpointGroupsNodeBusinessTx(tx, original, orpc, in.OriginalSeal, true)
	if err != nil {
		return localDomainReceipt{}, err
	}
	body := wire.EndpointGroupsNodeReconciled{ContractRevision: wire.OwnerEndpointGroupsContractRevision, OriginalOperation: orpc.Operation, OriginalOperationID: orpc.OperationID, OriginalSequence: orpc.Sequence, OriginalPacketDigest: orpc.RequestDigest, State: r.state, ReceiptPacket: r.packet, ObservedAt: appNodeStamp(in.At)}
	packet, err := seal(HubEndpointGroupsNodeOutput{Result: body})
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = endpointGroupsNodeSaveTx(tx, rpc, r.state, packet, in.At, false); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: r.state}, nil
}

func endpointGroupsNodeRegistrationTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, b *NodeControlKeyBinding, endpoint string) (*hubEndpointGroupsRegistration, error) {
	r, err := endpointGroupsRegistrationTx(tx, endpoint)
	if err != nil || r == nil || r.anchor.Registration.OwnerID != b.OwnerID || r.anchor.Registration.NodeID != b.NodeID || r.anchor.NodeKeyEpoch != b.NodeKeyEpoch || !reflect.DeepEqual(r.hub, in.Hub) || endpointGroupsRegistrationCurrentTx(tx, r, in.At) != nil {
		return nil, ErrNetworkPermission
	}
	return r, nil
}

func endpointGroupsNodeEffectTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, rpc NodeControlRPCInput) (any, error) {
	b, err := localDomainNodeCurrentTx(tx, in, rpc)
	if err != nil {
		return nil, err
	}
	switch q := in.Body.(type) {
	case wire.EndpointGroupsNodeDescribe:
		r, err := endpointGroupsEnsureRegistrationTx(tx, b.OwnerID, b.NodeID, q.NetworkID, q.EndpointID, in.Hub, in.NodeControlPublic, in.At)
		if err != nil {
			return nil, err
		}
		return endpointGroupsNodeDescribeTx(tx, in, r, q)
	case wire.EndpointGroupsNodeKeyPrepare:
		r, err := endpointGroupsNodeRegistrationTx(tx, in, b, q.EndpointID)
		if err != nil {
			return nil, err
		}
		return endpointGroupsNodeKeyPrepareTx(tx, in, r, q)
	case wire.EndpointGroupsNodeKeyComplete:
		r, err := endpointGroupsNodeRegistrationTx(tx, in, b, q.EndpointID)
		if err != nil {
			return nil, err
		}
		return endpointGroupsNodeKeyCompleteTx(tx, in, r, q)
	case wire.EndpointGroupsNodeRenew:
		r, err := endpointGroupsNodeRegistrationTx(tx, in, b, q.EndpointID)
		if err != nil {
			return nil, err
		}
		return endpointGroupsNodeRenewTx(tx, in, r, q)
	}
	return nil, ErrHubAccountRejected
}

func endpointGroupsNodeDescribeTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, q wire.EndpointGroupsNodeDescribe) (any, error) {
	cards, err := endpointGroupsRelationCardsTx(tx, r, in.At)
	if err != nil {
		return nil, err
	}
	scope := fmt.Sprintf("node/%s/%s/%s/%s", r.anchor.Registration.OwnerID, r.anchor.Registration.NodeID, r.anchor.NetworkID, r.anchor.Registration.EndpointID)
	digest := endpointGroupsDigest(cards)
	after, err := endpointGroupsCursorAfter(q.Cursor, scope, digest)
	if err != nil {
		return nil, err
	}
	limit := q.Limit
	if limit == 0 {
		limit = 32
	}
	result := wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: r.anchor, Relations: []wire.OwnerEndpointGroupsRelationCard{}, Authorities: []wire.EndpointGroupCurrentEndpoint{}, RelationsRevision: r.listing, Complete: true, ObservedAt: appNodeStamp(in.At)}
	last := ""
	for _, card := range cards {
		if card.GroupID <= after {
			continue
		}
		if len(result.Relations) >= limit {
			result.Complete = false
			result.NextCursor = endpointGroupsPageCursor(scope, digest, last)
			break
		}
		_, authority, _, e := endpointGroupsResolveTx(tx, r, card.GroupID, in.At, false)
		if e != nil || (card.State == "ACTIVE") != (authority != nil) {
			return nil, ErrNetworkPermission
		}
		result.Relations = append(result.Relations, card)
		if authority != nil {
			result.Authorities = append(result.Authorities, *authority)
		}
		raw, e := json.Marshal(result)
		if e != nil {
			return nil, e
		}
		// Reserve enough space for a final cursor while measuring the actual DTO.
		if len(raw)+1024 > wire.MaxOwnerEndpointGroupsPageBytes {
			result.Relations = result.Relations[:len(result.Relations)-1]
			if authority != nil {
				result.Authorities = result.Authorities[:len(result.Authorities)-1]
			}
			if len(result.Relations) == 0 {
				return nil, ErrHubAccountRejected
			}
			result.Complete = false
			result.NextCursor = endpointGroupsPageCursor(scope, digest, last)
			break
		}
		last = card.GroupID
	}
	if wire.ValidateEndpointGroupsNodeDescribeResult(result, in.Hub, in.At) != nil {
		return nil, ErrNetworkPermission
	}
	return result, nil
}
