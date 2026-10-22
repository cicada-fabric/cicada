package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type HubLocalDomainNodeInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	CredentialDigest  string
	Packet            []byte
	Body              any
	SessionToken      string
	At                time.Time
	Now               func() time.Time
	Original          *HubLocalDomainNodeInput
	OriginalSeal      HubLocalDomainNodeSeal
}
type HubLocalDomainNodeOutput struct {
	Result    any
	ErrorCode string
}
type HubLocalDomainNodeSeal func(HubLocalDomainNodeOutput) ([]byte, error)

func localDomainNodeInput(in HubLocalDomainNodeInput) (NodeControlRPCInput, string, error) {
	p, err := wire.DecodeLocalDomainNodePacket(in.Packet)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest || in.At.IsZero() {
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	var op, id string
	switch q := in.Body.(type) {
	case wire.LocalDomainNodeAvailable:
		op = wire.OperationLocalDomainNodeAvailable
	case wire.LocalDomainNodeJoin:
		op, id = wire.OperationLocalDomainNodeJoin, q.Selection.PolicyID
	case wire.LocalDomainNodeKeyPrepare:
		op, id = wire.OperationLocalDomainNodeKeyPrepare, q.Selection.PolicyID
	case wire.LocalDomainNodeKeyComplete:
		op, id = wire.OperationLocalDomainNodeKeyComplete, q.Selection.PolicyID
	case wire.LocalDomainNodeDescribe:
		op, id = wire.OperationLocalDomainNodeDescribe, q.Selection.PolicyID
	case wire.LocalDomainNodeReconcile:
		op = wire.OperationLocalDomainNodeReconcile
	default:
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	raw, err := json.Marshal(in.Body)
	if err != nil {
		return NodeControlRPCInput{}, "", err
	}
	if _, err = wire.DecodeLocalDomainNodeRequest(op, raw); err != nil || op != p.Route.Operation || p.Route.HubID != in.Hub.HubID {
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	r := p.Route
	digest := sha256.Sum256(in.Packet)
	return NodeControlRPCInput{CredentialDigest: in.CredentialDigest, NodeID: r.NodeID, BindingID: r.BindingID, BindingVersion: r.BindingVersion, NodeKeyID: r.SenderKeyID, NodeKeyEpoch: r.NodeKeyEpoch, Sequence: r.Sequence, OperationID: r.OperationID, Operation: r.Operation, RequestDigest: hex.EncodeToString(digest[:])}, id, nil
}

func (s *Store) HubLocalDomainNodeKey(credential string, r nodewire.Route, hub wire.HubIdentity, control e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return localDomainRetainedNodeTx(tx, credential, r, hub, control)
}

func localDomainRetainedNodeTx(tx *sql.Tx, credential string, r nodewire.Route, hub wire.HubIdentity, control e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	if r.Direction != nodewire.DirectionRequest || r.HubID != hub.HubID || !validNodeCredentialDigest(credential) {
		return nil, ErrNodeControlKeyUnauthorized
	}
	b, err := localDomainNodeBindingTx(tx, r.NodeID, credential, r.NodeKeyEpoch, false)
	if err != nil || b.OwnerBindingID != r.BindingID || b.HubID != hub.HubID || b.NodeKeyID != r.SenderKeyID || b.NodeKeyVersion != r.SenderKeyVersion || b.HubKeyID != r.ReceiverKeyID || b.HubKeyVersion != r.ReceiverKeyVersion || !reflect.DeepEqual(b.HubPublicIdentity, control) {
		return nil, ErrNodeControlKeyUnauthorized
	}
	// The retained key authenticates the signed historical route, not current
	// authority. Revocation may have advanced b.version; business admission
	// independently requires the actual current binding version below.
	b.BindingVersion = r.BindingVersion
	return b, nil
}

func localDomainNodeCurrentTx(tx *sql.Tx, in HubLocalDomainNodeInput, rpc NodeControlRPCInput) (*NodeControlKeyBinding, error) {
	b, err := localDomainNodeBindingTx(tx, rpc.NodeID, rpc.CredentialDigest, rpc.NodeKeyEpoch, true)
	if err != nil || b.OwnerBindingID != rpc.BindingID || b.BindingVersion != rpc.BindingVersion || b.NodeKeyID != rpc.NodeKeyID || b.HubID != in.Hub.HubID || !reflect.DeepEqual(b.HubPublicIdentity, in.NodeControlPublic) {
		return nil, ErrNodeControlKeyUnauthorized
	}
	return b, nil
}

func (s *Store) ProcessHubLocalDomainNode(in HubLocalDomainNodeInput, seal HubLocalDomainNodeSeal) ([]byte, error) {
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
	g, err := tx.Exec(`UPDATE hub_local_domain_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := g.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	rpc, policy, err := localDomainNodeInput(in)
	if err != nil {
		return nil, err
	}
	p, err := wire.DecodeLocalDomainNodePacket(in.Packet)
	if err != nil {
		return nil, err
	}
	if _, err = localDomainRetainedNodeTx(tx, in.CredentialDigest, p.Route, in.Hub, in.NodeControlPublic); err != nil {
		return nil, err
	}
	var out localDomainReceipt
	if rpc.Operation == wire.OperationLocalDomainNodeReconcile {
		out, err = localDomainNodeReconcileTx(tx, in, rpc, seal)
	} else {
		out, err = localDomainNodeBusinessTx(tx, in, rpc, policy, seal, false)
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out.packet, nil
}

func localDomainNodeCachedTx(tx *sql.Tx, rpc NodeControlRPCInput, at time.Time) (localDomainReceipt, error) {
	for _, table := range []string{"hub_local_domain_node_operations_v1", "hub_local_domain_node_reads_v1"} {
		var op, digest, created string
		var seq uint64
		var r localDomainReceipt
		err := tx.QueryRow(`SELECT sequence,operation,request_digest,state,response_packet,created_at FROM `+table+` WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.OperationID).Scan(&seq, &op, &digest, &r.state, &r.packet, &created)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return r, err
		}
		if seq != rpc.Sequence || op != rpc.Operation || digest != rpc.RequestDigest {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		if table == "hub_local_domain_node_operations_v1" {
			return r, nil
		}
		start, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		if at.Before(start.Add(localDomainReadLifetime)) {
			return r, nil
		}
	}
	return localDomainReceipt{}, nil
}

func localDomainNodeReadOperation(op string) bool {
	return op == wire.OperationLocalDomainNodeAvailable || op == wire.OperationLocalDomainNodeDescribe || op == wire.OperationLocalDomainNodeReconcile
}

func localDomainNodeSaveTx(tx *sql.Tx, rpc NodeControlRPCInput, policy, state string, packet []byte, at time.Time, admitted bool) error {
	if len(packet) == 0 || len(packet) > wire.MaxLocalDomainNodeReconcilePacketBytes {
		return ErrHubAccountRejected
	}
	if localDomainNodeReadOperation(rpc.Operation) {
		rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_local_domain_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, rpc.BindingID, rpc.NodeKeyEpoch)
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
			if !at.Before(start.Add(localDomainReadLifetime)) || id == rpc.OperationID {
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
			if _, err = tx.Exec(`DELETE FROM hub_local_domain_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, rpc.BindingID, rpc.NodeKeyEpoch, id); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO hub_local_domain_node_reads_v1 VALUES(?,?,?,?,?,?,?,?,?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest, state, packet, appNodeStamp(at)); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO hub_local_domain_node_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, policy, rpc.RequestDigest, state, packet, appNodeStamp(at)); err != nil {
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
	// Read metadata can be reclaimed; only the permanent highwater determines
	// whether a sequence can run. Mutation rows and exact receipts remain.
	_, err := tx.Exec(`DELETE FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation IN('node.local_domain.available','node.local_domain.describe') AND state='COMPLETE' AND julianday(created_at)<julianday(?)`, rpc.BindingID, rpc.NodeKeyEpoch, appNodeStamp(at.Add(-localDomainReadLifetime)))
	return err
}

func localDomainNodeBusinessTx(tx *sql.Tx, in HubLocalDomainNodeInput, rpc NodeControlRPCInput, policy string, seal HubLocalDomainNodeSeal, fence bool) (localDomainReceipt, error) {
	old, err := localDomainNodeCachedTx(tx, rpc, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if err = localDomainRateTx(tx, "NODE", rpc.BindingID, rpc.NodeKeyEpoch, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	read := localDomainNodeReadOperation(rpc.Operation)
	var high uint64
	err = tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, rpc.BindingID, rpc.NodeKeyEpoch).Scan(&high)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return localDomainReceipt{}, err
	}
	if rpc.Sequence <= high {
		if !read {
			return localDomainReceipt{}, ErrNodeControlRPCConflict
		}
		packet, err := seal(HubLocalDomainNodeOutput{ErrorCode: "READ_EXPIRED"})
		if err != nil {
			return localDomainReceipt{}, err
		}
		if err = localDomainNodeSaveTx(tx, rpc, policy, wire.AppNodeReadExpired, packet, in.At, false); err != nil {
			return localDomainReceipt{}, err
		}
		return localDomainReceipt{packet: packet, state: wire.AppNodeReadExpired, policy: policy}, nil
	}
	if rpc.Sequence != high+1 {
		return localDomainReceipt{}, ErrNodeControlRPCConflict
	}
	if err = nativePairNodeAdmitTx(tx, rpc, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	state := wire.AppNodeCompleted
	out := HubLocalDomainNodeOutput{}
	if fence {
		out.ErrorCode = "REJECTED_UNADMITTED"
		state = wire.AppNodeRejectedFenced
	} else {
		if _, err = tx.Exec(`SAVEPOINT local_domain_node_effect`); err != nil {
			return localDomainReceipt{}, err
		}
		out.Result, err = localDomainNodeEffectTx(tx, in, rpc)
		if err != nil {
			if _, e := tx.Exec(`ROLLBACK TO local_domain_node_effect`); e != nil {
				return localDomainReceipt{}, e
			}
			out = HubLocalDomainNodeOutput{ErrorCode: "LOCAL_DOMAIN_REJECTED"}
			state = wire.AppNodeRejectedFenced
		}
		if _, err = tx.Exec(`RELEASE local_domain_node_effect`); err != nil {
			return localDomainReceipt{}, err
		}
	}
	packet, err := seal(out)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainNodeSaveTx(tx, rpc, policy, state, packet, in.At, true); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: state, policy: policy}, nil
}

func localDomainNodeReconcileTx(tx *sql.Tx, in HubLocalDomainNodeInput, rpc NodeControlRPCInput, seal HubLocalDomainNodeSeal) (localDomainReceipt, error) {
	old, err := localDomainNodeCachedTx(tx, rpc, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if err = localDomainRateTx(tx, "NODE", rpc.BindingID, rpc.NodeKeyEpoch, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	q, ok := in.Body.(wire.LocalDomainNodeReconcile)
	if !ok || in.Original == nil || in.OriginalSeal == nil {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	issued, err := time.Parse(time.RFC3339Nano, q.IssuedAt)
	if err != nil || issued.After(in.At.Add(30*time.Second)) || !in.At.Before(issued.Add(time.Minute)) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	original := *in.Original
	original.At = in.At
	original.Now = nil
	orpc, policy, err := localDomainNodeInput(original)
	if err != nil || orpc.Operation == wire.OperationLocalDomainNodeReconcile || orpc.BindingID != rpc.BindingID || orpc.NodeKeyEpoch != rpc.NodeKeyEpoch || orpc.NodeID != rpc.NodeID || original.CredentialDigest != in.CredentialDigest || !bytes.Equal(q.OriginalPacket, original.Packet) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	r, err := localDomainNodeBusinessTx(tx, original, orpc, policy, in.OriginalSeal, true)
	if err != nil {
		return localDomainReceipt{}, err
	}
	body := wire.LocalDomainNodeReconciled{ContractRevision: wire.LocalDomainContractRevision, OriginalOperation: orpc.Operation, OriginalOperationID: orpc.OperationID, OriginalSequence: orpc.Sequence, OriginalPacketDigest: wire.LocalDomainPacketDigest(original.Packet), State: r.state, ReceiptPacket: r.packet, ObservedAt: appNodeStamp(in.At)}
	packet, err := seal(HubLocalDomainNodeOutput{Result: body})
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainNodeSaveTx(tx, rpc, policy, r.state, packet, in.At, false); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: r.state, policy: policy}, nil
}
