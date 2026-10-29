package store

import (
	"bytes"
	"database/sql"
	"errors"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func appNodeScopedDiagnosticRate(tx *sql.Tx, owner, device string, at time.Time) error {
	var start string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_app_node_rates_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&start, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	window, parseErr := time.Parse(time.RFC3339Nano, start)
	if parseErr != nil || !at.Before(window.Add(time.Minute)) {
		start = appNodeStamp(at)
		count = 0
	}
	if count >= wire.MaxAppNodeScopedDiagnosticsPerMinute {
		return ErrHubOwnerDiagnosticsFull
	}
	_, err = tx.Exec(`INSERT INTO hub_app_node_rates_v1(owner_id,device_id,window_start,requests) VALUES(?,?,?,?) ON CONFLICT(owner_id,device_id) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, owner, device, start, count+1)
	return err
}

func appNodeScopedReconcile(tx *sql.Tx, a *hubAppNodeScopedActor, in HubAppNodeScopedAuthorityInput, seal HubAppNodeScopedSeal) ([]byte, error) {
	req, ok := in.Body.(wire.AppNodeScopedReconcile)
	if !ok {
		return nil, ErrHubAccountRejected
	}
	if req.AuthorityNodeID != a.scope.AuthorityNodeID {
		return nil, ErrHubAccountRejected
	}
	c := req.Context
	if err := appNodeScopedDiagnosticRate(tx, c.OwnerID, c.DeviceID, in.At); err != nil {
		return nil, err
	}
	var originalOperation, originalID, state string
	var receipt []byte
	var err error
	switch req.OriginalKind {
	case wire.AppNodeScopedOriginalAuthority:
		if in.Original == nil || in.OriginalSeal == nil || !bytes.Equal(req.OriginalPacket, in.Original.Packet) || !reflect.DeepEqual(in.Device, in.Original.Device) || !reflect.DeepEqual(in.Hub, in.Original.Hub) {
			return nil, ErrHubAccountRejected
		}
		original := *in.Original
		original.At = in.At
		oc, _, op, originalGrant, e := appNodeScopedInputRoute(original)
		if e != nil || req.GrantID != originalGrant || !wire.AppNodeScopedReconcileOriginalAllowed(req.OriginalKind, op) || oc.OwnerID != c.OwnerID || oc.DeviceID != c.DeviceID || oc.AccountID != c.AccountID || oc.Origin != c.Origin {
			return nil, ErrHubAccountRejected
		}
		originalOperation, originalID = op, oc.RequestID
		originalNode, e := appNodeScopedInputNode(tx, original)
		if status, ok := original.Body.(wire.AppNodeScopedStatus); ok && status.Target.CandidateCode != "" && errors.Is(e, sql.ErrNoRows) {
			// Anonymous GC may remove the only code-to-Node mapping. Settle
			// this authenticated read without consulting its old cache or
			// executing it. No original receipt or authority crosses Nodes.
			state = wire.AppNodeScopedReadExpired
			break
		}
		if e != nil || originalNode != req.AuthorityNodeID {
			return nil, ErrHubAccountRejected
		}
		receipt, state, err = appNodeCached(tx, c.OwnerID, c.DeviceID, oc.RequestID, op, wire.AppNodeScopedPacketDigest(original.Packet), in.At)
		if err != nil {
			return nil, err
		}
		if len(receipt) == 0 {
			receipt, err = appNodeScopedAuthority(tx, a, original, in.OriginalSeal, true)
			if err != nil {
				return nil, err
			}
			if op == wire.OperationAppNodeScopedStatus {
				state = wire.AppNodeScopedReadExpired
			} else {
				state = wire.AppNodeScopedRejectedFenced
			}
		}
		if state == wire.AppNodeScopedReadExpired {
			receipt = nil
		}
	case wire.AppNodeScopedOriginalClient:
		if in.OriginalClient == nil || !bytes.Equal(req.OriginalPacket, in.OriginalClient.Packet) || !reflect.DeepEqual(in.Device, in.OriginalClient.Device) || !reflect.DeepEqual(in.Hub, in.OriginalClient.Hub) {
			return nil, ErrHubAccountRejected
		}
		original := *in.OriginalClient
		original.At = in.At
		grant, _, e := wire.ParseAppNodeScopedBusinessOperationID(original.Route.OperationID)
		if e != nil || grant != req.GrantID || original.Route.OwnerID != c.OwnerID || original.Route.DeviceID != c.DeviceID || original.Route.Operation != "nodes.confirm" {
			return nil, ErrHubAccountRejected
		}
		originalNode, e := appNodeScopedGrantNode(tx, c.OwnerID, c.DeviceID, grant)
		if e != nil || originalNode != req.AuthorityNodeID {
			return nil, ErrHubAccountRejected
		}
		originalOperation, originalID = original.Route.Operation, original.Route.OperationID
		receipt, state, err = appNodeScopedClient(tx, a, original, true)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrHubAccountRejected
	}
	h, err := appNodeScopedHead(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID)
	if err != nil {
		return nil, err
	}
	current := wire.AppNodeScopedAbsent
	if g, e := appNodeScopedGrant(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, req.GrantID); e != nil {
		return nil, e
	} else if g != nil {
		current, _ = appNodeScopedEffectiveState(tx, a, g, in.At)
	}
	v := wire.AppNodeScopedReconciled{AuthorityNodeID: a.scope.AuthorityNodeID, Format: wire.AppNodeScopedReconciledFormat, Origin: a.scope.Origin, HubID: a.scope.HubID, AccountID: a.scope.AccountID, OwnerID: c.OwnerID, DeviceID: c.DeviceID, RequestID: c.RequestID, RequestPacketDigest: wire.AppNodeScopedPacketDigest(in.Packet), GrantID: req.GrantID, OriginalKind: req.OriginalKind, OriginalOperation: originalOperation, OriginalRequestID: originalID, OriginalPacketDigest: wire.AppNodeScopedPacketDigest(req.OriginalPacket), State: state, ReceiptPacket: receipt, AccountEpoch: a.scope.AccountEpoch, DeviceEpoch: a.scope.DeviceEpoch, CurrentHeadVersion: h.version, CurrentGrantState: current, ObservedAt: appNodeStamp(in.At)}
	packet, err := seal(v)
	if err != nil {
		return nil, err
	}
	if err = appNodeSaveRead(tx, c, wire.OperationAppNodeScopedReconcile, v.RequestPacketDigest, state, packet, in.At); err != nil {
		return nil, err
	}
	return packet, nil
}
