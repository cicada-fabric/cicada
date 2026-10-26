package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

var errNativePairNodeRejected = errors.New("native Pair operation has an authenticated terminal refusal; no new Join was issued")

// These records stay in the existing bounded private Node-Control state file.
// They never cross the model boundary. The signed response is retained before
// the shared outbox is cleared, including startup recovery without an MCP caller.
type machineNativePairReceipt struct {
	Operation          string `json:"operation"`
	PairID             string `json:"pair_id"`
	RequestBody        []byte `json:"request_body"`
	RequestPacket      []byte `json:"request_packet"`
	ResponsePacket     []byte `json:"response_packet"`
	DiagnosticPacket   []byte `json:"diagnostic_packet,omitempty"`
	DiagnosticResponse []byte `json:"diagnostic_response,omitempty"`
	Sequence           uint64 `json:"sequence"`
	Consumed           bool   `json:"consumed,omitempty"`
	Fenced             bool   `json:"fenced,omitempty"`
}

type machineNativePairDiagnostic struct {
	PairID         string `json:"pair_id"`
	OriginalDigest string `json:"original_digest"`
	Packet         []byte `json:"packet"`
	ResponsePacket []byte `json:"response_packet,omitempty"`
	CreatedAt      string `json:"created_at"`
}

func nativePairNodeBusinessOperation(operation string) bool {
	return operation == wire.OperationNativePairNodeDescribe || operation == wire.OperationNativePairNodeJoin
}

func machineNodeControlResponseCodeAllowedFor(operation, code string) bool {
	if endpointGroupsNodeBusinessOperation(operation) && endpointGroupsNodeCode(code) {
		return true
	}
	if localDomainNodeBusinessOperation(operation) && (code == "LOCAL_DOMAIN_REJECTED" || code == "READ_EXPIRED" || code == "REJECTED_UNADMITTED") {
		return true
	}
	return machineNodeControlResponseCodeAllowed(code) || operation == wire.OperationNativePairNodeJoin && code == wire.NativePairNodeJoinFenceCode || endpointNodeBusinessOperation(operation) && (code == nodewire.ErrEndpointContext.Error() || code == nodewire.ErrEndpointConflict.Error() || code == nodewire.ErrEndpointUnavailable.Error())
}

func cloneMachineNativePairReceipt(record machineNativePairReceipt) machineNativePairReceipt {
	record.RequestBody = bytes.Clone(record.RequestBody)
	record.RequestPacket = bytes.Clone(record.RequestPacket)
	record.ResponsePacket = bytes.Clone(record.ResponsePacket)
	record.DiagnosticPacket = bytes.Clone(record.DiagnosticPacket)
	record.DiagnosticResponse = bytes.Clone(record.DiagnosticResponse)
	return record
}

func cloneMachineNativePairState(state machineNodeControlState) machineNodeControlState {
	state.PendingNativePairBody = bytes.Clone(state.PendingNativePairBody)
	if state.NativePairReceipts != nil {
		original := state.NativePairReceipts
		state.NativePairReceipts = make(map[string]machineNativePairReceipt, len(original))
		for id, record := range original {
			state.NativePairReceipts[id] = cloneMachineNativePairReceipt(record)
		}
	}
	if state.NativePairDiagnostic != nil {
		diagnostic := *state.NativePairDiagnostic
		diagnostic.Packet = bytes.Clone(diagnostic.Packet)
		diagnostic.ResponsePacket = bytes.Clone(diagnostic.ResponsePacket)
		state.NativePairDiagnostic = &diagnostic
	}
	return state
}

func nativePairNodeBody(operation string, body []byte) (any, error) {
	if !nativePairNodeBusinessOperation(operation) {
		return nil, errors.New("not a native Pair business operation")
	}
	return wire.DecodeNativePairNodeRequest(operation, body)
}

func (client *machineNodeControlClient) rememberNativePairReceiptLocked(response, result []byte, ok bool, code string) error {
	operation := client.state.PendingOperation
	if !nativePairNodeBusinessOperation(operation) {
		return nil
	}
	request, err := nativePairNodeBody(operation, client.state.PendingNativePairBody)
	if err != nil {
		return errors.New("original native Pair request metadata is unavailable; pending packet retained")
	}
	hash := sha256.Sum256(client.state.PendingNativePairBody)
	packet, err := wire.DecodeNativePairNodePacket(client.state.PendingPacket)
	if err != nil || hex.EncodeToString(hash[:]) != client.state.PendingPlaintextDigest || packet.Route.Operation != operation || packet.Route.OperationID != client.state.PendingOperationID || packet.Route.Sequence != client.state.PendingSequence {
		return errors.New("original native Pair metadata does not match its durable sealed request")
	}
	if _, err := wire.DecodeNativePairNodePacket(response); err != nil {
		return err
	}
	record := machineNativePairReceipt{Operation: operation, RequestBody: bytes.Clone(client.state.PendingNativePairBody), RequestPacket: bytes.Clone(client.state.PendingPacket), ResponsePacket: bytes.Clone(response), Sequence: client.state.PendingSequence, Fenced: !ok}
	switch q := request.(type) {
	case wire.NativePairNodeDescribe:
		record.PairID = q.PairID
		if ok {
			d, err := wire.DecodeNativePairNodeDescription(result)
			if err != nil || d.PairID != q.PairID || d.HubIdentity.HubID != client.state.HubID {
				return errors.New("native Pair description differs from its original Node target")
			}
		} else if code != "RESULT_EXPIRED" {
			return errors.New("native Pair read lacks a recognized authenticated terminal result")
		}
	case wire.NativePairNodeJoin:
		record.PairID = q.PairID
		if ok {
			if _, err := client.validateNativePairJoinResultLocked(q, result); err != nil {
				return err
			}
		} else if code != wire.NativePairNodeJoinFenceCode {
			return errors.New("native Pair Join lacks its exact authenticated no-effect fence")
		}
	}
	if old, exists := client.state.NativePairReceipts[client.state.PendingOperationID]; exists {
		old.Consumed = false
		if !reflect.DeepEqual(old, record) {
			return errors.New("native Pair original receipt conflicts with retained history")
		}
		return nil
	}
	if client.state.NativePairReceipts == nil {
		client.state.NativePairReceipts = make(map[string]machineNativePairReceipt)
	}
	client.state.NativePairReceipts[client.state.PendingOperationID] = record
	return nil
}

func (client *machineNodeControlClient) validateNativePairJoinResultLocked(q wire.NativePairNodeJoin, raw []byte) (*fabric.JoinResult, error) {
	var joined fabric.JoinResult
	if decodeMachineNodeControlJSON(raw, &joined) != nil || joined.Endpoint.ID == "" || joined.Endpoint.PrincipalID == "" || joined.Endpoint.Harness != "codex" || joined.Endpoint.NativeSessionID != q.NativeSessionID || joined.Endpoint.Workspace != q.Workspace || joined.Endpoint.MachineID != client.nodeID || joined.SessionToken == "" || len(joined.SessionToken) > 512 || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return nil, errors.New("native Pair Join receipt differs from the original local Thread context")
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return nil, err
	}
	defer state.Close()
	p, err := state.NativePairPolicyForGroup(context.Background(), joined.Endpoint.GroupID)
	if err != nil || p.PairID != q.PairID || p.NodeID != client.nodeID || p.BootstrapDigest != q.BootstrapProofDigest || p.HubIdentity.HubID != client.state.HubID {
		return nil, errors.New("native Pair Join receipt is outside the original retained Owner policy")
	}
	return client.validateNativePairJoinResultWithPolicyLocked(q, raw, p)
}

func (client *machineNodeControlClient) validateNativePairJoinResultWithPolicyLocked(q wire.NativePairNodeJoin, raw []byte, p *nodekeys.NativePairPolicy) (*fabric.JoinResult, error) {
	var joined fabric.JoinResult
	if decodeMachineNodeControlJSON(raw, &joined) != nil || joined.Endpoint.ID == "" || joined.Endpoint.PrincipalID == "" || joined.Endpoint.Harness != "codex" || joined.Endpoint.NativeSessionID != q.NativeSessionID || joined.Endpoint.Workspace != q.Workspace || joined.Endpoint.MachineID != client.nodeID || joined.SessionToken == "" || len(joined.SessionToken) > 512 || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return nil, errors.New("native Pair Join receipt differs from the original local Thread context")
	}
	if p == nil || p.PairID != q.PairID || p.NodeID != client.nodeID || p.BootstrapDigest != q.BootstrapProofDigest || p.HubIdentity.HubID != client.state.HubID {
		return nil, errors.New("native Pair Join receipt is outside the original retained Owner policy")
	}
	var proof e2ee.OwnerNativePairProof
	if json.Unmarshal(p.BootstrapProof, &proof) != nil || joined.Endpoint.Owner != proof.Claims.Scope.Actor.OwnerID {
		return nil, errors.New("native Pair Join receipt changed its original Owner")
	}
	card, scope := joined.NetworkCard, joined.NativeContextScope
	if card.EndpointID != joined.Endpoint.ID || card.PrincipalID != joined.Endpoint.PrincipalID || card.GroupID != p.GroupID || card.NodeID != client.nodeID || (card.NativeSessionID != "" && card.NativeSessionID != q.NativeSessionID) || card.Workspace != q.Workspace || card.BindingID != joined.BindingID || card.BindingEpoch != joined.BindingEpoch || scope.HubID != p.HubIdentity.HubID || scope.GroupID != p.GroupID || scope.NetworkID != p.NetworkID {
		return nil, errors.New("native Pair Join receipt has inconsistent binding or Network scope")
	}
	end, endErr := time.Parse(time.RFC3339Nano, joined.LeaseExpiresAt)
	ceiling, ceilingErr := time.Parse(time.RFC3339Nano, p.PeerExpiresAt)
	if endErr != nil || ceilingErr != nil || end.After(ceiling) {
		return nil, errors.New("native Pair Join receipt exceeds its original peer ceiling")
	}
	return &joined, nil // History may be expired; this does not activate it.
}

func (client *machineNodeControlClient) openNativePairRecordedResultLocked(record machineNativePairReceipt) (json.RawMessage, error) {
	request, err := wire.DecodeNativePairNodePacket(record.RequestPacket)
	if err != nil || request.Route.Operation != record.Operation || request.Route.Sequence != record.Sequence {
		return nil, errors.New("retained native Pair original route is invalid")
	}
	binding := machineNodeControlBindingFromState(client)
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, record.ResponsePacket)
	wanted := request.Route
	wanted.Direction = nodewire.DirectionResponse
	wanted.SenderKeyID, wanted.ReceiverKeyID = wanted.ReceiverKeyID, wanted.SenderKeyID
	wanted.SenderKeyVersion, wanted.ReceiverKeyVersion = wanted.ReceiverKeyVersion, wanted.SenderKeyVersion
	if err != nil || opened.Route != wanted {
		return nil, errors.New("retained native Pair receipt failed its original Node-Control authentication")
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   string          `json:"error_code,omitempty"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
	}
	if decodeMachineNodeControlJSON(opened.Plaintext, &envelope) != nil || envelope.OperationID != request.Route.OperationID || envelope.Sequence != request.Route.Sequence || !envelope.OK || record.Fenced || envelope.ErrorCode != "" || len(envelope.Result) == 0 {
		return nil, errNativePairNodeRejected
	}
	return envelope.Result, nil
}
