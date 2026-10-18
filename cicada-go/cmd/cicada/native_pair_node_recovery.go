package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type machineNativePairEnvelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   string          `json:"error_code,omitempty"`
	OperationID string          `json:"operation_id"`
	Sequence    uint64          `json:"sequence"`
}

func (client *machineNodeControlClient) recoverNodeControlPending(ctx context.Context, token string) error {
	client.mu.Lock()
	pair := nativePairNodeBusinessOperation(client.state.PendingOperation)
	client.mu.Unlock()
	if pair {
		return client.recoverNativePairOriginal(ctx, token)
	}
	return client.recoverPending(ctx, token)
}

func (client *machineNodeControlClient) openNativePairNodeEnvelopeLocked(original, response []byte) (machineNativePairEnvelope, error) {
	request, err := wire.DecodeNativePairNodePacket(original)
	if err != nil {
		return machineNativePairEnvelope{}, err
	}
	if _, err := wire.DecodeNativePairNodePacket(response); err != nil {
		return machineNativePairEnvelope{}, err
	}
	binding := machineNodeControlBindingFromState(client)
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, response)
	wanted := request.Route
	wanted.Direction = nodewire.DirectionResponse
	wanted.SenderKeyID, wanted.ReceiverKeyID = wanted.ReceiverKeyID, wanted.SenderKeyID
	wanted.SenderKeyVersion, wanted.ReceiverKeyVersion = wanted.ReceiverKeyVersion, wanted.SenderKeyVersion
	if err != nil || opened.Route != wanted {
		return machineNativePairEnvelope{}, errors.New("native Pair response failed its exact original Node-Control route")
	}
	var envelope machineNativePairEnvelope
	if decodeMachineNodeControlJSON(opened.Plaintext, &envelope) != nil || envelope.OperationID != request.Route.OperationID || envelope.Sequence != request.Route.Sequence ||
		(envelope.OK && (envelope.ErrorCode != "" || len(envelope.Result) == 0)) ||
		(!envelope.OK && (len(envelope.Result) != 0 || !machineNodeControlResponseCodeAllowedFor(request.Route.Operation, envelope.ErrorCode))) {
		return machineNativePairEnvelope{}, errors.New("native Pair response body differs from the original Node request")
	}
	return envelope, nil
}

// The exact original always precedes a detached diagnostic or a new Describe.
// Neither HTTP errors nor an expired short read can reset a business sequence.
func (client *machineNodeControlClient) recoverNativePairOriginal(ctx context.Context, token string) error {
	originalError := client.recoverPending(ctx, token)
	if originalError == nil {
		return nil
	}
	client.mu.Lock()
	if !nativePairNodeBusinessOperation(client.state.PendingOperation) || len(client.state.PendingPacket) == 0 {
		client.mu.Unlock()
		return originalError
	}
	err := client.reconcileNativePairLocked(ctx, token)
	client.mu.Unlock()
	if err != nil {
		return err
	}
	return client.recoverPending(ctx, token)
}

func (client *machineNodeControlClient) reconcileNativePairLocked(ctx context.Context, token string) error {
	request, err := nativePairNodeBody(client.state.PendingOperation, client.state.PendingNativePairBody)
	if err != nil {
		return err
	}
	var pairID string
	switch q := request.(type) {
	case wire.NativePairNodeDescribe:
		pairID = q.PairID
	case wire.NativePairNodeJoin:
		pairID = q.PairID
	}
	original := client.state.PendingPacket
	packet, err := wire.DecodeNativePairNodePacket(original)
	bodyHash := sha256.Sum256(client.state.PendingNativePairBody)
	if err != nil || packet.Route.Operation != client.state.PendingOperation || packet.Route.OperationID != client.state.PendingOperationID || packet.Route.Sequence != client.state.PendingSequence || hex.EncodeToString(bodyHash[:]) != client.state.PendingPlaintextDigest {
		return errors.New("native Pair diagnostic has no matching retained business original")
	}
	digest := wire.NativePairNodePacketDigest(original)
	now := time.Now().UTC()
	diagnostic := client.state.NativePairDiagnostic
	if diagnostic != nil && (diagnostic.PairID != pairID || diagnostic.OriginalDigest != digest) {
		return errors.New("native Pair diagnostic differs from the retained business original")
	}
	if diagnostic == nil || len(diagnostic.ResponsePacket) == 0 && !now.Before(parseMachineNativePairTime(diagnostic.CreatedAt).Add(45*time.Second)) {
		nonce := make([]byte, wire.NonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		query := wire.NativePairNodeReconcile{ContractRevision: wire.NativePairContractRevision, PairID: pairID, Nonce: nonce, IssuedAt: now.Format(time.RFC3339Nano), OriginalPacket: bytes.Clone(original)}
		body, err := json.Marshal(query)
		if err != nil {
			return err
		}
		if _, err := wire.DecodeNativePairNodeRequest(wire.OperationNativePairNodeReconcile, body); err != nil {
			return err
		}
		route := packet.Route
		route.Operation = wire.OperationNativePairNodeReconcile
		route.OperationID, err = newMachineNodeControlOperationID()
		if err != nil {
			return err
		}
		binding := machineNodeControlBindingFromState(client)
		sealed, err := nodewire.SealRequest(client.identity, binding.HubKey, binding, route, body)
		if err != nil {
			return err
		}
		if _, err := wire.DecodeNativePairNodePacket(sealed); err != nil {
			return err
		}
		previous := cloneMachineNodeControlState(client.state)
		diagnostic = &machineNativePairDiagnostic{PairID: pairID, OriginalDigest: digest, Packet: sealed, CreatedAt: query.IssuedAt}
		client.state.NativePairDiagnostic = diagnostic
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return err
		}
	}
	response := diagnostic.ResponsePacket
	if len(response) == 0 {
		response, err = client.postPacket(ctx, token, diagnostic.Packet)
		if err != nil {
			return err // An unsigned HTTP error never settles the original.
		}
	}
	envelope, err := client.openNativePairNodeEnvelopeLocked(diagnostic.Packet, response)
	if err != nil || !envelope.OK {
		return errors.New("native Pair diagnostic is unauthenticated or unresolved; original retained")
	}
	reconciled, err := wire.DecodeNativePairNodeReconciled(envelope.Result)
	if err != nil || wire.ValidateNativePairNodeReconcileTarget(reconciled, pairID, original) != nil {
		return errors.New("native Pair diagnostic does not prove the exact original packet")
	}
	if reconciled.State != "READ_EXPIRED" {
		nested, err := client.openNativePairNodeEnvelopeLocked(original, reconciled.ReceiptPacket)
		if err != nil || reconciled.State == "COMPLETED" && !nested.OK || reconciled.State == "REJECTED_FENCED" && (nested.OK || nested.ErrorCode != wire.NativePairNodeJoinFenceCode) {
			return errors.New("native Pair diagnostic contradicts its nested authenticated receipt")
		}
	}
	previous := cloneMachineNodeControlState(client.state)
	diagnostic.ResponsePacket = bytes.Clone(response)
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	previous = cloneMachineNodeControlState(client.state)
	if reconciled.State == "READ_EXPIRED" {
		if client.state.NativePairReceipts == nil {
			client.state.NativePairReceipts = make(map[string]machineNativePairReceipt)
		}
		client.state.NativePairReceipts[client.state.PendingOperationID] = machineNativePairReceipt{Operation: client.state.PendingOperation, PairID: pairID, RequestBody: bytes.Clone(client.state.PendingNativePairBody), RequestPacket: bytes.Clone(original), Sequence: client.state.PendingSequence, Fenced: true, Consumed: true, DiagnosticPacket: bytes.Clone(diagnostic.Packet), DiagnosticResponse: bytes.Clone(response)}
		client.clearPendingLocked()
	} else {
		client.state.PendingResponsePacket = bytes.Clone(reconciled.ReceiptPacket)
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func parseMachineNativePairTime(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, raw)
	return t
}
