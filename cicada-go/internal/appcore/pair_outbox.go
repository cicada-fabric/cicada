package appcore

import (
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) pairRequestContext(scope e2ee.OwnerNativePairScope, now time.Time) (wire.NativePairRequestContext, error) {
	id, err := wire.NewRequestID()
	if err != nil {
		return wire.NativePairRequestContext{}, err
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		return wire.NativePairRequestContext{}, err
	}
	a := scope.Actor
	return wire.NativePairRequestContext{Origin: a.Origin, HubID: a.HubID, AccountID: a.AccountID, OwnerID: a.OwnerID,
		DeviceID: a.DeviceID, AccountSessionID: a.AccountSessionID, AccountEpoch: a.AccountEpoch, DeviceEpoch: a.DeviceEpoch,
		ClientSessionEpoch: a.ClientSessionEpoch, RequestID: id, ClientNonce: nonce, IssuedAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

// Sealing and storing the DTO/packet together makes target review refer to the
// actual local request. This method never sends or grants admission.
func (c *nativeController) beginPairOriginal(scope e2ee.OwnerNativePairScope, pairID string, body any) error {
	if c.device == nil || c.hasPairPending() {
		return ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	raw, err := wire.SealClientRequest(device, c.hub, body)
	if err != nil {
		return err
	}
	packet, err := wire.DecodeNativePairPacket(raw)
	if err != nil {
		clear(raw)
		return err
	}
	dto, err := json.Marshal(body)
	if err != nil {
		clear(raw)
		return err
	}
	route, digest := packet.Packet.Route, wire.NativePairPacketDigest(raw)
	record := &pairRequestRecord{Format: "cicada.native-pair.request.v1", Route: route, Digest: digest, Packet: raw, DTO: dto, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano),
		Target: pairPacketTarget{Vault: cardScope(c.connection), DeviceID: c.state.DeviceID, DeviceKeyID: c.state.DeviceKeyID,
			OwnerKeyID: c.state.OwnerKeyID, Scope: scope, PairID: pairID, OriginalRoute: route, OriginalDigest: digest}}
	if err := c.validatePairRequest(record, nil); err != nil {
		clear(raw)
		clear(dto)
		return err
	}
	// Clear the old response before replacing an already-applied original.
	// A crash here retains its Applied marker; a new unresolved original can
	// therefore never encounter the preceding operation's response record.
	if c.pairOriginalResponse != nil {
		if err := c.persistPairRecord(pairOriginalResponseRecord, nil); err != nil {
			clear(raw)
			clear(dto)
			return err
		}
		clear(c.pairOriginalResponse.Packet)
		c.pairOriginalResponse = nil
	}
	if err := c.persistPairRecord(pairOriginalRecord, record); err != nil {
		clear(raw)
		clear(dto)
		return err
	}
	if c.pairOriginal != nil {
		clear(c.pairOriginal.Packet)
		clear(c.pairOriginal.DTO)
	}
	c.pairOriginal = record
	return nil
}

func (c *nativeController) beginPairRecovery() error {
	original := c.pairOriginal
	if original == nil || original.Applied || c.device == nil {
		return ErrInvalidAction
	}
	if c.pairRecovery != nil && (c.pairRecoveryResponse != nil || c.cfg.Now().UTC().Before(parseExpiry(c.pairRecovery.CreatedAt).Add(wire.MaxSessionRequestLifetime))) {
		return ErrInvalidAction
	}
	ctx, err := c.pairRequestContext(original.Target.Scope, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	request := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: ctx,
		PairID: original.Target.PairID, OriginalPacket: original.Packet}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	raw, err := wire.SealClientRequest(device, c.hub, request)
	if err != nil {
		return err
	}
	packet, err := wire.DecodeNativePairPacket(raw)
	if err != nil {
		clear(raw)
		return err
	}
	record := &pairRequestRecord{Format: "cicada.native-pair.request.v1", Target: original.Target,
		Route: packet.Packet.Route, Digest: wire.NativePairPacketDigest(raw), Packet: raw, CreatedAt: ctx.IssuedAt}
	if err := c.validatePairRequest(record, original); err != nil {
		clear(raw)
		return err
	}
	if err := c.persistPairRecord(pairRecoveryRecord, record); err != nil {
		clear(raw)
		return err
	}
	if c.pairRecovery != nil {
		clear(c.pairRecovery.Packet)
	}
	c.pairRecovery = record
	return nil
}
