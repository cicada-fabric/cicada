package installationclient

import (
	"bytes"
	"context"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Recover asks for the exact original's committed receipt or permanent no-effect
// fence. A fresh recovery request has its own ID/nonce/time, retained before
// HTTP; it never rewrites the original, its timestamps, candidate or keys.
func (c *Client) Recover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	original := c.state.Pending
	if original == nil {
		return ErrPending
	}
	if len(original.Response) != 0 && c.state.Recovery == nil {
		return c.applyResponse(original)
	}
	if err := c.checkAvailable(ctx); err != nil {
		return err
	}
	admission, err := c.admission.E2EE()
	if err != nil {
		return ErrState
	}
	if c.state.Recovery == nil {
		var old wire.InstallationPacket
		if c.validateRecord(original) != nil || canonical(original.Original, &old, wire.MaxInstallationOriginalBytes) != nil || old.Self == nil {
			return ErrState
		}
		header, err := c.selfHeader(wire.OperationInstallationReconcile)
		if err != nil {
			return err
		}
		// A lost initial accept may already have created a parent. Reconcile
		// nevertheless preserves the original context, as required by C0.
		header.Self.ParentRegistrationID = old.Self.ParentRegistrationID
		header.Self.RegistrationEpoch = old.Self.RegistrationEpoch
		header.Self.AdmissionCredentialVersion = old.Self.AdmissionCredentialVersion
		body := wire.InstallationReconcile{Format: wire.InstallationFormat, OriginalOperation: original.Operation, OriginalRequestID: original.RequestID,
			OriginalPacketDigest: e2ee.InstallationPacketDigest(original.Original), OriginalPacket: original.Original}
		packet, err := wire.SealInstallationRequest(admission, c.cfg.Hub, header, body)
		if err != nil {
			return ErrState
		}
		c.state.Recovery = &requestRecord{Operation: header.Operation, RequestID: header.Self.RequestID, Original: packet}
		if err := c.persist(); err != nil {
			return err
		}
	}
	recovery := c.state.Recovery
	raw, err := postOriginal(ctx, c.cfg.HTTP, c.cfg.Origin, recovery.Operation, recovery.Original)
	if err != nil {
		return err
	}
	defer clear(raw)
	var result wire.InstallationReconciled
	if wire.OpenInstallationResponse(admission, c.cfg.Hub, recovery.Original, raw, &result) != nil ||
		result.OriginalOperation != original.Operation || result.OriginalRequestID != original.RequestID || result.OriginalPacketDigest != e2ee.InstallationPacketDigest(original.Original) {
		return ErrUnknown
	}
	if result.State == wire.InstallationReadExpired {
		if !wire.InstallationIsRead(original.Operation) || len(result.ReceiptPacket) != 0 {
			return ErrUnknown
		}
		// Only an authenticated expired pure read may be discharged without
		// an original effect receipt. Keep its exact reconciliation evidence.
		recovery.Response = bytes.Clone(raw)
		clearRecord(c.state.Last)
		clearRecord(original)
		c.state.Last, c.state.Pending, c.state.Recovery = recovery, nil, nil
		return c.persist()
	}
	reply, err := c.authenticateResponse(original, result.ReceiptPacket)
	if err != nil || reply.fenced != (result.State == wire.InstallationRejectedFenced) {
		return ErrUnknown
	}
	// The inner response independently authenticates the exact original and
	// its effect/fence. Retain those exact bytes before applying them; a second
	// copy of the large reconciliation envelope is unnecessary for recovery.
	original.Response = bytes.Clone(result.ReceiptPacket)
	clearRecord(recovery)
	clearRecord(c.state.Last)
	c.state.Last, c.state.Recovery = nil, nil
	if err := c.persist(); err != nil {
		return err
	}
	return c.applyResponse(original)
}
