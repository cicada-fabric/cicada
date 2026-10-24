package appcore

import (
	"encoding/base64"
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These are local retained-receipt ceilings, below the transport frame limits.
// Owner replies have no proof/capsule arrays. 192 KiB includes an ACK's bounded
// legacy confirmation wrapper, full Context/binding and both PQ/base64 layers.
// Oversized peer replies preserve the original unknown request, never settle it.
const nodePairTrustOwnerReceiptBytes = 192 << 10

func (c *nativeController) nodePairTrustResponseLimit(op string) int {
	switch op {
	case wire.OperationOwnerNodePairTrustLookup, wire.OperationOwnerNodePairTrustPrepare:
		return 96 << 10
	case wire.OperationOwnerNodePairTrustComplete:
		return 64 << 10
	case wire.OperationOwnerNodePairTrustStatus, wire.OperationOwnerNodePairTrustCancel:
		return nodePairTrustOwnerReceiptBytes
	}
	// An outer recovery has only bounded metadata plus that original ciphertext.
	if op != wire.OperationNodePairTrustReconcile || c.node.PairTrust == nil || c.node.PairTrust.Pending == nil {
		return 0
	}
	n, err := c.nodePairTrustPacketSize(base64.StdEncoding.EncodedLen(c.nodePairTrustResponseLimit(c.node.PairTrust.Pending.Operation)) + 4096)
	if err != nil {
		return 0
	}
	return n
}

func (c *nativeController) nodePairTrustPacketSize(plain int) (int, error) {
	n, err := e2ee.InstallationSealedEnvelopeSize(c.hub.Public, plain)
	if err != nil {
		return 0, err
	}
	h, err := json.Marshal(wire.NodePairTrustPacket{Format: wire.NodePairTrustPacketFormat, Version: 1,
		Operation: wire.OperationNodePairTrustReconcile, RequestID: "00000000000000000000000000000000",
		AttemptID: "00000000000000000000000000000000", SenderPublic: c.hub.Public})
	if err != nil {
		return 0, err
	}
	return len(h) - 4 + 2 + base64.StdEncoding.EncodedLen(n), nil
}

// Check both future receipt and recovery slots against the actual vault, before
// POST. Placeholder bytes exist only in memory and are cleared; CAS stores only
// real packets. The controller mutex and vault process lock serialize writers.
func (c *nativeController) nodePairTrustFits(p *nodePairTrustOperation) bool {
	state := c.node
	t := *state.PairTrust
	state.PairTrust = &t
	q := *p
	q.Response = make([]byte, c.nodePairTrustResponseLimit(p.Operation))
	defer clear(q.Response)
	if p.Operation != wire.OperationNodePairTrustReconcile {
		t.Pending = &q
	} else {
		original := *t.Pending
		original.Response = make([]byte, c.nodePairTrustResponseLimit(original.Operation))
		defer clear(original.Response)
		t.Pending = &original
	}
	// The ACK receipt is saved in the original confirmation before applying it.
	if (p.Operation == wire.OperationOwnerNodePairTrustStatus || p.Operation == wire.OperationOwnerNodePairTrustCancel) && t.Confirmation != nil && len(t.Confirmation.Response) == 0 {
		confirmation := *t.Confirmation
		confirmation.Response = make([]byte, wire.MaxAppNodeReceiptBytes)
		defer clear(confirmation.Response)
		t.Confirmation = &confirmation
	}
	main, err := json.Marshal(state)
	defer clear(main)
	if err != nil || len(main) > maxNodeStateRecordBytes {
		return false
	}
	var recovery any
	if p.Operation == wire.OperationNodePairTrustReconcile {
		recovery = nodeOperation{Operation: wire.OperationNodePairTrustReconcile, PairTrustRecovery: &nodePairTrustRecoveryRecord{state.Scope, t.Code.AttemptID, wire.NodePairTrustPacketDigest(t.Pending.Request), q}}
	} else {
		// Reserve the possible later outer recovery of this exact original.
		r := wire.NodePairTrustReconcile{Format: wire.NodePairTrustFormat, OriginalPacket: p.Request,
			OriginalPacketDigest: wire.NodePairTrustPacketDigest(p.Request), IssuedAt: "9999-12-31T23:59:59.999999999Z"}
		full, err := json.Marshal(r)
		if err != nil {
			return false
		}
		n, err := c.nodePairTrustPacketSize(len(full))
		clear(full)
		if err != nil {
			return false
		}
		body, digest, err := compactNodePairRecoveryBody(r)
		if err != nil {
			return false
		}
		defer clear(body)
		request, response := make([]byte, n), make([]byte, c.nodePairTrustResponseLimit(wire.OperationNodePairTrustReconcile))
		defer clear(request)
		defer clear(response)
		recovery = nodeOperation{Operation: wire.OperationNodePairTrustReconcile, PairTrustRecovery: &nodePairTrustRecoveryRecord{state.Scope, t.Code.AttemptID, r.OriginalPacketDigest,
			nodePairTrustOperation{Operation: wire.OperationNodePairTrustReconcile, Body: body, BodyDigest: digest, Request: request, Response: response}}}
	}
	saved, err := json.Marshal(recovery)
	defer clear(saved)
	if err != nil || len(saved) > maxNodeStateRecordBytes {
		return false
	}
	updates := map[string][]byte{nodeStateNamespace: main, nodeRecoveryNamespace: saved}
	// Installing a successful original confirmation occupies the existing
	// immutable receipt namespace before the main record's counters are updated.
	originalOp := p.Operation
	if originalOp == wire.OperationNodePairTrustReconcile {
		originalOp = t.Pending.Operation
	}
	if (originalOp == wire.OperationOwnerNodePairTrustStatus || originalOp == wire.OperationOwnerNodePairTrustCancel) && t.Confirmation != nil && c.nodeConfirmation == nil {
		confirmation := *t.Confirmation
		confirmation.Response = make([]byte, wire.MaxAppNodeReceiptBytes)
		defer clear(confirmation.Response)
		b, err := json.Marshal(nodeConfirmationRecord{Scope: state.Scope, Operation: confirmation})
		if err != nil {
			return false
		}
		// Full binding's two fixed public keys, bounded IDs, escaped names and
		// canonical timestamps fit this additional 32 KiB schema allowance.
		reserved := make([]byte, len(b)+(32<<10))
		copy(reserved, b)
		clear(b)
		defer clear(reserved)
		updates[nodeConfirmationNamespace] = reserved
	}
	return c.vault.CheckStateUpdates(updates) == nil
}
