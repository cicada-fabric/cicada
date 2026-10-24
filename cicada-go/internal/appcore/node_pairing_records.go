package appcore

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// NPT and old N3 reconciliation are mutually exclusive and share the existing
// recovery slot. This keeps the vault's existing 16-record limit. The target
// original is durable first; a recovery never replaces that original record.
type nodePairTrustRecoveryRecord struct {
	Scope                appvault.Scope         `json:"scope"`
	AttemptID            string                 `json:"attempt_id"`
	OriginalPacketDigest string                 `json:"original_packet_digest"`
	Operation            nodePairTrustOperation `json:"operation"`
}

func (c *nativeController) nodePairRecoveryRecord() any {
	t := c.node.PairTrust
	if t == nil || t.Recovery == nil {
		return nil
	}
	return nodeOperation{Operation: wire.OperationNodePairTrustReconcile,
		PairTrustRecovery: &nodePairTrustRecoveryRecord{c.node.Scope, t.Code.AttemptID, wire.NodePairTrustPacketDigest(t.Pending.Request), *t.Recovery}}
}

func (c *nativeController) persistNodePairRecovery() error {
	if c.nodeRecovery != nil {
		return ErrInvalidAction
	}
	return c.persistNodeRecord(nodeRecoveryNamespace, &c.nodeRecoveryVer, c.nodePairRecoveryRecord())
}

func (c *nativeController) restoreNodePairRecovery(p nodeOperation) error {
	t, r := c.node.PairTrust, p.PairTrustRecovery
	if t == nil || t.Pending == nil || r == nil || p.Operation != wire.OperationNodePairTrustReconcile ||
		!reflect.DeepEqual(p, nodeOperation{Operation: wire.OperationNodePairTrustReconcile, PairTrustRecovery: r}) ||
		r.Scope != c.node.Scope || r.AttemptID != t.Code.AttemptID || r.OriginalPacketDigest != wire.NodePairTrustPacketDigest(t.Pending.Request) || r.Operation.Operation != wire.OperationNodePairTrustReconcile {
		return appvault.ErrScopeMismatch
	}
	t.Recovery = &r.Operation
	return nil
}

func compactNodePairRecoveryBody(q wire.NodePairTrustReconcile) ([]byte, string, error) {
	full, err := json.Marshal(q)
	if err != nil {
		return nil, "", err
	}
	defer clear(full)
	digest := wire.NodePairTrustPacketDigest(full)
	q.OriginalPacket = nil
	b, err := json.Marshal(q)
	return b, digest, err
}

// The immutable original bytes are retained once. Rebuild only the local typed
// DTO, verifying its original canonical digest; never reseal the saved request.
func (c *nativeController) nodePairTrustBody(p *nodePairTrustOperation) (any, error) {
	body, err := pairTrustBody(p)
	if err != nil || p.Operation != wire.OperationNodePairTrustReconcile {
		return body, err
	}
	q := body.(*wire.NodePairTrustReconcile)
	t := c.node.PairTrust
	if t == nil || t.Pending == nil || len(q.OriginalPacket) != 0 || q.OriginalPacketDigest != wire.NodePairTrustPacketDigest(t.Pending.Request) {
		return nil, wire.ErrInvalid
	}
	q.OriginalPacket = bytes.Clone(t.Pending.Request)
	full, err := json.Marshal(q)
	defer clear(full)
	if err != nil || wire.NodePairTrustPacketDigest(full) != p.BodyDigest {
		return nil, wire.ErrInvalid
	}
	return q, nil
}
