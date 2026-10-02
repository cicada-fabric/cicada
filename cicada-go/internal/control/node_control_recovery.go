package control

import (
	"errors"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (c *Control) NodeControlRecoveryStatus(credentialDigest, nodeID string, packet []byte) ([]byte, error) {
	if c == nil || c.store == nil || c.nodeControlIdentity == nil {
		return nil, errors.New("Node recovery is unavailable")
	}
	b, q, status, err := c.store.NodeControlRecoveryStatus(credentialDigest, nodeID, func(b *store.NodeControlKeyBinding) (nodewire.RecoveryRequest, error) {
		return nodewire.OpenRecoveryRequest(c.nodeControlIdentity, nodeControlWireBinding(b), packet)
	})
	if err != nil {
		return nil, err
	}
	return nodewire.SealRecoveryResponse(c.nodeControlIdentity, nodeControlWireBinding(b), q, packet, status)
}
