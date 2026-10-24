package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) discoverNodePairTrust(ctx context.Context) error {
	c.pairTrustDiscovery, c.pairTrustAvailable = true, false
	c.pairTrustAvailability = "UNKNOWN"
	if !c.nodeAccountReady() || c.httpClient() == nil || c.state.Transport == nil {
		return ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, wire.NodePairTrustCapabilitiesPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.httpClient().Do(r)
	if err != nil {
		return wire.ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		return wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	defer clear(raw)
	var caps wire.NodePairTrustCapabilities
	if err != nil || len(raw) > 16384 || decodeStateJSON(raw, &caps) != nil {
		return wire.ErrInvalid
	}
	expected := wire.NodePairTrustContractCapabilities()
	expected.Available = caps.Available
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(caps)
	if !bytes.Equal(want, got) {
		return wire.ErrInvalid
	}
	if !caps.Available {
		c.pairTrustAvailability = "UNAVAILABLE"
		c.publish()
		return wire.ErrInvalid
	}
	c.pairTrustAvailable = true
	c.pairTrustAvailability = "AVAILABLE"
	c.publish()
	return nil
}
func (c *nativeController) postNodePairTrust(ctx context.Context, p *nodePairTrustOperation) ([]byte, error) {
	if c.httpClient() == nil || p == nil || len(p.Request) == 0 {
		return nil, wire.ErrInvalid
	}
	target, err := joinOrigin(c.connection.Origin, wire.NodePairTrustHTTPPath(p.Operation))
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(p.Request))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", c.connection.Origin)
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.httpClient().Do(r)
	if err != nil {
		return nil, wire.ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		return nil, wire.ErrInvalid
	}
	limit := c.nodePairTrustResponseLimit(p.Operation)
	if limit == 0 {
		return nil, wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, wire.ErrInvalid
	}
	return raw, nil
}
func (c *nativeController) newNodePairTrustOperation(ctx context.Context, operation string, body any) error {
	if c.nodePairTrustPending() || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return err
	}
	t := c.node.PairTrust
	h := wire.NodePairTrustPacket{Operation: operation, RequestID: id, AttemptID: t.Code.AttemptID}
	raw, err := wire.SealNodePairTrustRequest(device, c.hub, h, body, c.cfg.Now().UTC())
	if err != nil {
		return c.failNodePairing("APP_NODE_PAIRING_INVALID")
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	previous := t.Pending
	t.Pending = &nodePairTrustOperation{Operation: operation, Body: encoded, Request: raw}
	if !c.nodePairTrustFits(t.Pending) {
		t.Pending = previous
		clear(encoded)
		clear(raw)
		return c.failNodePairing("APP_NODE_PAIRING_STORAGE_FULL")
	}
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	c.publish()
	return c.sendNodePairTrustPending(ctx, true)
}
func (c *nativeController) sendNodePairTrustPending(ctx context.Context, fresh bool) error {
	t := c.node.PairTrust
	if t == nil || t.Pending == nil || t.Pending.Applied {
		return ErrInvalidAction
	}
	p := t.Pending
	if len(p.Response) == 0 {
		raw, err := c.postNodePairTrust(ctx, p)
		if err != nil {
			return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
		}
		defer clear(raw)
		if _, err = c.openNodePairTrustResponse(p, raw); err != nil {
			return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
		}
		p.Response = bytes.Clone(raw)
		if err := c.persistNode(); err != nil {
			return c.failStorage("APP_NODE_COMMIT_FAILED", err)
		}
	}
	if err := c.applyNodePairTrustResponse(fresh); err != nil {
		return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
	}
	c.publish()
	return nil
}
func (c *nativeController) openNodePairTrustResponse(p *nodePairTrustOperation, raw []byte) (wire.NodePairTrustResult, error) {
	body, err := c.nodePairTrustBody(p)
	if err != nil {
		return wire.NodePairTrustResult{}, err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return wire.NodePairTrustResult{}, err
	}
	result, err := wire.OpenNodePairTrustResponse(device, c.hub, p.Request, raw, body)
	if err != nil {
		return result, err
	}
	if result.ErrorCode == "" && p.Operation == wire.OperationOwnerNodePairTrustLookup {
		t := c.node.PairTrust
		descriptor, err := c.nodePairTrustDescriptor()
		if err != nil {
			return result, err
		}
		o, err := wire.MatchNodePairTrustCode(t.Code, *result.Context, c.hub, c.state.Transport.Descriptor.Claims.NodeControl, c.connection.Origin, wire.NodePairTrustDescriptorDigest(descriptor), parseExpiry(result.Context.IssuedAt))
		if err != nil || o != result.OOBCommitment {
			return result, wire.ErrInvalid
		}
	}
	return result, nil
}
