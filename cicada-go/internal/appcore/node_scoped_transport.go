package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) nodeTransportPolicy() string {
	if strings.HasPrefix(c.connection.Origin, "https://") {
		return wire.AppNodeScopedTransportHTTPS
	}
	if c.cfg.AllowLoopbackHTTP && c.connection.AllowLoopbackHTTP {
		return wire.AppNodeScopedTransportLoopbackTest
	}
	return ""
}

func (c *nativeController) discoverScopedNodes(ctx context.Context) error {
	c.scoped.discovered, c.scoped.available, c.scoped.availability = true, false, "UNAVAILABLE"
	if !c.nodeAccountReady() || c.state.Transport == nil {
		return ErrInvalidAction
	}
	for _, path := range []string{wire.AppNodeScopedCapabilitiesPath, wire.NodePairTrustScopedCapabilitiesPath} {
		raw, err := c.scopedHTTP(ctx, http.MethodGet, path, nil, wire.MaxAppNodeScopedCapabilitiesBytes)
		if err != nil {
			return err
		}
		if path == wire.AppNodeScopedCapabilitiesPath {
			cap, e := wire.DecodeAppNodeScopedCapabilities(bytes.TrimSpace(raw))
			err = e
			if e == nil && cap.TransportPolicy != c.nodeTransportPolicy() {
				err = wire.ErrInvalid
			}
		} else {
			_, err = wire.DecodeNodePairTrustScopedCapabilities(bytes.TrimSpace(raw))
		}
		clear(raw)
		if err != nil {
			return err
		}
	}
	c.scoped.available, c.scoped.availability = true, "AVAILABLE"
	return nil
}

func (c *nativeController) scopedHTTP(ctx context.Context, method, path string, body []byte, limit int) ([]byte, error) {
	if c.httpClient() == nil || path == "" || limit <= 0 {
		return nil, wire.ErrInvalid
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", c.connection.Origin)
	}
	response, err := c.httpClient().Do(r)
	if err != nil {
		return nil, wire.ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != r.URL.String() {
		return nil, wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, wire.ErrInvalid
	}
	return raw, nil
}

func (c *nativeController) scopedBody(p *scopedOriginal, parent *scopedOriginal) (any, error) {
	var body any
	if p.PairTrust {
		body = wire.NewNodePairTrustScopedRequestBody(p.Operation)
	} else {
		switch p.Operation {
		case wire.OperationAppNodeScopedPrepare:
			body = new(wire.AppNodeScopedPrepare)
		case wire.OperationAppNodeScopedComplete:
			body = new(wire.AppNodeScopedComplete)
		case wire.OperationAppNodeScopedStatus:
			body = new(wire.AppNodeScopedStatus)
		case wire.OperationAppNodeScopedCancel:
			body = new(wire.AppNodeScopedCancel)
		case wire.OperationAppNodeScopedReconcile:
			body = new(wire.AppNodeScopedReconcile)
		}
	}
	if body == nil || decodeStateJSON(p.Body, body) != nil {
		return nil, wire.ErrInvalid
	}
	// Recovery stores the small query metadata once; the exact business packet
	// remains in the original slot instead of being base64-copied into its header.
	if p.Recovery {
		if parent == nil || parent.NodeID != p.NodeID {
			return nil, wire.ErrInvalid
		}
		switch q := body.(type) {
		case *wire.AppNodeScopedReconcile:
			q.OriginalPacket = parent.Packet
		case *wire.NodePairTrustScopedReconcile:
			q.OriginalPacket = parent.Packet
		default:
			return nil, wire.ErrInvalid
		}
	}
	return body, nil
}

func (c *nativeController) validateScopedOriginal(p *scopedOriginal) error {
	if p == nil || p.Format != scopedFrameFormat || !c.scopedIdentity(p.Vault, p.DeviceKeyID, p.OwnerKeyID) || parseExpiry(p.CreatedAt).IsZero() || !localTargetText(p.NodeID, false) {
		return appvault.ErrScopeMismatch
	}
	if p.PairTrust {
		var packet wire.NodePairTrustScopedPacket
		if decodeStateJSON(p.Packet, &packet) != nil || packet.Format != wire.NodePairTrustScopedPacketFormat || packet.Version != 1 || packet.Operation != p.Operation || packet.RequestID != p.RequestID || packet.AttemptID != p.AttemptID || !reflect.DeepEqual(packet.SenderPublic, c.device.Public()) {
			return wire.ErrInvalid
		}
	} else {
		if _, err := wire.PreflightRequest(p.Packet, p.Operation); err != nil {
			return err
		}
		packet, err := wire.DecodePacket(p.Packet)
		if err != nil || packet.Packet.Route.OperationID != p.RequestID || !reflect.DeepEqual(packet.SenderPublicIdentity, c.device.Public()) {
			return wire.ErrInvalid
		}
	}
	return nil
}

func (c *nativeController) newScopedOriginal(body any, node string, pair bool) (*scopedOriginal, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	p := &scopedOriginal{Format: scopedFrameFormat, Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, NodeID: node, PairTrust: pair, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if pair {
		f := c.scoped.flow
		if f == nil || f.NodeID != node {
			return nil, ErrInvalidAction
		}
		switch body.(type) {
		case wire.NodePairTrustScopedOwnerLookup:
			p.Operation = wire.OperationOwnerNodePairTrustScopedLookup
		case wire.NodePairTrustScopedOwnerPrepare:
			p.Operation = wire.OperationOwnerNodePairTrustScopedPrepare
		case wire.NodePairTrustScopedOwnerComplete:
			p.Operation = wire.OperationOwnerNodePairTrustScopedComplete
		case wire.NodePairTrustScopedOwnerStatus:
			p.Operation = wire.OperationOwnerNodePairTrustScopedStatus
		case *wire.NodePairTrustScopedOwnerCancel:
			p.Operation = wire.OperationOwnerNodePairTrustScopedCancel
		case wire.NodePairTrustScopedReconcile:
			p.Operation = wire.OperationNodePairTrustScopedReconcile
		default:
			return nil, wire.ErrInvalid
		}
		p.RequestID, err = wire.NewRequestID()
		if err != nil {
			return nil, err
		}
		p.AttemptID = f.Code.AttemptID
		p.Packet, err = wire.SealNodePairTrustScopedRequest(device, c.hub, wire.NodePairTrustScopedPacket{Operation: p.Operation, RequestID: p.RequestID, AttemptID: p.AttemptID}, body, c.cfg.Now().UTC())
	} else {
		p.Packet, err = wire.SealClientRequest(device, c.hub, body)
		if err == nil {
			var packet wire.Packet
			packet, err = wire.DecodePacket(p.Packet)
			p.Operation, p.RequestID = packet.Packet.Route.Operation, packet.Packet.Route.OperationID
		}
	}
	if err != nil {
		return nil, err
	}
	p.Body, err = json.Marshal(body)
	if err != nil {
		return nil, err
	}
	switch q := body.(type) {
	case wire.AppNodeScopedPrepare:
		claims, e := e2ee.VerifyOwnerAppNodeScopedPreview(c.owner.Public(), q.OwnerIntent, time.Time{})
		if e != nil {
			return nil, e
		}
		p.GrantID = claims.GrantID
	case wire.AppNodeScopedComplete:
		claims, e := e2ee.VerifyOwnerAppNodeScopedGrant(c.owner.Public(), q.OwnerGrant, time.Time{})
		if e != nil {
			return nil, e
		}
		p.GrantID = claims.GrantID
	case wire.AppNodeScopedStatus:
		p.GrantID = q.GrantID
	case wire.AppNodeScopedCancel:
		p.GrantID = q.GrantID
	case wire.AppNodeScopedReconcile:
		p.GrantID = q.GrantID
	}
	return p, c.validateScopedOriginal(p)
}

func (c *nativeController) scopedResponseLimit(p *scopedOriginal) int {
	if p.Recovery {
		return scopedLocalRecoveryReceiptBytes
	}
	if p.PairTrust {
		return scopedLocalReceiptBytes
	}
	return wire.MaxAppNodeScopedReceiptBytes
}

func (c *nativeController) postScopedOriginal(ctx context.Context, p *scopedOriginal) ([]byte, error) {
	path := wire.AppNodeScopedHTTPPath(p.Operation)
	if p.PairTrust {
		path = wire.NodePairTrustScopedHTTPPath(p.Operation)
	}
	return c.scopedHTTP(ctx, http.MethodPost, path, p.Packet, c.scopedResponseLimit(p))
}

func (c *nativeController) makeScopedRecovery(p *scopedOriginal) (*scopedOriginal, error) {
	var body any
	if p.PairTrust {
		body = wire.NodePairTrustScopedReconcile{Format: wire.NodePairTrustScopedFormat, OriginalPacket: p.Packet, OriginalPacketDigest: wire.NodePairTrustScopedPacketDigest(p.Packet), IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	} else {
		q, err := wire.NewAppNodeScopedReconcile(c.nodeSession(), p.NodeID, wire.AppNodeScopedOriginalAuthority, p.GrantID, p.Packet, c.cfg.Now().UTC())
		if err != nil {
			return nil, err
		}
		body = q
	}
	r, err := c.newScopedOriginal(body, p.NodeID, p.PairTrust)
	if err != nil {
		return nil, err
	}
	r.Recovery = true
	var compact any
	switch q := body.(type) {
	case wire.AppNodeScopedReconcile:
		q.OriginalPacket = nil
		compact = q
	case wire.NodePairTrustScopedReconcile:
		q.OriginalPacket = nil
		compact = q
	}
	r.Body, err = json.Marshal(compact)
	return r, err
}
