package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) discoverLocalCollaboration(ctx context.Context) error {
	c.localDomain.discoveryTried, c.localDomain.available = true, false
	target, err := joinOrigin(c.connection.Origin, wire.LocalDomainCapabilitiesPath)
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
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		return wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxLocalDomainCapabilitiesBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > wire.MaxLocalDomainCapabilitiesBytes {
		return wire.ErrInvalid
	}
	capabilities, err := wire.DecodeLocalDomainCapabilities(raw)
	if err != nil {
		return err
	}
	if c.connection.AllowLoopbackHTTP && c.cfg.AllowLoopbackHTTP {
		if capabilities.TransportPolicy != wire.AppNodeTransportLoopbackTest {
			return wire.ErrInvalid
		}
	} else if capabilities.TransportPolicy != wire.AppNodeTransportHTTPS {
		return wire.ErrInvalid
	}
	c.localDomain.available = capabilities.Available
	return nil
}

func (c *nativeController) postLocalDomainPacket(ctx context.Context, request *localDomainRecord) ([]byte, error) {
	if request == nil || len(request.Packet) == 0 || c.httpClient() == nil {
		return nil, ErrInvalidAction
	}
	path := wire.LocalDomainHTTPPath(request.Route.Operation)
	if path == "" {
		return nil, ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(call, http.MethodPost, target, bytes.NewReader(request.Packet))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", c.connection.Origin)
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.httpClient().Do(r)
	if err != nil {
		return nil, errLocalDomainUnconfirmed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		return nil, errLocalDomainUnconfirmed
	}
	limit := wire.MaxLocalDomainPacketBytes
	if request.Route.Operation == wire.OperationLocalDomainReconcile {
		limit = wire.MaxLocalDomainReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, errLocalDomainUnconfirmed
	}
	return raw, nil
}

func localDomainRequestParts(body any) (wire.AppNodeRequestContext, []byte, error) {
	switch q := body.(type) {
	case wire.LocalDomainPrepare:
		return q.Context, q.OwnerProof, nil
	case wire.LocalDomainActivate:
		return q.Context, q.OwnerProof, nil
	case wire.LocalDomainStatusRequest:
		return q.Context, q.OwnerProof, nil
	case wire.LocalDomainRevoke:
		return q.Context, q.OwnerProof, nil
	case wire.LocalDomainReconcileRequest:
		return q.Context, nil, nil
	}
	return wire.AppNodeRequestContext{}, nil, wire.ErrInvalid
}

func (c *nativeController) localDomainDTO(record, original *localDomainRecord) (any, error) {
	var body any
	switch record.Route.Operation {
	case wire.OperationLocalDomainPrepare:
		var q wire.LocalDomainPrepare
		if decodeStateJSON(record.DTO, &q) != nil {
			return nil, wire.ErrInvalid
		}
		body = q
	case wire.OperationLocalDomainActivate:
		var q wire.LocalDomainActivate
		if decodeStateJSON(record.DTO, &q) != nil {
			return nil, wire.ErrInvalid
		}
		body = q
	case wire.OperationLocalDomainStatus:
		var q wire.LocalDomainStatusRequest
		if decodeStateJSON(record.DTO, &q) != nil {
			return nil, wire.ErrInvalid
		}
		body = q
	case wire.OperationLocalDomainRevoke:
		var q wire.LocalDomainRevoke
		if decodeStateJSON(record.DTO, &q) != nil {
			return nil, wire.ErrInvalid
		}
		body = q
	case wire.OperationLocalDomainReconcile:
		var q wire.LocalDomainReconcileRequest
		if original == nil || decodeStateJSON(record.DTO, &q) != nil || len(q.OriginalPacket) != 0 {
			return nil, wire.ErrInvalid
		}
		q.OriginalPacket = original.Packet
		body = q
	default:
		return nil, wire.ErrInvalid
	}
	context, rawProof, err := localDomainRequestParts(body)
	if err != nil || context.RequestID != record.Route.OperationID || context.HubID != c.hub.HubID || context.OwnerID != c.state.OwnerID || context.AccountID != c.state.AccountID || context.DeviceID != c.state.DeviceID {
		return nil, appvault.ErrScopeMismatch
	}
	if record.Route.Operation == wire.OperationLocalDomainReconcile {
		return body, nil
	}
	claims, err := e2ee.VerifyOwnerLocalDomainRequest(c.owner.Public(), rawProof, wire.LocalDomainOwnerPurpose(record.Route.Operation), time.Time{})
	if err != nil || claims.RequestID != context.RequestID || claims.Scope.Origin != c.connection.Origin || claims.Scope.HubID != c.hub.HubID || claims.Scope.HubFingerprint != c.connection.HubFingerprint || claims.Scope.OwnerID != c.state.OwnerID || claims.Scope.AccountID != c.state.AccountID || claims.Scope.DeviceID != c.state.DeviceID || !reflect.DeepEqual(claims.Scope.OwnerPublic, c.owner.Public()) || !reflect.DeepEqual(claims.Scope.DevicePublic, c.device.Public()) {
		return nil, appvault.ErrScopeMismatch
	}
	if _, ok := body.(wire.LocalDomainPrepare); ok {
		if claims.Target == nil || claims.Target.Node.NodeID != record.NodeID {
			return nil, appvault.ErrScopeMismatch
		}
	}
	if _, ok := body.(wire.LocalDomainStatusRequest); ok {
		if claims.NodeID != record.NodeID || claims.PolicyID != "" {
			return nil, appvault.ErrScopeMismatch
		}
	}
	if q, ok := body.(wire.LocalDomainActivate); ok {
		policy, err := e2ee.VerifyOwnerLocalDomainPolicy(c.owner.Public(), q.PolicyProof, time.Time{})
		if err != nil || policy.Node.NodeID != record.NodeID {
			return nil, appvault.ErrScopeMismatch
		}
	}
	if _, ok := body.(wire.LocalDomainRevoke); ok {
		p := record.PolicyTarget
		if p == nil || p.Node.NodeID != record.NodeID || p.PolicyID != claims.PolicyID || p.Epoch != claims.PolicyEpoch {
			return nil, appvault.ErrScopeMismatch
		}
		digest, err := e2ee.LocalDomainPolicyDigest(*p)
		if err != nil || digest != claims.PolicyDigest {
			return nil, appvault.ErrScopeMismatch
		}
	}
	return body, nil
}

type localDomainReceipt struct {
	Challenge *wire.LocalDomainChallenge
	Result    *wire.LocalDomainResult
	Recovery  *wire.LocalDomainReconciled
	Nested    *localDomainReceipt
}

func (c *nativeController) openLocalDomainReceipt(request *localDomainRecord, raw []byte, original *localDomainRecord) (localDomainReceipt, error) {
	var value localDomainReceipt
	if request == nil || len(raw) == 0 || c.device == nil {
		return value, wire.ErrInvalid
	}
	device, err := c.device.E2EE()
	if err != nil {
		return value, err
	}
	body, err := c.localDomainDTO(request, original)
	if err != nil {
		return value, err
	}
	open := func(out any) error { return wire.OpenLocalDomainResponse(device, c.hub, request.Packet, raw, out) }
	if request.Route.Operation == wire.OperationLocalDomainReconcile {
		var result wire.LocalDomainReconciled
		if original == nil || open(&result) != nil || result.RequestPacketDigest != request.Digest || result.OriginalOperation != original.Route.Operation || result.OriginalRequestID != original.Route.OperationID || result.OriginalPacketDigest != original.Digest {
			return value, wire.ErrInvalid
		}
		nested, err := c.openLocalDomainReceipt(original, result.ReceiptPacket, nil)
		if err != nil {
			return value, err
		}
		value.Recovery, value.Nested = &result, &nested
		return value, nil
	}
	if prepare, ok := body.(wire.LocalDomainPrepare); ok {
		var challenge wire.LocalDomainChallenge
		if open(&challenge) == nil && wire.ValidateLocalDomainChallenge(prepare, request.Packet, challenge, c.hub, time.Time{}) == nil {
			value.Challenge = &challenge
			return value, nil
		}
	}
	var result wire.LocalDomainResult
	if open(&result) != nil || wire.ValidateLocalDomainResultTarget(body, request.Packet, result, c.hub) != nil {
		return value, wire.ErrInvalid
	}
	if result.Description != nil && result.Description.Policy.Node.NodeID != request.NodeID {
		return value, wire.ErrInvalid
	}
	value.Result = &result
	return value, nil
}

func (c *nativeController) saveLocalDomainResponse(index int, request *localDomainRecord, raw []byte) (*localDomainRecord, error) {
	response := &localDomainRecord{Format: "cicada.app-local-domain.response.v1", Vault: request.Vault, DeviceKeyID: request.DeviceKeyID, OwnerKeyID: request.OwnerKeyID, NodeID: request.NodeID, Route: request.Route, Digest: wire.LocalDomainPacketDigest(raw), RequestDigest: request.Digest, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano), Packet: append([]byte(nil), raw...)}
	if err := c.persistLocalDomain(index, response); err != nil {
		clear(response.Packet)
		return nil, err
	}
	return response, nil
}

func (c *nativeController) newLocalDomainRequest(node string, body any) (*localDomainRecord, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	raw, err := wire.SealClientRequest(device, c.hub, body)
	if err != nil {
		return nil, err
	}
	packet, err := wire.DecodeLocalDomainPacket(raw)
	if err != nil {
		clear(raw)
		return nil, err
	}
	if q, ok := body.(wire.LocalDomainReconcileRequest); ok {
		q.OriginalPacket = nil
		body = q
	}
	dto, err := json.Marshal(body)
	if err != nil {
		clear(raw)
		return nil, err
	}
	record := &localDomainRecord{Format: "cicada.app-local-domain.request.v1", Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, NodeID: node, Route: packet.Packet.Route, Digest: wire.LocalDomainPacketDigest(raw), Packet: raw, DTO: dto, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if _, ok := body.(wire.LocalDomainRevoke); ok {
		if c.localDomain.state.Description == nil {
			clear(raw)
			clear(dto)
			return nil, wire.ErrInvalid
		}
		policy := c.localDomain.state.Description.Policy
		record.PolicyTarget = &policy
	}
	return record, nil
}
