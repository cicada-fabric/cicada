package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var errThreadGroupUnconfirmed = errors.New("Thread Group outcome is unconfirmed; original packet retained")

func threadGroupRequestParts(request any) (wire.AppNodeRequestContext, []byte) {
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		return q.Context, q.OwnerProof
	case wire.OwnerEndpointGroupsPrepareRequest:
		return q.Context, q.OwnerProof
	case wire.OwnerEndpointGroupsApplyRequest:
		return q.Context, q.OwnerProof
	case wire.OwnerEndpointGroupsStatusRequest:
		return q.Context, q.OwnerProof
	case wire.OwnerEndpointGroupsReconcileRequest:
		return q.Context, q.OwnerProof
	}
	return wire.AppNodeRequestContext{}, nil
}

func (c *nativeController) discoverThreadGroups(ctx context.Context) error {
	c.threadGroups.discoveryTried, c.threadGroups.available = true, false
	c.threadGroups.nativeSelfGroups = false
	target, err := joinOrigin(c.connection.Origin, wire.OwnerEndpointGroupsCapabilitiesPath)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil // Older Hub: no state write or fallback route.
	}
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 {
		return wire.ErrInvalid
	}
	capability, err := wire.DecodeOwnerEndpointGroupsCapabilities(raw, c.hub)
	if err == nil {
		c.threadGroups.available = capability.Available
		c.threadGroups.nativeSelfGroups = capability.NativeSelfGroups
	} else {
		c.threadGroups.discoveryTried = false
	}
	return err
}

func (c *nativeController) postThreadGroupPacket(ctx context.Context, record *threadGroupRecord) ([]byte, error) {
	path := wire.OwnerEndpointGroupsHTTPPath(record.Route.Operation)
	if path == "" || len(record.Packet) == 0 || c.httpClient() == nil {
		return nil, ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(call, http.MethodPost, target, bytes.NewReader(record.Packet))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Origin", c.connection.Origin)
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, errThreadGroupUnconfirmed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return nil, errThreadGroupUnconfirmed
	}
	limit := wire.MaxOwnerEndpointGroupsPacketBytes
	if record.Route.Operation == wire.OperationOwnerEndpointGroupsReconcile || record.Route.Operation == wire.OperationOwnerEndpointGroupsStatus {
		limit = wire.MaxOwnerEndpointGroupsReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, errThreadGroupUnconfirmed
	}
	return raw, nil
}

func (c *nativeController) newThreadGroupRecord(request any, seed *threadGroupRecord) (*threadGroupRecord, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	packet, err := wire.SealClientRequest(device, c.hub, request)
	if err != nil {
		return nil, err
	}
	opened, err := wire.DecodeOwnerEndpointGroupsPacket(packet)
	if err != nil {
		clear(packet)
		return nil, err
	}
	r := &threadGroupRecord{Format: "cicada.app-endpoint-groups.request.v1", Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID,
		OwnerKeyID: c.state.OwnerKeyID, Route: opened.Packet.Route, Digest: wire.OwnerEndpointGroupsPacketDigest(packet), Packet: packet,
		CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if seed != nil {
		r.NodeID, r.NetworkID = seed.NodeID, seed.NetworkID
		r.NetworkName = seed.NetworkName
		r.LocalUserScope = seed.LocalUserScope
		r.Review, r.ExpectedHead, r.Binding, r.Thread, r.Group, r.Relation = seed.Review, seed.ExpectedHead, seed.Binding, seed.Thread, seed.Group, seed.Relation
	}
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		r.NodeID, r.NetworkID = q.Body.NodeID, q.Body.NetworkID
	case wire.OwnerEndpointGroupsPrepareRequest:
		r.NodeID, r.NetworkID = q.Body.NodeID, q.Body.NetworkID
	case wire.OwnerEndpointGroupsReconcileRequest:
		if seed == nil {
			clear(packet)
			return nil, wire.ErrInvalid
		}
		r.ParentDigest = seed.Digest
		// The original already occupies its own immutable slot. Reconstruct
		// this typed reference for validation; never reseal the saved packet.
		q.Body.OriginalPacket = nil
		request = q
	case wire.OwnerEndpointGroupsStatusRequest:
		if seed != nil {
			r.ParentDigest = seed.Digest
		}
	}
	r.DTO, err = json.Marshal(request)
	if err != nil {
		clear(packet)
		return nil, err
	}
	return r, nil
}

func (c *nativeController) threadGroupDTO(record, original *threadGroupRecord) (any, error) {
	raw := record.DTO
	if record.Route.Operation == wire.OperationOwnerEndpointGroupsReconcile {
		var q wire.OwnerEndpointGroupsReconcileRequest
		if original == nil || record.ParentDigest != original.Digest || decodeStateJSON(raw, &q) != nil || len(q.Body.OriginalPacket) != 0 {
			return nil, wire.ErrInvalid
		}
		q.Body.OriginalPacket = original.Packet
		var err error
		raw, err = json.Marshal(q)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
	}
	request, err := wire.DecodeOwnerEndpointGroupsRequest(record.Route.Operation, raw, c.hub, time.Time{})
	if err != nil {
		return nil, err
	}
	qctx, proof := threadGroupRequestParts(request)
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(record.Route.Operation), time.Time{})
	if err != nil || qctx.RequestID != record.Route.OperationID || qctx.Origin != c.connection.Origin || qctx.AccountID != c.state.AccountID ||
		qctx.OwnerID != c.state.OwnerID || qctx.DeviceID != c.state.DeviceID || !reflect.DeepEqual(claims.Scope.DevicePublic, c.device.Public()) {
		return nil, appvault.ErrScopeMismatch
	}
	if err := c.validateThreadGroupTarget(record, request); err != nil {
		return nil, err
	}
	return request, nil
}

func (c *nativeController) validateThreadGroupRecord(record, original *threadGroupRecord) error {
	if record == nil || record.Format != "cicada.app-endpoint-groups.request.v1" || record.Vault != cardScope(c.connection) ||
		record.DeviceKeyID != c.state.DeviceKeyID || record.OwnerKeyID != c.state.OwnerKeyID || parseExpiry(record.CreatedAt).IsZero() {
		return appvault.ErrScopeMismatch
	}
	packet, err := wire.DecodeOwnerEndpointGroupsPacket(record.Packet)
	if err != nil || packet.Packet.Route != record.Route || record.Route.Direction != clientwire.DirectionRequest || record.Digest != wire.OwnerEndpointGroupsPacketDigest(record.Packet) ||
		record.Route.HubID != c.hub.HubID || record.Route.OwnerID != c.state.OwnerID || record.Route.DeviceID != c.state.DeviceID ||
		record.Route.SenderKeyID != c.state.DeviceKeyID || record.Route.ReceiverKeyID != c.hub.Public.ID || !reflect.DeepEqual(packet.SenderPublicIdentity, c.device.Public()) {
		return appvault.ErrScopeMismatch
	}
	_, err = c.threadGroupDTO(record, original)
	return err
}

func (c *nativeController) openThreadGroupResult(record *threadGroupRecord, raw []byte, original *threadGroupRecord) (*wire.OwnerEndpointGroupsResult, error) {
	request, err := c.threadGroupDTO(record, original)
	if err != nil {
		return nil, err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	var result wire.OwnerEndpointGroupsResult
	if wire.OpenOwnerEndpointGroupsResponse(device, c.hub, record.Packet, raw, &result) != nil || wire.VerifyOwnerEndpointGroupsResult(request, record.Packet, result, c.hub) != nil {
		return nil, wire.ErrInvalid
	}
	if err := c.verifyThreadGroupResultTarget(record, &result, original); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *nativeController) saveThreadGroupResponse(index int, request *threadGroupRecord, raw []byte) (*threadGroupRecord, error) {
	r := &threadGroupRecord{Format: "cicada.app-endpoint-groups.response.v1", Vault: request.Vault, DeviceKeyID: request.DeviceKeyID, OwnerKeyID: request.OwnerKeyID,
		NodeID: request.NodeID, NetworkID: request.NetworkID, Route: request.Route, Digest: wire.OwnerEndpointGroupsPacketDigest(raw), ParentDigest: request.Digest,
		CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano), Packet: append([]byte(nil), raw...)}
	if err := c.persistThreadGroupRecord(index, r); err != nil {
		clear(r.Packet)
		return nil, err
	}
	return r, nil
}
