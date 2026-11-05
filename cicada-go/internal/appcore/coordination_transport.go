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

var errCoordinationUnconfirmed = errors.New("Owner coordination outcome is unconfirmed; original retained")

func e2eeCoordinationClaims(c *nativeController, proof []byte, op string) (e2ee.OwnerEndpointGroupsRequestClaims, error) {
	return e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.ThreadCollaborationOwnerPurpose(op), time.Time{})
}

func coordinationParts(request any) (wire.AppNodeRequestContext, []byte, []byte) {
	switch q := request.(type) {
	case wire.ThreadCollaborationOwnerReadRequest:
		return q.Context, q.SessionToken, q.OwnerProof
	case wire.ThreadCollaborationOwnerPrepareRequest:
		return q.Context, q.SessionToken, q.OwnerProof
	case wire.ThreadCollaborationOwnerApplyRequest:
		return q.Context, q.SessionToken, q.OwnerProof
	case wire.ThreadCollaborationOwnerStatusRequest:
		return q.Context, q.SessionToken, q.OwnerProof
	case wire.ThreadCollaborationOwnerReconcileRequest:
		return q.Context, q.SessionToken, q.OwnerProof
	}
	return wire.AppNodeRequestContext{}, nil, nil
}

func (c *nativeController) newCoordinationRecord(request any, review *wire.ThreadCollaborationOwnerReview) (*coordinationRecord, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	packet, err := wire.SealClientRequest(device, c.hub, request)
	if err != nil {
		return nil, err
	}
	opened, err := wire.DecodeThreadCollaborationOwnerPacket(packet)
	if err != nil {
		clear(packet)
		return nil, err
	}
	r := &coordinationRecord{Format: "cicada.app-thread-collaboration.request.v1", Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, Route: opened.Packet.Route, Digest: wire.ThreadCollaborationOwnerPacketDigest(packet), Packet: packet, Review: review, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if q, ok := request.(wire.ThreadCollaborationOwnerPrepareRequest); ok {
		if role := q.Body.Role; role != nil && c.threadGroups.selected != nil && c.threadGroups.selected.EndpointID == role.EndpointID {
			r.DisplayName = c.threadGroups.selected.Name
		}
		group := ""
		if q.Body.Policy != nil {
			group = q.Body.Policy.GroupID
			r.DisplayName = q.Body.Policy.Name
		}
		if q.Body.Clear != nil {
			group = q.Body.Clear.Scope.GroupID
		}
		if group != "" {
			if read := c.currentCoordinationRead("", group); read != nil && read.Group != nil {
				r.DisplayName = read.Group.Name
				if q.Body.Clear != nil && read.GroupSlots != nil {
					for _, slot := range read.GroupSlots.Slots {
						if slot.Slot == q.Body.Clear.Slot && slot.HolderNameState == "VISIBLE" {
							r.HolderName = slot.HolderName
						}
					}
				}
			}
		}
	}
	if review != nil && c.coordination.reviewOriginal != nil {
		r.DisplayName = c.coordination.reviewOriginal.DisplayName
		r.HolderName = c.coordination.reviewOriginal.HolderName
	}
	if q, ok := request.(wire.ThreadCollaborationOwnerReconcileRequest); ok {
		r.ParentDigest = wire.ThreadCollaborationOwnerPacketDigest(q.Body.OriginalPacket)
		q.Body.OriginalPacket = nil
		request = q
	}
	r.DTO, err = json.Marshal(request)
	if err != nil {
		clear(packet)
		return nil, err
	}
	return r, nil
}

func (c *nativeController) coordinationDTO(record *coordinationRecord) (any, error) {
	raw := record.DTO
	if record.Route.Operation == wire.OperationThreadCollaborationOwnerReconcile {
		var q wire.ThreadCollaborationOwnerReconcileRequest
		original := c.coordination.original
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
	q, err := wire.DecodeThreadCollaborationOwnerRequest(record.Route.Operation, raw, c.hub, time.Time{})
	if err != nil {
		return nil, err
	}
	qctx, _, proof := coordinationParts(q)
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.ThreadCollaborationOwnerPurpose(record.Route.Operation), time.Time{})
	if err != nil || qctx.RequestID != record.Route.OperationID || qctx.Origin != c.connection.Origin || qctx.AccountID != c.state.AccountID || qctx.OwnerID != c.state.OwnerID || qctx.DeviceID != c.state.DeviceID || !reflect.DeepEqual(claims.Scope.OwnerPublic, c.owner.Public()) || !reflect.DeepEqual(claims.Scope.DevicePublic, c.device.Public()) {
		return nil, appvault.ErrScopeMismatch
	}
	return q, nil
}

func (c *nativeController) validateCoordinationRecord(r *coordinationRecord) error {
	if c.owner == nil || c.device == nil {
		return appvault.ErrScopeMismatch
	}
	if r == nil || r.Format != "cicada.app-thread-collaboration.request.v1" || r.Vault != cardScope(c.connection) || r.DeviceKeyID != c.state.DeviceKeyID || r.OwnerKeyID != c.state.OwnerKeyID || parseExpiry(r.CreatedAt).IsZero() {
		return appvault.ErrScopeMismatch
	}
	p, err := wire.DecodeThreadCollaborationOwnerPacket(r.Packet)
	if err != nil || p.Packet.Route != r.Route || r.Route.Direction != clientwire.DirectionRequest || r.Digest != wire.ThreadCollaborationOwnerPacketDigest(r.Packet) || r.Route.HubID != c.hub.HubID || r.Route.OwnerID != c.state.OwnerID || r.Route.DeviceID != c.state.DeviceID || r.Route.SenderKeyID != c.state.DeviceKeyID || r.Route.ReceiverKeyID != c.hub.Public.ID || !reflect.DeepEqual(p.SenderPublicIdentity, c.device.Public()) {
		return appvault.ErrScopeMismatch
	}
	_, err = c.coordinationDTO(r)
	return err
}

func (c *nativeController) validateCoordinationResponse(q, r *coordinationRecord) error {
	if r.Format != "cicada.app-thread-collaboration.response.v1" || r.Vault != q.Vault || r.DeviceKeyID != q.DeviceKeyID || r.OwnerKeyID != q.OwnerKeyID || r.Route != q.Route || r.ParentDigest != q.Digest || r.Digest != wire.ThreadCollaborationOwnerPacketDigest(r.Packet) {
		return appvault.ErrScopeMismatch
	}
	return nil
}

func (c *nativeController) openCoordinationResult(r *coordinationRecord, raw []byte) (*wire.ThreadCollaborationOwnerResult, error) {
	request, err := c.coordinationDTO(r)
	if err != nil {
		return nil, err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	var result wire.ThreadCollaborationOwnerResult
	if wire.OpenThreadCollaborationOwnerResponse(device, c.hub, r.Packet, raw, &result) != nil || wire.VerifyThreadCollaborationOwnerResult(request, r.Packet, result, c.hub) != nil {
		return nil, wire.ErrInvalid
	}
	if apply, ok := request.(wire.ThreadCollaborationOwnerApplyRequest); ok && result.State == "COMPLETED" {
		if r.Review == nil || wire.VerifyThreadCollaborationOwnerOperation(*r.Review, apply, r.Packet, result, c.hub) != nil {
			return nil, wire.ErrInvalid
		}
	}
	return &result, nil
}

func (c *nativeController) postCoordinationPacket(ctx context.Context, r *coordinationRecord) ([]byte, error) {
	path := wire.ThreadCollaborationHTTPPath(r.Route.Operation)
	if path == "" || len(r.Packet) == 0 || c.httpClient() == nil {
		return nil, ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(call, http.MethodPost, target, bytes.NewReader(r.Packet))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Origin", c.connection.Origin)
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, errCoordinationUnconfirmed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return nil, errCoordinationUnconfirmed
	}
	limit := wire.MaxThreadCollaborationOwnerPacketBytes
	if r.Route.Operation == wire.OperationThreadCollaborationOwnerReconcile || r.Route.Operation == wire.OperationThreadCollaborationOwnerStatus {
		limit = wire.MaxThreadCollaborationReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, errCoordinationUnconfirmed
	}
	return raw, nil
}

func (c *nativeController) discoverCoordination(ctx context.Context) error {
	g := &c.coordination
	g.discoveryTried, g.rolesAvailable, g.locksAvailable = true, false, false
	target, err := joinOrigin(c.connection.Origin, wire.ThreadCollaborationCapabilitiesPath)
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
		g.discoveryTried = false
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil
	}
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		g.discoveryTried = false
		return wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 {
		g.discoveryTried = false
		return wire.ErrInvalid
	}
	capability, err := wire.DecodeThreadCollaborationCapabilities(raw, c.hub)
	if err != nil {
		g.discoveryTried = false
		return err
	}
	g.rolesAvailable, g.locksAvailable = capability.ThreadScopeRoleAvailable, capability.GroupLocksAvailable
	return nil
}
