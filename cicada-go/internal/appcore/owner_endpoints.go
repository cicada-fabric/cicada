package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	ActionReadOwnerEndpoints    ActionKind = "READ_EXACT_OWNER_NODE_ENDPOINTS"
	ActionRecoverOwnerEndpoints ActionKind = "RECOVER_EXACT_OWNER_ENDPOINT_READ"
	ActionParkOwnerEndpoints    ActionKind = "RETAIN_UNCONFIRMED_OWNER_ENDPOINT_READ"
)

// A click approves one page for the exact displayed original Node. This local
// input is not an authorization credential and never supplies an Owner/SID.
type OwnerEndpointReadAction struct {
	ReviewID    string
	Cursor      string
	Limit       int
	ConfirmRead bool
	ConfirmPark bool
}

type OwnerEndpointView struct {
	EndpointID string `json:"endpoint_id"`
	Name       string `json:"name"`
	Workspace  string `json:"workspace"`
	Harness    string `json:"harness"`
	Presence   string `json:"presence"`
}

// All rows are snapshots. There is deliberately no management/communication
// permission or live-online flag in this view.
type OwnerEndpointSnapshot struct {
	Available       bool                `json:"available"`
	Pending         bool                `json:"pending"`
	NodeID          string              `json:"node_id,omitempty"`
	NodeName        string              `json:"node_name,omitempty"`
	ReviewID        string              `json:"review_id,omitempty"`
	NextReviewID    string              `json:"next_review_id,omitempty"`
	State           string              `json:"state,omitempty"`
	CapturedAt      string              `json:"captured_at,omitempty"`
	NextCursor      string              `json:"next_cursor,omitempty"`
	Endpoints       []OwnerEndpointView `json:"endpoints,omitempty"`
	ErrorCode       string              `json:"error_code,omitempty"`
	ParkReviewID    string              `json:"park_review_id,omitempty"`
	ParkAfter       string              `json:"park_after,omitempty"`
	RetainedUnknown int                 `json:"retained_unknown"`
}

func ownerEndpointActionKind(kind ActionKind) bool {
	return kind == ActionReadOwnerEndpoints || kind == ActionRecoverOwnerEndpoints || kind == ActionParkOwnerEndpoints
}

func nodePacketHTTPPath(operation string) string {
	if operation == wire.OperationOwnerEndpointRead {
		return wire.OwnerEndpointReadPath
	}
	return wire.AppNodeHTTPPath(operation)
}

func (c *nativeController) hasOwnerEndpointPending() bool {
	p := c.node.Pending
	return p.unresolved() && p.Operation == wire.OperationOwnerEndpointRead
}

func (c *nativeController) canReadOwnerEndpoints() bool {
	return c.pairAccountReady() && c.canBeginOperation() && !c.hasNodePending() && len(c.node.OwnerDirectoryUnknown) < ownerEndpointUnknownMax && c.ownerEndpointError != "APP_OWNER_DIRECTORY_HISTORY_FULL"
}

func (c *nativeController) ownerEndpointActions() []ActionKind {
	if c.storageFault || !c.connected || c.device == nil || c.vault == nil {
		return nil
	}
	if c.hasOwnerEndpointPending() {
		actions := []ActionKind{ActionRecoverOwnerEndpoints}
		if c.ownerEndpointParkReviewID() != "" && c.ownerEndpointUnknownFits(c.node.Pending) {
			actions = append(actions, ActionParkOwnerEndpoints)
		}
		return actions
	}
	if c.canReadOwnerEndpoints() {
		return []ActionKind{ActionReadOwnerEndpoints}
	}
	return nil
}

func (c *nativeController) ownerEndpointReviewID(cursor string, limit int) string {
	if !c.pairAccountReady() || limit < 1 || limit > 64 || len(cursor) > 256 {
		return ""
	}
	// Bind the native gesture to current local identities/session and the full
	// immutable INITIAL Node binding. No network/KDF work happens in publish.
	raw, err := json.Marshal(struct {
		Node                                 e2ee.OwnerAppNodeBinding
		AccountEpoch, DeviceEpoch            uint64
		SessionExpiry, SessionDigest, Cursor string
		Limit                                int
	}{c.nodeConfirmation.Binding, c.session.AccountEpoch, c.session.DeviceEpoch, c.session.ExpiresAt, sessionTokenDigest(c.session.SessionToken), cursor, limit})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("cicada/app/owner-directory-review/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func sessionTokenDigest(token []byte) string {
	digest := sha256.Sum256(token)
	return hex.EncodeToString(digest[:])
}

func (c *nativeController) discoverOwnerEndpoints(ctx context.Context) error {
	c.ownerEndpointAvailable = false
	if !c.connected || c.device == nil || c.owner == nil || c.httpClient() == nil {
		return ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, wire.OwnerEndpointReadPath)
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
		return errors.New("Owner directory availability is unknown")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != request.URL.String()) {
		return errors.New("Owner directory is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxOwnerEndpointCapabilitiesBytes+1))
	if err != nil || len(raw) > wire.MaxOwnerEndpointCapabilitiesBytes {
		return wire.ErrInvalid
	}
	capabilities, err := wire.ParseOwnerEndpointReadCapabilities(raw, c.hub)
	if err != nil || !capabilities.Available {
		return wire.ErrInvalid
	}
	c.ownerEndpointAvailable = true
	return nil
}

func (c *nativeController) readOwnerEndpoints(ctx context.Context, action OwnerEndpointReadAction) error {
	if !c.canReadOwnerEndpoints() || !action.ConfirmRead || action.ReviewID == "" ||
		action.ReviewID != c.ownerEndpointReviewID(action.Cursor, action.Limit) {
		return ErrInvalidAction
	}
	if action.Cursor != "" && (c.ownerEndpointResult == nil || action.Cursor != c.ownerEndpointResult.NextCursor) {
		return ErrInvalidAction
	}
	// Old/unavailable Hubs receive no new proof, durable read or secret POST.
	if err := c.discoverOwnerEndpoints(ctx); err != nil {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_UNAVAILABLE", err)
	}
	scope, err := c.pairActor(ctx)
	if err != nil {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_UNAVAILABLE", err)
	}
	if !c.canReadOwnerEndpoints() || action.ReviewID != c.ownerEndpointReviewID(action.Cursor, action.Limit) {
		return ErrInvalidAction
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewOwnerEndpointRead(c.nodeSession(), scope, c.nodeConfirmation.Binding, action.Cursor, action.Limit, owner, c.cfg.Now().UTC())
	if err != nil {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_REQUEST_INVALID", err)
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	packet, err := wire.SealClientRequest(device, c.hub, request)
	if err != nil || len(packet) > wire.MaxAppNodeOriginalBytes {
		clear(packet)
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_REQUEST_INVALID", wire.ErrInvalid)
	}
	// Reuse the existing single serialized Node outbox, not a parallel queue.
	pending := &nodeOperation{Kind: wire.AppNodeOriginalAuthority, Operation: wire.OperationOwnerEndpointRead,
		Request: packet, CreatedAt: request.Context.IssuedAt, OwnerEndpointRead: &request}
	if !c.ownerEndpointUnknownFits(pending) {
		clear(packet)
		clear(request.SessionToken)
		clear(request.OwnerProof)
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_HISTORY_FULL", errors.New("unconfirmed directory history capacity is exhausted"))
	}
	c.node.Pending = pending
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	c.ownerEndpointError = ""
	c.publish()
	if err := c.sendNodePending(ctx, true); err != nil {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_REQUEST_UNKNOWN", err)
	}
	return nil
}

func (c *nativeController) recoverOwnerEndpoints(ctx context.Context) error {
	if c.device == nil || c.vault == nil || !c.connected || !c.hasOwnerEndpointPending() {
		return ErrInvalidAction
	}
	// Public GET/unsigned errors cannot dispose of this packet. The old N3
	// reconcile allowlist does not contain this new purpose: only original
	// bytes and an authenticated, target-bound result settle it here.
	if err := c.sendNodePending(ctx, false); err != nil {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_REQUEST_UNKNOWN", err)
	}
	c.ownerEndpointError = ""
	c.publish()
	return nil
}

func (c *nativeController) validateOwnerEndpointOperation(p *nodeOperation) error {
	if p == nil || p.Kind != wire.AppNodeOriginalAuthority || p.Operation != wire.OperationOwnerEndpointRead || p.OwnerEndpointRead == nil || c.owner == nil {
		return wire.ErrInvalid
	}
	q := p.OwnerEndpointRead
	proof, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), q.OwnerProof, time.Time{})
	packet, packetErr := wire.PreflightRequest(p.Request, wire.OperationOwnerEndpointRead)
	if err != nil || packetErr != nil || !c.nodeScopeMatches(proof.Scope) || q.Format != wire.OwnerEndpointReadFormat ||
		!reflect.DeepEqual(packet.SenderPublicIdentity, proof.Scope.DevicePublic) ||
		len(q.SessionToken) != wire.MaxSessionTokenBytes || q.Context.RequestID != proof.RequestID || hex.EncodeToString(q.Context.ClientNonce) != proof.Nonce ||
		q.Context.IssuedAt != proof.IssuedAt || p.CreatedAt != proof.IssuedAt || packet.Packet.Route.OperationID != proof.RequestID ||
		q.Context.HubID != proof.Scope.HubID || q.Context.Origin != proof.Scope.Origin || q.Context.AccountID != proof.Scope.AccountID ||
		q.Context.OwnerID != proof.Scope.OwnerID || q.Context.DeviceID != proof.Scope.DeviceID ||
		q.Context.AccountEpoch != proof.Scope.AccountEpoch || q.Context.DeviceEpoch != proof.Scope.DeviceEpoch {
		return wire.ErrInvalid
	}
	return nil
}

func (c *nativeController) openOwnerEndpointResponse(p *nodeOperation, raw []byte) (*wire.OwnerEndpointReadResult, error) {
	if err := c.validateOwnerEndpointOperation(p); err != nil {
		return nil, err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	var result wire.OwnerEndpointReadResult
	if wire.OpenClientResponse(device, c.hub, p.Request, raw, &result) != nil ||
		wire.VerifyOwnerEndpointReadResult(result, *p.OwnerEndpointRead, p.Request) != nil {
		return nil, wire.ErrInvalid
	}
	return &result, nil
}

func (c *nativeController) applyOwnerEndpointResponse(p *nodeOperation, result *wire.OwnerEndpointReadResult) error {
	p.Applied = true
	c.node.OwnerDirectory = p
	c.ownerEndpointResult, c.ownerEndpointError = result, ""
	return c.persistNode()
}

func (c *nativeController) restoreOwnerDirectory() error {
	c.ownerEndpointResult = nil
	if err := c.validateOwnerEndpointUnknownHistory(); err != nil {
		return err
	}
	if p := c.node.OwnerDirectory; p != nil {
		if c.validateNodeStoredPacket(p) != nil || !p.Applied || len(p.Response) == 0 {
			return wire.ErrInvalid
		}
		result, err := c.openOwnerEndpointResponse(p, p.Response)
		if err != nil {
			return err
		}
		c.ownerEndpointResult = result
	}
	return nil
}

func (c *nativeController) failOwnerEndpoints(code string, err error) error {
	c.ownerEndpointError = code
	c.publish()
	return err
}

func (c *nativeController) populateOwnerEndpoints(view *Snapshot) {
	view.OwnerEndpoints = OwnerEndpointSnapshot{Pending: c.hasOwnerEndpointPending(), ErrorCode: c.ownerEndpointError}
	if !c.pairAccountReady() {
		return
	}
	binding := c.nodeConfirmation.Binding
	v := &view.OwnerEndpoints
	v.RetainedUnknown = len(c.node.OwnerDirectoryUnknown)
	if c.ownerEndpointUnknownFits(c.node.Pending) {
		v.ParkReviewID = c.ownerEndpointParkReviewID()
		if v.ParkReviewID != "" {
			claims, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), c.node.Pending.OwnerEndpointRead.OwnerProof, time.Time{})
			if err == nil {
				v.ParkAfter = claims.ExpiresAt
			}
		}
	}
	v.Available, v.NodeID, v.NodeName = c.ownerEndpointAvailable, binding.NodeID, binding.NodeName
	if c.canReadOwnerEndpoints() {
		v.ReviewID = c.ownerEndpointReviewID("", 64)
	}
	result, original := c.ownerEndpointResult, c.node.OwnerDirectory
	if result == nil || original == nil || original.OwnerEndpointRead == nil || result.NodeID != binding.NodeID {
		return
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), original.OwnerEndpointRead.OwnerProof, time.Time{})
	if err != nil || !reflect.DeepEqual(claims.Node, binding) || claims.Scope.AccountEpoch != c.session.AccountEpoch || claims.Scope.DeviceEpoch != c.session.DeviceEpoch {
		return
	}
	v.CapturedAt = result.CapturedAt
	if result.State != wire.AppNodeCompleted {
		v.State = "READ_EXPIRED"
		return
	}
	v.State, v.NextCursor = "SNAPSHOT_ONLY", result.NextCursor
	for _, card := range result.Endpoints {
		v.Endpoints = append(v.Endpoints, OwnerEndpointView{card.EndpointID, card.Name, card.Workspace, card.Harness, card.Presence})
	}
	if v.NextCursor != "" && c.canReadOwnerEndpoints() {
		v.NextReviewID = c.ownerEndpointReviewID(v.NextCursor, 64)
	}
}

func expireOwnerEndpointView(view *Snapshot, now time.Time) {
	if view.Account.RootState == RootStateActive && now.Before(parseExpiry(view.Account.SessionExpiresAt)) &&
		(view.Account.State == AccountStateOwnerReady || view.Account.State == AccountStateSessionActive) {
		if view.OwnerEndpoints.ParkAfter != "" && now.Before(parseExpiry(view.OwnerEndpoints.ParkAfter)) {
			view.OwnerEndpoints.ParkReviewID = ""
			filtered := view.AvailableActions[:0]
			for _, action := range view.AvailableActions {
				if action != ActionParkOwnerEndpoints {
					filtered = append(filtered, action)
				}
			}
			view.AvailableActions = filtered
		}
		return
	}
	view.OwnerEndpoints = OwnerEndpointSnapshot{Pending: view.OwnerEndpoints.Pending, ErrorCode: view.OwnerEndpoints.ErrorCode}
	filtered := view.AvailableActions[:0]
	for _, action := range view.AvailableActions {
		if action != ActionReadOwnerEndpoints && action != ActionParkOwnerEndpoints {
			filtered = append(filtered, action)
		}
	}
	view.AvailableActions = filtered
}
