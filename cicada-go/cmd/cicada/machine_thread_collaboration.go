package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

type localThreadCollaborationRequest struct {
	localEndpointGroupsRequest
	Operator    *endpointGroupsOperatorContextProof `json:"operator,omitempty"`
	ContextOnly bool                                `json:"context_only,omitempty"`
	Scope       *wire.GroupLockScope                `json:"scope,omitempty"`
	Acquire     *wire.GroupLockAcquireRequest       `json:"acquire,omitempty"`
	Renew       *wire.GroupLockRenewRequest         `json:"renew,omitempty"`
	Release     *wire.GroupLockReleaseRequest       `json:"release,omitempty"`
}

type localThreadCollaborationResult struct {
	Operation string                                    `json:"operation"`
	Scope     *wire.ThreadScopeView                     `json:"scope,omitempty"`
	Locks     *wire.GroupSlotView                       `json:"locks,omitempty"`
	Receipt   *wire.GroupLockReceipt                    `json:"receipt,omitempty"`
	Context   *localEndpointGroupsResult                `json:"context,omitempty"`
	Evidence  *localThreadCollaborationOriginalEvidence `json:"evidence,omitempty"`
}

func threadCollaborationTool(operation string, operator bool) string {
	if operator {
		return "codex.operator." + operation
	}
	switch operation {
	case wire.OperationThreadScopeRead:
		return "cicada_thread_scope"
	case wire.OperationGroupLocksRead:
		return "cicada_group_locks"
	case wire.OperationGroupLocksAcquire:
		return "cicada_group_lock_acquire"
	case wire.OperationGroupLocksRenew:
		return "cicada_group_lock_renew"
	case wire.OperationGroupLocksRelease:
		return "cicada_group_lock_release"
	}
	return ""
}

func (q localThreadCollaborationRequest) requestedScope() *wire.GroupLockScope {
	if q.Scope != nil {
		return q.Scope
	}
	if q.Acquire != nil {
		return &q.Acquire.Scope
	}
	if q.Renew != nil {
		return &q.Renew.Scope
	}
	if q.Release != nil {
		return &q.Release.Scope
	}
	return nil
}

func (q localThreadCollaborationRequest) body(endpoint, network string) (any, error) {
	n := 0
	for _, set := range []bool{q.Scope != nil, q.Acquire != nil, q.Renew != nil, q.Release != nil} {
		if set {
			n++
		}
	}
	switch q.Operation {
	case wire.OperationThreadScopeRead:
		if n == 0 {
			return wire.ThreadScopeNodeRead{EndpointID: endpoint, NetworkID: network}, nil
		}
	case wire.OperationGroupLocksRead:
		if n == 1 && q.Scope != nil {
			return wire.GroupLocksNodeRead{EndpointID: endpoint, Scope: *q.Scope}, nil
		}
	case wire.OperationGroupLocksAcquire:
		if n == 1 && q.Acquire != nil {
			return wire.GroupLocksNodeAcquire{EndpointID: endpoint, Request: *q.Acquire}, nil
		}
	case wire.OperationGroupLocksRenew:
		if n == 1 && q.Renew != nil {
			return wire.GroupLocksNodeRenew{EndpointID: endpoint, Request: *q.Renew}, nil
		}
	case wire.OperationGroupLocksRelease:
		if n == 1 && q.Release != nil {
			return wire.GroupLocksNodeRelease{EndpointID: endpoint, Request: *q.Release}, nil
		}
	}
	return nil, errThreadCollaborationInvalid
}

// ContextOnly observes metadata without spending the business invocation. The
// transition to used is atomic and permits exactly one execution per ticket.
func (a *localCodexContextAuthority) authorizeThreadCollaboration(q localThreadCollaborationRequest, consume bool, now time.Time) (localCodexContextRecord, error) {
	args, err := endpointGroupsBusinessArguments(q.Arguments)
	if err != nil {
		return localCodexContextRecord{}, err
	}
	digest, err := codexArgumentsDigest(args)
	if err != nil || digest != q.ArgumentsDigest {
		return localCodexContextRecord{}, errCodexMCPContext
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.consumed[q.ContextTicketID]
	if !ok || !localContextHex(q.ContextTicketID, 64) || !now.Before(r.Expires) || r.Origin != q.APIOrigin || r.Context.Harness != q.Harness || r.Context.NativeSessionID != q.NativeSessionID || r.Context.Workspace != q.Workspace || r.Nonce != q.ConnectionNonce || r.Tool != q.ToolName || r.Arguments != q.ArgumentsDigest || r.Tool != threadCollaborationTool(q.Operation, q.Operator != nil) {
		return r, errCodexMCPContext
	}
	if q.Operator != nil && (q.Operator.ContextTicketID != q.ContextTicketID || q.Operator.ContextConnectionNonce != q.ConnectionNonce) {
		return r, errCodexMCPContext
	}
	binding, err := codexContextBinding(r.Context)
	if err != nil || binding.codexEndpointGroupsBinding != q.codexEndpointGroupsBinding {
		return r, errCodexMCPContext
	}
	if a.operatorIntents == nil {
		a.operatorIntents = map[string]string{}
	}
	for id := range a.operatorIntents {
		v, exists := a.consumed[id]
		if !exists || !now.Before(v.Expires) {
			delete(a.operatorIntents, id)
		}
	}
	raw, _ := json.Marshal(struct {
		Operation, Group, Digest string
		Binding                  codexEndpointGroupsBinding
	}{q.Operation, q.GroupID, q.ArgumentsDigest, q.codexEndpointGroupsBinding})
	prepared := "thread-collaboration:prepared:" + threadCollaborationPacketDigest(raw)
	if prior, exists := a.operatorIntents[q.ContextTicketID]; exists && prior != prepared {
		return r, errCodexMCPContext
	}
	if consume {
		a.operatorIntents[q.ContextTicketID] = "thread-collaboration:used:" + threadCollaborationPacketDigest(raw)
	} else if q.ContextOnly {
		a.operatorIntents[q.ContextTicketID] = prepared
	}
	return r, nil
}

func (b *machineAgentJoinBridge) threadCollaborationAvailable(ctx context.Context, hub wire.HubIdentity, locks bool) error {
	var raw machineNativePairRawJSON
	if err := machineAPIJSON(ctx, b.baseURL+wire.ThreadCollaborationCapabilitiesPath, http.MethodGet, nil, &raw); err != nil {
		return errEndpointGroupsUnsupported
	}
	caps, err := wire.DecodeThreadCollaborationCapabilities(raw, hub)
	if err != nil || !caps.ThreadScopeRoleAvailable || locks && !caps.GroupLocksAvailable {
		return errEndpointGroupsUnsupported
	}
	return nil
}

func (b *machineAgentJoinBridge) threadCollaborationContext(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, q localThreadCollaborationRequest) (machineEndpointGroupsRegistration, *localEndpointGroupsResult, error) {
	r, d, err := b.describeEndpointGroups(ctx, c, r, "", 64)
	if err != nil {
		return r, nil, err
	}
	result := &localEndpointGroupsResult{Description: d, LocalAccessRevision: r.LocalAccessRevision}
	if q.GroupID == "" {
		return r, result, nil
	}
	// A Group business context still requires the actual completed key receipt;
	// a zero-attested registration can expose only its own classification read.
	_, joined, _, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return r, nil, err
	}
	result.SessionToken = joined.SessionToken
	for {
		for _, authority := range d.Authorities {
			if authority.Relation.GroupID == q.GroupID {
				result.Authority = authority
			}
		}
		if result.Authority != (wire.EndpointGroupCurrentEndpoint{}) {
			break
		}
		if d.Complete || d.NextCursor == "" {
			return r, nil, errEndpointGroupsSelection
		}
		r, d, err = b.describeEndpointGroups(ctx, c, r, d.NextCursor, 64)
		if err != nil {
			return r, nil, err
		}
	}
	raw, err := b.httpWithAuthorization(http.MethodGet, "/v2/fabric/whoami", nil, "CicadaSession "+joined.SessionToken, q.GroupID)
	if err != nil {
		return r, nil, err
	}
	var card fabric.NetworkCard
	if decodeStrictBridgeJSON(raw, &card) != nil || card.GroupID != q.GroupID || card.EndpointID != r.Anchor.Registration.EndpointID || card.PrincipalID != r.Anchor.Registration.PrincipalID || card.NodeID != b.nodeID || card.Harness != q.Harness || card.NativeSessionID != q.NativeSessionID || card.Workspace != q.Workspace || card.BindingID != r.Anchor.BindingID || card.BindingEpoch != r.Anchor.BindingEpoch {
		return r, nil, errEndpointGroupsRegistration
	}
	result.Card = &card
	result.Description = d
	result.Description.Registration = r.Anchor
	return r, result, nil
}

func requestMachineAgentThreadCollaboration(ctx context.Context, socketPath string, q localThreadCollaborationRequest) (*localThreadCollaborationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	if err = json.NewEncoder(connection).Encode(q); err != nil {
		return nil, errLocalJoinBridgeUnavailable
	}
	if unix, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = unix.CloseWrite()
	}
	var response struct {
		Version             int                             `json:"version"`
		ThreadCollaboration *localThreadCollaborationResult `json:"thread_collaboration,omitempty"`
		Error               string                          `json:"error,omitempty"`
		Retryable           bool                            `json:"retryable,omitempty"`
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 512<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || response.Version != localJoinProtocolVersion {
		return nil, errThreadCollaborationInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, errThreadCollaborationInvalid
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.ThreadCollaboration == nil || response.ThreadCollaboration.Operation != q.Operation {
		return nil, errThreadCollaborationInvalid
	}
	return response.ThreadCollaboration, nil
}

func prepareThreadCollaborationOutboxScope(ctx context.Context, socketPath string, q localThreadCollaborationRequest) (localThreadCollaborationRequest, mcpOutboxScope, error) {
	probe := q
	probe.ContextOnly = true
	probe.Scope, probe.Acquire, probe.Renew, probe.Release = nil, nil, nil, nil
	result, err := requestMachineAgentThreadCollaboration(ctx, socketPath, probe)
	if err != nil {
		return q, mcpOutboxScope{}, err
	}
	if result.Context == nil || result.Context.Card == nil || result.Context.SessionToken == "" || result.Context.LocalAccessRevision == 0 {
		return q, mcpOutboxScope{}, errThreadCollaborationInvalid
	}
	a := result.Context.Description.Registration
	card := result.Context.Card
	authority := result.Context.Authority
	if a.Registration.NativeSessionID != q.NativeSessionID || a.Registration.Workspace != q.Workspace || a.Registration.Harness != q.Harness || a.RegistrationDigest != q.RegistrationDigest || a.RegistrationRevision != q.RegistrationRevision || a.BindingID != q.RegistrationBindingID || a.BindingEpoch != q.RegistrationBindingEpoch || a.NodeKeyEpoch != q.RegistrationNodeKeyEpoch || card.EndpointID != a.Registration.EndpointID || card.GroupID != q.GroupID || authority.Relation.GroupID != q.GroupID || authority.Relation.EndpointID != card.EndpointID {
		return q, mcpOutboxScope{}, errThreadCollaborationInvalid
	}
	scope, _, err := mcpSessionScope(q.APIOrigin, harness.SessionContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, MachineID: a.Registration.NodeID, Workspace: q.Workspace})
	if err != nil {
		return q, mcpOutboxScope{}, err
	}
	binding := codexOutboxBinding{codexDomainBinding: codexDomainBinding{codexEndpointGroupsBinding: q.codexEndpointGroupsBinding}, NativeBindingID: a.BindingID, NativeBindingEpoch: a.BindingEpoch, EndpointGroupAuthority: authority}
	if binding.validate() != nil {
		return q, mcpOutboxScope{}, errThreadCollaborationInvalid
	}
	return q, mcpOutboxScope{APIOrigin: q.APIOrigin, Scope: scope, Harness: q.Harness, NativeSessionID: q.NativeSessionID, NodeID: a.Registration.NodeID, Workspace: q.Workspace, EndpointID: card.EndpointID, GroupID: card.GroupID, codexOutboxBinding: binding}, nil
}

func (q localThreadCollaborationRequest) withOriginal(original wire.ThreadCollaborationOriginal) localThreadCollaborationRequest {
	if q.Acquire != nil {
		v := *q.Acquire
		v.Original = original
		q.Acquire = &v
	}
	if q.Renew != nil {
		v := *q.Renew
		v.Original = original
		q.Renew = &v
	}
	if q.Release != nil {
		v := *q.Release
		v.Original = original
		q.Release = &v
	}
	return q
}

func threadCollaborationArgumentsMatch(q localThreadCollaborationRequest) error {
	arguments, err := endpointGroupsBusinessArguments(q.Arguments)
	if err != nil {
		return err
	}
	if !threadCollaborationMutation(q.Operation) {
		return nil
	}
	var slot uint8
	var version, generation uint64
	var ttl *uint32
	var note string
	switch {
	case q.Acquire != nil:
		slot, version, ttl, note = q.Acquire.Slot, q.Acquire.ExpectedVersion, q.Acquire.TTLSeconds, q.Acquire.Note
	case q.Renew != nil:
		slot, version, generation, ttl = q.Renew.Slot, q.Renew.ExpectedVersion, q.Renew.Generation, q.Renew.TTLSeconds
	case q.Release != nil:
		slot, version, generation = q.Release.Slot, q.Release.ExpectedVersion, q.Release.Generation
	default:
		return errThreadCollaborationInvalid
	}
	for name, want := range map[string]uint64{"slot": uint64(slot), "expected_version": version} {
		actual, ok := strictMCPInteger(arguments[name])
		if !ok || actual < 0 || uint64(actual) != want {
			return errCodexMCPContext
		}
	}
	if generation != 0 {
		actual, ok := strictMCPInteger(arguments["generation"])
		if !ok || actual < 0 || uint64(actual) != generation {
			return errCodexMCPContext
		}
	}
	if actual, present := arguments["ttl_seconds"]; present {
		n, ok := strictMCPInteger(actual)
		if !ok || ttl == nil || n < 0 || uint64(n) != uint64(*ttl) {
			return errCodexMCPContext
		}
	} else if ttl != nil {
		return errCodexMCPContext
	}
	if actual, present := arguments["note"]; present {
		v, ok := actual.(string)
		if !ok || v != note {
			return errCodexMCPContext
		}
	} else if note != "" {
		return errCodexMCPContext
	}
	return nil
}

func checkThreadCollaborationNativeHistory(ctx context.Context, q localThreadCollaborationRequest, anchor wire.EndpointGroupsRegistrationAnchor) error {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.NativeContexts == nil || hub.WriterScope == "" || hub.HubID != anchor.Registration.HubID || hub.NodeID != anchor.Registration.NodeID {
		return errThreadCollaborationInvalid
	}
	v, err := hub.NativeContexts.InspectThreadNetwork(ctx, hub.WriterScope, q.Harness, q.NativeSessionID)
	if err != nil {
		return err
	}
	if v.State != nodeinbox.ThreadNetworkCurrent || v.HubID != anchor.Registration.HubID || v.NetworkID != anchor.NetworkID {
		return errors.New(wire.ThreadCollaborationErrorNetworkConflict)
	}
	return nil
}

func (c *machineNodeControlClient) retainThreadCollaborationOriginal(q localThreadCollaborationRequest, r machineEndpointGroupsRegistration, caller wire.GroupLockHolder) (localThreadCollaborationRequest, string, error) {
	body, err := q.body(r.Anchor.Registration.EndpointID, r.Anchor.NetworkID)
	if err != nil {
		return q, "", err
	}
	original, _, request, err := threadCollaborationBodyOriginal(body)
	if err != nil {
		return q, "", err
	}
	if original.RequestDigest != strings.Repeat("0", 64) {
		return q, "", errThreadCollaborationInvalid
	}
	digest, err := wire.GroupLockRequestDigest(q.Operation, caller, request)
	if err != nil {
		return q, "", err
	}
	original.RequestDigest = digest
	q = q.withOriginal(original)
	body, err = q.body(r.Anchor.Registration.EndpointID, r.Anchor.NetworkID)
	if err != nil {
		return q, "", err
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return q, "", err
	}
	now := time.Now().UTC()
	record := machineThreadCollaborationOriginal{Operation: q.Operation, EndpointID: caller.EndpointID, Original: original, Scope: *q.requestedScope(), Caller: caller, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, RegistrationDigest: r.Anchor.RegistrationDigest, RegistrationRevision: r.Anchor.RegistrationRevision, Body: plain, State: localThreadCollaborationUnknown, CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano)}
	key := threadCollaborationOriginalKey(record)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, old := range c.state.ThreadCollaborationOriginals {
		if old.Scope == record.Scope && old.Caller == record.Caller && (old.Original.OperationID == original.OperationID || old.Original.IdempotencyKey == original.IdempotencyKey) {
			if old.Operation != record.Operation || old.Original != record.Original || !bytes.Equal(old.Body, plain) || old.Harness != q.Harness || old.NativeSessionID != q.NativeSessionID || old.Workspace != q.Workspace {
				return q, "", errThreadCollaborationInvalid
			}
			return q, threadCollaborationOriginalKey(old), nil
		}
	}
	if wire.ValidateGroupLockOriginalWindow(original, now) != nil {
		return q, "", errThreadCollaborationUnknown
	}
	previous := cloneMachineNodeControlState(c.state)
	if len(c.state.PendingPacket) > 0 || !c.makeThreadCollaborationOriginalRoomLocked(now) {
		c.state = previous
		return q, "", errThreadCollaborationUnknown
	}
	if c.state.ThreadCollaborationOriginals == nil {
		c.state.ThreadCollaborationOriginals = map[string]machineThreadCollaborationOriginal{}
	}
	c.state.ThreadCollaborationOriginals[key] = record
	// Reserve room for the bounded mutation PQC request and response before
	// any POST. Only already proven terminal entries may release that space.
	for {
		encoded, e := json.Marshal(c.state)
		if e != nil {
			c.state = previous
			return q, "", e
		}
		if len(encoded)+(512<<10) < maxMachineNodeControlStateBytes {
			break
		}
		if !c.evictThreadCollaborationTerminalLocked() {
			c.state = previous
			return q, "", errLocalEndpointHistoryFull
		}
	}
	if err = c.persistLocked(); err != nil {
		c.state = previous
		return q, "", err
	}
	return q, key, nil
}

// This is the sole private socket producer. Source identity comes only from a
// fresh consumed Host record plus original Node registration/possession proof.
func (b *machineAgentJoinBridge) threadCollaboration(q localThreadCollaborationRequest) (*localThreadCollaborationResult, error) {
	if q.Version != localJoinProtocolVersion || q.APIOrigin != b.baseURL || q.Harness != "codex" || !threadCollaborationNodeOperation(q.Operation) || q.codexEndpointGroupsBinding.validate() != nil || q.Cursor != "" || q.Limit != 0 || q.Operation != wire.OperationThreadScopeRead && !localContextText(q.GroupID, 256) {
		return nil, errThreadCollaborationInvalid
	}
	verified, err := b.codexContexts.authorizeThreadCollaboration(q, false, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(b.ctx, verified.Expires)
	defer cancel()
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || r.LocallyOffline || r.Anchor.RegistrationDigest != q.RegistrationDigest || r.Anchor.RegistrationRevision != q.RegistrationRevision || r.Anchor.BindingID != q.RegistrationBindingID || r.Anchor.BindingEpoch != q.RegistrationBindingEpoch || r.Anchor.NodeKeyEpoch != q.RegistrationNodeKeyEpoch {
		return nil, errEndpointGroupsRegistration
	}
	hub, err := b.endpointGroupsOriginalHub(ctx, c, r)
	if err != nil {
		return nil, err
	}
	if err = b.validateEndpointGroupsRegistration(ctx, c, r, r.Anchor, hub); err != nil {
		return nil, err
	}
	if err = checkThreadCollaborationNativeHistory(ctx, q, r.Anchor); err != nil {
		return nil, err
	}
	if err = b.threadCollaborationAvailable(ctx, hub, q.Operation != wire.OperationThreadScopeRead); err != nil {
		return nil, err
	}
	if requested := q.requestedScope(); requested != nil && (requested.HubID != hub.HubID || requested.NetworkID != r.Anchor.NetworkID || requested.GroupID != q.GroupID) {
		return nil, errThreadCollaborationInvalid
	}
	result := &localThreadCollaborationResult{Operation: q.Operation}
	// Recovery may only dispatch its already-persisted exact final Node body.
	var retainedKey string
	if threadCollaborationMutation(q.Operation) && !q.ContextOnly {
		if err = threadCollaborationArgumentsMatch(q); err != nil {
			return nil, err
		}
		body, e := q.body(r.Anchor.Registration.EndpointID, r.Anchor.NetworkID)
		if e != nil {
			return nil, e
		}
		original, _, _, e := threadCollaborationBodyOriginal(body)
		if e != nil {
			return nil, e
		}
		c.mu.Lock()
		for key, record := range c.state.ThreadCollaborationOriginals {
			if record.Harness == q.Harness && record.NativeSessionID == q.NativeSessionID && record.Workspace == q.Workspace && record.Scope == *q.requestedScope() && (record.Original.OperationID == original.OperationID || record.Original.IdempotencyKey == original.IdempotencyKey) {
				if original.RequestDigest != strings.Repeat("0", 64) && original.RequestDigest != record.Original.RequestDigest {
					c.mu.Unlock()
					return nil, errThreadCollaborationInvalid
				}
				candidate := q.withOriginal(record.Original)
				typed, ce := candidate.body(r.Anchor.Registration.EndpointID, r.Anchor.NetworkID)
				raw, _ := json.Marshal(typed)
				if ce != nil || record.Operation != q.Operation || record.Original.OperationID != original.OperationID || record.Original.IdempotencyKey != original.IdempotencyKey || !bytes.Equal(raw, record.Body) || record.RegistrationDigest != r.Anchor.RegistrationDigest || record.RegistrationRevision != r.Anchor.RegistrationRevision {
					c.mu.Unlock()
					return nil, errThreadCollaborationInvalid
				}
				q, retainedKey = candidate, key
				break
			}
		}
		c.mu.Unlock()
	}
	if retainedKey == "" {
		// A lost metadata read belongs to this same registered native source.
		// Recover it through the dedicated verifier before issuing another read;
		// no ContextOnly path is allowed to dispatch a pending mutation.
		c.mu.Lock()
		pendingOperation := c.state.PendingOperation
		c.mu.Unlock()
		if pendingOperation == wire.OperationThreadScopeRead {
			if err = c.callThreadCollaboration(ctx, b.nodeToken, pendingOperation, wire.ThreadScopeNodeRead{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID}, nil); err != nil {
				return nil, err
			}
		} else if pendingOperation == wire.OperationGroupLocksRead {
			if q.Operation != wire.OperationGroupLocksRead || q.Scope == nil {
				return nil, errThreadCollaborationUnknown
			}
			if err = c.callThreadCollaboration(ctx, b.nodeToken, pendingOperation, wire.GroupLocksNodeRead{EndpointID: r.Anchor.Registration.EndpointID, Scope: *q.Scope}, nil); err != nil {
				return nil, err
			}
		} else if threadCollaborationNodeOperation(pendingOperation) {
			return nil, errThreadCollaborationUnknown
		}
		var metadata *localEndpointGroupsResult
		metadataRequest := q
		if q.Operation == wire.OperationThreadScopeRead {
			metadataRequest.GroupID = ""
		}
		r, metadata, err = b.threadCollaborationContext(ctx, c, r, metadataRequest)
		if err != nil {
			return nil, err
		}
		var scope wire.ThreadScopeView
		if err = c.callThreadCollaboration(ctx, b.nodeToken, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID}, &scope); err != nil {
			return nil, err
		}
		if err = threadCollaborationScopeMatches(scope, r.Anchor); err != nil {
			return nil, err
		}
		if q.ContextOnly {
			result.Context, result.Scope = metadata, &scope
			return result, nil
		}
		if threadCollaborationMutation(q.Operation) {
			caller, e := threadCollaborationCaller(scope, r.Anchor)
			if e != nil {
				return nil, e
			}
			q, retainedKey, err = c.retainThreadCollaborationOriginal(q, r, caller)
			if err != nil {
				return nil, err
			}
		}
		if q.Operation == wire.OperationThreadScopeRead {
			result.Scope = &scope
		}
	}
	if _, err = b.codexContexts.authorizeThreadCollaboration(q, true, time.Now().UTC()); err != nil {
		return nil, err
	}
	if result.Scope != nil {
		return result, nil
	}
	body, err := q.body(r.Anchor.Registration.EndpointID, r.Anchor.NetworkID)
	if err != nil {
		return nil, err
	}
	if q.Operation == wire.OperationGroupLocksRead {
		var view wire.GroupSlotView
		if err = c.callThreadCollaboration(ctx, b.nodeToken, q.Operation, body, &view); err != nil {
			return nil, err
		}
		result.Locks = &view
		return result, nil
	}
	var receipt wire.GroupLockReceipt
	err = c.callThreadCollaboration(ctx, b.nodeToken, q.Operation, body, &receipt)
	var rejected *threadCollaborationOriginalRejection
	if err != nil && !errors.As(err, &rejected) {
		return nil, err
	}
	c.mu.Lock()
	record, ok := c.state.ThreadCollaborationOriginals[retainedKey]
	c.mu.Unlock()
	if !ok || record.State == localThreadCollaborationUnknown || len(record.ResponsePacket) == 0 {
		return nil, errThreadCollaborationUnknown
	}
	result.Evidence = &localThreadCollaborationOriginalEvidence{Operation: q.Operation, Original: record.Original, RequestPacketDigest: threadCollaborationPacketDigest(record.RequestPacket), ResponsePacketDigest: threadCollaborationPacketDigest(record.ResponsePacket), Outcome: record.State}
	if rejected != nil {
		result.Evidence.ErrorCode = rejected.code
	} else {
		result.Receipt = &receipt
	}
	return result, nil
}

// The normal issuer's Describe cannot run while this same source retains an
// unresolved RPC. This predicate permits only the exact pending operation's
// native identity to obtain a fresh Host ticket; it grants no business rights.
func threadCollaborationPendingNative(s machineNodeControlState, r machineEndpointGroupsRegistration, q localCodexContextIssue) bool {
	if !threadCollaborationNodeOperation(s.PendingOperation) || len(s.PendingPacket) == 0 || (q.ToolName != threadCollaborationTool(s.PendingOperation, false) && q.ToolName != threadCollaborationTool(s.PendingOperation, true)) || r.Anchor.Registration.NativeSessionID != q.NativeSessionID || r.Anchor.Registration.Workspace != q.Workspace || r.Anchor.Registration.Harness != q.Harness {
		return false
	}
	p, err := wire.DecodeThreadCollaborationNodePacket(s.PendingPacket)
	if err != nil || p.Route.Operation != s.PendingOperation || p.Route.OperationID != s.PendingOperationID || p.Route.Sequence != s.PendingSequence || p.Route.NodeID != r.Anchor.Registration.NodeID || p.Route.HubID != r.Anchor.Registration.HubID || p.Route.BindingID != s.BindingID || p.Route.NodeKeyEpoch != s.NodeKeyEpoch {
		return false
	}
	if threadCollaborationMutation(s.PendingOperation) {
		for _, original := range s.ThreadCollaborationOriginals {
			if bytes.Equal(original.RequestPacket, s.PendingPacket) && original.Operation == s.PendingOperation && original.Harness == q.Harness && original.NativeSessionID == q.NativeSessionID && original.Workspace == q.Workspace && original.RegistrationDigest == r.Anchor.RegistrationDigest && original.RegistrationRevision == r.Anchor.RegistrationRevision && original.Caller.NodeID == r.Anchor.Registration.NodeID && original.Caller.EndpointID == r.Anchor.Registration.EndpointID && original.Caller.PrincipalID == r.Anchor.Registration.PrincipalID && threadCollaborationPacketDigest(original.Body) == s.PendingPlaintextDigest {
				return true
			}
		}
		return false
	}
	if s.PendingOperation == wire.OperationThreadScopeRead {
		raw, _ := json.Marshal(wire.ThreadScopeNodeRead{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID})
		return threadCollaborationPacketDigest(raw) == s.PendingPlaintextDigest
	}
	for _, authority := range r.Authorities {
		relation := authority.Relation
		if relation.EndpointID != r.Anchor.Registration.EndpointID || relation.HubID != r.Anchor.Registration.HubID || relation.NetworkID != r.Anchor.NetworkID {
			continue
		}
		raw, _ := json.Marshal(wire.GroupLocksNodeRead{EndpointID: r.Anchor.Registration.EndpointID, Scope: wire.GroupLockScope{HubID: relation.HubID, NetworkID: relation.NetworkID, GroupID: relation.GroupID}})
		if threadCollaborationPacketDigest(raw) == s.PendingPlaintextDigest {
			return true
		}
	}
	return false
}

func (b *machineAgentJoinBridge) threadCollaborationVerificationProfile(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, q localCodexContextIssue) (localCodexContext, bool, error) {
	c.mu.Lock()
	selected := threadCollaborationPendingNative(c.state, r, q)
	c.mu.Unlock()
	if !selected {
		return localCodexContext{}, false, nil
	}
	if r.LocallyOffline || r.TranscriptPath != q.TranscriptPath || verifyCodexContextTranscriptProfile(r.TranscriptPath, q.NativeSessionID, q.Workspace, true) != nil {
		return localCodexContext{}, true, errEndpointGroupsRegistration
	}
	hub, err := b.endpointGroupsOriginalHub(ctx, c, r)
	if err != nil {
		return localCodexContext{}, true, err
	}
	if err = b.validateEndpointGroupsRegistration(ctx, c, r, r.Anchor, hub); err != nil {
		return localCodexContext{}, true, err
	}
	if err = checkThreadCollaborationNativeHistory(ctx, localThreadCollaborationRequest{localEndpointGroupsRequest: localEndpointGroupsRequest{Harness: q.Harness, NativeSessionID: q.NativeSessionID}}, r.Anchor); err != nil {
		return localCodexContext{}, true, err
	}
	if err = ctx.Err(); err != nil {
		return localCodexContext{}, true, err
	}
	return endpointGroupsContextForAnchor(r.Anchor, q), true, nil
}
