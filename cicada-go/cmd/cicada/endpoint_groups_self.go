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
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Only the trusted MCP process builds this private request, after actual Hook
// consumption. Business arguments cannot provide its native identity or token.
type localEndpointGroupsRequest struct {
	Version         int             `json:"version"`
	Operation       string          `json:"operation"`
	APIOrigin       string          `json:"api_origin"`
	Harness         string          `json:"harness"`
	NativeSessionID string          `json:"native_session_id"`
	Workspace       string          `json:"workspace"`
	ContextTicketID string          `json:"context_ticket_id"`
	ConnectionNonce string          `json:"connection_nonce"`
	ToolName        string          `json:"tool_name"`
	ArgumentsDigest string          `json:"arguments_digest"`
	Arguments       json.RawMessage `json:"arguments"`
	Cursor          string          `json:"cursor,omitempty"`
	Limit           int             `json:"limit,omitempty"`
	GroupID         string          `json:"group_id,omitempty"`
	codexEndpointGroupsBinding
}

type localEndpointGroupsResult struct {
	LocalAccessRevision uint64                                `json:"local_access_revision"`
	Description         wire.EndpointGroupsNodeDescribeResult `json:"description"`
	SessionToken        string                                `json:"session_token"`
	Authority           wire.EndpointGroupCurrentEndpoint     `json:"authority,omitzero"`
	Card                *fabric.NetworkCard                   `json:"card,omitempty"`
}

func endpointGroupsBusinessArguments(raw json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var arguments map[string]any
	if decoder.Decode(&arguments) != nil || arguments == nil {
		return nil, errCodexMCPContext
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, errCodexMCPContext
	}
	canonical, err := json.Marshal(arguments)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errCodexMCPContext
	}
	return arguments, nil
}

func parseEndpointGroupsMCPArguments(arguments map[string]any) (string, int, error) {
	cursor, limit := "", 64
	for key, value := range arguments {
		switch key {
		case "cursor":
			var ok bool
			cursor, ok = value.(string)
			if !ok || len(cursor) > 256 || strings.TrimSpace(cursor) != cursor {
				return "", 0, errCodexMCPContext
			}
		case "limit":
			n, ok := strictMCPInteger(value)
			if !ok || n < 1 || n > 64 {
				return "", 0, errCodexMCPContext
			}
			limit = int(n)
		default:
			return "", 0, errors.New("cicada_groups accepts only cursor and limit; identity and scope are derived by the trusted Node")
		}
	}
	return cursor, limit, nil
}

func (b *machineAgentJoinBridge) endpointGroupsSelf(q localEndpointGroupsRequest) (*localEndpointGroupsResult, error) {
	if q.Version != localJoinProtocolVersion || q.Harness != "codex" || (q.Operation != "endpoint_groups_self" && q.Operation != "endpoint_groups_select") || q.APIOrigin != b.baseURL || q.codexEndpointGroupsBinding.validate() != nil {
		return nil, errCodexMCPContext
	}
	record, err := b.codexContexts.consumedEndpointGroups(q.ContextTicketID, q.APIOrigin, q.NativeSessionID, q.Workspace, time.Now())
	if err != nil || record.Nonce != q.ConnectionNonce || record.Tool != q.ToolName || record.Arguments != q.ArgumentsDigest {
		return nil, errCodexMCPContext
	}
	actual, err := codexContextBinding(record.Context)
	if err != nil || actual.codexEndpointGroupsBinding != q.codexEndpointGroupsBinding {
		return nil, errCodexMCPContext
	}
	arguments, err := endpointGroupsBusinessArguments(q.Arguments)
	if err != nil {
		return nil, err
	}
	digest, err := codexArgumentsDigest(arguments)
	if err != nil || digest != q.ArgumentsDigest {
		return nil, errCodexMCPContext
	}
	if q.Operation == "endpoint_groups_select" {
		if q.ToolName != "cicada_use_group" || len(arguments) != 1 || stringArgument(arguments, "group_id") != q.GroupID || q.GroupID == "" || q.Cursor != "" {
			return nil, errCodexMCPContext
		}
	} else if q.GroupID != "" {
		return nil, errCodexMCPContext
	}
	if q.ToolName == "cicada_groups" {
		cursor, limit, err := parseEndpointGroupsMCPArguments(arguments)
		if err != nil || q.Cursor != cursor || q.Limit != limit {
			return nil, errCodexMCPContext
		}
	}
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || r.Anchor.RegistrationDigest != q.RegistrationDigest || r.Anchor.RegistrationRevision != q.RegistrationRevision || r.Anchor.BindingID != q.RegistrationBindingID || r.Anchor.BindingEpoch != q.RegistrationBindingEpoch || r.Anchor.NodeKeyEpoch != q.RegistrationNodeKeyEpoch {
		return nil, errEndpointGroupsRegistration
	}
	if r.LocallyOffline {
		return nil, errEndpointGroupsOffline
	}
	ctx, cancel := context.WithDeadline(b.ctx, record.Expires)
	defer cancel()
	r, d, err := b.describeEndpointGroups(ctx, c, r, q.Cursor, q.Limit)
	if err != nil {
		return nil, err
	}
	r, err = b.renewEndpointGroupsRegistration(ctx, c, r)
	if err != nil {
		return nil, err
	}
	_, original, _, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return nil, err
	}
	result := &localEndpointGroupsResult{Description: d, SessionToken: original.SessionToken, LocalAccessRevision: r.LocalAccessRevision}
	result.Description.Registration = r.Anchor
	if q.Operation != "endpoint_groups_select" {
		return result, nil
	}
	// Pagination is bounded by the actual consumed call's original deadline.
	// Incomplete pages never establish absence or erase registration credentials.
	for {
		for _, authority := range d.Authorities {
			if authority.Relation.GroupID == q.GroupID {
				result.Authority = authority
				break
			}
		}
		if result.Authority != (wire.EndpointGroupCurrentEndpoint{}) {
			break
		}
		if d.Complete {
			return nil, errors.New("OWNER_READD_REQUIRED: selected Group has no current key-ready authority")
		}
		if ctx.Err() != nil {
			return nil, errMachineNodeControlOutcomeUncertain
		}
		r, d, err = b.describeEndpointGroups(ctx, c, r, d.NextCursor, 64)
		if err != nil {
			return nil, err
		}
	}
	raw, err := b.httpWithAuthorization(http.MethodGet, "/v2/fabric/whoami", nil, "CicadaSession "+original.SessionToken, q.GroupID)
	if err != nil {
		return nil, err
	}
	var card fabric.NetworkCard
	if decodeStrictBridgeJSON(raw, &card) != nil || card.GroupID != q.GroupID || card.EndpointID != r.Anchor.Registration.EndpointID || card.PrincipalID != r.Anchor.Registration.PrincipalID || card.NodeID != b.nodeID || card.Harness != q.Harness || card.NativeSessionID != q.NativeSessionID || card.Workspace != q.Workspace || card.BindingID != r.Anchor.BindingID || card.BindingEpoch != r.Anchor.BindingEpoch {
		return nil, errEndpointGroupsRegistration
	}
	result.Card = &card
	result.Description = d
	result.Description.Registration = r.Anchor
	return result, nil
}

func requestMachineAgentEndpointGroups(ctx context.Context, socket string, q localEndpointGroupsRequest) (*localEndpointGroupsResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := netDialLocalBridge(socket)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(connection).Encode(q); err != nil {
		return nil, errLocalJoinBridgeUnavailable
	}
	if unix, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = unix.CloseWrite()
	}
	var response localJoinResponse
	decoder := json.NewDecoder(io.LimitReader(connection, 512<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || response.Version != localJoinProtocolVersion {
		return nil, errEndpointGroupsRegistration
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.EndpointGroups == nil {
		return nil, errEndpointGroupsRegistration
	}
	return response.EndpointGroups, nil
}
