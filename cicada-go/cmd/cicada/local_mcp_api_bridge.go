package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fabric "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
)

const localMCPMetadataMaxBody = 32 * 1024

// localMCPMetadataRequest carries only fixed MCP metadata and scoped leave operations
// through the owner-local Node socket. The Node rechecks the native record,
// current session Guard, Hub origin, and binding before using its checked HTTP
// transport. There is deliberately no caller-supplied path or header map.
type localMCPMetadataRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace"`
	APIOrigin       string `json:"api_origin"`
	SessionToken    string `json:"session_token"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
	GroupID         string `json:"group_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
	Query           string `json:"query,omitempty"`
	NodeFilter      string `json:"node_filter,omitempty"`
	WorkspaceFilter string `json:"workspace_filter,omitempty"`
	StatusFilter    string `json:"status_filter,omitempty"`
	HarnessFilter   string `json:"harness_filter,omitempty"`
	Limit           int    `json:"limit,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type localMCPMetadataResult struct {
	StatusCode int             `json:"status_code"`
	Body       json.RawMessage `json:"body,omitempty"`
}

func requestMachineAgentMCPMetadata(socketPath string, request localMCPMetadataRequest) (*localMCPMetadataResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = localJoinProtocolVersion
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("could not send protected MCP metadata request to the trusted Node")
	}
	if unixConnection, ok := connection.(interface{ CloseWrite() error }); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, errors.New("could not finish protected MCP metadata request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, errors.New("trusted Node returned an invalid protected MCP metadata response")
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.MCPMetadata == nil || response.MCPMetadata.StatusCode < 100 || response.MCPMetadata.StatusCode > 599 ||
		len(response.MCPMetadata.Body) == 0 || len(response.MCPMetadata.Body) > localMCPMetadataMaxBody ||
		!json.Valid(response.MCPMetadata.Body) {
		return nil, errors.New("trusted Node returned incomplete protected MCP metadata")
	}
	return response.MCPMetadata, nil
}

func (m *mcpServer) requestPQMetadata(method, path string, encodedBody []byte, authorization, groupID string) (any, error) {
	m.sessionMu.RLock()
	token, endpointID := strings.TrimSpace(m.sessionToken), strings.TrimSpace(m.endpointID)
	trusted, trustedSet, public := m.sessionContext, m.sessionContextSet, m.sessionPublic
	m.sessionMu.RUnlock()
	if !trustedSet || token == "" || authorization != "CicadaSession "+token ||
		strings.TrimSpace(groupID) == "" || strings.TrimSpace(public.BindingID) == "" || public.BindingEpoch == 0 {
		return nil, errors.New("protected MCP request has no complete current joined native context")
	}
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil {
		return nil, err
	}
	request := localMCPMetadataRequest{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, APIOrigin: origin, SessionToken: token,
		EndpointID: endpointID, PrincipalID: public.NetworkCard.PrincipalID,
		GroupID: strings.TrimSpace(groupID), BindingID: public.BindingID, BindingEpoch: public.BindingEpoch,
	}
	switch {
	case method == http.MethodGet && path == "/v2/fabric/whoami" && len(encodedBody) == 0:
		request.Operation = "mcp_metadata_whoami"
	case method == http.MethodPost && (path == "/v2/fabric/find" || path == "/v2/fabric/resolve" || path == "/v2/fabric/inspect"):
		var input fabric.ResolveInput
		if err := decodeStrictJSON(encodedBody, &input); err != nil {
			return nil, errors.New("protected MCP Directory query is invalid")
		}
		request.Query, request.NodeFilter, request.WorkspaceFilter = input.Query, input.NodeID, input.Workspace
		switch path {
		case "/v2/fabric/find":
			request.Operation = "mcp_metadata_find"
		case "/v2/fabric/resolve":
			request.Operation = "mcp_metadata_resolve"
		case "/v2/fabric/inspect":
			request.Operation = "mcp_metadata_inspect"
		}
	case method == http.MethodGet && (path == "/v2/fabric/members" || strings.HasPrefix(path, "/v2/fabric/members?")) && len(encodedBody) == 0:
		if err := request.membersQuery(path); err != nil {
			return nil, err
		}
		request.Operation = "mcp_metadata_members"
	case method == http.MethodPost && path == "/v2/fabric/leave-group":
		var input struct {
			Reason string `json:"reason"`
		}
		if err := decodeStrictJSON(encodedBody, &input); err != nil {
			return nil, errors.New("protected MCP leave-group input is invalid")
		}
		request.Operation, request.Reason = "mcp_metadata_leave_group", input.Reason
		if _, _, _, err := request.route(); err != nil {
			return nil, err
		}
	case method == http.MethodPost && path == "/v2/fabric/heartbeat" && len(encodedBody) == 0:
		request.Operation = "mcp_metadata_heartbeat"
	default:
		return nil, errors.New("protected MCP route is not available through the checked Node metadata bridge")
	}
	result, err := requestMachineAgentMCPMetadata(m.joinSocketPath(harness.SessionContext{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		MachineID: trusted.NodeID, Workspace: trusted.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if result.StatusCode >= 400 {
		return nil, &mcpHTTPError{statusCode: result.StatusCode,
			status:  fmt.Sprintf("%d %s", result.StatusCode, http.StatusText(result.StatusCode)),
			message: m.safeHTTPErrorMessage(result.Body)}
	}
	var decoded any
	if err := json.Unmarshal(result.Body, &decoded); err != nil {
		return nil, errors.New("trusted Node returned invalid protected MCP metadata")
	}
	return decoded, nil
}

func (b *machineAgentJoinBridge) mcpMetadata(request localMCPMetadataRequest) (*localMCPMetadataResult, error) {
	if request.Version != localJoinProtocolVersion || request.OperationName() == "invalid" {
		return nil, errors.New("invalid protected MCP metadata operation")
	}
	if strings.TrimSpace(request.SessionToken) == "" || strings.TrimSpace(request.NativeSessionID) == "" ||
		strings.TrimSpace(request.Workspace) == "" || strings.TrimSpace(request.GroupID) == "" ||
		strings.TrimSpace(request.EndpointID) == "" || strings.TrimSpace(request.BindingID) == "" ||
		request.BindingEpoch == 0 || request.NodeID != b.nodeID || harness.Canonical(request.Harness) != "codex" {
		return nil, errors.New("protected MCP metadata context is incomplete")
	}
	wantOrigin, err := normalizeMCPAPIOrigin(request.APIOrigin)
	if err != nil {
		return nil, errors.New("protected MCP metadata Hub origin is invalid")
	}
	gotOrigin, err := normalizeMCPAPIOrigin(b.baseURL)
	if err != nil || wantOrigin != gotOrigin {
		return nil, errors.New("protected MCP metadata Hub origin does not match the selected Node")
	}
	hub, ok := machineHubFrom(b.ctx)
	if !ok || hub.NodeTransport == nil || hub.NodeID != b.nodeID || !machineHubOriginMatches(b.ctx, b.baseURL) {
		return nil, errors.New("protected MCP metadata requires the selected Node's checked PQ transport")
	}
	method, path, body, err := request.route()
	if err != nil {
		return nil, err
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	perform := func(method, path string, payload []byte) (*localMCPMetadataResult, error) {
		endpoint := strings.TrimRight(b.baseURL, "/") + path
		var reader io.Reader
		if len(payload) > 0 {
			reader = bytes.NewReader(payload)
		}
		httpRequest, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, errors.New("could not prepare protected MCP metadata request")
		}
		httpRequest.Header.Set("Authorization", "CicadaSession "+request.SessionToken)
		httpRequest.Header.Set("Cicada-Group-Scope", request.GroupID)
		if len(payload) > 0 {
			httpRequest.Header.Set("Content-Type", "application/json")
		}
		client, err := machineNodeHTTPClient(ctx, 30*time.Second)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(httpRequest)
		if err != nil {
			return nil, &localSealedSendError{message: "could not reach the selected Hub through the checked Node transport", retryable: true}
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, localMCPMetadataMaxBody+1))
		if err != nil || len(data) > localMCPMetadataMaxBody {
			return nil, errors.New("Hub returned an invalid or oversized MCP metadata response")
		}
		if len(bytes.TrimSpace(data)) == 0 {
			data = []byte(`{}`)
		}
		if !json.Valid(data) {
			return nil, errors.New("Hub returned an invalid MCP metadata response")
		}
		if response.StatusCode >= 400 {
			message := safePQMetadataHTTPError(data, request.SessionToken)
			data, _ = json.Marshal(map[string]string{"error": message})
		}
		return &localMCPMetadataResult{StatusCode: response.StatusCode, Body: json.RawMessage(data)}, nil
	}
	var card fabric.NetworkCard
	if request.Operation == "mcp_metadata_whoami" {
		result, err := perform(method, path, body)
		if err != nil || result.StatusCode != http.StatusOK {
			return result, err
		}
		if err := decodeStrictJSON(result.Body, &card); err != nil || card.PrincipalID == "" {
			return nil, errors.New("Hub returned an invalid current session binding")
		}
	} else {
		preflight, err := perform(http.MethodGet, "/v2/fabric/whoami", nil)
		if err != nil || preflight.StatusCode != http.StatusOK {
			return preflight, err
		}
		if err := decodeStrictJSON(preflight.Body, &card); err != nil || card.PrincipalID == "" {
			return nil, errors.New("Hub returned an invalid current session binding")
		}
	}
	if card.EndpointID != request.EndpointID || card.PrincipalID == "" ||
		(request.PrincipalID != "" && card.PrincipalID != request.PrincipalID) ||
		(request.Operation != "mcp_metadata_whoami" && request.PrincipalID == "") ||
		card.GroupID != request.GroupID || card.NodeID != b.nodeID || card.BindingID != request.BindingID ||
		card.BindingEpoch != request.BindingEpoch || card.NativeSessionID != request.NativeSessionID ||
		harness.Canonical(card.Harness) != "codex" || filepath.Clean(card.Workspace) != filepath.Clean(request.Workspace) {
		return nil, errors.New("protected MCP metadata does not match the current native binding")
	}
	if request.Operation == "mcp_metadata_whoami" {
		return &localMCPMetadataResult{StatusCode: http.StatusOK, Body: marshalMCPMetadata(card)}, nil
	}
	result, err := perform(method, path, body)
	if err != nil || result.StatusCode < 200 || result.StatusCode >= 300 {
		return result, err
	}
	switch request.Operation {
	case "mcp_metadata_find", "mcp_metadata_resolve", "mcp_metadata_inspect":
		var resolved fabric.NetworkCard
		if err := decodeStrictJSON(result.Body, &resolved); err != nil || resolved.EndpointID == "" || resolved.GroupID != request.GroupID {
			return nil, errors.New("Hub returned an invalid Directory card")
		}
		result.Body = marshalMCPMetadata(resolved)
	case "mcp_metadata_members":
		result.Body, err = checkedMCPMembersResult(request, result.Body)
		if err != nil {
			return nil, err
		}
	case "mcp_metadata_leave_group":
		result.Body, err = checkedMCPLeaveGroupResult(request, result.Body)
		if err != nil {
			return nil, err
		}
	case "mcp_metadata_heartbeat":
		var actor fabric.Actor
		if err := decodeStrictJSON(result.Body, &actor); err != nil {
			return nil, errors.New("Hub returned an invalid heartbeat result")
		}
		result.Body = marshalMCPMetadata(struct {
			EndpointID   string `json:"endpoint_id,omitempty"`
			GroupID      string `json:"group_id,omitempty"`
			BindingID    string `json:"binding_id,omitempty"`
			BindingEpoch uint64 `json:"binding_epoch,omitempty"`
		}{actor.EndpointID, actor.GroupID, actor.BindingID, actor.BindingEpoch})
	}
	return result, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func safePQMetadataHTTPError(data []byte, token string) string {
	var envelope map[string]any
	if json.Unmarshal(data, &envelope) != nil {
		return ""
	}
	message, _ := envelope["error"].(string)
	message = strings.TrimSpace(message)
	if len(message) > 1024 {
		message = message[:1024]
	}
	if strings.Contains(message, "cicada_session_") || strings.Contains(message, "cicada_node_") {
		return ""
	}
	if token != "" {
		message = strings.ReplaceAll(message, token, "<redacted>")
		message = strings.ReplaceAll(message, fabric.HashSessionCredential(token), "<redacted>")
	}
	return message
}

func marshalMCPMetadata(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return json.RawMessage(data)
}

func (request localMCPMetadataRequest) OperationName() string {
	switch request.Operation {
	case "mcp_metadata_whoami":
		return "whoami"
	case "mcp_metadata_find":
		return "find"
	case "mcp_metadata_resolve":
		return "resolve"
	case "mcp_metadata_inspect":
		return "inspect"
	case "mcp_metadata_members":
		return "members"
	case "mcp_metadata_leave_group":
		return "leave-group"
	case "mcp_metadata_heartbeat":
		return "heartbeat"
	default:
		return "invalid"
	}
}

func (request localMCPMetadataRequest) route() (string, string, []byte, error) {
	if request.Operation != "mcp_metadata_leave_group" && request.Reason != "" {
		return "", "", nil, errors.New("unexpected leave-group reason")
	}
	if request.Operation != "mcp_metadata_members" && (request.StatusFilter != "" || request.HarnessFilter != "" || request.Limit != 0) {
		return "", "", nil, errors.New("unexpected members filters")
	}
	switch request.Operation {
	case "mcp_metadata_whoami":
		if request.Query != "" || request.NodeFilter != "" || request.WorkspaceFilter != "" {
			return "", "", nil, errors.New("whoami metadata request contains unexpected filters")
		}
		return http.MethodGet, "/v2/fabric/whoami", nil, nil
	case "mcp_metadata_find":
		return request.withDirectoryRoute("/v2/fabric/find")
	case "mcp_metadata_resolve":
		return request.withDirectoryRoute("/v2/fabric/resolve")
	case "mcp_metadata_inspect":
		return request.withDirectoryRoute("/v2/fabric/inspect")
	case "mcp_metadata_leave_group":
		if request.Query != "" || request.NodeFilter != "" || request.WorkspaceFilter != "" || len([]byte(request.Reason)) > 1024 {
			return "", "", nil, errors.New("leave-group input is invalid or oversized")
		}
		body, err := json.Marshal(struct {
			Reason string `json:"reason"`
		}{request.Reason})
		return http.MethodPost, "/v2/fabric/leave-group", body, err
	case "mcp_metadata_members":
		if request.Query != "" || request.WorkspaceFilter != "" || len([]byte(request.StatusFilter)) > 256 || len([]byte(request.NodeFilter)) > 256 || len([]byte(request.HarnessFilter)) > 256 || request.Limit < 1 || request.Limit > 200 {
			return "", "", nil, errors.New("members filters are invalid or oversized")
		}
		query := url.Values{}
		if request.StatusFilter != "" {
			query.Set("status", request.StatusFilter)
		}
		if request.NodeFilter != "" {
			query.Set("node_id", request.NodeFilter)
		}
		if request.HarnessFilter != "" {
			query.Set("harness", request.HarnessFilter)
		}
		query.Set("limit", strconv.Itoa(request.Limit))
		return http.MethodGet, "/v2/fabric/members?" + query.Encode(), nil, nil
	case "mcp_metadata_heartbeat":
		if request.Query != "" || request.NodeFilter != "" || request.WorkspaceFilter != "" {
			return "", "", nil, errors.New("heartbeat metadata request contains unexpected filters")
		}
		return http.MethodPost, "/v2/fabric/heartbeat", nil, nil
	default:
		return "", "", nil, fmt.Errorf("unsupported protected MCP metadata operation")
	}
}

func (request localMCPMetadataRequest) withDirectoryRoute(path string) (string, string, []byte, error) {
	if strings.TrimSpace(request.Query) == "" || len([]byte(request.Query)) > 4096 ||
		len([]byte(request.NodeFilter)) > 256 || len([]byte(request.WorkspaceFilter)) > 4096 {
		return "", "", nil, errors.New("Directory query is empty or oversized")
	}
	body, err := json.Marshal(fabric.ResolveInput{Query: request.Query, NodeID: request.NodeFilter, Workspace: request.WorkspaceFilter})
	if err != nil {
		return "", "", nil, errors.New("could not encode bounded Directory query")
	}
	return http.MethodPost, path, body, nil
}

// membersQuery accepts only the existing public members filters, never a caller path/header.
func (request *localMCPMetadataRequest) membersQuery(path string) error {
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed.Path != "/v2/fabric/members" || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return errors.New("invalid members route")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return errors.New("invalid members filters")
	}
	for key, values := range query {
		if len(values) != 1 || (key != "status" && key != "node_id" && key != "harness" && key != "limit") {
			return errors.New("unsupported members filter")
		}
	}
	request.StatusFilter, request.NodeFilter, request.HarnessFilter = query.Get("status"), query.Get("node_id"), query.Get("harness")
	request.Limit = 200
	if values, ok := query["limit"]; ok {
		request.Limit, err = strconv.Atoi(values[0])
		if err != nil {
			return errors.New("invalid members limit")
		}
	}
	request.Operation = "mcp_metadata_members"
	_, _, _, err = request.route()
	return err
}

func checkedMCPMembersResult(request localMCPMetadataRequest, body json.RawMessage) (json.RawMessage, error) {
	var members struct {
		Endpoints []fabric.NetworkCard `json:"endpoints"`
	}
	if len(body) > localMCPMetadataMaxBody || request.Limit < 1 || request.Limit > 200 || decodeStrictJSON(body, &members) != nil || members.Endpoints == nil || len(members.Endpoints) > request.Limit {
		return nil, errors.New("Hub returned an invalid members result")
	}
	seen := make(map[string]bool)
	for _, member := range members.Endpoints {
		if member.EndpointID == "" || len(member.EndpointID) > 256 || member.GroupID != request.GroupID || member.NativeSessionID != "" || seen[member.EndpointID] {
			return nil, errors.New("Hub returned an invalid scoped member")
		}
		seen[member.EndpointID] = true
	}
	return marshalMCPMetadata(members), nil
}
func checkedMCPLeaveGroupResult(request localMCPMetadataRequest, body json.RawMessage) (json.RawMessage, error) {
	var left struct {
		Status           string `json:"status"`
		LeftGroupID      string `json:"left_group_id"`
		RemainingGroupID string `json:"remaining_group_id"`
	}
	if len(body) > localMCPMetadataMaxBody || decodeStrictJSON(body, &left) != nil || left.Status != "left_group" || left.LeftGroupID != request.GroupID || len(left.RemainingGroupID) > 256 || left.RemainingGroupID == request.GroupID {
		return nil, errors.New("Hub returned an invalid leave-group result")
	}
	return marshalMCPMetadata(left), nil
}
