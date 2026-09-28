package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
)

type localNetworkDirectRequest struct {
	Version          int    `json:"version"`
	Operation        string `json:"operation"`
	NetworkID        string `json:"network_id"`
	EndpointID       string `json:"endpoint_id"`
	SessionToken     string `json:"network_session_token"`
	Harness          string `json:"harness"`
	NativeSessionID  string `json:"native_session_id"`
	Workspace        string `json:"workspace"`
	NodeID           string `json:"node_id"`
	OperationID      string `json:"operation_id"`
	IdempotencyKey   string `json:"idempotency_key"`
	TargetEndpointID string `json:"target_endpoint_id,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	Body             string `json:"body,omitempty"`
}

type localNetworkDirectResult struct {
	NetworkID        string `json:"network_id"`
	MessageID        string `json:"message_id,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	TargetEndpointID string `json:"target_endpoint_id,omitempty"`
	State            string `json:"state"`
	PayloadMode      string `json:"payload_mode,omitempty"`
	KeyFingerprint   string `json:"key_fingerprint,omitempty"`
}

func (m *mcpServer) networkDirectToolLocked(name string, arguments map[string]any,
	context harness.SessionContext, state networkCLIState) (any, error) {
	if state.NetworkID == "" || state.SessionToken == "" || state.EndpointID == "" {
		return nil, errors.New("Network registration is incomplete")
	}
	switch name {
	case "cicada_whoami":
		return m.networkDirectHTTP(state, http.MethodGet, "/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/whoami", nil)
	case "cicada_publish_endpoint_key_candidate":
		request := localNetworkDirectRequest{Version: localJoinProtocolVersion, Operation: "network_direct_publish_key",
			NetworkID: state.NetworkID, EndpointID: state.EndpointID, SessionToken: state.SessionToken,
			Harness: context.Harness, NativeSessionID: context.NativeSessionID, Workspace: context.Workspace, NodeID: context.MachineID}
		return requestMachineAgentNetworkDirect(defaultMCPJoinSocketPath(context), request)
	case "cicada_request_status", "request_status", "cicada_request_cancel", "cicada_cancel", "request_cancel", "cancel":
		requestID := stringArgument(arguments, "request_id")
		if requestID == "" {
			return nil, errors.New("request_id is required")
		}
		method, path := http.MethodGet, "/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/direct/request-status?request_id="+url.QueryEscape(requestID)
		var payload any
		if name == "cicada_request_cancel" || name == "cicada_cancel" || name == "request_cancel" || name == "cancel" {
			method, path = http.MethodPost, "/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/direct/request-cancel"
			payload = map[string]string{"request_id": requestID, "reason": stringArgument(arguments, "reason")}
		}
		return m.networkDirectHTTP(state, method, path, payload)
	case "cicada_operation_status", "cicada_operation_retry":
		outbox, err := m.ensureMCPOutbox()
		if err != nil {
			return nil, err
		}
		scope, err := m.networkDirectOutboxScope(context, state)
		if err != nil {
			return nil, err
		}
		op, err := outbox.load(scope, stringArgument(arguments, "operation_id"))
		if err != nil {
			return nil, err
		}
		if name == "cicada_operation_status" || op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
			return mcpOutboxPublicResult(op), nil
		}
		return m.dispatchMCPNetworkOutbox(outbox, scope, op, context, state)
	case "cicada_send", "cicada_ask", "cicada_reply":
		if stringArgument(arguments, "link_id") != "" || stringArgument(arguments, "data_scope") != "" {
			return nil, errors.New("Network direct scope cannot use a Group Link")
		}
		input := mcpOutboxInput{NetworkID: state.NetworkID, Target: stringArgument(arguments, "target"),
			RequestID: stringArgument(arguments, "request_id"), ExpiresAt: stringArgument(arguments, "expires_at")}
		kind := "network_send"
		switch name {
		case "cicada_send":
			input.Body = stringArgument(arguments, "body")
		case "cicada_ask":
			kind = "network_ask"
			input.Question = stringArgument(arguments, "question")
		case "cicada_reply":
			kind = "network_reply"
			input.Body = stringArgument(arguments, "body")
		}
		if kind != "network_reply" {
			if strings.TrimSpace(input.Target) == "" || len(input.Target) > 256 {
				return nil, errors.New("Network direct target is required")
			}
			if !strings.HasPrefix(input.Target, "ep_") {
				// A nickname requires discovery; an exact Endpoint ID can be
				// used with direct.send alone. Retries keep the resolved ID.
				resolved, err := m.networkDirectHTTP(state, http.MethodPost,
					"/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/resolve",
					map[string]string{"query": input.Target})
				if err != nil {
					return nil, err
				}
				card, ok := resolved.(map[string]any)
				if !ok {
					return nil, errors.New("invalid Network resolution")
				}
				endpointID, _ := card["endpoint_id"].(string)
				if !strings.HasPrefix(endpointID, "ep_") || len(endpointID) > 256 {
					return nil, errors.New("Network target did not resolve to an Endpoint")
				}
				input.Target = endpointID
			}
			if input.Target == state.EndpointID {
				return nil, errors.New("Network target cannot be the sender")
			}
		}
		if kind == "network_reply" && input.RequestID == "" {
			return nil, errors.New("request_id is required")
		}
		if (kind == "network_ask" && input.Question == "") || (kind != "network_ask" && input.Body == "") {
			return nil, errors.New("Network direct body is required")
		}
		if len(input.Body) > 64*1024 || len(input.Question) > 64*1024 {
			return nil, errors.New("Network direct body exceeds 64 KiB")
		}
		scope, err := m.networkDirectOutboxScope(context, state)
		if err != nil {
			return nil, err
		}
		outbox, err := m.ensureMCPOutbox()
		if err != nil {
			return nil, err
		}
		op, created, err := outbox.prepare(scope, kind, stringArgument(arguments, "idempotency_key"), input)
		if err != nil {
			return nil, err
		}
		if !created {
			return mcpOutboxPublicResult(op), nil
		}
		return m.dispatchMCPNetworkOutbox(outbox, scope, op, context, state)
	default:
		return nil, errors.New("unsupported Network direct operation")
	}
}

func (m *mcpServer) networkDirectOutboxScope(context harness.SessionContext, state networkCLIState) (mcpOutboxScope, error) {
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil {
		return mcpOutboxScope{}, err
	}
	scope, _, err := mcpSessionScope(m.baseURL, context)
	if err != nil {
		return mcpOutboxScope{}, err
	}
	return mcpOutboxScope{APIOrigin: origin, Scope: scope, Harness: context.Harness, NativeSessionID: context.NativeSessionID,
		NodeID: context.MachineID, Workspace: context.Workspace, EndpointID: state.EndpointID, NetworkID: state.NetworkID}, nil
}

func (m *mcpServer) dispatchMCPNetworkOutbox(outbox *mcpOutboxStore, scope mcpOutboxScope,
	op mcpOutboxOperation, context harness.SessionContext, state networkCLIState) (any, error) {
	if scope.NetworkID != state.NetworkID || scope.EndpointID != state.EndpointID || !mcpOutboxScopeMatches(op, scope) {
		return nil, errMCPOutboxContext
	}
	op, err := outbox.markAttempt(scope, op.OperationID)
	if err != nil {
		if errors.Is(err, errMCPOutboxTerminal) {
			return mcpOutboxPublicResult(op), nil
		}
		return nil, err
	}
	var input mcpOutboxInput
	if err := json.Unmarshal([]byte(op.InputJSON), &input); err != nil || input.NetworkID != scope.NetworkID {
		failed, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed, errors.New("Network direct immutable input is corrupt"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	request := localNetworkDirectRequest{Version: localJoinProtocolVersion, NetworkID: state.NetworkID, EndpointID: state.EndpointID,
		SessionToken: state.SessionToken, Harness: context.Harness, NativeSessionID: context.NativeSessionID, Workspace: context.Workspace,
		NodeID: context.MachineID, OperationID: op.OperationID, IdempotencyKey: op.IdempotencyKey,
		TargetEndpointID: input.Target, RequestID: input.RequestID, ExpiresAt: input.ExpiresAt, Body: input.Body}
	if op.Kind == "network_ask" && request.ExpiresAt == "" {
		created, err := time.Parse(time.RFC3339Nano, op.CreatedAt)
		if err != nil {
			return nil, errors.New("Network ASK outbox timestamp is invalid")
		}
		request.ExpiresAt = created.UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
	}
	switch op.Kind {
	case "network_send":
		request.Operation = "network_direct_send"
	case "network_ask":
		request.Operation = "network_direct_ask"
		request.Body = input.Question
	case "network_reply":
		request.Operation = "network_direct_reply"
	default:
		return nil, errors.New("unsupported Network direct outbox operation")
	}
	result, err := requestMachineAgentNetworkDirect(defaultMCPJoinSocketPath(context), request)
	if err != nil {
		unknown, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusUnknown, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	encoded, err := mcpOutboxResultJSON(result, state.SessionToken)
	if err != nil {
		return nil, err
	}
	sent, err := outbox.markResult(scope, op.OperationID, mcpOutboxStatusSent, "", encoded)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(sent), nil
}

func (m *mcpServer) networkDirectHTTP(state networkCLIState, method, path string, payload any) (any, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, m.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Cicada-Network-Session "+state.SessionToken)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := networkHTTPClient().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("Network direct API %s", response.Status)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, errors.New("invalid Network direct response")
	}
	return value, nil
}

func requestMachineAgentNetworkDirect(socketPath string, request localNetworkDirectRequest) (*localNetworkDirectResult, error) {
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("could not submit Network direct operation to local Node")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		_ = unixConnection.CloseWrite()
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, errors.New("invalid local Network direct response")
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	if response.NetworkDirect == nil || response.NetworkDirect.NetworkID != request.NetworkID {
		return nil, errors.New("incomplete local Network direct response")
	}
	return response.NetworkDirect, nil
}
