package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

type mcpServer struct {
	baseURL       string
	endpointID    string
	joinMu        sync.Mutex
	heartbeatOnce sync.Once
	stop          chan struct{}
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func runMCP(args []string) error {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	apiURL := flags.String("api-url", envOr("CICADA_API_URL", "http://127.0.0.1:8787"), "Cicada Control URL")
	endpointID := flags.String("endpoint", strings.TrimSpace(os.Getenv("CICADA_ENDPOINT_ID")), "existing Endpoint ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	server := &mcpServer{baseURL: strings.TrimRight(*apiURL, "/"), endpointID: *endpointID, stop: make(chan struct{})}
	defer close(server.stop)
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var request mcpRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode MCP request: %w", err)
		}
		response, send := server.handle(request)
		if !send {
			continue
		}
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode MCP response: %w", err)
		}
	}
}

func (m *mcpServer) handle(request mcpRequest) (mcpResponse, bool) {
	id := decodeMCPID(request.ID)
	switch request.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(request.Params, &params)
		protocol := params.ProtocolVersion
		if protocol == "" {
			protocol = "2025-06-18"
		}
		return mcpResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"protocolVersion": protocol,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "cicada-fabric", "version": "0.4.0"},
			"instructions":    "Join the current session to Cicada Fabric, resolve endpoints on demand, and use ask for request/reply work.",
		}}, true
	case "notifications/initialized", "notifications/cancelled":
		return mcpResponse{}, false
	case "ping":
		return mcpResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{}}, true
	case "tools/list":
		return mcpResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": cicadaMCPTools()}}, true
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return mcpFailure(id, -32602, "invalid tool arguments: "+err.Error()), true
		}
		result, err := m.callTool(params.Name, params.Arguments)
		if err != nil {
			return mcpResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true,
			}}, true
		}
		encoded, _ := json.MarshalIndent(result, "", "  ")
		return mcpResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(encoded)}},
			"structuredContent": result,
		}}, true
	default:
		if len(request.ID) == 0 {
			return mcpResponse{}, false
		}
		return mcpFailure(id, -32601, "method not found"), true
	}
}

func decodeMCPID(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var id any
	if json.Unmarshal(raw, &id) != nil {
		return nil
	}
	return id
}

func mcpFailure(id any, code int, message string) mcpResponse {
	return mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: message}}
}

func cicadaMCPTools() []map[string]any {
	object := func(properties map[string]any, required ...string) map[string]any {
		schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			schema["required"] = required
		}
		return schema
	}
	stringField := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	return []map[string]any{
		{"name": "cicada_whoami", "description": "Join or inspect the current native session's Cicada Endpoint and Network Card.", "inputSchema": object(map[string]any{"endpoint_id": stringField("Optional existing Endpoint ID")})},
		{"name": "cicada_list", "description": "List the currently visible Fabric machines and endpoints.", "inputSchema": object(map[string]any{"status": stringField("Optional endpoint status"), "machine_id": stringField("Optional Machine ID")})},
		{"name": "cicada_resolve", "description": "Resolve an Endpoint ID, full address, server-qualified alias, or unique global alias.", "inputSchema": object(map[string]any{"query": stringField("Endpoint address or alias")}, "query")},
		{"name": "cicada_inspect", "description": "Read a bounded Network Card for one Endpoint. This never returns its prompt or transcript.", "inputSchema": object(map[string]any{"query": stringField("Endpoint address or alias")}, "query")},
		{"name": "cicada_send", "description": "Send an asynchronous one-way message to another Endpoint.", "inputSchema": object(map[string]any{"target": stringField("Endpoint address or alias"), "message": stringField("Message body")}, "target", "message")},
		{"name": "cicada_ask", "description": "Send an asynchronous request with a durable request_id for a later reply.", "inputSchema": object(map[string]any{"target": stringField("Endpoint address or alias"), "question": stringField("Question or task")}, "target", "question")},
		{"name": "cicada_reply", "description": "Reply to a Cicada ask request and wake the original Endpoint.", "inputSchema": object(map[string]any{"request_id": stringField("Request ID from cicada_ask"), "message": stringField("Answer")}, "request_id", "message")},
		{"name": "cicada_receive", "description": "Claim queued Fabric messages addressed to the current Endpoint.", "inputSchema": object(map[string]any{})},
	}
}

func (m *mcpServer) callTool(name string, arguments map[string]any) (any, error) {
	if name == "cicada_whoami" {
		if id := stringArgument(arguments, "endpoint_id"); id != "" {
			if m.endpointID != "" && m.endpointID != id {
				return nil, errors.New("this MCP process is already bound to a different Endpoint")
			}
			m.endpointID = id
		}
	}
	if err := m.ensureEndpoint(); err != nil {
		return nil, err
	}
	switch name {
	case "cicada_whoami":
		return m.api(http.MethodGet, "/v1/fabric/whoami?endpoint_id="+url.QueryEscape(m.endpointID), nil)
	case "cicada_list":
		path := "/v1/fabric/list?endpoint_id=" + url.QueryEscape(m.endpointID)
		if status := stringArgument(arguments, "status"); status != "" {
			path += "&status=" + url.QueryEscape(status)
		}
		if machine := stringArgument(arguments, "machine_id"); machine != "" {
			path += "&machine_id=" + url.QueryEscape(machine)
		}
		return m.api(http.MethodGet, path, nil)
	case "cicada_resolve", "cicada_inspect":
		query := stringArgument(arguments, "query")
		if query == "" {
			return nil, errors.New("query is required")
		}
		return m.api(http.MethodPost, "/v1/fabric/"+strings.TrimPrefix(name, "cicada_"), control.EndpointResolveInput{Query: query, RequesterEndpointID: m.endpointID})
	case "cicada_send":
		return m.api(http.MethodPost, "/v1/fabric/send", control.FabricSendInput{
			FromEndpointID: m.endpointID, Target: stringArgument(arguments, "target"), Message: stringArgument(arguments, "message"),
		})
	case "cicada_ask":
		return m.api(http.MethodPost, "/v1/fabric/ask", control.FabricAskInput{
			FromEndpointID: m.endpointID, Target: stringArgument(arguments, "target"), Question: stringArgument(arguments, "question"),
		})
	case "cicada_reply":
		return m.api(http.MethodPost, "/v1/fabric/reply", control.FabricReplyInput{
			FromEndpointID: m.endpointID, RequestID: stringArgument(arguments, "request_id"), Message: stringArgument(arguments, "message"),
		})
	case "cicada_receive":
		return m.api(http.MethodPost, "/v1/endpoints/"+url.PathEscape(m.endpointID)+"/messages", nil)
	default:
		return nil, fmt.Errorf("unknown Cicada tool: %s", name)
	}
}

func (m *mcpServer) ensureEndpoint() error {
	m.joinMu.Lock()
	defer m.joinMu.Unlock()
	if strings.TrimSpace(m.endpointID) != "" {
		m.startHeartbeat()
		return nil
	}
	context, err := harness.DetectCurrentSession()
	if err != nil {
		return err
	}
	result, err := m.api(http.MethodPost, "/v1/endpoints", control.EndpointJoinInput{
		Harness: context.Harness, NativeSessionID: context.NativeSessionID,
		MachineID: context.MachineID, Workspace: context.Workspace,
		Capabilities: context.Capabilities,
	})
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(result)
	var endpoint store.Endpoint
	if err := json.Unmarshal(encoded, &endpoint); err != nil || endpoint.ID == "" {
		return errors.New("Cicada Control returned an invalid Endpoint")
	}
	m.endpointID = endpoint.ID
	m.startHeartbeat()
	return nil
}

func (m *mcpServer) startHeartbeat() {
	endpointID := m.endpointID
	m.heartbeatOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					_, _ = m.api(http.MethodPost, "/v1/endpoints/"+url.PathEscape(endpointID)+"/heartbeat", map[string]string{"status": "online"})
				case <-m.stop:
					return
				}
			}
		}()
	})
}

func (m *mcpServer) api(method, path string, body any) (any, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, m.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token := clientAPIToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return nil, fmt.Errorf("Cicada Control request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("Cicada Control %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode Cicada Control response: %w", err)
	}
	return value, nil
}

func stringArgument(arguments map[string]any, name string) string {
	value, _ := arguments[name].(string)
	return strings.TrimSpace(value)
}
