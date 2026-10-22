package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/harness"
)

const codexMCPContextArgument = "_cicada_context"

var errCodexMCPContext = errors.New("CODEX_CALL_CONTEXT_REQUIRED: this Cicada call needs a fresh verified runtime context; no previous Thread identity is reused")

// One MCP connection owns one random routing nonce. Actual SID/cwd comes only
// from the Node's consumed one-use ticket. Nothing writes process SID env or
// a shared last-context file.
type codexMCPContextState struct {
	nonce       string
	nodeID      string
	callMu      sync.Mutex
	mu          sync.RWMutex
	active      *harness.SessionContext
	heartbeatMu sync.Mutex
	heartbeat   *codexFrozenHeartbeat

	activeVerification *localCodexContext
}

func configuredCodexNodeID() (string, error) {
	nodeID := strings.TrimSpace(os.Getenv("CICADA_MACHINE_ID"))
	if nodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return "", errCodexMCPContext
		}
		nodeID = strings.SplitN(hostname, ".", 2)[0]
	}
	if !localContextText(nodeID, 256) {
		return "", errCodexMCPContext
	}
	return nodeID, nil
}

func (m *mcpServer) enableCodexContext(nodeID string) error {
	if !localContextText(nodeID, 256) || strings.TrimSpace(m.sessionStatePath) == "" {
		return errCodexMCPContext
	}
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	m.codexContext = &codexMCPContextState{nonce: hex.EncodeToString(nonce[:]), nodeID: nodeID}
	m.baseURL = origin
	// A configured/cached Endpoint is not the caller of this new connection.
	m.clearSessionMemory()
	return nil
}

func codexBusinessArguments(arguments map[string]any) (map[string]any, error) {
	if len(arguments) > 256 {
		return nil, errCodexMCPContext
	}
	copy := make(map[string]any, len(arguments))
	for key, value := range arguments {
		if key != codexMCPContextArgument {
			copy[key] = value
		}
	}
	return copy, nil
}

// Go's JSON object-key ordering and the same JSON number decoder are used on
// both sides. Context/ticket is excluded; the Node separately binds nonce/tool.
func codexArgumentsDigest(arguments map[string]any) (string, error) {
	raw, err := json.Marshal(arguments)
	if err != nil || len(raw) > 2<<20 {
		return "", errCodexMCPContext
	}
	digest := sha256.Sum256(append([]byte("cicada/codex/tool-arguments/v1\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (m *mcpServer) contextualMCPTools() []map[string]any {
	tools := cicadaMCPTools()
	if m.codexContext == nil {
		return tools
	}
	for _, tool := range tools {
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			continue
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		properties[codexMCPContextArgument] = map[string]any{
			"type": "object", "description": "Runtime context. Echo the connection nonce exactly; the trusted local hook replaces the ticket. Never provide a Thread ID.",
			"properties": map[string]any{"connection_nonce": map[string]any{"type": "string", "const": m.codexContext.nonce}, "ticket": map[string]any{"type": "string", "maxLength": 256}},
			"required":   []string{"connection_nonce"}, "additionalProperties": false,
		}
		required, _ := schema["required"].([]string)
		schema["required"] = append(required, codexMCPContextArgument)
	}
	return tools
}

func (m *mcpServer) callContextualTool(name string, arguments map[string]any) (any, error) {
	state := m.codexContext
	if state == nil {
		return nil, errCodexMCPContext
	}
	state.callMu.Lock()
	defer state.callMu.Unlock()
	if err := revalidateCodexLocalNode(context.Background(), m.localNode); err != nil {
		m.stopCodexHeartbeat()
		m.clearSessionMemory()
		return nil, err
	}
	if !isCicadaMCPTool(name) {
		return nil, errCodexMCPContext
	}
	contextValue, ok := arguments[codexMCPContextArgument].(map[string]any)
	if !ok || len(contextValue) != 2 {
		return nil, errCodexMCPContext
	}
	nonce, nonceOK := contextValue["connection_nonce"].(string)
	ticket, ticketOK := contextValue["ticket"].(string)
	if !nonceOK || nonce != state.nonce || !ticketOK || ticket == "" || len(ticket) > 256 {
		return nil, errCodexMCPContext
	}
	business, err := codexBusinessArguments(arguments)
	if err != nil {
		return nil, err
	}
	if err := validateMCPArguments(name, business); err != nil {
		return nil, err
	}
	digest, err := codexArgumentsDigest(business)
	if err != nil {
		return nil, err
	}
	socketPath := m.joinSocketPath(harness.SessionContext{MachineID: state.nodeID})
	consumed, err := requestMachineAgentCodexContextConsume(socketPath, localCodexContextConsume{
		Version: localJoinProtocolVersion, Operation: "codex_context_consume", APIOrigin: m.baseURL,
		ConnectionNonce: nonce, ToolName: name, ArgumentsDigest: digest, Ticket: ticket,
	})
	if err != nil || consumed == nil {
		return nil, errCodexMCPContext
	}
	selection, domain, err := codexContextDomain(consumed.Context)
	if err != nil {
		return nil, err
	}
	if _, pair, _ := parseNativePairJoinSelection(business); pair && domain {
		return nil, errCodexMCPContext
	}
	verifiedDomain := codexDomainBinding{}
	if domain {
		verifiedDomain = codexDomainBinding{LocalDomainVersion: 1, LocalDomain: selection}
	}
	context := harness.SessionContext{Harness: consumed.Context.Harness, NativeSessionID: consumed.Context.NativeSessionID,
		MachineID: state.nodeID, Workspace: consumed.Context.Workspace, Capabilities: map[string]any{"fabric_tools": true, "wake": "codex_queue"}}
	if context.Harness != "codex" || !localContextText(context.NativeSessionID, 256) || !filepath.IsAbs(context.Workspace) || filepath.Clean(context.Workspace) != context.Workspace {
		return nil, errCodexMCPContext
	}
	trusted, err := normalizeMCPTrustedContext(context)
	if err != nil {
		return nil, errCodexMCPContext
	}
	m.sessionMu.RLock()
	same := m.sessionContextSet && m.sessionContext == trusted && m.sessionDomain == verifiedDomain
	m.sessionMu.RUnlock()
	if !same {
		m.stopCodexHeartbeat()
		m.clearSessionMemory()
	}
	state.mu.Lock()
	state.active = &context
	state.activeVerification = &consumed.Context
	state.mu.Unlock()
	defer func() { state.mu.Lock(); state.active = nil; state.activeVerification = nil; state.mu.Unlock() }()
	defer m.reconcileCodexHeartbeat()
	if !m.isJoined() {
		if err := m.restoreSession(context); err != nil {
			return nil, err
		}
	}
	return m.callToolWithContext(name, business)
}

func (m *mcpServer) detectCurrentSession() (harness.SessionContext, error) {
	if m.codexContext == nil {
		return harness.DetectCurrentSession()
	}
	m.codexContext.mu.RLock()
	defer m.codexContext.mu.RUnlock()
	if m.codexContext.active == nil {
		return harness.SessionContext{}, errCodexMCPContext
	}
	return *m.codexContext.active, nil
}

func (m *mcpServer) detectCurrentCodexSession() (harness.SessionContext, error) {
	if m.codexContext == nil {
		return detectCodexMCPJoinSession()
	}
	return m.detectCurrentSession()
}
