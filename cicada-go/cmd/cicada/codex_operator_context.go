package main

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/harness"
)

func codexOperatorContextTool(operation string) string {
	switch operation {
	case "endpoint_register", "endpoint_leave", "endpoint_directory", "native_pair_available", "native_pair_join_named":
		return "codex.operator." + operation
	}
	return ""
}

func codexOperatorRegistrationName(command codexOperatorCommand, event codexHookInput) string {
	if command.name != "" {
		return command.name
	}
	return filepath.Base(event.CWD) + " · Thread"
}

// Literal commands use the same private Node issue/consume boundary as MCP.
// Missing native event IDs stay missing; only these five operator purposes may
// carry the producer's reviewed double-empty form. A random nonce is a call
// marker and never a replacement Thread, turn or tool-use identity.
func verifyCodexOperatorContext(event codexHookInput, coordinates harness.SessionContext, origin string, connection *LocalNodeConnection, command codexOperatorCommand) (codexDomainBinding, error) {
	tool := codexOperatorContextTool(command.operation)
	if tool == "" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	name := ""
	if command.operation == "endpoint_register" {
		name = codexOperatorRegistrationName(command, event)
	}
	digest, err := codexArgumentsDigest(map[string]any{"operation": command.operation, "name": name, "pair_label": command.label, "slot": command.slot})
	if err != nil {
		return codexDomainBinding{}, err
	}
	var marker [32]byte
	if _, err := rand.Read(marker[:]); err != nil {
		return codexDomainBinding{}, errCodexMCPContext
	}
	nonce := hex.EncodeToString(marker[:])
	socket := codexHookSocket(coordinates, connection)
	issued, err := requestMachineAgentCodexContextIssue(socket, localCodexContextIssue{Version: localJoinProtocolVersion, Operation: "codex_context_issue", APIOrigin: origin, Harness: "codex", NativeSessionID: coordinates.NativeSessionID, Workspace: coordinates.Workspace, TranscriptPath: event.TranscriptPath, ConnectionNonce: nonce, ToolName: tool, ArgumentsDigest: digest, TurnID: event.TurnID, ToolUseID: event.ToolUseID})
	if err != nil || issued == nil || issued.Ticket == "" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	consumed, err := requestMachineAgentCodexContextConsume(socket, localCodexContextConsume{Version: localJoinProtocolVersion, Operation: "codex_context_consume", APIOrigin: origin, ConnectionNonce: nonce, ToolName: tool, ArgumentsDigest: digest, Ticket: issued.Ticket})
	if err != nil || consumed == nil {
		return codexDomainBinding{}, errCodexMCPContext
	}
	value := consumed.Context
	if value.Harness != "codex" || value.NativeSessionID != coordinates.NativeSessionID || value.Workspace != coordinates.Workspace || value.TurnID != event.TurnID || value.ToolUseID != event.ToolUseID {
		return codexDomainBinding{}, errCodexMCPContext
	}
	selection, domain, err := codexContextDomain(value)
	if err != nil {
		return codexDomainBinding{}, err
	}
	if !domain {
		return codexDomainBinding{}, nil
	}
	if command.operation == "native_pair_available" || command.operation == "native_pair_join_named" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	return codexDomainBinding{LocalDomainVersion: 1, LocalDomain: selection}, nil
}
