package main

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"

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
	return verifyCodexOperatorContextProof(event, coordinates, origin, connection, command, nil)
}

func verifyCodexOperatorContextProof(event codexHookInput, coordinates harness.SessionContext, origin string, connection *LocalNodeConnection, command codexOperatorCommand, proof *endpointGroupsOperatorContextProof) (codexDomainBinding, error) {
	return verifyCodexOperatorInvocation(event.TranscriptPath, event.TurnID, event.ToolUseID, codexOperatorRegistrationName(command, event), coordinates, origin, connection, command, proof)
}

// The caller identifies its real producer. Terminal invocations have no native
// Hook turn/tool-use IDs and pass empty values instead of manufacturing them.
func verifyCodexOperatorInvocation(transcript, turnID, toolUseID, registrationName string, coordinates harness.SessionContext, origin string, connection *LocalNodeConnection, command codexOperatorCommand, proof *endpointGroupsOperatorContextProof) (codexDomainBinding, error) {
	tool := codexOperatorContextTool(command.operation)
	if tool == "" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	name := ""
	if command.operation == "endpoint_register" {
		name = registrationName
	}
	return verifyCodexOperatorInvocationArguments(transcript, turnID, toolUseID, coordinates, origin, connection, command, map[string]any{"operation": command.operation, "name": name, "pair_label": command.label, "slot": command.slot}, proof)
}

func endpointGroupsFreshOperatorProof(transcript, turnID, toolUseID string, native harness.SessionContext, connection *LocalNodeConnection, q localEndpointRequest) (*endpointGroupsOperatorContextProof, error) {
	var proof endpointGroupsOperatorContextProof
	arguments := map[string]any{"operation": q.Operation, "name": q.Name, "pair_label": q.PairLabel, "slot": q.Slot, "original_request_id": q.RequestID, "original_intent_digest": codexOperatorDigest(q, false)}
	binding, err := verifyCodexOperatorInvocationArguments(transcript, turnID, toolUseID, native, q.APIOrigin, connection, codexOperatorCommand{operation: q.Operation}, arguments, &proof)
	if err != nil || binding.EndpointGroupsVersion != 1 || binding.codexEndpointGroupsBinding != q.codexEndpointGroupsBinding {
		return nil, errCodexMCPContext
	}
	return &proof, nil
}

func verifyCodexOperatorInvocationArguments(transcript, turnID, toolUseID string, coordinates harness.SessionContext, origin string, connection *LocalNodeConnection, command codexOperatorCommand, arguments map[string]any, proof *endpointGroupsOperatorContextProof) (codexDomainBinding, error) {
	tool := codexOperatorContextTool(command.operation)
	if tool == "" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	digest, err := codexArgumentsDigest(arguments)
	if err != nil {
		return codexDomainBinding{}, err
	}
	var marker [32]byte
	if _, err := rand.Read(marker[:]); err != nil {
		return codexDomainBinding{}, errCodexMCPContext
	}
	nonce := hex.EncodeToString(marker[:])
	socket := codexHookSocket(coordinates, connection)
	issued, err := requestMachineAgentCodexContextIssue(socket, localCodexContextIssue{Version: localJoinProtocolVersion, Operation: "codex_context_issue", APIOrigin: origin, Harness: "codex", NativeSessionID: coordinates.NativeSessionID, Workspace: coordinates.Workspace, TranscriptPath: transcript, ConnectionNonce: nonce, ToolName: tool, ArgumentsDigest: digest, TurnID: turnID, ToolUseID: toolUseID})
	if err != nil || issued == nil || issued.Ticket == "" {
		return codexDomainBinding{}, errCodexMCPContext
	}
	consumed, err := requestMachineAgentCodexContextConsume(socket, localCodexContextConsume{Version: localJoinProtocolVersion, Operation: "codex_context_consume", APIOrigin: origin, ConnectionNonce: nonce, ToolName: tool, ArgumentsDigest: digest, Ticket: issued.Ticket})
	if err != nil || consumed == nil {
		return codexDomainBinding{}, errCodexMCPContext
	}
	value := consumed.Context
	if value.Harness != "codex" || value.NativeSessionID != coordinates.NativeSessionID || value.Workspace != coordinates.Workspace || value.TurnID != turnID || value.ToolUseID != toolUseID {
		return codexDomainBinding{}, errCodexMCPContext
	}
	binding, err := codexContextBinding(value)
	if err != nil {
		return codexDomainBinding{}, err
	}
	if binding.EndpointGroupsVersion == 1 {
		if command.operation == "native_pair_available" || command.operation == "native_pair_join_named" {
			return codexDomainBinding{}, errCodexMCPContext
		}
		if proof != nil {
			proof.ContextTicketID = strings.Split(issued.Ticket, ".")[0]
			proof.ContextConnectionNonce = nonce
		}
		return binding, nil
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
