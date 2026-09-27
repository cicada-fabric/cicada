package main

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
)

func (m *mcpServer) receiveMCPInbox(cursor string, limit int) (any, error) {
	// The Node inbox page is intentionally bounded. Models commonly request a
	// larger page than the adapter supports; cap it before the trusted bridge
	// validates the request so ordinary reads remain usable and predictable.
	if limit > 16 {
		limit = 16
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	trustedContext, err := normalizeMCPTrustedContext(harness.SessionContext{
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID,
		MachineID: scope.NodeID, Workspace: scope.Workspace,
	})
	if err != nil {
		return nil, err
	}
	operation := mcpOutboxOperation{
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID,
	}
	trusted, err := m.currentMCPDeliveryRequest(operation, mcpOutboxInput{}, trustedContext)
	if err != nil {
		return nil, err
	}
	if !trusted.LocalPeerDeliveryPresent {
		return m.api(http.MethodPost, "/v2/fabric/receive", fabric.ReceiveInput{Cursor: cursor, Limit: limit})
	}
	if trusted.LocalPeerDelivery != "sealed_v1" {
		return nil, errors.New("unsupported peer-delivery capability; no Hub inbox fallback")
	}
	request := localGroupRequest{
		Operation: "local_receive", Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, SessionToken: trusted.SessionToken,
		EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID,
		BindingID: trusted.BindingID, BindingEpoch: trusted.BindingEpoch,
		Cursor: cursor, Limit: limit,
	}
	result, err := requestMachineAgentLocalGroup(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": result.Messages, "next_cursor": result.NextCursor}, nil
}
