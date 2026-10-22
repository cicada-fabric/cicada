package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func requestMachineAgentNativePairJoin(socketPath string, request localNativePairJoinRequest) (*fabric.JoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	if socketPath == "" {
		return nil, nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(90 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, nil, errors.New("could not send reserved Pair Join; its Node journal must be recovered")
	}
	if unix, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = unix.CloseWrite()
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, nil, errors.New("reserved Pair Join response unavailable; recover the original Node operation")
	}
	if response.Error != "" {
		if response.JoinRecovery != nil {
			return nil, nil, &localJoinCommittedScopeBlockedError{Status: *response.JoinRecovery}
		}
		return nil, nil, errors.New(response.Error)
	}
	if response.Join == nil || response.NativeContextScope == nil || !response.NativeContextScope.Accepted {
		return nil, nil, errors.New("Node omitted its accepted reserved Pair context")
	}
	return response.Join, response.NativeContextScope, nil
}

// Only the small existing public Join result crosses MCP. Node journals retain
// all complete proofs, sealed receipts and credentials behind the local socket.
func (m *mcpServer) joinNativePair(selection nativePairJoinSelection) (any, error) {
	if err := m.requireStrictCodexContext(); err != nil {
		return nil, err
	}
	current, err := m.detectCurrentCodexSession()
	if err != nil {
		return nil, err
	}
	trusted, err := normalizeMCPTrustedContext(current)
	if err != nil {
		return nil, err
	}
	request, err := nativePairLocalJoinRequest(selection, current)
	if err != nil {
		return nil, err
	}
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil {
		return nil, err
	}
	request.APIOrigin = origin
	joined, decision, err := requestMachineAgentNativePairJoin(m.joinSocketPath(current), request)
	if err != nil {
		if recovery, ok := localJoinRecoveryFromError(err); ok {
			return *recovery, nil
		}
		return nil, err
	}
	if joined.Endpoint.NativeSessionID != trusted.NativeSessionID || joined.Endpoint.MachineID != trusted.NodeID || joined.Endpoint.Harness != trusted.Harness || joined.Endpoint.Workspace != trusted.Workspace || joined.Endpoint.GroupID == "" || strings.TrimSpace(joined.SessionToken) == "" || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return nil, errors.New("reserved Pair Join changed the original native context")
	}
	scope, _, err := mcpSessionScope(origin, current)
	if err != nil {
		return nil, err
	}
	public := mcpPublicJoinResult{Endpoint: joined.Endpoint, NetworkCard: joined.NetworkCard, BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt, NativeContextScope: decision, Reused: joined.Reused}
	if state := m.sessionStateStore(); state != nil {
		if err := state.save(mcpCachedSession{ConnectionPin: m.localNodePin(), Scope: scope, APIOrigin: origin, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace, GroupID: joined.Endpoint.GroupID, EndpointID: joined.Endpoint.ID, OwnerID: joined.Endpoint.Owner, BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt, SessionToken: joined.SessionToken}); err != nil {
			return nil, fmt.Errorf("persist reserved Pair session: %w", err)
		}
	}
	m.setSession(joined.SessionToken, joined.Endpoint.ID, joined.Endpoint.GroupID, trusted, scope, public)
	m.startHeartbeat()
	return public, nil
}
