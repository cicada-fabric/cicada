package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func (b *machineAgentJoinBridge) joinNetwork(request localNetworkJoinRequest) (*fabricpkg.NetworkJoinResult, error) {
	joined, _, err := b.joinNetworkWithScope(request)
	return joined, err
}

func (b *machineAgentJoinBridge) joinNetworkWithScope(request localNetworkJoinRequest) (*fabricpkg.NetworkJoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	if request.Version != localJoinProtocolVersion || request.Operation != "network_join" ||
		strings.TrimSpace(request.NetworkID) == "" || strings.TrimSpace(request.InvitationToken) == "" ||
		strings.TrimSpace(request.OwnerJoinProof) == "" {
		return nil, nil, errors.New("incomplete Network Join request")
	}
	if strings.TrimSpace(request.Harness) != "codex" || harness.Canonical(request.Harness) != "codex" {
		return nil, nil, errors.New("Network Join requires a verified Codex session")
	}
	if strings.TrimSpace(request.NativeSessionID) == "" || len(request.NativeSessionID) > 512 ||
		len(request.Workspace) > 4096 || !filepath.IsAbs(request.Workspace) {
		return nil, nil, errors.New("invalid native Codex session context")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, nil, err
	}
	endpointName := strings.TrimSpace(request.EndpointName)
	if endpointName == "" {
		endpointName = filepath.Base(request.Workspace)
	}
	if endpointName == "." || endpointName == string(filepath.Separator) {
		endpointName = "codex"
	}
	input := fabricpkg.NetworkJoinInput{
		NetworkID:       strings.TrimSpace(request.NetworkID),
		InvitationToken: strings.TrimSpace(request.InvitationToken),
		OwnerJoinProof:  strings.TrimSpace(request.OwnerJoinProof),
		Harness:         "codex", NativeSessionID: strings.TrimSpace(request.NativeSessionID),
		EndpointName: endpointName,
		Capabilities: map[string]any{"fabric_tools": true, "wake": "codex_queue", "local_peer_delivery": "sealed_v1"},
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	client, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nil, nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.baseURL+"/v2/fabric/node/networks/join", bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, nil, errors.New("could not reach the Hub for Network Join")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("Hub rejected Network Join with HTTP %d", response.StatusCode)
	}
	var joined fabricpkg.NetworkJoinResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&joined); err != nil ||
		strings.TrimSpace(joined.SessionToken) == "" || strings.TrimSpace(joined.Endpoint.ID) == "" ||
		joined.NetworkID != request.NetworkID {
		return nil, nil, errors.New("Hub returned an invalid Network Join result")
	}
	return b.completeNetworkNativeJoin(&joined, request.Harness, request.NativeSessionID)
}

func (b *machineAgentJoinBridge) completeNetworkNativeJoin(joined *fabricpkg.NetworkJoinResult, runtime, nativeID string) (*fabricpkg.NetworkJoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	var err error
	decision := &nodeinbox.NativeContextScopeDecision{Accepted: true, ContextPolicy: joined.NativeContextScope.NetworkContextPolicy,
		NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}
	if hub, managed := machineHubFrom(b.ctx); managed {
		var scope nodeinbox.NativeContextScopeInput
		scope, err = machineNativeContextScopeFromMetadata(b.ctx, runtime, nativeID,
			joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch, joined.NativeContextScope)
		if err == nil {
			if hub.NativeContexts == nil {
				decision, err = checkMachineNativeContext(b.ctx, scope)
			} else {
				// Access renewal rotates a directory credential, not native
				// context. Retain the first actually observed enrollment epoch;
				// current access/native authority is independently guarded below.
				decision, err = hub.NativeContexts.CheckAndRecordNetworkEnrollmentContext(b.ctx, scope)
			}
		}
		if err != nil {
			return nil, nil, b.blockCommittedLocalJoin("NETWORK", joined.NativeContextScope.HubID, "",
				joined.NetworkID, joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch,
				joined.LeaseExpiresAt, err)
		}
	}
	if decision == nil || !decision.Accepted {
		return nil, nil, b.blockCommittedLocalJoin("NETWORK", joined.NativeContextScope.HubID, "",
			joined.NetworkID, joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch,
			joined.LeaseExpiresAt, errors.New("native context scope was not accepted"))
	}
	if joined.Endpoint.PrincipalID == "" || joined.Endpoint.MachineID != b.nodeID ||
		joined.Endpoint.NativeSessionID != nativeID || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return nil, nil, errors.New("Hub returned a Network Join identity inconsistent with this original Thread")
	}
	if _, _, err := b.ensureNetworkNativeBinding(joined.NetworkID, joined.Endpoint.ID, nativeID,
		joined.SessionToken, joined.Endpoint.PrincipalID); err != nil {
		// Native scope is already accepted: retain this current access credential
		// privately so retry can renew it without repeating Owner consent or Join.
		return joined, decision, errors.New("NETWORK_NATIVE_BINDING_PENDING: Network access accepted; native identity registration failed; retry Network Join or renewal")
	}
	b.markLocalJoinRecoveryResolved("NETWORK", joined.NativeContextScope.HubID, "", joined.NetworkID,
		joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch, joined.LeaseExpiresAt, decision.NativeHistoryCoverage)
	return joined, decision, nil
}

func (b *machineAgentJoinBridge) renewNetwork(request localNetworkRenewRequest) (*fabricpkg.NetworkJoinResult, error) {
	if request.Version != localJoinProtocolVersion || request.Operation != "network_renew" ||
		request.NetworkID == "" || request.EndpointID == "" ||
		strings.TrimSpace(request.Harness) != "codex" || harness.Canonical(request.Harness) != "codex" ||
		request.NativeSessionID == "" || len(request.NativeSessionID) > 512 ||
		len(request.Workspace) > 4096 || !filepath.IsAbs(request.Workspace) {
		return nil, errors.New("invalid local Network Renew request")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, err
	}
	input := fabricpkg.NetworkRenewInput{NetworkID: request.NetworkID, EndpointID: request.EndpointID,
		Harness: "codex", NativeSessionID: request.NativeSessionID}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	client, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.baseURL+"/v2/fabric/node/networks/renew", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, errors.New("could not reach the Hub for Network Renew")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Hub rejected Network Renew with HTTP %d", response.StatusCode)
	}
	var renewed fabricpkg.NetworkJoinResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&renewed); err != nil ||
		renewed.SessionToken == "" || renewed.NetworkID != request.NetworkID ||
		renewed.Endpoint.ID != request.EndpointID {
		return nil, errors.New("Hub returned an invalid Network Renew result")
	}
	joined, _, err := b.completeNetworkNativeJoin(&renewed, request.Harness, request.NativeSessionID)
	return joined, err
}

func requestMachineAgentNetworkRenew(socketPath string, request localNetworkRenewRequest) (*fabricpkg.NetworkJoinResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version, request.Operation = localJoinProtocolVersion, "network_renew"
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("could not send Network Renew request to the local Node")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, errors.New("could not finish local Network Renew request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, errors.New("local Node returned an invalid Network Renew response")
	}
	if response.JoinRecovery != nil && response.JoinRecovery.Status == localJoinBlockedStatus {
		return nil, &localJoinCommittedScopeBlockedError{Status: *response.JoinRecovery}
	}
	if response.Error != "" && response.NetworkJoin == nil {
		return nil, errors.New(response.Error)
	}
	if response.NetworkJoin == nil || response.NetworkJoin.SessionToken == "" ||
		response.NetworkJoin.NetworkID != request.NetworkID || response.NetworkJoin.Endpoint.ID != request.EndpointID {
		return nil, errors.New("local Node returned an incomplete Network Renew result")
	}
	if response.Error != "" {
		return response.NetworkJoin, errors.New(response.Error)
	}
	return response.NetworkJoin, nil
}

func requestMachineAgentNetworkJoin(socketPath string, request localNetworkJoinRequest) (*fabricpkg.NetworkJoinResult, error) {
	joined, _, err := requestMachineAgentNetworkJoinWithScope(socketPath, request)
	return joined, err
}

func requestMachineAgentNetworkJoinWithScope(socketPath string, request localNetworkJoinRequest) (*fabricpkg.NetworkJoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	joined, scope, _, err := requestMachineAgentNetworkJoinWithScopeAndRecovery(socketPath, request)
	return joined, scope, err
}

func requestMachineAgentNetworkJoinWithScopeAndRecovery(socketPath string, request localNetworkJoinRequest) (*fabricpkg.NetworkJoinResult, *nodeinbox.NativeContextScopeDecision, *localJoinRecoveryStatus, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, nil, nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = localJoinProtocolVersion
	request.Operation = "network_join"
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, nil, nil, errors.New("could not send Network Join request to the local Node")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, nil, nil, errors.New("could not finish local Network Join request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, nil, nil, errors.New("local Node returned an invalid Network Join response")
	}
	if response.JoinRecovery != nil && response.JoinRecovery.Status == localJoinBlockedStatus {
		return nil, nil, nil, &localJoinCommittedScopeBlockedError{Status: *response.JoinRecovery}
	}
	if response.Error != "" && response.NetworkJoin == nil {
		return nil, nil, nil, errors.New(response.Error)
	}
	if response.NetworkJoin == nil || response.NetworkJoin.SessionToken == "" || response.NetworkJoin.NetworkID != request.NetworkID {
		return nil, nil, nil, errors.New("local Node returned an incomplete Network Join result")
	}
	if response.Error != "" {
		if response.NativeContextScope == nil || !response.NativeContextScope.Accepted {
			return nil, nil, nil, errors.New("local Node omitted accepted native scope for partial Network Join")
		}
		return response.NetworkJoin, response.NativeContextScope, response.JoinRecovery, errors.New(response.Error)
	}
	return response.NetworkJoin, response.NativeContextScope, response.JoinRecovery, nil
}
