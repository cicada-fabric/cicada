package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
)

func (m *mcpServer) dispatchSealedMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation) (any, error) {
	var input mcpOutboxInput
	if err := json.Unmarshal([]byte(operation.InputJSON), &input); err != nil {
		failed, persistErr := outbox.markError(scope, operation.OperationID, mcpOutboxStatusFailed,
			errors.New("sealed SEND operation has invalid immutable input"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	if input.LinkID == "" || input.DataScope == "" || input.Body == "" || len([]byte(input.Body)) > 64*1024 {
		failed, persistErr := outbox.markError(scope, operation.OperationID, mcpOutboxStatusFailed,
			errors.New("sealed SEND requires a Link ID, granted data scope, and non-empty body under 64 KiB"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	request, err := m.currentLocalSealedSendRequest(operation, input)
	if err != nil {
		status := mcpOutboxStatusFailed
		if sealedSendErrorRetryable(err) {
			status = mcpOutboxStatusUnknown
		}
		failed, persistErr := outbox.markError(scope, operation.OperationID, status,
			errors.New(m.safeMCPError(err)))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	result, err := requestMachineAgentSealedSend(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		status := mcpOutboxStatusFailed
		if sealedSendErrorRetryable(err) {
			status = mcpOutboxStatusUnknown
		}
		failed, persistErr := outbox.markError(scope, operation.OperationID, status,
			errors.New(m.safeMCPError(err)))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	resultJSON, err := mcpOutboxResultJSON(result, request.SessionToken)
	if err != nil {
		unknown, persistErr := outbox.markError(scope, operation.OperationID, mcpOutboxStatusUnknown, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	sent, err := outbox.markResult(scope, operation.OperationID, mcpOutboxStatusSent, "", resultJSON)
	if err != nil {
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "local outbox result persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(sent), nil
}

func (m *mcpServer) currentLocalSealedSendRequest(operation mcpOutboxOperation,
	input mcpOutboxInput) (localSealedSendRequest, error) {
	current, err := detectCodexMCPJoinSession()
	if err != nil {
		return localSealedSendRequest{}, err
	}
	trusted, err := normalizeMCPTrustedContext(current)
	if err != nil {
		return localSealedSendRequest{}, err
	}
	return m.currentMCPDeliveryRequest(operation, input, trusted)
}

// currentMCPDeliveryRequest verifies the current session-authenticated Hub
// identity, binding, and endpoint capability against the immutable outbox
// context. It does not prove local native-record possession; sealed local
// delivery still requires currentLocalSealedSendRequest and the Node bridge.
func (m *mcpServer) currentMCPDeliveryRequest(operation mcpOutboxOperation,
	input mcpOutboxInput, trusted mcpTrustedContext) (localSealedSendRequest, error) {
	m.sessionMu.RLock()
	token := strings.TrimSpace(m.sessionToken)
	endpointID := strings.TrimSpace(m.endpointID)
	groupID := strings.TrimSpace(m.sessionGroupID)
	boundContext := m.sessionContext
	boundContextSet := m.sessionContextSet
	storedScope := strings.TrimSpace(m.sessionScope)
	cached := m.sessionPublic
	m.sessionMu.RUnlock()
	if token == "" || !boundContextSet || boundContext != trusted {
		return localSealedSendRequest{}, errors.New("cicada_send requires the explicitly joined current native session")
	}
	if endpointID == "" || groupID == "" || cached.Endpoint.ID != endpointID || cached.Endpoint.GroupID != groupID ||
		cached.Endpoint.Owner == "" || cached.BindingID == "" || cached.BindingEpoch == 0 {
		return localSealedSendRequest{}, errors.New("current Cicada session has no complete trusted Endpoint and binding")
	}
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil {
		return localSealedSendRequest{}, err
	}
	currentScope, _, err := mcpSessionScope(origin, harness.SessionContext{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		MachineID: trusted.NodeID, Workspace: trusted.Workspace,
	})
	if err != nil {
		return localSealedSendRequest{}, err
	}
	if storedScope == "" || storedScope != currentScope ||
		!mcpOutboxScopeMatches(operation, mcpOutboxScope{
			APIOrigin: origin, Scope: currentScope, Harness: trusted.Harness,
			NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace,
			EndpointID: endpointID, GroupID: groupID,
		}) {
		return localSealedSendRequest{}, errMCPOutboxContext
	}
	result, err := m.apiForGroup(http.MethodGet, "/v2/fabric/whoami", nil, groupID)
	if err != nil {
		return localSealedSendRequest{}, err
	}
	card, err := networkCardFromResult(result)
	if err != nil {
		return localSealedSendRequest{}, errors.New("current Cicada session returned an invalid whoami response")
	}
	if card.EndpointID != endpointID || card.GroupID != groupID || card.NodeID != trusted.NodeID ||
		harness.Canonical(card.Harness) != trusted.Harness || card.PrincipalID == "" ||
		card.BindingID != cached.BindingID || card.BindingEpoch != cached.BindingEpoch ||
		card.NativeSessionID != trusted.NativeSessionID ||
		(filepathCleanIfSet(trusted.Workspace) != filepathCleanIfSet(card.Workspace)) ||
		(cached.NetworkCard.PrincipalID != "" && cached.NetworkCard.PrincipalID != card.PrincipalID) {
		return localSealedSendRequest{}, errors.New("current Cicada session does not match the joined native binding")
	}
	localPeerDelivery, localPeerDeliveryPresent := localPeerDeliveryCapability(card.Capabilities)
	for _, cachedCapabilities := range []map[string]any{cached.Endpoint.Capabilities, cached.NetworkCard.Capabilities} {
		cachedValue, cachedPresent := localPeerDeliveryCapability(cachedCapabilities)
		if !cachedPresent {
			continue
		}
		if cachedValue != "sealed_v1" || !localPeerDeliveryPresent || localPeerDelivery != cachedValue {
			return localSealedSendRequest{}, errors.New("current peer-delivery capability conflicts with joined session state; no plaintext fallback")
		}
	}
	return localSealedSendRequest{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		NodeID: trusted.NodeID, Workspace: trusted.Workspace, SessionToken: token,
		EndpointID: endpointID, PrincipalID: card.PrincipalID, OwnerID: cached.Endpoint.Owner,
		GroupID: groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
		LocalPeerDelivery:        localPeerDelivery,
		LocalPeerDeliveryPresent: localPeerDeliveryPresent,
		LinkID:                   input.LinkID, DataScope: input.DataScope, MessageID: operation.OperationID,
		IdempotencyKey: operation.IdempotencyKey, Body: input.Body,
	}, nil
}

func filepathCleanIfSet(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return filepath.Clean(value)
}

func sealedSendErrorRetryable(err error) bool {
	if localSealedSendRetryable(err) {
		return true
	}
	var httpErr *mcpHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.statusCode == http.StatusRequestTimeout || httpErr.statusCode == http.StatusTooManyRequests || httpErr.statusCode >= 500
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr)
}
