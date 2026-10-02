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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

const localSealedSendProtocolVersion = 1

// localSealedSendRequest crosses only the owner-only Unix socket. Its caller
// builds the local side from a fresh session-authenticated whoami response;
// none of these identity fields are exposed as MCP arguments. The Node bridge
// checks them against the signed Link bundle before touching private keys.
type localSealedSendRequest struct {
	Version                  int    `json:"version"`
	Operation                string `json:"operation"`
	Harness                  string `json:"harness"`
	NativeSessionID          string `json:"native_session_id"`
	NodeID                   string `json:"node_id"`
	Workspace                string `json:"workspace,omitempty"`
	SessionToken             string `json:"session_token"`
	EndpointID               string `json:"endpoint_id"`
	PrincipalID              string `json:"principal_id"`
	OwnerID                  string `json:"owner_id"`
	GroupID                  string `json:"group_id"`
	BindingID                string `json:"binding_id"`
	BindingEpoch             uint64 `json:"binding_epoch"`
	LocalPeerDelivery        string `json:"-"`
	LocalPeerDeliveryPresent bool   `json:"-"`
	LinkID                   string `json:"link_id"`
	DataScope                string `json:"data_scope"`
	MessageID                string `json:"message_id"`
	IdempotencyKey           string `json:"idempotency_key"`
	Body                     string `json:"body"`
}

type localSealedSendResult struct {
	MessageID        string `json:"message_id"`
	LinkID           string `json:"link_id"`
	TargetEndpointID string `json:"target_endpoint_id"`
	TargetGroupID    string `json:"target_group_id"`
	DataScope        string `json:"data_scope"`
	Sequence         uint64 `json:"endpoint_sequence"`
	CiphertextReused bool   `json:"ciphertext_reused"`
	OutboxState      string `json:"outbox_state"`
}

type localSealedSendError struct {
	message   string
	retryable bool
}

func (e *localSealedSendError) Error() string { return e.message }

func localSealedSendRetryable(err error) bool {
	if errors.Is(err, errLocalJoinBridgeUnavailable) {
		return true
	}
	var bridgeErr *localSealedSendError
	return errors.As(err, &bridgeErr) && bridgeErr.retryable
}

func requestMachineAgentSealedSend(socketPath string, request localSealedSendRequest) (*localSealedSendResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = localSealedSendProtocolVersion
	request.Operation = "sealed_send"
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("could not send sealed-send request to the trusted local Node agent")
	}
	if unixConnection, ok := connection.(interface{ CloseWrite() error }); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, errors.New("could not finish the local sealed-send request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, errors.New("trusted local Node agent returned an invalid sealed-send response")
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.SealedSend == nil || response.SealedSend.MessageID != request.MessageID {
		return nil, errors.New("trusted local Node agent returned an incomplete sealed-send result")
	}
	return response.SealedSend, nil
}

// netDialLocalBridge is a small seam for the socket protocol tests.
var netDialLocalBridge = func(path string) (localBridgeConn, error) {
	if err := validateMachineAgentJoinSocketForDial(path); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return nil, errLocalJoinBridgeUnavailable
		}
		return nil, errors.New("local Node socket path is not trusted")
	}
	connection, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, errLocalJoinBridgeUnavailable
		}
		return nil, errors.New("could not connect to the trusted local Node send bridge")
	}
	return connection, nil
}

type localBridgeConn interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
	Close() error
}

type localLinkContract struct {
	LinkID            string                               `json:"link_id"`
	SourceEndpointID  string                               `json:"source_endpoint_id"`
	SourcePrincipalID string                               `json:"source_principal_id"`
	SourceGroupID     string                               `json:"source_group_id"`
	SourceOwnerID     string                               `json:"source_owner_id"`
	SourceNodeID      string                               `json:"source_node_id"`
	TargetEndpointID  string                               `json:"target_endpoint_id"`
	TargetPrincipalID string                               `json:"target_principal_id"`
	TargetGroupID     string                               `json:"target_group_id"`
	TargetOwnerID     string                               `json:"target_owner_id"`
	TargetNodeID      string                               `json:"target_node_id"`
	Direction         string                               `json:"direction"`
	Actions           []string                             `json:"actions"`
	DataScopes        []string                             `json:"data_scopes"`
	TransportHubID    string                               `json:"transport_hub_id"`
	ExpiresAt         string                               `json:"expires_at"`
	ScopeSnapshot     store.CommunicationLinkScopeSnapshot `json:"scope_snapshot"`
}

func (b *machineAgentJoinBridge) sealedSend(request localSealedSendRequest) (*localSealedSendResult, error) {
	if err := validateLocalSealedSendRequest(request, b.nodeID); err != nil {
		return nil, err
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, err
	}
	card, err := b.verifyCurrentMCPBinding(request.SessionToken, request.GroupID)
	if err != nil {
		return nil, err
	}
	if card.EndpointID != request.EndpointID || card.GroupID != request.GroupID ||
		card.PrincipalID != request.PrincipalID || card.NodeID != b.nodeID ||
		card.BindingID != request.BindingID || card.BindingEpoch != request.BindingEpoch ||
		card.NativeSessionID != request.NativeSessionID ||
		harness.Canonical(card.Harness) != "codex" || filepath.Clean(card.Workspace) != filepath.Clean(request.Workspace) {
		return nil, errors.New("current Cicada session does not match its trusted native binding")
	}
	stateDir := machineNodeStateDir(b.stateDir, b.nodeID)
	identity, err := nodekeys.LoadOrCreate(stateDir, request.EndpointID)
	if err != nil {
		return nil, fmt.Errorf("load Node-local Endpoint identity: %w", err)
	}
	state, err := nodekeys.OpenCryptoState(stateDir)
	if err != nil {
		return nil, fmt.Errorf("open Node-local crypto state: %w", err)
	}
	defer state.Close()

	bundle, err := b.fetchLinkAuthorization(request.LinkID)
	if err != nil {
		return nil, err
	}
	if bundle.LinkState != "ACTIVE" && bundle.LinkState != "PROPOSED" {
		return nil, errors.New("the selected Communication Link is not available")
	}
	manifest := bundle.Manifest
	contract, err := parseLocalLinkContract(manifest.ContractCanonical)
	if err != nil || contract.LinkID != request.LinkID || contract.SourceEndpointID != manifest.Source.EndpointID ||
		contract.TargetEndpointID != manifest.Target.EndpointID || contract.TransportHubID == "" ||
		!containsLocalString(contract.Actions, "send") || !containsLocalString(contract.DataScopes, request.DataScope) {
		return nil, errors.New("selected Communication Link does not authorize this SEND scope")
	}
	localSide, peerSide, reverse, ok := localLinkSidesForEndpoint(manifest, request.EndpointID)
	if !ok || (reverse && contract.Direction != "bidirectional") ||
		!localManifestSideMatchesRequest(localSide, localSealedRPCRequest{
			EndpointID: request.EndpointID, OwnerID: request.OwnerID, PrincipalID: request.PrincipalID,
			GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
		}, b.nodeID) || localSide.KeyID != identity.Public().ID ||
		!sameLocalPublicIdentity(localSide.PublicIdentity, identity.Public()) ||
		!localCardMatchesLinkSide(card, localSide, localSealedRPCRequest{
			EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, GroupID: request.GroupID,
			BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
			NativeSessionID: request.NativeSessionID, Workspace: request.Workspace,
		}, b.nodeID) {
		return nil, errors.New("current native session does not match an authorized Link sender binding")
	}
	if peerSide.EndpointID == "" || peerSide.EndpointID == request.EndpointID ||
		peerSide.GroupID == request.GroupID || manifest.LinkID != request.LinkID {
		return nil, errors.New("selected Communication Link has an invalid single-recipient route")
	}
	local, peer, scope := localSealedPinContext(manifest, identity.Public(), b.nodeID, reverse)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(b.ctx, scope, local, peer, bundle); err != nil {
		return nil, fmt.Errorf("verify local trust and bilateral Link grants: %w", err)
	}
	route := localSealedRoute(manifest, contract, request.MessageID, "SEND", "", "", request.EndpointID, "")
	if route.MessageID == "" {
		return nil, errors.New("selected Communication Link does not authorize this SEND direction")
	}
	plaintext := []byte(request.Body)
	operationID, err := nodekeys.EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return nil, err
	}
	outbound, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(
		b.ctx, identity, scope, local, peer, bundle, request.DataScope, operationID, route, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal durable Endpoint message: %w", err)
	}
	accepted, err := b.postSealedLinkMessage(fabricpkg.NodeSealedLinkSendInput{
		LinkID: request.LinkID, MessageID: request.MessageID,
		IdempotencyKey: request.IdempotencyKey, DataScope: request.DataScope,
		Ciphertext: outbound.Envelope,
	})
	if err != nil {
		return nil, err
	}
	if accepted.MessageID != request.MessageID || accepted.PayloadMode != "SEALED_V1" {
		return nil, errors.New("Hub returned an invalid sealed-send receipt")
	}
	return &localSealedSendResult{
		MessageID: request.MessageID, LinkID: request.LinkID,
		TargetEndpointID: peer.EndpointID, TargetGroupID: peer.GroupID,
		DataScope: request.DataScope, Sequence: outbound.Sequence,
		CiphertextReused: outbound.Reused, OutboxState: accepted.OutboxState,
	}, nil
}

func validateLocalSealedSendRequest(request localSealedSendRequest, nodeID string) error {
	if request.Version != localSealedSendProtocolVersion || request.Operation != "sealed_send" ||
		harness.Canonical(request.Harness) != "codex" || strings.TrimSpace(request.NativeSessionID) == "" ||
		len(request.NativeSessionID) > 512 || filepath.Clean(strings.TrimSpace(request.Workspace)) == "." ||
		request.NodeID != nodeID || strings.TrimSpace(request.SessionToken) == "" ||
		request.EndpointID == "" || request.PrincipalID == "" || request.OwnerID == "" ||
		request.GroupID == "" || request.BindingID == "" || request.BindingEpoch == 0 ||
		request.LinkID == "" || request.DataScope == "" || request.MessageID == "" ||
		request.IdempotencyKey == "" || request.Body == "" || len([]byte(request.Body)) > 64*1024 {
		return errors.New("invalid trusted local sealed-send context")
	}
	for _, value := range []string{request.EndpointID, request.PrincipalID, request.OwnerID, request.GroupID,
		request.BindingID, request.LinkID, request.MessageID, request.DataScope, request.IdempotencyKey} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted local sealed-send context")
		}
	}
	return nil
}

func parseLocalLinkContract(data []byte) (localLinkContract, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract localLinkContract
	if err := decoder.Decode(&contract); err != nil {
		return localLinkContract{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localLinkContract{}, errors.New("Communication Link contract has trailing data")
	}
	return contract, nil
}

func containsLocalString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (b *machineAgentJoinBridge) fetchLinkAuthorization(linkID string) (nodekeys.PeerKeyAuthorizationBundle, error) {
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/links/" + url.PathEscape(linkID) + "/authorization"
	data, err := b.nodeHTTP(http.MethodGet, path, nil)
	if err != nil {
		return nodekeys.PeerKeyAuthorizationBundle{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle nodekeys.PeerKeyAuthorizationBundle
	if err := decoder.Decode(&bundle); err != nil {
		return nodekeys.PeerKeyAuthorizationBundle{}, errors.New("Hub returned an invalid Link authorization bundle")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nodekeys.PeerKeyAuthorizationBundle{}, errors.New("Hub returned an invalid Link authorization bundle")
	}
	return bundle, nil
}

type nodeSealedSendReceipt struct {
	MessageID   string `json:"message_id"`
	PayloadMode string `json:"payload_mode"`
	OutboxState string `json:"outbox_state"`
	Sequence    int64  `json:"sequence"`
}

func (b *machineAgentJoinBridge) postSealedLinkMessage(input fabricpkg.NodeSealedLinkSendInput) (nodeSealedSendReceipt, error) {
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/sealed/send"
	payload, err := json.Marshal(input)
	if err != nil {
		return nodeSealedSendReceipt{}, err
	}
	data, err := b.nodeHTTP(http.MethodPost, path, payload)
	if err != nil {
		return nodeSealedSendReceipt{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt nodeSealedSendReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nodeSealedSendReceipt{}, errors.New("Hub returned an invalid sealed-send receipt")
	}
	return receipt, nil
}

func (b *machineAgentJoinBridge) nodeHTTP(method, path string, body []byte) ([]byte, error) {
	return b.httpWithAuthorization(method, path, body, "CicadaNode "+b.nodeToken, "")
}

func (b *machineAgentJoinBridge) verifyCurrentMCPBinding(sessionToken, groupID string) (fabricpkg.NetworkCard, error) {
	if strings.TrimSpace(sessionToken) == "" {
		return fabricpkg.NetworkCard{}, errors.New("current Cicada session credential is required")
	}
	data, err := b.httpWithAuthorization(http.MethodGet, "/v2/fabric/whoami", nil,
		"CicadaSession "+sessionToken, groupID)
	if err != nil {
		if localSealedSendRetryable(err) {
			return fabricpkg.NetworkCard{}, err
		}
		return fabricpkg.NetworkCard{}, errors.New("current Cicada session binding could not be verified")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var card fabricpkg.NetworkCard
	if err := decoder.Decode(&card); err != nil {
		return fabricpkg.NetworkCard{}, errors.New("Hub returned an invalid current session binding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		card.EndpointID == "" || card.GroupID == "" || card.PrincipalID == "" ||
		card.NodeID == "" || card.BindingID == "" || card.BindingEpoch == 0 || card.NativeSessionID == "" {
		return fabricpkg.NetworkCard{}, errors.New("Hub returned an incomplete current session binding")
	}
	return card, nil
}

func (b *machineAgentJoinBridge) httpWithAuthorization(method, path string, body []byte,
	authorization, groupID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, b.baseURL+path, reader)
	if err != nil {
		return nil, errors.New("could not prepare Node Relay request")
	}
	request.Header.Set("Authorization", authorization)
	if strings.TrimSpace(groupID) != "" {
		request.Header.Set("Cicada-Group-Scope", groupID)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	client, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, &localSealedSendError{message: "could not reach the authorized Hub Node Relay", retryable: true}
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if readErr != nil || len(data) > 2*1024*1024 {
		return nil, &localSealedSendError{message: "Hub returned an invalid Node Relay response", retryable: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		retryable := response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooEarly ||
			response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		return nil, &localSealedSendError{
			message: fmt.Sprintf("Node Relay request failed with HTTP %d", response.StatusCode), retryable: retryable,
		}
	}
	return data, nil
}
