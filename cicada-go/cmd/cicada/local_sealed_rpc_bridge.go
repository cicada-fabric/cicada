package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

const (
	localSealedRPCProtocolVersion = 1
	localSealedAskDefaultLifetime = 30 * time.Minute
	localSealedAuthorizationRef   = "communication-link.v2:"
)

// localSealedRPCRequest crosses only the owner-only Unix socket. Identity is
// repeated from the MCP session so the machine agent can compare it to a fresh
// Session-authenticated whoami response and the signed Link manifest. Message
// IDs and route roles are intentionally absent: the bridge derives them.
type localSealedRPCRequest struct {
	Version            int    `json:"version"`
	Operation          string `json:"operation"`
	Harness            string `json:"harness"`
	NativeSessionID    string `json:"native_session_id"`
	NodeID             string `json:"node_id"`
	Workspace          string `json:"workspace,omitempty"`
	SessionToken       string `json:"session_token"`
	EndpointID         string `json:"endpoint_id"`
	PrincipalID        string `json:"principal_id"`
	OwnerID            string `json:"owner_id"`
	GroupID            string `json:"group_id"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	OperationID        string `json:"operation_id,omitempty"`
	OperationCreatedAt string `json:"operation_created_at,omitempty"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	LinkID             string `json:"link_id,omitempty"`
	DataScope          string `json:"data_scope,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	RequestID          string `json:"request_id,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Body               string `json:"body,omitempty"`
}

type localSealedRPCResult struct {
	RequestID           string `json:"request_id"`
	MessageID           string `json:"message_id,omitempty"`
	LinkID              string `json:"link_id,omitempty"`
	Status              string `json:"status"`
	ReplyMode           string `json:"reply_mode,omitempty"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	ReplyMessageID      string `json:"reply_message_id,omitempty"`
	LateResultMessageID string `json:"late_result_message_id,omitempty"`
	PayloadMode         string `json:"payload_mode,omitempty"`
	Delivery            string `json:"delivery,omitempty"`
	Sequence            uint64 `json:"endpoint_sequence,omitempty"`
	CiphertextReused    bool   `json:"ciphertext_reused,omitempty"`
}

func requestMachineAgentSealedRPC(socketPath string, request localSealedRPCRequest) (*localSealedRPCResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = localSealedRPCProtocolVersion
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "could not send sealed request to the trusted local Node agent", retryable: true}
	}
	if unixConnection, ok := connection.(interface{ CloseWrite() error }); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, &localSealedSendError{message: "could not finish the local sealed request", retryable: true}
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "trusted local Node agent returned an invalid sealed RPC response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.SealedRPC == nil || response.SealedRPC.RequestID == "" {
		return nil, &localSealedSendError{message: "trusted local Node agent returned an incomplete sealed RPC result", retryable: true}
	}
	if request.Operation == "sealed_ask" {
		messageID, requestID, idErr := localSealedRPCIDs(request.OperationID)
		if idErr != nil || response.SealedRPC.MessageID != messageID || response.SealedRPC.RequestID != requestID {
			return nil, &localSealedSendError{message: "trusted local Node agent returned an uncorrelated sealed ASK result", retryable: true}
		}
	} else if request.RequestID != "" && response.SealedRPC.RequestID != request.RequestID {
		return nil, &localSealedSendError{message: "trusted local Node agent returned an uncorrelated sealed request result", retryable: true}
	}
	return response.SealedRPC, nil
}

func (b *machineAgentJoinBridge) sealedRPC(request localSealedRPCRequest) (*localSealedRPCResult, error) {
	if err := validateLocalSealedRPCRequest(request, b.nodeID); err != nil {
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
		card.NativeSessionID != request.NativeSessionID || harness.Canonical(card.Harness) != "codex" ||
		filepath.Clean(card.Workspace) != filepath.Clean(request.Workspace) {
		return nil, errors.New("current Cicada session does not match its trusted native binding")
	}

	switch request.Operation {
	case "sealed_ask":
		return b.sealedAsk(request, card)
	case "sealed_reply":
		return b.sealedReply(request, card)
	case "sealed_status":
		return b.sealedStatus(request)
	case "sealed_cancel":
		return b.sealedCancel(request)
	default:
		return nil, errors.New("unsupported local sealed RPC operation")
	}
}

func validateLocalSealedRPCRequest(request localSealedRPCRequest, nodeID string) error {
	if request.Version != localSealedRPCProtocolVersion ||
		harness.Canonical(request.Harness) != "codex" || strings.TrimSpace(request.NativeSessionID) == "" ||
		len(request.NativeSessionID) > 512 || filepath.Clean(strings.TrimSpace(request.Workspace)) == "." ||
		request.NodeID != nodeID || strings.TrimSpace(request.SessionToken) == "" ||
		request.EndpointID == "" || request.PrincipalID == "" || request.OwnerID == "" ||
		request.GroupID == "" || request.BindingID == "" || request.BindingEpoch == 0 {
		return errors.New("invalid trusted local sealed RPC context")
	}
	for _, value := range []string{request.EndpointID, request.PrincipalID, request.OwnerID,
		request.GroupID, request.BindingID, request.LinkID, request.OperationID,
		request.IdempotencyKey, request.RequestID, request.DataScope} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted local sealed RPC context")
		}
	}
	if len([]byte(request.Body)) > 64*1024 || len(request.Reason) > 512 {
		return errors.New("invalid trusted local sealed RPC context")
	}
	switch request.Operation {
	case "sealed_ask":
		if request.OperationID == "" || request.IdempotencyKey == "" || request.LinkID == "" ||
			request.DataScope == "" || request.Body == "" || request.RequestID != "" || request.Reason != "" {
			return errors.New("invalid trusted local sealed ASK")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return errors.New("invalid trusted local sealed ASK operation identity")
		}
		if request.ExpiresAt == "" && request.OperationCreatedAt == "" {
			return errors.New("sealed ASK requires its durable operation creation time")
		}
		if request.ExpiresAt != "" && request.OperationCreatedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt); err != nil {
				return errors.New("sealed ASK has an invalid operation creation time")
			}
		}
	case "sealed_reply":
		if request.OperationID == "" || request.IdempotencyKey == "" || request.RequestID == "" ||
			request.Body == "" || request.DataScope != "" || request.ExpiresAt != "" ||
			request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid trusted local sealed REPLY")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return errors.New("invalid trusted local sealed REPLY operation identity")
		}
	case "sealed_status":
		if request.RequestID == "" || request.OperationID != "" || request.IdempotencyKey != "" ||
			request.DataScope != "" || request.ExpiresAt != "" || request.OperationCreatedAt != "" ||
			request.Body != "" || request.Reason != "" {
			return errors.New("invalid trusted local sealed status request")
		}
	case "sealed_cancel":
		if request.RequestID == "" || request.OperationID != "" || request.IdempotencyKey != "" ||
			request.DataScope != "" || request.ExpiresAt != "" || request.OperationCreatedAt != "" ||
			request.Body != "" {
			return errors.New("invalid trusted local sealed cancellation")
		}
	default:
		return errors.New("unsupported local sealed RPC operation")
	}
	if request.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, request.ExpiresAt); err != nil {
			return errors.New("sealed ASK has an invalid deadline")
		}
	}
	if request.OperationCreatedAt != "" {
		createdAt, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
		if err != nil || createdAt.After(time.Now().UTC().Add(time.Minute)) {
			return errors.New("sealed ASK has an invalid durable operation creation time")
		}
	}
	return nil
}

func localSealedRPCIDs(operationID string) (messageID, requestID string, err error) {
	if len(operationID) != 35 || !strings.HasPrefix(operationID, "op_") {
		return "", "", errors.New("invalid operation identity")
	}
	suffix := operationID[3:]
	decoded, decodeErr := hex.DecodeString(suffix)
	if decodeErr != nil || len(decoded) != 16 || strings.ToLower(suffix) != suffix {
		return "", "", errors.New("invalid operation identity")
	}
	return "msg_" + suffix, "rq_" + suffix, nil
}

func (b *machineAgentJoinBridge) sealedAsk(request localSealedRPCRequest, card fabricpkg.NetworkCard) (*localSealedRPCResult, error) {
	bundle, err := b.fetchLinkAuthorization(request.LinkID)
	if err != nil {
		return nil, err
	}
	if err := validateLocalSealedLinkBundle(bundle, request.LinkID, request.DataScope, "ask"); err != nil {
		return nil, err
	}
	manifest := bundle.Manifest
	identity, state, err := b.localCryptoState(request.EndpointID)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	if !localCardMatchesLinkSource(card, request, b.nodeID) ||
		!localManifestSideMatchesRequest(manifest.Source, request, b.nodeID) ||
		manifest.Source.KeyID != identity.Public().ID ||
		!sameLocalPublicIdentity(manifest.Source.PublicIdentity, identity.Public()) {
		return nil, errors.New("current native session does not match the selected Link source binding")
	}
	messageID, requestID, _ := localSealedRPCIDs(request.OperationID)
	contract, _ := parseLocalLinkContract(manifest.ContractCanonical)
	linkExpiry, err := time.Parse(time.RFC3339Nano, contract.ExpiresAt)
	if err != nil {
		return nil, errors.New("selected Communication Link has an invalid expiry")
	}
	expiresAt, err := localSealedAskDeadline(request, linkExpiry, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	route := localSealedRoute(manifest, contract, messageID, "REQUEST", requestID, "")
	local, peer, scope := localSealedPinContext(manifest, identity.Public(), b.nodeID, false)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(b.ctx, scope, local, peer, bundle); err != nil {
		return nil, fmt.Errorf("verify local trust and bilateral Link grants: %w", err)
	}
	plaintext := []byte(request.Body)
	operationID, err := nodekeys.EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return nil, err
	}
	outbound, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(
		b.ctx, identity, scope, local, peer, bundle, request.DataScope, operationID, route, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal durable Endpoint request: %w", err)
	}
	accepted, err := b.postSealedLinkAsk(fabricpkg.NodeSealedLinkAskInput{
		LinkID: request.LinkID, MessageID: messageID, RequestID: requestID,
		IdempotencyKey: request.IdempotencyKey, DataScope: request.DataScope,
		ExpiresAt: expiresAt.Format(time.RFC3339Nano), Ciphertext: outbound.Envelope,
	})
	if err != nil {
		return nil, err
	}
	if accepted.RequestID != requestID || accepted.MessageID != messageID ||
		accepted.State != store.FabricRequestOpen || accepted.ReplyMode != "asynchronous" ||
		accepted.PayloadMode != store.RelayPayloadModeSealedV1 || accepted.ExpiresAt != expiresAt.Format(time.RFC3339Nano) {
		return nil, &localSealedSendError{message: "Hub returned an invalid sealed ASK receipt", retryable: true}
	}
	return &localSealedRPCResult{
		RequestID: requestID, MessageID: messageID, LinkID: request.LinkID,
		Status: accepted.State, ReplyMode: accepted.ReplyMode, ExpiresAt: accepted.ExpiresAt,
		PayloadMode: accepted.PayloadMode, Delivery: "RELAY_PERSISTED",
		Sequence: outbound.Sequence, CiphertextReused: outbound.Reused,
	}, nil
}

func localSealedAskDeadline(request localSealedRPCRequest, linkExpiry, now time.Time) (time.Time, error) {
	var expiresAt time.Time
	if request.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if err != nil {
			return time.Time{}, errors.New("sealed ASK deadline is invalid")
		}
		expiresAt = parsed.UTC()
	} else {
		createdAt, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
		if err != nil || createdAt.After(now.Add(time.Minute)) {
			return time.Time{}, errors.New("sealed ASK operation creation time is invalid")
		}
		expiresAt = createdAt.Add(localSealedAskDefaultLifetime)
		if linkExpiry.Before(expiresAt) {
			expiresAt = linkExpiry
		}
	}
	if !expiresAt.After(now) || expiresAt.After(linkExpiry) {
		return time.Time{}, errors.New("sealed ASK deadline must be in the future and no later than the Link expiry")
	}
	return expiresAt.UTC(), nil
}

func (b *machineAgentJoinBridge) sealedReply(request localSealedRPCRequest, card fabricpkg.NetworkCard) (*localSealedRPCResult, error) {
	requestStatus, err := b.fetchSealedRequestStatus(request.RequestID)
	if err != nil {
		return nil, err
	}
	linkID, err := sealedRequestLinkID(requestStatus)
	if err != nil || (request.LinkID != "" && request.LinkID != linkID) {
		return nil, errors.New("sealed REPLY Link selector does not match the original request")
	}
	bundle, err := b.fetchLinkAuthorization(linkID)
	if err != nil {
		return nil, err
	}
	if err := validateLocalSealedLinkBundle(bundle, linkID, requestStatus.VisibilityPolicyRef, "reply"); err != nil {
		return nil, err
	}
	manifest := bundle.Manifest
	if !sealedRequestMatchesManifest(requestStatus, manifest) ||
		!localCardMatchesStatusReceiver(card, request, requestStatus, b.nodeID) ||
		manifest.Target.OwnerID != request.OwnerID || manifest.Target.NodeID != b.nodeID {
		return nil, errors.New("current native session is not the original authorized responder")
	}
	messageID, _, err := localSealedRPCIDs(request.OperationID)
	if err != nil {
		return nil, err
	}
	terminalMessageID := requestStatus.ReplyMessageID
	if requestStatus.State == store.FabricRequestLateResult {
		terminalMessageID = requestStatus.LateResultMessageID
	}
	if (requestStatus.State == store.FabricRequestReplied || requestStatus.State == store.FabricRequestLateResult) &&
		terminalMessageID != messageID {
		return nil, store.ErrRelayRequestTerminal
	}
	switch requestStatus.State {
	case store.FabricRequestOpen, store.FabricRequestCancelRequested,
		store.FabricRequestCancelled, store.FabricRequestExpired,
		store.FabricRequestReplied, store.FabricRequestLateResult:
	default:
		return nil, store.ErrRelayRequestTerminal
	}
	identity, state, err := b.localCryptoState(request.EndpointID)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	if manifest.Target.KeyID != identity.Public().ID ||
		!sameLocalPublicIdentity(manifest.Target.PublicIdentity, identity.Public()) {
		return nil, errors.New("current native session does not match the original responder key")
	}
	contract, _ := parseLocalLinkContract(manifest.ContractCanonical)
	route := localSealedRoute(manifest, contract, messageID, "REPLY", request.RequestID, requestStatus.MessageID)
	local, peer, scope := localSealedPinContext(manifest, identity.Public(), b.nodeID, true)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(b.ctx, scope, local, peer, bundle); err != nil {
		return nil, fmt.Errorf("verify local trust and bilateral Link grants: %w", err)
	}
	plaintext := []byte(request.Body)
	operationID, err := nodekeys.EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return nil, err
	}
	outbound, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(
		b.ctx, identity, scope, local, peer, bundle, requestStatus.VisibilityPolicyRef,
		operationID, route, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal durable Endpoint reply: %w", err)
	}
	accepted, err := b.postSealedLinkReply(fabricpkg.NodeSealedLinkReplyInput{
		RequestID: requestStatus.RequestID, MessageID: messageID,
		IdempotencyKey: request.IdempotencyKey, DataScope: requestStatus.VisibilityPolicyRef,
		Ciphertext: outbound.Envelope,
	})
	if err != nil {
		return nil, err
	}
	if accepted.RequestID != requestStatus.RequestID || accepted.MessageID != messageID ||
		accepted.PayloadMode != store.RelayPayloadModeSealedV1 {
		return nil, &localSealedSendError{message: "Hub returned an invalid sealed REPLY receipt", retryable: true}
	}
	delivery := "RELAY_PERSISTED"
	if accepted.State == store.FabricRequestLateResult {
		delivery = "LATE_RESULT_RETAINED"
	} else if accepted.State != store.FabricRequestReplied {
		return nil, &localSealedSendError{message: "Hub returned an invalid sealed REPLY lifecycle state", retryable: true}
	}
	return &localSealedRPCResult{
		RequestID: requestStatus.RequestID, MessageID: messageID, LinkID: linkID,
		Status: accepted.State, PayloadMode: accepted.PayloadMode, Delivery: delivery,
		Sequence: outbound.Sequence, CiphertextReused: outbound.Reused,
	}, nil
}

func (b *machineAgentJoinBridge) sealedStatus(request localSealedRPCRequest) (*localSealedRPCResult, error) {
	status, err := b.fetchSealedRequestStatus(request.RequestID)
	if err != nil {
		return nil, err
	}
	linkID, err := sealedRequestLinkID(status)
	if err != nil || request.LinkID != "" && request.LinkID != linkID {
		return nil, errors.New("sealed request Link selector does not match its authorization")
	}
	if !localCardMatchesStatusEitherSide(request, status, b.nodeID) {
		return nil, errors.New("current native session is not bound to either side of this sealed request")
	}
	return localSealedStatusResult(status, linkID), nil
}

func (b *machineAgentJoinBridge) sealedCancel(request localSealedRPCRequest) (*localSealedRPCResult, error) {
	status, err := b.fetchSealedRequestStatus(request.RequestID)
	if err != nil {
		return nil, err
	}
	linkID, err := sealedRequestLinkID(status)
	if err != nil || request.LinkID != "" && request.LinkID != linkID {
		return nil, errors.New("sealed request Link selector does not match its authorization")
	}
	if !localCardMatchesStatusSender(request, status, b.nodeID) {
		return nil, errors.New("only the original native requester can cancel this sealed request")
	}
	body, err := json.Marshal(struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: request.Reason})
	if err != nil {
		return nil, err
	}
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/sealed/requests/" +
		url.PathEscape(request.RequestID) + "/cancel"
	data, err := b.nodeHTTP(http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	var cancelled store.FabricRequest
	if err := decodeStrictBridgeJSON(data, &cancelled); err != nil || cancelled.RequestID != status.RequestID {
		return nil, &localSealedSendError{message: "Hub returned an invalid sealed cancellation status", retryable: true}
	}
	return localSealedStatusResult(&cancelled, linkID), nil
}

func (b *machineAgentJoinBridge) fetchSealedRequestStatus(requestID string) (*store.FabricRequest, error) {
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/sealed/requests/" + url.PathEscape(requestID)
	data, err := b.nodeHTTP(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var status store.FabricRequest
	if err := decodeStrictBridgeJSON(data, &status); err != nil || status.RequestID != requestID ||
		status.MessageID == "" || status.SenderEndpointID == "" || status.SenderPrincipalID == "" ||
		status.SenderGroupID == "" || status.SenderBindingID == "" || status.SenderBindingEpoch == 0 ||
		status.ReceiverEndpointID == "" || status.ReceiverPrincipalID == "" ||
		status.ReceiverGroupID == "" || status.ReceiverBindingID == "" || status.ReceiverBindingEpoch == 0 ||
		status.VisibilityPolicyRef == "" || status.Digest == "" {
		return nil, &localSealedSendError{message: "Hub returned incomplete sealed request status", retryable: true}
	}
	return &status, nil
}

func (b *machineAgentJoinBridge) localCryptoState(endpointID string) (*e2ee.Identity, *nodekeys.CryptoState, error) {
	stateDir := machineNodeStateDir(b.stateDir, b.nodeID)
	identity, err := nodekeys.LoadOrCreate(stateDir, endpointID)
	if err != nil {
		return nil, nil, fmt.Errorf("load Node-local Endpoint identity: %w", err)
	}
	state, err := nodekeys.OpenCryptoState(stateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open Node-local crypto state: %w", err)
	}
	return identity, state, nil
}

func validateLocalSealedLinkBundle(bundle nodekeys.PeerKeyAuthorizationBundle,
	linkID, dataScope, action string) error {
	if bundle.LinkState != "ACTIVE" && bundle.LinkState != "PROPOSED" {
		return errors.New("the selected Communication Link is not available")
	}
	manifest := bundle.Manifest
	contract, err := parseLocalLinkContract(manifest.ContractCanonical)
	if err != nil || manifest.LinkID != linkID || contract.LinkID != linkID ||
		contract.SourceEndpointID != manifest.Source.EndpointID ||
		contract.SourcePrincipalID != manifest.Source.PrincipalID ||
		contract.SourceOwnerID != manifest.Source.OwnerID || contract.SourceGroupID != manifest.Source.GroupID ||
		contract.SourceNodeID != manifest.Source.NodeID ||
		contract.TargetEndpointID != manifest.Target.EndpointID ||
		contract.TargetPrincipalID != manifest.Target.PrincipalID ||
		contract.TargetOwnerID != manifest.Target.OwnerID || contract.TargetGroupID != manifest.Target.GroupID ||
		contract.TargetNodeID != manifest.Target.NodeID || contract.TransportHubID == "" ||
		(contract.Direction != "forward" && contract.Direction != "bidirectional") ||
		manifest.Source.EndpointID == manifest.Target.EndpointID || manifest.Source.GroupID == manifest.Target.GroupID ||
		manifest.Source.OwnerID == manifest.Target.OwnerID || manifest.Source.NodeID == manifest.Target.NodeID ||
		!containsLocalString(contract.Actions, action) ||
		(action == "reply" && !containsLocalString(contract.Actions, "ask")) ||
		!containsLocalString(contract.DataScopes, dataScope) {
		return errors.New("selected Communication Link does not authorize this ASK/REPLY scope")
	}
	return nil
}

func localCardMatchesLinkSource(card fabricpkg.NetworkCard, request localSealedRPCRequest, nodeID string) bool {
	return card.EndpointID == request.EndpointID && card.GroupID == request.GroupID &&
		card.PrincipalID == request.PrincipalID && card.NodeID == nodeID &&
		card.BindingID == request.BindingID && card.BindingEpoch == request.BindingEpoch &&
		card.NativeSessionID == request.NativeSessionID && harness.Canonical(card.Harness) == "codex" &&
		filepath.Clean(card.Workspace) == filepath.Clean(request.Workspace)
}

func localManifestSideMatchesRequest(side nodekeys.PeerKeyManifestSide,
	request localSealedRPCRequest, nodeID string) bool {
	return side.EndpointID == request.EndpointID && side.PrincipalID == request.PrincipalID &&
		side.OwnerID == request.OwnerID && side.GroupID == request.GroupID && side.NodeID == nodeID &&
		side.BindingID == request.BindingID && side.BindingEpoch == request.BindingEpoch
}

func sameLocalPublicIdentity(a, b e2ee.PublicIdentity) bool {
	return a.ID == b.ID && bytes.Equal(a.KEMPublic, b.KEMPublic) &&
		bytes.Equal(a.SigningPublic, b.SigningPublic)
}

func localSealedPinContext(manifest nodekeys.PeerKeyAuthorizationManifest,
	public e2ee.PublicIdentity, nodeID string, reverse bool) (
	nodekeys.PeerPinLocalEndpoint, nodekeys.PeerPinIdentity, nodekeys.PeerPinScope) {
	localSide, peerSide := manifest.Source, manifest.Target
	if reverse {
		localSide, peerSide = manifest.Target, manifest.Source
	}
	local := nodekeys.PeerPinLocalEndpoint{
		EndpointID: localSide.EndpointID, GroupID: localSide.GroupID,
		PrincipalID: localSide.PrincipalID, OwnerID: localSide.OwnerID,
		NodeID: nodeID, BindingID: localSide.BindingID, BindingEpoch: localSide.BindingEpoch,
		KeyID: localSide.KeyID, Public: public,
	}
	peer := nodekeys.PeerPinIdentity{
		EndpointID: peerSide.EndpointID, GroupID: peerSide.GroupID,
		PrincipalID: peerSide.PrincipalID, OwnerID: peerSide.OwnerID,
	}
	scope := nodekeys.PeerPinScope{
		LocalEndpointID: local.EndpointID, LocalGroupID: local.GroupID,
		PeerEndpointID: peer.EndpointID, PeerGroupID: peer.GroupID,
		CommunicationLinkID: manifest.LinkID,
	}
	return local, peer, scope
}

func localSealedRoute(manifest nodekeys.PeerKeyAuthorizationManifest,
	contract localLinkContract, messageID, kind, requestID, replyTo string) e2ee.EndpointMessageContext {
	requestKind := kind == "REQUEST"
	sender, receiver := manifest.Source, manifest.Target
	senderMembershipRevision := contract.ScopeSnapshot.SourceMembershipRevision
	receiverMembershipRevision := contract.ScopeSnapshot.TargetMembershipRevision
	if !requestKind {
		sender, receiver = manifest.Target, manifest.Source
		senderMembershipRevision, receiverMembershipRevision = receiverMembershipRevision, senderMembershipRevision
	}
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		SenderEndpointID: sender.EndpointID, SenderPrincipalID: sender.PrincipalID,
		SenderOwnerID: sender.OwnerID, SenderGroupID: sender.GroupID,
		SenderMembershipRevision: senderMembershipRevision, SenderBindingEpoch: sender.BindingEpoch,
		SenderKeyID: sender.KeyID, ReceiverEndpointID: receiver.EndpointID,
		ReceiverPrincipalID: receiver.PrincipalID, ReceiverOwnerID: receiver.OwnerID,
		ReceiverGroupID: receiver.GroupID, ReceiverMembershipRevision: receiverMembershipRevision,
		ReceiverBindingEpoch: receiver.BindingEpoch, ReceiverKeyID: receiver.KeyID,
		LinkID: manifest.LinkID, LinkRevision: manifest.LinkVersion, TransportHubID: contract.TransportHubID,
	}
}

func sealedRequestLinkID(status *store.FabricRequest) (string, error) {
	if status == nil || !strings.HasPrefix(status.AuthorizationRef, localSealedAuthorizationRef) {
		return "", errors.New("request is not an authorized sealed Communication Link request")
	}
	linkID := strings.TrimPrefix(status.AuthorizationRef, localSealedAuthorizationRef)
	if linkID == "" || strings.ContainsAny(linkID, "/\\\r\n\x00") {
		return "", errors.New("request has an invalid sealed Communication Link reference")
	}
	return linkID, nil
}

func sealedRequestMatchesManifest(status *store.FabricRequest,
	manifest nodekeys.PeerKeyAuthorizationManifest) bool {
	return status != nil && status.AuthorizationRef == localSealedAuthorizationRef+manifest.LinkID &&
		status.SenderEndpointID == manifest.Source.EndpointID &&
		status.SenderPrincipalID == manifest.Source.PrincipalID && status.SenderGroupID == manifest.Source.GroupID &&
		status.SenderBindingID == manifest.Source.BindingID && status.SenderBindingEpoch == manifest.Source.BindingEpoch &&
		status.ReceiverEndpointID == manifest.Target.EndpointID &&
		status.ReceiverPrincipalID == manifest.Target.PrincipalID && status.ReceiverGroupID == manifest.Target.GroupID &&
		status.ReceiverBindingID == manifest.Target.BindingID && status.ReceiverBindingEpoch == manifest.Target.BindingEpoch &&
		status.MessageID != "" && status.RequestID != "" && status.VisibilityPolicyRef != ""
}

func localCardMatchesStatusReceiver(card fabricpkg.NetworkCard, request localSealedRPCRequest,
	status *store.FabricRequest, nodeID string) bool {
	return status != nil && request.EndpointID == status.ReceiverEndpointID &&
		request.PrincipalID == status.ReceiverPrincipalID && request.GroupID == status.ReceiverGroupID &&
		request.BindingID == status.ReceiverBindingID && request.BindingEpoch == status.ReceiverBindingEpoch &&
		card.EndpointID == status.ReceiverEndpointID && card.PrincipalID == status.ReceiverPrincipalID &&
		card.GroupID == status.ReceiverGroupID && card.BindingID == status.ReceiverBindingID &&
		card.BindingEpoch == status.ReceiverBindingEpoch && card.NodeID == nodeID &&
		card.NativeSessionID == request.NativeSessionID && harness.Canonical(card.Harness) == "codex" &&
		filepath.Clean(card.Workspace) == filepath.Clean(request.Workspace)
}

func localCardMatchesStatusSender(request localSealedRPCRequest,
	status *store.FabricRequest, nodeID string) bool {
	return status != nil && request.EndpointID == status.SenderEndpointID &&
		request.PrincipalID == status.SenderPrincipalID && request.GroupID == status.SenderGroupID &&
		request.BindingID == status.SenderBindingID && request.BindingEpoch == status.SenderBindingEpoch &&
		request.NodeID == nodeID
}

func localCardMatchesStatusEitherSide(request localSealedRPCRequest,
	status *store.FabricRequest, nodeID string) bool {
	return status != nil && request.NodeID == nodeID &&
		((request.EndpointID == status.SenderEndpointID && request.PrincipalID == status.SenderPrincipalID &&
			request.GroupID == status.SenderGroupID && request.BindingID == status.SenderBindingID &&
			request.BindingEpoch == status.SenderBindingEpoch) ||
			(request.EndpointID == status.ReceiverEndpointID && request.PrincipalID == status.ReceiverPrincipalID &&
				request.GroupID == status.ReceiverGroupID && request.BindingID == status.ReceiverBindingID &&
				request.BindingEpoch == status.ReceiverBindingEpoch))
}

func localSealedStatusResult(status *store.FabricRequest, linkID string) *localSealedRPCResult {
	if status == nil {
		return nil
	}
	return &localSealedRPCResult{
		RequestID: status.RequestID, MessageID: status.MessageID, LinkID: linkID,
		Status: status.State, ExpiresAt: status.ExpiresAt,
		ReplyMessageID: status.ReplyMessageID, LateResultMessageID: status.LateResultMessageID,
		PayloadMode: store.RelayPayloadModeSealedV1,
	}
}

type localSealedAskReceipt struct {
	RequestID   string `json:"request_id"`
	MessageID   string `json:"message_id"`
	State       string `json:"state"`
	ExpiresAt   string `json:"expires_at"`
	ReplyMode   string `json:"reply_mode"`
	PayloadMode string `json:"payload_mode"`
}

type localSealedReplyReceipt struct {
	RequestID   string `json:"request_id"`
	MessageID   string `json:"message_id"`
	State       string `json:"state"`
	PayloadMode string `json:"payload_mode"`
}

func (b *machineAgentJoinBridge) postSealedLinkAsk(input fabricpkg.NodeSealedLinkAskInput) (localSealedAskReceipt, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return localSealedAskReceipt{}, err
	}
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/sealed/ask"
	response, err := b.nodeHTTP(http.MethodPost, path, data)
	if err != nil {
		return localSealedAskReceipt{}, err
	}
	var receipt localSealedAskReceipt
	if err := decodeStrictBridgeJSON(response, &receipt); err != nil {
		return localSealedAskReceipt{}, &localSealedSendError{message: "Hub returned an invalid sealed ASK receipt", retryable: true}
	}
	return receipt, nil
}

func (b *machineAgentJoinBridge) postSealedLinkReply(input fabricpkg.NodeSealedLinkReplyInput) (localSealedReplyReceipt, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return localSealedReplyReceipt{}, err
	}
	path := "/v2/relay/nodes/" + url.PathEscape(b.nodeID) + "/sealed/reply"
	response, err := b.nodeHTTP(http.MethodPost, path, data)
	if err != nil {
		return localSealedReplyReceipt{}, err
	}
	var receipt localSealedReplyReceipt
	if err := decodeStrictBridgeJSON(response, &receipt); err != nil {
		return localSealedReplyReceipt{}, &localSealedSendError{message: "Hub returned an invalid sealed REPLY receipt", retryable: true}
	}
	return receipt, nil
}

func decodeStrictBridgeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("response has trailing data")
	}
	return nil
}
