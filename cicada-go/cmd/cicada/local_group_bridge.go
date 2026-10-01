package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	"github.com/cicada-ai/cicada/internal/store"
)

const localGroupProtocolVersion = 1

// localGroupRequest crosses the owner-only Node Unix socket. The model only
// supplies target/body (or a request ID); every identity and operation ID
// comes from the joined native Session and the durable MCP outbox. The Node
// independently rechecks both the Codex record and Hub Session binding.
type localGroupRequest struct {
	Version              int                                  `json:"version"`
	Operation            string                               `json:"operation"`
	Harness              string                               `json:"harness"`
	NativeSessionID      string                               `json:"native_session_id"`
	NodeID               string                               `json:"node_id"`
	Workspace            string                               `json:"workspace"`
	SessionToken         string                               `json:"session_token"`
	EndpointID           string                               `json:"endpoint_id"`
	PrincipalID          string                               `json:"principal_id"`
	OwnerID              string                               `json:"owner_id"`
	GroupID              string                               `json:"group_id"`
	BindingID            string                               `json:"binding_id"`
	BindingEpoch         uint64                               `json:"binding_epoch"`
	OperationID          string                               `json:"operation_id,omitempty"`
	OperationCreatedAt   string                               `json:"operation_created_at,omitempty"`
	IdempotencyKey       string                               `json:"idempotency_key,omitempty"`
	Target               string                               `json:"target,omitempty"`
	RequestID            string                               `json:"request_id,omitempty"`
	Reason               string                               `json:"reason,omitempty"`
	Body                 string                               `json:"body,omitempty"`
	Cursor               string                               `json:"cursor,omitempty"`
	Limit                int                                  `json:"limit,omitempty"`
	TaskHandoffID        string                               `json:"task_handoff_id,omitempty"`
	TaskID               string                               `json:"task_id,omitempty"`
	ExpectedRevision     int64                                `json:"expected_revision,omitempty"`
	OwnerEpoch           int64                                `json:"owner_epoch,omitempty"`
	HandoffMessageID     string                               `json:"handoff_message_id,omitempty"`
	ExpiresAt            string                               `json:"expires_at,omitempty"`
	RequiredArtifactRefs []store.SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
}

type localGroupResult struct {
	MessageID        string                     `json:"message_id,omitempty"`
	RequestID        string                     `json:"request_id,omitempty"`
	TargetEndpointID string                     `json:"target_endpoint_id,omitempty"`
	State            string                     `json:"state"`
	Delivery         string                     `json:"delivery,omitempty"`
	PayloadMode      string                     `json:"payload_mode,omitempty"`
	ExpiresAt        string                     `json:"expires_at,omitempty"`
	ReplyMessageID   string                     `json:"reply_message_id,omitempty"`
	LateMessageID    string                     `json:"late_message_id,omitempty"`
	Messages         []nodeinbox.VisibleMessage `json:"messages,omitempty"`
	NextCursor       string                     `json:"next_cursor,omitempty"`
	MessageDigest    string                     `json:"message_digest,omitempty"`
	SenderProof      []byte                     `json:"sender_proof,omitempty"`
	SharedMemoryRisk bool                       `json:"shared_memory_risk,omitempty"`
}

func requestMachineAgentLocalGroup(socketPath string, request localGroupRequest) (*localGroupResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = localGroupProtocolVersion
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "could not submit request to the local Node", retryable: true}
	}
	if unixConnection, ok := connection.(interface{ CloseWrite() error }); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, &localSealedSendError{message: "could not finish the local Node request", retryable: true}
		}
	}
	responseLimit := int64(64 * 1024)
	if request.Operation == "local_receive" {
		responseLimit = 2 * 1024 * 1024
	}
	decoder := json.NewDecoder(io.LimitReader(connection, responseLimit))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "local Node returned an invalid Group response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.LocalGroup == nil || response.LocalGroup.State == "" {
		return nil, &localSealedSendError{message: "local Node returned an incomplete Group result", retryable: true}
	}
	if request.RequestID != "" && response.LocalGroup.RequestID != request.RequestID {
		return nil, &localSealedSendError{message: "local Node returned an uncorrelated Group result", retryable: true}
	}
	if request.Operation == "local_task_handoff" || request.Operation == "local_task_handoff_recover" {
		if response.LocalGroup.MessageID != request.HandoffMessageID ||
			len(response.LocalGroup.MessageDigest) != 64 ||
			(request.Operation == "local_task_handoff" && len(response.LocalGroup.SenderProof) == 0) {
			return nil, &localSealedSendError{message: "local Node returned an uncorrelated sealed Task handoff", retryable: true}
		}
	} else if request.OperationID != "" {
		messageID, requestID, idErr := localSealedRPCIDs(request.OperationID)
		if idErr != nil || response.LocalGroup.MessageID != messageID ||
			(request.Operation == "local_ask" && response.LocalGroup.RequestID != requestID) {
			return nil, &localSealedSendError{message: "local Node returned an uncorrelated message result", retryable: true}
		}
	}
	return response.LocalGroup, nil
}

func validateLocalGroupRequest(request localGroupRequest, nodeID string) error {
	if request.Version != localGroupProtocolVersion || harness.Canonical(request.Harness) != "codex" ||
		request.NativeSessionID == "" || len(request.NativeSessionID) > 512 ||
		request.NodeID != nodeID || filepath.Clean(strings.TrimSpace(request.Workspace)) == "." ||
		request.SessionToken == "" || request.EndpointID == "" || request.PrincipalID == "" ||
		request.OwnerID == "" || request.GroupID == "" || request.BindingID == "" ||
		request.BindingEpoch == 0 {
		return errors.New("invalid trusted local Group context")
	}
	for _, value := range []string{request.EndpointID, request.PrincipalID, request.OwnerID, request.GroupID,
		request.BindingID, request.OperationID, request.IdempotencyKey, request.Target, request.RequestID,
		request.TaskHandoffID, request.TaskID, request.HandoffMessageID} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted local Group context")
		}
	}
	if len([]byte(request.Body)) > 64*1024 || len(request.Reason) > 512 {
		return errors.New("invalid trusted local Group request")
	}
	if request.Operation != "local_receive" && (request.Cursor != "" || request.Limit != 0) {
		return errors.New("unexpected inbox cursor or limit")
	}
	switch request.Operation {
	case "local_receive":
		if request.Limit < 0 || request.Limit > 16 {
			return errors.New("local receive page size is out of range")
		}
		if len(request.Cursor) > 2048 {
			return errors.New("local receive cursor is too long")
		}
		if request.Target != "" || request.Body != "" || request.Reason != "" ||
			request.RequestID != "" || request.OperationID != "" || request.IdempotencyKey != "" ||
			request.OperationCreatedAt != "" {
			return errors.New("invalid scoped local receive")
		}
	case "local_send", "local_ask":
		if request.Target == "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.Body == "" || request.RequestID != "" || request.Reason != "" {
			return errors.New("invalid trusted local Group send or ask")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return err
		}
		if request.Operation == "local_ask" {
			if _, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt); err != nil {
				return errors.New("local ASK requires its durable creation time")
			}
		} else if request.OperationCreatedAt != "" {
			return errors.New("local SEND cannot set a request deadline")
		}
	case "local_reply":
		if request.OperationID == "" || request.IdempotencyKey == "" || request.RequestID == "" ||
			request.Target != "" || request.Body == "" || request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid trusted local Group reply")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return err
		}
	case "local_status", "local_cancel":
		if request.RequestID == "" || request.Target != "" || request.Body != "" ||
			request.OperationID != "" || request.IdempotencyKey != "" || request.OperationCreatedAt != "" ||
			(request.Operation != "local_cancel" && request.Reason != "") {
			return errors.New("invalid trusted local Group request control")
		}
	case "local_task_handoff":
		if request.OperationID == "" || request.IdempotencyKey == "" || request.Target == "" ||
			request.TaskHandoffID == "" || request.TaskID == "" || request.ExpectedRevision <= 0 ||
			request.OwnerEpoch <= 0 || request.HandoffMessageID == "" || request.ExpiresAt == "" ||
			request.Body == "" || request.RequestID != "" || request.OperationCreatedAt == "" ||
			request.Reason != "" || len(request.RequiredArtifactRefs) > 32 {
			return errors.New("invalid local sealed Task handoff")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return err
		}
		handoffID, deadline, ok := parseTaskHandoffMessageID(request.HandoffMessageID)
		expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if !ok || handoffID != request.TaskHandoffID || err != nil ||
			deadline.UnixMilli() != expires.UnixMilli() || expires.Nanosecond()%1_000_000 != 0 {
			return errors.New("local sealed Task handoff ID and deadline do not match")
		}
		created, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
		if err != nil || created.After(time.Now().UTC().Add(time.Minute)) ||
			!expires.After(created) || expires.Sub(created) > 24*time.Hour {
			return errors.New("local sealed Task handoff creation time is invalid")
		}
	case "local_task_handoff_notify":
		if request.TaskHandoffID == "" || request.Target != "" || request.Body != "" ||
			request.TaskID != "" || request.OperationID != "" || request.IdempotencyKey != "" ||
			request.ExpectedRevision != 0 || request.OwnerEpoch != 0 || request.HandoffMessageID != "" ||
			request.ExpiresAt != "" || len(request.RequiredArtifactRefs) != 0 ||
			request.RequestID != "" || request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid local Task handoff wake request")
		}
	case "local_task_handoff_recover":
		if request.TaskHandoffID == "" || request.HandoffMessageID == "" ||
			request.Target != "" || request.Body != "" || request.TaskID != "" ||
			request.OperationID != "" || request.IdempotencyKey != "" ||
			request.ExpectedRevision != 0 || request.OwnerEpoch != 0 || request.ExpiresAt != "" ||
			len(request.RequiredArtifactRefs) != 0 || request.RequestID != "" ||
			request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid local Task handoff recovery request")
		}
		handoffID, _, ok := parseTaskHandoffMessageID(request.HandoffMessageID)
		if !ok || handoffID != request.TaskHandoffID {
			return errors.New("local Task handoff recovery ID does not match its route")
		}
	default:
		return errors.New("unsupported local Group operation")
	}
	return nil
}

func (b *machineAgentJoinBridge) verifyLocalGroupSource(request localGroupRequest) (fabric.NetworkCard, error) {
	if err := validateLocalGroupRequest(request, b.nodeID); err != nil {
		return fabric.NetworkCard{}, err
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return fabric.NetworkCard{}, err
	}
	card, err := b.verifyCurrentMCPBinding(request.SessionToken, request.GroupID)
	if err != nil {
		return fabric.NetworkCard{}, err
	}
	if card.EndpointID != request.EndpointID || card.PrincipalID != request.PrincipalID ||
		card.GroupID != request.GroupID || card.NodeID != b.nodeID ||
		card.BindingID != request.BindingID || card.BindingEpoch != request.BindingEpoch ||
		card.NativeSessionID != request.NativeSessionID || harness.Canonical(card.Harness) != "codex" ||
		filepath.Clean(card.Workspace) != filepath.Clean(request.Workspace) {
		return fabric.NetworkCard{}, errors.New("current Cicada session does not match its trusted native binding")
	}
	return card, nil
}

// fetchLocalGroupAuthorization asks only Hub Guard/Directory. It never sends
// peer body to Hub and never invokes a Hub Relay message endpoint. The second
// credential header binds the current native Session to the Node credential.
func (b *machineAgentJoinBridge) fetchLocalGroupAuthorization(sessionToken string,
	input store.LocalDeliveryAuthorizationInput) (*store.LocalDeliveryAuthorization, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(b.ctx, http.MethodPost,
		b.baseURL+"/v2/relay/nodes/"+urlPath(b.nodeID)+"/local/authorize", bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("could not prepare current local Group authorization")
	}
	request.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	request.Header.Set("X-Cicada-Session", sessionToken)
	request.Header.Set("Content-Type", "application/json")
	client, err := machineNodeHTTPClient(b.ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, &localSealedSendError{message: "could not reach Hub Guard for local Group authorization", retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &localSealedSendError{
			message:   fmt.Sprintf("current local Group authorization rejected with HTTP %d", response.StatusCode),
			retryable: response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500,
		}
	}
	// Two ML-DSA attestations and ML-KEM public identities are larger than
	// ordinary metadata. Keep a bound, but leave room for both candidates.
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256*1024))
	decoder.DisallowUnknownFields()
	var authorization store.LocalDeliveryAuthorization
	if err := decoder.Decode(&authorization); err != nil {
		return nil, errors.New("Hub returned an invalid local Group authorization")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Hub returned an invalid local Group authorization")
	}
	validUntil, err := time.Parse(time.RFC3339Nano, authorization.ValidUntil)
	if err != nil || !validUntil.After(time.Now().UTC()) || authorization.Action != input.Action ||
		authorization.Source.NodeID != b.nodeID || authorization.Target.NodeID != b.nodeID ||
		authorization.Source.OwnerID == "" || authorization.Source.OwnerID != authorization.Target.OwnerID ||
		authorization.Source.GroupID != input.GroupID || authorization.Target.GroupID != input.GroupID ||
		authorization.Target.NativeSessionID == "" || authorization.Source.EndpointID == authorization.Target.EndpointID {
		return nil, errors.New("Hub returned an invalid or stale local Group authorization")
	}
	return &authorization, nil
}

func validateLocalGroupAuthorizationForSource(authorization *store.LocalDeliveryAuthorization,
	request localGroupRequest) error {
	if authorization == nil || authorization.Source.EndpointID != request.EndpointID ||
		authorization.Source.PrincipalID != request.PrincipalID ||
		authorization.Source.OwnerID != request.OwnerID || authorization.Source.GroupID != request.GroupID ||
		authorization.Source.NodeID != request.NodeID || authorization.Source.BindingID != request.BindingID ||
		authorization.Source.BindingEpoch != request.BindingEpoch ||
		authorization.Source.MembershipRevision <= 0 || authorization.Target.MembershipRevision <= 0 ||
		authorization.Source.GroupJoinRevision <= 0 || authorization.Target.GroupJoinRevision <= 0 ||
		authorization.SourceKey.KeyID == "" || authorization.SourceKey.KeyID != authorization.SourceKey.Public.ID ||
		authorization.TargetKey.KeyID == "" || authorization.TargetKey.KeyID != authorization.TargetKey.Public.ID {
		return errors.New("current local Group authorization does not match the native source")
	}
	return nil
}

func localGroupEndpointRoute(authorization store.LocalDeliveryAuthorization,
	messageID, kind, requestID, replyTo string) e2ee.EndpointMessageContext {
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		SenderEndpointID:           authorization.Source.EndpointID,
		SenderPrincipalID:          authorization.Source.PrincipalID,
		SenderOwnerID:              authorization.Source.OwnerID,
		SenderGroupID:              authorization.Source.GroupID,
		SenderMembershipRevision:   authorization.Source.MembershipRevision,
		SenderBindingEpoch:         authorization.Source.BindingEpoch,
		SenderKeyID:                authorization.SourceKey.KeyID,
		ReceiverEndpointID:         authorization.Target.EndpointID,
		ReceiverPrincipalID:        authorization.Target.PrincipalID,
		ReceiverOwnerID:            authorization.Target.OwnerID,
		ReceiverGroupID:            authorization.Target.GroupID,
		ReceiverMembershipRevision: authorization.Target.MembershipRevision,
		ReceiverBindingEpoch:       authorization.Target.BindingEpoch,
		ReceiverKeyID:              authorization.TargetKey.KeyID,
	}
}

func (b *machineAgentJoinBridge) loadLocalGroupIdentities(
	authorization store.LocalDeliveryAuthorization) (*e2ee.Identity, *e2ee.Identity, error) {
	stateDir := machineNodeStateDir(b.stateDir, b.nodeID)
	if authorization.Source.NodeID != b.nodeID || authorization.Target.NodeID != b.nodeID ||
		authorization.Source.OwnerID == "" || authorization.Source.OwnerID != authorization.Target.OwnerID ||
		authorization.Source.GroupID == "" || authorization.Source.GroupID != authorization.Target.GroupID {
		return nil, nil, errors.New("local Group authorization is not a same-Node route")
	}
	for _, side := range []struct {
		endpoint store.LocalDeliveryEndpointAuthorization
		key      store.LocalDeliveryKeyCandidate
	}{{authorization.Source, authorization.SourceKey}, {authorization.Target, authorization.TargetKey}} {
		digest := sha256.Sum256(side.key.Proof)
		if side.key.KeyID == "" || side.key.KeyID != side.key.Public.ID ||
			side.key.ProofDigest != hex.EncodeToString(digest[:]) {
			return nil, nil, errors.New("local Endpoint candidate proof is invalid")
		}
		verified, err := e2ee.VerifyEndpointKeyAttestation(side.key.Proof,
			side.endpoint.EndpointID, side.endpoint.PrincipalID, side.endpoint.NodeID,
			side.endpoint.BindingID, side.endpoint.BindingEpoch)
		if err != nil || !sameLocalPublicIdentity(verified, side.key.Public) {
			return nil, nil, errors.New("local Endpoint candidate proof does not match current binding")
		}
	}
	source, err := nodekeys.LoadOrCreate(stateDir, authorization.Source.EndpointID)
	if err != nil {
		return nil, nil, fmt.Errorf("load local source Endpoint key: %w", err)
	}
	target, err := nodekeys.LoadOrCreate(stateDir, authorization.Target.EndpointID)
	if err != nil {
		return nil, nil, fmt.Errorf("load local target Endpoint key: %w", err)
	}
	if !sameLocalPublicIdentity(source.Public(), authorization.SourceKey.Public) ||
		!sameLocalPublicIdentity(target.Public(), authorization.TargetKey.Public) {
		return nil, nil, errors.New("local Endpoint private keys do not match current candidates")
	}
	return source, target, nil
}

func localGroupLedgerRoute(authorization store.LocalDeliveryAuthorization,
	sourceNativeSessionID string) (nodelocal.Route, error) {
	action, err := localGroupLedgerAction(authorization.Action)
	if err != nil {
		return nodelocal.Route{}, err
	}
	validUntil, err := time.Parse(time.RFC3339Nano, authorization.ValidUntil)
	if err != nil || !validUntil.After(time.Now().UTC()) ||
		sourceNativeSessionID == "" || authorization.Target.NativeSessionID == "" {
		return nodelocal.Route{}, errors.New("current local Group route has no valid native binding")
	}
	source, target := authorization.Source, authorization.Target
	return nodelocal.Route{
		SourceOwnerID: source.OwnerID, TargetOwnerID: target.OwnerID,
		SourceNodeID: source.NodeID, TargetNodeID: target.NodeID,
		SourcePrincipalID: source.PrincipalID, TargetPrincipalID: target.PrincipalID,
		SourceEndpointID: source.EndpointID, TargetEndpointID: target.EndpointID,
		SourceGroupID: source.GroupID, TargetGroupID: target.GroupID,
		SourceMembershipRevision: uint64(source.MembershipRevision),
		TargetMembershipRevision: uint64(target.MembershipRevision),
		SourceJoinRevision:       uint64(source.GroupJoinRevision),
		TargetJoinRevision:       uint64(target.GroupJoinRevision),
		SourceBindingID:          source.BindingID, TargetBindingID: target.BindingID,
		SourceBindingEpoch: source.BindingEpoch, TargetBindingEpoch: target.BindingEpoch,
		SourceKeyID: authorization.SourceKey.KeyID, TargetKeyID: authorization.TargetKey.KeyID,
		SourceSessionID: sourceNativeSessionID, TargetSessionID: target.NativeSessionID,
		SourceCandidateID:      authorization.SourceKey.KeyID,
		TargetCandidateID:      authorization.TargetKey.KeyID,
		SourceCandidateVersion: uint64(authorization.SourceKey.Version),
		TargetCandidateVersion: uint64(authorization.TargetKey.Version),
		AuthorizationRevision:  authorization.AuthorizationRevision,
		Action:                 action, Scope: source.GroupID,
		AuthorizationValidUntil: validUntil.UTC(),
	}, nil
}

func localGroupLedgerAction(guardAction string) (string, error) {
	switch guardAction {
	case "message.send":
		return "SEND", nil
	case "message.ask":
		return "ASK", nil
	case "message.reply":
		return "REPLY", nil
	default:
		return "", errors.New("unsupported local Group authorization action")
	}
}

func localGroupGuardAction(ledgerAction string) (string, error) {
	switch ledgerAction {
	case "SEND":
		return "message.send", nil
	case "ASK":
		return "message.ask", nil
	case "REPLY":
		return "message.reply", nil
	default:
		return "", errors.New("unsupported local Group ledger action")
	}
}

func (b *machineAgentJoinBridge) localGroup(request localGroupRequest) (*localGroupResult, error) {
	return b.localGroupWithBroadcastFence(request, nil)
}

func (b *machineAgentJoinBridge) localGroupWithBroadcastFence(request localGroupRequest,
	fence *groupBroadcastDeliveryFence) (*localGroupResult, error) {
	if fence != nil && request.Operation != "local_send" {
		return nil, errors.New("broadcast snapshot can only authorize SEND")
	}
	if _, err := b.verifyLocalGroupSource(request); err != nil {
		return nil, err
	}
	if request.Operation == "local_receive" {
		return b.receiveLocalGroup(request)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(b.stateDir, b.nodeID))
	if err != nil {
		return nil, fmt.Errorf("open local Group message ledger: %w", err)
	}
	defer ledger.Close()
	switch request.Operation {
	case "local_send", "local_ask", "local_reply":
		return b.submitLocalGroupMessage(ledger, request, fence)
	case "local_task_handoff":
		if fence != nil {
			return nil, errors.New("Task handoff cannot use a broadcast snapshot")
		}
		return b.submitLocalSealedTaskHandoff(ledger, request)
	case "local_task_handoff_notify":
		b.signalLocalGroupDelivery()
		return &localGroupResult{State: "READY", Delivery: "LOCAL_WAKE", PayloadMode: "SEALED_V1"}, nil
	case "local_task_handoff_recover":
		return b.recoverLocalSealedTaskHandoff(ledger, request)
	case "local_status", "local_cancel":
		stored, err := ledger.GetRequest(b.ctx, request.RequestID)
		if err != nil {
			return nil, err
		}
		requester := stored.Route.SourceEndpointID == request.EndpointID &&
			stored.Route.SourceSessionID == request.NativeSessionID &&
			stored.Route.SourceBindingID == request.BindingID &&
			stored.Route.SourceBindingEpoch == request.BindingEpoch &&
			stored.Route.SourceGroupID == request.GroupID
		if !requester {
			return nil, errors.New("local request is not owned by the current native session")
		}
		if request.Operation == "local_cancel" {
			stored, err = ledger.CancelRequest(b.ctx, request.RequestID, request.EndpointID)
			if err != nil {
				return nil, err
			}
		}
		return &localGroupResult{
			RequestID: stored.RequestID, MessageID: stored.MessageID,
			TargetEndpointID: stored.TargetEndpointID, State: string(stored.State),
			PayloadMode: "SEALED_V1", ExpiresAt: stored.ExpiresAt.UTC().Format(time.RFC3339Nano),
			ReplyMessageID: stored.ReplyMessageID,
		}, nil
	default:
		return nil, errors.New("unsupported local Group operation")
	}
}

func machineLocalGroupLedgerPath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "local-messages.sqlite3")
}

func machineLocalGroupInboxPath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "local-inbox.sqlite3")
}

func (b *machineAgentJoinBridge) submitLocalGroupMessage(ledger *nodelocal.Ledger,
	request localGroupRequest, fence *groupBroadcastDeliveryFence) (*localGroupResult, error) {
	messageID, derivedRequestID, err := localSealedRPCIDs(request.OperationID)
	if err != nil {
		return nil, err
	}
	action, kind, target, replyTo := "", "", request.Target, ""
	var original nodelocal.Request
	switch request.Operation {
	case "local_send":
		action, kind = "message.send", "SEND"
	case "local_ask":
		action, kind = "message.ask", "REQUEST"
	case "local_reply":
		action, kind = "message.reply", "REPLY"
		original, err = ledger.GetRequest(b.ctx, request.RequestID)
		if err != nil {
			return nil, err
		}
		if original.Route.TargetEndpointID != request.EndpointID ||
			original.Route.TargetGroupID != request.GroupID ||
			original.Route.TargetBindingID != request.BindingID ||
			original.Route.TargetBindingEpoch != request.BindingEpoch ||
			original.Route.TargetSessionID != request.NativeSessionID {
			return nil, errors.New("current native session is not the original local request responder")
		}
		target = original.Route.SourceEndpointID
		replyTo = original.MessageID
	default:
		return nil, errors.New("unsupported local Group message kind")
	}
	authorization, err := b.fetchLocalGroupAuthorization(request.SessionToken,
		store.LocalDeliveryAuthorizationInput{GroupID: request.GroupID, Target: target, Action: action})
	if err != nil {
		return nil, err
	}
	if err := validateLocalGroupAuthorizationForSource(authorization, request); err != nil {
		return nil, err
	}
	sourceContext, err := b.recordLocalNativeContext(*authorization, authorization.Source,
		request.Harness, request.NativeSessionID)
	if err != nil {
		return nil, err
	}
	targetContext, err := b.recordLocalNativeContext(*authorization, authorization.Target,
		request.Harness, authorization.Target.NativeSessionID)
	if err != nil {
		return nil, err
	}
	if request.Operation == "local_reply" &&
		(authorization.Target.EndpointID != original.Route.SourceEndpointID ||
			authorization.Target.BindingID != original.Route.SourceBindingID ||
			authorization.Target.BindingEpoch != original.Route.SourceBindingEpoch ||
			authorization.Target.NativeSessionID != original.Route.SourceSessionID) {
		return nil, errors.New("original requester native binding changed before local reply")
	}
	if err := fence.validateLocal(authorization); err != nil {
		return nil, err
	}
	sender, receiver, err := b.loadLocalGroupIdentities(*authorization)
	if err != nil {
		return nil, err
	}
	requestID := request.RequestID
	if request.Operation == "local_ask" {
		requestID = derivedRequestID
	}
	route := localGroupEndpointRoute(*authorization, messageID, kind, requestID, replyTo)
	ledgerRoute, err := localGroupLedgerRoute(*authorization, request.NativeSessionID)
	if err != nil {
		return nil, err
	}
	cryptoState, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return nil, err
	}
	defer cryptoState.Close()
	outbound, err := cryptoState.SealLocalSameGroupMessage(b.ctx, sender, receiver,
		authorization.SourceKey.Public, authorization.TargetKey.Public, route, []byte(request.Body))
	if err != nil {
		return nil, err
	}
	input := nodelocal.MessageInput{MessageID: messageID, Route: ledgerRoute, Ciphertext: outbound.Envelope}
	var accepted nodelocal.Accepted
	var expiresAt time.Time
	switch request.Operation {
	case "local_send":
		accepted, err = ledger.AcceptSend(b.ctx, input)
	case "local_ask":
		createdAt, parseErr := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
		if parseErr != nil || createdAt.After(time.Now().UTC().Add(time.Minute)) {
			return nil, errors.New("local ASK durable creation time is invalid")
		}
		expiresAt = createdAt.UTC().Add(localSealedAskDefaultLifetime)
		accepted, err = ledger.AcceptAsk(b.ctx, nodelocal.AskInput{
			MessageInput: input, RequestID: requestID, ExpiresAt: expiresAt,
		})
	case "local_reply":
		accepted, err = ledger.AcceptReply(b.ctx, nodelocal.ReplyInput{
			MessageInput: input, RequestID: requestID, ReplyToMessageID: replyTo,
		})
	}
	if err != nil {
		return nil, err
	}
	log.Printf("local peer accepted message_id=%s request_id=%s kind=%s source=%s target=%s node=%s state=%s",
		accepted.MessageID, requestID, kind, authorization.Source.EndpointID,
		authorization.Target.EndpointID, b.nodeID, accepted.State)
	if accepted.State != nodelocal.DeliveryLate {
		b.signalLocalGroupDelivery()
	}
	delivery := "LOCAL_PERSISTED"
	if accepted.State == nodelocal.DeliveryLate {
		delivery = "LATE_RESULT_RETAINED"
	}
	result := &localGroupResult{
		MessageID: accepted.MessageID, RequestID: requestID,
		TargetEndpointID: authorization.Target.EndpointID,
		State:            string(accepted.State), Delivery: delivery,
		PayloadMode: "SEALED_V1", SharedMemoryRisk: sourceContext.SharedMemoryRisk || targetContext.SharedMemoryRisk,
	}
	if request.Operation == "local_ask" {
		result.ExpiresAt = expiresAt.Format(time.RFC3339Nano)
	}
	return result, nil
}

func (b *machineAgentJoinBridge) signalLocalGroupDelivery() {
	if b == nil || b.localWake == nil {
		return
	}
	select {
	case b.localWake <- struct{}{}:
	default:
	}
}

// revalidateLocalGroupRoute is used after the original MCP call has returned
// or the Node restarted. The durable ledger stores no session credential;
// only the already bound Node credential may recheck an exact persisted route.
func (b *machineAgentJoinBridge) revalidateLocalGroupRoute(
	route nodelocal.Route, messageID, messageDigest string) (*store.LocalDeliveryAuthorization, error) {
	guardAction, err := localGroupGuardAction(route.Action)
	if err != nil {
		return nil, err
	}
	input := store.LocalDeliveryRevalidationInput{
		GroupID: route.SourceGroupID, SourceEndpointID: route.SourceEndpointID,
		SourceBindingID:    route.SourceBindingID,
		SourceBindingEpoch: route.SourceBindingEpoch,
		TargetEndpointID:   route.TargetEndpointID, Action: guardAction,
		MessageID: messageID, MessageDigest: messageDigest,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	data, err := b.nodeHTTP(http.MethodPost,
		"/v2/relay/nodes/"+urlPath(b.nodeID)+"/local/revalidate", encoded)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var current store.LocalDeliveryAuthorization
	if err := decoder.Decode(&current); err != nil {
		return nil, errors.New("Hub returned an invalid current local delivery authorization")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Hub returned an invalid current local delivery authorization")
	}
	if current.Action != guardAction || current.Source.EndpointID != route.SourceEndpointID ||
		current.Target.EndpointID != route.TargetEndpointID ||
		current.Source.NodeID != b.nodeID || current.Target.NodeID != b.nodeID {
		return nil, errors.New("current local delivery authorization changed route")
	}
	currentRoute, err := localGroupLedgerRoute(current, route.SourceSessionID)
	if err != nil {
		return nil, err
	}
	currentRoute.AuthorizationValidUntil = route.AuthorizationValidUntil
	if currentRoute != route {
		return nil, errors.New("current local delivery authorization is stale for the persisted route")
	}
	if _, err := b.recordLocalNativeContext(current, current.Source, "codex", route.SourceSessionID); err != nil {
		return nil, err
	}
	if _, err := b.recordLocalNativeContext(current, current.Target, "codex", route.TargetSessionID); err != nil {
		return nil, err
	}
	return &current, nil
}
