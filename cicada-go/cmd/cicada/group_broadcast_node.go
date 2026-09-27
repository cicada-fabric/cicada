package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

const (
	groupBroadcastProtocolVersion = 1
	groupBroadcastBatchSize       = 8
	groupBroadcastMaxRecipients   = store.SameGroupBroadcastV2MaxRecipients
)

type groupBroadcastRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace"`
	SessionToken    string `json:"session_token"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
	OwnerID         string `json:"owner_id"`
	GroupID         string `json:"group_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
	OperationID     string `json:"operation_id"`
	BroadcastID     string `json:"broadcast_id"`
	Body            string `json:"body"`
	Offset          int    `json:"offset"`
}

type groupBroadcastRecipientResult struct {
	EndpointID  string `json:"endpoint_id"`
	NodeID      string `json:"node_id"`
	MessageID   string `json:"message_id,omitempty"`
	State       string `json:"state"`
	FailureCode string `json:"failure_code,omitempty"`
}

type groupBroadcastResult struct {
	BroadcastID    string                          `json:"broadcast_id"`
	GroupID        string                          `json:"group_id"`
	SnapshotDigest string                          `json:"snapshot_digest"`
	RecipientCount int                             `json:"recipient_count"`
	Offset         int                             `json:"offset"`
	NextOffset     int                             `json:"next_offset"`
	Complete       bool                            `json:"complete"`
	Recipients     []groupBroadcastRecipientResult `json:"recipients"`
}

type groupBroadcastHubSnapshotResponse struct {
	HubID    string                             `json:"hub_id"`
	Snapshot store.SameGroupBroadcastV2Snapshot `json:"snapshot"`
}

func requestMachineAgentGroupBroadcast(socketPath string, request groupBroadcastRequest) (*groupBroadcastResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = groupBroadcastProtocolVersion
	request.Operation = "group_broadcast"
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "could not submit broadcast to the local Node", retryable: true}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 128*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "local Node returned an invalid broadcast response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	result := response.GroupBroadcast
	if result == nil || result.BroadcastID != request.BroadcastID || result.GroupID != request.GroupID ||
		result.SnapshotDigest == "" || result.Offset != request.Offset || result.RecipientCount < 0 ||
		result.RecipientCount > groupBroadcastMaxRecipients || result.NextOffset < result.Offset ||
		result.NextOffset > result.RecipientCount || len(result.Recipients) > groupBroadcastBatchSize ||
		len(result.Recipients) != result.NextOffset-result.Offset ||
		result.Complete != (result.NextOffset == result.RecipientCount) ||
		(!result.Complete && result.NextOffset == result.Offset) {
		return nil, &localSealedSendError{message: "local Node returned inconsistent broadcast progress", retryable: true}
	}
	seen := make(map[string]struct{}, len(result.Recipients))
	for _, recipient := range result.Recipients {
		if recipient.EndpointID == "" || recipient.NodeID == "" {
			return nil, &localSealedSendError{message: "local Node returned an invalid broadcast recipient", retryable: true}
		}
		if _, duplicate := seen[recipient.EndpointID]; duplicate {
			return nil, &localSealedSendError{message: "local Node repeated a broadcast recipient", retryable: true}
		}
		seen[recipient.EndpointID] = struct{}{}
		switch recipient.State {
		case "ACCEPTED":
			expected, _, idErr := localSealedRPCIDs(groupBroadcastChildOperationID(request.BroadcastID, recipient.EndpointID))
			if idErr != nil || recipient.MessageID != expected || recipient.FailureCode != "" {
				return nil, &localSealedSendError{message: "local Node returned an uncorrelated accepted broadcast child", retryable: true}
			}
		case "UNKNOWN":
			if recipient.MessageID != "" || recipient.FailureCode != "DELIVERY_OUTCOME_UNKNOWN" {
				return nil, &localSealedSendError{message: "local Node returned an invalid uncertain broadcast child", retryable: true}
			}
		case "FAILED":
			if recipient.MessageID != "" || recipient.FailureCode != "DELIVERY_REJECTED" {
				return nil, &localSealedSendError{message: "local Node returned an invalid failed broadcast child", retryable: true}
			}
		default:
			return nil, &localSealedSendError{message: "local Node returned an unknown broadcast child state", retryable: true}
		}
	}
	return result, nil
}

func validateGroupBroadcastRequest(request groupBroadcastRequest, nodeID string) error {
	if request.Version != groupBroadcastProtocolVersion || request.Operation != "group_broadcast" ||
		harness.Canonical(request.Harness) != "codex" || request.NativeSessionID == "" ||
		len(request.NativeSessionID) > 512 || request.NodeID != nodeID || strings.TrimSpace(request.Workspace) == "" ||
		request.SessionToken == "" || request.EndpointID == "" || request.PrincipalID == "" ||
		request.OwnerID == "" || request.GroupID == "" || request.BindingID == "" ||
		request.BindingEpoch == 0 || request.Offset < 0 || request.Offset > groupBroadcastMaxRecipients ||
		request.Body == "" || len([]byte(request.Body)) > 64*1024 {
		return errors.New("invalid trusted same-Group broadcast context")
	}
	if len(request.SessionToken) > 4096 || len(request.Workspace) > 4096 ||
		strings.TrimSpace(request.SessionToken) != request.SessionToken ||
		strings.ContainsAny(request.SessionToken, "\r\n\x00") {
		return errors.New("invalid trusted same-Group broadcast context")
	}
	for _, value := range []string{request.EndpointID, request.PrincipalID, request.OwnerID,
		request.GroupID, request.BindingID, request.OperationID, request.BroadcastID} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted same-Group broadcast context")
		}
	}
	if _, _, err := localSealedRPCIDs(request.OperationID); err != nil || len(request.BroadcastID) != 35 ||
		request.BroadcastID != "bc_"+strings.TrimPrefix(request.OperationID, "op_") {
		return errors.New("invalid durable Group broadcast identity")
	}
	return nil
}

func (b *machineAgentJoinBridge) groupBroadcast(request groupBroadcastRequest) (*groupBroadcastResult, error) {
	if err := validateGroupBroadcastRequest(request, b.nodeID); err != nil {
		return nil, err
	}
	// Reuse the same native-session and Session-binding checks as ordinary
	// same-Group delivery. This synthetic request is validated only; it is never
	// passed to crossNodeGroup and cannot cause an extra peer message.
	sourceCheck := crossNodeGroupRequest{
		Version: crossNodeGroupProtocolVersion, Operation: "cross_node_group_send",
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		NodeID: request.NodeID, Workspace: request.Workspace, SessionToken: request.SessionToken,
		EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID,
		GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
		TargetEndpointID: request.EndpointID, OperationID: request.OperationID,
		IdempotencyKey: request.OperationID, Body: request.Body,
	}
	card, err := b.verifyCrossNodeGroupSource(sourceCheck)
	if err != nil {
		return nil, err
	}
	snapshot, err := b.fetchGroupBroadcastSnapshot(request)
	if err != nil {
		return nil, err
	}
	if err := validateGroupBroadcastSnapshot(snapshot, request, card, b.nodeID); err != nil {
		return nil, err
	}
	return b.deliverGroupBroadcastBatch(request, snapshot)
}

func (b *machineAgentJoinBridge) fetchGroupBroadcastSnapshot(request groupBroadcastRequest) (*store.SameGroupBroadcastV2Snapshot, error) {
	expectedHubID := strings.TrimSpace(os.Getenv("CICADA_HUB_ID"))
	if expectedHubID == "" {
		return nil, errors.New("CICADA_HUB_ID must be pinned locally before Group broadcast")
	}
	payload, err := json.Marshal(struct {
		GroupID     string `json:"group_id"`
		BroadcastID string `json:"broadcast_id"`
	}{request.GroupID, request.BroadcastID})
	if err != nil {
		return nil, err
	}
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(b.baseURL, "/")+"/v2/relay/nodes/"+url.PathEscape(b.nodeID)+"/group/broadcast/snapshot",
		bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("could not prepare current Group broadcast snapshot request")
	}
	httpRequest.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	httpRequest.Header.Set("X-Cicada-Session", request.SessionToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}).Do(httpRequest)
	if err != nil {
		return nil, &localSealedSendError{message: "could not reach the pinned Hub broadcast snapshot", retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &localSealedSendError{message: "Hub did not authorize the current Group broadcast snapshot",
			retryable: response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500}
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024+1))
	decoder.DisallowUnknownFields()
	var envelope groupBroadcastHubSnapshotResponse
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("Hub returned an invalid Group broadcast snapshot")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Hub returned an invalid Group broadcast snapshot")
	}
	if envelope.HubID == "" || envelope.HubID != expectedHubID {
		return nil, errors.New("Group broadcast snapshot belongs to a different configured Hub")
	}
	return &envelope.Snapshot, nil
}

func validateGroupBroadcastSnapshot(snapshot *store.SameGroupBroadcastV2Snapshot,
	request groupBroadcastRequest, card fabric.NetworkCard, nodeID string) error {
	if snapshot == nil || snapshot.BroadcastID != request.BroadcastID || snapshot.GroupID != request.GroupID ||
		snapshot.Source.EndpointID != card.EndpointID || snapshot.Source.PrincipalID != card.PrincipalID ||
		snapshot.Source.OwnerID != request.OwnerID || snapshot.Source.NodeID != nodeID ||
		snapshot.Source.GroupID != request.GroupID || snapshot.Source.NativeSessionID != request.NativeSessionID ||
		snapshot.Source.BindingID != request.BindingID || snapshot.Source.BindingEpoch != request.BindingEpoch ||
		snapshot.GroupRevision <= 0 || snapshot.Source.GroupRevision != snapshot.GroupRevision ||
		snapshot.Source.MembershipRevision <= 0 || snapshot.Source.GroupJoinRevision <= 0 ||
		snapshot.Source.BindingVersion <= 0 || snapshot.Source.KeyVersion <= 0 ||
		snapshot.Source.KeyID == "" || snapshot.Source.KeyID != snapshot.Source.PublicKey.ID ||
		snapshot.Source.KeyProofDigest == "" || len(snapshot.Recipients) > groupBroadcastMaxRecipients {
		return errors.New("Hub returned a stale or inconsistent Group broadcast source snapshot")
	}
	if err := e2ee.ValidatePublicIdentity(snapshot.Source.PublicKey); err != nil {
		return errors.New("Hub returned invalid Group broadcast source key evidence")
	}
	for index, recipient := range snapshot.Recipients {
		if recipient.EndpointID == "" || recipient.EndpointID == snapshot.Source.EndpointID ||
			recipient.PrincipalID == "" || recipient.OwnerID != snapshot.Source.OwnerID ||
			recipient.NodeID == "" || recipient.GroupID != request.GroupID ||
			recipient.GroupRevision != snapshot.GroupRevision || recipient.MembershipRevision <= 0 ||
			recipient.GroupJoinRevision <= 0 || recipient.BindingID == "" || recipient.BindingEpoch == 0 ||
			recipient.BindingVersion <= 0 || recipient.KeyVersion <= 0 || recipient.KeyID == "" ||
			recipient.KeyID != recipient.PublicKey.ID || recipient.KeyProofDigest == "" ||
			(index > 0 && snapshot.Recipients[index-1].EndpointID >= recipient.EndpointID) {
			return errors.New("Hub returned an invalid or cross-Group broadcast recipient")
		}
		if err := e2ee.ValidatePublicIdentity(recipient.PublicKey); err != nil {
			return errors.New("Hub returned invalid Group broadcast recipient key evidence")
		}
	}
	if len(snapshot.SnapshotDigest) != sha256.Size*2 {
		return errors.New("Hub returned an invalid Group broadcast snapshot digest")
	}
	if _, err := hex.DecodeString(snapshot.SnapshotDigest); err != nil || strings.ToLower(snapshot.SnapshotDigest) != snapshot.SnapshotDigest {
		return errors.New("Hub returned an invalid Group broadcast snapshot digest")
	}
	digest, err := groupBroadcastSnapshotDigest(snapshot)
	if err != nil || digest != snapshot.SnapshotDigest {
		return errors.New("Hub Group broadcast snapshot digest did not match its contents")
	}
	return nil
}

func groupBroadcastSnapshotDigest(snapshot *store.SameGroupBroadcastV2Snapshot) (string, error) {
	if snapshot == nil {
		return "", errors.New("broadcast snapshot is required")
	}
	copy := *snapshot
	copy.SnapshotDigest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func groupBroadcastChildOperationID(broadcastID, endpointID string) string {
	hash := sha256.Sum256([]byte("cicada/group-broadcast-child/v1\x00" + broadcastID + "\x00" + endpointID))
	return "op_" + hex.EncodeToString(hash[:16])
}

func (b *machineAgentJoinBridge) deliverGroupBroadcastBatch(request groupBroadcastRequest,
	snapshot *store.SameGroupBroadcastV2Snapshot) (*groupBroadcastResult, error) {
	return fanoutGroupBroadcastBatch(request, snapshot, b.nodeID,
		func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
			return b.sendLocalGroupBroadcastChild(request, snapshot.Source, recipient, operationID)
		},
		func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
			return b.sendRemoteGroupBroadcastChild(request, snapshot.Source, recipient, operationID)
		})
}

func fanoutGroupBroadcastBatch(request groupBroadcastRequest,
	snapshot *store.SameGroupBroadcastV2Snapshot, sourceNode string,
	sendLocal func(store.SameGroupBroadcastV2Endpoint, string) (string, error),
	sendRemote func(store.SameGroupBroadcastV2Endpoint, string) (string, error)) (*groupBroadcastResult, error) {
	if snapshot == nil || sendLocal == nil || sendRemote == nil {
		return nil, errors.New("broadcast snapshot and delivery callbacks are required")
	}
	if len(snapshot.Recipients) > groupBroadcastMaxRecipients || request.Offset < 0 ||
		request.Offset > len(snapshot.Recipients) {
		return nil, errors.New("broadcast batch offset is outside the immutable recipient snapshot")
	}
	end := request.Offset + groupBroadcastBatchSize
	if end > len(snapshot.Recipients) {
		end = len(snapshot.Recipients)
	}
	result := &groupBroadcastResult{
		BroadcastID: snapshot.BroadcastID, GroupID: snapshot.GroupID,
		SnapshotDigest: snapshot.SnapshotDigest, RecipientCount: len(snapshot.Recipients),
		Offset: request.Offset, NextOffset: end, Complete: end == len(snapshot.Recipients),
		Recipients: make([]groupBroadcastRecipientResult, 0, end-request.Offset),
	}
	for _, recipient := range snapshot.Recipients[request.Offset:end] {
		child := groupBroadcastRecipientResult{EndpointID: recipient.EndpointID, NodeID: recipient.NodeID}
		operationID := groupBroadcastChildOperationID(snapshot.BroadcastID, recipient.EndpointID)
		var messageID string
		var err error
		if recipient.NodeID == sourceNode {
			messageID, err = sendLocal(recipient, operationID)
		} else {
			messageID, err = sendRemote(recipient, operationID)
		}
		if err != nil {
			child.State = "FAILED"
			child.FailureCode = "DELIVERY_REJECTED"
			if localSealedSendRetryable(err) {
				child.State = "UNKNOWN"
				child.FailureCode = "DELIVERY_OUTCOME_UNKNOWN"
			}
		} else {
			child.State = "ACCEPTED"
			child.MessageID = messageID
			expected, _, idErr := localSealedRPCIDs(operationID)
			if idErr != nil || messageID != expected {
				child.State = "UNKNOWN"
				child.MessageID = ""
				child.FailureCode = "DELIVERY_OUTCOME_UNKNOWN"
			}
		}
		result.Recipients = append(result.Recipients, child)
	}
	return result, nil
}

func (b *machineAgentJoinBridge) sendLocalGroupBroadcastChild(request groupBroadcastRequest,
	source, recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
	result, err := b.localGroupWithBroadcastFence(localGroupRequest{
		Version: localGroupProtocolVersion, Operation: "local_send",
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		NodeID: request.NodeID, Workspace: request.Workspace, SessionToken: request.SessionToken,
		EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID,
		GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
		OperationID: operationID, IdempotencyKey: operationID,
		Target: recipient.EndpointID, Body: request.Body,
	}, &groupBroadcastDeliveryFence{source: source, recipient: recipient})
	if err != nil {
		return "", err
	}
	expected, _, _ := localSealedRPCIDs(operationID)
	if result == nil || result.MessageID != expected || result.TargetEndpointID != recipient.EndpointID ||
		result.Delivery != "LOCAL_PERSISTED" || result.PayloadMode != "SEALED_V1" {
		return "", &localSealedSendError{message: "local broadcast child result is uncorrelated", retryable: true}
	}
	return result.MessageID, nil
}

func (b *machineAgentJoinBridge) sendRemoteGroupBroadcastChild(request groupBroadcastRequest,
	source, recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
	result, err := b.crossNodeGroupWithBroadcastFence(crossNodeGroupRequest{
		Version: crossNodeGroupProtocolVersion, Operation: "cross_node_group_send",
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		NodeID: request.NodeID, Workspace: request.Workspace, SessionToken: request.SessionToken,
		EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID,
		GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
		TargetEndpointID: recipient.EndpointID, OperationID: operationID,
		IdempotencyKey: operationID, Body: request.Body,
	}, &groupBroadcastDeliveryFence{source: source, recipient: recipient})
	if err != nil {
		return "", err
	}
	expected, _, _ := localSealedRPCIDs(operationID)
	if result == nil || result.MessageID != expected || result.TargetEndpointID != recipient.EndpointID ||
		result.Delivery != "RELAY_PERSISTED" || result.PayloadMode != "SEALED_V1" {
		return "", &localSealedSendError{message: "remote broadcast child result is uncorrelated", retryable: true}
	}
	return result.MessageID, nil
}
