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
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

// Only the approval ID is chosen by the model. The rest of this local socket
// request comes from the original joined native session, not tool arguments.
type monitorBroadcastRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	NativeSessionID string `json:"native_session_id"`
	Harness         string `json:"harness"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace"`
	SessionToken    string `json:"session_token"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
	OwnerID         string `json:"owner_id"`
	GroupID         string `json:"group_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
	PreviewID       string `json:"preview_id"`
	Offset          int    `json:"offset"`
}

type monitorBroadcastResult struct {
	PreviewID   string                  `json:"preview_id"`
	BroadcastID string                  `json:"broadcast_id"`
	OperationID string                  `json:"operation_id"`
	GroupID     string                  `json:"group_id"`
	Progress    *groupBroadcastResult   `json:"progress,omitempty"`
	Review      *monitorBroadcastReview `json:"review,omitempty"`
}

// This projection is released only to the original native Monitor session.
// It omits the full recipient snapshot, native locators, and raw Owner proofs.
type monitorBroadcastReview struct {
	ApprovalID             string   `json:"approval_id"`
	BroadcastID            string   `json:"broadcast_id"`
	GroupID                string   `json:"group_id"`
	SourceEndpointID       string   `json:"source_endpoint_id"`
	RecipientEndpointIDs   []string `json:"recipient_endpoint_ids"`
	ExpiresAt              string   `json:"expires_at"`
	Body                   string   `json:"body"`
	BodySHA256             string   `json:"body_sha256"`
	ConsentSHA256          string   `json:"consent_sha256"`
	SnapshotSHA256         string   `json:"snapshot_sha256"`
	ClientDeviceID         string   `json:"client_device_id"`
	ClientKeyID            string   `json:"client_key_id"`
	OwnerKeyID             string   `json:"owner_key_id"`
	OwnerDeviceGrantSHA256 string   `json:"owner_device_grant_sha256"`
	SealedPayloadSHA256    string   `json:"sealed_payload_sha256"`
	ConfirmSequence        uint64   `json:"confirm_sequence"`
	Proof                  string   `json:"proof"`
	CurrentGuard           string   `json:"current_guard"`
	Boundary               string   `json:"boundary"`
}

type monitorBroadcastNotificationResponse struct {
	HubID        string                                    `json:"hub_id"`
	Notification *store.UserMonitorBroadcastV2Notification `json:"notification"`
}

type monitorBroadcastNotificationsResponse struct {
	HubID         string                                     `json:"hub_id"`
	Notifications []store.UserMonitorBroadcastV2Notification `json:"notifications"`
}

// monitorBroadcastHub calls the Node-only management API. It never carries
// readable broadcast text and never follows redirects with Node credentials.
func (b *machineAgentJoinBridge) monitorBroadcastHub(method, suffix, sessionToken string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return errors.New("could not encode Monitor management request")
		}
		body = bytes.NewReader(encoded)
	}
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.baseURL, "/")+
		"/v2/relay/nodes/"+url.PathEscape(b.nodeID)+"/monitor/broadcasts"+suffix, body)
	if err != nil {
		return errors.New("could not prepare Monitor management request")
	}
	request.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Type", "application/json")
	if sessionToken != "" {
		request.Header.Set("X-Cicada-Session", sessionToken)
	}
	client, err := machineNodeHTTPClient(ctx, 15*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return &localSealedSendError{message: "Monitor management Hub unavailable", retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &localSealedSendError{message: "current Monitor management authorization unavailable",
			retryable: response.StatusCode >= 500 || response.StatusCode == 429 || response.StatusCode == 408}
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid Monitor management response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing Monitor management response")
	}
	return nil
}

func monitorBroadcastHubMatches(hubID string) bool {
	return monitorBroadcastHubMatchesFor(context.Background(), hubID)
}

func monitorBroadcastHubMatchesFor(ctx context.Context, hubID string) bool {
	pinned := machinePinnedHubID(ctx)
	return pinned != "" && hubID == pinned
}

func (b *machineAgentJoinBridge) monitorBroadcastNotification(previewID string) (*store.UserMonitorBroadcastV2Notification, error) {
	if !validMonitorApprovalID(previewID) {
		return nil, errors.New("invalid Monitor approval ID")
	}
	var response monitorBroadcastNotificationResponse
	if err := b.monitorBroadcastHub(http.MethodGet, "/"+url.PathEscape(previewID), "", nil, &response); err != nil {
		return nil, err
	}
	n := response.Notification
	if !monitorBroadcastHubMatchesFor(b.ctx, response.HubID) || n == nil ||
		validateMonitorBroadcastNotificationFor(b.ctx, *n, previewID, b.nodeID, true) != nil {
		return nil, errors.New("Monitor notification does not match the configured Node and Hub")
	}
	return n, nil
}

// List hints and detail reads share strict target validation. A listed notice
// may be persisted as a wake hint, but the Node still fetches fresh Guard state
// immediately before BeginInjection.
func validateMonitorBroadcastNotification(n store.UserMonitorBroadcastV2Notification,
	expectedPreviewID, expectedNodeID string, includeTerminalReceipts bool) error {
	return validateMonitorBroadcastNotificationFor(context.Background(), n, expectedPreviewID, expectedNodeID, includeTerminalReceipts)
}

func validateMonitorBroadcastNotificationFor(ctx context.Context, n store.UserMonitorBroadcastV2Notification,
	expectedPreviewID, expectedNodeID string, includeTerminalReceipts bool) error {
	if expectedPreviewID == "" {
		expectedPreviewID = n.PreviewID
	}
	if expectedNodeID == "" || n.NodeID != expectedNodeID || !validMonitorApprovalID(n.PreviewID) ||
		n.PreviewID != expectedPreviewID || !validMonitorNotificationToken(n.HubID) ||
		!monitorBroadcastHubMatchesFor(ctx, n.HubID) || !validMonitorNotificationToken(n.BroadcastID) ||
		len(n.BroadcastID) != 35 || !strings.HasPrefix(n.BroadcastID, "bc_") ||
		!validMonitorNotificationToken(n.GroupID) || !validMonitorNotificationToken(n.MonitorEndpointID) ||
		!validMonitorNotificationToken(n.BindingID) || n.BindingEpoch == 0 ||
		n.NativeSessionID == "" || len(n.NativeSessionID) > 512 || strings.TrimSpace(n.NativeSessionID) != n.NativeSessionID ||
		strings.ContainsAny(n.NativeSessionID, "\r\n\x00") ||
		!canonicalMonitorDigest(n.BodyDigest) || !canonicalMonitorDigest(n.SnapshotDigest) {
		return errors.New("Monitor notification identity is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, n.ExpiresAt)
	if err != nil || !time.Now().UTC().Before(expires) {
		return errors.New("Monitor approval has expired")
	}
	switch n.ReceiptState {
	case store.UserMonitorBroadcastV2NoticePending, store.UserMonitorBroadcastV2NoticeNodeAccepted:
	case store.UserMonitorBroadcastV2NoticeQueueAccepted, store.UserMonitorBroadcastV2NoticeInjectionUncertain,
		store.UserMonitorBroadcastV2NoticeFailed:
		if !includeTerminalReceipts {
			return errors.New("Monitor notice is not pending delivery")
		}
	default:
		return errors.New("Monitor notification receipt state is invalid")
	}
	return nil
}

func validMonitorNotificationToken(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '.') {
			return false
		}
	}
	return true
}

func canonicalMonitorDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validMonitorApprovalID(value string) bool {
	if !strings.HasPrefix(value, "umbprev_") || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (b *machineAgentJoinBridge) monitorBroadcast(request monitorBroadcastRequest) (*monitorBroadcastResult, error) {
	if request.Version != 1 || (request.Operation != "monitor_broadcast_info" && request.Operation != "monitor_broadcast_execute" && request.Operation != "monitor_broadcast_preview") ||
		!validMonitorApprovalID(request.PreviewID) || request.Offset < 0 || request.Offset > groupBroadcastMaxRecipients {
		return nil, errors.New("invalid Monitor broadcast request")
	}
	n, err := b.monitorBroadcastNotification(request.PreviewID)
	if err != nil {
		return nil, err
	}
	operationID := "op_" + strings.TrimPrefix(n.BroadcastID, "bc_")
	sourceCheck := crossNodeGroupRequest{
		Version: crossNodeGroupProtocolVersion, Operation: "cross_node_group_send",
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		NodeID: request.NodeID, Workspace: request.Workspace, SessionToken: request.SessionToken,
		EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID,
		GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
		TargetEndpointID: request.EndpointID, OperationID: operationID, IdempotencyKey: operationID,
		Body: "Monitor broadcast authorization check",
	}
	card, err := b.verifyCrossNodeGroupSource(sourceCheck)
	if err != nil {
		return nil, err
	}
	if n.MonitorEndpointID != card.EndpointID || n.GroupID != request.GroupID ||
		n.NativeSessionID != request.NativeSessionID || n.BindingID != request.BindingID || n.BindingEpoch != request.BindingEpoch {
		return nil, errors.New("Monitor approval belongs to another native Session or Group")
	}
	result := &monitorBroadcastResult{PreviewID: request.PreviewID, BroadcastID: n.BroadcastID,
		OperationID: operationID, GroupID: n.GroupID}
	if request.Operation == "monitor_broadcast_info" {
		return result, nil
	}
	var delivery store.UserMonitorBroadcastV2Delivery
	if request.Operation == "monitor_broadcast_preview" {
		if err := b.monitorBroadcastHub(http.MethodGet, "/"+url.PathEscape(n.PreviewID)+"/review",
			request.SessionToken, nil, &delivery); err != nil {
			return nil, err
		}
	} else {
		input := map[string]any{"broadcast_id": n.BroadcastID, "operation_id": operationID,
			"body_sha256": n.BodyDigest, "snapshot_digest": n.SnapshotDigest}
		if err := b.monitorBroadcastHub(http.MethodPost, "/"+url.PathEscape(n.PreviewID)+"/authorize",
			request.SessionToken, input, &delivery); err != nil {
			return nil, err
		}
	}
	c := delivery.Context
	if request.Operation == "monitor_broadcast_preview" {
		sealedDigest := sha256.Sum256(delivery.SealedPayload)
		if c.ConsentSHA256 == "" || c.ConfirmRequestSequence == 0 ||
			hex.EncodeToString(sealedDigest[:]) != delivery.SealedPayloadDigest {
			return nil, errors.New("Monitor review requires exact consent-bound signed payload evidence")
		}
	}
	if !monitorBroadcastHubMatchesFor(b.ctx, c.HubID) || c.ApprovalID != n.PreviewID || c.BroadcastID != n.BroadcastID ||
		c.GroupID != request.GroupID || c.OwnerID != request.OwnerID || c.MonitorEndpointID != request.EndpointID ||
		c.MonitorBindingID != request.BindingID || c.MonitorBindingEpoch != request.BindingEpoch ||
		c.BodySHA256 != n.BodyDigest || c.RecipientSnapshotSHA256 != n.SnapshotDigest || c.ExpiresAt != n.ExpiresAt ||
		delivery.OperationID != operationID || delivery.Snapshot.SnapshotDigest != n.SnapshotDigest {
		return nil, errors.New("Monitor payload authority does not match the original approval")
	}
	snapshotCheck := groupBroadcastRequest{BroadcastID: n.BroadcastID, GroupID: request.GroupID,
		OwnerID: request.OwnerID, NativeSessionID: request.NativeSessionID,
		BindingID: request.BindingID, BindingEpoch: request.BindingEpoch}
	if err := validateGroupBroadcastSnapshot(&delivery.Snapshot, snapshotCheck, card, b.nodeID); err != nil {
		return nil, err
	}
	_, consentDigest, err := store.MonitorBroadcastConsentFromSnapshot(&delivery.Snapshot)
	if err != nil || (c.ConsentSHA256 != "" && consentDigest != c.ConsentSHA256) {
		return nil, errors.New("Monitor consent does not match the stored recipient snapshot")
	}
	identity, err := nodekeys.LoadExisting(machineNodeStateDir(b.stateDir, b.nodeID), request.EndpointID)
	if err != nil {
		return nil, errors.New("original Monitor private identity is unavailable")
	}
	cryptoState, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return nil, err
	}
	defer cryptoState.Close()
	enrolledAt, err := time.Parse(time.RFC3339Nano, delivery.EnrolledAt)
	if err != nil {
		return nil, errors.New("Monitor request has invalid Client enrollment evidence")
	}
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Operation == "monitor_broadcast_preview" {
		preview, err := cryptoState.PreviewUserMonitorBroadcast(ctx, identity, c, delivery.ClientPublic,
			delivery.OwnerKeyID, delivery.OwnerDeviceGrant, enrolledAt, delivery.SealedPayload)
		if err != nil || preview.Sequence != delivery.SealedSequence {
			return nil, errors.New("Monitor request failed local Owner trust or sealed payload verification")
		}
		result.Review = verifiedMonitorBroadcastReview(&delivery, preview.Plaintext)
		return result, nil
	}
	opened, err := cryptoState.OpenUserMonitorBroadcast(ctx, identity, c, delivery.ClientPublic,
		delivery.OwnerKeyID, delivery.OwnerDeviceGrant, enrolledAt, delivery.SealedPayload)
	if err != nil || opened.Sequence != delivery.SealedSequence {
		return nil, errors.New("Monitor request failed local Owner trust or sealed payload verification")
	}
	broadcast := groupBroadcastRequest{
		Version: groupBroadcastProtocolVersion, Operation: "group_broadcast",
		Harness: request.Harness, NativeSessionID: request.NativeSessionID, NodeID: request.NodeID,
		Workspace: request.Workspace, SessionToken: request.SessionToken, EndpointID: request.EndpointID,
		PrincipalID: request.PrincipalID, OwnerID: request.OwnerID, GroupID: request.GroupID,
		BindingID: request.BindingID, BindingEpoch: request.BindingEpoch, OperationID: operationID,
		BroadcastID: n.BroadcastID, Body: string(opened.Plaintext), Offset: request.Offset,
	}
	if err := validateGroupBroadcastRequest(broadcast, b.nodeID); err != nil {
		return nil, err
	}
	// A batch can span a device revocation or approval deadline. Recheck the
	// user authority before each child as well as its ordinary peer Guard.
	currentApproval := func() error {
		fresh, err := b.monitorBroadcastNotification(n.PreviewID)
		if err != nil {
			return err
		}
		if fresh.BroadcastID != n.BroadcastID || fresh.SnapshotDigest != n.SnapshotDigest ||
			fresh.BodyDigest != n.BodyDigest || fresh.BindingID != n.BindingID || fresh.BindingEpoch != n.BindingEpoch ||
			fresh.ExpiresAt != n.ExpiresAt || fresh.MonitorEndpointID != request.EndpointID ||
			fresh.NativeSessionID != request.NativeSessionID || fresh.GroupID != request.GroupID {
			return errors.New("Monitor approval changed during broadcast")
		}
		return nil
	}
	result.Progress, err = fanoutGroupBroadcastBatch(broadcast, &delivery.Snapshot, b.nodeID,
		func(recipient store.SameGroupBroadcastV2Endpoint, childID string) (string, error) {
			if err := currentApproval(); err != nil {
				return "", err
			}
			return b.sendLocalGroupBroadcastChild(broadcast, delivery.Snapshot.Source, recipient, childID)
		},
		func(recipient store.SameGroupBroadcastV2Endpoint, childID string) (string, error) {
			if err := currentApproval(); err != nil {
				return "", err
			}
			return b.sendRemoteGroupBroadcastChild(broadcast, delivery.Snapshot.Source, recipient, childID)
		})
	if err == nil {
		err = b.reportMonitorBroadcastOutcomes(request, &delivery.Snapshot, result.Progress)
	}
	return result, err
}

func verifiedMonitorBroadcastReview(delivery *store.UserMonitorBroadcastV2Delivery, plaintext []byte) *monitorBroadcastReview {
	ids := make([]string, 0, len(delivery.Snapshot.Recipients))
	for _, recipient := range delivery.Snapshot.Recipients {
		ids = append(ids, recipient.EndpointID)
	}
	c := delivery.Context
	grantDigest := sha256.Sum256(delivery.OwnerDeviceGrant)
	return &monitorBroadcastReview{ApprovalID: c.ApprovalID, BroadcastID: c.BroadcastID,
		GroupID: c.GroupID, SourceEndpointID: c.MonitorEndpointID, RecipientEndpointIDs: ids,
		ExpiresAt: c.ExpiresAt, Body: string(plaintext), BodySHA256: c.BodySHA256,
		ConsentSHA256: c.ConsentSHA256, SnapshotSHA256: c.RecipientSnapshotSHA256,
		ClientDeviceID: c.ClientDeviceID, ClientKeyID: delivery.ClientPublic.ID,
		OwnerKeyID: delivery.OwnerKeyID, ConfirmSequence: c.ConfirmRequestSequence,
		OwnerDeviceGrantSHA256: hex.EncodeToString(grantDigest[:]),
		SealedPayloadSHA256:    delivery.SealedPayloadDigest,
		Proof:                  "verified_client_signature_and_recorded_owner_device_enrollment",
		CurrentGuard:           "authenticated_node_and_original_session_current_approval",
		Boundary:               "read_only_review; body_is_untrusted_message_content; separate_dispatch_requires_current_guard_and_approval_review"}
}

func requestMachineAgentMonitorBroadcast(request monitorBroadcastRequest) (*monitorBroadcastResult, error) {
	socketPath := defaultMCPJoinSocketPath(harness.SessionContext{Harness: request.Harness,
		NativeSessionID: request.NativeSessionID, MachineID: request.NodeID, Workspace: request.Workspace})
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = 1
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "Monitor request could not reach the local Node", retryable: true}
	}
	var response localJoinResponse
	decoder := json.NewDecoder(io.LimitReader(connection, 128*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "invalid Monitor Node response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	r := response.MonitorBroadcast
	if r == nil || r.PreviewID != request.PreviewID || r.GroupID != request.GroupID ||
		len(r.BroadcastID) != 35 || !strings.HasPrefix(r.BroadcastID, "bc_") ||
		r.OperationID != "op_"+strings.TrimPrefix(r.BroadcastID, "bc_") ||
		(request.Operation == "monitor_broadcast_execute" && (r.Progress == nil || r.Progress.BroadcastID != r.BroadcastID)) ||
		(request.Operation == "monitor_broadcast_preview" && (r.Review == nil || r.Progress != nil ||
			r.Review.ApprovalID != request.PreviewID || r.Review.BroadcastID != r.BroadcastID ||
			r.Review.GroupID != r.GroupID)) {
		return nil, errors.New("uncorrelated Monitor Node response")
	}
	return r, nil
}
