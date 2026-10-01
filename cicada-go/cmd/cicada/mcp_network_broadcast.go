package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

var mcpNetworkBroadcastTools = map[string]struct{}{
	"cicada_network_broadcast_preview": {},
	"cicada_network_broadcast":         {},
	"cicada_network_broadcast_status":  {},
}

func isMCPNetworkBroadcastTool(name string) bool {
	_, ok := mcpNetworkBroadcastTools[name]
	return ok
}

type networkBroadcastSnapshotView struct {
	NetworkID      string `json:"network_id"`
	SnapshotDigest string `json:"snapshot_digest"`
	Recipients     []struct {
		EndpointID string `json:"endpoint_id"`
	} `json:"recipients"`
}

func networkBroadcastDeadline(raw string, now time.Time) (string, error) {
	deadline, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("Network Broadcast expiry must be RFC3339")
	}
	deadline = deadline.UTC()
	if !deadline.After(now) || deadline.After(now.Add(24*time.Hour)) {
		return "", errors.New("Network Broadcast expiry must be within the next 24 hours")
	}
	return deadline.Format(time.RFC3339Nano), nil
}

func validNetworkBroadcastSnapshotDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func networkBroadcastChildOperationID(parentID, endpointID string) string {
	digest := sha256.Sum256([]byte("cicada-network-broadcast-send-v1\x00" + parentID + "\x00" + endpointID))
	return "op_" + hex.EncodeToString(digest[:16])
}

func networkBroadcastIDForOperation(operationID string) (string, error) {
	if len(operationID) != 35 || !strings.HasPrefix(operationID, "op_") {
		return "", errors.New("Network Broadcast outbox identity is invalid")
	}
	id := networkBroadcastMessagePrefix + strings.TrimPrefix(operationID, "op_")
	if !validNetworkBroadcastID(id) {
		return "", errors.New("Network Broadcast outbox identity is invalid")
	}
	return id, nil
}

func canonicalNetworkBroadcastTargets(targets []string, publisherEndpoint string) (string, error) {
	if len(targets) == 0 || len(targets) > 64 {
		return "", errors.New("Network Broadcast requires 1–64 eligible recipients")
	}
	copyTargets := append([]string(nil), targets...)
	sort.Strings(copyTargets)
	for index, endpointID := range copyTargets {
		if !strings.HasPrefix(endpointID, "ep_") || !validNetworkRouteID(endpointID) ||
			endpointID == publisherEndpoint || (index > 0 && endpointID == copyTargets[index-1]) {
			return "", errors.New("Network Broadcast snapshot contains invalid recipients")
		}
	}
	return strings.Join(copyTargets, ","), nil
}

func networkBroadcastTargetsMatch(saved, current []string) bool {
	if len(saved) != len(current) {
		return false
	}
	for index := range saved {
		if saved[index] != current[index] {
			return false
		}
	}
	return true
}

func (m *mcpServer) networkBroadcastToolLocked(name string, arguments map[string]any,
	context harness.SessionContext, state networkCLIState) (any, error) {
	base := "/v2/fabric/networks/" + url.PathEscape(state.NetworkID) + "/broadcasts/"
	switch name {
	case "cicada_network_broadcast_preview":
		return m.networkDirectHTTP(state, http.MethodPost, base+"preview", map[string]any{})
	case "cicada_network_broadcast_status":
		id := stringArgument(arguments, "broadcast_id")
		if !validNetworkBroadcastID(id) {
			return nil, errors.New("broadcast_id is invalid")
		}
		return m.networkDirectHTTP(state, http.MethodGet, base+"get?broadcast_id="+url.QueryEscape(id), nil)
	case "cicada_network_broadcast":
		digest := stringArgument(arguments, "snapshot_digest")
		body := stringArgument(arguments, "body")
		if !validNetworkBroadcastSnapshotDigest(digest) || body == "" || len([]byte(body)) > 64*1024 {
			return nil, errors.New("Network Broadcast requires a preview digest and non-empty body under 64 KiB")
		}
		requestedRefs, err := parseGroupSpaceReferenceRequest(arguments["record_refs"])
		if err != nil {
			return nil, err
		}
		deadline, err := networkBroadcastDeadline(stringArgument(arguments, "expires_at"), time.Now().UTC())
		if err != nil {
			return nil, err
		}
		key, err := normalizeMCPOutboxKey(stringArgument(arguments, "idempotency_key"))
		if err != nil || key == "" {
			return nil, errors.New("Network Broadcast requires a stable idempotency_key")
		}
		outbox, scope, err := m.networkTaskOutbox(context, state)
		if err != nil {
			return nil, err
		}
		if prior, findErr := outbox.findByIdempotencyKey(scope, key); findErr != nil {
			return nil, findErr
		} else if prior != nil {
			var saved mcpOutboxInput
			if prior.Kind != "network_broadcast" || json.Unmarshal([]byte(prior.InputJSON), &saved) != nil ||
				saved.NetworkID != state.NetworkID || saved.SnapshotDigest != digest ||
				saved.ExpiresAt != deadline || !groupSpaceMessageIntentMatches(saved.Body, body, requestedRefs) {
				return nil, errMCPOutboxConflict
			}
			if prior.Status == mcpOutboxStatusSent || prior.Status == mcpOutboxStatusFailed {
				return mcpOutboxPublicResult(*prior), nil
			}
			return m.dispatchMCPNetworkOutbox(outbox, scope, *prior, context, state)
		}
		body, err = m.encodeSelectedGroupSpaceReferences(body, arguments["record_refs"])
		if err != nil {
			return nil, err
		}
		value, err := m.networkDirectHTTP(state, http.MethodPost, base+"preview", map[string]any{})
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, errors.New("Network Broadcast preview is invalid")
		}
		var snapshot networkBroadcastSnapshotView
		if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.NetworkID != state.NetworkID ||
			!validNetworkBroadcastSnapshotDigest(snapshot.SnapshotDigest) || snapshot.SnapshotDigest != digest {
			return nil, errors.New("Network Broadcast recipient snapshot changed; review a fresh preview")
		}
		targets := make([]string, 0, len(snapshot.Recipients))
		for _, recipient := range snapshot.Recipients {
			targets = append(targets, recipient.EndpointID)
		}
		canonicalTargets, err := canonicalNetworkBroadcastTargets(targets, state.EndpointID)
		if err != nil {
			return nil, err
		}
		input := mcpOutboxInput{NetworkID: state.NetworkID, SnapshotDigest: digest,
			Targets: canonicalTargets, Body: body, ExpiresAt: deadline}
		opID, err := newMCPOutboxID("op")
		if err != nil {
			return nil, err
		}
		op, _, err := outbox.prepareOperation(scope, "network_broadcast", key, input, opID)
		if err != nil {
			return nil, err
		}
		return m.dispatchMCPNetworkOutbox(outbox, scope, op, context, state)
	default:
		return nil, errors.New("unsupported Network Broadcast operation")
	}
}

func (m *mcpServer) dispatchNetworkBroadcastOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, op mcpOutboxOperation, context harness.SessionContext,
	state networkCLIState, input mcpOutboxInput) (any, error) {
	fail := func(err error) (any, error) {
		unknown, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusUnknown, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	targets := strings.Split(input.Targets, ",")
	canonical, err := canonicalNetworkBroadcastTargets(targets, state.EndpointID)
	if err != nil || canonical != input.Targets || !validNetworkBroadcastSnapshotDigest(input.SnapshotDigest) {
		failed, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed,
			errors.New("Network Broadcast immutable recipient snapshot is corrupt"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	base := "/v2/fabric/networks/" + url.PathEscape(state.NetworkID) + "/broadcasts/"
	previewValue, err := m.networkDirectHTTP(state, http.MethodPost, base+"preview", map[string]any{})
	if err != nil {
		return fail(err)
	}
	previewJSON, err := json.Marshal(previewValue)
	if err != nil {
		return fail(err)
	}
	var current networkBroadcastSnapshotView
	if err := json.Unmarshal(previewJSON, &current); err != nil || current.NetworkID != state.NetworkID ||
		current.SnapshotDigest != input.SnapshotDigest {
		failed, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed,
			errors.New("Network Broadcast recipient authority changed; queued routes remain unpublished and unclaimable"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	currentTargets := make([]string, 0, len(current.Recipients))
	for _, item := range current.Recipients {
		currentTargets = append(currentTargets, item.EndpointID)
	}
	sort.Strings(currentTargets)
	if !networkBroadcastTargetsMatch(targets, currentTargets) {
		failed, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed,
			errors.New("Network Broadcast recipient list changed; queued routes remain unpublished and unclaimable"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	broadcastID, err := networkBroadcastIDForOperation(op.OperationID)
	if err != nil {
		return fail(err)
	}
	recipients := make([]store.NetworkBroadcastPublishRecipient, 0, len(targets))
	for _, target := range targets {
		childOperationID := networkBroadcastChildOperationID(op.OperationID, target)
		sealed, err := marshalNetworkBroadcastSealedPayload(broadcastID, input.Body)
		if err != nil {
			failed, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed, err)
			if persistErr != nil {
				return nil, persistErr
			}
			return mcpOutboxPublicResult(failed), nil
		}
		keyDigest := sha256.Sum256([]byte("cicada-network-broadcast-send-v1\x00" + childOperationID))
		child, err := requestMachineAgentNetworkDirect(m.joinSocketPath(context), localNetworkDirectRequest{
			Version: localJoinProtocolVersion, Operation: "network_direct_send", NetworkID: state.NetworkID,
			EndpointID: state.EndpointID, SessionToken: state.SessionToken, Harness: context.Harness,
			NativeSessionID: context.NativeSessionID, Workspace: context.Workspace, NodeID: context.MachineID,
			OperationID: childOperationID, TargetEndpointID: target,
			CollaborationPurpose: e2ee.NetworkCollaborationPurposeBroadcast, BroadcastID: broadcastID,
			IdempotencyKey: "nbroadcast:" + hex.EncodeToString(keyDigest[:16]), Body: sealed,
		})
		if err != nil {
			return fail(err)
		}
		wantMessageID := broadcastID + ":reader:" + strings.TrimPrefix(childOperationID, "op_")
		if child == nil || child.NetworkID != state.NetworkID || child.MessageID != wantMessageID ||
			child.TargetEndpointID != target || child.State != "RELAY_PERSISTED" {
			return fail(errors.New("local Node returned an invalid sealed Network Broadcast receipt"))
		}
		recipients = append(recipients, store.NetworkBroadcastPublishRecipient{
			EndpointID: target, MessageID: child.MessageID,
		})
	}
	published, err := m.networkDirectHTTP(state, http.MethodPost, base+"publish", store.NetworkBroadcastPublishInput{
		BroadcastID: broadcastID, SnapshotDigest: input.SnapshotDigest,
		ExpiresAt: input.ExpiresAt, Recipients: recipients,
	})
	if err != nil {
		return fail(err)
	}
	encoded, err := mcpOutboxResultJSON(published, state.SessionToken)
	if err != nil {
		return fail(err)
	}
	sent, err := outbox.markResult(scope, op.OperationID, mcpOutboxStatusSent, "", encoded)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(sent), nil
}
