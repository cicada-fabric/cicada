package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
)

var mcpNetworkTaskTools = map[string]struct{}{
	"cicada_network_task_offer": {}, "cicada_network_task_list": {}, "cicada_network_task_get": {},
	"cicada_network_task_claim": {}, "cicada_network_task_result": {}, "cicada_network_task_accept": {},
}

func isMCPNetworkTaskTool(name string) bool {
	_, ok := mcpNetworkTaskTools[name]
	return ok
}

func rawStringArgument(arguments map[string]any, name string) string {
	value, _ := arguments[name].(string)
	return value
}

type networkTaskOfferView struct {
	TaskID              string `json:"task_id"`
	NetworkID           string `json:"network_id"`
	PublisherEndpointID string `json:"publisher_endpoint_id"`
	Status              string `json:"status"`
	Revision            int64  `json:"revision"`
	OwnerEndpointID     string `json:"owner_endpoint_id"`
	OwnerEpoch          int64  `json:"owner_epoch"`
	LeaseExpiresAt      string `json:"lease_expires_at"`
	ExpiresAt           string `json:"expires_at"`
}

func (m *mcpServer) networkTaskToolLocked(name string, arguments map[string]any,
	context harness.SessionContext, state networkCLIState) (any, error) {
	base := "/v2/fabric/networks/" + url.PathEscape(state.NetworkID) + "/tasks/"
	taskID := stringArgument(arguments, "task_id")
	switch name {
	case "cicada_network_task_offer":
		return m.prepareNetworkTaskOffer(arguments, context, state)
	case "cicada_network_task_list":
		limit := int64(16)
		if raw, present := arguments["limit"]; present {
			var valid bool
			limit, valid = strictMCPInteger(raw)
			if !valid {
				return nil, errors.New("Network Task list limit must be an integer")
			}
		}
		if limit < 1 || limit > 100 {
			return nil, errors.New("Network Task list limit is invalid")
		}
		return m.networkDirectHTTP(state, http.MethodGet, base+"list?limit="+fmt.Sprint(limit), nil)
	case "cicada_network_task_get":
		if !validNetworkTaskID(taskID) {
			return nil, errors.New("Network Task ID is invalid")
		}
		return m.networkDirectHTTP(state, http.MethodGet, base+"get?task_id="+url.QueryEscape(taskID), nil)
	case "cicada_network_task_claim":
		revision, validRevision := strictMCPInteger(arguments["expected_revision"])
		leaseSeconds, validLease := strictMCPInteger(arguments["lease_seconds"])
		if !validNetworkTaskID(taskID) || !validRevision || revision <= 0 ||
			!validLease || leaseSeconds < 1 || leaseSeconds > 3600 {
			return nil, errors.New("Network Task claim parameters are invalid")
		}
		key, err := normalizeMCPOutboxKey(stringArgument(arguments, "idempotency_key"))
		if err != nil || key == "" {
			return nil, errors.New("Network Task claim requires a stable idempotency_key")
		}
		return m.networkDirectHTTP(state, http.MethodPost, base+"claim", map[string]any{
			"task_id": taskID, "expected_revision": revision,
			"idempotency_key": key, "lease_seconds": leaseSeconds,
		})
	case "cicada_network_task_result":
		return m.prepareNetworkTaskResult(taskID, rawStringArgument(arguments, "body"),
			stringArgument(arguments, "idempotency_key"), arguments["record_refs"], context, state)
	case "cicada_network_task_accept":
		revision, validRevision := strictMCPInteger(arguments["expected_revision"])
		if !validNetworkTaskID(taskID) || stringArgument(arguments, "result_id") == "" ||
			!validRevision || revision <= 0 {
			return nil, errors.New("Network Task acceptance parameters are invalid")
		}
		return m.networkDirectHTTP(state, http.MethodPost, base+"accept", map[string]any{
			"task_id": taskID, "result_id": stringArgument(arguments, "result_id"),
			"expected_revision": revision,
		})
	default:
		return nil, errors.New("unsupported Network Task operation")
	}
}

func (m *mcpServer) prepareNetworkTaskOffer(arguments map[string]any, context harness.SessionContext,
	state networkCLIState) (any, error) {
	targets := stringSliceArgument(arguments, "targets")
	rawCount := 0
	switch value := arguments["targets"].(type) {
	case []any:
		rawCount = len(value)
	case []string:
		rawCount = len(value)
	}
	body := rawStringArgument(arguments, "body")
	expiresAt, err := canonicalNetworkTaskDeadline(stringArgument(arguments, "expires_at"), time.Now().UTC())
	if err != nil || len(targets) == 0 || len(targets) > 16 || len(targets) != rawCount || body == "" || len([]byte(body)) > 60*1024 {
		return nil, errors.New("Network Task offer requires 1–16 exact Endpoints, a bounded body and a deadline within 24 hours")
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if !strings.HasPrefix(target, "ep_") || !validNetworkRouteID(target) || target == state.EndpointID {
			return nil, errors.New("Network Task recipients must be exact other Endpoint IDs")
		}
		if _, exists := seen[target]; exists {
			return nil, errors.New("Network Task recipient Endpoint IDs must be unique")
		}
		seen[target] = struct{}{}
	}
	sort.Strings(targets)
	key, err := normalizeMCPOutboxKey(stringArgument(arguments, "idempotency_key"))
	if err != nil || key == "" {
		return nil, errors.New("Network Task offer requires a stable idempotency_key")
	}
	outbox, scope, err := m.networkTaskOutbox(context, state)
	if err != nil {
		return nil, err
	}
	requestedRefs, err := parseGroupSpaceReferenceRequest(arguments["record_refs"])
	if err != nil {
		return nil, err
	}
	if prior, findErr := outbox.findByIdempotencyKey(scope, key); findErr != nil {
		return nil, findErr
	} else if prior != nil {
		var saved mcpOutboxInput
		if prior.Kind != "network_task_offer" || json.Unmarshal([]byte(prior.InputJSON), &saved) != nil ||
			saved.NetworkID != state.NetworkID || saved.Targets != strings.Join(targets, ",") ||
			saved.ExpiresAt != expiresAt || !groupSpaceMessageIntentMatches(saved.Body, body, requestedRefs) {
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
	if _, err := marshalNetworkTaskSealedPayload("offer", "ntask_00000000000000000000000000000000", 0, body); err != nil {
		return nil, err
	}
	input := mcpOutboxInput{NetworkID: state.NetworkID, Targets: strings.Join(targets, ","), Body: body, ExpiresAt: expiresAt}
	op, err := m.prepareNetworkTaskOperation(outbox, scope, "network_task_offer", key, input, true)
	if err != nil {
		return nil, err
	}
	if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPNetworkOutbox(outbox, scope, op, context, state)
}

func (m *mcpServer) prepareNetworkTaskResult(taskID, body, requestedKey string, rawRefs any,
	context harness.SessionContext, state networkCLIState) (any, error) {
	if !validNetworkTaskID(taskID) || body == "" || len([]byte(body)) > 60*1024 {
		return nil, errors.New("Network Task result ID or body is invalid")
	}
	key, err := normalizeMCPOutboxKey(requestedKey)
	if err != nil || key == "" {
		return nil, errors.New("Network Task result requires a stable idempotency_key")
	}
	outbox, scope, err := m.networkTaskOutbox(context, state)
	if err != nil {
		return nil, err
	}
	requestedRefs, err := parseGroupSpaceReferenceRequest(rawRefs)
	if err != nil {
		return nil, err
	}
	if prior, err := outbox.findByIdempotencyKey(scope, key); err != nil {
		return nil, err
	} else if prior != nil {
		if prior.Kind != "network_task_result" {
			return nil, errMCPOutboxConflict
		}
		var saved mcpOutboxInput
		if json.Unmarshal([]byte(prior.InputJSON), &saved) != nil || saved.NetworkID != state.NetworkID ||
			saved.TaskID != taskID || !groupSpaceMessageIntentMatches(saved.Body, body, requestedRefs) {
			return nil, errMCPOutboxConflict
		}
		if prior.Status == mcpOutboxStatusSent || prior.Status == mcpOutboxStatusFailed {
			return mcpOutboxPublicResult(*prior), nil
		}
		return m.dispatchMCPNetworkOutbox(outbox, scope, *prior, context, state)
	}
	body, err = m.encodeSelectedGroupSpaceReferences(body, rawRefs)
	if err != nil {
		return nil, err
	}
	if _, err := marshalNetworkTaskSealedPayload("result", taskID, 1, body); err != nil {
		return nil, err
	}
	view, err := m.getNetworkTaskView(state, taskID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, view.ExpiresAt)
	lease, leaseErr := time.Parse(time.RFC3339Nano, view.LeaseExpiresAt)
	if view.TaskID != taskID || view.NetworkID != state.NetworkID || view.PublisherEndpointID == "" ||
		view.Status != "CLAIMED" || view.OwnerEndpointID != state.EndpointID || view.OwnerEpoch <= 0 || view.Revision <= 0 ||
		deadlineErr != nil || !deadline.After(now) || leaseErr != nil || !lease.After(now) {
		return nil, errors.New("Network Task is not actively claimed by this Endpoint")
	}
	input := mcpOutboxInput{NetworkID: state.NetworkID, TaskID: taskID, Target: view.PublisherEndpointID,
		OwnerEpoch: view.OwnerEpoch, ExpectedRevision: view.Revision, Body: body}
	op, err := m.prepareNetworkTaskOperation(outbox, scope, "network_task_result", key, input, false)
	if err != nil {
		return nil, err
	}
	if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPNetworkOutbox(outbox, scope, op, context, state)
}

func (m *mcpServer) networkTaskOutbox(context harness.SessionContext, state networkCLIState) (*mcpOutboxStore, mcpOutboxScope, error) {
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, mcpOutboxScope{}, err
	}
	scope, err := m.networkDirectOutboxScope(context, state)
	if err != nil {
		return nil, mcpOutboxScope{}, err
	}
	return outbox, scope, nil
}

func (m *mcpServer) prepareNetworkTaskOperation(outbox *mcpOutboxStore, scope mcpOutboxScope,
	kind, key string, input mcpOutboxInput, deriveTaskID bool) (mcpOutboxOperation, error) {
	if prior, err := outbox.findByIdempotencyKey(scope, key); err != nil {
		return mcpOutboxOperation{}, err
	} else if prior != nil {
		var saved mcpOutboxInput
		if prior.Kind != kind || json.Unmarshal([]byte(prior.InputJSON), &saved) != nil ||
			saved.NetworkID != input.NetworkID || saved.Target != input.Target || saved.Body != input.Body ||
			saved.ExpiresAt != input.ExpiresAt || saved.OwnerEpoch != input.OwnerEpoch ||
			saved.ExpectedRevision != input.ExpectedRevision || saved.Targets != input.Targets ||
			input.TaskID != "" && saved.TaskID != input.TaskID || deriveTaskID && !validNetworkTaskID(saved.TaskID) {
			return mcpOutboxOperation{}, errMCPOutboxConflict
		}
		return *prior, nil
	}
	opID, err := newMCPOutboxID("op")
	if err != nil {
		return mcpOutboxOperation{}, err
	}
	if deriveTaskID {
		input.TaskID = "ntask_" + strings.TrimPrefix(opID, "op_")
	}
	op, _, err := outbox.prepareOperation(scope, kind, key, input, opID)
	if err != nil {
		// Independent MCP processes can race between lookup and insert. A
		// SQLite busy/unique-key winner is resolved by reading the committed
		// operation, then adopting its stable TaskID only for identical intent.
		for attempt := 0; attempt < 20; attempt++ {
			prior, findErr := outbox.findByIdempotencyKey(scope, key)
			if findErr == nil && prior != nil {
				var saved mcpOutboxInput
				if prior.Kind != kind || json.Unmarshal([]byte(prior.InputJSON), &saved) != nil ||
					!networkTaskInputMatches(saved, input, deriveTaskID) {
					return mcpOutboxOperation{}, errMCPOutboxConflict
				}
				return *prior, nil
			}
			if findErr != nil && !isMCPOutboxSQLiteBusy(findErr) {
				return mcpOutboxOperation{}, err
			}
			if attempt == 19 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		return mcpOutboxOperation{}, err
	}
	return op, nil
}

func networkTaskInputMatches(saved, wanted mcpOutboxInput, derivedTaskID bool) bool {
	taskMatches := saved.TaskID == wanted.TaskID
	if derivedTaskID {
		taskMatches = validNetworkTaskID(saved.TaskID)
	}
	return taskMatches && saved.NetworkID == wanted.NetworkID && saved.Target == wanted.Target &&
		saved.Body == wanted.Body && saved.ExpiresAt == wanted.ExpiresAt &&
		saved.OwnerEpoch == wanted.OwnerEpoch && saved.ExpectedRevision == wanted.ExpectedRevision &&
		saved.Targets == wanted.Targets
}

func isMCPOutboxSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "database is busy")
}

func canonicalNetworkTaskDeadline(raw string, now time.Time) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid Network Task deadline")
	}
	parsed = parsed.UTC()
	if !parsed.After(now) || parsed.After(now.Add(24*time.Hour)) {
		return "", errors.New("Network Task deadline must be within the next 24 hours")
	}
	return parsed.Format(time.RFC3339Nano), nil
}

func networkTaskChildOperationID(parentID, target string) string {
	digest := sha256.Sum256([]byte("cicada-network-task-offer-v1\x00" + parentID + "\x00" + target))
	return "op_" + hex.EncodeToString(digest[:16])
}

func (m *mcpServer) getNetworkTaskView(state networkCLIState, taskID string) (networkTaskOfferView, error) {
	path := "/v2/fabric/networks/" + url.PathEscape(state.NetworkID) + "/tasks/get?task_id=" + url.QueryEscape(taskID)
	value, err := m.networkDirectHTTP(state, http.MethodGet, path, nil)
	if err != nil {
		return networkTaskOfferView{}, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return networkTaskOfferView{}, errors.New("invalid Network Task metadata")
	}
	var view networkTaskOfferView
	if err := json.Unmarshal(encoded, &view); err != nil {
		return networkTaskOfferView{}, errors.New("invalid Network Task metadata")
	}
	return view, nil
}

func (m *mcpServer) dispatchNetworkTaskOutbox(outbox *mcpOutboxStore, scope mcpOutboxScope,
	op mcpOutboxOperation, context harness.SessionContext, state networkCLIState, input mcpOutboxInput) (any, error) {
	fail := func(err error) (any, error) {
		unknown, persistErr := outbox.markError(scope, op.OperationID, mcpOutboxStatusUnknown, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	var result any
	switch op.Kind {
	case "network_task_offer":
		targets := strings.Split(input.Targets, ",")
		if len(targets) == 0 || len(targets) > 16 || targets[0] == "" {
			failed, err := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed, errors.New("Network Task offer target list is corrupt"))
			if err != nil {
				return nil, err
			}
			return mcpOutboxPublicResult(failed), nil
		}
		messageIDs := make([]string, 0, len(targets))
		for _, target := range targets {
			childID := networkTaskChildOperationID(op.OperationID, target)
			sealed, err := marshalNetworkTaskSealedPayload("offer", input.TaskID, 0, input.Body)
			if err != nil {
				return nil, err
			}
			keyDigest := sha256.Sum256([]byte("cicada-network-task-send-v1\x00" + childID))
			child, err := requestMachineAgentNetworkDirect(m.joinSocketPath(context), localNetworkDirectRequest{
				Version: localJoinProtocolVersion, Operation: "network_direct_send", NetworkID: state.NetworkID,
				EndpointID: state.EndpointID, SessionToken: state.SessionToken, Harness: context.Harness,
				NativeSessionID: context.NativeSessionID, Workspace: context.Workspace, NodeID: context.MachineID,
				OperationID: childID, TaskID: input.TaskID, TargetEndpointID: target,
				IdempotencyKey: "ntask:" + hex.EncodeToString(keyDigest[:16]), Body: sealed,
			})
			if err != nil {
				return fail(err)
			}
			want := input.TaskID + ":offer:" + strings.TrimPrefix(childID, "op_")
			if child == nil || child.NetworkID != state.NetworkID || child.MessageID != want || child.TargetEndpointID != target || child.State != "RELAY_PERSISTED" {
				return fail(errors.New("local Node returned an invalid sealed Network Task offer receipt"))
			}
			messageIDs = append(messageIDs, child.MessageID)
		}
		value, err := m.networkDirectHTTP(state, http.MethodPost,
			"/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/tasks/publish",
			map[string]any{"task_id": input.TaskID, "expires_at": input.ExpiresAt, "offer_message_ids": messageIDs})
		if err != nil {
			return fail(err)
		}
		result = value
	case "network_task_result":
		sealed, err := marshalNetworkTaskSealedPayload("result", input.TaskID, input.OwnerEpoch, input.Body)
		if err != nil {
			return nil, err
		}
		child, err := requestMachineAgentNetworkDirect(m.joinSocketPath(context), localNetworkDirectRequest{
			Version: localJoinProtocolVersion, Operation: "network_direct_send", NetworkID: state.NetworkID,
			EndpointID: state.EndpointID, SessionToken: state.SessionToken, Harness: context.Harness,
			NativeSessionID: context.NativeSessionID, Workspace: context.Workspace, NodeID: context.MachineID,
			OperationID: op.OperationID, TaskID: input.TaskID, OwnerEpoch: input.OwnerEpoch,
			IdempotencyKey: op.IdempotencyKey, TargetEndpointID: input.Target, Body: sealed,
		})
		if err != nil {
			return fail(err)
		}
		want := input.TaskID + fmt.Sprintf(":result:%d:%s", input.OwnerEpoch, strings.TrimPrefix(op.OperationID, "op_"))
		if child == nil || child.NetworkID != state.NetworkID || child.MessageID != want || child.TargetEndpointID != input.Target || child.State != "RELAY_PERSISTED" {
			return fail(errors.New("local Node returned an invalid sealed Network Task result receipt"))
		}
		value, err := m.networkDirectHTTP(state, http.MethodPost,
			"/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/tasks/result",
			map[string]any{"task_id": input.TaskID, "expected_revision": input.ExpectedRevision,
				"owner_epoch": input.OwnerEpoch, "result_message_id": child.MessageID})
		if err != nil {
			return fail(err)
		}
		result = value
	default:
		failed, err := outbox.markError(scope, op.OperationID, mcpOutboxStatusFailed, errors.New("unsupported Network Task outbox operation"))
		if err != nil {
			return nil, err
		}
		return mcpOutboxPublicResult(failed), nil
	}
	encoded, err := mcpOutboxResultJSON(result, state.SessionToken)
	if err != nil {
		return nil, err
	}
	sent, err := outbox.markResult(scope, op.OperationID, mcpOutboxStatusSent, "", encoded)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(sent), nil
}
