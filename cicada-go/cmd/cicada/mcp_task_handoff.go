package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func (m *mcpServer) taskHandoffTool(name string, arguments map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	switch name {
	case "cicada_task_handoff_send":
		return m.submitSealedTaskHandoff(scope, arguments)
	case "cicada_task_handoff_get":
		handoffID := stringArgument(arguments, "handoff_id")
		if !validTaskHandoffToken(handoffID) {
			return nil, errors.New("handoff_id is required")
		}
		return m.apiForGroup(http.MethodGet, "/v2/fabric/tasks/sealed-handoffs/"+url.PathEscape(handoffID), nil, scope.GroupID)
	case "cicada_task_handoff_accept":
		handoffID := stringArgument(arguments, "handoff_id")
		expectedVersion, validVersion := strictMCPInteger(arguments["expected_version"])
		leaseSeconds := int64(0)
		validLease := true
		if rawLease, present := arguments["lease_seconds"]; present {
			leaseSeconds, validLease = strictMCPInteger(rawLease)
		}
		if !validTaskHandoffToken(handoffID) || !validVersion || expectedVersion <= 0 ||
			!validLease || leaseSeconds < 0 || leaseSeconds > 3600 {
			return nil, errors.New("handoff acceptance requires the exact ID, positive version, and a bounded optional lease")
		}
		return m.apiForGroup(http.MethodPost, "/v2/fabric/tasks/sealed-handoffs/"+url.PathEscape(handoffID)+"/accept",
			fabricpkg.SealedTaskHandoffAcceptInput{HandoffID: handoffID, ExpectedVersion: expectedVersion,
				LeaseSeconds: int(leaseSeconds)}, scope.GroupID)
	default:
		return nil, errors.New("unsupported sealed Task handoff tool")
	}
}

func (m *mcpServer) submitSealedTaskHandoff(scope mcpOutboxScope, arguments map[string]any) (any, error) {
	taskID, target, body := stringArgument(arguments, "task_id"), stringArgument(arguments, "target"), stringArgument(arguments, "body")
	if !validTaskHandoffToken(taskID) || target == "" || len(target) > 256 || strings.TrimSpace(body) == "" ||
		len([]byte(body)) > 60*1024 {
		return nil, errors.New("sealed Task handoff requires an exact Task ID, target, and body under 60 KiB")
	}
	key, err := normalizeMCPOutboxKey(stringArgument(arguments, "idempotency_key"))
	if err != nil || key == "" {
		return nil, errors.New("sealed Task handoff requires a stable idempotency_key")
	}
	deadline, err := time.Parse(time.RFC3339Nano, stringArgument(arguments, "expires_at"))
	if err != nil {
		return nil, errors.New("sealed Task handoff expires_at must be RFC3339")
	}
	deadline = time.UnixMilli(deadline.UnixMilli()).UTC()
	_, refsJSON, err := parseTaskHandoffRefs(arguments["required_artifact_refs"])
	if err != nil {
		return nil, err
	}
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	canonicalExpiry := deadline.Format(time.RFC3339Nano)
	if existing, findErr := outbox.findByIdempotencyKey(scope, key); findErr != nil {
		return nil, findErr
	} else if existing != nil {
		var saved mcpOutboxInput
		if existing.Kind != "sealed_task_handoff" || json.Unmarshal([]byte(existing.InputJSON), &saved) != nil ||
			saved.TaskID != taskID || saved.RequestedTarget != target || saved.Body != body ||
			saved.ExpiresAt != canonicalExpiry || saved.RequiredArtifactRefsJSON != refsJSON {
			return nil, errMCPOutboxConflict
		}
		if existing.Status == mcpOutboxStatusSent || existing.Status == mcpOutboxStatusFailed {
			return mcpOutboxPublicResult(*existing), nil
		}
		return m.dispatchMCPOutbox(outbox, scope, *existing)
	}
	if !deadline.After(time.Now().UTC()) || deadline.Sub(time.Now().UTC()) > 24*time.Hour {
		return nil, errors.New("sealed Task handoff deadline must be within the next 24 hours")
	}
	var task store.SharedTask
	result, err := m.apiForGroup(http.MethodGet, "/v2/fabric/tasks/"+url.PathEscape(taskID), nil, scope.GroupID)
	if err != nil {
		return nil, err
	}
	encodedTask, err := json.Marshal(result)
	if err != nil || json.Unmarshal(encodedTask, &task) != nil || task.ID != taskID || task.GroupID != scope.GroupID ||
		task.OwnerEndpointID != scope.EndpointID || task.Revision <= 0 || task.OwnerEpoch <= 0 ||
		(task.Status != store.SharedTaskClaimed && task.Status != store.SharedTaskRunning) {
		return nil, errors.New("current Endpoint does not own an active Task claim")
	}
	lease, err := time.Parse(time.RFC3339Nano, task.LeaseExpiresAt)
	if err != nil || !lease.After(time.Now().UTC()) {
		return nil, errors.New("current Task claim lease is not active")
	}
	operation := mcpOutboxOperation{APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID, Workspace: scope.Workspace,
		EndpointID: scope.EndpointID, GroupID: scope.GroupID}
	card, err := m.resolveMCPOutboxTarget(operation, target)
	if err != nil || card.GroupID != scope.GroupID || card.EndpointID == scope.EndpointID || card.NodeID == "" {
		return nil, errors.New("Task handoff target must resolve to another Endpoint in the current Group")
	}
	input := mcpOutboxInput{TaskID: taskID, Target: card.EndpointID, ExpectedRevision: task.Revision,
		RequestedTarget: target, OwnerEpoch: task.OwnerEpoch, Body: body, ExpiresAt: canonicalExpiry,
		RequiredArtifactRefsJSON: refsJSON}
	op, created, err := outbox.prepare(scope, "sealed_task_handoff", key, input)
	if err != nil {
		return nil, err
	}
	if !created && (op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed) {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(outbox, scope, op)
}

func parseTaskHandoffRefs(raw any) ([]store.SealedTaskHandoffArtifactRef, string, error) {
	refs := make([]store.SealedTaskHandoffArtifactRef, 0)
	if raw != nil {
		items, ok := raw.([]any)
		if !ok || len(items) > 32 {
			return nil, "", errors.New("required_artifact_refs must contain at most 32 exact Artifact references")
		}
		for index, item := range items {
			object, ok := item.(map[string]any)
			if !ok || len(object) != 3 {
				return nil, "", fmt.Errorf("required_artifact_refs[%d] must contain artifact_ref_id, version, and digest only", index)
			}
			id, _ := object["artifact_ref_id"].(string)
			digest, _ := object["digest"].(string)
			version, validVersion := strictMCPInteger(object["version"])
			if !validTaskHandoffToken(id) || !validVersion || version <= 0 || len(digest) != 64 {
				return nil, "", fmt.Errorf("required_artifact_refs[%d] is invalid", index)
			}
			for _, b := range []byte(digest) {
				if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
					return nil, "", fmt.Errorf("required_artifact_refs[%d] digest must be SHA-256 hex", index)
				}
			}
			refs = append(refs, store.SealedTaskHandoffArtifactRef{ArtifactRefID: id, Version: version,
				Digest: strings.ToLower(digest)})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ArtifactRefID < refs[j].ArtifactRefID })
	for i := 1; i < len(refs); i++ {
		if refs[i-1].ArtifactRefID == refs[i].ArtifactRefID {
			return nil, "", errors.New("required_artifact_refs cannot contain duplicates")
		}
	}
	if refs == nil {
		refs = []store.SealedTaskHandoffArtifactRef{}
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return nil, "", err
	}
	return refs, string(encoded), nil
}

// strictMCPInteger accepts JSON integer tokens and integer Go values, but
// refuses lossy float truncation, strings, booleans and signed overflow.
func strictMCPInteger(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		if uint64(number) > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case uint8:
		return int64(number), true
	case uint16:
		return int64(number), true
	case uint32:
		return int64(number), true
	case uint64:
		if number > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case float32:
		return strictMCPInteger(float64(number))
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number ||
			number < math.MinInt64 || number >= float64(math.MaxInt64) {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func parseOutboxTaskHandoffRefs(raw string) ([]store.SealedTaskHandoffArtifactRef, error) {
	if raw == "" {
		return []store.SealedTaskHandoffArtifactRef{}, nil
	}
	var refs []store.SealedTaskHandoffArtifactRef
	if json.Unmarshal([]byte(raw), &refs) != nil || len(refs) > 32 {
		return nil, errors.New("durable Task handoff Artifact references are invalid")
	}
	return refs, nil
}
