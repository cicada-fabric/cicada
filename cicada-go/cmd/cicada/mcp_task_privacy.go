package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

func validateTaskPrivacyMCPArguments(name string, args map[string]any) error {
	if name == "cicada_task_submit" && (stringArgument(args, "idempotency_key") == "" || args["artifact_refs"] == nil || args["assignment_version"] == nil || args["content_version"] == nil) {
		return store.ErrSharedTaskPeerPlaintext
	}
	allowed := map[string]bool{"task_id": true}
	switch name {
	case "cicada_task_define", "cicada_task_submit":
		for _, key := range []string{"expected_revision", "owner_epoch", "assignment_version", "content_version", "artifact_refs", "idempotency_key"} {
			allowed[key] = true
		}
		if name == "cicada_task_define" {
			allowed["target_endpoint_id"] = true
			allowed["objective"] = true
			allowed["acceptance_criteria"] = true
		} else {
			allowed["summary"] = true
		}
	case "cicada_task_body":
		allowed["message_id"] = true
	case "cicada_task_accept":
		allowed["result_id"] = true
		allowed["expected_revision"] = true
	default:
		return nil
	}
	for key := range args {
		if !allowed[key] {
			return errors.New("Task tool contains an unsupported input")
		}
	}
	return nil
}
func parseTaskPrivacyArtifacts(raw any) ([]store.SharedTaskArtifactRef, error) {
	if raw == nil {
		return []store.SharedTaskArtifactRef{}, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 32*1024 {
		return nil, store.ErrSharedTaskSealedReference
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var refs []store.SharedTaskArtifactRef
	if decoder.Decode(&refs) != nil || len(refs) > 32 {
		return nil, store.ErrSharedTaskSealedReference
	}
	if refs == nil {
		refs = []store.SharedTaskArtifactRef{}
	}
	seen := map[string]bool{}
	for i := range refs {
		r := &refs[i]
		if !validTaskHandoffToken(r.ArtifactRefID) || r.Version <= 0 || !validSHA256Hex(r.Digest) || strings.ToLower(r.Digest) != r.Digest || seen[r.ArtifactRefID] {
			return nil, store.ErrSharedTaskSealedReference
		}
		seen[r.ArtifactRefID] = true
		r.Scopes = append([]string(nil), r.Scopes...)
		sort.Strings(r.Scopes)
		meta, digest := false, false
		for j, scope := range r.Scopes {
			if j > 0 && scope == r.Scopes[j-1] {
				return nil, store.ErrSharedTaskSealedReference
			}
			switch scope {
			case store.ArtifactRefV2ScopeMetadata:
				meta = true
			case store.ArtifactRefV2ScopeDigest:
				digest = true
			case store.ArtifactRefV2ScopeContent:
			default:
				return nil, store.ErrSharedTaskSealedReference
			}
		}
		if !meta || !digest {
			return nil, store.ErrSharedTaskSealedReference
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ArtifactRefID < refs[j].ArtifactRefID })
	return refs, nil
}
func (m *mcpServer) currentTaskPeerView(scope mcpOutboxScope, taskID string) (*store.SharedTaskPeerView, error) {
	if !validTaskHandoffToken(taskID) {
		return nil, store.ErrSharedTaskSealedReference
	}
	result, err := m.apiForGroup(http.MethodGet, "/v2/fabric/tasks/"+url.PathEscape(taskID), nil, scope.GroupID)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var view store.SharedTaskPeerView
	if json.Unmarshal(encoded, &view) != nil || view.ID != taskID || view.GroupID != scope.GroupID {
		return nil, store.ErrSharedTaskSealedReference
	}
	return &view, nil
}
func (m *mcpServer) submitTaskPeerBody(name string, args map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	refs, err := parseTaskPrivacyArtifacts(args["artifact_refs"])
	if err != nil {
		return nil, err
	}
	key, err := normalizeMCPOutboxKey(stringArgument(args, "idempotency_key"))
	if err != nil || key == "" {
		return nil, errors.New("sealed Task submission requires a stable idempotency key")
	}
	revision, okR := strictMCPInteger(args["expected_revision"])
	epoch, okE := strictMCPInteger(args["owner_epoch"])
	assignment, okA := strictMCPInteger(args["assignment_version"])
	content, okC := strictMCPInteger(args["content_version"])
	if !okR || !okE || !okA || !okC || revision <= 0 || epoch < 0 || assignment <= 0 || content <= 0 {
		return nil, store.ErrSharedTaskSealedReference
	}
	packet := sealedTaskObjectPacket{Version: 1, TaskID: stringArgument(args, "task_id"), GroupID: scope.GroupID, AssignmentVersion: assignment, ContentVersion: content, TaskRevision: revision, OwnerEpoch: epoch, SenderEndpointID: scope.EndpointID, ArtifactRefs: refs}
	if name == "cicada_task_define" {
		packet.Purpose = store.SharedTaskDefinitionPurpose
		packet.ReaderEndpointID = stringArgument(args, "target_endpoint_id")
		packet.Objective = stringArgument(args, "objective")
		packet.AcceptanceCriteria = stringArgument(args, "acceptance_criteria")
	} else {
		packet.Purpose = store.SharedTaskResultPurpose
		packet.Summary = stringArgument(args, "summary")
	}
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	existing, err := outbox.findByIdempotencyKey(scope, key)
	if err != nil {
		return nil, err
	}
	var operation mcpOutboxOperation
	if existing != nil {
		var saved mcpOutboxInput
		if existing.Kind != "send" || json.Unmarshal([]byte(existing.InputJSON), &saved) != nil || saved.TaskID != packet.TaskID {
			return nil, errMCPOutboxConflict
		}
		savedPacket, err := decodeSealedTaskObjectPacket(saved.Body)
		if err != nil {
			return nil, errMCPOutboxConflict
		}
		if name == "cicada_task_submit" {
			packet.ReaderEndpointID = savedPacket.ReaderEndpointID
		}
		if !reflect.DeepEqual(savedPacket, &packet) || saved.Target != packet.ReaderEndpointID {
			return nil, errMCPOutboxConflict
		}
		operation = *existing
	} else {
		view, err := m.currentTaskPeerView(scope, packet.TaskID)
		if err != nil {
			return nil, err
		}
		if view.Assignment == nil || view.Assignment.Version != assignment || view.Assignment.ContentVersion != content || view.Revision != revision || view.OwnerEpoch != epoch {
			return nil, store.ErrSharedTaskSealedReference
		}
		if name == "cicada_task_define" {
			if view.Assignment.PublisherEndpointID != scope.EndpointID {
				return nil, store.ErrSharedTaskSealedReference
			}
		} else {
			if view.OwnerEndpointID != scope.EndpointID || view.DefinitionStatus != "REGISTERED" {
				return nil, store.ErrSharedTaskSealedReference
			}
			packet.ReaderEndpointID = view.Assignment.ResultRecipientEndpointID
		}
		encoded, err := json.Marshal(packet)
		if err != nil {
			return nil, err
		}
		if _, err = decodeSealedTaskObjectPacket(string(encoded)); err != nil {
			return nil, err
		}
		input := mcpOutboxInput{TaskID: packet.TaskID, ExpectedRevision: revision, OwnerEpoch: epoch, Target: packet.ReaderEndpointID, Body: string(encoded)}
		var created bool
		operation, created, err = outbox.prepare(scope, "send", key, input)
		if err != nil {
			return nil, err
		}
		if created {
			// Ordinary sealed SEND, forced through the existing Hub Relay path so
			// formal registration can bind its authentic persisted receipt.
			if _, err = m.dispatchMCPOutbox(outbox, scope, operation); err != nil {
				return nil, err
			}
			operation, err = outbox.load(scope, operation.OperationID)
			if err != nil {
				return nil, err
			}
		}
	}
	public := mcpOutboxPublicResult(operation)
	public["task_authority"] = "CANDIDATE_ONLY"
	if operation.Status != mcpOutboxStatusSent {
		return public, nil
	}
	var receipt crossNodeGroupResult
	if json.Unmarshal([]byte(operation.ResultJSON), &receipt) != nil || receipt.PayloadMode != store.RelayPayloadModeSealedV1 || receipt.Delivery != "RELAY_PERSISTED" || receipt.TargetEndpointID != packet.ReaderEndpointID || receipt.MessageID == "" || !validSHA256Hex(receipt.Digest) {
		return nil, store.ErrSharedTaskSealedReference
	}
	input := store.SharedTaskSealedRefInput{TaskID: packet.TaskID, Purpose: packet.Purpose, AssignmentVersion: assignment, ContentVersion: content, ExpectedRevision: revision, OwnerEpoch: epoch, MessageID: receipt.MessageID, MessageDigest: receipt.Digest, ArtifactRefs: refs}
	registered, err := m.apiForGroup(http.MethodPost, "/v2/fabric/tasks/sealed-reference", input, scope.GroupID)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(registered)
	if err != nil {
		return nil, err
	}
	var ref store.SharedTaskSealedRef
	if json.Unmarshal(encoded, &ref) != nil || ref.MessageID != receipt.MessageID || ref.MessageDigest != receipt.Digest || !matchSealedTaskObjectPacket(&packet, ref) {
		return nil, store.ErrSharedTaskSealedReference
	}
	public["task_authority"] = "REGISTERED"
	public["registered_ref"] = ref
	return public, nil
}
func (m *mcpServer) readTaskPeerBody(args map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	view, err := m.currentTaskPeerView(scope, stringArgument(args, "task_id"))
	if err != nil {
		return nil, err
	}
	messageID := stringArgument(args, "message_id")
	for _, ref := range append(view.DefinitionRefs, view.ResultRefs...) {
		if ref.MessageID == messageID {
			packet, err := m.readLocalRegisteredTaskPacket(scope, ref)
			if err != nil {
				return nil, err
			}
			finalView, err := m.currentTaskPeerView(scope, view.ID)
			if err != nil {
				return nil, err
			}
			for _, current := range append(finalView.DefinitionRefs, finalView.ResultRefs...) {
				if reflect.DeepEqual(current, ref) {
					return map[string]any{"registered_ref": ref, "body": packet, "content_trust": "UNTRUSTED_PEER_CONTENT"}, nil
				}
			}
			return nil, store.ErrSharedTaskSealedReference
		}
	}
	return nil, store.ErrSharedTaskSealedReference
}
func (m *mcpServer) acceptTaskPeerResult(args map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	view, err := m.currentTaskPeerView(scope, stringArgument(args, "task_id"))
	if err != nil {
		return nil, err
	}
	revision, valid := strictMCPInteger(args["expected_revision"])
	if !valid || revision != view.Revision {
		return nil, store.ErrSharedTaskConflict
	}
	resultID := stringArgument(args, "result_id")
	for _, ref := range view.ResultRefs {
		if ref.ResultID == resultID {
			if _, err = m.readLocalRegisteredTaskPacket(scope, ref); err != nil {
				return nil, err
			}
			return m.apiForGroup(http.MethodPost, "/v2/fabric/tasks/accept", map[string]any{"task_id": view.ID, "result_id": resultID, "expected_revision": revision}, scope.GroupID)
		}
	}
	return nil, store.ErrSharedTaskSealedReference
}

func taskPrivacyBodySchema(definition bool) map[string]any {
	properties := map[string]any{
		"task_id": map[string]any{"type": "string"}, "expected_revision": map[string]any{"type": "integer", "minimum": 1}, "owner_epoch": map[string]any{"type": "integer", "minimum": 0}, "assignment_version": map[string]any{"type": "integer", "minimum": 1}, "content_version": map[string]any{"type": "integer", "minimum": 1}, "idempotency_key": map[string]any{"type": "string"},
		"artifact_refs": map[string]any{"type": "array", "maxItems": 32, "items": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"artifact_ref_id", "version", "digest", "scopes"}, "properties": map[string]any{"artifact_ref_id": map[string]any{"type": "string"}, "version": map[string]any{"type": "integer", "minimum": 1}, "digest": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}, "scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"metadata", "digest", "content"}}}}}},
	}
	required := []string{"task_id", "expected_revision", "owner_epoch", "assignment_version", "content_version", "idempotency_key", "artifact_refs"}
	if definition {
		properties["target_endpoint_id"] = map[string]any{"type": "string"}
		properties["objective"] = map[string]any{"type": "string"}
		properties["acceptance_criteria"] = map[string]any{"type": "string"}
		required = append(required, "target_endpoint_id", "objective", "acceptance_criteria")
	} else {
		properties["summary"] = map[string]any{"type": "string"}
		required = append(required, "summary")
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}
