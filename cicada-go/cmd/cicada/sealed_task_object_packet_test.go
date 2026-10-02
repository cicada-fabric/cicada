package main

import (
	"encoding/json"
	"github.com/cicada-ai/cicada/internal/store"
	"strings"
	"testing"
)

func TestTaskPeerPrivacyTypedBodyCannotTransplantRegisteredAuthority(t *testing.T) {
	packet := sealedTaskObjectPacket{Version: 1, TaskID: "task_synthetic", GroupID: "group_synthetic", Purpose: store.SharedTaskDefinitionPurpose, AssignmentVersion: 1, ContentVersion: 2, TaskRevision: 3, OwnerEpoch: 0, SenderEndpointID: "ep_publisher", ReaderEndpointID: "ep_worker", ArtifactRefs: []store.SharedTaskArtifactRef{}, Objective: "synthetic private objective", AcceptanceCriteria: "synthetic private criteria"}
	ref := store.SharedTaskSealedRef{TaskID: packet.TaskID, GroupID: packet.GroupID, Purpose: packet.Purpose, AssignmentVersion: packet.AssignmentVersion, ContentVersion: packet.ContentVersion, TaskRevision: packet.TaskRevision, OwnerEpoch: packet.OwnerEpoch, SenderEndpointID: packet.SenderEndpointID, ReaderEndpointID: packet.ReaderEndpointID, ArtifactRefs: packet.ArtifactRefs}
	encoded, _ := json.Marshal(packet)
	decoded, err := decodeSealedTaskObjectPacket(string(encoded))
	if err != nil || !matchSealedTaskObjectPacket(decoded, ref) {
		t.Fatal("exact typed body was refused", err)
	}
	for _, change := range []func(*store.SharedTaskSealedRef){func(r *store.SharedTaskSealedRef) { r.TaskID = "other_task" }, func(r *store.SharedTaskSealedRef) { r.GroupID = "other_group" }, func(r *store.SharedTaskSealedRef) { r.Purpose = store.SharedTaskResultPurpose }, func(r *store.SharedTaskSealedRef) { r.AssignmentVersion++ }, func(r *store.SharedTaskSealedRef) { r.ContentVersion++ }, func(r *store.SharedTaskSealedRef) { r.TaskRevision++ }, func(r *store.SharedTaskSealedRef) { r.OwnerEpoch++ }, func(r *store.SharedTaskSealedRef) { r.ReaderEndpointID = "ep_other" }, func(r *store.SharedTaskSealedRef) { r.SenderEndpointID = "ep_other" }} {
		bad := ref
		change(&bad)
		if matchSealedTaskObjectPacket(decoded, bad) {
			t.Fatal("typed body accepted a transplanted registered coordinate")
		}
	}
	for _, body := range []string{string(encoded) + "{}", strings.Replace(string(encoded), "TASK_DEFINITION_V1", "APPROVED", 1), strings.Replace(string(encoded), "\"objective\":", "\"summary\":", 1), strings.TrimSuffix(string(encoded), "}") + ",\"approved\":true}"} {
		if _, err = decodeSealedTaskObjectPacket(body); err == nil {
			t.Fatal("untyped/mixed/fake-purpose body was accepted")
		}
	}
}
