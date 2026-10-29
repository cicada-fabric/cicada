package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"testing"
)

func TestLocalCollaborationSelectionKeepsExactNetworkAndRequiresPreview(t *testing.T) {
	s := appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionPrepareLocalCollaboration}, LocalCollaboration: appcore.LocalCollaborationSnapshot{Current: true}, Targets: appcore.TargetSelectionSnapshot{Networks: []appcore.SavedNetworkView{{NetworkID: "network-a", Name: "Same name"}, {NetworkID: "network-b", Name: "Same name"}}}}
	input, ok := LocalCollaborationSelection(s, "network-b", "ignored draft", "New default Group", 24)
	if !ok || input.NetworkID != "network-b" || input.NewNetworkName != "" || input.ExpiresInHours != 24 {
		t.Fatal("saved Network lost exact identity, created a duplicate or changed duration")
	}
	if _, ok := LocalCollaborationSelection(s, "missing", "draft", "Group", 0); ok {
		t.Fatal("unoffered choice fell back to a new Network")
	}
	s.Targets.Locked = true
	if _, ok := LocalCollaborationSelection(s, "network-a", "", "Group", 0); ok {
		t.Fatal("pending request allowed changing Network")
	}
	s.Targets.Locked = false
	s.AvailableActions = nil
	if _, ok := LocalCollaborationSelection(s, "network-a", "", "Group", 0); ok {
		t.Fatal("saved label supplied authorization")
	}
}
