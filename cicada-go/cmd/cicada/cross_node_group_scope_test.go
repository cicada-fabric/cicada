package main

import (
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestCrossNodeGroupPeerKeyRequiresCurrentHubAndGroupScope(t *testing.T) {
	valid := crossNodeGroupPeerKey{
		HubID:   "hub_test",
		GroupID: "group_test",
		NativeContextScope: store.NativeContextScopeMetadata{
			HubID: "hub_test", GroupID: "group_test", GroupContextPolicy: "group_scoped",
		},
		Sender:   crossNodeGroupScopeEndpoint("ep_sender", "node_sender", "hub_test", "group_test"),
		Receiver: crossNodeGroupScopeEndpoint("ep_receiver", "node_receiver", "hub_test", "group_test"),
	}
	if err := validateCrossNodeGroupPeerKey(valid, "group_test", "ep_sender", "ep_receiver", "node_sender"); err != nil {
		t.Fatalf("valid current scope was rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*crossNodeGroupPeerKey)
	}{
		{name: "different Hub", mutate: func(key *crossNodeGroupPeerKey) {
			key.NativeContextScope.HubID = "hub_other"
		}},
		{name: "different Group", mutate: func(key *crossNodeGroupPeerKey) {
			key.NativeContextScope.GroupID = "group_other"
		}},
		{name: "unknown policy", mutate: func(key *crossNodeGroupPeerKey) {
			key.NativeContextScope.GroupContextPolicy = "model_selected_policy"
		}},
		{name: "malformed Network scope", mutate: func(key *crossNodeGroupPeerKey) {
			key.NativeContextScope.NetworkID = "not a route id"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := valid
			test.mutate(&key)
			if err := validateCrossNodeGroupPeerKey(key, "group_test", "ep_sender", "ep_receiver", "node_sender"); err == nil {
				t.Fatal("mismatched current native scope was accepted")
			}
		})
	}
}

func crossNodeGroupScopeEndpoint(endpointID, nodeID, hubID, groupID string) crossNodeGroupEndpointEvidence {
	return crossNodeGroupEndpointEvidence{
		EndpointID: endpointID, PrincipalID: "principal_test", OwnerID: "owner_test",
		NodeID: nodeID, GroupID: groupID, BindingID: "binding_" + endpointID,
		BindingEpoch: 1, NativeSessionID: "native_test", GroupRevision: 1,
		MembershipRevision: 1, EndpointJoinRevision: 1,
		Grant: &store.OwnerGroupEndpointKeyGrant{Manifest: store.GroupEndpointKeyGrantManifest{HubID: hubID}},
	}
}
