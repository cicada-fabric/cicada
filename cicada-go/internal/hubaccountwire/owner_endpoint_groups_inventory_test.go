package hubaccountwire

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerEndpointGroupsMachineContractMatchesSharedDTO(t *testing.T) {
	raw, err := os.ReadFile("owner-endpoint-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups map[string]json.RawMessage `json:"proposed_owner_endpoint_groups"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid inventory")
	}
	fields := map[string]any{
		"key_prepare_result_fields": EndpointGroupKeyPrepareResult{}, "node_registration_anchor_fields": EndpointGroupsRegistrationAnchor{}, "node_describe_result_fields": EndpointGroupsNodeDescribeResult{}, "node_key_result_fields": EndpointGroupsNodeKeyResult{}, "node_renew_result_fields": EndpointGroupsNodeRenewResult{}, "node_reconciled_fields": EndpointGroupsNodeReconciled{}, "peer_source_fields": EndpointGroupPeerSource{},
		"owner_request_fields": OwnerEndpointGroupsReadRequest{}, "capability_fields": OwnerEndpointGroupsCapabilities{},
		"owner_thread_card_fields": OwnerEndpointGroupsThreadCard{}, "owner_relation_card_fields": OwnerEndpointGroupsRelationCard{}, "owner_group_card_fields": OwnerEndpointGroupsGroupCard{},
		"review_fields": OwnerEndpointGroupsReview{}, "cas_fields": OwnerEndpointGroupsCAS{}, "policy_fields": e2ee.EndpointGroupPolicy{}, "owner_request_claim_fields": e2ee.OwnerEndpointGroupsRequestClaims{},
		"result_fields": OwnerEndpointGroupsResult{}, "policy_proof_fields": e2ee.OwnerEndpointGroupPolicyProof{}, "node_key_claim_fields": e2ee.EndpointGroupKeyClaims{}, "node_proof_fields": e2ee.EndpointGroupKeyProof{},
		"relation_fields": EndpointGroupRelation{}, "delegated_grant_fields": EndpointGroupDelegatedGrant{}, "current_fields": EndpointGroupCurrent{}, "contribution_card_fields": OwnerEndpointGroupsContributionCard{},
		"native_identity_fields": e2ee.EndpointGroupNativeIdentity{}, "source_reference_fields": EndpointGroupSourceReference{}, "scope_action_fields": OwnerEndpointGroupsScopeActions{}, "relation_page_fields": OwnerEndpointGroupsRelationPage{},
		"operation_fields": OwnerEndpointGroupsOperation{}, "owner_control_fields": e2ee.EndpointGroupOwnerControl{}, "current_endpoint_fields": EndpointGroupCurrentEndpoint{},
	}
	for key, v := range fields {
		var expected []string
		if json.Unmarshal(document.Groups[key], &expected) != nil {
			t.Fatal("missing inventory", key)
		}
		typ := reflect.TypeOf(v)
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s field order disagrees: got %v want %v", key, got, expected)
		}
	}
	expected := map[string]any{"contract_revision": OwnerEndpointGroupsContractRevision, "implementation_phase": OwnerEndpointGroupsImplementationPhase, "default_available": false, "native_self_groups_default_available": false, "rights": e2ee.EndpointGroupRights(), "max_body_bytes": MaxOwnerEndpointGroupsBodyBytes, "max_page_canonical_bytes": MaxOwnerEndpointGroupsPageBytes, "max_original_bytes": MaxOwnerEndpointGroupsOriginalBytes, "max_packet_bytes": MaxOwnerEndpointGroupsPacketBytes, "max_reconcile_body_bytes": MaxOwnerEndpointGroupsReconcileBodyBytes, "max_reconcile_packet_bytes": MaxOwnerEndpointGroupsReconcilePacketBytes, "max_peer_carrier_bytes": MaxEndpointGroupCarrierBytes}
	for key, want := range expected {
		var got, normalized any
		encoded, _ := json.Marshal(want)
		if json.Unmarshal(document.Groups[key], &got) != nil || json.Unmarshal(encoded, &normalized) != nil || !reflect.DeepEqual(got, normalized) {
			t.Fatal("compiled value disagrees with inventory", key)
		}
	}
}
