package hubaccountwire

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestLocalDomainMachineContractMatchesCompiledProfile(t *testing.T) {
	raw, err := os.ReadFile("local-domain-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]json.RawMessage
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("contract inventory is not JSON")
	}
	paths := []string{}
	purposes := []string{}
	for _, op := range LocalDomainHTTPOperations() {
		paths = append(paths, LocalDomainHTTPPath(op))
		if purpose := LocalDomainOwnerPurpose(op); purpose != "" {
			purposes = append(purposes, purpose)
		}
	}
	expected := map[string]any{
		"contract_revision": LocalDomainContractRevision, "format": LocalDomainFormat, "format_version": 1, "implementation_phase": "HUB_NODE_RPC_CRYPTO_REPORT", "default_available": true,
		"capabilities_path": LocalDomainCapabilitiesPath, "http_operations": LocalDomainHTTPOperations(), "http_paths": paths, "node_path": "/v2/node/control/rpc", "node_operations": LocalDomainNodeOperations(), "owner_purposes": purposes,
		"persistent_policy_purpose": e2ee.OwnerLocalDomainPolicyPurpose, "node_user_report_purpose": e2ee.LocalDomainUserReportPurpose, "node_key_purpose": e2ee.LocalDomainEndpointKeyPurpose, "rights": e2ee.LocalDomainRights(),
		"max_nonterminal_policies_per_node_user": 1, "default_policy_expiry": nil, "optional_policy_expiry": true, "request_lifetime_seconds": int(e2ee.LocalDomainRequestLifetime.Seconds()), "user_report_lifetime_seconds": 300, "peer_current_lifetime_seconds": 30,
		"max_page_rows": 64, "max_page_canonical_bytes": MaxLocalDomainPageBytes, "max_body_bytes": MaxLocalDomainBodyBytes, "max_original_bytes": MaxLocalDomainOriginalBytes, "max_packet_bytes": MaxLocalDomainPacketBytes, "max_inner_packet_bytes": MaxLocalDomainInnerPacketBytes,
		"max_reconcile_body_bytes": MaxLocalDomainReconcileBodyBytes, "max_reconcile_packet_bytes": MaxLocalDomainReconcilePacketBytes, "max_reconcile_inner_packet_bytes": MaxLocalDomainReconcileInnerPacketBytes,
		"max_node_reconcile_body_bytes": MaxLocalDomainNodeReconcileBodyBytes, "max_node_original_bytes": MaxLocalDomainNodeOriginalBytes, "max_node_receipt_bytes": MaxLocalDomainNodeReceiptBytes, "max_node_reconcile_packet_bytes": MaxLocalDomainNodeReconcilePacketBytes,
		"max_peer_carrier_bytes": MaxLocalDomainCarrierBytes, "node_key_member_digest": "SHA256_CICADA_LOCAL_DOMAIN_MEMBER_V1_CANONICAL_DTO", "user_report_owner_id_hint_optional": true, "node_report_min_refresh_seconds": 120, "node_report_failure_backoff_max_seconds": 960, "read_cache_lifetime_seconds": 300, "max_cached_reads_per_actor_epoch": 128, "max_read_requests_per_actor_epoch_minute": 128, "final_authorization_linearization": "HUB_WRITER_TX_COMMIT_FOR_EXACT_NATIVE_ATTEMPT", "same_network_access_identity": "STABLE_ID_MONOTONIC_EPOCH",
		"policy_states": []string{LocalDomainPrepared, LocalDomainActive, LocalDomainRevoked, LocalDomainExpired}, "member_states": []string{LocalDomainMemberJoinedZero, LocalDomainMemberActive, LocalDomainMemberLeft, LocalDomainMemberRevoked, LocalDomainMemberExpired},
		"thread_selection": "EXPLICIT_CURRENT_THREAD_ONLY", "local_user_profile": "NODE_SIGNED_UNIX_UID_V1", "record_mode_022": "DIAGNOSTIC_ONLY_WITH_CURRENT_DOMAIN_POLICY_TICKET", "legacy_pair_record_mode_022": "REFUSE",
		"legacy_pair_contract_unchanged": true, "independent_original_owner_pin_required": true, "control_inference_required": false, "app_session_required_for_active_data_plane": false,
	}
	if len(c) != len(expected) {
		t.Fatal("contract inventory field set changed without its check")
	}
	for key, want := range expected {
		var got, normalized any
		encoded, _ := json.Marshal(want)
		if json.Unmarshal(c[key], &got) != nil || json.Unmarshal(encoded, &normalized) != nil || !reflect.DeepEqual(got, normalized) {
			t.Fatalf("contract inventory disagrees with compiled %s", key)
		}
	}
}
