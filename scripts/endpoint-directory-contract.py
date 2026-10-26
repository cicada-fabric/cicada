#!/usr/bin/env python3
"""Check the bounded native Endpoint extension; no deployment/runtime claim."""
import ast
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fields(source, name):
    body = re.search(r"type\s+" + name + r"\s+struct\s*\{(.*?)\n\}", source, re.S).group(1)
    return re.findall(r'`json:"([^",]+)(?:,[^"]*)?"`', body)


def check_owner_endpoint_groups(g, prose):
    """Shared-profile oracle: reject widening or an implied service/runtime pass."""
    assert g["contract_revision"] == "owner-endpoint-groups-v1"
    assert g["status"] == "CONTRACT_DRAFT"
    assert g["implementation_phase"] == "SHARED_DTO_CRYPTO"
    for key in ("default_available", "new_identity_tables",
                "legacy_finite_key_grant_allows_empty_expiry",
                "app_session_required_for_active_data_plane",
                "automatic_owner_key_signing", "mcp_join_changed",
                "control_inference_required", "group_creation_auto_enrolls_endpoint",
                "uncertain_clears_pending", "native_context_requires_default_policy",
                "native_context_fallback_to_legacy", "pending_manual_resets_existing_active_source",
                "native_self_groups_default_available", "manual_expiry_default_fallback",
                "pending_manual_clears_deny", "owner_control_mode_reverts_to_default"):
        assert g[key] is False, key
    for key in ("legacy_contract_unchanged",
                "registration_identity_preserved_on_last_group_remove",
                "policy_revoke_withdraws_only_its_source",
                "normal_cold_renewal_preserves_binding_epoch",
                "remove_withdraws_all_relation_contributions", "candidate_scope_actions_required",
                "native_context_one_use_required", "node_signs_projected_active_state",
                "owner_control_owner_mode_persistent",
                "pending_preserves_active_default_only_without_deny"):
        assert g[key] is True, key
    assert g["wire_version"] == 1
    assert g["schema_migration"] == "REQUIRED_NOT_ASSIGNED"
    assert g["required_participants"] == ["HUB", "NODE", "APP"]
    assert g["capabilities_path"] == "/v2/owner/endpoint-groups/capabilities"
    assert g["capabilities_format"] == "cicada.owner-endpoint-groups-capabilities.v1"
    assert g["format"] == "cicada.owner-endpoint-groups.v1"
    assert g["result_format"] == "cicada.owner-endpoint-groups-result.v1"
    assert g["current_format"] == "cicada.endpoint-group-current.v1"
    names = ["read", "prepare", "apply", "status", "reconcile"]
    assert g["http_operations"] == {
        "owner.endpoint_groups." + name: "/v2/owner/endpoint-groups/" + name
        for name in names}
    assert g["owner_request_purposes"] == {
        "owner.endpoint_groups." + name: "owner-endpoint-groups-" + name + ":v1"
        for name in names}
    assert g["node_rpc_path"] == "/v2/node/control/rpc"
    assert g["node_operations"] == ["node.endpoint_groups." + name for name in
                                    ["describe", "key_prepare", "key_complete", "renew", "reconcile"]]
    assert g["owner_request_domain"] == "cicada/owner/endpoint-groups/request/v1\0"
    assert g["policy_purpose"] == "endpoint-group-policy:v1"
    assert g["policy_domain"] == "cicada/owner/endpoint-groups/policy/v1\0"
    assert g["node_key_purpose"] == "endpoint-group-key-grant:v1"
    assert g["node_key_domain"] == "cicada/node/endpoint-groups/key-grant/v1\0"
    for kind in ("registration", "relation", "review", "body", "packet"):
        assert g[kind + "_digest_domain"] == "cicada/owner/endpoint-groups/" + kind + "/v1\0"
    assert g["native_identity_digest_domain"] == "cicada/owner/endpoint-groups/native-identity/v1\0"
    assert g["native_identity_fields"] == "hub_id owner_id node_id local_user_scope harness native_session_id workspace".split()
    assert g["deny_key"] == "PRIVATE_NATIVE_IDENTITY_DIGEST_AND_GROUP_ID"
    assert g["owner_control_fields"] == "mode revision deny_reason policy_id policy_epoch".split()
    assert g["owner_control_modes"] == ["DEFAULT", "OWNER"]
    assert g["owner_control_deny_reasons"] == ["NONE", "REMOVED", "EXPIRED"]
    assert g["owner_control_key"] == g["deny_key"]
    assert g["owner_control_digest_domain"] == "cicada/owner/endpoint-groups/owner-control/v1\0"
    assert g["owner_control_takeover_stage"] == "EXACT_PROJECTED_KEY_COMPLETE"
    assert g["manual_deny_cleared_at"] == "EXACT_PROJECTED_KEY_COMPLETE_ONLY"
    assert g["effective_source_rule"] == "OWNER_MODE_MANUAL_ONLY_ELSE_BLOCKED_DEFAULT_MODE_DEFAULT_ONLY"
    assert g["current_endpoint_fields"] == ["owner_control", "relation"]
    assert g["source_reference_fields"] == "source authority_id authority_epoch contribution_revision".split()
    assert g["group_creation_authorized_by"] == "SIGNED_OWNER_SCOPE_ACTION_NOT_GROUP_CARD_OR_PUBLIC_CAPABILITY"
    assert g["operation_id_source"] == "ORIGINAL_APPLY_CONTEXT_REQUEST_ID"
    assert g["status_digest_source"] == "EXACT_ORIGINAL_ENCRYPTED_APPLY_PACKET"
    assert g["relation_pagination_view"] == "RELATIONS"
    assert g["relation_history_scope"] == "EXACT_ENDPOINT_CURRENT_NETWORK_ALL_STORED_STATES"
    assert g["contribution_projection"] == "ONE_CURRENT_SLOT_PER_SOURCE_NOT_FULL_HISTORY"
    assert g["relation_cursor_change"] == "CURSOR_STALE_RESTART_KEEP_EXISTING_STATE"
    assert g["eligible_registration_sources"] == ["CODEX_LOCAL_DOMAIN"]
    assert g["native_context_profile"] == "OWNER_ENDPOINT_GROUPS_V1"
    assert g["key_challenge_digest_domain"] == "cicada/owner/endpoint-groups/key-challenge/v1\0"
    assert g["scope"] == "EXACT_REGISTERED_CODEX_LOCAL_DOMAIN_ENDPOINT_SAME_OWNER_NODE_USER_HUB_NETWORK"
    assert g["actions"] == ["CREATE_GROUP", "ADD_ENDPOINT", "REMOVE_ENDPOINT"]
    assert g["group_context_policy"] == "group_scoped"
    assert g["rights"] == ["directory.read", "message.ask", "message.receive",
                            "message.reply", "message.send"]
    assert g["default_duration"] == "until_revoked"
    assert g["duration_values"] == ["until_revoked", "1d", "7d", "30d"]
    assert g["fixed_duration_seconds"] == {"1d": 86400, "7d": 604800, "30d": 2592000}
    assert g["manual_deny_precedence"] == "OWNER_EXPLICIT_REMOVE_OVERRIDES_DEFAULT_ADMISSION"
    assert g["deny_cleared_only_by"] == "NEW_OWNER_SIGNED_ADD_FOR_EXACT_RELATION"
    assert g["registration_renewal_sources"] == ["REGISTRATION_ONLY", "DEFAULT_POLICY", "OWNER_EXPLICIT"]
    assert g["warm_renewal"] == "EXISTING_HEARTBEAT_NO_PER_TICK_PERMANENT_RECEIPT"
    assert g["peer_grant_variant"] == "endpoint_group_grant"
    assert g["peer_current_variant"] == "endpoint_group_current"
    assert g["mixed_default_manual_peers"] == "EXACT_SAME_GROUP_EACH_ENDPOINT_ONE_VERIFIED_SOURCE"
    assert g["final_authorization_linearization"] == "HUB_WRITER_TX_COMMIT_FOR_EXACT_NATIVE_ATTEMPT"
    exact = {
        "owner_request_fields": "format context session_token owner_proof body",
        "owner_request_claim_fields": "version purpose scope request_id nonce issued_at expires_at body_digest",
        "owner_thread_card_fields": "endpoint_id principal_id node_id network_id name workspace harness registration_digest registration_revision presence relations relation_states relations_revision relations_complete relations_next_cursor",
        "owner_relation_card_fields": "group_id group_name network_id state relation_revision decision_revision manual_deny owner_control contributions selected_source expires_at key_state allowed_actions unavailable_reason",
        "contribution_card_fields": "source authority_id authority_epoch contribution_revision state expires_at key_state effective unavailable_reason",
        "scope_action_fields": "node_id network_id allowed_actions unavailable_reason",
        "relation_page_fields": "endpoint_id network_id states relations_revision complete next_cursor",
        "operation_fields": "operation_id original_packet_digest action state error_code review_id target committed_at effect",
        "native_context_fields": "harness native_session_id workspace turn_id tool_use_id verification_profile endpoint_groups_version registration_digest registration_revision binding_id binding_epoch node_key_epoch",
        "key_prepare_result_fields": "challenge_id policy_id policy_epoch expected projected_owner_control projected_relation projected_key_manifest observed_at expires_at challenge_digest",
        "owner_group_card_fields": "group_id name network_id group_version context_policy allowed_actions unavailable_reason",
        "review_fields": "review_id request_id request_packet_digest action target expected projection policy key_manifest observed_at expires_at review_digest",
        "cas_fields": "owner_key_version node_owner_binding_id node_owner_binding_version node_key_epoch network_version group_version registration_digest registration_revision binding_id binding_epoch candidate_version candidate_proof_digest candidate_fingerprint membership_revision endpoint_join_revision relation_revision decision_revision owner_control_digest policy_epoch",
        "policy_fields": "version purpose policy_id epoch origin hub_id hub_fingerprint owner_id owner_public_identity owner_key_version node local_user_scope network_id group_id endpoint_id principal_id registration_digest registration_revision binding_id binding_epoch endpoint_key_id endpoint_public_identity endpoint_fingerprint candidate_version candidate_proof_digest expected_owner_control_digest expected_decision_revision rights issued_at expires_at review_id review_digest server_nonce",
        "policy_core_excludes": "review_id review_digest",
        "policy_proof_fields": "purpose policy signature",
        "node_proof_fields": "claims signature",
        "node_key_claim_fields": "version purpose hub_id node_id node_key_epoch policy_id policy_epoch policy_digest registration_digest owner_control_digest relation_digest manifest_digest candidate_binding_digest challenge_id challenge_digest issued_at expires_at",
        "relation_fields": "hub_id owner_id node_id local_user_scope network_id group_id endpoint_id principal_id registration_digest registration_revision source authority_id authority_epoch contribution_revision state decision_revision owner_control_digest policy_id policy_epoch binding_id binding_epoch membership_revision endpoint_join_revision candidate_version candidate_key_id candidate_fingerprint candidate_proof_digest expires_at",
        "current_fields": "format hub_id group_id sender receiver operation attempt_id observed_at expires_at",
        "result_fields": "format contract_revision request_id request_packet_digest hub_id owner_id device_id node_id state error_code captured_at freshness threads groups relations scope_actions relation_page next_cursor review operation current_relation current_group receipt_packet",
        "capability_fields": "format contract_revision available hub_id hub_fingerprint max_page_rows max_page_canonical_bytes max_active_groups_per_endpoint duration_values native_self_groups",
        "delegated_grant_fields": "manifest relation policy_proof node_proof",
        "sources": "DEFAULT_POLICY OWNER_EXPLICIT",
        "policy_states": "PENDING_KEY ACTIVE REVOKED EXPIRED",
        "relation_states": "NONE PENDING_KEY ACTIVE REMOVED EXPIRED",
        "key_states": "NOT_READY PENDING CURRENT STALE REVOKED EXPIRED",
        "operation_states": "PREPARED COMPLETED REJECTED_FENCED READ_EXPIRED",
    }
    for key, value in exact.items():
        assert g[key] == value.split(), key
    for key, value in g.items():
        if key.endswith("_fields"):
            assert len(value) == len(set(value)), key
    prepare = g["request_bodies"]["prepare"]
    assert prepare == {
        "CREATE_GROUP": ["action", "node_id", "network_id", "name"],
        "ADD_ENDPOINT": ["action", "node_id", "network_id", "group_id", "endpoint_id", "duration"],
        "REMOVE_ENDPOINT": ["action", "node_id", "network_id", "group_id", "endpoint_id"]}
    assert g["request_bodies"]["apply"] == {
        "required": ["review_id", "review_digest", "prepare_packet_digest"], "optional": ["policy_proof"]}
    assert g["request_bodies"]["reconcile"] == {"required": ["original_packet"], "optional": []}
    assert g["request_bodies"]["read"]["views"] == ["THREADS", "CANDIDATE_GROUPS", "RELATIONS"]
    assert g["effect_fields"]["ADD_ENDPOINT"] == "group_id endpoint_id relation_revision decision_revision policy_id policy_epoch contribution_revision contribution_state effective_relation_state owner_control".split()
    assert g["projection_fields"]["ADD_ENDPOINT"] == "source contribution_state effective_relation_state grants projected_rights duration expected_owner_control completion_owner_control policy_core".split()
    self_groups = g["self_groups"]
    assert self_groups == {
        "tool": "cicada_groups", "required": [], "optional": ["cursor", "limit"],
        "default_limit": 64, "max_limit": 64, "max_page_bytes": 128 << 10,
        "profile": "OWNER_ENDPOINT_GROUPS_V1", "requires_selected_group": False,
        "uses_owner_inventory": False, "creates_authority": False,
        "auto_selects_group": False, "fresh_one_use_context_required": True,
        "states": ["ACTIVE"], "node_source": "node.endpoint_groups.describe",
        "result_fields": "groups current_group_id selection_required complete next_cursor freshness".split(),
        "card_fields": "group_id name network_id current relation_revision source expires_at freshness".split(),
    }
    bounds = {"request_lifetime_seconds": 300, "peer_current_lifetime_seconds": 30,
              "max_future_skew_seconds": 30, "max_page_rows": 64,
              "max_page_canonical_bytes": 128 << 10, "max_active_groups_per_endpoint": 32,
              "max_proof_bytes": 32 << 10, "max_body_bytes": 192 << 10,
              "max_original_bytes": 256 << 10, "max_packet_bytes": 384 << 10,
              "max_reconcile_body_bytes": 640 << 10, "max_reconcile_packet_bytes": 896 << 10,
              "max_node_original_bytes": 64 << 10, "max_node_receipt_bytes": 224 << 10,
              "max_node_reconcile_body_bytes": 128 << 10, "max_node_reconcile_packet_bytes": 560 << 10,
              "max_peer_carrier_bytes": 320 << 10, "max_live_reviews_per_actor_epoch": 64,
              "read_cache_lifetime_seconds": 300, "max_cached_reads_per_actor_epoch": 128,
              "max_requests_per_actor_epoch_minute": 128, "inline_relation_limit": 8,
              "max_current_contributions_per_relation": 2, "native_context_ticket_seconds": 30}
    for key, value in bounds.items():
        assert type(g[key]) is int and g[key] == value, key
    for value in [g["contract_revision"], g["capabilities_path"], g["policy_purpose"],
                  g["node_key_purpose"], *g["http_operations"], *g["owner_request_purposes"].values()]:
        assert value in prose, value
    for marker in ("SHARED DTO + CRYPTO ONLY", "permanent manual deny",
                   "until_revoked", "Node/MCP restart", "NOT_RUN",
                   "App closure", "legacy", "past the actual lease-renewal"):
        assert marker in prose, marker
    for marker in ("Every actual Actor Guard must enforce",
                   "this source-specific five-right ceiling and current Owner-control",
                   "legacy paths and global mutations",
                   "Unknown legacy sources reject",
                   "return SHARED_MEMBERSHIP_CONFLICT or UNSUPPORTED_PROFILE without effects"):
        assert marker in prose, marker


def check():
    wire = ROOT / "cicada-go/internal/hubaccountwire"
    manifest = json.loads((wire / "owner-endpoint-contract.json").read_text())
    node = (ROOT / "cicada-go/internal/nodewire/endpoint.go").read_text() + (ROOT / "cicada-go/internal/nodewire/operator.go").read_text()
    owner = (wire / "owner_endpoint_read.go").read_text()
    crypto = (ROOT / "cicada-go/internal/e2ee/owner_endpoint_read.go").read_text()
    constants = {name: ast.literal_eval('"' + literal + '"') for name, literal in
                 re.findall(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"', node + owner + crypto)}
    assert manifest["contract_revision"] == "native-endpoint-directory-v1"
    assert manifest["wire_version"] == 1
    assert manifest["schema_changed"] is False and manifest["new_identity_tables"] is False
    assert manifest["automatic_owner_key_signing"] is False
    assert manifest["owner_capabilities_method"] == "GET"
    assert manifest["owner_capabilities_path"] == manifest["owner_read_path"]
    assert manifest["owner_capabilities_format"] == constants["OwnerEndpointReadCapabilitiesFormat"]
    assert manifest["owner_read_operation"] == constants["OperationOwnerEndpointRead"]
    assert manifest["owner_read_path"] == constants["OwnerEndpointReadPath"]
    assert manifest["owner_read_purpose"] == constants["OwnerEndpointReadPurpose"]
    assert manifest["owner_read_domain"] == constants["OwnerEndpointReadDomain"]
    assert set(manifest["node_operations"]) == {constants[x] for x in (
        "EndpointRegisterOperation", "EndpointLeaveOperation", "NativePairAvailableOperation", "EndpointDirectoryOperation")}
    profile = manifest["node_operator_profile"]
    assert profile["format"] == constants["NodeOperatorCapabilitiesFormat"]
    assert profile["contract_revision"] == constants["NodeOperatorContractRevision"]
    assert profile["query"] == "profile=" + constants["NodeOperatorProfile"]
    assert fields(node, "EndpointDirectoryCard") == profile["node_card_fields"]
    assert fields(owner, "OwnerEndpointReadRequest") == manifest["owner_request_fields"]
    assert fields(owner, "OwnerEndpointReadResult") == manifest["owner_result_fields"]
    assert fields(owner, "OwnerEndpointCard") == manifest["owner_card_fields"]
    for error in manifest["node_terminal_errors"]:
        assert f'errors.New("{error}")' in node
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    assert catalog["contract_revision"] == manifest["client_contract_revision"]
    assert len(catalog["operations"]) == manifest["client_catalog_operations"] == 55
    assert not set(manifest["node_operations"]) & {row["id"] for row in catalog["operations"]}
    assert manifest["owner_read_operation"] not in {row["id"] for row in catalog["operations"]}
    activation = (wire / "activation.go").read_text()
    allowed = re.search(r'func ActivationAllowedOperations\(\) \[\]string\s*\{(.*?)\}', activation, re.S).group(1)
    assert re.findall(r'"([^"]+)"', allowed) == manifest["old_activation_operations"]
    for relative in ("docs/native-endpoint-directory-contract.md", "docs/client-hub-wire-v1.md"):
        prose = (ROOT / relative).read_text()
        assert "native-endpoint-directory" in prose
    prose = (ROOT / "docs/native-endpoint-directory-contract.md").read_text()
    for marker in ("SNAPSHOT_ONLY", "READ_EXPIRED", "OUTCOME_UNCERTAIN", "90 seconds", "48 KiB", "before LIMIT"):
        assert marker in prose, marker
    check_owner_endpoint_groups(manifest["proposed_owner_endpoint_groups"], prose)
    assert not set(manifest["proposed_owner_endpoint_groups"]["http_operations"]) & {
        row["id"] for row in catalog["operations"]}
    assert "parseCanonicalUTC(grant.ExpiresAt)" in (ROOT / "cicada-go/internal/e2ee/owner_link_key_grant.go").read_text()
    print("owner-endpoint-groups-v1: SHARED_DTO_CRYPTO metadata PASS (availability false; product gates NOT_RUN)")
    print("native-endpoint-directory-v1: PASS (wire 1, catalog 55, old activation scope unchanged)")


if __name__ == "__main__":
    check()
