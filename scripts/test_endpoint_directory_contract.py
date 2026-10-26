#!/usr/bin/env python3
"""Synthetic mutations of the proposed contract; no product/runtime execution."""
import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("endpoint_contract", ROOT / "scripts/endpoint-directory-contract.py")
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
INVENTORY = ROOT / "cicada-go/internal/hubaccountwire/owner-endpoint-contract.json"
PROSE = (ROOT / "docs/native-endpoint-directory-contract.md").read_text()


class EndpointGroupContractTests(unittest.TestCase):
    def setUp(self):
        self.group = json.loads(INVENTORY.read_text())["proposed_owner_endpoint_groups"]

    def test_shared_crypto_metadata_baseline(self):
        CONTRACT.check_owner_endpoint_groups(self.group, PROSE)

    def test_reject_unsafe_mutations(self):
        replacements = {
            "default_available": True,
            "status": "IMPLEMENTED",
            "implementation_phase": "HUB_NODE_APP",
            "legacy_finite_key_grant_allows_empty_expiry": True,
            "app_session_required_for_active_data_plane": True,
            "automatic_owner_key_signing": True,
            "mcp_join_changed": True,
            "group_creation_auto_enrolls_endpoint": True,
            "registration_identity_preserved_on_last_group_remove": False,
            "policy_revoke_withdraws_only_its_source": False,
            "normal_cold_renewal_preserves_binding_epoch": False,
            "remove_withdraws_all_relation_contributions": False,
            "native_identity_fields": self.group["native_identity_fields"] + ["endpoint_id"],
            "scope": "ALL_NODE_THREADS",
            "rights": ["*"],
            "default_duration": "1d",
            "duration_values": ["until_revoked", "1d", "7d", "30d", "forever"],
            "fixed_duration_seconds": {"1d": 86400, "7d": 604800, "30d": 2592001},
            "manual_deny_precedence": "DEFAULT_ADMISSION_WINS",
            "deny_cleared_only_by": "NEW_ATTEMPT",
            "registration_renewal_sources": ["APP_SESSION"],
            "warm_renewal": "ROTATE_CREDENTIAL_EVERY_TICK",
            "policy_purpose": "local-domain-policy:v1",
            "node_key_purpose": "local-domain-endpoint-key-grant:v1",
            "mixed_default_manual_peers": "ONE_GRANT_FOR_THE_WHOLE_NODE",
            "body_digest_domain": "cicada/owner/endpoint-groups/policy/v1\0",
            "max_live_reviews_per_actor_epoch": 65,
            "group_creation_authorized_by": "PUBLIC_CAPABILITY",
            "operation_id_source": "RESPONSE_ALLOCATED_ID",
            "status_digest_source": "LAST_STATUS_REQUEST",
            "uncertain_clears_pending": True,
            "relation_history_scope": "ACTIVE_ONLY_NO_CURSOR",
            "node_signs_projected_active_state": False,
            "native_context_fallback_to_legacy": True,
            "native_context_requires_default_policy": True,
            "pending_manual_resets_existing_active_source": True,
            "manual_expiry_default_fallback": True,
            "pending_manual_clears_deny": True,
            "owner_control_mode_reverts_to_default": True,
            "owner_control_takeover_stage": "APPLY_BEFORE_NODE_PROOF",
            "max_page_rows": 100,
            "max_active_groups_per_endpoint": 32.0,
            "peer_current_lifetime_seconds": 60,
            "max_packet_bytes": 1 << 20,
            "owner_thread_card_fields": self.group["owner_thread_card_fields"] + ["native_session_id"],
            "cas_fields": [v for v in self.group["cas_fields"] if v != "decision_revision"],
            "policy_fields": [v for v in self.group["policy_fields"] if v != "endpoint_fingerprint"],
        }
        for key, replacement in replacements.items():
            with self.subTest(key=key):
                mutated = copy.deepcopy(self.group)
                mutated[key] = replacement
                with self.assertRaises(AssertionError):
                    CONTRACT.check_owner_endpoint_groups(mutated, PROSE)

    def test_reject_wrong_route_or_body(self):
        for mutation in (
            lambda g: g["http_operations"].update({"topology.apply": "/v2/client/rpc"}),
            lambda g: g["request_bodies"]["prepare"]["ADD_ENDPOINT"].append("owner_id"),
            lambda g: g["request_bodies"]["apply"]["optional"].append("approved"),
            lambda g: g["request_bodies"]["reconcile"]["required"].append("replacement_packet"),
            lambda g: g["self_groups"].update(requires_selected_group=True),
            lambda g: g["self_groups"].update(uses_owner_inventory=True),
            lambda g: g["self_groups"]["optional"].append("endpoint_id"),
        ):
            mutated = copy.deepcopy(self.group)
            mutation(mutated)
            with self.assertRaises(AssertionError):
                CONTRACT.check_owner_endpoint_groups(mutated, PROSE)

    def test_implemented_claim_in_prose_is_not_a_pass(self):
        with self.assertRaises(AssertionError):
            CONTRACT.check_owner_endpoint_groups(self.group, PROSE.replace("SHARED DTO + CRYPTO ONLY", "IMPLEMENTED"))

    def test_reject_missing_actual_guard_boundary(self):
        for marker in ("Every actual Actor Guard must enforce",
                       "this source-specific five-right ceiling and current Owner-control",
                       "legacy paths and global mutations",
                       "Unknown legacy sources reject",
                       "return SHARED_MEMBERSHIP_CONFLICT or UNSUPPORTED_PROFILE without effects"):
            with self.subTest(marker=marker):
                with self.assertRaises(AssertionError):
                    CONTRACT.check_owner_endpoint_groups(self.group, PROSE.replace(marker, ""))


if __name__ == "__main__":
    unittest.main()
