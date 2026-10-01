"""Deterministic evidence and authority oracles; no model or Runtime claims."""
import importlib.util
import copy
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("network_monitor", Path(__file__).with_name("test-native-network-monitor.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class NativeToolEvidenceTests(unittest.TestCase):
    def call(self, name="cicada_join", result=None):
        return {"type": "item.completed", "item": {"type": "mcp_tool_call", "tool": name,
                "status": "completed", "result": result if result is not None else {"content": []}}}

    def test_successful_exact_calls(self):
        driver.strict_tools([self.call()], ("cicada_join",))

    def test_rpc_error_is_not_success(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([self.call(result={"isError": True})], ("cicada_join",))

    def test_cli_error_flag_is_not_success(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([self.call(result={"is_error": True})], ("cicada_join",))

    def test_missing_tool_result_rejected(self):
        event = self.call()
        del event["item"]["result"]
        with self.assertRaises(RuntimeError):
            driver.strict_tools([event], ("cicada_join",))

    def test_unexpected_shell_action_rejected(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([self.call(), {"type": "item.completed", "item": {"type": "command_execution"}}], ("cicada_join",))

    def test_duplicate_call_rejected(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([self.call(), self.call()], ("cicada_join",))

    def test_unexpected_apply_rejected(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([self.call("cicada_regroup_apply")], ("cicada_regroup_propose",))

    def test_missing_call_rejected(self):
        with self.assertRaises(RuntimeError):
            driver.strict_tools([], ("cicada_join",))

    def test_stale_and_native_epoch_remain_distinct(self):
        preview = {"network_id": "synthetic-net", "group_id": "synthetic-group", "endpoint_id": "synthetic-endpoint",
                   "endpoint_migration_state": "READY", "network_version": 4, "group_version": 8,
                   "network_membership_revision": 3, "endpoint_network_revision": 2, "membership_revision": 0,
                   "endpoint_group_revision": 0, "network_access_binding_id": "synthetic-access", "network_access_epoch": 9,
                   "native_binding_id": "synthetic-native", "native_binding_epoch": 1, "history_included": False,
                   "key_grant_created": False, "admission_roles": ["member"], "admission_grants": []}
        result = driver.admission_input(preview)
        self.assertEqual(result["network_access_epoch"], 9)
        self.assertEqual(result["native_binding_epoch"], 1)
        self.assertEqual(result["expected_group_version"], 8)
        self.assertNotIn("admission_roles", result)
        self.assertNotIn("history_included", result)


class SelfAuthorityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.monitor = {"membership_id": "synthetic-member", "version": 2}
        self.member = {"id": "synthetic-member", "version": 2, "status": "active", "role": "monitor",
                       "principal_id": "synthetic-principal", "group_id": "synthetic-group",
                       "roles_json": '["monitor"]', "grants_json": driver.json.dumps(driver.MONITOR_GRANTS)}
        self.actor = {"endpoint_id": "synthetic-endpoint", "principal_id": "synthetic-principal", "group_id": "synthetic-group",
                      "binding_id": "synthetic-binding", "binding_epoch": 1}
        self.candidate = {**self.actor, "owner_id": "synthetic-owner", "node_id": "synthetic-node",
                          "state": "CANDIDATE", "key_id": "synthetic-public-key"}

    def check(self, member=None, candidate=None, grants=()):
        driver.check_self_authority(member or self.member, self.monitor, candidate or self.candidate,
                                    self.actor, "synthetic-owner", "synthetic-node", grants)

    def test_production_monitor_self_only_candidate(self):
        self.check()

    def test_added_directory_or_traffic_grant_rejected(self):
        for grant in ("directory.read", "message.send", "*"):
            with self.subTest(grant=grant), self.assertRaises(RuntimeError):
                member = copy.deepcopy(self.member)
                member["grants_json"] = driver.json.dumps(driver.MONITOR_GRANTS + [grant])
                self.check(member=member)

    def test_stale_or_changed_membership_rejected(self):
        for key, value in (("version", 3), ("id", "other-member"), ("status", "revoked"), ("role", "owner"),
                           ("principal_id", "other-principal"), ("group_id", "other-group")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.check(member={**self.member, key: value})

    def test_wrong_candidate_identity_binding_or_state_rejected(self):
        for key, value in (("endpoint_id", "peer"), ("owner_id", "other-owner"), ("node_id", "other-node"),
                           ("binding_epoch", 2), ("state", "TRUSTED"), ("key_id", "")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.check(candidate={**self.candidate, key: value})

    def test_candidate_is_not_owner_consent(self):
        with self.assertRaises(RuntimeError):
            self.check(grants=[{"id": "synthetic-key-grant"}])

    def test_durable_send_permission_failure_is_a_denial(self):
        driver.check_send_denied({"status": "FAILED", "retryable": False, "attempts": 1,
                                  "error": "Cicada Hub 403 Forbidden: fabric permission denied"})

    def test_queued_success_or_other_send_error_is_not_a_permission_denial(self):
        expected = {"status": "FAILED", "retryable": False, "attempts": 1,
                    "error": "Cicada Hub 403 Forbidden: fabric permission denied"}
        for key, value in (("status", "QUEUED"), ("status", "SENT"), ("retryable", True), ("attempts", 2),
                           ("error", "network timeout")):
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                driver.check_send_denied({**expected, key: value})


if __name__ == "__main__":
    unittest.main()
