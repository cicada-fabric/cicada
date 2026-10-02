"""Deterministic evidence and authority oracles; no model or Runtime claims."""
import importlib.util
import copy
import hashlib
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock
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


class ExactCleanImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cicada-native-driver-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = "sha256:" + "1" * 64
        self.source = {"revision": "2" * 40, "dirty": False, "source_fingerprint": "3" * 64,
                       "catalog_sha256": "4" * 64,
                       "input_inventory": {"schema_version": "cicada.hub-build-input-inventory.v1",
                                           "source_fingerprint_v4": {"sha256": "3" * 64},
                                           "entries": [{"path": "synthetic-code", "content_sha256": "5" * 64}]}}
        self.metadata = {"schema_version": "cicada.hub-build.v1", "transport_variant": "standard",
                         "pqtls_available": False, "source": self.source,
                         "image": {"id": self.image, "dockerfile": "docker/Dockerfile.hub"}}
        self.labels = {"org.opencontainers.image.revision": "2" * 40, "org.cicada.build.dirty": "false",
                       "org.cicada.build.source-fingerprint": "3" * 64,
                       "org.cicada.client-catalog.sha256": "4" * 64, "org.cicada.role": "hub"}

    def inspected(self):
        return {"Id": self.image, "Config": {"Labels": copy.deepcopy(self.labels)}}

    def test_clean_receipt_and_current_input_closure(self):
        current = {**self.source, "dirty": True}  # Driver-only worktree overlay is independently attributed.
        self.assertEqual(driver.check_clean_producer(self.metadata, current), self.image)
        driver.check_clean_image(self.metadata, self.inspected())

    def test_dirty_wrong_kind_or_nonimmutable_producer_rejected(self):
        changes = (("schema_version", "wrong"), ("transport_variant", "pqtls"), ("pqtls_available", True))
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.check_clean_producer({**self.metadata, key: value}, self.source)
        for dirty in (True, "false", 0, None):
            with self.subTest(dirty=dirty), self.assertRaises(RuntimeError):
                driver.check_clean_producer({**self.metadata, "source": {**self.source, "dirty": dirty}}, self.source)
        with self.assertRaises(RuntimeError):
            driver.check_clean_producer({**self.metadata, "image": {**self.metadata["image"], "id": "mutable:tag"}}, self.source)

    def test_wrong_revision_catalog_fingerprint_or_inventory_rejected(self):
        for key in ("revision", "source_fingerprint", "catalog_sha256", "input_inventory"):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.check_clean_producer(self.metadata, {**self.source, key: "synthetic-wrong"})
        wrong = copy.deepcopy(self.source)
        wrong["input_inventory"]["source_fingerprint_v4"]["sha256"] = "6" * 64
        with self.assertRaises(RuntimeError):
            driver.check_clean_producer({**self.metadata, "source": wrong}, wrong)

    def test_image_id_and_each_authoritative_label_are_exact(self):
        with self.assertRaises(RuntimeError):
            driver.check_clean_image(self.metadata, {**self.inspected(), "Id": "sha256:" + "9" * 64})
        for key in self.labels:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                inspected = self.inspected()
                inspected["Config"]["Labels"][key] = "synthetic-wrong"
                driver.check_clean_image(self.metadata, inspected)

    def test_full_receipt_sha_and_canonical_regular_path_required(self):
        path = self.root / "producer.json"
        data = json.dumps(self.metadata).encode()
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(driver.read_clean_producer(path, digest), self.metadata)
        with self.assertRaises(RuntimeError):
            driver.read_clean_producer(path, "0" * 64)
        link = self.root / "producer-link.json"
        link.symlink_to(path)
        with self.assertRaises(RuntimeError):
            driver.read_clean_producer(link, digest)
        path.write_bytes(b"malformed")
        with self.assertRaises(RuntimeError):
            driver.read_clean_producer(path, hashlib.sha256(b"malformed").hexdigest())

    def result(self):
        return {"status": "PREFLIGHT_PASS_NATIVE_NOT_RUN", "terminal_exit_code": 0, "models_invoked": 0,
                "native_model_turn_attempts": 0, "cleanup_owned_resources": True, "source_unchanged_during_gate": True,
                "build": self.metadata, "acceptance_mode": "exact-clean-image", "script_sha256": "5" * 64,
                "shared_driver_sha256": "6" * 64, "cicada_binary_sha256": "7" * 64,
                "operator_binary_sha256": "8" * 64, "runtime_image_id": driver.native.RUNTIME,
                "go_image_id": "sha256:" + "9" * 64, "hub_image_id": self.image,
                "producer_metadata_sha256": "a" * 64, "image_evidence_helper_sha256": "e" * 64}

    def test_preflight_mix_wrong_driver_binary_image_runtime_or_mode_rejected(self):
        result = self.result()
        driver.check_matching_preflight(copy.deepcopy(result), result)
        for key in ("acceptance_mode", "script_sha256", "shared_driver_sha256", "cicada_binary_sha256",
                    "operator_binary_sha256", "runtime_image_id", "go_image_id", "hub_image_id", "producer_metadata_sha256", "image_evidence_helper_sha256"):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.check_matching_preflight({**result, key: "synthetic-wrong"}, result)
        for key, value in (("terminal_exit_code", 1), ("models_invoked", 1), ("native_model_turn_attempts", 1),
                           ("cleanup_owned_resources", False), ("source_unchanged_during_gate", False)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.check_matching_preflight({**result, key: value}, result)
        prior = copy.deepcopy(result)
        prior["build"]["source"]["revision"] = "b" * 40
        with self.assertRaises(RuntimeError):
            driver.check_matching_preflight(prior, result)

    def test_derived_preflight_is_separately_labeled_and_binds_base_not_unique_fixture_image(self):
        result = {**self.result(), "acceptance_mode": "derived-source-fixture", "hub_base_image_id": "sha256:" + "b" * 64}
        prior = {**result, "hub_image_id": "sha256:" + "c" * 64}
        driver.check_matching_preflight(prior, result)
        with self.assertRaises(RuntimeError):
            driver.check_matching_preflight({**prior, "hub_base_image_id": "sha256:" + "d" * 64}, result)

    def gate(self, bad_labels=False, bad_binary=False):
        gate = object.__new__(driver.Gate)
        path = self.root / "producer.json"
        data = json.dumps(self.metadata).encode(); path.write_bytes(data)
        gate.args = SimpleNamespace(exact_clean_image_metadata=str(path),
                                    exact_clean_image_metadata_sha256=hashlib.sha256(data).hexdigest(),
                                    runtime_image=driver.native.RUNTIME, run_native=False)
        gate.repo = self.root; gate.root = self.root; gate.run_id = "synthetic-owned-unit"
        gate.containers = {}; gate.images = {}; gate.result = {}; gate.steps = []
        gate.step = lambda name: None
        def command(argv, **kwargs):
            self.assertIn("--source-info-only", argv)
            Path(argv[-1]).write_text(json.dumps({"source": self.source}))
        gate.command = command
        def inspect(kind, name):
            if name == self.image:
                row = self.inspected()
                if bad_labels: row["Config"]["Labels"]["org.cicada.build.dirty"] = "true"
                return row
            return {"Id": driver.native.RUNTIME if name == driver.native.RUNTIME else "sha256:" + "9" * 64}
        gate.inspect = inspect
        def docker(*argv, **kwargs):
            gate.steps.append(argv)
            self.assertNotIn(argv[0], ("build", "tag", "start", "run"))
            if argv[0] == "cp":
                binary = Path(argv[-1])
                if bad_binary: binary.symlink_to(path)
                else: binary.write_bytes(b"synthetic-image-binary"); binary.chmod(0o700)
        gate.docker = docker
        def go(*argv, **kwargs):
            gate.steps.append(("go", *argv))
            self.assertEqual(argv, ("build", "-trimpath", "-o", "/fixture/operator", "./cmd/cicada-native-network-fixture"))
            (self.root / "operator").write_bytes(b"synthetic-operator-fixture")
        gate.go = go
        return gate

    def test_exact_branch_never_rebuilds_or_overlays_hub_and_only_owns_extract_container(self):
        gate = self.gate()
        gate.build()
        self.assertEqual(gate.hub_image, self.image)
        self.assertEqual(gate.images, {})  # Shared immutable image never reaches image-removal cleanup.
        self.assertEqual(gate.containers, {gate.run_id + "-extract": self.image})
        self.assertEqual(gate.result["binary_provenance"]["origin"], "immutable-delivered-image")
        self.assertFalse(gate.result["binary_provenance"]["rebuilt"])
        self.assertFalse((self.root / "Dockerfile").exists())
        self.assertEqual(gate.result["cicada_binary_sha256"], hashlib.sha256(b"synthetic-image-binary").hexdigest())
        create = gate.steps[0]
        self.assertIn("org.cicada.test.run=" + gate.run_id, create)
        self.assertIn("--read-only", create)
        self.assertIn("none", create)
        self.assertEqual(create[-1], self.image)

    def test_bad_image_is_rejected_before_any_extract_or_fixture_compile(self):
        gate = self.gate(bad_labels=True)
        with self.assertRaises(RuntimeError): gate.build()
        self.assertEqual(gate.steps, [])
        self.assertEqual(gate.images, {})
        self.assertEqual(gate.containers, {})

    def test_symlink_extracted_binary_fails_without_operator_compile(self):
        gate = self.gate(bad_binary=True)
        with self.assertRaises(RuntimeError): gate.build()
        self.assertFalse(any(step[0] == "go" for step in gate.steps))
        self.assertEqual(gate.images, {})

    def test_live_hub_provenance_rejects_dirty_or_transplanted_exact_image(self):
        result = self.result()
        health = {key: self.source[key] for key in ("revision", "dirty", "source_fingerprint", "catalog_sha256")}
        driver.check_hub_provenance(health, result)
        for key, value in (("dirty", True), ("revision", "b" * 40), ("source_fingerprint", "c" * 64),
                           ("catalog_sha256", "d" * 64)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.check_hub_provenance({**health, key: value}, result)
        derived = {**result, "acceptance_mode": "derived-source-fixture"}
        driver.check_hub_provenance({**health, "dirty": True}, derived)
        with self.assertRaises(RuntimeError): driver.check_hub_provenance(health, derived)

    def test_cleanup_removes_only_verified_owned_container_never_delivered_image(self):
        gate = object.__new__(driver.Gate)
        gate.run_id = "synthetic-owned-unit"
        gate.root = self.root / "fixture"; gate.root.mkdir()
        gate.evidence = self.root / "evidence"; gate.evidence.mkdir()
        gate.forwarders = []; gate.networks = []; gate.images = {}
        gate.containers = {"synthetic-owned-extract": self.image, "synthetic-foreign": self.image}
        gate.result = {"status": "synthetic-unit"}
        def inspect(argv, **kwargs):
            name = argv[-1]
            owner = gate.run_id if name == "synthetic-owned-extract" else "synthetic-other-owner"
            return json.dumps([{ "Config": {"Labels": {"org.cicada.test.run": owner}}, "Image": self.image}]).encode()
        with mock.patch.object(driver.native.subprocess, "check_output", side_effect=inspect), \
                mock.patch.object(driver.native.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as remove:
            driver.native.Gate.cleanup(gate)
            remove.assert_called_once_with(["docker", "rm", "-f", "synthetic-owned-extract"], stdout=driver.native.subprocess.DEVNULL)
        self.assertFalse(gate.result["cleanup_owned_resources"])
        self.assertEqual(gate.result["status"], "FAIL")
        self.assertTrue((gate.evidence / "result.json").is_file())

    def test_three_turn_budget_has_no_retry(self):
        gate = object.__new__(driver.Gate)
        gate.result = {"native_model_turn_attempts": 3}
        with mock.patch.object(driver.native.Gate, "native_turn") as turn:
            with self.assertRaises(RuntimeError): gate.native_turn("a", "synthetic")
            turn.assert_not_called()
        gate.result = {"native_model_turn_attempts": 0}
        with mock.patch.object(driver.native.Gate, "native_turn", side_effect=RuntimeError("synthetic terminal")) as turn:
            with self.assertRaises(RuntimeError): gate.native_turn("a", "synthetic")
            turn.assert_called_once()
        self.assertEqual(gate.result["native_model_turn_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
