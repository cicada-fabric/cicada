"""Deterministic negative oracles; these are not native-runtime evidence."""
import importlib.util
import json
import copy
import hashlib
import os
import subprocess
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import tempfile

spec = importlib.util.spec_from_file_location("two_node_driver", Path(__file__).with_name("test-two-node-codex-native.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
THREAD = "01999d8a-2833-7356-b50e-1023a845852e"
OTHER = "01999d8a-2833-7356-b50e-1023a845852f"


class NativeWitnessTests(unittest.TestCase):
    def events(self, status="completed", thread=THREAD):
        return [{"type": "thread.started", "thread_id": thread},
                {"type": "item.completed", "item": {"type": "mcp_tool_call", "tool": "cicada_receive", "status": status}},
                {"type": "item.completed", "item": {"type": "agent_message", "text": "original synthetic context witness"}}]

    def test_exact_original_identity_and_context(self):
        witness = driver.turn_witness(self.events(), THREAD, ("cicada_receive",), ("synthetic context",))
        self.assertTrue(witness["same_original_thread"])

    def test_replacement_thread_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "native_thread_changed"):
            driver.turn_witness(self.events(thread=OTHER), THREAD)

    def test_synthetic_non_uuid_thread_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "native_thread_event_invalid"):
            driver.turn_witness(self.events(thread="synthetic-thread"))

    def test_failed_tool_is_not_consumption(self):
        with self.assertRaisesRegex(RuntimeError, "required_native_tool_not_completed"):
            driver.turn_witness(self.events(status="failed"), THREAD, ("cicada_receive",))

    def test_marker_in_tool_result_is_not_context_witness(self):
        events = self.events()
        events[-1]["item"]["text"] = "no remembered context"
        events[1]["item"]["result"] = {"text": "original synthetic context witness"}
        with self.assertRaisesRegex(RuntimeError, "original_context_witness_missing"):
            driver.turn_witness(events, THREAD, markers=("synthetic context witness",))

    def test_duplicate_thread_started_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "native_thread_event_invalid"):
            driver.turn_witness(self.events() + [{"type": "thread.started", "thread_id": THREAD}])

    def test_non_json_diagnostic_does_not_create_thread_evidence(self):
        data = b"WARNING: not evidence\n" + json.dumps(self.events()[0]).encode() + b"\n"
        self.assertEqual(driver.parse_events(data), [self.events()[0]])



monitor_spec = importlib.util.spec_from_file_location("monitor_driver", Path(__file__).with_name("test-native-monitor-regroup.py"))
monitor = importlib.util.module_from_spec(monitor_spec)
monitor_spec.loader.exec_module(monitor)


class MonitorWaitTests(unittest.TestCase):
    def fixture(self, root, state):
        group_input = root / "groups.json"
        group_input.write_text('{}')
        local = root / "nodes" / "node-synthetic-test"
        local.mkdir(parents=True)
        (local / "node-control-state.json").write_text(json.dumps(state))
        (local / "relay.token").write_text('synthetic-not-authority')
        gate = object.__new__(monitor.AttachGate)
        gate.nodes = {"a": {"node_id": "synthetic-test", "paths": {"state": root}}}
        gate.public = {"hub_id": "synthetic-hub"}
        gate.args = SimpleNamespace(wait_seconds=1, groups_file=str(group_input), marker='unused', public='unused')
        return gate

    def test_metadata_and_token_do_not_prove_owner_confirmation(self):
        with tempfile.TemporaryDirectory() as name:
            gate = self.fixture(Path(name), {})
            with patch.object(monitor.time, 'sleep', side_effect=InterruptedError), patch.object(monitor, 'verify_client_fixture') as verify:
                with self.assertRaises(InterruptedError):
                    gate.wait_actual_pairing()
                verify.assert_not_called()

    def test_wait_interval_retains_pending_identity(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            gate = self.fixture(root, {})
            with patch.object(monitor.time, 'monotonic', side_effect=[0, 2, 2]), patch.object(monitor.time, 'sleep', side_effect=InterruptedError), patch('builtins.print') as output:
                with self.assertRaises(InterruptedError):
                    gate.wait_actual_pairing()
                self.assertTrue(json.loads(output.call_args.args[0])['resources_retained'])
                self.assertTrue((root / 'nodes/node-synthetic-test/node-control-state.json').exists())

    def test_actual_binding_rechecks_fixture_before_proceeding(self):
        with tempfile.TemporaryDirectory() as name:
            gate = self.fixture(Path(name), {'hub_id': 'synthetic-hub', 'binding_id': 'synthetic-binding', 'binding_version': 1})
            with patch.object(monitor, 'verify_client_fixture') as verify, patch.object(monitor.time, 'sleep') as sleep:
                gate.wait_actual_pairing()
                verify.assert_called_once()
                sleep.assert_not_called()


class ExactDeliveredPairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-two-node-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hub = "sha256:" + "1" * 64; self.interop = "sha256:" + "2" * 64
        self.source = {"revision": "3" * 40, "dirty": False, "source_fingerprint": "4" * 64,
                       "catalog_sha256": "5" * 64, "input_inventory": {
                           "schema_version": "cicada.hub-build-input-inventory.v1",
                           "source_fingerprint_v4": {"sha256": "4" * 64}, "entries": [{"path": "synthetic-code"}]}}
        self.metadata = {"schema_version": "cicada.hub-build.v1", "transport_variant": "standard",
                         "pqtls_available": False, "source": self.source,
                         "image": {"id": self.hub, "dockerfile": "docker/Dockerfile.hub"},
                         "test_image": {"id": self.interop}}
        self.labels = {"org.opencontainers.image.revision": "3" * 40, "org.cicada.build.dirty": "false",
                       "org.cicada.build.source-fingerprint": "4" * 64, "org.cicada.client-catalog.sha256": "5" * 64}

    def gate(self, wrong_interop=False, wrong_go=False):
        gate = object.__new__(driver.Gate)
        data = json.dumps(self.metadata).encode(); metadata = self.root / "producer.json"; metadata.write_bytes(data)
        gate.args = SimpleNamespace(exact_clean_image_metadata=str(metadata),
                                    exact_clean_image_metadata_sha256=hashlib.sha256(data).hexdigest(),
                                    runtime_image=driver.RUNTIME, run_native=False)
        gate.root = self.root; gate.repo = self.root; gate.run_id = "synthetic-owned-pair"
        gate.containers = {}; gate.images = {}; gate.calls = []
        gate.result = {"acceptance_mode": "exact-clean-image-pair"}
        gate.step = lambda name: None
        def command(argv, **kwargs):
            self.assertIn("--source-info-only", argv)
            Path(argv[-1]).write_text(json.dumps({"source": self.source}))
        gate.command = command
        def inspect(kind, name):
            labels = copy.deepcopy(self.labels)
            if name == self.hub: labels["org.cicada.role"] = "hub"
            if name == self.interop:
                labels["org.opencontainers.image.title"] = "CICADA Hub interop test runner"
                if wrong_interop: labels["org.cicada.build.source-fingerprint"] = "6" * 64
            return {"Id": name, "Config": {"Labels": labels}}
        gate.inspect = inspect
        def docker(*argv, **kwargs):
            gate.calls.append(argv)
            self.assertNotIn(argv[0], ("build", "tag", "start", "exec"))
            if argv[0] == "cp":
                self.assertIn(":/usr/local/bin/cicada", argv[1]); binary = Path(argv[-1])
                binary.write_bytes(b"synthetic-delivered-hub-binary"); binary.chmod(0o700)
            if argv[0] == "run":
                self.assertIn("none", argv); self.assertIn(self.interop, argv)
                if argv[-1] == "version":
                    return b"go version go0.0.0 linux/amd64" if wrong_go else b"go version go1.27.1 linux/amd64"
                self.assertEqual(argv[-1], "./cmd/cicada-v68fixture")
                self.assertNotIn("./cmd/cicada", argv)
                (self.root / "cicada-v68fixture").write_bytes(b"synthetic-approved-owner-fixture")
            return b""
        gate.docker = docker
        return gate

    def test_exact_pair_only_compiles_fixture_and_never_overlays_or_owns_shared_images(self):
        gate = self.gate(); gate.build()
        self.assertEqual((gate.hub_image, gate.test_image), (self.hub, self.interop))
        self.assertEqual(gate.images, {})
        self.assertEqual(gate.containers, {gate.run_id + "-extract": self.hub})
        self.assertEqual(gate.result["cicada_binary_sha256"], hashlib.sha256(b"synthetic-delivered-hub-binary").hexdigest())
        self.assertTrue(gate.result["fixture_provenance"]["synthetic_owner_only"])
        self.assertFalse(gate.result["binary_provenance"]["hub_overlay"])
        self.assertEqual(gate.result["fixture_go_version"], "go version go1.27.1 linux/amd64")

    def test_wrong_actual_interop_rejected_before_extract_or_compile(self):
        gate = self.gate(wrong_interop=True)
        with self.assertRaises(RuntimeError): gate.build()
        self.assertEqual(gate.calls, [])

    def test_wrong_actual_go_version_rejected_without_fixture_compile(self):
        gate = self.gate(wrong_go=True)
        with self.assertRaisesRegex(RuntimeError, "actual_interop_go_toolchain_not_pinned"): gate.build()
        self.assertFalse((self.root / "cicada-v68fixture").exists())

    def test_missing_mutable_or_same_interop_id_rejected(self):
        for image in ({}, {"id": "mutable:tag"}, {"id": self.hub}):
            with self.subTest(image=image), self.assertRaises(RuntimeError):
                driver.image_evidence.check_clean_pair({**self.metadata, "test_image": image}, self.source)

    def test_each_interop_label_is_exact(self):
        labels = {**self.labels, "org.opencontainers.image.title": "CICADA Hub interop test runner"}
        driver.image_evidence.check_clean_image(self.metadata, {"Id": self.interop, "Config": {"Labels": labels}}, "interop")
        for key in labels:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.image_evidence.check_clean_image(self.metadata,
                    {"Id": self.interop, "Config": {"Labels": {**labels, key: "synthetic-wrong"}}}, "interop")

    def preparation(self):
        return {"status": "PREPARATION_PASS_NATIVE_NOT_RUN", "terminal_exit_code": 0, "models_invoked": 0,
                "native_model_turn_attempts": 0, "cleanup_owned_resources": True, "source_unchanged_during_gate": True,
                "build": self.metadata, "acceptance_mode": "exact-clean-image-pair", "script_sha256": "6" * 64,
                "image_evidence_helper_sha256": "7" * 64, "cicada_binary_sha256": "8" * 64,
                "fixture_binary_sha256": "9" * 64, "runtime_image_id": driver.RUNTIME,
                "hub_image_id": self.hub, "interop_image_id": self.interop, "producer_metadata_sha256": "a" * 64}

    def test_paid_preparation_mix_and_false_protocol_preflight_rejected(self):
        result = self.preparation(); driver.image_evidence.check_preparation(copy.deepcopy(result), result)
        for key in ("acceptance_mode", "script_sha256", "image_evidence_helper_sha256", "cicada_binary_sha256",
                    "fixture_binary_sha256", "runtime_image_id", "hub_image_id", "interop_image_id", "producer_metadata_sha256"):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.image_evidence.check_preparation({**result, key: "synthetic-wrong"}, result)
        for key, value in (("status", "PREFLIGHT_PASS_NATIVE_NOT_RUN"), ("models_invoked", 1), ("terminal_exit_code", 1),
                           ("native_model_turn_attempts", 1), ("cleanup_owned_resources", False), ("source_unchanged_during_gate", False)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.image_evidence.check_preparation({**result, key: value}, result)

    def test_actual_pair_health_requires_clean_revision_catalog(self):
        result = self.preparation(); health = {k:self.source[k] for k in ("revision", "dirty", "source_fingerprint", "catalog_sha256")}
        driver.image_evidence.check_hub_provenance(health, result)
        for key, value in (("dirty", True), ("revision", "b" * 40), ("catalog_sha256", "c" * 64)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                driver.image_evidence.check_hub_provenance({**health, key:value}, result)

    def test_budget_seven_rejects_eighth_and_first_failure_is_not_retried(self):
        gate = object.__new__(driver.Gate)
        gate.result = {"schema": "cicada.two-node-native.v1", "native_model_turn_attempts": 7}
        with self.assertRaisesRegex(RuntimeError, "native_seven_turn_budget_exceeded"):
            gate.native_turn("a", "synthetic")
        gate.result = {"schema": "cicada.two-node-native.v1", "native_model_turn_attempts": 0}
        gate.nodes = {"a": {}}
        with patch.object(gate, "native_config", side_effect=RuntimeError("synthetic terminal")) as call:
            with self.assertRaisesRegex(RuntimeError, "synthetic terminal"): gate.native_turn("a", "synthetic")
            call.assert_called_once()
        self.assertEqual(gate.result["native_model_turn_attempts"], 1)

    def test_timeout_is_terminal_and_argv_retained_without_retry(self):
        gate = object.__new__(driver.Gate); gate.result = {"steps": []}; gate.phase = "synthetic-unit"
        argv = ["synthetic-owned-command", "safe-arg"]
        with patch.object(driver.subprocess, "run", side_effect=subprocess.TimeoutExpired(argv, 1)) as call:
            with self.assertRaisesRegex(RuntimeError, "command_timeout_terminal_no_retry"): gate.command(argv, timeout=1)
            call.assert_called_once()
        self.assertEqual(gate.result["steps"][0]["argv"], argv)
        self.assertTrue(gate.result["steps"][0]["timed_out"])

if __name__ == "__main__":
    unittest.main()
