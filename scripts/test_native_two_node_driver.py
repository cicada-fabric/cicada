"""Deterministic negative oracles; these are not native-runtime evidence."""
import importlib.util
import json
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

if __name__ == "__main__":
    unittest.main()
