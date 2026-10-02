import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("task_privacy_gate", Path(__file__).with_name("test-task-peer-privacy.py"))
gate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate_module)


class GateTests(unittest.TestCase):
    def test_private_output_is_hashed_without_retaining_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = gate_module.Gate(root, root, root)
            gate.secrets.append("synthetic-fixture-token")
            for data in (b"synthetic-fixture-token", gate_module.SENTINELS[0].encode(),
                         b"-----BEGIN PRIVATE KEY-----"):
                report = gate.safe_output("private", "stdout", data)
                self.assertFalse(report["retained"])
                self.assertFalse((root / "private.stdout").exists())
            self.assertFalse(gate.secret_scan_passed)
            report = gate.safe_output("public", "stdout", b"bounded guard denied")
            self.assertTrue(report["retained"])
            self.assertEqual((root / "public.stdout").read_bytes(), b"bounded guard denied")

    def test_timeout_records_command_and_unknown_actual_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = gate_module.Gate(root, root, root)
            argv = ["docker", "run", "--label", gate_module.LABEL + "=" + gate.owner]
            with mock.patch.object(gate_module.subprocess, "run", side_effect=subprocess.TimeoutExpired(argv, 2, output=b"bounded diagnostic")):
                with self.assertRaises(RuntimeError):
                    gate.run(argv, timeout=2)
            report = json.loads((root / "commands.json").read_text())[0]
            self.assertEqual(report["argv"], argv)
            self.assertTrue(report["timed_out"])
            self.assertIsNone(report["exit_code"])
            self.assertEqual((root / "command-000.stdout").read_bytes(), b"bounded diagnostic")

    def test_cleanup_discovers_unregistered_network_but_refuses_foreign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = gate_module.Gate(root, root, root)
            own = "task-privacy-" + gate.owner + "-net"
            foreign = "task-privacy-foreign-net"
            calls = []

            def docker(args, **kwargs):
                calls.append(args)
                output = b""
                if args[:2] == ["network", "ls"]:
                    output = (own + "\n" + foreign + "\n").encode()
                return subprocess.CompletedProcess(args, 0, output, b"")

            with mock.patch.object(gate, "docker", side_effect=docker), mock.patch.object(gate, "verify_owned", side_effect=lambda kind, name: name == own):
                gate.cleanup()
            self.assertIn(["network", "rm", own], calls)
            self.assertNotIn(["network", "rm", foreign], calls)
            self.assertEqual(len(gate.cleanup_errors), 1)
            self.assertIn("ownership verification", gate.cleanup_errors[0])

    def test_real_label_and_name_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = gate_module.Gate(root, root, root)
            name = "task-privacy-" + gate.owner + "-hub"
            for labels, actual_name, expected in (({gate_module.LABEL: gate.owner}, name, True),
                                                  ({gate_module.LABEL: "foreign"}, name, False),
                                                  ({gate_module.LABEL: gate.owner}, "foreign", False)):
                result = subprocess.CompletedProcess([], 0, json.dumps([{"Name": "/" + actual_name, "Config": {"Labels": labels}}]).encode(), b"")
                with mock.patch.object(gate, "docker", return_value=result):
                    self.assertEqual(gate.verify_owned("container", name), expected)

    def test_inventory_detects_bytes_and_raw_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "file"
            path.write_bytes(b"original")
            path.chmod(0o600)
            result = subprocess.CompletedProcess([], 0, b"file\0", b"")
            with mock.patch.object(gate_module.subprocess, "run", return_value=result):
                before = gate_module.source_inventory(root)
                path.chmod(0o640)
                self.assertNotEqual(before, gate_module.source_inventory(root))
                path.chmod(0o600)
                path.write_bytes(b"different")
                self.assertNotEqual(before, gate_module.source_inventory(root))

    def test_fixture_credentials_recursive_scan_has_no_prose_record(self):
        tokens = gate_module.find_tokens({"node_token": "synthetic-node", "session": [{"Token": "synthetic-session"}], "objective": "private"})
        self.assertEqual(tokens, ["synthetic-node", "synthetic-session"])

    def test_sticky_secret_failure_still_cleans_owned_resources_and_reports_fail(self):
        for include_foreign in (False, True):
            with self.subTest(include_foreign=include_foreign), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".cicada-data/task-privacy").mkdir(parents=True)
                evidence = root / "evidence"
                owner = "synthetic-owner"
                container = "task-privacy-" + owner + "-node"
                network = "task-privacy-" + owner + "-net"
                foreign = "task-privacy-foreign-net"
                calls = []

                def run(argv, **kwargs):
                    calls.append(argv)
                    args = argv[1:]
                    output = b""
                    if args[:2] == ["image", "inspect"]:
                        output = json.dumps([{"Id": gate_module.IMAGE}]).encode()
                    elif args[:2] == ["ps", "-a"]:
                        output = (container + "\n").encode()
                    elif args[:2] == ["network", "ls"]:
                        names = [network, foreign] if include_foreign else [network]
                        output = ("\n".join(names) + "\n").encode()
                    elif args[:2] == ["container", "inspect"]:
                        output = json.dumps([{"Name": "/" + container, "Config": {"Labels": {gate_module.LABEL: owner}}}]).encode()
                    elif args[:2] == ["network", "inspect"]:
                        name = args[2]
                        output = json.dumps([{"Name": name, "Labels": {gate_module.LABEL: owner if name == network else "foreign"}}]).encode()
                    return subprocess.CompletedProcess(argv, 0, output, b"")

                def fixture(gate, artifacts, private, public):
                    # A fixture output is suppressed before cleanup begins. The
                    # sticky failure must never disable the cleanup subprocesses.
                    output = gate.safe_output("fixture", "stdout", gate_module.SENTINELS[0].encode())
                    self.assertFalse(output["retained"])
                    self.assertFalse(gate.secret_scan_passed)
                    return {"node-initial-report.json": {"cases": []}, "node-restart-report.json": {"cases": []}}

                args = mock.Mock(root=root, evidence=evidence, module_cache=root, image=gate_module.IMAGE)
                with mock.patch.object(gate_module.uuid, "uuid4", return_value=mock.Mock(hex=owner)), \
                     mock.patch.object(gate_module, "source_inventory", return_value={"synthetic-file": {"sha256": "synthetic", "raw_mode": 0o100600, "size": 0}}), \
                     mock.patch.object(gate_module.subprocess, "run", side_effect=run), \
                     mock.patch.object(gate_module.Gate, "build", return_value=None), \
                     mock.patch.object(gate_module.Gate, "fixtures", fixture), \
                     mock.patch("builtins.print"):
                    self.assertEqual(gate_module.execute(args), 1)
                self.assertIn(["docker", "rm", "-f", container], calls)
                self.assertIn(["docker", "network", "rm", network], calls)
                self.assertNotIn(["docker", "network", "rm", foreign], calls)
                self.assertFalse((evidence / "fixture.stdout").exists())
                report = json.loads((evidence / "report.json").read_text())
                self.assertEqual(report["status"], "FAIL")
                self.assertFalse(report["secret_scan_passed"])
                self.assertTrue(report["source_unchanged"])
                self.assertTrue(report["private_fixture_removed"])
                self.assertEqual(report["cleanup_passed"], not include_foreign)
                self.assertEqual(len(report["cleanup_errors"]), int(include_foreign))


if __name__ == "__main__":
    unittest.main()
