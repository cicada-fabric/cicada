import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ip_driver", Path(__file__).with_name("local-ip-pqtls-driver.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class IPDriverEvidenceTests(unittest.TestCase):
    def evidence(self, root, action, code=0):
        (root / "gate.private.jsonl").write_text(json.dumps({"Action": action, "Test": "TestIPFirstInstallOperatorCLI"}) + "\n")
        (root / "gate.exit").write_text(str(code))
        (root / "topology.json").write_text(json.dumps({"separate_node_networks": True}))

    def test_report_parses_once_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.evidence(root, "pass")
            args = SimpleNamespace(evidence=temporary, identity="cicada-ip-pq-synthetic")
            driver.report(args)
            self.assertEqual(json.loads((root / "result.json").read_text())["status"], "SCOPED_PASS")
            self.evidence(root, "fail")
            with self.assertRaises(RuntimeError):
                driver.report(args)
            self.assertEqual(json.loads((root / "result.json").read_text())["status"], "FAIL")

    def test_daemon_error_is_not_cleanup_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "result.json").write_text(json.dumps({"status": "SCOPED_PASS"}))
            args = SimpleNamespace(evidence=temporary, identity="cicada-ip-pq-synthetic")
            unavailable = subprocess.CompletedProcess([], 1, b"Cannot connect to the Docker daemon")
            with patch.object(driver, "docker", return_value=unavailable), self.assertRaises(RuntimeError):
                driver.cleanup(args)
            self.assertFalse(json.loads((root / "cleanup.json").read_text())["verified_absent"])
            self.assertEqual(json.loads((root / "result.json").read_text())["status"], "FAIL")

    def test_actual_daemon_absence_messages_require_successful_inventory(self):
        for kind, diagnostic in (("container", b"error: no such object: owned-name"),
                                 ("network", b"Error response from daemon: network owned-name not found")):
            inspected = subprocess.CompletedProcess([], 1, diagnostic)
            empty = subprocess.CompletedProcess([], 0, b"")
            with patch.object(driver, "docker", side_effect=[inspected, empty]):
                self.assertTrue(driver.absent("owned-name", "owned-id", kind)[0])
            unavailable = subprocess.CompletedProcess([], 1, b"daemon unavailable")
            with patch.object(driver, "docker", side_effect=[inspected, unavailable]):
                self.assertFalse(driver.absent("owned-name", "owned-id", kind)[0])

    def test_replaced_container_id_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = "cicada-ip-pq-synthetic"
            name = identity + "-driver"
            (root / "driver.id").write_text("original-cid\n")
            calls = []

            def command(args, timeout=40):
                calls.append(args)
                if args[0] == "inspect" and args[-1] == name:
                    return subprocess.CompletedProcess(args, 0, (identity if "Labels" in args[-2] else "replacement-cid").encode())
                if args[:2] == ["ps", "--all"]:
                    return subprocess.CompletedProcess(args, 0, ("replacement-cid " + name + "\n").encode())
                if args[:2] == ["network", "ls"]:
                    return subprocess.CompletedProcess(args, 0, b"")
                return subprocess.CompletedProcess(args, 1, b"Error: No such object")

            with patch.object(driver, "docker", side_effect=command), self.assertRaises(RuntimeError):
                driver.cleanup(SimpleNamespace(evidence=temporary, identity=identity))
            self.assertFalse(any(args[0] == "rm" for args in calls))


if __name__ == "__main__":
    unittest.main()
