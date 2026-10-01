"""Unit tests for the unified driver's Node-Control child status parser."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from completion_driver_status import classify


SCHEMA = "cicada.node-control-v1-http-flow.v1"


class CompletionDriverStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cicada-driver-status-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.result = self.root / "result.json"

    def write_result(self, status: str) -> None:
        self.result.write_text(json.dumps({"schema_version": SCHEMA, "status": status}), encoding="utf-8")

    def test_pass_marker_and_json_with_zero_exit(self) -> None:
        self.write_result("PASS")
        value = classify(f"PASS: {self.result}\n", 0)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["result_path"], str(self.result))

    def test_not_run_marker_and_json_remains_not_run(self) -> None:
        self.write_result("NOT_RUN")
        self.assertEqual(classify(f"NOT_RUN: {self.result}\n", 0)["status"], "NOT_RUN")

    def test_missing_result_fails(self) -> None:
        value = classify(f"PASS: {self.result}\n", 0)
        self.assertEqual(value["status"], "FAIL")
        self.assertIn("missing", value["reason"])

    def test_marker_json_disagreement_fails(self) -> None:
        self.write_result("NOT_RUN")
        value = classify(f"PASS: {self.result}\n", 0)
        self.assertEqual(value["status"], "FAIL")
        self.assertIn("disagree", value["reason"])

    def test_pass_with_nonzero_exit_fails(self) -> None:
        self.write_result("PASS")
        value = classify(f"PASS: {self.result}\n", 2)
        self.assertEqual(value["status"], "FAIL")
        self.assertIn("exited 2", value["reason"])


if __name__ == "__main__":
    unittest.main()
