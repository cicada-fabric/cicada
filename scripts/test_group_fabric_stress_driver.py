#!/usr/bin/env python3
"""Offline contract tests for the group-fabric stress driver input receipt."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "scripts" / "test-group-fabric-stress.py"
SPEC = importlib.util.spec_from_file_location("group_fabric_stress_driver", DRIVER_PATH)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def row(identity: str, **changes):
    value = {
        "id": identity,
        "status": "running",
        "image": "sha256:" + "a" * 64,
        "pid": 1234,
        "started_at": "2026-10-10T00:00:00.000000000Z",
        "restart_count": 0,
    }
    value.update(changes)
    return value


class ProtectedResidentReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="group-fabric-driver-", dir=ROOT / ".cicada-data")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        os.chmod(self.directory, 0o700)

    def write_receipt(self, value, *, raw: bytes | None = None) -> Path:
        path = self.directory / "residents.json"
        path.write_bytes(raw if raw is not None else json.dumps(value, sort_keys=True).encode())
        path.chmod(0o600)
        return path

    def load(self, value):
        return DRIVER.load_protected_residents(self.write_receipt(value))

    def test_accepts_empty_one_and_six_resident_maps(self):
        self.assertEqual(self.load({})[0], {})
        one = {"1" * 64: row("1" * 64)}
        loaded_one, _, _ = self.load(one)
        self.assertEqual(loaded_one["1" * 64], {
            "id": "1" * 64, "image_id": "sha256:" + "a" * 64,
            "host_pid": 1234, "started_at": "2026-10-10T00:00:00.000000000Z",
            "restart_count": 0, "running": True,
        })
        six = {f"{index:064x}": row(f"{index:064x}") for index in range(1, 7)}
        loaded_six, _, _ = self.load(six)
        self.assertEqual(set(loaded_six), set(six))

    def test_rejects_too_many_residents(self):
        value = {f"{index:064x}": row(f"{index:064x}")
                 for index in range(1, DRIVER.MAX_PROTECTED_RESIDENTS + 2)}
        with self.assertRaises(RuntimeError):
            self.load(value)

    def test_rejects_oversized_receipt_before_unbounded_read(self):
        path = self.write_receipt({})
        with path.open("ab") as receipt_file:
            receipt_file.truncate((1 << 20) + 1)
        with self.assertRaisesRegex(RuntimeError, "byte bound"):
            DRIVER.load_protected_residents(path)

    def test_rejects_missing_or_mismatched_row_metadata(self):
        identity = "2" * 64
        invalid_rows = (
            {identity: {key: value for key, value in row(identity).items() if key != "image"}},
            {identity: row("3" * 64)},
            {identity: row(identity, status="exited")},
            {identity: row(identity, pid=True)},
            {identity: row(identity, restart_count=-1)},
            {identity: row(identity, extra="unexpected")},
        )
        for value in invalid_rows:
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    self.load(value)

    def test_rejects_duplicate_ids_and_out_of_root_file(self):
        identity = "4" * 64
        duplicate = ("{" + json.dumps(identity) + ":" + json.dumps(row(identity)) + "," +
                     json.dumps(identity) + ":" + json.dumps(row(identity)) + "}").encode()
        with self.assertRaises(ValueError):
            DRIVER.load_protected_residents(self.write_receipt({}, raw=duplicate))
        with tempfile.TemporaryDirectory(prefix="group-fabric-outside-") as outside:
            path = Path(outside) / "residents.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(RuntimeError):
                DRIVER.load_protected_residents(path)

    def test_rejects_symlink_and_unsafe_receipt_mode(self):
        valid = self.write_receipt({})
        link = self.directory / "residents-link.json"
        link.symlink_to(valid)
        with self.assertRaises(RuntimeError):
            DRIVER.load_protected_residents(link)
        valid.chmod(0o644)
        with self.assertRaises(RuntimeError):
            DRIVER.load_protected_residents(valid)


if __name__ == "__main__":
    unittest.main()
