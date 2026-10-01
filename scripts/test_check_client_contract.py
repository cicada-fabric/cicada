"""Offline CLI regression checks using copied public protocol data only."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent
CHECKER = REPO / "scripts/check-client-contract.py"
SNAPSHOT = REPO / "contracts/client-hub-v1.6-4fb241b"
CATALOG = "cicada-go/internal/clientcontract/catalog.json"


class ContractCheckerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="client-contract-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "snapshot"
        shutil.copytree(SNAPSHOT, self.root)
        self.manifest = json.loads((self.root / "manifest.json").read_text())

    def save_manifest(self, value=None):
        (self.root / "manifest.json").write_text(
            json.dumps(self.manifest if value is None else value)
        )

    def run_checker(self, *args, optimized=False, use_default=False):
        command = [sys.executable] + (["-O"] if optimized else []) + [str(CHECKER)]
        if not use_default:
            command += ["--snapshot-dir", str(self.root)]
        return subprocess.run(
            command + list(args), capture_output=True, text=True, timeout=20
        )

    def assert_rejected(self, result):
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("PASS", result.stdout)

    def test_current_approved_defaults_remain_valid(self):
        result = self.run_checker(use_default=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(self.manifest["catalog_sha256"], result.stdout)

    def test_historical_snapshot_requires_its_own_explicit_pins(self):
        historical = REPO / "contracts/client-hub-v1.4-f30892f"
        args = ("--snapshot-dir", str(historical))
        self.assert_rejected(self.run_checker(*args, use_default=True))
        result = self.run_checker(
            *args,
            "--source-revision", "f30892fcd79a27bfe5604575deaecebe52c5ec50",
            "--catalog-sha256", "7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54",
            "--contract-revision", "client-hub-v1.4",
            use_default=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("PASS client-hub-v1.4", result.stdout)

    def test_explicit_source_and_catalog_are_independent_pins(self):
        # Synthetic public metadata tests the CLI; it is not a new Hub artifact.
        source = "1" * 40
        catalog = json.loads((self.root / CATALOG).read_text())
        catalog["test_fixture"] = "public synthetic checker test"
        raw = json.dumps(catalog).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (self.root / CATALOG).write_bytes(raw)
        self.manifest.update(source_revision=source, catalog_sha256=digest)
        self.manifest["files"][CATALOG] = {"bytes": len(raw), "sha256": digest}
        self.save_manifest()
        self.assert_rejected(self.run_checker())
        result = self.run_checker(
            "--source-revision", source, "--catalog-sha256", digest
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(digest, result.stdout)

    def test_invalid_manifest_pins_and_cleanliness_are_rejected(self):
        for field, value in (
            ("source_revision", "2" * 40),
            ("catalog_sha256", "3" * 64),
            ("source_dirty", True),
            ("source_dirty", "false"),
            ("wire_version", True),
            ("contract_revision", "client-hub-unapproved"),
        ):
            with self.subTest(field=field, value=value):
                changed = {**self.manifest, field: value}
                self.save_manifest(changed)
                self.assert_rejected(self.run_checker())

    def test_same_length_payload_tamper_is_rejected(self):
        path = self.root / "docs/client-hub-wire-v1.md"
        payload = path.read_bytes()
        path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
        self.assert_rejected(self.run_checker())

    def test_unlisted_nested_manifest_is_rejected(self):
        path = self.root / "extra/manifest.json"
        path.parent.mkdir()
        path.write_text("{}")
        self.assert_rejected(self.run_checker())

    def test_symlink_payload_is_rejected(self):
        path = self.root / "docs/client-hub-wire-v1.md"
        outside = Path(self.temp.name) / "outside.md"
        path.rename(outside)
        path.symlink_to(outside)
        self.assert_rejected(self.run_checker())

    def test_manifest_path_traversal_is_rejected(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_bytes(b"public synthetic data")
        raw = outside.read_bytes()
        self.manifest["files"]["../outside.txt"] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()
        }
        self.save_manifest()
        self.assert_rejected(self.run_checker())

    def test_python_optimization_cannot_disable_validation(self):
        self.manifest["source_dirty"] = True
        self.save_manifest()
        self.assert_rejected(self.run_checker(optimized=True))

    def test_malformed_expected_pins_are_rejected(self):
        for args in (
            ("--source-revision", "short"),
            ("--source-revision", "A" * 40),
            ("--catalog-sha256", "not-a-sha256"),
        ):
            with self.subTest(args=args):
                self.assert_rejected(self.run_checker(*args))


if __name__ == "__main__":
    unittest.main()
