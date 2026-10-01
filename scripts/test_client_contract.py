"""Artifact safety tests; uses only temporary directories and public fixtures."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("client_contract", Path(__file__).with_name("client-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ContractBundleTest(unittest.TestCase):
    def setUp(self):
        self.files, self.catalog = contract.read_contract(contract.ROOT)
        self.manifest = contract.contract_manifest(self.files, self.catalog, "synthetic-test-commit", False)

    def verify(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.tar.gz"
            path.write_bytes(data)
            return contract.verify_bundle(path)

    def copied_contract(self, directory):
        root = Path(directory)
        for name, data in self.files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def test_export_is_reproducible_and_complete(self):
        first = contract.archive_bytes(self.files, self.manifest)
        self.assertEqual(first, contract.archive_bytes(self.files, self.manifest))
        self.assertEqual(self.verify(first), self.manifest)

    def test_changed_file_cannot_reuse_manifest(self):
        files = {**self.files, contract.CATALOG: self.files[contract.CATALOG] + b" "}
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.verify(contract.archive_bytes(files, self.manifest))

    def test_incomplete_bundle_rejected(self):
        files = dict(self.files)
        files.pop(contract.CATALOG)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.verify(contract.archive_bytes(files, self.manifest))

    def test_pq_client_vectors_are_bundled(self):
        required = {
            "cicada-go/internal/e2ee/testdata/owner-link-review-policy-proof-v1.json",
            "cicada-go/internal/e2ee/testdata/network-collaboration-broadcast-consent-v1.json",
        }
        self.assertTrue(required.issubset(self.files))
        review = json.loads(self.files[next(name for name in required if "owner-link" in name)])
        broadcast = json.loads(self.files[next(name for name in required if "broadcast-consent" in name)])
        self.assertEqual(len(review["claims_field_order"]), 11)
        self.assertEqual(broadcast["purpose"], "BROADCAST")

    def test_review_policy_vector_rejects_claim_order_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copied_contract(directory)
            path = root / "cicada-go/internal/e2ee/testdata/owner-link-review-policy-proof-v1.json"
            vector = json.loads(path.read_text())
            vector["claims_field_order"][0], vector["claims_field_order"][1] = (
                vector["claims_field_order"][1], vector["claims_field_order"][0])
            path.write_text(json.dumps(vector))
            with self.assertRaisesRegex(ValueError, "wrong production domain/order"):
                contract.read_contract(root)

    def test_broadcast_vector_rejects_task_relabel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copied_contract(directory)
            path = root / "cicada-go/internal/e2ee/testdata/network-collaboration-broadcast-consent-v1.json"
            vector = json.loads(path.read_text())
            vector["purpose"] = "TASK"
            path.write_text(json.dumps(vector))
            with self.assertRaisesRegex(ValueError, "BROADCAST-purpose"):
                contract.read_contract(root)

    def test_unsafe_archive_is_never_extracted(self):
        for name, kind in (("../outside", tarfile.REGTYPE), (contract.CATALOG, tarfile.SYMTYPE)):
            with self.subTest(name=name, kind=kind):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                    archive.addfile(member, io.BytesIO(b""))
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    self.verify(output.getvalue())


if __name__ == "__main__":
    unittest.main()
