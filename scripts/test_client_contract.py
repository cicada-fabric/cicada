"""Artifact safety tests; uses only temporary directories and public fixtures."""

import importlib.util
import io
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
