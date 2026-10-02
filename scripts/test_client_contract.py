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

    def test_review_policy_initial_current_zero_and_next_proof_contract(self):
        contract.check_link_review_policy_contract(
            self.files["docs/client-hub-v1.openapi.yaml"].decode(),
            self.files["docs/client-hub-wire-v1.md"].decode())

    def test_review_policy_rejects_positive_only_current_version_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copied_contract(directory)
            path = root / "docs/client-hub-v1.openapi.yaml"
            text = path.read_text()
            start = text.index("    LinkReviewPolicyGrantRequest:")
            before, rest = text[:start], text[start:]
            path.write_text(before + rest.replace(
                "expected_policy_version: {type: integer, minimum: 0, maximum: 9223372036854775806}",
                "expected_policy_version: {type: integer, minimum: 1}", 1))
            with self.assertRaisesRegex(ValueError, "review policy current CAS range drift"):
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

    def test_group_directory_permission_requires_flag_and_current_CAS(self):
        for old, new in (
                ("required: [group_id, membership_id, enabled, expected_membership_version]",
                 "required: [group_id, membership_id, expected_membership_version]"),
                ("expected_membership_version: {type: integer, minimum: 1, maximum: 9223372036854775806}",
                 "expected_membership_version: {type: integer, minimum: 0}")):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as directory:
                root = self.copied_contract(directory)
                path = root / "docs/client-hub-v1.openapi.yaml"
                text = path.read_text()
                start = text.index("    ClientTopologySetDirectoryPermission:")
                path.write_text(text[:start] + text[start:].replace(old, new, 1))
                with self.assertRaisesRegex(ValueError, "Group directory permission flag/CAS schema drift"):
                    contract.read_contract(root)

    def test_group_directory_permission_snapshot_and_action_cannot_drift(self):
        for marker in ("directory_permission_enabled", "membership.set_directory_permission"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                root = self.copied_contract(directory)
                path = root / "docs/client-hub-v1.openapi.yaml"
                path.write_text(path.read_text().replace(marker, "synthetic_wrong_field"))
                with self.assertRaisesRegex(ValueError, "Group directory permission action/projection/scope drift"):
                    contract.read_contract(root)

    def test_link_client_proof_is_bundled_and_checked(self):
        self.assertIn("cicada-go/internal/e2ee/testdata/link-client-proof-v2.json", self.files)
        self.assertIn("docs/client-link-proof-evidence.md", self.files)
        vector = json.loads(self.files["cicada-go/internal/e2ee/testdata/link-client-proof-v2.json"])
        self.assertEqual([s["side"] for s in vector["statuses"]], ["SOURCE", "TARGET"])

    def test_link_client_proof_rejects_missing_side_or_mismatched_version(self):
        for change in ("side", "version", "proof", "domain"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = self.copied_contract(directory)
                path = root / "cicada-go/internal/e2ee/testdata/link-client-proof-v2.json"
                vector = json.loads(path.read_text())
                if change == "side":
                    vector["statuses"].pop()
                elif change == "version":
                    vector["statuses"][1]["evidence"]["link_version"] += 1
                elif change == "proof":
                    vector["statuses"][0]["evidence"]["signed_proof"] = "e30="
                else:
                    vector["grant_domain"] = "wrong-domain"
                path.write_text(json.dumps(vector))
                with self.assertRaises((ValueError, KeyError)):
                    contract.read_contract(root)

    def test_link_client_proof_schema_cannot_omit_current_public_key_or_trust(self):
        for old, new in (("owner_key_state: {const: ACTIVE}", "owner_key_state: {type: string}"),
                         ("owner_key_version: {type: integer, minimum: 1}", "owner_key_version: {type: integer, minimum: 0}")):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as directory:
                root = self.copied_contract(directory)
                path = root / "docs/client-hub-v1.openapi.yaml"
                text = path.read_text()
                start = text.index("    CommunicationLinkKeyGrantEvidence:")
                path.write_text(text[:start] + text[start:].replace(old, new, 1))
                with self.assertRaisesRegex(ValueError, "Client Link proof evidence schema/trust drift"):
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

    def test_node_pairing_contract_rejects_result_and_cas_drift(self):
        mutations = (
            ("docs/client-hub-v1.openapi.yaml", "result: '#/components/schemas/NodeControlKeyBinding'", "result: '#/components/schemas/NodeDeviceBinding'", "mapping drift"),
            ("docs/client-hub-v1.openapi.yaml", "        owner_binding_id: {type: string}", "        credential_digest: {type: string}", "field/required drift"),
            ("docs/client-hub-v1.openapi.yaml", "required: [user_code, candidate_digest, candidate_version]", "required: [user_code]", "field/required drift"),
            ("docs/client-hub-v1.openapi.yaml", "required: [user_code, verification_uri, candidate]", "required: [user_code, verification_uri]", "field/required drift"),
            ("docs/client-hub-wire-v1.md", '`nodes.confirm` | `NodeControlKeyBinding`', '`nodes.confirm` | `NodeDeviceBinding`', "wire result projection drift"),
        )
        for name, old, new, error in mutations:
            with self.subTest(file=name, mutation=old), tempfile.TemporaryDirectory() as directory:
                root = self.copied_contract(directory)
                path = root / name
                text = path.read_text()
                self.assertEqual(text.count(old), 1)
                path.write_text(text.replace(old, new))
                with self.assertRaisesRegex(ValueError, error):
                    contract.read_contract(root)


if __name__ == "__main__":
    unittest.main()
