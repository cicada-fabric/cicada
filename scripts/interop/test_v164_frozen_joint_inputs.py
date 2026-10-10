#!/usr/bin/env python3
"""Offline checks for the fixed Core adapter control and path interface."""

from __future__ import annotations

import copy
import datetime as dt
from decimal import Decimal
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "v164_frozen_joint_inputs_test", HERE / "v164-frozen-joint-inputs.py")
assert SPEC is not None and SPEC.loader is not None
joint = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = joint
SPEC.loader.exec_module(joint)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_file(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


class FinalConsumerPinTests(unittest.TestCase):
    def test_paths_hashes_freeze_test_map_and_android_url_match_final_parent_contract(self) -> None:
        self.assertEqual(joint.PARENT_PATH.name, "joint-parent-v5.py")
        self.assertEqual(joint.ADAPTER_PATH.name, "joint-adapter-parent-ready-v5.py")
        self.assertEqual(joint.INTERFACE_PATH.name, "JOINT-PARENT-V5-INTERFACE.NONAUTH.md")
        self.assertEqual(joint.FREEZE_PATH.name, "JOINT-PARENT-V5-FREEZE.NONAUTH.json")
        self.assertEqual(joint.QA_RECEIPT_PATH.name, "JOINT-PARENT-V5-FINAL-QA.NONAUTH.json")
        self.assertEqual(joint.QA_RECEIPT_SHA256,
            "fd96eb975fbf969ec88cf3f9604769fa7fa52dfb408315a897144d3abd38f3b3")
        self.assertEqual(joint.RECONCILE_PATH.parts[-3:], (
            "reconcile-final-compile-format-2", "bin", "cicada-link-joint-reconcile"))
        self.assertEqual(joint.RECONCILE_RECEIPT_PATH.parts[-2:], (
            "reconcile-final-compile-format-2", "PREPARATION-RESULT.NONAUTH.json"))
        self.assertEqual(joint.FROZEN_ARTIFACT_HASHES, {
            "parent_sha256": "1c6370701ab793b390e364d56ac18a8cb60cf4ca4e1b568e56fafab1e3880b01",
            "adapter_sha256": "211ec899ff9ba62ed56d66b13d0de8cd56c8aafd232e20be8ed14c76a10482d5",
            "interface_sha256": "eafb6ca987a5368ae9d04a9bf17d43fe15caaa36896cec4be3a9445ab2aa9e0d",
            "freeze_sha256": "33cc0d315f876d5da3187ee17548b1457b0a0af0ac3e816f6cbc6577dba50eb4",
        })
        self.assertEqual(joint.PREPARATION_REFERENCES, {
            "actual_compiler_review": {
                "path": "/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/ROOT-COMPILED-HELPERS.NONAUTH.json",
                "sha256": "3c4f5795335c18e56adab3d96d39aec24b6e93e1c88e5ee820b2079403d163c8",
            },
            "current_compiled_tuple_reference": {
                "path": "/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/CORE-COMPILED-READINESS.V5.NONAUTH.json",
                "sha256": "d400dc35b1952c62c75337f03b5027ce847c0a93c8748219ed0d89c9b63574e7",
            },
            "apk_endorsement": {
                "path": "/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/ROOT-APK-PINS.ENDORSED.private.json",
                "sha256": "fae3c7e442335369af39f0a35bc2dac95ae3cab591a2b2597b9d45f053cb03be",
            },
        })
        self.assertEqual(joint.RECONCILE_SHA256,
            "e0fddfb7580542e93b4a8ff93eabf9a39903f787b6034bce6cc7efb3e748c3d7")
        self.assertEqual(joint.RECONCILE_RECEIPT_SHA256,
            "728bcdc39eb25189c4ac465bec5434d2847e0d1ac308195eb1a692ff1d4f0197")
        self.assertEqual(joint.FROZEN_PREPARATION_TEST_HASHES, {
            "test_joint_parent_v5_snapshot.py": "dcad02d8919a9e875c81b4fa31c900bf14420cf0165b2d221164c5df016c95b1",
        })
        self.assertEqual(joint.RUN_ID, "v164-e2a1908-joint8-20261010")
        self.assertEqual(joint.ANDROID_BASE_URL, "http://127.0.0.1:8787")

    def test_ready_runner_is_the_new_adapter_not_parent_or_previous_adapter(self) -> None:
        adapter_sha = joint.FROZEN_ARTIFACT_HASHES["adapter_sha256"]
        self.assertEqual(joint._validate_runner_sha256(adapter_sha), adapter_sha)
        for label, candidate in (
                ("Parent source is not the fixture runner", joint.FROZEN_ARTIFACT_HASHES["parent_sha256"]),
                ("compiled v5 adapter is APK-HOLD and stale", "80b1549513a1aa881b728cee7119aa0f7272606948b704c36b428b0a9771cc53"),
                ("v4 adapter is stale", "907d12a63663543542bb58df83d74cec95e054593a6f8d214498cbc41f2860e4"),
                ("v3 adapter is stale", "86f093b82bcd548fd94bf3120db3e1f7413f8e3fea88ee2981a8204923765ae7"),
                ("v2 adapter is stale", "30fa655ab1ae4e8df120441a4aafb5ebe6cd3d5771f6ab83fff0f2e2a497ec96"),
                ("v1 adapter is stale", "7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4"),
                ("previous adapter is stale", "29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4")):
            with self.subTest(label=label), self.assertRaises(ValueError):
                joint._validate_runner_sha256(candidate)

    def test_carrier_consumer_accepts_only_the_local_reverse_android_url(self) -> None:
        ready = {"hub": {"hub_id": "synthetic-hub"}}
        fixture = {"owners": [{"owner_id": "synthetic-source-owner"}]}
        operation, mode = joint.CASES[0]
        manifest = {
            "schema": "cicada.client-v164-link-recovery-carrier.v1",
            "run_id": f"{joint.RUN_ID}-0",
            "run_scope": "v164-e2a1908-link-recovery",
            **joint._HUB_SOURCE,
            "fixture_pid": 123,
            "fixture_process_start": "456",
            "helper_sha256": joint.RECOVERY_HELPER_SHA256,
            "ready_raw_sha256": "a" * 64,
            "hub_id": "synthetic-hub",
            "upstream_origin": "http://127.0.0.1:18787",
            "android_base_url": joint.ANDROID_BASE_URL,
            "owner_id": "synthetic-source-owner",
            "device_id": "synthetic-device",
            "session_epoch": 1,
            "expected_operation": operation,
            "fault_mode": mode,
        }
        with mock.patch.object(joint, "_read_ready", return_value=(ready, "synthetic-ready-hash")), \
                mock.patch.object(joint, "validate_ready", return_value={"fixture_public": fixture}):
            joint._validate_carrier_manifest(manifest, Path("/tmp/synthetic-case"), 0)
            for stale_run in ("v164-e2a1908-joint-20261010-0", "v164-e2a1908-joint2-20261010-0",
                    "v164-e2a1908-joint3-20261010-0", "v164-e2a1908-joint4-20261010-0",
                    "v164-e2a1908-joint5-20261010-0", "v164-e2a1908-joint6-20261010-0",
                    "v164-e2a1908-joint7-20261010-0"):
                with self.subTest(run_id=stale_run), self.assertRaises(ValueError):
                    joint._validate_carrier_manifest(
                        dict(manifest, run_id=stale_run), Path("/tmp/synthetic-case"), 0)
            for wrong_url in (
                    "http://10.0.2.2:8787", "http://127.0.0.1:8788", "http://localhost:8787"):
                with self.subTest(android_base_url=wrong_url), self.assertRaises(ValueError):
                    joint._validate_carrier_manifest(
                        dict(manifest, android_base_url=wrong_url), Path("/tmp/synthetic-case"), 0)


class TypedControlTests(unittest.TestCase):
    def test_controls_are_closed_and_proxy_is_source_only(self) -> None:
        request_hash = "a" * 64
        self.assertEqual(joint.typed_control("prepare", 0), {"action": "prepare", "case": 0})
        self.assertEqual(joint.typed_control("device", 1, side="TARGET", manifest_sha256=request_hash), {
            "action": "device", "case": 1, "side": "TARGET", "manifest_sha256": request_hash,
        })
        self.assertEqual(joint.typed_control("proof", 2, side="SOURCE", input_sha256=request_hash), {
            "action": "proof", "case": 2, "side": "SOURCE", "input_sha256": request_hash,
        })
        self.assertEqual(joint.typed_control("proxy", 3, side="source"), {
            "action": "proxy", "case": 3, "side": "SOURCE",
        })
        self.assertEqual(joint.typed_control("capture", 4, capture_sha256=request_hash), {
            "action": "capture", "case": 4, "capture_sha256": request_hash,
        })
        self.assertEqual(joint.typed_control("finish", 5, result_sha256=request_hash,
            carrier_sha256="b" * 64), {
            "action": "finish", "case": 5, "result_sha256": request_hash,
            "carrier_sha256": "b" * 64,
        })

        invalid_controls = (
            ("unknown action", lambda: joint.typed_control("reconcile", 0)),
            ("target proxy", lambda: joint.typed_control("proxy", 0, side="TARGET")),
            ("unexpected run selector", lambda: joint.typed_control("prepare", 0, run_id="v164-other")),
            ("missing proof side", lambda: joint.typed_control("proof", 0, input_sha256=request_hash)),
            ("malformed input hash", lambda: joint.typed_control("capture", 0, capture_sha256="z" * 64)),
        )
        for label, call in invalid_controls:
            with self.subTest(label=label), self.assertRaises(ValueError):
                call()

    def test_case_index_is_an_integer_in_the_frozen_zero_through_seven_range(self) -> None:
        for invalid in (-1, 8, True, 1.0, "2"):
            with self.subTest(index=invalid), self.assertRaises(ValueError):
                joint.typed_control("prepare", invalid)


class FixedPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_temp = tempfile.TemporaryDirectory(prefix="cicada-joint-e2a-", dir="/tmp")
        self.addCleanup(self.root_temp.cleanup)
        self.case_root = Path(self.root_temp.name) / "cases" / "3"
        self.case_root.mkdir(mode=0o700, parents=True)

    def test_input_and_output_names_are_fixed_under_the_selected_case(self) -> None:
        self.assertEqual(joint.input_path(self.case_root, "SOURCE", "device"),
            self.case_root / "client-inputs/source-device-enrollment.json")
        self.assertEqual(joint.input_path(self.case_root, "TARGET", "review"),
            self.case_root / "client-inputs/target-review.json")
        self.assertEqual(joint.input_path(self.case_root, None, "capture"),
            self.case_root / "client-inputs/capture.json")
        self.assertEqual(joint.input_path(self.case_root, None, "result"),
            self.case_root / "client-inputs/result.json")
        self.assertEqual(joint.input_path(self.case_root, None, "carrier"),
            self.case_root / "client-inputs/carrier.json")

        self.assertEqual(joint.expected_output_path(self.case_root, "SOURCE", "device-grant"),
            self.case_root / "signed-proofs/source-device-grant.json")
        self.assertEqual(joint.expected_output_path(self.case_root, "TARGET", "link-proof"),
            self.case_root / "signed-proofs/target-link-proof.json")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "carrier-manifest"),
            self.case_root / "public/carrier-manifest.json")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "proxy-ready"),
            self.case_root / "public/proxy-ready.jsonl")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "scenario"),
            self.case_root / "public/recovery-scenario.json")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "fault-envelope"),
            self.case_root / "public/fault-envelope.json")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "fault-control"),
            self.case_root / "public/fault-control.jsonl")
        self.assertEqual(joint.expected_output_path(self.case_root, None, "ready"),
            self.case_root / "public/READY.json")

    def test_path_builders_reject_other_cases_sides_and_caller_selected_names(self) -> None:
        with self.assertRaises(ValueError):
            joint.input_path(self.case_root, "TARGET", "capture")
        with self.assertRaises(ValueError):
            joint.expected_output_path(self.case_root, "TARGET", "carrier-manifest")
        with self.assertRaises(ValueError):
            joint.input_path(self.case_root, None, "../capture")
        with self.assertRaises(ValueError):
            joint.expected_output_path(self.case_root, None, "../../carrier.json")

        other_case = self.case_root.parent / "8"
        with self.assertRaises(ValueError):
            joint.input_path(other_case, "SOURCE", "device")


class PublicMetadataTests(unittest.TestCase):
    @staticmethod
    def setup_fixture() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        hub_id = "synthetic-hub"
        link = {
            "link_id": "synthetic-link", "version": 1, "state": "PROPOSED",
            "expires_at": "2026-10-10T12:00:00Z", "contract_digest": "a" * 64,
        }
        fixture_owners = [
            {
                "owner_id": "synthetic-source-owner", "owner_key_id": "synthetic-source-key",
                "public_identity": "synthetic-public-identity-source", "source_of_pin": "fixture-pin-source",
            },
            {
                "owner_id": "synthetic-target-owner", "owner_key_id": "synthetic-target-key",
                "public_identity": "synthetic-public-identity-target", "source_of_pin": "fixture-pin-target",
            },
        ]
        hub_ready = {
            "identity": {
                "hub_id": hub_id, "control_key_version": 3,
                "control_public_identity": "synthetic-hub-control-public", "suite": "synthetic-pq-suite",
            },
            "base_url": "http://127.0.0.1:18787",
        }
        fixture = {"hub_id": hub_id, "owners": copy.deepcopy(fixture_owners), "link": copy.deepcopy(link)}
        value = {
            "schema": "cicada.client-link-v164-client-setup.v1",
            "status": "READY_FOR_ROOT_CLIENT_COORDINATION",
            "protocol_scope": "SYNTHETIC_PROTOCOL_ONLY",
            "native_runtime": "NOT_RUN",
            "model_calls": "NONE",
            "hub": {
                "hub_id": hub_id, "control_key_version": 3,
                "control_public_identity": hub_ready["identity"]["control_public_identity"],
                "suite": hub_ready["identity"]["suite"], "base_url": hub_ready["base_url"],
                "image_id": joint.HUB_IMAGE_ID, "source_revision": joint.CORE_REVISION,
                "source_fingerprint": joint.SOURCE_FINGERPRINT, "catalog_sha256": joint.CATALOG_SHA256,
                "contract_revision": joint.CONTRACT_REVISION, "build_source_dirty": False,
            },
            "owners": [
                {
                    "link_side": side, "owner_id": row["owner_id"],
                    "owner_key_id": row["owner_key_id"], "public_identity": row["public_identity"],
                    "pin_source": row["source_of_pin"],
                }
                for side, row in zip(("SOURCE", "TARGET"), fixture_owners)
            ],
            "link": copy.deepcopy(link),
            "client_instructions": {
                "reference_manifest": "offline only; Client fetches fresh live encrypted manifest before signing",
                "owner_private_keys_for_signing": "host only; never in APK or Hub",
            },
        }
        return value, fixture, hub_ready

    def test_client_setup_accepts_only_matching_public_refs_and_nonsecret_instructions(self) -> None:
        value, fixture, hub_ready = self.setup_fixture()
        self.assertIs(joint._validate_client_setup(value, fixture, hub_ready), value)

        wrong_owner_public = copy.deepcopy(value)
        wrong_owner_public["owners"][1]["public_identity"] = "different-synthetic-public-identity"
        wrong_hub_public = copy.deepcopy(value)
        wrong_hub_public["hub"]["control_public_identity"] = "different-synthetic-hub-public"
        private_key_instruction = copy.deepcopy(value)
        private_key_instruction["client_instructions"]["owner_private_keys_for_signing"] = "APK"
        with_unexpected_private_field = copy.deepcopy(value)
        with_unexpected_private_field["private_key"] = "synthetic-placeholder"

        for label, candidate in (
                ("Owner public identity mismatch", wrong_owner_public),
                ("Hub control public identity mismatch", wrong_hub_public),
                ("unsafe signing instruction", private_key_instruction),
                ("unexpected credential field", with_unexpected_private_field)):
            with self.subTest(label=label), self.assertRaises(ValueError):
                joint._validate_client_setup(candidate, fixture, hub_ready)


class FixtureBindingTests(unittest.TestCase):
    @staticmethod
    def fixture() -> dict[str, object]:
        # Reuse structural, explicitly non-cryptographic public test documents.
        # Nothing is written and no valid proof, private key or live Hub is used.
        from test_v164_f6_ready import MainF6ReadyTest
        builder = MainF6ReadyTest()
        builder.root = Path('/tmp/synthetic-fixture-not-created')
        builder.now = dt.datetime(2026, 10, 10, 12, tzinfo=dt.timezone.utc)
        _config, _setup, value, _reference, _owned = builder._documents()
        value['build'] = copy.deepcopy(joint._BUILD)
        value['link']['direction'] = 'bidirectional'
        for i, side in enumerate(('source', 'target')):
            owner_id = f'{joint.RUN_ID}-{side}-0'
            value['owners'][i]['owner_id'] = owner_id
            value['networks'][i]['owner_id'] = owner_id
            value['link'][side + '_owner_id'] = owner_id
            value['reference_manifest'][side]['owner_id'] = owner_id
        # Producer semantics: access, direct-native registration and Group
        # SessionBinding have independent IDs and counters, on the same Endpoint.
        return value

    def test_separate_network_access_and_native_bindings_pass(self) -> None:
        value = self.fixture()
        for layer, binding in zip(value['protocol_layers'], value['bindings']):
            self.assertEqual(len({layer['network_access_binding_id'], layer['native_binding_id'],
                                  binding['binding_id']}), 3)
            self.assertEqual(len({layer['network_access_epoch'], layer['native_binding_epoch'],
                                  binding['epoch']}), 3)
        self.assertIs(joint._validate_fixture_public(value, 0), value)

    def test_invalid_direct_native_id_and_epoch_are_rejected_on_either_side(self) -> None:
        for i in range(2):
            for field, replacement in (('native_binding_id', ''), ('native_binding_id', '../unsafe'),
                    ('native_binding_epoch', 0), ('native_binding_epoch', True),
                    ('native_binding_epoch', '1')):
                value = self.fixture()
                value['protocol_layers'][i][field] = replacement
                with self.subTest(side=i, field=field, replacement=replacement), self.assertRaisesRegex(
                        ValueError, '^FIXTURE_PROTOCOL_SCOPE$'):
                    joint._validate_fixture_public(value, 0)

    def test_group_binding_manifest_and_candidate_must_match_exactly(self) -> None:
        for i, side in enumerate(('source', 'target')):
            for collection, field, replacement, code in (
                    ('bindings', 'binding_id', 'wrong-group-binding', 'FIXTURE_BINDING_SCOPE'),
                    ('bindings', 'epoch', 999, 'FIXTURE_BINDING_SCOPE'),
                    ('bindings', 'endpoint_id', 'wrong-endpoint', 'FIXTURE_BINDING_SCOPE'),
                    ('reference_manifest', 'binding_id', 'wrong-manifest-binding', 'FIXTURE_BINDING_SCOPE'),
                    ('reference_manifest', 'binding_epoch', 999, 'FIXTURE_BINDING_SCOPE'),
                    ('reference_manifest', 'endpoint_id', 'wrong-endpoint', 'FIXTURE_MANIFEST_LINK'),
                    ('reference_manifest', 'node_id', 'wrong-node', 'FIXTURE_MANIFEST_LINK'),
                    ('endpoint_candidates', 'binding_id', 'wrong-candidate-binding', 'FIXTURE_CANDIDATE_SCOPE'),
                    ('endpoint_candidates', 'epoch', 999, 'FIXTURE_CANDIDATE_SCOPE'),
                    ('endpoint_candidates', 'endpoint_id', 'wrong-endpoint', 'FIXTURE_CANDIDATE_SCOPE')):
                value = self.fixture()
                value[collection][side if collection == 'reference_manifest' else i][field] = replacement
                with self.subTest(side=side, collection=collection, field=field), self.assertRaisesRegex(
                        ValueError, '^' + code + '$'):
                    joint._validate_fixture_public(value, 0)

        # bool equals integer 1 in Python, but is not an epoch from the producer.
        value = self.fixture()
        value['bindings'][0]['epoch'] = value['reference_manifest']['source']['binding_epoch'] = 1
        value['endpoint_candidates'][0]['epoch'] = True
        with self.assertRaisesRegex(ValueError, '^FIXTURE_CANDIDATE_SCOPE$'):
            joint._validate_fixture_public(value, 0)

    def test_endpoint_node_runtime_roles_and_grants_guards_remain(self) -> None:
        for i in range(2):
            for field, replacement in (('endpoint_id', 'wrong-endpoint'), ('node_id', 'wrong-node'),
                    ('native_runtime', 'RUNNING'), ('group_membership_roles', ['monitor']),
                    ('group_membership_grants', ['link.review'])):
                value = self.fixture()
                value['protocol_layers'][i][field] = replacement
                with self.subTest(side=i, field=field), self.assertRaisesRegex(
                        ValueError, '^FIXTURE_PROTOCOL_SCOPE$'):
                    joint._validate_fixture_public(value, 0)

    def test_network_access_id_epoch_and_expiry_are_checked_independently(self) -> None:
        for field, replacement in (('network_access_binding_id', '../unsafe'),
                ('network_access_epoch', 0), ('network_access_epoch', True),
                ('network_access_epoch', '1'), ('network_access_expires_at', '2026-10-10T12:00:00+00:00')):
            value = self.fixture()
            value['protocol_layers'][0][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                joint._validate_fixture_public(value, 0)


class CanonicalTimeTests(unittest.TestCase):
    def test_accepts_frozen_go_fractional_timestamp_without_float_rounding(self) -> None:
        parsed = joint._canonical_time("2026-10-10T12:34:56.123456789Z")
        self.assertIsInstance(parsed, Decimal)
        self.assertEqual(parsed - int(parsed), Decimal("0.123456789"))

        for value in ("2026-10-10T12:34:56.123456780Z", "2026-10-10T12:34:56.1234567890Z",
                "2026-10-10T12:34:56.123456789+00:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                joint._canonical_time(value)


class ArtifactPinTests(unittest.TestCase):
    def artifact_fixture(self, root: Path):
        parent = root / "joint-parent-v5.py"
        adapter = root / "joint-adapter-parent-ready-v5.py"
        interface = root / "JOINT-PARENT-V5-INTERFACE.NONAUTH.md"
        freeze = root / "JOINT-PARENT-V5-FREEZE.NONAUTH.json"
        reconcile, receipt_path = self.auxiliary_paths(root)
        parent_raw = b"# synthetic frozen Root Parent source\n"
        adapter_raw = b"# synthetic frozen Parent-ready adapter\n"
        interface_raw = b"# synthetic frozen Parent interface\n"
        reconcile_raw = b"synthetic offline compiler bytes; never executable in this test\n"
        reconcile_sha = digest(reconcile_raw)
        receipt_value = {
            "status": "PASS_OFFLINE_COMPILE_ONLY",
            "scope": "OFFLINE_COMPILE_ONLY",
            "runtime": "NOT_RUN",
            "android": "NOT_RUN",
            "cleanup": "CONFIRMED",
            "source_before_after_exact": True,
            "six_residents_exact": True,
            "compile_exit_code": 0,
            "model_calls": 0,
            "compiled_source": {
                "dirty": False,
                "image": joint.TEST_IMAGE_ID,
                "revision": joint.CORE_REVISION,
                "source_fingerprint": joint.SOURCE_FINGERPRINT,
            },
            "binaries": {
                "cicada-link-joint-reconcile": {
                    "bytes": len(reconcile_raw), "mode": "0o755", "sha256": reconcile_sha,
                },
            },
            "artifact_sha256": {"bin/cicada-link-joint-reconcile": reconcile_sha},
        }
        receipt_raw = json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode()
        source_hashes = {
            "JOINT-PARENT-V5-INTERFACE.NONAUTH.md": digest(interface_raw),
            "joint-adapter-parent-ready-v5.py": digest(adapter_raw),
            "joint-parent-v5.py": digest(parent_raw),
            **joint.FROZEN_PREPARATION_TEST_HASHES,
        }
        qa_path = root / "JOINT-PARENT-V5-FINAL-QA.NONAUTH.json"
        counts = {"exit_code": 0, "fail": 0, "skip": 0, "subtests": 2, "tests": 3}
        log_path = root / "JOINT-PARENT-V5-SNAPSHOT-QA.private.log"
        log_sha = "36e6c0b1f129292ea03afa6bb19bd15e98cfeee2edd4d025f174ab8be2f49ae7"
        qa_raw = json.dumps({
            "status": "PASS_OFFLINE_SNAPSHOT_ONLY", "AST": "PASS",
            "Runtime_Docker_model_calls": 0, "files": source_hashes,
            "elapsed_seconds": 0.16, **counts,
            "argv": ["python3", "-B", str(root / "test_joint_parent_v5_snapshot.py")],
            "previous_QA_receipt_sha256": "a" * 64,
            "raw_output_path": str(log_path), "raw_output_sha256": log_sha,
        }, sort_keys=True, separators=(",", ":")).encode()
        freeze_value = {
            "status": "SOURCE_FROZEN_OFFLINE_PASS",
            "online": "NOT_GO",
            "operator_sources": {parent.name: digest(parent_raw), adapter.name: digest(adapter_raw)},
            "event_count": 82, "callback_fields": 25, "policy_fields": 11,
            "outer_seconds": 3600, "runtime_effects": 0,
            "Client_APK_Hub_helpers_production_changed": False,
            "reserved_batch": joint.RUN_ID,
            **copy.deepcopy(joint.PREPARATION_REFERENCES),
            "qa_receipt": {"path": str(qa_path), "sha256": digest(qa_raw),
                           "elapsed_seconds": 0.16, **counts},
            "files": {
                **{str(root / name): sha for name, sha in source_hashes.items()},
                str(qa_path): digest(qa_raw), str(log_path): log_sha,
                str(root / "JOINT-PARENT-V5-SNAPSHOT.patch"):
                    "0cb0acb900e9fe1a1a1ecbaefa62c66282e66d6de82182c140f2d22f3b9f3299",
            },
        }
        freeze_raw = json.dumps(freeze_value, sort_keys=True, separators=(",", ":")).encode()
        write_file(parent, parent_raw)
        write_file(interface, interface_raw)
        write_file(adapter, adapter_raw)
        write_file(reconcile, reconcile_raw, mode=0o755)
        write_file(receipt_path, receipt_raw)
        write_file(qa_path, qa_raw)
        write_file(freeze, freeze_raw)
        expected = {
            "parent_sha256": digest(parent_raw),
            "interface_sha256": digest(interface_raw),
            "freeze_sha256": digest(freeze_raw),
            "adapter_sha256": digest(adapter_raw),
        }
        return parent, adapter, interface, freeze, freeze_value, expected

    @staticmethod
    def auxiliary_paths(root: Path) -> tuple[Path, Path]:
        directory = root / "reconcile-final-compile-format-2"
        return directory / "bin/cicada-link-joint-reconcile", directory / "PREPARATION-RESULT.NONAUTH.json"

    def patch_artifacts(self, parent: Path, adapter: Path, interface: Path, freeze: Path,
            expected: dict[str, str], *, reconcile_sha256: str | None = None,
            receipt_sha256: str | None = None, qa_sha256: str | None = None):
        reconcile, receipt_path = self.auxiliary_paths(parent.parent)
        if reconcile_sha256 is None:
            reconcile_sha256 = digest(reconcile.read_bytes())
        if receipt_sha256 is None:
            receipt_sha256 = digest(receipt_path.read_bytes())
        qa_path = parent.parent / "JOINT-PARENT-V5-FINAL-QA.NONAUTH.json"
        if qa_sha256 is None:
            qa_sha256 = digest(qa_path.read_bytes())
        return mock.patch.multiple(
            joint,
            PARENT_PATH=parent,
            INTERFACE_PATH=interface,
            ADAPTER_PATH=adapter,
            FREEZE_PATH=freeze,
            FROZEN_ARTIFACT_HASHES=expected,
            QA_RECEIPT_PATH=qa_path,
            QA_RECEIPT_SHA256=qa_sha256,
            RECONCILE_PATH=reconcile,
            RECONCILE_RECEIPT_PATH=receipt_path,
            RECONCILE_SHA256=reconcile_sha256,
            RECONCILE_RECEIPT_SHA256=receipt_sha256,
        )

    def test_verify_artifacts_accepts_only_the_exact_private_frozen_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-") as temp:
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(Path(temp))
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches:
                self.assertEqual(joint.verify_artifacts(), expected)

    def test_verify_artifacts_rejects_changed_qa_bytes_scope_and_source_joins(self) -> None:
        for change in ("bytes", "mode", "runtime", "source", "bool-count", "extra-field"):
            with self.subTest(change=change), tempfile.TemporaryDirectory(
                    prefix="v164-joint-qa-") as temp:
                parent, adapter, interface, freeze, value, expected = self.artifact_fixture(Path(temp))
                qa_path = parent.parent / "JOINT-PARENT-V5-FINAL-QA.NONAUTH.json"
                original = qa_path.read_bytes()
                qa_sha = digest(original)
                if change == "bytes":
                    write_file(qa_path, original + b"\n")
                elif change == "mode":
                    qa_path.chmod(0o644)
                else:
                    qa = json.loads(original)
                    if change == "runtime":
                        qa["Runtime_Docker_model_calls"] = 1
                    elif change == "source":
                        qa["files"]["joint-parent-v5.py"] = "0" * 64
                    elif change == "bool-count":
                        qa["exit_code"] = False
                    else:
                        qa["unapproved_field"] = True
                    changed = json.dumps(qa, sort_keys=True, separators=(",", ":")).encode()
                    write_file(qa_path, changed)
                    qa_sha = digest(changed)
                    value["qa_receipt"]["sha256"] = qa_sha
                    value["files"][str(qa_path)] = qa_sha
                    freeze_raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    write_file(freeze, freeze_raw)
                    expected = dict(expected, freeze_sha256=digest(freeze_raw))
                patches = self.patch_artifacts(
                    parent, adapter, interface, freeze, expected, qa_sha256=qa_sha)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

    def test_verify_auxiliary_rejects_tampering_wrong_modes_and_symlinks(self) -> None:
        for target_name in ("compiler", "receipt"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory(
                    prefix="v164-joint-aux-tamper-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                compiler, receipt = self.auxiliary_paths(root)
                compiler_pin, receipt_pin = digest(compiler.read_bytes()), digest(receipt.read_bytes())
                path = compiler if target_name == "compiler" else receipt
                mode = 0o755 if target_name == "compiler" else 0o600
                write_file(path, b"tampered synthetic bytes\n", mode=mode)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected,
                    reconcile_sha256=compiler_pin, receipt_sha256=receipt_pin)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

        for target_name, bad_mode in (("compiler", 0o700), ("receipt", 0o644)):
            with self.subTest(target=target_name, bad_mode=oct(bad_mode)), tempfile.TemporaryDirectory(
                    prefix="v164-joint-aux-mode-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                compiler, receipt = self.auxiliary_paths(root)
                (compiler if target_name == "compiler" else receipt).chmod(bad_mode)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

        for target_name in ("compiler", "receipt"):
            with self.subTest(symlink=target_name), tempfile.TemporaryDirectory(
                    prefix="v164-joint-aux-link-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                compiler, receipt = self.auxiliary_paths(root)
                path = compiler if target_name == "compiler" else receipt
                target = path.with_name(path.name + ".target")
                path.rename(target)
                path.symlink_to(target)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-aux-hardlink-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            compiler, _receipt = self.auxiliary_paths(root)
            (root / "compiler-extra-link").hardlink_to(compiler)
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

    def test_verify_auxiliary_rejects_stale_auxiliary_pins(self) -> None:
        for stale in ("reconcile", "receipt"):
            with self.subTest(pin=stale), tempfile.TemporaryDirectory(
                    prefix="v164-joint-aux-stale-pin-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                pins = {"reconcile_sha256": None, "receipt_sha256": None}
                pins["reconcile_sha256" if stale == "reconcile" else "receipt_sha256"] = "0" * 64
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected, **pins)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

    def test_verify_auxiliary_rejects_wrong_receipt_scope_compile_source_and_hash_metadata(self) -> None:
        def change_scope(value):
            value["scope"] = "ONLINE"

        def change_compile(value):
            value["compile_exit_code"] = 1

        def change_model_calls(value):
            value["model_calls"] = 1

        def change_source(value):
            value["compiled_source"]["revision"] = "0" * 40

        def dirty_source(value):
            value["compiled_source"]["dirty"] = True

        def change_binary_digest(value):
            value["binaries"]["cicada-link-joint-reconcile"]["sha256"] = "0" * 64

        def change_artifact_digest(value):
            value["artifact_sha256"]["bin/cicada-link-joint-reconcile"] = "0" * 64

        for label, mutate, expected_error in (
                ("scope", change_scope, "RECONCILE_RECEIPT_SCOPE"),
                ("compile status", change_compile, "RECONCILE_RECEIPT_SCOPE"),
                ("model calls", change_model_calls, "RECONCILE_RECEIPT_SCOPE"),
                ("source revision", change_source, "RECONCILE_SOURCE"),
                ("dirty source", dirty_source, "RECONCILE_SOURCE"),
                ("binary digest", change_binary_digest, "RECONCILE_BINARY_RECEIPT"),
                ("artifact digest", change_artifact_digest, "RECONCILE_BINARY_RECEIPT")):
            with self.subTest(receipt_field=label), tempfile.TemporaryDirectory(
                    prefix="v164-joint-aux-metadata-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, freeze_value, expected = self.artifact_fixture(root)
                compiler, receipt_path = self.auxiliary_paths(root)
                receipt_value = json.loads(receipt_path.read_text())
                mutate(receipt_value)
                receipt_raw = json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode()
                write_file(receipt_path, receipt_raw)
                freeze_raw = json.dumps(freeze_value, sort_keys=True, separators=(",", ":")).encode()
                write_file(freeze, freeze_raw)
                expected = dict(expected, freeze_sha256=digest(freeze_raw))
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, self.assertRaisesRegex(ValueError, expected_error):
                    joint.verify_artifacts()

    def test_verify_artifacts_rejects_changed_bytes_wrong_modes_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-bytes-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            write_file(interface, b"# changed bytes\n")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

        for label, artifact_name, legacy_bytes in (
                ("Parent", "parent", b"# previous Root source bytes\n"),
                ("adapter", "adapter", b"# previous adapter source bytes\n")):
            with self.subTest(artifact=label), tempfile.TemporaryDirectory(
                    prefix="v164-joint-artifacts-old-source-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                write_file(parent if artifact_name == "parent" else adapter, legacy_bytes)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-mode-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            interface.chmod(0o644)
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-link-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            target = root / "interface-target.private"
            interface.rename(target)
            interface.symlink_to(target)
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

    def test_verify_artifacts_rejects_parent_mismatch_and_previous_source_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-parent-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            write_file(parent, b"# changed Parent bytes\n")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-old-pins-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            old_source_pins = dict(expected,
                interface_sha256="618ecef915ad00c6f9fc61d842285989a8e61c59eded900c26aa64cc0e216805",
                freeze_sha256="eb34be4e43c4ae8e64e5b7fc397e76be0a2ef47b10cd5313918361b4d6eaa107",
                adapter_sha256="29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, old_source_pins)
            with patches, self.assertRaises(ValueError):
                joint.verify_artifacts()

    def test_verify_artifacts_rejects_superseded_parent_delivery_pins(self) -> None:
        previous = (
            ("parent_sha256", "d5320c7698c26696eb8e20d543ad7f9dab377a9500ffcf03ed3fbf7c8ff70600"),
            ("adapter_sha256", "907d12a63663543542bb58df83d74cec95e054593a6f8d214498cbc41f2860e4"),
            ("adapter_sha256", "80b1549513a1aa881b728cee7119aa0f7272606948b704c36b428b0a9771cc53"),
            ("interface_sha256", "bfbdee608e7d94da42cee16ec38a6f9ce2b14ce1f637886bbf12b7d2a979be06"),
            ("freeze_sha256", "861624c34369564950a486e07a846e457d31056ce4b5cf7124384aebfa7071f2"),
            ("parent_sha256", "5d3172d862f92a2b651d59dc261a6ea141bd25cc9c559058e98063d0cf6a94d2"),
            ("adapter_sha256", "86f093b82bcd548fd94bf3120db3e1f7413f8e3fea88ee2981a8204923765ae7"),
            ("interface_sha256", "53b2bc24bcdcac148f9dfc85171e4c41f7d07ee0bf0be901e0f672bdf807f5aa"),
            ("freeze_sha256", "ba5d5fc5104b69fe0012c523d1ccf45440621d557fc08b86809a9959cecce539"),
            ("parent_sha256", "cdf8d8caa9f95823b0fd8c50d450c7add46134e0a6f90ce8e325277afc5ab496"),
            ("adapter_sha256", "30fa655ab1ae4e8df120441a4aafb5ebe6cd3d5771f6ab83fff0f2e2a497ec96"),
            ("interface_sha256", "4a294d87a4584c547163350be9a1d9b65c4875daf350a190982a2af2d6689f8e"),
            ("freeze_sha256", "8624d782f3380fef43b9bf1d30a7d1e5541b5db56752b2ab82954002ee613733"),
            ("parent_sha256", "6ebaf8bdba59c1fe5568382d9044a6185652320b00573106aa6b3b68de1737db"),
            ("freeze_sha256", "2a4bad174ebf7c11a60264c14b45e3c5e9f3ccf80920d870ab504d80beddbd0c"),
            ("parent_sha256", "479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794"),
            ("adapter_sha256", "7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4"),
            ("interface_sha256", "8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570"),
            ("freeze_sha256", "6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39"),
            ("interface_sha256", "ead77141679ef0b7a0379c3e2d77b1ac58e4dd1b19277b667c39c47d45c7c966"),
            ("freeze_sha256", "5736703af551999b9e5acbbfc4e2b8d6e2073879219d06276e4a387efd1f1ce4"),
        )
        for name, old_hash in previous:
            with self.subTest(pin=name), tempfile.TemporaryDirectory(
                    prefix="v164-joint-artifacts-stale-pin-") as temp:
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(Path(temp))
                stale_pins = dict(expected, **{name: old_hash})
                patches = self.patch_artifacts(parent, adapter, interface, freeze, stale_pins)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()

    def test_verify_artifacts_rejects_legacy_source_filenames(self) -> None:
        for attribute, legacy_name in (
                ("PARENT_PATH", "joint-parent-v4.py"),
                ("ADAPTER_PATH", "joint-adapter-parent-ready-v4.py"),
                ("INTERFACE_PATH", "JOINT-PARENT-V4-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "JOINT-PARENT-V4-FREEZE.NONAUTH.json"),
                ("QA_RECEIPT_PATH", "JOINT-PARENT-V4-FINAL-QA.NONAUTH.json"),
                ("PARENT_PATH", "joint-parent-v3.py"),
                ("ADAPTER_PATH", "joint-adapter-parent-ready-v3.py"),
                ("INTERFACE_PATH", "JOINT-PARENT-V3-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "JOINT-PARENT-V3-FREEZE.NONAUTH.json"),
                ("QA_RECEIPT_PATH", "JOINT-PARENT-V3-QA.NONAUTH.json"),
                ("PARENT_PATH", "joint-parent-v2.py"),
                ("ADAPTER_PATH", "joint-adapter-parent-ready-v2.py"),
                ("INTERFACE_PATH", "JOINT-PARENT-V2-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "ADAPTER-PARENT-V2-FREEZE.NONAUTH.json"),
                ("FREEZE_PATH", "ADAPTER-PARENT-V3-FREEZE.NONAUTH.json"),
                ("PARENT_PATH", "joint-parent.py"),
                ("ADAPTER_PATH", "joint-adapter-parent-ready.py"),
                ("INTERFACE_PATH", "JOINT-PARENT-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "ADAPTER-PARENT-FREEZE.NONAUTH.json"),
                ("PARENT_PATH", "joint.py"),
                ("ADAPTER_PATH", "joint-adapter.py"),
                ("INTERFACE_PATH", "JOINT-8CASE-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "ADAPTER-FREEZE.NONAUTH.json")):
            with self.subTest(path=legacy_name), tempfile.TemporaryDirectory(
                    prefix="v164-joint-artifacts-old-name-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, \
                        mock.patch.object(joint, attribute, root / legacy_name), self.assertRaises(ValueError):
                    joint.verify_artifacts()

    def test_verify_artifacts_requires_exact_seven_entry_v5_freeze_map(self) -> None:
        def wrong_pin(value):
            path = next(key for key in value["files"] if key.endswith("/test_joint_parent_v5_snapshot.py"))
            value["files"][path] = "0" * 64

        def extra_entry(value):
            value["files"]["unexpected.py"] = "1" * 64

        def missing_entry(value):
            path = next(key for key in value["files"] if key.endswith("/joint-parent-v5.py"))
            del value["files"][path]

        def legacy_entry(value):
            path = next(key for key in value["files"] if key.endswith("/joint-parent-v5.py"))
            value["files"][str(Path(path).with_name("joint-parent-v4.py"))] = value["files"].pop(path)

        def old_operator_source(value):
            value["operator_sources"]["joint-parent-v4.py"] = value["operator_sources"].pop("joint-parent-v5.py")

        def wrong_reserved_batch(value):
            value["reserved_batch"] = "v164-e2a1908-joint7-20261010"

        def wrong_preparation_reference(value):
            value["actual_compiler_review"]["sha256"] = "0" * 64

        def wrong_callback_count(value):
            value["callback_fields"] = 26

        def wrong_status(value):
            value["status"] = "PASS"

        def wrong_online_status(value):
            value["online"] = "GO"

        def wrong_qa_receipt_pin(value):
            value["qa_receipt"]["sha256"] = "0" * 64

        def legacy_qa_receipt_path(value):
            value["qa_receipt"]["path"] = str(Path(value["qa_receipt"]["path"]).with_name(
                "PREPARATION-RESULT.NONAUTH.json"))

        for label, mutate in (
                ("wrong pinned digest", wrong_pin),
                ("extra freeze entry", extra_entry),
                ("missing freeze entry", missing_entry),
                ("v4 freeze source name", legacy_entry),
                ("v4 operator source name", old_operator_source),
                ("reserved batch changed", wrong_reserved_batch),
                ("preparation reference changed", wrong_preparation_reference),
                ("callback count changed", wrong_callback_count),
                ("status changed", wrong_status),
                ("online status changed", wrong_online_status),
                ("QA receipt pin changed", wrong_qa_receipt_pin),
                ("legacy QA receipt path", legacy_qa_receipt_path)):
            with self.subTest(mutation=label), tempfile.TemporaryDirectory(
                    prefix="v164-joint-artifacts-freeze-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, freeze_value, expected = self.artifact_fixture(root)
                mutate(freeze_value)
                changed_freeze = json.dumps(
                    freeze_value, sort_keys=True, separators=(",", ":")).encode()
                write_file(freeze, changed_freeze)
                expected = dict(expected, freeze_sha256=digest(changed_freeze))
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches, self.assertRaises(ValueError):
                    joint.verify_artifacts()


if __name__ == "__main__":
    unittest.main()
