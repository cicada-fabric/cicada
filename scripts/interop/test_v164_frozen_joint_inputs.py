#!/usr/bin/env python3
"""Offline checks for the fixed Core adapter control and path interface."""

from __future__ import annotations

import copy
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
        self.assertEqual(joint.PARENT_PATH.name, "joint-parent.py")
        self.assertEqual(joint.ADAPTER_PATH.name, "joint-adapter-parent-ready.py")
        self.assertEqual(joint.INTERFACE_PATH.name, "JOINT-PARENT-INTERFACE.NONAUTH.md")
        self.assertEqual(joint.FREEZE_PATH.name, "ADAPTER-PARENT-FREEZE.NONAUTH.json")
        self.assertEqual(joint.FROZEN_ARTIFACT_HASHES, {
            "parent_sha256": "479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794",
            "adapter_sha256": "7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4",
            "interface_sha256": "8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570",
            "freeze_sha256": "6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39",
        })
        self.assertEqual(joint.FROZEN_PREPARATION_TEST_HASHES, {
            "test_joint_adapter_parent_ready.py": "21a9bf235542a99c34d736406e37f9f3551349d9bacf4b0fe00eae3f72cb0add",
            "test_joint_parent.py": "660f201b30f4e27089ae6a7f4a8151c80bd492cfa7e52934fc945b3564a9ea1b",
        })
        self.assertEqual(joint.ANDROID_BASE_URL, "http://127.0.0.1:8787")

    def test_ready_runner_is_the_new_adapter_not_parent_or_previous_adapter(self) -> None:
        adapter_sha = joint.FROZEN_ARTIFACT_HASHES["adapter_sha256"]
        self.assertEqual(joint._validate_runner_sha256(adapter_sha), adapter_sha)
        for label, candidate in (
                ("Parent source is not the fixture runner", joint.FROZEN_ARTIFACT_HASHES["parent_sha256"]),
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
        parent = root / "joint-parent.py"
        adapter = root / "joint-adapter-parent-ready.py"
        interface = root / "JOINT-PARENT-INTERFACE.NONAUTH.md"
        freeze = root / "ADAPTER-PARENT-FREEZE.NONAUTH.json"
        parent_raw = b"# synthetic frozen Root Parent source\n"
        adapter_raw = b"# synthetic frozen Parent-ready adapter\n"
        interface_raw = b"# synthetic frozen Parent interface\n"
        freeze_value = {
            "status": "PASS_PREPARATION_SCOPE_ONLY",
            "online": "NOT_GO",
            "files": {
                "JOINT-PARENT-INTERFACE.NONAUTH.md": digest(interface_raw),
                "joint-adapter-parent-ready.py": digest(adapter_raw),
                "joint-parent.py": digest(parent_raw),
                **joint.FROZEN_PREPARATION_TEST_HASHES,
            },
        }
        freeze_raw = json.dumps(freeze_value, sort_keys=True, separators=(",", ":")).encode()
        write_file(parent, parent_raw)
        write_file(interface, interface_raw)
        write_file(adapter, adapter_raw)
        write_file(freeze, freeze_raw)
        expected = {
            "parent_sha256": digest(parent_raw),
            "interface_sha256": digest(interface_raw),
            "freeze_sha256": digest(freeze_raw),
            "adapter_sha256": digest(adapter_raw),
        }
        return parent, adapter, interface, freeze, freeze_value, expected

    def patch_artifacts(self, parent: Path, adapter: Path, interface: Path, freeze: Path,
            expected: dict[str, str]):
        return (
            mock.patch.object(joint, "PARENT_PATH", parent),
            mock.patch.object(joint, "INTERFACE_PATH", interface),
            mock.patch.object(joint, "ADAPTER_PATH", adapter),
            mock.patch.object(joint, "FREEZE_PATH", freeze),
            mock.patch.object(joint, "FROZEN_ARTIFACT_HASHES", expected),
        )

    def test_verify_artifacts_accepts_only_the_exact_private_frozen_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-") as temp:
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(Path(temp))
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                self.assertEqual(joint.verify_artifacts(), expected)

    def test_verify_artifacts_rejects_changed_bytes_wrong_modes_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-bytes-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            write_file(interface, b"# changed bytes\n")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
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
                with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                    joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-mode-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            interface.chmod(0o644)
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-link-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            target = root / "interface-target.private"
            interface.rename(target)
            interface.symlink_to(target)
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                joint.verify_artifacts()

    def test_verify_artifacts_rejects_parent_mismatch_and_previous_source_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-parent-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            write_file(parent, b"# changed Parent bytes\n")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                joint.verify_artifacts()

        with tempfile.TemporaryDirectory(prefix="v164-joint-artifacts-old-pins-") as temp:
            root = Path(temp)
            parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
            old_source_pins = dict(expected,
                interface_sha256="618ecef915ad00c6f9fc61d842285989a8e61c59eded900c26aa64cc0e216805",
                freeze_sha256="eb34be4e43c4ae8e64e5b7fc397e76be0a2ef47b10cd5313918361b4d6eaa107",
                adapter_sha256="29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4")
            patches = self.patch_artifacts(parent, adapter, interface, freeze, old_source_pins)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                joint.verify_artifacts()

    def test_verify_artifacts_rejects_legacy_source_filenames(self) -> None:
        for attribute, legacy_name in (
                ("PARENT_PATH", "joint.py"),
                ("ADAPTER_PATH", "joint-adapter.py"),
                ("INTERFACE_PATH", "JOINT-8CASE-INTERFACE.NONAUTH.md"),
                ("FREEZE_PATH", "ADAPTER-FREEZE.NONAUTH.json")):
            with self.subTest(path=legacy_name), tempfile.TemporaryDirectory(
                    prefix="v164-joint-artifacts-old-name-") as temp:
                root = Path(temp)
                parent, adapter, interface, freeze, _value, expected = self.artifact_fixture(root)
                patches = self.patch_artifacts(parent, adapter, interface, freeze, expected)
                with patches[0], patches[1], patches[2], patches[3], patches[4], \
                        mock.patch.object(joint, attribute, root / legacy_name), self.assertRaises(ValueError):
                    joint.verify_artifacts()

    def test_verify_artifacts_requires_exact_five_entry_freeze_map(self) -> None:
        def wrong_pin(value):
            value["files"]["test_joint_parent.py"] = "0" * 64

        def extra_entry(value):
            value["files"]["unexpected.py"] = "1" * 64

        def missing_entry(value):
            del value["files"]["joint-parent.py"]

        def wrong_status(value):
            value["status"] = "PASS"

        def wrong_online_status(value):
            value["online"] = "GO"

        for label, mutate in (
                ("wrong pinned digest", wrong_pin),
                ("extra freeze entry", extra_entry),
                ("missing freeze entry", missing_entry),
                ("status changed", wrong_status),
                ("online status changed", wrong_online_status)):
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
                with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
                    joint.verify_artifacts()


if __name__ == "__main__":
    unittest.main()
