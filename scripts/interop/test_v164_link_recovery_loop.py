#!/usr/bin/env python3
"""Offline guards for the bounded v1.6.4 recovery loop and process runner.

Socket tests use only socketpair callbacks. The process-runner tests use a
bounded Python argv and never invoke Docker, ADB, Hub/Core, or the network.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


loop = load("v164_link_recovery_loop_test", "v164-link-recovery-loop.py")
budget = loop.budget


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write_private_json(path: Path, value: object) -> dict[str, str]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = compact(value)
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)
    return {"path": str(path), "sha256": digest(raw)}


def recovery_plan_fixture(root: Path) -> tuple[dict[str, object], Path, tempfile.TemporaryDirectory]:
    cache = root / "cache"
    cache.mkdir(mode=0o700)
    recovery_run = "v16-deterministic-v164-recovery-offline-tests"
    android_evidence = cache / recovery_run / "artifacts"
    android_evidence.mkdir(mode=0o700, parents=True)
    evidence_root = cache / "batch-evidence"
    evidence_root.mkdir(mode=0o700)

    inputs = loop.inputs
    pins = {
        "schema": inputs.PINS_SCHEMA,
        "run_scope": inputs.RUN_SCOPE,
        **{key: inputs.delivery.PINS[key] for key in inputs.CORE_KEYS},
        "delivery_manifest_sha256": inputs.delivery.DELIVERY_SHA256,
        "client_build_commit": loop.BUILD_COMMIT,
        "client_build_dirty": True,
        "client_input_sha256": loop.BUILD_INPUT_SHA,
        "app_sha256": loop.APP_SHA,
        "test_sha256": loop.TEST_SHA,
    }
    pin_ref = write_private_json(root / "apk-pins.private.json", pins)

    # The frozen Core checkout is not mounted in the offline Docker test. Keep
    # the accepted path shape while placing only empty synthetic case folders
    # there. Plan tests patch joint.verify_artifacts and never touch Core files.
    core_fixture = tempfile.TemporaryDirectory(prefix="cicada-joint-e2a-", dir="/tmp")
    core_fixture_root = Path(core_fixture.name)
    cases = []
    run_base = loop.joint.RUN_ID
    ordered_pairs = ((operation, mode) for operation in inputs.OPERATIONS for mode in inputs.MODES)
    for case_index, (operation, mode) in enumerate(ordered_pairs):
        fixture_root = core_fixture_root / "cases" / str(case_index)
        fixture_root.mkdir(mode=0o700, parents=True)
        cases.append({
            "case_id": f"case_{case_index}",
            "run_id": f"{run_base}-{case_index}",
            "core_case_index": case_index,
            "side": "source",
            "operation": operation,
            "mode": mode,
            "fixture_root": str(fixture_root),
        })

    plan = {
        "schema": loop.PLAN_SCHEMA,
        "batch_id": "offline-test-batch",
        "android_evidence": str(android_evidence),
        "evidence_root": str(evidence_root),
        "core_fixture_root": str(core_fixture_root),
        "apk_pins": pin_ref,
        "driver_sha256": {
            name: digest((HERE / name).read_bytes()) for name in loop.DRIVERS
        },
        "cases": cases,
    }
    return plan, cache, core_fixture


def valid_go(plan_sha256: str, **changes: object) -> dict[str, object]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    value: dict[str, object] = {
        "schema": loop.GO_SCHEMA,
        "root_thread_id": loop.ROOT_THREAD,
        "batch_id": "offline-test-batch",
        "plan_sha256": plan_sha256,
        "approved": True,
        "approval_id": "root-approval-1",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "outer_seconds": 3600,
        "case_seconds": 360,
    }
    value.update(changes)
    return value


class PlanAndGoTests(unittest.TestCase):
    def test_plan_requires_exactly_eight_unique_operation_mode_pairs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-loop-plan-") as temp:
            root = Path(temp)
            plan, cache, core_fixture = recovery_plan_fixture(root)
            self.addCleanup(core_fixture.cleanup)
            with mock.patch.object(loop, "CACHE", cache), mock.patch.object(
                    loop.joint, "verify_artifacts",
                    return_value=dict(loop.joint.FROZEN_ARTIFACT_HASHES)) as verify_artifacts:
                self.assertEqual(plan["schema"], "cicada.client-v164-recovery-loop-plan.v2")
                self.assertIs(loop.validate_plan(plan), plan)
                verify_artifacts.assert_called_once_with()
                expected_modes = ("response-loss", "processing", "uncertain", "legacy")
                expected_pairs = [("link.key_grant", mode) for mode in expected_modes] + [
                    ("link.review_policy_grant", mode) for mode in expected_modes]
                self.assertEqual([(case["operation"], case["mode"]) for case in plan["cases"]],
                    expected_pairs)
                self.assertEqual([case["core_case_index"] for case in plan["cases"]], list(range(8)))
                self.assertTrue(all(case["side"] == "source" for case in plan["cases"]))
                self.assertEqual([case["run_id"] for case in plan["cases"]],
                    [f"{loop.joint.RUN_ID}-{index}" for index in range(8)])
                self.assertEqual([case["fixture_root"] for case in plan["cases"]],
                    [str(Path(plan["core_fixture_root"]) / "cases" / str(index)) for index in range(8)])

                for count in (7, 9):
                    malformed = copy.deepcopy(plan)
                    malformed["cases"] = malformed["cases"][:count] if count == 7 else \
                        malformed["cases"] + [copy.deepcopy(malformed["cases"][0])]
                    with self.subTest(count=count), self.assertRaises(loop.LoopError):
                        loop.validate_plan(malformed)

                duplicate_pair = copy.deepcopy(plan)
                duplicate_pair["cases"][1]["operation"] = duplicate_pair["cases"][0]["operation"]
                duplicate_pair["cases"][1]["mode"] = duplicate_pair["cases"][0]["mode"]
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(duplicate_pair)

                outside_root = copy.deepcopy(plan)
                outside_root["cases"][0]["fixture_root"] = str(root / "outside-cache")
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(outside_root)

                wrong_case_root = copy.deepcopy(plan)
                wrong_case_root["cases"][0]["fixture_root"] = wrong_case_root["cases"][1]["fixture_root"]
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_case_root)

                wrong_side = copy.deepcopy(plan)
                wrong_side["cases"][0]["side"] = "target"
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_side)

                wrong_index = copy.deepcopy(plan)
                wrong_index["cases"][0]["core_case_index"] = 1
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_index)

                non_integer_index = copy.deepcopy(plan)
                non_integer_index["cases"][0]["core_case_index"] = True
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(non_integer_index)

                wrong_run_base = copy.deepcopy(plan)
                wrong_run_base["cases"][4]["run_id"] = "v164-another-batch-4"
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_run_base)

                consistent_other_run_base = copy.deepcopy(plan)
                for index, case in enumerate(consistent_other_run_base["cases"]):
                    case["run_id"] = f"v164-e2a1908-other-{index}"
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(consistent_other_run_base)

                wrong_run_index = copy.deepcopy(plan)
                wrong_run_index["cases"][4]["run_id"] = f"{loop.joint.RUN_ID}-3"
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_run_index)

                wrong_order = copy.deepcopy(plan)
                wrong_order["cases"][0]["operation"], wrong_order["cases"][4]["operation"] = (
                    wrong_order["cases"][4]["operation"], wrong_order["cases"][0]["operation"])
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_order)

                outside_core_root = copy.deepcopy(plan)
                outside_core_root["core_fixture_root"] = str(root / "not-a-joint-root")
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(outside_core_root)

                missing_core_root = copy.deepcopy(plan)
                del missing_core_root["core_fixture_root"]
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(missing_core_root)

    def test_plan_refuses_old_apk_f6_lane_and_mismatched_driver_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-loop-pins-") as temp:
            root = Path(temp)
            plan, cache, core_fixture = recovery_plan_fixture(root)
            self.addCleanup(core_fixture.cleanup)
            with mock.patch.object(loop, "CACHE", cache), mock.patch.object(
                    loop.joint, "verify_artifacts",
                    return_value=dict(loop.joint.FROZEN_ARTIFACT_HASHES)):
                old_apk_pins = {
                    "schema": loop.inputs.PINS_SCHEMA,
                    "run_scope": loop.inputs.RUN_SCOPE,
                    **{key: loop.inputs.delivery.PINS[key] for key in loop.inputs.CORE_KEYS},
                    "delivery_manifest_sha256": loop.inputs.delivery.DELIVERY_SHA256,
                    "client_build_commit": loop.BUILD_COMMIT,
                    "client_build_dirty": True,
                    "client_input_sha256": loop.BUILD_INPUT_SHA,
                    "app_sha256": loop.consent.runner.F6_APP_SHA256,
                    "test_sha256": loop.consent.runner.F6_TEST_SHA256,
                }
                old_ref = write_private_json(root / "old-f6-pins.private.json", old_apk_pins)
                stale_apk = copy.deepcopy(plan)
                stale_apk["apk_pins"] = old_ref
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(stale_apk)

                correct_attribution = {
                    "schema": loop.inputs.PINS_SCHEMA,
                    "run_scope": loop.inputs.RUN_SCOPE,
                    **{key: loop.inputs.delivery.PINS[key] for key in loop.inputs.CORE_KEYS},
                    "delivery_manifest_sha256": loop.inputs.delivery.DELIVERY_SHA256,
                    "client_build_commit": loop.BUILD_COMMIT,
                    "client_build_dirty": True,
                    "client_input_sha256": loop.BUILD_INPUT_SHA,
                    "app_sha256": loop.APP_SHA,
                    "test_sha256": loop.TEST_SHA,
                }
                clean_relabel = copy.deepcopy(plan)
                clean_relabel["apk_pins"] = write_private_json(
                    root / "clean-relabel-pins.json",
                    dict(correct_attribution, client_build_dirty=False))
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(clean_relabel)

                wrong_commit = dict(correct_attribution, client_build_commit="a" * 40)
                wrong_commit_plan = copy.deepcopy(plan)
                wrong_commit_plan["apk_pins"] = write_private_json(
                    root / "wrong-build-commit-pins.json", wrong_commit)
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(wrong_commit_plan)

                historical_lane = copy.deepcopy(plan)
                historical_lane["delivery_pins_sha256"] = "c" * 64
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(historical_lane)

                stale_driver = copy.deepcopy(plan)
                stale_driver["driver_sha256"][loop.DRIVERS[0]] = "d" * 64
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(stale_driver)

                missing_driver = copy.deepcopy(plan)
                del missing_driver["driver_sha256"][loop.DRIVERS[-1]]
                with self.assertRaises(loop.LoopError):
                    loop.validate_plan(missing_driver)

    def test_root_go_must_be_present_unexpired_and_for_this_root_and_plan(self) -> None:
        plan_sha = digest(b"synthetic canonical plan bytes")
        go = valid_go(plan_sha)
        self.assertGreater(loop.validate_go(go, plan_sha, "offline-test-batch"), time.time())

        absent = None
        missing = dict(go)
        del missing["approved"]
        wrong_root = dict(go, root_thread_id="01a0a91b-c2b6-76b2-baf5-95422f4defff")
        wrong_plan = dict(go, plan_sha256=digest(b"different plan"))
        expired = dict(go, issued_at="2000-01-01T00:00:00Z", expires_at="2000-01-01T00:05:00Z")
        issued = dt.datetime.strptime(go["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        short_reserve = dict(go,
            expires_at=(issued + dt.timedelta(seconds=200)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        for label, candidate in (("absent GO", absent), ("missing field", missing), ("wrong root", wrong_root),
                ("wrong plan", wrong_plan), ("expired", expired), ("cleanup reserve under 240 seconds", short_reserve)):
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.validate_go(candidate, plan_sha, "offline-test-batch")


class OwnedCaseRootTests(unittest.TestCase):
    @staticmethod
    def owned_tree(index: int = 0):
        manager = tempfile.TemporaryDirectory(prefix="cicada-joint-e2a-", dir="/tmp")
        root = Path(manager.name)
        cases = root / "cases"
        cases.mkdir(mode=0o700)
        case_root = cases / str(index)
        case_root.mkdir(mode=0o700)
        plan = {"core_fixture_root": str(root)}
        case = {"core_case_index": index, "fixture_root": str(case_root)}
        return manager, plan, case, root, cases, case_root

    def test_owned_case_root_requires_exact_core_root_index_and_existing_owned_case(self) -> None:
        manager, plan, case, root, cases, case_root = self.owned_tree()
        self.addCleanup(manager.cleanup)
        loop.validate_owned_case_root(plan, case)

        other_case = cases / "1"
        other_case.mkdir(mode=0o700)
        for label, candidate_plan, candidate_case in (
                ("case index outside fixed range", plan, dict(case, core_case_index=8)),
                ("index points at another case", plan, dict(case, core_case_index=1)),
                ("fixture points at another case", plan, dict(case, fixture_root=str(other_case)))):
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(candidate_plan, candidate_case)

        with tempfile.TemporaryDirectory(prefix="arbitrary-joint-", dir="/tmp") as arbitrary:
            arbitrary_root = Path(arbitrary)
            arbitrary_case = arbitrary_root / "cases" / "0"
            arbitrary_case.mkdir(mode=0o700, parents=True)
            with self.subTest(label="arbitrary root"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(
                    {"core_fixture_root": str(arbitrary_root)},
                    {"core_case_index": 0, "fixture_root": str(arbitrary_case)})

        foreign_manager = tempfile.TemporaryDirectory(prefix="cicada-joint-e2a-", dir="/tmp")
        self.addCleanup(foreign_manager.cleanup)
        foreign_case = Path(foreign_manager.name) / "cases" / "0"
        foreign_case.mkdir(mode=0o700, parents=True)
        with self.subTest(label="foreign fixture root"), self.assertRaises(loop.LoopError):
            loop.validate_owned_case_root(plan, dict(case, fixture_root=str(foreign_case)))

    def test_absolute_path_rejects_lexical_aliases(self) -> None:
        canonical = "/tmp/cicada-joint-e2a-abcdefgh/cases/0"
        for label, value in (
                ("repeated separator", canonical.replace("/cases/", "//cases/")),
                ("dot component", canonical.replace("/cases/", "/./cases/")),
                ("trailing separator", canonical + "/")):
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.absolute_path(value)

    def test_owned_case_root_rejects_public_modes_at_each_directory_level(self) -> None:
        for label, component in (("Core root", "root"), ("cases directory", "cases"),
                ("case directory", "case")):
            manager, plan, case, root, cases, case_root = self.owned_tree()
            try:
                path = {"root": root, "cases": cases, "case": case_root}[component]
                path.chmod(0o755)
                with self.subTest(component=label), self.assertRaises(loop.LoopError):
                    loop.validate_owned_case_root(plan, case)
            finally:
                manager.cleanup()

    def test_owned_case_root_rejects_symlinked_levels(self) -> None:
        manager, plan, case, root, cases, case_root = self.owned_tree()
        root_link = root.with_name(root.name + "-alias")
        try:
            root_link.symlink_to(root, target_is_directory=True)
            with self.subTest(component="Core root"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(
                    {"core_fixture_root": str(root_link)},
                    dict(case, fixture_root=str(root_link / "cases" / "0")))
        finally:
            if root_link.is_symlink():
                root_link.unlink()
            manager.cleanup()

        manager, plan, case, root, cases, case_root = self.owned_tree()
        cases_real = cases.with_name("cases-real")
        try:
            cases.rename(cases_real)
            cases.symlink_to(cases_real, target_is_directory=True)
            with self.subTest(component="cases directory"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(plan, case)
        finally:
            if cases.is_symlink():
                cases.unlink()
            if cases_real.exists():
                cases_real.rename(cases)
            manager.cleanup()

        manager, plan, case, root, cases, case_root = self.owned_tree()
        case_real = cases / "0-real"
        try:
            case_root.rename(case_real)
            case_root.symlink_to(case_real, target_is_directory=True)
            with self.subTest(component="case directory"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(plan, case)
        finally:
            if case_root.is_symlink():
                case_root.unlink()
            if case_real.exists():
                case_real.rename(case_root)
            manager.cleanup()

    def test_owned_case_root_rejects_non_directory_levels(self) -> None:
        manager, plan, case, root, cases, case_root = self.owned_tree()
        root_real = root.with_name(root.name + "-real")
        try:
            root.rename(root_real)
            root.write_text("synthetic non-directory Core root", encoding="utf-8")
            with self.subTest(component="Core root"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(plan, case)
        finally:
            if root.is_file():
                root.unlink()
            if root_real.exists():
                root_real.rename(root)
            manager.cleanup()

        manager, plan, case, root, cases, case_root = self.owned_tree()
        cases_real = cases.with_name("cases-real")
        try:
            cases.rename(cases_real)
            cases.write_text("synthetic non-directory cases node", encoding="utf-8")
            with self.subTest(component="cases directory"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(plan, case)
        finally:
            if cases.is_file():
                cases.unlink()
            if cases_real.exists():
                cases_real.rename(cases)
            manager.cleanup()

        manager, plan, case, root, cases, case_root = self.owned_tree()
        try:
            case_root.rmdir()
            case_root.write_text("synthetic non-directory case node", encoding="utf-8")
            with self.subTest(component="case directory"), self.assertRaises(loop.LoopError):
                loop.validate_owned_case_root(plan, case)
        finally:
            if case_root.is_file():
                case_root.unlink()
            manager.cleanup()


class FaultReadyVerificationTests(unittest.TestCase):
    def test_carrier_control_requires_literal_capture_verification_first(self) -> None:
        ready = {
            "ready": {"path": "/tmp/frozen-case/public/fault-envelope.json", "sha256": "a" * 64},
            "capture_verified": True,
            "control_installed": True,
        }
        self.assertIsNone(loop.validate_fault_ready_reply(ready))

        variants = (
            ("capture not verified", dict(ready, capture_verified=False)),
            ("carrier installed before verification", dict(ready, capture_verified=False, control_installed=True)),
            ("control not installed", dict(ready, control_installed=False)),
            ("truthy integer capture", dict(ready, capture_verified=1)),
            ("truthy integer control", dict(ready, control_installed=1)),
            ("unknown field", dict(ready, scenario={"run_id": "not-an-input"})),
            ("missing capture flag", {key: value for key, value in ready.items() if key != "capture_verified"}),
            ("missing control flag", {key: value for key, value in ready.items() if key != "control_installed"}),
        )
        for label, candidate in variants:
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.validate_fault_ready_reply(candidate)


class ParentChannelTests(unittest.TestCase):
    def test_rejects_unix_peer_with_an_untrusted_uid(self) -> None:
        client, server = socket.socketpair()
        try:
            fake_credentials = struct.pack("3i", os.getpid(), os.getuid() + 1, os.getgid())
            with mock.patch.object(socket.socket, "getsockopt", return_value=fake_credentials):
                with self.assertRaises(loop.LoopError):
                    loop.ParentChannel(client.fileno(), "socket-test-batch")
        finally:
            client.close()
            server.close()

    def exchange(self, response_factory, *, timeout: float = 1.0,
            close_peer: bool = False, response_delay: float = 0.0,
            close_original: bool = False):
        client, server = socket.socketpair()
        parent = loop.ParentChannel(client.fileno(), "socket-test-batch")
        if close_original:
            client.close()
        observed: dict[str, object] = {}

        def callback() -> None:
            data = bytearray()
            try:
                while b"\n" not in data:
                    part = server.recv(4096)
                    if not part:
                        return
                    data.extend(part)
                request = json.loads(bytes(data))
                observed["request"] = request
                if close_peer:
                    server.close()
                    return
                if response_delay:
                    time.sleep(response_delay)
                response = response_factory(request)
                if response is not None:
                    try:
                        server.sendall(response)
                    except OSError:
                        # The tested absolute deadline may close the duplicated
                        # client socket before this delayed synthetic callback.
                        pass
            except OSError:
                pass

        thread = threading.Thread(target=callback, daemon=True)
        thread.start()
        result = None
        error = None
        try:
            result = parent.request(
                "TEST_EVENT", "case_socket", {"fixture": "synthetic"}, budget.Deadline.after(timeout))
        except Exception as caught:  # Return the error so each case can state its expected class.
            error = caught
        finally:
            parent.close()
            client.close()
            server.close()
            thread.join(timeout=1.0)
        return result, error, observed

    @staticmethod
    def reply(request: dict[str, object], **changes: object) -> bytes:
        value: dict[str, object] = {
            "schema": loop.REPLY_SCHEMA,
            "request_id": request["request_id"],
            "batch_id": request["batch_id"],
            "case_id": request["case_id"],
            "event": request["event"],
            "result": "READY",
            "payload": {"ready": True},
        }
        value.update(changes)
        return loop.canonical(value)

    def test_inherited_fd_is_duplicated_and_correlated_reply_succeeds(self) -> None:
        result, error, observed = self.exchange(self.reply, close_original=True)
        self.assertIsNone(error)
        self.assertEqual(result, {"ready": True})
        request = observed["request"]
        self.assertEqual(request["request_id"], 1)
        self.assertEqual(request["batch_id"], "socket-test-batch")
        self.assertEqual(request["event"], "TEST_EVENT")
        self.assertGreater(request["remaining_ms"], 0)

    def test_socket_peer_drop_malformed_frames_and_correlation_mismatch_fail_closed(self) -> None:
        result, error, _ = self.exchange(self.reply, close_peer=True)
        self.assertIsNone(result)
        self.assertIsInstance(error, loop.LoopError)

        malformed = (
            lambda _request: b"{broken json}\n",
            lambda _request: b"{}\n{}\n",
            lambda request: self.reply(request, request_id=request["request_id"] + 1),
            lambda request: self.reply(request, batch_id="other-batch"),
            lambda request: self.reply(request, case_id="other-case"),
            lambda request: self.reply(request, event="OTHER_EVENT"),
            lambda request: self.reply(request, payload={"token": ""}),
        )
        for index, factory in enumerate(malformed):
            with self.subTest(index=index):
                result, error, _ = self.exchange(factory)
                self.assertIsNone(result)
                self.assertIsInstance(error, ValueError)

    def test_parent_block_and_silent_callback_timeout_remain_distinct(self) -> None:
        result, error, _ = self.exchange(
            lambda request: self.reply(request, result="BLOCKED"))
        self.assertIsNone(result)
        self.assertIsInstance(error, loop.ParentBlocked)

        result, error, _ = self.exchange(
            self.reply, timeout=0.08, response_delay=0.25)
        self.assertIsNone(result)
        self.assertIsInstance(error, loop.LoopError)


class PublicFileReferenceTests(unittest.TestCase):
    def test_only_public_json_refs_without_secrets_path_segments_are_accepted(self) -> None:
        for candidate in (
                {"path": "/tmp/offline-input.bin", "sha256": "a" * 64},
                {"path": "/tmp/secrets/fixture.json", "sha256": "b" * 64}):
            with self.subTest(candidate=candidate), self.assertRaises(loop.LoopError):
                loop.FileRef.parse(candidate)


class DeadlineTests(unittest.TestCase):
    def test_nested_deadline_never_outlives_its_parent(self) -> None:
        outer = budget.Deadline.after(2)
        nested = budget.Deadline.after(60, parent=outer)
        self.assertLessEqual(nested._expires_at, outer._expires_at)
        self.assertLessEqual(nested.remaining(), outer.remaining() + 0.01)
        self.assertLessEqual(nested.clamp(60), outer.remaining() + 0.01)


class ReconciliationTests(unittest.TestCase):
    def fixture(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        case = {
            "case_id": "synthetic_case",
            "run_id": "v164-synthetic-case",
            "side": "source",
            "operation": "link.key_grant",
            "mode": "response-loss",
        }
        binding = {
            "hub_id": "synthetic-hub-id",
            "link_id": "synthetic-link-id",
            "link_version": 7,
            "source_owner_id": "synthetic-source-owner",
            "target_owner_id": "synthetic-target-owner",
            "device_id": "synthetic-faulted-device",
        }
        capture = {"proof_sha256": "a" * 64}
        review = {"native_review_json": {
            "manifestDigest": "e" * 64,
            "policyVersion": "1",
            "policyDigest": "a" * 64,
        }}
        value = {
            "schema": "cicada.client-v164-recovery-loop-direct-reconciliation.v1",
            "case_id": case["case_id"],
            "run_id_sha256": loop.sha(case["run_id"].encode()),
            "link_id_sha256": loop.sha(binding["link_id"].encode()),
            "link_version": "7",
            "owner_id_sha256": loop.sha(binding["target_owner_id"].encode()),
            "device_id_sha256": loop.sha(b"separate-reconciliation-device"),
            "hub_id_sha256": loop.sha(binding["hub_id"].encode()),
            "binding_sha256": loop.sha(loop.canonical(binding)),
            "manifest_digest": "e" * 64,
            "scope_binding_verified": True,
            "endpoint_attestations_verified": True,
            "owner_proofs_verified": True,
            "session_epoch": 1,
            "transport": "DIRECT",
            "encrypted_verified": True,
            "read_only": True,
            "proof_sha256": capture["proof_sha256"],
            "proof_observed": True,
            "source_status": "ACCEPTED",
            "target_status": "MISSING",
            "policy_mode": None,
            "bilateral_verified": False,
            "policy": None,
            "reads": [
                {
                    "operation": "link.key_manifest",
                    "operation_id_sha256": "b" * 64,
                    "request_sha256": "c" * 64,
                    "response_sha256": "d" * 64,
                    "request_sequence": "1",
                    "response_sequence": "2",
                },
                {
                    "operation": "link.key_grants",
                    "operation_id_sha256": "f" * 64,
                    "request_sha256": "1" * 64,
                    "response_sha256": "2" * 64,
                    "request_sequence": "3",
                    "response_sequence": "4",
                },
            ],
        }
        return case, binding, {**value, "_capture": capture, "_review": review}

    def test_accepts_separate_encrypted_read_only_proof_reconciliation(self) -> None:
        case, binding, wrapped = self.fixture()
        value = dict(wrapped)
        capture = value.pop("_capture")
        review = value.pop("_review")
        self.assertIsNone(loop.validate_reconciliation(value, case, binding, capture, review))

        for mode in ("processing", "uncertain", "legacy"):
            outer_absent = copy.deepcopy(value)
            outer_absent.update(proof_observed=False, source_status="MISSING")
            with self.subTest(outer_absent_mode=mode):
                self.assertIsNone(loop.validate_reconciliation(
                    outer_absent, dict(case, mode=mode), binding, capture, review))

    def test_key_reconciliation_is_source_only_and_requires_its_exact_ordered_read_pair(self) -> None:
        case, binding, wrapped = self.fixture()
        value = dict(wrapped)
        capture = value.pop("_capture")
        review = value.pop("_review")
        self.assertIsNone(loop.validate_reconciliation(value, case, binding, capture, review))

        for mode in ("response-loss", "processing", "uncertain", "legacy"):
            opposite_present = copy.deepcopy(value)
            selected_case = dict(case, mode=mode)
            if mode == "response-loss":
                opposite_present.update(target_status="ACCEPTED", bilateral_verified=True)
            else:
                opposite_present.update(proof_observed=False, source_status="MISSING",
                    target_status="ACCEPTED", bilateral_verified=False)
            with self.subTest(opposite_present_mode=mode), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(opposite_present, selected_case, binding, capture, review)

        extra = copy.deepcopy(value)
        extra["reads"].append({
            "operation": "link.list", "operation_id_sha256": "9" * 64,
            "request_sha256": "8" * 64, "response_sha256": "7" * 64,
            "request_sequence": "5", "response_sequence": "6",
        })
        duplicate = copy.deepcopy(value)
        repeated = dict(duplicate["reads"][1], operation_id_sha256="9" * 64,
            request_sha256="8" * 64, response_sha256="7" * 64,
            request_sequence="5", response_sequence="6")
        duplicate["reads"].append(repeated)
        reordered = copy.deepcopy(value)
        reordered["reads"][0]["operation"], reordered["reads"][1]["operation"] = (
            reordered["reads"][1]["operation"], reordered["reads"][0]["operation"])
        for label, candidate in (("extra operation", extra), ("duplicate operation", duplicate),
                ("reordered operations", reordered)):
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)

    def test_rejects_faulted_device_foreign_owner_writes_missing_rpc_and_acceptance_inference(self) -> None:
        case, binding, wrapped = self.fixture()
        baseline = dict(wrapped)
        capture = baseline.pop("_capture")
        review = baseline.pop("_review")
        mutations = (
            {"device_id_sha256": loop.sha(binding["device_id"].encode())},
            {"owner_id_sha256": loop.sha(b"foreign-owner")},
            {"owner_id_sha256": loop.sha(binding["source_owner_id"].encode())},
            {"hub_id_sha256": loop.sha(b"foreign-hub")},
            {"binding_sha256": "0" * 64},
            {"manifest_digest": "not-a-digest"},
            {"scope_binding_verified": False},
            {"endpoint_attestations_verified": False},
            {"owner_proofs_verified": False},
            {"read_only": False},
            {"reads": []},
            {"reads": [{**baseline["reads"][0], "operation": "link.list"}]},
            {"reads": [{**baseline["reads"][0], "operation": "link.key_grant"}]},
            {"reads": [{**baseline["reads"][0], "operation": "link.recover"}]},
            {"proof_sha256": "e" * 64},
            {"proof_observed": False},
            {"source_status": "INVALID"},
            {"bilateral_verified": True},
            {"policy": {"unexpected": "key-mode-policy"}},
        )
        for index, mutation in enumerate(mutations):
            candidate = {**baseline, **mutation}
            with self.subTest(index=index, mutation=mutation), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)

        changed_manifest_review = {"native_review_json": {
            **review["native_review_json"], "manifestDigest": "0" * 64}}
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(baseline, case, binding, capture, changed_manifest_review)

        bilateral_without_peer = {**baseline, "target_status": "ACCEPTED"}
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(bilateral_without_peer, case, binding, capture, review)

        duplicate_ids = copy.deepcopy(baseline)
        duplicate_ids["reads"][1]["operation_id_sha256"] = duplicate_ids["reads"][0]["operation_id_sha256"]
        equal_sequence = copy.deepcopy(baseline)
        equal_sequence["reads"][1]["request_sequence"] = equal_sequence["reads"][0]["request_sequence"]
        decreasing_response = copy.deepcopy(baseline)
        decreasing_response["reads"][1]["response_sequence"] = decreasing_response["reads"][0]["response_sequence"]
        for label, candidate in (("duplicate operation id", duplicate_ids),
                ("reused request sequence", equal_sequence), ("reused response sequence", decreasing_response)):
            with self.subTest(label=label), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)

    def test_none_policy_reconciliation_requires_all_authoritative_reads(self) -> None:
        case, binding, wrapped = self.fixture()
        case["operation"] = "link.review_policy_grant"
        case["mode"] = "processing"
        capture = dict(wrapped.pop("_capture"))
        review = wrapped.pop("_review")
        value = dict(wrapped)
        value.update({
            "binding_sha256": loop.sha(loop.canonical(binding)),
            "manifest_digest": review["native_review_json"]["manifestDigest"],
            "proof_observed": False,
            "source_status": "MISSING",
            "target_status": "MISSING",
            "policy_mode": "NONE",
            "policy": {
                "candidate_version": "1",
                "candidate_digest": "a" * 64,
                "candidate_current": False,
                "candidate_evidence_origin": "DB_READONLY_CONFIRMED_ABSENT",
                "candidate_evidence_receipt_sha256": "9" * 64,
                "head_version": "0",
                "head_digest": "",
                "head_current": True,
                "head_source_status": "MISSING",
                "head_target_status": "MISSING",
                "head_bilateral_verified": False,
            },
            "reads": [],
        })
        for index, operation in enumerate(("link.key_manifest", "link.key_grants",
                "link.review_policy_status", "link.review_policy_preview")):
            value["reads"].append({
                "operation": operation,
                "operation_id_sha256": f"{index + 1:x}" * 64,
                "request_sha256": f"{index + 5:x}" * 64,
                "response_sha256": f"{index + 9:x}" * 64,
                "request_sequence": str(2 * index + 1),
                "response_sequence": str(2 * index + 2),
            })
        for mode in ("processing", "uncertain", "legacy"):
            with self.subTest(outer_absent_mode=mode):
                self.assertIsNone(loop.validate_reconciliation(
                    value, dict(case, mode=mode), binding, capture, review))

        loss_head_zero = copy.deepcopy(value)
        loss_head_zero["proof_observed"] = True
        loss_head_zero["source_status"] = "VERIFIED"
        loss_head_zero["policy"]["candidate_evidence_origin"] = "DB_READONLY_VERIFIED_SIGNED_PROOF"
        loss_case = dict(case, mode="response-loss")
        self.assertIsNone(loop.validate_reconciliation(
            loss_head_zero, loss_case, binding, capture, review))

        bad_policy_candidates = (
            {"candidate_version": "4"},
            {"candidate_digest": "b" * 64},
            {"candidate_current": True},
            {"candidate_evidence_origin": "DB_READONLY_VERIFIED_SIGNED_PROOF"},
            {"candidate_evidence_origin": "E2EE_VERIFIED_SIGNED_PROOF"},
            {"candidate_evidence_origin": "DB_READONLY_CONFIRMED_ABSENT_WITH_UNVERIFIED_PROOF"},
            {"candidate_evidence_receipt_sha256": ""},
            {"candidate_evidence_receipt_sha256": "A" * 64},
            {"candidate_evidence_receipt_sha256": "g" * 64},
            {"candidate_evidence_receipt_sha256": "9" * 63},
            {"head_version": "1"},
            {"head_digest": "b" * 64},
            {"head_current": False},
            {"head_source_status": "VERIFIED"},
            {"head_target_status": "VERIFIED"},
            {"head_bilateral_verified": True},
        )
        for index, mutation in enumerate(bad_policy_candidates):
            candidate = copy.deepcopy(value)
            candidate["policy"].update(mutation)
            with self.subTest(policy_mutation=mutation), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)

        missing_origin = copy.deepcopy(value)
        del missing_origin["policy"]["candidate_evidence_origin"]
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(missing_origin, case, binding, capture, review)
        missing_receipt = copy.deepcopy(value)
        del missing_receipt["policy"]["candidate_evidence_receipt_sha256"]
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(missing_receipt, case, binding, capture, review)
        extra_evidence_claim = copy.deepcopy(value)
        extra_evidence_claim["policy"]["candidate_evidence_label"] = "E2EE_CURRENT_HEAD"
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(extra_evidence_claim, case, binding, capture, review)

        downgraded_loss = copy.deepcopy(loss_head_zero)
        downgraded_loss["policy"]["candidate_evidence_origin"] = "DB_READONLY_CONFIRMED_ABSENT"
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(downgraded_loss, loss_case, binding, capture, review)

        head_inferred_from_absent_candidate = copy.deepcopy(value)
        head_inferred_from_absent_candidate["policy"].update({
            "head_version": head_inferred_from_absent_candidate["policy"]["candidate_version"],
            "head_digest": head_inferred_from_absent_candidate["policy"]["candidate_digest"],
            "head_source_status": "VERIFIED",
            "head_target_status": "VERIFIED",
            "head_bilateral_verified": True,
        })
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(head_inferred_from_absent_candidate, case, binding, capture, review)

        full_bilateral = copy.deepcopy(loss_head_zero)
        full_bilateral.update({"target_status": "VERIFIED", "bilateral_verified": True})
        full_bilateral["policy"].update({
            "candidate_current": True,
            "head_version": "1",
            "head_digest": "a" * 64,
            "head_source_status": "VERIFIED",
            "head_target_status": "VERIFIED",
            "head_bilateral_verified": True,
        })
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(full_bilateral, loss_case, binding, capture, review)

        wrong_joint_candidate_version = copy.deepcopy(value)
        wrong_joint_candidate_version["policy"]["candidate_version"] = "2"
        wrong_native_receipt = copy.deepcopy(review)
        wrong_native_receipt["native_review_json"]["policyVersion"] = "2"
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(wrong_joint_candidate_version, case, binding, capture,
                wrong_native_receipt)

        extra_top_level_evidence = copy.deepcopy(value)
        extra_top_level_evidence["candidate_evidence_origin"] = "DB_READONLY_CONFIRMED_ABSENT"
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(extra_top_level_evidence, case, binding, capture, review)
        missing_top_level = copy.deepcopy(value)
        del missing_top_level["reads"]
        with self.assertRaises(loop.LoopError):
            loop.validate_reconciliation(missing_top_level, case, binding, capture, review)

        extra_read = copy.deepcopy(value)
        extra_read["reads"].append({
            "operation": "link.list", "operation_id_sha256": "d" * 64,
            "request_sha256": "e" * 64, "response_sha256": "f" * 64,
            "request_sequence": "9", "response_sequence": "10",
        })
        repeated_read = copy.deepcopy(value)
        repeated_read["reads"].append(dict(repeated_read["reads"][1],
            operation_id_sha256="d" * 64, request_sha256="e" * 64,
            response_sha256="f" * 64, request_sequence="9", response_sequence="10"))
        reordered_reads = copy.deepcopy(value)
        reordered_reads["reads"][2]["operation"], reordered_reads["reads"][3]["operation"] = (
            reordered_reads["reads"][3]["operation"], reordered_reads["reads"][2]["operation"])
        for label, candidate in (("extra operation", extra_read),
                ("duplicate operation", repeated_read), ("reordered operations", reordered_reads)):
            with self.subTest(read_set=label), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)

        for removed in ("link.key_manifest", "link.key_grants", "link.review_policy_status",
                "link.review_policy_preview"):
            candidate = copy.deepcopy(value)
            candidate["reads"] = [row for row in candidate["reads"] if row["operation"] != removed]
            with self.subTest(missing=removed), self.assertRaises(loop.LoopError):
                loop.validate_reconciliation(candidate, case, binding, capture, review)


def cleanup_fixture(root: Path):
    cache = root / "cache"
    session = "v16-deterministic-v164-recovery-loop-harness"
    android_evidence = cache / session / "artifacts"
    evidence_root = cache / "batch"
    core_fixture = tempfile.TemporaryDirectory(prefix="cicada-joint-e2a-", dir="/tmp")
    core_fixture_root = Path(core_fixture.name)
    android_evidence.mkdir(mode=0o700, parents=True)
    evidence_root.mkdir(mode=0o700)
    ownership = {
        "schema": "cicada.client-v164-recovery-loop-android-owned.v1",
        "container_id": "1" * 64,
        "image_id": loop.consent.driver.IMAGE,
        "network": "none",
        "auto_remove": True,
        "label": loop.consent.runner.LABEL,
        "run_id": session,
    }
    ownership_ref = write_private_json(android_evidence / "ownership.json", ownership)
    container = ownership["container_id"]
    command_values = {
        "remove": {
            "schema": "cicada.client-v164-recovery-loop-android-command.v1",
            "role": "remove",
            "argv": ["docker", "rm", "--force", container],
            "exit_code": 0,
            "stdout_sha256": digest(b"synthetic remove stdout"),
            "stderr_sha256": digest(b"synthetic remove stderr"),
            "absence_confirmed": False,
        },
        "absence": {
            "schema": "cicada.client-v164-recovery-loop-android-command.v1",
            "role": "absence",
            "argv": ["docker", "inspect", container, "--format", "{{.Id}}"],
            "exit_code": 1,
            "stdout_sha256": digest(b"synthetic absence stdout"),
            "stderr_sha256": digest(b"synthetic absence stderr"),
            "absence_confirmed": True,
        },
    }
    command_refs = {
        role: write_private_json(evidence_root / f"cleanup-command-{role}.json", value)
        for role, value in command_values.items()
    }
    cleanup = {
        "schema": "cicada.client-v164-recovery-loop-android-close.v1",
        "ownership_sha256": ownership_ref["sha256"],
        "container_id_sha256": loop.sha(ownership["container_id"].encode()),
        "removed": True,
        "absence_exit_code": 1,
        "absence_confirmed": True,
        "process_groups_closed": True,
        "command_receipts": [command_refs["remove"], command_refs["absence"]],
    }
    cleanup_ref = write_private_json(evidence_root / "cleanup.json", cleanup)
    plan = {
        "android_evidence": str(android_evidence),
        "evidence_root": str(evidence_root),
        "core_fixture_root": str(core_fixture_root),
    }
    return plan, ownership_ref, cleanup, cleanup_ref, command_values, command_refs, core_fixture


def bounded_loop_harness(root: Path, failure: type[Exception], *, case_runner=None):
    plan, ownership_ref, _cleanup, cleanup_ref, _command_values, _command_refs, core_fixture = cleanup_fixture(root)
    pairs = ((operation, mode) for operation in loop.inputs.OPERATIONS for mode in loop.inputs.MODES)
    cases = []
    for index, (operation, mode) in enumerate(pairs):
        fixture_root = Path(plan["core_fixture_root"]) / "cases" / str(index)
        fixture_root.mkdir(mode=0o700, parents=True)
        cases.append({
            "case_id": f"loop_case_{index}", "run_id": f"{loop.joint.RUN_ID}-{index}",
            "core_case_index": index, "operation": operation, "mode": mode,
            "side": "source", "fixture_root": str(fixture_root),
        })
    plan["cases"] = cases
    outer = budget.Deadline.after(30)

    class Parent:
        def __init__(self):
            self.events: list[tuple[str, str | None, budget.Deadline]] = []
            self.case_controls: list[dict[str, object]] = []

        def request(self, event, case_id, payload, deadline):
            self.events.append((event, case_id, deadline))
            if event == "BOOT_READY":
                return {"ownership": ownership_ref, "core_fixture_root": plan["core_fixture_root"]}
            if event == "CASE_READY":
                self.case_controls.append(payload["core_control"])
                raise failure("synthetic prerequisite result")
            if event == "CLOSE_ANDROID":
                return {"receipt": cleanup_ref}
            raise AssertionError(f"unexpected synthetic parent event: {event}")

    class Driver:
        receipts: list[dict[str, object]] = []

    parent = Parent()
    runner = loop.RecoveryLoop(plan, parent, Driver(), outer,
        budget.Deadline.after(20, parent=outer))
    if case_runner is None:
        result = runner.run()
    else:
        with mock.patch.object(loop.RecoveryLoop, "one_case", new=case_runner):
            result = runner.run()
    return result, parent, outer, core_fixture


class CleanupEvidenceTests(unittest.TestCase):
    def test_accepts_remove_and_absence_receipts_for_the_owned_container(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-cleanup-valid-") as temp:
            plan, ownership_ref, cleanup, _cleanup_ref, _commands, _refs, core_fixture = cleanup_fixture(Path(temp))
            self.addCleanup(core_fixture.cleanup)
            owner = loop.FileRef.parse(ownership_ref)
            self.assertIsNone(loop.validate_cleanup(cleanup, plan, owner))

    def test_rejects_bogus_command_foreign_container_duplicate_refs_and_wrong_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-cleanup-invalid-") as temp:
            plan, ownership_ref, cleanup, _cleanup_ref, commands, refs, core_fixture = cleanup_fixture(Path(temp))
            self.addCleanup(core_fixture.cleanup)
            owner = loop.FileRef.parse(ownership_ref)
            evidence_root = Path(plan["evidence_root"])
            remove = commands["remove"]

            bogus = dict(remove, argv=["docker", "run", remove["argv"][-1]])
            bogus_ref = write_private_json(evidence_root / "bogus-command.json", bogus)
            foreign = dict(remove, argv=["docker", "rm", "--force", "2" * 64])
            foreign_ref = write_private_json(evidence_root / "foreign-container.json", foreign)
            wrong_exit = dict(remove, exit_code=1)
            wrong_exit_ref = write_private_json(evidence_root / "wrong-exit.json", wrong_exit)
            same_bytes_ref = write_private_json(evidence_root / "duplicate-hash.json", remove)

            variants = (
                ("bogus argv", [bogus_ref, refs["absence"]]),
                ("foreign container", [foreign_ref, refs["absence"]]),
                ("wrong exit", [wrong_exit_ref, refs["absence"]]),
                ("repeated path and hash", [refs["remove"], refs["remove"], refs["absence"]]),
                ("repeated hash at another path", [refs["remove"], same_bytes_ref, refs["absence"]]),
            )
            for label, receipts in variants:
                candidate = dict(cleanup, command_receipts=receipts)
                with self.subTest(label=label), self.assertRaises(loop.LoopError):
                    loop.validate_cleanup(candidate, plan, owner)

            ownership_value, _ = loop.inputs.read_private_json(owner.path, owner.sha256)
            non_auto_remove = dict(ownership_value, auto_remove=False)
            non_auto_remove_ref = loop.FileRef.parse(write_private_json(
                Path(plan["android_evidence"]) / "ownership-no-auto-remove.json", non_auto_remove))
            cleanup_for_non_auto_remove = dict(cleanup, ownership_sha256=non_auto_remove_ref.sha256)
            with self.assertRaises(loop.LoopError):
                loop.validate_cleanup(cleanup_for_non_auto_remove, plan, non_auto_remove_ref)


class LoopFailureTests(unittest.TestCase):
    def test_supervisor_runs_all_eight_cases_in_order_then_cleans_up(self) -> None:
        observed: list[tuple[int, str, budget.Deadline]] = []

        def fake_case(_self, case, record, deadline):
            observed.append((case["core_case_index"], case["run_id"], deadline))
            record.update(result="PASS", phase="RECONCILED")

        with tempfile.TemporaryDirectory(prefix="v164-loop-success-") as temp:
            result, parent, outer, core_fixture = bounded_loop_harness(
                Path(temp), loop.LoopError, case_runner=fake_case)
            self.addCleanup(core_fixture.cleanup)

        self.assertEqual([index for index, _run_id, _deadline in observed], list(range(8)))
        self.assertEqual([run_id for _index, run_id, _deadline in observed],
            [f"{loop.joint.RUN_ID}-{index}" for index in range(8)])
        self.assertTrue(all(deadline._expires_at <= outer._expires_at
            for _index, _run_id, deadline in observed))
        self.assertEqual([item["result"] for item in result["cases"]], ["PASS"] * 8)
        self.assertEqual(result["failure_class"], None)
        self.assertEqual(result["cleanup"]["result"], "PASS")
        self.assertEqual([event for event, _case, _deadline in parent.events],
            ["BOOT_READY", "CLOSE_ANDROID"])

    def test_failure_stops_later_cases_and_attempts_cleanup_with_outer_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-loop-failure-") as temp:
            result, parent, outer, core_fixture = bounded_loop_harness(Path(temp), loop.LoopError)
            self.addCleanup(core_fixture.cleanup)
        self.assertEqual([item["result"] for item in result["cases"]],
            ["UNKNOWN", *(["NOT_RUN"] * 7)])
        self.assertEqual(result["failure_class"], "LoopError")
        self.assertEqual(result["cleanup"]["result"], "PASS")
        self.assertEqual([item[0] for item in parent.events], ["BOOT_READY", "CASE_READY", "CLOSE_ANDROID"])
        self.assertEqual(parent.events[1][1], "loop_case_0")
        self.assertEqual(parent.case_controls, [{"action": "prepare", "case": 0}])
        event, case_id, cleanup_deadline = parent.events[-1]
        self.assertEqual((event, case_id), ("CLOSE_ANDROID", None))
        self.assertLessEqual(cleanup_deadline._expires_at, outer._expires_at)
        self.assertLessEqual(cleanup_deadline.remaining(), 240)

    def test_parent_blocked_is_not_misreported_as_unknown_and_still_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-loop-blocked-") as temp:
            result, parent, _outer, core_fixture = bounded_loop_harness(Path(temp), loop.ParentBlocked)
            self.addCleanup(core_fixture.cleanup)
        self.assertEqual([item["result"] for item in result["cases"]],
            ["BLOCKED", *(["NOT_RUN"] * 7)])
        self.assertEqual(result["failure_class"], "ParentBlocked")
        self.assertEqual(result["cleanup"]["result"], "PASS")
        self.assertEqual([item[0] for item in parent.events].count("CLOSE_ANDROID"), 1)


@unittest.skipUnless(sys.platform.startswith("linux") and Path("/proc").is_dir(),
    "owned process-group evidence is Linux-specific")
class OwnedProcessRunnerTests(unittest.TestCase):
    def assert_private_journal(self, receipt) -> None:
        self.assertIsNotNone(receipt.ownership_journal_path)
        journal = Path(receipt.ownership_journal_path)
        self.assertTrue(journal.is_file())
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        entries = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([entry["event"] for entry in entries], ["start", "finish"])
        identity_fields = {"event", "pid", "pgid", "leader_start_ticks", "command_sha256"}
        self.assertEqual(set(entries[0]), identity_fields)
        self.assertEqual(set(entries[1]), identity_fields | {
            "process_group_closed", "process_reaped", "result", "exit_code", "term_sent", "kill_sent"})
        self.assertEqual(entries[0]["pid"], receipt.started_pid)
        self.assertEqual(entries[0]["pgid"], receipt.started_pgid)
        self.assertEqual(entries[0]["command_sha256"], receipt.command_sha256)
        self.assertEqual(entries[1]["pid"], receipt.started_pid)
        self.assertEqual(entries[1]["pgid"], receipt.started_pgid)
        self.assertEqual(entries[1]["result"], receipt.status)
        self.assertEqual(entries[1]["exit_code"], receipt.exit_code)
        self.assertEqual(entries[1]["process_group_closed"], receipt.process_group_closed)
        self.assertEqual(entries[1]["process_reaped"], receipt.process_reaped)
        self.assertNotIn("argv", entries[0])
        self.assertNotIn("stdin", entries[0])
        redacted = receipt.as_dict()
        for private_field in ("stdout_path", "stderr_path", "ownership_journal_path"):
            self.assertNotIn(private_field, redacted)
        self.assertEqual(receipt.as_dict(include_private_paths=True)["ownership_journal_path"],
            receipt.ownership_journal_path)

    def test_safe_argv_records_closed_owned_group_and_reaped_leader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-owned-runner-") as temp:
            runner = budget.OwnedProcessRunner()
            receipt = runner.run(
                [sys.executable, "-c", "print('offline-runner-ok')"],
                budget.Deadline.after(5), temp, "safe-success",
                cleanup_deadline=budget.Deadline.after(2),
            )
            self.assert_private_journal(receipt)
        self.assertEqual(receipt.status, "SUCCESS")
        self.assertEqual(receipt.exit_code, 0)
        self.assertTrue(receipt.started)
        self.assertTrue(receipt.group_ownership_verified)
        self.assertTrue(receipt.process_group_closed)
        self.assertTrue(receipt.process_reaped)

    def test_deadline_stops_and_reaps_a_safe_synthetic_python_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v164-owned-timeout-") as temp:
            runner = budget.OwnedProcessRunner()
            receipt = runner.run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                budget.Deadline.after(0.15), temp, "safe-timeout",
                cleanup_deadline=budget.Deadline.after(3),
            )
            self.assert_private_journal(receipt)
        self.assertEqual(receipt.status, "UNKNOWN")
        self.assertEqual(receipt.exit_code, 124)
        self.assertTrue(receipt.timed_out)
        self.assertTrue(receipt.process_group_closed)
        self.assertTrue(receipt.process_reaped)


if __name__ == "__main__":
    unittest.main()
