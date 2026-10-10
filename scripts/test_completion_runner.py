"""Focused, effect-free tests for the one-click completion supervisor."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from scripts import completion_runner as runner
from scripts import owned_fixture_cleanup


class CompletionRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="completion-runner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "logs" / "child.log"
        runner._STOP = False

    def tearDown(self) -> None:
        runner._STOP = False

    @staticmethod
    def child_env() -> dict[str, str]:
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1"}

    def run_child(self, argv: list[str], *, timeout: float, **kwargs) -> dict:
        processes = []
        original_popen = subprocess.Popen

        def capture(*args, **popen_kwargs):
            process = original_popen(*args, **popen_kwargs)
            processes.append(process)
            return process

        try:
            with mock.patch.object(runner.subprocess, "Popen", side_effect=capture):
                return runner.run_process(argv, log_path=self.log, timeout=timeout,
                                          env=self.child_env(), **kwargs)
        finally:
            for process in processes:
                if process.stdout is not None:
                    process.stdout.close()

    @staticmethod
    def fast_group_stop(process, grace=runner.STOP_GRACE) -> bool:
        try:
            os.killpg(process.pid, runner.signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, runner.signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return False
        return not runner._process_group_alive(process.pid)

    def test_run_process_success_observes_exit_and_pipe_eof(self) -> None:
        result = self.run_child(
            [sys.executable, "-c", "print('child-ok')"],
            timeout=5,
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["process_exit_confirmed"])
        self.assertTrue(result["process_group_cleanup_confirmed"])
        self.assertTrue(result["pipe_eof_observed"])
        self.assertEqual(self.log.read_text(), "child-ok\n")

    def test_eof_while_child_runs_uses_bounded_polling(self) -> None:
        calls = 0
        original_select = runner.select.select

        def counted_select(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original_select(*args, **kwargs)

        with mock.patch.object(runner.select, "select", side_effect=counted_select):
            result = self.run_child(
                [sys.executable, "-c",
                 "import os,time; os.close(1); os.close(2); time.sleep(.15)"],
                timeout=5,
            )

        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["process_exit_confirmed"])
        self.assertTrue(result["pipe_eof_observed"])
        self.assertLess(calls, 20)

    def test_run_process_timeout_stops_exact_process_group(self) -> None:
        with mock.patch.object(runner, "process_group_stop", side_effect=self.fast_group_stop):
            result = self.run_child(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=0.2,
            )
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_exit_confirmed"])
        self.assertTrue(result["process_group_cleanup_confirmed"])

    def test_run_process_stop_flag_is_unknown_after_child_cleanup(self) -> None:
        runner._STOP = True
        with mock.patch.object(runner, "process_group_stop", side_effect=self.fast_group_stop):
            result = self.run_child(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=5,
            )
        self.assertTrue(result["interrupted"])
        self.assertTrue(result["process_exit_confirmed"])
        self.assertTrue(result["process_group_cleanup_confirmed"])
        state, _ = runner.classification(result, self.log, "synthetic-child")
        self.assertEqual(state, "UNKNOWN")

    def test_run_process_caps_log_and_does_not_pass_overflow(self) -> None:
        with mock.patch.object(runner, "MAX_LOG_BYTES", 64):
            with mock.patch.object(runner, "process_group_stop", side_effect=self.fast_group_stop):
                result = self.run_child(
                    [sys.executable, "-c",
                     "import os,time; os.write(1,b'x'*8192); time.sleep(30)"],
                    timeout=5,
                )
        self.assertTrue(result["log_bound_exceeded"])
        self.assertLessEqual(self.log.stat().st_size, 64)
        self.assertEqual(result["log_bytes_retained"], self.log.stat().st_size)

    def test_marker_status_handles_zero_exit_failure_and_pass(self) -> None:
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text("PASS: fixture complete\n")
        self.assertEqual(runner.marker_status(self.log, 0)[0], "PASS")
        self.log.write_text("FAIL: fixture assertion\n")
        self.assertEqual(runner.marker_status(self.log, 0)[0], "FAIL")

    def _complete_run_record(self) -> dict:
        return {"exit_code": 0, "timed_out": False, "interrupted": False,
                "process_exit_confirmed": True, "process_group_cleanup_confirmed": True,
                "log_bound_exceeded": False, "pipe_eof_observed": True}

    def test_structured_child_failure_overrides_zero_exit(self) -> None:
        receipt = self.root / "joined-v68" / "result.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_text(json.dumps({"status": "FAIL", "cleanup_owned_scratch": True}))
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text("")
        state, codes = runner.classification(
            self._complete_run_record(), self.log, "joined-v68", [receipt]
        )
        self.assertEqual(state, "FAIL")
        self.assertIn("CHILD_RECEIPT_FAILURE", codes)

    def test_classification_requires_observed_pipe_eof(self) -> None:
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text("PASS: fixture complete\n")
        run = self._complete_run_record() | {"pipe_eof_observed": False}
        state, codes = runner.classification(run, self.log, "synthetic-child")
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(codes, ["CHILD_OUTPUT_EOF_UNCONFIRMED"])

    def test_go_container_absence_requires_exact_id_and_not_daemon_error(self) -> None:
        cid = "a" * 64
        run_id = "synthetic-run"

        def absent(stderr: str) -> list[subprocess.CompletedProcess]:
            return [
                subprocess.CompletedProcess([], 1, stdout="", stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr=stderr),
            ]

        for error in (f"Error: No such object: {cid}", f"error: no such object: {cid}"):
            with self.subTest(stderr=error), mock.patch.object(
                runner.subprocess, "run", side_effect=absent(error)
            ):
                self.assertTrue(runner.remove_exact_go_container(cid, run_id))

        for error in (
            f"error: no such object: {'b' * 64}",
            "error during connect: daemon unavailable",
        ):
            with self.subTest(stderr=error), mock.patch.object(
                runner.subprocess, "run", side_effect=absent(error)
            ):
                self.assertFalse(runner.remove_exact_go_container(cid, run_id))

    def test_other_lane_receipt_does_not_override_exact_current_receipt(self) -> None:
        lane_root = self.root / "interop"
        current = lane_root / "current" / "result.json"
        stale = lane_root / "stale-other-lane" / "result.json"
        current.parent.mkdir(parents=True)
        stale.parent.mkdir(parents=True)
        current.write_text(json.dumps(self._actual_child_cleanup_receipt()[0]))
        stale.write_text(json.dumps({"status": "FAIL", "cleanup_owned_resources": False}))
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text("PASS: current lane\n")
        state, _ = runner.classification(
            self._complete_run_record(), self.log, "client-interop", [current],
            expected_run_id="synthetic-run-01", expected_lane="client",
            expected_roles={"hub", "test", "hub-image", "test-image"},
        )
        self.assertEqual(state, "PASS")

    def test_go_json_events_count_packages_tests_and_skips(self) -> None:
        go_test = self.root / "go" / "out" / "go-test.jsonl"
        go_test.parent.mkdir(parents=True)
        events = [
            {"Action": "pass", "Package": "example/a"},
            {"Action": "fail", "Package": "example/b"},
            {"Action": "pass", "Package": "example/a", "Test": "TestOne"},
            {"Action": "fail", "Package": "example/b", "Test": "TestTwo"},
            {"Action": "skip", "Package": "example/c", "Test": "TestOptional"},
            {"Action": "not-an-action", "Package": "example/c", "Test": "TestIgnored"},
        ]
        go_test.write_text("".join(json.dumps(event) + "\n" for event in events))
        counts = runner.parse_go_counts(self.root)
        self.assertEqual((counts["package_pass"], counts["package_fail"]), (1, 1))
        self.assertEqual((counts["test_pass"], counts["test_fail"], counts["test_skip"]), (1, 1, 1))
        self.assertEqual(counts["skipped_tests"], [{"package": "example/c", "test": "TestOptional"}])

    def _source_identity_with_untracked(self, name: str, *, file_sha=None) -> dict:
        source_root = self.root / "repo"
        source_root.mkdir(exist_ok=True)
        (source_root / name).write_bytes(b"synthetic source")
        data = source_root / ".cicada-data"
        data.mkdir(exist_ok=True)

        def fake_git(argv, **kwargs):
            command = argv[1]
            if command == "rev-parse":
                stdout = "synthetic-head\n"
            elif command == "ls-files":
                stdout = (name + "\n").encode()
            else:
                stdout = b""
            return subprocess.CompletedProcess(argv, 0, stdout=stdout)

        patches = [mock.patch.object(runner, "ROOT", source_root),
                   mock.patch.object(runner, "DATA", data),
                   mock.patch.object(runner.subprocess, "run", side_effect=fake_git)]
        if file_sha is not None:
            patches.append(mock.patch.object(runner, "file_sha", side_effect=file_sha))
        with contextlib.ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            return runner.source_identity()

    def test_source_identity_marks_oversized_untracked_source_incomplete(self) -> None:
        with mock.patch.object(runner, "MAX_SOURCE_FILE_BYTES", 8):
            identity = self._source_identity_with_untracked("large_fixture.py")
        self.assertFalse(identity["complete"])
        self.assertEqual(identity["incomplete_sources"][0]["path"], "large_fixture.py")

    def test_source_identity_marks_unreadable_untracked_source_incomplete(self) -> None:
        def denied(_path: Path) -> str:
            raise PermissionError("synthetic unreadable source")

        identity = self._source_identity_with_untracked("unreadable_fixture.py", file_sha=denied)
        self.assertFalse(identity["complete"])
        self.assertEqual(identity["incomplete_sources"][0]["reason"], "PermissionError")

    def test_incomplete_source_comparison_cannot_be_unchanged(self) -> None:
        before = {"complete": False, "incomplete_sources": [{"path": "x.py"}], "head": "same"}
        after = dict(before)
        comparison = runner.compare_source_identity(before, after)
        self.assertFalse(comparison["complete"])
        self.assertIsNone(comparison["unchanged"])
        self.assertEqual(comparison["status"], "UNKNOWN")
        self.assertEqual(runner.final_status([{"status": "PASS"}], comparison, False), "UNKNOWN")

    def test_background_initial_result_exists_before_worker_spawn(self) -> None:
        run_root = self.root / "runs"
        run_root.mkdir(mode=0o700)
        observed: dict[str, object] = {}

        def spawn(argv, **kwargs):
            run_dir = Path(argv[-1])
            initial = json.loads((run_dir / "result.json").read_text())
            self.assertEqual(initial["overall_status"], "RUNNING")
            observed["run_dir"] = run_dir
            observed["run_id"] = argv[-2]
            return types.SimpleNamespace(pid=43210)

        with mock.patch.object(runner, "private_run_root", return_value=run_root), \
             mock.patch.object(runner.subprocess, "Popen", side_effect=spawn), \
             mock.patch.object(runner, "process_start_token", return_value="synthetic-start-token", create=True), \
             contextlib.redirect_stdout(io.StringIO()):
            result = runner.main(["--background", "--max-seconds", "60"])
        self.assertEqual(result, 0)
        worker = json.loads((observed["run_dir"] / "worker.json").read_text())
        self.assertEqual(worker["pid"], 43210)
        self.assertEqual(worker["start_token"], "synthetic-start-token")

    def test_status_marks_running_result_unknown_when_worker_identity_changed(self) -> None:
        run_id = "20261010T123456Z-0123456789"
        run_root = self.root / "runs"
        run_dir = run_root / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "result.json").write_text(json.dumps({
            "run_id": run_id, "overall_status": "RUNNING", "lanes": []
        }))
        (run_dir / "worker.json").write_text(json.dumps({"pid": 43210, "start_token": "old-token"}))
        output = io.StringIO()
        with mock.patch.object(runner, "private_run_root", return_value=run_root), \
             mock.patch.object(runner, "process_start_token", return_value="new-token", create=True), \
             contextlib.redirect_stdout(output):
            runner.status_mode(run_id)
        status, _ = json.JSONDecoder().raw_decode(output.getvalue())
        self.assertEqual(status["overall_status"], "UNKNOWN")

    def test_go_metadata_stage_exposes_only_five_pinned_public_files(self) -> None:
        public_files = (
            "VERSION", "docs/client-hub-wire-v1.md", "docs/client-hub-v1.openapi.yaml",
            ".agents/plugins/cicada/plugin.json",
            ".agents/plugins/cicada/.codex-plugin/plugin.json",
        )
        source_root = self.root / "source"
        for index, relpath in enumerate(public_files):
            source = source_root / relpath
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(f"synthetic-public-{index}".encode())
            source.chmod(0o644)
        (source_root / "cicada-go").mkdir()
        (source_root / ".env").write_text("PRIVATE_SENTINEL_MUST_NOT_BE_STAGED")
        (source_root / "unrelated.md").write_text("not an allowlisted input")
        go_root = self.root / "go"

        with mock.patch.object(runner, "ROOT", source_root):
            identity = runner.stage_go_metadata(go_root)

        self.assertIs(identity["complete"], True)
        metadata_root = Path(identity["metadata_root"])
        staged = sorted(path.relative_to(metadata_root).as_posix()
                        for path in metadata_root.rglob("*") if path.is_file())
        self.assertEqual(staged, sorted(public_files))
        rows = {row["path"]: row for row in identity["rows"]}
        self.assertEqual(set(rows), set(public_files))
        for relpath in public_files:
            data = (source_root / relpath).read_bytes()
            self.assertEqual((metadata_root / relpath).read_bytes(), data)
            self.assertEqual(rows[relpath]["sha256"], runner.sha256(data))
            self.assertEqual(rows[relpath]["bytes"], len(data))
        self.assertTrue((metadata_root / "cicada-go").is_dir())
        self.assertEqual(list((metadata_root / "cicada-go").iterdir()), [])
        self.assertNotIn(b"PRIVATE_SENTINEL_MUST_NOT_BE_STAGED",
                         b"".join((metadata_root / path).read_bytes() for path in public_files))

    def _go_envelope(self) -> tuple[dict, dict]:
        go_root = self.root / "go"
        metadata_root = go_root / "public-root"
        expected_mounts = [
            {"source": str(metadata_root), "destination": "/repo", "type": "bind", "rw": False},
            {"source": str(runner.ROOT / "cicada-go"), "destination": "/repo/cicada-go", "type": "bind", "rw": False},
            {"source": str(runner.ROOT / ".cicada-data/m1-gomodcache"), "destination": "/gomod", "type": "bind", "rw": False},
            {"source": str(go_root / "cache"), "destination": "/gocache", "type": "bind", "rw": True},
            {"source": str(go_root / "tmp"), "destination": "/t", "type": "bind", "rw": True},
            {"source": str(go_root / "out"), "destination": "/out", "type": "bind", "rw": True},
        ]
        tmpfs_options = "uid=0,gid=0,mode=1777,rw,nosuid,nodev,size=128m"
        env = {"TMPDIR": "/t", "GOTMPDIR": "/t", "GOCACHE": "/gocache",
               "GOMODCACHE": "/gomod", "GOTOOLCHAIN": "local", "GOPROXY": "off",
               "GOSUMDB": "off"}
        fields = {
            "image_ref": runner.GO_IMAGE,
            "user": f"{os.getuid()}:{os.getgid()}",
            "network": "none", "readonly_root": True, "nano_cpus": 2_000_000_000,
            "memory_bytes": 3 * 1024 * 1024 * 1024, "pids_limit": 256,
            "cap_add": [], "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"],
            "mounts": expected_mounts,
            "tmpfs": {"/tmp": ["uid=0", "gid=0", "mode=1777", "rw", "nosuid", "nodev", "size=128m"]},
            "env": env, "workdir": "/repo/cicada-go", "tmp_identity": "0:0:1777",
        }
        projection = copy.deepcopy(fields)
        projection["tmpfs"] = {"/tmp": tmpfs_options}
        return projection, fields

    def test_go_envelope_keeps_exact_mounts_short_temp_and_root_owned_tmp(self) -> None:
        projection, expected = self._go_envelope()
        valid, reason = runner.verify_go_envelope(projection, expected)
        self.assertTrue(valid, reason)
        self.assertEqual(projection["env"]["TMPDIR"], "/t")
        self.assertEqual(projection["env"]["GOTMPDIR"], "/t")
        self.assertEqual(projection["workdir"], "/repo/cicada-go")
        self.assertEqual(projection["tmp_identity"], "0:0:1777")
        self.assertNotRegex(projection["tmpfs"]["/tmp"], r"(?:^|,)(?:uid|gid)=(?!0(?:,|$))")
        self.assertEqual(len(projection["mounts"]), 6)
        self.assertEqual({row["destination"] for row in projection["mounts"]},
                         {"/repo", "/repo/cicada-go", "/gomod", "/gocache", "/t", "/out"})

    def test_go_envelope_rejects_extra_mount_wrong_source_or_tmp_policy(self) -> None:
        _projection, expected = self._go_envelope()
        variants = []
        extra = copy.deepcopy(expected)
        extra["mounts"].append({"source": "/host", "destination": "/leak", "type": "bind", "rw": False})
        variants.append(extra)
        wrong_source = copy.deepcopy(expected)
        wrong_source["mounts"][0]["source"] = str(self.root / "whole-repository")
        variants.append(wrong_source)
        wrong_temp = copy.deepcopy(expected)
        wrong_temp["env"]["TMPDIR"] = "/tmp"
        variants.append(wrong_temp)
        chowned_tmp = copy.deepcopy(expected)
        chowned_tmp["tmpfs"]["/tmp"] = "uid=1000,gid=1000,mode=1777,rw,nosuid,nodev,size=128m"
        chowned_tmp["tmp_identity"] = "1000:1000:1777"
        variants.append(chowned_tmp)
        for projection in variants:
            with self.subTest(projection=projection):
                valid, _reason = runner.verify_go_envelope(projection, expected)
                self.assertFalse(valid)

    def test_python_modules_run_in_separate_child_processes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="python-module-isolation-") as temp:
            module_root = Path(temp)
            (module_root / "poison_module.py").write_text(
                "import builtins, unittest\n"
                "builtins._cicada_completion_poison = True\n"
                "class T(unittest.TestCase):\n"
                " def test_module_loaded(self): self.assertTrue(builtins._cicada_completion_poison)\n")
            (module_root / "clean_module.py").write_text(
                "import builtins, unittest\n"
                "class T(unittest.TestCase):\n"
                " def test_fresh_interpreter(self): self.assertFalse(hasattr(builtins, '_cicada_completion_poison'))\n")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "PYTHONPATH": str(module_root), "PYTHONDONTWRITEBYTECODE": "1"}
            records = runner.run_python_modules(["poison_module", "clean_module"],
                                                self.root / "python-modules", 30, env)
        self.assertEqual(records["status"], "PASS")
        self.assertEqual(records["modules_requested"], 2)
        self.assertEqual(records["modules_completed"], 2)
        self.assertEqual(records["tests_run"], 2)
        self.assertEqual(records["failures"], 0)
        self.assertEqual(records["errors"], 0)
        self.assertEqual(records["skips"], 0)
        modules = records["modules"]
        self.assertEqual([record["module"] for record in modules],
                         ["poison_module", "clean_module"])
        self.assertTrue(all(record["status"] == "PASS" and record["pipe_eof_observed"]
                            for record in modules))

    def _actual_child_cleanup_receipt(
        self, *, wrong_container_id: bool = False, wrong_container_label: bool = False,
        daemon_after_remove: bool = False, remove_fails: bool = False,
    ) -> tuple[dict, dict]:
        """Build real cleanup-helper evidence with an in-memory Docker double."""
        run_id, lane = "synthetic-run-01", "client"
        run_label, role_label = "org.cicada.test.run", "org.cicada.test.role"
        hub_image, test_image = "sha256:" + "c" * 64, "sha256:" + "d" * 64
        fixture_suffix = self.root.name
        hub_name, test_name = "fixture-hub-" + fixture_suffix, "fixture-test-" + fixture_suffix
        hub_tag, test_tag = "fixture-hub:" + fixture_suffix, "fixture-test:" + fixture_suffix
        container_specs = [
            ("hub", hub_name, hub_image, "a" * 64),
            ("test", test_name, test_image, "b" * 64),
        ]
        image_specs = [
            ("hub-image", hub_tag),
            ("test-image", test_tag),
        ]

        class FakeDocker:
            def __init__(self) -> None:
                self.containers: dict[str, dict] = {}
                self.images: dict[str, str] = {}
                self.removed_any = False

            def __call__(self, argv: list[str]) -> subprocess.CompletedProcess:
                kind = argv[1]
                if argv[1:3] in (["container", "inspect"], ["image", "inspect"]):
                    resource_kind, selector = argv[1], argv[3]
                    if daemon_after_remove and self.removed_any:
                        return subprocess.CompletedProcess(argv, 125, "", "daemon unavailable")
                    if resource_kind == "container":
                        resource = self.containers.get(selector)
                        if resource is None:
                            resource = next((item for item in self.containers.values()
                                             if selector == item["name"]), None)
                        if resource is not None:
                            fields = (resource["id"], "/" + resource["name"], resource["image"],
                                      resource["run"], resource["role"])
                            return subprocess.CompletedProcess(argv, 0, "|".join(fields) + "\n", "")
                    else:
                        image_id = self.images.get(selector)
                        if image_id is not None:
                            return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
                    return subprocess.CompletedProcess(
                        argv, 1, "", f"Error response from daemon: No such {resource_kind}: {selector}\n")
                if argv[1:3] == ["rm", "-f"]:
                    if remove_fails:
                        return subprocess.CompletedProcess(argv, 1, "", "synthetic remove failure")
                    self.containers.pop(argv[3], None)
                    self.removed_any = True
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[1:3] == ["image", "rm"]:
                    self.images.pop(argv[3], None)
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError("unexpected fake Docker command")

        docker = FakeDocker()
        serial = getattr(self, "_cleanup_fixture_counter", 0) + 1
        self._cleanup_fixture_counter = serial
        scratch = self.root / f"independent-random-scratch-{serial}"
        scratch.mkdir(mode=0o700)
        plan = owned_fixture_cleanup.prepare(
            scratch, run_id, lane,
            [(role, name, image_id) for role, name, image_id, _cid in container_specs],
            image_specs, call=docker)
        self.assertTrue(plan["creation_authorized"])
        self.assertTrue(all(row["pre_creation"] == "EXACT_ABSENT" for row in plan["resources"]))
        for role, name, image_id, cid in container_specs:
            cid_path = next(Path(row["cidfile"]) for row in plan["resources"] if row["role"] == role)
            cid_path.write_text(cid, encoding="ascii")
            cid_path.chmod(0o600)
            docker.containers[cid] = {
                "id": ("f" * 64 if wrong_container_id and role == "hub" else cid),
                "name": name, "image": image_id, "run": run_id,
                "role": ("wrong-role" if wrong_container_label and role == "hub" else role),
            }
        docker.images.update({hub_tag: hub_image, test_tag: test_image})
        cleanup = owned_fixture_cleanup.cleanup(
            plan, build={"image": {"id": hub_image}, "test_image": {"id": test_image}}, call=docker)
        receipt = {
            "run_id": run_id, "lane": lane,
            "status": "PASS" if cleanup["status"] == "CONFIRMED" else cleanup["status"],
            "cleanup_owned_resources": cleanup["status"] == "CONFIRMED",
            "fixture_cleanup_status": cleanup["status"],
            "fixture_cleanup": cleanup,
        }
        return receipt, cleanup

    def test_child_cleanup_confirms_only_exact_owned_absence_receipts(self) -> None:
        receipt, helper_result = self._actual_child_cleanup_receipt()
        self.assertEqual(helper_result["status"], "CONFIRMED")
        self.assertNotIn(receipt["run_id"], helper_result["scratch"]["path"])
        self.assertTrue(all(receipt["run_id"] not in row["name_or_ref"]
                            for row in helper_result["resources"]))
        scratch = helper_result["scratch"]
        self.assertEqual(scratch["creation_proof"], "MKDTEMP_INODE")
        self.assertEqual(scratch["ownership"], "VERIFIED")
        self.assertGreater(scratch["device"], 0)
        self.assertGreater(scratch["inode"], 0)
        self.assertEqual(scratch["uid"], os.getuid())
        self.assertNotIn("pre_creation", scratch)
        for row in helper_result["resources"]:
            self.assertEqual(row["pre_creation"], "EXACT_ABSENT")
            self.assertEqual(row["post_cleanup"], "EXACT_ABSENT")
            self.assertNotIn(receipt["run_id"], row["name_or_ref"])
            if row["kind"] == "container":
                self.assertEqual(row["creation_proof"], "CIDFILE")
                self.assertEqual(row["ownership"], "VERIFIED")
                self.assertEqual(row["labels_observed"], row["labels_intended"])
            else:
                self.assertEqual(row["creation_proof"], "FRESH_TAG")
                self.assertEqual(row["ownership"], "VERIFIED")
                self.assertEqual(row["id"], row["expected_image_id"])
        result = runner.reduce_child_cleanup(
            receipt, expected_run_id="synthetic-run-01", expected_lane="client",
            expected_roles={"hub", "test", "hub-image", "test-image"})
        self.assertEqual(result["status"], "CONFIRMED")

    def test_child_cleanup_generic_claims_missing_or_ambiguous_proof_do_not_confirm(self) -> None:
        expected = {"hub", "test", "hub-image", "test-image"}
        generic = {"status": "PASS", "cleanup_owned_resources": True}
        self.assertEqual(runner.reduce_child_cleanup(
            generic, "synthetic-run-01", "client", expected)["status"], "UNKNOWN")
        cases = []
        missing_role, _ = self._actual_child_cleanup_receipt()
        missing_role["fixture_cleanup"]["resources"].pop()
        cases.append((missing_role, "UNKNOWN"))
        wrong_run, _ = self._actual_child_cleanup_receipt()
        wrong_run["run_id"] = "other-run"
        cases.append((wrong_run, "UNKNOWN"))
        wrong_cid, wrong_cid_cleanup = self._actual_child_cleanup_receipt(wrong_container_id=True)
        self.assertEqual(wrong_cid_cleanup["resources"][0]["ownership"], "MISMATCH")
        cases.append((wrong_cid, "UNKNOWN"))
        wrong_label, wrong_label_cleanup = self._actual_child_cleanup_receipt(wrong_container_label=True)
        self.assertEqual(wrong_label_cleanup["resources"][0]["ownership"], "MISMATCH")
        cases.append((wrong_label, "UNKNOWN"))
        daemon_unknown, daemon_cleanup = self._actual_child_cleanup_receipt(daemon_after_remove=True)
        self.assertNotEqual(daemon_cleanup["status"], "CONFIRMED")
        cases.append((daemon_unknown, "UNKNOWN"))
        still_present, still_present_cleanup = self._actual_child_cleanup_receipt(remove_fails=True)
        self.assertEqual(still_present_cleanup["status"], "FAILED")
        cases.append((still_present, "FAILED"))
        for receipt, expected_status in cases:
            with self.subTest(expected_status=expected_status):
                result = runner.reduce_child_cleanup(
                    receipt, "synthetic-run-01", "client", expected)
                self.assertEqual(result["status"], expected_status)

    @staticmethod
    def _exact_missing_docker_probe(calls: list[list[str]], *, daemon_error: bool = False):
        def probe(argv, **_kwargs):
            calls.append(list(argv))
            reference = argv[3] if argv[1] == "network" else argv[2]
            if daemon_error:
                return subprocess.CompletedProcess(argv, 125, "", "error during connect: daemon unavailable\n")
            if argv[1] == "network":
                error = f"error: no such network: {reference}\n"
            else:
                error = f"error: no such object: {reference}\n"
            return subprocess.CompletedProcess(argv, 1, "[]\n", error)
        return probe

    def _v68_known_cleanup_receipt(self) -> tuple[dict, Path]:
        run_id = "cicada-v68-abc12345"
        scratch = self.root / "cicada-v68-1234abcd"
        receipt_path = self.root / "v68" / "result.json"
        return ({
            "schema": "cicada.v68-joined-result.v1",
            "fixture_run_id": run_id,
            "owned_fixture": {
                "run_id": run_id,
                "containers": [run_id + suffix for suffix in ("-hub", "-node-a", "-node-b")],
                "networks": [run_id + suffix for suffix in ("-node-a-net", "-node-b-net")],
                "images": [run_id + suffix for suffix in (":hub", ":test")],
                "scratch_path": str(scratch),
            },
            "cleanup_owned_containers_and_networks": True,
            "cleanup_owned_scratch": True,
        }, receipt_path)

    def _browser_known_cleanup_receipt(self) -> tuple[dict, Path]:
        run_id = "cicada-webpanel-abc123"
        base = self.root / "browser"
        receipt_path = base / "result.json"
        return ({
            "schema_version": "cicada.hub-web-panel-browser.v1",
            "fixture_run_id": run_id,
            "owned_fixture": {
                "run_id": run_id,
                "containers": [run_id + suffix for suffix in ("-hub", "-chromium", "-node", "-node-2")],
                "networks": [run_id + "-net"],
                "images": [],
                "scratch_path": str(base / "fixture"),
            },
            "fixture_cleanup": {
                "status": "PASS",
                "hub_container_removed": True,
                "chromium_container_removed": True,
                "docker_network_removed": True,
                "fixture_directory_removed": True,
                "node_container_removed": True,
                "second_node_container_removed": True,
            },
        }, receipt_path)

    @staticmethod
    def _stress_known_cleanup_receipt(run_id: str = "stress-run-01") -> dict:
        cids = [f"{number:064x}" for number in range(1, 6)]
        return {
            "schema": "cicada.v01.group-fabric-stress-run.v1",
            "security_envelope": {"owner_labels": {
                "cicada.acceptance.task": "cicada.v01.group-fabric-stress",
                "cicada.acceptance.run": run_id,
            }},
            "builder": {"cid": cids[0], "cleanup_confirmed": True},
            "workloads": [{"cid": cid, "cleanup_confirmed": True} for cid in cids[1:]],
            "emergency_cleanup": [],
        }

    def test_known_v68_cleanup_requires_exact_receipt_and_readonly_absence(self) -> None:
        receipt, _path = self._v68_known_cleanup_receipt()
        calls: list[list[str]] = []
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.root)}), \
             mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls)):
            result = runner.reduce_known_cleanup(receipt, "joined-v68", self.root / "v68/result.json", None)
        self.assertEqual(result["status"], "CONFIRMED")
        self.assertEqual(len(calls), 7)
        self.assertTrue(all(argv[1] in {"inspect", "network"} and "rm" not in argv for argv in calls))

        wrong_schema = copy.deepcopy(receipt)
        wrong_schema["schema"] = "unknown"
        renamed = copy.deepcopy(receipt)
        renamed["owned_fixture"]["containers"][0] += "-other"
        with mock.patch.object(runner.subprocess, "run") as docker:
            for candidate in (wrong_schema, renamed):
                rejected = runner.reduce_known_cleanup(candidate, "joined-v68", self.root / "v68/result.json", None)
                self.assertEqual(rejected["status"], "UNKNOWN")
            docker.assert_not_called()

        scratch = Path(receipt["owned_fixture"]["scratch_path"])
        scratch.mkdir()
        calls.clear()
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.root)}), \
             mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls)):
            remains = runner.reduce_known_cleanup(receipt, "joined-v68", self.root / "v68/result.json", None)
        self.assertEqual(remains["status"], "FAILED")

        calls.clear()
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.root)}), \
             mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls, daemon_error=True)):
            uncertain = runner.reduce_known_cleanup(receipt, "joined-v68", self.root / "v68/result.json", None)
        self.assertEqual(uncertain["status"], "UNKNOWN")

    def test_known_browser_cleanup_requires_schema_and_exact_readonly_absence(self) -> None:
        receipt, receipt_path = self._browser_known_cleanup_receipt()
        calls: list[list[str]] = []
        with mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls)):
            result = runner.reduce_known_cleanup(receipt, "hub-web-panel-browser", receipt_path, None)
        self.assertEqual(result["status"], "CONFIRMED")
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[-1][1], "network")
        self.assertTrue(all("rm" not in argv for argv in calls))

        wrong_schema = copy.deepcopy(receipt)
        wrong_schema["schema_version"] = "wrong"
        wrong_name = copy.deepcopy(receipt)
        wrong_name["owned_fixture"]["networks"][0] += "-foreign"
        with mock.patch.object(runner.subprocess, "run") as docker:
            for candidate in (wrong_schema, wrong_name):
                rejected = runner.reduce_known_cleanup(
                    candidate, "hub-web-panel-browser", receipt_path, None)
                self.assertEqual(rejected["status"], "UNKNOWN")
            docker.assert_not_called()

        scratch = Path(receipt["owned_fixture"]["scratch_path"])
        scratch.mkdir(parents=True)
        calls.clear()
        with mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls)):
            remains = runner.reduce_known_cleanup(receipt, "hub-web-panel-browser", receipt_path, None)
        self.assertEqual(remains["status"], "FAILED")

        calls.clear()
        with mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls, daemon_error=True)):
            uncertain = runner.reduce_known_cleanup(receipt, "hub-web-panel-browser", receipt_path, None)
        self.assertEqual(uncertain["status"], "UNKNOWN")

    def test_known_stress_cleanup_requires_owner_scope_and_readonly_absence(self) -> None:
        run_id = "stress-run-01"
        receipt = self._stress_known_cleanup_receipt(run_id)
        receipt_path = self.root / run_id / "RUN.NONAUTH.json"
        calls: list[list[str]] = []
        with mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls)):
            result = runner.reduce_known_cleanup(receipt, "group-fabric-stress", receipt_path, run_id)
        self.assertEqual(result["status"], "CONFIRMED")
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(argv[1] == "inspect" and "rm" not in argv for argv in calls))

        wrong_run = copy.deepcopy(receipt)
        wrong_run["security_envelope"]["owner_labels"]["cicada.acceptance.run"] = "other-run"
        failed_claim = copy.deepcopy(receipt)
        failed_claim["workloads"][0]["cleanup_confirmed"] = False
        wrong_schema = copy.deepcopy(receipt)
        wrong_schema["schema"] = "wrong"
        with mock.patch.object(runner.subprocess, "run") as docker:
            self.assertEqual(runner.reduce_known_cleanup(
                wrong_run, "group-fabric-stress", receipt_path, run_id)["status"], "UNKNOWN")
            self.assertEqual(runner.reduce_known_cleanup(
                wrong_schema, "group-fabric-stress", receipt_path, run_id)["status"], "UNKNOWN")
            self.assertEqual(runner.reduce_known_cleanup(
                failed_claim, "group-fabric-stress", receipt_path, run_id)["status"], "FAILED")
            docker.assert_not_called()

        calls.clear()
        with mock.patch.object(runner.subprocess, "run", side_effect=self._exact_missing_docker_probe(calls, daemon_error=True)):
            uncertain = runner.reduce_known_cleanup(
                receipt, "group-fabric-stress", receipt_path, run_id)
        self.assertEqual(uncertain["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
