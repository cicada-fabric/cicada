"""Focused, effect-free tests for the one-click completion supervisor."""

from __future__ import annotations

import contextlib
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
        current.write_text(json.dumps({"status": "PASS", "cleanup_owned_resources": True}))
        stale.write_text(json.dumps({"status": "FAIL", "cleanup_owned_resources": False}))
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text("PASS: current lane\n")
        state, _ = runner.classification(
            self._complete_run_record(), self.log, "synthetic-lane", [current]
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


if __name__ == "__main__":
    unittest.main()
