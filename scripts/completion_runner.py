#!/usr/bin/env python3
"""Bounded supervisor for the repository's existing Architecture v2 gates.

The runner owns summaries and process-group timeouts. Child test drivers retain
ownership of their disposable containers, networks, databases, and cleanup.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / ".cicada-data"
DEFAULT_EVIDENCE = DATA / "architecture-v2-completion"
GO_IMAGE = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
GO_TASK_LABEL = "architecture-v2-completion-go"
MAX_GLOBAL_SECONDS = 2 * 60 * 60
DEFAULT_GLOBAL_SECONDS = MAX_GLOBAL_SECONDS
GLOBAL_CLEANUP_RESERVE = 60
MAX_LOG_BYTES = 16 * 1024 * 1024
STOP_GRACE = 8
_STOP = False

SAFE_ENV = {
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ",
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    "CICADA_HUB_IMAGE", "CICADA_BUILD_METADATA", "CICADA_EXPECT_SOURCE_FINGERPRINT",
    "CICADA_CHROMIUM_IMAGE", "CICADA_BROWSER_RESULT_DIR", "CICADA_V68_EVIDENCE_ROOT",
    "CICADA_NODE_CONTROL_GOMODCACHE", "CICADA_M5_GOLANG_IMAGE", "CICADA_GOMODCACHE",
    "CICADA_NATIVE_ENV_FILE", "CICADA_NATIVE_CODEX_IMAGE", "CICADA_NATIVE_PROXY",
    "CICADA_CURRENT_BINDING_FILE", "CICADA_CURRENT_BINDING_SHA", "CICADA_COMPLETION_EVIDENCE_ROOT",
}

PYTHON_TESTS = [
    "scripts.test_build_input_inventory", "scripts.test_client_contract",
    "scripts.test_client_network_fixture", "scripts.test_client_recovery_fault_proxy",
    "scripts.test_completion_driver_status", "scripts.test_completion_runner",
    "scripts.test_group_fabric_stress_driver", "scripts.test_hub_restore_activation",
    "scripts.test_native_network_monitor_driver", "scripts.test_native_request_observer",
    "scripts.test_native_request_observer_io", "scripts.test_native_tool_trace",
    "scripts.test_native_two_node_driver", "scripts.test_node_restore_recovery",
    "scripts.test_real_node_codex_approval_overlay", "scripts.test_task_peer_privacy",
    "scripts.native_observer.test_request_observer_binding",
]

LANE_TIMEOUTS = {
    "go-build-test-vet": 1200, "python-unittests": 900, "client-contract": 120,
    "release-packaging": 600, "wiring-checks": 600,
    "client-interop": 900, "network-m1": 900, "group-spaces-m2": 900,
    "capacity": 900, "joined-v68": 1200, "multi-hub": 900,
    "node-control-v1": 900, "group-fabric-stress": 900,
    "hub-web-browser": 1200, "native-worker-approval": 1200,
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


MAX_SOURCE_FILE_BYTES = 256 * 1024 * 1024


def source_identity() -> dict:
    """Hash source state without storing diffs or reading .cicada-data."""
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout.strip()
    diff = subprocess.run(["git", "diff", "--binary", "HEAD", "--", ".", ":!.cicada-data"],
                          cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    staged = subprocess.run(["git", "diff", "--cached", "--binary", "--", ".", ":!.cicada-data"],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all", "--", ".", ":!.cicada-data"],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    untracked = []
    incomplete = []
    allowed_names = {"Makefile", "Dockerfile", "README", "LICENSE", "go.mod", "go.sum"}
    allowed_suffixes = {".go", ".py", ".sh", ".mjs", ".js", ".html", ".css", ".json",
                        ".jsonl", ".toml", ".yaml", ".yml", ".md", ".txt", ".proto",
                        ".sql", ".mod", ".sum", ".lock", ".conf"}
    excluded_names = {".env", "credentials.json", "config.toml", "id_rsa"}
    for raw in subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "--", ".", ":!.cicada-data"],
                              cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout.decode(errors="replace").splitlines():
        path = ROOT / raw
        if any(part in {".git", ".cicada-data", "node_modules", "vendor", "__pycache__"} for part in path.parts):
            continue
        if path.name.lower() in excluded_names or path.suffix.lower() in {".env", ".pem", ".key", ".p12", ".sqlite", ".db"}:
            continue
        if path.name not in allowed_names and not path.name.startswith("Dockerfile") and path.suffix.lower() not in allowed_suffixes:
            continue
        try:
            if path.is_symlink():
                target = os.readlink(path)
                untracked.append((raw, "symlink", path.lstat().st_mode & 0o7777, sha256(target.encode())))
            elif path.is_file() and path.stat().st_size <= MAX_SOURCE_FILE_BYTES:
                untracked.append((raw, "file", path.stat().st_mode & 0o7777, file_sha(path)))
            elif path.is_file():
                incomplete.append({"path": raw, "reason": "source file exceeds bounded identity limit"})
            else:
                incomplete.append({"path": raw, "reason": "source path is not a regular file or symlink"})
        except OSError as error:
            incomplete.append({"path": raw, "reason": type(error).__name__})
    return {
        "head": head,
        "tracked_worktree_sha256": sha256(diff),
        "tracked_index_sha256": sha256(staged),
        "status_names_sha256": sha256(status),
        "untracked_source_sha256": sha256(json.dumps(untracked, separators=(",", ":")).encode()),
        "complete": not incomplete,
        "incomplete_sources": incomplete,
    }


def compare_source_identity(before: dict, after: dict) -> dict:
    complete = before.get("complete") is True and after.get("complete") is True
    unchanged = before == after if complete else None
    return {"complete": complete, "unchanged": unchanged,
            "status": "PASS" if unchanged is True else "FAIL" if unchanged is False else "UNKNOWN"}


def private_run_root() -> Path:
    raw = os.environ.get("CICADA_COMPLETION_EVIDENCE_ROOT")
    root = Path(raw).expanduser() if raw else DEFAULT_EVIDENCE
    root = root.resolve()
    data = DATA.resolve()
    if root != data and data not in root.parents:
        raise ValueError("CICADA_COMPLETION_EVIDENCE_ROOT must remain under .cicada-data")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root


def safe_child_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    result = {key: value for key, value in os.environ.items() if key in SAFE_ENV}
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result.setdefault("TMPDIR", "/tmp")
    if overrides:
        result.update(overrides)
    return result


def process_group_stop(proc: subprocess.Popen, grace: int = STOP_GRACE) -> bool:
    pgid = proc.pid
    def alive() -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    for sig, window in ((signal.SIGINT, grace), (signal.SIGTERM, 3), (signal.SIGKILL, 3)):
        if not alive():
            break
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + window
        while time.monotonic() < deadline and alive():
            time.sleep(0.05)
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        return False
    return not alive()


def run_process(argv: list[str], *, log_path: Path, timeout: int, env: dict[str, str],
                cwd: Path = ROOT) -> dict:
    start = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with log_path.open("xb") as log:
        os.chmod(log_path, 0o600)
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    start_new_session=True, bufsize=0)
        except FileNotFoundError:
            return {"exit_code": None, "timed_out": False, "spawn_error": "EXECUTABLE_MISSING",
                    "duration_seconds": round(time.monotonic() - start, 3), "process_exit_confirmed": True,
                    "process_group_cleanup_confirmed": True, "log_bound_exceeded": False}
        assert proc.stdout is not None
        os.set_blocking(proc.stdout.fileno(), False)
        deadline = start + timeout
        kept = 0
        overflow = False
        stopped = False
        process_group_cleanup = True
        eof = False
        drain_deadline = deadline + STOP_GRACE + 8
        while not eof or proc.poll() is None:
            if not stopped and (_STOP or time.monotonic() >= deadline):
                stopped = True
                process_group_cleanup = process_group_stop(proc)
            if not overflow and kept >= MAX_LOG_BYTES and proc.poll() is None:
                overflow = True
                stopped = True
                process_group_cleanup = process_group_stop(proc)
            if time.monotonic() > drain_deadline:
                break
            if eof:
                # select() on an EOF fd is immediately readable; keep the
                # child-exit wait bounded without spinning a CPU core.
                time.sleep(0.1)
                continue
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if not ready:
                if proc.poll() is not None and not ready:
                    # A final read distinguishes EOF from an inherited open pipe.
                    try:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                    except BlockingIOError:
                        chunk = None
                    if chunk == b"": eof = True
                    elif chunk:
                        room = max(0, MAX_LOG_BYTES - kept)
                        if room:
                            part = chunk[:room]
                            log.write(part); kept += len(part)
                        if len(chunk) > room:
                            overflow = True
                continue
            try:
                chunk = os.read(proc.stdout.fileno(), 65536)
            except BlockingIOError:
                continue
            if chunk == b"":
                eof = True
                continue
            room = max(0, MAX_LOG_BYTES - kept)
            if room:
                part = chunk[:room]
                log.write(part)
                kept += len(part)
            if len(chunk) > room and not overflow:
                overflow = True
                if not stopped:
                    stopped = True
                    process_group_cleanup = process_group_stop(proc)
        if proc.poll() is None or _process_group_alive(proc.pid):
            process_group_cleanup = process_group_stop(proc, grace=1)
        else:
            process_group_cleanup = True
        code = proc.poll()
        return {"exit_code": code, "timed_out": (not _STOP and time.monotonic() >= deadline),
                "interrupted": _STOP, "duration_seconds": round(time.monotonic() - start, 3),
                "process_exit_confirmed": code is not None, "process_group_cleanup_confirmed": bool(process_group_cleanup),
                "log_bound_exceeded": overflow, "log_bytes_retained": kept,
                "pipe_eof_observed": eof}


def _process_group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def marker_status(log_path: Path, exit_code: int | None) -> tuple[str, list[str]]:
    if exit_code is None:
        return "BLOCKED", ["child executable could not be started"]
    try:
        if log_path.stat().st_size > MAX_LOG_BYTES:
            return "UNKNOWN", ["LOG_BOUND_EXCEEDED"]
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "UNKNOWN", ["child log could not be read"]
    explicit = []
    for line in text.splitlines():
        line = line.strip()
        if re.match(r"^(FAIL|ERROR)\b", line):
            explicit.append("CHILD_FAILURE_MARKER")
        elif re.match(r"^BLOCKED\b", line):
            explicit.append("CHILD_BLOCKED_MARKER")
        elif re.match(r"^NOT_RUN\b", line):
            explicit.append("CHILD_NOT_RUN_MARKER")
        elif re.match(r"^SKIP\b", line):
            explicit.append("CHILD_SKIP_MARKER")
    if re.search(r'"(?:status|outcome|overall_status)"\s*:\s*"(?:FAIL|ERROR)"', text):
        explicit.append("STRUCTURED_CHILD_FAILURE_MARKER")
    if "CHILD_FAILURE_MARKER" in explicit:
        return "FAIL", sorted(set(explicit))
    if "STRUCTURED_CHILD_FAILURE_MARKER" in explicit:
        return "FAIL", sorted(set(explicit))
    if "CHILD_BLOCKED_MARKER" in explicit:
        return "BLOCKED", sorted(set(explicit))
    if "CHILD_NOT_RUN_MARKER" in explicit:
        return ("NOT_RUN" if exit_code == 0 else "FAIL"), sorted(set(explicit))
    if "CHILD_SKIP_MARKER" in explicit:
        return ("SKIP" if exit_code == 0 else "FAIL"), sorted(set(explicit))
    if exit_code != 0:
        return "FAIL", ["CHILD_NONZERO_EXIT"]
    return "PASS", []


def parse_go_counts(run_dir: Path) -> dict:
    test_file = run_dir / "go" / "out" / "go-test.jsonl"
    counts = {"package_pass": 0, "package_fail": 0, "test_pass": 0, "test_fail": 0,
              "test_skip": 0, "skipped_tests": []}
    if not test_file.exists():
        return counts
    with test_file.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            action, name = event.get("Action"), event.get("Test")
            if not name:
                if action == "pass": counts["package_pass"] += 1
                elif action == "fail": counts["package_fail"] += 1
                continue
            if action == "pass": counts["test_pass"] += 1
            elif action == "fail": counts["test_fail"] += 1
            elif action == "skip":
                counts["test_skip"] += 1
                counts["skipped_tests"].append({"package": event.get("Package"), "test": name})
    return counts


def child_receipt_status(paths: list[Path]) -> tuple[str | None, str, list[str], str | None]:
    """Read only this lane's known result path(s); never scan sibling lanes."""
    candidates: list[Path] = []
    for path in paths:
        if path.is_file():
            candidates.append(path)
        elif path.is_dir():
            candidates.extend(sorted(path.glob("*/result.json")))
            candidates.extend(sorted(path.glob("result.json")))
    if not candidates:
        return None, "UNKNOWN", ["CHILD_RESULT_RECEIPT_MISSING"], None
    latest = max(candidates, key=lambda p: p.stat().st_mtime_ns)
    if latest.stat().st_size > 1024 * 1024:
        return str(latest), "UNKNOWN", ["CHILD_RESULT_RECEIPT_OVERSIZE"], None
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return str(latest), "UNKNOWN", ["CHILD_RESULT_RECEIPT_INVALID"], None
    if not isinstance(data, dict):
        return str(latest), "UNKNOWN", ["CHILD_RESULT_RECEIPT_INVALID"], None
    status = data.get("status", data.get("outcome", data.get("overall_status")))
    cleanup_values = []
    def collect(value, in_cleanup=False):
        if isinstance(value, dict):
            for k, v in value.items(): collect(v, in_cleanup or "cleanup" in k.lower())
        elif in_cleanup:
            cleanup_values.append(value)
    collect(data)
    if not cleanup_values:
        cleanup = "UNKNOWN"
    elif all(value is True or (isinstance(value, str) and value in {"PASS", "REMOVED", "ABSENT", "CONFIRMED", "NOT_CREATED"}) for value in cleanup_values):
        cleanup = "CONFIRMED"
    elif any(value is False or (isinstance(value, str) and value in {"FAIL", "FAILED", "UNKNOWN", "NOT_CONFIRMED"}) for value in cleanup_values):
        cleanup = "FAILED"
    else:
        cleanup = "UNKNOWN"
    return str(latest), cleanup, ["CHILD_FIXTURE_CLEANUP_" + cleanup], status


def classification(run: dict, log: Path, lane: str, receipt_paths: list[Path] | None = None,
                   cleanup_required: bool = False) -> tuple[str, list[str]]:
    if run.get("interrupted") or not run.get("process_exit_confirmed") or not run.get("process_group_cleanup_confirmed"):
        return "UNKNOWN", ["INTERRUPTED_OR_PROCESS_CLEANUP_UNCONFIRMED"]
    if run.get("timed_out"):
        return "UNKNOWN", ["LANE_TIMEOUT"]
    if run.get("log_bound_exceeded"):
        return "UNKNOWN", ["LOG_BOUND_EXCEEDED"]
    if run.get("exit_code") is not None and run.get("pipe_eof_observed") is not True:
        return "UNKNOWN", ["CHILD_OUTPUT_EOF_UNCONFIRMED"]
    state, codes = marker_status(log, run.get("exit_code"))
    if state == "FAIL":
        return "FAIL", codes
    if state == "BLOCKED":
        return "BLOCKED", codes
    if receipt_paths:
        receipt_path, cleanup, receipt_codes, receipt_status = child_receipt_status(receipt_paths)
        run["child_result_path"] = receipt_path
        run["fixture_cleanup_status"] = cleanup
        run["child_receipt_status"] = receipt_status
        codes.extend(receipt_codes)
        if receipt_status in {"FAIL", "ERROR"}:
            return "FAIL", codes + ["CHILD_RECEIPT_FAILURE"]
        if receipt_status == "BLOCKED":
            return "BLOCKED", codes + ["CHILD_RECEIPT_BLOCKED"]
        if receipt_status == "NOT_RUN":
            return ("NOT_RUN" if run.get("exit_code") == 0 else "FAIL"), codes + ["CHILD_RECEIPT_NOT_RUN"]
        if receipt_status == "SKIP":
            return ("SKIP" if run.get("exit_code") == 0 else "FAIL"), codes + ["CHILD_RECEIPT_SKIP"]
        if receipt_status not in {"PASS", "FAIL", "ERROR", "BLOCKED", "NOT_RUN", "SKIP"}:
            return "UNKNOWN", codes + ["CHILD_RECEIPT_STATUS_UNKNOWN"]
        if cleanup == "FAILED":
            return "FAIL", codes
        if cleanup == "UNKNOWN":
            return "UNKNOWN", codes
    elif cleanup_required and state == "PASS":
        run["fixture_cleanup_status"] = "UNKNOWN"
        return "UNKNOWN", codes + ["CHILD_FIXTURE_CLEANUP_RECEIPT_MISSING"]
    if lane == "go-build-test-vet":
        go = log.parent.parent / "go"
        exits = go / "phase-exits.json"
        if not exits.exists():
            return "FAIL" if run.get("exit_code") not in (0, None) else "UNKNOWN", ["GO_PHASE_RECEIPT_MISSING"]
        try:
            values = json.loads(exits.read_text())
        except (ValueError, OSError):
            return "UNKNOWN", ["GO_PHASE_RECEIPT_INVALID"]
        if any(values.get(key) != 0 for key in ("gofmt", "build", "test", "vet")):
            return "FAIL", ["GO_PHASE_NONZERO"]
        counts = parse_go_counts(log.parent.parent)
        if counts["test_fail"] or counts["package_fail"]:
            return "FAIL", ["GO_TEST_FAILURE_EVENT"]
        if counts["test_skip"]:
            return "PASS_WITH_SKIPS", ["GO_OPTIONAL_TESTS_SKIPPED"]
    if state == "PASS":
        if lane in {"python-unittests", "release-packaging"}:
            match = re.search(r"\bOK\s*\(skipped=(\d+)\)", log.read_text(encoding="utf-8", errors="replace"))
            if match and int(match.group(1)):
                run["skip_count"] = int(match.group(1))
                return "PASS_WITH_SKIPS", ["UNITTEST_OPTIONAL_TESTS_SKIPPED"]
        return state, codes
    return state, codes


def write_live(run_dir: Path, result: dict) -> None:
    atomic_json(run_dir / "result.json", result)
    summary = [f"Architecture v2 completion: {result['overall_status']}",
               f"Run: {result['run_id']}", f"Updated: {result['updated_at']}", ""]
    for lane in result.get("lanes", []):
        summary.append(f"{lane['name']:<27} {lane['status']:<16} {lane.get('note','')}")
    tmp = run_dir / "summary.txt.tmp"
    tmp.write_text("\n".join(summary) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(run_dir / "summary.txt")


def docker_available(timeout: float = 20) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, env=safe_child_env())
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def create_protected_resident_receipt(destination: Path, deadline: float) -> tuple[bool, str, int]:
    """Capture the existing deployment as-is for the stress driver's guard."""
    def remaining_timeout(cap: float) -> float:
        if _STOP:
            raise TimeoutError("runner interrupted during resident snapshot")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("stress lane budget expired during resident snapshot")
        return min(cap, remaining)
    listed = subprocess.run(["docker", "ps", "--no-trunc", "-q"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=remaining_timeout(15), env=safe_child_env())
    if listed.returncode != 0:
        return False, "UNKNOWN: could not capture current Docker resident IDs", 0
    ids = listed.stdout.splitlines()
    if len(ids) > 256 or any(not re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids):
        return False, "BLOCKED: current Docker resident set exceeded the bounded receipt format", len(ids)
    records = {}
    template = "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.RestartCount}}"
    for cid in ids:
        try:
            timeout = remaining_timeout(15)
        except TimeoutError as error:
            return False, str(error), len(records)
        inspected = subprocess.run(["docker", "inspect", "--format", template, cid], text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=timeout, env=safe_child_env())
        fields = inspected.stdout.strip().split("|", 5) if inspected.returncode == 0 else []
        if len(fields) != 6 or fields[0] != cid or fields[2] != "running":
            return False, "UNKNOWN: resident changed during its read-only Docker snapshot", len(records)
        try:
            pid, restart = int(fields[3]), int(fields[5])
        except ValueError:
            return False, "UNKNOWN: Docker resident metadata was not numeric", len(records)
        if pid <= 0 or restart < 0 or not fields[1] or not fields[4]:
            return False, "UNKNOWN: Docker resident metadata failed closed validation", len(records)
        records[cid] = {"id": cid, "status": "running", "image": fields[1],
                        "pid": pid, "started_at": fields[4], "restart_count": restart}
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write((json.dumps(records, sort_keys=True, indent=2) + "\n").encode())
    except OSError:
        return False, "UNKNOWN: could not write the fresh protected-resident receipt", len(records)
    return True, f"captured {len(records)} current Docker residents read-only", len(records)


def go_lane(run_dir: Path, run_id: str, timeout: int) -> dict:
    lane_deadline = time.monotonic() + timeout
    def remaining(cap: float) -> float:
        if _STOP:
            raise TimeoutError("runner interrupted during Go lane")
        value = lane_deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("Go lane time budget expired")
        return min(cap, value)
    go_root = run_dir / "go"
    for name in ("out", "cache", "tmp"):
        (go_root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    module_cache = ROOT / ".cicada-data" / "m1-gomodcache"
    if not module_cache.is_dir():
        return {"status": "BLOCKED", "note": "pinned offline module cache is absent", "exit_code": None}
    try:
        if not docker_available(remaining(20)):
            return {"status": "BLOCKED", "note": "Docker daemon unavailable; Go lane not started", "exit_code": None}
    except TimeoutError:
        return {"status": "BLOCKED", "note": "Go lane budget expired before Docker preflight", "exit_code": None}
    try:
        inspect = subprocess.run(["docker", "image", "inspect", GO_IMAGE, "--format", "{{.Id}}"],
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=remaining(20), env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired, TimeoutError):
        return {"status": "BLOCKED", "note": "pinned Go image inspection did not complete in its lane", "exit_code": None}
    if inspect.returncode != 0 or not inspect.stdout.strip():
        return {"status": "BLOCKED", "note": "pinned Go image is not present locally; runner will not pull", "exit_code": None}
    image_id = inspect.stdout.strip()
    container_name = f"cicada-completion-go-{run_id}"
    out = go_root / "out"
    script = r'''set +e
umask 077
run_bounded() {
  target="$1"; shift
  "$@" > "$target" 2>&1 & child=$!
  while [ -r "/proc/$child/stat" ]; do
    procstat=$(cat "/proc/$child/stat" 2>/dev/null || true)
    state=${procstat##*) }
    state=${state%% *}
    { [ "$state" = Z ] || [ "$state" = X ]; } && break
    size=$(stat -c %s "$target" 2>/dev/null || echo 0)
    if [ "$size" -gt 16777216 ]; then
      : > /out/output-bound-exceeded
      kill -TERM "$child" 2>/dev/null || true
      sleep 1
      kill -KILL "$child" 2>/dev/null || true
      wait "$child"; return 125
    fi
    sleep 0.2
  done
  wait "$child"; rc=$?
  size=$(stat -c %s "$target" 2>/dev/null || echo 0)
  [ "$size" -le 16777216 ] || { : > /out/output-bound-exceeded; return 125; }
  return "$rc"
}
find . -type f -name '*.go' -print0 | xargs -0 gofmt -l > /out/gofmt-files.txt 2>/out/gofmt.stderr
fmt_rc=$?
run_bounded /out/build.log go build -mod=readonly -p=2 ./...
build_rc=$?
umask 0022
run_bounded /out/go-test.jsonl go test -json -count=1 -timeout=15m -mod=readonly -p=2 ./...
test_rc=$?
umask 077
run_bounded /out/vet.log go vet -mod=readonly -p=2 ./...
vet_rc=$?
printf '{"gofmt":%s,"build":%s,"test":%s,"vet":%s}\n' "$fmt_rc" "$build_rc" "$test_rc" "$vet_rc" > /out/phase-exits.json
chmod 600 /out/* 2>/dev/null
if [ -f /out/output-bound-exceeded ]; then exit 124; fi
if [ "$fmt_rc" -eq 0 ] && [ ! -s /out/gofmt-files.txt ] && [ "$build_rc" -eq 0 ] && [ "$test_rc" -eq 0 ] && [ "$vet_rc" -eq 0 ]; then exit 0; else exit 1; fi'''
    argv = ["docker", "create", "--name", container_name,
            "--label", "cicada.acceptance.task=architecture-v2-completion-go",
            "--label", f"cicada.acceptance.run={run_id}",
            "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "3g", "--pids-limit", "256",
            "--mount", f"type=bind,src={ROOT / 'cicada-go'},dst=/repo,readonly",
            "--mount", f"type=bind,src={module_cache},dst=/gomod,readonly",
            "--mount", f"type=bind,src={go_root / 'cache'},dst=/gocache",
            "--mount", f"type=bind,src={go_root / 'tmp'},dst=/gotmp",
            "--mount", f"type=bind,src={out},dst=/out",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--workdir", "/repo",
            "--env", "GOTOOLCHAIN=local", "--env", "GOPROXY=off", "--env", "GOSUMDB=off",
            "--env", "GOMODCACHE=/gomod", "--env", "GOCACHE=/gocache", "--env", "GOTMPDIR=/gotmp",
            GO_IMAGE, "bash", "-c", script]
    if len(script.encode()) > 8192:
        return {"status": "FAIL", "note": "internal Go script exceeded reviewed bound", "exit_code": None}
    try:
        created = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=remaining(30), env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired, TimeoutError):
        cleanup = remove_exact_go_container_by_name(container_name, run_id)
        return {"status": "UNKNOWN", "note": "Docker create did not complete within the Go lane",
                "exit_code": None, "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    (go_root / "create.log").write_text((created.stderr or "")[-8000:], encoding="utf-8")
    (go_root / "create.log").chmod(0o600)
    if created.returncode != 0:
        cleanup = remove_exact_go_container_by_name(container_name, run_id)
        return {"status": "BLOCKED" if cleanup else "UNKNOWN",
                "note": "Docker could not create the pinned Go container", "exit_code": created.returncode,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    cid = created.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        cleanup = remove_exact_go_container_by_name(container_name, run_id)
        return {"status": "UNKNOWN", "note": "Docker create returned an invalid container ID",
                "exit_code": None, "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    try:
        (go_root / "container-id").write_text(cid + "\n", encoding="ascii")
        (go_root / "container-id").chmod(0o600)
    except OSError:
        cleanup = remove_exact_go_container(cid, run_id)
        return {"status": "UNKNOWN", "note": "could not record the exact owned Go container ID",
                "exit_code": None, "container_id": cid,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    try:
        projection = subprocess.run(["docker", "inspect", "--format",
            "{{.Id}}|{{.Config.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .Mounts}}|{{json .HostConfig.Tmpfs}}|{{index .Config.Labels \"cicada.acceptance.run\"}}|{{index .Config.Labels \"cicada.acceptance.task\"}}", cid],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=remaining(20), env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired, TimeoutError):
        cleanup = remove_exact_go_container(cid, run_id)
        return {"status": "UNKNOWN", "note": "created Go container could not be inspected within its lane",
                "exit_code": None, "container_id": cid,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    expected_prefix = [cid, GO_IMAGE, f"{os.getuid()}:{os.getgid()}", "none", "true", "2000000000", "3221225472", "256"]
    fields = projection.stdout.strip().split("|", 14) if projection.returncode == 0 else []
    valid = len(fields) == 15 and fields[:8] == expected_prefix and fields[13] == run_id and fields[14] == GO_TASK_LABEL
    if valid:
        try:
            cap_add = json.loads(fields[8]) or []
            caps = json.loads(fields[9]); security = json.loads(fields[10]); mounts = json.loads(fields[11])
            tmpfs = json.loads(fields[12])
            valid = cap_add == [] and caps == ["ALL"] and no_new_privileges_enabled(security)
            expected_mounts = {
                (str(ROOT / "cicada-go"), "/repo", False), (str(module_cache), "/gomod", False),
                (str(go_root / "cache"), "/gocache", True), (str(go_root / "tmp"), "/gotmp", True),
                (str(out), "/out", True),
            }
            actual_mounts = {(item.get("Source"), item.get("Destination"), item.get("RW"))
                             for item in mounts if item.get("Type") == "bind"}
            tmp_options = set(tmpfs.get("/tmp", "").split(",")) if isinstance(tmpfs, dict) else set()
            size_ok = bool(tmp_options & {"size=128m", "size=134217728"})
            valid = valid and actual_mounts == expected_mounts and size_ok and {"rw", "nosuid", "nodev"}.issubset(tmp_options)
        except (ValueError, TypeError):
            valid = False
    if not valid:
        cleanup = remove_exact_go_container(cid, run_id)
        return {"status": "FAIL", "note": "actual Go container envelope did not match the fixed policy", "exit_code": None,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    try:
        (go_root / "envelope.json").write_text(json.dumps({"image_id": image_id, "image_ref": GO_IMAGE,
            "user": fields[2], "network": fields[3], "read_only_root": fields[4] == "true",
            "nano_cpus": int(fields[5]), "memory_bytes": int(fields[6]), "pids_limit": int(fields[7]),
            "cap_add": json.loads(fields[8]) or [], "cap_drop": json.loads(fields[9]),
            "security_opt": json.loads(fields[10]), "mounts": json.loads(fields[11]),
        "tmpfs": json.loads(fields[12]), "run_label": run_id, "task_label": fields[14]}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (go_root / "envelope.json").chmod(0o600)
    except OSError:
        cleanup = remove_exact_go_container(cid, run_id)
        return {"status": "UNKNOWN", "note": "could not preserve the verified Go container envelope",
                "exit_code": None, "container_id": cid,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    log = go_root / "docker-output.log"
    timed_out = interrupted = False
    cleanup = False
    wait = None
    started_info = {}
    try:
        started_info = run_process(["docker", "start", "--attach", cid], log_path=log,
                                   timeout=max(1, int(remaining(timeout))), env=safe_child_env())
        timed_out = bool(started_info.get("timed_out"))
        interrupted = bool(started_info.get("interrupted"))
        if timed_out or interrupted or started_info.get("log_bound_exceeded"):
            stop_exact_go_container(cid, run_id)
        wait = subprocess.run(["docker", "inspect", "--format", "{{.State.ExitCode}}|{{.State.Status}}", cid],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
                              env=safe_child_env())
    except BaseException:
        interrupted = True
    finally:
        cleanup = remove_exact_go_container(cid, run_id)
    for child in out.glob("*"):
        if child.is_file(): child.chmod(0o600)
    counts = parse_go_counts(run_dir)
    phase_path = out / "phase-exits.json"
    phase_codes = None
    if phase_path.exists():
        try: phase_codes = json.loads(phase_path.read_text())
        except ValueError: pass
    state = wait.stdout.strip().split("|", 1) if wait and wait.returncode == 0 else []
    if interrupted or timed_out or started_info.get("log_bound_exceeded") or (out / "output-bound-exceeded").exists() or not started_info.get("process_exit_confirmed") or not started_info.get("process_group_cleanup_confirmed") or not cleanup or len(state) != 2:
        status = "UNKNOWN"
    elif state[0] != "0" or counts["package_pass"] + counts["package_fail"] == 0 or counts["test_pass"] + counts["test_fail"] + counts["test_skip"] == 0 or counts["test_fail"] or counts["package_fail"] or not phase_codes or any(phase_codes.get(k) != 0 for k in ("gofmt", "build", "test", "vet")):
        status = "FAIL"
    elif counts["test_skip"]:
        status = "PASS_WITH_SKIPS"
    else:
        status = "PASS"
    return {"status": status, "exit_code": int(state[0]) if len(state) == 2 and state[0].isdigit() else None,
            "timed_out": timed_out, "interrupted": interrupted,
            "process_exit_confirmed": bool(started_info.get("process_exit_confirmed")),
            "process_group_cleanup_confirmed": bool(started_info.get("process_group_cleanup_confirmed")),
            "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN",
            "note": "Go build, full default tests, go vet, and read-only gofmt check in pinned offline image",
            "counts": counts, "phase_exit_codes": phase_codes, "container_id": cid,
            "actual_state": state[1] if len(state) == 2 else None, "image_id": image_id,
            "envelope_verified": valid}


def remove_exact_go_container(cid: str, run_id: str) -> bool:
    try:
        inspected = subprocess.run(["docker", "inspect", "--format",
            "{{.Id}}|{{index .Config.Labels \"cicada.acceptance.run\"}}", cid], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    if inspected.returncode != 0:
        try:
            absent = subprocess.run(["docker", "inspect", cid], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env=safe_child_env())
        except (OSError, subprocess.TimeoutExpired):
            return False
        return absent.returncode != 0 and exact_docker_absence(absent.stderr, cid)
    if inspected.stdout.strip() != f"{cid}|{run_id}":
        return False
    try:
        removed = subprocess.run(["docker", "rm", "--force", cid], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=30, env=safe_child_env())
        absent = subprocess.run(["docker", "inspect", cid], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    confirmed_absent = absent.returncode != 0 and exact_docker_absence(absent.stderr, cid)
    return removed.returncode == 0 and confirmed_absent


def exact_docker_absence(stderr: str, object_ref: str) -> bool:
    """Recognize only Docker's exact missing-object response for this target."""
    lines = [line.strip().casefold() for line in stderr.splitlines() if line.strip()]
    target = object_ref.casefold()
    return len(lines) == 1 and lines[0] in {
        f"no such object: {target}", f"error: no such object: {target}"
    }


def no_new_privileges_enabled(security_opt: object) -> bool:
    if not isinstance(security_opt, list) or any(not isinstance(item, str) for item in security_opt):
        return False
    setting = [item.casefold() for item in security_opt
               if item.casefold().startswith("no-new-privileges")]
    return len(setting) == 1 and setting[0] in {
        "no-new-privileges", "no-new-privileges:true"
    }


def stop_exact_go_container(cid: str, run_id: str) -> bool:
    try:
        inspected = subprocess.run(["docker", "inspect", "--format",
            "{{.Id}}|{{index .Config.Labels \"cicada.acceptance.run\"}}", cid], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    if inspected.returncode != 0 or inspected.stdout.strip() != f"{cid}|{run_id}":
        return False
    try:
        stopped = subprocess.run(["docker", "stop", "--time", "10", cid], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=20, env=safe_child_env())
        return stopped.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def remove_exact_go_container_by_name(name: str, run_id: str) -> bool:
    try:
        inspected = subprocess.run(["docker", "inspect", "--format",
            "{{.Id}}|{{.Name}}|{{index .Config.Labels \"cicada.acceptance.run\"}}", name],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    if inspected.returncode != 0:
        return exact_docker_absence(inspected.stderr, name)
    fields = inspected.stdout.strip().split("|", 2)
    if (len(fields) != 3 or fields[1] != "/" + name or fields[2] != run_id
            or not re.fullmatch(r"[0-9a-f]{64}", fields[0])):
        return False
    return remove_exact_go_container(fields[0], run_id)


def make_lanes(run_dir: Path, flags: dict, docker_ok: bool) -> list[dict]:
    lanes: list[dict] = []
    def add(name: str, kind: str, argv: list[str] | None = None, note: str = "",
            env: dict[str, str] | None = None, receipt_paths: list[Path] | None = None,
            cleanup_required: bool = False):
        lanes.append({"name": name, "kind": kind, "argv": argv, "note": note,
                      "env": env or {}, "receipt_paths": receipt_paths or [],
                      "cleanup_required": cleanup_required,
                      "timeout_seconds": LANE_TIMEOUTS.get(name, 600)})

    add("go-build-test-vet", "go")
    add("python-unittests", "command", ["python3", "-B", "-m", "unittest", "-q", *PYTHON_TESTS],
        env={"PYTHONPATH": f"{ROOT / 'scripts'}:{ROOT / 'scripts/native_observer'}"})
    add("client-contract", "command", ["python3", "-B", "scripts/client-contract.py", "check"])
    add("release-packaging", "command", ["python3", "-B", "scripts/test-release-packaging.py"])
    if shutil.which("node"):
        add("web-panel-model", "command", ["node", "scripts/test-web-panel.mjs", "--model-only", "--ui", "cicada-go/internal/server/ui"])
        add("web-panel-browser-config", "command", ["node", "scripts/test-hub-web-panel-browser-config.mjs"])
    else:
        add("web-panel-model", "blocked", note="Node.js is not installed")
        add("web-panel-browser-config", "blocked", note="Node.js is not installed")
    wire = os.environ.get("CICADA_CURRENT_BINDING_FILE")
    wire_sha = os.environ.get("CICADA_CURRENT_BINDING_SHA")
    if bool(wire) != bool(wire_sha):
        add("wiring-checks", "blocked", note="current binding requires both file and SHA environment values")
    elif wire and wire_sha:
        add("wiring-checks", "command", ["python3", "-B", "scripts/native_observer/request_observer_wiring_checks.py",
            "--current-binding-file", wire, "--current-binding-sha", wire_sha])
    else:
        add("wiring-checks", "skip", note="no explicit current binding file and SHA supplied")
    if docker_ok:
        interop = ROOT / "scripts/test-client-hub-interop.sh"
        for lane, suite in (("client-interop", "client"), ("network-m1", "network-m1"),
                            ("group-spaces-m2", "group-spaces-m2"), ("capacity", "capacity")):
            output = run_dir / "interop" / lane
            add(lane, "command", ["bash", str(interop), "--suite", suite],
                env={"CICADA_INTEROP_OUTPUT": str(output)}, receipt_paths=[output / "result.json"], cleanup_required=True)
        add("joined-v68", "command", ["bash", "scripts/test-joined-v68-docker.sh"],
            env={"CICADA_V68_EVIDENCE_ROOT": str(run_dir / "v68")}, receipt_paths=[run_dir / "v68"], cleanup_required=True)
        add("multi-hub", "command", ["bash", "scripts/test-multi-hub-services.sh"], cleanup_required=True)
        add("node-control-v1", "command", ["python3", "-B", "scripts/test-node-control-v1-flow.py", "--run",
            "--output-dir", str(run_dir / "node-control")], env={"CICADA_NODE_CONTROL_V1_ENABLED": "1"},
            receipt_paths=[run_dir / "node-control" / "result.json"], cleanup_required=True)
    else:
        for lane in ("client-interop", "network-m1", "group-spaces-m2", "capacity", "joined-v68", "multi-hub", "node-control-v1"):
            add(lane, "blocked", note="Docker daemon unavailable; disposable child not started")
    protected = os.environ.get("CICADA_COMPLETION_PROTECTED_RESIDENTS_FILE")
    if docker_ok:
        stress_root = DATA / f"completion-stress-{run_dir.name}"
        add("group-fabric-stress", "stress", note=f"protected snapshot destination: {run_dir / 'protected-residents.json'}",
            receipt_paths=[stress_root / "RUN.NONAUTH.json"], cleanup_required=True)
    else:
        add("group-fabric-stress", "blocked", note="Docker daemon unavailable")
    browser_vars = ("CICADA_HUB_IMAGE", "CICADA_BUILD_METADATA", "CICADA_EXPECT_SOURCE_FINGERPRINT")
    if all(os.environ.get(key) for key in browser_vars) and docker_ok and shutil.which("node"):
        add("hub-web-browser", "command", ["node", "scripts/test-hub-web-panel-browser.mjs"],
            env={"CICADA_BROWSER_RESULT_DIR": str(run_dir / "browser")},
            receipt_paths=[run_dir / "browser" / "result.json"], cleanup_required=True)
    else:
        add("hub-web-browser", "blocked", note="requires Docker, Node, CICADA_HUB_IMAGE, CICADA_BUILD_METADATA, and CICADA_EXPECT_SOURCE_FINGERPRINT")
    if flags.get("native_worker"):
        env_file = os.environ.get("CICADA_NATIVE_ENV_FILE")
        image = os.environ.get("CICADA_NATIVE_CODEX_IMAGE")
        if not env_file or not Path(env_file).is_file() or not image:
            add("native-worker-approval", "blocked", note="--native requires existing CICADA_NATIVE_ENV_FILE path and CICADA_NATIVE_CODEX_IMAGE")
        elif docker_ok:
            argv = ["python3", "-B", "scripts/test-real-node-codex-approval.py", "--env-file", env_file,
                    "--image", image, "--output", str(run_dir / "native-worker-result.json")]
            if os.environ.get("CICADA_NATIVE_PROXY"):
                argv.extend(["--proxy", os.environ["CICADA_NATIVE_PROXY"]])
            add("native-worker-approval", "command", argv,
                receipt_paths=[run_dir / "native-worker-result.json"], cleanup_required=True)
        else:
            add("native-worker-approval", "blocked", note="Docker daemon unavailable")
    else:
        add("native-worker-approval", "skip", note="explicit paid Worker lane not requested")
    for name, requested in (("native-peer-ask-reply", flags.get("native_peer")),
                            ("native-g4-injection", flags.get("native_g4")),
                            ("native-g5-guards", flags.get("native_g5"))):
        if requested:
            add(name, "blocked", note="no reviewed stable tracked command is available; no native command was started")
        else:
            add(name, "skip", note="native acceptance lane not requested or not exposed by this runner")
    return lanes


def update_lane_result(result: dict, lane_result: dict) -> None:
    result["updated_at"] = now()
    result["lanes"].append(lane_result)
    write_live(Path(result["run_dir"]), result)


def final_status(lanes: list[dict], source_check: dict | bool, interrupted: bool) -> str:
    statuses = {lane["status"] for lane in lanes}
    source_state = source_check.get("status") if isinstance(source_check, dict) else ("PASS" if source_check else "FAIL")
    if "FAIL" in statuses or source_state == "FAIL":
        return "FAIL"
    if "UNKNOWN" in statuses or source_state == "UNKNOWN" or interrupted:
        return "UNKNOWN"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if "NOT_RUN" in statuses or "SKIP" in statuses or "PASS_WITH_SKIPS" in statuses:
        return "INCOMPLETE"
    return "PASS"


def worker(run_dir: Path, run_id: str, flags: dict) -> int:
    global _STOP
    max_seconds = min(MAX_GLOBAL_SECONDS, max(60, int(flags.get("max_seconds", DEFAULT_GLOBAL_SECONDS))))
    result = {"schema": "cicada.architecture-v2-one-click.v1", "run_id": run_id,
              "run_dir": str(run_dir), "overall_status": "RUNNING", "started_at": now(),
              "updated_at": now(), "source_before": None, "source_after": None,
              "source_unchanged": None, "lanes": [], "platform_gates": {
                  "android": "NOT_RUN", "physical_device": "NOT_RUN", "public_https": "NOT_RUN",
                  "native_runtime_model": "NOT_RUN"}}
    write_live(run_dir, result)
    try:
        global_start = time.monotonic()
        before = source_identity()
        result["source_before"] = before
        if before.get("complete") is not True:
            result["source_verification"] = "INCOMPLETE"
        result["runner_sha256"] = file_sha(Path(__file__))
        result["entry_sha256"] = file_sha(ROOT / "scripts/test-architecture-v2-completion.sh")
        result["fixed_go_image"] = GO_IMAGE
        result["child_environment_names"] = sorted(SAFE_ENV & set(os.environ))
        docker_ok = docker_available()
        result["docker_available"] = docker_ok
        lanes = make_lanes(run_dir, flags, docker_ok)
        for lane in lanes:
            if _STOP:
                lane_result = {"name": lane["name"], "status": "NOT_RUN", "note": "runner interrupted before lane start"}
                update_lane_result(result, lane_result)
                continue
            remaining = max_seconds - (time.monotonic() - global_start)
            available = remaining - GLOBAL_CLEANUP_RESERVE
            if available <= 0:
                lane_result = {"name": lane["name"], "status": "NOT_RUN", "note": "global runtime budget exhausted"}
                update_lane_result(result, lane_result)
                continue
            started = now()
            result["active_lane"] = lane["name"]
            result["updated_at"] = started
            write_live(run_dir, result)
            if lane["kind"] == "skip":
                info = {"status": "NOT_RUN", "note": lane["note"], "exit_code": None}
            elif lane["kind"] == "blocked":
                info = {"status": "BLOCKED", "note": lane["note"], "exit_code": None}
            elif lane["kind"] == "go":
                info = go_lane(run_dir, run_id, min(lane["timeout_seconds"], int(available)))
            elif lane["kind"] == "stress":
                lane_deadline = time.monotonic() + min(lane["timeout_seconds"], int(available))
                if os.getuid() != 1000:
                    info = {"status": "BLOCKED", "note": "existing stress driver requires its cache directory to be owned by UID 1000", "exit_code": None}
                else:
                    protected_file = run_dir / "protected-residents.json"
                    try:
                        captured, note, resident_count = create_protected_resident_receipt(protected_file, lane_deadline)
                    except (OSError, subprocess.TimeoutExpired, TimeoutError):
                        captured, note, resident_count = False, "bounded resident snapshot did not complete", 0
                    if not captured:
                        status = ("UNKNOWN" if note.startswith("UNKNOWN:") or "budget" in note or "interrupted" in note
                                  else "BLOCKED")
                        info = {"status": status, "note": note, "exit_code": None,
                                "protected_resident_count": resident_count}
                    else:
                        stress_dir = DATA / f"completion-stress-{run_dir.name}"
                        cache_dir = run_dir / "stress-go-cache"
                        cache_dir.mkdir(mode=0o700, exist_ok=True)
                        argv = ["python3", "-B", "scripts/test-group-fabric-stress.py", "--run",
                                "--evidence-dir", str(stress_dir), "--protected-residents-file",
                                str(protected_file), "--go-cache-dir", str(cache_dir)]
                        log = run_dir / "logs" / "group-fabric-stress.log"
                        stress_timeout = max(1, int(lane_deadline - time.monotonic()))
                        proc_info = run_process(argv, log_path=log, timeout=stress_timeout, env=safe_child_env())
                        status, codes = classification(proc_info, log, lane["name"], lane["receipt_paths"])
                        info = {**proc_info, "status": status, "failure_codes": codes,
                                "note": note, "protected_receipt_sha256": file_sha(protected_file),
                                "protected_resident_count": resident_count}
            else:
                log = run_dir / "logs" / f"{lane['name']}.log"
                log.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                cmd_env = safe_child_env(lane["env"])
                info = run_process(lane["argv"], log_path=log,
                    timeout=min(lane["timeout_seconds"], int(available)), env=cmd_env)
                status, codes = classification(info, log, lane["name"], lane.get("receipt_paths"),
                                                lane.get("cleanup_required", False))
                if status == "PASS":
                    skips = sum(1 for line in log.read_text(encoding="utf-8", errors="replace").splitlines()
                                if re.match(r"^SKIP\b|^\s*--- SKIP:", line))
                    if skips:
                        status = "PASS_WITH_SKIPS"
                        codes.append("CHILD_REPORTED_SKIPS")
                info.update(status=status, failure_codes=codes)
            info.setdefault("status", "UNKNOWN")
            info["name"] = lane["name"]
            info["entrypoint"] = lane.get("argv", ["pinned-go-docker-lane"])[0] if lane.get("argv") else lane["kind"]
            info["started_at"] = started
            info["finished_at"] = now()
            info["note"] = info.get("note") or lane["note"]
            if lane["kind"] == "command":
                info["private_log"] = str(run_dir / "logs" / f"{lane['name']}.log")
            update_lane_result(result, info)
        after = source_identity()
        result["source_after"] = after
        source_check = compare_source_identity(before, after)
        result["source_verification"] = source_check
        result["source_unchanged"] = source_check["unchanged"]
        result["overall_status"] = final_status(result["lanes"], source_check, _STOP)
        result["finished_at"] = now()
        result.pop("active_lane", None)
        write_live(run_dir, result)
        return 0 if result["overall_status"] == "PASS" else 1
    except BaseException as error:
        result["overall_status"] = "UNKNOWN"
        result["fatal_error_class"] = type(error).__name__
        result["finished_at"] = now()
        result.pop("active_lane", None)
        write_live(run_dir, result)
        return 1


def process_identity(pid: int) -> tuple[str | None, str | None]:
    """Read Linux process start time (field 22), robust to spaces in comm."""
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = stat_line.rfind(")")
        if close < 0:
            return None, None
        fields = stat_line[close + 1:].strip().split()
        return (fields[0], fields[19]) if len(fields) > 19 else (None, None)
    except (OSError, UnicodeError):
        return None, None


def process_start_token(pid: int) -> str | None:
    return process_identity(pid)[1]


def flags_from(args: argparse.Namespace) -> dict:
    return {"native_worker": args.native or args.native_worker, "native_peer": args.native_peer,
            "native_g4": args.native_g4, "native_g5": args.native_g5,
            "max_seconds": args.max_seconds}


def create_run(flags: dict) -> tuple[str, Path]:
    parent = private_run_root()
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
    run_dir = parent / run_id
    run_dir.mkdir(mode=0o700)
    (run_dir / "logs").mkdir(mode=0o700)
    atomic_json(run_dir / "request.json", {"run_id": run_id, "created_at": now(), "flags": flags,
                                           "runner_sha256": file_sha(Path(__file__))})
    return run_id, run_dir


def status_mode(run_id: str) -> int:
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}", run_id):
        print("invalid run id", file=sys.stderr); return 2
    parent = private_run_root()
    run_dir = parent / run_id
    if not run_dir.is_dir():
        print("run not found", file=sys.stderr); return 2
    result_path = run_dir / "result.json"
    if not result_path.exists():
        print(json.dumps({"run_id": run_id, "overall_status": "UNKNOWN", "reason": "summary absent"}, indent=2))
        return 2
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("overall_status") == "RUNNING":
        worker_path = run_dir / "worker.json"
        worker_state = "UNKNOWN"
        try:
            worker = json.loads(worker_path.read_text(encoding="utf-8"))
            pid = worker.get("pid")
            expected_token = worker.get("start_token")
            current_state, current_token = process_identity(pid) if isinstance(pid, int) and pid > 0 else (None, None)
            if expected_token and current_token == expected_token and current_state not in {"Z", "X"}:
                worker_state = "RUNNING"
            elif expected_token and current_token is None:
                worker_state = "STOPPED"
            else:
                worker_state = "REPLACED_OR_UNVERIFIABLE"
        except (OSError, ValueError, TypeError):
            worker_state = "MISSING_OR_INVALID"
        if worker_state != "RUNNING":
            result = dict(result)
            result["overall_status"] = "UNKNOWN"
            result["worker_state"] = worker_state
            result["status_reason"] = "worker is not verifiably running and no terminal result was published"
    print(json.dumps(result, sort_keys=True, indent=2))
    summary_lines = [f"Architecture v2 completion: {result.get('overall_status', 'UNKNOWN')}",
                     f"Run: {run_id}", f"Updated: {result.get('updated_at', 'unknown')}", ""]
    for lane in result.get("lanes", []):
        summary_lines.append(f"{lane.get('name','unknown'):<27} {lane.get('status','UNKNOWN'):<16} {lane.get('note','')}")
    if result.get("active_lane") and result.get("overall_status") == "RUNNING":
        summary_lines.append(f"Active lane: {result['active_lane']}")
    print("\n".join(summary_lines))
    return 1 if result.get("overall_status") == "UNKNOWN" else 0


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--background", action="store_true", help="start one detached bounded run and return its ID")
    mode.add_argument("--status", metavar="RUN_ID", help="print the current JSON and human summary for a run")
    parser.add_argument("--native", action="store_true", help="explicitly run the existing paid Worker approval gate")
    parser.add_argument("--native-worker", action="store_true", help="same as --native")
    parser.add_argument("--native-peer", action="store_true", help="record unsupported peer lane as BLOCKED; does not execute")
    parser.add_argument("--native-g4", action="store_true", help="record unsupported G4 lane as BLOCKED; does not execute")
    parser.add_argument("--native-g5", action="store_true", help="record unsupported G5 lane as BLOCKED; does not execute")
    parser.add_argument("--max-seconds", type=int, default=DEFAULT_GLOBAL_SECONDS,
                        help=f"downward-only overall runtime bound, 60..{MAX_GLOBAL_SECONDS} seconds")
    parser.add_argument("--_worker", nargs=2, metavar=("RUN_ID", "RUN_DIR"), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.max_seconds < 60 or args.max_seconds > MAX_GLOBAL_SECONDS:
        parser.error(f"--max-seconds must be between 60 and {MAX_GLOBAL_SECONDS}")
    if args.status:
        return status_mode(args.status)
    if args._worker:
        run_id, run_path = args._worker
        run_dir = Path(run_path).resolve()
        parent = private_run_root()
        if parent not in run_dir.parents or run_dir.name != run_id:
            print("invalid worker run path", file=sys.stderr); return 2
        signal.signal(signal.SIGINT, lambda *_: _set_stop())
        signal.signal(signal.SIGTERM, lambda *_: _set_stop())
        try:
            request = json.loads((run_dir / "request.json").read_text(encoding="utf-8"))
            if request.get("runner_sha256") != file_sha(Path(__file__)) or request.get("run_id") != run_id:
                raise ValueError("worker request/source pin mismatch")
            return worker(run_dir, run_id, request["flags"])
        except BaseException as error:
            result_path = run_dir / "result.json"
            result = {"schema": "cicada.architecture-v2-one-click.v1", "run_id": run_id,
                      "run_dir": str(run_dir), "overall_status": "UNKNOWN", "updated_at": now(),
                      "fatal_error_class": type(error).__name__, "lanes": []}
            write_live(run_dir, result)
            return 1
    flags = flags_from(args)
    run_id, run_dir = create_run(flags)
    if args.background:
        initial = {"schema": "cicada.architecture-v2-one-click.v1", "run_id": run_id,
                   "run_dir": str(run_dir), "overall_status": "RUNNING", "started_at": now(),
                   "updated_at": now(), "lanes": [], "active_lane": None}
        write_live(run_dir, initial)
        worker_log = run_dir / "logs" / "supervisor.log"
        try:
            with worker_log.open("xb") as stream:
                os.chmod(worker_log, 0o600)
                proc = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--_worker", run_id, str(run_dir)],
                    cwd=ROOT, env=safe_child_env(), stdin=subprocess.DEVNULL, stdout=stream,
                    stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            failed = {"schema": "cicada.architecture-v2-one-click.v1", "run_id": run_id,
                      "run_dir": str(run_dir), "overall_status": "UNKNOWN", "updated_at": now(),
                      "finished_at": now(), "fatal_error_class": type(error).__name__, "lanes": []}
            write_live(run_dir, failed)
            print(f"UNKNOWN {run_id}: supervisor could not start")
            return 1
        atomic_json(run_dir / "worker.json", {"pid": proc.pid, "started_at": now(),
                                               "start_token": process_start_token(proc.pid)})
        print(f"RUNNING {run_id}")
        print(f"Status: scripts/test-architecture-v2-completion.sh --status {run_id}")
        return 0
    signal.signal(signal.SIGINT, lambda *_: _set_stop())
    signal.signal(signal.SIGTERM, lambda *_: _set_stop())
    rc = worker(run_dir, run_id, flags)
    print((run_dir / "summary.txt").read_text(encoding="utf-8"), end="")
    print(f"JSON: {run_dir / 'result.json'}")
    return rc


def _set_stop() -> None:
    global _STOP
    _STOP = True


if __name__ == "__main__":
    raise SystemExit(main())
