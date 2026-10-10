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
    "PYTHONPATH",
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    "CICADA_HUB_IMAGE", "CICADA_BUILD_METADATA", "CICADA_EXPECT_SOURCE_FINGERPRINT", "CICADA_INTEROP_OUTPUT",
    "CICADA_CHROMIUM_IMAGE", "CICADA_BROWSER_RESULT_DIR", "CICADA_V68_EVIDENCE_ROOT",
    "CICADA_NODE_CONTROL_GOMODCACHE", "CICADA_M5_GOLANG_IMAGE", "CICADA_GOMODCACHE",
    "CICADA_NATIVE_ENV_FILE", "CICADA_NATIVE_CODEX_IMAGE", "CICADA_NATIVE_PROXY",
    "CICADA_CURRENT_BINDING_FILE", "CICADA_CURRENT_BINDING_SHA", "CICADA_COMPLETION_EVIDENCE_ROOT",
    "CICADA_COMPLETION_CHILD_RUN_ID", "CICADA_COMPLETION_CHILD_LANE", "CICADA_M5_EVIDENCE_ROOT",
    "CICADA_NODE_CONTROL_V1_ENABLED",
    "CICADA_RELEASE_ARTIFACT_DIR", "CICADA_PQTLS_STAGE", "CICADA_PQTLS_PACKAGE_DIR",
}

PYTHON_TESTS = [
    "scripts.test_build_input_inventory", "scripts.test_client_contract",
    "scripts.test_client_network_fixture", "scripts.test_client_recovery_fault_proxy",
    "scripts.test_completion_driver_status", "scripts.test_completion_runner",
    "scripts.test_group_fabric_stress_driver", "scripts.test_hub_restore_activation",
    "scripts.test_owned_fixture_cleanup",
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
    "capacity": 900, "joined-v68": 1200, "multi-hub-services": 900,
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
    reasons = []
    if before.get("complete") is not True or after.get("complete") is not True:
        reasons.append("SOURCE_IDENTITY_INCOMPLETE")
    elif unchanged is False:
        reasons.append("SOURCE_IDENTITY_CHANGED")
    return {"complete": complete, "unchanged": unchanged, "reason_codes": reasons,
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
    result = {key: value for key, value in os.environ.items() if key in SAFE_ENV and key != "PYTHONPATH"}
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result.setdefault("TMPDIR", "/tmp")
    if overrides:
        unknown = set(overrides) - SAFE_ENV
        if unknown:
            raise ValueError("child environment override is not allowlisted")
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
        proc.stdout.close()
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


def child_receipt_status(paths: list[Path], expected_run_id: str | None = None,
                         expected_lane: str | None = None,
                         expected_roles: set[str] | None = None) -> tuple[str | None, str, list[str], str | None]:
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
    if expected_lane in {"joined-v68", "hub-web-panel-browser", "group-fabric-stress"}:
        reduced = reduce_known_cleanup(data, expected_lane, latest, expected_run_id)
        return str(latest), reduced["status"], reduced["reason_codes"], status
    if not expected_run_id or not expected_lane or expected_roles is None:
        return str(latest), "UNKNOWN", ["CHILD_FIXTURE_CLEANUP_SCOPE_UNBOUND"], status
    reduced = reduce_child_cleanup(data, expected_run_id, expected_lane, expected_roles)
    if expected_lane == "node-control-v1" and reduced["status"] == "CONFIRMED":
        source_check = reduce_node_control_source(data, latest, expected_run_id)
        reduced = {"status": source_check["status"],
                   "reason_codes": reduced["reason_codes"] + source_check["reason_codes"]}
    return str(latest), reduced["status"], reduced["reason_codes"], status


def reduce_node_control_source(receipt: dict, receipt_path: Path, expected_run_id: str) -> dict:
    """Check scoped references, then compare the complete original metadata."""
    metadata = []
    for phase in ("before", "after"):
        reference = receipt.get("source_" + phase)
        if not isinstance(reference, dict):
            return {"status": "UNKNOWN", "reason_codes": ["CHILD_SOURCE_REFERENCE_MISSING"]}
        expected_scope = {"schema": "cicada.node-control-source-reference.v1",
                          "run_id": expected_run_id, "lane": "node-control-v1", "phase": phase,
                          "metadata_file": f"source-{phase}.json",
                          "binding_file": f"source-{phase}.binding.json"}
        if any(reference.get(key) != value for key, value in expected_scope.items()):
            return {"status": "UNKNOWN", "reason_codes": ["CHILD_SOURCE_SCOPE_MISMATCH"]}
        size = reference.get("size_bytes")
        if (not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 16 * 1024 * 1024
                or any(not isinstance(reference.get(key), str)
                       or not re.fullmatch(r"[0-9a-f]{64}", reference[key])
                       for key in ("sha256", "binding_sha256"))):
            return {"status": "UNKNOWN", "reason_codes": ["CHILD_SOURCE_REFERENCE_INVALID"]}
        source_path = receipt_path.parent / reference["metadata_file"]
        binding_path = receipt_path.parent / reference["binding_file"]
        try:
            if (source_path.is_symlink() or binding_path.is_symlink()
                    or not source_path.is_file() or not binding_path.is_file()
                    or source_path.stat().st_size != size or binding_path.stat().st_size > 4096):
                raise ValueError("invalid source archive")
            with source_path.open("rb") as stream:
                raw = stream.read(size + 1)
            with binding_path.open("rb") as stream:
                binding_raw = stream.read(4097)
            if (len(raw) != size or hashlib.sha256(raw).hexdigest() != reference["sha256"]
                    or len(binding_raw) > 4096
                    or hashlib.sha256(binding_raw).hexdigest() != reference["binding_sha256"]):
                raise ValueError("source archive hash mismatch")
            binding = json.loads(binding_raw)
            if binding != {key: value for key, value in reference.items()
                           if key not in {"binding_file", "binding_sha256"}}:
                raise ValueError("source archive scope mismatch")
            value = json.loads(raw)
            if not isinstance(value, dict) or not value:
                raise ValueError("invalid source metadata")
        except (OSError, ValueError):
            return {"status": "UNKNOWN", "reason_codes": ["CHILD_SOURCE_ARCHIVE_UNCONFIRMED"]}
        metadata.append(value)
    if metadata[0] != metadata[1]:
        return {"status": "FAILED", "reason_codes": ["CHILD_SOURCE_INPUTS_CHANGED"]}
    return {"status": "CONFIRMED", "reason_codes": ["CHILD_SOURCE_FULL_METADATA_UNCHANGED"]}


CHILD_CLEANUP_SCHEMA = "cicada.child-cleanup.v1"
CHILD_CLEANUP_ROLES = {
    "client": {"hub", "test", "hub-image", "test-image"},
    "network-m1": {"hub", "test", "hub-image", "test-image"},
    "group-spaces-m2": {"hub", "test", "hub-image", "test-image"},
    "capacity": {"hub", "test", "hub-image", "test-image"},
    "multi-hub-services": {"test"},
    "node-control-v1": {"test"},
}
CHILD_CLEANUP_KINDS = {
    "hub": "container", "test": "container",
    "hub-image": "image", "test-image": "image",
}


def _known_resource_absence(kind: str, reference: str, deadline: float) -> str:
    """Read-only, exact-target Docker check; no cleanup is ever performed here."""
    remaining = deadline - time.monotonic()
    if remaining <= 0 or len(reference) > 255 or not reference or "\x00" in reference:
        return "UNKNOWN"
    argv = (["docker", "network", "inspect", reference]
            if kind == "network" else ["docker", "inspect", reference])
    try:
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=min(5, remaining), env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN"
    if result.returncode == 0:
        return "PRESENT"
    stdout = result.stdout.strip()
    if len(result.stdout) > 512 or len(result.stderr) > 512 or stdout not in {"", "[]"}:
        return "UNKNOWN"
    lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
    # Match Docker's fixed error prefix case-insensitively while keeping the
    # inspected object reference exact. A daemon error or a different target
    # must remain UNKNOWN.
    exact_missing = {
        f"error: no such object: {reference}",
        f"Error: No such object: {reference}",
        f"No such object: {reference}",
    }
    if kind == "network":
        exact_missing |= {
            f"error response from daemon: network {reference} not found",
            f"Error response from daemon: network {reference} not found",
            f"error: no such network: {reference}",
            f"Error: No such network: {reference}",
        }
    return ("EXACT_ABSENT" if result.returncode == 1 and len(lines) == 1
            and lines[0] in exact_missing else "UNKNOWN")


def _private_path_absent(path_text: object) -> str:
    if not isinstance(path_text, str) or not Path(path_text).is_absolute():
        return "UNKNOWN"
    try:
        Path(path_text).lstat()
    except FileNotFoundError:
        return "EXACT_ABSENT"
    except OSError:
        return "UNKNOWN"
    return "PRESENT"


def _projection_names(value: object, expected: list[str]) -> bool:
    return (isinstance(value, list) and len(value) == len(expected)
            and all(isinstance(item, str) and item and "\x00" not in item for item in value)
            and value == expected)


def reduce_known_cleanup(receipt: dict, lane: str, receipt_path: Path,
                         expected_run_id: str | None) -> dict:
    """Validate the three existing cleanup schemas by exact producer contract."""
    unknown = {"status": "UNKNOWN", "reason_codes": []}
    fail = {"status": "FAILED", "reason_codes": []}
    if lane == "joined-v68":
        if receipt.get("schema") != "cicada.v68-joined-result.v1":
            unknown["reason_codes"].append("V68_CLEANUP_SCHEMA_MISMATCH")
            return unknown
        fixture = receipt.get("owned_fixture")
        fixture_run = receipt.get("fixture_run_id")
        if not isinstance(fixture, dict) or not isinstance(fixture_run, str):
            unknown["reason_codes"].append("V68_OWNED_FIXTURE_PROJECTION_MISSING")
            return unknown
        run_id = fixture.get("run_id")
        if (run_id != fixture_run or not re.fullmatch(r"cicada-v68-[A-Za-z0-9-]{8,80}", run_id or "")
                or not _projection_names(fixture.get("containers"), [run_id + suffix for suffix in ("-hub", "-node-a", "-node-b")])
                or not _projection_names(fixture.get("networks"), [run_id + suffix for suffix in ("-node-a-net", "-node-b-net")])
                or not _projection_names(fixture.get("images"), [run_id + suffix for suffix in (":hub", ":test")])):
            unknown["reason_codes"].append("V68_OWNED_FIXTURE_PROJECTION_INVALID")
            return unknown
        scratch = fixture.get("scratch_path")
        tmp_root = Path(os.environ.get("TMPDIR") or "/tmp").resolve()
        scratch_path = Path(scratch) if isinstance(scratch, str) else Path("/")
        if (scratch_path.parent.resolve() != tmp_root
                or not re.fullmatch(r"cicada-v68-[A-Za-z0-9]{8}", scratch_path.name)):
            unknown["reason_codes"].append("V68_SCRATCH_PATH_SCOPE_INVALID")
            return unknown
        if receipt.get("cleanup_owned_containers_and_networks") is not True or receipt.get("cleanup_owned_scratch") is not True:
            if receipt.get("cleanup_owned_containers_and_networks") is False or receipt.get("cleanup_owned_scratch") is False:
                fail["reason_codes"].append("V68_PRODUCER_REPORTED_CLEANUP_FAILURE")
                return fail
            unknown["reason_codes"].append("V68_CLEANUP_PROJECTION_INCOMPLETE")
            return unknown
        resources = [("container", item) for item in fixture["containers"]]
        resources += [("network", item) for item in fixture["networks"]]
        resources += [("image", item) for item in fixture["images"]]
        scratch = str(scratch_path)
    elif lane == "hub-web-panel-browser":
        if receipt.get("schema_version") != "cicada.hub-web-panel-browser.v1":
            unknown["reason_codes"].append("BROWSER_CLEANUP_SCHEMA_MISMATCH")
            return unknown
        fixture = receipt.get("owned_fixture")
        fixture_run = receipt.get("fixture_run_id")
        if not isinstance(fixture, dict) or not isinstance(fixture_run, str):
            unknown["reason_codes"].append("BROWSER_OWNED_FIXTURE_PROJECTION_MISSING")
            return unknown
        run_id = fixture.get("run_id")
        browser_prefix = "cicada-webpanel-"
        suffix = run_id[len(browser_prefix):] if isinstance(run_id, str) and run_id.startswith(browser_prefix) else ""
        expected_containers = [browser_prefix + suffix + suffix_name
                               for suffix_name in ("-hub", "-chromium", "-node", "-node-2")]
        if (run_id != fixture_run or not suffix
                or not _projection_names(fixture.get("containers"), expected_containers)
                or not _projection_names(fixture.get("networks"), [browser_prefix + suffix + "-net"])
                or not _projection_names(fixture.get("images"), [])):
            unknown["reason_codes"].append("BROWSER_OWNED_FIXTURE_PROJECTION_INVALID")
            return unknown
        expected_scratch = receipt_path.parent / "fixture"
        scratch_path = fixture.get("scratch_path")
        if (not isinstance(scratch_path, str)
                or Path(os.path.abspath(scratch_path)) != Path(os.path.abspath(expected_scratch))):
            unknown["reason_codes"].append("BROWSER_SCRATCH_PATH_SCOPE_INVALID")
            return unknown
        cleanup = receipt.get("fixture_cleanup")
        expected_fields = ("hub_container_removed", "chromium_container_removed", "docker_network_removed",
                           "fixture_directory_removed", "node_container_removed", "second_node_container_removed")
        if not isinstance(cleanup, dict):
            unknown["reason_codes"].append("BROWSER_CLEANUP_PROJECTION_MISSING")
            return unknown
        if cleanup.get("status") == "FAIL" or any(cleanup.get(key) is False for key in expected_fields):
            fail["reason_codes"].append("BROWSER_PRODUCER_REPORTED_CLEANUP_FAILURE")
            return fail
        if cleanup.get("status") != "PASS" or any(cleanup.get(key) is not True for key in expected_fields):
            unknown["reason_codes"].append("BROWSER_CLEANUP_PROJECTION_INCOMPLETE")
            return unknown
        resources = [("container", item) for item in fixture["containers"]]
        resources += [("network", item) for item in fixture["networks"]]
        scratch = scratch_path
    elif lane == "group-fabric-stress":
        if receipt.get("schema") != "cicada.v01.group-fabric-stress-run.v1":
            unknown["reason_codes"].append("STRESS_CLEANUP_SCHEMA_MISMATCH")
            return unknown
        if not isinstance(expected_run_id, str) or receipt_path.parent.name != expected_run_id:
            unknown["reason_codes"].append("STRESS_EVIDENCE_ROOT_UNBOUND")
            return unknown
        security = receipt.get("security_envelope")
        labels = security.get("owner_labels") if isinstance(security, dict) else None
        if not isinstance(expected_run_id, str) or labels != {
                "cicada.acceptance.task": "cicada.v01.group-fabric-stress",
                "cicada.acceptance.run": expected_run_id}:
            unknown["reason_codes"].append("STRESS_RUN_OWNERSHIP_UNBOUND")
            return unknown
        builder = receipt.get("builder")
        workloads = receipt.get("workloads")
        if not isinstance(builder, dict) or not isinstance(workloads, list) or len(workloads) != 4:
            unknown["reason_codes"].append("STRESS_CLEANUP_ROWS_MISSING")
            return unknown
        rows = [builder, *workloads]
        if any(not isinstance(item.get("cid"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["cid"])
               for item in rows):
            unknown["reason_codes"].append("STRESS_CLEANUP_CID_MISSING")
            return unknown
        ids = [item["cid"] for item in rows]
        if len(set(ids)) != len(ids):
            unknown["reason_codes"].append("STRESS_CLEANUP_CID_DUPLICATE")
            return unknown
        if any(item.get("cleanup_confirmed") is False for item in rows):
            fail["reason_codes"].append("STRESS_PRODUCER_REPORTED_CLEANUP_FAILURE")
            return fail
        if any(item.get("cleanup_confirmed") is not True for item in rows):
            unknown["reason_codes"].append("STRESS_CLEANUP_NOT_CONFIRMED")
            return unknown
        emergency = receipt.get("emergency_cleanup")
        if not isinstance(emergency, list) or len(emergency) > 5 or any(
                not isinstance(item, dict) or not isinstance(item.get("cid"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["cid"])
                for item in emergency):
            unknown["reason_codes"].append("STRESS_EMERGENCY_CLEANUP_INVALID")
            return unknown
        if any(item.get("confirmed") is False for item in emergency):
            fail["reason_codes"].append("STRESS_EMERGENCY_CLEANUP_FAILED")
            return fail
        if any(item.get("confirmed") is not True for item in emergency):
            unknown["reason_codes"].append("STRESS_EMERGENCY_CLEANUP_UNKNOWN")
            return unknown
        ids.extend(item["cid"] for item in emergency)
        resources = [("container", item) for item in sorted(set(ids))]
        scratch = None
    else:
        unknown["reason_codes"].append("CHILD_FIXTURE_CLEANUP_SCOPE_UNBOUND")
        return unknown

    deadline = time.monotonic() + 30
    for kind, reference in resources:
        state = _known_resource_absence(kind, reference, deadline)
        if state == "PRESENT":
            fail["reason_codes"].append("KNOWN_FIXTURE_RESOURCE_REMAINS")
            return fail
        if state != "EXACT_ABSENT":
            unknown["reason_codes"].append("KNOWN_FIXTURE_RESOURCE_ABSENCE_UNCONFIRMED")
            return unknown
    if scratch is not None:
        state = _private_path_absent(scratch)
        if state == "PRESENT":
            fail["reason_codes"].append("KNOWN_FIXTURE_SCRATCH_REMAINS")
            return fail
        if state != "EXACT_ABSENT":
            unknown["reason_codes"].append("KNOWN_FIXTURE_SCRATCH_ABSENCE_UNCONFIRMED")
            return unknown
    return {"status": "CONFIRMED", "reason_codes": ["KNOWN_PRODUCER_CLEANUP_AND_EXACT_ABSENCE_CONFIRMED"]}


def reduce_child_cleanup(receipt: dict, expected_run_id: str, expected_lane: str,
                         expected_roles: set[str]) -> dict:
    """Validate the child cleanup contract without inferring cleanup from exit 0."""
    unknown = {"status": "UNKNOWN", "reason_codes": []}
    fail = {"status": "FAILED", "reason_codes": []}
    if not isinstance(receipt, dict):
        unknown["reason_codes"].append("CLEANUP_RECEIPT_INVALID")
        return unknown
    cleanup = receipt.get("fixture_cleanup")
    resources = cleanup.get("resources") if isinstance(cleanup, dict) else None
    if not isinstance(cleanup, dict) or not isinstance(resources, list):
        unknown["reason_codes"].append("CLEANUP_RESOURCES_MISSING")
        return unknown
    if cleanup.get("schema") != CHILD_CLEANUP_SCHEMA:
        unknown["reason_codes"].append("CLEANUP_SCHEMA_MISMATCH")
        return unknown
    if (cleanup.get("run_id") != expected_run_id or cleanup.get("lane") != expected_lane
            or receipt.get("run_id", expected_run_id) != expected_run_id
            or receipt.get("lane", expected_lane) != expected_lane):
        unknown["reason_codes"].append("CLEANUP_INVOCATION_BINDING_MISMATCH")
        return unknown
    if cleanup.get("status") == "FAILED" or receipt.get("fixture_cleanup_status") == "FAILED":
        fail["reason_codes"].append("CHILD_CLEANUP_FAILED")
        return fail
    if (cleanup.get("status") != "CONFIRMED"
            or receipt.get("fixture_cleanup_status") != "CONFIRMED"
            or receipt.get("cleanup_owned_resources") is not True):
        unknown["reason_codes"].append("CHILD_CLEANUP_NOT_CONFIRMED")
        return unknown
    found = {}
    for item in resources:
        if not isinstance(item, dict) or not isinstance(item.get("role"), str):
            unknown["reason_codes"].append("CLEANUP_RESOURCE_ROW_INVALID")
            return unknown
        role = item["role"]
        if role in found:
            unknown["reason_codes"].append("CLEANUP_RESOURCE_ROLE_DUPLICATE")
            return unknown
        found[role] = item
    if set(found) != set(expected_roles):
        unknown["reason_codes"].append("CLEANUP_RESOURCE_ROLE_SET_MISMATCH")
        return unknown
    scratch = cleanup.get("scratch")
    if not isinstance(scratch, dict) or scratch.get("role") != "private-scratch":
        unknown["reason_codes"].append("CLEANUP_SCRATCH_MISSING")
        return unknown
    scratch_path = scratch.get("path")
    scratch_device = scratch.get("device")
    scratch_inode = scratch.get("inode")
    scratch_uid = scratch.get("uid")
    if (not isinstance(scratch_path, str) or not Path(scratch_path).is_absolute()
            or scratch.get("creation_proof") != "MKDTEMP_INODE"
            or scratch.get("ownership") not in {"VERIFIED", "MISMATCH", "UNKNOWN"}
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 0
                   for value in (scratch_device, scratch_inode, scratch_uid))
            or scratch_inode == 0
            or scratch.get("post_cleanup") not in {"EXACT_ABSENT", "PRESENT", "UNKNOWN"}):
        unknown["reason_codes"].append("CLEANUP_SCRATCH_UNBOUND")
        return unknown
    if scratch["post_cleanup"] == "PRESENT" and scratch["ownership"] == "VERIFIED":
        fail["reason_codes"].append("CLEANUP_SCRATCH_REMAINS")
        return fail
    if scratch["ownership"] != "VERIFIED" or scratch_uid != os.getuid():
        unknown["reason_codes"].append("CLEANUP_SCRATCH_OWNERSHIP_UNCONFIRMED")
        return unknown
    if scratch["post_cleanup"] != "EXACT_ABSENT":
        unknown["reason_codes"].append("CLEANUP_SCRATCH_ABSENCE_UNCONFIRMED")
        return unknown
    for role, item in found.items():
        kind = item.get("kind")
        if kind not in {"container", "image"}:
            unknown["reason_codes"].append("CLEANUP_RESOURCE_KIND_INVALID")
            return unknown
        if CHILD_CLEANUP_KINDS.get(role) != kind:
            unknown["reason_codes"].append("CLEANUP_RESOURCE_ROLE_KIND_MISMATCH")
            return unknown
        resource_id = item.get("id")
        name = item.get("name_or_ref")
        pre = item.get("pre_creation")
        post = item.get("post_cleanup")
        proof = item.get("creation_proof")
        ownership = item.get("ownership")
        if post == "PRESENT" or ownership == "MISMATCH":
            fail["reason_codes"].append("CLEANUP_RESOURCE_REMAINS_OR_MISMATCH")
            return fail
        if pre != "EXACT_ABSENT":
            unknown["reason_codes"].append("CLEANUP_RESOURCE_PRECREATION_UNCONFIRMED")
            return unknown
        if not isinstance(name, str) or not name or "\x00" in name:
            unknown["reason_codes"].append("CLEANUP_RESOURCE_NAME_INVALID")
            return unknown
        if post != "EXACT_ABSENT":
            unknown["reason_codes"].append("CLEANUP_RESOURCE_ABSENCE_UNCONFIRMED")
            return unknown
        if proof == "NOT_CREATED" and ownership == "NOT_CREATED" and resource_id is None:
            expected_labels = ({"org.cicada.test.run": expected_run_id,
                                "org.cicada.test.role": role}
                               if kind == "container" else {})
            if (item.get("labels_observed") not in ({}, None)
                    or item.get("labels_intended") != expected_labels):
                unknown["reason_codes"].append("CLEANUP_NOT_CREATED_HAS_OBSERVED_LABELS")
                return unknown
            if kind == "image" and item.get("expected_image_id") not in (None,):
                unknown["reason_codes"].append("CLEANUP_NOT_CREATED_IMAGE_HAS_EXPECTED_ID")
                return unknown
            continue
        if kind == "container":
            if (not isinstance(resource_id, str) or not re.fullmatch(r"[0-9a-f]{64}", resource_id)
                    or proof != "CIDFILE" or ownership != "VERIFIED"):
                unknown["reason_codes"].append("CLEANUP_CONTAINER_OWNERSHIP_UNCONFIRMED")
                return unknown
            expected_image = item.get("expected_image_id")
            if not isinstance(expected_image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image):
                unknown["reason_codes"].append("CLEANUP_CONTAINER_IMAGE_UNBOUND")
                return unknown
            labels = item.get("labels_observed")
            expected_labels = {"org.cicada.test.run": expected_run_id,
                               "org.cicada.test.role": role}
            if labels != expected_labels or item.get("labels_intended") != expected_labels:
                unknown["reason_codes"].append("CLEANUP_CONTAINER_LABELS_UNCONFIRMED")
                return unknown
        else:
            if (not isinstance(resource_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", resource_id)
                    or proof != "FRESH_TAG" or ownership != "VERIFIED"
                    or item.get("expected_image_id") != resource_id):
                unknown["reason_codes"].append("CLEANUP_IMAGE_OWNERSHIP_UNCONFIRMED")
                return unknown
            if item.get("labels_observed") not in ({}, None):
                unknown["reason_codes"].append("CLEANUP_IMAGE_LABELS_UNEXPECTED")
                return unknown
            if item.get("labels_intended") not in ({}, None):
                unknown["reason_codes"].append("CLEANUP_IMAGE_LABELS_UNEXPECTED")
                return unknown
    return {"status": "CONFIRMED", "reason_codes": ["EXACT_CHILD_CLEANUP_CONFIRMED"]}


def _unittest_counts(log_path: Path) -> dict:
    counts = {"tests_run": 0, "failures": 0, "errors": 0, "skips": 0, "footer_present": False}
    try:
        if log_path.stat().st_size > MAX_LOG_BYTES:
            return counts
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return counts
    match = re.search(r"^Ran (\d+) tests? in [^\n]+$", text, re.MULTILINE)
    if not match:
        return counts
    counts["tests_run"] = int(match.group(1))
    counts["footer_present"] = True
    summary = re.search(r"^FAILED \(([^)]*)\)$", text, re.MULTILINE)
    if summary:
        for key, token in (("failures", "failures"), ("errors", "errors"), ("skips", "skipped")):
            found = re.search(rf"(?:^|, )({token})=(\d+)", summary.group(1))
            if found:
                counts[key] = int(found.group(2))
    else:
        ok = re.search(r"^OK(?: \(skipped=(\d+)\))?$", text, re.MULTILINE)
        if ok and ok.group(1):
            counts["skips"] = int(ok.group(1))
    return counts


def run_python_module(module: str, log_path: Path, deadline: float, env: dict) -> dict:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", module):
        return {"module": module, "status": "BLOCKED", "reason_codes": ["PYTHON_MODULE_NAME_INVALID"]}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"module": module, "status": "NOT_RUN", "reason_codes": ["PYTHON_LANE_BUDGET_EXHAUSTED"]}
    started = now()
    proc = run_process(["python3", "-B", "-m", "unittest", "-q", module], log_path=log_path,
                       timeout=max(1, int(remaining)), env=env)
    counts = _unittest_counts(log_path)
    if proc.get("spawn_error"):
        status, reasons = "BLOCKED", [proc["spawn_error"]]
    elif (proc.get("timed_out") or proc.get("interrupted") or proc.get("log_bound_exceeded")
          or not proc.get("process_exit_confirmed") or not proc.get("process_group_cleanup_confirmed")
          or proc.get("pipe_eof_observed") is not True):
        status, reasons = "UNKNOWN", ["PYTHON_CHILD_NOT_CLEANLY_OBSERVED"]
    elif proc.get("exit_code") != 0:
        status, reasons = "FAIL", ["PYTHON_MODULE_NONZERO_EXIT"]
    elif not counts["footer_present"] or counts["tests_run"] == 0:
        status, reasons = "UNKNOWN", ["PYTHON_UNITTEST_SUMMARY_MISSING"]
    elif counts["failures"] or counts["errors"]:
        status, reasons = "FAIL", ["PYTHON_UNITTEST_FAILURES"]
    elif counts["skips"]:
        status, reasons = "PASS_WITH_SKIPS", ["PYTHON_OPTIONAL_TESTS_SKIPPED"]
    else:
        status, reasons = "PASS", []
    return {"module": module, "status": status, "reason_codes": reasons,
            "exit_code": proc.get("exit_code"), "started_at": started,
            "duration_seconds": proc.get("duration_seconds"), "log_path": str(log_path),
            "log_sha256": file_sha(log_path) if log_path.exists() else None,
            "process_exit_confirmed": proc.get("process_exit_confirmed"),
            "process_group_cleanup_confirmed": proc.get("process_group_cleanup_confirmed"),
            "timed_out": proc.get("timed_out"), "interrupted": proc.get("interrupted"),
            "log_bound_exceeded": proc.get("log_bound_exceeded"),
            "log_bytes_retained": proc.get("log_bytes_retained"),
            "pipe_eof_observed": proc.get("pipe_eof_observed"), **counts}


def run_python_modules(modules: list[str], run_dir: Path, timeout: int, env: dict) -> dict:
    deadline = time.monotonic() + timeout
    records = []
    for index, module in enumerate(modules):
        if _STOP or deadline - time.monotonic() <= 0:
            records.extend({"module": remaining, "status": "NOT_RUN",
                            "reason_codes": ["PYTHON_LANE_INTERRUPTED_OR_BUDGET_EXHAUSTED"]}
                           for remaining in modules[index:])
            break
        log = run_dir / "logs" / "python" / f"{index:02d}-{module.replace('.', '_')}.log"
        records.append(run_python_module(module, log, deadline, env))
    totals = {key: sum(int(record.get(key, 0) or 0) for record in records)
              for key in ("tests_run", "failures", "errors", "skips")}
    states = {record.get("status") for record in records}
    if "FAIL" in states:
        status = "FAIL"
    elif "UNKNOWN" in states:
        status = "UNKNOWN"
    elif "BLOCKED" in states:
        status = "BLOCKED"
    elif "NOT_RUN" in states or len(records) != len(modules):
        status = "UNKNOWN"
    elif "PASS_WITH_SKIPS" in states:
        status = "PASS_WITH_SKIPS"
    elif states == {"PASS"} and totals["tests_run"] > 0:
        status = "PASS"
    else:
        status = "UNKNOWN"
    return {"status": status, "modules": records, "modules_requested": len(modules),
            "modules_completed": sum(record.get("status") not in {"NOT_RUN", "BLOCKED"} for record in records),
            **totals}


def classification(run: dict, log: Path, lane: str, receipt_paths: list[Path] | None = None,
                   cleanup_required: bool = False, expected_run_id: str | None = None,
                   expected_lane: str | None = None,
                   expected_roles: set[str] | None = None) -> tuple[str, list[str]]:
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
        receipt_path, cleanup, receipt_codes, receipt_status = child_receipt_status(
            receipt_paths, expected_run_id, expected_lane, expected_roles)
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


GO_PUBLIC_METADATA = (
    "VERSION",
    "docs/client-hub-wire-v1.md",
    "docs/client-hub-v1.openapi.yaml",
    ".agents/plugins/cicada/plugin.json",
    ".agents/plugins/cicada/.codex-plugin/plugin.json",
)


def _regular_source_file(relative: str) -> Path:
    candidate = ROOT / relative
    current = ROOT
    for part in Path(relative).parts:
        current = current / part
        info = current.lstat()
        if current.is_symlink():
            raise ValueError("source metadata path contains a symlink")
    if not candidate.is_file():
        raise ValueError("source metadata path is not a regular file")
    return candidate


def stage_go_metadata(go_root: Path) -> dict:
    """Stage only the public root metadata needed by the Go source tree."""
    public_root = go_root / "public-root"
    source_mount = public_root / "cicada-go"
    rows = []
    try:
        public_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        for relative in GO_PUBLIC_METADATA:
            source = _regular_source_file(relative)
            info = source.stat()
            target = public_root / relative
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with source.open("rb") as src, target.open("xb") as dst:
                os.chmod(target, info.st_mode & 0o777)
                digest = hashlib.sha256()
                size = 0
                while True:
                    block = src.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    dst.write(block)
                    size += len(block)
                dst.flush()
                os.fsync(dst.fileno())
            if size != info.st_size:
                raise OSError("metadata source changed while staging")
            rows.append({"path": relative, "sha256": digest.hexdigest(), "bytes": size,
                         "mode": info.st_mode & 0o777})
        source_mount.mkdir(mode=0o755)
        return {"complete": True, "source_root": str(ROOT), "metadata_root": str(public_root),
                "source_mountpoint": str(source_mount), "rows": rows, "reason_codes": []}
    except (OSError, ValueError) as error:
        return {"complete": False, "source_root": str(ROOT), "metadata_root": str(public_root),
                "source_mountpoint": str(source_mount), "rows": rows,
                "reason_codes": ["GO_METADATA_STAGE_" + type(error).__name__]}


def verify_go_envelope(projection: dict, expected: dict) -> tuple[bool, str]:
    """Compare a closed Docker projection with the fixed Go-lane policy."""
    scalar_keys = ("image_ref", "user", "network", "readonly_root", "nano_cpus",
                   "memory_bytes", "pids_limit", "cap_add", "cap_drop", "env", "workdir")
    for key in scalar_keys:
        if projection.get(key) != expected.get(key):
            return False, "GO_ENVELOPE_" + key.upper() + "_MISMATCH"
    security = projection.get("security_opt")
    if not no_new_privileges_enabled(security):
        return False, "GO_ENVELOPE_NO_NEW_PRIVILEGES_MISMATCH"
    mounts = projection.get("mounts")
    expected_mounts = expected.get("mounts")
    if not isinstance(mounts, list) or not isinstance(expected_mounts, list):
        return False, "GO_ENVELOPE_MOUNTS_MISSING"
    def mount_tuple(item: object) -> tuple | None:
        if not isinstance(item, dict):
            return None
        return (item.get("source"), item.get("destination"), item.get("type"), item.get("rw"))
    actual_rows = [mount_tuple(item) for item in mounts]
    expected_rows = [mount_tuple(item) for item in expected_mounts]
    if (None in actual_rows or len(set(actual_rows)) != len(actual_rows)
            or len(actual_rows) != len(expected_rows) or set(actual_rows) != set(expected_rows)):
        return False, "GO_ENVELOPE_MOUNT_SET_MISMATCH"
    tmpfs = projection.get("tmpfs")
    required_tmpfs = expected.get("tmpfs")
    if not isinstance(tmpfs, dict) or not isinstance(required_tmpfs, dict):
        return False, "GO_ENVELOPE_TMPFS_MISSING"
    actual_options = set(str(tmpfs.get("/tmp", "")).split(","))
    required_options = set(required_tmpfs.get("/tmp", []))
    actual_options = {"size=128m" if value == "size=134217728" else value for value in actual_options}
    if required_options != actual_options:
        return False, "GO_ENVELOPE_TMPFS_OPTIONS_MISMATCH"
    if "tmp_identity" in expected and projection.get("tmp_identity") != expected.get("tmp_identity"):
        return False, "GO_ENVELOPE_TMP_IDENTITY_MISMATCH"
    return True, "GO_ENVELOPE_MATCH"


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
    staged = stage_go_metadata(go_root)
    if not staged.get("complete"):
        return {"status": "BLOCKED", "note": "public root metadata could not be staged exactly",
                "exit_code": None, "metadata_stage": staged}
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
printf '%s|%s|%s\n' "$TMPDIR" "$GOTMPDIR" "$(stat -c '%u:%g:%a' /tmp 2>/dev/null)" > /out/preflight.txt
if [ "$TMPDIR" != "/t" ] || [ "$GOTMPDIR" != "/t" ] || [ "$(stat -c '%u:%g:%a' /tmp 2>/dev/null)" != "0:0:1777" ]; then
  printf '{"preflight":1,"gofmt":125,"build":125,"test":125,"vet":125}\n' > /out/phase-exits.json
  exit 125
fi
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
printf '{"preflight":0,"gofmt":%s,"build":%s,"test":%s,"vet":%s}\n' "$fmt_rc" "$build_rc" "$test_rc" "$vet_rc" > /out/phase-exits.json
chmod 600 /out/* 2>/dev/null
if [ -f /out/output-bound-exceeded ]; then exit 124; fi
if [ "$fmt_rc" -eq 0 ] && [ ! -s /out/gofmt-files.txt ] && [ "$build_rc" -eq 0 ] && [ "$test_rc" -eq 0 ] && [ "$vet_rc" -eq 0 ]; then exit 0; else exit 1; fi'''
    argv = ["docker", "create", "--name", container_name,
            "--label", "cicada.acceptance.task=architecture-v2-completion-go",
            "--label", f"cicada.acceptance.run={run_id}",
            "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "3g", "--pids-limit", "256",
            "--mount", f"type=bind,src={go_root / 'public-root'},dst=/repo,readonly",
            "--mount", f"type=bind,src={ROOT / 'cicada-go'},dst=/repo/cicada-go,readonly",
            "--mount", f"type=bind,src={module_cache},dst=/gomod,readonly",
            "--mount", f"type=bind,src={go_root / 'cache'},dst=/gocache",
            "--mount", f"type=bind,src={go_root / 'tmp'},dst=/t",
            "--mount", f"type=bind,src={out},dst=/out",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=0,gid=0,mode=1777", "--workdir", "/repo/cicada-go",
            "--env", "GOTOOLCHAIN=local", "--env", "GOPROXY=off", "--env", "GOSUMDB=off",
            "--env", "GOMODCACHE=/gomod", "--env", "GOCACHE=/gocache",
            "--env", "GOTMPDIR=/t", "--env", "TMPDIR=/t",
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
            "{{.Id}}|{{.Config.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .Mounts}}|{{json .HostConfig.Tmpfs}}|{{json .Config.Env}}|{{.Config.WorkingDir}}|{{index .Config.Labels \"cicada.acceptance.run\"}}|{{index .Config.Labels \"cicada.acceptance.task\"}}", cid],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=remaining(20), env=safe_child_env())
    except (OSError, subprocess.TimeoutExpired, TimeoutError):
        cleanup = remove_exact_go_container(cid, run_id)
        return {"status": "UNKNOWN", "note": "created Go container could not be inspected within its lane",
                "exit_code": None, "container_id": cid,
                "fixture_cleanup_status": "CONFIRMED" if cleanup else "UNKNOWN"}
    expected_prefix = [cid, GO_IMAGE, f"{os.getuid()}:{os.getgid()}", "none", "true", "2000000000", "3221225472", "256"]
    fields = projection.stdout.strip().split("|", 16) if projection.returncode == 0 else []
    valid = len(fields) == 17 and fields[:8] == expected_prefix and fields[15] == run_id and fields[16] == GO_TASK_LABEL
    env_projection = {}
    projected = {}
    expected = {}
    if valid:
        try:
            cap_add = json.loads(fields[8]) or []
            caps = json.loads(fields[9]); security = json.loads(fields[10]); mounts = json.loads(fields[11])
            tmpfs = json.loads(fields[12]); raw_env = json.loads(fields[13])
            if not isinstance(raw_env, list):
                raise ValueError("container environment projection is not a list")
            all_env = dict(item.split("=", 1) for item in raw_env if isinstance(item, str) and "=" in item)
            env_names = ("GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOMODCACHE", "GOCACHE", "GOTMPDIR", "TMPDIR")
            env_projection = {key: all_env[key] for key in env_names if key in all_env}
            valid = cap_add == [] and caps == ["ALL"] and no_new_privileges_enabled(security)
            expected_mounts = {
                (str(go_root / "public-root"), "/repo", "bind", False),
                (str(ROOT / "cicada-go"), "/repo/cicada-go", "bind", False),
                (str(module_cache), "/gomod", "bind", False),
                (str(go_root / "cache"), "/gocache", "bind", True),
                (str(go_root / "tmp"), "/t", "bind", True),
                (str(out), "/out", "bind", True),
            }
            mount_projection = [{"source": item.get("Source"), "destination": item.get("Destination"),
                                 "type": item.get("Type"), "rw": item.get("RW")} for item in mounts]
            expected_mount_projection = [{"source": source, "destination": destination,
                                          "type": kind, "rw": rw}
                                         for source, destination, kind, rw in sorted(expected_mounts)]
            tmp_options = set(tmpfs.get("/tmp", "").split(",")) if isinstance(tmpfs, dict) else set()
            projected = {"image_ref": fields[1], "user": fields[2], "network": fields[3],
                         "readonly_root": fields[4] == "true", "nano_cpus": int(fields[5]),
                         "memory_bytes": int(fields[6]), "pids_limit": int(fields[7]),
                         "cap_add": cap_add, "cap_drop": caps, "security_opt": security,
                         "mounts": mount_projection, "tmpfs": tmpfs, "env": env_projection,
                         "workdir": fields[14]}
            expected = {"image_ref": GO_IMAGE, "user": f"{os.getuid()}:{os.getgid()}",
                        "network": "none", "readonly_root": True, "nano_cpus": 2_000_000_000,
                        "memory_bytes": 3 * 1024 * 1024 * 1024, "pids_limit": 256,
                        "cap_add": [], "cap_drop": ["ALL"], "security_opt": security,
                        "mounts": expected_mount_projection,
                        "tmpfs": {"/tmp": ["rw", "nosuid", "nodev", "size=128m", "uid=0", "gid=0", "mode=1777"]},
                        "env": {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
                                "GOMODCACHE": "/gomod", "GOCACHE": "/gocache",
                                "GOTMPDIR": "/t", "TMPDIR": "/t"},
                        "workdir": "/repo/cicada-go"}
            valid, envelope_reason = verify_go_envelope(projected, expected)
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
        "tmpfs": json.loads(fields[12]), "env": env_projection, "workdir": fields[14],
        "run_label": run_id, "task_label": fields[16], "metadata_stage": staged}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
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
    preflight_fields = []
    preflight_path = out / "preflight.txt"
    if preflight_path.exists() and preflight_path.stat().st_size <= 1024:
        try:
            preflight_fields = preflight_path.read_text(encoding="ascii").strip().split("|", 2)
        except (OSError, UnicodeError):
            preflight_fields = []
    preflight_valid = (preflight_fields == ["/t", "/t", "0:0:1777"])
    if valid and preflight_valid:
        runtime_projection = dict(projected, tmp_identity=preflight_fields[2])
        runtime_expected = dict(expected, tmp_identity="0:0:1777")
        valid, _ = verify_go_envelope(runtime_projection, runtime_expected)
    state = wait.stdout.strip().split("|", 1) if wait and wait.returncode == 0 else []
    if interrupted or timed_out or started_info.get("log_bound_exceeded") or (out / "output-bound-exceeded").exists() or not started_info.get("process_exit_confirmed") or not started_info.get("process_group_cleanup_confirmed") or not cleanup or len(state) != 2:
        status = "UNKNOWN"
    elif state[0] != "0" or not preflight_valid or not valid or counts["package_pass"] + counts["package_fail"] == 0 or counts["test_pass"] + counts["test_fail"] + counts["test_skip"] == 0 or counts["test_fail"] or counts["package_fail"] or not phase_codes or any(phase_codes.get(k) != 0 for k in ("preflight", "gofmt", "build", "test", "vet")):
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
            "envelope_verified": valid, "runtime_preflight": {
                "tmpdir": preflight_fields[0] if len(preflight_fields) == 3 else None,
                "gotmpdir": preflight_fields[1] if len(preflight_fields) == 3 else None,
                "tmp_identity": preflight_fields[2] if len(preflight_fields) == 3 else None,
                "passed": preflight_valid}, "metadata_stage": staged}


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


def make_lanes(run_dir: Path, run_id: str, flags: dict, docker_ok: bool) -> list[dict]:
    lanes: list[dict] = []
    def add(name: str, kind: str, argv: list[str] | None = None, note: str = "",
            env: dict[str, str] | None = None, receipt_paths: list[Path] | None = None,
            cleanup_required: bool = False, child_lane: str | None = None,
            expected_roles: set[str] | None = None, cleanup_run_id: str | None = None):
        lanes.append({"name": name, "kind": kind, "argv": argv, "note": note,
                      "env": env or {}, "receipt_paths": receipt_paths or [],
                      "cleanup_required": cleanup_required,
                      "child_lane": child_lane,
                      "expected_roles": expected_roles,
                      "cleanup_run_id": run_id if cleanup_run_id is None else cleanup_run_id,
                      "timeout_seconds": LANE_TIMEOUTS.get(name, 600)})

    add("go-build-test-vet", "go")
    add("python-unittests", "python-modules",
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
                env={"CICADA_INTEROP_OUTPUT": str(output),
                     "CICADA_COMPLETION_CHILD_RUN_ID": run_id,
                     "CICADA_COMPLETION_CHILD_LANE": suite},
                receipt_paths=[output / "result.json"], cleanup_required=True,
                child_lane=suite, expected_roles=CHILD_CLEANUP_ROLES[suite])
        add("joined-v68", "command", ["bash", "scripts/test-joined-v68-docker.sh"],
            env={"CICADA_V68_EVIDENCE_ROOT": str(run_dir / "v68")}, receipt_paths=[run_dir / "v68"],
            cleanup_required=True, child_lane="joined-v68")
        m5_dir = run_dir / "multi-hub-services"
        add("multi-hub-services", "command", ["bash", "scripts/test-multi-hub-services.sh"],
            env={"CICADA_M5_EVIDENCE_ROOT": str(m5_dir),
                 "CICADA_COMPLETION_CHILD_RUN_ID": run_id,
                 "CICADA_COMPLETION_CHILD_LANE": "multi-hub-services"},
            receipt_paths=[m5_dir / "result.json"], cleanup_required=True,
            child_lane="multi-hub-services", expected_roles=CHILD_CLEANUP_ROLES["multi-hub-services"])
        add("node-control-v1", "command", ["python3", "-B", "scripts/test-node-control-v1-flow.py", "--run",
            "--output-dir", str(run_dir / "node-control")],
            receipt_paths=[run_dir / "node-control"], cleanup_required=True,
            child_lane="node-control-v1", expected_roles=CHILD_CLEANUP_ROLES["node-control-v1"],
            env={"CICADA_NODE_CONTROL_V1_ENABLED": "1",
                 "CICADA_COMPLETION_CHILD_RUN_ID": run_id,
                 "CICADA_COMPLETION_CHILD_LANE": "node-control-v1"})
    else:
        for lane in ("client-interop", "network-m1", "group-spaces-m2", "capacity", "joined-v68", "multi-hub-services", "node-control-v1"):
            add(lane, "blocked", note="Docker daemon unavailable; disposable child not started")
    protected = os.environ.get("CICADA_COMPLETION_PROTECTED_RESIDENTS_FILE")
    if docker_ok:
        stress_root = DATA / f"completion-stress-{run_dir.name}"
        add("group-fabric-stress", "stress", note=f"protected snapshot destination: {run_dir / 'protected-residents.json'}",
            receipt_paths=[stress_root / "RUN.NONAUTH.json"], cleanup_required=True,
            child_lane="group-fabric-stress", cleanup_run_id=stress_root.name)
    else:
        add("group-fabric-stress", "blocked", note="Docker daemon unavailable")
    browser_vars = ("CICADA_HUB_IMAGE", "CICADA_BUILD_METADATA", "CICADA_EXPECT_SOURCE_FINGERPRINT")
    if all(os.environ.get(key) for key in browser_vars) and docker_ok and shutil.which("node"):
        add("hub-web-browser", "command", ["node", "scripts/test-hub-web-panel-browser.mjs"],
            env={"CICADA_BROWSER_RESULT_DIR": str(run_dir / "browser")},
            receipt_paths=[run_dir / "browser" / "result.json"], cleanup_required=True,
            child_lane="hub-web-panel-browser")
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
        lanes = make_lanes(run_dir, run_id, flags, docker_ok)
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
            elif lane["kind"] == "python-modules":
                info = run_python_modules(PYTHON_TESTS, run_dir,
                    min(lane["timeout_seconds"], int(available)), safe_child_env(lane["env"]))
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
                        status, codes = classification(proc_info, log, lane["name"], lane["receipt_paths"],
                            lane.get("cleanup_required", False), lane.get("cleanup_run_id", run_id),
                            lane.get("child_lane"), lane.get("expected_roles"))
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
                                                lane.get("cleanup_required", False), lane.get("cleanup_run_id", run_id),
                                                lane.get("child_lane"), lane.get("expected_roles"))
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
