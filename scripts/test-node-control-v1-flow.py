#!/usr/bin/env python3
"""Run the disposable Node-Control v1 HTTP protocol fixture in pinned Go.

The fixture owns its Hub, Owner/Client/Node identities, SQLite state, and
loopback listener. The default no-argument invocation records NOT_RUN unless
the caller explicitly sets CICADA_NODE_CONTROL_V1_ENABLED=1. It exercises
production HTTP handlers and wire cryptography only; no Node agent, model, or
native Runtime is started.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

import owned_fixture_cleanup as owned_cleanup


GO_IMAGE = (
    "golang:1.27.1-bookworm@sha256:"
    "69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
)
TEST_NAME = "TestNodeControlV1HTTPProtocolFlow"
TEST_SELECTOR = "^" + TEST_NAME + "$"
SCHEMA = "cicada.node-control-v1-http-flow.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, timeout: int = 30, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=capture, check=False, timeout=timeout)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def read_source_info(repo: Path, output: Path) -> tuple[int, dict | None, str]:
    command = [str(repo / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(output)]
    result = run(command, timeout=120)
    (output.parent / (output.stem + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8")
    (output.parent / (output.stem + ".log")).chmod(0o600)
    if result.returncode != 0 or not output.is_file():
        return result.returncode or 1, None, "Hub source metadata could not be captured"
    try:
        metadata = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or not metadata:
            raise ValueError("source metadata must be an object")
        output.chmod(0o600)
        return 0, metadata, ""
    except (OSError, ValueError):
        return 1, None, "Hub source metadata was not valid JSON"


def source_reference(path: Path, run_id: str, phase: str) -> dict:
    """Keep full source-info private and bind its exact bytes to this invocation."""
    binding = {"schema": "cicada.node-control-source-reference.v1",
               "run_id": run_id, "lane": "node-control-v1", "phase": phase,
               "metadata_file": path.name, "sha256": sha256_file(path),
               "size_bytes": path.stat().st_size}
    binding_path = path.with_name(path.stem + ".binding.json")
    write_json(binding_path, binding)
    return {**binding, "binding_file": binding_path.name,
            "binding_sha256": sha256_file(binding_path)}


def parse_go_test_log(source: Path, destination: Path) -> tuple[str, bool]:
    events: list[dict] = []
    exact_pass = False
    exact_fail = False
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        action = event.get("Action")
        name = event.get("Test", "")
        if action not in {"run", "pass", "fail", "skip", "output"}:
            continue
        if name and name != TEST_NAME:
            continue
        item = {"test": name or None, "action": action}
        if action == "output":
            output = str(event.get("Output", "")).strip()
            # The Go fixture's own log is a short protocol-scope line. Keep only
            # this known safe marker; arbitrary failure output stays private.
            if output.startswith("scope=HTTP_PROTOCOL "):
                item["scope"] = output
        events.append(item)
        exact_pass = exact_pass or action == "pass" and name == TEST_NAME
        exact_fail = exact_fail or action == "fail" and name == TEST_NAME
    destination.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in events), encoding="utf-8")
    destination.chmod(0o600)
    if exact_pass:
        return "PASS", False
    if exact_fail:
        return "FAIL", False
    return "FAIL", False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly run even when CICADA_NODE_CONTROL_V1_ENABLED is unset")
    parser.add_argument("--output-dir", type=Path, help="private evidence directory (must not already exist)")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    script = Path(__file__).resolve()
    enabled = args.run or os.environ.get("CICADA_NODE_CONTROL_V1_ENABLED") == "1"
    invalid_enable = "CICADA_NODE_CONTROL_V1_ENABLED" in os.environ and os.environ["CICADA_NODE_CONTROL_V1_ENABLED"] not in {"0", "1"}

    default_root = repo / ".cicada-data/node-control-v1-flow"
    output_root = args.output_dir.resolve() if args.output_dir else default_root
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_root, 0o700)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = output_root / f"{timestamp}-{os.getpid()}"
    try:
        evidence.mkdir(mode=0o700)
    except FileExistsError:
        print(f"BLOCKED: evidence directory already exists: {evidence}")
        return 2
    logs = evidence / "logs"
    scripts = evidence / "scripts"
    logs.mkdir(mode=0o700)
    scripts.mkdir(mode=0o700)
    shutil.copyfile(script, scripts / script.name)
    (scripts / script.name).chmod(0o600)
    script_hash_start = sha256_file(script)
    command_name = "cicada-node-control-v1-" + uuid.uuid4().hex[:12]
    child_run_id = os.environ.get("CICADA_COMPLETION_CHILD_RUN_ID", command_name)

    result: dict = {
        "schema_version": SCHEMA,
        "status": "NOT_RUN",
        "run_id": child_run_id,
        "lane": "node-control-v1",
        "recorded_at": utc_now(),
        "scope": "HTTP_PROTOCOL",
        "test": TEST_NAME,
        "test_selector": TEST_SELECTOR,
        "script_sha256_start": script_hash_start,
        "script_sha256_end": script_hash_start,
        "source_before": None,
        "source_after": None,
        "command_exit_code": None,
        "cleanup": {"temporary_container": "NOT_CREATED", "scratch": "NOT_CREATED"},
        "native_node_agent": "NOT_RUN",
        "native_runtime": "NOT_RUN",
        "android": "NOT_RUN",
        "public_https": "NOT_RUN",
    }

    if invalid_enable:
        result.update(status="BLOCKED", reason="CICADA_NODE_CONTROL_V1_ENABLED must be 0 or 1")
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2
    if not enabled:
        result["reason"] = "explicit opt-in is required: set CICADA_NODE_CONTROL_V1_ENABLED=1 or pass --run"
        write_json(evidence / "result.json", result)
        print(f"NOT_RUN: {evidence / 'result.json'}")
        return 0

    missing = [name for name in ("docker", "git", "python3", "sha256sum") if shutil.which(name) is None]
    if missing:
        result.update(status="BLOCKED", reason="required command unavailable: " + ",".join(missing))
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2
    docker_info = run(["docker", "info"], timeout=30)
    if docker_info.returncode != 0:
        result.update(status="BLOCKED", reason="Docker daemon is unavailable")
        (logs / "docker-info.log").write_text((docker_info.stdout + docker_info.stderr), encoding="utf-8")
        (logs / "docker-info.log").chmod(0o600)
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2

    module_cache = Path(os.environ.get("CICADA_NODE_CONTROL_GOMODCACHE",
                                      str(repo / ".cicada-data/m1-gomodcache"))).expanduser().resolve()
    if not module_cache.is_dir():
        result.update(status="BLOCKED", reason="offline Go module cache is unavailable")
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2
    image_check = run(["docker", "image", "inspect", GO_IMAGE, "--format", "{{.Id}}"], timeout=30)
    if image_check.returncode != 0 or not owned_cleanup.ID.fullmatch(image_check.stdout.strip()):
        result.update(status="BLOCKED", reason="pinned Go 1.27.1 image is not present locally")
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2

    source_before_path = evidence / "source-before.json"
    source_rc, source_before, source_error = read_source_info(repo, source_before_path)
    if source_rc != 0:
        result.update(status="BLOCKED", reason=source_error)
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2
    result["source_before"] = source_reference(source_before_path, child_run_id, "before")

    if os.environ.get("CICADA_COMPLETION_CHILD_LANE", "node-control-v1") != "node-control-v1":
        raise ValueError("CHILD_LANE_MISMATCH")
    scratch = Path(tempfile.mkdtemp(prefix="cicada-node-control-v1-"))
    os.chmod(scratch, 0o700)
    go_cache = Path(os.environ.get("CICADA_NODE_CONTROL_GOCACHE", str(scratch / "go-cache"))).expanduser().resolve()
    go_cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        cleanup_plan = owned_cleanup.prepare(scratch, child_run_id, "node-control-v1",
                                             [("test", command_name, image_check.stdout.strip())], [])
    except owned_cleanup.PreflightFailure as error:
        cleanup = owned_cleanup.cleanup(error.plan)
        result.update(status="BLOCKED", reason="fixture prestart ownership was not confirmed",
                      fixture_cleanup=cleanup, fixture_cleanup_status=cleanup["status"],
                      cleanup_owned_resources=False)
        write_json(evidence / "result.json", result)
        print(f"BLOCKED: {evidence / 'result.json'}")
        return 2
    owned_cleanup.write(evidence / "cleanup-plan.json", cleanup_plan)
    fixture_tmp = "/fixture-tmp"
    command = [
        "docker", "run", "--pull=never", "--name", command_name,
        "--cidfile", str(scratch / "test.cid"),
        "--label", f"{owned_cleanup.LABEL}={child_run_id}",
        "--label", f"{owned_cleanup.ROLE_LABEL}=test",
        "--network", "none", "--cpus", "2", "--memory", "3g", "--pids-limit", "256",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
        "--tmpfs", f"{fixture_tmp}:rw,exec,nosuid,nodev,size=2g",
        "-e", "GOTOOLCHAIN=local", "-e", "GOPROXY=off", "-e", "GOMAXPROCS=4",
        "-e", f"TMPDIR={fixture_tmp}", "-e", f"GOTMPDIR={fixture_tmp}",
        "-e", "GOMODCACHE=/gomod", "-e", "GOCACHE=/gocache",
        "-v", f"{repo}:/repo:ro", "-v", f"{module_cache}:/gomod:ro",
        "-v", f"{go_cache}:/gocache", "-w", "/repo/cicada-go", GO_IMAGE,
        "go", "test", "-buildvcs=false", "-json", "-p=1", "./internal/server",
        "-run", TEST_SELECTOR, "-count=1",
    ]
    (logs / "command.json").write_text(json.dumps({"command": command, "image": GO_IMAGE}, indent=2) + "\n", encoding="utf-8")
    (logs / "command.json").chmod(0o600)
    start = time.monotonic()
    raw_log = scratch / "go-test-private.jsonl"
    def interrupted(signum, frame):
        raise InterruptedError("FIXTURE_INTERRUPTED")

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    previous_int = signal.signal(signal.SIGINT, interrupted)
    try:
        completed = run(command, timeout=900)
        raw_log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        raw_log.chmod(0o600)
        (logs / "go-test-private.jsonl").write_text(raw_log.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        (logs / "go-test-private.jsonl").chmod(0o600)
        result["command_exit_code"] = completed.returncode
        result["duration_seconds"] = round(time.monotonic() - start, 3)
        test_status, _ = parse_go_test_log(raw_log, logs / "test-events.jsonl")
        source_after_path = evidence / "source-after.json"
        source_after_rc, source_after, source_after_error = read_source_info(repo, source_after_path)
        if source_after_rc != 0:
            result.update(status="FAIL", reason=source_after_error)
        else:
            result["source_after"] = source_reference(source_after_path, child_run_id, "after")
            if source_before != source_after or sha256_file(script) != script_hash_start:
                result.update(status="FAIL", reason="source inputs or driver changed during the run")
            elif completed.returncode == 0 and test_status == "PASS":
                result.update(status="PASS", reason="real-TCP production HTTP protocol fixture passed")
            else:
                result.update(status="FAIL", reason="the selected Go HTTP protocol test did not pass")
    except subprocess.TimeoutExpired:
        result.update(status="BLOCKED", reason="pinned Go fixture exceeded the 15-minute bound")
        result["command_exit_code"] = 124
    except InterruptedError:
        result.update(status="BLOCKED", reason="fixture interrupted before terminal evidence")
        result["command_exit_code"] = 143
    finally:
        # Repeated termination may stop the outer process, but never fabricate
        # cleanup confirmation. Restore the caller's signal disposition.
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        cleanup = owned_cleanup.cleanup(cleanup_plan)
        owned_cleanup.write(evidence / "cleanup.json", cleanup)
        result["fixture_cleanup"] = cleanup
        result["fixture_cleanup_status"] = cleanup["status"]
        result["cleanup_owned_resources"] = cleanup["status"] == "CONFIRMED"
        result["cleanup"]["temporary_container"] = "ABSENT" if cleanup["resources"][0]["post_cleanup"] == "EXACT_ABSENT" else "UNKNOWN"
        result["cleanup"]["scratch"] = "REMOVED" if cleanup["scratch"]["post_cleanup"] == "EXACT_ABSENT" else "UNKNOWN"
        result["script_sha256_end"] = sha256_file(script)
        result["recorded_at"] = utc_now()
        if not result["cleanup_owned_resources"] and result["status"] == "PASS":
            result.update(status="FAIL", reason="owned fixture cleanup was not confirmed")
        write_json(evidence / "result.json", result)

    marker = result["status"]
    print(f"{marker}: {evidence / 'result.json'}")
    if marker in {"FAIL", "BLOCKED"}:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
