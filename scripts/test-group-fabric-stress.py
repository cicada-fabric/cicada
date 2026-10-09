#!/usr/bin/env python3
"""Run the bounded public Go stress slice in isolated, offline containers.

Build and workload containers are separate so cgroup workload metrics exclude
the Go compiler. This runner deliberately has no provider, credential, runtime,
or Docker-socket mount support.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
GO_SOURCE = ROOT / "cicada-go"
MODULE_CACHE = ROOT / ".cicada-data" / "m1-gomodcache"
DEFAULT_GO_CACHE = ROOT / ".cicada-data" / "group-fabric-stress-20261009a" / "alias-repro-build" / "gocache"
PINNED_IMAGE = "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
RUN_LABEL = "cicada.v01.group-fabric-stress"
MAX_WORKLOAD_SECONDS = 180

STAGES = (
    {
        "name": "server-broadcast-guard",
        "binary": "server.test",
        "package": "./internal/server",
        "pattern": r"^TestRelayNodeGroupBroadcastSnapshotIsOwnerBoundAndImmutable$",
        "expected_tests": ["TestRelayNodeGroupBroadcastSnapshotIsOwnerBoundAndImmutable"],
    },
    {
        "name": "store",
        "binary": "store.test",
        "package": "./internal/store",
        "pattern": r"^TestStress(GroupDirectoryAndMembershipLimits|SameGroupBroadcastSnapshotCapAndRevocation|ConcurrentLinkSendAskReplyAndBacklogIsolation|FourSendersSixteenAsksEachAndShuffledReplies)$",
        "expected_tests": [
            "TestStressGroupDirectoryAndMembershipLimits",
            "TestStressSameGroupBroadcastSnapshotCapAndRevocation",
            "TestStressConcurrentLinkSendAskReplyAndBacklogIsolation",
            "TestStressFourSendersSixteenAsksEachAndShuffledReplies",
        ],
    },
    {
        "name": "cmd-cicada",
        "binary": "cicada.test",
        "package": "./cmd/cicada",
        "pattern": r"^TestStress(GroupBroadcast32RecipientPagination|FabricHTTPDirectory1001JoinBoundaryAndAlias|MachineNativeQueueSerializesSameEndpoint)$",
        "expected_tests": [
            "TestStressGroupBroadcast32RecipientPagination",
            "TestStressFabricHTTPDirectory1001JoinBoundaryAndAlias",
            "TestStressMachineNativeQueueSerializesSameEndpoint",
        ],
    },
    {
        "name": "control-alias",
        "binary": "control.test",
        "package": "./internal/control",
        "pattern": r"^TestStressResolveEndpointAliasBeyondListLimitFailsClosed$",
        "expected_tests": ["TestStressResolveEndpointAliasBeyondListLimitFailsClosed"],
    },
)


def command(argv: list[str], *, timeout: float = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {argv[0]} {argv[1:3]}")
    return result


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_inventory() -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    for path in sorted(GO_SOURCE.rglob("*")):
        relative = path.relative_to(GO_SOURCE).as_posix()
        if any(part in {".git", ".cicada-data", "vendor", "__pycache__"} for part in path.parts):
            continue
        if path.is_symlink():
            target = os.readlink(path)
            entries.append({"path": relative, "kind": "symlink", "sha256": sha256_bytes(target.encode())})
        elif path.is_file():
            entries.append({"path": relative, "kind": "file", "sha256": sha256_bytes(path.read_bytes())})
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"files": entries, "file_count": len(entries), "tree_sha256": sha256_bytes(canonical)}


def git_metadata() -> dict[str, str]:
    head = command(["git", "rev-parse", "HEAD"]).stdout.strip()
    status = command(["git", "status", "--short", "--", "cicada-go"]).stdout
    diff = command(["git", "diff", "--binary", "HEAD", "--", "cicada-go"]).stdout.encode()
    return {
        "head": head,
        "cicada_go_status": status,
        "cicada_go_diff_sha256": sha256_bytes(diff),
    }


def resident_snapshot() -> list[dict[str, Any]]:
    ids = command(["docker", "ps", "--no-trunc", "-q"]).stdout.split()
    residents: list[dict[str, Any]] = []
    template = "{{.Id}}|{{.Image}}|{{.Config.Image}}|{{.State.Status}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.Name}}"
    for container_id in ids:
        output = command(["docker", "inspect", "--format", template, container_id]).stdout.strip()
        values = output.split("|", 7)
        if len(values) != 8:
            raise RuntimeError("docker inspect returned an unexpected resident projection")
        residents.append({
            "id": values[0], "image_id": values[1], "image_ref": values[2],
            "state": values[3], "host_pid": int(values[4]), "started_at": values[5],
            "restart_count": int(values[6]), "name": values[7],
        })
    return sorted(residents, key=lambda item: item["id"])


def resident_core(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"], "image_id": row["image_id"], "host_pid": row["host_pid"],
        "started_at": row["started_at"], "restart_count": row["restart_count"],
        "running": row["state"] == "running",
    }


def load_protected_residents(path: pathlib.Path) -> tuple[dict[str, dict[str, Any]], str, str]:
    resolved = path.resolve(strict=True)
    data_root = (ROOT / ".cicada-data").resolve()
    if data_root not in resolved.parents or not resolved.is_file():
        raise RuntimeError("protected-resident receipt must be a file under .cicada-data")
    raw = resolved.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict) or len(document) != 6:
        raise RuntimeError("protected-resident receipt must contain exactly six container records")
    expected: dict[str, dict[str, Any]] = {}
    for container_id, row in document.items():
        if (not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id)
                or not isinstance(row, dict) or row.get("id") != container_id
                or row.get("status") != "running" or not isinstance(row.get("image"), str)
                or not isinstance(row.get("pid"), int) or row["pid"] <= 0
                or not isinstance(row.get("started_at"), str)
                or not isinstance(row.get("restart_count"), int) or row["restart_count"] < 0):
            raise RuntimeError("protected-resident receipt has an invalid public identity row")
        expected[container_id] = {
            "id": container_id, "image_id": row["image"], "host_pid": row["pid"],
            "started_at": row["started_at"], "restart_count": row["restart_count"], "running": True,
        }
    return expected, str(resolved), sha256_bytes(raw)


def known_qa_projection(container_id: str, resident: dict[str, Any]) -> dict[str, Any]:
    inspected = inspect_container(container_id)
    if inspected["id"] != container_id or not inspected["running"]:
        raise RuntimeError("nominated QA container is not the exact running container")
    task = inspected["cicada_task_label"]
    acceptance_task = inspected["task_label"]
    if task == "<no value>":
        task = ""
    if acceptance_task == "<no value>":
        acceptance_task = ""
    if not task and not acceptance_task:
        raise RuntimeError("nominated concurrent container has no recognized QA task label")
    if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", value) for value in (task, acceptance_task) if value):
        raise RuntimeError("concurrent QA label contains unsupported characters")
    return {**resident_core(resident), "cicada_task_label": task,
            "acceptance_task_label": acceptance_task, "acceptance_run_label": inspected["run_label"]}


def validate_initial_residents(actual: list[dict[str, Any]], protected: dict[str, dict[str, Any]],
                               known_qa_ids: set[str]) -> list[dict[str, Any]]:
    actual_by_id = {row["id"]: row for row in actual}
    if not set(protected).issubset(actual_by_id):
        raise RuntimeError("one or more protected resident containers are absent")
    for container_id, expected in protected.items():
        if resident_core(actual_by_id[container_id]) != expected:
            raise RuntimeError("a protected resident identity differs from its pinned receipt")
    extra_ids = set(actual_by_id) - set(protected)
    if extra_ids != known_qa_ids:
        raise RuntimeError("running containers differ from protected residents plus nominated QA IDs")
    projections = []
    for container_id in sorted(known_qa_ids):
        projection = known_qa_projection(container_id, actual_by_id[container_id])
        projections.append(projection)
    return projections


def compare_final_residents(actual: list[dict[str, Any]], protected: dict[str, dict[str, Any]],
                            excluded_qa_before: list[dict[str, Any]]) -> dict[str, Any]:
    actual_by_id = {row["id"]: row for row in actual}
    protected_ids = set(protected)
    qa_before = {row["id"]: row for row in excluded_qa_before}
    current_ids = set(actual_by_id)
    unknown_ids = current_ids - protected_ids - set(qa_before)
    protected_ok = protected_ids.issubset(current_ids) and all(
        resident_core(actual_by_id[container_id]) == expected
        for container_id, expected in protected.items()
    )
    qa_ok = True
    for container_id in current_ids & set(qa_before):
        try:
            projected = known_qa_projection(container_id, actual_by_id[container_id])
        except RuntimeError:
            qa_ok = False
            continue
        expected = qa_before[container_id]
        if any(projected.get(field) != expected.get(field) for field in
               ("image_id", "host_pid", "started_at", "restart_count", "running",
                "cicada_task_label", "acceptance_task_label", "acceptance_run_label")):
            qa_ok = False
    return {
        "protected_residents_unchanged": protected_ok,
        "known_qa_residents_unchanged_or_exited": qa_ok,
        "unknown_running_ids": sorted(unknown_ids),
        "unchanged": protected_ok and qa_ok and not unknown_ids,
    }


def write_json(path: pathlib.Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")[:48]


def docker_common(name: str, output_dir: pathlib.Path, cache_dir: pathlib.Path,
                  *, build: bool) -> list[str]:
    tmpfs_options = "rw,noexec,nosuid,nodev,size=268435456,mode=1777" if build else \
        "rw,exec,nosuid,nodev,size=268435456,mode=1777"
    args = [
        "docker", "create", "--name", name,
        "--label", f"cicada.acceptance.task={RUN_LABEL}",
        "--label", f"cicada.acceptance.run={output_dir.name}",
        "--network", "none", "--read-only", "--user", "1000:1000",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--cpus", "2", "--pids-limit", "256",
        "--tmpfs", f"/tmp:{tmpfs_options}",
        "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp",
        "--env", "GOPROXY=off", "--env", "GOSUMDB=off",
        "--env", "GOTOOLCHAIN=local", "--env", "GOMAXPROCS=2",
        "--env", "GOTELEMETRY=off", "--env", "GOCACHE=/cache",
        "--env", "GOMODCACHE=/gomod",
        "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=", "--env", "ALL_PROXY=",
        "--env", "http_proxy=", "--env", "https_proxy=", "--env", "all_proxy=",
        "--env", "CODEX_API_KEY=", "--env", "OPENAI_API_KEY=", "--env", "API_KEY=",
        "--mount", f"type=bind,src={GO_SOURCE},dst=/repo,readonly",
        "--mount", f"type=bind,src={MODULE_CACHE},dst=/gomod,readonly",
        "--mount", f"type=bind,src={cache_dir},dst=/cache",
    ]
    if build:
        args += ["--env", "GOTMPDIR=/out/tmp"]
        args += ["--memory", "3221225472", "--memory-swap", "3221225472"]
        args += ["--mount", f"type=bind,src={output_dir / 'build'},dst=/out"]
        args += ["--workdir", "/repo", PINNED_IMAGE, "/bin/sh", "-c"]
    else:
        args += ["--memory", "1073741824", "--memory-swap", "1073741824"]
        args += ["--mount", f"type=bind,src={output_dir / 'build' / 'bin'},dst=/test,readonly"]
    return args


def inspect_container(container_id: str) -> dict[str, Any]:
    template = "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.Running}}|{{.State.ExitCode}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.OOMKilled}}|{{index .Config.Labels \"cicada.acceptance.task\"}}|{{index .Config.Labels \"cicada.acceptance.run\"}}|{{index .Config.Labels \"cicada.task\"}}"
    output = command(["docker", "inspect", "--format", template, container_id]).stdout.strip()
    values = output.split("|", 11)
    if len(values) != 12:
        raise RuntimeError("docker inspect returned an unexpected owned-container projection")
    return {
        "id": values[0], "image_id": values[1], "state": values[2],
        "running": values[3].lower() == "true", "exit_code": int(values[4]),
        "host_pid": int(values[5]), "started_at": values[6], "finished_at": values[7],
        "oom_killed": values[8].lower() == "true",
        "task_label": values[9], "run_label": values[10], "cicada_task_label": values[11],
    }


def owned_container_matches(container: dict[str, Any], container_id: str,
                            run_label: str, resident_ids: set[str]) -> bool:
    return (
        container.get("id") == container_id
        and container.get("image_id") == PINNED_IMAGE
        and container.get("task_label") == RUN_LABEL
        and container.get("run_label") == run_label
        and container_id not in resident_ids
    )


def cgroup_directory(host_pid: int) -> pathlib.Path | None:
    if host_pid <= 0:
        return None
    try:
        rows = pathlib.Path(f"/proc/{host_pid}/cgroup").read_text(encoding="ascii").splitlines()
    except OSError:
        return None
    for row in rows:
        fields = row.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            root = pathlib.Path("/sys/fs/cgroup").resolve()
            candidate = (root / fields[2].lstrip("/")).resolve()
            if candidate == root or root not in candidate.parents:
                raise RuntimeError("owned test process cgroup escaped the cgroup v2 root")
            return candidate
    return None


def read_int(path: pathlib.Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def cgroup_metrics(path: pathlib.Path | None) -> dict[str, Any]:
    if path is None:
        return {"available": False}
    result: dict[str, Any] = {"available": True}
    for filename, key in (("memory.peak", "memory_peak_bytes"), ("memory.current", "memory_current_bytes")):
        value = read_int(path / filename)
        if value is not None:
            result[key] = value
    try:
        cpu = {}
        for line in (path / "cpu.stat").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit():
                cpu[fields[0]] = int(fields[1])
        result["cpu_stat"] = cpu
    except OSError:
        result["cpu_stat"] = {}
    try:
        events = {}
        for line in (path / "memory.events").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit():
                events[fields[0]] = int(fields[1])
        result["memory_events"] = events
    except OSError:
        result["memory_events"] = {}
    return result


def process_high_water_rss_kib(host_pid: int) -> int | None:
    if host_pid <= 0:
        return None
    try:
        for line in pathlib.Path(f"/proc/{host_pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def parse_final_cgroup_metrics(text: str) -> dict[str, Any]:
    markers = {}
    for line in text.splitlines():
        for key in ("MEMORY_PEAK_BYTES", "MEMORY_CURRENT_BYTES", "MEMORY_EVENTS", "CPU_STAT"):
            prefix = f"CICADA_CGROUP_FINAL_{key}="
            if line.startswith(prefix):
                markers[key] = line[len(prefix):]
    if not {"MEMORY_PEAK_BYTES", "MEMORY_CURRENT_BYTES", "MEMORY_EVENTS", "CPU_STAT"}.issubset(markers):
        return {"available": False, "reason": "final cgroup footer missing"}
    try:
        events = {}
        for item in markers["MEMORY_EVENTS"].split(";"):
            fields = item.strip().split()
            if len(fields) == 2 and fields[1].isdigit():
                events[fields[0]] = int(fields[1])
        cpu = {}
        for item in markers["CPU_STAT"].split(";"):
            fields = item.strip().split()
            if len(fields) == 2 and fields[1].isdigit():
                cpu[fields[0]] = int(fields[1])
        peak = int(markers["MEMORY_PEAK_BYTES"])
        current = int(markers["MEMORY_CURRENT_BYTES"])
    except ValueError:
        return {"available": False, "reason": "invalid final cgroup footer"}
    return {"available": True, "source": "container-PID1-footer-before-exit",
            "memory_peak_bytes": peak, "memory_current_bytes_before_exit": current,
            "memory_events": events, "cpu_stat": cpu}


def workload_shell_command(stage: dict[str, Any]) -> str:
    argv = [f"/test/{stage['binary']}", "-test.v", "-test.timeout=150s", f"-test.run={stage['pattern']}"]
    test = " ".join(shlex.quote(part) for part in argv)
    return (
        "set +e; " + test + "; test_status=$?; "
        "printf 'CICADA_CGROUP_FINAL_MEMORY_PEAK_BYTES='; cat /sys/fs/cgroup/memory.peak; "
        "printf 'CICADA_CGROUP_FINAL_MEMORY_CURRENT_BYTES='; cat /sys/fs/cgroup/memory.current; "
        "printf 'CICADA_CGROUP_FINAL_MEMORY_EVENTS='; tr '\\n' ';' < /sys/fs/cgroup/memory.events; printf '\\n'; "
        "printf 'CICADA_CGROUP_FINAL_CPU_STAT='; tr '\\n' ';' < /sys/fs/cgroup/cpu.stat; printf '\\n'; "
        "exit \"$test_status\""
    )


def run_owned_container(container_id: str, cidfile: pathlib.Path, log_path: pathlib.Path,
                        timeout_seconds: float, max_wall_deadline: float | None = None,
                        *, final_cgroup_footer: bool = False) -> dict[str, Any]:
    start_argv = ["docker", "start", container_id]
    start_result = command(start_argv, timeout=20)
    started = time.monotonic()
    initial = inspect_container(container_id)
    host_pid = initial["host_pid"]
    cgroup = cgroup_directory(host_pid)
    high_water_rss = process_high_water_rss_kib(host_pid)
    cgroup_samples = [cgroup_metrics(cgroup)]
    deadline = started + timeout_seconds
    if max_wall_deadline is not None:
        deadline = min(deadline, max_wall_deadline)
    timed_out = False
    stop_argv: list[str] | None = None
    wait_client_killed = False
    waiter = subprocess.Popen(["docker", "wait", container_id], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while waiter.poll() is None:
        rss = process_high_water_rss_kib(host_pid)
        if rss is not None and (high_water_rss is None or rss > high_water_rss):
            high_water_rss = rss
        cgroup_samples.append(cgroup_metrics(cgroup))
        if time.monotonic() >= deadline:
            timed_out = True
            stop_argv = ["docker", "stop", "--time", "5", container_id]
            command(stop_argv, timeout=15, check=False)
            break
        time.sleep(0.1)
    try:
        waiter_stdout, waiter_stderr = waiter.communicate(timeout=12 if timed_out else 5)
    except subprocess.TimeoutExpired:
        wait_client_killed = True
        waiter.kill()
        waiter_stdout, waiter_stderr = waiter.communicate(timeout=3)
    final = inspect_container(container_id)
    logs = command(["docker", "logs", container_id], timeout=20, check=False)
    log_path.write_text(logs.stdout, encoding="utf-8")
    log_path.chmod(0o600)
    try:
        cgroup_samples.append(cgroup_metrics(cgroup))
        sampled_metrics: dict[str, Any] = {"available": any(sample.get("available") for sample in cgroup_samples),
                                           "scope": "host samples before process exit; lower-bound only"}
        peaks = [sample.get("memory_peak_bytes") for sample in cgroup_samples if isinstance(sample.get("memory_peak_bytes"), int)]
        currents = [sample.get("memory_current_bytes") for sample in cgroup_samples if isinstance(sample.get("memory_current_bytes"), int)]
        if peaks:
            sampled_metrics["memory_peak_bytes_lower_bound"] = max(peaks)
        if currents:
            sampled_metrics["memory_current_bytes_at_last_sample"] = currents[-1]
        sampled_metrics["cpu_stat_last_sample"] = next((sample["cpu_stat"] for sample in reversed(cgroup_samples) if sample.get("cpu_stat")), {})
    except RuntimeError:
        sampled_metrics = {"available": False, "reason": "invalid cgroup path", "scope": "host samples before process exit; lower-bound only"}
    if high_water_rss is not None:
        sampled_metrics["process_host_vm_hwm_kib"] = high_water_rss
    logs_text = logs.stdout
    exact_cgroup = parse_final_cgroup_metrics(logs_text) if final_cgroup_footer else {"available": False, "reason": "build stage uses sampled metrics only"}
    return {
        "cid": container_id,
        "cidfile": str(cidfile),
        "docker_start_argv": start_argv,
        "docker_stop_argv": stop_argv,
        "docker_start_output": start_result.stdout.strip(),
        "docker_wait_exit_code": waiter.returncode,
        "docker_wait_stdout": waiter_stdout.strip(),
        "docker_wait_stderr_sha256": sha256_bytes(waiter_stderr.encode()),
        "docker_wait_client_killed": wait_client_killed,
        "started_at": final["started_at"], "finished_at": final["finished_at"],
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "exit_code": final["exit_code"], "running_after_wait": final["running"],
        "docker_wait_matches_inspect": waiter.returncode == 0 and waiter_stdout.strip() == str(final["exit_code"]),
        "timed_out": timed_out, "oom_killed": final["oom_killed"],
        "workload_cgroup_metrics": exact_cgroup,
        "sampled_cgroup_metrics_lower_bound": sampled_metrics,
        "log_path": str(log_path), "log_sha256": sha256_bytes(logs.stdout.encode()),
        "stress_metrics": parse_stress_metrics(logs_text),
        "test_outcomes": parse_test_outcomes(logs_text),
    }


def parse_stress_metrics(text: str) -> list[dict[str, Any]]:
    metrics = []
    for line in text.splitlines():
        marker = "CICADA_STRESS_METRIC "
        index = line.find(marker)
        if index < 0:
            continue
        try:
            metrics.append(json.loads(line[index + len(marker):]))
        except json.JSONDecodeError:
            metrics.append({"parse_error": True})
    return metrics


def parse_test_outcomes(text: str) -> dict[str, Any]:
    outcomes: list[dict[str, str]] = []
    pattern = re.compile(r"^\s*--- (PASS|FAIL|SKIP): ([^\s]+)(?:\s+\((.*)\))?\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            outcomes.append({"status": match.group(1), "name": match.group(2), "detail": match.group(3) or ""})
    top = [item for item in outcomes if "/" not in item["name"]]
    sub = [item for item in outcomes if "/" in item["name"]]
    return {
        "top_pass": sum(item["status"] == "PASS" for item in top),
        "top_fail": sum(item["status"] == "FAIL" for item in top),
        "top_skip": sum(item["status"] == "SKIP" for item in top),
        "sub_pass": sum(item["status"] == "PASS" for item in sub),
        "sub_fail": sum(item["status"] == "FAIL" for item in sub),
        "sub_skip": sum(item["status"] == "SKIP" for item in sub),
        "outcomes": outcomes,
    }


def create_container(args: list[str], cidfile: pathlib.Path, run_label: str,
                     resident_ids: set[str]) -> str:
    argv = container_create_argv(args, cidfile)
    container_id = ""
    try:
        command(argv, timeout=60)
        container_id = cidfile.read_text(encoding="ascii").strip()
        cidfile.chmod(0o600)
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("docker did not create a full 64-character container ID")
        inspected = inspect_container(container_id)
        if not owned_container_matches(inspected, container_id, run_label, resident_ids):
            raise RuntimeError("created container failed exact ID/image/owner-label validation")
        return container_id
    except Exception:
        if not container_id and cidfile.exists():
            try:
                cidfile.chmod(0o600)
            except OSError:
                pass
            candidate = cidfile.read_text(encoding="ascii", errors="ignore").strip()
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                container_id = candidate
        if re.fullmatch(r"[0-9a-f]{64}", container_id):
            remove_exact_container(container_id, run_label, resident_ids)
        raise


def container_create_argv(args: list[str], cidfile: pathlib.Path) -> list[str]:
    if cidfile.exists():
        raise RuntimeError(f"refusing to overwrite existing owned cidfile: {cidfile}")
    try:
        image_index = args.index(PINNED_IMAGE)
    except ValueError as error:
        raise RuntimeError("container argv is missing the pinned image") from error
    return args[:image_index] + ["--cidfile", str(cidfile)] + args[image_index:]


def inspect_confirms_absent(returncode: int, output: str, container_id: str) -> bool:
    if returncode == 0 or not re.fullmatch(r"[0-9a-f]{64}", container_id):
        return False
    normalized = output.lower()
    return any(phrase in normalized for phrase in (
        f"no such object: {container_id}", f"no such container: {container_id}",
    ))


def verify_absence_predicate() -> bool:
    sample_id = "a" * 64
    return (
        inspect_confirms_absent(1, f"Error: No such object: {sample_id}\n", sample_id)
        and inspect_confirms_absent(1, f"error: no such container: {sample_id}\n", sample_id)
        and not inspect_confirms_absent(0, f"no such object: {sample_id}", sample_id)
        and not inspect_confirms_absent(1, "Cannot connect to the Docker daemon", sample_id)
        and not inspect_confirms_absent(1, f"no such object: {'b' * 64}", sample_id)
    )


def remove_exact_container(container_id: str, run_label: str, resident_ids: set[str]) -> bool:
    if not re.fullmatch(r"[0-9a-f]{64}", container_id) or container_id in resident_ids:
        return False
    before = command(["docker", "inspect", "--format", "{{.Id}}", container_id], timeout=15, check=False)
    if before.returncode != 0:
        return inspect_confirms_absent(before.returncode, before.stdout, container_id)
    try:
        inspected = inspect_container(container_id)
    except RuntimeError:
        return False
    if not owned_container_matches(inspected, container_id, run_label, resident_ids):
        return False
    result = command(["docker", "rm", "--force", container_id], timeout=30, check=False)
    remaining = command(["docker", "inspect", container_id], timeout=15, check=False)
    absent = inspect_confirms_absent(remaining.returncode, remaining.stdout, container_id)
    return result.returncode == 0 and absent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="required: perform bounded offline build and stress stages")
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path,
                        help="new private directory below .cicada-data; existing paths are never overwritten")
    parser.add_argument("--protected-residents-file", required=True, type=pathlib.Path,
                        help="public NONAUTH snapshot containing exactly the six protected resident IDs")
    parser.add_argument("--go-cache-dir", type=pathlib.Path, default=DEFAULT_GO_CACHE,
                        help="existing writable Go build cache under .cicada-data")
    parser.add_argument("--known-concurrent-qa-id", action="append", default=[],
                        help="full ID of an explicitly nominated, QA-labeled concurrent test container")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required; this runner intentionally has no implicit execution mode")
    if not verify_absence_predicate():
        parser.error("Docker exact-absence predicate self-check failed")
    evidence = args.evidence_dir if args.evidence_dir.is_absolute() else ROOT / args.evidence_dir
    evidence = evidence.resolve(strict=False)
    data_root = (ROOT / ".cicada-data").resolve()
    if evidence.parent != data_root:
        parser.error("--evidence-dir must be a new direct child of this repository's .cicada-data directory")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", evidence.name):
        parser.error("--evidence-dir basename must be 1-63 safe ASCII label characters")
    if len(set(args.known_concurrent_qa_id)) != len(args.known_concurrent_qa_id):
        parser.error("--known-concurrent-qa-id values must be unique")
    if any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in args.known_concurrent_qa_id):
        parser.error("--known-concurrent-qa-id requires full 64-character container IDs")
    if evidence.exists():
        parser.error("evidence directory already exists; refusing to overwrite it")
    if not GO_SOURCE.is_dir() or not MODULE_CACHE.is_dir():
        parser.error("required public Go source or existing offline module cache is missing")
    if command(["docker", "image", "inspect", PINNED_IMAGE], check=False).returncode != 0:
        parser.error("pinned Go builder image is not already present locally")
    try:
        protected_residents, protected_path, protected_sha = load_protected_residents(args.protected_residents_file)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(f"invalid protected-resident receipt: {type(error).__name__}")
    go_cache_dir = args.go_cache_dir if args.go_cache_dir.is_absolute() else ROOT / args.go_cache_dir
    try:
        go_cache_dir = go_cache_dir.resolve(strict=True)
    except OSError:
        parser.error("existing Go build cache is missing")
    cache_stat = go_cache_dir.stat()
    if (data_root not in go_cache_dir.parents or not go_cache_dir.is_dir()
            or cache_stat.st_uid != 1000 or not (cache_stat.st_mode & 0o200)
            or not os.access(go_cache_dir, os.W_OK)):
        parser.error("Go build cache must be an existing writable directory under .cicada-data")
    known_qa_ids = set(args.known_concurrent_qa_id)
    if known_qa_ids & set(protected_residents):
        parser.error("a protected resident ID cannot also be nominated as a QA container")

    try:
        initial_residents = resident_snapshot()
        excluded_qa_before = validate_initial_residents(initial_residents, protected_residents, known_qa_ids)
    except (RuntimeError, OSError) as error:
        parser.error(f"resident preflight failed: {type(error).__name__}")
    resident_ids = {item["id"] for item in initial_residents}

    evidence.mkdir(mode=0o700)
    (evidence / "build" / "bin").mkdir(mode=0o700, parents=True)
    (evidence / "build" / "tmp").mkdir(mode=0o700)
    build_cache = go_cache_dir
    initial_inventory = source_inventory()
    initial_git = git_metadata()
    runner_sha256 = sha256_bytes(pathlib.Path(__file__).read_bytes())
    receipt: dict[str, Any] = {
        "schema": "cicada.v01.group-fabric-stress-run.v1",
        "scope": "offline component stress only; no Node/Hub deployment, native Runtime, provider, model, credential, replay/decryption, or real-device proof",
        "head": initial_git["head"], "cicada_go_git_status": initial_git["cicada_go_status"],
        "cicada_go_diff_sha256": initial_git["cicada_go_diff_sha256"],
        "source_inventory": initial_inventory,
        "runner": {"path": str(pathlib.Path(__file__).resolve()), "sha256": runner_sha256},
        "runner_parameters": {
            "build_packages": [stage["package"] for stage in STAGES],
            "workload_stages": [{"name": stage["name"], "package": stage["package"],
                                 "pattern": stage["pattern"], "expected_tests": stage["expected_tests"]}
                                for stage in STAGES],
            "combined_workload_budget_seconds": MAX_WORKLOAD_SECONDS,
            "stage_test_timeout_seconds": 150,
            "go_cache_path": str(build_cache),
            "go_cache_reused": True,
            "workload_cpu_limit": 2,
            "workload_memory_limit_bytes": 1073741824,
            "workload_pids_limit": 256,
            "cleanup_absence_predicate_selfcheck": "PASS",
        },
        "go_image_id": PINNED_IMAGE,
        "security_envelope": {
            "network": "none", "uid_gid": "1000:1000", "cap_drop": "ALL",
            "no_new_privileges": True, "cpu_limit": 2,
            "build_memory_limit_bytes": 3221225472, "workload_memory_limit_bytes": 1073741824,
            "workload_pids_limit": 256, "source_mount": "read-only /repo",
            "module_cache_mount": "read-only /gomod", "no_secret_mounts": True,
            "no_published_ports": True, "no_docker_socket": True,
            "owner_labels": {"cicada.acceptance.task": RUN_LABEL, "cicada.acceptance.run": evidence.name},
        },
        "resident_before": initial_residents,
        "protected_resident_receipt": {"path": protected_path, "sha256": protected_sha,
                                        "count": len(protected_residents)},
        "protected_residents_expected": list(protected_residents.values()),
        "excluded_owned_qa_before": excluded_qa_before,
        "builder": None,
        "workloads": [],
    }
    write_json(evidence / "RUN.NONAUTH.json", receipt)
    owned: list[str] = []
    success = False
    try:
        build_script = "set -eu; go test -c -buildvcs=false -mod=readonly -p=2 -o /out/bin/server.test ./internal/server; go test -c -buildvcs=false -mod=readonly -p=2 -o /out/bin/store.test ./internal/store; go test -c -buildvcs=false -mod=readonly -p=2 -o /out/bin/cicada.test ./cmd/cicada; go test -c -buildvcs=false -mod=readonly -p=2 -o /out/bin/control.test ./internal/control"
        build_name = safe_name("cicada-gf-stress-" + evidence.name + "-build")
        build_cidfile = evidence / "build.cid"
        build_args = docker_common(build_name, evidence, build_cache, build=True)
        build_argv = container_create_argv(build_args + [build_script], build_cidfile)
        build_cid = create_container(build_args + [build_script], build_cidfile, evidence.name, resident_ids)
        owned.append(build_cid)
        build = run_owned_container(build_cid, build_cidfile, evidence / "build.log", timeout_seconds=900)
        build["docker_create_argv"] = build_argv
        build["command"] = ["go test -c -buildvcs=false -mod=readonly -p=2", "./internal/server", "./internal/store", "./cmd/cicada", "./internal/control"]
        receipt["builder"] = build
        receipt["builder"]["cleanup_confirmed"] = remove_exact_container(build_cid, evidence.name, resident_ids)
        receipt["builder"]["docker_cleanup_argv"] = ["docker", "rm", "--force", build_cid]
        owned.remove(build_cid)
        if build["exit_code"] != 0 or build["timed_out"] or build["oom_killed"] or not receipt["builder"]["cleanup_confirmed"]:
            raise RuntimeError("offline stress test-binary build did not complete cleanly")
        if source_inventory()["tree_sha256"] != initial_inventory["tree_sha256"]:
            receipt["source_changed_during_run"] = True
            raise RuntimeError("Go source bytes changed while the source RO snapshot was building")

        workload_started = time.monotonic()
        workload_deadline = workload_started + MAX_WORKLOAD_SECONDS
        for stage in STAGES:
            remaining = workload_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("combined bounded workload budget expired")
            name = safe_name("cicada-gf-stress-" + evidence.name + "-" + stage["name"])
            cidfile = evidence / f"{stage['name']}.cid"
            docker_args = docker_common(name, evidence, build_cache, build=False)
            docker_args += ["--workdir", "/repo", PINNED_IMAGE, "/bin/sh", "-c",
                            workload_shell_command(stage)]
            create_argv = container_create_argv(docker_args, cidfile)
            cid = create_container(docker_args, cidfile, evidence.name, resident_ids)
            owned.append(cid)
            result = run_owned_container(cid, cidfile, evidence / f"{stage['name']}.log",
                                         timeout_seconds=remaining, max_wall_deadline=workload_deadline,
                                         final_cgroup_footer=True)
            result["stage"] = stage["name"]
            result["test_pattern"] = stage["pattern"]
            result["docker_create_argv"] = create_argv
            result["package"] = stage["package"]
            result["expected_tests"] = stage["expected_tests"]
            test_log = (evidence / f"{stage['name']}.log").read_text(encoding="utf-8", errors="replace")
            result["test_outcomes"] = parse_test_outcomes(test_log)
            passed_names = sorted(item["name"] for item in result["test_outcomes"]["outcomes"]
                                  if item["status"] == "PASS" and "/" not in item["name"])
            result["expected_tests_observed"] = passed_names == sorted(stage["expected_tests"])
            result["cleanup_confirmed"] = remove_exact_container(cid, evidence.name, resident_ids)
            result["docker_cleanup_argv"] = ["docker", "rm", "--force", cid]
            owned.remove(cid)
            receipt["workloads"].append(result)
            write_json(evidence / "RUN.NONAUTH.json", receipt)
            memory_events = result["workload_cgroup_metrics"].get("memory_events", {})
            cpu_stat = result["workload_cgroup_metrics"].get("cpu_stat", {})
            if (result["exit_code"] != 0 or result["running_after_wait"] or
                    not result["docker_wait_matches_inspect"] or result["timed_out"] or result["oom_killed"] or
                    not {"oom", "oom_kill"}.issubset(memory_events) or
                    memory_events.get("oom", 1) != 0 or memory_events.get("oom_kill", 1) != 0 or
                    not result["cleanup_confirmed"] or
                    not result["workload_cgroup_metrics"].get("available") or
                    not isinstance(result["workload_cgroup_metrics"].get("memory_peak_bytes"), int) or
                    result["workload_cgroup_metrics"].get("memory_peak_bytes", 0) > 1073741824 or
                    not isinstance(cpu_stat.get("usage_usec"), int) or
                    not result["expected_tests_observed"] or result["test_outcomes"]["top_skip"] or
                    result["test_outcomes"]["sub_skip"] or result["test_outcomes"]["top_fail"] or
                    result["test_outcomes"]["sub_fail"]):
                raise RuntimeError(f"workload stage {stage['name']} failed or did not clean up")
            if source_inventory()["tree_sha256"] != initial_inventory["tree_sha256"]:
                receipt["source_changed_during_run"] = True
                raise RuntimeError("Go source bytes changed during a stress workload")

        success = True
    except Exception as error:  # noqa: BLE001 - sanitized error category is retained in receipt
        receipt["runner_error_type"] = type(error).__name__
        receipt["runner_error"] = str(error)[:300]
    finally:
        cleanup_results = []
        for container_id in list(owned):
            cleanup_results.append({"cid": container_id,
                                    "confirmed": remove_exact_container(container_id, evidence.name, resident_ids)})
            owned.remove(container_id)
        receipt["emergency_cleanup"] = cleanup_results
        final_inventory = source_inventory()
        receipt["source_inventory_after"] = {
            "file_count": final_inventory["file_count"], "tree_sha256": final_inventory["tree_sha256"],
            "unchanged": final_inventory["tree_sha256"] == initial_inventory["tree_sha256"],
        }
        receipt["resident_after"] = resident_snapshot()
        resident_comparison = compare_final_residents(receipt["resident_after"], protected_residents,
                                                      excluded_qa_before)
        receipt["resident_comparison"] = resident_comparison
        receipt["residents_unchanged"] = resident_comparison["unchanged"]
        receipt["workload_budget_seconds"] = MAX_WORKLOAD_SECONDS
        receipt["workload_elapsed_seconds"] = round(time.monotonic() - workload_started, 6) if "workload_started" in locals() else None
        receipt["status"] = "PASS" if success and receipt["residents_unchanged"] and receipt["source_inventory_after"]["unchanged"] else "FAIL"
        write_json(evidence / "RUN.NONAUTH.json", receipt)

    print(json.dumps({
        "status": receipt["status"], "receipt": str(evidence / "RUN.NONAUTH.json"),
        "receipt_sha256": sha256_bytes((evidence / "RUN.NONAUTH.json").read_bytes()),
        "workload_stages": [{"stage": item.get("stage"), "exit_code": item.get("exit_code"),
                             "elapsed_seconds": item.get("elapsed_seconds"), "cleanup_confirmed": item.get("cleanup_confirmed")}
                            for item in receipt["workloads"]],
        "residents_unchanged": receipt["residents_unchanged"],
        "source_unchanged": receipt["source_inventory_after"]["unchanged"],
    }, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
