#!/usr/bin/env python3
"""Host-only bridge for explicit fixture requests; no Docker socket in actors."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def docker(args, timeout=40):
    return subprocess.run(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def write(path, value):
    temporary = Path(str(path) + ".tmp")
    with temporary.open("x") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def owned(name, identity, kind="container", expected=None):
    result = docker(["inspect" if kind == "container" else "network", *([] if kind == "container" else ["inspect"]), "--format", '{{index .Config.Labels "cicada.fixture"}}' if kind == "container" else '{{index .Labels "cicada.fixture"}}', name])
    if result.returncode or result.stdout.decode().strip() != identity:
        return False
    observed = docker(["inspect" if kind == "container" else "network", *([] if kind == "container" else ["inspect"]), "--format", "{{.Id}}", name])
    return observed.returncode == 0 and expected is not None and observed.stdout.decode().strip() == expected


def absent(name, expected, kind="container"):
    inspect = docker(["inspect", "--format", "{{.Id}}", name] if kind == "container" else ["network", "inspect", "--format", "{{.Id}}", name])
    listed = docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}} {{.Names}}"] if kind == "container" else ["network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Name}}"])
    objects = [line.split() for line in listed.stdout.decode().splitlines()] if listed.returncode == 0 else []
    diagnostic = inspect.stdout.lower()
    recognized_absence = b"no such object:" in diagnostic or b"no such container:" in diagnostic or (kind == "network" and (b"network " + name.encode() + b" not found") in diagnostic)
    missing = inspect.returncode == 1 and recognized_absence and listed.returncode == 0 and not any(name in row or (expected is not None and expected in row) for row in objects)
    return missing, inspect.returncode, listed.returncode


def run(a):
    root = Path(a.evidence).resolve()
    driver = a.identity + "-driver"
    nodes = {}
    receipts = []
    handled = set()
    isolation = None
    fixture_root = None
    deadline = time.monotonic() + 400
    while time.monotonic() < deadline:
        for path in sorted((root / "commands").glob("*.request.json")):
            if path.name in handled:
                continue
            request = json.loads(path.read_text())
            target = request["target"]
            if target not in ("node-a", "node-b"):
                raise ValueError("unowned fixture target")
            name = a.identity + "-" + target
            state = Path(request["state_root"]).resolve()
            transfers = Path(request["transfer_root"]).resolve()
            trust = Path(request["trust_root"]).resolve()
            candidate_root = state.parent
            if fixture_root is None:
                if candidate_root.parent != root or not candidate_root.name.startswith("synthetic-ip-first-install-") or candidate_root.is_symlink():
                    raise ValueError("unowned first-install root")
                fixture_root = candidate_root
                write(root / "owned-fixture.json", {"root_name": fixture_root.name})
            if candidate_root != fixture_root or state.name != target or transfers != fixture_root / "transfers" or trust != fixture_root / "trust" or Path(request["owner_public"]).resolve() != fixture_root / "owner-signer" / "public.json" or Path(request["bootstrap_root"]).resolve() != trust / "bootstrap-root.pem" or Path(request["pq_root"]).resolve() != trust / "root.pem":
                raise ValueError("fixture command escaped its exact first-install root")
            for value in (request["state_root"], request["transfer_root"], request["trust_root"], request["owner_public"], request["bootstrap_root"]):
                if Path(value).absolute() != Path(value).resolve():
                    raise ValueError("fixture path has symlink or noncanonical spelling")
            if target not in nodes:
                arm = target == "node-b" and a.arm64_package
                package = a.arm64_package if arm else a.amd64_package
                args = ["create", "--name", name, "--label", "cicada.fixture=" + a.identity,
                        "--network", a.identity + ("-a" if target == "node-a" else "-b"),
                        "--ip", a.node_a if target == "node-a" else a.node_b,
                        "--cpus", "2", "--memory", "1g", "--pids-limit", "128", "--user", f"{os.getuid()}:{os.getgid()}",
                        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--tmpfs", f"/tmp:rw,exec,nosuid,nodev,size=268435456,mode=0700,uid={os.getuid()},gid={os.getgid()}",
                        "-v", f"{state}:{state}", "-v", f"{transfers}:{transfers}", "-v", f"{trust}:{trust}:ro",
                        "-v", f'{request["owner_public"]}:{request["owner_public"]}:ro',
                        "-v", f"{package}:/node-package:ro", "-v", f"{root / 'network-fixture'}:/network-fixture:ro"]
                if arm:
                    args += ["-v", f"{a.arm64_rootfs}:/arm64-rootfs:ro", "-v", f"{a.qemu}:/usr/local/bin/qemu-aarch64-static:ro"]
                args += [a.builder, "sleep", "390"]
                result = docker(args)
                if result.returncode:
                    raise RuntimeError("owned Node container startup failed")
                cid = result.stdout.decode().strip()
                (root / (target + ".id")).write_text(cid + "\n")
                nodes[target] = {"name": name, "cid": cid, "arm": bool(arm), "allowed_sources": {str(state), str(transfers), str(trust), request["owner_public"], package, str(root / "network-fixture"), *([a.arm64_rootfs, a.qemu] if arm else [])}}
                if docker(["start", cid]).returncode:
                    raise RuntimeError("owned Node CID failed to start")
            if len(nodes) == 2 and isolation is None:
                probes = []
                for probe_target in ("node-a", "node-b"):
                    started = docker(["exec", "--detach", nodes[probe_target]["cid"], "/network-fixture", "listen", "--address", "0.0.0.0:39251"])
                    if started.returncode:
                        raise RuntimeError("owned isolation listener did not start")
                time.sleep(0.2)
                for probe_target, peer in (("node-a", a.node_b), ("node-b", a.node_a)):
                    for attempt in range(5):
                        local = docker(["exec", nodes[probe_target]["cid"], "/network-fixture", "probe", "--address", "127.0.0.1:39251", "--expect", "reachable"])
                        if not local.returncode:
                            break
                        time.sleep(0.1)
                    if local.returncode:
                        raise RuntimeError("owned isolation probe listener unavailable")
                    probes.append(json.loads(local.stdout))
                    observed = docker(["exec", nodes[probe_target]["cid"], "/network-fixture", "probe", "--address", peer + ":39251", "--expect", "unreachable"])
                    if observed.returncode:
                        raise RuntimeError("Node-to-Node network isolation failed")
                    probes.append(json.loads(observed.stdout))
                isolation = probes
            actor = nodes[target]
            if not owned(actor["cid"], a.identity, expected=actor["cid"]):
                raise RuntimeError("owned Node CID or label changed")
            command = ["exec", "-e", "SSL_CERT_FILE=" + request["bootstrap_root"], "-e", "OPENSSL_CONF=/dev/null", "-e", "LD_LIBRARY_PATH=", "-e", "LD_PRELOAD="]
            command += [actor["cid"]]
            if actor["arm"]:
                command += ["/usr/local/bin/qemu-aarch64-static", "-L", "/arm64-rootfs"]
            command += ["/node-package/bin/cicada", *request["args"]]
            result = docker(command, timeout=30)
            receipts.append({"sequence": request["sequence"], "target": target, "arm64_emulated": actor["arm"],
                             "phase": request["args"][:2], "exit": result.returncode,
                             "transcript_sha256": hashlib.sha256(result.stdout).hexdigest(), "transcript_bytes": len(result.stdout)})
            write(Path(str(path) + ".response.json"), {"exit": result.returncode, "output": base64.b64encode(result.stdout).decode()})
            handled.add(path.name)
        status = docker(["inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", driver])
        if status.returncode or status.stdout.decode().split()[0] != "true":
            code = int(status.stdout.decode().split()[1]) if not status.returncode else 1
            write(root / "node-command-receipts.json", receipts)
            # Independent namespaces: every Node has exactly one network. The
            # driver has two; product Hub accepts outbound connections from both.
            topology = []
            for target, actor in nodes.items():
                observed = docker(["inspect", "--format", "{{json .NetworkSettings.Networks}}", actor["cid"]])
                networks = json.loads(observed.stdout) if not observed.returncode else {}
                mount_result = docker(["inspect", "--format", "{{json .Mounts}}", actor["cid"]])
                mounts = json.loads(mount_result.stdout) if not mount_result.returncode else []
                sources = {m["Source"] for m in mounts}
                if not sources or sources != actor["allowed_sources"]:
                    raise RuntimeError("actual Node mount inventory differs from its narrow fixture scope")
                hub_mounted = any(Path(source) == fixture_root or Path(source).is_relative_to(fixture_root / "hub-state") or (fixture_root / "hub-state").is_relative_to(Path(source)) for source in sources)
                owner_private_mounted = any(Path(source) == fixture_root or Path(source) == fixture_root / "owner-signer" or Path(source) == fixture_root / "owner-signer" / "private.json" for source in sources)
                topology.append({"target": target, "networks": sorted(networks), "arm64_emulated": actor["arm"],
                                 "actual_mount_count": len(mounts), "actual_mount_destinations": sorted(m["Destination"] for m in mounts if not m["Destination"].startswith(str(fixture_root))),
                                 "hub_database_mounted": hub_mounted, "owner_private_key_mounted": owner_private_mounted})
            write(root / "topology.json", {"nodes": topology, "isolation_probes": isolation, "separate_node_networks": len(topology) == 2 and all(len(n["networks"]) == 1 for n in topology) and topology[0]["networks"] != topology[1]["networks"] and bool(isolation), "hub_a": a.hub_a, "hub_b": a.hub_b, "node_a": a.node_a, "node_b": a.node_b})
            return code
        time.sleep(0.1)
    raise TimeoutError("bounded deployment fixture deadline exceeded")


def report(a):
    root = Path(a.evidence).resolve()
    counts = {"pass": 0, "fail": 0, "skip": 0}
    public = []
    private = root / "gate.private.jsonl"
    for line in private.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            event = {"Output": line}
        if event.get("Test") and event.get("Action") in counts:
            counts[event["Action"]] += 1
        output = event.get("Output", "")
        if output and not output.strip().startswith(("=== RUN", "--- PASS", "--- FAIL", "--- SKIP", "PASS", "FAIL", "ok ", "phase=")):
            event["Output"] = "diagnostic suppressed sha256=" + hashlib.sha256(output.encode()).hexdigest() + "\n"
        public.append(event)
    write(root / "gate-events.json", public)
    topology = json.loads((root / "topology.json").read_text()) if (root / "topology.json").exists() else {}
    code = int((root / "gate.exit").read_text())
    passed = code == 0 and counts["pass"] == 1 and counts["fail"] == counts["skip"] == 0 and topology.get("separate_node_networks")
    write(root / "result.json", {"status": "SCOPED_PASS" if passed else "FAIL", "process_exit": code, "counts": counts, "topology": topology,
                               "bootstrap_transport": "synthetic standard HTTPS IP SAN; local fixture root only",
                               "enrolled_transport": "signed IP locator; strict NIST PQ TLS and independent encrypted NodeControl current query",
                               "native_runtime": "NOT_RUN", "android": "NOT_RUN", "physical_device": "NOT_RUN", "public_https": "NOT_RUN", "peer_sender": "fixture using production checked Runtime/Relay API", "peer_receiver": "product Node Agent; native scope rejected before provider call", "peer_relay_fault_matrix": "scoped ciphertext queue across Hub restart; original send retry and NODE_RECEIVED ACK dedup"})
    if not passed:
        raise RuntimeError("deployment scope did not pass its required checks")


def cleanup(a):
    root = Path(a.evidence).resolve()
    entries = []
    for suffix in ("-driver", "-node-a", "-node-b"):
        name = a.identity + suffix
        id_file = root / ("driver.id" if suffix == "-driver" else suffix[1:] + ".id")
        expected = id_file.read_text().strip() if id_file.exists() else None
        if owned(name, a.identity, expected=expected):
            stop_result = docker(["stop", "--time", "5", expected], timeout=15)
            state_result = docker(["inspect", "--format", "{{json .State}}", expected])
            limits_result = docker(["inspect", "--format", "{{json .HostConfig}}", expected])
            if state_result.returncode == limits_result.returncode == 0:
                state = json.loads(state_result.stdout)
                limits = json.loads(limits_result.stdout)
                runtime = {"created_id": expected, "stop_exit": stop_result.returncode, "exit_code_after_stop": state.get("ExitCode"), "running_after_stop": state.get("Running"), "oom_killed": state.get("OOMKilled"), "nano_cpus": limits.get("NanoCpus"), "memory": limits.get("Memory"), "pids_limit": limits.get("PidsLimit"), "read_only_rootfs": limits.get("ReadonlyRootfs"), "cap_drop": limits.get("CapDrop"), "security_opt": limits.get("SecurityOpt"), "tmpfs": limits.get("Tmpfs")}
                write(root / (suffix[1:] + "-runtime.json"), runtime)
            docker(["rm", "--force", expected])
        missing, inspect_exit, list_exit = absent(name, expected)
        entries.append({"kind": "container", "name": name, "created_id": expected, "inspect_exit": inspect_exit, "list_exit": list_exit, "absent": missing})
    for suffix in ("-a", "-b"):
        name = a.identity + suffix
        id_file = root / ("network-a.id" if suffix == "-a" else "network-b.id")
        expected = id_file.read_text().strip() if id_file.exists() else None
        if owned(name, a.identity, "network", expected=expected):
            docker(["network", "rm", expected])
        missing, inspect_exit, list_exit = absent(name, expected, "network")
        entries.append({"kind": "network", "name": name, "created_id": expected, "inspect_exit": inspect_exit, "list_exit": list_exit, "absent": missing})
    if not all(e["absent"] for e in entries):
        write(root / "cleanup.json", {"resources": entries, "verified_absent": False, "private_fixture_cleanup": "BLOCKED_BY_REMAINING_RESOURCE"})
        if (root / "result.json").exists():
            result = json.loads((root / "result.json").read_text())
            result.update(status="FAIL", cleanup_verified_absent=False)
            write(root / "result.json", result)
        raise RuntimeError("owned fixture cleanup incomplete")
    fixture_receipt = root / "owned-fixture.json"
    paths = [root / json.loads(fixture_receipt.read_text())["root_name"]] if fixture_receipt.exists() else []
    for path in paths:
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != root:
            raise ValueError("unsafe fixture cleanup root")
        shutil.rmtree(path)
    shutil.rmtree(root / "commands", ignore_errors=True)
    private = root / "gate.private.jsonl"
    if private.exists() and not (root / "gate-events.json").exists():
        try:
            report(a)
        except Exception:
            data = private.read_bytes()
            if not (root / "gate-events.json").exists():
                write(root / "gate-events.json", [{"Output": "failed gate transcript sha256=" + hashlib.sha256(data).hexdigest()}])
    if private.exists():
        private.unlink()
    write(root / "cleanup.json", {"resources": entries, "verified_absent": all(e["absent"] for e in entries), "private_fixture_roots_remaining": len(list(root.glob("synthetic-ip-first-install-*")))})
    if (root / "result.json").exists():
        result = json.loads((root / "result.json").read_text())
        result.update(cleanup_verified_absent=True)
        write(root / "result.json", result)
    if not all(e["absent"] for e in entries):
        raise RuntimeError("owned fixture cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "report", "cleanup"))
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--identity", required=True)
    for field in ("builder", "amd64-package", "stage", "hub-a", "hub-b", "node-a", "node-b", "arm64-package", "arm64-rootfs", "qemu"):
        parser.add_argument("--" + field)
    args = parser.parse_args()
    if not args.identity.startswith("cicada-ip-pq-") or not all(c.isalnum() or c == "-" for c in args.identity):
        parser.error("owned fixture identity required")
    return run(args) if args.action == "run" else report(args) if args.action == "report" else cleanup(args)


if __name__ == "__main__":
    sys.exit(main())
