#!/usr/bin/env python3
"""Bounded offline Task privacy gate. No real Hub, Runtime, credentials or keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

IMAGE = "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
LABEL = "cicada.task-privacy.owner"
SENTINELS = (
    "SYNTHETIC_PRIVATE_TASK_OBJECTIVE_SENTINEL",
    "SYNTHETIC_PRIVATE_TASK_CRITERIA_SENTINEL",
    "SYNTHETIC_PRIVATE_TASK_RESULT_SENTINEL",
)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_inventory(root):
    result = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"],
                            cwd=root, check=True, capture_output=True)
    rows = {}
    for raw in sorted(set(result.stdout.split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = root / name
        info = path.lstat()
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        rows[name] = {"sha256": sha(data), "raw_mode": info.st_mode, "size": len(data)}
    return rows


def find_tokens(value):
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            if "token" in key.lower() and isinstance(child, str) and child:
                found.append(child)
            found.extend(find_tokens(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(find_tokens(child))
    return found


def is_secret(data, secrets):
    return (any(secret and secret.encode() in data for secret in secrets)
            or bool(re.search(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", data)))


class Gate:
    def __init__(self, root, evidence, cache, image=IMAGE):
        self.root, self.evidence, self.cache, self.image = root, evidence, cache, image
        self.owner = uuid.uuid4().hex
        self.commands = []
        self.secrets = list(SENTINELS) + ["synthetic-task-manager-bearer"]
        self.resources = {"container": [], "network": []}
        self.cleanup_errors = []
        self.secret_scan_passed = True

    def safe_output(self, prefix, stream, data):
        safe = not is_secret(data, self.secrets)
        self.secret_scan_passed &= safe
        if safe:
            path = self.evidence / (prefix + "." + stream)
            path.write_bytes(data)
            path.chmod(0o600)
        return {"sha256": sha(data), "size": len(data), "secret_scan_passed": safe,
                "retained": safe}

    def run(self, argv, timeout=60, check=True):
        index = len(self.commands)
        prefix = f"command-{index:03d}"
        record = {"argv": argv, "timeout_seconds": timeout}
        self.commands.append(record)
        save(self.evidence / "commands.json", self.commands)
        started = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=self.root, capture_output=True, timeout=timeout)
            record.update(exit_code=result.returncode, timed_out=False,
                          stdout=self.safe_output(prefix, "stdout", result.stdout),
                          stderr=self.safe_output(prefix, "stderr", result.stderr))
        except subprocess.TimeoutExpired as error:
            record.update(exit_code=None, timed_out=True,
                          stdout=self.safe_output(prefix, "stdout", error.stdout or b""),
                          stderr=self.safe_output(prefix, "stderr", error.stderr or b""))
            result = None
        except OSError as error:
            record.update(exit_code=None, launch_error=type(error).__name__)
            result = None
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save(self.evidence / "commands.json", self.commands)
        if check and (result is None or result.returncode != 0):
            raise RuntimeError(f"command-{index:03d} failed; see recorded actual exit")
        if check and not self.secret_scan_passed:
            raise RuntimeError("output secret scan failed; offending output not retained")
        return result

    def docker(self, args, **kwargs):
        return self.run(["docker", *args], **kwargs)

    def verify_owned(self, kind, name):
        result = self.docker([kind, "inspect", name], check=False)
        if result is None or result.returncode:
            return False
        objects = json.loads(result.stdout)
        if len(objects) != 1:
            return False
        obj = objects[0]
        labels = obj.get("Config", {}).get("Labels", {}) if kind == "container" else obj.get("Labels", {})
        actual_name = obj.get("Name", "").lstrip("/")
        return labels.get(LABEL) == self.owner and actual_name.startswith("task-privacy-" + self.owner)

    def cleanup(self):
        # Discover even resources created immediately before a client timeout.
        for kind in ("container", "network"):
            args = ["ps", "-a"] if kind == "container" else ["network", "ls"]
            result = self.docker([*args, "--filter", "label=" + LABEL + "=" + self.owner,
                                  "--format", "{{.Names}}" if kind == "container" else "{{.Name}}"], check=False)
            discovered = [] if result is None or result.returncode else result.stdout.decode().splitlines()
            if result is None or result.returncode:
                self.cleanup_errors.append(kind + " discovery failed")
            for name in sorted(set(self.resources[kind] + discovered)):
                if not self.verify_owned(kind, name):
                    self.cleanup_errors.append(kind + " ownership verification failed: " + name)
                    continue
                args = ["rm", "-f", name] if kind == "container" else ["network", "rm", name]
                result = self.docker(args, check=False)
                if result is None or result.returncode:
                    self.cleanup_errors.append(kind + " removal failed: " + name)

    def build(self, artifacts):
        cache = self.root / ".cicada-data/task-privacy/gocache"
        cache.mkdir(parents=True, exist_ok=True)
        base = ["run", "--rm", "--pull", "never", "--network", "none", "--label", LABEL + "=" + self.owner,
                "--name", "task-privacy-" + self.owner + "-build", "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", str(self.root / "cicada-go") + ":/src:ro", "-v", str(self.cache) + ":/gomod:ro",
                "-v", str(cache) + ":/gocache:rw", "-v", str(artifacts) + ":/artifacts:rw",
                "-e", "GOTOOLCHAIN=local", "-e", "GOPROXY=off", "-e", "GOSUMDB=off",
                "-e", "GOMODCACHE=/gomod", "-e", "GOCACHE=/gocache",
                "-e", "GOFLAGS=-mod=readonly -buildvcs=false", "-w", "/src", self.image]
        self.docker([*base, "go", "build", "-o", "/artifacts/cicada", "./cmd/cicada"], timeout=240)
        self.docker([*base, "go", "test", "-c", "-o", "/artifacts/privacy.test", "./cmd/cicada"], timeout=240)
        save(self.evidence / "binaries.json", {name: sha((artifacts / name).read_bytes())
                                              for name in ("cicada", "privacy.test")})

    def wait_file(self, path, container, timeout=90):
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if path.is_file():
                return
            result = self.docker(["inspect", "--format", "{{.State.Running}}", container])
            if result.stdout.strip() != b"true":
                self.docker(["logs", container], check=False)
                raise RuntimeError("fixture exited before readiness")
            time.sleep(0.5)
        self.docker(["logs", container], check=False)
        raise RuntimeError("fixture readiness timed out")

    def wait_exit(self, name):
        result = self.docker(["wait", name], timeout=240)
        if result.stdout.strip() != b"0":
            self.docker(["logs", name], check=False)
            raise RuntimeError("fixture process exit was " + result.stdout.decode().strip())

    def load_secrets(self, private):
        self.secrets.extend(find_tokens(json.loads((private / "config.json").read_text())))
        # Scan exact encoded private key components too; never retain their values.
        for path in private.rglob("*.json"):
            if path.stat().st_size > 1 << 20:
                continue
            try:
                value = json.loads(path.read_bytes())
            except (ValueError, UnicodeError):
                continue
            def visit(item):
                if isinstance(item, dict):
                    for key, child in item.items():
                        if "private" in key.lower() and isinstance(child, str) and len(child) > 16:
                            self.secrets.append(child)
                        visit(child)
                elif isinstance(item, list):
                    for child in item:
                        visit(child)
            visit(value)

    def fixtures(self, artifacts, private, public):
        network = "task-privacy-" + self.owner + "-net"
        self.docker(["network", "create", "--internal", "--label", LABEL + "=" + self.owner, network])
        self.resources["network"].append(network)
        hub = "task-privacy-" + self.owner + "-hub"
        node = "task-privacy-" + self.owner + "-node"
        common = ["run", "-d", "--pull", "never", "--network", network, "--label", LABEL + "=" + self.owner,
                  "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                  "-v", str(self.root / "cicada-go") + ":/src:ro", "-v", str(artifacts) + ":/artifacts:ro",
                  "-v", str(private) + ":/node-private:rw", "-v", str(public) + ":/public:rw",
                  "-e", "CICADA_TASK_PRIVACY_NODE_ROOT=/node-private", "-e", "CICADA_TASK_PRIVACY_PUBLIC_ROOT=/public",
                  "-e", "CICADA_TASK_PRIVACY_CLI=/artifacts/cicada", "-w", "/src/cmd/cicada"]
        self.docker([*common, "--name", hub, "--network-alias", "task-privacy-hub.localhost",
                     "-e", "CICADA_TASK_PRIVACY_FIXTURE_ROLE=hub", self.image,
                     "/artifacts/privacy.test", "-test.run", "^TestTaskPeerPrivacyIsolatedHubFixture$", "-test.timeout", "480s"])
        self.resources["container"].append(hub)
        self.wait_file(public / "hub-ready.json", hub)
        self.load_secrets(private)
        info = json.loads(self.docker(["inspect", hub]).stdout)[0]
        address = info["NetworkSettings"]["Networks"][network]["IPAddress"]
        self.docker([*common, "--name", node, "--add-host", "task-privacy-hub.localhost:" + address,
                     "-e", "CICADA_TASK_PRIVACY_FIXTURE_ROLE=node", self.image,
                     "/artifacts/privacy.test", "-test.run", "^TestTaskPeerPrivacyIsolatedNodeFixture$", "-test.timeout", "180s"])
        self.resources["container"].append(node)
        self.wait_exit(node)
        self.docker(["logs", node])
        self.load_secrets(private)
        if not (public / "node-initial-report.json").is_file():
            raise RuntimeError("initial case report missing")
        self.docker(["restart", node])
        self.wait_exit(node)
        self.docker(["logs", node])
        self.wait_exit(hub)
        self.docker(["logs", hub])
        reports = {}
        for name in ("hub-ready.json", "node-initial-report.json", "node-restart-report.json", "hub-report.json"):
            data = (public / name).read_bytes()
            if is_secret(data, self.secrets):
                self.secret_scan_passed = False
                raise RuntimeError("public report secret scan failed")
            reports[name] = json.loads(data)
            save(self.evidence / name, reports[name])
        if any(reports[name].get("status") != "PASS" for name in ("node-initial-report.json", "node-restart-report.json")):
            raise RuntimeError("case report did not pass")
        if not reports["hub-report.json"].get("private_prose_absent_in_http"):
            raise RuntimeError("Hub received private prose")
        return reports


def execute(args):
    root, evidence, cache = args.root.resolve(), args.evidence.resolve(), args.module_cache.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    evidence.chmod(0o700)
    gate = Gate(root, evidence, cache, args.image)
    summary = {"status": "FAIL", "owner": gate.owner, "image": args.image,
               "native_runtime": "NOT_RUN", "android": "NOT_RUN", "physical_device": "NOT_RUN", "public_https": "NOT_RUN"}
    private = None
    before = source_inventory(root)
    save(evidence / "source-before.json", before)
    save(evidence / "invocation.json", {"argv": os.sys.argv, "attribution": "overlay + local uncommitted privacy source", "source_inventory": "source-before.json"})
    try:
        info = json.loads(gate.docker(["image", "inspect", args.image]).stdout)[0]
        if info["Id"] != args.image:
            raise RuntimeError("pinned image mismatch")
        save(evidence / "image.json", {"Id": info["Id"], "RepoDigests": info.get("RepoDigests", [])})
        artifacts = evidence / "bin"
        artifacts.mkdir(mode=0o700)
        public = evidence / "public-work"
        public.mkdir(mode=0o700)
        private = Path(tempfile.mkdtemp(prefix="task-privacy-private-", dir=root / ".cicada-data/task-privacy"))
        gate.build(artifacts)
        reports = gate.fixtures(artifacts, private, public)
        summary["cases"] = reports["node-initial-report.json"]["cases"] + reports["node-restart-report.json"]["cases"]
        summary["status"] = "PASS"
    except Exception as error:
        # Only controlled diagnostics/types; exceptions may contain local secret-bearing data.
        summary["failure_type"] = type(error).__name__
        summary["failure"] = str(error) if isinstance(error, RuntimeError) else "see exact command records"
    finally:
        try:
            gate.cleanup()
        except Exception as error:
            gate.cleanup_errors.append("cleanup exception " + type(error).__name__)
        if private is not None:
            try:
                shutil.rmtree(private)
            except OSError as error:
                gate.cleanup_errors.append("private fixture removal " + type(error).__name__)
        summary["private_fixture_removed"] = private is None or not private.exists()
        after = source_inventory(root)
        save(evidence / "source-after.json", after)
        summary.update(source_unchanged=before == after, secret_scan_passed=gate.secret_scan_passed,
                       cleanup_errors=gate.cleanup_errors, cleanup_passed=not gate.cleanup_errors,
                       command_count=len(gate.commands))
        if not all((summary["source_unchanged"], summary["secret_scan_passed"], summary["cleanup_passed"], summary["private_fixture_removed"])):
            summary["status"] = "FAIL"
        save(evidence / "report.json", summary)
    print(json.dumps({"status": summary["status"], "evidence": str(evidence)}))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--module-cache", type=Path, required=True)
    parser.add_argument("--image", default=IMAGE, choices=[IMAGE])
    raise SystemExit(execute(parser.parse_args()))
