#!/usr/bin/env python3
"""Owned offline Hub B-to-C activation gate using real maintenance CLI and TCP.

Supply already-built production and fixture binaries from the frozen candidate.
A compilation container is never counted as this gate. Every fixture is visibly
synthetic, every Docker resource has a unique owner label, and no Runtime,
provider, model, host credentials, or resident deployment is mounted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

PINNED_IMAGE = "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
LABEL = "cicada.synthetic.hub-forward-validation"
SELECTOR = "^TestHubRestoreForwardDisposableFixture$"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    root = Path(root)
    records = {}
    for path in [root] + sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise RuntimeError("unsafe synthetic tree entry")
        records[str(path.relative_to(root))] = {"mode_raw": info.st_mode,
            "size": info.st_size if path.is_file() else 0,
            "sha256": sha(path.read_bytes()) if path.is_file() else None}
    return records


def source_inventory(repo):
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=repo).split(b"\0")
    records = {}
    for raw in sorted(filter(None, names)):
        path = repo / os.fsdecode(raw)
        info = path.lstat()
        records[os.fsdecode(raw)] = {"sha256": sha(path.read_bytes()), "mode_raw": info.st_mode}
    return records


class Gate:
    def __init__(self, repo, evidence, binary, fixture, image, build_manifest):
        self.repo, self.evidence = repo, evidence
        self.binary, self.fixture, self.image = binary, fixture, image
        self.owner = uuid.uuid4().hex
        self.commands, self.resources = [], []
        self.summary = {"result": "RUNNING", "synthetic_only": True, "synthetic_model_provider_calls": 0, "model_provider_execution": "NOT_TOUCHED",
            "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
            "build_manifest_sha256": sha(build_manifest.read_bytes()),
            "source_revision_role": "worktree checkout; effective build source is the frozen overlay manifest",
            "image_id": image, "binaries": {"product_sha256": sha(binary.read_bytes()), "fixture_sha256": sha(fixture.read_bytes())},
            "cases": [], "separate_results": {name: "NOT_RUN" for name in (
                "Android", "real_native_Runtime", "physical_device", "public_HTTPS", "production_StateDir", "source_loss_disaster_activation")}}

    def save(self):
        for name, value in (("commands", self.commands), ("summary", self.summary)):
            path = self.evidence / (name + ".json")
            path.write_text(json.dumps(value, indent=2) + "\n")
            path.chmod(0o600)

    def run(self, args, expect=None, timeout=60):
        start = time.monotonic()
        try:
            reply = subprocess.run(list(map(str, args)), cwd=self.repo, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.commands.append({"argv": list(map(str,args)), "exit": None, "timeout": True,
                "stdout_sha256": sha(exc.stdout or b""), "stderr_sha256": sha(exc.stderr or b"")})
            self.save()
            raise RuntimeError("command timed out; exit unknown") from exc
        self.commands.append({"argv": list(map(str,args)), "exit": reply.returncode,
            "elapsed_seconds": round(time.monotonic()-start, 3), "stdout_sha256": sha(reply.stdout), "stderr_sha256": sha(reply.stderr)})
        self.save()
        if expect is not None and reply.returncode != expect:
            raise RuntimeError("command exit mismatch (payload withheld; see commands.json)")
        return reply

    def docker(self, *args, **kwargs):
        if args and args[0] == "run":
            args = ("run", "--label", LABEL+"="+self.owner, *args[1:])
        return self.run(["docker", *args], **kwargs)

    def verify_owned(self, kind, name):
        args = ("inspect", name) if kind == "container" else ("network", "inspect", name)
        metadata = json.loads(self.docker(*args, expect=0).stdout)[0]
        labels = metadata.get("Config", {}).get("Labels", {}) if kind == "container" else metadata.get("Labels", {})
        if labels.get(LABEL) != self.owner:
            raise RuntimeError("refusing foreign resource cleanup")
        return metadata

    def cleanup(self):
        for kind, args in (("container", ("ps", "-aq")), ("network", ("network", "ls", "-q"))):
            found = self.docker(*args, "--filter", "label="+LABEL+"="+self.owner, expect=0)
            for name in found.stdout.decode().split():
                self.verify_owned(kind, name)
                if (kind, name) not in self.resources:
                    self.resources.append((kind, name))
        failures = []
        # Names and discovered IDs can refer to the same resource; deduplicate
        # by immutable Docker Id before deleting anything.
        owned = {}
        for kind, name in self.resources:
            metadata = self.verify_owned(kind, name)
            owned[(kind, metadata["Id"])] = name
        for (kind, _), name in sorted(owned.items(), key=lambda item: item[0][0] != "container"):
            try:
                self.verify_owned(kind, name)
                if kind == "container": self.docker("rm", "-f", name, expect=0)
                else: self.docker("network", "rm", name, expect=0)
            except Exception:
                failures.append((kind, name))
        self.resources = failures
        if failures:
            raise RuntimeError("owned Docker cleanup incomplete")

    def launch(self, name, network, root, command, mode="", state="source"):
        args = ["run", "-d", "--pull", "never", "--name", name, "--network", network,
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{root}:/synthetic", "-v", f"{self.binary}:/fixture/cicada:ro", "-v", f"{self.fixture}:/fixture/hub-forward.test:ro"]
        if mode:
            args += ["-e", "CICADA_SYNTHETIC_HUB_FORWARD_MODE="+mode,
                     "-e", "CICADA_SYNTHETIC_HUB_FORWARD_ROOT=/synthetic",
                     "-e", "CICADA_SYNTHETIC_HUB_FORWARD_STATE=/synthetic/"+state]
        self.docker(*args, self.image, *command, expect=0)
        self.resources.append(("container", name))

    def fixture_call(self, runner, mode, state="source", next_seq=3, origin=""):
        return self.docker("exec", "-e", "CICADA_SYNTHETIC_HUB_FORWARD_MODE="+mode,
            "-e", "CICADA_SYNTHETIC_HUB_FORWARD_ROOT=/synthetic",
            "-e", "CICADA_SYNTHETIC_HUB_FORWARD_STATE=/synthetic/"+state,
            "-e", "CICADA_SYNTHETIC_HUB_FORWARD_NEXT="+str(next_seq),
            "-e", "CICADA_SYNTHETIC_HUB_FORWARD_ORIGIN="+origin,
            runner, "/fixture/hub-forward.test", "-test.run", SELECTOR, expect=0)

    def cli(self, runner, *args, expect=0):
        return self.docker("exec", runner, "/fixture/cicada", "migration", *args, expect=expect)

    def ready(self, runner, hub):
        # Readiness is read-only. No write packet is retried on readiness failure.
        for _ in range(60):
            reply = self.docker("exec", runner, "curl", "--silent", "--fail", "--max-time", "1", "http://"+hub+":8787/v2/client/identity")
            if reply.returncode == 0: return
            time.sleep(0.1)
        raise RuntimeError("disposable TCP Hub readiness failed")

    def reject(self, reply):
        if reply.returncode == 0 or reply.stdout:
            raise RuntimeError("unsafe maintenance transition admitted")

    def case(self, private, fault):
        root = private / ("synthetic-"+fault); root.mkdir(mode=0o700)
        prefix = "cicada-hub-forward-"+self.owner[:10]+"-"+fault
        net, runner, original, target = (prefix+"-"+part for part in ("net", "runner", "source", "target"))
        self.docker("network", "create", "--internal", "--label", LABEL+"="+self.owner, net, expect=0)
        self.resources.append(("network", net))
        self.launch(runner, net, root, ["sleep", "infinity"])
        self.fixture_call(runner, "init")
        original_keys = inventory(root / "source" / "e2ee")
        pin = root / "synthetic-established-pin.json"
        self.cli(runner, "recovery", "register", "--source", "/synthetic/source", "--trust-file", "/synthetic/synthetic-established-pin.json", "--trust-sha256", sha(pin.read_bytes()))
        self.launch(original, net, root, ["/fixture/hub-forward.test", "-test.run", SELECTOR], "serve")
        self.ready(runner, original)
        self.docker("stop", "--time", "5", original, expect=0)
        self.cli(runner, "backup", "--state-dir", "/synthetic/source", "--output", "/synthetic/B")
        base_before = inventory(root / "B")
        self.fixture_call(runner, "advance")
        if fault != "happy": self.fixture_call(runner, fault)
        prepare = self.cli(runner, "recovery", "prepare", "--source", "/synthetic/source", "--backup", "/synthetic/B", "--capsule", "/synthetic/C", "--state-dir", "/synthetic/T", expect=None)
        if fault != "happy":
            self.reject(prepare)
            self.cli(runner, "restore", "--backup", "/synthetic/B", "--state-dir", "/synthetic/T")
            self.fixture_call(runner, "held-constructor", "T")
            self.reject(self.cli(runner, "recovery", "activate", "--source", "/synthetic/source", "--state-dir", "/synthetic/T", expect=None))
        else:
            if prepare.returncode != 0: raise RuntimeError("trusted current capsule preparation failed")
            self.fixture_call(runner, "held-constructor", "source")
            self.cli(runner, "restore", "--backup", "/synthetic/B", "--state-dir", "/synthetic/T")
            self.fixture_call(runner, "held-constructor", "T")
            restored_before = inventory(root / "T")
            all_before = inventory(root)
            self.cli(runner, "recovery", "status", "--source", "/synthetic/source", "--state-dir", "/synthetic/T")
            if inventory(root) != all_before: raise RuntimeError("status mutated synthetic state")
            # A copied restored directory cannot bootstrap with original pins.
            shutil.copytree(root / "T", root / "copy")
            self.reject(self.cli(runner, "recovery", "register", "--source", "/synthetic/copy", "--trust-file", "/synthetic/synthetic-established-pin.json", "--trust-sha256", sha(pin.read_bytes()), expect=None))
            self.fixture_call(runner, "held-constructor", "copy")
            reconciliation = json.loads(self.cli(runner, "recovery", "reconcile", "--source", "/synthetic/source", "--state-dir", "/synthetic/T").stdout)
            parked_coordinate = reconciliation.get("parked_state_dir", "")
            parked = root / Path(parked_coordinate).name
            if not parked_coordinate.startswith("/synthetic/") or inventory(parked) != restored_before:
                raise RuntimeError("original B-restored payload was not preserved after atomic exchange")
            if inventory(root / "T" / "e2ee") != original_keys:
                raise RuntimeError("forward installation changed original Hub identity bytes or modes")
            self.fixture_call(runner, "inspect", "T", 3)
            self.fixture_call(runner, "held-constructor", "T")
            self.cli(runner, "recovery", "activate", "--source", "/synthetic/source", "--state-dir", "/synthetic/T")
            self.fixture_call(runner, "fabric-constructor", "T")
            for iteration in range(2):
                if iteration == 0:
                    self.launch(target, net, root, ["/fixture/hub-forward.test", "-test.run", SELECTOR], "serve", "T")
                else: self.docker("start", target, expect=0)
                self.ready(runner, target)
                self.fixture_call(runner, "probe", "T", 4+iteration, "http://"+target+":8787")
                self.fixture_call(runner, "inspect", "T", 4+iteration)
                self.docker("stop", "--time", "5", target, expect=0)
            # A consumed authority cannot grant a second target activation.
            self.reject(self.cli(runner, "recovery", "activate", "--source", "/synthetic/source", "--state-dir", "/synthetic/copy", expect=None))
            holds = {key: value for key,value in restored_before.items() if "restore-pending" in key}
            active_inventory = inventory(root / "T")
            if not holds or any(active_inventory.get(key) != value for key,value in holds.items()):
                raise RuntimeError("activation erased or rewrote original hold lineage")
        if inventory(root / "B") != base_before: raise RuntimeError("base B backup was mutated")
        self.summary["cases"].append({"name": fault, "result": "PASS", "base_B_preserved": True,
            "current_floor_revocation_unknown_TCP_restart": fault == "happy"})
        self.cleanup()
        shutil.rmtree(root)
        self.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture-binary", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True, help="supervisor frozen effective source/build manifest (Main plus owned overlays)")
    parser.add_argument("--image", default=PINNED_IMAGE)
    args = parser.parse_args(argv)
    os.umask(0o077)
    repo, evidence = args.repo.resolve(), args.evidence.absolute()
    parent = repo / ".cicada-data" / "restore-validation"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.parent.resolve() != parent.resolve() or evidence.exists():
        parser.error("evidence must be a new immediate child of task-local restore-validation")
    evidence.mkdir(mode=0o700)
    gate = Gate(repo, evidence, args.binary.resolve(), args.fixture_binary.resolve(), args.image, args.build_manifest.resolve())
    before = source_inventory(repo)
    (evidence / "source-before.json").write_text(json.dumps(before, indent=2)+"\n")
    private = Path(tempfile.mkdtemp(prefix="synthetic-private-", dir=evidence))
    try:
        image = json.loads(gate.docker("image", "inspect", args.image, expect=0).stdout)[0]
        if image["Id"] != args.image: raise RuntimeError("image must be an exact already-local immutable image ID")
        gate.summary["image_repo_digests"] = image.get("RepoDigests", [])
        for fault in ("happy", "lost-unknown", "pending"):
            gate.case(private, fault)
        gate.summary["result"] = "PASS"
    except Exception as exc:
        gate.summary["result"], gate.summary["failure"] = "FAIL", str(exc)
    finally:
        try: gate.cleanup()
        except Exception as exc: gate.summary["result"],gate.summary["cleanup_failure"]="FAIL",str(exc)
        # Private keys are never retained as evidence. Container cleanup precedes
        # fixture removal; a failed cleanup keeps its exact owned references.
        if not gate.resources:
            shutil.rmtree(private)
        after = source_inventory(repo)
        (evidence / "source-after.json").write_text(json.dumps(after, indent=2)+"\n")
        gate.summary["source_unchanged"] = before == after
        gate.summary["private_fixture_cleanup"] = not private.exists()
        if before != after: gate.summary["result"] = "FAIL"
        gate.save()
    print(json.dumps({"result":gate.summary["result"],"evidence":str(evidence)}), flush=True)
    return 0 if gate.summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
