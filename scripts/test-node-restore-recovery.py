#!/usr/bin/env python3
"""Offline, owned disposable production CLI restore/recovery fault gate.

Only synthetic trees are mounted. Fault controls exist in the command test
binary, never in the production binary. No native Runtime/provider is invoked.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid

PINNED_IMAGE = "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
NODE = "synthetic-restore-node"
LABEL = "cicada.synthetic.restore-validation"
PLAN = hashlib.sha256(b"synthetic immutable restore plan; no retry authorization").hexdigest()
STATUS_FIELDS = {"hub_id", "node_id", "binding_id", "binding_version", "node_key_id",
                 "node_key_version", "node_key_epoch", "hub_key_id", "hub_key_version",
                 "credential_version", "accepted_highwater", "operations"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    """Raw modes and byte hashes, including every advisory lock and hold."""
    root = Path(root)
    result = {}
    for path in [root] + sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError("unsafe fixture inventory type")
        result[str(path.relative_to(root))] = {
            "mode_raw": info.st_mode, "size": info.st_size if path.is_file() else 0,
            "sha256": sha(path.read_bytes()) if path.is_file() else None,
        }
    return result


def source_inventory(repo):
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=repo).split(b"\0")
    result = {}
    for raw in sorted(filter(None, names)):
        name = os.fsdecode(raw)
        path = repo / name
        info = path.lstat()
        result[name] = {"sha256": sha(path.read_bytes()), "mode_raw": info.st_mode}
    return result


def bounded_status(data, expected, secrets=()):
    for secret in secrets:
        if secret and secret in data:
            raise RuntimeError("public output secret scan failed")
    report = json.loads(data)
    if set(report) != {"restore_digest", "plan_digest", "agent_may_start", "status"} or report["agent_may_start"] is not False:
        raise RuntimeError("unsafe recovery report fields or admission")
    if report["plan_digest"] != PLAN or len(report["restore_digest"]) != 64:
        raise RuntimeError("query plan/restore binding mismatch")
    status = report["status"]
    if set(status) != STATUS_FIELDS or status["accepted_highwater"] != 40 or status["node_id"] != NODE:
        raise RuntimeError("unbounded or incorrect authorized metadata")
    operations = status["operations"]
    if len(operations) != 1 or set(operations[0]) != {"operation_id", "sequence", "request_digest", "state"}:
        raise RuntimeError("unsafe operation metadata")
    if operations[0]["state"] != expected or operations[0]["sequence"] != 7 or operations[0]["operation_id"] != "synthetic-restored-status":
        raise RuntimeError("incorrect authentic receipt metadata")
    return report


def node_metadata(restored):
    node = Path(restored) / "nodes" / ("node-"+NODE)
    def read(dbname, query):
        with sqlite3.connect((node / dbname).as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            return db.execute(query).fetchone()[0]
    return {
        "local_sequence": read("node-crypto-state.sqlite", "SELECT MAX(last_sequence) FROM node_crypto_sequences"),
        "replay_rows": read("node-crypto-state.sqlite", "SELECT count(*) FROM node_crypto_replay"),
        "uncertain_deliveries": read("inbox.sqlite", "SELECT count(*) FROM node_inbox_deliveries WHERE state='INJECTION_UNCERTAIN'"),
        "uncertain_attempts": read("inbox.sqlite", "SELECT count(*) FROM node_inbox_attempts WHERE state='INJECTION_UNCERTAIN'"),
        "owner_trust_rows": read("node-crypto-state.sqlite", "SELECT count(*) FROM node_crypto_owner_key_trust"),
    }


def hub_recovery_digest(hub):
    # Hash all columns of the relevant authoritative tables without retaining
    # bearer/grant/packet contents. The read cannot initialize or migrate state.
    with sqlite3.connect((Path(hub) / "cicada.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        value = []
        for table in ("node_control_rpc_sequences_v1", "node_control_rpc_inbox_v1", "node_control_key_bindings_v1", "fabric_node_credentials", "node_owner_bindings_v2"):
            rows = db.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall()
            value.append((table, repr(rows)))
    return sha(repr(value).encode())


class Gate:
    def __init__(self, repo, cache, evidence):
        self.repo, self.cache, self.evidence = repo, cache, evidence
        self.owner = uuid.uuid4().hex
        self.commands = []
        self.resources = []
        self.summary = {"result": "RUNNING", "synthetic_only": True, "model_provider_calls": 0,
                        "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                        "image_id": PINNED_IMAGE, "cases": [], "skips": {
                            "Android": "NOT_RUN", "real_native_Runtime": "NOT_RUN", "physical_device": "NOT_RUN",
                            "public_HTTPS": "NOT_RUN", "production_StateDir": "NOT_RUN"}}

    def save(self):
        (self.evidence / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        (self.evidence / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")

    def run(self, args, expect=None, timeout=300):
        started = time.time()
        try:
            result = subprocess.run(args, cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.commands.append({"argv":args,"exit":None,"timeout":True,"elapsed_seconds":round(time.time()-started,3),
                                  "stdout_sha256":sha(exc.stdout or b""),"stderr_sha256":sha(exc.stderr or b"")})
            self.save()
            raise RuntimeError("command timed out; exit unknown, gate failed") from exc
        self.commands.append({"argv": args, "exit": result.returncode, "elapsed_seconds": round(time.time()-started, 3),
                              "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
        self.save()
        if expect is not None and result.returncode != expect:
            raise RuntimeError("command exit mismatch; inspect commands.json (output withheld)")
        return result

    def docker(self, *args, **kw):
        if args and args[0]=="run":
            args=("run","--label",LABEL+"="+self.owner,*args[1:])
        return self.run(["docker", *map(str, args)], **kw)

    def verify_owned(self, kind, name):
        result = self.docker("inspect" if kind == "container" else "network", *([] if kind == "container" else ["inspect"]), name, expect=0)
        metadata = json.loads(result.stdout)[0]
        labels = metadata.get("Config", {}).get("Labels", {}) if kind == "container" else metadata.get("Labels", {})
        if labels.get(LABEL) != self.owner:
            raise RuntimeError("refusing cleanup of unowned Docker resource")
        return metadata

    def cleanup(self):
        # --rm does not imply that a client timeout stopped its daemon process.
        # Discover only this run's labelled containers, then verify each label.
        found=self.docker("ps","-aq","--filter","label="+LABEL+"="+self.owner,expect=0)
        for name in found.stdout.decode().split():
            metadata=self.verify_owned("container",name)
            canonical=metadata.get("Name","").lstrip("/")
            if ("container",name) not in self.resources and ("container",canonical) not in self.resources:
                self.resources.append(("container",name))
        networks=self.docker("network","ls","-q","--filter","label="+LABEL+"="+self.owner,expect=0)
        for name in networks.stdout.decode().split():
            metadata=self.verify_owned("network",name)
            canonical=metadata.get("Name","")
            if ("network",name) not in self.resources and ("network",canonical) not in self.resources:
                # Networks must be removed after their attached containers.
                self.resources.insert(0,("network",name))
        errors = []
        failed = []
        for kind, name in reversed(self.resources):
            try:
                self.verify_owned(kind, name)
                self.docker("rm", "-f", name, expect=0) if kind == "container" else self.docker("network", "rm", name, expect=0)
            except Exception as exc:
                errors.append(str(exc))
                failed.append((kind,name))
        self.resources=list(reversed(failed))
        if errors:
            raise RuntimeError("owned cleanup incomplete: " + "; ".join(errors))

    def build(self):
        image = json.loads(self.docker("image", "inspect", PINNED_IMAGE, expect=0).stdout)[0]
        if image["Id"] != PINNED_IMAGE:
            raise RuntimeError("pinned offline Go image mismatch")
        self.summary["image_repo_digests"] = image.get("RepoDigests", [])
        (self.evidence / "bin").mkdir(mode=0o700)
        cache_dir = self.repo / ".cicada-data" / "restore-validation" / "gocache"
        cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        common = ["run", "--rm", "--pull", "never", "--network", "none", "-v", f"{self.repo}:/src:ro",
                  "-v", f"{self.cache}:/gomodcache:ro", "-v", f"{cache_dir}:/gocache", "-v", f"{self.evidence}/bin:/out",
                  "-w", "/src/cicada-go", "-e", "GOTOOLCHAIN=local", "-e", "GOPROXY=off", "-e", "GOSUMDB=off",
                  "-e", "GOMODCACHE=/gomodcache", "-e", "GOCACHE=/gocache", PINNED_IMAGE]
        common[-1:-1]=["-e","GOFLAGS=-mod=readonly -buildvcs=false"]
        self.docker(*common, "go", "version", expect=0)
        self.docker(*common, "go", "build", "-o", "/out/cicada", "./cmd/cicada", expect=0)
        self.docker(*common, "go", "test", "-c", "-o", "/out/restore-fixture.test", "./cmd/cicada", expect=0)
        self.summary["binaries"] = {p.name: sha(p.read_bytes()) for p in (self.evidence / "bin").iterdir()}

    def fixture(self, hub, node, mode, fault=""):
        return self.docker("run", "--rm", "--pull", "never", "--network", "none",
	                       "--user", f"{os.getuid()}:{os.getgid()}",
                           "-v", f"{self.evidence}/bin:/bin-fixture:ro", "-v", f"{hub}:/hub", "-v", f"{node}:/node",
                           "-e", f"CICADA_SYNTHETIC_RESTORE_MODE={mode}", "-e", "CICADA_SYNTHETIC_HUB=/hub",
                           "-e", "CICADA_SYNTHETIC_NODE=/node/source", "-e", "CICADA_SYNTHETIC_ORIGIN=http://hub.fixture.localhost:8787",
                           "-e", f"CICADA_SYNTHETIC_FAULT={fault}", PINNED_IMAGE,
                           "/bin-fixture/restore-fixture.test", "-test.run", "^TestMachineRestoreRecoveryDisposableFixture$", expect=0)

    def case(self, root, name):
        print("restore recovery case:", name, flush=True)
        case = root / name; case.mkdir(mode=0o700)
        hub, node = case / "hub", case / "node"
        hub.mkdir(mode=0o700); node.mkdir(mode=0o700)
        self.fixture(hub, node, "init")
        if name in {"missing-receipt", "uncertain", "stale-epoch", "highwater-rollback", "digest-mismatch", "revoked"}:
            self.fixture(hub, node, "fault", name)
        network, hub_name, node_name = ["cicada-restore-"+self.owner[:12]+"-"+part for part in ("net", "hub", "node")]
        self.docker("network", "create", "--internal", "--label", LABEL+"="+self.owner, network, expect=0)
        self.resources.append(("network", network))
        self.docker("run", "-d", "--name", hub_name, "--pull", "never", "--network", network,
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--network-alias", "hub.fixture.localhost", "--label", LABEL+"="+self.owner, "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "-v", f"{hub}:/hub", "-v", f"{self.evidence}/bin:/bin-fixture:ro",
                    "-e", "CICADA_SYNTHETIC_RESTORE_MODE=serve", "-e", "CICADA_SYNTHETIC_HUB=/hub",
                    "-e", "CICADA_SYNTHETIC_NODE=/node/source", "-e", "CICADA_SYNTHETIC_ORIGIN=http://hub.fixture.localhost:8787",
                    PINNED_IMAGE, "/bin-fixture/restore-fixture.test", "-test.run", "^TestMachineRestoreRecoveryDisposableFixture$", expect=0)
        self.resources.append(("container", hub_name))
        self.docker("run", "-d", "--name", node_name, "--pull", "never", "--network", network,
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--label", LABEL+"="+self.owner, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "-v", f"{node}:/node", "-v", f"{self.evidence}/bin:/bin-fixture:ro", PINNED_IMAGE, "sleep", "infinity", expect=0)
        self.resources.append(("container", node_name))
        def cli(*args, expect=None):
            return self.docker("exec", node_name, "/bin-fixture/cicada", "machine", *args, expect=expect, timeout=60)
        # Poll only public identity readiness. Never send or retry a write.
        for _ in range(60):
            ready = self.docker("exec", node_name, "curl", "--silent", "--fail", "--max-time", "1", f"http://{hub_name}:8787/v2/node/identity")
            if ready.returncode == 0: break
            time.sleep(0.1)
        else: raise RuntimeError("synthetic production handler did not start")
        cli("backup", "--id", NODE, "--state-dir", "/node/source", "--output", "/node/archive", expect=0)
        cli("verify", "--backup", "/node/archive", expect=0)
        cli("restore", "--backup", "/node/archive", "--state-dir", "/node/restored", expect=0)
        restored = node / "restored"
        if name == "tampered-archive":
            path = node / "archive" / "payload" / "identity.json"
            path.write_bytes(path.read_bytes()+b"synthetic tamper")
        if name == "missing-shared-fence":
            (restored / "node-provider-admission.sqlite3").unlink()
        if name == "read-only-lock-mode":
            os.chmod(restored / "nodes" / ".locks" / ("node-"+NODE+".maintenance.lock"), 0o400)
        if name == "changed-registration":
            (restored / "nodes" / ".recovery-pending" / ("node-"+NODE+".json")).write_text("synthetic invalid registration")
        before = inventory(restored)
        (self.evidence / (name+"-state-before.json")).write_text(json.dumps(before, indent=2)+"\n")
        hub_before = hub_recovery_digest(hub)
        secrets = [b"SYNTHETIC PRIVATE PAYLOAD DO NOT LOG", b"KEMPrivate", b"kem_private", b"signing_private", b"private_identity"]
        for path in (restored / "nodes" / ("node-"+NODE)).rglob("*"):
            if not path.is_file(): continue
            try: secret_file=json.loads(path.read_bytes())
            except (ValueError,UnicodeDecodeError): continue
            if isinstance(secret_file,dict):
                for field in ("kem_private","signing_private","pending_packet"):
                    value=secret_file.get(field)
                    if isinstance(value,str) and value: secrets.append(value.encode())
        token = (restored / "nodes" / ("node-"+NODE) / "relay.token").read_bytes().strip()
        if token: secrets += [token, base64.urlsafe_b64encode(hashlib.sha256(token).digest()).rstrip(b"=")]
        query = ["recovery", "query", "--backup", "/node/archive", "--state-dir", "/node/restored", "--plan-sha256", PLAN]
        expected = {"complete":"COMPLETE", "missing-receipt":"NOT_RECORDED", "uncertain":"UNCERTAIN"}.get(name)
        report = {"case":name, "query_expected": expected or "DENIED", "secret_scan":True,
                  "receipt_absence_is_nonexecution":False, "quarantine_released":False}
        for phase in ("initial", "restart"):
            result = cli(*query)
            if any(secret and secret in result.stdout+result.stderr for secret in secrets):
                raise RuntimeError("public query secret scan failed")
            if expected:
                if result.returncode != 0: raise RuntimeError("authenticated query failed")
                report[phase+"_report"] = bounded_status(result.stdout, expected, secrets)
            elif result.returncode == 0 or result.stdout:
                raise RuntimeError("fault query admitted or exposed metadata")
            if inventory(restored) != before or hub_recovery_digest(hub) != hub_before:
                raise RuntimeError("read/restart changed keys, replay, counters, fences, holds or Hub recovery tables")
            report[phase+"_query_exit"] = result.returncode
            if phase == "initial":
                self.docker("restart", node_name, hub_name, expect=0)
                # The next authenticated read is a new packet; no uncertain write
                # is dispatched, repeated or reconciled during restart.
                for _ in range(60):
                    ready = self.docker("exec", node_name, "curl", "--silent", "--fail", "--max-time", "1", f"http://{hub_name}:8787/v2/node/identity")
                    if ready.returncode==0: break
                    time.sleep(0.1)
                else: raise RuntimeError("restarted fixture did not become ready")
        metadata = node_metadata(restored)
        if metadata != {"local_sequence":9,"replay_rows":1,"uncertain_deliveries":1,"uncertain_attempts":1,"owner_trust_rows":1}:
            raise RuntimeError("restart lost crypto, trust or uncertain native lineage")
        report["node_metadata"] = metadata
        writes = [
            ["agent","--id",NODE,"--state-dir","/node/restored","--control-url","http://hub.fixture.localhost:8787","--relay-only","--once"],
            ["node-control","mark-uncertain","--node-id",NODE,"--state-dir","/node/restored"],
            ["node-control","inspect","--node-id",NODE,"--state-dir","/node/restored"],
            ["node-control","reconcile-provider","--node-id",NODE,"--state-dir","/node/restored","--writer-root","/node/alternate","--resolution","COMPLETED_CONFIRMED","--evidence-id","synthetic-unverified","--observed-at","2026-10-02T00:00:00Z"],
            ["backup","--id",NODE,"--state-dir","/node/restored","--output","/node/forbidden-backup"],
            ["restore","--backup","/node/archive","--state-dir","/node/restored"],
        ]
        (node / "alternate").mkdir(mode=0o700)
        for operation, args_file in (("trust-owner-key","synthetic-trust-args.json"),("revoke-owner-key","synthetic-revoke-args.json")):
            writes.append([operation,"--id",NODE,"--state-dir","/node/restored",*json.loads((node / "source" / args_file).read_text())])
        report["writes"] = []
        for args in writes:
            write_before = inventory(restored)
            result = cli(*args)
            reasons=(b"quarantine",b"recovery is pending")
            if args[0]=="restore": reasons=(b"not new or empty",b"not empty",b"backup is incomplete or invalid",b"differs from manifest")
            if result.returncode==0 or result.stdout or not any(word in result.stderr.lower() for word in reasons):
                raise RuntimeError("write did not fail at recovery guard")
            after = inventory(restored)
            delta = {key:{"before":write_before.get(key),"after":after.get(key)} for key in set(write_before)|set(after) if write_before.get(key)!=after.get(key)}
            if delta:
                raise RuntimeError("write denial changed durable state or raw modes")
            report["writes"].append({"entrypoint":args[0]+(" "+args[1] if args[0]=="node-control" else ""),"exit":result.returncode,"advisory_delta":delta})
        if hub_recovery_digest(hub)!=hub_before: raise RuntimeError("denied writes changed authoritative Hub recovery tables")
        # There is no supported quarantine-release transition. Exercise the
        # actual recovery command dispatcher and assert no new state is made.
        transition_before=inventory(restored)
        transition=cli("recovery","resume","--state-dir","/node/restored")
        if transition.returncode==0 or transition.stdout or b"usage:" not in transition.stderr or inventory(restored)!=transition_before:
            raise RuntimeError("unsupported recovery transition admitted")
        report["unavailable_transition"]={"entrypoint":"machine recovery resume","exit":transition.returncode,"supported":False}
        report["hub_recovery_tables_sha256"] = hub_before
        (self.evidence / (name+"-state-after.json")).write_text(json.dumps(inventory(restored), indent=2)+"\n")
        self.summary["cases"].append(report)
        self.cleanup()
        shutil.rmtree(case)
        self.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--module-cache", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True, help="new directory under this repo .cicada-data/restore-validation")
    args = parser.parse_args(argv)
    repo, cache = args.repo.resolve(), args.module_cache.resolve()
    parent = repo / ".cicada-data" / "restore-validation"
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    evidence = args.evidence.absolute()
    if evidence.parent.resolve()!=parent.resolve() or evidence.exists():
        parser.error("evidence must be a new immediate child of task-local restore-validation")
    evidence.mkdir(mode=0o700)
    before = source_inventory(repo)
    (evidence / "source-before.json").write_text(json.dumps(before,indent=2)+"\n")
    gate = Gate(repo, cache, evidence)
    private = Path(tempfile.mkdtemp(prefix=".synthetic-",dir=evidence))
    try:
        gate.build()
        for name in ("complete","missing-receipt","uncertain","stale-epoch","highwater-rollback","digest-mismatch","revoked","tampered-archive","missing-shared-fence","read-only-lock-mode","changed-registration"):
            gate.case(private,name)
        gate.summary["result"]="PASS"
    except Exception as exc:
        gate.summary["result"]="FAIL"
        gate.summary["failure"]=str(exc)
    finally:
        try: gate.cleanup()
        except Exception as exc: gate.summary["result"]="FAIL"; gate.summary["cleanup_failure"]=str(exc)
        try: shutil.rmtree(private)
        except Exception as exc: gate.summary["result"]="FAIL"; gate.summary["private_cleanup_failure"]=str(exc)
        after=source_inventory(repo)
        (evidence / "source-after.json").write_text(json.dumps(after,indent=2)+"\n")
        gate.summary["source_unchanged"] = before==after
        gate.summary["private_fixture_cleanup"] = not private.exists()
        if before!=after: gate.summary["result"]="FAIL"
        gate.save()
    print(json.dumps({"result":gate.summary["result"],"evidence":str(evidence)}),flush=True)
    return 0 if gate.summary["result"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(main())
