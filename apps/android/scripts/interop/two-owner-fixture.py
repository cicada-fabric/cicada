#!/usr/bin/env python3
"""Manage only the disposable, fixed-image two-Owner authorization fixture.

Owner registration uses the shipped offline owner-key CLI while the disposable
Hub is stopped. This helper never opens or queries the Hub database itself.
All private identities, Node credentials and short codes remain outside Git.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


IMAGE = "sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7"
GO_IMAGE = "sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244"
EMULATOR_IMAGE = "sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f"
NODE_HELPER_SHA = "a8277b7cf17e527c7d9e247e59f46d26577332c1c4e2ab50c5b625f2136b214d"
REVISION = "967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a"
CATALOG = "25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9"
ARCHIVE_SHA = "7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a"
SCHEMA = "cicada.client-two-owner-fixture.v1"
LABEL = "org.cicada.client-two-owner-fixture"
BASE = Path("/gpu1-share/data/cicada-client")
CORE = Path("/home/zyf/CICADA")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def write_private(path, value):
    path = Path(path)
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    path.chmod(0o600)


def run(state, name, command, *, secret_output=False, expected=(0,), timeout=90, input_data=None):
    started = time.monotonic()
    proc = subprocess.run(command, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    entry = {"step": name, "command": command, "exit_code": proc.returncode,
             "seconds": round(time.monotonic() - started, 3),
             "output_sha256": hashlib.sha256(proc.stdout).hexdigest()}
    evidence = Path(state["evidence"])
    with (evidence / "fixture-commands.jsonl").open("a") as out:
        out.write(json.dumps(entry) + "\n")
    (evidence / "fixture-commands.jsonl").chmod(0o600)
    if not secret_output:
        write_private(evidence / (name + ".log"), proc.stdout)
    if proc.returncode not in expected:
        raise RuntimeError(f"{name} exited {proc.returncode}; output is private")
    return proc.stdout.decode(errors="replace")


def get_json(url):
    with OPENER.open(url, timeout=5) as response:
        return json.load(response)


def start_hub(state):
    root = Path(state["root"])
    run(state, "hub-start", ["docker", "run", "--rm", "-d", "--name", state["hub_container"],
        "--label", f"{LABEL}={state['run_id']}", "--env-file", str(root / "hub.env"),
        "-p", "127.0.0.1::8787", "-v", f"{root / 'hub-state'}:/state", IMAGE,
        "serve", "--host", "0.0.0.0", "--port", "8787"])
    port = run(state, "hub-port", ["docker", "port", state["hub_container"], "8787/tcp"]).strip().rsplit(":", 1)[1]
    state["hub_url"] = "http://127.0.0.1:" + port
    for _ in range(80):
        try:
            health = get_json(state["hub_url"] + "/healthz")
            break
        except (OSError, ValueError):
            time.sleep(.25)
    else:
        raise RuntimeError("disposable Hub readiness timed out")
    capabilities = get_json(state["hub_url"] + "/v2/client/capabilities")
    identity = get_json(state["hub_url"] + "/v2/client/identity")
    assert health["revision"] == REVISION and health["dirty"] is False
    assert health["catalog_sha256"] == CATALOG
    assert capabilities["contract_revision"] == "client-hub-v1.2.1" and capabilities["catalog_sha256"] == CATALOG
    previous = state.get("hub_identity")
    if previous:
        assert previous["hub_id"] == identity["hub_id"]
        assert previous["control_public_identity"] == identity["control_public_identity"]
    state["hub_identity"] = identity
    write_private(Path(state["evidence"]) / "runtime-provenance.json",
                  {"health": health, "capabilities": capabilities, "image_id": IMAGE})
    save_state(state)


def save_state(state):
    write_private(Path(state["root"]) / "fixture.json", state)


def prepare():
    os.umask(0o077)
    if subprocess.check_output(["docker", "info", "--format", "{{.DockerRootDir}}"], text=True).strip() != "/gpu1-share/data/docker-root":
        raise RuntimeError("unexpected Docker data root")
    archive = CORE / ".cicada-data/contracts" / f"client-hub-{ARCHIVE_SHA}.tar.gz"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE]))[0]
    labels = image["Config"]["Labels"]
    assert image["Id"] == IMAGE and labels["org.opencontainers.image.revision"] == REVISION
    assert labels["org.cicada.build.dirty"] == "false" and labels["org.cicada.client-catalog.sha256"] == CATALOG
    root = Path(tempfile.mkdtemp(prefix="cto.", dir="/tmp"))
    suffix = root.name.replace(".", "-")
    run_id = "two-owner-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + suffix
    evidence = BASE / run_id / "evidence"
    evidence.mkdir(parents=True, mode=0o700)
    evidence.parent.chmod(0o700)
    state = {"schema": SCHEMA, "root": str(root), "run_id": run_id, "evidence": str(evidence),
             "hub_container": "cicada-" + suffix + "-hub", "image_id": IMAGE, "revision": REVISION,
             "catalog_sha256": CATALOG, "archive_sha256": ARCHIVE_SHA, "owners": {}}
    for name in ("hub-state", "bin", "owner-public", "owner-private", "node-A", "node-B"):
        (root / name).mkdir(mode=0o700)
    write_private(root / "hub.env", ("CICADA_API_TOKEN=" + secrets.token_hex(32) + "\n").encode())
    save_state(state)
    write_private(evidence / "fixture-path.txt", (str(root) + "\n").encode())
    write_private(evidence / "fixed-target.json", {"image_id": IMAGE, "revision": REVISION,
                  "source_dirty": False, "catalog_sha256": CATALOG, "archive_sha256": ARCHIVE_SHA})
    try:
        run(state, "verify-contract", ["python3", str(CORE / "scripts/client-contract.py"), "verify", str(archive)])
        extract = "cicada-" + suffix + "-extract"
        run(state, "extract-create", ["docker", "create", "--name", extract, "--label", f"{LABEL}={run_id}", IMAGE])
        try:
            run(state, "extract-copy", ["docker", "cp", extract + ":/usr/local/bin/cicada", str(root / "bin/cicada")])
        finally:
            run(state, "extract-remove", ["docker", "rm", extract])
        for side in ("A", "B"):
            private = root / "owner-private" / (side + ".json")
            public = root / "owner-public" / (side + ".json")
            run(state, "owner-" + side + "-generate", [str(root / "bin/cicada"), "owner-key", "generate",
                "--private", str(private), "--public", str(public)], secret_output=True)
            assert private.stat().st_mode & 0o777 == 0o600
            pub = json.loads(public.read_text())
            state["owners"][side] = {"owner_id": "owner-" + suffix + "-" + side.lower(),
                "owner_key_id": pub["id"], "owner_public_identity": pub,
                "device_id": "phone-" + suffix + "-" + side.lower(),
                "node_id": "node-" + suffix + "-" + side.lower()}
        state["owners"]["A"]["admin_device_id"] = "phone-" + suffix + "-a-admin"
        save_state(state)
        start_hub(state)
        run(state, "hub-stop-before-owner-register", ["docker", "stop", "--time", "10", state["hub_container"]])
        for side in ("A", "B"):
            owner = state["owners"][side]
            register_name = "cicada-" + suffix + "-owner-register-" + side.lower()
            run(state, "owner-" + side + "-register", ["docker", "run", "--rm", "--name", register_name,
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--label", f"{LABEL}={run_id}", "-v", f"{root / 'hub-state'}:/state",
                "-v", f"{root / 'owner-public'}:/owner-public:ro", IMAGE, "owner-key", "register",
                "--db", "/state/cicada.sqlite3", "--owner-id", owner["owner_id"],
                "--public", "/owner-public/" + side + ".json", "--expect-key-id", owner["owner_key_id"]])
        start_hub(state)
        print(json.dumps({"result": "PREPARED", "fixture": str(root), "evidence": str(evidence), "image_id": IMAGE}))
    except Exception:
        save_state(state)
        print(json.dumps({"result": "FAILED_PREPARATION", "fixture": str(root), "evidence": str(evidence)}))
        raise


def load_state(path):
    root = Path(path)
    if root.is_symlink() or root.resolve().parent != Path("/tmp") or not root.name.startswith("cto."):
        raise RuntimeError("not an owned fixture directory")
    state = json.loads((root / "fixture.json").read_text())
    if state.get("schema") != SCHEMA or state.get("root") != str(root.resolve()) or state.get("image_id") != IMAGE:
        raise RuntimeError("fixture marker mismatch")
    suffix = root.name.replace(".", "-")
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise RuntimeError("fixture ownership or mode mismatch")
    if not re.fullmatch(r"two-owner-\d{8}T\d{6}Z-" + re.escape(suffix), state["run_id"]):
        raise RuntimeError("fixture run ID mismatch")
    if state["hub_container"] != "cicada-" + suffix + "-hub":
        raise RuntimeError("fixture Hub name mismatch")
    if state.get("emulator_container", "cicada-" + suffix + "-android") != "cicada-" + suffix + "-android":
        raise RuntimeError("fixture emulator name mismatch")
    evidence = Path(state["evidence"])
    expected = BASE / state["run_id"] / "evidence"
    if evidence != expected or evidence.resolve() != expected or evidence.stat().st_uid != os.getuid():
        raise RuntimeError("fixture evidence directory mismatch")
    return state


def bootstrap(state):
    root = Path(state["root"])
    for side in ("A", "B"):
        owner = state["owners"][side]
        raw = run(state, "node-" + side + "-bootstrap", [str(root / "bin/cicada"), "machine", "agent",
            "--id", owner["node_id"], "--name", "Synthetic authorization fixture " + side,
            "--control-url", state["hub_url"], "--state-dir", str(root / ("node-" + side)), "--once"],
            secret_output=True, expected=(1,))
        match = re.search(r"Device code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}) ", raw)
        if not match:
            raise RuntimeError("Node did not return the expected pending code")
        write_private(root / ("node-code-" + side + ".txt"), (match.group(1) + "\n").encode())
    print(json.dumps({"result": "PENDING_CODES_READY", "fixture": state["root"]}))


def start_emulator(state):
    def available(port):
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

    port = next(p for p in range(5620, 5678, 2) if available(p) and available(p + 1))
    adb = next(p for p in range(5060, 5099) if available(p))
    image = subprocess.check_output(["docker", "image", "inspect", EMULATOR_IMAGE,
                                     "--format", "{{.Id}}"], text=True).strip()
    assert image == EMULATOR_IMAGE
    name = state["hub_container"].removesuffix("hub") + "android"
    state.update(emulator_container=name, emulator_port=port, adb_port=adb, emulator_image_id=image)
    save_state(state)
    repo = Path(__file__).resolve().parents[2]
    run(state, "emulator-start", ["docker", "run", "--rm", "-d", "--user", "root", "--name", name,
        "--label", f"{LABEL}={state['run_id']}", "--device", "/dev/kvm", "--network", "host",
        "-e", f"CICADA_TWO_OWNER_EMULATOR_PORT={port}", "-e", f"ANDROID_ADB_SERVER_PORT={adb}",
        "-e", f"CICADA_EVIDENCE_OWNER={os.getuid()}:{os.getgid()}",
        "-v", f"{repo}:/workspace:ro", "-v", f"{state['evidence']}:/out", image,
        "bash", "/workspace/scripts/interop/two-owner-emulator.sh"])
    print(json.dumps({"result": "BOOTING", "container": name, "serial": f"emulator-{port}", "adb_port": adb}))


def android_config(state):
    root = Path(state["root"])
    owners = json.loads(json.dumps(state["owners"]))
    groups = json.loads((root / "groups.json").read_text()) if (root / "groups.json").exists() else {}
    for side in ("A", "B"):
        for field, file in (("owner_device_grant_base64", f"device-grant-{side}.json"),
                            ("owner_proof_base64", f"group-proof-{side}.json")):
            if (root / file).exists():
                owners[side][field] = base64.b64encode((root / file).read_bytes()).decode()
        if side in groups:
            owners[side]["group_id"] = groups[side]["group_id"]
        endpoint = root / ("node-fixture-" + side) / "public-result.json"
        if endpoint.exists():
            value = json.loads(endpoint.read_text())
            assert value["group_id"] == owners[side]["group_id"]
            assert value["node_id"] == owners[side]["node_id"]
            owners[side]["endpoint_id"] = value["endpoint_id"]
    admin = root / "device-grant-A_admin.json"
    if admin.exists():
        owners["A"]["admin_owner_device_grant_base64"] = base64.b64encode(admin.read_bytes()).decode()
    write_private(root / "android-fixture.json", {"schema": "cicada.client-two-owner-acceptance.v1",
        "hub_base_url": state["hub_url"], "hub_identity": state["hub_identity"], "owners": owners})
    if all((root / f"node-code-{side}.txt").exists() for side in ("A", "B")):
        write_private(root / "android-private-fixture.json", {
            "schema": "cicada.client-two-owner-private-fixture.v1",
            "node_user_codes": {side: (root / f"node-code-{side}.txt").read_text().strip() for side in ("A", "B")}})
    print(json.dumps({"result": "ANDROID_CONFIG_READY", "fixture": str(root)}))


def sign_devices(state):
    root = Path(state["root"])
    public = json.loads((root / "device-publics.json").read_text())
    signer = BASE / "group-owner-signer-build-967dbd-20260925/bin/group_owner_signer"
    assert hashlib.sha256(signer.read_bytes()).hexdigest() == "cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1"
    for label, side in (("A", "A"), ("A_admin", "A"), ("B", "B")):
        owner = state["owners"][side]
        device = owner["admin_device_id"] if label == "A_admin" else owner["device_id"]
        identity = public[label]
        path = root / ("device-public-" + label + ".json")
        # The external signer requires the exact compact public-identity JSON shape.
        canonical = {key: identity[key] for key in ("id", "kem_public", "signing_public")}
        write_private(path, json.dumps(canonical, separators=(",", ":")).encode())
        # This is explicit synthetic-fixture consent, not a repeated human/native UI acceptance.
        challenge = "SIGN DEVICE " + device + " " + identity["id"] + "\n"
        run(state, "sign-device-" + label, [str(signer), "device-grant", "--private", str(root / "owner-private" / (side + ".json")),
            "--device-public", str(path), "--owner", owner["owner_id"], "--device", device,
            "--hub", state["hub_identity"]["hub_id"], "--expect-device-key", identity["id"],
            "--out", str(root / ("device-grant-" + label + ".json"))], input_data=challenge.encode())
    android_config(state)


def publish_endpoints(state):
    root = Path(state["root"])
    groups = json.loads((root / "groups.json").read_text())
    binary_dir = BASE / "two-owner-node-fixture-build/bin"
    assert hashlib.sha256((binary_dir / "two-owner-node-fixture").read_bytes()).hexdigest() == NODE_HELPER_SHA
    runner_image = subprocess.check_output(["docker", "image", "inspect", GO_IMAGE, "--format", "{{.Id}}"], text=True).strip()
    assert runner_image == GO_IMAGE
    state["node_helper_image_id"] = runner_image
    save_state(state)
    for side in ("A", "B"):
        node_dir = root / ("node-" + side)
        work = root / ("node-fixture-" + side)
        work.mkdir(mode=0o700, exist_ok=True)
        node_id = state["owners"][side]["node_id"]
        credential = node_dir / "nodes" / ("node-" + node_id) / "relay.token"
        if not credential.is_file():
            raise RuntimeError("fixed CLI Node credential file was not created")
        mounted_credential = work / "relay.token"
        write_private(work / "spec.json", {"schema_version": 1, "hub_base_url": state["hub_url"],
            "group_id": groups[side]["group_id"], "node_credential_file": str(mounted_credential),
            "native_session_id": "synthetic-authorization-only-" + state["run_id"] + "-" + side,
            "workspace": "/synthetic-two-owner-authorization/" + side,
            "endpoint_private_key_file": str(work / "endpoint-private.json"),
            "public_result_file": str(work / "public-result.json"), "lease_seconds": 3600})
        run(state, "node-" + side + "-join-candidate", ["docker", "run", "--rm", "--network", "host",
            "--name", state["hub_container"].removesuffix("hub") + "node-fixture-" + side.lower(),
            "--label", f"{LABEL}={state['run_id']}", "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{work}:{work}", "-v", f"{credential}:{mounted_credential}:ro",
            "-v", f"{binary_dir}:/tools:ro",
            runner_image, "/tools/two-owner-node-fixture", "-spec", str(work / "spec.json")])
        write_private(Path(state["evidence"]) / ("endpoint-" + side + ".private.json"), (work / "public-result.json").read_bytes())
    android_config(state)


def sign_groups(state):
    root = Path(state["root"])
    manifests = json.loads((root / "manifests.json").read_text())
    signer = BASE / "group-owner-signer-build-967dbd-20260925/bin/group_owner_signer"
    assert hashlib.sha256(signer.read_bytes()).hexdigest() == "cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1"
    for side in ("A", "B"):
        manifest = manifests[side]
        assert manifest["owner_id"] == state["owners"][side]["owner_id"]
        assert manifest["hub_id"] == state["hub_identity"]["hub_id"]
        manifest_file = root / ("manifest-" + side + ".json")
        write_private(manifest_file, json.dumps(manifest, separators=(",", ":")).encode())
        command = [str(signer), "group-grant", "--private", str(root / "owner-private" / (side + ".json")),
                   "--manifest", str(manifest_file)]
        for flag, key in (("owner", "owner_id"), ("hub", "hub_id"), ("group", "group_id"),
                          ("endpoint", "endpoint_id"), ("node", "node_id"), ("principal", "principal_id"), ("digest", "digest")):
            command += ["--expect-" + flag, manifest[key]]
        command += ["--out", str(root / ("group-proof-" + side + ".json"))]
        run(state, "sign-group-" + side, command, input_data=("SIGN GROUP " + manifest["digest"] + "\n").encode())
    android_config(state)


def cleanup(state):
    # Inspect only labels/image for our names, never Docker environment secrets.
    prefix = state["hub_container"].removesuffix("hub")
    for name in (state.get("emulator_container"), state["hub_container"], prefix + "extract",
                 prefix + "owner-register-a", prefix + "owner-register-b",
                 prefix + "node-fixture-a", prefix + "node-fixture-b"):
        if not name:
            continue
        check = subprocess.run(["docker", "inspect", "--format", "{{.Image}} {{index .Config.Labels \"" + LABEL + "\"}}", name],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if check.returncode:
            continue
        if name == state.get("emulator_container"):
            expected_image = state["emulator_image_id"]
        elif name in (prefix + "node-fixture-a", prefix + "node-fixture-b"):
            expected_image = state.get("node_helper_image_id", "")
        else:
            expected_image = IMAGE
        if check.stdout.strip().split() != [expected_image, state["run_id"]]:
            raise RuntimeError("refusing to stop a container with a foreign fixture image or label")
        if name == state.get("emulator_container"):
            # Allow the emulator's trap to stop its ADB server and return evidence ownership.
            # This fixture uses --rm, so a successful stop also removes its container.
            run(state, "cleanup-" + name, ["docker", "stop", "--time", "10", name])
        else:
            run(state, "cleanup-" + name, ["docker", "rm", "-f", "-v", name])
    root = Path(state["root"])
    shutil.rmtree(root)
    write_private(Path(state["evidence"]) / "teardown.json", {"result": "PASS", "fixture_removed": not root.exists(),
                  "owned_resources_only": True, "owner_private_keys_removed": True})
    print(json.dumps({"result": "CLEANED", "evidence": state["evidence"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = {"bootstrap-nodes": bootstrap, "start-emulator": start_emulator, "android-config": android_config,
               "sign-devices": sign_devices, "publish-endpoints": publish_endpoints, "sign-groups": sign_groups, "stop": cleanup}
    parser.add_argument("action", choices=("prepare", *actions))
    parser.add_argument("fixture", nargs="?")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare()
    else:
        if not args.fixture:
            parser.error("fixture directory is required")
        state = load_state(args.fixture)
        actions[args.action](state)


if __name__ == "__main__":
    main()
