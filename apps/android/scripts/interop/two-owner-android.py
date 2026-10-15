#!/usr/bin/env python3
"""Stage private fixture files through stdin and run the disposable Android tests.

Only a public run ID is passed in instrumentation arguments. Node codes never
enter process arguments, public output or Git. Owner/Node private keys and
bearers are never staged to Android at all.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("two_owner_fixture", Path(__file__).with_name("two-owner-fixture.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
PACKAGE = "ai.cicada.client"
TEST_CLASS = "ai.cicada.client.hub.TwoOwnerInteropTest"


def adb(state, interactive=False):
    return ["docker", "exec"] + (["-i"] if interactive else []) + [state["emulator_container"],
        "/opt/android-sdk/platform-tools/adb", "-P", str(state["adb_port"]), "-s", "emulator-" + str(state["emulator_port"])]


def remote_dir(state):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", state["run_id"]):
        raise ValueError("unsafe public run ID")
    return "no_backup/cicada-two-owner/" + state["run_id"]


def install(state):
    repo = Path(__file__).resolve().parents[2]
    artifacts = {}
    for name, relative in (("app", "android/app/build/outputs/apk/debug/app-debug.apk"),
                           ("androidTest", "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")):
        path = repo / relative
        artifacts[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "path": str(path)}
        fixture.run(state, "install-" + name, adb(state) + ["install", "-r", "/workspace/" + relative])
    port = state["hub_url"].rsplit(":", 1)[1]
    fixture.run(state, "adb-reverse", adb(state) + ["reverse", "tcp:" + port, "tcp:" + port])
    artifacts["client_base_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    fixture.write_private(Path(state["evidence"]) / "android-artifacts.json", artifacts)
    print(json.dumps({"result": "INSTALLED", "app_sha256": artifacts["app"]["sha256"],
                      "android_test_sha256": artifacts["androidTest"]["sha256"]}))


def stage(state, source, name):
    source = Path(source)
    if source.is_symlink() or source.stat().st_mode & 0o077:
        raise ValueError("staged fixture must be a private regular file")
    data = source.read_bytes()
    parsed = json.loads(data)
    if name == "private-fixture.json":
        if (set(parsed) != {"schema", "node_user_codes"} or
                parsed.get("schema") != "cicada.client-two-owner-private-fixture.v1" or
                set(parsed["node_user_codes"]) != {"A", "B"}):
            raise ValueError("unexpected private fixture content")
        if not all(isinstance(value, str) and re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", value)
                   for value in parsed["node_user_codes"].values()):
            raise ValueError("invalid one-time Node code format")
    else:
        allowed = {"schema", "hub_base_url", "hub_identity", "owners"}
        if set(parsed) - allowed or parsed.get("schema") != "cicada.client-two-owner-acceptance.v1":
            raise ValueError("unexpected public fixture content")
        # Reject private credential fields even when nested in an otherwise valid fixture.
        def check(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if any(word in key.lower() for word in ("private", "bearer", "credential", "secret", "token")):
                        raise ValueError("private credentials must never be staged to Android")
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
        check(parsed)
    directory = remote_dir(state)
    shell = "umask 077; mkdir -p " + shlex.quote(directory) + "; cat > " + shlex.quote(directory + "/" + name)
    command = adb(state, True) + ["shell", shlex.join(["run-as", PACKAGE, "sh", "-c", shell])]
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("private fixture staging failed with exit " + str(result.returncode))
    print(json.dumps({"result": "STAGED", "file": name, "exit_code": 0}))


def execute(state, method):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,100}", method):
        raise ValueError("invalid instrumentation method")
    command = adb(state) + ["shell", "am", "instrument", "-w", "-e", "run_id", state["run_id"],
        "-e", "class", TEST_CLASS + "#" + method, PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"]
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    output = proc.stdout.decode(errors="replace")
    match = re.search(r"(?m)^OK \((\d+) tests?\)$", output)
    passed = proc.returncode == 0 and match and match.group(1) == "1" and "FAILURES!!!" not in output
    summary = {"result": "PASS" if passed else "FAIL", "method": method, "adb_exit_code": proc.returncode,
               "runner_exit_code": 0 if passed else 1, "junit": match.group(0) if match else "NO_PASS_SUMMARY",
               "command": command}
    evidence = Path(state["evidence"])
    fixture.write_private(evidence / (method + ".private.log"), proc.stdout)
    fixture.write_private(evidence / (method + ".json"), summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "command"}))
    if not passed:
        raise SystemExit(1)


def export(state, name):
    command = adb(state) + ["exec-out", "run-as", PACKAGE, "cat", remote_dir(state) + "/" + name]
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise RuntimeError("public result export failed with exit " + str(proc.returncode))
    json.loads(proc.stdout)
    fixture.write_private(Path(state["root"]) / name, proc.stdout)
    fixture.write_private(Path(state["evidence"]) / (name.removesuffix(".json") + ".private.json"), proc.stdout)
    print(json.dumps({"result": "EXPORTED", "file": name, "exit_code": 0,
                      "sha256": hashlib.sha256(proc.stdout).hexdigest()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("install")
    p = sub.add_parser("stage")
    p.add_argument("source")
    p.add_argument("name", choices=("fixture.json", "private-fixture.json"))
    p = sub.add_parser("test")
    p.add_argument("method")
    p = sub.add_parser("export")
    p.add_argument("name", choices=("device-publics.json", "groups.json", "manifests.json", "result.json"))
    args = parser.parse_args()
    state = fixture.load_state(args.fixture)
    if args.action == "install": install(state)
    elif args.action == "stage": stage(state, args.source, args.name)
    elif args.action == "test": execute(state, args.method)
    else: export(state, args.name)


if __name__ == "__main__":
    os.umask(0o077)
    main()
