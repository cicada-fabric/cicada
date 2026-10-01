#!/usr/bin/env python3
"""Independently verify the public v1.6.1 retrospective build-input supplement.

Reads pinned Git objects and declared mode evidence. Writes no files and does
not execute the Core reproducer or claim original build-time mode capture.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys


REVISION = "fe565b41bb1aa86d400a0ec98c528c856d0b9579"
FINGERPRINT = "6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be"
MANIFEST_SHA = "1177e6045120082c3871f81afca9ec938364e132598c016645abe0a66bfd02aa"
REPRODUCER_SHA = "1db351e37eded5e4453ba092527e363b4c2b23b287f3e51e0e83f5cb5bb9fd1a"
DOMAIN = b"cicada-hub-build-inputs-v4\x00"
SCOPES = ("cicada-go/", "docker/Dockerfile.hub", ".dockerignore",
          "scripts/build-web-panel.sh", "scripts/write-web-panel-manifest.py",
          "scripts/build-hub-image.sh", ".github/workflows/release.yml")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def public_file(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative,
            "invalid relative evidence path")
    path = PurePosixPath(relative)
    require(not path.is_absolute() and path.as_posix() == relative and
            all(part not in (".", "..") for part in path.parts), "unsafe evidence path")
    actual = root
    for part in path.parts:
        actual = actual / part
        require(not actual.is_symlink(), "evidence path traverses a symlink")
    require(actual.is_file(), "public evidence file missing")
    return actual


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def verify(root, manifest_path):
    data = manifest_path.read_bytes()
    require(len(data) <= 2 * 1024 * 1024, "manifest too large")
    require(hashlib.sha256(data).hexdigest() == MANIFEST_SHA, "supplement digest mismatch")
    manifest = json.loads(data, object_pairs_hook=unique_object)
    source = manifest["source"]
    require(source["revision"] == REVISION and source["input_count"] == 773 and
            source["dirty_at_immutable_build"] is False and
            source["source_fingerprint"] == FINGERPRINT, "wrong immutable source")
    require(source["input_scope"] == list(SCOPES), "wrong input scope")
    require(manifest["schema_version"] == "cicada.hub-build-input-manifest.v4-reconstruction" and
            manifest["status"] == "MATCH_RECONSTRUCTED", "wrong supplement type")
    require(manifest["fingerprint_domain_hex"] == DOMAIN.hex(), "fingerprint domain mismatch")
    require(manifest["mode_provenance"]["original_build_file_modes_directly_captured"] is False,
            "retrospective evidence mislabeled as original capture")
    tree_oid = git(root, "rev-parse", REVISION + "^{tree}").decode().strip()
    require(source["pinned_git_tree_oid"] == tree_oid, "wrong Git tree")

    tree = {}
    for entry in git(root, "ls-tree", "-r", "-z", "--full-tree", REVISION).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        path = raw_path.decode("utf-8")
        if any(path.startswith(scope) if scope.endswith("/") else path == scope for scope in SCOPES):
            require(kind == "blob" and path not in tree, "invalid scoped Git entry")
            tree[path] = (mode, oid)
    require(len(tree) == 773, "pinned input set changed")
    records = manifest["inputs"]
    require(isinstance(records, list) and len(records) == len(tree), "incomplete input inventory")
    paths = [record["path"] for record in records]
    require(paths == sorted(tree, key=os.fsencode), "input order/set mismatch")
    digest = hashlib.sha256(DOMAIN)
    modes = Counter()
    snapshot_count = 0
    for record in records:
        path = record["path"]
        tree_mode, oid = tree[path]
        require(record["git_tree_mode"] == tree_mode and record["git_blob_oid"] == oid,
                "Git blob/mode mismatch")
        blob = git(root, "cat-file", "blob", oid)
        sha = hashlib.sha256(blob).digest()
        require(record["pinned_content_sha256"] == sha.hex() and
                type(record["size_bytes"]) is int and record["size_bytes"] == len(blob),
                "pinned content digest/size mismatch")
        mode = record["fingerprint_mode_decimal"]
        require(type(mode) is int and 0 <= mode <= 0o7777 and
                record["fingerprint_mode_octal"] == format(mode, "04o"), "invalid raw mode")
        evidence = record["mode_evidence"]
        if "snapshot_path" in evidence:
            snapshot_count += 1
            snapshot = public_file(root, evidence["snapshot_path"])
            require(snapshot.read_bytes() == blob and
                    evidence["snapshot_file_sha256"] == sha.hex() and
                    evidence["snapshot_file_mode_octal"] == format(mode, "04o") and
                    stat.S_IMODE(snapshot.stat().st_mode) == mode, "snapshot mode/content mismatch")
            snapshot_meta = public_file(root, evidence["snapshot_manifest_path"]).read_bytes()
            require(hashlib.sha256(snapshot_meta).hexdigest() == evidence["snapshot_manifest_sha256"],
                    "snapshot metadata digest mismatch")
        else:
            observed = public_file(root, path)
            require(evidence["observed_mode_octal"] == format(mode, "04o") and
                    stat.S_IMODE(observed.stat().st_mode) == mode, "current mode observation changed")
        require("reconstructed, not original build capture" in record["mode_source"],
                "mode observation mislabeled")
        raw_path = os.fsencode(path)
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(sha)
        modes[format(mode, "04o")] += 1
    require(snapshot_count == 6, "snapshot observation set changed")
    require(digest.hexdigest() == FINGERPRINT, "independent fingerprint mismatch")
    reproducer = public_file(root, manifest["reconstruction_script_path"])
    require(hashlib.sha256(reproducer.read_bytes()).hexdigest() == REPRODUCER_SHA and
            manifest["reconstruction_script_sha256"] == REPRODUCER_SHA, "reproducer digest mismatch")
    return {"result": "PASS_RETROSPECTIVE_RECONSTRUCTION", "core_commit": REVISION,
            "git_tree_oid": tree_oid, "manifest_sha256": MANIFEST_SHA,
            "computed_fingerprint": digest.hexdigest(), "fingerprint_domain_hex": DOMAIN.hex(),
            "pinned_inputs_verified": len(tree), "snapshot_mode_observations": snapshot_count,
            "current_mode_observations": len(tree) - snapshot_count, "raw_mode_counts": dict(modes),
            "original_build_time_mode_capture": "NOT_PROVIDED", "core_reproducer_executed": False,
            "hub_runtime": "NOT_RUN", "native_runtime": "NOT_RUN", "models_invoked": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.core.resolve(), args.manifest), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError):
        print(json.dumps({"result": "FAIL", "reason": "public reconstruction evidence validation failed"}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
