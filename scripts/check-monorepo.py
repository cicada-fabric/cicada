#!/usr/bin/env python3
"""Read-only checks for retained local history and the Android subtree import."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fsck", action="store_true", help="also verify the complete object database")
    args = parser.parse_args()
    record = json.loads((ROOT / "docs/repository-migration.json").read_text())
    errors = []

    def check(condition, message):
        if not condition:
            errors.append(message)

    reachable = set(git("rev-list", "--all").splitlines())
    for field in ("core_reflog_only_commits", "android_reflog_commits"):
        check(set(record[field]) <= reachable, field + " contains unreachable history")
    for field in ("core_source_refs", "android_source_refs"):
        for row in record[field]:
            name, commit = row.split()
            check(commit in reachable, "source ref is not retained: " + name)
    for name, commit in record["archive_refs"].items():
        try:
            check(git("rev-parse", name) == commit, "archive ref changed: " + name)
        except subprocess.CalledProcessError:
            errors.append("archive ref missing: " + name)
    merge = record["subtree_import_commit"]
    check(git("show", "-s", "--format=%P", merge).split() ==
          [record["core_source_head"], record["android_source_head"]], "import parents changed")
    check(git("rev-parse", merge + ":" + record["android_prefix"]) ==
          git("rev-parse", record["android_source_head"] + "^{tree}"), "imported Android tree differs")
    check(git("rev-parse", "main") == record["unchanged_main"], "main changed since migration")
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    check(not (common / "objects/info/alternates").exists(), "object alternates dependency exists")
    check(not common.is_symlink(), "common Git directory is a symbolic link")
    if args.fsck:
        result = subprocess.run(["git", "-C", str(ROOT), "fsck", "--full"], capture_output=True, text=True)
        check(result.returncode == 0, "git fsck failed")
    print(json.dumps({"status": "FAIL" if errors else "PASS", "errors": errors,
                      "core_reflog_only_commits": len(record["core_reflog_only_commits"]),
                      "android_reflog_commits": len(record["android_reflog_commits"]),
                      "archive_refs": len(record["archive_refs"]),
                      "fsck": "PASS" if args.fsck and not errors else "NOT_RUN"}, indent=2))
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
