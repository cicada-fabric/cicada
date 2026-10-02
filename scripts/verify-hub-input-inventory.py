#!/usr/bin/env python3
"""Independently verify a data-only Hub input inventory against pinned Git.

This tool reads metadata, Git objects and optionally the checkout. It never
imports or executes the Core inventory helper or starts a runtime service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from hub_input_inventory import InventoryVerificationError, verify_inventory
from hub_input_inventory_git import verify_repository


MAX_METADATA_BYTES = 16 * 1024 * 1024


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryVerificationError("Metadata contains duplicate JSON keys")
        result[key] = value
    return result


def reject_constant(_: str) -> object:
    raise InventoryVerificationError("Metadata contains non-finite JSON numbers")


def load_metadata(path: Path) -> tuple[dict, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_METADATA_BYTES:
            raise InventoryVerificationError("Metadata must be a bounded regular file")
        content = stream.read(MAX_METADATA_BYTES + 1)
        after = os.fstat(stream.fileno())
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(content) > MAX_METADATA_BYTES or any(
        getattr(before, field) != getattr(after, field) for field in stable_fields
    ):
        raise InventoryVerificationError("Metadata changed while being read")
    value = json.loads(content, object_pairs_hook=unique_object, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise InventoryVerificationError("Metadata must be a JSON object")
    return value, hashlib.sha256(content).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-catalog-sha256")
    parser.add_argument("--expected-source-fingerprint")
    parser.add_argument("--expected-helper-sha256")
    parser.add_argument("--allow-dirty", action="store_true", help="Diagnostic verification only")
    parser.add_argument("--verify-worktree", action="store_true", help="Also verify actual raw modes and current index")
    args = parser.parse_args()
    try:
        metadata, metadata_sha256 = load_metadata(args.metadata)
        verified = verify_inventory(
            metadata, expected_revision=args.expected_revision, require_clean=not args.allow_dirty,
        )
        for supplied, key in (
            (args.expected_catalog_sha256, "catalog_sha256"),
            (args.expected_source_fingerprint, "source_fingerprint"),
        ):
            if supplied is not None and supplied != verified[key]:
                raise InventoryVerificationError("Metadata does not match the independently supplied pin")
        repository = verify_repository(
            verified, args.repository, verify_worktree=args.verify_worktree,
            expected_helper_sha256=args.expected_helper_sha256,
        )
        report = {key: value for key, value in verified.items() if key != "inventory"}
        report.update({
            "schema_version": "cicada.client-hub-input-inventory-verification.v1",
            "result": "DIRTY_DIAGNOSTIC_ONLY" if verified["dirty"] else "PASS",
            "metadata_sha256": metadata_sha256,
            "repository_proof": repository,
            "verifier_sha256": {
                name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                for name in (
                    "verify-hub-input-inventory.py", "hub_input_inventory.py", "hub_input_inventory_git.py",
                )
            },
            "limits": "Inventory and Git verification only; no image equivalence or live acceptance claim.",
        })
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (InventoryVerificationError, ValueError, OSError, RecursionError, subprocess.SubprocessError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error)[:256]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
