#!/usr/bin/env python3
"""Verify an imported public Client/Hub protocol snapshot offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent / "contracts" / "client-hub-v1.4-f30892f"
SOURCE_REVISION = "f30892fcd79a27bfe5604575deaecebe52c5ec50"
CATALOG_SHA256 = "7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54"
CONTRACT_REVISION = "client-hub-v1.4"
WIRE_VERSION = 1
CATALOG_PATH = "cicada-go/internal/clientcontract/catalog.json"
SOURCE_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def resolve_snapshot_root(snapshot_dir: Path) -> Path:
    requested = Path(snapshot_dir).expanduser()
    candidate = requested if requested.is_absolute() else Path.cwd() / requested

    # Reject symlinks in the caller-supplied directory path, not just a symlink
    # at its final component.
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        if part == "..":
            current = current.parent
            continue
        if part in ("", "."):
            continue
        current = current / part
        require(not current.is_symlink(), f"snapshot path traverses symlink: {current}")

    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"snapshot directory cannot be resolved: {candidate}") from exc
    require(root.is_dir(), f"snapshot path is not a directory: {root}")
    return root


def safe_snapshot_file(root: Path, name: str) -> Path:
    require(isinstance(name, str) and bool(name), "snapshot file name must be a non-empty string")
    require("\\" not in name, f"snapshot file name must use POSIX separators: {name!r}")
    relative = PurePosixPath(name)
    require(not relative.is_absolute(), f"absolute snapshot file path is forbidden: {name!r}")
    require(relative.as_posix() == name, f"non-canonical snapshot file path: {name!r}")
    require(all(part not in ("", ".", "..") for part in relative.parts),
            f"unsafe snapshot file path: {name!r}")

    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"snapshot file path traverses symlink: {name!r}")

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"snapshot file is missing or cannot be resolved: {name!r}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"snapshot file resolves outside snapshot: {name!r}") from exc

    try:
        mode = candidate.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"cannot stat snapshot file: {name!r}") from exc
    require(stat.S_ISREG(mode), f"snapshot entry is not a regular file: {name!r}")
    return candidate


def read_json(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid JSON for {description}: {path}") from exc


def actual_payload_files(root: Path) -> set[str]:
    actual: set[str] = set()
    def walk_error(error: OSError) -> None:
        raise ValueError(f"cannot enumerate snapshot: {error.filename}") from error

    for directory, directory_names, file_names in os.walk(
        root, topdown=True, onerror=walk_error, followlinks=False
    ):
        base = Path(directory)
        for name in directory_names:
            path = base / name
            require(not path.is_symlink(), f"snapshot contains symlink directory: {path.relative_to(root)}")
            require(path.is_dir(), f"snapshot entry is not a directory: {path.relative_to(root)}")
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError(f"snapshot directory resolves outside snapshot: {path.relative_to(root)}") from exc

        for name in file_names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            require(not path.is_symlink(), f"snapshot contains symlink file: {relative}")
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise ValueError(f"cannot stat snapshot entry: {relative}") from exc
            require(stat.S_ISREG(mode), f"snapshot entry is not a regular file: {relative}")
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError(f"snapshot file resolves outside snapshot: {relative}") from exc
            if relative != "manifest.json":
                actual.add(relative)
    return actual


def verify_snapshot(
    snapshot_dir: Path,
    expected_source_revision: str,
    expected_catalog_sha256: str,
    expected_contract_revision: str = CONTRACT_REVISION,
) -> int:
    require(
        isinstance(expected_source_revision, str)
        and SOURCE_REVISION_PATTERN.fullmatch(expected_source_revision) is not None,
        "expected source revision must be 40 lowercase hexadecimal characters",
    )
    require(
        isinstance(expected_catalog_sha256, str)
        and SHA256_PATTERN.fullmatch(expected_catalog_sha256) is not None,
        "expected catalog SHA-256 must be 64 lowercase hexadecimal characters",
    )
    require(
        isinstance(expected_contract_revision, str) and bool(expected_contract_revision),
        "expected contract revision must be a non-empty string",
    )

    root = resolve_snapshot_root(snapshot_dir)
    manifest_path = safe_snapshot_file(root, "manifest.json")
    manifest = read_json(manifest_path, "manifest")
    require(isinstance(manifest, dict), "manifest must be a JSON object")
    require(type(manifest.get("manifest_version")) is int and manifest["manifest_version"] == 1,
            "manifest version does not match the supported version")
    require(manifest.get("contract_revision") == expected_contract_revision,
            "manifest contract revision does not match the expected revision")
    require(manifest.get("source_revision") == expected_source_revision,
            "manifest source revision does not match the expected revision")
    require(manifest.get("source_dirty") is False, "manifest source must be clean")
    require(manifest.get("catalog_sha256") == expected_catalog_sha256,
            "manifest catalog SHA-256 does not match the expected value")
    require(type(manifest.get("wire_version")) is int and manifest["wire_version"] == WIRE_VERSION,
            "manifest wire version does not match the supported version")

    listed = manifest.get("files")
    require(isinstance(listed, dict) and bool(listed), "manifest files must be a non-empty object")
    require("manifest.json" not in listed, "manifest.json cannot be listed as a payload file")
    require(CATALOG_PATH in listed, "manifest does not list the protocol catalog")

    contents_by_name: dict[str, bytes] = {}
    for name, expected in listed.items():
        safe_path = safe_snapshot_file(root, name)
        require(isinstance(expected, dict), f"manifest payload metadata must be an object: {name!r}")
        expected_bytes = expected.get("bytes")
        expected_digest = expected.get("sha256")
        require(type(expected_bytes) is int and expected_bytes >= 0,
                f"manifest payload byte count is invalid: {name!r}")
        require(isinstance(expected_digest, str) and SHA256_PATTERN.fullmatch(expected_digest) is not None,
                f"manifest payload SHA-256 is invalid: {name!r}")
        try:
            contents = safe_path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read snapshot payload: {name!r}") from exc
        require(len(contents) == expected_bytes, f"snapshot payload byte count mismatch: {name!r}")
        actual_digest = hashlib.sha256(contents).hexdigest()
        require(actual_digest == expected_digest, f"snapshot payload SHA-256 mismatch: {name!r}")
        contents_by_name[name] = contents

    actual = actual_payload_files(root)
    require(actual == set(listed), "snapshot contains missing or unlisted files")

    catalog_bytes = contents_by_name[CATALOG_PATH]
    actual_catalog_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    require(actual_catalog_sha256 == expected_catalog_sha256,
            "catalog bytes do not match the expected catalog SHA-256")
    catalog = read_json_bytes(catalog_bytes, "catalog")
    require(isinstance(catalog, dict), "catalog must be a JSON object")
    require(catalog.get("contract_revision") == expected_contract_revision,
            "catalog contract revision does not match the expected revision")
    require(type(catalog.get("wire_version")) is int and catalog["wire_version"] == WIRE_VERSION,
            "catalog wire version does not match the supported version")

    return len(listed)


def read_json_bytes(contents: bytes, description: str) -> Any:
    try:
        return json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse valid JSON for {description}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-dir", type=Path, default=ROOT, help="imported snapshot directory")
    parser.add_argument("--source-revision", default=SOURCE_REVISION, help="expected 40-character source revision")
    parser.add_argument("--catalog-sha256", default=CATALOG_SHA256, help="expected catalog SHA-256")
    parser.add_argument("--contract-revision", default=CONTRACT_REVISION, help="expected contract revision")
    args = parser.parse_args()

    try:
        file_count = verify_snapshot(
            args.snapshot_dir,
            args.source_revision,
            args.catalog_sha256,
            args.contract_revision,
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(f"PASS {args.contract_revision} {args.catalog_sha256} ({file_count} files)")


if __name__ == "__main__":
    main()
