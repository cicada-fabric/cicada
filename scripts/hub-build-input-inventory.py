#!/usr/bin/env python3
"""Capture a data-only inventory of the Hub build's selected source inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = "cicada.hub-build-input-inventory.v1"
IMPLEMENTATION_VERSION = "1"
IMPLEMENTATION_PATH = "scripts/hub-build-input-inventory.py"
DOMAIN = b"cicada-hub-build-input-inventory-v1\0"
V4_DOMAIN = b"cicada-hub-build-inputs-v4\0"
SCOPE = (
    "cicada-go",
    "docker/Dockerfile.hub",
    ".dockerignore",
    "scripts/build-web-panel.sh",
    "scripts/write-web-panel-manifest.py",
    "scripts/build-hub-image.sh",
    ".github/workflows/release.yml",
)


class InventoryError(RuntimeError):
    """Raised when a complete, stable inventory cannot be captured."""


def _run_git(root: bytes, *arguments: bytes) -> bytes:
    result = subprocess.run(
        [b"git", b"-C", root, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise InventoryError("git could not enumerate Hub build inputs")
    return result.stdout


def _input_paths(root: bytes) -> list[bytes]:
    output = _run_git(
        root,
        b"ls-files",
        b"--cached",
        b"--others",
        b"--exclude-standard",
        b"-z",
        b"--",
        *(os.fsencode(path) for path in SCOPE),
    )
    return sorted({path for path in output.split(b"\0") if path})


def _index_entries(root: bytes) -> dict[bytes, tuple[bytes, bytes]]:
    """Return only unambiguous stage-zero index modes and blob object IDs."""
    output = _run_git(root, b"ls-files", b"--stage", b"-z", b"--", *(os.fsencode(path) for path in SCOPE))
    entries: dict[bytes, list[tuple[bytes, bytes, bytes]]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, object_id, stage = header.split(b" ", 2)
        except ValueError as error:
            raise InventoryError("git returned an invalid index entry") from error
        entries.setdefault(path, []).append((mode, object_id, stage))
    return {
        path: (rows[0][0], rows[0][1])
        for path, rows in entries.items()
        if len(rows) == 1 and rows[0][2] == b"0"
    }


def _git_object_format(root: bytes) -> str:
    value = _run_git(root, b"rev-parse", b"--show-object-format").strip()
    try:
        object_format = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise InventoryError("git reported an unsupported object format") from error
    if object_format not in {"sha1", "sha256"}:
        raise InventoryError("git reported an unsupported object format")
    return object_format


def _git_mode(file_type: str, raw_mode: int) -> bytes | None:
    if file_type == "symlink":
        return b"120000"
    if file_type == "regular":
        return b"100755" if raw_mode & 0o111 else b"100644"
    return None


def _git_blob_oid(object_format: str, content: bytes) -> bytes:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.new(object_format, header + content).hexdigest().encode("ascii")


def _source_fingerprint_v4(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Reproduce the unchanged shell v4 fingerprint from the inventory rows."""
    digest = hashlib.sha256(V4_DOMAIN)
    for entry in entries:
        if entry["file_type"] == "missing":
            continue
        path = bytes.fromhex(entry["path_bytes_hex"])
        raw_mode = int(entry["raw_mode"], 8)
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(stat.S_IMODE(raw_mode).to_bytes(4, "big"))
        digest.update(bytes.fromhex(entry["content_sha256"]))
    return {
        "algorithm": "sha256",
        "domain_hex": V4_DOMAIN.hex(),
        "sha256": digest.hexdigest(),
        "reproduction": {
            "path_order": "filesystem path bytes, ascending",
            "path_length": "8-byte unsigned big-endian",
            "mode": "stat.S_IMODE(raw_mode), 4-byte unsigned big-endian",
            "content_digest": "raw 32-byte SHA-256 of file bytes or symlink target bytes",
            "missing_paths": "skipped",
        },
    }


def _read_regular(path: bytes, metadata: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise InventoryError("Hub build input changed while being read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (opened.st_mode, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        identity_after = (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise InventoryError("Hub build input changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _capture_once(root_path: pathlib.Path) -> dict[str, Any]:
    root = os.fsencode(os.fspath(root_path))
    paths = _input_paths(root)
    index = _index_entries(root)
    object_format = _git_object_format(root)
    entries: list[dict[str, Any]] = []

    for relative in paths:
        absolute = os.path.join(root, relative)
        try:
            metadata = os.lstat(absolute)
        except FileNotFoundError:
            entries.append(
                {
                    "path": os.fsdecode(relative),
                    "path_bytes_hex": relative.hex(),
                    "file_type": "missing",
                    "raw_mode": None,
                    "size_bytes": None,
                    "content_sha256": None,
                }
            )
            continue

        raw_mode = metadata.st_mode
        if stat.S_ISREG(raw_mode):
            file_type = "regular"
            content = _read_regular(absolute, metadata)
        elif stat.S_ISLNK(raw_mode):
            file_type = "symlink"
            content = os.fsencode(os.readlink(absolute))
            try:
                after = os.lstat(absolute)
            except FileNotFoundError as error:
                raise InventoryError("Hub build input changed while being read") from error
            if (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_mtime_ns,
            ):
                raise InventoryError("Hub build input changed while being read")
        else:
            raise InventoryError("unsupported non-file Hub build input")

        entry: dict[str, Any] = {
            "path": os.fsdecode(relative),
            "path_bytes_hex": relative.hex(),
            "file_type": file_type,
            "raw_mode": f"0o{raw_mode:o}",
            "size_bytes": len(content),
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }
        index_entry = index.get(relative)
        git_mode = _git_mode(file_type, raw_mode)
        if index_entry is not None and git_mode is not None:
            index_mode, index_oid = index_entry
            if index_mode == git_mode and index_oid == _git_blob_oid(object_format, content):
                entry["git_index"] = {
                    "blob_oid": index_oid.decode("ascii"),
                    "mode": index_mode.decode("ascii"),
                    "object_format": object_format,
                }
        entries.append(entry)

    implementation_bytes = pathlib.Path(__file__).read_bytes()
    implementation = {
        "path": IMPLEMENTATION_PATH,
        "version": IMPLEMENTATION_VERSION,
        "sha256": hashlib.sha256(implementation_bytes).hexdigest(),
    }
    source_fingerprint_v4 = _source_fingerprint_v4(entries)
    scope = list(SCOPE)
    fingerprint_payload = {
        "entries": entries,
        "implementation": implementation,
        "source_fingerprint_v4": source_fingerprint_v4,
        "scope": scope,
    }
    encoded_payload = json.dumps(
        fingerprint_payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    fingerprint = hashlib.sha256(DOMAIN + encoded_payload).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "fingerprint": {
            "algorithm": "sha256",
            "domain_hex": DOMAIN.hex(),
            "sha256": fingerprint,
        },
        "implementation": implementation,
        "source_fingerprint_v4": source_fingerprint_v4,
        "scope": scope,
        "entries": entries,
    }


def capture(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Capture twice and reject a checkout that changes during collection."""
    root_path = pathlib.Path(root).resolve(strict=True)
    first = _capture_once(root_path)
    second = _capture_once(root_path)
    if first != second:
        raise InventoryError("Hub build inputs changed while inventory was captured")
    return first


def verify(root: str | os.PathLike[str], expected: dict[str, Any]) -> None:
    current = capture(root)
    if current != expected:
        raise InventoryError("Hub build inputs changed after inventory capture")


def _write_atomic(path: str, value: dict[str, Any]) -> None:
    destination = pathlib.Path(path)
    directory = destination.parent.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".hub-input-inventory-", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=True, sort_keys=True, indent=2)
            output.write("\n")
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--root", required=True)
    capture_parser.add_argument("--output")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True)
    verify_parser.add_argument("--expected", required=True)
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "capture":
            result = capture(arguments.root)
            if arguments.output:
                _write_atomic(arguments.output, result)
            else:
                json.dump(result, sys.stdout, ensure_ascii=True, sort_keys=True, indent=2)
                sys.stdout.write("\n")
            return 0

        with open(arguments.expected, encoding="utf-8") as source:
            expected = json.load(source)
        verify(arguments.root, expected)
        return 0
    except (InventoryError, OSError, json.JSONDecodeError) as error:
        print(f"hub-build-input-inventory: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
