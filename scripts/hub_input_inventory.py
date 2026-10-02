"""Validate Hub build-input inventory metadata without reading repository files.

This module verifies only the supplied data. Repository and implementation
file provenance must be checked by the caller in its own trust boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from pathlib import PurePosixPath
from typing import Any


SCHEMA_VERSION = "cicada.hub-build-input-inventory.v1"
SOURCE_METADATA_SCHEMA = "cicada.hub-build-source.v1"
BUILD_METADATA_SCHEMA = "cicada.hub-build.v1"
IMPLEMENTATION_PATH = "scripts/hub-build-input-inventory.py"
IMPLEMENTATION_VERSION = "1"
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
V4_REPRODUCTION = {
    "path_order": "filesystem path bytes, ascending",
    "path_length": "8-byte unsigned big-endian",
    "mode": "stat.S_IMODE(raw_mode), 4-byte unsigned big-endian",
    "content_digest": "raw 32-byte SHA-256 of file bytes or symlink target bytes",
    "missing_paths": "skipped",
}

MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_METADATA_NODES = 500_000
MAX_METADATA_DEPTH = 64
MAX_ENTRY_COUNT = 250_000
MAX_PATH_BYTES = 4096
MAX_FILE_SIZE = (1 << 63) - 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class InventoryVerificationError(ValueError):
    """Raised when Hub build-input metadata is incomplete or inconsistent."""


def _fail(message: str) -> None:
    raise InventoryVerificationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _ascii_json_string_length(value: str) -> int:
    """Return the size of a string as emitted by ensure_ascii JSON."""
    length = 2  # surrounding quotes
    short_escapes = {'"', "\\", "\b", "\f", "\n", "\r", "\t"}
    for character in value:
        codepoint = ord(character)
        if character in short_escapes:
            length += 2
        elif codepoint < 0x20:
            length += 6
        elif 0x20 <= codepoint < 0x7F:
            length += 1
        elif codepoint < 0x10000:
            length += 6
        else:
            length += 12
    return length


def _bounded_json_size(value: Any) -> None:
    """Reject non-JSON, cyclic, deeply nested, or oversized input values."""
    stack: list[tuple[str, Any, int]] = [("visit", value, 0)]
    active_containers: set[int] = set()
    nodes = 0
    estimated_bytes = 0

    while stack:
        action, current, depth = stack.pop()
        if action == "leave":
            active_containers.remove(current)
            continue

        nodes += 1
        _require(nodes <= MAX_METADATA_NODES, "metadata contains too many values")
        _require(depth <= MAX_METADATA_DEPTH, "metadata is nested too deeply")

        value_type = type(current)
        if value_type is str:
            estimated_bytes += _ascii_json_string_length(current)
        elif value_type is bool or current is None:
            estimated_bytes += 5
        elif value_type is int:
            decimal_upper_bound = max(1, (current.bit_length() * 30103) // 100000 + 1)
            _require(decimal_upper_bound + (1 if current < 0 else 0) <= MAX_METADATA_BYTES,
                     "metadata integer is too large")
            try:
                estimated_bytes += len(str(current))
            except ValueError as error:
                raise InventoryVerificationError("metadata integer is too large") from error
        elif value_type is float:
            _require(math.isfinite(current), "metadata contains a non-finite number")
            estimated_bytes += len(repr(current))
        elif value_type is list:
            identity = id(current)
            _require(identity not in active_containers, "metadata contains a cycle")
            _require(nodes + len(current) <= MAX_METADATA_NODES, "metadata contains too many values")
            active_containers.add(identity)
            estimated_bytes += 2 + max(0, len(current) - 1)
            stack.append(("leave", identity, depth))
            for item in reversed(current):
                stack.append(("visit", item, depth + 1))
        elif value_type is dict:
            identity = id(current)
            _require(identity not in active_containers, "metadata contains a cycle")
            _require(nodes + (2 * len(current)) <= MAX_METADATA_NODES, "metadata contains too many values")
            _require(all(type(key) is str for key in current), "metadata keys must be strings")
            active_containers.add(identity)
            estimated_bytes += 2 + max(0, len(current) - 1) + len(current)
            stack.append(("leave", identity, depth))
            for key, item in reversed(list(current.items())):
                stack.append(("visit", item, depth + 1))
                stack.append(("visit", key, depth + 1))
        else:
            _fail("metadata contains a non-JSON value")

        _require(estimated_bytes <= MAX_METADATA_BYTES, "metadata exceeds the size limit")


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    _require(type(value) is dict and set(value) == expected, f"invalid {label} fields")


def _sha256(value: Any, label: str) -> str:
    _require(type(value) is str and _SHA256_RE.fullmatch(value) is not None, f"invalid {label}")
    return value


def _revision(value: Any, label: str) -> str:
    _require(type(value) is str and _REVISION_RE.fullmatch(value) is not None, f"invalid {label}")
    return value


def _inventory_path(entry: dict[str, Any]) -> tuple[str, bytes]:
    path = entry["path"]
    path_hex = entry["path_bytes_hex"]
    _require(type(path) is str and path != "", "invalid inventory path")
    _require(
        "\\" not in path and not any(unicodedata.category(character) == "Cc" for character in path),
        "unsafe inventory path",
    )
    _require(not PurePosixPath(path).is_absolute(), "unsafe inventory path")
    components = path.split("/")
    _require(all(component not in ("", ".", "..") for component in components), "unsafe inventory path")
    _require(PurePosixPath(path).as_posix() == path, "non-canonical inventory path")

    _require(
        type(path_hex) is str and path_hex != "" and len(path_hex) <= 2 * MAX_PATH_BYTES,
        "invalid inventory path bytes",
    )
    try:
        raw_path = bytes.fromhex(path_hex)
    except ValueError as error:
        raise InventoryVerificationError("invalid inventory path bytes") from error
    _require(raw_path.hex() == path_hex, "non-canonical inventory path bytes")
    _require(len(raw_path) <= MAX_PATH_BYTES, "inventory path is too long")
    try:
        encoded_display = os.fsencode(path)
        decoded_display = os.fsdecode(raw_path)
    except (UnicodeError, ValueError) as error:
        raise InventoryVerificationError("invalid inventory path encoding") from error
    _require(encoded_display == raw_path and decoded_display == path, "inventory path bytes do not match path")

    in_scope = path.startswith("cicada-go/") or path in SCOPE[1:]
    _require(in_scope, "inventory path is outside the declared scope")
    return path, raw_path


def _parse_raw_mode(value: Any, file_type: str) -> int:
    _require(type(value) is str and value.startswith("0o"), "invalid raw file mode")
    digits = value[2:]
    _require(
        1 <= len(digits) <= 6 and all(character in "01234567" for character in digits),
        "invalid raw file mode",
    )
    raw_mode = int(digits, 8)
    _require(value == f"0o{raw_mode:o}" and raw_mode <= 0o177777, "non-canonical raw file mode")
    if file_type == "regular":
        _require(stat.S_ISREG(raw_mode), "regular row has a non-regular mode")
    elif file_type == "symlink":
        _require(stat.S_ISLNK(raw_mode), "symlink row has a non-symlink mode")
    else:
        _fail("unsupported inventory file type")
    return raw_mode


def _validate_git_index(value: Any, file_type: str, raw_mode: int) -> None:
    _exact_keys(value, {"blob_oid", "mode", "object_format"}, "Git index record")
    object_format = value["object_format"]
    _require(object_format in ("sha1", "sha256"), "unsupported Git object format")
    oid = value["blob_oid"]
    oid_length = 40 if object_format == "sha1" else 64
    _require(
        type(oid) is str and len(oid) == oid_length and all(character in "0123456789abcdef" for character in oid),
        "invalid Git blob object ID",
    )
    if file_type == "regular":
        expected_mode = "100755" if raw_mode & 0o111 else "100644"
    else:
        expected_mode = "120000"
    _require(value["mode"] == expected_mode, "Git index mode does not match the file type and executable bits")


def _validate_entries(entries: Any, source_dirty: bool) -> tuple[int, bool]:
    _require(type(entries) is list and len(entries) <= MAX_ENTRY_COUNT, "invalid inventory entries")
    previous_path: bytes | None = None
    seen_paths: set[bytes] = set()
    has_missing = False

    for entry in entries:
        _require(type(entry) is dict, "invalid inventory row")
        file_type = entry.get("file_type")
        if file_type == "missing":
            _exact_keys(
                entry,
                {"path", "path_bytes_hex", "file_type", "raw_mode", "size_bytes", "content_sha256"},
                "missing inventory row",
            )
            _require(entry["raw_mode"] is None and entry["size_bytes"] is None and entry["content_sha256"] is None,
                     "missing row must have null mode, size, and digest")
            has_missing = True
        else:
            _require(file_type in ("regular", "symlink"), "unsupported inventory file type")
            allowed = {"path", "path_bytes_hex", "file_type", "raw_mode", "size_bytes", "content_sha256"}
            if "git_index" in entry:
                allowed.add("git_index")
            _exact_keys(entry, allowed, "inventory row")

        _, raw_path = _inventory_path(entry)
        _require(raw_path not in seen_paths, "duplicate inventory path")
        seen_paths.add(raw_path)
        _require(previous_path is None or previous_path < raw_path, "inventory entries are not byte-sorted")
        previous_path = raw_path

        if file_type == "missing":
            continue

        raw_mode = _parse_raw_mode(entry["raw_mode"], file_type)
        size_bytes = entry["size_bytes"]
        _require(
            type(size_bytes) is int and 0 <= size_bytes <= MAX_FILE_SIZE,
            "invalid inventory file size",
        )
        _sha256(entry["content_sha256"], "content digest")
        if "git_index" in entry:
            _validate_git_index(entry["git_index"], file_type, raw_mode)

    _require(not has_missing or source_dirty, "missing inputs require dirty source metadata")
    return len(entries), has_missing


def _compute_v4(entries: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256(V4_DOMAIN)
    for entry in entries:
        if entry["file_type"] == "missing":
            continue
        raw_path = bytes.fromhex(entry["path_bytes_hex"])
        raw_mode = int(entry["raw_mode"][2:], 8)
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        digest.update(stat.S_IMODE(raw_mode).to_bytes(4, "big"))
        digest.update(bytes.fromhex(entry["content_sha256"]))
    return digest.hexdigest()


def _compute_inventory_fingerprint(inventory: dict[str, Any]) -> str:
    payload = {
        "entries": inventory["entries"],
        "implementation": inventory["implementation"],
        "source_fingerprint_v4": inventory["source_fingerprint_v4"],
        "scope": inventory["scope"],
    }
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(DOMAIN + encoded).hexdigest()


def verify_inventory(
    metadata: dict[str, Any],
    expected_revision: str | None = None,
    require_clean: bool = True,
) -> dict[str, Any]:
    """Validate captured source metadata and return its verified inventory.

    When ``require_clean`` is false, dirty metadata may be returned for
    diagnostic use and is labeled ``DIRTY_DIAGNOSTIC_ONLY``.
    """
    _require(type(metadata) is dict, "metadata must be an object")
    _require(type(require_clean) is bool, "require_clean must be a boolean")
    _bounded_json_size(metadata)

    _require(metadata.get("schema_version") in (SOURCE_METADATA_SCHEMA, BUILD_METADATA_SCHEMA),
             "unsupported Hub build metadata schema")
    source = metadata.get("source")
    _exact_keys(
        source,
        {"revision", "dirty", "source_fingerprint", "catalog_sha256", "input_inventory"},
        "source metadata",
    )

    source_revision = _revision(source["revision"], "source revision")
    if expected_revision is not None:
        expected_revision = _revision(expected_revision, "expected revision")
        _require(source_revision == expected_revision, "source revision mismatch")
    source_dirty = source["dirty"]
    _require(type(source_dirty) is bool, "source dirty state must be a boolean")
    if require_clean:
        _require(not source_dirty, "dirty source metadata is not accepted")

    source_fingerprint = _sha256(source["source_fingerprint"], "source fingerprint")
    catalog_sha256 = _sha256(source["catalog_sha256"], "catalog digest")
    inventory = source["input_inventory"]

    # Validate schema fields and row types first; permit missing rows only when
    # the enclosing metadata explicitly records a dirty checkout.
    fingerprint_sha, inventory_v4_sha = _validate_inventory_header(inventory)
    entries = inventory["entries"]
    entry_count, has_missing = _validate_entries(entries, source_dirty=source_dirty)
    _require(not has_missing or source_dirty, "missing inputs require dirty source metadata")
    _require(_compute_v4(entries) == inventory_v4_sha, "v4 source fingerprint mismatch")
    _require(source_fingerprint == inventory_v4_sha, "metadata source fingerprint mismatch")
    _require(_compute_inventory_fingerprint(inventory) == fingerprint_sha, "inventory fingerprint mismatch")

    return {
        "inventory": inventory,
        "source_revision": source_revision,
        "dirty": source_dirty,
        "source_fingerprint": source_fingerprint,
        "inventory_sha256": fingerprint_sha,
        "catalog_sha256": catalog_sha256,
        "entry_count": entry_count,
        "source_status": "DIRTY_DIAGNOSTIC_ONLY" if source_dirty else "CLEAN",
    }


def _validate_inventory_header(inventory: Any) -> tuple[str, str]:
    """Validate inventory fields not dependent on source dirty state."""
    _exact_keys(
        inventory,
        {"schema_version", "fingerprint", "implementation", "source_fingerprint_v4", "scope", "entries"},
        "inventory",
    )
    _require(inventory["schema_version"] == SCHEMA_VERSION, "unsupported inventory schema")
    _require(type(inventory["scope"]) is list and inventory["scope"] == list(SCOPE), "inventory scope mismatch")

    implementation = inventory["implementation"]
    _exact_keys(implementation, {"path", "version", "sha256"}, "implementation identity")
    _require(implementation["path"] == IMPLEMENTATION_PATH, "inventory implementation path mismatch")
    _require(implementation["version"] == IMPLEMENTATION_VERSION, "inventory implementation version mismatch")
    _sha256(implementation["sha256"], "implementation digest")

    fingerprint = inventory["fingerprint"]
    _exact_keys(fingerprint, {"algorithm", "domain_hex", "sha256"}, "inventory fingerprint")
    _require(fingerprint["algorithm"] == "sha256", "unsupported inventory fingerprint algorithm")
    _require(fingerprint["domain_hex"] == DOMAIN.hex(), "inventory fingerprint domain mismatch")
    fingerprint_sha = _sha256(fingerprint["sha256"], "inventory fingerprint")

    source_v4 = inventory["source_fingerprint_v4"]
    _exact_keys(source_v4, {"algorithm", "domain_hex", "sha256", "reproduction"}, "v4 source fingerprint")
    _require(source_v4["algorithm"] == "sha256", "unsupported v4 fingerprint algorithm")
    _require(source_v4["domain_hex"] == V4_DOMAIN.hex(), "v4 fingerprint domain mismatch")
    v4_sha = _sha256(source_v4["sha256"], "v4 source fingerprint")
    _exact_keys(source_v4["reproduction"], set(V4_REPRODUCTION), "v4 reproduction rules")
    _require(source_v4["reproduction"] == V4_REPRODUCTION, "v4 reproduction rules mismatch")

    return fingerprint_sha, v4_sha
