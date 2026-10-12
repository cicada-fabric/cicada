#!/usr/bin/env python3
"""Bounded, duplicate-key-rejecting validators for the local Hub update gate."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from typing import Any


SMALL_JSON_LIMIT = 2 * 1024 * 1024
MANIFEST_JSON_LIMIT = 8 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Invalid(ValueError):
    pass


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise Invalid("non-finite number")


def load_json_bytes(path: str, limit: int) -> bytes:
    with open(path, "rb") as stream:
        if os.fstat(stream.fileno()).st_size > limit:
            raise Invalid("input too large")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Invalid("input too large")
    return raw


def parse_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)


def load_json(path: str, limit: int) -> Any:
    return parse_json(load_json_bytes(path, limit))


def _dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid("expected object")
    return value


def _exact_keys(value: dict[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise Invalid("unexpected object shape")


def _string(value: Any) -> bool:
    return isinstance(value, str) and not any(ord(ch) < 32 for ch in value)


def validate_manifest(value: Any) -> None:
    manifest = _dict(value)
    _exact_keys(manifest, {"format_version", "complete", "created_at", "database", "contacts", "files"})
    if type(manifest["format_version"]) is not int or manifest["format_version"] != 1:
        raise Invalid("unsupported manifest version")
    if manifest["complete"] is not True or not _string(manifest["created_at"]) or not manifest["created_at"]:
        raise Invalid("incomplete manifest")

    database = _dict(manifest["database"])
    _exact_keys(database, {
        "copy_mode", "sqlite_version", "journal_mode", "integrity_check", "foreign_key_check",
        "schema_fingerprint", "checksum", "tables",
    })
    for field in ("copy_mode", "sqlite_version", "journal_mode", "integrity_check", "foreign_key_check", "schema_fingerprint"):
        if not _string(database[field]) or not database[field]:
            raise Invalid("invalid database metadata")
    if (database["copy_mode"] != "offline-byte-copy" or database["integrity_check"] != "ok" or
            database["foreign_key_check"] != "ok"):
        raise Invalid("database checks failed")
    if not HEX64.fullmatch(database["checksum"]) or not HEX64.fullmatch(database["schema_fingerprint"]):
        raise Invalid("invalid database checksum")
    tables = database["tables"]
    if not isinstance(tables, list):
        raise Invalid("invalid table inventory")
    for table_value in tables:
        table = _dict(table_value)
        _exact_keys(table, {"name", "rows"})
        if not _string(table["name"]) or type(table["rows"]) is not int or table["rows"] < 0:
            raise Invalid("invalid table inventory entry")

    contacts = _dict(manifest["contacts"])
    _exact_keys(contacts, {
        "contacts", "peer_sessions", "peer_messages", "replay_sequences", "send_sequence_total",
        "receive_count_total", "send_count_total", "contact_digest", "peer_session_digest",
        "peer_message_digest", "digest",
    })
    for field in ("contacts", "peer_sessions", "peer_messages", "replay_sequences"):
        if type(contacts[field]) is not int or contacts[field] < 0:
            raise Invalid("invalid contact counts")
    for field in ("send_sequence_total", "receive_count_total", "send_count_total"):
        if type(contacts[field]) is not int or contacts[field] < 0:
            raise Invalid("invalid contact totals")
    for field in ("contact_digest", "peer_session_digest", "peer_message_digest", "digest"):
        digest = contacts[field]
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise Invalid("invalid contact digest")

    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise Invalid("missing file inventory")
    seen: set[str] = set()
    for file_value in files:
        file_row = _dict(file_value)
        _exact_keys(file_row, {"path", "size", "mode", "sha256"})
        path = file_row["path"]
        if not _string(path) or not path or path.startswith("/") or "\\" in path:
            raise Invalid("invalid file path")
        pieces = path.split("/")
        if any(piece in {"", ".", ".."} for piece in pieces) or pieces[0] == "nodes":
            raise Invalid("unsafe or excluded file path")
        if path in seen:
            raise Invalid("duplicate file path")
        seen.add(path)
        if type(file_row["size"]) is not int or file_row["size"] < 0:
            raise Invalid("invalid file size")
        if type(file_row["mode"]) is not int or file_row["mode"] < 0 or file_row["mode"] > 0o777:
            raise Invalid("invalid file mode")
        if not isinstance(file_row["sha256"], str) or not HEX64.fullmatch(file_row["sha256"]):
            raise Invalid("invalid file checksum")


def command_compose(args: list[str]) -> None:
    path, project, volume, image, api_port = args
    config = _dict(load_json(path, SMALL_JSON_LIMIT))
    services = _dict(config.get("services"))
    volumes = _dict(config.get("volumes"))
    if set(services) != {"hub"} or config.get("name") != project:
        raise Invalid("wrong Compose scope")
    service = _dict(services["hub"])
    if (service.get("image") != image or service.get("network_mode") != "host" or
            service.get("restart") != "unless-stopped" or service.get("user") not in (None, "")):
        raise Invalid("wrong Hub service")
    environment = _dict(service.get("environment") or {})
    if (set(environment) != {"CICADA_API_HOST", "CICADA_API_PORT", "CICADA_STATE_DIR"} or
            environment.get("CICADA_API_HOST") != "127.0.0.1" or
            environment.get("CICADA_STATE_DIR") != "/state" or
            str(environment.get("CICADA_API_PORT", "")) != api_port):
        raise Invalid("wrong Hub environment")
    mounts = service.get("volumes")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise Invalid("wrong Hub mounts")
    mount = _dict(mounts[0])
    if (mount.get("type") != "volume" or mount.get("source") != "hub-state" or
            mount.get("target") != "/state" or mount.get("read_only", False) is not False):
        raise Invalid("wrong Hub state mount")
    named = _dict(volumes.get("hub-state"))
    if named.get("name") != volume:
        raise Invalid("wrong Hub volume")


def command_container(args: list[str]) -> None:
    inspect_path, expected_id, project, volume, output_path = args
    rows = load_json(inspect_path, SMALL_JSON_LIMIT)
    if not isinstance(rows, list) or len(rows) != 1:
        raise Invalid("wrong container result count")
    row = _dict(rows[0])
    cid, image_id = row.get("Id", ""), row.get("Image", "")
    state = _dict(row.get("State", {}))
    config = _dict(row.get("Config", {}))
    labels = _dict(config.get("Labels") or {})
    mounts = row.get("Mounts") or []
    host_config = _dict(row.get("HostConfig") or {})
    if (cid != expected_id or not re.fullmatch(r"[0-9a-f]{64}", cid) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or
            labels.get("com.docker.compose.project") != project or
            labels.get("com.docker.compose.service") != "hub" or
            not isinstance(config.get("Image"), str) or not config.get("Image") or
            config.get("User", "") not in ("", "cicada") or host_config.get("NetworkMode") != "host" or
            not isinstance(mounts, list) or len(mounts) != 1):
        raise Invalid("wrong Hub container")
    mount = _dict(mounts[0])
    source = mount.get("Source", "")
    if (mount.get("Type") != "volume" or mount.get("Name") != volume or
            mount.get("Destination") != "/state" or mount.get("RW") is not True or
            not isinstance(source, str) or not os.path.isabs(source) or
            any(ord(ch) < 32 for ch in source) or any(ch in source for ch in ",|")):
        raise Invalid("wrong Hub volume mount")
    status = state.get("Status")
    if status not in {"running", "exited", "created"} or state.get("Paused") or state.get("Restarting") or state.get("Dead"):
        raise Invalid("unsafe Hub state")
    name = row.get("Name", "")
    if not isinstance(name, str) or not name.startswith("/") or any(ord(ch) < 32 for ch in name) or any(ch in name for ch in "|,"):
        raise Invalid("invalid Hub name")
    with open(output_path, "w", encoding="utf-8") as stream:
        stream.write("\n".join((image_id, status, source, name, cid)) + "\n")


def command_volume(args: list[str]) -> None:
    inspect_path, project, volume, output_path = args
    rows = load_json(inspect_path, SMALL_JSON_LIMIT)
    if not isinstance(rows, list) or len(rows) != 1:
        raise Invalid("wrong volume result count")
    row = _dict(rows[0])
    labels = _dict(row.get("Labels") or {})
    mountpoint = row.get("Mountpoint", "")
    if (row.get("Name") != volume or row.get("Driver") != "local" or
            labels.get("com.docker.compose.project") != project or
            labels.get("com.docker.compose.volume") != "hub-state" or
            not isinstance(mountpoint, str) or not os.path.isabs(mountpoint) or
            any(ord(ch) < 32 for ch in mountpoint) or any(ch in mountpoint for ch in ",|")):
        raise Invalid("wrong Hub volume")
    with open(output_path, "w", encoding="utf-8") as stream:
        stream.write(mountpoint + "\n")


def command_destination(args: list[str]) -> None:
    destination, mountpoint, repo, uid_text, gid_text = args
    uid, gid = int(uid_text), int(gid_text)
    if (not os.path.isabs(destination) or any(ord(ch) < 32 for ch in destination) or
            any(ch in destination for ch in ",|\n") or os.path.lexists(destination)):
        raise Invalid("unsafe destination")
    parent = os.path.dirname(destination)
    if not parent or os.path.realpath(parent) != parent:
        raise Invalid("noncanonical destination parent")
    current = os.path.sep
    for component in parent.split(os.path.sep):
        if not component:
            continue
        current = os.path.join(current, component)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Invalid("unsafe destination parent")
    info = os.stat(parent, follow_symlinks=False)
    if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700:
        raise Invalid("destination parent is not private")
    parent_real = os.path.realpath(parent)
    mount_real = os.path.realpath(mountpoint)
    repo_real = os.path.realpath(repo)
    if parent_real != parent or mount_real != mountpoint:
        raise Invalid("noncanonical source or destination")
    if os.path.commonpath((parent_real, mount_real)) == mount_real:
        raise Invalid("destination overlaps Hub volume")
    if os.path.commonpath((parent_real, repo_real)) == repo_real:
        raise Invalid("destination overlaps source checkout")


def command_consumer(args: list[str]) -> None:
    inspect_path, volume = args
    rows = load_json(inspect_path, SMALL_JSON_LIMIT)
    if not isinstance(rows, list) or len(rows) != 1:
        raise Invalid("wrong consumer result count")
    row = _dict(rows[0])
    mounts = row.get("Mounts")
    if not isinstance(mounts, list):
        raise Invalid("invalid consumer mounts")
    for mount_value in mounts:
        mount = _dict(mount_value)
        if mount.get("Type") == "volume" and mount.get("Name") == volume:
            if type(mount.get("RW")) is not bool:
                raise Invalid("invalid volume access mode")
            if mount["RW"]:
                raise SystemExit(2)


def command_image(args: list[str]) -> None:
    image_path, expected_id = args
    rows = load_json(image_path, SMALL_JSON_LIMIT)
    if not isinstance(rows, list) or len(rows) != 1:
        raise Invalid("wrong image result count")
    row = _dict(rows[0])
    config = _dict(row.get("Config") or {})
    labels = _dict(config.get("Labels") or {})
    if row.get("Id") != expected_id or labels.get("org.cicada.role") != "hub" or config.get("User", "") != "cicada":
        raise Invalid("image is not the expected Hub")
    print("hub")


def command_manifests(args: list[str]) -> None:
    backup_path, verify_path, disk_manifest_path = args
    backup = load_json(backup_path, MANIFEST_JSON_LIMIT)
    verified = load_json(verify_path, MANIFEST_JSON_LIMIT)
    disk_bytes = load_json_bytes(disk_manifest_path, MANIFEST_JSON_LIMIT)
    on_disk = parse_json(disk_bytes)
    for manifest in (backup, verified, on_disk):
        validate_manifest(manifest)
    if backup != verified or backup != on_disk:
        raise Invalid("backup results differ")
    print(hashlib.sha256(disk_bytes).hexdigest())


COMMANDS = {
    "compose": (command_compose, 5),
    "container": (command_container, 5),
    "volume": (command_volume, 4),
    "destination": (command_destination, 5),
    "consumer": (command_consumer, 2),
    "image": (command_image, 2),
    "manifests": (command_manifests, 3),
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        return 2
    command, count = COMMANDS[argv[0]]
    if len(argv) != count + 1:
        return 2
    try:
        command(argv[1:])
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeDecodeError, json.JSONDecodeError, OverflowError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
