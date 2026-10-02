"""Verify Hub input inventory claims against an immutable Git revision.

This module is intentionally read-only. It does not import or execute the Hub
inventory producer. Git objects establish content and Git mode provenance;
raw filesystem modes are reported only when the optional worktree pass runs.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any


SCOPE = (
    "cicada-go",
    "docker/Dockerfile.hub",
    ".dockerignore",
    "scripts/build-web-panel.sh",
    "scripts/write-web-panel-manifest.py",
    "scripts/build-hub-image.sh",
    ".github/workflows/release.yml",
)
HELPER_PATH = "scripts/hub-build-input-inventory.py"
HELPER_VERSION = "1"
CATALOG_PATH = "cicada-go/internal/clientcontract/catalog.json"

_SHA_RE = re.compile(r"\A[0-9a-f]+\Z")
_HEX256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class RepositoryVerificationError(ValueError):
    """Raised when Git or optional worktree evidence contradicts the inventory."""


def _fail(message: str) -> None:
    raise RepositoryVerificationError(message)


def _git_env() -> dict[str, str]:
    # The repository argument, rather than ambient GIT_DIR/OBJECT_DIRECTORY/
    # INDEX_FILE overrides, must select the evidence being verified.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # In particular, keep status and index reads from opportunistically
    # refreshing the shared repository index.
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    # Replacement refs can make an immutable revision name resolve to different
    # commit or blob bytes than the object IDs recorded by the repository.
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    return environment


def _run_git(root: bytes, *arguments: bytes) -> bytes:
    try:
        result = subprocess.run(
            [b"git", b"-C", root, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(),
        )
    except OSError as error:
        raise RepositoryVerificationError("could not run read-only Git verification") from error
    if result.returncode != 0:
        raise RepositoryVerificationError("read-only Git verification command failed")
    return result.stdout


def _git_text(root: bytes, *arguments: bytes) -> str:
    output = _run_git(root, *arguments)
    try:
        return output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RepositoryVerificationError("Git returned a non-ASCII identity") from error


def _object_format(root: bytes) -> str:
    value = _git_text(root, b"rev-parse", b"--show-object-format")
    if value not in ("sha1", "sha256"):
        _fail("repository uses an unsupported Git object format")
    return value


def _object_id_ok(value: Any, object_format: str) -> bool:
    length = 40 if object_format == "sha1" else 64
    return isinstance(value, str) and len(value) == length and _SHA_RE.fullmatch(value) is not None


def _absolute_checkout_path(repository: Path | str) -> Path:
    """Normalize lexically and reject symlinks in every checkout path component."""
    supplied = os.fspath(repository)
    if not isinstance(supplied, (str, bytes)):
        _fail("repository path is invalid")
    try:
        raw = os.fsdecode(supplied)
        if not raw:
            _fail("repository path is empty")
        absolute = Path(os.path.abspath(raw))
        # os.path.abspath is lexical; this explicit walk avoids resolve(),
        # which follows symlinks before they can be rejected.
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current = current / component
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                _fail("repository path traverses a symlink")
        if not absolute.is_dir():
            _fail("repository path is not a directory")
        return absolute
    except RepositoryVerificationError:
        raise
    except OSError as error:
        raise RepositoryVerificationError("repository path is unavailable") from error


def _scope_path(path: bytes) -> bool:
    for scope in SCOPE:
        encoded = os.fsencode(scope)
        if scope == "cicada-go":
            if path == encoded or path.startswith(encoded + b"/"):
                return True
        elif path == encoded:
            return True
    return False


def _safe_relative_path(path_hex: Any, display_path: Any) -> bytes:
    if not isinstance(path_hex, str) or not path_hex or len(path_hex) % 2:
        _fail("inventory contains an invalid encoded path")
    try:
        raw = bytes.fromhex(path_hex)
    except ValueError as error:
        raise RepositoryVerificationError("inventory contains an invalid encoded path") from error
    if raw.hex() != path_hex:
        _fail("inventory path encoding is not canonical")
    if not raw or raw.startswith(b"/") or b"\\" in raw or b"\0" in raw:
        _fail("inventory contains an unsafe repository path")
    parts = raw.split(b"/")
    if any(part in (b"", b".", b"..") for part in parts):
        _fail("inventory contains an unsafe repository path")
    if not _scope_path(raw):
        _fail("inventory contains a path outside the fixed Hub input scope")
    try:
        rendered = os.fsdecode(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise RepositoryVerificationError("inventory path cannot be decoded") from error
    if display_path != rendered:
        _fail("inventory display path does not match its encoded path")
    return raw


def _parse_inventory(verified: dict[str, Any], object_format: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(verified, dict):
        _fail("verified inventory result is invalid")
    inventory = verified.get("inventory")
    if not isinstance(inventory, dict):
        _fail("verified inventory is missing")
    if inventory.get("scope") != list(SCOPE):
        _fail("inventory scope does not match the fixed Hub input scope")
    if inventory.get("schema_version") != "cicada.hub-build-input-inventory.v1":
        _fail("unsupported Hub input inventory schema")

    source_revision = verified.get("source_revision")
    if not _object_id_ok(source_revision, object_format):
        _fail("source revision is not a full object ID for this repository")
    if type(verified.get("dirty")) is not bool:
        _fail("source dirty state is invalid")

    source_fingerprint = verified.get("source_fingerprint")
    catalog_sha256 = verified.get("catalog_sha256")
    inventory_sha256 = verified.get("inventory_sha256")
    entry_count = verified.get("entry_count")
    if not isinstance(source_fingerprint, str) or not _HEX256_RE.fullmatch(source_fingerprint):
        _fail("source fingerprint is invalid")
    if not isinstance(catalog_sha256, str) or not _HEX256_RE.fullmatch(catalog_sha256):
        _fail("catalog digest is invalid")
    if not isinstance(inventory_sha256, str) or not _HEX256_RE.fullmatch(inventory_sha256):
        _fail("inventory digest is invalid")
    if type(entry_count) is not int or entry_count < 0:
        _fail("inventory entry count is invalid")

    fingerprint = inventory.get("fingerprint")
    if not isinstance(fingerprint, dict) or fingerprint.get("algorithm") != "sha256":
        _fail("inventory fingerprint metadata is invalid")
    if fingerprint.get("sha256") != inventory_sha256:
        _fail("verified inventory digest differs from its inventory")
    source_record = inventory.get("source_fingerprint_v4")
    if not isinstance(source_record, dict) or source_record.get("sha256") != source_fingerprint:
        _fail("verified source fingerprint differs from its inventory")
    if type(inventory.get("entries")) is not list:
        _fail("inventory entries are invalid")
    entries = inventory["entries"]
    if len(entries) != entry_count:
        _fail("verified entry count differs from its inventory")

    parsed: list[dict[str, Any]] = []
    prior_path: bytes | None = None
    for original in entries:
        if not isinstance(original, dict):
            _fail("inventory entry is invalid")
        entry = dict(original)
        path = _safe_relative_path(entry.get("path_bytes_hex"), entry.get("path"))
        if prior_path is not None and path <= prior_path:
            _fail("inventory paths are not uniquely sorted")
        prior_path = path
        entry["_path_bytes"] = path

        file_type = entry.get("file_type")
        raw_mode = entry.get("raw_mode")
        size_bytes = entry.get("size_bytes")
        content_sha256 = entry.get("content_sha256")
        if file_type == "missing":
            if raw_mode is not None or size_bytes is not None or content_sha256 is not None:
                _fail("missing inventory row contains file metadata")
        else:
            if file_type not in ("regular", "symlink"):
                _fail("inventory contains an unsupported filesystem type")
            if not isinstance(raw_mode, str) or not re.fullmatch(r"0o[0-7]+", raw_mode):
                _fail("inventory raw mode is invalid")
            numeric_mode = int(raw_mode, 8)
            expected_type = stat.S_IFREG if file_type == "regular" else stat.S_IFLNK
            if stat.S_IFMT(numeric_mode) != expected_type:
                _fail("inventory file type disagrees with raw mode")
            if type(size_bytes) is not int or size_bytes < 0:
                _fail("inventory file size is invalid")
            if not isinstance(content_sha256, str) or not _HEX256_RE.fullmatch(content_sha256):
                _fail("inventory content digest is invalid")

        git_index = entry.get("git_index")
        if git_index is not None:
            if not isinstance(git_index, dict):
                _fail("inventory Git index claim is invalid")
            if file_type not in ("regular", "symlink"):
                _fail("non-file inventory row claims Git index provenance")
            if git_index.get("object_format") != object_format:
                _fail("inventory Git index object format differs from the repository")
            if not _object_id_ok(git_index.get("blob_oid"), object_format):
                _fail("inventory Git index object ID is invalid")
            if git_index.get("mode") not in ("100644", "100755", "120000"):
                _fail("inventory Git index mode is unsupported")
            if git_index["mode"] != _row_git_mode(entry):
                _fail("inventory Git index mode disagrees with its file type or mode")
        parsed.append(entry)

    return inventory, parsed


def _row_git_mode(entry: dict[str, Any]) -> str:
    file_type = entry.get("file_type")
    if file_type == "symlink":
        return "120000"
    if file_type == "regular":
        raw_mode = int(entry["raw_mode"], 8)
        return "100755" if raw_mode & 0o111 else "100644"
    return ""


def _tree_entries(root: bytes, revision: str) -> dict[bytes, tuple[str, str, str]]:
    arguments = [
        b"ls-tree",
        b"-r",
        b"-t",
        b"-z",
        b"--full-tree",
        os.fsencode(revision),
        b"--",
        *(os.fsencode(path) for path in SCOPE),
    ]
    output = _run_git(root, *arguments)
    tree: dict[bytes, tuple[str, str, str]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            raw_mode, kind, oid = header.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as error:
            raise RepositoryVerificationError("Git returned an invalid tree entry") from error
        if not _scope_path(raw_path):
            continue
        if raw_mode == "160000" or kind == "commit":
            _fail("scoped Git submodules or gitlinks are unsupported")
        if kind == "tree":
            if raw_mode != "040000":
                _fail("Git returned an unsupported scoped directory mode")
            continue
        if kind != "blob" or raw_mode not in ("100644", "100755", "120000"):
            _fail("scoped Git tree contains an unsupported object or mode")
        if raw_path in tree:
            _fail("pinned Git tree contains a duplicate scoped path")
        tree[raw_path] = (raw_mode, oid, kind)

    for required in SCOPE[1:]:
        raw_required = os.fsencode(required)
        if raw_required not in tree:
            _fail("pinned Git tree is missing a required Hub build input")
    if not any(path.startswith(b"cicada-go/") for path in tree):
        _fail("pinned Git tree contains no scoped cicada-go inputs")
    return tree


def _helper_tree_entry(root: bytes, revision: str) -> tuple[str, str] | None:
    output = _run_git(
        root,
        b"ls-tree",
        b"-r",
        b"-z",
        b"--full-tree",
        os.fsencode(revision),
        b"--",
        os.fsencode(HELPER_PATH),
    )
    rows: list[tuple[str, str, str]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as error:
            raise RepositoryVerificationError("Git returned an invalid helper tree entry") from error
        if path == os.fsencode(HELPER_PATH):
            rows.append((mode, kind, oid))
    if not rows:
        return None
    if len(rows) != 1 or rows[0][1] != "blob" or rows[0][0] not in ("100644", "100755"):
        _fail("pinned Git revision does not contain the expected regular helper")
    return rows[0][0], rows[0][2]


def _batch_blob_info(root: bytes, object_format: str, object_ids: set[str]) -> dict[str, dict[str, Any]]:
    if not object_ids:
        return {}
    ordered = sorted(object_ids)
    hash_length = 40 if object_format == "sha1" else 64
    if any(len(value) != hash_length or _SHA_RE.fullmatch(value) is None for value in ordered):
        _fail("Git object claim is not a full object ID")

    try:
        process = subprocess.Popen(
            [b"git", b"-C", root, b"cat-file", b"--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(),
        )
    except OSError as error:
        raise RepositoryVerificationError("could not read pinned Git objects") from error
    assert process.stdin is not None and process.stdout is not None

    result: dict[str, dict[str, Any]] = {}
    try:
        for expected_oid in ordered:
            process.stdin.write(expected_oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline()
            if not header.endswith(b"\n"):
                _fail("Git object batch ended before its header")
            fields = header[:-1].split(b" ")
            if len(fields) == 2 and fields[1] == b"missing":
                _fail("claimed Git object is missing")
            if len(fields) != 3:
                _fail("Git returned an invalid object batch header")
            actual_oid, kind, size_bytes = fields
            if actual_oid.decode("ascii", "strict") != expected_oid or kind != b"blob":
                _fail("Git object claim does not name the expected blob")
            try:
                object_size = int(size_bytes)
            except ValueError as error:
                raise RepositoryVerificationError("Git returned an invalid blob size") from error
            if object_size < 0:
                _fail("Git returned an invalid blob size")

            content_hash = hashlib.sha256()
            git_hash = hashlib.new(object_format)
            git_hash.update(b"blob " + str(object_size).encode("ascii") + b"\0")
            remaining = object_size
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    _fail("Git object batch ended inside a blob")
                content_hash.update(chunk)
                git_hash.update(chunk)
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                _fail("Git object batch framing is invalid")
            if git_hash.hexdigest() != expected_oid:
                _fail("Git blob bytes do not hash to their claimed object ID")
            result[expected_oid] = {"size_bytes": object_size, "content_sha256": content_hash.hexdigest()}
        process.stdin.close()
        return_code = process.wait()
        if return_code != 0:
            _fail("Git object batch could not be completed")
        return result
    except (BrokenPipeError, OSError) as error:
        raise RepositoryVerificationError("Git object batch could not be completed") from error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _read_root_no_follow(root: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _fail("this platform cannot safely verify a worktree without following links")
    descriptor = os.open(os.fsencode(root.anchor), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in root.parts[1:]:
            next_descriptor = os.open(
                os.fsencode(component),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise RepositoryVerificationError("repository path changed during safe worktree access") from error


def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_parent(root_fd: int, path: bytes) -> tuple[int, bytes]:
    components = path.split(b"/")
    parent_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        return parent_fd, components[-1]
    except OSError as error:
        os.close(parent_fd)
        if isinstance(error, FileNotFoundError):
            return -1, components[-1]
        raise RepositoryVerificationError("worktree path traverses a non-directory or symlink") from error


def _read_worktree_entry(root_fd: int, path: bytes, object_format: str) -> dict[str, Any]:
    parent_fd, leaf = _open_parent(root_fd, path)
    if parent_fd == -1:
        return {"file_type": "missing", "raw_mode": None, "size_bytes": None, "content_sha256": None}
    try:
        try:
            before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"file_type": "missing", "raw_mode": None, "size_bytes": None, "content_sha256": None}

        if stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | os.O_NOFOLLOW
            try:
                descriptor = os.open(leaf, flags, dir_fd=parent_fd)
            except OSError as error:
                raise RepositoryVerificationError("worktree file changed while being opened") from error
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or _stat_signature(opened) != _stat_signature(before):
                    _fail("worktree file changed while being opened")
                content_hash = hashlib.sha256()
                git_hash = hashlib.new(object_format)
                git_hash.update(b"blob " + str(opened.st_size).encode("ascii") + b"\0")
                size = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    content_hash.update(chunk)
                    git_hash.update(chunk)
                    size += len(chunk)
                after = os.fstat(descriptor)
                if _stat_signature(opened) != _stat_signature(after) or size != opened.st_size:
                    _fail("worktree file changed while being read")
                try:
                    path_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError as error:
                    raise RepositoryVerificationError("worktree file changed while being read") from error
                if _stat_signature(after) != _stat_signature(path_after):
                    _fail("worktree file was replaced while being read")
                return {
                    "file_type": "regular",
                    "raw_mode": f"0o{after.st_mode:o}",
                    "size_bytes": size,
                    "content_sha256": content_hash.hexdigest(),
                    "git_blob_oid": git_hash.hexdigest(),
                }
            finally:
                os.close(descriptor)

        if stat.S_ISLNK(before.st_mode):
            target = os.fsencode(os.readlink(leaf, dir_fd=parent_fd))
            try:
                after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError as error:
                raise RepositoryVerificationError("worktree symlink changed while being read") from error
            if _stat_signature(before) != _stat_signature(after):
                _fail("worktree symlink changed while being read")
            return {
                "file_type": "symlink",
                "raw_mode": f"0o{after.st_mode:o}",
                "size_bytes": len(target),
                "content_sha256": hashlib.sha256(target).hexdigest(),
                "git_blob_oid": _git_blob_oid(object_format, target),
            }

        _fail("worktree scope contains a special filesystem node")
    finally:
        os.close(parent_fd)


def _git_blob_oid(object_format: str, content: bytes) -> str:
    digest = hashlib.new(object_format)
    digest.update(b"blob " + str(len(content)).encode("ascii") + b"\0")
    digest.update(content)
    return digest.hexdigest()


def _parse_index(root: bytes) -> dict[bytes, list[tuple[str, str, int]]]:
    output = _run_git(
        root,
        b"ls-files",
        b"--stage",
        b"-z",
        b"--",
        *(os.fsencode(path) for path in SCOPE),
    )
    entries: dict[bytes, list[tuple[str, str, int]]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, oid, stage_raw = header.decode("ascii").split(" ")
            stage = int(stage_raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise RepositoryVerificationError("Git returned an invalid index entry") from error
        if not _scope_path(path):
            continue
        entries.setdefault(path, []).append((mode, oid, stage))
    return entries


def _current_scope_paths(root: bytes) -> list[bytes]:
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
    paths = sorted({path for path in output.split(b"\0") if path})
    if any(not _scope_path(path) for path in paths):
        _fail("Git enumerated a path outside the fixed Hub input scope")
    return paths


def _status_snapshot(root: bytes) -> tuple[bool, str]:
    output = _run_git(
        root,
        b"-c",
        b"core.fsmonitor=false",
        b"-c",
        b"core.untrackedCache=false",
        b"status",
        b"--porcelain=v1",
        b"-z",
        b"--untracked-files=all",
    )
    return bool(output), hashlib.sha256(output).hexdigest()


def _head_revision(root: bytes, object_format: str) -> str:
    value = _git_text(root, b"rev-parse", b"--verify", b"HEAD^{commit}")
    if not _object_id_ok(value, object_format):
        _fail("current HEAD is not a full commit object ID")
    return value


def _verify_worktree(
    root_path: Path,
    root: bytes,
    entries: list[dict[str, Any]],
    object_format: str,
    source_revision: str,
    claimed_dirty: bool,
) -> dict[str, Any]:
    root_fd = _read_root_no_follow(root_path)
    try:
        start_revision = _head_revision(root, object_format)
        start_dirty, start_status_sha256 = _status_snapshot(root)
        if start_revision != source_revision:
            _fail("current worktree revision differs from the verified source revision")
        if start_dirty != claimed_dirty:
            _fail("current worktree dirty state differs from the verified source state")
        helper_before = _read_worktree_entry(root_fd, os.fsencode(HELPER_PATH), object_format)

        expected_paths = [entry["_path_bytes"] for entry in entries]
        first_paths = _current_scope_paths(root)
        if first_paths != expected_paths:
            _fail("current Hub input path enumeration differs from the verified inventory")
        first_rows = {path: _read_worktree_entry(root_fd, path, object_format) for path in first_paths}

        current_index = _parse_index(root)
        index_claims_verified = 0
        index_paths: set[bytes] = set()
        for entry in entries:
            path = entry["_path_bytes"]
            index_paths.add(path)
            rows = current_index.get(path, [])
            stage_zero = [row for row in rows if row[2] == 0]
            has_unmerged_stages = any(row[2] != 0 for row in rows)
            actual = first_rows[path]
            expected_claim: dict[str, str] | None = None
            if len(rows) == 1 and len(stage_zero) == 1 and not has_unmerged_stages:
                index_mode, index_oid, _ = stage_zero[0]
                if (
                    index_mode == _row_git_mode(actual)
                    and actual["file_type"] in ("regular", "symlink")
                    and index_oid == actual.get("git_blob_oid")
                ):
                    expected_claim = {
                        "blob_oid": index_oid,
                        "mode": index_mode,
                        "object_format": object_format,
                    }
            if entry.get("git_index") != expected_claim:
                _fail("current Git index provenance differs from the inventory claim")
            if expected_claim is not None:
                index_claims_verified += 1

        if any(path not in index_paths for path in current_index):
            _fail("current Git index has an unrepresented scoped path")

        second_paths = _current_scope_paths(root)
        second_rows = {path: _read_worktree_entry(root_fd, path, object_format) for path in second_paths}
        helper_after = _read_worktree_entry(root_fd, os.fsencode(HELPER_PATH), object_format)
        second_index = _parse_index(root)
        end_dirty, end_status_sha256 = _status_snapshot(root)
        end_revision = _head_revision(root, object_format)

        if first_paths != second_paths or first_rows != second_rows:
            _fail("worktree changed during repository verification")
        if helper_before != helper_after:
            _fail("helper changed during repository verification")
        if current_index != second_index:
            _fail("Git index changed during repository verification")
        if (
            start_revision != end_revision
            or start_dirty != end_dirty
            or start_status_sha256 != end_status_sha256
        ):
            _fail("repository revision or status changed during verification")

        for entry in entries:
            actual = first_rows[entry["_path_bytes"]]
            for field in ("file_type", "raw_mode", "size_bytes", "content_sha256"):
                if actual.get(field) != entry.get(field):
                    _fail("current worktree bytes, type, size, or raw mode differ from inventory")

        if helper_after.get("file_type") != "regular":
            _fail("current helper is missing or is not a regular file")
        return {
            "result": "PASS",
            "scoped_paths_verified": len(first_paths),
            "raw_filesystem_modes_verified": sum(1 for row in first_rows.values() if row["file_type"] != "missing"),
            "current_index_claims_verified": index_claims_verified,
            "repository_status_sha256": start_status_sha256,
            "helper_sha256": helper_after["content_sha256"],
        }
    finally:
        os.close(root_fd)


def _check_helper_source(content: bytes) -> None:
    path_values = re.findall(rb"(?m)^IMPLEMENTATION_PATH\s*=\s*([\"'])(.*?)\1\s*$", content)
    version_values = re.findall(rb"(?m)^IMPLEMENTATION_VERSION\s*=\s*([\"'])(.*?)\1\s*$", content)
    if len(path_values) != 1 or path_values[0][1].decode("ascii", "strict") != HELPER_PATH:
        _fail("pinned helper implementation path constant is invalid")
    if len(version_values) != 1 or version_values[0][1].decode("ascii", "strict") != HELPER_VERSION:
        _fail("pinned helper implementation version constant is invalid")


def verify_repository(
    verified: dict[str, Any],
    repository: Path | str,
    *,
    verify_worktree: bool = False,
    expected_helper_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify inventory provenance using read-only Git object and index queries.

    `verified` is the result from the independent inventory validator. A dirty
    result remains diagnostic evidence only. Optional worktree verification
    reads files safely and checks raw modes, the current index, and repository
    stability without executing the inventory helper.
    """
    if type(verify_worktree) is not bool:
        _fail("verify_worktree must be a bool")
    if expected_helper_sha256 is not None and (
        not isinstance(expected_helper_sha256, str)
        or _HEX256_RE.fullmatch(expected_helper_sha256) is None
    ):
        _fail("expected helper SHA-256 is invalid")

    root_path = _absolute_checkout_path(repository)
    root = os.fsencode(os.fspath(root_path))
    object_format = _object_format(root)
    inventory, entries = _parse_inventory(verified, object_format)

    source_revision = verified["source_revision"]
    resolved_revision = _git_text(root, b"rev-parse", b"--verify", os.fsencode(source_revision + "^{commit}"))
    if resolved_revision != source_revision:
        _fail("source revision does not resolve to its claimed commit")
    tree_oid = _git_text(root, b"rev-parse", b"--verify", os.fsencode(source_revision + "^{tree}"))
    if not _object_id_ok(tree_oid, object_format):
        _fail("source revision has an invalid tree object ID")

    pinned_tree = _tree_entries(root, source_revision)
    pinned_helper = _helper_tree_entry(root, source_revision)
    object_ids: set[str] = {row[1] for row in pinned_tree.values()}
    if pinned_helper is not None:
        object_ids.add(pinned_helper[1])
    elif not verified["dirty"]:
        _fail("clean pinned Git revision does not contain the expected helper")
    for entry in entries:
        claim = entry.get("git_index")
        if claim is not None:
            object_ids.add(claim["blob_oid"])
    blobs = _batch_blob_info(root, object_format, object_ids)

    pinned_tree_verified = 0
    inventory_present_in_tree = 0
    inventory_rows_matching_tree = 0
    clean = not verified["dirty"]
    entry_by_path = {entry["_path_bytes"]: entry for entry in entries}
    if len(entry_by_path) != len(entries):
        _fail("inventory contains duplicate paths")

    for path, (tree_mode, oid, _) in pinned_tree.items():
        blob = blobs[oid]
        pinned_tree_verified += 1
        row = entry_by_path.get(path)
        if row is None:
            if clean:
                _fail("clean inventory omits a path from the pinned Git tree")
            continue
        inventory_present_in_tree += 1
        if row.get("file_type") == "missing":
            if clean:
                _fail("clean inventory contains a missing scoped input")
            continue
        if (
            row["size_bytes"] == blob["size_bytes"]
            and row["content_sha256"] == blob["content_sha256"]
            and _row_git_mode(row) == tree_mode
        ):
            inventory_rows_matching_tree += 1
        elif clean:
            _fail("clean inventory bytes or Git mode differ from the pinned tree")

    if clean and set(entry_by_path) != set(pinned_tree):
        _fail("clean inventory path set differs from the pinned Git tree")

    if clean:
        for entry in entries:
            if entry.get("file_type") == "missing":
                _fail("clean inventory contains a missing scoped input")
            tree_row = pinned_tree.get(entry["_path_bytes"])
            expected_claim = None if tree_row is None else {
                "blob_oid": tree_row[1],
                "mode": tree_row[0],
                "object_format": object_format,
            }
            if entry.get("git_index") != expected_claim:
                _fail("clean inventory lacks a matching stage-zero Git index claim")

    # Every claimed git_index object is independently read and rehashed above.
    claimed_index_verified = 0
    claimed_index_matching_tree = 0
    for entry in entries:
        claim = entry.get("git_index")
        if claim is None:
            continue
        blob = blobs[claim["blob_oid"]]
        if blob["size_bytes"] != entry["size_bytes"] or blob["content_sha256"] != entry["content_sha256"]:
            _fail("claimed Git index blob does not match the inventory bytes")
        claimed_index_verified += 1
        tree_row = pinned_tree.get(entry["_path_bytes"])
        if tree_row is not None and tree_row[0] == claim["mode"] and tree_row[1] == claim["blob_oid"]:
            claimed_index_matching_tree += 1
        elif clean:
            _fail("clean Git index claim differs from the pinned tree")

    helper_record = inventory.get("implementation")
    if not isinstance(helper_record, dict):
        _fail("inventory helper implementation record is invalid")
    if (
        helper_record.get("path") != HELPER_PATH
        or helper_record.get("version") != HELPER_VERSION
        or not isinstance(helper_record.get("sha256"), str)
        or _HEX256_RE.fullmatch(helper_record["sha256"]) is None
    ):
        _fail("inventory helper path, version, or digest is invalid")
    helper_mode: str | None = None
    helper_oid: str | None = None
    helper_bytes_hash: str | None = None
    if pinned_helper is not None:
        helper_mode, helper_oid = pinned_helper
        helper_blob = blobs[helper_oid]
        helper_bytes_hash = helper_blob["content_sha256"]
        # Fetch only this small helper a second way for literal version/path
        # constant inspection. `cat-file` itself remains the sole source reader.
        helper_content = _run_git(root, b"cat-file", b"blob", os.fsencode(helper_oid))
        if len(helper_content) != helper_blob["size_bytes"] or hashlib.sha256(helper_content).hexdigest() != helper_bytes_hash:
            _fail("pinned helper blob changed between Git reads")
        if clean:
            try:
                _check_helper_source(helper_content)
            except UnicodeDecodeError as error:
                raise RepositoryVerificationError("pinned helper constants are not valid ASCII") from error
    if clean and helper_record["sha256"] != helper_bytes_hash:
        _fail("clean inventory helper digest differs from the pinned Git blob")
    if expected_helper_sha256 is not None and helper_record["sha256"] != expected_helper_sha256:
        _fail("inventory helper digest differs from the expected helper digest")
    if not clean and expected_helper_sha256 is None and not verify_worktree:
        _fail("dirty helper identity needs an expected digest or safe worktree verification")

    catalog_row = entry_by_path.get(os.fsencode(CATALOG_PATH))
    if catalog_row is None or catalog_row.get("file_type") != "regular":
        _fail("inventory does not contain the client contract catalog row")
    if catalog_row.get("content_sha256") != verified["catalog_sha256"]:
        _fail("catalog digest differs from its captured inventory row")
    pinned_catalog = pinned_tree.get(os.fsencode(CATALOG_PATH))
    if pinned_catalog is None:
        _fail("pinned Git tree is missing the client contract catalog")
    catalog_blob = blobs[pinned_catalog[1]]
    catalog_matches_pinned_tree = catalog_blob["content_sha256"] == verified["catalog_sha256"]
    if clean and not catalog_matches_pinned_tree:
        _fail("clean catalog digest differs from its pinned Git blob")

    if not clean:
        for entry in entries:
            if entry.get("file_type") == "missing":
                continue
            claim = entry.get("git_index")
            if claim is None:
                continue
            # This checks the claimed blob object and the row bytes, not the
            # current index and not a claim that this OID occupies the pinned
            # HEAD tree at the same path.
            if claim["mode"] != _row_git_mode(entry):
                _fail("dirty Git index claim mode differs from its captured file")

    if verify_worktree:
        worktree = _verify_worktree(root_path, root, entries, object_format, source_revision, verified["dirty"])
        if worktree["helper_sha256"] != helper_record["sha256"]:
            _fail("current helper bytes differ from the inventory implementation digest")
        worktree["helper_bytes_verified"] = True
    else:
        worktree = {"result": "NOT_RUN", "raw_filesystem_modes": "NOT_RUN"}

    return {
        "verification": "PASS_CLEAN" if clean else "DIRTY_DIAGNOSTIC_ONLY",
        "source_revision": source_revision,
        "git_tree_oid": tree_oid,
        "object_format": object_format,
        "dirty": verified["dirty"],
        "source_fingerprint": verified["source_fingerprint"],
        "inventory_sha256": verified["inventory_sha256"],
        "catalog_sha256": verified["catalog_sha256"],
        "catalog_matches_pinned_tree": catalog_matches_pinned_tree,
        "entry_count": len(entries),
        "pinned_tree_entries_verified": pinned_tree_verified,
        "inventory_paths_present_in_pinned_tree": inventory_present_in_tree,
        "inventory_rows_matching_pinned_tree": inventory_rows_matching_tree,
        "claimed_git_index_objects_verified": claimed_index_verified,
        "claimed_git_index_objects_matching_pinned_tree": claimed_index_matching_tree,
        "helper": {
            "path": HELPER_PATH,
            "version": HELPER_VERSION,
            "pinned_git_mode": helper_mode,
            "pinned_git_blob_oid": helper_oid,
            "pinned_git_status": "PRESENT" if pinned_helper is not None else "NOT_PRESENT",
            "pinned_sha256": helper_bytes_hash,
            "inventory_sha256_match": helper_record["sha256"] == helper_bytes_hash,
            "identity_basis": (
                "pinned_git_blob"
                if clean
                else "expected_digest"
                if expected_helper_sha256 is not None
                else "safe_worktree_bytes"
            ),
        },
        "worktree": worktree,
    }
