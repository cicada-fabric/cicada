"""Independent synthetic tests for Hub build-input inventory verification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from hub_input_inventory import (  # noqa: E402
    InventoryVerificationError,
    LICENSE_SCOPE,
    SCOPE,
    verify_inventory,
)
from hub_input_inventory_git import verify_repository  # noqa: E402


INVENTORY_DOMAIN = bytes.fromhex(
    "6369636164612d6875622d6275696c642d696e7075742d696e76656e746f72792d763100"
)
V4_DOMAIN = bytes.fromhex("6369636164612d6875622d6275696c642d696e707574732d763400")
V4_REPRODUCTION = {
    "path_order": "filesystem path bytes, ascending",
    "path_length": "8-byte unsigned big-endian",
    "mode": "stat.S_IMODE(raw_mode), 4-byte unsigned big-endian",
    "content_digest": "raw 32-byte SHA-256 of file bytes or symlink target bytes",
    "missing_paths": "skipped",
}
IMPLEMENTATION_PATH = "scripts/hub-build-input-inventory.py"
IMPLEMENTATION_SHA256 = "a" * 64
CATALOG_CONTENT = b'{"synthetic_catalog":true}\n'
CATALOG_SHA256 = hashlib.sha256(CATALOG_CONTENT).hexdigest()
REVISION = "1" * 40
TEST_TMP = Path(os.environ.get(
    "CICADA_CLIENT_TEST_TMP", "/gpu1-share/data/cicada-client/hub-input-inventory-20261001/tmp",
))


def _raw_mode(file_type: str, permissions: int) -> int:
    if file_type == "regular":
        return stat.S_IFREG | permissions
    if file_type == "symlink":
        return stat.S_IFLNK | permissions
    raise ValueError(file_type)


def _entry(
    path: str,
    content: bytes = b"synthetic input\n",
    *,
    file_type: str = "regular",
    permissions: int = 0o644,
    git_index: dict[str, str] | None = None,
) -> dict[str, object]:
    raw = path.encode("utf-8")
    raw_mode = _raw_mode(file_type, permissions)
    result: dict[str, object] = {
        "path": path,
        "path_bytes_hex": raw.hex(),
        "file_type": file_type,
        "raw_mode": f"0o{raw_mode:o}",
        "size_bytes": len(content),
        "content_sha256": hashlib.sha256(content).hexdigest(),
    }
    if git_index is not None:
        result["git_index"] = dict(git_index)
    return result


def _missing(path: str) -> dict[str, object]:
    return {
        "path": path,
        "path_bytes_hex": path.encode("utf-8").hex(),
        "file_type": "missing",
        "raw_mode": None,
        "size_bytes": None,
        "content_sha256": None,
    }


def _v4_sha256(entries: list[dict[str, object]]) -> str:
    digest = hashlib.sha256(V4_DOMAIN)
    for entry in entries:
        if entry["file_type"] == "missing":
            continue
        path = bytes.fromhex(str(entry["path_bytes_hex"]))
        raw_mode = int(str(entry["raw_mode"])[2:], 8)
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(stat.S_IMODE(raw_mode).to_bytes(4, "big"))
        digest.update(bytes.fromhex(str(entry["content_sha256"])))
    return digest.hexdigest()


def _inventory_sha256(inventory: dict[str, object]) -> str:
    payload = {
        "entries": inventory["entries"],
        "implementation": inventory["implementation"],
        "source_fingerprint_v4": inventory["source_fingerprint_v4"],
        "scope": inventory["scope"],
    }
    encoded = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(INVENTORY_DOMAIN + encoded).hexdigest()


def _metadata(
    entries: list[dict[str, object]],
    *,
    revision: str = REVISION,
    dirty: bool = False,
    implementation_sha256: str = IMPLEMENTATION_SHA256,
    schema_version: str = "cicada.hub-build-source.v1",
    scope: tuple[str, ...] = SCOPE,
) -> dict[str, object]:
    sorted_entries = sorted(entries, key=lambda entry: bytes.fromhex(str(entry["path_bytes_hex"])))
    inventory: dict[str, object] = {
        "schema_version": "cicada.hub-build-input-inventory.v1",
        "fingerprint": {
            "algorithm": "sha256",
            "domain_hex": INVENTORY_DOMAIN.hex(),
            "sha256": "0" * 64,
        },
        "implementation": {
            "path": IMPLEMENTATION_PATH,
            "version": "1",
            "sha256": implementation_sha256,
        },
        "source_fingerprint_v4": {
            "algorithm": "sha256",
            "domain_hex": V4_DOMAIN.hex(),
            "sha256": "0" * 64,
            "reproduction": dict(V4_REPRODUCTION),
        },
        "scope": list(scope),
        "entries": sorted_entries,
    }
    return _resign({
        "schema_version": schema_version,
        "source": {
            "revision": revision,
            "dirty": dirty,
            "source_fingerprint": "0" * 64,
            "catalog_sha256": CATALOG_SHA256,
            "input_inventory": inventory,
        },
    })


def _resign(metadata: dict[str, object]) -> dict[str, object]:
    """Recompute both normative hashes after a deliberate fixture mutation."""
    source = metadata["source"]
    assert isinstance(source, dict)
    inventory = source["input_inventory"]
    assert isinstance(inventory, dict)
    entries = inventory["entries"]
    assert isinstance(entries, list)
    source_v4 = inventory["source_fingerprint_v4"]
    fingerprint = inventory["fingerprint"]
    assert isinstance(source_v4, dict) and isinstance(fingerprint, dict)
    source_v4["sha256"] = _v4_sha256(entries)
    source["source_fingerprint"] = source_v4["sha256"]
    fingerprint["sha256"] = _inventory_sha256(inventory)
    return metadata


def _simple_metadata(*, entries: list[dict[str, object]] | None = None,
                     dirty: bool = False,
                     scope: tuple[str, ...] = SCOPE) -> dict[str, object]:
    if entries is None:
        entries = [_entry("cicada-go/example.go")]
    return _metadata(entries, dirty=dirty, scope=scope)


def _cli_module():
    path = SCRIPT_DIR / "verify-hub-input-inventory.py"
    spec = importlib.util.spec_from_file_location("hub_input_inventory_cli_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load inventory verification CLI module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


class InventoryDataTests(unittest.TestCase):
    def test_valid_inventory_reproduces_both_domain_separated_digests(self) -> None:
        metadata = _simple_metadata()
        verified = verify_inventory(metadata, expected_revision=REVISION)
        inventory = metadata["source"]["input_inventory"]  # type: ignore[index]
        self.assertEqual(verified["inventory_sha256"], inventory["fingerprint"]["sha256"])
        self.assertEqual(verified["source_fingerprint"], inventory["source_fingerprint_v4"]["sha256"])
        self.assertEqual(verified["entry_count"], 1)
        self.assertEqual(verified["catalog_sha256"], CATALOG_SHA256)
        self.assertEqual(verified["source_status"], "CLEAN")

    def test_license_first_scope_is_supported_but_not_added_to_legacy_scope(self) -> None:
        current = _simple_metadata(
            entries=[_entry("LICENSE", b"synthetic license\n"), _entry("cicada-go/example.go")],
            scope=LICENSE_SCOPE,
        )
        verified = verify_inventory(current)
        self.assertEqual(verified["inventory"]["scope"], list(LICENSE_SCOPE))

        legacy_with_license = _simple_metadata(
            entries=[_entry("LICENSE", b"synthetic license\n")],
        )
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(legacy_with_license)

        unsupported = _simple_metadata(
            entries=[_entry("cicada-go/example.go")],
            scope=("LICENSE", *SCOPE[1:], SCOPE[0]),
        )
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(unsupported)

    def test_raw_mode_changes_v4_while_nonexecutable_git_mode_stays_the_same(self) -> None:
        narrow = _simple_metadata(entries=[_entry("cicada-go/example.go", permissions=0o644,
                                                   git_index={"blob_oid": "c" * 40,
                                                              "mode": "100644",
                                                              "object_format": "sha1"})])
        broad = _simple_metadata(entries=[_entry("cicada-go/example.go", permissions=0o664,
                                                  git_index={"blob_oid": "c" * 40,
                                                             "mode": "100644",
                                                             "object_format": "sha1"})])
        narrow_verified = verify_inventory(narrow)
        broad_verified = verify_inventory(broad)
        self.assertEqual(narrow["source"]["input_inventory"]["entries"][0]["git_index"]["mode"], "100644")  # type: ignore[index]
        self.assertEqual(broad["source"]["input_inventory"]["entries"][0]["git_index"]["mode"], "100644")  # type: ignore[index]
        self.assertNotEqual(narrow_verified["source_fingerprint"], broad_verified["source_fingerprint"])

    def test_rejects_bad_domains_even_when_outer_hash_is_recomputed(self) -> None:
        for field, bad in (("fingerprint", "00" * 32), ("source_fingerprint_v4", "11" * 32)):
            with self.subTest(field=field):
                metadata = _simple_metadata()
                inventory = metadata["source"]["input_inventory"]  # type: ignore[index]
                inventory[field]["domain_hex"] = bad
                _resign(metadata)
                with self.assertRaises(InventoryVerificationError):
                    verify_inventory(metadata)

    def test_rejects_digest_revision_catalog_and_helper_identity_mismatches(self) -> None:
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(_simple_metadata(), expected_revision="2" * 40)

        bad = _simple_metadata()
        bad["source"]["input_inventory"]["source_fingerprint_v4"]["sha256"] = "f" * 64  # type: ignore[index]
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(bad)

        bad = _simple_metadata()
        bad["source"]["input_inventory"]["fingerprint"]["sha256"] = "f" * 64  # type: ignore[index]
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(bad)

        metadata = _simple_metadata()
        metadata["source"]["source_fingerprint"] = "f" * 64  # type: ignore[index]
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(metadata)

        metadata = _simple_metadata()
        metadata["source"]["catalog_sha256"] = "not-a-digest"  # type: ignore[index]
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(metadata)

        for field, value in (("path", "scripts/untrusted.py"), ("version", "2")):
            with self.subTest(field=field):
                metadata = _simple_metadata()
                inventory = metadata["source"]["input_inventory"]  # type: ignore[index]
                inventory["implementation"][field] = value
                _resign(metadata)
                with self.assertRaises(InventoryVerificationError):
                    verify_inventory(metadata)

    def test_rejects_invalid_inventory_rows_and_git_claim_shapes(self) -> None:
        cases = []
        bad = _simple_metadata()
        bad["source"]["input_inventory"]["entries"][0]["content_sha256"] = "abc"  # type: ignore[index]
        cases.append(("sha", bad))

        bad = _simple_metadata()
        bad["source"]["input_inventory"]["entries"][0]["size_bytes"] = -1  # type: ignore[index]
        cases.append(("size", _resign(bad)))

        bad = _simple_metadata()
        row = bad["source"]["input_inventory"]["entries"][0]  # type: ignore[index]
        row["file_type"] = "fifo"
        cases.append(("type", _resign(bad)))

        bad = _simple_metadata()
        row = bad["source"]["input_inventory"]["entries"][0]  # type: ignore[index]
        row["raw_mode"] = "0o120777"
        cases.append(("mode-type", _resign(bad)))

        for field, value in (("blob_oid", "g" * 40), ("object_format", "sha512"),
                             ("mode", "100755")):
            bad = _simple_metadata(entries=[_entry("cicada-go/example.go", git_index={
                "blob_oid": "c" * 40, "mode": "100644", "object_format": "sha1",
            })])
            row = bad["source"]["input_inventory"]["entries"][0]  # type: ignore[index]
            row["git_index"][field] = value
            cases.append((f"git-{field}", _resign(bad)))

        for name, metadata in cases:
            with self.subTest(name=name), self.assertRaises(InventoryVerificationError):
                verify_inventory(metadata)

    def test_rejects_duplicate_unsorted_escaped_and_mismatched_display_paths(self) -> None:
        duplicate = _simple_metadata(entries=[_entry("cicada-go/a.go"), _entry("cicada-go/a.go")])
        escaped = _simple_metadata(entries=[_entry("../outside")])
        mismatch = _simple_metadata()
        mismatch["source"]["input_inventory"]["entries"][0]["path"] = "cicada-go/other.go"  # type: ignore[index]
        unsorted = _simple_metadata(entries=[_entry("cicada-go/a.go"), _entry("cicada-go/z.go")])
        unsorted["source"]["input_inventory"]["entries"].reverse()  # type: ignore[index]
        for metadata in (duplicate, escaped, _resign(mismatch), _resign(unsorted)):
            with self.subTest(paths=metadata["source"]["input_inventory"]["entries"]):  # type: ignore[index]
                with self.assertRaises(InventoryVerificationError):
                    verify_inventory(metadata)

    def test_missing_rows_are_diagnostic_only_and_require_explicit_dirty_metadata(self) -> None:
        metadata = _simple_metadata(entries=[_missing("cicada-go/deleted.go")], dirty=True)
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(metadata)
        verified = verify_inventory(metadata, require_clean=False)
        self.assertTrue(verified["dirty"])
        self.assertEqual(verified["source_status"], "DIRTY_DIAGNOSTIC_ONLY")
        self.assertEqual(verified["entry_count"], 1)

        inconsistent = _simple_metadata(entries=[_missing("cicada-go/deleted.go")], dirty=False)
        with self.assertRaises(InventoryVerificationError):
            verify_inventory(inconsistent, require_clean=False)

    def test_symlink_target_digest_is_part_of_the_valid_inventory(self) -> None:
        target = b"../target with spaces\n"
        metadata = _simple_metadata(entries=[_entry(
            "cicada-go/link", target, file_type="symlink", permissions=0o777,
            git_index={"blob_oid": "c" * 40, "mode": "120000", "object_format": "sha1"},
        )])
        verified = verify_inventory(metadata)
        self.assertEqual(verified["source_fingerprint"], metadata["source"]["source_fingerprint"])  # type: ignore[index]


class MetadataLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cli = _cli_module()

    def test_loader_hashes_exact_bytes_and_rejects_nonobject_duplicate_and_nonfinite_json(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as directory:
            path = Path(directory) / "metadata.json"
            encoded = b'{"synthetic":true}\n'
            path.write_bytes(encoded)
            parsed, digest = self.cli.load_metadata(path)
            self.assertEqual(parsed, {"synthetic": True})
            self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

            for encoded_bad in (
                b"[]", b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}',
                b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
            ):
                path.write_bytes(encoded_bad)
                with self.subTest(encoded=encoded_bad), self.assertRaises(ValueError):
                    self.cli.load_metadata(path)

    def test_loader_rejects_oversize_nonregular_and_leaf_symlink(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as directory:
            root = Path(directory)
            path = root / "metadata.json"
            path.write_bytes(b"{" + b" " * 200 + b"}")
            with mock.patch.object(self.cli, "MAX_METADATA_BYTES", 128):
                with self.assertRaises(ValueError):
                    self.cli.load_metadata(path)

            with self.assertRaises((ValueError, OSError)):
                self.cli.load_metadata(root)

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            symlink = root / "metadata-link.json"
            symlink.symlink_to(target)
            with self.assertRaises((ValueError, OSError)):
                self.cli.load_metadata(symlink)


def _fixture_helper_content(scope: tuple[str, ...]) -> bytes:
    return (
        b'IMPLEMENTATION_PATH = "scripts/hub-build-input-inventory.py"\n'
        b'IMPLEMENTATION_VERSION = "1"\n'
        + b"SCOPE = " + repr(scope).encode("ascii") + b"\n"
    )


class GitFixture:
    FILE_CONTENTS = {
        "cicada-go/sample.go": b"package sample\n",
        "cicada-go/internal/clientcontract/catalog.json": CATALOG_CONTENT,
        "docker/Dockerfile.hub": b"FROM scratch\n",
        ".dockerignore": b".git\n",
        "scripts/build-web-panel.sh": b"#!/bin/sh\nexit 0\n",
        "scripts/write-web-panel-manifest.py": b"pass\n",
        "scripts/build-hub-image.sh": b"#!/bin/sh\nexit 0\n",
        ".github/workflows/release.yml": b"name: synthetic\n",
    }
    HELPER_CONTENT = _fixture_helper_content(SCOPE)
    HELPER_SHA256 = hashlib.sha256(HELPER_CONTENT).hexdigest()

    def __init__(self, repo: Path, *, permissions: dict[str, int] | None = None,
                 symlinks: dict[str, str] | None = None, include_helper: bool = True,
                 scope: tuple[str, ...] = SCOPE) -> None:
        self.repo = repo
        self.scope = scope
        self.helper_content = _fixture_helper_content(scope)
        self.helper_sha256 = hashlib.sha256(self.helper_content).hexdigest()
        permissions = permissions or {}
        symlinks = symlinks or {}
        files = dict(self.FILE_CONTENTS)
        if "LICENSE" in scope:
            files["LICENSE"] = b"synthetic license\n"
        for relative, content in files.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative in symlinks:
                path.symlink_to(symlinks[relative])
            else:
                path.write_bytes(content)
                os.chmod(path, permissions.get(relative, 0o755 if content.startswith(b"#!/") else 0o644))
        if include_helper:
            helper = repo / "scripts/hub-build-input-inventory.py"
            helper.parent.mkdir(parents=True, exist_ok=True)
            helper.write_bytes(self.helper_content)
            os.chmod(helper, 0o755)
        _git(repo, "init", "--quiet")
        _git(repo, "add", "--all")
        _git(repo, "commit", "--quiet", "-m", "synthetic inventory fixture")
        self.revision = _git(repo, "rev-parse", "HEAD")
        self.object_format = _git(repo, "rev-parse", "--show-object-format")

    def entries(self) -> list[dict[str, object]]:
        raw_records = subprocess.run(
            ["git", "-C", os.fspath(self.repo), "ls-files", "--stage", "-z"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        records: dict[bytes, tuple[str, str]] = {}
        for record in raw_records.split(b"\0"):
            if not record:
                continue
            header, raw_path = record.split(b"\t", 1)
            mode, oid, stage = header.split(b" ", 2)
            if stage != b"0":
                raise AssertionError("synthetic repo unexpectedly has a non-stage-zero index entry")
            records[raw_path] = (mode.decode("ascii"), oid.decode("ascii"))
        entries = []
        for raw_path, (mode, oid) in records.items():
            relative = os.fsdecode(raw_path)
            if relative == "scripts/hub-build-input-inventory.py":
                continue
            path = self.repo / relative
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                content = os.fsencode(os.readlink(path))
                file_type = "symlink"
            else:
                content = path.read_bytes()
                file_type = "regular"
            entries.append(_entry(
                relative, content, file_type=file_type,
                permissions=stat.S_IMODE(metadata.st_mode),
                git_index={"blob_oid": oid, "mode": mode, "object_format": self.object_format},
            ))
        return sorted(entries, key=lambda entry: bytes.fromhex(str(entry["path_bytes_hex"])))

    def metadata(self, *, dirty: bool = False, entries: list[dict[str, object]] | None = None) -> dict[str, object]:
        return _metadata(entries or self.entries(), revision=self.revision, dirty=dirty,
                         implementation_sha256=self.helper_sha256, scope=self.scope)


class RepositoryVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for name in ("user.name", "user.email"):
            result = subprocess.run(["git", "config", "--global", "--get", name],
                                    check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0 or not result.stdout.strip():
                raise AssertionError("synthetic Git commits require the inherited server global identity")

    def setUp(self) -> None:
        TEST_TMP.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.root = Path(self._temporary.name)
        self.repo_path = self.root / "repo"
        self.repo_path.mkdir()
        self.repo = GitFixture(self.repo_path)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _verified(self, metadata: dict[str, object] | None = None, *, clean: bool = True):
        selected = metadata if metadata is not None else self.repo.metadata()
        return verify_inventory(selected, expected_revision=self.repo.revision, require_clean=clean)

    def test_clean_tiny_repository_and_pinned_helper_identity(self) -> None:
        verified = self._verified()
        result = verify_repository(
            verified, self.repo_path, expected_helper_sha256=GitFixture.HELPER_SHA256,
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("source_revision"), self.repo.revision)
        worktree = result.get("worktree")
        if isinstance(worktree, dict):
            worktree_status = worktree.get("result", worktree.get("status"))
        else:
            worktree_status = worktree
        self.assertEqual(worktree_status, "NOT_RUN")

    def test_license_scope_and_worktree_are_verified_and_license_tampering_fails(self) -> None:
        current_path = self.root / "license-repo"
        current_path.mkdir()
        current_repo = GitFixture(current_path, scope=LICENSE_SCOPE)
        metadata = current_repo.metadata()
        verified = verify_inventory(metadata, expected_revision=current_repo.revision)
        self.assertEqual(verified["inventory"]["scope"], list(LICENSE_SCOPE))
        self.assertIn("LICENSE", [row["path"] for row in verified["inventory"]["entries"]])

        result = verify_repository(
            verified, current_path, verify_worktree=True,
            expected_helper_sha256=current_repo.helper_sha256,
        )
        self.assertEqual(result["verification"], "PASS_CLEAN")
        self.assertEqual(result["worktree"]["result"], "PASS")

        tampered = current_repo.metadata()
        license_row = next(
            row for row in tampered["source"]["input_inventory"]["entries"]
            if row["path"] == "LICENSE"
        )
        license_row["content_sha256"] = "e" * 64
        _resign(tampered)
        tampered_verified = verify_inventory(tampered, expected_revision=current_repo.revision)
        with self.assertRaisesRegex(ValueError, "clean inventory bytes or Git mode differ"):
            verify_repository(tampered_verified, current_path)

        omitted = current_repo.metadata()
        omitted["source"]["input_inventory"]["entries"] = [
            row for row in omitted["source"]["input_inventory"]["entries"]
            if row["path"] != "LICENSE"
        ]
        _resign(omitted)
        omitted_verified = verify_inventory(omitted, expected_revision=current_repo.revision)
        with self.assertRaisesRegex(ValueError, "clean inventory omits a path"):
            verify_repository(omitted_verified, current_path)

    def test_inventory_cannot_downgrade_a_license_scoped_helper_to_legacy_scope(self) -> None:
        current_path = self.root / "scope-downgrade-repo"
        current_path.mkdir()
        current_repo = GitFixture(current_path, scope=LICENSE_SCOPE)
        metadata = current_repo.metadata()
        inventory = metadata["source"]["input_inventory"]
        inventory["scope"] = list(SCOPE)
        inventory["entries"] = [row for row in inventory["entries"] if row["path"] != "LICENSE"]
        _resign(metadata)

        verified = verify_inventory(metadata, expected_revision=current_repo.revision)
        with self.assertRaisesRegex(ValueError, "pinned helper scope differs"):
            verify_repository(verified, current_path)

    def test_replace_refs_cannot_substitute_pinned_git_blob_bytes(self) -> None:
        verified = self._verified()
        entry = verified["inventory"]["entries"][0]
        original_oid = entry["git_index"]["blob_oid"]
        replacement = subprocess.run(
            ["git", "-C", os.fspath(self.repo_path), "hash-object", "-w", "--stdin"],
            input=b"replacement bytes from a synthetic replace ref\n",
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.decode("ascii").strip()
        _git(self.repo_path, "replace", original_oid, replacement)
        # The replacement ref is inside the disposable fixture only. A correct
        # verifier must read the pinned object's real bytes, not its substitute.
        result = verify_repository(verified, self.repo_path)
        self.assertEqual(result.get("source_revision"), self.repo.revision)

    def test_rejects_pinned_git_bytes_omitted_scope_rows_and_tampered_blob_claims(self) -> None:
        verified = self._verified()
        tampered = self.repo.metadata()
        row = tampered["source"]["input_inventory"]["entries"][0]
        row["content_sha256"] = "e" * 64
        row["size_bytes"] += 1
        _resign(tampered)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(tampered), self.repo_path)

        omitted = self.repo.metadata()
        omitted["source"]["input_inventory"]["entries"].pop()
        _resign(omitted)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(omitted), self.repo_path)

        lie = self.repo.metadata()
        lie["source"]["input_inventory"]["entries"][0]["git_index"]["blob_oid"] = "0" * 40
        _resign(lie)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(lie), self.repo_path)

        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(verified, self.repo_path,
                              expected_helper_sha256="d" * 64)

    def test_clean_inventory_requires_matching_index_claims(self) -> None:
        metadata = self.repo.metadata()
        row = metadata["source"]["input_inventory"]["entries"][0]
        del row["git_index"]
        _resign(metadata)
        verified = self._verified(metadata)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(verified, self.repo_path)

    def test_rejects_tree_mode_and_object_format_lies(self) -> None:
        wrong_mode = self.repo.metadata()
        row = wrong_mode["source"]["input_inventory"]["entries"][0]
        # Keep the inventory row internally valid while claiming executable
        # raw mode; the pinned Git tree still has the non-executable mode.
        row["raw_mode"] = f"0o{stat.S_IFREG | 0o755:o}"
        row["git_index"]["mode"] = "100755"
        _resign(wrong_mode)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(wrong_mode), self.repo_path)

        wrong_format = self.repo.metadata()
        row = wrong_format["source"]["input_inventory"]["entries"][0]
        row["git_index"]["object_format"] = "sha256"
        row["git_index"]["blob_oid"] = "f" * 64
        _resign(wrong_format)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(wrong_format), self.repo_path)

    def test_raw_permission_inventory_can_match_same_git_tree_and_worktree(self) -> None:
        relative = "cicada-go/sample.go"
        path = self.repo_path / relative
        os.chmod(path, 0o664)
        rows = self.repo.entries()
        sample = next(row for row in rows if row["path"] == relative)
        self.assertEqual(sample["git_index"]["mode"], "100644")
        self.assertEqual(sample["raw_mode"], f"0o{stat.S_IFREG | 0o664:o}")
        verified = self._verified(self.repo.metadata(entries=rows))
        result = verify_repository(verified, self.repo_path, verify_worktree=True)
        self.assertEqual(result.get("source_revision"), self.repo.revision)
        worktree = result.get("worktree")
        self.assertIsInstance(worktree, dict)
        self.assertEqual(worktree.get("result", worktree.get("status")), "PASS")

    def test_worktree_bytes_mode_and_ancestor_symlink_drift_are_rejected(self) -> None:
        verified = self._verified()
        verify_repository(verified, self.repo_path, verify_worktree=True)

        sample = self.repo_path / "cicada-go/sample.go"
        sample.write_bytes(b"changed only in the temporary fixture\n")
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(verified, self.repo_path, verify_worktree=True)

        # Restore exact bytes before the ancestor-symlink probe.
        sample.write_bytes(GitFixture.FILE_CONTENTS["cicada-go/sample.go"])
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sample.go").write_bytes(b"never part of the repository\n")
        import shutil
        shutil.rmtree(self.repo_path / "cicada-go")
        (self.repo_path / "cicada-go").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(verified, self.repo_path, verify_worktree=True)

    def test_dirty_inventory_is_labeled_diagnostic_only_and_missing_rows_stay_untrusted(self) -> None:
        dirty = self.repo.metadata(dirty=True)
        verified = self._verified(dirty, clean=False)
        self.assertTrue(verified["dirty"])
        self.assertEqual(verified["source_status"], "DIRTY_DIAGNOSTIC_ONLY")
        result = verify_repository(verified, self.repo_path,
                                  expected_helper_sha256=GitFixture.HELPER_SHA256)
        self.assertIn("DIRTY_DIAGNOSTIC_ONLY", str(result))

    def test_dirty_older_git_revision_without_pinned_helper_is_explicitly_diagnostic(self) -> None:
        legacy_repo_path = self.root / "old-repo"
        legacy_repo_path.mkdir()
        legacy = GitFixture(legacy_repo_path, include_helper=False)
        # The newer helper exists only as an untracked current input; it is not
        # attributed to this older immutable commit. No helper code is run.
        helper = legacy_repo_path / "scripts/hub-build-input-inventory.py"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_bytes(GitFixture.HELPER_CONTENT)
        os.chmod(helper, 0o755)
        metadata = legacy.metadata(dirty=True)
        verified = verify_inventory(metadata, expected_revision=legacy.revision, require_clean=False)
        result = verify_repository(
            verified, legacy_repo_path, expected_helper_sha256=GitFixture.HELPER_SHA256,
        )
        self.assertEqual(result.get("verification"), "DIRTY_DIAGNOSTIC_ONLY")
        self.assertIn("NOT_PRESENT", str(result.get("helper")))
        with_worktree = verify_repository(
            verified, legacy_repo_path, verify_worktree=True,
            expected_helper_sha256=GitFixture.HELPER_SHA256,
        )
        self.assertEqual(with_worktree.get("verification"), "DIRTY_DIAGNOSTIC_ONLY")
        self.assertEqual(with_worktree["worktree"].get("result",
                                                       with_worktree["worktree"].get("status")), "PASS")

    def test_symlink_target_is_compared_as_blob_bytes_not_followed(self) -> None:
        self.repo_path = self.root / "symlink-repo"
        self.repo_path.mkdir()
        self.repo = GitFixture(self.repo_path, symlinks={"cicada-go/sample.go": "../outside"})
        verified = self._verified()
        verify_repository(verified, self.repo_path, verify_worktree=True)
        tampered = self.repo.metadata()
        row = tampered["source"]["input_inventory"]["entries"][0]
        if row["file_type"] == "symlink":
            row["content_sha256"] = hashlib.sha256(b"different target").hexdigest()
            row["size_bytes"] = len(b"different target")
        else:
            row = next(item for item in tampered["source"]["input_inventory"]["entries"]
                       if item["file_type"] == "symlink")
            row["content_sha256"] = hashlib.sha256(b"different target").hexdigest()
            row["size_bytes"] = len(b"different target")
        _resign(tampered)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            verify_repository(self._verified(tampered), self.repo_path)


if __name__ == "__main__":
    unittest.main()
