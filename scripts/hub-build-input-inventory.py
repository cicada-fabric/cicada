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
import shutil
import re
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

PQ_SCOPE = tuple(path for path in SCOPE if path != "docker/Dockerfile.hub") + (
    "docker/Dockerfile.hub-pqtls",
    "scripts/hub-build-input-inventory.py",
    "scripts/build-release.sh",
    "scripts/test-pqtls-packaging.sh",
)
PQ_DOMAIN = b"cicada-pqtls-distribution-inputs-v1\0"
PQ_HEADER_SHA256 = "970a70cabcb6058c0152f957925d62bca6274d5de25a8cece9540f746b4b443c"
PQ_RUNTIME_PINS = {
    "lib/libssl.so.3": "83a963dfc76672d91efad7ddbd151b8d9dfea69c1080b4980520d56566b35696",
    "lib/libcrypto.so.3": "f188195dd6841a349002ca8dc081ecaa1acf50503a3224ce8d2ccc5ee8a70352",
    "share/licenses/openssl/LICENSE.txt": "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
}


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


def _input_paths(root: bytes, scope: tuple[str, ...] = SCOPE) -> list[bytes]:
    output = _run_git(
        root,
        b"ls-files",
        b"--cached",
        b"--others",
        b"--exclude-standard",
        b"-z",
        b"--",
        *(os.fsencode(path) for path in scope),
    )
    return sorted({path for path in output.split(b"\0") if path})


def _index_entries(root: bytes, scope: tuple[str, ...] = SCOPE) -> dict[bytes, tuple[bytes, bytes]]:
    """Return only unambiguous stage-zero index modes and blob object IDs."""
    output = _run_git(root, b"ls-files", b"--stage", b"-z", b"--", *(os.fsencode(path) for path in scope))
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


def _capture_once(root_path: pathlib.Path, selected_scope: tuple[str, ...] = SCOPE) -> dict[str, Any]:
    root = os.fsencode(os.fspath(root_path))
    paths = _input_paths(root, selected_scope)
    index = _index_entries(root, selected_scope)
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
    scope = list(selected_scope)
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


def capture_runtime(prefix: str | os.PathLike[str]) -> dict[str, Any]:
    """Read only the accepted public headers, two libraries and license."""
    directory = pathlib.Path(prefix)
    if directory.is_symlink() or not directory.is_dir():
        raise InventoryError("PQ stage must be an existing regular directory")
    header_dir = directory / "include"
    if header_dir.is_symlink() or not header_dir.is_dir():
        raise InventoryError("accepted PQ development headers required")
    rows: dict[str, dict[str, Any]] = {}
    header_sha: dict[str, str] = {}
    for path in sorted(header_dir.rglob("*")):
        if path.is_symlink():
            raise InventoryError("PQ header symlinks are forbidden")
        if path.is_dir():
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise InventoryError("PQ headers must be regular files")
        name = path.relative_to(directory).as_posix()
        content = _read_regular(os.fsencode(path), metadata)
        digest = hashlib.sha256(content).hexdigest()
        header_sha[name] = digest
        rows[name] = {"sha256": digest, "bytes": len(content), "mode": stat.S_IMODE(metadata.st_mode)}
    canonical = "".join(f"{header_sha[p]}  {p}\n" for p in sorted(header_sha)).encode()
    if hashlib.sha256(canonical).hexdigest() != PQ_HEADER_SHA256:
        raise InventoryError("accepted OpenSSL3.5.9 header closure mismatch")
    for name, expected_sha in PQ_RUNTIME_PINS.items():
        path = directory / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise InventoryError("PQ runtime files must be regular, non-symlink files")
        content = _read_regular(os.fsencode(path), metadata)
        digest = hashlib.sha256(content).hexdigest()
        if digest != expected_sha:
            raise InventoryError("accepted OpenSSL3.5.9 runtime/license mismatch")
        rows[name] = {"sha256": digest, "bytes": len(content), "mode": stat.S_IMODE(metadata.st_mode)}
    aliases = {}
    for library in ("libssl", "libcrypto"):
        path = directory / "lib" / (library + ".so")
        target = library + ".so.3"
        if not path.is_symlink() or os.readlink(path) != target:
            raise InventoryError("PQ linker alias must reference its exact accepted local library")
        aliases["lib/" + library + ".so"] = target
    canonical = "".join(f"{rows[p]['sha256']}  {p}\n" for p in sorted(rows)).encode()
    return {"schema_version": "cicada.pqtls-runtime-inputs.v1", "openssl_version": "3.5.9",
            "platform": "linux/amd64", "source_archive_sha256": "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a",
            "headers_sha256": PQ_HEADER_SHA256, "closure_sha256": hashlib.sha256(canonical).hexdigest(), "files": rows, "linker_aliases": aliases}


def capture_pqtls(root: str | os.PathLike[str], prefix: str | os.PathLike[str]) -> dict[str, Any]:
    root_path = pathlib.Path(root).resolve(strict=True)
    def once() -> dict[str, Any]:
        source = _capture_once(root_path, PQ_SCOPE)
        # A PQ scope must never be described as the historical standard v4.
        source.pop("source_fingerprint_v4")
        runtime = capture_runtime(prefix)
        payload = {"source": source, "runtime": runtime, "transport_variant": "pqtls"}
        data = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        return {**payload, "schema_version": "cicada.pqtls-distribution-inputs.v1",
                "fingerprint": {"algorithm": "sha256", "domain_hex": PQ_DOMAIN.hex(), "sha256": hashlib.sha256(PQ_DOMAIN + data).hexdigest()}}
    first, second = once(), once()
    if first != second:
        raise InventoryError("PQ source/runtime inputs changed while being read")
    return first


def collect_go_notices(source: str, destination: str, tags: str, targets: str = "") -> None:
    """Retain actual toolchain and compiled dependency notices, not source trees."""
    output = pathlib.Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    goroot = subprocess.check_output(["go", "env", "GOROOT"], cwd=source, text=True).strip()
    (output / "go").mkdir(exist_ok=True)
    shutil.copyfile(pathlib.Path(goroot) / "LICENSE", output / "go" / "LICENSE")
    command = ["go", "list", "-deps", "-json"]
    if tags:
        command += ["-tags", tags]
    command.append("./cmd/cicada")
    selected_targets = targets.split(",") if targets else [subprocess.check_output(["go", "env", "GOOS"], cwd=source, text=True).strip() + "/" + subprocess.check_output(["go", "env", "GOARCH"], cwd=source, text=True).strip()]
    streams = []
    for target in selected_targets:
        if not re.fullmatch(r"(linux|darwin|windows)/(amd64|arm64)", target):
            raise InventoryError("unsupported notice collection target")
        goos, goarch = target.split("/")
        streams.append(subprocess.check_output(command, cwd=source, text=True,
                                               env={**os.environ, "GOOS": goos, "GOARCH": goarch}))
    stream = "\n".join(streams)
    decoder = json.JSONDecoder()
    modules: dict[str, dict[str, Any]] = {}
    while stream.strip():
        package, end = decoder.raw_decode(stream.lstrip())
        stream = stream.lstrip()[end:]
        module = package.get("Module")
        if not module or module.get("Main"):
            continue
        if module.get("Replace"):
            raise InventoryError("distribution requires an explicitly reviewed dependency replacement")
        name, version = module["Path"], module.get("Version", "")
        key = name + "@" + version
        row = modules.setdefault(key, {"module": name, "version": version, "sum": module.get("Sum"), "source": "https://pkg.go.dev/" + key, "notices": {}})
        module_root = pathlib.Path(module["Dir"]).resolve()
        directory = pathlib.Path(package["Dir"]).resolve()
        for ancestor in [directory, *directory.parents]:
            if ancestor != module_root and module_root not in ancestor.parents:
                break
            for file in sorted(ancestor.iterdir()):
                if not file.is_file() or not file.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
                    continue
                relative = file.relative_to(module_root)
                target = output / "modules" / name / version / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, target)
                row["notices"][relative.as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
            if ancestor == module_root:
                break
    if any(not row["notices"] for row in modules.values()):
        raise InventoryError("compiled dependency has no retained cached license/notice")
    manifest = {"toolchain": subprocess.check_output(["go", "version"], text=True).strip(), "go_source": "https://go.dev/src/", "compiled_targets": selected_targets, "build_tags": tags, "modules": [modules[k] for k in sorted(modules)]}
    (output / "go" / "MODULES.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")


def verify_distribution(root: str, prefix: str, package: str, receipt_path: str,
                        receipt_sha: str, image_receipt: str | None = None,
                        image_receipt_sha: str | None = None) -> dict[str, Any]:
    """Bind the test to independent build receipts and the current input closure."""
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_sha):
        raise InventoryError("independently expected receipt SHA256 required")
    receipt_file = pathlib.Path(receipt_path)
    if hashlib.sha256(receipt_file.read_bytes()).hexdigest() != receipt_sha:
        raise InventoryError("expected package build receipt SHA mismatch")
    receipt = json.loads(receipt_file.read_text())
    if receipt.get("schema_version") != "cicada.pqtls-package-build-receipt.v1":
        raise InventoryError("unsupported package build receipt")
    current = capture_pqtls(root, prefix)
    if receipt["source_fingerprint"] != current["fingerprint"]["sha256"]:
        raise InventoryError("package receipt does not match current source/runtime")
    directory = pathlib.Path(package)
    if directory.is_symlink() or not directory.is_dir():
        raise InventoryError("package must be a regular directory")
    actual: dict[str, str] = {}
    for file in directory.rglob("*"):
        if file.is_symlink():
            raise InventoryError("package symlinks are forbidden")
        if file.is_file():
            actual[file.relative_to(directory).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    if actual != receipt["package_file_sha256"]:
        raise InventoryError("package bytes do not match independent build receipt")
    metadata = json.loads((directory / "BUILD-METADATA.json").read_text())
    if (metadata["source"]["input_inventory"] != current or
            metadata["runtime"] != current["runtime"] or
            metadata["source"].get("source_fingerprint") != current["fingerprint"]["sha256"] or
            metadata.get("pqtls_available") is not True or
            metadata.get("cgo_enabled") is not True or
            metadata.get("transport_variant") != "pqtls" or
            metadata.get("targets") != ["linux/amd64"]):
        raise InventoryError("package metadata/input closure mismatch")
    archive = receipt_file.parent / "cicada-linux-amd64-pqtls.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != receipt["archive_sha256"]:
        raise InventoryError("archive does not match independent build receipt")
    image = None
    if image_receipt:
        file = pathlib.Path(image_receipt)
        if not image_receipt_sha or hashlib.sha256(file.read_bytes()).hexdigest() != image_receipt_sha:
            raise InventoryError("expected image build receipt SHA mismatch")
        image = json.loads(file.read_text())
        if (image.get("transport_variant") != "pqtls" or
                image["image"]["dockerfile"] != "docker/Dockerfile.hub-pqtls" or
                image["source"]["input_inventory"] != current or
                image["source"]["source_fingerprint"] != current["fingerprint"]["sha256"]):
            raise InventoryError("image receipt source/runtime mismatch")
        image_id = image["image"]["id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise InventoryError("immutable image ID required")
        inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", image_id], text=True))[0]
        labels = inspected["Config"].get("Labels", {})
        if (inspected["Id"] != image_id or labels.get("org.cicada.build.source-fingerprint") != current["fingerprint"]["sha256"] or
                labels.get("org.cicada.transport.variant") != "pqtls-linux-amd64"):
            raise InventoryError("actual immutable image metadata mismatch")
    return {"source_fingerprint": current["fingerprint"]["sha256"], "input_inventory": current,
            "package_build_receipt_sha256": receipt_sha, "package_file_sha256": actual,
            "archive_sha256": receipt["archive_sha256"], "image_id": image["image"]["id"] if image else None,
            "image_build_receipt_sha256": image_receipt_sha if image else None}


def distribution_dirty(root: str) -> bool:
    """PQ provenance describes the whole worktree, including packaging inputs."""
    return bool(_run_git(os.fsencode(root), b"status", b"--porcelain=v1", b"--untracked-files=all"))


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
    capture_parser.add_argument("--transport", choices=("standard", "pqtls"), default="standard")
    capture_parser.add_argument("--pqtls-stage")
    capture_parser.add_argument("--fingerprint-only", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True)
    verify_parser.add_argument("--expected", required=True)
    verify_parser.add_argument("--pqtls-stage")
    runtime_parser = subparsers.add_parser("runtime")
    runtime_parser.add_argument("--pqtls-stage", required=True)
    dirty_parser = subparsers.add_parser("dirty")
    dirty_parser.add_argument("--root", required=True)
    notices_parser = subparsers.add_parser("go-notices")
    notices_parser.add_argument("--source", required=True)
    notices_parser.add_argument("--destination", required=True)
    notices_parser.add_argument("--tags", default="")
    notices_parser.add_argument("--targets", default="")
    distribution_parser = subparsers.add_parser("verify-distribution")
    distribution_parser.add_argument("--root", required=True)
    distribution_parser.add_argument("--pqtls-stage", required=True)
    distribution_parser.add_argument("--package", required=True)
    distribution_parser.add_argument("--receipt", required=True)
    distribution_parser.add_argument("--receipt-sha256", required=True)
    distribution_parser.add_argument("--image-receipt")
    distribution_parser.add_argument("--image-receipt-sha256")
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "dirty":
            print("true" if distribution_dirty(arguments.root) else "false")
            return 0
        if arguments.command == "verify-distribution":
            result = verify_distribution(arguments.root, arguments.pqtls_stage, arguments.package,
                                         arguments.receipt, arguments.receipt_sha256,
                                         arguments.image_receipt, arguments.image_receipt_sha256)
            json.dump(result, sys.stdout, sort_keys=True, indent=2)
            sys.stdout.write("\n")
            return 0
        if arguments.command == "go-notices":
            collect_go_notices(arguments.source, arguments.destination, arguments.tags, arguments.targets)
            return 0
        if arguments.command == "runtime":
            json.dump(capture_runtime(arguments.pqtls_stage), sys.stdout, sort_keys=True, indent=2)
            sys.stdout.write("\n")
            return 0
        if arguments.command == "capture":
            if arguments.transport == "pqtls" and not arguments.pqtls_stage:
                raise InventoryError("--pqtls-stage is required for PQ")
            result = capture_pqtls(arguments.root, arguments.pqtls_stage) if arguments.transport == "pqtls" else capture(arguments.root)
            if arguments.fingerprint_only:
                print(result["fingerprint" if arguments.transport == "pqtls" else "source_fingerprint_v4"]["sha256"])
                return 0
            if arguments.output:
                _write_atomic(arguments.output, result)
            else:
                json.dump(result, sys.stdout, ensure_ascii=True, sort_keys=True, indent=2)
                sys.stdout.write("\n")
            return 0

        with open(arguments.expected, encoding="utf-8") as source:
            expected = json.load(source)
        if expected.get("transport_variant") == "pqtls":
            if not arguments.pqtls_stage or capture_pqtls(arguments.root, arguments.pqtls_stage) != expected:
                raise InventoryError("PQ source/runtime changed after capture")
        else:
            verify(arguments.root, expected)
        return 0
    except (InventoryError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"hub-build-input-inventory: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
