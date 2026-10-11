"""Mechanical, NONAUTH source binding for the current 0.162 acceptance bundle.

This module only reads explicitly named public build artifacts and writes a new
binding directory.  It never builds a product or runtime, runs Docker, or opens
credential paths.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


SCHEMA = "cicada.request-observer-current-binding.v1"
BUNDLE_SCHEMA = "cicada.request-observer-current-build.v1"
REUSE_BUNDLE_SCHEMA = "cicada.request-observer-packaging-reuse-build.v1"
REUSE_EQUALITY_SCHEMA = "cicada.native-packaging-reuse-equality.v1"
REUSE_INPUT_SCOPE = "PRODUCT_TRACKED_INVENTORY_AND_HELPER_SELECTED_BYTES_PACKAGE_GENERATED_OUTPUTS"
REUSE_GENERATED_PATHS = ["cicada-go/internal/server/ui/generated/"+name for name in
    ("cicada-webcrypto.wasm.gz", "panel.manifest.json", "wasm_exec.js")]
RUNTIME_SCHEMA = "cicada.request-observer-runtime-cli-overlay.v1"
CLI_VERSION = "0.162.1"
CLI_SHA256 = "628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1"
BASE_RUNTIME_IMAGE_ID = "sha256:e7540d8a8ff83952fe0dc8e46c20446d45566a2f6fb1195a98d0ab6afe216a29"
EVIDENCE_ROOT = Path("/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007")
BINDING_ROOT = EVIDENCE_ROOT / "request-observer-current-0162"
REPOSITORY_ROOT = Path("/home/zyf/CICADA")
CLI_BINARY = EVIDENCE_ROOT / "current-peer-cli01621-20261010a/shell-output/home/.codex/packages/standalone/releases/0.162.1-x86_64-unknown-linux-musl/bin/codex"

CURRENT_BUNDLE_FIELDS = {
    "schema", "output_parent", "current_commit", "source_dirty", "source_fingerprint",
    "delivery", "equality", "runtime_receipt", "official_cli",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(Path(path), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("CURRENT_BUNDLE_FILE_TYPE")
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("CURRENT_BUNDLE_FILE_CHANGED_DURING_READ")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def read_json(path: Path, limit: int = 1 << 20) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(Path(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("CURRENT_BUNDLE_FILE_TYPE")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > limit:
        raise ValueError("CURRENT_BUNDLE_JSON_LIMIT")
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError("CURRENT_BUNDLE_JSON_OBJECT")
    return value, raw


def public_path(path: str | Path, *, roots: tuple[Path, ...], exact: Path | None = None) -> Path:
    value = Path(path)
    if not value.is_absolute() or os.path.normpath(str(value)) != str(value):
        raise ValueError("CURRENT_BUNDLE_PATH_CANONICAL")
    if exact is not None and value != exact:
        raise ValueError("CURRENT_BUNDLE_PATH_EXACT")
    resolved = value.resolve(strict=True)
    if resolved != value:
        raise ValueError("CURRENT_BUNDLE_PATH_SYMLINK")
    if exact is None and not any(value.is_relative_to(root) for root in roots):
        raise ValueError("CURRENT_BUNDLE_PATH_SCOPE")
    metadata = value.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("CURRENT_BUNDLE_FILE_TYPE")
    return value


def file_row(path: str | Path, known_sha256: str | None = None) -> dict[str, Any]:
    value = Path(path)
    metadata = value.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("CURRENT_BUNDLE_FILE_TYPE")
    return {"path": str(value), "sha256": known_sha256 or sha256_file(value),
            "bytes": metadata.st_size, "rawmode": oct(metadata.st_mode)}


def _sha(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _image_id(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def validate_reuse_equality(delivery, equality, expected_commit):
    if (expected_commit!='328f5b5fa69571e67e7bb3e4582d5fb3bb920fd7' or
            equality.get('status')!='TRACKED_INPUT_INVENTORY_CURRENT_BYTES_EQUAL' or
            equality.get('input_scope')!=REUSE_INPUT_SCOPE or
            equality.get('excluded_generated_paths')!=REUSE_GENERATED_PATHS or
            equality.get('current_commit')!=expected_commit or
            equality.get('product_artifact_origin_revision')!=expected_commit or
            equality.get('fixture_revision')!='39bce535b93ab82c3b4f4fbf5cb09c6114dca942' or equality.get('fixture_dirty') is not True or
            equality.get('artifact_binary_sha256')!=delivery['binary_sha256'] or
            not _sha(equality.get('artifact_input_projection_sha256')) or
            equality.get('artifact_input_projection_sha256')!=equality.get('current_input_projection_sha256') or
            any(key in equality for key in ('artifact_compiled_inputs_sha256','current_compiled_inputs_sha256'))):
        raise ValueError('REUSE_EQUALITY_DOMAIN')
    package=Path(delivery['package'])
    metadata_path=package/'BUILD-METADATA.json'
    if sha256_file(metadata_path)!=delivery.get('package_metadata_sha256'):
        raise ValueError('REUSE_PACKAGE_METADATA_PIN')
    metadata,_=read_json(metadata_path)
    if (metadata.get('source',{}).get('revision')!=expected_commit or
            metadata['source'].get('dirty') is not False or metadata.get('pqtls_available') is not True or
            not _sha(equality.get('package_generated_manifest_sha256')) or
            equality['package_generated_manifest_sha256']!=metadata.get('hub_webcrypto_manifest_sha256')):
        raise ValueError('REUSE_PACKAGE_GENERATED_MANIFEST')


def current_bundle(delivery_path: Path, equality_path: Path, runtime_path: Path,
                   output_parent: Path, expected_commit: str) -> dict[str, Any]:
    """Validate actual Root-produced current artifacts and return their bound projection."""
    output_parent = Path(output_parent)
    if (not output_parent.is_absolute() or output_parent.parent != BINDING_ROOT or
            not re.fullmatch(r"bundle-[a-z0-9]{8,20}", output_parent.name)):
        raise ValueError("CURRENT_BUNDLE_OUTPUT_SCOPE")
    if type(expected_commit) is not str or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", expected_commit) is None:
        raise ValueError("CURRENT_EXPECTED_COMMIT")
    if output_parent.is_symlink():
        raise ValueError("CURRENT_BUNDLE_OUTPUT_SYMLINK")
    if BINDING_ROOT.exists() or BINDING_ROOT.is_symlink():
        root_metadata = BINDING_ROOT.lstat()
        if (not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode) or
                stat.S_IMODE(root_metadata.st_mode) != 0o700 or root_metadata.st_uid != os.getuid()):
            raise ValueError("CURRENT_BUNDLE_ROOT_MODE")

    delivery_path = public_path(delivery_path, roots=(EVIDENCE_ROOT,))
    equality_path = public_path(equality_path, roots=(EVIDENCE_ROOT,))
    runtime_path = public_path(runtime_path, roots=(EVIDENCE_ROOT,))
    cli_path = public_path(CLI_BINARY, roots=(), exact=CLI_BINARY)
    cli_sha = sha256_file(cli_path)
    if cli_sha != CLI_SHA256:
        raise ValueError("CURRENT_OFFICIAL_CLI_PIN")

    delivery, _ = read_json(delivery_path)
    equality, _ = read_json(equality_path)
    runtime, _ = read_json(runtime_path)
    required_delivery = ("source_repo", "commit", "source_dirty", "fingerprint",
                         "binary_sha256", "compiled_input_equality_receipt")
    if any(key not in delivery for key in required_delivery):
        raise ValueError("CURRENT_DELIVERY_FIELDS")
    if (delivery["source_repo"] != str(REPOSITORY_ROOT) or
            delivery["commit"] != expected_commit or type(delivery["source_dirty"]) is not bool or
            not _sha(delivery["fingerprint"]) or not _sha(delivery["binary_sha256"]) or
            delivery["compiled_input_equality_receipt"] != str(equality_path)):
        raise ValueError("CURRENT_DELIVERY_PROVENANCE")
    reuse = equality.get('schema') == REUSE_EQUALITY_SCHEMA
    if reuse:
        validate_reuse_equality(delivery, equality, expected_commit)
    else:
        if (equality.get("status") != "COMPILED_INPUTS_EXACT" or
                equality.get("current_commit") != expected_commit or
                equality.get("product_artifact_origin_revision") != expected_commit or
                equality.get("artifact_binary_sha256") != delivery["binary_sha256"] or
                not _sha(equality.get("artifact_compiled_inputs_sha256")) or
                equality.get("artifact_compiled_inputs_sha256") != equality.get("current_compiled_inputs_sha256")):
            raise ValueError("CURRENT_COMPILED_INPUT_EQUALITY")
    dirty = equality.get("product_artifact_origin_dirty", equality.get("source_dirty"))
    if (type(dirty) is not bool or dirty != delivery["source_dirty"] or
            type(equality.get("source_dirty")) is not bool or equality["source_dirty"] != dirty):
        raise ValueError("CURRENT_DIRTY_STATE_MISMATCH")
    equality_fingerprint = equality.get("product_source_fingerprint", equality.get("source_fingerprint"))
    if equality_fingerprint is not None and equality_fingerprint != delivery["fingerprint"]:
        raise ValueError("CURRENT_SOURCE_FINGERPRINT_MISMATCH")

    expected_runtime = {
        "schema": RUNTIME_SCHEMA,
        "status": "PASS_PINNED_CLI_IMAGE_OVERLAY",
        "base_runtime_image_id": BASE_RUNTIME_IMAGE_ID,
        "runtime_image_id": runtime.get("runtime_image_id"),
        "cli_version": CLI_VERSION,
        "cli_path": str(cli_path),
        "cli_sha256": CLI_SHA256,
        "overlay_mode": "PINNED_CLI_IMAGE_OVERLAY",
    }
    if (not _image_id(runtime.get("runtime_image_id")) or
            set(runtime) != set(expected_runtime) or
            any(runtime.get(key) != value for key, value in expected_runtime.items()) or
            not _image_id(runtime.get("runtime_image_id"))):
        raise ValueError("CURRENT_RUNTIME_RECEIPT")

    return {
        "schema": REUSE_BUNDLE_SCHEMA if reuse else BUNDLE_SCHEMA,
        "output_parent": str(output_parent),
        "current_commit": expected_commit,
        "source_dirty": delivery["source_dirty"],
        "source_fingerprint": delivery["fingerprint"],
        "delivery": {"path": str(delivery_path), "sha256": sha256_file(delivery_path),
                     "binary_sha256": delivery["binary_sha256"]},
        "equality": ({"path":str(equality_path),"sha256":sha256_file(equality_path),
            "input_scope":REUSE_INPUT_SCOPE,"input_projection_sha256":equality["current_input_projection_sha256"],
            "excluded_generated_paths":REUSE_GENERATED_PATHS,
            "package_generated_manifest_sha256":equality["package_generated_manifest_sha256"]} if reuse else
            {"path":str(equality_path),"sha256":sha256_file(equality_path),
             "compiled_inputs_sha256":equality["current_compiled_inputs_sha256"]}),
        "runtime_receipt": {"path": str(runtime_path), "sha256": sha256_file(runtime_path),
                             "image_id": runtime["runtime_image_id"]},
        "official_cli": {"path": str(cli_path), "sha256": cli_sha,
                         "version": CLI_VERSION},
    }


def current_binding_payload(template: dict[str, Any], *, bundle: dict[str, Any],
                            rows: list[dict[str, Any]], candidate_root: Path,
                            candidate_names: tuple[str, ...],
                            effective_sources: dict[str, str]) -> dict[str, Any]:
    """Copy immutable historical context and replace only current candidate rows."""
    payload = dict(template)
    by_path = {row["path"]: {key: row[key] for key in ("sha256", "bytes", "rawmode")} for row in rows}
    payload.update(schema=SCHEMA, output_parent=bundle["output_parent"],
                   current_bundle=bundle, candidate_root=str(candidate_root),
                   effective_sources=dict(effective_sources))
    payload["candidate_files"] = {name: by_path[str(candidate_root / name)] for name in candidate_names}
    payload["public_files"] = {path: by_path[path] for path in sorted(by_path)}
    payload["files"] = [{"path": path, **payload["public_files"][path]} for path in sorted(by_path)]
    runtime = bundle["runtime_receipt"]
    payload["current_CLI_Runtime"] = {
        "CLI_sha256": bundle["official_cli"]["sha256"],
        "image_id": runtime["image_id"],
        "native_acceptance": "NOT_RUN_RESOURCE_IMAGE",
        "resource_receipt_sha256": runtime["sha256"],
        "resource_receipt_path": runtime["path"],
        "version": bundle["official_cli"]["version"],
    }
    domains = dict(payload.get("source_domains", {}))
    domains.update(candidate="CURRENT_0162_CANDIDATE_SOURCE_ROWS",
                   product="CURRENT_DELIVERY_AND_COMPILED_INPUT_EQUALITY_RECEIPTS",
                   runtime="CURRENT_0162_DERIVED_RUNTIME_IMAGE_AND_OFFICIAL_CLI_ASSET")
    payload["source_domains"] = domains
    payload["scope"] = "CURRENT_0162_CURRENT_SOURCE_DELIVERY_EQUALITY_NONAUTH"
    if bundle["schema"] == REUSE_BUNDLE_SCHEMA:
        domains.update(product="CLEAN_328F_PACKAGE_WITH_ITS_GENERATED_OUTPUTS_AND_CURRENT_TRACKED_INPUT_BYTES",
                       helper="ACTUAL_39BCE_DIRTY_SELECTED_GO_INPUTS_AND_TLS_OVERLAY_BUILD",
                       candidate="CURRENT_BYTE_PINNED_CANDIDATE_ROWS_EXECUTION_SOURCE_BOUND_BY_DEFAULT_FIXTURE_MANIFEST")
        payload["scope"] = "PACKAGING_REUSE_328F_PRODUCT_39BCE_FIXTURE_NONAUTH"
    return payload


def binding_bytes(binding: dict[str, Any]) -> bytes:
    return json.dumps(binding, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def write_binding_pair(binding: dict[str, Any], output_parent: Path) -> tuple[Path, str]:
    """Create a fresh private directory and write the binding plus byte-identical alias."""
    output_parent = Path(output_parent)
    if (output_parent.exists() or output_parent.is_symlink() or
            output_parent.parent != BINDING_ROOT):
        raise ValueError("CURRENT_BUNDLE_OUTPUT_NOT_FRESH")
    if not output_parent.parent.exists():
        output_parent.parent.mkdir(mode=0o700)
    root_metadata = output_parent.parent.lstat()
    if (not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode) or
            stat.S_IMODE(root_metadata.st_mode) != 0o700 or root_metadata.st_uid != os.getuid()):
        raise ValueError("CURRENT_BUNDLE_ROOT_MODE")
    output_parent.mkdir(mode=0o700)
    output_metadata = output_parent.lstat()
    if (not stat.S_ISDIR(output_metadata.st_mode) or stat.S_ISLNK(output_metadata.st_mode) or
            stat.S_IMODE(output_metadata.st_mode) != 0o700 or output_metadata.st_uid != os.getuid()):
        raise ValueError("CURRENT_BUNDLE_OUTPUT_MODE")
    raw = binding_bytes(binding)
    paths = (output_parent / "binding.NONAUTH.json", output_parent / "source-binding.json")
    for path in paths:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
    return paths[0], hashlib.sha256(raw).hexdigest()


def validate_bundle_binding(binding: dict[str, Any], *, binding_raw: bytes,
                            binding_path: Path, expected_sha256: str | None,
                            required_paths: set[str], candidate_names: tuple[str, ...]) -> tuple[dict[str, Any], str]:
    """Strictly verify the refreshed binding, its rows, and identical sibling alias."""
    raw = binding_raw
    sha = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and sha != expected_sha256:
        raise ValueError("CURRENT_BINDING_SHA")
    if binding.get("schema") != SCHEMA or binding.get("authority") != "NONAUTH":
        raise ValueError("CURRENT_BINDING_SCHEMA")
    binding_file = Path(binding_path)
    parent = Path(binding_path).parent.resolve(strict=True)
    if (not binding_file.is_absolute() or binding_file.resolve(strict=True) != binding_file or
            binding.get("output_parent") != str(parent) or parent.parent != BINDING_ROOT):
        raise ValueError("CURRENT_BINDING_PARENT")
    parent_mode = parent.lstat()
    binding_mode = binding_file.lstat()
    if (not stat.S_ISDIR(parent_mode.st_mode) or stat.S_IMODE(parent_mode.st_mode) != 0o700 or
            parent_mode.st_uid != os.getuid() or not stat.S_ISREG(binding_mode.st_mode) or
            stat.S_IMODE(binding_mode.st_mode) != 0o600 or binding_mode.st_uid != os.getuid()):
        raise ValueError("CURRENT_BINDING_MODE")
    alias = parent / "source-binding.json"
    alias_mode = alias.lstat()
    if (not stat.S_ISREG(alias_mode.st_mode) or stat.S_IMODE(alias_mode.st_mode) != 0o600 or
            alias_mode.st_uid != os.getuid()):
        raise ValueError("CURRENT_BINDING_ALIAS_TYPE")
    if alias.read_bytes() != raw:
        raise ValueError("CURRENT_BINDING_ALIAS")
    bundle = binding.get("current_bundle")
    if type(bundle) is not dict or set(bundle) != CURRENT_BUNDLE_FIELDS:
        raise ValueError("CURRENT_BINDING_BUNDLE_SCHEMA")
    rebuilt = current_bundle(Path(bundle.get("delivery", {}).get("path", "")),
        Path(bundle.get("equality", {}).get("path", "")),
        Path(bundle.get("runtime_receipt", {}).get("path", "")), parent,
        bundle.get("current_commit"))
    if rebuilt != bundle:
        raise ValueError("CURRENT_BINDING_BUNDLE_CHANGED")
    rows = binding.get("files")
    if type(rows) is not list or any(type(row) is not dict or
            set(row) != {"path", "sha256", "bytes", "rawmode"} for row in rows):
        raise ValueError("CURRENT_BINDING_ROWS")
    listed = {row["path"]: {key: row[key] for key in ("sha256", "bytes", "rawmode")} for row in rows}
    if len(listed) != len(rows) or listed != binding.get("public_files") or set(listed) != required_paths:
        raise ValueError("CURRENT_BINDING_PATH_SET")
    bundle_hashes = {
        bundle["delivery"]["path"]: bundle["delivery"]["sha256"],
        bundle["equality"]["path"]: bundle["equality"]["sha256"],
        bundle["runtime_receipt"]["path"]: bundle["runtime_receipt"]["sha256"],
        bundle["official_cli"]["path"]: bundle["official_cli"]["sha256"],
    }
    for path, row in listed.items():
        value = Path(path)
        if not value.is_absolute() or str(value.resolve(strict=True)) != path:
            raise ValueError("CURRENT_BINDING_PATH_CANONICAL")
        metadata = value.lstat()
        observed_hash = bundle_hashes.get(path)
        if observed_hash is None:
            observed_hash = sha256_file(value)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size != row["bytes"] or
                oct(metadata.st_mode) != row["rawmode"] or observed_hash != row["sha256"]):
            raise ValueError("CURRENT_BINDING_FILE_CHANGED")
    candidate_rows = binding.get("candidate_files")
    candidate_root = Path(binding.get("candidate_root", ""))
    if candidate_root.resolve(strict=True) != candidate_root:
        raise ValueError("CURRENT_BINDING_CANDIDATE_ROOT")
    expected_candidates = {name: listed[str(candidate_root / name)] for name in candidate_names}
    if candidate_rows != expected_candidates:
        raise ValueError("CURRENT_BINDING_CANDIDATE_ROWS")
    if (type(binding.get("effective_sources")) is not dict or
            set(binding["effective_sources"]) != {"audit", "bootstrap", "command", "gate", "provider"} or
            any(not _sha(value) for value in binding["effective_sources"].values())):
        raise ValueError("CURRENT_BINDING_EFFECTIVE_SOURCES")
    return binding, sha
