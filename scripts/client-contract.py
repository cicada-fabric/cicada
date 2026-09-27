#!/usr/bin/env python3
"""Export/verify the Client-Hub contract without third-party dependencies."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parent.parent
CATALOG = "cicada-go/internal/clientcontract/catalog.json"
FILES = (
    CATALOG,
    "docs/client-hub-v1.openapi.yaml",
    "docs/client-hub-wire-v1.md",
    "docs/android-client-hub-contract.md",
    "docs/client-hub-development.md",
    "docs/client-hub-interop-v1.md",
    "docs/client-hub-handoff.md",
    "docs/owner-approval-bootstrap.md",
    "docs/client-hub-v12-validation.md",
    "docs/client-hub-v12-client-prompt.md",
    "cicada-go/internal/clientwire/testdata/README.md",
    "cicada-go/internal/clientwire/testdata/client-control-v1.json",
    "cicada-go/internal/e2ee/testdata/endpoint-key-attestation-v1.json",
)
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def read_contract(root):
    files = {name: (root / name).read_bytes() for name in FILES}
    catalog = json.loads(files[CATALOG])
    if catalog["catalog_schema_version"] != 1 or catalog["wire_version"] != 1:
        raise ValueError("unsupported catalog/wire version")
    if not catalog["contract_revision"]:
        raise ValueError("missing contract revision")
    operations = catalog["operations"]
    names = [operation["id"] for operation in operations]
    if not names or any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("operation IDs must be nonempty and unique")
    for operation in operations:
        if operation["method"] != "POST" or not operation["roles"]:
            raise ValueError("operation method/roles missing")
        if set(operation["roles"]) - {"manager", "external"}:
            raise ValueError("unknown operation role")
        for field in ("request_ref", "result_ref"):
            reference = operation[field].split("#", 1)[0]
            if reference not in files:
                raise ValueError(f"unbundled {field}: {reference}")
    vectors = json.loads(files["cicada-go/internal/clientwire/testdata/client-control-v1.json"])
    if vectors.get("warning") != "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT":
        raise ValueError("unlabelled cryptographic fixture")
    if vectors.get("wire_version") != catalog["wire_version"]:
        raise ValueError("wire fixture/catalog version mismatch")
    attestation = json.loads(files["cicada-go/internal/e2ee/testdata/endpoint-key-attestation-v1.json"])
    if (attestation.get("warning") != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT"
            or attestation.get("fixture_version") != 1):
        raise ValueError("unlabelled Endpoint attestation fixture")
    proof = attestation.get("attestation_utf8", "").encode()
    if hashlib.sha256(proof).hexdigest() != attestation.get("proof_sha256"):
        raise ValueError("Endpoint attestation fixture digest mismatch")
    claims = json.loads(proof)
    if not isinstance(claims.get("signature"), str) or not claims["signature"]:
        raise ValueError("Endpoint attestation fixture signature missing")
    if claims.get("public_identity") != attestation.get("public_identity"):
        raise ValueError("Endpoint attestation fixture public key mismatch")
    claims["signature"] = None
    unsigned = json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode()
    signed = b"cicada/fabric/endpoint-key-attestation/v1\x00" + unsigned
    if signed.hex() != attestation.get("signed_input_hex"):
        raise ValueError("Endpoint attestation fixture signed bytes mismatch")
    return files, catalog


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def contract_manifest(files, catalog, revision, dirty):
    return {
        "manifest_version": 1,
        "contract_revision": catalog["contract_revision"],
        "wire_version": catalog["wire_version"],
        "catalog_sha256": sha256(files[CATALOG]),
        "source_revision": revision,
        "source_dirty": dirty,
        "files": {name: {"sha256": sha256(data), "bytes": len(data)}
                  for name, data in sorted(files.items())},
        "coverage": {
            "inner_rpc_shapes": "partial_prose_references",
            "android_interop": "NOT_RUN",
            "native_runtime": "NOT_RUN",
        },
    }


def archive_bytes(files, manifest):
    payload = {**files, "manifest.json": canonical(manifest) + b"\n"}
    output = io.BytesIO()
    # No wall clock, host UID, or absolute path in a published contract bundle.
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(payload.items()):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def verify_bundle(path):
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("bundle exceeds size limit")
    files = {}
    total = 0
    # Verify in memory. Never extract an untrusted archive to the filesystem.
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive:
            name = member.name
            if (not member.isfile() or PurePosixPath(name).is_absolute()
                    or ".." in PurePosixPath(name).parts or name in files):
                raise ValueError("unsafe or duplicate archive member")
            if name not in FILES and name != "manifest.json":
                raise ValueError(f"unexpected archive member: {name}")
            total += member.size
            if member.size < 0 or total > MAX_BUNDLE_BYTES:
                raise ValueError("expanded bundle exceeds size limit")
            files[name] = archive.extractfile(member).read()
    if set(files) != {*FILES, "manifest.json"}:
        raise ValueError("bundle is incomplete")
    manifest = json.loads(files.pop("manifest.json"))
    if manifest.get("manifest_version") != 1 or set(manifest["files"]) != set(FILES):
        raise ValueError("unsupported or incomplete manifest")
    for name, data in files.items():
        if manifest["files"][name] != {"sha256": sha256(data), "bytes": len(data)}:
            raise ValueError(f"bundle checksum mismatch: {name}")
    catalog = json.loads(files[CATALOG])
    if (manifest["catalog_sha256"] != sha256(files[CATALOG])
            or manifest["contract_revision"] != catalog["contract_revision"]
            or manifest["wire_version"] != catalog["wire_version"]):
        raise ValueError("manifest/catalog mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="check exportable files; Go tests check runtime contract drift")
    export = sub.add_parser("export", help="create a content-addressed, versioned protocol bundle")
    export.add_argument("--output", type=Path, required=True, help="output directory")
    inspect = sub.add_parser("verify", help="verify bundle contents without extracting")
    inspect.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if args.command == "verify":
        manifest = verify_bundle(args.bundle)
        print(json.dumps({"status": "PASS", "contract_revision": manifest["contract_revision"],
                          "catalog_sha256": manifest["catalog_sha256"],
                          "note": "integrity verified; trust the publisher separately"}))
        return
    files, catalog = read_contract(ROOT)
    summary = {"status": "PASS", "contract_revision": catalog["contract_revision"],
               "catalog_sha256": sha256(files[CATALOG]), "operations": len(catalog["operations"])}
    if args.command == "export":
        manifest = contract_manifest(files, catalog, git(ROOT, "rev-parse", "HEAD"),
                                     bool(git(ROOT, "status", "--porcelain")))
        data = archive_bytes(files, manifest)
        digest = sha256(data)
        args.output.mkdir(parents=True, exist_ok=True)
        path = args.output / f"client-hub-{digest}.tar.gz"
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError("existing artifact has different bytes")
        else:
            with path.open("xb") as output:
                output.write(data)
        verify_bundle(path)
        summary.update(bundle=str(path.resolve()), bundle_sha256=digest,
                       source_revision=manifest["source_revision"], source_dirty=manifest["source_dirty"])
    print(json.dumps(summary))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"Client contract failed: {error}", file=sys.stderr)
        sys.exit(1)
