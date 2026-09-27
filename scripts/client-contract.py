#!/usr/bin/env python3
"""Export/verify the Client-Hub contract without third-party dependencies."""

import argparse
import base64
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
    "docs/client-hub-v13-client-prompt.md",
    "docs/client-hub-development.md",
    "docs/client-hub-interop-v1.md",
    "docs/client-hub-handoff.md",
    "docs/owner-approval-bootstrap.md",
    "docs/client-hub-v12-validation.md",
    "docs/client-hub-v12-client-prompt.md",
    "cicada-go/internal/clientwire/testdata/README.md",
    "cicada-go/internal/clientwire/testdata/client-control-v1.json",
    "cicada-go/internal/e2ee/testdata/endpoint-key-attestation-v1.json",
    "cicada-go/internal/e2ee/testdata/monitor-broadcast-consent-v2.json",
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
    openapi = files["docs/client-hub-v1.openapi.yaml"].decode()
    if "x-contract-revision: " + catalog["contract_revision"] not in openapi:
        raise ValueError("OpenAPI/catalog contract revision mismatch")
    for operation in operations:
        request_schema = operation.get("request_schema")
        result_schema = operation.get("result_schema")
        if request_schema or result_schema:
            if not request_schema or not result_schema:
                raise ValueError("operation has an incomplete OpenAPI schema pair")
            for schema in (request_schema, result_schema):
                if "    " + schema + ":\n" not in openapi:
                    raise ValueError("catalog references missing OpenAPI schema: " + schema)
            mapping = ("        " + operation["id"] + ":\n          request: '#/components/schemas/"
                       + request_schema + "'\n          result: '#/components/schemas/" + result_schema + "'")
            if mapping not in openapi:
                raise ValueError("catalog/OpenAPI request-result mapping drift: " + operation["id"])
    required_monitor = {
        "monitor.broadcast_prepare", "monitor.broadcast_confirm",
        "monitor.broadcast_status", "monitor.broadcast_recover",
    }
    monitor_ops = {operation["id"]: operation for operation in operations
                   if operation["id"] in required_monitor}
    if set(monitor_ops) != required_monitor or any(
            set(monitor_ops[operation]["roles"]) != {"manager", "external"}
            for operation in required_monitor):
        raise ValueError("Monitor operations are not complete for both owner roles")
    if ("membership.set_broadcast_permission: '#/components/schemas/TopologySetBroadcastPermissionAction'" not in openapi
            or "broadcast_permission_enabled:" not in openapi):
        raise ValueError("topology contract omits explicit broadcast permission or its snapshot projection")
    for marker in (
            "MonitorBroadcastEnvelopeV2:",
            "x-canonical-json-field-order: [type, version, suite, context, sealed, signature]",
            "x-signature-null-for-signing-bytes: true",
            "x-outer-and-inner-sequence-equality:",
            "x-session-chain-fields: forbidden"):
        if marker not in openapi:
            raise ValueError("OpenAPI Monitor v2 byte contract is incomplete: " + marker)
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
    monitor = json.loads(files["cicada-go/internal/e2ee/testdata/monitor-broadcast-consent-v2.json"])
    if (monitor.get("synthetic_fixture") is not True or monitor.get("never_deploy") is not True
            or "SYNTHETIC" not in monitor.get("warning", "")
            or "synthetic_never_deploy" not in monitor.get("context", {}).get("hub_id", "")):
        raise ValueError("unlabelled public Monitor consent fixture")
    scope = monitor.get("consent_scope")
    if not isinstance(scope, dict) or list(scope) != [
            "version", "broadcast_id", "group_id", "group_revision", "source", "recipients"]:
        raise ValueError("Monitor consent scope field order changed")
    scope_card_order = [
        "endpoint_id", "principal_id", "owner_id", "node_id", "membership_revision",
        "group_join_revision", "binding_id", "binding_epoch", "key_id", "key_version",
        "key_fingerprint", "key_proof_digest",
    ]
    source = scope.get("source")
    if not isinstance(source, dict) or list(source) != scope_card_order:
        raise ValueError("Monitor consent source field order changed")
    recipients = scope.get("recipients")
    if (not isinstance(recipients, list) or len(recipients) > 32
            or [card.get("endpoint_id") for card in recipients] != sorted(card.get("endpoint_id") for card in recipients)):
        raise ValueError("Monitor consent recipients are not bounded and ordered")
    if any(not isinstance(card, dict) or list(card) != scope_card_order for card in recipients):
        raise ValueError("Monitor consent recipient field order changed")
    scope_bytes = json.dumps(scope, ensure_ascii=False, separators=(",", ":")).encode()
    consent = sha256(b"cicada/client/monitor-broadcast/consent/v1\x00" + scope_bytes)
    context = monitor.get("context", {})
    context_order = [
        "hub_id", "owner_id", "client_device_id", "client_session_epoch", "client_key_version",
        "approval_id", "broadcast_id", "group_id", "monitor_endpoint_id", "monitor_key_id",
        "monitor_binding_id", "monitor_binding_epoch", "body_sha256", "recipient_snapshot_sha256",
        "expires_at", "consent_sha256", "confirm_request_sequence",
    ]
    if list(context) != context_order:
        raise ValueError("Monitor v2 context field order changed")
    if (consent != monitor.get("consent_sha256") or context.get("consent_sha256") != consent
            or context.get("confirm_request_sequence") != monitor.get("sequence")):
        raise ValueError("Monitor consent digest/context binding mismatch")
    monitor_identity = monitor.get("monitor_public_identity", {})
    source_bindings = (
        (scope.get("broadcast_id"), context.get("broadcast_id")),
        (scope.get("group_id"), context.get("group_id")),
        (source.get("endpoint_id"), context.get("monitor_endpoint_id")),
        (source.get("owner_id"), context.get("owner_id")),
        (source.get("binding_id"), context.get("monitor_binding_id")),
        (source.get("binding_epoch"), context.get("monitor_binding_epoch")),
        (source.get("key_id"), context.get("monitor_key_id")),
        (source.get("key_id"), monitor_identity.get("id")),
    )
    fingerprint = "sha256:" + sha256(
        b"cicada/nodekeys/peer-key-fingerprint/v1\x00"
        + base64.b64decode(monitor_identity.get("kem_public", ""), validate=True)
        + base64.b64decode(monitor_identity.get("signing_public", ""), validate=True)
    )
    if any(left != right for left, right in source_bindings) or source.get("key_fingerprint") != fingerprint:
        raise ValueError("Monitor consent source/context/key identity mismatch")
    envelope_bytes = base64.b64decode(monitor.get("envelope", ""), validate=True)
    envelope = json.loads(envelope_bytes)
    sealed = envelope.get("sealed", {})
    client_identity = monitor.get("client_public_identity", {})
    if (list(envelope) != ["type", "version", "suite", "context", "sealed", "signature"]
            or list(sealed) != ["version", "algorithm", "sequence", "kem_ciphertext", "nonce",
                               "ciphertext", "sender_id", "sender_signing_public", "signature"]):
        raise ValueError("Monitor v2 outer or sealed field order changed")
    if (envelope.get("type") != "MONITOR_BROADCAST" or envelope.get("version") != 2
            or envelope.get("suite") != "ML-KEM-768+ML-DSA-65/AES-256-GCM"
            or envelope.get("context") != context or sealed.get("version") != 1
            or sealed.get("sequence") != monitor.get("sequence")
            or sealed.get("sender_id") != client_identity.get("id")
            or sealed.get("sender_signing_public") != client_identity.get("signing_public")
            or not sealed.get("signature") or not envelope.get("signature")):
        raise ValueError("Monitor consent envelope does not match the public context")
    aad = b"cicada/client/monitor-broadcast/aad/v1\x00" + json.dumps(
        context, ensure_ascii=False, separators=(",", ":")).encode()
    if aad.hex() != monitor.get("aad_hex"):
        raise ValueError("Monitor consent envelope AAD bytes changed")
    unsigned_envelope = dict(envelope)
    unsigned_envelope["signature"] = None
    signed_envelope = b"cicada/client/monitor-broadcast/sign/v1\x00" + json.dumps(
        unsigned_envelope, ensure_ascii=False, separators=(",", ":")).encode()
    if signed_envelope.hex() != monitor.get("outer_signing_bytes_hex"):
        raise ValueError("Monitor consent envelope signing bytes changed")
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
