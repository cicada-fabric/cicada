#!/usr/bin/env python3
"""Export/verify the Client-Hub contract without third-party dependencies."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
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
    "cicada-go/internal/e2ee/testdata/owner-link-review-policy-proof-v1.json",
    "cicada-go/internal/e2ee/testdata/cross-owner-group-key-v2.json",
    "cicada-go/internal/e2ee/testdata/monitor-broadcast-consent-v2.json",
    "cicada-go/internal/e2ee/testdata/network-direct-key-consent-v1.json",
    "cicada-go/internal/e2ee/testdata/network-collaboration-key-consent-v1.json",
    "cicada-go/internal/e2ee/testdata/network-collaboration-broadcast-consent-v1.json",
    "cicada-go/internal/store/testdata/network-direct-key-production-v1.json",
)
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def node_schema(openapi, name):
    """Read the flat field declarations in our Node schemas, not arbitrary YAML."""
    match = re.search(r"^    " + re.escape(name) + r":\n(.*?)(?=^    \S|\Z)",
                      openapi, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError("missing Node schema: " + name)
    block = match.group(1)
    properties = set(re.findall(r"^        ([a-z_]+):", block, re.MULTILINE))
    required = re.search(r"^      required: \[([^\]]*)\]", block, re.MULTILINE)
    return block, properties, set(required.group(1).split(", ")) if required else set()


def check_node_pairing_contract(openapi, wire):
    mappings = {
        "nodes.preview": ("NodesPreviewRequest", "NodeControlKeyCandidate"),
        "nodes.confirm": ("NodesConfirmRequest", "NodeControlKeyBinding"),
        "nodes.list": ("NodesListRequest", "NodeDeviceBindingList"),
        "nodes.revoke": ("NodesRevokeRequest", "NodeDeviceBinding"),
    }
    for operation, (request, result) in mappings.items():
        mapping = (f"        {operation}:\n          request: '#/components/schemas/{request}'"
                   f"\n          result: '#/components/schemas/{result}'")
        if mapping not in openapi:
            raise ValueError("Node request/result mapping drift: " + operation)
    expected = {
        "NodeControlKeyBinding": "owner_binding_id owner_id hub_id node_id node_name client_device_id owner_key_id node_credential_version binding_version node_key_id node_public_identity node_key_fingerprint node_key_version node_key_epoch hub_key_id hub_public_identity hub_key_fingerprint hub_key_version approved_request_id approved_request_version approved_candidate_digest approved_owner_device_id approved_owner_key_id approved_at state version revoked_at",
        "NodeDeviceBinding": "id owner_id hub_id node_id node_name client_device_id owner_key_id node_credential_version state authorized version created_at updated_at revoked_at",
        "NodeControlKeyCandidate": "request_id version mode hub_id node_id node_name node_key_id node_key_fingerprint hub_node_control_key_id hub_node_control_key_version hub_node_control_fingerprint node_key_epoch candidate_digest expires_at state binding_id binding_version",
        "NodesConfirmRequest": "user_code candidate_digest candidate_version",
        "NodeDeviceCodeRequest": "node_id node_name credential_digest request_nonce node_public_identity node_fingerprint proof_packet hub_id hub_public_identity hub_key_version hub_fingerprint",
        "NodeDeviceCode": "user_code verification_uri candidate",
    }
    for name, fields in expected.items():
        block, properties, required = node_schema(openapi, name)
        optional = {"revoked_at"} if name.endswith("Binding") else (
            {"binding_id", "binding_version"} if name == "NodeControlKeyCandidate" else set())
        if (properties != set(fields.split()) or required != properties - optional
                or "      additionalProperties: false\n" not in block):
            raise ValueError("Node schema field/required drift: " + name)
    for operation, shape in (("confirm", "NodeControlKeyBinding"), ("list", "NodeDeviceBinding")):
        row = next((line for line in wire.splitlines()
                    if f'id="rpc-result-nodes-{operation}"' in line), "")
        if f"`{shape}`" not in row or operation == "confirm" and "`nodes.list`" in row:
            raise ValueError("Node wire result projection drift: " + operation)


def check_link_review_policy_contract(openapi, wire):
    for name in ("LinkReviewPolicyGrantRequest", "LinkReviewPolicyPreviewResult"):
        block, _, _ = node_schema(openapi, name)
        if "expected_policy_version: {type: integer, minimum: 0, maximum: 9223372036854775806}" not in block:
            raise ValueError("review policy current CAS range drift: " + name)
    preview, _, _ = node_schema(openapi, "LinkReviewPolicyPreviewResult")
    grant, _, _ = node_schema(openapi, "LinkReviewPolicyGrantRequest")
    if ("policy_version: {type: integer, minimum: 1, maximum: 9223372036854775807}" not in preview
            or "expected_policy_version + 1" not in grant
            or '"expected_policy_version":0' not in wire
            or "`expected_policy_version + 1`" not in wire):
        raise ValueError("review policy current/next version semantics drift")


def check_group_directory_permission_contract(openapi, wire):
    action, properties, required = node_schema(openapi, "ClientTopologySetDirectoryPermission")
    if (properties != {"group_id", "membership_id", "enabled", "expected_membership_version"}
            or required != properties
            or "      additionalProperties: false\n" not in action
            or "enabled: {type: boolean}" not in action
            or "expected_membership_version: {type: integer, minimum: 1, maximum: 9223372036854775806}" not in action):
        raise ValueError("Group directory permission flag/CAS schema drift")
    wrapper, properties, required = node_schema(openapi, "TopologySetDirectoryPermissionAction")
    member, properties_member, required_member = node_schema(openapi, "ClientTopologyMember")
    if (properties != {"kind", "set_directory_permission"} or required != properties
            or "      additionalProperties: false\n" not in wrapper
            or "kind: {const: membership.set_directory_permission}" not in wrapper
            or "membership.set_directory_permission: '#/components/schemas/TopologySetDirectoryPermissionAction'" not in openapi
            or "directory_permission_enabled" not in properties_member
            or "directory_permission_enabled" not in required_member
            or "| `membership.set_directory_permission` |" not in wire
            or "all of that Principal's joined Endpoints in this Group" not in wire):
        raise ValueError("Group directory permission action/projection/scope drift")


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
    check_node_pairing_contract(openapi, files["docs/client-hub-wire-v1.md"].decode())
    check_link_review_policy_contract(openapi, files["docs/client-hub-wire-v1.md"].decode())
    check_group_directory_permission_contract(openapi, files["docs/client-hub-wire-v1.md"].decode())
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
            "group.create: '#/components/schemas/TopologyCreateGroupAction'",
            "x-topology-snapshot-schema: '#/components/schemas/ClientTopologySnapshot'",
            "x-topology-network-projection-schema: '#/components/schemas/ClientTopologyNetwork'",
            "network_endpoints_truncated:",
            "can_create_group:",
            "network_ids:"):
        if marker not in openapi:
            raise ValueError("ACTIVE Network topology contract is incomplete: " + marker)
    expected_network_key_ops = {"network.key_manifest", "network.key_grant", "network.key_status"}
    network_key_ops = {operation["id"]: operation for operation in operations
                       if operation["id"] in expected_network_key_ops}
    if set(network_key_ops) != expected_network_key_ops or any(
            set(network_key_ops[name]["roles"]) != {"manager", "external"}
            for name in expected_network_key_ops):
        raise ValueError("Network Owner key consent operations are incomplete")
    directory = next((operation for operation in operations if operation["id"] == "network.directory"), None)
    if (directory is None or set(directory["roles"]) != {"manager", "external"}
            or directory.get("request_schema") != "NetworkDirectoryRequest"
            or directory.get("result_schema") != "NetworkDirectoryResult"
            or "Only currently enrolled, discoverable Endpoints" not in openapi):
        raise ValueError("opted-in Network directory operation or privacy projection is incomplete")
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
    direct = json.loads(files["cicada-go/internal/e2ee/testdata/network-direct-key-consent-v1.json"])
    if (direct.get("synthetic_only") is not True or
            "Never initialize a deployment" not in direct.get("warning", "") or
            direct.get("synthetic_native_session_id") != "native_synthetic_private_locator" or
            direct.get("native_session_digest") != sha256(
                b"cicada/network/native-session/v1\x00native_synthetic_private_locator")):
        raise ValueError("unlabelled or sensitive Network direct public vector")
    for field, signed_field, digest_field, domain in (
            ("attestation", "attestation_signed_input_base64", "attestation_signed_sha256",
             b"cicada/network/direct-key-attestation/v1\x00"),
            ("owner_grant", "owner_grant_signed_input_base64", "owner_grant_signed_sha256",
             b"cicada/network/direct-key-grant/v1\x00")):
        claims = json.loads(direct[field])
        if not claims.get("signature"):
            raise ValueError("Network direct public proof lacks a signature")
        claims["signature"] = None
        expected = domain + json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode()
        actual = base64.b64decode(direct[signed_field], validate=True)
        if actual != expected or sha256(actual) != direct[digest_field]:
            raise ValueError("Network direct public signed bytes differ")
    manifest = direct["manifest_canonical_json"].encode()
    if (sha256(b"cicada/network/direct-key-manifest/v1\x00" + manifest) != direct["manifest_digest"] or
            json.loads(direct["owner_grant"])["manifest_digest"] != direct["manifest_digest"]):
        raise ValueError("Network direct public manifest consent differs")
    if json.loads(direct["network_envelope"])["context"] != direct["network_context"]:
        raise ValueError("Network direct public envelope context differs")
    collaboration = json.loads(files["cicada-go/internal/e2ee/testdata/network-collaboration-key-consent-v1.json"])
    if (collaboration.get("fixture_version") != 1 or collaboration.get("synthetic_only") is not True or
            collaboration.get("warning") != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" or
            collaboration.get("purpose") != "TASK" or
            collaboration.get("native_session_digest") != sha256(
                b"cicada/network/native-session/v1\x00" +
                collaboration.get("synthetic_native_session_id", "").encode())):
        raise ValueError("unlabelled Network collaboration proof vector")
    manifest = collaboration.get("manifest_canonical_json", "").encode()
    expected_manifest_digest = sha256(
        b"cicada/network/collaboration-key-manifest/v1\x00TASK\x00" + manifest)
    if collaboration.get("collaboration_manifest_digest") != expected_manifest_digest:
        raise ValueError("Network collaboration manifest digest differs")
    grant = json.loads(collaboration.get("owner_grant_json", "{}"))
    claims = dict(grant)
    if (grant.get("purpose") != "TASK" or
            grant.get("manifest_digest") != expected_manifest_digest or
            grant.get("owner_key_id") != collaboration.get("owner_public_identity", {}).get("id") or
            not grant.get("signature")):
        raise ValueError("Network collaboration Owner proof claims differ")
    claims["signature"] = None
    unsigned = json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode()
    canonical_unsigned = collaboration.get("canonical_unsigned_json", "").encode()
    signed = b"cicada/network/collaboration-key-grant/v1\x00" + unsigned
    if (unsigned != canonical_unsigned or
            b'"signature":null' not in unsigned or
            base64.b64decode(collaboration.get("signed_input_base64", ""), validate=True) != signed or
            bytes.fromhex(collaboration.get("signed_input_hex", "")) != signed or
            sha256(signed) != collaboration.get("signed_input_sha256")):
        raise ValueError("Network collaboration Owner proof signed bytes differ")
    review = json.loads(files["cicada-go/internal/e2ee/testdata/owner-link-review-policy-proof-v1.json"])
    review_domain = b"cicada/communication-link/review-policy-owner-approval/v1\x00"
    review_claim_order = [
        "version", "owner_id", "link_id", "contract_digest", "policy_digest",
        "expected_link_version", "policy_version", "side", "issued_at", "expires_at", "nonce",
    ]
    review_wire_order = review_claim_order + ["signature"]
    if (review.get("fixture_version") != 1 or review.get("synthetic_only") is not True or
            review.get("warning") != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" or
            review.get("algorithm") != "ML-DSA-65" or
            review.get("signing_domain") != "cicada/communication-link/review-policy-owner-approval/v1\\x00" or
            review.get("signing_domain_hex") != review_domain.hex() or
            review.get("claims_field_order") != review_claim_order):
        raise ValueError("unlabelled OwnerLinkReviewPolicyProof vector or wrong production domain/order")
    review_identity = review.get("owner_public_identity", {})
    review_proof_raw = review.get("proof_json", "").encode()
    review_proof = json.loads(review_proof_raw)
    if (list(review_proof) != review_wire_order or
            review.get("mldsa_public_key_base64") != review_identity.get("signing_public") or
            review_proof.get("owner_id") != "owner_synthetic_review_policy" or
            review_proof.get("link_id") != "link_synthetic_review_policy" or
            not review_proof.get("signature")):
        raise ValueError("OwnerLinkReviewPolicyProof public key/scope/wire fields differ")
    review_signature = base64.b64decode(review_proof["signature"], validate=True)
    if (base64.b64encode(review_signature).decode() != review.get("signature_base64") or
            json.dumps(review_proof, ensure_ascii=False, separators=(",", ":")).encode() != review_proof_raw or
            sha256(review_proof_raw) != review.get("proof_sha256")):
        raise ValueError("OwnerLinkReviewPolicyProof signature or canonical proof JSON differs")
    review_claims = dict(review_proof)
    review_claims.pop("signature")
    review_unsigned = json.dumps(review_claims, ensure_ascii=False, separators=(",", ":")).encode()
    if (list(review_claims) != review_claim_order or
            review_unsigned.decode() != review.get("canonical_unsigned_json")):
        raise ValueError("OwnerLinkReviewPolicyProof must sign exactly 11 ordered claims without signature")
    review_signed = review_domain + review_unsigned
    try:
        review_signed_hex = bytes.fromhex(review.get("signed_bytes_hex", ""))
        review_signed_base64 = base64.b64decode(review.get("signed_bytes_base64", ""), validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("OwnerLinkReviewPolicyProof signed bytes encoding is invalid") from error
    if (review_signed != review_signed_hex or review_signed != review_signed_base64 or
            sha256(review_signed) != review.get("signed_bytes_sha256")):
        raise ValueError("OwnerLinkReviewPolicyProof signed bytes/hash differ from ordered production claims")
    broadcast = json.loads(files["cicada-go/internal/e2ee/testdata/network-collaboration-broadcast-consent-v1.json"])
    broadcast_domain = b"cicada/network/collaboration-key-grant/v1\x00"
    broadcast_claim_order = [
        "version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id",
        "owner_key_id", "manifest_digest", "issued_at", "expires_at", "nonce", "signature",
    ]
    if (broadcast.get("fixture_version") != 1 or broadcast.get("synthetic_only") is not True or
            broadcast.get("warning") != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" or
            broadcast.get("purpose") != "BROADCAST" or
            broadcast.get("signing_domain") != "cicada/network/collaboration-key-grant/v1\\x00" or
            broadcast.get("claims_field_order") != broadcast_claim_order or
            broadcast.get("manifest_canonical_json") != collaboration.get("manifest_canonical_json")):
        raise ValueError("unlabelled or incomplete BROADCAST-purpose Network collaboration vector")
    broadcast_manifest = broadcast["manifest_canonical_json"].encode()
    expected_broadcast_digest = sha256(
        b"cicada/network/collaboration-key-manifest/v1\x00BROADCAST\x00" + broadcast_manifest)
    broadcast_grant_raw = broadcast.get("owner_grant_json", "").encode()
    broadcast_grant = json.loads(broadcast_grant_raw)
    if (expected_broadcast_digest != broadcast.get("collaboration_manifest_digest") or
            broadcast_grant.get("purpose") != "BROADCAST" or
            broadcast_grant.get("manifest_digest") != expected_broadcast_digest or
            broadcast_grant.get("owner_key_id") != broadcast.get("owner_public_identity", {}).get("id") or
            not broadcast_grant.get("signature")):
        raise ValueError("BROADCAST grant is not bound to its purpose-specific manifest and Owner key")
    if (list(broadcast_grant) != broadcast_claim_order or
            json.dumps(broadcast_grant, ensure_ascii=False, separators=(",", ":")).encode() != broadcast_grant_raw):
        raise ValueError("BROADCAST Owner grant wire field order/canonical JSON differs")
    broadcast_claims = dict(broadcast_grant)
    broadcast_signature = broadcast_claims["signature"]
    broadcast_claims["signature"] = None
    broadcast_unsigned = json.dumps(broadcast_claims, ensure_ascii=False, separators=(",", ":")).encode()
    if (list(broadcast_claims) != broadcast_claim_order or
            broadcast_unsigned.decode() != broadcast.get("canonical_unsigned_json")):
        raise ValueError("BROADCAST Owner grant must sign ordered claims with signature:null")
    broadcast_signed = broadcast_domain + broadcast_unsigned
    try:
        broadcast_signed_hex = bytes.fromhex(broadcast.get("signed_input_hex", ""))
        broadcast_signed_base64 = base64.b64decode(broadcast.get("signed_input_base64", ""), validate=True)
        broadcast_signature_bytes = base64.b64decode(broadcast_signature, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("BROADCAST Owner grant signature or signed bytes encoding is invalid") from error
    task_grant = json.loads(collaboration["owner_grant_json"])
    if (broadcast_signed != broadcast_signed_hex or broadcast_signed != broadcast_signed_base64 or
            sha256(broadcast_signed) != broadcast.get("signed_input_sha256") or
            broadcast_signature != broadcast.get("signature_base64") or not broadcast_signature_bytes or
            task_grant.get("purpose") != "TASK" or
            task_grant.get("manifest_digest") == expected_broadcast_digest or
            task_grant.get("signature") == broadcast_signature):
        raise ValueError("BROADCAST vector reused TASK bytes/digest or has inconsistent signed input")
    cross = json.loads(files["cicada-go/internal/e2ee/testdata/cross-owner-group-key-v2.json"])
    if (cross.get("fixture_version") != 1 or
            cross.get("warning") != "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT"):
        raise ValueError("unlabelled cross-owner Group key vector")
    manifest = cross.get("manifest", {})
    if (manifest.get("operation") != "group-endpoint-key-grant:v2:cross-owner" or
            manifest.get("endpoint_owner_id") == manifest.get("group_owner_id") or
            manifest.get("cross_owner_context_shared") is not True or
            manifest.get("history_included") is not False or
            manifest.get("candidate_public_identity", {}).get("id") != manifest.get("candidate_key_id")):
        raise ValueError("cross-owner Group key vector is not an exact two-Owner, no-history scope")
    candidate_attestation = base64.b64decode(manifest.get("candidate_attestation", ""), validate=True)
    if sha256(candidate_attestation) != manifest.get("candidate_proof_digest"):
        raise ValueError("cross-owner Endpoint proof digest differs from manifest")
    binding = {
        "hub_id": manifest["hub_id"], "network_id": manifest["network_id"],
        "group_id": manifest["group_id"], "endpoint_id": manifest["endpoint_id"],
        "binding_id": manifest["binding_id"], "binding_epoch": manifest["binding_epoch"],
        "candidate_key_id": manifest["candidate_key_id"],
        "candidate_version": manifest["candidate_version"],
        "fingerprint": manifest["candidate_fingerprint"],
        "proof_digest": manifest["candidate_proof_digest"],
    }
    binding_bytes = json.dumps(binding, ensure_ascii=False, separators=(",", ":")).encode()
    expected_binding = sha256(b"cicada/group/cross-owner-key-binding/v2\x00" + binding_bytes)
    if expected_binding != manifest.get("candidate_binding_digest"):
        raise ValueError("cross-owner Endpoint binding digest differs")
    unsigned_manifest = dict(manifest)
    unsigned_manifest["digest"] = ""
    manifest_bytes = json.dumps(unsigned_manifest, ensure_ascii=False, separators=(",", ":")).encode()
    expected_manifest = sha256(b"cicada/group/cross-owner-key-manifest/v2\x00" + manifest_bytes)
    if expected_manifest != manifest.get("digest"):
        raise ValueError("cross-owner manifest digest differs")
    for proof_key, owner_key, owner_field, label in (
            ("endpoint_consent", "endpoint_owner_public_identity", "endpoint_owner_id", "ENDPOINT"),
            ("group_admission", "group_owner_public_identity", "group_owner_id", "GROUP")):
        proof = cross.get(proof_key, {})
        owner = cross.get(owner_key, {})
        if (proof.get("signer_owner_id") != manifest.get(owner_field) or
                proof.get("signer_side") != label or proof.get("owner_key_id") != owner.get("id") or
                proof.get("manifest_digest") != manifest.get("digest") or
                proof.get("current_status") != "CURRENT" or not proof.get("signed_proof")):
            raise ValueError("cross-owner proof is not bound to its distinct Owner side")
        grant = json.loads(base64.b64decode(proof["signed_proof"], validate=True))
        if (grant.get("owner_id") != manifest.get(owner_field) or
                grant.get("link_id") != manifest.get("operation") or
                grant.get("contract_digest") != manifest.get("digest") or
                grant.get("key_binding_digest") != manifest.get("candidate_binding_digest") or
                grant.get("expected_link_version") != manifest.get("candidate_version") or
                grant.get("side") != ("SOURCE" if label == "ENDPOINT" else "TARGET")):
            raise ValueError("cross-owner owner-key grant claims differ from the signed manifest role")
        # Match OwnerLinkKeyGrant.claims() exactly. Production signs this
        # ordered claims struct; the wire signature is not part of the signed
        # bytes (and is never serialized as `signature: null`).
        claim_fields = ("version", "owner_id", "link_id", "contract_digest",
                        "key_binding_digest", "expected_link_version", "side",
                        "issued_at", "expires_at", "nonce")
        signed_claims = {field: grant[field] for field in claim_fields}
        signed_grant = b"cicada/communication-link/owner-key-grant/v2\x00" + json.dumps(
            signed_claims, ensure_ascii=False, separators=(",", ":")).encode()
        expected_signed_b64 = cross.get(proof_key + "_signed_input_base64")
        expected_signed_sha256 = cross.get(proof_key + "_signed_input_sha256")
        if (base64.b64encode(signed_grant).decode() != expected_signed_b64 or
                sha256(signed_grant) != expected_signed_sha256):
            raise ValueError("cross-owner Owner signed bytes or digest differ from public vector")
    production = json.loads(files["cicada-go/internal/store/testdata/network-direct-key-production-v1.json"])
    manifest = production.get("manifest", {})
    if production.get("synthetic_only") is not True or "Never initialize a deployment" not in production.get("warning", ""):
        raise ValueError("unlabelled Network production-shape vector")
    claims = dict(manifest)
    claims.pop("native_session_id", None)
    claims["digest"] = ""
    canonical_claims = json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode()
    if (canonical_claims != production.get("canonical_claims", "").encode() or
            sha256(b"cicada/network/direct-key-manifest/v1\x00" + canonical_claims) != production.get("manifest_digest") or
            manifest.get("digest") != production.get("manifest_digest") or
            sha256(b"cicada/network/native-session/v1\x00" + manifest.get("native_session_id", "").encode()) != manifest.get("native_session_digest")):
        raise ValueError("Network production-shape canonical claims differ")
    for proof, encoded_proof, signed_field, digest_field, domain in (
            (manifest["candidate"]["attestation"], True, "attestation_signed_input_base64", "attestation_signed_sha256",
             b"cicada/network/direct-key-attestation/v1\x00"),
            (production["owner_proof"], False, "owner_grant_signed_input_base64", "owner_grant_signed_sha256",
             b"cicada/network/direct-key-grant/v1\x00")):
        decoded = json.loads(base64.b64decode(proof, validate=True) if encoded_proof else proof)
        if not decoded.get("signature"):
            raise ValueError("Network production-shape proof lacks a signature")
        decoded["signature"] = None
        expected = domain + json.dumps(decoded, ensure_ascii=False, separators=(",", ":")).encode()
        actual = base64.b64decode(production[signed_field], validate=True)
        if actual != expected or sha256(actual) != production[digest_field]:
            raise ValueError("Network production-shape proof bytes differ")
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
