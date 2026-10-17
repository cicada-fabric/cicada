#!/usr/bin/env python3
"""Validate native-pair A1 metadata; no runtime/service acceptance claim."""
import ast
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIRE = ROOT / "cicada-go/internal/hubaccountwire"


def go_string_values(source):
    return {name: ast.literal_eval('"' + literal + '"') for name, literal in
            re.findall(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"', source)}


def struct_fields(source, name):
    body = re.search(r'type\s+' + name + r'\s+struct\s*\{(.*?)\n\}', source, re.S).group(1)
    return re.findall(r'(\w+)\s+(\S+)\s+`json:"([^"]+)"`', body)


def check():
    manifest = json.loads((WIRE / "native-pair-contract.json").read_text())
    types = (WIRE / "native_pair_types.go").read_text()
    claims = (ROOT / "cicada-go/internal/e2ee/owner_native_pair_claims.go").read_text()
    proofs = (ROOT / "cicada-go/internal/e2ee/owner_native_pair_proof.go").read_text()
    validators = (WIRE / "native_pair_validation.go").read_text()
    packets = (WIRE / "native_pair_packets.go").read_text()
    targets = (WIRE / "native_pair_targets.go").read_text()
    prose = (ROOT / "docs/hub-native-pair-contract.md").read_text()
    strings = go_string_values(types + claims)
    assert manifest["contract_revision"] == strings["NativePairContractRevision"] == "native-pair-v1"
    assert manifest["implementation_phase"] == strings["NativePairImplementationPhase"] == "WIRE_ONLY"
    assert manifest["format"] == strings["NativePairFormat"]
    assert manifest["wire_version"] == manifest["account_route_epoch"] == manifest["account_packet_sequence"] == 1
    assert len(manifest["operations"]) == 8
    for row in manifest["operations"]:
        assert row["method"] == "POST" and row["operation"] in strings.values()
        assert row["path"] in validators
        for field in ("request", "response"):
            assert re.search(r'type\s+' + row[field] + r'\s+(struct|NativePairBootstrapPrepare)', types), row[field]
    assert manifest["discovery"]["path"] == strings["NativePairCapabilitiesPath"]
    assert set(manifest["node_control_operations"]).issubset(strings.values())
    for purpose, domain in manifest["owner_purposes"].items():
        assert purpose in strings.values() and domain in strings.values()
        assert purpose in prose and domain[:-1] in prose
    for domain in manifest["digest_domains"].values():
        assert repr(domain)[1:-1] in validators + packets
    for name, value in manifest["bounds"].items():
        found = re.search(r'\b' + name + r'\s*=\s*([\d *]+)', types + proofs)
        assert found and eval(found.group(1), {"__builtins__": {}}, {}) == value, name
    assert manifest["fixed_policy"] == dict(max_root_asks=4, max_replies=4, max_replies_per_ask=1,
        max_outstanding_asks=1, max_causal_depth=0, max_messages=8, max_plaintext_bytes=8192,
        max_total_plaintext_bytes=65536, max_ciphertext_bytes=131072,
        max_total_ciphertext_bytes=1048576, max_native_deliveries=8)
    policy_body = re.search(r'func NativePairFixedPeerPolicy\(\).*?return NativePairPeerPolicy\{(.*?)\n\}', claims, re.S).group(1)
    policy_values = {k: eval(v, {"__builtins__": {}}, {}) for k, v in
                     re.findall(r'(\w+):\s*([\d *]+)', policy_body)}
    for field, _, tag in struct_fields(claims, "NativePairPeerPolicy"):
        assert policy_values.get(field, 0) == manifest["fixed_policy"][tag], field
    assert manifest["group_grants"] == ["directory.read", "message.ask", "message.receive", "message.reply"]
    assert manifest["max_slot_generations"] == 16
    for helper in ("ValidateNativePairBootstrapTarget", "ValidateNativePairPlanTarget"):
        assert helper in targets and helper in prose
    assert manifest["mandatory_independent_owner_pin"] and manifest["mandatory_node_policy_marker"]
    assert not any(manifest[k] for k in ("recovery_requires_live_administration", "absent_settles_mutation",
        "resets_budgets_on_retry_restart_or_reopen", "runtime_executed_in_a1"))
    for path, digest in manifest["frozen_artifacts"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest, path
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    assert len(catalog["operations"]) == 55 and catalog["contract_revision"] == "client-hub-v1.6.5"
    store = (ROOT / "cicada-go/internal/store/group_endpoint_key_grants_v2.go").read_text()
    assert struct_fields(types, "NativePairGroupKeyClaims") == struct_fields(store, "groupEndpointKeyGrantManifestClaims")
    limits = (ROOT / "cicada-go/internal/clientwire/native_pair_limits.go").read_text()
    assert 'r.Operation == NativePairReconcileOperation' in limits
    assert 'bodyLimit <= 192*1024' in limits and 'packetLimit <= 384*1024' in limits
    assert 'return decodePacketWithLimit(raw, MaxPacketBytes)' in (WIRE / "packet.go").read_text()
    print("native-pair-v1 A1 wire/crypto metadata PASS (service/runtime unavailable)")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["check"]):
        raise SystemExit("usage: native-pair-contract.py [check]")
    check()
