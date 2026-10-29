#!/usr/bin/env python3
"""Check additive N3 Hub Nodes metadata; do not assert deployment acceptance."""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check():
    package = ROOT / "cicada-go/internal/hubaccountwire"
    manifest = json.loads((package / "app-node-contract.json").read_text())
    source = (package / "app_node_authority.go").read_text()
    source += (ROOT / "cicada-go/internal/e2ee/owner_app_node_claims.go").read_text()
    prose = (ROOT / "docs/hub-app-node-authority-contract.md").read_text()
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    n2 = json.loads((package / "activation-contract.json").read_text())
    assert manifest["contract_revision"] == "app-node-authority-v1"
    assert manifest["status"] == "HUB_NODES_ONLY"
    assert manifest["wire_version"] == manifest["account_packet_sequence"] == manifest["account_route_epoch"] == 1
    assert manifest["packet_format"] == "cicada.owner-account-packet.v1"
    assert manifest["frozen_client_contract"] == catalog["contract_revision"] == "client-hub-v1.6.5"
    assert manifest["frozen_client_catalog_count"] == len(catalog["operations"]) == 55
    assert manifest["allowed_operations"] == ["nodes.confirm"]
    assert manifest["status_only_operations"] == []
    assert manifest["max_read_cache_entries_per_device"] == manifest["max_diagnostics_per_minute"] == 128
    assert manifest["read_cache_seconds"] == 300
    assert "max_diagnostics_per_epoch" not in manifest and manifest["read_settlement"] == "READ_EXPIRED"
    assert manifest["confirmation_limit"] == 1 and manifest["status_only_confirmation_limit"] == 0
    assert manifest["node_status_read_explicit"] and manifest["account_session_bound"]
    assert manifest["requires_completed_n2_history"]
    assert manifest["requires_n2_client_session_epoch"] == 1
    assert not any(manifest[k] for k in ("runtime_lease_renewable", "absent_settles_pending", "n2_lease_mutable", "other_modes_accept_n3", "liveness_uses_worker_status"))
    assert n2["allowed_operations"] == ["nodes.list", "session.capabilities"]
    assert n2["runtime_lease_seconds"] == 900 and not n2["runtime_lease_renewable"]
    assert manifest["max_mutation_packet_bytes"] == manifest["max_original_bytes"] == manifest["max_receipt_bytes"] == 128 * 1024
    assert manifest["max_body_bytes"] == 192 * 1024 and manifest["max_proof_bytes"] == 32 * 1024
    assert manifest["max_inner_bytes"] == manifest["max_outer_bytes"] == 384 * 1024 and manifest["legacy_inner_bytes"] == 256 * 1024
    assert (manifest["intent_max_seconds"], manifest["proof_max_seconds"], manifest["runtime_lease_seconds"]) == (60, 300, 900)
    assert manifest["serve_mode"] == "--hub-nodes-only"
    assert manifest["node_control_operations"] == ["node.binding.status"]
    assert manifest["liveness_states"] == ["UNKNOWN", "CONNECTED", "STALE"]
    assert manifest["observation_stale_after_seconds"] == 120
    assert len(manifest["operations"]) == 5
    assert manifest["discovery"]["method"] == "GET" and manifest["discovery"]["max_bytes"] == 8192
    for key in ("path", "response"):
        assert manifest["discovery"][key] in source and manifest["discovery"][key] in prose
    for row in manifest["operations"]:
        assert row["method"] == "POST"
        for key in ("operation", "path", "request", "response"):
            assert row[key] in source and row[key] in prose, (key, row[key])
        for typ in (row["request"], row["response"]):
            assert re.search(r"type\s+" + typ + r"\s+struct", source), typ
    for value in manifest["purposes"] + manifest["profiles"] + manifest["prepare_targets"]:
        assert value in source and value in prose, value
    for error in manifest["error_codes"]:
        assert error in prose, error
    print("app-node-authority-v1 Hub Nodes metadata PASS (deployment acceptance not asserted)")


def check_scoped():
    package = ROOT / "cicada-go/internal/hubaccountwire"
    manifest = json.loads((package / "app-node-scoped-contract.json").read_text())
    source = "\n".join(p.read_text() for p in package.glob("app_node_scoped_*.go") if not p.name.endswith("_test.go"))
    source += (ROOT / "cicada-go/internal/e2ee/owner_app_node_scoped_claims.go").read_text()
    npt = "\n".join(p.read_text() for p in package.glob("node_pair_trust_scoped_*.go") if not p.name.endswith("_test.go"))
    proof = (ROOT / "cicada-go/internal/e2ee/node_pair_trust_scoped.go").read_text()
    prose = (ROOT / "docs/hub-app-node-scoped-authority-contract.md").read_text()
    npt_prose = (ROOT / "docs/node-pair-trust-scoped-contract.md").read_text()
    assert manifest["contract_revision"] == "app-node-authority-node-scoped-v1"
    assert manifest["status"] == "CODEC_ONLY_UNAVAILABLE" and not manifest["available"]
    assert (manifest["scope_kind"], manifest["scope_version"], manifest["wire_version"], manifest["catalog_count"]) == ("NODE_V1", 2, 1, 55)
    assert manifest["legacy_contract_revision"] == "app-node-authority-v1" and manifest["legacy_scope_version"] == 1
    assert manifest["head_key"] == ["owner_id", "device_id", "authority_node_id"]
    assert manifest["global_client_counters"] and manifest["global_pending_limit"] == manifest["global_reserved_limit"] == 1
    assert (manifest["confirmation_limit"], manifest["read_confirmation_limit"], manifest["runtime_lease_seconds"], manifest["intent_seconds"], manifest["proof_seconds"]) == (1, 0, 900, 60, 300)
    assert manifest["allowed_operations"] == ["nodes.confirm"] and manifest["status_allowed_operations"] == []
    assert manifest["business_operation_prefix"] == "n3s."
    assert re.search(r"AppNodeScopedPublicAvailable\s*=\s*false", source)
    assert re.search(r"NodePairTrustScopedPublicAvailable\s*=\s*false", npt)
    assert len(manifest["operations"]) == 5
    for row in manifest["operations"]:
        for field in ("operation", "path", "request", "response"):
            assert row[field] in source and row[field] in prose, row[field]
        for typ in (row["request"], row["response"]):
            assert re.search(r"type\s+" + typ + r"\s+struct", source), typ
    for purpose in manifest["purposes"]:
        assert purpose in source and purpose in prose
    for domain in manifest["proof_domains"]:
        assert domain.replace("\x00", "\\x00") in source
    meta = manifest["npt"]
    assert meta["contract_revision"] == "node-pair-trust-node-scoped-v1"
    assert (meta["packet_version"], meta["scope_version"], meta["owner_proof_version"], meta["code_schema_version"]) == (1, 2, 2, 2)
    assert meta["code_prefix"] == "cicada-npts1." and meta["max_code_bytes"] == 1536
    assert re.search(r"MaxNodePairTrustScopedCodeBytes\s*=\s*1536", npt)
    assert meta["owner_domain"].replace("\x00", "\\x00") in proof
    assert meta["owner_purpose"] in npt and meta["owner_purpose"] in npt_prose
    assert len(meta["operations"]) == 12
    for row in meta["operations"]:
        assert row["operation"] in npt and row["path"] in npt
    for key in ("format", "packet_format", "code_prefix", "discovery_path"):
        assert meta[key] in npt and meta[key] in npt_prose
    print("app-node-authority-node-scoped-v1 / scoped NPT codec-only metadata PASS (availability false; carrier acceptance not asserted)")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["check"]):
        raise SystemExit("usage: app-node-authority-contract.py [check]")
    check()
    check_scoped()
