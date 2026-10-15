#!/usr/bin/env python3
"""Check the additive N2 manifest against Go helpers and authoritative prose.

This checks published metadata, not full protocol behavior or server support.
Use the Go wire/Store/HTTP and disposable Docker tests for those claims.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check():
    package = ROOT / "cicada-go/internal/hubaccountwire"
    manifest = json.loads((package / "activation-contract.json").read_text())
    source = (package / "activation.go").read_text() + (package / "reconcile.go").read_text()
    prose = (ROOT / "docs/hub-owner-activation-contract.md").read_text()
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    assert manifest["contract_revision"] == "owner-activation-v1"
    assert manifest["wire_version"] == 1
    assert manifest["packet_format"] == "cicada.owner-account-packet.v1"
    assert manifest["frozen_client_contract"] == catalog["contract_revision"]
    assert manifest["frozen_client_catalog_count"] == len(catalog["operations"]) == 55
    assert manifest["allowed_operations"] == ["nodes.list", "session.capabilities"]
    assert not manifest["runtime_lease_renewable"] and not manifest["absent_settles_pending"]
    for row in manifest["operations"]:
        assert row["method"] == "POST"
        for key in ("operation", "path", "request", "response"):
            assert row[key] in source, ("Go", row[key])
            assert row[key] in prose, ("prose", row[key])
        for typ in (row["request"], row["response"]):
            assert re.search(r"type\s+" + typ + r"\s+struct", source)
    for purpose in manifest["purposes"]:
        assert purpose in source and purpose in prose
    expected = {"MaxActivationLifetime": ("activation_max_seconds", 3600),
                "MaxActivationProofLifetime": ("proof_max_seconds", 600),
                "MaxAppLeaseLifetime": ("runtime_lease_seconds", 900)}
    for name, (key, seconds) in expected.items():
        assert name in source and manifest[key] == seconds
    assert manifest["enrollment_grant_max_seconds"] == 600
    assert manifest["max_activation_receipt_bytes"] == 128 * 1024
    assert "MaxActivationReceiptBytes" in source
    print("owner-activation-v1 metadata check PASS (server availability not asserted)")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["check"]):
        raise SystemExit("usage: owner-activation-contract.py [check]")
    check()
