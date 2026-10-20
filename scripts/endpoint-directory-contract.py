#!/usr/bin/env python3
"""Check the bounded native Endpoint extension; no deployment/runtime claim."""
import ast
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fields(source, name):
    body = re.search(r"type\s+" + name + r"\s+struct\s*\{(.*?)\n\}", source, re.S).group(1)
    return re.findall(r'`json:"([^",]+)(?:,[^"]*)?"`', body)


def check():
    wire = ROOT / "cicada-go/internal/hubaccountwire"
    manifest = json.loads((wire / "owner-endpoint-contract.json").read_text())
    node = (ROOT / "cicada-go/internal/nodewire/endpoint.go").read_text() + (ROOT / "cicada-go/internal/nodewire/operator.go").read_text()
    owner = (wire / "owner_endpoint_read.go").read_text()
    crypto = (ROOT / "cicada-go/internal/e2ee/owner_endpoint_read.go").read_text()
    constants = {name: ast.literal_eval('"' + literal + '"') for name, literal in
                 re.findall(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"', node + owner + crypto)}
    assert manifest["contract_revision"] == "native-endpoint-directory-v1"
    assert manifest["wire_version"] == 1
    assert manifest["schema_changed"] is False and manifest["new_identity_tables"] is False
    assert manifest["automatic_owner_key_signing"] is False
    assert manifest["owner_capabilities_method"] == "GET"
    assert manifest["owner_capabilities_path"] == manifest["owner_read_path"]
    assert manifest["owner_capabilities_format"] == constants["OwnerEndpointReadCapabilitiesFormat"]
    assert manifest["owner_read_operation"] == constants["OperationOwnerEndpointRead"]
    assert manifest["owner_read_path"] == constants["OwnerEndpointReadPath"]
    assert manifest["owner_read_purpose"] == constants["OwnerEndpointReadPurpose"]
    assert manifest["owner_read_domain"] == constants["OwnerEndpointReadDomain"]
    assert set(manifest["node_operations"]) == {constants[x] for x in (
        "EndpointRegisterOperation", "EndpointLeaveOperation", "NativePairAvailableOperation", "EndpointDirectoryOperation")}
    profile = manifest["node_operator_profile"]
    assert profile["format"] == constants["NodeOperatorCapabilitiesFormat"]
    assert profile["contract_revision"] == constants["NodeOperatorContractRevision"]
    assert profile["query"] == "profile=" + constants["NodeOperatorProfile"]
    assert fields(node, "EndpointDirectoryCard") == profile["node_card_fields"]
    assert fields(owner, "OwnerEndpointReadRequest") == manifest["owner_request_fields"]
    assert fields(owner, "OwnerEndpointReadResult") == manifest["owner_result_fields"]
    assert fields(owner, "OwnerEndpointCard") == manifest["owner_card_fields"]
    for error in manifest["node_terminal_errors"]:
        assert f'errors.New("{error}")' in node
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    assert catalog["contract_revision"] == manifest["client_contract_revision"]
    assert len(catalog["operations"]) == manifest["client_catalog_operations"] == 55
    assert not set(manifest["node_operations"]) & {row["id"] for row in catalog["operations"]}
    assert manifest["owner_read_operation"] not in {row["id"] for row in catalog["operations"]}
    activation = (wire / "activation.go").read_text()
    allowed = re.search(r'func ActivationAllowedOperations\(\) \[\]string\s*\{(.*?)\}', activation, re.S).group(1)
    assert re.findall(r'"([^"]+)"', allowed) == manifest["old_activation_operations"]
    for relative in ("docs/native-endpoint-directory-contract.md", "docs/client-hub-wire-v1.md"):
        prose = (ROOT / relative).read_text()
        assert "native-endpoint-directory" in prose
    prose = (ROOT / "docs/native-endpoint-directory-contract.md").read_text()
    for marker in ("SNAPSHOT_ONLY", "READ_EXPIRED", "OUTCOME_UNCERTAIN", "90 seconds", "48 KiB", "before LIMIT"):
        assert marker in prose, marker
    print("native-endpoint-directory-v1: PASS (wire 1, catalog 55, old activation scope unchanged)")


if __name__ == "__main__":
    check()
