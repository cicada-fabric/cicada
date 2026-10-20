#!/usr/bin/env python3
"""Check the disabled C0 installation contract, not production acceptance."""
import ast
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIRE = ROOT / "cicada-go/internal/hubaccountwire"
CRYPTO = ROOT / "cicada-go/internal/e2ee"


def source_contract():
    strings, schemas, source = {}, {}, ""
    files = sorted(p for folder in (WIRE, CRYPTO)
                   for p in folder.glob("installation_registration*.go")
                   if not p.name.endswith("_test.go"))
    for path in files:
        raw = path.read_text()
        source += raw
        for name, literal in re.findall(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"', raw):
            strings[name] = ast.literal_eval('"' + literal + '"')
        for name, body in re.findall(r'type\s+(\w+)\s+struct\s*\{(.*?)\n\}', raw, re.S):
            fields = re.findall(r'\w+\s+[^\n`]+`json:"([^"]+)"`', body)
            if fields:
                schemas[name] = fields
    return strings, schemas, source


def check():
    manifest = json.loads((WIRE / "installation-registration-contract.json").read_text())
    strings, schemas, source = source_contract()
    assert manifest["contract_revision"] == strings["InstallationContractRevision"] == "installation-registration-v1.1"
    assert manifest["format"] == strings["InstallationRegistrationFormat"] == "cicada.installation-registration.v1"
    assert manifest["packet_format"] == strings["InstallationPacketFormat"]
    assert manifest["implementation_phase"] == strings["InstallationImplementationPhase"] == "CONTRACT_CANDIDATE"
    assert manifest["public_available"] is False
    assert re.search(r'InstallationPublicAvailable\s*=\s*false', source)
    assert manifest["wire_version"] == 1 and manifest["serve_mode"] == "--hub-nodes-only"
    assert manifest["discovery"] == {"method": "GET", "path": strings["InstallationCapabilitiesPath"]}
    operations = manifest["operations"]
    assert len(operations) == 14 and len({row["path"] for row in operations}) == 14
    for row in operations:
        assert row["method"] == "POST" and row["operation"] in strings.values()
        assert 'return "' + row["path"] + '"' in source
    assert manifest["schema_fields"] == schemas
    assert schemas["InstallationCandidateBase"] == ["format", "hub", "installation_id", "attempt_id", "admission_public_identity", "components", "subject", "trust", "issued_at", "expires_at"]
    assert not {"capsule_digest", "ack_commitment", "signature", "owner_proof_digest"}.intersection(schemas["InstallationApprovalBase"])
    assert "node_credential,omitempty" in schemas["InstallationStart"]
    assert not any("credential" in name for name in schemas["InstallationCandidateBase"])
    assert schemas["InstallationExistingTrust"][0] == "source"
    assert schemas["InstallationAccountScope"] == ["version", "origin", "hub_id", "hub_fingerprint", "account_id", "account_session_id", "account_session_expires_at", "owner_id", "owner_public_identity", "owner_key_version", "device_id", "device_public_identity", "account_epoch", "device_epoch", "transport_policy"]
    assert "actor_scope" in schemas["InstallationConnectionsSnapshot"]
    assert "subjects" in schemas["InstallationConnectionsSnapshot"]
    assert "pending_attempts" in schemas["InstallationConnectionsSnapshot"]
    assert {"installation_id", "owner_id"}.issubset(schemas["InstallationSubjectBinding"])
    assert "OwnerAppNodeScope" not in source
    assert manifest["trust_modes"] == ["FIRST_OOB", "EXISTING_LOCAL_PIN"]
    assert manifest["existing_trust_sources"] == ["REGISTERED_PARENT", "LEGACY_NODE"]
    assert manifest["read_profiles"] == ["N3_NODE_STATUS_READ", "N3_PAIR_STATUS_READ"]
    assert manifest["read_authorization"] == ["OWNER_READ_PROOF", "RECIPIENT_GRANTS"]
    assert manifest["registration_default_business_grants"] == []
    assert manifest["production_changes_in_C0"] == []
    for name, expected in manifest["bounds"].items():
        match = re.search(r'\b' + name + r'\s*=\s*([\d *]+)', source)
        assert match and eval(match.group(1), {"__builtins__": {}}, {}) == expected, name
    domains = {key: value for key, value in strings.items()
               if value.startswith("cicada/") and value.endswith("\0")}
    assert manifest["domains"] == domains
    for value in manifest["target_domains"].values():
        assert repr(value)[1:-1] in source
    assert manifest["grant_limit_semantics"] == "CONCURRENTLY_EFFECTIVE_ONLY_NOT_HISTORY"
    assert manifest["empty_recipient_grant_ids"] == "CURRENT_AUTHENTICATED_RECIPIENT_ONLY"
    assert manifest["historical_original_api"] == "AuthenticateInstallationOriginal_NEVER_FRESH_ADMISSION"
    assert manifest["pagination"] == "COUNT_AND_ENCODED_BYTES_WITH_CURSOR_TRUNCATED_PQ_SEAL_ONCE"
    assert manifest["snapshot_count_lists"] == ["grants", "parents", "subjects", "pending_attempts", "nodes", "pairs"]
    assert manifest["query_kinds"] == ["INSTALLATIONS", "GRANTED", "NODE_STATUS", "PAIR_STATUS"]
    assert manifest["query_target_ids"] == {"INSTALLATIONS": "INSTALLATION_IDS", "GRANTED_OWNER": "RECIPIENT_SUBJECT_REGISTRATION_IDS", "GRANTED_RECIPIENT": [], "NODE_STATUS": "ACTUAL_BINDING_IDS_NOT_NODE_ALIASES", "PAIR_STATUS": "ACTUAL_PAIR_IDS"}
    assert manifest["grant_ref_states"] == ["PREPARED", "ACTIVE", "EXPIRED", "REVOKED"]
    assert manifest["grant_ref_origins"] == ["installation-registration-v1.1"]
    assert manifest["approval_receipt_digest"] == "EXACT_RAW_HUB_TO_SAME_ADMISSION_POLL_RESPONSE"
    assert manifest["new_node"] == {
        "binding_id": "ACTUAL_SUBJECT_REGISTRATION_ID",
        "legacy_coordinates": "EMPTY_STRINGS_AND_ZERO_VERSIONS",
        "legacy_node_binding": None,
        "node_credential": None,
        "credential_commitment": "",
        "credential_version": 0,
        "heartbeat_source": strings["InstallationHeartbeatSource"],
        "business_authority": [],
    }
    assert manifest["supersedes"] == {"contract_revision": "installation-registration-v1", "manifest_sha256": "4d2b15eb31b9a9d28e0755d72e08fcd57ead1eeeca6867f650f01e3d5d23339a", "old_scope_proofs_compatible": False}
    assert manifest["time_policy"] == {
        "clock": "ACTUAL_TRUSTED_OS_SYNCHRONIZED_UTC_TIMEZONE_DISPLAY_ONLY",
        "issuance_early_tolerance_seconds": 30,
        "expiry_grace_seconds": 0,
        "fresh_age_seconds": 60,
        "cross_issuer_lower_bound": "BASE_ISSUED_AT_MINUS_30_SECONDS",
        "original_times": "IMMUTABLE",
    }
    assert re.search(r'InstallationIssuanceSkew\s*=\s*30\s*\*\s*time.Second', source)
    for path, expected in manifest["frozen_artifacts"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
    catalog = json.loads((ROOT / "cicada-go/internal/clientcontract/catalog.json").read_text())
    assert len(catalog["operations"]) == 55 and catalog["contract_revision"] == "client-hub-v1.6.5"
    fixture_path = ROOT / manifest["fixture"]["path"]
    assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == manifest["fixture"]["sha256"]
    fixture = json.loads(fixture_path.read_text())
    assert fixture["contract_revision"] == manifest["contract_revision"]
    assert fixture["synthetic_only"] is True and "NEVER INITIALIZE A DEPLOYMENT" in fixture["warning"]
    assert fixture["candidate"]["base"]["hub"]["origin"].endswith(".invalid")

    def no_private(value):
        if isinstance(value, dict):
            assert not {"kem_private", "signing_private", "private_identity", "password", "session_token", "node_credential"}.intersection(value)
            for child in value.values():
                no_private(child)
        elif isinstance(value, list):
            for child in value:
                no_private(child)

    no_private(fixture)
    prose = (ROOT / "docs/hub-installation-registration-contract.md").read_text()
    for marker in ["CONTRACT_CANDIDATE", "FIRST_OOB", "LEGACY_NODE", "REGISTERED_PARENT", "OWNER_READ_PROOF", "RECIPIENT_GRANTS", "AuthenticateInstallationOriginal", "NodeCredential", "NextCursor/Truncated", "30 seconds", "no expiry grace", "InstallationAccountScope", "ActorScope", "PendingAttempts", "CredentialVersion=0", "Poll response", "installation-registration-v1.1"]:
        assert marker in prose, marker
    assert not (ROOT / "cicada-go/internal/server/hub_installation_registration.go").exists()
    assert not (ROOT / "cicada-go/internal/store/hub_installation_registration_schema_v1.go").exists()
    print("installation-registration-v1.1 C0.1 contract PASS (availability disabled; no Store/three-component/Runtime claim)")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["check"]):
        raise SystemExit("usage: installation-registration-contract.py [check]")
    check()
