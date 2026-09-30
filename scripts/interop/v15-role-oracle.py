#!/usr/bin/env python3
"""Compare one Android stored authenticated role against the pinned v1.5 catalog.

The full Android session-state file is parsed only in memory. This tool saves
the role, approved operation names, selection generation, hashes and command
exit only; pending ciphertext, grants and key material are never logged.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / 'contracts/client-hub-v1.5-bd79ff9'
CONTRACT_MANIFEST = CONTRACT / 'manifest.json'
CATALOG = CONTRACT / 'cicada-go/internal/clientcontract/catalog.json'
CONTRACT_REVISION = 'client-hub-v1.5'
CATALOG_SHA256 = 'a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68'
CORE_REVISION = 'bd79ff93c90ecafc28a2471dd9523444903b39e6'
LOCAL_IMPLEMENTED = {
    'session.capabilities', 'status.snapshot', 'status.changes', 'goal.lifecycle',
    'topology.snapshot', 'topology.apply', 'devices.list', 'devices.revoke',
    'nodes.preview', 'nodes.confirm', 'nodes.list', 'nodes.revoke',
    'approvals.list', 'approvals.decide', 'goal.result', 'intent.get', 'intent.status',
    'intent.list', 'intent.submit', 'link.list', 'link.invite_create', 'link.invite_preview',
    'link.invite_accept', 'group.key_manifest', 'group.key_grant', 'group.key_status',
    'network.key_manifest', 'network.key_grant', 'network.key_status',
    'monitor.broadcast_prepare', 'monitor.broadcast_confirm', 'monitor.broadcast_status',
    'monitor.broadcast_recover',
}
DEFERRED_CONSENT = {
    'space.foreign_member_admit', 'space.foreign_member_revoke', 'space.foreign_endpoint_join',
    'space.key_manifest_v2', 'space.key_consent_v2', 'space.key_admission_v2',
    'space.key_status_v2', 'topology.delegation_issue', 'topology.delegation_revoke',
    'topology.regroup_proposal',
}
UNSUPPORTED_LINK_KEYS = {'link.key_manifest', 'link.key_grant', 'link.key_grants'}


def load_runner():
    path = ROOT / 'scripts/interop/v15-android-deterministic.py'
    spec = importlib.util.spec_from_file_location('v15_deterministic', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def verify_contract():
    manifest = json.loads(CONTRACT_MANIFEST.read_text())
    catalog_bytes = CATALOG.read_bytes()
    actual_hash = hashlib.sha256(catalog_bytes).hexdigest()
    catalog = json.loads(catalog_bytes)
    if manifest.get('source_revision') != CORE_REVISION or \
            manifest.get('contract_revision') != CONTRACT_REVISION or \
            manifest.get('catalog_sha256') != CATALOG_SHA256 or \
            actual_hash != CATALOG_SHA256 or \
            catalog.get('contract_revision') != CONTRACT_REVISION or \
            catalog.get('rpc_route') != '/v2/client/rpc':
        raise ValueError('the imported v1.5 contract snapshot did not match its trusted pin')
    operations = catalog.get('operations')
    if not isinstance(operations, list):
        raise ValueError('the pinned catalog has no operation list')
    role_operations = {role: set() for role in ('manager', 'external')}
    for item in operations:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not isinstance(item.get('roles'), list):
            raise ValueError('the pinned catalog contains an invalid operation')
        for role in role_operations:
            if role in item['roles']:
                role_operations[role].add(item['id'])
    expected = {role: LOCAL_IMPLEMENTED & role_operations[role] for role in role_operations}
    if len(LOCAL_IMPLEMENTED) != 33 or len(expected['manager']) != 33 or len(expected['external']) != 25:
        raise ValueError('the pinned role allowlists do not match the Android supported-operation contract')
    if LOCAL_IMPLEMENTED & DEFERRED_CONSENT or LOCAL_IMPLEMENTED & UNSUPPORTED_LINK_KEYS:
        raise ValueError('the local supported-operation list unexpectedly contains gated operations')
    return expected


def read_state_in_memory(command):
    proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=20)
    outcome = {'exit_code': proc.returncode, 'stdout_bytes': len(proc.stdout),
        'stderr_bytes': len(proc.stderr)}
    if proc.returncode != 0:
        return None, outcome
    if not 1 <= len(proc.stdout) <= 256 * 1024:
        outcome['error'] = 'session state exceeded the bounded read size'
        return None, outcome
    try:
        return json.loads(proc.stdout), outcome
    except (json.JSONDecodeError, UnicodeDecodeError):
        outcome['error'] = 'session state was not valid bounded JSON'
        return None, outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    parser.add_argument('--manifest', required=True,
        help='private public-device manifest for the enrolled profile')
    parser.add_argument('--tag', required=True, choices=('base', 'processing', 'uncertain', 'legacy'))
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', CATALOG_SHA256):
        parser.error('invalid pinned catalog digest')
    module = load_runner()
    driver = module.driver
    evidence = driver.private_evidence(args.evidence)
    state = module.owned_state(evidence)
    manifest_path = Path(args.manifest)
    if manifest_path.is_symlink() or not manifest_path.is_file() or evidence not in manifest_path.parents or \
            manifest_path.stat().st_mode & 0o077:
        parser.error('device manifest must be a private regular file in this run evidence')
    device = json.loads(manifest_path.read_bytes())
    if device.get('schema') != 'cicada.client-network-device.v1':
        parser.error('invalid public device manifest')
    profile_id = device.get('profile_id')
    device_id = device.get('device_id')
    if not isinstance(profile_id, str) or not re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', profile_id) or \
            not isinstance(device_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', device_id):
        parser.error('invalid profile or device identifier in public manifest')
    expected = verify_contract()
    adb = driver.adb(state)
    registry_path = 'no_backup/client-hub-profiles/profiles.json'
    state_path = 'no_backup/client-hub-profiles/' + profile_id + '/session-state.json'
    registry_command = adb + ['exec-out', 'run-as', driver.PACKAGE, 'cat', registry_path]
    session_command = adb + ['exec-out', 'run-as', driver.PACKAGE, 'cat', state_path]
    registry, registry_outcome = read_state_in_memory(registry_command)
    session, session_outcome = read_state_in_memory(session_command)
    if registry is None or session is None:
        raise RuntimeError('bounded Android profile/session state read failed; see redacted command exit record')

    active = registry.get('activeProfileId') == profile_id
    generation = registry.get('selectionGeneration')
    role = session.get('role')
    actual_list = session.get('allowedOperations')
    actual = set(actual_list) if isinstance(actual_list, list) and all(isinstance(x, str) for x in actual_list) else set()
    enrollment = session.get('enrollment')
    enrollment = enrollment if isinstance(enrollment, dict) else {}
    pin = session.get('pin')
    pin = pin if isinstance(pin, dict) else {}
    errors = []
    if not active or not isinstance(generation, int) or generation < 1:
        errors.append('profile_scope_not_active')
    if role not in expected:
        errors.append('authenticated_role_missing_or_unknown')
    elif actual != expected[role]:
        errors.append('stored_allowlist_differs_from_pinned_role_intersection')
    if len(actual_list or []) != len(actual):
        errors.append('stored_allowlist_contains_duplicates_or_invalid_data')
    if not actual.isdisjoint(DEFERRED_CONSENT | UNSUPPORTED_LINK_KEYS):
        errors.append('gated_operations_are_present')
    if session.get('sessionCapabilitiesReady') is not True or \
            session.get('validatedContractRevision') != CONTRACT_REVISION or \
            session.get('validatedCatalogSha256') != CATALOG_SHA256:
        errors.append('authenticated_capability_revision_or_catalog_mismatch')
    if enrollment.get('deviceId') != device_id or enrollment.get('state') != 'ACTIVE':
        errors.append('active_enrollment_does_not_match_prepared_device')

    summary = {
        'schema': 'cicada.client-v15-role-oracle.v1',
        'result': 'PASS' if not errors else 'FAIL',
        'tag': args.tag,
        'authenticated_role': role if role in expected else None,
        'allowed_operations': sorted(actual),
        'allowed_operation_count': len(actual),
        'expected_operation_count': len(expected[role]) if role in expected else None,
        'gated_operation_count': len(actual & (DEFERRED_CONSENT | UNSUPPORTED_LINK_KEYS)),
        'profile_id_sha256': digest(profile_id),
        'device_id_sha256': digest(device_id),
        'owner_id_sha256': digest(enrollment.get('ownerId', '')),
        'hub_id_sha256': digest(pin.get('hubId', '')),
        'selection_generation': generation if isinstance(generation, int) else None,
        'catalog_sha256': CATALOG_SHA256,
        'catalog_source_revision': CORE_REVISION,
        'session_state_command': ['docker', 'exec', state['container'], '<adb>', 'exec-out',
            'run-as', driver.PACKAGE, 'cat', 'no_backup/client-hub-profiles/<profile-id>/session-state.json'],
        'session_state_command_exit_code': session_outcome['exit_code'],
        'session_state_bytes_read': session_outcome['stdout_bytes'],
        'registry_command_exit_code': registry_outcome['exit_code'],
        'errors': errors,
        'private_state_persisted_to_evidence': False,
    }
    driver.save(evidence / ('role-oracle-' + args.tag + '.redacted.json'), summary)
    print(json.dumps(summary, separators=(',', ':')))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
