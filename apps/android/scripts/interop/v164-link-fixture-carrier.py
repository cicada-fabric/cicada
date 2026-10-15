#!/usr/bin/env python3
"""Opaque five-route Android carrier for synthetic v1.6.4 Core fixtures.

F1-F5 retain their historical pin paths. Fresh F6 requires independently
Root-hashed delivery pins plus matching local delivery metadata. The adapter
performs read-only selected-field Docker inspections, then reuses the existing
v1.5 STDIO/HTTP relay framing. It never reads container env values, Hub state,
Owner private keys, or request/response plaintext semantics.
"""

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
import time

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[2]
V16_CARRIER_PATH = ROOT / 'scripts/interop/v16-host-stdio-carrier.py'
V164_RUNNER_PATH = ROOT / 'scripts/interop/v164-android-deterministic.py'
F164_PINS_PATH = ROOT / 'scripts/interop/v164-link-fixture-pins.py'
F1_FIXTURE_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-20261002')
F2_FIXTURE_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-02-20261002')
F3_FIXTURE_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-03-20261002')
F4_FIXTURE_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-04-20261002')
F5_FIXTURE_ROOT = Path('/gpu1-share/data/cicada-client/v164-25bc586-20261002/fixture-f5')
F6_MAIN_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002')
F6_MAIN_REVISION = 'dd81575b160aa901b642137e54d7a60961e4bd68'

CONTRACT_REVISION = 'client-hub-v1.6.4'
CORE_REVISION = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
SOURCE_FINGERPRINT = '4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032'
CATALOG_SHA256 = '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'
HUB_IMAGE = 'sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4'
INTEROP_IMAGE = 'sha256:bcb8856c3d766c54c53e6c1dc1dcbe32beb2806c02260442610fde1af21cb6b1'
F6_APP_SHA256 = '56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67'
F6_TEST_SHA256 = 'caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6'
HUB_PORT = 8787
F1_HUB_ID = 'hub_6ef2ca06267060f9'
F1_HOST_PORT = 38473
F1_SETUP_SHA256 = 'c8b4f73bb049d86bd75783e5f645caddd2c3b49c32310b1f3d8755e17141dfed'
F1_READY_SHA256 = '26f6727ed8d57c8277b6e4f3547757cbeda7c7c0fc340d6802c65fe20b321cfc'
F1_OWNED_MANIFEST_SHA256 = '49b200833a72f90efe9c74a1043ea10321861426f34059d71c167c00891c2809'
SCHEMA = 'cicada.client-v164-host-stdio-carrier.v1'
ALLOWED = {
    ('GET', '/v2/client/identity'),
    ('GET', '/v2/client/capabilities'),
    ('POST', '/v2/client/devices/enroll'),
    ('POST', '/v2/client/rpc'),
    ('POST', '/v2/client/rpc/recover'),
}

_EXPECTED_APP_SHA256 = None
_EXPECTED_TEST_SHA256 = None
_CONFIG = None


def _input_paths(root):
    return {
        'root': root,
        'setup': root / 'public/client-setup.json',
        'ready': root / 'evidence/ready-receipt.json',
        'reference': root / 'public/reference-manifest.json',
        'manifest': root / 'evidence/owned-hub-manifest.json',
    }


def _fail(message):
    raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('pinned Core metadata contains duplicate JSON fields')
        result[key] = value
    return result


def _reject_constant(_value):
    _fail('pinned Core metadata contains a non-finite number')


def _check_depth(value, depth=0):
    if depth > 24:
        _fail('pinned Core metadata exceeds its nesting bound')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail('pinned Core metadata has an invalid object key')
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _read_exact_private(path, expected_sha256, *, maximum):
    if not path.is_absolute() or path.is_symlink():
        _fail('pinned Core metadata path must be absolute and nonsymlinked')
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
        setup_mode = path == _CONFIG['paths']['setup']
        allowed_modes = {0o600, 0o644} if setup_mode else {0o600}
        if resolved != path or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in allowed_modes or \
                info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > maximum:
            _fail('pinned Core metadata is not an owned bounded regular file with an allowed mode')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
                _fail('pinned Core metadata changed while opening')
            raw = bytearray()
            while len(raw) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            if len(raw) != before.st_size or \
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                _fail('pinned Core metadata changed while reading')
        finally:
            os.close(fd)
    except OSError:
        _fail('pinned Core metadata is unavailable')
    raw = bytes(raw)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail('pinned Core metadata bytes differ from the frozen SHA-256')
    try:
        document = json.loads(raw.decode('utf-8', errors='strict'),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('pinned Core metadata is malformed')
    _check_depth(document)
    if not isinstance(document, dict):
        _fail('pinned Core metadata root must be an object')
    return raw, document


def _exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        _fail(label + ' fields do not match the pinned schema')


_F6_READY_FIELDS = {
    'schema', 'status', 'fixture_root', 'protocol_scope', 'native_runtime', 'model_calls',
    'public_references', 'source', 'hub', 'client_setup_sha256', 'hub_ready_sha256',
    'reference_manifest_sha256', 'owned_manifest_sha256', 'coordination_nonce',
    'coordination_deadline', 'coordination_ttl_seconds', 'cleanup_policy',
}
_F6_HUB_FIELDS = {
    'hub_id', 'base_url', 'container_id', 'network_id', 'link_id', 'link_state',
    'link_version', 'bindings', 'business_networks', 'review_policy_qualification',
}
_F6_REFERENCE_FIELDS = {'path', 'sha256', 'bytes', 'mode', 'relative_path'}
_F6_REFERENCE_NAMES = {
    'client_setup', 'custody_manifest', 'fixture_public', 'helper_binary',
    'helper_provenance', 'helper_source', 'hub_ready', 'reference_manifest', 'runner',
}
_F6_PUBLIC_PATHS = {
    'client_setup': ('public/client-setup.json', 0o100644),
    'custody_manifest': ('public/custody.json', 0o100600),
    'fixture_public': ('public/fixture-public.json', 0o100600),
    'helper_binary': ('bin/cicada-link-v164-fixture', 0o100755),
    'helper_source': ('helper-src/main.go', 0o100600),
    'reference_manifest': ('public/reference-manifest.json', 0o100600),
    'runner': ('fixture.sh', 0o100700),
}
_F6_REVIEW_QUALIFICATION = 'METADATA_NOT_PREPARED: KEY+NONE only; no reviewer or link.review grants'
_F6_SETUP_TOP_FIELDS = {
    'schema', 'status', 'protocol_scope', 'native_runtime', 'model_calls',
    'hub', 'owners', 'link', 'client_instructions',
}
_F6_SETUP_HUB_FIELDS = {
    'base_url', 'hub_id', 'control_key_version', 'control_public_identity', 'suite',
    'image_id', 'source_revision', 'source_fingerprint', 'catalog_sha256', 'contract_revision',
}
_F6_SETUP_OWNER_FIELDS = {'link_side', 'owner_id', 'owner_key_id', 'public_identity', 'pin_source'}
_F6_SETUP_LINK_FIELDS = {'link_id', 'version', 'state', 'expires_at', 'contract_digest'}
_F6_INSTRUCTION_FIELDS = {
    'generate_device_identity_on_android', 'obtain_fresh_enrollment_manifest_from_android',
    'owner_private_keys_for_signing', 'reference_manifest', 'endpoint_identity',
    'review_policy_qualification',
}
_F6_PUBLIC_FIXTURE_FIELDS = {
    'networks', 'protocol_layers', 'review_policy_qualification', 'bindings',
    'endpoint_candidates', 'schema', 'status', 'protocol_scope', 'native_runtime',
    'model_calls', 'build', 'hub_id', 'owners', 'link', 'reference_manifest',
    'reference_manifest_use', 'endpoint_private_key_policy', 'owner_private_key_policy', 'scope',
}
_F6_BUILD_FIELDS = {
    'revision', 'source_fingerprint', 'catalog_sha256', 'contract_revision',
    'hub_image_id', 'interop_image_id',
}
_F6_PUBLIC_OWNER_FIELDS = {
    'owner_id', 'owner_key_id', 'public_identity', 'source_of_pin',
    'hub_registration', 'private_key_policy',
}
_F6_BINDING_FIELDS = {'endpoint_id', 'binding_id', 'epoch', 'lease_expires_at', 'status'}
_F6_CANDIDATE_FIELDS = {'endpoint_id', 'binding_id', 'epoch', 'key_id', 'state', 'version'}
_F6_NETWORK_FIELDS = {'network_id', 'owner_id', 'group_id', 'state', 'hub_id'}
_F6_PROTOCOL_FIELDS = {
    'endpoint_id', 'node_id', 'network_access_binding_id', 'network_access_epoch',
    'network_access_expires_at', 'native_binding_id', 'native_binding_epoch',
    'group_membership_roles', 'group_membership_grants', 'native_runtime',
}
_F6_PUBLIC_LINK_FIELDS = {
    'link_id', 'source_endpoint_id', 'source_principal_id', 'source_group_id',
    'source_owner_id', 'source_node_id', 'target_endpoint_id', 'target_principal_id',
    'target_group_id', 'target_owner_id', 'target_node_id', 'direction', 'actions',
    'data_scopes', 'transport_hub_id', 'expires_at', 'scope_snapshot',
    'contract_digest', 'state', 'version', 'created_at', 'updated_at',
}
_F6_LINK_SNAPSHOT_FIELDS = {
    'source_membership_revision', 'source_join_revision', 'source_group_version',
    'target_membership_revision', 'target_join_revision', 'target_group_version',
}
_F6_MANIFEST_FIELDS = {
    'version', 'link_id', 'link_version', 'contract_digest', 'contract_canonical',
    'source', 'target', 'digest',
}
_F6_MANIFEST_SIDE_FIELDS = {
    'endpoint_id', 'group_id', 'principal_id', 'owner_id', 'node_id', 'binding_id',
    'binding_epoch', 'candidate_version', 'key_id', 'key_fingerprint', 'proof_digest',
    'public_identity', 'attestation',
}
_F6_CONTAINER_FIELDS = {
    'id', 'name', 'created', 'image_id', 'state', 'entrypoint', 'cmd', 'user', 'labels',
    'environment_variable_names', 'resource_caps', 'network_mode', 'port_bindings', 'mounts', 'networks',
}
_F6_NETWORK_MANIFEST_FIELDS = {'id', 'name', 'driver', 'internal', 'attachable', 'labels', 'containers'}
_F6_HUB_READY_FIELDS = {'stage', 'base_url', 'health', 'capabilities', 'identity'}
_F6_HEALTH_FIELDS = {
    'status', 'service', 'version', 'stage', 'revision', 'dirty', 'source_fingerprint', 'catalog_sha256',
}
_F6_IDENTITY_FIELDS = {
    'contract', 'hub_id', 'control_public_identity', 'control_key_version', 'suite',
}
_F6_CAPABILITY_FIELDS = {
    'contract', 'contract_revision', 'catalog_sha256', 'status', 'planned_platform',
    'legacy_management_api_available', 'client_control_pq_e2ee', 'authenticated_client_session',
    'status_snapshot', 'topology_management', 'status_events', 'status_changes_partial',
    'control_intents', 'device_binding', 'external_thread_links', 'external_link_invites',
    'external_client_sessions', 'link_key_consent', 'group_endpoint_key_grants',
    'client_device_enrollment', 'rpc_recovery', 'client_device_management',
    'approval_read_and_decide', 'queued_goal_lifecycle', 'available_rpc_operations',
    'external_rpc_operations',
}
def _f6_sha(value, label):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None:
        _fail(label + ' must be a full lowercase SHA-256')


def _f6_string(value, label, pattern=r'[^\x00-\x1f\x7f]{1,512}'):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        _fail(label + ' has an invalid string value')


def _f6_expected_helper_source_mount(config):
    # Existing F6 pins predate an explicit helper-mount field. Preserve that
    # exact baseline while requiring future fixtures to provide the mount from
    # an independent Root-verified pin; the helper provenance document cannot
    # authenticate its own expected source path.
    expected = config.get('helper_source_image_mount')
    if expected is None and config.get('fixture_label') == 'client-link-v164-06':
        expected = '/src/cmd/cicada-client-link-v164-fixture-06'
    if not isinstance(expected, str) or re.fullmatch(
            r'/src/cmd/cicada-client-link-v164-fixture-[0-9]{2}', expected) is None:
        _fail('Root pins lack a bounded independent helper source-image mount')
    return expected


def _f6_positive_int(value, label):
    if type(value) is not int or value <= 0:
        _fail(label + ' must be a positive JSON integer')


def _f6_typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_f6_typed_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_f6_typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def _f6_utc_nanoseconds(value, label, *, future=False):
    if not isinstance(value, str):
        _fail(label + ' must be a UTC RFC3339Nano string')
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
    if match is None or (match.group(2) is not None and match.group(2).endswith('0')):
        _fail(label + ' must be canonical UTC RFC3339Nano')
    try:
        base = datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError:
        _fail(label + ' is not a valid UTC timestamp')
    nanos = int((match.group(2) or '').ljust(9, '0') or '0')
    second = int(base.timestamp())
    result = second * 1_000_000_000 + nanos
    if future and result <= time.time_ns():
        _fail(label + ' is expired')
    return result


def _f6_python_utc(value, label):
    """Validate the exact `datetime.isoformat()` representation used by fixture.sh."""
    if not isinstance(value, str):
        _fail(label + ' must be a canonical Python UTC ISO timestamp')
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail(label + ' is not a valid UTC timestamp')
    if parsed.utcoffset() != datetime.now(timezone.utc).utcoffset() or parsed.isoformat() != value:
        _fail(label + ' must use the exact UTC offset form emitted by fixture.sh')
    return parsed


def _f6_parse_json(raw, label):
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail(label + ' is malformed JSON')
    _check_depth(value)
    return value


def _f6_reference_file(root, name, record, relative_path, expected_mode, *, expected_sha=None):
    _exact_keys(record, _F6_REFERENCE_FIELDS, 'F6 public reference record')
    path = root / relative_path
    if record.get('path') != str(path) or record.get('relative_path') != relative_path:
        _fail('F6 public reference path does not match its exact fixture-relative path')
    _f6_sha(record.get('sha256'), 'F6 public reference digest')
    if expected_sha is not None and record['sha256'] != expected_sha:
        _fail('F6 public reference digest differs from its Root-pinned digest')
    if type(record.get('bytes')) is not int or record['bytes'] <= 0:
        _fail('F6 public reference byte count must be a positive JSON integer')
    mode = record.get('mode')
    if not isinstance(mode, str) or mode != oct(expected_mode):
        _fail('F6 public reference mode does not match the source-pinned mode')
    try:
        if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root:
            _fail('F6 fixture root must be a real nonsymlink directory')
        current = root
        for part in Path(relative_path).parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                _fail('F6 public reference has a symlink path component')
            if current != path and not stat.S_ISDIR(info.st_mode):
                _fail('F6 public reference path has a non-directory ancestor')
    except OSError:
        _fail('F6 public reference path is unavailable')
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_mode != expected_mode or \
                before.st_uid != os.getuid() or before.st_nlink != 1 or \
                before.st_size != record['bytes'] or before.st_size > 32 * 1024 * 1024:
            _fail('F6 public reference is not the exact owned regular file described by READY')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode) != \
                    (before.st_dev, before.st_ino, before.st_size, before.st_mode):
                _fail('F6 public reference changed while opening')
            raw = bytearray()
            while len(raw) <= 32 * 1024 * 1024:
                chunk = os.read(fd, min(65536, 32 * 1024 * 1024 + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            if len(raw) != before.st_size or \
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode, opened.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns):
                _fail('F6 public reference changed while reading')
        finally:
            os.close(fd)
    except OSError:
        _fail('F6 public reference could not be safely opened')
    digest = hashlib.sha256(raw).hexdigest()
    if digest != record['sha256']:
        _fail('F6 public reference bytes differ from the READY digest')
    return bytes(raw), digest


def _f6_id(value, label, pattern=r'[A-Za-z0-9_-]{1,128}'):
    _f6_string(value, label, pattern)


def _f6_base64(value, label, expected_size):
    if not isinstance(value, str) or not value or re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value) is None:
        _fail(label + ' must be padded standard Base64')
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail(label + ' is malformed Base64')
    if base64.b64encode(decoded).decode('ascii') != value or \
            (expected_size is not None and len(decoded) != expected_size):
        _fail(label + ' is noncanonical or has the wrong decoded size')
    return decoded


def _f6_validate_endpoint_attestation(side):
    """Check the public proof's exact JSON scope and digest, not its signature."""
    raw = _f6_base64(side.get('attestation'), 'F6 Endpoint attestation', None)
    if not 0 < len(raw) <= 32 * 1024 or hashlib.sha256(raw).hexdigest() != side.get('proof_digest'):
        _fail('F6 Endpoint attestation bytes are unbounded or differ from their proof digest')
    proof = _f6_parse_json(raw, 'F6 Endpoint attestation')
    proof_fields = {
        'version', 'endpoint_id', 'principal_id', 'node_id', 'binding_id',
        'binding_epoch', 'public_identity', 'signature',
    }
    _exact_keys(proof, proof_fields, 'F6 Endpoint attestation proof')
    if type(proof.get('version')) is not int or proof['version'] != 1 or \
            type(proof.get('binding_epoch')) is not int or \
            any(proof.get(key) != side.get(source) for key, source in (
                ('endpoint_id', 'endpoint_id'), ('principal_id', 'principal_id'),
                ('node_id', 'node_id'), ('binding_id', 'binding_id'),
                ('binding_epoch', 'binding_epoch'), ('public_identity', 'public_identity'))):
        _fail('F6 Endpoint attestation JSON claims differ from the manifest tuple')
    signature = proof.get('signature')
    if not isinstance(signature, str):
        _fail('F6 Endpoint attestation signature field is not Base64')
    _f6_base64(signature, 'F6 Endpoint attestation signature', None)
    return raw


def _f6_validate_setup(setup, config):
    _exact_keys(setup, _F6_SETUP_TOP_FIELDS, 'F6 public setup')
    if setup.get('schema') != 'cicada.client-link-v164-client-setup.v1' or \
            setup.get('status') != 'READY_FOR_ROOT_CLIENT_COORDINATION' or \
            setup.get('protocol_scope') != 'SYNTHETIC_PROTOCOL_ONLY' or \
            setup.get('native_runtime') != 'NOT_RUN' or setup.get('model_calls') != 'NONE':
        _fail('F6 setup is not the exact synthetic, no-native, no-model setup')
    hub = setup.get('hub')
    _exact_keys(hub, _F6_SETUP_HUB_FIELDS, 'F6 setup Hub')
    expected_origin = f"http://127.0.0.1:{config['host_port']}"
    if hub.get('base_url') != expected_origin or hub.get('hub_id') != config['hub_id'] or \
            hub.get('control_key_version') != 1 or type(hub.get('control_key_version')) is not int or \
            hub.get('suite') != 'ML-KEM-768+ML-DSA-65+AES-256-GCM' or \
            hub.get('image_id') != config['hub_image_id'] or \
            hub.get('source_revision') != config['core_revision'] or \
            hub.get('source_fingerprint') != config['source_fingerprint'] or \
            hub.get('catalog_sha256') != config['catalog_sha256'] or \
            hub.get('contract_revision') != config['contract_revision']:
        _fail('F6 setup Hub does not match the independently pinned clean delivery')
    identity = hub.get('control_public_identity')
    _exact_keys(identity, {'id', 'kem_public', 'signing_public'}, 'F6 setup Hub public identity')
    _f6_string(identity.get('id'), 'F6 Hub identity ID', r'pq1-[0-9a-f]{32}')
    _f6_base64(identity.get('kem_public'), 'F6 Hub KEM public key', 1184)
    _f6_base64(identity.get('signing_public'), 'F6 Hub signing public key', 1952)

    owners = setup.get('owners')
    if not isinstance(owners, list) or len(owners) != 2:
        _fail('F6 setup must contain exactly source and target public Owner pins')
    owner_ids = []
    for side, row in zip(('SOURCE', 'TARGET'), owners):
        _exact_keys(row, _F6_SETUP_OWNER_FIELDS, 'F6 setup Owner pin')
        if row.get('link_side') != side or row.get('pin_source') != \
                'host-generated Owner public identity, independently checked before Hub registration':
            _fail('F6 setup Owner pin source or side is invalid')
        _f6_id(row.get('owner_id'), 'F6 Owner ID')
        _f6_string(row.get('owner_key_id'), 'F6 Owner key ID', r'pq1-[0-9a-f]{32}')
        owner_identity = row.get('public_identity')
        _exact_keys(owner_identity, {'id', 'kem_public', 'signing_public'}, 'F6 Owner public identity')
        if owner_identity.get('id') != row.get('owner_key_id'):
            _fail('F6 setup Owner identity ID differs from its key pin')
        _f6_base64(owner_identity.get('kem_public'), 'F6 Owner KEM public key', 1184)
        _f6_base64(owner_identity.get('signing_public'), 'F6 Owner signing public key', 1952)
        owner_ids.append(row['owner_id'])
    if len(set(owner_ids)) != 2:
        _fail('F6 setup Owner IDs must be distinct')

    link = setup.get('link')
    _exact_keys(link, _F6_SETUP_LINK_FIELDS, 'F6 setup Link')
    _f6_id(link.get('link_id'), 'F6 Link ID')
    if type(link.get('version')) is not int or link['version'] != 1 or link.get('state') != 'PROPOSED':
        _fail('F6 setup must identify one fresh PROPOSED Link version 1')
    _f6_sha(link.get('contract_digest'), 'F6 Link contract digest')
    _f6_utc_nanoseconds(link.get('expires_at'), 'F6 Link expiry', future=True)
    instructions = setup.get('client_instructions')
    _exact_keys(instructions, _F6_INSTRUCTION_FIELDS, 'F6 client instructions')
    if type(instructions.get('generate_device_identity_on_android')) is not bool or \
            instructions['generate_device_identity_on_android'] is not True or \
            type(instructions.get('obtain_fresh_enrollment_manifest_from_android')) is not bool or \
            instructions['obtain_fresh_enrollment_manifest_from_android'] is not True or \
            instructions.get('owner_private_keys_for_signing') != 'host-only mode 0600; never place in APK or send to Hub' or \
            instructions.get('reference_manifest') != 'offline Store preflight only; fetch a fresh live encrypted manifest before consent/signing' or \
            instructions.get('endpoint_identity') != 'current candidate identities, bindings, attestations, and leases are in fresh live RPC manifests' or \
            instructions.get('review_policy_qualification') != _F6_REVIEW_QUALIFICATION:
        _fail('F6 client instructions exceed the exact KEY/NONE-only synthetic scope')
    return link, owners


def _f6_validate_fixture_public(fixture, reference, setup, config):
    _exact_keys(fixture, _F6_PUBLIC_FIXTURE_FIELDS, 'F6 public fixture')
    if fixture.get('schema') != 'cicada.client-link-v164-fixture.v1' or \
            fixture.get('status') != 'READY_FOR_CLIENT_COORDINATION' or \
            fixture.get('protocol_scope') != 'SYNTHETIC_PROTOCOL_ONLY' or \
            fixture.get('native_runtime') != 'NOT_RUN' or fixture.get('model_calls') != 'NONE' or \
            fixture.get('hub_id') != config['hub_id'] or \
            fixture.get('reference_manifest_use') != 'offline Store preflight only; Client must fetch and verify a fresh encrypted link.key_manifest before consent or signing' or \
            fixture.get('endpoint_private_key_policy') != 'host-only mode 0600; never mounted into Hub, helper build container, or APK' or \
            fixture.get('owner_private_key_policy') != 'host-only mode 0600; never mounted into Hub, helper build container, or APK' or \
            fixture.get('scope') != 'No Runtime, native Endpoint, model call, physical device, or public HTTPS claim.' or \
            fixture.get('review_policy_qualification') != _F6_REVIEW_QUALIFICATION:
        _fail('F6 public fixture contains an unsupported readiness or policy claim')
    build = fixture.get('build')
    _exact_keys(build, _F6_BUILD_FIELDS, 'F6 public build pins')
    expected_build = {
        'revision': config['core_revision'],
        'source_fingerprint': config['source_fingerprint'],
        'catalog_sha256': config['catalog_sha256'],
        'contract_revision': config['contract_revision'],
        'hub_image_id': config['hub_image_id'],
        'interop_image_id': config['interop_image_id'],
    }
    if build != expected_build or any(not isinstance(value, str) for value in build.values()):
        _fail('F6 source/build fields differ from the Root-pinned delivery')

    setup_link, setup_owners = _f6_validate_setup(setup, config)
    link = fixture.get('link')
    _exact_keys(link, _F6_PUBLIC_LINK_FIELDS, 'F6 complete synthetic Link')
    if not isinstance(link, dict) or link.get('link_id') != setup_link['link_id'] or \
            link.get('version') != setup_link['version'] or type(link.get('version')) is not int or \
            link.get('state') != setup_link['state'] or link.get('expires_at') != setup_link['expires_at'] or \
            link.get('contract_digest') != setup_link['contract_digest']:
        _fail('F6 setup and fixture Link selector disagree')
    for key in ('source_endpoint_id', 'source_principal_id', 'source_group_id', 'source_owner_id',
            'source_node_id', 'target_endpoint_id', 'target_principal_id', 'target_group_id',
            'target_owner_id', 'target_node_id', 'direction', 'transport_hub_id'):
        _f6_id(link.get(key), 'F6 complete Link ' + key)
    if link.get('transport_hub_id') != config['hub_id']:
        _fail('F6 Link is not assigned to the pinned Hub')
    _f6_utc_nanoseconds(link.get('created_at'), 'F6 Link creation time')
    _f6_utc_nanoseconds(link.get('updated_at'), 'F6 Link update time')
    if not isinstance(link.get('actions'), list) or not link['actions'] or \
            any(not isinstance(value, str) or not value for value in link['actions']) or \
            not isinstance(link.get('data_scopes'), list) or not link['data_scopes'] or \
            any(not isinstance(value, str) or not value for value in link['data_scopes']):
        _fail('F6 Link action and data scope arrays are invalid')
    snapshot = link.get('scope_snapshot')
    _exact_keys(snapshot, _F6_LINK_SNAPSHOT_FIELDS, 'F6 Link scope snapshot')
    for value in snapshot.values():
        _f6_positive_int(value, 'F6 Link scope revision')

    public_owners = fixture.get('owners')
    if not isinstance(public_owners, list) or len(public_owners) != 2:
        _fail('F6 public fixture must contain exactly two public Owner records')
    for public_owner, setup_owner in zip(public_owners, setup_owners):
        _exact_keys(public_owner, _F6_PUBLIC_OWNER_FIELDS, 'F6 fixture Owner record')
        if public_owner.get('owner_id') != setup_owner.get('owner_id') or \
                public_owner.get('owner_key_id') != setup_owner.get('owner_key_id') or \
                public_owner.get('public_identity') != setup_owner.get('public_identity') or \
                public_owner.get('source_of_pin') != 'host-generated Owner public identity, independently checked before Hub registration' or \
                public_owner.get('hub_registration') != 'ACTIVE public key only; Hub has no Owner private key' or \
                public_owner.get('private_key_policy') != 'host-only mode 0600; not mounted into Hub, helper build container, or APK':
            _fail('F6 public fixture Owner record differs from the setup pin')

    if fixture.get('reference_manifest') != reference:
        _fail('F6 public fixture and separately pinned reference manifest disagree')
    manifest = reference
    _exact_keys(manifest, _F6_MANIFEST_FIELDS, 'F6 offline reference manifest')
    if type(manifest.get('version')) is not int or manifest['version'] != 2 or \
            manifest.get('link_id') != link['link_id'] or manifest.get('link_version') != link['version'] or \
            type(manifest.get('link_version')) is not int or \
            manifest.get('contract_digest') != link['contract_digest']:
        _fail('F6 offline reference manifest does not bind the selected Link tuple')
    _f6_string(manifest.get('contract_canonical'), 'F6 reference canonical contract', r'[A-Za-z0-9+/]+={0,2}')
    _f6_sha(manifest.get('digest'), 'F6 reference manifest digest')

    bindings = fixture.get('bindings')
    candidates = fixture.get('endpoint_candidates')
    networks = fixture.get('networks')
    protocols = fixture.get('protocol_layers')
    collections = (bindings, candidates, networks, protocols)
    if any(not isinstance(rows, list) or len(rows) != 2 for rows in collections):
        _fail('F6 fixture must bind exactly two current Endpoint, network, and protocol records')
    for rows, fields, label in (
            (bindings, _F6_BINDING_FIELDS, 'binding'),
            (candidates, _F6_CANDIDATE_FIELDS, 'candidate'),
            (networks, _F6_NETWORK_FIELDS, 'business network'),
            (protocols, _F6_PROTOCOL_FIELDS, 'protocol layer')):
        for row in rows:
            _exact_keys(row, fields, 'F6 ' + label)

    side_names = ('source', 'target')
    link_endpoint_pairs = (
        ('source_endpoint_id', 'source_group_id', 'source_owner_id', 'source_principal_id', 'source_node_id'),
        ('target_endpoint_id', 'target_group_id', 'target_owner_id', 'target_principal_id', 'target_node_id'),
    )
    network_ids = set()
    endpoint_ids = set()
    binding_by_endpoint = {}
    candidate_by_endpoint = {}
    network_by_owner = {}
    protocol_by_endpoint = {}
    for row in bindings:
        _f6_id(row.get('endpoint_id'), 'F6 binding Endpoint ID')
        _f6_id(row.get('binding_id'), 'F6 binding ID')
        _f6_positive_int(row.get('epoch'), 'F6 binding epoch')
        _f6_utc_nanoseconds(row.get('lease_expires_at'), 'F6 binding lease', future=True)
        if row.get('status') != 'leased' or row['endpoint_id'] in binding_by_endpoint:
            _fail('F6 binding must be a unique current leased binding')
        binding_by_endpoint[row['endpoint_id']] = row
    for row in candidates:
        _f6_id(row.get('endpoint_id'), 'F6 candidate Endpoint ID')
        _f6_id(row.get('binding_id'), 'F6 candidate binding ID')
        _f6_string(row.get('key_id'), 'F6 candidate key ID', r'pq1-[0-9a-f]{32}')
        _f6_positive_int(row.get('epoch'), 'F6 candidate binding epoch')
        _f6_positive_int(row.get('version'), 'F6 candidate version')
        if row.get('state') != 'CANDIDATE' or row['endpoint_id'] in candidate_by_endpoint:
            _fail('F6 Endpoint key candidate must be unique and current')
        binding = binding_by_endpoint.get(row['endpoint_id'])
        if binding is None or any(row.get(k) != binding.get(k) for k in ('endpoint_id', 'binding_id', 'epoch')):
            _fail('F6 Endpoint key candidate differs from its live binding')
        candidate_by_endpoint[row['endpoint_id']] = row
    for row in networks:
        for key in ('network_id', 'owner_id', 'group_id', 'hub_id'):
            _f6_id(row.get(key), 'F6 business network ' + key)
        if row.get('state') != 'ACTIVE' or row['network_id'] in network_ids or row['owner_id'] in network_by_owner or \
                row.get('hub_id') != config['hub_id']:
            _fail('F6 business network is not one distinct ACTIVE current network at the pinned Hub')
        network_ids.add(row['network_id'])
        network_by_owner[row['owner_id']] = row
    for row in protocols:
        for key in ('endpoint_id', 'node_id', 'network_access_binding_id', 'native_binding_id'):
            _f6_id(row.get(key), 'F6 protocol layer ' + key)
        for key in ('network_access_epoch', 'native_binding_epoch'):
            _f6_positive_int(row.get(key), 'F6 protocol layer ' + key)
        _f6_utc_nanoseconds(row.get('network_access_expires_at'), 'F6 NetworkAccess lease', future=True)
        if row.get('group_membership_roles') != ['member'] or row.get('group_membership_grants') != [] or \
                row.get('native_runtime') != 'NOT_RUN' or row['endpoint_id'] in protocol_by_endpoint:
            _fail('F6 protocol layer claims an unsupported membership, grant, or native runtime')
        protocol_by_endpoint[row['endpoint_id']] = row

    sides = (manifest.get('source'), manifest.get('target'))
    setup_owner_ids = {row['owner_id'] for row in setup_owners}
    for index, (side_name, field_tuple, side) in enumerate(zip(side_names, link_endpoint_pairs, sides)):
        _exact_keys(side, _F6_MANIFEST_SIDE_FIELDS, 'F6 reference manifest ' + side_name + ' side')
        endpoint_field, group_field, owner_field, principal_field, node_field = field_tuple
        endpoint_id, group_id, owner_id = link.get(endpoint_field), link.get(group_field), link.get(owner_field)
        if not all(isinstance(value, str) and value for value in (endpoint_id, group_id, owner_id)) or \
                side.get('endpoint_id') != endpoint_id or side.get('group_id') != group_id or \
                side.get('owner_id') != owner_id or side.get('principal_id') != link.get(principal_field) or \
                side.get('node_id') != link.get(node_field):
            _fail('F6 reference manifest side differs from the Link endpoint/group/Owner tuple')
        owner_pin = setup_owners[0 if side_name == 'source' else 1]
        if owner_id != owner_pin['owner_id']:
            _fail('F6 Link side Owner differs from its independent public pin')
        _f6_id(side.get('principal_id'), 'F6 reference manifest principal ID')
        _f6_id(side.get('node_id'), 'F6 reference manifest Node ID')
        _f6_id(side.get('binding_id'), 'F6 reference manifest binding ID')
        _f6_positive_int(side.get('binding_epoch'), 'F6 reference manifest binding epoch')
        _f6_positive_int(side.get('candidate_version'), 'F6 reference manifest candidate version')
        _f6_string(side.get('key_id'), 'F6 reference manifest key ID', r'pq1-[0-9a-f]{32}')
        _f6_string(side.get('key_fingerprint'), 'F6 reference manifest key fingerprint', r'sha256:[0-9a-f]{64}')
        _f6_sha(side.get('proof_digest'), 'F6 reference manifest proof digest')
        identity = side.get('public_identity')
        _exact_keys(identity, {'id', 'kem_public', 'signing_public'}, 'F6 reference Endpoint identity')
        if identity.get('id') != side.get('key_id'):
            _fail('F6 reference Endpoint identity differs from its candidate key ID')
        _f6_base64(identity.get('kem_public'), 'F6 Endpoint KEM public key', 1184)
        _f6_base64(identity.get('signing_public'), 'F6 Endpoint signing public key', 1952)
        _f6_validate_endpoint_attestation(side)
        candidate = candidate_by_endpoint.get(endpoint_id)
        binding = binding_by_endpoint.get(endpoint_id)
        protocol = protocol_by_endpoint.get(endpoint_id)
        network = network_by_owner.get(owner_id)
        if candidate is None or binding is None or protocol is None or network is None or \
                candidate.get('key_id') != side.get('key_id') or candidate.get('version') != side.get('candidate_version') or \
                side.get('binding_id') != binding.get('binding_id') or side.get('binding_epoch') != binding.get('epoch') or \
                protocol.get('endpoint_id') != endpoint_id or network.get('group_id') != group_id or \
                protocol.get('node_id') != side.get('node_id'):
            _fail('F6 current Endpoint, binding, network, and manifest tuple disagree')
        if networks[index].get('owner_id') != owner_id or networks[index].get('group_id') != group_id or \
                bindings[index].get('endpoint_id') != endpoint_id or candidates[index].get('endpoint_id') != endpoint_id or \
                protocols[index].get('endpoint_id') != endpoint_id:
            _fail('F6 public active-network, binding, candidate, and protocol arrays are not SOURCE/TARGET ordered')
        endpoint_ids.add(endpoint_id)
    if len(endpoint_ids) != 2 or set(binding_by_endpoint) != endpoint_ids or \
            set(candidate_by_endpoint) != endpoint_ids or set(protocol_by_endpoint) != endpoint_ids or \
            set(network_by_owner) != setup_owner_ids:
        _fail('F6 fresh synthetic Endpoint/network sides are incomplete or reused')
    return link, bindings, networks


def _f6_validate_custody(document, root):
    _exact_keys(document, {'schema', 'private_key_root', 'owner_private_files', 'endpoint_private_files', 'not_mounted_into'},
        'F6 custody manifest')
    if document.get('schema') != 'cicada.client-link-v164-fixture.v1' or \
            document.get('private_key_root') != str(root) or \
            document.get('not_mounted_into') != ['Hub', 'interop helper build container', 'APK']:
        _fail('F6 custody manifest has unsupported private-key scope')
    expected = [
        {'path': 'owner-private/source-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
        {'path': 'owner-private/target-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
    ]
    endpoints = [
        {'path': 'endpoint-private/source-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
        {'path': 'endpoint-private/target-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
    ]
    if document.get('owner_private_files') != expected or document.get('endpoint_private_files') != endpoints:
        _fail('F6 custody manifest does not enumerate only host-private key paths')


def _f6_validate_helper_provenance(document, config, refs):
    fields = {
        'schema', 'helper_source_path', 'helper_source_sha256', 'helper_binary_path',
        'helper_binary_sha256', 'builder_image_id', 'builder_entrypoint_override',
        'helper_source_image_mount', 'private_keys_mounted_during_build', 'shipped_hub_binary_modified',
    }
    _exact_keys(document, fields, 'F6 helper provenance')
    expected_source_mount = _f6_expected_helper_source_mount(config)
    if document.get('schema') != 'cicada.client-link-v164-helper-build.v1' or \
            document.get('helper_source_path') != 'helper-src/main.go' or \
            document.get('helper_binary_path') != 'bin/cicada-link-v164-fixture' or \
            document.get('helper_source_sha256') != refs['helper_source_sha256'] or \
            document.get('helper_binary_sha256') != refs['helper_binary_sha256'] or \
            document.get('builder_image_id') != config['interop_image_id'] or \
            document.get('builder_entrypoint_override') != 'go' or \
            document.get('helper_source_image_mount') != expected_source_mount or \
            type(document.get('private_keys_mounted_during_build')) is not bool or \
            document['private_keys_mounted_during_build'] is not False or \
            type(document.get('shipped_hub_binary_modified')) is not bool or \
            document['shipped_hub_binary_modified'] is not False:
        _fail('F6 helper build provenance differs from the pinned offline toolchain scope')


def _f6_validate_hub_ready(document, config, setup):
    _exact_keys(document, _F6_HUB_READY_FIELDS, 'F6 final Hub readiness probe')
    origin = f"http://127.0.0.1:{config['host_port']}"
    if document.get('stage') != 'final' or document.get('base_url') != origin:
        _fail('F6 final Hub probe does not bind the exact loopback fixture')
    health = document.get('health')
    _exact_keys(health, _F6_HEALTH_FIELDS, 'F6 Hub health response')
    if health.get('status') != 'ok' or health.get('service') != 'cicada-control' or \
            health.get('revision') != config['core_revision'] or \
            type(health.get('dirty')) is not bool or health.get('dirty') is not False or \
            health.get('source_fingerprint') != config['source_fingerprint'] or \
            health.get('catalog_sha256') != config['catalog_sha256'] or \
            not isinstance(health.get('version'), str) or not health['version'] or \
            not isinstance(health.get('stage'), str) or not health['stage']:
        _fail('F6 Hub health response differs from Root-pinned build provenance')
    identity = document.get('identity')
    _exact_keys(identity, _F6_IDENTITY_FIELDS, 'F6 Hub identity response')
    setup_hub = setup['hub']
    if identity.get('contract') != 'android-hub-v1' or identity.get('hub_id') != config['hub_id'] or \
            identity.get('control_key_version') != 1 or type(identity.get('control_key_version')) is not int or \
            identity.get('control_public_identity') != setup_hub.get('control_public_identity') or \
            identity.get('suite') != 'ML-KEM-768+ML-DSA-65+AES-256-GCM':
        _fail('F6 Hub identity response differs from the public setup pin')
    capabilities = document.get('capabilities')
    _exact_keys(capabilities, _F6_CAPABILITY_FIELDS, 'F6 Hub capability response')
    if capabilities.get('contract') != 'android-hub-v1-draft' or \
            capabilities.get('contract_revision') != config['contract_revision'] or \
            capabilities.get('catalog_sha256') != config['catalog_sha256'] or \
            capabilities.get('status') != 'partial' or capabilities.get('planned_platform') != 'android':
        _fail('F6 Hub capability response differs from the pinned v1.6.4 operation catalog')
    bool_fields = _F6_CAPABILITY_FIELDS - {'contract', 'contract_revision', 'catalog_sha256', 'status',
        'planned_platform', 'available_rpc_operations', 'external_rpc_operations'}
    for field in bool_fields:
        if type(capabilities.get(field)) is not bool:
            _fail('F6 Hub capability flags must use explicit JSON booleans')
    if capabilities.get('client_control_pq_e2ee') is not True or \
            capabilities.get('authenticated_client_session') is not True or \
            capabilities.get('link_key_consent') is not True or \
            capabilities.get('external_thread_links') is not False or \
            capabilities.get('status_events') is not False:
        _fail('F6 Hub capability response makes an unsupported secure or Thread-link claim')
    for field in ('available_rpc_operations', 'external_rpc_operations'):
        values = capabilities.get(field)
        if not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values) or \
                len(values) != len(set(values)):
            _fail('F6 Hub RPC capability lists must be unique nonempty operation names')
    if 'link.key_manifest' not in capabilities['available_rpc_operations'] or \
            'link.key_grants' not in capabilities['available_rpc_operations']:
        _fail('F6 Hub does not advertise the pinned Link key-review operations')


def _f6_validate_manifest(manifest, config, ready):
    _exact_keys(manifest, {'schema', 'captured_at_utc', 'fixture_dir', 'container', 'network',
        'secret_environment_values_recorded'}, 'F6 owned Docker manifest')
    if manifest.get('schema') != 'cicada.client-link-v164-owned-docker-manifest.v1' or \
            manifest.get('fixture_dir') != str(config['paths']['root']) or \
            type(manifest.get('secret_environment_values_recorded')) is not bool or \
            manifest['secret_environment_values_recorded'] is not False:
        _fail('F6 owned Docker manifest scope is invalid')
    _f6_python_utc(manifest.get('captured_at_utc'), 'F6 Docker capture time')
    container = manifest.get('container')
    network = manifest.get('network')
    _exact_keys(container, _F6_CONTAINER_FIELDS, 'F6 Hub container manifest')
    _exact_keys(network, _F6_NETWORK_MANIFEST_FIELDS, 'F6 Hub network manifest')
    _f6_id(container.get('id'), 'F6 Hub container ID', r'[0-9a-f]{64}')
    _f6_id(network.get('id'), 'F6 Hub network ID', r'[0-9a-f]{64}')
    resource_name = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
    _f6_string(container.get('name'), 'F6 Hub container name', resource_name)
    _f6_string(network.get('name'), 'F6 Hub network name', resource_name)
    expected_ports = {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(config['host_port'])}]}
    if container.get('image_id') != config['hub_image_id'] or \
            container.get('entrypoint') != ['/usr/local/bin/cicada'] or \
            container.get('cmd') != ['serve', '--host', '0.0.0.0', '--port', '8787'] or \
            not isinstance(container.get('user'), str) or re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', container['user']) is None or \
            container.get('network_mode') != network.get('name') or container.get('networks') != [network.get('name')] or \
            container.get('port_bindings') != expected_ports:
        _fail('F6 owned Hub container image, command, user, bridge, or port is invalid')
    state = container.get('state')
    if not isinstance(state, dict) or state.get('Running') is not True or state.get('Status') != 'running':
        _fail('F6 owned Hub container is not recorded as running')
    labels = container.get('labels')
    network_labels = network.get('labels')
    expected_labels = {
        'org.cicada.fixture': config['fixture_label'],
        'org.cicada.fixture.dir': str(config['paths']['root']),
        'org.cicada.fixture.source.revision': config['core_revision'],
        'org.cicada.fixture.catalog.sha256': config['catalog_sha256'],
        'org.cicada.fixture.source.fingerprint': config['source_fingerprint'],
        'org.cicada.fixture.image.id': config['hub_image_id'],
    }
    if not isinstance(labels, dict) or not isinstance(network_labels, dict) or \
            any(labels.get(key) != value for key, value in expected_labels.items()) or \
            any(network_labels.get(key) != value for key, value in expected_labels.items()):
        _fail('F6 owned Hub/network labels do not bind the exact root and clean build')
    resource_caps = container.get('resource_caps')
    _exact_keys(resource_caps, {'memory', 'nano_cpus', 'pids_limit'}, 'F6 Hub resource caps')
    if resource_caps.get('memory') != 536870912 or type(resource_caps.get('memory')) is not int or \
            resource_caps.get('nano_cpus') != 1000000000 or type(resource_caps.get('nano_cpus')) is not int or \
            resource_caps.get('pids_limit') != 256 or type(resource_caps.get('pids_limit')) is not int or \
            not isinstance(container.get('environment_variable_names'), list) or \
            any(not isinstance(name, str) or not name for name in container['environment_variable_names']) or \
            container['environment_variable_names'] != sorted(set(container['environment_variable_names'])):
        _fail('F6 owned Hub resource or environment-name inventory is invalid')
    mounts = container.get('mounts')
    expected_mounts = [
        {'source': str(config['paths']['root'] / 'state'), 'destination': '/state', 'rw': True, 'type': 'bind'},
        {'source': str(config['paths']['root'] / 'workspace'), 'destination': '/workspace', 'rw': True, 'type': 'bind'},
    ]
    if not isinstance(mounts, list) or sorted(mounts, key=lambda row: row.get('destination', '') if isinstance(row, dict) else '') != \
            sorted(expected_mounts, key=lambda row: row['destination']):
        _fail('F6 owned Hub mount manifest includes a non-state/workspace source')
    if network.get('driver') != 'bridge' or type(network.get('internal')) is not bool or network['internal'] is not False or \
            type(network.get('attachable')) is not bool or network['attachable'] is not False or \
            not isinstance(network.get('containers'), dict) or set(network['containers']) != {container['id']}:
        _fail('F6 owned Hub network must be one noninternal, nonattachable bridge')
    hub = ready['hub']
    if container['id'] != hub['container_id'] or network['id'] != hub['network_id']:
        _fail('F6 READY and owned Docker manifest identify different resources')


def _validate_f6_ready(ready, setup, manifest, config):
    """Validate the Main17 READY emitted by the fresh F6 owner coordinator."""
    if config.get('f6') is not True or config.get('core_revision') != F6_MAIN_REVISION or \
            config.get('paths', {}).get('root') != F6_MAIN_ROOT or \
            config.get('source_dirty') is not False or config.get('contract_revision') != 'client-hub-v1.6.4' or \
            type(config.get('wire_version')) is not int or config['wire_version'] != 1 or \
            type(config.get('schema_version')) is not int or config['schema_version'] != 57 or \
            type(config.get('operation_count')) is not int or config['operation_count'] != 55 or \
            config.get('catalog_sha256') != CATALOG_SHA256 or config.get('fixture_label') != 'client-link-v164-06':
        _fail('Main17 readiness is permitted only for the Root-pinned clean dd81575 Core F6 fixture')
    for key in ('source_fingerprint', 'catalog_sha256', 'producer_sha256', 'package_sha256'):
        _f6_sha(config.get(key), 'Root-pinned F6 ' + key)
    for key in ('hub_image_id', 'interop_image_id'):
        if not isinstance(config.get(key), str) or re.fullmatch(r'sha256:[0-9a-f]{64}', config[key]) is None:
            _fail('Root-pinned F6 image ID is malformed')
    _exact_keys(ready, _F6_READY_FIELDS, 'F6 Main READY receipt')
    root = config['paths']['root']
    if ready.get('schema') != 'cicada.client-link-v164-fixture-ready.v1' or \
            ready.get('status') != 'READY_FOR_CLIENT_COORDINATION' or \
            ready.get('fixture_root') != str(root) or \
            ready.get('protocol_scope') != 'SYNTHETIC_PROTOCOL_ONLY' or \
            ready.get('native_runtime') != 'NOT_RUN' or \
            type(ready.get('model_calls')) is not int or ready['model_calls'] != 0 or \
            ready.get('cleanup_policy') != 'one terminal consumer ACK or fixed deadline; no renewal; fresh private state destroyed':
        _fail('F6 Main READY does not prove its exact synthetic-only, no-native, no-model scope')
    _f6_sha(config.get('setup_sha256'), 'Root-pinned F6 setup digest')
    _f6_sha(config.get('ready_sha256'), 'Root-pinned F6 READY digest')
    _f6_sha(config.get('reference_sha256'), 'Root-pinned F6 reference digest')
    _f6_sha(config.get('manifest_sha256'), 'Root-pinned F6 owned-manifest digest')
    for field, config_field in (
            ('client_setup_sha256', 'setup_sha256'),
            ('hub_ready_sha256', None),
            ('reference_manifest_sha256', 'reference_sha256'),
            ('owned_manifest_sha256', 'manifest_sha256')):
        _f6_sha(ready.get(field), 'F6 READY ' + field)
        if config_field is not None and ready[field] != config[config_field]:
            _fail('F6 READY four-hash binding differs from Root pins')

    nonce = ready.get('coordination_nonce')
    if not isinstance(nonce, str) or re.fullmatch(r'[0-9a-f]{48}', nonce) is None:
        _fail('F6 one-use coordination nonce is malformed')
    if type(ready.get('coordination_ttl_seconds')) is not int or ready['coordination_ttl_seconds'] != 720:
        _fail('F6 coordination TTL is not the exact fixed maximum')
    deadline_ns = _f6_utc_nanoseconds(ready.get('coordination_deadline'), 'F6 coordination deadline')
    remaining_ns = deadline_ns - time.time_ns()
    if remaining_ns <= 0 or remaining_ns > 720 * 1_000_000_000:
        _fail('F6 READY deadline is expired or exceeds the one-use 12-minute TTL')

    refs = ready.get('public_references')
    _exact_keys(refs, _F6_REFERENCE_NAMES, 'F6 nine-file public reference inventory')
    hub_ready_rel = refs.get('hub_ready', {}).get('relative_path') if isinstance(refs.get('hub_ready'), dict) else None
    attempt = re.fullmatch(r'evidence/(attempt-[0-9]{2})/hub-ready-final\.json', hub_ready_rel or '')
    if attempt is None:
        _fail('F6 hub-ready reference does not identify one bounded dynamic attempt-NN')
    dynamic = attempt.group(1)
    expected_paths = dict(_F6_PUBLIC_PATHS)
    expected_paths.update({
        'hub_ready': (f'evidence/{dynamic}/hub-ready-final.json', 0o100600),
        'helper_provenance': (f'evidence/{dynamic}/helper-provenance.json', 0o100600),
    })
    loaded = {}
    ref_digests = {}
    for name in sorted(_F6_REFERENCE_NAMES):
        relative_path, expected_mode = expected_paths[name]
        raw, digest = _f6_reference_file(root, name, refs[name], relative_path, expected_mode,
            expected_sha=config['setup_sha256'] if name == 'client_setup' else
                config['reference_sha256'] if name == 'reference_manifest' else None)
        ref_digests[name] = digest
        if name in {'client_setup', 'custody_manifest', 'fixture_public', 'helper_provenance',
                'hub_ready', 'reference_manifest'}:
            loaded[name] = _f6_parse_json(raw, 'F6 ' + name)
        elif name == 'helper_binary':
            # The helper is opaque executable evidence; it is only hashed and never run here.
            pass
    if ready['client_setup_sha256'] != ref_digests['client_setup'] or \
            ready['hub_ready_sha256'] != ref_digests['hub_ready'] or \
            ready['reference_manifest_sha256'] != ref_digests['reference_manifest']:
        _fail('F6 READY hash fields disagree with the verified public-reference bytes')
    if loaded['client_setup'] != setup:
        _fail('F6 public setup argument is not the exact hashed public-reference document')
    _f6_validate_custody(loaded['custody_manifest'], root)
    _f6_validate_helper_provenance(loaded['helper_provenance'], config, {
        'helper_source_sha256': ref_digests['helper_source'],
        'helper_binary_sha256': ref_digests['helper_binary'],
    })
    _f6_validate_hub_ready(loaded['hub_ready'], config, setup)
    fixture_link, bindings, networks = _f6_validate_fixture_public(
        loaded['fixture_public'], loaded['reference_manifest'], setup, config)
    source = ready.get('source')
    _exact_keys(source, _F6_BUILD_FIELDS, 'F6 Main READY source/build pins')
    if source != loaded['fixture_public'].get('build'):
        _fail('F6 Main READY source is not the exact fixture-public build projection')
    hub = ready.get('hub')
    _exact_keys(hub, _F6_HUB_FIELDS, 'F6 Main READY Hub')
    expected_origin = f'http://127.0.0.1:{config["host_port"]}'
    if hub.get('hub_id') != config['hub_id'] or hub.get('base_url') != expected_origin or \
            not isinstance(hub.get('container_id'), str) or re.fullmatch(r'[0-9a-f]{64}', hub['container_id']) is None or \
            not isinstance(hub.get('network_id'), str) or re.fullmatch(r'[0-9a-f]{64}', hub['network_id']) is None or \
            hub.get('link_id') != fixture_link.get('link_id') or \
            hub.get('link_state') != 'PROPOSED' or \
            type(hub.get('link_version')) is not int or hub.get('link_version') != 1 or \
            not _f6_typed_equal(hub.get('bindings'), bindings) or \
            not _f6_typed_equal(hub.get('business_networks'), networks) or \
            hub.get('review_policy_qualification') != _F6_REVIEW_QUALIFICATION:
        _fail('F6 Main READY Hub scope differs from its active public fixture records')
    _f6_validate_manifest(manifest, config, ready)
    return loaded


def _pinned(config, name, legacy_name):
    if not isinstance(config, dict):
        _fail('verified fixture configuration is required')
    if config.get('f6'):
        if name not in config:
            _fail('fresh F6 configuration is missing a verified delivery pin')
        return config[name]
    return globals()[legacy_name]


def _docker_inspect(kind, resource_id, fields):
    template = '\t'.join('{{json .' + field + '}}' for field in fields)
    try:
        output = subprocess.check_output(['docker', 'inspect', '--type', kind, '--format', template,
            resource_id], text=True, timeout=20).rstrip('\n')
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        _fail('bounded Docker inspection failed')
    values = output.split('\t')
    if len(values) != len(fields):
        _fail('bounded Docker inspection returned an unexpected field count')
    try:
        return dict(zip(fields, (json.loads(value) for value in values)))
    except json.JSONDecodeError:
        _fail('bounded Docker inspection returned malformed selected fields')


def _discover_owned(flag, root):
    if flag == 'container':
        command = ['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=org.cicada.fixture.dir=' + str(root)]
    else:
        command = ['docker', 'network', 'ls', '-q', '--no-trunc', '--filter',
            'label=org.cicada.fixture.dir=' + str(root)]
    try:
        values = subprocess.check_output(command, text=True, timeout=20).split()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        _fail('bounded Docker ownership discovery failed')
    if any(re.fullmatch(r'[0-9a-f]{64}', item) is None for item in values) or len(values) != len(set(values)):
        _fail('Docker ownership discovery returned malformed IDs')
    return values


def _validate_f3_ready(ready, setup, manifest, config):
    root = config['paths']['root']
    if config.get('f6'):
        fixture_label = config['fixture_label']
    else:
        legacy_label = {
        F3_FIXTURE_ROOT: 'client-link-v164-03',
        F4_FIXTURE_ROOT: 'client-link-v164-04',
        F5_FIXTURE_ROOT: 'client-link-v164-05',
        }[root]
        fixture_label = config.get('fixture_label', legacy_label)
    contract_revision = _pinned(config, 'contract_revision', 'CONTRACT_REVISION')
    core_revision = _pinned(config, 'core_revision', 'CORE_REVISION')
    source_fingerprint = _pinned(config, 'source_fingerprint', 'SOURCE_FINGERPRINT')
    catalog_sha256 = _pinned(config, 'catalog_sha256', 'CATALOG_SHA256')
    hub_image_id = _pinned(config, 'hub_image_id', 'HUB_IMAGE')
    interop_image_id = _pinned(config, 'interop_image_id', 'INTEROP_IMAGE')
    _exact_keys(ready, {'schema', 'status', 'scope', 'generated_at', 'source', 'images', 'hub',
        'setup', 'files', 'cleanup', 'custody'}, 'F3 readiness receipt')
    if ready.get('schema') != 'cicada.client-link-v164-fixture-ready.v1' or \
            ready.get('status') != 'READY_FOR_CLIENT_COORDINATION' or \
            ready.get('scope') != 'synthetic protocol-only fixture; model_calls=NONE; native_runtime=NOT_RUN; Android operations not run by fixture agent':
        _fail('F3 readiness receipt is not the exact synthetic-only, not-run receipt')
    if not isinstance(ready.get('generated_at'), str) or \
            re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', ready['generated_at']) is None:
        _fail('F3 readiness timestamp is not canonical UTC')

    source = ready.get('source')
    _exact_keys(source, {'contract_revision', 'revision', 'fingerprint', 'catalog_sha256', 'dirty'}, 'F3 source pins')
    if source != {'contract_revision': contract_revision, 'revision': core_revision,
            'fingerprint': source_fingerprint, 'catalog_sha256': catalog_sha256, 'dirty': False}:
        _fail('F3 source provenance differs from the frozen clean Core pins')
    if config.get('f6') and (type(source.get('dirty')) is not bool or source['dirty'] is not False):
        _fail('F6 readiness receipt does not explicitly prove source_dirty=false')
    images = ready.get('images')
    _exact_keys(images, {'hub', 'interop'}, 'F3 image pins')
    if images != {'hub': hub_image_id, 'interop': interop_image_id}:
        _fail('F3 image IDs differ from the frozen Hub and interop images')

    setup_receipt = ready.get('setup')
    _exact_keys(setup_receipt, {'actions', 'all_zero', 'command_exit_count'}, 'F3 setup receipt')
    if setup_receipt != {
            'actions': 'same fresh PROPOSED Link and current endpoint bindings; one fresh manifest required from Client before consent/signing',
            'all_zero': True, 'command_exit_count': 10}:
        _fail('F3 fixture setup commands are not the exact successful zero-exit preparation')
    if config.get('f6') and (type(setup_receipt.get('all_zero')) is not bool or
            type(setup_receipt.get('command_exit_count')) is not int):
        _fail('F6 fixture setup command result types are invalid')

    cleanup = ready.get('cleanup')
    _exact_keys(cleanup, {'hub_and_network_owned_by_fixture', 'keep_live_until_client_terminal_ack'}, 'F3 cleanup receipt')
    if cleanup != {'hub_and_network_owned_by_fixture': fixture_label + ' label and unique fixture path label',
            'keep_live_until_client_terminal_ack': True}:
        _fail('F3/F4 Hub ownership or live-fixture handoff is not authorized')
    if config.get('f6') and type(cleanup.get('keep_live_until_client_terminal_ack')) is not bool:
        _fail('F6 cleanup handoff flag must be a JSON boolean')

    custody = ready.get('custody')
    _exact_keys(custody, {'host_private_files', 'owner_device_grant_signer_template',
        'private_bytes_or_signatures_in_evidence'}, 'F3 custody receipt')
    expected_private_paths = {
        str(root / 'owner-private/source-owner-private.bin'),
        str(root / 'owner-private/target-owner-private.bin'),
        str(root / 'endpoint-private/source-endpoint-private.bin'),
        str(root / 'endpoint-private/target-endpoint-private.bin'),
    }
    custody_rows = custody.get('host_private_files')
    if not isinstance(custody_rows, list) or len(custody_rows) != 4 or \
            any(not isinstance(row, dict) or row != {
                'path': row.get('path'), 'mode': '0o600', 'contents_recorded': False} for row in custody_rows) or \
            {row['path'] for row in custody_rows if isinstance(row, dict)} != expected_private_paths or \
            custody.get('owner_device_grant_signer_template') != str(root / 'evidence/owner-device-grant-cli.txt') or \
            custody.get('private_bytes_or_signatures_in_evidence') is not False:
        _fail('F3 private-file custody is incomplete or records private bytes')
    if config.get('f6') and any(type(row.get('contents_recorded')) is not bool for row in custody_rows):
        _fail('F6 custody records must use explicit JSON booleans')

    expected_file_specs = {
        'client_setup': ('public/client-setup.json', '0o644', config['setup_sha256']),
        'custody_manifest': ('public/custody.json', '0o600', None),
        'fixture_public': ('public/fixture-public.json', '0o600', None),
        'helper_binary': ('bin/cicada-link-v164-fixture', '0o755', None),
        'helper_provenance': ('evidence/helper-provenance.json', '0o600', None),
        'helper_source': ('helper-src/main.go', '0o644' if root == F4_FIXTURE_ROOT else '0o600', None),
        'hub_ready': ('evidence/hub-ready-final.json', '0o600', None),
        'reference_manifest': ('public/reference-manifest.json', '0o600', config['reference_sha256']),
        'runner': ('fixture.sh', '0o700', None),
    }
    files = ready.get('files')
    _exact_keys(files, set(expected_file_specs), 'F3 file inventory')
    for name, (relative_path, mode, expected_digest) in expected_file_specs.items():
        record = files.get(name)
        _exact_keys(record, {'path', 'mode', 'sha256'}, 'F3 file record')
        if record.get('path') != str(root / relative_path) or record.get('mode') != mode or \
                re.fullmatch(r'[0-9a-f]{64}', record.get('sha256', '')) is None or \
                (expected_digest is not None and record['sha256'] != expected_digest):
            _fail('F3 file inventory path, mode, or trusted hash is invalid')

    hub = ready.get('hub')
    _exact_keys(hub, {'id', 'base_url', 'container_id', 'container_name', 'link_id', 'link_version',
        'link_state', 'link_expires_at', 'reference_manifest_digest', 'health', 'bindings',
        'endpoint_candidates'}, 'F3 Hub receipt')
    origin = f"http://127.0.0.1:{config['host_port']}"
    if hub.get('id') != config['hub_id'] or hub.get('base_url') != origin or \
            hub.get('container_id') != manifest.get('container', {}).get('id') or \
            hub.get('container_name') != manifest.get('container', {}).get('name') or \
            type(hub.get('link_version')) is not int or hub['link_version'] < 1 or \
            re.fullmatch(r'[0-9a-f]{64}', hub.get('reference_manifest_digest', '')) is None:
        _fail('F3 readiness receipt does not bind the pinned Hub, loopback, container, and reference digest')
    health = hub.get('health')
    _exact_keys(health, {'status', 'service', 'revision', 'source_fingerprint', 'catalog_sha256', 'dirty', 'stage', 'version'}, 'F3 health')
    if health != {'status': 'ok', 'service': 'cicada-control', 'revision': core_revision,
            'source_fingerprint': source_fingerprint, 'catalog_sha256': catalog_sha256,
            'dirty': False, 'stage': 'codex-supervisor', 'version': '0.1.0-dev'}:
        _fail('F3 Hub health is not pinned to the clean Core build')
    if config.get('f6') and (type(health.get('dirty')) is not bool or health['dirty'] is not False):
        _fail('F6 Hub health does not explicitly prove source_dirty=false')
    if not isinstance(hub.get('bindings'), list) or len(hub['bindings']) != 2 or \
            not isinstance(hub.get('endpoint_candidates'), list) or len(hub['endpoint_candidates']) != 2:
        _fail('F3 Hub receipt does not contain exactly two endpoint bindings and candidates')
    candidates = {}
    for candidate in hub['endpoint_candidates']:
        _exact_keys(candidate, {'endpoint_id', 'binding_id', 'epoch', 'key_id', 'state', 'version'}, 'F3 Endpoint candidate')
        if not isinstance(candidate.get('endpoint_id'), str) or not candidate['endpoint_id'] or \
                not isinstance(candidate.get('binding_id'), str) or not candidate['binding_id'] or \
                type(candidate.get('epoch')) is not int or candidate['epoch'] < 1 or \
                not isinstance(candidate.get('key_id'), str) or not candidate['key_id'].startswith('pq1-') or \
                candidate.get('state') != 'CANDIDATE' or type(candidate.get('version')) is not int or candidate['version'] != 1 or \
                candidate['endpoint_id'] in candidates:
            _fail('F3 Endpoint candidate metadata is invalid')
        candidates[candidate['endpoint_id']] = candidate
    binding_ids = set()
    for binding in hub['bindings']:
        _exact_keys(binding, {'endpoint_id', 'binding_id', 'epoch', 'lease_expires_at', 'status'}, 'F3 Endpoint binding')
        candidate = candidates.get(binding.get('endpoint_id'))
        if candidate is None or (config.get('f6') and type(binding.get('epoch')) is not int) or \
                binding.get('binding_id') != candidate['binding_id'] or \
                binding.get('epoch') != candidate['epoch'] or binding.get('status') != 'leased' or \
                binding['binding_id'] in binding_ids or \
                re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z', binding.get('lease_expires_at', '')) is None:
            _fail('F3 Endpoint binding metadata is not current and cross-matched')
        binding_ids.add(binding['binding_id'])

    link = setup.get('link')
    if not isinstance(link, dict) or hub.get('link_id') != link.get('link_id') or \
            hub.get('link_state') != link.get('state') or hub.get('link_version') != link.get('version') or \
            hub.get('link_expires_at') != link.get('expires_at'):
        _fail('F3 Hub Link identity differs from the independently pinned public setup')

    container = manifest.get('container')
    network = manifest.get('network')
    if not isinstance(container, dict) or not isinstance(network, dict) or \
            container.get('image_id') != hub_image_id or container.get('user') != '1000:1000' or \
            container.get('port_bindings') != {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(config['host_port'])}]}:
        _fail('F3 owned manifest Hub image, user, or loopback port is invalid')
    if root in (F4_FIXTURE_ROOT, F5_FIXTURE_ROOT) or config.get('f6'):
        if config.get('f6'):
            fixture_label = config['fixture_label']
        else:
            fixture_label = 'client-link-v164-04' if root == F4_FIXTURE_ROOT else 'client-link-v164-05'
        expected_labels = {
            'org.cicada.fixture': fixture_label,
            'org.cicada.fixture.dir': str(root),
            'org.cicada.fixture.source.revision': core_revision,
            'org.cicada.fixture.catalog.sha256': catalog_sha256,
            'org.cicada.fixture.source.fingerprint': source_fingerprint,
        }
        if any(not isinstance(row, dict) or any(row.get(key) != value for key, value in expected_labels.items())
                for row in (container.get('labels'), network.get('labels'))):
            _fail('F4 owned Hub/network fixture labels do not match the exact authorized root and source')


def _expected_fixture(ready, setup, manifest, config):
    if config.get('f6') is True:
        _validate_f6_ready(ready, setup, manifest, config)
        return
    root = config['paths']['root']
    setup_path = config['paths']['setup']
    manifest_path = config['paths']['manifest']
    setup_sha = config['setup_sha256']
    manifest_sha = config['manifest_sha256']
    expected_hub_id = config['hub_id']
    host_port = config['host_port']
    origin = f'http://127.0.0.1:{host_port}'
    contract_revision = _pinned(config, 'contract_revision', 'CONTRACT_REVISION')
    core_revision = _pinned(config, 'core_revision', 'CORE_REVISION')
    source_fingerprint = _pinned(config, 'source_fingerprint', 'SOURCE_FINGERPRINT')
    catalog_sha256 = _pinned(config, 'catalog_sha256', 'CATALOG_SHA256')
    hub_image_id = _pinned(config, 'hub_image_id', 'HUB_IMAGE')
    is_f2 = root == F2_FIXTURE_ROOT
    is_new_ready = root in (F3_FIXTURE_ROOT, F4_FIXTURE_ROOT, F5_FIXTURE_ROOT) or config.get('f6') is True
    if is_new_ready:
        _validate_f3_ready(ready, setup, manifest, config)
    elif is_f2:
        if ready.get('schema') != 'cicada.client-link-v164-fixture-02-ready-receipt.v1' or \
                ready.get('status') != 'READY_FOR_ROOT_CLIENT_COORDINATION; fixture setup/readiness only, not Android/client-operation PASS' or \
                ready.get('scope') != 'synthetic protocol fixture only; no production credentials/keys; no Android/native/model claims':
            _fail('Core readiness receipt is not the exact synthetic F2 fixture receipt')
        operations = ready.get('operations')
        if not isinstance(operations, dict) or any(operations.get(key) is not False for key in (
                'android_tests_run', 'key_grants_or_review_policies_signed', 'client_operations_run',
                'owner_device_grants_signed')) or operations.get('model_calls') != 'NONE' or \
                operations.get('native_runtime') != 'NOT_RUN' or operations.get('public_https') != 'NOT_RUN':
            _fail('F2 readiness receipt claims an unapproved operation')
        source_snapshot = ready.get('source_snapshot')
        if not isinstance(source_snapshot, dict) or source_snapshot.get('same_during_setup') is not True or \
                source_snapshot.get('build_source_is_separately_pinned') is not True:
            _fail('F2 receipt lacks its bounded source/build provenance')
        custody = ready.get('private_host_custody')
        expected_private_paths = {
            str(root / 'owner-private/source-owner-private.bin'),
            str(root / 'owner-private/target-owner-private.bin'),
            str(root / 'endpoint-private/source-endpoint-private.bin'),
            str(root / 'endpoint-private/target-endpoint-private.bin'),
            str(root / 'hub.env'),
        }
        if not isinstance(custody, list) or len(custody) != len(expected_private_paths) or \
                any(not isinstance(row, dict) or set(row) != {'path', 'mode', 'regular_file'} or \
                    row.get('mode') != '0600' or row.get('regular_file') is not True for row in custody) or \
                {row['path'] for row in custody if isinstance(row, dict)} != expected_private_paths:
            _fail('F2 private-file custody metadata is incomplete or outside the fixture root')
    else:
        if ready.get('schema') != 'cicada.client-link-v164-fixture-ready-receipt.v1' or \
                ready.get('status') != 'READY_FOR_ROOT_CLIENT_COORDINATION; not an Android/native/client-consent pass' or \
                ready.get('protocol_scope') != 'SYNTHETIC_PROTOCOL_ONLY' or \
                ready.get('model_calls') != 'NONE' or ready.get('native_runtime') != 'NOT_RUN' or \
                ready.get('public_https') != 'NOT_RUN':
            _fail('Core readiness receipt is not the exact synthetic v1.6.4 fixture receipt')
        for key in ('android_tests_run', 'client_key_grants_or_review_policy_signed',
                'client_operations_run', 'owner_device_grants_signed'):
            if ready.get(key) is not False:
                _fail('Core readiness receipt claims an unapproved client operation')
    if not is_new_ready:
        if ready.get('client_setup_path') != str(setup_path) or ready.get('client_setup_sha256') != setup_sha or \
                ready.get('fixture_root') != str(root):
            _fail('Core readiness receipt is bound to another fixture or public setup')
        build = ready.get('build')
        if not isinstance(build, dict) or build.get('contract_revision') != contract_revision or \
                build.get('source_revision') != core_revision or build.get('source_fingerprint') != source_fingerprint or \
                build.get('catalog_sha256') != catalog_sha256 or build.get('hub_image_id') != hub_image_id or \
                build.get('source_dirty') is not False:
            _fail('Core build pins in the readiness receipt are invalid')
    hub = ready.get('hub')
    if is_new_ready:
        if hub.get('id') != expected_hub_id or hub.get('base_url') != origin or \
                hub.get('container_id') != manifest['container']['id'] or \
                hub.get('container_name') != manifest['container']['name'] or \
                ready['files']['reference_manifest']['sha256'] != config['reference_sha256']:
            _fail('F3 readiness receipt does not bind the exact pinned Hub manifest')
    elif not isinstance(hub, dict) or hub.get('hub_id') != expected_hub_id or \
            hub.get('base_url') != origin or \
            hub.get('container_id') != manifest['container']['id'] or \
            hub.get('network_id') != manifest['network']['id'] or \
            hub.get('owned_manifest_path') != str(manifest_path) or \
            hub.get('owned_manifest_sha256') != manifest_sha or \
            (hub.get('hub_image_id') != HUB_IMAGE if is_f2 else hub.get('ready_status_command_exit_code') != 0) or \
            (is_f2 and (hub.get('status') != 'healthy' or hub.get('loopback_only') is not True)):
        _fail('Core readiness receipt does not bind the exact owned Hub manifest')
    if is_f2:
        if ready.get('cleanup', {}).get('performed') is not False or \
                ready.get('cleanup', {}).get('keep_live_for_client') is not True:
            _fail('F2 Core fixture is no longer in the authorized ready state')
    elif not is_new_ready and (ready.get('container_snapshot', {}).get('exact_owned_hub_checked') is not True or \
            ready.get('container_snapshot', {}).get('nonfixture_container_deltas_at_capture') != []):
        _fail('Core readiness receipt lacks the bounded ownership capture')
    if not is_f2 and not is_new_ready and (ready.get('cleanup', {}).get('performed') is not False or \
            ready.get('cleanup', {}).get('awaiting_root_client_coordination') is not True):
        _fail('Core fixture is no longer in the authorized ready state')

    if setup.get('schema') != 'cicada.client-link-v164-client-setup.v1' or \
            setup.get('status') != 'READY_FOR_ROOT_CLIENT_COORDINATION' or \
            setup.get('protocol_scope') != 'SYNTHETIC_PROTOCOL_ONLY' or \
            setup.get('model_calls') != 'NONE' or setup.get('native_runtime') != 'NOT_RUN':
        _fail('Core public setup is not the exact synthetic-only v1.6.4 setup')
    setup_hub = setup.get('hub')
    if not isinstance(setup_hub, dict) or setup_hub.get('hub_id') != expected_hub_id or \
            setup_hub.get('base_url') != origin or \
            setup_hub.get('contract_revision') != contract_revision or \
            setup_hub.get('source_revision') != core_revision or \
            setup_hub.get('source_fingerprint') != source_fingerprint or \
            setup_hub.get('catalog_sha256') != catalog_sha256 or \
            setup_hub.get('image_id') != hub_image_id or \
            (setup_hub.get('build_source_dirty') is not False if config.get('f6') else
                (setup_hub.get('build_source_dirty') is not False and setup_hub.get('build_source_dirty') is not None)):
        _fail('Core public setup build or loopback pins are invalid')
    link = setup.get('link')
    if not isinstance(link, dict) or link.get('state') != 'PROPOSED' or \
            type(link.get('version')) is not int or link['version'] != 1 or \
            not isinstance(link.get('expires_at'), str):
        _fail('Core setup Link selector is invalid')
    if not is_new_ready:
        ready_link = ready.get('link')
        if not isinstance(ready_link, dict) or any(ready_link.get(key) != link.get(key)
                for key in ('contract_digest', 'expires_at', 'link_id', 'state', 'version')):
            _fail('Core readiness receipt and public setup Link selector disagree')
    try:
        expires = datetime.strptime(link['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        _fail('Core setup Link expiry is not canonical UTC')
    if datetime.now(timezone.utc) >= expires:
        _fail('synthetic Core Link fixture has expired')
    if not isinstance(setup.get('owners'), list) or len(setup['owners']) != 2 or \
            {row.get('link_side') for row in setup['owners'] if isinstance(row, dict)} != {'SOURCE', 'TARGET'}:
        _fail('Core public setup does not contain exactly the two public synthetic Owner identities')

    container = manifest['container']
    network = manifest['network']
    if manifest.get('schema') != 'cicada.client-link-v164-owned-docker-manifest.v1' or \
            manifest.get('fixture_dir') != str(root) or \
            manifest.get('secret_environment_values_recorded') is not False:
        _fail('Core owned Docker manifest scope is invalid')
    allowed_network_modes = {network.get('name')}
    if root == F4_FIXTURE_ROOT and isinstance(network.get('name'), str):
        # Core explicitly attests a renamed F4 network; Docker retains its original
        # HostConfig mode name. Full network ID, attachment and labels stay checked.
        allowed_network_modes.add(network['name'].replace('cicada-cl164-04-', 'cicada-cl164-03-', 1))
    if container.get('id') != hub['container_id'] or container.get('image_id') != hub_image_id or \
            container.get('name') != hub.get('container_name') or container.get('user') != '1000:1000' or \
            container.get('network_mode') not in allowed_network_modes or \
            container.get('networks') != [network.get('name')] or \
            container.get('port_bindings') != {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(host_port)}]}:
        _fail('Core owned Hub manifest identity, bridge, or loopback binding is invalid')
    if (not is_new_ready and (network.get('id') != hub.get('network_id') or network.get('name') != hub.get('network_name'))) or \
            network.get('driver') != 'bridge' or network.get('internal') is not False or \
            set(network.get('containers', {})) != {container.get('id')}:
        _fail('Core owned Hub network manifest is not the exact one-Hub bridge')


def verify_hub(_fixture_arg, _public_arg, recovery_mode=None, **native_pins):
    if recovery_mode is not None:
        _fail('v1.6.4 carrier has no recovery-fixture mode')
    config = _CONFIG
    if not isinstance(config, dict):
        _fail('explicit Core fixture pins are required')
    contract_revision = _pinned(config, 'contract_revision', 'CONTRACT_REVISION')
    core_revision = _pinned(config, 'core_revision', 'CORE_REVISION')
    source_fingerprint = _pinned(config, 'source_fingerprint', 'SOURCE_FINGERPRINT')
    catalog_sha256 = _pinned(config, 'catalog_sha256', 'CATALOG_SHA256')
    hub_image_id = _pinned(config, 'hub_image_id', 'HUB_IMAGE')
    paths = config['paths']
    expected_pins = {
        'native_topology': str(paths['ready']),
        'native_topology_sha256': config['ready_sha256'],
        'fixture_sha256': config['setup_sha256'],
        'public_sha256': config['ready_sha256'],
        'native_mounts': str(paths['manifest']),
        'native_mounts_sha256': config['manifest_sha256'],
    }
    if native_pins != expected_pins:
        _fail('all three trusted v1.6.4 Core metadata pins are required')
    _setup_raw, setup = _read_exact_private(paths['setup'], config['setup_sha256'], maximum=32 * 1024)
    _ready_raw, ready = _read_exact_private(paths['ready'], config['ready_sha256'], maximum=64 * 1024)
    if paths['root'] in (F3_FIXTURE_ROOT, F4_FIXTURE_ROOT, F5_FIXTURE_ROOT) or config.get('f6'):
        _read_exact_private(paths['reference'], config['reference_sha256'],
            maximum=32 * 1024 * 1024 if config.get('f6') else 64 * 1024)
    _manifest_raw, manifest = _read_exact_private(paths['manifest'], config['manifest_sha256'], maximum=64 * 1024)
    _expected_fixture(ready, setup, manifest, config)

    c = manifest['container']
    n = manifest['network']
    container_fields = [
        'Id', 'Name', 'Image', 'Config.Image', 'State.Running', 'Config.Labels', 'Config.User',
        'HostConfig.NetworkMode', 'HostConfig.PortBindings', 'HostConfig.Privileged',
        'NetworkSettings.Networks', 'NetworkSettings.Ports', 'Mounts',
    ]
    actual_c = _docker_inspect('container', c['id'], container_fields)
    if actual_c.get('Id') != c['id'] or actual_c.get('Name') != '/' + c['name'] or \
            actual_c.get('Image') != hub_image_id or actual_c.get('Config.Image') != hub_image_id or \
            actual_c.get('State.Running') is not True or actual_c.get('Config.User') != c['user'] or \
            actual_c.get('Config.Labels') != c.get('labels') or \
            actual_c.get('HostConfig.NetworkMode') != c['network_mode'] or \
            actual_c.get('HostConfig.PortBindings') != c.get('port_bindings') or \
            actual_c.get('HostConfig.Privileged') is not False:
        _fail('actual Core Hub container differs from the pinned selected-field manifest')

    expected_mounts = c.get('mounts')
    if not isinstance(expected_mounts, list) or len(expected_mounts) != 2:
        _fail('owned Hub manifest must enumerate exactly its state and workspace mounts')
    actual_mounts = actual_c.get('Mounts')
    if not isinstance(actual_mounts, list) or len(actual_mounts) != len(expected_mounts):
        _fail('actual Hub mount inventory is incomplete')
    normalize_mount = lambda row: {key: row.get(key) for key in
        ('type', 'source', 'destination', 'rw')}
    actual_mount_rows = [{
        'type': row.get('Type'), 'source': row.get('Source'), 'destination': row.get('Destination'),
        'rw': row.get('RW'),
    } for row in actual_mounts if isinstance(row, dict)]
    if len(actual_mount_rows) != len(actual_mounts) or \
            sorted((tuple(sorted(row.items())) for row in actual_mount_rows)) != \
            sorted((tuple(sorted(normalize_mount(row).items())) for row in expected_mounts if isinstance(row, dict))):
        _fail('actual Hub mounts differ from the exact owned manifest')
    root_prefix = str(paths['root']) + '/'
    required_mounts = {
        ('bind', str(paths['root'] / 'state'), '/state', True),
        ('bind', str(paths['root'] / 'workspace'), '/workspace', True),
    }
    if {(row['type'], row['source'], row['destination'], row['rw']) for row in actual_mount_rows} != required_mounts or \
            any(not row['source'].startswith(root_prefix) for row in actual_mount_rows):
        _fail('Hub mount scope includes an unapproved source or destination')

    attached = actual_c.get('NetworkSettings.Networks')
    if not isinstance(attached, dict) or set(attached) != {n['name']} or \
            not isinstance(attached[n['name']], dict) or attached[n['name']].get('NetworkID') != n['id']:
        _fail('actual Hub is attached to an unapproved Docker network')
    ports = actual_c.get('NetworkSettings.Ports')
    expected_ports = {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(config['host_port'])}]}
    if ports != expected_ports:
        _fail('actual Hub publish is not restricted to the pinned host loopback port')

    network_fields = ['Id', 'Name', 'Driver', 'Internal', 'EnableIPv6', 'Labels', 'Containers']
    actual_n = _docker_inspect('network', n['id'], network_fields)
    members = actual_n.get('Containers')
    if actual_n.get('Id') != n['id'] or actual_n.get('Name') != n['name'] or \
            actual_n.get('Driver') != 'bridge' or actual_n.get('Internal') is not False or \
            actual_n.get('EnableIPv6') is not False or actual_n.get('Labels') != n.get('labels') or \
            not isinstance(members, dict) or set(members) != {c['id']} or \
            members[c['id']].get('Name') != c['name']:
        _fail('actual Hub bridge differs from the exact one-container manifest')

    image_fields = ['Id', 'Config.Labels']
    actual_image = _docker_inspect('image', hub_image_id, image_fields)
    image_labels = actual_image.get('Config.Labels') or {}
    pinned_image_labels = {
        'org.opencontainers.image.revision': core_revision,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': source_fingerprint,
        'org.cicada.client-catalog.sha256': catalog_sha256,
        'org.cicada.role': 'hub',
    }
    if actual_image.get('Id') != hub_image_id or any(image_labels.get(k) != v for k, v in pinned_image_labels.items()):
        _fail('actual immutable Hub image ID or provenance labels differ from the pinned build')
    if config.get('f6'):
        actual_interop = _docker_inspect('image', config['interop_image_id'], ['Id'])
        if actual_interop.get('Id') != config['interop_image_id']:
            _fail('actual immutable interop image ID differs from the Root-pinned delivery')
    if _discover_owned('container', paths['root']) != [c['id']] or \
            _discover_owned('network', paths['root']) != [n['id']]:
        _fail('current Docker discovery contains extra or missing fixture-owned resources')
    try:
        with socket.create_connection(('127.0.0.1', config['host_port']), timeout=3):
            pass
    except OSError:
        _fail('pinned Core Hub host loopback endpoint is not reachable')

    fixture = {
        'container': c['name'], 'network': n['name'], 'image': hub_image_id,
        'source_revision': core_revision, 'client_public': str(paths['setup']),
        'base_url': f"http://127.0.0.1:{config['host_port']}", 'fixture_dir': str(paths['root']),
    }
    public_projection = {
        'base_url': f"http://127.0.0.1:{config['host_port']}", 'source_revision': core_revision,
        'source_fingerprint': source_fingerprint, 'catalog_sha256': catalog_sha256,
        'contract_revision': contract_revision,
    }
    hub = {'Id': c['id'], 'Image': hub_image_id, 'Config': {'Image': hub_image_id, 'Labels': c['labels']},
        'State': {'Running': True}}
    network = {'Id': n['id'], 'Name': n['name']}
    return fixture, public_projection, hub, network, '127.0.0.1', config['host_port']


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        _fail('required existing Android carrier module is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _configure(args):
    global _CONFIG
    root = Path(args.fixture_root)
    pin_args = (
        getattr(args, 'root_pins', None), getattr(args, 'root_pins_sha256', None),
        getattr(args, 'delivery_metadata', None), getattr(args, 'delivery_metadata_sha256', None),
    )
    if any(value is not None for value in pin_args):
        if not all(value is not None for value in pin_args):
            _fail('F6 requires the Root pins path/hash and actual delivery metadata path/hash together')
        legacy_override_args = (
            getattr(args, 'setup_sha256', None), getattr(args, 'ready_sha256', None),
            getattr(args, 'reference_sha256', None), getattr(args, 'manifest_sha256', None),
            getattr(args, 'hub_id', None), getattr(args, 'hub_port', None),
        )
        if any(value is not None for value in legacy_override_args):
            _fail('F6 refuses legacy per-file or Hub override pins')
        pins_module = _load_module(F164_PINS_PATH, 'v164_link_fixture_pins')
        pins = pins_module.read_trusted_delivery(
            args.root_pins, args.root_pins_sha256, args.delivery_metadata,
            args.delivery_metadata_sha256,
        )
        fixture = pins_module.validate_f6_fixture(pins, root)
        paths = {
            'root': fixture['root'], 'setup': fixture['setup'], 'ready': fixture['ready'],
            'reference': fixture['reference'], 'manifest': fixture['manifest'],
        }
        _CONFIG = {**fixture, 'f6': True, 'paths': paths}
        return _CONFIG

    if root not in (F1_FIXTURE_ROOT, F2_FIXTURE_ROOT, F3_FIXTURE_ROOT, F4_FIXTURE_ROOT, F5_FIXTURE_ROOT):
        _fail('only the five Root-authorized v1.6.4 fixture roots are allowed')
    if root == F1_FIXTURE_ROOT:
        trusted = {
            'setup_sha256': F1_SETUP_SHA256,
            'ready_sha256': F1_READY_SHA256,
            'manifest_sha256': F1_OWNED_MANIFEST_SHA256,
            'hub_id': F1_HUB_ID,
            'host_port': F1_HOST_PORT,
        }
        for arg, key in (('setup_sha256', 'setup_sha256'), ('ready_sha256', 'ready_sha256'),
                ('manifest_sha256', 'manifest_sha256'), ('hub_id', 'hub_id'), ('hub_port', 'host_port')):
            supplied = getattr(args, arg)
            if supplied is not None and supplied != trusted[key]:
                _fail('supplied historical fixture pin differs from its frozen value')
    elif root == F2_FIXTURE_ROOT:
        required = ('setup_sha256', 'ready_sha256', 'manifest_sha256', 'hub_id', 'hub_port')
        if any(getattr(args, name) is None for name in required):
            _fail('F2 requires all three metadata hashes and explicit trusted Hub ID and port')
        trusted = {
            'setup_sha256': args.setup_sha256,
            'ready_sha256': args.ready_sha256,
            'manifest_sha256': args.manifest_sha256,
            'hub_id': args.hub_id,
            'host_port': args.hub_port,
        }
    else:
        required = ('setup_sha256', 'ready_sha256', 'reference_sha256', 'manifest_sha256', 'hub_id', 'hub_port')
        if any(getattr(args, name) is None for name in required):
            _fail('F3/F4/F5 require all four metadata hashes and explicit trusted Hub ID and port')
        trusted = {
            'setup_sha256': args.setup_sha256,
            'ready_sha256': args.ready_sha256,
            'reference_sha256': args.reference_sha256,
            'manifest_sha256': args.manifest_sha256,
            'hub_id': args.hub_id,
            'host_port': args.hub_port,
        }
    for key in ('setup_sha256', 'ready_sha256', 'manifest_sha256'):
        if re.fullmatch(r'[0-9a-f]{64}', trusted[key] or '') is None:
            _fail('full lowercase SHA-256 pins are required for all Core metadata files')
    if trusted.get('reference_sha256') is not None and \
            re.fullmatch(r'[0-9a-f]{64}', trusted['reference_sha256']) is None:
        _fail('full lowercase SHA-256 pin is required for the F3 reference manifest')
    if not isinstance(trusted['hub_id'], str) or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', trusted['hub_id']) is None or \
            type(trusted['host_port']) is not int or not 1024 <= trusted['host_port'] <= 65535:
        _fail('explicit trusted Hub ID or loopback port is invalid')
    _CONFIG = {**trusted, 'paths': _input_paths(root)}
    return _CONFIG


def run(args):
    global _EXPECTED_APP_SHA256, _EXPECTED_TEST_SHA256
    config = _configure(args)
    if args.android_url_port is None:
        args.android_url_port = config['host_port']
    if args.android_url_port != config['host_port']:
        _fail('Android URL port differs from the explicitly trusted Core loopback port')
    for value in (args.app_sha256, args.test_sha256):
        if re.fullmatch(r'[0-9a-f]{64}', value or '') is None:
            _fail('full lowercase app and test APK hashes are required')
    if config.get('f6') and (args.app_sha256 != F6_APP_SHA256 or args.test_sha256 != F6_TEST_SHA256):
        _fail('fresh F6 carrier accepts only the independently frozen retry-6 APK pair')
    if args.fault != 'none':
        _fail('this bounded synthetic fixture carrier does not inject network faults')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', args.tag):
        _fail('invalid carrier tag')
    if not 1024 <= args.carrier_port <= 65535 or args.carrier_port == config['host_port']:
        _fail('carrier and Hub loopback ports must be distinct valid high ports')
    _EXPECTED_APP_SHA256, _EXPECTED_TEST_SHA256 = args.app_sha256, args.test_sha256

    contract_revision = _pinned(config, 'contract_revision', 'CONTRACT_REVISION')
    core_revision = _pinned(config, 'core_revision', 'CORE_REVISION')
    source_fingerprint = _pinned(config, 'source_fingerprint', 'SOURCE_FINGERPRINT')
    catalog_sha256 = _pinned(config, 'catalog_sha256', 'CATALOG_SHA256')
    hub_image_id = _pinned(config, 'hub_image_id', 'HUB_IMAGE')
    interop_image_id = _pinned(config, 'interop_image_id', 'INTEROP_IMAGE')

    carrier = _load_module(V16_CARRIER_PATH, 'v16_host_carrier_for_v164')
    carrier.CONTRACT_REVISION = contract_revision
    carrier.CORE_REVISION = core_revision
    carrier.SOURCE_FINGERPRINT = source_fingerprint
    carrier.CATALOG_SHA256 = catalog_sha256
    carrier.HUB_IMAGE = hub_image_id
    carrier.SCHEMA = SCHEMA
    carrier.ALLOWED = ALLOWED
    carrier._NATIVE_FIXTURE_MODE = True
    carrier._EXPECTED_APP_SHA256 = args.app_sha256
    carrier._EXPECTED_TEST_SHA256 = args.test_sha256
    def load_driver():
        module = _load_module(V164_RUNNER_PATH, 'v164_android_driver_for_link_carrier')
        module.CONTRACT_REVISION = contract_revision
        module.CORE_REVISION = core_revision
        module.CORE_SOURCE_FINGERPRINT = source_fingerprint
        module.CATALOG_SHA256 = catalog_sha256
        module.HUB_IMAGE = hub_image_id
        module.INTEROP_IMAGE = interop_image_id
        return module

    carrier.load_driver = load_driver
    carrier.verify_hub = verify_hub
    carrier.v15_host.SCHEMA = SCHEMA
    carrier.v15_host.CONTRACT_REVISION = contract_revision
    carrier.v15_host.CORE_REVISION = core_revision
    carrier.v15_host.SOURCE_FINGERPRINT = source_fingerprint
    carrier.v15_host.CATALOG_SHA256 = catalog_sha256
    carrier.v15_host.HUB_IMAGE = hub_image_id
    carrier.v15_host.ALLOWED = ALLOWED
    carrier.v15_host._EXPECTED_APP_SHA256 = args.app_sha256
    carrier.v15_host._EXPECTED_TEST_SHA256 = args.test_sha256

    # The existing v1.6 wrapper requires six immutable-file pin positions; the
    # v1.6.4 adapter binds them to setup, readiness, and owned Docker metadata.
    args.fixture = str(config['paths']['setup'])
    args.public = str(config['paths']['ready'])
    args.native_topology = str(config['paths']['ready'])
    args.native_topology_sha256 = config['ready_sha256']
    args.fixture_sha256 = config['setup_sha256']
    args.public_sha256 = config['ready_sha256']
    args.native_mounts = str(config['paths']['manifest'])
    args.native_mounts_sha256 = config['manifest_sha256']
    args.recovery_mode = None
    carrier.run(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-root', default=str(F1_FIXTURE_ROOT),
        help='an exact F1-F5 root or explicitly Root-pinned fresh F6 root')
    parser.add_argument('--evidence', required=True, help='owned v1.6.4 Android evidence directory')
    parser.add_argument('--tag', required=True, help='unique opaque-carrier evidence tag')
    parser.add_argument('--app-sha256', required=True, help='full SHA-256 of the installed Client APK')
    parser.add_argument('--test-sha256', required=True, help='full SHA-256 of the installed test APK')
    parser.add_argument('--setup-sha256', help='trusted full SHA-256 of this fixture public setup')
    parser.add_argument('--ready-sha256', help='trusted full SHA-256 of this fixture ready receipt')
    parser.add_argument('--reference-sha256', help='trusted full SHA-256 of the F3 reference manifest')
    parser.add_argument('--manifest-sha256', help='trusted full SHA-256 of this owned Docker manifest')
    parser.add_argument('--hub-id', help='trusted Hub ID; required for F2/F3/F4/F5')
    parser.add_argument('--hub-port', type=int, help='trusted loopback port; required for F2/F3/F4/F5')
    parser.add_argument('--root-pins', help='external Root-trusted F6 delivery/fixture pins JSON')
    parser.add_argument('--root-pins-sha256', help='out-of-band SHA-256 for the Root pins bytes')
    parser.add_argument('--delivery-metadata', help='local actual clean Core delivery metadata JSON')
    parser.add_argument('--delivery-metadata-sha256', help='full SHA-256 of the actual delivery metadata')
    parser.add_argument('--fault', choices=('none',), default='none')
    parser.add_argument('--carrier-port', type=int, default=38097)
    parser.add_argument('--android-url-port', type=int)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        run(args)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        print(json.dumps({'result': 'FAIL', 'tag': args.tag,
            'reason': 'pinned synthetic v1.6.4 fixture verification or opaque relay failed'}),
            file=sys.stderr, flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
