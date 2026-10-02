#!/usr/bin/env python3
"""Opaque five-route Android carrier for synthetic v1.6.4 Core fixtures.

F1-F5 retain their historical pin paths. Fresh F6 requires independently
Root-hashed delivery pins plus matching local delivery metadata. The adapter
performs read-only selected-field Docker inspections, then reuses the existing
v1.5 STDIO/HTTP relay framing. It never reads container env values, Hub state,
Owner private keys, or request/response plaintext semantics.
"""

import argparse
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
        _read_exact_private(paths['reference'], config['reference_sha256'], maximum=64 * 1024)
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
