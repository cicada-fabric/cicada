#!/usr/bin/env python3
"""Strict Root-pinned delivery metadata for fresh v1.6.4 Link fixtures.

This is an internal offline fixture adapter, not a Hub protocol or discovery
format. The Root pins file is trusted only when its exact bytes match a hash
provided independently by the caller. Local Hub responses never select pins.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat


ROOT_PINS_SCHEMA = 'cicada.client-v164-f6-root-pins.v1'
DELIVERY_SCHEMA = 'cicada.client-v164-local-delivery.v1'
CONTRACT_REVISION = 'client-hub-v1.6.4'
WIRE_VERSION = 1
SCHEMA_VERSION = 57
OPERATION_COUNT = 55
CATALOG_SHA256 = '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'
AUTHORIZED_CORE_REVISIONS = {
    '25bc586232db43362c6e03eccef1fa3a0dbec8ee',
    'dd81575b160aa901b642137e54d7a60961e4bd68',
}
CACHE_ROOT = Path('/gpu1-share/data/cicada-client')
CORE_F6_ROOT = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002')
CORE_F6_REVISION = 'dd81575b160aa901b642137e54d7a60961e4bd68'
FIXTURE_LABEL = 'client-link-v164-06'
HEX64 = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
HUB_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')

_ROOT_KEYS = {
    'schema', 'scope', 'fixture_root', 'delivery_metadata_sha256',
    'core', 'images', 'fixture',
}
_CORE_KEYS = {
    'revision', 'source_dirty', 'source_fingerprint', 'contract_revision',
    'wire_version', 'schema_version', 'operation_count', 'catalog_sha256',
    'producer_sha256', 'package_sha256',
}
_IMAGE_KEYS = {'hub', 'interop'}
_FIXTURE_KEYS = {
    'label', 'setup_sha256', 'ready_sha256', 'reference_sha256',
    'owned_manifest_sha256', 'hub_id', 'host_port',
}
_DELIVERY_KEYS = {
    'schema', 'revision', 'source_dirty', 'source_fingerprint',
    'contract_revision', 'wire_version', 'schema_version',
    'operation_count', 'catalog_sha256', 'producer_sha256',
    'package_sha256', 'hub_image_id', 'interop_image_id',
}
_MAX_FILE = 64 * 1024
_MAIN_READY_KEYS = {
    'schema', 'status', 'fixture_root', 'protocol_scope', 'native_runtime',
    'model_calls', 'public_references', 'source', 'hub', 'client_setup_sha256',
    'hub_ready_sha256', 'reference_manifest_sha256', 'owned_manifest_sha256',
    'coordination_nonce', 'coordination_deadline', 'coordination_ttl_seconds',
    'cleanup_policy',
}
_MAIN_REFERENCE_NAMES = {
    'client_setup', 'custody_manifest', 'fixture_public', 'helper_binary',
    'helper_provenance', 'helper_source', 'hub_ready', 'reference_manifest', 'runner',
}


def _main_f6_paths(pins, root):
    """Resolve Main fixture paths from Root-bound READY bytes, never a draft.

    The carrier independently validates all referenced files and runtime facts.
    This shared path resolver also serves the Android runner and coordinator.
    """
    ready_path = root / 'public/READY.json'
    _raw, _digest, ready = _read_file(ready_path,
        expected_sha256=pins['fixture_pins']['ready_sha256'])
    _exact(ready, _MAIN_READY_KEYS, 'Main F6 READY')
    if ready['schema'] != 'cicada.client-link-v164-fixture-ready.v1' or \
            ready['status'] != 'READY_FOR_CLIENT_COORDINATION' or \
            ready['fixture_root'] != str(root):
        _fail('Main F6 requires an actual Root-bound READY for the selected root')
    for field, pin in (
            ('client_setup_sha256', 'setup_sha256'),
            ('reference_manifest_sha256', 'reference_sha256'),
            ('owned_manifest_sha256', 'owned_manifest_sha256')):
        if ready[field] != pins['fixture_pins'][pin]:
            _fail('Main F6 READY digests disagree with independently supplied Root pins')
    refs = ready['public_references']
    _exact(refs, _MAIN_REFERENCE_NAMES, 'Main F6 public references')
    hub_ready = refs['hub_ready']
    _exact(hub_ready, {'path', 'sha256', 'bytes', 'mode', 'relative_path'},
        'Main F6 Hub readiness reference')
    relative = hub_ready['relative_path']
    if not isinstance(relative, str) or \
            re.fullmatch(r'evidence/attempt-[0-9]{2}/hub-ready-final\.json', relative) is None or \
            hub_ready['path'] != str(root / relative):
        _fail('Main F6 Hub readiness path must identify an exact public attempt')
    _sha(hub_ready['sha256'], 'Main F6 Hub readiness SHA-256')
    if ready['hub_ready_sha256'] != hub_ready['sha256'] or \
            type(hub_ready['bytes']) is not int or not 0 < hub_ready['bytes'] <= _MAX_FILE or \
            hub_ready['mode'] != '0o100600':
        _fail('Main F6 Hub readiness reference is malformed')
    attempt = (root / relative).parent
    _reject_symlink_path_components(attempt)
    return ready_path, attempt / 'owned-hub-manifest.json'


def _fail(message):
    raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('trusted delivery JSON contains duplicate fields')
        result[key] = value
    return result


def _reject_constant(_value):
    _fail('trusted delivery JSON contains a non-finite number')


def _depth(value, level=0):
    if level > 12:
        _fail('trusted delivery JSON exceeds its nesting bound')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail('trusted delivery JSON has a non-string key')
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def _read_file(path_value, *, expected_sha256=None, accepted_modes=(0o600,)):
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        _fail('trusted metadata paths must be absolute and nonsymlinked')
    try:
        resolved = path.resolve(strict=True)
        before = path.lstat()
        if resolved != path or not stat.S_ISREG(before.st_mode) or \
                stat.S_IMODE(before.st_mode) not in accepted_modes or \
                before.st_uid != os.getuid() or before.st_nlink != 1 or \
                not 0 < before.st_size <= _MAX_FILE:
            _fail('trusted metadata must be an owned bounded regular file with an allowed mode')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != \
                    (before.st_dev, before.st_ino, before.st_size):
                _fail('trusted metadata changed while opening')
            chunks = bytearray()
            while len(chunks) <= _MAX_FILE:
                part = os.read(fd, min(65536, _MAX_FILE + 1 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
            after = os.fstat(fd)
            if len(chunks) != opened.st_size or \
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                _fail('trusted metadata changed while reading')
        finally:
            os.close(fd)
    except OSError:
        _fail('trusted metadata is unavailable')
    raw = bytes(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        _fail('trusted metadata bytes differ from the expected SHA-256')
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('trusted metadata JSON is malformed')
    _depth(value)
    if not isinstance(value, dict):
        _fail('trusted metadata root must be an object')
    return raw, digest, value


def _exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(label + ' fields do not match the closed schema')


def _sha(value, label):
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        _fail(label + ' must be a full lowercase SHA-256')


def _validate_core(core, images):
    _exact(core, _CORE_KEYS, 'Root core pins')
    _exact(images, _IMAGE_KEYS, 'Root immutable image pins')
    if not isinstance(core['revision'], str) or core['revision'] not in AUTHORIZED_CORE_REVISIONS or \
            type(core['source_dirty']) is not bool or core['source_dirty'] is not False or \
            core['contract_revision'] != CONTRACT_REVISION or \
            type(core['wire_version']) is not int or core['wire_version'] != WIRE_VERSION or \
            type(core['schema_version']) is not int or core['schema_version'] != SCHEMA_VERSION or \
            type(core['operation_count']) is not int or core['operation_count'] != OPERATION_COUNT or \
            core['catalog_sha256'] != CATALOG_SHA256:
        _fail('delivery metadata does not match the authorized clean v1.6.4 contract pins')
    for field in ('source_fingerprint', 'catalog_sha256', 'producer_sha256', 'package_sha256'):
        _sha(core[field], 'core ' + field)
    for field in ('hub', 'interop'):
        if not isinstance(images[field], str) or IMAGE_ID.fullmatch(images[field]) is None:
            _fail('immutable ' + field + ' image ID is malformed')


def _validate_fixture(fixture):
    _exact(fixture, _FIXTURE_KEYS, 'Root fresh-fixture pins')
    if fixture['label'] != FIXTURE_LABEL:
        _fail('fixture label does not select the fresh F6 scope')
    for field in ('setup_sha256', 'ready_sha256', 'reference_sha256', 'owned_manifest_sha256'):
        _sha(fixture[field], 'fixture ' + field)
    if not isinstance(fixture['hub_id'], str) or HUB_ID.fullmatch(fixture['hub_id']) is None or \
            type(fixture['host_port']) is not int or not 1024 <= fixture['host_port'] <= 65535:
        _fail('fixture Hub ID or loopback port is malformed')


def _reject_symlink_path_components(path):
    """Reject symlink aliases in an authorized absolute path, if it exists yet."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            # F6 may be pinned before Core creates its leaf directory. Any
            # existing ancestor has still been checked for symlink aliases.
            break
        except OSError:
            _fail('Core-owned fixture path cannot be safely inspected')
        if stat.S_ISLNK(info.st_mode):
            _fail('Core-owned fixture path must not contain symlink components')
        if current != path and not stat.S_ISDIR(info.st_mode):
            _fail('Core-owned fixture path has a non-directory ancestor')
        if current == path and not stat.S_ISDIR(info.st_mode):
            _fail('Core-owned fixture root is not a directory')


def _validate_fixture_root(root_value, expected_value, revision):
    if not isinstance(root_value, str) or not isinstance(expected_value, str) or \
            not isinstance(revision, str):
        _fail('Root-authorized fixture root or selected revision is malformed')
    root = Path(root_value)
    expected = Path(expected_value)
    if not root.is_absolute() or root != expected or root.as_posix() != expected_value or \
            '..' in root.parts or '.' in root.parts:
        _fail('fixture root must exactly match the Root-authorized F6 path')

    # One separately authorized Core-owned location supports the clean dd81575
    # delivery. Keep it literal and revision-bound; it is not a general Core
    # path fallback and the older 25bc586 delivery remains cache-only.
    if root == CORE_F6_ROOT and expected_value == CORE_F6_ROOT.as_posix():
        if revision != CORE_F6_REVISION:
            _fail('Core-owned F6 fixture root is authorized only for the dd81575 delivery')
        _reject_symlink_path_components(root)
        return root

    if root.name != 'fixture-f6':
        _fail('fixture root must exactly match the Root-authorized F6 path')
    try:
        relative = root.relative_to(CACHE_ROOT)
    except ValueError:
        _fail('fresh F6 fixture root must be inside the dedicated Client evidence cache')
    if len(relative.parts) != 2 or not relative.parts[0].startswith('v164-'):
        _fail('fresh F6 fixture root has an unexpected cache layout')
    # Scope the path to the selected Core revision while allowing Root's dated
    # cache directory name to vary without inventing a particular date.
    cache_name = relative.parts[0]
    if cache_name != 'v164-' + revision[:7] and not cache_name.startswith('v164-' + revision[:7] + '-'):
        _fail('fresh F6 fixture cache does not identify the selected Core revision')
    return root


def read_trusted_delivery(pins_path, pins_sha256, metadata_path, metadata_sha256=None):
    """Read Root trust pins and compare them with a local delivery metadata file.

    `pins_sha256` is supplied independently of the pins file. The pins bind the
    complete local metadata bytes; `metadata_sha256`, when supplied by a
    caller, is a redundant explicit check rather than an alternate trust path.
    """
    _sha(pins_sha256, 'Root pins SHA-256')
    if metadata_sha256 is not None:
        _sha(metadata_sha256, 'local delivery metadata SHA-256')
    _pins_raw, actual_pins_sha, pins = _read_file(pins_path,
        expected_sha256=pins_sha256, accepted_modes=(0o600,))
    _exact(pins, _ROOT_KEYS, 'Root trust pins')
    if pins.get('schema') != ROOT_PINS_SCHEMA or pins.get('scope') != 'fresh-F6':
        _fail('Root trust pins do not describe one fresh F6 fixture')
    delivery_sha = pins.get('delivery_metadata_sha256')
    _sha(delivery_sha, 'Root-pinned local delivery metadata SHA-256')
    _local_raw, actual_delivery_sha, delivery = _read_file(metadata_path,
        expected_sha256=delivery_sha, accepted_modes=(0o600, 0o644))
    if metadata_sha256 is not None and actual_delivery_sha != metadata_sha256:
        _fail('local delivery metadata differs from the caller-supplied SHA-256')
    _exact(delivery, _DELIVERY_KEYS, 'local delivery metadata')
    if delivery.get('schema') != DELIVERY_SCHEMA:
        _fail('local delivery metadata schema is unrecognized')

    core = pins.get('core')
    images = pins.get('images')
    _validate_core(core, images)
    _validate_fixture(pins.get('fixture'))

    actual_core = {key: delivery[key] for key in _CORE_KEYS}
    actual_images = {'hub': delivery['hub_image_id'], 'interop': delivery['interop_image_id']}
    _validate_core(actual_core, actual_images)
    if actual_core != core or actual_images != images:
        _fail('Root delivery pins and local clean delivery metadata disagree')

    root = _validate_fixture_root(pins.get('fixture_root'), pins.get('fixture_root'), core['revision'])
    result = dict(pins)
    result['root_pins_sha256'] = actual_pins_sha
    result['delivery_metadata_sha256'] = actual_delivery_sha
    result['metadata_path'] = str(Path(metadata_path))
    result['fixture_root'] = str(root)
    result['core_revision'] = core['revision']
    result['source_fingerprint'] = core['source_fingerprint']
    result['source_dirty'] = core['source_dirty']
    result['contract_revision'] = core['contract_revision']
    result['wire_version'] = core['wire_version']
    result['schema_version'] = core['schema_version']
    result['operation_count'] = core['operation_count']
    result['catalog_sha256'] = core['catalog_sha256']
    result['producer_sha256'] = core['producer_sha256']
    result['package_sha256'] = core['package_sha256']
    result['hub_image_id'] = images['hub']
    result['interop_image_id'] = images['interop']
    result['fixture_label'] = pins['fixture']['label']
    result['fixture_pins'] = dict(pins['fixture'])
    return result


def validate_f6_fixture(pins, root):
    """Bind an explicit caller-supplied root to previously verified Root pins."""
    if not isinstance(pins, dict) or pins.get('scope') != 'fresh-F6':
        _fail('verified Root pins for fresh F6 are required')
    selected_root = _validate_fixture_root(str(root), pins.get('fixture_root'), pins['core_revision'])
    if pins.get('fixture_label') != FIXTURE_LABEL:
        _fail('verified Root pins do not carry the dedicated F6 ownership label')
    ready = selected_root / 'evidence/ready-receipt.json'
    manifest = selected_root / 'evidence/owned-hub-manifest.json'
    if selected_root == CORE_F6_ROOT:
        ready, manifest = _main_f6_paths(pins, selected_root)
    return {
        'root': selected_root,
        'setup': selected_root / 'public/client-setup.json',
        'ready': ready,
        'reference': selected_root / 'public/reference-manifest.json',
        'manifest': manifest,
        'setup_sha256': pins['fixture_pins']['setup_sha256'],
        'ready_sha256': pins['fixture_pins']['ready_sha256'],
        'reference_sha256': pins['fixture_pins']['reference_sha256'],
        'manifest_sha256': pins['fixture_pins']['owned_manifest_sha256'],
        'hub_id': pins['fixture_pins']['hub_id'],
        'host_port': pins['fixture_pins']['host_port'],
        'fixture_label': pins['fixture_label'],
        'core_revision': pins['core_revision'],
        'source_fingerprint': pins['source_fingerprint'],
        'source_dirty': pins['source_dirty'],
        'contract_revision': pins['contract_revision'],
        'wire_version': pins['wire_version'],
        'schema_version': pins['schema_version'],
        'operation_count': pins['operation_count'],
        'catalog_sha256': pins['catalog_sha256'],
        'producer_sha256': pins['producer_sha256'],
        'package_sha256': pins['package_sha256'],
        'hub_image_id': pins['hub_image_id'],
        'interop_image_id': pins['interop_image_id'],
        'root_pins_sha256': pins['root_pins_sha256'],
        'delivery_metadata_sha256': pins['delivery_metadata_sha256'],
    }
