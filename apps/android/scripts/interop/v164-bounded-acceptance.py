#!/usr/bin/env python3
"""Single-process supervisor for one Root-authorized offline v1.6.4 run.

Plan validation is offline and read-only. Runtime execution requires both an
independently pinned bootstrap plan and one fresh business-plan ticket on
stdin. Ticket delivery is not itself authorization; the embedded exact Scope
and Root GO bytes are checked before any declared business command runs.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[2]
CACHE = Path('/gpu1-share/data/cicada-client')
DOCKER_ROOT = '/gpu1-share/data/docker-root'
BOOT_SCHEMA = 'cicada.client-v164-launcher-boot.v1'
BOOT_PLAN_SCHEMA = 'cicada.client-v164-bounded-bootstrap-plan.v1'
BUSINESS_PLAN_SCHEMA = 'cicada.client-v164-bounded-business-plan.v1'
SCOPE_SCHEMA = 'cicada.f8.m5-owner-actor-scope.v1'
GO_SCHEMA = 'cicada.f8.owner-actor-root-go.v1'
GO_FIELDS = {
    'schema', 'scope_token', 'scope_path', 'scope_sha256', 'approval_id',
    'root_thread_id', 'approved', 'approved_at', 'expires_at', 'max_requests',
}
ROOT_THREAD_ID = '01a0a91b-c2b6-76b2-baf5-95422f4deeef'
CORE_COMMIT = 'dd81575b160aa901b642137e54d7a60961e4bd68'
HUB_IMAGE = 'sha256:ab189ee06372e4eaa248eac6e3699f7b4e2d9105505e87027f0081d118adc561'
CATALOG_SHA256 = '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'
CONTRACT_ARCHIVE_SHA256 = '5a4e52b8e6df15e10870c568cdd745ac8246bf856ff45d39efac398b4a418ef1'
CORE_SOURCE_FINGERPRINT = 'b874b7fbf3453e0a5faa3ba36c1eb89337d0c4920353ed225b314666e1c04556'
EMULATOR_IMAGE = 'sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f'
INTEROP_IMAGE = 'sha256:c926d0f3809572e541414cbb239efdc00ba82d07e16950318199df4c6d5e2679'
APK_HASHES = {
    'app': '56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67',
    'test': 'caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6',
}
EXPECTED_RUNTIME = {
    'api_level': '35', 'android_release': '15', 'abi': 'x86_64', 'emulator': '1',
}
DECLARED_FLOW_ORDER = [
    'source-device', 'target-device', 'source-key', 'source-none',
    'target-key-rn', 'target-none',
]
HEX64 = re.compile(r'[0-9a-f]{64}')
HEX40 = re.compile(r'[0-9a-f]{40}')
RUN_ID = re.compile(r'v16-deterministic-v164-f6-[A-Za-z0-9_-]{1,80}')
UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z')
SOURCE_ROLES = {'boot', 'runtime_consumer', 'stop_runner'}
ALLOWED_PLACEHOLDERS = {
    '{EVIDENCE_ROOT}', '{CLIENT_COMMIT}', '{READINESS_SHA256}', '{CONTAINER_ID}',
    '{BOOT_RECEIPT_SHA256}', '{BOOT_PLAN_SHA256}', '{FIXTURE_ROOT}',
    '{SCOPE_SHA256}', '{ROOT_GO_SHA256}', '{DELIVERY_PINS}',
    '{DELIVERY_PINS_SHA256}', '{DELIVERY_METADATA}',
    '{DELIVERY_METADATA_SHA256}', '{CARRIER_TAG}', '{FLOW_ORDER_JSON}',
    '{CARRIER_HOST_PID}', '{CARRIER_PID}',
    '{ANDROID_RUN_ID}', '{RUNTIME_CONSUMER_PATH}', '{RUNTIME_CONSUMER_SHA256}',
}
TOPOLOGY_NAMES = {
    'client_setup', 'custody_manifest', 'fixture_public', 'helper_binary',
    'helper_provenance', 'helper_source', 'hub_ready', 'reference_manifest', 'runner',
}
TOPOLOGY_MODES = {
    name: (0o644 if name == 'client_setup' else
        0o755 if name == 'helper_binary' else
        0o700 if name == 'runner' else 0o600)
    for name in TOPOLOGY_NAMES
}
SCOPE_FIELDS = {
    'allowed_business_operations', 'allowed_signatures', 'bindings', 'business_networks',
    'coordination_deadline', 'device_scope', 'endpoints', 'fixed', 'fixture_label',
    'fixture_root', 'groups', 'hub', 'key_manifest_digest', 'link',
    'max_signature_requests', 'model_calls_by_actor', 'native_review_id',
    'native_runtime_by_actor', 'none', 'owned_manifest', 'owner_actor_authority',
    'owners', 'phone_expiry_rule', 'ready', 'schema', 'scope_token',
    'target_rn_alert_obligation',
}
_STOP = False
_TICKET_FD = None


class PlanError(ValueError):
    """A bounded plan, evidence, or execution contract failed."""


class Deadline:
    """An absolute UTC cutoff captured once onto a monotonic clock."""

    def __init__(self, wall_epoch, wall_text, monotonic_epoch=None):
        self.wall_epoch = wall_epoch
        self.wall_text = wall_text
        if monotonic_epoch is None:
            self.monotonic_epoch = time.monotonic() + max(0.0, wall_epoch - time.time())
        else:
            self.monotonic_epoch = monotonic_epoch

    @classmethod
    def from_utc(cls, value):
        return cls(_utc(value, 'deadline'), value)

    @classmethod
    def after(cls, seconds, label='bounded cleanup'):
        if type(seconds) not in (int, float) or isinstance(seconds, bool) or seconds <= 0:
            raise PlanError(label + ' duration is invalid')
        now_wall = time.time()
        now_mono = time.monotonic()
        stamp = dt.datetime.fromtimestamp(now_wall + seconds, dt.timezone.utc)
        text = stamp.strftime('%Y-%m-%dT%H:%M:%SZ')
        return cls(now_wall + seconds, text, now_mono + seconds)

    @classmethod
    def earliest(cls, deadlines):
        chosen = min(deadlines, key=lambda deadline: deadline.wall_epoch)
        remaining = max(0.0, min(deadline.wall_epoch for deadline in deadlines) - time.time())
        mono = min(min(deadline.monotonic_epoch for deadline in deadlines),
            time.monotonic() + remaining)
        return cls(chosen.wall_epoch, chosen.wall_text, mono)

    def remaining(self):
        return min(self.monotonic_epoch - time.monotonic(), self.wall_epoch - time.time())


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PlanError('JSON contains a duplicate object key')
        value[key] = item
    return value


def _no_constant(value):
    raise PlanError('JSON contains a non-finite number')


def _depth(value, level=0):
    if level > 24:
        raise PlanError('JSON exceeds the nesting bound')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PlanError('JSON object key is invalid')
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def parse_json(raw, label):
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
            object_pairs_hook=_unique_object, parse_constant=_no_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PlanError(label + ' is malformed JSON') from error
    _depth(value)
    if not isinstance(value, dict):
        raise PlanError(label + ' must be a JSON object')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise PlanError(label + ' fields do not match the frozen schema')


def _sha(value, label):
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise PlanError(label + ' must be a full lowercase SHA-256')


def _utc(value, label):
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise PlanError(label + ' must be canonical UTC with a Z suffix')
    fraction = value[20:-1].lstrip('.')
    if fraction and fraction.endswith('0'):
        raise PlanError(label + ' has a noncanonical fractional timestamp')
    try:
        return dt.datetime.fromisoformat(value[:-1] + '+00:00').timestamp()
    except ValueError as error:
        raise PlanError(label + ' is not a valid timestamp') from error


def _is_under(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _absolute_nonsymlink(path, label, *, must_exist=True):
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise PlanError(label + ' must be an absolute path')
    candidate = Path(path)
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as error:
        raise PlanError(label + ' is unavailable') from error
    if resolved != candidate:
        raise PlanError(label + ' must not use a symlink or path alias')
    return candidate


def _read_file(path_value, expected_sha=None, *, label='file', max_bytes=1024 * 1024,
        modes=(0o600,), require_owner=True, roots=None, retain_bytes=True):
    path = _absolute_nonsymlink(path_value, label)
    if roots and not any(_is_under(path, root) for root in roots):
        raise PlanError(label + ' is outside the explicitly allowed roots')
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) not in modes or \
                before.st_nlink != 1 or before.st_size <= 0 or before.st_size > max_bytes or \
                (require_owner and before.st_uid != os.getuid()):
            raise PlanError(label + ' is not an owned bounded regular file with an allowed mode')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != \
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                raise PlanError(label + ' changed while opening')
            chunks, size, hasher = [], 0, hashlib.sha256()
            while size <= max_bytes:
                chunk = os.read(fd, min(65536, max_bytes + 1 - size))
                if not chunk:
                    break
                hasher.update(chunk)
                if retain_bytes:
                    chunks.append(chunk)
                size += len(chunk)
            after = os.fstat(fd)
            if size != opened.st_size or (opened.st_dev, opened.st_ino, opened.st_size,
                    opened.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise PlanError(label + ' changed while reading')
        finally:
            os.close(fd)
    except OSError as error:
        raise PlanError(label + ' cannot be read safely') from error
    raw = b''.join(chunks) if retain_bytes else None
    digest = hasher.hexdigest()
    if expected_sha is not None and digest != expected_sha:
        raise PlanError(label + ' bytes differ from the independent SHA-256 pin')
    return raw, digest


def _private_plan(path, expected_sha, label):
    _sha(expected_sha, label + ' command-line SHA-256')
    raw, digest = _read_file(path, expected_sha, label=label, max_bytes=512 * 1024,
        roots=(CACHE,))
    return parse_json(raw, label), digest


def _source_refs(refs, required_roles, label):
    if not isinstance(refs, dict) or not refs:
        raise PlanError(label + ' source_refs must be a nonempty object')
    roles = {}
    for name, ref in refs.items():
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', name):
            raise PlanError(label + ' has an invalid source reference name')
        _keys(ref, {'path', 'sha256', 'role'}, label + ' source reference')
        role = ref['role']
        if not isinstance(role, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', role):
            raise PlanError(label + ' has an invalid source role')
        path = _absolute_nonsymlink(ref['path'], label + ' source path')
        if not (_is_under(path, REPO) or _is_under(path, CACHE)):
            raise PlanError(label + ' source files must be under Client repo or cache')
        if any(word in path.name.lower() for word in ('watcher', 'watchdog', 'idlewatch')):
            raise PlanError('legacy watcher sources are prohibited')
        _sha(ref['sha256'], label + ' source SHA-256')
        _read_file(str(path), ref['sha256'], label=label + ' source', max_bytes=64 * 1024 * 1024,
            modes=(0o600, 0o644, 0o700, 0o755), require_owner=False,
            roots=(REPO, CACHE))
        roles.setdefault(role, []).append(name)
    if not required_roles.issubset(roles):
        raise PlanError(label + ' omits a required pinned source role')
    return roles


def _git_identity():
    env = _child_environment()
    try:
        head = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=True, env=env, text=True).stdout.strip()
        status = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain',
            '--untracked-files=all'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=True, env=env, text=True).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise PlanError('Client Git checkout cannot be verified') from error
    if status:
        raise PlanError('Client checkout is not clean')
    return head


def validate_bootstrap_document(plan, expected_sha=None, *, verify_checkout=True, verify_apks=True):
    _keys(plan, {'schema', 'approval_id', 'client_commit', 'target', 'android',
        'docker_root', 'cache_root', 'source_refs', 'launcher_evidence_root',
        'idle_deadline', 'timeouts'}, 'bootstrap plan')
    if plan['schema'] != BOOT_PLAN_SCHEMA:
        raise PlanError('unsupported bootstrap plan schema')
    if not isinstance(plan['approval_id'], str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',
            plan['approval_id']) is None:
        raise PlanError('bootstrap approval identifier is invalid')
    if not isinstance(plan['client_commit'], str) or HEX40.fullmatch(plan['client_commit']) is None:
        raise PlanError('bootstrap Client commit must be a full Git SHA')
    expected_target_keys = {'core_commit', 'contract_revision', 'wire_version', 'schema_version',
        'operation_count', 'contract_archive_sha256', 'source_fingerprint', 'source_dirty',
        'hub_image_id', 'interop_image_id', 'catalog_sha256'}
    _keys(plan['target'], expected_target_keys, 'bootstrap target')
    target = plan['target']
    if target.get('contract_revision') != 'client-hub-v1.6.4' or \
            type(target.get('wire_version')) is not int or target['wire_version'] != 1 or \
            type(target.get('schema_version')) is not int or target['schema_version'] != 57 or \
            type(target.get('operation_count')) is not int or target['operation_count'] != 55 or \
            target.get('catalog_sha256') != CATALOG_SHA256 or target.get('source_dirty') is not False or \
            not isinstance(target.get('core_commit'), str) or HEX40.fullmatch(target['core_commit']) is None or \
            not isinstance(target.get('source_fingerprint'), str) or HEX64.fullmatch(target['source_fingerprint']) is None or \
            not isinstance(target.get('contract_archive_sha256'), str) or HEX64.fullmatch(target['contract_archive_sha256']) is None or \
            any(not isinstance(target.get(name), str) or re.fullmatch(r'sha256:[0-9a-f]{64}',
                target[name]) is None for name in ('hub_image_id', 'interop_image_id')):
        raise PlanError('bootstrap target differs from the fixed v1.6.4 delivery')
    if plan['docker_root'] != DOCKER_ROOT or plan['cache_root'] != str(CACHE):
        raise PlanError('bootstrap Docker data root or Client cache differs from the fixed host layout')
    android = plan['android']
    _keys(android, {'run_id', 'evidence_root', 'image_id', 'network', 'app', 'test'},
        'bootstrap Android target')
    if not isinstance(android['run_id'], str) or RUN_ID.fullmatch(android['run_id']) is None:
        raise PlanError('bootstrap run ID is invalid')
    if android['image_id'] != EMULATOR_IMAGE or android['network'] != 'none':
        raise PlanError('bootstrap emulator image/network differs from the fixed offline target')
    expected_evidence = CACHE / android['run_id'] / 'android'
    if android['evidence_root'] != str(expected_evidence):
        raise PlanError('Android evidence path is not the exact fresh run location')
    _absolute_nonsymlink(android['evidence_root'], 'Android evidence path', must_exist=False)
    for name in ('app', 'test'):
        item = android[name]
        _keys(item, {'path', 'sha256'}, name + ' APK pin')
        _sha(item['sha256'], name + ' APK SHA-256')
        if item['sha256'] != APK_HASHES[name]:
            raise PlanError(name + ' APK SHA-256 differs from the frozen pair')
        path = _absolute_nonsymlink(item['path'], name + ' APK path')
        if not _is_under(path, CACHE):
            raise PlanError('frozen APK must be in the Client cache')
        if verify_apks:
            _read_file(str(path), item['sha256'], label=name + ' APK',
                max_bytes=256 * 1024 * 1024, roots=(CACHE,), retain_bytes=False)
    launch_root = _absolute_nonsymlink(plan['launcher_evidence_root'],
        'launcher evidence path', must_exist=False)
    if not _is_under(launch_root, CACHE) or launch_root == expected_evidence or \
            _is_under(launch_root, expected_evidence.parent):
        raise PlanError('launcher evidence must use a separate fresh cache path')
    if not isinstance(plan['idle_deadline'], str) or re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', plan['idle_deadline']) is None:
        raise PlanError('bootstrap idle deadline must be an exact UTC second')
    deadline = _utc(plan['idle_deadline'], 'bootstrap idle deadline')
    if not 90 < deadline - time.time() <= 1200:
        raise PlanError('original idle deadline must be 90..1200 seconds ahead')
    _keys(plan['timeouts'], {'boot_seconds', 'command_seconds', 'carrier_ready_seconds',
        'cleanup_seconds'}, 'bootstrap timeouts')
    for name, maximum in (('boot_seconds', 90), ('command_seconds', 180),
            ('carrier_ready_seconds', 60), ('cleanup_seconds', 20)):
        value = plan['timeouts'][name]
        if type(value) is not int or not 1 <= value <= maximum:
            raise PlanError('bootstrap timeout is outside its fixed bound')
    source_roles = _source_refs(plan['source_refs'], SOURCE_ROLES, 'bootstrap plan')
    if any(len(source_roles[role]) != 1 for role in SOURCE_ROLES):
        raise PlanError('bootstrap source roles must each have one exact pinned file')
    if verify_checkout:
        if _git_identity() != plan['client_commit']:
            raise PlanError('Client HEAD differs from the independently pinned clean commit')
    if expected_sha is not None:
        _sha(expected_sha, 'bootstrap plan SHA-256')
    return {'run_id': android['run_id'], 'evidence_root': android['evidence_root'],
        'idle_deadline': plan['idle_deadline'], 'client_commit': plan['client_commit']}


def _read_declared(ref, label, *, max_bytes=1024 * 1024, roots=None, modes=(0o600,)):
    _keys(ref, {'path', 'sha256'}, label + ' pin')
    _sha(ref['sha256'], label + ' SHA-256')
    return _read_file(ref['path'], ref['sha256'], label=label, max_bytes=max_bytes,
        roots=roots, modes=modes)[0]


def _verify_topology_reference(name, ref, fixture_root):
    _keys(ref, {'path', 'sha256'}, 'Root topology reference')
    _sha(ref['sha256'], 'Root topology reference SHA-256')
    # Match the already shipped fixture verifier, including its executable
    # helper/runner and public setup modes. Hash large binaries without copies.
    _read_file(ref['path'], ref['sha256'], label='Root topology reference',
        max_bytes=32 * 1024 * 1024, modes=(TOPOLOGY_MODES[name],),
        roots=(fixture_root,), retain_bytes=False)


def _bind_aggregate_ready(ready, scope, refs, fixture_root):
    """Bind Main's aggregate READY independently of its inner Hub readiness."""
    if scope['ready']['path'] != str(fixture_root / 'public/READY.json') or \
            ready.get('schema') != 'cicada.client-link-v164-fixture-ready.v1' or \
            ready.get('status') != 'READY_FOR_CLIENT_COORDINATION' or \
            ready.get('fixture_root') != str(fixture_root) or \
            ready.get('coordination_deadline') != scope['coordination_deadline']:
        raise PlanError('Scope aggregate READY identity or deadline differs from the fixture')
    public_refs = ready.get('public_references')
    _keys(public_refs, TOPOLOGY_NAMES, 'aggregate READY public references')
    for name, ref in refs.items():
        actual = public_refs[name]
        _keys(actual, {'path', 'sha256', 'bytes', 'mode', 'relative_path'},
            'aggregate READY public reference')
        if ref != {'path': actual['path'], 'sha256': actual['sha256']}:
            raise PlanError('aggregate READY reference differs from its Root topology pin')
    for field, expected in (
        ('client_setup_sha256', refs['client_setup']['sha256']),
        ('hub_ready_sha256', refs['hub_ready']['sha256']),
        ('reference_manifest_sha256', refs['reference_manifest']['sha256']),
        ('owned_manifest_sha256', scope['owned_manifest']['sha256']),
    ):
        if ready.get(field) != expected:
            raise PlanError('aggregate READY four-hash binding differs from Root pins')


def _scope_go(plan, boot, boot_sha):
    if plan['bootstrap_plan_sha256'] != boot_sha:
        raise PlanError('business plan is not bound to this pinned bootstrap plan')
    if plan['container_id'] != boot.get('container_id') or \
            plan['boot_receipt_sha256'] != boot.get('receipt_sha256'):
        raise PlanError('business plan is not bound to the observed BOOT receipt')
    fixture = _absolute_nonsymlink(plan['fixture_root'], 'fresh fixture root')
    fixture_root = Path(plan['fixture_root'])
    core_data = Path('/home/zyf/CICADA/.cicada-data')
    if not _is_under(fixture_root, core_data) or \
            not fixture_root.name.startswith('client-link-v164-fixture-') or \
            fixture_root.name.endswith('-09-20261002'):
        raise PlanError('business plan must name a fresh exact v1.6.4 fixture root')
    if not isinstance(plan['fixture_label'], str) or not re.fullmatch(
            r'client-link-v164-[A-Za-z0-9_-]{1,48}', plan['fixture_label']):
        raise PlanError('fixture label is invalid')
    token = plan['scope_token']
    if not isinstance(token, str) or re.fullmatch(r'fresh-[A-Za-z0-9][A-Za-z0-9_-]{0,31}', token) is None or token == 'fresh-F9':
        raise PlanError('business plan requires a new explicit Scope token')
    if plan['scope']['path'] != str(fixture_root / 'public/M5-SCOPE.json') or \
            plan['go']['path'] != str(fixture_root / 'public/Root-GO.json'):
        raise PlanError('Scope and GO paths must be the exact fresh fixture documents')
    allowed = (fixture_root, CACHE)
    scope_raw = _read_declared(plan['scope'], 'fresh Scope', max_bytes=128 * 1024,
        roots=allowed)
    scope = parse_json(scope_raw, 'fresh Scope')
    _keys(scope, SCOPE_FIELDS, 'fresh Scope')
    if scope.get('schema') != SCOPE_SCHEMA or scope.get('scope_token') != token or \
            scope.get('fixture_root') != str(fixture_root) or \
            scope.get('fixture_label') != plan['fixture_label']:
        raise PlanError('fresh Scope does not bind the exact fixture and token')
    target = boot['plan']['target']
    fixed = {'revision': target['core_commit'], 'hub_image': target['hub_image_id'],
        'interop_image': target['interop_image_id'],
        'contract_package_sha256': target['contract_archive_sha256'],
        'catalog_sha256': target['catalog_sha256'],
        'source_fingerprint': target['source_fingerprint']}
    if scope.get('fixed') != fixed:
        raise PlanError('fresh Scope fixed delivery fields differ from the six pinned values')
    if type(scope.get('max_signature_requests')) is not int or scope['max_signature_requests'] != 6:
        raise PlanError('fresh Scope does not carry the exact six-request limit')
    scope_ready = None
    for name in ('ready', 'owned_manifest'):
        item = scope.get(name)
        _keys(item, {'path', 'sha256'}, 'Scope ' + name)
        _sha(item['sha256'], 'Scope ' + name + ' SHA-256')
        if not _is_under(Path(item['path']), fixture_root):
            raise PlanError('Scope ' + name + ' must be inside the exact fixture root')
        raw, _digest = _read_file(item['path'], item['sha256'], label='Scope ' + name,
            max_bytes=128 * 1024, roots=(fixture_root,))
        if name == 'ready':
            scope_ready = parse_json(raw, 'Scope aggregate READY')
    for digest in ('key_manifest_digest',):
        _sha(scope.get(digest), 'Scope ' + digest)
    _sha(scope.get('link', {}).get('contract_digest'), 'Scope Link contract digest')
    scope_deadline = _utc(scope.get('coordination_deadline'), 'Scope deadline')
    go_raw = _read_declared(plan['go'], 'fresh Root GO', max_bytes=128 * 1024,
        roots=allowed)
    go = parse_json(go_raw, 'fresh Root GO')
    _keys(go, GO_FIELDS, 'Root GO')
    if go.get('schema') != GO_SCHEMA or go.get('scope_token') != token or \
            go.get('scope_path') != plan['scope']['path'] or \
            go.get('scope_sha256') != plan['scope']['sha256'] or \
            go.get('approved') is not True or type(go.get('max_requests')) is not int or \
            go['max_requests'] != 6 or go.get('root_thread_id') != ROOT_THREAD_ID or \
            not isinstance(go.get('approval_id'), str) or re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', go['approval_id']) is None:
        raise PlanError('Root GO does not match the exact six-request fresh Scope')
    now = time.time()
    approved = _utc(go.get('approved_at'), 'Root GO approval time')
    expires = _utc(go.get('expires_at'), 'Root GO expiry')
    idle = _utc(boot['plan']['idle_deadline'], 'bootstrap idle deadline')
    stop = _utc(plan['business_stop_at_utc'], 'business stop deadline')
    if approved > now or now >= expires or expires > scope_deadline or \
            scope_deadline > idle or stop > scope_deadline or stop > expires or \
            stop > idle or now >= stop:
        raise PlanError('Root GO, Scope, business stop, and idle deadlines are not a valid bounded chain')
    if stop - now > 1200:
        raise PlanError('business stop exceeds the absolute twenty-minute bound')
    _read_declared(plan['delivery_pins'], 'fresh Root delivery pins', max_bytes=256 * 1024,
        roots=allowed)
    _read_declared(plan['delivery_metadata'], 'fresh delivery metadata', max_bytes=256 * 1024,
        roots=allowed, modes=(0o600, 0o644))
    root_plan_refs = plan['source_root_plan_refs']
    if not isinstance(root_plan_refs, list) or not root_plan_refs:
        raise PlanError('business plan requires individually pinned fresh Root source-plan files')
    root_plan_paths = set()
    for ref in root_plan_refs:
        if ref.get('path') in root_plan_paths:
            raise PlanError('business plan repeats a source Root plan reference')
        root_plan_paths.add(ref.get('path'))
        _read_declared(ref, 'fresh Root source-plan file', max_bytes=256 * 1024,
            roots=allowed, modes=(0o600, 0o644))
    refs = plan['topology_refs']
    _keys(refs, TOPOLOGY_NAMES, 'Root topology references')
    for name, ref in refs.items():
        _verify_topology_reference(name, ref, fixture_root)
    _bind_aggregate_ready(scope_ready, scope, refs, fixture_root)
    return {'scope': scope, 'go': go, 'scope_deadline': scope_deadline,
        'go_expires': expires, 'business_stop': stop}


def validate_business_document(plan, boot_plan, boot_sha, boot_receipt, expected_container=None):
    _keys(plan, {'schema', 'bootstrap_plan_sha256', 'container_id', 'boot_receipt_sha256',
        'fixture_root', 'fixture_label', 'scope_token', 'scope', 'go', 'delivery_pins',
        'delivery_metadata', 'source_root_plan_refs', 'topology_refs', 'source_refs', 'carrier_tag',
        'declared_flow_order', 'business_stop_at_utc', 'commands'}, 'business plan')
    if plan['schema'] != BUSINESS_PLAN_SCHEMA:
        raise PlanError('unsupported business plan schema')
    if not isinstance(plan['container_id'], str) or HEX64.fullmatch(plan['container_id']) is None or \
            (expected_container is not None and plan['container_id'] != expected_container):
        raise PlanError('business plan container ID differs from the observed emulator')
    _sha(plan['boot_receipt_sha256'], 'BOOT receipt SHA-256')
    if plan['declared_flow_order'] != DECLARED_FLOW_ORDER:
        raise PlanError('business flow order differs from the six-phase bounded contract')
    if not isinstance(plan['carrier_tag'], str) or re.fullmatch(r'[A-Za-z0-9_-]{1,80}',
            plan['carrier_tag']) is None:
        raise PlanError('carrier tag is invalid')
    roles = _source_refs(plan['source_refs'], {'bind', 'carrier', 'hot_preflight', 'flow'},
        'business plan')
    for role in ('runtime_consumer', 'stop_runner'):
        if role not in roles:
            refs = boot_plan['source_refs']
            match = next((r for r in refs.values() if r['role'] == role), None)
            if match is None:
                raise PlanError('business plan is missing a reusable bootstrap source')
    commands = plan['commands']
    _keys(commands, {'prepare', 'bind', 'carrier', 'hot_preflight', 'flow'}, 'business commands')
    if not isinstance(commands['prepare'], list) or len(commands['prepare']) > 8:
        raise PlanError('prepare commands must be a bounded list of at most eight entries')
    slots = [('bind', commands['bind'], 'bind'), ('carrier', commands['carrier'], 'carrier'),
        ('hot_preflight', commands['hot_preflight'], 'hot_preflight'), ('flow', commands['flow'], 'flow')]
    for command in commands['prepare']:
        _validate_command(command, plan['source_refs'], 'prepare')
    for name, command, role in slots:
        _validate_command(command, plan['source_refs'], role)
    authorization = _scope_go(plan, {'plan': boot_plan, 'receipt_sha256': boot_receipt[
        'receipt_sha256'], 'container_id': boot_receipt['document']['container_id']}, boot_sha)
    return authorization


def _validate_command(command, refs, required_role):
    _keys(command, {'source_ref', 'args', 'timeout_seconds'}, 'command')
    name = command['source_ref']
    if not isinstance(name, str) or name not in refs:
        raise PlanError('command references an undeclared source')
    if refs[name]['role'] != required_role:
        raise PlanError('command source role does not match its execution slot')
    args = command['args']
    if not isinstance(args, list) or len(args) > 128 or any(
            not isinstance(arg, str) or len(arg) > 4096 or '\x00' in arg or '\n' in arg or '\r' in arg
            for arg in args):
        raise PlanError('command arguments are malformed or exceed their bound')
    for arg in args:
        if arg.split('=', 1)[0].lower() in {'ack', '--ack', '--acknowledge', '--fixture-ack'}:
            raise PlanError('Core fixture ACK commands or arguments are prohibited in this launcher')
        for brace in re.findall(r'\{[^{}]*\}', arg):
            if brace not in ALLOWED_PLACEHOLDERS:
                raise PlanError('command contains an unsupported argument placeholder')
        residue = re.sub(r'\{[^{}]*\}', '', arg)
        if '{' in residue or '}' in residue:
            raise PlanError('command contains a malformed placeholder')
    timeout = command['timeout_seconds']
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or \
            not 1 <= timeout <= 300:
        raise PlanError('command timeout is outside its fixed bound')


def _child_environment():
    env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
    if os.environ.get('HOME'):
        env['HOME'] = os.environ['HOME']
    return env


def _source_for(plan, role):
    found = [ref for ref in plan['source_refs'].values() if ref['role'] == role]
    if len(found) == 1:
        return found[0]
    raise PlanError('required pinned source role is missing: ' + role)


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


class Journal:
    def __init__(self, root):
        self.path = root / 'command-journal.private.jsonl'
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(fd)
        self.sequence = 0
        self.records = []
        self.last_record = None

    def append(self, record):
        raw = canonical(record)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0))
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.records.append(record)
        self.last_record = record

    def next_output(self, label):
        self.sequence += 1
        stem = f'{self.sequence:02d}-{label}'
        return self.path.parent / (stem + '.stdout.private'), self.path.parent / (stem + '.stderr.private')


def _utc_now():
    now = dt.datetime.now(dt.timezone.utc)
    fraction = f'{now.microsecond:06d}'.rstrip('0')
    return now.strftime('%Y-%m-%dT%H:%M:%S') + ('.' + fraction if fraction else '') + 'Z'


def _remaining(deadline):
    return deadline.remaining()


def _cmd_argv(command, refs, values):
    source = refs[command['source_ref']]['path']
    argv = [sys.executable, source]
    for arg in command['args']:
        resolved = arg
        for token, value in values.items():
            resolved = resolved.replace(token, str(value))
        if '{' in resolved or '}' in resolved:
            raise PlanError('command has an unresolved placeholder')
        argv.append(resolved)
    return argv


def _run_process(journal, label, argv, timeout, deadline, *, cwd=REPO,
        guard_ticket=True, respond_to_signal=True):
    remaining = _remaining(deadline)
    allowed = min(float(timeout), remaining)
    if allowed <= 0:
        raise PlanError('fixed business deadline reached before ' + label)
    if respond_to_signal and _STOP:
        raise PlanError('supervisor received a termination signal before ' + label)
    if guard_ticket:
        _reject_extra_ticket()
    out_path, err_path = journal.next_output(label)
    started = _utc_now()
    began = time.monotonic()
    timed_out = False
    interrupted = False
    proc = None
    problem = None
    code = 127
    try:
        with out_path.open('xb') as stdout, err_path.open('xb') as stderr:
            try:
                proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, env=_child_environment(), close_fds=True,
                    start_new_session=True)
            except OSError as error:
                problem = PlanError(label + ' could not start; the one attempt is recorded')
                problem.__cause__ = error
            if proc is not None:
                wait_end = time.monotonic() + allowed
                while proc.poll() is None:
                    try:
                        if guard_ticket:
                            _reject_extra_ticket()
                        if respond_to_signal and _STOP:
                            raise PlanError('supervisor received a termination signal')
                    except BaseException as error:
                        problem = error
                        interrupted = True
                        _terminate_owned(proc, 5.0)
                        break
                    left = min(wait_end - time.monotonic(), deadline.remaining())
                    if left <= 0:
                        timed_out = True
                        _terminate_owned(proc, 5.0)
                        break
                    try:
                        proc.wait(timeout=min(0.2, left))
                    except subprocess.TimeoutExpired:
                        continue
                code = proc.returncode if proc.returncode is not None else 124
    except BaseException as error:
        if problem is None:
            problem = error
        if proc is not None and proc.poll() is None:
            timed_out = True
            _terminate_owned(proc, 5.0)
        code = proc.returncode if proc is not None and proc.returncode is not None else 124
    ended = _utc_now()
    duration = time.monotonic() - began
    out_sha, out_size = _hash_file(out_path)
    err_sha, err_size = _hash_file(err_path)
    journal.append({'sequence': journal.sequence, 'label': label, 'argv': argv,
        'pid': None if proc is None else proc.pid,
        'started_at_utc': started, 'ended_at_utc': ended, 'duration_seconds': duration,
        'timeout_seconds': allowed, 'fixed_deadline_utc': deadline.wall_text, 'timed_out': timed_out,
        'interrupted': interrupted,
        'exit_code': code, 'stdout_path': str(out_path), 'stdout_sha256': out_sha,
        'stdout_bytes': out_size, 'stderr_path': str(err_path), 'stderr_sha256': err_sha,
        'stderr_bytes': err_size})
    if problem is not None:
        raise problem
    if timed_out:
        raise PlanError(label + ' timed out; no retry was made')
    if code != 0:
        raise PlanError(label + ' exited nonzero; no retry was made')
    raw = out_path.read_bytes()
    return raw


def _hash_file(path):
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            size += len(block)
            if size > 16 * 1024 * 1024:
                raise PlanError('private command output exceeds the 16 MiB bound')
            digest.update(block)
    return digest.hexdigest(), size


def _terminate_owned(proc, wait_seconds):
    if proc.poll() is not None:
        return proc.returncode
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return proc.wait(timeout=wait_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return proc.wait(timeout=5)


def _parse_one_json_line(raw, label):
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1 or len(raw) > 4096:
        raise PlanError(label + ' must emit exactly one bounded JSON line')
    return parse_json(raw[:-1], label)


def validate_boot_wrapper(raw, plan, launcher_pid):
    wrapper = _parse_one_json_line(raw, 'BOOT wrapper')
    _keys(wrapper, {'result', 'receipt_path', 'receipt_sha256'}, 'BOOT wrapper')
    _sha(wrapper['receipt_sha256'], 'BOOT receipt SHA-256')
    expected = str(Path(plan['android']['evidence_root']) / 'launcher-boot.redacted.json')
    if wrapper['result'] != 'BOOT_READY' or wrapper['receipt_path'] != expected:
        raise PlanError('bootstrap helper emitted an unexpected BOOT wrapper')
    receipt_raw, digest = _read_file(wrapper['receipt_path'], wrapper['receipt_sha256'],
        label='canonical BOOT receipt', max_bytes=32 * 1024)
    doc = parse_json(receipt_raw, 'BOOT receipt')
    fields = {'schema', 'result', 'run_id', 'evidence_root', 'container', 'container_id',
        'image_id', 'network', 'app_sha256', 'test_sha256', 'runtime_properties',
        'ready_observed_at_utc', 'idle_deadline', 'supervisor_pid',
        'cold_boot_elapsed_seconds', 'supervision', 'business'}
    _keys(doc, fields, 'BOOT receipt')
    if canonical(doc) != receipt_raw:
        raise PlanError('BOOT receipt bytes are not canonical JSON')
    android = plan['android']
    expected_container = 'cicada-' + android['run_id']
    if doc['schema'] != BOOT_SCHEMA or doc['result'] != 'BOOT_READY' or \
            doc['run_id'] != android['run_id'] or doc['evidence_root'] != android['evidence_root'] or \
            doc['container'] != expected_container or not isinstance(doc['container_id'], str) or \
            HEX64.fullmatch(doc['container_id']) is None or doc['image_id'] != EMULATOR_IMAGE or \
            doc['network'] != 'none' or doc['app_sha256'] != APK_HASHES['app'] or \
            doc['test_sha256'] != APK_HASHES['test'] or doc['runtime_properties'] != EXPECTED_RUNTIME or \
            doc['idle_deadline'] != plan['idle_deadline'] or type(doc['supervisor_pid']) is not int or \
            doc['supervisor_pid'] != launcher_pid or doc['supervision'] != 'LAUNCHER_ONLY' or \
            doc['business'] != 'NOT_RUN':
        raise PlanError('BOOT receipt does not match the approved fixed bootstrap')
    _utc(doc['ready_observed_at_utc'], 'BOOT READY time')
    elapsed = doc['cold_boot_elapsed_seconds']
    if type(elapsed) not in (int, float) or isinstance(elapsed, bool) or not 0 <= elapsed <= 90:
        raise PlanError('BOOT cold-start duration is outside its bound')
    readiness_path = str(Path(doc['evidence_root']) / 'emulator-readiness.redacted.json')
    readiness_raw, readiness_sha = _read_file(readiness_path,
        label='canonical emulator readiness receipt', max_bytes=16 * 1024)
    readiness = parse_json(readiness_raw, 'emulator readiness receipt')
    _keys(readiness, {'container_id', 'marker', 'observed_at_utc', 'result'},
        'emulator readiness receipt')
    if canonical(readiness) != readiness_raw or readiness.get('result') != 'READY' or \
            readiness.get('container_id') != doc['container_id'] or \
            readiness.get('marker') != {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'} or \
            readiness.get('observed_at_utc') != doc['ready_observed_at_utc']:
        raise PlanError('emulator readiness receipt does not bind the canonical BOOT receipt')
    return {'document': doc, 'receipt_sha256': digest, 'readiness_sha256': readiness_sha,
        'path': expected, 'container_id': doc['container_id']}


def parse_carrier_ready(raw, *, tag, host_pid):
    event = _parse_one_json_line(raw, 'carrier READY event')
    _keys(event, {'result', 'tag', 'host_pid', 'carrier_pid', 'proxy_pid', 'fault',
        'allowed_route_count'}, 'carrier READY event')
    if event['result'] != 'READY' or event['tag'] != tag or type(event['host_pid']) is not int or \
            event['host_pid'] != host_pid or type(event['carrier_pid']) is not int or \
            event['carrier_pid'] <= 0 or event['proxy_pid'] is not None or event['fault'] != 'none' or \
            type(event['allowed_route_count']) is not int or event['allowed_route_count'] != 5:
        raise PlanError('carrier READY event does not match its owned host, tag, and five-route scope')
    return event


def validate_hot_preflight(raw, *, boot, ready, tag):
    result = _parse_one_json_line(raw, 'carrier hot preflight')
    _keys(result, {'result', 'container_id', 'host_pid', 'carrier_pid', 'tag', 'fault',
        'allowed_route_count', 'transaction_count', 'marker_sha256', 'log_sha256',
        'android_preflight'}, 'carrier hot preflight')
    if result.get('result') != 'PASS' or result.get('container_id') != boot['container_id'] or \
            result.get('host_pid') != ready['host_pid'] or result.get('carrier_pid') != ready['carrier_pid'] or \
            result.get('tag') != tag or result.get('fault') != 'none' or \
            type(result.get('allowed_route_count')) is not int or result['allowed_route_count'] != 5 or \
            type(result.get('transaction_count')) is not int or result['transaction_count'] != 0 or \
            result.get('android_preflight') != 'ANDROID_BOOTSTRAP_CHECK_PASS':
        raise PlanError('carrier hot check did not prove the same live zero-transaction carrier and Android preflight')
    _sha(result['marker_sha256'], 'carrier marker SHA-256')
    _sha(result['log_sha256'], 'carrier log SHA-256')
    return result


def _wait_ticket(deadline):
    global _TICKET_FD
    fd = sys.stdin.fileno()
    try:
        os.set_blocking(fd, False)
    except OSError as error:
        raise PlanError('trusted business ticket stdin is unavailable') from error
    buffer = bytearray()
    while _remaining(deadline) > 0 and not _STOP:
        readable, _, _ = select.select([fd], [], [], min(0.5, max(0, _remaining(deadline))))
        if not readable:
            continue
        chunk = os.read(fd, 4097 - len(buffer))
        if not chunk:
            raise PlanError('trusted caller closed stdin before delivering one ticket')
        buffer.extend(chunk)
        if len(buffer) > 4096:
            raise PlanError('business ticket line exceeds 4 KiB')
        if b'\n' in buffer:
            if buffer.count(b'\n') != 1 or not buffer.endswith(b'\n'):
                raise PlanError('stdin must contain exactly one business ticket line')
            ticket = parse_json(bytes(buffer[:-1]), 'business ticket')
            _TICKET_FD = fd
            return ticket
    raise PlanError('fixed idle deadline arrived before the single business ticket')


def _reject_extra_ticket():
    global _TICKET_FD
    if _TICKET_FD is None:
        return
    readable, _, _ = select.select([_TICKET_FD], [], [], 0)
    if not readable:
        return
    extra = os.read(_TICKET_FD, 4097)
    if not extra:
        _TICKET_FD = None
        return
    raise PlanError('a second or trailing business ticket arrived after the one-use ticket')


def _signal(_signum, _frame):
    global _STOP
    _STOP = True


def _create_launcher_evidence(plan, plan_sha):
    root = Path(plan['launcher_evidence_root'])
    if root.exists() or root.is_symlink():
        raise PlanError('single-use launcher evidence path already exists')
    parent = root.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.resolve(strict=True) != parent:
        raise PlanError('launcher evidence parent must not use a symlink')
    root.mkdir(mode=0o700)
    marker = {'schema': 'cicada.client-v164-bounded-launcher-use.v1',
        'bootstrap_plan_sha256': plan_sha, 'run_id': plan['android']['run_id'],
        'started_at_utc': _utc_now(), 'launcher_pid': os.getpid()}
    _write_new(root / 'single-use.private.json', canonical(marker))
    return root


def _run_bootstrap_preflight(journal, plan, boot, deadline):
    ref = _source_for(plan, 'runtime_consumer')
    argv = [sys.executable, ref['path'], boot['document']['evidence_root'], 'bootstrap-preflight']
    raw = _run_process(journal, 'bootstrap-preflight', argv,
        plan['timeouts']['command_seconds'], deadline)
    result = _parse_one_json_line(raw, 'strict bootstrap preflight')
    if result.get('result') != 'ANDROID_BOOTSTRAP_CHECK_PASS' or \
            result.get('run_id') != boot['document']['run_id'] or \
            result.get('container_id') != boot['container_id'] or \
            result.get('image_id') != EMULATOR_IMAGE or result.get('network') != 'none' or \
            result.get('runtime_properties') != EXPECTED_RUNTIME or \
            result.get('hub') != 'NOT_CHECKED' or result.get('root_delivery') != 'NOT_CHECKED':
        raise PlanError('strict repository-consumer bootstrap preflight did not pass exactly')
    return result


def _command_values(boot_plan, boot, plan_sha, business=None, ready=None):
    values = {
        '{EVIDENCE_ROOT}': boot_plan['android']['evidence_root'],
        '{CLIENT_COMMIT}': boot_plan['client_commit'],
        '{READINESS_SHA256}': boot['readiness_sha256'],
        '{CONTAINER_ID}': boot['container_id'],
        '{BOOT_RECEIPT_SHA256}': boot['receipt_sha256'],
        '{BOOT_PLAN_SHA256}': plan_sha,
    }
    if business is not None:
        values.update({
            '{FIXTURE_ROOT}': business['fixture_root'],
            '{SCOPE_SHA256}': business['scope']['sha256'],
            '{ROOT_GO_SHA256}': business['go']['sha256'],
            '{DELIVERY_PINS}': business['delivery_pins']['path'],
            '{DELIVERY_PINS_SHA256}': business['delivery_pins']['sha256'],
            '{DELIVERY_METADATA}': business['delivery_metadata']['path'],
            '{DELIVERY_METADATA_SHA256}': business['delivery_metadata']['sha256'],
            '{CARRIER_TAG}': business['carrier_tag'],
            '{FLOW_ORDER_JSON}': json.dumps(business['declared_flow_order'], separators=(',', ':')),
        })
    if ready is not None:
        values.update({'{CARRIER_HOST_PID}': ready['host_pid'],
            '{CARRIER_PID}': ready['carrier_pid']})
    return values


def _run_declared(journal, business, name, boot_plan, boot, plan_sha, deadline, ready=None):
    command = business['commands'][name]
    argv = _cmd_argv(command, business['source_refs'],
        _command_values(boot_plan, boot, plan_sha, business, ready))
    return _run_process(journal, name, argv, command['timeout_seconds'], deadline)


def _start_carrier(journal, business, boot_plan, boot, plan_sha, deadline):
    command = business['commands']['carrier']
    argv = _cmd_argv(command, business['source_refs'],
        _command_values(boot_plan, boot, plan_sha, business))
    remaining = _remaining(deadline)
    runtime_timeout = min(float(command['timeout_seconds']), remaining)
    ready_timeout = min(float(command['timeout_seconds']),
        float(boot_plan['timeouts']['carrier_ready_seconds']), remaining)
    if ready_timeout <= 0 or _STOP:
        raise PlanError('fixed business deadline arrived before carrier startup')
    _reject_extra_ticket()
    out_path, err_path = journal.next_output('carrier')
    out = out_path.open('xb')
    err = err_path.open('xb')
    started = _utc_now()
    began = time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=err, env=_child_environment(), close_fds=True, start_new_session=True, bufsize=0)
    except OSError as error:
        out.close()
        err.close()
        out_sha, out_size = _hash_file(out_path)
        err_sha, err_size = _hash_file(err_path)
        journal.append({'sequence': journal.sequence, 'label': 'carrier', 'argv': argv,
            'pid': None, 'started_at_utc': started, 'ended_at_utc': _utc_now(),
            'duration_seconds': time.monotonic() - began, 'timeout_seconds': runtime_timeout,
            'ready_timeout_seconds': ready_timeout, 'timed_out': False, 'exit_code': 127,
            'stdout_path': str(out_path), 'stdout_sha256': out_sha, 'stdout_bytes': out_size,
            'stderr_path': str(err_path), 'stderr_sha256': err_sha, 'stderr_bytes': err_size})
        raise PlanError('carrier process could not start; no retry was made') from error
    ready_raw = bytearray()
    selector_fd = proc.stdout.fileno()
    os.set_blocking(selector_fd, False)
    details = (argv, started, began, runtime_timeout, ready_timeout, out_path, err_path, False)
    state = (proc, out, err, None, details)
    try:
        end = time.monotonic() + ready_timeout
        while time.monotonic() < end and not _STOP:
            _reject_extra_ticket()
            readable, _, _ = select.select([selector_fd], [], [], min(0.2, max(0, end-time.monotonic())))
            if not readable:
                if proc.poll() is not None:
                    break
                continue
            chunk = os.read(selector_fd, 4097 - len(ready_raw))
            if not chunk:
                break
            ready_raw.extend(chunk)
            out.write(chunk)
            out.flush()
            if b'\n' in ready_raw:
                break
            if len(ready_raw) > 4096:
                break
        ready = parse_carrier_ready(bytes(ready_raw), tag=business['carrier_tag'], host_pid=proc.pid)
        readable, _, _ = select.select([selector_fd], [], [], 0)
        if readable and os.read(selector_fd, 4097):
            raise PlanError('carrier wrote unexpected stdout after its first READY event')
        state = (proc, out, err, ready,
            (argv, started, began, runtime_timeout, ready_timeout, out_path, err_path, False))
        return state
    except BaseException:
        timed_out = not ready_raw.endswith(b'\n')
        try:
            _finish_carrier(journal, (proc, out, err, None,
                (argv, started, began, runtime_timeout, ready_timeout, out_path, err_path, timed_out)))
        except BaseException:
            pass
        raise


def _finish_carrier(journal, carrier_state, *, terminate=True):
    if carrier_state is None:
        return 0
    proc, out, err, _ready, details = carrier_state
    argv, started, began, runtime_timeout, ready_timeout, out_path, err_path, timed_out = details
    if terminate and proc.poll() is None:
        _terminate_owned(proc, min(5, float(runtime_timeout)))
    if proc.poll() is None:
        _terminate_owned(proc, 5.0)
    code = proc.wait()
    try:
        if proc.stdout:
            while True:
                readable, _, _ = select.select([proc.stdout], [], [], 0)
                if not readable:
                    break
                try:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                out.write(chunk)
        out.flush()
        out.close()
        err.flush()
        err.close()
    except OSError:
        pass
    out_sha, out_size = _hash_file(out_path)
    err_sha, err_size = _hash_file(err_path)
    carrier_sequence = int(out_path.name.split('-', 1)[0])
    journal.append({'sequence': carrier_sequence, 'label': 'carrier', 'argv': argv,
        'pid': proc.pid, 'started_at_utc': started, 'ended_at_utc': _utc_now(),
        'duration_seconds': time.monotonic() - began, 'timeout_seconds': runtime_timeout,
        'ready_timeout_seconds': ready_timeout, 'timed_out': timed_out,
        'exit_code': code, 'stdout_path': str(out_path),
        'stdout_sha256': out_sha, 'stdout_bytes': out_size, 'stderr_path': str(err_path),
        'stderr_sha256': err_sha, 'stderr_bytes': err_size, 'ready_host_pid': proc.pid,
        'ready_observed': _ready is not None})
    return code


def _cleanup_emulator(journal, boot_plan):
    evidence = Path(boot_plan['android']['evidence_root'])
    marker = evidence / 'android-driver.json'
    if not marker.exists() and not marker.is_symlink():
        return 'NOT_PRESENT'
    try:
        raw, _ = _read_file(str(marker), label='owned emulator marker', max_bytes=16 * 1024)
        state = parse_json(raw, 'owned emulator marker')
    except PlanError:
        return 'OWNERSHIP_UNVERIFIED'
    run_id = boot_plan['android']['run_id']
    if state.get('run_id') != run_id or state.get('container') != 'cicada-' + run_id or \
            state.get('image_id') != EMULATOR_IMAGE or state.get('network') != 'none':
        return 'OWNERSHIP_UNVERIFIED'
    ref = _source_for(boot_plan, 'stop_runner')
    argv = [sys.executable, ref['path'], str(evidence), 'stop']
    try:
        cleanup_limit = Deadline.after(boot_plan['timeouts']['cleanup_seconds'], 'owned emulator cleanup')
        raw = _run_process(journal, 'emulator-stop', argv,
            boot_plan['timeouts']['cleanup_seconds'], cleanup_limit,
            guard_ticket=False, respond_to_signal=False)
        result = _parse_one_json_line(raw, 'emulator stop runner')
        if result.get('result') != 'PASS' or result.get('owned_emulator_removed') is not True:
            return 'FAIL'
        return 'PASS'
    except PlanError:
        return 'FAIL'


def execute(boot_plan, boot_sha):
    global _STOP, _TICKET_FD
    _STOP = False
    _TICKET_FD = None
    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)
    root = _create_launcher_evidence(boot_plan, boot_sha)
    journal = Journal(root)
    journal.append({'event': 'policy', 'core_ack': 'CORE_ACK_NOT_SENT'})
    carrier_state = None
    boot = None
    business = None
    business_sha = None
    failure = None
    flow_attempted = False
    carrier_attempted = False
    flow_exit_code = None
    cleanup = {'flow': 'NOT_STARTED', 'carrier': 'NOT_STARTED', 'emulator': 'NOT_PRESENT'}
    idle_deadline = Deadline.from_utc(boot_plan['idle_deadline'])
    try:
        android = boot_plan['android']
        if (CACHE / android['run_id']).exists() or (CACHE / android['run_id']).is_symlink():
            raise PlanError('Android run cache path already exists; single-use boot refused')
        boot_ref = _source_for(boot_plan, 'boot')
        boot_argv = [sys.executable, boot_ref['path'], '--run-id', android['run_id'],
            '--evidence-root', android['evidence_root'], '--app-apk', android['app']['path'],
            '--test-apk', android['test']['path'], '--idle-deadline', boot_plan['idle_deadline'],
            '--supervisor-pid', str(os.getpid()), '--execute']
        boot_raw = _run_process(journal, 'bootstrap', boot_argv,
            boot_plan['timeouts']['boot_seconds'], idle_deadline)
        boot = validate_boot_wrapper(boot_raw, boot_plan, os.getpid())
        boot['plan'] = boot_plan
        _run_bootstrap_preflight(journal, boot_plan, boot, idle_deadline)
        ready_event = {'event': 'READY', 'run_id': android['run_id'],
            'container_id': boot['container_id'], 'boot_receipt_sha256': boot['receipt_sha256'],
            'bootstrap_plan_sha256': boot_sha, 'launcher_pid': os.getpid(),
            'idle_deadline': boot_plan['idle_deadline']}
        sys.stdout.buffer.write(canonical(ready_event))
        sys.stdout.buffer.flush()
        ticket = _wait_ticket(idle_deadline)
        _keys(ticket, {'plan_path', 'plan_sha256'}, 'business ticket')
        business_plan, business_sha = _private_plan(ticket['plan_path'], ticket['plan_sha256'],
            'business plan')
        authorization = validate_business_document(business_plan, boot_plan, boot_sha,
            boot, expected_container=boot['container_id'])
        business = business_plan
        operation_deadline = Deadline.earliest([idle_deadline,
            Deadline.from_utc(business['business_stop_at_utc']),
            Deadline.from_utc(authorization['go']['expires_at']),
            Deadline.from_utc(authorization['scope']['coordination_deadline'])])
        values = _command_values(boot_plan, boot, boot_sha, business)
        for index, command in enumerate(business['commands']['prepare']):
            argv = _cmd_argv(command, business['source_refs'], values)
            _run_process(journal, f'prepare-{index + 1}', argv,
                command['timeout_seconds'], operation_deadline)
        _run_declared(journal, business, 'bind', boot_plan, boot, boot_sha, operation_deadline)
        carrier_attempted = True
        carrier_state = _start_carrier(journal, business, boot_plan, boot, boot_sha, operation_deadline)
        ready = carrier_state[3]
        if carrier_state[0].poll() is not None:
            raise PlanError('owned carrier exited before hot preflight')
        hot_raw = _run_declared(journal, business, 'hot_preflight', boot_plan, boot,
            boot_sha, operation_deadline, ready)
        validate_hot_preflight(hot_raw, boot=boot, ready=ready, tag=business['carrier_tag'])
        if carrier_state[0].poll() is not None:
            raise PlanError('owned carrier exited during hot preflight')
        _reject_extra_ticket()
        if _STOP or operation_deadline.remaining() <= 0:
            raise PlanError('fixed business deadline arrived before the single flow invocation')
        if _remaining(operation_deadline) <= 0:
            raise PlanError('fixed business deadline arrived before the single flow invocation')
        flow_attempted = True
        try:
            _run_declared(journal, business, 'flow', boot_plan, boot, boot_sha,
                operation_deadline, ready)
        except BaseException:
            flow_record = next((record for record in reversed(journal.records)
                if record.get('label') == 'flow'), None)
            flow_exit_code = None if flow_record is None else flow_record.get('exit_code')
            raise
        flow_record = next(record for record in reversed(journal.records) if record.get('label') == 'flow')
        flow_exit_code = flow_record['exit_code']
        if flow_exit_code != 0:
            raise PlanError('single six-phase flow failed or timed out; no retry was made')
    except BaseException as error:
        failure = error
    finally:
        flow_record = next((record for record in reversed(journal.records)
            if record.get('label') == 'flow'), None)
        if flow_attempted and flow_record is not None and flow_record.get('pid') is not None:
            cleanup['flow'] = 'EXITED_AND_WAITED'
        elif flow_attempted:
            cleanup['flow'] = 'START_FAILED_OR_NOT_RUN'
        if carrier_state is not None:
            try:
                carrier_code = _finish_carrier(journal, carrier_state)
                cleanup['carrier'] = 'TERMINATED_AND_WAITED' if carrier_code == 0 else 'FAIL'
                if carrier_code != 0 and failure is None:
                    failure = PlanError('owned carrier shutdown exited nonzero')
            except BaseException:
                cleanup['carrier'] = 'FAIL'
                if failure is None:
                    failure = PlanError('owned carrier shutdown failed')
        elif carrier_attempted:
            cleanup['carrier'] = 'START_FAILED_OR_ALREADY_WAITED'
        try:
            cleanup['emulator'] = _cleanup_emulator(journal, boot_plan)
        except BaseException:
            cleanup['emulator'] = 'FAIL'
        if cleanup['emulator'] in {'FAIL', 'OWNERSHIP_UNVERIFIED'} and failure is None:
            failure = PlanError('owned emulator cleanup failed or ownership could not be verified')
        if flow_record is not None:
            flow_exit_code = flow_record.get('exit_code')
        flow_started = flow_record is not None and flow_record.get('pid') is not None
        if flow_started and (flow_exit_code != 0 or flow_record.get('timed_out') or
                flow_record.get('interrupted')):
            business_result = 'OUTCOME_UNKNOWN_PRESERVE_PENDING'
        elif flow_started and flow_exit_code == 0:
            business_result = 'FLOW_EXITED_ZERO'
        else:
            business_result = 'NOT_RUN'
        terminal = {'schema': 'cicada.client-v164-bounded-launcher-terminal.v1',
            'run_id': boot_plan['android']['run_id'], 'bootstrap_plan_sha256': boot_sha,
            'business_plan_sha256': business_sha,
            'result': 'FAIL' if failure is not None else ('FLOW_EXITED_ZERO' if flow_exit_code == 0 else 'BOOTSTRAP_ONLY'),
            'business': business_result, 'core_ack': 'CORE_ACK_NOT_SENT',
            'cleanup': cleanup, 'finished_at_utc': _utc_now(),
            'failure_type': None if failure is None else type(failure).__name__,
            'failure_message': None if failure is None else str(failure)[:240]}
        try:
            _write_new(root / 'terminal.private.json', canonical(terminal))
        except OSError:
            pass
    if failure is not None:
        raise failure
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-plan', required=True)
    parser.add_argument('--bootstrap-plan-sha256', required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check-plan', action='store_true',
        help='validate pinned plans and sources without booting or creating evidence')
    action.add_argument('--execute', action='store_true',
        help='start one bounded offline bootstrap and wait for one trusted business ticket')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        plan, digest = _private_plan(args.bootstrap_plan, args.bootstrap_plan_sha256,
            'bootstrap plan')
        summary = validate_bootstrap_document(plan, digest)
        if not args.execute:
            print(canonical({'result': 'PLAN_VALID', 'bootstrap_plan_sha256': digest,
                'run_id': summary['run_id'], 'client_commit': summary['client_commit']}).decode(), end='')
            return 0
        return execute(plan, digest)
    except (PlanError, OSError, subprocess.SubprocessError, ValueError) as error:
        print('bounded acceptance stopped: ' + str(error), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
