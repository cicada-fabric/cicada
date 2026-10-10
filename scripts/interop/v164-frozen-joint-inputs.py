#!/usr/bin/env python3
"""Read-only validator for the frozen e2a1908 Core/Client joint interface."""

import base64
import datetime as dt
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
CORE_PREP = Path('/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation')
PARENT_PATH = CORE_PREP / 'joint-parent-v4.py'
ADAPTER_PATH = CORE_PREP / 'joint-adapter-parent-ready-v4.py'
INTERFACE_PATH = CORE_PREP / 'JOINT-PARENT-V4-INTERFACE.NONAUTH.md'
FREEZE_PATH = CORE_PREP / 'JOINT-PARENT-V4-FREEZE.NONAUTH.json'
QA_RECEIPT_PATH = CORE_PREP / 'JOINT-PARENT-V4-FINAL-QA.NONAUTH.json'
QA_RECEIPT_SHA256 = '6e11241b1f429ed2ccd8d0d5195bcf10b6bb5cce7b02d976743b57b7fa724d77'
RECONCILE_PATH = CORE_PREP / 'reconcile-final-compile-format-2/bin/cicada-link-joint-reconcile'
RECONCILE_RECEIPT_PATH = CORE_PREP / 'reconcile-final-compile-format-2/PREPARATION-RESULT.NONAUTH.json'
RECONCILE_SHA256 = '54d8c31b4a2aa5f762173876961b3b04ec680f23576ac1a42f3e9c65dd04d0b3'
RECONCILE_RECEIPT_SHA256 = '96dbd99b2c2f6e9e6310d35432fd10d7214202f92ef0e0c1aa69e3a5e3296b1e'

FROZEN_ARTIFACT_HASHES = {
    'parent_sha256': 'd5320c7698c26696eb8e20d543ad7f9dab377a9500ffcf03ed3fbf7c8ff70600',
    'adapter_sha256': '907d12a63663543542bb58df83d74cec95e054593a6f8d214498cbc41f2860e4',
    'interface_sha256': 'bfbdee608e7d94da42cee16ec38a6f9ce2b14ce1f637886bbf12b7d2a979be06',
    'freeze_sha256': '861624c34369564950a486e07a846e457d31056ce4b5cf7124384aebfa7071f2',
}
FROZEN_PREPARATION_TEST_HASHES = {
    'test_joint_parent_v4_snapshot.py': '9a1f0dfe6603f5a39bea1571f09d067d8e6c872079edaa17c5dccfd3e5e0f559',
}

CORE_REVISION = 'e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59'
HUB_IMAGE_ID = 'sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01'
TEST_IMAGE_ID = 'sha256:73ec018a026a27fb04ec0c651bafa976ebbed71efca87d302d0c7c4c2e59ba6a'
SOURCE_FINGERPRINT = '7a8b99036b32e7d4727ab7011a53fa477854505cabfbdeccb8bc54baed7580d5'
CATALOG_SHA256 = '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'
CONTRACT_REVISION = 'client-hub-v1.6.4'
WIRE_VERSION = 1
RUN_ID = 'v164-e2a1908-joint7-20261010'
ANDROID_BASE_URL = 'http://127.0.0.1:8787'
JOINT_HELPER_SHA256 = 'f9a9ce392d67ab3a2c8451546884dbbc8c78d27a3c409e60e32ac5a3df3254c8'
RECOVERY_HELPER_SHA256 = 'cf995108fa72b9bde1c65261da0bb766961ea7afd6b8d03124e3bc3e921be61b'
HELPER_SOURCE_SHA256 = 'ff72bf85df580f2b6d35274c721d0bdf1c1fe832eb6c195e211045bc52f37cb8'
PREPARATION_RECEIPT_SHA256 = '77877867ee986b1bef429125eefdb98958d671c2b7e0cc25afcab02393619353'

CASES = tuple((operation, mode)
    for operation in ('link.key_grant', 'link.review_policy_grant')
    for mode in ('response-loss', 'processing', 'uncertain', 'legacy'))
HEX64 = re.compile(r'[0-9a-f]{64}')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}')
ROOT_ID = re.compile(r'[A-Za-z0-9_-]{1,96}')
MAX_JSON_BYTES = 64 * 1024

READY_FIELDS = set('schema status fixture_root protocol_scope native_runtime model_calls public_references source hub client_setup_sha256 hub_ready_sha256 reference_manifest_sha256 owned_manifest_sha256 coordination_nonce coordination_deadline coordination_ttl_seconds cleanup_policy'.split())
REFERENCE_NAMES = {
    'client_setup', 'custody_manifest', 'fixture_public', 'helper_binary',
    'helper_provenance', 'helper_source', 'hub_ready', 'reference_manifest', 'runner',
}
REFERENCE_PATHS = {
    'client_setup': 'public/client-setup.json',
    'custody_manifest': 'public/custody.json',
    'fixture_public': 'public/fixture-public.json',
    'helper_binary': 'bin/cicada-link-v164-fixture',
    'helper_provenance': 'evidence/attempt-08/helper-provenance.json',
    'helper_source': 'helper-src/main.go',
    'hub_ready': 'evidence/attempt-08/hub-ready-final.json',
    'reference_manifest': 'public/reference-manifest.json',
    'runner': 'fixture.sh',
}
REFERENCE_MODES = {
    'client_setup': 0o100644,
    'custody_manifest': 0o100600,
    'fixture_public': 0o100600,
    'helper_binary': 0o100755,
    'helper_provenance': 0o100600,
    'helper_source': 0o100600,
    'hub_ready': 0o100600,
    'reference_manifest': 0o100600,
    'runner': 0o100700,
}
REFERENCE_LIMITS = {
    'client_setup': MAX_JSON_BYTES, 'custody_manifest': MAX_JSON_BYTES,
    'fixture_public': MAX_JSON_BYTES, 'helper_binary': 32 * 1024 * 1024,
    'helper_provenance': MAX_JSON_BYTES, 'helper_source': 1024 * 1024,
    'hub_ready': MAX_JSON_BYTES, 'reference_manifest': MAX_JSON_BYTES,
    'runner': 256 * 1024,
}
JSON_REFERENCES = {
    'client_setup', 'custody_manifest', 'fixture_public', 'helper_provenance',
    'hub_ready', 'reference_manifest',
}

CONTROL_FIELDS = {
    'prepare': {'action', 'case'},
    'device': {'action', 'case', 'side', 'manifest_sha256'},
    'proof': {'action', 'case', 'side', 'input_sha256'},
    'proxy': {'action', 'case', 'side'},
    'capture': {'action', 'case', 'capture_sha256'},
    'finish': {'action', 'case', 'result_sha256', 'carrier_sha256'},
}
INPUT_NAMES = {
    'device': '{side}-device-enrollment.json',
    'review': '{side}-review.json',
    'capture': 'capture.json',
    'result': 'result.json',
    'carrier': 'carrier.json',
}
OUTPUT_NAMES = {
    'device-grant': 'signed-proofs/{side}-device-grant.json',
    'link-proof': 'signed-proofs/{side}-link-proof.json',
    'carrier-manifest': 'public/carrier-manifest.json',
    'proxy-ready': 'public/proxy-ready.jsonl',
    'scenario': 'public/recovery-scenario.json',
    'fault-envelope': 'public/fault-envelope.json',
    'fault-control': 'public/fault-control.jsonl',
    'ready': 'public/READY.json',
}
FAULT_CONTROL_REQUIRES_CAPTURE_VERIFIED = True


def _load_pins():
    name = 'v164_frozen_joint_fixture_pins'
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / 'v164-link-fixture-pins.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('fixture metadata validator is unavailable')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_pins = _load_pins()


def _fail(code):
    raise ValueError(code)


def _need(value, code):
    if not value:
        _fail(code)


def _exact(value, fields, code):
    _need(isinstance(value, dict) and set(value) == set(fields), code)


def _sha(value, code='SHA256'):
    _need(isinstance(value, str) and HEX64.fullmatch(value) is not None, code)


def _fingerprint(value, code='FINGERPRINT'):
    _need(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None, code)


def _load_json(path, *, expected_sha256=None, mode=0o600):
    raw, digest, value = _pins._read_file(
        path, expected_sha256=expected_sha256, accepted_modes=(mode,))
    _need(len(raw) <= MAX_JSON_BYTES, 'JSON_SIZE')
    return raw, digest, value


def _hash_regular(path, *, accepted_modes, maximum):
    """Hash a regular public source/binary without retaining or copying it."""
    path = Path(path)
    _need(path.is_absolute() and not path.is_symlink(), 'FILE_PATH')
    try:
        _need(path.resolve(strict=True) == path, 'FILE_ALIAS')
        before = path.lstat()
        _need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) in accepted_modes and
              before.st_uid == os.getuid() and before.st_nlink == 1 and
              0 < before.st_size <= maximum, 'FILE_SCOPE')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        digest = hashlib.sha256()
        total = 0
        try:
            opened = os.fstat(fd)
            _need((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                  (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), 'FILE_CHANGED')
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                _need(total <= maximum, 'FILE_SIZE')
                digest.update(chunk)
            after = os.fstat(fd)
            _need(total == opened.st_size and
                  (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'FILE_CHANGED')
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError('FILE_UNAVAILABLE') from error
    return total, digest.hexdigest()


def verify_auxiliary():
    """Hash the compiled reconciliation helper and its offline receipt; never execute it."""
    _need(RECONCILE_PATH.parts[-3:] == (
        'reconcile-final-compile-format-2', 'bin', 'cicada-link-joint-reconcile') and
        RECONCILE_RECEIPT_PATH.parts[-2:] == (
            'reconcile-final-compile-format-2', 'PREPARATION-RESULT.NONAUTH.json') and
        RECONCILE_PATH.parent.parent == RECONCILE_RECEIPT_PATH.parent, 'RECONCILE_PATH')
    binary_size, binary_sha = _hash_regular(
        RECONCILE_PATH, accepted_modes=(0o755,), maximum=32 * 1024 * 1024)
    _need(binary_sha == RECONCILE_SHA256, 'RECONCILE_PIN')
    receipt_size, receipt_sha = _hash_regular(
        RECONCILE_RECEIPT_PATH, accepted_modes=(0o600,), maximum=MAX_JSON_BYTES)
    _, parsed_sha, receipt = _load_json(
        RECONCILE_RECEIPT_PATH, expected_sha256=RECONCILE_RECEIPT_SHA256)
    _need(receipt_size > 0 and receipt_sha == parsed_sha == RECONCILE_RECEIPT_SHA256,
          'RECONCILE_RECEIPT_PIN')
    _need(receipt.get('status') == 'PASS_OFFLINE_COMPILE_ONLY' and
          receipt.get('scope') == 'OFFLINE_COMPILE_ONLY' and
          receipt.get('runtime') == 'NOT_RUN' and receipt.get('android') == 'NOT_RUN' and
          receipt.get('cleanup') == 'CONFIRMED' and
          receipt.get('source_before_after_exact') is True and
          receipt.get('six_residents_exact') is True and
          type(receipt.get('compile_exit_code')) is int and receipt['compile_exit_code'] == 0 and
          type(receipt.get('model_calls')) is int and receipt['model_calls'] == 0,
          'RECONCILE_RECEIPT_SCOPE')
    source = receipt.get('compiled_source')
    _exact(source, {'dirty', 'image', 'revision', 'source_fingerprint'}, 'RECONCILE_SOURCE')
    _need(source['dirty'] is False and source['image'] == TEST_IMAGE_ID and
          source['revision'] == CORE_REVISION and
          source['source_fingerprint'] == SOURCE_FINGERPRINT, 'RECONCILE_SOURCE')
    binaries = receipt.get('binaries')
    _need(isinstance(binaries, dict), 'RECONCILE_BINARY_RECEIPT')
    binary = binaries.get('cicada-link-joint-reconcile')
    _exact(binary, {'bytes', 'mode', 'sha256'}, 'RECONCILE_BINARY_RECEIPT')
    _need(type(binary['bytes']) is int and binary['bytes'] == binary_size and
          binary['mode'] == '0o755' and binary['sha256'] == binary_sha,
          'RECONCILE_BINARY_RECEIPT')
    artifacts = receipt.get('artifact_sha256')
    _need(isinstance(artifacts, dict) and
          artifacts.get('bin/cicada-link-joint-reconcile') == binary_sha,
          'RECONCILE_BINARY_RECEIPT')
    return {'reconcile_sha256': binary_sha, 'reconcile_receipt_sha256': receipt_sha}


def verify_artifacts():
    """Pin the Parent delivery and reconciliation auxiliary; execute no Core code."""
    _need(PARENT_PATH.name == 'joint-parent-v4.py', 'PARENT_PATH')
    _need(ADAPTER_PATH.name == 'joint-adapter-parent-ready-v4.py', 'ADAPTER_PATH')
    _need(INTERFACE_PATH.name == 'JOINT-PARENT-V4-INTERFACE.NONAUTH.md', 'INTERFACE_PATH')
    _need(FREEZE_PATH.name == 'JOINT-PARENT-V4-FREEZE.NONAUTH.json', 'FREEZE_PATH')
    _need(QA_RECEIPT_PATH.name == 'JOINT-PARENT-V4-FINAL-QA.NONAUTH.json' and
          QA_RECEIPT_PATH.parent == FREEZE_PATH.parent, 'QA_RECEIPT_PATH')
    parent_size, parent_sha = _hash_regular(
        PARENT_PATH, accepted_modes=(0o600,), maximum=2 * 1024 * 1024)
    interface_size, interface_sha = _hash_regular(
        INTERFACE_PATH, accepted_modes=(0o600,), maximum=256 * 1024)
    adapter_size, adapter_sha = _hash_regular(
        ADAPTER_PATH, accepted_modes=(0o600,), maximum=2 * 1024 * 1024)
    _need(parent_size > 0 and parent_sha == FROZEN_ARTIFACT_HASHES['parent_sha256'],
          'PARENT_PIN')
    _need(interface_size > 0 and interface_sha == FROZEN_ARTIFACT_HASHES['interface_sha256'],
          'INTERFACE_PIN')
    _need(adapter_size > 0 and adapter_sha == FROZEN_ARTIFACT_HASHES['adapter_sha256'],
          'ADAPTER_PIN')
    freeze_raw, freeze_sha, freeze = _pins._read_file(
        FREEZE_PATH, accepted_modes=(0o600,))
    _need(0 < len(freeze_raw) <= MAX_JSON_BYTES and
          freeze_sha == FROZEN_ARTIFACT_HASHES['freeze_sha256'], 'FREEZE_PIN')
    expected_sources = {
        'JOINT-PARENT-V4-INTERFACE.NONAUTH.md': interface_sha,
        'joint-adapter-parent-ready-v4.py': adapter_sha,
        'joint-parent-v4.py': parent_sha,
        **FROZEN_PREPARATION_TEST_HASHES,
    }
    expected_files = {str(FREEZE_PATH.parent / name): sha
                      for name, sha in expected_sources.items()}
    expected_files.update({
        str(QA_RECEIPT_PATH): QA_RECEIPT_SHA256,
        str(FREEZE_PATH.parent / 'JOINT-PARENT-V4-SNAPSHOT-QA.private.log'):
            '4f51e267721b3c0a7cb3354c57d679be0ac4233e1f93a1692d285490843a9382',
        str(FREEZE_PATH.parent / 'JOINT-PARENT-V4-SNAPSHOT.patch'):
            'c146f3c6af8eec2f17764e691fb4f7acc56e0b426f3c95471ecbacc924b9f631',
    })
    _, _, qa = _load_json(QA_RECEIPT_PATH, expected_sha256=QA_RECEIPT_SHA256)
    _exact(qa, {'AST', 'Runtime_Docker_model_calls', 'argv', 'elapsed_seconds',
                'exit_code', 'fail', 'files', 'previous_QA_receipt_sha256',
                'raw_output_path', 'raw_output_sha256', 'skip', 'status',
                'subtests', 'tests'}, 'QA_RECEIPT_SCOPE')
    counts = {'exit_code': 0, 'fail': 0, 'skip': 0, 'subtests': 2, 'tests': 3}
    _need(qa['status'] == 'PASS_OFFLINE_SNAPSHOT_ONLY' and qa['AST'] == 'PASS' and
          type(qa['Runtime_Docker_model_calls']) is int and
          qa['Runtime_Docker_model_calls'] == 0 and qa['files'] == expected_sources and
          all(type(qa[key]) is int and qa[key] == value for key, value in counts.items()) and
          type(qa['elapsed_seconds']) in (int, float) and
          0 <= qa['elapsed_seconds'] < 10 and
          qa['raw_output_path'] == str(FREEZE_PATH.parent / 'JOINT-PARENT-V4-SNAPSHOT-QA.private.log') and
          qa['raw_output_sha256'] == expected_files[qa['raw_output_path']],
          'QA_RECEIPT_SCOPE')
    _need(freeze.get('status') == 'SOURCE_FROZEN_OFFLINE_PASS' and
          freeze.get('online') == 'NOT_GO' and freeze.get('files') == expected_files and
          freeze.get('operator_sources') == {
              PARENT_PATH.name: parent_sha, ADAPTER_PATH.name: adapter_sha} and
          freeze.get('event_count') == 82 and freeze.get('callback_fields') == 25 and
          freeze.get('policy_fields') == 11 and freeze.get('outer_seconds') == 3600 and
          type(freeze.get('runtime_effects')) is int and freeze['runtime_effects'] == 0 and
          freeze.get('Client_APK_Hub_helpers_production_changed') is False and
          freeze.get('qa_receipt') == {
              'path': str(QA_RECEIPT_PATH), 'sha256': QA_RECEIPT_SHA256,
              'elapsed_seconds': qa['elapsed_seconds'], **counts},
          'FREEZE_CONTENT')
    verify_auxiliary()
    return dict(FROZEN_ARTIFACT_HASHES)


def _case_root(value):
    root = Path(value)
    _need(root.is_absolute() and root.as_posix() == str(root) and '..' not in root.parts and
          '.' not in root.parts and root.name in {str(i) for i in range(8)} and
          root.parent.name == 'cases' and root.parent.parent.parent == Path('/tmp') and
          re.fullmatch(r'cicada-joint-e2a-[A-Za-z0-9_-]{1,96}', root.parent.parent.name) is not None,
          'CASE_ROOT_SCOPE')
    _need(root.resolve(strict=False) == root, 'CASE_ROOT_ALIAS')
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise ValueError('CASE_ROOT_UNAVAILABLE') from error
        _need(not stat.S_ISLNK(info.st_mode), 'CASE_ROOT_SYMLINK')
        if current != root:
            _need(stat.S_ISDIR(info.st_mode), 'CASE_ROOT_ANCESTOR')
    return root


def _index(index):
    _need(type(index) is int and 0 <= index < len(CASES), 'CASE_INDEX')
    return index


def _side(side):
    if side in ('SOURCE', 'source'):
        return 'SOURCE'
    if side in ('TARGET', 'target'):
        return 'TARGET'
    _fail('CASE_SIDE')


def _sha_fields(record):
    for key, item in record.items():
        if key.endswith('_sha256'):
            _sha(item, 'CONTROL_HASH')


def typed_control(action, index, **kwargs):
    """Build one exact Core FD3 record. No Client fields or paths are accepted."""
    _index(index)
    _need(isinstance(action, str) and action in CONTROL_FIELDS, 'CONTROL_ACTION')
    _need('action' not in kwargs and 'case' not in kwargs, 'CONTROL_RESERVED_FIELDS')
    fields = CONTROL_FIELDS[action]
    record = {'action': action, 'case': index, **kwargs}
    _exact(record, fields, 'CONTROL_FIELDS')
    if 'side' in record:
        record['side'] = _side(record['side'])
    _need(action != 'proxy' or record['side'] == 'SOURCE', 'PROXY_SOURCE_ONLY')
    _sha_fields(record)
    return record


def input_path(case_root, side, kind):
    """Return only a frozen Core client-input path under the selected case."""
    root = _case_root(case_root)
    _need(isinstance(kind, str) and kind in INPUT_NAMES, 'INPUT_KIND')
    if kind in ('device', 'review'):
        side_name = _side(side).lower()
        name = INPUT_NAMES[kind].format(side=side_name)
    else:
        _need(side is None or _side(side) == 'SOURCE', 'INPUT_SOURCE_ONLY')
        name = INPUT_NAMES[kind]
    return root / 'client-inputs' / name


def expected_output_path(case_root, side, kind):
    """Return one fixed Core output path; never accepts a caller-provided name."""
    root = _case_root(case_root)
    _need(isinstance(kind, str) and kind in OUTPUT_NAMES, 'OUTPUT_KIND')
    if kind in ('device-grant', 'link-proof'):
        name = OUTPUT_NAMES[kind].format(side=_side(side).lower())
    else:
        _need(side is None or _side(side) == 'SOURCE', 'OUTPUT_SOURCE_ONLY')
        name = OUTPUT_NAMES[kind]
    return root / name


def _canonical_time(value):
    _need(isinstance(value, str), 'UTC_TYPE')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?Z', value)
    _need(match is not None and (match[2] is None or not match[2].endswith('0')), 'UTC_CANONICAL')
    try:
        parsed = dt.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ValueError('UTC_CANONICAL') from error
    seconds = int(parsed.timestamp())
    fraction = Decimal('0.' + match[2]) if match[2] else Decimal(0)
    return Decimal(seconds) + fraction


def _loopback_origin(value):
    _need(isinstance(value, str) and len(value) <= 128, 'LOOPBACK_ORIGIN')
    match = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{1,5})', value)
    _need(match is not None and 1024 <= int(match[1]) <= 65535, 'LOOPBACK_ORIGIN')
    return value


def _safe_id(value, code='ID'):
    _need(isinstance(value, str) and ID.fullmatch(value) is not None, code)


def _public_identity(value, code='PUBLIC_IDENTITY'):
    _exact(value, {'id', 'kem_public', 'signing_public'}, code)
    _safe_id(value['id'], code)
    for field in ('kem_public', 'signing_public'):
        _need(isinstance(value[field], str) and len(value[field]) <= 16384, code)
        try:
            decoded = base64.b64decode(value[field], validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError(code) from error
        _need(decoded and base64.b64encode(decoded).decode('ascii') == value[field], code)


_BUILD = {
    'revision': CORE_REVISION,
    'source_fingerprint': SOURCE_FINGERPRINT,
    'catalog_sha256': CATALOG_SHA256,
    'contract_revision': CONTRACT_REVISION,
    'hub_image_id': HUB_IMAGE_ID,
    'interop_image_id': TEST_IMAGE_ID,
}
_HUB_SOURCE = {
    'core_revision': CORE_REVISION,
    'hub_image_id': HUB_IMAGE_ID,
    'source_fingerprint': SOURCE_FINGERPRINT,
    'catalog_sha256': CATALOG_SHA256,
    'contract_revision': CONTRACT_REVISION,
    'wire_version': WIRE_VERSION,
}


def _validate_link(link):
    required = set('link_id source_endpoint_id source_principal_id source_group_id source_owner_id source_node_id target_endpoint_id target_principal_id target_group_id target_owner_id target_node_id direction actions data_scopes expires_at scope_snapshot contract_digest state version created_at updated_at'.split())
    optional = {'transport_hub_id', 'revoked_at', 'revoked_by_owner_id', 'revocation_reason'}
    _need(isinstance(link, dict) and required <= set(link) <= required | optional, 'LINK_FIELDS')
    for key in ('link_id', 'source_endpoint_id', 'source_principal_id', 'source_group_id', 'source_owner_id', 'source_node_id', 'target_endpoint_id', 'target_principal_id', 'target_group_id', 'target_owner_id', 'target_node_id'):
        _safe_id(link[key], 'LINK_ID')
    _need(link['direction'] in ('forward', 'bidirectional') and
          isinstance(link['actions'], list) and 0 < len(link['actions']) <= 32 and
          all(isinstance(x, str) and 0 < len(x) <= 128 for x in link['actions']) and
          isinstance(link['data_scopes'], list) and 0 < len(link['data_scopes']) <= 32 and
          all(isinstance(x, str) and 0 < len(x) <= 128 for x in link['data_scopes']), 'LINK_CONTRACT')
    _need(link['state'] == 'PROPOSED' and type(link['version']) is int and link['version'] == 1, 'LINK_STATE')
    _sha(link['contract_digest'], 'LINK_DIGEST')
    _canonical_time(link['expires_at'])
    _canonical_time(link['created_at'])
    _canonical_time(link['updated_at'])
    _exact(link['scope_snapshot'], {'source_membership_revision', 'source_join_revision', 'source_group_version', 'target_membership_revision', 'target_join_revision', 'target_group_version'}, 'LINK_SNAPSHOT_FIELDS')
    _need(all(type(v) is int and 0 <= v < 2**63 for v in link['scope_snapshot'].values()),
          'LINK_SNAPSHOT')
    _need(not any(key in link and link[key] for key in ('revoked_at', 'revoked_by_owner_id', 'revocation_reason')), 'LINK_REVOKED_FIELDS')
    if 'transport_hub_id' in link:
        _need(isinstance(link['transport_hub_id'], str) and len(link['transport_hub_id']) <= 128, 'LINK_TRANSPORT_HUB')


def _validate_manifest(manifest, link):
    _exact(manifest, {'version', 'link_id', 'link_version', 'contract_digest', 'contract_canonical', 'source', 'target', 'digest'}, 'REFERENCE_MANIFEST')
    _need(type(manifest['version']) is int and manifest['version'] == 2 and
          manifest['link_id'] == link['link_id'] and manifest['link_version'] == link['version'] and
          manifest['contract_digest'] == link['contract_digest'], 'REFERENCE_MANIFEST_SCOPE')
    for field in ('contract_canonical',):
        _need(isinstance(manifest[field], str) and len(manifest[field]) <= 32768, 'REFERENCE_MANIFEST_BYTES')
        try:
            raw = base64.b64decode(manifest[field], validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError('REFERENCE_MANIFEST_BYTES') from error
        _need(base64.b64encode(raw).decode('ascii') == manifest[field], 'REFERENCE_MANIFEST_BYTES')
    _sha(manifest['digest'], 'REFERENCE_MANIFEST_DIGEST')
    side_fields = {'endpoint_id', 'group_id', 'principal_id', 'owner_id', 'node_id', 'binding_id', 'binding_epoch', 'candidate_version', 'key_id', 'key_fingerprint', 'proof_digest', 'public_identity', 'attestation'}
    for side in ('source', 'target'):
        row = manifest[side]
        _exact(row, side_fields, 'REFERENCE_MANIFEST_SIDE')
        for field in ('endpoint_id', 'group_id', 'principal_id', 'owner_id', 'node_id', 'binding_id', 'key_id'):
            _safe_id(row[field], 'REFERENCE_MANIFEST_SIDE_ID')
        for field in ('binding_epoch', 'candidate_version'):
            _need(type(row[field]) is int and 0 < row[field] < 2**63, 'REFERENCE_MANIFEST_COUNTER')
        _fingerprint(row['key_fingerprint'], 'REFERENCE_MANIFEST_FINGERPRINT')
        _sha(row['proof_digest'], 'REFERENCE_MANIFEST_SIDE_HASH')
        _public_identity(row['public_identity'], 'REFERENCE_MANIFEST_PUBLIC_IDENTITY')
        _need(isinstance(row['attestation'], str) and len(row['attestation']) <= 16384, 'REFERENCE_MANIFEST_ATTESTATION')
        try:
            decoded = base64.b64decode(row['attestation'], validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError('REFERENCE_MANIFEST_ATTESTATION') from error
        _need(base64.b64encode(decoded).decode('ascii') == row['attestation'], 'REFERENCE_MANIFEST_ATTESTATION')


FIXTURE_PROTOCOL_CHECKS = frozenset({
    'ENDPOINT_MATCH', 'NODE_MATCH', 'DIRECT_NATIVE_ID_VALID',
    'DIRECT_NATIVE_EPOCH_VALID', 'RUNTIME_NOT_RUN', 'MEMBER_ROLE_ONLY',
    'NO_MEMBERSHIP_GRANTS',
})


def _validate_fixture_public(value, case_index):
    fields = {'networks', 'protocol_layers', 'review_policy_qualification', 'bindings', 'endpoint_candidates', 'schema', 'status', 'protocol_scope', 'native_runtime', 'model_calls', 'build', 'hub_id', 'owners', 'link', 'reference_manifest', 'reference_manifest_use', 'endpoint_private_key_policy', 'owner_private_key_policy', 'scope'}
    _exact(value, fields, 'FIXTURE_PUBLIC_FIELDS')
    _need(value['schema'] == 'cicada.client-link-v164-fixture.v1' and
          value['status'] == 'READY_FOR_CLIENT_COORDINATION' and
          value['protocol_scope'] == 'SYNTHETIC_PROTOCOL_ONLY' and
          value['native_runtime'] == 'NOT_RUN' and value['model_calls'] == 'NONE' and
          value['build'] == _BUILD, 'FIXTURE_PUBLIC_SCOPE')
    _safe_id(value['hub_id'], 'FIXTURE_HUB_ID')
    _need(value['review_policy_qualification'] == 'METADATA_NOT_PREPARED: KEY+NONE only; no reviewer or link.review grants' and
          value['reference_manifest_use'] == 'offline Store preflight only; Client must fetch and verify a fresh encrypted link.key_manifest before consent or signing' and
          value['endpoint_private_key_policy'] == 'host-only mode 0600; never mounted into Hub, helper build container, or APK' and
          value['owner_private_key_policy'] == 'host-only mode 0600; never mounted into Hub, helper build container, or APK' and
          value['scope'] == 'No Runtime, native Endpoint, model call, physical device, or public HTTPS claim.', 'FIXTURE_PUBLIC_POLICY')
    _need(isinstance(value['owners'], list) and len(value['owners']) == 2, 'FIXTURE_OWNERS')
    owner_fields = {'owner_id', 'owner_key_id', 'public_identity', 'source_of_pin', 'hub_registration', 'private_key_policy'}
    expected_owner_text = (
        'host-generated Owner public identity, independently checked before Hub registration',
        'ACTIVE public key only; Hub has no Owner private key',
        'host-only mode 0600; not mounted into Hub, helper build container, or APK',
    )
    owner_ids = []
    for i, (side, owner) in enumerate(zip(('source', 'target'), value['owners'])):
        _exact(owner, owner_fields, 'FIXTURE_OWNER_FIELDS')
        _safe_id(owner['owner_id'], 'FIXTURE_OWNER_ID')
        _need(owner['owner_id'] == f'{RUN_ID}-{side}-{case_index}' and
              owner['source_of_pin'] == expected_owner_text[0] and
              owner['hub_registration'] == expected_owner_text[1] and
              owner['private_key_policy'] == expected_owner_text[2], 'FIXTURE_OWNER_SCOPE')
        _public_identity(owner['public_identity'])
        _need(owner['owner_key_id'] == owner['public_identity']['id'], 'FIXTURE_OWNER_KEY')
        owner_ids.append(owner['owner_id'])
    link = value['link']
    _validate_link(link)
    _need(link['source_owner_id'] == owner_ids[0] and link['target_owner_id'] == owner_ids[1], 'FIXTURE_LINK_OWNERS')
    _validate_manifest(value['reference_manifest'], link)
    for side in ('source', 'target'):
        manifest_side = value['reference_manifest'][side]
        _need(manifest_side['owner_id'] == link[side + '_owner_id'] and
              manifest_side['endpoint_id'] == link[side + '_endpoint_id'] and
              manifest_side['group_id'] == link[side + '_group_id'] and
              manifest_side['principal_id'] == link[side + '_principal_id'] and
              manifest_side['node_id'] == link[side + '_node_id'], 'FIXTURE_MANIFEST_LINK')
    _need(isinstance(value['networks'], list) and len(value['networks']) == 2 and
          isinstance(value['protocol_layers'], list) and len(value['protocol_layers']) == 2 and
          isinstance(value['bindings'], list) and len(value['bindings']) == 2 and
          isinstance(value['endpoint_candidates'], list) and len(value['endpoint_candidates']) == 2, 'FIXTURE_SCOPE_ROWS')
    network_fields = {'network_id', 'owner_id', 'group_id', 'state', 'hub_id'}
    protocol_fields = {'endpoint_id', 'node_id', 'network_access_binding_id', 'network_access_epoch', 'network_access_expires_at', 'native_binding_id', 'native_binding_epoch', 'group_membership_roles', 'group_membership_grants', 'native_runtime'}
    binding_fields = {'endpoint_id', 'binding_id', 'epoch', 'lease_expires_at', 'status'}
    candidate_fields = {'endpoint_id', 'binding_id', 'epoch', 'key_id', 'state', 'version'}
    for i, side in enumerate(('source', 'target')):
        network, layer, binding, candidate = (rows[i] for rows in (value['networks'], value['protocol_layers'], value['bindings'], value['endpoint_candidates']))
        _exact(network, network_fields, 'FIXTURE_NETWORK_FIELDS')
        _exact(layer, protocol_fields, 'FIXTURE_PROTOCOL_FIELDS')
        _exact(binding, binding_fields, 'FIXTURE_BINDING_FIELDS')
        _exact(candidate, candidate_fields, 'FIXTURE_CANDIDATE_FIELDS')
        manifest_side = value['reference_manifest'][side]
        _need(network['owner_id'] == owner_ids[i] and network['group_id'] == link[side + '_group_id'] and
              network['hub_id'] == value['hub_id'] and network['state'] == 'ACTIVE', 'FIXTURE_NETWORK_SCOPE')
        # Access session, direct-native registration and Group SessionBinding
        # have separate ID/epoch domains. Only the Group binding joins the
        # manifest/candidate below. This projection omits direct Principal/session
        # coordinates, which the pinned helper validates before exporting it.
        protocol_checks = {
            'ENDPOINT_MATCH': layer['endpoint_id'] == manifest_side['endpoint_id'],
            'NODE_MATCH': layer['node_id'] == manifest_side['node_id'],
            'DIRECT_NATIVE_ID_VALID': isinstance(layer['native_binding_id'], str) and
                ID.fullmatch(layer['native_binding_id']) is not None,
            'DIRECT_NATIVE_EPOCH_VALID': type(layer['native_binding_epoch']) is int and
                layer['native_binding_epoch'] > 0,
            'RUNTIME_NOT_RUN': layer['native_runtime'] == 'NOT_RUN',
            'MEMBER_ROLE_ONLY': layer['group_membership_roles'] == ['member'],
            'NO_MEMBERSHIP_GRANTS': layer['group_membership_grants'] == [],
        }
        if not all(protocol_checks.values()):
            error = ValueError('FIXTURE_PROTOCOL_SCOPE')
            error.protocol_scope_checks = protocol_checks
            raise error
        _need(binding['endpoint_id'] == manifest_side['endpoint_id'] and binding['binding_id'] == manifest_side['binding_id'] and
              type(binding['epoch']) is int and binding['epoch'] == manifest_side['binding_epoch'] and
              binding['status'] == 'leased', 'FIXTURE_BINDING_SCOPE')
        _canonical_time(binding['lease_expires_at'])
        _need(candidate['endpoint_id'] == manifest_side['endpoint_id'] and candidate['binding_id'] == manifest_side['binding_id'] and
              type(candidate['epoch']) is int and candidate['epoch'] == manifest_side['binding_epoch'] and
              candidate['key_id'] == manifest_side['key_id'] and
              candidate['state'] == 'CANDIDATE' and candidate['version'] == manifest_side['candidate_version'], 'FIXTURE_CANDIDATE_SCOPE')
        for row, fields_to_check in ((network, ('network_id',)), (layer, ('network_access_binding_id', 'native_binding_id'))):
            for field in fields_to_check:
                _safe_id(row[field], 'FIXTURE_PUBLIC_ID')
        for field in ('network_access_epoch', 'native_binding_epoch'):
            _need(type(layer[field]) is int and layer[field] > 0, 'FIXTURE_PROTOCOL_COUNTER')
        _canonical_time(layer['network_access_expires_at'])
    return value


def _validate_custody(value, case_root):
    _exact(value, {'schema', 'private_key_root', 'owner_private_files', 'endpoint_private_files', 'not_mounted_into'}, 'CUSTODY_FIELDS')
    _need(value['schema'] == 'cicada.client-link-v164-fixture.v1' and
          value['private_key_root'] == str(case_root) and
          value['not_mounted_into'] == ['Hub', 'interop helper build container', 'APK'], 'CUSTODY_SCOPE')
    expected = {
        'owner_private_files': [
            {'path': 'owner-private/source-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
            {'path': 'owner-private/target-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
        ],
        'endpoint_private_files': [
            {'path': 'endpoint-private/source-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
            {'path': 'endpoint-private/target-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
        ],
    }
    _need(value['owner_private_files'] == expected['owner_private_files'] and
          value['endpoint_private_files'] == expected['endpoint_private_files'], 'CUSTODY_PRIVATE_SCOPE')


def _validate_provenance(value):
    _exact(value, {'compile_receipt_sha256', 'helper_binary_sha256', 'helper_source_sha256', 'image_id', 'source_revision', 'source_dirty'}, 'PROVENANCE_FIELDS')
    _need(value == {
        'compile_receipt_sha256': PREPARATION_RECEIPT_SHA256,
        'helper_binary_sha256': JOINT_HELPER_SHA256,
        'helper_source_sha256': HELPER_SOURCE_SHA256,
        'image_id': TEST_IMAGE_ID,
        'source_revision': CORE_REVISION,
        'source_dirty': False,
    }, 'PROVENANCE_SCOPE')


def _validate_runner_sha256(value):
    _need(value == FROZEN_ARTIFACT_HASHES['adapter_sha256'], 'READY_RUNNER')
    return value


def _validate_hub_ready(value, fixture):
    _exact(value, {'base_url', 'health', 'identity', 'capabilities'}, 'HUB_READY_FIELDS')
    origin = _loopback_origin(value['base_url'])
    health = value['health']
    _exact(health, {'status', 'service', 'version', 'stage', 'revision', 'dirty', 'source_fingerprint', 'catalog_sha256'}, 'HUB_HEALTH_FIELDS')
    _need(health['status'] == 'ok' and health['service'] == 'cicada-control' and
          isinstance(health['version'], str) and 0 < len(health['version']) <= 128 and
          isinstance(health['stage'], str) and 0 < len(health['stage']) <= 128 and
          health['revision'] == CORE_REVISION and health['dirty'] is False and
          health['source_fingerprint'] == SOURCE_FINGERPRINT and health['catalog_sha256'] == CATALOG_SHA256,
          'HUB_HEALTH_SCOPE')
    identity = value['identity']
    _exact(identity, {'contract', 'hub_id', 'control_public_identity', 'control_key_version', 'suite'}, 'HUB_IDENTITY_FIELDS')
    _public_identity(identity['control_public_identity'], 'HUB_CONTROL_IDENTITY')
    _need(identity['contract'] == 'android-hub-v1' and identity['hub_id'] == fixture['hub_id'] and
          type(identity['control_key_version']) is int and identity['control_key_version'] == 1 and
          identity['suite'] == 'ML-KEM-768+ML-DSA-65+AES-256-GCM', 'HUB_IDENTITY_SCOPE')
    capability_fields = {
        'contract', 'contract_revision', 'catalog_sha256', 'status', 'planned_platform',
        'legacy_management_api_available', 'client_control_pq_e2ee', 'authenticated_client_session',
        'status_snapshot', 'topology_management', 'status_events', 'status_changes_partial',
        'control_intents', 'device_binding', 'external_thread_links', 'external_link_invites',
        'external_client_sessions', 'link_key_consent', 'group_endpoint_key_grants',
        'client_device_enrollment', 'rpc_recovery', 'client_device_management',
        'approval_read_and_decide', 'queued_goal_lifecycle', 'available_rpc_operations',
        'external_rpc_operations',
    }
    capabilities = value['capabilities']
    _exact(capabilities, capability_fields, 'HUB_CAPABILITY_FIELDS')
    expected = {
        'contract': 'android-hub-v1-draft', 'contract_revision': CONTRACT_REVISION,
        'catalog_sha256': CATALOG_SHA256, 'status': 'partial', 'planned_platform': 'android',
        'legacy_management_api_available': True, 'client_control_pq_e2ee': True,
        'authenticated_client_session': True, 'status_snapshot': True, 'topology_management': True,
        'status_events': False, 'status_changes_partial': True, 'control_intents': True,
        'device_binding': True, 'external_thread_links': False, 'external_link_invites': True,
        'external_client_sessions': True, 'link_key_consent': True,
        'group_endpoint_key_grants': True, 'client_device_enrollment': True,
        'rpc_recovery': True, 'client_device_management': True,
        'approval_read_and_decide': True, 'queued_goal_lifecycle': True,
    }
    for key, item in expected.items():
        _need(capabilities[key] == item and type(capabilities[key]) is type(item), 'HUB_CAPABILITY_SCOPE')
    for key in ('available_rpc_operations', 'external_rpc_operations'):
        operations = capabilities[key]
        _need(isinstance(operations, list) and len(operations) <= 1024 and
              all(isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9_.:-]{0,127}', item) for item in operations) and
              len(operations) == len(set(operations)), 'HUB_CAPABILITY_OPERATIONS')
    return origin


def _validate_client_setup(value, fixture, hub_ready):
    _exact(value, {'schema', 'status', 'protocol_scope', 'native_runtime', 'model_calls', 'hub', 'owners', 'link', 'client_instructions'}, 'CLIENT_SETUP_FIELDS')
    _need(value['schema'] == 'cicada.client-link-v164-client-setup.v1' and
          value['status'] == 'READY_FOR_ROOT_CLIENT_COORDINATION' and
          value['protocol_scope'] == 'SYNTHETIC_PROTOCOL_ONLY' and
          value['native_runtime'] == 'NOT_RUN' and value['model_calls'] == 'NONE', 'CLIENT_SETUP_SCOPE')
    hub = value['hub']
    _exact(hub, {'hub_id', 'control_key_version', 'control_public_identity', 'suite', 'base_url', 'image_id', 'source_revision', 'source_fingerprint', 'catalog_sha256', 'contract_revision', 'build_source_dirty'}, 'CLIENT_SETUP_HUB_FIELDS')
    identity = hub_ready['identity']
    _need(hub['hub_id'] == fixture['hub_id'] == identity['hub_id'] and
          hub['control_key_version'] == identity['control_key_version'] and type(hub['control_key_version']) is int and
          hub['control_public_identity'] == identity['control_public_identity'] and
          hub['suite'] == identity['suite'] and hub['base_url'] == hub_ready['base_url'] and
          hub['image_id'] == HUB_IMAGE_ID and hub['source_revision'] == CORE_REVISION and
          hub['source_fingerprint'] == SOURCE_FINGERPRINT and hub['catalog_sha256'] == CATALOG_SHA256 and
          hub['contract_revision'] == CONTRACT_REVISION and hub['build_source_dirty'] is False,
          'CLIENT_SETUP_HUB_SCOPE')
    _loopback_origin(hub['base_url'])
    _need(isinstance(value['owners'], list) and len(value['owners']) == 2, 'CLIENT_SETUP_OWNERS')
    owner_fields = {'link_side', 'owner_id', 'owner_key_id', 'public_identity', 'pin_source'}
    for side, setup_owner, fixture_owner in zip(('SOURCE', 'TARGET'), value['owners'], fixture['owners']):
        _exact(setup_owner, owner_fields, 'CLIENT_SETUP_OWNER_FIELDS')
        _need(setup_owner == {
            'link_side': side, 'owner_id': fixture_owner['owner_id'],
            'owner_key_id': fixture_owner['owner_key_id'],
            'public_identity': fixture_owner['public_identity'],
            'pin_source': fixture_owner['source_of_pin'],
        }, 'CLIENT_SETUP_OWNER_SCOPE')
    _exact(value['link'], {'link_id', 'version', 'state', 'expires_at', 'contract_digest'}, 'CLIENT_SETUP_LINK_FIELDS')
    link = fixture['link']
    _need(value['link'] == {key: link[key] for key in ('link_id', 'version', 'state', 'expires_at', 'contract_digest')}, 'CLIENT_SETUP_LINK_SCOPE')
    _exact(value['client_instructions'], {'reference_manifest', 'owner_private_keys_for_signing'}, 'CLIENT_SETUP_INSTRUCTIONS')
    _need(value['client_instructions'] == {
        'reference_manifest': 'offline only; Client fetches fresh live encrypted manifest before signing',
        'owner_private_keys_for_signing': 'host only; never in APK or Hub',
    }, 'CLIENT_SETUP_INSTRUCTION_SCOPE')
    return value


def validate_ready(value, case_root):
    """Validate Core's full READY and its nine fixed references, returning only public metadata."""
    root = _case_root(case_root)
    _raw, ready_sha, disk_value = _load_json(root / 'public/READY.json', mode=0o600)
    _exact(value, READY_FIELDS, 'READY_FIELDS')
    _need(disk_value == value, 'READY_DISK_MISMATCH')
    _need(value['schema'] == 'cicada.client-link-v164-fixture-ready.v1' and
          value['status'] == 'READY_FOR_CLIENT_COORDINATION' and
          value['fixture_root'] == str(root) and
          value['protocol_scope'] == 'SYNTHETIC_PROTOCOL_ONLY' and
          value['native_runtime'] == 'NOT_RUN' and type(value['model_calls']) is int and
          value['model_calls'] == 0, 'READY_SCOPE')
    _need(value['source'] == _BUILD, 'READY_SOURCE')
    hub = value['hub']
    hub_fields = {'hub_id', 'base_url', 'container_id', 'network_id', 'link_id', 'link_state', 'link_version', 'bindings', 'business_networks', 'review_policy_qualification'}
    _exact(hub, hub_fields, 'READY_HUB_FIELDS')
    _loopback_origin(hub['base_url'])
    _need(HEX64.fullmatch(hub['container_id']) is not None and
          HEX64.fullmatch(hub['network_id']) is not None and
          hub['link_state'] == 'PROPOSED' and type(hub['link_version']) is int and
          hub['link_version'] == 1, 'READY_HUB_SCOPE')
    _sha(value['owned_manifest_sha256'], 'READY_OWNED_MANIFEST_HASH')
    _need(isinstance(value['public_references'], dict) and
          set(value['public_references']) == REFERENCE_NAMES, 'READY_REFERENCE_NAMES')
    parsed = {}
    for name in sorted(REFERENCE_NAMES):
        ref = value['public_references'][name]
        _exact(ref, {'path', 'relative_path', 'mode', 'bytes', 'sha256'}, 'READY_REFERENCE_FIELDS')
        relative = REFERENCE_PATHS[name]
        expected_mode = REFERENCE_MODES[name]
        path = root / relative
        _need(ref['relative_path'] == relative and ref['path'] == str(path) and
              ref['mode'] == oct(expected_mode) and type(ref['bytes']) is int and
              0 < ref['bytes'] <= REFERENCE_LIMITS[name], 'READY_REFERENCE_SCOPE')
        _sha(ref['sha256'], 'READY_REFERENCE_HASH')
        if name in JSON_REFERENCES:
            raw, digest, object_value = _load_json(
                path, expected_sha256=ref['sha256'], mode=stat.S_IMODE(expected_mode))
            _need(len(raw) == ref['bytes'], 'READY_REFERENCE_SIZE')
            if name in ('client_setup', 'fixture_public', 'hub_ready'):
                parsed[name] = object_value
            elif name == 'custody_manifest':
                _validate_custody(object_value, root)
            elif name == 'helper_provenance':
                _validate_provenance(object_value)
            elif name == 'reference_manifest':
                _need(isinstance(object_value, dict), 'READY_REFERENCE_JSON')
                parsed[name] = object_value
        else:
            size, digest = _hash_regular(path, accepted_modes=(stat.S_IMODE(expected_mode),), maximum=REFERENCE_LIMITS[name])
            _need(size == ref['bytes'] and digest == ref['sha256'], 'READY_REFERENCE_BYTES')
            if name == 'helper_binary':
                _need(digest == JOINT_HELPER_SHA256, 'READY_HELPER_BINARY')
            elif name == 'helper_source':
                _need(digest == HELPER_SOURCE_SHA256, 'READY_HELPER_SOURCE')
            elif name == 'runner':
                _validate_runner_sha256(digest)
    fixture = _validate_fixture_public(parsed['fixture_public'], int(root.name))
    _need(parsed['reference_manifest'] == fixture['reference_manifest'], 'READY_REFERENCE_MANIFEST_JOIN')
    hub_origin = _validate_hub_ready(parsed['hub_ready'], fixture)
    setup = _validate_client_setup(parsed['client_setup'], fixture, parsed['hub_ready'])
    link = fixture['link']
    _need(hub['hub_id'] == fixture['hub_id'] == parsed['hub_ready']['identity']['hub_id'] and
          hub['base_url'] == hub_origin == parsed['client_setup']['hub']['base_url'] and
          hub['link_id'] == link['link_id'] and hub['link_state'] == link['state'] and
          hub['link_version'] == link['version'] and hub['bindings'] == fixture['bindings'] and
          hub['business_networks'] == fixture['networks'] and
          hub['review_policy_qualification'] == fixture['review_policy_qualification'],
          'READY_HUB_METADATA_JOIN')
    for field, ref_name in (('client_setup_sha256', 'client_setup'),
                            ('hub_ready_sha256', 'hub_ready'),
                            ('reference_manifest_sha256', 'reference_manifest')):
        _need(value[field] == value['public_references'][ref_name]['sha256'], 'READY_HASH_JOIN')
    _need(re.fullmatch(r'[0-9a-f]{48}', value['coordination_nonce']) is not None and
          type(value['coordination_ttl_seconds']) is int and
          value['coordination_ttl_seconds'] == 720 and
          value['cleanup_policy'] == 'one terminal consumer ACK or fixed deadline; no renewal; fresh private state destroyed',
          'READY_COORDINATION_SCOPE')
    deadline = _canonical_time(value['coordination_deadline'])
    remaining = deadline - Decimal(str(time.time()))
    _need(Decimal(30) < remaining <= Decimal(720), 'READY_DEADLINE')
    return {'ready': value, 'client_setup': setup, 'fixture_public': fixture, 'hub_ready': parsed['hub_ready']}


def _read_ready(root, expected_sha256=None):
    _raw, digest, value = _load_json(expected_output_path(root, None, 'ready'),
        expected_sha256=expected_sha256, mode=0o600)
    return value, digest


def _check_run_id(value, index):
    _need(value == f'{RUN_ID}-{index}', 'CASE_RUN_ID')


def _validate_signed_wrapper(path, expected_sha256, index, side, action, root):
    _raw, _digest, wrapper = _load_json(path, expected_sha256=expected_sha256, mode=0o600)
    ready, _ = _read_ready(root)
    fixture = validate_ready(ready, root)['fixture_public']
    owner = fixture['owners'][0 if side == 'SOURCE' else 1]
    if action == 'device':
        fields = {'schema', 'run_id', 'profile_id', 'profile_generation', 'hub_id', 'owner_id', 'owner_key_id', 'device_id', 'catalog_sha256', 'device_public_identity_sha256', 'owner_device_grant_base64', 'grant_sha256'}
        _exact(wrapper, fields, 'SIGNED_DEVICE_FIELDS')
        _need(wrapper['schema'] == 'cicada.client-v164-owner-device-grant-handoff.v1' and
              wrapper['hub_id'] == fixture['hub_id'] and wrapper['owner_id'] == owner['owner_id'] and
              wrapper['owner_key_id'] == owner['owner_key_id'] and wrapper['catalog_sha256'] == CATALOG_SHA256 and
              isinstance(wrapper['profile_id'], str) and ROOT_ID.fullmatch(wrapper['profile_id']) is not None and
              type(wrapper['profile_generation']) is int and wrapper['profile_generation'] > 0 and
              isinstance(wrapper['device_id'], str) and ID.fullmatch(wrapper['device_id']) is not None,
              'SIGNED_DEVICE_SCOPE')
        _check_run_id(wrapper['run_id'], index)
        _sha(wrapper['device_public_identity_sha256'], 'SIGNED_DEVICE_IDENTITY_HASH')
        payload_field, digest_field = 'owner_device_grant_base64', 'grant_sha256'
    else:
        fields = {'schema', 'run_id', 'review_id', 'consent_digest', 'link_id', 'link_version', 'side', 'owner_id', 'owner_key_id', 'signed_proof_base64', 'proof_sha256'}
        _exact(wrapper, fields, 'SIGNED_PROOF_FIELDS')
        link = fixture['link']
        _need(wrapper['schema'] == 'cicada.client-v164-owner-signed-proof.v1' and
              wrapper['review_id'] and ROOT_ID.fullmatch(wrapper['review_id']) is not None and
              wrapper['consent_digest'] and HEX64.fullmatch(wrapper['consent_digest']) is not None and
              wrapper['link_id'] == link['link_id'] and wrapper['link_version'] == str(link['version']) and
              wrapper['side'] == side and wrapper['owner_id'] == owner['owner_id'] and
              wrapper['owner_key_id'] == owner['owner_key_id'], 'SIGNED_PROOF_SCOPE')
        _check_run_id(wrapper['run_id'], index)
        payload_field, digest_field = 'signed_proof_base64', 'proof_sha256'
    _sha(wrapper[digest_field], 'SIGNED_PAYLOAD_HASH')
    encoded = wrapper[payload_field]
    _need(isinstance(encoded, str) and 0 < len(encoded) <= 65536, 'SIGNED_PAYLOAD')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError('SIGNED_PAYLOAD') from error
    _need(raw and base64.b64encode(raw).decode('ascii') == encoded and
          hashlib.sha256(raw).hexdigest() == wrapper[digest_field], 'SIGNED_PAYLOAD_HASH')


def _validate_carrier_manifest(value, root, index):
    fields = {'schema', 'run_id', 'run_scope', *_HUB_SOURCE.keys(), 'fixture_pid', 'fixture_process_start', 'helper_sha256', 'ready_raw_sha256', 'hub_id', 'upstream_origin', 'android_base_url', 'owner_id', 'device_id', 'session_epoch', 'expected_operation', 'fault_mode'}
    _exact(value, fields, 'CARRIER_MANIFEST_FIELDS')
    ready, _ = _read_ready(root)
    fixture = validate_ready(ready, root)['fixture_public']
    operation, mode = CASES[index]
    _need(value['schema'] == 'cicada.client-v164-link-recovery-carrier.v1' and
          value['run_scope'] == 'v164-e2a1908-link-recovery', 'CARRIER_MANIFEST_SCOPE')
    _check_run_id(value['run_id'], index)
    for key, item in _HUB_SOURCE.items():
        _need(value[key] == item and type(value[key]) is type(item), 'CARRIER_CORE_SOURCE')
    _need(type(value['fixture_pid']) is int and value['fixture_pid'] > 0 and
          isinstance(value['fixture_process_start'], str) and value['fixture_process_start'].isdigit() and
          value['helper_sha256'] == RECOVERY_HELPER_SHA256 and HEX64.fullmatch(value['ready_raw_sha256']) is not None and
          value['hub_id'] == ready['hub']['hub_id'] and value['android_base_url'] == ANDROID_BASE_URL and
          value['owner_id'] == fixture['owners'][0]['owner_id'] and
          isinstance(value['device_id'], str) and ID.fullmatch(value['device_id']) is not None and
          type(value['session_epoch']) is int and value['session_epoch'] > 0 and
          value['expected_operation'] == operation and value['fault_mode'] == mode,
          'CARRIER_MANIFEST_BINDING')
    _loopback_origin(value['upstream_origin'])
    _need(value['android_base_url'] == ANDROID_BASE_URL, 'CARRIER_ANDROID_URL')


def _validate_fault_files(root, index, envelope_sha256):
    envelope_path = expected_output_path(root, None, 'fault-envelope')
    frame_path = expected_output_path(root, None, 'fault-control')
    envelope_raw, envelope_digest, envelope = _load_json(
        envelope_path, expected_sha256=envelope_sha256, mode=0o600)
    _exact(envelope, {'schema', 'run_id', 'hub_source', 'fault_ready_raw_base64', 'fault_ready_raw_sha256', 'restart'}, 'FAULT_ENVELOPE_FIELDS')
    _need(envelope['schema'] == 'cicada.client-v164-link-recovery-ready.v1', 'FAULT_ENVELOPE_SCHEMA')
    _check_run_id(envelope['run_id'], index)
    _exact(envelope['hub_source'], set(_HUB_SOURCE), 'FAULT_SOURCE_FIELDS')
    _need(envelope['hub_source'] == _HUB_SOURCE, 'FAULT_SOURCE_SCOPE')
    encoded_event = envelope['fault_ready_raw_base64']
    _need(isinstance(encoded_event, str) and 0 < len(encoded_event) <= 8192, 'FAULT_EVENT')
    try:
        fault_raw = base64.b64decode(encoded_event, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError('FAULT_EVENT') from error
    _need(base64.b64encode(fault_raw).decode('ascii') == encoded_event and
          hashlib.sha256(fault_raw).hexdigest() == envelope['fault_ready_raw_sha256'], 'FAULT_EVENT_HASH')
    _sha(envelope['fault_ready_raw_sha256'], 'FAULT_EVENT_HASH')
    try:
        fault = json.loads(fault_raw.decode('utf-8'), object_pairs_hook=_unique_object)
        _pins._depth(fault)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ValueError('FAULT_EVENT_JSON') from error
    operation, mode = CASES[index]
    common = {'event', 'mode', 'operation', 'request_sha256', 'request_sequence', 'business_outcome', 'handler_executed', 'scope', 'request_status', 'reserved_response_sequence'}
    _exact(fault, common | ({'response_sha256'} if mode == 'response-loss' else {'restart_required'}), 'FAULT_EVENT_FIELDS')
    _need(fault['event'] == 'FAULT_READY' and fault['mode'] == mode and fault['operation'] == operation and
          fault['business_outcome'] == 'UNKNOWN' and HEX64.fullmatch(fault['request_sha256']) is not None and
          type(fault['request_sequence']) is int and fault['request_sequence'] > 0 and
          type(fault['reserved_response_sequence']) is int and fault['reserved_response_sequence'] >= 0,
          'FAULT_EVENT_SCOPE')
    if mode == 'response-loss':
        _need(fault['handler_executed'] is True and fault['scope'] == 'REAL_HANDLER_COMPLETED_TRANSPORT' and
              fault['request_status'] == 'COMPLETED' and fault['reserved_response_sequence'] > 0,
              'FAULT_EVENT_RESPONSE_LOSS')
        _sha(fault['response_sha256'], 'FAULT_EVENT_RESPONSE_HASH')
    else:
        status = 'UNCERTAIN' if mode == 'legacy' else 'PROCESSING'
        _need(fault['handler_executed'] is False and fault['scope'] == 'OUTER_RPC_LEDGER_ONLY' and
              fault['request_status'] == status and
              fault['restart_required'] is (mode == 'uncertain') and
              (fault['reserved_response_sequence'] > 0 if mode == 'uncertain' else fault['reserved_response_sequence'] == 0),
              'FAULT_EVENT_LEDGER')
    restart = envelope['restart']
    _exact(restart, {'status', 'receipt_sha256'}, 'FAULT_RESTART_FIELDS')
    if mode == 'uncertain':
        _need(restart['status'] == 'VERIFIED', 'FAULT_RESTART_REQUIRED')
        _sha(restart['receipt_sha256'], 'FAULT_RESTART_RECEIPT')
    else:
        _need(restart == {'status': 'NOT_REQUIRED', 'receipt_sha256': None}, 'FAULT_RESTART_FORBIDDEN')
    _raw, _frame_digest, frame = _load_json(frame_path, mode=0o600)
    _exact(frame, {'kind', 'envelope_b64', 'envelope_sha256'}, 'FAULT_CONTROL_FIELDS')
    _need(frame['kind'] == 'fault-ready' and
          frame['envelope_b64'] == base64.b64encode(envelope_raw).decode('ascii') and
          frame['envelope_sha256'] == envelope_digest, 'FAULT_CONTROL_SCOPE')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'JSON_DUPLICATE')
        result[key] = value
    return result


def validate_output_event(event, case_root, *, index, action=None):
    """Validate one closed Core stdout event and its fixed output paths."""
    root = _case_root(case_root)
    _need(isinstance(event, dict) and isinstance(event.get('event'), str), 'OUTPUT_EVENT')
    name = event['event']
    if name == 'BOOT_READY':
        _need(index is None or (type(index) is int and 0 <= index < len(CASES)), 'CASE_INDEX')
        _exact(event, {'event', 'scope', 'upstream_origin', 'fixture_root', 'setup_restart_count'}, 'BOOT_READY_FIELDS')
        _need(event['scope'] == 'CORE_JOINT_FIXTURE_ONLY' and
              event['fixture_root'] == str(root.parent.parent) and
              type(event['setup_restart_count']) is int and event['setup_restart_count'] == 1,
              'BOOT_READY_SCOPE')
        _loopback_origin(event['upstream_origin'])
        return event
    _index(index)
    _need(root.name == str(index), 'OUTPUT_EVENT_CASE_ROOT')
    if name == 'CASE_READY':
        _exact(event, {'event', 'case', 'operation', 'mode', 'root', 'ready_sha256', 'deadline'}, 'CASE_READY_FIELDS')
        operation, mode = CASES[index]
        _need(event['case'] == index and type(event['case']) is int and
              event['operation'] == operation and event['mode'] == mode and
              event['root'] == str(root), 'CASE_READY_SCOPE')
        _sha(event['ready_sha256'], 'CASE_READY_HASH')
        deadline = _canonical_time(event['deadline'])
        ready, _digest = _read_ready(root, event['ready_sha256'])
        validate_ready(ready, root)
        _need(ready['coordination_deadline'] == event['deadline'] and
              deadline > Decimal(str(time.time())), 'CASE_READY_DEADLINE')
        _need(action in (None, 'prepare'), 'CASE_READY_ACTION')
    elif name == 'SIGNED':
        _exact(event, {'event', 'case', 'action', 'side', 'path', 'sha256'}, 'SIGNED_FIELDS')
        side = _side(event['side'])
        _need(event['case'] == index and type(event['case']) is int and
              event['action'] in ('device', 'proof') and (action is None or action == event['action']), 'SIGNED_SCOPE')
        kind = 'device-grant' if event['action'] == 'device' else 'link-proof'
        path = expected_output_path(root, side, kind)
        _need(event['path'] == str(path), 'SIGNED_PATH')
        _sha(event['sha256'], 'SIGNED_HASH')
        _validate_signed_wrapper(path, event['sha256'], index, side, event['action'], root)
    elif name == 'PROXY_READY':
        _exact(event, {'event', 'case', 'manifest', 'manifest_sha256', 'ready'}, 'PROXY_READY_FIELDS')
        _need(event['case'] == index and type(event['case']) is int, 'PROXY_READY_CASE')
        manifest_path = expected_output_path(root, None, 'carrier-manifest')
        ready_path = expected_output_path(root, None, 'proxy-ready')
        _need(event['manifest'] == str(manifest_path) and event['ready'] == str(ready_path), 'PROXY_READY_PATHS')
        _sha(event['manifest_sha256'], 'PROXY_READY_HASH')
        _raw, _manifest_sha, manifest = _load_json(manifest_path, expected_sha256=event['manifest_sha256'], mode=0o600)
        _validate_carrier_manifest(manifest, root, index)
        size, digest = _hash_regular(ready_path, accepted_modes=(0o600,), maximum=4096)
        _need(size <= 4096 and digest == manifest['ready_raw_sha256'], 'PROXY_READY_RAW')
        if action is not None:
            _need(action == 'proxy', 'PROXY_READY_ACTION')
    elif name == 'FAULT_READY':
        _exact(event, {'event', 'case', 'envelope', 'envelope_sha256', 'control_frame'}, 'FAULT_READY_FIELDS')
        _need(event['case'] == index and type(event['case']) is int and
              event['envelope'] == str(expected_output_path(root, None, 'fault-envelope')) and
              event['control_frame'] == str(expected_output_path(root, None, 'fault-control')), 'FAULT_READY_PATHS')
        _sha(event['envelope_sha256'], 'FAULT_READY_HASH')
        _validate_fault_files(root, index, event['envelope_sha256'])
    elif name in ('CAPTURE_VERIFIED', 'CASE_FINISHED'):
        _exact(event, {'event', 'case'}, name + '_FIELDS')
        _need(event['case'] == index and type(event['case']) is int, name + '_CASE')
        required_action = 'capture' if name == 'CAPTURE_VERIFIED' else 'finish'
        _need(action in (None, required_action), name + '_ACTION')
    else:
        _fail('OUTPUT_EVENT_UNKNOWN')
    return event
