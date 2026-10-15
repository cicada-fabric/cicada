#!/usr/bin/env python3
"""Run bounded live v1.6.1 Link status selectors on the owned Android emulator.

The caller supplies a public selector copied from a genuine Link fixture. The
Android test independently confirms it against the encrypted Owner Link list.
This driver never creates or mutates Hub Link or policy records. Configured
policy, revocation, missing-capability, third-Owner, and process-death cases are
reported as NOT_RUN until their real fixtures exist.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
V16_RUNNER = ROOT / 'scripts/interop/v16-android-deterministic.py'
V16_CARRIER = ROOT / 'scripts/interop/v16-host-stdio-carrier.py'
TEST_CLASS = 'ai.cicada.client.hub.LinkReviewPolicyStatusInteropTest'
SELECTION_SCHEMA = 'cicada.client-v161-link-status-selection.v1'
OWNER_RESULT_SCHEMA = 'cicada.client-v161-link-status-owner-summary.v1'
AGGREGATE_SCHEMA = 'cicada.client-v161-link-status-two-owner-summary.v1'
RPC_DROP_OPERATION = 'link.review_policy_status'
MAX_SELECTION_BYTES = 32 * 1024
MAX_RECEIPT_BYTES = 64 * 1024


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('required pinned interop module is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def save_private(path, value):
    path = Path(path)
    parent_info = path.parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o700 or \
            parent_info.st_uid != os.getuid():
        raise ValueError('evidence output parent must be an owned private mode-0700 directory')
    if path.exists() or path.is_symlink():
        raise ValueError('refusing to overwrite existing link-status evidence')
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('JSON contains duplicate fields')
        result[key] = value
    return result


def read_private_json(path_value, *, maximum=MAX_RECEIPT_BYTES):
    path = Path(path_value)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or \
                before.st_uid != os.getuid() or before.st_size <= 0 or before.st_size > maximum:
            raise ValueError('input must be a bounded private regular file')
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('input changed while it was read')
        value = json.loads(data, object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('invalid JSON number')))
        if not isinstance(value, dict):
            raise ValueError('input must be a JSON object')
        return value, digest_bytes(bytes(data))
    finally:
        os.close(fd)


def valid_id(value):
    return isinstance(value, str) and value == value.strip() and 0 < len(value) <= 256 and \
        not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_pins(args, runner, carrier):
    expected = {
        'core_commit': carrier.CORE_REVISION,
        'source_fingerprint': carrier.SOURCE_FINGERPRINT,
        'catalog_sha256': carrier.CATALOG_SHA256,
        'hub_image': carrier.HUB_IMAGE,
    }
    supplied = {
        'core_commit': args.core_commit,
        'source_fingerprint': args.source_fingerprint,
        'catalog_sha256': args.catalog_sha256,
        'hub_image': args.hub_image,
    }
    if supplied != expected or runner.CORE_REVISION != args.core_commit or \
            runner.CORE_SOURCE_FINGERPRINT != args.source_fingerprint or \
            runner.CATALOG_SHA256 != args.catalog_sha256 or runner.HUB_IMAGE != args.hub_image:
        raise ValueError('CLI Core pins must exactly equal both owned v1.6.1 driver pin sets')
    for value in (args.app_sha256, args.test_sha256, args.source_fingerprint, args.catalog_sha256):
        if not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('full lowercase SHA-256 values are required')
    if not re.fullmatch(r'[0-9a-f]{40}', args.core_commit) or not args.hub_image.startswith('sha256:'):
        raise ValueError('full pinned Core commit and Hub image ID are required')


def validate_selection(path, args, core_public, owner_id):
    selection, selection_sha = read_private_json(path, maximum=MAX_SELECTION_BYTES)
    required = {'schema', 'run_id', 'hub_id', 'owner_id', 'device_id', 'catalog_sha256',
        'link_id', 'expected_link_version'}
    optional = {'foreign_link_id'}
    if set(selection) - (required | optional) or not required.issubset(selection):
        raise ValueError('public Link selector fields do not match the bounded schema')
    if selection.get('schema') != SELECTION_SCHEMA or selection.get('run_id') != args.run_id or \
            selection.get('hub_id') != core_public.get('hub_id') or selection.get('owner_id') != owner_id or \
            selection.get('device_id') != 'phone-' + args.run_id or \
            selection.get('catalog_sha256') != args.catalog_sha256:
        raise ValueError('public Link selector belongs to another Core fixture, Owner, or device')
    if not valid_id(selection.get('link_id')) or \
            type(selection.get('expected_link_version')) is not int or \
            not 1 <= selection['expected_link_version'] <= 9_007_199_254_740_991:
        raise ValueError('public Link selector has an invalid ID or version')
    foreign_id = selection.get('foreign_link_id')
    if foreign_id is not None and (not valid_id(foreign_id) or foreign_id == selection['link_id']):
        raise ValueError('optional foreign Link selector is invalid')
    return selection, selection_sha


def owned_emulator(evidence, runner, args):
    state = runner.owned_state(evidence)
    artifacts = json.loads((evidence / 'android-artifacts.json').read_text())
    if artifacts.get('contract_revision') != 'client-hub-v1.6.1' or \
            artifacts.get('app_sha256') != args.app_sha256 or artifacts.get('test_sha256') != args.test_sha256:
        raise ValueError('owned emulator does not have the CLI-pinned app and test APKs')
    for name, expected in (('app', args.app_sha256), ('test', args.test_sha256)):
        path = evidence / ('installed-' + name + '.private.apk')
        if path.is_symlink() or not path.is_file() or digest_bytes(path.read_bytes()) != expected:
            raise ValueError('archived installed APK bytes do not match the full CLI digest')
        receipt = json.loads((evidence / ('install-' + name + '.json')).read_text())
        command = receipt.get('command')
        if receipt.get('result') != 'PASS' or receipt.get('exit_code') != 0 or \
                not isinstance(command, list) or 'install' not in command or \
                ('/tmp/cicada-v15-' + name + '.apk') not in command:
            raise ValueError('owned emulator installation receipt does not bind the pinned APK')
    return state, artifacts


def _read_ready(process, timeout=15):
    ready_deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while time.monotonic() < ready_deadline:
            if process.poll() is not None:
                raise RuntimeError('owned v1.6.1 carrier exited before readiness')
            for _key, _mask in selector.select(0.2):
                line = process.stdout.readline()
                if not line:
                    break
                value = json.loads(line)
                if value.get('result') == 'READY':
                    return value
        raise RuntimeError('owned v1.6.1 carrier readiness timed out')
    finally:
        selector.close()


def start_carrier(evidence, args, carrier, tag, fault):
    command = [sys.executable, str(V16_CARRIER), '--evidence', str(evidence), '--tag', tag,
        '--fixture', args.fixture, '--public', args.public, '--app-sha256', args.app_sha256,
        '--test-sha256', args.test_sha256, '--fault', fault, '--android-url-port', str(args.android_url_port),
        '--carrier-port', str(args.carrier_port)]
    if fault == 'rpc':
        command.extend(['--rpc-drop-operation', RPC_DROP_OPERATION])
    native_values = (args.native_topology, args.native_topology_sha256, args.fixture_sha256,
        args.public_sha256, args.native_mounts, args.native_mounts_sha256)
    if all(value is not None for value in native_values):
        command.extend([
            '--native-topology', args.native_topology,
            '--native-topology-sha256', args.native_topology_sha256,
            '--fixture-sha256', args.fixture_sha256,
            '--public-sha256', args.public_sha256,
            '--native-mounts', args.native_mounts,
            '--native-mounts-sha256', args.native_mounts_sha256,
        ])
    elif any(value is not None for value in native_values):
        raise ValueError('all six native topology and mount pins must be supplied together')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1, start_new_session=True)
    try:
        ready = _read_ready(process)
    except Exception:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        raise
    if ready.get('tag') != tag or ready.get('fault') != fault:
        process.terminate()
        process.wait(timeout=5)
        raise RuntimeError('carrier readiness did not match the requested owner-scoped run')
    return process, command


def stop_carrier(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        raise RuntimeError('owned carrier did not stop within its bounded cleanup window')
    lines = [line for line in stdout.splitlines() if line.strip()]
    try:
        stopped = json.loads(lines[-1]) if lines else {}
    except json.JSONDecodeError:
        stopped = {}
    if process.returncode != 0 or stopped.get('result') != 'STOPPED' or \
            stopped.get('docker_exec_exit_code') != 0 or \
            stopped.get('proxy_exit_code') not in (None, 0, -signal.SIGTERM):
        raise RuntimeError('owned carrier or response-loss proxy did not stop cleanly')
    return {'exit_code': process.returncode, 'result': stopped.get('result'),
        'transactions': stopped.get('transactions')}


def run_selector(evidence, state, driver, method, label):
    command = driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id',
        state['run_id'], '-e', 'class', TEST_CLASS + '#' + method,
        driver.PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner']
    output = driver.run(evidence, label, command, junit=True)
    summary = json.loads((evidence / (label + '.json')).read_text())
    if summary.get('driver_exit_code') != 0 or summary.get('junit') != 'OK (1 test)':
        raise RuntimeError('bounded Link status instrumentation selector did not run exactly once')
    return {'selector': method, 'result': 'PASS', 'exit_code': summary['exit_code'],
        'junit': summary['junit'], 'output_sha256': digest_bytes(output)}


def stage_selector(evidence, state, driver, selection):
    remote = f'no_backup/network-v16/{state["run_id"]}/link-status-selection.json'
    command = driver.adb(state, True) + ['shell', shlex.join([
        'run-as', driver.PACKAGE, 'sh', '-c', 'umask 077; cat > ' + shlex.quote(remote)])]
    raw = (json.dumps(selection, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    if len(raw) > MAX_SELECTION_BYTES:
        raise ValueError('staged Link selector exceeds its bound')
    output = driver.run(evidence, 'link-status-stage-' + digest_bytes(selection['owner_id'].encode())[:8],
        command, data=raw)
    if output:
        raise RuntimeError('Link selector staging returned unexpected stdout')
    return {'result': 'PASS', 'stdin_bytes': len(raw), 'stdin_sha256': digest_bytes(raw),
        'stdout_bytes': 0, 'command': command}


def read_android_receipt(evidence, state, driver, receipt_name, label):
    path = f'no_backup/network-v16/{state["run_id"]}/{receipt_name}'
    command = driver.adb(state) + ['exec-out', 'run-as', driver.PACKAGE, 'cat', path]
    raw = driver.run(evidence, label, command)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError('Android did not return a bounded redacted Link status receipt') from error
    if not isinstance(value, dict) or len(raw) > MAX_RECEIPT_BYTES:
        raise RuntimeError('Android Link status receipt exceeded its bound')
    return value


def _proxy_loss_events(path):
    values = []
    with open(path, 'rb') as source:
        for line in source:
            if len(line) > 16 * 1024:
                raise ValueError('response-loss evidence row exceeded its bound')
            item = json.loads(line)
            if isinstance(item, dict):
                values.append(item)
    return values


def verify_packet_recovery(evidence, tag, recovery_receipt):
    path = evidence / ('response-loss-' + tag + '.private.jsonl')
    events = _proxy_loss_events(path)
    if len(events) != 2:
        raise ValueError('status fault proxy must record exactly one lost response and its exact recovery')
    dropped, recovered = events
    for event in (dropped, recovered):
        if event.get('schema') != 'cicada.client-v15-response-loss.v1' or \
                event.get('http_status') != 200 or \
                not re.fullmatch(r'[0-9a-f]{64}', event.get('response_envelope_sha256', '')):
            raise ValueError('status fault proxy omitted the accepted encrypted response hash')
    original_request_hash = recovery_receipt.get('original_packet_sha256')
    if not re.fullmatch(r'[0-9a-f]{64}', original_request_hash or '') or \
            dropped.get('request_sha256') != original_request_hash or \
            recovered.get('request_sha256') != original_request_hash or \
            dropped.get('response_sha256') != recovered.get('response_sha256') or \
            dropped.get('kind') != 'original_or_exact_retry' or dropped.get('dropped') is not True or \
            recovered.get('kind') != 'recover' or recovered.get('dropped') is not False or \
            dropped.get('response_envelope_sha256') != recovered.get('response_envelope_sha256'):
        raise ValueError('Hub did not return the same encrypted response envelope during exact recovery')
    return {'result': 'PASS', 'drop_operation': RPC_DROP_OPERATION,
        'original_packet_sha256': original_request_hash,
        'original_request_sha256': dropped['request_sha256'],
        'recovery_request_sha256': recovered['request_sha256'],
        'original_response_sha256': dropped['response_sha256'],
        'recovery_response_sha256': recovered['response_sha256'],
        'original_http_status': dropped['http_status'], 'recovery_http_status': recovered['http_status'],
        'dropped_response_envelope_sha256': dropped['response_envelope_sha256'],
        'recovered_response_envelope_sha256': recovered['response_envelope_sha256'],
        'same_encrypted_response_envelope': True, 'payload_persisted': False}


def run_owner(args):
    native_values = (args.native_topology, args.native_topology_sha256, args.fixture_sha256,
        args.public_sha256, args.native_mounts, args.native_mounts_sha256)
    if any(value is not None for value in native_values) and not all(value is not None for value in native_values):
        raise ValueError('all six native topology and mount pins must be supplied together')
    runner = load_module(V16_RUNNER, 'v16_status_runner')
    carrier = load_module(V16_CARRIER, 'v16_status_carrier')
    validate_pins(args, runner, carrier)
    evidence = runner.driver.private_evidence(args.evidence)
    if not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', args.run_id) or \
            args.run_id != evidence.parent.name:
        raise ValueError('instrumentation run ID must match the owned evidence directory')
    state, artifacts = owned_emulator(evidence, runner, args)
    fixture, core_public, _hub, _network, _hub_ip, _hub_port = carrier.verify_hub(
        args.fixture, args.public,
        native_topology=args.native_topology,
        native_topology_sha256=args.native_topology_sha256,
        fixture_sha256=args.fixture_sha256,
        public_sha256=args.public_sha256,
        native_mounts=args.native_mounts,
        native_mounts_sha256=args.native_mounts_sha256)
    if core_public.get('source_revision') != args.core_commit or \
            core_public.get('source_fingerprint') != args.source_fingerprint or \
            core_public.get('catalog_sha256') != args.catalog_sha256 or \
            core_public.get('image_id') != args.hub_image:
        raise ValueError('actual Core public fixture differs from all CLI-supplied pins')
    owner_id_key = 'owner_id' if args.owner == 'primary' else 'foreign_owner_id'
    owner_id = core_public.get(owner_id_key)
    if not valid_id(owner_id):
        raise ValueError('selected real Owner is absent from the pinned public Core fixture')
    selection, selection_sha = validate_selection(args.selection, args, core_public, owner_id)
    if args.android_url_port != core_public.get('host_port'):
        raise ValueError('Android reverse origin differs from the actual pinned Core fixture port')

    owner_hash = digest_bytes(owner_id.encode())
    tag_base = args.tag + '-' + args.owner + '-' + owner_hash[:8]
    carrier_tags = (tag_base + '-normal', tag_base + '-response-loss')
    if any(len(tag) > 80 for tag in carrier_tags):
        raise ValueError('composed v1.6.1 carrier tag exceeds its 80-character bound')
    staged = stage_selector(evidence, state, runner.driver, selection)
    adb = runner.driver.adb(state)
    reverse_list = runner.driver.run(evidence, 'link-status-reverse-list-' + owner_hash[:8],
        adb + ['reverse', '--list']).decode(errors='replace').splitlines()
    prefix = 'emulator-' + str(state['emulator_port']) + ' tcp:' + str(args.android_url_port) + ' '
    if any(line.startswith(prefix) for line in reverse_list):
        raise ValueError('refusing to replace an existing Android reverse mapping')

    selectors = [
        ('readsCurrentNonePolicyForSelectedOwnerLink', 'none'),
        ('refusesUnknownAndOptionalForeignLinkBeforeStatusRpc', 'owner-filter'),
        ('rejectsStaleExpectedLinkVersionBeforeStatusRpc', 'stale-selection'),
        ('rejectsGenericStatusRpcBypassWithoutSequenceUse', 'generic-bypass'),
    ]
    results = []
    carrier_receipts = []
    normal, normal_command = start_carrier(evidence, args, carrier, tag_base + '-normal', 'none')
    carrier_receipts.append({'command': normal_command, 'fault': 'none'})
    try:
        for method, scenario in selectors:
            step = 'link-status-' + owner_hash[:8] + '-' + scenario
            results.append(run_selector(evidence, state, runner.driver, method, step))
            receipt = read_android_receipt(evidence, state, runner.driver,
                'link-status-' + scenario + '-' + owner_hash[:16] + '.redacted.json',
                step + '-receipt')
            if receipt.get('result') != 'PASS' or receipt.get('owner_id_sha256') != owner_hash:
                raise ValueError('Android Link status selector receipt failed its Owner binding')
            if scenario == 'none':
                default_receipt = receipt
        normal_cleanup = stop_carrier(normal)
        normal = None
    finally:
        if normal is not None:
            stop_carrier(normal)
    remaining_reverse = runner.driver.run(evidence, 'link-status-reverse-verify-' + owner_hash[:8],
        adb + ['reverse', '--list']).decode(errors='replace').splitlines()
    if any(line.startswith(prefix) for line in remaining_reverse):
        raise RuntimeError('owned host carrier did not remove its Android reverse mapping')

    loss, loss_command = start_carrier(evidence, args, carrier, tag_base + '-response-loss', 'rpc')
    carrier_receipts.append({'command': loss_command, 'fault': 'rpc', 'drop_operation': RPC_DROP_OPERATION})
    try:
        method, scenario = 'capturesAndRecoversExactStatusPacket', 'response-loss-recovery'
        step = 'link-status-' + owner_hash[:8] + '-' + scenario
        results.append(run_selector(evidence, state, runner.driver, method, step))
        recovery_receipt = read_android_receipt(evidence, state, runner.driver,
            'link-status-' + scenario + '-' + owner_hash[:16] + '.redacted.json', step + '-receipt')
        if recovery_receipt.get('result') != 'PASS' or recovery_receipt.get('owner_id_sha256') != owner_hash or \
                recovery_receipt.get('operation') != RPC_DROP_OPERATION:
            raise ValueError('Android exact-packet recovery selector receipt failed its operation binding')
        loss_cleanup = stop_carrier(loss)
        loss = None
    finally:
        if loss is not None:
            stop_carrier(loss)
    remaining_reverse = runner.driver.run(evidence, 'link-status-reverse-verify-loss-' + owner_hash[:8],
        adb + ['reverse', '--list']).decode(errors='replace').splitlines()
    if any(line.startswith(prefix) for line in remaining_reverse):
        raise RuntimeError('owned response-loss carrier did not remove its Android reverse mapping')

    packet_recovery = verify_packet_recovery(evidence, tag_base + '-response-loss', recovery_receipt)
    if default_receipt.get('scenario') != 'selected_link_default_none' or \
            default_receipt.get('policy_mode') != 'NONE' or default_receipt.get('policy_version') != 0 or \
            default_receipt.get('approval_inferred') is not False:
        raise ValueError('actual selected Link status did not match the no-policy baseline')
    summary = {
        'schema': OWNER_RESULT_SCHEMA,
        'result': 'PASS',
        'run_id': args.run_id,
        'owner_selection': args.owner,
        'core_commit': args.core_commit,
        'source_fingerprint': args.source_fingerprint,
        'catalog_sha256': args.catalog_sha256,
        'hub_image': args.hub_image,
        'app_sha256': artifacts['app_sha256'],
        'test_sha256': artifacts['test_sha256'],
        'selection_file_sha256': selection_sha,
        'hub_id_sha256': digest_bytes(selection['hub_id'].encode()),
        'owner_id_sha256': owner_hash,
        'device_id_sha256': digest_bytes(selection['device_id'].encode()),
        'link_id_sha256': digest_bytes(selection['link_id'].encode()),
        'link_version': selection['expected_link_version'],
        'my_side': default_receipt.get('my_side'),
        'policy_mode': default_receipt.get('policy_mode'),
        'policy_version': default_receipt.get('policy_version'),
        'policy_digest_sha256': default_receipt.get('policy_digest_sha256'),
        'approval_inferred': False,
        'selectors': results,
        'normal_carrier': normal_cleanup,
        'response_loss_carrier': loss_cleanup,
        'response_loss': packet_recovery,
        'optional_unverified_selector': 'AUTHENTICATED_LIST_SELECTION_REFUSAL_TO_UNVERIFIED_REFERENCE'
            if selection.get('foreign_link_id') else 'NOT_RUN',
        'foreign_owner_hub_guard': 'NOT_RUN',
        'configured_policy': 'NOT_RUN',
        'missing_capabilities': 'NOT_RUN',
        'device_revocation': 'NOT_RUN',
        'third_owner': 'NOT_RUN',
        'process_death_recovery': 'NOT_RUN',
        'hub_stopped_by_driver': False,
        'emulator_stopped_by_driver': False,
        'payload_persisted_by_carrier': False,
        'staging': staged,
        'carrier_commands': carrier_receipts,
    }
    owner_receipt = evidence / ('link-status-owner-' + owner_hash[:16] + '.redacted.json')
    save_private(owner_receipt, summary)
    return {'result': 'PASS', 'owner_receipt': str(owner_receipt), 'my_side': summary['my_side'],
        'link_version': summary['link_version'], 'selectors': len(results),
        'same_encrypted_response_envelope': True}


def aggregate(args):
    left, left_sha = read_private_json(args.owner_a)
    right, right_sha = read_private_json(args.owner_b)
    for item in (left, right):
        if item.get('schema') != OWNER_RESULT_SCHEMA or item.get('result') != 'PASS' or \
                item.get('policy_mode') != 'NONE' or item.get('policy_version') != 0 or \
                item.get('approval_inferred') is not False:
            raise ValueError('each Owner receipt must contain a passing real default-NONE status read')
        selectors = item.get('selectors')
        expected_selectors = {
            'readsCurrentNonePolicyForSelectedOwnerLink',
            'refusesUnknownAndOptionalForeignLinkBeforeStatusRpc',
            'rejectsStaleExpectedLinkVersionBeforeStatusRpc',
            'rejectsGenericStatusRpcBypassWithoutSequenceUse',
            'capturesAndRecoversExactStatusPacket',
        }
        if not isinstance(selectors, list) or len(selectors) != len(expected_selectors) or \
                {row.get('selector') for row in selectors
                if isinstance(row, dict) and row.get('result') == 'PASS'} != expected_selectors or \
                item.get('response_loss', {}).get('same_encrypted_response_envelope') is not True:
            raise ValueError('Owner receipt is missing a passing selector or exact encrypted recovery proof')
    same = ('run_id', 'core_commit', 'source_fingerprint', 'catalog_sha256', 'hub_image',
        'app_sha256', 'test_sha256', 'hub_id_sha256', 'link_id_sha256', 'link_version',
        'policy_mode', 'policy_version', 'policy_digest_sha256')
    if any(left.get(key) != right.get(key) for key in same) or \
            left.get('owner_id_sha256') == right.get('owner_id_sha256') or \
            {left.get('my_side'), right.get('my_side')} != {'SOURCE', 'TARGET'}:
        raise ValueError('two Owner receipts do not identify the same Link with distinct opposite Owner sides')
    source_owner = left if left.get('my_side') == 'SOURCE' else right
    target_owner = right if source_owner is left else left
    output = {
        'schema': AGGREGATE_SCHEMA,
        'result': 'PASS',
        'run_id': left['run_id'],
        'core_commit': left['core_commit'],
        'source_fingerprint': left['source_fingerprint'],
        'catalog_sha256': left['catalog_sha256'],
        'hub_image': left['hub_image'],
        'app_sha256': left['app_sha256'],
        'test_sha256': left['test_sha256'],
        'hub_id_sha256': left['hub_id_sha256'],
        'link_id_sha256': left['link_id_sha256'],
        'link_version': left['link_version'],
        'owner_a_sha256': left['owner_id_sha256'],
        'owner_a_side': left['my_side'],
        'owner_b_sha256': right['owner_id_sha256'],
        'owner_b_side': right['my_side'],
        'same_link_confirmed_from_both_owner_lists': True,
        'policy_mode': 'NONE',
        'bilateral_approval_inferred': False,
        'configured_policy': 'NOT_RUN',
        'third_owner_refusal': 'NOT_RUN',
        'source_owner_id_sha256': source_owner['owner_id_sha256'],
        'target_owner_id_sha256': target_owner['owner_id_sha256'],
        'source_owner_receipt_sha256': left_sha if source_owner is left else right_sha,
        'target_owner_receipt_sha256': right_sha if target_owner is right else left_sha,
    }
    save_private(args.output, output)
    print(json.dumps({'result': 'PASS', 'output': str(args.output),
        'opposite_sides': True, 'bilateral_approval_inferred': False}, separators=(',', ':')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    run = commands.add_parser('run-owner', help='run one real enrolled Owner scope against a supplied Link selector')
    for name in ('evidence', 'fixture', 'public', 'selection', 'run-id', 'tag', 'app-sha256',
            'test-sha256', 'core-commit', 'source-fingerprint', 'catalog-sha256', 'hub-image'):
        run.add_argument('--' + name, required=True)
    run.add_argument('--native-topology')
    run.add_argument('--native-topology-sha256')
    run.add_argument('--fixture-sha256')
    run.add_argument('--public-sha256')
    run.add_argument('--native-mounts')
    run.add_argument('--native-mounts-sha256')
    run.add_argument('--owner', choices=('primary', 'foreign'), required=True)
    run.add_argument('--android-url-port', type=int, required=True)
    run.add_argument('--carrier-port', type=int, default=38097)
    pair = commands.add_parser('aggregate-two-owners', help='require matching SOURCE and TARGET receipts for one real Link')
    pair.add_argument('--owner-a', required=True)
    pair.add_argument('--owner-b', required=True)
    pair.add_argument('--output', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'aggregate-two-owners':
        aggregate(args)
        return
    args.evidence = Path(args.evidence)
    args.fixture = str(Path(args.fixture))
    args.public = str(Path(args.public))
    args.selection = str(Path(args.selection))
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', args.tag) or \
            not 1024 <= args.android_url_port <= 65535 or not 1024 <= args.carrier_port <= 65535 or \
            args.android_url_port == args.carrier_port:
        raise ValueError('run tag or explicit carrier ports are invalid')
    result = run_owner(args)
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(json.dumps({'result': 'FAIL', 'reason': 'bounded Link status interop failed',
            'error_type': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
