#!/usr/bin/env python3
"""Closed, test-only Root coordination inputs for the clean e2a1908 APK pair.

These files authorize a fixture run, not a Hub operation. Android still checks
its independent Hub/Owner pins, Grant, ciphertext, response sequence and fences.
No Core fixture path, database, secret or bearer is accepted here.
"""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


delivery = load('v164-clean-delivery.py', 'v164_recovery_clean_delivery')
PINS_SCHEMA = 'cicada.client-v164-e2a1908-recovery-apk-pins.v1'
SCENARIO_SCHEMA = 'cicada.client-v164-link-consent-recovery-scenario.v2'
CAPTURE_SCHEMA = 'cicada.client-v164-link-consent-recovery-capture.v2'
RESULT_SCHEMA = 'cicada.client-v164-link-consent-recovery-result.v2'
RUN_SCOPE = 'v164-e2a1908-link-recovery'
HEX64 = re.compile(r'[0-9a-f]{64}')
RUN_ID = re.compile(r'v164-[A-Za-z0-9_-]{1,72}')
MAX_LONG = 9_223_372_036_854_775_807
MODES = ('response-loss', 'processing', 'uncertain', 'legacy')
OPERATIONS = ('link.key_grant', 'link.review_policy_grant')
CORE_KEYS = ('source_revision', 'source_dirty', 'source_fingerprint', 'contract_revision',
    'wire_version', 'catalog_sha256', 'bundle_sha256', 'build_metadata_sha256',
    'hub_image_id', 'test_image_id')
APK_PIN_KEYS = {'schema', 'run_scope', *CORE_KEYS, 'delivery_manifest_sha256',
    'client_build_commit', 'client_build_dirty', 'client_input_sha256', 'app_sha256', 'test_sha256'}


def require(condition, message='invalid recovery fixture input'):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_hash(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def bounded_long(value, minimum=0):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,18}', value) is not None,
        'recovery counter must be a canonical decimal string')
    parsed = int(value)
    require(minimum <= parsed <= MAX_LONG, 'recovery counter outside signed Long')
    return parsed


def read_private_json(path, expected_sha256=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'fixture file path must be absolute without symlinks')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and
        before.st_uid == os.getuid() and before.st_nlink == 1 and 0 < before.st_size <= 256 * 1024,
        'fixture input must be an owned, bounded mode-0600 regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), 'fixture file changed while opening')
        raw = stream.read(256 * 1024 + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == opened.st_size and (opened.st_size, opened.st_mtime_ns) ==
            (after.st_size, after.st_mtime_ns), 'fixture file changed while reading')
    if expected_sha256 is not None:
        require(canonical_hash(expected_sha256) and sha(raw) == expected_sha256,
            'fixture bytes differ from independently provided SHA-256')
    return delivery.parse(raw), raw


def validate_apk_pins(value):
    require(isinstance(value, dict) and set(value) == APK_PIN_KEYS, 'recovery APK pins have unexpected fields')
    require(value['schema'] == PINS_SCHEMA and value['run_scope'] == RUN_SCOPE, 'recovery APK pin scope differs')
    for key in CORE_KEYS:
        require(value[key] == delivery.PINS[key] and type(value[key]) is type(delivery.PINS[key]),
            'recovery APK pins differ from frozen clean e2a1908 delivery')
    require(value['delivery_manifest_sha256'] == delivery.DELIVERY_SHA256,
        'recovery delivery manifest pin differs')
    require(isinstance(value['client_build_commit'], str) and
        re.fullmatch(r'[0-9a-f]{40}', value['client_build_commit']) and
        type(value['client_build_dirty']) is bool, 'Client build attribution is malformed')
    for key in ('client_input_sha256', 'app_sha256', 'test_sha256'):
        require(canonical_hash(value[key]), 'Client APK/input digest is malformed')
    return value


def read_apk_pins(args):
    path = getattr(args, 'recovery_apk_pins', None)
    expected = getattr(args, 'recovery_apk_pins_sha256', None)
    if path is None and expected is None:
        return None
    require(path is not None and expected is not None, 'recovery APK pins require an independent SHA-256')
    require(not any(getattr(args, key, None) is not None for key in
        ('delivery_pins', 'delivery_pins_sha256', 'delivery_metadata', 'delivery_metadata_sha256', 'fixture_root')),
        'recovery and historical F6 coordination lanes cannot be combined')
    value, raw = read_private_json(path, expected)
    validate_apk_pins(value)
    return {**value, 'root_pins_sha256': sha(raw)}


def artifact_fields(pins):
    return {'fixture_lane': RUN_SCOPE, 'recovery_apk_pins_sha256': pins['root_pins_sha256'],
        'core_source_revision': pins['source_revision'], 'core_source_fingerprint': pins['source_fingerprint'],
        'contract_revision': pins['contract_revision'], 'catalog_sha256': pins['catalog_sha256'],
        'wire_version': pins['wire_version'], 'source_dirty': False,
        'pinned_hub_image_id': pins['hub_image_id'], 'pinned_interop_image_id': pins['test_image_id'],
        'apk_source_commit': pins['client_build_commit'], 'apk_source_dirty': pins['client_build_dirty'],
        'apk_input_sha256': pins['client_input_sha256'],
        'app_sha256': pins['app_sha256'], 'test_sha256': pins['test_sha256']}


def validate_scenario(value, run_id=None, operation=None, mode=None):
    require(isinstance(value, dict) and set(value) == {'schema', 'run_id', 'expected_operation', 'fault_mode'} and
        value['schema'] == SCENARIO_SCHEMA and isinstance(value['run_id'], str) and
        RUN_ID.fullmatch(value['run_id']) and value['expected_operation'] in OPERATIONS and
        value['fault_mode'] in MODES, 'recovery scenario has invalid fields or scope')
    require(run_id is None or value['run_id'] == run_id, 'recovery scenario belongs to another run')
    require(operation is None or value['expected_operation'] == operation, 'recovery operation differs from selector')
    require(mode is None or value['fault_mode'] == mode, 'recovery mode differs from selector')
    return value


def case_stem(side, operation, mode):
    require(side in ('source', 'target') and operation in OPERATIONS and mode in MODES)
    return f'{side}-link-recovery-{operation.removeprefix("link.")}-{mode}'


def validate_capture(value, scenario, side):
    validate_scenario(scenario)
    fields = {'schema', 'phase', 'run_id_sha256', 'owner_role', 'expected_operation', 'fault_mode',
        'operation_id_sha256', 'packet_sha256', 'proof_sha256', 'tuple_sha256', 'request_sequence',
        'expected_response_sequence', 'next_sequence', 'last_response_sequence', 'original_pending',
        'original_fence', 'submit_network_error', 'native_confirmed_argument', 'phone_ui_confirmation_observed'}
    require(isinstance(value, dict) and set(value) == fields and value['schema'] == CAPTURE_SCHEMA and
        value['phase'] == 'CAPTURED' and value['owner_role'] == side and
        value['run_id_sha256'] == sha(scenario['run_id'].encode()) and
        value['expected_operation'] == scenario['expected_operation'] and value['fault_mode'] == scenario['fault_mode'],
        'capture receipt scope differs')
    for key in ('run_id_sha256', 'operation_id_sha256', 'packet_sha256', 'proof_sha256', 'tuple_sha256'):
        require(canonical_hash(value[key]), 'capture digest is invalid')
    request = bounded_long(value['request_sequence'], 1)
    response = bounded_long(value['expected_response_sequence'], 1)
    require(bounded_long(value['next_sequence'], 1) == request + 1 and
        bounded_long(value['last_response_sequence']) + 1 == response, 'capture counters differ')
    require(value['original_pending'] is True and value['original_fence'] is True and
        value['submit_network_error'] == 'NETWORK_ERROR' and value['native_confirmed_argument'] is True and
        value['phone_ui_confirmation_observed'] is False, 'capture is not the original transport loss')
    return value


def validate_ready_envelope(value, run_id, capture):
    """Join the Root envelope to redacted Android capture; no packet is exported."""
    require(isinstance(capture, dict), 'Root READY staging requires the original capture reference')
    scenario = {'schema': SCENARIO_SCHEMA, 'run_id': run_id,
        'expected_operation': capture.get('expected_operation'), 'fault_mode': capture.get('fault_mode')}
    validate_capture(capture, scenario, capture.get('owner_role'))
    fields = {'schema', 'run_id', 'hub_source', 'fault_ready_raw_base64', 'fault_ready_raw_sha256', 'restart'}
    require(isinstance(value, dict) and set(value) == fields and
        value['schema'] == 'cicada.client-v164-link-recovery-ready.v1' and value['run_id'] == run_id,
        'Root READY envelope has invalid fields or run')
    expected_source = {'core_revision': delivery.PINS['source_revision'],
        'hub_image_id': delivery.PINS['hub_image_id'], 'source_fingerprint': delivery.PINS['source_fingerprint'],
        'catalog_sha256': delivery.PINS['catalog_sha256'], 'contract_revision': delivery.PINS['contract_revision'],
        'wire_version': 1}
    require(isinstance(value['hub_source'], dict) and set(value['hub_source']) == set(expected_source) and
        all(value['hub_source'][key] == expected and type(value['hub_source'][key]) is type(expected)
            for key, expected in expected_source.items()), 'Root READY source is not the frozen clean delivery')
    encoded = value['fault_ready_raw_base64']
    require(isinstance(encoded, str) and len(encoded) <= 5500, 'Core event encoding is not bounded')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError('Core event encoding is invalid') from error
    require(2 <= len(raw) <= 4096 and raw.endswith(b'\n') and raw.count(b'\n') == 1 and b'\r' not in raw and
        base64.b64encode(raw).decode() == encoded and sha(raw) == value['fault_ready_raw_sha256'],
        'Core FAULT_READY raw bytes or SHA differ')
    event = delivery.parse(raw)
    mode = scenario['fault_mode']
    common = {'event', 'mode', 'operation', 'request_sha256', 'request_sequence', 'business_outcome',
        'handler_executed', 'scope', 'request_status', 'reserved_response_sequence'}
    extra = {'response_sha256'} if mode == 'response-loss' else {'restart_required'}
    require(isinstance(event, dict) and set(event) == common | extra and event['event'] == 'FAULT_READY' and
        event['mode'] == mode and event['operation'] == scenario['expected_operation'] and
        event['request_sha256'] == capture['packet_sha256'] and type(event['request_sequence']) is int and
        event['request_sequence'] == bounded_long(capture['request_sequence'], 1) and
        event['business_outcome'] == 'UNKNOWN' and type(event['reserved_response_sequence']) is int,
        'Core FAULT_READY is not the captured original request')
    response = bounded_long(capture['expected_response_sequence'], 1)
    expected_status, reservation, handler, scope = {
        'response-loss': ('COMPLETED', response, True, 'REAL_HANDLER_COMPLETED_TRANSPORT'),
        'processing': ('PROCESSING', 0, False, 'OUTER_RPC_LEDGER_ONLY'),
        'uncertain': ('PROCESSING', response, False, 'OUTER_RPC_LEDGER_ONLY'),
        'legacy': ('UNCERTAIN', 0, False, 'OUTER_RPC_LEDGER_ONLY'),
    }[mode]
    require(event['request_status'] == expected_status and event['reserved_response_sequence'] == reservation and
        event['handler_executed'] is handler and event['scope'] == scope, 'Core fault claims differ from selected mode')
    restart = value['restart']
    require(isinstance(restart, dict) and set(restart) == {'status', 'receipt_sha256'}, 'Root restart fields differ')
    if mode == 'uncertain':
        require(event['restart_required'] is True and restart['status'] == 'VERIFIED' and
            canonical_hash(restart['receipt_sha256']), 'uncertain requires externally verified isolated restart')
    else:
        require(restart == {'status': 'NOT_REQUIRED', 'receipt_sha256': None}, 'restart is invalid for selected mode')
        if mode == 'response-loss':
            require(canonical_hash(event['response_sha256']), 'Core cached ciphertext digest is malformed')
        else:
            require(event['restart_required'] is False, 'unexpected Core restart request')
    return event


def validate_result(value, capture, scenario, side, ready, ready_raw):
    """Validate a native recovery receipt. Carrier ciphertext comparison remains separate."""
    validate_capture(capture, scenario, side)
    event = validate_ready_envelope(ready, scenario['run_id'], capture)
    require(isinstance(ready_raw, bytes) and delivery.parse(ready_raw) == ready, 'READY raw bytes differ')
    mode = scenario['fault_mode']
    common = {'schema', 'phase', 'run_id_sha256', 'owner_role', 'expected_operation', 'fault_mode',
        'operation_id_sha256', 'packet_sha256', 'proof_sha256', 'tuple_sha256', 'request_sequence',
        'expected_response_sequence', 'capture_next_sequence', 'capture_last_response_sequence',
        'observed_next_sequence', 'observed_last_response_sequence', 'request_status', 'reserved_response_sequence',
        'business_outcome', 'handler_executed', 'scope', 'hub_source_sha256', 'ready_envelope_sha256',
        'fault_ready_raw_sha256', 'recovery_outcome', 'fence_state', 'original_pending_preserved',
        'retired_pending_preserved', 'reconciliation_required', 'native_confirmed_argument',
        'phone_ui_confirmation_observed', 'business_acceptance'}
    extra = {'response_sha256'} if mode == 'response-loss' else {
        'restart_required', 'mutation_attempted', 'mutation_rejected', 'mutation_rejection_code', 'mutation_state_unchanged'}
    if mode == 'uncertain':
        extra |= {'restart_receipt_sha256', 'native_session_error'}
    elif mode != 'response-loss':
        extra |= {'recovery_error_code'}
    require(isinstance(value, dict) and set(value) == common | extra and
        value['schema'] == RESULT_SCHEMA and value['phase'] == 'RECOVERED', 'recovery result fields differ')
    for field in ('run_id_sha256', 'owner_role', 'expected_operation', 'fault_mode', 'operation_id_sha256',
            'packet_sha256', 'proof_sha256', 'tuple_sha256', 'request_sequence', 'expected_response_sequence'):
        require(value[field] == capture[field], 'recovery result differs from immutable capture')
    require(value['capture_next_sequence'] == capture['next_sequence'] and
        value['capture_last_response_sequence'] == capture['last_response_sequence'] and
        value['observed_next_sequence'] == capture['next_sequence'], 'recovery allocated another request sequence')
    expected_last = capture['expected_response_sequence'] if mode in ('response-loss', 'uncertain') else capture['last_response_sequence']
    require(value['observed_last_response_sequence'] == expected_last, 'recovery response counter differs')
    for field in ('request_status', 'business_outcome', 'scope', 'fault_ready_raw_sha256'):
        expected = ready['fault_ready_raw_sha256'] if field == 'fault_ready_raw_sha256' else event[field]
        require(value[field] == expected, 'recovery result differs from Core fault claims')
    require(value['reserved_response_sequence'] == str(event['reserved_response_sequence']) and
        value['handler_executed'] is event['handler_executed'], 'recovery reservation or execution claim differs')
    hub_source_bytes = json.dumps(ready['hub_source'], ensure_ascii=False, separators=(',', ':')).encode()
    require(value['hub_source_sha256'] == sha(hub_source_bytes) and value['ready_envelope_sha256'] == sha(ready_raw),
        'recovery Root envelope attribution differs')
    outcome, fence, pending, retired, reconciliation = {
        'response-loss': ('COMPLETED', 'NONE', False, False, False),
        'processing': ('STILL_PROCESSING', 'STILL_PROCESSING', True, False, True),
        'uncertain': ('OUTCOME_UNCERTAIN', 'UNCERTAIN', False, True, True),
        'legacy': ('RECOVERY_UNAVAILABLE', 'RECOVERY_UNAVAILABLE', True, False, True),
    }[mode]
    require(value['recovery_outcome'] == outcome and value['fence_state'] == fence and
        value['original_pending_preserved'] is pending and value['retired_pending_preserved'] is retired and
        value['reconciliation_required'] is reconciliation and value['native_confirmed_argument'] is True and
        value['phone_ui_confirmation_observed'] is False and value['business_acceptance'] == 'NOT_ESTABLISHED',
        'recovery result state or acceptance boundary differs')
    if mode == 'response-loss':
        require(value['response_sha256'] == event['response_sha256'], 'cached ciphertext expectation differs')
    else:
        rejection = 'LINK_CONSENT_RECOVERY_REQUIRED' if mode == 'uncertain' else 'PENDING_RECOVERY_REQUIRED'
        require(value['restart_required'] is event['restart_required'] and value['mutation_attempted'] is True and
            value['mutation_rejected'] is True and value['mutation_state_unchanged'] is True and
            value['mutation_rejection_code'] == rejection, 'unresolved recovery did not refuse a later local write')
        if mode == 'uncertain':
            require(value['native_session_error'] == 'OUTCOME_UNCERTAIN' and
                value['restart_receipt_sha256'] == ready['restart']['receipt_sha256'],
                'authenticated uncertainty or Root restart attribution differs')
        else:
            require(value['recovery_error_code'] == outcome, 'HTTP409 recovery code differs')
    return value


def validate_carrier_snapshot(value, capture, scenario, ready, ready_raw):
    """Join actual opaque transport evidence; this still cannot establish a grant."""
    validate_capture(capture, scenario, capture.get('owner_role'))
    event = validate_ready_envelope(ready, scenario['run_id'], capture)
    fields = {'state', 'request_sha256', 'response_sha256', 'expected_response_sha256', 'route_sha256',
        'fault_ready_raw_sha256', 'fault_ready_mode', 'request_status', 'root_ready_envelope_sha256',
        'restart_status', 'restart_receipt_sha256', 'request_sequence', 'reserved_response_sequence',
        'frame_count', 'forward_count', 'last_http_status', 'payload_persisted'}
    require(isinstance(value, dict) and set(value) == fields and value['state'] == 'RECOVERY_RESPONDED' and
        value['request_sha256'] == capture['packet_sha256'] and value['payload_persisted'] is False,
        'carrier did not return exactly the authorized original recovery')
    for key in ('response_sha256', 'route_sha256'):
        require(canonical_hash(value[key]), 'carrier actual ciphertext or route digest is malformed')
    require(value['fault_ready_raw_sha256'] == ready['fault_ready_raw_sha256'] and
        value['root_ready_envelope_sha256'] == sha(ready_raw) and value['fault_ready_mode'] == scenario['fault_mode'] and
        value['request_status'] == event['request_status'] and type(value['request_sequence']) is int and
        value['request_sequence'] == int(capture['request_sequence']) and
        type(value['reserved_response_sequence']) is int and
        value['reserved_response_sequence'] == event['reserved_response_sequence'], 'carrier fault attribution differs')
    require(value['restart_status'] == ready['restart']['status'] and
        value['restart_receipt_sha256'] == ready['restart']['receipt_sha256'], 'carrier restart readiness differs')
    require(type(value['frame_count']) is int and type(value['forward_count']) is int and
        2 <= value['frame_count'] == value['forward_count'] <= 256, 'carrier has rejected or unbounded extra requests')
    mode = scenario['fault_mode']
    status = 200 if mode in ('response-loss', 'uncertain') else 409
    require(type(value['last_http_status']) is int and value['last_http_status'] == status,
        'carrier observed HTTP status differs from the selected recovery mode')
    expected = event.get('response_sha256')
    require(value['expected_response_sha256'] == expected, 'carrier Core cached ciphertext expectation differs')
    if mode == 'response-loss':
        require(value['response_sha256'] == expected, 'recovered ciphertext differs from Core cached original bytes')
    return value
