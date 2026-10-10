#!/usr/bin/env python3
"""Offline regressions for strict Root and Android Link recovery receipts."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f'cannot load {filename}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inputs = load('v164_link_recovery_inputs_test', 'v164-link-recovery-inputs.py')
android = load('v164_link_consent_android_test', 'v164-link-consent-android.py')


RUN_ID = 'v164-inputs-regression-slot_1'
LARGE_REQUEST = '9007199254740993'  # Above JavaScript's exact integer range.
LARGE_NEXT = str(int(LARGE_REQUEST) + 1)
LARGE_RESPONSE = str(int(LARGE_REQUEST) + 8)
LARGE_LAST_RESPONSE = str(int(LARGE_RESPONSE) - 1)


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def scenario(operation: str, mode: str, run_id: str = RUN_ID) -> dict[str, str]:
    return {
        'schema': inputs.SCENARIO_SCHEMA,
        'run_id': run_id,
        'expected_operation': operation,
        'fault_mode': mode,
    }


def capture_receipt(operation: str, mode: str, side: str = 'source') -> dict[str, object]:
    expected = int(LARGE_RESPONSE)
    return {
        'schema': inputs.CAPTURE_SCHEMA,
        'phase': 'CAPTURED',
        'run_id_sha256': digest(RUN_ID.encode()),
        'owner_role': side,
        'expected_operation': operation,
        'fault_mode': mode,
        'operation_id_sha256': 'a' * 64,
        'packet_sha256': 'b' * 64,
        'proof_sha256': 'c' * 64,
        'tuple_sha256': 'd' * 64,
        'request_sequence': LARGE_REQUEST,
        'expected_response_sequence': str(expected),
        'next_sequence': LARGE_NEXT,
        'last_response_sequence': LARGE_LAST_RESPONSE,
        'original_pending': True,
        'original_fence': True,
        'submit_network_error': 'NETWORK_ERROR',
        'native_confirmed_argument': True,
        'phone_ui_confirmation_observed': False,
    }


def hub_source() -> dict[str, object]:
    pins = inputs.delivery.PINS
    return {
        'core_revision': pins['source_revision'],
        'hub_image_id': pins['hub_image_id'],
        'source_fingerprint': pins['source_fingerprint'],
        'catalog_sha256': pins['catalog_sha256'],
        'contract_revision': pins['contract_revision'],
        'wire_version': pins['wire_version'],
    }


def ready_envelope(capture: dict[str, object], mode: str | None = None):
    operation = str(capture['expected_operation'])
    mode = mode or str(capture['fault_mode'])
    request_sequence = int(str(capture['request_sequence']))
    expected_response = int(str(capture['expected_response_sequence']))
    event: dict[str, object] = {
        'event': 'FAULT_READY', 'mode': mode, 'operation': operation,
        'request_sha256': capture['packet_sha256'], 'request_sequence': request_sequence,
        'business_outcome': 'UNKNOWN',
    }
    if mode == 'response-loss':
        event.update({
            'request_status': 'COMPLETED', 'reserved_response_sequence': expected_response,
            'handler_executed': True, 'scope': 'REAL_HANDLER_COMPLETED_TRANSPORT',
            'response_sha256': 'e' * 64,
        })
    else:
        status, reservation = {
            'processing': ('PROCESSING', 0),
            'uncertain': ('PROCESSING', expected_response),
            'legacy': ('UNCERTAIN', 0),
        }[mode]
        event.update({
            'request_status': status, 'reserved_response_sequence': reservation,
            'handler_executed': False, 'scope': 'OUTER_RPC_LEDGER_ONLY',
            'restart_required': mode == 'uncertain',
        })
    raw_event = compact(event) + b'\n'
    ready = {
        'schema': 'cicada.client-v164-link-recovery-ready.v1',
        'run_id': RUN_ID,
        'hub_source': hub_source(),
        'fault_ready_raw_base64': base64.b64encode(raw_event).decode('ascii'),
        'fault_ready_raw_sha256': digest(raw_event),
        'restart': ({'status': 'VERIFIED', 'receipt_sha256': 'f' * 64}
            if mode == 'uncertain' else {'status': 'NOT_REQUIRED', 'receipt_sha256': None}),
    }
    ready_raw = compact(ready) + b'\n'
    return ready, ready_raw, event, raw_event


def result_receipt(capture: dict[str, object], ready: dict[str, object], ready_raw: bytes,
        event: dict[str, object], mode: str) -> dict[str, object]:
    outcome, fence, pending, retired, reconcile = {
        'response-loss': ('COMPLETED', 'NONE', False, False, False),
        'processing': ('STILL_PROCESSING', 'STILL_PROCESSING', True, False, True),
        'uncertain': ('OUTCOME_UNCERTAIN', 'UNCERTAIN', False, True, True),
        'legacy': ('RECOVERY_UNAVAILABLE', 'RECOVERY_UNAVAILABLE', True, False, True),
    }[mode]
    source_raw = json.dumps(ready['hub_source'], ensure_ascii=False, separators=(',', ':')).encode()
    value: dict[str, object] = {
        'schema': inputs.RESULT_SCHEMA, 'phase': 'RECOVERED',
        'run_id_sha256': capture['run_id_sha256'], 'owner_role': capture['owner_role'],
        'expected_operation': capture['expected_operation'], 'fault_mode': capture['fault_mode'],
        'operation_id_sha256': capture['operation_id_sha256'], 'packet_sha256': capture['packet_sha256'],
        'proof_sha256': capture['proof_sha256'], 'tuple_sha256': capture['tuple_sha256'],
        'request_sequence': capture['request_sequence'],
        'expected_response_sequence': capture['expected_response_sequence'],
        'capture_next_sequence': capture['next_sequence'],
        'capture_last_response_sequence': capture['last_response_sequence'],
        'observed_next_sequence': capture['next_sequence'],
        'observed_last_response_sequence': capture['expected_response_sequence']
            if mode in ('response-loss', 'uncertain') else capture['last_response_sequence'],
        'request_status': event['request_status'],
        'reserved_response_sequence': str(event['reserved_response_sequence']),
        'business_outcome': event['business_outcome'],
        'handler_executed': event['handler_executed'], 'scope': event['scope'],
        'hub_source_sha256': digest(source_raw), 'ready_envelope_sha256': digest(ready_raw),
        'fault_ready_raw_sha256': ready['fault_ready_raw_sha256'],
        'recovery_outcome': outcome, 'fence_state': fence,
        'original_pending_preserved': pending, 'retired_pending_preserved': retired,
        'reconciliation_required': reconcile, 'native_confirmed_argument': True,
        'phone_ui_confirmation_observed': False, 'business_acceptance': 'NOT_ESTABLISHED',
    }
    if mode == 'response-loss':
        value['response_sha256'] = event['response_sha256']
    else:
        value.update({
            'restart_required': event['restart_required'],
            'mutation_attempted': True, 'mutation_rejected': True,
            'mutation_rejection_code': 'LINK_CONSENT_RECOVERY_REQUIRED'
                if mode == 'uncertain' else 'PENDING_RECOVERY_REQUIRED',
            'mutation_state_unchanged': True,
        })
        if mode == 'uncertain':
            value.update({
                'restart_receipt_sha256': ready['restart']['receipt_sha256'],
                'native_session_error': 'OUTCOME_UNCERTAIN',
            })
        else:
            value['recovery_error_code'] = outcome
    return value


def carrier_snapshot(capture: dict[str, object], ready: dict[str, object], ready_raw: bytes,
        event: dict[str, object], mode: str) -> dict[str, object]:
    actual_response = event.get('response_sha256', '9' * 64)
    return {
        'state': 'RECOVERY_RESPONDED',
        'request_sha256': capture['packet_sha256'],
        'response_sha256': actual_response,
        'expected_response_sha256': event.get('response_sha256'),
        'route_sha256': 'a' * 64,
        'fault_ready_raw_sha256': ready['fault_ready_raw_sha256'],
        'fault_ready_mode': mode,
        'request_status': event['request_status'],
        'root_ready_envelope_sha256': digest(ready_raw),
        'restart_status': ready['restart']['status'],
        'restart_receipt_sha256': ready['restart']['receipt_sha256'],
        'request_sequence': event['request_sequence'],
        'reserved_response_sequence': event['reserved_response_sequence'],
        'frame_count': 4,
        'forward_count': 4,
        'last_http_status': 200 if mode in ('response-loss', 'uncertain') else 409,
        'payload_persisted': False,
    }


class RecoveryInputTests(unittest.TestCase):
    def test_clean_e2_apk_pins_are_closed_and_reject_historical_lane_fields(self) -> None:
        pin_fields = {key: inputs.delivery.PINS[key] for key in inputs.CORE_KEYS}
        pins = {
            'schema': inputs.PINS_SCHEMA, 'run_scope': inputs.RUN_SCOPE, **pin_fields,
            'delivery_manifest_sha256': inputs.delivery.DELIVERY_SHA256,
            'client_build_commit': 'a' * 40, 'client_build_dirty': False,
            'client_input_sha256': '1' * 64, 'app_sha256': '2' * 64, 'test_sha256': '3' * 64,
        }
        self.assertIs(inputs.validate_apk_pins(pins), pins)

        stale_revision = dict(pins, source_revision='c9b2935da17167ce7694abaeffca22aaa0daa3f2')
        with self.assertRaises(ValueError):
            inputs.validate_apk_pins(stale_revision)
        stale_image = dict(pins, hub_image_id='sha256:' + '4' * 64)
        with self.assertRaises(ValueError):
            inputs.validate_apk_pins(stale_image)
        wrong_type = dict(pins, wire_version=True)
        with self.assertRaises(ValueError):
            inputs.validate_apk_pins(wrong_type)
        historical_lane = dict(pins, delivery_pins_sha256='5' * 64)
        with self.assertRaises(ValueError):
            inputs.validate_apk_pins(historical_lane)
        malformed_dirty = dict(pins, client_build_dirty=0)
        with self.assertRaises(ValueError):
            inputs.validate_apk_pins(malformed_dirty)

        args = type('Args', (), {
            'recovery_apk_pins': '/unused/pins.json', 'recovery_apk_pins_sha256': '6' * 64,
            'delivery_pins': '/historical/pins.json',
        })()
        with self.assertRaises(ValueError):
            inputs.read_apk_pins(args)

    def test_each_v2_recovery_selector_accepts_only_its_operation_and_mode(self) -> None:
        self.assertEqual(len(android.RECOVERY_SELECTORS), 8)
        for selector, (operation, mode) in android.RECOVERY_SELECTORS.items():
            with self.subTest(selector=selector):
                candidate = scenario(operation, mode)
                self.assertIs(inputs.validate_scenario(candidate, RUN_ID, operation, mode), candidate)
                other_operation = next(item for item in inputs.OPERATIONS if item != operation)
                with self.assertRaises(ValueError):
                    inputs.validate_scenario(candidate, RUN_ID, other_operation, mode)
                other_mode = next(item for item in inputs.MODES if item != mode)
                with self.assertRaises(ValueError):
                    inputs.validate_scenario(candidate, RUN_ID, operation, other_mode)

        candidate = scenario('link.key_grant', 'response-loss')
        with self.assertRaises(ValueError):
            inputs.validate_scenario(dict(candidate, unexpected='field'))
        with self.assertRaises(ValueError):
            inputs.validate_scenario(dict(candidate, run_id='v164-other-slot'), RUN_ID)

    def test_canonical_long_strings_preserve_values_above_double_precision(self) -> None:
        self.assertEqual(inputs.bounded_long(LARGE_REQUEST, 1), 9_007_199_254_740_993)
        self.assertEqual(inputs.bounded_long(str(inputs.MAX_LONG)), inputs.MAX_LONG)
        for value in (9_007_199_254_740_993, 9_007_199_254_740_992.0, True,
                '09007199254740993', '-1', '+1', '1e3', str(inputs.MAX_LONG + 1)):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                inputs.bounded_long(value, 1)

    def test_capture_receipt_is_closed_and_keeps_large_counters_as_strings(self) -> None:
        current = scenario('link.review_policy_grant', 'uncertain')
        capture = capture_receipt(current['expected_operation'], current['fault_mode'], 'target')
        self.assertIs(inputs.validate_capture(capture, current, 'target'), capture)
        self.assertEqual(inputs.bounded_long(capture['request_sequence']), 9_007_199_254_740_993)

        for field, value in (
            ('request_sequence', 9_007_199_254_740_993),
            ('expected_response_sequence', 9_007_199_254_741_001.0),
            ('next_sequence', True),
            ('last_response_sequence', '09007199254741000'),
        ):
            damaged = dict(capture, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                inputs.validate_capture(damaged, current, 'target')
        with self.assertRaises(ValueError):
            inputs.validate_capture(dict(capture, unexpected='data'), current, 'target')

    def test_all_four_core_fault_modes_bind_raw_jsonl_and_restart_scope(self) -> None:
        for operation in inputs.OPERATIONS:
            for mode in inputs.MODES:
                with self.subTest(operation=operation, mode=mode):
                    current = scenario(operation, mode)
                    capture = capture_receipt(operation, mode)
                    ready, _ready_raw, event, raw_event = ready_envelope(capture)
                    self.assertEqual(inputs.validate_ready_envelope(ready, RUN_ID, capture), event)
                    self.assertGreater(int(event['request_sequence']), 2**53)
                    self.assertEqual(base64.b64decode(ready['fault_ready_raw_base64']), raw_event)

        capture = capture_receipt('link.key_grant', 'uncertain')
        ready, _, _, _ = ready_envelope(capture)
        bad_event = dict(ready)
        bad_event['fault_ready_raw_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            inputs.validate_ready_envelope(bad_event, RUN_ID, capture)
        bad_restart = dict(ready, restart={'status': 'NOT_REQUIRED', 'receipt_sha256': None})
        with self.assertRaises(ValueError):
            inputs.validate_ready_envelope(bad_restart, RUN_ID, capture)
        with self.assertRaises(ValueError):
            inputs.validate_ready_envelope(dict(ready, extra='field'), RUN_ID, capture)

        raw_value = json.loads(base64.b64decode(ready['fault_ready_raw_base64']))
        raw_value['request_sequence'] = True
        raw_event = compact(raw_value) + b'\n'
        malformed = dict(ready, fault_ready_raw_base64=base64.b64encode(raw_event).decode(),
            fault_ready_raw_sha256=digest(raw_event))
        with self.assertRaises(ValueError):
            inputs.validate_ready_envelope(malformed, RUN_ID, capture)

    def test_result_semantics_join_capture_core_event_and_exact_ready_bytes(self) -> None:
        for operation in inputs.OPERATIONS:
            for mode in inputs.MODES:
                with self.subTest(operation=operation, mode=mode):
                    current = scenario(operation, mode)
                    capture = capture_receipt(operation, mode)
                    ready, ready_raw, event, _raw_event = ready_envelope(capture)
                    result = result_receipt(capture, ready, ready_raw, event, mode)
                    self.assertIs(inputs.validate_result(
                        result, capture, current, 'source', ready, ready_raw), result)

        capture = capture_receipt('link.key_grant', 'response-loss')
        ready, ready_raw, event, _raw_event = ready_envelope(capture)
        result = result_receipt(capture, ready, ready_raw, event, 'response-loss')
        with self.assertRaises(ValueError):
            inputs.validate_result(dict(result, packet_sha256='9' * 64), capture,
                scenario('link.key_grant', 'response-loss'), 'source', ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_result(dict(result, response_sha256='8' * 64), capture,
                scenario('link.key_grant', 'response-loss'), 'source', ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_result(result, capture, scenario('link.key_grant', 'response-loss'),
                'source', ready, ready_raw + b' ')

    def test_carrier_snapshot_joins_the_original_ciphertext_and_fault_for_all_modes(self) -> None:
        for operation in inputs.OPERATIONS:
            for mode in inputs.MODES:
                with self.subTest(operation=operation, mode=mode):
                    current = scenario(operation, mode)
                    capture = capture_receipt(operation, mode)
                    ready, ready_raw, event, _raw_event = ready_envelope(capture)
                    snapshot = carrier_snapshot(capture, ready, ready_raw, event, mode)
                    self.assertIs(inputs.validate_carrier_snapshot(
                        snapshot, capture, current, ready, ready_raw), snapshot)
                    self.assertEqual(snapshot['request_sequence'], 9_007_199_254_740_993)

    def test_carrier_rejects_ciphertext_drop_foreign_fault_and_wrapper_mismatches(self) -> None:
        capture = capture_receipt('link.key_grant', 'response-loss')
        current = scenario('link.key_grant', 'response-loss')
        ready, ready_raw, event, _raw_event = ready_envelope(capture)
        good = carrier_snapshot(capture, ready, ready_raw, event, 'response-loss')

        with self.assertRaises(ValueError):
            inputs.validate_carrier_snapshot(dict(good, response_sha256='8' * 64),
                capture, current, ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_carrier_snapshot(dict(good, state='RECOVERY_DROPPED'),
                capture, current, ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_carrier_snapshot(dict(good, last_http_status=409),
                capture, current, ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_carrier_snapshot(good, capture, current, ready, ready_raw + b' ')

        foreign_capture = dict(capture, packet_sha256='7' * 64)
        foreign_ready, foreign_raw, foreign_event, _ = ready_envelope(foreign_capture)
        foreign_snapshot = carrier_snapshot(foreign_capture, foreign_ready, foreign_raw, foreign_event,
            'response-loss')
        with self.assertRaises(ValueError):
            inputs.validate_carrier_snapshot(foreign_snapshot, capture, current, foreign_ready, foreign_raw)

    def test_carrier_status_tracks_processing_legacy_and_uncertain_modes(self) -> None:
        for mode, expected_status in (('processing', 409), ('legacy', 409), ('uncertain', 200)):
            with self.subTest(mode=mode):
                capture = capture_receipt('link.review_policy_grant', mode)
                ready, ready_raw, event, _raw_event = ready_envelope(capture)
                current = scenario('link.review_policy_grant', mode)
                snapshot = carrier_snapshot(capture, ready, ready_raw, event, mode)
                self.assertEqual(snapshot['last_http_status'], expected_status)
                self.assertIs(inputs.validate_carrier_snapshot(
                    snapshot, capture, current, ready, ready_raw), snapshot)
                wrong_status = 200 if expected_status == 409 else 409
                with self.assertRaises(ValueError):
                    inputs.validate_carrier_snapshot(dict(snapshot, last_http_status=wrong_status),
                        capture, current, ready, ready_raw)
                wrong_event_status = 'UNCERTAIN' if mode in ('processing', 'uncertain') else 'PROCESSING'
                with self.assertRaises(ValueError):
                    inputs.validate_carrier_snapshot(dict(snapshot, request_status=wrong_event_status),
                        capture, current, ready, ready_raw)

        capture = capture_receipt('link.key_grant', 'uncertain')
        ready, ready_raw, event, _raw_event = ready_envelope(capture)
        result = result_receipt(capture, ready, ready_raw, event, 'uncertain')
        with self.assertRaises(ValueError):
            inputs.validate_result(dict(result, native_session_error='RECOVERY_UNAVAILABLE'), capture,
                scenario('link.key_grant', 'uncertain'), 'source', ready, ready_raw)
        with self.assertRaises(ValueError):
            inputs.validate_result(dict(result, restart_receipt_sha256='7' * 64), capture,
                scenario('link.key_grant', 'uncertain'), 'source', ready, ready_raw)

    def test_deterministic_receipt_candidates_match_one_immutable_case(self) -> None:
        for side in ('source', 'target'):
            for method, (operation, mode) in android.RECOVERY_SELECTORS.items():
                case = scenario(operation, mode)
                name = f'{side}-link-recovery-{operation.removeprefix("link.")}-{mode}.recovery.redacted.json'
                self.assertEqual(android.receipt_candidates(side, method, case), [(name, 'RECOVERED')])
            for method, operation in android.CAPTURE_SELECTORS.items():
                case = scenario(operation, 'response-loss')
                name = f'{side}-link-recovery-{operation.removeprefix("link.")}-response-loss.capture.redacted.json'
                self.assertEqual(android.receipt_candidates(side, method, case), [(name, 'CAPTURED')])
        with self.assertRaises(ValueError):
            android.receipt_candidates('source', 'recoverKeyResponseLoss')


if __name__ == '__main__':
    unittest.main(verbosity=2)
