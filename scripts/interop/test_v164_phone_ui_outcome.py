#!/usr/bin/env python3
"""Offline guards for actual Android UI outcomes and bounded stage receipts."""

import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'phone_ui_outcome', Path(__file__).with_name('v164-link-consent-android.py'))
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)


class PhoneUiOutcomeTests(unittest.TestCase):
    def test_junit_failure_overrides_successful_adb_exit(self):
        for log in (
            b'FAILURES!!!\nTests run: 1, Failures: 1\n',
            b'Error in actualReactNativeLinkConsentAlertUsesCurrentExternallySignedReview\n',
            b'INSTRUMENTATION_FAILED: runner stopped\n',
            b'Tests run: 1, Failures: 1\nOK (1 test)\n',
        ):
            with self.subTest(log=log):
                self.assertEqual(interop.classify_phone_ui_instrumentation(log, 0), 'JUNIT_FAILED')

    def test_success_requires_one_completed_test_and_successful_process(self):
        log = b'ai.cicada.client.hub.LinkConsentPhoneUiTest: .\nTime: 3.5\nOK (1 test)\n'
        self.assertEqual(interop.classify_phone_ui_instrumentation(log, 0), 'JUNIT_PASSED')
        self.assertEqual(interop.classify_phone_ui_instrumentation(log, None), 'RUNNING')
        self.assertEqual(interop.classify_phone_ui_instrumentation(log, 1), 'PROCESS_FAILED')
        self.assertEqual(interop.classify_phone_ui_instrumentation(log, False), 'PROCESS_FAILED')

    def test_missing_duplicate_or_other_test_summaries_are_unconfirmed(self):
        for log in (b'', b'OK (0 tests)\n', b'OK (2 tests)\n',
            b'not a summary OK (1 test)\n', b'OK (1 test)\nOK (1 test)\n',
            b'x' * (interop.MAX_OUTPUT + 1)):
            self.assertEqual(interop.classify_phone_ui_instrumentation(log, 0), 'INSTRUMENTATION_UNCONFIRMED')

    def test_real_f28_failure_is_not_a_receipt_timeout(self):
        log = b'''Error in actualReactNativeLinkConsentAlertUsesCurrentExternallySignedReview:
java.lang.IllegalStateException: Could not scroll to the requested visible Link review content
FAILURES!!!
Tests run: 1, Failures: 1
'''
        self.assertEqual(interop.classify_phone_ui_instrumentation(log, 0), 'JUNIT_FAILED')

    def receipt(self, stage='REVIEW_READY'):
        return {'schema': 'cicada.client-v164-phone-ui-prepare.v1',
            'result': 'PASS' if stage == 'REVIEW_READY' else 'FAIL',
            'run_id_sha256': 'a' * 64, 'stage': stage,
            'native_session_methods_called_by_test': False}

    def test_only_fixed_settled_stages_can_be_exported(self):
        for stage in ('REVIEW_READY', 'PREPARE_API_REJECTED', 'DTO_REJECTED', 'REVIEW_INVALIDATED',
            'PREPARE_NOT_STARTED', 'PREPARE_TIMEOUT', 'REVIEW_NOT_VISIBLE'):
            self.assertEqual(interop.validate_phone_ui_prepare_receipt(
                json.dumps(self.receipt(stage)).encode(), 'a' * 64), stage)

    def test_receipts_reject_payloads_wrong_run_and_unsettled_states(self):
        for change in ({'payload': 'forbidden'}, {'stage': 'PREPARING'},
            {'stage': ['REVIEW_READY']}, {'stage': 'arbitrary error text'},
            {'native_session_methods_called_by_test': True}, {'result': 'FAIL'},
            {'run_id_sha256': 'b' * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                interop.validate_phone_ui_prepare_receipt(
                    json.dumps({**self.receipt(), **change}).encode(), 'a' * 64)

    def test_receipts_reject_duplicates_nonobjects_and_oversized_input(self):
        for raw in (b'{}', b'[]', b'null', b'{"stage":"REVIEW_READY","stage":"DTO_REJECTED"}',
            b'x' * 4097, b''):
            with self.assertRaises(ValueError):
                interop.validate_phone_ui_prepare_receipt(raw, 'a' * 64)

    def consent_receipt(self, stage='CONFIRM_READY', **fields):
        return {'schema': 'cicada.client-v164-phone-ui-consent.v1',
            'result': 'PASS' if stage == 'CONFIRM_READY' else 'FAIL',
            'run_id_sha256': 'a' * 64, 'stage': stage,
            'control_count': 1, 'enabled_count': 1, 'busy': False, 'proof_ready': True,
            'native_session_methods_called_by_test': False, **fields}

    def test_readiness_needs_one_enabled_nonbusy_proof_ready_control(self):
        self.assertEqual(interop.validate_phone_ui_consent_receipt(
            json.dumps(self.consent_receipt()).encode(), 'a' * 64)['stage'], 'CONFIRM_READY')
        for change in ({'control_count': 0}, {'control_count': 2}, {'enabled_count': 0},
            {'busy': True}, {'proof_ready': False}, {'proof_ready': None}, {'result': 'FAIL'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                interop.validate_phone_ui_consent_receipt(
                    json.dumps(self.consent_receipt(**change)).encode(), 'a' * 64)

    def test_control_failures_distinguish_unknown_state_from_disabled_or_busy(self):
        cases = [
            ('CONTROL_MISSING', dict(control_count=0, enabled_count=0, busy=None, proof_ready=None)),
            ('CONTROL_MULTIPLE', dict(control_count=2, busy=None, proof_ready=None)),
            ('CONTROL_UNCONFIRMED', dict(busy=None, proof_ready=None)),
            ('CONTROL_BUSY', dict(busy=True, proof_ready=None, enabled_count=0)),
            ('PROOF_INVALID', dict(proof_ready=False, enabled_count=0)),
            ('CONTROL_DISABLED', dict(enabled_count=0)),
            ('ACCESSIBILITY_CLICK_FAILED', {}),
        ]
        for stage, changes in cases:
            with self.subTest(stage=stage):
                self.assertEqual(interop.validate_phone_ui_consent_receipt(
                    json.dumps(self.consent_receipt(stage, **changes)).encode(), 'a' * 64)['stage'], stage)
        with self.assertRaises(ValueError):
            interop.validate_phone_ui_consent_receipt(
                json.dumps(self.consent_receipt('CONTROL_MISSING', control_count=0,
                    enabled_count=0, busy=False, proof_ready=False)).encode(), 'a' * 64)

    def test_control_receipts_reject_payloads_invalid_types_and_wrong_run(self):
        for change in ({'tree': 'forbidden'}, {'proof': 'forbidden'}, {'control_count': True},
            {'control_count': 3}, {'enabled_count': -1}, {'busy': 0}, {'proof_ready': 'true'},
            {'stage': ['CONFIRM_READY']}, {'stage': 'exception body'}, {'result': 'SUCCESS'},
            {'run_id_sha256': 'b' * 64}, {'native_session_methods_called_by_test': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                interop.validate_phone_ui_consent_receipt(
                    json.dumps(self.consent_receipt(**change)).encode(), 'a' * 64)

    def test_control_receipts_reject_duplicates_nonobjects_and_oversized_input(self):
        for raw in (b'{}', b'[]', b'null', b'{"busy":true,"busy":false}', b'x' * 4097, b''):
            with self.assertRaises(ValueError):
                interop.validate_phone_ui_consent_receipt(raw, 'a' * 64)


if __name__ == '__main__':
    unittest.main()
