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


if __name__ == '__main__':
    unittest.main()
