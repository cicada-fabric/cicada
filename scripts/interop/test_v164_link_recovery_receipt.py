"""Offline synthetic guards for the redacted v1.6.4 Link recovery receipt."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name('v164-link-consent-android.py')
spec = importlib.util.spec_from_file_location('v164_link_recovery_receipt', SCRIPT)
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)


class ExactRecoveryReceiptTests(unittest.TestCase):
    def receipt(self, **changes):
        value = {
            'schema': interop.RECOVERY_RECEIPT_SCHEMA,
            'result': 'PASS',
            'run_id_sha256': 'a' * 64,
            'phase': 'source-exact-recovery',
            'original_operation': 'link.key_grant',
            'original_operation_id_sha256': 'b' * 64,
            'original_packet_sha256': 'c' * 64,
            'original_request_sequence': '9007199254740993',
            'original_expected_response_sequence': '9007199254740994',
            'observed_response_sequence': '9007199254740994',
            'original_packet_context_verified': True,
            'original_request_sequence_unchanged': True,
            'reconciliation_required': False,
            'pending_after_recovery': False,
            'recovery_state': 'COMPLETED',
            'business_acceptance': 'NOT_ESTABLISHED',
            'recovery_packet_resend_by_test': False,
        }
        value.update(changes)
        return value

    def test_accepts_only_bounded_terminal_transport_receipt(self):
        for phase in ('source-exact-recovery', 'target-exact-recovery'):
            for operation in ('link.key_grant', 'link.review_policy_grant'):
                with self.subTest(phase=phase, operation=operation):
                    value = self.receipt(phase=phase, original_operation=operation)
                    self.assertEqual(interop.validate_exact_recovery_receipt(value), value)

    def test_rejects_unknown_operation_and_malformed_digests(self):
        mutations = (
            {'original_operation': 'link.list'},
            {'original_operation': 'link.key_grant.extra'},
            {'original_operation_id_sha256': 'B' * 64},
            {'original_operation_id_sha256': 'b' * 63},
            {'original_operation_id_sha256': 'g' * 64},
            {'original_packet_sha256': 'C' * 64},
            {'original_packet_sha256': 'c' * 63},
            {'original_packet_sha256': None},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                interop.validate_exact_recovery_receipt(self.receipt(**mutation))

    def test_sequences_must_be_canonical_positive_long_strings_and_match(self):
        invalid_sequences = (0, True, '0', '01', '-1', '+1', ' 1',
            '9223372036854775808', '99999999999999999999')
        for field in ('original_request_sequence', 'original_expected_response_sequence',
                'observed_response_sequence'):
            for sequence in invalid_sequences:
                with self.subTest(field=field, sequence=sequence), self.assertRaises(ValueError):
                    interop.validate_exact_recovery_receipt(self.receipt(**{field: sequence}))
        with self.assertRaises(ValueError):
            interop.validate_exact_recovery_receipt(
                self.receipt(observed_response_sequence='9007199254740993'))

    def test_rejects_false_or_nonboolean_verification_and_terminal_flags(self):
        mutations = (
            {'original_packet_context_verified': False},
            {'original_packet_context_verified': 1},
            {'original_request_sequence_unchanged': False},
            {'original_request_sequence_unchanged': 'true'},
            {'reconciliation_required': True},
            {'reconciliation_required': 0},
            {'pending_after_recovery': True},
            {'pending_after_recovery': None},
            {'recovery_packet_resend_by_test': True},
            {'recovery_packet_resend_by_test': 0},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                interop.validate_exact_recovery_receipt(self.receipt(**mutation))

    def test_rejects_noncompleted_or_acceptance_claims(self):
        for mutation in (
            {'recovery_state': 'STILL_PROCESSING'},
            {'recovery_state': 'OUTCOME_UNCERTAIN'},
            {'recovery_state': 'RECOVERY_UNAVAILABLE'},
            {'business_acceptance': 'ACCEPTED'},
            {'business_acceptance': 'BILATERAL_VERIFIED'},
            {'business_acceptance': 'PASS'},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                interop.validate_exact_recovery_receipt(self.receipt(**mutation))

    def test_rejects_wrong_envelope_or_extra_sensitive_fields(self):
        for mutation in (
            {'schema': 'other'},
            {'result': 'NOT_RUN'},
            {'phase': 'exact-recovery'},
            {'phase': 'owner-exact-recovery'},
            {'phase': 'key-proof-submit'},
            {'run_id_sha256': 'z' * 64},
            {'proof': 'forbidden'},
            {'packet': 'forbidden'},
            {'bilateral_verified': True},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                interop.validate_exact_recovery_receipt(self.receipt(**mutation))
        with self.assertRaises(ValueError):
            interop.validate_exact_recovery_receipt([])
        missing_field = self.receipt()
        del missing_field['original_packet_sha256']
        with self.assertRaises(ValueError):
            interop.validate_exact_recovery_receipt(missing_field)


if __name__ == '__main__':
    unittest.main()
