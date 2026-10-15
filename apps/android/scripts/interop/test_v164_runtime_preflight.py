"""Regression coverage for strict v1.6.4 Android runtime receipts."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'v164_runtime_preflight_test_consumer',
    ROOT / 'scripts/interop/v164-link-consent-android.py',
)
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def _f9_runtime():
    return {
        'schema': consumer.runner.SCHEMA,
        'image_id': consumer.runner.driver.IMAGE,
        'api_level': '35',
        'android_release': '15',
        'abi': 'x86_64',
        'emulator': '1',
    }


def _legacy_runtime():
    return {
        'platform': 'Android emulator',
        'emulator_image_id': consumer.runner.driver.IMAGE,
        'api_level': '35',
        'android_release': '15',
        'abi': 'x86_64',
        'emulator': '1',
    }


class RuntimeReceiptTest(unittest.TestCase):
    def test_accepts_exact_f9_and_legacy_producer_shapes(self):
        self.assertEqual(consumer.validate_runtime_receipt(_f9_runtime()), 'f9')
        self.assertEqual(consumer.validate_runtime_receipt(_legacy_runtime()), 'legacy')
        legacy_with_network = {**_legacy_runtime(), 'network': 'none'}
        self.assertEqual(consumer.validate_runtime_receipt(legacy_with_network), 'legacy')

    def test_rejects_image_platform_property_network_and_alias_mismatches(self):
        invalid_f9 = []
        for field, value in (
                ('image_id', 'sha256:' + '0' * 64),
                ('schema', 'cicada.client-v164-other.v1'),
                ('api_level', '34'),
                ('android_release', '14'),
                ('abi', 'arm64-v8a'),
                ('emulator', '0')):
            value_doc = _f9_runtime()
            value_doc[field] = value
            invalid_f9.append(value_doc)
        invalid_f9.extend((
            {**_f9_runtime(), 'network': 'host'},
            {**_f9_runtime(), 'emulator_image_id': 'sha256:' + '0' * 64},
            {**_f9_runtime(), 'platform': 'Android emulator'},
        ))
        invalid_legacy = (
            {**_legacy_runtime(), 'platform': 'Android device'},
            {**_legacy_runtime(), 'emulator_image_id': 'sha256:' + '0' * 64},
            {**_legacy_runtime(), 'emulator': '0'},
            {**_legacy_runtime(), 'network': 'host'},
            {**_legacy_runtime(), 'image_id': 'sha256:' + 'f' * 64},
        )
        for receipt in (*invalid_f9, *invalid_legacy):
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                consumer.validate_runtime_receipt(receipt)


class BootstrapPreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='v164-bootstrap-preflight-')
        self.evidence = Path(self.temp.name)
        self.container_id = 'a' * 64
        self.state = {
            'run_id': 'v16-deterministic-v164-f6-f9-preflight',
            'container': 'cicada-v16-deterministic-v164-f6-f9-preflight',
            'image_id': consumer.runner.driver.IMAGE,
            'network': 'none',
            'adb_port': 5070,
            'emulator_port': 5640,
        }
        self._write('emulator-ready.json', {
            'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'})
        id_command = ['docker', 'inspect', '--format', '{{.Id}}', self.state['container']]
        self._write('container-id.json', {
            'command': id_command, 'exit_code': 0, 'expected_exit_code': 0,
            'result': 'PASS', 'output': self.container_id})
        self._write('emulator-readiness.redacted.json', {
            'container_id': self.container_id,
            'marker': {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'},
            'observed_at_utc': '2026-10-03T12:00:00.000Z', 'result': 'READY'})
        self._write('android-runtime.redacted.json', _f9_runtime())
        for field, (prop, value) in consumer.RUNTIME_PROPERTIES.items():
            self._write('runtime-' + field + '.json', {
                'command': [*consumer.driver.adb(self.state), 'shell', 'getprop', prop],
                'exit_code': 0, 'expected_exit_code': 0, 'result': 'PASS', 'output': value})

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, name, value):
        path = self.evidence / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_readonly_preflight_binds_actual_container_and_raw_properties(self):
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                mock.patch.object(consumer, 'inspect_readonly',
                    side_effect=[self.container_id, 'true running']) as inspect:
            result = consumer.bootstrap_preflight(self.evidence)
        self.assertEqual(result['result'], 'ANDROID_BOOTSTRAP_CHECK_PASS')
        self.assertEqual(result['container_id'], self.container_id)
        self.assertEqual(result['network'], 'none')
        self.assertEqual(result['hub'], 'NOT_CHECKED')
        self.assertEqual(result['root_delivery'], 'NOT_CHECKED')
        self.assertEqual(inspect.call_count, 2)

    def test_readonly_preflight_rejects_wrong_network_and_property_command(self):
        wrong_state = {**self.state, 'network': 'host'}
        with mock.patch.object(consumer.runner, 'owned_state', return_value=wrong_state), \
                self.assertRaises(ValueError):
            consumer.bootstrap_preflight(self.evidence)

        path = self.evidence / 'runtime-emulator.json'
        receipt = json.loads(path.read_text())
        receipt['command'][-1] = 'ro.kernel.qemu.fake'
        self._write('runtime-emulator.json', receipt)
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                mock.patch.object(consumer, 'inspect_readonly',
                    side_effect=[self.container_id, 'true running']), \
                self.assertRaises(ValueError):
            consumer.bootstrap_preflight(self.evidence)

    def test_readonly_preflight_rejects_unbound_ready_id(self):
        readiness = json.loads((self.evidence / 'emulator-readiness.redacted.json').read_text())
        readiness['container_id'] = 'b' * 64
        self._write('emulator-readiness.redacted.json', readiness)
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                self.assertRaises(ValueError):
            consumer.bootstrap_preflight(self.evidence)

    def test_readonly_preflight_rejects_boolean_exit_codes(self):
        for field in ('exit_code', 'expected_exit_code'):
            with self.subTest(field=field):
                path = self.evidence / 'runtime-emulator.json'
                receipt = json.loads(path.read_text())
                receipt[field] = False
                self._write('runtime-emulator.json', receipt)
                with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                        mock.patch.object(consumer, 'inspect_readonly',
                            side_effect=[self.container_id, 'true running']), \
                        self.assertRaises(ValueError):
                    consumer.bootstrap_preflight(self.evidence)
                receipt[field] = 0
                self._write('runtime-emulator.json', receipt)

    def test_readonly_preflight_rejects_live_container_id_mismatch(self):
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                mock.patch.object(consumer, 'inspect_readonly', side_effect=['b' * 64]), \
                self.assertRaises(ValueError):
            consumer.bootstrap_preflight(self.evidence)

    def test_readonly_preflight_rejects_nonrunning_container(self):
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                mock.patch.object(consumer, 'inspect_readonly',
                    side_effect=[self.container_id, 'false exited']), \
                self.assertRaises(ValueError):
            consumer.bootstrap_preflight(self.evidence)

    def test_readonly_preflight_rejects_missing_raw_property_receipt(self):
        (self.evidence / 'runtime-abi.json').unlink()
        with mock.patch.object(consumer.runner, 'owned_state', return_value=self.state), \
                mock.patch.object(consumer, 'inspect_readonly',
                    side_effect=[self.container_id, 'true running']), \
                self.assertRaises(OSError):
            consumer.bootstrap_preflight(self.evidence)


if __name__ == '__main__':
    unittest.main()
