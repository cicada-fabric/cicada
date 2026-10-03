"""Offline regression tests for the bounded v1.6.4 emulator bootstrap helper.

All Android, Docker and APK inputs here are synthetic. No child process is
started; subprocess calls are captured and answered by a local fake.
"""

import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'v164_acceptance_boot_test_subject',
    ROOT / 'scripts/interop/v164-acceptance-boot.py',
)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


class BoundedBootTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='v164-bounded-boot-')
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        self.run_id = 'v16-deterministic-v164-f6-offline-case'
        self.evidence = self.cache / self.run_id / 'android'
        self.app_bytes = b'synthetic-app-apk'
        self.test_bytes = b'synthetic-test-apk'
        self.app = self.cache / 'app.private.apk'
        self.test = self.cache / 'test.private.apk'
        self._private(self.app, self.app_bytes)
        self._private(self.test, self.test_bytes)
        self.hashes = {
            'app': hashlib.sha256(self.app_bytes).hexdigest(),
            'test': hashlib.sha256(self.test_bytes).hexdigest(),
        }
        deadline = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
            datetime.timedelta(minutes=10)
        self.idle_deadline = deadline.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.args = SimpleNamespace(
            execute=True,
            supervisor_pid=os.getppid(),
            run_id=self.run_id,
            evidence_root=str(self.evidence),
            idle_deadline=self.idle_deadline,
            app_apk=str(self.app),
            test_apk=str(self.test),
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _private(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def _fake_runner(self):
        state = {
            'run_id': self.run_id,
            'container': 'cicada-' + self.run_id,
            'image_id': boot.IMAGE,
            'network': 'none',
            'adb_port': 5070,
            'emulator_port': 5640,
        }
        runner = SimpleNamespace(
            SCHEMA='cicada.client-v164-deterministic.v1',
            owned_state=mock.Mock(return_value=state),
            driver=SimpleNamespace(IMAGE=boot.IMAGE, adb=mock.Mock(return_value=['fake-adb'])),
        )
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _module: None))
        return runner, spec

    def _fake_commands(self, *, monotonic_tick=None, marker=None):
        container_id = 'a' * 64
        properties = {
            'ro.build.version.sdk': '35',
            'ro.build.version.release': '15',
            'ro.product.cpu.abi': 'x86_64',
            'ro.kernel.qemu': '1',
        }
        calls = []

        def run(argv, **kwargs):
            calls.append((list(argv), kwargs))
            if monotonic_tick is not None:
                monotonic_tick()
            output = ''
            if argv[:3] == ['docker', 'info', '--format']:
                output = '/gpu1-share/data/docker-root'
            elif argv[:3] == ['docker', 'image', 'inspect']:
                output = boot.IMAGE
            elif len(argv) > 1 and argv[:2] == ['docker', 'run']:
                if marker is not None:
                    self.evidence.mkdir(parents=True, mode=0o700, exist_ok=True)
                    ready = self.evidence / 'emulator-ready.json'
                    self._private(ready, json.dumps(marker, separators=(',', ':')).encode('ascii'))
                output = container_id
            elif len(argv) > 2 and argv[:2] == ['docker', 'inspect']:
                output = container_id if '{{.Id}}' in argv else 'synthetic-inspection'
            elif 'getprop' in argv:
                output = properties[argv[-1]]
            else:
                output = 'Success'
            return SimpleNamespace(returncode=0, stdout=(output + '\n').encode(), stderr=b'')

        return calls, run, properties, container_id

    def _boot_patches(self, runner, spec, run, apk_hashes=None):
        return (
            mock.patch.object(boot, 'CACHE', self.cache),
            mock.patch.object(boot, 'APK_HASHES', apk_hashes or self.hashes),
            mock.patch.object(boot.importlib.util, 'spec_from_file_location', return_value=spec),
            mock.patch.object(boot.importlib.util, 'module_from_spec', return_value=runner),
            mock.patch.object(boot.subprocess, 'run', side_effect=run),
        )

    def test_execute_and_actual_parent_pid_are_required_before_io(self):
        with mock.patch.object(boot, 'CACHE', self.cache):
            self.args.execute = False
            with self.assertRaisesRegex(ValueError, 'approving parent supervisor'):
                boot.boot(self.args)
            self.args.execute = True
            self.args.supervisor_pid = os.getppid() + 1
            with self.assertRaisesRegex(ValueError, 'approving parent supervisor'):
                boot.boot(self.args)
        self.assertFalse(self.evidence.parent.exists())

    def test_bootstrap_keeps_frozen_apk_pins_and_rejects_symlink_or_wrong_digest(self):
        self.assertEqual(boot.APK_HASHES, {
            'app': '56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67',
            'test': 'caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6',
        })
        with mock.patch.object(boot, 'CACHE', self.cache):
            copied = self.root / 'copied.apk'
            boot.copy_apk(self.app, copied, self.hashes['app'])
            self.assertEqual(copied.read_bytes(), self.app_bytes)
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)

            with self.assertRaisesRegex(ValueError, 'differs from its frozen SHA-256'):
                boot.copy_apk(self.app, self.root / 'wrong.apk', '0' * 64)
            alias = self.cache / 'app-alias.apk'
            alias.symlink_to(self.app)
            with self.assertRaisesRegex(ValueError, 'owned bounded private Client cache file'):
                boot.copy_apk(alias, self.root / 'alias-copy.apk', self.hashes['app'])

    def test_boot_receipt_and_all_four_raw_runtime_receipts_are_canonical(self):
        runner, spec = self._fake_runner()
        ready = {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'}
        calls, fake_run, properties, container_id = self._fake_commands(marker=ready)
        stack = self._boot_patches(runner, spec, fake_run)
        with stack[0], stack[1], stack[2], stack[3], stack[4], \
                mock.patch.object(boot.subprocess, 'Popen') as popen:
            result = boot.boot(self.args)

        self.assertEqual(result['result'], 'BOOT_READY')
        receipt_path = Path(result['receipt_path'])
        raw = receipt_path.read_bytes()
        receipt = json.loads(raw)
        self.assertEqual(raw, boot.canonical(receipt))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['receipt_sha256'])
        self.assertEqual(set(receipt), {
            'schema', 'result', 'run_id', 'evidence_root', 'container',
            'container_id', 'image_id', 'network', 'app_sha256', 'test_sha256',
            'runtime_properties', 'ready_observed_at_utc', 'idle_deadline',
            'supervisor_pid', 'cold_boot_elapsed_seconds', 'supervision', 'business',
        })
        self.assertEqual(receipt['result'], 'BOOT_READY')
        self.assertEqual(receipt['container_id'], container_id)
        self.assertEqual(receipt['network'], 'none')
        self.assertEqual(receipt['business'], 'NOT_RUN')
        self.assertEqual(receipt['supervision'], 'LAUNCHER_ONLY')
        self.assertEqual(receipt['app_sha256'], self.hashes['app'])
        self.assertEqual(receipt['test_sha256'], self.hashes['test'])

        for field, (prop, value) in boot.PROPERTIES.items():
            raw_receipt = json.loads((self.evidence / f'runtime-{field}.json').read_bytes())
            self.assertEqual(raw_receipt, {
                'command': ['fake-adb', 'shell', 'getprop', prop],
                'exit_code': 0, 'expected_exit_code': 0,
                'result': 'PASS', 'output': value,
            })
            self.assertEqual(receipt['runtime_properties'][field], properties[prop])
        aggregate = json.loads((self.evidence / 'android-runtime.redacted.json').read_bytes())
        self.assertEqual(aggregate, {
            'schema': runner.SCHEMA, 'image_id': boot.IMAGE,
            'api_level': '35', 'android_release': '15', 'abi': 'x86_64', 'emulator': '1',
        })
        self.assertNotIn('instrument', [arg for argv, _ in calls for arg in argv])
        popen.assert_not_called()

    def test_unexpected_ready_identity_stops_the_single_boot_attempt(self):
        runner, spec = self._fake_runner()
        calls, fake_run, _properties, _container_id = self._fake_commands(
            marker={'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-foreign'},
        )
        stack = self._boot_patches(runner, spec, fake_run)
        with stack[0], stack[1], stack[2], stack[3], stack[4], \
                mock.patch.object(boot.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(ValueError, 'READY marker differs'):
                boot.boot(self.args)
        self.assertEqual(sum(argv[:2] == ['docker', 'run'] for argv, _ in calls), 1)
        popen.assert_not_called()
        self.assertFalse((self.evidence / 'launcher-boot.redacted.json').exists())

    def test_aggregate_boot_budget_stops_before_a_third_command(self):
        runner, spec = self._fake_runner()
        elapsed = [0.0]

        def tick():
            elapsed[0] += 45.0

        calls, fake_run, _properties, _container_id = self._fake_commands(monotonic_tick=tick)
        stack = self._boot_patches(runner, spec, fake_run)
        with stack[0], stack[1], stack[2], stack[3], stack[4], \
                mock.patch.object(boot.time, 'monotonic', side_effect=lambda: elapsed[0]), \
                mock.patch.object(boot.time, 'sleep') as sleep, \
                mock.patch.object(boot.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'budget exhausted'):
                boot.boot(self.args)
        self.assertEqual(len(calls), 2)
        self.assertLessEqual(calls[1][1]['timeout'], 30)
        sleep.assert_not_called()
        popen.assert_not_called()
        self.assertFalse((self.evidence / 'launcher-boot.redacted.json').exists())


if __name__ == '__main__':
    unittest.main()
