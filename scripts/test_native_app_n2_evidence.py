#!/usr/bin/env python3
"""Ensure empty, incomplete and stale acceptance evidence cannot report success."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import subprocess

spec = importlib.util.spec_from_file_location('n2_evidence', Path(__file__).with_name('native_app_n2_evidence.py'))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def test_explicit_missing_resident_is_recorded_not_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'residents.json'
            missing = subprocess.CompletedProcess([], 1, '', 'not found')
            with mock.patch.dict(evidence.os.environ, {'CICADA_N2_RESIDENT_NAMES': 'synthetic-resident'}), mock.patch.object(evidence.subprocess, 'run', return_value=missing):
                evidence.containers(path)
            self.assertEqual(json.loads(path.read_text()), [{'id': 'synthetic-resident', 'missing': True}])

    def test_later_pass_cannot_hide_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'tests.log'
            path.write_text('\n'.join(json.dumps({'Action': action, 'Test': 'TestX', 'Package': 'p'})
                                      for action in ('fail', 'pass')))
            self.assertEqual(evidence.events(path), {('p', 'TestX'): 'fail'})

    def test_missing_log_contains_no_passing_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(evidence.events(Path(tmp) / 'absent.log'), {})

    def test_parser_preserves_skip_and_package_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'tests.log'
            path.write_text('\n'.join(['not JSON', json.dumps({'Action': 'skip', 'Test': 'TestX', 'Package': 'p'}),
                                       json.dumps({'Action': 'pass', 'Package': 'p'})]))
            self.assertEqual(evidence.events(path), {('p', 'TestX'): 'skip'})

    def test_zero_tests_never_pass_even_with_zero_command_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = Path(tmp) / 'run', Path(tmp) / 'artifacts'
            run.mkdir(); artifacts.mkdir()
            source = {'head': 'synthetic', 'dirty': True, 'manifest_sha256': 'synthetic'}
            for name in ('source-before.json', 'source-after.json'):
                evidence.save(run / name, source)
            for name in ('containers-before.json', 'containers-after.json'):
                evidence.save(run / name, [])
            for lane in ('version', 'compile', 'account-process', 'existing-guards', 'vet'):
                (run / (lane + '.exit')).write_text('0\n')
                (run / (lane + '.log')).write_text('')
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                evidence.finish(run, artifacts, 'sha256:synthetic', False, False)
            self.assertEqual(caught.exception.code, 1)
            result = json.loads((run / 'result.json').read_text())
            self.assertEqual(result['baseline'], 'FAIL')
            self.assertEqual(result['n2_acceptance'], 'NOT_RUN')
            self.assertIn('TestN2AccountProcessRecovery/drop/logout', result['missing_or_unpassed_tests'])
            self.assertEqual(result['windows_dpapi'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
