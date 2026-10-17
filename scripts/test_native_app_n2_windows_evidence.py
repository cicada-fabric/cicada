#!/usr/bin/env python3
"""Synthetic receipt tests only; these never claim Windows API execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('windows_evidence', Path(__file__).with_name('native_app_n2_windows_evidence.py'))
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.build = self.root / 'build.json'
        self.build.write_text(json.dumps({'schema': 'cicada.n2.windows.native-build.v1', 'files': {
            'cicada-appvault-tests.exe': 'c' * 64, 'run-native-app-n2-windows.ps1': 'd' * 64}}))
        self.a, self.b = self.make_phase('A'), self.make_phase('B')

    def actor(self, phase):
        return {'sid': 'S-1-5-21-1-2-3-' + ('1001' if phase == 'A' else '1002'),
                'machine_sha256': 'b' * 64, 'windows_build': '10.0.26200', 'ordinary_user': True}

    def acl(self, label, valid=True):
        directory = label.startswith('directory')
        entries = [{'sid': sid, 'type': 0, 'mask': 0x1f01ff, 'flags': 3 if directory else 0}
                   for sid in [self.actor('A')['sid'], 'S-1-5-18']]
        return {'object': label, 'owner': self.actor('A')['sid'], 'protected': valid,
                'directory': directory, 'sddl': 'SYNTHETIC-SDDL-' + str(valid), 'entries': entries}

    def receipt(self, name, phase):
        item = {'schema': 'cicada.n2.windows.native-result.v1', 'test': name, 'run_id': 'a' * 32,
                **self.actor(phase), 'assertions': ['synthetic-parser-fixture']}
        if name == ev.TESTS[2]:
            item['acls'] = [self.acl(label) for label in ['directory', 'vault', 'lock']]
        if '/' in name:
            acl = self.acl(name.split('/')[1], False)
            item['acls'] = [acl, copy.deepcopy(acl)]
        if name in ev.TESTS[4:]:
            item.update(fixture_sha256='e' * 64, entropy_sha256='f' * 64, producer_sid=self.actor('A')['sid'], unwrap_attempted=True)
        if name == ev.TESTS[6]:
            item['assertions'] = ['exact-transfer-bytes-read-and-hashed', 'same-entropy', 'same-host',
                                  'different-ordinary-user-sid', 'consumer-own-dpapi-control', 'actual-producer-unwrap-rejected']
        return item

    def make_phase(self, phase):
        directory = self.root / phase
        directory.mkdir()
        (directory / 'build-manifest.json').write_bytes(self.build.read_bytes())
        (directory / 'test-list.log').write_text('\n'.join(ev.TESTS) + '\n')
        names = ev.PHASE_A if phase == 'A' else ev.PHASE_B
        cases = []
        for name in names:
            full_names = [name] + ([name + '/' + m for m in ev.TAMPER] if name == ev.TESTS[3] else [])
            receipts = [self.receipt(n, phase) for n in full_names]
            lines = [line for n, receipt in zip(full_names, receipts) for line in
                     [f'=== RUN   {n}', 'N2_NATIVE_RESULT ' + json.dumps(receipt), f'--- PASS: {n} (0.01s)']]
            log = directory / (name + '.log')
            log.write_text('\n'.join(lines + ['PASS']) + '\n')
            cases.append({'name': name, 'exit_code': 0, 'log': log.name, 'log_sha256': ev.sha(log), 'receipts': receipts})
        result = {'schema': 'cicada.n2.windows.native-phase.v1', 'phase': phase, 'run_id': 'a' * 32,
                  'status': 'SCOPED_PASS_PHASE_' + phase, 'exit_code': 0, 'failure': '',
                  'cross_user': 'NOT_RUN' if phase == 'A' else 'CONSUMER_REJECTION_OBSERVED_REQUIRES_MATCHING_PHASE_A',
                  'exe_sha256': 'c' * 64, 'runner_sha256': 'd' * 64, 'build_manifest_sha256': ev.sha(self.build),
                  'context': cases[0]['receipts'][0], 'fixture_sha256': 'e' * 64, 'entropy_sha256': 'f' * 64,
                  'producer_sid': self.actor('A')['sid'], 'tests': cases}
        self.save(directory, result)
        return directory

    def save(self, directory, result):
        (directory / 'result.json').write_text(json.dumps(result))
        index = {p.name: ev.sha(p) for p in directory.iterdir() if p.name != 'artifacts.sha256.json'}
        (directory / 'artifacts.sha256.json').write_text(json.dumps(index))

    def change(self, directory, change):
        result = ev.load(directory / 'result.json')
        change(result)
        for case in result['tests']:
            lines = [line for receipt in case['receipts'] for line in
                     [f"=== RUN   {receipt['test']}", 'N2_NATIVE_RESULT ' + json.dumps(receipt), f"--- PASS: {receipt['test']} (0.01s)"]]
            log = directory / case['log']
            log.write_text('\n'.join(lines + ['PASS']) + '\n')
            case['log_sha256'] = ev.sha(log)
        self.save(directory, result)

    def test_valid_pair_and_absent_consumer_are_distinct(self):
        self.assertEqual(ev.verify_pair(self.a, self.b, self.build)['exit_code'], 0)
        self.assertEqual(ev.verify_pair(self.a, None, self.build)['exit_code'], 2)

    def test_no_tests_skips_failure_duplicate_or_wrong_exit_never_pass(self):
        name, run = ev.TESTS[0], 'a' * 32
        r = self.receipt(name, 'A')
        good = f'=== RUN   {name}\nN2_NATIVE_RESULT {json.dumps(r)}\n--- PASS: {name} (0.01s)\nPASS\n'
        for text, code in [('PASS\n', 0), (good, 1), (good + f'--- SKIP: {name} (0s)\n', 0),
                           (good + f'--- FAIL: {name} (0s)\n', 0), (good + f'--- PASS: {name} (0s)\n', 0)]:
            with self.subTest(code=code, text=text[-40:]), self.assertRaises(ev.InvalidEvidence):
                ev.parse_run(text, name, run, code)

    def test_same_sid_cannot_pass(self):
        def mutate(r):
            r['context']['sid'] = self.actor('A')['sid']
            for case in r['tests']:
                for receipt in case['receipts']:
                    receipt['sid'] = self.actor('A')['sid']
        self.change(self.b, mutate)
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, self.b, self.build)

    def test_different_ciphertext_entropy_or_machine_cannot_pass(self):
        for field in ('fixture_sha256', 'entropy_sha256', 'machine_sha256'):
            with self.subTest(field=field):
                original = {p.name: p.read_bytes() for p in self.b.iterdir()}
                def mutate(r):
                    if field == 'machine_sha256': r['context'][field] = '0' * 64
                    else: r[field] = '0' * 64
                    for case in r['tests']:
                        for receipt in case['receipts']:
                            if field in receipt: receipt[field] = '0' * 64
                self.change(self.b, mutate)
                with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, self.b, self.build)
                for name, raw in original.items(): (self.b / name).write_bytes(raw)

    def test_missing_own_control_or_actual_unwrap_cannot_pass(self):
        self.change(self.b, lambda r: r['tests'][1]['receipts'][0]['assertions'].remove('consumer-own-dpapi-control'))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, self.b, self.build)

    def test_acl_repair_or_broad_positive_acl_cannot_pass(self):
        self.change(self.a, lambda r: r['tests'][2]['receipts'][0]['acls'][0].update(protected=False))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, self.b, self.build)

    def test_wrong_phase_exit_and_tampered_artifact_cannot_pass(self):
        self.change(self.b, lambda r: r.update(exit_code=2))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, self.b, self.build)
        (self.a / 'test-list.log').write_text('PASS\n')
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, None, self.build)

    def test_index_cannot_request_arbitrary_paths(self):
        path = self.a / 'artifacts.sha256.json'
        index = ev.load(path); index['../unrelated-vault'] = '0' * 64
        path.write_text(json.dumps(index))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, None, self.build)

    def test_nonordinary_consumer_is_not_run_not_pass(self):
        result = ev.load(self.b / 'result.json')
        result.update(status='NOT_RUN', exit_code=2, cross_user='NOT_RUN', failure='No ordinary consumer account')
        (self.b / result['tests'][1]['log']).unlink()
        result['tests'] = result['tests'][:1]
        result['context']['ordinary_user'] = False
        result['tests'][0]['receipts'][0]['ordinary_user'] = False
        self.save(self.b, result)
        self.change(self.b, lambda r: None)
        self.assertEqual(ev.verify_pair(self.a, self.b, self.build)['exit_code'], 2)

    def test_missing_case_or_native_nonzero_exit_cannot_pass(self):
        self.change(self.a, lambda r: r['tests'].pop())
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, None, self.build)
        self.change(self.b, lambda r: r['tests'][1].update(exit_code=2))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_phase(self.b, self.build)

    def test_acl_negative_requires_no_repair(self):
        self.change(self.a, lambda r: r['tests'][3]['receipts'][1]['acls'][1].update(sddl='SYNTHETIC-REPAIRED'))
        with self.assertRaises(ev.InvalidEvidence): ev.verify_pair(self.a, None, self.build)


if __name__ == '__main__':
    unittest.main()
