#!/usr/bin/env python3
"""Guard preparation results against accidental N3 promotion."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('n3_evidence', Path(__file__).with_name('native_app_n3_evidence.py'))
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


class PreparationEvidenceTests(unittest.TestCase):
    def fixture(self, root, all_tests=True):
        run, artifacts = root / 'run', root / 'artifacts'
        run.mkdir(); artifacts.mkdir()
        for name in ('n3.test', 'cicada'): (artifacts / name).write_bytes(b'SYNTHETIC evidence-parser fixture; not executable')
        source = {'head': 'synthetic', 'dirty': True, 'manifest_sha256': 'synthetic', 'files': ev.CONTRACT['files']}
        for side in ('before', 'after'): ev.save(run / ('source-' + side + '.json'), source)
        for lane in ('version', 'compile-cli', 'compile-tests', 'harness', 'vet'): (run / (lane + '.exit')).write_text('0\n')
        for lane in ('version', 'compile-cli', 'compile-tests', 'harness', 'vet'):
            ev.save(run / (lane + '.command.json'), ['docker', 'run', 'synthetic-image', 'go', lane])
        for side in ('before', 'after'):
            ev.save(run / ('binaries-' + side + '.json'), ev.binary_manifest(artifacts))
        (run / 'harness.log').write_text('\n'.join(json.dumps({'Action': 'pass', 'Test': name})
                                                 for name in sorted(ev.EXPECTED) if all_tests))
        return run, artifacts

    def finish(self, run, artifacts, required=True, owned=False):
        with contextlib.redirect_stdout(io.StringIO()):
            code = ev.finish(run, artifacts, 'synthetic-image', required, owned)
        return code, json.loads((run / 'result.json').read_text())

    def test_harness_pass_still_cannot_accept_unrun_n3(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            code, result = self.finish(run, artifacts)
            self.assertEqual(code, 3)
            self.assertEqual(result['harness'], 'SCOPED_PASS')
            self.assertEqual(result['n3_acceptance'], 'NOT_RUN')
            self.assertEqual(result['reviewed_contract']['status'], 'HUB_NODES_ONLY')
            self.assertTrue(result['contract_pin_matches'])
            self.assertTrue(all(state == 'NOT_RUN' for state in result['matrix'].values()))

    def test_empty_cases_and_zero_exits_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp), False)
            code, result = self.finish(run, artifacts)
            self.assertEqual(code, 1)
            self.assertTrue(result['missing_or_unpassed_tests'])
            self.assertEqual(result['actors']['hub'], 'NOT_RUN')

    def test_failure_or_skip_cannot_be_hidden_by_later_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            with (run / 'harness.log').open('a') as f:
                for action in ('fail', 'skip', 'pass'):
                    f.write('\n' + json.dumps({'Action': action, 'Test': 'TestN3HarnessDelayedPacketCancellation'}))
            code, result = self.finish(run, artifacts)
            self.assertEqual(code, 1)
            self.assertEqual(result['test_events']['fail'], 1)

    def test_source_change_and_owned_resource_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            self.assertEqual(self.finish(run, artifacts, owned=True)[0], 1)
            ev.save(run / 'source-after.json', {'head': 'different', 'dirty': True, 'manifest_sha256': 'different'})
            self.assertEqual(self.finish(run, artifacts)[0], 1)

    def test_missing_compiled_binary_is_not_a_harness_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            (artifacts / 'cicada').unlink()
            self.assertEqual(self.finish(run, artifacts)[0], 1)

    def test_execution_evidence_cannot_promote_installation_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            code, result = self.finish(run, artifacts, required=False)
            self.assertEqual(code, 0)
            self.assertTrue(result['executed_binaries_stable'])
            self.assertTrue(result['execution_argv_recorded'])
            self.assertEqual(result['installation_acceptance'], 'NOT_RUN')
            for lane, record in result['execution_commands'].items():
                self.assertEqual(record['sha256'], ev.sha(run / (lane + '.command.json')))

    def lifecycle_fixture(self, root):
        run, artifacts = self.fixture(root)
        source = json.loads((run / 'source-before.json').read_text())
        source['files'] = ev.LIFECYCLE_CONTRACT['files']
        for side in ('before', 'after'):
            ev.save(run / ('source-' + side + '.json'), source)
        (run / 'harness.log').write_text(json.dumps({'Action': 'pass', 'Test': next(iter(ev.LIFECYCLE_EXPECTED))}))
        return run, artifacts

    def test_lifecycle_stays_scoped_and_requires_its_own_source_pins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.lifecycle_fixture(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', False, False, 'app-lifecycle'), 0)
            result = json.loads((run / 'result.json').read_text())
            self.assertEqual(result['app_lifecycle'], 'SCOPED_HARNESS_PASS')
            self.assertEqual(result['n3_acceptance'], 'NOT_RUN')
            self.assertEqual(result['installation_acceptance'], 'NOT_RUN')
            self.assertTrue(result['contract_pin_required'])
            self.assertTrue(result['contract_pin_matches'])
            self.assertEqual(result['reviewed_contract'], ev.LIFECYCLE_CONTRACT)
            self.assertTrue(all(v == 'NOT_RUN' for v in result['matrix'].values()))
            source = json.loads((run / 'source-before.json').read_text())
            source['files'].pop(next(iter(ev.LIFECYCLE_CONTRACT['files'])))
            for side in ('before', 'after'):
                ev.save(run / ('source-' + side + '.json'), source)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', False, False, 'app-lifecycle'), 1)

    def test_lifecycle_zero_match_skip_and_failed_child_never_pass(self):
        for action in (None, 'skip', 'fail'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                run, artifacts = self.lifecycle_fixture(Path(tmp))
                (run / 'harness.log').write_text('' if action is None else json.dumps({'Action': action, 'Test': next(iter(ev.LIFECYCLE_EXPECTED))}))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', False, False, 'app-lifecycle'), 1)

    def app2_fixture(self, root):
        run, artifacts = self.fixture(root)
        (run / 'harness.log').write_text(json.dumps({'Action': 'pass', 'Test': next(iter(ev.APP2_EXPECTED))}))
        (run / 'app2').mkdir()
        report = {'scope': 'APP2_EMPTY_CORE_CONTAINER_ISOLATION_ONLY', 'status': 'SCOPED_PASS',
                  'errors': [], 'owned_container_absent': True, 'inspection': {'mounts_verified': True},
                  'child_test_passed': True, 'binary_stable': True, 'exit_code': 0,
                  'binary_sha256': ev.sha(artifacts / 'n3.test')}
        (run / 'app2/command.json').write_text('["SYNTHETIC parser fixture, not executed"]\n')
        (run / 'app2/stdout.log').write_text('=== RUN   TestN3App2Process\n--- PASS: TestN3App2Process (0.00s)\nPASS\n')
        (run / 'app2/stderr.log').write_text('')
        report['evidence_files'] = {name: ev.sha(run / 'app2' / name)
                                    for name in ('command.json', 'stdout.log', 'stderr.log')}
        ev.save(run / 'app2/receipt.json', report)
        (run / 'app2/supervisor.exit').write_text('0\n')
        return run, artifacts, report

    def app2_finish(self, run, artifacts):
        with contextlib.redirect_stdout(io.StringIO()):
            code = ev.finish(run, artifacts, 'synthetic-image', False, False, 'app2-isolation')
        return code, json.loads((run / 'result.json').read_text())

    def test_app2_harness_never_accepts_business_or_hub_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts, _ = self.app2_fixture(Path(tmp))
            code, result = self.app2_finish(run, artifacts)
            self.assertEqual(code, 0)
            self.assertEqual(result['app2_isolation'], 'SCOPED_HARNESS_PASS')
            self.assertEqual(result['n3_acceptance'], 'NOT_RUN')
            self.assertEqual(result['installation_acceptance'], 'NOT_RUN')
            self.assertEqual(result['actors']['hub'], 'NOT_RUN')
            self.assertTrue(all(value == 'NOT_RUN' for value in result['matrix'].values()))

    def test_app2_requires_supervisor_exit_and_complete_child_receipt(self):
        for bad in (None, [], 'SYNTHETIC invalid receipt', {}):
            with self.subTest(receipt=bad), tempfile.TemporaryDirectory() as tmp:
                run, artifacts, _ = self.app2_fixture(Path(tmp))
                ev.save(run / 'app2/receipt.json', bad)
                self.assertEqual(self.app2_finish(run, artifacts)[0], 1)
        for field, bad in [('owned_container_absent', False), ('inspection', {}),
                           ('child_test_passed', False), ('binary_stable', False),
                           ('binary_sha256', 'other'), ('exit_code', False), ('errors', ['failure'])]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                run, artifacts, report = self.app2_fixture(Path(tmp))
                report[field] = bad; ev.save(run / 'app2/receipt.json', report)
                self.assertEqual(self.app2_finish(run, artifacts)[0], 1)
        for name in ['receipt.json', 'supervisor.exit']:
            with self.subTest(missing=name), tempfile.TemporaryDirectory() as tmp:
                run, artifacts, _ = self.app2_fixture(Path(tmp))
                (run / 'app2' / name).unlink()
                self.assertEqual(self.app2_finish(run, artifacts)[0], 1)
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts, _ = self.app2_fixture(Path(tmp))
            (run / 'app2/stdout.log').write_text('changed after child receipt\n')
            self.assertEqual(self.app2_finish(run, artifacts)[0], 1)
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts, _ = self.app2_fixture(Path(tmp))
            (run / 'harness.log').write_text(json.dumps({'Action': 'skip', 'Test': next(iter(ev.APP2_EXPECTED))}))
            self.assertEqual(self.app2_finish(run, artifacts)[0], 1)

    def test_app2_zero_match_skip_or_failure_cannot_be_a_child_pass(self):
        for body in ['', 'testing: warning: no tests to run\nPASS\n',
                     '=== RUN   TestN3App2Process\n--- SKIP: TestN3App2Process (0.00s)\nPASS\n',
                     '=== RUN   TestN3App2Process\n--- FAIL: TestN3App2Process (0.00s)\n--- PASS: TestN3App2Process (0.00s)\nPASS\n']:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'child.log'; path.write_text(body)
                self.assertFalse(ev.app2_child_passed(path))

    def test_app2_checks_daemon_namespaces_capabilities_and_actual_mounts(self):
        mounts = {'/app2/profile': ('/synthetic/profile', True), '/app2/io': ('/synthetic/io', True),
                  '/tests/n3.test': ('/synthetic/n3.test', False)}
        info = {'Id': 'synthetic-child', 'Image': 'synthetic-image-id',
                'Config': {'Labels': {'cicada.n3.app2.run': 'synthetic-run'}, 'User': '1000:1000',
                           'Image': 'synthetic-image-ref', 'Env': ['CICADA_N3_APP2_CHILD=1']},
                'HostConfig': {'NetworkMode': 'container:synthetic-parent', 'PidMode': '',
                               'IpcMode': 'private', 'Privileged': False, 'CapAdd': None,
                               'CapDrop': ['ALL'], 'ReadonlyRootfs': True, 'PortBindings': {},
                               'SecurityOpt': ['no-new-privileges']},
                'Mounts': [{'Type': 'bind', 'Destination': dst, 'Source': src, 'RW': rw}
                           for dst, (src, rw) in mounts.items()]}
        self.assertTrue(ev.app2_inspection(info, 'synthetic-parent', 'synthetic-run', mounts)['mounts_verified'])
        for field, bad in [('PidMode', 'host'), ('PidMode', 'container:other'), ('IpcMode', 'host'),
                           ('IpcMode', 'container:other'), ('Privileged', True), ('CapAdd', ['SYS_PTRACE']),
                           ('ReadonlyRootfs', False), ('NetworkMode', 'host'), ('SecurityOpt', [])]:
            with self.subTest(field=field):
                other = copy.deepcopy(info); other['HostConfig'][field] = bad
                with self.assertRaises(ValueError): ev.app2_inspection(other, 'synthetic-parent', 'synthetic-run', mounts)
        for extra in [{'Type': 'bind', 'Destination': '/state', 'Source': '/synthetic/App1', 'RW': False},
                      {'Type': 'bind', 'Destination': '/var/run/docker.sock', 'Source': '/var/run/docker.sock', 'RW': True}]:
            other = copy.deepcopy(info); other['Mounts'].append(extra)
            with self.assertRaises(ValueError): ev.app2_inspection(other, 'synthetic-parent', 'synthetic-run', mounts)
        other = copy.deepcopy(info); other['Mounts'][-1]['RW'] = True
        with self.assertRaises(ValueError): ev.app2_inspection(other, 'synthetic-parent', 'synthetic-run', mounts)

    def test_replacing_executed_binary_after_inventory_cannot_pass(self):
        for name in ('cicada', 'n3.test'):
            with self.subTest(binary=name), tempfile.TemporaryDirectory() as tmp:
                run, artifacts = self.fixture(Path(tmp))
                (artifacts / name).write_bytes(b'SYNTHETIC replaced after execution')
                code, result = self.finish(run, artifacts)
                self.assertEqual(code, 1)
                self.assertFalse(result['executed_binaries_stable'])

    def test_missing_malformed_or_changed_binary_inventory_cannot_pass(self):
        for side in ('before', 'after'):
            for value in (None, b'{', b'[]', b'{}'):
                with self.subTest(side=side, value=value), tempfile.TemporaryDirectory() as tmp:
                    run, artifacts = self.fixture(Path(tmp))
                    path = run / ('binaries-' + side + '.json')
                    if value is None: path.unlink()
                    else: path.write_bytes(value)
                    code, result = self.finish(run, artifacts)
                    self.assertEqual(code, 1)
                    self.assertFalse(result['executed_binaries_stable'])

    def test_symlink_cannot_substitute_executed_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            outside = Path(tmp) / 'SYNTHETIC_OUTSIDE_ARTIFACTS'
            outside.write_bytes((artifacts / 'cicada').read_bytes())
            (artifacts / 'cicada').unlink()
            (artifacts / 'cicada').symlink_to(outside)
            for side in ('before', 'after'):
                ev.save(run / ('binaries-' + side + '.json'), ev.binary_manifest(artifacts))
            code, result = self.finish(run, artifacts)
            self.assertEqual(code, 1)
            self.assertNotIn('cicada', result['executed_binary_inventory']['files'])
            self.assertIsNone(result['cicada_binary_sha256'])

    def test_missing_or_invalid_execution_argv_cannot_pass(self):
        for lane in ('version', 'compile-cli', 'compile-tests', 'harness', 'vet'):
            for value in (None, b'{', b'{}', b'[]', b'["docker","run",17,"go"]',
                          b'["docker","run","wrong-image","go","test"]',
                          b'["echo","synthetic-image","go","test"]'):
                with self.subTest(lane=lane, value=value), tempfile.TemporaryDirectory() as tmp:
                    run, artifacts = self.fixture(Path(tmp))
                    path = run / (lane + '.command.json')
                    if value is None: path.unlink()
                    else: path.write_bytes(value)
                    code, result = self.finish(run, artifacts)
                    self.assertEqual(code, 1)
                    self.assertFalse(result['execution_argv_recorded'])

    def test_unreviewed_contract_bytes_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            source = json.loads((run / 'source-before.json').read_text())
            source['files']['docs/hub-app-node-authority-contract.md'] = 'different'
            for side in ('before', 'after'): ev.save(run / ('source-' + side + '.json'), source)
            code, result = self.finish(run, artifacts)
            self.assertEqual(code, 1)
            self.assertFalse(result['contract_pin_matches'])

    def test_actual_discovery_scope_cannot_promote_full_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            (run / 'harness.log').write_text('\n'.join(json.dumps({'Action': 'pass', 'Test': name})
                                                     for name in sorted(ev.DISCOVERY_EXPECTED)))
            with contextlib.redirect_stdout(io.StringIO()):
                code = ev.finish(run, artifacts, 'synthetic-image', False, False, 'discovery')
            result = json.loads((run / 'result.json').read_text())
            self.assertEqual(code, 0)
            self.assertEqual(result['discovery_guard'], 'SCOPED_PASS')
            self.assertEqual(result['matrix']['N3-01'], 'PARTIAL_DISCOVERY_GUARD')
            self.assertEqual(result['n3_acceptance'], 'NOT_RUN')

    def seed_fixture(self, root):
        task = root / 'state' / 'n3-acceptance'
        source = task / 'run-seed' / 'retained-aged-n2'
        source.mkdir(parents=True)
        ev.save(source / 'synthetic-aged-n2-receipt.json', {
            'synthetic_acceptance_only_never_deploy': True, 'seed_source_head': 'SYNTHETIC_SOURCE',
            'writers_stopped_at': '2000-01-01T00:00:00Z', 'immutable_n2_expires_at': '2000-01-01T00:15:00Z'})
        (source / 'SYNTHETIC_NOT_A_DATABASE').write_bytes(b'Synthetic parser fixture; never execute')
        return task, source

    def test_aged_copy_keeps_stopped_synthetic_source_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); task, source = self.seed_fixture(root)
            before = {p.name: p.read_bytes() for p in source.iterdir()}
            ev.copy_aged_seed(source, root / 'copy', task, root / 'copy-receipt.json')
            self.assertEqual(before, {p.name: p.read_bytes() for p in source.iterdir()})
            self.assertEqual(before, {p.name: p.read_bytes() for p in (root / 'copy').iterdir()})
            self.assertTrue(json.loads((root / 'copy-receipt.json').read_text())['copied_after_real_expiry'])

    def test_aged_copy_rejects_escape_symlink_and_unexpired_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); task, source = self.seed_fixture(root)
            with self.assertRaises(ValueError): ev.copy_aged_seed(source, root / 'copy', root / 'unrelated', root / 'receipt')
            (source / 'symlink').symlink_to(source / 'SYNTHETIC_NOT_A_DATABASE')
            with self.assertRaises(ValueError): ev.copy_aged_seed(source, root / 'copy', task, root / 'receipt')
            (source / 'symlink').unlink()
            seed = json.loads((source / 'synthetic-aged-n2-receipt.json').read_text())
            seed['immutable_n2_expires_at'] = '2999-01-01T00:00:00Z'
            ev.save(source / 'synthetic-aged-n2-receipt.json', seed)
            with self.assertRaises(ValueError): ev.copy_aged_seed(source, root / 'copy', task, root / 'receipt')

    def ubuntu_fixture(self, root):
        run, artifacts = self.fixture(root)
        source = {'n3_acceptance': 'SCOPED_PASS', 'exit_code': 0, 'source_stable': True,
                  'source_head': 'SYNTHETIC', 'source_dirty': True, 'source_manifest_sha256': 'SYNTHETIC',
                  'expected_tests': sorted(ev.RUNTIME_EXPECTED | {ev.AGED_TEST}),
                  'test_events': {'pass': len(ev.RUNTIME_EXPECTED) + 1, 'fail': 0, 'skip': 0},
                  'test_binary_sha256': ev.sha(artifacts / 'n3.test'),
                  'cicada_binary_sha256': ev.sha(artifacts / 'cicada')}
        ev.save(run / 'result.json', source)
        ubuntu = root / 'ubuntu'; ubuntu.mkdir()
        ev.ubuntu_prepare(run, artifacts, ubuntu / 'input.json')
        (ubuntu / 'container-os-release').write_text('VERSION_ID="24.04"\nVERSION="24.04.4 LTS"\n')
        (ubuntu / 'container-machine').write_text('x86_64\n')
        for name in ('runtime', 'parse'): (ubuntu / (name + '.exit')).write_text('0\n')
        (ubuntu / 'harness.log').write_text('\n'.join(json.dumps({'Action': 'pass', 'Test': name})
                                                    for name in source['expected_tests']))
        return run, artifacts, ubuntu

    def test_automatic_entry_scope_does_not_promote_old_runtime_or_Windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            (run / 'harness.log').write_text('\n'.join(json.dumps({'Action': 'pass', 'Test': name})
                                                        for name in sorted(ev.AUTO_EXPECTED)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', False, False, 'auto'), 0)
            result = json.loads((run / 'result.json').read_text())
            self.assertEqual(result['auto_status_acceptance'], 'SCOPED_PASS')
            self.assertEqual(result['n3_acceptance'], 'NOT_RUN')
            self.assertEqual(result['Windows_30_second_scheduler'], 'NOT_RUN')
            self.assertEqual(result['matrix']['N3-19'], 'NOT_RUN')
            self.assertEqual(result['matrix']['N3-27'], 'SCOPED_AUTO_CORE_ENTRY_ONLY')
            with (run / 'harness.log').open('a') as f:
                f.write('\n' + json.dumps({'Action': 'skip', 'Test': next(iter(ev.AUTO_EXPECTED))}))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', False, False, 'auto'), 1)

    def test_full_runtime_requires_all_events_and_attributes_clock_per_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.fixture(Path(tmp))
            expected = ev.RUNTIME_EXPECTED | {ev.AGED_TEST}
            (run / 'harness.log').write_text('\n'.join(json.dumps({'Action': 'pass', 'Test': name})
                                                        for name in sorted(expected)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', True, False, 'runtime'), 0)
            with (run / 'harness.log').open('a') as f:
                f.write('\n' + json.dumps({'Action': 'fail', 'Test': 'TestN3ActualAppConsentBindingRelayAndWallClockDecay'}))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.finish(run, artifacts, 'synthetic-image', True, False, 'runtime'), 1)
            result = json.loads((run / 'result.json').read_text())
            self.assertEqual(result['clock_evidence']['heartbeat_decay_120_seconds'], 'NOT_ACCEPTED')

    def test_ubuntu_requires_exact_full_inventory_and_original_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts, ubuntu = self.ubuntu_fixture(Path(tmp))
            source = json.loads((run / 'result.json').read_text())
            source['expected_tests'].remove(next(name for name in source['expected_tests'] if '/' in name))
            ev.save(run / 'result.json', source)
            with self.assertRaises(ValueError): ev.ubuntu_prepare(run, artifacts, ubuntu / 'other.json')
            source['expected_tests'] = sorted(ev.RUNTIME_EXPECTED | {ev.AGED_TEST})
            ev.save(run / 'result.json', source)
            (artifacts / 'n3.test').write_bytes(b'SYNTHETIC DIFFERENT BINARY')
            with self.assertRaises(ValueError): ev.ubuntu_prepare(run, artifacts, ubuntu / 'other.json')

    def test_ubuntu_does_not_promote_physical_or_skip_or_changed_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, artifacts, ubuntu = self.ubuntu_fixture(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.ubuntu_finish(ubuntu, artifacts, 'synthetic-image', False), 0)
            result = json.loads((ubuntu / 'result.json').read_text())
            self.assertEqual(result['physical_Ubuntu_24_04_3'], 'NOT_RUN')
            self.assertEqual(result['Windows_native'], 'NOT_RUN')
            with (ubuntu / 'harness.log').open('a') as f:
                f.write('\n' + json.dumps({'Action': 'skip', 'Test': ev.AGED_TEST}))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.ubuntu_finish(ubuntu, artifacts, 'synthetic-image', False), 1)
            (artifacts / 'n3.test').unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ev.ubuntu_finish(ubuntu, artifacts, 'synthetic-image', False), 1)


if __name__ == '__main__': unittest.main()
