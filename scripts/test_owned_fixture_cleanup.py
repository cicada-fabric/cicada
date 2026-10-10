"""Synthetic Docker replies exercise exact ownership and absence decisions."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import owned_fixture_cleanup as cleanup

CID = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64


class Docker:
    def __init__(self):
        self.containers = {}
        self.images = {}
        self.calls = []
        self.daemon_error = False
        self.rm_error = False
        self.reappear = False

    def __call__(self, argv):
        self.calls.append(argv)
        if self.daemon_error:
            return subprocess.CompletedProcess(argv, 1, '', 'Cannot connect to the Docker daemon')
        if argv[1:3] in (['container', 'inspect'], ['image', 'inspect']):
            kind, selector = argv[1], argv[3]
            if kind == 'container':
                row = next((row for row in self.containers.values() if selector in (row[0], row[1][1:])), None)
                output = '|'.join(row) if row else None
            else:
                output = self.images.get(selector)
            if output is None:
                return subprocess.CompletedProcess(argv, 1, '\n', f'Error response from daemon: No such {kind}: {selector}\n')
            return subprocess.CompletedProcess(argv, 0, output + '\n', '')
        if argv[1:3] == ['rm', '-f']:
            if self.rm_error:
                return subprocess.CompletedProcess(argv, 1, '', 'closed synthetic failure')
            row = self.containers.pop(argv[3])
            if self.reappear:
                self.containers['c' * 64] = ['c' * 64, row[1], *row[2:]]
        elif argv[1:3] == ['image', 'rm']:
            self.images.pop(argv[3])
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, '', '')


class OwnedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'scratch'
        self.root.mkdir(mode=0o700)
        self.docker = Docker()
        self.plan = cleanup.prepare(self.root, 'run-001', 'node-control-v1',
                                    [('test', 'owned-test', IMAGE)], [], self.docker)

    def created(self):
        (self.root / 'test.cid').write_text(CID)
        self.docker.containers[CID] = [CID, '/owned-test', IMAGE, 'run-001', 'test']

    def test_verified_cid_removed_and_both_selectors_absent(self):
        self.created()
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'CONFIRMED')
        row = receipt['resources'][0]
        self.assertEqual(row['labels_observed'], row['labels_intended'])
        self.assertEqual(row['ownership'], 'VERIFIED')
        self.assertEqual(row['post_cleanup'], 'EXACT_ABSENT')
        self.assertEqual(receipt['scratch']['post_cleanup'], 'EXACT_ABSENT')
        self.assertEqual(receipt['scratch']['creation_proof'], 'MKDTEMP_INODE')
        self.assertEqual(receipt['scratch']['ownership'], 'VERIFIED')
        self.assertEqual(receipt['scratch']['uid'], os.getuid())
        self.assertEqual(row['expected_image_id'], IMAGE)
        self.assertIn(['docker', 'rm', '-f', CID], self.docker.calls)
        self.assertNotIn(['docker', 'rm', '-f', 'owned-test'], self.docker.calls)

    def test_not_created_exact_absence(self):
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'CONFIRMED')
        self.assertEqual(receipt['resources'][0]['creation_proof'], 'NOT_CREATED')

    def test_daemon_error_unknown_no_deletion(self):
        self.created()
        self.docker.daemon_error = True
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'UNKNOWN')
        self.assertTrue(self.root.exists())
        self.assertFalse(any(argv[1:3] == ['rm', '-f'] for argv in self.docker.calls))
        self.assertNotIn('Cannot connect', json.dumps(receipt))

    def test_wrong_label_image_name_and_role_do_not_remove(self):
        for index, wrong in ((1, '/wrong'), (2, 'sha256:' + 'c' * 64), (3, 'other-run'), (4, 'hub')):
            with self.subTest(index=index):
                self.created()
                self.docker.containers[CID][index] = wrong
                receipt = cleanup.cleanup(self.plan, call=self.docker)
                self.assertEqual(receipt['status'], 'UNKNOWN')
                self.assertEqual(receipt['resources'][0]['ownership'], 'MISMATCH')
                self.assertIn(CID, self.docker.containers)

    def test_missing_cidfile_never_adopts_existing_container(self):
        self.created()
        (self.root / 'test.cid').unlink()
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'UNKNOWN')
        self.assertIn(CID, self.docker.containers)

    def test_malformed_cidfile_not_not_created(self):
        (self.root / 'test.cid').write_text('not-an-id')
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'UNKNOWN')

    def test_auto_removed_without_observed_labels_is_unknown(self):
        (self.root / 'test.cid').write_text(CID)
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'UNKNOWN')
        self.assertEqual(receipt['resources'][0]['post_cleanup'], 'EXACT_ABSENT')

    def test_rm_error_does_not_infer_absence(self):
        self.created()
        self.docker.rm_error = True
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertNotEqual(receipt['status'], 'CONFIRMED')
        self.assertIn(CID, self.docker.containers)

    def test_name_replacement_after_exact_cid_removal_is_failed(self):
        self.created()
        self.docker.reappear = True
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertIn('c' * 64, self.docker.containers)

    def test_scratch_identity_replacement_is_not_removed(self):
        original = self.root.with_name('original')
        self.root.rename(original)
        self.root.mkdir(mode=0o700)
        receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertNotEqual(receipt['status'], 'CONFIRMED')
        self.assertTrue(self.root.exists())
        self.assertTrue(original.exists())
        self.assertEqual(receipt['scratch']['ownership'], 'MISMATCH')

    def test_scratch_removal_error_is_failed(self):
        with patch.object(cleanup.shutil, 'rmtree', side_effect=OSError('synthetic secret')):
            receipt = cleanup.cleanup(self.plan, call=self.docker)
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertNotIn('synthetic secret', json.dumps(receipt))

    def test_fresh_image_tag_removal_uses_tag_not_shared_id(self):
        plan = cleanup.prepare(self.root, 'run-001', 'client', [],
                               [('hub-image', 'fresh:hub')], self.docker)
        self.docker.images['fresh:hub'] = IMAGE
        receipt = cleanup.cleanup(plan, {'image': {'id': IMAGE}}, self.docker)
        self.assertEqual(receipt['status'], 'CONFIRMED')
        self.assertIn(['docker', 'image', 'rm', 'fresh:hub'], self.docker.calls)
        self.assertEqual(receipt['resources'][0]['expected_image_id'], IMAGE)
        self.assertEqual(receipt['resources'][0]['id'], IMAGE)
        self.assertFalse(any(argv == ['docker', 'image', 'rm', IMAGE] for argv in self.docker.calls))

    def test_wrong_image_tag_target_not_removed(self):
        plan = cleanup.prepare(self.root, 'run-001', 'client', [],
                               [('hub-image', 'fresh:hub')], self.docker)
        self.docker.images['fresh:hub'] = 'sha256:' + 'c' * 64
        receipt = cleanup.cleanup(plan, {'image': {'id': IMAGE}}, self.docker)
        self.assertEqual(receipt['status'], 'UNKNOWN')
        self.assertIn('fresh:hub', self.docker.images)

    def test_missing_reply_is_exact_selector_and_kind_only(self):
        for stderr in ('Error response from daemon: No such container: other',
                       'Error response from daemon: No such image: owned-test',
                       'Error response from daemon: No such container: owned-test\nsecret'):
            with self.subTest(stderr=stderr):
                reply = lambda argv: subprocess.CompletedProcess(argv, 1, '[]', stderr)
                self.assertEqual(cleanup.inspect('container', 'owned-test', reply)[0], 'UNKNOWN')
        for prefix in ('Error', 'error', 'Error response from daemon'):
            reply = lambda argv: subprocess.CompletedProcess(argv, 1, '[]', prefix + ': No such container: owned-test')
            self.assertEqual(cleanup.inspect('container', 'owned-test', reply)[0], 'EXACT_ABSENT')

    def test_receipt_private_and_exclusive(self):
        path = Path(self.temp.name) / 'receipt.json'
        cleanup.write(path, {'status': 'UNKNOWN'})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            cleanup.write(path, {'status': 'CONFIRMED'})
        self.assertEqual(json.loads(path.read_text())['status'], 'UNKNOWN')

    def test_preexisting_name_or_tag_refuses_creation(self):
        self.created()
        with self.assertRaisesRegex(ValueError, 'CONTAINER_NAME_NOT_ABSENT'):
            cleanup.prepare(self.root, 'run-001', 'client', [('test', 'owned-test', IMAGE)], [], self.docker)
        self.docker.images['existing:hub'] = IMAGE
        with self.assertRaisesRegex(ValueError, 'IMAGE_TAG_NOT_ABSENT'):
            cleanup.prepare(self.root, 'run-001', 'client', [], [('hub-image', 'existing:hub')], self.docker)


class NodeControlCleanupTests(unittest.TestCase):
    def test_actual_driver_command_and_interrupt_cleanup(self):
        path = Path(__file__).with_name('test-node-control-v1-flow.py')
        spec = importlib.util.spec_from_file_location('node_control_driver', path)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        for interrupted, source_changed in ((False, False), (True, False), (False, True)):
            with self.subTest(interrupted=interrupted, source_changed=source_changed), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'output'
                module_cache = Path(temporary) / 'gomod'
                module_cache.mkdir()
                docker = Docker()
                actual = []

                def invoke(argv, **kwargs):
                    if argv[1:] == ['info']:
                        return subprocess.CompletedProcess(argv, 0, '', '')
                    if argv[1:3] == ['image', 'inspect']:
                        return subprocess.CompletedProcess(argv, 0, IMAGE + '\n', '')
                    if argv[1] == 'run':
                        actual.append(argv)
                        name = argv[argv.index('--name') + 1]
                        Path(argv[argv.index('--cidfile') + 1]).write_text(CID)
                        docker.containers[CID] = [CID, '/' + name, IMAGE, 'test-run', 'test']
                        if interrupted:
                            raise InterruptedError('not logged synthetic secret')
                        event = dict(Action='pass', Test=driver.TEST_NAME)
                        return subprocess.CompletedProcess(argv, 0, json.dumps(event) + '\n', '')
                    return docker(argv)

                environment = {'CICADA_NODE_CONTROL_GOMODCACHE': str(module_cache),
                               'CICADA_COMPLETION_CHILD_RUN_ID': 'test-run',
                               'CICADA_COMPLETION_CHILD_LANE': 'node-control-v1'}
                def source_info(_repo, destination):
                    # The fingerprint stays identical; only the complete source
                    # inventory reveals the after-run change.
                    metadata = {'source': {'source_fingerprint': 'a' * 64,
                                           'input_inventory': {'entries': ['synthetic-' + 'x' * 600000]}},
                                'extra_source_domain': 'changed' if source_changed and destination.stem == 'source-after' else 'same'}
                    driver.write_json(destination, metadata)
                    return 0, metadata, ''

                with patch.dict(os.environ, environment), \
                     patch('sys.argv', [str(path), '--run', '--output-dir', str(output)]), \
                     patch.object(driver.shutil, 'which', return_value='/synthetic/tool'), \
                     patch.object(driver, 'read_source_info', side_effect=source_info), \
                     patch.object(cleanup.subprocess, 'run', side_effect=invoke), \
                     patch('builtins.print'):
                    self.assertEqual(driver.main(), 2 if interrupted or source_changed else 0)
                argv = actual[0]
                for flag, value in (('--cpus', '2'), ('--memory', '3g'), ('--pids-limit', '256'),
                                    ('--cap-drop', 'ALL'), ('--security-opt', 'no-new-privileges')):
                    self.assertEqual(argv[argv.index(flag) + 1], value)
                self.assertNotIn('--rm', argv)
                self.assertIn(cleanup.LABEL + '=test-run', argv)
                self.assertIn(cleanup.ROLE_LABEL + '=test', argv)
                result = json.loads(next(output.glob('*/result.json')).read_text())
                self.assertEqual(result['fixture_cleanup_status'], 'CONFIRMED')
                self.assertEqual(result['status'], 'BLOCKED' if interrupted else 'FAIL' if source_changed else 'PASS')
                self.assertEqual(result['cleanup']['temporary_container'], 'ABSENT')
                self.assertEqual(result['cleanup']['scratch'], 'REMOVED')
                self.assertNotIn('synthetic secret', json.dumps(result))
                self.assertFalse(docker.containers)
                result_path = next(output.glob('*/result.json'))
                self.assertLess(result_path.stat().st_size, 16 * 1024)
                self.assertGreater((result_path.parent / 'source-before.json').stat().st_size, 600000)
                self.assertNotIn('input_inventory', result['source_before'])
                self.assertEqual((result_path.parent / 'source-before.json').stat().st_mode & 0o777, 0o600)
                from scripts import completion_runner
                if not interrupted:
                    reduced = completion_runner.reduce_node_control_source(result, result_path, 'test-run')
                    self.assertEqual(reduced['status'], 'FAILED' if source_changed else 'CONFIRMED')

    def test_preflight_failure_cleans_only_unmounted_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'scratch'
            root.mkdir(mode=0o700)
            docker = Docker()
            docker.containers[CID] = [CID, '/collision', IMAGE, 'other-run', 'test']
            with self.assertRaises(cleanup.PreflightFailure) as caught:
                cleanup.prepare(root, 'run-001', 'client', [('test', 'collision', IMAGE)], [], docker)
            result = cleanup.cleanup(caught.exception.plan, call=docker)
            self.assertEqual(result['status'], 'UNKNOWN')
            self.assertEqual(result['scratch']['post_cleanup'], 'EXACT_ABSENT')
            self.assertIn(CID, docker.containers)
            self.assertFalse(any(argv[1:3] == ['rm', '-f'] for argv in docker.calls))


if __name__ == '__main__':
    unittest.main()
