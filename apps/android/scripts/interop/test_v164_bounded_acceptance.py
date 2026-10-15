"""Synthetic, offline tests for the v1.6.4 bounded launcher.

These tests mock filesystem trust boundaries where a validator needs isolated
input bytes and use fake child processes. They never run Docker, a Hub, Android,
the emulator, an enrollment, or an Owner signer.
"""

import copy
import datetime as dt
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'v164_bounded_acceptance_test_subject',
    ROOT / 'scripts/interop/v164-bounded-acceptance.py',
)
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)
HOT_SPEC = importlib.util.spec_from_file_location(
    'v164_acceptance_hot_test_subject',
    ROOT / 'scripts/interop/v164-acceptance-hot.py',
)
hot = importlib.util.module_from_spec(HOT_SPEC)
HOT_SPEC.loader.exec_module(hot)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _utc(offset_seconds=0):
    value = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) + dt.timedelta(seconds=offset_seconds)
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def _line(value):
    return engine.canonical(value)


class BoundedAcceptanceTest(unittest.TestCase):
    def setUp(self):
        engine._TICKET_FD = None
        engine._STOP = False
        self.temp = tempfile.TemporaryDirectory(prefix='v164-bounded-tests-')
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.cache = self.root / 'cache'
        self.repo.mkdir(mode=0o700)
        self.cache.mkdir(mode=0o700)
        self.patch_roots = (
            mock.patch.object(engine, 'REPO', self.repo),
            mock.patch.object(engine, 'CACHE', self.cache),
        )
        for patcher in self.patch_roots:
            patcher.start()
        self.addCleanup(lambda: [patcher.stop() for patcher in reversed(self.patch_roots)])

    def tearDown(self):
        engine._TICKET_FD = None
        engine._STOP = False
        self.temp.cleanup()

    def _file(self, path, content, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = content if isinstance(content, bytes) else content.encode('utf-8')
        path.write_bytes(raw)
        path.chmod(mode)
        return path, raw

    def _source_refs(self, roles):
        result = {}
        for index, role in enumerate(roles):
            path, raw = self._file(self.repo / f'{role}.py', f'# synthetic {role} {index}\n', 0o644)
            result[role] = {
                'path': str(path), 'sha256': _sha(raw), 'role': role,
            }
        return result

    def _bootstrap(self):
        run_id = 'v16-deterministic-v164-f6-unit-synthetic'
        app, _ = self._file(self.cache / 'app.apk', b'synthetic app')
        test, _ = self._file(self.cache / 'test.apk', b'synthetic test')
        refs = self._source_refs(('boot', 'runtime_consumer', 'stop_runner'))
        plan = {
            'schema': engine.BOOT_PLAN_SCHEMA,
            'approval_id': 'offline-test-approval',
            'client_commit': '1' * 40,
            'target': {
                'core_commit': engine.CORE_COMMIT,
                'contract_revision': 'client-hub-v1.6.4',
                'wire_version': 1,
                'schema_version': 57,
                'operation_count': 55,
                'contract_archive_sha256': engine.CONTRACT_ARCHIVE_SHA256,
                'source_fingerprint': engine.CORE_SOURCE_FINGERPRINT,
                'source_dirty': False,
                'hub_image_id': engine.HUB_IMAGE,
                'interop_image_id': engine.INTEROP_IMAGE,
                'catalog_sha256': engine.CATALOG_SHA256,
            },
            'android': {
                'run_id': run_id,
                'evidence_root': str(self.cache / run_id / 'android'),
                'image_id': engine.EMULATOR_IMAGE,
                'network': 'none',
                'app': {'path': str(app), 'sha256': engine.APK_HASHES['app']},
                'test': {'path': str(test), 'sha256': engine.APK_HASHES['test']},
            },
            'docker_root': engine.DOCKER_ROOT,
            'cache_root': str(self.cache),
            'source_refs': refs,
            'launcher_evidence_root': str(self.cache / 'offline-launcher-evidence' / 'run-1'),
            'idle_deadline': _utc(600),
            'timeouts': {
                'boot_seconds': 90, 'command_seconds': 180,
                'carrier_ready_seconds': 60, 'cleanup_seconds': 20,
            },
        }
        return plan

    def _validated_bootstrap(self):
        plan = self._bootstrap()
        digest = _sha(_line(plan))
        result = engine.validate_bootstrap_document(
            plan, digest, verify_checkout=False, verify_apks=False,
        )
        return plan, digest, result

    def test_exact_bootstrap_plan_accepts_the_fixed_offline_target(self):
        plan, digest, result = self._validated_bootstrap()
        self.assertEqual(result['run_id'], plan['android']['run_id'])
        self.assertEqual(result['idle_deadline'], plan['idle_deadline'])
        self.assertEqual(digest, _sha(engine.canonical(plan)))

    def test_utc_timestamps_and_deadline_do_not_gain_time_after_wall_clock_moves_back(self):
        stamp = engine._utc_now()
        self.assertTrue(stamp.endswith('Z'))
        self.assertLess(abs(engine._utc(stamp, 'test timestamp') -
            dt.datetime.now(dt.timezone.utc).timestamp()), 1.0)

        deadline = engine.Deadline(2000.0, '1970-01-01T00:33:20Z', monotonic_epoch=105.0)
        with mock.patch.object(engine.time, 'time', return_value=1900.0), \
                mock.patch.object(engine.time, 'monotonic', return_value=100.0):
            capped = engine.Deadline.earliest([deadline])
            self.assertEqual(capped.monotonic_epoch, 105.0)
            self.assertEqual(capped.remaining(), 5.0)
        with mock.patch.object(engine.time, 'time', return_value=1800.0), \
                mock.patch.object(engine.time, 'monotonic', return_value=101.0):
            self.assertEqual(deadline.remaining(), 4.0)

    def test_bootstrap_plan_rejects_schema_target_scope_timeouts_and_bad_source_pins(self):
        plan, _, _ = self._validated_bootstrap()
        mutations = (
            lambda value: value.update(extra='unexpected'),
            lambda value: value.update(schema='cicada.client-v164-bootstrap.v2'),
            lambda value: value['target'].update(contract_revision='client-hub-v9'),
            lambda value: value['target'].update(hub_image_id='sha256:invalid'),
            lambda value: value['android'].update(network='bridge'),
            lambda value: value['android']['app'].update(sha256='0' * 64),
            lambda value: value['timeouts'].update(boot_seconds=True),
            lambda value: value.update(idle_deadline=_utc(90)),
        )
        for mutate in mutations:
            bad = copy.deepcopy(plan)
            mutate(bad)
            with self.subTest(plan=bad), self.assertRaises(engine.PlanError):
                engine.validate_bootstrap_document(bad, verify_checkout=False, verify_apks=False)
        bad_plans = []
        missing = copy.deepcopy(plan)
        missing['source_refs'].pop('stop_runner')
        bad_plans.append(missing)
        duplicate = copy.deepcopy(plan)
        duplicate['source_refs']['other-stop'] = dict(duplicate['source_refs']['stop_runner'])
        duplicate['source_refs']['other-stop']['role'] = 'boot'
        bad_plans.append(duplicate)
        watcher = copy.deepcopy(plan)
        watcher_path, watcher_raw = self._file(self.repo / 'legacy-watcher.py', '# watcher\n', 0o644)
        watcher['source_refs']['boot'] = {
            'path': str(watcher_path), 'sha256': _sha(watcher_raw), 'role': 'boot',
        }
        bad_plans.append(watcher)
        mismatch = copy.deepcopy(plan)
        mismatch['source_refs']['boot']['sha256'] = 'f' * 64
        bad_plans.append(mismatch)
        for bad in bad_plans:
            with self.subTest(refs=bad['source_refs']), self.assertRaises(engine.PlanError):
                engine.validate_bootstrap_document(bad, verify_checkout=False, verify_apks=False)

    def _business_case(self):
        boot_plan, boot_sha, _ = self._validated_bootstrap()
        fixture = Path('/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-unit-synthetic')
        token = 'fresh-unit-20261003'
        scope_path = fixture / 'public/M5-SCOPE.json'
        go_path = fixture / 'public/Root-GO.json'
        relative_paths = {
            'client_setup': 'public/client-setup.json',
            'custody_manifest': 'public/custody.json',
            'fixture_public': 'public/fixture-public.json',
            'helper_binary': 'bin/cicada-link-v164-fixture',
            'helper_provenance': 'evidence/attempt-06/helper-provenance.json',
            'helper_source': 'helper-src/main.go',
            'hub_ready': 'evidence/attempt-06/hub-ready-final.json',
            'reference_manifest': 'public/reference-manifest.json',
            'runner': 'fixture.sh',
        }
        modes = {
            name: ('0o100644' if name == 'client_setup' else
                '0o100755' if name == 'helper_binary' else
                '0o100700' if name == 'runner' else '0o100600')
            for name in engine.TOPOLOGY_NAMES
        }
        topology_bytes = {}
        topology_refs = {}
        ready_refs = {}
        for name, relative in relative_paths.items():
            path = str(fixture / relative)
            raw = ('{"synthetic":"' + name + '"}\n').encode('ascii')
            topology_bytes[path] = raw
            digest = _sha(raw)
            topology_refs[name] = {'path': path, 'sha256': digest}
            ready_refs[name] = {
                'path': path, 'sha256': digest, 'bytes': len(raw),
                'mode': modes[name], 'relative_path': relative,
            }
        scope_deadline = _utc(500)
        owned_raw = b'{"owned":"synthetic"}\n'
        owned_ref = {
            'path': str(fixture / 'evidence/attempt-06/owned-hub-manifest.json'),
            'sha256': _sha(owned_raw),
        }
        target = boot_plan['target']
        ready = {
            'schema': 'cicada.client-link-v164-fixture-ready.v1',
            'status': 'READY_FOR_CLIENT_COORDINATION', 'fixture_root': str(fixture),
            'protocol_scope': 'SYNTHETIC_PROTOCOL_ONLY', 'native_runtime': 'NOT_RUN',
            'model_calls': 0, 'public_references': ready_refs,
            'source': {
                'revision': target['core_commit'],
                'source_fingerprint': target['source_fingerprint'],
                'catalog_sha256': target['catalog_sha256'],
                'contract_revision': target['contract_revision'],
                'hub_image_id': target['hub_image_id'],
                'interop_image_id': target['interop_image_id'],
            },
            'hub': {
                'hub_id': 'hub_synthetic', 'base_url': 'http://127.0.0.1:43217',
                'container_id': 'a' * 64, 'network_id': 'b' * 64,
                'link_id': 'link_synthetic', 'link_state': 'PROPOSED',
                'link_version': 1, 'bindings': [], 'business_networks': [],
                'review_policy_qualification':
                    'METADATA_NOT_PREPARED: KEY+NONE only; no reviewer or link.review grants',
            },
            'client_setup_sha256': topology_refs['client_setup']['sha256'],
            'hub_ready_sha256': topology_refs['hub_ready']['sha256'],
            'reference_manifest_sha256': topology_refs['reference_manifest']['sha256'],
            'owned_manifest_sha256': owned_ref['sha256'],
            'coordination_nonce': 'c' * 48,
            'coordination_deadline': scope_deadline,
            'coordination_ttl_seconds': 720,
            'cleanup_policy':
                'one terminal consumer ACK or fixed deadline; no renewal; fresh private state destroyed',
        }
        ready_raw = engine.canonical(ready)
        ready_ref = {'path': str(fixture / 'public/READY.json'), 'sha256': _sha(ready_raw)}
        scope = {
            'schema': engine.SCOPE_SCHEMA, 'scope_token': token,
            'fixture_root': str(fixture), 'fixture_label': 'client-link-v164-unit',
            'coordination_deadline': scope_deadline,
            'allowed_business_operations': [], 'allowed_signatures': [],
            'bindings': [], 'business_networks': [], 'device_scope': {},
            'endpoints': [], 'groups': [], 'hub': {},
            'model_calls_by_actor': {}, 'native_review_id': None,
            'native_runtime_by_actor': {}, 'none': [], 'owner_actor_authority': {},
            'owners': [], 'phone_expiry_rule': {},
            'target_rn_alert_obligation': {},
            'max_signature_requests': 6,
            'ready': ready_ref,
            'owned_manifest': owned_ref,
            'key_manifest_digest': 'a' * 64,
            'link': {'contract_digest': 'b' * 64},
            'fixed': {
                'revision': boot_plan['target']['core_commit'],
                'hub_image': boot_plan['target']['hub_image_id'],
                'interop_image': boot_plan['target']['interop_image_id'],
                'contract_package_sha256': boot_plan['target']['contract_archive_sha256'],
                'catalog_sha256': boot_plan['target']['catalog_sha256'],
                'source_fingerprint': boot_plan['target']['source_fingerprint'],
            },
        }
        scope_raw = engine.canonical(scope)
        go = {
            'schema': engine.GO_SCHEMA, 'scope_token': token,
            'scope_path': str(scope_path), 'scope_sha256': _sha(scope_raw),
            'approval_id': 'unit-go-approval', 'root_thread_id': engine.ROOT_THREAD_ID,
            'approved': True, 'approved_at': _utc(-20), 'expires_at': _utc(300),
            'max_requests': 6,
        }
        go_raw = engine.canonical(go)

        business_refs = self._source_refs(('bind', 'carrier', 'hot_preflight', 'flow',
            'runtime_consumer', 'stop_runner'))
        pins_path, pins_raw = self._file(self.cache / 'pins.json', b'synthetic pins')
        metadata_path, metadata_raw = self._file(self.cache / 'delivery.json', b'synthetic delivery')
        source_plan_path, source_plan_raw = self._file(self.cache / 'root-source-plan.json',
            b'synthetic Root source plan')
        commands = {
            'prepare': [],
            'bind': {'source_ref': 'bind', 'args': [], 'timeout_seconds': 10},
            'carrier': {'source_ref': 'carrier', 'args': [], 'timeout_seconds': 20},
            'hot_preflight': {'source_ref': 'hot_preflight', 'args': [], 'timeout_seconds': 15},
            'flow': {'source_ref': 'flow', 'args': [], 'timeout_seconds': 60},
        }
        plan = {
            'schema': engine.BUSINESS_PLAN_SCHEMA,
            'bootstrap_plan_sha256': boot_sha,
            'container_id': 'a' * 64,
            'boot_receipt_sha256': 'b' * 64,
            'fixture_root': str(fixture), 'fixture_label': 'client-link-v164-unit',
            'scope_token': token,
            'scope': {'path': str(scope_path), 'sha256': _sha(scope_raw)},
            'go': {'path': str(go_path), 'sha256': _sha(go_raw)},
            'delivery_pins': {'path': str(pins_path), 'sha256': _sha(pins_raw)},
            'delivery_metadata': {'path': str(metadata_path), 'sha256': _sha(metadata_raw)},
            'source_root_plan_refs': [{'path': str(source_plan_path), 'sha256': _sha(source_plan_raw)}],
            'topology_refs': topology_refs,
            'source_refs': business_refs,
            'carrier_tag': 'carrier-unit-test',
            'declared_flow_order': list(engine.DECLARED_FLOW_ORDER),
            'business_stop_at_utc': _utc(240), 'commands': commands,
        }
        receipt_sha = plan['boot_receipt_sha256']
        boot_receipt = {
            'receipt_sha256': receipt_sha,
            'document': {'container_id': plan['container_id'], 'receipt_sha256': receipt_sha},
        }
        return {
            'plan': plan, 'boot_plan': boot_plan, 'boot_sha': boot_sha,
            'boot_receipt': boot_receipt, 'fixture': fixture,
            'scope': scope, 'scope_path': scope_path, 'scope_raw': scope_raw,
            'go': go, 'go_path': go_path, 'go_raw': go_raw,
            'topology_bytes': topology_bytes, 'ready': ready,
            'scope_ready_raw': ready_raw,
            'owned_raw': owned_raw,
        }

    def _validate_business_case(self, case):
        real_abs = engine._absolute_nonsymlink
        real_declared = engine._read_declared
        real_file = engine._read_file

        def abs_for_fixture(path, label, **kwargs):
            if label in ('fresh fixture root', 'Root topology reference pin'):
                return Path(path)
            return real_abs(path, label, **kwargs)

        def read_declared(ref, label, **kwargs):
            synthetic = None
            if label == 'fresh Scope':
                synthetic = case['scope_raw']
            elif label == 'fresh Root GO':
                synthetic = case['go_raw']
            elif label == 'Root topology reference':
                path = Path(ref['path'])
                if not path.is_relative_to(case['fixture']):
                    raise engine.PlanError('synthetic topology reference escaped fixture root')
                synthetic = case['topology_bytes'][str(path)]
            if synthetic is not None:
                engine._keys(ref, {'path', 'sha256'}, label + ' pin')
                engine._sha(ref['sha256'], label + ' SHA-256')
                if _sha(synthetic) != ref['sha256']:
                    raise engine.PlanError(label + ' bytes differ from the independent SHA-256 pin')
                return synthetic
            return real_declared(ref, label, **kwargs)

        def read_file(path, expected_sha=None, *, label='file', **kwargs):
            synthetic = None
            if label == 'Scope ready':
                synthetic = case['scope_ready_raw']
            elif label == 'Scope owned_manifest':
                synthetic = case['owned_raw']
            if synthetic is not None:
                if expected_sha is not None and _sha(synthetic) != expected_sha:
                    raise engine.PlanError(label + ' bytes differ from the independent SHA-256 pin')
                return synthetic, _sha(synthetic)
            return real_file(path, expected_sha, label=label, **kwargs)

        def verify_topology(_name, ref, _fixture_root):
            engine._keys(ref, {'path', 'sha256'}, 'Root topology reference')
            raw = case['topology_bytes'][ref['path']]
            if _sha(raw) != ref['sha256']:
                raise engine.PlanError('Root topology reference bytes differ from their pin')

        with mock.patch.object(engine, '_absolute_nonsymlink', side_effect=abs_for_fixture), \
                mock.patch.object(engine, '_read_declared', side_effect=read_declared), \
                mock.patch.object(engine, '_read_file', side_effect=read_file), \
                mock.patch.object(engine, '_verify_topology_reference', side_effect=verify_topology):
            result = engine.validate_business_document(
                case['plan'], case['boot_plan'], case['boot_sha'], case['boot_receipt'],
                expected_container='a' * 64,
            )
        return result

    def _rewrite_authority_files(self, case, *, scope=None, go=None,
            preserve_go_scope_hash=False):
        scope = copy.deepcopy(case['scope'] if scope is None else scope)
        go = copy.deepcopy(case['go'] if go is None else go)
        scope_raw = engine.canonical(scope)
        case['scope_raw'] = scope_raw
        case['plan']['scope']['sha256'] = _sha(scope_raw)
        if not preserve_go_scope_hash:
            go['scope_path'] = case['plan']['scope']['path']
            go['scope_sha256'] = case['plan']['scope']['sha256']
        go_raw = engine.canonical(go)
        case['go_raw'] = go_raw
        case['plan']['go']['sha256'] = _sha(go_raw)
        return scope, go

    def test_business_scope_and_root_go_bind_exact_ids_and_valid_deadline_chain(self):
        case = self._business_case()
        result = self._validate_business_case(case)
        self.assertEqual(result['scope']['scope_token'], case['plan']['scope_token'])
        self.assertLess(result['business_stop'], result['scope_deadline'])
        self.assertLess(result['go_expires'], result['scope_deadline'])

    def test_business_plan_rejects_scope_go_expiry_and_unbound_command_variants(self):
        cases = []
        wrong_token = self._business_case()
        wrong_token['plan']['scope_token'] = 'fresh-other-20261003'
        cases.append(wrong_token)

        wrong_hash = self._business_case()
        bad_go = copy.deepcopy(wrong_hash['go'])
        bad_go['scope_sha256'] = 'f' * 64
        self._rewrite_authority_files(wrong_hash, go=bad_go, preserve_go_scope_hash=True)
        cases.append(wrong_hash)

        wrong_schema = self._business_case()
        bad_scope = copy.deepcopy(wrong_schema['scope'])
        bad_scope['schema'] = 'cicada.owner-scope.v0'
        self._rewrite_authority_files(wrong_schema, scope=bad_scope)
        cases.append(wrong_schema)

        wrong_scope_target = self._business_case()
        bad_scope = copy.deepcopy(wrong_scope_target['scope'])
        bad_scope['fixed']['hub_image'] = 'sha256:' + 'f' * 64
        self._rewrite_authority_files(wrong_scope_target, scope=bad_scope)
        cases.append(wrong_scope_target)

        unapproved = self._business_case()
        bad_go = copy.deepcopy(unapproved['go'])
        bad_go['approved'] = False
        self._rewrite_authority_files(unapproved, go=bad_go)
        cases.append(unapproved)

        expired = self._business_case()
        bad_go = copy.deepcopy(expired['go'])
        bad_go['expires_at'] = _utc(-5)
        self._rewrite_authority_files(expired, go=bad_go)
        cases.append(expired)

        beyond_idle = self._business_case()
        bad_scope = copy.deepcopy(beyond_idle['scope'])
        bad_scope['coordination_deadline'] = _utc(700)
        bad_go = copy.deepcopy(beyond_idle['go'])
        bad_go['expires_at'] = _utc(650)
        self._rewrite_authority_files(beyond_idle, scope=bad_scope, go=bad_go)
        cases.append(beyond_idle)

        for case in cases:
            with self.subTest(scope_token=case['plan']['scope_token'], go=case['go']), \
                    self.assertRaises(engine.PlanError):
                self._validate_business_case(case)

        ready_tamper = self._business_case()
        bad_ready = copy.deepcopy(ready_tamper['ready'])
        bad_ready['public_references']['hub_ready']['sha256'] = 'f' * 64
        ready_raw = engine.canonical(bad_ready)
        ready_tamper['ready'] = bad_ready
        ready_tamper['scope_ready_raw'] = ready_raw
        bad_scope = copy.deepcopy(ready_tamper['scope'])
        bad_scope['ready']['sha256'] = _sha(ready_raw)
        ready_tamper['scope'] = bad_scope
        self._rewrite_authority_files(ready_tamper, scope=bad_scope)
        with self.assertRaisesRegex(engine.PlanError, 'aggregate READY reference'):
            self._validate_business_case(ready_tamper)

        case = self._business_case()
        wrong_boot = copy.deepcopy(case)
        wrong_boot['plan']['bootstrap_plan_sha256'] = 'e' * 64
        with self.assertRaisesRegex(engine.PlanError, 'pinned bootstrap plan'):
            self._validate_business_case(wrong_boot)

        missing_root = self._business_case()
        missing_root['plan']['source_root_plan_refs'] = []
        with self.assertRaisesRegex(engine.PlanError, 'source-plan files'):
            self._validate_business_case(missing_root)

        wrong_role = self._business_case()
        wrong_role['plan']['commands']['bind']['source_ref'] = 'carrier'
        with self.assertRaisesRegex(engine.PlanError, 'source role'):
            self._validate_business_case(wrong_role)

    def test_large_executable_topology_helper_accepts_pinned_mode_and_rejects_mode_drift(self):
        fixture = Path('/synthetic/client-link-v164-fixture-helper-mode')
        helper = self.cache / 'helper-binary.synthetic'
        raw = b'synthetic executable helper\n' * 6000
        self._file(helper, raw, 0o755)
        ref = {'path': str(helper), 'sha256': _sha(raw)}
        original_is_under = engine._is_under

        def under(path, root):
            if Path(path) == helper and Path(root) == fixture:
                return True
            return original_is_under(path, root)

        with mock.patch.object(engine, '_is_under', side_effect=under):
            engine._verify_topology_reference('helper_binary', ref, fixture)
            helper.chmod(0o644)
            with self.assertRaisesRegex(engine.PlanError, 'allowed mode'):
                engine._verify_topology_reference('helper_binary', ref, fixture)

    def test_boot_wrapper_requires_canonical_pinned_receipt_and_launcher_pid(self):
        plan, _, _ = self._validated_bootstrap()
        evidence = Path(plan['android']['evidence_root'])
        receipt_path = evidence / 'launcher-boot.redacted.json'
        receipt_path.parent.mkdir(parents=True, mode=0o700)
        doc = {
            'schema': engine.BOOT_SCHEMA, 'result': 'BOOT_READY',
            'run_id': plan['android']['run_id'], 'evidence_root': plan['android']['evidence_root'],
            'container': 'cicada-' + plan['android']['run_id'], 'container_id': 'a' * 64,
            'image_id': engine.EMULATOR_IMAGE, 'network': 'none',
            'app_sha256': engine.APK_HASHES['app'], 'test_sha256': engine.APK_HASHES['test'],
            'runtime_properties': dict(engine.EXPECTED_RUNTIME),
            'ready_observed_at_utc': _utc(), 'idle_deadline': plan['idle_deadline'],
            'supervisor_pid': 4321, 'cold_boot_elapsed_seconds': 37.0,
            'supervision': 'LAUNCHER_ONLY', 'business': 'NOT_RUN',
        }
        raw = engine.canonical(doc)
        self._file(receipt_path, raw)
        readiness_path = evidence / 'emulator-readiness.redacted.json'
        readiness = {
            'container_id': doc['container_id'],
            'marker': {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'},
            'observed_at_utc': doc['ready_observed_at_utc'], 'result': 'READY',
        }
        readiness_raw = engine.canonical(readiness)
        self._file(readiness_path, readiness_raw)
        wrapper = _line({'result': 'BOOT_READY', 'receipt_path': str(receipt_path),
            'receipt_sha256': _sha(raw)})
        result = engine.validate_boot_wrapper(wrapper, plan, 4321)
        self.assertEqual(result['container_id'], doc['container_id'])
        self.assertEqual(result['receipt_sha256'], _sha(raw))
        self.assertEqual(result['readiness_sha256'], _sha(readiness_raw))

        bad_runtime = {**doc, 'runtime_properties': {**doc['runtime_properties'], 'api_level': '34'}}
        bad_alias = {**doc, 'android_image_id': engine.EMULATOR_IMAGE}
        for bad_doc, message in (
                ({**doc, 'supervisor_pid': 4322}, 'approved fixed bootstrap'),
                (bad_runtime, 'approved fixed bootstrap'),
                (bad_alias, 'fields do not match')):
            with self.subTest(receipt_change=bad_doc):
                bad_raw = engine.canonical(bad_doc)
                self._file(receipt_path, bad_raw)
                bad_wrapper = _line({'result': 'BOOT_READY', 'receipt_path': str(receipt_path),
                    'receipt_sha256': _sha(bad_raw)})
                with self.assertRaisesRegex(engine.PlanError, message):
                    engine.validate_boot_wrapper(bad_wrapper, plan, 4321)

        self._file(receipt_path, raw)
        bad_readiness = {**readiness, 'marker': {**readiness['marker'], 'serial': 'emulator-9999'}}
        self._file(readiness_path, engine.canonical(bad_readiness))
        with self.assertRaisesRegex(engine.PlanError, 'readiness receipt'):
            engine.validate_boot_wrapper(wrapper, plan, 4321)

    def test_invalid_carrier_ready_terminates_owned_child_with_strict_pid_tag_and_scope_checks(self):
        ready = {
            'result': 'READY', 'tag': 'f6-carrier-test', 'host_pid': 501,
            'carrier_pid': 602, 'proxy_pid': None, 'fault': 'none',
            'allowed_route_count': 5,
        }
        self.assertEqual(engine.parse_carrier_ready(_line(ready), tag='f6-carrier-test', host_pid=501), ready)
        mutations = (
            {'host_pid': 502}, {'tag': 'foreign'}, {'proxy_pid': 700},
            {'allowed_route_count': 6}, {'carrier_pid': 0}, {'host_pid': True},
        )
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(engine.PlanError):
                engine.parse_carrier_ready(_line({**ready, **changes}), tag='f6-carrier-test', host_pid=501)

        self._assert_hot_boundary_cases()

        class Pipe:
            def fileno(self):
                return 73

            def read(self, _size):
                return b''

        class Child:
            pid = 7111
            returncode = None
            stdout = Pipe()

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.returncode = -15
                return self.returncode

        child = Child()
        evidence = self.root / 'carrier-ready-evidence'
        evidence.mkdir(mode=0o700)
        journal = engine.Journal(evidence)
        source = self.repo / 'carrier.py'
        self._file(source, '# synthetic carrier source\n', 0o644)
        business = {
            'commands': {'carrier': {'source_ref': 'carrier', 'args': [], 'timeout_seconds': 10}},
            'source_refs': {'carrier': {'path': str(source), 'role': 'carrier'}},
            'fixture_root': '/synthetic/fixture', 'scope': {'sha256': 'a' * 64},
            'go': {'sha256': 'b' * 64}, 'delivery_pins': {'path': '/synthetic/pins', 'sha256': 'c' * 64},
            'delivery_metadata': {'path': '/synthetic/metadata', 'sha256': 'd' * 64},
            'carrier_tag': 'expected-carrier', 'declared_flow_order': list(engine.DECLARED_FLOW_ORDER),
        }
        boot_plan = {
            'android': {'evidence_root': str(self.cache / 'run' / 'android')},
            'client_commit': '1' * 40,
            'timeouts': {'carrier_ready_seconds': 30},
        }
        boot = {
            'receipt_sha256': 'e' * 64, 'readiness_sha256': 'd' * 64,
            'container_id': 'f' * 64,
        }
        invalid_ready = _line({
            'result': 'READY', 'tag': 'wrong-carrier', 'host_pid': child.pid,
            'carrier_pid': 8122, 'proxy_pid': None, 'fault': 'none',
            'allowed_route_count': 5,
        })
        with mock.patch.object(engine.subprocess, 'Popen', return_value=child) as popen, \
                mock.patch.object(engine.select, 'select', return_value=([73], [], [])), \
                mock.patch.object(engine.os, 'set_blocking'), \
                mock.patch.object(engine.os, 'read', side_effect=[invalid_ready, b'']), \
                mock.patch.object(engine.os, 'killpg') as killpg:
            with self.assertRaisesRegex(engine.PlanError, 'carrier READY event'):
                engine._start_carrier(journal, business, boot_plan, boot,
                    '9' * 64, engine.Deadline.after(30))

        popen.assert_called_once()
        killpg.assert_called_once_with(child.pid, engine.signal.SIGTERM)
        self.assertEqual(len(journal.records), 1)
        self.assertEqual(journal.records[0]['label'], 'carrier')
        self.assertFalse(journal.records[0]['ready_observed'])

    def test_partial_boot_failure_stops_owned_emulator_even_after_signal_without_claiming_boot_ready(self):
        case = self._business_case()
        boot_plan = case['boot_plan']
        evidence = Path(boot_plan['android']['evidence_root'])
        events = []
        stop_options = []

        def fake_run_process(_journal, label, _argv, _timeout, _deadline, **kwargs):
            events.append(label)
            if label == 'bootstrap':
                evidence.mkdir(parents=True, mode=0o700)
                owned = {
                    'run_id': boot_plan['android']['run_id'],
                    'container': 'cicada-' + boot_plan['android']['run_id'],
                    'image_id': engine.EMULATOR_IMAGE, 'network': 'none',
                }
                self._file(evidence / 'android-driver.json', engine.canonical(owned))
                engine._STOP = True
                return b'{"result":"untrusted"}\n'
            if label == 'emulator-stop':
                stop_options.append(kwargs)
                return b'{"result":"PASS","owned_emulator_removed":true}\n'
            raise AssertionError('unexpected child stage: ' + label)

        root = Path(boot_plan['launcher_evidence_root'])
        with mock.patch.object(engine, '_run_process', side_effect=fake_run_process), \
                mock.patch.object(engine, 'validate_boot_wrapper',
                    side_effect=engine.PlanError('synthetic malformed BOOT wrapper')), \
                mock.patch.object(engine.signal, 'signal'), \
                mock.patch.object(engine, '_wait_ticket') as wait_ticket:
            with self.assertRaisesRegex(engine.PlanError, 'malformed BOOT wrapper'):
                engine.execute(boot_plan, case['boot_sha'])

        wait_ticket.assert_not_called()
        self.assertEqual(events, ['bootstrap', 'emulator-stop'])
        self.assertEqual(len(stop_options), 1)
        self.assertFalse(stop_options[0]['guard_ticket'])
        self.assertFalse(stop_options[0]['respond_to_signal'])
        self.assertFalse((evidence / 'launcher-boot.redacted.json').exists())
        terminal = json.loads((root / 'terminal.private.json').read_bytes())
        self.assertEqual(terminal['result'], 'FAIL')
        self.assertEqual(terminal['business'], 'NOT_RUN')
        self.assertEqual(terminal['cleanup']['emulator'], 'PASS')

    def test_started_flow_failure_waits_then_cleans_carrier_then_emulator_once(self):
        case = self._business_case()
        boot_plan, business = case['boot_plan'], case['plan']
        events = []
        boot_info = {
            'receipt_sha256': case['plan']['boot_receipt_sha256'],
            'readiness_sha256': 'c' * 64,
            'container_id': case['plan']['container_id'],
            'document': {
                'evidence_root': boot_plan['android']['evidence_root'],
                'run_id': boot_plan['android']['run_id'],
            },
        }
        ready = {
            'result': 'READY', 'tag': business['carrier_tag'], 'host_pid': 1001,
            'carrier_pid': 1002, 'proxy_pid': None, 'fault': 'none',
            'allowed_route_count': 5,
        }
        authorization = {
            'scope': case['scope'],
            'go': case['go'],
            'go_expires': engine._utc(case['go']['expires_at'], 'GO expiry'),
            'scope_deadline': engine._utc(case['scope']['coordination_deadline'], 'Scope deadline'),
            'business_stop': engine._utc(business['business_stop_at_utc'], 'business stop'),
        }
        deadline_texts = []
        flow_count = [0]

        def fake_run_process(journal, label, _argv, _timeout, deadline, **_kwargs):
            if label == 'bootstrap':
                return b'{"synthetic":"boot wrapper"}\n'
            if label == 'bind':
                events.append('bind')
                deadline_texts.append(deadline.wall_text)
                return b'{"result":"BOUND"}\n'
            if label == 'hot_preflight':
                events.append('hot')
                deadline_texts.append(deadline.wall_text)
                return b'{"result":"PASS"}\n'
            if label == 'flow':
                flow_count[0] += 1
                events.append('flow-exited-and-waited')
                deadline_texts.append(deadline.wall_text)
                journal.append({'sequence': journal.sequence, 'label': 'flow',
                    'pid': 1003, 'exit_code': 17, 'timed_out': False})
                raise engine.PlanError('flow child exited nonzero; no retry')
            raise AssertionError('unexpected process label: ' + label)

        def finish_carrier(_journal, _state):
            events.append('carrier-terminated-and-waited')
            return 0

        class LiveCarrier:
            def poll(self):
                return None

        carrier = LiveCarrier()

        def stop_emulator(_journal, _boot_plan):
            events.append('emulator-stopped')
            return 'PASS'

        out = type('FakeStdout', (), {'buffer': io.BytesIO()})()
        root = Path(boot_plan['launcher_evidence_root'])
        with mock.patch.object(engine, '_run_process', side_effect=fake_run_process), \
                mock.patch.object(engine, 'validate_boot_wrapper', return_value=boot_info), \
                mock.patch.object(engine, '_run_bootstrap_preflight', return_value={'result': 'PASS'}), \
                mock.patch.object(engine, '_wait_ticket', return_value={
                    'plan_path': '/synthetic/business.json', 'plan_sha256': '9' * 64}), \
                mock.patch.object(engine, '_private_plan', return_value=(business, _sha(engine.canonical(business)))), \
                mock.patch.object(engine, 'validate_business_document', return_value=authorization), \
                mock.patch.object(engine, '_start_carrier', side_effect=lambda *_args: (
                    carrier, object(), object(), ready, object())), \
                mock.patch.object(engine, 'validate_hot_preflight', return_value={'result': 'PASS'}), \
                mock.patch.object(engine, '_finish_carrier', side_effect=finish_carrier), \
                mock.patch.object(engine, '_cleanup_emulator', side_effect=stop_emulator), \
                mock.patch.object(engine.signal, 'signal'), \
                mock.patch.object(engine.sys, 'stdout', out):
            with self.assertRaisesRegex(engine.PlanError, 'flow child exited nonzero'):
                engine.execute(boot_plan, case['boot_sha'])

        self.assertEqual(flow_count[0], 1)
        self.assertEqual(events[-3:], [
            'flow-exited-and-waited', 'carrier-terminated-and-waited', 'emulator-stopped',
        ])
        self.assertEqual(set(deadline_texts), {business['business_stop_at_utc']})
        terminal = json.loads((root / 'terminal.private.json').read_bytes())
        self.assertEqual(terminal['result'], 'FAIL')
        self.assertEqual(terminal['business'], 'OUTCOME_UNKNOWN_PRESERVE_PENDING')
        self.assertEqual(terminal['core_ack'], 'CORE_ACK_NOT_SENT')
        self.assertEqual(terminal['cleanup']['flow'], 'EXITED_AND_WAITED')
        self.assertEqual(terminal['cleanup']['carrier'], 'TERMINATED_AND_WAITED')
        self.assertEqual(terminal['cleanup']['emulator'], 'PASS')

    def _write_hot_evidence(self, *, marker_changes=None, extra_log=None):
        run_id = 'v16-deterministic-v164-f6-hot-test'
        evidence = self.cache / run_id / 'android'
        evidence.mkdir(parents=True, mode=0o700, exist_ok=True)
        tag, host_pid, carrier_pid = 'hot-carrier-test', 711, 822
        marker = {
            'schema': hot.SCHEMA, 'result': 'RUNNING', 'tag': tag,
            'host_pid': host_pid, 'docker_exec_pid': carrier_pid, 'proxy_pid': None,
            'fault': 'none', 'emulator_container': 'cicada-' + run_id,
            'emulator_label': run_id, 'emulator_network_mode': 'none',
            'allowed_routes': hot.ROUTES, 'payload_persistence': 'NONE',
        }
        marker.update(marker_changes or {})
        expected_event = {
            'event': 'ready', 'tag': tag, 'host_pid': host_pid,
            'docker_exec_pid': carrier_pid, 'proxy_pid': None, 'fault': 'none',
            'allowed_route_count': 5, 'payload_persisted': False,
        }
        records = [expected_event]
        if extra_log is not None:
            records.append(extra_log)
        marker_path = evidence / f'stdio-carrier-{tag}.private.json'
        log_path = evidence / f'stdio-carrier-{tag}.redacted.jsonl'
        self._file(marker_path, json.dumps(marker, sort_keys=True, separators=(',', ':')))
        self._file(log_path, b''.join(json.dumps(record, sort_keys=True,
            separators=(',', ':')).encode('ascii') + b'\n' for record in records))
        return evidence, tag, host_pid, carrier_pid

    def _assert_hot_boundary_cases(self):
        evidence, tag, host_pid, carrier_pid = self._write_hot_evidence()
        with mock.patch.object(hot, 'process_exists') as process_exists:
            marker_raw, log_raw = hot.check_carrier(evidence, tag, host_pid, carrier_pid)
        self.assertEqual(hashlib.sha256(marker_raw).hexdigest(), _sha(marker_raw))
        self.assertEqual(len(log_raw.splitlines()), 1)
        self.assertEqual(process_exists.call_args_list, [
            mock.call(host_pid), mock.call(carrier_pid),
        ])
        cases = (
            {'marker_changes': {'payload_persistence': 'PERSISTED'}},
            {'extra_log': {'event': 'request', 'route': 'POST /v2/client/rpc'}},
        )
        for options in cases:
            evidence, tag, host_pid, carrier_pid = self._write_hot_evidence(**options)
            with self.subTest(options=options), \
                    mock.patch.object(hot, 'process_exists'), \
                    self.assertRaises(ValueError):
                hot.check_carrier(evidence, tag, host_pid, carrier_pid)

    def test_single_ticket_admission_rejects_replay_oversize_symlink_and_hash_mismatch(self):
        ticket = {'plan_path': '/synthetic/business.json', 'plan_sha256': 'd' * 64}

        def read_ticket(raw):
            with mock.patch.object(engine.sys, 'stdin', mock.Mock(fileno=lambda: 9)), \
                    mock.patch.object(engine.os, 'set_blocking'), \
                    mock.patch.object(engine.select, 'select', return_value=([9], [], [])), \
                    mock.patch.object(engine.os, 'read', return_value=raw), \
                    mock.patch.object(engine, '_remaining', return_value=10):
                return engine._wait_ticket(1234)

        engine._TICKET_FD = None
        self.assertEqual(read_ticket(_line(ticket)), ticket)
        engine._TICKET_FD = None
        with self.assertRaisesRegex(engine.PlanError, 'exactly one'):
            read_ticket(_line(ticket) + _line(ticket))
        engine._TICKET_FD = None
        with self.assertRaisesRegex(engine.PlanError, '4 KiB'):
            read_ticket(b'x' * 4097)
        engine._TICKET_FD = None
        with self.assertRaises(engine.PlanError):
            engine.parse_json(b'{"deadline":NaN}', 'ticket')
        nested = b'{"x":' + b'[' * 26 + b'0' + b']' * 26 + b'}'
        with self.assertRaisesRegex(engine.PlanError, 'nesting bound'):
            engine.parse_json(nested, 'ticket')
        duplicate = b'{"plan_path":"/synthetic/business.json","plan_sha256":"' + \
            (b'd' * 64) + b'","plan_sha256":"' + (b'd' * 64) + b'"}\n'
        with self.assertRaisesRegex(engine.PlanError, 'duplicate'):
            read_ticket(duplicate)

        doc = {'schema': engine.BUSINESS_PLAN_SCHEMA, 'synthetic': True}
        plan_path = self.cache / 'one-use-business-plan.json'
        plan_raw = engine.canonical(doc)
        self._file(plan_path, plan_raw)
        parsed, digest = engine._private_plan(str(plan_path), _sha(plan_raw), 'business plan')
        self.assertEqual(parsed, doc)
        self.assertEqual(digest, _sha(plan_raw))
        with self.assertRaisesRegex(engine.PlanError, 'independent SHA-256 pin'):
            engine._private_plan(str(plan_path), '0' * 64, 'business plan')
        alias = self.cache / 'plan-alias.json'
        alias.symlink_to(plan_path)
        with self.assertRaisesRegex(engine.PlanError, 'symlink or path alias'):
            engine._private_plan(str(alias), _sha(plan_raw), 'business plan')

        ticket = {'plan_path': '/synthetic/business.json', 'plan_sha256': 'd' * 64}
        with mock.patch.object(engine.sys, 'stdin', mock.Mock(fileno=lambda: 17)), \
                mock.patch.object(engine.os, 'set_blocking'), \
                mock.patch.object(engine.select, 'select', return_value=([17], [], [])), \
                mock.patch.object(engine.os, 'read', return_value=_line(ticket)), \
                mock.patch.object(engine, '_remaining', return_value=10):
            self.assertEqual(engine._wait_ticket(1234), ticket)
        with mock.patch.object(engine.select, 'select', return_value=([17], [], [])), \
                mock.patch.object(engine.os, 'read', return_value=_line(ticket)):
            with self.assertRaisesRegex(engine.PlanError, 'second or trailing'):
                engine._reject_extra_ticket()

    def test_child_failure_timeout_and_late_ticket_are_journaled_once_and_terminated(self):
        class ExitedProcess:
            pid = 7001
            returncode = 23

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        for label in ('bind', 'hot_preflight', 'flow'):
            with self.subTest(label=label):
                root = self.root / ('exit-' + label)
                root.mkdir(mode=0o700)
                journal = engine.Journal(root)
                process = ExitedProcess()

                def start(argv, **kwargs):
                    kwargs['stdout'].write(b'synthetic child output')
                    kwargs['stderr'].write(b'synthetic child failure')
                    return process

                with mock.patch.object(engine.subprocess, 'Popen', side_effect=start) as popen:
                    with self.assertRaisesRegex(engine.PlanError, label + ' exited nonzero'):
                        engine._run_process(journal, label, ['synthetic-child'], 10,
                            engine.Deadline.after(30))
                popen.assert_called_once()
                self.assertEqual(len(journal.records), 1)
                self.assertEqual(journal.records[0]['label'], label)
                self.assertEqual(journal.records[0]['exit_code'], 23)
                self.assertEqual(Path(journal.records[0]['stdout_path']).read_bytes(),
                    b'synthetic child output')

        class Cutoff:
            wall_text = _utc(30)

            def __init__(self):
                self.calls = 0

            def remaining(self):
                self.calls += 1
                return 2.0 if self.calls == 1 else 0.0

        class RunningProcess:
            pid = 7002
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.returncode = -15
                return self.returncode

        for cancel_reason in ('deadline', 'late-ticket'):
            with self.subTest(cancel_reason=cancel_reason):
                root = self.root / ('cancel-' + cancel_reason)
                root.mkdir(mode=0o700)
                journal = engine.Journal(root)
                process = RunningProcess()

                def start(argv, **kwargs):
                    kwargs['stdout'].write(b'owned child started')
                    return process

                extra_guard = mock.patch.object(engine, '_reject_extra_ticket',
                    side_effect=[None, engine.PlanError('second ticket arrived')]) \
                    if cancel_reason == 'late-ticket' else mock.patch.object(engine, '_reject_extra_ticket')
                with mock.patch.object(engine.subprocess, 'Popen', side_effect=start) as popen, \
                        mock.patch.object(engine.os, 'killpg') as killpg, extra_guard:
                    message = 'second ticket arrived' if cancel_reason == 'late-ticket' else 'timed out'
                    with self.assertRaisesRegex(engine.PlanError, message):
                        engine._run_process(journal, 'bind', ['synthetic-child'], 20, Cutoff())
                popen.assert_called_once()
                killpg.assert_called_once_with(process.pid, engine.signal.SIGTERM)
                self.assertEqual(len(journal.records), 1)
                self.assertEqual(journal.records[0]['exit_code'], -15)
                self.assertEqual(journal.records[0]['timed_out'], cancel_reason == 'deadline')
                self.assertEqual(journal.records[0]['interrupted'], cancel_reason == 'late-ticket')


if __name__ == '__main__':
    unittest.main()
