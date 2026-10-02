"""Offline synthetic tests for Root-pinned v1.6.4 F6 delivery metadata."""

import hashlib
import importlib.util
import json
from argparse import Namespace
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pins_module = _load(ROOT / 'scripts/interop/v164-link-fixture-pins.py', 'v164_test_pins')
carrier = _load(ROOT / 'scripts/interop/v164-link-fixture-carrier.py', 'v164_test_carrier')
runner = _load(ROOT / 'scripts/interop/v164-android-deterministic.py', 'v164_test_runner')


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def _synthetic_documents(root):
    core = {
        'revision': 'dd81575b160aa901b642137e54d7a60961e4bd68',
        'source_dirty': False,
        'source_fingerprint': '1' * 64,
        'contract_revision': pins_module.CONTRACT_REVISION,
        'wire_version': pins_module.WIRE_VERSION,
        'schema_version': pins_module.SCHEMA_VERSION,
        'operation_count': pins_module.OPERATION_COUNT,
        'catalog_sha256': pins_module.CATALOG_SHA256,
        'producer_sha256': '2' * 64,
        'package_sha256': '3' * 64,
    }
    images = {'hub': 'sha256:' + '4' * 64, 'interop': 'sha256:' + '5' * 64}
    delivery = {
        'schema': pins_module.DELIVERY_SCHEMA,
        **core,
        'hub_image_id': images['hub'],
        'interop_image_id': images['interop'],
    }
    pins = {
        'schema': pins_module.ROOT_PINS_SCHEMA,
        'scope': 'fresh-F6',
        'fixture_root': str(root),
        'delivery_metadata_sha256': None,
        'core': core,
        'images': images,
        'fixture': {
            'label': pins_module.FIXTURE_LABEL,
            'setup_sha256': '6' * 64,
            'ready_sha256': '7' * 64,
            'reference_sha256': '8' * 64,
            'owned_manifest_sha256': '9' * 64,
            'hub_id': 'hub_f6synthetic',
            'host_port': 43217,
        },
    }
    return pins, delivery


class LinkFixturePinsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='v164-pins-test-')
        self.work = Path(self.temp.name)
        self.fixture_root = Path('/gpu1-share/data/cicada-client/v164-dd81575-20261002/fixture-f6')
        self.pins_path = self.work / 'root-pins.json'
        self.metadata_path = self.work / 'delivery-metadata.json'
        self.pins, self.delivery = _synthetic_documents(self.fixture_root)
        self._persist()

    def tearDown(self):
        self.temp.cleanup()

    def _persist(self):
        delivery_raw = _json_bytes(self.delivery)
        self.pins['delivery_metadata_sha256'] = _sha(delivery_raw)
        _write(self.metadata_path, delivery_raw)
        pins_raw = _json_bytes(self.pins)
        _write(self.pins_path, pins_raw)
        self.pins_sha256 = _sha(pins_raw)
        self.delivery_sha256 = _sha(delivery_raw)

    def _load(self, *, metadata_sha256=None):
        return pins_module.read_trusted_delivery(
            self.pins_path, self.pins_sha256, self.metadata_path, metadata_sha256,
        )

    def _runner_args(self, **overrides):
        values = {
            'delivery_pins': str(self.pins_path),
            'delivery_pins_sha256': self.pins_sha256,
            'delivery_metadata': str(self.metadata_path),
            'delivery_metadata_sha256': self.delivery_sha256,
            'fixture_root': str(self.fixture_root),
        }
        values.update(overrides)
        return Namespace(**values)

    def test_verified_synthetic_delivery_and_fixture_paths(self):
        trusted = self._load(metadata_sha256=self.delivery_sha256)
        fixture = pins_module.validate_f6_fixture(trusted, self.fixture_root)
        self.assertEqual(trusted['core_revision'], self.pins['core']['revision'])
        self.assertEqual(trusted['hub_image_id'], self.pins['images']['hub'])
        self.assertEqual(fixture['root'], self.fixture_root)
        self.assertEqual(fixture['ready'], self.fixture_root / 'evidence/ready-receipt.json')
        self.assertEqual(fixture['manifest_sha256'], self.pins['fixture']['owned_manifest_sha256'])

    def test_core_owned_f6_root_is_allowed_for_dd81575_delivery(self):
        core_root = pins_module.CORE_F6_ROOT
        self.pins['fixture_root'] = str(core_root)
        self._persist()

        trusted = self._load()
        ready = self._main_ready(core_root)
        with mock.patch.object(pins_module, '_read_file', return_value=(b'', self.pins_sha256, ready)):
            fixture = pins_module.validate_f6_fixture(trusted, core_root)
        self.assertEqual(fixture['root'], core_root)
        self.assertEqual(fixture['core_revision'], pins_module.CORE_F6_REVISION)
        self.assertEqual(fixture['ready'], core_root / 'public/READY.json')
        self.assertEqual(fixture['manifest'], core_root / 'evidence/attempt-06/owned-hub-manifest.json')

    def _main_ready(self, root):
        # This mock tests shared path resolution, not the carrier's full receipt
        # validator. It contains no current fixture identity or proof.
        ready = dict.fromkeys(pins_module._MAIN_READY_KEYS)
        ready.update(schema='cicada.client-link-v164-fixture-ready.v1',
            status='READY_FOR_CLIENT_COORDINATION', fixture_root=str(root),
            client_setup_sha256=self.pins['fixture']['setup_sha256'],
            reference_manifest_sha256=self.pins['fixture']['reference_sha256'],
            owned_manifest_sha256=self.pins['fixture']['owned_manifest_sha256'],
            hub_ready_sha256='e' * 64)
        ready['public_references'] = dict.fromkeys(pins_module._MAIN_REFERENCE_NAMES)
        relative = 'evidence/attempt-06/hub-ready-final.json'
        ready['public_references']['hub_ready'] = {
            'path': str(root / relative), 'relative_path': relative,
            'sha256': 'e' * 64, 'bytes': 200, 'mode': '0o100600',
        }
        return ready

    def test_main_path_resolution_rejects_draft_hash_mismatch_and_unsafe_attempt(self):
        root = pins_module.CORE_F6_ROOT
        self.pins['fixture_root'] = str(root)
        self._persist()
        trusted = self._load()
        mutations = (
            lambda ready: ready.update(status='DRAFT_SCHEMA_ONLY_NOT_AUTHORIZED'),
            lambda ready: ready.update(owned_manifest_sha256='f' * 64),
            lambda ready: ready.update(hub_ready_sha256='f' * 64),
            lambda ready: ready['public_references']['hub_ready'].update(relative_path='../private/state.json'),
            lambda ready: ready['public_references']['hub_ready'].update(path='/tmp/hub-ready-final.json'),
            lambda ready: ready['public_references']['hub_ready'].update(mode='0o100644'),
            lambda ready: ready['public_references']['hub_ready'].update(bytes=True),
        )
        for mutate in mutations:
            ready = self._main_ready(root)
            mutate(ready)
            with self.subTest(ready=ready), \
                    mock.patch.object(pins_module, '_read_file', return_value=(b'', self.pins_sha256, ready)):
                with self.assertRaises(ValueError):
                    pins_module.validate_f6_fixture(trusted, root)

    def test_main_path_resolution_requires_exact_root_ready_bytes(self):
        root = pins_module.CORE_F6_ROOT
        self.pins['fixture_root'] = str(root)
        self._persist()
        trusted = self._load()
        with mock.patch.object(pins_module, '_read_file', side_effect=ValueError('SHA-256 mismatch')) as read:
            with self.assertRaises(ValueError):
                pins_module.validate_f6_fixture(trusted, root)
        read.assert_called_once_with(root / 'public/READY.json',
            expected_sha256=self.pins['fixture']['ready_sha256'])

    def test_core_owned_f6_root_rejects_other_revision_and_symlink_alias(self):
        core_root = pins_module.CORE_F6_ROOT
        self.pins['fixture_root'] = str(core_root)
        self.pins['core']['revision'] = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
        self.delivery['revision'] = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

        target = self.work / 'actual-core-root'
        target.mkdir()
        parent_alias = self.work / 'core-parent-alias'
        parent_alias.symlink_to(target, target_is_directory=True)
        aliased_root = parent_alias / 'fixture-f6'
        with mock.patch.object(pins_module, 'CORE_F6_ROOT', aliased_root):
            with self.assertRaises(ValueError):
                pins_module._validate_fixture_root(
                    str(aliased_root), str(aliased_root), pins_module.CORE_F6_REVISION,
                )

    def test_carrier_f6_requires_and_loads_all_external_pins(self):
        from argparse import Namespace

        args = Namespace(
            fixture_root=str(self.fixture_root),
            root_pins=str(self.pins_path), root_pins_sha256=self.pins_sha256,
            delivery_metadata=str(self.metadata_path), delivery_metadata_sha256=self.delivery_sha256,
            setup_sha256=None, ready_sha256=None, reference_sha256=None, manifest_sha256=None,
            hub_id=None, hub_port=None,
        )
        config = carrier._configure(args)
        self.assertIs(config['f6'], True)
        self.assertEqual(config['hub_id'], self.pins['fixture']['hub_id'])
        self.assertEqual(config['paths']['root'], self.fixture_root)
        self.assertEqual(config['core_revision'], self.pins['core']['revision'])

    def test_carrier_refuses_mixed_legacy_cli_pins(self):
        from argparse import Namespace

        args = Namespace(
            fixture_root=str(self.fixture_root),
            root_pins=str(self.pins_path), root_pins_sha256=self.pins_sha256,
            delivery_metadata=str(self.metadata_path), delivery_metadata_sha256=self.delivery_sha256,
            setup_sha256='a' * 64, ready_sha256=None, reference_sha256=None, manifest_sha256=None,
            hub_id=None, hub_port=None,
        )
        with self.assertRaises(ValueError):
            carrier._configure(args)

    def test_carrier_refuses_partial_external_pin_set(self):
        from argparse import Namespace

        args = Namespace(
            fixture_root=str(self.fixture_root), root_pins=str(self.pins_path), root_pins_sha256=None,
            delivery_metadata=None, delivery_metadata_sha256=None,
        )
        with self.assertRaises(ValueError):
            carrier._configure(args)

    def test_existing_f5_cli_route_still_uses_legacy_pins(self):
        from argparse import Namespace

        args = Namespace(
            fixture_root=str(carrier.F5_FIXTURE_ROOT),
            root_pins=None, root_pins_sha256=None, delivery_metadata=None, delivery_metadata_sha256=None,
            setup_sha256='a' * 64, ready_sha256='b' * 64, reference_sha256='c' * 64,
            manifest_sha256='d' * 64, hub_id='hub_existing', hub_port=43218,
        )
        config = carrier._configure(args)
        self.assertNotIn('f6', config)
        self.assertEqual(config['paths']['root'], carrier.F5_FIXTURE_ROOT)
        self.assertEqual(config['hub_id'], 'hub_existing')

    def test_wrong_root_pins_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            pins_module.read_trusted_delivery(self.pins_path, 'f' * 64, self.metadata_path)

    def test_wrong_delivery_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            pins_module.read_trusted_delivery(
                self.pins_path, self.pins_sha256, self.metadata_path, 'f' * 64,
            )

    def test_changed_metadata_bytes_without_root_repin_are_rejected(self):
        self.metadata_path.write_bytes(self.metadata_path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            self._load()

    def test_local_delivery_core_mismatch_is_rejected_even_with_updated_hash(self):
        self.delivery['source_fingerprint'] = 'a' * 64
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

    def test_source_dirty_true_is_rejected(self):
        self.pins['core']['source_dirty'] = True
        self.delivery['source_dirty'] = True
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

    def test_unlisted_commit_is_rejected(self):
        self.pins['core']['revision'] = '0' * 40
        self.delivery['revision'] = '0' * 40
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

    def test_image_identity_mismatch_is_rejected(self):
        self.pins['images']['hub'] = 'sha256:' + 'a' * 64
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

    def test_contract_schema_catalog_and_count_pins_are_fixed(self):
        for field, value in (
                ('contract_revision', 'client-hub-v9'), ('wire_version', 2),
                ('schema_version', 58), ('operation_count', 54), ('catalog_sha256', 'f' * 64)):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                self.pins['core'][field] = value
                self.delivery[field] = value
                self._persist()
                with self.assertRaises(ValueError):
                    self._load()

    def test_metadata_json_types_do_not_coerce_boolean_or_float_to_integer(self):
        for field, value in (('wire_version', True), ('schema_version', 57.0), ('operation_count', 55.0)):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                self.delivery[field] = value
                self._persist()
                with self.assertRaises(ValueError):
                    self._load()

    def test_f5_path_cannot_be_reused_as_f6(self):
        self.pins['fixture_root'] = str(carrier.F5_FIXTURE_ROOT)
        self._persist()
        with self.assertRaises(ValueError):
            self._load()

    def test_duplicate_root_pin_key_is_rejected(self):
        raw = _json_bytes(self.pins).replace(b'"scope":"fresh-F6"',
            b'"scope":"fresh-F6","scope":"fresh-F6"')
        _write(self.pins_path, raw)
        with self.assertRaises(ValueError):
            pins_module.read_trusted_delivery(self.pins_path, _sha(raw), self.metadata_path)

    def test_wrong_owner_file_mode_is_rejected(self):
        self.pins_path.chmod(0o644)
        with self.assertRaises(ValueError):
            self._load()

    def test_root_pins_symlink_is_rejected(self):
        link = self.work / 'root-pins-link.json'
        link.symlink_to(self.pins_path)
        with self.assertRaises(ValueError):
            pins_module.read_trusted_delivery(link, self.pins_sha256, self.metadata_path)

    def test_f6_runner_requires_complete_root_and_delivery_pins(self):
        self.assertEqual(runner.read_f6_delivery(Namespace()), None)
        with self.assertRaises(ValueError):
            runner.read_f6_delivery(Namespace(delivery_pins=str(self.pins_path)))
        with self.assertRaises(ValueError):
            runner.read_f6_delivery(self._runner_args(delivery_pins_sha256='f' * 64))

    def test_f6_runner_rejects_mutated_root_or_delivery_bytes_on_revalidation(self):
        args = self._runner_args()
        first = runner.read_f6_delivery(args)
        self.assertIsNotNone(first)
        self.pins_path.write_bytes(self.pins_path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            runner.read_f6_delivery(args)

    def test_f6_start_rejects_missing_pins_before_any_runtime_action(self):
        evidence = self.work / 'v16-deterministic-v164-f6-no-pins' / 'evidence'
        evidence.mkdir(parents=True)
        args = Namespace(app_sha256='a' * 64, test_sha256='b' * 64)
        with mock.patch.object(runner.subprocess, 'check_output', side_effect=AssertionError('must not invoke Docker')):
            with self.assertRaises(ValueError):
                runner.start(evidence, args)

    def test_f6_start_rejects_old_frozen_app_or_test_hash_before_runtime(self):
        evidence = self.work / 'v16-deterministic-v164-f6-old-apk' / 'evidence'
        evidence.mkdir(parents=True)
        args = self._runner_args(
            app_sha256='1811e156012eb4996c8740ab875d4ac142bb1979ba0f1b0cfe94c1b6a9b4686e',
            test_sha256='be72fa25371c2494969888d77f60b1019e49d654bc0c1d81602da60ff92ee674',
            app_apk=str(self.work / 'no-app.apk'), test_apk=str(self.work / 'no-test.apk'),
        )

        def deny_runtime_commands(command, *args, **kwargs):
            if command and command[0] == 'git':
                return 'synthetic-git-metadata' if kwargs.get('text') else b''
            raise AssertionError('Docker, ADB, and other runtime commands are forbidden in this test')

        with mock.patch.object(runner.subprocess, 'check_output', side_effect=deny_runtime_commands):
            with self.assertRaises(ValueError):
                runner.start(evidence, args)

    def test_f6_start_rejects_preexisting_state_directory(self):
        evidence = self.work / 'v16-deterministic-v164-f6-existing' / 'evidence'
        evidence.mkdir(parents=True)
        (evidence / 'android-driver.json').write_text('{}', encoding='utf-8')
        args = self._runner_args(
            app_sha256=runner.F6_APP_SHA256, test_sha256=runner.F6_TEST_SHA256,
            app_apk=str(self.work / 'no-app.apk'), test_apk=str(self.work / 'no-test.apk'),
        )
        with mock.patch.object(runner.subprocess, 'check_output', side_effect=AssertionError('must not invoke Docker')):
            with self.assertRaises(ValueError):
                runner.start(evidence, args)

    def test_f6_metadata_cannot_be_applied_to_legacy_evidence(self):
        evidence = self.work / 'v16-deterministic-v164-legacy-old' / 'evidence'
        evidence.mkdir(parents=True)
        (evidence / 'android-artifacts.json').write_text('{}', encoding='utf-8')
        with self.assertRaises(ValueError):
            runner.validate_existing_f6_artifacts(evidence, self._runner_args())

    def test_runner_keeps_legacy_47_and_selects_49_only_with_verified_lane(self):
        legacy = {row[1]: row[2] for row in runner.MATRIX}
        f6 = {row[1]: row[2] for row in runner.F6_MATRIX}
        self.assertEqual(sum(legacy.values()), 47)
        self.assertEqual(sum(f6.values()), 49)
        self.assertEqual({name: count for name, count in f6.items() if count != legacy[name]}, {
            'LinkConsentAuthorityFactoryTest': 6, 'LinkConsentLedgerTest': 5,
        })

        evidence = self.work / 'v16-deterministic-v164-f6-matrix' / 'evidence'
        evidence.mkdir(parents=True)
        summary = evidence / 'deterministic-summary.redacted.json'
        summary.write_text('{}', encoding='utf-8')
        state = {'run_id': evidence.parent.name}
        args = self._runner_args()
        selected = []

        def fake_install(_evidence, _state):
            selected.append(tuple(runner.v15.MATRIX))
            return {'selected': len(runner.v15.MATRIX)}

        with mock.patch.object(runner, 'validate_existing_f6_artifacts', return_value={'fixture_lane': 'F6'}), \
                mock.patch.object(runner.v15, 'install_and_test', side_effect=fake_install):
            self.assertEqual(runner.test(evidence, state, args)['selected'], 7)
        self.assertEqual(selected[-1], runner.F6_MATRIX)

        legacy_evidence = self.work / 'v16-deterministic-v164-legacy-matrix' / 'evidence'
        legacy_evidence.mkdir(parents=True)
        (legacy_evidence / 'deterministic-summary.redacted.json').write_text('{}', encoding='utf-8')
        legacy_selected = []
        with mock.patch.object(runner, 'validate_existing_f6_artifacts', return_value=None), \
                mock.patch.object(runner.v15, 'install_and_test',
                    side_effect=lambda _evidence, _state: legacy_selected.append(tuple(runner.v15.MATRIX)) or {'selected': len(runner.v15.MATRIX)}):
            self.assertEqual(runner.test(legacy_evidence, {'run_id': legacy_evidence.parent.name}, Namespace())['selected'], 7)
        self.assertEqual(legacy_selected[-1], runner.MATRIX)


if __name__ == '__main__':
    unittest.main()
