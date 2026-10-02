"""Offline synthetic coverage for the strict Main17 v1.6.4 F6 READY adapter.

These fixtures exercise JSON/path/ownership gates only. They contain no valid
Hub proofs or private material and make no live-fixture acceptance claim.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
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


carrier = _load(ROOT / 'scripts/interop/v164-link-fixture-carrier.py', 'v164_f6_ready_test_carrier')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _b64(size, byte):
    return base64.b64encode(bytes([byte]) * size).decode('ascii')


def _go_utc(value):
    value = value.astimezone(timezone.utc)
    fraction = f'{value.microsecond:06d}'.rstrip('0')
    return value.strftime('%Y-%m-%dT%H:%M:%S') + ('.' + fraction if fraction else '') + 'Z'


def _python_utc(value):
    return value.astimezone(timezone.utc).isoformat()


def _public_identity(key_id, seed):
    return {'id': key_id, 'kem_public': _b64(1184, seed), 'signing_public': _b64(1952, seed + 1)}


def _attestation(side):
    """Structural placeholder only; the short signature is intentionally invalid."""
    proof = {
        'version': 1,
        'endpoint_id': side['endpoint_id'],
        'principal_id': side['principal_id'],
        'node_id': side['node_id'],
        'binding_id': side['binding_id'],
        'binding_epoch': side['binding_epoch'],
        'public_identity': side['public_identity'],
        'signature': base64.b64encode(b'x').decode('ascii'),
    }
    raw = _json_bytes(proof)
    side['proof_digest'] = _sha(raw)
    side['attestation'] = base64.b64encode(raw).decode('ascii')


class MainF6ReadyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='v164-f6-ready-')
        self.root = Path(self.temp.name) / 'fixture-f6'
        self.root.mkdir(mode=0o700)
        self.now = datetime.now(timezone.utc)
        self.config, self.setup, self.fixture_public, self.reference, self.manifest = self._documents()
        self.ready = self._write_references()

    def tearDown(self):
        self.temp.cleanup()

    def _documents(self):
        cfg = {
            'f6': True,
            'core_revision': carrier.F6_MAIN_REVISION,
            'source_dirty': False,
            'source_fingerprint': '1' * 64,
            'contract_revision': 'client-hub-v1.6.4',
            'wire_version': 1,
            'schema_version': 57,
            'operation_count': 55,
            'catalog_sha256': carrier.CATALOG_SHA256,
            'producer_sha256': '2' * 64,
            'package_sha256': '3' * 64,
            'hub_image_id': 'sha256:' + '4' * 64,
            'interop_image_id': 'sha256:' + '5' * 64,
            'fixture_label': 'client-link-v164-06',
            'hub_id': 'hub_f6fixture',
            'host_port': 43127,
            'setup_sha256': None,
            'ready_sha256': '6' * 64,
            'reference_sha256': None,
            'manifest_sha256': '7' * 64,
            'paths': {'root': self.root},
        }
        owner_ids = ('owner_source_f6', 'owner_target_f6')
        owner_key_ids = ('pq1-' + '8' * 32, 'pq1-' + '9' * 32)
        owners = [
            {
                'link_side': side, 'owner_id': owner_id, 'owner_key_id': key_id,
                'public_identity': _public_identity(key_id, index + 1),
                'pin_source': 'host-generated Owner public identity, independently checked before Hub registration',
            }
            for index, (side, owner_id, key_id) in enumerate(zip(('SOURCE', 'TARGET'), owner_ids, owner_key_ids))
        ]
        setup_link = {
            'link_id': 'link_f6_fixture', 'version': 1, 'state': 'PROPOSED',
            'expires_at': _go_utc(self.now + timedelta(minutes=30)), 'contract_digest': 'a' * 64,
        }
        setup = {
            'schema': 'cicada.client-link-v164-client-setup.v1',
            'status': 'READY_FOR_ROOT_CLIENT_COORDINATION', 'protocol_scope': 'SYNTHETIC_PROTOCOL_ONLY',
            'native_runtime': 'NOT_RUN', 'model_calls': 'NONE',
            'hub': {
                'base_url': 'http://127.0.0.1:43127', 'hub_id': cfg['hub_id'], 'control_key_version': 1,
                'control_public_identity': _public_identity('pq1-' + 'a' * 32, 11),
                'suite': 'ML-KEM-768+ML-DSA-65+AES-256-GCM', 'image_id': cfg['hub_image_id'],
                'source_revision': cfg['core_revision'], 'source_fingerprint': cfg['source_fingerprint'],
                'catalog_sha256': cfg['catalog_sha256'], 'contract_revision': cfg['contract_revision'],
            },
            'owners': owners,
            'link': setup_link,
            'client_instructions': {
                'generate_device_identity_on_android': True,
                'obtain_fresh_enrollment_manifest_from_android': True,
                'owner_private_keys_for_signing': 'host-only mode 0600; never place in APK or send to Hub',
                'reference_manifest': 'offline Store preflight only; fetch a fresh live encrypted manifest before consent/signing',
                'endpoint_identity': 'current candidate identities, bindings, attestations, and leases are in fresh live RPC manifests',
                'review_policy_qualification': carrier._F6_REVIEW_QUALIFICATION,
            },
        }
        source_ep, target_ep = 'ep_f6_source', 'ep_f6_target'
        source_group, target_group = 'group_f6_source', 'group_f6_target'
        source_node, target_node = 'node_f6_source', 'node_f6_target'
        source_binding, target_binding = 'binding_f6_source', 'binding_f6_target'
        source_access, target_access = 'access_f6_source', 'access_f6_target'
        source_native, target_native = 'native_f6_source', 'native_f6_target'
        source_key_id, target_key_id = 'pq1-' + 'b' * 32, 'pq1-' + 'c' * 32
        endpoint_ids = (source_ep, target_ep)
        group_ids = (source_group, target_group)
        node_ids = (source_node, target_node)
        binding_ids = (source_binding, target_binding)
        access_ids = (source_access, target_access)
        native_ids = (source_native, target_native)
        endpoint_key_ids = (source_key_id, target_key_id)
        networks = [
            {'network_id': f'network_f6_{side.lower()}', 'owner_id': owner_ids[index],
             'group_id': group_ids[index], 'state': 'ACTIVE', 'hub_id': cfg['hub_id']}
            for index, side in enumerate(('SOURCE', 'TARGET'))
        ]
        bindings = [
            {'endpoint_id': endpoint_ids[index], 'binding_id': binding_ids[index], 'epoch': index + 2,
             'lease_expires_at': _go_utc(self.now + timedelta(minutes=25)), 'status': 'leased'}
            for index in range(2)
        ]
        candidates = [
            {'endpoint_id': endpoint_ids[index], 'binding_id': binding_ids[index], 'epoch': index + 2,
             'key_id': endpoint_key_ids[index], 'state': 'CANDIDATE', 'version': index + 4}
            for index in range(2)
        ]
        protocols = [
            {'endpoint_id': endpoint_ids[index], 'node_id': node_ids[index],
             'network_access_binding_id': access_ids[index], 'network_access_epoch': index + 10,
             'network_access_expires_at': _go_utc(self.now + timedelta(minutes=22)),
             'native_binding_id': native_ids[index], 'native_binding_epoch': index + 20,
             'group_membership_roles': ['member'], 'group_membership_grants': [], 'native_runtime': 'NOT_RUN'}
            for index in range(2)
        ]
        full_link = {
            'link_id': setup_link['link_id'],
            'source_endpoint_id': source_ep, 'source_principal_id': 'principal_f6_source',
            'source_group_id': source_group, 'source_owner_id': owner_ids[0], 'source_node_id': source_node,
            'target_endpoint_id': target_ep, 'target_principal_id': 'principal_f6_target',
            'target_group_id': target_group, 'target_owner_id': owner_ids[1], 'target_node_id': target_node,
            'direction': 'BIDIRECTIONAL', 'actions': ['read'], 'data_scopes': ['messages'],
            'transport_hub_id': cfg['hub_id'], 'expires_at': setup_link['expires_at'],
            'scope_snapshot': {
                'source_membership_revision': 1, 'source_join_revision': 1, 'source_group_version': 1,
                'target_membership_revision': 1, 'target_join_revision': 1, 'target_group_version': 1,
            },
            'contract_digest': setup_link['contract_digest'], 'state': 'PROPOSED', 'version': 1,
            'created_at': _go_utc(self.now - timedelta(minutes=2)),
            'updated_at': _go_utc(self.now - timedelta(minutes=1)),
        }
        side_rows = []
        for index in range(2):
            public = _public_identity(endpoint_key_ids[index], index + 20)
            side = {
                'endpoint_id': endpoint_ids[index], 'group_id': group_ids[index],
                'principal_id': f'principal_f6_{("source", "target")[index]}',
                'owner_id': owner_ids[index], 'node_id': node_ids[index],
                'binding_id': binding_ids[index], 'binding_epoch': index + 2,
                'candidate_version': index + 4, 'key_id': endpoint_key_ids[index],
                'key_fingerprint': 'sha256:' + ('d' if index == 0 else 'e') * 64,
                'proof_digest': '0' * 64,
                'public_identity': public,
            }
            _attestation(side)
            side_rows.append(side)
        reference = {
            'version': 2, 'link_id': setup_link['link_id'], 'link_version': 1,
            'contract_digest': setup_link['contract_digest'],
            'contract_canonical': base64.b64encode(b'{}').decode('ascii'),
            'source': side_rows[0], 'target': side_rows[1], 'digest': '1' * 64,
        }
        public_owners = [
            {
                'owner_id': owner_ids[index], 'owner_key_id': owner_key_ids[index],
                'public_identity': owners[index]['public_identity'],
                'source_of_pin': 'host-generated Owner public identity, independently checked before Hub registration',
                'hub_registration': 'ACTIVE public key only; Hub has no Owner private key',
                'private_key_policy': 'host-only mode 0600; not mounted into Hub, helper build container, or APK',
            }
            for index in range(2)
        ]
        build = {
            'revision': cfg['core_revision'], 'source_fingerprint': cfg['source_fingerprint'],
            'catalog_sha256': cfg['catalog_sha256'], 'contract_revision': cfg['contract_revision'],
            'hub_image_id': cfg['hub_image_id'], 'interop_image_id': cfg['interop_image_id'],
        }
        fixture = {
            'networks': networks, 'protocol_layers': protocols,
            'review_policy_qualification': carrier._F6_REVIEW_QUALIFICATION,
            'bindings': bindings, 'endpoint_candidates': candidates,
            'schema': 'cicada.client-link-v164-fixture.v1', 'status': 'READY_FOR_CLIENT_COORDINATION',
            'protocol_scope': 'SYNTHETIC_PROTOCOL_ONLY', 'native_runtime': 'NOT_RUN', 'model_calls': 'NONE',
            'build': build, 'hub_id': cfg['hub_id'], 'owners': public_owners, 'link': full_link,
            'reference_manifest': reference,
            'reference_manifest_use': 'offline Store preflight only; Client must fetch and verify a fresh encrypted link.key_manifest before consent or signing',
            'endpoint_private_key_policy': 'host-only mode 0600; never mounted into Hub, helper build container, or APK',
            'owner_private_key_policy': 'host-only mode 0600; never mounted into Hub, helper build container, or APK',
            'scope': 'No Runtime, native Endpoint, model call, physical device, or public HTTPS claim.',
        }
        return cfg, setup, fixture, reference, self._owned_manifest(cfg)

    def _owned_manifest(self, cfg):
        root = self.root
        container_id = 'a' * 64
        network_id = 'b' * 64
        labels = {
            'org.cicada.fixture': 'client-link-v164-06',
            'org.cicada.fixture.dir': str(root),
            'org.cicada.fixture.source.revision': cfg['core_revision'],
            'org.cicada.fixture.catalog.sha256': cfg['catalog_sha256'],
            'org.cicada.fixture.source.fingerprint': cfg['source_fingerprint'],
            'org.cicada.fixture.image.id': cfg['hub_image_id'],
        }
        network_name = 'cicada-cl164-06-network'
        container_name = 'cicada-cl164-06-hub'
        return {
            'schema': 'cicada.client-link-v164-owned-docker-manifest.v1',
            'captured_at_utc': _python_utc(self.now), 'fixture_dir': str(root),
            'container': {
                'id': container_id, 'name': container_name,
                'created': _go_utc(self.now - timedelta(minutes=10)),
                'image_id': cfg['hub_image_id'], 'state': {'Running': True, 'Status': 'running'},
                'entrypoint': ['/usr/local/bin/cicada'],
                'cmd': ['serve', '--host', '0.0.0.0', '--port', '8787'], 'user': '1000:1000',
                'labels': labels, 'environment_variable_names': ['CICADA_API_TOKEN'],
                'resource_caps': {'memory': 536870912, 'nano_cpus': 1000000000, 'pids_limit': 256},
                'network_mode': network_name,
                'port_bindings': {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(cfg['host_port'])}]},
                'mounts': [
                    {'source': str(root / 'state'), 'destination': '/state', 'rw': True, 'type': 'bind'},
                    {'source': str(root / 'workspace'), 'destination': '/workspace', 'rw': True, 'type': 'bind'},
                ],
                'networks': [network_name],
            },
            'network': {
                'id': network_id, 'name': network_name, 'driver': 'bridge',
                'internal': False, 'attachable': False, 'labels': labels,
                'containers': {container_id: {}},
            },
            'secret_environment_values_recorded': False,
        }

    def _write_references(self):
        self.reference['link_id'] = self.fixture_public['link']['link_id']
        self.manifest['container']['id'] = 'a' * 64
        self.manifest['network']['id'] = 'b' * 64
        (self.root / 'public').mkdir()
        (self.root / 'helper-src').mkdir()
        (self.root / 'bin').mkdir()
        (self.root / 'fixture.sh').write_bytes(b'#!/bin/sh\n')
        (self.root / 'fixture.sh').chmod(0o700)
        (self.root / 'public/client-setup.json').write_bytes(_json_bytes(self.setup))
        (self.root / 'public/client-setup.json').chmod(0o644)
        (self.root / 'public/custody.json').write_bytes(_json_bytes({
            'schema': 'cicada.client-link-v164-fixture.v1', 'private_key_root': str(self.root),
            'owner_private_files': [
                {'path': 'owner-private/source-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
                {'path': 'owner-private/target-owner-private.bin', 'mode': '0600', 'custody': 'host only'},
            ],
            'endpoint_private_files': [
                {'path': 'endpoint-private/source-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
                {'path': 'endpoint-private/target-endpoint-private.bin', 'mode': '0600', 'custody': 'host only'},
            ],
            'not_mounted_into': ['Hub', 'interop helper build container', 'APK'],
        }))
        (self.root / 'public/custody.json').chmod(0o600)
        (self.root / 'public/fixture-public.json').write_bytes(_json_bytes(self.fixture_public))
        (self.root / 'public/fixture-public.json').chmod(0o600)
        (self.root / 'public/reference-manifest.json').write_bytes(_json_bytes(self.reference))
        (self.root / 'public/reference-manifest.json').chmod(0o600)
        source = b'// Synthetic public helper source for structural tests.\n'
        (self.root / 'helper-src/main.go').write_bytes(source)
        (self.root / 'helper-src/main.go').chmod(0o600)
        binary = b'opaque test bytes; not executed\n'
        (self.root / 'bin/cicada-link-v164-fixture').write_bytes(binary)
        (self.root / 'bin/cicada-link-v164-fixture').chmod(0o755)
        (self.root / 'evidence/attempt-06').mkdir(parents=True)
        capabilities = {field: False for field in carrier._F6_CAPABILITY_FIELDS
            if field not in {'contract', 'contract_revision', 'catalog_sha256', 'status',
                'planned_platform', 'available_rpc_operations', 'external_rpc_operations'}}
        capabilities.update({
            'contract': 'android-hub-v1-draft',
            'contract_revision': self.config['contract_revision'],
            'catalog_sha256': self.config['catalog_sha256'],
            'status': 'partial',
            'planned_platform': 'android',
            'client_control_pq_e2ee': True,
            'authenticated_client_session': True,
            'link_key_consent': True,
            'external_thread_links': False,
            'status_events': False,
            'available_rpc_operations': ['link.key_manifest', 'link.key_grants'],
            'external_rpc_operations': [],
        })
        hub_ready = {
            'stage': 'final',
            'base_url': f"http://127.0.0.1:{self.config['host_port']}",
            'health': {
                'status': 'ok', 'service': 'cicada-control', 'version': '0.1.0-dev',
                'stage': 'codex-supervisor', 'revision': self.config['core_revision'],
                'dirty': False, 'source_fingerprint': self.config['source_fingerprint'],
                'catalog_sha256': self.config['catalog_sha256'],
            },
            'identity': {
                'contract': 'android-hub-v1', 'hub_id': self.config['hub_id'],
                'control_public_identity': self.setup['hub']['control_public_identity'],
                'control_key_version': 1,
                'suite': 'ML-KEM-768+ML-DSA-65+AES-256-GCM',
            },
            'capabilities': capabilities,
        }
        (self.root / 'evidence/attempt-06/hub-ready-final.json').write_bytes(_json_bytes(hub_ready))
        (self.root / 'evidence/attempt-06/hub-ready-final.json').chmod(0o600)
        provenance = {
            'schema': 'cicada.client-link-v164-helper-build.v1',
            'helper_source_path': 'helper-src/main.go', 'helper_source_sha256': _sha(source),
            'helper_binary_path': 'bin/cicada-link-v164-fixture', 'helper_binary_sha256': _sha(binary),
            'builder_image_id': self.config['interop_image_id'], 'builder_entrypoint_override': 'go',
            'helper_source_image_mount': '/src/cmd/cicada-client-link-v164-fixture-06',
            'private_keys_mounted_during_build': False, 'shipped_hub_binary_modified': False,
        }
        (self.root / 'evidence/attempt-06/helper-provenance.json').write_bytes(_json_bytes(provenance))
        (self.root / 'evidence/attempt-06/helper-provenance.json').chmod(0o600)
        self.manifest_raw = _json_bytes(self.manifest)

        ref_rows = {}
        row_paths = dict(carrier._F6_PUBLIC_PATHS)
        row_paths.update({
            'hub_ready': ('evidence/attempt-06/hub-ready-final.json', 0o100600),
            'helper_provenance': ('evidence/attempt-06/helper-provenance.json', 0o100600),
        })
        for name, (relative, _mode) in row_paths.items():
            raw = (self.root / relative).read_bytes()
            ref_rows[name] = {
                'path': str(self.root / relative), 'relative_path': relative,
                'sha256': _sha(raw), 'bytes': len(raw),
                'mode': oct((self.root / relative).stat().st_mode),
            }
        ref_rows['helper_binary'] = {
            'path': str(self.root / 'bin/cicada-link-v164-fixture'),
            'relative_path': 'bin/cicada-link-v164-fixture',
            'sha256': _sha(binary), 'bytes': len(binary),
            'mode': oct((self.root / 'bin/cicada-link-v164-fixture').stat().st_mode),
        }
        ready = {
            'schema': 'cicada.client-link-v164-fixture-ready.v1',
            'status': 'READY_FOR_CLIENT_COORDINATION', 'fixture_root': str(self.root),
            'protocol_scope': 'SYNTHETIC_PROTOCOL_ONLY', 'native_runtime': 'NOT_RUN', 'model_calls': 0,
            'public_references': ref_rows, 'source': self.fixture_public['build'],
            'hub': {
                'hub_id': self.config['hub_id'], 'base_url': f"http://127.0.0.1:{self.config['host_port']}",
                'container_id': self.manifest['container']['id'], 'network_id': self.manifest['network']['id'],
                'link_id': self.fixture_public['link']['link_id'], 'link_state': 'PROPOSED', 'link_version': 1,
                'bindings': self.fixture_public['bindings'], 'business_networks': self.fixture_public['networks'],
                'review_policy_qualification': carrier._F6_REVIEW_QUALIFICATION,
            },
            'client_setup_sha256': ref_rows['client_setup']['sha256'],
            'hub_ready_sha256': ref_rows['hub_ready']['sha256'],
            'reference_manifest_sha256': ref_rows['reference_manifest']['sha256'],
            'owned_manifest_sha256': self.config['manifest_sha256'],
            'coordination_nonce': 'f' * 48,
            'coordination_deadline': _go_utc(self.now + timedelta(minutes=10)),
            'coordination_ttl_seconds': 720,
            'cleanup_policy': 'one terminal consumer ACK or fixed deadline; no renewal; fresh private state destroyed',
        }
        self.config['setup_sha256'] = ready['client_setup_sha256']
        self.config['reference_sha256'] = ready['reference_manifest_sha256']
        self.ready = ready
        return ready

    def _validate(self, ready=None, *, config=None, setup=None, manifest=None):
        with mock.patch.object(carrier, 'F6_MAIN_ROOT', self.root):
            return carrier._validate_f6_ready(
                copy.deepcopy(ready if ready is not None else self.ready),
                copy.deepcopy(setup if setup is not None else self.setup),
                copy.deepcopy(manifest if manifest is not None else self.manifest),
                copy.deepcopy(config if config is not None else self.config),
            )

    def test_synthetic_main17_scope_and_dynamic_attempt_pass(self):
        loaded = self._validate()
        self.assertEqual(loaded['fixture_public']['build']['revision'], carrier.F6_MAIN_REVISION)
        self.assertEqual(self.ready['public_references']['hub_ready']['relative_path'],
            'evidence/attempt-06/hub-ready-final.json')

    def test_draft_unknown_fields_and_non_boolean_numeric_values_fail(self):
        mutations = (
            lambda ready: ready.update(status='DRAFT_SCHEMA_ONLY_NOT_AUTHORIZED'),
            lambda ready: ready.update(unreviewed=True),
            lambda ready: ready.update(model_calls=True),
            lambda ready: ready.update(coordination_ttl_seconds=True),
            lambda ready: ready['hub'].update(link_version=True),
            lambda ready: ready['hub']['bindings'][0].update(epoch=True),
        )
        for mutate in mutations:
            ready = copy.deepcopy(self.ready)
            mutate(ready)
            with self.subTest(ready=ready), self.assertRaises(ValueError):
                self._validate(ready)

    def test_wrong_core_source_pin_or_review_qualification_fails(self):
        bad_core = copy.deepcopy(self.config)
        bad_core['core_revision'] = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
        with self.assertRaises(ValueError):
            self._validate(config=bad_core)
        bad_policy = copy.deepcopy(self.ready)
        bad_policy['hub']['review_policy_qualification'] = 'METADATA_PREPARED'
        with self.assertRaises(ValueError):
            self._validate(bad_policy)
        bad_network = copy.deepcopy(self.ready)
        bad_network['hub']['business_networks'][0]['state'] = 'PENDING'
        with self.assertRaises(ValueError):
            self._validate(bad_network)

    def test_attestation_is_bounded_full_json_with_digest_and_scope_binding(self):
        side = copy.deepcopy(self.reference['source'])
        self.assertEqual(carrier._f6_validate_endpoint_attestation(side),
            base64.b64decode(side['attestation']))
        wrong_digest = copy.deepcopy(side)
        wrong_digest['proof_digest'] = '0' * 64
        with self.assertRaises(ValueError):
            carrier._f6_validate_endpoint_attestation(wrong_digest)
        wrong_scope = copy.deepcopy(side)
        proof = json.loads(base64.b64decode(wrong_scope['attestation']))
        proof['endpoint_id'] = 'ep_f6_other'
        raw = _json_bytes(proof)
        wrong_scope['attestation'] = base64.b64encode(raw).decode('ascii')
        wrong_scope['proof_digest'] = _sha(raw)
        with self.assertRaises(ValueError):
            carrier._f6_validate_endpoint_attestation(wrong_scope)

    def test_ttl_expiry_and_oversized_deadline_fail(self):
        expired = copy.deepcopy(self.ready)
        expired['coordination_deadline'] = _go_utc(self.now - timedelta(seconds=1))
        with self.assertRaises(ValueError):
            self._validate(expired)
        too_long = copy.deepcopy(self.ready)
        too_long['coordination_deadline'] = _go_utc(self.now + timedelta(minutes=13))
        with self.assertRaises(ValueError):
            self._validate(too_long)

    def test_public_reference_tamper_wrong_mode_and_symlink_fail(self):
        source = self.root / 'helper-src/main.go'
        original = source.read_bytes()
        source.write_bytes(original + b'changed')
        with self.assertRaises(ValueError):
            self._validate()
        source.write_bytes(original)
        source.chmod(0o644)
        with self.assertRaises(ValueError):
            self._validate()
        source.unlink()
        source.symlink_to(self.root / 'fixture.sh')
        with self.assertRaises(ValueError):
            self._validate()

    def test_unknown_reference_or_unavailable_network_projection_fail(self):
        extra = copy.deepcopy(self.ready)
        extra['public_references']['runner']['raw'] = 'unexpected'
        with self.assertRaises(ValueError):
            self._validate(extra)
        missing_network = copy.deepcopy(self.ready)
        missing_network['hub']['business_networks'].pop()
        with self.assertRaises(ValueError):
            self._validate(missing_network)

    def test_owned_manifest_rejects_foreign_mount_and_wrong_root(self):
        bad_manifest = copy.deepcopy(self.manifest)
        bad_manifest['container']['mounts'].append({
            'source': str(self.root / 'owner-private'), 'destination': '/owner-private',
            'rw': True, 'type': 'bind',
        })
        with self.assertRaises(ValueError):
            self._validate(manifest=bad_manifest)
        bad_manifest = copy.deepcopy(self.manifest)
        bad_manifest['fixture_dir'] = str(self.root / 'other')
        with self.assertRaises(ValueError):
            self._validate(manifest=bad_manifest)


if __name__ == '__main__':
    unittest.main()
