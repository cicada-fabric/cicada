"""Self-contained offline tests for the v1.6.1 native Link topology guard."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import secrets
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / 'scripts/interop/v16-native-link-fixture.py'
spec = importlib.util.spec_from_file_location('v16_native_link_fixture_tested', MODULE_PATH)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _write_private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def _hub_labels(root, run_id):
    return {
        'org.cicada.fixture': 'client-network',
        'org.cicada.fixture.catalog.sha256': native.CATALOG_SHA256,
        'org.cicada.fixture.dir': str(root),
        'org.cicada.fixture.run': run_id,
        'org.cicada.fixture.source.fingerprint': native.SOURCE_FINGERPRINT,
        'org.cicada.fixture.source.revision': native.CORE_REVISION,
    }


def _internal_labels(root, run_id):
    return {
        'org.cicada.fixture': 'client-link-native',
        'org.cicada.fixture.dir': str(root),
        'org.cicada.fixture.run': run_id,
    }


def _mount(source, destination, *, read_write=True, mode=''):
    return {
        'Type': 'bind', 'Source': source, 'Destination': destination,
        'RW': read_write, 'Mode': mode, 'Propagation': 'rprivate',
    }


def _make_documents(root, topology_path, mounts_path):
    run_id = 'clnf-0123456789abcdef'
    hub_id, node_a_id, node_b_id = ('1' * 64, '2' * 64, '3' * 64)
    regular_id, node_a_net_id, node_b_net_id = ('a' * 64, 'b' * 64, 'c' * 64)
    host_port = 34879
    hub_name = 'cicada-cn-' + re.sub(r'[^a-z0-9]', '', root.name.lower()) + '-hub'
    regular_name = 'cicada-cn-' + re.sub(r'[^a-z0-9]', '', root.name.lower()) + '-net'
    node_a_name, node_b_name = run_id + '-a', run_id + '-b'
    node_a_net_name, node_b_net_name = node_a_name + '-net', node_b_name + '-net'

    hub = {
        'id': hub_id, 'name': hub_name, 'role': 'hub',
        'immutable_image_id': native.HUB_IMAGE, 'configured_image_id': native.HUB_IMAGE,
        'running': True, 'user': '1000:1000', 'fixture_labels': _hub_labels(root, run_id),
        'cap_drop': ['ALL'], 'privileged': False, 'security_options': ['no-new-privileges'],
        'sysctls': {'net.ipv4.ip_forward': '0'}, 'primary_network_name': regular_name,
        'networks': [
            {'name': regular_name, 'id': regular_id, 'ip': '172.22.0.2'},
            {'name': node_a_net_name, 'id': node_a_net_id, 'ip': '172.20.0.3'},
            {'name': node_b_net_name, 'id': node_b_net_id, 'ip': '172.21.0.3'},
        ],
        'published_ports': {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(host_port)}]},
        'owner_private_mounts_absent': True,
    }
    node_a = {
        'id': node_a_id, 'name': node_a_name, 'role': 'node_a',
        'immutable_image_id': native.NODE_IMAGE, 'configured_image_id': native.NODE_IMAGE,
        'running': True, 'user': '1000:1000', 'fixture_labels': _internal_labels(root, run_id),
        'cap_drop': ['ALL'], 'privileged': False, 'security_options': ['no-new-privileges'],
        'sysctls': {}, 'primary_network_name': node_a_net_name,
        'networks': [{'name': node_a_net_name, 'id': node_a_net_id, 'ip': '172.20.0.2'}],
        'published_ports': {}, 'owner_private_mounts_absent': True,
    }
    node_b = {
        'id': node_b_id, 'name': node_b_name, 'role': 'node_b',
        'immutable_image_id': native.NODE_IMAGE, 'configured_image_id': native.NODE_IMAGE,
        'running': True, 'user': '1000:1000', 'fixture_labels': _internal_labels(root, run_id),
        'cap_drop': ['ALL'], 'privileged': False, 'security_options': ['no-new-privileges'],
        'sysctls': {}, 'primary_network_name': node_b_net_name,
        'networks': [{'name': node_b_net_name, 'id': node_b_net_id, 'ip': '172.21.0.2'}],
        'published_ports': {}, 'owner_private_mounts_absent': True,
    }
    regular = {
        'id': regular_id, 'name': regular_name, 'role': 'hub_client_regular', 'driver': 'bridge',
        'internal': False, 'ipv6_enabled': False, 'subnet': '172.22.0.0/16',
        'gateway': '172.22.0.1', 'fixture_labels': _hub_labels(root, run_id),
        'members': [{'container_id': hub_id, 'name': hub_name, 'role': 'hub',
            'ipv4_cidr': '172.22.0.2/16'}],
    }
    bridge_a = {
        'id': node_a_net_id, 'name': node_a_net_name, 'role': 'node_a_internal', 'driver': 'bridge',
        'internal': True, 'ipv6_enabled': False, 'subnet': '172.20.0.0/16',
        'gateway': '172.20.0.1', 'fixture_labels': _internal_labels(root, run_id),
        'members': [
            {'container_id': hub_id, 'name': hub_name, 'role': 'hub', 'ipv4_cidr': '172.20.0.3/16'},
            {'container_id': node_a_id, 'name': node_a_name, 'role': 'node_a', 'ipv4_cidr': '172.20.0.2/16'},
        ],
    }
    bridge_b = {
        'id': node_b_net_id, 'name': node_b_net_name, 'role': 'node_b_internal', 'driver': 'bridge',
        'internal': True, 'ipv6_enabled': False, 'subnet': '172.21.0.0/16',
        'gateway': '172.21.0.1', 'fixture_labels': _internal_labels(root, run_id),
        'members': [
            {'container_id': hub_id, 'name': hub_name, 'role': 'hub', 'ipv4_cidr': '172.21.0.3/16'},
            {'container_id': node_b_id, 'name': node_b_name, 'role': 'node_b', 'ipv4_cidr': '172.21.0.2/16'},
        ],
    }
    marker_path = root / '.cicada-client-network-fixture.json'
    public_path = root / 'client-public.json'
    marker = {
        'schema': 'cicada.client-network-fixture.v2', 'fixture_dir': str(root),
        'source_dirty': False, 'source_revision': native.CORE_REVISION,
        'source_fingerprint': native.SOURCE_FINGERPRINT, 'catalog_sha256': native.CATALOG_SHA256,
        'contract_revision': native.CONTRACT_REVISION, 'image_id': native.HUB_IMAGE,
        'container': hub_name, 'network': regular_name, 'host_port': host_port,
    }
    public = {
        'schema': 'cicada.client-network-fixture-result.v2',
        'base_url': 'http://127.0.0.1:' + str(host_port), 'host_port': host_port,
        'docker_network': regular_name, 'image_id': native.HUB_IMAGE,
        'source_revision': native.CORE_REVISION, 'source_fingerprint': native.SOURCE_FINGERPRINT,
        'catalog_sha256': native.CATALOG_SHA256, 'contract_revision': native.CONTRACT_REVISION,
    }
    marker_raw = _json_bytes(marker)
    public_raw = _json_bytes(public)
    post_ready_sha = 'f' * 64
    topology = {
        'schema': native.TOPOLOGY_SCHEMA, 'synthetic_fixture': True,
        'not_real_user_approval': True, 'generated_utc': '2026-10-02T00:00:00Z',
        'fixture_root': str(root), 'fixture_run_id': run_id,
        'compatible_marker_path': str(marker_path), 'compatible_marker_sha256': _sha(marker_raw),
        'client_public_path': str(public_path), 'client_public_sha256': _sha(public_raw),
        'base_url': public['base_url'], 'hub_service_port': 8787,
        'producer_metadata_sha256': '4' * 64, 'product_revision': native.CORE_REVISION,
        'producer_source_fingerprint': native.SOURCE_FINGERPRINT,
        'actual_helper_overlay_source_fingerprint': '5' * 64,
        'contract_revision': native.CONTRACT_REVISION, 'catalog_sha256': native.CATALOG_SHA256,
        'hub_image_id': native.HUB_IMAGE, 'node_runtime_image_id': native.NODE_IMAGE,
        'node_binary_sha256': '6' * 64, 'frozen_owned_manifest_sha256': '7' * 64,
        'post_ready_receipt_sha256': post_ready_sha,
        'containers': [hub, node_a, node_b], 'networks': [regular, bridge_b, bridge_a],
        'exact_label_owned_container_ids': [hub_id, node_a_id, node_b_id],
        'exact_label_owned_network_ids': [regular_id, node_b_net_id, node_a_net_id],
        'verified_against_original_resources_and_marker': True, 'no_extra_members': True,
        'no_node_cross_bridge_attachment': True, 'host_client_publish_localhost_only': True,
        'hub_ipv4_forwarding_disabled': True, 'owner_private_mounts_absent': True,
    }
    topology_raw = _json_bytes(topology)
    topology_sha = _sha(topology_raw)
    ids = [hub_id, node_a_id, node_b_id]
    mount_sets = [
        [_mount(str(root / 'hub-state'), '/state')],
        [
            _mount(str(root / 'cicada'), '/out/cicada', read_write=False, mode='ro'),
            _mount(str(root / 'node-a-codex'), '/codex'),
            _mount(str(root / 'node-a-mcp'), '/mcp'),
            _mount(str(root / 'node-a-state'), '/state'),
            _mount(str(root / 'node-a-workspace'), '/workspace'),
        ],
        [
            _mount(str(root / 'cicada'), '/out/cicada', read_write=False, mode='ro'),
            _mount(str(root / 'node-b-codex'), '/codex'),
            _mount(str(root / 'node-b-mcp'), '/mcp'),
            _mount(str(root / 'node-b-state'), '/state'),
            _mount(str(root / 'node-b-workspace'), '/workspace'),
        ],
    ]
    rows = []
    for identifier, container, mounts in zip(ids, topology['containers'], mount_sets):
        rows.append({
            'id': identifier, 'name': container['name'], 'role': container['role'],
            'mount_count': len(mounts), 'mounts': mounts,
            'original_mount_sources_count': len(mounts),
            'original_recorded_mount_sources': sorted(item['Source'] for item in mounts),
            'original_source_list_exact_match': True,
        })
    sort_fields = ['Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation']
    mounts_document = {
        'artifact_owner': {
            'agent': 'synthetic-offline-test', 'gid': os.getgid(), 'raw_mode': '0o100600',
            'scope': 'New supplementary public allowlist only; original topology and receipts unchanged.',
            'uid': os.getuid(),
        },
        'comparison_contract': {
            'deny': 'Docker socket, /root, /run/user, unrelated host home, foreign Node state/workspace/MCP/runtime, unexpected mounts, writable shared binary.',
            'fields': sort_fields, 'preserve_count_and_duplicates': True,
            'require_exact_static_arrays': True,
            'rule': 'Compare exact sorted six-field rows and retain count and duplicates.',
            'runtime_home_rule': 'Synthetic fixture source allowlist is exact.',
            'sort_fields': sort_fields,
        },
        'containers': rows, 'exact_container_ids': ids,
        'fixture_root': str(root), 'fixture_run_id': run_id,
        'inspected_utc': '2026-10-02T00:00:00Z',
        'inspection': {
            'argv': ['docker', 'inspect', '--format', '{{json .Mounts}}', *ids],
            'exit': 0, 'mismatches': [], 'no_env_or_content_reads': True,
            'original_sources_sorted_count_and_exact_list_match': True,
            'resource_mutations': False, 'selected_field_only': 'Mounts',
        },
        'not_real_user_approval': True,
        'original_result_path': str(topology_path.parents[1] / 'result.json'),
        'original_result_sha256': post_ready_sha,
        'public_topology_path': str(topology_path), 'public_topology_sha256': topology_sha,
        'schema': 'cicada.client-link-native.mount-allowlist.v1', 'synthetic_fixture': True,
    }
    mounts_raw = _json_bytes(mounts_document)
    return topology, topology_raw, marker_raw, public_raw, mounts_document, mounts_raw


def _synthetic_inventory(topology, mounts_document):
    containers = {}
    for row in topology['containers']:
        attachments = {}
        for network in row['networks']:
            attachments[network['name']] = {
                'id': network['id'], 'ip': network['ip'],
                'aliases': ['hub'] if row['role'] == 'hub' and
                    network['name'] == row['primary_network_name'] else [],
            }
        mount_row = next(item for item in mounts_document['containers'] if item['id'] == row['id'])
        labels = native._labels_for_hub(row['fixture_labels']) if row['role'] == 'hub' else \
            copy.deepcopy(row['fixture_labels'])
        containers[row['id']] = {
            'id': row['id'], 'name': row['name'], 'image': row['immutable_image_id'],
            'configured_image': row['configured_image_id'], 'running': row['running'],
            'user': row['user'], 'labels': labels, 'cap_drop': copy.deepcopy(row['cap_drop']),
            'privileged': row['privileged'], 'security_options': copy.deepcopy(row['security_options']),
            'sysctls': copy.deepcopy(row['sysctls']), 'network_mode': row['primary_network_name'],
            'primary_network_name': row['primary_network_name'], 'networks': attachments,
            'published_ports': copy.deepcopy(row['published_ports']),
            'port_bindings': {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': ''}]}
                if row['role'] == 'hub' else {},
            'mounts': copy.deepcopy(mount_row['mounts']),
        }
    networks = {}
    for row in topology['networks']:
        networks[row['id']] = {
            'id': row['id'], 'name': row['name'], 'driver': row['driver'],
            'internal': row['internal'], 'ipv6_enabled': row['ipv6_enabled'],
            'subnet': row['subnet'], 'gateway': row['gateway'],
            'labels': copy.deepcopy(row['fixture_labels']),
            'members': {member['container_id']: {
                'name': member['name'], 'ipv4_cidr': member['ipv4_cidr'],
            } for member in row['members']},
        }
    image_labels = {
        'org.opencontainers.image.revision': native.CORE_REVISION,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': native.SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': native.CATALOG_SHA256,
        'org.cicada.role': 'hub',
    }
    return {
        'container_ids': list(reversed([row['id'] for row in topology['containers']])),
        'network_ids': list(reversed([row['id'] for row in topology['networks']])),
        'containers': containers, 'networks': networks,
        'images': {
            native.HUB_IMAGE: {'id': native.HUB_IMAGE, 'labels': image_labels},
            native.NODE_IMAGE: {'id': native.NODE_IMAGE, 'labels': {}},
        },
    }


class NativeLinkFixtureValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='cicada-native-link-test-')
        parent = Path(cls.temp.name) / 'private-hop-freeze' / 'approved-execution'
        cls.public_dir = parent / 'new-public-topology'
        cls.public_dir.mkdir(parents=True, mode=0o700)
        cls.fixture_root = Path('/tmp') / ('cn.' + secrets.token_hex(4))
        cls.fixture_root.mkdir(mode=0o700)
        cls.topology_path = cls.public_dir / 'public-topology.json'
        cls.mounts_path = cls.public_dir / 'mount-allowlist.json'
        (parent / 'result.json').write_text('synthetic receipt path only\n')
        (parent / 'result.json').chmod(0o600)
        (cls.fixture_root / 'hub-state').mkdir(mode=0o700)
        cls.topology, cls.topology_raw, cls.marker_raw, cls.public_raw, \
            cls.mounts_document, cls.mounts_raw = _make_documents(
                cls.fixture_root, cls.topology_path, cls.mounts_path)
        cls.fixture_path = cls.topology['compatible_marker_path']
        cls.public_path = cls.topology['client_public_path']
        _write_private(Path(cls.fixture_path), cls.marker_raw)
        _write_private(Path(cls.public_path), cls.public_raw)
        _write_private(cls.topology_path, cls.topology_raw)
        _write_private(cls.mounts_path, cls.mounts_raw)
        cls.topology_sha256 = _sha(cls.topology_raw)
        cls.fixture_sha256 = _sha(cls.marker_raw)
        cls.public_sha256 = _sha(cls.public_raw)
        cls.mounts_sha256 = _sha(cls.mounts_raw)
        cls.original_pins = (native.TRUSTED_TOPOLOGY_SHA256, native.TRUSTED_MOUNTS_SHA256)
        native.TRUSTED_TOPOLOGY_SHA256 = cls.topology_sha256
        native.TRUSTED_MOUNTS_SHA256 = cls.mounts_sha256
        cls.topology_raw, cls.marker_raw, cls.public_raw, cls.mounts_raw = native.read_native_inputs(
            cls.topology_path, cls.fixture_path, cls.public_path, cls.mounts_path,
            cls.topology_sha256, cls.fixture_sha256, cls.public_sha256, cls.mounts_sha256)
        cls.topology = native.strict_json(cls.topology_raw)
        cls.mounts_document = native.strict_json(cls.mounts_raw)
        cls.inventory = _synthetic_inventory(cls.topology, cls.mounts_document)

    @classmethod
    def tearDownClass(cls):
        native.TRUSTED_TOPOLOGY_SHA256, native.TRUSTED_MOUNTS_SHA256 = cls.original_pins
        cls.temp.cleanup()
        shutil.rmtree(cls.fixture_root, ignore_errors=True)

    def validate(self, *, inventory=None, topology_raw=None, marker_raw=None, public_raw=None,
            mounts_raw=None, topology_sha256=None, fixture_sha256=None, public_sha256=None,
            mounts_sha256=None):
        return native.validate_files_and_inventory(
            self.topology_raw if topology_raw is None else topology_raw,
            self.marker_raw if marker_raw is None else marker_raw,
            self.public_raw if public_raw is None else public_raw,
            self.mounts_raw if mounts_raw is None else mounts_raw,
            topology_sha256=self.topology_sha256 if topology_sha256 is None else topology_sha256,
            fixture_sha256=self.fixture_sha256 if fixture_sha256 is None else fixture_sha256,
            public_sha256=self.public_sha256 if public_sha256 is None else public_sha256,
            mounts_sha256=self.mounts_sha256 if mounts_sha256 is None else mounts_sha256,
            topology_path=str(self.topology_path), fixture_path=self.fixture_path,
            public_path=self.public_path, mounts_path=str(self.mounts_path),
            inventory=copy.deepcopy(self.inventory if inventory is None else inventory))

    def test_exact_pinned_topology_and_synthetic_inventory_pass(self):
        fixture, public, hub, network, target_ip, target_port = self.validate()
        self.assertEqual(fixture['container'], self.topology['containers'][0]['name'])
        self.assertEqual(public['base_url'], self.topology['base_url'])
        self.assertEqual(hub['Id'], self.topology['containers'][0]['id'])
        self.assertEqual(network['Id'], self.topology['networks'][0]['id'])
        self.assertEqual(target_ip, '172.22.0.2')
        self.assertEqual(target_port, 8787)

    def test_rejects_wrong_topology_hash(self):
        with self.assertRaises(ValueError):
            self.validate(topology_sha256='0' * 64)

    def test_rejects_changed_marker_and_public_bytes(self):
        with self.assertRaises(ValueError):
            self.validate(marker_raw=self.marker_raw + b' ')
        with self.assertRaises(ValueError):
            self.validate(public_raw=self.public_raw + b' ')

    def test_rejects_duplicate_json_fields(self):
        with self.assertRaises(ValueError):
            native.strict_json(b'{"fixture_root":"/tmp/cn.00000000","fixture_root":"/tmp/cn.11111111"}')

    def test_rejects_extra_owned_container_and_network(self):
        changed = copy.deepcopy(self.inventory)
        changed['container_ids'].append('f' * 64)
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['network_ids'].append('f' * 64)
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_wrong_full_container_id_and_image(self):
        hub_id = self.topology['containers'][0]['id']
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['id'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['image'] = native.NODE_IMAGE
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_changed_labels_and_privileges(self):
        hub_id = self.topology['containers'][0]['id']
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['labels']['org.cicada.fixture.run'] = 'foreign-run'
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['labels']['org.example.unrelated'] = 'unexpected'
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['cap_drop'] = []
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['privileged'] = True
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_node_cross_bridge_attachment(self):
        node_a = next(row for row in self.topology['containers'] if row['role'] == 'node_a')
        foreign_bridge = next(row for row in self.topology['networks'] if row['role'] == 'node_b_internal')
        changed = copy.deepcopy(self.inventory)
        changed['containers'][node_a['id']]['networks'][foreign_bridge['name']] = {
            'id': foreign_bridge['id'], 'ip': '172.21.0.4', 'aliases': [],
        }
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_foreign_bridge_member_and_changed_cidr(self):
        bridge = next(row for row in self.topology['networks'] if row['role'] == 'node_a_internal')
        changed = copy.deepcopy(self.inventory)
        changed['networks'][bridge['id']]['members']['f' * 64] = {
            'name': 'foreign-container', 'ipv4_cidr': '172.20.0.4/16',
        }
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        node_a = next(row for row in self.topology['containers'] if row['role'] == 'node_a')
        changed['networks'][bridge['id']]['members'][node_a['id']]['ipv4_cidr'] = '172.21.0.2/16'
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_public_host_publish_and_extra_hub_port(self):
        hub_id = self.topology['containers'][0]['id']
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['published_ports']['8787/tcp'][0]['HostIp'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        misconfigured = copy.deepcopy(self.inventory)
        misconfigured['containers'][hub_id]['port_bindings']['8787/tcp'][0]['HostIp'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            self.validate(inventory=misconfigured)
        changed = copy.deepcopy(self.inventory)
        extra = [{'HostIp': '127.0.0.1', 'HostPort': '34880'}]
        changed['containers'][hub_id]['published_ports']['9999/tcp'] = extra
        changed['containers'][hub_id]['port_bindings']['9999/tcp'] = copy.deepcopy(extra)
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_forwarding_setting(self):
        hub_id = self.topology['containers'][0]['id']
        changed = copy.deepcopy(self.inventory)
        changed['containers'][hub_id]['sysctls']['net.ipv4.ip_forward'] = '1'
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_mount_comparison_is_order_independent_and_exact(self):
        changed = copy.deepcopy(self.inventory)
        for row in changed['containers'].values():
            row['mounts'].reverse()
        self.validate(inventory=changed)
        node = next(row for row in self.topology['containers'] if row['role'] == 'node_a')
        changed = copy.deepcopy(self.inventory)
        changed['containers'][node['id']]['mounts'][0]['RW'] = True
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)
        changed = copy.deepcopy(self.inventory)
        changed['containers'][node['id']]['mounts'].append(
            copy.deepcopy(changed['containers'][node['id']]['mounts'][0]))
        with self.assertRaises(ValueError):
            self.validate(inventory=changed)

    def test_rejects_changed_mount_allowlist_hash(self):
        with self.assertRaises(ValueError):
            self.validate(mounts_sha256='0' * 64)


if __name__ == '__main__':
    unittest.main()
