#!/usr/bin/env python3
"""Fail-closed validator for the pinned v1.6.1 native Link fixture topology.

This module does not invoke Docker. Production callers pass a narrowly collected
inspection inventory; tests pass synthetic inventories. It never consumes
container environment variables or container file contents.
"""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


TRUSTED_TOPOLOGY_SHA256 = 'db4a30d22d487bc008ab9af87e518bf58a2cbfb8aabc143e3ed29fc284072dda'
TRUSTED_MOUNTS_SHA256 = '70c9d2f28037ac66fb05d5d039ad067f4dd018b94dd21d0606fd467a4c22dece'
TOPOLOGY_SCHEMA = 'cicada.client-link-native.public-topology.v1'
CONTRACT_REVISION = 'client-hub-v1.6.1'
CORE_REVISION = '144e079ddf62a4e08f1d1cf9476ab41d25d28f5c'
SOURCE_FINGERPRINT = 'e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902'
CATALOG_SHA256 = '6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b'
HUB_IMAGE = 'sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb'
NODE_IMAGE = 'sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57'
FIXTURE_LABEL = 'org.cicada.fixture'
FIXTURE_DIR_LABEL = 'org.cicada.fixture.dir'
FIXTURE_RUN_LABEL = 'org.cicada.fixture.run'


def _fail(message):
    raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('pinned JSON contains duplicate object fields')
        result[key] = value
    return result


def _reject_constant(_value):
    _fail('pinned JSON contains a non-finite number')


def _check_depth(value, depth=0):
    if depth > 16:
        _fail('pinned JSON exceeds its nesting bound')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail('pinned JSON object key is invalid')
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def strict_json(raw, *, maximum=256 * 1024):
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        _fail('pinned JSON has an invalid size')
    try:
        text = raw.decode('utf-8', errors='strict')
        value = json.loads(text, object_pairs_hook=_unique_object,
            parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('pinned JSON is malformed')
    _check_depth(value)
    if not isinstance(value, dict):
        _fail('pinned JSON root must be an object')
    return value


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _full_sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _secure_read(path_value, *, mode, maximum=256 * 1024):
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        _fail('pinned metadata path must be absolute and nonsymlinked')
    try:
        resolved = path.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        info = path.lstat()
        parent_info = path.parent.lstat()
        if resolved != path or parent != path.parent or stat.S_ISLNK(parent_info.st_mode):
            _fail('pinned metadata path is not canonical')
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or \
                info.st_uid != os.getuid() or info.st_nlink != 1:
            _fail('pinned metadata file does not have its required private ownership')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino) or \
                    before.st_size <= 0 or before.st_size > maximum:
                _fail('pinned metadata changed or exceeds its bound')
            chunks = bytearray()
            while len(chunks) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(fd)
            if len(chunks) != before.st_size or \
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                _fail('pinned metadata changed while it was read')
            return bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        _fail('pinned metadata file is unavailable')


def read_native_inputs(topology_path, fixture_path, public_path, mounts_path,
        topology_sha256, fixture_sha256, public_sha256, mounts_sha256):
    """Read all independently pinned files through no-follow private-file checks."""
    for supplied, trusted in ((topology_sha256, TRUSTED_TOPOLOGY_SHA256),
            (mounts_sha256, TRUSTED_MOUNTS_SHA256)):
        if not _full_sha(supplied) or trusted is None or supplied != trusted:
            _fail('native fixture trust pin is missing or does not match the frozen public pin')
    if not _full_sha(fixture_sha256) or not _full_sha(public_sha256):
        _fail('full lowercase fixture metadata hashes are required')
    topology_raw = _secure_read(topology_path, mode=0o600)
    fixture_raw = _secure_read(fixture_path, mode=0o600)
    public_raw = _secure_read(public_path, mode=0o600)
    mounts_raw = _secure_read(mounts_path, mode=0o600)
    if _sha256(topology_raw) != topology_sha256 or \
            _sha256(fixture_raw) != fixture_sha256 or \
            _sha256(public_raw) != public_sha256 or \
            _sha256(mounts_raw) != mounts_sha256:
        _fail('native fixture input bytes differ from their independently supplied hashes')
    return topology_raw, fixture_raw, public_raw, mounts_raw


def _exact_keys(value, expected, message):
    if not isinstance(value, dict) or set(value) != set(expected):
        _fail(message)


_TOPOLOGY_KEYS = {
    'schema', 'synthetic_fixture', 'not_real_user_approval', 'generated_utc', 'fixture_root',
    'fixture_run_id', 'compatible_marker_path', 'compatible_marker_sha256', 'client_public_path',
    'client_public_sha256', 'base_url', 'hub_service_port', 'producer_metadata_sha256',
    'product_revision', 'producer_source_fingerprint', 'actual_helper_overlay_source_fingerprint',
    'contract_revision', 'catalog_sha256', 'hub_image_id', 'node_runtime_image_id',
    'node_binary_sha256', 'frozen_owned_manifest_sha256', 'post_ready_receipt_sha256',
    'containers', 'networks', 'exact_label_owned_container_ids', 'exact_label_owned_network_ids',
    'verified_against_original_resources_and_marker', 'no_extra_members',
    'no_node_cross_bridge_attachment', 'host_client_publish_localhost_only',
    'hub_ipv4_forwarding_disabled', 'owner_private_mounts_absent',
}
_CONTAINER_KEYS = {
    'id', 'name', 'role', 'immutable_image_id', 'configured_image_id', 'running', 'user',
    'fixture_labels', 'cap_drop', 'privileged', 'security_options', 'sysctls',
    'primary_network_name', 'networks', 'published_ports', 'owner_private_mounts_absent',
}
_CONTAINER_NETWORK_KEYS = {'name', 'id', 'ip'}
_NETWORK_KEYS = {
    'id', 'name', 'role', 'driver', 'internal', 'ipv6_enabled', 'subnet', 'gateway',
    'fixture_labels', 'members',
}
_NETWORK_MEMBER_KEYS = {'container_id', 'name', 'role', 'ipv4_cidr'}
_TOPOLOGY_CONTAINER_ORDER = ('hub', 'node_a', 'node_b')
_TOPOLOGY_NETWORK_ORDER = ('hub_client_regular', 'node_b_internal', 'node_a_internal')


def _validate_topology(topology, topology_path, fixture_path, public_path, mounts_path):
    _exact_keys(topology, _TOPOLOGY_KEYS, 'public topology fields do not match v1')
    if topology.get('schema') != TOPOLOGY_SCHEMA or topology.get('synthetic_fixture') is not True or \
            topology.get('not_real_user_approval') is not True or \
            topology.get('contract_revision') != CONTRACT_REVISION or \
            topology.get('product_revision') != CORE_REVISION or \
            topology.get('producer_source_fingerprint') != SOURCE_FINGERPRINT or \
            topology.get('catalog_sha256') != CATALOG_SHA256 or \
            topology.get('hub_image_id') != HUB_IMAGE or topology.get('node_runtime_image_id') != NODE_IMAGE:
        _fail('public topology does not match the frozen v1.6.1 fixture pins')
    if topology.get('verified_against_original_resources_and_marker') is not True or \
            topology.get('no_extra_members') is not True or \
            topology.get('no_node_cross_bridge_attachment') is not True or \
            topology.get('host_client_publish_localhost_only') is not True or \
            topology.get('hub_ipv4_forwarding_disabled') is not True or \
            topology.get('owner_private_mounts_absent') is not True:
        _fail('public topology lacks the complete original-resource security attestation')
    for key in ('producer_metadata_sha256', 'producer_source_fingerprint',
            'actual_helper_overlay_source_fingerprint', 'catalog_sha256', 'node_binary_sha256',
            'frozen_owned_manifest_sha256', 'post_ready_receipt_sha256', 'compatible_marker_sha256',
            'client_public_sha256'):
        if not _full_sha(topology.get(key)):
            _fail('public topology contains an invalid SHA-256 field')
    root = topology.get('fixture_root')
    run_id = topology.get('fixture_run_id')
    if not isinstance(root, str) or not re.fullmatch(r'/tmp/cn.[A-Za-z0-9]{8}', root) or \
            not isinstance(run_id, str) or not re.fullmatch(r'clnf-[0-9a-f]{16}', run_id):
        _fail('public topology fixture ownership values are malformed')
    try:
        fixture_root = Path(root)
        root_info = fixture_root.lstat()
        if fixture_root.resolve(strict=True) != fixture_root or stat.S_ISLNK(root_info.st_mode) or \
                not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o700 or \
                root_info.st_uid != os.getuid():
            _fail('native fixture root must be an owned private canonical directory')
    except OSError:
        _fail('native fixture root is unavailable')
    expected_marker = root + '/.cicada-client-network-fixture.json'
    expected_public = root + '/client-public.json'
    if topology.get('compatible_marker_path') != expected_marker or \
            topology.get('client_public_path') != expected_public or \
            str(Path(fixture_path)) != expected_marker or str(Path(public_path)) != expected_public:
        _fail('CLI fixture metadata paths do not match the pinned owned fixture root')
    topology_file = Path(topology_path)
    if not topology_file.is_absolute() or topology_file.is_symlink() or \
            topology_file.resolve(strict=True) != topology_file:
        _fail('native topology file path must be canonical and nonsymlinked')
    mounts_file = Path(mounts_path)
    if not mounts_file.is_absolute() or mounts_file.is_symlink() or \
            mounts_file.resolve(strict=True) != mounts_file:
        _fail('native mount allowlist path must be canonical and nonsymlinked')
    if type(topology.get('hub_service_port')) is not int or topology['hub_service_port'] != 8787:
        _fail('native topology Hub service port is invalid')
    origin = urlsplit(topology.get('base_url', ''))
    if origin.scheme != 'http' or origin.hostname != '127.0.0.1' or origin.username or \
            origin.password or origin.path or origin.query or origin.fragment or \
            origin.port is None or not 1024 <= origin.port <= 65535:
        _fail('native topology must use the exact dynamic loopback Hub origin')
    containers = topology.get('containers')
    networks = topology.get('networks')
    if not isinstance(containers, list) or len(containers) != 3 or \
            not isinstance(networks, list) or len(networks) != 3:
        _fail('native topology must enumerate exactly three containers and three networks')
    by_role = {}
    for item in containers:
        _exact_keys(item, _CONTAINER_KEYS, 'container inventory fields do not match v1')
        role = item.get('role')
        if role not in _TOPOLOGY_CONTAINER_ORDER or role in by_role:
            _fail('native topology has duplicate or unknown container roles')
        by_role[role] = item
        if not _full_sha(item.get('id')) or item.get('running') is not True or \
                item.get('user') != '1000:1000' or item.get('privileged') is not False or \
                item.get('cap_drop') != ['ALL'] or item.get('security_options') != ['no-new-privileges'] or \
                item.get('owner_private_mounts_absent') is not True:
            _fail('native topology container security properties are not exact')
        expected_image = HUB_IMAGE if role == 'hub' else NODE_IMAGE
        if item.get('immutable_image_id') != expected_image or item.get('configured_image_id') != expected_image:
            _fail('native topology container image is not the exact immutable pinned image')
        if not isinstance(item.get('fixture_labels'), dict) or not item['fixture_labels'] or \
                item['fixture_labels'].get(FIXTURE_DIR_LABEL) != root or \
                item['fixture_labels'].get(FIXTURE_RUN_LABEL) != run_id:
            _fail('native topology container ownership labels are incomplete')
        if not isinstance(item.get('networks'), list) or not item['networks']:
            _fail('native topology container network attachments are absent')
        for attachment in item['networks']:
            _exact_keys(attachment, _CONTAINER_NETWORK_KEYS, 'container network fields do not match v1')
            if not _full_sha(attachment.get('id')) or not isinstance(attachment.get('name'), str):
                _fail('native topology container network identity is malformed')
            try:
                ipaddress.IPv4Address(attachment.get('ip', ''))
            except ipaddress.AddressValueError:
                _fail('native topology container network address is malformed')
    if set(by_role) != set(_TOPOLOGY_CONTAINER_ORDER):
        _fail('native topology must define Hub, Node A, and Node B exactly once')
    by_network_role = {}
    for item in networks:
        _exact_keys(item, _NETWORK_KEYS, 'network inventory fields do not match v1')
        role = item.get('role')
        if role not in _TOPOLOGY_NETWORK_ORDER or role in by_network_role:
            _fail('native topology has duplicate or unknown network roles')
        by_network_role[role] = item
        if not _full_sha(item.get('id')) or item.get('driver') != 'bridge' or \
                item.get('ipv6_enabled') is not False or \
                item.get('internal') is not (role != 'hub_client_regular'):
            _fail('native topology network isolation settings are invalid')
        if not isinstance(item.get('fixture_labels'), dict) or \
                item['fixture_labels'].get(FIXTURE_DIR_LABEL) != root or \
                item['fixture_labels'].get(FIXTURE_RUN_LABEL) != run_id:
            _fail('native topology network ownership labels are incomplete')
        try:
            subnet = ipaddress.IPv4Network(item.get('subnet', ''), strict=True)
            gateway = ipaddress.IPv4Address(item.get('gateway', ''))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            _fail('native topology network subnet or gateway is malformed')
        if gateway not in subnet or not isinstance(item.get('members'), list) or not item['members']:
            _fail('native topology network membership is malformed')
        seen_members = set()
        for member in item['members']:
            _exact_keys(member, _NETWORK_MEMBER_KEYS, 'network member fields do not match v1')
            if not _full_sha(member.get('container_id')) or member['container_id'] in seen_members:
                _fail('native topology contains duplicate or malformed network members')
            seen_members.add(member['container_id'])
            try:
                interface = ipaddress.IPv4Interface(member.get('ipv4_cidr', ''))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                _fail('native topology network member CIDR is malformed')
            if interface.network != subnet or interface.ip == gateway:
                _fail('native topology member address is outside its pinned subnet')
    if set(by_network_role) != set(_TOPOLOGY_NETWORK_ORDER):
        _fail('native topology must define exactly the Hub and two internal bridges')
    hub = by_role['hub']
    node_a = by_role['node_a']
    node_b = by_role['node_b']
    regular = by_network_role['hub_client_regular']
    bridge_a = by_network_role['node_a_internal']
    bridge_b = by_network_role['node_b_internal']
    expected_container_edges = {
        'hub': {regular['name'], bridge_a['name'], bridge_b['name']},
        'node_a': {bridge_a['name']},
        'node_b': {bridge_b['name']},
    }
    expected_network_edges = {
        'hub_client_regular': {hub['id']},
        'node_a_internal': {hub['id'], node_a['id']},
        'node_b_internal': {hub['id'], node_b['id']},
    }
    expected_primary = {
        'hub': regular['name'], 'node_a': bridge_a['name'], 'node_b': bridge_b['name'],
    }
    expected_names = {
        'hub': 'cicada-cn-' + re.sub(r'[^a-z0-9]', '', Path(root).name.lower()) + '-hub',
        'node_a': run_id + '-a', 'node_b': run_id + '-b',
        'hub_client_regular': 'cicada-cn-' + re.sub(r'[^a-z0-9]', '', Path(root).name.lower()) + '-net',
        'node_a_internal': run_id + '-a-net', 'node_b_internal': run_id + '-b-net',
    }
    for role, row in by_role.items():
        if row['name'] != expected_names[role] or row['primary_network_name'] != expected_primary[role] or \
                {attachment['name'] for attachment in row['networks']} != expected_container_edges[role]:
            _fail('native topology container names or bridge attachment edges are not exact')
    for role, row in by_network_role.items():
        if row['name'] != expected_names[role] or \
                {member['container_id'] for member in row['members']} != expected_network_edges[role]:
            _fail('native topology bridge names or endpoint member edges are not exact')
    if regular['internal'] is not False or bridge_a['internal'] is not True or bridge_b['internal'] is not True or \
            hub.get('sysctls') != {'net.ipv4.ip_forward': '0'} or \
            node_a.get('sysctls') != {} or node_b.get('sysctls') != {} or \
            hub.get('published_ports') != {'8787/tcp': [{'HostIp': '127.0.0.1',
                'HostPort': str(origin.port)}]} or node_a.get('published_ports') != {} or \
            node_b.get('published_ports') != {}:
        _fail('native topology forwarding or published ports are not exactly restricted')
    if topology['exact_label_owned_container_ids'] != [
            by_role[role]['id'] for role in _TOPOLOGY_CONTAINER_ORDER] or \
            topology['exact_label_owned_network_ids'] != [
                by_network_role[role]['id'] for role in _TOPOLOGY_NETWORK_ORDER]:
        _fail('native topology exact ownership lists do not match their ordered inventories')
    return by_role, by_network_role, root, run_id, origin.port


def _mounts_allowlist(mounts_document, topology, topology_path):
    expected_document_keys = {
        'artifact_owner', 'comparison_contract', 'containers', 'exact_container_ids',
        'fixture_root', 'fixture_run_id', 'inspected_utc', 'inspection', 'not_real_user_approval',
        'original_result_path', 'original_result_sha256', 'public_topology_path',
        'public_topology_sha256', 'schema', 'synthetic_fixture',
    }
    _exact_keys(mounts_document, expected_document_keys,
        'mount allowlist fields do not match its public schema')
    if mounts_document.get('schema') != 'cicada.client-link-native.mount-allowlist.v1' or \
            mounts_document.get('synthetic_fixture') is not True or \
            mounts_document.get('not_real_user_approval') is not True or \
            mounts_document.get('fixture_root') != topology.get('fixture_root') or \
            mounts_document.get('fixture_run_id') != topology.get('fixture_run_id') or \
            mounts_document.get('public_topology_path') != str(Path(topology_path)) or \
            mounts_document.get('public_topology_sha256') != TRUSTED_TOPOLOGY_SHA256 or \
            mounts_document.get('original_result_sha256') != topology.get('post_ready_receipt_sha256'):
        _fail('mount allowlist belongs to another fixture root or run')
    artifact_owner = mounts_document.get('artifact_owner')
    _exact_keys(artifact_owner, {'agent', 'gid', 'raw_mode', 'scope', 'uid'},
        'mount allowlist artifact ownership fields are invalid')
    if artifact_owner.get('uid') != os.getuid() or artifact_owner.get('gid') != os.getgid() or \
            artifact_owner.get('raw_mode') != '0o100600' or \
            artifact_owner.get('scope') != 'New supplementary public allowlist only; original topology and receipts unchanged.':
        _fail('mount allowlist artifact ownership or declared scope is unexpected')
    contract = mounts_document.get('comparison_contract')
    _exact_keys(contract, {'deny', 'fields', 'preserve_count_and_duplicates',
        'require_exact_static_arrays', 'rule', 'runtime_home_rule', 'sort_fields'},
        'mount comparison contract fields are invalid')
    mount_keys_order = ['Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation']
    if contract.get('fields') != mount_keys_order or contract.get('sort_fields') != mount_keys_order or \
            contract.get('preserve_count_and_duplicates') is not True or \
            contract.get('require_exact_static_arrays') is not True or \
            not isinstance(contract.get('deny'), str) or 'Docker socket' not in contract['deny'] or \
            '/root' not in contract['deny'] or '/run/user' not in contract['deny']:
        _fail('mount comparison contract does not require the exact safe six-field arrays')
    inspection = mounts_document.get('inspection')
    _exact_keys(inspection, {'argv', 'exit', 'mismatches', 'no_env_or_content_reads',
        'original_sources_sorted_count_and_exact_list_match', 'resource_mutations',
        'selected_field_only'}, 'mount inspection receipt fields are invalid')
    expected_ids_ordered = [row['id'] for row in topology['containers']]
    if inspection.get('argv') != ['docker', 'inspect', '--format', '{{json .Mounts}}', *expected_ids_ordered] or \
            inspection.get('exit') != 0 or inspection.get('mismatches') != [] or \
            inspection.get('no_env_or_content_reads') is not True or \
            inspection.get('original_sources_sorted_count_and_exact_list_match') is not True or \
            inspection.get('resource_mutations') is not False or \
            inspection.get('selected_field_only') != 'Mounts':
        _fail('mount allowlist inspection receipt is not a read-only, Mounts-only inspection')
    if mounts_document.get('exact_container_ids') != expected_ids_ordered or \
            mounts_document.get('original_result_path') != str(Path(topology_path).parents[1] / 'result.json'):
        _fail('mount allowlist resource IDs or original receipt binding is invalid')
    records = mounts_document.get('containers')
    if not isinstance(records, list) or len(records) != 3:
        _fail('mount allowlist must enumerate all three fixture containers')
    expected_ids = {item['id'] for item in topology['containers']}
    by_id = {}
    mount_keys = {'Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation'}
    for index, row in enumerate(records):
        _exact_keys(row, {'id', 'mount_count', 'mounts', 'name', 'original_mount_sources_count',
            'original_recorded_mount_sources', 'original_source_list_exact_match', 'role'},
            'mount allowlist row fields are invalid')
        container_id = row.get('id')
        if container_id not in expected_ids or container_id in by_id or not isinstance(row.get('mounts'), list):
            _fail('mount allowlist has an unknown, repeated, or malformed container row')
        topology_row = topology['containers'][index]
        if container_id != topology_row['id'] or row.get('name') != topology_row['name'] or \
                row.get('role') != topology_row['role'] or \
                type(row.get('mount_count')) is not int or row['mount_count'] != len(row['mounts']) or \
                type(row.get('original_mount_sources_count')) is not int or \
                row['original_mount_sources_count'] != row['mount_count'] or \
                row.get('original_source_list_exact_match') is not True or \
                not isinstance(row.get('original_recorded_mount_sources'), list) or \
                len(row['original_recorded_mount_sources']) != row['mount_count']:
            _fail('mount allowlist row does not match its exact original resource receipt')
        mounts = []
        for mount in row['mounts']:
            _exact_keys(mount, mount_keys, 'mount allowlist fields do not match the frozen inspection')
            if mount.get('Type') != 'bind' or not isinstance(mount.get('Source'), str) or \
                    not mount['Source'].startswith('/') or not isinstance(mount.get('Destination'), str) or \
                    not mount['Destination'].startswith('/') or type(mount.get('RW')) is not bool or \
                    not isinstance(mount.get('Mode'), str) or not isinstance(mount.get('Propagation'), str):
                _fail('mount allowlist contains an unsupported or malformed mount')
            mounts.append(tuple(mount[key] for key in
                ('Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation')))
        recorded_sources = row['original_recorded_mount_sources']
        if not all(isinstance(source, str) and source.startswith('/') for source in recorded_sources) or \
                sorted(recorded_sources) != sorted(mount[1] for mount in mounts):
            _fail('mount allowlist source list differs from the exact original inspection')
        by_id[container_id] = tuple(sorted(mounts))
    if set(by_id) != expected_ids:
        _fail('mount allowlist does not cover the exact three fixture containers')
    return by_id


def _labels_for_hub(topology_labels):
    labels = dict(topology_labels)
    labels.update({
        'org.opencontainers.image.revision': CORE_REVISION,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': CATALOG_SHA256,
        'org.cicada.role': 'hub',
    })
    return labels


def validate_inventory(topology, inventory, mounts_document, *, role_rows, network_rows, root, host_port,
        topology_path):
    """Compare the current read-only Docker inventory to the complete frozen allowlists."""
    if not isinstance(inventory, dict) or set(inventory) != {
            'container_ids', 'network_ids', 'containers', 'networks', 'images'}:
        _fail('current Docker inventory fields are incomplete')
    expected_container_ids = {row['id'] for row in role_rows.values()}
    expected_network_ids = {row['id'] for row in network_rows.values()}
    if not isinstance(inventory['container_ids'], list) or \
            len(inventory['container_ids']) != len(set(inventory['container_ids'])) or \
            set(inventory['container_ids']) != expected_container_ids or \
            not isinstance(inventory['network_ids'], list) or \
            len(inventory['network_ids']) != len(set(inventory['network_ids'])) or \
            set(inventory['network_ids']) != expected_network_ids:
        _fail('current Docker discovery includes missing or extra fixture-owned resources')
    if not isinstance(inventory['containers'], dict) or set(inventory['containers']) != expected_container_ids or \
            not isinstance(inventory['networks'], dict) or set(inventory['networks']) != expected_network_ids:
        _fail('current Docker inspect set differs from the exact full-ID allowlist')
    mount_rows = _mounts_allowlist(mounts_document, topology, topology_path)
    normalized_containers = {}
    container_role_by_id = {}
    for role in _TOPOLOGY_CONTAINER_ORDER:
        expected = role_rows[role]
        current = inventory['containers'].get(expected['id'])
        if not isinstance(current, dict) or set(current) != {
                'id', 'name', 'image', 'configured_image', 'running', 'user', 'labels', 'cap_drop',
                'privileged', 'security_options', 'sysctls', 'network_mode', 'primary_network_name',
                'networks', 'published_ports', 'port_bindings', 'mounts'}:
            _fail('current container inspection is incomplete')
        container_role_by_id[expected['id']] = role
        if current.get('id') != expected['id'] or current.get('name') != expected['name'] or \
                current.get('image') != expected['immutable_image_id'] or \
                current.get('configured_image') != expected['configured_image_id'] or \
                current.get('running') is not True or current.get('user') != expected['user'] or \
                current.get('cap_drop') != expected['cap_drop'] or \
                current.get('privileged') is not False or \
                current.get('security_options') != expected['security_options'] or \
                current.get('sysctls') != expected['sysctls']:
            _fail('current container image, execution, or security settings differ from the allowlist')
        image = inventory['images'].get(expected['immutable_image_id'])
        if not isinstance(image, dict) or image.get('id') != expected['immutable_image_id'] or \
                not isinstance(image.get('labels'), dict):
            _fail('current container immutable image label provenance is incomplete')
        exact_labels = dict(image['labels'])
        exact_labels.update(expected['fixture_labels'])
        if current.get('labels') != exact_labels:
            _fail('current container fixture labels are not an exact match')
        if current.get('primary_network_name') != expected['primary_network_name'] or \
                current.get('network_mode') != expected['primary_network_name']:
            _fail('current container primary bridge or network mode differs from the allowlist')
        expected_attachments = {row['name']: row for row in expected['networks']}
        attachments = current.get('networks')
        if not isinstance(attachments, dict) or set(attachments) != set(expected_attachments):
            _fail('current container has a missing, extra, or cross-bridge network attachment')
        for name, expected_attachment in expected_attachments.items():
            actual = attachments[name]
            if not isinstance(actual, dict) or set(actual) != {'id', 'ip', 'aliases'} or \
                    actual.get('id') != expected_attachment['id'] or \
                    actual.get('ip') != expected_attachment['ip'] or \
                    not isinstance(actual.get('aliases'), list) or \
                    not all(isinstance(alias, str) for alias in actual['aliases']) or \
                    len(actual['aliases']) != len(set(actual['aliases'])):
                _fail('current container attachment ID or IPv4 address differs from the allowlist')
        configured_ports = {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': ''}]} \
            if role == 'hub' else {}
        if current.get('published_ports') != expected['published_ports'] or \
                current.get('port_bindings') != configured_ports:
            _fail('current container published port bindings differ from the exact loopback allowlist')
        observed_mounts = current.get('mounts')
        if not isinstance(observed_mounts, list):
            _fail('current mount inspection is incomplete')
        normalized_mounts = []
        for mount in observed_mounts:
            if not isinstance(mount, dict) or set(mount) != {
                    'Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation'}:
                _fail('current mount inspection did not use the bounded public fields')
            normalized_mounts.append(tuple(mount[key] for key in
                ('Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation')))
        if len(normalized_mounts) != len(set(normalized_mounts)) or \
                tuple(sorted(normalized_mounts)) != mount_rows[expected['id']]:
            _fail('current mount sources or destinations differ from the exact pinned allowlist')
        normalized_containers[role] = current

    network_role_by_id = {}
    for role in _TOPOLOGY_NETWORK_ORDER:
        expected = network_rows[role]
        current = inventory['networks'].get(expected['id'])
        if not isinstance(current, dict) or set(current) != {
                'id', 'name', 'driver', 'internal', 'ipv6_enabled', 'subnet', 'gateway',
                'labels', 'members'}:
            _fail('current network inspection is incomplete')
        network_role_by_id[expected['id']] = role
        if current.get('id') != expected['id'] or current.get('name') != expected['name'] or \
                current.get('driver') != expected['driver'] or current.get('internal') is not expected['internal'] or \
                current.get('ipv6_enabled') is not False or current.get('subnet') != expected['subnet'] or \
                current.get('gateway') != expected['gateway'] or current.get('labels') != expected['fixture_labels']:
            _fail('current network identity, scope, IPAM, or ownership labels differ from the allowlist')
        expected_members = {
            member['container_id']: (member['name'], member['ipv4_cidr']) for member in expected['members']
        }
        actual_members = current.get('members')
        if not isinstance(actual_members, dict) or set(actual_members) != set(expected_members):
            _fail('current bridge has missing or foreign endpoint members')
        subnet = ipaddress.IPv4Network(expected['subnet'], strict=True)
        gateway = ipaddress.IPv4Address(expected['gateway'])
        for container_id, expected_member in expected_members.items():
            member = actual_members[container_id]
            if not isinstance(member, dict) or set(member) != {'name', 'ipv4_cidr'} or \
                    (member.get('name'), member.get('ipv4_cidr')) != expected_member:
                _fail('current network endpoint identity or CIDR differs from the allowlist')
            try:
                interface = ipaddress.IPv4Interface(member['ipv4_cidr'])
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                _fail('current network endpoint has an invalid IPv4 CIDR')
            if interface.network != subnet or interface.ip == gateway:
                _fail('current network endpoint is outside its exact subnet')
            attached = inventory['containers'][container_id]['networks'].get(expected['name'])
            if not isinstance(attached, dict) or attached.get('ip') != str(interface.ip) or \
                    attached.get('id') != expected['id']:
                _fail('current container and network endpoint inspections disagree')

    images = inventory['images']
    if not isinstance(images, dict) or set(images) != {HUB_IMAGE, NODE_IMAGE}:
        _fail('current immutable image inspection set is incomplete or contains an extra image')
    for image_id in (HUB_IMAGE, NODE_IMAGE):
        image = images[image_id]
        if not isinstance(image, dict) or set(image) != {'id', 'labels'} or image.get('id') != image_id or \
                not isinstance(image.get('labels'), dict):
            _fail('current immutable image inspection differs from the exact expected IDs')
    hub_labels = images[HUB_IMAGE]['labels']
    expected_hub_image_labels = {
        'org.opencontainers.image.revision': CORE_REVISION,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': CATALOG_SHA256,
        'org.cicada.role': 'hub',
    }
    if any(hub_labels.get(key) != value for key, value in expected_hub_image_labels.items()):
        _fail('pinned Hub image provenance labels differ from the expected Core revision')

    # Preserve the tuple expected by the existing opaque carrier. The Hub's
    # non-primary bridges remain validated above; only the primary bridge is
    # passed to the v1.5 carrier code that opens a numeric TCP connection.
    hub = normalized_containers['hub']
    hub_expected = role_rows['hub']
    primary = hub_expected['primary_network_name']
    # This branch routes directly to the verified numeric bridge address.
    # Docker DNS aliases are not a routing or ownership input for that path.
    hub_ip = hub['networks'][primary]['ip']
    network_expected = next(row for row in network_rows.values() if row['name'] == primary)
    hub_ports = hub['published_ports']
    published = hub_ports.get('8787/tcp')
    if not isinstance(published, list) or len(published) != 1 or \
            published[0] != {'HostIp': '127.0.0.1', 'HostPort': str(host_port)}:
        _fail('Hub dynamic host publish must bind only to loopback at the pinned port')
    pseudo_hub = {
        'Id': hub['id'], 'Image': hub['image'],
        'State': {'Running': hub['running']},
        'Config': {'Image': hub['configured_image'], 'Labels': hub['labels']},
        'NetworkSettings': {'Networks': {primary: {'IPAddress': hub_ip,
            'Aliases': hub['networks'][primary]['aliases']}}},
    }
    pseudo_network = {
        'Id': network_expected['id'], 'Driver': network_expected['driver'],
        'Internal': network_expected['internal'],
        'Containers': {member['container_id']: {'Name': member['name']}
            for member in network_rows['hub_client_regular']['members']},
    }
    fixture = {
        'container': hub_expected['name'], 'network': primary, 'image': HUB_IMAGE,
        'source_revision': CORE_REVISION, 'client_public': topology['client_public_path'],
        'base_url': topology['base_url'], 'fixture_dir': root,
    }
    public = None
    return fixture, public, pseudo_hub, pseudo_network, hub_ip, topology_service_port(topology)


def topology_service_port(topology):
    port = topology.get('hub_service_port')
    if type(port) is not int or port != 8787:
        _fail('Hub service port is invalid')
    return port


def validate_files_and_inventory(topology_raw, fixture_raw, public_raw, mounts_raw, *,
        topology_sha256, fixture_sha256, public_sha256, mounts_sha256, topology_path,
        fixture_path, public_path, mounts_path, inventory):
    if topology_sha256 != TRUSTED_TOPOLOGY_SHA256 or not _full_sha(topology_sha256):
        _fail('public native topology SHA-256 does not match the independently frozen pin')
    if not _full_sha(fixture_sha256) or not _full_sha(public_sha256) or not _full_sha(mounts_sha256):
        _fail('full lowercase metadata SHA-256 pins are required')
    if _sha256(topology_raw) != topology_sha256 or _sha256(fixture_raw) != fixture_sha256 or \
            _sha256(public_raw) != public_sha256 or _sha256(mounts_raw) != mounts_sha256:
        _fail('native fixture metadata bytes do not match all supplied SHA-256 pins')
    if TRUSTED_MOUNTS_SHA256 is None or mounts_sha256 != TRUSTED_MOUNTS_SHA256:
        _fail('mount allowlist SHA-256 does not match Root’s independently frozen pin')
    topology = strict_json(topology_raw)
    marker = strict_json(fixture_raw)
    public = strict_json(public_raw)
    mounts_document = strict_json(mounts_raw)
    # Keep path binding explicit rather than allowing callers to validate a
    # topology document while pointing the carrier at another fixture.
    role_rows, _network_rows, root, run_id, host_port = _validate_topology(
        topology, topology_path, fixture_path, public_path, mounts_path)
    if topology['compatible_marker_sha256'] != fixture_sha256 or \
            topology['client_public_sha256'] != public_sha256:
        _fail('CLI metadata hashes do not equal the topology’s pinned marker/public hashes')
    expected_hub = role_rows['hub']
    suffix = re.sub(r'[^a-z0-9]', '', Path(root).name.lower())
    expected_container = 'cicada-cn-' + suffix + '-hub'
    expected_network = expected_hub['primary_network_name']
    if marker.get('schema') != 'cicada.client-network-fixture.v2' or \
            marker.get('fixture_dir') != root or marker.get('source_dirty') is not False or \
            marker.get('source_revision') != CORE_REVISION or \
            marker.get('source_fingerprint') != SOURCE_FINGERPRINT or \
            marker.get('catalog_sha256') != CATALOG_SHA256 or \
            marker.get('contract_revision') != CONTRACT_REVISION or marker.get('image_id') != HUB_IMAGE or \
            marker.get('container') != expected_container or marker.get('network') != expected_network or \
            marker.get('host_port') != host_port:
        _fail('Core marker does not match the original v1.6.1 fixture pins')
    origin = urlsplit(public.get('base_url', ''))
    if origin.scheme != 'http' or origin.hostname != '127.0.0.1' or origin.username or origin.password or \
            origin.path or origin.query or origin.fragment or origin.port != host_port:
        _fail('Core public metadata does not carry the pinned dynamic loopback origin')
    if public.get('schema') != 'cicada.client-network-fixture-result.v2' or \
            public.get('base_url') != topology['base_url'] or public.get('host_port') != host_port or \
            public.get('docker_network') != expected_network or public.get('image_id') != HUB_IMAGE or \
            public.get('source_revision') != CORE_REVISION or \
            public.get('source_fingerprint') != SOURCE_FINGERPRINT or \
            public.get('catalog_sha256') != CATALOG_SHA256 or \
            public.get('contract_revision') != CONTRACT_REVISION:
        _fail('Core public metadata does not match the original v1.6.1 fixture pins')
    fixture, _unused, hub, network, target_ip, target_port = validate_inventory(
        topology, inventory, mounts_document, role_rows=role_rows,
        network_rows=_network_rows, root=root, host_port=host_port, topology_path=topology_path)
    return fixture, public, hub, network, target_ip, target_port
