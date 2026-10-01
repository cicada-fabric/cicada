#!/usr/bin/env python3
"""Relay the five Client-Control v2 routes to one pinned v1.6 Core fixture.

The Android emulator stays in Docker network-none mode. An ADB reverse mapping
connects its dynamic loopback origin to the in-emulator listener; that listener
uses bounded STDIO frames to this host process. Request and response bodies are
never decrypted, printed, or persisted.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
V15_HOST_PATH = ROOT / 'scripts/interop/v15-host-stdio-carrier.py'
V16_DRIVER_PATH = ROOT / 'scripts/interop/v16-android-deterministic.py'
CORE_REVISION = 'f4e4725c5d81c54b166f4291b9d450c70954e6df'
SOURCE_FINGERPRINT = 'c3d22f3d69ee668bb29215100ba78a33acf107fd1e03443a48e4651c70e44c4b'
CATALOG_SHA256 = '1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c'
HUB_IMAGE = 'sha256:6a7e0af78d3d14369f451760541b54d49a6e9505a1c813aa1124186176d4f5c9'
SCHEMA = 'cicada.client-v16-host-stdio-carrier.v1'
ALLOWED = {
    ('GET', '/v2/client/identity'),
    ('GET', '/v2/client/capabilities'),
    ('POST', '/v2/client/devices/enroll'),
    ('POST', '/v2/client/rpc'),
    ('POST', '/v2/client/rpc/recover'),
}
_EXPECTED_APP_SHA256 = None
_EXPECTED_TEST_SHA256 = None


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v15_host = _load(V15_HOST_PATH, 'v15_host_for_v16')
v15_host.SCHEMA = SCHEMA
v15_host.HUB_IMAGE = HUB_IMAGE
v15_host.CORE_REVISION = CORE_REVISION
v15_host.SOURCE_FINGERPRINT = SOURCE_FINGERPRINT
v15_host.CATALOG_SHA256 = CATALOG_SHA256
v15_host.ALLOWED = ALLOWED


def _private_json(path_value):
    path = Path(path_value)
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError('required Core metadata file is unavailable') from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('Core metadata must be a mode-0600 regular file without symlinks')
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Core metadata is not valid JSON') from error


def _fixture_root(marker_path):
    path = Path(marker_path)
    if path.is_symlink() or path.name != '.cicada-client-network-fixture.json':
        raise ValueError('expected the Core v2 fixture marker path')
    root = path.parent
    try:
        resolved = root.resolve(strict=True)
        info = root.lstat()
    except OSError as error:
        raise ValueError('Core fixture directory is unavailable') from error
    if resolved != root or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or \
            stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid() or \
            not re.fullmatch(r'/tmp/cn\.[A-Za-z0-9]{8}', str(root)):
        raise ValueError('Core fixture must be an owned private /tmp/cn.XXXXXXXX directory')
    return root


def _expected_docker_labels(root):
    return {
        'org.cicada.fixture': 'client-network',
        'org.cicada.fixture.dir': str(root),
        'org.cicada.fixture.source.revision': CORE_REVISION,
        'org.cicada.fixture.catalog.sha256': CATALOG_SHA256,
        'org.cicada.fixture.source.fingerprint': SOURCE_FINGERPRINT,
        'org.opencontainers.image.revision': CORE_REVISION,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': CATALOG_SHA256,
        'org.cicada.role': 'hub',
    }


def _labels_match(actual, expected):
    return all(actual.get(key) == value for key, value in expected.items())


def verify_hub(fixture_path, public_path, recovery_mode=None):
    if recovery_mode is not None:
        raise ValueError('v1.6 carrier refuses recovery_mode without a matching Core fixture')

    root = _fixture_root(fixture_path)
    marker = _private_json(fixture_path)
    public_file = Path(public_path)
    expected_public_file = root / 'client-public.json'
    public = _private_json(public_file)
    if public_file.resolve(strict=True) != expected_public_file:
        raise ValueError('client-public v2 must be the file owned by this Core fixture')

    suffix = re.sub(r'[^a-z0-9]', '', root.name.lower())
    # Core prefixes the already-sanitized "cn.<random>" basename with "cn-".
    expected_container = 'cicada-cn-' + suffix + '-hub'
    expected_network = 'cicada-cn-' + suffix + '-net'
    if marker.get('schema') != 'cicada.client-network-fixture.v2' or \
            marker.get('fixture_dir') != str(root) or marker.get('source_dirty') is not False or \
            marker.get('source_revision') != CORE_REVISION or \
            marker.get('source_fingerprint') != SOURCE_FINGERPRINT or \
            marker.get('catalog_sha256') != CATALOG_SHA256 or \
            marker.get('contract_revision') != 'client-hub-v1.6' or \
            marker.get('image_id') != HUB_IMAGE or marker.get('container') != expected_container or \
            marker.get('network') != expected_network:
        raise ValueError('Core fixture marker does not match the v1.6 pins')

    host_port = marker.get('host_port')
    if type(host_port) is not int or not 1024 <= host_port <= 65535:
        raise ValueError('Core fixture host port is invalid')
    expected_origin = f'http://127.0.0.1:{host_port}'
    origin = urlsplit(public.get('base_url', ''))
    if origin.scheme != 'http' or origin.hostname != '127.0.0.1' or origin.username or \
            origin.password or origin.path or origin.query or origin.fragment or origin.port != host_port:
        raise ValueError('client-public v2 must carry its dynamic loopback origin')
    if public.get('schema') != 'cicada.client-network-fixture-result.v2' or \
            public.get('base_url') != expected_origin or public.get('host_port') != host_port or \
            public.get('docker_network') != expected_network or public.get('image_id') != HUB_IMAGE or \
            public.get('source_revision') != CORE_REVISION or \
            public.get('source_fingerprint') != SOURCE_FINGERPRINT or \
            public.get('catalog_sha256') != CATALOG_SHA256 or \
            public.get('contract_revision') != 'client-hub-v1.6':
        raise ValueError('client-public v2 does not match the Core v1.6 fixture pins')

    fixture = {
        'container': expected_container,
        'network': expected_network,
        'image': HUB_IMAGE,
        'source_revision': CORE_REVISION,
        'client_public': str(expected_public_file),
        'base_url': expected_origin,
        'fixture_dir': str(root),
    }
    hub = json.loads(subprocess.check_output(['docker', 'inspect', expected_container], text=True))[0]
    network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', expected_network], text=True))[0]
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', HUB_IMAGE], text=True))[0]
    expected_labels = _expected_docker_labels(root)
    hub_labels = hub.get('Config', {}).get('Labels') or {}
    network_labels = network.get('Labels') or {}
    image_labels = image.get('Config', {}).get('Labels') or {}
    if image.get('Id') != HUB_IMAGE or not _labels_match(image_labels, {
            'org.opencontainers.image.revision': CORE_REVISION,
            'org.cicada.build.dirty': 'false',
            'org.cicada.build.source-fingerprint': SOURCE_FINGERPRINT,
            'org.cicada.client-catalog.sha256': CATALOG_SHA256,
            'org.cicada.role': 'hub',
    }):
        raise ValueError('Core Hub image ID or provenance labels do not match the v1.6 pins')
    if not hub.get('State', {}).get('Running') or hub.get('Id', '') == '' or \
            not re.fullmatch(r'[0-9a-f]{64}', hub.get('Id', '')) or \
            hub.get('Image') != HUB_IMAGE or hub.get('Config', {}).get('Image') != HUB_IMAGE or \
            not _labels_match(hub_labels, expected_labels):
        raise ValueError('Core Hub container ID, image, or fixture labels do not match the v1.6 pins')
    if network.get('Id', '') == '' or not re.fullmatch(r'[0-9a-f]{64}', network.get('Id', '')) or \
            network.get('Driver') != 'bridge' or network.get('Internal') is not False or \
            not _labels_match(network_labels, {key: expected_labels[key] for key in (
                'org.cicada.fixture', 'org.cicada.fixture.dir',
                'org.cicada.fixture.source.revision', 'org.cicada.fixture.catalog.sha256',
                'org.cicada.fixture.source.fingerprint')}):
        raise ValueError('Core fixture bridge ID, driver, or ownership labels do not match')

    discovered = subprocess.check_output([
        'docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=org.cicada.fixture.dir=' + str(root),
    ], text=True).split()
    if discovered != [hub['Id']]:
        raise ValueError('Core fixture must own exactly one container')
    if hub.get('HostConfig', {}).get('NetworkMode') != expected_network or \
            set(hub.get('NetworkSettings', {}).get('Networks', {})) != {expected_network} or \
            set(network.get('Containers', {})) != {hub['Id']} or \
            network['Containers'][hub['Id']].get('Name') != expected_container:
        raise ValueError('Core fixture network must contain exactly its one Hub')

    endpoint = hub['NetworkSettings']['Networks'][expected_network]
    try:
        address = ipaddress.IPv4Address(endpoint.get('IPAddress', ''))
    except ipaddress.AddressValueError:
        raise ValueError('Core Hub has no numeric private bridge IPv4 address') from None
    if not address.is_private:
        raise ValueError('Core Hub bridge IPv4 address is not private')
    target_ip = str(address)
    port_bindings = (hub.get('NetworkSettings', {}).get('Ports') or {}).get('8787/tcp') or []
    if len(port_bindings) != 1 or port_bindings[0].get('HostIp') != '127.0.0.1' or \
            port_bindings[0].get('HostPort') != str(host_port):
        raise ValueError('Core dynamic loopback origin is not bound to this Hub container')
    try:
        with socket.create_connection((target_ip, 8787), timeout=3):
            pass
    except OSError:
        raise ValueError('host cannot reach the pinned numeric Core bridge endpoint') from None
    return fixture, public, hub, network, target_ip, 8787


def verify_emulator(module, evidence):
    if not re.fullmatch(r'[0-9a-f]{64}', _EXPECTED_APP_SHA256 or '') or \
            not re.fullmatch(r'[0-9a-f]{64}', _EXPECTED_TEST_SHA256 or ''):
        raise ValueError('full CLI app and test APK SHA-256 values are required')
    state = module.owned_state(evidence)
    if state.get('network') != 'none':
        raise ValueError('the v1.6 Android emulator must stay network-none')
    actual = json.loads(subprocess.check_output(['docker', 'inspect', state['container']], text=True))[0]
    if actual.get('HostConfig', {}).get('NetworkMode') != 'none' or \
            set(actual.get('NetworkSettings', {}).get('Networks', {})) != {'none'}:
        raise ValueError('refusing to route through a networked or foreign emulator')
    artifacts = json.loads((evidence / 'android-artifacts.json').read_text())
    if artifacts.get('contract_revision') != 'client-hub-v1.6' or \
            artifacts.get('app_sha256') != _EXPECTED_APP_SHA256 or \
            artifacts.get('test_sha256') != _EXPECTED_TEST_SHA256:
        raise ValueError('the active emulator APKs do not match the CLI-provided full hashes')
    return state


def load_driver():
    return _load(V16_DRIVER_PATH, 'v16_deterministic_for_carrier')


def run(args):
    if args.recovery_mode is not None:
        raise ValueError('v1.6 carrier refuses recovery_mode without a matching Core fixture')
    if args.app_sha256 is None or args.test_sha256 is None or \
            not re.fullmatch(r'[0-9a-f]{64}', args.app_sha256) or \
            not re.fullmatch(r'[0-9a-f]{64}', args.test_sha256):
        raise ValueError('provide exact lowercase full app and test APK SHA-256 values')
    if args.android_url_port is None:
        public_hint = _private_json(args.public)
        dynamic_port = public_hint.get('host_port')
        if type(dynamic_port) is not int or not 1024 <= dynamic_port <= 65535:
            raise ValueError('client-public v2 has no valid dynamic host port')
        args.android_url_port = dynamic_port

    global _EXPECTED_APP_SHA256, _EXPECTED_TEST_SHA256
    _EXPECTED_APP_SHA256, _EXPECTED_TEST_SHA256 = args.app_sha256, args.test_sha256
    v15_host.load_driver = load_driver
    v15_host.verify_hub = verify_hub
    v15_host.verify_emulator = verify_emulator

    module = load_driver()
    evidence = module.driver.private_evidence(args.evidence)
    state = verify_emulator(module, evidence)
    fixture, public, _hub, _network, _target_ip, _target_port = verify_hub(
        args.fixture, args.public, None
    )
    if public.get('base_url') != f'http://127.0.0.1:{args.android_url_port}':
        raise ValueError('Android URL port differs from the dynamic Core public origin')

    adb = module.driver.adb(state)
    reverse_step = 'carrier-reverse-' + str(args.android_url_port)
    reversed_port = False
    try:
        module.driver.run(evidence, reverse_step, adb + [
            'reverse', f'tcp:{args.android_url_port}', f'tcp:{args.carrier_port}',
        ])
        reversed_port = True
        v15_host.run(args)
    finally:
        if reversed_port:
            module.driver.run(evidence, 'carrier-reverse-remove-' + str(args.android_url_port),
                adb + ['reverse', '--remove', f'tcp:{args.android_url_port}'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--fixture', required=True, help='Core .cicada-client-network-fixture.json marker')
    parser.add_argument('--public', required=True, help='Core client-public.json v2')
    parser.add_argument('--app-sha256', required=True, help='full SHA-256 of the installed Client APK')
    parser.add_argument('--test-sha256', required=True, help='full SHA-256 of the installed test APK')
    parser.add_argument('--fault', choices=('none', 'enrollment', 'rpc'), default='none')
    parser.add_argument('--carrier-port', type=int, default=38097)
    parser.add_argument('--android-url-port', type=int,
        help='expected dynamic client-public port; omitted means read from the pinned public file')
    args = parser.parse_args()
    args.recovery_mode = None
    os.umask(0o077)
    try:
        run(args)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        print(json.dumps({'result': 'FAIL', 'tag': args.tag,
            'reason': 'v1.6 fixture verification or bounded opaque relay failed'}),
            file=sys.stderr, flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
