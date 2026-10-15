#!/usr/bin/env python3
"""Exercise one fresh v1.6.1 Android RPC against a disposable Core Hub ledger.

The request is created while the network-none emulator has no adb reverse.
Only its opaque packet is exported to a mode-0600 /tmp file, passed to the
pinned interop-image Core producer, and removed before the Hub is recreated.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request


HERE = Path(__file__).resolve().parent
PACKAGE = 'ai.cicada.client'
TEST_CLASS = 'ai.cicada.client.hub.ClientHubV16RecoveryFaultTest'
TEST_RUNNER = PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner'
SCHEMA = 'cicada.client-v161-recovery-faults.v1'
EXPECTED = {
    'processing': ('STILL_PROCESSING', 409),
    'uncertain': ('OUTCOME_UNCERTAIN', 200),
    'legacy': ('RECOVERY_UNAVAILABLE', 409),
}
MAX_PACKET_BYTES = 256 * 1024
REMOTE_BASE = 'no_backup/network-v16/'


def load(name, filename):
    path = HERE / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('required pinned v1.6.1 Client tool is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('v16_runner_for_recovery_faults', 'v16-android-deterministic.py')
carrier = load('v16_carrier_for_recovery_faults', 'v16-host-stdio-carrier.py')
driver = runner.driver


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def save(evidence, name, value):
    driver.save(evidence / name, value)


def process(argv, *, input_bytes=None, stdin=None, timeout=60):
    try:
        return subprocess.run(argv, input=input_bytes, stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('bounded recovery command did not complete') from None


def docker_json(*argv):
    result = process(['docker', *argv], timeout=30)
    if result.returncode != 0:
        raise ValueError('Docker ownership inspection failed')
    try:
        return json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('Docker ownership inspection was malformed') from None


def private_file(path, *, exact_mode=0o600, maximum=1024 * 1024):
    path = Path(path)
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or \
                before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != exact_mode:
            raise ValueError('required fixture metadata is not a caller-owned private file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) or \
                    not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or \
                    stat.S_IMODE(current.st_mode) != exact_mode:
                raise ValueError('fixture metadata changed while it was opened')
            with os.fdopen(fd, 'rb') as source:
                fd = -1
                data = source.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError('fixture metadata exceeds its size bound')
            return data
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError:
        raise ValueError('required fixture metadata is unavailable') from None


def private_json(path):
    try:
        return json.loads(private_file(path))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('private fixture metadata is not valid JSON') from None


def require_real_path(path, *, kind, mode, owner=os.getuid()):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise ValueError('required disposable fixture path is unavailable') from None
    is_dir = stat.S_ISDIR(info.st_mode)
    is_file = stat.S_ISREG(info.st_mode)
    if stat.S_ISLNK(info.st_mode) or (kind == 'directory' and not is_dir) or \
            (kind == 'file' and not is_file) or info.st_uid != owner or \
            stat.S_IMODE(info.st_mode) != mode or path.resolve(strict=True) != path:
        raise ValueError('disposable fixture path ownership, type, or mode is unsafe')
    return info


def checked_fixture(fixture_path, public_path):
    marker_path = Path(fixture_path)
    if not marker_path.is_absolute() or marker_path.name != '.cicada-client-network-fixture.json':
        raise ValueError('pass the Core client-network fixture marker path')
    root = marker_path.parent
    require_real_path(Path('/tmp'), kind='directory', mode=0o1777, owner=0)
    root_info = require_real_path(root, kind='directory', mode=0o700)
    if not re.fullmatch(r'/tmp/cn\.[A-Za-z0-9]{8}', str(root)) or root_info.st_uid != os.getuid():
        raise ValueError('Core fixture must be the caller-owned private /tmp/cn.XXXXXXXX directory')
    if Path(public_path) != root / 'client-public.json':
        raise ValueError('client-public metadata must belong to the selected Core fixture')
    meta = private_json(marker_path)
    public = private_json(public_path)
    state_dir = root / 'state'
    workspace_dir = root / 'workspace'
    require_real_path(state_dir, kind='directory', mode=0o700)
    require_real_path(workspace_dir, kind='directory', mode=0o700)
    require_real_path(root / 'hub.env', kind='file', mode=0o600)
    db = state_dir / 'cicada.sqlite3'
    db_info = require_real_path(db, kind='file', mode=stat.S_IMODE(db.lstat().st_mode))
    if db_info.st_uid != os.getuid() or db_info.st_size <= 0 or db_info.st_nlink != 1:
        raise ValueError('disposable Hub database leaf is not a private single-link regular file')
    if meta.get('fixture_dir') != str(root) or meta.get('source_dirty') is not False or \
            meta.get('source_revision') != runner.CORE_REVISION or \
            meta.get('source_fingerprint') != runner.CORE_SOURCE_FINGERPRINT or \
            meta.get('catalog_sha256') != runner.CATALOG_SHA256 or \
            meta.get('contract_revision') != runner.CONTRACT_REVISION or \
            meta.get('image_id') != runner.HUB_IMAGE:
        raise ValueError('Core fixture metadata differs from the current v1.6.1 pins')
    if public.get('schema') != 'cicada.client-network-fixture-result.v2' or \
            public.get('hub_id') is None or public.get('hub_id') != meta.get('hub_id') or \
            public.get('catalog_sha256') != runner.CATALOG_SHA256 or \
            public.get('source_revision') != runner.CORE_REVISION or \
            public.get('source_fingerprint') != runner.CORE_SOURCE_FINGERPRINT or \
            public.get('contract_revision') != runner.CONTRACT_REVISION or \
            public.get('image_id') != runner.HUB_IMAGE:
        raise ValueError('Core public metadata differs from its v1.6.1 fixture marker')
    if (runner.CONTRACT_REVISION, runner.CORE_REVISION, runner.CORE_SOURCE_FINGERPRINT,
            runner.CATALOG_SHA256, runner.HUB_IMAGE) != (
            carrier.CONTRACT_REVISION, carrier.CORE_REVISION, carrier.SOURCE_FINGERPRINT,
            carrier.CATALOG_SHA256, carrier.HUB_IMAGE):
        raise ValueError('v1.6.1 emulator and carrier pins are inconsistent')
    return root, meta, public


def verify_tool_image():
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', runner.INTEROP_IMAGE):
        raise ValueError('pinned Core interop image digest is malformed')
    image = docker_json('image', 'inspect', runner.INTEROP_IMAGE)
    if len(image) != 1 or image[0].get('Id') != runner.INTEROP_IMAGE:
        raise ValueError('Core interop helper image digest mismatch')
    labels = image[0].get('Config', {}).get('Labels') or {}
    expected = {
        'org.opencontainers.image.revision': runner.CORE_REVISION,
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': runner.CORE_SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': runner.CATALOG_SHA256,
    }
    if any(labels.get(key) != value for key, value in expected.items()):
        raise ValueError('Core interop image provenance labels do not match the pinned source')


def docker_root():
    result = process(['docker', 'info', '--format', '{{.DockerRootDir}}'], timeout=30)
    if result.returncode != 0 or result.stdout.decode(errors='replace').strip() != '/gpu1-share/data/docker-root':
        raise ValueError('Docker data root differs from the approved Client test root')


def fixture_container(root, meta):
    found = docker_json('container', 'inspect', meta['container'])
    if len(found) != 1:
        raise ValueError('Core fixture Hub container is not unique')
    item = found[0]
    network = docker_json('network', 'inspect', meta['network'])
    if len(network) != 1:
        raise ValueError('Core fixture bridge is not unique')
    bridge = network[0]
    labels = item.get('Config', {}).get('Labels') or {}
    expected_labels = carrier._expected_docker_labels(root)
    mounts = item.get('Mounts') or []
    expected_mounts = {
        ('/state', str(root / 'state'), True),
        ('/workspace', str(root / 'workspace'), True),
    }
    observed_mounts = {(m.get('Destination'), m.get('Source'), m.get('RW')) for m in mounts}
    port_bindings = item.get('HostConfig', {}).get('PortBindings') or {}
    binding = port_bindings.get('8787/tcp') or []
    networks = item.get('NetworkSettings', {}).get('Networks') or {}
    if item.get('Name') != '/' + meta['container'] or not item.get('State', {}).get('Running') or \
            not re.fullmatch(r'[0-9a-f]{64}', item.get('Id', '')) or \
            item.get('Image') != runner.HUB_IMAGE or item.get('Config', {}).get('Image') != runner.HUB_IMAGE or \
            not all(labels.get(key) == value for key, value in expected_labels.items()) or \
            item.get('HostConfig', {}).get('AutoRemove') is not True or \
            item.get('HostConfig', {}).get('RestartPolicy', {}).get('Name') != 'no' or \
            item.get('HostConfig', {}).get('NetworkMode') != meta['network'] or \
            item.get('Config', {}).get('User') != f'{os.getuid()}:{os.getgid()}' or \
            item.get('Config', {}).get('Entrypoint') != ['/usr/local/bin/cicada'] or \
            item.get('Config', {}).get('Cmd') != ['serve', '--host', '0.0.0.0', '--port', '8787'] or \
            observed_mounts != expected_mounts or set(networks) != {meta['network']} or \
            bridge.get('Driver') != 'bridge' or bridge.get('Internal') is not False or \
            set(bridge.get('Containers', {})) != {item['Id']} or \
            bridge['Containers'][item['Id']].get('Name') != meta['container'] or \
            len(binding) != 1 or binding[0].get('HostIp') != '127.0.0.1' or \
            binding[0].get('HostPort') != str(meta['host_port']):
        raise ValueError('Hub is not the exact --rm Client-owned disposable fixture')
    return item, bridge


def scan_shared_mounts(root, meta, hub_id):
    """Reject any other container that can see the temporary fixture state."""
    listing = process(['docker', 'ps', '-aq', '--no-trunc'], timeout=30)
    if listing.returncode != 0:
        raise ValueError('Docker container ownership scan failed')
    targets = (root, root / 'state', root / 'state/cicada.sqlite3')
    for container_id in listing.stdout.decode(errors='replace').split():
        if container_id == hub_id:
            continue
        inspected = process(['docker', 'inspect', '--format', '{{json .Mounts}}', container_id], timeout=20)
        if inspected.returncode != 0:
            raise ValueError('Docker mount ownership scan changed during inspection')
        try:
            mounts = json.loads(inspected.stdout)
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError('Docker mount ownership scan was malformed') from None
        for mount in mounts if isinstance(mounts, list) else ():
            if mount.get('Type') != 'bind':
                continue
            source = mount.get('Source')
            if not isinstance(source, str) or not source.startswith('/'):
                continue
            lexical = Path(os.path.abspath(source))
            for target in targets:
                try:
                    overlaps = os.path.commonpath((str(lexical), str(target))) in (str(lexical), str(target))
                except ValueError:
                    overlaps = False
                if overlaps:
                    raise ValueError('another container shares or overlaps the disposable Hub state mount')


def verify_identity(public, base_url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(path):
        try:
            with opener.open(base_url + path, timeout=4) as response:
                raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise ValueError('Hub identity response exceeds its bound')
            return json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError('pinned Hub public identity is unavailable') from None

    identity = get('/v2/client/identity')
    capabilities = get('/v2/client/capabilities')
    if identity.get('hub_id') != public.get('hub_id') or \
            identity.get('control_public_identity') != public.get('control_public_identity') or \
            capabilities.get('contract_revision') != runner.CONTRACT_REVISION or \
            capabilities.get('catalog_sha256') != runner.CATALOG_SHA256:
        raise ValueError('Hub identity or encrypted capability catalog changed')
    identity_digest = digest(json.dumps({
        'hub_id': identity['hub_id'],
        'control_public_identity': identity['control_public_identity'],
    }, sort_keys=True, separators=(',', ':')))
    return identity_digest


def verify_android(evidence, app_sha256, test_sha256):
    if not re.fullmatch(r'[0-9a-f]{64}', app_sha256) or not re.fullmatch(r'[0-9a-f]{64}', test_sha256):
        raise ValueError('exact lowercase full app/test APK SHA-256 values are required')
    carrier._EXPECTED_APP_SHA256 = app_sha256
    carrier._EXPECTED_TEST_SHA256 = test_sha256
    state = carrier.verify_emulator(runner, evidence)
    artifacts = private_json(evidence / 'android-artifacts.json')
    if artifacts.get('contract_revision') != runner.CONTRACT_REVISION or \
            artifacts.get('app_sha256') != app_sha256 or artifacts.get('test_sha256') != test_sha256:
        raise ValueError('owned emulator APKs do not match the requested v1.6.1 binaries')
    return state


def remote_path(run_id, name):
    if not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('unsafe v1.6.1 emulator run ID')
    return REMOTE_BASE + run_id + '/' + name


def adb_output(state, argv, *, timeout=30, maximum=MAX_PACKET_BYTES + 1):
    result = process(driver.adb(state) + argv, timeout=timeout)
    if result.returncode != 0 or len(result.stdout) > maximum:
        raise ValueError('owned Android command failed or exceeded its output bound')
    return result.stdout


def reverse_list(state):
    raw = adb_output(state, ['reverse', '--list'], maximum=64 * 1024)
    try:
        return [line.split() for line in raw.decode().splitlines() if line.strip()]
    except UnicodeError:
        raise ValueError('adb reverse state is malformed') from None


def require_no_reverse(state):
    if reverse_list(state):
        raise ValueError('the recovery capture requires no existing adb reverse or carrier')


def remove_expected_reverse(state, host_port, carrier_port):
    rows = reverse_list(state)
    expected = ['emulator-' + str(state['emulator_port']), f'tcp:{host_port}', f'tcp:{carrier_port}']
    ours = [row for row in rows if row == expected]
    if ours:
        result = process(driver.adb(state) + ['reverse', '--remove', f'tcp:{host_port}'], timeout=30)
        if result.returncode != 0:
            return False
    return not reverse_list(state)


def run_selector(evidence, state, run_id, mode, method, step):
    selector = TEST_CLASS + '#' + method
    command = driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id', run_id,
        '-e', 'scenario', mode, '-e', 'class', selector, TEST_RUNNER]
    output = driver.run(evidence, step, command, junit=True)
    summary_path = evidence / (step + '.json')
    summary = json.loads(summary_path.read_text())
    if summary.get('result') != 'PASS' or summary.get('junit') != 'OK (1 test)':
        raise RuntimeError('the required v1.6.1 recovery selector did not pass exactly one test')
    return output


def export_private_json(evidence, state, run_id, name, local_name):
    raw = adb_output(state, ['exec-out', 'run-as', PACKAGE, 'cat', remote_path(run_id, name)], maximum=128 * 1024)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('Android redacted recovery receipt is malformed') from None
    save(evidence, local_name, raw)
    return value


def read_receipt(evidence, name):
    try:
        return private_json(evidence / name)
    except (ValueError, OSError):
        raise ValueError('required redacted recovery receipt is unavailable') from None


def validate_stage_context(evidence, run_id, public, prepared):
    stage = read_receipt(evidence, 'v16-fixture-stage.redacted.json')
    if stage.get('schema') != 'cicada.client-v16-fixture-stage.v1' or \
            stage.get('result') != 'PASS' or stage.get('run_id') != run_id or \
            stage.get('owner_selection') not in ('primary', 'foreign'):
        raise ValueError('a matching public v1.6 device grant staging receipt is required')
    owner_field = 'owner_id' if stage['owner_selection'] == 'primary' else 'foreign_owner_id'
    owner_id = public.get(owner_field)
    device_id = 'phone-' + run_id
    if not isinstance(owner_id, str) or not owner_id or \
            prepared.get('hub_id_sha256') != digest(public['hub_id']) or \
            prepared.get('owner_id_sha256') != digest(owner_id) or \
            prepared.get('device_id_sha256') != digest(device_id) or \
            prepared.get('contract_revision') != runner.CONTRACT_REVISION or \
            prepared.get('catalog_sha256') != runner.CATALOG_SHA256 or \
            type(prepared.get('session_epoch')) is not int or prepared['session_epoch'] < 1 or \
            type(prepared.get('next_sequence')) is not int or prepared['next_sequence'] < 1 or \
            type(prepared.get('last_response_sequence')) is not int or prepared['last_response_sequence'] < 0 or \
            prepared.get('enrolled') is not True or prepared.get('session_capabilities_ready') is not True or \
            prepared.get('pending') is not False:
        raise ValueError('active Client enrollment is not bound to this run, Owner, Hub, and catalog')


def preflight(args, *, run_prepare):
    evidence = driver.private_evidence(args.evidence)
    run_id = evidence.parent.name
    if not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('recovery requires a unique strict v1.6.1 deterministic run ID')
    if args.mode not in EXPECTED:
        raise ValueError('unsupported recovery mode')
    docker_root()
    verify_tool_image()
    state = verify_android(evidence, args.app_sha256, args.test_sha256)
    root, meta, public = checked_fixture(args.fixture, args.public)
    _fixture, verified_public, hub, network, _ip, _port = carrier.verify_hub(args.fixture, args.public)
    if verified_public != public:
        raise ValueError('Core public metadata changed during fixture verification')
    actual_hub, actual_network = fixture_container(root, meta)
    if actual_hub.get('Id') != hub.get('Id') or actual_network.get('Id') != network.get('Id'):
        raise ValueError('Core Hub identity changed during ownership verification')
    identity_hash = verify_identity(public, public['base_url'])
    require_no_reverse(state)
    tag = 'recovery-' + args.mode
    for name in (
        'recovery-result.redacted.json',
        'recovery-result-summary.redacted.json',
        'recovery-packet.redacted.json',
        'recovery-packet-export.redacted.json',
        'recovery-hub-restart.redacted.json',
        'recovery-capture-selector.json',
        'recovery-result-selector.json',
        'stdio-carrier-' + tag + '.private.json',
        'stdio-carrier-' + tag + '.redacted.jsonl',
        'stdio-carrier-' + tag + '-stopped.redacted.json',
    ):
        if (evidence / name).exists():
            raise ValueError('this strict v1.6.1 run already contains recovery evidence')

    prep_path = evidence / 'recovery-preparation.redacted.json'
    if prep_path.exists():
        prepared = read_receipt(evidence, 'recovery-preparation.redacted.json')
        if prepared.get('result') != 'PASS' or prepared.get('run_id') != run_id or \
                prepared.get('scenario') != args.mode or prepared.get('hub_container_id_sha256') != digest(hub['Id']) or \
                prepared.get('hub_identity_sha256') != identity_hash:
            raise ValueError('prepared recovery receipt belongs to a different live fixture or scenario')
    elif run_prepare:
        run_selector(evidence, state, run_id, args.mode, 'prepareRecoveryFault', 'recovery-prepare-selector')
        prepared = export_private_json(evidence, state, run_id,
            'recovery-preparation.redacted.json', 'recovery-preparation.redacted.json')
        if prepared.get('schema') != 'cicada.client-v161-recovery-preparation.v1' or \
                prepared.get('result') != 'PASS' or prepared.get('run_id') != run_id or \
                prepared.get('scenario') != args.mode:
            raise ValueError('Android preparation receipt did not match the requested mode')
        prepared['hub_container_id_sha256'] = digest(hub['Id'])
        prepared['hub_identity_sha256'] = identity_hash
        save(evidence, 'recovery-preparation.redacted.json', prepared)
    else:
        raise ValueError('run the bounded recovery preparation selector first')
    validate_stage_context(evidence, run_id, public, prepared)
    return evidence, run_id, state, root, meta, public, hub, network, identity_hash


def safe_marker(root):
    path = root / 'state/.cicada-disposable-recovery-fixture'
    try:
        info = path.lstat()
    except FileNotFoundError:
        data = b'disposable\n'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        created = path.lstat()
        if not stat.S_ISREG(created.st_mode) or created.st_uid != os.getuid() or \
                stat.S_IMODE(created.st_mode) != 0o600:
            raise ValueError('disposable helper marker could not be safely created')
        return path, (created.st_dev, created.st_ino), True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('existing disposable helper marker is unsafe')
    raw = private_file(path, exact_mode=0o600, maximum=64)
    if raw != b'disposable\n':
        raise ValueError('existing disposable helper marker has unexpected contents')
    return path, (info.st_dev, info.st_ino), False


def remove_created_marker(path, identity, created):
    if not created:
        return True
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or \
                (info.st_dev, info.st_ino) != identity or private_file(path, maximum=64) != b'disposable\n':
            return False
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def temp_packet(packet, expected_hash, expected_bytes):
    if not isinstance(packet, bytes) or not packet or len(packet) > MAX_PACKET_BYTES or \
            len(packet) != expected_bytes or digest(packet) != expected_hash:
        raise ValueError('exported opaque packet differs from its redacted Android receipt')
    directory = Path(tempfile.mkdtemp(prefix='cicada-v161-recovery-', dir='/tmp'))
    path = directory / 'original-packet.json'
    try:
        os.chmod(directory, 0o700)
        require_real_path(directory, kind='directory', mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(packet)
            output.flush()
            os.fsync(output.fileno())
        del packet
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or \
                info.st_size != expected_bytes or info.st_nlink != 1:
            raise ValueError('original packet temporary file is not mode-0600 and bounded')
        return directory, path, (info.st_dev, info.st_ino)
    except Exception:
        path.unlink(missing_ok=True)
        directory.rmdir()
        raise


def helper_container_spec(root, run_id, mode, image):
    suffix = digest(run_id + ':' + mode)[:16]
    name = 'cicada-v161-recovery-' + suffix
    label = run_id + '-' + mode
    args = [
        'docker', 'create', '--rm', '-i', '--name', name,
        '--label', 'org.cicada.client-v161-recovery=' + label,
        '--label', 'org.cicada.fixture.dir=' + str(root),
        '--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none',
        '--env', 'GOCACHE=/tmp/go-build', '--env', 'GOPROXY=off',
        '--env', 'GOTOOLCHAIN=local', '--env', 'CGO_ENABLED=0',
        '--mount', f'type=bind,source={root / "state"},target=/tmp/fixture-state',
        '--entrypoint', 'go', image,
        'run', './cmd/client-recovery-fixture',
        '--db', '/tmp/fixture-state/cicada.sqlite3', '--mode', mode,
    ]
    return name, label, args


def inspect_helper(container_id, name, label, root, image, mode):
    found = docker_json('container', 'inspect', container_id)
    if len(found) != 1:
        raise ValueError('one-off Core helper container disappeared before it could run')
    item = found[0]
    labels = item.get('Config', {}).get('Labels') or {}
    environment = set(item.get('Config', {}).get('Env') or [])
    mounts = item.get('Mounts') or []
    if item.get('Id') != container_id or item.get('Name') != '/' + name or \
            item.get('Image') != image or item.get('Config', {}).get('Image') != image or \
            labels.get('org.cicada.client-v161-recovery') != label or \
            labels.get('org.cicada.fixture.dir') != str(root) or \
            item.get('HostConfig', {}).get('AutoRemove') is not True or \
            item.get('HostConfig', {}).get('NetworkMode') != 'none' or \
            item.get('Config', {}).get('User') != f'{os.getuid()}:{os.getgid()}' or \
            item.get('Config', {}).get('Entrypoint') != ['go'] or \
            item.get('Config', {}).get('Cmd') != ['run', './cmd/client-recovery-fixture', '--db',
                '/tmp/fixture-state/cicada.sqlite3', '--mode', mode] or \
            item.get('Config', {}).get('OpenStdin') is not True or item.get('Config', {}).get('Tty') is not False or \
            not {'GOCACHE=/tmp/go-build', 'GOPROXY=off', 'GOTOOLCHAIN=local', 'CGO_ENABLED=0'} <= environment or \
            len(mounts) != 1 or mounts[0].get('Source') != str(root / 'state') or \
            mounts[0].get('Destination') != '/tmp/fixture-state' or mounts[0].get('RW') is not True or \
            set(item.get('NetworkSettings', {}).get('Networks', {})) != {'none'}:
        raise ValueError('one-off Core helper container is not the exact network-none scoped producer')


def remove_temp_packet(directory, path, identity):
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or \
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or \
                info.st_nlink != 1 or (info.st_dev, info.st_ino) != identity:
            return False
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    try:
        directory.rmdir()
        return True
    except OSError:
        return False


def run_helper(root, run_id, mode, image, packet_path, packet_identity):
    name, label, create = helper_container_spec(root, run_id, mode, image)
    if container_present(name):
        raise ValueError('one-off recovery helper name is already owned by another process')
    made = process(create, timeout=30)
    if made.returncode != 0:
        raise RuntimeError('pinned Core recovery producer container could not be prepared')
    container_id = made.stdout.decode(errors='replace').strip()
    if not re.fullmatch(r'[0-9a-f]{64}', container_id):
        raise RuntimeError('Docker did not return the new owned recovery producer ID')
    try:
        inspect_helper(container_id, name, label, root, image, mode)
        fd = os.open(packet_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as source:
            packet_info = os.fstat(source.fileno())
            if not stat.S_ISREG(packet_info.st_mode) or packet_info.st_uid != os.getuid() or \
                    stat.S_IMODE(packet_info.st_mode) != 0o600 or packet_info.st_nlink != 1 or \
                    (packet_info.st_dev, packet_info.st_ino) != packet_identity:
                raise ValueError('temporary original packet changed before the Core helper read it')
            started = process(['docker', 'start', '--attach', '--interactive', container_id],
                stdin=source, timeout=180)
        output_hash = digest(started.stdout)
        if started.returncode != 0 or started.stdout != b'fixture prepared\n':
            raise RuntimeError('Core producer rejected the fresh captured packet')
        if container_present(container_id):
            raise RuntimeError('auto-removed Core recovery producer remained after completion')
        return {'exit_code': 0, 'stdout_bytes': len(started.stdout), 'stdout_sha256': output_hash,
            'image_id': image, 'container_id_sha256': digest(container_id), 'network': 'none',
            'database_read_by_client': False}
    finally:
        if container_present(container_id):
            owned = docker_json('container', 'inspect', container_id)
            if len(owned) != 1 or owned[0].get('Id') != container_id or \
                    owned[0].get('Name') != '/' + name or owned[0].get('Image') != image or \
                    (owned[0].get('Config', {}).get('Labels') or {}).get(
                        'org.cicada.client-v161-recovery') != label or \
                    (owned[0].get('Config', {}).get('Labels') or {}).get('org.cicada.fixture.dir') != str(root):
                raise RuntimeError('recovery producer cleanup identity changed; no container was removed')
            removed = process(['docker', 'rm', '--force', container_id], timeout=30)
            if removed.returncode != 0 or not wait_absent(container_id):
                raise RuntimeError('owned one-off Core producer cleanup failed')


def wait_absent(container_id, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = process(['docker', 'container', 'inspect', container_id], timeout=15)
        if result.returncode == 1 and (b'no such container' in result.stderr.lower() or
                b'no such object' in result.stderr.lower()):
            return True
        if result.returncode != 0:
            raise RuntimeError('Docker could not prove the owned container absence')
        time.sleep(0.2)
    return False


def container_present(name_or_id):
    result = process(['docker', 'container', 'inspect', name_or_id], timeout=15)
    if result.returncode == 0:
        return True
    if result.returncode == 1 and (b'no such container' in result.stderr.lower() or
            b'no such object' in result.stderr.lower()):
        return False
    raise RuntimeError('Docker inspection failure did not prove container absence')


def stop_fixture_hub(root, meta, current_hub, current_network):
    container_id = current_hub['Id']
    item, bridge = fixture_container(root, meta)
    if item.get('Id') != container_id or bridge.get('Id') != current_network.get('Id'):
        raise ValueError('owned Hub identity changed before stop')
    stopped = process(['docker', 'stop', '--time', '10', container_id], timeout=30)
    if stopped.returncode != 0:
        if wait_absent(container_id):
            raise RuntimeError('owned Hub stopped but Docker returned an error')
        raise RuntimeError('owned Hub stop failed')
    if not wait_absent(container_id):
        raise RuntimeError('owned --rm Hub did not stop and disappear')
    remaining = process(['docker', 'ps', '-aq', '--no-trunc', '--filter',
        'label=org.cicada.fixture.dir=' + str(root)], timeout=15)
    if remaining.returncode != 0 or remaining.stdout.strip():
        raise RuntimeError('Core fixture still owns a container after stopping its Hub')
    bridge_after = docker_json('network', 'inspect', meta['network'])[0]
    if bridge_after.get('Id') != current_network.get('Id') or bridge_after.get('Containers'):
        raise RuntimeError('Core bridge changed or remained attached after the owned Hub stop')
    return {'exit_code': 0, 'container_id_sha256': digest(container_id),
        'auto_remove_confirmed': True, 'network_id_sha256': digest(current_network['Id'])}


def launch_same_hub(root, meta):
    suffix = re.sub(r'[^a-z0-9]', '', root.name.lower())
    expected_name = 'cicada-cn-' + suffix + '-hub'
    if meta.get('container') != expected_name:
        raise ValueError('fixture Hub name does not match the Core temporary owner path')
    if container_present(expected_name):
        raise ValueError('refusing to replace an unexpected container using the owned Hub name')
    args = [
        'docker', 'run', '--rm', '-d', '--name', expected_name,
        '--user', f'{os.getuid()}:{os.getgid()}', '--network', meta['network'],
        '--label', 'org.cicada.fixture=client-network',
        '--label', 'org.cicada.fixture.dir=' + str(root),
        '--label', 'org.cicada.fixture.source.revision=' + runner.CORE_REVISION,
        '--label', 'org.cicada.fixture.catalog.sha256=' + runner.CATALOG_SHA256,
        '--label', 'org.cicada.fixture.source.fingerprint=' + runner.CORE_SOURCE_FINGERPRINT,
        '--publish', f'127.0.0.1:{meta["host_port"]}:8787',
        '--env-file', str(root / 'hub.env'),
        '--volume', f'{root / "state"}:/state',
        '--volume', f'{root / "workspace"}:/workspace',
        runner.HUB_IMAGE, 'serve', '--host', '0.0.0.0', '--port', '8787',
    ]
    result = process(args, timeout=45)
    if result.returncode != 0:
        raise RuntimeError('the owned Hub could not be recreated from its original fixture inputs')
    new_id = result.stdout.decode(errors='replace').strip()
    if not re.fullmatch(r'[0-9a-f]{64}', new_id):
        raise RuntimeError('Docker did not return the recreated Hub container ID')
    return new_id


def restore_fixture_hub(root, meta, public, old_hub_id, old_network_id, *, require_new=True):
    if container_present(meta['container']):
        current = docker_json('container', 'inspect', meta['container'])[0]
        if current.get('Image') != runner.HUB_IMAGE or \
                current.get('Config', {}).get('Labels', {}).get('org.cicada.fixture.dir') != str(root):
            raise RuntimeError('Hub name is occupied by a foreign container; refusing cleanup')
        new_id = current['Id']
    else:
        network = docker_json('network', 'inspect', meta['network'])[0]
        if network.get('Id') != old_network_id or network.get('Containers'):
            raise RuntimeError('cannot safely restore the stopped Hub onto its original bridge')
        new_id = launch_same_hub(root, meta)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            item, bridge = fixture_container(root, meta)
            identity_hash = verify_identity(public, public['base_url'])
            if (require_new and item.get('Id') == old_hub_id) or bridge.get('Id') != old_network_id:
                raise RuntimeError('Hub restart did not create a new container on the same bridge')
            if item.get('Id') != new_id:
                raise RuntimeError('recreated Hub container ID changed during verification')
            return item, bridge, identity_hash
        except (ValueError, subprocess.CalledProcessError, RuntimeError):
            time.sleep(0.5)
    raise RuntimeError('recreated Hub did not return its pinned public identity')


def remove_android_packet(state, run_id):
    remote = remote_path(run_id, 'recovery-original.packet.private.json')
    removed = process(driver.adb(state) + ['shell', 'run-as', PACKAGE, 'rm', '-f', remote], timeout=30)
    # adb shell joins its arguments before Android's shell parses them.
    checked = process(driver.adb(state) + ['shell', shlex.join([
        'run-as', PACKAGE, 'sh', '-c', 'test ! -e ' + shlex.quote(remote),
    ])], timeout=30)
    return removed.returncode == 0 and checked.returncode == 0


class JsonLineReader:
    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()

    def line(self, process_handle, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b'\n' in self.buffer:
                line, _, rest = self.buffer.partition(b'\n')
                self.buffer = bytearray(rest)
                return line
            readable, _, _ = select.select([self.stream], [], [], 0.2)
            if readable:
                chunk = os.read(self.stream.fileno(), 4096)
                if not chunk:
                    break
                self.buffer.extend(chunk)
                if len(self.buffer) > 8192:
                    raise RuntimeError('carrier status frame exceeded its bound')
            elif process_handle.poll() is not None:
                break
        if self.buffer:
            line = bytes(self.buffer)
            self.buffer.clear()
            return line
        return None


def start_carrier(evidence, args, mode, carrier_port):
    tag = 'recovery-' + mode
    command = [sys.executable, str(HERE / 'v16-host-stdio-carrier.py'),
        '--evidence', str(evidence), '--tag', tag, '--fixture', args.fixture,
        '--public', args.public, '--app-sha256', args.app_sha256,
        '--test-sha256', args.test_sha256, '--fault', 'none',
        '--carrier-port', str(carrier_port)]
    # The v1.6.1 carrier derives its Android URL port from client-public.json.
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)
    except OSError:
        raise RuntimeError('pinned v1.6.1 carrier could not start') from None
    reader = JsonLineReader(proc.stdout)
    raw = reader.line(proc, 20)
    try:
        ready = json.loads(raw) if raw is not None else None
    except (UnicodeError, json.JSONDecodeError):
        ready = None
    if not isinstance(ready, dict) or ready.get('result') != 'READY' or ready.get('tag') != tag or \
            ready.get('fault') != 'none' or ready.get('allowed_route_count') != 5:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        raise RuntimeError('pinned carrier did not provide the exact no-fault readiness receipt')
    return proc, reader, tag


def stop_carrier(proc, reader, tag):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    raw = reader.line(proc, 20)
    try:
        stopped = json.loads(raw) if raw is not None else None
    except (UnicodeError, json.JSONDecodeError):
        stopped = None
    try:
        code = proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        code = proc.wait(timeout=5)
    if code != 0 or not isinstance(stopped, dict) or stopped.get('result') != 'STOPPED' or \
            stopped.get('tag') != tag or stopped.get('docker_exec_exit_code') != 0 or \
            stopped.get('proxy_exit_code') not in (None, 0, -signal.SIGTERM):
        raise RuntimeError('owned v1.6.1 carrier did not stop cleanly')
    return stopped


def verify_carrier(evidence, tag, mode, packet_receipt, result_receipt, stopped):
    transaction_path = evidence / ('stdio-carrier-' + tag + '.redacted.jsonl')
    stopped_path = evidence / ('stdio-carrier-' + tag + '-stopped.redacted.json')
    try:
        data = private_file(transaction_path, maximum=256 * 1024)
        transactions = [json.loads(line) for line in data.splitlines() if line]
        stopped_file = private_json(stopped_path)
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise ValueError('redacted carrier transaction evidence is malformed') from None
    if any(not isinstance(row, dict) for row in transactions):
        raise ValueError('redacted carrier transaction evidence contains a non-object row')
    events = [row.get('event') for row in transactions]
    responses = [row for row in transactions if row.get('event') == 'response']
    expected_code, expected_status = EXPECTED[mode]
    count = 2 if mode == 'uncertain' else 1
    if events.count('ready') != 1 or events.count('stopped') != 1 or \
            any(event not in ('ready', 'response', 'stopped') for event in events) or \
            len(responses) != count:
        raise RuntimeError('carrier observed an unexpected number of authenticated recovery requests')
    ready_row = next(row for row in transactions if row.get('event') == 'ready')
    stop_row = next(row for row in transactions if row.get('event') == 'stopped')
    if ready_row.get('tag') != tag or ready_row.get('fault') != 'none' or \
            ready_row.get('allowed_route_count') != 5 or ready_row.get('payload_persisted') is not False or \
            stop_row.get('tag') != tag or stop_row.get('docker_exec_exit_code') != 0 or \
            stop_row.get('proxy_exit_code') not in (None, 0, -signal.SIGTERM) or \
            stop_row.get('transactions') != count or stop_row.get('payload_persisted') is not False:
        raise RuntimeError('carrier readiness or in-band shutdown evidence was inconsistent')
    if [row.get('transaction') for row in responses] != list(range(1, count + 1)):
        raise RuntimeError('carrier response sequence did not match the isolated recovery exchange')
    recover = responses[0]
    if recover.get('method') != 'POST' or recover.get('path') != '/v2/client/rpc/recover' or \
            recover.get('http_status') != expected_status or \
            recover.get('request_sha256') != packet_receipt.get('packet_sha256') or \
            recover.get('request_bytes') != packet_receipt.get('packet_bytes') or \
            recover.get('response_bytes', 0) <= 0 or recover.get('fault') != 'none':
        raise RuntimeError('the real Hub did not answer the exact captured packet with the expected HTTP status')
    if mode == 'uncertain':
        followup = responses[1]
        if followup.get('method') != 'POST' or followup.get('path') != '/v2/client/rpc' or \
                followup.get('http_status') != 200 or followup.get('request_bytes', 0) <= 0 or \
                followup.get('request_sha256') == packet_receipt.get('packet_sha256') or \
                followup.get('fault') != 'none':
            raise RuntimeError('uncertain outcome was not followed by one fresh authoritative snapshot')
    forbidden = {'body', 'body_b64', 'request', 'response', 'plaintext', 'payload',
        'request_body', 'response_body'}
    if any(forbidden.intersection(row) for row in transactions):
        raise RuntimeError('carrier evidence unexpectedly retained a request or response payload')
    if stopped.get('tag') != tag or stopped.get('result') != 'STOPPED' or \
            stopped.get('docker_exec_exit_code') != 0 or \
            stopped.get('proxy_exit_code') not in (None, 0, -signal.SIGTERM) or \
            stopped.get('transactions') != count or stopped_file.get('schema') != carrier.SCHEMA or \
            stopped_file.get('tag') != tag or stopped_file.get('transactions') != count or \
            stopped_file.get('docker_exec_exit_code') != 0 or \
            stopped_file.get('proxy_exit_code') not in (None, 0, -signal.SIGTERM) or \
            stopped_file.get('result') != 'PASS' or stopped_file.get('payload_persisted') is not False:
        raise RuntimeError('carrier shutdown receipt does not match the observed route count')
    if result_receipt.get('recovery_code') != expected_code or \
            result_receipt.get('expected_http_status') != expected_status or \
            result_receipt.get('packet_sha256') != packet_receipt.get('packet_sha256') or \
            result_receipt.get('operation_id_sha256') != packet_receipt.get('operation_id_sha256') or \
            result_receipt.get('request_sequence') != packet_receipt.get('request_sequence') or \
            result_receipt.get('expected_response_sequence') != packet_receipt.get('expected_response_sequence'):
        raise RuntimeError('Android result did not preserve the original operation and sequence fence')
    return {'requests': count, 'recovery_http_status': expected_status,
        'followup_snapshot_http_status': 200 if mode == 'uncertain' else None,
        'original_packet_sha256': packet_receipt['packet_sha256'],
        'opaque_body_retained': False}


def verify_redacted(evidence, run_id, mode):
    prepared = read_receipt(evidence, 'recovery-preparation.redacted.json')
    captured = read_receipt(evidence, 'recovery-packet.redacted.json')
    result = read_receipt(evidence, 'recovery-result.redacted.json')
    expected_code, expected_status = EXPECTED[mode]
    followup = mode == 'uncertain'
    if type(prepared.get('next_sequence')) is not int or type(prepared.get('last_response_sequence')) is not int:
        raise ValueError('Android preparation receipt sequence counters are malformed')
    expected_next = prepared['next_sequence'] + (2 if followup else 1)
    expected_last_response = prepared['last_response_sequence'] + (2 if followup else 0)
    if prepared.get('schema') != 'cicada.client-v161-recovery-preparation.v1' or \
            captured.get('schema') != 'cicada.client-v161-recovery-packet.v1' or \
            result.get('schema') != 'cicada.client-v161-recovery-result.v1' or \
            any(row.get('result') != 'PASS' or row.get('run_id') != run_id or row.get('scenario') != mode
                for row in (prepared, captured, result)) or \
            any(row.get('contract_revision') != runner.CONTRACT_REVISION or
                row.get('catalog_sha256') != runner.CATALOG_SHA256
                for row in (prepared, captured, result)) or \
            captured.get('operation') != 'status.snapshot' or captured.get('pending') is not True or \
            captured.get('original_packet_persisted_before_network_io') is not True or \
            not re.fullmatch(r'[0-9a-f]{64}', captured.get('packet_sha256', '')) or \
            not re.fullmatch(r'[0-9a-f]{64}', captured.get('operation_id_sha256', '')) or \
            type(captured.get('packet_bytes')) is not int or not 1 <= captured['packet_bytes'] <= MAX_PACKET_BYTES or \
            any(type(captured.get(key)) is not int for key in (
                'request_sequence', 'expected_response_sequence', 'next_sequence', 'last_response_sequence')) or \
            captured.get('request_sequence') != prepared.get('next_sequence') or \
            captured.get('expected_response_sequence') != prepared.get('last_response_sequence', -1) + 1 or \
            captured.get('next_sequence') != prepared.get('next_sequence', -1) + 1 or \
            captured.get('last_response_sequence') != prepared.get('last_response_sequence') or \
            result.get('packet_sha256') != captured.get('packet_sha256') or \
            result.get('operation_id_sha256') != captured.get('operation_id_sha256') or \
            result.get('request_sequence') != captured.get('request_sequence') or \
            result.get('expected_response_sequence') != captured.get('expected_response_sequence') or \
            result.get('recovery_code') != expected_code or result.get('expected_http_status') != expected_status or \
            result.get('business_write_or_native_dispatch_claimed') is not False or \
            result.get('pending_after_recovery') is not (not followup) or \
            result.get('retired_original_packet_preserved') is not followup or \
            result.get('authoritative_followup_snapshot') is not followup or \
            result.get('on_device_packet_copy_removed') is not True or \
            result.get('next_sequence_after_followup') != expected_next or \
            result.get('last_response_sequence_after_followup') != expected_last_response:
        raise ValueError('redacted Android recovery receipts do not match this v1.6.1 scenario')
    return prepared, captured, result


def run_scenario(args):
    live_processing = args.mode == 'processing'
    if live_processing and not args.allow_disposable_live_processing:
        raise ValueError('processing requires the explicitly authorized disposable live fixture')
    evidence, run_id, state, root, meta, public, original_hub, original_network, identity_before = \
        preflight(args, run_prepare=True)
    old_hub_id = original_hub['Id']
    old_network_id = original_network['Id']
    host_port = meta['host_port']
    prepared = read_receipt(evidence, 'recovery-preparation.redacted.json')
    carrier_port = 38097 if host_port != 38097 else 38098
    packet_directory = packet_path = packet_identity = None
    marker_path = marker_identity = None
    marker_created = False
    carrier_process = carrier_reader = None
    carrier_tag = 'recovery-' + args.mode
    hub_stopped = False
    helper_name = helper_container_spec(root, run_id, args.mode, runner.INTEROP_IMAGE)[0]
    cleanup = {'hub_restored': True, 'temporary_packet_removed': True,
        'created_helper_marker_removed': True, 'android_packet_copy_removed': False,
        'carrier_stopped': True, 'adb_reverse_empty': True, 'core_helper_removed': True}
    candidate = {}
    failure_type = None
    try:
        # The incoming session is fresh and pinned before any recovery packet
        # can be captured. No other container may share the fixture state.
        scan_shared_mounts(root, meta, old_hub_id)
        require_no_reverse(state)
        run_selector(evidence, state, run_id, args.mode, 'captureOriginalPacket', 'recovery-capture-selector')
        captured = export_private_json(evidence, state, run_id,
            'recovery-packet.redacted.json', 'recovery-packet.redacted.json')
        if captured.get('schema') != 'cicada.client-v161-recovery-packet.v1' or \
                captured.get('result') != 'PASS' or captured.get('run_id') != run_id or \
                captured.get('scenario') != args.mode or captured.get('operation') != 'status.snapshot' or \
                not re.fullmatch(r'[0-9a-f]{64}', captured.get('packet_sha256', '')) or \
                not re.fullmatch(r'[0-9a-f]{64}', captured.get('operation_id_sha256', '')) or \
                type(captured.get('packet_bytes')) is not int or not 1 <= captured['packet_bytes'] <= MAX_PACKET_BYTES or \
                type(captured.get('request_sequence')) is not int or captured['request_sequence'] < 1 or \
                type(captured.get('expected_response_sequence')) is not int or \
                type(captured.get('next_sequence')) is not int or \
                type(captured.get('last_response_sequence')) is not int or \
                captured.get('request_sequence') != prepared.get('next_sequence') or \
                captured.get('expected_response_sequence') != prepared.get('last_response_sequence', -1) + 1 or \
                captured.get('next_sequence') != prepared.get('next_sequence', -1) + 1 or \
                captured.get('last_response_sequence') != prepared.get('last_response_sequence'):
            raise ValueError('Android did not persist one bounded fresh recovery request')
        packet = adb_output(state, ['exec-out', 'run-as', PACKAGE, 'cat',
            remote_path(run_id, 'recovery-original.packet.private.json')])
        packet_directory, packet_path, packet_identity = temp_packet(
            packet, captured['packet_sha256'], captured['packet_bytes'])
        cleanup['temporary_packet_removed'] = False
        del packet
        save(evidence, 'recovery-packet-export.redacted.json', {
            'schema': SCHEMA, 'result': 'PASS', 'run_id': run_id, 'scenario': args.mode,
            'packet_sha256': captured['packet_sha256'], 'packet_bytes': captured['packet_bytes'],
            'mode': '0600', 'location': 'temporary /tmp; outside Git', 'contents_retained': False,
        })

        # Recheck state/Hub ownership and shared mounts immediately before the
        # destructive --rm stop; the DB leaf is metadata-only lstat evidence.
        root_again, meta_again, public_again = checked_fixture(args.fixture, args.public)
        current, bridge = fixture_container(root_again, meta_again)
        if root_again != root or public_again != public or current.get('Id') != old_hub_id or \
                bridge.get('Id') != old_network_id:
            raise ValueError('Core fixture identity changed before its recovery interruption')
        scan_shared_mounts(root, meta, old_hub_id)

        # Processing is a separately authorized synthetic ledger injection:
        # restarting would fence it to UNCERTAIN. Other modes require a stop.
        cleanup['hub_restored'] = False
        if not live_processing:
            hub_stopped = True
            stop_fixture_hub(root, meta, original_hub, original_network)

        # Only the selected disposable Hub can own this state mount. The
        # network-none producer is the sole additional reader/writer.
        marker_path, marker_identity, marker_created = safe_marker(root)
        cleanup['created_helper_marker_removed'] = not marker_created
        cleanup['core_helper_removed'] = False
        helper_record = run_helper(root, run_id, args.mode, runner.INTEROP_IMAGE, packet_path, packet_identity)
        cleanup['core_helper_removed'] = True
        if not remove_created_marker(marker_path, marker_identity, marker_created):
            raise RuntimeError('owned disposable helper marker changed before cleanup')
        cleanup['created_helper_marker_removed'] = not marker_created or not marker_path.exists()
        marker_path = None
        if not remove_temp_packet(packet_directory, packet_path, packet_identity):
            raise RuntimeError('temporary original packet changed before its required cleanup')
        packet_path = packet_directory = None
        packet_identity = None
        cleanup['temporary_packet_removed'] = True

        if live_processing:
            restarted, bridge = fixture_container(root, meta)
            identity_after = verify_identity(public, public['base_url'])
            if restarted['Id'] != old_hub_id or bridge['Id'] != old_network_id:
                raise RuntimeError('live processing fixture was interrupted or replaced')
            scan_shared_mounts(root, meta, old_hub_id)
        else:
            new_hub_id = launch_same_hub(root, meta)
            restarted, bridge, identity_after = restore_fixture_hub(
                root, meta, public, old_hub_id, old_network_id)
            if new_hub_id != restarted['Id']:
                raise RuntimeError('restarted Hub container identity was not restored')
        if identity_after != identity_before:
            raise RuntimeError('selected Hub state changed its immutable public identity')
        hub_stopped = False
        cleanup['hub_restored'] = True
        save(evidence, 'recovery-hub-restart.redacted.json', {
            'schema': SCHEMA, 'result': 'PASS', 'scenario': args.mode,
            'old_container_id_sha256': digest(old_hub_id),
            'new_container_id_sha256': digest(restarted['Id']), 'container_id_changed': not live_processing,
            'image_id': runner.HUB_IMAGE, 'network_id_sha256': digest(bridge['Id']),
            'state_directory_sha256': digest(str(root / 'state')),
            'hub_identity_sha256_before': identity_before, 'hub_identity_sha256_after': identity_after,
            'auto_remove_stop_confirmed': not live_processing,
            'lifecycle': 'LIVE_SYNTHETIC_PROCESSING_INJECTION' if live_processing else 'STOP_HELPER_RESTART',
            'same_database_bind_mount': True, 'client_read_database': False,
        })

        carrier_process, carrier_reader, carrier_tag = start_carrier(
            evidence, args, args.mode, carrier_port)
        cleanup['carrier_stopped'] = False
        run_selector(evidence, state, run_id, args.mode, 'recoverAndVerify', 'recovery-result-selector')
        result_receipt = export_private_json(evidence, state, run_id,
            'recovery-result.redacted.json', 'recovery-result.redacted.json')
        stopped = stop_carrier(carrier_process, carrier_reader, carrier_tag)
        carrier_process = carrier_reader = None
        cleanup['carrier_stopped'] = True
        if not remove_expected_reverse(state, host_port, carrier_port):
            raise RuntimeError('the owned recovery carrier reverse mapping was not removed')
        cleanup['adb_reverse_empty'] = True
        cleanup['android_packet_copy_removed'] = remove_android_packet(state, run_id)
        if not cleanup['android_packet_copy_removed']:
            raise RuntimeError('the private Android copy of the original packet was not removed')
        if result_receipt.get('expected_http_status') != EXPECTED[args.mode][1]:
            raise RuntimeError('Android recovery receipt omitted its actual expected HTTP result')
        carrier_record = verify_carrier(evidence, carrier_tag, args.mode, captured, result_receipt, stopped)
        verify_redacted(evidence, run_id, args.mode)
        candidate = {
            'schema': SCHEMA, 'run_id': run_id, 'scenario': args.mode,
            'contract_revision': runner.CONTRACT_REVISION, 'catalog_sha256': runner.CATALOG_SHA256,
            'core_source_revision': runner.CORE_REVISION,
            'core_source_fingerprint': runner.CORE_SOURCE_FINGERPRINT,
            'hub_image_id': runner.HUB_IMAGE, 'interop_helper_image_id': runner.INTEROP_IMAGE,
            'app_sha256': args.app_sha256, 'test_sha256': args.test_sha256,
            'packet_sha256': captured['packet_sha256'], 'packet_bytes': captured['packet_bytes'],
            'operation_id_sha256': captured['operation_id_sha256'],
            'request_sequence': captured['request_sequence'],
            'expected_response_sequence': captured['expected_response_sequence'],
            'recovery_code': result_receipt['recovery_code'],
            'recovery_http_status': carrier_record['recovery_http_status'],
            'followup_snapshot_http_status': carrier_record['followup_snapshot_http_status'],
            'core_helper_exit_code': helper_record['exit_code'],
            'core_helper_stdout_sha256': helper_record['stdout_sha256'],
            'hub_identity_sha256': identity_after,
            'hub_container_id_changed_after_restart': not live_processing,
            'live_disposable_processing_authorized': live_processing,
            'carrier_transactions': carrier_record['requests'],
            'payload_persisted': False,
            'physical_android': 'NOT_RUN', 'public_https': 'NOT_RUN',
        }
    except Exception as error:
        failure_type = type(error).__name__
    finally:
        if carrier_process is not None:
            try:
                stop_carrier(carrier_process, carrier_reader, carrier_tag)
                cleanup['carrier_stopped'] = True
            except Exception:
                cleanup['carrier_stopped'] = False
        try:
            cleanup['adb_reverse_empty'] = remove_expected_reverse(state, host_port, carrier_port)
        except Exception:
            cleanup['adb_reverse_empty'] = False
        try:
            if container_present(helper_name):
                inspect = docker_json('container', 'inspect', helper_name)
                if len(inspect) != 1 or inspect[0].get('Image') != runner.INTEROP_IMAGE or \
                        inspect[0].get('Name') != '/' + helper_name or \
                        (inspect[0].get('Config', {}).get('Labels') or {}).get(
                            'org.cicada.fixture.dir') != str(root) or \
                        (inspect[0].get('Config', {}).get('Labels') or {}).get(
                            'org.cicada.client-v161-recovery') != run_id + '-' + args.mode:
                    cleanup['core_helper_removed'] = False
                else:
                    removed = process(['docker', 'rm', '--force', inspect[0]['Id']], timeout=30)
                    cleanup['core_helper_removed'] = removed.returncode == 0 and wait_absent(inspect[0]['Id'])
            else:
                cleanup['core_helper_removed'] = True
        except Exception:
            cleanup['core_helper_removed'] = False
        if packet_path is not None:
            cleanup['temporary_packet_removed'] = remove_temp_packet(
                packet_directory, packet_path, packet_identity)
        if marker_path is not None:
            cleanup['created_helper_marker_removed'] = cleanup['core_helper_removed'] and \
                remove_created_marker(marker_path, marker_identity, marker_created)
        try:
            cleanup['android_packet_copy_removed'] = remove_android_packet(state, run_id)
        except Exception:
            cleanup['android_packet_copy_removed'] = False
        if hub_stopped:
            try:
                restored, bridge, identity = restore_fixture_hub(
                    root, meta, public, old_hub_id, old_network_id, require_new=False)
                cleanup['hub_restored'] = bridge.get('Id') == old_network_id and identity == identity_before
            except Exception:
                cleanup['hub_restored'] = False
        elif live_processing:
            # Never restart this scenario to make a continuity check pass.
            try:
                current, bridge = fixture_container(root, meta)
                identity = verify_identity(public, public['base_url'])
                cleanup['hub_restored'] = current['Id'] == old_hub_id and \
                    bridge['Id'] == old_network_id and identity == identity_before
            except Exception:
                cleanup['hub_restored'] = False
        successful = failure_type is None and bool(candidate) and all(cleanup.values())
        final = dict(candidate)
        final.update({'schema': SCHEMA, 'result': 'PASS' if successful else 'FAIL',
            'run_id': run_id, 'scenario': args.mode, 'cleanup': cleanup})
        if not successful and failure_type:
            final['failure_type'] = failure_type
        save(evidence, 'recovery-result-summary.redacted.json', final)
    if not successful:
        raise RuntimeError('recovery scenario failed or an owned cleanup proof was incomplete')
    return final


def run_preparation(args):
    evidence, run_id, state, root, meta, public, hub, network, identity_hash = \
        preflight(args, run_prepare=True)
    prepared = read_receipt(evidence, 'recovery-preparation.redacted.json')
    return {'result': 'PASS', 'run_id': run_id, 'scenario': args.mode,
        'hub_container_id_sha256': digest(hub['Id']), 'hub_network_id_sha256': digest(network['Id']),
        'hub_identity_sha256': identity_hash, 'catalog_sha256': runner.CATALOG_SHA256,
        'next_sequence': prepared.get('next_sequence'), 'pending': False,
        'capture_requires_no_carrier_or_adb_reverse': True, 'evidence': str(evidence)}


def verify_command(args):
    evidence = driver.private_evidence(args.evidence)
    run_id = evidence.parent.name
    if not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('redacted verification requires a strict v1.6.1 run ID')
    if not re.fullmatch(r'[0-9a-f]{64}', args.app_sha256) or \
            not re.fullmatch(r'[0-9a-f]{64}', args.test_sha256):
        raise ValueError('verify requires exact lowercase app and test APK SHA-256 values')
    prepared, captured, result = verify_redacted(evidence, run_id, args.mode)
    summary = read_receipt(evidence, 'recovery-result-summary.redacted.json')
    restart = read_receipt(evidence, 'recovery-hub-restart.redacted.json')
    tag = 'recovery-' + args.mode
    stopped = read_receipt(evidence, 'stdio-carrier-' + tag + '-stopped.redacted.json')
    stopped_event = {'result': 'STOPPED', 'tag': stopped.get('tag'),
        'docker_exec_exit_code': stopped.get('docker_exec_exit_code'),
        'proxy_exit_code': stopped.get('proxy_exit_code'), 'transactions': stopped.get('transactions')}
    carrier_record = verify_carrier(evidence, tag, args.mode, captured, result, stopped_event)
    expected_code, expected_status = EXPECTED[args.mode]
    cleanup = summary.get('cleanup')
    restarted_expected = args.mode != 'processing'
    if summary.get('schema') != SCHEMA or summary.get('result') != 'PASS' or \
            summary.get('run_id') != run_id or summary.get('scenario') != args.mode or \
            summary.get('catalog_sha256') != runner.CATALOG_SHA256 or \
            summary.get('contract_revision') != runner.CONTRACT_REVISION or \
            summary.get('core_source_revision') != runner.CORE_REVISION or \
            summary.get('core_source_fingerprint') != runner.CORE_SOURCE_FINGERPRINT or \
            summary.get('hub_image_id') != runner.HUB_IMAGE or \
            summary.get('interop_helper_image_id') != runner.INTEROP_IMAGE or \
            summary.get('app_sha256') != args.app_sha256 or summary.get('test_sha256') != args.test_sha256 or \
            summary.get('packet_sha256') != captured.get('packet_sha256') or \
            summary.get('packet_bytes') != captured.get('packet_bytes') or \
            summary.get('operation_id_sha256') != captured.get('operation_id_sha256') or \
            summary.get('request_sequence') != captured.get('request_sequence') or \
            summary.get('expected_response_sequence') != captured.get('expected_response_sequence') or \
            summary.get('recovery_code') != expected_code or \
            summary.get('recovery_http_status') != expected_status or \
            summary.get('followup_snapshot_http_status') != (200 if args.mode == 'uncertain' else None) or \
            summary.get('core_helper_exit_code') != 0 or summary.get('carrier_transactions') != carrier_record['requests'] or \
            summary.get('hub_container_id_changed_after_restart') is not restarted_expected or \
            summary.get('live_disposable_processing_authorized') is not (not restarted_expected) or \
            summary.get('hub_identity_sha256') != restart.get('hub_identity_sha256_after') or \
            summary.get('payload_persisted') is not False or summary.get('physical_android') != 'NOT_RUN' or \
            summary.get('public_https') != 'NOT_RUN' or not isinstance(cleanup, dict) or \
            set(cleanup) != {'hub_restored', 'temporary_packet_removed', 'created_helper_marker_removed',
                'android_packet_copy_removed', 'carrier_stopped', 'adb_reverse_empty', 'core_helper_removed'} or \
            any(value is not True for value in cleanup.values()) or \
            restart.get('schema') != SCHEMA or restart.get('result') != 'PASS' or \
            restart.get('scenario') != args.mode or restart.get('image_id') != runner.HUB_IMAGE or \
            restart.get('container_id_changed') is not restarted_expected or restart.get('same_database_bind_mount') is not True or \
            restart.get('client_read_database') is not False or restart.get('auto_remove_stop_confirmed') is not restarted_expected or \
            restart.get('lifecycle') != ('STOP_HELPER_RESTART' if restarted_expected else 'LIVE_SYNTHETIC_PROCESSING_INJECTION') or \
            restart.get('hub_identity_sha256_before') != restart.get('hub_identity_sha256_after') or \
            (restart.get('old_container_id_sha256') != restart.get('new_container_id_sha256')) is not restarted_expected or \
            restart.get('hub_identity_sha256_after') != summary.get('hub_identity_sha256'):
        raise ValueError('redacted recovery driver summary does not match the pinned contract')
    return {'result': 'PASS', 'run_id': run_id, 'scenario': args.mode,
        'packet_sha256': summary.get('packet_sha256'), 'recovery_http_status': expected_status,
        'payload_persisted': False}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('prepare', 'run', 'verify'):
        sub = commands.add_parser(action)
        sub.add_argument('--evidence', required=True)
        sub.add_argument('--mode', choices=tuple(EXPECTED), required=True)
        sub.add_argument('--app-sha256', required=True)
        sub.add_argument('--test-sha256', required=True)
        if action == 'run':
            sub.add_argument('--allow-disposable-live-processing', action='store_true',
                help='explicit authorization for synthetic processing injection in a fresh owned fixture')
        if action != 'verify':
            sub.add_argument('--fixture', required=True, help='Core .cicada-client-network-fixture.json')
            sub.add_argument('--public', required=True, help='matching Core client-public.json')
    return parser.parse_args()


def main():
    os.umask(0o077)
    args = parse_args()
    if args.action == 'prepare':
        result = run_preparation(args)
    elif args.action == 'run':
        result = run_scenario(args)
    else:
        result = verify_command(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'result': 'FAIL', 'reason':
            'v1.6.1 recovery fixture ownership, request, helper, Hub restart, or redacted verification failed'}),
            file=sys.stderr)
        raise SystemExit(1)
