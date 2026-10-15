#!/usr/bin/env python3
"""Run one bounded Android v1.3 Client RPC recovery fault scenario.

The runner owns only the disposable Hub fixture, one narrow recovery proxy and
its adb reverse. It never reads SQLite; the fixed core helper receives only
the original encrypted packet from the proxy.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
import urllib.request

REPO = Path(__file__).resolve().parents[2]
CORE = REPO.parent / 'CICADA'
DRIVER_PATH = Path(__file__).with_name('monitor-android.py')
FIXTURE_PATH = Path(__file__).with_name('monitor-fixture.py')
CORE_FIXTURE = CORE / 'scripts/client-group-key-fixture.sh'
CORE_PROXY = CORE / 'scripts/client-recovery-fault-proxy.py'
BUILD_METADATA = CORE / '.cicada-data/client-v13-be0269e/interop/result.json'
HUB_SOURCE = 'be0269e80c41e94881d131bd4f4b233e80b6ffe6'
HUB_IMAGE = 'sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783'
PROXY_IMAGE = 'sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358'
CATALOG = '808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377'
HELPER_SHA256 = '2ddde2d128385e23ee97533e0078987e41c21b50abb76ae2e95ab47dd4530630'
PACKAGE = 'ai.cicada.client'
TEST_RUNNER = PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner'
TEST_CLASS = 'ai.cicada.client.hub.MonitorRecoveryFaultTest'
CAPTURE_TEST = TEST_CLASS + '#capturePrepareFaultPendingPacket'
RECOVERY_TESTS = {
    'processing': TEST_CLASS + '#recoverStillProcessing',
    'uncertain': TEST_CLASS + '#recoverSignedUncertain',
    'legacy': TEST_CLASS + '#recoverUnavailable',
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('required interop helper is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load_module('monitor_android', DRIVER_PATH)
fixture = load_module('monitor_fixture', FIXTURE_PATH)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def save(evidence, name, value):
    driver.save(evidence / name, value)


def command(command_args, *, timeout=60):
    return subprocess.run(command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=False)


def record_command(evidence, step, command_args, *, timeout=60):
    proc = command(command_args, timeout=timeout)
    save(evidence, step + '.json', {
        'command': command_args, 'exit_code': proc.returncode,
        'stdout_sha256': digest(proc.stdout), 'stdout_retained': False,
        'captured_at': now(),
    })
    return proc


def docker_json(*args):
    return json.loads(subprocess.check_output(['docker', *args], text=True))


def verify_runtime(evidence, helper):
    state = driver.state_for(evidence)
    docker_root = subprocess.check_output(
        ['docker', 'info', '--format', '{{.DockerRootDir}}'], text=True).strip()
    if docker_root != '/gpu1-share/data/docker-root':
        raise ValueError('Docker data root differs from the approved local root')
    image_id = subprocess.check_output(
        ['docker', 'image', 'inspect', PROXY_IMAGE, '--format', '{{.Id}}'], text=True).strip()
    if image_id != PROXY_IMAGE:
        raise ValueError('recovery proxy image digest mismatch')
    helper = Path(helper)
    if helper.is_symlink() or not helper.is_file() or helper.resolve() != helper:
        raise ValueError('fixture helper must be a real regular file')
    helper_hash = digest(helper.read_bytes())
    if helper_hash != HELPER_SHA256:
        raise ValueError('fixed recovery helper digest mismatch')
    committed_proxy = subprocess.check_output(
        ['git', '-C', str(CORE), 'show', HUB_SOURCE + ':scripts/client-recovery-fault-proxy.py'])
    proxy_hash = digest(CORE_PROXY.read_bytes())
    if proxy_hash != digest(committed_proxy):
        raise ValueError('recovery proxy differs from the pinned core source')
    artifacts_path = evidence / 'android-artifacts.json'
    if artifacts_path.is_symlink() or not artifacts_path.is_file():
        raise ValueError('installed APK evidence is missing')
    artifacts = json.loads(artifacts_path.read_text())
    if not isinstance(artifacts, dict) or not all(
            re.fullmatch(r'[0-9a-f]{64}', artifacts.get(key, ''))
            for key in ('app_sha256', 'test_sha256')):
        raise ValueError('installed APK checksums are absent or malformed')
    return state, helper, helper_hash, proxy_hash


def new_evidence_dir(root, scenario):
    parent = root / 'recovery-faults'
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.is_symlink() or parent.resolve() != parent or parent.stat().st_uid != os.getuid() or \
            parent.stat().st_mode & 0o077:
        raise ValueError('recovery evidence parent must remain private to the caller')
    scenario_dir = parent / scenario
    scenario_dir.mkdir(mode=0o700, exist_ok=False)
    directory = scenario_dir / 'evidence'
    directory.mkdir(mode=0o700)
    if directory.is_symlink() or directory.resolve() != directory or root not in directory.parents:
        raise ValueError('scenario evidence path escaped the owned evidence directory')
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise ValueError('scenario evidence must remain private to the caller')
    save(directory, 'android-artifacts.json', json.loads((root / 'android-artifacts.json').read_text()))
    return directory


def start_fixture(evidence, root_holder):
    if CORE_FIXTURE.is_symlink() or not CORE_FIXTURE.is_file() or BUILD_METADATA.is_symlink() or not BUILD_METADATA.is_file():
        raise ValueError('pinned core fixture inputs are missing')
    args = [str(CORE_FIXTURE), 'start', '--build-metadata', str(BUILD_METADATA)]
    proc = command(args, timeout=360)
    output = proc.stdout.decode(errors='replace')
    match = re.search(r'(?m)^Fixture result: (/tmp/cgk\.[A-Za-z0-9]+)/fixture-result\.json$', output)
    if proc.returncode != 0 or match is None:
        save(evidence, 'fixture-start.json', {
            'command': args, 'exit_code': proc.returncode,
            'stdout_sha256': digest(proc.stdout), 'stdout_retained': False,
            'result': 'FAIL', 'captured_at': now(),
        })
        raise RuntimeError('pinned disposable Hub fixture did not start; output was redacted')
    root = Path(match.group(1))
    root_holder.append(root)
    root, result = fixture.checked_fixture(root)
    if result['hub']['image_id'] != HUB_IMAGE or result['hub']['source_revision'] != HUB_SOURCE or \
            result['hub']['catalog_sha256'] != CATALOG:
        raise ValueError('started Hub fixture does not match pinned v1.3 metadata')
    db_path = root / 'state/cicada.sqlite3'
    marker = root / 'state/.cicada-disposable-recovery-fixture'
    if not db_path.is_file() or db_path.is_symlink():
        raise ValueError('disposable Hub database path is missing or unsafe')
    if marker.exists():
        if marker.is_symlink() or not marker.is_file() or marker.read_text() != 'disposable\n':
            raise ValueError('recovery helper marker is not the expected disposable marker')
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write('disposable\n')
    save(evidence, 'fixture-start.json', {
        'command': args, 'exit_code': proc.returncode,
        'stdout_sha256': digest(proc.stdout), 'stdout_retained': False,
        'fixture_path_sha256': digest(str(root)), 'hub_image_id': HUB_IMAGE,
        'hub_source_revision': HUB_SOURCE, 'catalog_sha256': CATALOG,
        'result': 'PASS', 'captured_at': now(),
    })
    return root, result


def inspect_fixture_hub(root, result):
    marker = json.loads((root / '.cicada-client-group-key-fixture.json').read_text())
    name = marker.get('hub_container')
    if not isinstance(name, str) or not name.startswith('cicada-cgk-'):
        raise ValueError('fixture Hub container name is invalid')
    container = docker_json('container', 'inspect', name)[0]
    labels = container.get('Config', {}).get('Labels') or {}
    if (container.get('Image') != HUB_IMAGE or labels.get('org.cicada.fixture') != 'client-group-key' or
            labels.get('org.cicada.fixture.dir') != str(root) or
            labels.get('org.opencontainers.image.revision') != HUB_SOURCE or
            labels.get('org.cicada.client-catalog.sha256') != CATALOG):
        raise ValueError('refusing to operate a Hub outside this pinned disposable fixture')
    mount = next((item for item in container.get('Mounts', []) if item.get('Destination') == '/state'), None)
    if not mount or mount.get('Source') != str(root / 'state') or mount.get('RW') is not True:
        raise ValueError('Hub state bind mount differs from the disposable fixture')
    return {
        'name': name, 'id': container['Id'], 'image': container['Image'],
        'state_source': mount['Source'], 'hub_url': result['hub']['url'],
    }


def get_json(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=3) as response:
        return json.load(response)


def hub_identity(hub_url):
    health = get_json(hub_url + '/healthz')
    capabilities = get_json(hub_url + '/v2/client/capabilities')
    identity = get_json(hub_url + '/v2/client/identity')
    if (health.get('status') != 'ok' or health.get('revision') != HUB_SOURCE or
            health.get('dirty') is not False or health.get('catalog_sha256') != CATALOG or
            capabilities.get('contract_revision') != 'client-hub-v1.3' or
            capabilities.get('catalog_sha256') != CATALOG or identity.get('contract') != 'android-hub-v1'):
        raise ValueError('restarted Hub did not return the pinned v1.3 identity')
    hub_id = identity.get('hub_id')
    if not isinstance(hub_id, str) or not hub_id:
        raise ValueError('Hub identity omitted its ID')
    return digest(hub_id)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def inspect_proxy(name, label, fixture_root):
    containers = docker_json('container', 'inspect', name)
    if not containers:
        raise ValueError('owned recovery proxy container disappeared')
    item = containers[0]
    labels = item.get('Config', {}).get('Labels') or {}
    if (item.get('Image') != PROXY_IMAGE or labels.get('org.cicada.client-monitor-recovery-proxy') != label or
            labels.get('org.cicada.fixture.dir') != str(fixture_root)):
        raise ValueError('refusing to operate a foreign recovery proxy')
    return item


def start_proxy(evidence, run_id, fixture_root, result, helper, scenario, ownership, port=None):
    step = f'{scenario}-proxy-start' if port is None else f'{scenario}-proxy-retarget-start'
    port = free_port() if port is None else port
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '-', run_id)[:70]
    name = f'cicada-monitor-recovery-{safe_id}-{scenario}'
    label = safe_id + '-' + scenario
    if command(['docker', 'container', 'inspect', name]).returncode == 0:
        raise ValueError('owned recovery proxy name is already in use')
    hub_url = result['hub']['url']
    args = ['docker', 'run', '--rm', '-d', '--name', name,
        '--label', 'org.cicada.client-monitor-recovery-proxy=' + label,
        '--label', 'org.cicada.fixture.dir=' + str(fixture_root),
        '--user', f'{os.getuid()}:{os.getgid()}', '--network', 'host',
        '-v', f'{fixture_root}:{fixture_root}', '-v', f'{CORE_PROXY}:/proxy.py:ro',
        '-v', f'{helper}:/client-recovery-fixture:ro', PROXY_IMAGE, 'python3', '/proxy.py',
        '--listen-port', str(port), '--hub-url', hub_url,
        '--db', str(fixture_root / 'state/cicada.sqlite3'),
        '--fixture-binary', '/client-recovery-fixture', '--scenario', scenario,
        '--operation', 'monitor.broadcast_prepare']
    proc = record_command(evidence, step, args)
    if proc.returncode != 0:
        raise RuntimeError('recovery proxy did not start')
    ownership.update({'name': name, 'label': label, 'port': port})
    inspect_proxy(name, label, fixture_root)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        logs = subprocess.check_output(['docker', 'logs', name], text=True)
        if re.search(rf'(?m)^READY listen={port} scenario={scenario} operation=monitor\.broadcast_prepare$', logs):
            return name, label, port
        time.sleep(0.25)
    raise RuntimeError('recovery proxy did not report its bounded READY line')


def run_test(evidence, state, step, selector, scenario=None):
    args = driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id', state['run_id']]
    if scenario:
        args += ['-e', 'scenario', scenario]
    args += ['-e', 'class', selector, TEST_RUNNER]
    return driver.run(evidence, step, args, junit=True)


def status_markers(output):
    allowed = re.compile(r'^(?:monitor_prepare_fault_(?:original_operation_sha256|original_packet_sha256|request_sequence|expected_response_sequence|business_dispatch_claimed)|monitor_prepare_recovery_(?:processing|legacy|uncertain|original_packet_retained|monitor_metadata_retained|authoritative_monitor_preview_claimed|business_dispatch_claimed))$')
    markers = {}
    for line in output.decode(errors='replace').splitlines():
        # AndroidJUnitRunner can prefix the first status with the class name.
        match = re.search(r'\bINSTRUMENTATION_STATUS: ([a-z0-9_]+)=(.*)$', line)
        if match and allowed.fullmatch(match.group(1)):
            markers[match.group(1)] = match.group(2)
    return markers


def verify_capture_markers(markers):
    required = {
        'monitor_prepare_fault_original_operation_sha256',
        'monitor_prepare_fault_original_packet_sha256',
        'monitor_prepare_fault_request_sequence',
        'monitor_prepare_fault_expected_response_sequence',
        'monitor_prepare_fault_business_dispatch_claimed',
    }
    if not required.issubset(markers):
        raise RuntimeError('fault capture omitted required redacted sequence evidence')
    for key in ('monitor_prepare_fault_original_operation_sha256', 'monitor_prepare_fault_original_packet_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', markers[key]):
            raise RuntimeError('fault capture digest marker is invalid')
    for key in ('monitor_prepare_fault_request_sequence', 'monitor_prepare_fault_expected_response_sequence'):
        if not markers[key].isdigit() or int(markers[key]) < 1:
            raise RuntimeError('fault capture sequence marker is invalid')
    if markers['monitor_prepare_fault_business_dispatch_claimed'] != 'false':
        raise RuntimeError('fault path unexpectedly claimed business dispatch')


def verify_recovery_markers(markers, scenario):
    expected_outcomes = {
        'processing': 'STILL_PROCESSING', 'uncertain': 'OUTCOME_UNCERTAIN',
        'legacy': 'RECOVERY_UNAVAILABLE',
    }
    required = {
        f'monitor_prepare_recovery_{scenario}',
        'monitor_prepare_recovery_original_packet_retained',
        'monitor_prepare_recovery_business_dispatch_claimed',
    }
    if scenario == 'uncertain':
        required.update({
            'monitor_prepare_recovery_monitor_metadata_retained',
            'monitor_prepare_recovery_authoritative_monitor_preview_claimed',
        })
    if not required.issubset(markers) or markers[f'monitor_prepare_recovery_{scenario}'] != expected_outcomes[scenario] or \
            markers['monitor_prepare_recovery_original_packet_retained'] != 'true' or \
            markers['monitor_prepare_recovery_business_dispatch_claimed'] != 'false':
        raise RuntimeError('recovery assertions or redacted state markers did not match the scenario')
    if scenario == 'uncertain' and (
            markers['monitor_prepare_recovery_monitor_metadata_retained'] != 'PREPARE_UNCERTAIN' or
            markers['monitor_prepare_recovery_authoritative_monitor_preview_claimed'] != 'false'):
        raise RuntimeError('uncertain recovery markers did not preserve unresolved Monitor metadata')


def run_scenario(root, helper, scenario):
    evidence = new_evidence_dir(root, scenario)
    state, helper, helper_hash, proxy_hash = verify_runtime(root, helper)
    runner_commit = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
    events = []
    fixture_root = None
    proxy_ownership = {}
    reverse_port = None
    primary_error = None
    result_record = {'schema': 'cicada.monitor-recovery-fault.v1', 'scenario': scenario,
                     'result': 'RUNNING', 'evidence': str(evidence), 'events': events}
    save(evidence, 'recovery-result.json', result_record)
    try:
        fixture_holder = []
        try:
            fixture_root, fixture_result = start_fixture(evidence, fixture_holder)
        except Exception:
            if fixture_holder:
                fixture_root = fixture_holder[0]
            raise
        events.append({'event': 'fixture_started', 'at': now()})
        hub = inspect_fixture_hub(fixture_root, fixture_result)
        hub_id_hash_before = hub_identity(hub['hub_url'])

        proxy_name, proxy_label, reverse_port = start_proxy(
            evidence, state['run_id'], fixture_root, fixture_result, helper, scenario, proxy_ownership)
        driver.run(evidence, f'{scenario}-adb-reverse',
            driver.adb(state) + ['reverse', f'tcp:{reverse_port}', f'tcp:{reverse_port}'])

        driver.run(evidence, f'{scenario}-pm-clear-before',
            driver.adb(state) + ['shell', 'pm', 'clear', PACKAGE])
        run_test(evidence, state, f'{scenario}-prepare-device',
                 'ai.cicada.client.hub.MonitorHubInteropTest#prepareDevice')
        public_device = driver.run(evidence, f'{scenario}-export-device-public',
            driver.adb(state) + ['exec-out', 'run-as', PACKAGE, 'cat',
                driver.remote(state) + '/device-public.json'])
        driver.save(evidence / 'device-public.private.json', public_device)

        cfg = fixture.config(fixture_root, fixture_result, evidence, reverse_port)
        fixture.sign_device(fixture_root, fixture_result, evidence, cfg)
        fixture.config(fixture_root, fixture_result, evidence, reverse_port)
        # config() also writes the fixture's Node pairing code for the broader
        # topology flow. This recovery-only test never pairs a Node or stages it.
        (fixture_root / 'monitor-node-codes.json').unlink(missing_ok=True)
        driver.stage(evidence, state, fixture_root / 'monitor-android-fixture.json', 'fixture.json')
        run_test(evidence, state, f'{scenario}-enroll-capabilities',
                 'ai.cicada.client.hub.MonitorHubInteropTest#enrollOwnerAndCheckCapabilities')

        capture = run_test(evidence, state, f'{scenario}-capture-prepare', CAPTURE_TEST, scenario)
        capture_markers = status_markers(capture)
        verify_capture_markers(capture_markers)
        logs = subprocess.check_output(['docker', 'logs', proxy_name], text=True)
        fault_line = f'FAULT_READY scenario={scenario} operation=monitor.broadcast_prepare'
        fault_count = len(re.findall(r'(?m)^' + re.escape(fault_line) + r'$', logs))
        ready_line = f'READY listen={reverse_port} scenario={scenario} operation=monitor.broadcast_prepare'
        ready_count = len(re.findall(r'(?m)^' + re.escape(ready_line) + r'$', logs))
        if fault_count != 1 or ready_count != 1:
            raise RuntimeError('fault proxy did not report FAULT_READY for the selected Prepare')
        driver.save(evidence / 'proxy-fault.private.log', logs.encode())
        fault_ready_at = now()
        events.append({'event': 'prepare_fault_ready', 'at': fault_ready_at,
                       'before_restart_at': fault_ready_at, 'fault_ready_occurrences': fault_count,
                       'operation': 'monitor.broadcast_prepare'})

        restart_record = {'performed': False}
        if scenario == 'uncertain':
            before = inspect_fixture_hub(fixture_root, fixture_result)
            if before['id'] != hub['id'] or before['image'] != HUB_IMAGE or before['state_source'] != hub['state_source']:
                raise ValueError('Hub container/image/state mount changed before uncertain recovery')
            restart = record_command(evidence, f'{scenario}-hub-restart',
                                     ['docker', 'restart', '--time', '10', before['name']], timeout=45)
            if restart.returncode != 0:
                raise RuntimeError('owned disposable Hub restart failed')
            # Docker may reassign a randomly published host port on restart.
            # Keep the Android origin fixed and retarget only the owned proxy.
            binding = record_command(evidence, f'{scenario}-hub-port-after-restart',
                                     ['docker', 'port', before['name'], '8787/tcp'])
            endpoint = binding.stdout.decode().strip()
            if binding.returncode != 0 or not re.fullmatch(r'127\.0\.0\.1:[0-9]+', endpoint):
                raise RuntimeError('restarted disposable Hub lacks its loopback port binding')
            restarted_url = 'http://' + endpoint
            deadline = time.monotonic() + 30
            post_hub_hash = None
            while time.monotonic() < deadline:
                try:
                    post_hub_hash = hub_identity(restarted_url)
                    break
                except Exception:
                    time.sleep(0.5)
            if post_hub_hash is None or post_hub_hash != hub_id_hash_before:
                raise RuntimeError('Hub did not recover with the same pinned identity')
            after = inspect_fixture_hub(fixture_root, fixture_result)
            if after['id'] != before['id'] or after['image'] != before['image'] or \
                    after['state_source'] != before['state_source']:
                raise RuntimeError('Hub container/image/state mount changed across restart')
            restart_record = {
                'performed': True, 'container_id_sha256': digest(after['id']),
                'image_id': after['image'], 'state_mount_source_sha256': digest(after['state_source']),
                'hub_id_sha256_before': hub_id_hash_before, 'hub_id_sha256_after': post_hub_hash,
                'health_revision': HUB_SOURCE, 'catalog_sha256': CATALOG,
                'upstream_port_changed': restarted_url != before['hub_url'],
            }
            if restarted_url != before['hub_url']:
                inspect_proxy(proxy_name, proxy_label, fixture_root)
                stopped = record_command(evidence, f'{scenario}-proxy-stop-before-retarget',
                                         ['docker', 'stop', '--time', '5', proxy_name], timeout=20)
                if stopped.returncode != 0:
                    raise RuntimeError('owned proxy could not stop before upstream retarget')
                deadline = time.monotonic() + 10
                while command(['docker', 'container', 'inspect', proxy_name]).returncode == 0:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('owned proxy was not removed before upstream retarget')
                    time.sleep(0.2)
                routed_result = json.loads(json.dumps(fixture_result))
                routed_result['hub']['url'] = restarted_url
                proxy_name, proxy_label, _ = start_proxy(
                    evidence, state['run_id'], fixture_root, routed_result, helper,
                    scenario, proxy_ownership, port=reverse_port)
                restart_record['android_origin_unchanged'] = True
                events.append({'event': 'owned_proxy_retargeted_same_android_origin', 'at': now()})
            events.append({'event': 'hub_restarted_and_identity_reconciled', 'at': now()})

        recovered = run_test(evidence, state, f'{scenario}-recover', RECOVERY_TESTS[scenario], scenario)
        recovery_markers = status_markers(recovered)
        verify_recovery_markers(recovery_markers, scenario)
        events.append({'event': 'recovery_assertions_passed', 'at': now()})
        save(evidence, 'recovery-markers.json', {
            'capture': capture_markers, 'recovery': recovery_markers,
            'sequence_chronology': [
                {'stage': 'captured encrypted Prepare',
                 'request_sequence': int(capture_markers['monitor_prepare_fault_request_sequence']),
                 'expected_response_sequence': int(capture_markers['monitor_prepare_fault_expected_response_sequence'])},
                {'stage': 'fault proxy closed original response'},
                *([{'stage': 'same Hub restarted with state volume preserved'}] if scenario == 'uncertain' else []),
                {'stage': 'read-only recovery result', 'outcome': recovery_markers[f'monitor_prepare_recovery_{scenario}']},
            ],
        })
        result_record.update({
            'result': 'PASS', 'helper_sha256': helper_hash, 'proxy_sha256': proxy_hash,
            'proxy_image_id': PROXY_IMAGE, 'hub_image_id': HUB_IMAGE,
            'hub_source_revision': HUB_SOURCE, 'catalog_sha256': CATALOG,
            'runner_commit': runner_commit,
            'android_artifacts': json.loads((root / 'android-artifacts.json').read_text()),
            'hub_container_id_sha256': digest(hub['id']),
            'hub_state_mount_source_sha256': digest(hub['state_source']),
            'hub_id_sha256': hub_id_hash_before, 'restart': restart_record,
            'captured_at': now(),
        })
    except Exception as error:
        primary_error = error
        result_record.update({'result': 'FAIL', 'failure_type': type(error).__name__, 'captured_at': now()})
        save(evidence, 'failure.private.log', str(error).encode())
    finally:
        cleanup_errors = []
        proxy_name = proxy_ownership.get('name')
        proxy_label = proxy_ownership.get('label')
        if proxy_name:
            try:
                inspect_proxy(proxy_name, proxy_label, fixture_root)
                try:
                    logs = subprocess.check_output(['docker', 'logs', proxy_name], text=True)
                    driver.save(evidence / 'proxy-complete.private.log', logs.encode())
                except subprocess.CalledProcessError:
                    pass
                stop = record_command(evidence, f'{scenario}-proxy-stop',
                                      ['docker', 'stop', '--time', '5', proxy_name], timeout=20)
                if stop.returncode != 0:
                    raise RuntimeError('owned recovery proxy stop failed')
                result_record['proxy_removed'] = True
            except Exception:
                cleanup_errors.append('proxy_cleanup_blocked')
        if reverse_port:
            try:
                driver.run(evidence, f'{scenario}-adb-reverse-remove',
                    driver.adb(state) + ['reverse', '--remove', f'tcp:{reverse_port}'])
                result_record['adb_reverse_removed'] = True
            except Exception:
                cleanup_errors.append('adb_reverse_cleanup_failed')
        try:
            driver.run(evidence, f'{scenario}-pm-clear-after',
                driver.adb(state) + ['shell', 'pm', 'clear', PACKAGE])
            result_record['android_private_state_cleared'] = True
        except Exception:
            cleanup_errors.append('android_state_cleanup_failed')
        if fixture_root:
            try:
                fixture.checked_fixture(fixture_root)
                stop = record_command(evidence, f'{scenario}-fixture-stop',
                                      [str(CORE_FIXTURE), 'stop', str(fixture_root)], timeout=60)
                if stop.returncode != 0:
                    raise RuntimeError('owned core fixture stop failed')
                result_record['fixture_and_synthetic_keys_removed'] = True
            except Exception:
                cleanup_errors.append('fixture_cleanup_blocked')
        result_record['cleanup_errors'] = cleanup_errors
        if cleanup_errors and primary_error is None:
            primary_error = RuntimeError('owned scenario cleanup did not fully complete')
        if primary_error is not None:
            result_record['result'] = 'FAIL'
        save(evidence, 'recovery-result.json', result_record)
    if primary_error:
        raise RuntimeError('scenario failed or cleanup was blocked; inspect its restricted evidence') from None
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    parser.add_argument('scenario', choices=tuple(RECOVERY_TESTS))
    parser.add_argument('--fixture-binary', required=True)
    args = parser.parse_args()
    evidence = driver.private_evidence(args.evidence)
    result_dir = run_scenario(evidence, args.fixture_binary, args.scenario)
    print(json.dumps({'result': 'PASS', 'scenario': args.scenario,
                      'evidence': str(result_dir)}, sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception:
        print('FAIL: recovery scenario stopped; inspect restricted evidence and owned-resource cleanup status',
              file=sys.stderr)
        raise SystemExit(1)
