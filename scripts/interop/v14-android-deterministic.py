#!/usr/bin/env python3
"""Run local Kotlin vectors and profile regressions in one owned, offline emulator.

No Hub is started or contacted. APK hashes are mandatory before a container can
start. Commands, exits and private logs use the existing instrumentation driver.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('monitor_android', Path(__file__).with_name('monitor-android.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

SCHEMA = 'cicada.client-v14-deterministic.v1'
LABEL = 'org.cicada.client-v14-deterministic'
MATRIX = (
    ('hub-profiles', 'HubProfileStoreTest', 10),
    ('network-key-vectors', 'NetworkKeyConsentVectorTest', 6),
    ('network-session-guards', 'NetworkSessionGuardTest', 8),
    ('client-wire-vectors', 'ClientWirePublicVectorTest', 5),
    ('endpoint-attestation-vectors', 'EndpointAttestationVectorTest', 4),
    ('monitor-broadcast-vectors', 'MonitorBroadcastVectorTest', 6),
    ('recovery-locks', 'ClientHubRecoveryLockTest', 6),
)


def source_fingerprint():
    output = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=driver.REPO)
    selected = sorted({path for path in output.split(b'\0') if path and
        (path.startswith((b'android/', b'src/')) or path in {
            b'App.tsx', b'index.js', b'package.json', b'package-lock.json', b'babel.config.js',
            b'metro.config.js', b'tsconfig.json', b'react-native.config.js'})})
    digest = hashlib.sha256()
    count = 0
    for raw in selected:
        path = driver.REPO / os.fsdecode(raw)
        if path.is_file() and not path.is_symlink():
            digest.update(raw + b'\0' + hashlib.sha256(path.read_bytes()).digest())
            count += 1
    return {'sha256': digest.hexdigest(), 'files': count, 'encoding': 'sorted path NUL SHA256(file) bytes'}


def start(evidence, args):
    run_id = evidence.parent.name
    if not re.fullmatch(r'v14-deterministic-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('unsafe v1.4 evidence run name')
    if (evidence / 'android-driver.json').exists():
        raise ValueError('this evidence directory already owns an emulator')
    artifacts = {'client_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=driver.REPO, text=True).strip(),
        'observed_checkout_source_fingerprint': source_fingerprint(),
        'source_observation': 'checkout observed at emulator start; APK hashes identify installed binaries',
        'physical_android': 'NOT_RUN', 'public_https': 'NOT_RUN'}
    for name in ('app', 'test'):
        path, expected = Path(getattr(args, name + '_apk')), getattr(args, name + '_sha256')
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('expected a regular APK and full lowercase SHA-256')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(name + ' APK hash mismatch')
        driver.save(evidence / ('installed-' + name + '.private.apk'), data)
        artifacts[name + '_sha256'] = expected
    root = subprocess.check_output(['docker', 'info', '--format', '{{.DockerRootDir}}'], text=True).strip()
    if root != '/gpu1-share/data/docker-root':
        raise ValueError('unexpected Docker data root')
    actual = subprocess.check_output(['docker', 'image', 'inspect', driver.IMAGE, '--format', '{{.Id}}'], text=True).strip()
    if actual != driver.IMAGE:
        raise ValueError('emulator image mismatch')
    state = {'schema': SCHEMA, 'run_id': run_id, 'container': 'cicada-' + run_id,
        'image_id': driver.IMAGE, 'emulator_port': 5640, 'adb_port': 5070,
        'evidence': str(evidence), 'network': 'none'}
    driver.save(evidence / 'android-artifacts.json', artifacts)
    driver.save(evidence / 'android-driver.json', state)
    driver.run(evidence, 'emulator-start', ['docker', 'run', '--rm', '-d', '--user', 'root',
        '--name', state['container'], '--label', LABEL + '=' + run_id, '--device', '/dev/kvm',
        '--network', 'none', '-e', 'CICADA_TWO_OWNER_EMULATOR_PORT=5640',
        '-e', 'ANDROID_ADB_SERVER_PORT=5070', '-e', f'CICADA_EVIDENCE_OWNER={os.getuid()}:{os.getgid()}',
        '-v', f'{driver.REPO}:/workspace:ro', '-v', f'{evidence}:/out',
        '-v', f'{evidence}/installed-app.private.apk:/tmp/cicada-v14-app.apk:ro',
        '-v', f'{evidence}/installed-test.private.apk:/tmp/cicada-v14-test.apk:ro',
        driver.IMAGE, 'bash', '/workspace/scripts/interop/two-owner-emulator.sh'])
    return {'result': 'BOOTING', 'evidence': str(evidence)}


def owned_state(evidence):
    state = json.loads((evidence / 'android-driver.json').read_text())
    if state != {'schema': SCHEMA, 'run_id': evidence.parent.name,
        'container': 'cicada-' + evidence.parent.name, 'image_id': driver.IMAGE,
        'emulator_port': 5640, 'adb_port': 5070, 'evidence': str(evidence), 'network': 'none'}:
        raise ValueError('v1.4 emulator ownership marker mismatch')
    actual = subprocess.check_output(['docker', 'inspect', '--format',
        '{{.Image}} {{index .Config.Labels "' + LABEL + '"}} {{.HostConfig.NetworkMode}}',
        state['container']], text=True).strip().split()
    if actual != [driver.IMAGE, state['run_id'], 'none']:
        raise ValueError('refusing to operate a foreign emulator')
    attached = json.loads(subprocess.check_output(['docker', 'inspect', '--format',
        '{{json .NetworkSettings.Networks}}', state['container']], text=True))
    attachment_path = evidence / 'disposable-network-attachment.redacted.json'
    if attachment_path.exists():
        attachment = json.loads(attachment_path.read_text())
        if attachment.get('schema') != 'cicada.client-v14-disposable-network.v1' or \
                attachment.get('container') != state['container'] or attachment.get('result') != 'PASS' or \
                set(attached) != {attachment['network_name']} or \
                attached[attachment['network_name']]['NetworkID'] != attachment['network_id']:
            raise ValueError('disposable fixture network ownership mismatch')
    elif set(attached) != {'none'}:
        raise ValueError('offline emulator acquired an unapproved network')
    return state


def install_and_test(evidence, state):
    deadline = time.monotonic() + 240
    ready = evidence / 'emulator-ready.json'
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(1)
    if not ready.exists():
        raise RuntimeError('owned emulator boot did not become ready')
    marker = json.loads(ready.read_text())
    if marker != {'result': 'READY', 'serial': 'emulator-5640', 'adb_port': 5070}:
        raise ValueError('owned emulator readiness marker mismatch')
    runtime = {'platform': 'Android emulator', 'emulator_image_id': driver.IMAGE}
    for field, prop in (('api_level', 'ro.build.version.sdk'), ('android_release', 'ro.build.version.release'),
                        ('abi', 'ro.product.cpu.abi'), ('emulator', 'ro.kernel.qemu')):
        runtime[field] = driver.run(evidence, 'runtime-' + field,
            driver.adb(state) + ['shell', 'getprop', prop]).decode().strip()
    driver.save(evidence / 'android-runtime.redacted.json', runtime)
    artifacts = json.loads((evidence / 'android-artifacts.json').read_text())
    for name in ('app', 'test'):
        source = evidence / ('installed-' + name + '.private.apk')
        if hashlib.sha256(source.read_bytes()).hexdigest() != artifacts[name + '_sha256']:
            raise ValueError('archived APK hash mismatch')
        driver.run(evidence, 'install-' + name, driver.adb(state) + ['install', '-r', '/tmp/cicada-v14-' + name + '.apk'])
    results = []
    for label, test, count in MATRIX:
        driver.run(evidence, label, driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e',
            'class', 'ai.cicada.client.hub.' + test,
            driver.PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner'], junit=True)
        result = json.loads((evidence / (label + '.json')).read_text())
        if result['junit'] != f'OK ({count} tests)':
            result.update(result='FAIL', driver_exit_code=1, expected_test_count=count)
            driver.save(evidence / (label + '.json'), result)
            raise RuntimeError(label + ' did not run the full expected test count')
        results.append({'selector': 'ai.cicada.client.hub.' + test, 'tests': count, 'result': 'PASS',
            'adb_exit_code': result['exit_code'], 'driver_exit_code': result['driver_exit_code'],
            'evidence': label + '.json'})
    summary = {'result': 'PASS', 'tests': sum(row['tests'] for row in results), 'selectors': results,
        'android_artifacts': artifacts, 'hub_runtime': 'NOT_RUN', 'physical_android': 'NOT_RUN',
        'public_https': 'NOT_RUN', 'network': 'none'}
    driver.save(evidence / 'deterministic-summary.redacted.json', summary)
    return {'result': 'PASS', 'tests': summary['tests'], 'evidence': str(evidence)}


def ui_smoke(evidence, state):
    """Review the actual offline product UI; native synthetic state tests remain separate."""
    driver.run(evidence, 'ui-launch', driver.adb(state) + ['shell', 'am', 'start', '-W', '-n',
        driver.PACKAGE + '/com.cicadaclient.MainActivity'])
    resolved_evidence = {}

    def layout(label):
        driver.run(evidence, 'ui-dump-' + label, driver.adb(state) + ['shell', 'uiautomator',
            'dump', '/sdcard/cicada-v14-layout.xml'])
        raw = driver.run(evidence, 'ui-read-' + label, driver.adb(state) + ['exec-out',
            'cat', '/sdcard/cicada-v14-layout.xml'])
        driver.save(evidence / ('ui-' + label + '.private.xml'), raw)
        return ET.fromstring(raw)

    def nodes(root):
        return list(root.iter('node'))

    def labels(root):
        return [node.get('text', '') for node in nodes(root)]

    def find(root, value, attribute='text'):
        matches = [node for node in nodes(root) if node.get(attribute) == value]
        if len(matches) != 1:
            raise RuntimeError('UI selector was missing or ambiguous: ' + value)
        return matches[0]

    def tap(label, node):
        bounds = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds', ''))
        if not bounds:
            raise ValueError('UI bounds were unavailable')
        x1, y1, x2, y2 = map(int, bounds.groups())
        if x2 <= x1 or y2 <= y1:
            raise ValueError('UI element was not visible')
        driver.run(evidence, 'ui-tap-' + label, driver.adb(state) + ['shell', 'input', 'tap',
            str((x1 + x2) // 2), str((y1 + y2) // 2)])

    def wait_for(label, value, attribute='text'):
        for attempt in range(12):
            root = layout(label + '-' + str(attempt))
            if any(node.get(attribute) == value for node in nodes(root)):
                resolved_evidence[label] = 'ui-' + label + '-' + str(attempt) + '.private.xml'
                return root
            time.sleep(0.5)
        raise RuntimeError('UI did not reach expected screen: ' + value)

    home = wait_for('bootstrap', '管理 Hub 连接', 'content-desc')
    if '未连接' not in labels(home) or not any('未固定身份' in text for text in labels(home)):
        raise RuntimeError('Fresh product UI did not show an unconnected, unpinned Hub')
    tap('connections', find(home, '管理 Hub 连接', 'content-desc'))
    initial = wait_for('connections', '新 Hub 配置名称', 'content-desc')
    current = [text for text in labels(initial) if text.endswith(' · 当前')]
    if len(current) != 1 or labels(initial).count('尚未固定 Hub 身份') != 1:
        raise RuntimeError('Fresh offline profile list was unexpected')
    initial_current = current[0]
    tap('new-label', find(initial, '新 Hub 配置名称', 'content-desc'))
    driver.run(evidence, 'ui-enter-label', driver.adb(state) + ['shell', 'input', 'text', 'OfflineQA'])
    driver.run(evidence, 'ui-hide-keyboard', driver.adb(state) + ['shell', 'input', 'keyevent', '4'])
    typed = wait_for('typed-label', 'OfflineQA')
    tap('create', find(typed, '创建连接'))
    created = wait_for('created', '选择此 Hub')
    texts = labels(created)
    if initial_current not in texts or 'OfflineQA · 当前' in texts or texts.count('尚未固定 Hub 身份') != 2 or \
            sum('设备未登记' in value and '未选择 Network' in value for value in texts) != 2:
        raise RuntimeError('Creating a profile selected it automatically or inherited enrollment/pin state')
    tap('select-new-profile', find(created, '选择此 Hub'))
    consent = wait_for('switch-review', '切换到 OfflineQA')
    if not any('每个 Hub 的密钥、授权、计数和待恢复密文保留在原配置' in text for text in labels(consent)):
        raise RuntimeError('Explicit profile switch consent was missing its isolation scope')
    tap('confirm-switch', find(consent, '切换'))
    switched = wait_for('switched', 'OfflineQA · 未固定身份')
    texts = labels(switched)
    if '未连接' not in texts or not any('OfflineQA' in text and '未固定身份' in text for text in texts):
        raise RuntimeError('New active profile reported a connected or inherited Hub identity')
    tap('review-new-profile', find(switched, '管理 Hub 连接', 'content-desc'))
    final = wait_for('final-profile', 'OfflineQA · 当前')
    if labels(final).count('尚未固定 Hub 身份') != 2:
        raise RuntimeError('Final offline profile list unexpectedly acquired Hub trust')
    summary = {'result': 'PASS', 'scope': 'fresh offline React Native product UI only',
        'checks': ['unconnected_bootstrap', 'create_does_not_activate', 'new_profile_unpinned_unenrolled',
            'explicit_switch_consent', 'switched_profile_stays_unconnected'],
        'android_artifacts': json.loads((evidence / 'android-artifacts.json').read_text()),
        'evidence': [resolved_evidence[label] for label in ('bootstrap', 'created', 'switch-review', 'final-profile')],
        'hub_runtime': 'NOT_RUN',
        'physical_android': 'NOT_RUN', 'public_https': 'NOT_RUN'}
    driver.save(evidence / 'ui-smoke-summary.redacted.json', summary)
    return {'result': 'PASS', 'scope': summary['scope'], 'evidence': str(evidence)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    commands = parser.add_subparsers(dest='action', required=True)
    prepare = commands.add_parser('start')
    for name in ('app', 'test'):
        prepare.add_argument('--' + name + '-apk', required=True)
        prepare.add_argument('--' + name + '-sha256', required=True)
    commands.add_parser('test')
    commands.add_parser('ui-smoke')
    commands.add_parser('stop')
    args = parser.parse_args()
    evidence = driver.private_evidence(args.evidence)
    if args.action == 'start':
        result = start(evidence, args)
    else:
        state = owned_state(evidence)
        if args.action == 'test':
            result = install_and_test(evidence, state)
        elif args.action == 'ui-smoke':
            result = ui_smoke(evidence, state)
        else:
            driver.run(evidence, 'emulator-stop', ['docker', 'stop', '--time', '10', state['container']])
            verification = ['docker', 'inspect', state['container'], '--format', '{{.Id}}']
            deadline = time.monotonic() + 10
            attempts = []
            while True:
                absent = subprocess.run(verification, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                removed = absent.returncode == 1 and b'no such object' in absent.stderr.lower()
                attempts.append({'exit_code': absent.returncode, 'absence_confirmed': removed})
                driver.save(evidence / 'emulator-absence-check.redacted.json', {
                    'command': verification, 'attempts': attempts,
                    'result': 'PASS' if removed else 'WAITING',
                })
                if removed:
                    break
                if absent.returncode != 0 or time.monotonic() >= deadline:
                    driver.save(evidence / 'emulator-absence-check.redacted.json', {
                        'command': verification, 'attempts': attempts, 'result': 'FAIL',
                    })
                    raise RuntimeError('owned emulator removal was not confirmed')
                time.sleep(0.2)
            result = {'result': 'PASS', 'owned_emulator_removed': True,
                'verification_command': verification, 'docker_inspect_exit_code': 1}
            driver.save(evidence / 'android-teardown.redacted.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
