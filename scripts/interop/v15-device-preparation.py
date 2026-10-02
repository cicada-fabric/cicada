#!/usr/bin/env python3
"""Prepare independent public device identities in the owned offline v1.5 emulator.

This runner uses the real React Native profile UI to create and select profiles,
then invokes the Android public-identity selector. It never attaches a Hub or
reads device private-key storage.
"""

import argparse
import base64
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

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / 'scripts/interop/v15-android-deterministic.py'
spec = importlib.util.spec_from_file_location('v15_deterministic', RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
driver = runner.driver

DEVICE_PLAN = (
    ('base', 'OfflineQA', 'v15-base-final-bd79ff9', 'client-v15-base-final-bd79ff9'),
    ('processing', 'V15ProcessingV15Processing', 'v15-processing-final-bd79ff9', 'client-v15-processing-final-bd79ff9'),
    ('uncertain', 'V15Uncertain', 'v15-uncertain-final-bd79ff9', 'client-v15-uncertain-final-bd79ff9'),
    ('legacy', 'V15Legacy', 'v15-legacy-final-bd79ff9', 'client-v15-legacy-final-bd79ff9'),
)
IDENTITY_DOMAIN = b'cicada/client/device-public-key/v1\0'


class ProfileNotFound(RuntimeError):
    pass


def bounds(node):
    match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds', ''))
    if not match:
        raise RuntimeError('Android UI node has no bounded screen position')
    return tuple(map(int, match.groups()))


def save_layout(evidence, state, label):
    driver.run(evidence, 'device-ui-dump-' + label, driver.adb(state) + ['shell', 'uiautomator',
        'dump', '/sdcard/cicada-v15-device-layout.xml'])
    raw = driver.run(evidence, 'device-ui-read-' + label, driver.adb(state) + ['exec-out',
        'cat', '/sdcard/cicada-v15-device-layout.xml'])
    driver.save(evidence / ('device-ui-' + label + '.private.xml'), raw)
    return ET.fromstring(raw)


def labels(root):
    return [node.get('text', '') for node in root.iter('node')]


def nodes(root, attribute, value):
    return [node for node in root.iter('node') if node.get(attribute) == value]


def tap_node(evidence, state, label, node):
    left, top, right, bottom = bounds(node)
    if right <= left or bottom <= top:
        raise RuntimeError('Android UI node is not visible')
    driver.run(evidence, 'device-ui-tap-' + label, driver.adb(state) + ['shell', 'input', 'tap',
        str((left + right) // 2), str((top + bottom) // 2)])


def swipe_up(evidence, state, label):
    output = driver.run(evidence, 'device-ui-size-' + label,
        driver.adb(state) + ['shell', 'wm', 'size']).decode(errors='replace')
    match = re.search(r'(?:Physical|Override) size: (\d+)x(\d+)', output)
    if not match:
        raise RuntimeError('Could not bound the owned emulator display')
    width, height = map(int, match.groups())
    driver.run(evidence, 'device-ui-scroll-' + label, driver.adb(state) + ['shell', 'input', 'swipe',
        str(width // 2), str(height * 4 // 5), str(width // 2), str(height // 3), '350'])


def swipe_down(evidence, state, label):
    output = driver.run(evidence, 'device-ui-size-' + label,
        driver.adb(state) + ['shell', 'wm', 'size']).decode(errors='replace')
    match = re.search(r'(?:Physical|Override) size: (\d+)x(\d+)', output)
    if not match:
        raise RuntimeError('Could not bound the owned emulator display')
    width, height = map(int, match.groups())
    driver.run(evidence, 'device-ui-scroll-down-' + label, driver.adb(state) + ['shell', 'input', 'swipe',
        str(width // 2), str(height // 3), str(width // 2), str(height * 4 // 5), '350'])


def find_visible(evidence, state, label, attribute, value, *, scroll=False):
    for attempt in range(10):
        root = save_layout(evidence, state, label + '-' + str(attempt))
        found = []
        for node in nodes(root, attribute, value):
            try:
                left, top, right, bottom = bounds(node)
            except RuntimeError:
                continue
            if right > left and bottom > top:
                found.append(node)
        if len(found) == 1:
            return root, found[0]
        if len(found) > 1:
            raise RuntimeError('Android UI selector is ambiguous: ' + value)
        if not scroll:
            time.sleep(0.4)
        else:
            swipe_up(evidence, state, label + '-' + str(attempt))
            time.sleep(0.3)
    raise RuntimeError('Android UI selector was not visible: ' + value)


def nearest_card_action(root, profile_label, action_label):
    profile = nodes(root, 'text', profile_label)
    actions = nodes(root, 'text', action_label)
    if len(profile) != 1 or not actions:
        raise RuntimeError('Target profile or action is missing from the Hub connection list')
    _, profile_top, _, profile_bottom = bounds(profile[0])
    profile_y = (profile_top + profile_bottom) // 2
    candidates = []
    for node in actions:
        _, top, _, bottom = bounds(node)
        center = (top + bottom) // 2
        if center >= profile_y:
            candidates.append((center - profile_y, node))
    if not candidates:
        raise RuntimeError('The selected profile has no visible switch action')
    return min(candidates, key=lambda item: item[0])[1]


def ensure_connection_modal(evidence, state, label):
    for attempt in range(8):
        root = save_layout(evidence, state, label + '-' + str(attempt))
        if nodes(root, 'content-desc', '新 Hub 配置名称'):
            return root
        if 'Hub 连接' in labels(root):
            swipe_up(evidence, state, label + '-scroll-' + str(attempt))
            time.sleep(0.3)
            continue
        buttons = nodes(root, 'content-desc', '管理 Hub 连接')
        if buttons:
            tap_node(evidence, state, label + '-open', buttons[0])
            time.sleep(0.6)
    raise RuntimeError('The Hub connection manager did not open or its profile list did not reach the create form')


def find_profile(evidence, state, profile_label, label):
    for attempt in range(12):
        root = save_layout(evidence, state, label + '-' + str(attempt))
        matches = nodes(root, 'text', profile_label) + nodes(root, 'text', profile_label + ' · 当前')
        if len(matches) == 1:
            return root, matches[0]
        if attempt < 6:
            swipe_down(evidence, state, label + '-' + str(attempt))
        else:
            swipe_up(evidence, state, label + '-' + str(attempt))
        time.sleep(0.25)
    raise ProfileNotFound('The target profile was not visible in the Hub connection list')


def select_profile(evidence, state, profile_label):
    root = ensure_connection_modal(evidence, state, 'profile-list-' + profile_label)
    root, profile_node = find_profile(evidence, state, profile_label, 'profile-' + profile_label)
    if profile_node.get('text') == profile_label + ' · 当前':
        return
    tap_node(evidence, state, 'select-' + profile_label,
        nearest_card_action(root, profile_label, '选择此 Hub'))
    for attempt in range(12):
        root = save_layout(evidence, state, 'switch-review-' + profile_label + '-' + str(attempt))
        if any('切换到 ' + profile_label in value for value in labels(root)):
            action = nodes(root, 'text', '切换')
            if len(action) != 1:
                raise RuntimeError('Profile switch confirmation was missing or ambiguous')
            tap_node(evidence, state, 'confirm-switch-' + profile_label, action[0])
            break
        time.sleep(0.3)
    else:
        raise RuntimeError('The explicit profile switch confirmation did not appear')
    expected = profile_label + ' · 未固定身份'
    for attempt in range(16):
        root = save_layout(evidence, state, 'switched-' + profile_label + '-' + str(attempt))
        if expected in labels(root):
            return
        time.sleep(0.4)
    raise RuntimeError('New profile did not remain unpinned after explicit switch')


def create_profile(evidence, state, profile_label):
    root = ensure_connection_modal(evidence, state, 'create-list-' + profile_label)
    try:
        root, existing_node = find_profile(evidence, state, profile_label, 'create-existing-' + profile_label)
    except ProfileNotFound:
        existing_node = None
    if existing_node is not None:
        if existing_node.get('text') == profile_label + ' · 当前':
            return
        select_profile(evidence, state, profile_label)
        return
    root, field = find_visible(evidence, state, 'new-field-' + profile_label,
        'content-desc', '新 Hub 配置名称', scroll=True)
    tap_node(evidence, state, 'focus-' + profile_label, field)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', profile_label):
        raise ValueError('UI profile preparation requires a bounded ASCII label')
    # Batched ADB key events can outpace a controlled React Native TextInput
    # on the software emulator. Type through the same real UI with time for
    # each change to settle, and verify the whole label before creating it.
    for index, character in enumerate(profile_label):
        driver.run(evidence, 'device-ui-type-' + profile_label + '-' + str(index),
            driver.adb(state) + ['shell', 'input', 'text', character])
        time.sleep(0.4)
    typed = save_layout(evidence, state, 'typed-' + profile_label)
    fields = nodes(typed, 'content-desc', '新 Hub 配置名称')
    if len(fields) != 1 or fields[0].get('text') != profile_label or \
            'Hub 连接' not in labels(typed):
        raise RuntimeError('Profile label did not remain in the visible connection form')
    # A hardware-keyboard emulator can leave the IME hidden. BACK in that
    # state dismisses the profile modal or exits the app instead of the IME.
    ime_command = driver.adb(state) + ['shell', 'dumpsys', 'input_method']
    ime_state = subprocess.check_output(ime_command, timeout=15).decode(errors='replace')
    shown = re.findall(r'\bmInputShown=(true|false)\b', ime_state)
    keyboard_shown = bool(shown) and all(value == 'true' for value in shown)
    driver.save(evidence / ('device-ui-keyboard-' + profile_label + '.json'), {
        'command': ime_command, 'exit_code': 0, 'keyboard_shown': keyboard_shown,
        'raw_ime_state_persisted': False,
    })
    if keyboard_shown:
        driver.run(evidence, 'device-ui-hide-keyboard-' + profile_label,
            driver.adb(state) + ['shell', 'input', 'keyevent', '4'])
    root, button = find_visible(evidence, state, 'create-button-' + profile_label,
        'text', '创建连接', scroll=True)
    tap_node(evidence, state, 'create-' + profile_label, button)
    root, _ = find_visible(evidence, state, 'created-' + profile_label,
        'text', profile_label, scroll=True)
    current_labels = labels(root)
    if profile_label + ' · 当前' in current_labels or '尚未固定 Hub 身份' not in current_labels or \
            not any('设备未登记' in value and '未选择 Network' in value for value in current_labels):
        raise RuntimeError('New profile inherited trust or was activated without consent')
    select_profile(evidence, state, profile_label)


def prepare_identity(evidence, state, tag, run_id, device_id):
    manifest_path = evidence / ('device-public-' + tag + '.private.json')
    test_result_path = evidence / ('prepare-device-' + tag + '.json')
    if manifest_path.is_file() and test_result_path.is_file():
        result = json.loads(test_result_path.read_text())
        if result.get('junit') != 'OK (1 test)' or result.get('result') != 'PASS':
            raise RuntimeError('Existing public identity evidence is not a complete PASS')
        raw = manifest_path.read_bytes()
    else:
        command = driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id', run_id,
            '-e', 'device_id', device_id, '-e', 'class',
            'ai.cicada.client.hub.ClientHubV15InteropTest#prepareDevice',
            driver.PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner']
        driver.run(evidence, 'prepare-device-' + tag, command, junit=True)
        result = json.loads(test_result_path.read_text())
        if result.get('junit') != 'OK (1 test)':
            raise RuntimeError('The Android public identity selector did not run exactly once')
        relative = 'no_backup/network-v15/' + run_id + '/device-public.json'
        raw = driver.run(evidence, 'export-device-' + tag,
            driver.adb(state) + ['exec-out', 'run-as', driver.PACKAGE, 'cat', relative])
        driver.save(manifest_path, raw)
    manifest = json.loads(raw)
    identity = manifest.get('device_public_identity')
    if manifest.get('schema') != 'cicada.client-network-device.v1' or \
            manifest.get('device_id') != device_id or not isinstance(identity, dict) or \
            sorted(identity) != ['id', 'kem_public', 'signing_public']:
        raise RuntimeError('Android exported an invalid public device manifest')
    kem = base64.b64decode(identity['kem_public'], validate=True)
    signing = base64.b64decode(identity['signing_public'], validate=True)
    if len(kem) != 1184 or len(signing) != 1952:
        raise RuntimeError('Android exported unexpected post-quantum public key sizes')
    identity_id = identity['id']
    derived_id = 'pq1-' + hashlib.sha256(kem + signing).digest()[:16].hex()
    if identity_id != derived_id:
        raise RuntimeError('Public identity ID did not match its public key material')
    canonical = json.dumps({'id': identity_id, 'kem_public': identity['kem_public'],
        'signing_public': identity['signing_public']}, ensure_ascii=False,
        separators=(',', ':')).encode()
    fingerprint = hashlib.sha256(IDENTITY_DOMAIN + canonical).hexdigest()
    profile_id = manifest.get('profile_id')
    if not isinstance(profile_id, str) or not re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', profile_id):
        raise RuntimeError('Android public manifest has no independent profile ID')
    summary = {'schema': 'cicada.client-v15-public-device-evidence.v1', 'result': 'PASS',
        'profile_id_sha256': hashlib.sha256(profile_id.encode()).hexdigest(),
        'device_id_sha256': hashlib.sha256(device_id.encode()).hexdigest(),
        'device_key_id_sha256': hashlib.sha256(identity_id.encode()).hexdigest(),
        'device_key_fingerprint': 'sha256:' + fingerprint,
        'public_manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'public_manifest_path': str(manifest_path), 'run_id': run_id,
        'enrolled': False, 'hub_network_attached': False}
    driver.save(evidence / ('device-public-' + tag + '.redacted.json'), summary)
    return {'tag': tag, 'run_id': run_id, 'device_id': device_id, 'profile_id': profile_id,
        'device_key_id': identity_id, 'full_fingerprint': 'sha256:' + fingerprint,
        'manifest': str(manifest_path), 'manifest_sha256': summary['public_manifest_sha256']}


def prepare_devices(args):
    evidence = driver.private_evidence(args.evidence)
    state = runner.owned_state(evidence)
    if state['network'] != 'none' or (evidence / 'disposable-network-attachment.redacted.json').exists():
        raise ValueError('device preparation requires the owned offline emulator')
    artifacts = json.loads((evidence / 'android-artifacts.json').read_text())
    deterministic = json.loads((evidence / 'deterministic-summary.redacted.json').read_text())
    ui = json.loads((evidence / 'ui-smoke-summary.redacted.json').read_text())
    if deterministic.get('result') != 'PASS' or deterministic.get('tests') != 54 or \
            artifacts.get('app_sha256') != args.app_sha256 or artifacts.get('test_sha256') != args.test_sha256 or \
            ui.get('result') != 'PASS' or ui.get('scope') != 'fresh offline React Native product UI only':
        raise ValueError('final APK, 54-test matrix and offline UI prerequisites must match')
    if subprocess_state_network(state) != 'none':
        raise ValueError('refusing to prepare public identities after any Hub bridge attachment')
    driver.run(evidence, 'device-product-launch', driver.adb(state) + ['shell', 'am', 'start', '-W', '-n',
        driver.PACKAGE + '/com.cicadaclient.MainActivity'])
    time.sleep(0.8)
    output = []
    for index, (tag, profile_label, run_id, device_id) in enumerate(DEVICE_PLAN):
        if index == 0:
            ensure_connection_modal(evidence, state, 'base-profile-list')
        else:
            create_profile(evidence, state, profile_label)
        output.append(prepare_identity(evidence, state, tag, run_id, device_id))
        if index + 1 < len(DEVICE_PLAN):
            driver.run(evidence, 'device-product-relaunch-' + tag,
                driver.adb(state) + ['shell', 'am', 'start', '-W', '-n',
                    driver.PACKAGE + '/com.cicadaclient.MainActivity'])
            time.sleep(0.8)
    driver.run(evidence, 'device-product-final-relaunch',
        driver.adb(state) + ['shell', 'am', 'start', '-W', '-n',
            driver.PACKAGE + '/com.cicadaclient.MainActivity'])
    time.sleep(0.8)
    ensure_connection_modal(evidence, state, 'restore-base-profile-list')
    select_profile(evidence, state, 'OfflineQA')
    driver.run(evidence, 'device-product-force-stop-after-preparation',
        driver.adb(state) + ['shell', 'am', 'force-stop', driver.PACKAGE])
    for left in range(len(output)):
        for right in range(left + 1, len(output)):
            if output[left]['profile_id'] == output[right]['profile_id'] or \
                    output[left]['device_key_id'] == output[right]['device_key_id'] or \
                    output[left]['full_fingerprint'] == output[right]['full_fingerprint']:
                raise RuntimeError('independent device preparation reused a profile or key')
    public_index = [{'tag': item['tag'], 'run_id': item['run_id'],
        'device_id': item['device_id'], 'profile_id': item['profile_id'],
        'device_key_id': item['device_key_id'], 'full_fingerprint': item['full_fingerprint'],
        'manifest': item['manifest'], 'manifest_sha256': item['manifest_sha256']} for item in output]
    driver.save(evidence / 'public-device-index.private.json', {'schema': 'cicada.client-v15-public-device-index.v1',
        'result': 'PASS', 'hub_network_attached': False, 'devices': public_index})
    driver.save(evidence / 'public-device-preparation.redacted.json', {'schema': 'cicada.client-v15-public-device-index.v1',
        'result': 'PASS', 'count': len(output), 'all_profiles_independent': True,
        'all_keys_distinct': True, 'hub_network_attached': False,
        'devices': [json.loads((evidence / ('device-public-' + item['tag'] + '.redacted.json')).read_text())
                    for item in output]})
    print(json.dumps({'result': 'PASS', 'devices': output}, separators=(',', ':')))


def subprocess_state_network(state):
    inspected = driver.run(Path(state['evidence']), 'network-state-check',
        ['docker', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', state['container']]).decode().strip()
    return inspected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    parser.add_argument('--app-sha256', required=True)
    parser.add_argument('--test-sha256', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', args.app_sha256) or not re.fullmatch(r'[0-9a-f]{64}', args.test_sha256):
        parser.error('expected full lowercase APK SHA-256 values')
    prepare_devices(args)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
