#!/usr/bin/env python3
"""Exercise the real Node pairing panel on an owned v1.6 Android emulator.

The driver never calls Client RPCs itself. It types the Core-issued short code
through an in-memory Docker STDIN pipe, checks the visible candidate against
Core public pins, and confirms only through the product UI.
"""

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('v16_ui_owner', HERE / 'v16-android-deterministic.py')
v16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v16)
driver = v16.driver
REVISION = '4fb241b5e824eb752ceb85586089f44c408e1e7e'
CATALOG = '1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c'
HANDOFF_SCHEMA = 'cicada.native-monitor-pairing-handoff.v1'
ROLE_SCHEMA = 'cicada.client-v16-role-oracle.v1'
GROUPS_SCHEMA = 'cicada.client-v16-monitor-groups.v1'
UI_XML = '/data/local/tmp/cicada-node-pairing-ui.xml'

HANDOFF_FIELDS = {
    'schema', 'source_revision', 'owned_run_label', 'container', 'hub_id', 'owner_id',
    'network_id', 'node_id', 'user_code', 'instruction', 'group_input_file',
    'client_confirm_operations',
}
HANDOFF_REFRESH_FIELDS = {'request_id', 'candidate_version', 'expires_at'}
PIN_FIELDS = {
    'request_id', 'version', 'hub_id', 'node_id', 'node_key_id', 'node_key_fingerprint',
    'hub_node_control_key_id', 'hub_node_control_key_version', 'hub_node_control_fingerprint',
    'node_key_epoch', 'candidate_digest', 'state', 'expires_at', 'hub_public_fingerprint_recomputed',
    'source', 'node_container_id', 'runtime_image', 'owned_run_label',
    'client_hub_source_revision', 'node_identity_generated_by_existing_agent_not_replaced',
}
PIN_REFRESH_FIELDS = {'same_node_key_refresh', 'previous_request_id'}
FRESH_IDENTITY_FIELDS = {'new_identity_not_recovery'}
ROLE_FIELDS = {
    'schema', 'result', 'tag', 'authenticated_role', 'allowed_operations',
    'allowed_operation_count', 'expected_operation_count', 'gated_operation_count',
    'profile_id_sha256', 'device_id_sha256', 'owner_id_sha256', 'hub_id_sha256',
    'selection_generation', 'catalog_sha256', 'catalog_source_revision',
    'session_state_command', 'session_state_command_exit_code', 'session_state_bytes_read',
    'registry_command_exit_code', 'errors', 'private_state_persisted_to_evidence',
}
GROUP_FIELDS = {'schema', 'run_id', 'hub_id', 'owner_id', 'network_id', 'network_version', 'groups',
    'device_public_identity_ref'}
RFC3339 = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d))$')
CODE = re.compile(rb'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')
HEX256 = re.compile(r'^[0-9a-f]{64}$')
TOKEN = re.compile(r'^[A-Za-z0-9_.:-]{1,256}$')


class SafeFailure(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def read_private_json(path_value, limit=32 * 1024):
    path = Path(path_value)
    try:
        before = path.lstat()
    except OSError:
        raise SafeFailure('private_input_unavailable') from None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or \
            stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid() or before.st_size > limit:
        raise SafeFailure('private_input_not_bounded_owned_0600')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    raw = bytearray()
    try:
        actual = os.fstat(fd)
        if actual.st_ino != before.st_ino or actual.st_dev != before.st_dev or \
                not stat.S_ISREG(actual.st_mode) or actual.st_size != before.st_size:
            raise SafeFailure('private_input_changed_during_open')
        while len(raw) <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise SafeFailure('private_input_exceeds_size_bound')
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise SafeFailure('private_input_invalid_json') from None
    finally:
        os.close(fd)
        raw[:] = b'\0' * len(raw)


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64 or not RFC3339.fullmatch(value):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def positive_int(value):
    return type(value) is int and 1 <= value <= 2**53 - 1


def safe_token(value):
    return isinstance(value, str) and bool(TOKEN.fullmatch(value))


def load_scope(evidence, handoff_path, pins_path):
    handoff = read_private_json(handoff_path, 16 * 1024)
    if not isinstance(handoff, dict) or not HANDOFF_FIELDS <= set(handoff) <= HANDOFF_FIELDS | HANDOFF_REFRESH_FIELDS | FRESH_IDENTITY_FIELDS or \
            bool(set(handoff) & HANDOFF_REFRESH_FIELDS) != (HANDOFF_REFRESH_FIELDS <= set(handoff)) or \
            handoff.get('schema') != HANDOFF_SCHEMA or handoff.get('source_revision') != REVISION or \
            handoff.get('client_confirm_operations') != ['nodes.preview', 'nodes.confirm']:
        raise SafeFailure('Core_handoff_contract_mismatch')
    code_text = handoff.pop('user_code', None)
    if not isinstance(code_text, str):
        raise SafeFailure('Core_handoff_code_invalid')
    try:
        code = bytearray(code_text.encode('ascii'))
    except UnicodeEncodeError:
        raise SafeFailure('Core_handoff_code_invalid') from None
    del code_text
    if not CODE.fullmatch(code):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_handoff_code_invalid')

    if Path(handoff_path).resolve().parent != Path(pins_path).resolve().parent:
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_handoff_and_pins_not_same_run')
    try:
        pins = read_private_json(pins_path, 16 * 1024)
    except SafeFailure:
        code[:] = b'\0' * len(code)
        raise
    if not isinstance(pins, dict) or not PIN_FIELDS <= set(pins) <= PIN_FIELDS | PIN_REFRESH_FIELDS | FRESH_IDENTITY_FIELDS or \
            bool(set(pins) & PIN_REFRESH_FIELDS) != (PIN_REFRESH_FIELDS <= set(pins)) or \
            pins.get('client_hub_source_revision') != REVISION or pins.get('state') != 'PENDING' or \
            pins.get('hub_public_fingerprint_recomputed') is not True or \
            pins.get('node_identity_generated_by_existing_agent_not_replaced') is not True or \
            not all(safe_token(pins.get(key)) for key in ('request_id', 'hub_id', 'node_id',
                'node_key_id', 'hub_node_control_key_id', 'owned_run_label')) or \
            not all(HEX256.fullmatch(pins.get(key, '')) for key in ('node_key_fingerprint',
                'hub_node_control_fingerprint', 'candidate_digest', 'node_container_id')) or \
            not all(positive_int(pins.get(key)) for key in ('version', 'hub_node_control_key_version',
                'node_key_epoch')) or not isinstance(pins.get('runtime_image'), str) or \
            not re.fullmatch(r'sha256:[0-9a-f]{64}', pins['runtime_image']):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_public_pins_invalid')
    if ('new_identity_not_recovery' in handoff or 'new_identity_not_recovery' in pins) and (
            handoff.get('new_identity_not_recovery') is not True or pins.get('new_identity_not_recovery') is not True):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_new_identity_scope_mismatch')
    if PIN_REFRESH_FIELDS <= set(pins) and (pins.get('same_node_key_refresh') is not True or
            not safe_token(pins.get('previous_request_id')) or pins['previous_request_id'] == pins['request_id']):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_refresh_scope_invalid')
    if HANDOFF_REFRESH_FIELDS <= set(handoff) and (any(handoff.get(key) != pins.get(key)
            for key in ('request_id', 'expires_at')) or handoff.get('candidate_version') != pins.get('version')):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_refresh_handoff_mismatch')
    if any(handoff.get(key) != pins.get(key) for key in ('hub_id', 'node_id', 'owned_run_label')) or \
            handoff.get('container') != 'cicada-native-two-' + handoff.get('owned_run_label', '').removeprefix('cicada-native-two-') + '-a' or \
            handoff.get('owner_id') == handoff.get('node_id') or not all(
                safe_token(handoff.get(key)) for key in ('hub_id', 'owner_id', 'network_id', 'node_id')):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_handoff_scope_mismatch')
    expiry = timestamp(pins.get('expires_at'))
    if expiry is None or expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=25):
        code[:] = b'\0' * len(code)
        raise SafeFailure('Core_candidate_expired_or_near_expiry')

    try:
        role = read_private_json(evidence / 'role-oracle-base.redacted.json', 64 * 1024)
    except SafeFailure:
        code[:] = b'\0' * len(code)
        raise
    if not isinstance(role, dict) or set(role) != ROLE_FIELDS or role.get('schema') != ROLE_SCHEMA or \
            role.get('result') != 'PASS' or role.get('tag') != 'base' or \
            role.get('authenticated_role') not in ('manager', 'external') or \
            role.get('catalog_sha256') != CATALOG or role.get('catalog_source_revision') != REVISION or \
            role.get('owner_id_sha256') != hashlib.sha256(handoff['owner_id'].encode()).hexdigest() or \
            role.get('hub_id_sha256') != hashlib.sha256(handoff['hub_id'].encode()).hexdigest() or \
            not positive_int(role.get('selection_generation')) or role.get('session_state_command_exit_code') != 0 or \
            role.get('registry_command_exit_code') != 0 or role.get('private_state_persisted_to_evidence') is not False or \
            role.get('errors') != [] or not isinstance(role.get('allowed_operations'), list) or \
            not {'nodes.preview', 'nodes.confirm', 'nodes.list'}.issubset(set(role['allowed_operations'])):
        code[:] = b'\0' * len(code)
        raise SafeFailure('authenticated_role_oracle_scope_mismatch')
    try:
        groups = read_private_json(evidence / 'fixture-groups.public.json', 64 * 1024)
    except SafeFailure:
        code[:] = b'\0' * len(code)
        raise
    if not isinstance(groups, dict) or set(groups) != GROUP_FIELDS or groups.get('schema') != GROUPS_SCHEMA or \
            any(groups.get(key) != handoff[key] for key in ('hub_id', 'owner_id', 'network_id')) or \
            not positive_int(groups.get('network_version')) or not isinstance(groups.get('groups'), list) or \
            not 1 <= len(groups['groups']) <= 64:
        code[:] = b'\0' * len(code)
        raise SafeFailure('fixture_group_scope_mismatch')
    return {key: handoff[key] for key in ('hub_id', 'owner_id', 'network_id', 'node_id', 'container',
        'owned_run_label')}, pins, role, code


def verify_owned_node(scope, pins):
    try:
        projection = subprocess.check_output(['docker', 'inspect', '--format',
            '{{.Id}}|{{.Image}}|{{.State.Running}}|{{index .Config.Labels "org.cicada.test.run"}}|{{json .NetworkSettings.Networks}}|{{json .HostConfig.PortBindings}}',
            scope['container']], stderr=subprocess.DEVNULL, timeout=10).decode().strip().split('|', 5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        raise SafeFailure('owned_Node_container_unavailable') from None
    if len(projection) != 6:
        raise SafeFailure('owned_Node_container_ambiguous')
    container_id, image, running, run_label, networks_raw, bindings_raw = projection
    try:
        networks = json.loads(networks_raw)
        bindings = json.loads(bindings_raw) if bindings_raw not in ('', 'null') else {}
    except json.JSONDecodeError:
        raise SafeFailure('owned_Node_network_metadata_invalid') from None
    if container_id != pins['node_container_id'] or image != pins['runtime_image'] or running != 'true' or \
            run_label != scope['owned_run_label'] or not isinstance(networks, dict) or len(networks) != 1 or bindings:
        raise SafeFailure('owned_Node_container_scope_mismatch')
    net = next(iter(networks))
    try:
        network_raw = subprocess.check_output(['docker', 'network', 'inspect', '--format',
            '{{index .Labels "org.cicada.test.run"}}|{{json .Containers}}', net],
            stderr=subprocess.DEVNULL, timeout=10).decode().strip().split('|', 1)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        raise SafeFailure('owned_Node_network_unavailable') from None
    if len(network_raw) != 2 or network_raw[0] != scope['owned_run_label']:
        raise SafeFailure('owned_Node_network_scope_mismatch')
    try:
        members = json.loads(network_raw[1])
    except json.JSONDecodeError:
        raise SafeFailure('owned_Node_network_scope_mismatch') from None
    if not isinstance(members, dict) or set(members) != {container_id}:
        raise SafeFailure('owned_Node_network_scope_mismatch')


class UI:
    def __init__(self, evidence, state, code):
        self.evidence = evidence
        self.state = state
        self.code = code
        self.steps = []
        self.width, self.height = self.screen_size()

    def adb(self, step, args, *, timeout=30):
        try:
            result = subprocess.run(driver.adb(self.state) + args, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.steps.append({'step': step, 'exit_code': 124})
            raise SafeFailure('Android_UI_step_timeout') from None
        self.steps.append({'step': step, 'exit_code': result.returncode})
        if result.returncode != 0:
            raise SafeFailure('Android_UI_step_failed')
        return result.stdout

    def screen_size(self):
        raw = self.adb('display-size', ['shell', 'wm', 'size']).decode(errors='strict')
        sizes = re.findall(r'(?:Physical|Override) size: (\d+)x(\d+)', raw)
        if not sizes:
            raise SafeFailure('Android_display_bounds_unavailable')
        width, height = map(int, sizes[-1])
        if not (320 <= width <= 8192 and 480 <= height <= 16384):
            raise SafeFailure('Android_display_bounds_invalid')
        return width, height

    def dump(self):
        self.adb('ui-dump-cleanup', ['shell', 'rm', '-f', UI_XML])
        try:
            self.adb('ui-dump', ['shell', 'uiautomator', 'dump', UI_XML])
            raw = self.adb('ui-read', ['exec-out', 'cat', UI_XML], timeout=15)
        finally:
            try:
                self.adb('ui-dump-cleanup', ['shell', 'rm', '-f', UI_XML])
            except SafeFailure:
                pass
        if self.code and bytes(self.code) in raw:
            raise SafeFailure('secure_code_was_exposed_in_accessibility_dump')
        if not 1 <= len(raw) <= 2 * 1024 * 1024:
            raise SafeFailure('Android_UI_dump_out_of_bounds')
        try:
            return ET.fromstring(raw)
        except ET.ParseError:
            raise SafeFailure('Android_UI_dump_invalid') from None

    @staticmethod
    def nodes(root):
        return list(root.iter('node'))

    def bounds(self, node):
        match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds', ''))
        if not match:
            return None
        left, top, right, bottom = map(int, match.groups())
        left, top = max(0, left), max(0, top)
        right, bottom = min(self.width, right), min(self.height, bottom)
        if right <= left or bottom <= top or node.get('visible-to-user') == 'false':
            return None
        return left, top, right, bottom

    def texts(self, root):
        return [node.get('text', '') for node in UI.nodes(root)
            if node.get('text', '') and self.bounds(node)]

    def require_checked(self, label):
        root = self.dump()
        matches = [node for node in self.nodes(root)
            if node.get('checkable') == 'true' and node.get('checked') == 'true' and
            label in (node.get('text', '') + node.get('content-desc', '')) and self.bounds(node)]
        if len(matches) != 1:
            raise SafeFailure('trusted_channel_checkbox_not_checked')

    def keyboard_visible(self, step):
        raw = self.adb(step, ['shell', 'dumpsys', 'input_method']).decode(errors='strict')
        # IME service views may remain constructed while its window is hidden.
        # The InputMethodManager's current mInputShown is authoritative here.
        current = re.search(r'\bmInputShown\s*=\s*(true|false)\b', raw)
        if current:
            return current.group(1) == 'true'
        service = re.search(r'\bmIsInputViewShown\s*=\s*(true|false)\b', raw)
        return service is not None and service.group(1) == 'true'

    def wait_for_keyboard(self):
        for attempt in range(12):
            if self.keyboard_visible('keyboard-ready-check'):
                return
            time.sleep(0.25)
        raise SafeFailure('secure_code_keyboard_did_not_open')

    def dismiss_keyboard_if_visible(self):
        if not self.keyboard_visible('keyboard-state'):
            return
        self.adb('dismiss-visible-keyboard', ['shell', 'input', 'keyevent', '4'])
        # Android applies IME visibility asynchronously after the single Back.
        # Poll its current state without sending a second navigation event.
        for _ in range(12):
            if not self.keyboard_visible('keyboard-state-after-dismiss'):
                return
            time.sleep(0.2)
        raise SafeFailure('secure_code_keyboard_remained_visible')

    def tap(self, step, node):
        bounds = self.bounds(node)
        if bounds is None:
            raise SafeFailure('Android_UI_target_has_no_bounds')
        left, top, right, bottom = bounds
        x = (left + right) // 2
        y = (top + bottom) // 2
        self.adb(step, ['shell', 'input', 'tap', str(x), str(y)])

    def scroll(self, direction='up'):
        root = self.dump()
        surfaces = [self.bounds(node) for node in self.nodes(root)
            if node.get('scrollable') == 'true' and self.bounds(node)]
        if not surfaces or direction not in ('up', 'down'):
            raise SafeFailure('Android_UI_scroll_surface_unavailable')
        left, top, right, bottom = max(surfaces, key=lambda area: (area[2] - area[0]) * (area[3] - area[1]))
        x = (left + right) // 2
        start, end = top + (bottom - top) * 4 // 5, top + (bottom - top) // 5
        if direction == 'down':
            start, end = end, start
        self.adb('ui-scroll-' + direction, ['shell', 'input', 'swipe', str(x), str(start),
            str(x), str(end), '250'])
        time.sleep(0.2)

    def find(self, value, *, attribute='text', contains=False, scroll=True, attempts=16):
        for _ in range(attempts):
            root = self.dump()
            matches = []
            for node in self.nodes(root):
                actual = node.get(attribute, '')
                if (value in actual if contains else actual == value) and self.bounds(node):
                    matches.append(node)
            if len(matches) == 1:
                return root, matches[0]
            if len(matches) > 1:
                # Accessibility may expose both a TextView and its clickable parent.
                unique = {self.bounds(node): node for node in matches}
                if len(unique) == 1:
                    return root, next(iter(unique.values()))
                raise SafeFailure('Android_UI_selector_ambiguous')
            if not scroll:
                break
            self.scroll()
        raise SafeFailure('Android_UI_target_not_visible')

    def expect_visible(self, value, *, attribute='text', contains=True, scroll=True, attempts=16):
        for _ in range(attempts):
            root = self.dump()
            if any((value in node.get(attribute, '') if contains else node.get(attribute, '') == value)
                   and self.bounds(node) for node in self.nodes(root)):
                return root
            if not scroll:
                break
            self.scroll()
        raise SafeFailure('Android_UI_target_not_visible')

    def collect_visible_text(self, *, attempts=18):
        collected = []
        for _ in range(attempts):
            root = self.dump()
            collected.extend(self.texts(root))
            yield root, collected


def exact_labeled_line(texts, label):
    prefix = label + '：'
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                return line[len(prefix):]
    return None


def has_exact_segment(texts, expected):
    return any(segment.strip() == expected for text in texts for line in text.splitlines()
        for segment in line.split(' · '))


def type_code_in_memory(state, code, steps):
    # The handoff code goes only to this inner Python process's STDIN. It is
    # absent from Docker/ADB arguments, host command receipts, and all logs.
    inner = """import re,subprocess,sys\nport=sys.argv[1]; serial=sys.argv[2]\ndata=sys.stdin.buffer.read(65)\nif not re.fullmatch(rb'[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}', data): raise SystemExit(31)\ncmd=['/opt/android-sdk/platform-tools/adb','-P',port,'-s',serial,'shell','input','text',data.decode('ascii')]\ntry: result=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)\nexcept subprocess.TimeoutExpired: raise SystemExit(32)\nraise SystemExit(result.returncode)\n"""
    try:
        result = subprocess.run(['docker', 'exec', '-i', state['container'], 'python3', '-c', inner,
                str(state['adb_port']), 'emulator-' + str(state['emulator_port'])], input=code,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except subprocess.TimeoutExpired:
        steps.append({'step': 'type-code-via-stdin', 'exit_code': 124})
        raise SafeFailure('secure_code_transfer_failed') from None
    steps.append({'step': 'type-code-via-stdin', 'exit_code': result.returncode})
    if result.returncode != 0:
        raise SafeFailure('secure_code_transfer_failed')


def run(args):
    evidence = driver.private_evidence(args.evidence)
    receipt_path = evidence / 'node-pairing-ui.redacted.json'
    if receipt_path.exists() or receipt_path.is_symlink():
        raise SafeFailure('receipt_already_exists_use_fresh_evidence_directory')
    scope, pins, role, code = load_scope(evidence, args.handoff, args.public_pins)
    steps = []
    result = 'FAIL'
    reason = 'operation_failed'
    candidate_checks = {}
    binding_verified = False
    mode = None
    artifacts = {}
    ui = None
    state = None
    try:
        state = v16.owned_state(evidence)  # Exact v1.6 emulator/container/network ownership gate.
        verify_owned_node(scope, pins)
        artifacts = read_private_json(evidence / 'android-artifacts.json', 32 * 1024)
        if artifacts.get('contract_revision') != 'client-hub-v1.6' or \
                not HEX256.fullmatch(artifacts.get('app_sha256', '')):
            raise SafeFailure('owned_Android_APK_pin_missing')
        archived_apk = evidence / 'installed-app.private.apk'
        apk_info = archived_apk.lstat()
        if not stat.S_ISREG(apk_info.st_mode) or stat.S_ISLNK(apk_info.st_mode) or \
                stat.S_IMODE(apk_info.st_mode) != 0o600 or hashlib.sha256(archived_apk.read_bytes()).hexdigest() != artifacts['app_sha256']:
            raise SafeFailure('owned_Android_APK_archive_mismatch')
        ui = UI(evidence, state, code)
        apk_paths = ui.adb('installed-apk-path', ['shell', 'pm', 'path', driver.PACKAGE]).decode().strip().splitlines()
        bases = [line.partition(':')[2] for line in apk_paths if line.endswith('/base.apk')]
        if len(bases) != 1:
            raise SafeFailure('installed_Android_APK_path_ambiguous')
        actual_apk = ui.adb('installed-apk-hash', ['exec-out', 'sha256sum', bases[0]]).decode().strip().split()
        if not actual_apk or actual_apk[0] != artifacts['app_sha256']:
            raise SafeFailure('installed_Android_APK_hash_mismatch')

        ui.adb('launch-client', ['shell', 'am', 'start', '-W', '-n',
            driver.PACKAGE + '/com.cicadaclient.MainActivity'])
        # Select the bottom navigation tab, not the same word in a page heading.
        root = ui.dump()
        candidates = [node for node in ui.nodes(root) if node.get('text') == '管理' and
            ui.bounds(node) and ui.bounds(node)[1] > ui.height * 0.65]
        if len(candidates) != 1:
            raise SafeFailure('management_tab_not_visible')
        ui.tap('open-management-tab', candidates[0])
        ui.expect_visible(scope['network_id'], contains=True, attempts=12)
        ui.expect_visible(scope['hub_id'], contains=True, attempts=12)
        # The selected Network card may be below the Node panel. Return to the
        # top through the actual scroll surface before locating that panel.
        for _ in range(12):
            visible = ui.dump()
            if any(node.get('text') == 'Node 密钥绑定' and ui.bounds(node) for node in ui.nodes(visible)):
                break
            ui.scroll('down')
        _, heading = ui.find('Node 密钥绑定', contains=False, attempts=4)
        root = ui.dump()
        collapsed = any(node.get('text') == '展开' for node in ui.nodes(root))
        if not collapsed:
            # A newly introduced panel must expose its collapsed state before use.
            raise SafeFailure('Node_pairing_panel_not_collapsed')
        ui.tap('expand-Node-panel', heading)
        _, field = ui.find('Node 一次性 user code', attribute='content-desc', scroll=False, attempts=6)
        if field.get('password') != 'true':
            raise SafeFailure('Node_code_field_is_not_secure')
        ui.tap('focus-secure-code-field', field)
        ui.wait_for_keyboard()

        expiry = timestamp(pins['expires_at'])
        if expiry is None or expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=10):
            raise SafeFailure('Core_candidate_expired_before_preview')
        type_code_in_memory(state, code, ui.steps)
        # Retain the in-memory code until the first post-input accessibility
        # dump has checked that secureTextEntry did not expose its value.
        ui.dismiss_keyboard_if_visible()
        _, preview = ui.find('读取 Node 候选', contains=False, attempts=8)
        ui.tap('preview-candidate', preview)

        card_ok = False
        for root, texts in ui.collect_visible_text(attempts=18):
            node_line = exact_labeled_line(texts, 'Node ID') or ''
            mode_values = [item for item in ('INITIAL', 'UPGRADE') if any(
                '加密 Node-Control 候选 · ' + item in text for text in texts)]
            mode = mode_values[0] if len(mode_values) == 1 else None
            candidate_checks = {
                'hub': exact_labeled_line(texts, 'Client-Control Hub ID') == scope['hub_id'],
                'node': node_line.startswith(scope['node_id'] + ' · '),
                'node_key_id': exact_labeled_line(texts, 'Node key ID') == pins['node_key_id'],
                'node_key_fingerprint': exact_labeled_line(texts, 'Node key fingerprint') == pins['node_key_fingerprint'],
                'node_key_epoch': exact_labeled_line(texts, 'Node key epoch') == str(pins['node_key_epoch']),
                'hub_node_control_key_id': exact_labeled_line(texts, 'Hub Node-Control key ID') == pins['hub_node_control_key_id'],
                'hub_node_control_key_version': exact_labeled_line(texts, 'Hub Node-Control key version') == str(pins['hub_node_control_key_version']),
                'hub_node_control_fingerprint': exact_labeled_line(texts, 'Hub Node-Control fingerprint') == pins['hub_node_control_fingerprint'],
                'candidate_digest': exact_labeled_line(texts, '候选 digest') == pins['candidate_digest'],
                'candidate_version': has_exact_segment(texts, '候选 version：' + str(pins['version'])),
                'candidate_state': has_exact_segment(texts, '状态：PENDING'),
                'candidate_expiry': has_exact_segment(texts, '到期：' + pins['expires_at']),
                'candidate_mode': mode is not None,
            }
            if all(candidate_checks.values()):
                card_ok = True
                break
            ui.scroll()
        if not card_ok:
            raise SafeFailure('visible_candidate_differs_from_Core_pins')
        # Network selection was visibly checked before entering the short code.
        # It is not a field of the documented Node-Control candidate; the real
        # panel rechecks its complete current scope before preview and confirm.
        if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=5):
            raise SafeFailure('Core_candidate_expired_before_review')

        node_checkbox = '我通过独立可信渠道核对了完整 Node key fingerprint。'
        hub_checkbox = '我通过独立可信渠道核对了 Hub Node-Control key ID 与 fingerprint；这不是手机固定的 Client-Control Hub key。'
        _, first = ui.find(node_checkbox, contains=True, attempts=16)
        ui.tap('trust-Node-key', first)
        ui.require_checked(node_checkbox)
        _, second = ui.find(hub_checkbox, contains=True, attempts=16)
        ui.tap('trust-Hub-Node-Control-key', second)
        ui.require_checked(hub_checkbox)
        _, confirm = ui.find('核对完整信息并确认', contains=False, attempts=16)
        ui.tap('open-confirm-review', confirm)

        # The native Alert is the final product-owned consent surface. Check
        # every pinned field there before tapping its confirm button.
        alert_texts = ui.texts(ui.dump())
        status_segment = '状态：PENDING'
        mode_segment = '模式：' + str(mode)
        version_segment = '候选版本：' + str(pins['version'])
        exact_alert = (
            exact_labeled_line(alert_texts, '请求 ID') == pins['request_id'] and
            exact_labeled_line(alert_texts, '候选摘要') == pins['candidate_digest'] and
            exact_labeled_line(alert_texts, '到期') == pins['expires_at'] and
            (exact_labeled_line(alert_texts, 'Node') or '').endswith(' · ' + scope['node_id']) and
            exact_labeled_line(alert_texts, 'Node key ID') == pins['node_key_id'] and
            exact_labeled_line(alert_texts, 'Node key fingerprint') == pins['node_key_fingerprint'] and
            exact_labeled_line(alert_texts, 'Node key epoch') == str(pins['node_key_epoch']) and
            exact_labeled_line(alert_texts, 'Hub Node-Control key ID') == pins['hub_node_control_key_id'] and
            exact_labeled_line(alert_texts, 'Hub Node-Control key version') == str(pins['hub_node_control_key_version']) and
            exact_labeled_line(alert_texts, 'Hub Node-Control fingerprint') == pins['hub_node_control_fingerprint'] and
            exact_labeled_line(alert_texts, 'Client-Control Hub 固定身份') == scope['hub_id'] and
            has_exact_segment(alert_texts, status_segment) and has_exact_segment(alert_texts, mode_segment) and
            has_exact_segment(alert_texts, version_segment))
        if not exact_alert:
            raise SafeFailure('confirmation_Alert_does_not_match_public_pins')
        candidate_checks['request_id_in_Alert'] = True
        _, final_confirm = ui.find('确认此候选', contains=False, scroll=False, attempts=4)
        if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=2):
            raise SafeFailure('Core_candidate_expired_before_confirm')
        ui.tap('confirm-via-product-Alert', final_confirm)

        # The panel must report the post-ACK nodes.list refresh. Then find the
        # matching binding card and require its exact Node ID and authorized UI.
        ui.expect_visible('已读取 Hub 的 nodes.list 权威状态', contains=True, attempts=24)
        for root, texts in ui.collect_visible_text(attempts=24):
            matching_rows = [text for text in texts if text.startswith('Node ' + scope['node_id'] + ' · ')
                and '授权：有效' in text]
            if matching_rows:
                if not any(re.search(r'绑定版本：?\s*[1-9][0-9]*', row) for row in matching_rows):
                    raise SafeFailure('refreshed_Node_binding_version_not_visible')
                binding_verified = True
                break
            ui.scroll()
        if not binding_verified:
            raise SafeFailure('refreshed_Node_binding_not_visible_in_authoritative_list')
        result = 'PASS'
        reason = None
    except SafeFailure as error:
        reason = error.reason
        raise
    except Exception:
        reason = 'unexpected_bounded_UI_failure'
        raise
    finally:
        code[:] = b'\0' * len(code)
        receipt = {
            'schema': 'cicada.client-v16-node-pairing-ui.v1', 'result': result, 'reason': reason,
            'android_run_id': state.get('run_id') if state else None,
            'client_apk_sha256': artifacts.get('app_sha256'),
            'core_source_revision': REVISION,
            'role': role.get('authenticated_role'),
            'profile_id_sha256': role.get('profile_id_sha256'),
            'selection_generation': role.get('selection_generation'),
            'owner_id_sha256': hashlib.sha256(scope['owner_id'].encode()).hexdigest(),
            'hub_id_sha256': hashlib.sha256(scope['hub_id'].encode()).hexdigest(),
            'network_id_sha256': hashlib.sha256(scope['network_id'].encode()).hexdigest(),
            'node_id_sha256': hashlib.sha256(scope['node_id'].encode()).hexdigest(),
            'candidate_request_id_sha256': hashlib.sha256(pins['request_id'].encode()).hexdigest(),
            'candidate_version': pins['version'], 'candidate_digest_sha256': hashlib.sha256(pins['candidate_digest'].encode()).hexdigest(),
            'candidate_fields_matched': candidate_checks,
            'owner_source': 'authenticated_role_oracle_owner_hash_plus_current_Client_panel_authority_gate',
            'network_source': 'selected_Network_UI_before_code_plus_current_Client_panel_scope_gate',
            'binding_verified_from_refreshed_nodes_list_ui': binding_verified,
            'no_RPC_injection': True, 'short_code_logged_or_persisted': False,
            'uiautomator_dump_persisted': False, 'network_or_Rpc_route_modified': False,
            'steps': ui.steps if ui else steps,
        }
        driver.save(receipt_path, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, help='owned v1.6 Android evidence directory under Client data root')
    parser.add_argument('--handoff', required=True, help='Core mode-0600 Node pairing handoff JSON')
    parser.add_argument('--public-pins', required=True, help='Core mode-0600 Node-Control public pin JSON')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        receipt = run(args)
        print(json.dumps({'result': receipt['result'], 'binding_verified': receipt['binding_verified_from_refreshed_nodes_list_ui'],
            'evidence': str(Path(args.evidence).resolve() / 'node-pairing-ui.redacted.json')}, separators=(',', ':')))
    except (SafeFailure, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, TypeError):
        print(json.dumps({'result': 'FAIL', 'reason': 'bounded Node pairing UI or ownership check failed'}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
