#!/usr/bin/env python3
"""Finite eight-case Client test loop for the frozen e2a1908 APK pair.

The Core parent supplies public files and owns signing, opaque transport,
restarts and separate-session reconciliation. This module does not start a
Hub, read a database, sign a proof, export pending packets or rebuild an APK.
Its private parent channel is separate from the carrier's FAULT_READY FD.
"""

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


consent = load('recovery_loop_consent', 'v164-link-consent-android.py')
inputs = consent.recovery
budget = load('recovery_loop_budget', 'v164-recovery-loop-budget.py')
carrier = load('recovery_loop_carrier', 'v164-link-recovery-carrier.py')
joint = load('recovery_loop_joint', 'v164-frozen-joint-inputs.py')
CACHE = Path('/gpu1-share/data/cicada-client')
ROOT_THREAD = '01a0a91b-c2b6-76b2-baf5-95422f4deeef'
PLAN_SCHEMA = 'cicada.client-v164-recovery-loop-plan.v2'
GO_SCHEMA = 'cicada.client-v164-recovery-loop-go.v1'
REQUEST_SCHEMA = 'cicada.client-v164-recovery-loop-request.v1'
REPLY_SCHEMA = 'cicada.client-v164-recovery-loop-reply.v1'
APP_SHA = '3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9'
TEST_SHA = '243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae'
BUILD_COMMIT = '9b56832c9701b0ba469d8703fdf61611e0208f98'
BUILD_INPUT_SHA = '8d26a0029dacc957607293e015bf4e6732af4a73b046556457df2446adfac629'
DRIVERS = (
    'v164-link-recovery-loop.py', 'v164-recovery-loop-budget.py', 'v164-frozen-joint-inputs.py',
    'v164-link-consent-android.py', 'v164-android-deterministic.py',
    'v164-link-recovery-inputs.py', 'v164-link-recovery-carrier.py',
    'v164-clean-delivery.py', 'v164-link-fixture-pins.py',
    'v15-android-deterministic.py', 'monitor-android.py',
    'v16-link-review-policy-status.py',
)
SUFFIXES = {'response-loss': 'ResponseLoss', 'processing': 'Processing',
            'uncertain': 'Uncertain', 'legacy': 'Legacy'}
STAGES = {'prepare': 120, 'capture': 75, 'ready': 45, 'recover': 60, 'reconcile': 60}
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}')


class LoopError(ValueError):
    pass


class ParentBlocked(LoopError):
    pass


def require(condition, message):
    if not condition:
        raise LoopError(message)


def exact(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), label + ' fields differ')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def failure_diagnostic(error):
    """Keep trusted source locations, never exception values or frame locals.

    A guard code is exported only if it matches an uppercase string literal
    in a traced Client driver function. Arbitrary error text stays private.
    """
    sites, codes = [], set()
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        path = Path(code.co_filename)
        if path.parent == HERE and path.name in DRIVERS:
            sites.append({'file': path.name, 'function': code.co_name, 'line': trace.tb_lineno})
            codes.update(value for value in code.co_consts if type(value) is str and
                         re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}', value))
        trace = trace.tb_next
    guard = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
    return {'source_sites': sites[-8:], 'guard_code': guard if guard in codes else None}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def utc_epoch(value):
    require(isinstance(value, str) and value.endswith('Z'), 'expiry must be UTC')
    try:
        return dt.datetime.fromisoformat(value[:-1] + '+00:00').timestamp()
    except ValueError as error:
        raise LoopError('expiry is invalid') from error


def absolute_path(value, root=None):
    require(isinstance(value, str) and Path(value).is_absolute(), 'absolute path required')
    path = Path(value)
    require(path.as_posix() == value, 'path must use its canonical lexical form')
    require(path.resolve(strict=False) == path, 'path must not use symlinks or aliases')
    require(root is None or path.is_relative_to(root), 'path is outside its owned root')
    return path


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            'owned fixture directory must be private and cannot be a symlink')


def validate_owned_case_root(plan, case):
    """Bind existing private directories to this exact Root plan and case."""
    root = absolute_path(plan['core_fixture_root'])
    require(root.parent == Path('/tmp') and
            re.fullmatch(r'cicada-joint-e2a-[A-Za-z0-9_-]{8,64}', root.name),
            'exact Root-owned Core temporary fixture required')
    index = case['core_case_index']
    require(type(index) is int and 0 <= index < 8, 'owned Core case index differs')
    selected = absolute_path(case['fixture_root'])
    require(selected == root / 'cases' / str(index), 'owned Core case root differs from plan')
    for path in (root, root / 'cases', selected):
        private_directory(path)
    return selected


@dataclass(frozen=True)
class FileRef:
    path: Path
    sha256: str

    @classmethod
    def parse(cls, value):
        exact(value, {'path', 'sha256'}, 'file reference')
        require(inputs.canonical_hash(value['sha256']), 'file reference digest is invalid')
        path = absolute_path(value['path'])
        require(path.suffix in ('.json', '.jsonl') and 'secrets' not in path.parts,
                'only public JSON inputs are accepted')
        return cls(path, value['sha256'])

    def as_dict(self):
        return {'path': str(self.path), 'sha256': self.sha256}

    def read(self, roots):
        require(any(self.path.is_relative_to(root) for root in roots), 'public input is outside case roots')
        value, raw = inputs.read_private_json(self.path, self.sha256)
        require(not consent.secret_fields(value), 'public input contains forbidden credential fields')
        return value, raw


def validate_plan(plan):
    exact(plan, {'schema', 'batch_id', 'core_fixture_root', 'android_evidence', 'evidence_root', 'apk_pins',
                 'driver_sha256', 'cases'}, 'loop plan')
    require(plan['schema'] == PLAN_SCHEMA and isinstance(plan['batch_id'], str) and
            ID.fullmatch(plan['batch_id']), 'loop plan scope is invalid')
    evidence = absolute_path(plan['android_evidence'], CACHE)
    require(consent.runner.RECOVERY_RUN_ID.fullmatch(evidence.parent.name), 'fresh recovery emulator required')
    absolute_path(plan['evidence_root'], CACHE)
    core_root = absolute_path(plan['core_fixture_root'])
    require(core_root.parent == Path('/tmp') and
            re.fullmatch(r'cicada-joint-e2a-[A-Za-z0-9_-]{8,64}', core_root.name),
            'exact Root-owned Core temporary fixture required')
    joint.verify_artifacts()
    exact(plan['driver_sha256'], DRIVERS, 'driver pins')
    for name, expected in plan['driver_sha256'].items():
        require(inputs.canonical_hash(expected) and sha((HERE / name).read_bytes()) == expected,
                'Client driver bytes differ from Root pins')
    pins_ref = FileRef.parse(plan['apk_pins'])
    pins, _raw = inputs.read_private_json(pins_ref.path, pins_ref.sha256)
    inputs.validate_apk_pins(pins)
    require(pins['app_sha256'] == APP_SHA and pins['test_sha256'] == TEST_SHA,
            'loop requires the immutable application/test APK pair')
    require(pins['client_build_commit'] == BUILD_COMMIT and pins['client_build_dirty'] is True and
            pins['client_input_sha256'] == BUILD_INPUT_SHA, 'immutable APK build attribution differs')
    require(isinstance(plan['cases'], list) and len(plan['cases']) == 8, 'exactly eight cases required')
    pairs, case_ids, run_ids, roots = set(), set(), set(), set()
    core_pairs = [(op, mode) for op in ('link.key_grant', 'link.review_policy_grant')
                  for mode in ('response-loss', 'processing', 'uncertain', 'legacy')]
    for index, case in enumerate(plan['cases']):
        exact(case, {'case_id', 'core_case_index', 'run_id', 'side', 'operation', 'mode', 'fixture_root'}, 'case')
        require(isinstance(case['case_id'], str) and ID.fullmatch(case['case_id']) and
                isinstance(case['run_id'], str) and inputs.RUN_ID.fullmatch(case['run_id']) and
                case['side'] == 'source' and type(case['core_case_index']) is int and
                case['core_case_index'] == index, 'case identity or fixed SOURCE index is invalid')
        require(case['run_id'].endswith('-' + str(index)), 'Core case run suffix differs')
        base = case['run_id'][:-2]
        require(base == joint.RUN_ID, 'Core frozen case run base differs')
        require(case['operation'] in inputs.OPERATIONS and case['mode'] in inputs.MODES, 'case mode is invalid')
        require((case['operation'], case['mode']) == core_pairs[index], 'Core fixed case order differs')
        root = absolute_path(case['fixture_root'])
        require(root == core_root / 'cases' / str(index), 'fixed Core case root differs')
        pairs.add((case['operation'], case['mode']))
        case_ids.add(case['case_id'])
        run_ids.add(case['run_id'])
        roots.add(root)
    require(len(pairs) == len(case_ids) == len(run_ids) == len(roots) == 8,
            'cases must have distinct roots, IDs, runs and operation/mode pairs')
    require(not any(a != b and a.is_relative_to(b) for a in roots for b in roots),
            'case roots must not overlap')
    return plan


def validate_go(value, plan_sha, batch_id):
    exact(value, {'schema', 'root_thread_id', 'batch_id', 'plan_sha256', 'approved',
                  'approval_id', 'issued_at', 'expires_at', 'outer_seconds', 'case_seconds'}, 'Root GO')
    require(value['schema'] == GO_SCHEMA and value['root_thread_id'] == ROOT_THREAD and
            value['batch_id'] == batch_id and value['plan_sha256'] == plan_sha and
            value['approved'] is True and isinstance(value['approval_id'], str) and
            ID.fullmatch(value['approval_id']), 'Root GO does not authorize this exact plan')
    require(type(value['outer_seconds']) is int and value['outer_seconds'] == 3600 and
            type(value['case_seconds']) is int and value['case_seconds'] == 360, 'Root GO budget differs')
    issued, expires = utc_epoch(value['issued_at']), utc_epoch(value['expires_at'])
    require(issued <= time.time() and expires - time.time() > 240 and 0 < expires - issued <= 3600,
            'Root GO is expired, overlong or lacks the cleanup reserve')
    return expires


def validate_fault_ready_reply(reply):
    exact(reply, {'ready', 'capture_verified', 'control_installed'}, 'fault readiness')
    require(reply['capture_verified'] is True and reply['control_installed'] is True,
            'Core capture verification must precede Root carrier control installation')


class ParentChannel:
    """One inherited private Unix socket; each exchange has an absolute cutoff."""

    def __init__(self, fd, batch_id):
        require(type(fd) is int and fd >= 3, 'private parent FD required')
        self.socket = socket.socket(fileno=os.dup(fd))
        try:
            require(self.socket.family == socket.AF_UNIX and self.socket.type == socket.SOCK_STREAM,
                    'parent channel must be a Unix stream socket')
            _pid, uid, _gid = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid(), 'parent channel peer UID differs')
        except (LoopError, OSError):
            self.socket.close()
            raise
        self.batch_id, self.sequence = batch_id, 0

    def request(self, event, case_id, payload, deadline):
        self.sequence += 1
        request = {'schema': REQUEST_SCHEMA, 'request_id': self.sequence, 'batch_id': self.batch_id,
                   'case_id': case_id, 'event': event, 'remaining_ms': max(0, int(deadline.remaining() * 1000)),
                   'payload': payload}
        raw = canonical(request)
        require(len(raw) <= 64 * 1024 and deadline.remaining() > 0, 'parent request deadline or bound exceeded')
        self.socket.settimeout(deadline.remaining())
        try:
            self.socket.sendall(raw)
            output = bytearray()
            while b'\n' not in output:
                require(deadline.remaining() > 0, 'parent response deadline exceeded')
                self.socket.settimeout(deadline.remaining())
                part = self.socket.recv(min(4096, 65537 - len(output)))
                require(bool(part), 'parent control channel closed')
                output.extend(part)
                require(len(output) <= 65536, 'parent response exceeds bound')
        except (TimeoutError, OSError) as error:
            raise LoopError('parent control exchange failed') from error
        require(output.count(b'\n') == 1 and output.endswith(b'\n'), 'parent response framing differs')
        value = inputs.delivery.parse(bytes(output))
        exact(value, {'schema', 'request_id', 'batch_id', 'case_id', 'event', 'result', 'payload'}, 'parent reply')
        require(value['schema'] == REPLY_SCHEMA and type(value['request_id']) is int and
                value['request_id'] == self.sequence and value['batch_id'] == self.batch_id and
                value['case_id'] == case_id and value['event'] == event and isinstance(value['payload'], dict),
                'parent reply correlation differs')
        require(not consent.secret_fields(value['payload']), 'parent must not send credential fields')
        if value['result'] == 'BLOCKED':
            raise ParentBlocked('parent prerequisite is blocked')
        require(value['result'] == 'READY', 'parent prerequisite failed')
        require(deadline.remaining() > 0, 'parent returned after absolute deadline')
        return value['payload']

    def close(self):
        self.socket.close()


class SelectorDriver:
    """Only the existing allowlisted stage/selector/export CLI is executable."""

    def __init__(self, plan, runner, cleanup_deadline):
        self.plan, self.runner, self.cleanup_deadline = plan, runner, cleanup_deadline
        self.evidence = Path(plan['android_evidence'])
        self.logs = Path(plan['evidence_root']) / 'commands'
        self.logs.mkdir(mode=0o700)
        self.staged = Path(plan['evidence_root']) / 'inputs'
        self.staged.mkdir(mode=0o700)
        self.receipts, self.ordinal = [], 0

    def call(self, case, action, arguments, deadline):
        validate_plan(self.plan)
        self.ordinal += 1
        pins = FileRef.parse(self.plan['apk_pins'])
        argv = [sys.executable, str(HERE / 'v164-link-consent-android.py'), str(self.evidence), action,
                '--run-id', case['run_id'], *arguments,
                '--recovery-apk-pins', str(pins.path), '--recovery-apk-pins-sha256', pins.sha256]
        # Reserve two seconds inside this same stage/case deadline for reaping.
        execution = budget.Deadline.after(max(0, deadline.remaining() - 2), parent=deadline)
        receipt = self.runner.run(argv, execution, self.logs, f'step-{self.ordinal:03d}',
                                  cleanup_deadline=deadline)
        self.receipts.append(receipt.as_dict())
        require(receipt.exit_code == 0 and receipt.process_group_closed and receipt.process_reaped,
                'Client subprocess failed or ownership cleanup is incomplete')
        raw = Path(receipt.stdout_path).read_bytes()
        require(len(raw) <= 65536 and not receipt.stdout_truncated, 'Client command output exceeds bound')
        value = inputs.delivery.parse(raw)
        require(isinstance(value, dict), 'Client command omitted its result')
        require(deadline.remaining() > 0, 'Client command returned after deadline')
        return value

    def selector(self, case, method, deadline):
        require(method in consent.SELECTORS, 'selector is not allowlisted')
        value = self.call(case, 'selector', ['--method', method, '--side', case['side']], deadline)
        expected = 'CAPTURED' if method in consent.CAPTURE_SELECTORS else \
            'RECOVERED' if method in consent.RECOVERY_SELECTORS else 'PASS'
        require(value.get('result') == expected and value.get('selector') == method and
                value.get('side') == case['side'] and value.get('junit') == 'OK (1 test)',
                'Client selector did not establish its exact native phase')

    def stage(self, case, name, ref, deadline, reference=None):
        require(name in consent.STAGE_FILES, 'input name is not allowlisted')
        # The legacy driver normalizes most JSON inputs. First snapshot the
        # independently hashed bytes so a parent file change cannot race it.
        ref = self.freeze_input(ref)
        args = ['--name', name, '--input', str(ref.path), '--input-sha256', ref.sha256]
        if name != 'review-policy.json':
            args += ['--side', case['side']]
        if reference is not None:
            reference = self.freeze_input(reference)
            args += ['--reference', str(reference.path)]
        value = self.call(case, 'stage', args, deadline)
        require(value.get('result') == 'PASS' and value.get('file') == name, 'Client staging failed')

    def freeze_input(self, ref):
        value, raw = inputs.read_private_json(ref.path, ref.sha256)
        require(not consent.secret_fields(value), 'public stage input contains credentials')
        path = self.staged / f'input-{len(list(self.staged.iterdir())):03d}.private.json'
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o600)
        return FileRef(path, ref.sha256)

    def export(self, case, name, deadline):
        require(name in consent.EXPORT_FILES, 'export name is not allowlisted')
        value = self.call(case, 'export', ['--name', name, '--side', case['side']], deadline)
        require(value.get('result') == 'PASS' and value.get('file') == name and
                isinstance(value.get('private_evidence'), str) and
                Path(value['private_evidence']).name == value['private_evidence'], 'Client export is invalid')
        ref = FileRef.parse({'path': str(self.evidence / 'link-v164' / value['private_evidence']),
                             'sha256': value.get('sha256')})
        ref.read([self.evidence])
        return ref


class RecoveryLoop:
    def __init__(self, plan, parent, driver, outer, work_deadline):
        self.plan, self.parent, self.driver = plan, parent, driver
        self.outer, self.work_deadline = outer, work_deadline
        self.records = [{'case_id': case['case_id'], 'operation': case['operation'], 'mode': case['mode'],
                         'side': case['side'], 'result': 'NOT_RUN', 'business_outcome': 'UNKNOWN'}
                        for case in plan['cases']]
        self.seen = {name: set() for name in ('owner', 'owner_key', 'device', 'device_key', 'profile',
                                            'link', 'group', 'endpoint')}
        self.ownership = None

    def request(self, event, case, payload, deadline):
        return self.parent.request(event, case['case_id'] if case else None, payload, deadline)

    def read_ref(self, payload, key, case):
        ref = FileRef.parse(payload[key])
        value, raw = ref.read([Path(case['fixture_root']), Path(self.plan['android_evidence']),
                               Path(self.plan['evidence_root'])])
        return ref, value, raw

    def enroll_role(self, case, side, setup_ref, setup, stage):
        """TARGET first; create SOURCE last and never reactivate an old scope."""
        selected = dict(case, side=side)
        role = side.capitalize()
        self.driver.stage(selected, side + '-setup-public.json', setup_ref, stage)
        self.driver.selector(selected, 'export' + role + 'OwnerDeviceIdentityForHostGrant', stage)
        device = self.driver.export(selected, side + '-device-public.private.json', stage)
        value, _ = device.read([Path(self.plan['android_evidence'])])
        require(all(value[name] == setup[name] for name in ('hub_id', 'owner_id', 'owner_key_id', 'device_id')) and
                value['owner_role'] == side, 'exported Android device differs from setup')
        for name, identity in (('device_key', value['device_public_identity_sha256']), ('profile', value['profile_id'])):
            require(identity not in self.seen[name], 'Android device key or profile reused')
            self.seen[name].add(identity)
        control = joint.typed_control('device', case['core_case_index'], side=side.upper(), manifest_sha256=device.sha256)
        signed = self.request('SIGN_ENROLLMENT', case, {'device': device.as_dict(), 'core_control': control}, stage)
        exact(signed, {'grant'}, 'signed enrollment')
        grant, _, _ = self.read_ref(signed, 'grant', case)
        require(grant.path == joint.expected_output_path(Path(case['fixture_root']), side, 'device-grant'),
                'Core enrollment output path differs')
        self.driver.stage(selected, side + '-owner-device-grant.private.json', grant, stage, device)
        self.driver.selector(selected, 'enroll' + role + 'OwnerDeviceGrantAndVerifyFreshCapabilities', stage)
        receipt = self.driver.export(selected, side + '-onboarding-enroll.redacted.json', stage)
        return device, value, receipt

    def one_case(self, case, record, case_deadline):
        side, operation, mode = case['side'], case['operation'], case['mode']
        record['phase'] = 'PREPARING'
        kind = 'Key' if operation == 'link.key_grant' else 'None'
        stage = budget.Deadline.after(STAGES['prepare'], parent=case_deadline)
        ready = self.request('CASE_READY', case,
                             {'core_control': joint.typed_control('prepare', case['core_case_index'])}, stage)
        exact(ready, {'ready', 'setups', 'binding', 'valid_until'}, 'case READY')
        validate_owned_case_root(self.plan, case)
        ready_ref, legacy, _ = self.read_ref(ready, 'ready', case)
        require(ready_ref.path == Path(case['fixture_root']) / 'public/READY.json', 'Core READY path differs')
        frozen = joint.validate_ready(legacy, Path(case['fixture_root']))
        require(ready['valid_until'] == legacy['coordination_deadline'], 'Root deadline differs from Core READY')
        exact(ready['setups'], {'source', 'target'}, 'onboarding setups')
        setups = {}
        for owner_side in ('target', 'source'):
            ref, value, _ = self.read_ref(ready['setups'], owner_side, case)
            consent.validate_setup(value, owner_side, case['run_id'])
            public = frozen['client_setup']
            owner = next(row for row in public['owners'] if row['link_side'] == owner_side.upper())
            require(value['hub_id'] == public['hub']['hub_id'] and
                    value['control_public_identity'] == public['hub']['control_public_identity'] and
                    value['owner_id'] == owner['owner_id'] and value['owner_key_id'] == owner['owner_key_id'] and
                    value['owner_public_identity'] == owner['public_identity'], 'normalized setup differs from pinned Core public keys')
            setups[owner_side] = (ref, value)
        binding = ready['binding']
        exact(binding, {'hub_id', 'owner_id', 'owner_key_id', 'device_id', 'link_id', 'link_version',
                        'source_owner_id', 'target_owner_id', 'source_group_id', 'target_group_id',
                        'source_endpoint_id', 'target_endpoint_id'}, 'case binding')
        require(all(consent.checked_id(binding[name]) for name in binding if name != 'link_version') and
                type(binding['link_version']) is int and 1 <= binding['link_version'] <= 9_007_199_254_740_991,
                'case binding identity is invalid')
        require(binding['source_owner_id'] != binding['target_owner_id'] and
                binding['owner_id'] == binding[side + '_owner_id'], 'case Owner side differs')
        link = frozen['fixture_public']['link']
        require(binding['link_id'] == link['link_id'] and binding['link_version'] == link['version'] and
                all(binding[owner_side + '_owner_id'] == setups[owner_side][1]['owner_id'] for owner_side in ('source', 'target')) and
                all(binding[name] == link[name] for name in ('source_group_id', 'target_group_id',
                                                           'source_endpoint_id', 'target_endpoint_id')),
                'case Link/Owner binding differs from current Core public fixture')
        identity_sets = {'owner': {binding['source_owner_id'], binding['target_owner_id']},
                         'owner_key': {setups['source'][1]['owner_key_id'], setups['target'][1]['owner_key_id']},
                         'device': {setups['source'][1]['device_id'], setups['target'][1]['device_id']}, 'link': {binding['link_id']},
                         'group': {binding['source_group_id'], binding['target_group_id']},
                         'endpoint': {binding['source_endpoint_id'], binding['target_endpoint_id']}}
        require(all(len(identity_sets[name]) == 2 for name in ('group', 'endpoint', 'device', 'owner_key')),
                'source and target require distinct Group/Endpoint/device/Owner-key identities')
        for name, identities in identity_sets.items():
            require(not identities & self.seen[name], 'case identity reused')
            self.seen[name].update(identities)
        expiry = utc_epoch(ready['valid_until'])
        require(expiry > time.time(), 'fresh binding is expired')
        case_deadline = budget.Deadline.after(min(case_deadline.remaining(), expiry - time.time()), parent=case_deadline)
        stage = budget.Deadline.after(min(stage.remaining(), case_deadline.remaining()), parent=case_deadline)
        setup_ref, setup = setups[side]
        require(all(setup[name] == binding[name] for name in ('hub_id', 'owner_id', 'owner_key_id', 'device_id')),
                'Android setup differs from case binding')
        target_device, target_value, target_enrollment = self.enroll_role(case, 'target', *setups['target'], stage)
        device, device_value, enrollment = self.enroll_role(case, 'source', setup_ref, setup, stage)
        require(type(device_value['profile_generation']) is int and type(target_value['profile_generation']) is int and
                device_value['profile_generation'] > target_value['profile_generation'],
                'actual TARGET-to-SOURCE generation transition is not established')
        record.update(target_enrollment_receipt_sha256=target_enrollment.sha256,
                      source_enrollment_receipt_sha256=enrollment.sha256,
                      profile_transition='TARGET_THEN_SOURCE_NATIVE_GENERATION_OBSERVED',
                      target_profile_generation=target_value['profile_generation'],
                      source_profile_generation=device_value['profile_generation'],
                      source_return_switch='NOT_PERFORMED')
        selection_reply = self.request('LINK_SELECTION', case,
                                       {'device': device.as_dict(), 'enrollment': enrollment.as_dict()}, stage)
        expected_keys = {'selection'} if kind == 'Key' else {'selection', 'policy'}
        exact(selection_reply, expected_keys, 'Link selection')
        selection_ref, selection, _ = self.read_ref(selection_reply, 'selection', case)
        require(selection['link_id'] == binding['link_id'] and selection['expected_link_version'] == binding['link_version'],
                'selected Link differs from case binding')
        self.driver.stage(case, 'selection.json', selection_ref, stage, device)
        if kind == 'None':
            policy_ref, policy, _ = self.read_ref(selection_reply, 'policy', case)
            require(policy.get('policy') == {'mode': 'NONE', 'reviewers': [], 'max_failovers': 0,
                    'reviewer_lease_seconds': 0, 'max_review_age_seconds': 0},
                    'Root must supply exact empty NONE policy')
            self.driver.stage(case, 'review-policy.json', policy_ref, stage)
        self.driver.selector(case, 'confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval', stage)
        review_method = 'exportsFreshCurrentKeyReviewForExternalSigner' if kind == 'Key' else \
            'exportsReviewPolicyCandidateForExternalSigner'
        review_kind = 'key' if kind == 'Key' else 'policy'
        self.driver.selector(case, review_method, stage)
        review = self.driver.export(case, side + '-' + review_kind + '-review.private.json', stage)
        review_value, _ = review.read([Path(self.plan['android_evidence'])])
        signed = self.request('SIGN_CONSENT', case, {'review': review.as_dict(),
                             'core_control': joint.typed_control('proof', case['core_case_index'],
                                                                side='SOURCE', input_sha256=review.sha256)}, stage)
        exact(signed, {'proof', 'valid_until'}, 'signed consent')
        proof, _, _ = self.read_ref(signed, 'proof', case)
        require(proof.path == joint.expected_output_path(Path(case['fixture_root']), 'source', 'link-proof'),
                'Core consent output path differs')
        proof_expiry = utc_epoch(signed['valid_until'])
        flat = inputs.delivery.parse(review_value['signing_request_json'].encode())
        require(signed['valid_until'] == flat['expires_at'], 'Root proof expiry differs from the exact reviewed signing request')
        require(time.time() < proof_expiry <= utc_epoch(review_value['native_review_json']['maximumProofExpiresAt']),
                'Owner proof expiry exceeds the native reviewed maximum')
        case_deadline = budget.Deadline.after(min(case_deadline.remaining(), proof_expiry - time.time()), parent=case_deadline)
        stage = budget.Deadline.after(stage.remaining(), parent=case_deadline)
        self.driver.stage(case, side + '-' + review_kind + '-proof.private.json', proof, stage, review)
        record['phase'] = 'ENROLLED_REVIEWED_SIGNED'
        stage = budget.Deadline.after(STAGES['capture'], parent=case_deadline)
        activated = self.request('ACTIVATE_OPAQUE', case, {'enrollment': enrollment.as_dict(),
                                 'core_control': joint.typed_control('proxy', case['core_case_index'], side='SOURCE')}, stage)
        exact(activated, {'carrier_manifest', 'raw_ready', 'scenario'}, 'opaque activation')
        manifest_ref, carrier_manifest, _ = self.read_ref(activated, 'carrier_manifest', case)
        raw_ref, _, raw_ready = self.read_ref(activated, 'raw_ready', case)
        scenario_ref, scenario, _ = self.read_ref(activated, 'scenario', case)
        for ref, kind_name in ((manifest_ref, 'carrier-manifest'), (raw_ref, 'proxy-ready'), (scenario_ref, 'scenario')):
            require(ref.path == joint.expected_output_path(Path(case['fixture_root']), 'source', kind_name),
                    'Core proxy output path differs')
        inputs.validate_scenario(scenario, case['run_id'], operation, mode)
        manifest = carrier.RootManifest.from_mapping(carrier_manifest)
        carrier.parse_ready(raw_ready, manifest)
        enrolled, _ = enrollment.read([Path(self.plan['android_evidence'])])
        require(manifest.run_id == case['run_id'] and manifest.expected_operation == operation and
                manifest.fault_mode == mode and manifest.hub_id == binding['hub_id'] and
                manifest.owner_id == binding['owner_id'] and manifest.device_id == binding['device_id'] and
                manifest.android_base_url == setup['base_url'] and
                manifest.session_epoch == enrolled['session_epoch'], 'opaque scope differs from current Android enrollment')
        self.driver.stage(case, side + '-recovery-scenario.v2.json', scenario_ref, stage)
        self.driver.selector(case, 'captures' + kind + 'OriginalConsentFault', stage)
        stem = inputs.case_stem(side, operation, mode)
        capture = self.driver.export(case, stem + '.capture.redacted.json', stage)
        capture_value, _ = capture.read([Path(self.plan['android_evidence'])])
        inputs.validate_capture(capture_value, scenario, side)
        record.update(phase='CAPTURED', packet_sha256=capture_value['packet_sha256'],
                      operation_id_sha256=capture_value['operation_id_sha256'], proof_sha256=capture_value['proof_sha256'])
        stage = budget.Deadline.after(STAGES['ready'], parent=case_deadline)
        reply = self.request('FAULT_READY', case, {'capture': capture.as_dict(),
                             'core_control': joint.typed_control('capture', case['core_case_index'],
                                                                capture_sha256=capture.sha256)}, stage)
        validate_fault_ready_reply(reply)
        fault_ref, fault, fault_raw = self.read_ref(reply, 'ready', case)
        require(fault_ref.path == joint.expected_output_path(Path(case['fixture_root']), 'source', 'fault-envelope'),
                'Core fault envelope path differs')
        inputs.validate_ready_envelope(fault, case['run_id'], capture_value)
        self.driver.stage(case, side + '-fault-ready.json', fault_ref, stage, capture)
        stage = budget.Deadline.after(STAGES['recover'], parent=case_deadline)
        self.driver.selector(case, 'recover' + kind + SUFFIXES[mode], stage)
        result = self.driver.export(case, stem + '.recovery.redacted.json', stage)
        result_value, _ = result.read([Path(self.plan['android_evidence'])])
        inputs.validate_result(result_value, capture_value, scenario, side, fault, fault_raw)
        record['phase'] = 'RECOVERED'
        reply = self.request('CARRIER_SNAPSHOT', case, {'capture': capture.as_dict(), 'result': result.as_dict()}, stage)
        exact(reply, {'snapshot'}, 'carrier snapshot')
        snapshot_ref, snapshot, _ = self.read_ref(reply, 'snapshot', case)
        inputs.validate_carrier_snapshot(snapshot, capture_value, scenario, fault, fault_raw)
        finished = self.request('FINISH_CASE', case,
                                {'result': result.as_dict(), 'snapshot': snapshot_ref.as_dict(),
                                 'core_control': joint.typed_control('finish', case['core_case_index'],
                                                                    result_sha256=result.sha256,
                                                                    carrier_sha256=snapshot_ref.sha256)}, stage)
        exact(finished, {'case_finished'}, 'Core finish')
        require(finished['case_finished'] is True, 'Core did not acknowledge matching capture/result/carrier joins')
        stage = budget.Deadline.after(STAGES['reconcile'], parent=case_deadline)
        reply = self.request('RECONCILE_DIRECT', case, {'capture': capture.as_dict(), 'result': result.as_dict(),
                                                     'review': review.as_dict()}, stage)
        exact(reply, {'receipt'}, 'separate-session reconciliation')
        reconciliation_ref, reconciliation, _ = self.read_ref(reply, 'receipt', case)
        record_reconciliation(record, reconciliation, case, binding, capture_value,
                              review_value, reconciliation_ref.sha256)

    def run(self):
        failure = None
        diagnostic = None
        cleanup = {'result': 'NOT_RUN'}
        try:
            boot = self.request('BOOT_READY', None, {}, budget.Deadline.after(480, parent=self.work_deadline))
            exact(boot, {'ownership', 'core_fixture_root'}, 'Android boot readiness')
            require(boot['core_fixture_root'] == self.plan['core_fixture_root'], 'Root Core boot scope differs')
            core_root = Path(boot['core_fixture_root'])
            private_directory(core_root)
            self.ownership = FileRef.parse(boot['ownership'])
            ownership, _ = self.ownership.read([Path(self.plan['android_evidence']), Path(self.plan['evidence_root'])])
            validate_ownership(ownership, self.plan)
            for case, record in zip(self.plan['cases'], self.records):
                record['result'] = 'UNKNOWN'
                try:
                    self.one_case(case, record, budget.Deadline.after(360, parent=self.work_deadline))
                except ParentBlocked:
                    record['result'] = 'BLOCKED'
                    raise
        except (ValueError, OSError, TimeoutError, RuntimeError, KeyError, TypeError) as error:
            failure = type(error).__name__
            diagnostic = failure_diagnostic(error)
        finally:
            try:
                reply = self.request('CLOSE_ANDROID', None,
                                     {'ownership': self.ownership.as_dict() if self.ownership else None,
                                      'child_journal_directory': str(Path(self.plan['evidence_root']) / 'commands')},
                                     budget.Deadline.after(240, parent=self.outer))
                exact(reply, {'receipt'}, 'Android close')
                ref = FileRef.parse(reply['receipt'])
                value, _ = ref.read([Path(self.plan['android_evidence']), Path(self.plan['evidence_root'])])
                validate_cleanup(value, self.plan, self.ownership)
                cleanup = {'result': 'PASS', 'receipt_sha256': ref.sha256}
            except (ValueError, OSError, TimeoutError, RuntimeError, KeyError, TypeError):
                cleanup = {'result': 'UNKNOWN'}
        return {'schema': 'cicada.client-v164-recovery-loop-result.v1',
                'result': 'PASS' if failure is None and cleanup['result'] == 'PASS' else 'FAIL',
                'cases': self.records, 'cleanup': cleanup, 'failure_class': failure,
                'failure_diagnostic': diagnostic,
                'child_processes': self.driver.receipts, 'native_worker': 'NOT_RUN',
                'physical_android': 'NOT_RUN', 'public_https': 'NOT_RUN'}


def validate_ownership(value, plan):
    exact(value, {'schema', 'container_id', 'image_id', 'network', 'auto_remove', 'label', 'run_id'}, 'Android ownership')
    require(value['schema'] == 'cicada.client-v164-recovery-loop-android-owned.v1' and
            isinstance(value['container_id'], str) and inputs.canonical_hash(value['container_id']) and
            value['image_id'] == consent.driver.IMAGE and value['network'] == 'none' and value['auto_remove'] is True and
            value['label'] == consent.runner.LABEL and value['run_id'] == Path(plan['android_evidence']).parent.name,
            'Android ownership differs from exact allowed emulator')


def validate_cleanup(value, plan, ownership_ref):
    exact(value, {'schema', 'ownership_sha256', 'container_id_sha256', 'removed',
                  'absence_exit_code', 'absence_confirmed', 'process_groups_closed', 'command_receipts'}, 'Android close evidence')
    require(value['schema'] == 'cicada.client-v164-recovery-loop-android-close.v1' and ownership_ref is not None and
            value['ownership_sha256'] == ownership_ref.sha256 and inputs.canonical_hash(value['container_id_sha256']) and
            value['removed'] is True and type(value['absence_exit_code']) is int and value['absence_exit_code'] == 1 and
            value['absence_confirmed'] is True and value['process_groups_closed'] is True and
            isinstance(value['command_receipts'], list) and 2 <= len(value['command_receipts']) <= 3,
            'exact owned Android removal is not established')
    ownership, _ = ownership_ref.read([Path(plan['android_evidence']), Path(plan['evidence_root'])])
    validate_ownership(ownership, plan)
    require(value['container_id_sha256'] == sha(ownership['container_id'].encode()), 'closed container differs')
    paths, hashes, roles = set(), set(), set()
    container = ownership['container_id']
    commands = {'stop': ['docker', 'stop', '--time', '10', container],
                'remove': ['docker', 'rm', '--force', container],
                'absence': ['docker', 'inspect', container, '--format', '{{.Id}}']}
    for entry in value['command_receipts']:
        ref = FileRef.parse(entry)
        require(ref.path not in paths and ref.sha256 not in hashes, 'cleanup command evidence duplicated')
        paths.add(ref.path)
        hashes.add(ref.sha256)
        command, _ = ref.read([Path(plan['android_evidence']), Path(plan['evidence_root'])])
        exact(command, {'schema', 'role', 'argv', 'exit_code', 'stdout_sha256', 'stderr_sha256',
                        'absence_confirmed'}, 'Android cleanup command')
        role = command['role']
        require(command['schema'] == 'cicada.client-v164-recovery-loop-android-command.v1' and
                role in commands and role not in roles and command['argv'] == commands[role] and
                type(command['exit_code']) is int and command['exit_code'] == (1 if role == 'absence' else 0) and
                command['absence_confirmed'] is (role == 'absence') and
                inputs.canonical_hash(command['stdout_sha256']) and inputs.canonical_hash(command['stderr_sha256']),
                'Android cleanup command or actual exit differs')
        roles.add(role)
    require('absence' in roles and bool(roles & {'stop', 'remove'}), 'owned removal or absence command missing')


def validate_reconciliation(value, case, binding, capture, review):
    """Check parent evidence scope; label its crypto/read execution separately."""
    fields = {'schema', 'case_id', 'run_id_sha256', 'link_id_sha256', 'link_version', 'owner_id_sha256',
              'device_id_sha256', 'session_epoch', 'transport', 'encrypted_verified', 'read_only',
              'hub_id_sha256', 'binding_sha256', 'manifest_digest', 'scope_binding_verified',
              'endpoint_attestations_verified', 'owner_proofs_verified',
              'proof_sha256', 'proof_observed', 'source_status', 'target_status', 'policy_mode',
              'bilateral_verified', 'policy', 'reads'}
    exact(value, fields, 'direct reconciliation')
    require(value['schema'] == 'cicada.client-v164-recovery-loop-direct-reconciliation.v1' and
            value['case_id'] == case['case_id'] and value['run_id_sha256'] == sha(case['run_id'].encode()) and
            value['link_id_sha256'] == sha(binding['link_id'].encode()) and
            value['link_version'] == str(binding['link_version']) and
            value['owner_id_sha256'] == sha(binding[('target' if case['side'] == 'source' else 'source') + '_owner_id'].encode()) and
            inputs.canonical_hash(value['device_id_sha256']) and
            value['device_id_sha256'] != sha(binding['device_id'].encode()) and
            value['hub_id_sha256'] == sha(binding['hub_id'].encode()) and
            value['binding_sha256'] == sha(canonical(binding)) and inputs.canonical_hash(value['manifest_digest']) and
            value['manifest_digest'] == review['native_review_json']['manifestDigest'] and
            value['scope_binding_verified'] is True and value['endpoint_attestations_verified'] is True and
            value['owner_proofs_verified'] is True and
            type(value['session_epoch']) is int and 0 < value['session_epoch'] <= inputs.MAX_LONG and
            value['transport'] == 'DIRECT' and value['encrypted_verified'] is True and value['read_only'] is True and
            value['proof_sha256'] == capture['proof_sha256'], 'reconciliation session or proof scope differs')
    is_key = case['operation'] == 'link.key_grant'
    accepted = 'ACCEPTED' if is_key else 'VERIFIED'
    statuses = {'MISSING', 'ACCEPTED', 'KEY_BINDING_STALE', 'OWNER_KEY_REVOKED', 'PROOF_EXPIRED',
                'INVALID', 'LEGACY_KEY_UNBOUND'} if is_key else \
               {'MISSING', 'VERIFIED', 'OWNER_KEY_REVOKED', 'PROOF_EXPIRED', 'SCOPE_STALE', 'INVALID'}
    require(value['source_status'] in statuses and value['target_status'] in statuses,
            'reconciliation status is unknown')
    local = value[case['side'] + '_status']
    require(type(value['proof_observed']) is bool and value['proof_observed'] == (case['mode'] == 'response-loss') and
            local == (accepted if value['proof_observed'] else 'MISSING'),
            'reconciliation inferred or lost original grant acceptance')
    require(value['policy_mode'] == (None if is_key else 'NONE'), 'reconciliation policy differs')
    peer = value[('target' if case['side'] == 'source' else 'source') + '_status']
    require(peer == 'MISSING' and value['bilateral_verified'] is False,
            'fresh SOURCE-only reconciliation cannot establish bilateral acceptance')
    if is_key:
        require(value['policy'] is None, 'KEY reconciliation contains a policy claim')
    else:
        policy = value['policy']
        exact(policy, {'candidate_version', 'candidate_digest', 'candidate_current', 'head_version',
                       'head_digest', 'head_current', 'head_source_status', 'head_target_status',
                       'head_bilateral_verified', 'candidate_evidence_origin',
                       'candidate_evidence_receipt_sha256'}, 'NONE candidate and current head')
        expected_origin = 'DB_READONLY_VERIFIED_SIGNED_PROOF' if value['proof_observed'] else \
            'DB_READONLY_CONFIRMED_ABSENT'
        require(policy['candidate_evidence_origin'] == expected_origin and
                inputs.canonical_hash(policy['candidate_evidence_receipt_sha256']),
                'NONE candidate evidence must identify the verified Core readonly receipt')
        native = review['native_review_json']
        require(policy['candidate_version'] == native['policyVersion'] == '1' and
                policy['candidate_digest'] == native['policyDigest'] and
                inputs.canonical_hash(policy['candidate_digest']) and
                policy['candidate_current'] is False and policy['head_current'] is True,
                'NONE candidate differs from the reviewed tuple or current head is unverified')
        require(policy['head_version'] == '0' and policy['head_digest'] == '' and
                policy['head_source_status'] == policy['head_target_status'] == 'MISSING' and
                policy['head_bilateral_verified'] is False, 'fresh unconfigured NONE head differs')
    required = ('link.key_manifest', 'link.key_grants')
    if not is_key:
        required += ('link.review_policy_status', 'link.review_policy_preview')
    require(isinstance(value['reads'], list) and len(value['reads']) == len(required),
            'reconciliation requires exactly the frozen direct reads')
    operation_ids = set()
    previous_request, previous_response = 0, 0
    for index, read in enumerate(value['reads']):
        exact(read, {'operation', 'operation_id_sha256', 'request_sha256', 'response_sha256',
                     'request_sequence', 'response_sequence'}, 'encrypted direct read')
        require(read['operation'] == required[index], 'reconciliation read order or operation differs')
        require(all(inputs.canonical_hash(read[name]) for name in
                    ('operation_id_sha256', 'request_sha256', 'response_sha256')), 'read correlation hashes are invalid')
        request = inputs.bounded_long(read['request_sequence'], 1)
        response = inputs.bounded_long(read['response_sequence'], 1)
        require(request > previous_request and response > previous_response and
                read['operation_id_sha256'] not in operation_ids, 'direct read sequence or operation was reused')
        previous_request, previous_response = request, response
        operation_ids.add(read['operation_id_sha256'])


def record_reconciliation(record, value, case, binding, capture, review, receipt_sha256):
    """Record success only after validating the separately attributed evidence."""
    validate_reconciliation(value, case, binding, capture, review)
    record.update(result='PASS', phase='RECONCILED',
                  reconciliation_source='CORE_PARENT_SEPARATE_ENCRYPTED_OWNER_SESSION'
                      if case['operation'] == 'link.key_grant' else
                      'CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE',
                  reconciliation_receipt_sha256=receipt_sha256,
                  android_readonly_reconciliation='NOT_RUN', business_outcome='SEPARATELY_RECONCILED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--validate-plan', action='store_true')
    parser.add_argument('--root-go')
    parser.add_argument('--root-go-sha256')
    parser.add_argument('--parent-fd', type=int)
    args = parser.parse_args()
    os.umask(0o077)
    plan, raw = inputs.read_private_json(args.plan, args.plan_sha256)
    validate_plan(plan)
    if args.validate_plan:
        require(args.root_go is None and args.root_go_sha256 is None and args.parent_fd is None,
                'offline validation must not include runtime coordination')
        print(json.dumps({'result': 'PASS_OFFLINE_PLAN', 'cases': 8, 'plan_sha256': sha(raw),
                          'android_execution': 'NOT_RUN'}))
        return
    require(args.root_go is not None and args.root_go_sha256 is not None and args.parent_fd is not None,
            'exact Root GO and private parent channel are required')
    go, _ = inputs.read_private_json(args.root_go, args.root_go_sha256)
    expires = validate_go(go, sha(raw), plan['batch_id'])
    root = Path(plan['evidence_root'])
    require(root.is_dir() and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700 and
            not any(root.iterdir()), 'loop evidence must be fresh and caller-owned mode0700')
    require(expires - time.time() > 240, 'Root GO no longer has cleanup runway')
    # A create-only marker consumes GO before any coordination or child spawn.
    with (root / 'go-consumed.private.json').open('xb') as stream:
        stream.write(canonical({'plan_sha256': sha(raw), 'go_sha256': args.root_go_sha256}))
    outer = budget.Deadline.after(min(3600, expires - time.time()))
    work = budget.Deadline.after(outer.remaining() - 240, parent=outer)
    parent = ParentChannel(args.parent_fd, plan['batch_id'])
    driver = SelectorDriver(plan, budget.OwnedProcessRunner(), outer)
    try:
        result = RecoveryLoop(plan, parent, driver, outer, work).run()
    finally:
        parent.close()
    with (root / 'result.redacted.json').open('xb') as stream:
        stream.write(canonical(result))
    print(json.dumps({'result': result['result'], 'case_results': [item['result'] for item in result['cases']],
                      'android_cleanup': result['cleanup']['result']}))
    raise SystemExit(0 if result['result'] == 'PASS' else 1)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TimeoutError, RuntimeError, KeyError, TypeError):
        print('Recovery loop refused or stopped; retain private evidence.', file=sys.stderr)
        raise SystemExit(1)
