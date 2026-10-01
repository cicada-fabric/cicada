#!/usr/bin/env python3
"""Run the Client v1.6.1 offline Android selector matrix in an owned emulator.

The command reuses the v1.5 instrumentation driver, but records v1.6.1 run IDs,
ownership labels, and the v1.6.1 selector matrix. It never starts or contacts a
Hub. APK hashes are mandatory before an emulator can start.
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


V15_PATH = Path(__file__).with_name('v15-android-deterministic.py')
_spec = importlib.util.spec_from_file_location('v15_deterministic_for_v16', V15_PATH)
v15 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v15)
driver = v15.driver

SCHEMA = 'cicada.client-v161-deterministic.v1'
LABEL = 'org.cicada.client-v161-deterministic'
CONTRACT_REVISION = 'client-hub-v1.6.1'
CORE_REVISION = 'fe565b41bb1aa86d400a0ec98c528c856d0b9579'
CORE_SOURCE_FINGERPRINT = '6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be'
CATALOG_SHA256 = '6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b'
HUB_IMAGE = 'sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589'
INTEROP_IMAGE = 'sha256:a6a88de73b1c8c00b38fafb4e9236c404b52b06165527a0b4e097c0f17f3a6be'
MATRIX = (
    ('hub-profiles', 'HubProfileStoreTest', 10),
    ('network-key-vectors', 'NetworkKeyConsentVectorTest', 6),
    ('network-session-guards', 'NetworkSessionGuardTest', 8),
    ('client-wire-vectors', 'ClientWirePublicVectorTest', 5),
    ('endpoint-attestation-vectors', 'EndpointAttestationVectorTest', 4),
    ('monitor-broadcast-vectors', 'MonitorBroadcastVectorTest', 6),
    ('recovery-locks', 'ClientHubRecoveryLockTest', 6),
    ('v16-operation-policy', 'ClientHubV16OperationPolicyTest', 6),
    ('link-review-policy-status-validation', 'LinkReviewPolicyStatusValidationTest', 5),
    ('network-production-vectors', 'NetworkKeyProductionVectorTest', 5),
    ('owner-link-review-policy-vectors', 'OwnerLinkReviewPolicyV1VectorTest', 3),
    ('network-collaboration-broadcast-vectors', 'NetworkCollaborationBroadcastConsentV1VectorTest', 3),
    ('network-collaboration-task-vectors', 'NetworkCollaborationTaskV1VectorTest', 3),
    ('node-control-key-binding', 'NodeControlKeyBindingVerifierTest', 3),
    ('regroup-delegation-validation', 'RegroupDelegationValidationTest', 8),
)

# The delegated v1.5 helpers resolve these values in their own module globals.
v15.SCHEMA = SCHEMA
v15.LABEL = LABEL
v15.MATRIX = MATRIX


def owned_state(evidence):
    state = json.loads((evidence / 'android-driver.json').read_text())
    expected = {
        'schema': SCHEMA,
        'run_id': evidence.parent.name,
        'container': 'cicada-' + evidence.parent.name,
        'image_id': driver.IMAGE,
        'emulator_port': 5640,
        'adb_port': 5070,
        'evidence': str(evidence),
        'network': 'none',
    }
    if state != expected or not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', state['run_id']):
        raise ValueError('v1.6.1 emulator ownership marker mismatch')
    actual = subprocess.check_output([
        'docker', 'inspect', '--format',
        '{{.Image}} {{index .Config.Labels "' + LABEL + '"}} {{.HostConfig.NetworkMode}}',
        state['container'],
    ], text=True).strip().split()
    if actual != [driver.IMAGE, state['run_id'], 'none']:
        raise ValueError('refusing to operate a foreign v1.6.1 emulator')
    attached = json.loads(subprocess.check_output([
        'docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', state['container'],
    ], text=True))
    if set(attached) != {'none'}:
        raise ValueError('the v1.6.1 emulator must remain detached from Docker networks')
    return state


def start(evidence, args):
    run_id = evidence.parent.name
    if not re.fullmatch(r'v16-deterministic-v161-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('unsafe v1.6.1 evidence run name')
    if (evidence / 'android-driver.json').exists():
        raise ValueError('this evidence directory already owns an emulator')

    artifacts = {
        'contract_revision': CONTRACT_REVISION,
        'core_source_revision': CORE_REVISION,
        'core_source_fingerprint': CORE_SOURCE_FINGERPRINT,
        'catalog_sha256': CATALOG_SHA256,
        'pinned_hub_image_id': HUB_IMAGE,
        'pinned_interop_image_id': INTEROP_IMAGE,
        'client_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=driver.REPO, text=True).strip(),
        'observed_checkout_source_fingerprint': v15.source_fingerprint(),
        'source_observation': 'checkout observed at emulator start; CLI APK hashes identify installed binaries',
        'physical_android': 'NOT_RUN',
        'public_https': 'NOT_RUN',
    }
    for name in ('app', 'test'):
        path = Path(getattr(args, name + '_apk'))
        expected = getattr(args, name + '_sha256')
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
    actual_image = subprocess.check_output(
        ['docker', 'image', 'inspect', driver.IMAGE, '--format', '{{.Id}}'], text=True
    ).strip()
    if actual_image != driver.IMAGE:
        raise ValueError('emulator image mismatch')

    state = {
        'schema': SCHEMA,
        'run_id': run_id,
        'container': 'cicada-' + run_id,
        'image_id': driver.IMAGE,
        'emulator_port': 5640,
        'adb_port': 5070,
        'evidence': str(evidence),
        'network': 'none',
    }
    driver.save(evidence / 'android-artifacts.json', artifacts)
    driver.save(evidence / 'android-driver.json', state)
    driver.run(evidence, 'emulator-start', [
        'docker', 'run', '--rm', '-d', '--user', 'root',
        '--name', state['container'], '--label', LABEL + '=' + run_id,
        '--device', '/dev/kvm', '--network', 'none',
        '-e', 'CICADA_TWO_OWNER_EMULATOR_PORT=5640',
        '-e', 'ANDROID_ADB_SERVER_PORT=5070',
        '-e', f'CICADA_EVIDENCE_OWNER={os.getuid()}:{os.getgid()}',
        '-v', f'{driver.REPO}:/workspace:ro', '-v', f'{evidence}:/out',
        # The existing v1.5 install helper expects these in-container paths.
        '-v', f'{evidence}/installed-app.private.apk:/tmp/cicada-v15-app.apk:ro',
        '-v', f'{evidence}/installed-test.private.apk:/tmp/cicada-v15-test.apk:ro',
        driver.IMAGE, 'bash', '/workspace/scripts/interop/two-owner-emulator.sh',
    ])
    return {'result': 'BOOTING', 'evidence': str(evidence), 'run_id': run_id}


def test(evidence, state):
    result = v15.install_and_test(evidence, state)
    summary_path = evidence / 'deterministic-summary.redacted.json'
    summary = json.loads(summary_path.read_text())
    summary.update(schema=SCHEMA, run_id=state['run_id'], contract_revision=CONTRACT_REVISION)
    driver.save(summary_path, summary)
    return result


def ui(evidence, state):
    result = v15.ui_smoke(evidence, state)
    summary_path = evidence / 'ui-smoke-summary.redacted.json'
    summary = json.loads(summary_path.read_text())
    summary.update(schema=SCHEMA, run_id=state['run_id'], contract_revision=CONTRACT_REVISION)
    driver.save(summary_path, summary)
    return result


def stop(evidence, state):
    driver.run(evidence, 'emulator-stop', ['docker', 'stop', '--time', '10', state['container']])
    verification = ['docker', 'inspect', state['container'], '--format', '{{.Id}}']
    deadline = time.monotonic() + 10
    attempts = []
    while True:
        absent = subprocess.run(verification, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        removed = absent.returncode == 1 and b'no such object' in absent.stderr.lower()
        attempts.append({'exit_code': absent.returncode, 'absence_confirmed': removed})
        driver.save(evidence / 'emulator-absence-check.redacted.json', {
            'schema': SCHEMA,
            'command': verification,
            'attempts': attempts,
            'result': 'PASS' if removed else 'WAITING',
        })
        if removed:
            break
        if absent.returncode != 0 or time.monotonic() >= deadline:
            driver.save(evidence / 'emulator-absence-check.redacted.json', {
                'schema': SCHEMA, 'command': verification, 'attempts': attempts, 'result': 'FAIL',
            })
            raise RuntimeError('owned emulator removal was not confirmed')
        time.sleep(0.2)
    result = {
        'schema': SCHEMA,
        'result': 'PASS',
        'owned_emulator_removed': True,
        'verification_command': verification,
        'docker_inspect_exit_code': 1,
    }
    driver.save(evidence / 'android-teardown.redacted.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    commands = parser.add_subparsers(dest='action', required=True)
    prepare = commands.add_parser('start')
    for name in ('app', 'test'):
        prepare.add_argument('--' + name + '-apk', required=True)
        prepare.add_argument('--' + name + '-sha256', required=True)
    commands.add_parser('test')
    commands.add_parser('ui', aliases=['ui-smoke'])
    commands.add_parser('stop')
    args = parser.parse_args()
    evidence = driver.private_evidence(args.evidence)
    if args.action == 'start':
        result = start(evidence, args)
    else:
        state = owned_state(evidence)
        if args.action == 'test':
            result = test(evidence, state)
        elif args.action in ('ui', 'ui-smoke'):
            result = ui(evidence, state)
        else:
            result = stop(evidence, state)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
