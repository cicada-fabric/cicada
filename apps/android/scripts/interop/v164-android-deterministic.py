#!/usr/bin/env python3
"""Run the Client v1.6.4 offline Android selector matrix in an owned emulator.

The command reuses the v1.5 instrumentation driver, but records v1.6.4 run IDs,
ownership labels, and the v1.6.4 selector matrix. It never starts or contacts a
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

sys.dont_write_bytecode = True


V15_PATH = Path(__file__).with_name('v15-android-deterministic.py')
_spec = importlib.util.spec_from_file_location('v15_deterministic_for_v164', V15_PATH)
v15 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v15)
driver = v15.driver
_recovery_spec = importlib.util.spec_from_file_location('v164_recovery_inputs',
    Path(__file__).with_name('v164-link-recovery-inputs.py'))
recovery_inputs = importlib.util.module_from_spec(_recovery_spec)
_recovery_spec.loader.exec_module(recovery_inputs)

SCHEMA = 'cicada.client-v164-deterministic.v1'
LABEL = 'org.cicada.client-v164-deterministic'
CONTRACT_REVISION = 'client-hub-v1.6.4'
CORE_REVISION = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
CORE_SOURCE_FINGERPRINT = '4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032'
CATALOG_SHA256 = '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'
HUB_IMAGE = 'sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4'
INTEROP_IMAGE = 'sha256:bcb8856c3d766c54c53e6c1dc1dcbe32beb2806c02260442610fde1af21cb6b1'
F6_APP_SHA256 = '56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67'
F6_TEST_SHA256 = 'caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6'
FIXTURE_PINS_PATH = Path(__file__).with_name('v164-link-fixture-pins.py')
F6_RUN_ID = re.compile(r'v16-deterministic-v164-f6-[A-Za-z0-9_-]{1,80}')
RECOVERY_RUN_ID = re.compile(r'v16-deterministic-v164-recovery-[A-Za-z0-9_-]{1,80}')
MATRIX = (
    ('client-wire-vectors', 'ClientWirePublicVectorTest', 5),
    ('endpoint-attestation-vectors', 'EndpointAttestationVectorTest', 4),
    ('link-key-vectors', 'LinkKeyManifestVerifierTest', 7),
    ('link-policy-canonical-vectors', 'LinkReviewPolicyConsentValidationTest', 9),
    ('v164-bilateral-policy-evidence', 'LinkReviewPolicyEvidenceV164Test', 13),
    ('native-link-authority', 'LinkConsentAuthorityFactoryTest', 5),
    ('durable-link-consent-ledger', 'LinkConsentLedgerTest', 4),
)
F6_MATRIX = (
    ('client-wire-vectors', 'ClientWirePublicVectorTest', 5),
    ('endpoint-attestation-vectors', 'EndpointAttestationVectorTest', 4),
    ('link-key-vectors', 'LinkKeyManifestVerifierTest', 7),
    ('link-policy-canonical-vectors', 'LinkReviewPolicyConsentValidationTest', 9),
    ('v164-bilateral-policy-evidence', 'LinkReviewPolicyEvidenceV164Test', 13),
    ('native-link-authority', 'LinkConsentAuthorityFactoryTest', 6),
    ('durable-link-consent-ledger', 'LinkConsentLedgerTest', 5),
)

# The delegated v1.5 helpers resolve these values in their own module globals.
v15.SCHEMA = SCHEMA
v15.LABEL = LABEL
v15.MATRIX = MATRIX


def add_delivery_arguments(parser):
    parser.add_argument('--delivery-pins', help='Root-trusted fresh F6 pins JSON')
    parser.add_argument('--delivery-pins-sha256', help='out-of-band SHA-256 of the exact Root pins bytes')
    parser.add_argument('--delivery-metadata', help='actual local delivery metadata JSON')
    parser.add_argument('--delivery-metadata-sha256', help='independently supplied SHA-256 of the exact metadata bytes')
    parser.add_argument('--fixture-root', help='Root-pinned fresh F6 fixture directory')
    parser.add_argument('--recovery-apk-pins', help='Root-owned clean e2a1908 recovery APK pins JSON')
    parser.add_argument('--recovery-apk-pins-sha256', help='independent SHA-256 of exact recovery APK pins bytes')


def read_f6_delivery(args):
    names = (
        'delivery_pins', 'delivery_pins_sha256', 'delivery_metadata',
        'delivery_metadata_sha256', 'fixture_root',
    )
    values = [getattr(args, name, None) for name in names]
    if not any(value is not None for value in values):
        return None
    if not all(value is not None for value in values):
        raise ValueError('F6 requires Root pins, both independent SHA-256 values, actual metadata, and fixture root')
    if not FIXTURE_PINS_PATH.is_file() or FIXTURE_PINS_PATH.is_symlink():
        raise ValueError('trusted F6 fixture pin validator is unavailable')
    spec = importlib.util.spec_from_file_location('v164_link_fixture_pins', FIXTURE_PINS_PATH)
    if spec is None or spec.loader is None:
        raise ValueError('trusted F6 fixture pin validator cannot be loaded')
    pins_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pins_module)
    pins = pins_module.read_trusted_delivery(
        args.delivery_pins,
        args.delivery_pins_sha256,
        args.delivery_metadata,
        args.delivery_metadata_sha256,
    )
    fixture = pins_module.validate_f6_fixture(pins, args.fixture_root)
    return pins, fixture


def f6_artifact_fields(args, verified=None):
    """Return the exact trusted pins to record and later recheck from source files."""
    verified = read_f6_delivery(args) if verified is None else verified
    if verified is None:
        return None
    pins, fixture = verified
    fixture_record = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in fixture.items()
    }
    return {
        'fixture_lane': 'F6',
        'root_delivery_pins_path': str(Path(args.delivery_pins)),
        'root_delivery_pins_sha256': pins['root_pins_sha256'],
        'delivery_metadata_path': pins['metadata_path'],
        'delivery_metadata_sha256': pins['delivery_metadata_sha256'],
        'fixture_root': str(fixture['root']),
        'root_delivery_pins': pins,
        'validated_f6_fixture': fixture_record,
    }


def f6_pinned_artifact_values(args, verified=None):
    verified = read_f6_delivery(args) if verified is None else verified
    if verified is None:
        return None
    pins, _fixture = verified
    return {
        'contract_revision': pins['contract_revision'],
        'core_source_revision': pins['core_revision'],
        'core_source_fingerprint': pins['source_fingerprint'],
        'catalog_sha256': pins['catalog_sha256'],
        'pinned_hub_image_id': pins['hub_image_id'],
        'pinned_interop_image_id': pins['interop_image_id'],
        'wire_version': pins['wire_version'],
        'schema_version': pins['schema_version'],
        'operation_count': pins['operation_count'],
        'source_dirty': pins['source_dirty'],
        'producer_sha256': pins['producer_sha256'],
        'package_sha256': pins['package_sha256'],
        **f6_artifact_fields(args, verified),
    }


def validate_existing_f6_artifacts(evidence, args, verified=None):
    verified = read_f6_delivery(args) if verified is None else verified
    artifacts_path = evidence / 'android-artifacts.json'
    if artifacts_path.is_symlink() or not artifacts_path.is_file():
        raise ValueError('Android artifact receipt is missing or unsafe')
    artifacts = json.loads(artifacts_path.read_text())
    if not isinstance(artifacts, dict):
        raise ValueError('Android artifact receipt must be a JSON object')
    run_id = evidence.parent.name
    recovery = recovery_inputs.read_apk_pins(args)
    if recovery is not None:
        if not RECOVERY_RUN_ID.fullmatch(run_id):
            raise ValueError('recovery APK pins require a fresh recovery evidence run')
        expected = recovery_inputs.artifact_fields(recovery)
        if any(artifacts.get(key) != value for key, value in expected.items()):
            raise ValueError('recovery artifact attribution differs from independently pinned APK inputs')
        for name in ('app', 'test'):
            path = evidence / ('installed-' + name + '.private.apk')
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != recovery[name + '_sha256']:
                raise ValueError('recovery installed APK bytes differ from Root pins')
        return artifacts
    if artifacts.get('fixture_lane') == recovery_inputs.RUN_SCOPE or RECOVERY_RUN_ID.fullmatch(run_id):
        raise ValueError('recovery evidence cannot fall back to historical delivery defaults')
    f6_markers = {
        'fixture_lane', 'root_delivery_pins_path', 'root_delivery_pins_sha256',
        'delivery_metadata_path', 'delivery_metadata_sha256', 'fixture_root',
        'root_delivery_pins', 'validated_f6_fixture',
    }
    if verified is None:
        if run_id.startswith('v16-deterministic-v164-f6-') or any(key in artifacts for key in f6_markers):
            raise ValueError('F6 artifact verification requires its Root pins and actual delivery metadata')
        if artifacts.get('app_sha256') == F6_APP_SHA256 or artifacts.get('test_sha256') == F6_TEST_SHA256:
            raise ValueError('F6 APKs cannot be used with the legacy 25bc selector matrix')
        return None
    if F6_RUN_ID.fullmatch(run_id) is None:
        raise ValueError('Root-pinned F6 metadata cannot be applied to a legacy evidence run')
    expected = f6_pinned_artifact_values(args, verified)
    if any(artifacts.get(key) != value for key, value in expected.items()):
        raise ValueError('saved F6 artifact receipt does not match independently reverified Root pins')
    for name, sha256 in (('app', F6_APP_SHA256), ('test', F6_TEST_SHA256)):
        path = evidence / ('installed-' + name + '.private.apk')
        if artifacts.get(name + '_sha256') != sha256 or path.is_symlink() or not path.is_file() or \
                hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
            raise ValueError('saved F6 ' + name + ' APK does not match its authorized binary pin')
    return artifacts


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
    if state != expected or not re.fullmatch(r'v16-deterministic-v164-[A-Za-z0-9_-]{1,80}', state['run_id']):
        raise ValueError('v1.6.4 emulator ownership marker mismatch')
    actual = subprocess.check_output([
        'docker', 'inspect', '--format',
        '{{.Image}} {{index .Config.Labels "' + LABEL + '"}} {{.HostConfig.NetworkMode}}',
        state['container'],
    ], text=True).strip().split()
    if actual != [driver.IMAGE, state['run_id'], 'none']:
        raise ValueError('refusing to operate a foreign v1.6.4 emulator')
    attached = json.loads(subprocess.check_output([
        'docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', state['container'],
    ], text=True))
    if set(attached) != {'none'}:
        raise ValueError('the v1.6.4 emulator must remain detached from Docker networks')
    return state


def start(evidence, args):
    run_id = evidence.parent.name
    if not re.fullmatch(r'v16-deterministic-v164-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('unsafe v1.6.4 evidence run name')
    delivery = read_f6_delivery(args)
    recovery = recovery_inputs.read_apk_pins(args)
    if recovery is not None:
        if not RECOVERY_RUN_ID.fullmatch(run_id) or any(evidence.iterdir()):
            raise ValueError('recovery pins require a completely fresh recovery evidence directory')
    elif RECOVERY_RUN_ID.fullmatch(run_id):
        raise ValueError('recovery run IDs cannot fall back to historical defaults')
    if delivery is not None:
        if F6_RUN_ID.fullmatch(run_id) is None:
            raise ValueError('Root-pinned delivery inputs require a new F6 run ID')
        if any(evidence.iterdir()):
            raise ValueError('F6 evidence must use a completely fresh empty directory')
    elif run_id.startswith('v16-deterministic-v164-f6-'):
        raise ValueError('F6 run IDs cannot fall back to legacy 25bc defaults')
    if (evidence / 'android-driver.json').exists() or \
            delivery is not None and (evidence / 'android-artifacts.json').exists():
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
    if delivery is not None:
        artifacts.update(f6_pinned_artifact_values(args, delivery))
    if recovery is not None:
        artifacts.update(recovery_inputs.artifact_fields(recovery))
    for name in ('app', 'test'):
        path = Path(getattr(args, name + '_apk'))
        expected = getattr(args, name + '_sha256')
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('expected a regular APK and full lowercase SHA-256')
        if delivery is not None and expected != (F6_APP_SHA256 if name == 'app' else F6_TEST_SHA256):
            raise ValueError('F6 only accepts the independently authorized application and test APK hashes')
        if recovery is not None and expected != recovery[name + '_sha256']:
            raise ValueError('recovery APK differs from independently supplied Root pins')
        if delivery is None and expected in (F6_APP_SHA256, F6_TEST_SHA256):
            raise ValueError('F6 APKs require Root pins and a fresh F6 evidence run')
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


def test(evidence, state, args, verified=None):
    artifacts = validate_existing_f6_artifacts(evidence, args, verified)
    selected_matrix = F6_MATRIX if artifacts is not None else MATRIX
    original_matrix = v15.MATRIX
    try:
        v15.MATRIX = selected_matrix
        result = v15.install_and_test(evidence, state)
    finally:
        v15.MATRIX = original_matrix
    summary_path = evidence / 'deterministic-summary.redacted.json'
    summary = json.loads(summary_path.read_text())
    summary.update(schema=SCHEMA, run_id=state['run_id'], contract_revision=CONTRACT_REVISION,
        matrix_lane=artifacts.get('fixture_lane', 'F6') if artifacts is not None else 'legacy-25bc')
    driver.save(summary_path, summary)
    return result


def ui(evidence, state, args, verified=None):
    artifacts = validate_existing_f6_artifacts(evidence, args, verified)
    result = v15.ui_smoke(evidence, state)
    summary_path = evidence / 'ui-smoke-summary.redacted.json'
    summary = json.loads(summary_path.read_text())
    summary.update(schema=SCHEMA, run_id=state['run_id'], contract_revision=CONTRACT_REVISION,
        matrix_lane=artifacts.get('fixture_lane', 'F6') if artifacts is not None else 'legacy-25bc')
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
    add_delivery_arguments(prepare)
    test_parser = commands.add_parser('test')
    add_delivery_arguments(test_parser)
    ui_parser = commands.add_parser('ui', aliases=['ui-smoke'])
    add_delivery_arguments(ui_parser)
    commands.add_parser('stop')
    args = parser.parse_args()
    evidence = driver.private_evidence(args.evidence)
    if args.action == 'start':
        result = start(evidence, args)
    elif args.action == 'stop':
        state = owned_state(evidence)
        result = stop(evidence, state)
    else:
        verified = read_f6_delivery(args)
        validate_existing_f6_artifacts(evidence, args, verified)
        state = owned_state(evidence)
        if args.action == 'test':
            result = test(evidence, state, args, verified)
        elif args.action in ('ui', 'ui-smoke'):
            result = ui(evidence, state, args, verified)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
