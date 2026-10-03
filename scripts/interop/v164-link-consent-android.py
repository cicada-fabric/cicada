#!/usr/bin/env python3
"""Stage public v1.6.4 Link inputs and run one bounded Android selector.

The emulator must already be owned by v164-android-deterministic.py. Inputs
are read from private host files and sent only on stdin through run-as; selector
arguments contain only the public run ID and method name. This tool never starts
or contacts a Hub and never exports Android Keystore or session-state files.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise ValueError('required interop module is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('v164_android_driver', 'v164-android-deterministic.py')
driver = runner.driver
link = load('v16_link_status_helpers', 'v16-link-review-policy-status.py')

SCHEMA = 'cicada.client-v164-link-consent-driver.v1'
TEST_CLASS = 'ai.cicada.client.hub.LinkConsentInteropTest'
SELECTION_SCHEMA = 'cicada.client-v164-link-consent-selection.v2'
ONBOARDING_SCHEMA = 'cicada.client-v164-onboarding-public.v1'
DEVICE_SCHEMA = 'cicada.client-v164-device-public-handoff.v1'
GRANT_SCHEMA = 'cicada.client-v164-owner-device-grant-handoff.v1'
REVIEW_SCHEMA = 'cicada.client-v164-link-consent-review-handoff.v1'
PROOF_SCHEMA = 'cicada.client-v164-owner-signed-proof.v1'
POLICY_SCHEMA = 'cicada.client-v164-review-policy-fixture.v1'
RECOVERY_SCHEMA = 'cicada.client-v164-link-consent-recovery-scenario.v1'
CATALOG_SHA256 = runner.CATALOG_SHA256
MAX_INPUT = 256 * 1024
MAX_OUTPUT = 512 * 1024
HEX64 = re.compile(r'[0-9a-f]{64}')
RUN_ID = re.compile(r'v164-[A-Za-z0-9_-]{1,72}')
SIDES = {'source', 'target'}
RUNTIME_PROPERTIES = {
    'api_level': ('ro.build.version.sdk', '35'),
    'android_release': ('ro.build.version.release', '15'),
    'abi': ('ro.product.cpu.abi', 'x86_64'),
    'emulator': ('ro.kernel.qemu', '1'),
}

PACKAGE = driver.PACKAGE
REMOTE_ROOT = 'no_backup/link-v164'

STAGE_FILES = {
    'source-setup-public.json': ('setup', 'source'),
    'target-setup-public.json': ('setup', 'target'),
    'source-owner-device-grant.private.json': ('grant', 'source'),
    'target-owner-device-grant.private.json': ('grant', 'target'),
    'selection.json': ('selection', None),
    'review-policy.json': ('policy', None),
    'source-key-proof.private.json': ('proof-key', 'source'),
    'target-key-proof.private.json': ('proof-key', 'target'),
    'source-policy-proof.private.json': ('proof-policy', 'source'),
    'target-policy-proof.private.json': ('proof-policy', 'target'),
    'source-negative-key-proof.private.json': ('proof-negative', 'source'),
    'target-negative-key-proof.private.json': ('proof-negative', 'target'),
    'source-recovery-scenario.json': ('recovery', 'source'),
    'target-recovery-scenario.json': ('recovery', 'target'),
}

SELECTORS = {
    'exportSourceOwnerDeviceIdentityForHostGrant': ('source', 'source-onboarding-device.redacted.json', 'source-onboarding-device'),
    'enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities': ('source', 'source-onboarding-enroll.redacted.json', 'source-onboarding-enroll'),
    'exportTargetOwnerDeviceIdentityForHostGrant': ('target', 'target-onboarding-device.redacted.json', 'target-onboarding-device'),
    'enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities': ('target', 'target-onboarding-enroll.redacted.json', 'target-onboarding-enroll'),
    'confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval': (None, 'owner-pins.redacted.json', 'owner-pins'),
    'exportsFreshCurrentKeyReviewForExternalSigner': (None, 'key-review-export.redacted.json', 'key-review-export'),
    'submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus': (None, 'key-proof-submit.redacted.json', 'key-proof-submit'),
    'exportsReviewPolicyCandidateForExternalSigner': (None, 'policy-review-export.redacted.json', 'policy-review-export'),
    'submitsHostSignedPolicyProofAndRevalidatesFreshV164Status': (None, 'policy-proof-submit.redacted.json', 'policy-proof-submit'),
    'rejectsWrongPinAndGenericRpcBypassWithoutConsumingSequence': (None, 'negative-local-guards.redacted.json', 'negative-local-guards'),
    'exportsFreshKeyReviewForTamperedProofNegativeCase': (None, 'negative-proof-review-export.redacted.json', 'negative-proof-review-export'),
    'rejectsTamperedFreshOwnerProofBeforeLinkGrantWrite': (None, 'negative-proof-submit.redacted.json', 'negative-proof-submit'),
    'recoversOnlyAnExplicitlySelectedOriginalConsentOperation': (None, 'exact-recovery.redacted.json', 'exact-recovery'),
}

EXPORT_FILES = {
    f'{side}-device-public.private.json' for side in SIDES
} | {
    f'{side}-{kind}-review.private.json'
    for side in SIDES for kind in ('key', 'policy', 'negative-key')
} | {
    f'{side}-{stage}.redacted.json'
    for side in SIDES for stage in (
        'onboarding', 'onboarding-device', 'onboarding-enroll', 'owner-pins', 'key-review-export',
        'key-proof-submit', 'policy-review-export', 'policy-proof-submit',
        'negative-local-guards', 'negative-proof-review-export', 'negative-proof-submit',
        'exact-recovery',
    )
} | {'selection.redacted.json'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=link._unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('invalid JSON number')))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError('input JSON is malformed or contains duplicate fields') from error
    if not isinstance(value, dict):
        raise ValueError('input JSON must be an object')
    return value


def secret_fields(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = key.lower().replace('-', '_')
            if any(word in lowered for word in ('private_key', 'privatekey', 'seed', 'bearer', 'token', 'password', 'credential', 'secret')):
                return True
            if secret_fields(nested):
                return True
    elif isinstance(value, list):
        return any(secret_fields(item) for item in value)
    return False


def checked_id(value):
    return link.valid_id(value)


def validate_runtime_receipt(runtime):
    """Accept only the exact v1.5 or F9 v1.6.4 producer receipt shape."""
    properties = {key: value for key, (_property, value) in RUNTIME_PROPERTIES.items()}
    # The F9 producer records its v1.6.4 schema and image_id. The exact Android
    # getprop values below identify the platform because this producer omits the
    # older explicit platform tag.
    f9 = {'schema': runner.SCHEMA, 'image_id': runner.driver.IMAGE, **properties}
    if runtime == f9:
        return 'f9'

    # The v1.5 producer records an explicit platform and emulator_image_id.
    # Its network field was historically optional, but if present must say none;
    # the separately checked ownership marker and Docker inspection remain the
    # authority for the actual network attachment.
    legacy = {'platform': 'Android emulator', 'emulator_image_id': runner.driver.IMAGE, **properties}
    if runtime in (legacy, {**legacy, 'network': None}, {**legacy, 'network': 'none'}):
        return 'legacy'
    raise ValueError('owned emulator runtime metadata is inconsistent')


def read_receipt(evidence, name):
    return link.read_private_json(evidence / name, maximum=16 * 1024)[0]


def validate_f9_property_receipts(evidence, state):
    """Verify all four raw F9 adb getprop command receipts exactly."""
    properties = {}
    for field, (prop, expected_output) in RUNTIME_PROPERTIES.items():
        receipt = read_receipt(evidence, 'runtime-' + field + '.json')
        expected = {
            'command': [*driver.adb(state), 'shell', 'getprop', prop],
            'result': 'PASS',
            'output': expected_output,
        }
        if set(receipt) != {'command', 'exit_code', 'expected_exit_code', 'result', 'output'} or \
                type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0 or \
                type(receipt.get('expected_exit_code')) is not int or receipt['expected_exit_code'] != 0 or \
                any(receipt.get(key) != value for key, value in expected.items()):
            raise ValueError('F9 Android runtime property receipt is inconsistent')
        properties[field] = receipt['output']
    return properties


def inspect_readonly(argv):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=10, text=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError('read-only Docker bootstrap inspection failed') from error
    if result.returncode != 0:
        raise ValueError('read-only Docker bootstrap inspection failed')
    return result.stdout.strip()


def bootstrap_preflight(evidence, state=None):
    """Read-only Android boot/runtime check; it does not establish Hub readiness."""
    state = runner.owned_state(evidence) if state is None else state
    if state.get('image_id') != runner.driver.IMAGE or state.get('network') != 'none':
        raise ValueError('bootstrap preflight requires the exact offline emulator image')
    if not runner.F6_RUN_ID.fullmatch(state['run_id']):
        raise ValueError('bootstrap preflight requires an F6-format Android evidence run')

    marker = read_receipt(evidence, 'emulator-ready.json')
    expected_marker = {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'}
    if marker != expected_marker:
        raise ValueError('F9 emulator READY marker is inconsistent')

    id_argv = ['docker', 'inspect', '--format', '{{.Id}}', state['container']]
    id_receipt = read_receipt(evidence, 'container-id.json')
    if set(id_receipt) != {'command', 'exit_code', 'expected_exit_code', 'result', 'output'} or \
            id_receipt.get('command') != id_argv or id_receipt.get('result') != 'PASS' or \
            type(id_receipt.get('exit_code')) is not int or id_receipt['exit_code'] != 0 or \
            type(id_receipt.get('expected_exit_code')) is not int or id_receipt['expected_exit_code'] != 0 or \
            not isinstance(id_receipt.get('output'), str) or not re.fullmatch(r'[0-9a-f]{64}', id_receipt['output']):
        raise ValueError('F9 container ID receipt is inconsistent')
    readiness = read_receipt(evidence, 'emulator-readiness.redacted.json')
    if set(readiness) != {'container_id', 'marker', 'observed_at_utc', 'result'} or \
            readiness.get('result') != 'READY' or readiness.get('marker') != expected_marker or \
            readiness.get('container_id') != id_receipt['output'] or \
            not isinstance(readiness.get('observed_at_utc'), str) or not readiness['observed_at_utc']:
        raise ValueError('F9 readiness receipt is not bound to the owned container')

    actual_id = inspect_readonly(id_argv)
    if actual_id != id_receipt['output']:
        raise ValueError('current Docker container ID differs from the F9 READY receipt')
    status = inspect_readonly(['docker', 'inspect', '--format',
        '{{.State.Running}} {{.State.Status}}', state['container']])
    if status != 'true running':
        raise ValueError('the owned F9 Android emulator is not running')

    runtime = read_receipt(evidence, 'android-runtime.redacted.json')
    if validate_runtime_receipt(runtime) != 'f9':
        raise ValueError('F9 bootstrap preflight requires the F9 runtime receipt shape')
    properties = validate_f9_property_receipts(evidence, state)
    return {
        'result': 'ANDROID_BOOTSTRAP_CHECK_PASS',
        'run_id': state['run_id'],
        'container_id': actual_id,
        'image_id': runner.driver.IMAGE,
        'network': 'none',
        'runtime_properties': properties,
        'hub': 'NOT_CHECKED',
        'root_delivery': 'NOT_CHECKED',
    }


def canonical_identity_string(raw):
    value = parse_json(raw.encode())
    if list(value) != ['id', 'kem_public', 'signing_public'] or \
            not isinstance(value.get('id'), str) or not re.fullmatch(r'pq1-[0-9a-f]{32}', value['id']) or \
            any(not isinstance(value.get(name), str) for name in ('kem_public', 'signing_public')):
        raise ValueError('Owner public identity JSON has an invalid bounded shape')
    if json.dumps(value, separators=(',', ':'), ensure_ascii=False) != raw:
        raise ValueError('Owner public identity JSON must use the canonical field order and bytes')
    validate_identity(value)
    return value


def validate_identity(value):
    if not isinstance(value, dict) or list(value) != ['id', 'kem_public', 'signing_public'] or \
            not isinstance(value.get('id'), str) or not re.fullmatch(r'pq1-[0-9a-f]{32}', value['id']):
        raise ValueError('Owner public identity JSON has an invalid bounded shape')
    decoded_keys = []
    for field, expected in (('kem_public', 1184), ('signing_public', 1952)):
        encoded = value.get(field)
        if not isinstance(encoded, str):
            raise ValueError('Owner public identity JSON has an invalid bounded shape')
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError('Owner public identity key is not canonical base64') from error
        if len(decoded) != expected or base64.b64encode(decoded).decode() != encoded:
            raise ValueError('Owner public identity key has an invalid encoding or size')
        decoded_keys.append(decoded)
    expected_id = 'pq1-' + hashlib.sha256(decoded_keys[0] + decoded_keys[1]).digest()[:16].hex()
    if value['id'] != expected_id:
        raise ValueError('Owner public identity ID does not derive from its public keys')


def validate_setup(value, side, run_id):
    fields = {'schema', 'run_id', 'base_url', 'hub_id', 'owner_id', 'owner_key_id', 'device_id',
        'catalog_sha256', 'control_public_identity', 'owner_public_identity'}
    if set(value) != fields or value.get('schema') != ONBOARDING_SCHEMA or value.get('run_id') != run_id or \
            value.get('catalog_sha256') != CATALOG_SHA256 or not isinstance(value.get('base_url'), str) or \
            not 8 <= len(value['base_url']) <= 2048 or value['base_url'] != value['base_url'].strip():
        raise ValueError(f'{side} public onboarding fixture schema or contract pin is invalid')
    url = urlsplit(value['base_url'])
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError(f'{side} public onboarding URL must not contain embedded credentials or query data')
    if any(not checked_id(value.get(key)) for key in ('hub_id', 'owner_id', 'owner_key_id', 'device_id')):
        raise ValueError(f'{side} public onboarding IDs are invalid')
    for key in ('control_public_identity', 'owner_public_identity'):
        identity = value.get(key)
        validate_identity(identity)
    if value['owner_public_identity']['id'] != value['owner_key_id']:
        raise ValueError(f'{side} Owner key ID does not match its public identity')


def validate_selection(value, run_id, reference):
    fields = {'schema', 'run_id', 'profile_id', 'profile_generation', 'hub_id', 'owner_id', 'device_id',
        'link_id', 'expected_link_version', 'catalog_sha256', 'source_owner_pin', 'target_owner_pin'}
    if set(value) != fields or value.get('schema') != SELECTION_SCHEMA or value.get('run_id') != run_id or \
            value.get('catalog_sha256') != CATALOG_SHA256:
        raise ValueError('Link selection schema, run ID, or catalog pin is invalid')
    if not isinstance(value.get('profile_id'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', value['profile_id']) or \
            type(value.get('profile_generation')) is not int or not 1 <= value['profile_generation'] <= 9_007_199_254_740_991 or \
            type(value.get('expected_link_version')) is not int or not 1 <= value['expected_link_version'] <= 9_007_199_254_740_991:
        raise ValueError('Link selection profile generation or version is invalid')
    for key in ('hub_id', 'owner_id', 'device_id', 'link_id'):
        if not checked_id(value.get(key)):
            raise ValueError('Link selection contains an invalid identifier')
    pins = []
    for key in ('source_owner_pin', 'target_owner_pin'):
        pin = value.get(key)
        if not isinstance(pin, dict) or set(pin) != {'owner_id', 'key_id', 'public_identity_json', 'fingerprint'} or \
                not checked_id(pin.get('owner_id')) or not isinstance(pin.get('key_id'), str) or \
                not re.fullmatch(r'pq1-[0-9a-f]{32}', pin['key_id']):
            raise ValueError('Link selection Owner pin shape is invalid')
        identity = canonical_identity_string(pin['public_identity_json'])
        fingerprint = pin.get('fingerprint')
        fingerprint = fingerprint.removeprefix('sha256:') if isinstance(fingerprint, str) else ''
        expected_fingerprint = hashlib.sha256(
            b'cicada/client/device-public-key/v1\0' + pin['public_identity_json'].encode()).hexdigest()
        if identity['id'] != pin['key_id'] or fingerprint != expected_fingerprint:
            raise ValueError('Link selection Owner identity key ID or fingerprint is invalid')
        pins.append(pin)
    if pins[0]['owner_id'] == pins[1]['owner_id'] or pins[0]['key_id'] == pins[1]['key_id'] or \
            value['owner_id'] not in {pins[0]['owner_id'], pins[1]['owner_id']}:
        raise ValueError('Link selection must pin distinct source/target Owners and select one')
    role = 'source' if value['owner_id'] == pins[0]['owner_id'] else 'target'
    if reference is None:
        raise ValueError('Link selection staging requires a fresh exported device-profile handoff')
    device_fields = {'schema', 'run_id', 'owner_role', 'profile_id', 'profile_generation', 'hub_id', 'owner_id',
        'owner_key_id', 'device_id', 'catalog_sha256', 'device_public_identity', 'device_public_identity_sha256'}
    device_identity = reference.get('device_public_identity')
    validate_identity(device_identity)
    device_identity_json = json.dumps(device_identity, separators=(',', ':'), ensure_ascii=False)
    if set(reference) != device_fields or reference.get('schema') != DEVICE_SCHEMA or reference.get('run_id') != run_id or \
            reference.get('catalog_sha256') != CATALOG_SHA256 or type(reference.get('profile_generation')) is not int or \
            reference.get('device_public_identity_sha256') != digest(device_identity_json.encode()) or \
            reference.get('profile_id') != value['profile_id'] or reference.get('profile_generation') != value['profile_generation'] or \
            reference.get('hub_id') != value['hub_id'] or reference.get('owner_id') != value['owner_id'] or \
            reference.get('device_id') != value['device_id']:
        raise ValueError('Link selection differs from its exact exported device-profile handoff')
    if reference.get('owner_role') != role:
        raise ValueError('Link selection does not match the selected fresh device-profile handoff')
    local_pin = pins[0] if role == 'source' else pins[1]
    if reference.get('owner_key_id') != local_pin['key_id']:
        raise ValueError('Link selection does not match its independently pinned local Owner key')
    return role


def validate_grant(value, side, run_id, device):
    fields = {'schema', 'run_id', 'profile_id', 'profile_generation', 'hub_id', 'owner_id', 'owner_key_id',
        'device_id', 'catalog_sha256', 'device_public_identity_sha256', 'owner_device_grant_base64', 'grant_sha256'}
    if set(value) != fields or value.get('schema') != GRANT_SCHEMA or value.get('run_id') != run_id or \
            value.get('catalog_sha256') != CATALOG_SHA256:
        raise ValueError(f'{side} OwnerDeviceGrant handoff schema is invalid')
    device_fields = {'schema', 'run_id', 'owner_role', 'profile_id', 'profile_generation', 'hub_id', 'owner_id',
        'owner_key_id', 'device_id', 'catalog_sha256', 'device_public_identity', 'device_public_identity_sha256'}
    identity = device.get('device_public_identity') if isinstance(device, dict) else None
    if device is not None:
        validate_identity(identity)
    if device is None or set(device) != device_fields or device.get('schema') != DEVICE_SCHEMA or \
            device.get('run_id') != run_id or device.get('catalog_sha256') != CATALOG_SHA256 or \
            device.get('device_public_identity_sha256') != digest(
                json.dumps(identity, separators=(',', ':'), ensure_ascii=False).encode()) or \
            device.get('owner_role') != side or \
            any(value.get(key) != device.get(key) for key in (
                'profile_id', 'profile_generation', 'hub_id', 'owner_id', 'owner_key_id', 'device_id',
                'device_public_identity_sha256')):
        raise ValueError(f'{side} OwnerDeviceGrant does not match its fresh device identity handoff')
    validate_public_signature(value['owner_device_grant_base64'], value['grant_sha256'], 32 * 1024)


def validate_public_signature(encoded, expected_sha, max_bytes):
    if not isinstance(encoded, str) or not 4 <= len(encoded) <= max_bytes * 2 or not isinstance(expected_sha, str) or \
            not HEX64.fullmatch(expected_sha):
        raise ValueError('bounded signed public proof or digest is invalid')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError('signed public proof is not canonical base64') from error
    if not raw or len(raw) > max_bytes or base64.b64encode(raw).decode() != encoded or digest(raw) != expected_sha:
        raise ValueError('signed public proof bytes do not match their digest')


def validate_review_handoff(value, kind, run_id):
    fields = {'schema', 'run_id', 'kind', 'review_id', 'consent_digest', 'link_id', 'link_version',
        'side', 'owner_id', 'owner_key_id', 'signing_request_json', 'native_review_json'}
    if kind == 'REVIEW_POLICY':
        fields.add('policy_json')
    if not isinstance(value, dict) or set(value) != fields or value.get('schema') != REVIEW_SCHEMA or \
            value.get('run_id') != run_id or value.get('kind') != kind or \
            not isinstance(value.get('native_review_json'), dict):
        raise ValueError('native review handoff schema is invalid')
    native = value['native_review_json']
    native_fields = {'reviewId', 'consentDigest', 'linkId', 'linkVersion', 'side', 'manifestDigest',
        'contractDigest', 'sourceEndpointId', 'sourceGroupId', 'targetEndpointId', 'targetGroupId',
        'direction', 'actions', 'dataScopes', 'expiresAt', 'sourceKeyFingerprint', 'targetKeyFingerprint',
        'maximumProofExpiresAt', 'ownerKeyId', 'ownerKeyFingerprint', 'peerOwnerKeyFingerprint',
        'qualifications', 'signingRequestJson'}
    if kind == 'REVIEW_POLICY':
        native_fields |= {'policyDigest', 'policyVersion'}
        if 'currentPolicyStatus' in native:
            native_fields.add('currentPolicyStatus')
            current = native['currentPolicyStatus']
            if not isinstance(current, dict) or set(current) != {
                    'policyVersion', 'digest', 'current', 'sourceStatus', 'targetStatus', 'bilateralVerified'}:
                raise ValueError('current policy status in review handoff is malformed')
    if set(native) != native_fields:
        raise ValueError('native review DTO has missing or unexpected fields')
    for outer, inner in (('review_id', 'reviewId'), ('consent_digest', 'consentDigest'),
            ('link_id', 'linkId'), ('link_version', 'linkVersion'), ('side', 'side')):
        if value.get(outer) != native.get(inner):
            raise ValueError('review handoff does not match its native DTO')
    if not isinstance(value.get('consent_digest'), str) or not HEX64.fullmatch(value['consent_digest']) or \
            not isinstance(value.get('link_version'), str) or not re.fullmatch(r'[1-9][0-9]*', value['link_version']) or \
            value.get('side') not in {'SOURCE', 'TARGET'}:
        raise ValueError('native review handoff tuple is malformed')
    if native.get('ownerKeyId') != value.get('owner_key_id'):
        raise ValueError('native review handoff Owner key differs from its envelope')
    signer_text = value.get('signing_request_json')
    if not isinstance(signer_text, str) or signer_text != native.get('signingRequestJson'):
        raise ValueError('review signer envelope differs from its native DTO')
    signer = parse_json(signer_text.encode())
    signer_fields = {'schema', 'kind', 'owner_id', 'owner_key_id', 'owner_key_fingerprint', 'link_id',
        'link_version', 'contract_digest', 'side', 'max_expiry', 'expires_at'}
    signer_fields |= {'manifest_digest'} if kind == 'KEY' else {
        'policy_digest', 'expected_policy_version', 'policy_version'}
    link_version = signer.get('link_version')
    if set(signer) != signer_fields or signer.get('schema') != 'cicada.client.link-consent-signing-request.v1' or \
            signer.get('kind') != kind or signer.get('link_id') != value['link_id'] or \
            type(link_version) is not int or not 1 <= link_version <= 9_223_372_036_854_775_807 or \
            str(link_version) != value['link_version'] or signer.get('side') != value['side'] or \
            signer.get('contract_digest') != native.get('contractDigest') or \
            signer.get('owner_id') != value['owner_id'] or signer.get('owner_key_id') != value['owner_key_id']:
        raise ValueError('native Owner signer envelope is not bound to its review handoff')
    native_fingerprint = native.get('ownerKeyFingerprint')
    if not isinstance(native_fingerprint, str) or not native_fingerprint.startswith('sha256:') or \
            signer.get('owner_key_fingerprint') != native_fingerprint.removeprefix('sha256:'):
        raise ValueError('native Owner signer fingerprint differs from its review DTO')
    if kind == 'KEY' and signer.get('manifest_digest') != native.get('manifestDigest'):
        raise ValueError('Owner key signer envelope is not bound to the current manifest')
    if kind == 'REVIEW_POLICY':
        expected_version, policy_version = signer.get('expected_policy_version'), signer.get('policy_version')
        if type(expected_version) is not int or not 0 <= expected_version < 9_223_372_036_854_775_807 or \
                type(policy_version) is not int or policy_version != expected_version + 1 or \
                str(policy_version) != native.get('policyVersion') or signer.get('policy_digest') != native.get('policyDigest'):
            raise ValueError('review policy signer version or digest is not bound to its preview')
        policy = value.get('policy_json')
        if not isinstance(policy, str) or secret_fields(parse_json(policy.encode())):
            raise ValueError('review policy handoff is malformed or contains credentials')


def validate_proof(value, kind, side, run_id, review):
    fields = {'schema', 'run_id', 'review_id', 'consent_digest', 'link_id', 'link_version', 'side',
        'owner_id', 'owner_key_id', 'signed_proof_base64', 'proof_sha256'}
    if set(value) != fields or value.get('schema') != PROOF_SCHEMA or value.get('run_id') != run_id:
        raise ValueError('signed Owner proof handoff schema is invalid')
    validate_review_handoff(review, kind, run_id)
    for field in ('review_id', 'consent_digest', 'link_id', 'link_version', 'side', 'owner_id', 'owner_key_id'):
        review_field = {'review_id': 'review_id', 'consent_digest': 'consent_digest', 'link_id': 'link_id',
            'link_version': 'link_version', 'side': 'side', 'owner_id': 'owner_id', 'owner_key_id': 'owner_key_id'}[field]
        if value.get(field) != review.get(review_field):
            raise ValueError('signed Owner proof does not match the exact exported native review')
    if value['side'] != side.upper():
        raise ValueError('signed Owner proof side does not match this staged handoff')
    if not isinstance(value.get('consent_digest'), str) or not HEX64.fullmatch(value['consent_digest']) or \
            not isinstance(value.get('link_version'), str) or not re.fullmatch(r'[1-9][0-9]*', value['link_version']):
        raise ValueError('signed Owner proof scope tuple is malformed')
    validate_public_signature(value['signed_proof_base64'], value['proof_sha256'], 16 * 1024)


def validate_stage(value, name, kind, side, run_id, reference):
    if secret_fields(value):
        raise ValueError('private keys, bearer tokens, and credentials cannot be staged to Android')
    if kind == 'setup':
        validate_setup(value, side, run_id)
    elif kind == 'selection':
        validate_selection(value, run_id, reference)
    elif kind == 'grant':
        validate_grant(value, side, run_id, reference)
    elif kind.startswith('proof-'):
        proof_kind = 'KEY' if kind in {'proof-key', 'proof-negative'} else 'REVIEW_POLICY'
        validate_proof(value, proof_kind, side, run_id, reference)
    elif kind == 'policy':
        if set(value) != {'schema', 'run_id', 'policy'} or value.get('schema') != POLICY_SCHEMA or value.get('run_id') != run_id:
            raise ValueError('review policy fixture schema is invalid')
        policy = value['policy']
        if not isinstance(policy, dict) or set(policy) != {'mode', 'reviewers', 'max_failovers',
                'reviewer_lease_seconds', 'max_review_age_seconds'} or policy.get('mode') not in {'NONE', 'METADATA'}:
            raise ValueError('review policy fixture DTO is invalid')
        reviewers = policy.get('reviewers')
        numbers = [policy.get(key) for key in ('max_failovers', 'reviewer_lease_seconds', 'max_review_age_seconds')]
        if not isinstance(reviewers, list) or len(reviewers) > 8 or any(type(number) is not int or number < 0 for number in numbers) or \
                any(not isinstance(row, dict) or set(row) != {'endpoint_id', 'group_id'} or
                    not all(checked_id(row.get(key)) for key in ('endpoint_id', 'group_id')) for row in reviewers):
            raise ValueError('review policy fixture values are invalid')
        failovers, lease, age = numbers
        if policy['mode'] == 'NONE' and (reviewers or failovers or lease or age) or \
                policy['mode'] == 'METADATA' and (not reviewers or failovers > len(reviewers) - 1 or
                    not 30 <= lease <= 3600 or not 60 <= age <= 86400):
            raise ValueError('review policy fixture exceeds its bounded configuration')
    elif kind == 'recovery':
        if set(value) != {'schema', 'run_id', 'expected_operation'} or value.get('schema') != RECOVERY_SCHEMA or \
                value.get('run_id') != run_id or value.get('expected_operation') not in {'link.key_grant', 'link.review_policy_grant'}:
            raise ValueError('Link recovery scenario schema is invalid')
    else:
        raise ValueError('unsupported bounded staging kind')


def check_evidence(evidence, args):
    delivery = runner.read_f6_delivery(args)
    run_id = evidence.parent.name
    if delivery is None and run_id.startswith('v16-deterministic-v164-f6-'):
        raise ValueError('F6 artifact verification requires its Root pins and actual delivery metadata')
    if delivery is not None and not runner.F6_RUN_ID.fullmatch(run_id):
        raise ValueError('Root-pinned F6 metadata cannot be applied to a legacy evidence run')
    state = runner.owned_state(evidence)
    if state.get('network') != 'none':
        raise ValueError('the owned v1.6.4 emulator must remain offline')
    artifacts, _ = link.read_private_json(evidence / 'android-artifacts.json', maximum=64 * 1024)
    if delivery is None:
        f6_markers = {
            'fixture_lane', 'root_delivery_pins_path', 'root_delivery_pins_sha256',
            'delivery_metadata_path', 'delivery_metadata_sha256', 'fixture_root',
            'root_delivery_pins', 'validated_f6_fixture',
        }
        if state['run_id'].startswith('v16-deterministic-v164-f6-') or any(key in artifacts for key in f6_markers):
            raise ValueError('F6 artifact verification requires its Root pins and actual delivery metadata')
        expected = {
            'contract_revision': runner.CONTRACT_REVISION,
            'core_source_revision': runner.CORE_REVISION,
            'core_source_fingerprint': runner.CORE_SOURCE_FINGERPRINT,
            'catalog_sha256': CATALOG_SHA256,
            'pinned_hub_image_id': runner.HUB_IMAGE,
            'pinned_interop_image_id': runner.INTEROP_IMAGE,
        }
    else:
        expected = runner.f6_pinned_artifact_values(args, delivery)
    if any(artifacts.get(key) != value for key, value in expected.items()):
        raise ValueError('installed emulator artifact metadata does not match its independently verified pin inputs')
    for app in ('app', 'test'):
        expected_sha = artifacts.get(app + '_sha256')
        path = evidence / f'installed-{app}.private.apk'
        if delivery is not None and expected_sha != (runner.F6_APP_SHA256 if app == 'app' else runner.F6_TEST_SHA256):
            raise ValueError(f'F6 {app} APK does not match its authorized binary pin')
        if delivery is None and expected_sha in (runner.F6_APP_SHA256, runner.F6_TEST_SHA256):
            raise ValueError('F6 APKs require Root pins and a fresh F6 evidence run')
        if not isinstance(expected_sha, str) or not HEX64.fullmatch(expected_sha) or path.is_symlink() or \
                not path.is_file() or digest(path.read_bytes()) != expected_sha:
            raise ValueError(f'installed {app} APK does not match its full recorded SHA-256')
    runtime_path = evidence / 'android-runtime.redacted.json'
    if runtime_path.is_symlink() or not runtime_path.is_file():
        raise ValueError('owned emulator runtime receipt is missing')
    runtime, _ = link.read_private_json(runtime_path, maximum=16 * 1024)
    runtime_kind = validate_runtime_receipt(runtime)
    if runtime_kind == 'f9':
        validate_f9_property_receipts(evidence, state)
    return state, artifacts


def output_dir(evidence):
    path = evidence / 'link-v164'
    if path.is_symlink():
        raise ValueError('Link evidence output directory cannot be a symlink')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if not path.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Link evidence output directory must be caller-owned mode 0700')
    return path


def save_unique(directory, stem, raw):
    sha = digest(raw)
    base = f'{stem}-{sha[:12]}'
    for attempt in range(1, 1000):
        suffix = '' if attempt == 1 else f'-{attempt}'
        path = directory / f'{base}{suffix}.private.json'
        try:
            link.save_private(path, raw)
            return path, sha
        except FileExistsError:
            continue
        except ValueError:
            if path.exists() or path.is_symlink():
                continue
            raise
    raise ValueError('unable to allocate a unique private evidence filename')


def remote_dir(run_id):
    if not RUN_ID.fullmatch(run_id):
        raise ValueError('instrumentation run ID must be bounded v164-*')
    return f'{REMOTE_ROOT}/{run_id}'


def remote_file(state, run_id, name):
    if name not in STAGE_FILES and name not in EXPORT_FILES:
        raise ValueError('file name is outside the bounded Link consent allowlist')
    return remote_dir(run_id) + '/' + name


def stage(evidence, state, args):
    name = args.name
    kind, side = STAGE_FILES[name]
    run_id = args.run_id
    if side is not None and args.side != side:
        raise ValueError('staged file name and --side do not match')
    if side is None and args.side is not None and kind not in {'selection'}:
        raise ValueError('this shared fixture does not accept --side')
    parsed, raw_sha = link.read_private_json(args.input, maximum=MAX_INPUT)
    reference = None
    if args.reference:
        reference, _ = link.read_private_json(args.reference, maximum=MAX_OUTPUT)
    stage_side = side or args.side
    if kind == 'selection':
        stage_side = validate_selection(parsed, run_id, reference)
        if args.side is not None and args.side != stage_side:
            raise ValueError('selection owner and --side do not match its device handoff')
    validate_stage(parsed, name, kind, stage_side, run_id, reference)
    raw = (json.dumps(parsed, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    if len(raw) > MAX_INPUT:
        raise ValueError('normalized staged JSON exceeds its bound')
    state, _ = check_evidence(evidence, args)
    output = output_dir(evidence)
    input_copy, staged_sha = save_unique(output, 'staged-' + Path(name).stem, raw)
    remote = remote_file(state, run_id, name)
    shell = 'umask 077; mkdir -p ' + shlex.quote(remote_dir(run_id)) + ' && chmod 700 ' + \
        shlex.quote(remote_dir(run_id)) + ' && cat > ' + \
        shlex.quote(remote) + ' && chmod 600 ' + shlex.quote(remote)
    command = driver.adb(state, True) + ['shell', shlex.join(['run-as', PACKAGE, 'sh', '-c', shell])]
    step = f'link-v164-{run_id}-{stage_side or "shared"}-stage-{Path(name).stem}'
    result = driver.run(evidence, step, command, data=raw)
    if result:
        raise RuntimeError('Android staging returned unexpected stdout')
    summary = {
        'schema': SCHEMA, 'result': 'PASS', 'action': 'stage', 'run_id_sha256': digest(run_id.encode()),
        'side': stage_side or 'shared', 'file': name, 'input_sha256': raw_sha, 'staged_sha256': staged_sha,
        'private_evidence': str(input_copy.name), 'stdin_bytes': len(raw), 'command_sha256': digest(shlex.join(command).encode()),
    }
    summary_path, _ = save_unique(output, f'stage-{stage_side or "shared"}-{Path(name).stem}',
        (json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return {'result': 'PASS', 'action': 'stage', 'side': stage_side or 'shared', 'file': name,
        'stdin_sha256': staged_sha, 'receipt': summary_path.name}


def export_file(evidence, state, run_id, name, side):
    if name not in EXPORT_FILES:
        raise ValueError('only public device identities, signer reviews and redacted receipts may be exported')
    if side and not name.startswith(side + '-') and name != 'selection.redacted.json':
        raise ValueError('export filename and --side do not match')
    remote = remote_file(state, run_id, name)
    command = driver.adb(state) + ['exec-out', 'run-as', PACKAGE, 'cat', remote]
    raw = driver.run(evidence, f'link-v164-{run_id}-{side or "shared"}-export-{Path(name).stem}', command)
    if len(raw) > MAX_OUTPUT:
        raise ValueError('Android export exceeded the bounded output size')
    value = parse_json(raw)
    if secret_fields(value):
        raise ValueError('refusing to export an Android object containing private credentials')
    if name.endswith('.redacted.json'):
        if value.get('schema') != 'cicada.client-v164-link-consent-redacted-receipt.v1' or \
                value.get('result') not in {'PASS', 'NOT_RUN'} or \
                value.get('run_id_sha256') != digest(run_id.encode()) or \
                value.get('phase') != name.removesuffix('.redacted.json'):
            raise ValueError('Android receipt is not a recognized redacted v1.6.4 result')
    elif name.endswith('device-public.private.json'):
        validate_identity(value.get('device_public_identity'))
        if value.get('schema') != DEVICE_SCHEMA or value.get('run_id') != run_id or \
                value.get('device_public_identity_sha256') != digest(json.dumps(
                    value['device_public_identity'], separators=(',', ':'), ensure_ascii=False).encode()):
            raise ValueError('Android device export is not a v1.6.4 public device handoff')
    elif name.endswith('review.private.json'):
        kind = 'REVIEW_POLICY' if '-policy-' in name else 'KEY'
        validate_review_handoff(value, kind, run_id)
    output = output_dir(evidence)
    path, sha = save_unique(output, 'export-' + Path(name).stem, raw)
    response = {'result': 'PASS', 'action': 'export', 'side': side or 'shared', 'file': name,
        'sha256': sha, 'private_evidence': path.name, 'bytes': len(raw)}
    if name.endswith('.redacted.json'):
        response['receipt_result'] = value['result']
    return response


def read_remote_json(evidence, state, run_id, name, step):
    remote = remote_file(state, run_id, name)
    shell = 'if [ -f ' + shlex.quote(remote) + ' ]; then cat ' + shlex.quote(remote) + '; else printf __MISSING__; fi'
    command = driver.adb(state) + ['exec-out', 'run-as', PACKAGE, 'sh', '-c', shell]
    raw = driver.run(evidence, step, command)
    if raw.strip() == b'__MISSING__':
        return None, raw
    return parse_json(raw), raw


def receipt_candidates(side, method):
    _method_side, success_name, success_phase = SELECTORS[method]
    receipt = success_name if success_name.startswith(side + '-') else f'{side}-{success_name}'
    phase = success_phase if success_phase.startswith(side + '-') else f'{side}-{success_phase}'
    choices = [(receipt, phase)]
    for name, phase in (
        ('selection.redacted.json', 'selection'),
        (f'{side}-onboarding.redacted.json', f'{side}-onboarding'),
        (f'{side}-onboarding-enroll.redacted.json', f'{side}-onboarding-enroll'),
    ):
        if (name, phase) not in choices:
            choices.append((name, phase))
    dedup = []
    for item in choices:
        if item not in dedup:
            dedup.append(item)
    return dedup


def selection_side_hint(value):
    if not isinstance(value, dict):
        raise ValueError('active Link selection is not an object')
    owner_id = value.get('owner_id')
    source = value.get('source_owner_pin')
    target = value.get('target_owner_pin')
    matches = [side for side, pin in (('source', source), ('target', target))
        if isinstance(pin, dict) and pin.get('owner_id') == owner_id]
    if len(matches) != 1:
        raise ValueError('active Link selection does not identify exactly one pinned Owner side')
    return matches[0]


def run_selector(evidence, state, args):
    method = args.method
    expected_side, _success_file, _success_phase = SELECTORS[method]
    side = args.side or expected_side
    if side not in SIDES or expected_side is not None and side != expected_side:
        raise ValueError('selector and --side do not match the bounded source/target phase')
    run_id = args.run_id
    if expected_side is None:
        selection, _ = read_remote_json(evidence, state, run_id, 'selection.json',
            f'link-v164-{run_id}-{side}-read-selection')
        if selection is not None:
            role = selection_side_hint(selection)
            device, _ = read_remote_json(evidence, state, run_id, f'{role}-device-public.private.json',
                f'link-v164-{run_id}-{side}-read-device-handoff')
            if device is not None:
                role = validate_selection(selection, run_id, device)
            if role != side:
                raise ValueError('active public selection belongs to the other Owner side')
    state, _artifacts = check_evidence(evidence, args)
    output = output_dir(evidence)
    candidates = receipt_candidates(side, method)
    for index, (name, _phase) in enumerate(candidates, 1):
        old, raw = read_remote_json(evidence, state, run_id, name,
            f'link-v164-{run_id}-{side}-{method}-receipt-preflight-{index}')
        if old is not None:
            save_unique(output, f'prior-{side}-{Path(name).stem}', raw)
            remote = remote_file(state, run_id, name)
            command = driver.adb(state) + ['shell', 'run-as', PACKAGE, 'rm', '-f', remote]
            driver.run(evidence, f'link-v164-{run_id}-{side}-{method}-clear-{index}', command)

    command = driver.adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id', run_id,
        '-e', 'class', TEST_CLASS + '#' + method, PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner']
    step = f'link-v164-{run_id}-{side}-{method}'
    output_log = driver.run(evidence, step, command, junit=True)
    junit = json.loads((evidence / (step + '.json')).read_text())
    if junit.get('exit_code') != 0 or junit.get('junit') != 'OK (1 test)':
        raise RuntimeError('selector did not run exactly one passing JUnit test; inspect private log and summary')

    found = []
    for index, (name, expected_phase) in enumerate(candidates, 1):
        value, raw = read_remote_json(evidence, state, run_id, name,
            f'link-v164-{run_id}-{side}-{method}-receipt-{index}')
        if value is None:
            continue
        if value.get('schema') != 'cicada.client-v164-link-consent-redacted-receipt.v1' or \
                value.get('phase') != expected_phase or value.get('run_id_sha256') != digest(run_id.encode()) or \
                value.get('result') not in {'PASS', 'NOT_RUN'}:
            raise ValueError('selector receipt is malformed or belongs to another stage')
        found.append((name, value, raw))
    if len(found) != 1:
        raise RuntimeError('selector must create exactly one fresh redacted receipt')
    receipt_name, receipt, receipt_raw = found[0]
    receipt_path, receipt_sha = save_unique(output, f'receipt-{side}-{method}', receipt_raw)
    result = receipt['result']
    summary = {
        'schema': SCHEMA, 'result': result, 'action': 'selector', 'side': side, 'selector': method,
        'run_id_sha256': digest(run_id.encode()), 'junit': junit.get('junit'), 'exit_code': junit.get('exit_code'),
        'command_sha256': digest(shlex.join(command).encode()), 'log_sha256': digest(output_log),
        'receipt_file': receipt_name, 'receipt_sha256': receipt_sha, 'private_evidence': receipt_path.name,
    }
    summary_path, _ = save_unique(output, f'selector-{side}-{method}',
        (json.dumps(summary, sort_keys=True, separators=(',', ':')) + '\n').encode())
    public = {'result': result, 'action': 'selector', 'side': side, 'selector': method,
        'junit': junit['junit'], 'log_sha256': summary['log_sha256'], 'receipt_sha256': receipt_sha,
        'evidence': summary_path.name}
    if result == 'NOT_RUN':
        print(json.dumps(public))
        raise SystemExit(2)
    return public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', help='private evidence directory owned by the v1.6.4 emulator driver')
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('bootstrap-preflight',
        help='read-only Android boot/runtime check; makes no Hub or Root delivery claim')
    preflight = commands.add_parser('preflight',
        help='read-only F6 artifact, owned-emulator, and runtime checks without running a selector')
    preflight.add_argument('--run-id', required=True)
    runner.add_delivery_arguments(preflight)
    stage_parser = commands.add_parser('stage')
    stage_parser.add_argument('--run-id', required=True)
    stage_parser.add_argument('--name', choices=sorted(STAGE_FILES), required=True)
    stage_parser.add_argument('--input', required=True)
    stage_parser.add_argument('--side', choices=sorted(SIDES))
    stage_parser.add_argument('--reference', help='private exported device or exact review handoff')
    runner.add_delivery_arguments(stage_parser)
    selector = commands.add_parser('selector')
    selector.add_argument('--run-id', required=True)
    selector.add_argument('--method', choices=sorted(SELECTORS), required=True)
    selector.add_argument('--side', choices=sorted(SIDES))
    runner.add_delivery_arguments(selector)
    export = commands.add_parser('export')
    export.add_argument('--run-id', required=True)
    export.add_argument('--name', choices=sorted(EXPORT_FILES), required=True)
    export.add_argument('--side', choices=sorted(SIDES))
    runner.add_delivery_arguments(export)
    args = parser.parse_args()
    evidence = driver.private_evidence(args.evidence)
    if args.action == 'bootstrap-preflight':
        print(json.dumps(bootstrap_preflight(evidence)))
        return
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError('instrumentation run ID must match v164-[A-Za-z0-9_-]{1,72}')
    if args.action == 'preflight':
        state, _artifacts = check_evidence(evidence, args)
        result = bootstrap_preflight(evidence, state)
        result.update({'action': 'preflight', 'instrumentation_run_id': args.run_id})
        print(json.dumps(result))
        return
    state, _artifacts = check_evidence(evidence, args)
    if args.action == 'stage':
        result = stage(evidence, state, args)
    elif args.action == 'selector':
        result = run_selector(evidence, state, args)
    else:
        result = export_file(evidence, state, args.run_id, args.name, args.side)
    print(json.dumps(result))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
