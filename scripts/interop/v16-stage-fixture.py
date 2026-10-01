#!/usr/bin/env python3
"""Stage a bounded, public-only v1.6 enrollment fixture to the owned emulator."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('input must be a private mode-0600 regular file')
        with os.fdopen(fd, 'rb') as source:
            fd = -1
            data = source.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError('input exceeds the fixture size bound')
        return data
    finally:
        if fd >= 0:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('evidence', 'fixture', 'public', 'grant', 'run-id'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'v16-[A-Za-z0-9_-]{1,80}', args.run_id):
        raise ValueError('invalid v1.6 run ID')
    runner = load('v16_runner_for_fixture', 'v16-android-deterministic.py')
    carrier = load('v16_carrier_for_fixture', 'v16-host-stdio-carrier.py')
    driver = runner.driver
    evidence = driver.private_evidence(args.evidence)
    state = runner.owned_state(evidence)
    _fixture, core, _hub, _network, _ip, _port = carrier.verify_hub(args.fixture, args.public)
    manifest_path = evidence / 'device-public.private.json'
    manifest_raw = private_bytes(manifest_path)
    manifest = json.loads(manifest_raw)
    identity = manifest.get('device_public_identity')
    if manifest.get('schema') != 'cicada.client-network-device.v1' or \
            manifest.get('device_id') != 'phone-' + args.run_id or not isinstance(identity, dict) or \
            set(identity) != {'id', 'kem_public', 'signing_public'}:
        raise ValueError('public device manifest does not match the v1.6 run')
    kem = base64.b64decode(identity['kem_public'], validate=True)
    signing = base64.b64decode(identity['signing_public'], validate=True)
    if len(kem) != 1184 or len(signing) != 1952 or \
            identity['id'] != 'pq1-' + hashlib.sha256(kem + signing).digest()[:16].hex():
        raise ValueError('public device identity is malformed')
    canonical_identity = json.dumps(identity, separators=(',', ':'), ensure_ascii=False).encode()
    fingerprint = hashlib.sha256(b'cicada/client/device-public-key/v1\0' + canonical_identity).hexdigest()
    root = Path(args.fixture).parent.resolve(strict=True)
    expected_grant = root / 'owner-device-grant-primary.json'
    if Path(args.grant).resolve(strict=True) != expected_grant:
        raise ValueError('grant must be the primary Owner grant from this Core fixture')
    grant_raw = private_bytes(args.grant)
    grant = json.loads(grant_raw)
    expected_fields = {'version', 'owner_id', 'owner_key_id', 'device_id', 'device_key_id',
        'device_key_fingerprint', 'hub_id', 'purpose', 'issued_at', 'expires_at', 'nonce', 'signature'}
    owner_public = core.get('owner_public_identity')
    if not isinstance(grant, dict) or set(grant) != expected_fields or type(grant.get('version')) is not int or \
            grant.get('version') != 1 or \
            grant.get('purpose') != 'CLIENT_CONTROL' or grant.get('owner_id') != core.get('owner_id') or \
            grant.get('owner_key_id') != core.get('owner_key_id') or \
            grant.get('hub_id') != core.get('hub_id') or grant.get('device_id') != manifest['device_id'] or \
            grant.get('device_key_id') != identity['id'] or \
            grant.get('device_key_fingerprint') != fingerprint or \
            not isinstance(owner_public, dict) or owner_public.get('id') != core.get('owner_key_id'):
        raise ValueError('Owner grant does not bind this primary Owner, Hub, and public device')
    if len(base64.b64decode(grant['signature'], validate=True)) != 3309:
        raise ValueError('Owner grant signature encoding has the wrong size')
    public_manifest = {key: manifest[key] for key in ('schema', 'device_id', 'device_public_identity')}
    fixture = dict(core)
    fixture.update(schema='cicada.client-v16-fixture.v1', device_id=manifest['device_id'],
        public_manifest=public_manifest, owner_device_grant=base64.b64encode(grant_raw).decode('ascii'))
    staged = (json.dumps(fixture, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    if len(staged) > 256 * 1024:
        raise ValueError('staged v1.6 fixture exceeds its size bound')
    remote = f'no_backup/network-v16/{args.run_id}/devfixture.json'
    shell = 'umask 077; cat > ' + shlex.quote(remote)
    command = driver.adb(state, True) + ['shell', shlex.join(['run-as', driver.PACKAGE, 'sh', '-c', shell])]
    output = driver.run(evidence, 'stage-v16-devfixture', command, data=staged)
    if output:
        raise RuntimeError('fixture staging command returned unexpected stdout')
    receipt = {'schema': 'cicada.client-v16-fixture-stage.v1', 'result': 'PASS',
        'run_id': args.run_id, 'command': command, 'stdin_bytes': len(staged),
        'stdin_sha256': hashlib.sha256(staged).hexdigest(), 'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
        'grant_bytes': len(grant_raw), 'grant_sha256': hashlib.sha256(grant_raw).hexdigest(), 'stdout_bytes': 0}
    driver.save(evidence / 'v16-fixture-stage.redacted.json', receipt)
    print(json.dumps({'result': 'PASS', 'stdin_sha256': receipt['stdin_sha256'],
        'grant_sha256': receipt['grant_sha256'], 'stdin_bytes': len(staged), 'stdout_bytes': 0}))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, json.JSONDecodeError):
        print(json.dumps({'result': 'FAIL', 'reason': 'bounded public fixture validation or staging failed'}), file=sys.stderr)
        raise SystemExit(1)
