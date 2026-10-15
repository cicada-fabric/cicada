#!/usr/bin/env python3
"""Export one Android PUBLIC device manifest for offline Owner enrollment.

This uses the existing profile UI and public identity adapter. It never reads
wrapped private keys or enrolls a device, and requires the owned v1.6 emulator.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--profile', default='OfflineQA')
    args = parser.parse_args()
    if not re.fullmatch(r'v16-[A-Za-z0-9_-]{1,80}', args.run_id):
        raise ValueError('invalid public-device run ID')
    runner = module('v16_runner', 'v16-android-deterministic.py')
    ui = module('profile_ui', 'v15-device-preparation.py')
    driver = runner.driver
    evidence = driver.private_evidence(args.evidence)
    state = runner.owned_state(evidence)
    driver.run(evidence, 'public-device-launch', driver.adb(state) + ['shell', 'am', 'start', '-W', '-n',
        driver.PACKAGE + '/com.cicadaclient.MainActivity'])
    time.sleep(0.8)
    ui.ensure_connection_modal(evidence, state, 'v16-public-profile-list')
    ui.create_profile(evidence, state, args.profile)
    driver.run(evidence, 'public-device-prepare', driver.adb(state) + ['shell', 'am', 'instrument', '-w',
        '-e', 'run_id', args.run_id, '-e', 'class',
        'ai.cicada.client.hub.ClientHubV16InteropTest#prepareDevice',
        driver.PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner'], junit=True)
    result = json.loads((evidence / 'public-device-prepare.json').read_text())
    if result['junit'] != 'OK (1 test)':
        raise ValueError('the public selector did not run exactly once')
    relative = 'no_backup/network-v16/' + args.run_id + '/device-public.json'
    raw = driver.run(evidence, 'public-device-export', driver.adb(state) + ['exec-out', 'run-as',
        driver.PACKAGE, 'cat', relative])
    manifest = json.loads(raw)
    identity = manifest['device_public_identity']
    if manifest['schema'] != 'cicada.client-network-device.v1' or \
            manifest['device_id'] != 'phone-' + args.run_id or \
            sorted(identity) != ['id', 'kem_public', 'signing_public']:
        raise ValueError('invalid public device manifest')
    kem = base64.b64decode(identity['kem_public'], validate=True)
    signing = base64.b64decode(identity['signing_public'], validate=True)
    if len(kem) != 1184 or len(signing) != 1952 or \
            identity['id'] != 'pq1-' + hashlib.sha256(kem + signing).digest()[:16].hex():
        raise ValueError('invalid independent device public identity')
    canonical = json.dumps(identity, separators=(',', ':'), ensure_ascii=False).encode()
    fingerprint = 'sha256:' + hashlib.sha256(b'cicada/client/device-public-key/v1\0' + canonical).hexdigest()
    path = evidence / 'device-public.private.json'
    driver.save(path, raw)
    receipt = {'result': 'PASS', 'run_id': args.run_id, 'public_manifest': str(path),
        'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'device_id': manifest['device_id'],
        'device_key_id': identity['id'], 'device_fingerprint': fingerprint,
        'profile_id_sha256': hashlib.sha256(manifest['profile_id'].encode()).hexdigest(),
        'private_key_exported': False, 'enrolled': False}
    driver.save(evidence / 'public-device.redacted.json', receipt)
    print(json.dumps(receipt))


if __name__ == '__main__':
    os.umask(0o077)
    main()
