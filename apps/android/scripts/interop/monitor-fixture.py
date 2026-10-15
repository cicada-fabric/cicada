#!/usr/bin/env python3
"""Prepare public Android inputs for the frozen, synthetic Monitor protocol run.

The core fixture owns Hub lifecycle. This adapter never reads a database and
never stages Owner private keys or Node credentials into Android. It deliberately
does not claim native Monitor execution.
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

SOURCE = 'be0269e80c41e94881d131bd4f4b233e80b6ffe6'
IMAGE = 'sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783'
CATALOG = '808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377'
GO_IMAGE = 'sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244'
BASE = Path('/gpu1-share/data/cicada-client')
SIGNER = BASE / 'group-owner-signer-build-967dbd-20260925/bin/group_owner_signer'
SIGNER_SHA = 'cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1'
NODE_BINARY = BASE / 'monitor-v13-build/two-owner-node-fixture-build/bin/two-owner-node-fixture'
LABELS = ('monitor', 'recipient-a', 'recipient-b')

spec = importlib.util.spec_from_file_location('monitor_android', Path(__file__).with_name('monitor-android.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
save, run = driver.save, driver.run


def read(path):
    return json.loads(path.read_text())


def checked_fixture(value):
    root = Path(value)
    if (root.is_symlink() or root.resolve() != root or root.parent != Path('/tmp') or
            not root.name.startswith('cgk.') or root.stat().st_uid != os.getuid() or
            root.stat().st_mode & 0o077):
        raise ValueError('expected the private, real core-created /tmp/cgk.* fixture')
    marker = read(root / '.cicada-client-group-key-fixture.json')
    expected = {'fixture_dir': str(root), 'image_id': IMAGE, 'source_revision': SOURCE,
                'source_dirty': False, 'catalog_sha256': CATALOG, 'contract_revision': 'client-hub-v1.3'}
    if any(marker.get(key) != value for key, value in expected.items()):
        raise ValueError('core fixture fixed target mismatch')
    actual = subprocess.check_output(['docker', 'inspect', '--format',
        '{{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}', marker['hub_container']], text=True).strip()
    if actual.split() != [IMAGE, SOURCE]:
        raise ValueError('running fixture image/source mismatch')
    result = read(root / 'fixture-result.json')
    if result['hub']['image_id'] != IMAGE or result['hub']['source_revision'] != SOURCE:
        raise ValueError('fixture result does not match its marker')
    return root, result


def config(root, result, evidence, proxy_port):
    owner = {key: result['owner'][key] for key in ('owner_id', 'owner_key_id')}
    owner['device_id'] = 'android-' + evidence.parent.name
    owner['owner_public_identity'] = read(root / 'owner-public/owner-public.json')
    grant = root / 'monitor-device-grant.json'
    if grant.exists():
        owner['owner_device_grant_base64'] = base64.b64encode(grant.read_bytes()).decode()
    cfg = {'schema': 'cicada.client-monitor-fixture.v1',
           'hub_base_url': f'http://127.0.0.1:{proxy_port}',
           'hub_identity': read(root / 'hub-identity.json'), 'owner': owner,
           'nodes': [{'label': 'node', 'node_id': result['node']['node_id']}]}
    setup = evidence / 'setup.private.json'
    if setup.exists():
        cfg['group_id'] = read(setup)['group_id']
    endpoints = []
    for label in LABELS:
        path = root / ('monitor-' + label) / 'public-result.json'
        if not path.exists():
            continue
        value = read(path)
        if (value['source_commit'] != SOURCE or value['group_id'] != cfg['group_id'] or
                value['node_id'] != result['node']['node_id'] or
                value['fixture_kind'] != 'SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE'):
            raise ValueError('synthetic Endpoint coordinates/provenance mismatch')
        endpoint = {'label': label, 'endpoint_id': value['endpoint_id']}
        proof = root / ('monitor-proof-' + label + '.json')
        if proof.exists():
            endpoint['owner_signed_proof_base64'] = base64.b64encode(proof.read_bytes()).decode()
        endpoints.append(endpoint)
        if label == 'monitor':
            cfg['monitor_endpoint_id'] = value['endpoint_id']
    if endpoints:
        cfg['endpoints'] = endpoints
    save(root / 'monitor-android-fixture.json', cfg)
    save(root / 'monitor-node-codes.json', {'node': (root / 'node-device-code.txt').read_text().strip()})
    return cfg


def sign_device(root, result, evidence, cfg):
    identity = read(evidence / 'device-public.private.json')
    path = root / 'monitor-device-public.json'
    save(path, json.dumps({key: identity[key] for key in ('id', 'kem_public', 'signing_public')}, separators=(',', ':')).encode())
    owner = cfg['owner']
    run(evidence, 'owner-sign-device', [str(SIGNER), 'device-grant', '--private',
        result['owner']['private_key_path'], '--device-public', str(path), '--owner', owner['owner_id'],
        '--device', owner['device_id'], '--hub', cfg['hub_identity']['hub_id'],
        '--expect-device-key', identity['id'], '--out', str(root / 'monitor-device-grant.json')],
        data=('SIGN DEVICE ' + owner['device_id'] + ' ' + identity['id'] + '\n').encode())


def refresh_node(root, result, evidence):
    """Renew an expired pairing code through the fixed CLI, with no credential output."""
    command = ['docker', 'run', '--rm', '--network', 'host', '--user', f'{os.getuid()}:{os.getgid()}',
        '-v', f'{root / "node-state"}:{root / "node-state"}', '-v', f'{root / "bin"}:/tools:ro',
        GO_IMAGE, '/tools/cicada', 'machine', 'agent', '--id', result['node']['node_id'],
        '--name', 'Disposable Client Monitor Node', '--control-url', result['hub']['url'],
        '--state-dir', str(root / 'node-state'), '--once']
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    match = re.search(rb'Device code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}) ', process.stdout)
    passed = process.returncode == 1 and match is not None
    save(evidence / 'node-pairing-refresh.json', {'command': command, 'exit_code': process.returncode,
        'expected_pending_exit_code': 1, 'result': 'PASS' if passed else 'FAIL', 'raw_output_retained': False})
    if not passed:
        raise RuntimeError('fixed Node did not produce a pending pairing code')
    save(root / 'node-device-code.txt', match.group(1) + b'\n')


def publish(root, result, evidence, cfg, refresh=False):
    binary_sha = hashlib.sha256(NODE_BINARY.read_bytes()).hexdigest()
    save(evidence / 'node-helper.json', {'source_commit': SOURCE, 'binary_sha256': binary_sha,
        'image_id': GO_IMAGE, 'fixture_kind': 'SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE'})
    credential = Path(result['node']['state_dir']) / 'nodes' / ('node-' + result['node']['node_id']) / 'relay.token'
    if credential.is_symlink() or not credential.is_file() or credential.stat().st_mode & 0o077:
        raise ValueError('Node credential must remain private on the Node')
    for label in LABELS:
        work = root / ('monitor-' + label)
        if refresh:
            if not work.is_dir() or work.is_symlink():
                raise ValueError('refresh requires the original private Endpoint fixture')
        else:
            work.mkdir(mode=0o700)
        spec = {'schema_version': 1, 'hub_base_url': result['hub']['url'],
            'group_id': cfg['group_id'], 'node_credential_file': str(work / 'relay.token'),
            'native_session_id': 'synthetic-monitor-protocol-' + evidence.parent.name + '-' + label,
            'workspace': '/synthetic-monitor-protocol/' + label,
            'endpoint_private_key_file': str(work / 'endpoint-private.json'),
            'public_result_file': str(work / 'public-result.json'), 'lease_seconds': 3600}
        if refresh:
            spec['refresh'] = True
            prior = read(work / 'public-result.json')
            save(evidence / f'endpoint-{label}-epoch-{prior["binding_epoch"]}.private.json',
                 (work / 'public-result.json').read_bytes())
        save(work / 'spec.json', spec)
        run(evidence, ('refresh-' if refresh else 'publish-') + label, ['docker', 'run', '--rm', '--network', 'host',
            '--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{work}:{work}',
            '-v', f'{credential}:{work / "relay.token"}:ro', '-v', f'{NODE_BINARY.parent}:/tools:ro',
            GO_IMAGE, '/tools/two-owner-node-fixture', '-spec', str(work / 'spec.json')])
        save(evidence / ('endpoint-' + label + '.private.json'), (work / 'public-result.json').read_bytes())


def sign_groups(root, result, evidence, cfg):
    manifests = read(evidence / 'manifests.private.json')
    for label in LABELS:
        manifest = manifests[label]
        endpoint = next(item for item in cfg['endpoints'] if item['label'] == label)
        expected = {'owner_id': cfg['owner']['owner_id'], 'hub_id': cfg['hub_identity']['hub_id'],
                    'group_id': cfg['group_id'], 'endpoint_id': endpoint['endpoint_id'], 'node_id': result['node']['node_id']}
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError('manifest is outside the independently selected fixture scope')
        path = root / ('monitor-manifest-' + label + '.json')
        save(path, json.dumps(manifest, separators=(',', ':')).encode())
        command = [str(SIGNER), 'group-grant', '--private', result['owner']['private_key_path'], '--manifest', str(path)]
        for flag, key in (('owner', 'owner_id'), ('hub', 'hub_id'), ('group', 'group_id'),
                          ('endpoint', 'endpoint_id'), ('node', 'node_id'), ('principal', 'principal_id'), ('digest', 'digest')):
            command += ['--expect-' + flag, manifest[key]]
        command += ['--out', str(root / ('monitor-proof-' + label + '.json'))]
        run(evidence, 'owner-sign-' + label, command, data=('SIGN GROUP ' + manifest['digest'] + '\n').encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence'); parser.add_argument('fixture')
    parser.add_argument('action', choices=('config', 'sign-device', 'refresh-node', 'publish', 'refresh', 'sign-groups'))
    parser.add_argument('--proxy-port', type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.proxy_port <= 65535:
        raise ValueError('expected a high loopback proxy port')
    evidence = driver.private_evidence(args.evidence)
    root, result = checked_fixture(args.fixture)
    if hashlib.sha256(SIGNER.read_bytes()).hexdigest() != SIGNER_SHA:
        raise ValueError('external Owner signer binary changed')
    cfg = config(root, result, evidence, args.proxy_port)
    if args.action == 'sign-device': sign_device(root, result, evidence, cfg)
    elif args.action == 'refresh-node': refresh_node(root, result, evidence)
    elif args.action == 'publish': publish(root, result, evidence, cfg)
    elif args.action == 'refresh': publish(root, result, evidence, cfg, refresh=True)
    elif args.action == 'sign-groups': sign_groups(root, result, evidence, cfg)
    config(root, result, evidence, args.proxy_port)
    save(evidence / 'external-signer.json', {'binary_sha256': SIGNER_SHA,
        'source_commit': '967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a',
        'protocol': 'unchanged OwnerDeviceGrant v1 and OwnerLinkKeyGrant v2', 'private_key_in_android': False})
    print(json.dumps({'result': 'PASS', 'action': args.action, 'fixture_kind': 'SYNTHETIC_PROTOCOL_ONLY'}))


if __name__ == '__main__':
    os.umask(0o077)
    main()
