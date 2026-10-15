#!/usr/bin/env python3
"""Own one disposable Android emulator and record v1.3 instrumentation evidence.

This driver never starts or modifies a Hub. A core-provided disposable Hub is
connected with an explicit localhost reverse port. Staged public fixtures use
stdin, and a separate private file carries only short-lived Node pairing codes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
BASE = Path('/gpu1-share/data/cicada-client')
IMAGE = 'sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f'
LABEL = 'org.cicada.client-monitor-android'
PACKAGE = 'ai.cicada.client'


def save(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    Path(path).chmod(0o600)


def private_evidence(value):
    path = Path(value)
    if path.is_symlink() or path.resolve() != path or BASE not in path.parents:
        raise ValueError('evidence must be a real absolute directory under the Client data root')
    if not path.is_dir() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('evidence must be owned by the caller with mode 0700')
    return path


def available(port):
    try:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False


def run(evidence, step, command, *, data=None, junit=False):
    if (evidence / (step + '.json')).exists():
        history = evidence / 'history'
        history.mkdir(mode=0o700, exist_ok=True)
        revision = next(index for index in range(1, 10000)
                        if not (history / f'{step}.{index}.json').exists())
        for suffix in ('.json', '.private.log'):
            prior = evidence / (step + suffix)
            if prior.exists():
                save(history / (f'{step}.{revision}' + suffix), prior.read_bytes())
    try:
        proc = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=360)
        output, code = proc.stdout, proc.returncode
    except subprocess.TimeoutExpired as error:
        output, code = (error.stdout or b'') + b'\nDRIVER_TIMEOUT\n', 124
    text = output.decode(errors='replace').replace('\r\n', '\n')
    match = re.search(r'(?m)^OK \((\d+) tests?\)$', text) if junit else None
    passed = code == 0 and (not junit or (match and int(match[1]) > 0 and 'FAILURES!!!' not in text))
    save(evidence / (step + '.private.log'), output)
    summary = {'command': command, 'exit_code': code, 'driver_exit_code': 0 if passed else 1,
               'result': 'PASS' if passed else 'FAIL', 'junit': match[0] if match else None}
    if junit and (evidence / 'android-artifacts.json').exists():
        summary['android_artifacts'] = json.loads((evidence / 'android-artifacts.json').read_text())
    save(evidence / (step + '.json'), summary)
    if not passed:
        raise RuntimeError(f'{step} failed; see its restricted log and exit record')
    return output


def start(evidence):
    marker = evidence / 'android-driver.json'
    if marker.exists():
        raise ValueError('this evidence directory already owns an emulator')
    if subprocess.check_output(['docker', 'info', '--format', '{{.DockerRootDir}}'], text=True).strip() != '/gpu1-share/data/docker-root':
        raise ValueError('unexpected Docker data root')
    image = subprocess.check_output(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], text=True).strip()
    assert image == IMAGE
    run_id = evidence.parent.name
    if not re.fullmatch(r'monitor-v13-[A-Za-z0-9_-]{1,80}', run_id):
        raise ValueError('unsafe evidence run name')
    port = next(p for p in range(5640, 5678, 2) if available(p) and available(p + 1))
    adb_port = next(p for p in range(5070, 5100) if available(p))
    state = {'schema': 'cicada.client-monitor-android.v1', 'run_id': run_id,
             'container': 'cicada-' + run_id, 'image_id': IMAGE, 'emulator_port': port,
             'adb_port': adb_port, 'evidence': str(evidence)}
    save(marker, state)
    run(evidence, 'emulator-start', ['docker', 'run', '--rm', '-d', '--user', 'root',
        '--name', state['container'], '--label', LABEL + '=' + run_id, '--device', '/dev/kvm',
        '--network', 'host', '-e', f'CICADA_TWO_OWNER_EMULATOR_PORT={port}',
        '-e', f'ANDROID_ADB_SERVER_PORT={adb_port}', '-e', f'CICADA_EVIDENCE_OWNER={os.getuid()}:{os.getgid()}',
        '-v', f'{REPO}:/workspace:ro', '-v', f'{evidence}:/out', IMAGE,
        'bash', '/workspace/scripts/interop/two-owner-emulator.sh'])
    return {'result': 'BOOTING', 'serial': 'emulator-' + str(port), 'adb_port': adb_port}


def state_for(evidence):
    state = json.loads((evidence / 'android-driver.json').read_text())
    if (state.get('schema') != 'cicada.client-monitor-android.v1' or
            state.get('image_id') != IMAGE or state.get('evidence') != str(evidence) or
            state.get('run_id') != evidence.parent.name or
            state.get('container') != 'cicada-' + evidence.parent.name):
        raise ValueError('emulator marker mismatch')
    actual = subprocess.check_output(['docker', 'inspect', '--format',
        '{{.Image}} {{index .Config.Labels "' + LABEL + '"}}', state['container']], text=True).strip()
    if actual.split() != [IMAGE, state['run_id']]:
        raise ValueError('refusing to operate a foreign emulator')
    return state


def adb(state, interactive=False):
    return ['docker', 'exec'] + (['-i'] if interactive else []) + [state['container'],
        '/opt/android-sdk/platform-tools/adb', '-P', str(state['adb_port']), '-s',
        'emulator-' + str(state['emulator_port'])]


def remote(state):
    return 'no_backup/monitor-v13/' + state['run_id']


def stage(evidence, state, source, name):
    path = Path(source)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('staged input must be a private regular file')
    data = path.read_bytes()
    if len(data) > 256 * 1024:
        raise ValueError('staged fixture exceeds its bound')
    parsed = json.loads(data)
    if name == 'node-codes.json':
        if not isinstance(parsed, dict) or not parsed or not all(
                isinstance(k, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', k) and
                isinstance(v, str) and re.fullmatch(r'[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}', v)
                for k, v in parsed.items()):
            raise ValueError('private staging accepts only labeled Node pairing codes')
    else:
        def check(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if any(word in key.lower() for word in ('private', 'bearer', 'token', 'secret', 'credential')):
                        raise ValueError('fixture contains a prohibited credential field')
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
        check(parsed)
    directory = remote(state)
    shell = 'umask 077; mkdir -p ' + shlex.quote(directory) + '; cat > ' + shlex.quote(directory + '/' + name)
    run(evidence, 'stage-' + name, adb(state, True) + ['shell',
        shlex.join(['run-as', PACKAGE, 'sh', '-c', shell])], data=data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence')
    actions = parser.add_subparsers(dest='action', required=True)
    for name in ('start', 'install', 'stop'):
        actions.add_parser(name)
    p = actions.add_parser('reverse'); p.add_argument('port', type=int)
    p = actions.add_parser('test'); p.add_argument('test'); p.add_argument('--label')
    p = actions.add_parser('stage'); p.add_argument('source'); p.add_argument('name', choices=('fixture.json', 'node-codes.json'))
    p = actions.add_parser('export'); p.add_argument('name', choices=('device-public.json', 'setup.json', 'manifests.json', 'prepared.json', 'result.json'))
    p = actions.add_parser('screenshot'); p.add_argument('label')
    p = actions.add_parser('tap'); p.add_argument('label'); p.add_argument('x', type=int); p.add_argument('y', type=int)
    args = parser.parse_args()
    evidence = private_evidence(args.evidence)
    if args.action == 'start':
        print(json.dumps(start(evidence))); return
    state = state_for(evidence)
    if args.action == 'stop':
        run(evidence, 'emulator-stop', ['docker', 'stop', '--time', '10', state['container']])
        save(evidence / 'android-teardown.json', {'result': 'PASS', 'owned_emulator_removed': True})
    elif args.action == 'install':
        artifacts = {'client_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()}
        for name, part in (('app', 'debug/app-debug.apk'), ('test', 'androidTest/debug/app-debug-androidTest.apk')):
            relative = 'android/app/build/outputs/apk/' + part
            artifacts[name + '_sha256'] = hashlib.sha256((REPO / relative).read_bytes()).hexdigest()
            run(evidence, 'install-' + name, adb(state) + ['install', '-r', '/workspace/' + relative])
        save(evidence / 'android-artifacts.json', artifacts)
        save(evidence / ('android-artifacts-' + artifacts['app_sha256'] + '-' + artifacts['test_sha256'] + '.json'), artifacts)
    elif args.action == 'reverse':
        if not 1024 <= args.port <= 65535: raise ValueError('expected a high disposable Hub port')
        run(evidence, 'reverse-' + str(args.port), adb(state) + ['reverse', f'tcp:{args.port}', f'tcp:{args.port}'])
    elif args.action == 'stage':
        stage(evidence, state, args.source, args.name)
    elif args.action == 'export':
        data = run(evidence, 'export-' + args.name, adb(state) + ['exec-out', 'run-as', PACKAGE,
            'cat', remote(state) + '/' + args.name])
        json.loads(data)
        save(evidence / (args.name.removesuffix('.json') + '.private.json'), data)
        save(evidence / (args.name.removesuffix('.json') + '-' + hashlib.sha256(data).hexdigest() + '.private.json'), data)
    elif args.action == 'test':
        if not re.fullmatch(r'[A-Za-z0-9_.]+(?:#[A-Za-z0-9_]+)?', args.test): raise ValueError('invalid test selector')
        label = args.label or args.test.split('.')[-1].replace('#', '-')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', label): raise ValueError('invalid evidence label')
        run(evidence, label, adb(state) + ['shell', 'am', 'instrument', '-w', '-e', 'run_id', state['run_id'],
            '-e', 'class', args.test, PACKAGE + '.test/androidx.test.runner.AndroidJUnitRunner'], junit=True)
    else:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', args.label): raise ValueError('invalid evidence label')
        if args.action == 'screenshot':
            data = run(evidence, 'capture-' + args.label, adb(state) + ['exec-out', 'screencap', '-p'])
            save(evidence / (args.label + '.private.png'), data)
        else:
            if not 0 <= args.x <= 4096 or not 0 <= args.y <= 4096: raise ValueError('invalid screen coordinate')
            run(evidence, 'tap-' + args.label, adb(state) + ['shell', 'input', 'tap', str(args.x), str(args.y)])
    print(json.dumps({'result': 'PASS', 'action': args.action}))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
