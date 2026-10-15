#!/usr/bin/env python3
"""Boot the pinned offline emulator for the bounded acceptance supervisor.

This internal fixture helper creates no Hub, device identity, signing request
or business RPC. Its parent supervisor owns the fixed deadline and teardown.
"""

import argparse
import datetime
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

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CACHE = Path('/gpu1-share/data/cicada-client')
REPO = HERE.parents[1]
SCHEMA = 'cicada.client-v164-launcher-boot.v1'
IMAGE = 'sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f'
LABEL = 'org.cicada.client-v164-deterministic'
APK_HASHES = {
    'app': '56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67',
    'test': 'caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6',
}
PROPERTIES = {
    'api_level': ('ro.build.version.sdk', '35'),
    'android_release': ('ro.build.version.release', '15'),
    'abi': ('ro.product.cpu.abi', 'x86_64'),
    'emulator': ('ro.kernel.qemu', '1'),
}
READY = {'result': 'READY', 'adb_port': 5070, 'serial': 'emulator-5640'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('READY marker contains duplicate fields')
        result[key] = value
    return result


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def save_new(path, value):
    raw = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    return hashlib.sha256(raw).hexdigest()


def utc_now():
    now = datetime.datetime.now(datetime.timezone.utc)
    fraction = f'{now.microsecond:06d}'.rstrip('0')
    return now.strftime('%Y-%m-%dT%H:%M:%S') + ('.' + fraction if fraction else '') + 'Z'


def idle_seconds(value):
    if not isinstance(value, str) or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value) is None:
        raise ValueError('bootstrap idle deadline must be an exact UTC second')
    return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
        tzinfo=datetime.timezone.utc).timestamp()


def copy_apk(source, target, expected_sha):
    source = Path(source)
    info = source.lstat()
    if source.resolve(strict=True) != source or CACHE not in source.parents or \
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or \
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= 256 * 1024 * 1024:
        raise ValueError('APK must be an owned bounded private Client cache file')
    digest = hashlib.sha256()
    src_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    dst_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(src_fd, 'rb') as original, os.fdopen(dst_fd, 'wb') as copied:
        before = os.fstat(original.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise ValueError('APK changed while opening')
        while block := original.read(1024 * 1024):
            digest.update(block)
            copied.write(block)
        after = os.fstat(original.fileno())
        if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or \
                digest.hexdigest() != expected_sha:
            raise ValueError('APK changed or differs from its frozen SHA-256')
        copied.flush()
        os.fsync(copied.fileno())


def boot(args):
    if not args.execute or type(args.supervisor_pid) is not int or args.supervisor_pid != os.getppid():
        raise ValueError('bootstrap requires its actual approving parent supervisor')
    if re.fullmatch(r'v16-deterministic-v164-f6-[A-Za-z0-9_-]{1,80}', args.run_id) is None:
        raise ValueError('unsafe Android evidence run ID')
    evidence = Path(args.evidence_root)
    if evidence != CACHE / args.run_id / 'android' or evidence.parent.resolve() != evidence.parent or \
            evidence.parent.exists() or evidence.parent.is_symlink():
        raise ValueError('bootstrap requires a fresh exact nonsymlinked evidence run')
    idle = idle_seconds(args.idle_deadline)
    if not 90 < idle - time.time() <= 1200:
        raise ValueError('original fixed idle deadline must be 90..1200 seconds ahead')
    spec = importlib.util.spec_from_file_location('bounded_boot_driver', HERE / 'v164-android-deterministic.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    if runner.driver.IMAGE != IMAGE:
        raise ValueError('bootstrap driver emulator image differs from the frozen image')
    evidence.parent.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    start = time.monotonic()
    limit = min(start + 90, start + idle - time.time())

    def command(name, argv, expected=0):
        remaining = min(limit - time.monotonic(), idle - time.time())
        if remaining <= 0:
            raise RuntimeError('bootstrap budget exhausted; no retry')
        started_at = utc_now()
        command_start = time.monotonic()
        timed_out = False
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                timeout=min(30, remaining))
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            code, raw, timed_out = 124, (error.stdout or b'') + (error.stderr or b''), True
        output = raw.decode(errors='replace').strip()
        # Raw-property receipts retain the exact shape shared with the consumer.
        save_new(evidence / (name + '.json'), {
            'command': argv, 'exit_code': code, 'expected_exit_code': expected,
            'result': 'PASS' if code == expected else 'FAIL', 'output': output,
        })
        save_new(evidence / (name + '-timing.redacted.json'), {
            'command': argv, 'started_at_utc': started_at, 'ended_at_utc': utc_now(),
            'duration_seconds': time.monotonic() - command_start,
            'timeout_seconds': min(30, remaining), 'timed_out': timed_out,
            'exit_code': code, 'fixed_idle_deadline': args.idle_deadline,
            'output_sha256': hashlib.sha256(raw).hexdigest(),
        })
        if code != expected:
            raise RuntimeError(name + ' failed; preserve the original attempt')
        return output

    if command('docker-root', ['docker', 'info', '--format', '{{.DockerRootDir}}']) != '/gpu1-share/data/docker-root':
        raise ValueError('Docker data root differs from the declared root')
    if command('image-id', ['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}']) != IMAGE:
        raise ValueError('actual immutable emulator image differs')
    for name, expected in APK_HASHES.items():
        copy_apk(getattr(args, name + '_apk'), evidence / ('installed-' + name + '.private.apk'), expected)
    state = {
        'schema': runner.SCHEMA, 'run_id': args.run_id, 'container': 'cicada-' + args.run_id,
        'image_id': IMAGE, 'emulator_port': 5640, 'adb_port': 5070,
        'evidence': str(evidence), 'network': 'none',
    }
    save_new(evidence / 'android-driver.json', state)
    argv = [
        'docker', 'run', '--rm', '-d', '--user', 'root', '--name', state['container'],
        '--label', LABEL + '=' + args.run_id, '--device', '/dev/kvm', '--network', 'none',
        '-e', 'CICADA_TWO_OWNER_EMULATOR_PORT=5640', '-e', 'ANDROID_ADB_SERVER_PORT=5070',
        '-e', f'CICADA_EVIDENCE_OWNER={os.getuid()}:{os.getgid()}',
        '-v', str(REPO) + ':/workspace:ro', '-v', str(evidence) + ':/out',
        '-v', str(evidence / 'installed-app.private.apk') + ':/tmp/cicada-v15-app.apk:ro',
        '-v', str(evidence / 'installed-test.private.apk') + ':/tmp/cicada-v15-test.apk:ro',
        IMAGE, 'bash', '/workspace/scripts/interop/two-owner-emulator.sh',
    ]
    container_id = command('emulator-start', argv)
    if re.fullmatch(r'[0-9a-f]{64}', container_id) is None:
        raise ValueError('Docker did not return a full owned container ID')
    marker_path = evidence / 'emulator-ready.json'
    while not marker_path.exists():
        if min(limit - time.monotonic(), idle - time.time()) <= 0:
            raise RuntimeError('bootstrap READY budget exhausted; no retry')
        time.sleep(0.1)
    marker_info = marker_path.lstat()
    if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid() or \
            stat.S_IMODE(marker_info.st_mode) != 0o600 or marker_info.st_nlink != 1 or \
            not 0 < marker_info.st_size <= 4096:
        raise ValueError('emulator READY marker is unsafe')
    marker_fd = os.open(marker_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(marker_fd, 'rb') as ready_file:
        opened = os.fstat(ready_file.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != \
                (marker_info.st_dev, marker_info.st_ino, marker_info.st_size, marker_info.st_mtime_ns):
            raise ValueError('READY marker changed while opening')
        marker_raw = ready_file.read(4097)
        if len(marker_raw) != opened.st_size:
            raise ValueError('READY marker changed while reading')
    marker = json.loads(marker_raw, object_pairs_hook=unique_object)
    if marker != READY:
        raise ValueError('actual emulator READY marker differs')
    observed = utc_now()
    save_new(evidence / 'emulator-readiness.redacted.json', {
        'container_id': container_id, 'marker': marker, 'observed_at_utc': observed, 'result': 'READY',
    })
    for name, fmt in (
        ('container-id', '{{.Id}}'),
        ('container-config', '{{.Image}} {{index .Config.Labels "' + LABEL + '"}} {{.HostConfig.NetworkMode}}'),
        ('container-networks', '{{json .NetworkSettings.Networks}}'),
    ):
        command(name, ['docker', 'inspect', '--format', fmt, state['container']])
    runner.owned_state(evidence)
    adb = runner.driver.adb(state)
    for name in APK_HASHES:
        command('install-' + name, [*adb, 'install', '-r', '/tmp/cicada-v15-' + name + '.apk'])
    properties = {}
    for field, (prop, expected) in PROPERTIES.items():
        properties[field] = command('runtime-' + field, [*adb, 'shell', 'getprop', prop])
        if properties[field] != expected:
            raise ValueError('actual Android runtime property differs')
    save_new(evidence / 'android-runtime.redacted.json', {'schema': runner.SCHEMA, 'image_id': IMAGE, **properties})
    receipt = {
        'schema': SCHEMA, 'result': 'BOOT_READY', 'run_id': args.run_id,
        'evidence_root': str(evidence), 'container': state['container'], 'container_id': container_id,
        'image_id': IMAGE, 'network': 'none', 'app_sha256': APK_HASHES['app'],
        'test_sha256': APK_HASHES['test'], 'runtime_properties': properties,
        'ready_observed_at_utc': observed, 'idle_deadline': args.idle_deadline,
        'supervisor_pid': args.supervisor_pid, 'cold_boot_elapsed_seconds': time.monotonic() - start,
        'supervision': 'LAUNCHER_ONLY', 'business': 'NOT_RUN',
    }
    path = evidence / 'launcher-boot.redacted.json'
    return {'result': 'BOOT_READY', 'receipt_path': str(path), 'receipt_sha256': save_new(path, receipt)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run-id', 'evidence-root', 'app-apk', 'test-apk', 'idle-deadline'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--supervisor-pid', type=int, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if not args.execute:
        parser.error('runtime bootstrap requires a separately approved parent launcher --execute')
    print(json.dumps(boot(args)), flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
