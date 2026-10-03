#!/usr/bin/env python3
"""Read-only checks between actual carrier READY and the declared Android flow."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
REPO = Path('/home/zyf/CICADA_CLIENT')
CACHE = Path('/gpu1-share/data/cicada-client')
SCHEMA = 'cicada.client-v164-host-stdio-carrier.v1'
ROUTES = sorted([
    'GET /v2/client/identity', 'GET /v2/client/capabilities',
    'POST /v2/client/devices/enroll', 'POST /v2/client/rpc',
    'POST /v2/client/rpc/recover',
])


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('hot preflight JSON contains a duplicate field')
        value[key] = item
    return value


def read_bytes(path, maximum, modes=(0o600,)):
    path = Path(path)
    before = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISREG(before.st_mode) or \
            before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) not in modes or \
            before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('hot preflight input must be an owned bounded regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != \
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError('hot preflight input changed while opening')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(raw) != opened.st_size or (after.st_size, after.st_mtime_ns) != \
                (opened.st_size, opened.st_mtime_ns):
            raise ValueError('hot preflight input changed while reading')
    return raw


def decode(raw):
    def reject_constant(_value):
        raise ValueError('hot preflight JSON contains a non-finite number')
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def process_exists(pid):
    if type(pid) is not int or pid <= 0:
        raise ValueError('hot preflight requires the actual carrier process IDs')
    os.kill(pid, 0)


def check_carrier(evidence, tag, host_pid, carrier_pid):
    if not isinstance(tag, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,96}', tag) is None:
        raise ValueError('carrier evidence tag is invalid')
    marker_raw = read_bytes(evidence / ('stdio-carrier-' + tag + '.private.json'), 16 * 1024)
    marker = decode(marker_raw)
    if not isinstance(marker, dict) or marker.get('schema') != SCHEMA or marker.get('result') != 'RUNNING' or \
            marker.get('tag') != tag or type(marker.get('host_pid')) is not int or marker['host_pid'] != host_pid or \
            type(marker.get('docker_exec_pid')) is not int or marker['docker_exec_pid'] != carrier_pid or \
            marker.get('proxy_pid') is not None or marker.get('fault') != 'none' or \
            marker.get('emulator_container') != 'cicada-' + evidence.parent.name or \
            marker.get('emulator_label') != evidence.parent.name or \
            marker.get('emulator_network_mode') != 'none' or marker.get('allowed_routes') != ROUTES or \
            marker.get('payload_persistence') != 'NONE':
        raise ValueError('actual carrier marker differs from its READY identity and route boundary')
    log_path = evidence / ('stdio-carrier-' + tag + '.redacted.jsonl')
    log_raw = read_bytes(log_path, 16 * 1024)
    records = [decode(line) for line in log_raw.splitlines()]
    expected = {
        'event': 'ready', 'tag': tag, 'host_pid': host_pid, 'docker_exec_pid': carrier_pid,
        'proxy_pid': None, 'fault': 'none', 'allowed_route_count': 5, 'payload_persisted': False,
    }
    if records != [expected]:
        raise ValueError('carrier has unexpected activity before the first declared flow')
    process_exists(host_pid)
    process_exists(carrier_pid)
    return marker_raw, log_raw


def load_consumer(path, expected_sha):
    path = Path(path)
    if REPO not in path.parents and CACHE not in path.parents:
        raise ValueError('runtime consumer must come from the declared Client source')
    if not isinstance(expected_sha, str) or re.fullmatch(r'[0-9a-f]{64}', expected_sha) is None:
        raise ValueError('runtime consumer requires its independently declared full source SHA-256')
    raw = read_bytes(path, 256 * 1024, (0o600, 0o644))
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('runtime consumer source differs from its declared SHA-256')
    spec = importlib.util.spec_from_file_location('bounded_hot_runtime_consumer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight(args):
    consumer = load_consumer(args.consumer_script, args.consumer_sha256)
    evidence = consumer.driver.private_evidence(args.evidence_root)
    marker_raw, log_raw = check_carrier(evidence, args.tag, args.carrier_host_pid, args.carrier_pid)
    state, _artifacts = consumer.check_evidence(evidence, args)
    boot = consumer.bootstrap_preflight(evidence, state)
    if boot.get('result') != 'ANDROID_BOOTSTRAP_CHECK_PASS':
        raise ValueError('Android artifact and runtime preflight did not pass')
    # No flow is released if the carrier changed or became active during checks.
    marker_after, log_after = check_carrier(evidence, args.tag, args.carrier_host_pid, args.carrier_pid)
    if marker_after != marker_raw or log_after != log_raw:
        raise ValueError('carrier identity or activity changed during hot preflight')
    return {
        'result': 'PASS', 'container_id': boot['container_id'],
        'host_pid': args.carrier_host_pid, 'carrier_pid': args.carrier_pid,
        'tag': args.tag, 'fault': 'none', 'allowed_route_count': 5,
        'transaction_count': 0, 'marker_sha256': hashlib.sha256(marker_raw).hexdigest(),
        'log_sha256': hashlib.sha256(log_raw).hexdigest(),
        'android_preflight': 'ANDROID_BOOTSTRAP_CHECK_PASS',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence-root', 'run-id', 'tag', 'consumer-script', 'consumer-sha256',
            'delivery-pins', 'delivery-pins-sha256', 'delivery-metadata',
            'delivery-metadata-sha256', 'fixture-root'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--carrier-host-pid', type=int, required=True)
    parser.add_argument('--carrier-pid', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(preflight(args), separators=(',', ':')), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
