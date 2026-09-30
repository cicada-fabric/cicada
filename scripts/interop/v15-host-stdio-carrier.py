#!/usr/bin/env python3
"""Host-side opaque HTTP coordinator for a v1.5 network-none Android emulator.

This coordinator is the only process that can reach the private Docker bridge.
It validates the Core-owned public fixture and Hub labels, then relays bounded
HTTP frames to either that exact Hub or the existing response-loss proxy. It
never decodes or persists request/response payload bytes.
"""

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import http.client
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = ROOT / 'scripts/interop/v15-android-deterministic.py'
PROXY_PATH = ROOT / 'scripts/interop/v15-drop-response-proxy.py'
SCHEMA = 'cicada.client-v15-host-stdio-carrier.v1'
HUB_IMAGE = 'sha256:4c321cd8f91a1e19befabd1f5c8983be46e6aed811614c68bd6f62ad06584771'
CORE_REVISION = 'bd79ff93c90ecafc28a2471dd9523444903b39e6'
SOURCE_FINGERPRINT = '586ca8adbbcf9ea18c83f03e59267ad848c10792452520f5d499ef08ae340f17'
CATALOG_SHA256 = 'a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68'
APP_SHA256 = '5bba1c02fb2b0233006661bd4a67fd3f60811c270cc825f9337c7f4170aaa1ee'
TEST_SHA256 = '11d8dc7166d539cc91e342553d740f969923d48667498c0c3cf105c5f0a8b5f9'
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FRAME_BYTES = 6 * 1024 * 1024
ALLOWED = {
    ('GET', '/v2/client/identity'),
    ('GET', '/v2/client/capabilities'),
    ('POST', '/v2/client/devices/enroll'),
    ('POST', '/v2/client/rpc'),
    ('POST', '/v2/client/rpc/recover'),
}


def load_driver():
    spec = importlib.util.spec_from_file_location('v15_deterministic', DRIVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_pinned_json(path_value):
    path = Path(path_value)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Core metadata must be a private regular file')
    return json.loads(path.read_bytes())


def verify_hub(fixture_path, public_path, recovery_mode=None):
    supplied = read_pinned_json(fixture_path)
    public = read_pinned_json(public_path)
    if recovery_mode:
        if recovery_mode not in ('processing', 'uncertain', 'legacy') or not isinstance(supplied, list):
            raise ValueError('expected a declared isolated recovery fixture')
        matching = [item for item in supplied if isinstance(item, dict) and item.get('mode') == recovery_mode]
        if len(matching) != 1:
            raise ValueError('recovery fixture selection must be unique')
        record = matching[0]
        if record.get('schema') != 'cicada.supervisor-recovery-fixture.v1' or \
                record.get('operation') != 'status.snapshot' or \
                record.get('fault') != 'READY_PROXY_ONLY_NO_FAULT_TRIGGERED' or \
                record.get('business_execution') != 'NOT_RUN' or \
                record.get('source_revision') != CORE_REVISION or record.get('image_id') != HUB_IMAGE:
            raise ValueError('Core recovery fixture does not match its declared test scope')
        container = record.get('container', '')
        if not isinstance(container, str) or not re.fullmatch(r'cicada-cn-[a-z0-9]+-hub', container) or \
                record.get('docker_network') != container.removesuffix('-hub') + '-net' or \
                record.get('private_bridge_origin') != 'http://' + container + ':18790':
            raise ValueError('refusing a non-disposable recovery target')
        fixture = {'container': container, 'network': record['docker_network'],
            'image': record['image_id'], 'source_revision': record['source_revision'],
            'client_public': record['client_public'], 'base_url': record['host_direct_origin']}
        expected_fixture_label, target_port = 'client-network', 18790
    else:
        if not isinstance(supplied, dict):
            raise ValueError('expected the declared base fixture')
        fixture = supplied
        if fixture.get('status') != 'READY' or fixture.get('purpose') != 'base' or \
                fixture.get('source_revision') != CORE_REVISION or fixture.get('image') != HUB_IMAGE:
            raise ValueError('Core base fixture does not match the trusted v1.5 pins')
        expected_fixture_label, target_port = 'supervisor-client-v15', 8787

    origin = urlsplit(public.get('base_url', ''))
    if origin.scheme != 'http' or origin.hostname != '127.0.0.1' or origin.username or origin.password or \
            origin.path or origin.query or origin.fragment or origin.port is None:
        raise ValueError('Android test origin must be an explicit loopback HTTP endpoint')
    if public.get('source_revision') != CORE_REVISION or \
            public.get('source_fingerprint') != SOURCE_FINGERPRINT or \
            public.get('catalog_sha256') != CATALOG_SHA256 or \
            public.get('contract_revision') != 'client-hub-v1.5' or \
            (not recovery_mode and (public.get('base_url') != 'http://127.0.0.1:32897' or \
                public.get('bridge_base_url') != 'http://hub:8787')):
        raise ValueError('Core public metadata does not match the trusted v1.5 pins')
    # The public key document does not carry a Docker container name. The
    # supervisor fixture owns that binding and names this exact public file.
    if fixture.get('client_public') != str(Path(public_path).resolve()) or \
            fixture.get('base_url') != public.get('base_url') or \
            fixture.get('network') != public.get('docker_network') or \
            fixture.get('image') != public.get('image_id'):
        raise ValueError('Core fixture and public metadata disagree')

    hub_name, network_name = fixture['container'], fixture['network']
    hub = json.loads(subprocess.check_output(['docker', 'inspect', hub_name], text=True))[0]
    network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', network_name], text=True))[0]
    labels = hub['Config'].get('Labels') or {}
    if not hub['State']['Running'] or hub['Image'] != HUB_IMAGE or hub['Config'].get('Image') != HUB_IMAGE:
        raise ValueError('Core base Hub container is not the trusted running image')
    expected_labels = {
        'org.cicada.fixture': expected_fixture_label,
        'org.cicada.role': 'hub',
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': SOURCE_FINGERPRINT,
        'org.cicada.client-catalog.sha256': CATALOG_SHA256,
        'org.opencontainers.image.revision': CORE_REVISION,
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise ValueError('Core Hub image labels do not match the trusted pins')
    endpoint = hub['NetworkSettings']['Networks'].get(network_name)
    if endpoint is None or (not recovery_mode and 'hub' not in (endpoint.get('Aliases') or [])):
        raise ValueError('Core Hub is not on its pinned bridge with the expected alias')
    if network.get('Driver') != 'bridge' or network.get('Internal') is True or \
            set(network['Containers']) != {hub['Id']}:
        raise ValueError('Core base bridge has an unexpected network or container set')
    target_ip = endpoint.get('IPAddress')
    try:
        address = ipaddress.IPv4Address(target_ip)
    except ipaddress.AddressValueError:
        raise ValueError('Core Hub has no pinned private IPv4 address') from None
    if not address.is_private:
        raise ValueError('Core Hub has no pinned private IPv4 address')
    target_ip = str(address)
    try:
        with socket.create_connection((target_ip, target_port), timeout=3):
            pass
    except OSError:
        raise ValueError('host cannot reach the independently pinned Core Hub bridge endpoint') from None
    return fixture, public, hub, network, target_ip, target_port


def verify_emulator(module, evidence):
    state = module.owned_state(evidence)
    if state.get('network') != 'none':
        raise ValueError('the existing Android emulator must remain in network-none mode')
    actual = json.loads(subprocess.check_output(['docker', 'inspect', state['container']], text=True))[0]
    if actual['HostConfig'].get('NetworkMode') != 'none' or \
            set(actual['NetworkSettings']['Networks']) != {'none'}:
        raise ValueError('refusing to route through a networked or foreign emulator')
    artifacts = json.loads((evidence / 'android-artifacts.json').read_text())
    if artifacts.get('app_sha256') != APP_SHA256 or artifacts.get('test_sha256') != TEST_SHA256:
        raise ValueError('the active emulator does not own the final APK3 pair')
    return state


def append_record(fd, value):
    raw = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    os.write(fd, raw)
    os.fsync(fd)


def write_frame(stream, value):
    raw = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError('response frame exceeds its bound')
    view = memoryview(raw)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise OSError('carrier STDIO closed while writing a bounded frame')
        view = view[written:]
    stream.flush()


def parse_frame(raw):
    if len(raw) > MAX_FRAME_BYTES or not raw.endswith(b'\n'):
        raise ValueError('invalid carrier frame size')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('invalid carrier frame object')
    return value


def run(args):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', args.tag):
        raise ValueError('invalid carrier tag')
    if args.fault not in ('none', 'enrollment', 'rpc'):
        raise ValueError('invalid fault selector')
    if args.recovery_mode and args.fault != 'none':
        raise ValueError('Core recovery fixtures exclusively own their fault injection')
    if not all(1024 <= port <= 65535 for port in (args.carrier_port, args.android_url_port)) or \
            args.carrier_port == args.android_url_port:
        raise ValueError('expected distinct high ports')
    module = load_driver()
    driver = module.driver
    evidence = driver.private_evidence(args.evidence)
    state = verify_emulator(module, evidence)
    fixture, public, hub, network, target_ip, upstream_port = verify_hub(args.fixture, args.public, args.recovery_mode)
    if public['base_url'] != f'http://127.0.0.1:{args.android_url_port}':
        raise ValueError('Android base URL port differs from the pinned Core public metadata')

    marker_path = evidence / ('stdio-carrier-' + args.tag + '.private.json')
    transaction_path = evidence / ('stdio-carrier-' + args.tag + '.redacted.jsonl')
    stopped_path = evidence / ('stdio-carrier-' + args.tag + '-stopped.redacted.json')
    if any(path.exists() for path in (marker_path, transaction_path, stopped_path)):
        raise ValueError('this carrier tag already has evidence')
    record_fd = os.open(transaction_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW, 0o600)

    proxy_process = None
    proxy_port = None
    stop_requested = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_requested.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop_requested.set())
    carrier_process = None
    setup_complete = False
    try:
        if args.fault != 'none':
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                proxy_port = sock.getsockname()[1]
            if args.fault == 'enrollment':
                drop_path, operation = '/v2/client/devices/enroll', ''
            else:
                drop_path, operation = '/v2/client/rpc', 'status.snapshot'
            proxy_record = evidence / ('response-loss-' + args.tag + '.private.jsonl')
            proxy_command = [sys.executable, str(PROXY_PATH), '--listen', str(proxy_port), '--target', '8787',
                '--target-host', target_ip, '--drop-path', drop_path, '--evidence', str(proxy_record)]
            if operation:
                proxy_command.extend(['--drop-operation', operation])
            proxy_process = subprocess.Popen(proxy_command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                start_new_session=True)
            ready_deadline = time.monotonic() + 10
            ready = ''
            while time.monotonic() < ready_deadline:
                if proxy_process.poll() is not None:
                    raise ValueError('owned response-loss proxy exited before ready')
                readable, _, _ = select.select([proxy_process.stdout], [], [], 0.2)
                if readable:
                    ready = proxy_process.stdout.readline().strip()
                    break
            if ready != 'READY response-loss proxy; no payload logging':
                proxy_process.terminate()
                proxy_process.wait(timeout=3)
                raise ValueError('owned response-loss proxy did not report ready')

        target_host, target_port = (('127.0.0.1', proxy_port) if proxy_port else (target_ip, upstream_port))
        carrier_command = ['docker', 'exec', '-i', state['container'], 'python3',
            '/workspace/scripts/interop/v15-stdio-carrier.py', '--listen-port', str(args.carrier_port),
            '--android-url-port', str(args.android_url_port)]
        carrier_process = subprocess.Popen(carrier_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)
        carrier_fd = carrier_process.stdout.fileno()
        ready_deadline = time.monotonic() + 10
        initial = bytearray()
        while time.monotonic() < ready_deadline and b'\n' not in initial:
            if carrier_process.poll() is not None:
                raise ValueError('in-emulator carrier exited before ready')
            readable, _, _ = select.select([carrier_process.stdout], [], [], 0.2)
            if readable:
                chunk = os.read(carrier_fd, 4096)
                if not chunk:
                    break
                initial.extend(chunk)
                if len(initial) > 8192:
                    break
        first, separator, remainder = bytes(initial).partition(b'\n')
        if not separator:
            raise ValueError('in-emulator carrier did not provide a readiness frame')
        ready_frame = parse_frame(first + b'\n')
        if ready_frame != {'kind': 'ready', 'listen_port': args.carrier_port,
                'android_url_port': args.android_url_port, 'allowed_route_count': 5}:
            raise ValueError('in-emulator carrier readiness frame did not match')

        marker = {
            'schema': SCHEMA,
            'result': 'RUNNING',
            'tag': args.tag,
            'host_pid': os.getpid(),
            'docker_exec_pid': carrier_process.pid,
            'proxy_pid': proxy_process.pid if proxy_process else None,
            'emulator_container': state['container'],
            'emulator_label': state['run_id'],
            'emulator_network_mode': 'none',
            'carrier_port': args.carrier_port,
            'android_url_port': args.android_url_port,
            'android_base_url': public['base_url'],
        'fault': args.fault,
        'core_recovery_mode': args.recovery_mode,
            'proxy_port': proxy_port,
            'hub_container': fixture['container'],
            'hub_image_id': fixture['image'],
            'hub_network': fixture['network'],
            'hub_network_id': network['Id'],
        'hub_ip_sha256': digest(target_ip.encode()),
        'hub_upstream_port': upstream_port,
            'hub_source_revision': fixture['source_revision'],
            'hub_source_fingerprint': public['source_fingerprint'],
            'catalog_sha256': public['catalog_sha256'],
            'allowed_routes': [method + ' ' + path for method, path in sorted(ALLOWED)],
            'payload_persistence': 'NONE',
        }
        fd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(marker, out, sort_keys=True)
            out.write('\n')
        append_record(record_fd, {'event': 'ready', 'tag': args.tag, 'host_pid': os.getpid(),
            'docker_exec_pid': carrier_process.pid, 'proxy_pid': proxy_process.pid if proxy_process else None,
            'fault': args.fault, 'allowed_route_count': len(ALLOWED), 'payload_persisted': False})
        print(json.dumps({'result': 'READY', 'tag': args.tag, 'host_pid': os.getpid(),
            'carrier_pid': carrier_process.pid, 'proxy_pid': proxy_process.pid if proxy_process else None,
            'fault': args.fault, 'allowed_route_count': len(ALLOWED)}, separators=(',', ':')), flush=True)

        setup_complete = True
    finally:
        if not setup_complete:
            # Startup is transactional: no proxy, exec process, or open
            # evidence descriptor survives a failed readiness/marker step.
            if carrier_process is not None:
                try:
                    write_frame(carrier_process.stdin, {'kind': 'shutdown'})
                except (OSError, ValueError, AttributeError):
                    pass
                try:
                    carrier_process.stdin.close()
                except (OSError, AttributeError):
                    pass
                try:
                    carrier_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    carrier_process.terminate()
                    try:
                        carrier_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        carrier_process.kill()
                        carrier_process.wait(timeout=3)
                for stream in (carrier_process.stdin, carrier_process.stdout):
                    try:
                        if stream is not None:
                            stream.close()
                    except OSError:
                        pass
            proxy_exit_on_setup_error = None
            if proxy_process is not None:
                proxy_process.terminate()
                try:
                    proxy_exit_on_setup_error = proxy_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy_process.kill()
                    proxy_exit_on_setup_error = proxy_process.wait(timeout=3)
                try:
                    proxy_process.stdout.close()
                except (OSError, AttributeError):
                    pass
            try:
                append_record(record_fd, {'event': 'setup_failed',
                    'carrier_exit_code': carrier_process.returncode if carrier_process else None,
                    'proxy_exit_code': proxy_exit_on_setup_error, 'payload_persisted': False})
            finally:
                os.close(record_fd)
            if marker_path.exists():
                try:
                    failed_marker = json.loads(marker_path.read_text())
                    failed_marker['result'] = 'SETUP_FAILED'
                    driver.save(marker_path, failed_marker)
                except (OSError, ValueError, TypeError):
                    pass
    buffer = bytearray(remainder)
    transaction = 0
    try:
        while not stop_requested.is_set():
            if carrier_process.poll() is not None:
                append_record(record_fd, {'event': 'carrier_exit', 'exit_code': carrier_process.returncode})
                break
            readable, _, _ = select.select([carrier_process.stdout], [], [], 0.2)
            if not readable:
                continue
            chunk = os.read(carrier_fd, 65536)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > MAX_FRAME_BYTES and b'\n' not in buffer:
                append_record(record_fd, {'event': 'invalid_frame', 'reason': 'frame_bound_exceeded'})
                break
            while b'\n' in buffer:
                raw, _, tail = buffer.partition(b'\n')
                buffer = bytearray(tail)
                frame = parse_frame(raw + b'\n')
                if frame.get('kind') != 'request':
                    append_record(record_fd, {'event': 'invalid_frame', 'reason': 'unexpected_kind'})
                    stop_requested.set()
                    break
                method, path = frame.get('method'), frame.get('path')
                encoded = frame.get('body_b64')
                headers = frame.get('headers')
                if (method, path) not in ALLOWED or not isinstance(encoded, str) or \
                        not isinstance(headers, dict):
                    append_record(record_fd, {'event': 'rejected_request', 'reason': 'route_or_shape_not_allowed'})
                    write_frame(carrier_process.stdin, {'kind': 'drop'})
                    continue
                try:
                    body = base64.b64decode(encoded, validate=True)
                except (ValueError, base64.binascii.Error):
                    append_record(record_fd, {'event': 'rejected_request', 'reason': 'invalid_body_encoding'})
                    write_frame(carrier_process.stdin, {'kind': 'drop'})
                    continue
                if len(body) != frame.get('body_bytes') or len(body) > MAX_REQUEST_BYTES:
                    append_record(record_fd, {'event': 'rejected_request', 'reason': 'body_bound_mismatch'})
                    write_frame(carrier_process.stdin, {'kind': 'drop'})
                    continue
                request_headers = {'Accept-Encoding': 'identity', 'Connection': 'close'}
                for key in ('content-type', 'accept'):
                    value = headers.get(key)
                    if isinstance(value, str) and len(value) <= 256 and '\r' not in value and '\n' not in value:
                        request_headers[key.title()] = value
                response_headers = {}
                status = None
                response_body = b''
                transport_failed = False
                connection = http.client.HTTPConnection(target_host, target_port, timeout=45)
                try:
                    connection.request(method, path, body=body if method == 'POST' else None,
                        headers=request_headers)
                    response = connection.getresponse()
                    response_body = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(response_body) > MAX_RESPONSE_BYTES:
                        raise ValueError('response bound exceeded')
                    status = response.status
                    for key in ('content-type', 'content-encoding'):
                        value = response.getheader(key)
                        if value and len(value) <= 256 and '\r' not in value and '\n' not in value:
                            response_headers[key] = value
                except (OSError, ValueError, http.client.HTTPException):
                    transport_failed = True
                finally:
                    connection.close()
                transaction += 1
                if transport_failed:
                    append_record(record_fd, {'event': 'transport_drop', 'transaction': transaction,
                        'method': method, 'path': path, 'request_bytes': len(body),
                        'request_sha256': digest(body), 'fault': args.fault})
                    write_frame(carrier_process.stdin, {'kind': 'drop'})
                    continue
                response_frame = {'kind': 'response', 'status': status, 'headers': response_headers,
                    'body_b64': base64.b64encode(response_body).decode('ascii')}
                append_record(record_fd, {'event': 'response', 'transaction': transaction,
                    'method': method, 'path': path, 'http_status': status,
                    'request_bytes': len(body), 'request_sha256': digest(body),
                    'response_bytes': len(response_body), 'response_sha256': digest(response_body),
                    'fault': args.fault})
                write_frame(carrier_process.stdin, response_frame)
    finally:
        try:
            write_frame(carrier_process.stdin, {'kind': 'shutdown'})
        except (OSError, ValueError):
            pass
        try:
            carrier_process.stdin.close()
        except OSError:
            pass
        try:
            carrier_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            carrier_process.terminate()
            try:
                carrier_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                carrier_process.kill()
                carrier_process.wait(timeout=3)
        proxy_exit = None
        if proxy_process:
            proxy_process.terminate()
            try:
                proxy_exit = proxy_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                proxy_exit = proxy_process.wait(timeout=3)
        append_record(record_fd, {'event': 'stopped', 'tag': args.tag,
            'docker_exec_exit_code': carrier_process.returncode, 'proxy_exit_code': proxy_exit,
            'transactions': transaction, 'payload_persisted': False})
        os.close(record_fd)
        stopped = {'schema': SCHEMA, 'result': 'PASS', 'tag': args.tag,
            'docker_exec_exit_code': carrier_process.returncode, 'proxy_exit_code': proxy_exit,
            'transactions': transaction, 'payload_persisted': False}
        fd = os.open(stopped_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(stopped, out, sort_keys=True)
            out.write('\n')
        print(json.dumps({'result': 'STOPPED', 'tag': args.tag,
            'docker_exec_exit_code': carrier_process.returncode, 'proxy_exit_code': proxy_exit,
            'transactions': transaction}, separators=(',', ':')), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--public', required=True)
    parser.add_argument('--fault', choices=('none', 'enrollment', 'rpc'), default='none')
    parser.add_argument('--recovery-mode', choices=('processing', 'uncertain', 'legacy'))
    parser.add_argument('--carrier-port', type=int, default=38097)
    parser.add_argument('--android-url-port', type=int, default=32897)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        run(args)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        print(json.dumps({'result': 'FAIL', 'tag': args.tag, 'reason': 'bounded carrier setup or relay failed'}),
            file=sys.stderr, flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
