#!/usr/bin/env python3
"""Lose one accepted test response; retain only bounded request/response hashes.

Derived from drop-first-response-proxy.py. Use only an independently verified
disposable Hub. This proxy does not access Hub state or cryptographic keys.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def digest(value):
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', type=int, required=True)
    parser.add_argument('--target', type=int, required=True)
    parser.add_argument('--target-host', default='127.0.0.1')
    parser.add_argument('--drop-path', choices=('/v2/client/devices/enroll', '/v2/client/rpc'), required=True)
    parser.add_argument('--drop-operation', default='')
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.target_host)
    if not isinstance(address, ipaddress.IPv4Address) or not (address.is_private or address.is_loopback):
        parser.error('target must be an explicitly pinned private IPv4 address')
    if not all(1024 <= port <= 65535 for port in (args.listen, args.target)):
        parser.error('expected explicit high ports')
    if (args.drop_path == '/v2/client/rpc') != bool(args.drop_operation):
        parser.error('an RPC operation is required only for RPC response loss')
    evidence = Path(args.evidence)
    if evidence.is_symlink() or not evidence.parent.is_dir() or evidence.parent.stat().st_mode & 0o077:
        parser.error('evidence must be in a private directory')
    if evidence.exists():
        parser.error('use a fresh evidence file for this single fault')
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    lock = threading.Lock()
    dropped = False

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.forward(b'')

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if self.headers.get('Transfer-Encoding') or not 0 <= length <= 256 * 1024:
                    raise ValueError('unbounded request')
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete request')
            except (ValueError, OSError):
                self.send_error(413)
                self.close_connection = True
                return
            self.forward(body)

        def forward(self, body):
            nonlocal dropped
            operation = ''
            if self.path in ('/v2/client/rpc', '/v2/client/rpc/recover'):
                try:
                    operation = json.loads(body)['route']['operation']
                except (KeyError, TypeError, ValueError):
                    pass
            matches = self.path == args.drop_path and operation == args.drop_operation
            recovery = args.drop_path == '/v2/client/rpc' and self.path == '/v2/client/rpc/recover' and operation == args.drop_operation
            connection = http.client.HTTPConnection(args.target_host, args.target, timeout=45)
            try:
                excluded = {'host', 'connection', 'content-length', 'transfer-encoding'}
                headers = {key: value for key, value in self.headers.items() if key.lower() not in excluded}
                connection.request(self.command, self.path, body=body if self.command == 'POST' else None, headers=headers)
                response = connection.getresponse()
                content = response.read(4 * 1024 * 1024 + 1)
                if len(content) > 4 * 1024 * 1024:
                    raise ValueError('upstream response exceeds the test bound')
                with lock:
                    lose = matches and not dropped and response.status in (200, 201)
                    if lose:
                        dropped = True
                    if matches or recovery:
                        record = {'schema': 'cicada.client-v15-response-loss.v1',
                                  'request_sha256': digest(body), 'response_sha256': digest(content),
                                  'http_status': response.status, 'dropped': lose,
                                  'kind': 'recover' if recovery else 'original_or_exact_retry',
                                  'request_bytes': len(body), 'response_bytes': len(content)}
                        if args.drop_path == '/v2/client/rpc' and response.status == 200:
                            try:
                                packet = json.loads(content)
                                envelope = packet['envelope']
                                if isinstance(envelope, str):
                                    record['response_envelope_sha256'] = digest(envelope.encode())
                            except (KeyError, TypeError, ValueError):
                                pass
                        encoded = (json.dumps(record, separators=(',', ':')) + '\n').encode()
                        os.write(descriptor, encoded)
                        os.fsync(descriptor)
                if lose:
                    print('DROPPED accepted response; hashes recorded', flush=True)
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in excluded:
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (OSError, ValueError, http.client.HTTPException):
                self.send_error(502)
            finally:
                connection.close()

    server = ThreadingHTTPServer(('127.0.0.1', args.listen), Handler)
    server.daemon_threads = True
    print('READY response-loss proxy; no payload logging', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        os.close(descriptor)


if __name__ == '__main__':
    os.umask(0o077)
    main()
