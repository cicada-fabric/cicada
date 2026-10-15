#!/usr/bin/env python3
"""Opaque loopback HTTP endpoint carried over one Docker exec STDIO stream.

The Android emulator has Docker network mode ``none``. This tiny listener lives
inside that owned emulator, accepts only the Client-Control v2 routes, and
relays request/response frames to a host-side coordinator over its existing
``docker exec -i`` pipes. Payload bytes are never decoded, printed, or saved.
"""

import argparse
import base64
import json
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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


def emit(value):
    data = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    if len(data) > MAX_FRAME_BYTES:
        raise ValueError('carrier frame exceeds its bound')
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def read_responses(response_queue, stop_event):
    while not stop_event.is_set():
        line = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
        if not line:
            stop_event.set()
            return
        if len(line) > MAX_FRAME_BYTES or not line.endswith(b'\n'):
            stop_event.set()
            return
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            stop_event.set()
            return
        if not isinstance(value, dict):
            stop_event.set()
            return
        if value.get('kind') == 'shutdown':
            # Wake a handler waiting on the single in-flight transaction before
            # asking the synchronous HTTPServer loop to stop.
            try:
                response_queue.put_nowait({'kind': 'drop'})
            except queue.Full:
                pass
            stop_event.set()
            return
        if value.get('kind') not in ('response', 'drop'):
            stop_event.set()
            return
        response_queue.put(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--android-url-port', type=int, required=True)
    args = parser.parse_args()
    if not all(1024 <= port <= 65535 for port in (args.listen_port, args.android_url_port)) or \
            args.listen_port == args.android_url_port:
        parser.error('expected distinct explicit high ports')

    stop_event = threading.Event()
    response_queue = queue.Queue(maxsize=1)
    io_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(60)

        def log_message(self, *_args):
            pass

        def do_GET(self):
            try:
                if self.headers.get('Transfer-Encoding') or int(self.headers.get('Content-Length', '0')) != 0:
                    self.close_connection = True
                    return
            except ValueError:
                self.close_connection = True
                return
            self.forward(b'')

        def do_POST(self):
            try:
                length_text = self.headers.get('Content-Length', '0')
                length = int(length_text)
                if self.headers.get('Transfer-Encoding') or not 0 <= length <= MAX_REQUEST_BYTES:
                    raise ValueError('invalid request bound')
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete request')
            except (ValueError, OSError):
                self.close_connection = True
                return
            self.forward(body)

        def forward(self, body):
            if (self.command, self.path) not in ALLOWED or len(body) > MAX_REQUEST_BYTES:
                self.close_connection = True
                return
            request_headers = {}
            for name in ('Content-Type', 'Accept'):
                value = self.headers.get(name)
                if value is not None and '\r' not in value and '\n' not in value and len(value) <= 256:
                    request_headers[name.lower()] = value
            frame = {
                'kind': 'request',
                'method': self.command,
                'path': self.path,
                'headers': request_headers,
                'body_b64': base64.b64encode(body).decode('ascii'),
                'body_bytes': len(body),
            }
            try:
                with io_lock:
                    emit(frame)
                    response = response_queue.get(timeout=90)
            except (OSError, ValueError, queue.Empty):
                self.close_connection = True
                return
            if response.get('kind') == 'drop':
                self.close_connection = True
                try:
                    self.connection.shutdown(2)
                except OSError:
                    pass
                return
            status = response.get('status')
            headers = response.get('headers')
            encoded = response.get('body_b64')
            if not isinstance(status, int) or not 100 <= status <= 599 or \
                    not isinstance(headers, dict) or not isinstance(encoded, str):
                self.close_connection = True
                return
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error):
                self.close_connection = True
                return
            if len(content) > MAX_RESPONSE_BYTES:
                self.close_connection = True
                return
            self.send_response(status)
            for name in ('Content-Type', 'Content-Encoding'):
                value = headers.get(name.lower())
                if isinstance(value, str) and '\r' not in value and '\n' not in value and len(value) <= 256:
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(content)
            self.wfile.flush()
            self.close_connection = True

    class Server(HTTPServer):
        allow_reuse_address = True
        timeout = 0.5

    server = Server(('127.0.0.1', args.listen_port), Handler)
    reader = threading.Thread(target=read_responses, args=(response_queue, stop_event), daemon=True)

    def stop_when_requested():
        stop_event.wait()
        server.shutdown()

    watcher = threading.Thread(target=stop_when_requested, daemon=True)
    reader.start()
    watcher.start()
    emit({'kind': 'ready', 'listen_port': args.listen_port,
          'android_url_port': args.android_url_port, 'allowed_route_count': len(ALLOWED)})
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (OSError, ValueError, RuntimeError):
        # The Docker exec channel carries protocol frames only. Never leak data
        # or a request-derived exception to either output stream.
        raise SystemExit(1)
