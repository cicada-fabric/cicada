#!/usr/bin/env python3
"""Loopback-only test proxy for one interrupted encrypted Client RPC.

The Hub runtime image remains unchanged. The companion Go fixture mutates only
a marked disposable SQLite database; neither tool is a production endpoint.
"""

import argparse
import http.client
import json
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--hub-url", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--fixture-binary", required=True)
    parser.add_argument("--scenario", choices=("processing", "uncertain", "legacy"), required=True)
    parser.add_argument("--operation", required=True)
    args = parser.parse_args()
    target = urlsplit(args.hub_url)
    if target.scheme != "http" or target.hostname not in ("127.0.0.1", "localhost") or not target.port or target.path not in ("", "/"):
        parser.error("--hub-url must be a loopback HTTP origin for a disposable Hub")
    guard = threading.Lock()
    used = False
    ready = False

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass  # Never log Client packet, path query, credential, or response.

        def do_GET(self):
            self.handle_request(b"")

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 256 * 1024:
                self.send_error(413)
                return
            self.handle_request(self.rfile.read(length))

        def handle_request(self, body):
            nonlocal used, ready
            operation = ""
            if self.command == "POST" and self.path == "/v2/client/rpc":
                try:
                    operation = json.loads(body)["route"]["operation"]
                except (ValueError, KeyError, TypeError):
                    pass
            with guard:
                intercept = not used and operation == args.operation
                if intercept:
                    used = True
                blocked = not intercept and used and not ready and operation == args.operation
            if blocked:
                self.send_error(503)
                return
            if intercept:
                try:
                    result = subprocess.run(
                        [args.fixture_binary, "--db", args.db, "--mode", args.scenario],
                        input=body, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=20, check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    result = None
                if result is None or result.returncode != 0:
                    print("FIXTURE_FAILED; no request forwarded", flush=True)
                    self.send_error(502)
                    return
                with guard:
                    ready = True
                print(f"FAULT_READY scenario={args.scenario} operation={args.operation}", flush=True)
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            connection = http.client.HTTPConnection(target.hostname, target.port, timeout=45)
            try:
                excluded = {"host", "connection", "content-length", "transfer-encoding"}
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() not in excluded}
                connection.request(self.command, self.path,
                                   body=body if self.command == "POST" else None,
                                   headers=headers)
                response = connection.getresponse()
                content = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in excluded:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (OSError, http.client.HTTPException):
                self.send_error(502)
            finally:
                connection.close()

    server = ThreadingHTTPServer(("127.0.0.1", args.listen_port), Handler)
    server.daemon_threads = True
    print(f"READY listen={args.listen_port} scenario={args.scenario} operation={args.operation}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
