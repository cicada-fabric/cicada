#!/usr/bin/env python3
"""Test-only HTTP proxy that loses one selected Hub response after Hub accepted it.

Run inside a local Docker container with host networking. It never logs packet
contents, grants, or response bodies and must not be used as an App endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, default=8790)
    parser.add_argument("--target", type=int, default=8789)
    parser.add_argument("--drop-path", default="")
    parser.add_argument("--drop-operation", default="")
    parser.add_argument("--result-evidence-file", default="")
    parser.add_argument("--max-body-bytes", type=int, default=256 * 1024)
    args = parser.parse_args()
    guard = threading.Lock()
    dropped = False

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.forward(b"")

        def do_POST(self) -> None:
            try:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    chunks = []
                    total = 0
                    while True:
                        size_line = self.rfile.readline(128)
                        size = int(size_line.split(b";", 1)[0].strip(), 16)
                        if size == 0:
                            while self.rfile.readline(8192).strip():
                                pass
                            break
                        total += size
                        if total > args.max_body_bytes:
                            raise ValueError("request exceeds test proxy limit")
                        chunk = self.rfile.read(size)
                        if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                            raise ValueError("invalid chunked request")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > args.max_body_bytes:
                        raise ValueError("request exceeds test proxy limit")
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete request")
            except (ValueError, OSError):
                self.send_error(413)
                self.close_connection = True
                return
            self.forward(body)

        def do_PUT(self) -> None:
            self.do_POST()

        def record_accepted_node_result(self, body: bytes, status: int) -> None:
            if not args.result_evidence_file or status != 200:
                return
            match = re.fullmatch(r"/v2/relay/nodes/[^/]+/jobs/([^/]+)/result", self.path)
            if not match:
                return
            try:
                submitted = json.loads(body)
                thread_id = submitted["thread_id"]
                if not isinstance(thread_id, str) or not thread_id:
                    return
                evidence = {
                    "worker_sha256": hashlib.sha256(match.group(1).encode()).hexdigest(),
                    "thread_sha256": hashlib.sha256(thread_id.encode()).hexdigest(),
                    "attempt": submitted["attempt"],
                    "status": submitted["status"],
                    "hub_status": status,
                }
                encoded = (json.dumps(evidence, sort_keys=True) + "\n").encode()
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(args.result_evidence_file, flags, 0o600)
                with os.fdopen(descriptor, "ab") as output:
                    output.write(encoded)
            except (KeyError, TypeError, ValueError, OSError):
                return

        def forward(self, body: bytes) -> None:
            nonlocal dropped
            connection = http.client.HTTPConnection("127.0.0.1", args.target, timeout=45)
            try:
                excluded = {"host", "connection", "content-length", "transfer-encoding"}
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() not in excluded}
                connection.request(self.command, self.path, body=body if self.command in ("POST", "PUT") else None,
                                   headers=headers)
                response = connection.getresponse()
                if response.getheader("Content-Type", "").startswith("text/event-stream"):
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {"connection", "content-length", "transfer-encoding"}:
                            self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    while True:
                        chunk = response.read1(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    return
                content = response.read()
                self.record_accepted_node_result(body, response.status)
                operation = ""
                if self.path == args.drop_path and args.drop_operation:
                    try:
                        operation = json.loads(body).get("route", {}).get("operation", "")
                    except (ValueError, AttributeError):
                        operation = ""
                matches = self.path == args.drop_path and operation == args.drop_operation
                with guard:
                    lose = matches and not dropped and response.status in (200, 201)
                    if lose:
                        dropped = True
                if lose:
                    print(f"DROPPED path={self.path} operation={operation or '-'} "
                          f"hub_status={response.status}", flush=True)
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in {"connection", "content-length", "transfer-encoding"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (OSError, http.client.HTTPException):
                self.send_error(502)
            finally:
                connection.close()

    server = ThreadingHTTPServer(("127.0.0.1", args.listen), Handler)
    server.daemon_threads = True
    print(f"READY listen={args.listen} target={args.target} drop={args.drop_path} "
          f"operation={args.drop_operation or '-'}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
