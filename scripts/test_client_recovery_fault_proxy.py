import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest


SCRIPT = Path(__file__).with_name("client-recovery-fault-proxy.py")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RecoveryFaultProxyTest(unittest.TestCase):
    def test_intercepts_only_one_named_rpc_and_forwards_recovery(self):
        counts = {"rpc": 0, "recover": 0}

        class Hub(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                data = b'{"hub_id":"test-hub"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                key = "recover" if self.path.endswith("/recover") else "rpc"
                counts[key] += 1
                data = b'{"code":"RECOVERY_UNAVAILABLE"}'
                self.send_response(409)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        hub = ThreadingHTTPServer(("127.0.0.1", 0), Hub)
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        with TemporaryDirectory() as root:
            fixture = Path(root) / "fixture.sh"
            fixture.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
            fixture.chmod(0o700)
            port = free_port()
            process = subprocess.Popen([
                sys.executable, str(SCRIPT), "--listen-port", str(port),
                "--hub-url", f"http://127.0.0.1:{hub.server_port}",
                "--db", str(Path(root) / "unused.sqlite3"),
                "--fixture-binary", str(fixture), "--scenario", "legacy",
                "--operation", "status.snapshot",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                        connection.request("GET", "/v2/client/identity")
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.load(response), {"hub_id": "test-hub"})
                        connection.close()
                        break
                    except OSError:
                        time.sleep(0.02)
                else:
                    self.fail("proxy did not start")
                packet = json.dumps({"route": {"operation": "status.snapshot"}}).encode()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request("POST", "/v2/client/rpc", body=packet)
                with self.assertRaises(http.client.RemoteDisconnected):
                    connection.getresponse()
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request("POST", "/v2/client/rpc/recover", body=packet)
                response = connection.getresponse()
                self.assertEqual(response.status, 409)
                self.assertEqual(json.load(response), {"code": "RECOVERY_UNAVAILABLE"})
                connection.close()
                self.assertEqual(counts, {"rpc": 0, "recover": 1})
            finally:
                process.terminate()
                process.wait(timeout=5)
        hub.shutdown()
        hub.server_close()

    def test_failed_fixture_never_forwards_matching_rpc(self):
        forwards = []

        class Hub(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                forwards.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        hub = ThreadingHTTPServer(("127.0.0.1", 0), Hub)
        threading.Thread(target=hub.serve_forever, daemon=True).start()
        with TemporaryDirectory() as root:
            fixture = Path(root) / "fixture.sh"
            fixture.write_text("#!/bin/sh\nexit 1\n")
            fixture.chmod(0o700)
            port = free_port()
            process = subprocess.Popen([
                sys.executable, str(SCRIPT), "--listen-port", str(port),
                "--hub-url", f"http://127.0.0.1:{hub.server_port}",
                "--db", str(Path(root) / "unused.sqlite3"),
                "--fixture-binary", str(fixture), "--scenario", "processing",
                "--operation", "status.snapshot",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                packet = json.dumps({"route": {"operation": "status.snapshot"}}).encode()
                for expected in (502, 503):
                    for _ in range(100):
                        try:
                            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                            connection.request("POST", "/v2/client/rpc", body=packet)
                            response = connection.getresponse()
                            self.assertEqual(response.status, expected)
                            response.read()
                            connection.close()
                            break
                        except OSError:
                            time.sleep(0.02)
                    else:
                        self.fail("proxy did not respond")
                self.assertEqual(forwards, [])
            finally:
                process.terminate()
                process.wait(timeout=5)
        hub.shutdown()
        hub.server_close()

    def test_concurrent_matching_rpc_cannot_bypass_preparing_fixture(self):
        forwards = []

        class Hub(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                forwards.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        hub = ThreadingHTTPServer(("127.0.0.1", 0), Hub)
        threading.Thread(target=hub.serve_forever, daemon=True).start()
        with TemporaryDirectory() as root:
            started = Path(root) / "started"
            fixture = Path(root) / "fixture.sh"
            fixture.write_text(f"#!/bin/sh\ntouch '{started}'\nsleep 0.3\ncat >/dev/null\n")
            fixture.chmod(0o700)
            port = free_port()
            process = subprocess.Popen([
                sys.executable, str(SCRIPT), "--listen-port", str(port),
                "--hub-url", f"http://127.0.0.1:{hub.server_port}",
                "--db", str(Path(root) / "unused.sqlite3"),
                "--fixture-binary", str(fixture), "--scenario", "processing",
                "--operation", "status.snapshot",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            packet = json.dumps({"route": {"operation": "status.snapshot"}}).encode()
            first_result = []

            def first_call():
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    connection.request("POST", "/v2/client/rpc", body=packet)
                    connection.getresponse()
                    first_result.append("unexpected response")
                except http.client.RemoteDisconnected:
                    first_result.append("dropped")

            try:
                for _ in range(100):
                    if process.poll() is not None:
                        self.fail("proxy exited")
                    try:
                        probe = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                        probe.close()
                        break
                    except OSError:
                        time.sleep(0.02)
                thread = threading.Thread(target=first_call)
                thread.start()
                for _ in range(100):
                    if started.exists():
                        break
                    time.sleep(0.01)
                else:
                    self.fail("fixture was not started")
                second = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                second.request("POST", "/v2/client/rpc", body=packet)
                response = second.getresponse()
                self.assertEqual(response.status, 503)
                response.read()
                second.close()
                thread.join(timeout=3)
                self.assertEqual(first_result, ["dropped"])
                self.assertEqual(forwards, [])
            finally:
                process.terminate()
                process.wait(timeout=5)
        hub.shutdown()
        hub.server_close()


if __name__ == "__main__":
    unittest.main()
