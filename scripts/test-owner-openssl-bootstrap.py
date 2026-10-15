#!/usr/bin/env python3
"""Disposable synthetic PTY/OpenSSL/Hub test for external Owner bootstrap.

This driver uses only generated test keys and an isolated local Hub container.
It intentionally stores no terminal transcript, key material, proof bytes, or
Hub response bytes in its evidence output.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import termios
import threading
import time
import urllib.error
import urllib.request
import uuid


REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_EXPECTED_HELPER_SHA256 = "f0d7216b14daca417cd683bd55646a4fe87370cf93f07b78b4be6f426e9518f0"
EXPECTED_HUB_IMAGE = "sha256:fc90076f45293a36d304dd7e31d00b6052828c0b1748fdde2c616b5900ebe9d1"
DEFAULT_HELPER = REPOSITORY / ".cicada-data/owner-openssl-check-20261014/cicada-linux-amd64"
WORKSPACE = pathlib.Path(os.environ.get("CICADA_WORKSPACE_ROOT") or
    pathlib.Path(subprocess.check_output(
        ["git", "-C", str(REPOSITORY), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        text=True).strip()).parent.parent)
DEFAULT_OPENSSL = WORKSPACE / (
    ".local/evidence/legacy/CICADA-pqtls-data/pqtls-openssl-accepted-build/"
    "stage/opt/cicada-openssl/3.5.9/bin/openssl"
)
SYNTHETIC_PASSWORD = b"Synthetic-Only-Owner-Key-2026!"
MARKER_TEXT = "CICADA disposable external-Owner OpenSSL test scratch\n"
MAX_PTY_OUTPUT = 1 << 20
MAX_COMMAND_OUTPUT = 512 << 10
MAX_PROXY_BODY = 512 << 10


class DriverFailure(Exception):
    def __init__(self, phase: str, code: str):
        super().__init__(f"{phase}: {code}")
        self.phase = phase
        self.code = code


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256_pin(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise argparse.ArgumentTypeError("expected SHA-256 must be exactly 64 lowercase hexadecimal characters")
    return value


def write_json_exclusive(path: pathlib.Path, value: object, mode: int = 0o600) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def write_json_replace(path: pathlib.Path, value: object) -> None:
    temp = path.with_name(path.name + ".tmp")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    os.replace(temp, path)


def run_command(
    argv: list[str],
    *,
    phase: str,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 45,
) -> bytes:
    try:
        result = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DriverFailure(phase, "bounded command timeout") from error
    except OSError as error:
        raise DriverFailure(phase, "command could not start") from error
    if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > MAX_COMMAND_OUTPUT:
        raise DriverFailure(phase, "bounded command output exceeded")
    if result.returncode != 0:
        raise DriverFailure(phase, f"command exited {result.returncode}")
    return result.stdout


def parse_json(data: bytes, phase: str) -> dict:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise DriverFailure(phase, "command returned invalid JSON") from error
    if not isinstance(value, dict):
        raise DriverFailure(phase, "command returned unexpected JSON shape")
    return value


def run_tty(
    argv: list[str],
    *,
    phase: str,
    env: dict[str, str],
    approval_fingerprints: list[str],
    passphrase_paths: list[pathlib.Path],
    timeout: int = 180,
) -> tuple[int, bytes, dict[str, int]]:
    """Run one real terminal ceremony and answer only exact known prompts."""
    if os.name != "posix" or not hasattr(termios, "TIOCSCTTY"):
        raise DriverFailure(phase, "real POSIX PTY required")
    master, slave = pty.openpty()
    # Keep normal terminal echo for the public approval line. OpenSSL must
    # disable echo itself while it reads each passphrase; the transcript check
    # below fails if the synthetic test password is ever displayed.
    pid = os.fork()
    if pid == 0:
        try:
            os.close(master)
            os.setsid()
            import fcntl

            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for target_fd in (0, 1, 2):
                os.dup2(slave, target_fd)
            if slave > 2:
                os.close(slave)
            os.execve(argv[0], argv, env)
        except BaseException:
            try:
                os.write(2, b"test child could not start\n")
            except OSError:
                pass
            os._exit(127)
    os.close(slave)
    os.set_blocking(master, False)
    output = bytearray()
    handled: set[tuple[str, int, int]] = set()
    approvals_seen = 0
    passphrases_seen = 0
    stats = {"approval_prompts": 0, "openssl_passphrase_prompts": 0}
    approval_re = re.compile(rb"Type\s+`approve ([0-9a-f]{64})`", re.IGNORECASE)
    passphrase_re = re.compile(rb"Enter pass phrase for ([^\r\n:]+):")
    started = time.monotonic()
    child_status: int | None = None
    failure: str | None = None

    def handle_prompts() -> None:
        nonlocal approvals_seen, passphrases_seen, failure
        matches: list[tuple[int, str, re.Match[bytes]]] = []
        for match in approval_re.finditer(output):
            key = ("approval", match.start(), match.end())
            if key not in handled:
                matches.append((match.start(), "approval", match))
        for match in passphrase_re.finditer(output):
            key = ("passphrase", match.start(), match.end())
            if key not in handled:
                matches.append((match.start(), "passphrase", match))
        for _, kind, match in sorted(matches, key=lambda entry: entry[0]):
            key = (kind, match.start(), match.end())
            if key in handled:
                continue
            handled.add(key)
            if kind == "approval":
                if approvals_seen >= len(approval_fingerprints):
                    failure = "unexpected TTY approval prompt"
                    return
                actual = match.group(1).decode("ascii").lower()
                expected = approval_fingerprints[approvals_seen].lower()
                if actual != expected:
                    failure = "TTY approval fingerprint differed from independently computed value"
                    return
                approvals_seen += 1
                stats["approval_prompts"] += 1
                os.write(master, f"approve {expected}\n".encode("ascii"))
            else:
                if passphrases_seen >= len(passphrase_paths):
                    failure = "unexpected OpenSSL private-key prompt"
                    return
                shown = match.group(1).decode("utf-8", "replace").strip().strip("'\"")
                expected_path = passphrase_paths[passphrases_seen]
                if shown not in (str(expected_path), expected_path.name):
                    failure = "OpenSSL requested an unexpected private-key path"
                    return
                passphrases_seen += 1
                stats["openssl_passphrase_prompts"] += 1
                os.write(master, SYNTHETIC_PASSWORD + b"\n")

    try:
        while True:
            if time.monotonic() - started > timeout:
                failure = "TTY command exceeded its bounded deadline"
                break
            try:
                ready, _, _ = select.select([master], [], [], 0.1)
            except InterruptedError:
                continue
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    if len(output) > MAX_PTY_OUTPUT:
                        failure = "TTY output exceeded its bounded limit"
                        break
                    if SYNTHETIC_PASSWORD in output:
                        failure = "synthetic passphrase unexpectedly appeared in terminal output"
                        break
                    handle_prompts()
                    if failure:
                        break
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                child_status = os.waitstatus_to_exitcode(status)
                # Drain bytes still queued after process exit.
                while True:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_PTY_OUTPUT:
                        failure = "TTY output exceeded its bounded limit"
                        break
                break
    finally:
        if failure and child_status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if child_status is None:
            try:
                _, status = os.waitpid(pid, 0)
                child_status = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                pass
        os.close(master)
    if failure:
        raise DriverFailure(phase, failure)
    if approvals_seen != len(approval_fingerprints):
        raise DriverFailure(phase, "expected exact TTY approval prompt was not observed")
    if passphrases_seen != len(passphrase_paths):
        raise DriverFailure(phase, "expected OpenSSL passphrase prompts were not observed")
    if child_status is None:
        raise DriverFailure(phase, "TTY child exit could not be collected")
    if SYNTHETIC_PASSWORD in output:
        raise DriverFailure(phase, "synthetic passphrase unexpectedly appeared in terminal output")
    return child_status, bytes(output), stats


def terminal_json(output: bytes, phase: str) -> dict:
    # CLI JSON is emitted as the final line; review text remains only in memory.
    for line in reversed(output.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise DriverFailure(phase, "TTY command returned no final JSON result")


class ProxyState:
    def __init__(self, state_path: pathlib.Path | None = None) -> None:
        self.lock = threading.Lock()
        self.state_path = state_path
        self.accepts: list[dict[str, object]] = []

    def record(self, request_body: bytes, status: int, response_body: bytes, drop: bool) -> None:
        with self.lock:
            self.accepts.append({
                "request_sha256": sha256_bytes(request_body),
                "status": status,
                "response_sha256": sha256_bytes(response_body),
                "dropped": drop,
            })

            snapshot = {"status": "ready", "accepts": list(self.accepts)}
        if self.state_path is not None:
            temp_path = self.state_path.with_name(self.state_path.name + ".tmp")
            data = (json.dumps(snapshot, sort_keys=True) + "\n").encode()
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, self.state_path)


def run_proxy_child(listen_port: int, upstream_port: int, state_path: pathlib.Path) -> None:
    state = ProxyState(state_path)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self.forward()

        def do_POST(self) -> None:
            self.forward()

        def forward(self) -> None:
            if self.path.startswith("//") or "\r" in self.path or "\n" in self.path:
                self.send_error(400)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > MAX_PROXY_BODY:
                self.send_error(413)
                return
            try:
                body = self.rfile.read(length) if length else b""
                if len(body) != length:
                    self.send_error(400)
                    return
                upstream = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=30)
                headers = {"Connection": "close"}
                content_type = self.headers.get("Content-Type")
                if content_type:
                    headers["Content-Type"] = content_type
                if length:
                    headers["Content-Length"] = str(length)
                upstream.request(self.command, self.path, body=body, headers=headers)
                response = upstream.getresponse()
                response_body = response.read(MAX_PROXY_BODY + 1)
                status = response.status
                response_type = response.getheader("Content-Type")
                upstream.close()
            except (OSError, http.client.HTTPException):
                self.send_error(502)
                return
            drop = False
            if self.path.split("?", 1)[0] == "/v2/owner/bootstrap/accept" and status == 200:
                with state.lock:
                    first = len(state.accepts) == 0
                drop = first
                state.record(body, status, response_body, drop)
            if drop:
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.connection.close()
                except OSError:
                    pass
                return
            self.send_response(status)
            if response_type:
                self.send_header("Content-Type", response_type)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
            self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", listen_port), Handler)
    server.daemon_threads = True
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"status": "ready", "accepts": []}) + "\n", encoding="utf-8")
    state_path.chmod(0o600)
    server.serve_forever(poll_interval=0.1)


def start_proxy(upstream_port: int, listen_port: int, state_path: pathlib.Path,
                env: dict[str, str]) -> subprocess.Popen:
    command = [sys.executable, "-B", str(pathlib.Path(__file__).resolve()), "--proxy-child",
               str(listen_port), str(upstream_port), str(state_path)]
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    except OSError as error:
        raise DriverFailure("proxy-start", "owned loopback proxy child could not start") from error
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DriverFailure("proxy-start", "owned loopback proxy child exited during startup")
        try:
            status = json.loads(state_path.read_bytes())
        except (OSError, json.JSONDecodeError):
            time.sleep(0.05)
            continue
        if status.get("status") == "ready":
            return process
        time.sleep(0.05)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    raise DriverFailure("proxy-start", "owned loopback proxy child did not become ready")


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(url: str, timeout: float = 2.0) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            raw = response.read(128 * 1024 + 1)
            if response.status != 200 or len(raw) > 128 * 1024:
                raise ValueError("unexpected response")
            value = json.loads(raw)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as error:
        raise DriverFailure("hub-health", "Hub health request failed") from error
    if not isinstance(value, dict):
        raise DriverFailure("hub-health", "Hub health response was invalid")
    return value


class Driver:
    def __init__(self, helper: pathlib.Path, openssl: pathlib.Path, run_root: pathlib.Path,
                 expected_helper_sha256: str = DEFAULT_EXPECTED_HELPER_SHA256,
                 helper_pin_overridden: bool = False):
        self.helper = helper.resolve(strict=True)
        self.openssl = openssl.resolve(strict=True)
        self.run_root = run_root
        self.expected_helper_sha256 = expected_helper_sha256
        self.helper_pin_overridden = (helper_pin_overridden or
                                      expected_helper_sha256 != DEFAULT_EXPECTED_HELPER_SHA256)
        self.run_id = uuid.uuid4().hex[:16]
        self.run_dir: pathlib.Path | None = None
        self.private_dir: pathlib.Path | None = None
        self.container_name = f"cicada-owner-openssl-{self.run_id}"
        self.container_id = ""
        self.container_created = False
        self.proxy_process: subprocess.Popen | None = None
        self.proxy_state_path: pathlib.Path | None = None
        self.proxy_port = 0
        self.hub_port = 0
        self.base_env: dict[str, str] = {}
        self.result: dict[str, object] = {
            "format": "cicada.owner-openssl-bootstrap-test.v1",
            "run_id": self.run_id,
            "status": "RUNNING",
            "stages": {},
            "scope": "synthetic local OpenSSL PTY + disposable software 0.0.5 Hub image + existing Client SDK CLI",
            "android": "NOT_RUN",
            "native_node_runtime": "NOT_RUN",
            "physical_device": "NOT_RUN",
            "public_https": "NOT_RUN",
        }

    def record_stage(self, name: str, **fields: object) -> None:
        stages = self.result["stages"]
        assert isinstance(stages, dict)
        stages[name] = {"status": "PASS", **fields}
        self.write_result()

    def write_result(self) -> None:
        if self.run_dir is not None:
            write_json_replace(self.run_dir / "result.json", self.result)

    def require(self, condition: bool, phase: str, code: str) -> None:
        if not condition:
            raise DriverFailure(phase, code)

    def initialize(self) -> None:
        if os.name != "posix" or os.getuid() != 1000:
            raise DriverFailure("preflight", "Linux/POSIX and runtime UID 1000 are required")
        if re.fullmatch(r"[0-9a-f]{64}", self.expected_helper_sha256) is None:
            raise DriverFailure("preflight", "expected helper SHA-256 pin is malformed")
        if self.helper.is_symlink() or not self.helper.is_file() or not os.access(self.helper, os.X_OK):
            raise DriverFailure("preflight", "helper must be an absolute executable regular file")
        observed_helper_sha256 = sha256_file(self.helper)
        if observed_helper_sha256 != self.expected_helper_sha256:
            raise DriverFailure("preflight", "helper digest differs from the approved test input")
        if self.openssl.is_symlink() or not self.openssl.is_file() or not os.access(self.openssl, os.X_OK):
            raise DriverFailure("preflight", "OpenSSL must be an absolute executable regular file")
        if not self.run_root.is_absolute():
            raise DriverFailure("preflight", "evidence root must be absolute")
        cicada_data = REPOSITORY / ".cicada-data"
        if cicada_data.is_symlink() or not cicada_data.is_dir():
            raise DriverFailure("preflight", "repository scratch root is unavailable or symlinked")
        self.run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.run_root.is_symlink() or not self.run_root.resolve().is_relative_to(cicada_data.resolve()):
            raise DriverFailure("preflight", "evidence root escaped the repository-owned scratch area")
        self.run_dir = self.run_root / ("run-" + self.run_id)
        self.run_dir.mkdir(mode=0o700)
        self.private_dir = self.run_dir / "private"
        self.private_dir.mkdir(mode=0o700)
        self.proxy_state_path = self.private_dir / "proxy-state.json"
        write_json_exclusive(self.private_dir / ".cicada-disposable-test", {"marker": MARKER_TEXT, "run_id": self.run_id})
        (self.private_dir / ".cicada-disposable-test").chmod(0o600)
        home = self.private_dir / "home"
        home.mkdir(mode=0o700)
        self.base_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "TMPDIR": str(self.private_dir),
        }
        try:
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPOSITORY, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5).stdout.decode().strip()
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
            head = "unknown"
        self.result["provenance"] = {
            "repository_head_observed": head,
            "driver_sha256": sha256_file(pathlib.Path(__file__).resolve()),
            "helper_expected_sha256": self.expected_helper_sha256,
            "helper_sha256": observed_helper_sha256,
            "helper_pin_overridden": self.helper_pin_overridden,
            "hub_image_reference": EXPECTED_HUB_IMAGE,
            "openssl_sha256": sha256_file(self.openssl),
        }
        self.write_result()
        self.record_stage("preflight", helper_version=self.helper_version(), uid=os.getuid())

    def helper_version(self) -> str:
        output = run_command([str(self.helper), "version"], phase="preflight", env=self.base_env, timeout=10)
        version = output.decode("utf-8", "replace").strip()
        if "0.0.5" not in version:
            raise DriverFailure("preflight", "helper software version is not 0.0.5")
        return version

    def setup_dirs(self) -> dict[str, pathlib.Path]:
        assert self.private_dir is not None
        dirs = {name: self.private_dir / name for name in ("keys", "hub-state", "workspace", "transfer", "owner", "client")}
        for path in dirs.values():
            path.mkdir(mode=0o700)
        return dirs

    def openssl_env(self) -> dict[str, str]:
        env = self.base_env.copy()
        env["OPENSSL_CONF"] = "/dev/null"
        env.pop("OPENSSL_MODULES", None)
        env["LD_LIBRARY_PATH"] = str(self.openssl.parent.parent / "lib")
        return env

    def generate_keys(self, dirs: dict[str, pathlib.Path]) -> dict[str, pathlib.Path]:
        keys = {
            "kem_private": dirs["keys"] / "synthetic-owner-kem-private.pem",
            "kem_public": dirs["keys"] / "synthetic-owner-kem-public.pem",
            "signing_private": dirs["keys"] / "synthetic-owner-signing-private.pem",
            "signing_public": dirs["keys"] / "synthetic-owner-signing-public.pem",
        }
        env = self.openssl_env()
        for algorithm, private_key, public_key in (
            ("ML-KEM-768", keys["kem_private"], keys["kem_public"]),
            ("ML-DSA-65", keys["signing_private"], keys["signing_public"]),
        ):
            run_command(
                [str(self.openssl), "genpkey", "-algorithm", algorithm, "-aes-256-cbc", "-pass", "stdin",
                 "-out", str(private_key)],
                phase="synthetic-key-generation", env=env,
                input_bytes=SYNTHETIC_PASSWORD + b"\n", timeout=120,
            )
            private_key.chmod(0o600)
            run_command(
                [str(self.openssl), "pkey", "-in", str(private_key), "-passin", "stdin", "-pubout", "-out", str(public_key)],
                phase="synthetic-public-key-export", env=env,
                input_bytes=SYNTHETIC_PASSWORD + b"\n", timeout=60,
            )
            private_data = private_key.read_bytes()
            if b"ENCRYPTED" not in private_data[:4096] or SYNTHETIC_PASSWORD in private_data:
                raise DriverFailure("synthetic-key-generation", "generated test private PEM was not encrypted")
            if private_key.stat().st_mode & 0o777 != 0o600:
                raise DriverFailure("synthetic-key-generation", "generated test private PEM mode was not 0600")
        self.record_stage("synthetic_keys", algorithms=["ML-KEM-768", "ML-DSA-65"], private_mode="0600",
                          generated_only=True, private_key_material_recorded=False)
        return keys

    def verify_openssl(self) -> str:
        env = self.openssl_env()
        output = run_command([str(self.openssl), "version"], phase="preflight", env=env, timeout=10)
        version = output.decode("utf-8", "replace").strip()
        if not version.startswith("OpenSSL 3.5.9"):
            raise DriverFailure("preflight", "OpenSSL version differs from the accepted 3.5.9 build")
        return version

    def verify_hub_image(self) -> tuple[str, dict]:
        output = run_command(["docker", "image", "inspect", EXPECTED_HUB_IMAGE], phase="docker-image", timeout=15)
        try:
            image_list = json.loads(output)
        except json.JSONDecodeError as error:
            raise DriverFailure("docker-image", "image inspection returned invalid JSON") from error
        if not isinstance(image_list, list) or len(image_list) != 1 or not isinstance(image_list[0], dict):
            raise DriverFailure("docker-image", "pinned Hub image is not locally available")
        image = image_list[0]
        image_id = image.get("Id")
        config = image.get("Config") or {}
        if image_id != EXPECTED_HUB_IMAGE or config.get("User") not in ("1000", "1000:1000"):
            raise DriverFailure("docker-image", "Hub image ID or runtime UID differed from the pinned fixture")
        return image_id, image

    def create_setup(self, dirs: dict[str, pathlib.Path], proxy_origin: str) -> dict:
        connection_path = dirs["transfer"] / "hub-owner-connection.json"
        output = run_command([
            str(self.helper), "hub", "setup", "--owner-label", "Synthetic OpenSSL PTY test Owner",
            "--origin", proxy_origin, "--allow-loopback-http", "--public-config", str(connection_path),
            "--state-dir", str(dirs["hub-state"]), "--workspace-root", str(dirs["workspace"]),
        ], phase="hub-setup", env=self.base_env, timeout=60)
        setup_result = parse_json(output, "hub-setup")
        connection = json.loads(connection_path.read_bytes())
        if (connection.get("format") != "cicada.hub-owner-connection.v1" or
                connection.get("purpose") != "ROOT_SIGNER_BOOTSTRAP" or
                connection.get("origin") != proxy_origin or connection.get("allow_loopback_http") is not True):
            raise DriverFailure("hub-setup", "local Hub setup did not pin the exact loopback origin")
        if setup_result.get("state") != "HUB_READY":
            raise DriverFailure("hub-setup", "local Hub setup did not report HUB_READY")
        return connection

    def setup_openssl_profile(self, dirs: dict[str, pathlib.Path], keys: dict[str, pathlib.Path], connection: dict) -> tuple[dict, dict[str, int]]:
        connection_path = dirs["transfer"] / "hub-owner-connection.json"
        public_identity_path = dirs["transfer"] / "synthetic-owner-public-identity.json"
        owner_public_output = run_command([
            str(self.helper), "owner-key", "from-openssl", "--kem-public", str(keys["kem_public"]),
            "--signing-public", str(keys["signing_public"]), "--output", str(public_identity_path),
        ], phase="owner-public-identity", env=self.base_env, timeout=30)
        owner_public_result = parse_json(owner_public_output, "owner-public-identity")
        owner_public = json.loads(public_identity_path.read_bytes())
        profile = dirs["owner"] / "profile"
        args = [str(self.helper), "owner-signer", "prepare-openssl", "--profile", str(profile),
                "--connection-file", str(connection_path), "--openssl", str(self.openssl),
                "--kem-private", str(keys["kem_private"]), "--signing-private", str(keys["signing_private"]),
                "--kem-public", str(keys["kem_public"]), "--signing-public", str(keys["signing_public"])]
        status, terminal, stats = run_tty(args, phase="owner-prepare-openssl", env=self.openssl_env(),
                                          approval_fingerprints=[owner_public_result["public_identity_fingerprint"]],
                                          passphrase_paths=[])
        if status != 0:
            raise DriverFailure("owner-prepare-openssl", f"command exited {status}")
        prepared = terminal_json(terminal, "owner-prepare-openssl")
        manifest_path = pathlib.Path(prepared.get("public_manifest_file", ""))
        if not manifest_path.is_file() or prepared.get("state") != "NEEDS_BOOTSTRAP":
            raise DriverFailure("owner-prepare-openssl", "Owner public candidate manifest was not exported")
        manifest = json.loads(manifest_path.read_bytes())
        if (manifest.get("owner_public_identity") != owner_public or
                manifest.get("fingerprint") != owner_public_result.get("public_identity_fingerprint") or
                manifest.get("account_id") != connection.get("account_id") or
                manifest.get("owner_id") != connection.get("owner_id")):
            raise DriverFailure("owner-prepare-openssl", "exported Owner candidate changed the independently pinned public tuple")
        profile_meta = profile / "owner-signer-openssl.json"
        stored = profile_meta.read_bytes()
        if (keys["kem_private"].read_bytes() in stored or keys["signing_private"].read_bytes() in stored or
                SYNTHETIC_PASSWORD in stored):
            raise DriverFailure("owner-prepare-openssl", "external Owner profile serialized private key bytes or passphrase")
        if profile.stat().st_mode & 0o777 != 0o700 or profile_meta.stat().st_mode & 0o777 != 0o600:
            raise DriverFailure("owner-prepare-openssl", "external Owner profile permissions differed from 0700/0600")
        self.record_stage("owner_profile", state=prepared["state"], owner_key_id=manifest["owner_public_identity"]["id"],
                          owner_fingerprint=manifest["fingerprint"], approval_prompts=stats["approval_prompts"],
                          private_material_in_profile=False, profile_mode="0700", metadata_mode="0600")
        return manifest, stats

    def issue_pair(self, dirs: dict[str, pathlib.Path], manifest: dict, connection: dict) -> dict[str, int]:
        pair_path = dirs["transfer"] / "synthetic-owner-bootstrap-pair.json"
        fingerprint = manifest["fingerprint"]
        args = [str(self.helper), "hub", "owner-bootstrap-issue", "--candidate-manifest",
                str(dirs["owner"] / "profile" / "owner-public.json"), "--candidate-fingerprint", fingerprint,
                "--pair-file", str(pair_path), "--state-dir", str(dirs["hub-state"]),
                "--workspace-root", str(dirs["workspace"])]
        status, terminal, stats = run_tty(args, phase="hub-owner-bootstrap-issue", env=self.base_env,
                                          approval_fingerprints=[fingerprint], passphrase_paths=[])
        if status != 0:
            raise DriverFailure("hub-owner-bootstrap-issue", f"command exited {status}")
        issued = terminal_json(terminal, "hub-owner-bootstrap-issue")
        pair = json.loads(pair_path.read_bytes())
        if (issued.get("state") != "PAIRING_ISSUED" or issued.get("candidate_fingerprint") != fingerprint or
                pair.get("manifest", {}).get("candidate_fingerprint") != fingerprint or
                pair.get("origin") != connection.get("origin")):
            raise DriverFailure("hub-owner-bootstrap-issue", "finite pairing did not bind the exact public candidate")
        if pair_path.stat().st_mode & 0o777 != 0o600:
            raise DriverFailure("hub-owner-bootstrap-issue", "pairing file mode differed from 0600")
        self.record_stage("local_pair_issuance", status=issued["state"], approval_prompts=stats["approval_prompts"],
                          candidate_fingerprint=fingerprint, pair_mode="0600", public_issuer_http="NOT_USED")
        return stats

    def create_hub_container(self, dirs: dict[str, pathlib.Path], image_id: str, api_token: str) -> None:
        assert self.private_dir is not None
        cidfile = self.private_dir / "hub.cid"
        command = [
            "docker", "create", "--pull=never", "--cidfile", str(cidfile),
            "--label", f"org.cicada.test.run={self.run_id}",
            "--label", "org.cicada.test.role=hub",
            "--label", "org.cicada.test.suite=owner-openssl-bootstrap",
            "--name", self.container_name,
            "--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
            "--user", "1000:1000", "--publish", f"127.0.0.1:{self.hub_port}:8787",
            "--mount", f"type=bind,source={dirs['hub-state']},target=/state",
            "--mount", f"type=bind,source={dirs['workspace']},target=/workspace",
            "--env", f"CICADA_API_TOKEN={api_token}",
            image_id, "serve", "--host", "0.0.0.0", "--port", "8787",
        ]
        output = run_command(command, phase="docker-create", timeout=30)
        self.container_id = output.decode("ascii", "replace").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", self.container_id):
            raise DriverFailure("docker-create", "Docker did not return one exact owned container ID")
        self.container_created = True
        try:
            cid = cidfile.read_text().strip()
        except OSError as error:
            raise DriverFailure("docker-create", "owned container cidfile was not created") from error
        if cid != self.container_id:
            raise DriverFailure("docker-create", "cidfile did not match the created container ID")
        run_command(["docker", "start", self.container_id], phase="docker-start", timeout=30)
        inspect = self.inspect_owned_container()
        binds = [mount for mount in inspect.get("Mounts", []) if mount.get("Type") == "bind"]
        expected = {
            (str(dirs["hub-state"].resolve()), "/state"),
            (str(dirs["workspace"].resolve()), "/workspace"),
        }
        actual = {(str(pathlib.Path(mount.get("Source", "")).resolve()), mount.get("Destination")) for mount in binds}
        if actual != expected:
            raise DriverFailure("docker-start", "Hub container bind mounts were not exactly StateDir and Workspace")
        if any(pathlib.Path(source).is_relative_to(self.private_dir / "owner") or
               pathlib.Path(source).is_relative_to(self.private_dir / "keys") for source, _ in actual):
            raise DriverFailure("docker-start", "Owner signer profile or private keys were mounted into Hub")
        self.result["docker_fixture"] = {
            "container_name": self.container_name,
            "container_id": self.container_id,
            "run_label": self.run_id,
            "role_label": "hub",
            "suite_label": "owner-openssl-bootstrap",
            "image_id": inspect.get("Image"),
            "host_bind_ip": "127.0.0.1",
            "host_port": self.hub_port,
            "bind_mount_destinations": sorted(destination for _, destination in actual),
            "owner_profile_or_key_mounts": False,
        }
        self.write_result()
        self.wait_hub()
        self.record_stage("disposable_hub_start", image_id=inspect.get("Image"), host_bind_ip="127.0.0.1",
                          owner_profile_or_key_mounts=False, bind_mount_destinations=["/state", "/workspace"])

    def inspect_owned_container(self) -> dict:
        output = run_command(["docker", "inspect", self.container_id], phase="docker-inspect", timeout=20)
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise DriverFailure("docker-inspect", "owned container inspect was invalid JSON") from error
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise DriverFailure("docker-inspect", "owned container inspection did not identify one container")
        item = value[0]
        labels = item.get("Config", {}).get("Labels", {}) or {}
        if (item.get("Id") != self.container_id or item.get("Name") != "/" + self.container_name or
                labels.get("org.cicada.test.run") != self.run_id or
                labels.get("org.cicada.test.role") != "hub" or
                labels.get("org.cicada.test.suite") != "owner-openssl-bootstrap"):
            raise DriverFailure("docker-inspect", "container name, ID, or ownership labels changed")
        return item

    def wait_hub(self) -> None:
        deadline = time.monotonic() + 60
        url = f"http://127.0.0.1:{self.hub_port}/healthz"
        last_error: DriverFailure | None = None
        while time.monotonic() < deadline:
            try:
                health = http_json(url, timeout=2)
                if health.get("status") == "ok":
                    return
            except DriverFailure as error:
                last_error = error
            time.sleep(0.25)
        # Keep diagnostics bounded and do not persist container logs.
        raise DriverFailure("hub-health", "owned Hub did not become ready within 60 seconds") from last_error

    def stop_start_hub(self) -> None:
        self.inspect_owned_container()
        run_command(["docker", "stop", "--time", "10", self.container_id], phase="hub-restart", timeout=20)
        run_command(["docker", "start", self.container_id], phase="hub-restart", timeout=30)
        self.wait_hub()
        self.record_stage("same_hub_restart", container_id=self.container_id, same_state_dir=True)

    def check_saved_pending(self, profile: pathlib.Path) -> str:
        state_path = profile / "owner-signer-openssl.json"
        try:
            state = json.loads(state_path.read_bytes())
            pending = state["bootstrap"]
            pair_file = base64.b64decode(pending["pair_file"], validate=True)
            proof = base64.b64decode(pending["proof"], validate=True)
            response = base64.b64decode(pending.get("response", ""), validate=True)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise DriverFailure("lost-response", "saved Owner proof state is unavailable") from error
        if not pair_file or not proof or response:
            raise DriverFailure("lost-response", "expected exact saved proof without cached response")
        return sha256_bytes(proof)

    def owner_bootstrap(self, dirs: dict[str, pathlib.Path], manifest: dict, proxy_origin: str) -> dict[str, object]:
        profile = dirs["owner"] / "profile"
        pair_path = dirs["transfer"] / "synthetic-owner-bootstrap-pair.json"
        fingerprint = manifest["fingerprint"]
        first_status, _first_terminal, first_stats = run_tty(
            [str(self.helper), "owner-signer", "bootstrap", "--profile", str(profile), "--pair-file", str(pair_path)],
            phase="owner-bootstrap-first-attempt", env=self.openssl_env(), approval_fingerprints=[fingerprint],
            passphrase_paths=[dirs["keys"] / "synthetic-owner-kem-private.pem",
                              dirs["keys"] / "synthetic-owner-signing-private.pem"], timeout=180,
        )
        if first_status == 0:
            raise DriverFailure("lost-response", "first accepted bootstrap response was not lost")
        first_accepts = self.proxy_accepts(wait_for=1)
        if len(first_accepts) != 1 or not first_accepts[0].get("dropped"):
            raise DriverFailure("lost-response", "proxy did not observe and drop a committed Hub response")
        proof_hash_before = self.check_saved_pending(profile)
        self.stop_start_hub()
        recovered_status, recovered_terminal, recover_stats = run_tty(
            [str(self.helper), "owner-signer", "recover", "--profile", str(profile)],
            phase="owner-bootstrap-recover", env=self.openssl_env(), approval_fingerprints=[fingerprint],
            passphrase_paths=[dirs["keys"] / "synthetic-owner-kem-private.pem"], timeout=180,
        )
        if recovered_status != 0:
            raise DriverFailure("owner-bootstrap-recover", f"command exited {recovered_status}")
        receipt = terminal_json(recovered_terminal, "owner-bootstrap-recover")
        if receipt.get("state") != "ACTIVE" or receipt.get("owner_id") != manifest.get("owner_id"):
            raise DriverFailure("owner-bootstrap-recover", "receipt did not confirm the exact active Root")
        proof_hash_after = self.check_saved_pending_with_response(profile)
        accepts = self.proxy_accepts(wait_for=2)
        if len(accepts) != 2:
            raise DriverFailure("lost-response", "expected exactly two Hub accept requests")
        first, second = accepts
        if (first["status"] != 200 or not first["dropped"] or second["status"] != 200 or second["dropped"] or
                first["request_sha256"] != second["request_sha256"] or
                first["response_sha256"] != second["response_sha256"] or
                proof_hash_before != proof_hash_after or proof_hash_before != first["request_sha256"]):
            raise DriverFailure("lost-response", "recovery changed the saved proof or cached receipt bytes")
        self.record_stage("finite_root_bootstrap", owner_state=receipt["state"],
                          first_response_deliberately_dropped=True, same_hub_restarted=True,
                          exact_proof_retried=True, exact_cached_receipt_replayed=True,
                          proof_sha256=proof_hash_before, receipt_sha256=first["response_sha256"],
                          first_attempt_passphrase_prompts=first_stats["openssl_passphrase_prompts"],
                          first_attempt_approval_prompts=first_stats["approval_prompts"],
                          recovery_passphrase_prompts=recover_stats["openssl_passphrase_prompts"],
                          recovery_approval_prompts=recover_stats["approval_prompts"],
                          public_issuer_http="NOT_USED")
        return {"receipt": receipt, "proof_sha256": proof_hash_before}

    def check_saved_pending_with_response(self, profile: pathlib.Path) -> str:
        state_path = profile / "owner-signer-openssl.json"
        try:
            state = json.loads(state_path.read_bytes())
            pending = state["bootstrap"]
            proof = base64.b64decode(pending["proof"], validate=True)
            response = base64.b64decode(pending["response"], validate=True)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise DriverFailure("owner-bootstrap-recover", "authenticated receipt was not persisted") from error
        if not proof or not response:
            raise DriverFailure("owner-bootstrap-recover", "saved proof or authenticated receipt is empty")
        return sha256_bytes(proof)

    def manager_client(self, dirs: dict[str, pathlib.Path], connection: dict, manifest: dict,
                       keys: dict[str, pathlib.Path]) -> dict[str, object]:
        # The Client input files contain only the already reviewed public Hub
        # identity, Owner identity and IDs. The private Owner profile stays out
        # of this independent management Client profile and out of Hub mounts.
        hub_public_path = dirs["transfer"] / "client-hub-identity.json"
        owner_public_path = dirs["transfer"] / "client-owner-public-identity.json"
        write_json_exclusive(hub_public_path, connection["hub"], 0o644)
        owner_public = manifest["owner_public_identity"]
        write_json_exclusive(owner_public_path, owner_public, 0o644)
        client_profile = dirs["client"] / "manager-profile"
        client_profile.mkdir(mode=0o700)
        origin = connection["origin"]
        prepare = run_command([
            str(self.helper), "client", "prepare", "--profile", str(client_profile), "--origin", origin,
            "--hub-identity", str(hub_public_path), "--owner-id", manifest["owner_id"],
            "--owner-public", str(owner_public_path), "--allow-loopback-http",
        ], phase="client-prepare", env=self.base_env, timeout=60)
        prepared = parse_json(prepare, "client-prepare")
        if prepared.get("state") != "NEEDS_OWNER_GRANT":
            raise DriverFailure("client-prepare", "existing Client path did not produce a grant-bound profile")
        client_manifest_path = pathlib.Path(prepared["manifest_file"])
        client_manifest = json.loads(client_manifest_path.read_bytes())
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=20)).replace(microsecond=0)
        expires_at = expiry.isoformat().replace("+00:00", "Z")
        grant_path = dirs["transfer"] / "synthetic-client-owner-grant.json"
        summary_path = dirs["transfer"] / "synthetic-client-owner-grant-summary.json"
        owner_profile = dirs["owner"] / "profile"
        status, terminal, grant_stats = run_tty(
            [str(self.helper), "owner-signer", "grant", "--profile", str(owner_profile), "--manifest-file",
             str(client_manifest_path), "--expires-at", expires_at, "--output", str(grant_path),
             "--summary-output", str(summary_path)],
            phase="owner-device-grant", env=self.openssl_env(),
            approval_fingerprints=[client_manifest["device_key_fingerprint"]],
            passphrase_paths=[keys["kem_private"], keys["signing_private"]], timeout=180,
        )
        if status != 0:
            raise DriverFailure("owner-device-grant", f"command exited {status}")
        terminal_summary = terminal_json(terminal, "owner-device-grant")
        summary = json.loads(summary_path.read_bytes())
        if (summary != terminal_summary or summary.get("format") != "cicada.owner-device-grant-summary.v1" or
                summary.get("state") != "GRANT_WRITTEN" or
                summary.get("owner_public_identity") != owner_public or
                summary.get("device_id") != client_manifest.get("device_id") or
                summary.get("device_key_fingerprint") != client_manifest.get("device_key_fingerprint") or
                summary.get("expires_at") != expires_at or summary.get("purpose") != "CLIENT_CONTROL"):
            raise DriverFailure("owner-device-grant", "public summary did not match the exact signed Client grant")
        grant_bytes = grant_path.read_bytes()
        if not grant_bytes or grant_path.stat().st_mode & 0o777 != 0o600:
            raise DriverFailure("owner-device-grant", "signed grant file was empty or not protected as mode 0600")
        enrolled = run_command([
            str(self.helper), "client", "enroll", "--profile", str(client_profile), "--grant-file", str(grant_path),
        ], phase="client-enroll", env=self.base_env, timeout=90)
        capabilities = parse_json(enrolled, "client-enroll")
        operations = capabilities.get("available_rpc_operations")
        if (capabilities.get("role") != "manager" or not isinstance(operations, list) or
                not {"intent.submit", "approvals.decide"}.issubset(set(operations))):
            raise DriverFailure("client-enroll", "newly bootstrapped Owner did not enroll a manager Client")
        if self.private_material_in_hub_state(dirs, keys):
            raise DriverFailure("custody", "Hub state contains synthetic private key bytes or test passphrase")
        mounts = self.inspect_owned_container().get("Mounts", [])
        if len([mount for mount in mounts if mount.get("Type") == "bind"]) != 2:
            raise DriverFailure("custody", "Hub bind mount set changed during enrollment")
        self.record_stage("existing_client_grant_and_enrollment", summary_format=summary["format"],
                          grant_mode="0600", summary_mode=oct(summary_path.stat().st_mode & 0o777),
                          manager_role=capabilities["role"],
                          manager_operations=sorted(set(operations).intersection({"intent.submit", "approvals.decide"})),
                          grant_passphrase_prompts=grant_stats["openssl_passphrase_prompts"],
                          grant_approval_prompts=grant_stats["approval_prompts"],
                          private_key_bytes_in_hub_state=False, test_passphrase_in_hub_state=False,
                          private_owner_mounts_into_hub=False)
        return {"role": capabilities["role"], "operations": operations, "summary_format": summary["format"]}

    def private_material_in_hub_state(self, dirs: dict[str, pathlib.Path], keys: dict[str, pathlib.Path]) -> bool:
        needles = [keys["kem_private"].read_bytes(), keys["signing_private"].read_bytes(), SYNTHETIC_PASSWORD]
        for path in dirs["hub-state"].rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if path.stat().st_size > 64 * 1024 * 1024:
                raise DriverFailure("custody", "bounded Hub state scan limit exceeded")
            try:
                data = path.read_bytes()
            except OSError as error:
                raise DriverFailure("custody", "Hub state file could not be checked") from error
            if any(needle in data for needle in needles):
                return True
        return False

    def run(self) -> None:
        self.initialize()
        assert self.private_dir is not None
        dirs = self.setup_dirs()
        openssl_version = self.verify_openssl()
        image_id, _image = self.verify_hub_image()
        self.record_stage("pinned_inputs", openssl_version=openssl_version, hub_image_id=image_id,
                          hub_image_rebuilt_by_driver=False)
        api_token = "synthetic-test-only-" + uuid.uuid4().hex + uuid.uuid4().hex
        self.hub_port = free_loopback_port()
        self.proxy_port = free_loopback_port()
        proxy_origin = f"http://127.0.0.1:{self.proxy_port}"
        connection = self.create_setup(dirs, proxy_origin)
        self.record_stage("fresh_local_setup", state="HUB_READY", origin=proxy_origin,
                          stable_account_id=connection["account_id"], owner_id=connection["owner_id"])
        keys = self.generate_keys(dirs)
        manifest, _ = self.setup_openssl_profile(dirs, keys, connection)
        self.issue_pair(dirs, manifest, connection)
        self.create_hub_container(dirs, image_id, api_token)
        assert self.proxy_state_path is not None
        self.proxy_process = start_proxy(self.hub_port, self.proxy_port, self.proxy_state_path, self.base_env)
        self.record_stage("local_loss_proxy", host_bind_ip="127.0.0.1", no_raw_packets_persisted=True)
        if self.private_material_in_hub_state(dirs, keys):
            raise DriverFailure("custody", "Hub state contains synthetic private key bytes or test passphrase")
        self.record_stage("hub_state_custody", private_key_bytes_in_state=False, test_passphrase_in_state=False,
                          owner_profile_not_mounted=True)
        self.owner_bootstrap(dirs, manifest, proxy_origin)
        self.manager_client(dirs, connection, manifest, keys)

    def cleanup(self) -> dict[str, object]:
        outcome: dict[str, object] = {"container_cleanup": "NOT_CREATED", "proxy_stopped": True,
                                      "private_scratch_removed": False, "images_removed": False}
        if self.proxy_process is not None:
            try:
                if self.proxy_process.poll() is None:
                    self.proxy_process.terminate()
                self.proxy_process.wait(timeout=5)
                outcome["proxy_stopped"] = self.proxy_process.poll() is not None
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
                try:
                    self.proxy_process.wait(timeout=5)
                    outcome["proxy_stopped"] = True
                except subprocess.TimeoutExpired:
                    outcome["proxy_stopped"] = False
        container_gone = not self.container_created
        if self.container_created and self.container_id:
            try:
                self.inspect_owned_container()
                inspected = self.inspect_owned_container()
                running = bool(inspected.get("State", {}).get("Running"))
                if running:
                    run_command(["docker", "stop", "--time", "10", self.container_id],
                                phase="cleanup", timeout=20)
                run_command(["docker", "rm", "--force", self.container_id], phase="cleanup", timeout=30)
                check = subprocess.run(["docker", "inspect", self.container_id], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=10, check=False)
                container_gone = check.returncode != 0
                outcome["container_cleanup"] = "REMOVED" if container_gone else "STILL_PRESENT"
            except Exception:
                outcome["container_cleanup"] = "FAILED_OWNED_CONTAINER_RETAINED"
        if self.private_dir is not None and self.run_dir is not None:
            marker = self.private_dir / ".cicada-disposable-test"
            try:
                marker_value = json.loads(marker.read_bytes())
                owned = (marker_value.get("marker") == MARKER_TEXT and marker_value.get("run_id") == self.run_id and
                         self.private_dir.parent == self.run_dir and self.private_dir.name == "private")
            except (OSError, json.JSONDecodeError, AttributeError):
                owned = False
            if owned and container_gone and outcome["proxy_stopped"]:
                shutil.rmtree(self.private_dir)
                outcome["private_scratch_removed"] = not self.private_dir.exists()
            elif self.private_dir.exists():
                outcome["private_scratch_removed"] = False
                outcome["retained_private_scratch"] = "cleanup condition was not confirmed; contains synthetic-only test material"
        if self.run_dir is not None:
            self.result["cleanup"] = outcome
            if self.result.get("status") == "RUNNING":
                self.result["status"] = "PASS"
            if outcome.get("container_cleanup") not in ("REMOVED", "NOT_CREATED") or not outcome.get("proxy_stopped"):
                self.result["status"] = "FAIL"
                self.result.setdefault("failure", {"phase": "cleanup", "code": "owned disposable resources were not fully confirmed removed"})
            self.result["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            self.write_result()
            try:
                write_json_exclusive(self.run_dir / "cleanup.json", outcome)
            except FileExistsError:
                pass
        return outcome

    def proxy_accepts(self, wait_for: int = 0) -> list[dict[str, object]]:
        if self.proxy_state_path is None:
            raise DriverFailure("proxy-state", "proxy state path is unavailable")
        deadline = time.monotonic() + 10
        while True:
            try:
                state = json.loads(self.proxy_state_path.read_bytes())
            except (OSError, json.JSONDecodeError):
                state = {}
            accepts = state.get("accepts", []) if isinstance(state, dict) else []
            if isinstance(accepts, list) and len(accepts) >= wait_for:
                return accepts
            if time.monotonic() >= deadline:
                return accepts if isinstance(accepts, list) else []
            time.sleep(0.05)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=pathlib.Path, default=DEFAULT_HELPER)
    parser.add_argument("--expected-helper-sha256", type=parse_sha256_pin, default=None,
                        help="independently approved helper SHA-256 pin (default: original frozen helper)")
    parser.add_argument("--openssl", type=pathlib.Path, default=DEFAULT_OPENSSL)
    parser.add_argument("--run-root", type=pathlib.Path,
                        default=REPOSITORY / ".cicada-data/owner-openssl-bootstrap-runs")
    args = parser.parse_args()
    helper_pin_overridden = args.expected_helper_sha256 is not None
    expected_helper_sha256 = args.expected_helper_sha256 or DEFAULT_EXPECTED_HELPER_SHA256
    driver = Driver(args.helper, args.openssl, args.run_root, expected_helper_sha256,
                    helper_pin_overridden=helper_pin_overridden)
    error: DriverFailure | None = None
    try:
        driver.run()
    except DriverFailure as caught:
        error = caught
        driver.result["status"] = "FAIL"
        driver.result["failure"] = {"phase": caught.phase, "code": caught.code}
    except BaseException as caught:
        error = DriverFailure("driver", "unexpected bounded-test failure")
        driver.result["status"] = "FAIL"
        driver.result["failure"] = {"phase": "driver", "code": "unexpected bounded-test failure",
                                     "exception_type": type(caught).__name__}
    finally:
        outcome = driver.cleanup()
    if driver.run_dir is not None:
        result_sha = sha256_file(driver.run_dir / "result.json")
        cleanup_sha = sha256_file(driver.run_dir / "cleanup.json") if (driver.run_dir / "cleanup.json").exists() else ""
        print(json.dumps({"status": driver.result.get("status"), "run_id": driver.run_id,
                          "result": str(driver.run_dir / "result.json"), "result_sha256": result_sha,
                          "cleanup": str(driver.run_dir / "cleanup.json"), "cleanup_sha256": cleanup_sha,
                          "cleanup_outcome": outcome}, sort_keys=True))
    else:
        print(json.dumps({"status": "FAIL", "phase": error.phase if error else "preflight",
                          "code": error.code if error else "run directory not created"}, sort_keys=True))
    if error:
        print(f"owner OpenSSL bootstrap test failed at {error.phase}: {error.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--proxy-child":
        try:
            run_proxy_child(int(sys.argv[2]), int(sys.argv[3]), pathlib.Path(sys.argv[4]))
        except BaseException:
            sys.exit(2)
    sys.exit(main())
