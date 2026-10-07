"""NONAUTH test-only, default-off Runtime-local HTTP/1.1 request observer.

Import and the default CLI do no I/O. No deployment launcher is provided. The
embedding disposable Runtime must explicitly supply enabled=True, trusted core
association, fixed HTTPS endpoint, and a closed-record sink. One request per
connection; no retry, redirects, disk capture, response accumulation, or logging.
"""
import hashlib
import json
import re
import socket
import ssl
import time
import threading
import uuid
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

SCHEMA = "cicada.test-request-observer.v1"
HASH_DOMAIN = "sha256:parsed-input-json-utf8-sortkeys-compact-v1"
BODY_HASH_DOMAIN = "sha256:prepared-http-entity-body-bytes-v1"
TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
MAX_HEADER = 16384
MAX_BODY = 4 * 1024 * 1024
MAX_WIRE = MAX_BODY + 65536
MAX_CHUNKS = 512
MAX_CONNECTIONS = 16
MAX_SECONDS = 240
STATUSES = frozenset(("FORWARDED", "UNKNOWN_UNSUPPORTED", "UNKNOWN_BOUNDS",
                      "UNKNOWN_FRAMING", "UNKNOWN_JSON", "UNKNOWN_ASSOCIATION",
                      "UNKNOWN_IO", "UNKNOWN_BUDGET", "UNKNOWN_DISABLED"))
RECORD_KEYS = frozenset(("schema", "status", "alpha_present", "input_sha256", "input_bytes", "hash_domain",
                        "request_body_sha256", "request_body_bytes", "body_hash_domain", "association_provenance",
                        "runtime_thread_bound", "thread", "turn", "attempt", "outbound_POST_count"))


class ClosedFailure(Exception):
    """Only a closed code; never retain an offending value or exception text."""

    def __init__(self, code):
        self.code = code if code in STATUSES else "UNKNOWN_IO"
        super().__init__(self.code)


def fixed_url(value):
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 2048 or not value.isascii():
            raise ValueError()
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if not host or (port is not None and not 1 <= port <= 65535):
            raise ValueError()
        if ":" in host:
            ipaddress.IPv6Address(host)
        elif not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            raise ValueError()
        return parsed
    except (ValueError, TypeError, UnicodeError):
        raise ClosedFailure("UNKNOWN_UNSUPPORTED") from None


def validate_record(record):
    """Validate inside Runtime BEFORE exporting any file bytes to a host sink."""
    try:
        if (type(record) is not dict or set(record) != RECORD_KEYS or record["schema"] != SCHEMA or
                record["status"] not in STATUSES or record["hash_domain"] != HASH_DOMAIN or
                record["body_hash_domain"] != BODY_HASH_DOMAIN or
                record["association_provenance"] not in ("CORE_METADATA", "EXPLICIT_CORE_ASSIGNMENT") or
                type(record["runtime_thread_bound"]) is not bool or
                (record["alpha_present"] is not None and type(record["alpha_present"]) is not bool) or
                type(record["outbound_POST_count"]) is not int or not 0 <= record["outbound_POST_count"] <= MAX_CONNECTIONS):
            raise ValueError()
        for key in ("input_sha256", "request_body_sha256"):
            if record[key] is not None and (type(record[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record[key])):
                raise ValueError()
        for key in ("input_bytes", "request_body_bytes"):
            if record[key] is not None and (type(record[key]) is not int or not 0 <= record[key] <= MAX_BODY):
                raise ValueError()
        if any(record[key] is not None for key in ("thread", "turn", "attempt")):
            Association(record["thread"], record["turn"], record["attempt"])
        return dict(record)
    except Exception:
        raise ClosedFailure("UNKNOWN_FRAMING") from None


def summarize_records(records, expected_thread, actual_turns, a3_turn, drain):
    """Retain truthful diagnostic rows regardless of ALPHA/native acceptance."""
    rows = [validate_record(record) for record in records]
    actual = set(actual_turns)
    counted = [row["outbound_POST_count"] for row in rows]
    count_complete = (bool(rows) and counted == list(range(1, len(rows)+1)) and
                      type(drain) is dict and drain.get("outbound_POST_count") == counted[-1])
    joins_complete = (bool(actual) and {(row["thread"], row["turn"]) for row in rows} == actual and
                      all(row["thread"] == expected_thread and row["runtime_thread_bound"] for row in rows))
    drained = (type(drain) is dict and drain.get("schema") == "cicada.test-request-observer-drain.v1" and
               drain.get("drained") is True and drain.get("closed") is True and drain.get("forced") is False)
    a3 = [row for row in rows if row["thread"] == expected_thread and row["turn"] == a3_turn]
    alpha = (True if any(row["alpha_present"] is True for row in a3) else
             False if a3 and all(row["alpha_present"] is False for row in a3) else None)
    complete = (count_complete and joins_complete and drained and
                all(row["status"] == "FORWARDED" for row in rows))
    return {"schema":"cicada.test-request-observer-diagnostic.v1", "records":rows,
            "capture_status":"COMPLETE" if complete else "UNKNOWN",
            "POST_count_complete":count_complete, "turn_joins_complete":joins_complete,
            "drain_complete":drained, "a3_ALPHA_present":alpha,
            "native_acceptance":"UNCHANGED"}


@dataclass(frozen=True)
class Association:
    """Trusted core assignment, never derived from request headers/body."""
    thread: str
    turn: str
    attempt: int

    def __post_init__(self):
        try:
            valid = (str(uuid.UUID(self.thread)) == self.thread and
                     str(uuid.UUID(self.turn)) == self.turn and
                     type(self.attempt) is int and 1 <= self.attempt <= MAX_CONNECTIONS)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ClosedFailure("UNKNOWN_ASSOCIATION")


class Reader:
    def __init__(self, sock, deadline):
        self.sock, self.deadline, self.buf = sock, deadline, bytearray()

    def recv(self, size=65536):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ClosedFailure("UNKNOWN_BUDGET")
        self.sock.settimeout(remaining)
        return self.sock.recv(size)

    def until(self, delimiter, limit):
        while True:
            at = self.buf.find(delimiter)
            if at >= 0:
                end = at + len(delimiter)
                if end > limit:
                    raise ClosedFailure("UNKNOWN_BOUNDS")
                data = bytes(self.buf[:end])
                del self.buf[:end]
                return data
            if len(self.buf) >= limit:
                raise ClosedFailure("UNKNOWN_BOUNDS")
            data = self.recv(min(4096, limit - len(self.buf)))
            if not data:
                raise ClosedFailure("UNKNOWN_FRAMING")
            self.buf.extend(data)

    def exact(self, length):
        while len(self.buf) < length:
            data = self.recv(min(65536, length - len(self.buf)))
            if not data:
                raise ClosedFailure("UNKNOWN_FRAMING")
            self.buf.extend(data)
        data = bytes(self.buf[:length])
        del self.buf[:length]
        return data


def headers(raw, strict=True):
    lines = raw[:-4].split(b"\r\n")
    fields = []
    if len(lines) > 65:
        raise ClosedFailure("UNKNOWN_BOUNDS")
    for line in lines[1:]:
        if b":" not in line:
            raise ClosedFailure("UNKNOWN_FRAMING")
        name, value = line.split(b":", 1)
        if not TOKEN.fullmatch(name) or any(x < 32 or x == 127 for x in value):
            raise ClosedFailure("UNKNOWN_FRAMING")
        fields.append((name, value.strip(b" ")))
    table = {}
    for name, value in fields:
        key = name.lower()
        if key in table and (strict or key in (b"content-length", b"transfer-encoding", b"connection",
                                               b"content-encoding", b"upgrade", b"trailer", b"host")):
            # Conservative rejection avoids ambiguous framing/security headers.
            raise ClosedFailure("UNKNOWN_FRAMING")
        table[key] = value
    return lines[0], fields, table


def framing(table, request=False):
    if b"content-length" in table and b"transfer-encoding" in table:
        raise ClosedFailure("UNKNOWN_FRAMING")
    if b"transfer-encoding" in table:
        if table[b"transfer-encoding"].lower() != b"chunked":
            raise ClosedFailure("UNKNOWN_UNSUPPORTED")
        return "chunked", None
    if b"content-length" in table:
        value = table[b"content-length"]
        if not value or len(value) > 10 or not value.isdigit():
            raise ClosedFailure("UNKNOWN_FRAMING")
        count = int(value)
        if request and count > MAX_BODY:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        return "length", count
    if request:
        raise ClosedFailure("UNKNOWN_FRAMING")
    return "eof", None


def unsupported(table, request=False):
    if ((request and table.get(b"content-encoding", b"identity").lower() != b"identity") or
            b"upgrade" in table or b"trailer" in table or
            b"upgrade" in table.get(b"connection", b"").lower()):
        raise ClosedFailure("UNKNOWN_UNSUPPORTED")
    if request and b"expect" in table:
        raise ClosedFailure("UNKNOWN_UNSUPPORTED")


def request_body(reader, mode, count):
    if mode == "length":
        body = reader.exact(count)
        return body, body
    wire, body = bytearray(), bytearray()
    for _ in range(MAX_CHUNKS):
        line = reader.until(b"\r\n", 32)
        size = line[:-2]
        if not size or len(size) > 8 or not re.fullmatch(rb"[0-9a-fA-F]+", size):
            raise ClosedFailure("UNKNOWN_UNSUPPORTED")
        length = int(size, 16)
        if len(body) + length > MAX_BODY or len(wire) + length + len(line) + 2 > MAX_WIRE:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        wire.extend(line)
        data = reader.exact(length + 2)
        if data[-2:] != b"\r\n":
            raise ClosedFailure("UNKNOWN_FRAMING")
        wire.extend(data)
        if length == 0:
            return bytes(wire), bytes(body)
        body.extend(data[:-2])
    raise ClosedFailure("UNKNOWN_BOUNDS")


class ResponseFraming:
    """Incremental validation; keeps at most one short chunk-size/CRLF line."""
    def __init__(self, mode, count):
        self.mode, self.remaining = mode, count
        self.state, self.line = "line", bytearray()

    def feed(self, data):
        if self.mode == "eof":
            return
        if self.mode == "length":
            self.remaining -= len(data)
            if self.remaining < 0:
                raise ClosedFailure("UNKNOWN_FRAMING")
            return
        at = 0
        while at < len(data):
            if self.state == "done":
                raise ClosedFailure("UNKNOWN_FRAMING")
            if self.state == "data":
                take = min(self.remaining, len(data)-at)
                self.remaining -= take
                at += take
                if self.remaining == 0:
                    self.state = "crlf"
                continue
            self.line.append(data[at])
            at += 1
            limit = 32 if self.state == "line" else 2
            if len(self.line) > limit:
                raise ClosedFailure("UNKNOWN_BOUNDS")
            if not self.line.endswith(b"\r\n"):
                continue
            if self.state == "line":
                size = bytes(self.line[:-2])
                if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size):
                    raise ClosedFailure("UNKNOWN_UNSUPPORTED")
                self.remaining = int(size, 16)
                self.state = "data" if self.remaining else "last"
            else:
                if self.line != b"\r\n":
                    raise ClosedFailure("UNKNOWN_FRAMING")
                self.state = "done" if self.state == "last" else "line"
            self.line.clear()

    def finish(self):
        if ((self.mode == "length" and self.remaining != 0) or
                (self.mode == "chunked" and self.state != "done")):
            raise ClosedFailure("UNKNOWN_FRAMING")

    def complete(self):
        return ((self.mode == "length" and self.remaining == 0) or
                (self.mode == "chunked" and self.state == "done"))


def input_witness(body, marker, association=None):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    def invalid(_):
        raise ValueError()
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=invalid)
        if not isinstance(parsed, dict) or "input" not in parsed:
            raise ValueError()
        if association is not None:
            metadata = parsed.get("client_metadata")
            if (not isinstance(metadata, dict) or metadata.get("thread_id") != association.thread or
                    metadata.get("turn_id") != association.turn):
                raise ClosedFailure("UNKNOWN_ASSOCIATION")
        value = parsed["input"]
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if nodes > 65536 or depth > 64:
                raise ClosedFailure("UNKNOWN_BOUNDS")
            if isinstance(item, list):
                pending.extend((x, depth + 1) for x in item)
            elif isinstance(item, dict):
                pending.extend((x, depth + 1) for x in item.values())
        # Decode actual Responses message text only. Tools, metadata, object
        # keys and arbitrary string fields cannot manufacture the ALPHA bit.
        texts = [value] if isinstance(value, str) else []
        if isinstance(value, list):
            for message in value:
                if (not isinstance(message, dict) or
                        message.get("type", "message") != "message" or
                        message.get("role") not in ("user", "assistant", "system", "developer")):
                    continue
                content = message.get("content")
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if (isinstance(block, dict) and block.get("type") in ("input_text", "output_text") and
                                isinstance(block.get("text"), str)):
                            texts.append(block["text"])
        present = any(marker in text for text in texts)
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        return present, hashlib.sha256(encoded).hexdigest(), len(encoded)
    except ClosedFailure:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ClosedFailure("UNKNOWN_JSON") from None


IO_SCHEMA = "cicada.native-request-observer-io.v1"
IO_PHASES = frozenset(("READ_REQUEST", "PARSE_INPUT", "CONNECT", "INJECTED_CONNECTOR", "TLS_SETUP", "TCP_CONNECT",
    "PROXY_CONNECT_SEND", "PROXY_CONNECT_READ", "TLS_HANDSHAKE", "ALPN_VALIDATE", "SEND_REQUEST", "READ_HEAD",
    "WRITE_HEAD", "READ_BODY", "WRITE_BODY", "FRAMING_FINISH", "CLOSE_PLAIN",
    "CLOSE_UPSTREAM", "CLOSE_CLIENT", "ORIGINAL_SINK"))
IO_CLASSES = frozenset(("CLOSED_FAILURE", "TIMEOUT", "BROKEN_PIPE", "CONNECTION_RESET",
    "CONNECTION_ABORTED", "SSL_ERROR", "SSL_VERIFY", "OS_ERROR", "OTHER"))
IO_KEYS = frozenset(("schema", "sequence", "POST_before", "POST_after", "shutdown_requested",
    "first_failure", "cleanup_failures", "cleanup_truncated", "upstream_eof"))


def validate_io_diagnostic(record):
    """Validate BEFORE independently exporting a sibling record; no raw values."""
    if type(record) is not dict or set(record) != IO_KEYS or type(record["schema"]) is not str or record["schema"] != IO_SCHEMA:
        raise ValueError("IO_DIAGNOSTIC_SCHEMA")
    for key in ("sequence", "POST_before", "POST_after"):
        if type(record[key]) is not int or not 0 <= record[key] <= MAX_CONNECTIONS:
            raise ValueError("IO_DIAGNOSTIC_COUNT")
    if record["sequence"] >= MAX_CONNECTIONS or not record["POST_before"] <= record["POST_after"] <= record["POST_before"]+1:
        raise ValueError("IO_DIAGNOSTIC_COUNT")
    if any(type(record[key]) is not bool for key in ("shutdown_requested", "cleanup_truncated", "upstream_eof")):
        raise ValueError("IO_DIAGNOSTIC_TYPE")
    if type(record["cleanup_failures"]) is not list or len(record["cleanup_failures"]) > 3:
        raise ValueError("IO_DIAGNOSTIC_BOUNDS")
    failures = ([] if record["first_failure"] is None else [record["first_failure"]]) + record["cleanup_failures"]
    for index, failure in enumerate(failures):
        if type(failure) is not dict or set(failure) != {"phase", "class", "order", "shutdown_requested"}:
            raise ValueError("IO_DIAGNOSTIC_SCHEMA")
        if type(failure["phase"]) is not str or failure["phase"] not in IO_PHASES or type(failure["class"]) is not str or failure["class"] not in IO_CLASSES:
            raise ValueError("IO_DIAGNOSTIC_ENUM")
        if type(failure["shutdown_requested"]) is not bool:
            raise ValueError("IO_DIAGNOSTIC_TYPE")
        if type(failure["order"]) is not int or failure["order"] != index:
            raise ValueError("IO_DIAGNOSTIC_ORDER")
    if len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()) > 2048:
        raise ValueError("IO_DIAGNOSTIC_BOUNDS")
    return record


def _note_io(record, phase, error, cleanup=False, shutdown_requested=False):
    # Optional evidence must never replace the original exception or status.
    try:
        if record is None:
            return
        classes = {TimeoutError: "TIMEOUT", BrokenPipeError: "BROKEN_PIPE",
            ConnectionResetError: "CONNECTION_RESET", ConnectionAbortedError: "CONNECTION_ABORTED",
            ssl.SSLError: "SSL_ERROR", ssl.SSLCertVerificationError: "SSL_VERIFY", OSError: "OS_ERROR"}
        name = "CLOSED_FAILURE" if type(error) is ClosedFailure else classes.get(type(error), "OTHER")
        if cleanup and len(record["cleanup_failures"]) >= 3:
            record["cleanup_truncated"] = True
            return
        if not cleanup and record["first_failure"] is not None:
            return
        failure = {"phase": phase, "class": name, "shutdown_requested": shutdown_requested,
            "order": (record["first_failure"] is not None) + len(record["cleanup_failures"])}
        if cleanup:
            record["cleanup_failures"].append(failure)
        else:
            record["first_failure"] = failure
    except BaseException:
        pass


class Observer:
    """Sequential bounded owner; sink receives ONLY the closed projection.

    injected_connector is for socketpair synthetic tests only. Live origin
    connector always verifies TLS, forces HTTP/1.1 ALPN and uses the explicit
    pinned HTTP CONNECT gateway when supplied; environment proxies are ignored.
    Its HTTP semantics/proxy compatibility need separate authorization/review.
    """
    def __init__(self, endpoint, marker, sink, *, enabled=False,
                 injected_connector=None, lifetime=30, gateway=None,
                 max_connections=5, bound_thread=None, core_metadata=False, io_sink=None):
        self.enabled = enabled is True
        self.io_sink = io_sink if callable(io_sink) else None
        self.io_sequence = 0
        self.shutdown_requested = False
        origin = fixed_url(endpoint)
        if (origin.scheme != "https" or not origin.hostname or origin.username or
                origin.password or origin.query or origin.fragment or
                not origin.path.startswith("/") or not origin.path.isascii() or
                any(ord(c) <= 32 or ord(c) == 127 for c in endpoint)):
            raise ClosedFailure("UNKNOWN_UNSUPPORTED")
        if not isinstance(marker, str) or not 1 <= len(marker) <= 256:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        if type(lifetime) not in (int, float) or not 0 < lifetime <= MAX_SECONDS:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        if type(max_connections) is not int or not 1 <= max_connections <= MAX_CONNECTIONS:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        if self.enabled and (bound_thread is not None or not core_metadata):
            Association(bound_thread, "00000000-0000-4000-8000-000000000000", 1)
        self.bound_thread, self.max_connections = bound_thread, max_connections
        self.core_metadata = core_metadata is True
        self.turn_attempts = {}
        self.host, self.port, self.target = origin.hostname, origin.port or 443, origin.path.encode("ascii")
        host = self.host if ":" not in self.host else "[" + self.host + "]"
        self.authority = (host + (":" + str(self.port) if self.port != 443 else "")).encode("ascii")
        self.gateway = None
        if gateway is not None:
            proxy = fixed_url(gateway)
            if (proxy.scheme != "http" or not proxy.hostname or proxy.username or proxy.password or
                    proxy.path not in ("", "/") or proxy.query or proxy.fragment or
                    proxy.port is None or any(ord(c) <= 32 or ord(c) == 127 for c in gateway)):
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            self.gateway = (proxy.hostname, proxy.port)
            try:
                ipaddress.ip_address(proxy.hostname)
            except ValueError:
                raise ClosedFailure("UNKNOWN_UNSUPPORTED") from None
        self.marker, self.sink, self.connector = marker, sink, injected_connector
        self.lifetime = lifetime
        self.deadline = None
        self.connections = self.posts = 0
        self.listener = None
        self.active = None
        self.active_upstream = None
        self.lock = threading.Lock()
        self.closed = False
        self.busy = False
        self.idle = threading.Event()
        self.idle.set()

    def connect(self, deadline):
        return self._connect(deadline, None)

    def _connect(self, deadline, diagnostic):
        if self.connector is not None:
            try:
                return self.connector(deadline)
            except BaseException as error:
                _note_io(diagnostic, "INJECTED_CONNECTOR", error, shutdown_requested=self.shutdown_requested)
                raise
        phase = "TLS_SETUP"
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClosedFailure("UNKNOWN_BUDGET")
            phase = "TCP_CONNECT"
            plain = socket.create_connection(self.gateway or (self.host, self.port), timeout=remaining)
        except BaseException as error:
            _note_io(diagnostic, phase, error, shutdown_requested=self.shutdown_requested)
            raise
        try:
            if self.gateway is not None:
                host = self.host if ":" not in self.host else "[" + self.host + "]"
                tunnel = (host + ":" + str(self.port)).encode("ascii")
                phase = "PROXY_CONNECT_SEND"
                plain.settimeout(max(.001, deadline-time.monotonic()))
                # No API-key, Authorization, request entity, or proxy credential
                # may cross this plaintext Runtime-local CONNECT boundary.
                plain.sendall(b"CONNECT " + tunnel + b" HTTP/1.1\r\nHost: " + tunnel + b"\r\n\r\n")
                reader = Reader(plain, deadline)
                phase = "PROXY_CONNECT_READ"
                first, _, table = headers(reader.until(b"\r\n\r\n", MAX_HEADER))
                if not re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", first):
                    raise ClosedFailure("UNKNOWN_UNSUPPORTED")
                unsupported(table)
                if reader.buf or b"transfer-encoding" in table or table.get(b"content-length", b"0") != b"0":
                    raise ClosedFailure("UNKNOWN_FRAMING")
            phase = "TLS_HANDSHAKE"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClosedFailure("UNKNOWN_BUDGET")
            plain.settimeout(remaining)
            tls = context.wrap_socket(plain, server_hostname=self.host)
            phase = "ALPN_VALIDATE"
            if tls.selected_alpn_protocol() not in (None, "http/1.1"):
                tls.close()
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            return tls
        except BaseException as error:
            _note_io(diagnostic, phase, error, shutdown_requested=self.shutdown_requested)
            try:
                plain.close()
            except BaseException as close_error:
                _note_io(diagnostic, "CLOSE_PLAIN", close_error, cleanup=True, shutdown_requested=self.shutdown_requested)
                raise
            raise

    def open(self):
        if not self.enabled:
            raise ClosedFailure("UNKNOWN_DISABLED")
        if self.deadline is not None:
            raise ClosedFailure("UNKNOWN_BUDGET")
        self.deadline = time.monotonic() + self.lifetime
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(1)
            self.listener.settimeout(self.lifetime)
            return self.listener.getsockname()[1]
        except BaseException:
            self.close()
            raise

    def serve_one(self, association=None):
        with self.lock:
            listener = self.listener
        if listener is None:
            raise ClosedFailure("UNKNOWN_DISABLED")
        if self.connections >= self.max_connections or time.monotonic() >= self.deadline:
            raise ClosedFailure("UNKNOWN_BUDGET")
        listener.settimeout(max(.001, self.deadline-time.monotonic()))
        client, address = listener.accept()
        if address[0] != "127.0.0.1":
            client.close()
            raise ClosedFailure("UNKNOWN_UNSUPPORTED")
        return self.handle(client, association)

    def handle(self, client, association=None):
        """Owns/always closes client; tests inject an AF_UNIX socketpair."""
        event = dict(schema=SCHEMA, status="UNKNOWN_IO", alpha_present=None,
                     input_sha256=None, input_bytes=None, hash_domain=HASH_DOMAIN,
                     request_body_sha256=None, request_body_bytes=None, body_hash_domain=BODY_HASH_DOMAIN,
                     association_provenance="CORE_METADATA" if association is None and self.core_metadata else "EXPLICIT_CORE_ASSIGNMENT",
                     runtime_thread_bound=self.bound_thread is not None,
                     thread=None, turn=None, attempt=None, outbound_POST_count=self.posts)
        upstream = None
        registered = False
        diagnostic = None
        phase = "READ_REQUEST"
        try:
            with self.lock:
                if self.closed or self.busy:
                    raise ClosedFailure("UNKNOWN_BUDGET")
                self.busy = True
                self.active = client
                self.idle.clear()
                registered = True
                try:
                    if self.enabled and self.io_sink is not None and self.io_sequence < MAX_CONNECTIONS:
                        diagnostic = dict(schema=IO_SCHEMA, sequence=self.io_sequence, POST_before=self.posts, POST_after=self.posts, shutdown_requested=self.shutdown_requested, first_failure=None, cleanup_failures=[], cleanup_truncated=False, upstream_eof=False)
                        self.io_sequence += 1
                except BaseException:
                    diagnostic = None
            if not self.enabled:
                raise ClosedFailure("UNKNOWN_DISABLED")
            if self.deadline is None:
                self.deadline = time.monotonic() + self.lifetime
            self.connections += 1
            if self.connections > self.max_connections or time.monotonic() >= self.deadline:
                raise ClosedFailure("UNKNOWN_BUDGET")
            if association is not None and not isinstance(association, Association):
                raise ClosedFailure("UNKNOWN_ASSOCIATION")
            if association is None and not self.core_metadata:
                raise ClosedFailure("UNKNOWN_ASSOCIATION")
            reader = Reader(client, self.deadline)
            raw = reader.until(b"\r\n\r\n", MAX_HEADER)
            first, fields, table = headers(raw)
            if first != b"POST " + self.target + b" HTTP/1.1" or b"host" not in table:
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            unsupported(table, request=True)
            if table.get(b"content-type", b"").lower().split(b";", 1)[0].strip() != b"application/json":
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            mode, count = framing(table, request=True)
            wire, body = request_body(reader, mode, count)
            if reader.buf:
                raise ClosedFailure("UNKNOWN_FRAMING")
            phase = "PARSE_INPUT"
            present, digest, length = input_witness(body, self.marker, association)
            if association is None:
                # input_witness already rejects duplicate keys, invalid JSON and
                # bounds. Only Core-reserved top-level metadata is considered.
                metadata = json.loads(body.decode("utf-8")).get("client_metadata")
                if not isinstance(metadata, dict):
                    raise ClosedFailure("UNKNOWN_ASSOCIATION")
                thread, turn = metadata.get("thread_id"), metadata.get("turn_id")
                Association(thread, turn, 1)
                association = Association(thread, turn, self.turn_attempts.get((thread, turn), 0)+1)
            if self.bound_thread is not None and association.thread != self.bound_thread:
                raise ClosedFailure("UNKNOWN_ASSOCIATION")
            event.update(thread=association.thread, turn=association.turn, attempt=association.attempt)
            event.update(alpha_present=present, input_sha256=digest, input_bytes=length)
            event.update(request_body_sha256=hashlib.sha256(body).hexdigest(), request_body_bytes=len(body))
            # Preserve entity/framing bytes exactly, pin authority and close each
            # connection. Drop hop-specific Connection and prohibit upgrades.
            forwarded = [first, b"Host: " + self.authority]
            if table.get(b"connection", b"close").lower() not in (b"close", b"keep-alive"):
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            forwarded.extend(line for line in raw[:-4].split(b"\r\n")[1:]
                             if line.split(b":", 1)[0].lower() not in
                             (b"host", b"connection"))
            forwarded.extend((b"Connection: close", b"", b""))
            prepared = b"\r\n".join(forwarded)
            phase = "CONNECT"
            if getattr(self.connect, "__func__", None) is Observer.connect:
                upstream = self._connect(self.deadline, diagnostic)
            else:
                upstream = self.connect(self.deadline)  # preserve existing override signature
            with self.lock:
                if self.closed:
                    raise ClosedFailure("UNKNOWN_BUDGET")
                self.active_upstream = upstream
            # Count the single send attempt BEFORE sendall. Partial writes count
            # too; this is never a claim that the provider accepted/processed it.
            self.posts += 1
            self.turn_attempts[(association.thread, association.turn)] = association.attempt
            event["outbound_POST_count"] = self.posts
            phase = 'SEND_REQUEST'
            upstream.settimeout(max(.001, self.deadline-time.monotonic()))
            upstream.sendall(prepared)
            upstream.sendall(wire)
            response = Reader(upstream, self.deadline)
            phase = 'READ_HEAD'
            head = response.until(b"\r\n\r\n", MAX_HEADER)
            start, _, response_table = headers(head, strict=False)
            if not re.fullmatch(rb"HTTP/1\.[01] [245][0-9]{2}(?: [\x20-\x7e]*)?", start):
                raise ClosedFailure("UNKNOWN_UNSUPPORTED")
            unsupported(response_table)
            response_mode, response_count = framing(response_table)
            if start.split(b" ", 2)[1] == b"204":
                if b"transfer-encoding" in response_table or response_count not in (None, 0):
                    raise ClosedFailure("UNKNOWN_FRAMING")
                response_mode, response_count = "length", 0
            validator = ResponseFraming(response_mode, response_count)
            phase = 'WRITE_HEAD'
            client.settimeout(max(.001, self.deadline-time.monotonic()))
            client.sendall(head)
            if response.buf:
                validator.feed(response.buf)
                phase = "WRITE_BODY"
                client.sendall(response.buf)
                response.buf.clear()
            while not validator.complete():
                phase = 'READ_BODY'
                data = response.recv()
                if not data:
                    if diagnostic is not None:
                        diagnostic["upstream_eof"] = True
                    break
                validator.feed(data)
                phase = 'WRITE_BODY'
                client.settimeout(max(.001, self.deadline-time.monotonic()))
                client.sendall(data)
            phase = 'FRAMING_FINISH'
            validator.finish()
            event["status"] = "FORWARDED"
        except ClosedFailure as failure:
            _note_io(diagnostic, phase, failure, shutdown_requested=self.shutdown_requested)
            event["status"] = failure.code
        except Exception as error:
            _note_io(diagnostic, phase, error, shutdown_requested=self.shutdown_requested)
            event["status"] = "UNKNOWN_IO"
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except Exception as error:
                    _note_io(diagnostic, 'CLOSE_UPSTREAM', error, cleanup=True, shutdown_requested=self.shutdown_requested)
                    event["status"] = "UNKNOWN_IO"
            with self.lock:
                if self.active_upstream is upstream:
                    self.active_upstream = None
            try:
                client.close()
            except Exception as error:
                _note_io(diagnostic, 'CLOSE_CLIENT', error, cleanup=True, shutdown_requested=self.shutdown_requested)
                event["status"] = "UNKNOWN_IO"
            with self.lock:
                if self.active is client:
                    self.active = None
            try:
                self.sink(dict(event))
            except Exception as error:
                _note_io(diagnostic, 'ORIGINAL_SINK', error, cleanup=True, shutdown_requested=self.shutdown_requested)
                event["status"] = "UNKNOWN_IO"
            # Publish the bounded sibling while this handle still owns busy.
            # No observer lock is held during the optional callback. Quiesce and
            # a subsequent handle must not observe idle before publication ends.
            try:
                if diagnostic is not None:
                    try:
                        diagnostic.update(POST_after=self.posts, shutdown_requested=self.shutdown_requested)
                        self.io_sink(validate_io_diagnostic(diagnostic))
                    except BaseException:
                        pass
            finally:
                if registered:
                    with self.lock:
                        self.busy = False
                        self.idle.set()
        return event

    def close(self):
        # Detach under a lock, then independently close local references. A
        # concurrent finally/second close cannot turn a socket into None midway.
        with self.lock:
            self.shutdown_requested = True
            self.closed = True
            sockets = (self.listener, self.active, self.active_upstream)
            self.listener = self.active = self.active_upstream = None
        successful = True
        for owned in sockets:
            if owned is None:
                continue
            try:
                owned.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                owned.close()
            except Exception:
                successful = False
        return successful

    def quiesce(self, timeout=2):
        """Terminal only: refuse new work, allow short drain, then force close.

        A forced or failed drain is UNKNOWN; it never upgrades native acceptance.
        The return is a closed summary, not an export of private request values.
        """
        if type(timeout) not in (int, float) or not 0 < timeout <= 5:
            raise ClosedFailure("UNKNOWN_BOUNDS")
        end = time.monotonic() + timeout
        with self.lock:
            self.shutdown_requested = True
            self.closed = True
            listener, self.listener = self.listener, None
        closed = True
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                listener.close()
            except Exception:
                closed = False
        drained = self.idle.wait(timeout/2)
        forced = not drained
        closed = self.close() and closed
        drained = self.idle.wait(max(0, end-time.monotonic()))
        return {"schema":"cicada.test-request-observer-drain.v1", "drained":drained,
                "closed":closed, "forced":forced, "outbound_POST_count":self.posts}


def main():
    # Deliberately no enable switch or environment-triggered credential access.
    print(json.dumps(dict(schema=SCHEMA, enabled=False, effects=False,
                          outbound_POST_count=0), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
