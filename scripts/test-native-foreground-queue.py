#!/usr/bin/env python3
"""Opt-in, zero-paid foreground/draft acceptance for official Codex 0.162.1.

The disposable Runtime uses a loopback-only synthetic Responses provider inside
a network-none container. The TUI is driven through a real PTY; queue delivery
uses the official `codex queue` CLI. No host provider credentials are inherited.
"""

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import termios
import shutil


IMAGE = "sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e"
CODEX = "/home/cicada/.local/bin/codex"
CLI_VERSION = "0.162.1"
CLI_SHA256 = "628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1"
CLI_BYTES = 294415048
MAX_RUNTIME_SECONDS = 140
COMPOSER_READY = b"Ask Codex to do anything"
MAX_TERMINAL_TAIL_BYTES = 16 * 1024
MAX_FILE_TRACE_LINE_BYTES = 4 * 1024
MAX_FILE_TRACE_LINES = 16
MAX_FILE_TRACE_BYTES = MAX_FILE_TRACE_LINE_BYTES * MAX_FILE_TRACE_LINES
MAX_NOTIFICATION_METHODS = 64
MAX_LIFECYCLE_EVENTS = 32
MAX_NOTIFICATION_COUNT = 2**31 - 1
SAFE_NOTIFICATION_METHOD = re.compile(r"[A-Za-z0-9_./-]{1,80}\Z")
SAFE_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
SAFE_TURN_STATUS = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
LIFECYCLE_METHODS = frozenset(("turn/started", "turn/completed", "thread/started", "error"))
SAFE_THREAD_SOURCES = frozenset(("user", "thread_title", "subagent", "guardian_review", "memory_consolidation", "UNKNOWN"))

STRACE_FILES = {
    "strace": ("/usr/bin/strace", "28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001", 0o555),
    "ld-linux-x86-64.so.2": ("/lib64/ld-linux-x86-64.so.2", "1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829", 0o555),
    "lib/libunwind-ptrace.so.0": ("/lib/x86_64-linux-gnu/libunwind-ptrace.so.0", "ec993e45c024b66ea0f17085be1333001428dc714bd9f0520f44a0cde18b921b", 0o444),
    "lib/libunwind-x86_64.so.8": ("/lib/x86_64-linux-gnu/libunwind-x86_64.so.8", "70a88c376a1aced719ca7bdcd5cdd6c5d3bdce44b99f5ab2037fdad096bbf03d", 0o444),
    "lib/libc.so.6": ("/lib/x86_64-linux-gnu/libc.so.6", "d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75", 0o444),
    "lib/liblzma.so.5": ("/lib/x86_64-linux-gnu/liblzma.so.5", "a9793942a8a5f6f4d0f523ef9e0a5be4f0033f2c6c28520cd2b4e706d53c6e17", 0o444),
    "lib/libunwind.so.8": ("/lib/x86_64-linux-gnu/libunwind.so.8", "28e77a498f2f17f8cb883c91303f9901343ea0d8e34959d138dd462fcc9b201f", 0o444),
}


WRAPPER = r'''import base64, hashlib, http.server, json, os, pathlib, queue, re, select, secrets, signal, socket, struct, subprocess, sys, threading, time, urllib.parse

CODEX = "/home/cicada/.local/bin/codex"
EXPECTED_CLI_VERSION = __CICADA_CLI_VERSION__
EXPECTED_CLI_SHA256 = __CICADA_CLI_SHA256__
EXPECTED_CLI_BYTES = __CICADA_CLI_BYTES__
RUN = "/run/cicada"
HOME = "/codex"
CODEX_HOME = HOME + "/.codex"
SOCKET_PATH = "/tmp/cfq.sock"
BUSY = os.environ["CICADA_BUSY_SENTINEL"]
QUEUED = os.environ["CICADA_QUEUE_SENTINEL"]
DRAFT = os.environ["CICADA_DRAFT_SENTINEL"]
SUFFIX = os.environ["CICADA_DRAFT_SUFFIX"]
LOCK = threading.RLock()
STATE = {"schema": "cicada.native-foreground-queue-run.v1", "provider_requests": [], "server_ready": False,
         "notification_method_histogram": {}, "notification_method_other_count": 0,
         "held_original_turn_id": ""}
EVENTS = []
FIRST_RELEASE = threading.Event()
STOP = threading.Event()
TUI = None
APP = None
TRACE_LINES = []
TRACE_COUNTS = {"bytes_read": 0, "ero_fs_lines_seen": 0, "ero_fs_lines_truncated": False,
                "stderr_seen": False, "ptrace_permission_denied": False}
TUI_TRACE_LINES = []
TUI_TRACE_COUNTS = {"bytes_read": 0, "ero_fs_lines_seen": 0, "ero_fs_lines_truncated": False,
                    "stderr_seen": False, "ptrace_permission_denied": False}
TRACE_LOCK = threading.Lock()
TRACE_THREADS = []
MAX_TRACE_LINE = 4096
MAX_TRACE_LINES = 16
MAX_NOTIFICATION_METHODS = 64
MAX_NOTIFICATION_COUNT = 2**31 - 1
MAX_RESUME_TURNS = 8
SAFE_NOTIFICATION_METHOD = re.compile(r"[A-Za-z0-9_./-]{1,80}\Z")
SAFE_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
SAFE_TURN_STATUS = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
SAFE_THREAD_SOURCES = frozenset(("user", "thread_title", "subagent", "guardian_review", "memory_consolidation"))

def count_notification_method(method):
    with LOCK:
        histogram = STATE["notification_method_histogram"]
        if isinstance(method, str) and SAFE_NOTIFICATION_METHOD.fullmatch(method):
            if method in histogram or len(histogram) < MAX_NOTIFICATION_METHODS:
                histogram[method] = min(histogram.get(method, 0) + 1, MAX_NOTIFICATION_COUNT)
            else:
                STATE["notification_method_other_count"] = min(
                    STATE["notification_method_other_count"] + 1, MAX_NOTIFICATION_COUNT)
        else:
            STATE["notification_method_other_count"] = min(
                STATE["notification_method_other_count"] + 1, MAX_NOTIFICATION_COUNT)

def safe_uuid(value):
    if isinstance(value, str) and SAFE_UUID.fullmatch(value):
        return value.lower()
    return ""

def safe_turn_status(params):
    turn = params.get("turn") if isinstance(params, dict) else None
    status = turn.get("status") if isinstance(turn, dict) else None
    if isinstance(status, str) and SAFE_TURN_STATUS.fullmatch(status):
        return status
    return ""

def safe_thread_source(params):
    thread = params.get("thread") if isinstance(params, dict) else None
    source = thread.get("threadSource") if isinstance(thread, dict) else None
    return source if isinstance(source, str) and source in SAFE_THREAD_SOURCES else "UNKNOWN"

def safe_thread_ephemeral(params):
    thread = params.get("thread") if isinstance(params, dict) else None
    value = thread.get("ephemeral") if isinstance(thread, dict) else None
    return value if type(value) is bool else None

def trace_bucket(scope):
    if scope == "app":
        return TRACE_LINES, TRACE_COUNTS
    if scope == "tui":
        return TUI_TRACE_LINES, TUI_TRACE_COUNTS
    raise ValueError("unknown_trace_scope")

def collect_file_trace(stream, scope):
    lines, counts = trace_bucket(scope)
    pending = bytearray()
    dropping = False
    while True:
        chunk = stream.read(4096)
        if not chunk:
            break
        counts["bytes_read"] += len(chunk)
        for byte in chunk:
            if byte == 10:
                if not dropping:
                    line = bytes(pending).decode("utf-8", "replace").strip()
                    if "EROFS" in line and " = -1 " in line and "EROFS (" in line:
                        with TRACE_LOCK:
                            counts["ero_fs_lines_seen"] += 1
                            if len(lines) < MAX_TRACE_LINES:
                                lines.append(line[:MAX_TRACE_LINE])
                            else:
                                counts["ero_fs_lines_truncated"] = True
                pending.clear()
                dropping = False
            elif not dropping:
                if len(pending) < MAX_TRACE_LINE:
                    pending.append(byte)
                else:
                    dropping = True
    lines = list(lines)
    trace_save_error = ""
    if lines:
        try:
            path = pathlib.Path(RUN) / (scope + "-file-syscalls.private.txt")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as out:
                for line in lines:
                    out.write(line.encode("utf-8", "replace")[:MAX_TRACE_LINE] + b"\n")
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            trace_save_error = type(exc).__name__
    with LOCK:
        STATE[scope + "_file_syscall_trace"] = {
            "collector_completed": True,
            "bytes_read": counts["bytes_read"],
            "ero_fs_lines_seen": counts["ero_fs_lines_seen"],
            "ero_fs_lines_retained": len(lines),
            "ero_fs_lines_truncated": counts["ero_fs_lines_truncated"],
            "strace_stderr_seen": counts["stderr_seen"],
            "ptrace_permission_denied_observed": counts["ptrace_permission_denied"],
            "private_summary_save_error": trace_save_error,
        }
        publish()

def collect_strace_stderr(stream, scope):
    _, counts = trace_bucket(scope)
    pending = bytearray()
    while True:
        chunk = stream.read(1024)
        if not chunk:
            break
        for byte in chunk:
            if byte == 10:
                line = bytes(pending).lower()
                if line:
                    counts["stderr_seen"] = True
                    if b"ptrace" in line and (b"operation not permitted" in line or b"permission denied" in line):
                        counts["ptrace_permission_denied"] = True
                pending.clear()
            elif len(pending) < 1024:
                pending.append(byte)

def start_trace_readers(proc, scope, trace_stdout=None):
    output_stream = trace_stdout or proc.stdout
    reader = threading.Thread(target=collect_file_trace, args=(output_stream, scope), daemon=True)
    reader.start()
    TRACE_THREADS.append(reader)
    reader = threading.Thread(target=collect_strace_stderr, args=(proc.stderr, scope), daemon=True)
    reader.start()
    TRACE_THREADS.append(reader)

def traced_app_server(command):
    tracer = "/opt/cicada-strace"
    argv = [tracer + "/ld-linux-x86-64.so.2", "--library-path", tracer + "/lib",
            tracer + "/strace", "-f", "-qq", "-e", "trace=%file", "-e", "status=failed",
            "-s", "4096", "-o", "/dev/stdout", "--", "/bin/sh", "-c",
            'exec "$@" >/dev/null 2>&1', "sh", *command]
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    start_trace_readers(proc, "app")
    return proc

def traced_tui(command):
    tracer = "/opt/cicada-strace"
    tty_fds = []
    try:
        tty_out = os.dup(sys.stdout.fileno())
        tty_fds.append(tty_out)
        tty_err = os.dup(sys.stderr.fileno())
        tty_fds.append(tty_err)
        redirect = 'exec "$@" >/proc/self/fd/' + str(tty_out) + ' 2>/proc/self/fd/' + str(tty_err)
        argv = [tracer + "/ld-linux-x86-64.so.2", "--library-path", tracer + "/lib",
                tracer + "/strace", "-f", "-qq", "-e", "trace=%file", "-e", "status=failed",
                "-s", "4096", "-o", "/dev/stdout", "--", "/bin/sh", "-c", redirect, "sh", *command]
        proc = subprocess.Popen(argv, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=(tty_out, tty_err))
    finally:
        for fd in reversed(tty_fds):
            os.close(fd)
    with LOCK:
        STATE["tui_tracer_invocation"] = argv
        publish()
    start_trace_readers(proc, "tui")
    return proc

def publish():
    path = pathlib.Path(RUN) / "status.json"
    temp = path.with_suffix(".tmp")
    data = json.dumps(STATE, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)

def event_line(event):
    with LOCK:
        EVENTS.append(event)
        path = pathlib.Path(RUN) / "events.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "ab") as out:
            out.write((json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode())
            out.flush()
        if event.get("thread_id") and not STATE.get("thread_id"):
            STATE["thread_id"] = event["thread_id"]
        publish()

def text_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from text_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from text_values(item)

def event_thread(params):
    if not isinstance(params, dict):
        return ""
    if isinstance(params.get("threadId"), str):
        candidate = safe_uuid(params["threadId"])
        if candidate:
            return candidate
    thread = params.get("thread")
    if isinstance(thread, dict) and isinstance(thread.get("id"), str):
        candidate = safe_uuid(thread["id"])
        if candidate:
            return candidate
    turn = params.get("turn")
    if isinstance(turn, dict) and isinstance(turn.get("threadId"), str):
        candidate = safe_uuid(turn["threadId"])
        if candidate:
            return candidate
    return ""

def event_turn(params):
    if not isinstance(params, dict):
        return ""
    turn = params.get("turn")
    if isinstance(turn, dict) and isinstance(turn.get("id"), str):
        candidate = safe_uuid(turn["id"])
        if candidate:
            return candidate
    return safe_uuid(params.get("turnId", ""))

class SocketRPC:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(path)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        self.sock.sendall(("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 16384:
            part = self.sock.recv(4096)
            if not part:
                raise RuntimeError("websocket_handshake_closed")
            response.extend(part)
        head, extra = bytes(response).split(b"\r\n\r\n", 1)
        lines = head.decode("latin1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.lower().strip()] = value.strip()
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if not lines[0].startswith("HTTP/1.1 101") or headers.get("sec-websocket-accept") != accept:
            raise RuntimeError("websocket_handshake_rejected")
        self.sock.settimeout(None)
        self.initial = bytearray(extra)
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.pending = {}
        self.next_id = 0
        self.error = None
        self.done = threading.Event()
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()

    def _read_exact(self, length):
        data = bytearray()
        if self.initial:
            take = min(length, len(self.initial))
            data.extend(self.initial[:take])
            del self.initial[:take]
        while len(data) < length:
            part = self.sock.recv(length - len(data))
            if not part:
                raise RuntimeError("websocket_closed")
            data.extend(part)
        return bytes(data)

    def _send_frame(self, opcode, payload):
        payload = bytes(payload)
        first = bytes([0x80 | opcode])
        size = len(payload)
        if size < 126:
            head = first + bytes([0x80 | size])
        elif size <= 65535:
            head = first + bytes([0x80 | 126]) + struct.pack("!H", size)
        else:
            head = first + bytes([0x80 | 127]) + struct.pack("!Q", size)
        mask = secrets.token_bytes(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        with self.send_lock:
            self.sock.sendall(head + mask + masked)

    def _read_frame(self):
        head = self._read_exact(2)
        fin = bool(head[0] & 0x80)
        opcode = head[0] & 0x0f
        length = head[1] & 0x7f
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if length > 2 * 1024 * 1024:
            raise RuntimeError("websocket_frame_too_large")
        mask = self._read_exact(4) if head[1] & 0x80 else b""
        payload = self._read_exact(length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return fin, opcode, payload

    def _reader(self):
        fragments = bytearray()
        try:
            while not STOP.is_set():
                fin, opcode, payload = self._read_frame()
                if opcode == 8:
                    break
                if opcode == 9:
                    self._send_frame(10, payload)
                    continue
                if opcode == 10:
                    continue
                if opcode in (1, 2):
                    fragments = bytearray(payload)
                elif opcode == 0:
                    fragments.extend(payload)
                else:
                    continue
                if len(fragments) > 2 * 1024 * 1024:
                    raise RuntimeError("websocket_message_too_large")
                if not fin:
                    continue
                try:
                    message = json.loads(fragments.decode("utf-8"))
                except (UnicodeError, ValueError):
                    raise RuntimeError("invalid_appserver_json")
                fragments.clear()
                self._dispatch(message)
        except Exception:
            with self.lock:
                self.error = "appserver_observer_closed"
                pending = list(self.pending.values())
                self.pending.clear()
            for waiter in pending:
                waiter.put(None)
        finally:
            self.done.set()

    def _dispatch(self, message):
        if not isinstance(message, dict):
            return
        method = message.get("method", "")
        if method:
            params = message.get("params", {})
            if "id" not in message:
                count_notification_method(method)
            if isinstance(method, str) and method in ("turn/started", "turn/completed", "thread/started", "error"):
                event_line({"method": method, "thread_id": event_thread(params), "turn_id": event_turn(params),
                            "turn_status": safe_turn_status(params),
                            **({"thread_source": safe_thread_source(params), "ephemeral": safe_thread_ephemeral(params)}
                               if method == "thread/started" else {})})
            return
        ident = message.get("id")
        if isinstance(ident, int):
            with self.lock:
                waiter = self.pending.pop(ident, None)
            if waiter:
                waiter.put(message)

    def send(self, obj):
        self._send_frame(1, json.dumps(obj, separators=(",", ":")).encode())

    def request(self, method, params, timeout=8):
        with self.lock:
            self.next_id += 1
            ident = self.next_id
            waiter = queue.Queue(maxsize=1)
            self.pending[ident] = waiter
        self.send({"id": ident, "method": method, "params": params})
        try:
            message = waiter.get(timeout=timeout)
        except queue.Empty:
            with self.lock:
                self.pending.pop(ident, None)
            raise RuntimeError("appserver_rpc_timeout_" + method)
        if not isinstance(message, dict):
            if self.error:
                raise RuntimeError(self.error)
            raise RuntimeError("appserver_rpc_missing_response_" + method)
        if "error" in message:
            raise RuntimeError("appserver_rpc_rejected_" + method)
        if "result" not in message:
            raise RuntimeError("appserver_rpc_error_" + method)
        return message["result"]

    def close(self):
        try:
            self._send_frame(8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

def response_body(request, index):
    model = request.get("model") if isinstance(request, dict) else "synthetic"
    response_id = "resp_cicada_synthetic_" + str(index)
    message_id = "msg_cicada_synthetic_" + str(index)
    now = int(time.time())
    text = "Synthetic local response; no model was called."
    content = [{"type": "output_text", "text": text, "annotations": []}]
    item = {"id": message_id, "type": "message", "status": "completed", "role": "assistant", "content": content}
    completed = {"id": response_id, "object": "response", "created_at": now, "status": "completed",
                 "completed_at": now, "model": model, "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    working = dict(completed)
    working["status"] = "in_progress"
    working.pop("completed_at", None)
    working["output"] = []
    delta = {"type": "output_text", "text": "", "annotations": []}
    events = [
        {"type": "response.created", "response": working},
        {"type": "response.in_progress", "response": working},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {"id": message_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []}},
        {"type": "response.content_part.added", "item_id": message_id, "output_index": 0, "content_index": 0, "part": delta},
        {"type": "response.output_text.delta", "item_id": message_id, "output_index": 0, "content_index": 0, "delta": text},
        {"type": "response.output_text.done", "item_id": message_id, "output_index": 0, "content_index": 0, "text": text},
        {"type": "response.content_part.done", "item_id": message_id, "output_index": 0, "content_index": 0, "part": content[0]},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": completed},
    ]
    return b"".join(("event: " + event["type"] + "\ndata: " + json.dumps(event, separators=(",", ":")) + "\n\n").encode() for event in events) + b"data: [DONE]\n\n"

class Provider(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        return
    def do_POST(self):
        if self.path != "/v1/responses":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= 2 * 1024 * 1024:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        rendered = "\n".join(text_values(body))
        metadata = body.get("client_metadata") if isinstance(body, dict) else None
        request_thread_id = safe_uuid(metadata.get("thread_id")) if isinstance(metadata, dict) else ""
        request_turn_id = safe_uuid(metadata.get("turn_id")) if isinstance(metadata, dict) else ""
        with LOCK:
            index = len(STATE["provider_requests"]) + 1
            user_thread_ids = {event.get("thread_id") for event in EVENTS if isinstance(event, dict) and
                               event.get("method") == "thread/started" and
                               event.get("thread_source") == "user" and event.get("ephemeral") is False and
                               isinstance(event.get("thread_id"), str)}
            hold_for_busy_gate = (len(user_thread_ids) == 1 and request_thread_id in user_thread_ids and
                                  bool(request_turn_id) and BUSY in rendered and
                                  not STATE.get("held_original_turn_id"))
            if hold_for_busy_gate:
                STATE["held_original_turn_id"] = request_turn_id
            record = {"index": index, "body_sha256": hashlib.sha256(raw).hexdigest(),
                      "thread_id": request_thread_id, "turn_id": request_turn_id,
                      "expected_model_present": isinstance(body, dict) and body.get("model") == "gpt-5.6-luna",
                      "initial_prompt_present": BUSY in rendered, "queue_prompt_present": QUEUED in rendered,
                      "draft_prompt_present": DRAFT in rendered,
                      "draft_with_suffix_present": (DRAFT + SUFFIX) in rendered,
                      "held_for_busy_gate": hold_for_busy_gate, "received_monotonic": time.monotonic(),
                      "response_sent": False}
            STATE["provider_requests"].append(record)
            publish()
        if hold_for_busy_gate:
            deadline = time.monotonic() + 155
            while not FIRST_RELEASE.is_set() and not STOP.is_set() and time.monotonic() < deadline:
                time.sleep(0.025)
            if not FIRST_RELEASE.is_set():
                return
        payload = response_body(body, index)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            with LOCK:
                STATE["provider_requests"][index - 1]["response_sent"] = True
                publish()
        except (BrokenPipeError, ConnectionResetError, OSError):
            with LOCK:
                STATE["provider_requests"][index - 1]["client_closed_before_response"] = True
                publish()
        self.close_connection = True

class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def snapshot(rpc, thread_id, request_id):
    queue_result = rpc.request("thread/queue/list", {"threadId": thread_id, "limit": 8})
    data = queue_result.get("data") if isinstance(queue_result, dict) else None
    cursor = queue_result.get("nextCursor") if isinstance(queue_result, dict) else None
    queue_text = ["\n".join(text_values(row)) for row in data if isinstance(row, (dict, list))] if isinstance(data, list) else []
    with LOCK:
        events = [item.copy() for item in EVENTS if item.get("thread_id") == thread_id]
    selected = [{"method": event["method"], "thread_id": event["thread_id"],
                 "turn_id": event.get("turn_id", ""), "turn_status": event.get("turn_status", "")}
                for event in events if event["method"] in ("turn/started", "turn/completed")]
    result = {"request_id": request_id, "thread_id": thread_id, "queue_count": len(data) if isinstance(data, list) else -1,
              "queue_terminal": cursor is None, "queue_prompt_present": any(QUEUED in text for text in queue_text),
              "turn_events": selected, "turn_started_count": sum(e["method"] == "turn/started" for e in selected),
              "turn_completed_count": sum(e["method"] == "turn/completed" for e in selected)}
    path = pathlib.Path(RUN) / "snapshot.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    return result

def resume_snapshot(rpc, thread_id, request_id):
    response = rpc.request("thread/resume", {"threadId": thread_id, "excludeTurns": False})
    thread = response.get("thread") if isinstance(response, dict) else None
    raw_turns = thread.get("turns") if isinstance(thread, dict) else None
    turns = []
    if isinstance(raw_turns, list):
        for turn in raw_turns[:MAX_RESUME_TURNS]:
            if not isinstance(turn, dict):
                continue
            turn_id = safe_uuid(turn.get("id"))
            status = turn.get("status")
            if turn_id and isinstance(status, str) and SAFE_TURN_STATUS.fullmatch(status):
                turns.append({"turn_id": turn_id, "status": status})
    result = {"request_id": request_id,
              "thread_id": safe_uuid(thread.get("id")) if isinstance(thread, dict) else "",
              "turn_count": len(raw_turns) if isinstance(raw_turns, list) else -1,
              "turns_truncated": isinstance(raw_turns, list) and len(raw_turns) > MAX_RESUME_TURNS,
              "turns": turns}
    path = pathlib.Path(RUN) / "resume-snapshot.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    return result

def controls(rpc):
    last_snapshot = 0
    last_resume = 0
    path = pathlib.Path(RUN) / "control.json"
    while not STOP.is_set():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            current = {}
        if current.get("release_first") is True:
            FIRST_RELEASE.set()
        request = current.get("snapshot")
        if isinstance(request, dict) and isinstance(request.get("request_id"), int) and request["request_id"] > last_snapshot:
            last_snapshot = request["request_id"]
            try:
                snapshot(rpc, request.get("thread_id", ""), last_snapshot)
            except Exception:
                pass
        resume = current.get("resume")
        if isinstance(resume, dict) and isinstance(resume.get("request_id"), int) and resume["request_id"] > last_resume:
            last_resume = resume["request_id"]
            thread_id = safe_uuid(resume.get("thread_id"))
            try:
                if not thread_id:
                    raise ValueError("invalid_thread_id")
                resume_snapshot(rpc, thread_id, last_resume)
            except Exception as exc:
                result = {"request_id": last_resume, "thread_id": thread_id,
                          "error_class": type(exc).__name__}
                resume_path = pathlib.Path(RUN) / "resume-snapshot.json"
                temp = resume_path.with_suffix(".tmp")
                temp.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                os.chmod(temp, 0o600)
                os.replace(temp, resume_path)
        time.sleep(0.025)

def main():
    global APP, TUI
    pathlib.Path(HOME).mkdir(mode=0o700, parents=True, exist_ok=True)
    pathlib.Path(CODEX_HOME).mkdir(mode=0o700, parents=True, exist_ok=True)
    work = pathlib.Path("/tmp/cicada-workspace")
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = LocalServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = ('model = "gpt-5.6-luna"\n'
              'model_provider = "cicada-local"\n'
              'approval_policy = "never"\n'
              'sandbox_mode = "read-only"\n'
              'log_dir = "/codex/.codex/log"\n'
              '[notice.model_migrations]\n'
              '"gpt-5.6-luna" = "gpt-6-luna"\n'
              '[model_providers.cicada-local]\n'
              'name = "CICADA synthetic loopback"\n'
              'base_url = "http://127.0.0.1:' + str(server.server_port) + '/v1"\n'
              'env_key = "CICADA_SYNTHETIC_API_KEY"\n'
              'wire_api = "responses"\n'
              'requires_openai_auth = false\n'
              'request_max_retries = 0\n'
              'stream_idle_timeout_ms = 90000\n'
              '[projects."/tmp/cicada-workspace"]\n'
              'trust_level = "trusted"\n')
    (pathlib.Path(CODEX_HOME) / "config.toml").write_text(config, encoding="utf-8")
    os.chmod(pathlib.Path(CODEX_HOME) / "config.toml", 0o600)
    with open(CODEX, "rb") as binary:
        actual_cli_sha = hashlib.file_digest(binary, "sha256").hexdigest()
        actual_cli_bytes = os.fstat(binary.fileno()).st_size
    with LOCK:
        STATE["runtime_cli_sha256"] = actual_cli_sha
        STATE["runtime_cli_bytes"] = actual_cli_bytes
        STATE["runtime_cli_binary_ok"] = (actual_cli_sha == EXPECTED_CLI_SHA256 and
                                           actual_cli_bytes == EXPECTED_CLI_BYTES)
        if not STATE["runtime_cli_binary_ok"]:
            STATE["phase"] = "runtime_version_mismatch"
            STATE["runtime_version_ok"] = False
        publish()
    if not STATE["runtime_cli_binary_ok"]:
        return 20
    version = subprocess.run([CODEX, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8)
    if version.returncode != 0 or version.stdout.strip() != "codex-cli " + EXPECTED_CLI_VERSION:
        with LOCK:
            STATE["phase"] = "runtime_version_mismatch"
            STATE["runtime_version_ok"] = False
            publish()
        return 20
    with LOCK:
        STATE["runtime_version_ok"] = True
        STATE["runtime_cli_version"] = EXPECTED_CLI_VERSION
        STATE["local_provider_port"] = server.server_port
        publish()
    app_command = [CODEX, "app-server", "--disable", "plugins", "--listen", "unix://" + SOCKET_PATH]
    if os.environ.get("CICADA_TRACE_APP_FILE_FAILURES") == "1":
        APP = traced_app_server(app_command)
    else:
        APP = subprocess.Popen(app_command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 12
    while not os.path.exists(SOCKET_PATH) and APP.poll() is None and time.monotonic() < deadline:
        time.sleep(0.025)
    if not os.path.exists(SOCKET_PATH):
        with LOCK:
            STATE["phase"] = "appserver_socket_unavailable"
            STATE["appserver_exit_code"] = APP.poll()
            publish()
        return 21
    rpc = None
    for _ in range(60):
        try:
            rpc = SocketRPC(SOCKET_PATH)
            break
        except (OSError, RuntimeError):
            time.sleep(0.1)
    if rpc is None:
        with LOCK:
            STATE["phase"] = "appserver_observer_unavailable"
            publish()
        return 22
    try:
        initialized = rpc.request("initialize", {"clientInfo": {"name": "cicada-foreground-queue", "title": "CICADA synthetic foreground test", "version": "1"},
                                                   "capabilities": {"experimentalApi": True}})
    except Exception as exc:
        rpc.close()
        code = str(exc)
        safe_phase = {
            "appserver_rpc_timeout_initialize": "appserver_initialize_response_timeout",
            "appserver_rpc_rejected_initialize": "appserver_initialize_rejected",
            "appserver_rpc_error_initialize": "appserver_initialize_response_invalid",
            "appserver_rpc_missing_response_initialize": "appserver_initialize_response_missing",
            "appserver_observer_closed": "appserver_initialize_connection_closed",
        }.get(code, "appserver_initialize_transport_error" if isinstance(exc, OSError) else "appserver_initialize_client_error")
        with LOCK:
            STATE["phase"] = safe_phase
            publish()
        return 23
    if not isinstance(initialized, dict) or not isinstance(initialized.get("userAgent"), str):
        with LOCK:
            STATE["phase"] = "appserver_initialize_response_invalid"
            publish()
        return 24
    user_agent = initialized["userAgent"]
    if not re.search(r"(?:^|[^0-9])" + re.escape(EXPECTED_CLI_VERSION) + r"(?:[^0-9]|$)", user_agent):
        with LOCK:
            STATE["phase"] = "runtime_version_mismatch"
            STATE["appserver_user_agent_version_ok"] = False
            publish()
        return 25
    with LOCK:
        STATE["appserver_user_agent"] = user_agent
        STATE["appserver_user_agent_version_ok"] = True
        publish()
    try:
        rpc.send({"method": "initialized"})
    except Exception as exc:
        rpc.close()
        with LOCK:
            STATE["phase"] = "appserver_initialized_notification_send_failed"
            STATE["initialize_notification_error_class"] = type(exc).__name__
            publish()
        return 26
    threading.Thread(target=controls, args=(rpc,), daemon=True).start()
    with LOCK:
        STATE["server_ready"] = True
        publish()
    tui_command = [CODEX, "--disable", "plugins", "--remote", "unix://" + SOCKET_PATH,
                   "--no-alt-screen", "--cd", str(work), "--ask-for-approval", "never", "--sandbox", "read-only"]
    if os.environ.get("CICADA_TRACE_TUI_FILE_FAILURES") == "1":
        TUI = traced_tui(tui_command)
    else:
        TUI = subprocess.Popen(tui_command, stdin=None, stdout=None, stderr=None)
    with LOCK:
        STATE["tui_started"] = True
        STATE["tui_process_alive"] = TUI.poll() is None
        STATE["tui_pid"] = TUI.pid
        publish()
    try:
        while TUI.poll() is None:
            time.sleep(0.05)
        code = TUI.wait()
    finally:
        STOP.set()
        FIRST_RELEASE.set()
        if APP and APP.poll() is None:
            APP.terminate()
            try:
                APP.wait(timeout=3)
            except subprocess.TimeoutExpired:
                APP.kill()
                try:
                    APP.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        for reader in TRACE_THREADS:
            reader.join(timeout=2)
        if os.environ.get("CICADA_TRACE_APP_FILE_FAILURES") == "1":
            with LOCK:
                TRACE_STATE = STATE.get("app_file_syscall_trace", {})
                TRACE_STATE["strace_exit_code"] = APP.returncode if APP else None
                TRACE_STATE["strace_stderr_seen"] = TRACE_COUNTS["stderr_seen"]
                TRACE_STATE["ptrace_permission_denied_observed"] = TRACE_COUNTS["ptrace_permission_denied"]
                if TRACE_COUNTS["ptrace_permission_denied"]:
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_PTRACE_PERMISSION_DENIED"
                elif not TRACE_STATE.get("collector_completed"):
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_TRACE_COLLECTOR_INCOMPLETE"
                elif TRACE_COUNTS["stderr_seen"]:
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_STRACE_DIAGNOSTIC_UNCLASSIFIED"
                elif APP and APP.returncode not in (None, 0, -signal.SIGTERM, -signal.SIGKILL):
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_STRACE_EXIT_NONZERO"
                else:
                    TRACE_STATE["instrumentation_status"] = "TRACE_COLLECTOR_COMPLETE_NO_STRACE_DIAGNOSTIC"
                STATE["app_file_syscall_trace"] = TRACE_STATE
                publish()
        if os.environ.get("CICADA_TRACE_TUI_FILE_FAILURES") == "1":
            with LOCK:
                TRACE_STATE = STATE.get("tui_file_syscall_trace", {})
                TRACE_STATE["strace_exit_code"] = TUI.returncode if TUI else None
                TRACE_STATE["strace_stderr_seen"] = TUI_TRACE_COUNTS["stderr_seen"]
                TRACE_STATE["ptrace_permission_denied_observed"] = TUI_TRACE_COUNTS["ptrace_permission_denied"]
                if TUI_TRACE_COUNTS["ptrace_permission_denied"]:
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_PTRACE_PERMISSION_DENIED"
                elif not TRACE_STATE.get("collector_completed"):
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_TRACE_COLLECTOR_INCOMPLETE"
                elif TUI_TRACE_COUNTS["stderr_seen"]:
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_STRACE_DIAGNOSTIC_UNCLASSIFIED"
                elif TUI and TUI.returncode in (-signal.SIGTERM, -signal.SIGKILL):
                    TRACE_STATE["instrumentation_status"] = "BLOCKED_TRACER_SIGNALLED_DURING_CLEANUP"
                else:
                    TRACE_STATE["instrumentation_status"] = "TRACE_COLLECTOR_COMPLETE"
                STATE["tui_file_syscall_trace"] = TRACE_STATE
                publish()
        rpc.close()
        server.shutdown()
        server.server_close()
    with LOCK:
        STATE["tui_process_alive"] = False
        STATE["tui_exit_code"] = code
        STATE["phase"] = "tui_exited"
        publish()
    return code

def stop(signum, frame):
    STOP.set()
    FIRST_RELEASE.set()
    for process in (TUI, APP):
        if process and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    sys.exit(main())
except Exception:
    with LOCK:
        STATE["phase"] = "runtime_harness_error"
        publish()
    sys.exit(24)
'''
WRAPPER = (WRAPPER.replace("__CICADA_CLI_VERSION__", repr(CLI_VERSION))
           .replace("__CICADA_CLI_SHA256__", repr(CLI_SHA256))
           .replace("__CICADA_CLI_BYTES__", str(CLI_BYTES)))


class GateError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class StartupDiagnosticComplete(Exception):
    pass


class PTY:
    def __init__(self, container_id):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 120, 0, 0))
        self.pump = subprocess.Popen(["docker", "start", "-ai", container_id], stdin=slave, stdout=slave,
                                     stderr=slave, close_fds=True, start_new_session=True)
        os.close(slave)
        self.reader_stop = threading.Event()
        self.output_bytes = 0
        self.output_tail = bytearray()
        self.composer_ready = threading.Event()
        self._composer_marker_tail = b""
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while not self.reader_stop.is_set():
            ready, _, _ = select.select([self.master], [], [], 0.2)
            if not ready:
                if self.pump.poll() is not None:
                    return
                continue
            try:
                chunk = os.read(self.master, 8192)
            except OSError:
                return
            if not chunk:
                return
            self.output_bytes += len(chunk)
            self.output_tail.extend(chunk)
            if len(self.output_tail) > MAX_TERMINAL_TAIL_BYTES:
                del self.output_tail[:-MAX_TERMINAL_TAIL_BYTES]
            if not self.composer_ready.is_set():
                observed = self._composer_marker_tail + chunk
                if COMPOSER_READY in observed:
                    self.composer_ready.set()
                self._composer_marker_tail = observed[-(len(COMPOSER_READY) - 1):]

    def send(self, data):
        os.write(self.master, data)

    def close(self):
        self.reader_stop.set()
        try:
            os.close(self.master)
        except OSError:
            pass
        try:
            self.pump.wait(timeout=7)
        except subprocess.TimeoutExpired:
            self.pump.terminate()
            try:
                self.pump.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.pump.kill()
                self.pump.wait(timeout=2)
        return self.pump.returncode


def run(command, *, timeout=12, input_text=None, check=False):
    try:
        return subprocess.run(command, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, check=check)
    except subprocess.TimeoutExpired as exc:
        raise GateError("BLOCKED", "bounded_command_timeout") from exc


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def wait_for(description, deadline, predicate, status_path, events_path):
    while time.monotonic() < deadline:
        status = read_json(status_path)
        events = []
        try:
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line]
        except (OSError, ValueError):
            pass
        if predicate(status, events):
            return status, events
        if any(event.get("method") == "error" for event in events):
            raise GateError("BLOCKED", "appserver_error_notification")
        if status.get("phase") in ("appserver_socket_unavailable", "appserver_observer_unavailable",
                                     "appserver_initialize_failed", "runtime_version_mismatch", "runtime_harness_error"):
            raise GateError("BLOCKED", status["phase"])
        if status.get("phase") == "tui_exited":
            raise GateError("BLOCKED", "tui_exited_before_" + description)
        time.sleep(0.05)
    raise GateError("BLOCKED", "timeout_waiting_for_" + description)


def wait_for_composer_ready(session, deadline, status_path):
    while time.monotonic() < deadline:
        if session.composer_ready.is_set():
            return
        status = read_json(status_path)
        if status.get("tui_started") is True and status.get("tui_process_alive") is False:
            raise GateError("BLOCKED", "tui_exited_before_composer_ready")
        time.sleep(0.05)
    raise GateError("BLOCKED", "timeout_waiting_for_tui_composer_ready")


def startup_diagnostics(status_path, events_path, session):
    status = read_json(status_path)
    counts = {"thread_started": 0, "turn_started": 0, "turn_completed": 0}
    lifecycle_events = []
    try:
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            method = event.get("method") if isinstance(event, dict) else None
            if method == "thread/started":
                counts["thread_started"] += 1
            elif method == "turn/started":
                counts["turn_started"] += 1
            elif method == "turn/completed":
                counts["turn_completed"] += 1
            if isinstance(event, dict) and isinstance(method, str) and method in LIFECYCLE_METHODS and len(lifecycle_events) < MAX_LIFECYCLE_EVENTS:
                lifecycle_events.append(event)
    except OSError:
        pass
    requests = status.get("provider_requests")
    return {
        "server_ready": status.get("server_ready") is True,
        "tui_spawn_reported": status.get("tui_started") is True,
        "tui_process_alive": status.get("tui_process_alive"),
        "tui_exit_code": status.get("tui_exit_code"),
        "composer_ready_marker_seen": bool(session and session.composer_ready.is_set()),
        "terminal_output_bytes": session.output_bytes if session else 0,
        "provider_request_count": len(requests) if isinstance(requests, list) else 0,
        "thread_started_event_count": counts["thread_started"],
        "turn_started_event_count": counts["turn_started"],
        "turn_completed_event_count": counts["turn_completed"],
        "notification_diagnostics": sanitized_notification_diagnostics(status, lifecycle_events),
    }


def sanitized_notification_diagnostics(status, lifecycle_events):
    histogram = {}
    other_count = status.get("notification_method_other_count")
    other_count = min(other_count, MAX_NOTIFICATION_COUNT) if type(other_count) is int and other_count >= 0 else 0
    raw_histogram = status.get("notification_method_histogram")
    if isinstance(raw_histogram, dict):
        for method, count in sorted(raw_histogram.items(), key=lambda item: item[0] if isinstance(item[0], str) else ""):
            if type(count) is not int or count < 0:
                other_count = min(other_count + 1, MAX_NOTIFICATION_COUNT)
                continue
            count = min(count, MAX_NOTIFICATION_COUNT)
            if not isinstance(method, str) or not SAFE_NOTIFICATION_METHOD.fullmatch(method):
                other_count = min(other_count + count, MAX_NOTIFICATION_COUNT)
            elif method in histogram:
                histogram[method] = min(histogram[method] + count, MAX_NOTIFICATION_COUNT)
            elif len(histogram) < MAX_NOTIFICATION_METHODS:
                histogram[method] = count
            else:
                other_count = min(other_count + count, MAX_NOTIFICATION_COUNT)

    closed_events = []
    for event in lifecycle_events:
        if not isinstance(event, dict):
            continue
        method = event.get("method")
        if not isinstance(method, str) or method not in LIFECYCLE_METHODS:
            continue
        closed = {"method": method}
        for source, target in (("thread_id", "thread_id"), ("turn_id", "turn_id")):
            value = event.get(source)
            if isinstance(value, str) and SAFE_UUID.fullmatch(value):
                closed[target] = value.lower()
        status = event.get("turn_status")
        if isinstance(status, str) and SAFE_TURN_STATUS.fullmatch(status):
            closed["turn_status"] = status
        if method == "thread/started":
            source = event.get("thread_source")
            closed["thread_source"] = source if isinstance(source, str) and source in SAFE_THREAD_SOURCES else "UNKNOWN"
            ephemeral = event.get("ephemeral")
            if type(ephemeral) is bool:
                closed["ephemeral"] = ephemeral
        closed_events.append(closed)
        if len(closed_events) == MAX_LIFECYCLE_EVENTS:
            break
    return {"method_histogram": histogram, "other_method_count": other_count,
            "lifecycle_events": closed_events}


def sanitized_provider_requests(status):
    requests = status.get("provider_requests")
    if not isinstance(requests, list):
        return []
    summaries = []
    for request in requests:
        if not isinstance(request, dict):
            continue
        digest = request.get("body_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            digest = None
        index = request.get("index")
        thread_id = request.get("thread_id")
        if not isinstance(thread_id, str) or not SAFE_UUID.fullmatch(thread_id):
            thread_id = None
        turn_id = request.get("turn_id")
        if not isinstance(turn_id, str) or not SAFE_UUID.fullmatch(turn_id):
            turn_id = None
        summaries.append({
            "index": index if type(index) is int else None,
            "body_sha256": digest,
            "thread_id": thread_id.lower() if thread_id else None,
            "turn_id": turn_id.lower() if turn_id else None,
            "expected_model_present": request.get("expected_model_present") is True,
            "initial_prompt_present": request.get("initial_prompt_present") is True,
            "queue_prompt_present": request.get("queue_prompt_present") is True,
            "draft_prompt_present": request.get("draft_prompt_present") is True,
            "draft_with_suffix_present": request.get("draft_with_suffix_present") is True,
            "held_for_busy_gate": request.get("held_for_busy_gate") is True,
            "response_sent": request.get("response_sent") is True,
            "client_closed_before_response": request.get("client_closed_before_response") is True,
        })
    return summaries


def save_private_terminal_tail(result_path, session):
    if result_path is None or session is None:
        return None
    result_path = result_path.expanduser().resolve()
    result_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if result_path.parent.stat().st_mode & 0o077:
        raise PermissionError("result directory is not private")
    tail_path = result_path.with_name("terminal-output-tail.private.bin")
    raw = bytes(session.output_tail[-MAX_TERMINAL_TAIL_BYTES:])
    fd = os.open(tail_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return {"file": tail_path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def control(private_dir, **values):
    path = private_dir / "control.json"
    old = read_json(path)
    old.update(values)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(old, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def request_snapshot(private_dir, sequence, thread_id, deadline):
    control(private_dir, snapshot={"request_id": sequence, "thread_id": thread_id})
    path = private_dir / "snapshot.json"
    while time.monotonic() < deadline:
        snapshot = read_json(path)
        if snapshot.get("request_id") == sequence:
            return snapshot
        time.sleep(0.05)
    raise GateError("BLOCKED", "timeout_waiting_for_queue_snapshot")


def request_resume_snapshot(private_dir, sequence, thread_id, deadline):
    control(private_dir, resume={"request_id": sequence, "thread_id": thread_id})
    path = private_dir / "resume-snapshot.json"
    while time.monotonic() < deadline:
        snapshot = read_json(path)
        if snapshot.get("request_id") == sequence:
            if snapshot.get("error_class"):
                raise GateError("BLOCKED", "running_thread_resume_failed")
            return snapshot
        time.sleep(0.05)
    raise GateError("BLOCKED", "timeout_waiting_for_running_thread_resume")


def held_initial_prompt_request(status, thread_id=None):
    requests = status.get("provider_requests")
    if not isinstance(requests, list):
        return None
    matches = [item for item in requests if isinstance(item, dict) and
               item.get("thread_id") and item.get("turn_id") and
               (thread_id is None or item.get("thread_id") == thread_id) and
               item.get("initial_prompt_present") is True and item.get("held_for_busy_gate") is True and
               item.get("response_sent") is False]
    return matches[0] if len(matches) == 1 else None


def user_thread_ids(events):
    return [event.get("thread_id") for event in events if isinstance(event, dict) and
            event.get("method") == "thread/started" and event.get("thread_source") == "user" and
            event.get("ephemeral") is False and isinstance(event.get("thread_id"), str) and
            SAFE_UUID.fullmatch(event["thread_id"])]


def sole_user_thread_id(events):
    matches = user_thread_ids(events)
    if len(matches) != 1:
        raise GateError("BLOCKED", "exact_non_ephemeral_user_thread_unavailable_or_ambiguous")
    return matches[0].lower()


def active_turn_from_resume(snapshot, expected_thread_id):
    if snapshot.get("thread_id") != expected_thread_id or snapshot.get("turns_truncated") is not False:
        raise GateError("BLOCKED", "running_thread_resume_snapshot_invalid")
    turns = snapshot.get("turns")
    if not isinstance(turns, list) or snapshot.get("turn_count") != 1 or len(turns) != 1:
        raise GateError("BLOCKED", "running_thread_resume_turn_snapshot_incomplete")
    active = [turn for turn in turns if isinstance(turn, dict) and turn.get("status") == "inProgress"]
    if len(active) != 1:
        raise GateError("BLOCKED", "original_active_turn_snapshot_not_unique")
    turn_id = active[0].get("turn_id")
    if not isinstance(turn_id, str) or not SAFE_UUID.fullmatch(turn_id):
        raise GateError("BLOCKED", "original_active_turn_id_invalid")
    return turn_id.lower(), active[0]["status"]


def thread_turn_events(events, thread_id):
    return [event for event in events if event.get("thread_id") == thread_id and
            event.get("method") in ("turn/started", "turn/completed")]


def held_turn_events_valid(events, thread_id, original_turn_id):
    selected = thread_turn_events(events, thread_id)
    return (all(event.get("turn_id") == original_turn_id for event in selected) and
            sum(event.get("method") == "turn/started" for event in selected) <= 1 and
            not any(event.get("method") == "turn/completed" for event in selected))


def completed_queued_turn_id(events, thread_id, original_turn_id):
    selected = thread_turn_events(events, thread_id)
    original_completed = [index for index, event in enumerate(selected)
                          if event.get("method") == "turn/completed" and
                          event.get("turn_id") == original_turn_id and
                          event.get("turn_status") == "completed"]
    if len(original_completed) != 1:
        return ""
    before = selected[:original_completed[0]]
    if len(before) > 1:
        return ""
    if before and (len(before) != 1 or before[0].get("method") != "turn/started" or
                   before[0].get("turn_id") != original_turn_id):
        return ""
    after = selected[original_completed[0] + 1:]
    if len(after) < 2:
        return ""
    queued_id = after[0].get("turn_id", "")
    if (after[0].get("method") != "turn/started" or not isinstance(queued_id, str) or
            not SAFE_UUID.fullmatch(queued_id) or
            queued_id == original_turn_id or after[1].get("method") != "turn/completed" or
            after[1].get("turn_id") != queued_id or after[1].get("turn_status") != "completed"):
        return ""
    return queued_id


def final_queued_and_draft_turn_ids(events, thread_id, original_turn_id):
    queued_id = completed_queued_turn_id(events, thread_id, original_turn_id)
    if not queued_id:
        return "", ""
    selected = thread_turn_events(events, thread_id)
    original_completed = next(index for index, event in enumerate(selected)
                              if event.get("method") == "turn/completed" and
                              event.get("turn_id") == original_turn_id)
    following = selected[original_completed + 1:]
    if len(following) != 4:
        return "", ""
    draft_id = following[2].get("turn_id", "")
    if (following[0].get("method") != "turn/started" or following[0].get("turn_id") != queued_id or
            following[1].get("method") != "turn/completed" or following[1].get("turn_id") != queued_id or
            following[1].get("turn_status") != "completed" or
            following[2].get("method") != "turn/started" or not isinstance(draft_id, str) or
            not SAFE_UUID.fullmatch(draft_id) or
            draft_id in (original_turn_id, queued_id) or following[3].get("method") != "turn/completed" or
            following[3].get("turn_id") != draft_id or following[3].get("turn_status") != "completed"):
        return "", ""
    return queued_id, draft_id


def verify_container(container_id, run_id):
    result = run(["docker", "inspect", "--format", "{{.Id}}|{{.Image}}|{{.HostConfig.NetworkMode}}|{{index .Config.Labels \"io.cicada.test.run\"}}", container_id])
    if result.returncode != 0:
        return False
    parts = result.stdout.strip().split("|", 3)
    return len(parts) == 4 and parts[0] == container_id and parts[1] == IMAGE and parts[2] == "none" and parts[3] == run_id


def owned_container(container_id, run_id):
    result = run(["docker", "inspect", "--format", "{{.Id}}|{{index .Config.Labels \"io.cicada.test.run\"}}", container_id])
    if result.returncode != 0:
        return False
    parts = result.stdout.strip().split("|", 1)
    return len(parts) == 2 and parts[0] == container_id and parts[1] == run_id


def container_absent(container_id):
    result = run(["docker", "inspect", container_id], timeout=5)
    if result.returncode == 0:
        return False
    diagnostic = result.stderr.lower()
    return "no such object" in diagnostic or "no such container" in diagnostic


def write_result(path, result):
    if path is None:
        return
    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", help=f"run one isolated real {CLI_VERSION} TUI/queue check")
    parser.add_argument("--startup-diagnostic-only", action="store_true",
                        help="stop at the first synthetic provider POST or TUI exit; skip queue and draft checks")
    parser.add_argument("--trace-app-file-failures", action="store_true",
                        help="with startup diagnostics, trace app-server failed file syscalls using staged host strace")
    parser.add_argument("--trace-tui-file-failures", action="store_true",
                        help="with startup diagnostics, trace TUI failed file syscalls while preserving its PTY")
    parser.add_argument("--timeout", type=int, default=140, help="evidence deadline; cleanup remains within 180 seconds")
    parser.add_argument("--result", type=Path, help="write a sanitized private JSON result with O_EXCL")
    args = parser.parse_args()
    if args.startup_diagnostic_only and not args.run_native:
        parser.error("--startup-diagnostic-only requires --run-native")
    if args.trace_app_file_failures and not args.startup_diagnostic_only:
        parser.error("--trace-app-file-failures requires --startup-diagnostic-only")
    if args.trace_tui_file_failures and not args.startup_diagnostic_only:
        parser.error("--trace-tui-file-failures requires --startup-diagnostic-only")
    if args.trace_app_file_failures and args.trace_tui_file_failures:
        parser.error("select only one trace scope per startup diagnostic")
    if args.trace_app_file_failures and not args.result:
        parser.error("--trace-app-file-failures requires --result for bounded private evidence")
    if args.trace_tui_file_failures and not args.result:
        parser.error("--trace-tui-file-failures requires --result for bounded private evidence")
    if not args.run_native:
        print(json.dumps({"status": "NOT_RUN", "reason": f"pass --run-native to create one disposable {CLI_VERSION} TUI"}, sort_keys=True))
        return 0
    max_timeout = 60 if args.startup_diagnostic_only else MAX_RUNTIME_SECONDS
    if not 30 <= args.timeout <= max_timeout:
        parser.error(f"--timeout must be between 30 and {max_timeout} seconds")
    if args.result and args.result.exists():
        parser.error("--result already exists; refusing to overwrite evidence")
    if args.result and args.result.expanduser().resolve().with_name("terminal-output-tail.private.bin").exists():
        parser.error("private terminal-tail path already exists; refusing to overwrite evidence")
    if args.result and args.result.expanduser().resolve().with_name("app-file-syscalls.private.txt").exists():
        parser.error("private app-file-trace path already exists; refusing to overwrite evidence")
    if args.result and args.trace_tui_file_failures and args.result.expanduser().resolve().with_name("tui-file-syscalls.private.txt").exists():
        parser.error("private TUI-file-trace path already exists; refusing to overwrite evidence")

    result = {"schema": "cicada.native-foreground-queue-run.v1", "status": "BLOCKED",
              "runtime_image": IMAGE, "provider": "synthetic_loopback_only", "external_network": "none",
              "expected_cli_version": CLI_VERSION, "expected_cli_sha256": CLI_SHA256,
              "expected_cli_bytes": CLI_BYTES,
              "paid_model_calls": 0, "human_ui_draft": "NOT_RUN", "foreground_busy_queue": "NOT_RUN",
              "provider_requests": []}
    result["driver_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["invocation"] = ["python3", str(Path(__file__).resolve()), "--run-native", "--timeout", str(args.timeout)]
    if args.startup_diagnostic_only:
        result["invocation"].append("--startup-diagnostic-only")
    if args.trace_app_file_failures:
        result["invocation"].append("--trace-app-file-failures")
    if args.trace_tui_file_failures:
        result["invocation"].append("--trace-tui-file-failures")
    if args.result:
        result["invocation"] += ["--result", str(args.result.resolve())]
    started_at = time.time()
    deadline = time.monotonic() + args.timeout
    run_id = "native-foreground-queue-" + secrets.token_hex(8)
    name = "cicada-" + run_id
    container_id = ""
    session = None
    cidfile = None
    private_dir = None
    tracer_base = None
    try:
        image = run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE])
        if image.returncode != 0 or image.stdout.strip() != IMAGE:
            raise GateError("BLOCKED", "pinned_runtime_image_unavailable_or_mismatched")
        result["runtime_image_id"] = image.stdout.strip()
        uid, gid = os.getuid(), os.getgid()
        private_dir = Path(tempfile.mkdtemp(prefix="cicada-native-foreground-queue-"))
        os.chmod(private_dir, 0o700)
        (private_dir / "control.json").write_text("{}", encoding="utf-8")
        os.chmod(private_dir / "control.json", 0o600)
        if args.trace_app_file_failures or args.trace_tui_file_failures:
            tracer_base = Path(tempfile.mkdtemp(prefix="cicada-native-foreground-tracer-"))
            os.chmod(tracer_base, 0o700)
            tracer_dir = tracer_base / "cicada-strace"
            tracer_dir.mkdir(mode=0o755)
            tracer_inputs = {}
            for relative, (source, expected_sha256, mode) in STRACE_FILES.items():
                source_path = Path(source).resolve(strict=True)
                data = source_path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if digest != expected_sha256:
                    raise GateError("BLOCKED", "host_strace_input_hash_mismatch")
                target = tracer_dir / relative
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                target.write_bytes(data)
                os.chmod(target, mode)
                if hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha256:
                    raise GateError("BLOCKED", "staged_strace_input_hash_mismatch")
                tracer_inputs[relative] = {"resolved_source": str(source_path), "sha256": digest,
                                           "bytes": len(data), "mode": oct(mode)}
            result["file_trace_tool"] = {"implementation": "host_strace_sha256_pinned", "inputs": tracer_inputs,
                                         "read_only_mount": "/opt/cicada-strace",
                                         "retained_ero_fs_line_limit": MAX_FILE_TRACE_LINES,
                                         "retained_ero_fs_line_bytes": MAX_FILE_TRACE_LINE_BYTES,
                                         "trace_scope": ("app-server descendants, failed %file syscalls only"
                                                         if args.trace_app_file_failures else
                                                         "TUI descendants with original PTY fds, failed %file syscalls only")}
        cidfile = private_dir / "cid"
        t = secrets.token_hex(12)
        busy = "CICADA_BUSY_" + t
        queued = "CICADA_QUEUED_" + t
        draft = "CICADA_DRAFT_" + t
        suffix = "_PRESERVED_SUFFIX_" + secrets.token_hex(8)
        unix_uri = "unix:///tmp/cfq.sock"
        diagnostic_env = []
        if args.startup_diagnostic_only:
            diagnostic_env = ["--env", "RUST_BACKTRACE=1", "--env", "RUST_LIB_BACKTRACE=1"]
        trace_mount = []
        trace_env = []
        if args.trace_app_file_failures or args.trace_tui_file_failures:
            trace_mount = ["--mount", f"type=bind,src={tracer_dir},dst=/opt/cicada-strace,readonly"]
            scope_env = "CICADA_TRACE_APP_FILE_FAILURES=1" if args.trace_app_file_failures else "CICADA_TRACE_TUI_FILE_FAILURES=1"
            trace_env = ["--env", scope_env]
        run_command = ["docker", "create", "--pull=never", "--cidfile", str(cidfile), "--name", name,
                       "--label", "io.cicada.test.run=" + run_id, "--interactive", "--tty", "--init",
                       "--network", "none", "--read-only", "--user", f"{uid}:{gid}", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges:true", "--pids-limit", "96", "--cpus", "1",
                        "--memory", "768m", "--tmpfs", f"/tmp:rw,nosuid,nodev,size=256m,uid={uid},gid={gid}",
                        "--tmpfs", f"/codex:rw,nosuid,nodev,mode=0700,size=128m,uid={uid},gid={gid}",
                        "--mount", f"type=bind,src={private_dir},dst=/run/cicada", "--workdir", "/tmp",
                        *trace_mount,
                       "--env", "HOME=/codex", "--env", "CODEX_HOME=/codex/.codex",
                       "--env", "TMPDIR=/tmp", "--env", "PATH=/home/cicada/.local/bin:/usr/local/bin:/usr/bin:/bin",
                       "--env", "TERM=xterm-256color", "--env", "CICADA_SYNTHETIC_API_KEY=local-only-not-a-secret",
                       "--env", "CICADA_BUSY_SENTINEL=" + busy, "--env", "CICADA_QUEUE_SENTINEL=" + queued,
                       "--env", "CICADA_DRAFT_SENTINEL=" + draft, "--env", "CICADA_DRAFT_SUFFIX=" + suffix,
                       "--env", "OPENAI_API_KEY=", "--env", "API_KEY=", "--env", "ANTHROPIC_API_KEY=",
                        "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=", "--env", "ALL_PROXY=",
                        "--env", "http_proxy=", "--env", "https_proxy=", "--env", "all_proxy=",
                        *diagnostic_env, *trace_env,
                       "--entrypoint", "python3", IMAGE, "-u", "-c", WRAPPER]
        created = run(run_command, timeout=20)
        result["docker_create_exit_code"] = created.returncode
        container_id = cidfile.read_text(encoding="ascii").strip() if cidfile.is_file() else created.stdout.strip()
        if len(container_id) != 64 or any(ch not in "0123456789abcdef" for ch in container_id):
            container_id = ""
            raise GateError("BLOCKED", "docker_create_id_unavailable")
        if created.returncode != 0:
            raise GateError("BLOCKED", "docker_create_failed")
        if not verify_container(container_id, run_id):
            raise GateError("BLOCKED", "created_container_identity_or_isolation_mismatch")
        result["container_id"] = container_id
        result["runtime_command"] = ["codex app-server --disable plugins --listen unix:///tmp/cfq.sock",
                                     "codex --disable plugins --remote unix:///tmp/cfq.sock --no-alt-screen --cd /tmp/cicada-workspace --ask-for-approval never --sandbox read-only"]
        if args.trace_app_file_failures:
            result["tracer_invocation"] = ["/opt/cicada-strace/ld-linux-x86-64.so.2", "--library-path",
                                           "/opt/cicada-strace/lib", "/opt/cicada-strace/strace", "-f", "-qq",
                                           "-e trace=%file", "-e status=failed", "-s 4096", "-o /dev/stdout",
                                           "-- /bin/sh -c 'exec \"$@\" >/dev/null 2>&1' sh",
                                           CODEX, "app-server --disable plugins --listen unix:///tmp/cfq.sock"]
        elif args.trace_tui_file_failures:
            result["tracer_invocation_template"] = ["/opt/cicada-strace/ld-linux-x86-64.so.2", "--library-path",
                                                    "/opt/cicada-strace/lib", "/opt/cicada-strace/strace", "-f", "-qq",
                                                    "-e trace=%file", "-e status=failed", "-s 4096", "-o /dev/stdout",
                                                    "-- /bin/sh -c 'exec \"$@\" >/proc/self/fd/<passed-pty-out> 2>/proc/self/fd/<passed-pty-err>' sh",
                                                    CODEX, "<TUI command argv>"]
        result["queue_command_shape"] = ["docker", "exec", container_id, CODEX, "queue", "--remote", unix_uri,
                                         "--thread", "<exact-TUI-thread-id>", "--message", "<synthetic-redacted>"]
        binds = ["one private controller directory"]
        if args.trace_app_file_failures or args.trace_tui_file_failures:
            binds.append("one read-only strace-only tool directory")
        binds.append("no repository mount")
        result["docker_create_isolation"] = {"network": "none", "read_only_root": True, "cap_drop_all": True,
                                             "no_new_privileges": True, "binds": binds}
        session = PTY(container_id)
        result["docker_start_attach_argv"] = ["docker", "start", "-ai", container_id]
        print("native_foreground_container_started=" + container_id, file=sys.stderr, flush=True)
        status_path, events_path = private_dir / "status.json", private_dir / "events.jsonl"
        wait_for("runtime_tui_started", min(deadline, time.monotonic() + 20),
                 lambda status, _: status.get("server_ready") is True and status.get("tui_started") is True,
                 status_path, events_path)
        wait_for_composer_ready(session, min(deadline, time.monotonic() + 25), status_path)
        result["composer_ready_marker_seen"] = True
        session.send(busy.encode())
        time.sleep(0.35)
        session.send(b"\r")
        if args.startup_diagnostic_only:
            status, events = wait_for("first_synthetic_provider_request", min(deadline, time.monotonic() + 35),
                                      lambda s, _: bool(s.get("provider_requests")),
                                      status_path, events_path)
        else:
            status, events = wait_for("held_synthetic_post_and_user_thread", min(deadline, time.monotonic() + 35),
                                      lambda s, e: any(held_initial_prompt_request(s, thread_id) is not None
                                                       for thread_id in user_thread_ids(e)),
                                      status_path, events_path)
        thread_id = None if args.startup_diagnostic_only else sole_user_thread_id(events)
        initial = status["provider_requests"][0] if args.startup_diagnostic_only else held_initial_prompt_request(status, thread_id)
        if not isinstance(initial, dict):
            raise GateError("BLOCKED", "held_initial_synthetic_provider_request_unavailable")
        if not initial.get("initial_prompt_present"):
            raise GateError("BLOCKED", "synthetic_provider_request_missing_initial_prompt")
        if not initial.get("expected_model_present"):
            raise GateError("FAIL", "synthetic_provider_request_model_mismatch")
        if args.startup_diagnostic_only:
            result["status"] = "PASS_STARTUP_DIAGNOSTIC_ONLY"
            result["startup_diagnostic"] = "first_synthetic_provider_post_observed"
            result["provider_requests"] = [{"initial_prompt_present": initial.get("initial_prompt_present"),
                                             "expected_model_present": initial.get("expected_model_present"),
                                             "response_sent": initial.get("response_sent"),
                                             "body_sha256": initial.get("body_sha256")}]
            raise StartupDiagnosticComplete()
        if initial.get("response_sent") is not False:
            raise GateError("BLOCKED", "initial_synthetic_provider_request_not_held")
        result["native_thread_id"] = thread_id
        result["appserver_user_agent"] = status.get("appserver_user_agent")
        result["queue_command"] = ["docker", "exec", container_id, CODEX, "queue", "--remote", unix_uri,
                                   "--thread", thread_id, "--message", "<synthetic-redacted>"]
        resume = request_resume_snapshot(private_dir, 1, thread_id, min(deadline, time.monotonic() + 10))
        original_turn_id, original_turn_status = active_turn_from_resume(resume, thread_id)
        if initial.get("turn_id") != original_turn_id:
            raise GateError("BLOCKED", "held_provider_turn_does_not_match_active_turn_snapshot")
        result["original_active_turn_snapshot"] = {"thread_id": thread_id, "turn_id": original_turn_id,
                                                    "turn_status": original_turn_status,
                                                    "source": "thread/resume_response"}
        if not initial.get("initial_prompt_present") or initial.get("response_sent") is not False:
            raise GateError("BLOCKED", "synthetic_provider_did_not_hold_initial_turn")
        baseline = request_snapshot(private_dir, 1, thread_id, min(deadline, time.monotonic() + 10))
        if (baseline.get("queue_count") != 0 or not baseline.get("queue_terminal") or
                baseline.get("turn_completed_count") != 0 or baseline.get("turn_started_count", 0) > 1 or
                not held_turn_events_valid(baseline.get("turn_events", []), thread_id, original_turn_id)):
            raise GateError("BLOCKED", "initial_busy_turn_or_empty_queue_not_observed")
        result["busy_turn_baseline"] = {key: baseline.get(key) for key in
                                        ("turn_started_count", "turn_completed_count", "turn_events")}
        session.send(draft.encode())
        time.sleep(0.35)
        before_queue = read_json(status_path)
        before_requests = before_queue.get("provider_requests", [])
        if any(isinstance(request, dict) and request.get("thread_id") == thread_id and
               request.get("draft_prompt_present") for request in before_requests):
            raise GateError("FAIL", "unsent_draft_started_a_second_provider_request")
        queue_argv = ["docker", "exec", container_id, CODEX, "queue", "--remote", unix_uri,
                      "--thread", thread_id, "--message", queued]
        queued_result = run(queue_argv, timeout=min(20, max(1, int(deadline - time.monotonic()))))
        result["queue_exit_code"] = queued_result.returncode
        if queued_result.returncode != 0:
            raise GateError("BLOCKED", "official_queue_cli_failed")
        time.sleep(0.35)
        busy_snapshot = request_snapshot(private_dir, 2, thread_id, min(deadline, time.monotonic() + 10))
        busy_status = read_json(status_path)
        result["busy_snapshot"] = {key: busy_snapshot.get(key) for key in
                                    ("queue_count", "queue_terminal", "queue_prompt_present",
                                     "turn_started_count", "turn_completed_count", "turn_events")}
        if busy_snapshot.get("queue_count") != 1 or not busy_snapshot.get("queue_terminal") or not busy_snapshot.get("queue_prompt_present"):
            raise GateError("FAIL", "official_queue_submission_not_visible_exactly_once")
        if (busy_snapshot.get("turn_completed_count") != 0 or busy_snapshot.get("turn_started_count", 0) > 1 or
                not held_turn_events_valid(busy_snapshot.get("turn_events", []), thread_id, original_turn_id)):
            raise GateError("FAIL", "busy_original_turn_was_completed_or_superseded_before_release")
        if (held_initial_prompt_request(busy_status, thread_id) is None or
                any(isinstance(request, dict) and request.get("thread_id") == thread_id and
                    request.get("turn_id") != original_turn_id for
                    request in busy_status.get("provider_requests", []))):
            raise GateError("FAIL", "held_original_provider_turn_was_interrupted_before_release")
        control(private_dir, release_first=True)
        status, events = wait_for("queued_turn_completed", min(deadline, time.monotonic() + 35),
                                  lambda _s, e: bool(completed_queued_turn_id(e, thread_id, original_turn_id)),
                                  status_path, events_path)
        requests = status["provider_requests"]
        queued_turn_id = completed_queued_turn_id(events, thread_id, original_turn_id)
        if not queued_turn_id:
            raise GateError("BLOCKED", "queued_turn_lifecycle_not_proven_by_notifications")
        queued_requests = [request for request in requests if isinstance(request, dict) and
                           request.get("thread_id") == thread_id and request.get("turn_id") == queued_turn_id]
        if len(queued_requests) != 1:
            raise GateError("FAIL", "queued_synthetic_provider_request_not_unique")
        queued_request = queued_requests[0]
        if queued_request.get("draft_prompt_present") is not False:
            raise GateError("FAIL", "unsent_draft_leaked_into_queued_turn")
        if (not queued_request.get("expected_model_present") or queued_request.get("response_sent") is not True or
                not queued_request.get("queue_prompt_present")):
            raise GateError("FAIL", "queued_synthetic_provider_request_model_mismatch")
        result["queued_turn_id"] = queued_turn_id
        completed_snapshot = request_snapshot(private_dir, 3, thread_id, min(deadline, time.monotonic() + 10))
        if completed_snapshot.get("queue_count") != 0 or not completed_snapshot.get("queue_terminal"):
            raise GateError("BLOCKED", "queue_completion_not_observable")
        result["after_queue_turns"] = {key: completed_snapshot.get(key) for key in ("queue_count", "turn_started_count", "turn_completed_count")}
        session.send(suffix.encode())
        time.sleep(0.35)
        session.send(b"\r")
        status, events = wait_for("final_synthetic_turn_completed", min(deadline, time.monotonic() + 30),
                                  lambda _s, e: all(final_queued_and_draft_turn_ids(e, thread_id, original_turn_id)),
                                  status_path, events_path)
        queued_turn_id, draft_turn_id = final_queued_and_draft_turn_ids(events, thread_id, original_turn_id)
        if queued_turn_id != result.get("queued_turn_id") or not draft_turn_id:
            raise GateError("BLOCKED", "future_queued_or_draft_turn_notifications_unproven")
        draft_requests = [request for request in status["provider_requests"] if isinstance(request, dict) and
                          request.get("thread_id") == thread_id and request.get("turn_id") == draft_turn_id]
        if len(draft_requests) != 1:
            raise GateError("FAIL", "preserved_draft_provider_request_not_unique")
        final_request = draft_requests[0]
        result["draft_request_evidence"] = {"request_sha256": final_request.get("body_sha256"),
                                             "expected_model_present": final_request.get("expected_model_present") is True,
                                             "original_draft_plus_suffix_present": final_request.get("draft_with_suffix_present") is True}
        if not final_request.get("expected_model_present"):
            raise GateError("FAIL", "draft_synthetic_provider_request_model_mismatch")
        if not final_request.get("draft_prompt_present") or not final_request.get("draft_with_suffix_present"):
            raise GateError("FAIL", "original_unsent_draft_was_not_preserved_exactly")
        turn_events = thread_turn_events(events, thread_id)
        result["turn_event_order"] = [{"method": e["method"], "turn_id": e.get("turn_id", "")} for e in turn_events]
        if final_request.get("turn_id") != draft_turn_id:
            raise GateError("BLOCKED", "draft_provider_request_turn_id_mismatch")
        result["draft_turn_id"] = draft_turn_id
        result["provider_requests"] = [{"index": item.get("index"), "thread_id": item.get("thread_id"),
                                         "turn_id": item.get("turn_id"),
                                         "body_sha256": item.get("body_sha256"),
                                         "held_for_busy_gate": item.get("held_for_busy_gate"),
                                         "expected_model_present": item.get("expected_model_present"),
                                         "initial_prompt_present": item.get("initial_prompt_present"),
                                         "queue_prompt_present": item.get("queue_prompt_present"),
                                         "draft_prompt_present": item.get("draft_prompt_present"),
                                         "draft_with_suffix_present": item.get("draft_with_suffix_present"),
                                         "response_sent": item.get("response_sent")}
                                        for item in status.get("provider_requests", [])]
        methods = [item["method"] for item in turn_events]
        optional_original_start = (methods[:2] == ["turn/started", "turn/completed"] and
                                   turn_events[0].get("turn_id") == original_turn_id)
        if optional_original_start:
            future_methods = methods[2:]
        elif methods and methods[0] == "turn/completed" and turn_events[0].get("turn_id") == original_turn_id:
            future_methods = methods[1:]
        else:
            future_methods = []
        if future_methods != ["turn/started", "turn/completed", "turn/started", "turn/completed"]:
            raise GateError("BLOCKED", "turn_event_sequence_unexpected")
        completed_statuses = [event.get("turn_status", "") for event in turn_events if event["method"] == "turn/completed"]
        if completed_statuses != ["completed", "completed", "completed"]:
            raise GateError("BLOCKED", "synthetic_turn_completion_status_unproven")
        if optional_original_start and turn_events[0].get("turn_id") != turn_events[1].get("turn_id"):
            raise GateError("BLOCKED", "original_turn_id_event_mismatch")
        if turn_events[-4].get("turn_id") != turn_events[-3].get("turn_id") or \
                turn_events[-2].get("turn_id") != turn_events[-1].get("turn_id"):
            raise GateError("BLOCKED", "future_turn_id_event_pair_mismatch")
        if turn_events[-4].get("turn_id") != queued_turn_id or turn_events[-2].get("turn_id") != draft_turn_id:
            raise GateError("BLOCKED", "future_turn_id_order_mismatch")
        result["foreground_busy_queue"] = "PASS"
        result["human_ui_draft"] = "PASS"
        result["status"] = "PASS_ZERO_PAID_SYNTHETIC_RUNTIME_ONLY"
        result["native_turn_events_observed"] = len(turn_events)
        result["native_thread_id"] = thread_id
        result["container_attached_output_bytes"] = session.output_bytes
    except GateError as exc:
        result["status"] = exc.status
        result["reason"] = exc.reason
    except StartupDiagnosticComplete:
        pass
    except Exception as exc:
        result["status"] = "BLOCKED"
        result["reason"] = "harness_exception_" + type(exc).__name__
    finally:
        is_owned = False
        if container_id:
            try:
                is_owned = owned_container(container_id, run_id)
            except Exception:
                is_owned = False
        if container_id and is_owned:
            try:
                stop = run(["docker", "stop", "--time", "4", container_id], timeout=8)
                result["docker_stop_exit_code"] = stop.returncode
            except Exception:
                result["docker_stop_exit_code"] = None
            try:
                removed = run(["docker", "rm", "--force", container_id], timeout=8)
                result["docker_remove_exit_code"] = removed.returncode
            except Exception:
                result["docker_remove_exit_code"] = None
            try:
                result["owned_container_absent_after_cleanup"] = container_absent(container_id)
            except Exception:
                result["owned_container_absent_after_cleanup"] = False
        else:
            try:
                result["owned_container_absent_after_cleanup"] = container_id == "" or container_absent(container_id)
            except Exception:
                result["owned_container_absent_after_cleanup"] = container_id == ""
        if session:
            try:
                result["docker_start_attach_exit_code"] = session.close()
            except Exception:
                result["docker_start_attach_exit_code"] = None
        if private_dir:
            run_status = read_json(private_dir / "status.json")
            for key in ("runtime_cli_sha256", "runtime_cli_bytes", "runtime_cli_binary_ok",
                        "runtime_cli_version", "runtime_version_ok", "appserver_user_agent_version_ok"):
                if key in run_status:
                    result[key] = run_status[key]
            if isinstance(run_status.get("provider_requests"), list):
                result["provider_requests"] = sanitized_provider_requests(run_status)
            result["startup_diagnostics"] = startup_diagnostics(
                private_dir / "status.json", private_dir / "events.jsonl", session
            )
            trace_scope = "app" if args.trace_app_file_failures else "tui" if args.trace_tui_file_failures else ""
            if trace_scope:
                trace_key = trace_scope + "_file_syscall_trace"
                trace_summary = run_status.get(trace_key)
                if trace_scope == "tui" and isinstance(run_status.get("tui_tracer_invocation"), list):
                    result["tracer_invocation"] = run_status["tui_tracer_invocation"]
                result[trace_key] = trace_summary or {
                    "enabled": True, "collector_completed": False, "instrumentation_status": "BLOCKED_NO_TRACE_SUMMARY"
                }
                trace_path = private_dir / (trace_scope + "-file-syscalls.private.txt")
                if trace_path.is_file() and args.result:
                    destination = args.result.expanduser().resolve().with_name(trace_scope + "-file-syscalls.private.txt")
                    try:
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        trace_bytes = trace_path.read_bytes()[:MAX_FILE_TRACE_BYTES + MAX_FILE_TRACE_LINES]
                        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                        with os.fdopen(fd, "wb") as output:
                            output.write(trace_bytes)
                            output.flush()
                            os.fsync(output.fileno())
                        result[trace_key]["private_artifact"] = destination.name
                        result[trace_key]["private_artifact_sha256"] = hashlib.sha256(trace_bytes).hexdigest()
                        result[trace_key]["private_artifact_bytes"] = len(trace_bytes)
                    except OSError as exc:
                        result[trace_key]["private_artifact_error"] = type(exc).__name__
        try:
            result["private_terminal_tail"] = save_private_terminal_tail(args.result, session)
        except Exception as exc:
            result["private_terminal_tail"] = {"saved": False, "error_class": type(exc).__name__}
        if result["owned_container_absent_after_cleanup"] and private_dir:
            try:
                if private_dir.is_dir() and private_dir.name.startswith("cicada-native-foreground-queue-"):
                    shutil.rmtree(private_dir)
                result["private_directory_removed"] = not private_dir.exists()
            except Exception:
                result["private_directory_removed"] = False
        else:
            result["private_directory_removed"] = private_dir is None
        if tracer_base:
            if result["owned_container_absent_after_cleanup"]:
                try:
                    if tracer_base.is_dir() and tracer_base.name.startswith("cicada-native-foreground-tracer-"):
                        shutil.rmtree(tracer_base)
                    result["tracer_directory_removed"] = not tracer_base.exists()
                except OSError:
                    result["tracer_directory_removed"] = False
            else:
                result["tracer_directory_removed"] = False
        if not result["owned_container_absent_after_cleanup"] or not result["private_directory_removed"]:
            result["status"] = "BLOCKED"
            result["cleanup_issue"] = "owned_resource_cleanup_unconfirmed"
            if not result.get("reason"):
                result["reason"] = result["cleanup_issue"]
        if not result.get("tracer_directory_removed", True):
            result["status"] = "BLOCKED"
            result["cleanup_issue"] = "owned_tracer_directory_cleanup_unconfirmed"
            if not result.get("reason"):
                result["reason"] = result["cleanup_issue"]
        result["duration_seconds"] = round(time.time() - started_at, 3)
        result["finish_unix_seconds"] = int(time.time())
        try:
            write_result(args.result, result)
        except Exception:
            result["result_write_error"] = True
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"].startswith("PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
