#!/usr/bin/env python3
"""Absolute deadlines and an owned-process runner for immutable selectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
from typing import Any, NamedTuple, Sequence


_MAX_ARGV_COUNT = 256
_MAX_ARG_BYTES = 64 * 1024
_MAX_STDIN_BYTES = 1024 * 1024
_MAX_LOG_BYTES = 1024 * 1024
_READ_BYTES = 64 * 1024
_TERM_GRACE_SECONDS = 0.5
_CLEANUP_SECONDS = 2.0
_SAFE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SHELL_NAMES = {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh",
                "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TMP", "TEMP", "JAVA_HOME")


class RunnerError(RuntimeError):
    """A redacted process-runner error."""


@dataclass(frozen=True)
class Deadline:
    """An absolute cutoff on Python's monotonic clock."""

    _expires_at: float

    def __post_init__(self) -> None:
        if isinstance(self._expires_at, bool) or not isinstance(self._expires_at, (int, float)) or \
                not math.isfinite(self._expires_at):
            raise ValueError("absolute deadline is invalid")

    @classmethod
    def after(cls, seconds: float, parent: "Deadline | None" = None) -> "Deadline":
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("deadline duration is invalid")
        seconds = float(seconds)
        if not math.isfinite(seconds) or seconds < 0 or (parent is not None and not isinstance(parent, cls)):
            raise ValueError("deadline duration is invalid")
        expiry = time.monotonic() + seconds
        return cls(min(expiry, parent._expires_at) if parent else expiry)

    def remaining(self) -> float:
        return max(0.0, self._expires_at - time.monotonic())

    def clamp(self, seconds: float) -> float:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or \
                not math.isfinite(seconds) or seconds < 0:
            raise ValueError("duration clamp is invalid")
        return min(float(seconds), self.remaining())


@dataclass(frozen=True)
class RunReceipt:
    label: str
    exit_code: int
    status: str
    stdout_path: str
    stdout_sha256: str
    stderr_path: str
    stderr_sha256: str
    ownership_journal_path: str | None
    stdout_stream_sha256: str
    stderr_stream_sha256: str
    command_sha256: str
    started: bool
    started_pid: int | None
    started_pgid: int | None
    started_at_monotonic: float | None
    elapsed_seconds: float
    timed_out: bool
    failure: str | None
    stdout_bytes: int
    stderr_bytes: int
    stdout_saved_bytes: int
    stderr_saved_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_reader_ok: bool
    stderr_reader_ok: bool
    group_ownership_verified: bool
    process_group_closed: bool
    term_sent: bool
    kill_sent: bool
    process_reaped: bool

    def as_dict(self, *, include_private_paths: bool = False) -> dict[str, Any]:
        """Return redacted metadata; argv, stdin, and captured output are omitted."""
        value = asdict(self)
        if not include_private_paths:
            for key in ("stdout_path", "stderr_path", "ownership_journal_path"):
                value.pop(key)
        return value


class _CaptureResult(NamedTuple):
    stream_sha256: str
    saved_sha256: str
    total_bytes: int
    saved_bytes: int
    truncated: bool
    ok: bool


class _GroupToken(NamedTuple):
    pid: int
    pgid: int
    leader_start_ticks: int | None


class _GroupSnapshot(NamedTuple):
    available: bool
    present: bool
    owned: bool
    active: bool


def _command_digest(argv: Sequence[str]) -> str:
    raw = json.dumps(list(argv), ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple)) or not argv or \
            len(argv) > _MAX_ARGV_COUNT:
        raise RunnerError("explicit argv is required")
    args: list[str] = []
    total = 0
    for arg in argv:
        if not isinstance(arg, str) or "\0" in arg:
            raise RunnerError("argv is invalid")
        try:
            total += len(arg.encode("utf-8", errors="strict"))
        except UnicodeError:
            raise RunnerError("argv is invalid") from None
        if total > _MAX_ARG_BYTES:
            raise RunnerError("argv exceeds the supported bound")
        args.append(arg)
    if not args[0] or any(Path(arg).name.lower() in _SHELL_NAMES for arg in args):
        raise RunnerError("shell executables are not accepted")
    return tuple(args)


def _child_environment() -> dict[str, str]:
    env = {key: os.environ[key] for key in _ENV_KEYS
           if key in os.environ and "\0" not in os.environ[key]}
    env.setdefault("PATH", os.defpath or "/usr/bin:/bin")
    env.update(PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
    return env


def _private_dir(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute():
            raise RunnerError("private output directory must be absolute")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RunnerError("private output directory is not private")
        return path
    except RunnerError:
        raise
    except Exception:
        raise RunnerError("private output directory is unavailable") from None


def _new_file(path: Path, prefix: str, suffix: str) -> tuple[str, int]:
    fd: int | None = None
    name: str | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=path)
        os.fchmod(fd, 0o600)
        return name, fd
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if name:
            try:
                os.unlink(name)
            except OSError:
                pass
        raise RunnerError("private file creation failed") from None


def _write_all(fd: int, data: bytes) -> None:
    pos = 0
    while pos < len(data):
        count = os.write(fd, data[pos:])
        if count <= 0:
            raise OSError("short private file write")
        pos += count


def _write_journal(fd: int, event: str, token: _GroupToken, command_sha256: str,
                   finish: dict[str, Any] | None = None) -> None:
    if event not in ("start", "finish"):
        raise ValueError("invalid journal event")
    record = {"event": event, "pid": token.pid, "pgid": token.pgid,
              "leader_start_ticks": token.leader_start_ticks, "command_sha256": command_sha256}
    if event == "finish":
        if finish is None:
            raise ValueError("finish evidence is required")
        record.update(finish)
    elif finish is not None:
        raise ValueError("start record cannot contain finish evidence")
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
    _write_all(fd, (line + "\n").encode("ascii"))
    os.fsync(fd)


class _Capture:
    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.stream_hash = hashlib.sha256()
        self.total = 0
        self.tail = bytearray()
        self.ok = True

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        self.stream_hash.update(data)
        self.tail.extend(data)
        if len(self.tail) > _MAX_LOG_BYTES:
            del self.tail[:-_MAX_LOG_BYTES]

    def finish(self) -> _CaptureResult:
        digest = hashlib.sha256()
        saved = 0
        try:
            _write_all(self.fd, self.tail)
        except OSError:
            self.ok = False
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            while data := os.read(self.fd, _READ_BYTES):
                digest.update(data)
                saved += len(data)
        except OSError:
            self.ok = False
        try:
            os.close(self.fd)
        except OSError:
            self.ok = False
        return _CaptureResult(self.stream_hash.hexdigest(), digest.hexdigest(), self.total, saved,
                              self.total > saved, self.ok)


def _proc_stat(raw: str) -> tuple[str, int, int, int] | None:
    close = raw.rfind(")")
    if close < 0:
        return None
    fields = raw[close + 1:].split()
    try:
        return fields[0], int(fields[2]), int(fields[3]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _effective_uid(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[2])
    except (OSError, UnicodeError, IndexError, ValueError):
        pass
    return None


def _leader_start_ticks(pid: int) -> int | None:
    try:
        parsed = _proc_stat(Path(f"/proc/{pid}/stat").read_text(encoding="ascii"))
    except (OSError, UnicodeError):
        return None
    if parsed and parsed[1] == pid and parsed[2] == pid:
        return parsed[3]
    return None


def _group_snapshot(token: _GroupToken) -> _GroupSnapshot:
    root = Path("/proc")
    if not root.is_dir():
        return _GroupSnapshot(False, False, False, False)
    found, owned = False, True
    active = False
    try:
        entries = tuple(root.iterdir())
    except OSError:
        return _GroupSnapshot(False, False, False, False)
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            parsed = _proc_stat((entry / "stat").read_text(encoding="ascii"))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return _GroupSnapshot(False, False, False, False)
        if parsed is None:
            continue
        state, pgrp, session, start_ticks = parsed
        if pgrp != token.pgid:
            continue
        pid = int(entry.name)
        found = True
        if session != token.pgid or _effective_uid(pid) != os.geteuid():
            owned = False
        if pid == token.pid and (token.leader_start_ticks is None or start_ticks != token.leader_start_ticks):
            owned = False
        active |= state != "Z"
    return _GroupSnapshot(True, found, found and owned, active)


def _signal_owned_group(token: _GroupToken, signum: int) -> tuple[bool, bool]:
    snap = _group_snapshot(token)
    if not snap.available:
        return False, False
    if not snap.present:
        return False, True
    if not snap.owned:
        return False, False
    try:
        os.killpg(token.pgid, signum)
        return True, True
    except ProcessLookupError:
        return False, True
    except OSError:
        return False, False


def _cleanup_group(token: _GroupToken, proc: subprocess.Popen[bytes], deadline: Deadline
                   ) -> tuple[bool, bool, bool, bool]:
    """Close only the verified session, with TERM then KILL inside deadline."""
    term_sent = kill_sent = verified = False
    snap = _group_snapshot(token)
    if snap.available and not snap.present:
        return True, False, False, False
    if not snap.available or not snap.owned:
        return False, False, False, False
    verified = True

    def wait(until: float | None) -> int:
        """Return 1 when absent, -1 when unowned/unverifiable, else 0 at cutoff."""
        while deadline.remaining() > 0 and (until is None or time.monotonic() < until):
            proc.poll()
            current = _group_snapshot(token)
            if current.available and not current.present:
                return 1
            if not current.available or not current.owned:
                return -1
            delay = min(0.025, deadline.remaining())
            if until is not None:
                delay = min(delay, max(0.0, until - time.monotonic()))
            time.sleep(delay)
        return 0

    # Zombies cannot be signaled; wait only for their reaper.
    if not snap.active:
        result = wait(None)
        return result == 1, verified and result >= 0, False, False

    sent, safe = _signal_owned_group(token, signal.SIGTERM)
    term_sent, verified = sent, verified and safe
    result = wait(time.monotonic() + deadline.clamp(_TERM_GRACE_SECONDS))
    if result:
        return result == 1, verified and result == 1, term_sent, kill_sent
    snap = _group_snapshot(token)
    if snap.available and not snap.present:
        return True, verified, term_sent, kill_sent
    if not snap.available or not snap.owned or deadline.remaining() <= 0:
        return False, False, term_sent, kill_sent
    if not snap.active:
        result = wait(None)
        if result:
            return result == 1, verified and result == 1, term_sent, kill_sent
        snap = _group_snapshot(token)
        closed = snap.available and not snap.present
        return closed, verified and (closed or snap.owned), term_sent, kill_sent
    sent, safe = _signal_owned_group(token, signal.SIGKILL)
    kill_sent, verified = sent, verified and safe
    result = wait(None)
    if result:
        return result == 1, verified and result == 1, term_sent, kill_sent
    snap = _group_snapshot(token)
    closed = snap.available and not snap.present
    return closed, verified and (closed or snap.owned), term_sent, kill_sent


def _empty_capture() -> _CaptureResult:
    empty = hashlib.sha256(b"").hexdigest()
    return _CaptureResult(empty, empty, 0, 0, False, True)


def _receipt(label: str, call_started: float, command_sha256: str, stdout_path: str, stderr_path: str,
             journal_path: str | None, *, exit_code: int = 124, status: str = "UNKNOWN",
             stdout: _CaptureResult | None = None, stderr: _CaptureResult | None = None,
             started: bool = False, pid: int | None = None, started_at: float | None = None,
             timed_out: bool = False, failure: str | None = None, ownership_verified: bool = False,
             group_closed: bool = True, term_sent: bool = False, kill_sent: bool = False,
             reaped: bool = False) -> RunReceipt:
    stdout = stdout or _empty_capture()
    stderr = stderr or _empty_capture()
    return RunReceipt(
        label, exit_code, status, stdout_path, stdout.saved_sha256, stderr_path, stderr.saved_sha256,
        journal_path, stdout.stream_sha256, stderr.stream_sha256, command_sha256, started, pid, pid,
        started_at, max(0.0, time.monotonic() - call_started), timed_out, failure,
        stdout.total_bytes, stderr.total_bytes, stdout.saved_bytes, stderr.saved_bytes,
        stdout.truncated, stderr.truncated, stdout.ok, stderr.ok, ownership_verified,
        group_closed, term_sent, kill_sent, reaped)


class OwnedProcessRunner:
    """Run one explicit argv in a new session and retain bounded private logs."""

    def run(self, argv: Sequence[str], deadline: Deadline,
            private_output_dir: str | os.PathLike[str], label: str,
            stdin: bytes | bytearray | memoryview | None = None, *,
            cleanup_deadline: Deadline | None = None) -> RunReceipt:
        if not isinstance(deadline, Deadline) or (cleanup_deadline is not None and
                not isinstance(cleanup_deadline, Deadline)):
            raise RunnerError("deadline argument is invalid")
        if not isinstance(label, str) or not _SAFE_LABEL.fullmatch(label):
            raise RunnerError("safe log label is required")
        if stdin is not None and not isinstance(stdin, (bytes, bytearray, memoryview)):
            raise RunnerError("stdin must be bytes or omitted")
        if stdin is not None and memoryview(stdin).nbytes > _MAX_STDIN_BYTES:
            raise RunnerError("stdin exceeds the supported bound")
        try:
            input_bytes = None if stdin is None else bytes(stdin)
        except Exception:
            raise RunnerError("stdin could not be prepared") from None
        command = _validate_argv(argv)
        command_sha256 = _command_digest(command)
        call_started = time.monotonic()
        output_dir = _private_dir(private_output_dir)
        stdout_path, stdout_fd = _new_file(output_dir, f"{label}-", ".stdout.log")
        try:
            stderr_path, stderr_fd = _new_file(output_dir, f"{label}-", ".stderr.log")
        except Exception:
            os.close(stdout_fd)
            try:
                os.unlink(stdout_path)
            except OSError:
                pass
            raise

        def not_started(failure: str, *, timed_out: bool = False,
                        selector: Any = None, journal: tuple[str, int] | None = None) -> RunReceipt:
            if selector is not None:
                selector.close()
            os.close(stdout_fd)
            os.close(stderr_fd)
            if journal is not None:
                path, fd = journal
                os.close(fd)
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return _receipt(label, call_started, command_sha256, stdout_path, stderr_path, None,
                            failure=failure, timed_out=timed_out)

        if deadline.remaining() <= 0:
            return not_started("deadline_expired_before_start", timed_out=True)
        try:
            selector = selectors.DefaultSelector()
        except Exception:
            return not_started("runner_setup_failed")
        try:
            journal_path, journal_fd = _new_file(output_dir, "ownership-", ".jsonl")
        except Exception:
            return not_started("ownership_journal_failed", selector=selector)
        if deadline.remaining() <= 0:
            return not_started("deadline_expired_before_start", timed_out=True, selector=selector,
                               journal=(journal_path, journal_fd))
        try:
            proc = subprocess.Popen(
                command, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True,
                start_new_session=True, bufsize=0, env=_child_environment())
        except Exception:
            return not_started("spawn_failed", selector=selector, journal=(journal_path, journal_fd))

        started_at = time.monotonic()
        token = _GroupToken(proc.pid, proc.pid, _leader_start_ticks(proc.pid))
        try:
            _write_journal(journal_fd, "start", token, command_sha256)
            journal_ok = True
        except OSError:
            journal_ok = False
        stdout_capture, stderr_capture = _Capture(stdout_fd), _Capture(stderr_fd)
        captures = {proc.stdout: stdout_capture, proc.stderr: stderr_capture}
        stdin_stream = proc.stdin
        stdin_open = input_bytes is not None and stdin_stream is not None
        input_offset = 0
        stdin_ok = True
        failure = None if journal_ok else "ownership_journal_failed"
        timed_out = False
        term_sent = kill_sent = False
        # Popen(start_new_session=True) creates this new group for this runner.
        ownership_verified = True
        group_closed = False
        needs_cleanup = not journal_ok
        exit_code: int | None = None

        def close_stream(stream: Any) -> None:
            try:
                selector.unregister(stream)
            except Exception:
                pass
            try:
                stream.close()
            except Exception:
                pass

        def pump(timeout: float) -> None:
            nonlocal input_offset, stdin_open, stdin_ok, failure
            try:
                events = selector.select(timeout)
            except Exception:
                failure = failure or "runner_failure"
                return
            for key, _ in events:
                kind, stream = key.data
                if kind == "read":
                    try:
                        data = os.read(stream.fileno(), _READ_BYTES)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except (OSError, ValueError):
                        captures[stream].ok = False
                        failure = failure or "output_capture_failed"
                        close_stream(stream)
                        captures.pop(stream, None)
                        continue
                    if data:
                        captures[stream].feed(data)
                    else:
                        close_stream(stream)
                        captures.pop(stream, None)
                else:
                    try:
                        end = min(len(input_bytes or b""), input_offset + _READ_BYTES)
                        count = os.write(stream.fileno(), (input_bytes or b"")[input_offset:end])
                    except (BlockingIOError, InterruptedError):
                        continue
                    except (BrokenPipeError, OSError, ValueError):
                        stdin_ok = stdin_open = False
                        failure = failure or "stdin_delivery_incomplete"
                        close_stream(stream)
                        continue
                    if count <= 0:
                        stdin_ok = False
                        stdin_open = False
                        failure = failure or "stdin_delivery_incomplete"
                        close_stream(stream)
                        continue
                    input_offset += count
                    if input_offset >= len(input_bytes or b""):
                        stdin_open = False
                        close_stream(stream)

        try:
            for stream in captures:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, ("read", stream))
            if stdin_open and stdin_stream is not None:
                if not input_bytes:
                    stdin_open = False
                    close_stream(stdin_stream)
                else:
                    os.set_blocking(stdin_stream.fileno(), False)
                    selector.register(stdin_stream, selectors.EVENT_WRITE, ("write", stdin_stream))
        except Exception:
            needs_cleanup = True
            failure = failure or "runner_failure"

        try:
            while not needs_cleanup:
                polled = proc.poll()
                if polled is not None:
                    exit_code = polled
                    snap = _group_snapshot(token)
                    if snap.available and not snap.present and not captures:
                        group_closed = True
                        break
                    if snap.present:
                        needs_cleanup, failure = True, "process_group_leaked"
                        break
                    if not snap.available:
                        needs_cleanup, failure = True, "process_group_verification_unavailable"
                        break
                if failure:
                    needs_cleanup = True
                    break
                remaining = deadline.remaining()
                if remaining <= 0:
                    timed_out, needs_cleanup, failure = True, True, "deadline_expired"
                    break
                pump(min(0.05, remaining))
        except Exception:
            needs_cleanup = True
            failure = failure or "runner_failure"

        if needs_cleanup:
            local_cleanup = Deadline.after(_CLEANUP_SECONDS, parent=cleanup_deadline)
            group_closed, ownership_verified, term_sent, kill_sent = _cleanup_group(token, proc, local_cleanup)
            while local_cleanup.remaining() > 0 and captures:
                if proc.poll() is not None:
                    exit_code = proc.returncode
                pump(min(0.025, local_cleanup.remaining()))

        for stream in tuple(captures):
            captures[stream].ok = False
            close_stream(stream)
            captures.pop(stream, None)
        if stdin_open and stdin_stream is not None:
            stdin_ok = False
            close_stream(stdin_stream)
        try:
            selector.close()
        except Exception:
            failure = failure or "runner_failure"
        stdout = stdout_capture.finish()
        stderr = stderr_capture.finish()
        if not stdin_ok:
            failure = failure or "stdin_delivery_incomplete"
        if not stdout.ok or not stderr.ok:
            failure = failure or "output_capture_failed"

        try:
            exit_code = proc.poll()
            reaped = exit_code is not None
        except Exception:
            reaped = False
        final = _group_snapshot(token)
        group_closed = final.available and not final.present
        ownership_verified = ownership_verified or final.owned
        if not group_closed:
            failure = failure or "process_group_not_closed"
        if not reaped:
            failure = failure or "leader_not_reaped"

        if timed_out or failure:
            result_code, status = 124, "UNKNOWN"
        elif exit_code == 0:
            result_code, status = 0, "SUCCESS"
        elif exit_code == 124:
            result_code, status, failure = 124, "UNKNOWN", "child_exit_124"
        else:
            result_code, status = int(exit_code if exit_code is not None else 124), "FAILED"
        try:
            _write_journal(journal_fd, "finish", token, command_sha256, {
                "process_group_closed": group_closed,
                "process_reaped": reaped,
                "result": status,
                "exit_code": result_code,
                "term_sent": term_sent,
                "kill_sent": kill_sent,
            })
        except Exception:
            failure = failure or "ownership_journal_failed"
            result_code, status = 124, "UNKNOWN"
        finally:
            try:
                os.close(journal_fd)
            except OSError:
                pass
        return _receipt(
            label, call_started, command_sha256, stdout_path, stderr_path, journal_path,
            exit_code=result_code, status=status, stdout=stdout, stderr=stderr,
            started=True, pid=proc.pid, started_at=started_at, timed_out=timed_out,
            failure=failure, ownership_verified=ownership_verified, group_closed=group_closed,
            term_sent=term_sent, kill_sent=kill_sent, reaped=reaped)


__all__ = ["Deadline", "OwnedProcessRunner", "RunReceipt", "RunnerError"]
