#!/usr/bin/env python3
"""Capture one short real interactive CLI into a new private fixture file.

The JSON config names argv, capture_path and timeout_seconds. The caller owns
the config/capture directory and supplies the actual delivered pairing-code
command. No pairing-code format or protocol state is synthesized here. Only
exit/length/hash metadata goes to stdout; terminal contents remain private.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def capture(config):
    argv, target, seconds = config.get('argv'), config.get('capture_path'), config.get('timeout_seconds')
    if (not isinstance(argv, list) or not argv or any(not isinstance(a, str) or '\0' in a for a in argv)
            or not isinstance(target, str) or type(seconds) is not int or not 1 <= seconds <= 30):
        raise ValueError('Invalid private TTY fixture configuration')
    target = Path(target)
    parent = target.parent.stat()
    if not target.is_absolute() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError('Private TTY capture requires an owned private directory')
    master, slave = pty.openpty()
    raw, process = bytearray(), None
    expired, overflow = False, False
    try:
        if not all(os.isatty(fd) for fd in (master, slave)):
            raise ValueError('Real PTY unavailable')
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 25, 4096, 0, 0))

        def new_session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        process = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                   close_fds=True, preexec_fn=new_session)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                expired = True
                break
            if not select.select([master], [], [], min(remaining, 0.1))[0]:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break  # Linux PTY EOF after all slave references close.
                raise
            if not chunk:
                break
            if len(raw) + len(chunk) > 65536:
                overflow = True
                break
            raw.extend(chunk)
        if expired or overflow:
            process.kill()
        try:
            status = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            expired, status = True, 124
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        result = {'scope': 'OWNED_REAL_PTY_PRIVATE_CAPTURE_NOT_PHYSICAL_KEYBOARD',
                  'child_exit_code': status, 'timeout': expired, 'overflow': overflow,
                  'captured_bytes': len(raw), 'capture_sha256': hashlib.sha256(raw).hexdigest()}
        print(json.dumps(result, sort_keys=True))
        return 0 if status == 0 and not expired and not overflow else 1
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        os.close(master)
        if slave is not None:
            os.close(slave)
        raw[:] = b'\0' * len(raw)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise ValueError('Expected one private fixture config')
        config = json.loads(Path(sys.argv[1]).read_text())
        if not isinstance(config, dict):
            raise ValueError('Invalid private fixture config')
        code = capture(config)
    except Exception:
        # Never copy command arguments, PTY output or raw exception text.
        print('{"scope":"OWNED_REAL_PTY_PRIVATE_CAPTURE_NOT_PHYSICAL_KEYBOARD","fixture_error":true}')
        code = 1
    raise SystemExit(code)
