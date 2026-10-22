#!/usr/bin/env python3
"""Read-only OS boundary probe inside the exact owned acceptance container.

Run with docker exec --user 1001:1000, a bounded synthetic manifest on stdin,
and no additional capabilities. The trusted fixture must first verify that the
listed actual Node files/sockets exist. This probe never reads key bytes, sends
IPC requests or supplies context/signing evidence. Those separate assertions
remain NOT_RUN until the real domain lane connects them.
"""
import errno
import json
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import sys


def manifest():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError('manifest bound')
    value = json.loads(raw)
    if set(value) != {'synthetic', 'owner_uid', 'private_files', 'private_sockets'}:
        raise ValueError('manifest fields')
    if value['synthetic'] is not True or value['owner_uid'] != 1000:
        raise ValueError('fixture identity')
    labels, paths = set(), set()
    for kind in ('private_files', 'private_sockets'):
        rows = value[kind]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
            raise ValueError('probe count')
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'label', 'path'}:
                raise ValueError('probe fields')
            if not isinstance(row['label'], str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', row['label']):
                raise ValueError('public label')
            if not isinstance(row['path'], str) or len(row['path']) > 4096:
                raise ValueError('path bound')
            path = PurePosixPath(row['path'])
            private_runtime_socket = kind == 'private_sockets' and re.fullmatch(r'/tmp/cicada-j-1000/[0-9a-f]{64}\.sock', row['path'])
            if not path.is_absolute() or '..' in path.parts or not (path.is_relative_to('/state/tmp') or private_runtime_socket):
                raise ValueError('owned fixture path')
            if row['label'] in labels or row['path'] in paths:
                raise ValueError('duplicate probe')
            labels.add(row['label'])
            paths.add(row['path'])
    return value


def run(preflight=False):
    # Same group as the trusted writer is intentional. Do not silently test a
    # different process identity, a root process or a mode-helper simulation.
    uid = 1000 if preflight else 1001
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, 1000, 1000):
        raise ValueError('actual process identity')
    security = dict(line.split(':', 1) for line in open('/proc/self/status').read().splitlines() if ':' in line)
    if int(security['CapEff'].strip(), 16) != 0 or security['NoNewPrivs'].strip() != '1':
        raise ValueError('actual process isolation')
    spec = manifest()
    checks = []
    for kind in ('private_files', 'private_sockets'):
        for row in spec[kind]:
            observed = {'label': row['label'], 'operation': 'open_read_only' if kind == 'private_files' else 'connect_unix'}
            try:
                if preflight:
                    metadata = os.lstat(row['path'])
                    regular = stat.S_ISREG(metadata.st_mode) if kind == 'private_files' else stat.S_ISSOCK(metadata.st_mode)
                    if metadata.st_uid != 1000 or not regular:
                        raise ValueError('original Node target')
                    for parent in PurePosixPath(row['path']).parents:
                        if stat.S_ISLNK(os.lstat(parent).st_mode):
                            raise ValueError('substituted Node target')
                if kind == 'private_files':
                    descriptor = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    os.close(descriptor)  # Never read/export private bytes.
                else:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(2)
                        connection.connect(row['path'])  # Never send a packet.
                observed.update(permission_denied=False, owner_access_observed=preflight, unexpected_access=not preflight)
            except OSError as error:
                observed.update(permission_denied=error.errno in (errno.EACCES, errno.EPERM),
                                errno=error.errno)
            checks.append(observed)
    denied = all(row.get('owner_access_observed') if preflight else row['permission_denied'] for row in checks)
    print(json.dumps({'scope': 'ACTUAL_OWNER_NODE_ACCESS_PRECONDITION' if preflight else 'ACTUAL_OTHER_UID_OS_PRIVATE_FILE_AND_IPC_ACCESS_ONLY',
                      'status': ('OBSERVED_OWNER_ACCESS' if preflight else 'OBSERVED_DENIAL') if denied else 'FAIL',
                      'uid': os.getuid(), 'gid': os.getgid(), 'checks': checks,
                      'effective_capabilities_zero': True, 'no_new_privileges': True,
                      'key_bytes_read': False, 'IPC_payloads_sent': False,
                      'not_run': ['domain_context_proof', 'domain_signed_business_request',
                                  'same_UID_isolation', 'Windows_ACL']}, sort_keys=True))
    return 0 if denied else 1


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in ([], ['--preflight-owner']):
            raise ValueError('arguments')
        code = run(sys.argv[1:] == ['--preflight-owner'])
    except (ValueError, TypeError, KeyError):
        print(json.dumps({'scope': 'ACTUAL_OTHER_UID_OS_PRIVATE_FILE_AND_IPC_ACCESS_ONLY',
                          'status': 'NOT_RUN', 'reason': 'INVALID_PROCESS_IDENTITY_OR_MANIFEST'}))
        code = 2
    raise SystemExit(code)
