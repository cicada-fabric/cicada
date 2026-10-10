#!/usr/bin/env python3
"""Exact owned Docker fixture closeout; never remove resources by guessed name."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

DEADLINE = None

LABEL = 'org.cicada.test.run'
ROLE_LABEL = 'org.cicada.test.role'
ID = re.compile(r'(?:sha256:)?[0-9a-f]{64}\Z')


def command(argv):
    try:
        return subprocess.run(argv, text=True, capture_output=True, timeout=max(0.01, min(10, DEADLINE - time.monotonic())) if DEADLINE is not None else 10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(argv, 125, '', '')


def inspect(kind, selector, call=command):
    template = '{{.Id}}' if kind == 'image' else '{{.Id}}|{{.Name}}|{{.Image}}|{{index .Config.Labels "' + LABEL + '"}}|{{index .Config.Labels "' + ROLE_LABEL + '"}}'
    reply = call(['docker', kind, 'inspect', selector, '--format', template])
    missing = {f'{prefix}: No such {kind}: {selector}' for prefix in ('Error', 'error', 'Error response from daemon', 'error response from daemon')}
    if len(reply.stderr) <= 512 and reply.returncode == 1 and reply.stdout.strip() in ('', '[]') and reply.stderr.strip() in missing:
        return 'EXACT_ABSENT', None
    if reply.returncode != 0 or len(reply.stdout) > 512:
        return 'UNKNOWN', None
    fields = reply.stdout.strip().split('|')
    if kind == 'image' and len(fields) == 1 and ID.fullmatch(fields[0]):
        return 'PRESENT', fields
    if kind == 'container' and len(fields) == 5 and re.fullmatch('[0-9a-f]{64}', fields[0]) and ID.fullmatch(fields[2]):
        return 'PRESENT', fields
    return 'UNKNOWN', None


class PreflightFailure(ValueError):
    def __init__(self, code, plan):
        super().__init__(code)
        self.plan = plan


def prepare(scratch, run_id, lane, containers, images, call=command):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,191}', run_id or '') or lane not in {'client', 'network-m1', 'group-spaces-m2', 'capacity', 'multi-hub-services', 'node-control-v1'} or len(containers) + len(images) > 4:
        raise ValueError('CLEANUP_SCOPE')
    root = Path(scratch)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('SCRATCH_IDENTITY')
    resources = []
    for role, name, image in containers:
        state, _ = inspect('container', name, call)
        resources.append(dict(role=role, kind='container', name_or_ref=name, pre_creation=state, expected_image_id=image,
                              cidfile=str(root / (role + '.cid')), labels_intended={LABEL: run_id, ROLE_LABEL: role}))
    for role, ref in images:
        state, _ = inspect('image', ref, call)
        resources.append(dict(role=role, kind='image', name_or_ref=ref, pre_creation=state, labels_intended={}))
    plan = dict(schema='cicada.child-cleanup.v1', run_id=run_id, lane=lane, resources=resources,
                creation_authorized=all(row['pre_creation'] == 'EXACT_ABSENT' for row in resources),
                scratch=dict(role='private-scratch', creation_proof='MKDTEMP_INODE', path=str(root.resolve()), device=info.st_dev, inode=info.st_ino, uid=info.st_uid))
    for row in resources:
        if row['pre_creation'] != 'EXACT_ABSENT':
            raise PreflightFailure('CONTAINER_NAME_NOT_ABSENT' if row['kind'] == 'container' else 'IMAGE_TAG_NOT_ABSENT', plan)
    return plan


def cleanup(plan, build=None, call=command):
    global DEADLINE
    if call is command:
        DEADLINE = time.monotonic() + 30
    rows = []
    for resource in plan['resources']:
        row = {key: resource[key] for key in ('role', 'kind', 'name_or_ref', 'pre_creation', 'labels_intended')}
        row.update(labels_observed={}, expected_image_id=None, id=None, creation_proof='UNKNOWN', ownership='UNKNOWN', post_cleanup='UNKNOWN')
        kind, selector = row['kind'], row['name_or_ref']
        if not plan['creation_authorized']:
            row['post_cleanup'], _ = inspect(kind, selector, call)
            rows.append(row)
            continue
        expected = resource.get('expected_image_id')
        if build is not None:
            metadata = build.get('image' if row['role'] in ('hub', 'hub-image') else 'test_image', {})
            expected = metadata.get('id')
        expected = expected if isinstance(expected, str) and ID.fullmatch(expected) else None
        row['expected_image_id'] = expected
        if kind == 'container':
            path = Path(resource['cidfile'])
            try:
                info = path.lstat()
                cid = path.read_text().strip() if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= 65 else ''
            except OSError:
                cid = ''
            if not re.fullmatch('[0-9a-f]{64}', cid):
                if path.exists() or path.is_symlink():
                    rows.append(row)
                    continue
                state, _ = inspect(kind, selector, call)
                if state == 'EXACT_ABSENT':
                    row.update(creation_proof='NOT_CREATED', ownership='NOT_CREATED', post_cleanup=state)
                elif state == 'PRESENT':
                    row['post_cleanup'] = 'PRESENT'
                rows.append(row)
                continue
            row.update(id=cid, creation_proof='CIDFILE')
            state, fields = inspect(kind, cid, call)
            if state == 'PRESENT':
                if fields != [cid, '/' + selector, expected, plan['run_id'], row['role']]:
                    row.update(ownership='MISMATCH', post_cleanup='PRESENT')
                    rows.append(row)
                    continue
                row['labels_observed'] = {LABEL: fields[3], ROLE_LABEL: fields[4]}
                row['ownership'] = 'VERIFIED'
                call(['docker', 'rm', '-f', cid])
            elif state == 'EXACT_ABSENT':
                row['ownership'] = 'UNKNOWN'
            else:
                rows.append(row)
                continue
            cid_state, _ = inspect(kind, cid, call)
            name_state, _ = inspect(kind, selector, call)
            row['post_cleanup'] = 'EXACT_ABSENT' if cid_state == name_state == 'EXACT_ABSENT' else ('PRESENT' if 'PRESENT' in (cid_state, name_state) else 'UNKNOWN')
        else:
            state, fields = inspect(kind, selector, call)
            if state == 'EXACT_ABSENT':
                row.update(creation_proof='NOT_CREATED' if not expected else 'FRESH_TAG', ownership='NOT_CREATED' if not expected else 'VERIFIED', id=expected, post_cleanup=state)
            elif state == 'PRESENT' and expected and fields == [expected]:
                row.update(id=expected, creation_proof='FRESH_TAG', ownership='VERIFIED')
                call(['docker', 'image', 'rm', selector])
                row['post_cleanup'], _ = inspect(kind, selector, call)
            elif state == 'PRESENT':
                row.update(ownership='MISMATCH', post_cleanup='PRESENT')
        rows.append(row)
    scratch = plan['scratch']
    root = Path(scratch['path'])
    scratch_state = 'UNKNOWN'
    scratch_ownership = 'UNKNOWN'
    try:
        info = root.lstat()
        if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and (info.st_dev, info.st_ino, info.st_uid) == (scratch['device'], scratch['inode'], scratch['uid']) and scratch['uid'] == os.getuid():
            scratch_ownership = 'VERIFIED'
            # Do not remove mounted fixture state while a container is unresolved.
            if not plan['creation_authorized'] or all(row['post_cleanup'] == 'EXACT_ABSENT' for row in rows):
                shutil.rmtree(root)
        else:
            scratch_ownership = 'MISMATCH'
        try:
            root.lstat()
            scratch_state = 'PRESENT'
        except FileNotFoundError:
            scratch_state = 'EXACT_ABSENT'
    except FileNotFoundError:
        scratch_state = 'EXACT_ABSENT'
        scratch_ownership = 'VERIFIED' if scratch['uid'] == os.getuid() else 'UNKNOWN'
    except OSError:
        try:
            root.lstat()
            scratch_state = 'PRESENT'
        except FileNotFoundError:
            scratch_state = 'EXACT_ABSENT'
        except OSError:
            pass
    states = [row['post_cleanup'] for row in rows] + [scratch_state]
    exact_absence = all(value == 'EXACT_ABSENT' for value in states)
    ownership = scratch_ownership == 'VERIFIED' and all(row['ownership'] in ('VERIFIED', 'NOT_CREATED') for row in rows)
    remaining_owned = any(row['ownership'] == 'VERIFIED' and row['post_cleanup'] == 'PRESENT' for row in rows)
    remaining_scratch = scratch_ownership == 'VERIFIED' and all(row['post_cleanup'] == 'EXACT_ABSENT' for row in rows) and scratch_state == 'PRESENT'
    status = 'CONFIRMED' if exact_absence and ownership else ('FAILED' if remaining_owned or remaining_scratch else 'UNKNOWN')
    return dict(schema=plan['schema'], run_id=plan['run_id'], lane=plan['lane'], status=status,
                resources=rows, scratch=dict(role=scratch['role'], creation_proof=scratch['creation_proof'], ownership=scratch_ownership, device=scratch['device'], inode=scratch['inode'], uid=scratch['uid'], path=scratch['path'], post_cleanup=scratch_state))


def write(path, value):
    target = Path(path)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    target.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'cleanup'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--output')
    parser.add_argument('--scratch')
    parser.add_argument('--run-id')
    parser.add_argument('--lane')
    parser.add_argument('--container', nargs=3, action='append', default=[])
    parser.add_argument('--image', nargs=2, action='append', default=[])
    parser.add_argument('--build-metadata')
    args = parser.parse_args()
    if args.operation == 'prepare':
        try:
            plan = prepare(args.scratch, args.run_id, args.lane, args.container, args.image)
        except PreflightFailure as error:
            write(args.plan, error.plan)
            return 2
        write(args.plan, plan)
        return 0
    build = None
    if args.build_metadata and Path(args.build_metadata).is_file():
        build = json.loads(Path(args.build_metadata).read_text())
    result = cleanup(json.loads(Path(args.plan).read_text()), build)
    write(args.output, result)
    return 0 if result['status'] == 'CONFIRMED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
