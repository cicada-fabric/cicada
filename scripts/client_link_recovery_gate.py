#!/usr/bin/env python3
"""Link-only Go JSON coordinator; shell owns build, containers and exact cleanup."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.request

SUITE = 'client-link-recovery'
TOP = 'TestClientDockerHubLinkFaultFixture'
PACKAGE = 'github.com/cicada-ai/cicada/cmd/client-recovery-fixture'
OPS = ('link.key_grant', 'link.review_policy_grant')
TESTS = {TOP} | {TOP + '/' + op + '/' + mode for op in OPS for mode in ('response-loss', 'processing', 'uncertain', 'legacy')}
MARKER = re.compile(r'\s*link_proxy_test\.go:[0-9]+: FAULT_READY ROOT_RESTART_REQUIRED operation=(link\.(?:key_grant|review_policy_grant)) request_sha256=([0-9a-f]{64})\s*\Z')
ID = re.compile(r'[0-9a-f]{64}\Z')
RAW_LIMIT = 16 * 1024 * 1024
COMMAND_LIMIT = 4 * 1024 * 1024
LIFECYCLE_LIMIT = 64
MOUNTINFO_LIMIT = 64 * 1024
GO_ARGS = ['test', '-json', '-p=1', '-mod=readonly', '-buildvcs=false', '-count=1', '-timeout=180s', './cmd/client-recovery-fixture', '-run', '^' + TOP + '$']


class GateFailure(ValueError):
    pass


def need(value, code):
    if not value:
        raise GateFailure(code)


def budget(end, cap):
    remaining = end - time.monotonic()
    need(remaining > 0, 'ABSOLUTE_DEADLINE')
    return min(cap, remaining)


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n')
    Path(path).chmod(0o600)


def call(argv, end, cap=3):
    deadline = time.monotonic() + budget(end, cap)
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'DOCKER_COMMAND')
                for key, _ in selector.select(timeout=min(remaining, 0.1)):
                    data = os.read(key.fd, min(65536, COMMAND_LIMIT - len(output) + 1))
                    need(len(output) + len(data) <= COMMAND_LIMIT, 'DOCKER_COMMAND')
                    if data:
                        output.extend(data)
                    else:
                        selector.unregister(key.fileobj)
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'DOCKER_COMMAND')
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise GateFailure('DOCKER_COMMAND') from None
            need(code == 0, 'DOCKER_COMMAND')
        return bytes(output)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)
        process.stdout.close()


def canonical(row):
    return {k: row[k] for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig')} | {'Mounts': sorted(row['Mounts'], key=lambda m: m['Destination'])}


def runner_canonical(row):
    # Docker changes this default from false to null on start. Resident
    # snapshots still hash canonical(row) with every original field intact.
    host = row['HostConfig']
    need('OomKillDisable' in host and (host['OomKillDisable'] is False or host['OomKillDisable'] is None), 'OWNED_OOM_KILL_DISABLE')
    return canonical(row) | {'HostConfig': dict(host, OomKillDisable=None)}


def runner_provenance(row):
    return {'canonical_sha256': hashlib.sha256(json.dumps(canonical(row), sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'oom_kill_disable': row['HostConfig']['OomKillDisable']}


def read_owned_mountinfo(pid):
    need(type(pid) is int and pid > 0, 'OWNED_PID')
    path = Path('/proc') / str(pid) / 'mountinfo'
    try:
        parent = path.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid(), 'OWNED_PID_OWNER')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
            info = os.fstat(source.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), 'OWNED_PID_OWNER')
            data = source.read(MOUNTINFO_LIMIT + 1)
    except OSError:
        raise GateFailure('OWNED_MOUNTINFO_UNREADABLE') from None
    need(len(data) <= MOUNTINFO_LIMIT, 'OWNED_MOUNTINFO_SIZE')
    return data


def kernel_tmpfs(data, role):
    need(len(data) <= MOUNTINFO_LIMIT, 'OWNED_MOUNTINFO_SIZE')
    try:
        lines = [line.split() for line in data.decode('ascii').splitlines()]
    except UnicodeDecodeError:
        raise GateFailure('OWNED_KERNEL_TMPFS') from None
    rows = [line for line in lines if len(line) > 4 and line[4] == '/tmp']
    need(len(rows) == 1, 'OWNED_KERNEL_TMPFS')
    row = rows[0]
    need(row.count('-') == 1 and row.index('-') >= 6 and len(row) == row.index('-') + 4, 'OWNED_KERNEL_TMPFS')
    split = row.index('-'); flags = set(row[5].split(',')); options = row[split + 3].split(',')
    size = 131072 if role == 'hub' else 786432
    need(row[split + 1:split + 3] == ['tmpfs', 'tmpfs'] and {'rw', 'nosuid', 'nodev'} <= flags and 'ro' not in flags and
         ('noexec' in flags) == (role == 'hub') and 'rw' in options and 'ro' not in options and
         [value for value in options if value.startswith('size=')] == ['size=' + str(size) + 'k'], 'OWNED_KERNEL_TMPFS')
    return {'fstype': 'tmpfs', 'rw': True, 'nosuid': True, 'nodev': True, 'noexec': role == 'hub', 'size_kib': size}


def snapshot(path, expected=None):
    end = time.monotonic() + 15
    baseline = json.loads(Path(expected).read_text()) if expected else None
    if baseline is not None:
        need(isinstance(baseline, list) and 0 <= len(baseline) <= 16 and all(
            isinstance(r, dict) and isinstance(r.get('Id'), str) and ID.fullmatch(r['Id'])
            for r in baseline), 'RESIDENT_IDS')
        ids = sorted(r['Id'] for r in baseline)
        need(len(ids) == len(set(ids)) and [r['Id'] for r in baseline] == ids, 'RESIDENT_IDS')
    else:
        ids = sorted(call(['docker', 'ps', '-q', '--no-trunc'], end).decode().split())
    need(len(ids) <= 16 and all(ID.fullmatch(x) for x in ids), 'RESIDENT_IDS')
    rows = json.loads(call(['docker', 'inspect', *ids], end)) if ids else []
    rows = sorted([canonical(r) | {'Running': r['State']['Running'], 'StartedAt': r['State']['StartedAt'], 'RestartCount': r['RestartCount']} for r in rows], key=lambda r: r['Id'])
    # Full inspect values exist only in memory. Evidence contains no Env or
    # arbitrary label text; hash the complete canonical row, not selected fields.
    evidence = [{'Id': r['Id'], 'Running': r['Running'], 'StartedAt': r['StartedAt'],
                 'RestartCount': r['RestartCount'], 'canonical_sha256':
                 hashlib.sha256(json.dumps(r, sort_keys=True, separators=(',', ':')).encode()).hexdigest()} for r in rows]
    save(path, evidence)
    need(all(r['Running'] for r in rows) and [r['Id'] for r in rows] == ids, 'RESIDENT_NOT_RUNNING')
    if expected:
        need(evidence == baseline, 'RESIDENT_CHANGED')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise GateFailure('REDIRECT_REFUSED')


class LinkGate:
    def __init__(self, config):
        self.c = config
        self.end = min(config['work_deadline'], time.monotonic() + 30)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        need(config['suite'] == SUITE and re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', config['origin']), 'LINK_SCOPE')
        need(1 <= int(config['origin'].rsplit(':', 1)[1]) <= 65535, 'LOOPBACK_PORT')
        self.build = json.loads(Path(config['build']).read_text())
        self.hub_id = None
        self.raw_bytes = 0
        self.kernel_verified = {}
        self.validating_role = None
        self.result = {'schema': 'cicada.client-link-recovery-gate.v1', 'suite_name': SUITE, 'status': 'UNKNOWN', 'tests': [], 'restarts': [], 'runner_exit_code': None}

    def capture(self, raw, data):
        total = self.raw_bytes + len(data)
        need(total <= RAW_LIMIT, 'GO_RAW_TOTAL_SIZE')
        raw.write(data); raw.flush()
        self.raw_bytes = total

    def security(self, row, role):
        host = row['HostConfig']
        need('OomKillDisable' in host and (host['OomKillDisable'] is False or host['OomKillDisable'] is None), 'OWNED_OOM_KILL_DISABLE')
        cpu, memory, pids, tmp = ((1_000_000_000, 268435456, 128, 'rw,noexec,nosuid,nodev,size=128m') if role == 'hub'
                                  else (2_000_000_000, 3221225472, 256, 'rw,exec,nosuid,nodev,size=768m,mode=1777'))
        need(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False and host.get('CapDrop') == ['ALL'] and
             host.get('CapAdd') in (None, []) and host.get('SecurityOpt') == ['no-new-privileges'], 'OWNED_SECURITY')
        need(host.get('NanoCpus') == cpu and host.get('Memory') == memory and host.get('MemorySwap') == memory and
             host.get('PidsLimit') == pids and host.get('Tmpfs') == {'/tmp': tmp}, 'OWNED_RESOURCES_TMPFS')

    def row(self, role, end):
        self.validating_role = role
        info = Path(self.c[role + '_cidfile']).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and 1 <= info.st_size <= 65, 'CIDFILE')
        cid = Path(self.c[role + '_cidfile']).read_text().strip()
        need(ID.fullmatch(cid), 'CIDFILE')
        row = json.loads(call(['docker', 'inspect', cid], end))[0]
        self.security(row, role)
        labels = row['Config']['Labels']
        image = self.build['image' if role == 'hub' else 'test_image']['id']
        need(row['Id'] == cid and row['Image'] == image and row['Name'] == '/' + self.c[role + '_name'] and
             labels.get('org.cicada.test.run') == self.c['run_id'] and labels.get('org.cicada.test.role') == role and
             labels.get('org.cicada.test.suite') == SUITE, 'OWNED_IDENTITY')
        mounts = {m['Destination']: m for m in row['Mounts']}
        target = '/state' if role == 'hub' else '/tmp/fixture-state'
        allowed = {'/state', '/workspace'} if role == 'hub' else {'/tmp/fixture-state'}
        need(len(mounts) == len(row['Mounts']) and set(mounts) - {'/tmp'} == allowed and mounts[target]['Source'] == self.c['state'] and
             mounts[target]['Destination'] == target and mounts[target]['Type'] == 'bind' and mounts[target]['RW'] is True and
             mounts[target].get('Mode') == '' and mounts[target].get('Propagation') == 'rprivate', 'OWNED_MOUNT')
        need(('/tmp' not in mounts or mounts['/tmp'] == {'Type': 'tmpfs', 'Source': '', 'Destination': '/tmp', 'Mode': '', 'RW': True, 'Propagation': ''}) and
             row['Config']['User'] == str(os.getuid()) + ':' + str(os.getgid()), 'OWNED_USER_TMP')
        if role == 'hub':
            port = self.c['origin'].rsplit(':', 1)[1]
            workspace = mounts['/workspace']
            need(workspace['Source'] == self.c['workspace'] and workspace['Destination'] == '/workspace' and workspace['Type'] == 'bind' and
                 workspace['RW'] is True and workspace.get('Mode') == '' and workspace.get('Propagation') == 'rprivate' and
                 row['HostConfig']['PortBindings'] == {'8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': port}]}, 'HUB_ORIGIN_MOUNT')
        else:
            env = dict(item.split('=', 1) for item in row['Config']['Env'] if '=' in item)
            required = {'CICADA_TEST_HUB_URL': self.c['origin'], 'CICADA_TEST_HUB_DB': '/tmp/fixture-state/cicada.sqlite3', 'CICADA_TEST_LINK_UNCERTAIN_RESTART': 'external',
                        'GOCACHE': '/tmp/go-build', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'CGO_ENABLED': '0', 'GOMAXPROCS': '2'}
            need(all(env.get(k) == v for k, v in required.items()), 'GO_ENV')
            need(row['Config']['Entrypoint'] == ['go'] and row['Config']['Cmd'] == GO_ARGS and row['HostConfig']['NetworkMode'] == 'host', 'GO_COMMAND')
        if row['State']['Running']:
            witness = (row['State']['Pid'], row['State']['StartedAt'])
            need(isinstance(witness[1], str) and bool(witness[1]), 'OWNED_PID')
            if self.kernel_verified.get(role) != witness:
                need(len(self.result.get('kernel_tmpfs', [])) < 4, 'OWNED_KERNEL_WITNESS_LIMIT')
                budget(end, 0.5)
                projection = kernel_tmpfs(read_owned_mountinfo(witness[0]), role)
                after = json.loads(call(['docker', 'inspect', cid], end))[0]
                compare = runner_canonical if role == 'test' else canonical
                need(after['State']['Running'] and (after['State']['Pid'], after['State']['StartedAt']) == witness and
                     compare(after) == compare(row), 'OWNED_PID_CHANGED')
                self.kernel_verified[role] = witness
                self.result.setdefault('kernel_tmpfs', []).append({'role': role, **projection})
        self.validating_role = None
        return row

    def get(self, path, end):
        with self.opener.open(self.c['origin'] + path, timeout=budget(end, 0.5)) as response:
            body = response.read(1024 * 1024 + 1)
            need(response.status == 200 and len(body) <= 1024 * 1024, 'HTTP_RESPONSE')
            return json.loads(body)

    def ready(self, end, poll=False):
        while True:
            budget(end, 1)
            try:
                health, identity, caps = [self.get(p, end) for p in ('/healthz', '/v2/client/identity', '/v2/client/capabilities')]
            except (OSError, urllib.error.URLError):
                if not poll:
                    raise GateFailure('HUB_UNAVAILABLE')
                time.sleep(budget(end, 0.1))
                continue
            need(health.get('status') == 'ok' and all(health.get(k) == self.build['source'][k] for k in ('revision', 'dirty', 'source_fingerprint', 'catalog_sha256')), 'HEALTH_PROVENANCE')
            need(caps.get('status') == 'partial' and caps.get('catalog_sha256') == self.build['source']['catalog_sha256'] and caps.get('contract_revision') == self.c['contract_revision'] and caps.get('external_thread_links') is False, 'CAPABILITIES')
            need(bool(identity.get('hub_id')) and (self.hub_id is None or self.hub_id == identity['hub_id']), 'HUB_ID_CHANGED')
            self.hub_id = identity['hub_id']
            return

    def event(self, event):
        need(event.get('Package') == PACKAGE and (not event.get('Test') or event['Test'] in TESTS), 'GO_JSON_SCOPE')
        action, test = event.get('Action'), event.get('Test')
        if action in ('run', 'pass', 'fail', 'skip'):
            need(len(self.result['tests']) < LIFECYCLE_LIMIT, 'GO_LIFECYCLE_SIZE')
            self.result['tests'].append({k: event[k] for k in ('Time', 'Test', 'Action', 'Elapsed') if k in event})
        if action == 'output' and 'ROOT_RESTART_REQUIRED' in event.get('Output', ''):
            match = MARKER.fullmatch(event['Output'])
            need(match is not None, 'MARKER_FORMAT')
            op, digest = match.groups()
            need(len(self.result['restarts']) < 2, 'MARKER_ORDER_OR_REPEAT')
            need(test == TOP + '/' + op + '/uncertain' and op == OPS[len(self.result['restarts'])], 'MARKER_ORDER_OR_REPEAT')
            need(digest not in {r['request_sha256'] for r in self.result['restarts']}, 'MARKER_REPEAT')
            stamp = datetime.datetime.fromisoformat(event['Time'].replace('Z', '+00:00')).timestamp()
            lag = time.time() - stamp
            need(0 <= lag < 45, 'MARKER_DEADLINE')
            end = min(self.end, time.monotonic() + 45 - lag)
            record = {'operation': op, 'request_sha256': digest, 'status': 'UNKNOWN'}
            self.result['restarts'].append(record)
            before = self.row('hub', end)
            need(before['State']['Running'] and canonical(before) == self.baseline, 'HUB_CONFIG_CHANGED')
            self.ready(end)
            call(['docker', 'restart', '--timeout', '10', before['Id']], end, 13)
            self.ready(end, poll=True)
            after = self.row('hub', end)
            need(after['State']['Running'] and canonical(after) == self.baseline and after['State']['StartedAt'] != before['State']['StartedAt'] and after['RestartCount'] == before['RestartCount'], 'RESTART_POSTCHECK')
            record['status'] = 'PASS'
        need(action not in ('fail', 'skip'), 'GO_TEST_' + str(action).upper())

    def run(self):
        process = None
        raw_path = Path(self.c['raw'])
        try:
            hub = self.row('hub', self.end)
            need(hub['State']['Running'], 'HUB_NOT_RUNNING')
            self.baseline = canonical(hub)
            self.ready(min(self.end, time.monotonic() + 30), poll=True)
            runner = self.row('test', self.end)
            need(runner['State']['Status'] == 'created', 'RUNNER_NOT_FRESH')
            self.result['runner_created'] = runner_provenance(runner)
            self.end = min(self.c['work_deadline'], time.monotonic() + 190)
            process = subprocess.Popen(['docker', 'start', '--attach', runner['Id']], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            self.result['attach_pid'] = process.pid
            startup = min(self.end, time.monotonic() + 10)
            verified, buffer = False, b''
            with raw_path.open('xb') as raw, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if not verified:
                        actual = self.row('test', startup)
                        need(runner_canonical(actual) == runner_canonical(runner), 'RUNNER_CHANGED')
                        verified = actual['State']['Running']
                        if verified:
                            self.result['runner_running'] = runner_provenance(actual)
                        need(verified or actual['State']['Status'] == 'created', 'RUNNER_START_FAILED')
                    for key, _ in selector.select(timeout=budget(self.end if verified else startup, 0.1)):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        self.capture(raw, data); buffer += data
                        need(len(buffer) <= 2 * 1024 * 1024, 'GO_JSON_SIZE')
                    while verified and b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        self.event(json.loads(line))
                need(not buffer, 'GO_JSON_TRUNCATED')
            self.result['runner_exit_code'] = process.wait(timeout=budget(self.end, 2))
            after = self.row('test', self.end)
            self.result['runner_terminal'] = runner_provenance(after)
            passes = [e.get('Test') for e in self.result['tests'] if e['Action'] == 'pass' and e.get('Test')]
            package_pass = any(e['Action'] == 'pass' and not e.get('Test') for e in self.result['tests'])
            need(verified and len(passes) == len(TESTS) and set(passes) == TESTS and package_pass and self.result['runner_exit_code'] == 0 and after['State']['ExitCode'] == 0 and not after['State']['Running'] and not after['State']['OOMKilled'] and runner_canonical(after) == runner_canonical(runner), 'MATRIX_INCOMPLETE')
            need(len(self.result['restarts']) == 2 and all(r['status'] == 'PASS' for r in self.result['restarts']), 'RESTART_INCOMPLETE')
            final_hub = self.row('hub', self.end)
            need(final_hub['State']['Running'] and canonical(final_hub) == self.baseline, 'FINAL_HUB_CONFIG')
            self.ready(min(self.end, time.monotonic() + 3))
            self.result['status'] = 'PASS'
        except Exception as error:
            self.result.update(status='FAIL', failure_code=str(error) if type(error) is GateFailure else type(error).__name__)
            if self.validating_role:
                self.result['failure_role'] = self.validating_role
        finally:
            if process and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM); process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=1)
                except ProcessLookupError:
                    pass
            if raw_path.exists():
                raw_path.chmod(0o600)
                self.result['raw_bytes'] = raw_path.stat().st_size
                self.result['raw_sha256'] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            save(self.c['receipt'], self.result)
        return 0 if self.result['status'] == 'PASS' else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    parser.add_argument('--snapshot')
    parser.add_argument('--expected')
    args = parser.parse_args()
    if args.snapshot:
        snapshot(args.snapshot, args.expected)
        return 0
    need(args.config and not args.expected, 'CONFIG_REQUIRED')
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(GateFailure('OPERATOR_TERM')))
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(GateFailure('OPERATOR_INT')))
    return LinkGate(json.loads(Path(args.config).read_text())).run()


if __name__ == '__main__':
    raise SystemExit(main())
