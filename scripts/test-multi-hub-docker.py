#!/usr/bin/env python3
"""Bounded real two-Hub gate. All fixtures are synthetic and owned by this run."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid

HUB_IMAGE = 'sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4'
GO_IMAGE = 'sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
BASE = '25bc586232db43362c6e03eccef1fa3a0dbec8ee'
LABEL = 'cicada.multi-hub-disposable.owner'
ROOT = Path(__file__).resolve().parents[1]
HELPER = 'TestMachineMultiHubDockerFixture'
SHA = lambda b: hashlib.sha256(b).hexdigest()
UTC = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o600)


def source_inventory(root):
    env = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0'}
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], env=env)
    rows = {}
    for name in sorted(set(git('ls-files', '-co', '--exclude-standard', '-z').decode().rstrip('\0').split('\0'))):
        p = root / name
        st = p.lstat()
        data = os.fsencode(os.readlink(p)) if stat.S_ISLNK(st.st_mode) else p.read_bytes()
        rows[name] = {'sha256': SHA(data), 'raw_mode': st.st_mode, 'bytes': len(data), 'file_type': 'symlink' if stat.S_ISLNK(st.st_mode) else 'regular'}
    index = Path(git('rev-parse', '--git-path', 'index').decode().strip())
    if not index.is_absolute(): index = root / index
    return {'head': git('rev-parse', 'HEAD').decode().strip(), 'status': git('status', '--porcelain=v1', '-uall').decode(), 'index_sha256': SHA(index.read_bytes()), 'files': rows, 'canonical_sha256': SHA(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode())}


class Gate:
    def __init__(self, args):
        self.args = args
        self.out = args.evidence.resolve()
        self.out.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.owner = 'cicada-two-hubs-' + uuid.uuid4().hex
        self.commands = []
        self.secrets = []
        self.safe = True
        self.private = self.out / 'private'
        self.private.mkdir(mode=0o700)
        (self.private / '.multi-hub-owned').write_text('cicada.multihub.disposable.v1\n' + self.owner + '\n')
        (self.private / '.multi-hub-owned').chmod(0o600)
        for name in ['bin', 'logs', 'cache', 'tmp']:
            (self.out / name).mkdir(mode=0o700)
        self.report = {'status': 'IN_PROGRESS', 'owner_label': LABEL, 'owner': self.owner, 'started_utc': UTC(), 'limits': {'native_runtime': 'NOT_RUN', 'models_providers': 'NOT_RUN', 'Android_public_HTTPS_physical_device': 'NOT_RUN', 'EndpointJoin_ACTIVE_Network': 'NOT_RUN', 'sealed_message_injection_receipt_business_CAS': 'NOT_RUN', 'lost_reply': 'NOT_RUN'}, 'cases': []}
        self.main_before = None
        self.before = None

    def run(self, argv, name, timeout=120, check=True):
        record = {'argv': argv, 'cwd': str(ROOT), 'started_utc': UTC(), 'timeout_seconds': timeout}
        start = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=ROOT, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'PYTHONDONTWRITEBYTECODE': '1'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            out, err = result.stdout, result.stderr
            record['exit'] = result.returncode
        except subprocess.TimeoutExpired as e:
            out, err = e.stdout or b'', e.stderr or b''
            record.update(exit=None, timeout=True)
        safe = not any(secret and secret in out + err for secret in self.secrets)
        safe = safe and not any(x in out + err for x in [b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----'])
        self.safe = self.safe and safe
        record.update(finished_utc=UTC(), elapsed_seconds=round(time.monotonic() - start, 3), stdout_sha256=SHA(out), stderr_sha256=SHA(err), output_secret_scan_passed=safe)
        if safe:
            for channel, data in [('stdout', out), ('stderr', err)]:
                path = self.out / 'logs' / (name + '.' + channel)
                path.write_bytes(data); path.chmod(0o600)
                record[channel + '_path'] = str(path)
        self.commands.append(record)
        save(self.out / 'commands.json', self.commands)
        print(json.dumps({'command': name, 'exit': record['exit'], 'safe_output': safe}), flush=True)
        if check and (record['exit'] != 0 or not safe):
            raise RuntimeError('command failed: ' + name + '; inspect bounded safe receipt')
        return record, out, err

    def docker(self, args, name, timeout=120, check=True):
        return self.run(['docker', *args], name, timeout, check)

    def owned(self, kind, ident):
        r, out, _ = self.docker([kind, 'inspect', ident, '--format', '{{index .Labels "' + LABEL + '"}}' if kind == 'network' else '{{index .Config.Labels "' + LABEL + '"}}'], 'ownership-' + ident[:16], check=False)
        if r['exit'] != 0 or out.decode().strip() != self.owner:
            raise RuntimeError('refuse resource without exact task owner label')

    def base(self, name, network='none'):
        return ['run', '--rm', '--pull', 'never', '--network', network, '--user', f'{os.getuid()}:{os.getgid()}', '--name', self.owner + '-' + name, '--label', LABEL + '=' + self.owner, '--cpus', '3', '--memory', '4g', '--pids-limit', '512']

    def helper_args(self, action, root):
        return ['--env', 'CICADA_MULTI_HUB_FIXTURE_ACTION=' + action, '--env', 'CICADA_MULTI_HUB_FIXTURE_ROOT=' + root]

    def metric(self):
        try: return json.loads((self.private / 'node/observed.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError): return None

    def wait_metrics(self, predicate, name, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.metric()
            if value and predicate(value):
                save(self.out / (name + '.json'), value)
                return value
            time.sleep(0.2)
        raise RuntimeError('bounded metric condition failed: ' + name)

    def heartbeats(self):
        result = {}
        for e in self.public:
            path = self.private / 'hubs' / e['name'] / 'state/cicada.sqlite3'
            with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3) as db:
                row = db.execute('SELECT id, owner_id, last_seen FROM machines WHERE id=?', (e['node_id'],)).fetchone()
                assert row and row[1] == e['owner_id']
                result[e['name']] = {'node_id': row[0], 'owner_id': row[1], 'last_seen': row[2], 'approved_node_bindings': db.execute("SELECT count(*) FROM node_owner_bindings_v2 WHERE state='ACTIVE'").fetchone()[0]}
        return result

    def credentials(self):
        result = {}
        for e in self.public:
            directory = self.private / 'node' / e['state_relative'] / 'nodes' / ('node-' + e['node_id'])
            rows = {}
            for name in ['identity.json', 'relay.token']:
                p = directory / name; st = p.lstat(); assert st.st_mode == stat.S_IFREG | 0o600
                rows[name] = {'sha256': SHA(p.read_bytes()), 'raw_mode': st.st_mode}
            with sqlite3.connect((directory / 'node-crypto-state.sqlite').as_uri() + '?mode=ro', uri=True) as db:
                rows['crypto'] = {'owner_trust_rows': db.execute('SELECT count(*) FROM node_crypto_owner_key_trust').fetchone()[0], 'replay_rows': db.execute('SELECT count(*) FROM node_crypto_replay').fetchone()[0], 'outbox_rows': db.execute('SELECT count(*) FROM node_crypto_outbox').fetchone()[0], 'last_sequence_total': db.execute('SELECT coalesce(sum(last_sequence),0) FROM node_crypto_sequences').fetchone()[0]}
            result[e['name']] = rows
        return result

    def execute(self):
        self.before = source_inventory(ROOT); save(self.out / 'source-before.json', self.before)
        self.main_before = source_inventory(Path('/home/zyf/CICADA')); save(self.out / 'Main-before.json', self.main_before)
        assert self.before['head'] == BASE and self.main_before['head'] == BASE
        assert self.main_before['status'] == ''
        self.docker(['image', 'inspect', self.args.hub_image, '--format', '{{.Id}} {{json .Config.Labels}}'], 'hub-image')
        self.docker(['image', 'inspect', self.args.go_image, '--format', '{{.Id}}'], 'go-image')
        self.docker(['ps', '-a', '--no-trunc', '--format', '{{json .}}'], 'resident-before')
        builder = self.base('build') + ['--mount', 'type=bind,src=' + str(ROOT) + '/cicada-go,dst=/src,readonly', '--mount', 'type=bind,src=' + str(self.out) + ',dst=/evidence', '--mount', 'type=bind,src=' + str(self.args.module_cache.resolve()) + ',dst=/modules,readonly', '--workdir', '/src', '--env', 'GOTOOLCHAIN=local', '--env', 'GOPROXY=off', '--env', 'GOSUMDB=off', '--env', 'GOFLAGS=-mod=readonly -buildvcs=false', '--env', 'CGO_ENABLED=0', '--env', 'GOMODCACHE=/modules', '--env', 'GOCACHE=/evidence/cache', '--env', 'TMPDIR=/evidence/tmp', '--env', 'PYTHONDONTWRITEBYTECODE=1', self.args.go_image]
        self.docker(builder + ['go', 'test', '-c', '-o', '/evidence/bin/multi-hub-fixture.test', './cmd/cicada'], 'fixture-compile', timeout=600)
        self.docker(self.base('focused') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.v', '-test.run', '^TestMachineMultiHubDockerFixtureRejectsUnownedAndSharedCoordinates$'], 'focused-helper-check', timeout=30)
        copy_name = self.owner + '-extract'
        self.docker(['create', '--pull', 'never', '--network', 'none', '--name', copy_name, '--label', LABEL + '=' + self.owner, self.args.hub_image], 'shipped-binary-container')
        self.docker(['cp', copy_name + ':/usr/local/bin/cicada', str(self.out / 'bin/cicada')], 'extract-shipped-binary')
        self.owned('container', copy_name)
        self.docker(['rm', copy_name], 'remove-extract-container')
        self.docker(self.base('version') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, '/bin-fixture/cicada', 'version'], 'shipped-version')
        self.docker(self.base('build-info') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, 'go', 'version', '-m', '/bin-fixture/cicada'], 'shipped-build-info')
        self.docker(self.base('seed') + ['--mount', 'type=bind,src=' + str(self.private) + ',dst=/fixture', '--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', *self.helper_args('seed', '/fixture'), self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$'], 'synthetic-seed', timeout=60)
        config = json.loads((self.private / 'node/proxy.json').read_text())
        for e in config:
            self.secrets.extend(e[k].encode() for k in ['token', 'foreign_owner_token', 'manager_token'])
        for p in (self.private / 'hubs').rglob('identity.json'):
            value = json.loads(p.read_text())
            def collect(v):
                if isinstance(v, dict):
                    for key, item in v.items():
                        if 'private' in key.lower() or key.lower() in {'dk', 'sk'}:
                            if isinstance(item, str): self.secrets.append(item.encode())
                        else: collect(item)
                elif isinstance(v, list):
                    for item in v: collect(item)
            collect(value)
        self.public = json.loads((self.private / 'fixture-public.json').read_text()); save(self.out / 'fixture-public.json', self.public)
        assert len({e['hub_id'] for e in self.public}) == 2 and len({e['owner_id'] for e in self.public}) == 2 and len({e['state_relative'] for e in self.public}) == 2
        self.credentials_before = self.credentials(); save(self.out / 'credentials-before.json', self.credentials_before)
        self.hb_before = self.heartbeats(); save(self.out / 'heartbeats-before.json', self.hb_before)
        network = self.owner + '-internal'
        self.docker(['network', 'create', '--internal', '--label', LABEL + '=' + self.owner, network], 'internal-network')
        self.docker(['network', 'inspect', network, '--format', '{{.Internal}}'], 'internal-network-proof')
        for e in self.public:
            name = e['name']; path = self.private / 'hubs' / name
            argv = ['run', '-d', '--pull', 'never', '--network', network, '--network-alias', 'hub-' + name, '--user', f'{os.getuid()}:{os.getgid()}', '--name', self.owner + '-hub-' + name, '--label', LABEL + '=' + self.owner, '--mount', 'type=bind,src=' + str(path / 'state') + ',dst=/state', '--mount', 'type=bind,src=' + str(path / 'workspace') + ',dst=/workspace', '--env-file', str(path / 'env'), self.args.hub_image, 'serve', '--fabric-only', '--host', '0.0.0.0', '--port', '8787']
            self.docker(argv, 'launch-hub-' + name)
        node = self.owner + '-node'
        self.docker(['run', '-d', '--pull', 'never', '--network', network, '--user', f'{os.getuid()}:{os.getgid()}', '--name', node, '--label', LABEL + '=' + self.owner, '--mount', 'type=bind,src=' + str(self.private / 'node') + ',dst=/node', '--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', *self.helper_args('runtime', '/node'), '--env', 'CICADA_MULTI_HUB_SHIPPED_BINARY=/bin-fixture/cicada', self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$'], 'launch-multi-hub-node')
        valid = lambda m: all(v['heartbeats_ok'] >= 2 and v['sealed_claims_ok'] >= 2 and v['group_claims_ok'] >= 2 and v['sse_headers_ok'] >= 1 and v['sse_ready_frames'] >= 1 and v['wrong_agent_bearer'] == 0 and v['control_requests'] == 0 for v in m.values())
        first = self.wait_metrics(valid, 'initial-actual-agent')
        heartbeats = self.heartbeats(); save(self.out / 'heartbeats-initial.json', heartbeats)
        assert all(heartbeats[k]['last_seen'] > self.hb_before[k]['last_seen'] for k in heartbeats)
        self.report['cases'].append({'case': 'two-independent-shipped-Hubs-and-shipped-multi-Hub-Agent', 'result': 'PASS', 'scope': 'actual SSE ready frames, owner-bound heartbeats and empty sealed/group reconciliation claims'})
        probe = ['exec', '--env', 'CICADA_MULTI_HUB_FIXTURE_ACTION=probe', '--env', 'CICADA_MULTI_HUB_FIXTURE_ROOT=/node', node, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$']
        _, out, _ = self.docker(probe, 'actual-http-auth-negatives', timeout=60)
        public_probe = next(json.loads(line) for line in out.decode().splitlines() if line.startswith('{"cases"'))
        assert len(public_probe['cases']) == 8
        save(self.out / 'actual-http-auth-negatives.json', public_probe)
        self.report['cases'].extend({**e, 'result': 'PASS'} for e in public_probe['cases'])
        self.owned('container', self.owner + '-hub-a')
        self.docker(['stop', '--time', '5', self.owner + '-hub-a'], 'stop-only-hub-a', timeout=20)
        start = self.metric(); hb = self.heartbeats()
        outage = self.wait_metrics(lambda m: m['b']['heartbeats_ok'] >= start['b']['heartbeats_ok'] + 2 and m['b']['sealed_claims_ok'] >= start['b']['sealed_claims_ok'] + 2 and m['a']['upstream_failures'] > start['a']['upstream_failures'], 'hub-a-outage-hub-b-live', timeout=30)
        now = self.heartbeats(); save(self.out / 'heartbeats-outage.json', now)
        assert now['b']['last_seen'] > hb['b']['last_seen'] and now['a']['last_seen'] == hb['a']['last_seen']
        self.report['cases'].append({'case': 'Hub-A-outage-does-not-stop-Hub-B', 'result': 'PASS'})
        self.docker(['start', self.owner + '-hub-a'], 'restart-existing-hub-a')
        restored = self.wait_metrics(lambda m: valid(m) and m['a']['heartbeats_ok'] > outage['a']['heartbeats_ok'] and m['a']['sealed_claims_ok'] > outage['a']['sealed_claims_ok'] and m['a']['sse_ready_frames'] > outage['a']['sse_ready_frames'], 'hub-a-reconnect')
        self.report['cases'].append({'case': 'Hub-A-restart-preserves-independent-bindings', 'result': 'PASS'})
        self.owned('container', node)
        self.docker(['restart', '--time', '8', node], 'restart-shipped-multi-hub-node', timeout=30)
        # Runtime observation counters start anew after restart; require a new ready stream per Hub.
        self.wait_metrics(lambda m: valid(m) and m['a']['heartbeats_ok'] < restored['a']['heartbeats_ok'], 'node-restart-new-observation-window', timeout=30)
        after = self.credentials(); save(self.out / 'credentials-after-restart.json', after)
        assert after == self.credentials_before
        self.report['cases'].append({'case': 'Node-process-restart-keeps-two-credential-and-replay-scopes', 'result': 'PASS', 'scope': 'token/identity bytes and raw modes, owner-trust/replay/outbox/sequence counts unchanged; no injected messages'})
        for name in ['a', 'b']:
            self.docker(['inspect', self.owner + '-hub-' + name, '--format', '{{.State.Pid}} {{.Id}} {{.Image}}'], 'actual-hub-process-' + name)
        self.docker(['top', node], 'actual-helper-and-shipped-agent-processes')
        self.report['status'] = 'SCOPED_PASS'

    def cleanup(self):
        failures = []
        for kind, query in [('container', ['ps', '-aq']), ('network', ['network', 'ls', '-q'])]:
            r, out, _ = self.docker([*query, '--filter', 'label=' + LABEL + '=' + self.owner], 'cleanup-discovery-' + kind, check=False)
            if r['exit'] != 0:
                failures.append(kind + ' discovery failed'); continue
            for ident in out.decode().split():
                try:
                    if kind == 'container': self.docker(['logs', '--tail', '100', ident], 'bounded-runtime-log-' + ident[:12], check=False)
                    self.owned(kind, ident)
                    args = ['rm', '-f', ident] if kind == 'container' else ['network', 'rm', ident]
                    r, _, _ = self.docker(args, 'cleanup-remove-' + ident[:12], check=False)
                    if r['exit'] != 0: failures.append(kind + ' removal failed')
                except Exception as e: failures.append(str(e))
            r, out, _ = self.docker([*query, '--filter', 'label=' + LABEL + '=' + self.owner], 'cleanup-absence-' + kind, check=False)
            if r['exit'] != 0 or out.strip(): failures.append(kind + ' remains')
        self.report['owned_resources_absent'] = not failures
        self.report['cleanup_errors'] = failures
        try:
            shutil.rmtree(self.private)
            self.report['private_fixtures_removed'] = not self.private.exists()
        except OSError as e:
            self.report['private_fixtures_removed'] = False
            failures.append('private fixture cleanup: ' + str(e))
        if failures: self.report['status'] = 'FAIL'

    def finish(self):
        try:
            self.execute()
        except Exception as e:
            self.report.update(status='FAIL', error=str(e))
        finally:
            try: self.cleanup()
            except Exception as e: self.report.update(status='FAIL', cleanup_exception=str(e))
            try:
                after = source_inventory(ROOT); save(self.out / 'source-after.json', after)
                main_after = source_inventory(Path('/home/zyf/CICADA')); save(self.out / 'Main-after.json', main_after)
                self.report['fixture_source_before_after_exact'] = self.before == after
                self.report['Main_before_after_exact'] = self.main_before == main_after
                if self.before != after or self.main_before != main_after: self.report['status'] = 'FAIL'
            except Exception as e: self.report.update(status='FAIL', source_error=str(e))
            self.report['secret_scan_passed'] = self.safe
            if not self.safe: self.report['status'] = 'FAIL'
            self.report['temporary_build_roots_remaining'] = sorted(p.name for p in (self.out / 'tmp').iterdir())
            if self.report['temporary_build_roots_remaining']: self.report['status'] = 'FAIL'
            self.report['binaries'] = {p.name: {'sha256': SHA(p.read_bytes()), 'bytes': p.stat().st_size, 'raw_mode': p.stat().st_mode, 'role': 'exact shipped CLI extracted from clean Hub image' if p.name == 'cicada' else 'synthetic fixture helper from dirty independent checkout'} for p in (self.out / 'bin').iterdir() if p.is_file()}
            self.report.update(finished_utc=UTC(), hub_image=self.args.hub_image, go_image=self.args.go_image)
            save(self.out / 'receipt.json', self.report)
            self.docker(['ps', '-a', '--no-trunc', '--format', '{{json .}}'], 'resident-after', check=False)
        print(json.dumps({'status': self.report['status'], 'receipt_sha256': SHA((self.out / 'receipt.json').read_bytes())}), flush=True)
        return 0 if self.report['status'] == 'SCOPED_PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--hub-image', default=HUB_IMAGE)
    parser.add_argument('--go-image', default=GO_IMAGE)
    parser.add_argument('--module-cache', required=True, type=Path)
    args = parser.parse_args()
    if args.hub_image != HUB_IMAGE or args.go_image != GO_IMAGE: parser.error('only reviewed pinned local images supported')
    if not args.module_cache.is_dir(): parser.error('offline module cache is unavailable')
    if ROOT not in args.evidence.resolve().parents or '.cicada-data' not in args.evidence.resolve().relative_to(ROOT).parts: parser.error('new ignored checkout-local evidence path required')
    return Gate(args).finish()


if __name__ == '__main__':
    sys.exit(main())
