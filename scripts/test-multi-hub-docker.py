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
sys.dont_write_bytecode = True
import re
import unittest
from unittest import mock

GO_IMAGE = 'sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
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


FIXTURE_OWNED = {'scripts/test-multi-hub-docker.py', 'cicada-go/cmd/cicada/machine_multi_hub_docker_fixture_test.go', 'docs/node-multi-hub-docker-validation.md'}
CORE_OWNED = {'cicada-go/internal/nodeinbox/native_context_history.go', 'cicada-go/internal/nodeinbox/native_context_history_test.go'}
OWNED = FIXTURE_OWNED | CORE_OWNED


def validate_metadata(producer, build, revision, binary_sha):
    # This explicitly parses the accepted std-producer shape. The JSON remains
    # immutable; it is never rewritten into a different historical schema.
    expected_keys = {'binary', 'build_command', 'full_source_before_sha256', 'go_version', 'image_gate', 'images', 'recorded_utc', 'reusable_artifact_images_retained', 'software_version', 'source', 'verification_records'}
    if set(producer) != expected_keys or set(build) != {'image', 'pqtls_available', 'schema_version', 'source', 'test_image', 'transport_variant'}:
        raise ValueError('unrecognized accepted producer/build shape')
    if build['schema_version'] != 'cicada.hub-build.v1' or build['transport_variant'] != 'standard' or build['pqtls_available'] is not False:
        raise ValueError('existing standard transport artifacts required')
    source = producer['source']
    if set(source) != {'catalog_sha256', 'dirty', 'input_inventory', 'revision', 'source_fingerprint'} or source != build['source']:
        raise ValueError('producer/build source inventory mismatch')
    if source['revision'] != revision or source['dirty'] is not False or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('exact clean production revision required')
    if not all(re.fullmatch('[0-9a-f]{64}', source[k]) for k in ['catalog_sha256', 'source_fingerprint']):
        raise ValueError('bounded source/catalog identity required')
    if source['input_inventory']['source_fingerprint_v4']['sha256'] != source['source_fingerprint']:
        raise ValueError('standard v4 input domain mismatch')
    if producer['go_version'] != 'go version go1.27.1 linux/amd64' or producer['software_version'] != '0.1.0-dev' or producer['reusable_artifact_images_retained'] is not True:
        raise ValueError('accepted tool/version/artifact identity mismatch')
    if set(producer['images']) != {'image', 'test_image'} or producer['binary']['sha256'] != binary_sha or not re.fullmatch('[0-9a-f]{64}', binary_sha) or producer['binary']['bytes'] <= 0:
        raise ValueError('accepted image pair/exact binary required')
    for role in ['image', 'test_image']:
        image = producer['images'][role]
        if not re.fullmatch('sha256:[0-9a-f]{64}', image['id']) or image['id'] != build[role]['id'] or image['reference'] != build[role]['reference']:
            raise ValueError('producer/build image identity mismatch')
        expected = {'org.opencontainers.image.revision': revision, 'org.cicada.build.dirty': 'false', 'org.cicada.build.source-fingerprint': source['source_fingerprint'], 'org.cicada.client-catalog.sha256': source['catalog_sha256']}
        if any(image['labels'].get(k) != v for k, v in expected.items()):
            raise ValueError('image labels mismatch current production source/catalog')
    return producer


def validate_artifacts(args):
    values = []
    for path, expected in [(args.producer_receipt, args.producer_sha256), (args.build_receipt, args.build_sha256)]:
        if not re.fullmatch('[0-9a-f]{64}', expected) or not path.is_file() or path.stat().st_size > 8*1024*1024:
            raise ValueError('bounded fixed metadata hash required')
        data = path.read_bytes()
        if SHA(data) != expected: raise ValueError('accepted metadata bytes changed')
        values.append(json.loads(data))
    return validate_metadata(values[0], values[1], args.source_revision, args.shipped_binary_sha256)


def validate_node_artifact(args, inventory):
    if args.node_artifact is None:
        return None
    if args.node_artifact.is_symlink(): raise ValueError('Node producer cannot be a symlink')
    path=args.node_artifact.resolve()
    if ROOT not in path.parents or '.cicada-data' not in path.relative_to(ROOT).parts or path.stat().st_size>4*1024*1024 or not re.fullmatch('[0-9a-f]{64}',args.node_artifact_sha256 or ''):
        raise ValueError('fixed checkout-local Node artifact metadata required')
    data=path.read_bytes()
    if SHA(data)!=args.node_artifact_sha256: raise ValueError('Node producer metadata bytes changed')
    artifact=json.loads(data)
    if set(artifact)!={'schema','role','source_inventory','source_domain','binary','go_image','go_version','build_commands_sha256'} or artifact['schema']!='cicada.patched-node-fixture-build.v1' or artifact['role']!='actual patched production Node CLI':
        raise ValueError('unrecognized Node build domain')
    if artifact['source_inventory']!=inventory or artifact['source_domain']!='dirty independent checkout full bytes/raw-modes/index' or artifact['go_image']!=GO_IMAGE or artifact['go_version']!='go1.27.1':
        raise ValueError('patched Node source/tool attribution mismatch')
    if Path(artifact['binary']['path']).is_symlink(): raise ValueError('Node binary cannot be a symlink')
    binary=Path(artifact['binary']['path']).resolve()
    if ROOT not in binary.parents or '.cicada-data' not in binary.relative_to(ROOT).parts or not binary.is_file() or binary.is_symlink(): raise ValueError('owned existing Node binary required')
    if SHA(binary.read_bytes())!=artifact['binary']['sha256'] or binary.stat().st_size!=artifact['binary']['bytes'] or binary.stat().st_mode!=artifact['binary']['raw_mode']: raise ValueError('patched Node binary bytes/mode mismatch')
    return artifact


class Gate:
    def __init__(self, args):
        self.args = args
        self.args.hub_image = 'UNVERIFIED'
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
        self.report = {'status': 'IN_PROGRESS', 'owner_label': LABEL, 'owner': self.owner, 'started_utc': UTC(), 'limits': {'native_runtime': 'NOT_RUN', 'models_providers': 'NOT_RUN', 'Android_public_HTTPS_physical_device': 'NOT_RUN', 'native_session_verification': 'NOT_RUN; Hub Join uses visibly synthetic coordinates', 'native_message_injection_business_CAS': 'NOT_RUN', 'lost_reply': 'bounded synthetic observer loses committed SEND response; exact opaque retry only'}, 'cases': []}
        self.production_before = None
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
        try: return {n: json.loads((self.private / n / 'observed.json').read_text()) for n in ['node', 'node-r']}
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
                receiver = db.execute('SELECT id, owner_id, last_seen FROM machines WHERE id=?', (e['receiver_node_id'],)).fetchone()
                assert receiver and receiver[1] == e['owner_id']
                result[e['name']] = {'node_id': row[0], 'receiver_node_id': receiver[0], 'owner_id': row[1], 'last_seen': row[2], 'receiver_last_seen': receiver[2], 'approved_node_bindings': db.execute("SELECT count(*) FROM node_owner_bindings_v2 WHERE state='ACTIVE'").fetchone()[0]}
        return result

    def credentials(self):
        result = {}
        for n in ['node', 'node-r']:
            for e in self.public:
                node_id = e['node_id'] if n == 'node' else e['receiver_node_id']
                relative = e['state_relative'] if n == 'node' else e['receiver_state_relative']
                directory = self.private / n / relative / 'nodes' / ('node-' + node_id)
                rows = {}
                for p in [directory / 'identity.json', directory / 'relay.token', *sorted((directory / 'endpoint-keys').glob('*'))]:
                    st = p.lstat(); assert st.st_mode == stat.S_IFREG | 0o600
                    rows[p.relative_to(directory).as_posix()] = {'sha256': SHA(p.read_bytes()), 'raw_mode': st.st_mode}
                with sqlite3.connect((directory / 'node-crypto-state.sqlite').as_uri() + '?mode=ro', uri=True) as db:
                    rows['crypto'] = {'owner_trust_rows': db.execute('SELECT count(*) FROM node_crypto_owner_key_trust').fetchone()[0], 'replay_rows': db.execute('SELECT count(*) FROM node_crypto_replay').fetchone()[0], 'crypto_inbox_rows': db.execute('SELECT count(*) FROM node_crypto_inbox').fetchone()[0], 'outbox_rows': db.execute('SELECT count(*) FROM node_crypto_outbox').fetchone()[0], 'last_sequence_total': db.execute('SELECT coalesce(sum(last_sequence),0) FROM node_crypto_sequences').fetchone()[0]}
                result[n + '/' + e['name']] = rows
        return result

    def collect_secrets(self):
        self.secrets = []
        def collect(v):
            if isinstance(v, dict):
                for key, item in v.items():
                    if any(term in key.lower() for term in ['token', 'private', 'proof', 'invitation']) or key.lower() in {'dk', 'sk', 'payload'}:
                        if isinstance(item, str): self.secrets.append(item.encode())
                    else: collect(item)
            elif isinstance(v, list):
                for item in v: collect(item)
        for p in self.private.rglob('*'):
            if p.is_file() and p.suffix in {'.json', '.key'}:
                try: collect(json.loads(p.read_text()))
                except (UnicodeDecodeError, json.JSONDecodeError): pass
        for hub in ['a', 'b']:
            for kind in ['SEND', 'REQUEST', 'REPLY']:
                self.secrets.append(('CICADA-MULTIHUB-SYNTHETIC-OPAQUE-' + hub + '-' + kind).encode())

    def fixture_action(self, action, network, name=None):
        name = name or action
        argv = self.base('action-' + name, network) + ['--mount', 'type=bind,src=' + str(self.private) + ',dst=/fixture', '--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', *self.helper_args(action, '/fixture'), self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$']
        _, out, _ = self.docker(argv, 'actual-' + name, timeout=90)
        result = next(json.loads(line) for line in out.decode().splitlines() if line.startswith('{"cases"'))
        assert result['result'] == 'PASS'
        save(self.out / ('actual-' + name + '.json'), result)
        self.report['cases'].extend({**e, 'result': 'PASS', 'phase': name} for e in result['cases'])
        self.collect_secrets()
        return result

    def execute(self):
        self.before = source_inventory(ROOT); save(self.out / 'source-before.json', self.before)
        self.production_before = source_inventory(self.args.production_source); save(self.out / 'production-source-before.json', self.production_before)
        assert self.before['head'] == self.args.source_revision and self.production_before['head'] == self.args.source_revision
        assert self.production_before['status'] == ''
        modified = subprocess.check_output(['git', 'diff', '--name-only'], cwd=ROOT).decode().splitlines()
        assert set(modified) <= OWNED and not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=ROOT).strip()
        node_artifact = validate_node_artifact(self.args, self.before)
        if set(modified) & CORE_OWNED and node_artifact is None: raise ValueError('modified Core requires distinctly attributed patched Node artifact')
        producer = validate_artifacts(self.args)
        self.args.hub_image = producer['images']['image']['id']
        self.report['accepted_producer'] = {'producer_sha256': self.args.producer_sha256, 'build_sha256': self.args.build_sha256, 'shipped_binary_sha256': self.args.shipped_binary_sha256, 'production_revision': self.args.source_revision, 'production_standard_source_fingerprint': producer['source']['source_fingerprint'], 'interop': 'IDENTITY_VERIFIED_ONLY; independent interop tests NOT_RUN by this gate'}
        spec = importlib.util.spec_from_file_location('hub_inputs', self.args.production_source / 'scripts/hub-build-input-inventory.py')
        inventory_helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(inventory_helper)
        inventory = inventory_helper.capture(self.args.production_source)
        assert inventory == producer['source']['input_inventory']
        save(self.out / 'production-standard-inputs.json', inventory)
        for role in ['image', 'test_image']:
            expected = producer['images'][role]
            _, data, _ = self.docker(['image', 'inspect', expected['id']], 'accepted-' + role)
            inspected = json.loads(data)[0]
            assert inspected['Id'] == expected['id'] and inspected['Config']['Labels'] == expected['labels']
        self.docker(['image', 'inspect', self.args.go_image, '--format', '{{.Id}}'], 'go-image')
        self.docker(['ps', '-a', '--no-trunc', '--format', '{{json .}}'], 'resident-before')
        builder = self.base('build') + ['--mount', 'type=bind,src=' + str(ROOT) + '/cicada-go,dst=/src,readonly', '--mount', 'type=bind,src=' + str(self.out) + ',dst=/evidence', '--mount', 'type=bind,src=' + str(self.args.module_cache.resolve()) + ',dst=/modules,readonly', '--workdir', '/src', '--env', 'GOTOOLCHAIN=local', '--env', 'GOPROXY=off', '--env', 'GOSUMDB=off', '--env', 'GOFLAGS=-mod=readonly -buildvcs=false', '--env', 'CGO_ENABLED=0', '--env', 'GOMODCACHE=/modules', '--env', 'GOCACHE=/evidence/cache', '--env', 'TMPDIR=/evidence/tmp', '--env', 'PYTHONDONTWRITEBYTECODE=1', self.args.go_image]
        self.docker(builder + ['go', 'test', '-c', '-o', '/evidence/bin/multi-hub-fixture.test', './cmd/cicada'], 'fixture-compile', timeout=600)
        self.docker(self.base('focused') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.v', '-test.run', '^TestMachineMultiHubDocker(FixtureRejectsUnownedAndSharedCoordinates|HTTPRequiresExactStatusAndTypedDenial|ObserverPreservesStreamAndRejectsFalseReady)$'], 'focused-helper-check', timeout=30)
        if node_artifact is None:
            copy_name = self.owner + '-extract'
            self.docker(['create', '--pull', 'never', '--network', 'none', '--name', copy_name, '--label', LABEL + '=' + self.owner, self.args.hub_image], 'shipped-binary-container')
            self.docker(['cp', copy_name + ':/usr/local/bin/cicada', str(self.out / 'bin/cicada')], 'extract-shipped-binary')
            self.owned('container', copy_name)
            self.docker(['rm', copy_name], 'remove-extract-container')
            assert SHA((self.out / 'bin/cicada').read_bytes()) == self.args.shipped_binary_sha256
            self.node_binary_role = 'exact shipped CLI extracted from clean Hub image'
        else:
            shutil.copyfile(node_artifact['binary']['path'],self.out/'bin/cicada')
            (self.out/'bin/cicada').chmod(stat.S_IMODE(node_artifact['binary']['raw_mode']))
            assert SHA((self.out/'bin/cicada').read_bytes())==node_artifact['binary']['sha256']
            self.node_binary_role='actual patched production Node CLI from separately attributed dirty checkout'
            self.report['patched_Node_artifact']={'metadata_sha256':self.args.node_artifact_sha256,'binary':node_artifact['binary'],'source_full_sha256':node_artifact['source_inventory']['canonical_sha256'],'source_domain':node_artifact['source_domain'],'build_commands_sha256':node_artifact['build_commands_sha256']}
        self.docker(self.base('version') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, '/bin-fixture/cicada', 'version'], 'Node-version')
        self.docker(self.base('build-info') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, 'go', 'version', '-m', '/bin-fixture/cicada'], 'Node-build-info')
        self.docker(self.base('helper-build-info') + ['--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', self.args.go_image, 'go', 'version', '-m', '/bin-fixture/multi-hub-fixture.test'], 'helper-build-info')
        self.docker(self.base('seed') + ['--mount', 'type=bind,src=' + str(self.private) + ',dst=/fixture', '--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', *self.helper_args('seed', '/fixture'), self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$'], 'synthetic-seed', timeout=60)
        self.collect_secrets()
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
            argv = ['run', '-d', '--pull', 'never', '--network', network, '--network-alias', 'hub-' + name, '--user', f'{os.getuid()}:{os.getgid()}', '--name', self.owner + '-hub-' + name, '--label', LABEL + '=' + self.owner, '--mount', 'type=bind,src=' + str(path / 'state') + ',dst=/state', '--mount', 'type=bind,src=' + str(path / 'workspace') + ',dst=/workspace', '--env-file', str(path / 'env'), '--env', 'CICADA_CODEX_BIN=/nonexistent-fixture-no-runtime', '--env', 'CICADA_MONITOR_INTERVAL_SECONDS=3600', '--env', 'CICADA_SNAPSHOT_GC_INTERVAL_SECONDS=0', '--env', 'CICADA_MAX_RECOVERIES=0', self.args.hub_image, 'serve', '--host', '0.0.0.0', '--port', '8787']
            self.docker(argv, 'launch-hub-' + name)
        self.fixture_action('enroll', network)
        for e in self.public:
            name = e['name']; path = self.private / 'hubs' / name
            with sqlite3.connect((path/'state/cicada.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
                assert db.execute('SELECT count(*) FROM goals').fetchone()[0] == 0
                assert db.execute('SELECT count(*) FROM workers').fetchone()[0] == 0
            identity = path/'state/e2ee/identity.json'
            before_identity = {'sha256':SHA(identity.read_bytes()),'raw_mode':identity.stat().st_mode}
            hub = self.owner+'-hub-'+name
            self.owned('container',hub)
            self.docker(['stop','--time','5',hub],'stop-enrollment-Control-'+name,timeout=20)
            self.owned('container',hub)
            self.docker(['rm',hub],'remove-enrollment-Control-'+name)
            argv = ['run','-d','--pull','never','--network',network,'--network-alias','hub-'+name,'--user',f'{os.getuid()}:{os.getgid()}','--name',hub,'--label',LABEL+'='+self.owner,'--mount','type=bind,src='+str(path/'state')+',dst=/state','--mount','type=bind,src='+str(path/'workspace')+',dst=/workspace','--env-file',str(path/'env'),self.args.hub_image,'serve','--fabric-only','--host','0.0.0.0','--port','8787']
            self.docker(argv,'launch-Control-absent-peer-Hub-'+name)
            assert before_identity == {'sha256':SHA(identity.read_bytes()),'raw_mode':identity.stat().st_mode}
            self.report['cases'].append({'case':'legitimate-Control-enrollment-then-Control-absent-peer-Hub','hub':name,'result':'PASS','same_Hub_identity':before_identity,'management_goal_worker_count':0})
        self.fixture_action('control-absent', network)
        self.credentials_before = self.credentials(); save(self.out / 'credentials-after-enrollment.json', self.credentials_before)
        nodes = {}
        for n in ['node', 'node-r']:
            node = self.owner + '-' + n; nodes[n] = node
            self.docker(['run', '-d', '--pull', 'never', '--network', network, '--network-alias', 'node-sender' if n == 'node' else 'node-receiver', '--user', f'{os.getuid()}:{os.getgid()}', '--name', node, '--label', LABEL + '=' + self.owner, '--mount', 'type=bind,src=' + str(self.private / n) + ',dst=/node', '--mount', 'type=bind,src=' + str(self.out / 'bin') + ',dst=/bin-fixture,readonly', *self.helper_args('runtime', '/node'), '--env', 'CICADA_MULTI_HUB_SHIPPED_BINARY=/bin-fixture/cicada', self.args.go_image, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$'], 'launch-multi-hub-' + n)
        valid = lambda m: all(v['heartbeats_ok'] >= 2 and v['network_claims_ok'] >= 2 and v['sse_headers_ok'] >= 1 and v['sse_ready_frames'] >= 1 and v['wrong_agent_bearer'] == 0 and v['control_requests'] == 0 for workers in m.values() for v in workers.values())
        first = self.wait_metrics(valid, 'initial-four-actual-agent-workers')
        heartbeats = self.heartbeats(); save(self.out / 'heartbeats-initial.json', heartbeats)
        assert all(heartbeats[k][field] > self.hb_before[k][field] for k in heartbeats for field in ['last_seen','receiver_last_seen'])
        self.report['cases'].append({'case': 'two-independent-shipped-Hubs-and-two-production-multi-Hub-Agents', 'result': 'PASS', 'scope': 'actual SSE ready frames and owner-bound heartbeat/Network claims from four workers'})
        self.fixture_action('messages', network)
        self.fixture_action('received', network)
        self.fixture_action('reply', network)
        persisted = self.fixture_action('inspect', network, 'initial-message-persistence')
        self.credentials_before_restart = self.credentials(); save(self.out / 'credentials-before-restart.json', self.credentials_before_restart)
        self.wait_metrics(lambda m: all(m['node-r'][h]['network_nonempty_deliveries'] >= 2 and m['node'][h]['network_nonempty_deliveries'] >= 1 for h in ['a', 'b']), 'actual-nonempty-four-scope-claims')
        node = nodes['node']
        probe = ['exec', '--env', 'CICADA_MULTI_HUB_FIXTURE_ACTION=probe', '--env', 'CICADA_MULTI_HUB_FIXTURE_ROOT=/node', node, '/bin-fixture/multi-hub-fixture.test', '-test.run', '^' + HELPER + '$']
        _, out, _ = self.docker(probe, 'actual-http-auth-negatives', timeout=60)
        public_probe = next(json.loads(line) for line in out.decode().splitlines() if line.startswith('{"cases"'))
        assert len(public_probe['cases']) == 8
        save(self.out / 'actual-http-auth-negatives.json', public_probe)
        self.report['cases'].extend({**e, 'result': 'PASS'} for e in public_probe['cases'])
        self.owned('container', self.owner + '-hub-a')
        self.docker(['stop', '--time', '5', self.owner + '-hub-a'], 'stop-only-hub-a', timeout=20)
        start = self.metric(); hb = self.heartbeats()
        outage = self.wait_metrics(lambda m: all(m[n]['b']['heartbeats_ok'] >= start[n]['b']['heartbeats_ok'] + 2 and m[n]['b']['network_claims_ok'] >= start[n]['b']['network_claims_ok'] + 2 and m[n]['a']['upstream_failures'] > start[n]['a']['upstream_failures'] for n in ['node', 'node-r']), 'hub-a-outage-hub-b-live', timeout=30)
        now = self.heartbeats(); save(self.out / 'heartbeats-outage.json', now)
        assert all(now['b'][field] > hb['b'][field] and now['a'][field] == hb['a'][field] for field in ['last_seen','receiver_last_seen'])
        self.report['cases'].append({'case': 'Hub-A-outage-does-not-stop-Hub-B', 'result': 'PASS'})
        self.docker(['start', self.owner + '-hub-a'], 'restart-existing-hub-a')
        restored = self.wait_metrics(lambda m: valid(m) and all(m[n]['a']['heartbeats_ok'] > outage[n]['a']['heartbeats_ok'] and m[n]['a']['network_claims_ok'] > outage[n]['a']['network_claims_ok'] and m[n]['a']['sse_ready_frames'] > outage[n]['a']['sse_ready_frames'] for n in ['node', 'node-r']), 'hub-a-reconnect')
        self.report['cases'].append({'case': 'Hub-A-restart-preserves-independent-bindings', 'result': 'PASS'})
        self.fixture_action('replay', network, 'exact-retry-after-Hub-restart')
        for n, node in nodes.items():
            self.owned('container', node)
            self.docker(['restart', '--time', '8', node], 'restart-production-multi-hub-' + n, timeout=30)
        self.wait_metrics(lambda m: valid(m) and all(m[n]['a']['heartbeats_ok'] < restored[n]['a']['heartbeats_ok'] for n in ['node', 'node-r']), 'node-restart-new-observation-window', timeout=45)
        repeated = self.fixture_action('inspect', network, 'persistence-after-two-Node-restarts')
        self.fixture_action('replay', network, 'exact-retry-after-Node-restart')
        after = self.credentials(); save(self.out / 'credentials-after-restart.json', after)
        assert after == self.credentials_before_restart
        assert [{k: v for k, v in c.items() if k not in {'node_inbox_state', 'actual_receipt_layers'}} for c in persisted['cases']] == [{k: v for k, v in c.items() if k not in {'node_inbox_state', 'actual_receipt_layers'}} for c in repeated['cases']]
        self.report['cases'].append({'case': 'two-Node-process-restarts-keep-four-credential-and-replay-scopes', 'result': 'PASS', 'scope': 'identity/token/Endpoint-key bytes/raw modes; Owner trust, ciphertext/replay/outbox/sequence counts unchanged; no Runtime receipt'})
        for name in ['a', 'b']:
            self.docker(['inspect', self.owner + '-hub-' + name, '--format', '{{.State.Pid}} {{.Id}} {{.Image}}'], 'actual-hub-process-' + name)
        for n, node in nodes.items(): self.docker(['top', node], 'actual-helper-and-production-agent-processes-' + n)
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
                production_after = source_inventory(self.args.production_source); save(self.out / 'production-source-after.json', production_after)
                self.report['fixture_source_before_after_exact'] = self.before == after
                self.report['production_source_before_after_exact'] = self.production_before == production_after
                if self.before != after or self.production_before != production_after: self.report['status'] = 'FAIL'
            except Exception as e: self.report.update(status='FAIL', source_error=str(e))
            self.report['secret_scan_passed'] = self.safe
            if not self.safe: self.report['status'] = 'FAIL'
            self.report['temporary_build_roots_remaining'] = sorted(p.name for p in (self.out / 'tmp').iterdir())
            if self.report['temporary_build_roots_remaining']: self.report['status'] = 'FAIL'
            self.report['binaries'] = {p.name: {'sha256': SHA(p.read_bytes()), 'bytes': p.stat().st_size, 'raw_mode': p.stat().st_mode, 'role': getattr(self,'node_binary_role','UNVERIFIED Node CLI') if p.name == 'cicada' else 'synthetic fixture helper from dirty independent checkout'} for p in (self.out / 'bin').iterdir() if p.is_file()}
            self.report.update(finished_utc=UTC(), hub_image=self.args.hub_image, go_image=self.args.go_image)
            r, _, _ = self.docker(['ps', '-a', '--no-trunc', '--format', '{{json .}}'], 'resident-after', check=False)
            if r['exit'] != 0 or not self.safe: self.report.update(status='FAIL', secret_scan_passed=self.safe)
            save(self.out / 'receipt.json', self.report)
        print(json.dumps({'status': self.report['status'], 'receipt_sha256': SHA((self.out / 'receipt.json').read_bytes())}), flush=True)
        return 0 if self.report['status'] == 'SCOPED_PASS' else 1



class DriverTests(unittest.TestCase):
    def metadata(self):
        revision, digest, binary = '1'*40, '2'*64, '3'*64
        source = {'catalog_sha256':digest, 'dirty':False, 'input_inventory':{'source_fingerprint_v4':{'sha256':digest}}, 'revision':revision, 'source_fingerprint':digest}
        labels = {'org.opencontainers.image.revision':revision, 'org.cicada.build.dirty':'false', 'org.cicada.build.source-fingerprint':digest, 'org.cicada.client-catalog.sha256':digest}
        images = {role:{'id':'sha256:'+str(i)*64, 'reference':role, 'labels':dict(labels)} for i,role in enumerate(['image','test_image'],4)}
        producer = {'binary':{'sha256':binary,'bytes':1}, 'build_command':[], 'full_source_before_sha256':digest, 'go_version':'go version go1.27.1 linux/amd64', 'image_gate':'NOT_RUN_YET', 'images':images, 'recorded_utc':'synthetic', 'reusable_artifact_images_retained':True, 'software_version':'0.1.0-dev', 'source':source, 'verification_records':[]}
        build = {'image':{k:images['image'][k] for k in ['id','reference']}, 'test_image':{k:images['test_image'][k] for k in ['id','reference']}, 'pqtls_available':False, 'schema_version':'cicada.hub-build.v1','source':json.loads(json.dumps(source)), 'transport_variant':'standard'}
        return producer,build,revision,binary

    def test_metadata_crossbind_and_fail_closed(self):
        p,b,r,sha = self.metadata()
        self.assertIs(validate_metadata(p,b,r,sha),p)
        for mutate in [lambda p,b:p.update(unknown=True), lambda p,b:b['source'].update(dirty=True), lambda p,b:p['binary'].update(sha256='9'*64), lambda p,b:p['images']['image']['labels'].update({'org.cicada.build.dirty':'true'}), lambda p,b:b['test_image'].update(id='sha256:'+'0'*64)]:
            p,b,r,sha = self.metadata(); mutate(p,b)
            with self.assertRaises(ValueError): validate_metadata(p,b,r,sha)

    def test_patched_node_artifact_requires_exact_source_and_binary(self):
        parent=ROOT/'.cicada-data';parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            path=Path(directory);binary=path/'node';binary.write_bytes(b'synthetic-artifact-validation-only');binary.chmod(0o700)
            inventory={'canonical_sha256':'7'*64,'status':'dirty'}
            artifact={'schema':'cicada.patched-node-fixture-build.v1','role':'actual patched production Node CLI','source_inventory':inventory,'source_domain':'dirty independent checkout full bytes/raw-modes/index','binary':{'path':str(binary),'sha256':SHA(binary.read_bytes()),'bytes':binary.stat().st_size,'raw_mode':binary.stat().st_mode},'go_image':GO_IMAGE,'go_version':'go1.27.1','build_commands_sha256':'8'*64}
            metadata=path/'producer.json';save(metadata,artifact)
            args=argparse.Namespace(node_artifact=metadata,node_artifact_sha256=SHA(metadata.read_bytes()))
            self.assertEqual(validate_node_artifact(args,inventory),artifact)
            with self.assertRaises(ValueError):validate_node_artifact(args,{'status':'different'})
            binary.write_bytes(b'changed')
            with self.assertRaises(ValueError):validate_node_artifact(args,inventory)

    def cleanup_gate(self, directory, foreign=False):
        args = argparse.Namespace(evidence=Path(directory)/'run', production_source=ROOT, go_image=GO_IMAGE, node_artifact=None, node_artifact_sha256=None)
        gate = Gate(args); gate.secrets=[b'synthetic-secret-marker']
        present={'container':['owned-c'], 'network':['owned-n']}; removed=[]
        def process(argv, **kwargs):
            if argv == ['fixture-leak']: return subprocess.CompletedProcess(argv,0,b'synthetic-secret-marker',b'')
            if argv == ['fixture-safe']: return subprocess.CompletedProcess(argv,0,b'public',b'')
            if argv[:2] == ['docker','logs']: data=b''
            elif 'inspect' in argv: data=(( 'foreign' if foreign and 'owned-c' in argv else gate.owner)+'\n').encode()
            elif '--filter' in argv:
                kind='network' if argv[1]=='network' else 'container'; data=('\n'.join(present[kind])+'\n').encode() if present[kind] else b''
            elif argv[1:3] == ['rm','-f'] or argv[1:3] == ['network','rm']:
                ident=argv[-1]; kind='network' if ident=='owned-n' else 'container'; present[kind].remove(ident); removed.append(ident); data=b''
            else: raise AssertionError('unexpected mock command '+repr(argv))
            return subprocess.CompletedProcess(argv,0,data,b'')
        with mock.patch.object(subprocess,'run',side_effect=process):
            with self.assertRaises(RuntimeError): gate.run(['fixture-leak'],'leak')
            self.assertFalse((gate.out/'logs/leak.stdout').exists())
            gate.cleanup()
            gate.run(['fixture-safe'],'safe-after-leak',check=False)
        return gate,removed

    def test_sticky_secret_failure_still_cleans_verified_resources(self):
        parent=ROOT/'.cicada-data'; parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            gate,removed=self.cleanup_gate(directory)
            self.assertEqual(set(removed),{'owned-c','owned-n'})
            self.assertTrue(gate.report['owned_resources_absent'])
            self.assertTrue(gate.report['private_fixtures_removed'])
            self.assertFalse(gate.safe)
            # Final result remains failed even when cleanup and safe output succeed.
            gate.execute=lambda:gate.report.update(status='SCOPED_PASS')
            gate.cleanup=lambda:None
            gate.before=gate.production_before={'same':True}
            with mock.patch('builtins.print'), mock.patch.object(sys.modules[__name__],'source_inventory',return_value={'same':True}), mock.patch.object(gate,'docker',return_value=({'exit':0},b'',b'')):
                self.assertEqual(gate.finish(),1)
            self.assertEqual(json.loads((gate.out/'receipt.json').read_text())['status'],'FAIL')
            for log in (gate.out/'logs').iterdir(): self.assertNotIn(b'synthetic-secret-marker',log.read_bytes())

    def test_cleanup_refuses_foreign_resource_after_scan_failure(self):
        parent=ROOT/'.cicada-data'; parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            gate,removed=self.cleanup_gate(directory,True)
            self.assertNotIn('owned-c',removed)
            self.assertFalse(gate.report['owned_resources_absent'])
            self.assertEqual(gate.report['status'],'FAIL')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--source-revision')
    parser.add_argument('--production-source', type=Path)
    parser.add_argument('--producer-receipt', type=Path)
    parser.add_argument('--producer-sha256')
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--build-sha256')
    parser.add_argument('--shipped-binary-sha256')
    parser.add_argument('--node-artifact', type=Path)
    parser.add_argument('--node-artifact-sha256')
    parser.add_argument('--go-image', default=GO_IMAGE)
    parser.add_argument('--module-cache', type=Path)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DriverTests))
        return 0 if result.wasSuccessful() else 1
    if not all(getattr(args, k) is not None for k in ['evidence', 'source_revision', 'production_source', 'producer_receipt', 'producer_sha256', 'build_receipt', 'build_sha256', 'shipped_binary_sha256', 'module_cache']):
        parser.error('fixed clean source, producer/build/binary identities, offline module cache and new evidence are required')
    if (args.node_artifact is None) != (args.node_artifact_sha256 is None): parser.error('Node artifact path and fixed hash must be supplied together')
    if args.go_image != GO_IMAGE: parser.error('only reviewed pinned Go 1.27.1 local tool image supported')
    if not args.module_cache.is_dir(): parser.error('offline module cache is unavailable')
    if ROOT not in args.evidence.resolve().parents or '.cicada-data' not in args.evidence.resolve().relative_to(ROOT).parts: parser.error('new ignored checkout-local evidence path required')
    args.production_source = args.production_source.resolve()
    return Gate(args).finish()


if __name__ == '__main__':
    sys.exit(main())
