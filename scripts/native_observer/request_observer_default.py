"""Opt-in test fixture: real Node queue to the official local default daemon.

No effect at import. Reuses the pinned Peer transport and the current gate;
this module supplies neither native account authority nor a delivery callback.
"""
import ast
import datetime
import fcntl
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import select
import signal
import sqlite3
import stat
import subprocess
import sys
import textwrap
import threading
import time
import types
from urllib.parse import quote

CLI = '/opt/official-codex/bin/codex'
CLI_SHA = '628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1'
CLI_BYTES = 294415048
IMAGE = 'sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e'
LOGICAL = '/codex/app-server-control/app-server-control.sock'
PHYSICAL = '/tmp/codex-daemon-1000/' + hashlib.sha256(LOGICAL.encode()).hexdigest()
PROVIDER = 'zzswitch'
ORIGIN = 'https://api.zzswitch.com/v1'
BASE = Path('/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007')
PEER = BASE / 'peer-outer-broker-20261009a'
PACKAGE_RECEIPT_SHA = 'f3a199fead412ada976c2d4add958e03173cdf8ea8e6ad8abc3eba1c30683f12'
PHASE_OVERLAY = PEER / 'peer_phase_budget_overlay.py'
PHASE_OVERLAY_SHA = 'b48446282014d13b31a566269636452c3f1e0f16c54acf1fe185739ee079d9b1'
HELPER_PRODUCER_REVISION = '39bce535b93ab82c3b4f4fbf5cb09c6114dca942'
FIXTURE_SCHEMA_V2 = 'cicada.native-default-peer-fixture.v2'


def install_phase_capacity(native, library):
    """Use the pinned derivation on this instance; retain all admission caps."""
    original = library.NATIVE.NativeBroker.note_phase
    if (type(native) is not library.PeerNativeBroker or
            native.note_phase.__func__ is not original or
            library.MAX_REQUESTS != 16 or native.max_connections != 16 or
            native.closed_phases != [] or native.headers_prepared != 0):
        raise ValueError('DEFAULT_PHASE_INSTANCE_SCOPE')
    overlay = load_dependency('peer_phase_budget_overlay', PHASE_OVERLAY)
    derived, proof = overlay.prepare(library)
    if (proof['old_phase_limit'] != 32 or proof['new_phase_limit'] != 128 or
            proof['request_cap'] != 16 or proof['phases_per_request_bound'] != 8 or
            proof['original_method_unchanged'] is not True):
        raise ValueError('DEFAULT_PHASE_DERIVATION_SCOPE')
    native.note_phase = types.MethodType(derived, native)
    native._default_phase_capacity = dict(proof, installed_on='OWNED_NATIVE_INSTANCE_ONLY')
    return native._default_phase_capacity


def phase_capacity_snapshot(native):
    """Only measured diagnostic length and header preparation count are public."""
    proof = getattr(native, '_default_phase_capacity', None)
    phases = getattr(native, 'closed_phases', None)
    headers = getattr(native, 'headers_prepared', None)
    if (type(proof) is not dict or proof.get('new_phase_limit') != 128 or
            type(phases) is not list or len(phases) > 128 or
            type(headers) is not int or not 0 <= headers <= 16):
        return {'status':'UNKNOWN'}
    return {'status':'MEASURED', 'capacity':128, 'current_length':len(phases),
            'headers_prepared':headers}

RESPONSE_HEAD_REASONS = frozenset({'HEADERS_REFUSED','STATUS_LINE_REFUSED',
    'UPGRADE_REFUSED','TRAILER_REFUSED','CONNECTION_UPGRADE_REFUSED',
    'TRANSFER_ENCODING_REFUSED','FRAMING_REFUSED','NO_CONTENT_FRAMING_REFUSED'})


def derive_response_head_diagnostic(core):
    """Clone the selected parser statements; observe only response refusals.

    No request data enters this callback. The original statements, exception
    object and successful response remain the authority; diagnostics cannot
    throw into the handler or retain the head/table/exception.
    """
    source = textwrap.dedent(inspect.getsource(core.Observer.handle))
    first = '                start, _, response_table = headers(head, strict=False)\n'
    last = '                validator = ResponseFraming(response_mode, response_count)\n'
    # Dedenting the method shifts its body eight columns relative to the file.
    first, last = first[4:], last[4:]
    start, end = source.index(first), source.index(last)
    block = source[start:end]
    helper = textwrap.dedent(block)
    helper = replace_once(helper, 'start, _, response_table = headers(head, strict=False)',
        "reason = 'HEADERS_REFUSED'\nstart, _, response_table = headers(head, strict=False)\n"
        "match = re.fullmatch(rb'HTTP/1\\.[01] ([1-5][0-9]{2})(?: [\\x20-\\x7e]*)?', start)\n"
        "status = int(match.group(1)) if match else None\nreason = 'STATUS_LINE_REFUSED'")
    helper = replace_once(helper, 'unsupported(response_table)',
        "reason = ('UPGRADE_REFUSED' if b'upgrade' in response_table else\n"
        "          'TRAILER_REFUSED' if b'trailer' in response_table else\n"
        "          'CONNECTION_UPGRADE_REFUSED' if b'upgrade' in response_table.get(b'connection', b'').lower() else\n"
        "          'FRAMING_REFUSED')\nunsupported(response_table)")
    helper = replace_once(helper, 'response_mode, response_count = framing(response_table)',
        "reason = ('TRANSFER_ENCODING_REFUSED' if b'transfer-encoding' in response_table and\n"
        "          b'content-length' not in response_table and response_table[b'transfer-encoding'].lower() != b'chunked' else\n"
        "          'FRAMING_REFUSED')\nresponse_mode, response_count = framing(response_table)")
    helper = replace_once(helper, 'if start.split(b" ", 2)[1] == b"204":',
        "reason = 'NO_CONTENT_FRAMING_REFUSED'\nif start.split(b\" \", 2)[1] == b\"204\":")
    helper = ('def _default_response_head(self, head, association):\n'
        '    status = None\n    try:\n' + textwrap.indent(helper, '        ') +
        '        return start, response_table, response_mode, response_count\n'
        '    except BaseException:\n        try:\n'
        '            self._default_response_head_emit(self, association, reason, status)\n'
        '        except BaseException:\n            pass\n        raise\n')
    namespace = dict(core.Observer.handle.__globals__)
    exec(compile(helper, '<default-response-head-diagnostic>', 'exec'), namespace)
    source = source[:start] + ('            start, response_table, response_mode, response_count = '
        '_default_response_head(self, head, association)\n') + source[end:]
    exec(compile(source, '<default-observer-response-only>', 'exec'), namespace)
    return namespace['handle'], namespace['_default_response_head']


def install_response_head_diagnostic(native, library, emit):
    """Preserve the pinned Peer association guard and inherited Core handler."""
    if (type(native) is not library.PeerNativeBroker or native.response_byte_passthrough is not False or
            getattr(native, '_default_response_head_emit', None) is not None or
            library.PeerNativeBroker.__mro__[1].handle is not library.CORE.Observer.handle):
        raise ValueError('DEFAULT_RESPONSE_HEAD_INSTANCE_SCOPE')
    handle, _ = derive_response_head_diagnostic(library.CORE)
    source = textwrap.dedent(inspect.getsource(library.PeerNativeBroker.handle))
    source = replace_once(source, 'return super().handle(client, association)',
                          'return _default_observer_handle(self, client, association)')
    namespace = dict(library.PeerNativeBroker.handle.__globals__)
    namespace['_default_observer_handle'] = handle
    exec(compile(source, '<default-peer-association-guard>', 'exec'), namespace)
    native._default_response_head_emit = emit
    native.handle = types.MethodType(namespace['handle'], native)


def record_response_head(owner, library, native, association, reason, status):
    """Closed metadata for the actual original-SID bound handler, at most16/node."""
    letter = next((key for key, broker in owner.peer_brokers.items() if broker.native is native), None)
    if letter not in ('a','b'):
        owner.result['default_response_head_diagnostic_status'] = 'UNKNOWN'
        return False
    broker = owner.peer_brokers[letter]
    rows = owner.result.setdefault('default_response_head_refusals', {'a':[], 'b':[]})[letter]
    if (type(association) is not library.CORE.Association or native.association is not association or
            broker.current_turn != (association.thread, association.turn) or
            owner.nodes[letter].get('thread') != association.thread or
            broker.current_attempt != association.attempt or type(native.posts) is not int or
            not 1 <= native.posts <= 16 or len(rows) >= 16 or reason not in RESPONSE_HEAD_REASONS or
            status is not None and (type(status) is not int or not 100 <= status <= 599)):
        owner.result['default_response_head_diagnostic_status'] = 'UNKNOWN'
        return False
    row = {'schema':'cicada.default-response-head-refusal.v1','node':letter,
        'thread_id':association.thread,'turn_id':association.turn,'attempt':association.attempt,
        'outbound_POST_send_attempts':native.posts,'response_status_code':status,'refusal_reason':reason,
        'raw_response_exported':False,'cause_proven':False}
    if len(json.dumps(row, separators=(',',':')).encode()) > 1024:
        owner.result['default_response_head_diagnostic_status'] = 'UNKNOWN'
        return False
    rows.append(row)
    owner.result.setdefault('default_response_head_diagnostic_status', 'OBSERVED')
    return True


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('DEFAULT_SOURCE_CONTEXT')
    return text.replace(old, new, 1)


def verify_package(path, receipt_path):
    path, receipt_path = Path(path), Path(receipt_path)
    raw = receipt_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PACKAGE_RECEIPT_SHA:
        raise ValueError('DEFAULT_PACKAGE_RECEIPT_PIN')
    receipt = json.loads(raw)
    if path != Path(receipt['root']) or path.resolve(strict=True) != path:
        raise ValueError('DEFAULT_PACKAGE_ROOT')
    actual = {}
    for item in path.rglob('*'):
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        name = str(item.relative_to(path))
        row = {'path':name, 'mode':oct(info.st_mode)}
        if stat.S_ISREG(info.st_mode):
            row.update(bytes=info.st_size, sha256=digest(item))
        elif stat.S_ISLNK(info.st_mode):
            row['target'] = os.readlink(item)
        else:
            raise ValueError('DEFAULT_PACKAGE_FILE_TYPE')
        actual[name] = row
    expected = {row['path']:row for row in receipt['rows'] + receipt['installer_aliases']}
    if actual != expected or len(actual) != 45:
        raise ValueError('DEFAULT_PACKAGE_CONTENTS')
    if actual['bin/codex']['sha256'] != CLI_SHA or actual['bin/codex']['bytes'] != CLI_BYTES:
        raise ValueError('DEFAULT_CLI_PIN')
    return receipt


def neutral_config(public):
    """Rename a historical provider identifier only in a new owned config."""
    import tomllib
    value = tomllib.loads(public)
    alias = value.get('model_provider')
    provider = value.get('model_providers', {}).get(alias, {})
    if alias not in ('basil', PROVIDER) or provider.get('base_url') != ORIGIN:
        raise ValueError('DEFAULT_PROVIDER_ORIGIN')
    if 'basil.xin' in public:
        raise ValueError('DEFAULT_MISLEADING_PROVIDER_DOMAIN')
    if alias != PROVIDER:
        public = replace_once(public, 'model_provider = "basil"', 'model_provider = "'+PROVIDER+'"')
        public = replace_once(public, '[model_providers.basil]', '[model_providers.'+PROVIDER+']')
    if provider.get("name") == "Basil relay":
        public = replace_once(public, 'name = "Basil relay"', 'name = "Cicada fixture provider"')
    return public


def default_runtime_config(public):
    """Apply the existing no-retry policy to the selected no-key Peer template."""
    import tomllib
    value = tomllib.loads(public)
    providers = value.get('model_providers', {})
    provider = providers.get(PROVIDER, {})
    if (value.get('model') != 'gpt-5.6-luna' or value.get('model_provider') != PROVIDER or
            value.get('sandbox_mode') != 'workspace-write' or value.get('approval_policy') != 'on-request' or
            value.get('approvals_reviewer', 'user') != 'user' or set(providers) != {PROVIDER} or
            set(provider) != {'name','base_url','requires_openai_auth','supports_websockets',
                              'wire_api','request_max_retries','stream_idle_timeout_ms'} or
            provider.get('base_url') != 'http://127.0.0.1:18767/v1' or
            provider.get('wire_api') != 'responses' or provider.get('stream_idle_timeout_ms') != 300000 or
            provider.get('requires_openai_auth') is not False or provider.get('supports_websockets') is not False or
            'env_key' in provider or provider.get('request_max_retries') != 4 or
            'stream_max_retries' in provider or value.get('features') is not None):
        raise ValueError('DEFAULT_PUBLIC_RUNTIME_CONFIG')
    public = replace_once(public, 'approval_policy = "on-request"', 'approval_policy = "never"')
    if 'approvals_reviewer' not in value:
        public = replace_once(public, 'approval_policy = "never"',
                              'approval_policy = "never"\napprovals_reviewer = "user"')
    public = replace_once(public, 'request_max_retries = 4', 'request_max_retries = 0\nstream_max_retries = 0')
    return public.replace('/var/log/cicada/codex', '/codex/logs')


BOOTSTRAP = '''import hashlib,json,os,pathlib,subprocess,sys
CLI='/opt/official-codex/bin/codex'
SHA='628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1'
for key in ('API_KEY','OPENAI_API_KEY','CODEX_API_KEY','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','CODEX_REMOTE','CODEX_THREAD_ID','CODEX_SESSION_ID','CICADA_NATIVE_SESSION_ID'):
 os.environ.pop(key,None)
os.environ.update(CODEX_HOME='/codex',HOME='/codex',PATH='/opt/official-codex/bin:/opt/official-codex/codex-path:/usr/local/bin:/usr/bin:/bin')
os.chdir('/workspace')
target=pathlib.Path('/state/managed-server-process.json')
def publish(value):
 temp=target.with_suffix('.tmp');temp.write_text(json.dumps(value)+'\\n');temp.chmod(0o600);temp.replace(target)
try:
 if hashlib.sha256(pathlib.Path(CLI).read_bytes()).hexdigest()!=SHA: raise ValueError('CLI_PIN')
 p=subprocess.run([CLI,'--version'],capture_output=True,timeout=5)
 if p.returncode or p.stdout.strip()!=b'codex-cli 0.162.1': raise ValueError('CLI_VERSION')
 # Default daemon owns its managed child.
 p=subprocess.run([CLI,'app-server','daemon','start'],capture_output=True,timeout=20)
 if p.returncode: raise ValueError('DAEMON_START')
 p=subprocess.run([CLI,'app-server','daemon','version'],capture_output=True,timeout=5)
 value=json.loads(p.stdout)
 if p.returncode or value.get('status')!='running' or value.get('appServerVersion')!='0.162.1' or value.get('socketPath')!='/codex/app-server-control/app-server-control.sock': raise ValueError('DAEMON_VERSION')
 managed=pathlib.Path(value.get('managedCodexPath',''))
 if not managed.is_absolute() or not managed.is_relative_to(pathlib.Path('/codex')) or hashlib.sha256(managed.read_bytes()).hexdigest()!=SHA: raise ValueError('MANAGED_CLI_PIN')
 publish({'exit_code':None,'daemon_status':'running','daemon_version':'0.162.1','logical_socket':value['socketPath'],'managed_cli_sha256':SHA})
except BaseException:
 publish({'exit_code':1,'daemon_status':'UNKNOWN'});raise
'''


def derive_start(source):
    """Change only the current selected ManagedGate daemon setup."""
    tree = ast.parse(source)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'start_managed_servers')
    text = textwrap.dedent(ast.get_source_segment(source, node))
    text = replace_once(text, 'public = base.isolated_runtime_config(Path(self.args.config_template).read_text())',
                        'public = default_runtime_config(Path(self.args.config_template).read_text())')
    text = replace_once(text, "for name in ('server_bootstrap.py', 'codex_queue_remote.py'):", "for name in ('server_bootstrap.py',):")
    text = replace_once(text, "path = node['paths']['codex'] / 'codex-appserver.sock'", "path = node['paths']['codex'] / 'app-server-control' / 'app-server-control.sock'")
    # Zero starts the same registered relay/owner, without a turn or key reader.
    text = replace_once(text, 'if self.args.run_native:\n                self.provider_forwarder(node)',
                        'self.provider_forwarder(node)')
    # Config comparisons use the new identifier, keeping the exact old policy.
    text = text.replace("'basil'", repr(PROVIDER))
    return text


def derive_flow(source):
    source = replace_once(source, "self.step('original_a_managed_ask')", "self.hold_default_bob()\n    self.step('original_a_managed_ask')")
    statement = "self.result['request_ids'] = {k: request[k] for k in ('request_id', 'message_id')}"
    source = replace_once(source, statement, statement + '\n    self.arm_default_pair(request)\n    self.release_default_bob()')
    return source


def default_bootstrap_argv(argv, owned_nodes):
    if argv[:2] == ['exec','-d'] and len(argv) > 4 and argv[3:5] == ['python3','/state/server_bootstrap.py']:
        if len(argv) != 7 or argv[2] not in owned_nodes or argv[5] not in ('paid','offline'):
            raise ValueError('DEFAULT_BOOTSTRAP_OWNED_ARGV')
        argv = list(argv)
        argv[4] = '/opt/peer/server_bootstrap.py'
    return argv


def publish_default_result(evidence, result, run_id):
    evidence=Path(evidence)
    parent=evidence.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or
            parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700 or
            evidence.resolve(strict=True)!=evidence or result.get('run_id')!=run_id):
        raise ValueError('DEFAULT_RESULT_PARENT_SCOPE')
    target=evidence/'result.json'
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        current=os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_uid!=os.getuid() or stat.S_IMODE(current.st_mode)!=0o600:
            raise ValueError('DEFAULT_RESULT_TARGET_SCOPE')
        with os.fdopen(fd,'r',closefd=False) as stream:
            raw=stream.read(4*1024*1024+1)
        if len(raw)>4*1024*1024 or json.loads(raw).get('run_id')!=run_id:
            raise ValueError('DEFAULT_RESULT_RUN_SCOPE')
    finally:
        os.close(fd)
    temporary=evidence/'default-result-final.tmp'
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(descriptor,'w') as stream:
            json.dump(result,stream,sort_keys=True,indent=2);stream.write('\n')
        after=target.lstat();parent_after=evidence.lstat()
        if ((after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=
                (current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_size,current.st_mtime_ns,current.st_ctime_ns) or
                (parent_after.st_dev,parent_after.st_ino,parent_after.st_mode,parent_after.st_uid)!=
                (parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid)):
            raise ValueError('DEFAULT_RESULT_TARGET_CHANGED')
        os.replace(temporary,target)
    finally:
        if temporary.exists():temporary.unlink()


def loaded_idle(rpc, sid):
    thread = rpc.request('thread/read', {'threadId':sid, 'includeTurns':False}).get('thread', {})
    queue = rpc.request('thread/queue/list', {'threadId':sid, 'limit':8})
    if (thread.get('id') != sid or thread.get('cwd') != '/workspace' or
            thread.get('status', {}).get('type') != 'idle' or
            queue.get('data') != [] or queue.get('nextCursor') is not None):
        raise ValueError('DEFAULT_LOADED_IDLE_EMPTY')


def materialized(node, sid):
    found = []
    for path in (node['paths']['codex'] / 'sessions').rglob('rollout-*.jsonl'):
        # Only this fixture's first session_meta; never full native histories.
        with path.open('rb') as stream:
            raw = stream.readline((1 << 20) + 1)
        if len(raw) > (1 << 20) or not raw.endswith(b'\n'):
            raise ValueError('DEFAULT_SESSION_META_BOUND')
        row = json.loads(raw)
        meta = row.get('payload', {})
        if row.get('type') == 'session_meta' and meta.get('id') == sid:
            if meta.get('cwd') != '/workspace':
                raise ValueError('DEFAULT_ORIGINAL_CWD')
            found.append(path)
    if len(found) != 1:
        raise ValueError('DEFAULT_ORIGINAL_SID_NOT_MATERIALIZED')


def readonly_pending(state_root, node_id, sid):
    database = Path(state_root) / 'nodes' / ('node-' + quote(node_id, safe='')) / 'inbox.sqlite'
    if not database.is_file() or database.is_symlink():
        raise ValueError('DEFAULT_INBOX_PATH')
    with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
        if db.execute('SELECT count(*) FROM node_inbox_deliveries WHERE session_id=?', (sid,)).fetchone()[0]:
            raise ValueError('DEFAULT_PREHOLD_DELIVERY_PRESENT')
        if db.execute('SELECT count(*) FROM node_inbox_attempts WHERE session_id=?', (sid,)).fetchone()[0]:
            raise ValueError('DEFAULT_PREHOLD_ATTEMPT_PRESENT')
    directory = Path(state_root) / '.native-writers'
    name = hashlib.sha256(('uid:1000\0codex\0'+sid).encode()).hexdigest()+'.lock'
    lock = directory / name
    if lock.exists():
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    operations = directory / (name+'.operations')
    if operations.exists() and any(operations.iterdir()):
        raise ValueError('DEFAULT_PREHOLD_WRITER_OPERATION_PRESENT')


def signal_agent(agent, number, verify_live):
    verify_live(agent)
    if not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('DEFAULT_PIDFD_SIGNAL_UNAVAILABLE')
    signal.pidfd_send_signal(agent.pidfd, number)


def wait_agent_state(agent, verify_live, *, stopped):
    end = time.monotonic()+1
    while True:
        if select.select([agent.pidfd], [], [], 0)[0]:
            if stopped: raise ValueError('DEFAULT_AGENT_EXITED_BEFORE_HOLD')
            return
        verify_live(agent)
        status = Path('/proc/'+str(agent.identity.pid)+'/status').read_text()
        state = next(line.split()[1] for line in status.splitlines() if line.startswith('State:'))
        if (state in ('T','t')) == stopped: return
        if time.monotonic() >= end: raise ValueError('DEFAULT_AGENT_STATE_UNKNOWN')
        time.sleep(.01)


def create_owned_roots(fixture):
    paths = [Path(fixture['private_root'])] + [Path(fixture['socket_roots'][n]) for n in 'ab']
    if len(set(paths)) != 3 or any(p.parent != Path('/tmp') or
            not p.name.startswith('cicada-dflt-g2-') or len(os.fsencode(p/'provider.sock')) > 103 for p in paths):
        raise ValueError('DEFAULT_OWNED_ROOT_SCOPE')
    owned = {}
    try:
        for path in paths:
            path.mkdir(mode=0o700)
            info = path.lstat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('DEFAULT_OWNED_ROOT_MODE')
            owned[path] = (info.st_dev,info.st_ino)
    except BaseException:
        remove_owned_roots(owned)
        raise
    return owned


def remove_owned_roots(owned):
    absent = {}
    for path, identity in owned.items():
        try:
            info = path.lstat()
            if (info.st_dev,info.st_ino) != identity or not stat.S_ISDIR(info.st_mode):
                raise ValueError('DEFAULT_OWNED_ROOT_CHANGED')
            path.rmdir()  # Only an empty, exact owned directory.
            absent[str(path)] = not os.path.lexists(path)
        except BaseException:
            absent[str(path)] = False
    return absent


def binding_lease(owner, letter, previous=None, minimum_until=None):
    from readonly_snapshot import rows
    node = owner.nodes[letter]
    fields = 'id,endpoint_id,principal_id,group_id,native_session_id,node_id,workspace_id,epoch,status,lease_owner,lease_expires_at,version'
    values = rows(owner, 'SELECT '+fields+' FROM session_bindings WHERE id=?', (node['binding_before']['id'],))
    if len(values) != 1:
        raise ValueError('DEFAULT_HOLD_BINDING_MISSING')
    row = values[0]
    pinned = node['binding_before']
    if (row['id'] != pinned['id'] or row['endpoint_id'] != node['endpoint'] or
            row['native_session_id'] != node['thread'] or row['node_id'] != node['node_id'] or
            row['epoch'] != pinned['epoch'] or row['status'] not in ('active', 'leased') or
            row['group_id'] != node['current_group_id'] or not row['principal_id'] or
            not row['lease_owner'] or not row['workspace_id'] or row['version'] < 1):
        raise ValueError('DEFAULT_HOLD_BINDING_SCOPE')
    if previous is not None and row != previous:
        raise ValueError('DEFAULT_HOLD_BINDING_CHANGED')
    expiry = datetime.datetime.fromisoformat(row['lease_expires_at'].replace('Z','+00:00')).timestamp()
    if expiry <= (time.time() if minimum_until is None else minimum_until):
        raise ValueError('DEFAULT_HOLD_BINDING_EXPIRED')
    return row, expiry


def fixture_source_identity(fixture, binding):
    """Separate execution bytes from immutable product/helper provenance."""
    version = fixture.get('schema')
    if (version not in ('cicada.native-default-peer-fixture.v1', FIXTURE_SCHEMA_V2) or
            fixture.get('product_revision') != binding['current_bundle']['current_commit'] or
            fixture.get('product_revision') != '328f5b5fa69571e67e7bb3e4582d5fb3bb920fd7'):
        raise ValueError('DEFAULT_DUAL_SOURCE_IDENTITY')
    if version == FIXTURE_SCHEMA_V2:
        fields = {'schema','fixture_revision','fixture_source_dirty','helper_producer_revision',
            'fixture_files','module_sha256','product_revision','socket_roots','private_root',
            'credential_path','official_package','origin_receipt','origin_receipt_sha256',
            'origin_url','package_receipt','runtime_image','runtime_receipt_path'}
        if (set(fixture) != fields or type(fixture.get('fixture_revision')) is not str or
                not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', fixture['fixture_revision']) or
                type(fixture.get('fixture_source_dirty')) is not bool or
                fixture.get('helper_producer_revision') != HELPER_PRODUCER_REVISION):
            raise ValueError('DEFAULT_EXECUTION_SOURCE_IDENTITY')
    elif fixture.get('fixture_revision') != HELPER_PRODUCER_REVISION:
        raise ValueError('DEFAULT_DUAL_SOURCE_IDENTITY')
    repo = Path('/home/zyf/CICADA')
    expected = {str(repo/'scripts/native_observer'/name) for name in
        ('request_observer_default.py','test_request_observer_default.py','request_observer_gate.py','request_observer_run.py')}
    rows = fixture.get('fixture_files')
    if type(rows) is not dict or set(rows) != expected:
        raise ValueError('DEFAULT_FIXTURE_SOURCE_ROWS')
    for raw_path, pin in rows.items():
        path = Path(raw_path)
        if (type(pin) is not str or not re.fullmatch('[0-9a-f]{64}',pin) or
                path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode) or digest(path) != pin):
            raise ValueError('DEFAULT_FIXTURE_SOURCE_CHANGED')
    if version == FIXTURE_SCHEMA_V2:
        public = binding.get('public_files', {})
        for name in ('request_observer_gate.py','request_observer_run.py'):
            path = str(repo/'scripts/native_observer'/name)
            if public.get(path, {}).get('sha256') != rows[path]:
                raise ValueError('DEFAULT_FIXTURE_BINDING_SOURCE')
        if fixture.get('module_sha256') != rows[str(repo/'scripts/native_observer/request_observer_default.py')]:
            raise ValueError('DEFAULT_FIXTURE_MODULE_PIN')
    return {'fixture_revision':fixture['fixture_revision'],
        'fixture_source_dirty':fixture['fixture_source_dirty'] if version == FIXTURE_SCHEMA_V2 else True,
        'fixture_files':dict(rows), 'helper_producer_revision':HELPER_PRODUCER_REVISION}


def check_fixture(fixture, binding):
    if type(fixture.get('socket_roots')) is not dict or set(fixture['socket_roots']) != {'a','b'}:
        raise ValueError('DEFAULT_SOCKET_ROOT_SHAPE')
    identity = fixture_source_identity(fixture, binding)
    repo = Path('/home/zyf/CICADA')
    head = subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,check=True,timeout=5).stdout.decode().strip()
    if head != identity['fixture_revision']:
        raise ValueError('DEFAULT_FIXTURE_REVISION')
    if fixture['schema'] == FIXTURE_SCHEMA_V2:
        changed = subprocess.run(['git','-C',str(repo),'status','--porcelain','--untracked-files=normal'],
            capture_output=True,check=True,timeout=5).stdout
        if bool(changed) is not identity['fixture_source_dirty']:
            raise ValueError('DEFAULT_FIXTURE_DIRTY_STATE')
    # Read-only comparison: fixture edits do not produce a new shipping binary.
    subprocess.run(['git','-C',str(repo),'diff','--exit-code',fixture['product_revision'],'--',
        'cicada-go','VERSION','LICENSE'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
    return identity


class Generations:
    def __init__(self, turns, brokers):
        self.turns, self.brokers = turns, brokers
        self.pending, self.receipts = {}, {}

    def arm(self, node, sid, request_id):
        if node in self.pending or node in self.receipts or self.turns.queue_thread(node) != sid:
            raise ValueError('DEFAULT_GENERATION_SCOPE')
        gen = self.brokers[node].arm_pending_start(sid)
        try:
            self.turns.arm_automatic(node, gen, sid)
        except BaseException:
            self.brokers[node].cancel_pending_start(gen)
            raise
        self.pending[node] = {'generation':gen, 'thread_id':sid, 'request_id':request_id,
            'expected_phase':{'b':'queued-question','a':'queued-reply'}[node]}

    def drained(self, node, generation):
        row = self.pending.get(node)
        if (row is None or row['generation'] != generation or
                self.turns.drained_generations.get(node) != generation or
                not self.turns.drained_turns.get(node)):
            raise ValueError('DEFAULT_GENERATION_DRAIN')
        self.receipts[node] = {**row, 'actual_turn_id':self.turns.drained_turns[node]}
        self.pending.pop(node)

    def cancel(self):
        for node, row in tuple(self.pending.items()):
            gen = row['generation']
            if self.turns.automatic_generations.get(node) == gen:
                self.brokers[node].cancel_pending_start(gen)
                self.turns.cancel_automatic(node, gen)
                self.pending.pop(node)


def register_default_agent(queue, pids, init_pid, argv, pins):
    """Reuse the pinned actual process checks, removing only wrapper fields."""
    import inspect
    source = inspect.getsource(queue.register_node_agent)
    tree = ast.parse(source)
    function = tree.body[0]
    function.name = '_register_default_agent'
    names = [a.arg for a in function.args.kwonlyargs]
    for name in ('wrapper_source_path','wrapper_source_sha256'):
        i = names.index(name)
        del function.args.kwonlyargs[i]; del function.args.kw_defaults[i]; names.pop(i)
    remove = [n for n in function.body if
        (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ('wrapper_source_path','wrapper_hash') for t in n.targets)) or
        (isinstance(n, ast.If) and ast.unparse(n.test) == 'wrapper_hash != wrapper_source_sha256')]
    if len(remove) != 3:
        raise ValueError('DEFAULT_AGENT_REGISTER_CONTEXT')
    function.body = [n for n in function.body if n not in remove]
    for n in ast.walk(function):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'AgentRegistration':
            if len(n.args) != 8:
                raise ValueError('DEFAULT_AGENT_RETURN_CONTEXT')
            n.args[5:7] = [ast.Constant(None), ast.Constant(None)]
    namespace = dict(queue.__dict__)
    exec(compile(ast.fix_missing_locations(tree), '<default-actual-node-registration>', 'exec'), namespace)
    agent = namespace['_register_default_agent'](pids, init_pid, argv,
        **pins, wrapper_runtime_path=CLI)
    return agent


def transform_peer(source):
    """Select the reviewed H5 Peer lane, retaining all broker trust checks."""
    tree = ast.parse(source)
    install = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'install')
    cls = next(n for n in install.body if isinstance(n, ast.ClassDef) and n.name == 'PeerGate')
    ctor = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
    # Never create/copy/mount the old queue shim or queue listener directory.
    ctor.body = [n for n in ctor.body if not
        (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'wrapper' for t in n.targets)) and not
        (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and 'wrapper.' in ast.unparse(n.value)) and not
        (isinstance(n, ast.Assign) and any(ast.unparse(t) == 'self.peer_queue_wrapper' for t in n.targets))]
    for n in ast.walk(ctor):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'isolated_config':
            n.args[0] = ast.Call(func=ast.Name(id='neutral_config',ctx=ast.Load()),args=[n.args[0]],keywords=[])
    setup = next(n for n in ctor.body if isinstance(n, ast.Try))
    setup.body = [n for n in setup.body if not (isinstance(n, ast.For) and 'tempfile.mkdtemp' in ast.unparse(n))]
    for n in ast.walk(ctor):
        if isinstance(n, ast.keyword) and n.arg == 'on_automatic_drained':
            n.value = ast.parse('self.default_generation_drained', mode='eval').body
        if isinstance(n, ast.keyword) and n.arg == 'sink':
            n.value = ast.parse('lambda event, letter=letter: self.default_count_event(letter, event)', mode='eval').body
    mounts = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'peer_mounts')
    mounts.body = [n for n in mounts.body if not (isinstance(n, ast.AugAssign) and '/run/peer-queue-control' in ast.unparse(n))]
    mounts.body.insert(-1, ast.parse("mounts += ['--mount', 'type=bind,src='+str(default_package)+',dst=/opt/official-codex,readonly']").body[0])
    start = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'start_managed_servers')
    index = next(i for i,n in enumerate(start.body) if isinstance(n, ast.Assign) and any(ast.unparse(t) == 'code' for t in n.targets))
    start.body[index:] = ast.parse("derived=types.FunctionType(original.__code__, ns, original.__name__, original.__defaults__, original.__closure__)\nreturn derived(self)").body
    services = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'start_services')
    services.body = ast.parse('return default_start_services(self, letter, base_cls, binding, credential_path, private_root)').body
    command = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'command')
    tls_scope = command.body[0]
    if (not isinstance(tls_scope, ast.If) or 'peer_tls_helper_state' not in ast.unparse(tls_scope.test) or
            not isinstance(command.body[-1], ast.Return)):
        raise ValueError('DEFAULT_TLS_COMMAND_CONTEXT')
    tls_scope.body += ast.parse('self.peer_tls_helper_state.default_admitted_argv = tuple(argv)').body
    command.body[-1:] = [ast.Try(body=[command.body[-1]], handlers=[], orelse=[], finalbody=
        ast.parse('self.peer_tls_helper_state.default_admitted_argv = None').body)]
    witness = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'queue_acceptance_witness')
    for i,n in enumerate(witness.body):
        if isinstance(n, ast.ImportFrom) and n.module == 'peer_native_queue_oracle':
            witness.body[i] = ast.parse('verify_queue_accepted = default_historical_verifier').body[0]
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if n.value == 'basil': n.value = PROVIDER
            elif n.value == "public['model_providers']['basil']['base_url']":
                n.value = "public['model_providers'][public['model_provider']]['base_url']"
    cleanup = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'cleanup')
    checks = [n for n in ast.walk(cleanup) if isinstance(n, ast.If) and
        'not complete or any(' in ast.unparse(n.test) and 'agent_pidfd_exit_observed' in ast.unparse(n.test)]
    if len(checks) != 1:
        raise ValueError('DEFAULT_CLEANUP_CONTEXT')
    checks[0].test = ast.parse("not complete or any(v.get('agent_pidfd_exit_observed') is not True for v in queue_stops.values())", mode='eval').body
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'


def default_start_services(owner, letter, base_cls, binding, credential_path, private_root):
    result = base_cls.start_services(owner, letter)
    queue = sys.modules['peer_queue_admission']
    pins_module = sys.modules['peer_gate_derivative_phase_current_drainfix20261010b']
    node = owner.nodes[letter]
    info = owner.default_owned_container(letter)
    required = {'/opt/official-codex':str(owner.default_package)}
    owner._default_verify_boundary(info, required, credential_path, private_root)
    if any(m['Destination'] in ('/run/peer-queue-control','/state/codex_queue_remote.py') for m in info['Mounts']):
        raise ValueError('DEFAULT_SHIM_MOUNT_FORBIDDEN')
    rows = owner.docker('top',info['Id'],'-eo','pid').decode().splitlines()
    if not 1 <= len(rows)-1 <= 128 or any(not row.strip().isdigit() for row in rows[1:]):
        raise ValueError('DEFAULT_AGENT_CENSUS')
    state_mounts = [m for m in info['Mounts'] if m['Destination']=='/fixture/node-'+letter+'-state']
    if len(state_mounts)!=1 or state_mounts[0]['Source']!=str(node['paths']['state']) or state_mounts[0].get('RW') is not True:
        raise ValueError('DEFAULT_WRITER_ROOT_MAPPING')
    agent = register_default_agent(queue, [int(row) for row in rows[1:]], info['State']['Pid'],
        queue.expected_node_agent_argv(node['node_id'],'/fixture/node-'+letter+'-state',node['tls_config']),
        pins_module.source_verified_agent_pin(binding, owner.native_package))
    owner.queue_agents[letter] = agent
    owner.result.setdefault('default_node_registration', {})[letter] = {
        **agent.public(), 'native_cli_sha256':CLI_SHA, 'native_cli':CLI,
        'default_daemon':True, 'queue_callback':False, 'queue_remote':False}
    return result


def close_default_rpc(owner, rpc):
    """Actual EOF and a joined reader are required independently of health."""
    try:
        if not rpc.shutdown_eof.is_set() or rpc.reader is threading.current_thread():
            raise RuntimeError('DEFAULT_RPC_EOF_OR_JOIN_UNKNOWN')
        rpc.reader.join(timeout=owner.policy.limit(1))
        if rpc.reader.is_alive():
            raise RuntimeError('DEFAULT_RPC_READER_ALIVE')
        rpc.close()
    except BaseException:
        for letter, candidate in owner.rpcs.items():
            if candidate is rpc:
                owner.result.setdefault('observer_shutdown', {})[letter] = 'UNKNOWN_RETAINED_SUBSCRIBER'
        raise


def default_cleanup_method(original, gate_module):
    """Preserve the pinned ownership wrapper; select only its cleanup body."""
    cells = dict(zip(original.__code__.co_freevars, original.__closure__ or ()))
    if 'original_cleanup' in cells:
        source = textwrap.dedent(inspect.getsource(original))
        if original.__name__ != 'cleanup' or source.count('return original_cleanup(self)') != 1:
            raise ValueError('DEFAULT_CLEANUP_CLOSURE_CONTEXT')
        replacement = default_cleanup_method(cells['original_cleanup'].cell_contents, gate_module)
        def cell(value): return (lambda: value).__closure__[0]
        closure = tuple(cell(replacement) if name == 'original_cleanup' else cells[name]
                        for name in original.__code__.co_freevars)
        return types.FunctionType(original.__code__, dict(original.__globals__),
                                  original.__name__, original.__defaults__, closure)
    source = getattr(original, '_g2_cap_source', None) or inspect.getsource(original)
    source = replace_once(textwrap.dedent(source), 'rpc.close();', '_default_close_rpc(self,rpc);')
    namespace = gate_module.method_namespace(original)
    namespace['_default_close_rpc'] = close_default_rpc
    exec(compile(source, '<default-joined-cleanup>', 'exec'), namespace)
    selected = gate_module.lifecycle_method(namespace[original.__name__], source, cleanup=True)
    def cleanup(owner):
        try: return selected(owner)
        finally:
            for letter in owner.rpcs:
                if owner.result.get('observer_shutdown', {}).get(letter) != 'EXPECTED_EOF_CONFIRMED':
                    owner.result.setdefault('observer_shutdown', {})[letter] = 'UNKNOWN_RETAINED_SUBSCRIBER'
    return cleanup


def install(base_cls, binding, normal_seconds, *, fixture, gate_module):
    """Explicitly selected by load_default_gate; execution GO stays upstream."""
    if normal_seconds != 600 or fixture.get('schema') not in ('cicada.native-default-peer-fixture.v1', FIXTURE_SCHEMA_V2):
        raise ValueError('DEFAULT_FIXTURE_SCOPE')
    if digest(__file__) != fixture.get('module_sha256'):
        raise ValueError('DEFAULT_MODULE_PIN')
    if binding['current_bundle']['runtime_receipt']['path'] != fixture.get('runtime_receipt_path'):
        raise ValueError('DEFAULT_RUNTIME_RECEIPT_BINDING')
    check_fixture(fixture, binding)
    verify_dependencies(binding)
    package = Path(fixture['official_package'])
    verify_package(package, fixture['package_receipt'])
    if fixture.get('runtime_image') != IMAGE or fixture.get('origin_url') != ORIGIN:
        raise ValueError('DEFAULT_RUNTIME_ORIGIN_PIN')
    if digest(fixture['origin_receipt']) != fixture.get('origin_receipt_sha256'):
        raise ValueError('DEFAULT_PUBLIC_ORIGIN_RECEIPT_PIN')
    library = load_dependency('peer_outer_broker', PEER/'peer_outer_broker.py')
    load_dependency('peer_queue_admission', PEER/'peer_queue_admission.py')
    load_dependency('peer_gate_derivative_phase_current_drainfix20261010b', PEER/'peer_gate_derivative_phase_current_drainfix20261010b.py')
    load_dependency('peer_native_queue_oracle', PEER/'peer_native_queue_oracle.py')
    load_dependency('peer_origin_proxy', PEER/'peer_origin_proxy.py')
    source = transform_peer((PEER/'peer_gate_derivative_g2_current_36eb_h5.py').read_text())
    namespace = {'__file__':str(PEER/'peer_gate_derivative_g2_current_36eb_h5.py'),
        '__name__':'cicada_default_peer_selected', 'default_package':package,
        'neutral_config':neutral_config,
        'default_start_services':default_start_services,
        'default_historical_verifier':gate_module.selected_historical_queue_verifier()}
    exec(compile(source, '<pinned-default-peer-selector>', 'exec'), namespace)
    original_bundle = namespace['source_bundle']
    def source_bundle():
        selected = original_bundle()
        selected['bootstrap'] = BOOTSTRAP
        # The old source terminates in exec; insert environment before exec.
        selected['agent'] = replace_once(selected['agent'], "os.execvp('/bin/sh'", "os.environ.update(CODEX_HOME='/codex',HOME='/codex',PATH='/opt/official-codex/bin:/opt/official-codex/codex-path:/usr/local/bin:/usr/bin:/bin')\nos.execvp('/bin/sh'")
        return selected
    namespace['source_bundle'] = source_bundle
    # Capture the pinned base family before DefaultGate overrides start_services.
    # Peer rewrites the original program before Candidate's zero guard sees it.
    original_codex = base_cls.start_services.__globals__['CODEX']
    zero_agent_programs = types.MappingProxyType({
        'CODEX':CLI, 'AGENT_BOOTSTRAP':source_bundle()['agent']})
    start_source = derive_start(gate_module.effective_sources(normal_seconds)['gate'])
    start_namespace = dict(base_cls.start_managed_servers.__globals__)
    start_namespace['default_runtime_config'] = default_runtime_config
    exec(compile(start_source, '<default-daemon-start>', 'exec'), start_namespace)
    flow_source = derive_flow(base_cls.managed_golden_flow._g2_selected_source)
    flow_namespace = dict(base_cls.managed_golden_flow.__globals__)
    exec(compile(flow_source, '<default-six-turn-flow>', 'exec'), flow_namespace)
    flow = flow_namespace['managed_golden_flow']; flow._g2_selected_source = flow_source
    derived_base = type('DefaultDaemonCandidate', (base_cls,), {
        'start_managed_servers':start_namespace['start_managed_servers'], 'managed_golden_flow':flow})
    # Parse the approved public origin using the same pinned native validator.
    import inspect
    origin_source = inspect.getsource(library.NATIVE.origin_receipt)
    origin_source = replace_once(origin_source, "'/opt/origin/ORIGIN.NONAUTH.json'", 'default_origin_path')
    origin_ns = dict(library.NATIVE.origin_receipt.__globals__)
    origin_ns['default_origin_path'] = fixture['origin_receipt']
    exec(compile(origin_source, '<default-public-origin>', 'exec'), origin_ns)
    origin = origin_ns['origin_receipt']()
    peer_cls = namespace['install'](derived_base, binding, normal_seconds,
        private_root=fixture['private_root'], origin=origin,
        credential_path=fixture['credential_path'], socket_roots=fixture['socket_roots'])
    verify_boundary = namespace['verify_runtime_boundary']
    # Candidate owns the outer source check. Keep that call and Peer cleanup;
    # replace only the existing legacy cleanup selected beneath Candidate.
    inherited_cleanup = next(cls.__dict__['cleanup'] for cls in base_cls.__mro__[1:]
                             if 'cleanup' in cls.__dict__)
    selected_cleanup = default_cleanup_method(inherited_cleanup, gate_module)

    class DefaultGate(peer_cls):
        _default_daemon_fixture = True
        _default_zero_agent_programs = zero_agent_programs
        default_package = package
        _default_verify_boundary = staticmethod(verify_boundary)

        def __init__(self, args):
            self._default_abort_lock = threading.Lock()
            self._default_abort_claimed = False
            self._default_abort_done = threading.Event()
            self._default_abort_owner = None
            self._default_abort_error = None
            self._default_cleanup_owner = None
            self._held_bob = None
            self._hold_lock = threading.RLock()
            self._hold_timer = None
            self._default_daemons_attempted = False
            self._daemon_stops = {}
            self._hold_failed = False
            self._count_rows = {'a':[], 'b':[]}
            self._count_unknown = set()
            self._default_owned_roots = create_owned_roots(fixture)
            try:
                super().__init__(args)
            except BaseException:
                remove_owned_roots(self._default_owned_roots)
                raise
            self.default_generations = Generations(self.peer_turns, self.peer_brokers)
            self._closed_lifecycle_cleanup = types.MethodType(selected_cleanup, self)
            # Observe the actual per-instance RealGuard before any bound turn;
            # retain Native's false branch and its existing 16-request cap.
            gate_module.install_owned_peer_response_metadata(self)
            for broker in self.peer_brokers.values():
                install_phase_capacity(broker.native, library)
                install_response_head_diagnostic(broker.native, library,
                    lambda native, association, reason, status:
                        record_response_head(self, library, native, association, reason, status))
            self.result['preparation_binding']['effective_policy']['model_provider'] = PROVIDER
            self.result['preparation_binding'].update(provider_origin=ORIGIN, native_default_daemon=True,
                queue_remote=False, queue_callback=False, native_account_identity='NOT_PROVEN')
            if fixture['schema'] == FIXTURE_SCHEMA_V2:
                self.result['preparation_binding']['default_fixture_source'] = fixture_source_identity(fixture, binding)
            self.result['default_native_route'] = {'daemon':'official-default','cli':CLI,
                'provider_identifier':PROVIDER, 'verified_origin':ORIGIN,
                'queue_callback':False, 'remote':False, 'native_account_identity':'NOT_PROVEN',
                'turns':6, 'manual':4, 'automatic':2, 'V67':'UNSUPPORTED'}

        def docker(self, *arguments, **kwargs):
            values = [str(v) for v in arguments]
            values = ['CICADA_CODEX_BIN='+CLI if v=='CICADA_CODEX_BIN='+original_codex else v for v in values]
            values = default_bootstrap_argv(values, {node['container'] for node in getattr(self,'nodes',{}).values()})
            return super().docker(*values, **kwargs)

        def build(self):
            super().build()
            self.result.update(acceptance_mode='packaging-reuse-default-daemon-codex-cli-0.162.1',
                fixture_source_revision=fixture['fixture_revision'],
                fixture_source_dirty=fixture['fixture_source_dirty'] if fixture['schema'] == FIXTURE_SCHEMA_V2 else True,
                helper_producer_revision=HELPER_PRODUCER_REVISION,
                product_generated_assets_domain='IMMUTABLE_328F_PACKAGE_AND_IMAGE',
                source_domain_comparison={
                    'Node':'clean 328f package; current tracked input inventory bytes equal; generated outputs bound to package',
                    'Hub':'COPY image of the same clean 328f package and generated outputs',
                    'helper':'actual 39bce dirty selected Go inputs and TLS overlay build',
                    'fixture':'execution revision/dirty and exact fixture bytes separately manifest pinned',
                    'Runtime':'official codex-cli 0.162.1 full package SHA pinned'})

        def default_owned_container(self, letter):
            node = self.nodes[letter]
            value = self.inspect('container', node['container'])
            if (value['Id'] != self.submitted_objects[('container',node['container'])]['id'] or
                    value['Image'] != IMAGE or value['State']['Running'] is not True or
                    (value['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id):
                raise ValueError('DEFAULT_EXACT_CONTAINER')
            return value

        def mapped_official_socket(self, letter, alias):
            if alias != self.nodes[letter]['paths']['codex']/'app-server-control/app-server-control.sock':
                raise ValueError('DEFAULT_LOGICAL_SOCKET')
            receipt = self.nodes[letter]['paths']['state']/'managed-server-process.json'
            if not receipt.exists(): return None
            value = json.loads(receipt.read_text())
            if value != {'exit_code':None,'daemon_status':'running','daemon_version':'0.162.1','logical_socket':LOGICAL,'managed_cli_sha256':CLI_SHA}:
                raise ValueError('DEFAULT_DAEMON_READY_RECEIPT')
            if not os.path.lexists(alias): return None
            if not alias.is_symlink() or os.readlink(alias) != PHYSICAL:
                raise ValueError('DEFAULT_HASHED_SOCKET')
            return super().mapped_official_socket(letter, alias)

        def start_managed_servers(self):
            self._default_daemons_attempted = True
            return super().start_managed_servers()

        def manual_turn(self, letter, *args, **kwargs):
            turn = super().manual_turn(letter, *args, **kwargs)
            if sum(n==letter for n,t in self.manual_turn_ids) == 1:
                node = self.nodes[letter]
                materialized(node, node['thread'])
                loaded_idle(self.rpcs[letter], node['thread'])
                self.result.setdefault('default_materialized_first_business_turn', {})[letter] = {
                    'thread_id':node['thread'], 'turn_id':turn, 'cwd':'/workspace', 'extra_seed_turns':0}
            return turn

        def hold_default_bob(self):
            if self._held_bob is not None:
                raise ValueError('DEFAULT_HOLD_REENTRY')
            node = self.nodes['b']; self.default_owned_container('b')
            queue = sys.modules['peer_queue_admission']
            agent = self.queue_agents['b']; queue._verify_agent_live(agent)
            loaded_idle(self.rpcs['b'], node['thread'])
            binding_row, expiry = binding_lease(self, 'b')
            duration = min(60, expiry-time.time()-5, self.policy.normal_end-time.monotonic()-5)
            if duration <= 0: raise ValueError('DEFAULT_HOLD_EXPIRED')
            self._held_binding = binding_row
            self._held_binding_until = time.time()+duration+2
            binding_lease(self, 'b', binding_row, self._held_binding_until)
            readonly_pending(node['paths']['state'], node['node_id'], node['thread'])
            # Set before STOP: uncertain signal failure still attempts CONT.
            self._held_bob = agent
            try:
                signal_agent(agent, signal.SIGSTOP, queue._verify_agent_live)
                wait_agent_state(agent, queue._verify_agent_live, stopped=True)
                self.default_owned_container('b')
                binding_lease(self, 'b', self._held_binding, self._held_binding_until)
                readonly_pending(node['paths']['state'], node['node_id'], node['thread'])
                self._hold_end = time.monotonic()+duration
                self._hold_timer = threading.Timer(duration, self.expire_default_hold)
                self._hold_timer.daemon=True; self._hold_timer.start()
            except BaseException:
                self.release_default_bob(); raise

        def expire_default_hold(self):
            self._hold_failed = True
            self.result['default_agent_hold'] = 'DEADLINE_EXPIRED'
            self.release_default_bob(emergency=True)

        def release_default_bob(self, emergency=False):
            with self._hold_lock:
                agent = self._held_bob
                if agent is None: return
                if self._hold_timer is not None: self._hold_timer.cancel()
                queue = sys.modules['peer_queue_admission']
                try:
                    if not emergency:
                        self.default_owned_container('b')
                        binding_lease(self, 'b', self._held_binding, time.time()+1)
                        node = self.nodes['b']
                        readonly_pending(node['paths']['state'], node['node_id'], node['thread'])
                    signal_agent(agent, signal.SIGCONT, queue._verify_agent_live)
                    wait_agent_state(agent, queue._verify_agent_live, stopped=False)
                except BaseException:
                    self._hold_failed = True
                    self.result['default_agent_hold'] = 'CONT_OR_AUTHORIZATION_UNKNOWN'
                    # Still attempt the exact retained pidfd; never prevent container cleanup.
                    try: signal.pidfd_send_signal(agent.pidfd, signal.SIGCONT)
                    except BaseException: pass
                    if not emergency: raise
                    return
                self._held_bob = None
                self.result['default_agent_hold'] = 'EXACT_AGENT_RESUMED'

        def wait_turn(self, letter, turn, timeout=None):
            if self._held_bob is not None:
                timeout = min(self._hold_end-time.monotonic(), 600 if timeout is None else timeout)
                if timeout <= 0: raise ValueError('DEFAULT_HOLD_DEADLINE')
            return super().wait_turn(letter, turn, timeout)

        def arm_default_pair(self, request):
            with self._hold_lock:
                if self._held_bob is None or time.monotonic() >= self._hold_end:
                    raise ValueError('DEFAULT_HOLD_NOT_CURRENT')
                self.default_owned_container('b')
                binding_lease(self, 'b', self._held_binding, self._held_binding_until)
                node = self.nodes['b']
                readonly_pending(node['paths']['state'], node['node_id'], node['thread'])
                from readonly_snapshot import rows
                durable = rows(self, 'SELECT request_id,message_id,sender_endpoint_id,receiver_endpoint_id,receiver_binding_id,receiver_binding_epoch,state FROM relay_v2_requests WHERE request_id=?', (request['request_id'],))
                expected = {'request_id':request['request_id'],'message_id':request['message_id'],'sender_endpoint_id':self.nodes['a']['endpoint'],'receiver_endpoint_id':node['endpoint'],'receiver_binding_id':node['binding_before']['id'],'receiver_binding_epoch':node['binding_before']['epoch'],'state':'OPEN'}
                if durable != [expected]: raise ValueError('DEFAULT_DURABLE_ASK_SCOPE')
                for letter in ('b','a'):
                    node = self.nodes[letter]
                    loaded_idle(self.rpcs[letter], node['thread'])
                    self.default_generations.arm(letter, node['thread'], request['request_id'])
                if time.monotonic() >= self._hold_end: raise ValueError('DEFAULT_HOLD_DEADLINE')

        def default_generation_drained(self, letter, generation):
            self.default_generations.drained(letter, generation)
            self.result['default_automatic_generations'] = dict(self.default_generations.receipts)

        def default_count_event(self, letter, event):
            row = {key:event.get(key) for key in ('status','binding_status','saw_marker','provider_attempt')}
            self.result.setdefault('outer_broker_events',{}).setdefault(letter,[]).append(row)
            try:
                library.CORE.validate_record(event)
            except BaseException:
                self._count_unknown.add(letter); return
            count = event.get('outbound_POST_count')
            if type(count) is not int or not 0 <= count <= 16 or len(self._count_rows[letter]) >= 32:
                self._count_unknown.add(letter); return
            self._count_rows[letter].append({key:event.get(key) for key in ('status','thread','turn','attempt','outbound_POST_count')})

        def abort_owned(self, error):
            # A second reader must not kill Nodes while the first is stopping
            # their exact official daemons. No lock spans CLI or reader waits.
            with self._default_abort_lock:
                if self._default_abort_claimed: return
                if self._default_cleanup_owner is not None:
                    self.result.setdefault('managed_abort_class', type(error).__name__)
                    self.result['default_abort_deferred_to_cleanup'] = True
                    return
                self._default_abort_claimed = True
                self._default_abort_owner = threading.get_ident()
                self._default_abort_error = error
            try:
                self.cleaning = True
                self.policy.cleanup()  # Fixed absolute ends; phase only.
                self.intentional_shutdown = True
                for rpc in getattr(self, 'rpcs', {}).values(): rpc.shutdown_expected = True
                self.default_close_admission()
                self.release_default_bob(emergency=True)
                if hasattr(self, 'default_generations'):
                    try: self.default_generations.cancel()
                    except BaseException: self._hold_failed = True
                if self._default_daemons_attempted: self.stop_default_daemons()
            except BaseException as cleanup_error:
                self.result['default_abort_cleanup_error_class'] = type(cleanup_error).__name__
            finally:
                # Original error/abort and exact kill fallback remain intact.
                try: super().abort_owned(error)
                finally: self._default_abort_done.set()

        def default_close_admission(self):
            # Existing callbacks refuse new admissions and cancel current I/O;
            # stop() requests cancellation without waiting for relay/RPC exit.
            callbacks = []
            proxy = getattr(self, 'peer_origin_proxy', None)
            if proxy is not None: callbacks.append(proxy.close_admission)
            callbacks.extend(broker.stop for broker in getattr(self, 'peer_brokers', {}).values())
            for close in callbacks:
                try: close()
                except BaseException as error:
                    self._hold_failed = True
                    self.result.setdefault('default_admission_close_errors', []).append(type(error).__name__)

        def stop_default_daemons(self):
            for letter in self.nodes:
                if self._daemon_stops.get(letter, {}).get('logical_absent') is True: continue
                try:
                    info = self.default_owned_container(letter)
                    self.docker('exec',info['Id'],'env','CODEX_HOME=/codex','HOME=/codex',CLI,'app-server','daemon','stop',timeout=5)
                    code="import os,socket,json; p='/codex/app-server-control/app-server-control.sock'; q="+repr(PHYSICAL)+"; print(json.dumps({'logical_absent':not os.path.lexists(p),'physical_absent':not os.path.lexists(q)}))"
                    observed=json.loads(self.docker('exec',info['Id'],'python3','-c',code,timeout=3))
                    if observed != {'logical_absent':True,'physical_absent':True}: raise ValueError('DEFAULT_DAEMON_STOP_UNKNOWN')
                    self._daemon_stops[letter]=observed
                except BaseException:
                    self._daemon_stops[letter]={'status':'UNKNOWN'}
            self.result['default_daemon_cleanup']=dict(self._daemon_stops)

        def stop_and_capture(self):
            self.intentional_shutdown = True
            for rpc in self.rpcs.values(): rpc.shutdown_expected = True
            self.stop_default_daemons()
            if any(v.get('status')=='UNKNOWN' for v in self._daemon_stops.values()):
                raise ValueError('DEFAULT_DAEMON_STOP_UNKNOWN')
            return super().stop_and_capture()

        def queue_acceptance_witness(self, request, reply):
            super().queue_acceptance_witness(request, reply)
            verified = {}
            for letter,message in (('b',request['message_id']),('a',reply['reply_message_id'])):
                row = self.default_generations.receipts.get(letter,{})
                if (row.get('request_id') != request['request_id'] or row.get('thread_id') != self.nodes[letter]['thread'] or
                        row.get('actual_turn_id') not in {t for n,t in self.budget.completed if n==letter} or
                        row.get('expected_phase') != {'b':'queued-question','a':'queued-reply'}[letter]):
                    raise ValueError('DEFAULT_AUTOMATIC_BUSINESS_CORRELATION')
                verified[letter]={**row,'message_id':message,'correlation':'EXISTING_NATIVE_CONTEXT_AND_DURABLE_QUEUE_ORACLES'}
            self.result['default_automatic_business_correlation']=verified

        def cleanup(self):
            self.cleaning = True
            self.policy.cleanup()  # Fixed start+normal+60; never extended.
            with self._default_abort_lock:
                if not self._default_abort_claimed:
                    self._default_cleanup_owner = threading.get_ident()
            if self._default_abort_claimed and not self._default_abort_done.is_set():
                if self._default_abort_owner == threading.get_ident():
                    self._hold_failed = True
                    self.result['default_abort_wait'] = 'UNKNOWN_SELF_CLEANUP'
                    raise RuntimeError('DEFAULT_ABORT_SELF_CLEANUP')
                try:
                    if not self._default_abort_done.wait(self.policy.limit(30)):
                        raise TimeoutError('DEFAULT_ABORT_CLEANUP_WAIT')
                except BaseException:
                    self._hold_failed = True
                    self.result['default_abort_wait'] = 'UNKNOWN'
                    # Only the existing exact-owned parent kill fallback. The
                    # original error is retained; no daemon/EOF proof is made.
                    super().abort_owned(self._default_abort_error)
            # Mark expected transport closure before any owned daemon stop,
            # including failure cleanup. Existing RPC/Guard failures remain.
            self.intentional_shutdown = True
            for rpc in getattr(self, 'rpcs', {}).values(): rpc.shutdown_expected = True
            self.default_close_admission()
            self.release_default_bob(emergency=True)
            if hasattr(self,'default_generations'):
                try: self.default_generations.cancel()
                except BaseException: self._hold_failed=True
            if self._default_daemons_attempted and (not self._default_abort_claimed or self._default_abort_done.is_set()):
                self.stop_default_daemons()
            stopped=dict(self._daemon_stops)
            try:
                return super().cleanup()
            finally:
                roots=remove_owned_roots(self._default_owned_roots)
                self.result['default_owned_host_roots_absent']=roots
                if len(roots)!=3 or any(v is not True for v in roots.values()): self._hold_failed=True
                try: check_fixture(fixture, binding)
                except BaseException: self._hold_failed=True; self.result['default_fixture_sources_unchanged']=False
                else: self.result['default_fixture_sources_unchanged']=True
                self.result['default_daemon_cleanup']=stopped
                counts={}
                for letter,broker in self.peer_brokers.items():
                    native=broker.native
                    rows=self._count_rows[letter]
                    complete=(letter not in self._count_unknown and native.idle.is_set() and broker.handler_done.is_set() and
                        broker.owner_done.is_set() and len(rows)==native.connections and
                        0<=native.posts<=native.connections<=16 and
                        all(type(r['outbound_POST_count']) is int and 0<=r['outbound_POST_count']<=native.posts for r in rows) and
                        (not rows or max(r['outbound_POST_count'] for r in rows)==native.posts))
                    counts[letter]={'status':'COMPLETE' if complete else 'UNKNOWN',
                        'outbound_POST_send_attempts':native.posts,'auxiliary_included':True,
                        'provider_processed_or_billing_count':'NOT_PROVEN','cap':16}
                self.result['default_provider_post_attempts']=counts
                self.result['default_phase_capacity']={letter:phase_capacity_snapshot(broker.native)
                    for letter,broker in self.peer_brokers.items()}
                if (self.result.get('terminal_exit_code') != 0 or self._hold_failed or self._held_bob is not None or set(stopped)!={'a','b'} or any(v.get('status')=='UNKNOWN' for v in stopped.values()) or
                        set(counts)!={'a','b'} or any(v['status']!='COMPLETE' for v in counts.values())):
                    self.result['terminal_exit_code']=1; self.result['status']='FAIL'
                # Inherited cleanup persists before the Peer owner joins. Publish
                # the final owned result after these mandatory stop/count checks.
                if getattr(self,'evidence',None) is not None:
                    publish_default_result(self.evidence,self.result,self.run_id)
    return DefaultGate



DEPENDENCY_PINS = {'/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_ingress_runtime.py': 'cccc05a2e84c83269628c237ea290796e1fc2e0b88edf226cd3066a86839ab53', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_local_ingress.py': 'df47d4c8e6ae83986e4f0debf41241fa3491c0288c201d0187b47ea8b634b8fa', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_native_queue_oracle.py': '1911e57241729c663d4b4eb844b4e049f6f226c366fa5c045135c7ed509bafe7', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_outer_broker.py': '1dd4098780920974a3a55fe054f6c23c995e3bd0eba92775aa9420196183ca21', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_queue_admission.py': 'd75bd1b670fefb9cd1e8f86194e2b921ca60cffe25ad0bd169b0b72979f1774b', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-worker-0162-candidate/native_broker.py': '7865535b75875d9ead2ea136a7bd1a4926ba52be502f058be9e12f12d8cf029b', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-worker-0162-candidate/runtime_common.py': 'f5e585ef8636820dcf0680bf2fdbc44f31ab1f0b442bef983f320995ea321318', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/synthetic_https_broker_candidate.py': '5e3909045385fe2c9627d4b2a340bb1c520d53da2fe8ca138fee39ce5390da64', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/synthetic_uds_transport_candidate.py': '67ca4c857850a9a8679627c18ee37ba2ab3a02985548517e619cacf062a730b3', '/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/managed/server_bootstrap.py': '0eeaf6cee3c2485e3718ad9bdedf4394e46d5c689c9b683f7bedae49b536db79', '/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/test-two-node-codex-native.py': 'ceb3f94d55bd22a54cec655dc798e743670ffc7c80daeb7aa058f5d5f231e3f0', '/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/managed/migration.py': '7f34ea1ae1227d5fc81068eff6f5f03255f8e7c959bfa7f5ec431afc355911ea', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_origin_proxy.py': 'ac3faba284a20207226e8829815619473a256718cf4967268a41f28c5defa775', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_gate_derivative_g2_current_36eb_h5.py': 'bc202e8e0c3f65367dbc93e67c587bf38267a6a93542facd22cf53bcbe7c1ba0', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/peer_gate_derivative_phase_current_drainfix20261010b.py': '149348f5d7a533aaf2df122d3584e30db743f6ea5edcff453b3712bb40202b4c', '/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/peer-outer-broker-20261009a/WIRING-MANIFEST-PEER-ORIGIN-PROXY-G2-CURRENT-36EB-H3.NONAUTH.json': '151ccd233e3b5d0fbaa5af031ff7925c830dc58ef69079ed8688b6e42dd7988d'}


DEPENDENCY_PINS[str(PHASE_OVERLAY)] = PHASE_OVERLAY_SHA


def verify_dependencies(binding):
    # All imported legacy helpers were already enumerated by current binding.
    for raw_path, row in binding['public_files'].items():
        path=Path(raw_path)
        if path.suffix == '.py' and (path.resolve(strict=True)!=path or digest(path)!=row['sha256']):
            raise ValueError('DEFAULT_CURRENT_BINDING_DEPENDENCY')
    for raw_path, expected in DEPENDENCY_PINS.items():
        path=Path(raw_path)
        if path.resolve(strict=True)!=path or not stat.S_ISREG(path.lstat().st_mode) or digest(path)!=expected:
            raise ValueError('DEFAULT_DEPENDENCY_PIN')


def load_dependency(name, path):
    path=Path(path)
    if str(path) not in DEPENDENCY_PINS or digest(path)!=DEPENDENCY_PINS[str(path)]:
        raise ValueError('DEFAULT_IMPORT_PIN')
    existing=sys.modules.get(name)
    if existing is not None:
        if Path(existing.__file__).resolve()!=path:
            raise ValueError('DEFAULT_IMPORT_ORIGIN')
        return existing
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module)
    return module
