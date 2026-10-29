#!/usr/bin/env python3
"""Actual Codex 0.164 daemon, native A/B and production MCP peer forms.

The owned app-server client answers real Host form requests using their opaque
options. This measures the actual Host relay, not physical Windows/TUI form UI.
Only the installed Hook/Node may issue actor proofs. The Go parent owns actual
App policy, Hub, Node, read-only database audits and revocation checkpoints.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from codex_domain_host import (observed_operation_status, DomainHostCLI, StaticHostProvider, output_objects,
                               require_successful_output, unique_output_field)
from codex_product_cli import digest, private_json


TOOLS = ('cicada_whoami', 'cicada_select_peer', 'cicada_ask', 'cicada_receive',
         'cicada_reply', 'cicada_operation_status')
OWNER_GROUP_TOOLS = TOOLS + ('cicada_groups', 'cicada_use_group', 'cicada_find',
                             'cicada_resolve', 'cicada_send', 'cicada_operation_retry')
CODEX_SHA256 = 'b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306'
PEER_CODES = ('PEER_DIRECTORY_EMPTY', 'PEER_FORM_UNSUPPORTED', 'PEER_SELECTION_INVALID',
              'PEER_SELECTION_STALE', 'MCP_FORM_DECLINED', 'MCP_FORM_CANCELLED',
              'MCP_FORM_INVALID', 'MCP_FORM_TIMEOUT', 'MCP_FORM_UNAVAILABLE',
              'NETWORK_SESSION_UNAVAILABLE', 'CODEX_CALL_CONTEXT_REQUIRED', 'CODEX_NODE_TICKET_UNAVAILABLE')
HOST_FORM_POLICY = {'mcp_elicitations': True, 'rules': False, 'sandbox_approval': False,
                    'skill_approval': False, 'request_permissions': False}


def peer_output_diagnostic(value):
    rows = list(output_objects(value))
    texts = [r['text'] for r in rows if isinstance(r.get('text'), str)]
    if isinstance(value, str):
        texts.append(value)
    encoded = json.dumps(value)
    codes = [c for c in PEER_CODES if re.search(r'(?<![A-Z0-9_])' + c + r'(?![A-Z0-9_])', encoded)]
    kinds = set()
    for text in texts:
        if any(text.startswith(c + ':') for c in PEER_CODES):
            kinds.add('DIRECT_TYPED_ERROR')
        elif any(text.startswith('Error: ' + c + ':') for c in PEER_CODES):
            kinds.add('HOST_ERROR_PREFIX')
        elif text.lstrip().startswith(('{', '[')):
            kinds.add('JSON')
        elif text.startswith('Wall time: '):
            kinds.add('HOST_TIME_HEADER')
        else:
            kinds.add('OTHER')
    return {'codes': codes, 'text_kinds': sorted(kinds), 'text_blocks': len(texts),
            'root_array': isinstance(value, list), 'is_error_flag_present': any('isError' in r for r in rows)}


def require_host_refusal(value, codes=(), http_statuses=()):
    """Codex may preserve only MCP content blocks, without outer isError.

    Require the exact finite Cicada refusal code/status in the actual Host
    result, never an arbitrary error. If the MCP flag survives it must be true.
    Call-specific form/actor correlation and parent database audits are separate.
    """
    rows = list(output_objects(value))
    assert not any('isError' in r and r['isError'] is not True for r in rows), 'REFUSAL_CONTAINS_NON_ERROR_FLAG'
    assert not any(r.get(k) for r in rows for k in ('peer_selection_id', 'request_id', 'operation_id')), 'REFUSAL_CREATED_SUCCESS_COORDINATES'
    encoded = json.dumps(value)
    found = {c for c in PEER_CODES if re.search(r'(?<![A-Z0-9_])' + c + r'(?![A-Z0-9_])', encoded)}
    statuses = {int(n) for n in re.findall(r'Cicada Hub (401|403)\b', encoded)}
    assert found.intersection(codes) or statuses.intersection(http_statuses), 'EXPECTED_TYPED_HOST_REFUSAL_MISSING'
    return found


class PeerFormCLI(DomainHostCLI):
    """Use original app-server IDs; never turn a UI answer into an actor proof."""

    active_form = None

    def literal_admit(self, provider, label, name):
        before = provider.request_counts()['literal']
        prompt = 'cicada join ' + json.dumps(name)
        title = 'Local collaboration joined'
        sid = self.literal(label, prompt, title, registered_name=name)
        assert provider.request_counts()['literal'] == before, 'LITERAL_REACHED_PROVIDER'
        text = (self.root / ('cli-' + label) / 'tui.txt').read_text()
        compact = re.sub(r'\s+', '', text)
        echo = '›' + re.sub(r'\s+', '', prompt)
        assert echo in compact, 'CURRENT_LITERAL_PROMPT_NOT_VISIBLE'
        result = compact.rsplit(echo, 1)[1]
        assert (result.count(re.sub(r'\s+', '', title)) == 1 and
                re.sub(r'\s+', '', name) in result and str(self.workspace) in result), 'ACTUAL_LITERAL_FIELDS_MISSING'
        records = [row for row in self.native_metadata() if row['id'] == sid]
        assert (len(records) == 1 and records[0]['cwd_matches_original'] and
                records[0]['uid_matches_current'] and records[0]['open_inode_matches']), 'ORIGINAL_NATIVE_RECORD_MISMATCH'
        return sid, records[0]

    def answer_form(self, request):
        active = self.active_form
        assert active is not None and request.get('method') == 'mcpServer/elicitation/request', 'UNEXPECTED_HOST_SERVER_REQUEST'
        assert type(request.get('id')) in (int, str), 'HOST_FORM_REQUEST_ID_INVALID'
        p = request.get('params', {})
        assert (isinstance(p, dict) and p.get('threadId') == active['sid'] and
                p.get('serverName') == active['server'] and p.get('mode') == 'form'), 'HOST_FORM_ACTOR_CORRELATION_FAILED'
        turn = p.get('turnId')
        assert turn is None or isinstance(turn, str) and turn, 'HOST_FORM_TURN_INVALID'
        if active['turn_id'] is not None and turn is not None:
            assert turn == active['turn_id'], 'HOST_FORM_TURN_MISMATCH'
        assert not active['forms'], 'HOST_FORM_DUPLICATED'
        schema = p.get('requestedSchema')
        # Codex's typed app-server projection has no root additionalProperties
        # field. The raw production MCP wire is checked separately by the real
        # stdio Network lane; do not invent a field the Host does not expose.
        assert (isinstance(schema, dict) and schema.get('type') == 'object' and
                schema.get('required') == ['peer'] and
                ('additionalProperties' not in schema or schema['additionalProperties'] is False) and
                set(schema.get('properties', {})) == {'peer'}), 'HOST_FORM_TYPED_SCHEMA_INVALID'
        prop = schema['properties']['peer']
        choices = prop.get('oneOf')
        assert (prop.get('type') == 'string' and isinstance(choices, list) and
                0 < len(choices) <= 64), 'HOST_FORM_CHOICES_INVALID'
        assert all(isinstance(c, dict) and set(c) == {'const', 'title'} and
                   isinstance(c['const'], str) and c['const'] and
                   isinstance(c['title'], str) and c['title'] for c in choices), 'HOST_FORM_CHOICE_INVALID'
        assert len({c['const'] for c in choices}) == len(choices), 'HOST_FORM_CHOICE_DUPLICATED'
        # Match only actual display metadata from the finite authorized result.
        # There is deliberately no "pick the first peer" fallback.
        matches = [c for c in choices if active['name'] in c['title'] and active['workspace'] in c['title']]
        assert len(matches) == 1, 'HOST_FORM_EXACT_TARGET_LABEL_MISSING_OR_AMBIGUOUS'
        result = {'action': active['action']}
        if active['action'] == 'accept':
            result['content'] = {'peer': matches[0]['const']}
        active['forms'].append({'turn': turn, 'request_id_sha256': hashlib.sha256(
            json.dumps(request['id']).encode()).hexdigest(), 'option_count': len(choices),
            'schema_sha256': hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
            'action': active['action']})
        # Exact request ID is a transport correlation, never a capability.
        self.send_message({'id': request['id'], 'result': result})

    def rpc(self, method, params):
        if not hasattr(self, 'notifications'):
            self.notifications = collections.deque()
        self.last_method = method
        self.sequence += 1
        number = self.sequence
        self.send_message({'id': number, 'method': method, 'params': params})
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            reply = self.messages.get(timeout=max(.01, deadline - time.monotonic()))
            if isinstance(reply, Exception):
                raise reply
            if reply.get('id') == number and 'method' not in reply:
                assert 'error' not in reply, 'ACTUAL_DAEMON_RPC_REFUSED'
                return reply['result']
            if 'id' in reply:
                self.answer_form(reply)
            else:
                assert len(self.notifications) < 512, 'ACTUAL_DAEMON_NOTIFICATION_BOUND'
                self.notifications.append(reply)
        raise RuntimeError('ACTUAL_DAEMON_RPC_TIMEOUT')

    def host_call(self, provider, sid, label, tool, arguments, form=None):
        assert self.active_form is None, 'HOST_FORM_OVERLAP'
        provider.reset_diagnostic()
        self.peer_diagnostic = None
        assert sid in self.native_records(), 'HOST_THREAD_NOT_CREATED_BY_NATIVE_TUI'
        assert self.daemon_identity() == self.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
        resumed = self.rpc('thread/resume', {'threadId': sid})
        assert (resumed['thread']['id'] == sid and
                resumed['thread']['cwd'] == str(self.workspace)), 'ACTUAL_ORIGINAL_THREAD_SCOPE_CHANGED'
        policy = resumed.get('approvalPolicy', {})
        granular = policy.get('granular') if isinstance(policy, dict) else None
        assert (isinstance(granular, dict) and not (set(granular) - set(HOST_FORM_POLICY)) and
                all(type(granular.get(k, False)) is bool and granular.get(k, False) is v
                    for k, v in HOST_FORM_POLICY.items()) and
                resumed.get('approvalsReviewer') == 'user'), 'HOST_MCP_FORM_POLICY_NOT_EFFECTIVE'
        self.host_policy_observed = True
        self.await_idle(sid)
        if form is not None:
            assert tool == 'cicada_select_peer' and form['action'] in ('accept', 'decline', 'cancel'), 'HOST_FORM_ACTION_INVALID'
            self.active_form = {**form, 'sid': sid, 'turn_id': None, 'forms': []}
        try:
            provider.begin(label, tool, arguments, sid)
            started = self.rpc('turn/start', {'threadId': sid,
                'input': [{'type': 'text', 'text': 'SYNTHETIC LOCAL DOMAIN HOST TOOL ' + label}]})
            turn_id = started['turn']['id']
            if self.active_form is not None:
                self.active_form['turn_id'] = turn_id
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                event = self.notifications.popleft() if self.notifications else self.messages.get(timeout=max(.01, deadline - time.monotonic()))
                if isinstance(event, Exception):
                    raise event
                if 'id' in event:
                    self.answer_form(event)
                    continue
                params = event.get('params', {})
                if (event.get('method') == 'turn/completed' and params.get('threadId') == sid and
                        params.get('turn', {}).get('id') == turn_id):
                    assert params['turn']['status'] == 'completed' and not params['turn'].get('error'), 'ACTUAL_NATIVE_HOST_TURN_FAILED'
                    output, summary = provider.finish(turn_id)
                    self.peer_diagnostic = peer_output_diagnostic(output)
                    forms = [] if self.active_form is None else self.active_form['forms']
                    assert form is None or len(forms) == 1, 'ACTUAL_HOST_FORM_NOT_OBSERVED'
                    assert all(f['turn'] in (None, turn_id) for f in forms), 'HOST_FORM_TURN_MISMATCH'
                    assert self.daemon_identity() == self.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
                    summary['forms'] = [{k: v for k, v in f.items() if k != 'turn'} for f in forms]
                    return output, summary
            raise RuntimeError('ACTUAL_NATIVE_HOST_TURN_TIMEOUT')
        finally:
            self.active_form = None


def run_owner_groups(config):
    """Extend this Host driver; the Go parent owns actual App actions/Guards.

    Checkpoints mean observed transport only. Only the parent can emit M1-M8
    acceptance after checking actual authority, DB, crypto and lease evidence.
    """
    os.umask(0o077)
    assert config['codex_sha256'] == CODEX_SHA256 and config['daemon_umask'] == '0002'
    cli = PeerFormCLI(config)
    workspaces = [Path(p) for p in config['workspaces']]
    assert len(workspaces) == 4 and len(set(workspaces)) == 4
    assert all(p.is_dir() and p.is_relative_to(cli.root) for p in workspaces)
    control = Path(config['control'])
    control.mkdir(mode=0o700)
    provider = StaticHostProvider(str(cli.root))
    provider.capture_nonce_hash = True
    result = {'scope': 'ACTUAL_OWNER_GROUP_HOST_TRANSPORT_NOT_PRODUCT_ACCEPTANCE', 'status': 'FAIL',
              'real_model_turns': 0, 'Windows_DPAPI_ACL_GUI': 'NOT_RUN'}
    phase, started, restarts = 'SETUP', False, 0
    ids, summaries, nonces, retired_nonces = [], [], {}, {}
    histories = {}

    bootstrap_sequence = 0

    def bootstrap_progress(stage, actor=None):
        nonlocal phase, bootstrap_sequence
        phase = stage
        value = {'scope': 'CLOSED_HOST_BOOTSTRAP_PROGRESS_NOT_ACCEPTANCE',
                 'phase': stage, 'host_pid': os.getpid(), 'daemon_started': started,
                 'original_native_thread_count': len(ids)}
        if actor is not None:
            value['actor'] = actor
        private_json(control / ('0.progress-' + str(bootstrap_sequence) + '.json'), value)
        bootstrap_sequence += 1

    def conserve_native_history():
        previous_workspace = cli.workspace
        try:
            for index, sid in enumerate(ids):
                cli.workspace = workspaces[index]
                records = cli.native_records()
                assert sid in records, 'OWNER_GROUP_ORIGINAL_RECORD_LOST'
                path = Path(records[sid]['path'])
                assert path.is_relative_to(cli.codex_home / 'sessions') and not path.is_symlink(), 'OWNER_GROUP_RECORD_PATH_CHANGED'
                size = path.stat().st_size
                assert 0 < size <= 64 * 1024 * 1024, 'OWNER_GROUP_RECORD_SIZE'
                prior = histories.get(sid)
                if prior is not None:
                    assert path == prior['path'] and size >= prior['size'], 'OWNER_GROUP_NATIVE_HISTORY_REPLACED'
                current_hash = hashlib.sha256()
                with path.open('rb') as stream:
                    if prior is not None:
                        remaining = prior['size']
                        while remaining:
                            block = stream.read(min(65536, remaining))
                            assert block, 'OWNER_GROUP_NATIVE_HISTORY_TRUNCATED'
                            current_hash.update(block)
                            remaining -= len(block)
                        assert current_hash.hexdigest() == prior['digest'], 'OWNER_GROUP_NATIVE_HISTORY_REWRITTEN'
                    remaining = size - (prior['size'] if prior is not None else 0)
                    while remaining:
                        block = stream.read(min(65536, remaining))
                        assert block, 'OWNER_GROUP_NATIVE_HISTORY_TRUNCATED'
                        current_hash.update(block)
                        remaining -= len(block)
                histories[sid] = {'path': path, 'size': size, 'digest': current_hash.hexdigest()}
        finally:
            cli.workspace = previous_workspace

    def close_proxy():
        if not hasattr(cli, 'proxy'):
            return
        cli.proxy.stdin.close()
        try:
            cli.proxy.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cli.proxy.kill()
            cli.proxy.wait()
        cli.proxy_log.close()
        del cli.proxy

    def create_native_tui(index):
        # A normal prompt through the real TUI/Host creates its native record.
        # The local static provider returns neutral text, with no Cicada tool,
        # implicit Join, model service or fabricated record/SID.
        label = 'owner-create-' + 'abcd'[index]
        prompt = 'SYNTHETIC_OWNER_GROUP_NATIVE_CREATE_' + provider.scope + '_' + label
        prior = cli.state
        cli.state = cli.root / ('cli-' + label)
        cli.state.mkdir(mode=0o700)
        keys = ('literal_prompt', 'literal_expected', 'literal_resume_sid')
        previous = {key: cli.config.get(key) for key in keys}
        try:
            provider.expect_native_seed(prompt)
            cli.actual_result_ready = lambda: provider.native_seed_inputs[prompt]['posts'] == 1
            cli.actual_before_tui_exit = lambda: cli.await_idle(provider.native_seed_inputs[prompt]['sid'])
            cli.config.update(literal_prompt=prompt, literal_expected='SYNTHETIC STATIC HOST RESPONSE; NO REAL MODEL', literal_resume_sid=None)
            sid = cli.literal_tui(cli.inventory(label + '-before'))
            observed = provider.native_seed_inputs[prompt]
            assert observed['sid'] == sid and observed['posts'] == 1, 'OWNER_GROUP_REAL_NATIVE_SEED_MISMATCH'
            records = [row for row in cli.native_metadata() if row['id'] == sid]
            assert (len(records) == 1 and records[0]['cwd_matches_original'] and records[0]['uid_matches_current'] and
                    records[0]['open_inode_matches']), 'OWNER_GROUP_ORIGINAL_NATIVE_RECORD_INVALID'
            return sid
        finally:
            cli.state = prior
            del cli.actual_result_ready
            del cli.actual_before_tui_exit
            for key, value in previous.items():
                if value is None:
                    cli.config.pop(key, None)
                else:
                    cli.config[key] = value

    def register_cli(index, sid):
        binary = Path(config['selected_root']) / 'components/node/bin/cicada'
        assert digest(binary) == config['cicada_sha256'], 'OWNER_GROUP_REGISTRATION_BINARY_CHANGED'
        arguments = [str(binary), 'join', '--thread', sid, '--name', 'Synthetic Owner Group ' + 'ABCD'[index],
                     '--user-root', config['selected_root']]
        with (cli.root / ('private-cli-register-' + 'abcd'[index] + '.log')).open('xb') as log:
            completed = subprocess.run(arguments, env=cli.environment, cwd=cli.workspace,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=45)
        assert completed.returncode == 0, 'OWNER_GROUP_ACTUAL_CLI_REGISTRATION_FAILED'
        assert digest(binary) == config['cicada_sha256'] and sid in cli.native_records(), 'OWNER_GROUP_CLI_REPLACED_NATIVE_RECORD'

    def trust_actual_pretool(index, sid):
        # Resume that same TUI and let its normal hook-trust control act on a
        # real Cicada call. Never inject trust hashes or fake a UserPromptSubmit.
        label = 'owner-pretool-' + 'abcd'[index]
        provider.begin(label, 'cicada_groups', {'limit': 64}, sid)
        cli.actual_result_ready = lambda: provider.phase is not None and provider.phase['posts'] == 2 and provider.phase['output_received']
        cli.actual_before_tui_exit = lambda: cli.await_idle(sid)
        try:
            resumed = cli.literal(label, 'SYNTHETIC LOCAL DOMAIN HOST TOOL ' + label,
                                  'SYNTHETIC STATIC HOST RESPONSE; NO REAL MODEL', resume=sid)
        finally:
            del cli.actual_result_ready
            del cli.actual_before_tui_exit
        assert resumed == sid and provider.phase is not None, 'OWNER_GROUP_PRETOOL_REPLACED_NATIVE_THREAD'
        output, summary = provider.finish(provider.phase['turn_id'])
        require_successful_output(output)
        summaries.append(summary)
        nonces[sid] = summary['connection_nonce_sha256']

    def start_daemon(label, connect=True):
        nonlocal started
        daemon = json.loads(cli.command(label, ['app-server', 'daemon', 'start']))
        started = True
        cli.control_socket = daemon['socketPath']
        assert Path(cli.control_socket).is_relative_to(cli.codex_home)
        cli.config['persistent_remote'] = 'unix://' + cli.control_socket
        cli.original_daemon = cli.daemon_identity()
        cli.notifications = collections.deque()
        if connect:
            cli.connect()

    def stop_daemon(label):
        nonlocal started
        original = cli.original_daemon
        cli.command(label, ['app-server', 'daemon', 'stop'])
        started = False
        path = Path('/proc') / str(original['pid']) / 'stat'
        deadline = time.monotonic() + 5
        while path.exists() and time.monotonic() < deadline:
            try:
                fields = path.read_text().rsplit(') ', 1)[1].split()
            except FileNotFoundError:
                return
            if fields[19] != original['start_ticks'] or fields[0] == 'Z':
                return
            time.sleep(.025)
        assert not path.exists(), 'OWNER_GROUP_PRIVATE_DAEMON_STILL_RUNNING'

    def reply(sequence, **values):
        assert cli.daemon_identity() == cli.original_daemon, 'OWNER_GROUP_HOST_DAEMON_CHANGED'
        assert provider.request_counts()['literal'] == 0, 'LITERAL_REACHED_PROVIDER'
        assert len(ids) == 4 and not set(ids).intersection(provider.native_title_sids), 'OWNER_GROUP_ORIGINAL_RECORD_COUNT'
        conserve_native_history()
        with provider.lock:
            queue_posts = {body: row['posts'] for body, row in provider.queue_inputs.items()}
        private_json(control / (str(sequence) + '.reply.json'), {'status': 'OBSERVED',
            'daemon': cli.original_daemon, 'native_session_ids': ids, 'fixture_scope': provider.scope,
            'daemon_restarts': restarts, 'literal_provider_posts': 0,
            'native_record_count': len(histories), 'native_history_prefix_conserved': True,
            'queue_posts': queue_posts, **values})

    try:
        bootstrap_progress('CONFIGURATION')
        configuration = cli.codex_home / 'config.toml'
        assert not configuration.exists(), 'OWNED_CONFIG_ALREADY_EXISTS'
        text = '''model = "synthetic-owner-groups"
model_provider = "qa_static"
approval_policy = {granular = {mcp_elicitations = true, rules = false, sandbox_approval = false, skill_approval = false, request_permissions = false}}
approvals_reviewer = "user"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic local static Host; no real model"
base_url = BASE_URL
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('BASE_URL', json.dumps(provider.origin))
        for workspace in workspaces:
            text += '\n[projects.' + json.dumps(str(workspace)) + ']\ntrust_level = "trusted"\n'
        for tool in OWNER_GROUP_TOOLS:
            text += '\n[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.' + tool + ']\napproval_mode = "approve"\n'
        configuration.write_text(text)
        bootstrap_progress('MARKETPLACE_INSTALL')
        cli.command('owner-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        bootstrap_progress('PLUGIN_INSTALL')
        cli.command('owner-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        bootstrap_progress('DAEMON_START')
        start_daemon('owner-daemon-start', connect=False)
        cli.config['startup_only'] = True
        bootstrap_progress('STARTUP_TUI')
        cli.literal_tui([])
        cli.config.pop('startup_only')
        bootstrap_progress('HOST_CONNECT')
        cli.connect()
        for index in range(4):
            cli.workspace = workspaces[index]
            bootstrap_progress('CREATE_NATIVE_TUI', index)
            sid = create_native_tui(index)
            assert sid not in ids, 'OWNER_GROUP_NATIVE_THREAD_DUPLICATED'
            ids.append(sid)
            bootstrap_progress('EXTERNAL_CLI_REGISTRATION', index)
            register_cli(index, sid)
            bootstrap_progress('NORMAL_PRETOOL_TRUST', index)
            trust_actual_pretool(index, sid)
            bootstrap_progress('MCP_STATUS', index)
            status = cli.tool_status(sid)
            assert status['tools_count'] > 0 and not status['tools_error'], 'CURRENT_NATIVE_MCP_NOT_READY'
        bootstrap_progress('ORIGINAL_FOUR_READY')
        reply(0)
        sequence = 1
        while True:
            phase = 'WAIT_PARENT'
            path = control / (str(sequence) + '.command.json')
            deadline = time.monotonic() + 900  # Parent may cross an actual five-minute lease.
            while not path.is_file() and time.monotonic() < deadline:
                time.sleep(.025)
            assert path.is_file(), 'OWNER_GROUP_PARENT_TIMEOUT'
            command = json.loads(path.read_text())
            assert isinstance(command, dict) and not (set(command) - {
                'action', 'actor', 'label', 'tool', 'arguments', 'form', 'queue', 'bind_queue',
                'observe_fields', 'expected_request_id', 'expected_body_marker', 'observe_self_groups'}), 'OWNER_GROUP_COMMAND_FIELDS'
            action, actor = command['action'], command.get('actor', 0)
            assert type(actor) is int and 0 <= actor < 4, 'OWNER_GROUP_ACTOR_INDEX'
            cli.workspace = workspaces[actor]
            for item in command.get('queue', []):
                assert set(item) == {'body', 'native_session_id', 'sender_endpoint_id', 'receiver_endpoint_id', 'group_id', 'kind'}, 'OWNER_GROUP_QUEUE_FIELDS'
                assert item['native_session_id'] in ids, 'OWNER_GROUP_QUEUE_FOREIGN_SID'
                provider.expect_queue(item['body'], item['native_session_id'], item['sender_endpoint_id'], item['receiver_endpoint_id'], item['group_id'], item['kind'])
            for body, request in command.get('bind_queue', {}).items():
                provider.bind_queue_request(body, request)
            if action in ('call', 'receive_match'):
                phase = 'HOST_CALL'
                assert isinstance(command.get('label'), str) and re.fullmatch('[A-Za-z0-9_.-]{1,80}', command['label']), 'OWNER_GROUP_CALL_LABEL'
                tool, args = command['tool'], command.get('arguments', {})
                assert tool in OWNER_GROUP_TOOLS and isinstance(args, dict) and '_cicada_context' not in args, 'OWNER_GROUP_TOOL_OR_CONTEXT_INVALID'
                form = command.get('form')
                if form is not None and not form.get('server'):
                    catalog = cli.rpc('mcpServerStatus/list', {'threadId': ids[actor], 'limit': 100, 'detail': 'full'})
                    servers = [row for row in catalog['data'] if row.get('pluginId') == cli.original_plugin_id and
                               'cicada_select_peer' in row.get('tools', {})]
                    assert len(servers) == 1 and isinstance(servers[0].get('name'), str), 'OWNER_GROUP_ACTUAL_FORM_SERVER_NOT_UNIQUE'
                    form = {**form, 'server': servers[0]['name']}
                if action == 'receive_match':
                    assert tool == 'cicada_receive' and command.get('expected_request_id') and command.get('expected_body_marker'), 'OWNER_GROUP_RECEIVE_EXPECTATION'
                if action == 'receive_match':
                    # Let this exact original native queue turn arrive before
                    # starting more turns on that same SID. SENT is not arrival.
                    phase = 'WAIT_ORIGINAL_NATIVE_QUEUE'
                    deadline = time.monotonic() + 75
                    wait_poll = 0
                    while True:
                        with provider.lock:
                            expected = provider.queue_inputs.get(command['expected_body_marker'])
                            assert expected and expected['sid'] == ids[actor] and expected['request_id'] == command['expected_request_id'], 'OWNER_GROUP_NATIVE_BARRIER_SCOPE'
                            arrived = expected['posts']
                        private_json(control / (str(sequence) + '.progress-native-' + str(wait_poll) + '.json'), {
                            'scope': 'CLOSED_NATIVE_QUEUE_PROGRESS_NOT_ACCEPTANCE', 'phase': phase,
                            'expected_request_sha256': hashlib.sha256(command['expected_request_id'].encode()).hexdigest(),
                            'expected_body_sha256': hashlib.sha256(command['expected_body_marker'].encode()).hexdigest(),
                            'native_queue_posts_for_body': arrived, 'provider_unclassified_posts': provider.request_counts()['literal']})
                        assert provider.request_counts()['literal'] == 0, 'ACTUAL_PROVIDER_REQUEST_UNCLASSIFIED'
                        if arrived == 1:
                            break
                        assert time.monotonic() < deadline, 'OWNER_GROUP_EXACT_NATIVE_QUEUE_NOT_ARRIVED'
                        wait_poll += 1
                        time.sleep(1)
                    phase = 'HOST_CALL'
                for poll in range(60 if action == 'receive_match' else 1):
                    output, summary = cli.host_call(provider, ids[actor], command['label'] + '-' + str(poll), tool, args, form)
                    summaries.append(summary)
                    nonce = summary['connection_nonce_sha256']
                    if ids[actor] in retired_nonces:
                        assert nonce != retired_nonces[ids[actor]], 'OWNER_GROUP_MCP_NONCE_REUSED_AFTER_RESTART'
                    nonces[ids[actor]] = nonce
                    if action == 'receive_match':
                        objects = list(output_objects(output))
                        request_match = [row for row in objects if row.get('request_id') == command['expected_request_id']]
                        matched = any(command['expected_body_marker'] in json.dumps(row) for row in request_match)
                        with provider.lock:
                            queue_row = provider.queue_inputs.get(command['expected_body_marker'])
                            queue_posts = queue_row['posts'] if queue_row else 0
                        private_json(control / (str(sequence) + '.progress-' + str(poll) + '.json'), {
                            'scope': 'CLOSED_RECEIVE_PROGRESS_NOT_ACCEPTANCE', 'poll': poll,
                            'expected_request_sha256': hashlib.sha256(command['expected_request_id'].encode()).hexdigest(),
                            'expected_body_sha256': hashlib.sha256(command['expected_body_marker'].encode()).hexdigest(),
                            'matched': matched, 'request_match_count': len(request_match),
                            'page_message_counts': [len(row['messages']) for row in objects if isinstance(row.get('messages'), list)],
                            'observed_request_sha256': sorted({hashlib.sha256(row['request_id'].encode()).hexdigest()
                                                              for row in objects if isinstance(row.get('request_id'), str) and row['request_id']}),
                            'native_queue_posts_for_body': queue_posts,
                            'host_diagnostic': provider.safe_diagnostic()})
                        if matched:
                            break
                    else:
                        break
                    time.sleep(.25)
                else:
                    raise AssertionError('OWNER_GROUP_EXACT_REQUEST_NOT_RECEIVED')
                public = {}
                for field in command.get('observe_fields', []):
                    assert field in ('request_id', 'operation_id', 'endpoint_id', 'group_id', 'native_session_id', 'workspace', 'node_id', 'peer_selection_id', 'scope_id'), 'OWNER_GROUP_PUBLIC_FIELD'
                    values = {row[field] for row in output_objects(output) if isinstance(row.get(field), str) and row[field]}
                    assert len(values) <= 1, 'OWNER_GROUP_PUBLIC_FIELD_AMBIGUOUS'
                    public[field] = next(iter(values), '')
                extra = {'host_diagnostic': provider.safe_diagnostic()}
                if tool in ('cicada_ask', 'cicada_reply', 'cicada_operation_status', 'cicada_operation_retry'):
                    extra['operation_status'] = observed_operation_status(output)
                    retryable = {row['retryable'] for row in output_objects(output)
                                 if isinstance(row.get('operation_id'), str) and row['operation_id'] and
                                 type(row.get('retryable')) is bool}
                    assert len(retryable) <= 1, 'OWNER_GROUP_OPERATION_RETRYABLE_AMBIGUOUS'
                    if retryable:
                        extra['operation_retryable'] = next(iter(retryable))
                if command.get('observe_self_groups', False):
                    assert tool == 'cicada_groups' and command['observe_self_groups'] is True, 'OWNER_GROUP_SELF_LIST_TOOL'
                    rows = [row for row in output_objects(output) if set(row) == {
                        'groups', 'current_group_id', 'selection_required', 'complete', 'next_cursor', 'freshness'}]
                    assert len(rows) == 1, 'OWNER_GROUP_SELF_LIST_MISSING_OR_AMBIGUOUS'
                    row = rows[0]
                    assert (isinstance(row['groups'], list) and len(row['groups']) <= 64 and
                            type(row['selection_required']) is bool and type(row['complete']) is bool and
                            all(isinstance(row[key], str) for key in ('current_group_id', 'next_cursor', 'freshness'))), 'OWNER_GROUP_SELF_LIST_FIELDS'
                    for group in row['groups']:
                        assert isinstance(group, dict) and set(group) == {
                            'group_id', 'name', 'network_id', 'current', 'relation_revision', 'source', 'expires_at', 'freshness'}, 'OWNER_GROUP_SELF_CARD_FIELDS'
                        assert (type(group['current']) is bool and type(group['relation_revision']) is int and
                                0 < group['relation_revision'] < 2**63 and all(isinstance(group[key], str) for key in (
                                    'group_id', 'name', 'network_id', 'source', 'expires_at', 'freshness'))), 'OWNER_GROUP_SELF_CARD_TYPES'
                    extra['self_groups'] = row
                reply(sequence, output=output, summary=summary, public=public, **extra)
            elif action == 'restart_host':
                phase = 'RESTART_PRIVATE_HOST'
                old = cli.original_daemon
                close_proxy()
                stop_daemon('owner-daemon-stop-' + str(restarts))
                retired_nonces.update(nonces)
                nonces.clear()
                restarts += 1
                cli.state = cli.root / ('owner-host-connection-' + str(restarts))
                cli.state.mkdir(mode=0o700)
                start_daemon('owner-daemon-restart-' + str(restarts))
                assert cli.original_daemon != old, 'OWNER_GROUP_HOST_NOT_RESTARTED'
                reply(sequence)
            elif action == 'checkpoint':
                reply(sequence)
            elif action == 'finish':
                reply(sequence)
                result.update(status='HOST_FIXTURE_COMPLETED_NOT_PRODUCT_ACCEPTANCE', native_session_ids=ids,
                              daemon_restarts=restarts, tool_summaries=summaries)
                break
            else:
                raise AssertionError('OWNER_GROUP_COMMAND_UNSUPPORTED')
            sequence += 1
    except Exception as error:
        code = str(error) if isinstance(error, AssertionError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'UNCLASSIFIED'
        result.update(status='FAIL', failure_phase=phase, failure_kind=type(error).__name__, failure_code=code,
                      host_diagnostic=provider.safe_diagnostic(), unclassified_shapes=provider.unclassified_shapes)
    finally:
        cleanup = True
        try:
            close_proxy()
            if started:
                stop_daemon('owner-daemon-final-stop')
        except Exception:
            cleanup = False
        provider.close()
        counts = provider.request_counts()
        result.update(cleanup_confirmed=cleanup, literal_provider_posts=counts['literal'],
                      host_provider_posts=counts['host'], native_queue_provider_posts=counts['native_queue'],
                      native_seed_provider_posts=counts['native_seed'], native_title_provider_posts=counts['native_title'],
                      static_provider_posts=len(provider.requests))
        if not cleanup or counts['literal'] or counts['native_seed'] != 4 or counts['native_title'] != len(provider.native_title_sids) or counts['native_title'] > len(provider.native_title_inputs) or digest(Path(cli.binary)) != cli.expected_binary:
            result['status'] = 'FAIL'
        private_json(Path(config['result']), result)
    return 0 if result['status'] == 'HOST_FIXTURE_COMPLETED_NOT_PRODUCT_ACCEPTANCE' else 1


def run(config):
    if config.get('step') == 'owner-groups-native':
        return run_owner_groups(config)
    os.umask(0o077)
    assert config['codex_sha256'] == CODEX_SHA256 and config['daemon_umask'] == '0002'
    cli = PeerFormCLI(config)
    workspaces = [Path(p) for p in config['workspaces']]
    assert len(workspaces) == 2 and len(set(workspaces)) == 2
    assert all(p.is_dir() and p.is_relative_to(cli.root) for p in workspaces)
    control = Path(config['control'])
    control.mkdir(mode=0o700)
    provider = StaticHostProvider(str(cli.root))
    result = {'scope': 'ACTUAL_HOST_PEER_FORM_NATIVE_AB', 'status': 'FAIL', 'real_model_turns': 0,
              'physical_form_UI_Windows_DPAPI_ACL': 'NOT_RUN', 'manual_independent_Owner_pin_prerequisite': True}
    phase, started, summaries = 'SETUP', False, []
    names = ['Synthetic peer form A', 'Synthetic peer form B']
    ids, actors, public_names = [], [], []

    def checkpoint(step, values):
        assert cli.daemon_identity() == cli.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
        assert provider.request_counts()['literal'] == 0, 'LITERAL_REACHED_PROVIDER'
        private_json(control / (str(step) + '.reply.json'), {'status': 'SCOPED_PASS',
            'daemon': cli.original_daemon, 'literal_provider_posts': 0, 'native_session_ids': ids,
            'actors': actors, **values})
        path = control / (str(step) + '.command.json')
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if path.is_file():
                return json.loads(path.read_text())
            time.sleep(.05)
        raise RuntimeError('PEER_FORM_PARENT_CHECKPOINT_TIMEOUT')

    def call(index, label, tool, args, form=None, success=True):
        cli.workspace = workspaces[index]
        output, summary = cli.host_call(provider, ids[index], label, tool, args, form)
        summaries.append(summary)
        return require_successful_output(output) if success else output

    def select(label, action='accept'):
        out = call(0, label, 'cicada_select_peer', {'scope': 'group', 'query': public_names[1]},
                   {'action': action, 'name': public_names[1], 'workspace': str(workspaces[1]),
                    'server': server_names[0]}, success=action == 'accept')
        if action != 'accept':
            expected_code = {'decline': 'MCP_FORM_DECLINED', 'cancel': 'MCP_FORM_CANCELLED'}[action]
            observed = require_host_refusal(out, codes=(expected_code,))
            actual_codes = observed.intersection(('MCP_FORM_DECLINED', 'MCP_FORM_CANCELLED', 'MCP_FORM_INVALID', 'MCP_FORM_TIMEOUT'))
            assert actual_codes == {expected_code}, 'FORM_ACTION_TYPED_ERROR_MISMATCH'
            assert not any(row.get('peer_selection_id') or row.get('request_id') for row in output_objects(out)), 'CANCELLED_SELECTION_CREATED_RESULT'
            return None
        handle = unique_output_field(out, 'peer_selection_id')
        assert unique_output_field(out, 'endpoint_id') == actors[1]['endpoint_id'], 'SELECTED_ENDPOINT_CHANGED'
        assert unique_output_field(out, 'scope_id') == actors[0]['group_id'], 'SELECTED_SCOPE_CHANGED'
        assert not any(row.get('request_id') for row in output_objects(out)), 'SELECTION_SENT_BUSINESS'
        return handle

    def request_id(output, prefix):
        for attempt in range(60):
            values = {r['request_id'] for r in output_objects(output) if isinstance(r.get('request_id'), str) and r['request_id']}
            assert len(values) <= 1, 'ACTUAL_ASK_REQUEST_ID_AMBIGUOUS'
            if values:
                return values.pop()
            operation = unique_output_field(output, 'operation_id')
            time.sleep(.25)
            output = call(0, prefix + '-status-' + str(attempt), 'cicada_operation_status', {'operation_id': operation})
        raise RuntimeError('ACTUAL_ASK_DURABLE_REQUEST_MISSING')

    def receive(index, wanted, marker, prefix):
        for attempt in range(60):
            output = call(index, prefix + '-' + str(attempt), 'cicada_receive', {'limit': 16})
            rows = [r for r in output_objects(output) if r.get('request_id') == wanted and marker in json.dumps(r)]
            if rows:
                return rows[0]['request_id']
            time.sleep(.25)
        raise RuntimeError('ACTUAL_SEALED_MESSAGE_NOT_RECEIVED')

    try:
        configuration = cli.codex_home / 'config.toml'
        assert not configuration.exists(), 'OWNED_CONFIG_ALREADY_EXISTS'
        text = '''model = "synthetic-peer-form"
model_provider = "qa_static"
approval_policy = {granular = {mcp_elicitations = true, rules = false, sandbox_approval = false, skill_approval = false, request_permissions = false}}
approvals_reviewer = "user"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic local static Host; no real model"
base_url = BASE_URL
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('BASE_URL', json.dumps(provider.origin))
        for workspace in workspaces:
            text += '\n[projects.' + json.dumps(str(workspace)) + ']\ntrust_level = "trusted"\n'
        for tool in TOOLS:
            text += '\n[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.' + tool + ']\napproval_mode = "approve"\n'
        configuration.write_text(text)
        cli.command('peer-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        cli.command('peer-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        phase = 'ORIGINAL_DAEMON'
        daemon = json.loads(cli.command('peer-daemon-start', ['app-server', 'daemon', 'start']))
        started = True
        cli.control_socket = daemon['socketPath']
        assert Path(cli.control_socket).is_relative_to(cli.codex_home)
        cli.config['persistent_remote'] = 'unix://' + cli.control_socket
        cli.original_daemon = cli.daemon_identity()
        cli.config['startup_only'] = True
        cli.literal_tui([])
        cli.config.pop('startup_only')
        cli.connect()
        phase = 'LITERAL_AB'
        server_names = []
        for index in range(2):
            cli.workspace = workspaces[index]
            sid, _ = cli.literal_admit(provider, 'peer-form-' + 'ab'[index], names[index])
            assert sid not in ids, 'NATIVE_THREAD_DUPLICATED'
            ids.append(sid)
            status = cli.tool_status(sid)
            assert status['tools_count'] > 0 and not status['tools_error'], 'CURRENT_NATIVE_MCP_NOT_READY'
            catalog = cli.rpc('mcpServerStatus/list', {'threadId': sid, 'limit': 100, 'detail': 'full'})
            servers = [r for r in catalog['data'] if r.get('pluginId') == cli.original_plugin_id]
            assert len(servers) == 1 and isinstance(servers[0].get('name'), str), 'ACTUAL_PLUGIN_SERVER_NOT_UNIQUE'
            assert 'cicada_select_peer' in servers[0].get('tools', {}), 'ACTUAL_SELECT_TOOL_NOT_ADVERTISED'
            server_names.append(servers[0]['name'])
        expected = checkpoint(1, {})
        phase = 'ACTUAL_HOST_IDENTITY'
        for index in range(2):
            out = call(index, 'whoami-' + 'ab'[index], 'cicada_whoami', {})
            actor = {k: unique_output_field(out, k) for k in
                     ('native_session_id', 'workspace', 'node_id', 'endpoint_id', 'group_id')}
            assert actor['native_session_id'] == ids[index] and actor['workspace'] == str(workspaces[index]), 'HOST_NATIVE_ACTOR_CHANGED'
            assert actor['node_id'] == expected['node_id'] and actor['group_id'] == expected['group_id'], 'HOST_AUTHORIZED_SCOPE_CHANGED'
            epochs = {r['binding_epoch'] for r in output_objects(out) if type(r.get('binding_epoch')) is int and r['binding_epoch'] > 0}
            assert len(epochs) == 1, 'HOST_BINDING_EPOCH_MISSING'
            actor['binding_epoch'] = epochs.pop()
            actors.append(actor)
            actual_names = {r['name'] for r in output_objects(out)
                            if r.get('endpoint_id') == actor['endpoint_id'] and isinstance(r.get('name'), str) and r['name']}
            assert len(actual_names) == 1, 'HOST_AUTHENTICATED_ACTOR_NAME_MISSING_OR_AMBIGUOUS'
            public_names.append(actual_names.pop())
        assert actors[0]['endpoint_id'] != actors[1]['endpoint_id'], 'HOST_ENDPOINT_DUPLICATED'
        checkpoint(2, {})
        phase = 'CANCEL_DECLINE'
        select('decline-b', 'decline')
        select('cancel-b', 'cancel')
        network_denied = call(0, 'shared-domain-has-no-network-grant', 'cicada_select_peer',
                              {'scope': 'network', 'network_id': expected['network_id']}, success=False)
        require_host_refusal(network_denied, codes=('NETWORK_SESSION_UNAVAILABLE',), http_statuses=(403,))
        checkpoint(3, {'cancel_decline_no_handle': True, 'shared_domain_network_denied': True})
        phase = 'SELECT_ASK_REPLY'
        handle = select('accept-b')
        selected_at = time.monotonic()
        checkpoint(4, {'selection_has_no_business_effect': True})
        question = 'SYNTHETIC_PEER_FORM_QUESTION_' + provider.scope
        answer = 'SYNTHETIC_PEER_FORM_ANSWER_' + provider.scope
        args = {'peer_selection_id': handle, 'question': question, 'idempotency_key': 'peer-form-' + provider.scope}
        provider.expect_queue(question, ids[1], actors[0]['endpoint_id'], actors[1]['endpoint_id'], actors[1]['group_id'], 'ask')
        asked = call(0, 'ask-selected-b-fresh-hook', 'cicada_ask', args)
        original = request_id(asked, 'selected-b')
        provider.bind_queue_request(question, original)
        inbound = receive(1, original, question, 'b-question')
        provider.expect_queue(answer, ids[0], actors[1]['endpoint_id'], actors[0]['endpoint_id'], actors[0]['group_id'], 'reply')
        provider.bind_queue_request(answer, inbound)
        call(1, 'reply-from-b-fresh-hook', 'cicada_reply', {'request_id': inbound, 'body': answer,
             'idempotency_key': 'peer-form-reply-' + provider.scope})
        receive(0, original, answer, 'a-answer')
        # Observe real frozen handle lifetime; never alter the product clock.
        phase = 'EXACT_RETRY_AFTER_SELECTION_EXPIRY'
        while time.monotonic() - selected_at < 121:
            assert cli.daemon_identity() == cli.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
            time.sleep(max(.01, min(1, 121 - (time.monotonic() - selected_at))))
        retry = call(0, 'exact-ask-retry', 'cicada_ask', args)
        assert request_id(retry, 'exact-retry') == original, 'EXACT_RETRY_CHANGED_REQUEST'
        checkpoint(5, {'roundtrip_request_id': original, 'exact_retry_same_request': True,
                       'actual_selection_lifetime_elapsed': True})
        phase = 'REVOKE'
        revoked_handle = select('accept-before-revoke')
        checkpoint(6, {})  # Parent explicitly revokes current actual App policy.
        denied = call(0, 'ask-after-current-revoke', 'cicada_ask', {'peer_selection_id': revoked_handle,
                      'question': 'SYNTHETIC_REVOKED_PEER_FORM', 'idempotency_key': 'peer-form-revoked-' + provider.scope}, success=False)
        require_host_refusal(denied, codes=('PEER_SELECTION_STALE', 'CODEX_NODE_TICKET_UNAVAILABLE'), http_statuses=(401, 403))
        checkpoint(7, {'revoke_denied_new_business': True})
        result.update(status='SCOPED_PASS', daemon=cli.original_daemon, native_session_ids=ids,
                      actors=actors, tool_summaries=summaries, exact_retry_same_request=True,
                      host_approval_policy='GRANULAR_MCP_ELICITATIONS_ONLY', host_approvals_reviewer='user',
                      actual_Host_form_relay=True, physical_TUI_form_display='NOT_RUN')
    except Exception as error:
        # Never persist raw exception text: it can contain a private tool body.
        code = str(error) if isinstance(error, AssertionError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'UNCLASSIFIED'
        result.update(failure_phase=phase, failure_kind=type(error).__name__, failure_code=code,
                      host_diagnostic=provider.safe_diagnostic(), peer_form_diagnostic=getattr(cli, 'peer_diagnostic', None),
                      host_approval_policy='GRANULAR_MCP_ELICITATIONS_ONLY' if getattr(cli, 'host_policy_observed', False) else 'NOT_OBSERVED',
                      host_approvals_reviewer='user' if getattr(cli, 'host_policy_observed', False) else 'NOT_OBSERVED',
                      literal_names_match_authenticated_names=public_names == names if len(public_names) == 2 else None)
    finally:
        cleanup = True
        if hasattr(cli, 'proxy'):
            cli.proxy.stdin.close()
            try:
                cli.proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cli.proxy.kill()
                cli.proxy.wait()
            cli.proxy_log.close()
        if started:
            try:
                cli.command('peer-daemon-stop', ['app-server', 'daemon', 'stop'])
                original = cli.original_daemon
                path = Path('/proc') / str(original['pid']) / 'stat'
                deadline = time.monotonic() + 5
                while path.exists() and time.monotonic() < deadline:
                    try:
                        fields = path.read_text().rsplit(') ', 1)[1].split()
                    except FileNotFoundError:
                        break
                    if fields[19] != original['start_ticks'] or fields[0] == 'Z':
                        break
                    time.sleep(.05)
                else:
                    cleanup = not path.exists()
            except Exception:
                cleanup = False
        provider.close()
        counts = provider.request_counts()
        result.update(cleanup_confirmed=cleanup, literal_provider_posts=counts['literal'],
                      host_provider_posts=counts['host'], native_queue_provider_posts=counts['native_queue'],
                      static_provider_posts=len(provider.requests))
        if not cleanup or counts['literal'] or digest(Path(cli.binary)) != cli.expected_binary:
            result['status'] = 'FAIL'
        private_json(Path(config['result']), result)
    return 0 if result['status'] == 'SCOPED_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(run(json.loads(Path(sys.argv[1]).read_text())))
