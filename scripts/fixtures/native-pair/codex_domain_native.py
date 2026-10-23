#!/usr/bin/env python3
"""Owned original umask-0002 daemon, literal A/B, actual static-provider MCP.

The Go fixture owns real Hub/App/Node authorization and sends only public
expectations and operator checkpoints. No native record, ticket or identity is
manufactured here. This driver remains opt-in until the full backend is present.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from codex_domain_host import DOMAIN_ADMISSION_TITLE, DomainHostCLI, StaticHostProvider, output_objects, require_successful_output, unique_output_field
from codex_product_cli import digest, private_json


NATIVE_PHASES = frozenset(('SETUP', 'ORIGINAL_DAEMON', 'WAIT_OWNER_POLICY', 'PLUGIN_UPDATE',
                          'LITERAL_AB', 'HOST_APP_CLOSED', 'WAIT_LOGIN_EXPIRY',
                          'HOST_POST_LOGIN_EXPIRY', 'LITERAL_C_AFTER_LOGIN_EXPIRY',
                          'HOST_NEW_C_AFTER_LOGIN_EXPIRY', 'WAIT_OWNER_REVOKE',
                          'HOST_AFTER_REVOKE', 'CLEANUP'))
NATIVE_TOOL_LABELS = {'cicada_whoami': 'WHOAMI', 'cicada_members': 'PEERS', 'cicada_ask': 'ASK',
                      'cicada_receive': 'RECEIVE', 'cicada_reply': 'REPLY',
                      'cicada_operation_status': 'OPERATION_STATUS'}
NATIVE_LABELS = frozenset(('NONE', 'DAEMON_START', 'TUI_INITIALIZE', 'HOST_CONNECT',
                          'MARKETPLACE_REMOVE', 'MARKETPLACE_ADD', 'PLUGIN_ADD', 'PLUGIN_INVENTORY', 'DAEMON_STOP')) | frozenset(
    actor + '_' + action for actor in 'ABC'
    for action in (*NATIVE_TOOL_LABELS.values(), 'JOIN', 'MCP_STATUS', 'RECEIVE_QUESTION', 'RECEIVE_ANSWER'))
NATIVE_FAILURE_KINDS = frozenset(('', 'ASSERTION', 'TIMEOUT', 'IO', 'DRIVER', 'OTHER', 'CLEANUP'))
NATIVE_ASSERTION_CODES = frozenset((
    'LITERAL_ADMISSION_REACHED_PROVIDER', 'CURRENT_LITERAL_PROMPT_NOT_VISIBLE',
    'DOMAIN_ADMISSION_TITLE_OR_ORIGINAL_FIELDS_MISSING', 'ORIGINAL_NATIVE_RECORD_MISMATCH',
    'ACTUAL_JOIN_RESULT_TITLE_DUPLICATED', 'ACTUAL_JOIN_RESULT_FIELDS_NOT_VISIBLE',
    'TERMINAL_OUTPUT_BOUND_EXCEEDED', 'ACTUAL_NATIVE_RECORD_REFUSED',
    'ACTUAL_PEERS_RESULT_TITLE_DUPLICATED', 'ACTUAL_PEERS_RESULT_FIELDS_NOT_VISIBLE',
    'ACTUAL_PTY_FOREGROUND_NOT_CONFIRMED', 'ACTUAL_TUI_LITERAL_RESULT_NOT_VISIBLE',
    'ACTUAL_TUI_EXIT_NONZERO', 'ACTUAL_ORIGINAL_THREAD_NOT_RESUMED', 'ACTUAL_TUI_NATIVE_IDENTITY_UNCONFIRMED',
    'ORIGINAL_DAEMON_REPLACED', 'INSTALLED_PLUGIN_ID_CHANGED', 'INSTALLED_HOOK_STALE_SOURCE',
    'NORMAL_NEW_HOOK_TRUST_REQUIRED'))
NATIVE_ASSERTION_CODES |= frozenset((
    'ACTUAL_HOST_TOOL_REFUSED', 'HOST_PHASE_OVERLAP', 'CALLER_CONTEXT_TICKET_SUBSTITUTE_FORBIDDEN',
    'ACTUAL_HOST_PHASE_INCOMPLETE', 'HOST_THREAD_NOT_CREATED_BY_NATIVE_TUI', 'ORIGINAL_DAEMON_CHANGED',
    'ACTUAL_ORIGINAL_THREAD_SCOPE_CHANGED', 'UNEXPECTED_NATIVE_HOST_APPROVAL_OR_RPC',
    'ACTUAL_DAEMON_NOTIFICATION_BOUND', 'ACTUAL_NATIVE_HOST_TURN_FAILED',
    'ACTUAL_DAEMON_RPC_REFUSED_thread/resume', 'ACTUAL_DAEMON_RPC_REFUSED_turn/start',
    'ACTUAL_DAEMON_RPC_REFUSED_thread/read', 'ACTUAL_HOST_THREAD_NOT_IDLE', 'ACTUAL_HOST_THREAD_STATUS_INVALID',
    'ACTUAL_PROVIDER_REQUEST_UNCLASSIFIED', 'ACTUAL_HOST_TURN_CORRELATION_FAILED',
    'ACTUAL_QUEUE_EXPECTATION_INVALID', 'ACTUAL_QUEUE_REQUEST_CORRELATION_FAILED',
    'OWNED_PUBLIC_SUMMARY_PATH_REQUIRED', 'OWNED_PUBLIC_SUMMARY_SYMLINK_REFUSED',
    'ORIGINAL_0002_DAEMON_CHANGED', 'LITERAL_REACHED_PROVIDER', 'ACTUAL_ASK_REQUEST_ID_AMBIGUOUS',
    'ACTUAL_HOST_BINDING_EPOCH_MISSING_OR_AMBIGUOUS', 'ACTUAL_HOST_NATIVE_IDENTITY_CHANGED',
    'ACTUAL_HOST_OWNER_POLICY_SCOPE_CHANGED', 'ACTUAL_NAMED_PEER_NOT_VISIBLE',
    'CURRENT_DOMAIN_REVOKE_NOT_ENFORCED', 'REVOKED_NEW_ASK_CREATED_REQUEST',
    'CURRENT_NATIVE_MCP_NOT_READY', 'AUTHENTICATED_LOGIN_DEADLINE_OUTSIDE_FIXTURE_BOUND')) | frozenset(
    'ACTUAL_HOST_RESULT_FIELD_MISSING_OR_AMBIGUOUS_' + field for field in
    ('native_session_id', 'workspace', 'node_id', 'endpoint_id', 'group_id'))
NATIVE_HOOK_MARKERS = {
    'domain_saved': (DOMAIN_ADMISSION_TITLE, '当前 Thread 的本地协作接入结果已保存；后续通信由当前 Hub Guard 验证。'),
    'registered_zero': ('This Thread is registered; registration does not add or renew communication permission.',
                        '当前 Thread 登记已确认；登记本身不新增或延长通信权限。'),
    'context_refused': ('CODEX_NATIVE_COORDINATES_INVALID', 'CODEX_NATIVE_RECORD_UNVERIFIED',
                        'CODEX_TOOL_INPUT_MISSING', 'CODEX_CALL_CONTEXT_MISSING', 'CODEX_CONNECTION_NONCE_INVALID',
                        'CODEX_TOOL_ARGUMENTS_INVALID', 'CODEX_ARGUMENT_DIGEST_UNAVAILABLE', 'CODEX_NODE_TICKET_UNAVAILABLE',
                        'Cicada could not verify the current scope.') + tuple(
                            'CODEX_NATIVE_RECORD_' + stage + ':' for stage in
                            ('ROOT', 'PATH', 'OWNERSHIP', 'PERMISSION', 'INODE', 'METADATA', 'SOURCE', 'SESSION', 'WORKSPACE')),
    'command_unconfirmed': ('This Cicada result is unconfirmed; retry the same command without substituting an identity.',
                            'This Cicada command was refused; no connection or authorization success is claimed.',
                            'The original Cicada result needs recovery; success is unconfirmed.',
                            'Cicada connection state is not safely saved; the original command is retained for retry.',
                            'Cicada has not confirmed this result.'),
    'local_config_error': ('The original Cicada state location needs recovery; no replacement was created.',
                           'Cicada local state is unavailable.', 'Restore the original Cicada cache; no replacement state was created.',
                           'The Node for this installation is not running; start the original Node manually.',
                           'The Node is not ready; no replacement identity was created.',
                           'Multiple Nodes were found; select an exact Hub and Node.',
                           'The original Node binding or configuration changed; the original request is retained without switching identity.',
                           "Restore the original Node configuration; no other deployment's environment configuration was used.",
                           'Local Node discovery material could not be verified.',
                           'Local Node discovery is unavailable; restore the original Node and retry.',
                           'Local Node discovery exceeded its limit; no other Node was guessed.')}


def native_assertion_code(error):
    if isinstance(error, AssertionError) and len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in NATIVE_ASSERTION_CODES:
        return error.args[0]
    return 'UNCLASSIFIED'


def classify_literal_hook(text, prompt):
    compact = re.sub(r'\s+', '', text)
    echo = '›' + re.sub(r'\s+', '', prompt)
    if echo not in compact:
        return 'none'
    result = compact.rsplit(echo, 1)[1]
    matches = {kind for kind, markers in NATIVE_HOOK_MARKERS.items()
               if any(re.sub(r'\s+', '', marker) in result for marker in markers)}
    return matches.pop() if len(matches) == 1 else 'none'


def native_stage_summary(phase, label, status='IN_PROGRESS', failure_kind='', failure_code='UNCLASSIFIED',
                         hook_result='none', literal_provider_posts=None, provider_posts=None, host_diagnostic=None,
                         host_provider_posts=None, native_queue_provider_posts=None):
    # Location is diagnostic only. It cannot establish a successful measurement.
    assert phase in NATIVE_PHASES and label in NATIVE_LABELS and status in ('IN_PROGRESS', 'FAIL')
    assert failure_kind in NATIVE_FAILURE_KINDS
    assert failure_code == 'UNCLASSIFIED' or failure_code in NATIVE_ASSERTION_CODES
    assert hook_result == 'none' or hook_result in NATIVE_HOOK_MARKERS
    assert all(value is None or type(value) is int and value >= 0 for value in
               (literal_provider_posts, provider_posts, host_provider_posts, native_queue_provider_posts))
    return {'scope': 'NATIVE_DOMAIN_LOCATION_ONLY_NOT_ACCEPTANCE', 'status': status,
            'phase': phase, 'label': label, 'failure_kind': failure_kind, 'failure_code': failure_code,
            'hook_result': hook_result, 'literal_provider_posts': literal_provider_posts, 'provider_posts': provider_posts,
            'host_provider_posts': host_provider_posts, 'native_queue_provider_posts': native_queue_provider_posts,
            'host_diagnostic': host_diagnostic}


def native_failure_kind(error):
    if isinstance(error, AssertionError):
        return 'ASSERTION'
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired, queue.Empty)):
        return 'TIMEOUT'
    if isinstance(error, OSError):
        return 'IO'
    return 'DRIVER' if isinstance(error, RuntimeError) else 'OTHER'


def run(config):
    assert config['daemon_umask'] == '0002' and config['preparation'] == 'none'
    cli = DomainHostCLI(config)
    workspaces = [Path(value) for value in config['workspaces']]
    names = ['Synthetic native domain A', 'Synthetic native domain B', 'Synthetic native domain C']
    assert len(workspaces) == 3 and len(set(workspaces)) == 3 and all(path.is_dir() and path.is_relative_to(cli.root) for path in workspaces)
    control = Path(config['control'])
    control.mkdir(mode=0o700)
    provider = StaticHostProvider(str(cli.root))
    reply = {'status': 'FAIL', 'real_model_turns': 0, 'manual_independent_Owner_pin_prerequisite': True,
             'real_model_and_real_model_automatic_wake_Windows': 'NOT_RUN'}
    daemon_started = False
    summaries = []
    active_literal = None
    public_path = config.get('public_summary')
    assert public_path in (None, '', '/state/domain-native-public-summary.json'), 'OWNED_PUBLIC_SUMMARY_PATH_REQUIRED'
    location = native_stage_summary('SETUP', 'NONE')

    def publish_location():
        if public_path:
            path = Path(public_path)
            assert not path.is_symlink(), 'OWNED_PUBLIC_SUMMARY_SYMLINK_REFUSED'
            pending = path.with_name(path.name + '.next')
            private_json(pending, location)
            os.replace(pending, path)

    def locate(phase, label='NONE'):
        location.clear()
        location.update(native_stage_summary(phase, label))
        publish_location()

    def admit(index, label):
        nonlocal active_literal
        active_literal = (label, 'cicada join ' + json.dumps(names[index]))
        return cli.literal_admit(provider, label, names[index])

    def failed_hook_result():
        if active_literal is None or location['phase'] not in ('LITERAL_AB', 'LITERAL_C_AFTER_LOGIN_EXPIRY'):
            return 'none'
        label, prompt = active_literal
        try:
            with (cli.root / ('cli-' + label) / 'tui.txt').open() as stream:
                text = stream.read(65537)
        except (OSError, UnicodeError):
            return 'none'
        return classify_literal_hook(text, prompt) if len(text) <= 65536 else 'none'

    locate('SETUP')

    def checkpoint(step, values):
        assert cli.daemon_identity() == cli.original_daemon, 'ORIGINAL_0002_DAEMON_CHANGED'
        assert not any(row['phase'] == 'literal' for row in provider.requests), 'LITERAL_REACHED_PROVIDER'
        private_json(control / (str(step) + '.reply.json'),
                     {'status': 'SCOPED_PASS', 'daemon': cli.original_daemon, 'literal_provider_posts': 0, **values})

    def await_command(step):
        path = control / (str(step) + '.command.json')
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            if path.is_file():
                return json.loads(path.read_text())
            time.sleep(.1)
        raise RuntimeError('NATIVE_DOMAIN_PARENT_CHECKPOINT_TIMEOUT')

    def call(index, label, tool, arguments):
        action = NATIVE_TOOL_LABELS[tool]
        if tool == 'cicada_receive':
            action = 'RECEIVE_QUESTION' if '-receive-question-' in label else 'RECEIVE_ANSWER'
        locate(location['phase'], 'ABC'[index] + '_' + action)
        cli.workspace = workspaces[index]
        output, summary = cli.host_call(provider, ids[index], label, tool, arguments)
        summaries.append(summary)
        return require_successful_output(output)

    def request_id(index, output, prefix):
        values = {row['request_id'] for row in output_objects(output) if isinstance(row.get('request_id'), str) and row['request_id']}
        assert len(values) <= 1, 'ACTUAL_ASK_REQUEST_ID_AMBIGUOUS'
        if values:
            return values.pop()
        operation = unique_output_field(output, 'operation_id')
        deadline = time.monotonic() + 45
        count = 0
        while time.monotonic() < deadline:
            count += 1
            time.sleep(.25)
            current = call(index, prefix + '-status-' + str(count), 'cicada_operation_status', {'operation_id': operation})
            values = {row['request_id'] for row in output_objects(current) if isinstance(row.get('request_id'), str) and row['request_id']}
            assert len(values) <= 1, 'ACTUAL_ASK_REQUEST_ID_AMBIGUOUS'
            if values:
                return values.pop()
        raise RuntimeError('ACTUAL_ASK_DID_NOT_REACH_DURABLE_REQUEST')

    def receive(index, wanted_id, marker, prefix):
        deadline = time.monotonic() + 60
        count = 0
        while time.monotonic() < deadline:
            count += 1
            output = call(index, prefix + '-' + str(count), 'cicada_receive', {'limit': 16})
            rows = list(output_objects(output))
            matched = [row for row in rows if row.get('request_id') == wanted_id and marker in json.dumps(row, ensure_ascii=False)]
            if matched:
                # The reply ID is taken from the actual receiver's authenticated
                # inbox result, not a pasted identifier or a fabricated message.
                return matched[0]['request_id']
            time.sleep(.25)
        raise RuntimeError('ACTUAL_RECEIVER_DID_NOT_READ_SEALED_MESSAGE')

    def roundtrip(prefix, sender=0, receiver=1):
        question = 'SYNTHETIC_DOMAIN_QUESTION_' + provider.scope + '_' + prefix
        answer = 'SYNTHETIC_DOMAIN_ANSWER_' + provider.scope + '_' + prefix
        provider.expect_queue(question, ids[receiver], actors[sender]['endpoint_id'], actors[receiver]['endpoint_id'],
                              actors[receiver]['group_id'], 'ask')
        asked = call(sender, prefix + '-ask', 'cicada_ask', {'target': names[receiver], 'question': question,
                     'idempotency_key': 'synthetic-domain-' + provider.scope + '-' + prefix})
        original = request_id(sender, asked, prefix)
        provider.bind_queue_request(question, original)
        inbound = receive(receiver, original, question, prefix + '-receive-question')
        provider.expect_queue(answer, ids[sender], actors[receiver]['endpoint_id'], actors[sender]['endpoint_id'],
                              actors[sender]['group_id'], 'reply')
        provider.bind_queue_request(answer, inbound)
        call(receiver, prefix + '-reply', 'cicada_reply', {'request_id': inbound, 'body': answer,
             'idempotency_key': 'synthetic-domain-reply-' + provider.scope + '-' + prefix})
        receive(sender, original, answer, prefix + '-receive-answer')
        return {'request_id': original, 'question_sha256': hashlib.sha256(question.encode()).hexdigest(),
                'answer_sha256': hashlib.sha256(answer.encode()).hexdigest()}

    def whoami(index, expected, label):
        result = call(index, label, 'cicada_whoami', {})
        actual = {name: unique_output_field(result, name) for name in
                  ('native_session_id', 'workspace', 'node_id', 'endpoint_id', 'group_id')}
        epochs = {row['binding_epoch'] for row in output_objects(result)
                  if type(row.get('binding_epoch')) is int and row['binding_epoch'] > 0}
        assert len(epochs) == 1, 'ACTUAL_HOST_BINDING_EPOCH_MISSING_OR_AMBIGUOUS'
        actual['binding_epoch'] = epochs.pop()
        assert actual['native_session_id'] == ids[index] and actual['workspace'] == str(workspaces[index]), 'ACTUAL_HOST_NATIVE_IDENTITY_CHANGED'
        assert actual['node_id'] == expected['node_id'] and actual['group_id'] == expected['group_id'], 'ACTUAL_HOST_OWNER_POLICY_SCOPE_CHANGED'
        return actual

    try:
        configuration = cli.codex_home / 'config.toml'
        assert not configuration.exists()
        text = '''model = "synthetic-local-domain"
model_provider = "qa_static"
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic static Host calls; no real model"
base_url = BASE_URL
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('BASE_URL', json.dumps(provider.origin))
        for path in workspaces:
            text += '\n[projects.' + json.dumps(str(path)) + ']\ntrust_level = "trusted"\n'
        for tool in ('cicada_whoami', 'cicada_members', 'cicada_ask', 'cicada_receive', 'cicada_reply', 'cicada_operation_status'):
            text += '\n[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.' + tool + ']\napproval_mode = "approve"\n'
        configuration.write_text(text)
        cli.workspace = workspaces[0]
        locate('SETUP', 'MARKETPLACE_ADD')
        cli.command('old-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        locate('SETUP', 'PLUGIN_ADD')
        cli.command('old-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        locate('ORIGINAL_DAEMON', 'DAEMON_START')
        started = json.loads(cli.command('original-0002-daemon-start', ['app-server', 'daemon', 'start']))
        cli.control_socket = started['socketPath']
        assert Path(cli.control_socket).is_relative_to(cli.codex_home)
        cli.config['persistent_remote'] = 'unix://' + cli.control_socket
        daemon_started = True
        cli.original_daemon = cli.daemon_identity()
        cli.config['startup_only'] = True
        locate('ORIGINAL_DAEMON', 'TUI_INITIALIZE')
        cli.literal_tui([])  # Real native TUI initializes the original daemon first.
        cli.config.pop('startup_only')
        locate('ORIGINAL_DAEMON', 'HOST_CONNECT')
        cli.connect()
        locate('ORIGINAL_DAEMON', 'PLUGIN_INVENTORY')
        cli.inventory('original-before-file-install')
        checkpoint(0, {'original_daemon_before_plugin_update': True})

        locate('WAIT_OWNER_POLICY')
        expected = await_command(1)
        locate('PLUGIN_UPDATE', 'MARKETPLACE_REMOVE')
        cli.command('old-marketplace-remove', ['plugin', 'marketplace', 'remove', 'cicada-repo'])
        cli.marketplace = Path(expected['marketplace'])
        locate('PLUGIN_UPDATE', 'MARKETPLACE_ADD')
        cli.command('installed-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        locate('PLUGIN_UPDATE', 'PLUGIN_ADD')
        cli.command('installed-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        ids, metadata = [], []
        for index in range(2):
            cli.workspace = workspaces[index]
            locate('LITERAL_AB', 'AB'[index] + '_JOIN')
            sid, record = admit(index, 'domain-native-' + 'ab'[index])
            assert sid not in ids
            ids.append(sid)
            metadata.append(record)
            locate('LITERAL_AB', 'AB'[index] + '_MCP_STATUS')
            status = cli.tool_status(sid)
            assert status['tools_count'] > 0 and not status['tools_error'], 'CURRENT_NATIVE_MCP_NOT_READY'
        checkpoint(1, {'native_session_ids': ids, 'names': names[:2], 'native_metadata': metadata})

        locate('HOST_APP_CLOSED')
        await_command(2)  # The actual App has completed normal Controller.Close.
        actors = [whoami(index, expected, 'initial-whoami-' + 'ab'[index]) for index in range(2)]
        assert actors[0]['endpoint_id'] != actors[1]['endpoint_id']
        peers = call(0, 'initial-peers-a', 'cicada_members', {})
        assert names[1] in json.dumps(peers) and actors[1]['endpoint_id'] in json.dumps(peers), 'ACTUAL_NAMED_PEER_NOT_VISIBLE'
        first = roundtrip('app-closed')
        checkpoint(2, {'actors': actors, 'roundtrip': first, 'actual_Host_MCP': True, 'App_closed': True})

        locate('WAIT_LOGIN_EXPIRY')
        timer = await_command(3)
        waited = timer.get('wait_login_expiry') is True
        if waited:
            end = datetime.datetime.fromisoformat(timer['login_expires_at'].replace('Z', '+00:00')).timestamp() + 1
            assert -60 <= end - time.time() <= 1200, 'AUTHENTICATED_LOGIN_DEADLINE_OUTSIDE_FIXTURE_BOUND'
            next_status = time.monotonic()
            while time.time() < end:
                assert cli.daemon_identity() == cli.original_daemon, 'ORIGINAL_0002_DAEMON_CHANGED'
                if time.monotonic() >= next_status:
                    cli.workspace = workspaces[0]
                    locate('WAIT_LOGIN_EXPIRY', 'A_MCP_STATUS')
                    cli.tool_status(ids[0])  # Local catalog health only, no model/tool call.
                    next_status = time.monotonic() + 30
                time.sleep(min(1, max(.01, end - time.time())))
            locate('HOST_POST_LOGIN_EXPIRY')
            second = roundtrip('after-original-login-expiry')
            cli.workspace = workspaces[2]
            locate('LITERAL_C_AFTER_LOGIN_EXPIRY', 'C_JOIN')
            sid, record = admit(2, 'domain-native-c-after-expiry')
            assert sid not in ids
            ids.append(sid)
            metadata.append(record)
            locate('HOST_NEW_C_AFTER_LOGIN_EXPIRY')
            actors.append(whoami(2, expected, 'after-expiry-whoami-c'))
            third = roundtrip('new-c-after-original-login-expiry', sender=2, receiver=1)
            expiry_results = {'post_login_expiry': second, 'new_thread_after_login_expiry': third}
        else:
            expiry_results = {'login_expiry_new_C': 'NOT_RUN'}
        checkpoint(3, {'native_session_ids': ids, 'actors': actors, 'native_metadata': metadata,
                       'actual_wall_clock_expiry': waited, **expiry_results})

        locate('WAIT_OWNER_REVOKE')
        await_command(4)  # Real App re-login and explicit revoke, not window close.
        cli.workspace = workspaces[0]
        locate('HOST_AFTER_REVOKE', 'A_ASK')
        denied, summary = cli.host_call(provider, ids[0], 'after-current-policy-revoke', 'cicada_ask',
                                       {'target': names[1], 'question': 'SYNTHETIC_NEW_REQUEST_AFTER_REVOKE',
                                        'idempotency_key': 'synthetic-new-after-revoke-' + provider.scope})
        summaries.append(summary)
        denial = json.dumps(denied)
        assert ('CODEX_NODE_TICKET_UNAVAILABLE' in denial or re.search(r'Cicada Hub (?:401|403)', denial)), 'CURRENT_DOMAIN_REVOKE_NOT_ENFORCED'
        assert not any(row.get('request_id') for row in output_objects(denied)), 'REVOKED_NEW_ASK_CREATED_REQUEST'
        checkpoint(4, {'new_business_denied_after_current_revoke': True, 'native_session_ids': ids})
        reply.update(status='SCOPED_PASS', daemon=cli.original_daemon, native_session_ids=ids,
                     native_metadata=metadata, literal_provider_posts=0, actual_wall_clock_login_expiry=waited,
                     host_calls_completed=len(summaries), host_submission_mode='START_OR_STEER',
                     host_provider_posts=provider.request_counts()['host'],
                     native_queue_provider_posts=provider.request_counts()['native_queue'],
                     static_provider_posts=len(provider.requests),
                     tool_summaries=summaries, provider_requests=provider.requests)
    except Exception as error:
        reply['failure_category'] = (type(error).__name__ + ': ' + str(error))[:180]
        reply.update(failure_phase=location['phase'], failure_label=location['label'], failure_kind=native_failure_kind(error),
                     failure_code=native_assertion_code(error), hook_result=failed_hook_result(),
                     host_diagnostic=provider.safe_diagnostic() if location['phase'] in
                     ('HOST_APP_CLOSED', 'HOST_POST_LOGIN_EXPIRY', 'HOST_NEW_C_AFTER_LOGIN_EXPIRY', 'HOST_AFTER_REVOKE') else None)
    finally:
        if reply['status'] == 'SCOPED_PASS':
            locate('CLEANUP')
        if hasattr(cli, 'proxy'):
            cli.proxy.stdin.close()
            try:
                cli.proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cli.proxy.kill()
                cli.proxy.wait()
            cli.proxy_log.close()
        if daemon_started:
            try:
                if reply['status'] == 'SCOPED_PASS':
                    locate('CLEANUP', 'DAEMON_STOP')
                cli.command('owned-daemon-stop', ['app-server', 'daemon', 'stop'])
            except Exception:
                if reply['status'] == 'SCOPED_PASS':
                    reply.update(failure_phase='CLEANUP', failure_label='DAEMON_STOP', failure_kind='CLEANUP',
                                 failure_code='UNCLASSIFIED', hook_result='none', host_diagnostic=None)
                reply['status'] = 'FAIL'
                reply['cleanup_failed'] = True
        provider.close()
        assert digest(Path(cli.binary)) == cli.expected_binary
        counts = provider.request_counts()
        if reply['status'] == 'SCOPED_PASS':
            reply.update(host_provider_posts=counts['host'], native_queue_provider_posts=counts['native_queue'],
                         static_provider_posts=len(provider.requests))
            if counts['literal']:
                reply.update(status='FAIL', failure_phase='CLEANUP', failure_label='NONE', failure_kind='ASSERTION',
                             failure_code='ACTUAL_PROVIDER_REQUEST_UNCLASSIFIED', hook_result='none', host_diagnostic=None)
        if reply['status'] != 'SCOPED_PASS':
            reply.update(provider_posts=len(provider.requests),
                         literal_provider_posts=sum(row['phase'] == 'literal' for row in provider.requests))
            location.clear()
            location.update(native_stage_summary(reply['failure_phase'], reply['failure_label'], 'FAIL', reply['failure_kind'],
                                                reply['failure_code'], reply['hook_result'],
                                                reply['literal_provider_posts'], reply['provider_posts'], reply['host_diagnostic'],
                                                counts['host'], counts['native_queue']))
            publish_location()
        private_json(Path(config['result']), reply)
    return 0 if reply['status'] == 'SCOPED_PASS' else 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(run(json.loads(Path(sys.argv[1]).read_text())))
