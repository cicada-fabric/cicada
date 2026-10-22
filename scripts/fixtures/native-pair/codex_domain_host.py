#!/usr/bin/env python3
"""Actual persistent Codex Host calls through a local static provider.

Support for the isolated native-domain driver, not a replacement MCP server or
model. Original Thread IDs come only from actual native TUI records. The only
context value supplied here is the exact nonce advertised in the current real
Host tool schema; the installed Hook/Node must issue and consume their ticket.
"""
import collections
import hashlib
import http.server
import json
import re
import sys
import threading
import time

sys.dont_write_bytecode = True
from codex_three_stage import PersistentCLI

DOMAIN_ADMISSION_TITLE = "This Thread's local collaboration admission is saved; current Hub Guard verifies subsequent communication."


def output_objects(value):
    """Decode real MCP wrappers; do not infer values from arbitrary text."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from output_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from output_objects(child)
    elif isinstance(value, str) and value.lstrip().startswith(('{', '[')):
        try:
            decoded = json.loads(value)
        except ValueError:
            return
        yield from output_objects(decoded)


def unique_output_field(value, name):
    values = {row[name] for row in output_objects(value)
              if isinstance(row.get(name), str) and row[name] and len(row[name]) <= 4096}
    assert len(values) == 1, 'ACTUAL_HOST_RESULT_FIELD_MISSING_OR_AMBIGUOUS_' + name
    return values.pop()


def require_successful_output(value):
    rows = list(output_objects(value))
    assert value is not None and not any(row.get('isError') is True for row in rows), 'ACTUAL_HOST_TOOL_REFUSED'
    return value


HOST_PROVIDER_ISSUES = frozenset(('ACTUAL_HOST_TOOL_NOT_UNIQUE_OR_MISSING', 'ACTUAL_HOST_CURRENT_NONCE_MISSING',
                                 'CURRENT_HOST_TOOL_OUTPUT_MISSING_OR_DUPLICATED', 'UNEXPECTED_EXTRA_PROVIDER_POST'))
HOST_PUBLIC_FIELDS = ('native_session_id', 'workspace', 'node_id', 'endpoint_id', 'group_id', 'binding_epoch',
                      'operation_id', 'request_id', 'error_code', 'code', 'isError')
HOST_PRODUCT_ERROR_CODES = frozenset(('CODEX_CALL_CONTEXT_REQUIRED', 'CODEX_NATIVE_COORDINATES_INVALID',
                                     'CODEX_NATIVE_RECORD_UNVERIFIED', 'CODEX_TOOL_INPUT_MISSING',
                                     'CODEX_CALL_CONTEXT_MISSING', 'CODEX_CONNECTION_NONCE_INVALID',
                                     'CODEX_TOOL_ARGUMENTS_INVALID', 'CODEX_ARGUMENT_DIGEST_UNAVAILABLE',
                                     'CODEX_NODE_TICKET_UNAVAILABLE')) | frozenset(
    'CODEX_NATIVE_RECORD_' + stage for stage in
    ('ROOT', 'PATH', 'OWNERSHIP', 'PERMISSION', 'INODE', 'METADATA', 'SOURCE', 'SESSION', 'WORKSPACE'))


def host_value_type(value):
    return {type(None): 'null', bool: 'boolean', int: 'integer', float: 'number', str: 'string',
            list: 'array', dict: 'object'}.get(type(value), 'other')


def host_output_diagnostic(value, issues=(), observed=True):
    # Inspect the existing parser's result without changing it. Only fixed
    # field names, types, booleans and public error-code enums leave memory.
    rows = list(output_objects(value)) if observed else []
    flags = [row['isError'] for row in rows if type(row.get('isError')) is bool]
    prefix = 'not_string'
    if observed and isinstance(value, str):
        prefix = 'object' if value.lstrip().startswith('{') else 'array' if value.lstrip().startswith('[') else 'other'
    try:
        text = json.dumps(value) if observed else ''
    except (TypeError, ValueError):
        text = ''
    return {'observed': observed, 'output_type': host_value_type(value) if observed else 'not_observed',
            'json_string_prefix': prefix, 'parsed_object_present': bool(rows),
            'is_error_observed': bool(flags), 'is_error': any(flags) if flags else None,
            'fields': {name: {'present': any(name in row for row in rows),
                              'types': sorted({host_value_type(row[name]) for row in rows if name in row})}
                       for name in HOST_PUBLIC_FIELDS},
            'product_error_codes': sorted(code for code in HOST_PRODUCT_ERROR_CODES
                                          if re.search(r'(?<![A-Z0-9_])' + code + r'(?![A-Z0-9_])', text)),
            'hub_http_statuses': sorted({int(code) for code in re.findall(r'Cicada Hub (401|403|409|410|429|500|503)\b', text)}),
            'provider_issues': sorted({code if code in HOST_PROVIDER_ISSUES else 'UNCLASSIFIED' for code in issues})}


class StaticHostProvider:
    def __init__(self, run_scope):
        self.scope = hashlib.sha256(run_scope.encode()).hexdigest()[:16]
        self.phase = None
        self.sequence = 0
        self.requests = []
        self.last_diagnostic = None
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"data":[]}')

            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 <= size <= 4 * 1024 * 1024:
                    self.send_error(413)
                    return
                raw = self.rfile.read(size)
                request = json.loads(raw)
                phase = owner.phase
                owner.requests.append({'phase': phase['label'] if phase else 'literal',
                                       'request_sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
                phase_id = phase['id'] if phase else owner.scope + '_unexpected_literal'
                final = 'SYNTHETIC STATIC HOST RESPONSE; NO REAL MODEL'
                item = {'type': 'message', 'id': 'msg_' + phase_id + '_' + str(len(owner.requests)), 'role': 'assistant', 'status': 'completed',
                        'content': [{'type': 'output_text', 'text': final, 'annotations': []}]}
                events = []
                if phase is None:
                    # Even an accidental literal pass-through receives only a
                    # neutral bounded text. The literal driver requires zero POSTs.
                    phase_id = owner.scope + '_unexpected_literal'
                else:
                    phase_id = phase['id']
                    phase['posts'] += 1
                    if phase['posts'] == 1:
                        matches = [(tool['name'], function) for tool in request.get('tools', [])
                                   if tool.get('type') == 'namespace'
                                   for function in tool.get('tools', [])
                                   if function.get('type') == 'function' and function.get('name') == phase['tool']]
                        if len(matches) != 1:
                            phase['issues'].append('ACTUAL_HOST_TOOL_NOT_UNIQUE_OR_MISSING')
                        else:
                            namespace, function = matches[0]
                            schema = function.get('parameters', {}).get('properties', {}).get('_cicada_context', {}).get('properties', {}).get('connection_nonce', {})
                            nonce = schema.get('const')
                            allowed = schema.get('enum')
                            if nonce is None and isinstance(allowed, list) and len(allowed) == 1:
                                nonce = allowed[0]
                            elif nonce is not None and allowed is not None and allowed != [nonce]:
                                nonce = None
                            if not isinstance(nonce, str) or re.fullmatch('[0-9a-f]{64}', nonce) is None:
                                phase['issues'].append('ACTUAL_HOST_CURRENT_NONCE_MISSING')
                            else:
                                arguments = {**phase['arguments'], '_cicada_context': {'connection_nonce': nonce}}
                                encoded = json.dumps(arguments, separators=(',', ':'))
                                item = {'type': 'function_call', 'id': 'fc_' + phase_id, 'call_id': phase['call_id'],
                                        'namespace': namespace, 'name': phase['tool'], 'arguments': encoded, 'status': 'completed'}
                                events = [
                                    ('response.output_item.added', {'output_index': 0, 'item': {**item, 'arguments': '', 'status': 'in_progress'}}),
                                    ('response.function_call_arguments.delta', {'item_id': item['id'], 'output_index': 0, 'delta': encoded}),
                                    ('response.function_call_arguments.done', {'item_id': item['id'], 'output_index': 0, 'arguments': encoded})]
                    elif phase['posts'] == 2:
                        outputs = [value for value in request.get('input', [])
                                   if value.get('type') == 'function_call_output' and value.get('call_id') == phase['call_id']]
                        if len(outputs) != 1:
                            phase['issues'].append('CURRENT_HOST_TOOL_OUTPUT_MISSING_OR_DUPLICATED')
                        else:
                            phase['output'] = outputs[0].get('output')
                            phase['output_received'] = True
                            phase['output_sha256'] = hashlib.sha256(json.dumps(phase['output'], sort_keys=True).encode()).hexdigest()
                    else:
                        phase['issues'].append('UNEXPECTED_EXTRA_PROVIDER_POST')
                response = {'id': 'resp_' + phase_id + '_' + str(len(owner.requests)), 'object': 'response',
                            'status': 'completed', 'created_at': int(time.time()), 'output': [item],
                            'usage': {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}}
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Connection', 'close')
                self.end_headers()
                for index, (name, value) in enumerate([
                        ('response.created', {'response': {**response, 'status': 'in_progress', 'output': []}}),
                        *events,
                        ('response.output_item.done', {'output_index': 0, 'item': item}),
                        ('response.completed', {'response': response})]):
                    self.wfile.write(('event: ' + name + '\ndata: ' + json.dumps({'type': name, 'sequence_number': index, **value}) + '\n\n').encode())
                    self.wfile.flush()

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def origin(self):
        return 'http://127.0.0.1:' + str(self.server.server_port) + '/v1'

    def begin(self, label, tool, arguments):
        assert self.phase is None, 'HOST_PHASE_OVERLAP'
        assert '_cicada_context' not in arguments, 'CALLER_CONTEXT_TICKET_SUBSTITUTE_FORBIDDEN'
        self.sequence += 1
        unique = self.scope + '_' + str(self.sequence) + '_' + hashlib.sha256(label.encode()).hexdigest()[:12]
        self.phase = {'label': label, 'id': unique, 'call_id': 'call_' + unique, 'tool': tool,
                      'arguments': arguments, 'posts': 0, 'issues': [], 'output': None, 'output_received': False}

    def reset_diagnostic(self):
        self.last_diagnostic = None

    def safe_diagnostic(self):
        if self.phase is not None:
            return host_output_diagnostic(self.phase['output'], self.phase['issues'], self.phase['output_received'])
        return self.last_diagnostic

    def finish(self):
        if self.phase is not None:
            self.last_diagnostic = self.safe_diagnostic()
        phase, self.phase = self.phase, None
        assert phase and phase['posts'] == 2 and not phase['issues'] and phase['output'] is not None, 'ACTUAL_HOST_PHASE_INCOMPLETE'
        # Raw tool output is used only in memory by this owned synthetic driver.
        # Persist only explicitly selected public metadata/digests in its caller.
        return phase['output'], {'label': phase['label'], 'tool': phase['tool'], 'provider_posts': phase['posts'],
                                 'output_sha256': phase['output_sha256'], 'real_model_turns': 0}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class DomainHostCLI(PersistentCLI):
    """Original native TUI's same daemon, using the official v2 JSON-RPC schema."""

    def literal_admit(self, provider, label, name):
        before = len(provider.requests)
        prompt = 'cicada join ' + json.dumps(name)
        sid = self.literal(label, prompt, DOMAIN_ADMISSION_TITLE, registered_name=name)
        assert len(provider.requests) == before, 'LITERAL_ADMISSION_REACHED_PROVIDER'
        screen = (self.root / ('cli-' + label) / 'tui.txt').read_text()
        compact = re.sub(r'\s+', '', screen)
        prompt_echo = '›' + re.sub(r'\s+', '', prompt)
        assert prompt_echo in compact, 'CURRENT_LITERAL_PROMPT_NOT_VISIBLE'
        result = compact.rsplit(prompt_echo, 1)[1]
        title = re.sub(r'\s+', '', DOMAIN_ADMISSION_TITLE)
        assert result.count(title) == 1 and re.sub(r'\s+', '', name) in result and str(self.workspace) in result, 'DOMAIN_ADMISSION_TITLE_OR_ORIGINAL_FIELDS_MISSING'
        records = [row for row in self.native_metadata() if row['id'] == sid]
        assert len(records) == 1 and records[0]['cwd_matches_original'] and records[0]['uid_matches_current'] and records[0]['open_inode_matches'], 'ORIGINAL_NATIVE_RECORD_MISMATCH'
        return sid, records[0]

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
                assert 'error' not in reply, 'ACTUAL_DAEMON_RPC_REFUSED_' + method
                return reply['result']
            assert 'id' not in reply, 'UNEXPECTED_NATIVE_HOST_APPROVAL_OR_RPC'
            assert len(self.notifications) < 512, 'ACTUAL_DAEMON_NOTIFICATION_BOUND'
            self.notifications.append(reply)
        raise RuntimeError('ACTUAL_DAEMON_RPC_TIMEOUT_' + method)

    def host_call(self, provider, sid, label, tool, arguments):
        provider.reset_diagnostic()
        assert sid in self.native_records(), 'HOST_THREAD_NOT_CREATED_BY_NATIVE_TUI'
        assert self.daemon_identity() == self.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
        resumed = self.rpc('thread/resume', {'threadId': sid})
        assert resumed['thread']['id'] == sid and resumed['thread']['cwd'] == str(self.workspace), 'ACTUAL_ORIGINAL_THREAD_SCOPE_CHANGED'
        provider.begin(label, tool, arguments)
        started = self.rpc('turn/start', {'threadId': sid,
                           'input': [{'type': 'text', 'text': 'SYNTHETIC LOCAL DOMAIN HOST TOOL ' + label}]})
        turn_id = started['turn']['id']
        deadline = time.monotonic() + 80
        while time.monotonic() < deadline:
            event = self.notifications.popleft() if self.notifications else self.messages.get(timeout=max(.01, deadline - time.monotonic()))
            if isinstance(event, Exception):
                raise event
            assert 'id' not in event, 'UNEXPECTED_NATIVE_HOST_APPROVAL_OR_RPC'
            params = event.get('params', {})
            if event.get('method') == 'turn/completed' and params.get('threadId') == sid and params.get('turn', {}).get('id') == turn_id:
                assert params['turn']['status'] == 'completed' and not params['turn'].get('error'), 'ACTUAL_NATIVE_HOST_TURN_FAILED'
                result = provider.finish()
                assert self.daemon_identity() == self.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
                return result
        raise RuntimeError('ACTUAL_NATIVE_HOST_TURN_TIMEOUT')
