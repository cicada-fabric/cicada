#!/usr/bin/env python3
"""Actual installed-plugin CLI gate; local static text source, no model.

Invoked only inside the disposable network-none product fixture. All raw CLI,
RPC and terminal output stays in its private state. This does not manufacture
native session_meta, replace a product Hook/MCP/Node, or prepare Hook trust by
editing hashes in config.toml.
"""
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import queue
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import unicodedata


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')


def render_terminal(raw, rows=45, columns=180):
    """Render the bounded PTY viewport; cursor moves also carry word spaces.

    Keep the original raw stream separately. This artifact reader implements
    cursor/erase/scroll operations used by the actual TUI, ignoring colors,
    mouse/keyboard modes and terminal capability queries.
    """
    screen = [[' '] * columns for _ in range(rows)]
    row = column = 0
    saved = (0, 0)
    text = raw.decode(errors='replace')
    index = 0

    def advance_line():
        nonlocal row
        row += 1
        if row >= rows:
            screen.pop(0)
            screen.append([' '] * columns)
            row = rows - 1

    while index < len(text):
        char = text[index]
        if char == '\x1b':
            if text[index:index + 2] == '\x1b[':
                match = re.match(r'\x1b\[([0-?]*)([ -/]*)([@-~])', text[index:])
                if match is None:
                    break
                values, _, final = match.groups()
                private = values.startswith('?')
                parameters = [int(value) if value.isdigit() else 0 for value in values.lstrip('?').split(';')]
                count = parameters[0] or 1
                if not private:
                    if final in ('H', 'f'):
                        row = max(0, min(rows - 1, count - 1))
                        column = max(0, min(columns - 1, (parameters[1] or 1) - 1 if len(parameters) > 1 else 0))
                    elif final in ('A', 'B'):
                        row = max(0, min(rows - 1, row + (count if final == 'B' else -count)))
                    elif final in ('C', 'D'):
                        column = max(0, min(columns - 1, column + (count if final == 'C' else -count)))
                    elif final in ('E', 'F'):
                        row = max(0, min(rows - 1, row + (count if final == 'E' else -count)))
                        column = 0
                    elif final == 'G':
                        column = max(0, min(columns - 1, count - 1))
                    elif final == 'd':
                        row = max(0, min(rows - 1, count - 1))
                    elif final == 'K':
                        start = 0 if parameters[0] in (1, 2) else column
                        end = columns if parameters[0] in (0, 2) else column + 1
                        screen[row][start:end] = [' '] * (end - start)
                    elif final == 'J':
                        if parameters[0] == 2:
                            screen = [[' '] * columns for _ in range(rows)]
                        elif parameters[0] == 0:
                            screen[row][column:] = [' '] * (columns - column)
                            screen[row + 1:] = [[' '] * columns for _ in range(rows - row - 1)]
                        elif parameters[0] == 1:
                            screen[:row] = [[' '] * columns for _ in range(row)]
                            screen[row][:column + 1] = [' '] * (column + 1)
                    elif final == 's':
                        saved = (row, column)
                    elif final == 'u':
                        row, column = saved
                index += len(match.group())
                continue
            if text[index:index + 2] == '\x1b]':
                match = re.match(r'\x1b\].*?(?:\x07|\x1b\\)', text[index:], re.DOTALL)
                if match is None:
                    break
                index += len(match.group())
                continue
            if text[index:index + 2] in ('\x1b7', '\x1b8'):
                if text[index + 1] == '7':
                    saved = (row, column)
                else:
                    row, column = saved
            index += 2
            continue
        if char == '\r':
            column = 0
        elif char == '\n':
            advance_line()
        elif char == '\b':
            column = max(0, column - 1)
        elif char == '\t':
            column = min(columns - 1, (column // 8 + 1) * 8)
        elif char >= ' ' and char != '\x7f':
            if unicodedata.combining(char) or unicodedata.category(char) in ('Mn', 'Me', 'Cf'):
                if column:
                    screen[row][column - 1] += char
            else:
                width = 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
                if column + width > columns:
                    column = 0
                    advance_line()
                screen[row][column] = char
                if width == 2:
                    screen[row][column + 1] = ''
                column += width
        index += 1
    return '\n'.join(''.join(line).rstrip() for line in screen).rstrip()


class ActualCLI:
    def __init__(self, config):
        self.config = config
        self.root = Path(config['root'])
        self.workspace = Path(config['workspace'])
        self.codex_home = Path(config['codex_home'])
        self.binary = config['codex_binary']
        self.marketplace = Path(config['marketplace'])
        self.environment = dict(item.split('=', 1) for item in config['environment'])
        self.environment['CICADA_SYNTHETIC_API_KEY'] = 'SYNTHETIC_LOCAL_STATIC_ONLY'
        self.step = config['step']
        self.state = self.root / ('cli-' + self.step)
        self.state.mkdir(mode=0o700)
        self.expected_binary = config['codex_sha256']
        assert digest(Path(self.binary)) == self.expected_binary, 'CODEX_BINARY_CHANGED'
        assert self.workspace.is_absolute() and self.codex_home.is_absolute()
        assert Path(self.environment['HOME']).is_relative_to(self.root)
        assert self.codex_home.is_relative_to(self.root)
        assert not (self.codex_home / 'hooks.json').exists(), 'USER_HOOK_SUBSTITUTE_FORBIDDEN'

    def command(self, label, arguments, timeout=25):
        # The actual 0.163 plugin management CLI rejects --strict-config.
        # Runtime invocations retain it; plugin installation uses its own
        # documented exact command in this empty owned HOME/CODEX_HOME.
        flags = [] if arguments[0] == 'plugin' else ['--no-daemon', '--strict-config']
        argv = [self.binary, *flags, *arguments]
        private_json(self.state / (label + '.command.json'), argv)
        process = subprocess.Popen(argv, env=self.environment, cwd=self.workspace,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            out, err = process.communicate()
            raise RuntimeError('CLI_TIMEOUT_' + label) from None
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        (self.state / (label + '.stdout')).write_bytes(out)
        (self.state / (label + '.stderr')).write_bytes(err)
        private_json(self.state / (label + '.exit.json'), {'exit_code': process.returncode})
        assert process.returncode == 0, 'CLI_NONZERO_' + label
        return out

    def inventory(self, label):
        argv = [self.binary, '--no-daemon', '--strict-config', 'app-server', '--stdio']
        log = (self.state / (label + '.rpc.stderr')).open('xb')
        process = subprocess.Popen(argv, env=self.environment, cwd=self.workspace,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, start_new_session=True)
        pending = queue.Queue(maxsize=32)

        def receive():
            for raw in process.stdout:
                if len(raw) > 4 * 1024 * 1024:
                    return
                pending.put(json.loads(raw))

        threading.Thread(target=receive, daemon=True).start()
        trace = []

        def rpc(number, method, params):
            value = {'id': number, 'method': method, 'params': params}
            trace.append({'send': value})
            process.stdin.write(json.dumps(value).encode() + b'\n')
            process.stdin.flush()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                value = pending.get(timeout=max(.01, deadline - time.monotonic()))
                trace.append({'receive': value})
                if value.get('id') == number:
                    assert 'error' not in value, 'ACTUAL_APP_SERVER_RPC_ERROR'
                    return value['result']
            raise TimeoutError('ACTUAL_APP_SERVER_RPC_TIMEOUT')

        try:
            rpc(1, 'initialize', {'clientInfo': {'name': 'synthetic-product-acceptance', 'version': '1'},
                                  'capabilities': {'experimentalApi': True}})
            plugins = rpc(2, 'plugin/list', {'cwds': [str(self.workspace)], 'forceRefetch': False,
                                            'marketplaceKinds': ['local']})
            hooks = rpc(3, 'hooks/list', {'cwds': [str(self.workspace)]})
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            log.close()
            private_json(self.state / (label + '.rpc.json'), trace)
        private_json(self.state / (label + '.plugins.json'), plugins)
        private_json(self.state / (label + '.hooks.json'), hooks)
        marketplaces = [m for m in plugins['marketplaces'] if m['name'] == 'cicada-repo']
        assert len(marketplaces) == 1, 'EXISTING_MARKETPLACE_NOT_LOADED'
        selected = [p for p in marketplaces[0]['plugins'] if p['name'] == 'cicada']
        assert len(selected) == 1 and selected[0]['installed'] and selected[0]['enabled'], 'EXISTING_PLUGIN_NOT_INSTALLED'
        plugin = selected[0]
        rows = [row for row in hooks['data'] if row['cwd'] == str(self.workspace)]
        assert len(rows) == 1 and not rows[0]['errors'], 'PRODUCT_HOOK_LOAD_ERROR'
        actual = rows[0]['hooks']
        assert len(actual) == 2, 'UNEXPECTED_HOOK_DEFINITIONS'
        assert {h['eventName'] for h in actual} == {'userPromptSubmit', 'preToolUse'}
        source_hash = digest(self.marketplace / '.agents/plugins/cicada/hooks/hooks.json')
        for hook in actual:
            assert hook['source'] == 'plugin' and hook['pluginId'] == plugin['id'], 'HOOK_NOT_FROM_INSTALLED_PLUGIN'
            assert hook['enabled'] and hook['handlerType'] == 'command'
            assert hook['command'] == 'cicada codex-hook', 'UNEXPECTED_PRODUCT_HOOK_COMMAND'
            assert digest(Path(hook['sourcePath'])) == source_hash, 'INSTALLED_HOOK_ASSET_DIFFERS'
        return actual

    def native_records(self):
        records = {}
        for path in (self.codex_home / 'sessions').rglob('rollout-*.jsonl'):
            assert len(records) < 64 and path.is_file() and not path.is_symlink()
            with path.open('rb') as stream:
                for _ in range(8):
                    raw = stream.readline(1024 * 1024)
                    if not raw:
                        break
                    value = json.loads(raw)
                    if value.get('type') == 'session_meta':
                        meta = value['payload']
                        if meta.get('cwd') == str(self.workspace):
                            records[meta['id']] = {'path': str(path), 'metadata': meta}
                        break
        return records

    def mcp_environment(self):
        # Only the actual product executable's owned MCP children inside this
        # network-none container are considered. Never export raw environment,
        # unrelated processes or credentials, only exact configuration matches.
        observed = []
        keys = ('HOME', 'CODEX_HOME', 'CICADA_API_URL', 'CICADA_MACHINE_ID',
                'CICADA_NODE_STATE_DIR', 'CICADA_STATE_DIR', 'CICADA_MCP_SESSION_STATE_FILE')
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if (proc / 'exe').resolve() != Path('/out/cicada'):
                    continue
                argv = (proc / 'cmdline').read_bytes().split(b'\0')
                if argv[1:3] != [b'mcp', b'--codex-context']:
                    continue
                environment = dict(value.split(b'=', 1) for value in (proc / 'environ').read_bytes().split(b'\0') if b'=' in value)
                observed.append({key: environment.get(key.encode()) == self.environment[key].encode() for key in keys})
            except (OSError, KeyError):
                continue
        return observed

    def literal_tui(self, hooks):
        before = set(self.native_records())
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 45, 180, 0, 0))
        prompt = 'cicada join "Synthetic installed-plugin Thread"'
        argv = [self.binary, '--no-daemon', '--no-alt-screen', '-C', str(self.workspace), prompt]
        private_json(self.state / 'tui.command.json', argv)
        # Attach a real controlling terminal before exec. Merely setsid with
        # inherited slave FDs leaves /dev/tty and its foreground group unset.
        # This is PTY plumbing only; the same reviewed Codex binary/argv and
        # installed product Hook/MCP execute without wrappers or overrides.
        launcher = ['/usr/bin/python3', '-c',
                    'import os,sys; os.login_tty(0); os.execvpe(sys.argv[1],sys.argv[1:],os.environ)', *argv]
        private_json(self.state / 'tui.launch.command.json', launcher)
        process = subprocess.Popen(launcher, env=self.environment, cwd=self.workspace,
                                   stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        captured = bytearray()
        trusted_by_tui = False
        trust_ready_at = None
        sent_peers = False
        visible = False
        peers_ready_at = None
        started = time.monotonic()
        plain = ''
        frames = []
        foreground_verified = False

        def type_command(command):
            # Human-paced ordinary terminal keys. One write containing an
            # entire prompt plus Enter is handled as a paste burst by Codex,
            # leaving Enter in the composer instead of submitting the prompt.
            for value in command.encode():
                os.write(master, bytes([value]))
                time.sleep(.05)
            time.sleep(.2)
            os.write(master, b'\r')
        try:
            while time.monotonic() - started < 45 and process.poll() is None:
                if trust_ready_at is not None and time.monotonic() >= trust_ready_at and not trusted_by_tui:
                    # Let the actual terminal capability/input initialization
                    # finish before choosing the still-visible normal control.
                    # The prior actual 0.163 normal-trust run waited two seconds.
                    if '2.Trustallandcontinue' in re.sub(r'\s+', '', plain):
                        os.write(master, b'2\r')
                        trusted_by_tui = True
                        frames.append({'stage': 'normal-trust-control', 'screen': plain,
                                       'elapsed_seconds': time.monotonic() - started})
                if peers_ready_at is not None and time.monotonic() >= peers_ready_at and not sent_peers:
                    if self.config.get('require_unique_literal_titles'):
                        assert compact.count('ThisThreadisregistered') == 1, 'ACTUAL_JOIN_RESULT_TITLE_DUPLICATED'
                        result_body = compact.split('ThisThreadisregistered', 1)[1]
                        assert 'Syntheticinstalled-pluginThread' in result_body and str(self.workspace) in result_body, 'ACTUAL_JOIN_RESULT_FIELDS_NOT_VISIBLE'
                    frames.append({'stage': 'literal-join', 'screen': plain})
                    type_command('cicada peers')
                    sent_peers = True
                if not select.select([master], [], [], .1)[0]:
                    continue
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                captured.extend(data)
                if not foreground_verified:
                    foreground_verified = os.tcgetpgrp(master) == process.pid
                assert len(captured) <= 2 * 1024 * 1024, 'TERMINAL_OUTPUT_BOUND_EXCEEDED'
                if b'\x1b[6n' in data:
                    os.write(master, b'\x1b[1;1R')
                if b'\x1b[c' in data:
                    os.write(master, b'\x1b[?1;2c')
                plain = render_terminal(captured)
                compact = re.sub(r'\s+', '', plain)
                # The two definitions were read from the actual installed
                # plugin and checked above. Use only the observed normal TUI
                # control; never inject prepared trust hashes or bypass flags.
                if '2.Trustallandcontinue' in compact and not trusted_by_tui:
                    assert all(h['trustStatus'] in ('untrusted', 'modified', 'trusted', 'managed') for h in hooks)
                    if trust_ready_at is None:
                        trust_ready_at = time.monotonic() + 2
                if 'ThisThreadisregistered' in compact and peers_ready_at is None:
                    peers_ready_at = time.monotonic() + .5
                if (sent_peers and 'NodeThreaddirectorysnapshot' in compact and
                        'Syntheticinstalled-pluginThread' in compact and str(self.workspace) in compact and
                        'Offlineatsnapshot' in compact):
                    if self.config.get('require_unique_literal_titles'):
                        time.sleep(.4)
                        while select.select([master], [], [], 0)[0]:
                            captured.extend(os.read(master, 65536))
                        plain = render_terminal(captured)
                        compact = re.sub(r'\s+', '', plain)
                        assert compact.count('NodeThreaddirectorysnapshot') == 1, 'ACTUAL_PEERS_RESULT_TITLE_DUPLICATED'
                        result_body = compact.split('NodeThreaddirectorysnapshot', 1)[1]
                        assert ('Syntheticinstalled-pluginThread' in result_body and str(self.workspace) in result_body and
                                'Offlineatsnapshot' in result_body), 'ACTUAL_PEERS_RESULT_FIELDS_NOT_VISIBLE'
                    visible = True
                    frames.append({'stage': 'literal-peers', 'screen': plain})
                    type_command('/exit')
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        pass
                    break
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            os.close(master)
            (self.state / 'tui.raw').write_bytes(captured)
            (self.state / 'tui.txt').write_text(plain)
            private_json(self.state / 'tui.frames.json', frames)
            sdk_log = self.codex_home / 'log/codex-tui.log'
            if sdk_log.is_file():
                with sdk_log.open('rb') as stream:
                    stream.seek(max(0, sdk_log.stat().st_size - 2 * 1024 * 1024))
                    (self.state / 'sdk-tui.private.txt').write_bytes(stream.read(2 * 1024 * 1024))
            private_json(self.state / 'tui.exit.json', {'exit_code': process.returncode,
                         'normal_trust_control_used': trusted_by_tui, 'literal_join_peers_visible': visible,
                         'controlling_terminal_foreground_verified': foreground_verified})
        assert foreground_verified, 'ACTUAL_PTY_FOREGROUND_NOT_CONFIRMED'
        assert visible, 'ACTUAL_TUI_LITERAL_RESULT_NOT_VISIBLE'
        assert process.returncode == 0, 'ACTUAL_TUI_EXIT_NONZERO'
        added = set(self.native_records()) - before
        assert len(added) == 1, 'ACTUAL_TUI_NATIVE_IDENTITY_UNCONFIRMED'
        return added.pop()


def run(config):
    cli = ActualCLI(config)
    requests = []
    # An actual resumed Thread includes prior function outputs. Bind this
    # static dispatch to a distinct phase ID so only its current result is
    # considered; history must not satisfy or mask the current Guard check.
    invocation_suffix = hashlib.sha256(cli.step.encode()).hexdigest()[:16]
    call_id = 'call_synthetic_actual_whoami_' + invocation_suffix
    item_id = 'fc_synthetic_actual_whoami_' + invocation_suffix
    stage = {'name': 'literal', 'issues': [], 'whoami_not_joined': False,
             'context_required': False, 'mcp_environment': [], 'whoami_actor': None, 'guard_denied': False}

    def actor_from_output(value):
        if isinstance(value, dict):
            if value.get('endpoint_id') and value.get('binding_epoch'):
                return value
            for child in value.values():
                found = actor_from_output(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = actor_from_output(child)
                if found is not None:
                    return found
        elif isinstance(value, str):
            for match in re.finditer(r'\{', value):
                try:
                    decoded, _ = json.JSONDecoder().raw_decode(value[match.start():])
                except ValueError:
                    continue
                if isinstance(decoded, (dict, list)):
                    found = actor_from_output(decoded)
                    if found is not None:
                        return found
        return None

    class StaticProvider(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"data":[]}')

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            assert 0 <= size <= 4 * 1024 * 1024
            raw = self.rfile.read(size)
            request = json.loads(raw)
            requests.append({'stage': stage['name'], 'path': self.path, 'request_sha256': hashlib.sha256(raw).hexdigest()})
            count = sum(item['stage'] == stage['name'] for item in requests)
            private_json(cli.state / (stage['name'] + '-provider-request-' + str(count) + '.json'), request)
            # A literal command should never need this harmless text response.
            # Keeping it finite exposes accidental pass-through as a semantic
            # failure even if the actual CLI exits successfully.
            item = {'type': 'message', 'id': 'msg_synthetic_local', 'role': 'assistant', 'status': 'completed',
                    'content': [{'type': 'output_text', 'text': 'SYNTHETIC LOCAL STATIC TEXT; NO MODEL', 'annotations': []}]}
            argument_events = []
            if stage['name'] == 'host-whoami':
                if count == 1:
                    stage['mcp_environment'] = cli.mcp_environment()
                    matches = [(tool['name'], function) for tool in request.get('tools', [])
                               if tool.get('type') == 'namespace'
                               for function in tool.get('tools', [])
                               if function.get('type') == 'function' and function.get('name') == 'cicada_whoami']
                    if len(matches) != 1:
                        stage['issues'].append('ACTUAL_HOST_WHOAMI_NOT_ADVERTISED')
                    else:
                        namespace, function = matches[0]
                        nonce_schema = function.get('parameters', {}).get('properties', {}).get('_cicada_context', {}).get('properties', {}).get('connection_nonce', {})
                        nonce = nonce_schema.get('const')
                        # Actual 0.163 exposes the product's const as a
                        # singleton enum in the model-facing function schema.
                        # Read only that advertised unique value, never infer
                        # a nonce from prior calls, metadata or another scope.
                        allowed = nonce_schema.get('enum')
                        if nonce is None and isinstance(allowed,list) and len(allowed)==1:
                            nonce = allowed[0]
                        elif nonce is not None and allowed is not None and allowed != [nonce]:
                            nonce = None
                        if not isinstance(nonce, str) or re.fullmatch('[0-9a-f]{64}', nonce) is None:
                            stage['issues'].append('ACTUAL_HOST_CONNECTION_NONCE_NOT_ADVERTISED')
                        else:
                            arguments = json.dumps({'_cicada_context': {'connection_nonce': nonce}})
                            item = {'type': 'function_call', 'id': item_id, 'call_id': call_id,
                                    'namespace': namespace, 'name': function['name'], 'arguments': arguments, 'status': 'completed'}
                            argument_events = [
                                ('response.output_item.added', {'output_index': 0, 'item': {**item, 'arguments': '', 'status': 'in_progress'}}),
                                ('response.function_call_arguments.delta', {'item_id': item['id'], 'output_index': 0, 'delta': arguments}),
                                ('response.function_call_arguments.done', {'item_id': item['id'], 'output_index': 0, 'arguments': arguments})]
                elif count == 2:
                    outputs = [value for value in request.get('input', [])
                               if value.get('type') == 'function_call_output' and value.get('call_id') == call_id]
                    text = json.dumps(outputs, ensure_ascii=False)
                    stage['context_required'] = any(value in text for value in
                                                     ('CODEX_CALL_CONTEXT_REQUIRED', 'CODEX_CONTEXT_UNSUPPORTED', 'could not verify this invocation'))
                    stage['whoami_not_joined'] = (len(outputs) == 1 and not stage['context_required'] and
                                                  any(value in text for value in
                                                      ('requires an active Cicada session; call cicada_join first',
                                                       'Cicada session is not joined; call cicada_join first')))
                    stage['whoami_actor'] = actor_from_output(outputs)
                    stage['guard_denied'] = (len(outputs) == 1 and not stage['context_required'] and
                                             'requires approval' not in text and
                                             re.search(r'Cicada Hub (?:401|403)', text) is not None)
                else:
                    stage['issues'].append('UNEXPECTED_HOST_WHOAMI_PROVIDER_REQUEST')
            response = {'id': 'resp_synthetic_' + invocation_suffix + '_' + stage['name'].replace('-', '_') + '_' + str(count), 'object': 'response', 'status': 'completed', 'created_at': int(time.time()),
                        'output': [item], 'usage': {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}}
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            for index, (name, value) in enumerate([
                    ('response.created', {'response': {**response, 'status': 'in_progress', 'output': []}}),
                    *argument_events,
                    ('response.output_item.done', {'output_index': 0, 'item': item}),
                    ('response.completed', {'response': response})]):
                self.wfile.write(('event: ' + name + '\ndata: ' + json.dumps({'type': name, 'sequence_number': index, **value}) + '\n\n').encode())
                self.wfile.flush()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), StaticProvider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    result = {'scope': 'ACTUAL_INSTALLED_PLUGIN_LITERAL_TUI_AND_HOST_MCP_CONTEXT', 'status': 'FAIL',
              'real_model_turns': 0, 'provider_http_requests': requests}
    try:
        configuration = cli.codex_home / 'config.toml'
        operation = config.get('operation', 'full')
        assert operation in ('full', 'literal-setup', 'literal-command', 'host-whoami'), 'UNKNOWN_ACCEPTANCE_PHASE'
        if operation in ('full', 'literal-setup'):
            assert not configuration.exists(), 'FRESH_CLI_HOME_REQUIRED'
            configuration.write_text('''model = "synthetic-no-model"
model_provider = "qa_static"
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic local static text; no model"
base_url = "http://127.0.0.1:PORT/v1"
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('PORT', str(server.server_port)) + '\n[projects.' + json.dumps(str(cli.workspace)) + ']\ntrust_level = "trusted"\n')
            cli.command('marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
            cli.command('plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
            hooks = cli.inventory('installed-before')
            sid = cli.literal_tui(hooks)
            after = cli.inventory('installed-after')
            assert all(h['trustStatus'] in ('trusted', 'managed') for h in after), 'NORMAL_PLUGIN_HOOK_TRUST_NOT_CONFIRMED'
            assert {h['key']: h['currentHash'] for h in hooks} == {h['key']: h['currentHash'] for h in after}
            record = cli.native_records()[sid]
            assert record['metadata']['source'] == 'cli', 'ACTUAL_TUI_SOURCE_NOT_CONFIRMED'
            assert not requests, 'LITERAL_COMMAND_REACHED_PROVIDER'
            result.update(native_session_id=sid, native_record=record['path'],
                          name='Synthetic installed-plugin Thread', workspace=str(cli.workspace), presence='offline',
                          actual_plugin_hook_source=True, literal_join_peers_visible=True, literal_provider_requests=0)
            if operation == 'literal-setup':
                result.update(status='SCOPED_PASS', scope='ACTUAL_LITERAL_SETUP_ONLY_NO_MCP_TOOL')
                return 0
        else:
            assert configuration.is_file(), 'ORIGINAL_CLI_PROFILE_REQUIRED'
            # Replace only this fixture's static provider endpoint. Keep the
            # actual normal trust entries, native records and product state.
            updated, count = re.subn(r'base_url = "http://127\.0\.0\.1:[0-9]+/v1"',
                                    'base_url = "http://127.0.0.1:' + str(server.server_port) + '/v1"', configuration.read_text())
            assert count == 1, 'ORIGINAL_STATIC_PROVIDER_CONFIGURATION_CHANGED'
            configuration.write_text(updated)
            hooks = cli.inventory('installed-before')
            assert all(h['trustStatus'] in ('trusted', 'managed') for h in hooks), 'ORIGINAL_HOOK_TRUST_REQUIRED'
        if operation == 'literal-command':
            prompt = config['prompt']
            assert prompt.startswith('cicada '), 'LITERAL_COMMAND_REQUIRED'
            arguments = ['exec', '--json', '--skip-git-repo-check', '--color', 'never', '-C', str(cli.workspace)]
            if config.get('resume_sid'):
                arguments += ['resume', config['resume_sid']]
            out = cli.command('literal-command', [*arguments, prompt], timeout=45)
            events = [json.loads(line) for line in out.splitlines() if line.startswith(b'{')]
            ids = [event['thread_id'] for event in events if event.get('type') == 'thread.started']
            assert len(ids) == 1 and (not config.get('resume_sid') or ids[0] == config['resume_sid']), 'ACTUAL_ORIGINAL_THREAD_NOT_RESUMED'
            record = cli.native_records()[ids[0]]
            assert not requests, 'LITERAL_COMMAND_REACHED_PROVIDER'
            result.update(status='SCOPED_PASS', scope='ACTUAL_LITERAL_COMMAND_ONLY_OUTCOME_REQUIRES_SIGNED_APP_CHECK',
                          native_session_id=ids[0], native_record=record['path'], literal_provider_requests=0)
            return 0
        # Normal user policy for exactly one installed-plugin read tool. This
        # changes no MCP transport, Hook trust, context ticket or Cicada grant;
        # global Never still denies unapproved tools. The actual tool must
        # still reach the business not-joined refusal below.
        policy = '\n[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.cicada_whoami]\napproval_mode = "approve"\n'
        if '[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.cicada_whoami]' not in configuration.read_text():
            with configuration.open('a') as stream:
                stream.write(policy)
        private_json(cli.state / 'host-single-tool-policy.json', {
            'configuration': policy, 'global_approval_policy': 'never',
            'official_documentation': 'https://learn.chatgpt.com/docs/extend/mcp#plugin-provided-mcp-servers',
            'official_source_commit': '83086188ae0614bd882818ff1aa23f3194962012',
            'scope': 'normal host approval for this read tool only; no Cicada authorization'})
        stage['name'] = 'host-whoami'
        arguments = ['exec', '--json', '--skip-git-repo-check', '--color', 'never', '-C', str(cli.workspace)]
        if config.get('resume_sid'):
            arguments += ['resume', config['resume_sid']]
        cli.command('host-whoami', [*arguments, 'Synthetic acceptance: call the installed Cicada cicada_whoami tool once.'], timeout=45)
        result['host_whoami_not_joined'] = stage['whoami_not_joined']
        result['host_context_required'] = stage['context_required']
        result['host_whoami_provider_requests'] = sum(item['stage'] == 'host-whoami' for item in requests)
        result['host_mcp_configuration_matches'] = stage['mcp_environment']
        assert not stage['issues'], ','.join(stage['issues'])
        assert result['host_whoami_provider_requests'] == 2, 'HOST_WHOAMI_DISPATCH_NOT_CONFIRMED'
        expected = config.get('expected_actor')
        if expected:
            actor = stage['whoami_actor']
            assert actor and not stage['context_required'] and all(actor.get(key) == value for key, value in expected.items()), 'HOST_WHOAMI_ORIGINAL_ACTOR_MISMATCH'
            result['host_actor'] = {key: actor[key] for key in expected}
        elif config.get('expect_guard_denied'):
            assert stage['guard_denied'] and not stage['context_required'], 'HOST_WHOAMI_EXPECTED_CURRENT_GUARD_DENIAL'
            result['host_current_guard_denied'] = True
        else:
            assert stage['whoami_not_joined'] and not stage['context_required'], 'HOST_WHOAMI_EXPECTED_NOT_JOINED'
        # Context-mode MCP receives native identity from its verified Node
        # ticket, not CODEX_HOME history. Keep CODEX_HOME as an observation;
        # only Node/Hook must share that actual record root. Hub/Node/state
        # configuration and the owned HOME are required in the real child.
        required_configuration = ('HOME', 'CICADA_API_URL', 'CICADA_MACHINE_ID',
                                  'CICADA_NODE_STATE_DIR', 'CICADA_STATE_DIR', 'CICADA_MCP_SESSION_STATE_FILE')
        assert stage['mcp_environment'] and all(all(row.get(key) is True for key in required_configuration)
                                               for row in stage['mcp_environment']), 'HOST_MCP_CONFIGURATION_NOT_PRESERVED'
        if operation == 'full':
            assert len(cli.native_records()) == 2, 'HOST_WHOAMI_NATIVE_EXEC_RECORD_NOT_CONFIRMED'
        result['status'] = 'SCOPED_PASS'
    except Exception as error:
        result['failure_category'] = str(error)[:180]
        # This diagnostic reads actual persisted trust in another process; it
        # cannot confer trust, replace the original failure or qualify visible
        # output. Preserve it even when the PTY phase did not complete.
        if (cli.state / 'installed-before.hooks.json').is_file():
            try:
                post = cli.inventory('failed-after')
                result['post_failure_hook_trust'] = {hook['eventName']: hook['trustStatus'] for hook in post}
                result['post_failure_hook_hashes'] = {hook['eventName']: hook['currentHash'] for hook in post}
            except Exception as diagnostic_error:
                result['post_failure_inventory_error'] = str(diagnostic_error)[:180]
    finally:
        server.shutdown()
        server.server_close()
        result['codex_sha256_after'] = digest(Path(cli.binary))
        if result['codex_sha256_after'] != cli.expected_binary:
            result['status'] = 'FAIL'
            result['failure_category'] = 'CODEX_BINARY_CHANGED'
        private_json(Path(config['result']), result)
    return 0 if result['status'] == 'SCOPED_PASS' else 1


if __name__ == '__main__':
    os.umask(0o077)
    with Path(sys.argv[1]).open() as stream:
        config = json.load(stream)
    raise SystemExit(run(config))
