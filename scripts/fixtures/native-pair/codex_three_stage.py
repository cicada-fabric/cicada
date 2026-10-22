#!/usr/bin/env python3
"""One real persistent Codex daemon; install/connect/restart, no Pair or model."""
import hashlib
import base64
import struct
import http.server
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
import traceback

sys.dont_write_bytecode = True
from codex_product_cli import ActualCLI, digest, private_json


class PersistentCLI(ActualCLI):
    def command(self, label, arguments, timeout=30):
        argv = [self.binary, *arguments]
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
        (self.state / (label + '.stdout')).write_bytes(out)
        (self.state / (label + '.stderr')).write_bytes(err)
        private_json(self.state / (label + '.exit.json'), {'exit_code': process.returncode})
        assert process.returncode == 0, 'CLI_NONZERO_' + label
        return out

    def daemon_identity(self):
        found = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                executable = (proc / 'exe').resolve()
                # The official daemon start command installs an exact package
                # copy in this owned CODEX_HOME. Verify those bytes rather than
                # requiring the original read-only package pathname.
                if executable != Path(self.binary) and not executable.is_relative_to(self.codex_home / 'packages/app-server-daemon'):
                    continue
                if digest(executable) != self.expected_binary:
                    continue
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if b'app-server' not in args or b'proxy' in args or b'daemon' in args:
                    continue
                env = dict(value.split(b'=', 1) for value in (proc / 'environ').read_bytes().split(b'\0') if b'=' in value)
                if env.get(b'CODEX_HOME') != str(self.codex_home).encode():
                    continue
                keys = ('CICADA_API_URL', 'CICADA_MACHINE_ID', 'CICADA_NODE_STATE_DIR',
                        'CICADA_STATE_DIR', 'CICADA_MCP_SESSION_STATE_FILE')
                assert not any(env.get(key.encode()) for key in keys), 'DAEMON_INHERITED_DEPLOYMENT_ENV'
                start = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
                found.append({'pid': int(proc.name), 'start_ticks': start, 'five_deployment_variables_absent': True, 'executable_sha256': self.expected_binary})
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        assert len(found) == 1, 'ONE_OWNED_PERSISTENT_DAEMON_REQUIRED'
        return found[0]

    def connect(self):
        self.proxy_log = (self.state / 'persistent-proxy.stderr').open('xb')
        self.proxy = subprocess.Popen([self.binary, 'app-server', 'proxy', '--sock', self.control_socket],
                                     env=self.environment, cwd=self.workspace,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self.proxy_log, start_new_session=True, bufsize=0)
        self.messages = queue.Queue(maxsize=256)
        self.sequence = 0
        # The official Unix control socket carries WebSocket, not JSONL.
        # The official proxy supplies only the byte transport; this bounded
        # stdlib framing connects to that same already-running daemon.
        self.write_lock = threading.Lock()
        key = base64.b64encode(os.urandom(16)).decode()
        request = ('GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
                   'Connection: Upgrade\r\nSec-WebSocket-Key: ' + key +
                   '\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.proxy.stdin.write(request.encode())
        self.proxy.stdin.flush()
        header = bytearray()
        while not header.endswith(b'\r\n\r\n'):
            value = self.proxy.stdout.read(1)
            assert value and len(header) < 8192, 'DAEMON_WEBSOCKET_UPGRADE_MISSING'
            header.extend(value)
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert header.startswith(b'HTTP/1.1 101 ') and accept.lower() in header.lower(), 'DAEMON_WEBSOCKET_UPGRADE_REFUSED'
        def receive():
            try:
                fragments = bytearray()
                while True:
                    first, second = self.read_exact(2)
                    opcode, final = first & 15, bool(first & 128)
                    size = second & 127
                    if size == 126:
                        size = struct.unpack('!H', self.read_exact(2))[0]
                    elif size == 127:
                        size = struct.unpack('!Q', self.read_exact(8))[0]
                    assert not second & 128 and size <= 4 * 1024 * 1024, 'DAEMON_WEBSOCKET_FRAME_INVALID'
                    payload = self.read_exact(size)
                    if opcode == 8:
                        return
                    if opcode == 9:
                        self.send_frame(payload, 10)
                        continue
                    if opcode == 10:
                        continue
                    assert opcode in (0, 1) and len(fragments) + size <= 4 * 1024 * 1024
                    fragments.extend(payload)
                    if final:
                        self.messages.put(json.loads(fragments))
                        fragments.clear()
            except Exception as error:
                self.messages.put(error)
        threading.Thread(target=receive, daemon=True).start()
        self.rpc('initialize', {'clientInfo': {'name': 'synthetic-three-stage', 'version': '1'},
                               'capabilities': {'experimentalApi': True}})
        self.send_message({'method': 'initialized', 'params': {}})

    def read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.proxy.stdout.read(size - len(data))
            if not part:
                raise RuntimeError('DAEMON_CONTROL_SOCKET_CLOSED')
            data.extend(part)
        return bytes(data)

    def send_frame(self, payload, opcode=1):
        size = len(payload)
        header = bytes([128 | opcode])
        if size < 126:
            header += bytes([128 | size])
        elif size < 65536:
            header += bytes([128 | 126]) + struct.pack('!H', size)
        else:
            header += bytes([128 | 127]) + struct.pack('!Q', size)
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        with self.write_lock:
            self.proxy.stdin.write(header + mask + masked)
            self.proxy.stdin.flush()

    def send_message(self, message):
        self.send_frame(json.dumps(message).encode())

    def rpc(self, method, params):
        self.last_method = method
        self.sequence += 1
        number = self.sequence
        self.send_message({'id': number, 'method': method, 'params': params})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            reply = self.messages.get(timeout=max(.01, deadline - time.monotonic()))
            if isinstance(reply, Exception):
                raise reply
            if reply.get('id') == number:
                assert 'error' not in reply, 'PERSISTENT_DAEMON_RPC_ERROR_' + method
                return reply['result']
        raise RuntimeError('PERSISTENT_DAEMON_RPC_TIMEOUT_' + method)

    def inventory(self, label):
        assert self.daemon_identity() == self.original_daemon, 'ORIGINAL_DAEMON_REPLACED'
        plugins = self.rpc('plugin/list', {'cwds': [str(self.workspace)], 'forceRefetch': True,
                                          'marketplaceKinds': ['local']})
        hooks = self.rpc('hooks/list', {'cwds': [str(self.workspace)]})
        private_json(self.state / (label + '.plugins.json'), plugins)
        private_json(self.state / (label + '.hooks.json'), hooks)
        market = [row for row in plugins['marketplaces'] if row['name'] == 'cicada-repo']
        assert len(market) == 1
        selected = [row for row in market[0]['plugins'] if row['name'] == 'cicada']
        assert len(selected) == 1 and selected[0]['installed'] and selected[0]['enabled']
        if hasattr(self, 'original_plugin_id'):
            assert selected[0]['id'] == self.original_plugin_id, 'INSTALLED_PLUGIN_ID_CHANGED'
        else:
            self.original_plugin_id = selected[0]['id']
        rows = [row for row in hooks['data'] if row['cwd'] == str(self.workspace)]
        assert len(rows) == 1 and not rows[0]['errors']
        actual = rows[0]['hooks']
        assert len(actual) == 2 and {row['eventName'] for row in actual} == {'userPromptSubmit', 'preToolUse'}
        expected_hash = digest(self.marketplace / '.agents/plugins/cicada/hooks/hooks.json')
        for hook in actual:
            assert hook['source'] == 'plugin' and hook['pluginId'] == self.original_plugin_id and hook['enabled']
            assert digest(Path(hook['sourcePath'])) == expected_hash, 'INSTALLED_HOOK_STALE_SOURCE'
        return actual

    def literal(self, label, prompt=None, expected=None, resume=None):
        # Reuse the actual controlling-PTY/normal-trust path. Only transport
        # changes: the TUI attaches to the original managed daemon.
        prior = self.state
        self.state = self.root / ('cli-' + label)
        self.state.mkdir(mode=0o700)
        self.config['literal_prompt'] = prompt or 'cicada join "Synthetic installed-plugin Thread"'
        self.config['literal_expected'] = expected
        self.config['literal_resume_sid'] = resume
        stopped = threading.Event()
        observed = {}
        def watch_hook_environment():
            while not stopped.is_set():
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit() or proc.name in observed:
                        continue
                    try:
                        args = (proc / 'cmdline').read_bytes().split(b'\0')
                        if len(args) < 2 or args[1] != b'codex-hook':
                            continue
                        executable = (proc / 'exe').resolve()
                        if not executable.is_relative_to(Path(self.config['selected_root']) / 'components/node'):
                            continue
                        env = dict(value.split(b'=', 1) for value in (proc / 'environ').read_bytes().split(b'\0') if b'=' in value)
                        observed[proc.name] = {'HOME_matches_owned': env.get(b'HOME') == self.environment['HOME'].encode(),
                                              'CODEX_HOME_present': bool(env.get(b'CODEX_HOME')),
                                              'CODEX_HOME_matches_original': env.get(b'CODEX_HOME') == str(self.codex_home).encode()}
                    except (OSError, PermissionError):
                        continue
                stopped.wait(.005)
        watcher = threading.Thread(target=watch_hook_environment, daemon=True)
        watcher.start()
        try:
            hooks = self.inventory('before')
            sid = self.literal_tui(hooks)
            trusted = self.inventory('after')
            assert all(row['trustStatus'] in ('trusted', 'managed') for row in trusted), 'NORMAL_NEW_HOOK_TRUST_REQUIRED'
            assert self.daemon_identity() == self.original_daemon
            return sid
        finally:
            stopped.set()
            watcher.join(timeout=2)
            records = []
            for native_id, value in self.native_records().items():
                path = Path(value['path'])
                before = path.lstat()
                with path.open('rb') as stream:
                    opened = os.fstat(stream.fileno())
                meta = value['metadata']
                source = meta.get('source')
                records.append({'id': native_id, 'cwd_matches_original': meta.get('cwd') == str(self.workspace),
                                'source': source if isinstance(source, str) else {'keys': sorted(source or {})},
                                'originator': meta.get('originator'), 'forked_from_id': meta.get('forked_from_id'),
                                'path': str(path), 'under_original_CODEX_HOME': path.is_relative_to(self.codex_home),
                                'under_HOME_default_CODEX_HOME': path.is_relative_to(Path(self.environment['HOME']) / '.codex'),
                                'mode': oct(before.st_mode & 0o777), 'uid_matches_current': before.st_uid == os.getuid(),
                                'size': before.st_size, 'readable': True,
                                'open_inode_matches': (before.st_ino, before.st_dev) == (opened.st_ino, opened.st_dev)})
            private_json(self.state / 'native-record-checks.json', {'hook_transcript_path_observed': False,
                         'actual_native_record_metadata_only': records, 'actual_Hook_environment_matches_only': observed})
            self.state = prior

    def tool_status(self, sid):
        reply = self.rpc('mcpServerStatus/list', {'threadId': sid, 'limit': 100, 'detail': 'full'})
        rows = [row for row in reply['data'] if row.get('pluginId') == self.original_plugin_id]
        assert len(rows) == 1, 'ACTUAL_THREAD_MCP_SERVER_MISSING'
        row = rows[0]
        return {'tools_count': len(row['tools']), 'tools_error': row.get('toolsError'),
                'runtime_status': row.get('runtimeStatus')}


def run(config):
    cli = PersistentCLI(config)
    control = Path(config['control'])
    control.mkdir(mode=0o700)
    requests = []
    class NoModel(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"data":[]}')
        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            assert size <= 4 * 1024 * 1024
            raw = self.rfile.read(size)
            requests.append(hashlib.sha256(raw).hexdigest())
            self.send_response(503)
            self.end_headers()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), NoModel)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    reply = {'status': 'FAIL', 'real_model_turns': 0}
    daemon_started = False
    def checkpoint(step, values):
        assert not requests, 'LITERAL_COMMAND_REACHED_PROVIDER'
        assert cli.daemon_identity() == cli.original_daemon, 'ORIGINAL_DAEMON_CHANGED'
        private_json(control / (str(step) + '.reply.json'),
                     {'status': 'SCOPED_PASS', 'daemon': cli.original_daemon, 'provider_posts': 0, **values})
    def await_command(step):
        path = control / (str(step) + '.command.json')
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            if path.is_file():
                return json.loads(path.read_text())
            time.sleep(.05)
        raise RuntimeError('THREE_STAGE_PARENT_CHECKPOINT_TIMEOUT')
    try:
        configuration = cli.codex_home / 'config.toml'
        assert not configuration.exists()
        configuration.write_text('''model = "synthetic-no-model"
model_provider = "qa_static"
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic no-model failure sentinel"
base_url = "http://127.0.0.1:PORT/v1"
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('PORT', str(server.server_port)) + '\n[projects.' + json.dumps(str(cli.workspace)) + ']\ntrust_level = "trusted"\n')
        cli.command('old-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        cli.command('old-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        started = json.loads(cli.command('daemon-start-before-install', ['app-server', 'daemon', 'start']))
        cli.control_socket = started['socketPath']
        assert Path(cli.control_socket).is_relative_to(cli.codex_home), 'DAEMON_CONTROL_SOCKET_OUTSIDE_OWNED_HOME'
        cli.config['persistent_remote'] = 'unix://' + cli.control_socket
        daemon_started = True
        cli.original_daemon = cli.daemon_identity()
        # Let the actual native TUI initialize its own daemon first. A custom
        # observer must not establish the daemon's global native originator.
        cli.config['startup_only'] = True
        cli.literal_tui([])
        cli.config.pop('startup_only')
        cli.connect()
        cli.inventory('old-installed-before-file-install')
        checkpoint(0, {'old_same_plugin_installed': True, 'daemon_started_before_file_install': True})
        command = await_command(1)
        cli.command('old-marketplace-remove', ['plugin', 'marketplace', 'remove', 'cicada-repo'])
        cli.marketplace = Path(command['marketplace'])
        cli.command('installed-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        cli.command('installed-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        absent_sid = cli.literal('three-stage-node-absent', 'cicada peers', 'NODE_NOT_RUNNING')
        checkpoint(1, {'node_absent_literal_refusal': True, 'native_session_id': absent_sid})
        await_command(2)
        sid = cli.literal('three-stage-node-connected')
        status = cli.tool_status(sid)
        assert status['tools_count'] > 0 and not status['tools_error'], 'CURRENT_DAEMON_MCP_DISCOVERY_FAILED'
        checkpoint(2, {'native_session_id': sid, 'mcp_tools_count': status['tools_count'], 'actual_literal_registration': True})
        await_command(3)
        cli.literal('three-stage-node-stopped', 'cicada peers', 'NODE_NOT_RUNNING', sid)
        checkpoint(3, {'same_native_session_id': sid, 'stopped_node_literal_refusal': True})
        await_command(4)
        cli.literal('three-stage-node-restarted', 'cicada peers', 'Node Thread directory snapshot', sid)
        status = cli.tool_status(sid)
        assert status['tools_count'] > 0 and not status['tools_error']
        checkpoint(4, {'same_native_session_id': sid, 'mcp_tools_count': status['tools_count'], 'original_daemon_retained': True})
        reply.update(status='SCOPED_PASS', daemon=cli.original_daemon,
                     native_session_id=sid, provider_posts=len(requests), original_plugin_id=cli.original_plugin_id)
    except Exception as error:
        reply['failure_category'] = (type(error).__name__ + ': ' + str(error) + ' phase=' + getattr(cli, 'last_method', 'startup'))[:180]
        reply['diagnostic_traceback'] = traceback.format_exc()[-5000:]
        private_json(control / 'failure.json', reply)
    finally:
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
                cli.command('owned-daemon-stop', ['app-server', 'daemon', 'stop'])
            except Exception:
                reply['status'] = 'FAIL'
                reply['cleanup_failed'] = True
        server.shutdown()
        server.server_close()
        assert digest(Path(cli.binary)) == cli.expected_binary
        private_json(Path(config['result']), reply)
    return 0 if reply['status'] == 'SCOPED_PASS' else 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(run(json.loads(Path(sys.argv[1]).read_text())))
