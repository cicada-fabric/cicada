#!/usr/bin/env python3
"""One actual persistent daemon, installed plugin and literal Join; zero models.

The Go parent supplies its already automatically pinned Node and separately
approved local policy. Reuse existing native CLI plumbing without fabricating
a native record, endpoint, context ticket or Owner pin. No Host turn, ASK/Reply
or provider request is authorized by this driver.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from codex_domain_host import DomainHostCLI, StaticHostProvider
from codex_product_cli import digest, private_json


def run(config):
    os.umask(0o077)
    cli = DomainHostCLI(config)
    provider = StaticHostProvider(str(cli.root))
    result = {'scope': 'ACTUAL_AUTOMATIC_PIN_TO_EXISTING_NATIVE_DAEMON_PLUGIN_LITERAL_JOIN',
              'status': 'FAIL', 'real_model_turns': 0, 'provider_posts': 0,
              'manual_Owner_pin_used': False, 'cleanup_confirmed': False, 'daemon_after_stop_state': 'UNKNOWN'}
    started = False
    phase = 'SETUP'
    try:
        text = '''model = "synthetic-zero-model-node-pair-consumer"
model_provider = "qa_static"
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.qa_static]
name = "Synthetic local sentinel; no provider requests allowed"
base_url = BASE_URL
env_key = "CICADA_SYNTHETIC_API_KEY"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
'''.replace('BASE_URL', json.dumps(provider.origin))
        text += '\n[projects.' + json.dumps(str(cli.workspace)) + ']\ntrust_level = "trusted"\n'
        configuration = cli.codex_home / 'config.toml'
        assert not configuration.exists()
        configuration.write_text(text)
        phase = 'DAEMON'
        daemon = json.loads(cli.command('owned-daemon-start', ['app-server', 'daemon', 'start']))
        started = True
        cli.control_socket = daemon['socketPath']
        assert Path(cli.control_socket).is_relative_to(cli.codex_home)
        cli.config['persistent_remote'] = 'unix://' + cli.control_socket
        cli.original_daemon = cli.daemon_identity()
        cli.config['startup_only'] = True
        cli.literal_tui([])
        cli.config.pop('startup_only')
        cli.connect()
        phase = 'PLUGIN'
        cli.command('owned-marketplace-add', ['plugin', 'marketplace', 'add', str(cli.marketplace)])
        cli.command('owned-plugin-add', ['plugin', 'add', 'cicada@cicada-repo'])
        cli.inventory('installed-existing-consumer')
        phase = 'LITERAL_JOIN'
        sid, native = cli.literal_admit(provider, 'node-pair-single-native', 'SYNTHETIC automatically pinned Node consumer')
        status = cli.tool_status(sid)
        assert status['tools_count'] > 0 and not status['tools_error']
        assert cli.daemon_identity() == cli.original_daemon
        assert not provider.requests
        result.update(status='SCOPED_PASS', native_session_id=sid, workspace=str(cli.workspace),
                      native_metadata=native, daemon=cli.original_daemon, MCP=status)
    except Exception as error:
        result.update(failure_phase=phase, failure_category=type(error).__name__)
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
                cli.command('owned-daemon-stop', ['app-server', 'daemon', 'stop'])
                original = cli.original_daemon
                path = Path('/proc') / str(original['pid']) / 'stat'
                deadline = time.monotonic() + 5
                while path.exists() and time.monotonic() < deadline:
                    try:
                        process_state = path.read_text().rsplit(') ', 1)[1].split()
                        ticks = process_state[19]
                        result['daemon_after_stop_state'] = process_state[0]
                    except FileNotFoundError:
                        result['daemon_after_stop_state'] = 'GONE'
                        break
                    if ticks != original['start_ticks']:
                        result['daemon_after_stop_state'] = 'PID_REUSED'
                        break
                    # The official stop command succeeded. An exact-identity
                    # zombie has exited and only awaits its container parent's
                    # reap; live states must still disappear before the deadline.
                    if process_state[0] == 'Z':
                        break
                    time.sleep(.05)
                else:
                    if path.exists():
                        cleanup = False
                    else:
                        result['daemon_after_stop_state'] = 'GONE'
            except Exception:
                cleanup = False
        provider.close()
        result.update(provider_posts=len(provider.requests), cleanup_confirmed=cleanup)
        if provider.requests or not cleanup or digest(Path(cli.binary)) != cli.expected_binary:
            result['status'] = 'FAIL'
        private_json(Path(config['result']), result)
    return 0 if result['status'] == 'SCOPED_PASS' else 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('one owned private configuration path required')
    raise SystemExit(run(json.loads(Path(sys.argv[1]).read_text())))
