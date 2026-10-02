#!/usr/bin/env python3
"""Opt-in real Codex gate; two Docker namespaces on one physical host.

Reuse the V68 fixture's Owner binding/key consent and the native gate's exact
Thread/MCP configuration. No fake queue, synthetic session record, or SQL write
is permitted. Controlled resume proves safe-point consumption, not busy wake.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
import urllib.error
import urllib.request

RUNTIME = "sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57"
CODEX = "/home/cicada/.local/bin/codex"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

image_spec = importlib.util.spec_from_file_location("native_image_evidence", Path(__file__).with_name("native_image_evidence.py"))
image_evidence = importlib.util.module_from_spec(image_spec)
image_spec.loader.exec_module(image_evidence)

# Executed inside an owned Node container. The provider credential is never a
# docker argv/env value and never appears in captured stdout/stderr.
NATIVE_BOOTSTRAP = r'''import json,os,re,subprocess,sys
from pathlib import Path
request=json.load(sys.stdin)
text=Path('/run/secrets/provider.env').read_text()
match=re.search(r'(?m)^\s*(?:export\s+)?API_KEY=(.*?)\s*$',text)
if not match or not match.group(1).strip(): raise SystemExit(31)
os.environ['API_KEY']=match.group(1).strip().strip("\"'")
os.environ['CODEX_HOME']='/codex'
os.environ['HTTP_PROXY']=request['proxy'];os.environ['HTTPS_PROXY']=request['proxy']
os.environ['NO_PROXY']='127.0.0.1,localhost'
for name in ('CODEX_THREAD_ID','CODEX_SESSION_ID','CICADA_NATIVE_SESSION_ID','CICADA_API_TOKEN','CICADA_API_TOKEN_FILE','CICADA_NODE_TOKEN','CICADA_NODE_TOKEN_FILE'):
 os.environ.pop(name,None)
original=Path('/run/config/codex.toml')
target=Path('/codex/config.toml')
if not target.exists():
 target.write_text(original.read_text().replace('log_dir = "/var/log/cicada/codex"', 'log_dir = "/codex/logs"'));target.chmod(0o600)
os.chdir('/workspace')
result=subprocess.run(['/home/cicada/.local/bin/codex',*request['argv']],capture_output=True)
if len(result.stdout)>8<<20 or len(result.stderr)>8<<20: raise SystemExit(33)
key=os.environ['API_KEY'].encode()
sys.stdout.buffer.write(result.stdout.replace(key,b'[REDACTED_API_KEY]'))
sys.stderr.buffer.write(result.stderr.replace(key,b'[REDACTED_API_KEY]'))
raise SystemExit(result.returncode)
'''

AGENT_BOOTSTRAP = r'''import os,re,sys
from pathlib import Path
match=re.search(r'(?m)^\s*(?:export\s+)?API_KEY=(.*?)\s*$',Path('/run/secrets/provider.env').read_text())
if not match or not match.group(1).strip(): raise SystemExit(31)
os.environ['API_KEY']=match.group(1).strip().strip("\"'")
os.execvp('/bin/sh',['/bin/sh',*sys.argv[1:]])
'''

FORWARDER = r'''import socket,sys,threading
target,port,listen_port=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
def pipe(a,b):
 try:
  while True:
   chunk=a.recv(65536)
   if not chunk: break
   b.sendall(chunk)
 except OSError: pass
 try: b.shutdown(socket.SHUT_WR)
 except OSError: pass
def handle(a):
 try: b=socket.create_connection((target,port),timeout=5)
 except OSError: a.close();return
 threading.Thread(target=pipe,args=(a,b),daemon=True).start();pipe(b,a);a.close();b.close()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',listen_port));s.listen()
while True:
 a,_=s.accept();threading.Thread(target=handle,args=(a,),daemon=True).start()
'''


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def parse_events(data):
    events = []
    for line in data.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def turn_witness(events, expected_thread=None, required_tools=(), markers=()):
    threads = [e.get("thread_id") for e in events if e.get("type") == "thread.started"]
    if len(threads) != 1 or not UUID.fullmatch(threads[0] or ""):
        raise RuntimeError("native_thread_event_invalid")
    if expected_thread and threads[0] != expected_thread:
        raise RuntimeError("native_thread_changed")
    completed = []
    agent_text = []
    for event in events:
        item = event.get("item") or {}
        if item.get("type") == "mcp_tool_call" and event.get("type") == "item.completed" and item.get("status") == "completed":
            completed.append(item.get("tool") or item.get("name"))
        if item.get("type") == "agent_message":
            agent_text.append(item.get("text", ""))
    if any(tool not in completed for tool in required_tools):
        raise RuntimeError("required_native_tool_not_completed")
    if any(marker not in "\n".join(agent_text) for marker in markers):
        raise RuntimeError("original_context_witness_missing")
    return {"thread_id": threads[0], "completed_tools": completed,
            "same_original_thread": expected_thread is None or threads[0] == expected_thread,
            "context_witnesses": [True for _ in markers]}


class Gate:
    def __init__(self, arguments):
        self.args = arguments
        self.repo = Path(__file__).resolve().parent.parent
        self.evidence = Path(arguments.result_dir).resolve()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root = Path(tempfile.mkdtemp(prefix="cicada-native-two-"))
        self.root.chmod(0o700)
        self.run_id = "cicada-native-two-" + uuid.uuid4().hex[:16]
        self.containers = {}
        self.networks = []
        self.images = {}
        self.forwarders = []
        self.node_letters = "ab"
        self.phase = "preflight"
        self.result = {"schema": "cicada.two-node-native.v1", "status": "FAIL",
                       "run_id": self.run_id, "steps": [], "model": "gpt-5.6-luna",
                       "limits": ["one physical host, two isolated Docker Node namespaces",
                                  "owned loopback HTTP Hub forwarding; public HTTPS NOT_RUN",
                                  "controlled native resume; busy autowake NOT_RUN",
                                  "Android and physical dual-Node NOT_RUN"],
                       "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "image_evidence_helper_sha256": hashlib.sha256(Path(image_evidence.__file__).read_bytes()).hexdigest(),
                       "acceptance_mode": "exact-clean-image-pair" if getattr(arguments, "exact_clean_image_metadata", None) else "rebuilt-two-node-fixture",
                       "native_model_turn_attempts": 0, "models_invoked": 0, "native_turn_budget": 7}
        with os.fdopen(os.open(self.evidence / "executed-driver.py", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(Path(__file__).read_bytes())

    def command(self, command, input_data=None, timeout=120, log=None):
        start = time.monotonic()
        try:
            process = subprocess.run(command, input=input_data, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.result["steps"].append({"phase": self.phase, "exit_code": None, "timed_out": True,
                                         "timeout_seconds": timeout, "argv": list(map(str, command))})
            raise RuntimeError("command_timeout_terminal_no_retry") from None
        if log:
            with os.fdopen(os.open(self.evidence / log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                output.write(process.stdout)
                output.write(process.stderr)
        self.result["steps"].append({"phase": self.phase, "exit_code": process.returncode,
                                      "elapsed_seconds": round(time.monotonic() - start, 3), "argv": list(map(str, command))})
        if process.returncode:
            raise RuntimeError("command_exit_" + str(process.returncode))
        return process.stdout

    def docker(self, *arguments, **kwargs):
        return self.command(["docker", *map(str, arguments)], **kwargs)

    def inspect(self, kind, name):
        return json.loads(self.docker(kind, "inspect", name))[0]

    def step(self, name):
        self.phase = name
        print(json.dumps({"phase": name, "run_id": self.run_id}), flush=True)

    def build(self):
        if getattr(self.args, "exact_clean_image_metadata", None):
            self.build_exact_pair()
            return
        self.step("build_same_source")
        build = self.root / "build.json"
        hub_tag, test_tag = self.run_id + ":hub", self.run_id + ":test"
        self.command([str(self.repo / "scripts/build-hub-image.sh"), "--image", hub_tag,
                      "--interop-test-image", test_tag, "--metadata-file", str(build)], timeout=900,
                     log="build.log")
        metadata = json.loads(build.read_text())
        self.result["build"] = metadata
        self.hub_image, self.test_image = metadata["image"]["id"], metadata["test_image"]["id"]
        self.images = {hub_tag: self.hub_image, test_tag: self.test_image}
        self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                    "-v", str(self.root) + ":/fixture", "-w", "/src", "-e", "GOTOOLCHAIN=local",
                    "-e", "GOPROXY=off", "-e", "GOCACHE=/tmp/native-go-cache", "--entrypoint", "go",
                    self.test_image, "build", "-trimpath", "-o", "/fixture/cicada-v68fixture",
                    "./cmd/cicada-v68fixture", timeout=180, log="helper-build.log")
        self.root.joinpath("cicada-v68fixture").chmod(0o700)
        extract = self.run_id + "-extract"
        self.docker("create", "--name", extract, "--label", "org.cicada.test.run=" + self.run_id,
                    self.test_image)
        self.containers[extract] = self.test_image
        self.docker("cp", extract + ":/out/cicada", self.root / "cicada")
        self.root.joinpath("cicada").chmod(0o700)
        self.result["cicada_binary_sha256"] = hashlib.sha256(self.root.joinpath("cicada").read_bytes()).hexdigest()

    def build_exact_pair(self):
        self.step("verify_exact_delivered_standard_pair")
        metadata = image_evidence.read_clean_producer(self.args.exact_clean_image_metadata,
                                                     self.args.exact_clean_image_metadata_sha256)
        snapshot = self.root / "fixture-source.json"
        self.command([str(self.repo / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(snapshot)])
        current = json.loads(snapshot.read_text())["source"]
        hub_id, interop_id = image_evidence.check_clean_pair(metadata, current)
        image_evidence.check_clean_image(metadata, self.inspect("image", hub_id))
        image_evidence.check_clean_image(metadata, self.inspect("image", interop_id), "interop")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.args.runtime_image):
            raise RuntimeError("immutable_runtime_image_required")
        runtime_id = self.inspect("image", self.args.runtime_image)["Id"]
        if runtime_id != self.args.runtime_image:
            raise RuntimeError("immutable_runtime_image_mismatch")
        self.hub_image, self.test_image = hub_id, interop_id
        self.result.update(build=metadata, fixture_source_snapshot=current,
                           producer_metadata_sha256=self.args.exact_clean_image_metadata_sha256,
                           hub_image_id=hub_id, interop_image_id=interop_id, runtime_image_id=runtime_id)
        binary_sha, provenance = image_evidence.extract_image_binary(self, hub_id)
        self.result.update(cicada_binary_sha256=binary_sha, binary_provenance=provenance)
        version = self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                              "--label", "org.cicada.test.run=" + self.run_id,
                              "--entrypoint", "go", interop_id, "version").decode().strip()
        if version != "go version go1.27.1 linux/amd64":
            raise RuntimeError("actual_interop_go_toolchain_not_pinned")
        self.result["fixture_go_version"] = version
        self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                    "--label", "org.cicada.test.run=" + self.run_id,
                    "-v", str(self.root) + ":/fixture", "-w", "/src", "-e", "GOTOOLCHAIN=local",
                    "-e", "GOPROXY=off", "-e", "GOSUMDB=off", "-e", "GOMAXPROCS=4", "-e", "CGO_ENABLED=0",
                    "-e", "GOCACHE=/tmp/native-go-cache", "--entrypoint", "go", interop_id,
                    "build", "-trimpath", "-o", "/fixture/cicada-v68fixture", "./cmd/cicada-v68fixture",
                    timeout=300, log="fixture-build.log")
        fixture = self.root / "cicada-v68fixture"
        fixture.chmod(0o700)
        self.result["fixture_binary_sha256"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        self.result["fixture_provenance"] = {"synthetic_owner_only": True, "compiled_inside_immutable_interop": interop_id,
                                             "source_fingerprint": current["source_fingerprint"], "fixture_only": True}
        if self.args.run_native:
            data = Path(self.args.preparation_result).read_bytes()
            image_evidence.check_preparation(json.loads(data), self.result)
            self.result["preparation_result_sha256"] = hashlib.sha256(data).hexdigest()

    def start_nodes(self):
        self.step("isolated_nodes")
        self.nodes = {}
        for letter in self.node_letters:
            paths = {}
            for name in ("codex", "workspace", "state", "mcp"):
                paths[name] = self.root / ("node-" + letter + "-" + name)
                paths[name].mkdir(mode=0o700)
            network = self.run_id + "-" + letter + "-net"
            self.docker("network", "create", "--label", "org.cicada.test.run=" + self.run_id, network)
            self.networks.append(network)
            gateway = self.inspect("network", network)["IPAM"]["Config"][0]["Gateway"]
            name = self.run_id + "-" + letter
            secret_mount = []
            if self.args.run_native:
                info = Path(self.args.credential_file).lstat()
                if stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("provider_file_not_private")
                secret_mount = ["--mount", "type=bind,src=" + str(Path(self.args.credential_file).resolve()) + ",dst=/run/secrets/provider.env,readonly"]
            self.docker("run", "-d", "--name", name, "--network", network,
                        "--label", "org.cicada.test.run=" + self.run_id,
                        "--user", f"{os.getuid()}:{os.getgid()}",
                        "-v", str(paths["codex"]) + ":/codex", "-v", str(paths["workspace"]) + ":/workspace",
                        "-v", str(paths["state"]) + ":/state", "-v", str(paths["mcp"]) + ":/mcp",
                        "-v", str(self.root / "cicada") + ":/out/cicada:ro",
                        "-v", str(self.repo / "docker/codex-config.toml") + ":/run/config/codex.toml:ro",
                        *secret_mount, "--entrypoint", "/bin/sh", self.args.runtime_image, "-c", "while :; do sleep 3600; done")
            self.containers[name] = self.args.runtime_image
            self.nodes[letter] = {"container": name, "paths": paths, "network": network, "gateway": gateway}
            version = self.docker("exec", name, CODEX, "--version").decode().strip()
            if version != "codex-cli 0.159.3":
                raise RuntimeError("runtime_version_not_pinned")
            self.result.setdefault("runtime_versions", {})[letter] = version

    def provider_forwarder(self, node):
        # Bind only this owned bridge gateway; no resident proxy reconfiguration.
        listener = socket.socket()
        listener.bind((node["gateway"], 0))
        listener.listen()
        listener.settimeout(.5)
        self.forwarders.append(listener)
        def pipe(source, target):
            try:
                while True:
                    chunk = source.recv(65536)
                    if not chunk:
                        break
                    target.sendall(chunk)
            except OSError:
                pass
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        def connect(client):
            try:
                upstream = socket.create_connection(("127.0.0.1", 7890), timeout=5)
                upstream.settimeout(None)
                threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
                pipe(upstream, client)
                upstream.close()
            except OSError:
                pass
            client.close()
        def accept():
            while listener.fileno() >= 0:
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=connect, args=(client,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        node["proxy"] = f"http://{node['gateway']}:{listener.getsockname()[1]}"

    def native_config(self, letter, thread=None, tools=()):
        node = self.nodes[letter]
        config = []  # A seed turn has no MCP server table or incomplete transport.
        if thread:
            environment = {"CICADA_API_URL": "http://127.0.0.1:8787", "CICADA_NODE_STATE_DIR": "/state",
                           "CICADA_MCP_STATE_DIR": "/mcp", "CICADA_MACHINE_ID": node["node_id"],
                           "CICADA_HARNESS": "codex", "CICADA_GROUP_ID": self.meta["group_id"],
                           "CICADA_API_TOKEN": "", "CICADA_API_TOKEN_FILE": "",
                           "CODEX_HOME": "/codex", "CODEX_THREAD_ID": thread}
            env_table = "{" + ",".join(key + "=" + json.dumps(value) for key, value in environment.items()) + "}"
            config = ["-c", 'mcp_servers.cicada.enabled=true', "-c", 'mcp_servers.cicada.command="/out/cicada"',
                      "-c", 'mcp_servers.cicada.args=["mcp","--api-url","http://127.0.0.1:8787"]',
                      "-c", "mcp_servers.cicada.env=" + env_table]
            config += ["-c", 'mcp_servers.cicada.omit_tools_from=["deferred"]',
                       "-c", "mcp_servers.cicada.enabled_tools=" + json.dumps(list(tools)),
                       "-c", "mcp_servers.cicada.required=true"]
        return config

    def protocol_tools_preflight(self, letter, thread, tools):
        node = self.nodes[letter]
        environment = {"CICADA_API_URL": "http://127.0.0.1:8787", "CICADA_NODE_STATE_DIR": "/state",
                       "CICADA_MCP_STATE_DIR": "/mcp", "CICADA_MACHINE_ID": node.get("node_id", ""),
                       "CICADA_HARNESS": "codex", "CICADA_GROUP_ID": getattr(self, "meta", {}).get("group_id", ""),
                       "CICADA_API_TOKEN": "", "CICADA_API_TOKEN_FILE": "",
                       "CODEX_HOME": "/codex", "CODEX_THREAD_ID": thread or ""}
        argv = ["exec", "-i", "--workdir", "/workspace"]
        for key, value in environment.items():
            argv += ["-e", key + "=" + value]
        argv += [node["container"], "/out/cicada", "mcp", "--api-url", "http://127.0.0.1:8787"]
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "native-gate-preflight", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
        raw = self.docker(*argv, input_data=("\n".join(map(json.dumps, messages)) + "\n").encode(),
                          log=f"mcp-protocol-{self.phase}-{letter}.json.private")
        events = parse_events(raw)
        responses = [event for event in events if event.get("id") == 2]
        names = [item.get("name") for event in responses for item in event.get("result", {}).get("tools", [])]
        if not any(event.get("id") == 1 and "result" in event for event in events) or len(responses) != 1 or any(tool not in names for tool in tools):
            raise RuntimeError("actual_mcp_required_tools_not_listed_no_model")
        self.result.setdefault("actual_mcp_preflight", []).append({"phase": self.phase, "node": letter,
            "needed_tools": list(tools), "all_listed": True, "model_calls": 0, "original_thread_id": thread})

    def parse_config_offline(self, letter, config):
        node = self.nodes[letter]
        target = node["paths"]["codex"] / "config.toml"
        if not target.exists():
            text = (self.repo / "docker/codex-config.toml").read_text().replace("/var/log/cicada/codex", "/codex/logs")
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                output.write(text)
        self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                    "-v", str(node["paths"]["codex"]) + ":/codex:ro", "-e", "CODEX_HOME=/codex",
                    "--entrypoint", CODEX, self.args.runtime_image, "mcp", "list", "--json", *config,
                    log=f"offline-config-{self.phase}-{letter}.json.private")
        self.result.setdefault("offline_config_checks", []).append({"node": letter, "phase": self.phase,
            "exit_code": 0, "network": "none", "credential_mounted": False, "model_calls": 0,
            "config_argv_sha256": hashlib.sha256(json.dumps(config).encode()).hexdigest()})

    def native_turn(self, letter, prompt, thread=None, tools=(), markers=()):
        # This driver's seven turns are distinct from the Monitor subclass's own three-turn budget.
        if self.result.get("schema") == "cicada.two-node-native.v1":
            if self.result["native_model_turn_attempts"] >= 7:
                raise RuntimeError("native_seven_turn_budget_exceeded")
            self.result["native_model_turn_attempts"] += 1
            self.result["models_invoked"] = self.result["native_model_turn_attempts"]
        node = self.nodes[letter]
        config = self.native_config(letter, thread, tools)
        self.parse_config_offline(letter, config)
        if thread:
            self.protocol_tools_preflight(letter, thread, tools)
        argv = ["exec", "--json", "--skip-git-repo-check", "--approve-for-me", "-C", "/workspace", "--model", "gpt-5.6-luna"]
        if thread:
            argv += ["resume", "-c", 'approval_policy="on-request"', "-c", 'approvals_reviewer="auto_review"', *config, thread, prompt]
        else:
            argv += [*config, prompt]
        output = self.docker("exec", "-i", "--workdir", "/workspace", node["container"], "python3", "-c", NATIVE_BOOTSTRAP,
                             input_data=json.dumps({"argv": argv, "proxy": node["proxy"]}).encode(), timeout=240,
                             log=f"native-{self.phase}-{letter}.jsonl.private")
        witness = turn_witness(parse_events(output), thread, tools, markers)
        records = list(node["paths"]["codex"].joinpath("sessions").rglob("*.jsonl"))
        matching = []
        for record in records:
            with record.open() as source:
                event = json.loads(source.readline())
            payload = event.get("payload", {})
            if event.get("type") == "session_meta" and payload.get("id") == witness["thread_id"] and payload.get("cwd") == "/workspace":
                matching.append(record)
        if len(matching) != 1:
            raise RuntimeError("local_native_record_not_exact")
        witness["local_session_record_exact"] = True
        self.result.setdefault("native_turns", []).append({"phase": self.phase, "node": letter, **witness})
        return witness["thread_id"]

    def current_actor(self, letter):
        node = self.nodes[letter]
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cicada_whoami", "arguments": {}}}]
        environment = {"CODEX_HOME": "/codex", "CODEX_THREAD_ID": node["thread"], "CICADA_HARNESS": "codex",
                       "CICADA_MACHINE_ID": node["node_id"], "CICADA_NODE_STATE_DIR": "/state", "CICADA_MCP_STATE_DIR": "/mcp",
                       "CICADA_HUB_ID": self.meta["hub_id"], "CICADA_GROUP_ID": self.meta["group_id"],
                       "CICADA_API_TOKEN": "", "CICADA_API_TOKEN_FILE": ""}
        command = ["exec", "-i", "--workdir", "/workspace"]
        for key, value in environment.items():
            command += ["-e", key + "=" + value]
        command += [node["container"], "/out/cicada", "mcp", "--api-url", "http://127.0.0.1:8787"]
        output = self.docker(*command, input_data=("\n".join(json.dumps(message) for message in messages) + "\n").encode())
        responses = [event for event in parse_events(output) if event.get("id") == 2]
        if len(responses) != 1 or "error" in responses[0]:
            raise RuntimeError("current_native_actor_rpc_failed")
        result = responses[0].get("result", {})
        if result.get("isError"):
            raise RuntimeError("current_native_actor_denied")
        actor = result.get("structuredContent")
        if not actor:
            for block in result.get("content", []):
                if block.get("type") == "text":
                    try:
                        actor = json.loads(block["text"])
                    except ValueError:
                        pass
        if not isinstance(actor, dict) or actor.get("group_id") != self.meta["group_id"] or not actor.get("endpoint_id") or not actor.get("binding_epoch"):
            raise RuntimeError("current_native_actor_scope_mismatch")
        return {key: actor.get(key) for key in ("endpoint_id", "principal_id", "network_id", "group_id", "membership_id", "membership_revision", "binding_id", "binding_epoch")}

    def helper(self, action, *arguments):
        return self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                           "-v", str(self.root) + ":/fixture", "--entrypoint", "/fixture/cicada-v68fixture",
                           self.test_image, action, "--db", "/fixture/hub-state/cicada.sqlite3", "--fixture", "/fixture",
                           *arguments)

    def hub_rows(self, query, parameters=()):
        path = self.root / "hub-state/cicada.sqlite3"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(query, parameters)]

    def start_hub(self, create=False):
        if create:
            environment = self.root / "hub.env"
            with os.fdopen(os.open(environment, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                output.write("CICADA_API_TOKEN=" + secrets.token_hex(32) + "\n")
            name = self.run_id + "-hub"
            self.hub = name
            self.docker("run", "-d", "--name", name, "--label", "org.cicada.test.run=" + self.run_id,
                        "--user", f"{os.getuid()}:{os.getgid()}", "--network", "bridge",
                        "-p", self.nodes["a"]["gateway"] + "::8787", "-p", self.nodes["b"]["gateway"] + "::8787",
                        "--env-file", environment, "-e", "CICADA_STATE_DIR=/state",
                        "-v", str(self.root / "hub-state") + ":/state",
                        "-v", str(self.root / "cicada-v68fixture") + ":/fixture-helper:ro", self.hub_image,
                        "serve", "--host", "0.0.0.0", "--port", "8787", "--fabric-only")
            self.containers[name] = self.hub_image
        else:
            self.docker("start", self.hub)
        record = self.inspect("container", self.hub)
        bindings = record["NetworkSettings"]["Ports"]["8787/tcp"]
        token = self.root.joinpath("hub.env").read_text().strip().split("=", 1)[1]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for node in self.nodes.values():
            ports = [item["HostPort"] for item in bindings if item["HostIp"] == node["gateway"]]
            if len(ports) != 1:
                raise RuntimeError("hub_gateway_port_ambiguous")
            node["hub_port"] = ports[0]
            ready = False
            for _ in range(60):
                request = urllib.request.Request(f"http://{node['gateway']}:{ports[0]}/v1/machines",
                                                 headers={"Authorization": "Bearer " + token})
                try:
                    with opener.open(request, timeout=1) as response:
                        status = response.status
                except urllib.error.HTTPError as error:
                    status = error.code
                    error.close()
                except OSError:
                    status = 0
                if status == 503:
                    ready = True
                    break
                time.sleep(.25)
            if not ready:
                raise RuntimeError("fabric_only_control_probe_failed")
            if self.result["acceptance_mode"] == "exact-clean-image-pair":
                with opener.open(f"http://{node['gateway']}:{ports[0]}/healthz", timeout=2) as response:
                    image_evidence.check_hub_provenance(json.load(response), self.result)
        self.result["control_business"] = {"enabled": False, "authenticated_management_http_status": 503,
                                            "peer_business_calls": 0, "evidence": "production --fabric-only entry point"}

    def start_services(self, letter):
        node = self.nodes[letter]
        self.docker("exec", "-d", node["container"], "python3", "-c", FORWARDER,
                    node["gateway"], node["hub_port"], "8787")
        self.docker("exec", "-d", "-e", "CICADA_CODEX_BIN=" + CODEX, "-e", "CODEX_HOME=/codex",
                    "-e", "CICADA_HUB_ID=" + self.meta["hub_id"], node["container"], "python3", "-c", AGENT_BOOTSTRAP, "-c",
                    '/out/cicada machine agent --id "$1" --control-url http://127.0.0.1:8787 --state-dir /state --interval 1s --relay-only >>/state/agent.log 2>&1; printf "%s\\n" "$?" >/state/agent.exit',
                    "sh", node["node_id"])
        for _ in range(80):
            result = subprocess.run(["docker", "exec", node["container"], "test", "-S",
                                     "/state/nodes/node-" + node["node_id"] + "/join.sock"], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError("node_local_bridge_not_ready")
        probe = r'''import json,sys,urllib.request
from pathlib import Path
node=sys.argv[1];token=Path('/state/nodes/node-'+node+'/relay.token').read_text().strip()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
request=urllib.request.Request('http://127.0.0.1:8787/v2/relay/nodes/'+node+'/events',headers={'Authorization':'CicadaNode '+token,'Accept':'text/event-stream'})
with opener.open(request,timeout=4) as response:
 result={'status':response.status,'event_stream':response.headers.get('Content-Type','').startswith('text/event-stream'),'ready':response.readline(128).startswith(b'event: ready')}
print(json.dumps(result))
'''
        result = json.loads(self.docker("exec", node["container"], "python3", "-c", probe, node["node_id"]))
        if result != {"status": 200, "event_stream": True, "ready": True}:
            raise RuntimeError("node_outbound_events_not_verified")
        self.result.setdefault("outbound_sse", {})[letter] = result

    def binding_witness(self, letter):
        node = self.nodes[letter]
        rows = self.hub_rows("SELECT id,endpoint_id,native_session_id,node_id,epoch,status FROM session_bindings WHERE native_session_id=?",
                             (node["thread"],))
        if len(rows) != 1 or rows[0]["node_id"] != node["node_id"] or rows[0]["epoch"] <= 0:
            raise RuntimeError("current_native_binding_not_exact")
        row = rows[0]
        node["endpoint"] = row["endpoint_id"]
        return row

    def network_witness(self):
        listener = "import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',19437));s.listen();\nwhile True:\n c,_=s.accept();c.close()"
        probe = "import socket,sys;\ntry:\n s=socket.create_connection((sys.argv[1],19437),timeout=1.5);s.close();print('REACHABLE')\nexcept OSError:\n print('DENIED')"
        ips = {}
        for letter, node in self.nodes.items():
            record = self.inspect("container", node["container"])
            if list(record["NetworkSettings"]["Networks"]) != [node["network"]] or record["HostConfig"]["PortBindings"]:
                raise RuntimeError("node_network_or_ports_not_isolated")
            ips[letter] = record["NetworkSettings"]["Networks"][node["network"]]["IPAddress"]
            self.docker("exec", "-d", node["container"], "python3", "-c", listener)
            for _ in range(30):
                result = self.docker("exec", node["container"], "python3", "-c", probe, "127.0.0.1").decode().strip()
                if result == "REACHABLE":
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("isolation_probe_listener_missing")
        for source, target in (("a", "b"), ("b", "a")):
            result = self.docker("exec", self.nodes[source]["container"], "python3", "-c", probe, ips[target]).decode().strip()
            if result != "DENIED":
                raise RuntimeError("node_peer_direct_path_reachable")
        for letter in "ab":
            result = json.loads(self.docker("exec", self.hub, "/fixture-helper", "probe", "--address", ips[letter] + ":19437"))
            if result != {"tcp_reachable": False}:
                raise RuntimeError("hub_inbound_node_path_reachable")
        self.result["network_isolation"] = {"node_a_to_node_b": "DENIED", "node_b_to_node_a": "DENIED",
                                           "hub_to_each_node": "DENIED", "node_ports_published": False,
                                           "separate_network_namespaces": True}

    def wait_queue(self, letter, message, expected_body):
        node = self.nodes[letter]
        path = node["paths"]["state"] / "nodes" / ("node-" + node["node_id"]) / "inbox.sqlite"
        for _ in range(120):
            try:
                with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1) as connection:
                    row = connection.execute("SELECT session_id,endpoint_id,state,payload FROM node_inbox_deliveries WHERE message_id=?", (message,)).fetchone()
                if row:
                    if row[0] != node["thread"] or row[1] != node["endpoint"]:
                        raise RuntimeError("durable_inbox_wrong_native_target")
                    if row[2] == "CONSUMPTION_UNCONFIRMED":
                        payload = row[3].encode() if isinstance(row[3], str) else bytes(row[3] or b"")
                        if expected_body.encode() not in payload:
                            raise RuntimeError("opened_native_inbox_body_mismatch")
                        self.result.setdefault("durable_queue", []).append({"node": letter, "message_id": message,
                            "state": row[2], "exact_original_thread": True, "expected_opened_body": True})
                        return
                    if row[2] in ("FAILED", "INJECTION_UNCERTAIN"):
                        raise RuntimeError("native_queue_" + row[2].lower())
            except sqlite3.Error:
                pass
            time.sleep(.5)
        raise RuntimeError("native_queue_acceptance_timeout")

    def native_flow(self):
        self.step("zero_model_actual_mcp_startup")
        for letter in "ab":
            self.protocol_tools_preflight(letter, None, ("cicada_join", "cicada_find", "cicada_ask", "cicada_receive", "cicada_reply"))
        for letter in "ab":
            self.provider_forwarder(self.nodes[letter])
        nonce = secrets.token_hex(8)
        alpha = "CICADA-ORIGINAL-A-" + secrets.token_hex(16)
        beta = "CICADA-ORIGINAL-B-" + secrets.token_hex(16)
        question = "CICADA-V68-PLAINTEXT-NEVER-IN-RELAY:" + nonce + " reply with your original remembered response phrase"
        answer = "CICADA-V68-REPLY-ONLY-OPAQUE:" + beta
        self.step("create_original_threads")
        self.nodes["a"]["thread"] = self.native_turn("a", f"Remember {alpha} as your original context witness. Do not use tools. Finish with this marker and READY.", markers=(alpha,))
        self.nodes["b"]["thread"] = self.native_turn("b", f"Remember {beta}. Your exact response phrase for a later peer question is {answer}. Do not use tools. Finish with your witness and READY.", markers=(beta,))
        if self.nodes["a"]["thread"] == self.nodes["b"]["thread"]:
            raise RuntimeError("native_threads_not_distinct")
        self.step("legitimate_synthetic_owner_fixture")
        self.root.joinpath("hub-state").mkdir(mode=0o700)
        self.root.joinpath(".cicada-v68-owned").write_text("cicada.v68.disposable.v1\n" + self.run_id + "\n")
        self.root.joinpath(".cicada-v68-owned").chmod(0o600)
        self.helper("bootstrap", "--native-thread-a", self.nodes["a"]["thread"], "--native-thread-b", self.nodes["b"]["thread"])
        self.meta = json.loads(self.root.joinpath("fixture.json").read_text())
        for letter in "ab":
            self.nodes[letter]["node_id"] = self.meta["node_" + letter]
        self.start_hub(create=True)
        for letter in "ab":
            self.start_services(letter)
        self.step("explicit_original_thread_join")
        for letter in "ab":
            node = self.nodes[letter]
            self.native_turn(letter, "At this safe point call cicada_join exactly once with {}. The trusted MCP configuration fixes the Group. Finish with READY. Do not call other tools.", node["thread"], ("cicada_join",))
            node["binding_before"] = self.binding_witness(letter)
        self.result["bindings_before"] = {letter: node["binding_before"] for letter, node in self.nodes.items()}
        self.step("owner_exact_endpoint_key_consent")
        self.docker("stop", self.nodes["a"]["container"], self.nodes["b"]["container"], self.hub)
        self.helper("approve")
        self.start_hub()
        for letter in "ab":
            self.docker("start", self.nodes[letter]["container"])
            self.start_services(letter)
        self.step("actual_namespace_isolation")
        self.network_witness()
        self.step("offline_sealed_native_ask")
        self.docker("stop", self.nodes["b"]["container"])
        self.native_turn("a", f"Call cicada_find with query {json.dumps(self.nodes['b']['endpoint'])}. Then call cicada_ask exactly once targeting this exact Endpoint with question {json.dumps(question)}. Finish with ACCEPTED. Do not retry an attempted tool call.",
                         self.nodes["a"]["thread"], ("cicada_find", "cicada_ask"))
        requests = self.hub_rows("SELECT * FROM relay_v2_requests")
        if len(requests) != 1:
            raise RuntimeError("sealed_request_not_unique")
        request = requests[0]
        if request["sender_endpoint_id"] != self.nodes["a"]["endpoint"] or request["receiver_endpoint_id"] != self.nodes["b"]["endpoint"]:
            raise RuntimeError("sealed_request_route_not_exact")
        self.result["request_ids"] = {key: request[key] for key in ("request_id", "message_id")}
        self.step("outbound_reconnect_real_native_queue")
        self.docker("start", self.nodes["b"]["container"])
        self.start_services("b")
        self.wait_queue("b", request["message_id"], question)
        self.step("original_b_receive_reply_context")
        self.native_turn("b", "At this controlled safe point call cicada_receive. Locate the pending peer question and reply exactly once with your response phrase remembered from your original context, using its exact request_id. Finish by stating your original context witness. Do not create a new Thread.",
                         self.nodes["b"]["thread"], ("cicada_receive", "cicada_reply"), (beta,))
        final = self.hub_rows("SELECT * FROM relay_v2_requests WHERE request_id=?", (request["request_id"],))[0]
        if final["state"] != "REPLIED" or not final["reply_message_id"]:
            raise RuntimeError("sealed_reply_not_terminal")
        self.wait_queue("a", final["reply_message_id"], answer)
        self.step("original_a_receive_context")
        self.native_turn("a", "At this controlled safe point call cicada_receive. Report the exact received peer response and your original context witness. Do not create a new Thread or send another message.",
                         self.nodes["a"]["thread"], ("cicada_receive",), (alpha, beta))
        self.result["bindings_after"] = {letter: self.binding_witness(letter) for letter in "ab"}
        if self.result["bindings_before"] != self.result["bindings_after"]:
            raise RuntimeError("original_binding_changed")
        self.step("hub_blind_terminal_oracle")
        self.docker("stop", self.nodes["a"]["container"], self.nodes["b"]["container"], self.hub)
        for name, text in (("expected-question.txt", question), ("expected-answer.txt", answer)):
            path = self.root / name
            path.write_text(text)
            path.chmod(0o600)
        self.helper("check", "--message-id", request["message_id"], "--request-id", request["request_id"],
                    "--plaintext-file", "/fixture/expected-question.txt", "--reply-plaintext-file", "/fixture/expected-answer.txt")
        for path in self.root.joinpath("hub-state").glob("cicada.sqlite3*"):
            if any(marker.encode() in path.read_bytes() for marker in (question, answer, alpha, beta)):
                raise RuntimeError("hub_persisted_peer_plaintext")
        logs = self.docker("logs", self.hub)
        if any(marker.encode() in logs for marker in (question, answer, alpha, beta)):
            raise RuntimeError("hub_logged_peer_plaintext")
        self.result["hub_blind"] = {"sealed_ask_reply_oracle": True, "database_wal_log_markers_absent": True,
                                    "node_keys_or_provider_credentials_mounted_to_hub": False}
        if len(self.result.get("native_turns", [])) != 7 or self.result["native_model_turn_attempts"] != 7:
            raise RuntimeError("native_seven_actual_turn_receipts_required")
        self.result["status"] = "PASS"

    def cleanup(self):
        if self.result.get("acceptance_mode") == "exact-clean-image-pair" and self.result.get("build"):
            try:
                path = self.evidence / "source-after.json"
                self.command([str(self.repo / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(path)],
                             log="source-after-capture.log")
                after = json.loads(path.read_text())["source"]
                self.result["source_unchanged_during_gate"] = after == self.result["fixture_source_snapshot"]
                if not self.result["source_unchanged_during_gate"]:
                    raise RuntimeError("source_changed_during_exact_pair_gate")
            except Exception as error:
                self.result.update(status="FAIL", failure_phase="source_after_gate", failure_class=type(error).__name__)

        clean = True
        for listener in self.forwarders:
            listener.close()
        for name, image in self.containers.items():
            try:
                record = json.loads(subprocess.check_output(["docker", "inspect", name], stderr=subprocess.DEVNULL))[0]
                if record["Config"]["Labels"].get("org.cicada.test.run") != self.run_id or record["Image"] != image:
                    clean = False
                    continue
                clean = subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL).returncode == 0 and clean
            except subprocess.CalledProcessError:
                pass
        for network in self.networks:
            record = json.loads(subprocess.check_output(["docker", "network", "inspect", network]))[0]
            if record["Labels"].get("org.cicada.test.run") != self.run_id:
                clean = False
                continue
            clean = subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL).returncode == 0 and clean
        for tag, image in self.images.items():
            actual = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], capture_output=True, text=True)
            if actual.returncode == 0 and actual.stdout.strip() == image:
                clean = subprocess.run(["docker", "image", "rm", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0 and clean
        shutil.rmtree(self.root)
        self.result["cleanup_owned_resources"] = clean
        if not clean:
            self.result["status"] = "FAIL"
        self.result["terminal_exit_code"] = 0 if self.result["status"] != "FAIL" else 1
        private_json(self.evidence / "result.json", self.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", required=True)
    parser.add_argument("--runtime-image", default=RUNTIME)
    parser.add_argument("--credential-file", default="/gpu1-share/data/cicada/secrets/cicada.env")
    parser.add_argument("--exact-clean-image-metadata", help="delivered standard Hub+interop producer receipt")
    parser.add_argument("--exact-clean-image-metadata-sha256", help="independently supplied complete producer JSON SHA-256")
    parser.add_argument("--preparation-result", help="matching successful zero-model exact-pair preparation receipt")
    parser.add_argument("--run-native", action="store_true", help="explicitly permit bounded real model turns")
    arguments = parser.parse_args()
    if bool(arguments.exact_clean_image_metadata) != bool(arguments.exact_clean_image_metadata_sha256):
        parser.error("exact delivered pair requires metadata and its SHA-256")
    if arguments.run_native and arguments.exact_clean_image_metadata and not arguments.preparation_result:
        parser.error("paid exact delivered pair requires --preparation-result")
    gate = Gate(arguments)
    try:
        gate.build()
        gate.start_nodes()
        if arguments.run_native:
            gate.native_flow()
        else:
            gate.result["status"] = "PREPARATION_PASS_NATIVE_NOT_RUN"
    except Exception as error:
        gate.result["failure_phase"] = gate.phase
        gate.result["failure_class"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        gate.cleanup()
    print(json.dumps({"status": gate.result["status"], "result": str(gate.evidence / "result.json")}), flush=True)
    return 0 if gate.result["status"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
