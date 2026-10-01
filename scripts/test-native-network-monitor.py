#!/usr/bin/env python3
"""Disposable native Network -> explicit Owner admission -> Monitor proposal gate.

Default: no credentials/model, synthetic Codex record; full real HTTP preflight.
--run-native requires a matching successful preflight and an explicit caller's
approval; exactly three CLI turns maximum and no retry after an attempted turn.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("native_two", Path(__file__).with_name("test-two-node-codex-native.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
GO = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
HUB_BASE = "sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589"
TOOLS = ("cicada_network_join", "cicada_join", "cicada_regroup_propose")
MONITOR_GRANTS = ["artifact.share", "federation.represent", "task.read", "task.verify"]


def check_send_denied(result):
    # SEND reports a durable operation result even on permission failure; a
    # completed MCP RPC alone is neither delivery success nor an isError flag.
    if (result.get("status") != "FAILED" or result.get("retryable") is not False or result.get("attempts") != 1 or
            "403" not in result.get("error", "") or "permission denied" not in result.get("error", "")):
        raise RuntimeError("group_send_permission_failure_not_terminal")


def check_self_authority(member, monitor, candidate, actor, owner_id, node_id, key_grants):
    if (member.get("id") != monitor.get("membership_id") or member.get("version") != monitor.get("version") or
            member.get("principal_id") != actor.get("principal_id") or member.get("group_id") != actor.get("group_id") or
            member.get("status") != "active" or member.get("role") != "monitor" or
            json.loads(member.get("roles_json", "[]")) != ["monitor"] or
            sorted(json.loads(member.get("grants_json", "[]"))) != MONITOR_GRANTS):
        raise RuntimeError("self_operations_changed_explicit_monitor_authority")
    expected = {"endpoint_id": actor["endpoint_id"], "principal_id": actor["principal_id"], "owner_id": owner_id,
                "node_id": node_id, "binding_id": actor["binding_id"], "binding_epoch": actor["binding_epoch"], "state": "CANDIDATE"}
    if any(candidate.get(key) != value for key, value in expected.items()) or not candidate.get("key_id") or key_grants:
        raise RuntimeError("self_candidate_identity_or_no_owner_key_grant_mismatch")


def strict_tools(events, required):
    calls = [e["item"] for e in events if e.get("type") == "item.completed" and (e.get("item") or {}).get("type") == "mcp_tool_call"]
    for call in calls:
        name = call.get("tool") or call.get("name")
        result = call.get("result")
        if name not in required or call.get("status") != "completed" or call.get("error"):
            raise RuntimeError("unexpected_or_failed_native_tool")
        if not isinstance(result, dict):
            raise RuntimeError("native_tool_result_missing")
        if result.get("isError") or result.get("is_error"):
            raise RuntimeError("native_tool_result_is_error")
    if any((e.get("item") or {}).get("type") in ("command_execution", "file_change", "web_search", "collab_tool_call") for e in events):
        raise RuntimeError("unexpected_native_non_mcp_tool")
    names = [item.get("tool") or item.get("name") for item in calls]
    if sorted(names) != sorted(required):
        raise RuntimeError("native_required_tools_not_exactly_once")


def admission_input(preview):
    mapping = {"endpoint_migration_state": "expected_endpoint_migration_state", "network_version": "expected_network_version",
               "group_version": "expected_group_version", "network_membership_revision": "expected_network_membership_revision",
               "endpoint_network_revision": "expected_endpoint_network_revision", "membership_revision": "expected_membership_revision",
               "endpoint_group_revision": "expected_endpoint_group_revision"}
    keep = ("network_id", "group_id", "endpoint_id", "network_access_binding_id", "network_access_epoch", "native_binding_id", "native_binding_epoch",
            "existing_group_binding_id", "existing_group_binding_epoch")
    return {**{key: preview[key] for key in keep if key in preview}, **{target: preview[source] for source, target in mapping.items()}}


class Gate(native.Gate):
    def __init__(self, args):
        super().__init__(args)
        self.node_letters = "a"
        self.result.update(schema="cicada.native-network-monitor.v1", native_model_turn_attempts=0,
                           operator="synthetic disposable Owner; encrypted wire v1; no Android UI", models_invoked=0,
                           runtime_queue_consumption="CONSUMPTION_UNCONFIRMED; no Group messages are sent in this proposal gate",
                           limits=["one Docker Node on one physical host", "controlled native resumes; busy wake NOT_RUN",
                                   "Android, physical device and public HTTPS NOT_RUN", "proposal only; delegation execution NOT_RUN"])
        self.result["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.evidence.joinpath("executed-driver.py").rename(self.evidence / "executed-shared-driver.py")
        with os.fdopen(os.open(self.evidence / "executed-driver.py", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(Path(__file__).read_bytes())

    def command(self, command, input_data=None, timeout=120, log=None):
        count = len(self.result["steps"])
        try:
            return super().command(command, input_data, timeout, log)
        except subprocess.TimeoutExpired:
            self.result["steps"].append({"phase": self.phase, "exit_code": None, "timed_out": True,
                                         "timeout_seconds": timeout, "argv": list(map(str, command))})
            raise RuntimeError("command_timeout_terminal_no_retry")
        finally:
            if len(self.result["steps"]) > count:
                self.result["steps"][-1]["argv"] = list(map(str, command))

    def go(self, *args, log=None, timeout=300):
        return self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                           "-v", str(self.repo / "cicada-go") + ":/src", "-v", str(self.root) + ":/fixture",
                           "-v", "/home/zyf/CICADA/.cicada-data/m1-gomodcache:/gomodcache:ro",
                           "-v", "/home/zyf/.cache/go-build:/gocache", "-w", "/src", "-e", "GOTOOLCHAIN=local",
                           "-e", "GOPROXY=off", "-e", "GOMODCACHE=/gomodcache", "-e", "GOCACHE=/gocache",
                           "-e", "CGO_ENABLED=0", "--entrypoint", "go", GO, *args, log=log, timeout=timeout)

    def build(self):
        self.step("offline_frozen_source_build")
        metadata_path = self.root / "source.json"
        self.command([str(self.repo / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(metadata_path)])
        self.result["build"] = json.loads(metadata_path.read_text())
        source = self.result["build"]["source"]
        flags = "-s -w " + " ".join("-X github.com/cicada-ai/cicada/internal/buildinfo." + key + "=" + str(value) for key, value in
                                      (("Version", "0.1.0-dev"), ("Revision", source["revision"]), ("Dirty", "true"), ("SourceFingerprint", source["source_fingerprint"])))
        self.go("build", "-trimpath", "-ldflags=" + flags, "-o", "/fixture/cicada", "./cmd/cicada", log="binary-build.log")
        self.go("build", "-trimpath", "-o", "/fixture/operator", "./cmd/cicada-native-network-fixture", log="operator-build.log")
        for name in ("cicada", "operator"):
            self.root.joinpath(name).chmod(0o700)
            self.result[name + "_binary_sha256"] = hashlib.sha256(self.root.joinpath(name).read_bytes()).hexdigest()
        tag = self.run_id + ":hub"
        base_tag = self.run_id + ":base"
        base_id = self.inspect("image", self.args.hub_base_image)["Id"]
        self.docker("tag", base_id, base_tag)
        self.images[base_tag] = base_id
        dockerfile = "FROM " + base_tag + "\nCOPY cicada /usr/local/bin/cicada\n" + "\n".join(
            "LABEL " + key + "=" + json.dumps(str(value)) for key, value in {
                "org.cicada.test.run": self.run_id, "org.opencontainers.image.revision": source["revision"],
                "org.cicada.build.dirty": "true", "org.cicada.build.source-fingerprint": source["source_fingerprint"],
                "org.cicada.client-catalog.sha256": source["catalog_sha256"]}.items()) + "\n"
        self.root.joinpath("Dockerfile").write_text(dockerfile)
        self.docker("build", "--network", "none", "--pull=false", "-t", tag, self.root, log="image-build.log", timeout=180)
        self.hub_image = self.inspect("image", tag)["Id"]
        self.images[tag] = self.hub_image
        self.result["hub_image_id"] = self.hub_image
        self.result["hub_base_image_id"] = base_id
        self.result["go_image_id"] = self.inspect("image", GO)["Id"]
        self.result["runtime_image_id"] = self.inspect("image", self.args.runtime_image)["Id"]
        self.test_image = GO
        if self.args.run_native:
            prior = json.loads(Path(self.args.preflight_result).read_text())
            if prior.get("status") != "PREFLIGHT_PASS_NATIVE_NOT_RUN" or prior.get("build", {}).get("source") != source or prior.get("script_sha256") != self.result["script_sha256"] or prior.get("cicada_binary_sha256") != self.result["cicada_binary_sha256"] or prior.get("runtime_image_id") != self.result["runtime_image_id"]:
                raise RuntimeError("successful_preflight_exact_source_driver_binary_runtime_required")
            self.result["preflight_result_sha256"] = hashlib.sha256(Path(self.args.preflight_result).read_bytes()).hexdigest()

    def operator(self, action, *args):
        return self.docker("run", "--rm", "--network", "host" if action == "rpc" else "none", "--user", f"{os.getuid()}:{os.getgid()}",
                           "--label", "org.cicada.test.run=" + self.run_id, "-v", str(self.root) + ":/fixture",
                           "--entrypoint", "/fixture/operator", GO, action, "--fixture", "/fixture", *args, log="operator-" + action + "-" + str(len(self.result["steps"])) + ".json.private")

    def owner_rpc(self, operation, body, expect_ok=True):
        index = len(self.result.setdefault("owner_rpc", [])) + 1
        name = f"owner-input-{index}.json"
        native.private_json(self.root / name, body)
        raw = self.operator("rpc", "--url", self.owner_url, "--operation", operation, "--body-file", "/fixture/" + name)
        value = json.loads(raw)
        self.result["owner_rpc"].append({"operation": operation, "ok": value.get("ok") is True, "request_id": value.get("request_id")})
        if (value.get("ok") is True) != expect_ok:
            raise RuntimeError("encrypted_owner_operation_unexpected_result_" + operation)
        return value.get("result") if expect_ok else value

    def prepare(self):
        self.start_nodes()
        self.root.joinpath(".native-network-owned").write_text("cicada.native-network.disposable.v1\n" + self.run_id + "\n")
        self.root.joinpath(".native-network-owned").chmod(0o600)
        self.operator("bootstrap")
        self.meta = json.loads(self.root.joinpath("network-fixture.json").read_text())
        node = self.nodes["a"]
        node["node_id"] = self.meta["node_id"]
        self.hub = self.run_id + "-hub"
        env = self.root / "hub.env"
        env.write_text("CICADA_API_TOKEN=" + secrets.token_hex(32) + "\n")
        env.chmod(0o600)
        self.switch_hub("management")
        caps = self.owner_rpc("session.capabilities", {})
        if caps.get("owner_id") != self.meta["owner_id"] or not set(("topology.apply", "topology.endpoint_admission_preview", "topology.regroup_proposal")).issubset(caps.get("available_rpc_operations", [])):
            raise RuntimeError("encrypted_owner_operations_unavailable")
        groups = []
        for label in ("source", "target"):
            result = self.owner_rpc("topology.apply", {"kind": "group.create", "create_group": {"group": {
                "network_id": self.meta["network_id"], "name": "Synthetic native Monitor " + label,
                "context_policy": "group_scoped", "isolation_profile": "trusted_host", "external_mode": "explicit_links"}}})
            groups.append(result["group"])
        self.source, self.target = groups
        self.meta["group_id"] = self.source["group_id"]
        nodes = self.owner_rpc("nodes.list", {})
        current = [n for n in nodes if n.get("node_id") == self.meta["node_id"]]
        if len(current) != 1 or current[0].get("owner_id") != self.meta["owner_id"] or current[0].get("hub_id") != self.meta["hub_id"] or current[0].get("state") != "ACTIVE" or current[0].get("authorized") is not True or current[0].get("version", 0) <= 0:
            raise RuntimeError("encrypted_current_node_binding_not_exact")
        self.result["current_owner_node_binding"] = current[0]
        self.switch_hub("fabric")
        self.start_services("a")

    def switch_hub(self, mode):
        self.step("owned_hub_mode_" + mode)
        node = self.nodes["a"]
        if self.hub in self.containers:
            current = self.inspect("container", self.hub)
            if current["Config"]["Labels"].get("org.cicada.test.run") != self.run_id or current["Image"] != self.hub_image:
                raise RuntimeError("mode_switch_not_owned_hub")
            if current["State"]["Running"]:
                self.docker("stop", self.hub)
            self.docker("rm", self.hub)
        owner_port = getattr(self, "owner_port", "")
        node_port = node.get("hub_port", "")
        self.docker("run", "-d", "--name", self.hub, "--label", "org.cicada.test.run=" + self.run_id,
                    "--user", f"{os.getuid()}:{os.getgid()}", "--network", "bridge", "-p", "127.0.0.1:" + owner_port + ":8787",
                    "-p", node["gateway"] + ":" + node_port + ":8787", "--env-file", self.root / "hub.env", "-e", "CICADA_STATE_DIR=/state",
                    "-e", "CICADA_INTENT_PLANNER_BIN=", "-e", "CICADA_COMPLETION_VERIFIER_BIN=",
                    "-v", str(self.root / "hub-state") + ":/state", self.hub_image,
                    "serve", "--host", "0.0.0.0", "--port", "8787", *(["--fabric-only"] if mode == "fabric" else []))
        self.containers[self.hub] = self.hub_image
        ports = self.inspect("container", self.hub)["NetworkSettings"]["Ports"]["8787/tcp"]
        self.owner_port = next(p["HostPort"] for p in ports if p["HostIp"] == "127.0.0.1")
        self.owner_url = "http://127.0.0.1:" + self.owner_port
        node["hub_port"] = next(p["HostPort"] for p in ports if p["HostIp"] == node["gateway"])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(80):
            try:
                with opener.open(self.owner_url + "/healthz", timeout=1) as response:
                    health = json.load(response)
                break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError("owned_hub_not_ready")
        if health.get("source_fingerprint") != self.result["build"]["source"]["source_fingerprint"] or health.get("dirty") is not True:
            raise RuntimeError("hub_actual_build_provenance_mismatch")
        if mode == "fabric":
            request = urllib.request.Request(self.owner_url + "/v1/machines", headers={"Authorization": "Bearer " + self.root.joinpath("hub.env").read_text().strip().split("=", 1)[1]})
            try:
                opener.open(request, timeout=2)
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            else:
                status = 200
            if status != 503:
                raise RuntimeError("business_control_not_disabled")
            self.result["control_business"] = {"enabled": False, "authenticated_http_status": status, "evidence": "production --fabric-only; structural isolation"}
        self.hub_mode = mode
        self.result.setdefault("hub_mode_boundaries", []).append({"mode": mode, "identity_preserved": True, "database_preserved": True, "image_id": self.hub_image})

    def start_services(self, letter):
        node = self.nodes[letter]
        self.docker("exec", "-d", node["container"], "python3", "-c", native.FORWARDER, node["gateway"], node["hub_port"], "8787")
        self.docker("exec", "-d", "-e", "CICADA_CODEX_BIN=" + native.CODEX, "-e", "CODEX_HOME=/codex", "-e", "CICADA_HUB_ID=" + self.meta["hub_id"], node["container"], "/bin/sh", "-c",
                    '/out/cicada machine agent --id "$1" --control-url http://127.0.0.1:8787 --state-dir /state --interval 1s --relay-only >>/state/agent.log 2>&1', "sh", node["node_id"])
        for _ in range(100):
            if node["paths"]["state"].joinpath("nodes", "node-" + node["node_id"], "join.sock").is_socket():
                break
            time.sleep(.2)
        else:
            raise RuntimeError("actual_node_bridge_not_ready")
        probe = '''import json,sys,urllib.request\nfrom pathlib import Path\nnode=sys.argv[1];token=Path('/state/nodes/node-'+node+'/relay.token').read_text().strip()\nrequest=urllib.request.Request('http://127.0.0.1:8787/v2/relay/nodes/'+node+'/events',headers={'Authorization':'CicadaNode '+token,'Accept':'text/event-stream'})\nwith urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:\n print(json.dumps({'status':response.status,'ready':response.readline(128).startswith(b'event: ready')}))\n'''
        result = json.loads(self.docker("exec", node["container"], "python3", "-c", probe, node["node_id"]))
        if result != {"status": 200, "ready": True}:
            raise RuntimeError("actual_node_current_binding_sse_denied")
        self.result["outbound_sse"] = result

    def environment(self, thread):
        return {"CICADA_API_URL": "http://127.0.0.1:8787", "CICADA_NODE_STATE_DIR": "/state", "CICADA_MCP_STATE_DIR": "/mcp",
                "CICADA_MACHINE_ID": self.meta["node_id"], "CICADA_HARNESS": "codex", "CICADA_GROUP_ID": self.meta["group_id"],
                "CICADA_HUB_ID": self.meta["hub_id"], "CICADA_NETWORK_JOIN_DIR": "/mcp/network-join",
                "CICADA_NETWORK_SESSION_DIR": "/mcp/network-session", "CICADA_API_TOKEN": "", "CICADA_API_TOKEN_FILE": "",
                "CODEX_HOME": "/codex", "CODEX_THREAD_ID": thread or ""}

    def native_config(self, letter, thread=None, tools=()):
        if not thread:
            return []
        config = super().native_config(letter, thread, tools)
        env = "{" + ",".join(key + "=" + json.dumps(value) for key, value in self.environment(thread).items()) + "}"
        index = next(i for i, value in enumerate(config) if value.startswith("mcp_servers.cicada.env="))
        config[index] = "mcp_servers.cicada.env=" + env
        return config

    def mcp(self, thread, tool=None, arguments=None, expect_error=False, expected_error_contains=None):
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "synthetic-offline-network-monitor", "version": "1"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call" if tool else "tools/list", "params": {"name": tool, "arguments": arguments or {}} if tool else {}}]
        args = ["exec", "-i", "--workdir", "/workspace"]
        for key, value in self.environment(thread).items():
            args += ["-e", key + "=" + value]
        raw = self.docker(*args, self.nodes["a"]["container"], "/out/cicada", "mcp", "--api-url", "http://127.0.0.1:8787",
                          input_data=("\n".join(map(json.dumps, messages)) + "\n").encode(),
                          log="mcp-" + str(tool or "list") + "-" + str(len(self.result["steps"])) + ".json.private")
        responses = [event for event in native.parse_events(raw) if event.get("id") == 2]
        initialized = [event for event in native.parse_events(raw) if event.get("id") == 1]
        if len(initialized) != 1 or "error" in initialized[0] or "result" not in initialized[0]:
            raise RuntimeError("actual_mcp_initialization_failed")
        if len(responses) != 1:
            raise RuntimeError("actual_mcp_response_not_unique")
        result = responses[0].get("result", {})
        error = "error" in responses[0] or result.get("isError") is True
        if error != expect_error:
            raise RuntimeError("actual_mcp_tool_unexpected_result_" + str(tool))
        if not tool:
            return result
        if expect_error:
            if expected_error_contains and expected_error_contains not in json.dumps(responses[0]):
                raise RuntimeError("actual_mcp_negative_error_class_mismatch")
            return {"denied": True}
        if result.get("structuredContent"):
            return result["structuredContent"]
        for block in result.get("content", []):
            if block.get("type") == "text":
                try:
                    return json.loads(block["text"])
                except ValueError:
                    pass
        raise RuntimeError("actual_mcp_structured_result_missing")

    def protocol_tools_preflight(self, letter, thread, tools):
        result = self.mcp(thread)
        names = [item.get("name") for item in result.get("tools", [])]
        if not set(tools).issubset(names):
            raise RuntimeError("actual_mcp_required_tools_missing")
        self.result.setdefault("actual_mcp_preflight", []).append({"needed_tools": list(tools), "all_listed": True, "model_calls": 0})

    def parse_config_offline(self, letter, config):
        super().parse_config_offline(letter, config)
        node = self.nodes[letter]
        target = node["paths"]["codex"] / "config.toml"
        for path in (node["paths"]["codex"], target):
            item = path.lstat()
            if stat.S_ISLNK(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != (0o700 if path.is_dir() else 0o600):
                raise RuntimeError("private_codex_config_ownership_or_mode_mismatch")
        if config:
            needed = ("mcp_servers.cicada.enabled_tools=", 'mcp_servers.cicada.required=true', 'mcp_servers.cicada.omit_tools_from=["deferred"]')
            if any(not any(item.startswith(key) for item in config) for key in needed):
                raise RuntimeError("explicit_native_mcp_allowlist_configuration_missing")
        self.result["private_codex_config"] = {"directory_mode": "0700", "file_mode": "0600", "owner_current_uid": True,
                                               "offline_cli_parsed_explicit_allowlist": bool(config), "credential_mounted_in_parser": False}

    def issue(self, thread):
        scope = hashlib.sha256(("http://127.0.0.1:8787\x00codex\x00" + thread + "\x00" + self.meta["node_id"]).encode()).hexdigest()
        self.operator("issue", "--native-thread", thread, "--scope", scope)
        self.network_scope = scope

    def network_endpoint(self, thread):
        path = self.nodes["a"]["paths"]["mcp"] / "network-session/scopes" / self.network_scope / (self.meta["network_id"] + ".session.json")
        state = json.loads(path.read_text())
        rows = self.hub_rows("SELECT id,endpoint_id,node_id,native_session_id,epoch,status FROM network_direct_native_bindings_v2 WHERE endpoint_id=?", (state["endpoint_id"],))
        if len(rows) != 1 or rows[0]["native_session_id"] != thread or rows[0]["node_id"] != self.meta["node_id"] or rows[0]["epoch"] <= 0 or rows[0]["status"] != "active":
            raise RuntimeError("actual_network_native_binding_not_exact_current")
        self.result["network_native_binding"] = rows[0]
        self.endpoint = state["endpoint_id"]
        return self.endpoint

    def directory_only_guard(self):
        probe = r'''import base64,json,sys,urllib.request,urllib.error
from pathlib import Path
node,scope,network=sys.argv[1:]
state=json.loads(Path('/mcp/network-session/scopes/'+scope+'/'+network+'.session.json').read_text())
token=Path('/state/nodes/node-'+node+'/relay.token').read_text().strip()
body={'network_id':network,'network_session_token':state['session_token'],'target_endpoint_id':'ep_synthetic_denied','message_id':'msg_synthetic_denied','ciphertext':base64.b64encode(b'synthetic opaque negative guard fixture').decode()}
request=urllib.request.Request('http://127.0.0.1:8787/v2/fabric/node/networks/direct/send',data=json.dumps(body).encode(),headers={'Authorization':'CicadaNode '+token,'Content-Type':'application/json'})
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response: status=response.status
except urllib.error.HTTPError as error: status=error.code;error.close()
print(json.dumps({'http_status':status,'payload_printed':False}))
'''
        value = json.loads(self.docker("exec", self.nodes["a"]["container"], "python3", "-c", probe, self.meta["node_id"], self.network_scope, self.meta["network_id"]))
        if value["http_status"] != 403:
            raise RuntimeError("directory_only_direct_send_guard_not_403")
        rows = self.hub_rows("SELECT grants_json FROM network_memberships_v2 WHERE network_id=? AND principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=?)", (self.meta["network_id"], self.endpoint))
        if len(rows) != 1 or sorted(json.loads(rows[0]["grants_json"])) != ["directory.discover", "directory.publish"]:
            raise RuntimeError("directory_only_network_grants_changed")
        self.result["directory_only_guard"] = {"http_status": 403, "grants": ["directory.discover", "directory.publish"], "relay_commits": len(self.hub_rows("SELECT message_id FROM relay_v2_message_payloads"))}

    def admit_and_bind(self, endpoint, thread):
        self.switch_hub("management")
        admissions = []
        for group in (self.source, self.target):
            self.step("encrypted_owner_admission_" + ("source" if group == self.source else "target"))
            preview = self.owner_rpc("topology.endpoint_admission_preview", {"network_id": self.meta["network_id"], "group_id": group["group_id"], "endpoint_id": endpoint})
            if preview.get("history_included") or preview.get("key_grant_created") or preview.get("admission_grants") or preview.get("admission_roles") != ["member"]:
                raise RuntimeError("admission_expands_authority")
            changed = self.owner_rpc("topology.apply", {"kind": "endpoint.admit_group", "admit_endpoint": {"admission": admission_input(preview)}})
            member = changed["endpoint_member"]
            if member["role"] != "member":
                raise RuntimeError("admission_auto_monitor_role")
            admissions.append({"group_id": group["group_id"], "membership_id": member["membership_id"], "version": member["version"],
                               "role": member["role"], "grants": preview["admission_grants"], "history_included": False, "key_grant_created": False})
            if group == self.source:
                self.step("encrypted_owner_explicit_monitor_role_cas")
                bound = self.owner_rpc("topology.apply", {"kind": "membership.bind_role", "bind_role": {"group_id": group["group_id"],
                    "membership_id": member["membership_id"], "role": "monitor", "expected_membership_version": member["version"]}})
                monitor = bound["membership"]
        self.result["encrypted_owner_admissions"] = admissions
        self.result["encrypted_owner_monitor_role"] = monitor
        self.step("encrypted_owner_fresh_group_versions")
        snapshot = self.owner_rpc("topology.snapshot", {})
        self.source, self.target = [next(g for g in snapshot["groups"] if g["group_id"] == old["group_id"]) for old in (self.source, self.target)]
        self.result["fresh_group_versions"] = {"source": self.source, "target": self.target}
        self.switch_hub("fabric")

    def self_identity_guard(self, thread):
        self.step("group_self_identity_candidate_and_peer_denials_without_directory_grant")
        actor = self.current_actor("a")
        query = "SELECT id,principal_id,group_id,role,roles_json,grants_json,status,revision,version FROM memberships WHERE id=? AND principal_id=? AND group_id=?"
        member_scope = (self.result["encrypted_owner_monitor_role"]["membership_id"], actor["principal_id"], actor["group_id"])
        members = self.hub_rows(query, member_scope)
        candidate_query = "SELECT endpoint_id,principal_id,owner_id,node_id,key_id,binding_id,binding_epoch,state,version FROM endpoint_key_candidates_v2 WHERE endpoint_id=?"
        candidates = self.hub_rows(candidate_query, (self.endpoint,))
        if len(members) != 1 or len(candidates) != 1:
            raise RuntimeError("own_join_membership_candidate_missing")
        before, candidate = members[0], candidates[0]
        key_grants = self.hub_rows("SELECT id FROM group_endpoint_key_grants_v2 WHERE endpoint_id=?", (self.endpoint,))
        check_self_authority(before, self.result["encrypted_owner_monitor_role"], candidate, actor,
                             self.meta["owner_id"], self.meta["node_id"], key_grants)
        self.mcp(thread, "cicada_publish_endpoint_key_candidate", {})
        self.mcp(thread, "cicada_members", {}, expect_error=True, expected_error_contains="403")
        self.mcp(thread, "cicada_find", {"query": self.endpoint}, expect_error=True, expected_error_contains="403")
        send = self.mcp(thread, "cicada_send", {"target": "ep_synthetic_denied", "body": "synthetic negative traffic fixture"})
        check_send_denied(send)
        # Read only the owned Node's private cached session inside its namespace;
        # emit statuses, never credentials. The SEND result above independently
        # proves a terminal permission denial rather than a delivery or retry.
        probe = r'''import json,sys,urllib.request,urllib.error
from pathlib import Path
scope,group,endpoint,node,thread=sys.argv[1:]
disk=json.loads(Path('/mcp/mcp/scopes/'+scope+'.json').read_text())
matches=[s for s in disk['sessions'] if s['group_id']==group and s['endpoint_id']==endpoint and s['node_id']==node and s['native_session_id']==thread]
if len(matches)!=1: raise RuntimeError('exact_private_group_session_missing')
headers={'Authorization':'CicadaSession '+matches[0]['session_token'],'Cicada-Group-Scope':group}
statuses={}
for name,path in [('own_key','/v2/fabric/endpoint-keys/'+endpoint),('peer_key','/v2/fabric/endpoint-keys/ep_synthetic_denied')]:
 request=urllib.request.Request('http://127.0.0.1:8787'+path,headers=headers)
 try:
  with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response: statuses[name]=response.status
 except urllib.error.HTTPError as error: statuses[name]=error.code;error.close()
print(json.dumps(statuses))
'''
        statuses = json.loads(self.docker("exec", self.nodes["a"]["container"], "python3", "-c", probe,
                                           self.network_scope, self.source["group_id"], self.endpoint, self.meta["node_id"], thread))
        if statuses != {"own_key": 200, "peer_key": 403}:
            raise RuntimeError("self_key_peer_directory_traffic_guard_status_mismatch")
        after_members = self.hub_rows(query, member_scope)
        after_candidates = self.hub_rows(candidate_query, (self.endpoint,))
        after_grants = self.hub_rows("SELECT id FROM group_endpoint_key_grants_v2 WHERE endpoint_id=?", (self.endpoint,))
        if after_members != [before] or after_candidates != [candidate] or after_grants or self.hub_rows("SELECT message_id FROM relay_v2_message_payloads"):
            raise RuntimeError("self_or_negative_peer_operations_changed_authority_key_or_relay")
        self.result["group_self_authority"] = {"membership": before, "candidate": candidate,
            "membership_unchanged": True, "candidate_unchanged_on_repeat": True, "owner_key_grants": 0,
            "directory_read_granted": False, "peer_members_and_find_denied": True, "send_denied": True,
            "send_operation_result": {key: send[key] for key in ("status", "retryable", "attempts", "error")},
            "http_statuses": statuses, "relay_commits": 0, "synthetic_operator_store_grant_used": False}

    def proposal_arguments(self):
        return {"network_id": self.meta["network_id"], "target_group_id": self.target["group_id"], "action": "SET_PARENT",
                "expected_source_version": self.source["version"], "expected_target_version": self.target["version"], "idempotency_key": self.run_id + "-proposal"}

    def check_proposal(self, proposal, thread):
        if proposal.get("state") != "PROPOSED" or proposal.get("endpoint_id") != self.endpoint or proposal.get("owner_id") != self.meta["owner_id"]:
            raise RuntimeError("proposal_provenance_or_state_mismatch")
        self.switch_hub("management")
        self.step("encrypted_owner_durable_proposal_and_no_auto_apply")
        authoritative = self.owner_rpc("topology.regroup_proposal", {"proposal_id": proposal["proposal_id"]})
        if authoritative != proposal:
            raise RuntimeError("durable_owner_proposal_differs_native_result")
        snapshot = self.owner_rpc("topology.snapshot", {})
        groups = [next(g for g in snapshot["groups"] if g["group_id"] == old["group_id"]) for old in (self.source, self.target)]
        if groups != [self.source, self.target] or self.hub_rows("SELECT delegation_id FROM regroup_delegations_v2"):
            raise RuntimeError("proposal_applied_or_created_delegation")
        self.switch_hub("fabric")
        self.step("exact_current_producer_native_endpoint_provenance")
        actor = self.current_actor("a")
        self.result["native_actor_after"] = actor
        bindings = self.hub_rows("SELECT id,endpoint_id,principal_id,group_id,node_id,native_session_id,epoch,status FROM session_bindings WHERE id=?", (actor["binding_id"],))
        if len(bindings) != 1 or any(bindings[0].get(key) != value for key, value in {
            "endpoint_id": self.endpoint, "principal_id": actor["principal_id"], "group_id": self.source["group_id"],
            "node_id": self.meta["node_id"], "native_session_id": thread, "epoch": actor["binding_epoch"]}.items()) or bindings[0]["status"] not in ("active", "leased", "online", "ready", "acquired"):
            raise RuntimeError("current_group_binding_native_uuid_node_endpoint_mismatch")
        native_bindings = self.hub_rows("SELECT id,endpoint_id,node_id,native_session_id,epoch,status FROM network_direct_native_bindings_v2 WHERE endpoint_id=?", (self.endpoint,))
        if len(native_bindings) != 1 or native_bindings[0]["native_session_id"] != thread or native_bindings[0]["node_id"] != self.meta["node_id"] or native_bindings[0]["id"] != self.result["network_native_binding"]["id"] or native_bindings[0]["status"] != "active":
            raise RuntimeError("current_network_native_binding_identity_changed")
        if self.result.get("native_actor_before") and self.result["native_actor_before"] != actor:
            raise RuntimeError("proposal_changed_current_native_actor")
        self.result["current_group_native_binding"] = bindings[0]
        self.result["current_network_native_binding"] = native_bindings[0]
        expected = {"operation_id": self.proposal_arguments()["idempotency_key"], "network_id": self.meta["network_id"],
                    "source_group_id": self.source["group_id"], "target_group_id": self.target["group_id"], "action": "SET_PARENT",
                    "expected_source_version": self.source["version"], "expected_target_version": self.target["version"]}
        if any(proposal.get("input", {}).get(key) != value for key, value in expected.items()) or proposal.get("hub_id") != self.meta["hub_id"] or proposal.get("principal_id") != actor["principal_id"] or proposal.get("binding_id") != actor["binding_id"] or proposal.get("binding_epoch") != actor["binding_epoch"]:
            raise RuntimeError("exact_proposal_input_or_producer_binding_mismatch")
        self.result["proposal"] = proposal
        self.result["proposal_only_topology_unchanged"] = True
        self.result["delegation_issue_or_apply_called"] = False
        self.result["original_thread_id"] = thread
        native.private_json(self.evidence / "proposal-redacted.json", proposal)

    def offline_flow(self):
        self.step("synthetic_native_record_full_preflight")
        thread = "11111111-2222-4333-8444-555555555555"
        self.nodes["a"]["thread"] = thread
        sessions = self.nodes["a"]["paths"]["codex"] / "sessions"
        sessions.mkdir(mode=0o700)
        with os.fdopen(os.open(sessions / ("rollout-synthetic-offline-" + thread + ".jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write(json.dumps({"type": "session_meta", "payload": {"id": thread, "cwd": "/workspace", "source": "cli"}}) + "\n")
        self.protocol_tools_preflight("a", thread, TOOLS)
        self.parse_config_offline("a", self.native_config("a", thread, TOOLS))
        self.issue(thread)
        self.step("actual_mcp_network_join_and_native_binding")
        self.mcp(thread, "cicada_network_join", {"network_id": self.meta["network_id"]})
        endpoint = self.network_endpoint(thread)
        if self.hub_rows("SELECT * FROM endpoint_group_memberships WHERE endpoint_id=?", (endpoint,)):
            raise RuntimeError("network_join_auto_group_admission")
        self.directory_only_guard()
        self.mcp(thread, "cicada_publish_endpoint_key_candidate", {"network_id": self.meta["network_id"]}, expect_error=True)
        self.admit_and_bind(endpoint, thread)
        self.step("actual_mcp_group_join_without_directory_grant")
        self.mcp(thread, "cicada_join", {})
        self.self_identity_guard(thread)
        before = self.current_actor("a")
        self.result["native_actor_before"] = before
        self.step("actual_mcp_monitor_proposal_and_spoof_denials")
        proposal = self.mcp(thread, "cicada_regroup_propose", self.proposal_arguments())["regroup_proposal"]
        self.mcp(thread, "cicada_regroup_apply", {"proposal_id": proposal["proposal_id"], "delegation_id": "synthetic-forged-user-approval"}, expect_error=True)
        self.mcp(thread, "cicada_regroup_propose", {**self.proposal_arguments(), "idempotency_key": self.run_id + "-forged", "user_approved": True}, expect_error=True)
        self.check_proposal(proposal, thread)
        self.result["synthetic_record_only"] = True
        self.result["negative_guards"] = {"no_auto_group": True, "no_auto_monitor": True, "directory_only_send_key_denied": True, "group_peer_directory_and_traffic_denied": True,
                                         "group_self_join_candidate_without_directory_grant": True, "spoof_user_approval_denied": True}
        self.result["status"] = "PREFLIGHT_PASS_NATIVE_NOT_RUN"

    def native_turn(self, letter, prompt, thread=None, tools=(), markers=()):
        if self.result["native_model_turn_attempts"] >= 3:
            raise RuntimeError("native_three_turn_budget_exceeded")
        self.result["native_model_turn_attempts"] += 1
        self.result["models_invoked"] = self.result["native_model_turn_attempts"]
        result = super().native_turn(letter, prompt, thread, tools, markers)
        events = native.parse_events(self.evidence.joinpath(f"native-{self.phase}-{letter}.jsonl.private").read_bytes())
        strict_tools(events, tools)
        return result

    def native_flow(self):
        self.step("native_original_seed")
        self.provider_forwarder(self.nodes["a"])
        marker = "CICADA-ORIGINAL-MONITOR-" + secrets.token_hex(16)
        thread = self.native_turn("a", "Remember your original context witness " + marker + ". Do not use tools. Finish with this marker and READY.", markers=(marker,))
        self.nodes["a"]["thread"] = thread
        self.issue(thread)
        self.step("native_explicit_network_join")
        self.native_turn("a", "Call cicada_network_join exactly once with " + json.dumps({"network_id": self.meta["network_id"]}) + ". Do not retry or request other authority. Finish with READY.", thread, ("cicada_network_join",))
        endpoint = self.network_endpoint(thread)
        self.directory_only_guard()
        self.admit_and_bind(endpoint, thread)
        self.step("native_original_group_join_proposal_context")
        arguments = self.proposal_arguments()
        self.native_turn("a", "Call cicada_join exactly once with {}. Then call cicada_regroup_propose exactly once with " + json.dumps(arguments) + ". Stop on any error, never retry. After the successful proposal state your original context witness remembered from the first turn; do not approve or apply the proposal.", thread, ("cicada_join", "cicada_regroup_propose"), (marker,))
        events = native.parse_events(self.evidence.joinpath(f"native-{self.phase}-a.jsonl.private").read_bytes())
        proposals = []
        def walk(value):
            if isinstance(value, dict):
                if isinstance(value.get("regroup_proposal"), dict):
                    proposals.append(value["regroup_proposal"])
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str):
                try:
                    walk(json.loads(value))
                except ValueError:
                    pass
        for event in events:
            if (event.get("item") or {}).get("type") == "mcp_tool_call":
                walk(event["item"].get("result"))
        unique = {json.dumps(p, sort_keys=True): p for p in proposals}
        if len(unique) != 1:
            raise RuntimeError("native_proposal_tool_result_not_unique")
        proposal = next(iter(unique.values()))
        self.mcp(thread, "cicada_regroup_apply", {"proposal_id": proposal["proposal_id"], "delegation_id": "synthetic-forged-user-approval"}, expect_error=True)
        self.result["native_current_monitor_fake_approval_denied"] = True
        self.check_proposal(proposal, thread)
        self.result["status"] = "NATIVE_NETWORK_MONITOR_PROPOSAL_PASS"

    def cleanup(self):
        if self.result.get("build"):
            try:
                self.command([str(self.repo / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(self.evidence / "source-after.json")],
                             log="source-after-capture.log")
                after = json.loads(self.evidence.joinpath("source-after.json").read_text())["source"]
                self.result["source_unchanged_during_gate"] = after == self.result["build"]["source"]
                if not self.result["source_unchanged_during_gate"]:
                    self.result.update(status="FAIL", failure_phase="source_after_gate", failure_class="source_changed_during_gate")
            except Exception as error:
                self.result.update(status="FAIL", failure_phase="source_after_gate", failure_class=str(error))
        super().cleanup()
        self.result["terminal_exit_code"] = 0 if self.result["status"] != "FAIL" else 1
        # The shared cleanup writes its result before the final cleanup outcome
        # is reflected in our terminal field. Replace only our private receipt.
        path = self.evidence / "result.json"
        with path.open("w") as output:
            json.dump(self.result, output, indent=2, sort_keys=True)
            output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", required=True)
    parser.add_argument("--runtime-image", default=native.RUNTIME)
    parser.add_argument("--hub-base-image", default=HUB_BASE)
    parser.add_argument("--credential-file", default="/gpu1-share/data/cicada/secrets/cicada.env")
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--preflight-result", help="successful matching source/driver/binary/runtime preflight")
    args = parser.parse_args()
    if args.run_native and not args.preflight_result:
        parser.error("--run-native requires --preflight-result")
    gate = Gate(args)
    try:
        gate.build()
        gate.prepare()
        gate.native_flow() if args.run_native else gate.offline_flow()
    except Exception as error:
        gate.result["failure_phase"] = gate.phase
        gate.result["failure_class"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        gate.result["terminal_exit_code"] = 0 if gate.result["status"] != "FAIL" else 1
        gate.cleanup()
    print(json.dumps({"status": gate.result["status"], "result": str(gate.evidence / "result.json"),
                      "failure_phase": gate.result.get("failure_phase"), "failure_class": gate.result.get("failure_class"),
                      "models_invoked": gate.result["models_invoked"], "cleanup_owned_resources": gate.result["cleanup_owned_resources"],
                      "terminal_exit_code": 0 if gate.result["status"] != "FAIL" else 1}), flush=True)
    return 0 if gate.result["status"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
