#!/usr/bin/env python3
"""Attach an owned native Monitor Node to an independently owned Client fixture.

The Client alone confirms Node pairing and assigns Group/Monitor authority.
This driver performs real native Join/propose, never delegation issue or apply.
It cannot stop/delete the Client Hub and never opens the Client Hub database.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import shutil
import stat
import subprocess
import threading
import time
from urllib.parse import urlsplit

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location("native_two", Path(__file__).with_name("test-two-node-codex-native.py"))
native = module_from_spec(spec)
spec.loader.exec_module(native)
REVISION = "4fb241b5e824eb752ceb85586089f44c408e1e7e"
CATALOG = "1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c"


def public_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
        raise RuntimeError("public_fixture_file_not_owned_private")
    return json.loads(path.read_text())


def verify_client_fixture(marker_path, public_path):
    marker, public = public_file(marker_path), public_file(public_path)
    root = marker_path.parent.resolve()
    if marker_path.name != ".cicada-client-network-fixture.json" or root != public_path.parent.resolve() or str(root) != marker["fixture_dir"]:
        raise RuntimeError("client_fixture_marker_path_mismatch")
    if marker["schema"] != "cicada.client-network-fixture.v2" or marker["source_revision"] != REVISION or marker["source_dirty"] is not False:
        raise RuntimeError("client_fixture_source_not_clean_pinned")
    record = json.loads(subprocess.check_output(["docker", "inspect", marker["container"]]))[0]
    labels = record["Config"]["Labels"]
    expected = {"org.cicada.fixture": "client-network", "org.cicada.fixture.dir": str(root),
                "org.opencontainers.image.revision": REVISION, "org.cicada.build.dirty": "false",
                "org.cicada.build.source-fingerprint": marker["source_fingerprint"],
                "org.cicada.client-catalog.sha256": CATALOG}
    if any(labels.get(key) != value for key, value in expected.items()) or record["Image"] != marker["image_id"] or not record["State"]["Running"]:
        raise RuntimeError("client_fixture_actual_image_label_mismatch")
    if list(record["NetworkSettings"]["Networks"]) != [marker["network"]]:
        raise RuntimeError("client_fixture_unexpected_network")
    network = json.loads(subprocess.check_output(["docker", "network", "inspect", marker["network"]]))[0]
    if set(network.get("Containers", {})) != {record["Id"]}:
        raise RuntimeError("client_fixture_network_not_hub_only")
    for key in ("hub_id", "image_id", "source_revision", "source_fingerprint", "catalog_sha256", "contract_revision"):
        if public[key] != marker[key]:
            raise RuntimeError("client_public_pin_mismatch")
    if public["owner_id"] != marker["primary_owner_id"] or public["network_id"] != marker["primary_network_id"]:
        raise RuntimeError("client_public_owner_network_mismatch")
    url = urlsplit(public["base_url"])
    if url.scheme != "http" or url.hostname != "127.0.0.1" or url.port != int(marker["host_port"]) or url.path not in ("", "/") or url.username or url.password or url.query or url.fragment:
        raise RuntimeError("client_fixture_url_not_exact_loopback")
    return marker, {key: public[key] for key in ("hub_id", "owner_id", "owner_key_id", "network_id", "owner_public_identity", "base_url")}


class AttachGate(native.Gate):
    def __init__(self, arguments):
        super().__init__(arguments)
        self.node_letters = "a"
        self.marker, self.public = verify_client_fixture(Path(arguments.marker), Path(arguments.public))
        self.result["schema"] = "cicada.native-monitor-regroup.v1"
        self.result["limits"] = ["one owned Docker Node on one physical host", "controlled native resume; busy wake NOT_RUN",
                                  "Owner pairing/Monitor/delegation authority belongs to the independent Client",
                                  "proposal alone changes no topology; no delegation issue/apply by this driver",
                                  "public HTTPS and physical Android NOT_RUN by this driver"]
        self.result["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.result["shared_driver_sha256"] = hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest()
        self.result["client_fixture_pins"] = {key: self.marker[key] for key in ("container", "image_id", "source_revision", "source_fingerprint", "hub_id", "catalog_sha256")}
        self.meta = {"hub_id": self.public["hub_id"]}
        native.private_json(self.evidence / "owner-public-pin.json", {key: self.public[key] for key in ("owner_id", "owner_key_id", "owner_public_identity", "hub_id")})
        self.evidence.joinpath("executed-driver.py").rename(self.evidence / "executed-shared-driver.py")
        with os.fdopen(os.open(self.evidence / "executed-driver.py", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(Path(__file__).read_bytes())
        self.adopted = None

    def adopt_pairing(self, handoff_path):
        handoff = public_file(Path(handoff_path))
        if handoff.get("schema") != "cicada.native-monitor-pairing-handoff.v1" or handoff.get("hub_id") != self.public["hub_id"] or handoff.get("owner_id") != self.public["owner_id"] or handoff.get("source_revision") != REVISION:
            raise RuntimeError("existing_owned_pairing_scope_mismatch")
        record = self.inspect("container", handoff["container"])
        if record["Config"]["Labels"].get("org.cicada.test.run") != handoff["owned_run_label"] or record["Image"] != self.args.runtime_image or not record["State"]["Running"]:
            raise RuntimeError("existing_owned_node_label_image_mismatch")
        mounts = {item["Destination"]: Path(item["Source"]) for item in record["Mounts"]}
        root = mounts["/state"].parent
        info = root.lstat()
        if root.parent != Path("/tmp") or not root.name.startswith("cicada-native-two-") or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise RuntimeError("existing_owned_node_root_unsafe")
        for destination in ("/state", "/codex", "/workspace", "/mcp", "/out/cicada"):
            if mounts[destination].parent != root or mounts[destination].is_symlink():
                raise RuntimeError("existing_owned_node_mount_scope_mismatch")
        if hashlib.sha256(mounts["/out/cicada"].read_bytes()).hexdigest() != self.result["cicada_binary_sha256"]:
            raise RuntimeError("existing_owned_node_binary_not_client_exact_image")
        networks = record["NetworkSettings"]["Networks"]
        if len(networks) != 1 or self.marker["network"] in networks or record["HostConfig"]["PortBindings"]:
            raise RuntimeError("existing_owned_node_network_unsafe")
        network_name = next(iter(networks))
        network = self.inspect("network", network_name)
        if network["Labels"].get("org.cicada.test.run") != handoff["owned_run_label"]:
            raise RuntimeError("existing_owned_node_network_label_mismatch")
        self.nodes = {"a": {"container": handoff["container"], "node_id": handoff["node_id"], "network": network_name,
                            "gateway": network["IPAM"]["Config"][0]["Gateway"],
                            "paths": {key: mounts["/" + key] for key in ("state", "codex", "workspace", "mcp")}}}
        self.adopted = handoff
        self.result["pairing_preparation_handoff"] = str(Path(handoff_path).resolve())
        self.result["runtime_versions"] = {"a": self.docker("exec", handoff["container"], native.CODEX, "--version").decode().strip()}
        if self.result["runtime_versions"]["a"] != "codex-cli 0.159.3":
            raise RuntimeError("existing_owned_node_cli_version_mismatch")

    def take_over_pairing(self, handoff_path):
        self.adopt_pairing(handoff_path)
        handoff = self.adopted
        receipt = public_file(Path(handoff_path).parent / "controller-handoff.json")
        if receipt.get("owned_run_label") != handoff["owned_run_label"] or receipt.get("node_id") != handoff["node_id"]:
            raise RuntimeError("controller_handoff_scope_mismatch")
        old_cmdline = Path("/proc") / str(receipt["previous_controller_pid"]) / "cmdline"
        if old_cmdline.exists() and old_cmdline.read_bytes():
            raise RuntimeError("previous_controller_still_running")
        node = self.nodes["a"]
        previous_root = node["paths"]["state"].parent
        shutil.rmtree(self.root)
        self.root = previous_root
        self.run_id = handoff["owned_run_label"]
        self.result["run_id"] = self.run_id
        self.result["controller_handoff"] = receipt
        self.containers = {node["container"]: self.args.runtime_image}
        self.networks = [node["network"]]
        self.adopted = None  # One controller owns cleanup; no stage-one signal.
        # Replace only the old owned Node's loopback forwarder. Node Agent,
        # key files, relay credential and pending candidate remain untouched.
        stop = r'''import os,pathlib,signal,sys
expected=sys.argv[1].encode()
for path in pathlib.Path('/proc').iterdir():
 if not path.name.isdigit() or int(path.name)==os.getpid(): continue
 try: args=path.joinpath('cmdline').read_bytes().split(b'\0')
 except OSError: continue
 if len(args)>=6 and args[0].endswith(b'python3') and args[1]==b'-c' and args[2]==expected and args[-2]==b'8787':
  os.kill(int(path.name),signal.SIGTERM)
'''
        self.docker("exec", node["container"], "python3", "-c", stop, native.FORWARDER)
        self.client_forwarder()
        self.step("same_node_controller_handoff_waiting_actual_confirm")
        self.wait_actual_pairing()

    def wait_actual_pairing(self):
        node = self.nodes["a"]
        local = node["paths"]["state"] / "nodes" / ("node-" + node["node_id"])
        deadline = time.monotonic() + self.args.wait_seconds
        while True:
            if time.monotonic() >= deadline:
                print(json.dumps({"phase": "WAIT_CLIENT", "node_id": node["node_id"], "resources_retained": True, "model_turns": 0}), flush=True)
                deadline = time.monotonic() + self.args.wait_seconds
            state_path = local / "node-control-state.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            if state.get("binding_id") and state.get("binding_version", 0) > 0 and state.get("hub_id") == self.public["hub_id"] and Path(self.args.groups_file).is_file():
                verify_client_fixture(Path(self.args.marker), Path(self.args.public))
                return
            time.sleep(1)

    def build(self):
        self.step("verified_client_binary_readonly_copy")
        self.docker("cp", self.marker["container"] + ":/usr/local/bin/cicada", self.root / "cicada")
        self.root.joinpath("cicada").chmod(0o700)
        self.result["cicada_binary_sha256"] = hashlib.sha256(self.root.joinpath("cicada").read_bytes()).hexdigest()

    def client_forwarder(self):
        node = self.nodes["a"]
        listener = socket.socket()
        listener.bind((node["gateway"], 0))
        listener.listen()
        listener.settimeout(.5)
        self.forwarders.append(listener)
        port = urlsplit(self.public["base_url"]).port
        def pipe(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        def handle(client):
            try:
                upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
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
                threading.Thread(target=handle, args=(client,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        self.docker("exec", "-d", node["container"], "python3", "-c", native.FORWARDER,
                    node["gateway"], str(listener.getsockname()[1]), "8787")

    def prepare_pairing(self):
        self.step("real_node_pq_pairing_pending_client")
        node = self.nodes["a"]
        node["node_id"] = self.run_id + "-monitor"
        self.client_forwarder()
        self.docker("exec", "-d", "-e", "CICADA_CODEX_BIN=" + native.CODEX, "-e", "CODEX_HOME=/codex",
                    "-e", "CICADA_HUB_ID=" + self.public["hub_id"], node["container"], "/bin/sh", "-c",
                    '/out/cicada machine agent --id "$1" --name "Native M4 fixture" --control-url http://127.0.0.1:8787 --state-dir /state --interval 1s --relay-only >>/state/agent.log 2>&1',
                    "sh", node["node_id"])
        local = node["paths"]["state"] / "nodes" / ("node-" + node["node_id"])
        for _ in range(150):
            try:
                state = json.loads(local.joinpath("node-control-state.json").read_text())
                code = state.get("pending_pairing_user_code")
            except (OSError, ValueError):
                code = None
            if code:
                break
            time.sleep(.2)
        else:
            raise RuntimeError("node_pq_pairing_candidate_not_observed")
        handoff = {"schema": "cicada.native-monitor-pairing-handoff.v1", "node_id": node["node_id"], "user_code": code,
                   "hub_id": self.public["hub_id"], "owner_id": self.public["owner_id"], "network_id": self.public["network_id"],
                   "client_confirm_operations": ["nodes.preview", "nodes.confirm"], "container": node["container"],
                   "owned_run_label": self.run_id, "source_revision": REVISION,
                   "group_input_file": str(Path(self.args.groups_file).resolve()),
                   "instruction": "Client confirms exact candidate via its encrypted Owner RPC; do not issue a regroup delegation automatically"}
        native.private_json(self.evidence / "pairing-handoff.json", handoff)
        print(json.dumps({"phase": self.phase, "handoff_file": str(self.evidence / "pairing-handoff.json"), "node_id": node["node_id"]}), flush=True)
        # A pending Owner review is not a terminal fixture failure.
        self.wait_actual_pairing()

    def propose(self):
        self.step("current_node_authority_before_model")
        node = self.nodes["a"]
        probe = r'''import json,sys,urllib.request
from pathlib import Path
node=sys.argv[1]
state=json.loads(Path('/state/nodes/node-'+node+'/node-control-state.json').read_text())
token=Path('/state/nodes/node-'+node+'/relay.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:8787/v2/relay/nodes/'+node+'/events',headers={'Authorization':'CicadaNode '+token,'Accept':'text/event-stream'})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request,timeout=5) as response:
 result={'http_status':response.status,'event_stream':response.headers.get('Content-Type','').startswith('text/event-stream'),'ready':response.readline(128).startswith(b'event: ready'),'hub_id':state.get('hub_id'),'binding_present':bool(state.get('binding_id')),'binding_version_positive':bool(state.get('binding_version',0)>0)}
print(json.dumps(result))
'''
        authority = json.loads(self.docker("exec", node["container"], "python3", "-c", probe, node["node_id"]))
        if authority != {"http_status": 200, "event_stream": True, "ready": True, "hub_id": self.public["hub_id"], "binding_present": True, "binding_version_positive": True}:
            raise RuntimeError("node_current_authority_not_ready_no_model")
        self.result["current_node_authority_before_model"] = authority
        groups = public_file(Path(self.args.groups_file))
        if groups.get("owner_id") != self.public["owner_id"] or groups.get("network_id") != self.public["network_id"]:
            raise RuntimeError("client_group_input_owner_network_mismatch")
        source, target = groups["source_group"], groups["target_group"]
        if any(group.get("state") != "ACTIVE" or not group.get("id") or not isinstance(group.get("version"), int) or group["version"] <= 0 for group in (source, target)):
            raise RuntimeError("client_group_input_not_active_versioned")
        action = groups.get("action", "CREATE_CHILD")
        if action not in ("SET_PARENT", "CREATE_CHILD") or (action == "SET_PARENT" and source["id"] == target["id"]):
            raise RuntimeError("proposal_action_or_target_invalid")
        self.meta["group_id"] = source["id"]
        self.step("zero_model_actual_mcp_startup")
        self.protocol_tools_preflight("a", None, ("cicada_join", "cicada_regroup_propose"))
        self.provider_forwarder(node)
        self.step("native_monitor_original_thread_create")
        marker = "CICADA-M4-ORIGINAL-" + self.run_id
        node["thread"] = self.native_turn("a", f"Remember your original context marker {marker}. You may later propose a grouping change but must never approve it or issue/apply a delegation. Do not use tools now; state the marker and READY.", markers=(marker,))
        self.step("native_monitor_explicit_join")
        self.native_turn("a", "Call cicada_join exactly once with {} using the trusted exact Group configuration. This only joins your current original Thread; do not request or assume a Monitor role. Finish with READY.", node["thread"], ("cicada_join",))
        actor = self.current_actor("a")
        if actor["network_id"] != self.public["network_id"]:
            raise RuntimeError("joined_actor_network_mismatch")
        self.result["native_actor_before"] = actor
        native.private_json(self.evidence / "joined-monitor-handoff.json", {"schema": "cicada.native-monitor-joined.v1", "node_id": node["node_id"], "native_thread_id": node["thread"], **actor,
            "source_group": source, "target_group": target, "owner_id": self.public["owner_id"],
            "client_instruction": "Independently authorize Monitor role and exact target Group admission with existing encrypted topology RPC; do not issue a delegation without user approval",
            "ready_file": str(self.evidence / "monitor-ready.json")})
        print(json.dumps({"phase": "client_monitor_authority_pending", "handoff_file": str(self.evidence / "joined-monitor-handoff.json")}), flush=True)
        deadline = time.monotonic() + self.args.wait_seconds
        ready_path = self.evidence / "monitor-ready.json"
        while not ready_path.is_file() and time.monotonic() < deadline:
            time.sleep(1)
        if not ready_path.is_file():
            raise RuntimeError("independent_client_monitor_authority_not_ready")
        ready = public_file(ready_path)
        if ready.get("endpoint_id") != actor["endpoint_id"] or ready.get("owner_id") != self.public["owner_id"]:
            raise RuntimeError("independent_monitor_ready_scope_mismatch")
        # Fresh versions supplied by the Client after any role/admission change.
        fresh_source, fresh_target = ready["source_group"], ready["target_group"]
        for old, fresh in ((source, fresh_source), (target, fresh_target)):
            if fresh.get("id") != old["id"] or fresh.get("state") != "ACTIVE" or not isinstance(fresh.get("version"), int) or fresh["version"] < old["version"]:
                raise RuntimeError("fresh_client_monitor_group_scope_or_version_mismatch")
        source, target = fresh_source, fresh_target
        arguments = {"network_id": self.public["network_id"], "target_group_id": target["id"], "action": action,
                     "expected_source_version": source["version"], "expected_target_version": target["version"],
                     "idempotency_key": self.run_id + "-proposal"}
        if action == "CREATE_CHILD":
            arguments["new_group_name"] = "Explicit native Monitor proposal (not approved)"
        self.step("native_monitor_propose_only")
        self.native_turn("a", "Call cicada_regroup_propose exactly once with these exact arguments: " + json.dumps(arguments) + ". Do not call cicada_regroup_apply or any delegation/approval tool. State your original context marker after the proposal returns.", node["thread"], ("cicada_regroup_propose",), (marker,))
        events = native.parse_events((self.evidence / "native-native_monitor_propose_only-a.jsonl.private").read_bytes())
        proposals = []
        def inspect(value):
            if isinstance(value, dict):
                if isinstance(value.get("regroup_proposal"), dict):
                    proposals.append(value["regroup_proposal"])
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)
            elif isinstance(value, str):
                try:
                    decoded = json.loads(value)
                except ValueError:
                    return
                if isinstance(decoded, (dict, list)):
                    inspect(decoded)
        for event in events:
            if event.get("type") == "item.completed" and (event.get("item") or {}).get("type") == "mcp_tool_call":
                inspect(event["item"].get("result"))
        proposals = list({json.dumps(proposal, sort_keys=True): proposal for proposal in proposals}.values())
        if len(proposals) != 1:
            raise RuntimeError("native_proposal_result_not_unique")
        proposal = proposals[0]
        if proposal.get("state") != "PROPOSED" or proposal.get("owner_id") != self.public["owner_id"] or proposal.get("endpoint_id") != actor["endpoint_id"] or proposal.get("delegation"):
            raise RuntimeError("native_proposal_scope_or_authority_mismatch")
        expected_input = {"operation_id": arguments["idempotency_key"], "network_id": arguments["network_id"],
                          "source_group_id": source["id"], "target_group_id": target["id"], "action": action,
                          "expected_source_version": source["version"], "expected_target_version": target["version"]}
        if any(proposal.get("input", {}).get(key) != value for key, value in expected_input.items()):
            raise RuntimeError("native_proposal_exact_input_mismatch")
        self.result["native_actor_after"] = self.current_actor("a")
        if self.result["native_actor_after"]["endpoint_id"] != actor["endpoint_id"] or self.result["native_actor_after"]["binding_id"] != actor["binding_id"]:
            raise RuntimeError("monitor_original_binding_changed")
        native.private_json(self.evidence / "native-proposal-public.json", proposal)
        self.result["proposal_id"] = proposal["proposal_id"]
        self.result["owner_review_operation"] = "topology.regroup_proposal"
        self.result["delegation_issue_or_apply_called"] = False
        self.result["status"] = "NATIVE_PROPOSE_PASS_OWNER_REVIEW_PENDING"
        self.result["cleanup_pending_owner_review"] = True
        native.private_json(self.evidence / "proposal-checkpoint.json", self.result)
        review_path = self.evidence / "owner-review-complete.json"
        print(json.dumps({"phase": "WAIT_OWNER_REVIEW", "proposal_file": str(self.evidence / "native-proposal-public.json"),
                          "proposal_id": proposal["proposal_id"], "cleanup_receipt_file": str(review_path), "resources_retained": True}), flush=True)
        deadline = time.monotonic() + self.args.wait_seconds
        while True:
            if review_path.exists():
                review = public_file(review_path)
                expected = {"hub_id": self.public["hub_id"], "owner_id": self.public["owner_id"],
                            "node_id": node["node_id"], "proposal_id": proposal["proposal_id"], "cleanup_authorized": True}
                if any(review.get(key) != value for key, value in expected.items()):
                    raise RuntimeError("owner_review_cleanup_receipt_scope_mismatch")
                self.result["cleanup_pending_owner_review"] = False
                self.result["owner_review_lifecycle_receipt"] = str(review_path)
                # This receipt authorizes fixture cleanup only; it is not a
                # delegation proof or an assertion that topology was applied.
                return
            if time.monotonic() >= deadline:
                print(json.dumps({"phase": "WAIT_OWNER_REVIEW", "resources_retained": True, "extra_model_turns": 0}), flush=True)
                deadline = time.monotonic() + self.args.wait_seconds
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--public", required=True)
    parser.add_argument("--groups-file", required=True, help="private public-DTO input supplied independently by Client/Root")
    parser.add_argument("--result-dir", required=True)
    parser.add_argument("--runtime-image", default=native.RUNTIME)
    parser.add_argument("--credential-file", default="/gpu1-share/data/cicada/secrets/cicada.env")
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--wait-seconds", type=int, default=3600)
    parser.add_argument("--takeover-owned-pairing", help="adopt a preserved same-Node fixture after its previous controller has exited")
    args = parser.parse_args()
    gate = AttachGate(args)
    try:
        gate.build()
        if args.takeover_owned_pairing:
            gate.take_over_pairing(args.takeover_owned_pairing)
        else:
            gate.start_nodes()
            gate.prepare_pairing()
        if args.run_native:
            gate.propose()
        else:
            gate.result["status"] = "PAIRED_NATIVE_PROPOSAL_NOT_RUN"
    except Exception as error:
        gate.result["failure_phase"] = gate.phase
        gate.result["failure_class"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        gate.cleanup()
    print(json.dumps({"status": gate.result["status"], "result": str(gate.evidence / "result.json")}), flush=True)
    return 0 if gate.result["status"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
