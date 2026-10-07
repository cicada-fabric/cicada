"""Narrow ZERO-PAID wiring guards. No Runtime, credential metadata or provider traffic."""
import ast
import copy
import hashlib
import io
import json
import sys
import types
import threading
import base64
import contextlib
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import queue
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import request_observer_run as run
import request_observer_gate as gate
import request_observer_bootstrap as bootstrap


class WiringChecks(unittest.TestCase):
    def test_binding_rows_and_active_alias_refuse_stale_metadata(self):
        """Metadata inconsistencies are refused before source imports or external effects."""
        with run.deny_preflight_effects():
            current,raw=run.bounded_json(run.BINDING)
            original=run.bounded_json
            cases=[]
            stale=copy.deepcopy(current);stale["files"][0]["sha256"]="0"*64;cases.append(("stale",stale,False))
            duplicate=copy.deepcopy(current);duplicate["files"].append(copy.deepcopy(duplicate["files"][0]));cases.append(("duplicate",duplicate,False))
            missing=copy.deepcopy(current);missing["files"].pop();cases.append(("missing",missing,False))
            extra=copy.deepcopy(current);extra["files"].append(dict(extra["files"][0],path="/synthetic/extra"));cases.append(("extra",extra,False))
            cases.append(("alias",copy.deepcopy(current),True))
            for label,binding,bad_alias in cases:
                with self.subTest(case=label):
                    changed=(json.dumps(binding,sort_keys=True)+"\n").encode()
                    def read(path):
                        if Path(path)==run.BINDING:return binding,changed
                        if Path(path)==run.BINDING.parent/"source-binding.json":return binding,(raw if bad_alias else changed)
                        return original(path)
                    with patch.object(run,"bounded_json",side_effect=read),patch.object(run,"required_paths",side_effect=AssertionError("LATE_VALIDATION_REACHED")):
                        with self.assertRaisesRegex(ValueError,"^(SOURCE_ROWS_INCONSISTENT|ACTIVE_SOURCE_BINDING_ALIAS)$"):
                            run.verify_binding()
            accepted,sha=run.verify_binding()
            self.assertEqual(accepted,current)
            self.assertEqual(sha,hashlib.sha256(raw).hexdigest())

    def test_a2_submission_supplements_original_task_without_oracle_change(self):
        """Only one trusted instruction changes; the actual strict witness still rejects omission."""
        with run.deny_preflight_effects():
            current = gate.effective_sources()
            with patch.object(gate, "A2_SUBMISSION_INSTRUCTION", gate.A2_LEGACY_INSTRUCTION):
                prior = gate.effective_sources()
            self.assertEqual(current["gate"].replace(gate.A2_SUBMISSION_INSTRUCTION,
                gate.A2_LEGACY_INSTRUCTION), prior["gate"])
            self.assertEqual({k:v for k,v in current.items() if k!="gate"},
                {k:v for k,v in prior.items() if k!="gate"})
            self.assertNotIn("ALPHA", gate.A2_SUBMISSION_INSTRUCTION)
            self.assertNotIn("BETA", gate.A2_SUBMISSION_INSTRUCTION)
            self.assertIn(ast.dump(ast.parse('json.dumps(self.nodes["b"]["endpoint"])', mode="eval").body),
                ast.dump(ast.parse(current["gate"])))
            self.assertIn(ast.dump(ast.parse("json.dumps(question)", mode="eval").body),
                ast.dump(ast.parse(current["gate"])))
            binding,_=run.verify_binding()
            delivery=run.bounded_json(run.BINDING.parent.parent/"native-observer-runtime-161-20261007"/"cicada-product826-pq-20261007a"/"actual-delivery.NONAUTH.json")[0]
            candidate,legacy=gate.load_gate(delivery,binding,inspect_only=True)
            audit=candidate.audit_turn
            closure=dict(zip(audit.__code__.co_freevars, (cell.cell_contents for cell in audit.__closure__)))
            witness=closure["original_audit_turn"].__globals__["base"].turn_witness
            thread="00000000-0000-4000-8000-000000000001"
            events=[{"type":"thread.started","thread_id":thread},
                    {"type":"item.completed","item":{"type":"agent_message","text":"SYNTHETIC_BETA exact-answer"}}]
            with self.assertRaisesRegex(RuntimeError,"^original_context_witness_missing$"):
                witness(events,expected_thread=thread,markers=("SYNTHETIC_ALPHA","SYNTHETIC_BETA","exact-answer"))
            events[-1]["item"]["text"]="SYNTHETIC_ALPHA SYNTHETIC_BETA exact-answer"
            self.assertTrue(witness(events,expected_thread=thread,
                markers=("SYNTHETIC_ALPHA","SYNTHETIC_BETA","exact-answer"))["same_original_thread"])

    def test_latest_zero_helper_registration(self):
        """Actual inherited helper argv: prior rejection and finite owned admission."""
        old_source='def register_submission(self, argv):\n            if (zero_model or getattr(self.args,"latest_runtime",False)) and argv[:2] in (["docker","run"],["docker","create"]) and self.args.runtime_image in argv:\n                if argv.count(self.args.runtime_image)!=1 or "--name" not in argv or "org.cicada.test.run="+self.run_id not in argv:\n                    raise RuntimeError("ZERO_RUNTIME_OWNERSHIP")\n                name=argv[argv.index("--name")+1]\n                if name not in (self.run_id+"-a",self.run_id+"-b"):\n                    raise RuntimeError("ZERO_RUNTIME_NAME")\n                key=("container",name)\n                self.submitted_objects[key]={"name":name,"id":None,"image":self.args.runtime_image,\n                    "run_id":self.run_id,"auto_remove":"--rm" in argv,"command_exit":None}\n                self.containers[name]=self.args.runtime_image\n                return key\n            return super().register_submission(argv)'
        namespace={"zero_model":True}
        exec(compile("class Prior:\n"+"\n".join("    "+line for line in old_source.splitlines()),"<public-prior-register>","exec"),namespace)
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.BINDING.parent.parent/"native-observer-runtime-161-20261007"/"cicada-product826-pq-20261007a"/"actual-delivery.NONAUTH.json")
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,zero_model=True)
            fixture=object.__new__(cls)
            fixture.args=types.SimpleNamespace(runtime_image=run.LATEST_RUNTIME,latest_runtime=True)
            fixture.run_id="cicada-two-turn-zerocli161-synthetic"
            fixture.root=Path("/synthetic-zero-fixture")
            fixture.native_package=Path("/synthetic-public-package")
            fixture.test_image=run.LATEST_RUNTIME
            fixture.submitted_objects={};fixture.containers={}
            captured=[]
            fixture.command=lambda argv,**kwargs:captured.append(argv) or (0,b"",b"")
            for action in ("bootstrap","tls-bootstrap"):
                fixture.helper(action)
                argv=captured[-1]
                with self.subTest(prior=action),self.assertRaisesRegex(RuntimeError,"ZERO_RUNTIME_NAME"):
                    namespace["Prior"].register_submission(fixture,argv)
                key=fixture.register_submission(argv)
                self.assertEqual(key,("container",fixture.run_id+"-helper-"+action))
                self.assertEqual(fixture.submitted_objects[key]["image"],run.LATEST_RUNTIME)
                self.assertTrue(fixture.submitted_objects[key]["auto_remove"])
                for flag,value in (("--name",fixture.run_id+"-helper-unknown"),
                    ("--label","org.cicada.test.run=other"),("--network","host"),
                    ("--entrypoint","/fixture/other")):
                    bad=list(argv);bad[bad.index(flag)+1]=value
                    with self.subTest(denial=flag),self.assertRaises(RuntimeError):fixture.register_submission(bad)
                bad=list(argv);bad[bad.index("--name")+1]=fixture.run_id+"-c"
                with self.assertRaises(RuntimeError):fixture.register_submission(bad)
                bad=list(argv)+["/run/secrets/provider.env"]
                with self.assertRaises(PermissionError):fixture.register_submission(bad)
                bad=list(argv);bad[bad.index(run.LATEST_RUNTIME)]="sha256:"+"0"*64
                with self.assertRaises(RuntimeError):fixture.register_submission(bad)

            fixture.hub=fixture.run_id+"-hub"
            for letter in "ab":
                argv=["docker","run","--rm","--pull=never","--name",fixture.run_id+"-helper-isolation-"+letter,
                    "--label","org.cicada.test.run="+fixture.run_id,"--network","container:"+fixture.hub,
                    "--user","1000:1000","-v",str(fixture.root)+":/fixture:ro",
                    "-v",str(fixture.native_package)+":/opt/cicada-pqtls:ro",
                    "-e","LD_LIBRARY_PATH=/opt/cicada-pqtls/lib","-e","OPENSSL_CONF=/dev/null",
                    "--entrypoint","/fixture/cicada-v68fixture",run.LATEST_RUNTIME,"probe","--address","192.0.2.1:19437"]
                with self.assertRaisesRegex(RuntimeError,"ZERO_RUNTIME_NAME"):
                    namespace["Prior"].register_submission(fixture,argv)
                self.assertEqual(fixture.register_submission(argv),("container",fixture.run_id+"-helper-isolation-"+letter))
                bad=list(argv);bad[bad.index("--network")+1]="container:other"
                with self.assertRaises(RuntimeError):fixture.register_submission(bad)
                bad=list(argv);bad[bad.index(run.LATEST_RUNTIME)+1]="bootstrap"
                with self.assertRaises(RuntimeError):fixture.register_submission(bad)

            paid_cls,_=gate.load_gate(delivery,binding,inspect_only=True,zero_model=False)
            paid=object.__new__(paid_cls)
            paid.args=fixture.args;paid.run_id=fixture.run_id;paid.root=fixture.root
            paid.native_package=fixture.native_package;paid.test_image=fixture.test_image
            paid.submitted_objects={};paid.containers={}
            approve=[]
            paid.command=lambda argv,**kwargs:approve.append(argv) or b""
            paid.helper("approve")
            argv=approve[0]
            self.assertEqual(paid.register_submission(argv),("container",paid.run_id+"-helper-approve"))
            with self.assertRaisesRegex(RuntimeError,"ZERO_RUNTIME_NAME"):fixture.register_submission(argv)

    def test_zero_agent_bootstrap_credential_free_exact_launch(self):
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,zero_model=True)
            fixture=object.__new__(cls)
            fixture.nodes={"a":{"container":"synthetic-a","gateway":"192.0.2.1","hub_port":"8443",
                "tls_config":"/fixture/synthetic-tls.json","node_id":"synthetic-node"}}
            fixture.meta={"hub_id":"synthetic-hub"};fixture.result={}
            calls=[]
            class BoundaryReached(Exception):pass
            def boundary(argv,**kwargs):
                calls.append(argv)
                if len(calls)==2:raise BoundaryReached()
                return b""
            fixture.command=boundary
            candidate_docker=cls.docker.__get__(fixture,cls)
            forwarder=fixture.start_services.__globals__["FORWARDER"]
            def synthetic_external_boundary(*arguments,**kwargs):
                if forwarder in arguments:
                    # Exact first launch's file-copy/target setup is external fixture I/O.
                    calls.append(["docker",*arguments])
                    return b""
                return candidate_docker(*arguments,**kwargs)
            fixture.docker=synthetic_external_boundary
            with self.assertRaises(BoundaryReached):fixture.start_services("a")
            agent=calls[1];program=agent[agent.index("python3")+2]
            self.assertEqual(program,gate.ZERO_AGENT_BOOTSTRAP)
            self.assertNotIn("/run/secrets/",program);self.assertNotIn("API_KEY",program)
            original=fixture.start_services.__globals__["AGENT_BOOTSTRAP"]
            self.assertIn("/run/secrets/provider.env",original)
            count=len(calls)
            bad=agent[1:];bad[bad.index("python3")+2]=original+"\n# near miss"
            with self.assertRaises(PermissionError):fixture.docker(*bad)
            self.assertEqual(len(calls),count)
            self.assertFalse(fixture.result["zero_agent_bootstrap"]["a"]["credential_access"])

    def test_zero_installed_managed_rpc_initialize_and_send_guard(self):
        """Real ManagedRPC/TypedRPC audit closure; only socket transport is synthetic."""
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,zero_model=True)
            source_namespace=cls.start_managed_servers.__globals__
            actual_config=source_namespace["base"].isolated_runtime_config(run.ZERO_CONFIG)
            self.assertIn('approval_policy = "never"',actual_config)
            self.assertIn('request_max_retries = 0',actual_config)
            self.assertIn('stream_max_retries = 0',actual_config)
            self.assertIn('model = "gpt-5.6-luna"',actual_config)
            rpc_class=source_namespace["ManagedRPC"]
            fixture=object.__new__(cls)
            fixture.audit_lock=threading.Lock();fixture.audit_bytes={}
            fixture.audit_files={"a":io.StringIO()};fixture.projection_files={"a":io.StringIO()}
            fixture.result={"actual_turn_started_event_count":0};fixture.nodes={};fixture.audit_counts={};fixture.managed_diagnostics={}
            fixture.root=Path("/synthetic-zero-fixture");fixture.phase="synthetic_initialize";fixture.args=types.SimpleNamespace(run_native=False)
            fixture.budget=types.SimpleNamespace(threads={},started=[],completed=[])
            aborts=[];sent=[]
            class LocalClient:
                def __init__(self):self.responses=queue.Queue();self.last_received_bytes=None;self.closed=False
                def send_obj(self,message):
                    sent.append(message)
                    if "id" in message:self.responses.put({"id":message["id"],"result":{"synthetic":True}})
                def recv_obj(self,timeout=.2):
                    if self.closed:raise EOFError()
                    try:value=self.responses.get(timeout=timeout)
                    except queue.Empty:raise TimeoutError()
                    self.last_received_bytes=json.dumps(value).encode();return value
                def close(self):self.closed=True
            client=LocalClient();wire_bytes=[]
            class MemoryWire(io.BytesIO):
                def close(self):
                    if not self.closed:wire_bytes.append(self.getvalue())
                    super().close()
            expected_wire=fixture.root/"managed-a-wire-0001.raw"
            def synthetic_open(path,flags,mode=0o777,*unused,**keywords):
                if Path(path)!=expected_wire or flags!=(os.O_WRONLY|os.O_CREAT|os.O_EXCL) or mode!=0o600:
                    raise PermissionError("NON_SYNTHETIC_WIRE_IO")
                return 900001
            def synthetic_fdopen(fd,mode,*unused,**keywords):
                if fd!=900001 or mode!="wb":raise PermissionError("NON_SYNTHETIC_WIRE_FD")
                return MemoryWire()
            module=sys.modules[rpc_class.__module__]
            with patch.object(module,"WSUnixClient",return_value=client),patch.object(os,"open",synthetic_open),patch.object(os,"fdopen",synthetic_fdopen):
                rpc=rpc_class("SYNTHETIC_NO_SOCKET","a",lambda *unused:None,fixture.audit_rpc,
                    aborts.append,lambda seconds:min(seconds,2))
                try:
                    self.assertEqual(rpc.request("initialize",{"clientInfo":{"name":"synthetic","version":"0"}}),{"synthetic":True})
                    self.assertIsNone(rpc.error)
                    before=len(sent)
                    with self.assertRaises(RuntimeError):rpc.request("turn/start",{})
                    self.assertEqual(len(sent),before)
                    self.assertEqual(len(aborts),1)
                    journal=[json.loads(line) for line in fixture.audit_files["a"].getvalue().splitlines()]
                    self.assertEqual([row["direction"] for row in journal],["sent","received"])
                    self.assertEqual(journal[0]["message"]["method"],"initialize")
                    self.assertEqual(journal[0]["message"]["id"],1)
                    self.assertEqual(journal[1]["message"],{"id":1,"result":{"synthetic":True}})
                    projection=[json.loads(line) for line in fixture.projection_files["a"].getvalue().splitlines()]
                    self.assertEqual(projection[1]["message_sha256"],hashlib.sha256(client.last_received_bytes).hexdigest())
                    self.assertEqual(projection[1]["message_size"],len(client.last_received_bytes))
                finally:rpc.close()
                self.assertFalse(rpc.reader.is_alive())
                self.assertTrue(rpc.closed)
                self.assertEqual(fixture.audit_counts,{"a":1})
                self.assertEqual(len(wire_bytes),1)
                self.assertEqual(json.loads(wire_bytes[0]),{"id":1,"result":{"synthetic":True}})

    def test_latest_zero_lane_public_guards(self):
        """Pure public inputs only; no fixture constructor or external operations."""
        sha="a"*64
        delivery={key:sha for key in ("commit","fingerprint","binary_sha256","helper_sha256",
            "package_metadata_sha256","hub_receipt_sha256")}
        delivery.update(hub_image="sha256:"+sha,package="/synthetic/package",helper="/synthetic/helper",
            hub_receipt_path="/synthetic/hub-receipt",source_repo="/synthetic/source")
        equality={"status":"COMPILED_INPUTS_EXACT","current_commit":"b"*40,
            "artifact_compiled_inputs_sha256":sha,"current_compiled_inputs_sha256":sha,
            "artifact_binary_sha256":sha}
        receipt={"status":"PASS","candidate_binding_sha256":sha,"Runtime_calls":0,"model_calls":0}
        raw=b"public synthetic"
        args=types.SimpleNamespace(execute_diagnostic=False,enable_io_diagnostics=False,
            unique_run="cicada-two-turn-zerocli161-20261007a",runtime_image=run.LATEST_RUNTIME,
            cleanup_hard_stop_unix=10000,binding_sha=sha,wiring_receipt="receipt",
            wiring_receipt_sha=hashlib.sha256(raw).hexdigest(),delivery="delivery",
            delivery_sha=hashlib.sha256(raw).hexdigest(),compiled_input_equality="equality",
            equality_sha=hashlib.sha256(raw).hexdigest(),current_commit="b"*40,
            result_dir=str(run.BINDING.parent/"native-preparation-cicada-two-turn-zerocli161-20261007a"))
        original_bounded_json=run.bounded_json
        def read(path,*unused):
            if str(path)==run.CREDENTIAL:return original_bounded_json(path)
            return {"receipt":receipt,"delivery":delivery,"equality":equality}[str(path)],raw
        with run.deny_preflight_effects(),patch.object(run,"verify_binding",return_value=({},sha)),             patch.object(run,"bounded_json",side_effect=read),patch.object(run,"digest",return_value=sha),             patch.object(run.time,"time",return_value=1000),patch.object(Path,"exists",return_value=False):
            self.assertEqual(run.zero_inputs(args)[2],delivery)
            for key,value in (("execute_diagnostic",True),("runtime_image",run.RUNTIME),
                              ("cleanup_hard_stop_unix",1100),("unique_run","old-run"),("delivery",run.CREDENTIAL)):
                changed=copy.copy(args);setattr(changed,key,value)
                with self.subTest(guard=key),self.assertRaises(PermissionError):run.zero_inputs(changed)
            equality["artifact_compiled_inputs_sha256"]="c"*64
            with self.assertRaises(PermissionError):run.zero_inputs(args)
        # Preparation alone never permits paid dispatch; missing proof stops before public reads.
        with run.deny_preflight_effects(),patch.object(run,"bounded_json",side_effect=AssertionError("NO_PREP_READ")):
            with self.assertRaisesRegex(PermissionError,"LATEST_RUNTIME_NOT_READY"):
                run.execute(types.SimpleNamespace(preparation_result=None,preparation_result_sha=None))
        for argv in (["docker","exec","owned","paid"],
                     ["docker","run","--mount","src=/gpu1-share/synthetic,dst=/run/secrets/provider.env"],
                     ["docker","exec","owned","turn/start"]):
            with self.subTest(argv_guard=True),self.assertRaises(PermissionError):gate.validate_zero_command(argv)
        gate.validate_zero_command(["docker","exec","owned","python3","/state/server_bootstrap.py","offline"])

    def test_client_read_reset_connection_scope_and_rails(self):
        """Actual pinned relay/installed policy, deterministic socket doubles only."""
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
            candidate,_=gate.load_gate(delivery,binding,inspect_only=True)
            original=candidate.provider_forwarder.__globals__["Forwarder"]
            run_id="cicada-two-turn-syntheticforwarder01"
            record={"run_id":run_id,"network_id":"a"*64,"network_name":run_id+"-a-net",
                "network_label":run_id,"driver":"bridge","subnet":"172.29.0.0/24","gateway":"172.29.0.1",
                "clients":["172.29.0.2"],"lifetime":10,"max_connections":4,"max_active":1,
                "upstream_host":"127.0.0.1","upstream_port":7890}
            actual={"Id":"a"*64,"Name":record["network_name"],"Driver":"bridge",
                "Labels":{"org.cicada.test.run":run_id},"IPAM":{"Config":[{"Subnet":record["subnet"],"Gateway":record["gateway"]}]},
                "Containers":{"b"*64:{"IPv4Address":"172.29.0.2/24"}}}
            class Sock:
                def __init__(self,events=(),send_error=None):self.events=list(events);self.closed=False;self.send_error=send_error
                def setblocking(self,value):pass
                def recv(self,n):
                    value=self.events.pop(0) if self.events else b""
                    if isinstance(value,BaseException):raise value
                    return value
                def send(self,data):
                    if self.send_error is not None:raise self.send_error
                    return len(data)
                def shutdown(self,how):pass
                def close(self):self.closed=True
            def create(client,upstream,owned=True):
                def select_ready(readers,writers,errors,timeout):
                    if writers:return [],writers,[]
                    return ([client] if client in readers else [upstream] if upstream in readers else []),[],[]
                value=original(record,actual,clock=lambda:0,connect=lambda *a,**k:upstream,select_ready=select_ready)
                if owned:gate.install_client_read_cancellation(value)
                self.assertTrue(value.admit(client,("172.29.0.2",50000)))
                return value
            def policy(value):
                owner=object.__new__(candidate)
                owner.cleaning=False;owner.aborted=False;owner.provider_errors={};owner.provider_adapters={"synthetic":value}
                owner.policy=types.SimpleNamespace(limit=lambda maximum:maximum)
                return owner
            legacy=create(Sock([ConnectionResetError(104,"PUBLIC_SYNTHETIC")]),Sock(),False)
            legacy.relay(next(iter(legacy.sockets)))
            self.assertEqual(legacy.failures,1)
            with self.assertRaises(RuntimeError):policy(legacy).limit(1)
            client=Sock([ConnectionResetError(104,"PUBLIC_SYNTHETIC")]);up=Sock()
            fixed=create(client,up);fixed.relay(client)
            self.assertEqual((fixed.failures,fixed.client_read_cancellations,fixed.active),(0,1,0))
            self.assertFalse(fixed.closed);self.assertTrue(client.closed and up.closed)
            self.assertEqual(policy(fixed).limit(1),1)
            self.assertEqual(fixed.owned_client_read_relay_sha256,binding["client_read_cancellation"]["relay_sha256"])
            self.assertEqual(fixed.summary()["last_client_read_cancellation"]["application_completion"],"UNKNOWN")
            second=Sock();second_up=Sock();fixed.connect=lambda *a,**k:second_up
            fixed.select_ready=lambda readers,writers,errors,timeout: (([second] if second in readers else [second_up] if second_up in readers else []),writers,[])
            self.assertTrue(fixed.admit(second,("172.29.0.2",50001)));fixed.relay(second)
            self.assertEqual((fixed.accepted,fixed.failures,fixed.clean_eof_disconnects,fixed.active),(2,0,1,0))
            class ResetSubclass(ConnectionResetError):pass
            for label,client_events,up_events,send_error in (
                ("upstream_reset",[b""],[ConnectionResetError(104,"PUBLIC_SYNTHETIC")],None),
                ("other_errno",[ConnectionResetError(111,"PUBLIC_SYNTHETIC")],[],None),
                ("subclass",[ResetSubclass(104,"PUBLIC_SYNTHETIC")],[],None),
                ("send_client_reset",[b""],[b"PUBLIC_SYNTHETIC"],ConnectionResetError(104,"PUBLIC_SYNTHETIC"))):
                with self.subTest(fatal=label):
                    client=Sock(client_events,send_error);value=create(client,Sock(up_events));value.relay(client)
                    self.assertEqual((value.failures,value.client_read_cancellations),(1,0))
                    with self.assertRaises(RuntimeError):policy(value).limit(1)
            client=Sock([b""] ,BrokenPipeError(32,"PUBLIC_SYNTHETIC"));value=create(client,Sock([b"PUBLIC_SYNTHETIC"]));value.relay(client)
            self.assertEqual((value.failures,value.client_write_cancellations,value.client_read_cancellations),(0,1,0))
            for rail in ("acl","active","quota","deadline","closed"):
                with self.subTest(rail=rail):
                    value=original(record,actual,clock=lambda:0);gate.install_client_read_cancellation(value)
                    if rail=="active":value.active=1
                    if rail=="quota":value.accepted=4
                    if rail=="deadline":value.deadline=0
                    if rail=="closed":value.closed=True
                    rejected=Sock();address="172.29.0.3" if rail=="acl" else "172.29.0.2"
                    self.assertFalse(value.admit(rejected,(address,50002)));self.assertTrue(rejected.closed)
            class Listener(Sock):
                def bind(self,address):pass
                def listen(self,count):pass
                def settimeout(self,seconds):pass
                def getsockname(self):return ("172.29.0.1",12345)
                def accept(self):raise OSError(5,"PUBLIC_SYNTHETIC")
            listener=Listener();value=original(record,actual,clock=lambda:0,socket_factory=lambda *a:listener)
            gate.install_client_read_cancellation(value);value.open()
            with self.assertRaises(OSError):value.serve()
            self.assertTrue(value.closed and listener.closed)
            # Remove ONLY the inserted branch: all remaining relay AST is identical.
            raw=ast.parse((gate.OLD/"provider_transport.py").read_bytes())
            cls=next(n for n in raw.body if isinstance(n,ast.ClassDef) and n.name=="Forwarder")
            old=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=="relay")
            new=ast.parse(gate.client_read_cancellation_relay_source()).body[0]
            outer=next(n for n in new.body if isinstance(n,ast.Try));branch=outer.handlers[0].body[-1]
            cancellation=branch.orelse[0]
            self.assertIn("type(error) is ConnectionResetError",ast.unparse(cancellation.test))
            branch.orelse=cancellation.orelse
            self.assertEqual(ast.dump(new),ast.dump(old))

    def test_default_off_no_file_or_legacy_access(self):
        def deny(*args,**kwargs):
            raise AssertionError("DEFAULT_OFF_EFFECT")
        output=io.StringIO()
        with patch.object(Path,"open",deny),patch.object(Path,"lstat",deny),patch.object(run,"safe_overlay",deny),redirect_stdout(output):
            self.assertEqual(run.main([]),0)
            self.assertEqual(bootstrap.main(["shim"]),0)
        records=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(all(row["status"]=="NONAUTH" and row["effects"] is False for row in records))

    def test_execute_without_fresh_go_has_no_public_or_credential_access(self):
        def deny(*args,**kwargs):
            raise AssertionError("UNAUTHORIZED_EFFECT")
        with patch.object(run,"verify_binding",deny),patch.object(Path,"lstat",deny),redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--execute-diagnostic"]),2)
        self.assertFalse(run.EXECUTION_EFFECTS_STARTED)

    def test_expired_wrong_typed_go_and_cutoff(self):
        binding,binding_sha=run.verify_binding()
        expected=run.expected_go(binding,binding_sha,"cicada-two-turn-observer20261004nonauth","0"*64,10000)
        expired=dict(expected,expires_at_unix=0)
        with self.assertRaises(PermissionError):
            run.validate_go(expired,expected,now=1)
        wrong=dict(expected,expires_at_unix=10000)
        wrong["runtime_execution_authorized"]=1
        with self.assertRaises(PermissionError):
            run.validate_go(wrong,expected,now=10000-241)
        nested=copy.deepcopy(wrong)
        nested["runtime_execution_authorized"]=True
        nested["test_request_observer"]["default_off"]=1
        with self.assertRaises(PermissionError):
            run.validate_go(nested,expected,now=10000-241)
        with self.assertRaises(PermissionError):
            run.validate_go(dict(expected,expires_at_unix=10000),expected,now=10000-239)

    def test_expired_go_rejected_before_credential_stat_or_claim(self):
        binding,binding_sha=run.verify_binding()
        run_id="cicada-two-turn-observer20261004nonauth"
        expected=run.expected_go(binding,binding_sha,run_id,"0"*64,10000)
        expired=dict(expected,expires_at_unix=0)
        raw=json.dumps(expired).encode()
        receipt={"status":"PASS","candidate_binding_sha256":binding_sha,"Runtime_calls":0,"provider_POSTs":0,"model_calls":0}
        receipt_raw=json.dumps(receipt).encode()
        wiring_sha=hashlib.sha256(receipt_raw).hexdigest()
        expected=run.expected_go(binding,binding_sha,run_id,wiring_sha,10000)
        expired=dict(expected,expires_at_unix=0)
        raw=json.dumps(expired).encode()
        args=types.SimpleNamespace(go_receipt=str(run.BINDING.parent/"request-observer-synthetic-expired.json"),
            go_receipt_sha=hashlib.sha256(raw).hexdigest(),binding_sha=binding_sha,
            wiring_receipt=str(run.BINDING.parent/"request-observer-wiring-synthetic.json"),wiring_receipt_sha=wiring_sha,unique_run=run_id,enable_io_diagnostics=True,cleanup_hard_stop_unix=10000)
        with patch.object(run,"verify_binding",return_value=(binding,binding_sha)),patch.object(run,"expected_go",return_value=expected),\
             patch.object(run,"bounded_json",side_effect=[(receipt,receipt_raw),(expired,raw)]),\
             patch.object(Path,"lstat",side_effect=AssertionError("CREDENTIAL_STAT_OR_CLAIM_FORBIDDEN")):
            with self.assertRaises(PermissionError):
                run.execute(args)
        self.assertFalse(run.EXECUTION_EFFECTS_STARTED)

    def test_shared_absolute_policy_never_resets(self):
        policy=types.SimpleNamespace()
        gate.bind_policy(policy,1000.0)
        with patch.object(gate.time,"monotonic",return_value=1170.0):
            self.assertEqual(policy.limit(500),10.0)
            policy.terminal()
            self.assertEqual(policy.limit(500),40.0)
            policy.terminal()
            self.assertEqual(policy.limit(500),40.0)
            policy.cleanup()
            self.assertEqual(policy.limit(500),70.0)
            policy.terminal()
            self.assertEqual(policy.phase,"cleanup")
        with patch.object(gate.time,"monotonic",return_value=1240.0):
            with self.assertRaises(TimeoutError):
                policy.limit(1)
        self.assertEqual((policy.started,policy.total,policy.terminal_end,policy.cleanup_end),(1000.0,240,1210.0,1240.0))

    def test_overlay_changes_only_provider_deadlines_and_owned_relay_install(self):
        source=gate.effective_sources()["provider"]
        tree=ast.parse((gate.OLD/"migration.py").read_text())
        install=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="install")
        original=next(node for node in install.body if isinstance(node,ast.FunctionDef) and node.name=="provider")
        changed=0
        for node in ast.walk(original):
            if isinstance(node,ast.Constant) and type(node.value) is int and node.value==240:
                node.value=180;changed+=1
        self.assertEqual(changed,2)
        setup=next(n for n in original.body if isinstance(n,ast.Assign) and
            any(isinstance(t,ast.Name) and t.id=="adapter" for t in n.targets))
        original.body.insert(original.body.index(setup)+1,ast.parse("_install_client_read_cancellation(adapter)").body[0])
        self.assertEqual(ast.dump(ast.parse(source).body[0]),ast.dump(original))
        self.assertIn("self.created_networks",source)
        self.assertIn("'max_connections': 16",source)
        self.assertIn("'clients'",source)
        effective=gate.effective_sources()["bootstrap"]
        self.assertIn("observer.deadline = normal_end",effective)
        self.assertIn("normal_end-time.monotonic()",effective)
        compile(effective,"<candidate-bootstrap-syntax>","exec")

    def test_actual_host_overlay_resolution_and_public_payload_pins(self):
        result=run.preflight()
        self.assertEqual(result["status"],"PASS")
        self.assertTrue(result["legacy_public_modules_imported"])
        self.assertFalse(result["fixture_constructor_called"])
        self.assertFalse(result["credential_metadata_accessed"])
        self.assertEqual((result["Runtime_calls"],result["provider_POSTs"],result["model_calls"]),(0,0,0))
        binding,_=run.verify_binding()
        delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
        cls,legacy=gate.load_gate(delivery,binding,inspect_only=True)
        with self.assertRaises(RuntimeError):
            cls(types.SimpleNamespace())
        self.assertEqual(Path(cls.start_managed_servers.__globals__["HERE"]),gate.OLD)
        self.assertEqual(legacy.ROOT,Path(binding["output_parent"]))
        capture=ast.parse(gate.effective_sources()["gate"])
        exports=[node.value.value for node in ast.walk(capture) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=="export" for target in node.targets)
            and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)]
        observer_exports=[value for value in exports if "from native_request_observer import validate_record" in value]
        self.assertEqual(len(observer_exports),1)
        self.assertIn("sys.path.insert(0,'/tmp')\nfrom native_request_observer import validate_record",observer_exports[0])
        self.assertIn("from native_request_observer_io import validate_export",observer_exports[0])
        self.assertNotIn("from request_observer import",observer_exports[0])
        self.assertNotIn("'/run'",observer_exports[0])
        compile(observer_exports[0],"<candidate-Runtime-export-syntax>","exec")

    def test_native_failure_capture_before_kill_preserves_first_error(self):
        binding,_=run.verify_binding()
        delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
        cls,_=gate.load_gate(delivery,binding,inspect_only=True)
        sources=gate.effective_sources()
        audit=ast.parse(sources["audit"]).body[0]
        # Execute the actual generated terminal raise site, excluding journal I/O.
        terminal=ast.FunctionDef(name="terminal",args=ast.arguments(posonlyargs=[],
            args=[ast.arg(arg=name) for name in ("self","node","direction","message")],kwonlyargs=[],kw_defaults=[],defaults=[]),
            body=audit.body[-1].body[-2:],decorator_list=[])
        tree=ast.fix_missing_locations(ast.Module(body=[terminal],type_ignores=[]))
        namespace={"_observer_mark_native_failure":gate.mark_native_failure,
                   "safe_error_diagnostic":cls.audit_rpc.__globals__["safe_error_diagnostic"]}
        exec(compile(tree,"<actual-native-terminal-site>","exec"),namespace)
        source_tree=ast.parse(sources["gate"])
        programs=[node.value.value for node in ast.walk(source_tree) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=="stop" for target in node.targets)
            and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)]
        self.assertEqual(len(programs),1)
        pins=gate.capture_program_pins(sources["gate"])
        clock=[1000.0]
        observed=[]
        checks=self
        class Fixture:
            abort_owned=cls.abort_owned
            def __init__(self,timeout=False):
                self.abort_lock=threading.Lock();self.aborted=False;self.cleaning=False
                self._observer_capture_lifecycle_lock=threading.Lock()
                self._observer_native_capture_state=None;self._observer_capture_cutoff=False
                self.args=types.SimpleNamespace(runtime_image=run.RUNTIME,test_request_observer=True,
                    go={"max_fatal_diagnostic_capture_seconds":5})
                self.run_id="synthetic";self.result={};self.timeout=timeout;self.last_argv=None
                self.policy=gate.bind_policy(types.SimpleNamespace(),1000.0)
                self.nodes={letter:{"container":"synthetic-"+letter,"thread":"synthetic-thread-"+letter} for letter in "ab"}
                self.budget=types.SimpleNamespace(threads={letter:"synthetic-thread-"+letter for letter in "ab"},
                    started=[("a","synthetic-turn-a")],completed={})
                self.submitted_objects={("container","synthetic-"+letter):{"id":letter*64,"image":run.RUNTIME} for letter in "ab"}
            def command(self,argv,**kwargs):
                if argv[:2]==["docker","inspect"]:
                    letter=argv[-1][-1]
                    return json.dumps([{"Id":letter*64,"Image":run.RUNTIME,"Config":{"Labels":{"org.cicada.test.run":"synthetic"}}}]).encode()
                checks.assertEqual(argv[:2],["docker","kill"])
                observed.append("kill")
                return b""
            def capture_test_request_observer(self,a3_turn):
                checks.assertTrue(self.aborted);checks.assertIsNone(a3_turn)
                checks.assertEqual(self.result["managed_abort_class"],"RuntimeError")
                observed.append("capture")
                for letter in "ab":
                    argv=["docker","exec",letter*64,"python3","-c",programs[0]]
                    gate.register_capture_command(self,argv,pins)
                    checks.assertTrue(gate.capture_command_allowed(self,argv))
                    self.last_argv=argv
                    forged=argv[:-1]+[programs[0]+"\n"]
                    with checks.assertRaises(RuntimeError):
                        cls.command(self,forged)
                    if self.timeout:
                        clock[0]=self._observer_capture_end+.01
                        checks.assertFalse(gate.capture_command_allowed(self,argv))
                        raise TimeoutError("SYNTHETIC_CAPTURE_TIMEOUT")
                    clock[0]+=.1
                self.result["test_request_observer"]={"capture_status":"COMPLETE","per_Runtime":{}}
        with patch.object(gate.time,"monotonic",side_effect=lambda:clock[0]):
            valid={"method":"error","params":{"threadId":"synthetic-thread-a","turnId":"synthetic-turn-a",
                "willRetry":False,"error":{"message":"SYNTHETIC_WITHHELD","codexErrorInfo":"other"}}}
            for timeout,start in ((False,1000.0),(True,1230.0),(False,1238.0)):
                observed.clear();clock[0]=start;fixture=Fixture(timeout)
                with self.assertRaises(RuntimeError) as raised:
                    namespace["terminal"](fixture,"a","received",valid)
                primary=raised.exception
                checks.assertIs(primary,fixture._observer_native_failures[threading.get_ident()][0])
                checks.assertEqual(observed,["capture","kill","kill"])
                checks.assertEqual(fixture._observer_capture_end,min(start+5,1240.0))
                checks.assertEqual(fixture.policy.started,1000.0)
                checks.assertEqual(fixture.result["test_request_observer"]["capture_status"],"UNKNOWN")
                checks.assertEqual(fixture.result["test_request_observer"]["a3_stage"],"NOT_REACHED")
                checks.assertFalse(gate.capture_command_allowed(fixture,fixture.last_argv))
                fixture.abort_owned(ValueError("SYNTHETIC_LATER_ERROR"))
                checks.assertEqual(fixture.result["managed_abort_class"],"RuntimeError")
                checks.assertEqual(observed,["capture","kill","kill"])
            for mismatch in ("wrong_object","wrong_thread","other_guard"):
                observed.clear();clock[0]=1000.0;fixture=Fixture();primary=RuntimeError("SYNTHETIC_FIRST_ERROR")
                if mismatch=="wrong_object":fixture._observer_native_failures={threading.get_ident():(RuntimeError(),"a","synthetic-thread-a","synthetic-turn-a")}
                elif mismatch=="wrong_thread":fixture._observer_native_failures={threading.get_ident()+1:(primary,"a","synthetic-thread-a","synthetic-turn-a")}
                fixture.abort_owned(primary)
                checks.assertEqual(observed,["kill","kill"])
                checks.assertNotIn("test_request_observer",fixture.result)
            invalid=[]
            for key,value in (("threadId","synthetic-thread-other"),("turnId","synthetic-turn-other"),("willRetry",1)):
                message=copy.deepcopy(valid);message["params"][key]=value;invalid.append(message)
            message=copy.deepcopy(valid);message["method"]="turn/started";invalid.append(message)
            for message in invalid:
                observed.clear();clock[0]=1000.0;fixture=Fixture()
                with self.assertRaises(RuntimeError):
                    namespace["terminal"](fixture,"a","received",message)
                checks.assertEqual(observed,["kill","kill"])
                checks.assertNotIn("test_request_observer",fixture.result)


def reproduce_fixed_installed_ordering():
    """Four full installed schedules; synthetic external Docker boundaries only.

    Cleanup-first is independent driver teardown; late delivery is a buffered
    native callback deliberately held until the destructive cutoff. Neither
    establishes the historical57fc branch or provider/native root cause.
    """
    with run.deny_preflight_effects():
        binding,binding_sha=run.verify_binding()
        delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
        cls,legacy=gate.load_gate(delivery,binding)
        rpc_cls=cls.start_managed_servers.__globals__["ManagedRPC"]
    cases=[]
    original_socket=socket.socket
    original_open,original_io_open=run.builtins.open,run.io.open
    original_stat,original_lstat=os.stat,os.lstat;original_os_open=os.open
    def deny(*args,**kwargs):raise PermissionError("OFFLINE_EXTERNAL_BOUNDARY_DENIED")
    def unix_socket(family=socket.AF_INET,*args,**kwargs):
        if family!=socket.AF_UNIX:deny()
        return original_socket(family,*args,**kwargs)
    def credential_path(path):
        if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path)==run.CREDENTIAL:deny()
    def open_guard(original):
        def guarded(path,*args,**kwargs):credential_path(path);return original(path,*args,**kwargs)
        return guarded
    def stat_guard(original):
        def guarded(path,*args,**kwargs):credential_path(path);return original(path,*args,**kwargs)
        return guarded
    def os_open_guard(path,*args,**kwargs):
        credential_path(path)
        return original_os_open(path,*args,**kwargs)
    with contextlib.ExitStack() as deny_stack:
        for owner,name,value in ((socket,"socket",unix_socket),(socket,"create_connection",deny),
            (socket,"getaddrinfo",deny),(socket,"gethostbyname",deny),(subprocess,"Popen",deny),(subprocess,"run",deny),
            (os,"system",deny),(run.builtins,"open",open_guard(original_open)),
            (run.io,"open",open_guard(original_io_open)),(os,"stat",stat_guard(original_stat)),
            (os,"lstat",stat_guard(original_lstat)),(os,"open",os_open_guard)):deny_stack.enter_context(patch.object(owner,name,value))
        for ordering in ("cleanup_first","native_first","absent","late_native"):
            events=[];event_lock=threading.Lock();failures=[];profile_violations=[];primary=[];holder={}
            marker_entered=threading.Event();cleanup_boundary=threading.Event();release_cleanup=threading.Event()
            turn_observed=threading.Event();rpc_failed=threading.Event();cleanup_finished=threading.Event()
            export_boundary=threading.Event();release_export=threading.Event();cleanup_capture_wait=threading.Event()
            capture_finished=threading.Event();persistence_boundary=threading.Event();release_persistence=threading.Event();release_marker=threading.Event()
            stop_exports={};persisted={};workers=[];owned=[]
            def event(name,actor=None,**fields):
                actor=actor or ("reader" if holder.get("rpc") and threading.current_thread() is holder["rpc"].reader else "cleanup" if threading.current_thread().name=="offline-cleanup" else "controller")
                with event_lock:events.append({"sequence":len(events),"event":name,"actor":actor,**fields})
            def observe_profile(frame,kind,arg):
                if kind not in ("call","return"):return
                name=frame.f_code.co_name;filename=Path(frame.f_code.co_filename).name
                instance=frame.f_locals.get("self")
                if kind=="call" and name=="mark_native_failure" and filename=="request_observer_gate.py":
                    error=frame.f_locals["error"];primary.append(error)
                    lock_free=instance.abort_lock.acquire(blocking=False)
                    if lock_free:instance.abort_lock.release()
                    event("marker_enter",lock_free=lock_free,rpc_error_assigned=holder["rpc"].error is not None)
                    marker_entered.set()
                    if ordering=="late_native" and not release_marker.wait(5):
                        profile_violations.append("LATE_MARKER_BARRIER_TIMEOUT")
                elif name=="abort_owned" and filename=="<effective-request-observer-gate>":
                    if kind=="call":event("abort_enter",latched=instance.aborted,error_is_primary=bool(primary) and frame.f_locals["error"] is primary[0])
                    elif kind=="return":event("abort_return",latched=instance.aborted,abort_class_present="managed_abort_class" in instance.result)
                elif name=="capture_native_failure" and filename=="request_observer_gate.py":
                    if kind=="call":event("capture_hook_enter")
                    elif kind=="return":
                        event("capture_hook_return",report_present="test_request_observer" in instance.result)
                        capture_finished.set()
                elif name=="wait" and filename=="threading.py" and threading.current_thread().name=="offline-cleanup":
                    publication=getattr(holder.get("fixture"),"_observer_native_capture_state",None)
                    if publication is not None and instance is publication["done"]:
                        if kind=="call":
                            timeout=frame.f_locals.get("timeout")
                            already_done=publication["done"].is_set()
                            numeric=type(timeout) in (int,float)
                            positive=numeric and timeout>0
                            within=numeric and 0<=timeout<=5 and (already_done or timeout<=publication["end"]-time.monotonic()+0.01)
                            unlocked=not holder["fixture"]._observer_capture_lifecycle_lock.locked()
                            if not within or (not already_done and not positive):profile_violations.append("EVENT_WAIT_TIMEOUT_INVALID")
                            if not unlocked:profile_violations.append("EVENT_WAIT_LIFECYCLE_LOCK_HELD")
                            event("cleanup_native_event_wait_enter",lifecycle_lock_held=not unlocked,already_done_at_entry=already_done,timeout_zero_allowed=already_done,timeout_positive=positive,pending_wait_within_deadline=within if not already_done else None)
                            cleanup_capture_wait.set()
                        else:
                            if arg is not True:profile_violations.append("EVENT_WAIT_NOT_COMPLETED")
                            event("cleanup_native_event_wait_return",completed=arg is True)
                elif name=="wait_native_capture_before_owned_cleanup" and filename=="request_observer_gate.py":
                    argv=frame.f_locals.get("argv",[])
                    if len(argv)>=2 and argv[:1]==["docker"] and argv[1] in ("stop","kill","rm"):
                        if kind=="call":event("owned_destructive_admission",native_publication_available=getattr(instance,"_observer_native_capture_state",None) is not None)
                        elif kind=="return":event("owned_destructive_admission_return",capture_cutoff=getattr(instance,"_observer_capture_cutoff",False))
                elif name=="fail" and filename=="native_protocol.py":
                    if kind=="call":event("rpc_fail_enter",rpc_error_assigned=instance.error is not None,error_is_primary=bool(primary) and frame.f_locals["error"] is primary[0])
                    else:event("rpc_fail_return",rpc_error_is_primary=bool(primary) and instance.error is primary[0]);rpc_failed.set()
                elif name=="observe" and filename=="managed_gate.py" and kind=="return" and instance is holder.get("fixture"):
                    if len(instance.budget.started)==1:turn_observed.set()
                elif name=="private_json" and holder.get("fixture"):
                    path=frame.f_locals.get("path")
                    if path is not None and Path(path)==holder["fixture"].evidence/"result.json":
                        if kind=="call":
                            event("result_persistence_boundary",abort_lock_held=holder["fixture"].abort_lock.locked())
                            persistence_boundary.set()
                            if ordering=="late_native" and not release_persistence.wait(5):
                                profile_violations.append("LATE_PERSISTENCE_BARRIER_TIMEOUT")
                        else:
                            value=json.loads(Path(path).read_bytes())
                            capture=value.get("test_request_observer",{})
                            persisted.update(abort_class_present="managed_abort_class" in value,
                                capture_present="test_request_observer" in value,
                                capture_scope=capture.get("fatal_capture_scope"),capture_status=capture.get("capture_status"),
                                capture_reason=capture.get("cleanup_capture_reason"),
                                candidate_sources_unchanged=value.get("candidate_sources_unchanged"),
                                native_error_retained=bool(value.get("safe_native_errors")))
                            event("result_persisted",abort_lock_held=holder["fixture"].abort_lock.locked(),**persisted)
            def profile(frame,kind,arg):
                # Instrumentation must never raise into, or disable tracing of,
                # application execution; validate observations after all workers.
                try:observe_profile(frame,kind,arg)
                except BaseException:profile_violations.append("PROFILE_OBSERVATION_FAILED")
            with tempfile.TemporaryDirectory(prefix="cicada-observer-ordering-") as temporary:
                args=types.SimpleNamespace(product_repo=run.PRODUCT_REPO,result_dir=str(Path(temporary)/"result"),
                    expected_product_revision=delivery["commit"],expected_source_fingerprint=delivery["fingerprint"],
                    runtime_image=run.RUNTIME,expected_codex_version="codex-cli 0.160.0",producer_receipt_sha256=delivery["package_metadata_sha256"],
                    exact_clean_image_metadata="OFFLINE_SYNTHETIC",run_native=True,source_binding_sha=binding_sha,
                    preparation_result_sha256=run.PREP_RESULT_SHA,offline_checks_sha="0"*64,config_template_sha=run.CONFIG_SHA,
                    candidate_binding_sha256=binding_sha,artifact_started=time.monotonic(),test_request_observer=True,
                    request_observer_source=str(run.SCRIPTS/"native_request_observer.py"),go={"authority":"NONAUTH_OFFLINE_CONSTRUCTOR",
                        "unique_run":"cicada-two-turn-offlineordering20261005","max_fatal_diagnostic_capture_seconds":5,
                        "preparation_source_binding_sha256":run.PREP_BINDING_SHA,"independent_review_sha256":run.PREP_REVIEW_SHA,
                        "test_request_observer":{"code_sha256":binding["public_files"][str(run.SCRIPTS/"native_request_observer.py")]["sha256"]}})
                fixture=cls(args);holder["fixture"]=fixture
                owned=[fixture.root,*fixture.uds_dirs.values()]
                assert type(fixture.abort_lock) is type(threading.Lock())
                fixture.abort_lock.acquire();assert not fixture.abort_lock.acquire(blocking=False);fixture.abort_lock.release()
                event("full_constructor",actual_nonreentrant_lock=True)
                states={};thread="00000000-0000-4000-8000-000000000001";turn="00000000-0000-4000-8000-000000000003"
                for letter in "ab":
                    name=fixture.run_id+"-"+letter;identity=letter*64
                    fixture.nodes[letter]={"container":name,"thread":thread if letter=="a" else "00000000-0000-4000-8000-000000000002"}
                    fixture.budget.bind(letter,fixture.nodes[letter]["thread"])
                    fixture.containers[name]=run.RUNTIME
                    fixture.submitted_objects[("container",name)]={"id":identity,"image":run.RUNTIME,"name":name,"run_id":fixture.run_id}
                    states[name]={"Id":identity,"Image":run.RUNTIME,"Config":{"Labels":{"org.cicada.test.run":fixture.run_id}},"State":{"Running":True}}
                fixture.audit_files["a"]=(fixture.root/"synthetic-rpc.jsonl").open("x")
                fixture.projection_files["a"]=(fixture.evidence/"managed-a-rpc-projection.jsonl").open("x")
                for stream in (fixture.audit_files["a"],fixture.projection_files["a"]):os.chmod(stream.name,0o600)
                fixture.phase="OFFLINE_SYNTHETIC_A1"
                listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(Path(temporary)/"rpc.sock"));listener.listen(1);listener.settimeout(5)
                peer_ready=threading.Event();close_peer=threading.Event()
                def server():
                    try:
                        peer,_=listener.accept();peer.settimeout(5);holder["peer"]=peer;header=b""
                        while b"\r\n\r\n" not in header:
                            part=peer.recv(4096)
                            if not part:raise EOFError("SYNTHETIC_HANDSHAKE_EOF")
                            header+=part
                            if len(header)>16384:raise AssertionError("SYNTHETIC_HANDSHAKE_BOUND")
                        key=next(line.split(b":",1)[1].strip() for line in header.split(b"\r\n") if line.lower().startswith(b"sec-websocket-key:"))
                        accept=base64.b64encode(hashlib.sha1(key+b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+accept+b"\r\n\r\n")
                        peer_ready.set();close_peer.wait(10)
                    except BaseException as error:failures.append(type(error).__name__);peer_ready.set()
                def send(value):
                    payload=json.dumps(value,separators=(",",":")).encode()
                    holder["peer"].sendall(b"\x81"+(bytes([len(payload)]) if len(payload)<126 else b"\x7e"+struct.pack("!H",len(payload)))+payload)
                program_pins=gate.capture_program_pins(gate.effective_sources()["gate"])
                def docker_boundary(argv,**kwargs):
                    if not isinstance(argv,list) or argv[0]!="docker":deny()
                    output=b"";code=0;operation=argv[1]
                    if operation in ("container","inspect"):
                        target=argv[-1];row=states.get(target) or next((v for v in states.values() if v["Id"]==target),None)
                        if row is None:deny()
                        if ordering=="cleanup_first" and threading.current_thread().name=="offline-cleanup" and not cleanup_boundary.is_set():
                            event("cleanup_boundary",abort_lock_held=fixture.abort_lock.locked(),independent_driver_cleanup=True)
                            cleanup_boundary.set()
                            if not release_cleanup.wait(5):raise AssertionError("CLEANUP_BARRIER_TIMEOUT")
                        output=json.dumps([row]).encode()
                    elif operation in ("stop","kill","rm"):
                        target=argv[-1];row=states.get(target) or next((v for v in states.values() if v["Id"]==target),None)
                        if row is None:deny()
                        row["State"]["Running"]=False;event("docker_"+operation)
                        if ordering=="absent":
                            close_peer.set()
                            peer=holder.get("peer")
                            if peer is not None:
                                try:peer.shutdown(socket.SHUT_RDWR)
                                except OSError:pass
                                peer.close()
                    elif operation=="exec":
                        assert len(argv) in (6,7) and argv[3:5]==["python3","-c"]
                        digest=hashlib.sha256(argv[5].encode()).hexdigest();assert program_pins.get(digest)==len(argv)
                        row=next((v for v in states.values() if v["Id"]==argv[2]),None);assert row is not None
                        if not row["State"]["Running"]:code=1;event("closed_export_Runtime_absent")
                        elif len(argv)==6:
                            stop_exports[argv[2]]=True;event("observer_cli_stop_boundary")
                            output=json.dumps({"schema":"cicada.test-request-observer-stop.v1","stop_requested":True}).encode()
                        else:
                            assert stop_exports.get(argv[2]);event("observer_export_boundary")
                            if ordering=="cleanup_first" and not export_boundary.is_set():
                                export_boundary.set()
                                if not release_export.wait(5):raise AssertionError("EXPORT_BARRIER_TIMEOUT")
                            output=json.dumps({"schema":"cicada.test-request-observer-export.v1","capture_status":"UNKNOWN","records":[],
                                "drain":{"schema":"cicada.test-request-observer-drain.v1","drained":False,"closed":False,"forced":True,"outbound_POST_count":0}}).encode()
                    else:deny()
                    kwargs["stdout"].write(output)
                    return types.SimpleNamespace(returncode=code)
                def cleanup_worker():
                    sys.setprofile(profile)
                    try:fixture.cleanup()
                    except BaseException as error:failures.append(type(error).__name__)
                    finally:event("cleanup_return");cleanup_finished.set();sys.setprofile(None)
                old_profile=threading.getprofile();threading.setprofile(profile)
                try:
                    with patch.object(subprocess,"run",docker_boundary):
                        worker=threading.Thread(target=server,name="offline-websocket",daemon=True);workers.append(worker);worker.start()
                        rpc=rpc_cls(str(Path(temporary)/"rpc.sock"),"a",fixture.observe,fixture.audit_rpc,fixture.abort_owned,fixture.limit)
                        holder["rpc"]=rpc;fixture.rpcs["a"]=rpc
                        assert rpc.abort.__self__ is fixture and rpc.abort.__func__ is cls.abort_owned
                        assert rpc.audit.__closure__ is not None
                        bound_audits=[cell.cell_contents for cell in rpc.audit.__closure__
                            if isinstance(cell.cell_contents,types.MethodType)]
                        assert any(method.__self__ is fixture and method.__func__ is cls.audit_rpc for method in bound_audits)
                        assert rpc.state.callback.__self__ is fixture and rpc.state.callback.__func__ is fixture.observe.__func__
                        event("real_callbacks_bound",audit=True,abort=True,observer=True)
                        assert peer_ready.wait(5) and not failures
                        send({"method":"turn/started","params":{"threadId":thread,"turn":{"id":turn,"status":"inProgress"}}})
                        assert turn_observed.wait(5)
                        native={"method":"error","emittedAtMs":0,"params":{"threadId":thread,"turnId":turn,"willRetry":False,
                            "error":{"message":"SYNTHETIC_WITHHELD","codexErrorInfo":"other","misalignment":None}}}
                        cleanup=threading.Thread(target=cleanup_worker,name="offline-cleanup",daemon=True);workers.append(cleanup)
                        if ordering=="cleanup_first":
                            cleanup.start();assert cleanup_boundary.wait(5);send(native);assert marker_entered.wait(5)
                            assert export_boundary.wait(5)
                            release_cleanup.set();assert cleanup_capture_wait.wait(5)
                            assert not any(row["event"] in ("docker_stop","docker_kill","docker_rm") for row in events)
                            assert not fixture._observer_native_capture_state["done"].is_set()
                            event("cleanup_blocked_until_capture_release");release_export.set()
                            assert capture_finished.wait(5) and rpc_failed.wait(5)
                            assert cleanup_finished.wait(8)
                        elif ordering=="native_first":
                            send(native);assert rpc_failed.wait(5);cleanup.start();assert cleanup_finished.wait(8)
                        elif ordering=="absent":
                            cleanup.start();assert cleanup_finished.wait(8)
                        else:
                            # Deliver only after actual destructive cleanup and
                            # before the inherited result-persistence call proceeds.
                            cleanup.start();assert persistence_boundary.wait(8)
                            assert fixture._observer_capture_cutoff and fixture._observer_native_capture_state is None
                            send(native);assert marker_entered.wait(5)
                            event("late_native_after_destructive_cutoff");release_marker.set()
                            assert rpc_failed.wait(5);release_persistence.set();assert cleanup_finished.wait(8)
                        rpc.reader.join(2);assert not rpc.reader.is_alive() and not failures
                        assert not profile_violations
                        native_seen=ordering!="absent"
                        if native_seen:assert rpc.error is primary[0]
                        else:assert rpc.error is None
                        event("reader_finished",primary_error_identity_preserved=True if native_seen else None)
                        result={"ordering":ordering,"trigger":{
                            "cleanup_first":"INDEPENDENT_DRIVER_CLEANUP","native_first":"NATIVE_READER_FIRST",
                            "absent":"CLEANUP_WITHOUT_NATIVE_ERROR","late_native":"BUFFERED_NATIVE_AFTER_DESTRUCTIVE_CUTOFF"}[ordering],
                            "events":events,"profile_violations":list(profile_violations),"persisted":dict(persisted),"post_reader_abort_class_present":"managed_abort_class" in fixture.result,
                            "post_reader_capture_present":"test_request_observer" in fixture.result,
                            "primary_error_identity_preserved":True if native_seen else None,
                            "actual_constructor":True,"real_ManagedRPC_TypedRPC_reader":True,"actual_nonreentrant_abort_lock":True,
                            "source_guard_PASS":persisted.get("candidate_sources_unchanged") is True,"external_Docker_boundary_calls_only":True,
                            "Runtime_calls":0,"provider_POSTs":0,"model_calls":0,"credential_access":False}
                        assert result["source_guard_PASS"] and persisted.get("capture_status")=="UNKNOWN"
                        assert persisted.get("abort_class_present")==native_seen
                        assert persisted.get("capture_present") is True
                        assert all(not e["abort_lock_held"] for e in events if e["event"] in ("result_persisted","result_persistence_boundary"))
                        if ordering in ("cleanup_first","native_first"):
                            assert persisted.get("capture_scope")=="AUDIT_TERMINAL_NATIVE_PROTOCOL"
                            assert next(e["sequence"] for e in events if e["event"]=="observer_export_boundary") < next(e["sequence"] for e in events if e["event"] in ("docker_stop","docker_kill"))
                        else:
                            assert persisted.get("capture_scope") is None
                            assert persisted.get("capture_reason")=="NO_NATIVE_CAPTURE_AT_DESTRUCTIVE_CUTOFF"
                            assert not any(e["event"]=="observer_export_boundary" for e in events)
                        cases.append(result)
                finally:
                    release_cleanup.set();release_export.set();release_marker.set();release_persistence.set();close_peer.set()
                    if holder.get("peer"):
                        try:holder["peer"].shutdown(socket.SHUT_RDWR)
                        except OSError:pass
                        holder["peer"].close()
                    if holder.get("rpc"):
                        holder["rpc"].close()
                    listener.close()
                    for worker in workers:worker.join(3)
                    threading.setprofile(old_profile)
                    for stream in list(fixture.audit_files.values())+list(fixture.projection_files.values()):
                        if not stream.closed:stream.close()
                    for path in owned:
                        if path.exists():shutil.rmtree(path)
                    assert all(not path.exists() for path in owned) and all(not worker.is_alive() for worker in workers)
                    if cases and cases[-1]["ordering"]==ordering:cases[-1]["owned_temporary_state_removed"]=True
    return {"schema":"cicada.offline-installed-ordering-proof.v1","authority":"NONAUTH_ZERO_PAID","status":"PASS",
        "candidate_binding_sha256":binding_sha,"subject_gate_sha256":binding["candidate_files"]["request_observer_gate.py"]["sha256"],
        "subject_run_sha256":binding["candidate_files"]["request_observer_run.py"]["sha256"],
        "checker_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"cases":cases,
        "historical57fc_executed_branch":"UNKNOWN","historical_native_provider_error_cause":"UNKNOWN"}


if __name__=="__main__":
    if "--reproduce-fixed-ordering" in sys.argv:
        try:
            proof=reproduce_fixed_installed_ordering()
            target=run.BINDING.parent/"request-observer-ordering-wired.NONAUTH.json"
            with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as stream:
                json.dump(proof,stream,sort_keys=True,indent=2);stream.write("\n")
            print(json.dumps({"status":"PASS","closed_trace":str(target),"sha256":hashlib.sha256(target.read_bytes()).hexdigest()}))
        except BaseException as error:
            print(json.dumps({"status":"FAIL","failure_class":type(error).__name__,"details":"CLOSED_WITHHELD"}));raise SystemExit(1)
    else:
        with run.deny_preflight_effects():
            unittest.main(verbosity=2)
