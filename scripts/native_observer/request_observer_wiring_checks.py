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

    def test_native_https_cli_typed_go_conflicts_and_tcp_cap(self):
        args=types.SimpleNamespace(native_https=True,execute_diagnostic=True,scenario='g2-g3',
            prepare_native_zero=False,enable_io_diagnostics=False,response_byte_passthrough=False)
        self.assertTrue(run.native_https_mode(args))
        self.assertFalse(run.native_https_mode(types.SimpleNamespace()))
        for key,value in (('native_https',1),('scenario','g1'),('execute_diagnostic',False),
                ('prepare_native_zero',True),('enable_io_diagnostics',True),('response_byte_passthrough',True)):
            wrong=copy.copy(args);setattr(wrong,key,value)
            with self.subTest(field=key),self.assertRaises(PermissionError):run.native_https_mode(wrong)
        with run.deny_preflight_effects():
            captured=[]
            with patch.object(run,'execute',side_effect=lambda value:captured.append(value) or 0):
                self.assertEqual(run.main(['--execute-diagnostic','--scenario','g2-g3','--native-https']),0)
                self.assertEqual(len(captured),1);self.assertIs(captured[0].native_https,True)
                self.assertEqual(run.main(['--execute-diagnostic','--scenario','g2-g3','--native-https','--enable-io-diagnostics']),2)
                self.assertEqual(len(captured),1)
            output=io.StringIO()
            with patch.object(sys,'stdout',output):
                self.assertEqual(run.main(['--execute-diagnostic','--scenario','g2-g3','--native-https']),2)
            blocked=json.loads(output.getvalue())
            self.assertEqual(blocked['status'],'BLOCKED_GUARD')
            self.assertEqual((blocked['Runtime_calls'],blocked['provider_POSTs'],blocked['model_calls']),(0,0,0))
            binding,sha=run.verify_binding()
            args.unique_run='cicada-two-turn-syntheticnativehttps';args.wiring_receipt_sha='1'*64
            args.cleanup_hard_stop_unix=10000;args.delivery_sha='2'*64;args.preparation_result_sha='3'*64
            args.preparation_review_sha='4'*64;args.equality_sha='5'*64
            delivery=dict(hub_image='synthetic',commit='synthetic',binary_sha256='6'*64,
                helper_sha256='7'*64,fingerprint='8'*64,component_proof_sha256='9'*64)
            expected=run.expected_latest_go(binding,sha,args,delivery);go=dict(expected,expires_at_unix=9000)
            run.validate_go(go,expected,now=1000)
            gate_args=types.SimpleNamespace(native_https=True,run_native=True,test_request_observer=False,
                response_byte_passthrough=False,go=go)
            self.assertTrue(gate.validate_native_https(gate_args,'g2-g3',False))
            for key,value in (('native_https',False),('max_manual_turns',3),('max_native_turns',7),
                    ('request_max_retries',1),('stream_max_retries',1),('max_accepted_TCP_connections_per_Runtime',17),
                    ('HTTP_POST_COUNT',0),('POST16_ENFORCEMENT','ENFORCED')):
                wrong=dict(go);wrong[key]=value
                with self.subTest(go_field=key),self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
                invalid=copy.copy(gate_args);invalid.go=wrong
                with self.assertRaises(PermissionError):gate.validate_native_https(invalid,'g2-g3',False)
            for field,value in (('response_byte_passthrough',True),('response_byte_passthrough',0),
                    ('response_byte_ceiling',4259840),('response_byte_ceiling',False),
                    ('response_chunk_ceiling',65536),('response_chunk_ceiling',0.0),
                    ('max_native_turns',True),('request_max_retries',False)):
                wrong=dict(go);wrong[field]=value
                invalid=copy.copy(gate_args);invalid.go=wrong
                with self.subTest(field=field,value_type=type(value)),self.assertRaises(PermissionError):gate.validate_native_https(invalid,'g2-g3',False)
                with self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
            for field in ('response_byte_passthrough','response_byte_ceiling','response_chunk_ceiling'):
                wrong=dict(go);del wrong[field]
                invalid=copy.copy(gate_args);invalid.go=wrong
                with self.subTest(missing=field),self.assertRaises(PermissionError):gate.validate_native_https(invalid,'g2-g3',False)
                with self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
            for scenario,zero,field,value in (('g1',False,'run_native',True),('g2-g3',True,'run_native',True),
                    ('g2-g3',False,'run_native',False),('g2-g3',False,'test_request_observer',True),
                    ('g2-g3',False,'response_byte_passthrough',True)):
                invalid=copy.copy(gate_args);setattr(invalid,field,value)
                with self.subTest(scenario=scenario,zero=zero,field=field),self.assertRaises(PermissionError):gate.validate_native_https(invalid,scenario,zero)
            self.assertNotIn('test_request_observer',go);self.assertNotIn('max_POST_attempts_per_Runtime',go)
            historical_delivery_pair=run.bounded_json(run.ACTUAL/'actual-delivery.json')
            execution=copy.copy(args)
            receipt_raw=b'SYNTHETIC_PUBLIC_WIRING_BYTES'
            execution.wiring_receipt_sha=hashlib.sha256(receipt_raw).hexdigest()
            execution.binding_sha=sha;execution.preparation_result='synthetic-ready'
            execution.go_receipt=str(run.BINDING.parent/'request-observer-synthetic-native-https-go.json')
            execution.wiring_receipt=str(run.BINDING.parent/'request-observer-wiring-synthetic-native-https.json')
            pinned=run.expected_latest_go(binding,sha,execution,delivery)
            receipt={'status':'PASS','candidate_binding_sha256':sha,'Runtime_calls':0,'provider_POSTs':0,'model_calls':0}
            for kind in ('expired','forged_budget'):
                candidate=dict(pinned,expires_at_unix=9000)
                if kind=='expired':candidate['expires_at_unix']=999
                else:candidate['max_manual_turns']=3
                raw=json.dumps(candidate,sort_keys=True).encode()
                execution.go_receipt_sha=hashlib.sha256(raw).hexdigest()
                def public_json(path):
                    if Path(path)==run.ACTUAL/'actual-delivery.json':return historical_delivery_pair
                    if str(path)==execution.wiring_receipt:return receipt,receipt_raw
                    if str(path)==execution.go_receipt:return candidate,raw
                    raise AssertionError('UNEXPECTED_PUBLIC_READ')
                with self.subTest(execute_refusal=kind),patch.object(run,'latest_dispatch_inputs',return_value=(binding,sha,delivery,{})),patch.object(run,'bounded_json',side_effect=public_json),patch.object(run.time,'time',return_value=1000),patch.object(Path,'lstat',side_effect=AssertionError('NO_METADATA')),patch.object(run.os,'open',side_effect=AssertionError('NO_CLAIM')),patch.object(run,'safe_overlay',side_effect=AssertionError('NO_FIXTURE')):
                    with self.assertRaises(PermissionError):run.execute(execution)
                self.assertFalse(run.EXECUTION_EFFECTS_STARTED)
            # Execute the installed config/read validation block with a memory RPC.
            actual_delivery,_=run.bounded_json(run.ACTUAL/'actual-delivery.json')
            cls,_=gate.load_gate(actual_delivery,binding,inspect_only=True,scenario='g2-g3')
            method=ast.parse(gate.effective_sources()['gate']).body
            managed=next(n for n in method if isinstance(n,ast.ClassDef))
            start=next(n for n in managed.body if isinstance(n,ast.FunctionDef) and n.name=='start_managed_servers')
            first=next(i for i,n in enumerate(start.body) if isinstance(n,ast.For))
            statements=start.body[first].body
            begin=next(i for i,n in enumerate(statements) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='resolved' for t in n.targets))
            end=next(i for i,n in enumerate(statements) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Subscript) and "actual_managed_config" in ast.unparse(t) for t in n.targets))
            function=ast.FunctionDef(name='check_config',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='self'),ast.arg(arg='rpc'),ast.arg(arg='letter')],kwonlyargs=[],kw_defaults=[],defaults=[]),body=statements[begin:end+1],decorator_list=[])
            namespace=gate.method_namespace(cls.start_managed_servers)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),'<installed-native-config-check>','exec'),namespace)
            import tomllib
            provider=tomllib.loads(run.CONFIG.read_text())['model_providers']['basil']
            resolved={'model':'gpt-5.6-luna','model_provider':'basil','approval_policy':'never','approvals_reviewer':'user',
                'sandbox_mode':'workspace-write','features':{'multi_agent':False,'goals':False},
                'model_providers':{'basil':dict(provider,request_max_retries=0,stream_max_retries=0)}}
            owner=types.SimpleNamespace(args=types.SimpleNamespace(test_request_observer=False,config_template=str(run.CONFIG)),result={})
            rpc=types.SimpleNamespace(request=lambda *args: {'config':resolved})
            namespace['check_config'](owner,rpc,'a')
            self.assertTrue(owner.result['actual_managed_config']['a']['base_url_matches_authorized_template'])
            for field in ('request_max_retries','stream_max_retries','base_url'):
                old=resolved['model_providers']['basil'][field]
                resolved['model_providers']['basil'][field]='https://synthetic.invalid' if field=='base_url' else 1
                with self.subTest(config_field=field),self.assertRaises(RuntimeError):namespace['check_config'](owner,rpc,'a')
                resolved['model_providers']['basil'][field]=old
            module=gate.safe_module('native_https_cap_public',gate.OLD/'provider_transport.py')
            adapter=object.__new__(module.Forwarder);adapter.lock=threading.Lock();adapter.closed=False
            adapter.remaining=lambda:1;adapter.client_allowed=lambda address:True
            adapter.binding={'max_connections':16,'max_active':4};adapter.accepted=0;adapter.active=0
            adapter.rejected=0;adapter.sockets=set()
            clients=[]
            for number in range(17):
                client=types.SimpleNamespace()
                class Client:
                    closed=False
                    def close(self):self.closed=True
                client=Client();clients.append(client)
                self.assertIs(adapter.admit(client,('192.0.2.1',1234)),number<16)
                adapter.active=0
            self.assertEqual((adapter.accepted,adapter.rejected),(16,1));self.assertTrue(clients[-1].closed)

    def test_response_passthrough_explicit_go_and_bootstrap(self):
        args=types.SimpleNamespace(response_byte_passthrough=True,execute_diagnostic=True,
            enable_io_diagnostics=True,prepare_native_zero=False,scenario='g2-g3')
        self.assertTrue(run.response_passthrough_mode(args))
        self.assertFalse(run.response_passthrough_mode(types.SimpleNamespace()))
        for field,value in (('response_byte_passthrough',1),('response_byte_passthrough','true'),
                ('scenario','g1'),('execute_diagnostic',False),('enable_io_diagnostics',False),('prepare_native_zero',True)):
            with self.subTest(field=field,value_type=type(value)):
                wrong=copy.copy(args);setattr(wrong,field,value)
                with self.assertRaises(PermissionError):run.response_passthrough_mode(wrong)
        gate_args=types.SimpleNamespace(response_byte_passthrough=True,run_native=True,test_request_observer=True,
            go={'response_byte_passthrough':True,'response_transport_semantics':'NATIVE_HTTP_VALIDATES_RESPONSE_EOF_NOT_BUSINESS_COMPLETION',
                'response_byte_ceiling':4259840,'response_chunk_ceiling':65536})
        self.assertTrue(gate.validate_response_mode(gate_args,'g2-g3',False))
        for scenario,zero in (('g1',False),('g2-g3',True)):
            with self.assertRaises(PermissionError):gate.validate_response_mode(gate_args,scenario,zero)
        for field,value in (('response_byte_passthrough',1),('response_byte_ceiling',4259840.0),
                ('response_chunk_ceiling',65536.0),('response_chunk_ceiling',True)):
            with self.subTest(go_field=field,value_type=type(value)):
                wrong=copy.copy(gate_args);wrong.go=dict(gate_args.go);wrong.go[field]=value
                with self.assertRaises(PermissionError):gate.validate_response_mode(wrong,'g2-g3',False)
        mismatch=copy.copy(gate_args);mismatch.response_byte_passthrough=False
        with self.assertRaises(PermissionError):gate.validate_response_mode(mismatch,'g2-g3',False)
        missing=copy.copy(gate_args);missing.go={}
        with self.assertRaises(PermissionError):gate.validate_response_mode(missing,'g2-g3',False)
        strict_args=types.SimpleNamespace(response_byte_passthrough=False,go={'response_byte_passthrough':False,
            'response_transport_semantics':'OBSERVER_STRICT_HTTP_FRAMING','response_byte_ceiling':None,'response_chunk_ceiling':None})
        self.assertFalse(gate.validate_response_mode(strict_args,'g1',False))
        strict_args.go['response_byte_ceiling']=4259840.0
        with self.assertRaises(PermissionError):gate.validate_response_mode(strict_args,'g1',False)
        self.assertFalse(gate.validate_response_mode(types.SimpleNamespace(),'g1',True))
        with run.deny_preflight_effects():
            binding,sha=run.verify_binding()
            args.unique_run='cicada-two-turn-syntheticmanual';args.wiring_receipt_sha='1'*64
            args.cleanup_hard_stop_unix=10000;args.delivery_sha='2'*64;args.preparation_result_sha='3'*64
            args.preparation_review_sha='4'*64;args.equality_sha='5'*64
            delivery=dict(runtime_image='synthetic',hub_image='synthetic',commit='synthetic',
                binary_sha256='6'*64,helper_sha256='7'*64,fingerprint='8'*64,
                component_proof_sha256='9'*64)
            expected=run.expected_latest_go(binding,sha,args,delivery)
            self.assertIs(expected['response_byte_passthrough'],True)
            self.assertEqual(expected['response_byte_ceiling'],4259840)
            self.assertEqual(expected['response_chunk_ceiling'],65536)
            self.assertEqual((expected['max_native_turns'],expected['max_manual_turns'],expected['max_automatic_turns']),(6,4,2))
            go=dict(expected,expires_at_unix=9000)
            run.validate_go(go,expected,now=1000)
            self.assertEqual(expected['official_cli_version'],run.LATEST_VERSION)
            self.assertEqual(expected['runtime_image'],run.LATEST_RUNTIME)
            self.assertEqual(expected['official_cli_sha256'],run.LATEST_CLI_SHA)
            for field,value in (('official_cli_version','0.160.1'),
                    ('runtime_image','sha256:ebea4c9988e539d2da914e9cf451c35d5c5039cf99706cd1effc0a6d7b449b83'),
                    ('official_cli_sha256','f34a4d2301892ae96c90097786bfe5dc269f187b6f69faf42a7b357b8c081e35')):
                with self.subTest(historical_candidate_field=field):
                    wrong=dict(go);wrong[field]=value
                    with self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
            for field,value in (('response_byte_passthrough',1),('response_byte_passthrough',False),
                    ('response_transport_semantics','OBSERVER_STRICT_HTTP_FRAMING'),('response_byte_ceiling',4259841)):
                wrong=dict(go);wrong[field]=value
                with self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
            wrong=dict(go);del wrong['response_byte_passthrough']
            with self.assertRaises(PermissionError):run.validate_go(wrong,expected,now=1000)
            argv=['exec','-d','synthetic','python3','/state/server_bootstrap.py','paid','http://192.0.2.1:7890','--test-request-observer','a'*64,'1180.0','16']
            strict=gate.runtime_bootstrap_argv(argv,binding,1000.0)
            selected=gate.runtime_bootstrap_argv(argv,binding,1000.0,response_byte_passthrough=True)
            self.assertEqual(selected,strict+['--response-byte-passthrough'])
            with self.assertRaises(ValueError):gate.runtime_bootstrap_argv(argv,binding,1000.0,response_byte_passthrough=1)
            source=bootstrap.effective_source(bootstrap.read_pinned(gate.OLD/'server_bootstrap.py',bootstrap.OLD_BOOTSTRAP_SHA).decode(),bootstrap.read_pinned(gate.LEGACY/'request-observer-integration.patch',bootstrap.PATCH_SHA).decode())
            self.assertIn('response_byte_passthrough=(sys.argv[7:] == ["--response-byte-passthrough"])',source)
            flow=gate.compile_g2_flow_methods(gate.effective_sources()['gate'],{})
            self.assertNotIn('response_byte_passthrough',flow['managed_golden_flow']._g2_selected_source)

    def test_g2_manual_dispatch_cap_and_original_order(self):
        sentinel=object()
        def original(): return sentinel
        selected, source_sha=gate.selected_g2_manual_turn(original)
        self.assertIs(selected.__globals__["sentinel"],sentinel)
        self.assertEqual(len(source_sha),64)
        raw=(gate.OLD/"managed_gate.py").read_text()
        tree=ast.parse(raw)
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="ManagedGate")
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=="manual_turn")
        source=ast.get_source_segment(raw,method)
        ns=gate.method_namespace(original)
        exec(compile(source,"<memory-original-manual>","exec"),ns)
        legacy=ns["manual_turn"]
        def fixture(enabled=True,fail=None):
            calls=[]
            owner=types.SimpleNamespace(args=types.SimpleNamespace(run_native=enabled),
                result_paid_dispatches=0,result={},manual_turn_ids=[],nodes={"a":{"thread":"original-a"}})
            def limit(value):
                calls.append(("limit",value))
                if fail and fail[0]=="limit": raise fail[1]
            def request(method,params):
                calls.append(("request",method,params))
                if fail and fail[0]=="request": raise fail[1]
                return {"turn":{"id":"turn-"+str(owner.result_paid_dispatches)}}
            def wait(letter,turn):
                calls.append(("wait",letter,turn))
                if fail and fail[0]=="wait": raise fail[1]
            owner.limit=limit;owner.rpcs={"a":types.SimpleNamespace(request=request)};owner.wait_turn=wait
            return owner,calls
        owner,calls=fixture()
        for index in range(1,5):
            self.assertEqual(selected(owner,"a","synthetic prompt"),"turn-"+str(index))
        self.assertEqual(owner.result_paid_dispatches,4)
        self.assertEqual(owner.result["paid_turn_start_submissions"],4)
        self.assertEqual(len(owner.manual_turn_ids),4)
        for index in range(4):
            block=calls[index*3:(index+1)*3]
            self.assertEqual([row[0] for row in block],["limit","request","wait"])
            self.assertEqual(block[0],("limit",.001))
            self.assertEqual(block[1][1],"turn/start")
            self.assertEqual(block[1][2]["threadId"],"original-a")
            self.assertEqual((block[1][2]["model"],block[1][2]["approvalPolicy"]),("gpt-5.6-luna","never"))
        before=list(owner.manual_turn_ids);requests=sum(row[0]=="request" for row in calls)
        with self.assertRaisesRegex(RuntimeError,"fifth manual turn forbidden"): selected(owner,"a","synthetic")
        self.assertEqual(owner.result_paid_dispatches,4);self.assertEqual(owner.manual_turn_ids,before)
        self.assertEqual(sum(row[0]=="request" for row in calls),requests)
        g1,g1calls=fixture();g1.result_paid_dispatches=3
        with self.assertRaisesRegex(RuntimeError,"fourth manual turn forbidden"): legacy(g1,"a","synthetic")
        self.assertEqual(g1calls,[("limit",.001)]);self.assertEqual(g1.result_paid_dispatches,3)
        zero,zerocalls=fixture(False)
        with self.assertRaisesRegex(RuntimeError,"turn forbidden in zero-model preparation"): selected(zero,"a","synthetic")
        self.assertEqual(zerocalls,[]);self.assertEqual((zero.result_paid_dispatches,zero.result,zero.manual_turn_ids),(0,{},[]))
        for boundary in ("limit","request","wait"):
            with self.subTest(boundary=boundary):
                error=RuntimeError("synthetic boundary")
                failed,failedcalls=fixture(fail=(boundary,error))
                with self.assertRaises(RuntimeError) as caught: selected(failed,"a","synthetic")
                self.assertIs(caught.exception,error)
                self.assertEqual(failed.result_paid_dispatches,0 if boundary=="limit" else 1)
                self.assertEqual(len(failed.manual_turn_ids),1 if boundary=="wait" else 0)
        old="if self.result_paid_dispatches >= 3:\n            raise RuntimeError('fourth manual turn forbidden')"
        new="if self.result_paid_dispatches >= 4:\n            raise RuntimeError('fifth manual turn forbidden')"
        self.assertEqual(source.count(old),1)
        expected=source.replace(old,new,1)
        self.assertEqual(source_sha,hashlib.sha256(expected.encode()).hexdigest())
        gate_tree=ast.parse(Path(gate.__file__).read_text())
        loader=next(n for n in gate_tree.body if isinstance(n,ast.FunctionDef) and n.name=="load_gate")
        branches=[n for n in ast.walk(loader) if isinstance(n,ast.If) and any(
            isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=="selected_g2_manual_turn"
            for statement in n.body for x in ast.walk(statement))]
        self.assertEqual(len(branches),1)
        self.assertEqual(ast.unparse(branches[0].test),"scenario == 'g2-g3'")
        with patch.object(gate,"OLD_GATE_SHA","0"*64):
            with self.assertRaisesRegex(ValueError,"G2_MANUAL_SOURCE_PIN"): gate.selected_g2_manual_turn(original)

    def test_two_pass_retarget_order_initial_and_partial_failure(self):
        sentinel=object()
        def original():return sentinel
        selected,source_sha=gate.selected_two_pass_refresh(original)
        self.assertIs(selected.__globals__["sentinel"],sentinel)
        self.assertEqual(len(source_sha),64)
        def fixture(phase,fail=None):
            calls=[];targets={letter:{"port":100+index} for index,letter in enumerate("ab")}
            class TargetFile:
                def __init__(self,letter):self.letter=letter
                def read_text(self):return json.dumps(targets[self.letter])
            class State:
                def __init__(self,letter):self.letter=letter
                def __truediv__(self,name):return TargetFile(self.letter)
            owner=types.SimpleNamespace(hub="owned-hub",nodes={letter:{"gateway":"synthetic-gateway-"+letter,"hub_port":200+index,
                "paths":{"state":State(letter)}} for index,letter in enumerate("ab")},
                result={"hub_forwarder_refresh":[] if phase=="initial" else [{"owned_hub_container_id":"owned-id"}]})
            witnessed={letter:0 for letter in "ab"}
            def forwarder(letter):
                calls.append("identity-"+letter);witnessed[letter]+=1
                return {"pid":10+ord(letter),"start_ticks":"synthetic","argv_sha256":"a"*64}
            def write(letter):
                calls.append("write-"+letter);targets[letter]={"gateway":owner.nodes[letter]["gateway"],"port":owner.nodes[letter]["hub_port"]}
                return dict(targets[letter])
            failure=RuntimeError("actual PQTLS ready/wake NOT_PROVEN")
            def witness(letter,**flags):
                calls.append("witness-"+letter)
                self.assertEqual([item for item in calls if item.startswith("write-")],["write-a","write-b"])
                self.assertEqual(flags,{"require_wake":False,"require_fresh":phase!="initial"})
                if letter==fail:raise failure
                return {"ready":True,"observation_id":"conn-3-"+letter}
            def inspect(kind,name):calls.append("hub-identity");return {"Id":"owned-id"}
            owner.forwarder_witness=forwarder;owner.write_forwarder_target=write
            owner.pq_transport_witness=witness;owner.inspect=inspect
            return owner,calls,targets,failure
        for phase in ("initial","synthetic-restart"):
            with self.subTest(phase=phase):
                owner,calls,targets,_=fixture(phase);selected(owner,phase)
                self.assertEqual(calls,["identity-a","write-a","identity-a","identity-b","write-b","identity-b","witness-a","witness-b","hub-identity"])
                row=owner.result["hub_forwarder_refresh"][-1]
                for letter in "ab":
                    self.assertEqual(set(row["nodes"][letter]),{"before_target","after_target","process_before","process_after","transport","hub_id_scope"})
                    self.assertEqual(row["nodes"][letter]["process_before"],row["nodes"][letter]["process_after"])
                    self.assertEqual(row["nodes"][letter]["after_target"],targets[letter])
                self.assertEqual(row["actual_inspected_mapping"],targets)
                self.assertEqual(row["nodes"]["a"]["before_target"],{"port":100})
        owner,calls,targets,failure=fixture("synthetic-restart",fail="b")
        with self.assertRaises(RuntimeError) as caught:selected(owner,"synthetic-restart")
        self.assertIs(caught.exception,failure)
        row=owner.result["hub_forwarder_refresh"][-1]
        self.assertEqual(set(row["nodes"]),{"a","b"})
        self.assertIn("transport",row["nodes"]["a"]);self.assertNotIn("transport",row["nodes"]["b"])
        self.assertNotIn("owned_hub_container_id",row)
        self.assertNotIn("hub-identity",calls)
        self.assertEqual(row["nodes"]["b"]["after_target"],targets["b"])

    def test_two_pass_retarget_identity_ownership_and_source_guards(self):
        def original():pass
        selected,_=gate.selected_two_pass_refresh(original)
        calls=[]
        class State:
            def __truediv__(self,name):return types.SimpleNamespace(read_text=lambda:'{"port":1}')
        owner=types.SimpleNamespace(hub="owned-hub",nodes={letter:{"gateway":"synthetic","hub_port":2,"paths":{"state":State()}} for letter in "ab"},
            result={"hub_forwarder_refresh":[{"owned_hub_container_id":"owned-id"}]},
            forwarder_witness=lambda letter:(calls.append("identity-"+letter) or {"pid":len(calls)}),
            write_forwarder_target=lambda letter:(calls.append("write-"+letter) or {"port":2}),
            pq_transport_witness=lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError("NO_WITNESS_ON_IDENTITY_FAILURE")))
        with self.assertRaisesRegex(RuntimeError,"identity changed during retarget"):selected(owner,"synthetic-restart")
        self.assertEqual(calls,["identity-a","write-a","identity-a"])
        self.assertEqual(owner.result["hub_forwarder_refresh"][-1]["nodes"],{})
        for baseline,current in (("owned-id","foreign-id"),(None,"owned-id")):
            with self.subTest(ownership=True):
                owner.result={"hub_forwarder_refresh":[{} if baseline is None else {"owned_hub_container_id":baseline}]}
                owner.forwarder_witness=lambda letter:{"pid":10}
                owner.pq_transport_witness=lambda *args,**kwargs:{"ready":True}
                owner.inspect=lambda *args:{"Id":current}
                with self.assertRaises((RuntimeError,KeyError)):selected(owner,"synthetic-restart")
        # Drift is refused before selecting/compiling an unpinned legacy method.
        with patch.object(Path,"read_bytes",return_value=b"synthetic changed legacy source"),self.assertRaisesRegex(ValueError,"SOURCE_PIN"):
            gate.selected_two_pass_refresh(original)


    def test_pre_stop_freshness_rejects_replay_and_accepts_appended_link(self):
        def record(identifier, event="got-conn", route="relay-events"):
            return dict(schema_version=1,event=event,observation_id=identifier,route=route,
                tls_version="TLSv1.3",group="MLKEM768",cipher_suite="TLS_AES_256_GCM_SHA384",
                peer_signature="ML-DSA-65",alpn="http/1.1",verification_result=0,
                hostname_verified=True,peer_kind="hub",hub_id="hub",local_node_id="a-node",
                certificate_sha256="a"*64,spki_sha256="b"*64)
        def encode(rows):return b"".join(json.dumps(row).encode()+b"\n" for row in rows)
        initial=encode([record("conn-1"),record("conn-1","ready"),record("conn-2"),record("conn-2","ready"),record("conn-9",route="fabric-whoami")])
        class Diagnostic:
            raw=initial
            inode=10
            growth=0
            def lstat(self):return types.SimpleNamespace(st_mode=0o100600,st_dev=1,st_ino=self.inode,st_uid=1000,st_size=len(self.raw)+self.growth)
            stat=lstat
            def exists(self):return True
            def is_file(self):return True
            def is_symlink(self):return False
            def read_bytes(self):return self.raw
        diagnostic=Diagnostic()
        class State:
            def __truediv__(self,name):return diagnostic
        owner=types.SimpleNamespace(nodes={"a":{"paths":{"state":State()},"node_id":"a-node","last_pq_observation":"conn-2"}},
            meta={"hub_id":"hub"},result={"hub_forwarder_refresh":[{"owned_hub_container_id":"hub-cid"}]},limit=lambda value:value)
        scope=gate.pq_file_scope(diagnostic.lstat())
        owner._pq_restart_anchors={"a":{"path":diagnostic,"node_id":"a-node","hub_id":"hub-cid","scope":scope,"prefix":initial,"ids":gate.pq_diagnostic_ids(initial)}}
        self.assertFalse(gate.fresh_restart_id(owner,"a","conn-1"))
        self.assertFalse(gate.fresh_restart_id(owner,"a","conn-9"))
        namespace={"time":gate.time,"json":json,"stat":gate.stat,"hashlib":hashlib,"re":__import__("re")}
        original=types.FunctionType((lambda:None).__code__,namespace)
        selected,_=gate.selected_fresh_witness(original)
        def snapshot(path):return {"scope":scope,"prefix":path.raw,"ids":gate.pq_diagnostic_ids(path.raw)}
        for replay in ("conn-1","conn-9"):
            ticks=iter((0,2,4,6))
            with self.subTest(replay=replay),patch.object(gate,"pq_diagnostic_snapshot",side_effect=snapshot),patch.object(gate.time,"monotonic",side_effect=lambda:next(ticks)),patch.object(gate.time,"sleep"):
                # Both consumed 1->2->1 and previously unconsumed other-route IDs stay old.
                diagnostic.raw=initial+encode([record(replay),record(replay,"ready")])
                with self.assertRaisesRegex(RuntimeError,"actual PQTLS ready/wake NOT_PROVEN"):
                    selected(owner,"a",require_fresh=True)
        diagnostic.raw=initial+encode([record("conn-3"),record("conn-3","ready")])
        diagnostic.growth=25  # Append after the captured complete read must not invalidate it.
        ticks=iter((0,1))
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=snapshot),patch.object(gate.time,"monotonic",side_effect=lambda:next(ticks)):
            self.assertEqual(selected(owner,"a",require_fresh=True)["observation_id"],"conn-3")
        diagnostic.growth=0;diagnostic.raw=initial
        owner._pq_restart_anchors={}
        with self.assertRaisesRegex(RuntimeError,"PQ_RESTART_ANCHOR_MISSING"):
            selected(owner,"a",require_fresh=True)
        ticks=iter((0,1))
        with patch.object(gate.time,"monotonic",side_effect=lambda:next(ticks)):
            self.assertEqual(selected(owner,"a",require_fresh=False)["observation_id"],"conn-2")

    def test_pre_stop_anchor_file_scope_and_malformed_bounds(self):
        raw=json.dumps({"schema_version":1,"event":"ready","observation_id":"conn-1"}).encode()+b"\n"
        for bad in (b"{}\n",b"[]\n",b"{",raw[:-1],raw.replace(b'"schema_version": 1',b'"schema_version": true'),raw.replace(b'"ready"',b'"unknown"'),raw.replace(b'"conn-1"',b'""'),b'{"schema_version":1,"schema_version":1}\n'):
            with self.subTest(malformed=True),self.assertRaises(RuntimeError):gate.pq_diagnostic_ids(bad)
        with patch.object(gate,"PQ_DIAGNOSTIC_MAX",10),self.assertRaises(RuntimeError):gate.pq_diagnostic_ids(raw)
        with patch.object(gate,"PQ_DIAGNOSTIC_ROWS_MAX",1),self.assertRaisesRegex(RuntimeError,"BOUNDS"):gate.pq_diagnostic_ids(raw+raw)
        scope=(1,10,1000,0o100600)
        path=types.SimpleNamespace(lstat=lambda:types.SimpleNamespace(st_dev=1,st_ino=10,st_uid=1000,st_mode=0o100600,st_size=len(raw)))
        owner=types.SimpleNamespace(nodes={"a":{"node_id":"node"}},result={"hub_forwarder_refresh":[{"owned_hub_container_id":"cid"}]},
            _pq_restart_anchors={"a":{"path":path,"node_id":"node","hub_id":"cid","scope":scope,"prefix":raw,"ids":frozenset({"conn-1"})}})
        gate.validate_restart_diagnostic(owner,"a",path,raw)
        # Captured FD differs even though the later path still matches the anchor.
        with patch.object(gate,"pq_diagnostic_snapshot",return_value={"scope":(1,11,1000,0o100600),"prefix":raw,"ids":frozenset({"conn-1"})}),self.assertRaisesRegex(RuntimeError,"FILE_SCOPE"):
            gate.read_restart_diagnostic(owner,"a",path)

        with self.assertRaisesRegex(RuntimeError,"FILE_SCOPE"):
            gate.validate_restart_diagnostic(owner,"a",path,raw.replace(b"conn-1",b"conn-2"))
        fake_stat=path.lstat()
        with patch.object(gate.os,"open",return_value=42) as opened,patch.object(gate.os,"fstat",return_value=fake_stat),patch.object(gate.os,"fdopen",return_value=io.BytesIO(raw)),patch.object(gate.os,"close") as closed:
            self.assertEqual(gate.pq_diagnostic_snapshot(path)["ids"],frozenset({"conn-1"}))
            self.assertEqual(opened.call_args.args[1],gate.os.O_RDONLY | gate.os.O_NOFOLLOW | gate.os.O_NONBLOCK)
            closed.assert_called_once_with(42)

        for inode,mode,uid,size in ((11,0o100600,1000,len(raw)),(10,0o120600,1000,len(raw)),(10,0o100644,1000,len(raw)),(10,0o100600,1001,len(raw)),(10,0o100600,1000,1)):
            path.lstat=lambda:types.SimpleNamespace(st_dev=1,st_ino=inode,st_uid=uid,st_mode=mode,st_size=size)
            with self.subTest(scope=True),self.assertRaises(RuntimeError):gate.validate_restart_diagnostic(owner,"a",path,raw)

    def test_pre_stop_anchor_both_sides_owned_order_and_cleanup_excluded(self):
        calls=[]
        class State:
            def __init__(self,letter):self.letter=letter
            def __truediv__(self,name):return self.letter
        owner=types.SimpleNamespace(hub="hub-name",hub_image="hub-image",run_id="run",args=types.SimpleNamespace(closed_failure_diagnostics=False),
            nodes={letter:{"paths":{"state":State(letter)},"node_id":letter} for letter in "ab"},
            result={"hub_forwarder_refresh":[{"owned_hub_container_id":"cid"}]})
        def inspect(*args):calls.append("inspect");return {"Id":"cid","Image":"hub-image","Config":{"Labels":{"org.cicada.test.run":"run"}}}
        owner.inspect=inspect
        def snapshot(path):calls.append("anchor-"+path);return {"scope":(1,1,1000,0o100600),"prefix":b"synthetic","ids":frozenset({"conn-1"})}
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=snapshot):gate.anchor_owned_restart(owner,"cid")
        self.assertEqual(calls,["inspect","anchor-a","anchor-b"])
        self.assertEqual(set(owner._pq_restart_anchors),{"a","b"})
        calls.clear();owner.inspect=lambda *args:{"Id":"foreign","Image":"hub-image","Config":{"Labels":{"org.cicada.test.run":"run"}}}
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=AssertionError("NO_FILE_READ")),self.assertRaisesRegex(RuntimeError,"OWNERSHIP"):
            gate.anchor_owned_restart(owner,"cid")
        self.assertEqual(calls,[])
        error=RuntimeError("owned provider transport failure")
        owner.policy=types.SimpleNamespace(phase="normal")
        owner.args.closed_failure_diagnostics=True
        def failed_limit(value):raise error
        owner.limit=failed_limit;owner.pq_transport_witness=lambda *args,**kwargs:None
        gate.install_closed_failure_diagnostics(owner)
        owner.inspect=lambda *args:owner.limit(1)
        with self.assertRaises(RuntimeError) as caught:gate.anchor_owned_restart(owner,"cid")
        self.assertIs(caught.exception,error)
        self.assertEqual([row["boundary"] for row in owner.result["closed_restart_failures"]],["LIMIT"])
        tree=ast.parse(Path(gate.__file__).read_text())
        candidate=next(node for node in ast.walk(tree) if isinstance(node,ast.ClassDef) and node.name=="CandidateGate")
        docker=next(node for node in candidate.body if isinstance(node,ast.FunctionDef) and node.name=="docker")
        branch=next(node for node in ast.walk(docker) if isinstance(node,ast.If) and 'not self.cleaning' in ast.unparse(node.test))
        self.assertIn("argv[0] == 'stop'",ast.unparse(branch.test))
        self.assertEqual(sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="anchor_owned_restart" for node in ast.walk(branch)),1)
        # Execute the actual owned docker method over a synthetic dispatch boundary.
        class Base:
            def docker(self,*args,**kwargs):calls.append("stop");return b""
        namespace={"Base":Base,"zero_model":False,"anchor_owned_restart":gate.anchor_owned_restart}
        method=ast.get_source_segment(Path(gate.__file__).read_text(),docker)
        exec(compile("class Installed(Base):\n"+"\n".join("    "+line for line in method.splitlines()),"<memory-owned-docker>","exec"),namespace)
        installed=namespace["Installed"]()
        installed.__dict__.update(hub="hub-name",hub_image="hub-image",run_id="run",cleaning=False,phase="zero_model_owned_hub_restart_transport",
            args=types.SimpleNamespace(closed_failure_diagnostics=False),nodes=owner.nodes,
            result={"hub_forwarder_refresh":[{"owned_hub_container_id":"cid"}]},inspect=inspect)
        calls.clear()
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=snapshot):installed.docker("stop","hub-name")
        self.assertEqual(calls,["inspect","anchor-a","anchor-b","stop"])
        calls.clear()
        def failed_b(path):
            calls.append("anchor-"+path)
            if path=="b":raise RuntimeError("PQ_RESTART_ANCHOR_MALFORMED")
            return snapshot_value
        snapshot_value={"scope":(1,1,1000,0o100600),"prefix":b"synthetic","ids":frozenset({"conn-1"})}
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=failed_b),self.assertRaises(RuntimeError):installed.docker("stop","hub-name")
        self.assertEqual(calls,["inspect","anchor-a","anchor-b"])
        calls.clear();installed.inspect=lambda *args:{"Id":"foreign","Image":"hub-image","Config":{"Labels":{"org.cicada.test.run":"run"}}}
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=AssertionError("NO_READ")),self.assertRaises(RuntimeError):installed.docker("stop","hub-name")
        self.assertEqual(calls,[])
        installed.cleaning=True;calls.clear()
        with patch.object(gate,"pq_diagnostic_snapshot",side_effect=AssertionError("NO_CLEANUP_READ")):installed.docker("stop","hub-name")
        self.assertEqual(calls,["stop"])



    def test_closed_restart_failure_enums_and_exception_identity(self):
        for literal, reason in gate.CLOSED_FAILURE_REASONS.items():
            with self.subTest(reason=reason):
                error = TimeoutError(literal) if reason == "ABSOLUTE_DEADLINE" else RuntimeError(literal)
                self.assertEqual(gate.closed_failure(error)["reason"], reason)
        class Hostile(RuntimeError):
            @property
            def args(self):
                raise AssertionError("diagnostics must not inspect subclass")
        for error in (Hostile(), RuntimeError("SYNTHETIC_PRIVATE_TOKEN"), RuntimeError(object()), KeyError("x"), ValueError("actual protected PQTLS state mismatch"), RuntimeError("CANDIDATE_ABSOLUTE_DEADLINE")):
            with self.subTest(kind=type(error) is RuntimeError):
                self.assertEqual(gate.closed_failure(error)["reason"], "UNKNOWN")
                self.assertNotIn("SYNTHETIC_PRIVATE_TOKEN", json.dumps(gate.closed_failure(error)))
        class HostileMeta(type):
            def __hash__(cls): raise AssertionError("NO_HASH")
            def __eq__(cls, other): raise AssertionError("NO_EQUALITY")
        class HostileMetaError(RuntimeError, metaclass=HostileMeta):
            @property
            def args(self): raise AssertionError("NO_ARGS")
            def __str__(self): raise AssertionError("NO_STR")
            def __repr__(self): raise AssertionError("NO_REPR")
        self.assertEqual(gate.closed_failure(HostileMetaError()),{"type":"UNKNOWN","reason":"UNKNOWN"})
        class HostileString(str):
            def __eq__(self,other): raise AssertionError("NO_STRING_EQUALITY")
        hostile_owner=types.SimpleNamespace(result={},policy=types.SimpleNamespace(phase=HostileString("normal")))
        gate.note_closed_failure(hostile_owner,RuntimeError("unknown"),HostileString("LIMIT"),HostileString("a"))
        self.assertEqual({key:hostile_owner.result["closed_restart_failures"][0][key] for key in ("boundary","side","phase")},
                         {"boundary":"UNKNOWN","side":"UNKNOWN","phase":"UNKNOWN"})

        error=RuntimeError("owned provider transport failure")
        owner=types.SimpleNamespace(result={},policy=types.SimpleNamespace(phase="normal"))
        def failing_limit(maximum): raise error
        def witness(letter, **flags): return owner.limit(5)
        owner.limit=failing_limit; owner.pq_transport_witness=witness
        gate.install_closed_failure_diagnostics(owner)
        with self.assertRaises(RuntimeError) as caught:
            owner.pq_transport_witness("b", require_fresh=True)
        self.assertIs(caught.exception,error)
        self.assertEqual(len(owner.result["closed_restart_failures"]),1)
        self.assertEqual(owner.result["closed_restart_failures"][0]["boundary"],"LIMIT")
        self.assertEqual(owner.result["closed_restart_failures"][0]["side"],"b")
        self.assertIs(owner.result["closed_restart_failures"][0]["require_fresh"],True)
        owner=types.SimpleNamespace(result={},policy=types.SimpleNamespace(phase="normal"),limit=lambda n:n)
        def failed_witness(letter, **flags): raise error
        owner.pq_transport_witness=failed_witness
        gate.install_closed_failure_diagnostics(owner)
        with patch.object(gate.time,"monotonic_ns",side_effect=RuntimeError("synthetic clock")):
            with self.assertRaises(RuntimeError) as caught: owner.pq_transport_witness("a", require_fresh=True)
        self.assertIs(caught.exception,error)
        self.assertIsNone(owner.result["closed_restart_failures"][0]["host_monotonic_ns"])
        self.assertEqual(owner.result["closed_restart_failures"][0]["boundary"],"FRESH_WITNESS")
        saved = owner.result["closed_restart_failures"][0].copy()
        for _ in range(20): gate.note_closed_failure(owner,error,"LIMIT","UNKNOWN")
        self.assertEqual(len(owner.result["closed_restart_failures"]),16)
        self.assertEqual(owner.result["closed_restart_failures"][0],saved)
        sentinel=object(); calls=[]
        success=types.SimpleNamespace(result={},policy=owner.policy,limit=lambda n:n)
        def success_witness(letter, **flags): calls.append((letter,flags)); return sentinel
        success.pq_transport_witness=success_witness
        gate.install_closed_failure_diagnostics(success)
        self.assertIs(success.pq_transport_witness("a",require_fresh=True),sentinel)
        self.assertEqual(calls,[("a",{"require_wake":False,"require_fresh":True})])
        self.assertEqual(success.result,{})
        state=types.SimpleNamespace(phase="explicit_zero_model_second_hub_restart",aborted=False,
            provider_errors={},provider_adapters={"a":types.SimpleNamespace(failures=0)},
            result={"actual_turn_started_count":2,"paid_turn_start_submissions":2})
        self.assertEqual(gate.closed_restart_state(state),{"operation":state.phase,
            "actual_turn_started_count":2,"manual_submission_count":2,"aborted":False,"provider_failed":False})
        state.phase="SYNTHETIC_PRIVATE_OPERATION";state.result["actual_turn_started_count"]=True
        state.result["paid_turn_start_submissions"]=7;state.aborted=1
        state.provider_adapters["a"].failures=-1
        self.assertEqual(gate.closed_restart_state(state),{"operation":"UNKNOWN",
            "actual_turn_started_count":None,"manual_submission_count":None,"aborted":None,"provider_failed":None})


    def test_explicit_zero_restart_ownership_order_and_default(self):
        calls=[]
        owner=types.SimpleNamespace(hub="owned-name",hub_image="owned-image",run_id="synthetic-run",
            result={"hub_forwarder_refresh":[{"owned_hub_container_id":"owned-id"}]})
        owner.step=lambda phase:calls.append(("phase",phase))
        def inspect(kind,name):
            calls.append(("inspect",kind,name))
            return {"Id":"owned-id","Image":"owned-image","Config":{"Labels":{"org.cicada.test.run":"synthetic-run"}}}
        owner.inspect=inspect
        owner.docker=lambda *args:calls.append(("docker",args))
        owner.start_hub=lambda:calls.append(("start",))
        owner.refresh_hub_forwarders=lambda phase:calls.append(("refresh",phase))
        gate.reproduce_owned_zero_restart(owner)
        self.assertEqual([row[0] for row in calls],["phase","inspect","docker","start","refresh"])
        self.assertEqual(calls[2][1],("stop","--time","1","owned-id"))
        self.assertEqual(owner.result["explicit_zero_restart"]["extra_restarts"],1)
        for key,value in (("Id","foreign-id"),("Image","foreign-image"),("Config",{"Labels":{}})):
            with self.subTest(key=key):
                calls.clear()
                actual={"Id":"owned-id","Image":"owned-image","Config":{"Labels":{"org.cicada.test.run":"synthetic-run"}}};actual[key]=value
                def denied_inspect(*args):
                    calls.append(("inspect",))
                    return actual
                owner.inspect=denied_inspect
                with self.assertRaises(RuntimeError):gate.reproduce_owned_zero_restart(owner)
                self.assertEqual([row[0] for row in calls],["phase","inspect"])
        tree=ast.parse(Path(run.__file__).read_text())
        prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="prepare_native_zero")
        branch=next(n for n in ast.walk(prepare) if isinstance(n,ast.If) and any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=="reproduce_owned_zero_restart" for stmt in n.body for x in ast.walk(stmt)))
        self.assertIn('reproduce_zero_hub_restart',ast.unparse(branch.test))
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main")
        option=next(n for n in ast.walk(main) if isinstance(n,ast.Call) and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=="--reproduce-zero-hub-restart")
        self.assertEqual(next(k.value.value for k in option.keywords if k.arg=="action"),"store_true")
        self.assertEqual(sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="reproduce_owned_zero_restart" for n in ast.walk(prepare)),1)
        with patch.object(run,"prepare_native_zero",side_effect=AssertionError("NO_DISPATCH")), redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(["--reproduce-zero-hub-restart"]),2)

    def test_g2_g3_selected_flow_keeps_original_oracle_and_six_turns(self):
        with run.deny_preflight_effects():
            sources = gate.effective_sources()
            namespace = {}
            prepared = gate.compile_g2_preparation_methods(sources['gate'],namespace)
            selected = gate.compile_g2_flow_methods(sources['gate'],namespace)
            self.assertEqual(set(prepared),{'prepare_managed','bind_mcp'})
            self.assertEqual(set(selected),{'audit_turn','audit_inline_reply','managed_golden_flow'})
            # The default source remains identical; scenario methods are local functions.
            self.assertEqual(sources,gate.effective_sources())
            code = selected['managed_golden_flow'].__code__
            text = '\n'.join(value for value in code.co_consts if type(value) is str)
            self.assertIn('cicada_leave_group',text)
            self.assertNotIn('Remember CICADA-ORIGINAL',text)
            self.assertIn('exact four manual and two automatic actual turns required',text)
            self.assertIn('actual_queue_original_a_receive_context',text)
            self.assertIn('managed_hub_blind_terminal_oracle',text)
            self.assertIn('g2-authorize-second',text)
            phase_ast=ast.parse(selected['managed_golden_flow']._g2_selected_source)
            calls=sorted((n for n in ast.walk(phase_ast) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='self'),key=lambda n:(n.lineno,n.col_offset))
            authorize=next(i for i,n in enumerate(calls) if n.func.attr=='helper' and n.args[0].value=='g2-authorize-second')
            self.assertEqual(calls[authorize-1].func.attr,'docker')
            self.assertEqual(calls[authorize-1].args[0].value,'stop')
            self.assertEqual([n.func.attr for n in calls[authorize+1:authorize+3]],['start_hub','refresh_hub_forwarders'])
            membership=next(i for i,n in enumerate(calls) if n.func.attr=='g2_second_binding')
            approve=next(i for i,n in enumerate(calls) if n.func.attr=='helper' and n.args[0].value=='approve')
            self.assertLess(authorize,membership);self.assertLess(membership,approve)

            protocol=gate.safe_module('g2_budget_test_public',gate.OLD/'managed_protocol.py')
            TurnBudget,ProtocolError=protocol.TurnBudget,protocol.ProtocolError
            for maximum,budget in ((5,TurnBudget()),(6,gate.g2_turn_budget(TurnBudget()))):
                budget.bind('a','original-a')
                for i in range(maximum):budget.observe('a',{'method':'turn/started','params':{'threadId':'original-a','turn':{'id':str(i)}}})
                with self.assertRaises(ProtocolError):budget.observe('a',{'method':'turn/started','params':{'threadId':'original-a','turn':{'id':'extra'}}})


            binding,_=run.bounded_json(run.BINDING)
            delivery,_=run.bounded_json(run.ACTUAL/'actual-delivery.json')
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,scenario='g2-g3')
            caps=gate.g2_cap_methods(cls.__mro__[2])
            cleanup_tree=ast.parse(caps['cleanup']._g2_cap_source)
            predicate=next(n.test for n in ast.walk(cleanup_tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='len(self.budget.started) > 6')
            check=compile(ast.Expression(predicate),'<late-cleanup-cap>','eval')
            for count,expected in ((5,False),(6,False),(7,True)):
                with self.subTest(late_cleanup=count):self.assertEqual(eval(check,{'self':types.SimpleNamespace(budget=types.SimpleNamespace(started=list(range(count))))}),expected)
            args=types.SimpleNamespace(scenario='g2-g3',unique_run='cicada-two-turn-syntheticg2cap',wiring_receipt_sha='a'*64,cleanup_hard_stop_unix=10000,delivery_sha='b'*64,preparation_result_sha='c'*64,preparation_review_sha='d'*64,equality_sha='e'*64)
            extended=dict(delivery,component_proof_sha256='f'*64)
            expected=run.expected_latest_go(binding,'a'*64,args,extended)
            self.assertEqual((expected['max_native_turns'],expected['max_manual_turns'],expected['max_automatic_turns']),(6,4,2))
            bad=dict(expected,max_native_turns=7)
            with self.assertRaises(PermissionError):run.validate_go(bad,expected,now=1000)
            args.scenario='g1'
            ordinary=run.expected_latest_go(binding,'a'*64,args,delivery)
            self.assertEqual((ordinary['max_native_turns'],ordinary['max_manual_turns'],ordinary['max_automatic_turns']),(5,3,2))
            names = code.co_names
            self.assertLess(names.index('g2_revoke_and_visibility'),names.index('stop_and_capture'))
            self.assertLess(names.index('stop_and_capture'),names.index('g3_restore_snapshot'))
            inline = selected['audit_inline_reply'].__code__
            self.assertIn('audit_turn',inline.co_names)
            self.assertIn('_g2_inline_reply_witness',inline.co_names)
            self.assertIn('alice_second_group_id',inline.co_consts)
            self.assertIn('link_id',inline.co_consts)
            with self.assertRaisesRegex(ValueError,'SCENARIO_UNSUPPORTED'):
                gate.load_gate({}, {}, inspect_only=True, scenario='unknown')

    def test_g2_selected_cleanup_preserves_closure_and_persists_terminal_result(self):
        with run.deny_preflight_effects():
            binding,_=run.bounded_json(run.BINDING)
            delivery,_=run.bounded_json(run.ACTUAL/'actual-delivery.json')
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,scenario='g2-g3')
            original=cls.__mro__[2].cleanup
            selected=cls.__mro__[1].cleanup
            def cells(method):
                return dict(zip(method.__code__.co_freevars,method.__closure__ or ()))
            original_inner=cells(original)['original_cleanup'].cell_contents
            selected_inner=cells(selected)['original_cleanup'].cell_contents
            pinned_base=cells(original_inner)['base'].cell_contents
            self.assertIs(selected_inner.__globals__['base'],pinned_base)
            self.assertEqual(original_inner.__code__.co_freevars,('base',))
            original_globals=dict(original_inner.__globals__)
            source_path=Path(gate.__file__)
            source_alias=selected_inner.__globals__['ROOT']/'source-binding.json'
            synthetic_manifest=json.dumps({'files':[{'path':str(source_path),
                'sha256':hashlib.sha256(source_path.read_bytes()).hexdigest()}]})
            read_text=Path.read_text
            def public_alias(path,*args,**kwargs):
                if path==source_alias:return synthetic_manifest
                return read_text(path,*args,**kwargs)
            for count in (0,6,7):
                with self.subTest(native_starts=count):
                    writes=[];operations=[]
                    namespace=dict(selected_inner.__globals__)
                    namespace['base']=types.SimpleNamespace(private_json=lambda path,result:
                        writes.append((path,copy.deepcopy(result))))
                    adapted_inner=types.FunctionType(selected_inner.__code__,namespace,
                        selected_inner.__name__,selected_inner.__defaults__,selected_inner.__closure__)
                    def cell(value):return (lambda:value).__closure__[0]
                    closure=tuple(cell(adapted_inner) if name=='original_cleanup' else value
                        for name,value in cells(selected).items())
                    adapted=types.FunctionType(selected.__code__,dict(selected.__globals__),
                        selected.__name__,selected.__defaults__,closure)
                    record={'Id':'synthetic-owned-id','Image':'synthetic-image',
                        'Config':{'Labels':{'org.cicada.test.run':'synthetic-cleanup'}},
                        'State':{'Running':False}}
                    def docker(*args):
                        self.assertEqual(args,('rm','synthetic-owned-id'));operations.append(args)
                    rpc=types.SimpleNamespace(shutdown_expected=False,
                        shutdown_eof=types.SimpleNamespace(wait=lambda timeout:True),
                        check=lambda:None,close=lambda:operations.append('rpc-close'))
                    fixture=types.SimpleNamespace(result={'status':'PREPARATION_PASS_NATIVE_NOT_RUN'},
                        policy=types.SimpleNamespace(cleanup=lambda:None,limit=lambda duration:duration),
                        rpcs={'a':rpc},containers={'synthetic-a':'synthetic-image'},
                        nodes={'a':{'container':'synthetic-a'}},run_id='synthetic-cleanup',
                        cleanup_inspect=lambda *args:copy.deepcopy(record),
                        inspect=lambda *args:copy.deepcopy(record),docker=docker,
                        close_provider_adapters=lambda:None,hub=None,networks=[],created_networks={},
                        provider_adapters={},audit_files={},projection_files={},uds_dirs={},
                        root=Path('/synthetic-private-state'),evidence=Path('/synthetic-evidence'),
                        result_paid_dispatches=0,manual_turn_ids=[],submitted_objects={},
                        budget=types.SimpleNamespace(started=list(range(count))))
                    with patch.object(Path,'read_text',public_alias):adapted(fixture)
                    self.assertEqual(len(writes),1)
                    self.assertEqual(writes[0][0],fixture.evidence/'result.json')
                    terminal=writes[0][1]
                    self.assertTrue(terminal['source_unchanged_during_gate'])
                    self.assertEqual(terminal['cleanup_owned_resources'],count<=6)
                    self.assertEqual(terminal['terminal_exit_code'],0 if count<=6 else 1)
                    self.assertEqual(terminal['observer_shutdown']['a'],
                        'EXPECTED_EOF_CONFIRMED' if count<=6 else 'UNKNOWN_RETAINED_SUBSCRIBER')
                    self.assertEqual(terminal['owned_cleanup_error_classes'],[] if count<=6 else ['RuntimeError'])
                    self.assertEqual('rpc-close' in operations,count<=6)
            self.assertEqual(original_inner.__globals__,original_globals)
            self.assertIs(cells(original_inner)['base'].cell_contents,pinned_base)

    def test_g2_link_dto_and_inline_strict_negative(self):
        with run.deny_preflight_effects():
            dto = types.SimpleNamespace(one=lambda items,tool: next(item for item in items if item['tool']==tool))
            result={'request_id':'rq-synthetic','message_id':'msg-synthetic','link_id':'link-synthetic',
                'status':'OPEN','reply_mode':'asynchronous','payload_mode':'SEALED_V1','delivery':'RELAY_PERSISTED'}
            payload={'operation':'ask','status':'SENT','retryable':False,'link_id':'link-synthetic',
                'request_id':'rq-synthetic','message_id':'msg-synthetic','result':result}
            item={'tool':'cicada_ask','arguments':{'link_id':'link-synthetic','data_scope':'thread.message','question':'synthetic question'}}
            request=gate.g2_accepted_ask(dto,item,payload,'ep-a','ep-b','synthetic question',{},'link-synthetic')
            for field,value in (('target','ep-b'),('data_scope','message.body'),('link_id','wrong')):
                with self.subTest(ask_field=field):
                    bad=copy.deepcopy(item);bad['arguments'][field]=value
                    with self.assertRaises(RuntimeError):gate.g2_accepted_ask(dto,bad,payload,'ep-a','ep-b','synthetic question',{},'link-synthetic')
            reply={'tool':'cicada_reply','arguments':{'request_id':'rq-synthetic','body':'synthetic BETA answer','link_id':'link-synthetic'}}
            r={'operation':'reply','status':'SENT','retryable':False,'link_id':'link-synthetic','request_id':'rq-synthetic','message_id':'reply-synthetic',
                'result':{'link_id':'link-synthetic','request_id':'rq-synthetic','message_id':'reply-synthetic','status':'REPLIED','payload_mode':'SEALED_V1','delivery':'RELAY_PERSISTED'}}
            accepted=gate.g2_accepted_reply(dto,[reply],lambda _:r,request,'synthetic BETA answer')
            self.assertEqual(accepted['reply_message_id'],'reply-synthetic')
            bad=copy.deepcopy(reply);del bad['arguments']['link_id']
            with self.assertRaises(RuntimeError):gate.g2_accepted_reply(dto,[bad],lambda _:r,request,'synthetic BETA answer')
            import importlib.util
            spec=importlib.util.spec_from_file_location('g2_inline_synthetic',gate.OLD/'inline_reply.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            original='01a115be-0c73-7fd0-86f6-4cc9c99a098e';turn='01a115bf-0c73-7fd0-86f6-4cc9c99a098e'
            expected={'message_id':'reply-synthetic','request_id':'rq-synthetic','reply_to':'msg-synthetic',
                'sender_endpoint_id':'ep-b','receiver_endpoint_id':'ep-a','group_id':'group-second','link_id':'link-synthetic'}
            user={'type':'userMessage','content':[{'type':'text','text':'Cicada SEALED_V1 REPLY. verified synthetic\n'+json.dumps(dict(expected,body='synthetic BETA answer'))}]}
            final={'type':'agentMessage','phase':'final_answer','text':'synthetic ALPHA synthetic BETA answer'}
            items=[{'threadId':original,'turnId':turn,'item':user},{'threadId':original,'turnId':turn,'item':final}]
            completion={'threadId':original,'turnId':turn,'status':'completed'}
            with patch.dict(sys.modules,{'inline_reply':module}):
                proof=gate.g2_inline_reply_witness(items,completion,original,turn,expected,('ALPHA','BETA'),'synthetic BETA answer',lambda _: {})
                self.assertTrue(proof['correct_answer'])
                items[-1]['item']['text']='synthetic BETA answer'
                with self.assertRaisesRegex(RuntimeError,'context/answer witness'):
                    gate.g2_inline_reply_witness(items,completion,original,turn,expected,('ALPHA','BETA'),'synthetic BETA answer',lambda _: {})
                items[-1]['item']['text']='synthetic ALPHA synthetic BETA answer'
                wrong=dict(expected,link_id='wrong')
                with self.assertRaisesRegex(RuntimeError,'exact correlation'):
                    gate.g2_inline_reply_witness(items,completion,original,turn,wrong,('ALPHA','BETA'),'synthetic BETA answer',lambda _: {})
            self.assertFalse(gate.g2_guard_denial(True,{'error':'timeout'}))
            self.assertFalse(gate.g2_guard_denial(False,{'status':'FAILED','retryable':True,'error':'communication link not found or not authorized'}))
            self.assertTrue(gate.g2_guard_denial(False,{'status':'FAILED','retryable':False,'error':'communication link not found or not authorized'}))

    def test_g2_current_mcp_and_g3_exact_readiness_admission(self):
        with run.deny_preflight_effects():
            binding,_=run.bounded_json(run.BINDING)
            delivery,_=run.bounded_json(run.ACTUAL/'actual-delivery.json')
            cls,_=gate.load_gate(delivery,binding,inspect_only=True,scenario='g2-g3')
            fixture=object.__new__(cls)
            fixture.run_id='cicada-two-turn-syntheticg2g3';fixture.test_image=run.LATEST_RUNTIME
            fixture.args=types.SimpleNamespace(runtime_image=run.LATEST_RUNTIME,latest_runtime=True)
            fixture.submitted_objects={};fixture.containers={};fixture.hub='own-hub';fixture.root=Path('/synthetic/owned');fixture.native_package=Path('/synthetic/package')
            fixture.result={'g3_hub_replacement':{'new_id':'a'*64}}
            fixture._g3_helper_hub_id='a'*64
            exact=gate.g3_readiness_argv(fixture,'a'*64)
            self.assertEqual(cls.register_submission(fixture,exact),('container',fixture.run_id+'-helper-g3-ready'))
            for label,change in (('network',('--network','bridge')),('entrypoint',('--entrypoint','sh')),('image',(run.LATEST_RUNTIME,run.RUNTIME))):
                with self.subTest(readiness=label):
                    bad=list(exact);index=bad.index(change[0]);bad[index+(0 if label=='image' else 1)]=change[1]
                    with self.assertRaises(RuntimeError):cls.register_submission(fixture,bad)
            fixture.nodes={'a':{'thread':'original-a','container':'own-a','node_id':'node-a','tls_config':'/synthetic/pq.json','current_group_id':'group-second'}}
            fixture.meta={'scenario':'g2-g3','group_id':'group-primary','alice_second_group_id':'group-second','owner_id':'owner-a','bob_owner_id':'owner-b','bob_group_id':'group-b'}
            captured=[]
            def boundary(*argv,**kwargs):
                captured.append((argv,kwargs))
                return (json.dumps({'id':1,'result':{}})+'\n'+json.dumps({'id':2,'result':{'structuredContent':{'endpoint_id':'ep-a'}}})+'\n').encode()
            fixture.docker=boundary
            bad,payload=gate.g2_mcp_call(fixture,'a','cicada_whoami',{})
            self.assertFalse(bad);self.assertEqual(payload['endpoint_id'],'ep-a')
            argv=captured[0][0]
            self.assertIn('CICADA_GROUP_ID=group-second',argv)
            self.assertIn('CICADA_NODE_PQTLS_CONFIG=/synthetic/pq.json',argv)
            self.assertIn('CODEX_THREAD_ID=original-a',argv)
            self.assertNotIn('turn/start',captured[0][1]['input_data'].decode())
            fixture.nodes['a'].update(endpoint='ep-a',binding_before={'id':'binding-a','epoch':7})
            card={'endpoint_id':'ep-a','native_session_id':'original-a','node_id':'node-a','group_id':'group-second','binding_id':'binding-a','binding_epoch':7}
            fixture.g2_mcp_call=lambda *args:(False,dict(card))
            self.assertEqual(gate.g2_current_actor(fixture,'a')['binding_id'],'binding-a')
            for key,value in (('endpoint_id','foreign'),('native_session_id','foreign'),('node_id','foreign'),('group_id','group-primary'),('binding_id','foreign'),('binding_epoch',8)):
                with self.subTest(actor_field=key):
                    altered=dict(card);altered[key]=value
                    fixture.g2_mcp_call=lambda *args:(False,altered)
                    with self.assertRaises(RuntimeError):gate.g2_current_actor(fixture,'a')
            self.assertTrue(gate.g2_guard_denial(True,{'error':'communication link is revoked'}))
            for payload in ({},{'error':'timeout'},{'status':'FAILED','retryable':False,'error':'protocol error'}):
                with self.subTest(denial=tuple(payload)):
                    self.assertFalse(gate.g2_guard_denial(False,payload))

    def test_g2_component_and_scenario_reject_old_authority(self):
        with run.deny_preflight_effects():
            actual_root = run.G2_BUILD_ROOT
            delivery,_ = run.bounded_json(actual_root/'mcp-fixed-actual-delivery.NONAUTH.json')
            equality,_ = run.bounded_json(actual_root/'mcp-fixed-compiled-input-equality.NONAUTH.json')
            self.assertEqual(run.g2_component_inputs(delivery,equality),delivery['component_proof_sha256'])
            old_delivery,_ = run.bounded_json(actual_root/'actual-delivery.NONAUTH.json')
            old_equality,_ = run.bounded_json(actual_root/'compiled-input-equality.NONAUTH.json')
            self.assertNotEqual(old_delivery['binary_sha256'],delivery['binary_sha256'])
            with self.assertRaises(PermissionError):run.g2_component_inputs(old_delivery,old_equality)
            for path in ('/gpu1-share/synthetic','/run/secrets/synthetic','/unknown/unowned.json'):
                with self.subTest(reference=path.split('/')[1]):
                    with patch.object(Path,'resolve',side_effect=AssertionError('UNAUTHORIZED_METADATA')):
                        with self.assertRaises(PermissionError):run.g2_public_path(path)
            with self.assertRaisesRegex(PermissionError,'SCENARIO_UNSUPPORTED'):
                run.scenario_inputs(types.SimpleNamespace(scenario='bad'),{})
            self.assertEqual(run.scenario_inputs(types.SimpleNamespace(scenario='g1'),{}),'g1')
            with self.assertRaisesRegex(PermissionError,'G2_FRESH_HELPER_REQUIRED'):
                run.scenario_inputs(types.SimpleNamespace(scenario='g2-g3'),{})
            with self.assertRaisesRegex(PermissionError,'G2_COMPONENT_EQUALITY_SCHEMA'):
                run.g2_component_inputs({}, {'schema':'cicada.compiled-input-equality.v1'})
            # Malformed/foreign source rows fail before any source read.
            for row in ({}, {'path':'/gpu1-share/synthetic','sha256':'0'*64,'bytes':1,'rawmode':0o100644},
                        {'path':'/synthetic','sha256':'0'*64,'bytes':True,'rawmode':0o100644}):
                with self.subTest(row_shape=sorted(row)):
                    with self.assertRaises(PermissionError):run.g2_public_row(row,paths=run.G2_SOURCE_PATHS)

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

    def test_g2_tls_overlay_is_exact_and_per_node(self):
        path = Path("/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/authority-bootstrap/tls_bootstrap.go")
        raw = path.read_bytes()
        changed = run.g2_tls_fixture_source(raw)
        self.assertNotEqual(changed, raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), run.G2_TLS_INPUT_SHA)
        self.assertIn(b'fixtureNodeScope(meta, n.id)', changed)
        self.assertIn(b'loadFixtureIdentity(fixtureRoot, "bob-owner-private", "owner.key")', changed)
        self.assertIn(b'db.GetClientDevice(old.OwnerID, deviceID)', changed)
        self.assertNotIn(b'n.binding.OwnerID!=meta.OwnerID', changed)
        self.assertTrue(changed.endswith(b"func init() { nativeTLSBootstrap = tlsBootstrap }\n"))
        with self.assertRaisesRegex(ValueError, "G2_TLS_INPUT_PIN"):
            run.g2_tls_fixture_source(raw + b"\n")
        with self.assertRaisesRegex(ValueError, "G2_TLS_INPUT_PIN"):
            run.g2_tls_fixture_source(raw.replace(b"same Owner identity", b"other Owner identity"))

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

    def test_installed_paid_bootstrap_observer_dispatch_exact_opt_in(self):
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
            cls,_=gate.load_gate(delivery,binding,inspect_only=True)
            original=['exec','-d','synthetic-runtime','python3','/state/server_bootstrap.py','paid','http://192.0.2.1:7890']
            for flag in (None,False,1,'true',True):
                with self.subTest(flag_type=type(flag),enabled=flag is True):
                    fixture=object.__new__(cls)
                    fixture.args=types.SimpleNamespace(response_byte_passthrough=False)
                    if flag is not None:fixture.args.test_request_observer=flag
                    fixture.result={};fixture.policy=types.SimpleNamespace(started=1000.0)
                    uploads=[];delegated=[]
                    fixture.command=lambda argv,**kwargs:uploads.append((argv,kwargs)) or b''
                    def base_boundary(owner,*argv,**kwargs):
                        delegated.append(list(argv));return b'SYNTHETIC_DELEGATED'
                    selected=original+['--test-request-observer',binding['upstream_base_url_sha256'],'1180.0','16'] if flag is True else original
                    payload_paths={gate.HERE/'request_observer_bootstrap.py',gate.LEGACY/'request-observer-integration.patch',gate.SCRIPTS/'native_request_observer_io.py'}
                    reads=[];original_read=Path.read_bytes
                    def read_boundary(path):
                        if path in payload_paths:
                            reads.append(path)
                            if flag is not True:raise AssertionError('OFF_PAYLOAD_READ')
                        return original_read(path)
                    with patch.object(cls.__mro__[1],'docker',base_boundary),patch.object(Path,'read_bytes',read_boundary):
                        self.assertEqual(fixture.docker(*selected),b'SYNTHETIC_DELEGATED')
                    self.assertEqual(len(delegated),1)
                    if flag is True:
                        self.assertEqual([row[0][-1] for row in uploads],
                            ['/tmp/request_observer_bootstrap.py','/tmp/request-observer-integration.patch','/tmp/native_request_observer_io.py'])
                        self.assertEqual(reads,[gate.HERE/'request_observer_bootstrap.py',gate.LEGACY/'request-observer-integration.patch',gate.SCRIPTS/'native_request_observer_io.py'])
                        self.assertEqual(delegated[0],gate.runtime_bootstrap_argv(selected,binding,1000.0))
                        self.assertIn('synthetic-runtime',fixture.result['effective_Runtime_bootstrap'])
                    else:
                        self.assertEqual(reads,[])
                        self.assertEqual(uploads,[])
                        self.assertEqual(delegated[0],original)
                        self.assertNotIn('effective_Runtime_bootstrap',fixture.result)
            zero_cls,_=gate.load_gate(delivery,binding,inspect_only=True,zero_model=True)
            fixture=object.__new__(zero_cls);fixture.args=types.SimpleNamespace(test_request_observer=False)
            fixture.nodes={};fixture.result={};calls=[]
            fixture.command=lambda *args,**kwargs:calls.append(args)
            with self.assertRaises(PermissionError):fixture.docker(*original)
            self.assertEqual(calls,[])
            offline=original[:5]+['offline','']
            delegated=[]
            def zero_boundary(owner,*argv,**kwargs):
                delegated.append(list(argv));return b'SYNTHETIC_OFFLINE'
            with patch.object(zero_cls.__mro__[1],'docker',zero_boundary),patch.object(Path,'read_bytes',side_effect=AssertionError('ZERO_PAYLOAD_READ')):
                self.assertEqual(fixture.docker(*offline),b'SYNTHETIC_OFFLINE')
            self.assertEqual(delegated,[offline]);self.assertEqual(calls,[])

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
            for key,value in (("execute_diagnostic",True),("go_receipt","SYNTHETIC_PAID"),("preparation_result","SYNTHETIC_PAID"),
                              ("reproduce_zero_hub_restart",1),("runtime_image",run.RUNTIME),
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

    def test_drained_upstream_eof_halfclose_is_connection_only(self):
        with run.deny_preflight_effects():
            binding,_=run.verify_binding()
            delivery,_=run.bounded_json(run.ACTUAL/"actual-delivery.json")
            candidate,_=gate.load_gate(delivery,binding,inspect_only=True)
            original=candidate.provider_forwarder.__globals__["Forwarder"]
            run_id="cicada-two-turn-synthetichalfclose1"
            record={"run_id":run_id,"network_id":"a"*64,"network_name":run_id+"-a-net","network_label":run_id,
                "driver":"bridge","subnet":"172.29.0.0/24","gateway":"172.29.0.1","clients":["172.29.0.2"],
                "lifetime":10,"max_connections":4,"max_active":1,"upstream_host":"127.0.0.1","upstream_port":7890}
            actual={"Id":"a"*64,"Name":record["network_name"],"Driver":"bridge","Labels":{"org.cicada.test.run":run_id},
                "IPAM":{"Config":[{"Subnet":record["subnet"],"Gateway":record["gateway"]}]},"Containers":{"b"*64:{"IPv4Address":"172.29.0.2/24"}}}
            class Sock:
                def __init__(self,events=(),shutdown_error=None):self.events=list(events);self.shutdown_error=shutdown_error;self.close_count=0
                def setblocking(self,value):pass
                def recv(self,n):
                    value=self.events.pop(0) if self.events else b""
                    if isinstance(value,BaseException):raise value
                    return value
                def send(self,data):return len(data)
                def shutdown(self,how):
                    if self.shutdown_error is not None:raise self.shutdown_error
                def close(self):self.close_count+=1
            def create(client,upstream,mode="upstream-first",diagnostics=True):
                def ready(readers,writers,errors,timeout):
                    if writers:return [],writers,[]
                    if mode=="both":return list(readers),[],[]
                    if mode=="pending":return [client,upstream],[],[]
                    first,second=(upstream,client) if mode=="upstream-first" else (client,upstream)
                    return ([first] if first in readers else [second] if second in readers else []),[],[]
                value=original(record,actual,clock=lambda:0,connect=lambda *args,**kwargs:upstream,select_ready=ready)
                gate.install_client_read_cancellation(value,io_diagnostics_v2=diagnostics)
                self.assertTrue(value.admit(client,("172.29.0.2",50000)))
                return value
            client=Sock(shutdown_error=OSError(107,"SYNTHETIC_PRIVATE_ERROR"));up=Sock()
            value=create(client,up);value.relay(client)
            self.assertEqual((value.failures,value.drained_upstream_eof_cancellations,value.peer_error_disconnects,value.active),(0,1,1,0))
            self.assertFalse(value.closed);self.assertIsNone(value.first_fatal_io)
            self.assertEqual((client.close_count,up.close_count),(1,1))
            self.assertEqual(value.summary()["last_drained_upstream_eof_cancellation"],{
                "classification":"CLIENT_HALFCLOSE_CANCELLED_CONNECTION_ONLY","stage":"halfclose_client","errno":107,
                "application_completion":"UNKNOWN","upstream_eof":True,"client_eof":False,"pending_client_bytes":0,"pending_upstream_bytes":0})
            self.assertNotIn("SYNTHETIC_PRIVATE_ERROR",json.dumps(value.summary()))
            second=Sock();second_up=Sock();value.connect=lambda *args,**kwargs:second_up
            value.select_ready=lambda readers,writers,errors,timeout: (([second] if second in readers else [second_up] if second_up in readers else []),writers,[])
            self.assertTrue(value.admit(second,("172.29.0.2",50001)));value.relay(second)
            self.assertEqual((value.accepted,value.failures,value.drained_upstream_eof_cancellations,value.clean_eof_disconnects,value.active),(2,0,1,1,0))
            self.assertEqual((second.close_count,second_up.close_count),(1,1))
            class Subclass(OSError):pass
            for label,client,up,mode in (
                ("pending_upstream",Sock([b"buffered"],OSError(107,"synthetic")),Sock(),"pending"),
                ("wrong_errno",Sock(shutdown_error=OSError(108,"synthetic")),Sock(),"upstream-first"),
                ("subclass",Sock(shutdown_error=Subclass(107,"synthetic")),Sock(),"upstream-first"),
                ("wrong_stage",Sock(),Sock(shutdown_error=OSError(107,"synthetic")),"client-first"),
                ("upstream_eof_absent",Sock(shutdown_error=OSError(107,"synthetic")),Sock([b"data",ConnectionResetError(104,"synthetic")]),"client-first")):
                with self.subTest(fatal=label):
                    fatal=create(client,up,mode);fatal.relay(client)
                    self.assertEqual((fatal.failures,fatal.drained_upstream_eof_cancellations,fatal.active),(1,0,0))
                    self.assertIsNotNone(fatal.first_fatal_io)
                    self.assertEqual((client.close_count,up.close_count),(1,1))
            # Preserve the original both-EOF branch; no second cancellation increment.
            client=Sock(shutdown_error=OSError(107,"synthetic"));up=Sock();both=create(client,up,"both");both.relay(client)
            self.assertEqual((both.failures,both.drained_enotconn_disconnects,both.drained_upstream_eof_cancellations),(0,1,0))
            plain=create(Sock(shutdown_error=OSError(107,"synthetic")),Sock(),diagnostics=False)
            plain.relay(next(sock for sock in plain.sockets if sock.shutdown_error is not None))
            self.assertFalse(hasattr(plain,"first_fatal_io"));self.assertNotIn("first_fatal_io",plain.summary())
            self.assertEqual(plain.drained_upstream_eof_cancellations,1)

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
            # Remove ONLY the two owned additions: all remaining relay AST is identical.
            raw=ast.parse((gate.OLD/"provider_transport.py").read_bytes())
            cls=next(n for n in raw.body if isinstance(n,ast.ClassDef) and n.name=="Forwarder")
            old=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=="relay")
            new=ast.parse(gate.client_read_cancellation_relay_source()).body[0]
            outer=next(n for n in new.body if isinstance(n,ast.Try));branch=outer.handlers[0].body[-1]
            cancellation=branch.orelse[0]
            self.assertIn("type(error) is ConnectionResetError",ast.unparse(cancellation.test))
            drained=cancellation.orelse[0]
            self.assertIn("type(error) is OSError",ast.unparse(drained.test))
            self.assertIn("stage == 'halfclose_client'",ast.unparse(drained.test))
            branch.orelse=drained.orelse
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
        original.body.insert(original.body.index(setup)+1,ast.parse("_install_client_read_cancellation(self, adapter)").body[0])
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

    def test_closed_native_error_classification_literals_and_privacy(self):
        fields={"category":"other","http_status_code":None,"will_retry":False}
        prefix="stream disconnected before completion: "
        cases=(("stream closed before response.completed","STREAM_CLOSED_BEFORE_COMPLETED"),
            ("idle timeout waiting for SSE","SSE_IDLE_TIMEOUT"),
            ("Incomplete response returned, reason: content_filter","CONTENT_FILTER"),
            ("Incomplete response returned, reason: unknown","INCOMPLETE_REASON_UNKNOWN"),
            ("failed to parse ResponseCompleted: SYNTHETIC_SECRET","RESPONSE_COMPLETED_PARSE_ERROR"),
            ("failed to parse ResponseCompleted: ","STREAM_DETAIL_WITHHELD"),
            ("SYNTHETIC_SECRET","STREAM_DETAIL_WITHHELD"))
        for detail,label in cases:
            with self.subTest(label=label,detail_empty=not detail):
                result=gate.closed_native_error_classification({"error":{"message":prefix+detail}},fields)
                self.assertEqual(result["classification"],label)
                self.assertNotIn("SYNTHETIC_SECRET",json.dumps(result))
                self.assertFalse(result["message_exported"])
                self.assertFalse(result["cause_proven"])
        for message in ("SYNTHETIC_SECRET",prefix+"x"*16384,None,42):
            self.assertEqual(gate.closed_native_error_classification({"error":{"message":message}},fields)["classification"],"UNKNOWN")
        self.assertEqual(gate.closed_native_error_classification({"error":{"message":prefix+cases[0][0]}},dict(fields,category="httpConnectionFailed"))["classification"],"UNKNOWN")

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
            literal_valid=json.loads(json.dumps(valid))
            literal_valid["params"]["error"]["message"]="stream disconnected before completion: idle timeout waiting for SSE"
            fixture=Fixture()
            def observe_before_abort(error):
                record=fixture.result["native_error_closed_diagnostic"]
                checks.assertEqual(record["classification"],"SSE_IDLE_TIMEOUT")
                checks.assertEqual((record["node"],record["thread_id"],record["turn_id"]),
                    ("a","synthetic-thread-a","synthetic-turn-a"))
                checks.assertEqual(record["host_monotonic_seconds"],clock[0])
                checks.assertIs(error,fixture._observer_native_failures[threading.get_ident()][0])
            fixture.abort_owned=observe_before_abort
            with checks.assertRaises(RuntimeError):
                namespace["terminal"](fixture,"a","received",literal_valid)
            first=fixture.result["native_error_closed_diagnostic"]
            fixture.budget.started.append(("b","synthetic-turn-b"))
            later=json.loads(json.dumps(literal_valid))
            later["params"].update(threadId="synthetic-thread-b",turnId="synthetic-turn-b")
            later["params"]["error"]["message"]="stream disconnected before completion: stream closed before response.completed"
            fixture.abort_owned=lambda error:checks.assertIs(fixture.result["native_error_closed_diagnostic"],first)
            with checks.assertRaises(RuntimeError):
                namespace["terminal"](fixture,"b","received",later)
            checks.assertIs(fixture.result["native_error_closed_diagnostic"],first)
            for flag,seconds,thread,started in ((False,5,"synthetic-thread-a",[("a","synthetic-turn-a")]),
                    (1,5,"synthetic-thread-a",[("a","synthetic-turn-a")]),
                    (True,True,"synthetic-thread-a",[("a","synthetic-turn-a")]),
                    (True,4,"synthetic-thread-a",[("a","synthetic-turn-a")]),
                    (True,5,"synthetic-foreign",[("a","synthetic-turn-a")]),
                    (True,5,"synthetic-thread-a",[("a","synthetic-turn-a"),("a","synthetic-busy")])):
                fixture=Fixture();fixture.args.test_request_observer=flag
                fixture.args.go["max_fatal_diagnostic_capture_seconds"]=seconds
                fixture.nodes["a"]["thread"]=thread;fixture.budget.started=started
                primary=RuntimeError("SYNTHETIC_PRIMARY")
                fixture.abort_owned=lambda error:checks.assertIs(error,primary)
                gate.mark_native_failure(fixture,primary,"a","received",valid,namespace["safe_error_diagnostic"](valid["params"]))
                checks.assertNotIn("native_error_closed_diagnostic",fixture.result)
            fixture=Fixture();primary=RuntimeError("SYNTHETIC_PRIMARY")
            fixture.abort_owned=lambda error:checks.assertIs(error,primary)
            with patch.object(gate,"closed_native_error_classification",side_effect=KeyboardInterrupt):
                gate.mark_native_failure(fixture,primary,"a","received",valid,namespace["safe_error_diagnostic"](valid["params"]))
            checks.assertIs(fixture._observer_native_failures[threading.get_ident()][0],primary)
            checks.assertNotIn("native_error_closed_diagnostic",fixture.result)
            for timeout,start in ((False,1000.0),(True,1230.0),(False,1238.0)):
                observed.clear();clock[0]=start;fixture=Fixture(timeout)
                with self.assertRaises(RuntimeError) as raised:
                    namespace["terminal"](fixture,"a","received",valid)
                primary=raised.exception
                checks.assertIs(primary,fixture._observer_native_failures[threading.get_ident()][0])
                checks.assertEqual(fixture.result["native_error_closed_diagnostic"]["classification"],"UNKNOWN")
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
