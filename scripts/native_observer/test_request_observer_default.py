"""Deterministic default-daemon selectors; no Docker, models or credentials."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import threading
import sys
import types
import unittest
from unittest.mock import MagicMock, Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('default_fixture_test_subject', HERE/'request_observer_default.py')
subject = importlib.util.module_from_spec(spec); spec.loader.exec_module(subject)


class MemorySocket:
    def __init__(self, data=b''):
        self.data=data;self.sent=bytearray();self.closed=False
    def recv(self, count):
        data,self.data=self.data[:count],self.data[count:];return data
    def sendall(self, data):self.sent.extend(data)
    def settimeout(self, timeout):pass
    def close(self):self.closed=True


class ExecutionSourceChecks(unittest.TestCase):
    def setUp(self):
        self.repo=HERE.parents[1]
        self.head=subprocess.run(['git','-C',str(self.repo),'rev-parse','HEAD'],
            capture_output=True,check=True,timeout=5).stdout.decode().strip()
        mapper=patch.object(subject,'Path',side_effect=self.source_path)
        mapper.start();self.addCleanup(mapper.stop)
        self.paths={str(HERE/name):hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('request_observer_default.py','test_request_observer_default.py','request_observer_gate.py','request_observer_run.py')}
        self.fixture=dict.fromkeys({'schema','fixture_revision','fixture_source_dirty','helper_producer_revision',
            'fixture_files','module_sha256','product_revision','socket_roots','private_root','credential_path',
            'official_package','origin_receipt','origin_receipt_sha256','origin_url','package_receipt',
            'runtime_image','runtime_receipt_path'},'PUBLIC_SYNTHETIC_UNUSED')
        self.fixture.update(schema=subject.FIXTURE_SCHEMA_V2,fixture_revision=self.head,fixture_source_dirty=True,
            helper_producer_revision=subject.HELPER_PRODUCER_REVISION,fixture_files=self.paths,
            module_sha256=self.paths[str(HERE/'request_observer_default.py')],
            product_revision='328f5b5fa69571e67e7bb3e4582d5fb3bb920fd7',socket_roots={'a':'/tmp/public-a','b':'/tmp/public-b'})
        self.binding={'current_bundle':{'current_commit':self.fixture['product_revision']},
            'public_files':{p:{'sha256':sha} for p,sha in self.paths.items() if Path(p).name in
                ('request_observer_gate.py','request_observer_run.py')}}

    def source_path(self,value,*parts):
        if value == subject.__file__ and not parts:
            return self.repo/'scripts/native_observer/request_observer_default.py'
        return Path(value,*parts)

    def run_module(self,name):
        spec=importlib.util.spec_from_file_location(name,HERE/'request_observer_run.py')
        run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
        original=run.safe_overlay
        def overlay(name):
            return subject if name == 'request_observer_default' else original(name)
        selected=patch.object(run,'safe_overlay',side_effect=overlay)
        selected.start();self.addCleanup(selected.stop)
        return run

    def git(self,head=None,dirty=True):
        def execute(argv,**kwargs):
            if argv[-2:]==['rev-parse','HEAD']:data=(head or self.head).encode()+b'\n'
            elif argv[-3:]==['status','--porcelain','--untracked-files=normal']:data=b' M public.py\n' if dirty else b''
            elif argv[-4:]==['--','cicada-go','VERSION','LICENSE']:data=b''
            else:raise AssertionError('unexpected effect')
            return subprocess.CompletedProcess(argv,0,data,b'')
        return patch.object(subject.subprocess,'run',side_effect=execute)

    def test_v2_real_head_exact_bytes_and_later_commit_are_accepted_v1_stays_historical(self):
        with self.git():identity=subject.check_fixture(self.fixture,self.binding)
        self.assertEqual(identity['fixture_revision'],self.head)
        future=dict(self.fixture,fixture_revision='a'*40,fixture_source_dirty=False)
        with self.git(head='a'*40,dirty=False):self.assertEqual(subject.check_fixture(future,self.binding)['fixture_revision'],'a'*40)
        old=dict(self.fixture,schema='cicada.native-default-peer-fixture.v1',fixture_revision=subject.HELPER_PRODUCER_REVISION)
        old.pop('fixture_source_dirty');old.pop('helper_producer_revision')
        with self.git(head='b'*40),self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_REVISION'):
            subject.check_fixture(old,self.binding)

    def test_revision_dirty_helper_product_and_public_binding_must_match(self):
        for key,value in [('fixture_revision','not-a-revision'),('fixture_revision',None),
                          ('fixture_source_dirty',1),('helper_producer_revision',self.head),
                          ('product_revision',self.head),('module_sha256','0'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                subject.fixture_source_identity(dict(self.fixture,**{key:value}),self.binding)
        for value in ('a'*40,'b'*40):
            with self.git(),self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_REVISION'):
                subject.check_fixture(dict(self.fixture,fixture_revision=value),self.binding)
        with self.git(dirty=False),self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_DIRTY_STATE'):
            subject.check_fixture(self.fixture,self.binding)
        for key in self.paths:
            rows=dict(self.paths);rows[key]='0'*64
            with self.subTest(path=Path(key).name),self.assertRaisesRegex(ValueError,'SOURCE_CHANGED'):
                subject.fixture_source_identity(dict(self.fixture,fixture_files=rows),self.binding)
        wrong=copy.deepcopy(self.binding);wrong['public_files'][str(HERE/'request_observer_run.py')]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_BINDING_SOURCE'):
            subject.fixture_source_identity(self.fixture,wrong)
        with self.assertRaises(ValueError):subject.fixture_source_identity(dict(self.fixture,extra='refused'),self.binding)

    def test_pinned_manifest_go_and_zero_preparation_bind_current_execution_not_old_helper(self):
        run=self.run_module('execution_source_run')
        with tempfile.TemporaryDirectory(prefix='public-source-manifest-') as root:
            path=Path(root)/'fixture.json';path.write_text(json.dumps(self.fixture))
            args=types.SimpleNamespace(default_daemon_fixture=str(path),default_daemon_fixture_sha=run.digest(path),
                unique_run='public',wiring_receipt_sha='a'*64,cleanup_hard_stop_unix=0,native_normal_seconds=600,
                scenario='g2-g3',native_https=False,response_byte_passthrough=False,delivery_sha='b'*64,
                preparation_result_sha='c'*64,preparation_review_sha='d'*64,equality_sha='e'*64)
            identity=run.validate_default_preparation_source(args,self.binding,
                {'default_fixture_source':subject.fixture_source_identity(self.fixture,self.binding)})
            for captured in (None,dict(identity,fixture_revision=subject.HELPER_PRODUCER_REVISION),
                             dict(identity,fixture_source_dirty=1),dict(identity,fixture_files={}),
                             dict(identity,helper_producer_revision=self.head)):
                with self.assertRaisesRegex(PermissionError,'LATEST_DEFAULT_PREPARATION_SOURCE'):
                    run.validate_default_preparation_source(args,self.binding,{'default_fixture_source':captured})
            with self.assertRaises(PermissionError):run.validate_default_preparation_source(args,self.binding,{})
            delivery=dict.fromkeys(('hub_image','commit','binary_sha256','helper_sha256','fingerprint','component_proof_sha256'),'a'*64)
            bundle={'runtime_receipt':{'image_id':'sha256:'+'f'*64}}
            with patch.object(run,'expected_go',return_value={}),patch.object(run,'require_current_bundle',return_value=bundle),\
                 patch.object(run,'current_cli',return_value={'sha256':'e'*64,'version':'0.162.1'}),\
                 patch.object(run,'default_fixture_source',wraps=run.default_fixture_source):
                expected=run.expected_latest_go(self.binding,'a'*64,args,delivery)
            self.assertEqual(expected['fixture_revision'],self.head)
            self.assertEqual(expected['default_daemon_fixture_sha256'],run.digest(path))
            # No GO is written; exact-field comparator rejects changed source/revision pins.
            for key in ('fixture_revision','default_daemon_fixture_sha256'):
                malformed=dict(expected,**{key:'0'*len(expected[key])},expires_at_unix=int(time.time())+100)
                with self.assertRaises(PermissionError):run.validate_go(malformed,expected)
            path.write_text(json.dumps(dict(self.fixture,fixture_revision='a'*40)))
            with self.assertRaisesRegex(PermissionError,'DEFAULT_FIXTURE_BYTE_PIN'):
                run.default_fixture_source(args,self.binding)

    def test_real_install_entry_accepts_v2_scope_then_stops_before_dependencies_or_effects(self):
        self.binding['current_bundle']['runtime_receipt']={'path':self.fixture['runtime_receipt_path']}
        with self.git(),patch.object(subject,'verify_dependencies',side_effect=PermissionError('PURE_EFFECT_BOUNDARY')) as denied:
            with self.assertRaisesRegex(PermissionError,'PURE_EFFECT_BOUNDARY'):
                subject.install(object,self.binding,600,fixture=self.fixture,gate_module=None)
            denied.assert_called_once_with(self.binding)
        for schema,budget in [('unknown',600),(subject.FIXTURE_SCHEMA_V2,180)]:
            with patch.object(subject,'verify_dependencies') as denied,self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_SCOPE'):
                subject.install(object,self.binding,budget,fixture=dict(self.fixture,schema=schema),gate_module=None)
            denied.assert_not_called()

    def test_actual_execute_rejects_stale_head_before_credential_metadata(self):
        run=self.run_module('stale_execution_run')
        with tempfile.TemporaryDirectory(prefix='public-stale-execution-') as root:
            parent=Path(root);binding=dict(self.binding,output_parent=str(parent))
            fixture=parent/'fixture.json';fixture.write_text(json.dumps(dict(self.fixture,fixture_revision='a'*40)))
            receipt=parent/'request-observer-wiring-public.json'
            receipt.write_text(json.dumps({'status':'PASS','candidate_binding_sha256':'b'*64,
                'Runtime_calls':0,'provider_POSTs':0,'model_calls':0}))
            expected={'result_dir':str(parent/'uncreated-result'),'claim_file':str(parent/'uncreated-claim'),
                'cleanup_hard_stop_unix':int(time.time())+700,'total_seconds':660}
            go=parent/'request-observer-public.json';go.write_text(json.dumps(dict(expected,expires_at_unix=int(time.time())+100)))
            args=types.SimpleNamespace(default_daemon_fixture=str(fixture),default_daemon_fixture_sha=run.digest(fixture),
                scenario='g2-g3',native_normal_seconds=600,preparation_result='public',preparation_result_sha='c'*64,
                go_receipt=str(go),go_receipt_sha=run.digest(go),binding_sha='b'*64,wiring_receipt=str(receipt),
                wiring_receipt_sha=run.digest(receipt),unique_run='public',cleanup_hard_stop_unix=int(time.time())+700)
            original=Path.lstat;credential_calls=[]
            def safe_stat(path,*a,**kw):
                if str(path)==run.CREDENTIAL:credential_calls.append(True);raise AssertionError('credential touched')
                return original(path,*a,**kw)
            with self.git(),patch.object(run,'latest_dispatch_inputs',return_value=(binding,'b'*64,{},{})),\
                 patch.object(run,'expected_latest_go',return_value=expected),patch.object(Path,'lstat',safe_stat):
                with self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_REVISION'):run.execute(args)
            self.assertEqual(credential_calls,[])
            self.assertFalse((parent/'uncreated-claim').exists());self.assertFalse(run.EXECUTION_EFFECTS_STARTED)

    def test_exact_path_and_loader_mapping_validate_a_different_public_source_directory(self):
        self.assertEqual(subject.Path(subject.__file__).resolve().parents[2],self.repo)
        for value in ('/home/zyf/CICADA-other','/tmp/public','relative',Path('/home/zyf/CICADA')):
            self.assertEqual(subject.Path(value),Path(value))
        self.assertEqual(subject.Path('/home/zyf/CICADA','child'),Path('/home/zyf/CICADA','child'))
        run=self.run_module('relocated_execution_source_run')
        self.assertIs(run.safe_overlay('request_observer_default'),subject)
        delegated=run.safe_overlay('request_observer_binding')
        self.assertEqual(Path(delegated.__file__),HERE/'request_observer_binding.py')
        self.assertIsNot(delegated,subject)
        with tempfile.TemporaryDirectory(prefix='public-four-source-fixture-') as root:
            self.repo=Path(root);directory=self.repo/'scripts/native_observer';directory.mkdir(parents=True)
            rows={}
            for name in ('request_observer_default.py','test_request_observer_default.py',
                         'request_observer_gate.py','request_observer_run.py'):
                path=directory/name;path.write_bytes((HERE/name).read_bytes())
                rows[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
            fixture=dict(self.fixture,fixture_files=rows,module_sha256=rows[str(directory/'request_observer_default.py')])
            binding={'current_bundle':self.binding['current_bundle'],
                'public_files':{p:{'sha256':sha} for p,sha in rows.items() if Path(p).name in
                    ('request_observer_gate.py','request_observer_run.py')}}
            with self.git():identity=subject.check_fixture(fixture,binding)
            self.assertEqual(identity['fixture_files'],rows)
            stale=dict(fixture,fixture_files=self.paths)
            with self.assertRaisesRegex(ValueError,'DEFAULT_FIXTURE_SOURCE_ROWS'):
                subject.fixture_source_identity(stale,binding)
            manifest=self.repo/'public-fixture.json';manifest.write_text(json.dumps(fixture))
            args=types.SimpleNamespace(default_daemon_fixture=str(manifest),default_daemon_fixture_sha=run.digest(manifest))
            self.assertEqual(run.default_fixture_source(args,binding)[1],identity)


@unittest.skipUnless(all(Path(path).is_file() for path in subject.DEPENDENCY_PINS),
                     'pinned Peer source is absent in a fresh checkout')
class RealGuardMetadataChecks(unittest.TestCase):
    def setUp(self):
        self.library=subject.load_dependency('peer_outer_broker',subject.PEER/'peer_outer_broker.py')
        spec=importlib.util.spec_from_file_location('default_guard_gate',HERE/'request_observer_gate.py')
        self.gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.gate)

    def native(self):
        lib=self.library;association=lib.CORE.Association('00000000-0000-4000-8000-000000000001',
            '00000000-0000-4000-8000-000000000002',1)
        native=object.__new__(lib.PeerNativeBroker);events=[];io=[];reads=[]
        lib.CORE.Observer.__init__(native,'https://api.zzswitch.com/v1/responses','PUBLIC_ALPHA',events.append,
            enabled=True,bound_thread=association.thread,max_connections=16,io_sink=io.append,io_diagnostics_v2=True)
        native.response_metadata=False;native.response_guard=None;native.closed_phases=[];native.headers_prepared=0
        native.association=association
        native.credential_reader=lambda:reads.append(True) or 'PUBLIC_SYNTHETIC_ONLY_TOKEN'
        return native,events,io,reads

    def test_phase_capacity_old_sixth_connect_is_red_new_sixteen_are_green(self):
        phases=('ORIGIN_CONNECT','ORIGIN_PROXY_CONNECTED','ORIGIN_PROXY_CONNECT_ACCEPTED',
            'ORIGIN_TLS_VERIFIED','HEADER_PREPARATION','HEADER_PREPARED_SEND_UNKNOWN')
        original,*_=self.native()
        for _ in range(5):
            for phase in phases:original.note_phase(phase)
        for phase in phases[:2]:original.note_phase(phase)
        with self.assertRaisesRegex(self.library.NATIVE.Failure,'BROKER_PHASE_BOUNDS'):
            original.note_phase(phases[2])
        self.assertEqual(len(original.closed_phases),32);self.assertEqual(original.headers_prepared,5)
        selected,*_=self.native();other,*_=self.native()
        original_method=self.library.NATIVE.NativeBroker.note_phase
        class_method=self.library.PeerNativeBroker.note_phase
        proof=subject.install_phase_capacity(selected,self.library)
        for _ in range(16):
            for phase in phases:selected.note_phase(phase)
        self.assertEqual(len(selected.closed_phases),96);self.assertEqual(selected.headers_prepared,16)
        self.assertEqual(proof['new_phase_limit'],128)
        self.assertEqual(subject.phase_capacity_snapshot(selected),{'status':'MEASURED','capacity':128,
            'current_length':96,'headers_prepared':16})
        self.assertIs(self.library.NATIVE.NativeBroker.note_phase,original_method)
        self.assertIs(self.library.PeerNativeBroker.note_phase,class_method)
        self.assertIs(other.note_phase.__func__,original_method)
        before=list(selected.closed_phases)
        with self.assertRaisesRegex(self.library.NATIVE.Failure,'BROKER_PHASE_BOUNDS'):
            selected.note_phase('INVALID_SYNTHETIC_PHASE')
        self.assertEqual(selected.closed_phases,before)
        for _ in range(32):selected.note_phase('ORIGIN_CONNECT')
        with self.assertRaisesRegex(self.library.NATIVE.Failure,'BROKER_PHASE_BOUNDS'):
            selected.note_phase('ORIGIN_CONNECT')
        self.assertEqual(len(selected.closed_phases),128)
        self.assertEqual(selected.headers_prepared,16)
        with self.assertRaisesRegex(ValueError,'DEFAULT_PHASE_INSTANCE_SCOPE'):
            subject.install_phase_capacity(selected,self.library)

    def test_phase_capacity_keeps_actual_socket_bytes_errors_and_seventeenth_request_cap(self):
        response=b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPUBLIC'
        original,*_=self.native();selected,events,io,reads=self.native()
        subject.install_phase_capacity(selected,self.library)
        for _ in range(5):
            for native in (original,selected):
                for phase in ('ORIGIN_CONNECT','ORIGIN_PROXY_CONNECTED',
                              'ORIGIN_PROXY_CONNECT_ACCEPTED','ORIGIN_TLS_VERIFIED'):
                    native.note_phase(phase)
            self.assertEqual(self.exchange(original,response),self.exchange(selected,response))
        for _ in range(11):
            for phase in ('ORIGIN_CONNECT','ORIGIN_PROXY_CONNECTED',
                          'ORIGIN_PROXY_CONNECT_ACCEPTED','ORIGIN_TLS_VERIFIED'):
                selected.note_phase(phase)
            self.assertEqual(self.exchange(selected,response)[0]['status'],'FORWARDED')
        before=list(selected.closed_phases)
        event,raw,upstream=self.exchange(selected,response)
        self.assertEqual(event['status'],'UNKNOWN_BUDGET')
        self.assertEqual(upstream,b'');self.assertEqual(selected.closed_phases,before)
        self.assertEqual(selected.max_connections,16);self.assertEqual(selected.posts,16)
        self.assertEqual(len(reads),16);self.assertEqual(selected.headers_prepared,16)
        # Existing response refusal codes and forwarded bytes are unchanged.
        for reply in (b'HTTP/1.1 403 Refused\r\nContent-Length: 0\r\n\r\n',
                      b'INVALID\r\n\r\n'):
            old,*_=self.native();new,*_=self.native();subject.install_phase_capacity(new,self.library)
            self.assertEqual(self.exchange(old,reply),self.exchange(new,reply))

    def test_phase_capacity_scope_and_measured_projection_are_closed(self):
        for attr,value in [('max_connections',15),('closed_phases',['ORIGIN_CONNECT']),
                           ('headers_prepared',1)]:
            native,*_=self.native();setattr(native,attr,value)
            with self.subTest(attr=attr),self.assertRaisesRegex(ValueError,'DEFAULT_PHASE_INSTANCE_SCOPE'):
                subject.install_phase_capacity(native,self.library)
        native,*_=self.native();self.assertEqual(subject.phase_capacity_snapshot(native),{'status':'UNKNOWN'})
        subject.install_phase_capacity(native,self.library);native.headers_prepared=True
        self.assertEqual(subject.phase_capacity_snapshot(native),{'status':'UNKNOWN'})

    def exchange(self,native,response,request=None):
        # Both transport legs are actual AF_UNIX sockets. Peer.connect and
        # RealGuard.sendall/recv remain the selected pinned implementations.
        client,ingress=socket.socketpair(socket.AF_UNIX);upstream,provider=socket.socketpair(socket.AF_UNIX)
        for item in (client,ingress,upstream,provider):item.settimeout(2)
        body=json.dumps({'input':'PUBLIC_ALPHA','client_metadata':{'thread_id':native.association.thread,
            'turn_id':native.association.turn}},separators=(',',':')).encode()
        request=request or b'POST /v1/responses HTTP/1.1\r\nHost: synthetic.invalid\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        native.connector=lambda deadline:upstream
        client.sendall(request);client.shutdown(socket.SHUT_WR)
        provider.sendall(response);provider.shutdown(socket.SHUT_WR)
        def drain(sock):
            result=bytearray()
            while True:
                try:data=sock.recv(4096)
                except ConnectionResetError:break
                if not data:break
                result.extend(data)
            return bytes(result)
        try:
            event=native.handle_bound(ingress)
            upstream.close()  # A pre-connect refusal leaves this synthetic leg unused.
            return event,drain(client),drain(provider)
        finally:
            for item in (client,ingress,upstream,provider):item.close()

    def test_actual_peer_realguard_socket_refusals_and_forwarding_are_identical(self):
        cases=[(b'HTTP/1.1 403 Refused\r\nContent-Length: 0\r\n\r\n','RESPONSE_NON_2XX',403),
            (b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n','RESPONSE_NONIDENTITY_ENCODING',200),
            (b'HTTP/1.1 200 OK\r\nX-Secret: synthetic\r\nContent-Length: 0\r\n\r\n','RESPONSE_SENSITIVE_HEADER',200),
            (b'HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n','RESPONSE_TRAILER_OR_UPGRADE',200),
            (b'HTTP/1.1 200 OK\r\nTrailer: synthetic\r\n\r\n','RESPONSE_TRAILER_OR_UPGRADE',200),
            (b'INVALID\r\nContent-Length: 0\r\n\r\n','RESPONSE_STATUS_INVALID',None),
            (b'HTTP/1.1 200 OK\r\nMalformed\r\n\r\n','RESPONSE_HEADER_FRAMING',None),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPUBLIC','HEADER_ACCEPTED',200),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\nPUBLIC_SYNTHETIC_ONLY_TOKEN','RESPONSE_TOKEN_ECHO',None)]
        for response,reason,status in cases:
            with self.subTest(reason=reason):
                original,*_=self.native();selected,events,io,reads=self.native();rows=[]
                self.gate.install_peer_response_metadata(selected,self.library,rows.append)
                self.assertEqual(self.exchange(original,response),self.exchange(selected,response))
                self.assertIs(selected.response_metadata,False);self.assertEqual(selected.posts,1)
                self.assertEqual(len(reads),1);self.assertEqual(len(io),1)
                self.assertEqual(rows[0]['response_rejection'],reason);self.assertEqual(rows[0]['response_status_code'],status)
                self.assertEqual(rows[0]['observer_sequence'],io[0]['sequence'])
                self.assertEqual(rows[0]['binding_status'],'HANDLER_IO_SEQUENCE')
                self.assertLessEqual(len(json.dumps(rows[0]).encode()),1024)
                self.assertNotIn('PUBLIC_SYNTHETIC_ONLY_TOKEN',json.dumps(rows))

    def test_callback_failure_request_refusal_and_cap_do_not_change_native(self):
        native,events,io,reads=self.native()
        state=self.gate.install_peer_response_metadata(native,self.library,Mock(side_effect=RuntimeError('synthetic')))
        response=b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        event,raw,_=self.exchange(native,response)
        self.assertEqual(event['status'],'FORWARDED');self.assertEqual(raw,response);self.assertTrue(state['unknown'])
        native,events,io,reads=self.native();rows=[]
        self.gate.install_peer_response_metadata(native,self.library,rows.append)
        self.exchange(native,response,request=b'GET /v1/responses HTTP/1.1\r\nHost: synthetic.invalid\r\n\r\n')
        self.assertEqual(native.posts,0);self.assertEqual(reads,[])
        self.assertEqual(rows[0]['response_rejection'],'RESPONSE_NOT_OBSERVED')
        native,events,io,reads=self.native();rows=[]
        state=self.gate.install_peer_response_metadata(native,self.library,rows.append)
        for _ in range(17):self.exchange(native,response)
        self.assertEqual(native.posts,16);self.assertEqual(len(rows),16);self.assertTrue(state['unknown'])
        self.assertIs(native.response_metadata,False)

    def test_scope_and_original_unbound_exception_remain_closed(self):
        native,events,io,reads=self.native();native.association=None
        client,ingress=socket.socketpair(socket.AF_UNIX)
        try:
            with self.assertRaises(self.library.NATIVE.Failure) as original:native.handle_bound(ingress)
            self.gate.install_peer_response_metadata(native,self.library,lambda row:None)
            with self.assertRaises(self.library.NATIVE.Failure) as selected:native.handle_bound(ingress)
            self.assertEqual(original.exception.args,selected.exception.args)
            self.assertEqual(native.posts,0);self.assertEqual(reads,[])
        finally:client.close();ingress.close()
        native,*_=self.native();native.response_metadata=True
        with self.assertRaisesRegex(ValueError,'INSTANCE_SCOPE'):self.gate.install_peer_response_metadata(native,self.library,lambda row:None)
        with self.assertRaisesRegex(ValueError,'INSTANCE_SCOPE'):self.gate.install_peer_response_metadata(object(),self.library,lambda row:None)

    def test_default_installs_existing_adapter_before_any_bound_turn(self):
        tree=ast.parse((HERE/'request_observer_default.py').read_text())
        cls=next(node for node in ast.walk(tree) if isinstance(node,ast.ClassDef) and node.name=='DefaultGate')
        init=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=='__init__')
        calls=[node for node in ast.walk(init) if isinstance(node,ast.Call) and
               isinstance(node.func,ast.Attribute) and node.func.attr=='install_owned_peer_response_metadata']
        self.assertEqual(len(calls),1);self.assertEqual(ast.unparse(calls[0]),'gate_module.install_owned_peer_response_metadata(self)')
        self.assertNotIn('handle_bound',ast.unparse(init));self.assertNotIn('turn/start',ast.unparse(init))


class ResponseHeadChecks(unittest.TestCase):
    def core(self):
        spec=importlib.util.spec_from_file_location('default_head_core',HERE.parent/'native_request_observer.py')
        core=importlib.util.module_from_spec(spec);sys.modules[spec.name]=core;spec.loader.exec_module(core)
        return core

    def fixture(self, response, derived=True, request=None):
        core=self.core();thread='00000000-0000-4000-8000-000000000001'
        association=core.Association(thread,'00000000-0000-4000-8000-000000000002',1)
        body=json.dumps({'input':'PUBLIC_ALPHA','client_metadata':
            {'thread_id':association.thread,'turn_id':association.turn}},separators=(',',':')).encode()
        request=request or b'POST /responses HTTP/1.1\r\nHost: synthetic.invalid\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        upstream,client=MemorySocket(response),MemorySocket(request)
        events,rows=[],[]
        native=core.Observer('https://synthetic.invalid/responses','PUBLIC_ALPHA',events.append,
            enabled=True,bound_thread=thread,injected_connector=lambda deadline:upstream)
        native._default_response_head_emit=lambda instance,assignment,reason,status:rows.append((reason,status))
        if derived:native.handle=types.MethodType(subject.derive_response_head_diagnostic(core)[0],native)
        return core,native,association,client,upstream,events,rows

    def test_response_refusal_enum_status_and_original_outcome_are_identical(self):
        cases=[(b'HTTP/1.1 302 Redirect\r\nContent-Length: 0\r\n\r\n','STATUS_LINE_REFUSED',302),
            (b'HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\n\r\n','STATUS_LINE_REFUSED',101),
            (b'INVALID\r\nContent-Length: 0\r\n\r\n','STATUS_LINE_REFUSED',None),
            (b'HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n','UPGRADE_REFUSED',200),
            (b'HTTP/1.1 200 OK\r\nTrailer: secret-value\r\n\r\n','TRAILER_REFUSED',200),
            (b'HTTP/1.1 200 OK\r\nConnection: upgrade\r\n\r\n','CONNECTION_UPGRADE_REFUSED',200),
            (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n','TRANSFER_ENCODING_REFUSED',200),
            (b'HTTP/1.1 200 OK\r\nContent-Length: bad\r\n\r\n','FRAMING_REFUSED',200),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n','FRAMING_REFUSED',200),
            (b'HTTP/1.1 204 No content\r\nContent-Length: 1\r\n\r\n','NO_CONTENT_FRAMING_REFUSED',204),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n','HEADERS_REFUSED',None),
            (b'HTTP/1.1 200 OK\r\nPrivate: value\x00hidden\r\n\r\n','HEADERS_REFUSED',None),
            (b'HTTP/1.1 200 OK\r\nmalformed\r\n\r\n','HEADERS_REFUSED',None)]
        for response,reason,status in cases:
            with self.subTest(reason=reason,status=status):
                original=self.fixture(response,False);selected=self.fixture(response)
                outcomes=[]
                for core,native,association,client,upstream,events,rows in (original,selected):
                    outcomes.append((native.handle(client,association),bytes(client.sent),bytes(upstream.sent)))
                    self.assertEqual(native.posts,1)
                self.assertEqual(outcomes[0],outcomes[1])
                self.assertEqual(selected[-1],[(reason,status)])
                self.assertEqual(original[-1],[])

    def test_success_response_bytes_and_request_refusal_do_not_emit_response_metadata(self):
        for response in (b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPUBLIC',
                         b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nPUBLIC\r\n0\r\n\r\n',
                         b'HTTP/1.1 204 No content\r\n\r\n'):
            original=self.fixture(response,False);selected=self.fixture(response)
            results=[]
            for core,native,association,client,upstream,events,rows in (original,selected):
                results.append(native.handle(client,association));self.assertEqual(bytes(client.sent),response)
                self.assertEqual(rows,[])
            self.assertEqual(results[0],results[1])
        core,native,association,client,upstream,events,rows=self.fixture(b'HTTP/1.1 302 X\r\n\r\n',
            request=b'GET /responses HTTP/1.1\r\nHost: x\r\n\r\n')
        self.assertNotEqual(native.handle(client,association)['status'],'FORWARDED')
        self.assertEqual(native.posts,0);self.assertEqual(rows,[]);self.assertEqual(upstream.sent,b'')

    def test_response_exception_identity_and_diagnostic_failure_cannot_change_parser(self):
        core,native,association,*_=self.fixture(b'')
        _,helper=subject.derive_response_head_diagnostic(core)
        error=core.ClosedFailure('UNKNOWN_FRAMING')
        helper.__globals__['headers']=Mock(side_effect=error)
        native._default_response_head_emit=Mock(side_effect=RuntimeError('diagnostic failure'))
        with self.assertRaises(core.ClosedFailure) as caught:helper(native,b'public synthetic head',association)
        self.assertIs(caught.exception,error)
        native._default_response_head_emit.assert_called_once_with(native,association,'HEADERS_REFUSED',None)

    def test_scope_counters_and_record_cap_are_closed_without_altering_owner(self):
        core,native,association,*_=self.fixture(b'')
        native.association=association;native.posts=1
        broker=types.SimpleNamespace(native=native,current_turn=(association.thread,association.turn),current_attempt=1)
        owner=types.SimpleNamespace(peer_brokers={'a':broker},nodes={'a':{'thread':association.thread}},result={})
        library=types.SimpleNamespace(CORE=core)
        record=lambda:subject.record_response_head(owner,library,native,association,'STATUS_LINE_REFUSED',302)
        self.assertTrue(record());row=owner.result['default_response_head_refusals']['a'][0]
        self.assertEqual(set(row),{'schema','node','thread_id','turn_id','attempt','outbound_POST_send_attempts',
            'response_status_code','refusal_reason','raw_response_exported','cause_proven'})
        for target,key,value in [(native,'posts',0),(native,'posts',17),(native,'posts',True),
            (native,'association',object()),(broker,'current_turn',('wrong',association.turn)),
            (broker,'current_attempt',2)]:
            previous=getattr(target,key);setattr(target,key,value)
            self.assertFalse(record());setattr(target,key,previous)
        owner.nodes['a']['thread']='wrong';self.assertFalse(record());owner.nodes['a']['thread']=association.thread
        self.assertFalse(subject.record_response_head(owner,library,object(),association,'STATUS_LINE_REFUSED',302))
        for reason,status in [('unclosed',302),('STATUS_LINE_REFUSED',True),('STATUS_LINE_REFUSED',600)]:
            self.assertFalse(subject.record_response_head(owner,library,native,association,reason,status))
        for _ in range(15):self.assertTrue(record())
        self.assertFalse(record());self.assertEqual(len(owner.result['default_response_head_refusals']['a']),16)
        self.assertEqual(native.posts,1);self.assertEqual(broker.current_attempt,1)

    @unittest.skipUnless(all(Path(path).is_file() for path in subject.DEPENDENCY_PINS),
                         'pinned Peer source is absent in a fresh checkout')
    def test_actual_pinned_peer_dispatch_keeps_association_guard_and_source_parser(self):
        library=subject.load_dependency('peer_outer_broker',subject.PEER/'peer_outer_broker.py')
        native=object.__new__(library.PeerNativeBroker);native.response_byte_passthrough=False
        rows=[];subject.install_response_head_diagnostic(native,library,lambda *row:rows.append(row))
        client=MemorySocket()
        with self.assertRaisesRegex(library.PeerBrokerFailure,'PARENT_ASSOCIATION_REQUIRED'):native.handle(client)
        self.assertTrue(client.closed);self.assertEqual(rows,[])
        with self.assertRaises(ValueError):subject.install_response_head_diagnostic(native,library,rows.append)
        native2=object.__new__(library.PeerNativeBroker);native2.response_byte_passthrough=True
        with self.assertRaises(ValueError):subject.install_response_head_diagnostic(native2,library,rows.append)
        for response in (b'HTTP/1.1 302 Redirect\r\nContent-Length: 0\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPUBLIC'):
            core=library.CORE;association=core.Association('00000000-0000-4000-8000-000000000001',
                '00000000-0000-4000-8000-000000000002',1)
            body=json.dumps({'input':'PUBLIC_ALPHA','client_metadata':{'thread_id':association.thread,
                'turn_id':association.turn}},separators=(',',':')).encode()
            request=b'POST /responses HTTP/1.1\r\nHost: synthetic.invalid\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
            selected=object.__new__(library.PeerNativeBroker);upstream=MemorySocket(response);events=[]
            core.Observer.__init__(selected,'https://synthetic.invalid/responses','PUBLIC_ALPHA',events.append,
                enabled=True,bound_thread=association.thread)
            selected.connect=lambda deadline:upstream;selected.association=association
            broker=types.SimpleNamespace(native=selected,current_turn=(association.thread,association.turn),current_attempt=1)
            owner=types.SimpleNamespace(peer_brokers={'a':broker},nodes={'a':{'thread':association.thread}},result={})
            subject.install_response_head_diagnostic(selected,library,
                lambda *args:subject.record_response_head(owner,library,*args))
            client=MemorySocket(request);event=selected.handle(client,association)
            self.assertEqual(selected.posts,1)
            if response.startswith(b'HTTP/1.1 302'):
                self.assertEqual(event['status'],'UNKNOWN_UNSUPPORTED');self.assertEqual(client.sent,b'')
                self.assertEqual(owner.result['default_response_head_refusals']['a'][0]['response_status_code'],302)
            else:
                self.assertEqual(event['status'],'FORWARDED');self.assertEqual(bytes(client.sent),response)
                self.assertEqual(owner.result,{})

    def test_default_native_error_classification_is_closed_and_published_before_abort(self):
        spec=importlib.util.spec_from_file_location('default_error_gate',HERE/'request_observer_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        thread='00000000-0000-4000-8000-000000000001';turn='00000000-0000-4000-8000-000000000002'
        params={'threadId':thread,'turnId':turn,'error':
            {'message':'stream disconnected before completion: stream closed before response.completed'}}
        fields={'schema_status':'SAFE_ENUM_FIELDS_VALIDATED','category':'other','http_status_code':None,'will_retry':False}
        for default in (True,False):
            owner=types.SimpleNamespace(_default_daemon_fixture=default,nodes={'a':{'thread':thread}},
                budget=types.SimpleNamespace(threads={'a':thread},started={('a',turn)},completed=set()),
                args=types.SimpleNamespace(test_request_observer=False,native_https=False,
                    go={'max_fatal_diagnostic_capture_seconds':5}),result={},aborted=False,
                abort_lock=threading.RLock(),_observer_capture_lifecycle_lock=threading.RLock())
            error=RuntimeError('original error')
            def abort(actual):
                self.assertIs(actual,error)
                self.assertEqual('native_error_closed_diagnostic' in owner.result,default)
            owner.abort_owned=abort
            gate.mark_native_failure(owner,error,'a','received',{'method':'error','params':params},fields)
            if default:
                row=owner.result['native_error_closed_diagnostic']
                self.assertEqual(row['classification'],'STREAM_CLOSED_BEFORE_COMPLETED')
                self.assertFalse(row['message_exported']);self.assertFalse(row['cause_proven'])
                self.assertNotIn('stream disconnected',json.dumps(row))
                self.assertFalse(hasattr(owner,'_observer_native_capture_state'))

    def test_unparsed_incomplete_response_head_and_budget_refusal_do_not_fabricate_status(self):
        core,native,association,client,upstream,events,rows=self.fixture(b'HTTP/1.1 302')
        self.assertNotEqual(native.handle(client,association)['status'],'FORWARDED')
        self.assertEqual(native.posts,1);self.assertEqual(rows,[])
        core,native,association,client,upstream,events,rows=self.fixture(b'HTTP/1.1 302 X\r\n\r\n')
        native.posts=16;native.connections=16
        self.assertEqual(native.handle(client,association)['status'],'UNKNOWN_BUDGET')
        self.assertEqual(native.posts,16);self.assertEqual(rows,[]);self.assertEqual(upstream.sent,b'')


class DefaultFixtureChecks(unittest.TestCase):
    def test_neutral_peer_runtime_config_preserves_exact_policy_and_rejects_drift(self):
        import tomllib
        # Same public pre-daemon shape retained by the actual C1 failed run.
        public = '\n'.join(['model = "gpt-5.6-luna"','model_provider = "zzswitch"',
            'sandbox_mode = "workspace-write"','approval_policy = "on-request"',
            'log_dir = "/var/log/cicada/codex"','[model_providers.zzswitch]',
            'name = "Cicada fixture provider"','base_url = "http://127.0.0.1:18767/v1"',
            'requires_openai_auth = false','supports_websockets = false','wire_api = "responses"',
            'request_max_retries = 4','stream_idle_timeout_ms = 300000',''])
        actual = tomllib.loads(subject.default_runtime_config(public))
        self.assertEqual(actual['approval_policy'],'never')
        self.assertEqual(actual['approvals_reviewer'],'user')
        self.assertEqual(actual['sandbox_mode'],'workspace-write')
        self.assertEqual(actual['model_provider'],'zzswitch')
        self.assertEqual(actual['log_dir'],'/codex/logs')
        self.assertEqual(actual['model_providers']['zzswitch']['request_max_retries'],0)
        self.assertEqual(actual['model_providers']['zzswitch']['stream_max_retries'],0)
        explicit = public.replace('approval_policy = "on-request"',
                                  'approval_policy = "on-request"\napprovals_reviewer = "user"')
        self.assertEqual(tomllib.loads(subject.default_runtime_config(explicit))['approvals_reviewer'],'user')
        for bad in (public.replace('http://127.0.0.1:18767/v1','https://api.zzswitch.com/v1'),
                    public+'env_key = "API_KEY"\n',public.replace('on-request','never'),
                    public.replace('workspace-write','danger-full-access'),
                    public.replace('request_max_retries = 4','request_max_retries = 1'),
                    public.replace('requires_openai_auth = false','requires_openai_auth = true'),
                    public.replace('approval_policy = "on-request"',
                                   'approval_policy = "on-request"\napprovals_reviewer = "guardian_subagent"'),
                    public.replace('zzswitch','basil')):
            with self.subTest(public=bad),self.assertRaises(ValueError):
                subject.default_runtime_config(bad)

    def test_default_zero_guard_accepts_only_exact_empty_proxy_mask_pair(self):
        spec=importlib.util.spec_from_file_location('pure_default_zero_gate',HERE/'request_observer_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        argv=['docker','run','-e','HTTPS_PROXY=','owned-image']
        gate.validate_zero_command(argv,default_daemon_fixture=True)
        with self.assertRaisesRegex(PermissionError,'ZERO_CREDENTIAL_OR_PROVIDER_ARGV'):
            gate.validate_zero_command(argv)
        for invalid in (['HTTPS_PROXY='],['--env','HTTPS_PROXY='],['-e','HTTPS_PROXY=http://unapproved'],
                        ['-e','API_KEY='],['/gpu1-share/no-key-read'],['/run/secrets/provider.env'],['paid']):
            with self.subTest(argv=invalid),self.assertRaises(PermissionError):
                gate.validate_zero_command(['docker','run',*invalid],default_daemon_fixture=True)

    def test_final_result_replaces_owned_parent_result_and_refuses_foreign_target(self):
        with tempfile.TemporaryDirectory() as root:
            parent=Path(root);parent.chmod(0o700);target=parent/'result.json'
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:json.dump({'run_id':'owned','status':'FAIL'},stream)
            subject.publish_default_result(parent,{'run_id':'owned','status':'FAIL','final_cleanup':True},'owned')
            self.assertTrue(json.loads(target.read_text())['final_cleanup'])
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertFalse((parent/'default-result-final.tmp').exists())
            before=target.read_bytes()
            with self.assertRaisesRegex(ValueError,'DEFAULT_RESULT_RUN_SCOPE'):
                subject.publish_default_result(parent,{'run_id':'other'},'other')
            self.assertEqual(target.read_bytes(),before)
            target.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'DEFAULT_RESULT_TARGET_SCOPE'):
                subject.publish_default_result(parent,{'run_id':'owned'},'owned')
            target.chmod(0o600);target.rename(parent/'preserved.json');target.symlink_to(parent/'preserved.json')
            with self.assertRaises(OSError):subject.publish_default_result(parent,{'run_id':'owned'},'owned')
            self.assertEqual((parent/'preserved.json').read_bytes(),before)

    def test_constructor_budget_requires_explicit_default_fixture_and_exact_caps(self):
        spec=importlib.util.spec_from_file_location('pure_default_budget_gate',HERE/'request_observer_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        zero=types.SimpleNamespace(native_https=False,native_normal_seconds=600,run_native=False,
            test_request_observer=False,response_byte_passthrough=False,
            go={'max_native_turns':0,'max_manual_turns':0,'max_automatic_turns':0})
        self.assertFalse(gate.validate_native_https(zero,'g2-g3',True,default_daemon_fixture=True))
        with self.assertRaisesRegex(PermissionError,'NATIVE_NORMAL_SECONDS'):
            gate.validate_native_https(zero,'g2-g3',True)
        for key,value in [('native_normal_seconds',180),('native_https',True),('run_native',True),
                          ('test_request_observer',True),('response_byte_passthrough',True)]:
            invalid=types.SimpleNamespace(**vars(zero));setattr(invalid,key,value)
            with self.subTest(field=key),self.assertRaises(PermissionError):
                gate.validate_native_https(invalid,'g2-g3',True,default_daemon_fixture=True)
        for key in zero.go:
            invalid=types.SimpleNamespace(**vars(zero));invalid.go=dict(zero.go);invalid.go[key]=1
            with self.subTest(cap=key),self.assertRaises(PermissionError):
                gate.validate_native_https(invalid,'g2-g3',True,default_daemon_fixture=True)
        with self.assertRaises(PermissionError):
            gate.validate_native_https(zero,'g1',True,default_daemon_fixture=True)
        paid=types.SimpleNamespace(**vars(zero));paid.run_native=True
        paid.go={'max_native_turns':6,'max_manual_turns':4,'max_automatic_turns':2}
        self.assertFalse(gate.validate_native_https(paid,'g2-g3',False,default_daemon_fixture=True))
        zero.native_normal_seconds=180
        self.assertFalse(gate.validate_native_https(zero,'g2-g3',True))

    def test_socket_root_shape_rejects_before_source_or_runtime_effects(self):
        with patch.object(subject.subprocess,'run',side_effect=AssertionError('EARLY_EFFECT')) as effect:
            for roots in (None, ['/tmp/a','/tmp/b'], {'a':'/tmp/a'}, {'a':'/tmp/a','b':'/tmp/b','c':'/tmp/c'}):
                with self.subTest(roots=roots), self.assertRaisesRegex(ValueError,'DEFAULT_SOCKET_ROOT_SHAPE'):
                    subject.check_fixture({'socket_roots':roots},{})
            effect.assert_not_called()

    def test_public_provider_origin_and_neutral_identifier(self):
        source='model_provider = "basil"\n[model_providers.basil]\nbase_url = "https://api.zzswitch.com/v1"\n'
        actual=subject.neutral_config(source)
        self.assertIn('[model_providers.'+subject.PROVIDER+']',actual)
        self.assertNotIn('basil',actual)
        for invalid in ('https://basil.xin/v1','http://api.zzswitch.com/v1','https://api.zzswitch.com/v1/other'):
            with self.subTest(origin=invalid), self.assertRaises(ValueError):
                subject.neutral_config(source.replace(subject.ORIGIN,invalid))

    def test_bootstrap_uses_only_pinned_default_daemon(self):
        ast.parse(subject.BOOTSTRAP)
        self.assertIn("[CLI,'app-server','daemon','start']",subject.BOOTSTRAP)
        self.assertIn("[CLI,'app-server','daemon','version']",subject.BOOTSTRAP)
        self.assertIn('managedCodexPath',subject.BOOTSTRAP)
        for forbidden in ('--listen','--remote','/run/secrets','PREPARE','turn/start'):
            self.assertNotIn(forbidden,subject.BOOTSTRAP)

    def test_zero_and_paid_bootstrap_target_only_exact_owned_nodes(self):
        for mode in ('offline','paid'):
            argv=['exec','-d','owned-a','python3','/state/server_bootstrap.py',mode,'']
            selected=subject.default_bootstrap_argv(argv,{'owned-a','owned-b'})
            self.assertEqual(selected[4],'/opt/peer/server_bootstrap.py')
            self.assertEqual(selected[:4]+selected[5:],argv[:4]+argv[5:])
            self.assertEqual(argv[4],'/state/server_bootstrap.py')
        for node,mode in (('unowned','offline'),('owned-a','unknown')):
            with self.subTest(node=node,mode=mode),self.assertRaisesRegex(ValueError,'DEFAULT_BOOTSTRAP_OWNED_ARGV'):
                subject.default_bootstrap_argv(['exec','-d',node,'python3','/state/server_bootstrap.py',mode,''],{'owned-a'})

    def test_official_logical_path_has_exact_hash(self):
        import hashlib
        self.assertEqual(subject.PHYSICAL,'/tmp/codex-daemon-1000/'+hashlib.sha256(subject.LOGICAL.encode()).hexdigest())

    def test_loaded_idle_requires_exact_sid_cwd_and_empty_queue(self):
        rpc=Mock()
        rpc.request.side_effect=[{'thread':{'id':'sid','cwd':'/workspace','status':{'type':'idle'}}},{'data':[],'nextCursor':None}]
        subject.loaded_idle(rpc,'sid')
        for thread,queue in [({'id':'other','cwd':'/workspace','status':{'type':'idle'}},{'data':[]}),
            ({'id':'sid','cwd':'/other','status':{'type':'idle'}},{'data':[]}),
            ({'id':'sid','cwd':'/workspace','status':{'type':'notLoaded'}},{'data':[]}),
            ({'id':'sid','cwd':'/workspace','status':{'type':'idle'}},{'data':[{'id':'pending'}]})]:
            with self.subTest(thread=thread,queue=queue), self.assertRaises(ValueError):
                rpc.request.side_effect=[{'thread':thread},queue]; subject.loaded_idle(rpc,'sid')

    def generations(self):
        turns=types.SimpleNamespace(queue_thread=lambda node:'sid-'+node,
            arm_automatic=Mock(),cancel_automatic=Mock(),automatic_generations={},
            drained_generations={},drained_turns={})
        brokers={n:types.SimpleNamespace(arm_pending_start=Mock(return_value=3),cancel_pending_start=Mock()) for n in 'ab'}
        return subject.Generations(turns,brokers),turns,brokers

    def test_generation_registers_real_broker_generation_once(self):
        owner,turns,brokers=self.generations()
        owner.arm('b','sid-b','request')
        brokers['b'].arm_pending_start.assert_called_once_with('sid-b')
        turns.arm_automatic.assert_called_once_with('b',3,'sid-b')
        self.assertNotIn('actual_turn_id',owner.pending['b'])
        with self.assertRaises(ValueError): owner.arm('b','sid-b','request')
        with self.assertRaises(ValueError): owner.arm('a','different-sid','request')

    def test_generation_arm_failure_cancels_without_retry(self):
        owner,turns,brokers=self.generations(); turns.arm_automatic.side_effect=ValueError('scope')
        with self.assertRaises(ValueError): owner.arm('a','sid-a','request')
        brokers['a'].cancel_pending_start.assert_called_once_with(3)
        self.assertEqual(owner.pending,{})

    def test_generation_completion_requires_actual_native_turn(self):
        owner,turns,brokers=self.generations(); owner.arm('b','sid-b','request')
        with self.assertRaises(ValueError): owner.drained('b',3)
        turns.drained_generations['b']=3;turns.drained_turns['b']='native-turn'
        with self.assertRaises(ValueError): owner.drained('b',4)
        owner.drained('b',3)
        self.assertEqual(owner.receipts['b']['actual_turn_id'],'native-turn')
        with self.assertRaises(ValueError): owner.drained('b',3)

    def test_generation_cancel_only_still_unbound(self):
        owner,turns,brokers=self.generations(); owner.arm('a','sid-a','request')
        turns.automatic_generations['a']=3;owner.cancel()
        turns.cancel_automatic.assert_called_once_with('a',3)
        brokers['a'].cancel_pending_start.assert_called_once_with(3)
        self.assertEqual(owner.pending,{})

    def test_pidfd_signal_checks_incarnation_first(self):
        agent=types.SimpleNamespace(pidfd=71)
        verify=Mock(side_effect=ValueError('incarnation'))
        with patch.object(signal,'pidfd_send_signal') as send:
            with self.assertRaises(ValueError): subject.signal_agent(agent,signal.SIGSTOP,verify)
            send.assert_not_called()
        with patch.object(signal,'pidfd_send_signal') as send:
            verify=Mock();subject.signal_agent(agent,signal.SIGCONT,verify)
            verify.assert_called_once_with(agent);send.assert_called_once_with(71,signal.SIGCONT)

    def test_materialization_requires_real_original_sid_and_cwd(self):
        with tempfile.TemporaryDirectory() as root:
            home=Path(root);sessions=home/'sessions';sessions.mkdir()
            path=sessions/'rollout-a.jsonl'
            node={'paths':{'codex':home}}
            with self.assertRaises(ValueError):subject.materialized(node,'sid')
            path.write_text(json.dumps({'type':'session_meta','payload':{'id':'sid','cwd':'/workspace'}})+'\n'+ 'SENSITIVE_HISTORY_NEVER_PARSED\n')
            subject.materialized(node,'sid')
            path.write_text(json.dumps({'type':'session_meta','payload':{'id':'sid','cwd':'/other'}})+'\n')
            with self.assertRaises(ValueError):subject.materialized(node,'sid')

    def test_materialization_first_header_uses_one_MiB_bound_without_reading_history(self):
        with tempfile.TemporaryDirectory() as root:
            home=Path(root);sessions=home/'sessions';sessions.mkdir();path=sessions/'rollout-a.jsonl'
            node={'paths':{'codex':home}}
            def header(sid='sid',cwd='/workspace',padding=20000):
                return (json.dumps({'type':'session_meta','payload':{'id':sid,'cwd':cwd,
                    'synthetic_base_instructions':'x'*padding}})+'\n').encode()
            raw=header();self.assertGreater(len(raw),16384)
            path.write_bytes(raw+b'INVALID_HISTORY_MUST_NOT_BE_PARSED\n')
            subject.materialized(node,'sid')
            boundary=header(padding=(1<<20)-len(header(padding=0)))
            self.assertEqual(len(boundary),1<<20);path.write_bytes(boundary);subject.materialized(node,'sid')
            for invalid in (header(padding=(1<<20)-len(header(padding=0))+1),raw[:-1],raw[:-3]+b'\n'):
                path.write_bytes(invalid)
                with self.subTest(length=len(invalid)),self.assertRaises(ValueError):subject.materialized(node,'sid')
            path.write_bytes(header(sid='other'))
            with self.assertRaisesRegex(ValueError,'DEFAULT_ORIGINAL_SID_NOT_MATERIALIZED'):subject.materialized(node,'sid')
            path.write_bytes(header(cwd='/other'))
            with self.assertRaisesRegex(ValueError,'DEFAULT_ORIGINAL_CWD'):subject.materialized(node,'sid')
            path.write_bytes(raw);(sessions/'rollout-b.jsonl').write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'DEFAULT_ORIGINAL_SID_NOT_MATERIALIZED'):subject.materialized(node,'sid')

    def test_prehold_inbox_is_read_only_and_rejects_inflight(self):
        with tempfile.TemporaryDirectory() as root:
            state=Path(root);parent=state/'nodes/node-node';parent.mkdir(parents=True)
            dbpath=parent/'inbox.sqlite'
            with sqlite3.connect(dbpath) as db:
                db.execute('CREATE TABLE node_inbox_deliveries(session_id TEXT)')
                db.execute('CREATE TABLE node_inbox_attempts(session_id TEXT)')
            before=dbpath.read_bytes();subject.readonly_pending(state,'node','sid')
            self.assertEqual(dbpath.read_bytes(),before)
            with sqlite3.connect(dbpath) as db:db.execute('INSERT INTO node_inbox_attempts VALUES (?)',('sid',))
            with self.assertRaises(ValueError):subject.readonly_pending(state,'node','sid')

    @unittest.skipUnless((subject.PEER/'peer_gate_derivative_g2_current_36eb_h5.py').is_file(),
                         'pinned local Peer fixture is absent in a fresh checkout')
    def test_pinned_peer_selection_has_no_queue_listener_or_shim_creation(self):
        source=(subject.PEER/'peer_gate_derivative_g2_current_36eb_h5.py').read_text()
        selected=subject.transform_peer(source);tree=ast.parse(selected)
        cls=next(n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.name=='PeerGate')
        for name in ('__init__','peer_mounts','start_services'):
            method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name)
            text=ast.unparse(method)
            for forbidden in ('QueueAdmissionServer','codex_queue_remote.py','/run/peer-queue-control','mkdtemp'):
                self.assertNotIn(forbidden,text)
        self.assertIn('self.default_generation_drained',selected)
        # Exercise the actual full legacy helper argv through the selected
        # Peer method and the current Candidate command consumer, without a
        # constructor or subprocess. These local fixture dependencies remain
        # explicit skips in a fresh checkout, never evidence of acceptance.
        gate=self.run_module().safe_overlay('request_observer_gate')
        stage=Path('/home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9')
        if not (stage/'bin/openssl').is_file():self.skipTest('pinned local TLS stage is absent')
        import hashlib,stat
        binding={'output_parent':'/public/binding','public_files':{
            str(gate.OLD/'migration.py'):{'sha256':gate.TLS_HELPER_MIGRATION_SHA}}}
        for name in ('bin/openssl','lib/libcrypto.so.3','lib/libssl.so.3'):
            p=stage/name;s=p.stat();binding['public_files'][str(p)]={
                'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':s.st_size,'rawmode':s.st_mode}
        old=gate.OLD.parent
        peer_ns={'ast':ast,'Path':Path,'os':os,'stat':stat,'hashlib':hashlib,'OLD':old,'binding':binding,
                 'BASE_PINS':{old/'managed/migration.py':gate.TLS_HELPER_MIGRATION_SHA}}
        helper_tree=ast.parse((gate.OLD/'migration.py').read_text())
        helper=next(n for n in ast.walk(helper_tree) if isinstance(n,ast.FunctionDef) and n.name=='helper')
        capture=[];generator=types.SimpleNamespace(run_id='owned',root=Path('/public/fixture'),
            native_package=Path('/public/package'),test_image=subject.IMAGE,
            command=lambda argv,**kw:capture.append(argv))
        helper_ns={'ROOT':Path(binding['output_parent']),'os':types.SimpleNamespace(getuid=lambda:1000,getgid=lambda:1000)}
        exec(compile(ast.Module(body=[helper],type_ignores=[]),'<actual-helper-source>','exec'),helper_ns)
        helper_ns['helper'](generator,'tls-bootstrap','--listen','0.0.0.0:8999',
            '--application-origin','http://127.0.0.1:8787','--openssl','/pqtls-stage/bin/openssl')
        original=capture[0]
        for name in ('pinned','approved_tls_helper_argv'):
            fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
            exec(compile(ast.Module(body=[fn],type_ignores=[]),'<actual-peer-source>','exec'),peer_ns)
        consumed=[]
        command=next(n for n in ast.walk(ast.parse((HERE/'request_observer_gate.py').read_text()))
                     if isinstance(n,ast.FunctionDef) and n.name=='guarded_command')
        ns={'zero_model':True,'scenario':'g2-g3','binding':binding,
            'validate_zero_command':gate.validate_zero_command,'approved_tls_helper_argv':gate.approved_tls_helper_argv,
            'original_command':lambda owner,argv,**kw:consumed.append(list(argv))}
        exec(compile(ast.Module(body=[command],type_ignores=[]),'<actual-candidate-command>','exec'),ns)
        class Parent:
            def command(owner,argv,**kwargs):return ns['guarded_command'](owner,argv,**kwargs)
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='command')
        peer_class=ast.ClassDef(name='SelectedPeer',bases=[ast.Name(id='Parent',ctx=ast.Load())],
            keywords=[],body=[method],decorator_list=[])
        peer_ns['Parent']=Parent
        exec(compile(ast.fix_missing_locations(ast.Module(body=[peer_class],type_ignores=[])),
                     '<actual-selected-peer-command>','exec'),peer_ns)
        owner=peer_ns['SelectedPeer']();owner.run_id=generator.run_id;owner.root=generator.root
        owner.native_package=generator.native_package;owner.test_image=subject.IMAGE;owner.result={}
        owner.peer_tls_helper_state=threading.local();owner.peer_tls_helper_state.active=True
        owner._observer_tls_helper_active=True;owner._default_daemon_fixture=True
        owner.command(original)
        admitted=consumed[-1]
        self.assertEqual([i for i,(a,b) in enumerate(zip(original,admitted)) if a!=b],[17])
        self.assertEqual(admitted[17],str(stage)+':/pqtls-stage:ro')
        self.assertIsNone(owner.peer_tls_helper_state.default_admitted_argv)
        for index,bad in ((17,'/wrong:/pqtls-stage:ro'),(25,'not-tls-bootstrap')):
            invalid=original.copy();invalid[index]=bad
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'TLS_HELPER_EXACT_SCOPE'):
                owner.command(invalid)
        owner.peer_tls_helper_state.active=False
        with self.assertRaisesRegex(ValueError,'DEFAULT_TLS_PEER_ADMISSION'):owner.command(original)
        owner.peer_tls_helper_state.active=True
        with self.assertRaisesRegex(ValueError,'DEFAULT_TLS_PEER_ADMISSION'):
            ns['guarded_command'](owner,admitted)  # No call-scoped Peer proof.
        owner._default_daemon_fixture=False
        ns['guarded_command'](owner,original)  # Old zero owner still validates and retargets.
        self.assertEqual(consumed[-1],admitted)
        with self.assertRaisesRegex(ValueError,'TLS_HELPER_EXACT_SCOPE'):
            ns['guarded_command'](owner,admitted)  # Old validator remains strict.

    @unittest.skipUnless(all(Path(path).is_file() for path in subject.DEPENDENCY_PINS),
                         'pinned local native gate dependencies are absent in a fresh checkout')
    def test_current_gate_start_and_flow_selectors_parse_without_execution(self):
        spec=importlib.util.spec_from_file_location('default_current_gate',HERE/'request_observer_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        sources=gate.effective_sources(600)
        start=subject.derive_start(sources['gate']);ast.parse(start)
        self.assertIn('app-server-control',start)
        self.assertNotIn('codex_queue_remote.py',start)
        flow=gate.compile_g2_flow_methods(sources['gate'],{})['managed_golden_flow']._g2_selected_source
        selected=subject.derive_flow(flow);ast.parse(selected)
        self.assertLess(selected.index('hold_default_bob'),selected.index("self.step('original_a_managed_ask')"))
        self.assertLess(selected.index('self.arm_default_pair(request)'),selected.index('self.release_default_bob()'))
        self.assertIn('exact four manual and two automatic actual turns required',selected)
        # Execute only the source-selected setup/daemon submissions. No RPC,
        # subprocess, FIFO or filesystem effects are needed for this proof.
        start_tree=ast.parse(start)
        setup_loop=next(n for n in ast.walk(start_tree) if isinstance(n,ast.For) and
            any(isinstance(x,ast.Expr) and 'self.provider_forwarder(node)'==ast.unparse(x.value) for x in n.body))
        selected_body=[n for n in setup_loop.body if
            (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('node','observer_args') for t in n.targets)) or
            (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and
             (ast.unparse(n.value.func)=='self.provider_forwarder' or
              (ast.unparse(n.value.func)=='self.docker' and '/state/server_bootstrap.py' in ast.unparse(n))))]
        self.assertEqual(len(selected_body),3)
        setup_loop.body=selected_body
        setup_ns={}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.FunctionDef(name='setup',
            args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='self')],kwonlyargs=[],kw_defaults=[],defaults=[]),
            body=[setup_loop],decorator_list=[])],type_ignores=[])), '<exact-default-setup-submissions>','exec'),setup_ns)
        peer_tree=ast.parse(subject.transform_peer((subject.PEER/'peer_gate_derivative_g2_current_36eb_h5.py').read_text()))
        provider=next(n for n in ast.walk(peer_tree) if isinstance(n,ast.FunctionDef) and n.name=='provider_forwarder')
        credentials=Mock(side_effect=AssertionError('NO_ZERO_KEY_READER'))
        broker=types.SimpleNamespace(register_relay=Mock(),start=Mock(),credential_reader=credentials)
        broker_b=types.SimpleNamespace(register_relay=Mock(),start=Mock(),credential_reader=credentials)
        import io
        provider_ns={'os':types.SimpleNamespace(fdopen=lambda *a:io.StringIO(),open=Mock(return_value=73),
            O_WRONLY=1,O_CREAT=2,O_EXCL=4,O_RDWR=8,O_NONBLOCK=16,O_CLOEXEC=32,
            mkfifo=Mock(),read=Mock(return_value=b'{"status":"READY","pid":99,"port":18767}\n'),close=Mock()),
            'json':json,'time':types.SimpleNamespace(monotonic=lambda:10),
            'ENTRY':'/opt/peer/peer_ingress_runtime.py','PORT':18767,'normal_seconds':600,
            'relay_registration':Mock(return_value={'synthetic':'exact-local-registration'})}
        exec(compile(ast.Module(body=[provider],type_ignores=[]),'<actual-peer-provider-forwarder>','exec'),provider_ns)
        owner=types.SimpleNamespace(args=types.SimpleNamespace(run_native=False,artifact_started=1),
            nodes={n:{'container':'owned-'+n,'paths':{'state':MagicMock()}} for n in 'ab'},
            peer_receipts={n:{'synthetic':'no-key'} for n in 'ab'},peer_brokers={'a':broker,'b':broker_b})
        submissions=[]
        def docker(*argv):
            gate.validate_zero_command(['docker',*argv],default_daemon_fixture=True)
            submissions.append(list(argv))
        owner.docker=docker;owner.provider_forwarder=lambda node:provider_ns['provider_forwarder'](owner,node)
        with patch('select.select',return_value=([73],[],[])):setup_ns['setup'](owner)
        self.assertEqual(submissions,[
            ['exec','-d','owned-a','python3','-B','/opt/peer/peer_ingress_runtime.py'],
            ['exec','-d','owned-a','python3','/state/server_bootstrap.py','offline',''],
            ['exec','-d','owned-b','python3','-B','/opt/peer/peer_ingress_runtime.py'],
            ['exec','-d','owned-b','python3','/state/server_bootstrap.py','offline','']])
        for b in (broker,broker_b):b.register_relay.assert_called_once();b.start.assert_called_once()
        credentials.assert_not_called()
        # Starting a registered owner does not authorize an unbound request.
        source=(subject.PEER/'peer_outer_broker.py').read_text()
        self.assertEqual(subject.digest(subject.PEER/'peer_outer_broker.py'),
            subject.DEPENDENCY_PINS[str(subject.PEER/'peer_outer_broker.py')])
        handle=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef) and n.name=='handle_connection')
        class Closed(Exception):pass
        ns={'PeerBrokerFailure':Closed,'verify_registered_relay':lambda *a:{'synthetic':True},
            'socket':types.SimpleNamespace(socket=object)}
        exec(compile(ast.Module(body=[handle],type_ignores=[]),'<actual-unbound-request-admission>','exec'),ns)
        unbound=types.SimpleNamespace(pending_condition=threading.Condition(),closed=False,stop_requested=False,
            active=False,pending_connection_generation=None,relay={},relay_pidfd=83,peer_auth_verified_count=0,
            peer_auth_last_proof=None,peer_auth_changed=threading.Event(),window=types.SimpleNamespace(accept_connection=lambda:20),
            current_turn=None,pending_start=None,native=types.SimpleNamespace(handle_trusted_turn=Mock(),credential_reader=credentials))
        client=Mock()
        with self.assertRaisesRegex(Closed,'BIND_MISSING'):ns['handle_connection'](unbound,client)
        credentials.assert_not_called();unbound.native.handle_trusted_turn.assert_not_called();client.close.assert_called_once()

    def selected_gate(self):
        tree=ast.parse((HERE/'request_observer_default.py').read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.name=='DefaultGate')
        class Parent:
            def cleanup(self): self.parent_cleanup_called=True
            def abort_owned(self, error):
                if hasattr(self, 'parent_abort'): self.parent_abort(error)
                self.aborted=True
        namespace=dict(subject.__dict__,peer_cls=Parent,package=Path('/public'),verify_boundary=lambda *a:None,
            zero_agent_programs=types.MappingProxyType({'CODEX':subject.CLI,'AGENT_BOOTSTRAP':'synthetic-agent'}),
            original_codex='/old/codex')
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<test-actual-default-methods>','exec'),namespace)
        return namespace['DefaultGate'],namespace

    def cleanup_owner(self, owner):
        gate=self.run_module().safe_overlay('request_observer_gate')
        owner.policy=gate.bind_policy(types.SimpleNamespace(),time.monotonic(),600)
        owner._default_abort_lock=threading.Lock();owner._default_abort_claimed=False
        owner._default_abort_done=threading.Event();owner._default_abort_owner=None
        owner._default_abort_error=None;owner._default_cleanup_owner=None
        return owner

    def abort_owner(self):
        cls,namespace=self.selected_gate();owner=self.cleanup_owner(object.__new__(cls))
        owner._held_bob=None;owner._hold_lock=threading.RLock();owner._hold_timer=None
        owner._hold_failed=False;owner._default_daemons_attempted=True;owner._daemon_stops={}
        owner._default_owned_roots={};owner._count_rows={};owner._count_unknown=set()
        owner.rpcs={'a':types.SimpleNamespace(shutdown_expected=False,error=RuntimeError('synthetic prior failure'))}
        owner.nodes={};owner.peer_brokers={};owner.result={'status':'FAIL','terminal_exit_code':1}
        owner.default_generations=types.SimpleNamespace(cancel=Mock())
        owner.peer_origin_proxy=types.SimpleNamespace(close_admission=Mock())
        namespace['check_fixture']=Mock()
        return owner,namespace

    def test_first_reader_abort_coordinates_main_cleanup_and_second_abort(self):
        owner,_=self.abort_owner();error=owner.rpcs['a'].error
        began=threading.Event();release=threading.Event();main_entered=threading.Event();trace=[];failures=[]
        ends=(owner.policy.normal_end,owner.policy.terminal_end,owner.policy.cleanup_end)
        def stop():
            self.assertTrue(owner.cleaning);self.assertTrue(owner.intentional_shutdown)
            self.assertTrue(owner.rpcs['a'].shutdown_expected)
            owner.peer_origin_proxy.close_admission.assert_called()
            self.assertEqual(ends,(owner.policy.normal_end,owner.policy.terminal_end,owner.policy.cleanup_end))
            self.assertTrue(owner._default_abort_lock.acquire(blocking=False));owner._default_abort_lock.release()
            trace.append('official-stop');began.set();self.assertTrue(release.wait(2))
        owner.stop_default_daemons=stop
        owner.parent_abort=lambda original:(self.assertIs(original,error),trace.append('parent-kill'))
        def call(method,*args):
            try:method(*args)
            except BaseException as caught:failures.append(caught)
        reader=threading.Thread(target=call,args=(owner.abort_owned,error));reader.start()
        self.assertTrue(began.wait(2))
        owner.abort_owned(error)  # Second abort cannot kill or repeat stop.
        original_cleanup=owner.policy.cleanup
        def phase():
            original_cleanup()
            if threading.get_ident()!=owner._default_abort_owner:main_entered.set()
        owner.policy.cleanup=phase
        main=threading.Thread(target=call,args=(owner.cleanup,));main.start()
        self.assertTrue(main_entered.wait(2))
        self.assertFalse(owner._default_abort_done.is_set());self.assertEqual(trace,['official-stop'])
        self.assertFalse(getattr(owner,'parent_cleanup_called',False))
        release.set();reader.join(2);main.join(2)
        self.assertFalse(reader.is_alive());self.assertFalse(main.is_alive());self.assertFalse(failures)
        # cleanup retries only an already complete stop method (real method is
        # idempotent via exact socketabsence); no kill precedes first completion.
        self.assertEqual(trace[:2],['official-stop','parent-kill'])
        self.assertTrue(owner.parent_cleanup_called);self.assertIs(owner.rpcs['a'].error,error)
        self.assertEqual(owner.result['status'],'FAIL');self.assertEqual(owner.policy.phase,'cleanup')
        self.assertEqual(ends,(owner.policy.normal_end,owner.policy.terminal_end,owner.policy.cleanup_end))

    def test_abort_timeout_partial_bootstrap_and_self_cleanup_preserve_unknown(self):
        for mode in ('expired','wait-timeout','self','partial'):
            with self.subTest(mode=mode):
                owner,_=self.abort_owner();error=owner.rpcs['a'].error
                owner.stop_default_daemons=Mock();owner.parent_abort=Mock()
                if mode=='partial':
                    owner._default_daemons_attempted=False;owner.rpcs={}
                    owner.abort_owned(error);owner.stop_default_daemons.assert_not_called()
                    owner.parent_abort.assert_called_once_with(error);continue
                owner._default_abort_claimed=True;owner._default_abort_error=error
                owner._default_abort_owner=threading.get_ident() if mode=='self' else -1
                if mode=='self':
                    with self.assertRaisesRegex(RuntimeError,'DEFAULT_ABORT_SELF_CLEANUP'):owner.cleanup()
                    owner.parent_abort.assert_not_called()
                else:
                    if mode=='expired':
                        for field in ('normal_end','terminal_end','cleanup_end'):setattr(owner.policy,field,0)
                    else:owner._default_abort_done=Mock(is_set=Mock(return_value=False),wait=Mock(return_value=False))
                    owner.cleanup();owner.parent_abort.assert_called_once_with(error)
                owner.stop_default_daemons.assert_not_called()
                self.assertTrue(owner._hold_failed);self.assertIn('UNKNOWN',owner.result['default_abort_wait'])
                self.assertIs(owner.rpcs['a'].error,error);self.assertEqual(owner.result['status'],'FAIL')

    def test_actual_default_stop_wrong_owner_dead_node_and_command_failure_fallback(self):
        for mode in ('wrong-cid','dead','stop-error','ok'):
            with self.subTest(mode=mode):
                owner,_=self.abort_owner();owner.nodes={'a':{'container':'synthetic-node'}}
                owner.run_id='synthetic-run';error=owner.rpcs['a'].error
                owner.submitted_objects={('container','synthetic-node'):{'id':'1'*64}}
                record={'Id':'2'*64 if mode=='wrong-cid' else '1'*64,'Image':subject.IMAGE,
                    'State':{'Running':mode!='dead'},'Config':{'Labels':{'org.cicada.test.run':owner.run_id}}}
                owner.inspect=Mock(return_value=record);argv=[]
                def docker(*args,**kwargs):
                    argv.append((args,kwargs))
                    if mode=='stop-error':raise TimeoutError('synthetic stop deadline')
                    return json.dumps({'logical_absent':True,'physical_absent':True})
                owner.docker=docker;owner.parent_abort=Mock()
                owner.abort_owned(error);owner.parent_abort.assert_called_once_with(error)
                if mode=='ok':
                    self.assertEqual(owner._daemon_stops['a'],{'logical_absent':True,'physical_absent':True})
                    self.assertEqual(argv[0][0],('exec','1'*64,'env','CODEX_HOME=/codex','HOME=/codex',subject.CLI,'app-server','daemon','stop'))
                    self.assertEqual([row[1]['timeout'] for row in argv],[5,3])
                else:
                    self.assertEqual(owner._daemon_stops['a'],{'status':'UNKNOWN'})
                    self.assertEqual(len(argv),1 if mode=='stop-error' else 0)
                self.assertIs(owner.rpcs['a'].error,error)

    @unittest.skipUnless(all(Path(path).is_file() for path in subject.DEPENDENCY_PINS),
                         'pinned effective cleanup source absent in a fresh checkout')
    def test_source_derived_cleanup_preserves_health_error_requires_eof_and_join(self):
        gate=self.run_module().safe_overlay('request_observer_gate')
        migration=next(Path(path) for path in subject.DEPENDENCY_PINS if path.endswith('/managed/migration.py'))
        self.assertEqual(subject.digest(migration),subject.DEPENDENCY_PINS[str(migration)])
        tree=ast.parse(migration.read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='cleanup'
                  and any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Attribute) and t.attr=='cleaning' for t in x.targets) for x in n.body))
        source=subject.replace_once(__import__('textwrap').dedent(ast.get_source_segment(migration.read_text(),node)),
                                    'len(self.budget.started)>5','len(self.budget.started)>6')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source-binding.json').write_text('{"files":[]}')
            ns={'stat':__import__('stat'),'shutil':types.SimpleNamespace(rmtree=Mock()),'hashlib':subject.hashlib,
                'json':json,'ROOT':root,'base':types.SimpleNamespace(private_json=Mock())}
            exec(compile(source,'<actual-selected-six-cleanup>','exec'),ns)
            original=ns['cleanup'];original._g2_cap_source=source
            selected=subject.default_cleanup_method(original,gate)
            for mode in ('error-with-eof','missing-eof','reader-alive','expired'):
                with self.subTest(mode=mode):
                    error=RuntimeError('synthetic existing native failure');eof=Mock()
                    eof.is_set.return_value=mode!='missing-eof';eof.wait.return_value=mode!='missing-eof'
                    reader=Mock();reader.is_alive.return_value=mode=='reader-alive'
                    rpc=types.SimpleNamespace(error=error,shutdown_eof=eof,reader=reader,
                        check=Mock(side_effect=error),close=Mock(),observer_rpc_fatal_error_class='RuntimeError')
                    owner=types.SimpleNamespace(rpcs={'a':rpc},nodes={'a':{'container':'synthetic-node'}},
                        containers={'synthetic-node':subject.IMAGE},networks=[],audit_files={},uds_dirs={},
                        result={'status':'FAIL','failure_class':'RuntimeError'},budget=types.SimpleNamespace(started=set()),
                        close_provider_adapters=Mock(),docker=Mock(),root=root,evidence=root,result_paid_dispatches=0,manual_turn_ids=[])
                    owner.policy=gate.bind_policy(types.SimpleNamespace(),time.monotonic(),600)
                    if mode=='expired':owner.policy.cleanup_end=0
                    record={'Id':'1'*64,'Image':subject.IMAGE,'State':{'Running':False},
                        'Config':{'Labels':{'org.cicada.test.run':'synthetic-run'}}}
                    owner.run_id='synthetic-run';owner.cleanup_inspect=Mock(return_value=record);owner.inspect=Mock(return_value=record)
                    selected(owner)
                    self.assertIs(rpc.error,error);self.assertEqual(owner.result['status'],'FAIL')
                    self.assertEqual(owner.result['terminal_exit_code'],1)
                    self.assertEqual(owner.result['cleanup_owned_resources'],mode=='error-with-eof')
                    if mode=='error-with-eof':
                        self.assertEqual(owner.result['observer_shutdown']['a'],'EXPECTED_EOF_CONFIRMED')
                        self.assertEqual(owner.result['observer_runtime_health_after_eof']['a']['status'],'FAILED')
                        reader.join.assert_called_once();rpc.close.assert_called_once()
                    else:
                        self.assertEqual(owner.result['observer_shutdown']['a'],'UNKNOWN_RETAINED_SUBSCRIBER')
                        rpc.close.assert_not_called()

    @unittest.skipUnless(all(Path(path).is_file() for path in subject.DEPENDENCY_PINS),
                         'pinned local service argv sources are absent in a fresh checkout')
    def test_full_source_generated_forwarder_and_agent_cross_actual_default_zero_guards(self):
        gate=self.run_module().safe_overlay('request_observer_gate')
        driver=gate.OLD.parent/'test-two-node-codex-native.py'
        self.assertEqual(subject.digest(driver),subject.DEPENDENCY_PINS[str(driver)])
        tree=ast.parse(driver.read_text())
        literals={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
                  if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
                  and n.targets[0].id in ('CODEX','AGENT_BOOTSTRAP','FORWARDER')}
        start=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='start_services')
        # Generate the two real complete submissions, without their readiness loop.
        start.body=start.body[:3]
        start_ns=dict(literals)
        exec(compile(ast.Module(body=[start],type_ignores=[]),'<pinned-original-service-submissions>','exec'),start_ns)
        original_base=types.SimpleNamespace(start_services=start_ns['start_services'],**literals)
        peer_tree=ast.parse(subject.transform_peer((subject.PEER/'peer_gate_derivative_g2_current_36eb_h5.py').read_text()))
        # Read the exact selected no-key program from the pinned Peer selector.
        bundle=next(n for n in peer_tree.body if isinstance(n,ast.FunctionDef) and n.name=='source_bundle')
        def pinned(path):
            self.assertEqual(subject.digest(path),subject.DEPENDENCY_PINS[str(path)])
            return path.read_text()
        bundle_ns={'ast':ast,'pinned':pinned,'OLD':gate.OLD.parent}
        exec(compile(ast.Module(body=[bundle],type_ignores=[]),'<pinned-peer-programs>','exec'),bundle_ns)
        agent=subject.replace_once(bundle_ns['source_bundle']()['agent'],"os.execvp('/bin/sh'",
            "os.environ.update(CODEX_HOME='/codex',HOME='/codex',PATH='/opt/official-codex/bin:/opt/official-codex/codex-path:/usr/local/bin:/usr/bin:/bin')\nos.execvp('/bin/sh'")
        programs=types.MappingProxyType({'CODEX':subject.CLI,'AGENT_BOOTSTRAP':agent})
        consumed=[]
        class Capture:
            def docker(owner,*argv,**kwargs):consumed.append(list(argv))
        def layer(name,parent,method,namespace):
            cls=ast.ClassDef(name=name,bases=[ast.Name(id='Parent',ctx=ast.Load())],
                keywords=[],body=[method],decorator_list=[])
            namespace=dict(namespace,Parent=parent)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),
                '<actual-'+name+'>','exec'),namespace)
            return namespace[name]
        managed_tree=ast.parse((gate.OLD/'managed_gate.py').read_text())
        managed=next(n for n in ast.walk(managed_tree) if isinstance(n,ast.FunctionDef) and n.name=='docker')
        copies=Mock()
        managed_cls=layer('Managed',Capture,managed,{'base':original_base,'shutil':types.SimpleNamespace(copyfile=copies),'HERE':gate.OLD})
        current_tree=ast.parse((HERE/'request_observer_gate.py').read_text())
        candidate=next(n for n in ast.walk(current_tree) if isinstance(n,ast.ClassDef) and n.name=='CandidateGate')
        candidate_docker=next(n for n in candidate.body if isinstance(n,ast.FunctionDef) and n.name=='docker')
        candidate_cls=layer('Candidate',managed_cls,candidate_docker,{
            'zero_model':True,'validate_zero_command':gate.validate_zero_command,
            'ZERO_AGENT_BOOTSTRAP':gate.ZERO_AGENT_BOOTSTRAP,'hashlib':__import__('hashlib')})
        peer=next(n for n in ast.walk(peer_tree) if isinstance(n,ast.ClassDef) and n.name=='PeerGate')
        peer_cls=layer('Peer',candidate_cls,next(n for n in peer.body if isinstance(n,ast.FunctionDef) and n.name=='docker'),
            {'base_cls':original_base,'sources':{'agent':agent}})
        default=next(n for n in ast.walk(ast.parse((HERE/'request_observer_default.py').read_text()))
                     if isinstance(n,ast.ClassDef) and n.name=='DefaultGate')
        default_cls=layer('Default',peer_cls,next(n for n in default.body if isinstance(n,ast.FunctionDef) and n.name=='docker'),
            {'CLI':subject.CLI,'original_codex':literals['CODEX'],'default_bootstrap_argv':subject.default_bootstrap_argv})
        owner=default_cls();owner._default_daemon_fixture=True;owner._default_zero_agent_programs=programs
        owner.args=types.SimpleNamespace(test_request_observer=False);owner.result={};owner.meta={'hub_id':'hub'}
        owner.run_id='owned';owner.write_forwarder_target=Mock()
        # This override intentionally has no inherited CODEX/AGENT globals.
        owner.start_services=lambda letter:None
        state=MagicMock();owner.nodes={'a':{'container':'owned-a','gateway':'gateway','hub_port':'8787',
            'tls_config':'/fixture/tls-a.json','node_id':'node-a','paths':{'state':state}}}
        generated=[];generator=types.SimpleNamespace(nodes=owner.nodes,meta=owner.meta,
            docker=lambda *argv:generated.append(list(argv)))
        start_ns['start_services'](generator,'a')
        self.assertEqual(len(generated),2)
        for argv in generated:owner.docker(*argv)
        self.assertEqual(consumed[0],['exec','-d','owned-a','python3','/state/hub_forwarder.py','gateway','owned'])
        self.assertEqual(consumed[1][3],'CICADA_CODEX_BIN='+subject.CLI)
        self.assertEqual(consumed[1][17],gate.ZERO_AGENT_BOOTSTRAP)
        self.assertEqual(consumed[1][-4:],generated[1][-4:])
        for argv in consumed:
            self.assertNotIn('--remote',argv)
            self.assertNotIn('CICADA_CODEX_BIN=/state/codex_queue_remote.py',argv)
            gate.validate_zero_command(['docker',*argv],default_daemon_fixture=True)
        self.assertFalse(owner.result['zero_agent_bootstrap']['a']['credential_access'])
        copies.assert_called_once();owner.write_forwarder_target.assert_called_once_with('a')
        invalid=generated[1].copy();invalid[-5]=literals['AGENT_BOOTSTRAP']+'\n# drift'
        with self.assertRaises((PermissionError,ValueError)):owner.docker(*invalid)
        owner._default_daemon_fixture=False
        with self.assertRaises(KeyError):owner.docker(*generated[0])

    def test_cont_failure_preserves_unknown_but_owned_cleanup_continues(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        self.cleanup_owner(owner)
        owner._held_bob=types.SimpleNamespace(pidfd=91)
        owner._hold_lock=threading.RLock();owner._hold_timer=None;owner._hold_failed=False
        owner.result={};owner.nodes={};owner.peer_brokers={};owner._default_daemons_attempted=False;owner._daemon_stops={};owner._default_owned_roots={}
        queue=types.SimpleNamespace(_verify_agent_live=Mock())
        namespace['signal_agent']=Mock(side_effect=OSError('gone'))
        namespace['check_fixture']=Mock()
        with patch.dict(sys.modules,{'peer_queue_admission':queue}),patch.object(signal,'pidfd_send_signal',side_effect=OSError('gone')):
            owner.cleanup()
        self.assertTrue(owner.parent_cleanup_called)
        self.assertIsNotNone(owner._held_bob)
        self.assertTrue(owner._hold_failed)
        self.assertEqual(owner.result['default_agent_hold'],'CONT_OR_AUTHORIZATION_UNKNOWN')
        self.assertEqual(owner.result['terminal_exit_code'],1)

    def test_failure_cleanup_marks_expected_shutdown_before_stop_and_retains_failure(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        self.cleanup_owner(owner)
        error=RuntimeError('existing transport failure')
        rpc=types.SimpleNamespace(shutdown_expected=False,error=error)
        owner.rpcs={'a':rpc};owner._held_bob=None;owner._hold_lock=threading.RLock()
        owner._hold_failed=False;owner.nodes={};owner.peer_brokers={};owner._default_daemons_attempted=True
        owner._daemon_stops={};owner._default_owned_roots={}
        owner.result={'status':'FAIL','failure_class':'RuntimeError','failure_phase':'isolated_nodes'}
        def stop():
            self.assertTrue(owner.intentional_shutdown)
            self.assertTrue(rpc.shutdown_expected)
            self.assertIs(rpc.error,error)
        owner.stop_default_daemons=Mock(side_effect=stop);namespace['check_fixture']=Mock()
        owner.cleanup()
        owner.stop_default_daemons.assert_called_once()
        self.assertTrue(owner.parent_cleanup_called)
        self.assertIs(rpc.error,error)
        self.assertEqual(owner.result['status'],'FAIL')
        self.assertEqual(owner.result['failure_phase'],'isolated_nodes')

    def test_inherited_terminal_failure_cannot_publish_preparation_pass(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        self.cleanup_owner(owner)
        owner.rpcs={};owner._held_bob=None;owner._hold_lock=threading.RLock()
        owner._hold_failed=False;owner._hold_timer=None;owner.nodes={};owner._default_daemons_attempted=False
        owner._daemon_stops={n:{'logical_absent':True,'physical_absent':True} for n in 'ab'}
        owner._default_owned_roots={};owner._count_rows={n:[] for n in 'ab'};owner._count_unknown=set()
        done=threading.Event();done.set()
        owner.peer_brokers={n:types.SimpleNamespace(native=types.SimpleNamespace(idle=done,connections=0,posts=0),
            handler_done=done,owner_done=done,stop=Mock()) for n in 'ab'}
        namespace['remove_owned_roots']=lambda roots:{'private':True,'a':True,'b':True}
        namespace['check_fixture']=Mock()
        owner.result={'status':'PREPARATION_PASS_NATIVE_NOT_RUN','failure_phase':'prior-cleanup',
            'failure_class':'PriorExactFailure','terminal_exit_code':1}
        owner.cleanup()
        self.assertEqual(owner.result['status'],'FAIL');self.assertEqual(owner.result['terminal_exit_code'],1)
        self.assertEqual(owner.result['failure_phase'],'prior-cleanup')
        self.assertEqual(owner.result['failure_class'],'PriorExactFailure')
        self.assertTrue(all(v['status']=='COMPLETE' for v in owner.result['default_provider_post_attempts'].values()))

    def test_cont_success_checks_actual_state_before_clearing_hold(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        agent=types.SimpleNamespace(pidfd=92);owner._held_bob=agent
        owner._hold_lock=threading.RLock();owner._hold_timer=Mock();owner.result={}
        owner._hold_failed=False
        calls=[]
        namespace['signal_agent']=lambda *a:calls.append('signal')
        namespace['wait_agent_state']=lambda *a,**k:calls.append('state')
        with patch.dict(sys.modules,{'peer_queue_admission':types.SimpleNamespace(_verify_agent_live=Mock())}):
            owner.release_default_bob(emergency=True)
        self.assertEqual(calls,['signal','state'])
        self.assertIsNone(owner._held_bob)
        self.assertEqual(owner.result['default_agent_hold'],'EXACT_AGENT_RESUMED')

    def test_expired_hold_marks_failure_and_uses_emergency_cont(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        owner.result={};owner._hold_failed=False;owner.release_default_bob=Mock()
        owner.expire_default_hold()
        self.assertTrue(owner._hold_failed)
        owner.release_default_bob.assert_called_once_with(emergency=True)

    def test_binding_lease_rejects_status_epoch_owner_and_expiry_changes(self):
        node={'binding_before':{'id':'bind','epoch':3},'endpoint':'ep','thread':'sid','node_id':'node','current_group_id':'group'}
        owner=types.SimpleNamespace(nodes={'b':node})
        row={'id':'bind','endpoint_id':'ep','principal_id':'owner','group_id':'group','native_session_id':'sid',
            'node_id':'node','workspace_id':'workspace','epoch':3,'status':'active','lease_owner':'lease',
            'lease_expires_at':'2099-01-01T00:00:00Z','version':2}
        query=Mock(return_value=[row])
        with patch.dict(sys.modules,{'readonly_snapshot':types.SimpleNamespace(rows=query)}):
            for status in ('active','leased'):
                with self.subTest(accepted_status=status):
                    baseline=dict(row,status=status);query.return_value=[baseline]
                    actual,expiry=subject.binding_lease(owner,'b',baseline)
                    self.assertEqual(actual,baseline)
            for status in ('revoked','superseded','released','expired','pending','unknown','online','ready','acquired',''):
                with self.subTest(rejected_status=status),self.assertRaisesRegex(ValueError,'DEFAULT_HOLD_BINDING_SCOPE'):
                    query.return_value=[dict(row,status=status)];subject.binding_lease(owner,'b')
            for key,value in [('status','revoked'),('epoch',4),('lease_owner','other'),('lease_expires_at','2000-01-01T00:00:00Z')]:
                with self.subTest(field=key),self.assertRaises(ValueError):
                    query.return_value=[dict(row,**{key:value})];subject.binding_lease(owner,'b',row)
            for key,value in [('id','other'),('endpoint_id','other'),('native_session_id','other'),
                ('node_id','other'),('group_id','other'),('principal_id',''),('lease_owner',''),
                ('workspace_id',''),('version',0)]:
                with self.subTest(scope_field=key),self.assertRaisesRegex(ValueError,'DEFAULT_HOLD_BINDING_SCOPE'):
                    query.return_value=[dict(row,**{key:value})];subject.binding_lease(owner,'b')
            query.return_value=[dict(row,status='leased')]
            with self.assertRaisesRegex(ValueError,'DEFAULT_HOLD_BINDING_CHANGED'):
                subject.binding_lease(owner,'b',row)
            query.return_value=[row]
            with self.assertRaises(ValueError):subject.binding_lease(owner,'b',minimum_until=expiry+1)

    def test_default_selector_is_off_and_opaque_lane_cannot_be_mixed(self):
        spec=importlib.util.spec_from_file_location('default_current_run',HERE/'request_observer_run.py')
        run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
        self.assertFalse(run.default_daemon_mode(types.SimpleNamespace()))
        args=types.SimpleNamespace(default_daemon_fixture='/public/fixture.json',default_daemon_fixture_sha='a'*64,
            scenario='g2-g3',native_https=False,enable_io_diagnostics=False,response_byte_passthrough=False,native_normal_seconds=600)
        self.assertTrue(run.default_daemon_mode(args));self.assertEqual(run.native_normal_seconds(args),600)
        for key,value in [('native_https',True),('scenario','g1'),('enable_io_diagnostics',True),('default_daemon_fixture_sha','wrong')]:
            with self.subTest(field=key),self.assertRaises(PermissionError):
                run.default_daemon_mode(types.SimpleNamespace(**dict(vars(args),**{key:value})))
        args.native_normal_seconds=180
        with self.assertRaises(PermissionError):run.native_normal_seconds(args)


    def test_default_socket_rejects_direct_socket_or_wrong_symlink(self):
        cls,namespace=self.selected_gate();owner=object.__new__(cls)
        with tempfile.TemporaryDirectory() as root:
            home=Path(root);state=home/'state';codex=home/'codex';state.mkdir();codex.mkdir()
            owner.nodes={'a':{'paths':{'state':state,'codex':codex}}}
            (state/'managed-server-process.json').write_text(json.dumps({'exit_code':None,'daemon_status':'running',
                'daemon_version':'0.162.1','logical_socket':subject.LOGICAL,'managed_cli_sha256':subject.CLI_SHA}))
            alias=codex/'app-server-control/app-server-control.sock';alias.parent.mkdir()
            alias.write_text('direct inode forbidden')
            with self.assertRaises(ValueError):owner.mapped_official_socket('a',alias)
            alias.unlink();alias.symlink_to('/tmp/other-daemon.sock')
            with self.assertRaises(ValueError):owner.mapped_official_socket('a',alias)

    def run_module(self):
        spec=importlib.util.spec_from_file_location('default_reuse_run',HERE/'request_observer_run.py')
        run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
        return run

    def test_reuse_receipt_pin_rejects_changed_actual_bytes(self):
        run=self.run_module()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'receipt.json';path.write_text('{"status":"PASS"}')
            with patch.object(run,'REUSE_ROOT',Path(root)),self.assertRaises(PermissionError):
                run.reuse_reference({'path':str(path),'sha256':'a'*64})

    def test_reuse_input_row_rejects_wrong_sha_without_build(self):
        run=self.run_module()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'fixture.go';path.write_text('package fixture\n')
            row={'path':str(path),'bytes':path.stat().st_size,'rawmode':path.stat().st_mode,'sha256':'a'*64}
            with self.assertRaises(PermissionError):run.g2_public_row(row,paths={str(path)})

    def test_reuse_refuses_wrong_producer_before_receipt_reads(self):
        run=self.run_module()
        keys={'schema','producer_revision','fixture_revision','fixture_dirty','packaging_result','pq_receipt',
            'standard_metadata','package_metadata','image_pins','image_assembly','image_result','helper','input_scope'}
        proof=dict.fromkeys(keys)
        proof.update(schema=run.PACKAGING_REUSE_SCHEMA,producer_revision='0'*40,
            fixture_revision=run.REUSE_FIXTURE_REV,fixture_dirty=True)
        with patch.object(run,'reuse_reference') as read,self.assertRaises(PermissionError):
            run.g2_packaging_reuse_inputs({'commit':run.REUSE_PRODUCT_REV,'source_dirty':False,'package':str(run.REUSE_PQ)}, {},proof)
        read.assert_not_called()

    def test_reuse_image_identity_rejects_standard_or_wrong_entry_bytes(self):
        import copy
        run=self.run_module();sha='a'*64;imageid='sha256:'+'b'*64
        hashes={'bin/cicada':sha}
        pins={'source_fingerprint':'c'*64,'package_receipt_sha256':'d'*64,'archive_sha256':'e'*64,
            'package_metadata_sha256':'f'*64,'context_files':{'hub.Dockerfile':{'sha256':sha}},
            'package_files':{'bin/cicada':{'bytes':10,'context_mode':493}}}
        producer={'revision':run.REUSE_PRODUCT_REV,'dirty':False,'software_version':'0.0.2',
            **{k:pins[k] for k in ('source_fingerprint','package_receipt_sha256','archive_sha256','package_metadata_sha256')}}
        paths={'/lib/x86_64-linux-gnu/libc.so.6','/lib64/ld-linux-x86-64.so.2','/etc/nsswitch.conf',
            '/etc/ssl/certs/ca-certificates.crt','/usr/share/licenses/glibc/copyright','/usr/share/licenses/glibc/LGPL-2.1',
            '/usr/share/licenses/glibc/GPL-2','/usr/share/licenses/ca-certificates/copyright','/usr/share/licenses/base-files/copyright',
            '/usr/share/licenses/donor/dpkg-status','/usr/share/licenses/donor/SOURCE.json'}
        image={'schema':'cicada.fixture-pqtls-image-assembly.v1','status':'PASS_ASSEMBLY_ONLY_NOT_NATIVE_NOT_RELEASE',
            'runtime_started':False,'models':0,'image':{'id':imageid,'donor_id':'sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195','recipe_sha256':sha},
            'producer':producer,'package_files':{'bin/cicada':{'sha256':sha,'bytes':10,'mode':493}},
            'donor_runtime_and_notices':{p:{'sha256':sha,'bytes':2} for p in paths}}
        result={'status':'PASS_ASSEMBLY_ONLY','build_exit_code':0,'image_id':imageid,'models':0,'runtime_starts':0,'checks':{'source':True}}
        delivery={'hub_image':imageid}
        run.reuse_image_identity(image,result,pins,delivery,hashes)
        wrong=copy.deepcopy(image);wrong['image']['id']='sha256:'+'9'*64
        with self.assertRaises(PermissionError):run.reuse_image_identity(wrong,result,pins,delivery,hashes)
        wrong=copy.deepcopy(image);wrong['package_files']['bin/cicada']['sha256']='0'*64
        with self.assertRaises(PermissionError):run.reuse_image_identity(wrong,result,pins,delivery,hashes)


    def test_owned_roots_do_not_delete_unknown_or_nonempty_directories(self):
        with tempfile.TemporaryDirectory(prefix='cicada-dflt-g2-test-') as root:
            paths=[Path(root)/n for n in 'abc']
            for p in paths:p.mkdir()
            owned={p:(p.stat().st_dev,p.stat().st_ino) for p in paths}
            (paths[1]/'unknown.txt').write_text('retain')
            owned[paths[2]]=(0,0)
            result=subject.remove_owned_roots(owned)
            self.assertTrue(result[str(paths[0])])
            self.assertFalse(result[str(paths[1])]);self.assertFalse(result[str(paths[2])])
            self.assertTrue((paths[1]/'unknown.txt').exists())


    def test_reuse_equality_rejects_missing_generated_manifest_or_false_domain(self):
        import hashlib
        run=self.run_module();binding=run.current_binding;sha='a'*64
        with tempfile.TemporaryDirectory() as root:
            package=Path(root);meta=package/'BUILD-METADATA.json'
            meta.write_text(json.dumps({'source':{'revision':run.REUSE_PRODUCT_REV,'dirty':False},'pqtls_available':True,'hub_webcrypto_manifest_sha256':sha}))
            delivery={'package':str(package),'package_metadata_sha256':hashlib.sha256(meta.read_bytes()).hexdigest(),'binary_sha256':'b'*64}
            equality={'schema':binding.REUSE_EQUALITY_SCHEMA,'status':'TRACKED_INPUT_INVENTORY_CURRENT_BYTES_EQUAL',
                'input_scope':binding.REUSE_INPUT_SCOPE,'excluded_generated_paths':binding.REUSE_GENERATED_PATHS,
                'current_commit':run.REUSE_PRODUCT_REV,'product_artifact_origin_revision':run.REUSE_PRODUCT_REV,
                'fixture_revision':run.REUSE_FIXTURE_REV,'fixture_dirty':True,'artifact_binary_sha256':'b'*64,
                'artifact_input_projection_sha256':'c'*64,'current_input_projection_sha256':'c'*64,'package_generated_manifest_sha256':sha}
            binding.validate_reuse_equality(delivery,equality,run.REUSE_PRODUCT_REV)
            for key,value in [('package_generated_manifest_sha256',None),('excluded_generated_paths',[]),
                ('input_scope','COMPILED_INPUTS_EXACT'),('status','COMPILED_INPUTS_EXACT'),('current_compiled_inputs_sha256','c'*64)]:
                with self.subTest(field=key),self.assertRaises(ValueError):
                    binding.validate_reuse_equality(delivery,dict(equality,**{key:value}),run.REUSE_PRODUCT_REV)
            with self.assertRaises(ValueError):
                binding.validate_reuse_equality(dict(delivery,package_metadata_sha256='0'*64),equality,run.REUSE_PRODUCT_REV)



if __name__=='__main__': unittest.main(verbosity=2)
