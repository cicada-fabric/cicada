"""Synthetic standalone codec + installed public wiring checks, no native calls."""
# Reuse the already reviewed pre-constructor external-effect tripwires and fixture.
import test_native_request_observer as base_fixture
from test_native_request_observer import (observer, FakeSocket,
    REQUEST, RESPONSE, THREAD, TURN, ASSOCIATION, denied)
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import builtins
import subprocess
import socket
import threading
import hashlib
import time
import pathlib
from unittest.mock import patch
_import_guards = contextlib.ExitStack()
_FORBIDDEN = '/synthetic/forbidden-io-credential'
_CREDENTIAL = '/gpu1-share/data/cicada/secrets/cicada-acceptance-zzswitch-20261003.env'
def guarded_path(original):
    def guarded(path,*args,**kwargs):
        if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path) in (_CREDENTIAL,_FORBIDDEN): denied()
        return original(path,*args,**kwargs)
    return guarded
for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):
    _import_guards.enter_context(patch.object(owner,name,guarded_path(getattr(owner,name))))
import native_request_observer_io as codec
sys.path.insert(0,str(Path(__file__).parent/'native_observer'))
import request_observer_gate as gate
import request_observer_run as run
import request_observer_bootstrap as bootstrap
_import_guards.close()


def row(sequence=0,before=0,after=1):
    return dict(schema=observer.IO_SCHEMA,sequence=sequence,POST_before=before,POST_after=after,
        shutdown_requested=False,first_failure=None,cleanup_failures=[],cleanup_truncated=False,upstream_eof=True)


def watermark(count):
    return dict(schema='cicada.native-observer-io-watermark.v1',admitted=count,successful=count,
                failed=False,sealed=True,drained=True)


class IOChecks(unittest.TestCase):
    def setUp(self):
        # Per-test lifetime survives another module's teardown; before any fixture.
        guards=contextlib.ExitStack()
        self.addCleanup(guards.close)
        for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):
            guards.enter_context(patch.object(owner,name,guarded_path(getattr(owner,name))))
        for owner,name,value in ((socket,'socket',base_fixture.unix_only),
            (socket,'create_connection',denied),(socket,'getaddrinfo',denied),
            (socket,'gethostbyname',denied),(subprocess,'Popen',denied),
            (subprocess,'run',denied),(os,'system',denied),
            (observer.ssl,'create_default_context',denied)):
            guards.enter_context(patch.object(owner,name,value))

    def test_sink_export_and_canonical_privacy(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'synthetic.jsonl'; sink=codec.IOSink(path)
            sink(row()); mark=sink.seal(type('State',(),{'io_sequence':1})(),{'drained':True})
            self.assertEqual(codec.validate_export(path.read_bytes(),mark),[row()])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertNotIn(b'PUBLIC_ALPHA',path.read_bytes())
            bad=row();bad['body']='PRIVATE'
            with self.assertRaises(ValueError):codec.canonical(bad)
            self.assertTrue(codec.IOSink(path).failed)

    def test_bounds_bad_watermark_and_duplicates(self):
        raw=codec.canonical(row())
        for field,value in [('failed',True),('sealed',False),('drained',False),('admitted',True),('successful',0)]:
            mark=watermark(1);mark[field]=value
            with self.assertRaises(ValueError):codec.validate_export(raw,mark)
        for data in (b'x'*32769,raw*17,raw.replace(b'"sequence":0',b'"sequence":0,"sequence":0'),json.dumps(row()).encode()+b'\n'):
            with self.assertRaises(ValueError):codec.validate_export(data,watermark(1))

    def test_ordinal_join_presend_failure_and_missing_join(self):
        fixture=base_fixture.DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture()
        instance.core_metadata=True
        instance.handle(client,None)
        joined=codec.join_records(diagnostics,originals,THREAD,{(THREAD,TURN)},watermark(1))
        self.assertEqual(joined['status'],'COMPLETE')
        # A completed ordinal with unchanged counter is valid before SEND_REQUEST.
        def failed_connect(deadline):
            raise ConnectionResetError('PUBLIC_SYNTHETIC')
        failed,failed_client,_,failed_originals,failed_diagnostics=fixture.fixture(connector=failed_connect)
        failed.core_metadata=True
        failed.handle(failed_client,None)
        self.assertEqual(failed_diagnostics[0]['POST_before'],0)
        self.assertEqual(failed_diagnostics[0]['POST_after'],0)
        self.assertEqual(failed_originals[0]['status'],'UNKNOWN_IO')
        self.assertEqual(failed_diagnostics[0]['first_failure']['phase'],'INJECTED_CONNECTOR')
        self.assertEqual(codec.join_records(failed_diagnostics,failed_originals,THREAD,{(THREAD,TURN)},watermark(1))['status'],'COMPLETE')
        for mark,turns in [(None,{(THREAD,TURN)}),(watermark(1),set())]:
            self.assertEqual(codec.join_records(diagnostics,originals,THREAD,turns,mark)['status'],'UNKNOWN')
        self.assertEqual(codec.join_records([],[],THREAD,set(),watermark(0))['status'],'UNKNOWN')

    def test_sink_failure_preserves_original_and_counter(self):
        fixture=base_fixture.DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture(sink=denied)
        instance.handle(client,ASSOCIATION)
        self.assertEqual(originals[0]['status'],'FORWARDED');self.assertEqual(instance.posts,1)
        self.assertFalse(instance.busy);self.assertTrue(instance.idle.is_set())

    def test_actual_publication_and_unix_quiesce(self):
        base_fixture.DiagnosticsChecks().test_publication_precedes_idle_and_next_handler()

    def test_default_off_and_fresh_cutoff_guard(self):
        with patch.object(Path,'open',denied),patch.object(Path,'lstat',denied),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(codec.main([]),0);self.assertEqual(run.main([]),0)
            self.assertEqual(bootstrap.main(['shim']),0)
            self.assertEqual(run.main(['--execute-diagnostic']),2)
        self.assertFalse(run.EXECUTION_EFFECTS_STARTED)

    def test_installed_effective_programs(self):
        sources=gate.effective_sources()
        import ast
        tree=ast.parse(sources['gate'])
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='capture_test_request_observer')
        export=next(n.value for n in ast.walk(method) if isinstance(n,ast.Constant) and type(n.value) is str and 'from native_request_observer_io import validate_export' in n.value)
        self.assertIn("sibling.get('watermark')",sources['gate'])
        class SyntheticThread:
            def __init__(self,*args,**kwargs): pass
            def start(self): pass
            def join(self,*args,**kwargs): pass
            def is_alive(self): return False
        process=type('Process',(),{'pid':123,'stdout':io.BytesIO(),'stderr':io.BytesIO(),'wait':lambda self:0})()
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            RealPath=type(base)
            def mapped(value):
                p=RealPath(value)
                return base/str(p).lstrip('/') if p.is_absolute() and not str(p).startswith(directory) else p
            for name in ('run/secrets','codex','state','tmp'):(base/name).mkdir(parents=True,exist_ok=True)
            (base/'run/secrets/provider.env').write_text('API_KEY=PUBLIC_SYNTHETIC\n')
            public="[model_providers.basil]\nbase_url='https://synthetic.invalid'\n"
            (base/'codex/config.toml').write_text(public)
            now=time.monotonic();args=['shim','paid','http://192.0.2.1:7890','--test-request-observer',hashlib.sha256(b'https://synthetic.invalid').hexdigest(),repr(now+20),'16']
            namespace={'__name__':'__synthetic_installed__'}
            guarded_open=os.open
            def mapped_open(path,flags,*args,**kwargs):
                if isinstance(path,(str,bytes,os.PathLike)):
                    if os.fsdecode(path) in (_CREDENTIAL,_FORBIDDEN): denied()
                    path=mapped(os.fsdecode(path))
                return guarded_open(path,flags,*args,**kwargs)
            original_quiesce=observer.Observer.quiesce
            original_seal=codec.IOSink.seal
            observed=[]
            def quiesce(instance,*args,**kwargs):
                observed.append(('quiesce',instance.io_sink))
                return original_quiesce(instance,*args,**kwargs)
            def seal(sink,instance,drain):
                observed.append(('seal',sink))
                return original_seal(sink,instance,drain)
            with patch.object(pathlib,'Path',mapped),patch.object(codec,'Path',mapped),patch.object(os,'open',mapped_open),patch.object(sys,'argv',args),patch.dict(os.environ,{},clear=True),patch.object(os,'chdir',lambda path:None),patch.object(sys,'excepthook',sys.excepthook),patch.object(subprocess,'Popen',return_value=process),patch.object(threading,'Thread',SyntheticThread),patch.object(observer.Observer,'open',return_value=12345),patch.object(observer.Observer,'quiesce',quiesce),patch.object(codec.IOSink,'seal',seal):
                with self.assertRaises(SystemExit) as stopped:exec(compile(sources['bootstrap'],'<synthetic-installed-bootstrap>','exec'),namespace)
                self.assertEqual(stopped.exception.code,0)
            created_watermark=base/'tmp/cicada-request-observer-io-watermark.json'
            self.assertTrue(created_watermark.is_file())
            self.assertEqual(json.loads(created_watermark.read_bytes()),watermark(0))
            self.assertEqual(created_watermark.stat().st_mode & 0o777,0o600)
            self.assertIsInstance(namespace['observer'].io_sink,codec.IOSink)
            self.assertEqual([item[0] for item in observed],['quiesce','seal'])
            fixture=base_fixture.DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture()
            instance.io_diagnostics_v2=True
            instance.handle(client,ASSOCIATION)
            (base/'tmp/cicada-request-observer-records.jsonl').write_text(json.dumps(originals[0])+'\n')
            (base/'tmp/cicada-request-observer-io.jsonl').write_bytes(codec.canonical(diagnostics[0],v2=True))
            mark_path=base/'tmp/cicada-request-observer-io-watermark.json'
            for mark,expected in ((watermark(1),'COMPLETE'),(dict(watermark(1),successful=0),'UNKNOWN')):
                mark_path.write_text(json.dumps(mark))
                output=io.StringIO()
                with patch.object(pathlib,'Path',mapped),patch.object(sys,'argv',['export',repr(time.monotonic()+1)]),contextlib.redirect_stdout(output):
                    exec(compile(export,'<synthetic-installed-export>','exec'),{'__name__':'__synthetic_export__'})
                result=json.loads(output.getvalue())
                self.assertEqual(result['io_sibling']['status'],expected)
                self.assertNotIn('PUBLIC_ALPHA',output.getvalue())
        for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):
            with self.assertRaises(AssertionError):getattr(owner,name)(_FORBIDDEN)



class V2MemoryChecks(unittest.TestCase):
    """Memory-only diagnostics; no socket creation, threads or external processes."""
    def fixture(self, *, v2=True, connector=None, upstream=None):
        originals, rows = [], []
        upstream = upstream or FakeSocket([RESPONSE])
        instance = observer.Observer('https://synthetic.invalid/responses', 'PUBLIC_ALPHA', originals.append,
            enabled=True, bound_thread=THREAD, core_metadata=True,
            injected_connector=connector or (lambda deadline: upstream), io_sink=rows.append,
            io_diagnostics_v2=v2)
        return instance, originals, rows

    def test_v1_bytes_and_v2_strict_codec_join(self):
        old=row(); old['upstream_eof']=False; self.assertEqual(codec.canonical(old), (json.dumps(old,sort_keys=True,separators=(',',':'))+'\n').encode())
        instance,originals,rows=self.fixture(); instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(originals[0]['status'],'FORWARDED'); self.assertEqual(instance.posts,1)
        with self.assertRaises(ValueError): codec.canonical(rows[0])
        raw=codec.canonical(rows[0],v2=True)
        self.assertEqual(codec.validate_export(raw,watermark(1),v2=True),rows)
        self.assertEqual(codec.join_records(rows,originals,THREAD,{(THREAD,TURN)},watermark(1),v2=True)['status'],'COMPLETE')
        for key,value in [('local_tcp_port',True),('local_tcp_port',65536),('sequence',16),('schema',observer.IO_SCHEMA)]:
            bad=copy.deepcopy(rows[0]);bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):codec.canonical(bad,v2=True)
        with self.assertRaises(ValueError):codec.validate_export(raw,watermark(0),v2=True)
        old_instance,old_originals,old_rows=self.fixture(v2=False);old_instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(originals,old_originals);self.assertEqual(codec.canonical(old_rows[0]),codec.canonical(old))

    def test_ssl_primary_before_masking_close_and_failure_instant(self):
        error=observer.ssl.SSLEOFError(8,'SECRET_EXCEPTION_NEVER_EXPORT');error.reason='UNEXPECTED_EOF_WHILE_READING'
        plain=FakeSocket(close_error=BrokenPipeError(32,'SECRET_CLOSE_NEVER_EXPORT'))
        plain.getsockname=lambda:('SECRET_ADDRESS_NEVER_EXPORT',43210)
        class TLS:
            def set_alpn_protocols(self,value):pass
            def wrap_socket(self,*a,**k):raise error
        instance,originals,rows=self.fixture();instance.connector=None
        diagnostic=dict(row(after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
        with patch.object(observer.ssl,'create_default_context',return_value=TLS()),patch.object(observer.socket,'create_connection',return_value=plain),patch.object(observer.time,'monotonic_ns',side_effect=[100,200]):
            with self.assertRaises(BrokenPipeError):instance._connect(time.monotonic()+1,diagnostic)
        self.assertEqual(diagnostic['first_failure']['ssl_subtype'],'SSL_EOF')
        self.assertEqual(diagnostic['first_failure']['errno'],8)
        self.assertEqual(diagnostic['first_failure']['class'],'OTHER')
        self.assertEqual(diagnostic['first_failure']['monotonic_ns'],100)
        self.assertEqual(diagnostic['cleanup_failures'][0]['monotonic_ns'],200)
        self.assertEqual(diagnostic['local_tcp_port'],43210); self.assertEqual(instance.posts,0)
        observer.validate_io_diagnostic_v2(diagnostic)
        self.assertNotIn('SECRET',codec.canonical(diagnostic,v2=True).decode())
        def fail(deadline):raise error
        instance,originals,rows=self.fixture(connector=fail)
        instance.sink=lambda record:(originals.append(record),instance.close())
        instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(rows[0]['first_failure']['phase'],'INJECTED_CONNECTOR')
        self.assertFalse(rows[0]['first_failure']['shutdown_requested']);self.assertTrue(rows[0]['shutdown_requested'])
        self.assertEqual(instance.posts,0)

    def test_closed_unknowns_clock_metadata_sink_failures(self):
        diagnostic=dict(row(after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
        error=observer.ssl.SSLError(99,'RAW_SECRET');error.reason='RAW_SECRET'
        with patch.object(observer.time,'monotonic_ns',side_effect=BaseException()):
            observer._note_io(diagnostic,'TLS_HANDSHAKE',error)
        failure=diagnostic['first_failure'];self.assertIsNone(failure['monotonic_ns']);self.assertIsNone(failure['errno'])
        self.assertEqual(failure['ssl_reason'],'OTHER_REASON')
        for n in range(5):observer._note_io(diagnostic,'CLOSE_PLAIN',error,cleanup=True)
        self.assertEqual(len(diagnostic['cleanup_failures']),3);self.assertTrue(diagnostic['cleanup_truncated'])
        observer.validate_io_diagnostic_v2(diagnostic)
        for key,value in [('ssl_subtype','RAW_SECRET'),('ssl_reason','RAW_SECRET'),('errno',True),('monotonic_ns',-1)]:
            bad=copy.deepcopy(diagnostic);bad['first_failure'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):codec.canonical(bad,v2=True)
        instance,originals,rows=self.fixture();instance.io_sink=lambda record:(_ for _ in ()).throw(BaseException())
        instance.handle(FakeSocket([REQUEST]),None);self.assertEqual(instance.posts,1)
        self.assertEqual(originals[0]['status'],'FORWARDED');self.assertFalse(instance.busy);self.assertTrue(instance.idle.is_set())

    def test_upstream_eof_and_v2_disabled_without_sink(self):
        instance,originals,rows=self.fixture(upstream=FakeSocket([b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nPUBLIC']));instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(instance.posts,1);self.assertTrue(rows[0]['upstream_eof'])
        instance,originals,rows=self.fixture();instance.io_sink=None;instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(instance.io_sequence,0);self.assertEqual(rows,[])

    def test_owned_relay_default_and_opt_in_ast_and_first_fatal(self):
        import ast,types
        default=gate.client_read_cancellation_relay_source()
        self.assertEqual(hashlib.sha256(default.encode()).hexdigest(),'0e0d25764e77e86855b0e01b47684cffc51b88f2706e4c827701b82f6aceacb0')
        enabled=ast.parse(gate.client_read_cancellation_relay_source(io_diagnostics_v2=True))
        calls=[n for n in ast.walk(enabled) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='_note_forwarder_fatal']
        self.assertEqual(len(calls),1)
        parent=next(n for n in ast.walk(enabled) if isinstance(n,ast.If) and calls[0] in n.orelse);parent.orelse.remove(calls[0])
        self.assertEqual(ast.dump(enabled),ast.dump(ast.parse(default)))
        client=FakeSocket();client.getpeername=lambda:('SECRET_ADDRESS',54321)
        upstream=FakeSocket();adapter=types.SimpleNamespace(lock=threading.RLock(),first_fatal_io=None)
        with patch.object(observer.time,'monotonic_ns',return_value=123):
            gate.note_forwarder_fatal(adapter,'connect',OSError(107,'SECRET'),client,None,None,None)
        first=copy.deepcopy(adapter.first_fatal_io)
        self.assertIsNone(first['pending_client_bytes']);self.assertIsNone(first['client_eof'])
        self.assertEqual(first['client_peer_port'],54321);self.assertEqual(first['monotonic_ns'],123)
        gate.note_forwarder_fatal(adapter,'recv_upstream',ConnectionResetError(104,'SECRET'),client,upstream,{client:bytearray(),upstream:bytearray()},{client})
        self.assertEqual(first,adapter.first_fatal_io);self.assertNotIn('SECRET',json.dumps(first))

    def test_effective_lane_selects_v2_without_default_codec_relaxation(self):
        source=gate.effective_sources()["bootstrap"]
        self.assertIn('io_diagnostics_v2=True',source);self.assertIn('v2=True',source)
        sources=gate.effective_sources();self.assertIn('validate_export(io_raw,io_mark,v2=True)',sources['gate'])
        self.assertIn("v2=True)",sources['gate']);self.assertIn('_install_client_read_cancellation(self, adapter)',sources['provider'])

    def test_enabled_actual_relay_fatal_vs_ignored_cancellation(self):
        module=gate.safe_module('memory_v2_provider',gate.OLD/'provider_transport.py')
        run_id='cicada-two-turn-v2memory0001'
        binding={'run_id':run_id,'network_id':'a'*64,'network_name':run_id+'-a-net','network_label':run_id,
            'driver':'bridge','subnet':'172.29.0.0/24','gateway':'172.29.0.1','clients':['172.29.0.2'],
            'lifetime':10,'max_connections':4,'max_active':1,'upstream_host':'127.0.0.1','upstream_port':7890}
        actual={'Id':'a'*64,'Name':binding['network_name'],'Driver':'bridge','Labels':{'org.cicada.test.run':run_id},
            'IPAM':{'Config':[{'Subnet':binding['subnet'],'Gateway':binding['gateway']}]},
            'Containers':{'b'*64:{'IPv4Address':'172.29.0.2/24'}}}
        class Sock(FakeSocket):
            def setblocking(self,value):pass
            def getpeername(self):return ('SECRET_IP',50001)
            def send(self,data):return len(data)
        for client_error,upstream_error,expected in [(ConnectionResetError(104,'SECRET'),None,0),
                (ConnectionResetError(107,'SECRET'),None,1),(None,ConnectionResetError(104,'SECRET'),1)]:
            with self.subTest(fatal=expected):
                client=Sock([client_error] if client_error else []);upstream=Sock([upstream_error] if upstream_error else [])
                adapter=module.Forwarder(binding,actual,clock=lambda:0,connect=lambda *a,**k:upstream,
                    select_ready=lambda readers,writers,errors,timeout:([client if client_error else upstream],[],[]))
                gate.install_client_read_cancellation(adapter,io_diagnostics_v2=True)
                adapter.active=1;adapter.sockets.add(client);adapter.relay(client)
                self.assertEqual(adapter.failures,expected)
                self.assertEqual(adapter.first_fatal_io is not None,bool(expected))
                self.assertEqual(adapter.active,0)
                if expected:self.assertEqual(adapter.first_fatal_io['errno'],107 if client_error else 104)
                else:self.assertEqual(adapter.client_read_cancellations,1)

    def test_concrete_ssl_subtypes_and_strict_memory_sink(self):
        for error_type,label in observer.SSL_SUBTYPES.items():
            with self.subTest(subtype=label):
                error=error_type(8,'SECRET');error.reason='UNEXPECTED_EOF_WHILE_READING'
                diagnostic=dict(row(after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
                observer._note_io(diagnostic,'TLS_HANDSHAKE',error)
                self.assertEqual(diagnostic['first_failure']['ssl_subtype'],label)
                codec.canonical(diagnostic,v2=True)
        class MemoryFile(io.BytesIO):
            def fileno(self):return 99
            def close(self):self.was_closed=True
        output=MemoryFile();diagnostic=dict(row(after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
        with patch.object(codec.os,'open',return_value=99),patch.object(codec.os,'fdopen',return_value=output),patch.object(codec.os,'fsync',return_value=None):
            sink=codec.IOSink('/synthetic/io',v2=True);sink(diagnostic)
            self.assertEqual(output.getvalue(),codec.canonical(diagnostic,v2=True))
            mark=sink.seal(type('Counter',(),{'io_sequence':1})(),{'drained':True})
            self.assertTrue(mark['sealed']);self.assertFalse(mark['failed'])
            invalid=copy.deepcopy(diagnostic);invalid['local_tcp_port']=True
            sink(invalid);self.assertTrue(sink.failed)

    def test_hostile_attributes_and_exact_opt_in_selected_pin(self):
        import types
        class Hostile(Exception):
            @property
            def reason(self):raise BaseException()
            @property
            def errno(self):raise BaseException()
        diagnostic=dict(row(after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
        observer._note_io(diagnostic,'TLS_HANDSHAKE',Hostile())
        self.assertEqual(diagnostic['first_failure']['class'],'OTHER')
        self.assertEqual(diagnostic['first_failure']['ssl_reason'],'OTHER_REASON')
        self.assertIsNone(diagnostic['first_failure']['errno']);codec.canonical(diagnostic,v2=True)
        adapter=types.SimpleNamespace(lock=threading.RLock(),first_fatal_io=None)
        gate.note_forwarder_fatal(adapter,'connect',Hostile(),FakeSocket(),None,None,None)
        self.assertIsNotNone(adapter.first_fatal_io);self.assertIsNone(adapter.first_fatal_io['errno'])
        default=gate.client_read_cancellation_relay_source()
        self.assertEqual(default,gate.client_read_cancellation_relay_source(io_diagnostics_v2=1))
        module=gate.safe_module('v2_selected_pin_provider',gate.OLD/'provider_transport.py')
        adapter=object.__new__(module.Forwarder)
        with self.assertRaisesRegex(ValueError,'OWNED_RELAY_PIN'):
            gate.install_client_read_cancellation(adapter,hashlib.sha256(default.encode()).hexdigest(),io_diagnostics_v2=True)
        with self.assertRaises(ValueError):codec.canonical(diagnostic,v2=1)

    def test_current_tls_entry_default_refusal_and_projection(self):
        import request_observer_tls_probe as probe
        with patch.object(sys,'argv',['probe']),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(),0)
        self.assertEqual(json.loads(output.getvalue()),{'status':'NONAUTH','effects':False})
        with patch.object(sys,'argv',['probe','--execute-tls-only','--unique-run','bad']):
            with self.assertRaises(ValueError):probe.main()
        compile(probe.PROGRAM,'<tls-only-v2-memory>','exec')
        self.assertNotIn('.handle(',probe.PROGRAM)
        self.assertNotIn('.sendall(',probe.PROGRAM)
        namespace={'dev':1,'ino':2,'link':'time:[2]','boot_id_sha256':'a'*64}
        records=[]
        for index in range(4):
            diagnostic=dict(row(index,before=0,after=0),schema=observer.IO_SCHEMA_V2,local_tcp_port=None)
            records.append({'attempt':index+1,'status':'TLS_HANDSHAKE_PASS','start_ns':index,'end_ns':index+1,'diagnostic':diagnostic})
        projection={'schema':'cicada.tls-only.closed.v2','rows':records,'application_POSTs':0,
            'observer_handle_called':False,'default_CA_configured':True,'hostname_validation_configured':True,
            'ALPN_policy':'http/1.1','time_namespace':namespace}
        self.assertEqual(probe.validate_projection(projection),projection)
        failed=copy.deepcopy(projection);failed['rows'][0]['status']='TLS_HANDSHAKE_FAILED'
        with self.assertRaises(ValueError):probe.validate_projection(failed)
        bad_time=copy.deepcopy(projection);bad_time['rows'][1]['start_ns']=0
        with self.assertRaises(ValueError):probe.validate_projection(bad_time)
        for key,value in [('application_POSTs',True),('rows',records[:3]),('time_namespace',dict(namespace,link='SECRET'))]:
            bad=copy.deepcopy(projection);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):probe.validate_projection(bad)

if __name__=='__main__':
    unittest.main(verbosity=2)
