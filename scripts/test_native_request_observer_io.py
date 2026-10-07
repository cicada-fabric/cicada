"""Synthetic standalone codec + installed public wiring checks, no native calls."""
# Reuse the already reviewed pre-constructor external-effect tripwires and fixture.
from test_native_request_observer import (observer, DiagnosticsChecks, FakeSocket,
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
_guards = contextlib.ExitStack()
_CREDENTIAL = '/gpu1-share/data/cicada/secrets/cicada-acceptance-zzswitch-20261003.env'
def guarded_path(original):
    def guarded(path,*args,**kwargs):
        if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path)==_CREDENTIAL: denied()
        return original(path,*args,**kwargs)
    return guarded
for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):
    _guards.enter_context(patch.object(owner,name,guarded_path(getattr(owner,name))))
import native_request_observer_io as codec
sys.path.insert(0,str(Path(__file__).parent/'native_observer'))
import request_observer_gate as gate
import request_observer_run as run
import request_observer_bootstrap as bootstrap


def row(sequence=0,before=0,after=1):
    return dict(schema=observer.IO_SCHEMA,sequence=sequence,POST_before=before,POST_after=after,
        shutdown_requested=False,first_failure=None,cleanup_failures=[],cleanup_truncated=False,upstream_eof=True)


def watermark(count):
    return dict(schema='cicada.native-observer-io-watermark.v1',admitted=count,successful=count,
                failed=False,sealed=True,drained=True)


class IOChecks(unittest.TestCase):
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
        fixture=DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture()
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
        fixture=DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture(sink=denied)
        instance.handle(client,ASSOCIATION)
        self.assertEqual(originals[0]['status'],'FORWARDED');self.assertEqual(instance.posts,1)
        self.assertFalse(instance.busy);self.assertTrue(instance.idle.is_set())

    def test_actual_publication_and_unix_quiesce(self):
        DiagnosticsChecks().test_publication_precedes_idle_and_next_handler()

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
                    if os.fsdecode(path)==_CREDENTIAL: denied()
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
            fixture=DiagnosticsChecks(); instance,client,up,originals,diagnostics=fixture.fixture()
            instance.handle(client,ASSOCIATION)
            (base/'tmp/cicada-request-observer-records.jsonl').write_text(json.dumps(originals[0])+'\n')
            (base/'tmp/cicada-request-observer-io.jsonl').write_bytes(codec.canonical(diagnostics[0]))
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
            with self.assertRaises(AssertionError):getattr(owner,name)(_CREDENTIAL)


if __name__=='__main__':
    unittest.main(verbosity=2)
