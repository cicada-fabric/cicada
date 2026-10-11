"""Public synthetic, offline-only IO diagnostic tests; no Runtime or provider."""
import builtins
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch


def denied(*args, **kwargs):
    raise AssertionError('EXTERNAL_EFFECT_DENIED')


# Deny external effects before loading the observer or constructing fixtures.
_guards = contextlib.ExitStack()
_socket = socket.socket

def unix_only(family=socket.AF_INET, *args, **kwargs):
    if family != socket.AF_UNIX:
        denied()
    return _socket(family, *args, **kwargs)

for owner, name, value in ((socket, 'socket', unix_only), (socket, 'create_connection', denied),
        (socket, 'getaddrinfo', denied), (socket, 'gethostbyname', denied),
        (subprocess, 'Popen', denied), (subprocess, 'run', denied), (os, 'system', denied)):
    _guards.enter_context(patch.object(owner, name, value))

CREDENTIAL_SENTINEL = '/synthetic/forbidden-credential'
def guard_path(original):
    def guarded(path, *args, **kwargs):
        if isinstance(path, (str, bytes, os.PathLike)) and os.fsdecode(path) == CREDENTIAL_SENTINEL:
            denied()
        return original(path, *args, **kwargs)
    return guarded

for owner, name in ((builtins, 'open'), (io, 'open'), (os, 'open'), (os, 'stat'), (os, 'lstat')):
    _guards.enter_context(patch.object(owner, name, guard_path(getattr(owner, name))))

_spec = importlib.util.spec_from_file_location('native_request_observer', Path(__file__).with_name('native_request_observer.py'))
observer = importlib.util.module_from_spec(_spec)
import sys
sys.modules[_spec.name] = observer
_spec.loader.exec_module(observer)
_guards.enter_context(patch.object(observer.ssl, 'create_default_context', denied))

THREAD = '00000000-0000-4000-8000-000000000001'
TURN = '00000000-0000-4000-8000-000000000002'
ASSOCIATION = observer.Association(THREAD, TURN, 1)
BODY = json.dumps({'input': 'PUBLIC_ALPHA', 'client_metadata': {'thread_id': THREAD, 'turn_id': TURN}}, separators=(',', ':')).encode()
REQUEST = b'POST /responses HTTP/1.1\r\nHost: synthetic.invalid\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(BODY)).encode() + b'\r\nConnection: close\r\n\r\n' + BODY
RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPUBLIC'


class FakeSocket:
    def __init__(self, parts=(), send_error=None, close_error=None):
        self.parts = list(parts)
        self.sent = bytearray()
        self.send_error, self.close_error = send_error, close_error
        self.closed = False
    def settimeout(self, timeout):
        pass
    def recv(self, length):
        if not self.parts:
            return b''
        item = self.parts.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item
    def sendall(self, data):
        if self.send_error is not None:
            raise self.send_error
        self.sent.extend(data)
    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error
    def shutdown(self, how):
        pass
    def selected_alpn_protocol(self):
        return 'http/1.1'


class DiagnosticsChecks(unittest.TestCase):
    def fixture(self, upstream=None, client=None, diagnostic=True, sink=None, connector=None):
        records, diagnostics = [], []
        upstream = upstream or FakeSocket([RESPONSE])
        instance = observer.Observer('https://synthetic.invalid/responses', 'PUBLIC_ALPHA',
            records.append, enabled=True, bound_thread=THREAD,
            injected_connector=connector or (lambda deadline: upstream),
            io_sink=(sink or diagnostics.append) if diagnostic else None)
        return instance, client or FakeSocket([REQUEST]), upstream, records, diagnostics

    def test_success_bytes_v1_invariance_and_default_off(self):
        first = self.fixture(diagnostic=False)
        second = self.fixture()
        outputs = []
        for instance, client, upstream, records, diagnostics in (first, second):
            result = instance.handle(client, ASSOCIATION)
            self.assertEqual(result['status'], 'FORWARDED')
            self.assertEqual(set(result), observer.RECORD_KEYS)
            self.assertEqual(records, [result])
            self.assertEqual(bytes(client.sent), RESPONSE)
            self.assertTrue(bytes(upstream.sent).endswith(BODY))
            self.assertEqual(instance.posts, 1)
            outputs.append((result, bytes(client.sent), bytes(upstream.sent)))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(first[-1], [])
        self.assertIsNone(second[-1][0]['first_failure'])
        self.assertIs(observer.validate_io_diagnostic(second[-1][0]), second[-1][0])
        record = []
        disabled = observer.Observer('https://synthetic.invalid/responses', 'PUBLIC_ALPHA', record.append,
            io_sink=lambda row: self.fail('default-off diagnostics emitted'))
        self.assertEqual(disabled.handle(FakeSocket([REQUEST]), ASSOCIATION)['status'], 'UNKNOWN_DISABLED')
        self.assertEqual(disabled.posts, 0)
        with self.assertRaises(AssertionError): socket.socket(socket.AF_INET)
        with self.assertRaises(AssertionError): os.open(CREDENTIAL_SENTINEL, os.O_RDONLY)

    def test_read_timeout_and_client_disconnect(self):
        for upstream, client, phase, cls in (
            (FakeSocket([TimeoutError('PRIVATE_TEXT')]), FakeSocket([REQUEST]), 'READ_HEAD', 'TIMEOUT'),
            (FakeSocket([RESPONSE]), FakeSocket([REQUEST], send_error=BrokenPipeError('PRIVATE_TEXT')), 'WRITE_HEAD', 'BROKEN_PIPE')):
            with self.subTest(phase=phase):
                instance, client, _, records, diagnostics = self.fixture(upstream, client)
                self.assertEqual(instance.handle(client, ASSOCIATION)['status'], 'UNKNOWN_IO')
                self.assertEqual(diagnostics[0]['first_failure']['phase'], phase)
                self.assertEqual(diagnostics[0]['first_failure']['class'], cls)
                self.assertEqual(diagnostics[0]['POST_after'], 1)
                self.assertNotIn('PRIVATE_TEXT', json.dumps(diagnostics))
                self.assertFalse(diagnostics[0]['first_failure']['shutdown_requested'])

    def test_upstream_eof_preserves_framing(self):
        instance, client, _, records, diagnostics = self.fixture(FakeSocket([b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nPUBLIC']))
        self.assertEqual(instance.handle(client, ASSOCIATION)['status'], 'UNKNOWN_FRAMING')
        self.assertTrue(diagnostics[0]['upstream_eof'])
        self.assertEqual(diagnostics[0]['first_failure']['phase'], 'FRAMING_FINISH')
        self.assertEqual(diagnostics[0]['first_failure']['class'], 'CLOSED_FAILURE')
        self.assertEqual(instance.posts, 1)
        self.assertTrue(bytes(client.sent).endswith(b'PUBLIC'))

    def test_co_buffered_second_post_is_refused_before_connect(self):
        connects = []
        upstream = FakeSocket([RESPONSE])
        instance, client, _, records, diagnostics = self.fixture(
            upstream=upstream, client=FakeSocket([REQUEST + REQUEST]),
            connector=lambda deadline: connects.append(deadline) or upstream)

        result = instance.handle(client, ASSOCIATION)

        self.assertEqual(result['status'], 'UNKNOWN_FRAMING')
        self.assertEqual(result['outbound_POST_count'], 0)
        self.assertEqual(instance.posts, 0)
        self.assertEqual(connects, [])
        self.assertEqual(bytes(upstream.sent), b'')
        self.assertEqual(bytes(client.sent), b'')
        self.assertEqual(records, [result])
        self.assertEqual(diagnostics[0]['POST_before'], 0)
        self.assertEqual(diagnostics[0]['POST_after'], 0)
        self.assertTrue(client.closed)
        self.assertTrue(instance.idle.is_set())
        self.assertFalse(instance.busy)

    def test_partial_upstream_request_send_counts_once_without_retry(self):
        for failed_part, fail_at in (('header', 1), ('body', 2)):
            with self.subTest(part=failed_part):
                class PartialRequestSocket(FakeSocket):
                    def __init__(self):
                        super().__init__([RESPONSE])
                        self.send_calls, self.read_calls = [], 0
                    def sendall(self, data):
                        self.send_calls.append(bytes(data))
                        if len(self.send_calls) == fail_at:
                            self.sent.extend(data[:3])
                            raise BrokenPipeError('PRIVATE_SEND_FAILURE')
                        self.sent.extend(data)
                    def recv(self, length):
                        self.read_calls += 1
                        return super().recv(length)

                upstream = PartialRequestSocket()
                connects = []
                instance, client, _, records, diagnostics = self.fixture(
                    upstream=upstream,
                    connector=lambda deadline: connects.append(deadline) or upstream)

                result = instance.handle(client, ASSOCIATION)

                self.assertEqual(result['status'], 'UNKNOWN_IO')
                self.assertEqual(result['outbound_POST_count'], 1)
                self.assertEqual(instance.posts, 1)
                self.assertEqual(len(connects), 1)
                self.assertEqual(len(upstream.send_calls), fail_at)
                self.assertEqual(upstream.read_calls, 0)
                self.assertEqual(upstream.parts, [RESPONSE])
                if failed_part == 'header':
                    self.assertEqual(bytes(upstream.sent), b'POS')
                else:
                    self.assertEqual(upstream.send_calls[1], BODY)
                    self.assertEqual(bytes(upstream.sent), upstream.send_calls[0] + BODY[:3])
                self.assertEqual(bytes(client.sent), b'')
                self.assertEqual(records, [result])
                self.assertEqual(diagnostics[0]['POST_before'], 0)
                self.assertEqual(diagnostics[0]['POST_after'], 1)
                self.assertEqual(diagnostics[0]['first_failure']['phase'], 'SEND_REQUEST')
                self.assertEqual(diagnostics[0]['first_failure']['class'], 'BROKEN_PIPE')
                self.assertNotIn('PRIVATE_SEND_FAILURE', json.dumps((records, diagnostics)))
                self.assertTrue(upstream.closed and client.closed)
                self.assertTrue(instance.idle.is_set())
                self.assertFalse(instance.busy)

    def test_connect_phases_and_close_masks_original(self):
        for phase in ('TCP_CONNECT', 'PROXY_CONNECT_SEND', 'PROXY_CONNECT_READ', 'TLS_HANDSHAKE', 'ALPN_VALIDATE', 'PROXY_SET_TIMEOUT', 'TLS_SET_TIMEOUT'):
            with self.subTest(phase=phase):
                primary = TimeoutError('PRIVATE_PRIMARY')
                closing = OSError('PRIVATE_CLOSE')
                plain = FakeSocket([b'HTTP/1.1 200 Connection established\r\n\r\n'], close_error=closing)
                class TLS:
                    def set_alpn_protocols(self, protocols): self.protocols = protocols
                    def wrap_socket(self, sock, server_hostname):
                        if phase == 'TLS_HANDSHAKE': raise primary
                        return sock
                if phase == 'PROXY_CONNECT_SEND': plain.send_error = primary
                if phase == 'PROXY_CONNECT_READ': plain.parts = [primary]
                if phase == 'ALPN_VALIDATE': plain.selected_alpn_protocol = lambda: 'h2'
                if phase in ('PROXY_SET_TIMEOUT', 'TLS_SET_TIMEOUT'):
                    timeout_calls = [0]
                    def setting_timeout(timeout):
                        timeout_calls[0] += 1
                        if timeout_calls[0] == (1 if phase == 'PROXY_SET_TIMEOUT' else 3):
                            raise primary
                    plain.settimeout = setting_timeout
                records, diagnostics = [], []
                instance = observer.Observer('https://synthetic.invalid/responses', 'PUBLIC_ALPHA', records.append,
                    enabled=True, bound_thread=THREAD, gateway='http://192.0.2.1:7890', io_sink=diagnostics.append)
                def connect(*args, **kwargs):
                    if phase == 'TCP_CONNECT': raise primary
                    return plain
                with patch.object(observer.socket, 'create_connection', connect), patch.object(observer.ssl, 'create_default_context', lambda: TLS()):
                    self.assertEqual(instance.handle(FakeSocket([REQUEST]), ASSOCIATION)['status'], 'UNKNOWN_IO')
                diagnostic = diagnostics[0]
                self.assertEqual(diagnostic['first_failure']['phase'], {'PROXY_SET_TIMEOUT':'PROXY_CONNECT_SEND', 'TLS_SET_TIMEOUT':'TLS_HANDSHAKE'}.get(phase, phase))
                self.assertEqual(diagnostic['POST_after'], 0)
                if phase != 'TCP_CONNECT':
                    self.assertEqual(diagnostic['cleanup_failures'][0]['phase'], 'CLOSE_PLAIN')
                    self.assertEqual(diagnostic['cleanup_failures'][0]['class'], 'OS_ERROR')
                self.assertNotIn('PRIVATE_', json.dumps(diagnostic))
        # Injected failures are not falsely classified as TCP/TLS failures.
        def injected(deadline): raise TimeoutError('PRIVATE')
        instance, client, _, _, diagnostics = self.fixture(connector=injected)
        instance.handle(client, ASSOCIATION)
        self.assertEqual(diagnostics[0]['first_failure']['phase'], 'INJECTED_CONNECTOR')
        # Preserve the original masking propagation on direct connect.
        instance.connector = None
        plain = FakeSocket(close_error=closing)
        with patch.object(observer.socket, 'create_connection', lambda *a, **k: plain), patch.object(observer.ssl, 'create_default_context', lambda: TLS()):
            phase = 'TLS_HANDSHAKE'
            with self.assertRaises(OSError) as caught: instance.connect(observer.time.monotonic()+10)
            self.assertIs(caught.exception, closing)

    def test_cleanup_separate_and_sink_failure_isolated(self):
        for diagnostic_sink in (None, lambda row: (_ for _ in ()).throw(RuntimeError('PRIVATE_DIAGNOSTIC'))):
            instance, client, _, records, diagnostics = self.fixture(
                FakeSocket([TimeoutError('PRIVATE_PRIMARY')], close_error=OSError('PRIVATE_UPSTREAM')),
                FakeSocket([REQUEST], close_error=BrokenPipeError('PRIVATE_CLIENT')), sink=diagnostic_sink)
            result = instance.handle(client, ASSOCIATION)
            self.assertEqual(result['status'], 'UNKNOWN_IO')
            self.assertEqual(len(records), 1)
            self.assertEqual(instance.posts, 1)
            if diagnostic_sink is None:
                d = diagnostics[0]
                self.assertEqual(d['first_failure']['class'], 'TIMEOUT')
                self.assertEqual([x['phase'] for x in d['cleanup_failures']], ['CLOSE_UPSTREAM', 'CLOSE_CLIENT'])
                self.assertEqual([x['order'] for x in [d['first_failure']]+d['cleanup_failures']], [0, 1, 2])
        # Real local AF_UNIX transport; no thread or remote socket required.
        peer, client = socket.socketpair(socket.AF_UNIX)
        try:
            peer.sendall(REQUEST)
            instance, _, _, _, diagnostics = self.fixture()
            instance.handle(client, ASSOCIATION)
            self.assertEqual(peer.recv(4096), RESPONSE)
        finally:
            peer.close(); client.close()

    def test_shutdown_snapshot_bounds_redaction_and_override(self):
        instance, client, upstream, _, diagnostics = self.fixture(FakeSocket([TimeoutError('PRIVATE')]))
        old_recv = upstream.recv
        def recv(length):
            instance.close()
            return old_recv(length)
        upstream.recv = recv
        instance.handle(client, ASSOCIATION)
        self.assertTrue(diagnostics[0]['first_failure']['shutdown_requested'])
        self.assertTrue(diagnostics[0]['shutdown_requested'])
        d = copy.deepcopy(diagnostics[0])
        for mutation in (lambda r:r.update(sequence=True), lambda r:r.update(sequence=16),
                lambda r:r.update(POST_after=17), lambda r:r.update(untrusted='PRIVATE'),
                lambda r:r['first_failure'].update(phase='PRIVATE'), lambda r:r['first_failure'].update(shutdown_requested=1)):
            bad = copy.deepcopy(d); mutation(bad)
            with self.assertRaises(ValueError): observer.validate_io_diagnostic(bad)
        for _ in range(5): observer._note_io(d, 'CLOSE_CLIENT', OSError('PRIVATE'), cleanup=True)
        self.assertEqual(len(d['cleanup_failures']), 3)
        self.assertTrue(d['cleanup_truncated'])
        self.assertNotIn('PRIVATE', json.dumps(d))
        # A later shutdown request cannot relabel the earlier failure snapshot.
        later, later_client, _, _, later_diagnostics = self.fixture(FakeSocket([TimeoutError('PRIVATE')]))
        later.handle(later_client, ASSOCIATION)
        later.close()
        self.assertTrue(later.shutdown_requested)
        self.assertFalse(later_diagnostics[0]['first_failure']['shutdown_requested'])
        # Original sink failure remains a distinct cleanup-phase observation.
        failing, failing_client, _, _, sink_diagnostics = self.fixture()
        failing.sink = lambda row: (_ for _ in ()).throw(OSError('PRIVATE_SINK'))
        self.assertEqual(failing.handle(failing_client, ASSOCIATION)['status'], 'UNKNOWN_IO')
        self.assertIsNone(sink_diagnostics[0]['first_failure'])
        self.assertEqual(sink_diagnostics[0]['cleanup_failures'][0]['phase'], 'ORIGINAL_SINK')
        # Existing public connect(deadline) overrides remain compatible.
        instance, client, upstream, _, diagnostics = self.fixture()
        instance.connect = lambda deadline: upstream
        self.assertEqual(instance.handle(client, ASSOCIATION)['status'], 'FORWARDED')


    def test_publication_precedes_idle_and_next_handler(self):
        entered, release, wait_entered, quiesce_done = (threading.Event() for _ in range(4))
        diagnostics, results, errors = [], [], []
        def blocked_sink(record):
            entered.set()
            if not release.wait(3):
                raise AssertionError('SYNTHETIC_RELEASE_TIMEOUT')
            diagnostics.append(record)
        instance, client, _, _, _ = self.fixture(sink=blocked_sink)
        original_wait = instance.idle.wait
        def observed_wait(timeout):
            wait_entered.set()
            return original_wait(timeout)
        def handle():
            try: results.append(instance.handle(client, ASSOCIATION))
            except BaseException as error: errors.append(type(error).__name__)
        def quiesce():
            try: results.append(instance.quiesce(timeout=4))
            except BaseException as error: errors.append(type(error).__name__)
            finally: quiesce_done.set()
        worker = threading.Thread(target=handle)
        shutdown = threading.Thread(target=quiesce)
        try:
            worker.start()
            self.assertTrue(entered.wait(2))
            self.assertTrue(instance.busy)
            self.assertFalse(instance.idle.is_set())
            self.assertEqual(instance.posts, 1)
            # Actual handle admission must refuse another request while busy.
            next_result = instance.handle(FakeSocket([REQUEST]), ASSOCIATION)
            self.assertEqual(next_result['status'], 'UNKNOWN_BUDGET')
            self.assertEqual(instance.posts, 1)
            with patch.object(instance.idle, 'wait', observed_wait):
                shutdown.start()
                self.assertTrue(wait_entered.wait(2))
                self.assertFalse(quiesce_done.is_set())
                self.assertEqual(diagnostics, [])
                release.set()
                worker.join(2); shutdown.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(shutdown.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(diagnostics), 1)
            self.assertEqual(diagnostics[0]['POST_after'], 1)
            self.assertTrue(instance.idle.is_set())
            self.assertTrue(next(x for x in results if 'drained' in x)['drained'])
        finally:
            release.set()
            if worker.ident is not None: worker.join(3)
            if shutdown.ident is not None: shutdown.join(3)

    def test_failure_flag_before_original_sink_requests_close(self):
        instance, client, _, records, diagnostics = self.fixture(FakeSocket([TimeoutError('PRIVATE_PRIMARY')]))
        def original_sink(record):
            records.append(record)
            instance.close()
        instance.sink = original_sink
        instance.handle(client, ASSOCIATION)
        self.assertFalse(diagnostics[0]['first_failure']['shutdown_requested'])
        self.assertTrue(diagnostics[0]['shutdown_requested'])
        self.assertEqual(diagnostics[0]['first_failure']['class'], 'TIMEOUT')
        # Even a BaseException from optional evidence releases ownership.
        def broken_sink(record): raise KeyboardInterrupt()
        failed, failed_client, _, _, _ = self.fixture(sink=broken_sink)
        self.assertEqual(failed.handle(failed_client, ASSOCIATION)['status'], 'FORWARDED')
        self.assertFalse(failed.busy)
        self.assertTrue(failed.idle.is_set())


class ResponsePassthroughMemoryChecks(unittest.TestCase):
    def fixture(self, parts, *, mode=True, client=None):
        records, diagnostics = [], []
        upstream = FakeSocket(parts)
        instance = observer.Observer('https://synthetic.invalid/responses', 'PUBLIC_ALPHA', records.append,
            enabled=True, bound_thread=THREAD, core_metadata=True, max_connections=16,
            injected_connector=lambda deadline: upstream, io_sink=diagnostics.append,
            response_byte_passthrough=mode)
        return instance, client or FakeSocket([REQUEST]), upstream, records, diagnostics

    def test_response_bytes_fragmentation_and_strict_default(self):
        # Deliberately malformed HTTP is relayed, never promoted to framing PASS.
        wire=b'HTTP/1.1 103 Early Hints\r\nX-Test:\tPUBLIC\r\n\r\nnot a final response'
        for parts in ([wire], [wire[:1],wire[1:19],wire[19:]], [bytes([value]) for value in wire]):
            with self.subTest(fragments=len(parts)):
                instance,client,upstream,records,diagnostics=self.fixture(parts)
                result=instance.handle(client,None)
                self.assertEqual(bytes(client.sent),wire)
                self.assertEqual(result['status'],'UNKNOWN_FRAMING')
                self.assertEqual(set(result),observer.RECORD_KEYS)
                self.assertEqual((result['thread'],result['turn'],result['attempt']),(THREAD,TURN,1))
                self.assertTrue(result['alpha_present']);self.assertEqual(instance.posts,1)
                self.assertTrue(bytes(upstream.sent).endswith(BODY))
                self.assertTrue(diagnostics[0]['upstream_eof'])
                self.assertIsNone(diagnostics[0]['first_failure'])
                self.assertTrue(client.closed and upstream.closed)
                self.assertFalse(instance.busy);self.assertTrue(instance.idle.is_set())
        strict,client,_,_,_=self.fixture([RESPONSE],mode=False)
        self.assertEqual(strict.handle(client,None)['status'],'FORWARDED')
        self.assertEqual(bytes(client.sent),RESPONSE)
        rejected,client,_,_,_=self.fixture([wire],mode=False)
        self.assertEqual(rejected.handle(client,None)['status'],'UNKNOWN_FRAMING')
        self.assertEqual(bytes(client.sent),b'')
        for invalid in (1,None,'true'):
            with self.subTest(invalid_type=type(invalid)):
                with self.assertRaises(observer.ClosedFailure):self.fixture([],mode=invalid)
        default=observer.Observer('https://synthetic.invalid/responses','PUBLIC_ALPHA',lambda row:None)
        self.assertFalse(default.response_byte_passthrough)
        self.assertEqual(default.handle(FakeSocket([REQUEST]),ASSOCIATION)['status'],'UNKNOWN_DISABLED')

    def test_response_cap_chunk_errors_and_partial_delivery(self):
        self.assertEqual(observer.MAX_WIRE,4259840)
        for total in (observer.MAX_WIRE-1,observer.MAX_WIRE,observer.MAX_WIRE+1):
            with self.subTest(total=total):
                parts=[b'x'*65536]*(total//65536)
                if total%65536:parts.append(b'x'*(total%65536))
                instance,client,_,_,diagnostics=self.fixture(parts)
                result=instance.handle(client,None)
                self.assertEqual(result['status'],'UNKNOWN_BOUNDS' if total>observer.MAX_WIRE else 'UNKNOWN_FRAMING')
                self.assertLessEqual(len(client.sent),observer.MAX_WIRE)
                self.assertEqual(instance.posts,1)
                self.assertEqual(diagnostics[0]['first_failure'] is None,total<=observer.MAX_WIRE)
        instance,client,_,_,_=self.fixture([b'x'*65537])
        self.assertEqual(instance.handle(client,None)['status'],'UNKNOWN_BOUNDS');self.assertEqual(bytes(client.sent),b'')
        for error in (TimeoutError(),ConnectionResetError()):
            with self.subTest(error_type=type(error)):
                instance,client,upstream,_,diagnostics=self.fixture([b'PUBLIC',error])
                self.assertEqual(instance.handle(client,None)['status'],'UNKNOWN_IO')
                self.assertEqual(bytes(client.sent),b'PUBLIC');self.assertEqual(instance.posts,1)
                self.assertEqual(diagnostics[0]['first_failure']['phase'],'READ_BODY')
                self.assertTrue(client.closed and upstream.closed)
        class PartialClient(FakeSocket):
            def sendall(self,data):
                self.sent.extend(data[:2]);raise BrokenPipeError()
        client=PartialClient([REQUEST]);instance,_,upstream,_,diagnostics=self.fixture([b'PUBLIC'],client=client)
        self.assertEqual(instance.handle(client,None)['status'],'UNKNOWN_IO')
        self.assertEqual(bytes(client.sent),b'PU');self.assertEqual(instance.posts,1)
        self.assertEqual(diagnostics[0]['first_failure']['phase'],'WRITE_BODY')
        self.assertTrue(client.closed and upstream.closed)

    def test_response_stall_forced_quiesce_retains_unknown_until_publication(self):
        reading,closed_wake,publishing,release,drain_wait,quiesce_done=(threading.Event() for _ in range(6))
        results,diagnostics,errors=[],[],[]
        class StalledUpstream(FakeSocket):
            def recv(self,size):
                reading.set()
                if not closed_wake.wait(3):raise AssertionError('SYNTHETIC_CLOSE_TIMEOUT')
                return b''
            def shutdown(self,how):closed_wake.set()
            def close(self):self.closed=True;closed_wake.set()
        upstream=StalledUpstream()
        instance,client,_,records,_=self.fixture([])
        instance.connector=lambda deadline:upstream
        def publish(record):
            publishing.set()
            if not release.wait(3):raise AssertionError('SYNTHETIC_PUBLISH_TIMEOUT')
            diagnostics.append(record)
        instance.io_sink=publish
        original_wait=instance.idle.wait
        waits=[]
        def forced_wait(timeout):
            waits.append(timeout)
            if len(waits)==1:return False
            drain_wait.set()
            return original_wait(timeout)
        def handle():
            try:results.append(instance.handle(client,None))
            except BaseException as error:errors.append(type(error))
        def quiesce():
            try:results.append(instance.quiesce(timeout=2))
            except BaseException as error:errors.append(type(error))
            finally:quiesce_done.set()
        worker=threading.Thread(target=handle);shutdown=threading.Thread(target=quiesce)
        try:
            worker.start();self.assertTrue(reading.wait(2))
            self.assertTrue(instance.busy);self.assertFalse(instance.idle.is_set())
            self.assertEqual(instance.posts,1)
            refused=instance.handle(FakeSocket([REQUEST]),None)
            self.assertEqual(refused['status'],'UNKNOWN_BUDGET');self.assertEqual(instance.posts,1)
            with patch.object(instance.idle,'wait',forced_wait):
                shutdown.start();self.assertTrue(publishing.wait(2));self.assertTrue(drain_wait.wait(2))
                self.assertTrue(instance.busy);self.assertFalse(instance.idle.is_set())
                self.assertFalse(quiesce_done.is_set());self.assertEqual(diagnostics,[])
                release.set();worker.join(2);shutdown.join(2)
            self.assertFalse(worker.is_alive());self.assertFalse(shutdown.is_alive());self.assertEqual(errors,[])
            self.assertEqual(len(diagnostics),1);self.assertFalse(diagnostics[0]['upstream_eof'])
            self.assertTrue(diagnostics[0]['shutdown_requested'])
            drain=next(row for row in results if 'drained' in row)
            self.assertTrue(drain['forced']);self.assertTrue(drain['drained'])
            self.assertTrue(client.closed and upstream.closed)
            report=observer.summarize_records(records,THREAD,[(THREAD,TURN)],TURN,drain)
            self.assertEqual(report['capture_status'],'UNKNOWN')
            self.assertEqual(next(row for row in results if 'status' in row)['status'],'UNKNOWN_FRAMING')
        finally:
            closed_wake.set();release.set()
            if worker.ident is not None:worker.join(3)
            if shutdown.ident is not None:shutdown.join(3)

    def test_response_multiple_posts_association_and_deadline(self):
        instance,_,_,records,_=self.fixture([])
        upstreams=[]
        def connector(deadline):
            current=FakeSocket([RESPONSE]);upstreams.append(current);return current
        instance.connector=connector
        for index in range(1,17):
            result=instance.handle(FakeSocket([REQUEST]),None)
            self.assertEqual((result['outbound_POST_count'],result['attempt']),(index,index))
            self.assertEqual((result['thread'],result['turn']),(THREAD,TURN))
        result=instance.handle(FakeSocket([REQUEST]),None)
        self.assertEqual(result['status'],'UNKNOWN_BUDGET');self.assertEqual(instance.posts,16)
        self.assertEqual(len(upstreams),16)
        expired,client,_,_,_=self.fixture([RESPONSE]);expired.deadline=0
        self.assertEqual(expired.handle(client,None)['status'],'UNKNOWN_BUDGET');self.assertEqual(expired.posts,0)
        # Response-side absolute deadline rejection retains the already counted POST.
        instance,client,upstream,_,diagnostics=self.fixture([RESPONSE])
        def expire_send(data):
            upstream.sent.extend(data)
            instance.deadline=0
        upstream.sendall=expire_send
        self.assertEqual(instance.handle(client,None)['status'],'UNKNOWN_BUDGET')
        self.assertEqual(instance.posts,1);self.assertEqual(bytes(client.sent),b'')
        self.assertEqual(diagnostics[0]['first_failure']['phase'],'READ_BODY')


def tearDownModule():
    _guards.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
