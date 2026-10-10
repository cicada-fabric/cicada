"""Minimal method overlay; imports legacy effects ONLY in authorized load_gate."""
import ast
import hashlib
import importlib.util
import json
import sys
import time
import types
import threading
import stat
import os
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEGACY = Path("/home/zyf/CICADA_task_handoff/.cicada-data/worktree-evidence/g1-complete-compat-dispatch-20261004")
SCRIPTS = HERE.parent
OLD = Path("/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/managed")
OLD_GATE_SHA = "83952e697f7af7257c2397d56ac2972e4047f4db909b9414539f8222772a7512"
PATCH_SHA = "e621d869098d54a8685f187eecc2bbd1030120349612225fefdc04f30e99da24"
TLS_HELPER_MIGRATION_SHA = "7f34ea1ae1227d5fc81068eff6f5f03255f8e7c959bfa7f5ec431afc355911ea"
METHODS = ("start_managed_servers", "managed_golden_flow", "capture_test_request_observer", "abort_owned")
A2_SUBMISSION_INSTRUCTION = ('This submission supplements the original task; the original task remains pending. '
    'Finish ACCEPTED ends only this submission turn. When the correlated reply arrives, report its exact response '
    'and the original context witness remembered from the first turn. Do not retry any attempted tool call.')
A2_LEGACY_INSTRUCTION = 'Finish ACCEPTED. Do not retry any attempted tool call.'


def closed_native_error_classification(params, native_fields):
    """Release-source-backed static labels; never retain message or details."""
    label = "UNKNOWN"
    if native_fields.get("category") == "other" and type(params) is dict:
        error = params.get("error")
        message = error.get("message") if type(error) is dict else None
        if type(message) is str and len(message) <= 16384 and len(message.encode("utf-8")) <= 16384:
            prefix = "stream disconnected before completion: "
            if message.startswith(prefix):
                detail = message[len(prefix):]
                literals = (
                    ("stream closed before response.completed", "STREAM_CLOSED_BEFORE_COMPLETED"),
                    ("response.failed event received", "RESPONSES_FAILED_EVENT"),
                    ("idle timeout waiting for SSE", "SSE_IDLE_TIMEOUT"),
                    ("Incomplete response returned, reason: content_filter", "CONTENT_FILTER"),
                    ("Incomplete response returned, reason: unknown", "INCOMPLETE_REASON_UNKNOWN"),
                )
                label = "STREAM_DETAIL_WITHHELD"
                for literal, candidate in literals:
                    if detail == literal:
                        label = candidate
                        break
                else:
                    parse_prefix = "failed to parse ResponseCompleted: "
                    if detail.startswith(parse_prefix) and len(detail) > len(parse_prefix):
                        label = "RESPONSE_COMPLETED_PARSE_ERROR"
    return {"schema": "cicada.native-error-closed-diagnostic.v1",
            "classification": label, "category": native_fields.get("category"),
            "http_status_code": native_fields.get("http_status_code"),
            "will_retry": native_fields.get("will_retry"),
            "message_exported": False, "cause_proven": False}


LIFECYCLE_EVENTS = ("NATIVE_TERMINAL_AUDIT", "ABORT_ENTRY", "FIRST_ABORT_COMMITTED", "OWNED_RUNTIME_STOP_ENTRY", "PROVIDER_CLOSE_ENTRY")
DEFAULT_NATIVE_NORMAL_SECONDS = 180
MAX_NATIVE_NORMAL_SECONDS = 600
NATIVE_TERMINAL_SECONDS = 30
NATIVE_CLEANUP_SECONDS = 30
PROVIDER_TRANSPORT_SHA = "91da1e83820caed12809ba8bd6a3156a015e84bf70c310eeb87d91d359118e72"


def install_peer_response_metadata(native, library, emit):
    """Instance-only closed metadata. Keep Peer binding/admission methods intact."""
    if getattr(native, '_owned_response_metadata_state', None) is not None:
        return native._owned_response_metadata_state
    if (type(native) is not library.PeerNativeBroker or
            native.response_metadata is not False or not callable(native.io_sink)):
        raise ValueError('PEER_RESPONSE_METADATA_INSTANCE_SCOPE')
    local = threading.local()
    state = {'local': local, 'lock': threading.Lock(), 'observations': 0,
             'emitted': 0, 'unknown': False,
             'summary': {'status': 'NO_OBSERVATIONS', 'observations': 0,
                         'emitted': 0, 'unknown': False}}
    original_bound = native.handle_bound
    original_connect = native.connect
    original_sink = native.io_sink

    def connect(deadline):
        guard = original_connect(deadline)
        context = getattr(local, 'context', None)
        if context is not None:
            try:
                if (type(guard) is library.NATIVE.RealGuard and
                        context['association'] is native.association and
                        context['guard'] is None):
                    # The actual guard's existing parser is opt-in; the Native
                    # broker flag remains false, avoiding its unrelated 4 cap.
                    guard.response_metadata = True
                    context['guard'] = guard
                else:
                    context['binding_unknown'] = True
            except BaseException:
                context['binding_unknown'] = True
        return guard

    def io_sink(record):
        context = getattr(local, 'context', None)
        if context is not None:
            try:
                validated = library.CORE.validate_io_diagnostic_v2(record)
                sequence = validated['sequence']
                if (type(sequence) is int and 0 <= sequence < 16 and
                        context['observer_sequence'] is None):
                    context['observer_sequence'] = sequence
                else:
                    context['binding_unknown'] = True
            except BaseException:
                context['binding_unknown'] = True
        # Original callback failures retain their original Core handling.
        return original_sink(record)

    def handle_bound(client, admission_index=None):
        previous = getattr(local, 'context', None)
        context = {'association': native.association, 'guard': None,
                   'observer_sequence': None, 'binding_unknown': False}
        with state['lock']:
            ordinal = state['observations'] + 1
            state['observations'] = min(16, ordinal)
        local.context = context
        event = None
        try:
            # Keep the actual inherited false branch and exception identity.
            event = original_bound(client, admission_index)
            return event
        finally:
            emitted = False
            unknown = ordinal > 16
            try:
                if ordinal > 16:
                    pass  # Diagnostic cap never changes Native admission.
                else:
                    guard = context['guard']
                    status = guard.response_status_code if guard is not None else None
                    rejection = guard.response_rejection if guard is not None else 'RESPONSE_NOT_OBSERVED'
                    if guard is not None and guard.guard_failed:
                        status, rejection = None, 'RESPONSE_TOKEN_ECHO'
                    elif rejection == 'HEADER_ACCEPTED' and (
                            type(event) is not dict or event.get('status') != 'FORWARDED'):
                        rejection = 'CORE_REJECTION_UNCLASSIFIED'
                    if (rejection not in library.NATIVE.RESPONSE_REJECTIONS or
                            (status is not None and
                             (type(status) is not int or not 100 <= status <= 999))):
                        raise ValueError('PEER_RESPONSE_METADATA_ENUM_SCOPE')
                    row = {'schema': 'cicada.peer-response-metadata.v1',
                           'observation_ordinal': ordinal,
                           'ordinal_scope': 'OBSERVATION_NOT_ADMISSION',
                           'observer_sequence': context['observer_sequence'],
                           'binding_status': 'UNKNOWN' if context['binding_unknown'] or
                               context['observer_sequence'] is None else 'HANDLER_IO_SEQUENCE',
                           'response_status_code': status, 'response_rejection': rejection}
                    if len(json.dumps(row, separators=(',', ':')).encode()) > 1024:
                        raise ValueError('PEER_RESPONSE_METADATA_BOUNDS')
                    emit(row)
                    emitted = True
                    unknown = row['binding_status'] == 'UNKNOWN'
            except BaseException:
                unknown = True
            finally:
                if previous is None:
                    del local.context
                else:
                    local.context = previous
                # No Guard/association survives in instance-shared state.
                context.clear()
                with state['lock']:
                    state['emitted'] += int(emitted)
                    state['unknown'] = state['unknown'] or unknown
                    state['summary'].update(observations=state['observations'],
                        emitted=state['emitted'], unknown=state['unknown'],
                        status='UNKNOWN' if state['unknown'] else 'OBSERVED')

    native.handle_bound, native.connect, native.io_sink = handle_bound, connect, io_sink
    native._owned_response_metadata_state = state
    return state


def install_owned_peer_response_metadata(owner):
    """Called before paid turn setup; absent Peer instances are a no-op."""
    brokers = getattr(owner, 'peer_brokers', None)
    if type(brokers) is not dict or set(brokers) != {'a', 'b'}:
        return
    library = sys.modules.get('peer_outer_broker')
    report = owner.result.setdefault('peer_response_metadata', {})
    for letter in ('a', 'b'):
        try:
            broker = brokers[letter]
            if library is None or type(broker) is not library.PeerOuterBroker:
                raise ValueError('PEER_RESPONSE_METADATA_OWNER_SCOPE')
            rows = report.setdefault(letter, [])
            def emit(row, side=letter, records=rows):
                raw = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
                if len(raw) > 1024 or len(records) >= 16:
                    raise ValueError('PEER_RESPONSE_METADATA_OUTPUT_BOUNDS')
                path = owner.evidence / ('response-metadata-%s-%02d.NONAUTH.json' %
                                         (side, row['observation_ordinal']))
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                    stream.write(raw)
                records.append(row)
            state = install_peer_response_metadata(broker.native, library, emit)
            owner.result.setdefault('peer_response_metadata_summary', {})[letter] = state['summary']
        except BaseException:
            owner.result['peer_response_metadata_setup'] = 'UNKNOWN'


def note_lifecycle(owner, event, side="UNKNOWN"):
    try:
        state = getattr(owner, "_closed_lifecycle_state", None)
        if state is None or state.get("complete") is not True or getattr(owner.args, "closed_failure_diagnostics", False) is not True:
            return
        if type(event) is not str or event not in LIFECYCLE_EVENTS: return
        side = side if type(side) is str and side in ("a", "b") else "UNKNOWN"
        with state["lock"]:
            try:
                stamp = time.monotonic_ns()
                if type(stamp) is not int or stamp < 0: stamp = None
            except BaseException:
                stamp = None
            if event in ("FIRST_ABORT_COMMITTED", "OWNED_RUNTIME_STOP_ENTRY"):
                if event in state["first"]: return
                state["first"].add(event)
            rows = owner.result.setdefault("closed_lifecycle_chronology", [])
            if type(rows) is not list: return
            if len(rows) >= 32:
                owner.result['closed_lifecycle_recording'] = 'TRUNCATED'
                return
            rows.append({"sequence":len(rows), "event":event, "side":side,
                         "host_monotonic_ns":stamp, "clock_domain":"HOST_ONLY"})
    except BaseException:
        pass


def safe_note_lifecycle(owner, event, side="UNKNOWN"):
    try: note_lifecycle(owner, event, side)
    except BaseException: pass


def note_owned_runtime_stop(owner, name):
    try:
        if name in {node['container'] for node in owner.nodes.values()}:
            note_lifecycle(owner, 'OWNED_RUNTIME_STOP_ENTRY')
    except BaseException:
        pass


def lifecycle_method(original, source, *, cleanup=False):
    import textwrap
    text = textwrap.dedent(source)
    if cleanup:
        cells=dict(zip(original.__code__.co_freevars,original.__closure__ or ()))
        if 'original_cleanup' in cells:
            import inspect
            wrapper=textwrap.dedent(inspect.getsource(original))
            if original.__name__!='cleanup' or wrapper.count('return original_cleanup(self)')!=1:
                raise ValueError('LIFECYCLE_CLOSURE_CONTEXT')
            inner=cells['original_cleanup'].cell_contents
            inner_source=getattr(inner,'_g2_cap_source',None) or inspect.getsource(inner)
            replacement=lifecycle_method(inner,inner_source,cleanup=True)
            def cell(value):return (lambda:value).__closure__[0]
            closure=tuple(cell(replacement) if name=='original_cleanup' else cells[name]
                for name in original.__code__.co_freevars)
            return types.FunctionType(original.__code__,dict(original.__globals__),original.__name__,original.__defaults__,closure)
    if cleanup:
        shutdown_marker = "for rpc in self.rpcs.values():rpc.shutdown_expected=True"
        if text.count(shutdown_marker) != 1:
            raise ValueError("LIFECYCLE_SHUTDOWN_MARKER_CONTEXT")
        text = text.replace(shutdown_marker, "", 1)
        check_marker = "rpc.check()"
        if text.count(check_marker) != 1:
            raise ValueError("LIFECYCLE_RPC_HEALTH_CONTEXT")
        health_lines = [
            "capture=_observer_rpc_observation_projection(rpc)",
            "self.result.setdefault('observer_rpc_observation',{})[letter]=capture",
            "if capture['runtime_health_status']=='FAILED':",
            " self.result.setdefault('observer_runtime_health_after_eof',{})[letter]={'status':'FAILED','exception_class':capture['runtime_error_class']}",
            " self.result['status']='FAIL'",
            "else:",
            " self.result.setdefault('observer_runtime_health_after_eof',{})[letter]={'status':'NO_READER_ERROR'}",
        ]
        lines = text.splitlines()
        checks = [index for index, line in enumerate(lines) if line.strip() == check_marker]
        if len(checks) != 1:
            raise ValueError("LIFECYCLE_RPC_HEALTH_CONTEXT")
        index = checks[0]
        indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
        lines[index:index + 1] = [indent + health_lines[0], indent + health_lines[1],
            indent + health_lines[2], indent + " " + health_lines[3],
            indent + " " + health_lines[4], indent + health_lines[5],
            indent + " " + health_lines[6]]
        text = "\n".join(lines) + "\n"
        stop="if record['State']['Running']:self.docker('stop','--time','1',name)"
        if (text.count(stop)!=1 or text.count("record=self.cleanup_inspect('container',name)")!=1 or
            text.count("record['Image']!=image")!=1 or text.count("raise RuntimeError('cleanup ownership')")!=1):
            raise ValueError("LIFECYCLE_RUNTIME_CONTEXT")
        lines=text.splitlines()
        index=next(index for index,line in enumerate(lines) if stop in line)
        indent=lines[index][:len(lines[index])-len(lines[index].lstrip())]
        lines[index:index+1]=[indent+"if record['State']['Running']:",
            indent+" _observer_expect_owned_container_shutdown(self, name)",
            indent+" _note_owned_runtime_stop(self, name)",
            indent+" self.docker('stop','--time','1',name)"]
        text='\n'.join(lines)+'\n'
        cleanup_unknown = "except Exception as e:clean=False;errors.append(type(e).__name__);self.result.setdefault('observer_shutdown',{})[letter]='UNKNOWN_RETAINED_SUBSCRIBER'"
        if text.count(cleanup_unknown) != 1:
            raise ValueError("LIFECYCLE_EOF_STATUS_CONTEXT")
        lines = text.splitlines()
        matches = [index for index, line in enumerate(lines) if line.strip() == cleanup_unknown]
        if len(matches) != 1:
            raise ValueError("LIFECYCLE_EOF_STATUS_CONTEXT")
        index = matches[0]
        indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
        lines[index:index + 1] = [indent + "except Exception as e:",
            indent + " clean=False;errors.append(type(e).__name__)",
            indent + " if not rpc.shutdown_eof.is_set():",
            indent + "  self.result.setdefault('observer_shutdown',{})[letter]='UNKNOWN_RETAINED_SUBSCRIBER'"]
        text = "\n".join(lines) + "\n"
    else:
        lines = text.splitlines()
        if lines[0].strip() != "def abort_owned(self, error):": raise ValueError("LIFECYCLE_EXACT_CONTEXT")
        body_indent = lines[1][:len(lines[1])-len(lines[1].lstrip())]
        lines.insert(1, body_indent+"_note_lifecycle(self, 'ABORT_ENTRY')")
        commits = [index for index,line in enumerate(lines) if line.strip() == 'self.aborted = True']
        if len(commits) != 1: raise ValueError("LIFECYCLE_EXACT_CONTEXT")
        index=commits[0];line=lines[index]
        lines.insert(index+1,line[:len(line)-len(line.lstrip())]+"_note_lifecycle(self, 'FIRST_ABORT_COMMITTED')")
        text='\n'.join(lines)+'\n'
        lines = text.splitlines()
        fragment = "self.command(['docker', 'kill', record['Id']], timeout=5)"
        matches = [index for index, line in enumerate(lines) if fragment in line]
        if len(matches) != 1: raise ValueError("LIFECYCLE_EXACT_CONTEXT")
        index = matches[0]; line = lines[index]
        lines.insert(index, line[:len(line)-len(line.lstrip())]+"_note_lifecycle(self, 'OWNED_RUNTIME_STOP_ENTRY')")
        index = next(index for index, current in enumerate(lines) if fragment in current)
        line = lines[index]
        lines.insert(index, line[:len(line)-len(line.lstrip())]+"_observer_expect_owned_node_shutdown(self, node)")
        text = '\n'.join(lines)+'\n'
    namespace = method_namespace(original)
    namespace['_note_lifecycle'] = safe_note_lifecycle
    namespace['_note_owned_runtime_stop'] = note_owned_runtime_stop
    namespace['_observer_expect_owned_node_shutdown'] = expect_owned_node_shutdown
    namespace['_observer_expect_owned_container_shutdown'] = expect_owned_container_shutdown
    namespace['_observer_rpc_observation_projection'] = rpc_observation_projection
    exec(compile(text, '<owned-lifecycle>', 'exec'), namespace)
    return namespace[original.__name__]


def expect_owned_node_shutdown(owner, node):
    matches = [letter for letter, candidate in getattr(owner, 'nodes', {}).items() if candidate is node]
    if len(matches) != 1:
        raise RuntimeError('owned RPC shutdown node identity')
    expect_owned_container_shutdown(owner, node.get('container'))


def expect_owned_container_shutdown(owner, container):
    matches = [letter for letter, node in getattr(owner, 'nodes', {}).items()
               if node.get('container') == container]
    if not matches:
        return
    if len(matches) != 1:
        raise RuntimeError('owned RPC shutdown container identity')
    rpc = getattr(owner, 'rpcs', {}).get(matches[0])
    if rpc is None:
        raise RuntimeError('owned RPC shutdown subscriber missing')
    rpc.shutdown_expected = True


def owned_rpc_fail(self, error):
    with self.lock:
        if self.error is not None:
            return
        self.error = error
        self.observer_rpc_observation_complete = False
        self.observer_rpc_fatal_error_class = type(error).__name__
        self.observer_rpc_dispatched_before_fatal = getattr(self, 'observer_rpc_dispatched_before_fatal', 0)
        self.observer_rpc_discarded_after_fatal = getattr(self, 'observer_rpc_discarded_after_fatal', 0)
    self.abort(error)


def _bounded_observer_count(value):
    return min(65535, max(0, int(value)))


def rpc_observation_projection(rpc):
    error_class = getattr(rpc, 'observer_rpc_fatal_error_class', None)
    eof_observed = bool(rpc.shutdown_eof.is_set())
    try:
        rpc.check()
    except Exception as error:
        runtime_health = 'FAILED'
        runtime_error_class = type(error).__name__
    else:
        runtime_health = 'NO_READER_ERROR'
        runtime_error_class = None
    if error_class:
        capture_status = 'INCOMPLETE_AFTER_FATAL'
    elif eof_observed:
        capture_status = 'OBSERVED_TO_OWNED_STOP'
    else:
        capture_status = 'UNKNOWN_DRAIN'
    result = {
        'status': capture_status,
        'normal_observation_complete': error_class is None and eof_observed,
        'runtime_health_status': runtime_health,
        'dispatched_messages_before_fatal': _bounded_observer_count(
            getattr(rpc, 'observer_rpc_dispatched_before_fatal', 0)),
        'discarded_frames_after_fatal': _bounded_observer_count(
            getattr(rpc, 'observer_rpc_discarded_after_fatal', 0)),
        'actual_shutdown_eof_observed': eof_observed,
        'shutdown_drain_timed_out': bool(getattr(rpc, 'shutdown_drain_timed_out', False)),
    }
    if error_class:
        result['fatal_error_class'] = error_class
    if runtime_error_class:
        result['runtime_error_class'] = runtime_error_class
    drain_error = getattr(rpc, 'shutdown_drain_error_class', None)
    if drain_error:
        result['shutdown_drain_error_class'] = drain_error
    return result


def owned_rpc_read(self):
    if not hasattr(self, 'observer_rpc_observation_complete'):
        self.observer_rpc_observation_complete = True
    if not hasattr(self, 'observer_rpc_dispatched_before_fatal'):
        self.observer_rpc_dispatched_before_fatal = 0
    if not hasattr(self, 'observer_rpc_discarded_after_fatal'):
        self.observer_rpc_discarded_after_fatal = 0
    draining = False
    deadline = None

    def drain_deadline():
        value = self.clock() + getattr(self, 'shutdown_drain_seconds', 5.0)
        owner = getattr(self.abort, '__self__', None)
        cleanup_end = getattr(getattr(owner, 'policy', None), 'cleanup_end', None)
        if type(cleanup_end) in (int, float):
            value = min(value, cleanup_end)
        return value

    while not self.closed:
        if self.shutdown_expected and not draining:
            draining = True
            deadline = drain_deadline()
        if draining and self.clock() >= deadline:
            self.shutdown_drain_timed_out = True
            return
        previous = getattr(self.client, 'last_received_bytes', None)
        timeout = .2
        if draining:
            timeout = min(timeout, max(.001, deadline - self.clock()))
        try:
            try:
                message = self.client.recv_obj(timeout=timeout)
            except TimeoutError:
                if draining and self.clock() >= deadline:
                    self.shutdown_drain_timed_out = True
                    return
                continue
            except Exception as error:
                if isinstance(error, EOFError):
                    if self.shutdown_expected:
                        self.shutdown_eof.set()
                    else:
                        current = getattr(self.client, 'last_received_bytes', None)
                        self.audit('wire_failure', {}, current if isinstance(current, bytes) and current is not previous else None)
                        if not self.closed:
                            self.fail(error)
                    return
                current = getattr(self.client, 'last_received_bytes', None)
                self.audit('wire_failure', {}, current if isinstance(current, bytes) and current is not previous else None)
                if draining:
                    self.shutdown_drain_error_class = type(error).__name__
                    return
                if not self.closed:
                    self.fail(error)
                if self.shutdown_expected:
                    draining = True
                    deadline = drain_deadline()
                    continue
                return
            if self.shutdown_expected and not draining:
                draining = True
                deadline = drain_deadline()
            if draining:
                if self.error is not None:
                    self.observer_rpc_discarded_after_fatal = _bounded_observer_count(
                        self.observer_rpc_discarded_after_fatal + 1)
                continue
            raw = getattr(self.client, 'last_received_bytes', None)
            self.audit('received', message, raw)
            self.dispatch(message, raw)
            if self.error is None:
                self.observer_rpc_dispatched_before_fatal = _bounded_observer_count(
                    self.observer_rpc_dispatched_before_fatal + 1)
        except Exception as error:
            if draining:
                self.shutdown_drain_error_class = type(error).__name__
                return
            if not self.closed:
                self.fail(error)
            if self.shutdown_expected:
                draining = True
                deadline = drain_deadline()
                continue
            return


def install_native_rpc_shutdown_drain(module, binding):
    import ast
    import inspect
    path = (OLD / 'native_protocol.py').resolve()
    if (module is None or Path(getattr(module, '__file__', '')).resolve() != path or
            not path.is_file()):
        raise ValueError('NATIVE_RPC_MODULE_ORIGIN')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    # native_protocol.py is an immutable readonly dependency, not one of the
    # six current candidate files. Its exact canonical public row is the
    # authority here; do not require or synthesize a candidate_files alias.
    public_files = binding.get('public_files', {})
    public = public_files.get(str(path)) if isinstance(public_files, dict) else None
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError('NATIVE_RPC_SOURCE_PIN') from None
    if (path.resolve(strict=True) != path or type(public) is not dict or
            set(public) != {'sha256', 'bytes', 'rawmode'} or
            not stat.S_ISREG(metadata.st_mode) or public.get('sha256') != digest or
            public.get('bytes') != len(raw) or public.get('rawmode') != oct(metadata.st_mode)):
        raise ValueError('NATIVE_RPC_SOURCE_PIN')
    installed = getattr(module.TypedRPC, '_observer_shutdown_drain_sha256', None)
    if installed is not None:
        if installed != hashlib.sha256((digest + '\0' + inspect.getsource(owned_rpc_fail) + inspect.getsource(owned_rpc_read)).encode()).hexdigest():
            raise ValueError('NATIVE_RPC_DERIVATIVE_CONFLICT')
        return installed
    tree = ast.parse(raw)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'TypedRPC']
    if len(classes) != 1:
        raise ValueError('NATIVE_RPC_CLASS_CONTEXT')
    methods = {node.name: node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name in ('fail', '_read')}
    if set(methods) != {'fail', '_read'}:
        raise ValueError('NATIVE_RPC_METHOD_CONTEXT')
    source = raw.decode('utf-8')
    fail_source = ast.get_source_segment(source, methods['fail'])
    read_source = ast.get_source_segment(source, methods['_read'])
    if (not fail_source or 'self.error=error;self.abort(error)' not in fail_source.replace(' ', '') or
            not read_source or 'self.fail(error)' not in read_source or 'self.shutdown_eof.set()' not in read_source):
        raise ValueError('NATIVE_RPC_METHOD_SOURCE_CONTEXT')
    namespace = dict(module.__dict__)
    namespace['_bounded_observer_count'] = _bounded_observer_count
    exec(compile(inspect.getsource(owned_rpc_fail) + '\n' + inspect.getsource(owned_rpc_read),
                 '<owned-native-rpc-shutdown-drain>', 'exec'), namespace)
    module.TypedRPC.fail = namespace['owned_rpc_fail']
    module.TypedRPC._read = namespace['owned_rpc_read']
    derivative = hashlib.sha256((digest + '\0' + inspect.getsource(owned_rpc_fail) + inspect.getsource(owned_rpc_read)).encode()).hexdigest()
    module.TypedRPC._observer_shutdown_drain_sha256 = derivative
    return derivative


def install_lifecycle(owner, abort_source, cleanup_source, original_cleanup=None):
    if getattr(owner.args, 'closed_failure_diagnostics', False) is not True: return
    if getattr(owner, '_closed_lifecycle_state', None) is not None: return
    abort = lifecycle_method(owner.abort_owned.__func__, abort_source)
    cleanup = lifecycle_method(original_cleanup if original_cleanup is not None else owner.cleanup.__func__, cleanup_source, cleanup=True)
    previous_abort = owner.abort_owned
    previous_cleanup = getattr(owner, '_closed_lifecycle_cleanup', None)
    try:
        owner.result['closed_lifecycle_installation'] = 'INSTALLED'
        owner.result['closed_lifecycle_recording'] = 'ACTIVE'
        owner.abort_owned = types.MethodType(abort, owner)
        owner._closed_lifecycle_cleanup = types.MethodType(cleanup, owner)
        owner._closed_lifecycle_state = {'lock':threading.Lock(), 'first':set(), 'complete':True}
    except BaseException:
        owner.abort_owned = previous_abort
        if previous_cleanup is None:
            if hasattr(owner, '_closed_lifecycle_cleanup'): del owner._closed_lifecycle_cleanup
        else: owner._closed_lifecycle_cleanup = previous_cleanup
        owner._closed_lifecycle_state = None
        raise


def install_provider_lifecycle(owner, adapter):
    try:
        if getattr(owner.args, 'closed_failure_diagnostics', False) is not True: return
        if getattr(adapter, '_closed_lifecycle_installed', False): return
        original = adapter.close
        def close():
            safe_note_lifecycle(owner, 'PROVIDER_CLOSE_ENTRY')
            return original()
        adapter.close = close
        adapter._closed_lifecycle_installed = True
    except BaseException:
        pass


def mark_native_failure(self, error, node, direction, message, native_fields):
    """Called only by the generated terminal-native-audit raise site."""
    params=message.get("params") if type(message) is dict else None
    native=(direction=="received" and type(message) is dict and message.get("method")=="error" and
            not set(message)-{"method","params","emittedAtMs"} and type(params) is dict and
            ("emittedAtMs" not in message or type(message["emittedAtMs"]) is int and -(2**63)<=message["emittedAtMs"]<=2**63-1) and
            native_fields.get("schema_status")=="SAFE_ENUM_FIELDS_VALIDATED" and
            node in self.nodes and type(params.get("threadId")) is str and
            params["threadId"]==self.nodes[node].get("thread")==self.budget.threads.get(node) and
            type(params.get("turnId")) is str and
            [key for key in self.budget.started if key[0]==node and key not in self.budget.completed]==[(node,params["turnId"])])
    if native: safe_note_lifecycle(self, "NATIVE_TERMINAL_AUDIT", node)
    publication = None
    with self.abort_lock, self._observer_capture_lifecycle_lock:
        if native and not self.aborted and not getattr(self,"_observer_capture_cutoff",False):
            if not hasattr(self,"_observer_native_failures"):
                self._observer_native_failures = {}
            origin = threading.get_ident()
            self._observer_native_failures[origin] = (error,node,params["threadId"],params["turnId"])
            if (getattr(self.args,"test_request_observer",False) and
                    type(self.args.go.get("max_fatal_diagnostic_capture_seconds")) is int and
                    self.args.go["max_fatal_diagnostic_capture_seconds"] == 5):
                publication = {"error":error,"origin":origin,"done":threading.Event(),
                    "end":min(time.monotonic()+5,self.policy.cleanup_end)}
                self._observer_native_capture_state = publication
            try:
                diagnostic_go = getattr(self.args,"go",None)
                if ((getattr(self.args,"native_https",False) is True or
                        getattr(self.args,"test_request_observer",False) is True) and
                        type(diagnostic_go) is dict and
                        type(diagnostic_go.get("max_fatal_diagnostic_capture_seconds")) is int and
                        diagnostic_go["max_fatal_diagnostic_capture_seconds"] == 5):
                    recorded_at = time.monotonic()
                    diagnostic = closed_native_error_classification(params, native_fields)
                    diagnostic.update(node=node, thread_id=params["threadId"], turn_id=params["turnId"],
                        host_monotonic_seconds=recorded_at,
                        classification_scope="RUNTIME_REPORTED_CONDITION_NOT_PROVEN_CAUSE")
                    self.result.setdefault("native_error_closed_diagnostic", diagnostic)
            except BaseException:
                # Memory diagnostics never mask the primary or change capture.
                pass
    # Publish before cleanup can stop the Runtime. No external calls hold this
    # short publication lock; inherited cleanup never holds it while persisting.
    try:
        self.abort_owned(error)
    finally:
        if publication is not None:
            publication["done"].set()


def capture_native_failure(self, error):
    marker = getattr(self,"_observer_native_failures",{}).get(threading.get_ident())
    if (marker is None or marker[0] is not error or marker[1] not in self.nodes or
        marker[2]!=self.nodes[marker[1]].get("thread") or marker[2]!=self.budget.threads.get(marker[1]) or
        [key for key in self.budget.started if key[0]==marker[1] and key not in self.budget.completed]!=[(marker[1],marker[3])] or
        not getattr(self.args,"test_request_observer",False) or
        type(self.args.go.get("max_fatal_diagnostic_capture_seconds")) is not int or
        self.args.go["max_fatal_diagnostic_capture_seconds"] != 5):
        return
    publication = getattr(self,"_observer_native_capture_state",None)
    if publication is None or publication["error"] is not error or publication["origin"] != threading.get_ident():
        return
    self._observer_capture_end = publication["end"]
    self._observer_capture_thread = threading.get_ident()
    self._observer_capture_allowlist = set()
    self._observer_capture_active = True
    self.result["test_request_observer"] = {"capture_status":"UNKNOWN", "per_Runtime":{}}
    try:
        if time.monotonic() >= self._observer_capture_end:
            raise TimeoutError("FATAL_CAPTURE_DEADLINE")
        self.capture_test_request_observer(None)
    except BaseException:
        self.result["test_request_observer"]["capture_status"] = "UNKNOWN"
    finally:
        self._observer_capture_active = False
        self._observer_capture_allowlist.clear()
        report = self.result["test_request_observer"]
        report.update(capture_status="UNKNOWN", fatal_capture_scope="AUDIT_TERMINAL_NATIVE_PROTOCOL",
                      max_capture_seconds=5, a3_stage="NOT_REACHED", native_acceptance="UNCHANGED")
        for letter in self.nodes:
            report.setdefault("per_Runtime",{}).setdefault(letter,{"capture_status":"UNKNOWN","records":[]})


def wait_native_capture_before_owned_cleanup(self, argv):
    """One existing capture deadline; no wait for absent, late or other errors."""
    if not getattr(self.args,"test_request_observer",False) or not getattr(self,"cleaning",False) or len(argv)<3 or argv[0]!="docker" or argv[1] not in ("stop","kill","rm"):
        return
    owned = {value for (kind,name),proof in self.submitted_objects.items()
        if kind=="container" and name in {node["container"] for node in self.nodes.values()}
        and proof.get("image")==self.args.runtime_image
        for value in (name,proof.get("id")) if type(value) is str and value}
    if argv[-1] not in owned:
        return
    with self._observer_capture_lifecycle_lock:
        publication = getattr(self,"_observer_native_capture_state",None)
        if publication is None:
            self._observer_capture_cutoff = True
            self.result.setdefault("test_request_observer",{})["cleanup_capture_reason"] = "NO_NATIVE_CAPTURE_AT_DESTRUCTIVE_CUTOFF"
            return
    if publication["origin"] == threading.get_ident():
        return
    end = min(publication["end"],self.policy.cleanup_end)
    if not publication["done"].wait(max(0,end-time.monotonic())):
        self.result.setdefault("test_request_observer",{})["capture_status"] = "UNKNOWN"
        self.result["test_request_observer"]["cleanup_capture_reason"] = "NATIVE_CAPTURE_DEADLINE_EXHAUSTED"


def capture_command_allowed(self, argv):
    return (getattr(self,"_observer_capture_active",False) is True and
            self._observer_capture_thread == threading.get_ident() and
            time.monotonic() < self._observer_capture_end and
            tuple(argv) in self._observer_capture_allowlist)


def register_capture_command(self, argv, program_pins):
    """Exact program/argv/CID allowlist; no generic post-abort exec permission."""
    if not getattr(self,"_observer_capture_active",False):
        return
    argv = list(map(str,argv))
    owned = {proof.get("id") for (kind,name),proof in self.submitted_objects.items()
             if kind=="container" and name in {node["container"] for node in self.nodes.values()}
             and proof.get("image")==self.args.runtime_image}
    if (self._observer_capture_thread != threading.get_ident() or len(argv) not in (6,7) or
        argv[:2] != ["docker","exec"] or argv[2] not in owned or
        argv[3:5] != ["python3","-c"] or
        program_pins.get(hashlib.sha256(argv[5].encode()).hexdigest()) != len(argv) or
        (len(argv)==7 and argv[6] != repr(self._observer_capture_end))):
        raise PermissionError("FATAL_CAPTURE_ARGV")
    self._observer_capture_allowlist.add(tuple(argv))


def capture_deadline(self):
    if getattr(self,"_observer_capture_active",False):
        return self._observer_capture_end
    return {"normal":self.policy.normal_end,"terminal":self.policy.terminal_end,
            "cleanup":self.policy.cleanup_end}[self.policy.phase]


def safe_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def provider_transport_source(normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    """Raise only the pinned adapter lifetime ceiling for an explicitly longer native budget."""
    if (type(normal_seconds) is not int or normal_seconds < DEFAULT_NATIVE_NORMAL_SECONDS or
            normal_seconds > MAX_NATIVE_NORMAL_SECONDS):
        raise ValueError("NATIVE_NORMAL_SECONDS")
    raw = (OLD / "provider_transport.py").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVIDER_TRANSPORT_SHA:
        raise ValueError("PROVIDER_TRANSPORT_BASE_PIN")
    tree = ast.parse(raw)
    validators = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == "validate_binding"]
    if len(validators) != 1:
        raise ValueError("PROVIDER_TRANSPORT_VALIDATOR_CONTEXT")
    loops = [node for node in ast.walk(validators[0])
             if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple) and
             [item.id for item in node.target.elts if isinstance(item, ast.Name)] == ["key", "upper"]]
    if len(loops) != 1 or not isinstance(loops[0].iter, ast.Tuple):
        raise ValueError("PROVIDER_TRANSPORT_LIMIT_CONTEXT")
    expected = (("lifetime", 240), ("max_connections", 16), ("max_active", 4))
    try:
        if ast.literal_eval(loops[0].iter) != expected:
            raise ValueError("PROVIDER_TRANSPORT_LIMIT_CONTEXT")
    except (ValueError, TypeError):
        raise ValueError("PROVIDER_TRANSPORT_LIMIT_CONTEXT") from None
    lifetime_ceiling = max(240, normal_seconds)
    loops[0].iter.elts[0].elts[1] = ast.Constant(value=lifetime_ceiling)
    ast.fix_missing_locations(tree)
    source = ast.unparse(tree) + "\n"
    compile(source, "<effective-request-observer-provider-transport>", "exec")
    return source


def effective_sources(normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    if (type(normal_seconds) is not int or normal_seconds < DEFAULT_NATIVE_NORMAL_SECONDS or
            normal_seconds > MAX_NATIVE_NORMAL_SECONDS):
        raise ValueError("NATIVE_NORMAL_SECONDS")
    transport_source = provider_transport_source(normal_seconds)
    shim = safe_module("cicada_observer_bootstrap_public", HERE / "request_observer_bootstrap.py")
    original = shim.read_pinned(OLD / "managed_gate.py", OLD_GATE_SHA, 131072).decode()
    patch = shim.read_pinned(LEGACY / "request-observer-integration.patch", PATCH_SHA).decode()
    source = shim.apply_section(original, patch, "managed/managed_gate.py")
    if source.count(A2_LEGACY_INSTRUCTION) != 1:
        raise ValueError("A2_TASK_INSTRUCTION_CONTEXT")
    source = source.replace(A2_LEGACY_INSTRUCTION, A2_SUBMISSION_INSTRUCTION)
    source = source.replace("/run/cicada-request-observer", "/tmp/cicada-request-observer")
    source = source.replace("/run/request_observer.py", "/tmp/native_request_observer.py")
    export_import = "sys.path.insert(0,'/run')\nfrom request_observer import validate_record"
    if source.count(export_import) != 1:
        raise ValueError("EXPORT_OBSERVER_IMPORT_CONTEXT")
    source = source.replace(export_import, "sys.path.insert(0,'/tmp')\nfrom native_request_observer import validate_record")
    old = "'lifetime_seconds':240, 'max_POST_attempts_per_Runtime':16,"
    if source.count(old) != 1:
        raise ValueError("GATE_OVERLAY_CONTEXT")
    source = source.replace(old, f"'lifetime_seconds':{normal_seconds}, 'max_POST_attempts_per_Runtime':16,")
    source = source.replace("observer_args = ['--test-request-observer', base_sha, '240', '16']",
        f"observer_args = ['--test-request-observer', base_sha, repr(self.policy.started+{normal_seconds}), '16']")
    def replace_once(value, old, new):
        if value.count(old)!=1:
            raise ValueError("FATAL_CAPTURE_CONTEXT")
        return value.replace(old,new)
    source = replace_once(source," end=time.monotonic()+3\n",
        " end=min(time.monotonic()+3,float(sys.argv[1]))\n")
    source = replace_once(source,
        "            stopped = json.loads(self.command(['docker','exec',node['container'],'python3','-c',stop],timeout=3))",
        "            stop_argv = ['docker','exec',container['Id'],'python3','-c',stop]\n"
        "            _observer_register_capture_command(self,stop_argv,_observer_capture_program_pins)\n"
        "            stopped = json.loads(self.command(stop_argv,timeout=3))")
    source = replace_once(source,
        "                exported = json.loads(self.command(['docker','exec',node['container'],'python3','-c',export],timeout=5))",
        "                export_argv = ['docker','exec',container['Id'],'python3','-c',export,repr(_observer_capture_deadline(self))]\n"
        "                _observer_register_capture_command(self,export_argv,_observer_capture_program_pins)\n"
        "                exported = json.loads(self.command(export_argv,timeout=5))")
    source = replace_once(source,
        "                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained",
        "                if a3_turn is None:\n"
        "                    report.update(capture_status='UNKNOWN',a3_stage='NOT_REACHED',a3_ALPHA_present=None)\n"
        "                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained")
    source = replace_once(source, "from native_request_observer import validate_record\nrows=[]", "from native_request_observer import validate_record\nfrom native_request_observer_io import validate_export\nrows=[]")
    source = replace_once(source, "print(json.dumps(result))\n\"\"\"\n            try:", "io_result={'status':'UNKNOWN','records':[]}\ntry:\n with Path('/tmp/cicada-request-observer-io.jsonl').open('rb') as io_stream: io_raw=io_stream.read(32769)\n with Path('/tmp/cicada-request-observer-io-watermark.json').open('rb') as io_stream: io_mark_raw=io_stream.read(1025)\n if len(io_mark_raw)>1024: raise ValueError()\n io_mark=json.loads(io_mark_raw)\n io_result={'status':'COMPLETE','records':validate_export(io_raw,io_mark,v2=True),'watermark':io_mark}\nexcept Exception: pass\nresult['io_sibling']=io_result\nprint(json.dumps(result))\n\"\"\"\n            try:")
    source = replace_once(source, "                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained", "                from native_request_observer_io import join_records\n                sibling=exported.get('io_sibling',{})\n                self.result.setdefault('observer_io_diagnostics',{})[letter]=(join_records(sibling.get('records',[]),exported['records'],node['thread'],actual,sibling.get('watermark'),v2=True) if sibling.get('status')=='COMPLETE' else {'status':'UNKNOWN','records':[]})\n                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained")
    gate_tree = ast.parse(source)
    gate_cls = next(node for node in gate_tree.body if isinstance(node,ast.ClassDef) and node.name=="ManagedGate")
    abort = next(node for node in gate_cls.body if isinstance(node,ast.FunctionDef) and node.name=="abort_owned")
    owned_lock = abort.body[0]
    if (not isinstance(owned_lock,ast.With) or not isinstance(owned_lock.body[-1],ast.Try) or
        "self.result['managed_abort_class'] = type(error).__name__" not in ast.unparse(abort)):
        raise ValueError("ABORT_CAPTURE_CONTEXT")
    kill = owned_lock.body[-1]
    guarded = ast.parse("try:\n _observer_capture_native_failure(self,error)\nexcept BaseException:\n self.result.setdefault('test_request_observer',{})['capture_status']='UNKNOWN'\nfinally:\n pass\n").body[0]
    guarded.finalbody=[kill]
    owned_lock.body[-1]=guarded
    ast.fix_missing_locations(gate_tree)
    source = ast.unparse(gate_tree)+"\n"
    compile(source, "<effective-request-observer-gate>", "exec")
    bootstrap = shim.effective_source(shim.read_pinned(OLD / "server_bootstrap.py", shim.OLD_BOOTSTRAP_SHA).decode(), patch)
    legacy_provider_lookup = "public['model_providers']['basil']['base_url']"
    if bootstrap.count(legacy_provider_lookup) != 1:
        raise ValueError("BOOTSTRAP_PROVIDER_LOOKUP_CONTEXT")
    bootstrap = bootstrap.replace(legacy_provider_lookup,
        "public['model_providers'][public['model_provider']]['base_url']")
    compile(bootstrap, "<effective-request-observer-bootstrap>", "exec")
    tree = ast.parse((OLD / "migration.py").read_text())
    install = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "install")
    provider = next(node for node in install.body if isinstance(node, ast.FunctionDef) and node.name == "provider")
    changed = 0
    for node in ast.walk(provider):
        if isinstance(node, ast.Constant) and type(node.value) is int and node.value == 240:
            node.value = normal_seconds
            changed += 1
    if changed != 2:
        raise ValueError("PROVIDER_DEADLINE_CONTEXT")
    setup=next(n for n in provider.body if isinstance(n,ast.Assign) and
        any(isinstance(t,ast.Name) and t.id=="adapter" for t in n.targets))
    if not isinstance(setup.value,ast.Call) or ast.unparse(setup.value.func)!="Forwarder":
        raise ValueError("FORWARDER_INSTANCE_CONTEXT")
    provider.body.insert(provider.body.index(setup)+1,ast.parse("_install_client_read_cancellation(self, adapter)").body[0])
    ast.fix_missing_locations(provider)
    provider_source = (ast.unparse(provider) + "\n" +
        "# provider_transport_sha256=" + hashlib.sha256(transport_source.encode()).hexdigest() +
        " lifetime_ceiling=" + str(max(240, normal_seconds)) + "\n")
    audit = next(node for node in install.body if isinstance(node,ast.FunctionDef) and node.name=="audit")
    terminal = audit.body[-1]
    if (not isinstance(terminal,ast.If) or not isinstance(terminal.body[-1],ast.Raise) or
        ast.unparse(terminal.body[-1])!="raise RuntimeError('terminal native protocol error')"):
        raise ValueError("NATIVE_AUDIT_MARKER_CONTEXT")
    terminal.body[-1:] = ast.parse("native_failure=RuntimeError('terminal native protocol error')\ntry:\n _observer_mark_native_failure(self,native_failure,node,direction,message,safe_error_diagnostic(message.get('params')))\nfinally:\n raise native_failure\n").body
    command = next(node for node in install.body if isinstance(node,ast.FunctionDef) and node.name=="command")
    guard = command.body[1]
    if (not isinstance(guard,ast.If) or not isinstance(guard.body[0],ast.Raise) or
        "no business after managed abort" not in ast.unparse(guard)):
        raise ValueError("ABORT_COMMAND_GUARD_CONTEXT")
    guard.test=ast.BoolOp(op=ast.And(),values=[guard.test,
        ast.UnaryOp(op=ast.Not(),operand=ast.parse("_observer_capture_command_allowed(self,argv)",mode="eval").body)])
    cap = ast.parse("if getattr(self,'_observer_capture_active',False) and self._observer_capture_thread==_observer_thread_identity():\n timeout=min(timeout,self._observer_capture_end-time.monotonic())\n if timeout<=0: raise TimeoutError('FATAL_CAPTURE_DEADLINE')\n").body[0]
    command.body.insert(1,cap)
    command.body.insert(1,ast.parse("_observer_wait_native_cleanup(self,argv)\n").body[0])
    ast.fix_missing_locations(audit);ast.fix_missing_locations(command)
    return {"gate":source, "bootstrap":bootstrap, "provider":provider_source,
            "audit":ast.unparse(audit)+"\n", "command":ast.unparse(command)+"\n"}


def approved_tls_helper_argv(argv, binding, *, run_id, fixture_root, native_package, image):
    """Retarget only the exact legacy TLS helper mount to binding-pinned public OpenSSL."""
    migration_path = OLD / "migration.py"
    migration_row = binding.get("public_files", {}).get(str(migration_path))
    if (type(migration_row) is not dict or
            migration_row.get("sha256") != TLS_HELPER_MIGRATION_SHA):
        raise ValueError("TLS_HELPER_MIGRATION_PIN")
    migration_raw = migration_path.read_bytes()
    if hashlib.sha256(migration_raw).hexdigest() != TLS_HELPER_MIGRATION_SHA:
        raise ValueError("TLS_HELPER_MIGRATION_PIN")
    tree = ast.parse(migration_raw)
    helpers = [node for node in ast.walk(tree)
               if isinstance(node, ast.FunctionDef) and node.name == "helper"]
    if len(helpers) != 1:
        raise ValueError("TLS_HELPER_SOURCE_CONTEXT")
    selected = ast.unparse(helpers[0])
    if (selected.count("str(ROOT / 'authority-bootstrap/openssl') + ':/pqtls-stage:ro'") != 1 or
            selected.count("self.command(argv, timeout=30)") != 1):
        raise ValueError("TLS_HELPER_SOURCE_CONTEXT")
    old_stage = Path(binding["output_parent"]) / "authority-bootstrap/openssl"
    expected = ["docker", "run", "--rm", "--pull=never", "--name", run_id + "-helper-tls-bootstrap",
        "--label", "org.cicada.test.run=" + run_id, "--network", "none", "--user", "1000:1000",
        "-v", str(fixture_root) + ":/fixture", "-v", str(native_package) + ":/opt/cicada-pqtls:ro",
        "-v", str(old_stage) + ":/pqtls-stage:ro", "-e", "LD_LIBRARY_PATH=/opt/cicada-pqtls/lib",
        "-e", "OPENSSL_CONF=/dev/null", "--entrypoint", "/fixture/cicada-v68fixture", image,
        "tls-bootstrap", "--db", "/fixture/hub-state/cicada.sqlite3", "--fixture", "/fixture",
        "--listen", "0.0.0.0:8999", "--application-origin", "http://127.0.0.1:8787",
        "--openssl", "/pqtls-stage/bin/openssl"]
    if list(argv) != expected:
        raise ValueError("TLS_HELPER_EXACT_SCOPE")
    files = binding["public_files"]
    executables = [Path(path) for path in files if path.endswith("/bin/openssl")]
    if len(executables) != 1:
        raise ValueError("TLS_STAGE_BINDING_LAYOUT")
    stage = executables[0].parent.parent
    if not stage.is_absolute() or stage.resolve(strict=True) != stage:
        raise ValueError("TLS_STAGE_CANONICAL")
    for relative in ("bin/openssl", "lib/libcrypto.so.3", "lib/libssl.so.3"):
        path = stage / relative
        row = files.get(str(path))
        if (type(row) is not dict or set(row) != {"bytes", "rawmode", "sha256"} or
                type(row["bytes"]) is not int or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("TLS_STAGE_BINDING_LAYOUT")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                    not before.st_mode & stat.S_IXUSR or before.st_size != row["bytes"]):
                raise ValueError("TLS_STAGE_PUBLIC_FILE")
            raw = bytearray()
            while len(raw) <= row["bytes"]:
                block = os.read(fd, min(65536, row["bytes"] + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(fd)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    hashlib.sha256(raw).hexdigest() != row["sha256"]):
                raise ValueError("TLS_STAGE_PUBLIC_PIN")
        finally:
            os.close(fd)
    rewritten = list(argv)
    rewritten[17] = str(stage) + ":/pqtls-stage:ro"
    return rewritten, stage


def capture_program_pins(source):
    tree=ast.parse(source)
    cls=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="ManagedGate")
    method=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=="capture_test_request_observer")
    programs={}
    for node in ast.walk(method):
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):
            names={target.id for target in node.targets if isinstance(target,ast.Name)}
            for name,length in (("stop",6),("export",7)):
                if name in names:
                    compile(node.value.value,"<pinned-Runtime-"+name+">","exec")
                    programs[hashlib.sha256(node.value.value.encode()).hexdigest()]=length
    if len(programs)!=2:
        raise ValueError("CAPTURE_PROGRAM_PIN_SET")
    return programs


def method_namespace(function):
    namespace=dict(function.__globals__)
    namespace.update({name:cell.cell_contents for name,cell in zip(function.__code__.co_freevars,function.__closure__ or ())})
    return namespace



# Closed host-only diagnostic metadata; never serialized exception text.
CLOSED_FAILURE_REASONS = {
    "PQTLS diagnostic NOT_PROVEN": "PQ_DIAGNOSTIC_UNPROVEN",
    "actual protected PQTLS state mismatch": "PQ_PROFILE_MISMATCH",
    "actual PQTLS ready/wake NOT_PROVEN": "PQ_READY_UNPROVEN",
    "owned provider transport failure": "PROVIDER_TRANSPORT_FAILURE",
    "CANDIDATE_ABSOLUTE_DEADLINE": "ABSOLUTE_DEADLINE",
    "PQ_RESTART_ANCHOR_MISSING": "RESTART_ANCHOR_MISSING",
    "PQ_RESTART_ANCHOR_FILE_SCOPE": "RESTART_ANCHOR_FILE_SCOPE",
    "PQ_RESTART_ANCHOR_MALFORMED": "RESTART_ANCHOR_MALFORMED",
    "PQ_RESTART_ANCHOR_BOUNDS": "RESTART_ANCHOR_BOUNDS",
    "PQ_RESTART_ANCHOR_HUB_OWNERSHIP": "RESTART_ANCHOR_OWNERSHIP",
}


def closed_failure(error):
    kind = None
    for builtin, label in ((RuntimeError, "RUNTIME_ERROR"), (TimeoutError, "TIMEOUT_ERROR"),
                           (ValueError, "VALUE_ERROR"), (OSError, "OS_ERROR")):
        if type(error) is builtin:
            kind = label
            break
    if kind is None:
        return {"type": "UNKNOWN", "reason": "UNKNOWN"}
    # Exact builtins only: subclasses can supply hostile args accessors.
    args = error.args
    reason = (CLOSED_FAILURE_REASONS.get(args[0], "UNKNOWN")
              if type(args) is tuple and len(args) == 1 and type(args[0]) is str else "UNKNOWN")
    if not ((type(error) is RuntimeError and reason != "ABSOLUTE_DEADLINE") or
            (type(error) is TimeoutError and reason == "ABSOLUTE_DEADLINE")):
        reason = "UNKNOWN"
    return {"type": kind, "reason": reason}



CLOSED_OPERATIONS = (
    "explicit_zero_model_second_hub_restart",
    "explicit_owner_second_membership_authorization",
    "zero_model_owned_hub_restart_transport",
    "original_managed_join_and_context",
    "original_a_authorized_second_group_join_leave",
    "g2_actual_hidden_members_and_revoked_link_denial",
    "g3_restored_control_authenticated_encrypted_snapshot",
)


def closed_restart_state(owner):
    operation = getattr(owner, "phase", None)
    operation = operation if type(operation) is str and operation in CLOSED_OPERATIONS else "UNKNOWN"
    def count(key):
        value = owner.result.get(key)
        return value if type(value) is int and 0 <= value <= 6 else None
    aborted = getattr(owner, "aborted", None)
    errors = getattr(owner, "provider_errors", None)
    adapters = getattr(owner, "provider_adapters", None)
    provider_failed = None
    if type(errors) is dict:
        if len(errors):
            provider_failed = True
        elif type(adapters) is dict and len(adapters) <= 2:
            values = [getattr(adapter, "failures", None) for adapter in adapters.values()]
            if all(type(value) is int and 0 <= value <= 65536 for value in values):
                provider_failed = any(value > 0 for value in values)
    return {"operation": operation, "actual_turn_started_count": count("actual_turn_started_count"),
            "manual_submission_count": count("paid_turn_start_submissions"),
            "aborted": aborted if type(aborted) is bool else None,
            "provider_failed": provider_failed}


def note_closed_failure(owner, error, boundary, side, fresh=None):
    try:
        try:
            stamp = time.monotonic_ns()
            if type(stamp) is not int or stamp < 0:
                stamp = None
        except BaseException:
            stamp = None
        rows = owner.result.setdefault("closed_restart_failures", [])
        if type(rows) is not list or len(rows) >= 16:
            return
        row = closed_failure(error)
        try:
            row.update(closed_restart_state(owner))
        except BaseException:
            row.update(operation="UNKNOWN", actual_turn_started_count=None, manual_submission_count=None, aborted=None, provider_failed=None)
        phase = owner.policy.phase
        row.update(sequence=len(rows),
                   boundary=boundary if type(boundary) is str and boundary in ("LIMIT", "FRESH_WITNESS", "WITNESS", "RESTART_ANCHOR") else "UNKNOWN",
                   require_fresh=fresh if type(fresh) is bool else None,
                   side=side if type(side) is str and side in ("a", "b") else "UNKNOWN",
                   phase=phase if type(phase) is str and phase in ("normal", "terminal", "cleanup") else "UNKNOWN",
                   host_monotonic_ns=stamp, clock_domain="HOST_ONLY",
                   cross_clock_order="NOT_VERIFIED")
        rows.append(row)
    except BaseException:
        pass


def install_closed_failure_diagnostics(owner):
    """Instance-only wrappers; original exceptions and limits propagate unchanged."""
    original_limit = owner.limit
    original_witness = owner.pq_transport_witness
    context = threading.local()
    owner._closed_failure_context = context
    def limit(maximum):
        try:
            return original_limit(maximum)
        except BaseException as error:
            note_closed_failure(owner, error, "LIMIT", getattr(context, "side", "UNKNOWN"), getattr(context, "fresh", None))
            context.limit_failed = True
            context.last_limit_error = error
            raise
    def witness(letter, require_wake=False, require_fresh=False):
        previous = (getattr(context, "side", "UNKNOWN"), getattr(context, "limit_failed", False), getattr(context, "fresh", None))
        context.side, context.limit_failed, context.fresh = letter, False, require_fresh
        try:
            return original_witness(letter, require_wake=require_wake, require_fresh=require_fresh)
        except BaseException as error:
            if not context.limit_failed:
                note_closed_failure(owner, error, "FRESH_WITNESS" if require_fresh else "WITNESS", letter, require_fresh)
            raise
        finally:
            context.side, context.limit_failed, context.fresh = previous
    owner.limit, owner.pq_transport_witness = limit, witness



PQ_DIAGNOSTIC_MAX = 2 << 20
PQ_DIAGNOSTIC_ROWS_MAX = 65536


def pq_file_scope(value):
    if (not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600 or
            not 0 <= value.st_size <= PQ_DIAGNOSTIC_MAX):
        raise RuntimeError("PQ_RESTART_ANCHOR_FILE_SCOPE")
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode)


def pq_diagnostic_ids(raw):
    if type(raw) is not bytes or not raw or len(raw) > PQ_DIAGNOSTIC_MAX or not raw.endswith(b"\n"):
        raise RuntimeError("PQ_RESTART_ANCHOR_MALFORMED")
    lines = raw.splitlines()
    if len(lines) > PQ_DIAGNOSTIC_ROWS_MAX:
        raise RuntimeError("PQ_RESTART_ANCHOR_BOUNDS")
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError("PQ_RESTART_ANCHOR_MALFORMED")
            value[key] = item
        return value
    ids = set()
    try:
        for line in lines:
            row = json.loads(line, object_pairs_hook=unique_object)
            if (type(row) is not dict or type(row.get("schema_version")) is not int or row["schema_version"] != 1 or
                    type(row.get("event")) is not str or row["event"] not in ("got-conn", "ready", "wake") or
                    type(row.get("observation_id")) is not str or not 1 <= len(row["observation_id"]) <= 256):
                raise RuntimeError("PQ_RESTART_ANCHOR_MALFORMED")
            ids.add(row["observation_id"])
    except (ValueError, UnicodeError):
        raise RuntimeError("PQ_RESTART_ANCHOR_MALFORMED") from None
    return frozenset(ids)


def pq_diagnostic_snapshot(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        scope = pq_file_scope(before)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(PQ_DIAGNOSTIC_MAX + 1)
        after = os.fstat(fd)
        current = path.lstat()
        if (scope != pq_file_scope(after) or scope != pq_file_scope(current) or
                after.st_size < len(raw) or current.st_size < len(raw)):
            raise RuntimeError("PQ_RESTART_ANCHOR_FILE_SCOPE")
        return {"scope": scope, "prefix": raw, "ids": pq_diagnostic_ids(raw)}
    finally:
        os.close(fd)


def anchor_owned_restart(owner, target):
    """Prove the current Hub, then snapshot BOTH files before submitting stop."""
    side = "UNKNOWN"
    try:
        actual = owner.inspect("container", owner.hub)
        if (target not in (owner.hub, actual.get("Id")) or
                actual.get("Id") != owner.result["hub_forwarder_refresh"][0]["owned_hub_container_id"] or
                actual.get("Image") != owner.hub_image or
                (actual.get("Config", {}).get("Labels") or {}).get("org.cicada.test.run") != owner.run_id):
            raise RuntimeError("PQ_RESTART_ANCHOR_HUB_OWNERSHIP")
        anchors = {}
        for letter in "ab":
            side = letter
            node = owner.nodes[letter]
            path = node["paths"]["state"] / "tls-diag/agent.jsonl"
            anchors[letter] = dict(pq_diagnostic_snapshot(path), path=path, node_id=node["node_id"], hub_id=actual["Id"])
        owner._pq_restart_anchors = anchors
    except BaseException as error:
        try:
            context = getattr(owner, "_closed_failure_context", None)
            if (getattr(context, "last_limit_error", None) is not error and
                    getattr(getattr(owner, "args", None), "closed_failure_diagnostics", False) is True):
                note_closed_failure(owner, error, "RESTART_ANCHOR", side)
        except BaseException:
            pass
        raise


def require_restart_anchor(owner, letter, path):
    anchor = getattr(owner, "_pq_restart_anchors", {}).get(letter)
    if (type(anchor) is not dict or anchor["path"] != path or
            anchor["node_id"] != owner.nodes[letter]["node_id"] or
            anchor["hub_id"] != owner.result["hub_forwarder_refresh"][0]["owned_hub_container_id"]):
        raise RuntimeError("PQ_RESTART_ANCHOR_MISSING")
    return anchor



def read_restart_diagnostic(owner, letter, path):
    anchor = require_restart_anchor(owner, letter, path)
    captured = pq_diagnostic_snapshot(path)
    if captured["scope"] != anchor["scope"]:
        raise RuntimeError("PQ_RESTART_ANCHOR_FILE_SCOPE")
    return captured["prefix"]


def validate_restart_diagnostic(owner, letter, path, raw):
    anchor = require_restart_anchor(owner, letter, path)
    current = path.lstat()
    pq_diagnostic_ids(raw)
    if pq_file_scope(current) != anchor["scope"] or current.st_size < len(raw) or not raw.startswith(anchor["prefix"]):
        raise RuntimeError("PQ_RESTART_ANCHOR_FILE_SCOPE")


def fresh_restart_id(owner, letter, identifier):
    # Called only by the selected witness after validating its file/prefix.
    return identifier not in owner._pq_restart_anchors[letter]["ids"]


def selected_fresh_witness(original):
    raw = (OLD / "managed_gate.py").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_GATE_SHA:
        raise ValueError("PQ_RESTART_WITNESS_SOURCE_PIN")
    tree = ast.parse(raw.decode())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ManagedGate")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "pq_transport_witness")
    source = ast.get_source_segment(raw.decode(), method)
    # Exact, bounded textual selection; preserve every original limit/TLS/loop statement.
    substitutions = (
        ("end=time.monotonic()+self.limit(5)", "if require_fresh: _require_restart_anchor(self, letter, path)\n        end=time.monotonic()+self.limit(5)"),
        ("raw=path.read_bytes()", "raw=_read_restart_diagnostic(self, letter, path) if require_fresh else path.read_bytes()\n                if require_fresh: _validate_restart_diagnostic(self, letter, path, raw)"),
        ("r.get('observation_id')!=node.get('last_pq_observation')", "_fresh_restart_id(self, letter, r.get('observation_id'))"),
    )
    for old, new in substitutions:
        if source.count(old) != 1:
            raise ValueError("PQ_RESTART_WITNESS_CONTEXT")
        source = source.replace(old, new, 1)
    namespace = method_namespace(original)
    namespace.update(_require_restart_anchor=require_restart_anchor,
        _validate_restart_diagnostic=validate_restart_diagnostic, _fresh_restart_id=fresh_restart_id,
        _read_restart_diagnostic=read_restart_diagnostic)
    exec(compile(source, "<owned-pre-stop-fresh-witness>", "exec"), namespace)
    return namespace["pq_transport_witness"], hashlib.sha256(source.encode()).hexdigest()



def selected_g2_manual_turn(original):
    """Only the owned G2/G3 lane admits its fourth manual submission."""
    raw = (OLD / "managed_gate.py").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_GATE_SHA:
        raise ValueError("G2_MANUAL_SOURCE_PIN")
    tree = ast.parse(raw.decode())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ManagedGate")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "manual_turn")
    source = ast.get_source_segment(raw.decode(), method)
    old = "if self.result_paid_dispatches >= 3:\n            raise RuntimeError('fourth manual turn forbidden')"
    new = "if self.result_paid_dispatches >= 4:\n            raise RuntimeError('fifth manual turn forbidden')"
    if source.count(old) != 1:
        raise ValueError("G2_MANUAL_CONTEXT")
    source = source.replace(old, new, 1)
    namespace = method_namespace(original)
    exec(compile(source, "<owned-g2-four-manual-turns>", "exec"), namespace)
    return namespace["manual_turn"], hashlib.sha256(source.encode()).hexdigest()


def selected_two_pass_refresh(original):
    raw = (OLD / "managed_gate.py").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_GATE_SHA:
        raise ValueError("TWO_PASS_REFRESH_SOURCE_PIN")
    tree = ast.parse(raw.decode())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ManagedGate")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "refresh_hub_forwarders")
    source = ast.get_source_segment(raw.decode(), method)
    old = """            observed = self.pq_transport_witness(letter, require_wake=False, require_fresh=phase!='initial')
            record['nodes'][letter] = {'before_target': old, 'after_target': target,
                'process_before': before, 'process_after': after, 'transport': observed,
                'hub_id_scope': 'same owned Hub container and persistent fixture; public health has no HubID field'}"""
    new = """            record['nodes'][letter] = {'before_target': old, 'after_target': target,
                'process_before': before, 'process_after': after,
                'hub_id_scope': 'same owned Hub container and persistent fixture; public health has no HubID field'}
        for letter in 'ab':
            observed = self.pq_transport_witness(letter, require_wake=False, require_fresh=phase!='initial')
            record['nodes'][letter]['transport'] = observed"""
    if source.count(old) != 1:
        raise ValueError("TWO_PASS_REFRESH_CONTEXT")
    source = source.replace(old, new, 1)
    namespace = method_namespace(original)
    exec(compile(source, "<owned-two-pass-hub-retarget>", "exec"), namespace)
    return namespace["refresh_hub_forwarders"], hashlib.sha256(source.encode()).hexdigest()


def reproduce_owned_zero_restart(owner):
    """Exactly one extra restart; no Join, membership, turn or message synthesis."""
    owner.step("explicit_zero_model_second_hub_restart")
    actual = owner.inspect("container", owner.hub)
    if (actual.get("Id") != owner.result["hub_forwarder_refresh"][0]["owned_hub_container_id"] or
            actual.get("Image") != owner.hub_image or
            (actual.get("Config", {}).get("Labels") or {}).get("org.cicada.test.run") != owner.run_id):
        raise RuntimeError("ZERO_RESTART_HUB_OWNERSHIP")
    owner.docker("stop", "--time", "1", actual["Id"])
    owner.start_hub()
    owner.refresh_hub_forwarders("explicit-zero-model-second-hub-restart")
    owner.result["explicit_zero_restart"] = {"extra_restarts": 1, "native_turns": 0,
        "membership_or_message_synthesized": False, "status": "RESTART_REFRESH_COMPLETED"}


def bind_policy(policy, started, normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    """Reuse existing instance with fixed absolute phase ends; no reset."""
    if (type(normal_seconds) is not int or normal_seconds < DEFAULT_NATIVE_NORMAL_SECONDS or
            normal_seconds > MAX_NATIVE_NORMAL_SECONDS):
        raise PermissionError("NATIVE_NORMAL_SECONDS")
    policy.started, policy.normal_seconds, policy.phase = started, normal_seconds, "normal"
    policy.normal_end = started + normal_seconds
    policy.terminal_end = policy.normal_end + NATIVE_TERMINAL_SECONDS
    policy.cleanup_end = policy.terminal_end + NATIVE_CLEANUP_SECONDS
    policy.total = normal_seconds + NATIVE_TERMINAL_SECONDS + NATIVE_CLEANUP_SECONDS
    def limit(self, maximum):
        end = {"normal":self.normal_end,"terminal":self.terminal_end,
               "cleanup":self.cleanup_end}[self.phase]
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("CANDIDATE_ABSOLUTE_DEADLINE")
        return min(maximum, left)
    def terminal(self):
        if self.phase != "cleanup":
            self.phase = "terminal"
    def cleanup(self):
        self.phase = "cleanup"
    policy.limit = types.MethodType(limit, policy)
    policy.terminal = types.MethodType(terminal, policy)
    policy.cleanup = types.MethodType(cleanup, policy)
    return policy


def compile_methods(source, namespace):
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ManagedGate")
    selected = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in METHODS]
    if {node.name for node in selected} != set(METHODS):
        raise ValueError("OVERLAY_METHOD_SET")
    for node in selected:
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<effective-request-observer-gate>", "exec"), namespace)
    return {name:namespace[name] for name in METHODS}


def validate_native_https(args, scenario, zero_model):
    mode=getattr(args,"native_https",False)
    if type(mode) is not bool:
        raise PermissionError("NATIVE_HTTPS_TYPE")
    go=getattr(args,"go",{})
    if type(go) is not dict or ("native_https" in go and go["native_https"] is not mode):
        raise PermissionError("NATIVE_HTTPS_GO")
    normal_seconds=getattr(args,"native_normal_seconds",DEFAULT_NATIVE_NORMAL_SECONDS)
    if (type(normal_seconds) is not int or normal_seconds < DEFAULT_NATIVE_NORMAL_SECONDS or
            normal_seconds > MAX_NATIVE_NORMAL_SECONDS or
            (not mode and normal_seconds != DEFAULT_NATIVE_NORMAL_SECONDS)):
        raise PermissionError("NATIVE_NORMAL_SECONDS")
    if mode:
        if (zero_model or scenario not in ("g1", "g2-g3") or getattr(args,"run_native",False) is not True or
                getattr(args,"test_request_observer",False) is not False or
                getattr(args,"response_byte_passthrough",False) is not False):
            raise PermissionError("NATIVE_HTTPS_LANE")
        turn_caps = (6, 4, 2) if scenario == "g2-g3" else (5, 3, 2)
        fields={"native_https":True,"response_byte_passthrough":False,
            "response_byte_ceiling":None,"response_chunk_ceiling":None,
            "max_native_turns":turn_caps[0],"max_manual_turns":turn_caps[1],"max_automatic_turns":turn_caps[2],
            "request_max_retries":0,"stream_max_retries":0,"max_accepted_TCP_connections_per_Runtime":16,
            "normal_seconds":normal_seconds,"terminal_seconds":NATIVE_TERMINAL_SECONDS,
            "cleanup_seconds":NATIVE_CLEANUP_SECONDS,
            "total_seconds":normal_seconds+NATIVE_TERMINAL_SECONDS+NATIVE_CLEANUP_SECONDS,
            "HTTP_POST_COUNT":"UNAVAILABLE","POST16_ENFORCEMENT":"UNAVAILABLE",
            "response_transport_semantics":"NATIVE_HTTPS_OPAQUE_PROXY",
            "TCP_connection_scope":"ADMITTED_SOCKETS_NOT_HTTP_POSTS_OR_COMPLETED_CONNECTS"}
        if any(key not in go or type(go[key]) is not type(value) or go[key]!=value for key,value in fields.items()) or any(
                key in go for key in ("max_POST_attempts_per_Runtime","observer_retries","io_diagnostics","test_request_observer")):
            raise PermissionError("NATIVE_HTTPS_GO")
    return mode


def validate_response_mode(args, scenario, zero_model):
    """Pure pre-constructor check; never silently switch a GO-selected mode."""
    mode = getattr(args, "response_byte_passthrough", False)
    if type(mode) is not bool:
        raise PermissionError("RESPONSE_MODE_TYPE")
    go = getattr(args, "go", {})
    if type(go) is not dict:
        raise PermissionError("RESPONSE_MODE_GO")
    if "response_byte_passthrough" in go and (type(go["response_byte_passthrough"]) is not bool or
                                               go["response_byte_passthrough"] is not mode):
        raise PermissionError("RESPONSE_MODE_GO")
    if mode:
        if zero_model or scenario != "g2-g3" or getattr(args,"run_native",False) is not True or getattr(args,"test_request_observer",False) is not True:
            raise PermissionError("RESPONSE_MODE_LANE")
        if (go.get("response_byte_passthrough") is not True or
                go.get("response_transport_semantics") != "NATIVE_HTTP_VALIDATES_RESPONSE_EOF_NOT_BUSINESS_COMPLETION" or
                type(go.get("response_byte_ceiling")) is not int or go["response_byte_ceiling"] != 4259840 or
                type(go.get("response_chunk_ceiling")) is not int or go["response_chunk_ceiling"] != 65536):
            raise PermissionError("RESPONSE_MODE_GO")
    elif getattr(args,"native_https",False) is not True and (any(key in go and go[key] is not None for key in ("response_byte_ceiling","response_chunk_ceiling")) or
          ("response_transport_semantics" in go and go["response_transport_semantics"] != "OBSERVER_STRICT_HTTP_FRAMING")):
        raise PermissionError("RESPONSE_MODE_GO")
    return mode


def runtime_bootstrap_argv(arguments, binding, started, *, response_byte_passthrough=False):
    """Pure selection shared by inspection and actual authorized Docker branch."""
    if type(response_byte_passthrough) is not bool:
        raise ValueError("RESPONSE_MODE_TYPE")
    argv = list(map(str, arguments))
    if len(argv) < 7 or argv[:2] != ["exec","-d"] or argv[3:6] != ["python3","/state/server_bootstrap.py","paid"]:
        raise ValueError("CANDIDATE_BOOTSTRAP_DISPATCH_SHAPE")
    argv[4] = "/tmp/request_observer_bootstrap.py"
    argv += [binding["candidate_files"]["request_observer_bootstrap.py"]["sha256"],
             binding["effective_sources"]["bootstrap"], repr(started), binding["public_files"][str(SCRIPTS/"native_request_observer_io.py")]["sha256"], "--io-diagnostics"]
    if response_byte_passthrough:
        argv.append("--response-byte-passthrough")
    return argv


def client_read_cancellation_relay_source(*, io_diagnostics_v2=False):
    """Single owned exception-branch overlay on the immutable public relay."""
    io_diagnostics_v2 = io_diagnostics_v2 is True
    raw=(OLD/"provider_transport.py").read_bytes()
    if hashlib.sha256(raw).hexdigest()!="91da1e83820caed12809ba8bd6a3156a015e84bf70c310eeb87d91d359118e72":
        raise ValueError("FORWARDER_BASE_PIN")
    tree=ast.parse(raw)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="Forwarder")
    relay=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=="relay")
    outer=next(n for n in relay.body if isinstance(n,ast.Try))
    branch=outer.handlers[0].body[-1]
    if not isinstance(branch,ast.If) or ast.unparse(branch.test)!="self.closed":
        raise ValueError("FORWARDER_FAILURE_CONTEXT")
    cancellation=ast.parse("if type(error) is ConnectionResetError and stage == 'recv_client' and code == 104:\n self.client_read_cancellations += 1\n self.peer_error_disconnects += 1\n self.last_client_read_cancellation = {'classification':'CLIENT_READ_CANCELLED_CONNECTION_ONLY','stage':'recv_client','errno':104,'application_completion':'UNKNOWN'}\n").body[0]
    drained=ast.parse("if type(error) is OSError and stage == 'halfclose_client' and code == 107 and type(pending) is dict and len(pending) == 2 and type(eof_sources) is set and upstream in eof_sources and client not in eof_sources and type(pending.get(client)) is bytearray and type(pending.get(upstream)) is bytearray and not pending[client] and not pending[upstream]:\n self.drained_upstream_eof_cancellations += 1\n self.peer_error_disconnects += 1\n self.last_drained_upstream_eof_cancellation = {'classification':'CLIENT_HALFCLOSE_CANCELLED_CONNECTION_ONLY','stage':'halfclose_client','errno':107,'application_completion':'UNKNOWN','upstream_eof':True,'client_eof':False,'pending_client_bytes':0,'pending_upstream_bytes':0}\n").body[0]
    drained.orelse=branch.orelse
    cancellation.orelse=[drained]
    branch.orelse=[cancellation]
    if io_diagnostics_v2:
        fatal = next(n for n in ast.walk(cancellation) if isinstance(n, ast.AugAssign)
            and isinstance(n.target, ast.Attribute) and n.target.attr == "failures")
        parent = next(n for n in ast.walk(cancellation) if isinstance(n, ast.If) and fatal in n.orelse)
        parent.orelse.insert(0, ast.parse("_note_forwarder_fatal(self, stage, error, client, upstream, locals().get('pending'), locals().get('eof_sources'))").body[0])
    ast.fix_missing_locations(relay)
    return ast.unparse(relay)+"\n"


FORWARDER_FATAL_STAGES = frozenset(("connect", "select", "recv_client", "recv_upstream",
    "send_client", "send_upstream", "halfclose_client", "halfclose_upstream"))


def note_forwarder_fatal(adapter, stage, error, client, upstream, pending, eof_sources):
    """Closed optional metadata; no transport handling or propagation changes."""
    try:
        try:
            stamp = time.monotonic_ns()
            stamp = stamp if type(stamp) is int and 0 <= stamp <= 2**63-1 else None
        except BaseException:
            stamp = None
        from native_request_observer import IO_ERRNOS
        with adapter.lock:
            if adapter.first_fatal_io is not None:
                return
            classes = {ConnectionResetError:"CONNECTION_RESET", BrokenPipeError:"BROKEN_PIPE",
                TimeoutError:"TIMEOUT", OSError:"OS_ERROR"}
            try:
                code = getattr(error,"errno",None)
            except BaseException:
                code = None
            code = code if type(code) is int and code in IO_ERRNOS else None
            def count(obj):
                try:
                    if type(pending) is not dict or obj not in pending:
                        return None
                    size = len(pending[obj])
                    return size if type(size) is int and 0 <= size <= 65536 else None
                except BaseException:
                    return None
            def eof(obj):
                try:
                    return obj in eof_sources if type(eof_sources) is set else None
                except BaseException:
                    return None
            port = None
            try:
                value = client.getpeername()[1]
                if type(value) is int and 1 <= value <= 65535: port = value
            except BaseException:
                pass
            adapter.first_fatal_io = {"schema":"cicada.owned-forwarder-fatal.v1",
                "stage":stage if stage in FORWARDER_FATAL_STAGES else "UNKNOWN",
                "class":classes.get(type(error),"OTHER"), "errno":code, "monotonic_ns":stamp,
                "pending_client_bytes":count(client), "pending_upstream_bytes":count(upstream),
                "client_eof":eof(client),
                "upstream_eof":eof(upstream),
                "client_peer_port":port, "causality":"NOT_PROVEN", "selection":"FIRST_PUBLISHED"}
    except BaseException:
        pass


def install_client_read_cancellation(adapter, expected_sha=None, *, io_diagnostics_v2=False):
    # Only this owned instance changes; the frozen class/module remain untouched.
    io_diagnostics_v2 = io_diagnostics_v2 is True
    namespace=dict(adapter.relay.__func__.__globals__)
    source=client_read_cancellation_relay_source(io_diagnostics_v2=io_diagnostics_v2)
    source_sha=hashlib.sha256(source.encode()).hexdigest()
    if expected_sha is not None and source_sha!=expected_sha:
        raise ValueError("OWNED_RELAY_PIN")
    adapter.owned_client_read_relay_sha256=source_sha
    if io_diagnostics_v2:
        namespace["_note_forwarder_fatal"] = note_forwarder_fatal
        adapter.first_fatal_io = None
    exec(compile(source,"<owned-client-read-cancellation-relay>","exec"),namespace)
    adapter.client_read_cancellations=0
    adapter.last_client_read_cancellation=None
    adapter.drained_upstream_eof_cancellations=0
    adapter.last_drained_upstream_eof_cancellation=None
    adapter.relay=types.MethodType(namespace["relay"],adapter)
    original_summary=adapter.summary
    def summary(self):
        value=original_summary()
        value.update(client_read_cancellations=self.client_read_cancellations,
            last_client_read_cancellation=self.last_client_read_cancellation,
            owned_client_read_relay_sha256=self.owned_client_read_relay_sha256,
            drained_upstream_eof_cancellations=self.drained_upstream_eof_cancellations,
            last_drained_upstream_eof_cancellation=self.last_drained_upstream_eof_cancellation)
        if io_diagnostics_v2:
            value["first_fatal_io"] = self.first_fatal_io
        return value
    adapter.summary=types.MethodType(summary,adapter)


G2_TOOLS = ("cicada_join", "cicada_use_group", "cicada_leave_group", "cicada_whoami", "cicada_members", "cicada_find", "cicada_ask", "cicada_receive", "cicada_reply")

def g2_node_scope(meta, letter):
    if letter not in ("a", "b") or meta.get("scenario") != "g2-g3":
        raise ValueError("G2_NODE_SCOPE")
    keys = ("owner_id", "group_id") if letter == "a" else ("bob_owner_id", "bob_group_id")
    values = tuple(meta.get(key) for key in keys)
    if any(type(value) is not str or not value for value in values) or meta.get("bob_owner_id") == meta.get("owner_id"):
        raise ValueError("G2_DISTINCT_AUTHORITY")
    return values

def compile_g2_preparation_methods(source, namespace):
    """Select existing preparation methods with narrow per-Node scope changes."""
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ManagedGate")
    selected = {}
    for name in ("prepare_managed", "bind_mcp"):
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)
        text = ast.get_source_segment(source, method)
        if name == "prepare_managed":
            old = "'--native-thread-b', self.nodes['b']['thread'])"
            if text.count(old) != 1: raise ValueError("G2_BOOTSTRAP_CONTEXT")
            text = text.replace(old, "'--native-thread-b', self.nodes['b']['thread'], '--scenario', 'g2-g3')", 1)
            old = "proof['group_id'] != self.meta['group_id'] or (proof['owner_id'] != self.meta['owner_id'])"
            if text.count(old) != 1: raise ValueError("G2_TLS_PROOF_CONTEXT")
            text = text.replace(old, "proof['group_id'] != _g2_node_scope(self.meta,letter)[1] or proof['owner_id'] != _g2_node_scope(self.meta,letter)[0]", 1)
            old = "required = {'cicada_join', 'cicada_find', 'cicada_ask', 'cicada_receive', 'cicada_reply'}"
            if text.count(old) != 1: raise ValueError("G2_DISCOVERY_CONTEXT")
            text = text.replace(old, "required = set(_g2_tools)", 1)
        else:
            old = "('cicada_join', 'cicada_find', 'cicada_ask', 'cicada_receive', 'cicada_reply')"
            if text.count(old) != 2: raise ValueError("G2_APPROVAL_CONTEXT")
            text = text.replace(old, "_g2_tools")
        # Source-segment retains method indentation after its first line.
        lines = text.splitlines()
        text = lines[0] + "\n" + "\n".join(line[4:] if line.startswith("    ") else line for line in lines[1:]) + "\n"
        exec(compile(text, "<owned-g2-preparation>", "exec"), namespace)
        selected[name] = namespace[name]
    return selected


def g2_turn_witness(base, events, thread, tools, markers=()):
    """Only initial multi-Join changes cardinality; strict shared marker parser stays."""
    calls = [event['item'] for event in events if event.get('type') == 'item.completed'
             and event.get('item', {}).get('type') == 'mcp_tool_call']
    if tuple(item.get('tool') or item.get('name') for item in calls) != tuple(tools):
        raise RuntimeError('G2_EXACT_ORDERED_TOOLS')
    hashes = []
    for item in calls:
        if item.get('status') != 'completed':
            raise RuntimeError('G2_TOOL_NOT_COMPLETED')
        payload = base.native_tool_payload(item)
        hashes.append({'tool': item.get('tool') or item.get('name'),
            'actual_result_sha256': hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()})
    without = [event for event in events if not (event.get('type') == 'item.completed'
               and event.get('item', {}).get('type') == 'mcp_tool_call')]
    witness = base.turn_witness(without, thread, (), markers)
    witness.update(completed_tools=list(tools), actual_tool_result_audit=hashes)
    return witness


def g2_initial_binding(self, letter, turn_id):
    ns = self.managed_golden_flow.__globals__
    base, dto = ns['base'], ns['dto_progression']
    items = [params['item'] for node, params in self.budget.items
             if node == letter and params['turnId'] == turn_id]
    calls = [item for item in items if item.get('type') == 'mcpToolCall']
    group = self.meta['group_id'] if letter == 'a' else self.meta['bob_group_id']
    if len(calls) != 1 or calls[0].get('tool') != 'cicada_join' or calls[0].get('arguments') != {'group_id':group} or calls[0].get('status') != 'completed':
        raise RuntimeError('G2_INITIAL_JOIN_SCOPE')
    payload=base.native_tool_payload(calls[0])
    binding=dto.join_binding(payload,self.nodes[letter]['thread'],self.nodes[letter]['node_id'],group)
    self.nodes[letter].update(binding_before=binding,endpoint=binding['endpoint_id'],trusted_join_card=dict(payload['network_card']),current_group_id=group)


def g2_second_binding(self, turn_id):
    ns=self.managed_golden_flow.__globals__;base,dto=ns['base'],ns['dto_progression']
    calls=[p['item'] for node,p in self.budget.items if node=='a' and p['turnId']==turn_id and p['item'].get('type')=='mcpToolCall']
    expected=('cicada_join','cicada_use_group','cicada_leave_group','cicada_whoami')
    if tuple(x.get('tool') for x in calls)!=expected or any(x.get('status')!='completed' for x in calls):raise RuntimeError('G2_SECOND_MEMBERSHIP_SEQUENCE')
    if [x.get('arguments') for x in calls]!=[{'group_id':self.meta['alice_second_group_id']},{'group_id':self.meta['group_id']},{},{}]:raise RuntimeError('G2_GROUP_ONLY_LEAVE_SCOPE')
    binding=dto.join_binding(base.native_tool_payload(calls[0]),self.nodes['a']['thread'],self.nodes['a']['node_id'],self.meta['alice_second_group_id'])
    if binding['endpoint_id']!=self.nodes['a']['endpoint']:raise RuntimeError('G2_ORIGINAL_ENDPOINT_CHANGED')
    left=base.native_tool_payload(calls[2]);card=base.native_tool_payload(calls[3])
    if left.get('status')!='left_group' or left.get('remaining_group_id')!=self.meta['alice_second_group_id'] or left.get('scope_activation_error'):raise RuntimeError('G2_OTHER_MEMBERSHIP_NOT_RETAINED')
    if card.get('endpoint_id')!=self.nodes['a']['endpoint'] or card.get('native_session_id')!=self.nodes['a']['thread'] or card.get('node_id')!=self.nodes['a']['node_id'] or card.get('group_id')!=self.meta['alice_second_group_id'] or type(card.get('binding_epoch')) is not int or card['binding_epoch']<1 or not card.get('binding_id'):raise RuntimeError('G2_FINAL_CURRENT_CARD_SCOPE')
    binding=dict(binding,id=card['binding_id'],epoch=card['binding_epoch'],status=card.get('binding_status'))
    self.nodes['a'].update(binding_before=binding,trusted_join_card=dict(card),current_group_id=card['group_id'])
    self.result['g2_membership']={'same_original_thread':True,'same_original_endpoint':True,'separately_authorized_principal_membership':True,'left_primary_only':True,'selected_group_id':card['group_id']}


def g2_accepted_ask(dto, item, payload, sender, receiver, question, card, link):
    # Link derives its exact target from the previously verified bilateral receipt.
    if item.get('arguments') != {'question': question, 'link_id': link, 'data_scope': 'thread.message'}:
        raise RuntimeError('G2_EXACT_NARROW_ASK')
    result = payload.get('result')
    if (type(result) is not dict or payload.get('operation') != 'ask' or payload.get('status') != 'SENT'
        or payload.get('retryable') is not False or payload.get('link_id') != link
        or result.get('link_id') != link or result.get('status') != 'OPEN'
        or result.get('reply_mode') != 'asynchronous' or result.get('payload_mode') != 'SEALED_V1'
        or result.get('delivery') != 'RELAY_PERSISTED'):
        raise RuntimeError('G2_ACCEPTED_LINK_SCOPE')
    for key in ('request_id','message_id'):
        if type(payload.get(key)) is not str or not payload[key] or result.get(key) != payload[key]:
            raise RuntimeError('G2_ASK_CORRELATION')
    return {'request_id':payload['request_id'],'message_id':payload['message_id'],
        'sender_endpoint_id':sender,'receiver_endpoint_id':receiver,'link_id':link,'state':'OPEN'}


def g2_accepted_reply(dto, items, parse, request, answer):
    item = dto.one(items, 'cicada_reply')
    payload = parse(item)
    result = payload.get('result')
    if (item.get('arguments') != {'request_id':request['request_id'],'body':answer,'link_id':request['link_id']}
        or type(result) is not dict or payload.get('operation') != 'reply' or payload.get('status') != 'SENT'
        or payload.get('retryable') is not False or payload.get('link_id') != request['link_id']
        or result.get('link_id') != request['link_id'] or result.get('status') != 'REPLIED'
        or result.get('payload_mode') != 'SEALED_V1' or result.get('delivery') != 'RELAY_PERSISTED'
        or payload.get('request_id') != request['request_id'] or result.get('request_id') != request['request_id']):
        raise RuntimeError('G2_EXACT_NARROW_REPLY')
    message = payload.get('message_id')
    if type(message) is not str or not message or message == request['message_id'] or result.get('message_id') != message:
        raise RuntimeError('G2_REPLY_CORRELATION')
    return {'request_id':request['request_id'],'reply_message_id':message,'state':'REPLIED'}


def g2_b_continuity(self, events, request, question, answer, beta):
    ns = self.managed_golden_flow.__globals__
    base = ns['base']
    if beta in question or answer in question:
        raise RuntimeError('G2_REPLY_SEED_REFEED')
    if (type(request.get('link_id')) is not str or not request['link_id'] or
            request.get('sender_endpoint_id') != self.nodes['a']['endpoint'] or
            request.get('receiver_endpoint_id') != self.nodes['b']['endpoint']):
        raise RuntimeError('G2_REPLY_REQUEST_BINDING')
    base.turn_witness(events, self.nodes['b']['thread'], ('cicada_receive', 'cicada_reply'))
    receive = base.exact_receive_witness(events, request['message_id'], request['request_id'], self.nodes['a']['endpoint'], question)
    items = [event['item'] for event in events if event.get('type') == 'item.completed']
    reply = g2_accepted_reply(ns['dto_progression'], items, base.native_tool_payload, request, answer)
    return {'continuity_proof': 'ACTUAL_EXACT_SEEDED_REPLY_BODY', 'original_thread_exact': True,
        'request_id_exact': True, 'actual_reply_body_sha256': hashlib.sha256(answer.encode()).hexdigest(),
        'seed_beta_in_actual_reply_body': beta in answer, 'link_bound_by_validated_ask_and_reply': True,
        'receive_correlated_by_request_message_sender_body': True, 'receive': receive, 'reply': reply}


def compile_g2_flow_methods(source, namespace):
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ManagedGate')
    result = {}
    def replace(text, old, new, count=1):
        if text.count(old) == count:
            return text.replace(old, new)
        # Effective source is normalized by the already-owned AST selector.
        # Match the exact statement AST spelling rather than legacy whitespace.
        import textwrap
        def normalize(value):
            value = textwrap.dedent(value)
            if value.rstrip().endswith(':'):
                return ast.unparse(ast.parse(value+'\n pass')).splitlines()[0]
            return ast.unparse(ast.parse(value))
        old, new = normalize(old), normalize(new)
        if text.count(old) != count:
            raise ValueError('G2_FLOW_EXACT_CONTEXT')
        position = text.index(old)
        indent = text[text.rfind('\n',0,position)+1:position]
        if indent.strip(): indent = ''
        return text.replace(old, new.replace('\n','\n'+indent))
    for name in ('audit_turn', 'audit_inline_reply', 'managed_golden_flow'):
        node = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)
        text = ast.get_source_segment(source, node)
        if name == 'audit_turn':
            old = "audited_events, extra = audit_initial_empty_receive(events, self.nodes[letter]['thread'], binding,\n                self.meta['group_id'], bool(self.result.get('initial_optional_empty_receive')))"
            text = replace(text, old, "audited_events = events")
            text = replace(text, "witness = base.turn_witness(audited_events, self.nodes[letter]['thread'], tools, () if initial_join else markers)",
                "witness = _g2_turn_witness(base, audited_events, self.nodes[letter]['thread'], tools, () if initial_join else markers) if initial_join else base.turn_witness(audited_events, self.nodes[letter]['thread'], tools, markers)")
        elif name == 'audit_inline_reply':
            text = replace(text, "from inline_reply import inline_reply_witness", "inline_reply_witness = _g2_inline_reply_witness")
            text = replace(text, "'group_id': self.meta['group_id']", "'group_id': self.meta['alice_second_group_id'], 'link_id': request['link_id']")
            text = replace(text,
                "        proof = inline_reply_witness(selected, {'threadId': self.nodes['a']['thread'],",
                "        membership = self.result.get('g2_membership')\n"
                "        if (type(membership) is not dict or set(membership) != {'same_original_thread', 'same_original_endpoint', 'separately_authorized_principal_membership', 'left_primary_only', 'selected_group_id'} or\n"
                "            membership.get('same_original_thread') is not True or membership.get('same_original_endpoint') is not True or\n"
                "            membership.get('separately_authorized_principal_membership') is not True or membership.get('left_primary_only') is not True or\n"
                "            membership.get('selected_group_id') != self.meta['alice_second_group_id']):\n"
                "            raise RuntimeError('G2_SHARED_MEMORY_SCOPE_EXPECTATION')\n"
                "        proof = inline_reply_witness(selected, {'threadId': self.nodes['a']['thread'],")
            text = replace(text,
                "turn_id, expected, markers, answer, base.native_tool_payload)",
                "turn_id, expected, markers, answer, base.native_tool_payload, shared_memory_risk=True)")
        else:
            start = text.index('        prompts = {')
            end = text.index("        self.result['bindings_before']", start)
            text = text[:start] + '''        prompts = {
            'a': f'Remember {alpha} as your original context. Call cicada_join exactly once with group_id {json.dumps(self.meta["group_id"])}. This turn calls only Join. Do not Receive now. Only in a later actual peer queued reply turn report the exact correlated response and original context witness remembered from this first turn, and send no further message. Finish now with your original witness and READY.',
            'b': f'Remember {beta}. Your exact future response phrase is {answer}. Call cicada_join exactly once with group_id {json.dumps(self.meta["bob_group_id"])} now. This turn calls only Join; do not Receive or Reply now. Later, on the actual peer queued question, call cicada_receive exactly once and cicada_reply exactly once using its exact request_id and link_id and your remembered response phrase. Do not retry. Finish now with your witness and READY.'}
        for letter in 'ab':
            turn_id = self.manual_turn(letter, prompts[letter])
            self.g2_initial_binding(letter, turn_id)
            tools = ('cicada_join',)
            self.audit_turn(letter, turn_id, tools, (alpha if letter == 'a' else beta,), initial_join=True)
        self.step('explicit_owner_second_membership_authorization')
        owned_hub=self.inspect('container',self.hub)
        if owned_hub['Image'] != self.hub_image or (owned_hub['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id: raise RuntimeError('G2_SECOND_AUTHORIZATION_HUB_OWNERSHIP')
        self.docker('stop','--time','1',owned_hub['Id'])
        authorization=json.loads(self.helper('g2-authorize-second'))
        self.start_hub()
        self.refresh_hub_forwarders('paid-after-explicit-second-membership-authorization')
        if authorization != {'status':'G2_SECOND_MEMBERSHIP_AUTHORIZED'}: raise RuntimeError('G2_SECOND_MEMBERSHIP_AUTHORIZATION_NOT_CONFIRMED')
        self.step('original_a_authorized_second_group_join_leave')
        membership_turn=self.manual_turn('a',f'Call cicada_join with group_id {json.dumps(self.meta["alice_second_group_id"])} exactly once, then cicada_use_group with group_id {json.dumps(self.meta["group_id"])}, then cicada_leave_group with {{}} and cicada_whoami with {{}}. The explicitly authorized second membership must survive on this same Endpoint and original native session. Do not call cicada_leave or any message tool. This supplements the original task, which remains pending; preserve its original output requirements. Finish only this submission turn READY.')
        self.g2_second_binding(membership_turn)
        self.audit_turn('a',membership_turn,('cicada_join','cicada_use_group','cicada_leave_group','cicada_whoami'))
''' + text[end:]
            text = replace(text, "self.refresh_hub_forwarders('paid-after-owner-approval-restart')", "self.refresh_hub_forwarders('paid-after-owner-approval-restart')\n        link_record = json.loads((self.root/'g2-link.json').read_text())\n        if set(link_record) != {'link_id','source_endpoint_id','target_endpoint_id'} or link_record['source_endpoint_id'] != self.nodes['a']['endpoint'] or link_record['target_endpoint_id'] != self.nodes['b']['endpoint']:\n            raise RuntimeError('G2_CURRENT_LINK_ENDPOINT_RECEIPT')\n        self.g2_link_id = link_record['link_id']")
            # Cross-Owner hidden-member search is separately tested below; Ask uses the exact authorized endpoint.
            transformed = ast.parse(text)
            calls = [value for value in ast.walk(transformed) if isinstance(value,ast.Call) and
                isinstance(value.func,ast.Attribute) and value.func.attr == 'manual_turn' and
                value.args and isinstance(value.args[0],ast.Constant) and value.args[0].value == 'a' and 'cicada_find' in (ast.get_source_segment(text,value) or '')]
            if len(calls) != 1: raise ValueError('G2_A2_EXACT_CALL')
            old_call = ast.get_source_segment(text,calls[0])
            new_call = "self.manual_turn('a', f'Call cicada_ask exactly once with link_id {json.dumps(self.g2_link_id)}, data_scope \"thread.message\", and question {json.dumps(question)}. ' + _g2_a2_instruction)"
            text = replace(text,old_call,new_call)
            text = replace(text, "('cicada_find', 'cicada_ask')", "('cicada_ask',)")
            text = replace(text, "request=dto_progression.accepted_ask(ask,base.native_tool_payload(ask),self.nodes['a']['endpoint'],self.nodes['b']['endpoint'],question,self.nodes['b']['trusted_join_card'])", "request=_g2_accepted_ask(dto_progression,ask,base.native_tool_payload(ask),self.nodes['a']['endpoint'],self.nodes['b']['endpoint'],question,self.nodes['b']['trusted_join_card'],self.g2_link_id)")
            old = "b_continuity = b_reply_continuity_witness(bevents, self.nodes['b']['thread'],\n            request['message_id'], request['request_id'], self.nodes['a']['endpoint'], question, answer, beta)"
            text = replace(text, old, "b_continuity = self.g2_b_continuity(bevents, request, question, answer, beta)")
            text = replace(text, "final=dto_progression.accepted_reply([e['item'] for e in bevents if e.get('type')=='item.completed'],base.native_tool_payload,request,answer)", "final=_g2_accepted_reply(dto_progression,[e['item'] for e in bevents if e.get('type')=='item.completed'],base.native_tool_payload,request,answer)")
            text = replace(text,"len(self.budget.started) != 5","len(self.budget.started) != 6",count=3)
            text = replace(text,"len(self.budget.completed) != 5","len(self.budget.completed) != 6")
            text = replace(text,"len(self.manual_turn_ids) != 3","len(self.manual_turn_ids) != 4")
            text = text.replace('exact three manual and two automatic actual turns required','exact four manual and two automatic actual turns required')
            text = replace(text, "self.step('managed_hub_blind_terminal_oracle')", "self.g2_revoke_and_visibility()\n        self.step('managed_hub_blind_terminal_oracle')")
            text = replace(text, "self.result['status'] = 'PASS'", "self.g3_restore_snapshot()\n        self.result['scenario_acceptance'] = {'G2':'PASS','G3':'AUTHENTICATED_ENCRYPTED_STATUS_SNAPSHOT_PASS','G4':'NOT_RUN','V67':'NOT_RUN'}\n        self.result['status'] = 'PASS'")
        lines = text.splitlines()
        text = lines[0]+'\n'+'\n'.join(line[4:] if line.startswith('    ') else line for line in lines[1:])+'\n'
        exec(compile(text, '<owned-g2-g3-flow>', 'exec'), namespace)
        result[name] = namespace[name]
        result[name]._g2_selected_source = text
    return result


G2_INLINE_REPLY_SOURCE_SHA = "d4c1cf530e647c90da0bf5d5adb75021e9ed6c7c6d0d63f206c54dd136dccf41"
G2_SHARED_MEMORY_WARNING = ("CICADA_CONTEXT_SCOPE_SHARED_MEMORY_RISK: this native session is known to have been "
    "used in multiple authorized scopes. Do not infer isolation or erase earlier context.\n")


def _inline_reply_witness_for_scenario(*args, expected_fields, prefix, code_prefix,
                                       shared_memory_risk=False):
    """Keep the complete inline envelope; check optional Receive by its real DTO."""
    if type(shared_memory_risk) is not bool or len(args) != 8 or type(args[0]) is not list:
        raise RuntimeError(code_prefix+'_INLINE_REPLY_ARGUMENTS')
    import inline_reply
    source_path = Path(inline_reply.__file__).resolve(strict=True)
    if source_path != (OLD / 'inline_reply.py').resolve(strict=True):
        raise ValueError('G2_INLINE_REPLY_SOURCE_ORIGIN')
    raw = source_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != G2_INLINE_REPLY_SOURCE_SHA:
        raise ValueError('G2_INLINE_REPLY_SOURCE_PIN')
    source = raw.decode('utf-8')
    old = "if any(message.get(k)!=v for k,v in expected.items()) or message.get('body')!=answer:"
    new = ("if any(message.get(k)!=expected[k] for k in "
           "('message_id','request_id','reply_to','sender_endpoint_id')) "
           "or message.get('body')!=answer:")
    if source.count(old) != 1:
        raise ValueError(code_prefix+'_INLINE_RECEIVE_CONTEXT')
    source = source.replace(old, new)
    old = "if not isinstance(payload, dict) or any(payload.get(k) != v for k,v in expected.items()):"
    new = ("if not isinstance(payload, dict) or set(payload) != set(expected) | {'body'} "
           "or any(payload.get(k) != v for k,v in expected.items()):")
    if source.count(old) != 1:
        raise ValueError(code_prefix+'_INLINE_PAYLOAD_SCHEMA')
    source = source.replace(old, new)
    namespace = dict(inline_reply.inline_reply_witness.__globals__)
    exec(compile(source, '<owned-g2-inline-reply>', 'exec'), namespace)
    # The pinned source declares its default prefix at module scope; set the
    # scenario's exact Link prefix only after executing that source.
    namespace['PREFIX'] = prefix
    function = namespace['inline_reply_witness']
    original_items, completed, original, turn, expected, markers, answer, tool_payload = args
    if (type(expected) is not dict or set(expected) != expected_fields or
            any(type(expected.get(key)) is not str or not expected[key] for key in expected_fields)):
        raise RuntimeError(code_prefix+'_INLINE_REPLY_EXPECTED_SCHEMA')
    selected_users = [row for row in original_items
        if type(row) is dict and row.get('turnId') == turn and
        type(row.get('item')) is dict and row['item'].get('type') == 'userMessage']
    if len(selected_users) != 1:
        raise RuntimeError(code_prefix+'_INLINE_REPLY_USER_COUNT')
    user = selected_users[0]['item']
    content = user.get('content')
    if (type(content) is not list or len(content) != 1 or type(content[0]) is not dict or
            content[0].get('type') != 'text' or type(content[0].get('text')) is not str):
        raise RuntimeError(code_prefix+'_INLINE_REPLY_USER_TEXT_SHAPE')
    original_text = content[0]['text']
    warning_present = G2_SHARED_MEMORY_WARNING in original_text
    if shared_memory_risk:
        if (not original_text.startswith(G2_SHARED_MEMORY_WARNING) or
                original_text.count(G2_SHARED_MEMORY_WARNING) != 1):
            raise RuntimeError(code_prefix+'_SHARED_MEMORY_WARNING_EXPECTED')
        normalized_text = original_text[len(G2_SHARED_MEMORY_WARNING):]
        if not normalized_text.startswith(prefix):
            raise RuntimeError(code_prefix+'_SHARED_MEMORY_WARNING_FRAME')
    else:
        if warning_present:
            raise RuntimeError(code_prefix+'_SHARED_MEMORY_WARNING_UNEXPECTED')
        normalized_text = original_text
    # Keep the captured event untouched. Only a local event copy omits the
    # independently proven, exact product warning so the pinned strict parser
    # can validate the canonical REPLY envelope. Restore its original-input
    # hash in the returned proof below.
    normalized_items = list(original_items)
    user_index = next(index for index, row in enumerate(original_items) if row is selected_users[0])
    normalized_row = dict(selected_users[0])
    normalized_user = dict(user)
    normalized_content = [dict(block) for block in content]
    normalized_content[0]['text'] = normalized_text
    normalized_user['content'] = normalized_content
    normalized_row['item'] = normalized_user
    normalized_items[user_index] = normalized_row
    proof = function(normalized_items, completed, original, turn, expected, markers, answer, tool_payload)
    proof['inline_sha256'] = hashlib.sha256(original_text.encode('utf-8')).hexdigest()
    proof['shared_memory_risk_warning_present'] = warning_present
    return proof


G1_INLINE_REPLY_FIELDS = frozenset(('message_id','request_id','reply_to','sender_endpoint_id',
                                   'receiver_endpoint_id','group_id'))
G2_INLINE_REPLY_FIELDS = frozenset(('message_id','request_id','reply_to','sender_endpoint_id',
                                   'receiver_endpoint_id','group_id','link_id'))


def g1_inline_reply_witness(*args):
    return _inline_reply_witness_for_scenario(*args, expected_fields=G1_INLINE_REPLY_FIELDS,
        prefix='Cicada SEALED_V1 same-Group REPLY. ', code_prefix='G1')


def g2_inline_reply_witness(*args, shared_memory_risk=False):
    """Keep the full inline Link check; validate optional Receive by its actual DTO."""
    return _inline_reply_witness_for_scenario(*args, expected_fields=G2_INLINE_REPLY_FIELDS,
        prefix='Cicada SEALED_V1 REPLY. ', code_prefix='G2',
        shared_memory_risk=shared_memory_risk)


def compile_g1_inline_reply_method(source, namespace):
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ManagedGate')
    node = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'audit_inline_reply')
    text = ast.get_source_segment(source, node)
    old = 'from inline_reply import inline_reply_witness'
    if text.count(old) != 1:
        raise ValueError('G1_INLINE_METHOD_IMPORT_CONTEXT')
    text = text.replace(old, 'inline_reply_witness = _g1_inline_reply_witness')
    exec(compile(text, '<owned-g1-inline-reply-method>', 'exec'), namespace)
    return {'audit_inline_reply': namespace['audit_inline_reply']}


def g2_mcp_call(self, letter, tool, arguments):
    """Actual existing caller/Node/stdin MCP, never a Native turn or queue call."""
    if tool not in ('cicada_whoami', 'cicada_members', 'cicada_find', 'cicada_ask'):
        raise RuntimeError('G2_DIAGNOSTIC_TOOL_NOT_ALLOWED')
    node = self.nodes[letter]
    import tomllib
    values = self.native_config(letter,node['thread'],G2_TOOLS)
    settings = tomllib.loads('\n'.join(values[index+1] for index in range(0,len(values),2)
        if values[index+1].startswith('mcp_servers.cicada.')))['mcp_servers']['cicada']
    env = settings['env']
    if (settings['command'] != '/opt/cicada-pqtls/bin/cicada' or
        settings['args'] != ['mcp','--api-url','http://127.0.0.1:8787'] or
        env.get('CODEX_THREAD_ID') != node['thread'] or env.get('CICADA_NODE_PQTLS_CONFIG') != node['tls_config']):
        raise RuntimeError('G2_ORIGINAL_CONFIG_CALLER')
    argv = ['exec','-i','--workdir','/workspace']
    for key, value in env.items(): argv += ['-e',key+'='+value]
    argv += [node['container'],settings['command'],*settings['args']]
    messages = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18'}},
        {'jsonrpc':'2.0','method':'notifications/initialized','params':{}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':tool,'arguments':arguments}}]
    raw = self.docker(*argv, input_data=('\n'.join(json.dumps(message) for message in messages)+'\n').encode())
    if len(raw) > 1 << 20: raise RuntimeError('G2_MCP_BOUNDED_RESPONSE')
    replies = [json.loads(line) for line in raw.splitlines() if line.strip()]
    initialized = [reply for reply in replies if reply.get('id') == 1]
    selected = [reply for reply in replies if reply.get('id') == 2]
    if len(initialized) != 1 or 'error' in initialized[0] or len(selected) != 1 or 'error' in selected[0]:
        raise RuntimeError('G2_MCP_PROTOCOL_FAILURE_NOT_DENIAL')
    result = selected[0].get('result')
    if type(result) is not dict: raise RuntimeError('G2_MCP_TOOL_RESULT')
    payload = result.get('structuredContent')
    if type(payload) is not dict:
        texts = [block.get('text') for block in result.get('content',[]) if block.get('type') == 'text']
        if len(texts) != 1 or type(texts[0]) is not str: raise RuntimeError('G2_MCP_STRUCTURED_RESPONSE')
        try: payload = json.loads(texts[0])
        except ValueError: payload = {'error':texts[0]}
    if type(payload) is not dict: raise RuntimeError('G2_MCP_OBJECT_RESPONSE')
    return result.get('isError') is True, payload


def g2_guard_denial(is_error, payload):
    """Only closed known authorization denial, never timeout/protocol/empty data."""
    text = payload.get('error')
    # A revoked Link is rejected by the Node's authorization lookup before the
    # Relay ASK is submitted. Preserve that privacy-preserving 404 only when
    # the typed MCP result also says the operation failed without retrying.
    if (text == 'Node Relay request failed with HTTP 404' and not is_error and
        payload.get('status') == 'FAILED' and payload.get('retryable') is False):
        return True
    known = ('communication link not found or not authorized', 'communication link is revoked',
             'communication link authorization is not current')
    if type(text) is str and any(reason in text.lower() for reason in known):
        if is_error or (payload.get('status') == 'FAILED' and payload.get('retryable') is False):
            return True
    return False


def g2_current_actor(self, letter):
    bad, card = self.g2_mcp_call(letter, 'cicada_whoami', {})
    group = self.meta['alice_second_group_id'] if letter == 'a' else self.meta['bob_group_id']
    node = self.nodes[letter]
    expected = node['binding_before']
    if (bad or card.get('group_id') != group or card.get('endpoint_id') != node['endpoint'] or card.get('native_session_id') != node['thread'] or
        card.get('node_id') != node['node_id'] or card.get('binding_id') != expected['id'] or card.get('binding_epoch') != expected['epoch']):
        raise RuntimeError('G2_CURRENT_ACTOR_SCOPE')
    return {key:card.get(key) for key in ('endpoint_id','principal_id','network_id','group_id','membership_id','membership_revision','binding_id','binding_epoch')}


def g2_revoke_and_visibility(self):
    self.step('g2_actual_hidden_members_and_revoked_link_denial')
    before = set(self.budget.started)
    before_actor = self.current_actor('a')
    bad, members = self.g2_mcp_call('a', 'cicada_members', {})
    rows = members.get('endpoints')
    if bad or type(rows) is not list or not any(row.get('endpoint_id') == self.nodes['a']['endpoint'] for row in rows):
        raise RuntimeError('G2_MEMBERS_QUERY_FAILED')
    if any(row.get('endpoint_id') == self.nodes['b']['endpoint'] or row.get('group_id') == self.meta['bob_group_id'] for row in rows):
        raise RuntimeError('G2_HIDDEN_FOREIGN_MEMBER_VISIBLE')
    bad, hidden = self.g2_mcp_call('a','cicada_find',{'query':self.nodes['b']['endpoint']})
    if not bad or type(hidden.get('error')) is not str or 'not found or not authorized' not in hidden['error'].lower():
        raise RuntimeError('G2_HIDDEN_ENDPOINT_CALLER_DENIAL_NOT_PROVEN')
    # Stop only this owned Hub while the original Nodes and MCP callers remain alive.
    owned_hub = self.inspect('container', self.hub)
    if owned_hub['Image'] != self.hub_image or (owned_hub['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id:
        raise RuntimeError('G2_REVOKE_HUB_OWNERSHIP')
    self.docker('stop', '--time', '1', owned_hub['Id'])
    raw = self.helper('g2-revoke')
    proof = json.loads(raw)
    if proof != {'status':'G2_LINK_REVOKED_CALLER_DENIAL_NOT_YET_TESTED'}:
        raise RuntimeError('G2_REVOKE_AUTHORITY_NOT_CONFIRMED')
    self.start_hub()
    self.refresh_hub_forwarders('g2-after-link-revocation')
    bad, denied = self.g2_mcp_call('a','cicada_ask',{'link_id':self.g2_link_id,'data_scope':'thread.message','question':'SYNTHETIC-REVOKED-LINK-DENIAL-NO-DELIVERY'})
    if not g2_guard_denial(bad, denied):
        raise RuntimeError('G2_REVOKED_CALLER_AUTHORIZATION_DENIAL_NOT_PROVEN')
    after_actor = self.current_actor('a')
    if after_actor != before_actor: raise RuntimeError('G2_POST_REVOKE_ORIGINAL_CALLER_CHANGED')
    if set(self.budget.started) != before:
        raise RuntimeError('G2_POST_REVOKE_CREATED_NATIVE_TURN')
    self.result['g2_post_revoke'] = {'actual_original_caller_mcp':True,'authorization_denied':True,
        'hidden_foreign_members':True,'hidden_endpoint_find_denied':True,
        'same_original_caller_binding_before_after':True,'native_turns_added':0,'delivery_scope':'NO_SUCCESSFUL_ACCEPTANCE_OBSERVED'}


def g3_readiness_argv(self, hub_id):
    if hub_id != self.result['g3_hub_replacement']['new_id']:
        raise RuntimeError('G3_READINESS_EXACT_HUB')
    return ['docker','run','--rm','--pull=never','--name',self.run_id+'-helper-g3-ready',
        '--label','org.cicada.test.run='+self.run_id,'--network','container:'+hub_id,
        '--user','1000:1000','-v',str(self.root)+':/fixture:ro',
        '-v',str(self.native_package)+':/opt/cicada-pqtls:ro',
        '-e','LD_LIBRARY_PATH=/opt/cicada-pqtls/lib','-e','OPENSSL_CONF=/dev/null',
        '--entrypoint','/fixture/cicada-v68fixture',self.test_image,'probe','--address','127.0.0.1:8787']


def g3_restore_snapshot(self):
    """Only stopped exact-owned peers; full Control uses the same SQLite/state mount."""
    self.step('g3_restored_control_authenticated_encrypted_snapshot')
    for node in self.nodes.values():
        record = self.inspect('container', node['container'])
        if record['State']['Running'] or record['Image'] != self.args.runtime_image or (record['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id:
            raise RuntimeError('G3_PEERS_NOT_OWNED_STOPPED')
    old = self.inspect('container', self.hub)
    if old['State']['Running'] or old['Image'] != self.hub_image or (old['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id:
        raise RuntimeError('G3_OLD_HUB_NOT_OWNED_STOPPED')
    old_id = old['Id']
    self.docker('rm',old_id)
    absent = self.command(['docker','container','inspect',old_id],timeout=3,allow_failure=True)
    valid_errors = ('Error: No such object: '+old_id, 'error: no such object: '+old_id,
        'Error response from daemon: No such container: '+old_id)
    if absent.returncode != 1 or absent.stdout.strip() != b'[]' or absent.stderr.decode().strip() not in valid_errors:
        raise RuntimeError('G3_OLD_HUB_ABSENCE_NOT_PROVEN')
    name = self.run_id+'-hub-control'
    self.docker('run','-d','--pull=never','--name',name,'--label','org.cicada.test.run='+self.run_id,
        '--user','1000:1000','--network','bridge','--env-file',str(self.root/'hub.env'),
        '-e','CICADA_STATE_DIR=/state','-v',str(self.root/'hub-state')+':/state',
        self.hub_image,'serve','--host','0.0.0.0','--port','8787')
    self.hub = name
    current = self.inspect('container',name)
    if current['Image'] != self.hub_image or (current['Config'].get('Labels') or {}).get('org.cicada.test.run') != self.run_id:
        raise RuntimeError('G3_NEW_HUB_OWNERSHIP')
    new_id = current['Id']
    self.result['g3_hub_replacement'] = {'old_id':old_id,'old_absence_confirmed':True,'new_id':new_id,
        'same_state_dir':True,'database_relative_path':'cicada.sqlite3','peer_nodes_stopped':True}
    # Readiness is not acceptance: one bounded own-container loopback health probe.
    self._g3_helper_hub_id = new_id
    try:
        end = time.monotonic()+self.limit(5)
        while time.monotonic() < end:
            ready = json.loads(self.command(g3_readiness_argv(self,new_id),timeout=min(2,end-time.monotonic())))
            if ready == {'tcp_reachable':True}: break
            if ready != {'tcp_reachable':False}: raise RuntimeError('G3_READINESS_PROBE_SHAPE')
            time.sleep(min(.05,max(0,end-time.monotonic())))
        else: raise RuntimeError('G3_CONTROL_TCP_NOT_READY')
    finally:
        self._g3_helper_hub_id = None
    raw = self.helper('control-snapshot')
    if json.loads(raw) != {'status':'G3_AUTHENTICATED_ENCRYPTED_STATUS_SNAPSHOT_MATCHED'}:
        raise RuntimeError('G3_ENCRYPTED_STATUS_NOT_MATCHED')
    self.result['g3_management'] = {'status':'AUTHENTICATED_ENCRYPTED_STATUS_SNAPSHOT_MATCHED',
        'typed_owner_group_membership_endpoint_node':True,'not_capabilities_only':True,
        'peer_business_calls':'NOT_INSTRUMENTED','same_owned_store':True}


def g2_cap_methods(legacy_cls):
    """Local exact six-turn selectors; frozen/default five-turn methods stay intact."""
    def selected(method, old, new):
        # These methods originate in the pinned public files; use their exact AST.
        import inspect, textwrap
        text = inspect.getsource(method)
        text = textwrap.dedent(text)
        if text.count(old) != 1:
            # Preserve the installed public ownership wrapper byte-for-byte;
            # replace only its closed-over original cleanup with the local cap.
            cells=dict(zip(method.__code__.co_freevars,method.__closure__ or ()))
            if method.__name__ != 'cleanup' or text.count(old) != 0 or 'original_cleanup' not in cells:
                raise ValueError('G2_CAP_EXACT_CONTEXT')
            inner=selected(cells['original_cleanup'].cell_contents,old,new)
            def cell(value): return (lambda:value).__closure__[0]
            closure=tuple(cell(inner) if name=='original_cleanup' else cells[name] for name in method.__code__.co_freevars)
            wrapped=types.FunctionType(method.__code__,dict(method.__globals__),method.__name__,method.__defaults__,closure)
            wrapped._g2_cap_source=inner._g2_cap_source
            return wrapped
        ns = method_namespace(method)
        exec(compile(text.replace(old,new,1),'<owned-g2-six-cap>','exec'),ns)
        selected_method=ns[method.__name__]
        selected_method._g2_cap_source=text.replace(old,new,1)
        return selected_method
    observed=selected(legacy_cls.observe,'len(self.budget.started) > 5','len(self.budget.started) > 6')
    cleanup=selected(legacy_cls.cleanup,'len(self.budget.started)>5','len(self.budget.started)>6')
    reconciled=selected(legacy_cls.reconcile_actual_history,"(3 if letter == 'a' else 2)","(4 if letter == 'a' else 2)")
    return {'observe':observed,'cleanup':cleanup,'reconcile_actual_history':reconciled}


def g2_turn_budget(default):
    import inspect
    text=inspect.getsource(type(default))
    for old,new in (('maximum=5','maximum=6'),('maximum != 5','maximum != 6'),('len(self.started) > 5','len(self.started) > 6')):
        if text.count(old)!=1: raise ValueError('G2_BUDGET_EXACT_CONTEXT')
        text=text.replace(old,new,1)
    ns=dict(type(default).observe.__globals__)
    exec(compile(text,'<owned-g2-six-budget>','exec'),ns)
    return ns['TurnBudget']()


def load_gate(delivery, binding, *, inspect_only=False, zero_model=False, scenario="g1",
              normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    """Inspection imports public helpers only; execution requires future GO."""
    if scenario not in ("g1", "g2-g3"):
        raise ValueError("SCENARIO_UNSUPPORTED")
    if (type(normal_seconds) is not int or normal_seconds < DEFAULT_NATIVE_NORMAL_SECONDS or
            normal_seconds > MAX_NATIVE_NORMAL_SECONDS):
        raise ValueError("NATIVE_NORMAL_SECONDS")
    loaded = {}
    for name in ("migration", "managed_gate"):
        if name in sys.modules:
            module = sys.modules[name]
            if Path(getattr(module,"__file__","")).resolve() != (LEGACY/(name+".py")).resolve():
                raise RuntimeError("CANDIDATE_IMPORT_ORIGIN_CONFLICT")
            loaded[name] = module
    migration = loaded.get("migration") or safe_module("migration", LEGACY / "migration.py")
    # Historical ROOT remains readonly for its historical stability check only.
    migration.configure(dict(delivery, root=binding["output_parent"]))
    wrapper = loaded.get("managed_gate") or safe_module("managed_gate", LEGACY / "managed_gate.py")
    legacy_cls, original_namespace = wrapper.ManagedGate, wrapper.module.__dict__
    if Path(original_namespace["HERE"]).resolve() != OLD.resolve():
        raise RuntimeError("LEGACY_GLOBAL_ORIGIN")
    rpc_module = sys.modules.get("native_protocol")
    rpc_drain_sha = install_native_rpc_shutdown_drain(rpc_module, binding)
    sources = effective_sources(normal_seconds)
    fresh_witness, fresh_witness_sha = selected_fresh_witness(legacy_cls.pq_transport_witness)
    two_pass_refresh, two_pass_refresh_sha = selected_two_pass_refresh(legacy_cls.refresh_hub_forwarders)
    namespace = dict(original_namespace)
    namespace.update(_observer_capture_native_failure=capture_native_failure,
        _observer_register_capture_command=register_capture_command,
        _observer_capture_deadline=capture_deadline,
        _observer_capture_program_pins=capture_program_pins(sources["gate"]))
    namespace["_g1_inline_reply_witness"] = g1_inline_reply_witness
    methods = compile_methods(sources["gate"], namespace)
    if scenario == "g2-g3":
        namespace.update(_g2_node_scope=g2_node_scope,_g2_tools=G2_TOOLS,
            _g2_turn_witness=g2_turn_witness,_g2_inline_reply_witness=g2_inline_reply_witness,
            _g2_accepted_ask=g2_accepted_ask,_g2_accepted_reply=g2_accepted_reply,
            _g2_a2_instruction=A2_SUBMISSION_INSTRUCTION)
        scenario_methods=compile_g2_preparation_methods(sources["gate"],namespace)
        scenario_methods.update(compile_g2_flow_methods(sources["gate"],namespace))
    else:
        scenario_methods=compile_g1_inline_reply_method(sources["gate"],namespace)
    provider_globals = legacy_cls.provider_forwarder.__globals__
    original_forwarder = provider_globals.get("Forwarder")
    provider_module_name = getattr(original_forwarder, "__module__", None)
    provider_module = sys.modules.get(provider_module_name)
    if (provider_module is None or
            Path(getattr(provider_module, "__file__", "")).resolve() != OLD / "provider_transport.py"):
        raise ValueError("IMPORTED_PROVIDER_GLOBAL_ORIGIN")
    provider_namespace = provider_module.__dict__
    transport_source = provider_transport_source(normal_seconds)
    exec(compile(transport_source, "<effective-request-observer-provider-transport>", "exec"),
         provider_namespace)
    provider_namespace["_install_client_read_cancellation"]=lambda owner, adapter: install_client_read_cancellation(adapter, binding["client_read_cancellation"]["diagnostic_relay_sha256" if getattr(owner.args,"test_request_observer",False) is True else "relay_sha256"], io_diagnostics_v2=getattr(owner.args,"test_request_observer",False) is True)
    original_relay_installer = provider_namespace['_install_client_read_cancellation']
    def owned_relay_installer(owner, adapter):
        returned = original_relay_installer(owner, adapter)
        install_provider_lifecycle(owner, adapter)
        return returned
    provider_namespace['_install_client_read_cancellation'] = owned_relay_installer
    exec(compile(sources["provider"], "<effective-request-observer-provider>", "exec"), provider_namespace)
    audit_namespace=method_namespace(legacy_cls.audit_rpc)
    audit_namespace["_observer_mark_native_failure"]=mark_native_failure
    exec(compile(sources["audit"],"<effective-request-observer-audit>","exec"),audit_namespace)
    command_namespace=method_namespace(legacy_cls.command)
    command_namespace.update(_observer_capture_command_allowed=capture_command_allowed,
                             _observer_thread_identity=threading.get_ident,
                             _observer_wait_native_cleanup=wait_native_capture_before_owned_cleanup)
    exec(compile(sources["command"],"<effective-request-observer-command>","exec"),command_namespace)
    if scenario == 'g2-g3':
        legacy_cls = type('OwnedG2SixGate',(legacy_cls,),g2_cap_methods(legacy_cls))
        inherited_wait_turn = legacy_cls.wait_turn
        inherited_automatic_turn = legacy_cls.automatic_turn
        def wait_turn(self, letter, turn_id, timeout=None):
            return inherited_wait_turn(self, letter, turn_id,
                normal_seconds if timeout is None else timeout)
        def automatic_turn(self, letter, prior_ids, timeout=None):
            return inherited_automatic_turn(self, letter, prior_ids,
                normal_seconds if timeout is None else timeout)
        legacy_cls = type('OwnedG2BudgetGate',(legacy_cls,),
            {'wait_turn':wait_turn,'automatic_turn':automatic_turn})
        old = "self.result['actual_turn_started_event_count'] > 5"
        audit_source = sources['audit']
        if audit_source.count(old) != 1: raise ValueError('G2_AUDIT_CAP_CONTEXT')
        exec(compile(audit_source.replace(old,"self.result['actual_turn_started_event_count'] > 6",1),'<owned-g2-six-audit>','exec'),audit_namespace)
    else:
        # Peer adapters pass None explicitly when their caller omits timeout.
        # Preserve the inherited method's own default (currently 180), rather
        # than passing None into migration's numeric absolute-deadline limit.
        inherited_wait_turn = legacy_cls.wait_turn
        inherited_automatic_turn = legacy_cls.automatic_turn
        def wait_turn(self, letter, turn_id, timeout=None):
            if timeout is None:
                return inherited_wait_turn(self, letter, turn_id)
            return inherited_wait_turn(self, letter, turn_id, timeout)
        def automatic_turn(self, letter, prior_ids, timeout=None):
            if timeout is None:
                return inherited_automatic_turn(self, letter, prior_ids)
            return inherited_automatic_turn(self, letter, prior_ids, timeout)
        legacy_cls = type('OwnedG1TimeoutABIGate',(legacy_cls,),
            {'wait_turn':wait_turn,'automatic_turn':automatic_turn})
    class CandidateGate(legacy_cls):
        def __init__(self, args):
            if inspect_only:
                raise RuntimeError("INSPECTION_FORBIDS_FIXTURE_CONSTRUCTOR")
            native_mode = validate_native_https(args,scenario,zero_model)
            if getattr(args,"native_normal_seconds",DEFAULT_NATIVE_NORMAL_SECONDS) != normal_seconds:
                raise PermissionError("NATIVE_NORMAL_SECONDS_BINDING")
            response_mode = validate_response_mode(args,scenario,zero_model)
            super().__init__(args)
            self.result["response_transport"] = {"response_byte_passthrough":response_mode,
                "response_framing_validation":"NOT_PERFORMED" if response_mode else "OBSERVER_STRICT",
                "application_completion":"UNKNOWN" if response_mode else "NATIVE_ORACLE_AUTHORITATIVE",
                "byte_ceiling":4259840 if response_mode else None, "chunk_ceiling":65536 if response_mode else None,
                "native_acceptance":"UNCHANGED"}
            if native_mode:
                self.result["response_transport"].update(response_framing_validation="NATIVE_HTTP_STACK",
                    application_completion="NATIVE_ORACLE_AUTHORITATIVE")
                self.result["native_https"]={"enabled":True,"HTTP_POST_COUNT":"UNAVAILABLE",
                    "POST16_ENFORCEMENT":"UNAVAILABLE","accepted_TCP_connection_cap":16,
                    "connection_scope":"ADMITTED_SOCKETS_NOT_HTTP_POSTS_OR_COMPLETED_CONNECTS",
                    "observer_request_ALPHA":"UNAVAILABLE","observer_body_digests":"UNAVAILABLE",
                    "observer_IO":"UNAVAILABLE","native_acceptance":"UNCHANGED"}
            if scenario == 'g2-g3':
                self.budget = g2_turn_budget(self.budget)
                self.result['owned_g2_manual_turn_sha256'] = self.owned_g2_manual_turn_sha256
                self.result['native_turn_budget'] = 6
                self.result['maximum_actual_turn_started'] = 0 if zero_model else 6
            self._observer_capture_lifecycle_lock = threading.Lock()
            self._observer_native_capture_state = None
            self._observer_capture_cutoff = False
            self._observer_tls_helper_active = False
            self.pq_transport_witness = types.MethodType(fresh_witness, self)
            self.result["owned_pre_stop_fresh_witness_sha256"] = fresh_witness_sha
            self.refresh_hub_forwarders = types.MethodType(two_pass_refresh, self)
            self.result["owned_two_pass_refresh_sha256"] = two_pass_refresh_sha
            bind_policy(self.policy, args.artifact_started, normal_seconds)
            if getattr(args,"closed_failure_diagnostics",False) is True:
                install_closed_failure_diagnostics(self)
                try:
                    import inspect
                    abort_tree = ast.parse(sources['gate'])
                    abort_node = next(node for node in ast.walk(abort_tree) if isinstance(node, ast.FunctionDef) and node.name == 'abort_owned')
                    cleanup_method = legacy_cls.cleanup
                    cleanup_text = getattr(cleanup_method, '_g2_cap_source', None) or inspect.getsource(cleanup_method)
                    install_lifecycle(self, ast.get_source_segment(sources['gate'], abort_node), cleanup_text, original_cleanup=cleanup_method)
                except BaseException:
                    try: self.result['closed_lifecycle_installation'] = 'NOT_INSTALLED'
                    except BaseException: pass
            self.result["historical_effective_owned_wrapper_sha256_dependency_only"] = self.result.pop("effective_owned_wrapper_sha256", {})
            self.result["effective_owned_wrapper_sha256"] = {name:row["sha256"] for name,row in binding["candidate_files"].items()}
            self.result["effective_candidate_source_sha256"] = {
                name:hashlib.sha256(value.encode()).hexdigest() for name,value in sources.items()}
            self.result["candidate_binding_sha256"] = args.candidate_binding_sha256
            self.result["owned_native_rpc_shutdown_drain_sha256"] = rpc_drain_sha
            self.result["native_budget_seconds"] = {"normal_seconds":normal_seconds,
                "terminal_seconds":NATIVE_TERMINAL_SECONDS,"cleanup_seconds":NATIVE_CLEANUP_SECONDS,
                "total_seconds":normal_seconds+NATIVE_TERMINAL_SECONDS+NATIVE_CLEANUP_SECONDS}
            self.result["shared_absolute_phase_seconds"] = {"normal":normal_seconds,
                "terminal":normal_seconds+NATIVE_TERMINAL_SECONDS,
                "cleanup":normal_seconds+NATIVE_TERMINAL_SECONDS+NATIVE_CLEANUP_SECONDS}
            self.result["observer_same_kernel_CLOCK_MONOTONIC"] = "REQUIRED_NOT_RUNTIME_VERIFIED"
            self.result.setdefault("matching_preparation_scope", {}).update(dispatch_only_wrapper_delta=False,
                reuse_scope="UNCHANGED_PRODUCT_BASELINE_ONLY",
                changed_observer_bootstrap_overlay_Runtime_preparation="NOT_RUN")
        def native_config(self, letter, thread=None, tools=()):
            values = super().native_config(letter, thread, tools)
            if scenario == "g1":
                if (not zero_model and getattr(self.args, 'run_native', False) is True and
                        getattr(self.args, 'native_https', False) is True and
                        getattr(self.args, 'closed_failure_diagnostics', False) is True):
                    install_owned_peer_response_metadata(self)
                return values
            old = "CICADA_GROUP_ID=" + json.dumps(self.meta["group_id"])
            new = "CICADA_GROUP_ID=" + json.dumps(self.nodes[letter].get("current_group_id",g2_node_scope(self.meta, letter)[1]))
            hits = sum(value.count(old) for value in values if type(value) is str)
            if hits != 1:
                raise RuntimeError("G2_NATIVE_CONFIG_CONTEXT")
            return [value.replace(old, new, 1) if type(value) is str else value for value in values]

        def build(self):
            if not zero_model and not getattr(self.args,"latest_runtime",False):
                return super().build()
            self.step("verify_current_product_latest_runtime")
            self.result["acceptance_mode"]="current-input-equal-product-"+self.args.expected_codex_version
            self.result["actual_product_source_dirty"]=delivery.get("source_dirty")
            self.native_package = Path(delivery["package"])
            self.hub_image = delivery["hub_image"]
            self.test_image = self.args.runtime_image
            for path, expected in ((self.native_package/"bin/cicada", delivery["binary_sha256"]),
                                   (Path(delivery["helper"]), delivery["helper_sha256"])):
                if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise RuntimeError("ZERO_DELIVERY_BINARY_CHANGED")
            for image in (self.hub_image,self.test_image):
                if self.inspect("image",image)["Id"]!=image:
                    raise RuntimeError("ZERO_IMMUTABLE_IMAGE_CHANGED")
            import shutil
            helper=self.root/"cicada-v68fixture"
            shutil.copyfile(delivery["helper"],helper); helper.chmod(0o700)
            self.result.update(cicada_binary_sha256=delivery["binary_sha256"],
                fixture_binary_sha256=delivery["helper_sha256"],hub_image_id=self.hub_image,
                runtime_image_id=self.test_image,source_unchanged_during_gate=True,
                product_sha256=delivery["binary_sha256"],helper_sha256=delivery["helper_sha256"],
                product_revision=delivery["commit"],node_code_fingerprint=delivery["fingerprint"],
                product_source_fingerprint=delivery["fingerprint"],current_delivery_sha256=self.args.delivery_sha,
                producer_metadata_sha256=delivery["package_metadata_sha256"],
                maximum_actual_turn_started=0 if zero_model else (6 if scenario == "g2-g3" else 5),
                source_domain_comparison={"Node":"current compiled-input equality bound package",
                    "Hub":"current compiled-input equality bound image","Runtime":self.args.expected_codex_version+" owned image"})
            if scenario == "g2-g3":
                self.result["fixture_scenario"] = scenario
                self.result["preparation_binding"].update(fixture_scenario=scenario,component_proof_sha256=delivery["component_proof_sha256"])
            self.result["preparation_binding"].update(runtime_image_id=self.test_image,
                official_cli_sha256=self.args.expected_cli_sha256,expected_codex_version=self.args.expected_codex_version,
                product_revision=delivery["commit"],node_code_checkpoint=delivery["commit"],
                product_sha256=delivery["binary_sha256"],helper_sha256=delivery["helper_sha256"],
                hub_image=self.hub_image,producer_fingerprint=delivery["fingerprint"],
                source_fingerprint=delivery["fingerprint"],node_source_fingerprint=delivery["fingerprint"],
                delivery_receipt_sha256=delivery["package_metadata_sha256"],
                producer_metadata_sha256=delivery["package_metadata_sha256"],
                maximum_actual_turn_started=0 if zero_model else (6 if scenario == "g2-g3" else 5),current_delivery_sha256=self.args.delivery_sha,
                compiled_input_equality_sha256=self.args.equality_sha)
        def register_submission(self, argv):
            if scenario == "g2-g3" and argv[:2] in (["docker","run"],["docker","create"]) and "--name" in argv and argv[argv.index("--name")+1] == self.run_id+"-helper-g3-ready":
                if zero_model or not getattr(self,"_g3_helper_hub_id",None) or argv != g3_readiness_argv(self,self._g3_helper_hub_id):
                    raise RuntimeError("G3_READINESS_SUBMISSION_SCOPE")
                name=self.run_id+"-helper-g3-ready"
                key=("container",name)
                self.submitted_objects[key]={"name":name,"id":None,"image":self.test_image,"run_id":self.run_id,"auto_remove":True,"command_exit":None}
                self.containers[name]=self.test_image
                return key
            if (zero_model or getattr(self.args,"latest_runtime",False)) and argv[:2] in (["docker","run"],["docker","create"]) and self.args.runtime_image in argv:
                if argv.count(self.args.runtime_image)!=1 or "--name" not in argv or "org.cicada.test.run="+self.run_id not in argv:
                    raise RuntimeError("ZERO_RUNTIME_OWNERSHIP")
                name=argv[argv.index("--name")+1]
                if name not in (self.run_id+"-a",self.run_id+"-b"):
                    actions=(("bootstrap","tls-bootstrap","g2-authorize-second") if scenario == "g2-g3" else ("bootstrap","tls-bootstrap")) if zero_model else (("bootstrap","tls-bootstrap","g2-authorize-second","approve","g2-revoke","control-snapshot") if scenario == "g2-g3" else ("bootstrap","tls-bootstrap","approve"))
                    action=next((x for x in actions if name==self.run_id+"-helper-"+x),None)
                    isolation=next((x for x in "ab" if name==self.run_id+"-helper-isolation-"+x),None)
                    if isolation is not None:
                        action="probe"
                    image_index=argv.index(self.args.runtime_image)
                    def exact_option(flag,value):
                        return argv.count(flag)==1 and argv.index(flag)+1<len(argv) and argv[argv.index(flag)+1]==value
                    if (action is None or argv[:2]!=["docker","run"] or "--rm" not in argv
                        or "--pull=never" not in argv or not exact_option("--label","org.cicada.test.run="+self.run_id)
                        or not exact_option("--network","container:"+self.hub if isolation is not None else "container:"+self._g3_helper_hub_id if action == "control-snapshot" and getattr(self,"_g3_helper_hub_id",None) else "none")
                        or not exact_option("--entrypoint","/fixture/cicada-v68fixture")
                        or image_index+1>=len(argv) or argv[image_index+1]!=action):
                        raise RuntimeError("ZERO_RUNTIME_NAME")
                if zero_model:
                    validate_zero_command(argv)
                key=("container",name)
                self.submitted_objects[key]={"name":name,"id":None,"image":self.args.runtime_image,
                    "run_id":self.run_id,"auto_remove":"--rm" in argv,"command_exit":None}
                self.containers[name]=self.args.runtime_image
                return key
            return super().register_submission(argv)
        def helper(self, action, *arguments):
            if zero_model and action == "tls-bootstrap":
                if self._observer_tls_helper_active:
                    raise RuntimeError("TLS_HELPER_OVERLAP")
                self._observer_tls_helper_active = True
                try:
                    return super().helper(action, *arguments)
                finally:
                    self._observer_tls_helper_active = False
            if scenario != "g2-g3" or action != "control-snapshot":
                return super().helper(action, *arguments)
            if zero_model or arguments or not self.result.get("g3_hub_replacement"):
                raise RuntimeError("G3_HELPER_SCOPE")
            record = self.inspect("container",self.hub)
            if record["Id"] != self.result["g3_hub_replacement"]["new_id"] or record["Image"] != self.hub_image or (record["Config"].get("Labels") or {}).get("org.cicada.test.run") != self.run_id:
                raise RuntimeError("G3_HELPER_HUB_IDENTITY")
            self._g3_helper_hub_id = record["Id"]
            argv = ["docker","run","--rm","--pull=never","--name",self.run_id+"-helper-control-snapshot",
                "--label","org.cicada.test.run="+self.run_id,"--network","container:"+record["Id"],
                "--user","1000:1000","-v",str(self.root)+":/fixture","-v",str(self.native_package)+":/opt/cicada-pqtls:ro",
                "-e","LD_LIBRARY_PATH=/opt/cicada-pqtls/lib","-e","OPENSSL_CONF=/dev/null",
                "--entrypoint","/fixture/cicada-v68fixture",self.test_image,"control-snapshot",
                "--db","/fixture/hub-state/cicada.sqlite3","--fixture","/fixture"]
            try: return self.command(argv,timeout=5)
            finally: self._g3_helper_hub_id = None
        runtime_bootstrap_argv = staticmethod(runtime_bootstrap_argv)
        def docker(self, *arguments, **kwargs):
            argv = list(map(str, arguments))
            if zero_model:
                if argv[:2]==["exec","-d"] and "python3" in argv and "-c" in argv:
                    original_agent=self.start_services.__globals__["AGENT_BOOTSTRAP"]
                    for letter,node in self.nodes.items():
                        prefix=["exec","-d","-e","CICADA_CODEX_BIN="+self.start_services.__globals__["CODEX"],
                            "-e","CODEX_HOME=/codex","-e","CICADA_HUB_ID="+self.meta["hub_id"],
                            "-e","CICADA_NODE_PQTLS_CONFIG="+node["tls_config"],
                            "-e","CICADA_NODE_STATE_DIR=/fixture/node-"+letter+"-state",
                            "-e","CICADA_PQTLS_DIAGNOSTIC_FILE=/state/tls-diag/agent.jsonl",
                            node["container"],"python3","-c"]
                        if (argv[:len(prefix)]==prefix and len(argv)==len(prefix)+5
                            and argv[len(prefix)]==original_agent and argv[-2:]==["sh",node["node_id"]]
                            and argv[len(prefix)+1]=="-c"):
                            argv[len(prefix)]=ZERO_AGENT_BOOTSTRAP
                            self.result.setdefault("zero_agent_bootstrap",{})[letter]={
                                "credential_access":False,"effective_program_sha256":hashlib.sha256(ZERO_AGENT_BOOTSTRAP.encode()).hexdigest()}
                            break
                validate_zero_command(["docker"]+argv)
            if (len(argv) >= 7 and argv[:2] == ["exec", "-d"] and argv[3:6] == ["python3", "/state/server_bootstrap.py", "paid"] and
                    getattr(self.args,"test_request_observer",False) is True):
                container = argv[2]
                for filename in ("request_observer_bootstrap.py", "request-observer-integration.patch", "native_request_observer_io.py"):
                    payload_path = (LEGACY/filename if filename.endswith(".patch") else SCRIPTS/filename if filename.startswith("native_") else HERE/filename)
                    row = binding["public_files"][str(payload_path)]
                    payload = payload_path.read_bytes()
                    if hashlib.sha256(payload).hexdigest() != row["sha256"]:
                        raise RuntimeError("CANDIDATE_RUNTIME_PAYLOAD_CHANGED")
                    upload = "import os,sys; p=sys.argv[1]; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); s=os.fdopen(f,'wb'); s.write(sys.stdin.buffer.read()); s.close()"
                    self.command(["docker","exec","-i",container,"python3","-c",upload,"/tmp/"+filename], input_data=payload, timeout=3)
                argv = self.runtime_bootstrap_argv(argv,binding,self.policy.started, response_byte_passthrough=getattr(self.args,"response_byte_passthrough",False))
                self.result.setdefault("effective_Runtime_bootstrap", {})[container] = {
                    "copied_payload_sha256":binding["candidate_files"]["request_observer_bootstrap.py"]["sha256"],
                    "effective_source_sha256":binding["effective_sources"]["bootstrap"],
                    "observer_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer.py")]["sha256"],
                    "normal_end_MONOTONIC":self.policy.normal_end}
            if (argv and argv[0] == "stop" and not self.cleaning and
                    self.phase != "g3_restored_control_authenticated_encrypted_snapshot"):
                target = argv[-1]
                known_id = self.result.get("hub_forwarder_refresh", [{}])[0].get("owned_hub_container_id")
                if target in (getattr(self,"hub",None), known_id):
                    anchor_owned_restart(self, target)
            return super().docker(*argv, **kwargs)
        def cleanup(self):
            # No abort lock spans inherited cleanup, reader waits or persistence.
            # Unknown is truthful when no native capture was available at entry;
            # an admitted capture may replace it before its owned stop boundary.
            if getattr(self.args,"test_request_observer",False):
                self.result.setdefault("test_request_observer",{
                    "capture_status":"UNKNOWN","per_Runtime":{},"native_acceptance":"UNCHANGED",
                    "cleanup_capture_reason":"NO_NATIVE_CAPTURE_AT_CLEANUP_ENTRY"})
            try:
                from request_observer_run import verify_binding
                verify_binding(self.args.candidate_binding_sha256,
                    getattr(self.args,"binding_file",None))
            except Exception:
                self.result["candidate_sources_unchanged"] = False
                self.result["status"] = "FAIL"
            else:
                self.result["candidate_sources_unchanged"] = True
            selected_cleanup = getattr(self, "_closed_lifecycle_cleanup", None)
            return selected_cleanup() if selected_cleanup is not None else super().cleanup()
    for name, function in methods.items():
        setattr(CandidateGate, name, function)
    for name, function in scenario_methods.items():
        setattr(CandidateGate, name, function)
    if scenario == "g2-g3":
        CandidateGate.manual_turn, CandidateGate.owned_g2_manual_turn_sha256 = selected_g2_manual_turn(legacy_cls.manual_turn)
        CandidateGate.g2_initial_binding = g2_initial_binding
        CandidateGate.g2_second_binding = g2_second_binding
        CandidateGate.g2_b_continuity = g2_b_continuity
        CandidateGate.g2_mcp_call = g2_mcp_call
        CandidateGate.current_actor = g2_current_actor
        CandidateGate.g2_revoke_and_visibility = g2_revoke_and_visibility
        CandidateGate.g3_restore_snapshot = g3_restore_snapshot
    CandidateGate.provider_forwarder = provider_namespace["provider"]
    CandidateGate.audit_rpc = audit_namespace["audit"]
    original_command=command_namespace["command"]
    def guarded_command(self, argv, **kwargs):
        if zero_model:
            validate_zero_command(argv)
        selected_argv = argv
        selected_stage = None
        if zero_model and getattr(self, "_observer_tls_helper_active", False):
            selected_argv, selected_stage = approved_tls_helper_argv(argv, binding,
                run_id=self.run_id, fixture_root=self.root, native_package=self.native_package,
                image=self.test_image)
        result = original_command(self, selected_argv, **kwargs)
        if selected_stage is not None:
            self.result["approved_tls_helper_stage"] = {
                "three_public_binding_pins_verified": True,
                "mount_readonly": True,
                "helper_family": "EXACT_OWNED_TLS_BOOTSTRAP_ONLY"}
        return result
    CandidateGate.command = guarded_command
    original_audit=CandidateGate.audit_rpc
    def zero_audit(self, letter, direction, message, raw=None):
        if zero_model and direction=="received" and type(message) is dict and message.get("method")=="turn/started":
            self.result["actual_turn_started_event_count"]+=1
            self.result["unexpected_zero_turn_started_observed"]=True
        if zero_model and type(message) is dict and message.get("method") in {
                "turn/start","turn/started","turn/completed","turn/steer","queue/submit"}:
            raise RuntimeError("ZERO_TURN_OR_QUEUE_FORBIDDEN")
        return original_audit(self,letter,direction,message,raw)
    if zero_model:
        CandidateGate.audit_rpc=zero_audit
    return CandidateGate, migration.LEGACY


def validate_zero_command(argv):
    """Closed zero lane: no credential metadata, paid bootstrap or provider dispatch."""
    words=list(map(str,argv))
    if any("/run/secrets/" in word or "/gpu1-share/" in word or
           "API_KEY=" in word or "HTTPS_PROXY=" in word for word in words):
        raise PermissionError("ZERO_CREDENTIAL_OR_PROVIDER_ARGV")
    if any(word in {"paid","turn/start","turn/steer","queue-submit","queue/push"} for word in words):
        raise PermissionError("ZERO_MODEL_ARGV")

ZERO_AGENT_BOOTSTRAP = "import os,sys\nos.execvp('/bin/sh',['/bin/sh',*sys.argv[1:]])\n"
