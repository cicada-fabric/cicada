"""Minimal method overlay; imports legacy effects ONLY in authorized load_gate."""
import ast
import hashlib
import importlib.util
import json
import sys
import time
import types
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEGACY = Path("/home/zyf/CICADA_task_handoff/.cicada-data/worktree-evidence/g1-complete-compat-dispatch-20261004")
SCRIPTS = HERE.parent
OLD = Path("/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/managed")
OLD_GATE_SHA = "83952e697f7af7257c2397d56ac2972e4047f4db909b9414539f8222772a7512"
PATCH_SHA = "e621d869098d54a8685f187eecc2bbd1030120349612225fefdc04f30e99da24"
METHODS = ("start_managed_servers", "managed_golden_flow", "capture_test_request_observer", "abort_owned")


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
                    "end":min(time.monotonic()+5,self.policy.cleanup_end,self.policy.started+240)}
                self._observer_native_capture_state = publication
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
    end = min(publication["end"],self.policy.cleanup_end,self.policy.started+240)
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
    return self.policy.started+{"normal":180,"terminal":210,"cleanup":240}[self.policy.phase]


def safe_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def effective_sources():
    shim = safe_module("cicada_observer_bootstrap_public", HERE / "request_observer_bootstrap.py")
    original = shim.read_pinned(OLD / "managed_gate.py", OLD_GATE_SHA, 131072).decode()
    patch = shim.read_pinned(LEGACY / "request-observer-integration.patch", PATCH_SHA).decode()
    source = shim.apply_section(original, patch, "managed/managed_gate.py")
    source = source.replace("/run/cicada-request-observer", "/tmp/cicada-request-observer")
    source = source.replace("/run/request_observer.py", "/tmp/native_request_observer.py")
    export_import = "sys.path.insert(0,'/run')\nfrom request_observer import validate_record"
    if source.count(export_import) != 1:
        raise ValueError("EXPORT_OBSERVER_IMPORT_CONTEXT")
    source = source.replace(export_import, "sys.path.insert(0,'/tmp')\nfrom native_request_observer import validate_record")
    old = "'lifetime_seconds':240, 'max_POST_attempts_per_Runtime':16,"
    if source.count(old) != 1:
        raise ValueError("GATE_OVERLAY_CONTEXT")
    source = source.replace(old, "'lifetime_seconds':180, 'max_POST_attempts_per_Runtime':16,")
    source = source.replace("observer_args = ['--test-request-observer', base_sha, '240', '16']",
        "observer_args = ['--test-request-observer', base_sha, repr(self.policy.started+180), '16']")
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
    source = replace_once(source, "print(json.dumps(result))\n\"\"\"\n            try:", "io_result={'status':'UNKNOWN','records':[]}\ntry:\n with Path('/tmp/cicada-request-observer-io.jsonl').open('rb') as io_stream: io_raw=io_stream.read(32769)\n with Path('/tmp/cicada-request-observer-io-watermark.json').open('rb') as io_stream: io_mark_raw=io_stream.read(1025)\n if len(io_mark_raw)>1024: raise ValueError()\n io_mark=json.loads(io_mark_raw)\n io_result={'status':'COMPLETE','records':validate_export(io_raw,io_mark),'watermark':io_mark}\nexcept Exception: pass\nresult['io_sibling']=io_result\nprint(json.dumps(result))\n\"\"\"\n            try:")
    source = replace_once(source, "                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained", "                from native_request_observer_io import join_records\n                sibling=exported.get('io_sibling',{})\n                self.result.setdefault('observer_io_diagnostics',{})[letter]=(join_records(sibling.get('records',[]),exported['records'],node['thread'],actual,sibling.get('watermark')) if sibling.get('status')=='COMPLETE' else {'status':'UNKNOWN','records':[]})\n                diagnostics[letter]=report  # alpha=false/UNKNOWN rows are retained")
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
    tree = ast.parse((OLD / "migration.py").read_text())
    install = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "install")
    provider = next(node for node in install.body if isinstance(node, ast.FunctionDef) and node.name == "provider")
    changed = 0
    for node in ast.walk(provider):
        if isinstance(node, ast.Constant) and type(node.value) is int and node.value == 240:
            node.value = 180
            changed += 1
    if changed != 2:
        raise ValueError("PROVIDER_DEADLINE_CONTEXT")
    provider_source = ast.unparse(provider) + "\n"
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


def bind_policy(policy, started):
    """Reuse existing instance with fixed absolute phase ends; no reset."""
    policy.started, policy.total, policy.phase = started, 240, "normal"
    policy.terminal_end, policy.cleanup_end = started + 210, started + 240
    def limit(self, maximum):
        end = self.started + {"normal":180, "terminal":210, "cleanup":240}[self.phase]
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


def runtime_bootstrap_argv(arguments, binding, started):
    """Pure selection shared by inspection and actual authorized Docker branch."""
    argv = list(map(str, arguments))
    if len(argv) < 7 or argv[:2] != ["exec","-d"] or argv[3:6] != ["python3","/state/server_bootstrap.py","paid"]:
        raise ValueError("CANDIDATE_BOOTSTRAP_DISPATCH_SHAPE")
    argv[4] = "/tmp/request_observer_bootstrap.py"
    argv += [binding["candidate_files"]["request_observer_bootstrap.py"]["sha256"],
             binding["effective_sources"]["bootstrap"], repr(started), binding["public_files"][str(SCRIPTS/"native_request_observer_io.py")]["sha256"], "--io-diagnostics"]
    return argv


def load_gate(delivery, binding, *, inspect_only=False):
    """Inspection imports public helpers only; execution requires future GO."""
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
    sources = effective_sources()
    namespace = dict(original_namespace)
    namespace.update(_observer_capture_native_failure=capture_native_failure,
        _observer_register_capture_command=register_capture_command,
        _observer_capture_deadline=capture_deadline,
        _observer_capture_program_pins=capture_program_pins(sources["gate"]))
    methods = compile_methods(sources["gate"], namespace)
    provider_namespace = dict(legacy_cls.provider_forwarder.__globals__)
    exec(compile(sources["provider"], "<effective-request-observer-provider>", "exec"), provider_namespace)
    audit_namespace=method_namespace(legacy_cls.audit_rpc)
    audit_namespace["_observer_mark_native_failure"]=mark_native_failure
    exec(compile(sources["audit"],"<effective-request-observer-audit>","exec"),audit_namespace)
    command_namespace=method_namespace(legacy_cls.command)
    command_namespace.update(_observer_capture_command_allowed=capture_command_allowed,
                             _observer_thread_identity=threading.get_ident,
                             _observer_wait_native_cleanup=wait_native_capture_before_owned_cleanup)
    exec(compile(sources["command"],"<effective-request-observer-command>","exec"),command_namespace)
    class CandidateGate(legacy_cls):
        def __init__(self, args):
            if inspect_only:
                raise RuntimeError("INSPECTION_FORBIDS_FIXTURE_CONSTRUCTOR")
            super().__init__(args)
            self._observer_capture_lifecycle_lock = threading.Lock()
            self._observer_native_capture_state = None
            self._observer_capture_cutoff = False
            bind_policy(self.policy, args.artifact_started)
            self.result["historical_effective_owned_wrapper_sha256_dependency_only"] = self.result.pop("effective_owned_wrapper_sha256", {})
            self.result["effective_owned_wrapper_sha256"] = {name:row["sha256"] for name,row in binding["candidate_files"].items()}
            self.result["effective_candidate_source_sha256"] = binding["effective_sources"]
            self.result["candidate_binding_sha256"] = args.candidate_binding_sha256
            self.result["shared_absolute_phase_seconds"] = {"normal":180,"terminal":210,"cleanup":240}
            self.result["observer_same_kernel_CLOCK_MONOTONIC"] = "REQUIRED_NOT_RUNTIME_VERIFIED"
            self.result["matching_preparation_scope"].update(dispatch_only_wrapper_delta=False,
                reuse_scope="UNCHANGED_PRODUCT_BASELINE_ONLY",
                changed_observer_bootstrap_overlay_Runtime_preparation="NOT_RUN")
        runtime_bootstrap_argv = staticmethod(runtime_bootstrap_argv)
        def docker(self, *arguments, **kwargs):
            argv = list(map(str, arguments))
            if len(argv) >= 7 and argv[:2] == ["exec", "-d"] and argv[3:6] == ["python3", "/state/server_bootstrap.py", "paid"]:
                container = argv[2]
                for filename in ("request_observer_bootstrap.py", "request-observer-integration.patch", "native_request_observer_io.py"):
                    payload_path = (LEGACY/filename if filename.endswith(".patch") else SCRIPTS/filename if filename.startswith("native_") else HERE/filename)
                    row = binding["public_files"][str(payload_path)]
                    payload = payload_path.read_bytes()
                    if hashlib.sha256(payload).hexdigest() != row["sha256"]:
                        raise RuntimeError("CANDIDATE_RUNTIME_PAYLOAD_CHANGED")
                    upload = "import os,sys; p=sys.argv[1]; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); s=os.fdopen(f,'wb'); s.write(sys.stdin.buffer.read()); s.close()"
                    self.command(["docker","exec","-i",container,"python3","-c",upload,"/tmp/"+filename], input_data=payload, timeout=3)
                argv = self.runtime_bootstrap_argv(argv,binding,self.policy.started)
                self.result.setdefault("effective_Runtime_bootstrap", {})[container] = {
                    "copied_payload_sha256":binding["candidate_files"]["request_observer_bootstrap.py"]["sha256"],
                    "effective_source_sha256":binding["effective_sources"]["bootstrap"],
                    "observer_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer.py")]["sha256"],
                    "normal_end_MONOTONIC":self.policy.started+180}
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
                verify_binding(self.args.candidate_binding_sha256)
            except Exception:
                self.result["candidate_sources_unchanged"] = False
                self.result["status"] = "FAIL"
            else:
                self.result["candidate_sources_unchanged"] = True
            return super().cleanup()
    for name, function in methods.items():
        setattr(CandidateGate, name, function)
    CandidateGate.provider_forwarder = provider_namespace["provider"]
    CandidateGate.audit_rpc = audit_namespace["audit"]
    CandidateGate.command = command_namespace["command"]
    return CandidateGate, migration.LEGACY
