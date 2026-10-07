"""ZERO-PAID preflight; separate future fresh-GO diagnostic, default disabled."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time
import types
import builtins
import contextlib
import io
import socket
import ssl
import subprocess
from unittest.mock import patch
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEGACY = Path("/home/zyf/CICADA_task_handoff/.cicada-data/worktree-evidence/g1-complete-compat-dispatch-20261004")
SCRIPTS = HERE.parent
sys.path.insert(0,str(SCRIPTS))
ACTUAL = Path("/home/zyf/CICADA_task_handoff/.cicada-data/worktree-evidence/g1-complete-prepare-20261004/actual-preparation-857-v2")
CONFIG = Path("/home/zyf/CICADA_real_codex_prep_20261002/cli/zzswitch-config-proof-20261003/home/config.toml")
CREDENTIAL = "/gpu1-share/data/cicada/secrets/cicada-acceptance-zzswitch-20261003.env"
PRODUCT_REPO = "/home/zyf/CICADA_task_handoff/.cicada-data/worktree-evidence/g1-complete-prepare-20261004/source-capture-857-v2/source-checkout"
BINDING = Path("/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/binding.NONAUTH.json")
DEPS_SHA = "a6520c48b317c9cd0164dc532e8927f8e2a2bd355bc147b8c61ca125a6d29c1e"
DELIVERY_SHA = "3778e42e01e4b7056f2dab13fd06a31b02186eb019d7a6d2d35037175f8eef12"
CONFIG_SHA = "c7d0a61a6a6805aedc39a8e07b937b54fa430c088d61629f84a08f16cb326baf"
RUNTIME = "sha256:d6004eb3f669966f7a30796333b8a4b1635b30ded40cc7d186e19c42c196818f"
CLI_SHA = "12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad"
ROOT_OFFLINE_SHA = "86b00fa2214f86375a4ddf2f3121e1ba66c8ec35b03339d4ac54612549d494ad"
ROOT_REVIEW_SHA = "08f0f9040f9b6037966027be4103dc9ffa919710cdf53dc3d67928f4f48b9526"
ARCHIVE = LEGACY/"request-observer-candidate-archive-1715bcb200a87c19"
ARCHIVE_SHA = "d33c63b2733307895f2004007e9b30c0c14b2c5be58a392d2efc8fd2aad69f64"
PREP_RESULT_SHA = "b3711815c51fbe5fef11d9886aaf4ac19ff70f64a2079e92b7cdffa5b04f67ec"
PREP_BINDING_SHA = "60838ae22ead11b86eed7c449bce8ba55e6528758c25e0e123b620e8a16b907e"
PREP_REVIEW_SHA = "d9c3fe5ce1823bfff8bc10f921e365f51544b96b9dcd6b1a24b866816a9bcfc2"
HARD_STOP_UNIX = 0  # Historical deadline is never execution authority.
NEW_NAMES = ("request_observer_gate.py", "request_observer_bootstrap.py", "request_observer_run.py", "request_observer_wiring_checks.py")
FROZEN_NAMES = ("request_observer.py", "request_observer_checks.py", "request-observer-integration.patch", "request-observer-design.NONAUTH.md")
EXECUTION_EFFECTS_STARTED = False


def bounded_json(path, limit=262144):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("BOUNDED_PUBLIC_JSON")
    return json.loads(raw), raw


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_overlay(name):
    spec = importlib.util.spec_from_file_location("cicada_"+name, HERE/(name+".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def required_paths():
    if digest(LEGACY/"readonly-dependencies.json") != DEPS_SHA:
        raise ValueError("READONLY_MANIFEST_CHANGED")
    deps, _ = bounded_json(LEGACY/"readonly-dependencies.json")
    paths = {str(HERE/name) for name in NEW_NAMES}
    paths.update(str(ARCHIVE/name) for name in NEW_NAMES+(
        "request-observer-candidate-binding.NONAUTH.json","request-observer-GO-proposal.NONAUTH.json",
        "request-observer-invocation.NONAUTH.txt","source-preservation.NONAUTH.json"))
    paths.update(row["path"] for row in deps)
    paths.update(str(LEGACY/name) for name in ("migration.py","managed_gate.py","run_managed.py","prepare_g1.py","readonly-dependencies.json",
        "request-observer-root-offline-20261004.NONAUTH.json","request-observer-root-review-20261004.NONAUTH.json"))
    paths.update(str(LEGACY/"formal-dispatch"/name) for name in ("source-binding.json","future-root-go.json","execution-claim.json"))
    paths.update(str(ACTUAL/name) for name in ("actual-delivery.json","hub-image-receipt.json","source-binding.json",
        "independent-review-b.NONAUTH.json","native-preparation/result.json","bin/cicada-v68fixture"))
    package = ACTUAL/"hub-context/cicada-linux-amd64-pqtls"
    paths.update(str(package/name) for name in ("BUILD-METADATA.json","bin/cicada"))
    if digest(package/"BUILD-METADATA.json") != "c418d2da5a05349c6492a9f1539db783bcf1ed651e1232544a2826faebfaff94":
        raise ValueError("PUBLIC_PACKAGE_METADATA_PIN")
    metadata, _ = bounded_json(package/"BUILD-METADATA.json",1048576)
    if any(Path(name).is_absolute() or ".." in Path(name).parts for name in metadata["runtime"]["files"]):
        raise ValueError("PUBLIC_PACKAGE_PATH")
    paths.update(str(package/name) for name in metadata["runtime"]["files"] if name.startswith(("lib/","lib64/","bin/","etc/")))
    paths.add(str(CONFIG))
    paths.update(str(LEGACY/name) for name in FROZEN_NAMES)
    paths.update(str(SCRIPTS/name) for name in ("native_request_observer.py","native_request_observer_io.py","test_native_request_observer.py","test_native_request_observer_io.py"))
    if CREDENTIAL in paths:
        raise ValueError("CREDENTIAL_EXCLUDED_FROM_PUBLIC_PREFLIGHT")
    return paths


def verify_binding(expected_sha=None):
    binding, raw = bounded_json(BINDING)
    sha = hashlib.sha256(raw).hexdigest()
    if expected_sha is not None and sha != expected_sha:
        raise ValueError("CANDIDATE_BINDING_SHA")
    if binding.get("schema") != "cicada.request-observer-candidate-binding.v1" or binding.get("authority") != "NONAUTH":
        raise ValueError("CANDIDATE_BINDING_SCHEMA")
    rows = binding.get("files")
    if type(rows) is not list or any(type(row) is not dict or
            set(row) != {"path", "sha256", "bytes", "rawmode"} for row in rows):
        raise ValueError("SOURCE_ROWS_SCHEMA")
    listed = {row["path"]: {key:row[key] for key in ("sha256", "bytes", "rawmode")} for row in rows}
    if len(listed) != len(rows) or listed != binding["public_files"]:
        raise ValueError("SOURCE_ROWS_INCONSISTENT")
    _, alias_raw = bounded_json(BINDING.parent / "source-binding.json")
    if alias_raw != raw:
        raise ValueError("ACTIVE_SOURCE_BINDING_ALIAS")
    paths = required_paths()
    if set(binding["public_files"]) != paths or set(binding["candidate_files"]) != set(NEW_NAMES):
        raise ValueError("PUBLIC_PATH_ALLOWLIST")
    for path, row in binding["public_files"].items():
        if Path(path).is_absolute() is not True or str(Path(path).resolve()) != path:
            raise ValueError("PUBLIC_CANONICAL_PATH")
        metadata = Path(path).lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size != row["bytes"] or
                oct(metadata.st_mode) != row["rawmode"] or digest(path) != row["sha256"]):
            raise ValueError("PUBLIC_SOURCE_CHANGED")
    for name, row in binding["candidate_files"].items():
        if row != binding["public_files"][str(HERE/name)]:
            raise ValueError("CANDIDATE_SOURCE_ROW")
    fixed = {ACTUAL/"actual-delivery.json":DELIVERY_SHA, CONFIG:CONFIG_SHA,
        ARCHIVE/"source-preservation.NONAUTH.json":ARCHIVE_SHA,
        LEGACY/"request-observer-root-offline-20261004.NONAUTH.json":ROOT_OFFLINE_SHA,
        LEGACY/"request-observer-root-review-20261004.NONAUTH.json":ROOT_REVIEW_SHA,
        ACTUAL/"native-preparation/result.json":PREP_RESULT_SHA,
        ACTUAL/"source-binding.json":PREP_BINDING_SHA,
        ACTUAL/"independent-review-b.NONAUTH.json":PREP_REVIEW_SHA}
    if any(binding["public_files"][str(path)]["sha256"] != sha for path,sha in fixed.items()):
        raise ValueError("IMMUTABLE_DELIVERY_OR_REVIEW_PIN")
    deps, _ = bounded_json(LEGACY/"readonly-dependencies.json")
    for row in deps:
        held = binding["public_files"][row["path"]]
        if held != {key:row[key] for key in ("sha256","bytes","rawmode")}:
            raise ValueError("FROZEN47_SOURCE_PIN")
    gate = safe_overlay("request_observer_gate")
    sources = gate.effective_sources()
    effective = {key:hashlib.sha256(value.encode()).hexdigest() for key,value in sources.items()}
    if effective != binding["effective_sources"]:
        raise ValueError("EFFECTIVE_OVERLAY_SOURCE_PIN")
    return binding, sha


@contextlib.contextmanager
def deny_preflight_effects():
    """Read-only host inspection: no sockets, subprocesses, writes or credential metadata."""
    def deny(*args, **kwargs):
        raise PermissionError("ZERO_PAID_PREFLIGHT_EFFECT_DENIED")
    old_open, old_io_open = builtins.open, io.open
    old_stat, old_lstat, old_os_open = os.stat, os.lstat, os.open
    def public_path(path):
        if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path)==CREDENTIAL:
            deny()
    def readonly_open(original):
        def guarded(path,mode="r",*args,**kwargs):
            public_path(path)
            if any(character in mode for character in "wax+"):
                deny()
            return original(path,mode,*args,**kwargs)
        return guarded
    def guarded_stat(original):
        def guarded(path,*args,**kwargs):
            public_path(path)
            return original(path,*args,**kwargs)
        return guarded
    def guarded_os_open(path,flags,*args,**kwargs):
        public_path(path)
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            deny()
        return old_os_open(path,flags,*args,**kwargs)
    bytecode=sys.dont_write_bytecode
    sys.dont_write_bytecode=True
    try:
        with contextlib.ExitStack() as stack:
            for owner,name in ((socket,"socket"),(socket,"create_connection"),(socket,"getaddrinfo"),
                               (socket,"gethostbyname"),(subprocess,"Popen"),(subprocess,"run"),(os,"system")):
                stack.enter_context(patch.object(owner,name,deny))
            for owner,name,value in ((builtins,"open",readonly_open(old_open)),(io,"open",readonly_open(old_io_open)),
                                     (os,"stat",guarded_stat(old_stat)),(os,"lstat",guarded_stat(old_lstat)),
                                     (os,"open",guarded_os_open)):
                stack.enter_context(patch.object(owner,name,value))
            yield
    finally:
        sys.dont_write_bytecode=bytecode


def _preflight(expected_sha=None):
    binding, sha = verify_binding(expected_sha)
    gate = safe_overlay("request_observer_gate")
    source = gate.effective_sources()["gate"]
    delivery,_=bounded_json(ACTUAL/"actual-delivery.json")
    cls,legacy=gate.load_gate(delivery,binding,inspect_only=True)
    methods={name:getattr(cls,name) for name in gate.METHODS}
    namespace=methods["start_managed_servers"].__globals__
    if any(method.__globals__ is not namespace for method in methods.values()) or Path(namespace["HERE"]) != gate.OLD:
        raise ValueError("ABSOLUTE_LEGACY_GLOBAL_RESOLUTION")
    if legacy.RUNTIME!=RUNTIME or legacy.CLI_SHA!=CLI_SHA:
        raise ValueError("IMPORTED_RUNTIME_SOURCE_PINS")
    provider_globals=cls.provider_forwarder.__globals__
    forwarder_module=sys.modules[provider_globals["Forwarder"].__module__]
    if Path(forwarder_module.__file__).resolve()!=gate.OLD/"provider_transport.py":
        raise ValueError("IMPORTED_PROVIDER_GLOBAL_ORIGIN")
    argv=cls.runtime_bootstrap_argv(["exec","-d","INSPECTION_ONLY","python3","/state/server_bootstrap.py","paid",
        "http://192.0.2.1:7890","--test-request-observer",binding["upstream_base_url_sha256"],"1180.0","16"],binding,1000.0)
    if argv[4]!="/tmp/request_observer_bootstrap.py" or argv[-5:]!=[
        binding["candidate_files"]["request_observer_bootstrap.py"]["sha256"],binding["effective_sources"]["bootstrap"],"1000.0",binding["public_files"][str(SCRIPTS/"native_request_observer_io.py")]["sha256"],"--io-diagnostics"]:
        raise ValueError("ACTUAL_BOOTSTRAP_PAYLOAD_SELECTION")
    return {"schema":"cicada.request-observer-wiring-preflight.v1", "status":"PASS",
        "authority":"NONAUTH_ZERO_PAID", "candidate_binding_sha256":sha,
        "methods":sorted(methods), "effective_sources":binding["effective_sources"],
        "import_resolution":"ACTUAL_HOST_PUBLIC_CLASS_GLOBALS_AND_BOOTSTRAP_SELECTION", "legacy_public_modules_imported":True,
        "fixture_constructor_called":False,
        "credential_metadata_accessed":False, "Runtime_calls":0,"provider_POSTs":0,"model_calls":0,
        "budget_seconds":{"normal":180,"terminal":30,"cleanup":30,"total":240},
        "native_ACCEPTANCE":"NOT_RUN", "real_Runtime":"NOT_RUN", "HTTP_TLS_semantic_parity":"NOT_PROVEN"}


def preflight(expected_sha=None):
    with deny_preflight_effects():
        return _preflight(expected_sha)


def expected_go(binding, binding_sha, run_id, wiring_sha, hard_stop_unix=0):
    if not re.fullmatch(r"cicada-two-turn-[a-z0-9]{12,32}", run_id or ""):
        raise ValueError("FRESH_RUN_ID")
    delivery, _ = bounded_json(ACTUAL/"actual-delivery.json")
    result = BINDING.parent/("request-observer-native-result-"+run_id)
    claim = BINDING.parent/("request-observer-execution-claim-"+run_id+".json")
    return {"schema":"cicada.managed-five-observer-go.v1","scope":"managed-five-observer-diagnostic",
        "authority":"ROOT_NATIVE_DIAGNOSTIC_GO", "runtime_execution_authorized":True,
        "provider_credential_access_authorized":True,"model_dispatch_authorized":True,
        "unique_run":run_id,"result_dir":str(result),"claim_file":str(claim),
        "candidate_binding_sha256":binding_sha,"wiring_receipt_sha256":wiring_sha,
        "candidate_files":binding["candidate_files"],"effective_sources":binding["effective_sources"],
        "observer_root_offline_receipt_sha256":ROOT_OFFLINE_SHA,"observer_root_review_sha256":ROOT_REVIEW_SHA,
        "max_native_turns":5,"max_manual_turns":3,"max_automatic_turns":2,
        "normal_seconds":180,"terminal_seconds":30,"cleanup_seconds":30,"total_seconds":240,
        "max_fatal_diagnostic_capture_seconds":5,
        "phase_deadlines_absolute":True,"max_POST_attempts_per_Runtime":16,
        "request_max_retries":0,"stream_max_retries":0,"observer_retries":0,
        "model":"gpt-5.6-luna","runtime_image":RUNTIME,"official_cli_sha256":CLI_SHA,
        "hub_image":delivery["hub_image"],"product_revision":delivery["commit"],
        "product_sha256":delivery["binary_sha256"],"helper_sha256":delivery["helper_sha256"],
        "node_source_fingerprint":delivery["fingerprint"],"config_template_sha256":CONFIG_SHA,
        "actual_delivery_sha256":DELIVERY_SHA,"require_native_pqtls":True,
        "a3_criterion":"INLINE_CORRELATED_REPLY_ORIGINAL_A_CONTEXT",
        "preparation_result_sha256":PREP_RESULT_SHA,"preparation_source_binding_sha256":PREP_BINDING_SHA,
        "independent_review_sha256":PREP_REVIEW_SHA,
        "credential_reference":CREDENTIAL,"credential_access_scope":"EXACT_RUNTIME_ONLY_READONLY",
        "credential_runtime_path":"/run/secrets/provider.env","cleanup_hard_stop_unix":hard_stop_unix,
        "io_diagnostics":{"enabled":True,"code_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer_io.py")]["sha256"],"max_rows":16,"max_bytes":32768},
        "test_request_observer":{"schema":"cicada.test-request-observer-go.v1",
            "code_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer.py")]["sha256"],
            "upstream_base_url_sha256":binding["upstream_base_url_sha256"],
            "lifetime_seconds":180,"max_POST_attempts_per_Runtime":16,"default_off":True}}


def validate_go(go, expected, now=None):
    now = time.time() if now is None else now
    if type(go) is not dict or set(go) != set(expected)|{"expires_at_unix"}:
        raise PermissionError("GO_FIELD_SET")
    def exact(left, right):
        if type(left) is not type(right):
            return False
        if type(right) is dict:
            return set(left)==set(right) and all(exact(left[key],right[key]) for key in right)
        if type(right) is list:
            return len(left)==len(right) and all(exact(a,b) for a,b in zip(left,right))
        return left==right
    for key,value in expected.items():
        if not exact(go[key],value):
            raise PermissionError("GO_TYPED_BINDING")
    if type(go["expires_at_unix"]) is not int or go["expires_at_unix"] <= now:
        raise PermissionError("GO_EXPIRED")
    if type(expected["cleanup_hard_stop_unix"]) is not int or now+240 > expected["cleanup_hard_stop_unix"]:
        raise PermissionError("CLEANUP_HARD_CUTOFF")


def execute(args):
    global EXECUTION_EFFECTS_STARTED
    if not getattr(args,"preparation_result",None) or not getattr(args,"preparation_result_sha",None):
        raise PermissionError("LATEST_RUNTIME_NOT_READY")
    with deny_preflight_effects():
        binding,binding_sha,delivery,prior=latest_dispatch_inputs(args)
    # No legacy imports, credential stat or effects before all public/fresh GO guards.
    if not getattr(args,"enable_io_diagnostics",False):
        raise PermissionError("IO_DIAGNOSTICS_OPT_IN_REQUIRED")
    required = (args.go_receipt,args.go_receipt_sha,args.binding_sha,args.wiring_receipt,args.wiring_receipt_sha,args.unique_run,getattr(args,"cleanup_hard_stop_unix",None))
    if not all(required):
        raise PermissionError("FRESH_GO_AND_WIRING_RECEIPT_REQUIRED")
    go_path=Path(args.go_receipt)
    if go_path.parent.absolute()!=BINDING.parent or not go_path.name.startswith("request-observer-") or not go_path.name.endswith(".json"):
        raise PermissionError("FRESH_GO_PUBLIC_PATH")
    receipt_path = Path(args.wiring_receipt)
    if receipt_path.parent.resolve()!=BINDING.parent or not receipt_path.name.startswith("request-observer-wiring-"):
        raise PermissionError("PUBLIC_WIRING_RECEIPT_PATH")
    receipt, raw = bounded_json(receipt_path)
    if (hashlib.sha256(raw).hexdigest()!=args.wiring_receipt_sha or receipt.get("status")!="PASS" or
        receipt.get("candidate_binding_sha256")!=binding_sha or receipt.get("Runtime_calls")!=0 or
        receipt.get("provider_POSTs")!=0 or receipt.get("model_calls")!=0):
        raise PermissionError("WIRING_OFFLINE_RECEIPT")
    expected = expected_latest_go(binding,binding_sha,args,delivery)
    go, raw = bounded_json(args.go_receipt)
    if hashlib.sha256(raw).hexdigest()!=args.go_receipt_sha:
        raise PermissionError("GO_BYTE_PIN")
    validate_go(go,expected)
    result, claim = Path(go["result_dir"]),Path(go["claim_file"])
    if result.exists() or claim.exists():
        raise PermissionError("FRESH_UNCONSUMED_PATHS_REQUIRED")
    # Metadata only, only after fresh GO. Contents are never read on the host.
    metadata=Path(CREDENTIAL).lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_uid!=1000:
        raise PermissionError("CREDENTIAL_METADATA")
    validate_go(go,expected)
    started=time.monotonic()
    with os.fdopen(os.open(claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as out:
        json.dump({"schema":"cicada.request-observer-execution-claim.v1","unique_run":args.unique_run,
                   "go_sha256":args.go_receipt_sha,"candidate_binding_sha256":binding_sha,
                   "artifact_started_MONOTONIC":started,"normal_end_MONOTONIC":started+180,
                   "hard_end_MONOTONIC":started+240},out)
        out.flush();os.fsync(out.fileno())
    EXECUTION_EFFECTS_STARTED = True
    gate_overlay=safe_overlay("request_observer_gate")
    cls,legacy=gate_overlay.load_gate(delivery,binding)
    ns=types.SimpleNamespace(execute=True,run_native=True,result_dir=str(result),product_repo=delivery["source_repo"],
        expected_product_revision=delivery["commit"],expected_source_fingerprint=delivery["fingerprint"],
        runtime_image=LATEST_RUNTIME,expected_codex_version="codex-cli 0.160.1",expected_cli_sha256=LATEST_CLI_SHA,
        producer_receipt_sha256=delivery["package_metadata_sha256"],producer_receipt=str(Path(delivery["package"])/"BUILD-METADATA.json"),
        exact_clean_image_metadata=delivery["hub_receipt_path"],exact_clean_image_metadata_sha256=delivery["hub_receipt_sha256"],
        config_template=str(CONFIG),config_template_sha=CONFIG_SHA,source_binding_sha=binding_sha,
        offline_checks_sha=args.wiring_receipt_sha,artifact_started=started,go=go,credential_file=CREDENTIAL,
        preparation_result=args.preparation_result,preparation_result_sha256=args.preparation_result_sha,
        latest_runtime=True,delivery_sha=args.delivery_sha,equality_sha=args.equality_sha,
        test_request_observer=True,request_observer_source=str(SCRIPTS/"native_request_observer.py"),candidate_binding_sha256=binding_sha)
    gate=None
    try:
        gate=cls(ns);gate.build();gate.start_nodes();gate.prepare_managed();gate.managed_golden_flow()
    except Exception as error:
        if gate is None:
            raise
        gate.result.update(status="FAIL",failure_phase=gate.phase,failure_class=type(error).__name__)
    finally:
        if gate is not None:
            gate.cleanup()
    return gate.result["terminal_exit_code"]


LATEST_RUNTIME = "sha256:ebea4c9988e539d2da914e9cf451c35d5c5039cf99706cd1effc0a6d7b449b83"
LATEST_CLI_SHA = "f34a4d2301892ae96c90097786bfe5dc269f187b6f69faf42a7b357b8c081e35"
ZERO_CONFIG = '\n'.join(['model = "gpt-5.6-luna"','model_provider = "basil"',
    'sandbox_mode = "workspace-write"','approval_policy = "on-request"','approvals_reviewer = "user"',
    '[model_providers.basil]','name="Synthetic zero-model provider"',
    'base_url="http://127.0.0.1:9/v1"','wire_api="responses"',
    'request_max_retries = 4',''])


def latest_dispatch_inputs(args):
    """Fresh preparation is evidence, never model authorization by itself."""
    binding,sha=verify_binding(args.binding_sha)
    delivery,raw=bounded_json(args.delivery)
    if hashlib.sha256(raw).hexdigest()!=args.delivery_sha:raise PermissionError("LATEST_DELIVERY_PIN")
    equality,raw=bounded_json(args.compiled_input_equality)
    if (hashlib.sha256(raw).hexdigest()!=args.equality_sha or equality.get("status")!="COMPILED_INPUTS_EXACT" or
        equality.get("current_commit")!=args.current_commit or
        equality.get("artifact_compiled_inputs_sha256")!=equality.get("current_compiled_inputs_sha256") or
        equality.get("artifact_binary_sha256")!=delivery.get("binary_sha256")):
        raise PermissionError("LATEST_COMPILED_INPUT_EQUALITY")
    prior,raw=bounded_json(args.preparation_result,1<<20)
    prep=prior.get("preparation_binding",{})
    if (hashlib.sha256(raw).hexdigest()!=args.preparation_result_sha or
        prior.get("status")!="PREPARATION_PASS_NATIVE_NOT_RUN" or prior.get("terminal_exit_code")!=0 or
        prior.get("cleanup_owned_resources") is not True or prior.get("candidate_sources_unchanged") is not True or
        prior.get("observer_shutdown")!={"a":"EXPECTED_EOF_CONFIRMED","b":"EXPECTED_EOF_CONFIRMED"} or
        prior.get("models_invoked")!=0 or prior.get("actual_turn_started_count")!=0 or
        prior.get("actual_turn_started_event_count")!=0 or prior.get("paid_turn_start_submissions")!=0 or
        prep.get("source_binding_sha256")!=sha or prep.get("runtime_image_id")!=LATEST_RUNTIME or
        prep.get("official_cli_sha256")!=LATEST_CLI_SHA or prep.get("current_delivery_sha256")!=args.delivery_sha or
        prep.get("compiled_input_equality_sha256")!=args.equality_sha):
        raise PermissionError("LATEST_RUNTIME_NOT_READY")
    review,raw=bounded_json(args.preparation_review)
    if hashlib.sha256(raw).hexdigest()!=args.preparation_review_sha or review.get("status")!="PASS" or review.get("result_sha256")!=args.preparation_result_sha:
        raise PermissionError("LATEST_PREPARATION_REVIEW")
    return binding,sha,delivery,prior


def expected_latest_go(binding,sha,args,delivery):
    expected=expected_go(binding,sha,args.unique_run,args.wiring_receipt_sha,args.cleanup_hard_stop_unix)
    expected.update(runtime_image=LATEST_RUNTIME,official_cli_sha256=LATEST_CLI_SHA,
        hub_image=delivery["hub_image"],product_revision=delivery["commit"],product_sha256=delivery["binary_sha256"],
        helper_sha256=delivery["helper_sha256"],node_source_fingerprint=delivery["fingerprint"],
        actual_delivery_sha256=args.delivery_sha,preparation_result_sha256=args.preparation_result_sha,
        preparation_source_binding_sha256=sha,independent_review_sha256=args.preparation_review_sha,
        compiled_input_equality_sha256=args.equality_sha,official_cli_version="0.160.1",
        preparation_provider_scope="SYNTHETIC_LOOPBACK_ZERO_MODEL_NOT_PROVIDER_PARITY")
    return expected


def zero_inputs(args):
    with deny_preflight_effects():
        return _zero_inputs_public(args)


def _zero_inputs_public(args):
    """Public-only fail-closed validation; no constructor or Docker before return."""
    if args.execute_diagnostic or getattr(args,"enable_io_diagnostics",False):
        raise PermissionError("ZERO_PAID_FLAGS")
    if not re.fullmatch(r"cicada-two-turn-zerocli161-[a-z0-9]{8,24}",args.unique_run or ""):
        raise PermissionError("ZERO_UNIQUE_RUN")
    if args.runtime_image!=LATEST_RUNTIME:
        raise PermissionError("ZERO_LATEST_RUNTIME_REQUIRED")
    if type(args.cleanup_hard_stop_unix) is not int or time.time()+240>=args.cleanup_hard_stop_unix:
        raise PermissionError("ZERO_ABSOLUTE_BUDGET")
    binding,sha=verify_binding(args.binding_sha)
    receipt,raw=bounded_json(args.wiring_receipt)
    if (hashlib.sha256(raw).hexdigest()!=args.wiring_receipt_sha or receipt.get("status")!="PASS" or
            receipt.get("candidate_binding_sha256")!=sha or receipt.get("Runtime_calls")!=0 or
            receipt.get("model_calls")!=0):
        raise PermissionError("ZERO_CURRENT_OFFLINE_RECEIPT")
    delivery,raw=bounded_json(args.delivery)
    if hashlib.sha256(raw).hexdigest()!=args.delivery_sha:
        raise PermissionError("ZERO_DELIVERY_PIN")
    equality,raw=bounded_json(args.compiled_input_equality)
    if hashlib.sha256(raw).hexdigest()!=args.equality_sha or equality.get("status")!="COMPILED_INPUTS_EXACT":
        raise PermissionError("ZERO_COMPILED_INPUT_EQUALITY")
    if (equality.get("current_commit")!=args.current_commit or
            equality.get("artifact_compiled_inputs_sha256")!=equality.get("current_compiled_inputs_sha256") or
            not re.fullmatch(r"[0-9a-f]{64}",equality.get("current_compiled_inputs_sha256", "")) or
            equality.get("artifact_binary_sha256")!=delivery.get("binary_sha256")):
        raise PermissionError("ZERO_CURRENT_PRODUCT_MISMATCH")
    for key in ("commit","fingerprint","binary_sha256","helper_sha256","hub_image",
                "package","helper","package_metadata_sha256","hub_receipt_path","hub_receipt_sha256","source_repo"):
        if type(delivery.get(key)) is not str or not delivery[key]:
            raise PermissionError("ZERO_DELIVERY_SHAPE")
    for path,pin in ((Path(delivery["package"])/"BUILD-METADATA.json",delivery["package_metadata_sha256"]),
                     (Path(delivery["hub_receipt_path"]),delivery["hub_receipt_sha256"])):
        if digest(path)!=pin:
            raise PermissionError("ZERO_PRODUCER_RECEIPT_CHANGED")
    result=Path(args.result_dir)
    if result.parent.absolute()!=BINDING.parent or result.name!="native-preparation-"+args.unique_run or result.exists():
        raise PermissionError("ZERO_FRESH_RESULT_PATH")
    return binding,sha,delivery


def prepare_native_zero(args):
    global EXECUTION_EFFECTS_STARTED
    binding,sha,delivery=zero_inputs(args)
    # Config is synthetic, private and created only after every public guard.
    config=BINDING.parent/(args.unique_run+"-config.toml")
    fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as output: output.write(ZERO_CONFIG)
    started=time.monotonic()
    if time.time()+240>=args.cleanup_hard_stop_unix:
        raise PermissionError("ZERO_ABSOLUTE_BUDGET")
    ns=types.SimpleNamespace(execute=True,run_native=False,result_dir=args.result_dir,
        product_repo=delivery["source_repo"],expected_product_revision=delivery["commit"],
        expected_source_fingerprint=delivery["fingerprint"],runtime_image=LATEST_RUNTIME,
        expected_codex_version="codex-cli 0.160.1",expected_cli_sha256=LATEST_CLI_SHA,
        producer_receipt=str(Path(delivery["package"])/"BUILD-METADATA.json"),
        producer_receipt_sha256=delivery["package_metadata_sha256"],
        exact_clean_image_metadata=delivery["hub_receipt_path"],exact_clean_image_metadata_sha256=delivery["hub_receipt_sha256"],
        config_template=str(config),config_template_sha=hashlib.sha256(ZERO_CONFIG.encode()).hexdigest(),
        source_binding_sha=sha,offline_checks_sha=args.wiring_receipt_sha,
        artifact_started=started,go={"unique_run":args.unique_run,"max_native_turns":0,"max_manual_turns":0,
            "max_automatic_turns":0},credential_file="ZERO_LANE_NO_CREDENTIAL_REFERENCE",
        preparation_result=None,preparation_result_sha256=None,test_request_observer=False,
        candidate_binding_sha256=sha,delivery_sha=args.delivery_sha,equality_sha=args.equality_sha,latest_runtime=True)
    gate=None
    try:
        overlay=safe_overlay("request_observer_gate")
        cls,_=overlay.load_gate(delivery,binding,zero_model=True)
        EXECUTION_EFFECTS_STARTED=True
        gate=cls(ns);gate.build();gate.start_nodes();gate.prepare_managed()
        for letter in "ab":
            actual=gate.result.get("actual_managed_config",{}).get(letter,{})
            if (actual.get("approval_policy")!="never" or
                any(type(actual.get(key)) is not int or actual[key]!=0 for key in ("request_max_retries","stream_max_retries"))):
                raise RuntimeError("ZERO_ACTUAL_EFFECTIVE_CONFIGURATION")
        gate.result["zero_actual_configuration_verified"]={"a":True,"b":True}
        if gate.budget.started or gate.result.get("paid_turn_start_submissions")!=0:
            raise RuntimeError("ZERO_ACTUAL_TURN_FORBIDDEN")
        gate.result.update(status="PREPARATION_PASS_NATIVE_NOT_RUN",latest_CLI="0.160.1",
            current_product_build_dirty=delivery.get("source_dirty"),actual_product_build_version=delivery.get("actual_product_build_version"),
            credential_access=False,model_dispatch_authorized=False,provider_endpoint="SYNTHETIC_LOOPBACK_DENY",
            current_product_compiled_input_equality_sha256=args.equality_sha)
    except Exception as error:
        if gate is None: raise
        gate.result.update(status="FAIL",failure_phase=gate.phase,failure_class=type(error).__name__)
    finally:
        if gate is not None: gate.cleanup()
    return gate.result["terminal_exit_code"]


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--enable-io-diagnostics",action="store_true")
    parser.add_argument("--cleanup-hard-stop-unix",type=int)
    parser.add_argument("--prepare-native-zero",action="store_true")
    for name in ("delivery","delivery-sha","compiled-input-equality","equality-sha","runtime-image","result-dir","current-commit","preparation-result","preparation-result-sha","preparation-review","preparation-review-sha"):
        parser.add_argument("--"+name)
    parser.add_argument("--preflight",action="store_true")
    parser.add_argument("--execute-diagnostic",action="store_true")
    for name in ("binding-sha","go-receipt","go-receipt-sha","wiring-receipt","wiring-receipt-sha","unique-run"):
        parser.add_argument("--"+name)
    args=parser.parse_args(argv)
    try:
        if args.prepare_native_zero:
            return prepare_native_zero(args)
        if args.execute_diagnostic:
            return execute(args)
        if args.preflight:
            print(json.dumps(preflight(args.binding_sha),sort_keys=True))
        else:
            print(json.dumps({"status":"NONAUTH","effects":False,"Runtime_calls":0,"provider_POSTs":0,"model_calls":0}))
        return 0
    except Exception:
        calls = None if EXECUTION_EFFECTS_STARTED else 0
        print(json.dumps({"status":"FAIL_OR_UNKNOWN" if EXECUTION_EFFECTS_STARTED else "BLOCKED_GUARD",
                          "Runtime_calls":calls,"provider_POSTs":calls,"model_calls":calls,
                          "details":"CLOSED_WITHHELD"},sort_keys=True))
        return 2


if __name__=="__main__":
    sys.dont_write_bytecode=True
    raise SystemExit(main())
