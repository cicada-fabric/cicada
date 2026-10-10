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
sys.path.insert(0, str(HERE))
import request_observer_binding as current_binding
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
LEGACY_NAMES = ("request_observer_gate.py", "request_observer_bootstrap.py", "request_observer_run.py", "request_observer_wiring_checks.py")
CURRENT_NAMES = LEGACY_NAMES + ("request_observer_binding.py", "test_request_observer_binding.py")
FROZEN_NAMES = ("request_observer.py", "request_observer_checks.py", "request-observer-integration.patch", "request-observer-design.NONAUTH.md")
EXECUTION_EFFECTS_STARTED = False
DEFAULT_NATIVE_NORMAL_SECONDS = 180
MAX_NATIVE_NORMAL_SECONDS = 600
NATIVE_TERMINAL_SECONDS = 30
NATIVE_CLEANUP_SECONDS = 30


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


def required_paths(current_bundle=None):
    if digest(LEGACY/"readonly-dependencies.json") != DEPS_SHA:
        raise ValueError("READONLY_MANIFEST_CHANGED")
    deps, _ = bounded_json(LEGACY/"readonly-dependencies.json")
    active_names = CURRENT_NAMES if current_bundle is not None else LEGACY_NAMES
    paths = {str(HERE/name) for name in active_names}
    paths.update(str(ARCHIVE/name) for name in LEGACY_NAMES+(
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
    if current_bundle is not None:
        paths.update((current_bundle["delivery"]["path"], current_bundle["equality"]["path"],
                      current_bundle["runtime_receipt"]["path"], current_bundle["official_cli"]["path"]))
    if CREDENTIAL in paths:
        raise ValueError("CREDENTIAL_EXCLUDED_FROM_PUBLIC_PREFLIGHT")
    return paths


def verify_binding(expected_sha=None, binding_path=None, *, allow_candidate_source_refresh=False,
                   require_current=False):
    binding_path = Path(binding_path) if binding_path is not None else BINDING
    binding, raw = bounded_json(binding_path)
    sha = hashlib.sha256(raw).hexdigest()
    if expected_sha is not None and sha != expected_sha:
        raise ValueError("CANDIDATE_BINDING_SHA")
    is_current = binding.get("schema") == current_binding.SCHEMA
    if require_current and not is_current:
        raise ValueError("CURRENT_BINDING_REQUIRED")
    if require_current and (type(expected_sha) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None):
        raise ValueError("CURRENT_BINDING_SHA_REQUIRED")
    if (binding.get("schema") not in ("cicada.request-observer-candidate-binding.v1", current_binding.SCHEMA)
            or binding.get("authority") != "NONAUTH"):
        raise ValueError("CANDIDATE_BINDING_SCHEMA")
    rows = binding.get("files")
    if type(rows) is not list or any(type(row) is not dict or
            set(row) != {"path", "sha256", "bytes", "rawmode"} for row in rows):
        raise ValueError("SOURCE_ROWS_SCHEMA")
    listed = {row["path"]: {key:row[key] for key in ("sha256", "bytes", "rawmode")} for row in rows}
    if len(listed) != len(rows) or listed != binding["public_files"]:
        raise ValueError("SOURCE_ROWS_INCONSISTENT")
    _, alias_raw = bounded_json(binding_path.parent / "source-binding.json")
    if alias_raw != raw:
        raise ValueError("ACTIVE_SOURCE_BINDING_ALIAS")
    current_bundle = binding.get("current_bundle") if is_current else None
    paths = required_paths(current_bundle)
    candidate_names = CURRENT_NAMES if is_current else LEGACY_NAMES
    if is_current:
        current_binding.validate_bundle_binding(binding, binding_raw=raw, binding_path=binding_path,
            expected_sha256=expected_sha, required_paths=paths, candidate_names=candidate_names)
    if set(binding["public_files"]) != paths or set(binding["candidate_files"]) != set(candidate_names):
        raise ValueError("PUBLIC_PATH_ALLOWLIST")
    refreshable_legacy_candidates = {str(HERE/name) for name in LEGACY_NAMES}
    refreshable_legacy_candidates.add(str(SCRIPTS/"test_native_request_observer_io.py"))
    for path, row in binding["public_files"].items():
        if Path(path).is_absolute() is not True or str(Path(path).resolve()) != path:
            raise ValueError("PUBLIC_CANONICAL_PATH")
        metadata = Path(path).lstat()
        if allow_candidate_source_refresh and not is_current and path in refreshable_legacy_candidates:
            if path == str(SCRIPTS/"test_native_request_observer_io.py"):
                if not stat.S_ISREG(metadata.st_mode) or oct(metadata.st_mode) != row["rawmode"]:
                    raise ValueError("REFRESHABLE_TEST_SOURCE_TYPE_OR_MODE")
            continue
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size != row["bytes"] or
                oct(metadata.st_mode) != row["rawmode"] or digest(path) != row["sha256"]):
            raise ValueError("PUBLIC_SOURCE_CHANGED")
    for name, row in binding["candidate_files"].items():
        candidate_root = Path(binding.get("candidate_root", HERE))
        if (not allow_candidate_source_refresh or is_current) and row != binding["public_files"][str(candidate_root/name)]:
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
    if not allow_candidate_source_refresh:
        gate = safe_overlay("request_observer_gate")
        sources = gate.effective_sources()
        effective = {key:hashlib.sha256(value.encode()).hexdigest() for key,value in sources.items()}
        if effective != binding["effective_sources"]:
            raise ValueError("EFFECTIVE_OVERLAY_SOURCE_PIN")
    return binding, sha


def refresh_current_binding(delivery_path, equality_path, runtime_receipt_path, output_parent,
                           expected_commit):
    """Create a new current bundle binding without mutating the historical binding."""
    template, template_sha = verify_binding(allow_candidate_source_refresh=True)
    bundle = current_binding.current_bundle(Path(delivery_path), Path(equality_path),
        Path(runtime_receipt_path), Path(output_parent), expected_commit)
    paths = required_paths(bundle) | {bundle["delivery"]["path"], bundle["equality"]["path"],
        bundle["runtime_receipt"]["path"], bundle["official_cli"]["path"]}
    previous = template["public_files"]
    candidate_paths = {str(HERE/name) for name in CURRENT_NAMES}
    refreshable_candidate_paths = candidate_paths | {str(SCRIPTS/"test_native_request_observer_io.py")}
    known_hashes = {
        bundle["delivery"]["path"]: bundle["delivery"]["sha256"],
        bundle["equality"]["path"]: bundle["equality"]["sha256"],
        bundle["runtime_receipt"]["path"]: bundle["runtime_receipt"]["sha256"],
        bundle["official_cli"]["path"]: bundle["official_cli"]["sha256"],
    }
    rows = []
    for path in sorted(paths):
        if path in refreshable_candidate_paths or path not in previous:
            rows.append(current_binding.file_row(path, known_hashes.get(path)))
        else:
            rows.append({"path":path, **previous[path]})
    gate = safe_overlay("request_observer_gate")
    sources = gate.effective_sources()
    effective = {key:hashlib.sha256(value.encode()).hexdigest() for key,value in sources.items()}
    refreshed = current_binding.current_binding_payload(template, bundle=bundle, rows=rows,
        candidate_root=HERE, candidate_names=CURRENT_NAMES, effective_sources=effective)
    refreshed["template_binding_sha256"] = template_sha
    path, sha = current_binding.write_binding_pair(refreshed, Path(output_parent))
    verified, verified_sha = verify_binding(sha, path, require_current=True)
    if verified_sha != sha or verified["current_bundle"] != bundle:
        raise ValueError("CURRENT_BINDING_SELF_CHECK")
    return {"schema":"cicada.request-observer-current-binding-refresh.v1",
        "status":"CURRENT_BINDING_READY_NONAUTH", "authority":"NONAUTH",
        "binding_path":str(path), "binding_sha256":sha,
        "alias_path":str(path.parent/"source-binding.json"),
        "template_binding_sha256":template_sha,
        "current_commit":bundle["current_commit"], "source_dirty":bundle["source_dirty"],
        "source_fingerprint":bundle["source_fingerprint"],
        "delivery_sha256":bundle["delivery"]["sha256"],
        "compiled_input_equality_sha256":bundle["equality"]["sha256"],
        "runtime_image_id":bundle["runtime_receipt"]["image_id"],
        "official_cli_version":bundle["official_cli"]["version"],
        "official_cli_sha256":bundle["official_cli"]["sha256"],
        "candidate_source_sha256":refreshed["candidate_files"],
        "effective_sources":refreshed["effective_sources"],
        "GO":"NOT_CREATED", "native_acceptance":"NOT_RUN"}


def require_current_bundle(binding):
    if type(binding) is not dict or binding.get("schema") != current_binding.SCHEMA:
        raise PermissionError("CURRENT_BINDING_REQUIRED")
    bundle = binding.get("current_bundle")
    if type(bundle) is not dict or bundle.get("schema") != current_binding.BUNDLE_SCHEMA:
        raise PermissionError("CURRENT_BUNDLE_REQUIRED")
    return bundle


def current_runtime(binding):
    return require_current_bundle(binding)["runtime_receipt"]["image_id"]


def current_cli(binding):
    cli = require_current_bundle(binding)["official_cli"]
    if cli != {"path":str(current_binding.CLI_BINARY), "sha256":current_binding.CLI_SHA256,
               "version":current_binding.CLI_VERSION}:
        raise PermissionError("CURRENT_CLI_PIN")
    return cli


def current_delivery(binding):
    bundle = require_current_bundle(binding)
    delivery, raw = bounded_json(bundle["delivery"]["path"])
    if hashlib.sha256(raw).hexdigest() != bundle["delivery"]["sha256"]:
        raise PermissionError("CURRENT_DELIVERY_CHANGED")
    return delivery


@contextlib.contextmanager
def deny_preflight_effects():
    """Read-only host inspection: no sockets, subprocesses, writes or credential metadata."""
    def deny(*args, **kwargs):
        raise PermissionError("ZERO_PAID_PREFLIGHT_EFFECT_DENIED")
    old_open, old_io_open = builtins.open, io.open
    old_stat, old_lstat, old_os_open = os.stat, os.lstat, os.open
    def public_path(path):
        if isinstance(path,(str,bytes,os.PathLike)) and (os.fsdecode(path)==CREDENTIAL or any(os.fsdecode(path)==prefix or os.fsdecode(path).startswith(prefix+"/") for prefix in ("/gpu1-share","/run/secrets"))):
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
            for owner,name in ((socket,"socket"),(socket,"socketpair"),(socket,"create_connection"),(socket,"getaddrinfo"),
                               (socket,"gethostbyname"),(ssl,"create_default_context"),(subprocess,"Popen"),(subprocess,"run"),
                               (subprocess,"call"),(subprocess,"check_call"),(subprocess,"check_output"),(os,"system")):
                stack.enter_context(patch.object(owner,name,deny))
            for owner,name,value in ((builtins,"open",readonly_open(old_open)),(io,"open",readonly_open(old_io_open)),
                                     (os,"stat",guarded_stat(old_stat)),(os,"lstat",guarded_stat(old_lstat)),
                                     (os,"open",guarded_os_open)):
                stack.enter_context(patch.object(owner,name,value))
            yield
    finally:
        sys.dont_write_bytecode=bytecode


def _preflight(expected_sha=None, binding_path=None):
    binding, sha = verify_binding(expected_sha, binding_path, require_current=True)
    gate = safe_overlay("request_observer_gate")
    source = gate.effective_sources()["gate"]
    delivery=current_delivery(binding)
    runtime_image=current_runtime(binding)
    cli=current_cli(binding)
    cls,legacy=gate.load_gate(delivery,binding,inspect_only=True)
    methods={name:getattr(cls,name) for name in gate.METHODS}
    namespace=methods["start_managed_servers"].__globals__
    if any(method.__globals__ is not namespace for method in methods.values()) or Path(namespace["HERE"]) != gate.OLD:
        raise ValueError("ABSOLUTE_LEGACY_GLOBAL_RESOLUTION")
    if (cli["version"] != current_binding.CLI_VERSION or cli["sha256"] != current_binding.CLI_SHA256 or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", runtime_image)):
        raise ValueError("CURRENT_RUNTIME_SOURCE_PINS")
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
        "current_product_revision":binding["current_bundle"]["current_commit"],
        "current_product_source_dirty":binding["current_bundle"]["source_dirty"],
        "current_product_source_fingerprint":binding["current_bundle"]["source_fingerprint"],
        "runtime_image_id":runtime_image,"official_cli_version":cli["version"],
        "official_cli_sha256":cli["sha256"],
        "methods":sorted(methods), "effective_sources":binding["effective_sources"],
        "import_resolution":"ACTUAL_HOST_PUBLIC_CLASS_GLOBALS_AND_BOOTSTRAP_SELECTION", "legacy_public_modules_imported":True,
        "fixture_constructor_called":False,
        "credential_metadata_accessed":False, "Runtime_calls":0,"provider_POSTs":0,"model_calls":0,
        "budget_seconds":{"normal":180,"terminal":30,"cleanup":30,"total":240},
        "native_ACCEPTANCE":"NOT_RUN", "real_Runtime":"NOT_RUN", "HTTP_TLS_semantic_parity":"NOT_PROVEN"}


def preflight(expected_sha=None, binding_path=None):
    with deny_preflight_effects():
        return _preflight(expected_sha, binding_path)


def native_phase_budget(normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    if type(normal_seconds) is not int or not DEFAULT_NATIVE_NORMAL_SECONDS <= normal_seconds <= MAX_NATIVE_NORMAL_SECONDS:
        raise PermissionError("NATIVE_NORMAL_SECONDS")
    terminal_end = normal_seconds + NATIVE_TERMINAL_SECONDS
    cleanup_end = terminal_end + NATIVE_CLEANUP_SECONDS
    return {"normal_seconds":normal_seconds,"terminal_seconds":NATIVE_TERMINAL_SECONDS,
            "cleanup_seconds":NATIVE_CLEANUP_SECONDS,"total_seconds":cleanup_end}


def expected_go(binding, binding_sha, run_id, wiring_sha, hard_stop_unix=0,
                normal_seconds=DEFAULT_NATIVE_NORMAL_SECONDS):
    if not re.fullmatch(r"cicada-two-turn-[a-z0-9]{12,32}", run_id or ""):
        raise ValueError("FRESH_RUN_ID")
    if binding.get("schema") == current_binding.SCHEMA:
        delivery = current_delivery(binding)
        output_parent = Path(binding["output_parent"])
        runtime_image = current_runtime(binding)
        cli_sha = current_cli(binding)["sha256"]
        delivery_sha = binding["current_bundle"]["delivery"]["sha256"]
        gate = safe_overlay("request_observer_gate")
        effective_source_hashes = {key:hashlib.sha256(value.encode()).hexdigest()
                                   for key,value in gate.effective_sources(normal_seconds).items()}
    else:
        delivery, _ = bounded_json(ACTUAL/"actual-delivery.json")
        output_parent = BINDING.parent
        runtime_image = RUNTIME
        cli_sha = CLI_SHA
        delivery_sha = DELIVERY_SHA
        effective_source_hashes = binding["effective_sources"]
    result = output_parent/("request-observer-native-result-"+run_id)
    claim = output_parent/("request-observer-execution-claim-"+run_id+".json")
    phase_budget = native_phase_budget(normal_seconds)
    return {"schema":"cicada.managed-five-observer-go.v1","scope":"managed-five-observer-diagnostic",
        "authority":"ROOT_NATIVE_DIAGNOSTIC_GO", "runtime_execution_authorized":True,
        "provider_credential_access_authorized":True,"model_dispatch_authorized":True,
        "unique_run":run_id,"result_dir":str(result),"claim_file":str(claim),
        "candidate_binding_sha256":binding_sha,"wiring_receipt_sha256":wiring_sha,
        "candidate_files":binding["candidate_files"],"effective_sources":effective_source_hashes,
        "observer_root_offline_receipt_sha256":ROOT_OFFLINE_SHA,"observer_root_review_sha256":ROOT_REVIEW_SHA,
        "max_native_turns":5,"max_manual_turns":3,"max_automatic_turns":2,
        **phase_budget,
        "max_fatal_diagnostic_capture_seconds":5,
        "phase_deadlines_absolute":True,"max_POST_attempts_per_Runtime":16,
        "request_max_retries":0,"stream_max_retries":0,"observer_retries":0,
        "model":"gpt-5.6-luna","runtime_image":runtime_image,"official_cli_sha256":cli_sha,
        "hub_image":delivery["hub_image"],"product_revision":delivery["commit"],
        "product_sha256":delivery["binary_sha256"],"helper_sha256":delivery["helper_sha256"],
        "node_source_fingerprint":delivery["fingerprint"],"config_template_sha256":CONFIG_SHA,
        "actual_delivery_sha256":delivery_sha,"require_native_pqtls":True,
        "a3_criterion":"INLINE_CORRELATED_REPLY_ORIGINAL_A_CONTEXT",
        "preparation_result_sha256":PREP_RESULT_SHA,"preparation_source_binding_sha256":PREP_BINDING_SHA,
        "independent_review_sha256":PREP_REVIEW_SHA,
        "credential_reference":CREDENTIAL,"credential_access_scope":"EXACT_RUNTIME_ONLY_READONLY",
        "credential_runtime_path":"/run/secrets/provider.env","cleanup_hard_stop_unix":hard_stop_unix,
        "io_diagnostics":{"enabled":True,"code_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer_io.py")]["sha256"],"max_rows":16,"max_bytes":32768},
        "test_request_observer":{"schema":"cicada.test-request-observer-go.v1",
            "code_sha256":binding["public_files"][str(SCRIPTS/"native_request_observer.py")]["sha256"],
            "upstream_base_url_sha256":binding["upstream_base_url_sha256"],
            "lifetime_seconds":normal_seconds,"max_POST_attempts_per_Runtime":16,"default_off":True}}


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
    if type(expected["cleanup_hard_stop_unix"]) is not int or now+expected["total_seconds"] > expected["cleanup_hard_stop_unix"]:
        raise PermissionError("CLEANUP_HARD_CUTOFF")


def native_https_mode(args):
    mode=getattr(args,"native_https",False)
    if type(mode) is not bool:
        raise PermissionError("NATIVE_HTTPS_TYPE")
    if mode and (getattr(args,"execute_diagnostic",False) is not True or
            getattr(args,"scenario","g1") not in ("g1","g2-g3") or
            getattr(args,"prepare_native_zero",False) is True or
            getattr(args,"enable_io_diagnostics",False) is not False or
            getattr(args,"response_byte_passthrough",False) is not False):
        raise PermissionError("NATIVE_HTTPS_LANE")
    return mode


def native_normal_seconds(args):
    raw = getattr(args, "native_normal_seconds", None)
    if raw is None:
        return DEFAULT_NATIVE_NORMAL_SECONDS
    if not native_https_mode(args):
        raise PermissionError("NATIVE_NORMAL_SECONDS_LANE")
    return native_phase_budget(raw)["normal_seconds"]


def response_passthrough_mode(args):
    mode = getattr(args, "response_byte_passthrough", False)
    if type(mode) is not bool:
        raise PermissionError("RESPONSE_MODE_TYPE")
    if mode and (getattr(args, "execute_diagnostic", False) is not True or
                 getattr(args, "enable_io_diagnostics", False) is not True or
                 getattr(args, "prepare_native_zero", False) is True or
                 getattr(args, "scenario", "g1") != "g2-g3"):
        raise PermissionError("RESPONSE_MODE_LANE")
    return mode


FAILURE_SOURCE_LABELS = {
    str(HERE / "request_observer_run.py"): "request_observer_run.py",
    str(HERE / "request_observer_gate.py"): "request_observer_gate.py",
    str(SCRIPTS / "native_request_observer.py"): "native_request_observer.py",
    **{str(Path("/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/managed") / name): name
       for name in ("managed_gate.py", "migration.py", "native_protocol.py", "managed_rpc.py")},
    **{label: label for label in (
        "<effective-request-observer-gate>", "<effective-request-observer-audit>",
        "<effective-request-observer-command>", "<effective-request-observer-provider>",
        "<effective-request-observer-provider-transport>", "<owned-lifecycle>",
        "<owned-g2-four-manual-turns>", "<owned-g2-six-audit>",
        "<owned-pre-stop-fresh-witness>", "<owned-two-pass-hub-retarget>",
        "<owned-g2-preparation>", "<owned-g2-g3-flow>", "<owned-g2-inline-reply>",
        "<owned-g1-inline-reply-method>", "<owned-g2-six-cap>", "<owned-g2-six-budget>")},
}
FAILURE_FUNCTIONS = frozenset((
    "execute", "manual_turn", "wait_turn", "wait", "automatic_turn", "auto",
    "limit", "request", "check", "audit", "audit_rpc", "audit_turn",
    "managed_golden_flow", "g2_initial_binding", "g2_second_binding",
    "g2_b_continuity", "g2_mcp_call", "g2_current_actor", "g2_revoke_and_visibility",
    "g3_restore_snapshot", "audit_inline_reply", "command", "guarded_command",
    "docker", "helper", "provider", "abort_owned", "pq_transport_witness",
    "build", "start_nodes", "prepare_managed", "start_managed_servers",
))


def public_failure_origin(error):
    """Only the terminal frame's fixed public label/function/line; no error text."""
    try:
        terminal = error.__traceback__
        while terminal is not None and terminal.tb_next is not None:
            terminal = terminal.tb_next
        if terminal is None:
            return None
        code = terminal.tb_frame.f_code
        label = FAILURE_SOURCE_LABELS.get(code.co_filename)
        line = terminal.tb_lineno
        if (label is None or code.co_name not in FAILURE_FUNCTIONS or
                type(line) is not int or not 1 <= line <= 1000000):
            return None
        return {"source_label": label, "function": code.co_name, "line": line}
    except Exception:
        # Evidence projection cannot replace the execution failure or cleanup.
        return None


def execute(args):
    global EXECUTION_EFFECTS_STARTED
    native_mode = native_https_mode(args)
    normal_seconds = native_normal_seconds(args)
    response_mode = response_passthrough_mode(args)
    if not getattr(args,"preparation_result",None) or not getattr(args,"preparation_result_sha",None):
        raise PermissionError("LATEST_RUNTIME_NOT_READY")
    with deny_preflight_effects():
        binding,binding_sha,delivery,prior=latest_dispatch_inputs(args)
    # No legacy imports, credential stat or effects before all public/fresh GO guards.
    if not native_mode and not getattr(args,"enable_io_diagnostics",False):
        raise PermissionError("IO_DIAGNOSTICS_OPT_IN_REQUIRED")
    required = (args.go_receipt,args.go_receipt_sha,args.binding_sha,args.wiring_receipt,args.wiring_receipt_sha,args.unique_run,getattr(args,"cleanup_hard_stop_unix",None))
    if not all(required):
        raise PermissionError("FRESH_GO_AND_WIRING_RECEIPT_REQUIRED")
    go_path=Path(args.go_receipt)
    output_parent = Path(binding["output_parent"])
    if go_path.parent.absolute()!=output_parent or not go_path.name.startswith("request-observer-") or not go_path.name.endswith(".json"):
        raise PermissionError("FRESH_GO_PUBLIC_PATH")
    receipt_path = Path(args.wiring_receipt)
    if receipt_path.parent.resolve()!=output_parent or not receipt_path.name.startswith("request-observer-wiring-"):
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
                   "artifact_started_MONOTONIC":started,"normal_end_MONOTONIC":started+normal_seconds,
                   "hard_end_MONOTONIC":started+expected["total_seconds"]},out)
        out.flush();os.fsync(out.fileno())
    EXECUTION_EFFECTS_STARTED = True
    gate_overlay=safe_overlay("request_observer_gate")
    cls,legacy=gate_overlay.load_gate(delivery,binding,scenario=getattr(args,"scenario","g1"),
                                      normal_seconds=normal_seconds)
    ns=types.SimpleNamespace(execute=True,run_native=True,result_dir=str(result),product_repo=delivery["source_repo"],
        expected_product_revision=delivery["commit"],expected_source_fingerprint=delivery["fingerprint"],
        runtime_image=current_runtime(binding),expected_codex_version="codex-cli "+current_cli(binding)["version"],expected_cli_sha256=current_cli(binding)["sha256"],
        producer_receipt_sha256=delivery["package_metadata_sha256"],producer_receipt=str(Path(delivery["package"])/"BUILD-METADATA.json"),
        exact_clean_image_metadata=delivery["hub_receipt_path"],exact_clean_image_metadata_sha256=delivery["hub_receipt_sha256"],
        config_template=str(CONFIG),config_template_sha=CONFIG_SHA,source_binding_sha=binding_sha,
        offline_checks_sha=args.wiring_receipt_sha,artifact_started=started,go=go,credential_file=CREDENTIAL,
        binding_file=str(args.binding_file),
        preparation_result=args.preparation_result,preparation_result_sha256=args.preparation_result_sha,
        latest_runtime=True,delivery_sha=args.delivery_sha,equality_sha=args.equality_sha,
        closed_failure_diagnostics=getattr(args,"enable_closed_failure_diagnostics",False),
        native_normal_seconds=normal_seconds,
        response_byte_passthrough=response_mode,
        native_https=native_mode,test_request_observer=not native_mode,request_observer_source=str(SCRIPTS/"native_request_observer.py"),candidate_binding_sha256=binding_sha)
    gate=None
    try:
        gate=cls(ns);gate.build();gate.start_nodes();gate.prepare_managed();gate.managed_golden_flow()
    except Exception as error:
        if gate is None:
            raise
        gate.result.update(status="FAIL",failure_phase=gate.phase,failure_class=type(error).__name__,
            failure_origin=public_failure_origin(error),
            failure_origin_scope="FIXED_PUBLIC_TERMINAL_FRAME_ONLY_NO_MESSAGE_OR_LOCALS")
    finally:
        if gate is not None:
            gate.cleanup()
    return gate.result["terminal_exit_code"]


LATEST_VERSION = current_binding.CLI_VERSION
# Kept only as a read-only fixture value for historical unit fixtures. Current
# CLI entrypoints require a fresh 0.162 binding and never dispatch this image.
LATEST_RUNTIME = "sha256:e7540d8a8ff83952fe0dc8e46c20446d45566a2f6fb1195a98d0ab6afe216a29"
LATEST_CLI_SHA = current_binding.CLI_SHA256
ZERO_CONFIG = '\n'.join(['model = "gpt-5.6-luna"','model_provider = "basil"',
    'sandbox_mode = "workspace-write"','approval_policy = "on-request"','approvals_reviewer = "user"',
    '# "basil" is a fixture alias only; its endpoint remains synthetic loopback.',
    '[model_providers.basil]','name="Synthetic zero-model provider"',
    'base_url="http://127.0.0.1:9/v1"','wire_api="responses"',
    'request_max_retries = 4',''])


def latest_dispatch_inputs(args):
    """Fresh preparation is evidence, never model authorization by itself."""
    binding,sha=verify_binding(args.binding_sha, getattr(args,"binding_file",None), require_current=True)
    bundle=require_current_bundle(binding)
    if (str(Path(args.delivery)) != bundle["delivery"]["path"] or
            str(Path(args.compiled_input_equality)) != bundle["equality"]["path"] or
            args.current_commit != bundle["current_commit"] or
            args.runtime_image != bundle["runtime_receipt"]["image_id"]):
        raise PermissionError("CURRENT_BUNDLE_ARGUMENTS")
    output_parent = Path(binding["output_parent"])
    preparation_path = Path(args.preparation_result)
    review_path = Path(args.preparation_review)
    if (preparation_path.parent.resolve() != output_parent.resolve() or
            not preparation_path.name.startswith("native-preparation-") or
            review_path.parent.resolve() != output_parent.resolve() or
            not review_path.name.startswith("native-preparation-review-")):
        raise PermissionError("CURRENT_PREPARATION_PATH")
    delivery,raw=bounded_json(args.delivery)
    if hashlib.sha256(raw).hexdigest()!=args.delivery_sha:raise PermissionError("LATEST_DELIVERY_PIN")
    scenario_inputs(args, delivery)
    equality,raw=bounded_json(args.compiled_input_equality)
    if (hashlib.sha256(raw).hexdigest()!=args.equality_sha or equality.get("status")!="COMPILED_INPUTS_EXACT" or
        equality.get("current_commit")!=args.current_commit or
        equality.get("artifact_compiled_inputs_sha256")!=equality.get("current_compiled_inputs_sha256") or
        equality.get("artifact_binary_sha256")!=delivery.get("binary_sha256") or
        equality.get("product_artifact_origin_dirty",equality.get("source_dirty"))!=bundle["source_dirty"] or
        delivery.get("commit")!=bundle["current_commit"] or delivery.get("source_dirty")!=bundle["source_dirty"] or
        delivery.get("fingerprint")!=bundle["source_fingerprint"]):
        raise PermissionError("LATEST_COMPILED_INPUT_EQUALITY")
    if getattr(args,"scenario","g1") == "g2-g3": g2_component_inputs(delivery,equality,current=True)
    prior,raw=bounded_json(args.preparation_result,1<<20)
    prep=prior.get("preparation_binding",{})
    if (hashlib.sha256(raw).hexdigest()!=args.preparation_result_sha or
        prior.get("status")!="PREPARATION_PASS_NATIVE_NOT_RUN" or prior.get("terminal_exit_code")!=0 or
        prior.get("cleanup_owned_resources") is not True or prior.get("candidate_sources_unchanged") is not True or
        prior.get("observer_shutdown")!={"a":"EXPECTED_EOF_CONFIRMED","b":"EXPECTED_EOF_CONFIRMED"} or
        prior.get("models_invoked")!=0 or prior.get("actual_turn_started_count")!=0 or
        prior.get("actual_turn_started_event_count")!=0 or prior.get("paid_turn_start_submissions")!=0 or
        prep.get("source_binding_sha256")!=sha or prep.get("runtime_image_id")!=bundle["runtime_receipt"]["image_id"] or
        prep.get("official_cli_sha256")!=bundle["official_cli"]["sha256"] or prep.get("expected_codex_version")!="codex-cli "+bundle["official_cli"]["version"] or prep.get("current_delivery_sha256")!=args.delivery_sha or
        prep.get("compiled_input_equality_sha256")!=args.equality_sha or
        prep.get("fixture_scenario", "g1")!=getattr(args,"scenario","g1") or
        (getattr(args,"scenario","g1")=="g2-g3" and prep.get("component_proof_sha256") != delivery["component_proof_sha256"])):
        raise PermissionError("LATEST_RUNTIME_NOT_READY")
    review,raw=bounded_json(args.preparation_review)
    if hashlib.sha256(raw).hexdigest()!=args.preparation_review_sha or review.get("status")!="PASS" or review.get("result_sha256")!=args.preparation_result_sha:
        raise PermissionError("LATEST_PREPARATION_REVIEW")
    return binding,sha,delivery,prior


def expected_latest_go(binding,sha,args,delivery):
    expected=expected_go(binding,sha,args.unique_run,args.wiring_receipt_sha,args.cleanup_hard_stop_unix,
                         native_normal_seconds(args))
    bundle=require_current_bundle(binding)
    runtime=require_current_bundle(binding)["runtime_receipt"]["image_id"]
    cli=current_cli(binding)
    mode = response_passthrough_mode(args)
    expected.update(response_byte_passthrough=mode, response_transport_semantics=(
        "NATIVE_HTTP_VALIDATES_RESPONSE_EOF_NOT_BUSINESS_COMPLETION" if mode else "OBSERVER_STRICT_HTTP_FRAMING"),
        response_byte_ceiling=4259840 if mode else None, response_chunk_ceiling=65536 if mode else None)
    expected.update(runtime_image=runtime,official_cli_sha256=cli["sha256"],
        hub_image=delivery["hub_image"],product_revision=delivery["commit"],product_sha256=delivery["binary_sha256"],
        helper_sha256=delivery["helper_sha256"],node_source_fingerprint=delivery["fingerprint"],
        actual_delivery_sha256=args.delivery_sha,preparation_result_sha256=args.preparation_result_sha,
        preparation_source_binding_sha256=sha,independent_review_sha256=args.preparation_review_sha,
        compiled_input_equality_sha256=args.equality_sha,
        preparation_provider_scope="SYNTHETIC_LOOPBACK_ZERO_MODEL_NOT_PROVIDER_PARITY",
        current_bundle_sha256=hashlib.sha256(json.dumps(bundle,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        official_cli_version=cli["version"])
    if getattr(args,"scenario","g1") != "g1":
        expected.update(fixture_scenario="g2-g3",component_proof_sha256=delivery["component_proof_sha256"],max_native_turns=6,max_manual_turns=4,max_automatic_turns=2)
    if native_https_mode(args):
        for key in ("max_POST_attempts_per_Runtime","observer_retries","io_diagnostics","test_request_observer"):
            expected.pop(key)
        expected.update(native_https=True,response_transport_semantics="NATIVE_HTTPS_OPAQUE_PROXY",
            HTTP_POST_COUNT="UNAVAILABLE",POST16_ENFORCEMENT="UNAVAILABLE",
            max_accepted_TCP_connections_per_Runtime=16,
            TCP_connection_scope="ADMITTED_SOCKETS_NOT_HTTP_POSTS_OR_COMPLETED_CONNECTS")
    return expected


G2_TLS_INPUT_SHA = "6485dde13d6ce11f2b086c6971c5f49f9ef7cc0fe7672225987c69260ac159a7"

def g2_tls_fixture_source(raw):
    """Pure build input transformation; never installs or mutates frozen source."""
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != G2_TLS_INPUT_SHA:
        raise ValueError("G2_TLS_INPUT_PIN")
    source = raw.decode("utf-8")
    substitutions = (
        ('\tsetups := []nodeSetup{{id: meta.NodeA, token: sourceToken, dns: "node-a.synthetic.invalid", owner: owner, state: meta.SourceState}, {id: meta.NodeB, token: targetToken, dns: "node-b.synthetic.invalid", owner: owner, state: meta.TargetState}}',
         '\tbobOwner := owner\n\tif meta.Scenario == "g2-g3" { bobOwner, err = loadFixtureIdentity(fixtureRoot, "bob-owner-private", "owner.key"); if err != nil { return err } }\n\tsetups := []nodeSetup{{id: meta.NodeA, token: sourceToken, dns: "node-a.synthetic.invalid", owner: owner, state: meta.SourceState}, {id: meta.NodeB, token: targetToken, dns: "node-b.synthetic.invalid", owner: bobOwner, state: meta.TargetState}}'),
        ('\t\tn.device, err = db.GetClientDevice(old.OwnerID, meta.DeviceID)',
         '\t\t_, _, deviceID, _, scopeErr := fixtureNodeScope(meta, n.id); if scopeErr != nil { return scopeErr }\n\t\tn.device, err = db.GetClientDevice(old.OwnerID, deviceID)'),
        ('\tknown := [][]byte{owner.Public().SigningPublic, hub.Public().SigningPublic}',
         '\tknown := [][]byte{owner.Public().SigningPublic, hub.Public().SigningPublic}\n\tif meta.Scenario == "g2-g3" { known = append(known, bobOwner.Public().SigningPublic) }'),
        ('for _,n:=range setups {if n.binding.OwnerID!=meta.OwnerID {return errors.New("same Owner identity required")};if err=writeJSONExclusive(filepath.Join(n.state,"native-tls-proof.json"),map[string]any{"version":1,"hub_id":hubID,"node_id":n.id,"owner_id":meta.OwnerID,"group_id":meta.GroupID,"tls_state":"TLS_ACTIVE","active_config":distributionActiveConfigPath(result.nodes[n.id])},0600);err!=nil{return err}}',
         'for _,n:=range setups {ownerID,keyID,_,groupID,scopeErr:=fixtureNodeScope(meta,n.id);if scopeErr!=nil{return scopeErr};if n.binding.OwnerID!=ownerID || n.binding.OwnerKeyID!=keyID {return errors.New("exact per-Node Owner identity required")};if err=writeJSONExclusive(filepath.Join(n.state,"native-tls-proof.json"),map[string]any{"version":1,"hub_id":hubID,"node_id":n.id,"owner_id":ownerID,"group_id":groupID,"tls_state":"TLS_ACTIVE","active_config":distributionActiveConfigPath(result.nodes[n.id])},0600);err!=nil{return err}}'),
    )
    for old, new in substitutions:
        if source.count(old) != 1:
            raise ValueError("G2_TLS_EXACT_CONTEXT")
        source = source.replace(old, new, 1)
    source += "\nfunc init() { nativeTLSBootstrap = tlsBootstrap }\n"
    return source.encode("utf-8")

G2_TLS_INPUT_PATH = Path('/home/zyf/CICADA_real_codex_prep_20261002/driver/proposals/managed-five-clean021-20261003/checkpoint-native-tls-v6/authority-bootstrap/tls_bootstrap.go')
G2_SOURCE_ROOT = Path('/home/zyf/CICADA/cicada-go')
G2_BUILD_ROOT = BINDING.parent/'g2g3-helper-build-20261007d'
G2_PRODUCT_REVIEW_PATH = Path('/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/root-g2g3-current-product-mcp-review-20261007a.NONAUTH.json')


def g2_public_path(path, *, exact=None):
    if type(path) is not str or not Path(path).is_absolute() or os.path.normpath(path) != path:
        raise PermissionError('G2_PUBLIC_PATH_LEXICAL')
    value = Path(path)
    if (exact is not None and value != exact) or (exact is None and not value.is_relative_to(G2_BUILD_ROOT)):
        raise PermissionError('G2_PUBLIC_BUILD_DOMAIN')
    if str(value.resolve()) != path:
        raise PermissionError('G2_PUBLIC_PATH_SYMLINK')
    return value


G2_PRODUCT_REVIEW_SHA = 'c6e76516e010453cc7d1bd547e14796234c43020104535c605ef5f4f62cbe153'
G2_SOURCE_PATHS = {str(G2_SOURCE_ROOT/'cmd/cicada-v68fixture'/name)
                   for name in ('main.go','main_test.go','payload_profile_test.go')}


def g2_public_row(row, *, paths=None):
    if (type(row) is not dict or set(row) != {'path','sha256','bytes','rawmode'}
        or type(row['path']) is not str or not Path(row['path']).is_absolute()
        or type(row['bytes']) is not int or row['bytes'] < 1
        or type(row['rawmode']) is not int or not stat.S_ISREG(row['rawmode'])
        or type(row['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',row['sha256'])):
        raise PermissionError('G2_SOURCE_ROW_SHAPE')
    path = Path(row['path'])
    if (os.path.normpath(row['path']) != row['path'] or (paths is not None and row['path'] not in paths) or
        (paths is None and not path.is_relative_to(G2_SOURCE_ROOT) and not path.is_relative_to(G2_BUILD_ROOT))):
        raise PermissionError('G2_SOURCE_PATH_SCOPE')
    if str(path.resolve()) != row['path']: raise PermissionError('G2_SOURCE_PATH_SYMLINK')
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode != row['rawmode'] or
        metadata.st_size != row['bytes'] or digest(path) != row['sha256']):
        raise PermissionError('G2_SOURCE_BYTES_MODE_CHANGED')


def g2_legacy_component_inputs(delivery, equality):
    """Measured current product + source-validated reused D helper; old full-tree proof is not authority."""
    if equality.get('schema') != 'cicada.native-g2g3-component-inputs.v1' or equality.get('fixture_scenario') != 'g2-g3':
        raise PermissionError('G2_COMPONENT_EQUALITY_SCHEMA')
    proof_path = g2_public_path(delivery['component_proof_path'])
    proof, raw = bounded_json(proof_path)
    pin = hashlib.sha256(raw).hexdigest()
    expected_keys = {'schema','fixture_scenario','product_binary_sha256','product_component_review',
        'fixture_source_rows','tls_recipe','compiled_inputs_manifest','helper_binary','helper_build_receipt'}
    if (type(proof) is not dict or set(proof) != expected_keys or proof['schema'] != 'cicada.native-g2g3-components.v1'
        or proof['fixture_scenario'] != 'g2-g3' or pin != delivery['component_proof_sha256']
        or equality.get('component_proof_sha256') != pin or proof['product_binary_sha256'] != delivery['binary_sha256']):
        raise PermissionError('G2_COMPONENT_PROOF_PIN')
    for name in ('product_component_review','helper_binary','helper_build_receipt'):
        row = proof[name]
        if type(row) is not dict or set(row) != {'path','sha256'} or not re.fullmatch('[0-9a-f]{64}',row.get('sha256','')):
            raise PermissionError('G2_COMPONENT_ARTIFACT_SHAPE')
        path = g2_public_path(row['path'],exact=G2_PRODUCT_REVIEW_PATH if name == 'product_component_review' else None)
        if not path.is_absolute() or path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or digest(path) != row['sha256']:
            raise PermissionError('G2_COMPONENT_ARTIFACT_PIN')
    if proof['product_component_review']['sha256'] != G2_PRODUCT_REVIEW_SHA or proof['helper_binary'] != {'path':delivery['helper'],'sha256':delivery['helper_sha256']}:
        raise PermissionError('G2_PRODUCT_HELPER_PROVENANCE')
    rows = proof['fixture_source_rows']
    if type(rows) is not list or len(rows) != 3 or any(type(row) is not dict for row in rows) or {row.get('path') for row in rows} != G2_SOURCE_PATHS:
        raise PermissionError('G2_EXACT_FIXTURE_SOURCES')
    for row in rows: g2_public_row(row, paths=G2_SOURCE_PATHS)
    recipe = proof['tls_recipe']
    recipe_keys = {'input_path','input_sha256','output_path','output_sha256','output_bytes','generator_function_sha256','generator_hash_representation'}
    if type(recipe) is not dict or set(recipe) != recipe_keys or recipe['input_path'] != str(G2_TLS_INPUT_PATH) or recipe['input_sha256'] != G2_TLS_INPUT_SHA or recipe['generator_hash_representation'] != 'source':
        raise PermissionError('G2_TLS_RECIPE_SHAPE')
    import ast
    generator_source = Path(__file__).read_text()
    tree = ast.parse(generator_source)
    function = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'g2_tls_fixture_source')
    function_sha = hashlib.sha256(ast.get_source_segment(generator_source,function).encode()).hexdigest()
    produced = g2_tls_fixture_source(G2_TLS_INPUT_PATH.read_bytes())
    output = g2_public_path(recipe['output_path'],exact=G2_BUILD_ROOT/'tls_bootstrap.go')
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISREG(output.lstat().st_mode)
        or type(recipe['output_bytes']) is not int or recipe['output_bytes'] != len(produced)
        or recipe['generator_function_sha256'] != function_sha
        or recipe['output_sha256'] != hashlib.sha256(produced).hexdigest() or output.read_bytes() != produced):
        raise PermissionError('G2_GENERATED_TLS_PIN')
    manifest_ref = proof['compiled_inputs_manifest']
    if type(manifest_ref) is not dict or set(manifest_ref) != {'path','sha256','product_count','helper_count','projection_sha256'}:
        raise PermissionError('G2_MANIFEST_REFERENCE')
    manifest_path = g2_public_path(manifest_ref['path'])
    manifest, raw = bounded_json(manifest_path, 1 << 20)
    if (set(manifest) != {'schema','fixture_scenario','components','module_inputs','selection','pqtls_closure','source_dirty'} or
        manifest.get('source_dirty') is not True): raise PermissionError('G2_MANIFEST_SHAPE')
    if hashlib.sha256(raw).hexdigest() != manifest_ref['sha256'] or manifest.get('schema') != 'cicada.native-selected-component-inputs.v1' or manifest.get('fixture_scenario') != 'g2-g3':
        raise PermissionError('G2_MANIFEST_PIN_SCHEMA')
    selection = manifest.get('selection')
    helper_keys = {'CGO_ENABLED','Go_version','actual_builder_image','actual_go_list_stream_sha256','build_receipt_sha256','scope','tags'}
    product_keys = {'historical_actual_go_list_receipt_sha256','scope'}
    if (type(selection) is not dict or set(selection) != {'product','helper'} or
        type(selection['helper']) is not dict or set(selection['helper']) != helper_keys or
        type(selection['product']) is not dict or set(selection['product']) != product_keys):
        raise PermissionError('G2_SELECTION_SCHEMA')
    helper_selection = selection['helper']
    if (type(helper_selection['CGO_ENABLED']) is not int or helper_selection['CGO_ENABLED'] != 1 or
        helper_selection['Go_version'] != 'go version go1.27.1 linux/amd64' or helper_selection['tags'] != 'cicada_pqtls' or
        helper_selection['actual_builder_image'] != 'sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195' or
        helper_selection['build_receipt_sha256'] != proof['helper_build_receipt']['sha256'] or
        not re.fullmatch('[0-9a-f]{64}',helper_selection['actual_go_list_stream_sha256']) or
        selection['product']['historical_actual_go_list_receipt_sha256'] != 'c697accbb459510f087be08d735e47d6dbdd14de88daf54f066c62186c2c4b15' or
        any(type(selection[name]['scope']) is not str or not selection[name]['scope'] for name in ('product','helper')) or
        manifest.get('pqtls_closure') != 'f4f0969bfff33d505e542dc234b97bb5358956474dd04ad455046e5390f8a4a3'):
        raise PermissionError('G2_SELECTION_PROVENANCE')
    built, _ = bounded_json(proof['helper_build_receipt']['path'])
    if (built.get('status') != 'PASS_BUILD_AND_TAGGED_FIXTURE_TESTS' or built.get('actual_container_exit_code') != 0 or
        built.get('frozen_three_Go_sources_unchanged') is not True or built.get('credential_mounts') != 0 or built.get('models') != 0 or
        built.get('helper_binary_sha256') != delivery['helper_sha256'] or
        built.get('outputs',{}).get('helper-go-list.json',{}).get('sha256') != helper_selection['actual_go_list_stream_sha256']):
        raise PermissionError('G2_ACTUAL_HELPER_BUILD_RECEIPT')
    components = manifest.get('components')
    if type(components) is not dict or set(components) != {'product','helper'}:
        raise PermissionError('G2_MANIFEST_COMPONENTS')
    for name, selected in components.items():
        if type(selected) is not list or not 0 < len(selected) <= 1000 or len(selected) != manifest_ref[name+'_count']:
            raise PermissionError('G2_MANIFEST_COMPONENT_COUNT')
        paths = [row.get('path') for row in selected if type(row) is dict]
        if len(paths) != len(selected) or any(type(path) is not str for path in paths) or paths != sorted(set(paths)):
            raise PermissionError('G2_MANIFEST_DUPLICATE_ORDER')
        for row in selected:
            path = Path(row['path'])
            if not path.is_relative_to(G2_SOURCE_ROOT) and path != output:
                raise PermissionError('G2_COMPILED_SOURCE_DOMAIN')
            if '.cicada-data' in path.parts and path != output:
                raise PermissionError('G2_COMPILED_PRIVATE_DOMAIN')
            g2_public_row(row)
    if len(components['product']) != 457 or type(manifest_ref['helper_count']) is not int:
        raise PermissionError('G2_PRODUCT_COMPONENT_COUNT')
    modules = manifest.get('module_inputs')
    if type(modules) is not list or len(modules) != 2 or any(type(row) is not dict for row in modules) or {row.get('path') for row in modules} != {str(G2_SOURCE_ROOT/'go.mod'),str(G2_SOURCE_ROOT/'go.sum')}:
        raise PermissionError('G2_MODULE_INPUTS')
    for row in modules: g2_public_row(row)
    projection = hashlib.sha256(json.dumps(components,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
    if projection != manifest_ref['projection_sha256'] or projection != equality.get('artifact_compiled_inputs_sha256') or projection != equality.get('current_compiled_inputs_sha256'):
        raise PermissionError('G2_COMPILED_PROJECTION')
    return pin


G2_CURRENT_EVIDENCE_ROOT = Path('/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007')
G2_CURRENT_SOURCE_ROOT = Path('/home/zyf/CICADA/cicada-go')
G2_CURRENT_REPOSITORY_ROOT = Path('/home/zyf/CICADA')
G2_CURRENT_MODULE_PATH = 'github.com/cicada-ai/cicada'
G2_GO_FILE_FIELDS = ('GoFiles','CgoFiles','CFiles','CXXFiles','MFiles','HFiles','SFiles','SysoFiles','EmbedFiles')


def g2_current_path(path, *, roots, exact=None):
    if type(path) is not str or not Path(path).is_absolute() or os.path.normpath(path) != path:
        raise PermissionError('G2_CURRENT_PATH_LEXICAL')
    value=Path(path)
    if (exact is not None and value != exact) or (exact is None and not any(value.is_relative_to(root) for root in roots)):
        raise PermissionError('G2_CURRENT_PATH_SCOPE')
    if str(value.resolve(strict=True)) != path:
        raise PermissionError('G2_CURRENT_PATH_SYMLINK')
    metadata=value.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError('G2_CURRENT_FILE_TYPE')
    return value


def g2_current_json_stream(path, *, limit=32<<20, max_objects=10000):
    with Path(path).open('rb') as stream:
        raw=stream.read(limit+1)
    if len(raw)>limit:
        raise PermissionError('G2_CURRENT_GO_LIST_LIMIT')
    try: text=raw.decode('utf-8')
    except UnicodeDecodeError as error: raise PermissionError('G2_CURRENT_GO_LIST_UTF8') from error
    decoder=json.JSONDecoder(); offset=0; values=[]
    while offset<len(text):
        while offset<len(text) and text[offset].isspace(): offset+=1
        if offset==len(text): break
        try: value,offset=decoder.raw_decode(text,offset)
        except json.JSONDecodeError as error: raise PermissionError('G2_CURRENT_GO_LIST_JSON') from error
        if type(value) is not dict or len(values)>=max_objects:
            raise PermissionError('G2_CURRENT_GO_LIST_OBJECTS')
        values.append(value)
    if not values:
        raise PermissionError('G2_CURRENT_GO_LIST_EMPTY')
    return values


def g2_current_prestart_script(prestart, *, schema, revision, dirty, builder_image, repository_mount):
    command=prestart.get('command')
    if (prestart.get('schema')!=schema or prestart.get('source_revision')!=revision or
            prestart.get('source_dirty') is not dirty or prestart.get('builder_image')!=builder_image or
            prestart.get('credential_mounts')!=0 or prestart.get('model_calls')!=0 or
            type(command) is not list):
        raise PermissionError('G2_CURRENT_PRESTART_RECEIPT')
    def pair(option,value):
        return option in command and command.index(option)+1<len(command) and command[command.index(option)+1]==value
    required=(('--network','none'),('--cap-drop','ALL'),('--security-opt','no-new-privileges'),('--user','1000:1000'))
    if (any(not pair(option,value) for option,value in required) or '--read-only' not in command or
            repository_mount not in command or 'GOPROXY=off' not in command or 'GOSUMDB=off' not in command or
            'GOTOOLCHAIN=local' not in command or 'CGO_ENABLED=1' not in command or 'GOMODCACHE=/go/pkg/mod' not in command):
        raise PermissionError('G2_CURRENT_PRESTART_SANDBOX')
    if not command or type(command[-1]) is not str:
        raise PermissionError('G2_CURRENT_PRESTART_COMMAND')
    return command[-1]


def g2_current_go_sources(path, *, source_root, go_list_root):
    """Derive selected module source/embed paths from the captured `go list -deps -json`."""
    selected=set()
    for package in g2_current_json_stream(path):
        module=package.get('Module')
        if type(module) is not dict or module.get('Path') != G2_CURRENT_MODULE_PATH or module.get('Main') is not True:
            continue
        directory=package.get('Dir')
        if type(directory) is not str or not Path(directory).is_absolute() or os.path.normpath(directory)!=directory:
            raise PermissionError('G2_CURRENT_GO_LIST_DIRECTORY')
        directory_path=Path(directory)
        try: relative=directory_path.relative_to(go_list_root)
        except ValueError as error: raise PermissionError('G2_CURRENT_GO_LIST_DOMAIN') from error
        host_directory=source_root/relative
        for field in G2_GO_FILE_FIELDS:
            names=package.get(field,[])
            if type(names) is not list or any(type(name) is not str for name in names):
                raise PermissionError('G2_CURRENT_GO_LIST_FILES')
            for name in names:
                file_path=Path(name)
                if file_path.is_absolute() or '..' in file_path.parts or not file_path.parts:
                    raise PermissionError('G2_CURRENT_GO_LIST_FILE_PATH')
                selected.add(str(host_directory/file_path))
    if not selected:
        raise PermissionError('G2_CURRENT_GO_LIST_NO_MAIN_MODULE')
    return selected


def g2_current_source_row(row, *, inventory, allowed_extra=()):
    g2_public_row(row, paths=None)
    path=Path(row['path'])
    if path.is_relative_to(G2_CURRENT_SOURCE_ROOT):
        relative=str(path.relative_to(G2_CURRENT_REPOSITORY_ROOT))
        inventory_row=inventory.get(relative)
        if type(inventory_row) is not dict or (
                inventory_row.get('content_sha256') != row['sha256'] or
                inventory_row.get('size_bytes') != row['bytes'] or
                inventory_row.get('raw_mode') != oct(row['rawmode'])):
            raise PermissionError('G2_CURRENT_SOURCE_INVENTORY_ROW')
    elif str(path) not in allowed_extra:
        raise PermissionError('G2_CURRENT_SOURCE_DOMAIN')


def g2_current_component_inputs(delivery, equality):
    """Verify a current dirty-aware product/helper proof from its actual v2 receipts."""
    if equality.get('schema') != 'cicada.native-g2g3-component-inputs.v2' or equality.get('fixture_scenario') != 'g2-g3':
        raise PermissionError('G2_CURRENT_EQUALITY_SCHEMA')
    if (type(delivery.get('component_proof_path')) is not str or
            not re.fullmatch('[0-9a-f]{64}',delivery.get('component_proof_sha256',''))):
        raise PermissionError('G2_CURRENT_DELIVERY_PROOF_REFERENCE')
    proof_path=g2_current_path(delivery['component_proof_path'],roots=(G2_CURRENT_EVIDENCE_ROOT,))
    if proof_path.name!='component-proof.NONAUTH.json':
        raise PermissionError('G2_CURRENT_PROOF_PATH')
    product_root=proof_path.parent
    if not product_root.name.startswith('current-peer-product-0162-'):
        raise PermissionError('G2_CURRENT_PRODUCT_BUILD_DOMAIN')
    if (delivery['component_proof_sha256'] != equality.get('component_proof_sha256') or
            delivery['component_proof_path'] != equality.get('component_proof_path')):
        raise PermissionError('G2_CURRENT_PROOF_EQUALITY_PIN')
    proof,proof_raw=bounded_json(proof_path)
    proof_sha=hashlib.sha256(proof_raw).hexdigest()
    expected_proof_keys={'schema','fixture_scenario','product_binary_sha256','product_component_review',
        'fixture_source_rows','tls_recipe','compiled_inputs_manifest','helper_binary','helper_build_receipt'}
    if (set(proof)!=expected_proof_keys or proof.get('schema')!='cicada.native-g2g3-components.v2' or
            proof.get('fixture_scenario')!='g2-g3' or proof_sha!=delivery['component_proof_sha256'] or
            proof_sha!=equality.get('component_proof_sha256') or
            proof.get('product_binary_sha256')!=delivery.get('binary_sha256')):
        raise PermissionError('G2_CURRENT_PROOF_PIN')
    if (equality.get('status')!='COMPILED_INPUTS_EXACT' or
            equality.get('current_commit')!=delivery.get('commit') or
            equality.get('product_artifact_origin_revision')!=delivery.get('commit') or
            type(delivery.get('source_dirty')) is not bool or
            equality.get('product_artifact_origin_dirty') is not delivery.get('source_dirty') or
            equality.get('source_dirty') is not delivery.get('source_dirty') or
            equality.get('source_fingerprint')!=delivery.get('fingerprint') or
            equality.get('product_source_fingerprint')!=delivery.get('fingerprint') or
            equality.get('artifact_binary_sha256')!=delivery.get('binary_sha256') or
            equality.get('artifact_compiled_inputs_sha256')!=equality.get('current_compiled_inputs_sha256') or
            not re.fullmatch('[0-9a-f]{64}',equality.get('current_compiled_inputs_sha256',''))):
        raise PermissionError('G2_CURRENT_PRODUCT_EQUALITY')
    commit=delivery.get('commit'); dirty=delivery.get('source_dirty'); fingerprint=delivery.get('fingerprint')
    if (type(commit) is not str or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})',commit) or
            type(fingerprint) is not str or not re.fullmatch('[0-9a-f]{64}',fingerprint)):
        raise PermissionError('G2_CURRENT_SOURCE_IDENTITY')

    helper_binary=proof['helper_binary']
    if (type(helper_binary) is not dict or set(helper_binary)!={'path','sha256'} or
            helper_binary['path']!=delivery.get('helper') or
            helper_binary['sha256']!=delivery.get('helper_sha256') or
            not re.fullmatch('[0-9a-f]{64}',helper_binary.get('sha256',''))):
        raise PermissionError('G2_CURRENT_HELPER_BINARY_REFERENCE')
    helper_path=g2_current_path(helper_binary['path'],roots=(G2_CURRENT_EVIDENCE_ROOT,))
    if helper_path.parts[-2:] != ('bin','cicada-v68fixture'):
        raise PermissionError('G2_CURRENT_HELPER_BINARY_PATH')
    helper_root=helper_path.parent.parent
    if helper_root==product_root or not helper_root.name.startswith('current-peer-helper-0162-'):
        raise PermissionError('G2_CURRENT_HELPER_BUILD_DOMAIN')
    if digest(helper_path)!=helper_binary['sha256']:
        raise PermissionError('G2_CURRENT_HELPER_BINARY_PIN')

    manifest_ref=proof['compiled_inputs_manifest']
    if (type(manifest_ref) is not dict or set(manifest_ref)!={'path','sha256','product_count','helper_count','projection_sha256'} or
            manifest_ref.get('path')!=str(product_root/'compiled-inputs.NONAUTH.json') or
            type(manifest_ref.get('product_count')) is not int or type(manifest_ref.get('helper_count')) is not int or
            any(n<1 or n>10000 for n in (manifest_ref['product_count'],manifest_ref['helper_count'])) or
            not re.fullmatch('[0-9a-f]{64}',manifest_ref.get('sha256','')) or
            not re.fullmatch('[0-9a-f]{64}',manifest_ref.get('projection_sha256',''))):
        raise PermissionError('G2_CURRENT_MANIFEST_REFERENCE')
    manifest_path=g2_current_path(manifest_ref['path'],roots=(product_root,),exact=product_root/'compiled-inputs.NONAUTH.json')
    manifest,manifest_raw=bounded_json(manifest_path,16<<20)
    manifest_sha=hashlib.sha256(manifest_raw).hexdigest()
    manifest_keys={'schema','fixture_scenario','source_revision','source_dirty','source_fingerprint','toolchain',
        'components','module_inputs','selection','pqtls_closure'}
    if (set(manifest)!=manifest_keys or manifest_sha!=manifest_ref['sha256'] or
            manifest.get('schema')!='cicada.native-selected-component-inputs.v2' or
            manifest.get('fixture_scenario')!='g2-g3' or manifest.get('source_revision')!=commit or
            manifest.get('source_dirty') is not dirty or manifest.get('source_fingerprint')!=fingerprint):
        raise PermissionError('G2_CURRENT_MANIFEST_IDENTITY')
    toolchain=manifest.get('toolchain')
    if (type(toolchain) is not dict or set(toolchain)!={'CGO_ENABLED','GOARCH','GOOS','builder_image','go_version','tags'} or
            toolchain!={'CGO_ENABLED':1,'GOARCH':'amd64','GOOS':'linux','builder_image':'sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195',
                        'go_version':'go version go1.27.1 linux/amd64','tags':'cicada_pqtls'}):
        raise PermissionError('G2_CURRENT_TOOLCHAIN')
    selection=manifest.get('selection')
    if type(selection) is not dict or set(selection)!={'product','helper'}:
        raise PermissionError('G2_CURRENT_SELECTION')
    product_selection=selection['product']; helper_selection=selection['helper']
    if (type(product_selection) is not dict or set(product_selection)!={'build_receipt','excluded_generated_paths','go_list','scope'} or
            type(helper_selection) is not dict or set(helper_selection)!={'build_receipt','go_list','prestart','scope'} or
            any(type(selection[name].get('scope')) is not str or not selection[name]['scope'] for name in ('product','helper'))):
        raise PermissionError('G2_CURRENT_SELECTION_SHAPE')

    product_result_path=product_root/'RESULT.NONAUTH.json'
    product_prestart_path=product_root/'PRESTART.NONAUTH.json'
    helper_result_path=helper_root/'RESULT.NONAUTH.json'
    helper_prestart_path=helper_root/'PRESTART.NONAUTH.json'
    product_go_list_path=product_root/'product-go-list.json'
    helper_go_list_path=helper_root/'helper-go-list.json'
    for path,root in ((product_result_path,product_root),(product_prestart_path,product_root),
            (helper_result_path,helper_root),(helper_prestart_path,helper_root),
            (product_go_list_path,product_root),(helper_go_list_path,helper_root)):
        g2_current_path(str(path),roots=(root,),exact=path)
    if (product_selection['build_receipt']!={'path':str(product_result_path),'sha256':digest(product_result_path)} or
            product_selection['go_list']!={'path':str(product_go_list_path),'sha256':digest(product_go_list_path)} or
            helper_selection['build_receipt']!={'path':str(helper_result_path),'sha256':digest(helper_result_path)} or
            helper_selection['go_list']!={'path':str(helper_go_list_path),'sha256':digest(helper_go_list_path)} or
            helper_selection['prestart']!={'path':str(helper_prestart_path),'sha256':digest(helper_prestart_path)}):
        raise PermissionError('G2_CURRENT_SELECTION_PINS')
    if proof['helper_build_receipt']!=helper_selection['build_receipt']:
        raise PermissionError('G2_CURRENT_HELPER_RECEIPT_REFERENCE')
    product_result,_=bounded_json(g2_current_path(str(product_result_path),roots=(product_root,),exact=product_result_path))
    product_prestart,_=bounded_json(g2_current_path(str(product_prestart_path),roots=(product_root,),exact=product_prestart_path))
    helper_result,_=bounded_json(g2_current_path(str(helper_result_path),roots=(helper_root,),exact=helper_result_path))
    helper_prestart,_=bounded_json(g2_current_path(str(helper_prestart_path),roots=(helper_root,),exact=helper_prestart_path))
    if (product_result.get('schema')!='cicada.root.current-peer-product-build.v1' or product_result.get('status')!='PASS_BUILD' or
            product_result.get('exit_code')!=0 or product_result.get('container_exit_code')!=0 or
            product_result.get('OOMKilled') is not False or product_result.get('credential_mounts')!=0 or product_result.get('models')!=0 or
            product_result.get('owned_removed') is not True or product_result.get('protected_residents_unchanged') is not True):
        raise PermissionError('G2_CURRENT_PRODUCT_BUILD_RECEIPT')
    product_script=g2_current_prestart_script(product_prestart,
        schema='cicada.root.current-peer-product-build.v1',revision=commit,dirty=dirty,
        builder_image=toolchain['builder_image'],repository_mount='type=bind,src=/home/zyf/CICADA,dst=/home/zyf/CICADA,readonly')
    if ('go list ' not in product_script or '-tags cicada_pqtls' not in product_script or
            '-deps -json ./cmd/cicada' not in product_script or '> /out/product-go-list.json' not in product_script or
            'build-release.sh' not in product_script or '--transport pqtls' not in product_script or
            '--pqtls-stage /opt/cicada-openssl/3.5.9' not in product_script):
        raise PermissionError('G2_CURRENT_PRODUCT_PRESTART_COMMAND')
    product_artifacts=product_result.get('artifacts',{})
    product_tar=product_root/'dist/cicada-linux-amd64-pqtls.tar.gz'
    if (type(product_artifacts) is not dict or
            product_artifacts.get('dist/cicada-linux-amd64-pqtls.tar.gz',{}).get('sha256')!=digest(
                g2_current_path(str(product_tar),roots=(product_root,),exact=product_tar))):
        raise PermissionError('G2_CURRENT_PRODUCT_ARTIFACT')
    helper_outputs=helper_result.get('outputs',{})
    if (helper_result.get('schema')!='cicada.root.current-peer-helper-build.v1' or
            helper_result.get('status')!='PASS_BUILD_AND_TAGGED_FIXTURE_TESTS' or helper_result.get('exit_code')!=0 or
            helper_result.get('container_exit_code')!=0 or helper_result.get('OOMKilled') is not False or
            helper_result.get('credential_mounts')!=0 or helper_result.get('models')!=0 or
            helper_result.get('owned_removed') is not True or helper_result.get('protected_residents_unchanged') is not True or
            helper_result.get('builder_image')!=toolchain['builder_image'] or
            helper_outputs.get('bin/cicada-v68fixture',{}).get('sha256')!=helper_binary['sha256'] or
            helper_outputs.get('helper-go-list.json',{}).get('sha256')!=helper_selection['go_list']['sha256']):
        raise PermissionError('G2_CURRENT_HELPER_BUILD_RECEIPT')
    helper_script=g2_current_prestart_script(helper_prestart,
        schema='cicada.root.current-peer-helper-build.v1',revision=commit,dirty=dirty,
        builder_image=toolchain['builder_image'],repository_mount='type=bind,src=/home/zyf/CICADA/cicada-go,dst=/repo/cicada-go,readonly')
    if any(fragment not in helper_script for fragment in (
            'go list ', 'go build ', 'go test ', ' -overlay=/fixture-build/overlay.json',
            '-tags=cicada_pqtls', './cmd/cicada-v68fixture')):
        raise PermissionError('G2_CURRENT_HELPER_PRESTART_COMMAND')

    review_ref=proof['product_component_review']
    if (type(review_ref) is not dict or set(review_ref)!={'path','sha256'} or
            review_ref.get('path')!=str(product_root/'product-component-review.NONAUTH.json') or
            not re.fullmatch('[0-9a-f]{64}',review_ref.get('sha256',''))):
        raise PermissionError('G2_CURRENT_REVIEW_REFERENCE')
    review_path=g2_current_path(review_ref['path'],roots=(product_root,),exact=product_root/'product-component-review.NONAUTH.json')
    review,review_raw=bounded_json(review_path)
    if hashlib.sha256(review_raw).hexdigest()!=review_ref['sha256']:
        raise PermissionError('G2_CURRENT_REVIEW_PIN')
    review_keys={'credential_mounts','current_source_dirty','current_source_fingerprint','current_source_revision','go_list',
        'helper_sources_verified_against_actual_product_inventory','models','package_binary_sha256','package_metadata',
        'package_webcrypto_manifest_sha256','product_build_receipt','projection_sha256','schema',
        'selected_sources_verified_against_actual_build_inventory','source_inventory'}
    if (set(review)!=review_keys or review.get('schema')!='cicada.root.native-g2g3-current-product-review.v1' or
            review.get('current_source_revision')!=commit or review.get('current_source_dirty') is not dirty or
            review.get('current_source_fingerprint')!=fingerprint or review.get('credential_mounts')!=0 or review.get('models')!=0 or
            review.get('package_binary_sha256')!=delivery.get('binary_sha256') or
            review.get('product_build_receipt')!=product_selection['build_receipt'] or
            review.get('projection_sha256')!=manifest_ref['projection_sha256']):
        raise PermissionError('G2_CURRENT_PRODUCT_REVIEW')
    review_go=review.get('go_list')
    if (type(review_go) is not dict or set(review_go)!={'count','excluded_generated_paths','path','same_selected_path_set','sha256'} or
            review_go.get('path')!=product_selection['go_list']['path'] or review_go.get('sha256')!=product_selection['go_list']['sha256'] or
            review_go.get('same_selected_path_set') is not True or type(review_go.get('count')) is not int):
        raise PermissionError('G2_CURRENT_PRODUCT_GO_LIST_REVIEW')
    package_dir=Path(delivery.get('package',''))
    if not package_dir.is_absolute() or not package_dir.is_relative_to(product_root) or str(package_dir.resolve())!=str(package_dir):
        raise PermissionError('G2_CURRENT_PACKAGE_PATH')
    package_metadata_path=package_dir/'BUILD-METADATA.json'
    package_metadata_ref=review.get('package_metadata')
    if (type(package_metadata_ref) is not dict or set(package_metadata_ref)!={'path','sha256'} or
            package_metadata_ref.get('path')!=str(package_metadata_path) or
            not re.fullmatch('[0-9a-f]{64}',package_metadata_ref.get('sha256','')) or
            digest(package_metadata_path)!=package_metadata_ref['sha256']):
        raise PermissionError('G2_CURRENT_PACKAGE_METADATA_PIN')
    package_metadata,_=bounded_json(g2_current_path(str(package_metadata_path),roots=(product_root,),exact=package_metadata_path),1<<20)
    if (package_metadata.get('transport_variant')!='pqtls' or package_metadata.get('pqtls_available') is not True or
            package_metadata.get('toolchain')!='go1.27.1' or package_metadata.get('cgo_enabled') is not True or
            package_metadata.get('source',{}).get('revision')!=commit or package_metadata.get('source',{}).get('dirty') is not dirty or
            package_metadata.get('source',{}).get('source_fingerprint')!=fingerprint or
            package_metadata.get('runtime',{}).get('closure_sha256')!=manifest.get('pqtls_closure') or
            package_metadata.get('hub_webcrypto_manifest_sha256')!=review.get('package_webcrypto_manifest_sha256')):
        raise PermissionError('G2_CURRENT_PACKAGE_METADATA')
    product_binary=g2_current_path(str(package_dir/'bin/cicada'),roots=(product_root,),exact=package_dir/'bin/cicada')
    if digest(product_binary)!=delivery.get('binary_sha256'):
        raise PermissionError('G2_CURRENT_PRODUCT_BINARY')

    inventory_ref=review.get('source_inventory')
    if (type(inventory_ref) is not dict or set(inventory_ref)!={'path','sha256'} or
            inventory_ref.get('path')!=str(product_root/'current-input-inventory.NONAUTH.json') or
            not re.fullmatch('[0-9a-f]{64}',inventory_ref.get('sha256',''))):
        raise PermissionError('G2_CURRENT_SOURCE_INVENTORY_REFERENCE')
    inventory_path=g2_current_path(inventory_ref['path'],roots=(product_root,),exact=product_root/'current-input-inventory.NONAUTH.json')
    inventory,inventory_raw=bounded_json(inventory_path,16<<20)
    if (hashlib.sha256(inventory_raw).hexdigest()!=inventory_ref['sha256'] or
            inventory.get('schema_version')!='cicada.pqtls-distribution-inputs.v1' or
            inventory.get('transport_variant')!='pqtls' or
            inventory.get('fingerprint',{}).get('sha256')!=fingerprint):
        raise PermissionError('G2_CURRENT_SOURCE_INVENTORY')
    source=inventory.get('source'); entries=source.get('entries') if type(source) is dict else None
    if type(entries) is not list or not 0<len(entries)<=100000:
        raise PermissionError('G2_CURRENT_SOURCE_INVENTORY_ROWS')
    inventory_rows={}
    for entry in entries:
        if (type(entry) is not dict or type(entry.get('path')) is not str or
                not entry['path'] or Path(entry['path']).is_absolute() or '..' in Path(entry['path']).parts or
                entry['path'] in inventory_rows or type(entry.get('size_bytes')) is not int or
                type(entry.get('content_sha256')) is not str or not re.fullmatch('[0-9a-f]{64}',entry['content_sha256']) or
                type(entry.get('raw_mode')) is not str or not re.fullmatch(r'0o[0-7]{6}',entry['raw_mode'])):
            raise PermissionError('G2_CURRENT_SOURCE_INVENTORY_ROW_SHAPE')
        inventory_rows[entry['path']]=entry

    fixture_rows=proof.get('fixture_source_rows')
    if type(fixture_rows) is not list or len(fixture_rows)!=3 or {row.get('path') for row in fixture_rows if type(row) is dict}!=G2_SOURCE_PATHS:
        raise PermissionError('G2_CURRENT_FIXTURE_SOURCE_ROWS')
    for row in fixture_rows: g2_public_row(row,paths=G2_SOURCE_PATHS)
    recipe=proof.get('tls_recipe')
    recipe_keys={'input_path','input_sha256','output_path','output_sha256','output_bytes','generator_function_sha256','generator_hash_representation'}
    if (type(recipe) is not dict or set(recipe)!=recipe_keys or recipe.get('input_path')!=str(G2_TLS_INPUT_PATH) or
            recipe.get('input_sha256')!=G2_TLS_INPUT_SHA or recipe.get('generator_hash_representation')!='source'):
        raise PermissionError('G2_CURRENT_TLS_RECIPE')
    import ast
    generator_source=Path(__file__).read_text(); tree=ast.parse(generator_source)
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='g2_tls_fixture_source')
    function_sha=hashlib.sha256(ast.get_source_segment(generator_source,function).encode()).hexdigest()
    produced=g2_tls_fixture_source(G2_TLS_INPUT_PATH.read_bytes())
    tls_output=g2_current_path(recipe['output_path'],roots=(G2_BUILD_ROOT,),exact=G2_BUILD_ROOT/'tls_bootstrap.go')
    if (recipe.get('generator_function_sha256')!=function_sha or recipe.get('output_bytes')!=len(produced) or
            recipe.get('output_sha256')!=hashlib.sha256(produced).hexdigest() or tls_output.read_bytes()!=produced):
        raise PermissionError('G2_CURRENT_TLS_OUTPUT')

    components=manifest.get('components')
    if type(components) is not dict or set(components)!={'product','helper'}:
        raise PermissionError('G2_CURRENT_COMPONENTS')
    for component in ('product','helper'):
        selected=components[component]
        if (type(selected) is not list or len(selected)!=manifest_ref[component+'_count'] or not 0<len(selected)<=10000):
            raise PermissionError('G2_CURRENT_COMPONENT_COUNT')
        paths=[row.get('path') for row in selected if type(row) is dict]
        if len(paths)!=len(selected) or any(type(path) is not str for path in paths) or len(paths)!=len(set(paths)):
            raise PermissionError('G2_CURRENT_COMPONENT_ORDER')
        for row in selected:
            g2_current_source_row(row,inventory=inventory_rows,allowed_extra=(str(tls_output),))
    modules=manifest.get('module_inputs')
    if (type(modules) is not list or len(modules)!=2 or
            {row.get('path') for row in modules if type(row) is dict}!={str(G2_CURRENT_SOURCE_ROOT/'go.mod'),str(G2_CURRENT_SOURCE_ROOT/'go.sum')}):
        raise PermissionError('G2_CURRENT_MODULE_INPUTS')
    for row in modules: g2_current_source_row(row,inventory=inventory_rows)

    product_excluded=product_selection.get('excluded_generated_paths')
    if (type(product_excluded) is not list or any(type(path) is not str for path in product_excluded) or
            product_excluded!=sorted(set(product_excluded)) or product_excluded!=review_go.get('excluded_generated_paths') or
            any(not Path(path).is_relative_to(G2_CURRENT_SOURCE_ROOT/'internal/server/ui/generated') for path in product_excluded)):
        raise PermissionError('G2_CURRENT_GENERATED_PATHS')
    product_sources=g2_current_go_sources(product_go_list_path,source_root=G2_CURRENT_SOURCE_ROOT,go_list_root=G2_CURRENT_SOURCE_ROOT)
    if not set(product_excluded).issubset(product_sources) or product_sources-set(product_excluded)!={row['path'] for row in components['product']}:
        raise PermissionError('G2_CURRENT_PRODUCT_SELECTION')
    helper_sources=g2_current_go_sources(helper_go_list_path,source_root=G2_CURRENT_SOURCE_ROOT,go_list_root=Path('/repo/cicada-go'))
    overlay_target='/repo/cicada-go/cmd/cicada-v68fixture/tls_bootstrap.go'
    overlay_target_source=str(G2_CURRENT_SOURCE_ROOT/Path(overlay_target).relative_to('/repo/cicada-go'))
    overlay_path=helper_root/'overlay.json'
    overlay=g2_current_path(str(overlay_path),roots=(helper_root,),exact=overlay_path)
    overlay_value,_=bounded_json(overlay)
    if overlay_value!={'Replace':{overlay_target:'/tls-bootstrap.go'}} or overlay_target_source not in helper_sources:
        raise PermissionError('G2_CURRENT_HELPER_OVERLAY')
    helper_sources.remove(overlay_target_source); helper_sources.add(str(tls_output))
    if helper_sources!={row['path'] for row in components['helper']}:
        raise PermissionError('G2_CURRENT_HELPER_SELECTION')
    helper_inventory_sources={path for path in helper_sources if Path(path).is_relative_to(G2_CURRENT_SOURCE_ROOT)}
    if (len(helper_sources)!=len(helper_inventory_sources)+1 or
            helper_sources-helper_inventory_sources!={str(tls_output)}):
        raise PermissionError('G2_CURRENT_HELPER_TLS_OVERLAY_SCOPE')
    if review_go.get('count') != len(components['product']):
        raise PermissionError('G2_CURRENT_PRODUCT_SELECTED_COUNT')
    projection=hashlib.sha256(json.dumps(components,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
    if (projection!=manifest_ref['projection_sha256'] or projection!=review.get('projection_sha256') or
            projection!=equality.get('artifact_compiled_inputs_sha256') or projection!=equality.get('current_compiled_inputs_sha256')):
        raise PermissionError('G2_CURRENT_COMPILED_PROJECTION')
    return proof_sha


def g2_component_inputs(delivery, equality, *, current=False):
    if current:
        return g2_current_component_inputs(delivery,equality)
    return g2_legacy_component_inputs(delivery,equality)


def scenario_inputs(args, delivery):
    scenario = getattr(args, "scenario", "g1")
    if scenario not in ("g1", "g2-g3"):
        raise PermissionError("SCENARIO_UNSUPPORTED")
    if scenario == "g2-g3":
        if delivery.get("fixture_scenario") != scenario or any(type(delivery.get(key)) is not str or not delivery[key] for key in ("component_proof_path","component_proof_sha256")):
            raise PermissionError("G2_FRESH_HELPER_REQUIRED")
    return scenario


def zero_inputs(args):
    with deny_preflight_effects():
        return _zero_inputs_public(args)


def _zero_inputs_public(args):
    """Public-only fail-closed validation; no constructor or Docker before return."""
    if any(type(getattr(args,key,False)) is not bool for key in ("reproduce_zero_hub_restart","enable_closed_failure_diagnostics")):
        raise PermissionError("ZERO_DIAGNOSTIC_OPT_IN")
    if getattr(args,"response_byte_passthrough",False) is not False:
        raise PermissionError("ZERO_RESPONSE_MODE_FORBIDDEN")
    if args.execute_diagnostic or getattr(args,"enable_io_diagnostics",False) or any(getattr(args,key,None) is not None for key in ("go_receipt","go_receipt_sha","preparation_result","preparation_result_sha","preparation_review","preparation_review_sha")):
        raise PermissionError("ZERO_PAID_FLAGS")
    if not re.fullmatch(r"cicada-two-turn-zerocli0162-[a-z0-9]{8,24}",args.unique_run or ""):
        raise PermissionError("ZERO_UNIQUE_RUN")
    if type(args.cleanup_hard_stop_unix) is not int or time.time()+240>=args.cleanup_hard_stop_unix:
        raise PermissionError("ZERO_ABSOLUTE_BUDGET")
    binding,sha=verify_binding(args.binding_sha,getattr(args,"binding_file",None),require_current=True)
    bundle=require_current_bundle(binding)
    if (args.runtime_image != bundle["runtime_receipt"]["image_id"] or
            str(Path(args.delivery)) != bundle["delivery"]["path"] or
            str(Path(args.compiled_input_equality)) != bundle["equality"]["path"]):
        raise PermissionError("ZERO_CURRENT_BUNDLE_ARGUMENTS")
    receipt,raw=bounded_json(args.wiring_receipt)
    if (hashlib.sha256(raw).hexdigest()!=args.wiring_receipt_sha or receipt.get("status")!="PASS" or
            receipt.get("candidate_binding_sha256")!=sha or receipt.get("Runtime_calls")!=0 or
            receipt.get("model_calls")!=0):
        raise PermissionError("ZERO_CURRENT_OFFLINE_RECEIPT")
    delivery,raw=bounded_json(args.delivery)
    if hashlib.sha256(raw).hexdigest()!=args.delivery_sha:
        raise PermissionError("ZERO_DELIVERY_PIN")
    scenario_inputs(args, delivery)
    equality,raw=bounded_json(args.compiled_input_equality)
    if hashlib.sha256(raw).hexdigest()!=args.equality_sha or equality.get("status")!="COMPILED_INPUTS_EXACT":
        raise PermissionError("ZERO_COMPILED_INPUT_EQUALITY")
    if (equality.get("current_commit")!=args.current_commit or
            args.current_commit!=bundle["current_commit"] or
            equality.get("artifact_compiled_inputs_sha256")!=equality.get("current_compiled_inputs_sha256") or
            not re.fullmatch(r"[0-9a-f]{64}",equality.get("current_compiled_inputs_sha256", "")) or
            equality.get("artifact_binary_sha256")!=delivery.get("binary_sha256") or
            equality.get("product_artifact_origin_dirty",equality.get("source_dirty"))!=bundle["source_dirty"] or
            delivery.get("commit")!=bundle["current_commit"] or delivery.get("source_dirty")!=bundle["source_dirty"] or
            delivery.get("fingerprint")!=bundle["source_fingerprint"]):
        raise PermissionError("ZERO_CURRENT_PRODUCT_MISMATCH")
    if getattr(args,"scenario","g1") == "g2-g3": g2_component_inputs(delivery,equality,current=True)
    for key in ("commit","fingerprint","binary_sha256","helper_sha256","hub_image",
                "package","helper","package_metadata_sha256","hub_receipt_path","hub_receipt_sha256","source_repo"):
        if type(delivery.get(key)) is not str or not delivery[key]:
            raise PermissionError("ZERO_DELIVERY_SHAPE")
    for path,pin in ((Path(delivery["package"])/"BUILD-METADATA.json",delivery["package_metadata_sha256"]),
                     (Path(delivery["hub_receipt_path"]),delivery["hub_receipt_sha256"])):
        if digest(path)!=pin:
            raise PermissionError("ZERO_PRODUCER_RECEIPT_CHANGED")
    result=Path(args.result_dir)
    if result.parent.absolute()!=Path(binding["output_parent"]).absolute() or result.name!="native-preparation-"+args.unique_run or result.exists():
        raise PermissionError("ZERO_FRESH_RESULT_PATH")
    return binding,sha,delivery


def prepare_native_zero(args):
    global EXECUTION_EFFECTS_STARTED
    binding,sha,delivery=zero_inputs(args)
    # Config is synthetic, private and created only after every public guard.
    output_parent=Path(binding["output_parent"])
    config=output_parent/(args.unique_run+"-config.toml")
    fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as output: output.write(ZERO_CONFIG)
    started=time.monotonic()
    if time.time()+240>=args.cleanup_hard_stop_unix:
        raise PermissionError("ZERO_ABSOLUTE_BUDGET")
    ns=types.SimpleNamespace(execute=True,run_native=False,result_dir=args.result_dir,
        product_repo=delivery["source_repo"],expected_product_revision=delivery["commit"],
        expected_source_fingerprint=delivery["fingerprint"],runtime_image=current_runtime(binding),
        expected_codex_version="codex-cli "+current_cli(binding)["version"],expected_cli_sha256=current_cli(binding)["sha256"],
        producer_receipt=str(Path(delivery["package"])/"BUILD-METADATA.json"),
        producer_receipt_sha256=delivery["package_metadata_sha256"],
        exact_clean_image_metadata=delivery["hub_receipt_path"],exact_clean_image_metadata_sha256=delivery["hub_receipt_sha256"],
        config_template=str(config),config_template_sha=hashlib.sha256(ZERO_CONFIG.encode()).hexdigest(),
        source_binding_sha=sha,binding_file=str(args.binding_file),offline_checks_sha=args.wiring_receipt_sha,
        artifact_started=started,go={"unique_run":args.unique_run,"max_native_turns":0,"max_manual_turns":0,
            "max_automatic_turns":0},credential_file="ZERO_LANE_NO_CREDENTIAL_REFERENCE",
        closed_failure_diagnostics=getattr(args,"enable_closed_failure_diagnostics",False) or getattr(args,"reproduce_zero_hub_restart",False),
        preparation_result=None,preparation_result_sha256=None,test_request_observer=False,
        candidate_binding_sha256=sha,delivery_sha=args.delivery_sha,equality_sha=args.equality_sha,latest_runtime=True)
    gate=None
    try:
        overlay=safe_overlay("request_observer_gate")
        cls,_=overlay.load_gate(delivery,binding,zero_model=True,scenario=getattr(args,"scenario","g1"))
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
        if getattr(args,"reproduce_zero_hub_restart",False) is True:
            overlay.reproduce_owned_zero_restart(gate)
        if gate.budget.started or gate.result.get("paid_turn_start_submissions")!=0:
            raise RuntimeError("ZERO_ACTUAL_TURN_FORBIDDEN")
        gate.result.update(status="PREPARATION_PASS_NATIVE_NOT_RUN",latest_CLI=LATEST_VERSION,
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
    parser.add_argument("--scenario",default="g1")
    parser.add_argument("--enable-io-diagnostics",action="store_true")
    parser.add_argument("--response-byte-passthrough",action="store_true")
    parser.add_argument("--native-https",action="store_true")
    parser.add_argument("--native-normal-seconds",type=int)
    parser.add_argument("--cleanup-hard-stop-unix",type=int)
    parser.add_argument("--prepare-native-zero",action="store_true")
    parser.add_argument("--reproduce-zero-hub-restart",action="store_true")
    parser.add_argument("--enable-closed-failure-diagnostics",action="store_true")
    parser.add_argument("--binding-file",default=str(BINDING))
    parser.add_argument("--refresh-current-binding",action="store_true")
    for name in ("delivery","delivery-sha","compiled-input-equality","equality-sha","runtime-image","runtime-image-receipt","result-dir","current-commit","expected-commit","output-parent","preparation-result","preparation-result-sha","preparation-review","preparation-review-sha"):
        parser.add_argument("--"+name)
    parser.add_argument("--preflight",action="store_true")
    parser.add_argument("--execute-diagnostic",action="store_true")
    for name in ("binding-sha","go-receipt","go-receipt-sha","wiring-receipt","wiring-receipt-sha","unique-run"):
        parser.add_argument("--"+name)
    args=parser.parse_args(argv)
    try:
        native_https_mode(args)
        native_normal_seconds(args)
        response_passthrough_mode(args)
        if args.refresh_current_binding:
            required = (args.delivery, args.compiled_input_equality, args.runtime_image_receipt,
                        args.output_parent, args.expected_commit)
            if not all(required) or args.execute_diagnostic or args.prepare_native_zero or args.preflight:
                raise PermissionError("CURRENT_BINDING_REFRESH_ARGUMENTS")
            print(json.dumps(refresh_current_binding(args.delivery, args.compiled_input_equality,
                args.runtime_image_receipt, args.output_parent, args.expected_commit),sort_keys=True))
            return 0
        if args.reproduce_zero_hub_restart and (not args.prepare_native_zero or args.execute_diagnostic):
            raise PermissionError("ZERO_RESTART_MODE")
        if args.prepare_native_zero:
            return prepare_native_zero(args)
        if args.execute_diagnostic:
            return execute(args)
        if args.preflight:
            print(json.dumps(preflight(args.binding_sha,args.binding_file),sort_keys=True))
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
