"""Default-off Runtime shim; only explicit future authorized argv enables it."""
import hashlib
import json
import sys
import time
from pathlib import Path
import re

OLD_BOOTSTRAP_SHA = "0eeaf6cee3c2485e3718ad9bdedf4394e46d5c689c9b683f7bedae49b536db79"
PATCH_SHA = "e621d869098d54a8685f187eecc2bbd1030120349612225fefdc04f30e99da24"
OBSERVER_SHA = "72002d09b01c2e6f87e91b398acd1f94e4f8c0a0cad276f727973bd20f3e4baa"


def apply_section(original, patch, target):
    """Strict pure in-memory patch; never writes or imports legacy sources."""
    lines = original.splitlines(True)
    output, position, selected = [], 0, False
    seen = False
    for line in patch.splitlines(True):
        if line.startswith("--- a/"):
            selected = False
        elif line.startswith("+++ b/"):
            selected = line[6:].strip() == target
            seen = seen or selected
        elif selected and line.startswith("@@ "):
            at = int(re.match(r"@@ -(\d+)", line).group(1)) - 1
            if at < position:
                raise ValueError("PATCH_ORDER")
            output.extend(lines[position:at])
            position = at
        elif selected and line.startswith("+"):
            output.append(line[1:])
        elif selected and line.startswith(("-", " ")):
            if position >= len(lines) or lines[position] != line[1:]:
                raise ValueError("PATCH_CONTEXT")
            if line.startswith(" "):
                output.append(line[1:])
            position += 1
    if not seen:
        raise ValueError("PATCH_TARGET")
    output.extend(lines[position:])
    return "".join(output)


def effective_source(original, patch):
    value = apply_section(original, patch, "managed/server_bootstrap.py")
    value = value.replace("/run/cicada-request-observer", "/tmp/cicada-request-observer")
    value = value.replace("sys.path.insert(0, '/run')", "sys.path.insert(0, '/tmp')")
    value = value.replace("    port_path.write_text(str(port))\n    port_path.chmod(0o600)\n",
        "    with os.fdopen(os.open(port_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:\n        output.write(str(port))\n")
    old = "    lifetime, post_limit = int(sys.argv[5]), int(sys.argv[6])\n"
    new = ("    normal_end = float(sys.argv[5])\n"
           "    lifetime, post_limit = normal_end-time.monotonic(), int(sys.argv[6])\n"
           "    if not 0 < lifetime <= 180 or post_limit != 16:\n"
           "        raise SystemExit(33)\n")
    if value.count(old) != 1 or value.count("    port = observer.open()\n") != 1:
        raise ValueError("BOOTSTRAP_OVERLAY_CONTEXT")
    value = value.replace(old, new).replace("    port = observer.open()\n",
                                          "    port = observer.open()\n    observer.deadline = normal_end\n")
    def replace_once(old, new):
        nonlocal value
        if value.count(old)!=1: raise ValueError("BOOTSTRAP_IO_CONTEXT")
        value=value.replace(old,new)
    replace_once('from request_observer import Observer, Association, ClosedFailure',
        'from native_request_observer import Observer, Association, ClosedFailure\n    from native_request_observer_io import IOSink')
    replace_once('    observer = Observer(', "    io_sink = IOSink('/tmp/cicada-request-observer-io.jsonl', v2=True)\n    observer = Observer(")
    replace_once('lifetime=lifetime, max_connections=post_limit)', 'lifetime=lifetime, max_connections=post_limit, io_sink=io_sink, io_diagnostics_v2=True, response_byte_passthrough=(sys.argv[7:] == ["--response-byte-passthrough"]))')
    replace_once("    drain_path = Path('/tmp/cicada-request-observer-drain.json')", "    try:\n        io_mark = io_sink.seal(observer, drain)\n        with os.fdopen(os.open('/tmp/cicada-request-observer-io-watermark.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as io_output:\n            json.dump(io_mark, io_output, sort_keys=True)\n    except BaseException: pass\n    drain_path = Path('/tmp/cicada-request-observer-drain.json')")
    compile(value, "<effective-request-observer-bootstrap>", "exec")
    return value


def read_pinned(path, sha, limit=65536):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError("RUNTIME_PUBLIC_PAYLOAD_PIN")
    return raw


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) <= 3 or argv[3] != "--test-request-observer":
        print(json.dumps({"schema":"cicada.request-observer-bootstrap.v1",
                          "status":"NONAUTH", "enabled":False, "effects":False}))
        return 0
    try:
        if (len(argv) not in (12,13) or argv[11] != "--io-diagnostics" or
                (len(argv)==13 and argv[12] != "--response-byte-passthrough") or argv[1] != "paid" or argv[6] != "16"):
            raise ValueError("RUNTIME_ARGS")
        started, normal_end = float(argv[9]), float(argv[5])
        now = time.monotonic()
        if normal_end != started + 180 or not started <= now < normal_end:
            raise ValueError("RUNTIME_CLOCK_OR_DEADLINE")
        # Only explicit activation may read these few public Runtime files.
        original = read_pinned("/state/server_bootstrap.py", OLD_BOOTSTRAP_SHA).decode()
        patch = read_pinned("/tmp/request-observer-integration.patch", PATCH_SHA).decode()
        read_pinned("/tmp/native_request_observer.py", OBSERVER_SHA)
        read_pinned("/tmp/native_request_observer_io.py", argv[10])
        read_pinned("/tmp/request_observer_bootstrap.py", argv[7])
        source = effective_source(original, patch)
        if hashlib.sha256(source.encode()).hexdigest() != argv[8]:
            raise ValueError("RUNTIME_EFFECTIVE_BOOTSTRAP_PIN")
    except Exception:
        print(json.dumps({"schema":"cicada.request-observer-bootstrap.v1",
                          "status":"UNKNOWN_PUBLIC_BINDING", "enabled":False, "effects":False}))
        return 33
    sys.dont_write_bytecode = True
    sys.argv = argv[:7] + argv[12:]
    namespace = {"__name__":"__main__", "__file__":"/tmp/request_observer_bootstrap.py"}
    # Prepared source runs only inside the explicitly authorized disposable Runtime.
    exec(compile(source, "<effective-request-observer-bootstrap>", "exec"), namespace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
