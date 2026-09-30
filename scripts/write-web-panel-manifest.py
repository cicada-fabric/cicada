#!/usr/bin/env python3
"""Write deterministic metadata for generated Hub WebCrypto assets."""

import base64
import hashlib
import json
import pathlib
import sys


def digest(path: pathlib.Path) -> tuple[bytes, str]:
    content = path.read_bytes()
    return content, hashlib.sha256(content).hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: write-web-panel-manifest.py ASSET_DIR GO_VERSION RAW_WASM", file=sys.stderr)
        return 2
    asset_dir = pathlib.Path(sys.argv[1])
    version = sys.argv[2]
    raw_wasm_path = pathlib.Path(sys.argv[3])
    toolchain = "go1.27.1" if "go1.27.1" in version else "unsupported"
    gzip_path = asset_dir / "cicada-webcrypto.wasm.gz"
    runtime_path = asset_dir / "wasm_exec.js"
    if toolchain != "go1.27.1" or not all(path.is_file() for path in (raw_wasm_path, gzip_path, runtime_path)):
        raise SystemExit("web-panel manifest inputs are missing or use an unsupported toolchain")
    wasm, wasm_sha = digest(raw_wasm_path)
    wasm_gzip, wasm_gzip_sha = digest(gzip_path)
    runtime, runtime_sha = digest(runtime_path)
    result = {
        "schema_version": "cicada.hub-web-panel.v1",
        "toolchain": toolchain,
        "wasm_file": gzip_path.name,
        "wasm_size": len(wasm),
        "wasm_sha256": wasm_sha,
        "wasm_gzip_size": len(wasm_gzip),
        "wasm_gzip_sha256": wasm_gzip_sha,
        "wasm_exec_file": runtime_path.name,
        "wasm_exec_size": len(runtime),
        "wasm_exec_sha256": runtime_sha,
        "wasm_exec_sri": "sha256-" + base64.b64encode(hashlib.sha256(runtime).digest()).decode("ascii"),
    }
    temporary = asset_dir / ".panel.manifest.json.tmp"
    temporary.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(asset_dir / "panel.manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
