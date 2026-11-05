#!/usr/bin/env bash
set -euo pipefail

# Compile against read-only source/modules in the existing offline builder;
# execute only the isolated UI/installer fixtures on the host for actual EGL.
# The final disposable Hub interop gate is a separate Root-owned operation.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110"
: "${CICADA_UI_GOMODCACHE:?set existing offline module cache}"
: "${CICADA_UI_HEADERS_ROOT:?set private extracted graphics sysroot}"
: "${CICADA_UI_HOST_GO:?set existing Go 1.27.3 bin directory}"
: "${CICADA_UI_EVIDENCE_ROOT:?set isolated task evidence parent}"
scope="${CICADA_UI_SCOPE:-all}"
case "$scope" in all|ui) ;; *) printf '%s\n' 'CICADA_UI_SCOPE must be all or ui.' >&2; exit 2 ;; esac
umask 077
mkdir -p "$CICADA_UI_EVIDENCE_ROOT"
run_dir="$(mktemp -d "$CICADA_UI_EVIDENCE_ROOT/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
mkdir "$run_dir/output" "$run_dir/go-build" "$run_dir/fixture-modules" "$run_dir/host-build"
build_cache="${CICADA_UI_BUILD_CACHE:-$run_dir/go-build}"
mkdir -p "$build_cache"
exec 9>"$build_cache/acceptance.lock"
flock -n 9 || { printf '%s\n' 'Task build cache is in use.' >&2; exit 2; }
docker image inspect "$image" >"$run_dir/builder-image.json"
"$CICADA_UI_HOST_GO/go" version >"$run_dir/go-version.txt"
git -C "$repo_root" rev-parse HEAD >"$run_dir/source-head.txt"
git -C "$repo_root" status --porcelain --untracked-files=all >"$run_dir/source-status.txt"
find "$CICADA_UI_HEADERS_ROOT/usr/include" "$CICADA_UI_HEADERS_ROOT/usr/lib/x86_64-linux-gnu/pkgconfig" -type f -print0 | sort -z | xargs -0 sha256sum >"$run_dir/graphics-inputs.sha256"
sha256sum /usr/lib/x86_64-linux-gnu/libEGL.so.1 /usr/lib/x86_64-linux-gnu/libGLESv2.so.2 >"$run_dir/graphics-host-libraries.sha256"
manifest() {
	(cd "$repo_root"; find cicada-go -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) -print0 | sort -z | xargs -0 sha256sum; sha256sum scripts/test-app-redesign.sh)
}
manifest >"$run_dir/source-before.sha256"
common=(docker run --rm --network none --label cicada.task=v01-app-redesign-validation
	--cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
	-e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
	-e GOCACHE=/gocache -e GOMODCACHE=/gomodcache
	--mount "type=bind,src=$repo_root,dst=/repo,readonly"
	--mount "type=bind,src=$CICADA_UI_GOMODCACHE,dst=/gomodcache,readonly"
	--mount "type=bind,src=$build_cache,dst=/gocache"
	--mount "type=bind,src=$run_dir/output,dst=/out"
	--mount "type=bind,src=$CICADA_UI_HEADERS_ROOT,dst=/graphics,readonly"
	--mount "type=bind,src=/usr/lib/x86_64-linux-gnu,dst=/host-gl,readonly"
	--workdir /repo/cicada-go "$image")
printf '%q ' "${common[@]}" >"$run_dir/builder-argv.txt"
printf '\n' >>"$run_dir/builder-argv.txt"
set +e
"${common[@]}" env CGO_ENABLED=1 CGO_CFLAGS=-I/graphics/usr/include \
	CGO_LDFLAGS='-L/host-gl -Wl,-rpath-link,/host-gl' \
	PKG_CONFIG_PATH=/graphics/usr/lib/x86_64-linux-gnu/pkgconfig \
	go test -mod=readonly -p=1 -c -tags 'cicada_ui_acceptance novulkan' -o /out/native-ui.test ./internal/appui/native \
	>"$run_dir/ui-build.log" 2>&1
ui_build=$?
shell_build=125
if [[ "$scope" == all ]]; then
	"${common[@]}" env CGO_ENABLED=0 go test -mod=readonly -p=1 -c -o /out/component-shell.test ./internal/componentinstall \
		>"$run_dir/shell-build.log" 2>&1
	shell_build=$?
fi
set -e
ui_run=125
shell_run=125
if [[ "$ui_build" -eq 0 ]]; then
	set +e
	EGL_PLATFORM=surfaceless LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe MESA_SHADER_CACHE_DISABLE=true \
		CICADA_UI_ACCEPTANCE_OUTPUT="$run_dir/output" \
		"$run_dir/output/native-ui.test" -test.run '^TestAcceptance' -test.v -test.timeout 180s \
		>"$run_dir/ui-tests.log" 2>&1
	ui_run=$?
	set -e
fi
if [[ "$shell_build" -eq 0 ]]; then
	set +e
	PATH="$CICADA_UI_HOST_GO:$PATH" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
		GOCACHE="$run_dir/host-build" GOMODCACHE="$run_dir/fixture-modules" \
		"$run_dir/output/component-shell.test" -test.run '^TestAcceptanceShell' -test.v -test.timeout 120s \
		>"$run_dir/shell-tests.log" 2>&1
	shell_run=$?
	set -e
fi
manifest >"$run_dir/source-after.sha256"
python3 - "$run_dir" "$scope" "$ui_build" "$ui_run" "$shell_build" "$shell_run" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
scope=sys.argv[2]
codes=dict(zip(('ui_build','ui_run','shell_build','shell_run'),map(int,sys.argv[3:])))
if scope=='ui':
    codes.update(shell_build=None,shell_run=None)
stable=(root/'source-before.sha256').read_bytes()==(root/'source-after.sha256').read_bytes()
rows=[{'path':str(p.relative_to(root)),'sha256':digest(p),'bytes':p.stat().st_size}
      for p in sorted(root.rglob('*')) if p.is_file() and
      p.parts[len(root.parts)] not in ('go-build','host-build','fixture-modules')]
passed=stable and all(v==0 for v in codes.values() if v is not None)
status=('PASS' if scope=='all' else 'SCOPED_PASS') if passed else 'FAIL'
result={'schema':'cicada.app-redesign.acceptance.v1','status':status,'requested_scope':scope,
        'exit_codes':codes,'source_head':(root/'source-head.txt').read_text().strip(),
        'source_dirty':bool((root/'source-status.txt').read_text()),'source_stable':stable,
        'source_manifest_sha256':digest(root/'source-before.sha256'),'artifacts':rows,
        'scope':'Production Gio layout, actual Router pointer/keyboard and Linux EGL pixels; synthetic Controller only.' + (' Common production component command with an injected disposable home, real Bash and inert executable probes.' if scope=='all' else ' Shell NOT_RUN in this execution; retain its separately attributed earlier receipt.'),
        'renderer_environment':{'EGL_PLATFORM':'surfaceless','LIBGL_ALWAYS_SOFTWARE':'1','GALLIUM_DRIVER':'llvmpipe','MESA_SHADER_CACHE_DISABLE':'true'},
        'shell': 'PASS' if scope=='all' and codes['shell_run']==0 else 'NOT_RUN' if scope=='ui' else 'FAIL',
        'NOT_RUN':['Windows physical GUI/DPAPI/ACL/IME','actual Hub/Node integration in this UI fixture','paid Runtime/model calls','public deployment'],
        'final_Hub_Docker_gate':'SEPARATE_ROOT_OWNED'}
(root/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(root/'result.json')
sys.exit(0 if passed else 1)
PY
