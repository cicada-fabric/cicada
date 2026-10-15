#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
module_cache="${CICADA_NATIVE_APP_GOMODCACHE:-$repo_root/.cicada-data/m1-gomodcache}"
if [[ -z "${HOME:-}" && -z "${CICADA_NATIVE_APP_GOCACHE:-}" ]]; then
	printf '%s\n' 'Set HOME or CICADA_NATIVE_APP_GOCACHE to choose the writable Go build cache.' >&2
	exit 2
fi
build_cache="${CICADA_NATIVE_APP_GOCACHE:-$HOME/.cache/go-build}"
artifact_root="$repo_root/.cicada-data/native-app-foundation"
synthetic_fixture="${CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR:-}"

if [[ ! -d "$module_cache" || ! -d "$build_cache" ]]; then
	printf '%s\n' 'Required offline Go caches are missing.' >&2
	exit 2
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
	printf '%s\n' 'Pinned Go builder image is not present locally; refusing network access.' >&2
	exit 2
fi
if [[ ! -w "$build_cache" ]]; then
	printf '%s\n' 'Go build cache is not writable by the current user.' >&2
	exit 2
fi

fixture_args=()
fixture_configured=false
if [[ -n "$synthetic_fixture" ]]; then
	if [[ -L "$synthetic_fixture" ]]; then
		printf '%s\n' 'Synthetic fixture directory must not be a symbolic link.' >&2
		exit 2
	fi
	if ! fixture_dir="$(realpath -e "$synthetic_fixture")"; then
		printf '%s\n' 'Synthetic fixture directory does not exist.' >&2
		exit 2
	fi
	case "$fixture_dir" in
		*synthetic*) ;;
		*) printf '%s\n' 'Optional OpenSSL fixture path must visibly include “synthetic”.' >&2; exit 2 ;;
	esac
	for fixture_name in kem-private.pem signing-private.pem kem-public.pem signing-public.pem; do
		if [[ ! -f "$fixture_dir/$fixture_name" || -L "$fixture_dir/$fixture_name" ]]; then
			printf 'Synthetic fixture is missing a regular %s file.\n' "$fixture_name" >&2
			exit 2
		fi
	done
	if [[ "$(find "$fixture_dir" -mindepth 1 -maxdepth 1 | wc -l)" -ne 4 ]]; then
		printf '%s\n' 'Synthetic fixture directory must contain only the four expected PEM files.' >&2
		exit 2
	fi
	fixture_args=(--mount "type=bind,src=$fixture_dir,dst=/synthetic-keys,readonly")
	fixture_configured=true
fi

mkdir -p "$artifact_root"
run_dir="$(mktemp -d "$artifact_root/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
chmod 700 "$run_dir"
mkdir -p "$run_dir/output"

source_head="$(git -C "$repo_root" rev-parse HEAD)"
source_dirty=false
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
	source_dirty=true
fi
(
	cd "$repo_root"
	find cicada-go -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -print0 \
		| sort -z \
		| xargs -0 -r sha256sum
	sha256sum scripts/test-native-app.sh
) >"$run_dir/source-files.sha256"
source_fingerprint="$(sha256sum "$run_dir/source-files.sha256" | awk '{print $1}')"

common=(
	docker run --rm --network none --cpus=3 --memory=3g --pids-limit=256
	--user "$(id -u):$(id -g)"
	-e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
	-e GOCACHE=/gocache -e GOMODCACHE=/gomodcache
	--mount "type=bind,src=$repo_root,dst=/repo,readonly"
	--mount "type=bind,src=$build_cache,dst=/gocache"
	--mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
	--mount "type=bind,src=$run_dir/output,dst=/out"
	"${fixture_args[@]}"
	--workdir /repo/cicada-go "$image"
)
if [[ "$fixture_configured" == true ]]; then
	common+=(env CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR=/synthetic-keys)
fi

set +e
"${common[@]}" go version >"$run_dir/go-version.txt" 2>&1
version_exit=$?
	"${common[@]}" go test -json -mod=readonly -p=1 -count=1 -timeout=120s \
		./internal/appui ./internal/appui/native ./cmd/cicada-app ./internal/appcore ./internal/appkeys ./internal/appvault \
		./internal/hubaccountwire ./internal/clientwire ./internal/ownerbootstrap \
	>"$run_dir/focused-tests.log" 2>&1
tests_exit=$?
	"${common[@]}" env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{with .Module}} {{.Path}}@{{.Version}}{{end}}{{end}}' ./cmd/cicada-app \
	>"$run_dir/windows-runtime-packages.txt" 2>"$run_dir/windows-runtime-packages.err"
runtime_list_exit=$?
	"${common[@]}" env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -mod=readonly -trimpath -ldflags='-s -w -H=windowsgui' -o /out/cicada-app.exe ./cmd/cicada-app \
	>"$run_dir/windows-build.log" 2>&1
build_exit=$?
set -e

(
	cd "$repo_root"
	find cicada-go -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -print0 \
		| sort -z \
		| xargs -0 -r sha256sum
	sha256sum scripts/test-native-app.sh
) >"$run_dir/source-files-after.sha256"
source_fingerprint_after="$(sha256sum "$run_dir/source-files-after.sha256" | awk '{print $1}')"
source_stable=false
if [[ "$source_fingerprint" == "$source_fingerprint_after" ]]; then
	source_stable=true
fi

export RUN_DIR="$run_dir" SOURCE_HEAD="$source_head" SOURCE_DIRTY="$source_dirty"
export SOURCE_FINGERPRINT="$source_fingerprint" SOURCE_FINGERPRINT_AFTER="$source_fingerprint_after"
export SOURCE_STABLE="$source_stable" IMAGE_DIGEST="$image"
export SYNTHETIC_FIXTURE_CONFIGURED="$fixture_configured"
export VERSION_EXIT="$version_exit" TESTS_EXIT="$tests_exit" RUNTIME_LIST_EXIT="$runtime_list_exit" BUILD_EXIT="$build_exit"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

run = Path(os.environ["RUN_DIR"])
binary = run / "output" / "cicada-app.exe"
binary_sha = None
binary_size = None
if binary.is_file():
    h = hashlib.sha256()
    with binary.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    binary_sha = h.hexdigest()
    binary_size = binary.stat().st_size

result = {
    "schema": "cicada.native-app.validation.v1",
    "source_head": os.environ["SOURCE_HEAD"],
    "source_dirty": os.environ["SOURCE_DIRTY"] == "true",
    "go_source_manifest_sha256": os.environ["SOURCE_FINGERPRINT"],
    "go_source_manifest_sha256_after": os.environ["SOURCE_FINGERPRINT_AFTER"],
    "go_source_stable_during_run": os.environ["SOURCE_STABLE"] == "true",
    "synthetic_openssl_fixture_configured": os.environ["SYNTHETIC_FIXTURE_CONFIGURED"] == "true",
    "builder_image": os.environ["IMAGE_DIGEST"],
    "go_version_exit_code": int(os.environ["VERSION_EXIT"]),
    "focused_tests": [
        "./internal/appui",
        "./internal/appui/native",
        "./cmd/cicada-app",
        "./internal/appcore",
        "./internal/appkeys",
        "./internal/appvault",
        "./internal/hubaccountwire",
        "./internal/clientwire",
        "./internal/ownerbootstrap",
    ],
    "focused_tests_exit_code": int(os.environ["TESTS_EXIT"]),
    "focused_test_counts": {"passed": 0, "skipped": 0, "failed": 0},
    "windows_runtime_package_list_exit_code": int(os.environ["RUNTIME_LIST_EXIT"]),
    "windows_runtime_package_list": "windows-runtime-packages.txt" if int(os.environ["RUNTIME_LIST_EXIT"]) == 0 else None,
    "windows_runtime_package_list_sha256": None,
    "windows_runtime_nonstandard_package_count": 0,
    "windows_amd64_cross_build_exit_code": int(os.environ["BUILD_EXIT"]),
    "windows_amd64_binary": str(binary.relative_to(run)) if binary_sha else None,
    "windows_amd64_binary_sha256": binary_sha,
    "windows_amd64_binary_bytes": binary_size,
    "native_windows_execution": "NOT_RUN",
}
counts = result["focused_test_counts"]
for line in (run / "focused-tests.log").read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("Action") == "pass" and "Test" in event:
        counts["passed"] += 1
    elif event.get("Action") == "skip" and "Test" in event:
        counts["skipped"] += 1
    elif event.get("Action") == "fail" and "Test" in event:
        counts["failed"] += 1
if int(os.environ["RUNTIME_LIST_EXIT"]) == 0:
    runtime_list = (run / "windows-runtime-packages.txt").read_bytes()
    result["windows_runtime_package_list_sha256"] = hashlib.sha256(runtime_list).hexdigest()
    result["windows_runtime_nonstandard_package_count"] = sum(
        1 for line in (run / "windows-runtime-packages.txt").read_text(encoding="utf-8").splitlines() if line
    )
(run / "validation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

chmod 444 "$run_dir"/source-files.sha256 "$run_dir"/source-files-after.sha256 "$run_dir"/go-version.txt "$run_dir"/focused-tests.log \
	"$run_dir"/windows-build.log "$run_dir"/validation.json
if [[ -f "$run_dir/windows-runtime-packages.txt" ]]; then
	chmod 444 "$run_dir"/windows-runtime-packages.txt
fi
if [[ -f "$run_dir/windows-runtime-packages.err" ]]; then
	chmod 444 "$run_dir"/windows-runtime-packages.err
fi
if [[ -f "$run_dir/output/cicada-app.exe" ]]; then
	chmod 444 "$run_dir/output/cicada-app.exe"
fi
chmod 555 "$run_dir/output" "$run_dir"
printf 'Native App validation artifacts: %s\n' "$run_dir"
if [[ "$version_exit" -ne 0 || "$tests_exit" -ne 0 || "$runtime_list_exit" -ne 0 || "$build_exit" -ne 0 || "$source_stable" != true ]]; then
	exit 1
fi
