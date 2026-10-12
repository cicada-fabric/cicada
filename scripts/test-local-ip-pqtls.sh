#!/usr/bin/env bash
# Explicit disposable IP first-install gate. No daemon socket enters a container.
set -Eeuo pipefail
umask 077
[[ "${CICADA_IP_PQTLS_RUN:-0}" == 1 ]] || { printf 'IP/PQ deployment gate is OFF; set CICADA_IP_PQTLS_RUN=1 to run.\n'; exit 0; }
[[ $# == 3 || $# == 6 ]] || { printf 'usage: %s AMD64_PACKAGE ACCEPTED_AMD64_PQ_STAGE NEW_EVIDENCE_DIR [ARM64_PACKAGE ARM64_ROOTFS QEMU_AARCH64_STATIC]\n' "$0" >&2; exit 2; }
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
package="$(realpath "$1")"
stage="$(realpath "$2")"
evidence="$(realpath -m "$3")"
[[ ! -e "$evidence" && -x "$package/bin/cicada" && -f "$package/BUILD-METADATA.json" && -f "$package/SHA256SUMS" && -d "$stage/include" && -d "$stage/lib" ]] || { printf 'new evidence directory and actual PQ package/stage required\n' >&2; exit 2; }
arm_package=""; arm_root=""; qemu=""
if [[ $# == 6 ]]; then
 arm_package="$(realpath "$4")"; arm_root="$(realpath "$5")"; qemu="$(realpath "$6")"
 [[ -x "$arm_package/bin/cicada" && -f "$arm_package/BUILD-METADATA.json" && -f "$arm_package/SHA256SUMS" && -d "$arm_root" && -x "$qemu" ]] || exit 2
fi
mkdir -m 700 -p "$evidence/commands" "$evidence/go-cache"
module_cache="${CICADA_TEST_MODULE_CACHE:-$repo/.cicada-data/m1-gomodcache}"
[[ -d "$module_cache" ]] || { printf 'offline module cache required\n' >&2; exit 2; }
(cd "$package" && sha256sum --check --status SHA256SUMS)
if [[ -n "$arm_package" ]]; then (cd "$arm_package" && sha256sum --check --status SHA256SUMS); fi
identity="cicada-ip-pq-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
driver="$identity-driver"; net_a="$identity-a"; net_b="$identity-b"
builder='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
cleanup() {
 python3 "$repo/scripts/local-ip-pqtls-driver.py" cleanup --evidence "$evidence" --identity "$identity"
}
trap 'cleanup || true' EXIT INT TERM
python3 "$repo/scripts/hub-build-input-inventory.py" capture --transport pqtls --root "$repo" --pqtls-stage "$stage" --output "$evidence/fixture-input-before.json"
cp "$package/BUILD-METADATA.json" "$evidence/amd64-product-metadata.json"
if [[ -n "$arm_package" ]]; then cp "$arm_package/BUILD-METADATA.json" "$evidence/arm64-product-metadata.json"; fi
sha256sum "$package/bin/cicada" > "$evidence/amd64-binary.sha256"
if [[ -n "$arm_package" ]]; then sha256sum "$arm_package/bin/cicada" "$qemu" > "$evidence/arm64-binary-qemu.sha256"; fi
docker network create --internal --label "cicada.fixture=$identity" "$net_a" > "$evidence/network-a.id"
docker network create --internal --label "cicada.fixture=$identity" "$net_b" > "$evidence/network-b.id"
subnet_ip() { docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$1" | python3 -c 'import ipaddress,sys;print(ipaddress.ip_network(sys.stdin.read().strip())[int(sys.argv[1])])' "$2"; }
hub_a="$(subnet_ip "$net_a" 10)"; hub_b="$(subnet_ip "$net_b" 10)"
node_a="$(subnet_ip "$net_a" 20)"; node_b="$(subnet_ip "$net_b" 20)"
docker create --name "$driver" --label "cicada.fixture=$identity" --network "$net_a" --ip "$hub_a" --cpus 2 --memory 3g --pids-limit 256 --user "$(id -u):$(id -g)" \
 --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs "/tmp:rw,exec,nosuid,nodev,size=536870912,mode=0700,uid=$(id -u),gid=$(id -g)" \
 -v "$repo:/work:ro" -v "$module_cache:/modcache:ro" -v "$evidence/go-cache:/gocache" -v "$evidence:$evidence" -v "$package:/artifact:ro" -v "$stage:/pqtls-stage:ro" \
 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off -e GOMODCACHE=/modcache -e GOCACHE=/gocache -e GOFLAGS=-buildvcs=false \
 -e CGO_ENABLED=1 -e CGO_CFLAGS=-I/pqtls-stage/include -e CGO_LDFLAGS=-L/pqtls-stage/lib -e LD_LIBRARY_PATH=/pqtls-stage/lib -e OPENSSL_CONF=/dev/null \
 -e PQTLS_TEST_OPENSSL=/pqtls-stage/bin/openssl -e "PQTLS_TEST_ARTIFACT_DIR=$evidence" -e CICADA_IP_TEST_BINARY=/artifact/bin/cicada \
 -e "CICADA_IP_TEST_COMMAND_DIR=$evidence/commands" -e "CICADA_IP_TEST_HUB_IP_A=$hub_a" -e "CICADA_IP_TEST_HUB_IP_B=$hub_b" \
 -w /work/cicada-go "$builder" bash -c 'CGO_ENABLED=0 go build -o "$PQTLS_TEST_ARTIFACT_DIR/network-fixture" ./cmd/cicada-ip-network-fixture && go test -tags cicada_pqtls -count=1 -json -timeout=6m -run "^TestIPFirstInstallOperatorCLI$" ./cmd/cicada' > "$evidence/driver.id"
docker network connect --ip "$hub_b" "$net_b" "$driver"
docker start "$driver" > "$evidence/driver-start.log"
set +e
arm_args=()
if [[ -n "$arm_package" ]]; then arm_args=(--arm64-package "$arm_package" --arm64-rootfs "$arm_root" --qemu "$qemu"); fi
timeout 420s python3 "$repo/scripts/local-ip-pqtls-driver.py" run --evidence "$evidence" --identity "$identity" --builder "$builder" --amd64-package "$package" --stage "$stage" --hub-a "$hub_a" --hub-b "$hub_b" --node-a "$node_a" --node-b "$node_b" "${arm_args[@]}"
gate_exit=$?
set -e
printf '%s\n' "$gate_exit" > "$evidence/gate.exit"
docker logs "$driver" > "$evidence/gate.private.jsonl" 2>&1
python3 "$repo/scripts/hub-build-input-inventory.py" capture --transport pqtls --root "$repo" --pqtls-stage "$stage" --output "$evidence/fixture-input-after.json"
cmp "$evidence/fixture-input-before.json" "$evidence/fixture-input-after.json"
(cd "$package" && sha256sum --check --status SHA256SUMS)
if [[ -n "$arm_package" ]]; then (cd "$arm_package" && sha256sum --check --status SHA256SUMS); fi
python3 "$repo/scripts/local-ip-pqtls-driver.py" report --evidence "$evidence" --identity "$identity"
cleanup
trap - EXIT INT TERM
exit "$gate_exit"
