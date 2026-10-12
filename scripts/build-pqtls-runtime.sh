#!/usr/bin/env bash
# Isolated OpenSSL 3.5.9 build. Never installs into the host filesystem.
set -Eeuo pipefail
umask 077
if [[ $# -lt 2 || $# -gt 3 ]]; then
  printf 'Usage: %s openssl-3.5.9.tar.gz NEW_OUTPUT_DIRECTORY [amd64|arm64]\n' "$0" >&2
  exit 2
fi
source_archive="$(realpath "$1")"
output_directory="$(realpath -m "$2")"
target_arch=amd64
if [[ $# -eq 3 ]]; then target_arch="$3"; fi
expected_sha=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
[[ ! -e "$output_directory" ]] || { printf 'Output already exists\n' >&2; exit 2; }
[[ "$(sha256sum "$source_archive" | cut -d ' ' -f1)" == "$expected_sha" ]] || {
  printf 'Pinned source SHA-256 mismatch\n' >&2; exit 1;
}
case "$target_arch" in
  amd64)
    configure_target=linux-x86_64
    expected_triple=x86_64-linux-gnu
    expected_machine='Advanced Micro Devices X86-64'
    expected_interpreter=/lib64/ld-linux-x86-64.so.2
    default_cc=gcc
    cross_prefix=''
    ;;
  arm64)
    configure_target=linux-aarch64
    expected_triple=aarch64-linux-gnu
    expected_machine=AArch64
    expected_interpreter=/lib/ld-linux-aarch64.so.1
    default_cc=aarch64-linux-gnu-gcc
    cross_prefix=aarch64-linux-gnu-
    if [[ "${CICADA_PQTLS_BUILD_IMAGE:-}" != *'@sha256:'* ||
          ! "${CICADA_PQTLS_BUILD_IMAGE:-}" =~ @sha256:[0-9a-f]{64} ]]; then
      printf 'ARM64 builds require a pinned CICADA_PQTLS_BUILD_IMAGE digest\n' >&2; exit 2
    fi
    if [[ "${CICADA_PQTLS_BUILD_SOURCE:-}" != http://snapshot.debian.org/archive/debian/* ]]; then
      printf 'ARM64 builds require the pinned Debian snapshot package source\n' >&2; exit 2
    fi
    ;;
  *) printf 'Unsupported target architecture: %s\n' "$target_arch" >&2; exit 2 ;;
esac
cc="$default_cc"
if printenv CC >/dev/null 2>&1 && [[ -n "$(printenv CC)" ]]; then cc="$(printenv CC)"; fi
command -v "$cc" >/dev/null 2>&1 || { printf 'Target C compiler is required: %s\n' "$cc" >&2; exit 1; }
cc_path="$(command -v "$cc")"
cc_target="$("$cc" -dumpmachine)"
[[ "$cc_target" == "$expected_triple" ]] || {
  printf 'Compiler target mismatch: expected %s, got %s\n' "$expected_triple" "$cc_target" >&2; exit 1;
}
export CC="$cc"
for command_name in make perl python3 readelf sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || { printf '%s is required\n' "$command_name" >&2; exit 1; }
done
mkdir -m 0700 -p "$output_directory"
tar -xzf "$source_archive" -C "$output_directory"
cd "$output_directory/openssl-3.5.9"
if [[ "$target_arch" == arm64 ]]; then
  # Configure prepends --cross-compile-prefix to CC; use the compiler stem.
  export CC=gcc
  if ! ./Configure "$configure_target" --cross-compile-prefix="$cross_prefix" shared no-tests no-docs no-legacy \
      --prefix=/opt/cicada-openssl/3.5.9 --libdir=lib > "$output_directory/configure.log" 2>&1; then
    tail -n 60 "$output_directory/configure.log" >&2
    exit 1
  fi
else
  if ! ./Configure "$configure_target" shared no-tests no-docs no-legacy \
      --prefix=/opt/cicada-openssl/3.5.9 --libdir=lib > "$output_directory/configure.log" 2>&1; then
    tail -n 60 "$output_directory/configure.log" >&2
    exit 1
  fi
fi
if ! make -s -j2 build_generated build_libs_nodep build_modules_nodep apps/openssl \
    > "$output_directory/build.log" 2>&1; then
  tail -n 60 "$output_directory/build.log" >&2
  exit 1
fi
make -s install_sw DESTDIR="$output_directory/stage" > "$output_directory/install.log" 2>&1
runtime_directory="$output_directory/stage/opt/cicada-openssl/3.5.9"
mkdir -p "$runtime_directory/share/licenses/openssl"
cp LICENSE.txt "$runtime_directory/share/licenses/openssl/"
if [[ -f NOTICE.txt ]]; then cp NOTICE.txt "$runtime_directory/share/licenses/openssl/"; fi
for name in libssl.so.3 libcrypto.so.3; do
  [[ -f "$runtime_directory/lib/$name" ]] || { printf 'Missing target OpenSSL library %s\n' "$name" >&2; exit 1; }
done
elf_machine() {
  readelf -h "$1" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }'
}
for artifact in "$runtime_directory/bin/openssl" "$runtime_directory/lib/libssl.so.3" "$runtime_directory/lib/libcrypto.so.3"; do
  actual_machine="$(elf_machine "$artifact")"
  [[ "$actual_machine" == "$expected_machine" ]] || {
    printf 'OpenSSL ELF Machine mismatch for %s: expected %s, got %s\n' \
      "$(basename "$artifact")" "$expected_machine" "$actual_machine" >&2; exit 1;
  }
done
interpreter="$(readelf -W -l "$runtime_directory/bin/openssl" |
  sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')"
[[ "$interpreter" == "$expected_interpreter" ]] || {
  printf 'OpenSSL ELF loader mismatch: expected %s, got %s\n' "$expected_interpreter" "$interpreter" >&2; exit 1;
}
for library_name in libssl.so.3 libcrypto.so.3; do
  if ! readelf -W -d "$runtime_directory/bin/openssl" | grep -F "Shared library: [$library_name]" >/dev/null; then
    printf 'OpenSSL CLI does not declare expected dependency %s\n' "$library_name" >&2; exit 1;
  fi
done
if [[ "$target_arch" == amd64 ]]; then
  LD_LIBRARY_PATH="$runtime_directory/lib" OPENSSL_CONF=/dev/null \
    "$runtime_directory/bin/openssl" version -a > "$output_directory/runtime-version.txt"
  [[ "$(head -n 1 "$output_directory/runtime-version.txt")" == 'OpenSSL 3.5.9 '* ]] || {
    printf 'Loaded OpenSSL runtime version mismatch\n' >&2; exit 1;
  }
  LD_LIBRARY_PATH="$runtime_directory/lib" ldd "$runtime_directory/bin/openssl" \
    > "$output_directory/runtime-loader.txt"
  for library_name in libssl.so.3 libcrypto.so.3; do
    loaded_path="$(awk -v name="$library_name" '$1 == name { print $3 }' "$output_directory/runtime-loader.txt")"
    [[ "$loaded_path" == "$runtime_directory/lib/$library_name" ]] || {
      printf 'Loaded runtime library mismatch: %s\n' "$library_name" >&2; exit 1;
    }
  done
else
  {
    printf 'OpenSSL 3.5.9 Linux/arm64 ELF inspection; execution deferred to explicit user-mode QEMU gate.\n'
    readelf -W -l "$runtime_directory/bin/openssl"
    readelf -W -d "$runtime_directory/bin/openssl"
  } > "$output_directory/runtime-loader.txt"
fi
mkdir -m 0700 -p "$output_directory/runtime/opt/cicada-openssl/3.5.9"
cp -a "$runtime_directory/bin" "$runtime_directory/lib" "$runtime_directory/share" \
  "$output_directory/runtime/opt/cicada-openssl/3.5.9/"
runtime_only="$output_directory/runtime/opt/cicada-openssl/3.5.9"
rm -f "$runtime_only/lib/"*.a
rm -rf "$runtime_only/lib/pkgconfig"
header_digest="$(python3 - "$runtime_directory/include" <<'PYCODE'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
rows = []
for path in sorted(root.rglob("*")):
    if path.is_symlink():
        raise SystemExit("OpenSSL header symlink is not allowed")
    if path.is_file():
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root.parent).as_posix()}\n")
print(hashlib.sha256("".join(rows).encode()).hexdigest())
PYCODE
)"
openssl_sha="$(sha256sum "$runtime_directory/lib/libssl.so.3" | cut -d ' ' -f1)"
crypto_sha="$(sha256sum "$runtime_directory/lib/libcrypto.so.3" | cut -d ' ' -f1)"
license_sha="$(sha256sum "$runtime_directory/share/licenses/openssl/LICENSE.txt" | cut -d ' ' -f1)"
cli_sha="$(sha256sum "$runtime_directory/bin/openssl" | cut -d ' ' -f1)"
compiler_version="$("$cc" --version | head -n 1)"
binutils_version="$(readelf --version | head -n 1)"
glibc_symbol="$(readelf --version-info "$runtime_directory/bin/openssl" 2>/dev/null |
  grep -oE 'GLIBC_[0-9]+([.][0-9]+)+' | sort -Vu | tail -n 1 || true)"
[[ -n "$glibc_symbol" ]] || glibc_symbol=unknown
toolchain_inventory_sha=not-recorded
toolchain_license_inventory_sha=not-recorded
toolchain_packages_json="$output_directory/toolchain-packages.json"
toolchain_licenses_json="$output_directory/toolchain-licenses.json"
apt_inrelease_sha=not-recorded
if command -v dpkg-query >/dev/null 2>&1; then
  if [[ "$target_arch" == arm64 ]]; then
    python3 - "$toolchain_packages_json" "$toolchain_licenses_json" <<'PYCODE'
import hashlib, json, pathlib, re, subprocess, sys
package_output, license_output = map(pathlib.Path, sys.argv[1:])
raw = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n"], text=True)
selected = []
for line in raw.splitlines():
    name, arch, version, source, source_version = (line.split("\t") + [""] * 5)[:5]
    if not re.search(r"(aarch64|arm64|cross|binutils|gcc-[0-9]+|cpp-[0-9]+)", name):
        continue
    query = f"{name}:{arch}={version}"
    info = subprocess.check_output(["apt-cache", "show", query], text=True, stderr=subprocess.DEVNULL)
    blocks = [dict(row.split(": ", 1) for row in block.splitlines() if ": " in row)
              for block in info.split("\n\n") if block.strip()]
    match = next((row for row in blocks if row.get("Version") == version and row.get("SHA256")), None)
    if not match:
        raise SystemExit("apt metadata lacks a signed index SHA256 for installed cross-toolchain package")
    selected.append({"package": name, "architecture": arch, "version": version,
                     "source_package": source, "source_version": source_version,
                     "deb_sha256": match["SHA256"]})
selected.sort(key=lambda row: (row["package"], row["architecture"]))
if not selected:
    raise SystemExit("cross-toolchain package inventory is empty")
package_output.write_text(json.dumps(selected, sort_keys=True, separators=(",", ":")) + "\n")
licenses = []
for row in selected:
    paths = subprocess.check_output(["dpkg-query", "-L", row["package"]], text=True, stderr=subprocess.DEVNULL).splitlines()
    for path in paths:
        candidate = pathlib.Path(path)
        if candidate.is_file() and re.search(r"/usr/share/doc/[^/]+/copyright$", path):
            licenses.append({"package": row["package"], "path": path,
                             "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()})
licenses.sort(key=lambda row: (row["package"], row["path"]))
if not licenses:
    raise SystemExit("cross-toolchain license inventory is empty")
license_output.write_text(json.dumps(licenses, sort_keys=True, separators=(",", ":")) + "\n")
PYCODE
    inrelease_count="$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' | wc -l)"
    [[ "$inrelease_count" == 1 ]] || { printf 'Expected one pinned Debian snapshot InRelease\n' >&2; exit 1; }
    inrelease_path="$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' -print -quit)"
    apt_inrelease_sha="$(sha256sum "$inrelease_path" | cut -d ' ' -f1)"
    toolchain_inventory_sha="$(sha256sum "$toolchain_packages_json" | cut -d ' ' -f1)"
    toolchain_license_inventory_sha="$(sha256sum "$toolchain_licenses_json" | cut -d ' ' -f1)"
  fi
fi
build_image=local-build-host-not-pinned
build_source=local-build-host
if printenv CICADA_PQTLS_BUILD_IMAGE >/dev/null 2>&1; then build_image="$(printenv CICADA_PQTLS_BUILD_IMAGE)"; fi
if printenv CICADA_PQTLS_BUILD_SOURCE >/dev/null 2>&1; then build_source="$(printenv CICADA_PQTLS_BUILD_SOURCE)"; fi
python3 - "$runtime_directory" "$target_arch" "$expected_triple" "$expected_machine" "$interpreter" \
  "$source_archive" "$header_digest" "$openssl_sha" "$crypto_sha" "$license_sha" "$cli_sha" \
  "$compiler_version" "$cc_target" "$cc_path" "$binutils_version" "$glibc_symbol" \
  "$build_image" "$build_source" "$toolchain_inventory_sha" "$toolchain_license_inventory_sha" \
  "$toolchain_packages_json" "$toolchain_licenses_json" "$apt_inrelease_sha" <<'PYCODE'
import hashlib, json, pathlib, sys
(root, arch, triple, machine, loader, source_archive, headers, libssl, libcrypto,
 license_sha, openssl_cli, compiler_version, compiler_target, compiler_path,
 binutils_version, glibc_symbol, build_image, build_source, packages_sha, licenses_sha,
 packages_path, licenses_path, apt_inrelease_sha) = sys.argv[1:]
root = pathlib.Path(root)
packages = json.loads(pathlib.Path(packages_path).read_text()) if packages_sha != "not-recorded" else []
licenses = json.loads(pathlib.Path(licenses_path).read_text()) if licenses_sha != "not-recorded" else []
metadata = {
    "schema_version": "cicada.pqtls-openssl-stage.v1",
    "target": {"platform": "linux/" + arch, "goarch": arch, "triple": triple,
               "elf_class": 64, "elf_endianness": "little", "elf_machine": machine,
               "interpreter": loader},
    "openssl": {"version": "3.5.9", "source_url": "https://www.openssl.org/source/openssl-3.5.9.tar.gz",
                "source_archive_sha256": hashlib.sha256(pathlib.Path(source_archive).read_bytes()).hexdigest(),
                "headers_sha256": headers,
                "runtime_files": {"lib/libssl.so.3": libssl, "lib/libcrypto.so.3": libcrypto,
                                  "bin/openssl": openssl_cli,
                                  "share/licenses/openssl/LICENSE.txt": license_sha}},
    "build_toolchain": {"image": build_image, "package_source": build_source,
                        "apt_inrelease_sha256": apt_inrelease_sha,
                        "compiler": {"path": compiler_path, "version": compiler_version,
                                     "target": compiler_target},
                        "binutils": binutils_version,
                        "packages": packages, "licenses": licenses,
                        "package_inventory_sha256": packages_sha,
                        "license_inventory_sha256": licenses_sha},
    "observed_glibc_symbol": glibc_symbol,
    "execution_validation": "native-amd64" if arch == "amd64" else "NOT_RUN; explicit user-mode QEMU gate required"
}
(root / "PQTLS-STAGE-METADATA.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
PYCODE
cp "$runtime_directory/PQTLS-STAGE-METADATA.json" "$runtime_only/PQTLS-STAGE-METADATA.json"
tar -czf "$output_directory/openssl-3.5.9-linux-$target_arch-runtime.tar.gz" \
  -C "$output_directory/runtime" opt
{
  printf 'export CC=%q\n' "$cc_path"
  printf 'export CGO_ENABLED=1\n'
  printf 'export GOOS=linux\n'
  printf 'export GOARCH=%q\n' "$target_arch"
  printf 'export CGO_CFLAGS=%q\n' "-I$runtime_directory/include"
  printf 'export CGO_LDFLAGS=%q\n' "-L$runtime_directory/lib"
  printf 'export LD_LIBRARY_PATH=%q\n' "$runtime_directory/lib"
  printf 'export OPENSSL_CONF=/dev/null\n'
  printf 'export PQTLS_TEST_OPENSSL=%q\n' "$runtime_directory/bin/openssl"
} > "$output_directory/cgo-runtime.env"
(
  cd "$runtime_directory"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "$output_directory/stage-sha256.txt"
sha256sum "$source_archive" "$runtime_directory/lib/libssl.so.3" \
  "$runtime_directory/lib/libcrypto.so.3" "$runtime_directory/share/licenses/openssl/"* \
  "$output_directory/openssl-3.5.9-linux-$target_arch-runtime.tar.gz" \
  "$runtime_directory/PQTLS-STAGE-METADATA.json" > "$output_directory/sha256.txt"
printf 'Isolated OpenSSL 3.5.9 linux/%s stage built at %s\n' "$target_arch" "$runtime_directory"
