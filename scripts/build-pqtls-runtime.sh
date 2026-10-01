#!/usr/bin/env bash
# Offline, isolated OpenSSL build. Never installs into the host filesystem.
set -euo pipefail
umask 077
if [[ $# != 2 ]]; then
  printf 'Usage: %s openssl-3.5.9.tar.gz NEW_OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi
source_archive="$(realpath "$1")"
output_directory="$(realpath -m "$2")"
expected_sha=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
[[ ! -e "$output_directory" ]] || { printf 'Output already exists\n' >&2; exit 2; }
[[ "$(sha256sum "$source_archive" | cut -d ' ' -f1)" == "$expected_sha" ]] || {
  printf 'Pinned source SHA-256 mismatch\n' >&2; exit 1;
}
mkdir -m 0700 -p "$output_directory"
tar -xzf "$source_archive" -C "$output_directory"
cd "$output_directory/openssl-3.5.9"
[[ "$(uname -m)" == x86_64 ]] || { printf 'Unsupported: only tested Linux amd64\n' >&2; exit 1; }
./Configure linux-x86_64 shared no-tests no-docs no-legacy \
  --prefix=/opt/cicada-openssl/3.5.9 --libdir=lib > "$output_directory/configure.log" 2>&1
make -s -j2 build_generated build_libs_nodep build_modules_nodep apps/openssl \
  > "$output_directory/build.log" 2>&1
make -s install_sw DESTDIR="$output_directory/stage" > "$output_directory/install.log" 2>&1
runtime_directory="$output_directory/stage/opt/cicada-openssl/3.5.9"
mkdir -p "$runtime_directory/share/licenses/openssl"
cp LICENSE.txt "$runtime_directory/share/licenses/openssl/"
if [[ -f NOTICE.txt ]]; then cp NOTICE.txt "$runtime_directory/share/licenses/openssl/"; fi
# The runtime artifact excludes development headers/static archives/pkg-config.
mkdir -p "$output_directory/runtime/opt/cicada-openssl/3.5.9"
cp -a "$runtime_directory/bin" "$runtime_directory/lib" "$runtime_directory/share" \
  "$output_directory/runtime/opt/cicada-openssl/3.5.9/"
rm -f "$output_directory/runtime/opt/cicada-openssl/3.5.9/lib/"*.a
rm -rf "$output_directory/runtime/opt/cicada-openssl/3.5.9/lib/pkgconfig"
tar -czf "$output_directory/openssl-3.5.9-linux-amd64-runtime.tar.gz" \
  -C "$output_directory/runtime" opt
# Explicit per-process paths; source this file inside the same build container.
# %q produces Bash quoting, including paths containing spaces or shell symbols.
{
  printf 'export CGO_CFLAGS=%q\n' "-I$runtime_directory/include"
  printf 'export CGO_LDFLAGS=%q\n' "-L$runtime_directory/lib"
  printf 'export LD_LIBRARY_PATH=%q\n' "$runtime_directory/lib"
  printf 'export OPENSSL_CONF=/dev/null\n'
  printf 'export PQTLS_TEST_OPENSSL=%q\n' "$runtime_directory/bin/openssl"
} > "$output_directory/cgo-runtime.env"
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
sha256sum "$source_archive" "$runtime_directory/lib/libssl.so.3" \
  "$runtime_directory/lib/libcrypto.so.3" "$runtime_directory/share/licenses/openssl/"* \
  "$output_directory/openssl-3.5.9-linux-amd64-runtime.tar.gz" > "$output_directory/sha256.txt"
printf 'Isolated OpenSSL 3.5.9 built at %s\n' "$output_directory"
