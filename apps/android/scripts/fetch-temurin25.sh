#!/usr/bin/env bash
set -euo pipefail

toolchain_dir=/gpu1-share/data/cicada-client/toolchains/temurin25
archive="$toolchain_dir/temurin25.tar.gz"
sha256=dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e
url='https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz'

mkdir -p "$toolchain_dir"
if [[ -f "$archive" ]] && printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -; then
  exit 0
fi

temp_archive="$(mktemp "$toolchain_dir/.temurin25.XXXXXX")"
trap 'rm -f "$temp_archive"' EXIT
curl --fail --location --retry 3 --connect-timeout 15 --output "$temp_archive" "$url"
printf '%s  %s\n' "$sha256" "$temp_archive" | sha256sum -c -
mv "$temp_archive" "$archive"
