#!/usr/bin/env bash
# Runs only inside a uniquely named disposable Docker container.
set -euo pipefail
umask 077

export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
port="${CICADA_TWO_OWNER_EMULATOR_PORT:?}"
adb_port="${ANDROID_ADB_SERVER_PORT:?}"
evidence_owner="${CICADA_EVIDENCE_OWNER:?}"
device=(adb -P "$adb_port" -s "emulator-$port")
emulator_pid=
cleanup() {
  if [[ -n "$emulator_pid" ]]; then kill "$emulator_pid" 2>/dev/null || true; fi
  adb -P "$adb_port" kill-server >/dev/null 2>&1 || true
  for file in /out/emulator.log /out/adb-start.log /out/avd-create.log /out/emulator-ready.json; do
    if [[ -f "$file" ]]; then chown "$evidence_owner" "$file"; fi
  done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf 'no\n' | avdmanager create avd --name cicada-two-owner \
  --package 'system-images;android-35;default;x86_64' --force >/out/avd-create.log 2>&1
adb -P "$adb_port" start-server >/out/adb-start.log 2>&1
emulator -avd cicada-two-owner -port "$port" -no-window -no-audio \
  -no-boot-anim -no-snapshot -gpu swiftshader_indirect -accel on \
  >/out/emulator.log 2>&1 &
emulator_pid=$!
timeout 120 "${device[@]}" wait-for-device
for _ in $(seq 1 120); do
  if [[ "$("${device[@]}" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; then
    printf '{"result":"READY","serial":"emulator-%s","adb_port":%s}\n' "$port" "$adb_port" > /out/emulator-ready.json
    chown "$evidence_owner" /out/emulator.log /out/adb-start.log /out/avd-create.log /out/emulator-ready.json
    wait "$emulator_pid"
    exit $?
  fi
  sleep 1
done
echo 'Disposable emulator boot timed out' >&2
exit 1
