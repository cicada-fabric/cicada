#!/usr/bin/env bash
set -euo pipefail
umask 077

# Requires an already enrolled debug Client and a running local development Hub.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
data_dir=/gpu1-share/data/cicada-client
output_dir="${CICADA_INTEROP_OUTPUT_DIR:-$data_dir/interop}"
hub_port="${CICADA_INTEROP_HUB_PORT:-8787}"
expected_role="${CICADA_INTEROP_EXPECTED_ROLE:-manager}"
container="${CICADA_INTEROP_EMULATOR_CONTAINER:-cicada-client-interop-emulator}"
serial="${CICADA_INTEROP_EMULATOR_SERIAL:-emulator-5554}"
expected_avd="${CICADA_INTEROP_EXPECTED_AVD:-cicada-interop}"
adb=(docker exec "$container" /opt/android-sdk/platform-tools/adb -s "$serial")

if [[ "$(docker info --format '{{.DockerRootDir}}')" != /gpu1-share/data/* ]]; then
  echo 'Docker data root must be under /gpu1-share/data' >&2
  exit 1
fi
app_apk="$data_dir/build-output/cicada-client-debug.apk"
test_apk="$repo_dir/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
if [[ ! -f "$app_apk" || ! -f "$test_apk" ]]; then
  echo 'Build the app and Android test APK before running this check.' >&2
  exit 1
fi
actual_avd="$("${adb[@]}" emu avd name | tr -d '\r' | head -n 1)"
if [[ "$actual_avd" != "$expected_avd" ]]; then
  echo "Refusing to touch $serial: expected AVD $expected_avd, found $actual_avd" >&2
  exit 1
fi
mkdir -p "$output_dir"
docker cp "$app_apk" "$container:/tmp/cicada-activity-app.apk" >/dev/null
docker cp "$test_apk" "$container:/tmp/cicada-activity-test.apk" >/dev/null
"${adb[@]}" install -r /tmp/cicada-activity-app.apk >/dev/null
"${adb[@]}" install -r /tmp/cicada-activity-test.apk >/dev/null

block_hub() {
  "${adb[@]}" shell su 0 iptables -I OUTPUT 1 -d 10.0.2.2 -p tcp --dport "$hub_port" -j REJECT
}
unblock_hub() {
  "${adb[@]}" shell su 0 iptables -D OUTPUT -d 10.0.2.2 -p tcp --dport "$hub_port" -j REJECT >/dev/null 2>&1 || true
}
run_one() {
  local test_name="$1" output_file="$2"
  "${adb[@]}" shell am instrument -w -e expected_role "$expected_role" -e class \
    "ai.cicada.client.ClientHubInteropTest#$test_name" \
    ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner | tee "$output_file"
  rg -q 'OK \(1 test\)' "$output_file"
}

trap unblock_hub EXIT
block_hub
run_one offlineLeavesExactPending "$output_dir/activity-offline.txt"
"${adb[@]}" shell am force-stop ai.cicada.client
unblock_hub
trap - EXIT

"${adb[@]}" shell am start -n ai.cicada.client/com.cicadaclient.MainActivity >/dev/null
recovered=0
"${adb[@]}" shell rm -f /sdcard/cicada-activity-recovery.xml
for _ in $(seq 1 30); do
  if "${adb[@]}" shell uiautomator dump /sdcard/cicada-activity-recovery.xml >/dev/null 2>&1 &&
    "${adb[@]}" shell cat /sdcard/cicada-activity-recovery.xml 2>/dev/null | rg -q 'text="Hub 权威快照 ·'; then
    recovered=1
    break
  fi
  sleep 2
done
if [[ "$recovered" != 1 ]]; then
  echo 'App did not show a reconciled Hub snapshot after restart.' >&2
  exit 1
fi
# The snapshot becomes visible before the trailing status.changes RPC finishes.
# Instrumentation force-stops the App process, so leave that RPC time to settle.
sleep 20
run_one sessionIsRecoveredAfterActivityRestart "$output_dir/activity-recovered.txt"
echo 'Verified: offline packet persisted, App restarted, original ciphertext recovered, snapshot reconciled.'
