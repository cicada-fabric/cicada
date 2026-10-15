#!/usr/bin/env bash
set -euo pipefail

export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
port="${CICADA_SMOKE_EMULATOR_PORT:-5590}"
serial="emulator-$port"
device=(adb -s "$serial")
printf 'no\n' | avdmanager create avd --name cicada-ui \
  --package 'system-images;android-35;default;x86_64' --force >/dev/null
proxy_args=()
if [[ -n "${CICADA_EMULATOR_PROXY:-}" ]]; then
  proxy_args=(-http-proxy "$CICADA_EMULATOR_PROXY")
fi
emulator -avd cicada-ui -port "$port" -no-window -no-audio -no-boot-anim \
  -no-snapshot -gpu swiftshader_indirect -accel on "${proxy_args[@]}" \
  >/out/emulator-smoke.log 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT
timeout 120 "${device[@]}" wait-for-device
booted=0
for _ in $(seq 1 90); do
  if [[ "$("${device[@]}" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; then
    booted=1
    break
  fi
  sleep 2
done
if [[ "$booted" != 1 ]]; then
  echo 'Emulator did not finish booting' >&2
  exit 1
fi
if [[ -n "${CICADA_EMULATOR_PROXY:-}" ]]; then
  "${device[@]}" shell settings put global http_proxy "$CICADA_EMULATOR_GUEST_PROXY"
fi
"${device[@]}" install -r /tmp/cicada.apk
"${device[@]}" shell am start -n ai.cicada.client/com.cicadaclient.MainActivity
sleep 8
capture() {
  local name="$1"
  local expected="$2"
  "${device[@]}" shell screencap -p "/sdcard/cicada-$name.png"
  "${device[@]}" pull "/sdcard/cicada-$name.png" "/out/cicada-$name.png" >/dev/null
  "${device[@]}" shell uiautomator dump "/sdcard/cicada-$name.xml" >/dev/null
  "${device[@]}" pull "/sdcard/cicada-$name.xml" "/out/cicada-$name.xml" >/dev/null
  if ! grep -q "$expected" "/out/cicada-$name.xml"; then
    echo "Expected text missing from $name: $expected" >&2
    exit 1
  fi
}
capture rn-today '工作进展'
"${device[@]}" shell input tap 95 566
sleep 1
capture rn-nodes '尚未连接 Hub；建立安全会话后显示真实 Node 状态。'
"${device[@]}" shell input tap 159 566
sleep 1
capture rn-work 'Goals'
"${device[@]}" shell input tap 224 566
sleep 1
capture rn-panel '配置安全连接'
"${device[@]}" shell input tap 112 371
sleep 2
capture rn-models '本地模型中心'
"${device[@]}" shell input tap 275 507
sleep 1
capture rn-composer '交给 Control'
"${device[@]}" shell pidof ai.cicada.client >/dev/null
echo 'CICADA React Native Android UI smoke passed: five pages and composer'

if [[ "${CICADA_EMULATOR_SECURITY_CHECK:-}" == 1 || "${CICADA_EMULATOR_VECTOR_CHECK:-}" == 1 ]]; then
  "${device[@]}" install -r /tmp/cicada-test.apk
fi
if [[ "${CICADA_EMULATOR_SECURITY_CHECK:-}" == 1 ]]; then
  "${device[@]}" shell am instrument -w \
    -e hub_base_url "${CICADA_EMULATOR_HUB_BASE_URL:-http://10.0.2.2:8787}" \
    -e class ai.cicada.client.ClientHubTrustNegativeTest \
    ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner \
    | tee /out/cicada-trust-negative.txt
  grep -q 'OK (1 test)' /out/cicada-trust-negative.txt
  echo 'CICADA Hub trust and Grant negative test passed on a fresh emulator'
fi
if [[ "${CICADA_EMULATOR_VECTOR_CHECK:-}" == 1 ]]; then
  "${device[@]}" shell am instrument -w \
    -e class ai.cicada.client.hub.ClientWirePublicVectorTest \
    ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner \
    | tee /out/cicada-public-vector.txt
  grep -q 'OK (5 tests)' /out/cicada-public-vector.txt
  echo 'CICADA public Kotlin wire vectors passed on a fresh emulator'
fi
