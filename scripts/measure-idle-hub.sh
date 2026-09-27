#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/measure-idle-hub.sh --image sha256:<64 hex digits> [--output-dir DIR]

Measure a fresh, disposable Hub at idle. The image must already exist locally.
Output defaults to .cicada-data/footprint/ under the repository root.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_dir="${repo_root}/.cicada-data/footprint"
image_id=""
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --image)
      (($# >= 2)) || { usage >&2; exit 2; }
      image_id="$2"; shift 2 ;;
    --output-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      output_dir="$2"; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ && -n "$output_dir" ]] || { usage >&2; exit 2; }
for command_name in docker python3 mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
actual_id="$(docker image inspect --format '{{.Id}}' "$image_id" 2>/dev/null)" || {
  printf 'Exact image ID is not present locally; no pull or build was attempted.\n' >&2
  exit 1
}
[[ "$actual_id" == "$image_id" ]] || { printf 'Local image ID mismatch.\n' >&2; exit 1; }
role="$(docker image inspect --format '{{index .Config.Labels "org.cicada.role"}}' "$image_id")"
[[ "$role" == hub ]] || { printf 'Image is not labeled as a CICADA Hub runtime.\n' >&2; exit 1; }

umask 077
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cicada-idle-hub.XXXXXXXX")"
container="$(basename "$scratch")"
started=0
cleanup() {
  if ((started)); then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
mkdir "$scratch/state" "$scratch/workspace"
python3 - "$scratch/hub.env" <<'PY'
from pathlib import Path
import secrets
import sys

Path(sys.argv[1]).write_text('CICADA_API_TOKEN=' + secrets.token_hex(32) + '\n')
PY
chmod 0600 "$scratch/hub.env"
docker run --pull=never --rm -d --name "$container" --memory=128m --memory-swap=128m --cpus=0.5 \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  --network bridge -p 127.0.0.1::8787 --env-file "$scratch/hub.env" \
  -v "$scratch/state:/state" -v "$scratch/workspace:/workspace" \
  "$image_id" >/dev/null
started=1
port="$(docker port "$container" 8787/tcp)"
[[ "$port" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { printf 'Hub did not bind a random loopback port.\n' >&2; exit 1; }
port="${port##*:}"
mkdir -p -- "$output_dir"

python3 - "$container" "$image_id" "$port" "$output_dir" <<'PY'
import datetime as dt
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

container, image_id, port, output_dir = sys.argv[1:]

def docker(*args, optional=False):
    result = subprocess.run(('docker', *args), capture_output=True, text=True)
    if result.returncode:
        if optional:
            return None
        raise SystemExit('Disposable Hub became unavailable during measurement')
    return result.stdout

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
url = 'http://127.0.0.1:' + port + '/healthz'
for _ in range(60):
    try:
        with opener.open(url, timeout=1) as response:
            if response.status == 200:
                break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(0.5)
else:
    raise SystemExit('Disposable Hub did not become healthy within 30 seconds')

image = json.loads(docker('image', 'inspect', image_id))[0]
labels = image.get('Config', {}).get('Labels') or {}

def cgroup_value(path):
    value = docker('exec', container, 'cat', path, optional=True)
    return value.strip() if value is not None else None

def proc_stat_cpu_ticks(raw):
    if raw is None:
        return None
    # The comm field is parenthesized and may itself contain spaces or ')'.
    # Everything after its final ')' starts at proc stat field 3 (state).
    close = raw.rfind(')')
    if close < 0:
        return None
    fields = raw[close + 1:].split()
    if len(fields) <= 12:
        return None
    try:
        user_ticks = int(fields[11])   # field 14: utime
        system_ticks = int(fields[12]) # field 15: stime
    except ValueError:
        return None
    if user_ticks < 0 or system_ticks < 0:
        return None
    return user_ticks + system_ticks

try:
    clock_ticks_per_second = int(os.sysconf('SC_CLK_TCK'))
    if clock_ticks_per_second <= 0:
        clock_ticks_per_second = None
except (AttributeError, OSError, ValueError):
    clock_ticks_per_second = None

def sample():
    status = docker('exec', container, 'cat', '/proc/1/status')
    fields = {}
    for line in status.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields[key] = value.strip()
    def proc_kib(name):
        value = fields.get(name, '')
        return int(value.split()[0]) if value.endswith('kB') else None
    pid1_stat = cgroup_value('/proc/1/stat')
    pid1_cpu_ticks = proc_stat_cpu_ticks(pid1_stat)
    pid1_cpu_seconds = (
        pid1_cpu_ticks / clock_ticks_per_second
        if pid1_cpu_ticks is not None and clock_ticks_per_second is not None else None
    )
    cpu_stat = cgroup_value('/sys/fs/cgroup/cpu.stat')
    if cpu_stat is not None:
        cpu_fields = dict(line.split() for line in cpu_stat.splitlines() if len(line.split()) == 2)
        usage = int(cpu_fields['usage_usec']) / 1_000_000 if cpu_fields.get('usage_usec', '').isdigit() else None
        memory = cgroup_value('/sys/fs/cgroup/memory.current')
        peak = cgroup_value('/sys/fs/cgroup/memory.peak')
        cgroup = 'v2'
    else:
        cpu_ns = cgroup_value('/sys/fs/cgroup/cpuacct/cpuacct.usage')
        usage = int(cpu_ns) / 1_000_000_000 if cpu_ns is not None and cpu_ns.isdigit() else None
        memory = cgroup_value('/sys/fs/cgroup/memory/memory.usage_in_bytes')
        peak = cgroup_value('/sys/fs/cgroup/memory/memory.max_usage_in_bytes')
        cgroup = 'v1' if memory is not None or cpu_ns is not None else 'unavailable'
    return {
        'rss_bytes': proc_kib('VmRSS') * 1024 if proc_kib('VmRSS') is not None else None,
        'process_peak_rss_bytes': proc_kib('VmHWM') * 1024 if proc_kib('VmHWM') is not None else None,
        'pid1_cpu_ticks': pid1_cpu_ticks,
        'pid1_cpu_seconds': pid1_cpu_seconds,
        'cgroup_memory_bytes': int(memory) if memory and memory.isdigit() else None,
        'cgroup_peak_memory_bytes': int(peak) if peak and peak.isdigit() else None,
        'cgroup_cpu_usage_seconds': usage,
        'cgroup_version': cgroup,
        '_sampled_at_monotonic': time.monotonic(),
    }

def counter_delta(current, previous, name):
    if current is None or previous is None:
        return None
    if current < previous:
        raise SystemExit(name + ' counter regressed during measurement')
    return current - previous

baseline = sample()
previous_sampled_at = baseline.pop('_sampled_at_monotonic')
baseline.update({
    'sample_period_seconds': None,
    'pid1_cpu_delta_ticks': None,
    'pid1_cpu_delta_seconds': None,
    'cgroup_cpu_delta_seconds': None,
})
previous = baseline
samples = []
started_at = previous_sampled_at
for interval in range(1, 4):
    time.sleep(2)
    measured = sample()
    sampled_at = measured.pop('_sampled_at_monotonic')
    sample_period = sampled_at - previous_sampled_at
    if sample_period <= 0:
        raise SystemExit('sample clock failed to advance')
    process_delta_ticks = counter_delta(
        measured['pid1_cpu_ticks'], previous['pid1_cpu_ticks'], 'PID 1 CPU'
    )
    measured['interval'] = interval
    measured['elapsed_seconds'] = round(sampled_at - started_at, 3)
    measured['sample_period_seconds'] = round(sample_period, 3)
    measured['pid1_cpu_delta_ticks'] = process_delta_ticks
    measured['pid1_cpu_delta_seconds'] = (
        process_delta_ticks / clock_ticks_per_second
        if process_delta_ticks is not None and clock_ticks_per_second is not None else None
    )
    measured['cgroup_cpu_delta_seconds'] = counter_delta(
        measured['cgroup_cpu_usage_seconds'], previous['cgroup_cpu_usage_seconds'], 'cgroup CPU'
    )
    samples.append(measured)
    previous = measured
    previous_sampled_at = sampled_at

artifact = {
    'schema': 'cicada-idle-hub-footprint-v1',
    'measured_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
    'scope': 'fresh Hub idle, zero enrolled devices and native Threads',
    'not_measured': ['Node', 'models', 'Android', 'loaded Hub'],
    'measurement_note': 'Container cgroup CPU deltas include sampling docker exec overhead. PID 1 CPU counters come from /proc/1/stat and exclude sampler processes. A missing metric is null, never a substituted zero.',
    'image': {
        'id': image['Id'], 'architecture': image.get('Architecture'),
        'size_bytes': image.get('Size'),
        'revision': labels.get('org.opencontainers.image.revision'),
        'dirty': labels.get('org.cicada.build.dirty'),
        'source_fingerprint': labels.get('org.cicada.build.source-fingerprint'),
    },
    'runtime': {
        'docker_server_version': docker('version', '--format', '{{.Server.Version}}').strip(),
        'host_system': platform.system(), 'host_kernel': platform.release(),
        'host_architecture': platform.machine(), 'host_logical_cpus': os.cpu_count(),
        'memory_limit_bytes': 128 * 1024 * 1024, 'cpu_limit_cores': 0.5,
        'sample_interval_seconds': 2,
        'pid1_cpu_clock_ticks_per_second': clock_ticks_per_second,
        'pid1_cpu_clock_source': 'host os.sysconf(SC_CLK_TCK), same kernel as container',
    },
    'baseline': baseline,
    'samples': samples,
}
name = 'idle-hub-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4) + '.json'
path = Path(output_dir) / name
with path.open('x') as output:
    json.dump(artifact, output, indent=2, sort_keys=True)
    output.write('\n')
print(path)
PY
