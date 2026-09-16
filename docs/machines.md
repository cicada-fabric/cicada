# Machine capability discovery

Control registers two local records at startup: `control-local` and
`worker-local`. Their capability maps are collected from the running process and
include OS, architecture, CPU count, `/proc/meminfo` memory, available
toolchains, container runtimes, compilers, `/proc/loadavg` 1-minute load,
free/total disk space for the workspace mount, a network-up indicator, and an
accelerator class. When `nvidia-smi`, `rocminfo`, or `npu-smi` is available,
Control records CUDA, ROCm, or Ascend/CANN model information and aggregate
memory where the tool reports it; otherwise the accelerator is explicitly
`cpu`.

Inspect the current inventory:

```bash
curl http://127.0.0.1:8787/v1/machines
```

For a host that is reachable through the operator's SSH configuration, pairing
can collect the same profile without manually copying fields. The remote
command is fixed to `cicada machine discover`; it emits JSON only, and the
local command submits the profile through the authenticated Control API:

```bash
cicada machine pair --host gpu2.example --user runner --id gpu2 \
  --name 'GPU server 2' --control-url https://control.example
```

`--identity-file` and `--port` select the SSH key and port when needed. Pairing
uses `BatchMode` and a connection timeout, never asks for a password, and does
not persist the SSH host or private key in the capability profile. The remote
profile command is also useful for an explicit read-only check:

```bash
ssh gpu2.example cicada machine discover
```

For local-network discovery, opt a machine agent into the unauthenticated UDP
profile responder and query it from the operator host:

```bash
cicada machine agent --lan-discovery --lan-port 8788
cicada machine discover-lan --port 8788 --wait 2s
```

LAN discovery returns non-secret profiles only and never registers or trusts a
machine automatically. Use the returned profile with an explicit machine
registration or pair it through SSH after verifying the host identity.

A remote worker can register its own capabilities through `POST /v1/machines`,
refresh liveness through `POST /v1/machines/MACHINE_ID/heartbeat`, and claim
Workers assigned by Control. Goal
resources use the same capability names: `os`, `arch`, `accelerator`,
`min_memory_gb`, `harness`, and `required_harness`. Control excludes stale or
unavailable records before selecting a machine; `max_load_1m`,
`min_disk_free_gb`, `required_toolchains`, `required_container`, and
`network_required` reject machines that cannot satisfy an explicit constraint.

For a machine that can reach Control, the bundled agent registers, sends the
same non-secret profile on a heartbeat interval, and executes queued Codex or
Shell Workers:

```bash
CICADA_MACHINE_ID=gpu2 \
CICADA_MACHINE_NAME='GPU server 2' \
CICADA_CONTROL_URL=https://control.example \
cicada machine agent --interval 30s
```

Use `--once` to register and drain the jobs currently assigned to the Machine.
The agent reads `CICADA_API_TOKEN` when Control authentication is enabled and
retries result delivery without declaring the Machine available in between; it
never logs the token or private network addresses. The complete execution and
shared-workspace contract is in
[`remote-execution.md`](remote-execution.md).

The discovery code records executable paths and interface names, never command
output, IP addresses, or credentials. GPU and disk probing have short
timeouts; missing utilities degrade to an empty capability map or CPU-only
capabilities.
