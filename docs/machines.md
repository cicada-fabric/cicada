# Machine capability discovery

Control registers two local records at startup: `control-local` and
`worker-local`. Their capability maps are collected from the running process and
include OS, architecture, CPU count, `/proc/meminfo` memory, available
toolchains, container runtimes, compilers, `/proc/loadavg` 1-minute load,
free/total disk space for the workspace mount, a network-up indicator, and an
accelerator class. When `nvidia-smi` is available, Control also records GPU
model, count, and aggregate memory; otherwise the accelerator is explicitly
`cpu`.

Inspect the current inventory:

```bash
curl http://127.0.0.1:8787/v1/machines
```

A remote worker can register its own capabilities through `POST /v1/machines`
and refresh liveness through `POST /v1/machines/MACHINE_ID/heartbeat`. Goal
resources use the same capability names: `os`, `arch`, `accelerator`,
`min_memory_gb`, `harness`, and `required_harness`. Control excludes stale or
unavailable records before selecting a machine; `max_load_1m`,
`min_disk_free_gb`, `required_toolchains`, `required_container`, and
`network_required` reject machines that cannot satisfy an explicit constraint.

For a machine that can reach Control, the bundled agent performs registration
and then sends the same non-secret profile on a heartbeat interval:

```bash
CICADA_MACHINE_ID=gpu2 \
CICADA_MACHINE_NAME='GPU server 2' \
CICADA_CONTROL_URL=https://control.example \
cicada machine agent --interval 30s
```

Use `--once` for a provisioning check. The agent reads `CICADA_API_TOKEN` when
Control authentication is enabled and reports transient failures on stderr
before retrying; it never logs the token or private network addresses.

The discovery code records executable paths and interface names, never command
output, IP addresses, or credentials. GPU and disk probing have short
timeouts; missing utilities degrade to an empty capability map or CPU-only
capabilities.
