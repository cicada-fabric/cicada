# Machine capability discovery

Control registers two local records at startup: `control-local` and
`worker-local`. Their capability maps are collected from the running process and
include OS, architecture, CPU count, `/proc/meminfo` memory, available
toolchains, and an accelerator class. When `nvidia-smi` is available, Control
also records GPU model, count, and aggregate memory; otherwise the accelerator
is explicitly `cpu`.

Inspect the current inventory:

```bash
curl http://127.0.0.1:8787/v1/machines
```

A remote worker can register its own capabilities through `POST /v1/machines`
and refresh liveness through `POST /v1/machines/MACHINE_ID/heartbeat`. Goal
resources use the same capability names: `os`, `arch`, `accelerator`,
`min_memory_gb`, `harness`, and `required_harness`. Control excludes stale or
unavailable records before selecting a machine.

The discovery code records executable paths, never command output or
credentials. GPU probing has a short timeout and degrades to CPU-only
capabilities when the vendor utility is absent.
