# Machine discovery and scheduling

Control keeps a durable capability profile for every Machine. A worker
heartbeat refreshes `last_seen` and can update the profile without changing the
machine's stable ID:

```bash
curl -X POST http://127.0.0.1:8787/v1/machines/gpu2/heartbeat \
  -H 'content-type: application/json' \
  -d '{"status":"available","capabilities":{"os":"linux","accelerator":"H100","memory_gb":80,"harnesses":["codex"]}}'
```

The scheduler ignores machines whose status is not `available` or `idle`, and
marks a machine `offline` after the configured heartbeat timeout
(`CICADA_MACHINE_STALE_SECONDS`, two minutes by default). Goal resources are
matched before a worker is launched. The current scheduler supports exact
capability keys, required harnesses, accelerator/OS/architecture values,
`min_memory_gb`, `max_load_1m`, `min_disk_free_gb`, `required_toolchains`,
`required_container`, and `network_required`. Toolchain and container
constraints accept either one command name or a list of names.

Workers selected for `control-local` or `worker-local` are launched by Control.
Workers selected for any other Machine remain durably queued until that
Machine's agent polls and atomically claims them. The agent reports completion,
failure, bounded evidence, and the Codex thread ID back to the same Goal state
machine. If a remote heartbeat expires, Control marks the Machine offline and
requeues its running Workers for recovery; the two reserved local Machines are
never marked stale by the remote heartbeat sweep.

For example:

```json
{
  "objective": "Profile the CUDA kernel",
  "resources": {
    "accelerator": "H100",
    "min_memory_gb": 40,
    "harness": "codex",
    "min_disk_free_gb": 20,
    "required_toolchains": ["git", "python3"],
    "network_required": true
  }
}
```

The periodic monitor loop records a `MonitorEvaluated` event for active running
workers. Its correction policy remains conservative: it queues a bounded stall
correction after the configured inactivity threshold, and explicit API or peer
commands use the same per-Worker command queue. A separate
[`completion verification`](completion-verification.md) step checks bounded
evidence before accepting a Worker's final claim.
