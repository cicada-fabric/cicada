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
matched before a worker is launched. The MVP supports exact capability keys,
required harnesses, accelerator/OS/architecture values, and
`min_memory_gb`.

For example:

```json
{
  "objective": "Profile the CUDA kernel",
  "resources": {
    "accelerator": "H100",
    "min_memory_gb": 40,
    "harness": "codex"
  }
}
```

The periodic monitor loop records a `MonitorEvaluated` event for active running
workers. Its correction policy remains conservative in the MVP: automatic
commands are still generated only from explicit monitor/API input, while the
evaluation hook is ready for progress and stall policies.
