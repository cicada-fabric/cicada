# Manual Codex TUI threads

Cicada can bridge two Codex TUIs that the operator opened manually. The
interactive processes stay under operator control; Control only invokes the
official `codex queue` command and records whether it succeeded.

After both TUIs are open, list their session UUIDs:

```bash
./scripts/list-codex-threads.sh
```

Register each UUID. The workspace must be inside the mounted Control workspace
root and must already exist:

```bash
docker compose exec -T control cicada thread register A_UUID Thread-A /workspace/manual-a
docker compose exec -T control cicada thread register B_UUID Thread-B /workspace/manual-b
docker compose exec -T control cicada thread sessions
```

Trigger a turn in the other TUI:

```bash
docker compose exec -T control cicada thread queue A_UUID B_UUID \
  'Thread A says: compare the two hypotheses and reply with your conclusion.'
```

The command calls `codex queue --thread B_UUID --message ...` without a shell.
Thread B receives the message in its own TUI. Reverse the two UUIDs to send a
reply. Every attempt is retained in `thread_deliveries` and can be inspected:

```bash
docker compose exec -T control cicada thread deliveries   # API clients can GET /v1/threads/deliveries
```

The HTTP API equivalents are `POST /v1/threads/sessions` and
`POST /v1/threads/queue`. A global `thread.queue` permission can deny or gate
the operation before any Codex process is started.
