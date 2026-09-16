# Remote worker execution

The machine agent is the execution boundary for Workers assigned to a remote
Machine. Control keeps the durable state machine and the agent performs this
loop:

1. register a bounded, non-secret capability profile;
2. heartbeat its availability;
3. poll `GET /v1/machines/MACHINE_ID/jobs`;
4. atomically claim a queued Worker through
   `POST /v1/workers/WORKER_ID/claim`;
5. execute the Codex or Shell harness in the assigned workspace;
6. return the bounded summary and Codex thread ID through
   `POST /v1/workers/WORKER_ID/result`.

The claim is a conditional SQLite transition from `queued` to `running`.
Competing agents using the same Machine ID therefore cannot both own the same
attempt. Result delivery retries through transient API and network failures. A
lost response is safe: a repeated result receives `409 Conflict` after Control
has already committed the first one.

Run an agent on the execution host:

```bash
export CICADA_MACHINE_ID=gpu2
export CICADA_MACHINE_NAME='GPU server 2'
export CICADA_CONTROL_URL=https://control.example
export CICADA_API_TOKEN='runtime Control token'
export CICADA_WORKSPACE_ROOT=/workspace
cicada machine agent --interval 30s
```

The remote host must have the official Codex CLI and its own relay credential
when it advertises the Codex harness. Remote Codex execution always passes
`--model gpt-5.5`; its `API_KEY` or `OPENAI_API_KEY` remains available to the
Codex subprocess. Control bearer tokens, peer relay tokens, and connector
secrets are removed from every child process. Shell Workers also lose model
credentials and execute the explicit `resources.argv` array without a shell.

`--once` registers, heartbeats, and drains the currently visible job list once.
It is useful for provisioning checks and deterministic tests. Production
agents should remain running under a process supervisor.

## Workspace contract

Control sends an absolute workspace path and the agent accepts it only when it
is contained by `CICADA_WORKSPACE_ROOT`. A Goal can declare a public HTTPS
[`Git workspace source`](workspace-provisioning.md), allowing machines with
independent disks to materialize the same pinned starting revision. Goals
without a source still require the same mounted storage or operator-provisioned
contents. Content-addressed transfer of modified workspaces and automatic
cross-machine migration remain separate product work.

The agent resolves symlinks before entering the workspace and rejects a path
that resolves outside the configured root. It always recreates the response
file as `.cicada-last-message` inside the resolved Worker directory.
The resolved Git revision is returned to Control as Workspace evidence.
Combined subprocess output is capped at 512 KiB, returned summaries are capped
at 16 KiB, and execution uses `CICADA_WORKER_TIMEOUT_SECONDS` (30 minutes by
default).

## Recovery semantics

While a job runs, the agent heartbeats with `busy`. If those heartbeats expire,
Control marks the remote Machine offline and requeues its running Workers. A
later claim increments the attempt counter. This provides at-least-once
execution after a network partition; workloads that mutate external systems
must therefore use idempotency keys or the approval-gated external action
boundary.

Control restart follows the same ownership rule: local Workers enter the local
recovery loop, while remote Workers return to `queued` and wait for their
assigned agent. Monitor and peer commands are consumed per Worker when that
Worker is claimed, so one branch cannot steal another branch's correction.
