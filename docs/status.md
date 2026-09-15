# Release status

The current line is **Cicada 0.3.0-dev**, an unreleased Codex-first autonomous
supervisor with secure collaboration boundaries. It is beyond the original
proof-of-concept MVP and is maintained on versioned feature branches rather
than being developed directly on `main`.

Implemented in this line:

- Go Control plane with durable SQLite Goals, Ideas, Workspaces, Memories,
  Artifacts, Events, Notifications, Approvals, Machines, Monitors, and Workers;
- Native Codex app-server workers using the official CLI and `gpt-5.5` through
  the configured relay;
- machine capability scheduling, heartbeats, stale-machine handling, worker
  recovery, deadlines, runtime/worker budgets, and conservative monitor
  correction;
- multiple isolated Workers per Goal and durable thread-to-thread messaging;
- durable parent/child execution graphs, monitor-only coordinator Goals,
  child-count budgets, and aggregated child evidence;
- ML-KEM-768 + ML-DSA-65 authenticated peer envelopes with persistent replay
  protection;
- signed ML-DSA contact announcements with durable discovery requests,
  idempotent ingress, and an explicit accept/reject then trust lifecycle;
- identity-routed federation ingress and optional opaque HTTP delivery with
  atomic replay persistence, retry idempotency, and plaintext-free receipts;
- Contact trust lifecycle and durable Contact/Goal/Workspace permission rules;
- optional bearer authentication for the HTTP/JSON Control boundary, with
  constant-time token comparison and runtime-only secret injection;
- signed external connector ingress with HMAC-SHA256 verification, idempotent
  event keys, durable payloads, Goal audit events, and P1 notifications;
- policy-gated external action requests with domain and SSRF checks, credential
  field rejection, durable approval transitions, executor claim/complete state,
  and append-only action audit events;
- responsive embedded Personal Client with a Today Goal overview, pending
  Approval decisions, prioritized notifications, per-tab remote bearer token,
  HTTP/JSON API, Docker image export, and a reproducible smoke test.
- durable natural-input Intent routing for Goal, Idea, Research, Question,
  Command, and explicitly requested Approval actions, with clarification states
  for missing targets or decisions.
- on-demand Goal detail view for conclusions, events, Workers, Artifacts,
  Workspaces, and external actions.
- local Machine capability discovery for OS, architecture, CPU, memory,
  toolchains, and NVIDIA/CPU accelerator matching.
- bounded personal, project, and execution Memory context in Worker prompts,
  labeled as reference data and persisted through the existing Memory API.

The release deliberately keeps its boundaries explicit. Contact directory and
rendezvous services, multi-peer relay routing, session ratcheting, a production
browser executor, external message/calendar connectors, additional harness
adapters, push, native mobile, voice, and a model-backed planner remain the
next feature lines. The
external action queue is a safe Control boundary; it does not pretend to be a
browser or grant an executor access to credentials. These are tracked as
product work rather than hidden behind claims that the current Codex adapter
supports them.

Version and branch workflow:

1. `develop` is the integration starting point.
2. `feat/*` branches contain one coherent feature and are pushed to
   `origin` (`git@github.com:cicada-fabric/cicada.git`) as work progresses.
3. `release/0.2.0` and tag `v0.2.0` identify this verified baseline.
4. `0.3.0-dev` identifies current unreleased work; it receives a release
   branch and tag only after its release checks pass.
5. `main` is reserved for reviewed release merges.

The version is declared in [`VERSION`](../VERSION) and shared by the CLI,
health endpoint, and Codex app-server metadata through the Go `buildinfo`
package. Docker artifacts are exported under
`/gpu1-share/data/cicada/images/` with a SHA-256 sidecar.
