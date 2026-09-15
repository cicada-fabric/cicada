# Release status

The current line is **Cicada 0.2.0**, a Codex-first autonomous supervisor
baseline. It is beyond the original proof-of-concept MVP and is maintained as
a versioned feature branch rather than being developed directly on `main`.

Implemented in this line:

- Go Control plane with durable SQLite Goals, Ideas, Workspaces, Memories,
  Artifacts, Events, Notifications, Approvals, Machines, Monitors, and Workers;
- Native Codex app-server workers using the official CLI and `gpt-5.5` through
  the configured relay;
- machine capability scheduling, heartbeats, stale-machine handling, worker
  recovery, deadlines, runtime/worker budgets, and conservative monitor
  correction;
- multiple isolated Workers per Goal and durable thread-to-thread messaging;
- ML-KEM-768 + ML-DSA-65 authenticated peer envelopes with persistent replay
  protection;
- Contact trust lifecycle and durable Contact/Goal/Workspace permission rules;
- embedded status Client, HTTP/JSON API, Docker image export, and a reproducible
  smoke test.

The release deliberately keeps its boundaries explicit. Automatic federation
and relay delivery, session ratcheting, authenticated browser actions, external
message/calendar connectors, additional harness adapters, and the mobile/voice
Client remain the next feature lines. They are tracked as product work rather
than hidden behind claims that the current Codex adapter supports them.

Version and branch workflow:

1. `develop` is the integration starting point.
2. `feat/*` branches contain one coherent feature and are pushed to
   `origin` (`git@github.com:cicada-fabric/cicada.git`) as work progresses.
3. `release/0.2.0` and tag `v0.2.0` identify this verified baseline.
4. `main` is reserved for reviewed release merges.

The version is declared in [`VERSION`](../VERSION) and shared by the CLI,
health endpoint, and Codex app-server metadata through the Go `buildinfo`
package. Docker artifacts are exported under
`/gpu1-share/data/cicada/images/` with a SHA-256 sidecar.
