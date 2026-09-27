# Cicada implementation language

## Decision

Cicada's MVP uses **Go for the Control and machine-agent core**, with a
TypeScript/React Native client planned for the later personal-client phase.
The official Codex CLI remains the execution engine for Native Codex workers.

The product is a long-running supervisor rather than a model-serving system.
Its critical paths are concurrent machine heartbeats, child-process lifecycle,
workspace and checkpoint operations, event persistence, scheduling, recovery,
and approval boundaries. Go gives these paths cheap goroutines, predictable
memory use, a race detector, a straightforward static Linux binary, and a
portable path to macOS/Windows agents. The LLM request itself remains the
dominant latency, so a Rust rewrite would not improve the user-visible MVP
without first finding a CPU or tail-latency hotspot through profiling.

The Go core exposes a language-neutral HTTP/JSON control API and stores a
durable event log in SQLite. This keeps the future mobile/web Client and a
future Rust data-plane component independent of the implementation language.

## Evidence from Happy

[Happy](https://github.com/slopus/happy) is a TypeScript/Node.js monorepo using
pnpm. Its relevant packages are also TypeScript:

- `happy-cli` contains the Codex app-server client, session lifecycle, daemon,
  persistence, and execution policy;
- `happy-agent` contains machine/session RPC and encryption helpers;
- `happy-server` contains the Fastify/Socket.IO backend and encrypted sync.

The checked-out source is recorded in
[`docs/upstream-happy.md`](upstream-happy.md). Happy remains a reference and a
possible source of narrowly ported protocol ideas; Cicada does not make its
TypeScript runtime a dependency of the Control plane. Its Codex app-server
message shapes and daemon liveness rules can be ported and tested against the
same upstream behavior.

## Alternatives

| Option | Strength | MVP cost | Decision |
| --- | --- | --- | --- |
| Go | Goroutines, static agents, low resident overhead, strong process/network primitives, race detector | Port protocol boundaries from Happy; choose SQLite driver | **Selected for Control/Agent** |
| TypeScript/Node.js | Direct Happy reuse, rich client ecosystem, fast UI iteration | Higher resident overhead and weaker single-binary machine deployment | **Selected for Client** |
| Rust | Strongest memory safety and predictable resource use | Highest rewrite and async integration cost; no direct Happy reuse | Later only after profiling |
| Python | Fastest scripting | Poorer fit for many long-lived agents and portable machine daemons | Removed |

The boundary is intentionally language-neutral: the HTTP/JSON API and SQLite
event schema can be implemented by a future Rust worker or scheduler without
changing Client or Control semantics.
