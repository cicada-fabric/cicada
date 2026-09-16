# Changelog

This file records user-visible changes by release line. `VERSION` and the Go
`buildinfo` package identify the running build; Git tags identify releases.

## 0.3.0-dev — unreleased

### Added

- Durable parent/child Goal supervision and multi-worker evidence aggregation.
- Signed external connector ingress and policy-gated external action requests.
- ML-DSA signed Contact discovery with an explicit pending trust lifecycle.
- Identity-routed federation ingress with atomic replay state, idempotent
  transport retries, and plaintext-free receipts.
- Optional bearer authentication for remotely exposed Control APIs.
- Responsive embedded Personal Client with Today counters, Goal and worker
  summaries, pending Approval decisions, prioritized notifications, and a
  per-tab remote bearer token.
- Durable `/v1/intents` routing for natural input into Goals, Ideas, research,
  questions, commands, and explicit Approval decisions, including persisted
  clarification states.
- On-demand Goal detail view for conclusions, events, workers, artifacts,
  workspaces, and external actions.
- Local machine capability discovery for scheduler matching, with bounded
  NVIDIA probing, CPU fallback, disk/network/toolchain/container discovery,
  and `max_load_1m`/disk/toolchain/container/network resource constraints.
- Bounded personal, project, and execution Memory context in Worker prompts,
  with explicit stale-data and prompt-instruction boundaries.
- Optional gpt-5.5 natural-input planning through an ephemeral read-only Codex
  invocation, with deterministic fallback and no model-driven Approval.
- Personal Client file/image/link attachments with 8 MiB per-file and five-item
  Intent limits, private generated paths, and non-fetching link references.
- Installable Personal Client PWA shell with static-only caching and no API or
  bearer-token cache.
- Bounded credential-free read-only HTTP execution for approved `fetch`,
  `search`, and `download` actions, with DNS-aware SSRF protection and capped
  response capture.
- Progressive browser speech input for the Personal Client, with no audio
  upload to the Control API.
- Authenticated Server-Sent Events for replaying and following a Goal's
  durable event history with reconnect offsets.
- A `cicada machine agent` heartbeat process for registering remote execution
  hosts with non-secret capability profiles.
- Bounded Shell workers with direct argv execution, capped output evidence, and
  secret-free child environments.
- Registered manual Codex TUI sessions with audited, permission-gated message
  delivery through the official `codex queue` command.

### Changed

- Parallel workers now publish one aggregate `GoalCompleted` event.
- Peer delivery no longer depends on matching local Contact IDs across two
  Control databases.
- Runtime, image, and test configuration consistently select `gpt-5.5`.

## 0.2.0 — 2026-09-15

- Established the verified Codex supervisor baseline on `release/0.2.0` and
  tag `v0.2.0`.
