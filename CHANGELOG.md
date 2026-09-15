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
  NVIDIA probing and CPU fallback.
- Bounded personal, project, and execution Memory context in Worker prompts,
  with explicit stale-data and prompt-instruction boundaries.

### Changed

- Parallel workers now publish one aggregate `GoalCompleted` event.
- Peer delivery no longer depends on matching local Contact IDs across two
  Control databases.
- Runtime, image, and test configuration consistently select `gpt-5.5`.

## 0.2.0 — 2026-09-15

- Established the verified Codex supervisor baseline on `release/0.2.0` and
  tag `v0.2.0`.
