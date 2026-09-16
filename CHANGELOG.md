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
- Signed PQ session offers with directional ratchet chain keys, durable replay
  counters, authenticated rotation, and a secret-free Contact session API.
- Ordered multi-relay peer delivery with opaque idempotent fallback retries.
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
- Atomic remote Worker dispatch through the machine agent, including queued job
  polling, Codex/Shell execution, bounded result delivery, busy heartbeats,
  retry-safe completion, and stale-machine requeue.
- Bounded Shell workers with direct argv execution, capped output evidence, and
  secret-free child environments.
- Registered manual Codex TUI sessions with audited, permission-gated message
  delivery through the official `codex queue` command.
- Isolated browser action agent with a bounded stdin/stdout runner protocol,
  approval-gated claims, credential-free payloads, process-group timeouts, and
  profile/HOME isolation for operator-supplied browser runtimes.
- Restart-safe inbound Telegram connector with a minimized normalized payload,
  connector-specific HMAC authentication, durable offsets, idempotent retries,
  and explicit event triage states.
- Provider-neutral Email and Calendar webhook adapters with HMAC verification,
  bounded JSON/iCalendar normalization, credential stripping, and idempotent
  durable events.
- Provider-neutral X, WeChat, and QQ webhook adapters with HMAC verification,
  bounded envelope stripping, idempotent normalized events, and deterministic
  first-pass classification.
- Conservative snapshot garbage collection and an authenticated
  `cicada snapshot replicate` path for copying verified archives between
  independent Controls.
- Bounded Claude Code, OpenCode, and Happy Agent adapters with direct
  stdin/stdout execution, capability discovery, JSON-lines session extraction,
  and secret-filtered remote machine support.
- Signed Contact directory/rendezvous records with bounded HTTPS endpoints,
  expiry reaping, and no implicit Contact trust.

### Changed

- Parallel workers now publish one aggregate `GoalCompleted` event.
- Peer delivery no longer depends on matching local Contact IDs across two
  Control databases.
- Runtime, image, and test configuration consistently select `gpt-5.5`.
- Monitor and peer correction commands are consumed per Worker, preventing one
  parallel branch from consuming a sibling's command.
- Worker completion claims now pass a bounded evidence verifier before artifact
  and Goal completion. High-confidence `gpt-5.5` rejections resume the Worker
  with a correction; verifier outages remain visible without blocking work.
- Compose service environments now inherit the complete shared Control
  configuration, so intent planning, completion verification, federation, and
  connector settings survive service-specific role overrides.
- Compose no longer replaces runtime-file webhook and peer relay secrets with
  empty interpolation defaults.
- Goals can provision a pinned public HTTPS Git workspace on local or remote
  executors. The adapter isolates credentials/config, rejects private network
  targets and symlink escapes, resumes marked workspaces, and records the
  resolved commit as evidence.
- Remote execution now uploads deterministic, bounded workspace snapshots to a
  SHA-256 content-addressed store. Requeued Workers carry the digest to a new
  Machine, which verifies and atomically restores modified files.

## 0.2.0 — 2026-09-15

- Established the verified Codex supervisor baseline on `release/0.2.0` and
  tag `v0.2.0`.
