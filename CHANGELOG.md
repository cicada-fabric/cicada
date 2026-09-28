# Changelog

This file records user-visible changes by release line. `VERSION` and the Go
`buildinfo` package identify the running build; Git tags identify releases.

## 0.1.0-dev — unreleased

Planned public product releases use the `0.1.x` line. Historical `0.2.0`,
`0.3.0-dev`, and `0.4.0-dev` entries and the retired historical `v0.2.0` tag
describe prototype checkpoints. Current development keeps Architecture v2.3
and Client wire v1, while the Hub implementation uses schema v36 and Client
contract `client-hub-v1.4` (36 catalog operations). M1 now includes explicit
Network topology, Owner-approved Network direct key grants, sealed Network
SEND/ASK/REPLY over Hub HTTP/Node delivery, and current-epoch guards on existing
paths. See the [service contract](docs/network-m1-contract.md),
[validation matrix](docs/network-m1-validation.md), and
[code audit](docs/m1-code-audit.md).

The M1 backend acceptance matrix passed on dirty source fingerprint
`479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe`
(`HEAD=733ca8640f86f4944b4f8d8f7c38f6cd929212f2` plus worktree): full Go
(25 packages, 894 top-level tests), vet, focused race (5 packages, 16 tests),
contract/eight Python tests, and separate disposable Client and Network Docker
gates all passed. Earlier fixture failures and an interrupted race run remain
historical, not passes; see the [validation matrix](docs/network-m1-validation.md).
The post-upgrade dependency scan passed on earlier fingerprint `05a486a4`; pins
did not change, and that scan is not attributed to the final source. This is
unreleased development work, not a `0.1.x` release. M2 has not started.
Android v1.4, real native Runtime, physical dual-Node, and public HTTPS are
**NOT_RUN**.

## 0.4.0-dev — historical prototype, unreleased

### Added

- 2026-09-27 final bounded v1.3 Monitor acceptance: clean Hub candidate `25013b5` passed full Go/vet, focused race, contract/export and exact-image TCP gates. One original Monitor Thread performed one read-only preview and one separately reviewed dispatch; both original recipient Threads passed receive/context assertions. Client's final 10 selectors/status, Core scoped ciphertext scan, Intake Hub-state audit, and owned fixture/emulator cleanup passed. See [candidate record](docs/client-hub-v13-25013b5-validation.md), [native runbook](docs/client-monitor-native-fixture.md), [approval review](docs/monitor-broadcast-approval-review.md), and the independent [Client report](../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md). Scope is two logical Nodes in one container; full React Native consent UX, physical Android/dual-Node and public HTTPS remain unrun; unattended cold wake remains unsupported. At this historical checkpoint, Agent Network and Group Journal/Discussion were proposed only.
- Historical 2026-09-27 pre-final snapshot: Hub v34 added consent metadata, live-intake caps of 16 previews per device / 64 per owner, and a persistent cursor limiting notice scans to 16 candidates per Node list call. Earlier frozen-contract and candidate gates passed. The earlier emulator pass involved nine selectors, Group grants and one reviewed Prepare/Confirm plus a separate read-only status selector; it did not claim consumption. At that earlier point, runner `28bd462` failed its post-receive tool-free body-recall assertion after Android reported two `ACCEPTED` children, and fresh runner `d76e630` was blocked after two Codex automatic-review denials before MCP execution (exit `1`, 468s), with no outbox or child chain. Those attempts remain historical and are superseded for the bounded `25013b5` result above. Earlier records: [frozen artifact](docs/client-hub-v13-validation.md), [candidate gates](docs/client-hub-v13-81d8f1f-validation.md), and [joint report](docs/client-monitor-native-81d8f1f-validation.md).
- Added the internal Monitor broadcast authorization and Node path (Hub schema v31–v33): device-bound preview/confirmation, immutable recipient/key scope, signed enrollment evidence, opaque Client-to-Monitor PQ payload verification, durable management notices, and single-operation MCP dispatch. Bounded per-recipient outcomes distinguish Node-reported acceptance from Hub-verified Relay persistence and never regress on retry. At that checkpoint no Client RPC capability was enabled; Android and real native Monitor acceptance remained pending.
- Monitor inboxes are created only when needed; an existing inbox can still open for durable recovery when the notice list is empty. Each Hub list returns at most 16 notices, while broadcasts retain the 32-recipient/8-child batch limit. Added an exact-image disposable idle-Hub measurement script with 128 MiB/0.5 CPU constraints; results must be attributed separately from Node, native models and load tests.
- Fence local and remote broadcast children to their original Endpoint, membership, binding and key snapshots before sealing, so a later authorization lookup cannot silently retarget an approved recipient.
- Retired legacy Monitor Federation body-write operations at MCP, HTTP and Fabric service boundaries. Historical Federation records remain readable; new peer traffic uses explicitly authorized sealed delivery.

- Added offline per-Node `machine backup/verify/restore` for the Node identity, endpoint keys, crypto/replay state, inboxes and local delivery ledgers. A cross-process maintenance lock (`gofrs/flock` 0.13.1) rejects live-Agent backups, each SQLite WAL is checkpointed and verified, and restore publishes only into a new or empty Node subtree with a startup-blocking recovery marker. Hub migration backup now excludes colocated `nodes/` state and refuses older archives containing Node files through the Hub restore path; native Codex and MCP state outside the Node subtree still require a separate device backup and reconciliation.
- Updated the supported build stack to Go 1.27.1, CIRCL 1.6.5, modernc SQLite 1.59.0, and Web Push Go 1.4.0; moved the full Node/Codex image to Ubuntu 26.04 LTS and the lightweight Hub image to Alpine 3.24 stable. Pinned current GitHub Actions releases that run on Node.js 24 LTS. Documented upstream choices, legacy plaintext/PQ-TLS gaps, and the Codex cold-thread queue limitation. CICADA has no Node.js service or Node 22 pin.
- Applied jittered exponential reconnect delay to short-lived Node→Hub Relay event streams while retaining the durable claim path and content-free wake hints.
- Added schema v29 request-scoped Client response sequence reservations and a signed `/v2/client/rpc/recover` route. Exact accepted enrollment retries survive lost HTTP 201 and Hub restart; interrupted RPCs return a durable encrypted uncertainty notice without redispatching the action. Historical requests without a safe reservation fail closed.
- Added manager-only encrypted `goal.result` for owner-attributed Client Intents. It exposes bounded Goal/Worker summaries and opaque Artifact metadata after the Node result is persisted, without Worker prompts or filesystem paths. Android adoption and real Node/Codex acceptance remain separate.

- Standardized Client/Hub development around an embedded, versioned RPC catalog,
  runtime role allowlists and contract drift checks. Added exact catalog identity
  to public and encrypted capabilities without changing wire v1 or device authority.
- Added a Codex-free Hub image with source provenance, a disposable Docker protocol
  gate, deterministic contract bundles, and public synthetic Client-Control wire
  vectors for independent Android verification. Normal pull-request CI now checks
  these alongside Go regression tests; native and Android acceptance remain separate.
- Added Hub schema v28 for immutable, exact-Group broadcast recipient snapshots. A joined Codex Session with both `message.broadcast` and `message.send` can submit a bounded `cicada_broadcast`; its Node sends separately sealed children through the existing local or one-Hub peer route, with durable MCP progress and stable per-recipient IDs for explicit retries. The Hub stores recipient/key evidence and ciphertext envelopes, not the broadcast body. This currently covers same-owner, same-Group Agent broadcast only; user-authorized Monitor broadcast and real native broadcast E2E remain pending.
- Added trusted message kind, request correlation and sender metadata to the sealed Node inbox/read result, preserving old rows and the exact Session/Group cursor boundary.
- Added signed Slack and Discord ingress/reply connector routes alongside the existing social adapters.
- Added a same-Node sealed Group message path: the joined Codex Session uses a trusted local Node socket, Hub Guard resolves current same-owner/same-Group bindings without seeing a peer body, and Node persists ciphertext/request correlation before exact native queue delivery. The Node ledger records terminal revocation and the inbox retains injection uncertainty; sealed-capable sessions fail closed instead of falling back to plaintext for unsupported operations.
- Added additive Hub schema v27 for owner-signed, Group-scoped Endpoint public-key grants, plus Node-only sealed SEND/ASK/REPLY and delivery-claim routes for same-owner Endpoints on different Nodes. The Hub checks current Group, Membership, Node owner binding, SessionBinding, key candidate, grant, Hub identity, and expiry; it stores and forwards ciphertext without entering Control business logic. The Node independently verifies owner signatures before encryption/decryption and native delivery. Store and Hub HTTP tests pass; two physical Nodes remain unverified; two logical Nodes with real Codex Threads passed sealed ASK/REPLY after this change. The Node currently requires an operator-pinned `CICADA_HUB_ID` before this route can run.
- Added sealed-session `cicada_receive` from the Node's durable inboxes. Its opaque cursor is scoped to the current Endpoint, native Session, binding epoch, and Group; it exposes only runtime-injected messages and opens inbox databases read-only. The result includes `message_id`, plaintext `body`, `kind`, `request_id`, `reply_to`, `sender_endpoint_id`, `state`, `sequence`, `created_at`, and `next_cursor` when trusted delivery metadata is available; legacy unmapped metadata is not guessed. The legacy Hub receive path remains available only when the current Session has no sealed-delivery capability; sealed sessions never downgrade to it.
- Removed the MCP Join management-bearer fallback and redundant sealed local-reply probe. Batched historical Relay inbox body reads and consolidated the Node inbox receipt API without changing retained migration data.
- Added owner-scoped encrypted Client sessions for separately trusted outside users. They can read their own attributed status/deltas and manage their own Client/Node bindings, Group/Endpoint topology and Link consent; resident Control Goals, Intents and Approvals remain isolated.
- Added one-use, bounded external Thread invitations over the encrypted Client RPC. A second owner can preview and accept an invitation into a durable `PROPOSED` Link; invitation acceptance does not activate peer routing or bypass Endpoint key grants.
- Added an owner-scoped, paged encrypted `link.list` so both Client owners can recover accepted proposal IDs and terms without exposing foreign topology.
- Added a Node-credential-authenticated guest Join service boundary and fenced guest Fabric session tokens when that Node's owner binding is revoked. The Node Agent now provides an owner-only local Unix-socket Join bridge that checks the Codex session record and workspace; real guest native-session continuity remains unverified.
- Connected explicit cross-owner Link SEND/ASK/REPLY from a joined Codex MCP session through a trusted local Node bridge, durable post-quantum Endpoint outbox, Hub-blind sealed Relay, both Node crypto inboxes, and exact native queue. Hub rechecks bilateral grants, scope, and bindings at enqueue, claim, and pre-injection; Node independently verifies trusted Owner keys and signatures. Two logical Node/fake Codex full-chain and failure tests pass. Real native cross-user validation, cross-owner broadcast, and complete device-level recovery remain pending.
- Hardened same-Group peer writes against MCP capability-cache downgrade at MCP, Fabric, and Store boundaries; the Node plaintext inbox now requires private storage, and exact Guard revalidation no longer scans the whole Group.
- Added owner-granted sealed REQUEST persistence: Node crypto validates the `ask` action and exact request correlation; the Hub Store atomically commits ciphertext, request lifecycle, quota and Relay delivery. The target Node decrypts and queues it to its bound native session with crash recovery and layered receipts. Bound Nodes can read opaque request status; the original sender can request cancellation via the trusted local bridge.
- Added correlated sealed REPLY persistence and Node-only Ask/Reply/status/cancel HTTP. The original responder signs a reply over the reverse route of the approved Link; wrong correlation, stale grants and forged Node identity are rejected. Late encrypted results remain durable evidence without automatically waking the requester. The MCP bridge derives the reply route from the original request, and two logical Node/fake Codex Ask/Reply passes; real cross-owner native Codex validation remains pending.
- Added the Android Client developer handoff and implementation prompt for the fixed Hub contract, including capability gates and the one-command isolated Docker Hub bootstrap.
- Added an encrypted Client Goal lifecycle operation for versioned pause/resume of unclaimed remote Node work. Node job listing and claims reject paused Goals, and running Workers are never reported as stopped by this operation.
- Extended the owner-bound Client status cursor with bounded Approval and Intent lifecycle metadata. Migration v25 preserves existing status rows and cursors while expanding entity types; request bodies and result text stay out of the feed.
- Added an encrypted Client↔Hub key-consent RPC for proposed CommunicationLinks. Both owner signatures bind the current Link contract, native SessionBindings, and Endpoint public-key candidates; old unbound grants remain historical and do not authorize routing.
- Moved the embedded panel's Endpoint read projection to `/v2/management/endpoints` and removed all `/v1/endpoints` HTTP routes.
- Added a versioned, owner-authorized Client↔Hub PQ RPC for Android integration: encrypted status and topology reads/writes, durable asynchronous Intent acceptance/progress, Approval and Client-device management, and a partial owner-bound status change cursor.
- Added Node-local bearer generation with short-lived device-code confirmation through an enrolled Client, owner/Hub-bound Relay authorization, and authenticated Node liveness updates. The separate Android app supplies the verification UI.
- Retired the public v1 Fabric peer, Endpoint write, manual Thread queue, Contact peer ingress/session management, SSH machine-pair, and server-issued plaintext Node credential routes; also removed the obsolete `cicada endpoint` CLI. The Endpoint read-only panel projection and historical data remain for migration and audit.
- Removed the unused Control→Contact relay sender and its old relay URL/token configuration; preserved historical Contact keys and ratchet records for migration.
- Added offline user-held post-quantum owner key generation and local Hub public-key registration, plus durable, separately signed SOURCE/TARGET CommunicationLink grants. These records do not activate a cross-Group route or change the existing plaintext Fabric transport.
- Session-first Endpoint membership for existing Codex threads, including
  automatic native session discovery, stable IDs, human-readable addresses,
  Network Cards, liveness, and explicit resolver ambiguity errors.
- Durable Fabric `send` and correlated `ask/reply` messaging with exact local
  and remote Codex session wake through machine agents.
- A bundled stdio MCP server and Codex plugin tools for joining, listing,
  resolving, inspecting, sending, asking, replying, and receiving without
  shell command construction.
- Additive Architecture v2 Fabric foundations: Principal/Group/Membership/
  SessionBinding records, explicit MCP `cicada_join`, Group-scoped actor
  authorization, durable Relay/Node receipts, and bounded representative
  federation state. The v2 path is still partial; Shared Task/Lease and
  product/interop phases remain unfinished.
- Node Relay calls use locally held, owner-confirmed credentials, validate
  active binding leases and monotonic receipts, and remove Control/Node
  credentials from native Codex child environments.
- Versioned additive v2 migrations now serialize concurrent upgrades, verify
  legacy state preservation, and roll back/retry an interrupted version.
- Added `serve --fabric-only`, `machine agent --relay-only`, and authenticated
  `fabric v2` CLI commands. MCP credentials remain outside model-visible join
  results and can recover an explicitly joined binding after process restart.
- Native peer injections retain request/source metadata as external content;
  an abnormal queue-process exit after launch is recorded as injection
  uncertainty instead of being blindly retried.
- Fabric Directory APIs, operator CLI commands, and a live Endpoint Network
  panel in the embedded desktop/mobile PWA.

## 0.3.0-dev

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
- Approval-backed connector reply actions with bounded HMAC-signed callback
  delivery and provider credentials kept in the operator connector process.
- Conservative snapshot garbage collection and an authenticated
  `cicada snapshot replicate` path for copying verified archives between
  independent Controls.
- Bounded Claude Code, OpenCode, and Happy Agent adapters with direct
  stdin/stdout execution, capability discovery, JSON-lines session extraction,
  and secret-filtered remote machine support.
- Signed Contact directory/rendezvous records with bounded HTTPS endpoints,
  expiry reaping, and no implicit Contact trust.
- VAPID-backed encrypted browser Push delivery for prioritized notifications,
  durable subscription registration, stale endpoint cleanup, and Personal
  Client opt-in controls.
- Scheduled parked-Idea revisits using explicit UTC timestamps or dates, with
  an idempotent assessed transition, rationale audit marker, and P2 notice.
- Authenticated Goal detail access to bounded raw Worker output with workspace
  and state-root containment checks.
- SSH Machine pairing through a fixed remote `machine discover` command, with
  bounded JSON output, BatchMode/timeout enforcement, and authenticated profile
  registration.
- Signed Documents ingress with bounded metadata normalization and explicit
  document lifecycle triage.
- Local capability discovery now recognizes ROCm and Ascend/CANN accelerators
  in addition to NVIDIA CUDA and CPU fallback.
- Opt-in UDP LAN capability discovery for Machine agents, with no automatic
  registration or trust from unauthenticated responses.

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
