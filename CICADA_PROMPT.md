# CICADA development task guidance

Read [AGENTS.md](AGENTS.md) and the adopted [CICADA.md](CICADA.md) before an
architecture change. The user's current instruction determines task scope and
authorization; this file is engineering guidance, not an instruction to restart
a completed historical M1–M5 task or run paid models.

## Current baseline and sources

Development is on `dev`. Check its actual HEAD, dirty state and existing work
before editing. The account implementation and gate evidence below were
captured from dirty `dev` before the local checkpoint commit. At capture, the
unreleased development source was software `0.0.5`, Architecture v2.3, and
contained additive schema 61 plus Hub Owner account claim/login source against
the earlier schema-60 bootstrap. The account backend, six encrypted operations,
local claim issuer, and two-page browser/WASM flow were implemented in the
captured source. That browser/WASM UI is retained as a bounded 0.0.5
implementation and validation history, not the current product entry. The
current target is a standalone Windows-first native Cicada App with no browser
or WebView dependency. Focused deterministic tests,
selected race checks and targeted vet pass. Root's final PQ-enabled disposable
Chromium account gate passed all 18 steps with fixture cleanup, and the official
standard Client Docker interop passed with exit 0 and confirmed cleanup. The
post-review UI retry guard now serializes same-origin actions with Web Locks/
singleflight and exact IndexedDB compare-and-swap; the post-CAS WASM/UI gate
passed. No Core or wire behavior changed. The latest sequenced Windows
cross-build passed; native Windows/ACL acceptance remains NOT_RUN. The native
App foundation is N1 PARTIAL: account claim/login and vault-backed identities
exist in source, but the one-code Root activation, encrypted PKCS#8 input,
automatic trusted-profile restart/reconciliation, and native App integration
for the authorized live canvas and Node actions are incomplete. Supported
unencrypted existing Owner identities can be imported into the encrypted
vault; using one to prove Root remains incomplete. The Hub/Node APIs and Guard
already exist for App integration. The App is not a released installer; N2 and
N3 are not complete. The target is for the Hub public root `/` to return 404;
this has not been validated. See
[`docs/native-app-architecture.md`](docs/native-app-architecture.md). These are
bounded local gates, not full-product or release acceptance. Attribute the
current browser image to dirty revision `d758086` and build-input fingerprint
`c4b52e67ed82f75fd2ef27f198d6e34591323de6f3dfa2f94f03adce7bc335a3`; its image
digest is `sha256:dc98a89e748959c357723610660145efe23b5e26014776d55d69edcf6b042d76`.
Its result is
[`result.json`](.cicada-data/hub-owner-account-browser/20261014t102757z-2975661-c0e87018/result.json),
SHA-256 `aa2e023eaafee20bf654a838657efa0eaf0edaab82d2a631d8cbcb112675d01b`;
build metadata is `.cicada-data/hub-owner-account-20261014/root-gate/build-pq-cas.json`.
The latest standard Client interop used image
`sha256:c9f94827e7cf96b6047b0e41cbc687931c7d36e6d8ae520ab6d7f7ecfe88431b`
with input fingerprint
`498b1299dba7a0ae8327ed6087dee0bb79102ca43d11f9247418e5ab24887540` and confirmed
cleanup; its result is `.cicada-data/hub-owner-account-20261014/root-gate/client-interop-cas/result.json`.
The prior 17-step browser pass remains a pre-CAS historical result. Do not
attribute this evidence to HEAD alone.
The intermediate build-provenance guard abort and two earlier browser-driver
failures remain recorded in the [account validation report](docs/hub-owner-account-validation.md);
the guard failure was not a product-test failure, and later passes do not
rewrite those attempts.

The original schema-60 checkpoint's scoped Docker A2 and segmented test
acceptance remain in its original record, including its A7/R3 aggregate
failures/timeouts. The source also retains the encrypted OpenSSL-key helper,
Hub identity/bootstrap separation, EN/zh-CN and an explicit advanced old-form
entry. Stage 1 Hub-only composition has its own segmented normal/race, vet and
contract evidence, with its earlier assertion failure and aggregate timeout
retained. The Linux synthetic OpenSSL PTY ceremony, pre-extraction Windows
cross-build, and older offline Go WASM/UI-model gate retain separate source
attribution in [the audit](docs/architecture-v2-audit.md) and
[validation record](docs/windows-owner-openssl-validation.md). A Windows
cross-build passed for the captured source, but native Windows/ACL execution of
the new account flow, Android, physical devices, native Codex end-to-end, and public HTTPS
remain NOT_RUN. Root-loss recovery,
password recovery, and account-device add/revoke remain unimplemented. Software
stays 0.0.5; no version bump, release or resident deployment replacement is
implied.
Current account replay handling permits a greater-than-60-second login-complete
or logout retry only when the exact packet digest matches a durable accepted
receipt and account/device/credential epochs remain current; the original device
envelope is still verified. New and altered packets keep the normal freshness
check. Schema 61 includes targeted indexes for token digests, session revocation
and exact receipt lookup, with their storage/write cost recorded in the
[migration note](docs/architecture-v2-migration.md).
Client contract `client-hub-v1.6.5`, encrypted wire 1 and
catalog 55 remain unchanged. Confirm those
identities in [VERSION](VERSION), the
[catalog](cicada-go/internal/clientcontract/catalog.json) and
[migrations](cicada-go/internal/store/migrations_v2.go); they are independent of
Git revision, build-input fingerprint, image digest and native Runtime version.
The candidate is unreleased and overall product acceptance remains partial.
Continue 0.0.x development on `dev`; a main merge or 0.1.0 release requires the
user's actual acceptance and separate authorization.

Use [implementation status](docs/architecture-v2-status.md),
[plan](docs/architecture-v2-plan.md), [audit](docs/architecture-v2-audit.md),
[migration](docs/architecture-v2-migration.md) and
[completion ledger](docs/completion-ledger.md) to identify actual remaining work.
Read relevant code and contracts rather than inferring implementation from the
specification or an old README. Current operations and limits are summarized in
[the technical guide](docs/v01-technical-guide.md); future product designs are
indexed in [the documentation index](docs/README.md).

## Architecture boundaries

- Physical responsibilities are Node, Hub and App. A human Owner is the
  authority; Manager coordinates goals/approvals, Advisor gives bounded
  recommendations, and Worker executes authorized work. Control is a Hub
  service. Network is a private tenant and authorization scope, not another
  deployment component or participant. Existing Client/Monitor identifiers
  and `client-hub-*` contracts are compatibility names, not product terminology.
- Owner account authentication belongs to Hub Identity/Authorization and must
  work without Control, Workspace or a model. The accepted product target is a
  standalone App flow with one encoded/scannable, secret-bearing, single-use
  activation code from a controlled operator channel. Its text representation
  may be long; users scan or import it rather than type a short code or copy
  JSON/IDs. This is not a browser wizard. The App fetches the Hub's full
  identity and independently verifies the full SHA-256 pin before sending the
  code or password. Account
  credentials, an ACCOUNT_LOGIN device and a pending Owner-public association
  remain distinct from active Root. The code and public association alone do
  not activate Root or Manager; final activation requires proof from the exact
  Owner private key and a finite device grant. Existing identity and key IDs
  must be preserved. Ten-plus-character passwords require registered-device
  PQC on every login; initial code is not ongoing MFA and an unknown device
  cannot enroll by password alone. Controlled continuation of an existing
  account must not reclaim/reset its Root. Setup secrets/password/proofs/results
  and account requests preserve NIST application envelopes; HTTPS is transport.
  A cookie/session hint alone is never an actor: authenticated device envelope,
  current epochs and nonce/sequence checks remain required. The implemented
  verifier is PBKDF2-SHA256-600000-v1 with a 32-byte salt, at least 10 Unicode
  code points, and a 1,024-byte maximum; two workers and four queued requests
  bound KDF work, which runs outside the Store transaction. Current restore
  fences advance the account epoch and invalidate pending claims, attempts and
  sessions while retaining credentials, active login devices and pending public
  association. The current source supports initial pre-Root account claim; the
  native App activation flow, existing-Root credential attachment, password
  recovery and device add/revoke are not implemented. The 0600 local claim card
  contains one-use setup authority and is suppressed from default CLI output.
  These implementation details do not imply full-product acceptance; the
  bounded legacy browser-compatibility and interop gates passed for the captured
  source.
- Control manages user intents, goals, budgets and approvals. Ordinary peer
  collaboration must not invoke its interpretation, planning or summarization.
  A Monitor can observe, review or represent within grants; it is not a mandatory
  message relay or a substitute for user approval. The old MA→MB→B1 compulsory
  representative path is retired as a development requirement.
- One Network has one authoritative Hub; a Group belongs to one Network. A real
  Thread/Endpoint can participate in multiple Networks/Groups. Membership,
  Endpoint Join, role grants, SessionBinding and key consent are separate.
  Nested Groups and communication links do not transitively grant permissions.
- Preserve explicit, idempotent Join and the original native Session identity.
  Installing integration never exposes every session or grants a role. Derive
  caller identity from trusted connections and current binding; reject model
  claims about sender, scope, role or “user approved.” MCP, HTTP, CLI and retries
  share core Guard and state-machine boundaries.
- Default peer delivery is ciphertext through one common HubRelay. Optional
  local direct requires the same physical host, the same Codex account and a
  Node-callable exact-target native API, plus current authorization. A Node label
  is insufficient. Nodes initiate outbound HTTPS/SSE; do not introduce inbound
  Node access or implicit Hub-to-Hub forwarding.
- Peer plaintext belongs at authorized Endpoints. App account operations are
  addressed to Hub Identity/Authorization; Manager instructions are decrypted
  by Control because Control interprets them. Hub Relay does not get peer
  plaintext. Preserve NIST application E2EE, keys, replay state and explicit
  Owner trust; HTTPS and future Windows PQTLS are separate transport layers.
  Native Windows PQTLS is NOT_IMPLEMENTED. Never silently downgrade to legacy
  plaintext.
- Shared native Threads share model memory. Changing Group scope cannot erase
  already consumed content. Journal, Discussion, messages, Tasks, Evidence and
  Approval have separate history, authorization and acceptance semantics.
  Cross-owner history/key access requires exact bilateral proofs and current
  Guard; unresolved paths remain fail closed.

## Implementation and acceptance

Preserve Go core and effective product capabilities, including Idea/Goal,
Workspace, scheduling, approvals, contacts, memory, notifications and connectors.
Reuse current MCP/service paths; do not create parallel infrastructure merely to
coordinate components. Android is a planned App distribution maintained under
`apps/android`, with its original history retained by the authorized monorepo
import. Follow its nested `AGENTS.md`; leave the old migration source untouched.
Use the canonical `~/Cicada/cicada` checkout on `dev` and task worktrees under
`~/Cicada/.worktrees/cicada/<task>` for concurrent writers. See
[`docs/repository-migration.md`](docs/repository-migration.md). New native App work follows
[`docs/native-app-architecture.md`](docs/native-app-architecture.md). Existing
Client-facing work continues to respect the frozen
[Hub contract boundary](docs/client-hub-development.md) until a versioned App
contract replaces it; do not rename wire identifiers in place.

Distinguish Relay persistence, Node persistence, Runtime injection, confirmed
model consumption and accepted business results. At-least-once transport does
not make arbitrary actions exactly-once. Injection crashes require native
idempotency reconciliation or INJECTION_UNCERTAIN, never blind replay. Old
session/task epochs cannot update a new owner. Lease expiry does not prove a
process stopped; enforce fencing at actual resources. Preserve foreground input
and exact original-session recovery; do not substitute terminal keystrokes or a
new same-name session for native integration.

Run relevant deterministic tests and isolated disposable Docker interop when
implementation changes require them. Never use a resident/shared Hub as the
fixture. Keep Android, actual native Runtime, physical-device and public HTTPS
results separate, with exact source/artifact identity. Synthetic/fake harness
checks cannot prove native wake. FAIL, UNKNOWN, BLOCKED, NOT_RUN and SKIP remain
visible and are not PASS. See [test automation](docs/test-automation.md) and
[current closeout](docs/v01-current-closeout-20261009-validation.md).

Keep meaningful code, tests, contract, documentation and validation together.
Respect the Git identity and commit requirements in AGENTS.md. Preserve dirty
work, deployments and real keys. Ordinary development does not authorize push,
release, merge to main, production migration or global Runtime changes; follow
explicit current user authorization for repository maintenance. Do not expose
private paths, credentials, full grants or sensitive payloads in public evidence.
Report changes, checks, remaining limits and the next actionable boundary.

## Superseded task instructions

The former 2026-09-28 M1-only and 2026-09-30 M2/M3–M5 task scopes were historical
implementation instructions. They no longer define the current task, do not
restart those stages and do not impose old provider/Runtime pins. Their actual
validation reports remain intact under docs with their original sources,
failures and environment limits. Repository history retains the prior task text.
