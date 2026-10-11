# CICADA development task guidance

Read [AGENTS.md](AGENTS.md) and the adopted [CICADA.md](CICADA.md) before an
architecture change. The user's current instruction determines task scope and
authorization; this file is engineering guidance, not an instruction to restart
a completed historical M1–M5 task or run paid models.

## Current baseline and sources

Development is on `dev`. Check its actual HEAD, dirty state and existing work
before editing. The development source line is `0.0.2`, Architecture v2.3, Hub schema 59,
Client contract `client-hub-v1.6.5`, encrypted wire 1 and catalog 55. Confirm those
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

- Physical responsibilities are Node, Hub and Client; logical participants are
  User, Control, Worker and optional Monitor. Network is a private tenant and
  authorization scope, not another deployment component or participant.
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
- Peer plaintext belongs at authorized Endpoints. Client management plaintext
  belongs at Client and Control: Control decrypts management commands. Preserve
  NIST application E2EE, keys, replay state and explicit Owner trust; transport
  TLS/PQTLS is a separate boundary. Never silently downgrade to legacy plaintext.
- Shared native Threads share model memory. Changing Group scope cannot erase
  already consumed content. Journal, Discussion, messages, Tasks, Evidence and
  Approval have separate history, authorization and acceptance semantics.
  Cross-owner history/key access requires exact bilateral proofs and current
  Guard; unresolved paths remain fail closed.

## Implementation and acceptance

Preserve Go core and effective product capabilities, including Idea/Goal,
Workspace, scheduling, approvals, contacts, memory, notifications and connectors.
Reuse current MCP/service paths; do not create parallel infrastructure merely to
coordinate repositories. Android belongs to the independent Client repository;
read it for interoperability but modify it only with explicit user authorization.
Client-facing work follows [the authoritative development boundary](docs/client-hub-development.md)
and updates implementation, contract and checks in one checkpoint.

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
