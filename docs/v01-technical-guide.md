# CICADA v0.1.x technical guide

This guide covers the current **0.0.1-dev** development source line. It is public technical
documentation for an unreleased candidate, not a release announcement or proof
of complete product acceptance. Read the [current closeout](v01-current-closeout-20261009-validation.md)
for retained failures and the [implementation ledger](completion-ledger.md) for
individual boundaries. The adopted [Architecture v2.3](../CICADA.md) is a product
specification; its architecture number is independent of software versions.
Development stays in 0.0.x on `dev` until the user's actual acceptance. A main
merge and initial 0.1.0 release require separate authorization.

## Deployment and collaboration

Physical responsibilities are **Node**, **Hub** and **Client**. A Node owns local
native-session access, Endpoint keys, inbox and writer state. A Hub provides
authoritative state, Directory, Relay, Guard and the user-facing Control
service. A Client provides user identity, review and approval. They need not
occupy three different machines. Android belongs to the separate
[CICADA Client repository](https://github.com/cicada-fabric/cicada-client);
this repository owns Hub, Node, Control and their protocols.

Logical participants are **User**, **Control**, **Worker** and optional
**Monitor**. Control manages user intents, goals and approvals; Workers execute
work; Monitors observe, review or represent a Group only within explicit grants.
Ordinary peer collaboration does not require Control planning or a Monitor to
relay every message. Thread, Endpoint, Network and Group are objects, not extra
deployment components or participant classes.

A Hub can host multiple private Networks, each with one authoritative Hub. A
Group belongs to one Network. A Thread/Endpoint can register in multiple Networks
and participate in multiple Groups; nested Groups do not inherit permissions.
Multi-Hub state and credentials are independent, with no implicit Hub-to-Hub
forwarding. Joining a Network does not grant all directory, Group, task or
history access. See the [Network contract](network-m1-contract.md).

## Install from a checkout

Review [distribution and deployment](distribution.md) before running these
existing entry points. Local Linux Hub deployment requires Docker Engine and
Compose v2; binary compilation requires the documented Go 1.27.1 toolchain.

```sh
# Builds this checkout and starts a local loopback Hub with persistent state.
scripts/install-cicada-server.sh

# Optional host Node; the example address and Node name are fictional.
CICADA_CONTROL_URL=https://hub.example.org \
CICADA_MACHINE_ID=node-example \
scripts/install-cicada-worker.sh --mode relay
```

The Hub profile defaults to loopback HTTP for same-host development. Remote Nodes
and physical Clients require operator-managed HTTPS, certificates and firewall
policy. The Node retains its own credential and initiates outbound HTTPS/SSE
connections; Hub does not dial into the Node. The installer submits a credential
digest for a 10-minute device code. An authenticated Owner must independently
Preview and Confirm that exact Node. The code alone grants no access. Explicit
`--mode managed` additionally processes authorized single-Node Worker/Monitor
work; it does not grant broader authority.

For local packaging, existing entry points are `scripts/build-release.sh VERSION
[OUTPUT_DIR]` and `scripts/build-hub-image.sh --image IMAGE --metadata-file PATH`.
They build local source and record provenance. A release workflow existing in
GitHub does not prove an image or release has been published. No downloadable
signed production installer or published v0.1.x artifact is assumed here.
Hub images contain no Codex CLI or provider credentials. Runtime/provider setup
belongs at the Node; consult [harness integration](harnesses.md).

## Join, binding and delivery

Installing CICADA, its MCP integration or a Runtime never joins all sessions.
Explicit Join binds an existing native Thread to a stable Endpoint and current
SessionBinding. Join is scoped and idempotent. It does not grant Worker/Monitor roles, arbitrary
peer access or old history; any seeded same-owner Group grants remain restricted
to exact scope and policy. Native identity comes from the trusted
connection and binding, rather than a model-supplied sender or approval claim.
See [Join self identity](native-join-self-identity.md) and
[Runtime capability limits](runtime-operation-capabilities.md).

The default authorized peer route is ciphertext through one common **HubRelay**.
The optional local direct route requires the same physical host, the same Codex
account and a Node-callable native API that can reach the exact target Thread,
plus current Join, binding and scope authorization. A shared Node label is
insufficient. Local sealed ledger/queue checks do not prove a general TUI direct
adapter, cold wake or model consumption. Native writer exclusion depends on all
participating Agents sharing the private WriterRoot; separate roots cannot claim
machine-wide exclusion.

The existing MCP and matching service surfaces provide identity/discovery and
`send`, asynchronous correlated `ask`/`reply`, receive/status and cancellation
operations within current grants. ASK acceptance returns a durable request
identity; it is not an answer. Distinguish Relay persistence, Node persistence,
Runtime injection, model consumption and business acceptance. Delivery is not a
promise that an arbitrary action executes exactly once; uncertain injection must
remain uncertain rather than be blindly retried. See [Fabric](fabric.md),
[native writer recovery](native-writer-recovery.md) and
[native queue crash acceptance](native-queue-crash-acceptance.md).

Tasks and handoff carry scoped responsibility and evidence; accepting or claiming
a task does not approve its result or expose another Group's private context.
Group Journal records bounded important checkpoints; Discussion provides topics,
replies and explicit status. Ordinary messages do not automatically become shared
history, and closing a discussion does not complete a Task. Read the
[task privacy contract](task-peer-privacy-contract.md),
[Group spaces contract](group-spaces-m2-contract.md) and
[multi-owner contract](group-spaces-multi-owner-contract.md) for exact grants,
limits and fail-closed cross-owner boundaries.

## Trust and encryption

Public capabilities advertise availability. Encrypted session capabilities and
server Guard determine what a particular device can do. Principal identity,
Network membership, Group membership, Endpoint Join, SessionBinding, key consent
and operation grants remain separate. Roles or approvals asserted in model text
cannot authorize an action. A shared native Thread also shares model memory;
switching Group scope cannot erase information already consumed by that Thread.

The protocol uses NIST ML-KEM, ML-DSA and authenticated encryption. Ordinary peer
content is encrypted to authorized Endpoints; Hub Relay is not its decryption
endpoint. Client management commands are encrypted to **Control**, which decrypts
them to perform management. This does not imply that every process on a Hub can
never see any plaintext. Historical compatibility paths must be assessed by
purpose and evidence. HTTPS and optional PQTLS protect transport and do not
replace application E2EE. Content submitted to an external model is visible to
that provider. See [Client wire v1](client-hub-wire-v1.md),
[Client development boundary](client-hub-development.md) and [E2EE](e2ee.md).

## Backup, upgrades and version maintenance

Back up Hub state and Node-local state separately. Stop the relevant writers,
verify the backup, retain Owner keys securely and review migration inventory
before changing binaries. Node backup is bounded to its selected subtree and
covered shared writer/fence state; it is not a backup of all native conversation
history or every Hub context. Restores retain quarantine until separately reviewed
safe activation. Never simulate rollback by deleting state or opening a newer
schema with an older binary. Follow [Node backup](node-backup.md),
[Hub restore quarantine](hub-restore-quarantine.md),
[safe activation](hub-restore-safe-activation.md) and
[migration boundaries](architecture-v2-migration.md).

| Identity | Current source meaning |
|---|---|
| Software | [`0.0.1-dev`](../VERSION), unreleased development |
| Architecture | v2.3 adopted specification |
| Hub SQLite schema | [59](../cicada-go/internal/store/migrations_v2.go) |
| Client contract | [`client-hub-v1.6.4`](../cicada-go/internal/clientcontract/catalog.json), 55 operations |
| Encrypted Client wire | 1 |
| Git / source fingerprint | Exact revision plus dirty state and actual build inputs |
| Binary / OCI / APK | Each artifact has its own digest and acceptance record |
| Native Runtime | Its installed version and tested capabilities, independent of CICADA |

After initial acceptance and an authorized release, in **v0.1.x**, `x` is an incrementing patch position: compatible bug fixes and
performance corrections can move `0.1.0` to `0.1.1` and onward. Large product,
authorization or integration changes belong to **v0.2.x**, with an explicit
migration and compatibility review. Publishing documentation does not increment
`VERSION`, create a release tag or complete an acceptance gate. Future work is
recorded in the [v0.2 roadmap](v02-openai-integration-roadmap.md) and
[Agent collaboration design](v02-agent-collaboration-design.md).

## Evidence and remaining limits

Deterministic Go/Python/contract tests, disposable Docker interoperability,
local browser checks, real native Runtime, Android, physical devices and public
HTTPS are separate evidence layers. A SKIP, NOT_RUN, UNKNOWN or BLOCKED result
is not PASS; neither an old passing checkpoint nor a successful HTTP response
qualifies a different source, binary or Runtime.

The latest recorded native G1/G2 attempts have not completed acceptance. Native
G1 completion, the G2 denial tail and G3 restore remain open; Android, physical
and public HTTPS results must be read separately. Bounded deterministic and
browser evidence exists, but overall v0.1 product acceptance remains partial.
Full ordinary-user/admin governance and expanded delegated workflows remain
future v0.2 work. Use the [current closeout](v01-current-closeout-20261009-validation.md)
and [test automation guide](test-automation.md) for exact sources, outcomes,
cleanup limitations and remaining gates.

The separate [documentation-site repository](https://github.com/cicada-fabric/cicada-fabric.github.io)
contains a static community overview. This core guide remains the maintained
runtime how-to; site-source publication does not prove Pages hosting is live.
