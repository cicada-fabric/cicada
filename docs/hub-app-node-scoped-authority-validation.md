# Node-scoped App/NPT producer validation

## 2026-10-29 disabled Hub carrier checkpoint

The Hub producer now implements the frozen Scope2 authority and NPT contracts
behind an explicit Go composition opt-in. The normal Hub constructor, Hub CLI
and both public availability defaults remain **false**. No deployment, CLI
enable flag, App implementation or Node consumer is changed here. The existing
wire version 1, operation catalog 55 and software version 0.0.5 are unchanged.

Migration **70** adds immutable `LEGACY_V1`/`NODE_V1` grant and NPT metadata,
exact `(Owner, App, Node)` heads and a writer guard. It leaves existing claims,
Owner proofs, original receipts, legacy heads/provenance, account/Owner/App/Node
identities, public keys and security epochs intact. There is no legacy proof
conversion or backfill of scoped authority. The original App request/response
counters, one PREPARED proposal, NPT RESERVED slot, nonce/history ledgers and
bounded anonymous/read/critical budgets remain shared across namespaces.

Authentication reuses the existing completed N2 provenance, current account
session, registered App key and Owner proof services. Password login alone
still produces no Root authority. INITIAL keeps its 15-minute lease and one
confirmation; READ_EXISTING keeps zero confirmations and the original binding
provenance. A new namespace cannot revive confirmed or revoked history. Exact
same-namespace unconfirmed expiry/self-cancel continuation remains possible.
Only the original Node's private ACK commits its original confirmation, binding,
global counter movement and both sealed receipts in one transaction.

The per-Node SQL writes require the exact Node/head/grant and one affected row.
Historical receipt recovery checks the authenticated original Node before any
cache/fence and remains possible after a later same-Node cancellation. A code
status whose anonymous candidate was actually collected may settle only as
READ_EXPIRED without an original receipt; other database errors fail closed.

Source/evidence root:
`/home/zyf/Cicada/.local/evidence/app-node-scoped-carrier-20261029-01/`.
This is a dirty producer build based on
`dceb77716ed936a2fe87cf9928549b026d0c1501`, not a HEAD-only attribution.
`tested-source-manifest-v1.json` SHA-256
`87456ca1b3f8e22f6dc811cfc337bb76e5943569a70dad662e8e07401d1ba1b7`
pins the broad regression and first Docker gate. The final GC read correction
changes exactly two Store files and one Store test file, recorded by
`tested-source-manifest-v2.json` SHA-256
`abf6707edd4cb43caae6fa016581d9cbd66d14cb3116411fca5d3c304532b38c`.
The affected normal/race/final Docker gates use v2. Later changes touch only
five pre-existing Store test files for historical schema fixtures, plus this
validation and README. Production Go source and the selected race/Docker test
bodies remain identical to v2; these test-only changes are separately recorded
in the final checkpoint review inventory.

The final gate receipt below records package terminals and skips. Earlier
development logs, the first single-TLS helper failure and the interrupted
normal/race harness runs are retained under the same evidence root; none is
silently promoted to a completed gate.

| Gate and exact source | Top-level results | Package terminal / exit |
| --- | --- | --- |
| Broad normal, v1 inventory | 778 PASS, **19 FAIL**, **10 SKIP** | Store FAIL 879.155s; Server PASS 265.616s; Hubauth PASS 1.514s; wrapper **1** |
| First fixture correction plus GC read, v2 production + two old test fixtures | **7 PASS**, zero FAIL/SKIP | Store PASS 7.360s; wrapper 0 |
| Remaining historical forward fixtures, v2 production + three old test fixtures | **13 PASS**, zero FAIL/SKIP | Store PASS 44.005s; wrapper 0 |
| Final affected GC read and actual two-Node TLS normal, v2 inventory | **2 PASS**, zero FAIL/SKIP | Store PASS 0.839s; Server PASS 10.360s; wrapper 0 |
| Final selected race, v2 inventory | **6 PASS**, zero FAIL/SKIP | Store PASS 140.836s; Server PASS 40.800s; wrapper 0 |
| First disposable Docker, v1 inventory | **43 PASS**, zero FAIL/SKIP | Store PASS 61.831s; Server PASS 16.980s; container exit 0 |
| Final affected disposable Docker, v2 inventory | **3 PASS**, zero FAIL/SKIP | Store PASS 2.166s; Server PASS 10.362s; container exit 0 |

The broad normal run retains its FAIL terminal. Five migration tests expected a
ledger ending at 69; one TLS backup and thirteen forward-restore tests opened a
current database while asserting the older restore boundary. The fixes add the
70 ledger expectation and reconstruct real empty schema-68 DDL only in private
historical fixtures. Their opener refuses any scoped/NPT or newer Group
authority before removing test DDL. All nineteen original failing tests then
pass in the two targeted runs above; this is not a rerun or PASS relabel of the
full suite. Their old restore business assertions remain intact. Three Store
physical-bind checks and seven Server external Docker/native-fixture checks
skip in the broad run; none counts as a pass. Exact names and package counts
are retained in `full-normal-v2-receipt.json`, SHA-256
`bc9b16abe48a0bca6a6568718c24d937d69a27a809edaf1188f88add026451f9`.

Final normal/race receipts and hashes are in
`completed-targeted-gates-receipt.json`, SHA-256
`d84200e8807aca2f47348ed20726b890f16f16e4b7d957f5fdfb56b79d193f7e`.
The thirteen historical schema-68 checks have their separate
`historical-restore-receipt.json`, SHA-256
`67d533aa3fd71b36de16580bebcbcea0748ce3d1a3fd7ec8b60aa3042f8a29d4`.
Exact host commands are retained in `host-commands.json` and
`historical-restore-command.json`. No unrelated full-suite repeat follows the
fixture corrections.

Both Docker gates use immutable image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
Go 1.27.3, network disabled, UID/GID 1000, read-only source/root/module cache,
disposable tmpfs and an existing build cache. Exact commands, source inventory,
test binary hashes, logs and exit/cleanup receipts remain under `docker/` and
`docker-v2/`. Both owned containers are absent afterward. Final Docker receipt
SHA-256 is `44cd7ac8b7bd8a3eb7c0c7fcf0f38d2927f9c8bf33bca02e998b379553e9d789`.
The joint Python metadata check and `git diff --check` pass; no public contract
or default availability is changed by this carrier checkpoint.

Real TLS qualification uses an isolated Go Hub handler, an actually activated
Owner/account/App and two independent synthetic Node keys. Both Nodes complete
separate Owner approval, local-secret/private ACK and original receipt recovery
with shared Client sequences 1 then 2. It checks cross-Node cached authority and
Client reconciliation rejection, unadmitted read rejection in the wrong Node,
same-Node recovery after cancellation and cancellation of A leaving B active.
This is not the shipped Hub CLI, an App Runtime, a Node daemon or a Network/Group
acceptance run. The Store fixtures exercise restart/rollback, concurrent head
CAS, namespace and candidate-version fences, shared PREPARED/RESERVED guards,
READ_EXISTING, five security fences and actual anonymous GC read settlement.
Account/account-device epoch cases explicitly mutate synthetic persisted test
epochs; Owner-key/device revocation and Client epoch changes use existing Store
operations.

Database process reopen is covered separately from backup/restore: schema 70
restore remains **UNSUPPORTED** by the retained reviewed restore-version pin;
the test verifies refusal and does not claim successful restoration. Actual
App + two Node daemons + existing Network/Group, shipped CLI scoped enablement,
native Runtime, physical Windows, Android and public HTTPS remain **NOT_RUN**
for this producer checkpoint. Combined consumer review must precede availability
enablement; public discovery is not caller authorization.

## Earlier shared codec checkpoint

2026-10-29 producer checkpoint, **CODEC_ONLY_UNAVAILABLE**. Contracts:
[finite authority](hub-app-node-scoped-authority-contract.md) and
[independent NPT](node-pair-trust-scoped-contract.md).

Tested source is base `d4566fcd969424dc47ab811bfdcfd8c65afc59e2` plus the
explicit dirty-file inventory in
`/home/zyf/Cicada/.local/evidence/app-node-scoped-codec-20261029-01/tested-source-manifest.json`,
SHA-256 `8e775f020da67e14ff78dd0f2a75f4b8996f2f7bc849d0d070411dbcdaab5c85`.
That inventory includes two unchanged Store dependency files as extra source
inputs; it is not the checkpoint's Git file list. The diagnostic-only commit
`98ed4e21d06476b41b75b4d3fee5f88696a4c6a2` was created after these source files
were frozen. Its unrelated `cmd/cicada` change is outside these tested packages.
This is not a clean-HEAD-only build attribution.

## Deterministic and disposable gates

Normal full `internal/e2ee` and `internal/hubaccountwire`: **174 top-level PASS**,
zero FAIL, **one SKIP**, package elapsed 0.673s and 5.111s. The optional external
`TestExternalOwnerOpenSSLRealSignatureInterop` skipped; it is not a pass.
`crypto-wire-normal.jsonl` SHA-256
`a41be5318b62f7709215169a87586749bc018035a5fbd6f1df13aa9cfa6a82f0`.

Normal isolated Server TCP: **2 PASS**, zero FAIL/SKIP, 3.086s. This runs the
existing N3 activation/Owner proof/confirmation/heartbeat/READ_EXISTING chain and
the new false-only discovery/method/closed-POST check.
`tcp-normal.jsonl` SHA-256
`6dcd42a576e41020aa34070ed6a4f83685161ae40e41a2f62bef82e9a48d2067`.

Disposable Docker: **11 top-level PASS**, zero FAIL/SKIP: nine scoped wire tests
(0.486s) and the same two Server TCP checks (3.152s). Image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network disabled, UID/GID 1000, read-only source/root/module cache, disposable
tmpfs and existing Go build cache. Test binary hashes, exact commands and raw
events are retained under `docker/`; the owned container is absent afterward.

The post-completion host receipt-count parser raised TypeError, so its wrapper
exited 1. This historical harness failure is retained. Both test package
terminals are PASS; the exact container's Docker `die` event independently
records **exitCode=0**, retained in `docker/completion-events.jsonl`, SHA-256
`b1e9d42604e0c052d4ff4682901b26e69b879d8e7163e4401f7989f25f7c6b48`.
`docker/receipt.json` records both results and their distinct attribution; no
test rerun or source change was used to replace the original logs.

The joint Python metadata check passes both unchanged `app-node-authority-v1`
and the new scoped contract, asserting wire/catalog, distinct routes/purposes,
Scope2, exact operation/DTO inventory, unchanged finite bounds and availability
false. `git diff --check` passes.

## Tested boundary and remaining work

New tests exercise real synthetic PQ envelopes and Owner signatures, strict
v1/new isolation (including an empty unknown field), exact candidate/binding
Node match, READ_EXISTING without a confirmation, XOR status resolution,
explicit head-zero Owner identity projection, `n3s.` original selection,
cancel/reconcile original binding, new secret-code matching, original Node
pairing proof, all twelve NPT request operations, independent local-secret
capsule/ACK verification, and an authenticated recovered receipt with identical
original bytes. They use only isolated temp state and visibly synthetic keys.

Both new capabilities remain false and scoped POST routes remain closed. No
Store migration or live scoped grant/confirmation carrier is implemented by
this checkpoint. Per-Node transactional CAS, global pending/RESERVED and
cross-namespace provenance behavior, crash/restart persistence, account/Owner
revocation across scopes, restore inventory, actual second Node through the
App into an existing Network and Group all remain **NOT_RUN** pending carrier
and consumer implementation. Race, Android, actual native Runtime, physical
Windows and public HTTPS are also **NOT_RUN** here. Existing v1 tests and the
new shared codec tests do not establish those acceptance scopes.
