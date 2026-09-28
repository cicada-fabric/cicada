# M1 Network validation design

**Status:** 2026-09-28 bounded Network M1 checkpoint **PASS** on the frozen dirty candidate and evidence below; overall M1 remains **NOT_COMPLETE** because the matrix is intentionally broader than these checks.
**Scope:** two Networks on one Hub, versioned Network memberships/admin grants, explicit owner-confirmed Endpoint registration, Group→Network migration, filtered discovery, authorization of existing service/Node paths, and one disposable real-HTTP test. M2 Journal/Discussion, M3 routing/unread, M4 delegated regrouping, M5 multi-Hub, Android changes, and real native Runtime runs are outside this validation.

## Evidence baseline

The implementation base is clean `dev` commit
`0cda61460757246789970782584b1e904173e653`. There are no Network membership,
Network admin, or trusted `network_id` types in that baseline. The clean
`25013b5` full Go/vet/focused-race/contract/disposable-TCP results and the
`0d532f2` fixed Android/native runner are prior evidence for their exact
candidate identities only. `0cda614` adds no application implementation over
that candidate; the pre-existing changes under `cicada-go` and `scripts` are
limited to the native fixture assertion and fixed runner. No M1 result is inferred
from the earlier gate. The bounded M1 checkpoint and its limitations are below.

## Bounded foundation checkpoint (2026-09-27)

The disposable Network suite passed on clean source `b0081a0ef16d9c39de4ebb5c75769f5a78327cf1` (`source_dirty=false`, fingerprint `31cec5b1f94290832b61bcb3f0fa696c8c42c0c4024778a8d7ba816c21e7f793`, software line `0.1.0-dev`). Hub image `sha256:c32d75640dd1a4bdbc134e72c871077df3410f4805027b3f1123abe373537db0`; test image `sha256:7c8860ff375fae05bfd50805a019d438406dec135b61c0c45c5f8ea808ebd529`. `TestNetworkM1DockerHub` ran over real TCP and exited `0`. It exercised same-Hub Networks A/B, operator mapping/dry-run/activation, explicit Owner-approved same-session registrations, Group non-membership, filtered discovery/resolve, duplicate alias 409 and hidden-scope denial, NetworkAdmin invite scope, membership revocation, old Group scope rejection and pending Group quarantine. Both the default Client and Network gates used separate fresh Hub StateDirs, images and owned prefixes; both exit `0`, cleanup recorded no remaining owned containers or image tags. Evidence is in `.cicada-data/network-m1-final-b0081a0/`.

The Client gate is the unchanged `client-hub-v1.3` contract (33 operations, catalog SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`) on its default PREPARING Hub. It does not test an ACTIVE Hub. v1.3 `group.create` has no Network selector; once activated, the server rejects a new Group lacking an explicit Network. Do not infer ACTIVE topology compatibility from the default smoke result. Use the [operator CLI contract](network-m1-contract.md); the frozen Android contract remains unchanged.

The full Go invocation at `b0081a0` exited `1` only because the legacy test `TestExternalThreadInviteMigrationRollsBackAndPreservesLegacyRows` expected the schema ledger to end at v34. Test-only commit `f9d3c7e0991b337440984c42c56f9e6b79ba2f04` updated that expectation for M1 schema v35. On f9d3c7e, the complete Store package suite passed (`go test -count=1 -timeout=15m ./internal/store`, exit `0`, 140.936s), Store vet passed, and `gofmt -l cmd internal` returned no files. Every other package passed in the initial `./...` run; do not describe that initial full command as exit `0`. On b0081a0, `go vet ./...`, focused Network race tests for Store/Fabric/CLI, the catalog check, seven Python tests, shell syntax and `git diff --check` passed. Exact commands and per-gate results are in the evidence directory.

## 2026-09-28 migration preservation addition

`TestNetworkV34UpgradeInterruptionPreservesCompleteLedgerAndMappingScope`
passed in the final race gate on the frozen dirty candidate at
`HEAD=975ce8e1a49fd48f1b09b34faf891e20dc977554`, source fingerprint
`1738095ea36e47655808857ce1934a72241bab1d8bb860d62f24299964c38d00`; the
pre/post gate fingerprint matched. The race log records the test passing in
21.23s and reports 93 legacy inventory entries, 52 nonempty, with only counts and SHA-256
digests. The 93 inventory entries include each pre-v35 application table plus
one digest entry for schema migration rows through v34; 52 entries contain
rows. The initial offline focused run was against a changing dirty worktree,
so it is retained only as development evidence in
`.cicada-data/checkpoint-next-20260928/network-migration-focused.json`; the
frozen race run is authoritative.

The fixture includes sealed REQUEST/claim receipt/REPLY and relay security and
outbox rows; Contact sequence replay, ratchet state and a peer message; Goal,
Workspace, Worker and Approval; cross-Group Link with both owner grants; owner
keys, endpoint key grants and session bindings; Monitor approval/dispatch;
Artifact references/grants; and Task/result rows. It hashes schema and all rows
from every pre-v35 table plus the v34 migration ledger, without printing row
contents. An injected `after_apply` failure verifies that all nine v35 Network
tables, `groups_network_idx` and `groups.network_id` roll back and the v34
snapshot remains equal. Reopen retries migration 35 exactly once. Explicit map
prepare leaves Group rows unchanged; approve changes only `network_id`,
`revision`, `version` and `updated_at` on the approved Groups, with both
revision and version increasing by one. Pending and unmapped Groups remain
unchanged, and activation preserves the mapping digest and Group snapshots.
This is synthetic SQLite preservation evidence, not a production StateDir
migration or recovery exercise. Passing the final migration test does not turn
the overall M1 matrix green; broader acceptance gaps remain listed below.

## Current disposable HTTP gates (2026-09-28)

The default Client smoke and opt-in Network M1 suite passed in separate
disposable Hub runs on the frozen shared candidate: `HEAD=975ce8e1a49fd48f1b09b34faf891e20dc977554`,
`dirty=true`, source fingerprint
`1738095ea36e47655808857ce1934a72241bab1d8bb860d62f24299964c38d00`, and
unchanged Client catalog SHA-256
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`.
`TestClientDockerHubSmoke` and `TestClientDockerHubRecoveryFixture` both
returned `0`; Hub image `sha256:5123d81250a94ba89fd835b86e852c7cd139785edaa630da01a51f3ffb8280aa`,
test image `sha256:668bb39bad508767ac0134b8cfd7690557c2dfe6dd58ba5e57b47b99a70a0f0c`.
`TestNetworkM1DockerHub` returned `0`; Hub image
`sha256:75ed5a357905da20aef715a846d61db297a07347007906c8ad3761658eae542d`,
test image `sha256:6d94a7849d948cf1ec4704d2cbb7e4c1269e9f02e532e8f64ac880d55c62ad15`.
The Network suite covers same-Hub dual Networks, operator mapping/activation,
same-session multi-Network registration, Group separation, filtered discovery,
alias ambiguity, NetworkAdmin grant scope, revocation, legacy Group scope, and
pending Group quarantine. Both runs used distinct StateDirs and owned resource
prefixes; cleanup confirmed no owned container or image tags remain. Result
JSON is under `.cicada-data/checkpoint-next-20260928/{client-docker,network-docker}/`.
These are real TCP tests of Go Hub code, not Android, native Runtime, physical
device, or public HTTPS evidence; each remains `NOT_RUN` for this candidate.
The full/race/vet/gofmt gate bundle also passed on the same frozen source:
`go test -p=4 -count=1 -timeout=15m ./...` exit `0` (146.289s; Store
126.894s); `go vet -p=4 ./...` exit `0` (6.566s); focused race command
`go test -race -p=2 -v -count=1 -timeout=12m ./internal/store ./internal/fabric ./internal/server ./cmd/cicada -run '^(TestNetwork|TestMappedNetwork|TestActiveNetwork)'`
exit `0` (202.884s); `gofmt -l cmd internal` exit `0` with no files listed.
The race selector had 24 top-level Network, MappedNetwork and ActiveNetwork
passes and skipped `TestNetworkM1DockerHub` because it was not attached to its
required disposable fixture; the separate Network Docker test above actually
ran that test and passed. `go-gates.json` records the same fingerprint before
and after all Go gates. Exact logs are in
`.cicada-data/checkpoint-next-20260928/`.

## Authorization rules under test

An authenticated call receives Network scope from its trusted Network-scoped
registration or credential, never from a request body, query parameter,
nickname, capability card, or model-supplied sender/role. Group-scoped actions
must resolve the Group's single approved Network and require the active
Principal NetworkMembership, Group Membership, Endpoint-Group join, binding,
and action grant as applicable. NetworkMembership alone does not join Groups
or authorize Group history. `NetworkAdmin` grants apply only to named Network
management operations and never stand in for Endpoint owner confirmation.

Use the same Core Guard from HTTP, MCP/CLI and Node claim/injection paths.
Authorization must be repeated when data moves from enqueue to claim, from
claim to Node authorization/injection, and when reading historical messages,
Requests, Artifacts, Tasks and results. A stale membership, stale scope or
unknown activation state fails closed. Aliases are filtered after scope is
authenticated; a duplicate visible alias is `AMBIGUOUS`, not a best guess.

The activation design is one way: schema migration creates a prepare/mapping
state, makes no implicit Network assignment, and requires versioned explicit
approval. In PREPARING, only still-unmapped legacy Groups remain
`LEGACY_UNSCOPED`; an APPROVED Group is strictly guarded immediately. Network
APIs are strict from introduction. Once activated, pending/unmapped Groups fail
closed across old and new entry points. Activation tests use an isolated fresh
Hub/StateDir because the transition must not leak into Client/recovery tests.

## M1 matrix

| ID | Gate | Required assertion | Evidence level | Status |
|---|---|---|---|---|
| M1-N01 | Same Hub, Network A and B | Same Hub identity hosts both scopes. An A-only actor cannot list, resolve, read, write, claim, or receive B-only resources. | Real HTTP + deterministic Store/Service | Partial: HTTP directory/resolve and service scope; read/write/claim/receive still pending |
| M1-N02 | Not joined | An unjoined native Session has no Endpoint discovery card, route, delivery claim, wake authorization, or mailbox/history access. | Real HTTP + deterministic Guard | Partial: unauthenticated directory and unknown-scope behavior only |
| M1-N03 | Same Thread, two Network registrations | The fixture preserves its original `EndpointID` and native Session ID while adding an independently scoped registration; the Node retains one current writer/binding owner. Leaving/revoking one Network leaves the other grant and writer intact. | Real HTTP; native Runtime expressly not implied | PASS for the HTTP/Store scope: `TestNetworkM1DockerHub` joins one native Thread to A and B, renews A without changing B or the original Group binding, then leaves A and verifies B plus the Group writer remain. Native Runtime behavior is not implied. |
| M1-N04 | Network membership is not Group membership | A Network member without the target Group's Principal Membership and Endpoint join cannot enumerate that Group, read its messages, or use Group grants. | Real HTTP + deterministic Guard | Partial: membership absence and selected Group `whoami` denial only |
| M1-N05 | Alias ambiguity | Duplicate aliases inside the caller's authorized scope return `AMBIGUOUS`; unauthorized aliases do not affect lookup or reveal a hidden Network/Group/Endpoint. | Real HTTP | Partial: duplicate alias gives 409; hidden alias gives 404 |
| M1-N06 | Trusted scope and actor | Forged Network, Principal, sender, Group, role, owner approval, or Node ID in a body/header cannot override the credential-bound actor/scope. Cross-Network replay/idempotency is isolated. | Real HTTP + deterministic Store | Partial: invalid Owner proof and cross-scope oracle subset only |
| M1-N07 | Revoke at enqueue | A revoked or expired Network grant cannot create new Send/Ask/Reply/Task operations even if a stale card or capability is presented. | Real HTTP + deterministic Store | Partial: passing `TestActiveNetworkSealedAskReplyWithoutControl` checks a revoked ACTIVE Network membership at real HTTP sealed SEND/ASK retry, new SEND/ASK, and pending REPLY enqueue; rejects with 403/404 and checks no new sealed rows while original accepted SEND/ASK remain. Task enqueue and other routes remain untested. |
| M1-N08 | Revoke at claim/injection | A queued delivery claimed before revocation is rejected by current claim/injection authorization after revocation. The exact attempt and binding epoch cannot be replayed as a new authorization. | Deterministic Node Guard + HTTP authorization endpoint | Partial: same-Group SEALED_V1 claim, native wake and pre-injection tests reject revoked/rejoined membership revisions; broader Node paths remain untested |
| M1-N09 | Revoke at history/read | Revoked members cannot read old Relay history, Request status/replies, Artifact refs, Task offers/results or any newly exposed scoped read view. Already exported plaintext cannot be recalled. | Real HTTP + deterministic Store | Partial: `TestNetworkScopedTaskAndRequestReadsFenceOldEnrollment` rejects stale Task/Request reads after revoke and rejoin while allowing current enrollment reads; `TestNetworkArtifactEndpointLeaveDeniesScopedMetadata` rejects Artifact metadata/list after Endpoint leave. Broader Relay history and all historical/read routes remain untested. |
| M1-N10 | NetworkAdmin boundary | NetworkAdmin can only perform its named Network grants. It cannot owner-confirm/adopt a Thread, create Group history access, access Node/device/workspace/private keys, approve user actions, or act across Network B. | Real HTTP + negative service tests | Partial: named invite, management-bearer denial and missing-grant denial only |
| M1-N11 | Old API bypass | Every old `/v2/fabric/*`, `/v2/relay/nodes/*`, local delivery/wake, Artifact/Task, directory, GroupCard/federation, and Group-management path either receives a credential-derived current scope or rejects unresolved/pending scope. Direct Store methods repeat checks. | Deterministic entry-point/Store tests; selected routes in Docker | Partial: old Join/`whoami`, claim, Task and Artifact examples only |
| M1-N12 | Explicit migration pending preservation | Dry-run and prepare expose safe counts/digest and affected links, key grants, deliveries/receipts, but never bodies, keys or credentials. Unmapped/ambiguous Group remains pending; old IDs, pending receipts, approvals, key/grant rows and replay counters remain unchanged. Activation fails closed for pending Groups. | Disposable synthetic SQLite + real HTTP | Partial: v34→v35 interruption/retry test hashes 93 legacy inventory entries (all pre-v35 tables plus v34 schema-ledger digest; 52 entries nonempty), checks all nine new tables roll back, explicit prepare/approve/quarantine/activation scope; Docker CLI path was exercised in the bounded checkpoint. This does not establish production StateDir recovery or every M1 migration edge. |
| M1-N13 | Control isolation | With Control management/business disabled or a failing test seam, valid Network/Fabric operations continue without planner, intent, scheduling, report, or Control inference calls. | Real HTTP + deterministic Store | PASS for the Network/Fabric paths: `TestActiveNetworkSealedAskReplyWithoutControl` completes sealed Ask/Reply over HTTP with `Handler.control == nil`; `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials` also passes and checks the unavailable Control management route. This does not claim Control-dependent routes work without Control. |

The exact protected entry points are listed in the [M1 code audit](architecture-v2-audit.md).
Every rejection must be asserted at the public status/error boundary and at the
service/Store transaction boundary where direct callers exist. `skip` is not
pass. This report separates Go tests and Docker HTTP results from Android,
real native Runtime, physical device and public HTTPS evidence.

## Remaining M1 acceptance gaps

The v34→v35 synthetic preservation test now snapshots every pre-v35 table and v34 migration-ledger row. Its populated fixture covers Relay request/reply/receipt/security/outbox, Contact replay/ratchet, Goal/Approval/Workspace, Links and bilateral grants, Endpoint key grants, artifacts/grants, Tasks/results, and Monitor dispatch. It confirms rollback/retry and that explicit mapping changes only the approved Group fields. This is broader ledger preservation evidence than the earlier selected-table test, but it remains a synthetic fixture and does not exercise a production StateDir, every operation-level recovery outcome, or actual power-loss recovery.

Network-only Join and directory are exercised. A Network-only Endpoint without any Group membership cannot use the current sealed Link transport: each endpoint needs its own authorized Group, both Groups must map to the same Network, and the Link needs bilateral Owner grants. Selected Link claim/pre-injection guards are covered by `TestNetworkLinkSealedPreInjectionRejectsRejoinedEnrollment`, but this checkpoint does not provide a new real-native end-to-end cross-Group Link acceptance result. Broader requirements remain partial: Task and other nonsealed enqueue after revoke; all claim/injection/wake adapters; Relay history and untested historical reads beyond the selected Task, Request, and Artifact cases above; every old HTTP/MCP/CLI/management/federation route; complete forged-actor/scope matrix; and the full set of NetworkAdmin operations. NetworkAdmin sessions authorize named Network operations and grant subsets; the local database operator CLI is a separate trusted host capability and is not a Network-scoped session. `TestMappedActiveNetworkRunsWithoutControlAndKeepsNativeGroupBinding`, `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials`, and `TestActiveNetworkSealedAskReplyWithoutControl` establish that these selected Network/Fabric paths work with Control absent; they do not establish availability for Control-dependent routes.

`TestNetworkSealedClaimAndPreInjectionFenceRevocation` and `TestMappedNetworkNativeWakeRejectsRevocationAndOldAttemptAfterRejoin` exercise selected claim, pre-injection and wake revision fences. They do not certify every custom Node delivery route. The full matrix remains the acceptance target; M1 is not complete, and these gaps must be closed or explicitly descoped before later M2–M5 work.

## Disposable Docker HTTP gate

The existing `scripts/test-client-hub-interop.sh` has an opt-in
`--suite network-m1`, leaving the default Client/Recovery selector untouched.
The suite creates a unique temporary Hub container, temporary SQLite StateDir,
synthetic opaque credentials and a separate test container; it runs only
`TestNetworkM1DockerHub` against the published real TCP port. The one-way
activation test gets its own Hub and cannot mutate the default v1.3 Client
smoke/recovery fixture. The runner records the separate suite name, source
revision, dirty flag, source fingerprint, contract revision, Hub/test image
IDs/digests, test exit and cleanup status. It writes only structured lifecycle
events; any raw failure log stays in a private temporary diagnostic file and is
never promoted into evidence.

The scenario uses no model, provider API, Android APK, production key, resident
Hub, or shared StateDir. The test creates a synthetic owner-bound Node and
legacy Groups in the disposable Hub. It uses the compiled `/out/cicada`
operator CLI for Network creation, mapping prepare/approval, migration dry-run,
invitations and one-way activation; it does not construct Network rows through
Store APIs. The Join, directory, resolve and revocation checks use real HTTP
against the owned Hub. The test proves that the same Hub can host A and B,
preserves a same-session Endpoint and Group binding, and rejects a credential
outside its scope. It includes an explicitly pending migration mapping and
preservation checks, then removes only resources carrying this run's unique
prefix. The test does not prove runtime-native wake, physical Node isolation,
Android consent UX, or public HTTPS.

Command used:

```bash
scripts/test-client-hub-interop.sh --suite network-m1
```

The exact run is recorded under `.cicada-data/network-m1-final-b0081a0/`; each
suite uses a separate disposable Hub and state. Docker missing/unavailable or
a skipped test remains `BLOCKED`/`SKIPPED`, never `PASS`. The M1 Docker result
does not establish real native Runtime, Android, physical dual-Node, or public
HTTPS behavior; all four remain **NOT_RUN** for M1.
