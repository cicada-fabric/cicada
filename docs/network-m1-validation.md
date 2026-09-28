# M1 Network validation design

**Status (2026-09-28): Backend M1 acceptance PASS.** Matrix N01–N13 and final gates passed on dirty source fingerprint `479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe` (`HEAD=733ca8640f86f4944b4f8d8f7c38f6cd929212f2`, dirty; Client catalog SHA-256 `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`). Full Go passed 25 packages/894 top-level tests (1273 including subtests), exit 0 in 157.382s; vet exit 0 in 2.384s; focused race passed 5 packages/16 selected tests, exit 0 in 175.209s; `gofmt -l` was empty. Contract check, eight Python tests and shell syntax passed; both separate real-TCP Client and Network Docker gates passed, exit 0 in 158.042s/158.551s. Final Hub images: Client `sha256:ac86a1e80ec9927565f187ba78c022a9975dc667c3a498e963611ea8e8868cba`, Network `sha256:1897f8940c82a51c2a937aaf39632c429a10eacf1d8b1329414d81cfc9c77356`. Exact evidence: [accepted Go gates](../.cicada-data/m1-final-20260928/accepted/go-gates.json), [Client Docker](../.cicada-data/m1-final-20260928/accepted/client-docker/result.json), [Network Docker](../.cicada-data/m1-final-20260928/accepted/network-docker/result.json), and [ancillary gates](../.cicada-data/m1-final-20260928/final/ancillary-gates.json). This is backend acceptance, not evidence for Android, real native Runtime, physical dual-Node, public HTTPS, or the future same-host native TUI adapter; those remain **NOT_RUN**. M2 is next and was not started in this checkpoint.
**Current contract:** Store schema v36; Hub Client contract `client-hub-v1.4` (36 operations, wire v1).
**Scope:** two Networks on one Hub, versioned Network memberships/admin grants, explicit Owner-confirmed Endpoint registration, Group→Network migration, filtered discovery, Network-only sealed direct SEND/ASK/REPLY over Hub HTTP/Node delivery, and old-route authorization. M2 Journal/Discussion, M3 routing/unread, M4 delegated regrouping, M5 multi-Hub, Android changes, same-host native TUI direct, real native Runtime, physical dual-Node and public HTTPS runs are outside this backend checkpoint.

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

## Current implementation work (2026-09-28; final gates passed)

The current worktree has advanced beyond the historical v35 foundation: Store schema is v36 and the Hub Client catalog is v1.4 (36 operations, SHA-256 `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`). v1.4 adds Network topology projection and encrypted Owner key-manifest/grant/status operations. The Network Docker test exercises same-Hub dual Network direct key consent, encrypted Owner topology, real HTTP sealed SEND/ASK/REPLY with Node claim/authorize/receipt, and a separate Control-free HTTP ASK/REPLY chain. These assertions passed on the final accepted fingerprint above. Earlier full-Go attempts exposed outdated test-fixture assumptions; the fixtures were corrected without weakening production authorization or lease checks.

Focused source changes in this worktree pass these deterministic tests: `TestGlobalEndpointLeaveThenGroupOnlyJoinDoesNotRestoreNetwork`; Store `TestLastGroupLeavePreservesIndependentNetworkAccess` and `TestGlobalEndpointLeaveRevokesOnlyItsNetworkEnrollment`; migration/report inventory tests; server `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials` (36 route-family subtests), `TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint` (five scope cases), and `TestReadJSONRequiresExactlyOneTopLevelValue`; Node code `TestNodeDeviceBindingExpiryUsesInstantsAndFailsClosed` and `TestNodeDeviceBindingCleanupUsesInstantExpiry`; snapshot restore preservation/rollback tests; and the command-server configuration plus slow-body timeout tests. The final whole-repository Go/vet and selected race gates passed separately on the accepted source.

The ACTIVE HTTP route-family test uses a real Network leave and then checks current Group credentials across Directory aliases, retired plaintext Relay methods, Receive/heartbeat, Endpoint keys, Task reads and mutations, Task handoffs, Request status/cancel, a real ArtifactRef list/read/grant/revoke, resource lease, federation/representative and Control management routes. Rejected Task calls leave its revision/status unchanged. Artifact routes use `Cicada-Group-Scope` with the shared Group authenticator; a multi-Group test proves the default binding Group, explicit A/B access, cross-Group denial and denial of an unjoined Group. This is a finite existing-route inventory, not a claim that every MCP/CLI/Node adapter path or every future route was executed over HTTP.

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
migration or recovery exercise. This is the earlier schema-v35 checkpoint;
the current v36 migration and report tests are listed in the M1 matrix.

## Previous disposable HTTP gates (2026-09-28; schema-v35 candidate)

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

## Historical interim 2026-09-28 gates (dirty source fingerprint 05a486a4)

The source identity for this interim run is `HEAD=733ca8640f86f4944b4f8d8f7c38f6cd929212f2`,
`dirty=true`, fingerprint
`05a486a4d681ac6ab4567dc50706a6efe8d68bf2d2d96203e4b1876f184c4959`, and
Client catalog SHA-256
`7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`. The
fingerprint, not HEAD alone, identifies the tested source.

The v1.4 Client Docker suite passed over real TCP (`TestClientDockerHubSmoke`
and `TestClientDockerHubRecoveryFixture`, exit 0) with Hub image
`sha256:77efe9db58de0e8344d503117215faa019f4d510b1d9e9798d4ad3815de8aeeb` and
test image
`sha256:14d8e4689a96bcc63902a877fd4b29f7398ef487491ee723a9c357b568bf54bc`.
The Network Docker suite passed (`TestNetworkM1DockerHub`, exit 0) with Hub
image
`sha256:e4bd75b6f7b9286535948cd10117469b497f50e7692ef7dcb1fae94ddf9536dd`
and test image
`sha256:d225e50058f4d477471c6b14ff7027ab902813b046b7a80b2361e7918aa16570`.
The Network scope includes encrypted dual-Network topology, Owner-approved
direct-key grant, real HTTP/Node SEND and ASK/REPLY claim/authorize/receipt,
and a fresh Control-free HTTP chain. One synthetic Node credential is used
with two synthetic native Session IDs; this is a Hub protocol test, not proof
of two independent physical Nodes or native Runtime. Result JSON, test logs and runner logs
are under `.cicada-data/m1-final-20260928/`.

`go vet -p=4 ./...` passed in 7.453s. The first full
`go test -p=4 -count=1 -timeout=15m ./...` run exited 1 on five old test
fixture assumptions: three Artifact tests used anonymous first publication,
and two lease tests used the production Renew API to create an already-expired
lease. Corrected fixtures reflect current authorization and time guards;
production checks were not weakened. A separate later run exposed two
additional obsolete fixtures; the initial race run was stopped with exit code
143 after 405.334 seconds.
None of those runs is counted as a pass. The corrected final full-Go and race
gates passed on the accepted fingerprint at the top of this report.

The after-upgrade `govulncheck` v1.8.0 run passed in 48.631s on Go 1.27.1
across 25 root packages/15 modules. It found 0 reachable symbols and 0
vulnerabilities in imported packages for the scanned graph; the only remaining
module-only result was GO-2026-5932 in unimported OpenPGP, with no upstream fix
at scan time. The earlier attempt that could not use the read-only module
cache is retained as a failed execution record; the successful retry used a
fresh container-private `/tmp/gomod` cache. Logs and JSON are
`.cicada-data/m1-final-20260928/govulncheck-after-retry.{log,json}`. This
dependency result belongs to the earlier `05a486a4` source, whose dependency
pins did not change; it does not substitute for the final Go/race gates.

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
| M1-N01 | Same Hub, Network A and B | Same Hub identity hosts both scopes; an A-scoped credential cannot enumerate or operate on B-only resources. | Real HTTP + deterministic Store/Service | Covered by the dual-Network disposable scenario, `TestNetworkDirectoryScopedReadRechecksAcrossStoreHandles`, and direct claim/key scope tests. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N02 | Not joined | An unjoined native Session has no Network card, route, delivery claim, wake authorization, or Group authority. | Real HTTP + deterministic Guard | Covered by `TestUnjoinedNativeSessionIsNotDirectoryObject`, `TestNetworkOnlyMCPStateCannotBecomeGroupAuthorization`, join-proof validation, and the disposable not-joined/unknown-scope cases. Final accepted full-Go/race gates PASS. |
| M1-N03 | Same Thread, two Network registrations | Preserve native Session/Endpoint identity and the Group writer while independently renewing/leaving one Network enrollment. | Real HTTP + deterministic Store; native Runtime expressly not implied | Covered by the disposable same-Thread A/B registration/renew/leave scenario, `TestLastGroupLeavePreservesIndependentNetworkAccess`, and `TestGlobalEndpointLeaveRevokesOnlyItsNetworkEnrollment`. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N04 | Network membership is not Group membership | Network membership alone cannot enumerate/read a Group or use its Group grants. | Real HTTP + deterministic Guard | Covered by `TestNetworkOnlyMCPStateCannotBecomeGroupAuthorization`, Network-only enrollment in the disposable scenario, and active Group route denials after Network leave. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N05 | Alias ambiguity | Duplicate visible aliases return `AMBIGUOUS`; hidden aliases do not reveal another scope. | Real HTTP | Covered by duplicate-alias 409 and hidden-scope 404 assertions in the disposable Network scenario. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N06 | Trusted scope and actor | Caller identity and authority derive from credential, signed Owner proof and current server-side scope, not body/header claims. | Real HTTP + deterministic Store/Node tests | Covered by Join/consent scope-binding tests, `TestNetworkConsentSignBindsExactScopeAndKeepsProofPrivate`, direct key/Owner trust tests, and credential separation in the HTTP route matrix. This is a finite claimed-field set, not a cross-product over arbitrary inputs. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N07 | Revoke at enqueue | Revoked or expired access cannot create new direct SEND/ASK/REPLY, Group Task, Artifact or resource mutations. | Real HTTP + deterministic Store | Covered by `TestActiveNetworkSealedAskReplyWithoutControl` (retries/new SEND/ASK/pending REPLY with no new sealed rows), `TestNetworkTaskWritesRecheckNativeBindingEpochInWriteTransaction`, `TestNetworkArtifactMutationsRejectStaleNativeActorAcrossStores`, and `TestNetworkResourceMutationsRejectStaleNativeActorAcrossStores`. Final accepted full-Go/race gates PASS. |
| M1-N08 | Revoke at claim/injection | A queued attempt must pass current scope and exact-attempt/native binding checks at claim and immediately before injection/authorization. | Real TCP + deterministic Node/Store | Covered by the current disposable direct SEND/ASK/REPLY claim-authorize-receipt chain, `TestNetworkSealedClaimAndPreInjectionFenceRevocation`, `TestNetworkLinkSealedPreInjectionRejectsRejoinedEnrollment`, and `TestMappedNetworkNativeWakeRejectsRevocationAndOldAttemptAfterRejoin`. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N09 | Revoke at history/read | Current reads of Task/Request/Artifact/direct status and retired receive routes recheck current enrollment; already exported plaintext cannot be recalled. | Real HTTP + deterministic Store | Covered by `TestNetworkScopedTaskAndRequestReadsFenceOldEnrollment`, `TestNetworkArtifactEndpointLeaveDeniesScopedMetadata`, the active old-route read matrix, and current direct request-status checks. This does not imply revocation can recall previously exported plaintext. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N10 | NetworkAdmin boundary | NetworkAdmin invitation powers are Network-scoped and cannot replace Owner consent or broader Group/device authority. | Real HTTP + CLI/service tests | Covered by scoped invite issuance and cross-Network/missing-grant denial in the disposable scenario, plus `TestNetworkPermissionPresetsHaveExactLeastPrivilegeGrants` and exact stored/Owner-signed preset tests. Local database operator CLI is a separate host capability. Final accepted Network Docker and full-Go/race gates PASS. |
| M1-N11 | Old API bypass | A finite inventory of existing Directory, Relay, local delivery/wake, Task/Handoff, Artifact/resource, GroupCard/federation and management route families either authenticates the correct scope or rejects a Network credential. | Real HTTP + deterministic Node/MCP/Store tests | Covered by `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials` (36 route-family cases), `TestNetworkStoreGuardErrorIsPermissionDeniedAtFabricHTTP`, Node wake/claim tests and MCP Network-state separation tests. This is the current-route inventory, not a claim about future endpoints. Final accepted full-Go/race gates PASS. |
| M1-N12 | Explicit migration and safe impact report | Dry-run is read-only and snapshot-consistent, shows bounded safe identifiers/counts/digests and Group relations without payloads/secrets; interrupted upgrade preserves the complete prior ledger and activation gates unresolved mappings. | Disposable synthetic SQLite + real HTTP/CLI | Covered by `TestNetworkMigrationReportInventoriesSafeIdentifiersAndGroupRelations`, `TestNetworkMigrationReportUsesOneSQLiteSnapshotAcrossHandles`, `TestNetworkMigrationBackupDryRunAndRestoreOnDisposableDatabase`, `TestNetworkMigrationReportBoundsGroupDetailsWithoutDroppingDigest`, v34/v35/v36 interruption-preservation tests, and the disposable CLI migration scenario. The synthetic fixture includes nonempty Relay, Contact, approval, Link, key, Artifact and Task ledgers; it is not production power-loss recovery. Final accepted full-Go/race gates PASS. |
| M1-N13 | Control isolation | Valid Network/Fabric flows work with Control absent and do not call planner/inference for the tested data-plane paths. | Real HTTP + deterministic Store | `TestActiveNetworkSealedAskReplyWithoutControl` proves Group-scoped HTTP Ask/Reply with `Handler.control == nil`; the disposable scenario passed with a fresh Control-free HTTP Ask/claim/authorize/Reply/claim/authorize/status chain. Its status response is checked for HTTP success, not parsed as `REPLIED`; the main real-HTTP chain checks the `REPLIED` JSON state. Final accepted full-Go/race gates PASS. |

The reviewed production surfaces and security boundaries are summarized in the [M1 code audit](m1-code-audit.md).
Every rejection must be asserted at the public status/error boundary and at the
service/Store transaction boundary where direct callers exist. `skip` is not
pass. This report separates Go tests and Docker HTTP results from Android,
real native Runtime, physical device and public HTTPS evidence.

## Backend acceptance boundary and remaining validation

The M1 backend matrix N01–N13 and its final full-Go/vet/focused-race, contract,
Python and two independent Docker gates passed on the accepted fingerprint.
Historical fixture failures and the interrupted race run above remain failure
records for their own source and are not counted toward this PASS.

Network-only endpoints can use the new Group-independent sealed Network direct
transport. A sealed Group Link has a different contract: each endpoint needs
its own authorized Group mapped to the same Network and bilateral Owner grants;
the endpoints need not share a Group. The selected Link pre-injection fence is
tested, but there is no new real-native end-to-end cross-Group Link run. This is
separate from Network direct messaging and does not block its Network-only
delivery path.

The migration inventory/dry-run and restore tests use synthetic disposable
SQLite files. They do not establish production StateDir recovery after actual
power loss. The HTTP route test is a finite inventory of current route
families, mapped to their shared Guards; it does not claim exhaustive testing
of future endpoints or every request-field permutation. A NetworkAdmin session
is limited by its named Network grants; the local database operator CLI is a
separate host capability. Control-free tests prove only the enumerated
Network/Fabric data-plane paths, not Control-dependent routes.

Android, real native Runtime, physical dual-Node, public HTTPS, and the future
same-host native TUI adapter remain outside this backend M1 gate and are
reported separately as **NOT_RUN**. M2–M5 are later product scope.

## Disposable Docker HTTP gate

The existing `scripts/test-client-hub-interop.sh` has an opt-in
`--suite network-m1`, leaving the default Client/Recovery selector untouched.
The suite creates a unique temporary Hub container, temporary SQLite StateDir,
synthetic opaque credentials and a separate test container; it runs only
`TestNetworkM1DockerHub` against the published real TCP port. The one-way
activation test gets its own Hub and cannot mutate the default Client
smoke/recovery fixture. The runner records the separate suite name, source
revision, dirty flag, source fingerprint, contract revision, Hub/test image
IDs/digests, test exit and cleanup status. It writes only structured lifecycle
events; any raw failure log stays in a private temporary diagnostic file and is
never promoted into evidence.

The scenario uses no model, provider API, Android APK, production key, resident
Hub, or shared StateDir. It creates synthetic owner-bound Node credentials and
legacy Groups in the disposable Hub. It uses the compiled `/out/cicada`
operator CLI for Network creation, mapping prepare/approval, migration dry-run,
invitations and one-way activation; it does not construct Network rows through
Store APIs. Join, directory, resolve, revocation, Owner key consent, sealed
direct SEND/ASK/REPLY, claim/authorize and receipts use real HTTP against the
owned Hub. The protocol fixture uses one synthetic Node credential with two
synthetic native Session IDs; it is a Hub protocol test, not proof of two
physical Nodes or real native Runtime. It preserves a same-session Endpoint
and Group binding, includes a pending mapping preservation check, and removes
only resources carrying the run's unique prefix. Android consent UX, physical
dual-Node, public HTTPS, and native wake remain separate evidence.

Command used:

```bash
scripts/test-client-hub-interop.sh --suite network-m1
```

The earlier bounded run is recorded under
`.cicada-data/network-m1-final-b0081a0/`; the interim run is under
`.cicada-data/m1-final-20260928/`, and the current final acceptance run writes
under `.cicada-data/m1-final-20260928/accepted/`. Each suite uses a separate
disposable Hub and state. Docker missing/unavailable or a
skipped test remains `BLOCKED`/`SKIPPED`, never `PASS`. The M1 Docker result
does not establish real native Runtime, Android, physical dual-Node, or public
HTTPS behavior; all four remain **NOT_RUN** for this backend M1 gate.
