# Native pair A1: wire/crypto checkpoint

Date: 2026-10-17. Contract: `native-pair-v1`; phase: `WIRE_ONLY`.
Base: `0fbd09105e73e1e6e2488dafcb0b7b14e8264faa` plus the recorded dirty
inputs. No Hub/Store/Node route or permission is enabled by this checkpoint.
Client wire remains 1; catalog remains `client-hub-v1.6.5`, 55 operations;
N2/N3 profiles, purposes and deadlines remain unchanged.

## Checked source and results

Evidence root outside Git: `~/Cicada/.local/evidence/n3-hub/`.
Go image: `sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`.
Tests used network-disabled, read-only source/root, synthetic keys, separate
writable build cache and immutable module cache. Input manifests were unchanged
during each run. This record and final prose/checker clarifications were added
after tests; compiled Go/JSON inputs were not changed afterward.

| Check | Result | Evidence |
| --- | --- | --- |
| Native pair targeted crypto/wire/targets | 42 pass / 0 fail / 0 skip | `runtime/native-pair-a1-envelope-and-target-*.json`; source manifest SHA `a719bd24b1f8bf06123e67dc44a5bceaa1e4053e9467517668420fe40ee6aac8` |
| Entire `e2ee`, `clientwire`, `hubaccountwire` packages | 300 pass / 0 fail / 1 skip | `runtime/native-pair-a1-normal-*.json`; source manifest SHA `adb0d0411109f8b86d455b84ae60166ded408f6cd9761f0ba376a86843fe2e8d` |
| Same three packages with `-race` | 300 pass / 0 fail / 1 skip | `runtime/native-pair-a1-race-*.json`; source manifest SHA `d9a368c243f0298a3bdeac5e7a724052079122b52122ee7058de426df9c62307` |
| `go vet` for those packages plus `hubauth`, `store`, `server` | exit 0 | Same unchanged compiled inputs and pinned offline image |
| New native-pair and existing N2/N3/catalog metadata checks | PASS | `scripts/native-pair-contract.py`, `owner-activation-contract.py`, `app-node-authority-contract.py`, `client-contract.py` |
| Disposable Docker client Hub interop | PASS; owned resources removed | `native-pair-a1-client-interop/result.json`; SHA `e4350a1efefe33895f27ab11681f33f437d4c539820d36d5909230975c7ca128` |

The one skip is `TestExternalOwnerOpenSSLRealSignatureInterop`: no independently
verified OpenSSL 3.5.9 executable was supplied. It is not an interop pass.
The Docker gate uses real TCP and existing Go clients, including Owner bootstrap,
recovery and headless operator. Its source fingerprint is
`96559aa8317e799992ff9c4f00adaf936aca2b41c0a73f1615153bbc03e85e5e`;
Hub image `sha256:344783accfa666ab3285ddd10bb3990800ca3823d772c609d876a48fcb6ab22a`.
It does not exercise a native-pair server, which is absent in A1.

## Crypto and size boundaries

Real ML-DSA-65 signatures cover six separate purposes. Tests reject wrong
purpose/Owner/key/epoch/SID, altered bytes/signature, duplicate/unknown/noncanonical
JSON, expanded policy, invalid projected manifest, swapped/omitted evidence,
expired administration as fresh consent and exclusive peer expiry. Historical
proof verification remains distinct from current authority. Packet tests cover
same original/digest recovery, unknown PairID prepare recovery with a replacement
login, typed permanent no-effect fencing and rejection of bare ABSENT.

Maximal accepted fixture sizes in bytes: bootstrap proof 30237, slot proofs
29320 each, Group proofs 5021 each, Plan 99182, evidence 231263, prepare request
92440, Plan response 193401, synthetic carrier plus base64-encoded 32 KiB metadata
275003. An opaque maximum 262144-byte nested receipt seal/open produces a
638714-byte reconcile packet. That opaque fixture proves framing capacity only;
a real nested receipt still needs original-route authentication and target checks.
Exact carrier limit succeeds and limit+1 fails. Body/receipt/inner/outer limits
reject excess; old/unknown operations cannot borrow the enlarged decoder or
crypto entry, and requests cannot borrow the larger response bound.

Earlier `initial`, `size-probe`, `max-size-probe`, `envelope-size-probe` and
`targeted` runs contain real failures. The original 192 KiB evidence/128 KiB
receipt proposal did not fit real PQ data. Their logs remain failed design
evidence; later successful runs use the reviewed explicit new-operation limits.
The metadata wrapper is not the actual peer-key/delivery DTO; A2 must measure
those full carriers independently.

## Reviewed A2 prerequisites and remaining scope

Root approved sealing A1 as inactive wire/crypto while requiring these corrections
before App depends on the first bootstrap/revoke flow:

1. Current N3 App data has no Store-only credential commitment or Node-Control
   binding version; it cannot construct the initial full NodeTupleDigest. Only
   bootstrap-preview will require those three fields all empty/zero. Prepare
   checks current Store authority and returns the complete tuple; App checks the
   original known Actor/Node, pinned Hub, structure and computed tuple digest,
   then Owner explicitly signs full bootstrap-commit. App cannot independently
   derive the credential commitment without the Node's raw credential. Node
   must verify it against its actual local credential before reserved Join.
2. Plan target comparison must reuse the full stable bootstrap/plan Scope
   comparison already used by peer evidence, excluding only account-session ID
   and expiry. Comparing only NodeTupleDigest at that last boundary is incomplete.
3. Add `NativePairRevokeTargetDigest(scope, pairID, expectedRevision)` with domain
   `cicada/native-pair/revoke-target/v1` plus NUL, canonical field order `scope`,
   `pair_id`, `expected_revision`. No dynamic budget/observation/heartbeat fields.
   App must not guess an empty or arbitrary target digest before this helper.

A2 still owns production transactions, replay/fence retention, atomic zero Join
and activation, current Guards, HTTP/Node handlers, mandatory Node policy marker,
actual authorization carriers and durable business/native delivery budgets.
No A1 test claims those features are implemented. Existing identity, keys,
epochs and native SIDs must remain retained throughout that work.

Android, Windows native App, physical devices, real native Runtime conversation,
automatic wake and public HTTPS: **NOT RUN** here. No model call, production key,
resident deployment replacement, push or merge was performed.

## A2 Store/HTTP preparation (available false)

Date: 2026-10-17. Base: `96c07d83528dc3a1429972d015ec3726156f2ef3`
plus the separately hashed dirty inputs below. Contract `native-pair-v1`, phase
`SERVER_PREPARATION`, schema 64. This is a Hub preparation checkpoint, not the
complete pair chain or a user-ready conversation. Public `available=false`.

The [contract](hub-native-pair-contract.md) and exact Go DTOs remain authoritative.
Existing Client wire/catalog, N2/N3 purposes, identities and epochs are unchanged.
Only the explicit Hub Nodes composition routes the eight new App operations.
Bootstrap prepare/complete, status, revoke and reconcile execute the guarded
preparation flow; consent/slot-reject currently return a permanent no-effect
fence. There is no Node pair RPC implementation or peer permission activation.

### Implemented boundary

The Store acquires its SQLite writer before sampling the trusted clock. Fresh
mutations reuse completed N2 device/Root and permanent N3 Node confirmation
provenance, a current account session, the original Owner public key, exact
credential/binding/key/epoch tuple and a purpose-specific Owner proof. Login or
an App-device PQ signature alone cannot replace that proof or adopt another
Owner/Node. Store converts the existing 32-byte credential digest to lowercase
hex without hashing it again.

Prepare reserves one immutable challenge and fixed deadlines. Complete atomically
creates one private ACTIVE Network, mapped ACTIVE Group and two empty slots;
it does not invent native SIDs, Endpoint candidates or peer grants. Revoke is
covered for PREPARED and WAITING_JOIN, preserving rows/keys/epochs. No ACTIVE-pair
revocation or native delivery acceptance is claimed at this stage.

Effects, consumed nonce/CAS and exact sealed receipt commit in one transaction.
A sealing failure rolls back the domain effects. A failure after random ID
allocation but before admission publishes no PairID in its bootstrap fence or
outer recovery metadata. Two independent Store connections competing to complete
produce one domain effect and one permanent rejection fence. A held second
SQLite writer proves time is sampled after writer acquisition; an expired
preview receives a fence and reserves no pair.

Exact history remains recoverable after reopen, login expiry or Root revocation.
Reconcile either returns the exact committed receipt or permanently fences the
unadmitted original; it never executes old consent. Known-pair fences bind the
verified Owner-proof PairID, exact operation/ID/packet digest and no-effect
outcome. Late originals return the same fence. Primary proof/nonce/slot/plan,
message-budget and Node-receipt tables are retained and included in restore
coverage; bounded read/rate caches are separate. Restore tests reject ten kinds
of history, deadline, generation, proof or budget rollback.

Status only advertises current administration when its query session ID and
account/device/Client epochs match the actual token-derived actor. Device-only
history and mismatched coordinates remain diagnostic. A cached exact read is
historical; after the five-minute cache, an aged original becomes READ_EXPIRED
with no slot pointers or administration. It cannot settle a mutation.

Network/Group row builders were extracted behind existing validated callers.
Their legacy timestamps retain RFC3339 second precision; new signed deadlines
retain RFC3339Nano. No legacy validator or frozen protocol is relaxed.

### Source and deterministic evidence

Evidence root: `~/Cicada/.local/evidence/n3-hub/`. Go image:
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`.
Tests use synthetic identities, disposable databases/TCP, read-only source/root,
network-disabled containers, offline immutable module cache and separate writable
Go cache. Every runner manifest records HEAD, all dirty input hashes, image and
arguments; its inputs-unchanged check passed. After both final runs, only the
contract Markdown evidence link and this validation record were updated.
All tested code, test files, JSON and checker inputs remain byte-for-byte
unchanged; the final worktree is not identical to the earlier full manifests.

| Lane under `runtime/` | Result | Source-manifest SHA-256 |
| --- | --- | --- |
| `native-pair-a2-preparation-regressions` | 24 pass / 0 fail / 0 skip | `c1fd180950b1e8a953bdebaefe8682052d183f4f8d253605fd9d47173a6a0d62` |
| `native-pair-a2-preparation-normal-fixed`, complete six packages | 1715 pass / 0 fail / 11 skip | `29d92d127a01de1c5627908b3cb59a9406bddab3528642d99b59fcb7f750eb45` |
| `native-pair-a2-preparation-race`, earlier scoped range | 65 pass / 0 fail / 0 skip | `cb7d1fc11556f3f92f9f2c7ac3f575379331485660e680201de79ee5bb8a8cdd` |
| `native-pair-a2-preparation-final-scope` | 73 pass / 0 fail / 0 skip | `4a820d8d71588e946322af367901ca9bd8189f544a47c8d5bdc9b3f73820e5b6` |
| `native-pair-a2-preparation-final-race` | 73 pass / 0 fail / 0 skip | `cb657131c1339f6b4d87e36ccd095dbe8c5586f72fc013999fc059fad3e43fdb` |

The six complete packages are `e2ee`, `clientwire`, `hubaccountwire`, `hubauth`,
`store`, `server`. The final scoped range reruns all native-pair wire/Store/TCP
cases and affected topology/migration regressions. Relative to the complete
six-package run, only one production Go file changed:
`hub_native_pair_reconcile_v1.go` adds the exact current-status context check.
Two test files add revoke/status coverage and strengthen the concurrency case
with separate Store connections; contract JSON bounds/prose/checker also changed.
The complete earlier run is not relabeled as this final source. Both final
normal/race runs test these final inputs. Final six-package `go vet` exited 0;
N2, N3, native-pair, catalog metadata checks and `git diff --check` passed.

The complete-run skips remain NOT_RUN, not passes:

| Exact test | Reason |
| --- | --- |
| `TestExternalOwnerOpenSSLRealSignatureInterop` | Independent OpenSSL 3.5.9 executable not supplied |
| `TestHubBoundedCapacityDocker` | Isolated bounded-capacity fixture not supplied |
| `TestClientDockerHubSmoke` | Isolated Hub URL/DB/token fixture not supplied in normal lane |
| `TestClientDockerHubHeadlessOperator` | Isolated headless Docker fixture not supplied in normal lane |
| `TestClientDockerHubOwnerBootstrap` | Disposable Docker Hub fixture not supplied in normal lane |
| `TestFabricDirectoryHidesRealUnjoinedNativeThreadHTTP` | No live owned native SID; real Runtime is user-only |
| `TestGroupSpacesM2DockerHub` | Disposable Group Spaces fixture not supplied |
| `TestNetworkM1DockerHub` | Disposable Network M1 fixture not supplied |
| `TestStateBackupRestorePhysicalBindAliases` | Two disposable bind mounts not supplied |
| `TestStateMaintenanceNonrootBindMountAliases` | Two disposable bind mounts not supplied |
| `TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence` | Two disposable bind mounts not supplied |

The separate standard disposable gate below executes its three skipped client
cases, but does not cover the other skipped scopes.

Earlier failures are retained: the initial 30-pass/2-fail run used an invalid
synthetic LOGGED_OUT session enum, corrected to REVOKED. The first broad run was
stopped after five real regressions (exit 143; 1156 pass/5 fail/8 skip): three
legacy topology timestamp-precision failures, a pre-v61 fixture leaving later
N3 tables while removing migration history, and an expected migration ledger
ending at 63. Production row precision and disposable migration fixtures were
corrected before the successful full run. These failed/interrupted lanes are
not counted as successful acceptance.

### Actual TCP framing and disposable compatibility gate

The two production-HTTP tests create synthetic account/Owner/App and Node through
actual N2 activation/login, Node PQ proof, Owner approval and N3 confirmation;
there is no DB grant injection in that TCP fixture. Store tests separately reuse
the historical synthetic N2 guard fixture and do not establish N2 acceptance.
Development HTTP probes explicitly bypass their own unavailable discovery gate
to test the new handlers. The supported capability decoder rejects false;
this is not supported App setup or full Runtime acceptance.

One successful TCP path performs exactly four pair POSTs: prepare, its exact
retry, complete, reconcile. The original setup has no SID/peer rights. Additional
cases exercise unadmitted original/late replay, malformed/noncanonical/oversize
frames, wrong Origin, missing Owner proof, substituted Owner and wrong Node.
Only byte lengths, elapsed times and HTTP statuses are logged, without tokens,
keys, proof bodies or peer payloads.

Final normal observations (request/response bytes; elapsed microseconds):
prepare 74252/51925, 24888; exact retry 74252/51925, 14897;
complete 75321/17546, 22112; reconcile 196028/58961, 37547.
These are single synthetic loopback samples under concurrent test load, not a
performance guarantee. Handlers add no background poll, inference or native
queue activity; idle resource performance has not been measured. Actual full
peer-key/delivery evidence carrier size still needs the next checkpoint.

`native-pair-a2-preparation-client-interop/result.json`: PASS, exit 0, owned
cleanup CONFIRMED (all three containers, both temporary image tags and scratch
EXACT_ABSENT). Receipt SHA-256:
`abe7748cc694688ee5b81189aad1d0203ee3b6f7d064930e2221649b9b881a30`.
Built dirty base `96c07d8`, source fingerprint
`0387321c88514df2b130140e70e0106a2f443648c46226de24eb4add30806f2c`;
Hub image `sha256:67c88c746deaea48b9e2522394caeb0e6ede035b30c8df0b701288ceabbe5da5`.
This compatibility gate predates the final status guard/test/contract changes;
its exact source remains separately attributed. It tests existing client TCP
transport/Owner bootstrap/recovery/headless behavior, not native-pair delivery.

### Remaining delivery boundary

Node describe/zero Join/detached reconciliation, actual candidate publication,
plan freezing, both atomic consents, reserved-scope bypass Guards, full signed
peer evidence, current delivery Guards and durable peer/native budgets remain
for the next checkpoint. No capability is enabled until that chain closes.
The independent QA readiness gate remains RED; no user package is produced here.
Real same-gpu1 original-Thread conversation belongs only to the user. No agent
created/seeded real SIDs, started a model turn, armed delivery or invoked a real
native queue. Windows/Android native execution, physical device, real Runtime
conversation, unattended wake, strict PQTLS and public HTTPS are NOT RUN.
No production credential, resident deployment, identity rotation, push or merge
was used. No new dependency or coordination infrastructure was added.

## A2 Node producer and CURRENT preparation — 2026-10-18

This checkpoint remains `SERVER_PREPARATION`, with public availability **false**.
It adds authenticated Node describe/zero Join/detached reconciliation, scoped
self/key-publication/heartbeat, reserved-scope legacy rejection, and the shared
CURRENT contract. Dual consent, ACTIVE peer authorization and native conversation
are not completed by this checkpoint.

Execution base: `a451b9bb2bd57acebe248a9ab80310f214c8c040` plus the recorded
dirty Hub inputs, not that commit alone. Root's fast-forward from `209b208`
retained all 40 existing dirty file hashes. Evidence is under
`~/Cicada/.local/evidence/n3-hub/runtime/`. Product freeze
`native-pair-node-checkpoint-product-freeze-20261018T002507Z.json`, SHA-256
`7009a91f0e620faea4ba162ec9fd4b4230b8be3b8f8363dd68822bbba11b3252`, records
2,242 inputs matching the final normal source. Only this append-only validation
record, which selected tests/checks do not read, is excluded.

Node zero Join consumes the exact reserved slot/generation, grants no peer
permissions, preserves the Node's opaque workspace and returns `fabric.JoinResult`.
New effects, sequence, exact sealed receipt and rejection fence commit together.
Additive schema v65 retains v64 history; old opaque Node outcomes remain UNKNOWN
instead of being inferred from slot state. Retained-key recovery supplies
history/fences, not fresh credentials or permission after revocation/expiry.

The confirmed read-cache defect now protects exact fresh receipts for 90 seconds
(including the existing 30-second clock allowance), with capacity backpressure.
Eviction cannot mint a fresh observation for the same still-fresh original.
Far-future status and detached originals fail before publishing read/rate rows.
Five-minute retention, 128 entries and 128 requests/minute remain unchanged;
no permanent poll tombstones are added. Independent original failure receipt:
`48e77fa4a1536d4b94112f2c9de255aee6478a22aaec6a33ff5f19142c452291`.

Ordinary Group heartbeat synchronizes still-live native/access leases in one
writer transaction, retaining IDs, epochs, credentials and lease owner, capped
at the signed peer ceiling. It does not use epoch-rotating `network_renew`.
The time tests use actual accepted zero-permission slots in WAITING_CONSENT,
not SQL-fabricated ACTIVE authority. Both slots accepted before JoinUntil may
retain their existing leases past it; incomplete WAITING_JOIN loses self and
renew permission exactly at JoinUntil even while both original lease deadlines
are later. Rejection/native-write rollback leaves both leases unchanged.
Historical receipt recovery cannot renew a lease or replace a SID/key.

The earlier 30-case source `a35981b103cb3221bac33c744a277ad1425211e6d696dfcedf6d7c22c94797c0`
had an insufficient one-slot cross-deadline positive fixture. The 124-case source
`788d72b7608c7fa47a33e381a8c139aa605eb134fa409e52003c9192657b9184` also predates the
explicit incomplete-Join guard. Those original records remain separate.

Final ordinary command, in the fixed isolated Docker environment recorded in
`native-pair-node-checkpoint-commands.json`:

```text
go test -json ./internal/hubaccountwire ./internal/store ./internal/fabric ./internal/hubnodes ./internal/server -run 'Test.*NativePair|Test.*NativeSelf|TestSameGroupSealed|Test.*SessionBinding.*Lease|TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable|TestHubNodes' -count=1 -timeout=240s
```

`native-pair-node-final-scope-20261018T000731Z-summary.json`: exit 0,
**125 PASS / 0 FAIL / 0 SKIP** including subtests, inputs unchanged; source
manifest `dcf163287d7bdb186f27ea7bacfa8c8c007b4debb86b2b6686d70c3d96060a51`.
This lane used ordinary disk-backed container `/tmp`. The Go toolchain image is
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`, with
network disabled and module inputs read-only. It is not a deployed Hub image.

Both race attempts below remain **FAILED / TIMEOUT**, not acceptance passes:

| Invocation | Completed observations | Terminal result / source manifest |
| --- | --- | --- |
| `native-pair-node-final-race-20261018T001145Z` | 64 PASS, no completed assertion failure | Store timeout at 240s; `604832973c6a039c9f06e755970b244bcbf2133e03c240dd40d5e17273bce8bf` |
| `native-pair-node-local-race-20261018T001854Z` | 30 PASS, no completed assertion failure | Store timeout at 240s; `0cc9f89ab80115c33da1c28299f864e7203e32e1996de65d1473408f157088c0` |

Both inputs remained unchanged and no race report was observed. The first
timeout stack was in synthetic fixture migration/fsync; it does not establish
a unique cause. Isolated `/tmp` tmpfs still showed roughly 18s per independent
Store fixture. The same-source necessary split selections completed with the
same 240s limit (both use isolated `/tmp` tmpfs):

| Successful race invocation | Exact `-run` selector | Result / source manifest |
| --- | --- | --- |
| `native-pair-node-cache-carrier-race-20261018T002556Z` | `TestNativePairNodeRealTCP\|TestHubNativePair(ReadCache\|FutureRead)\|TestNativePair(PeerCurrent\|ActualPeerCarriers)` | exit 0; **20/0/0**; `a0aba6cac5290858b3d9ea20395bdfd014cf560c251ebc88f0acd2f1821cc8d5` |
| `native-pair-node-heartbeat-race-20261018T002556Z` | `TestHubNativePairHeartbeat` | exit 0; **11/0/0**; `9256f7cb80aaf22ae8e627918bc7e873ecd55f800a8d7a7be1bad3885104c766` |

Both record unchanged frozen inputs. The two successful selections do not
change either earlier TIMEOUT into a successful invocation.
Tmpfs does not establish disk-recovery behavior. The normal temporary binary
was not retained; no test was repeated solely to capture its identity. The first
failed race lane's separate binary artifact captures its live `store.test`,
SHA-256 `9275dbdf553f2e660a994987d20d00db6f82dbd3a2bb950bed85ea3cbb06d5e3`.
That identity is not transferred to another invocation.

Actual Store DTOs with real synthetic PQ keys and all five proofs measure
peer-key **323,499**, delivery authorization **326,194**, CURRENT **1,569** bytes,
within unchanged 320 KiB/4 KiB limits. Evidence appears once beside independent
current coordinates; old peer-key receiver SID redaction remains. Actual JSON
expansion produces a **330,685** byte typed authorization that is rejected;
the ASCII fixture is not coverage of every token shape. Before enabling pair
permissions, the production authorization transaction must preflight its exact
complete encoding, rejecting/rolling back oversize without truncation or partial
publication. The typed fixture does not establish that production provider.

Remaining approved production points are dual consent/old GroupKeyGrant
activation, actual-row CURRENT/evidence, Relay budget/cancel/revoke guards, and
bounded peer-route plus App/Node consumer integration. No new message protocol,
general RPC permission, Owner identity or key is introduced. QA's necessary
Store overlay has its own normal/race binaries and source/overlay manifests;
its independent conclusions are not inferred from these producer results.

No agent used real SIDs, models, native queues, providers, resident state or real
credentials. Real gpu1 original-Thread conversation, Windows native execution,
physical devices, Android, public HTTPS and strict PQTLS remain NOT RUN for this
source. Prior full Client interop stays attributed to its original source.

Independent QA completed its necessary host-bound Store overlay gate at
`.local/evidence/native-pair-acceptance/run-20261018T002713Z-UQRXnU/result.json`,
SHA-256 `856cdff87698bb2cb0f246bc65b163e673fa88b8c83e7504b3b89d10bf307a33`:
**SCOPED_PASS**, normal **9/0/0**, race **9/0/0**, compile/version/harness/vet
exit 0. All 2,242 frozen product inputs plus five QA inputs matched before and
after; its actual executed binary hashes also matched. Its container is absent.
This lane used host-bound DB files, not tmpfs. It independently covers cache
capacity/90-second skew protection, close/reopen and historical recovery,
future direct/reconcile rollback, and single/double-slot JoinUntil minus 1ns,
equal and plus 1ns boundaries, atomic lease renewal and terminal candidate
publication rejection. It does not fabricate ACTIVE permission through SQL.
QA's source/overlay/binary evidence is separate from producer evidence. This
focused synthetic result changes neither recorded TIMEOUT into a pass and
does not establish E2E, ACTIVE peer permissions or real native conversation.
