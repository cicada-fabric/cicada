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

## 2026-10-18 A3: atomic consent and bounded existing Relay (candidate)

This section records the next Hub checkpoint on `task/n2-hub`, based on
`f279093d9e8e09d6576ac319f18b9cedf1d670bf` plus the frozen dirty inputs. It
implements the reviewed `native-pair-v1` server path; public availability remains
false. It does not add a protocol, change the 55-operation `client-hub-v1.6.5`
catalog, change N2/N3 purposes/identities/epochs, or authorize real Runtime work.
The earlier 13f and A2 validation remains attributed to its recorded source.

The server now derives a real two-candidate Plan, retains the first consent with
zero effective peer grants, and activates both projected memberships and both
existing Owner Group Endpoint key grants in one writer transaction. The shared
private Grant Tx helper preserves the old signature and nonce checks. Fresh
Owner intent can replace an unpublished Plan; stale candidate/member/Plan,
expired Plan, rejected generation and conflicting intent cannot adopt a changed
tuple. Slot rejection preserves its old SID/history and the other slot, revokes
the rejected attempt, and advances only its reserved generation. Exact sealed
responses/fences and first-consent history survive reopen.

Existing same-Group ASK/Reply, claim and final authorization now require actual
ACTIVE pair tuples. Actual rows supply Current independently of the signed
Plan; Owner evidence, projected old manifests and original access/native epochs
must match. The ordinary peer locator redactions remain. Immutable admitted
message rows enforce four root ASK, four replies, one outstanding ASK, no
child/SEND, and the fixed byte/message/native-submission budgets. An exact
ciphertext retry does not charge again; cancellation/revocation cannot authorize
subsequent injection or a new late reply. Administrative login revocation does
not erase the independently signed peer deadline. Same-identity ACTIVE heartbeat
can renew both live leases beyond JoinUntil without changing either SID/epoch.
The bounded Hub Nodes composition exposes only the existing reviewed peer route
shapes and resolve, with no Control construction/start or inference dependency.

Activation preflights complete actual peer carriers and both ASK/Reply delivery
shapes in both directions. Only unknown future route/attempt/observation fields
use internal size reservations at the unchanged old bounds (maximum JSON
escaping for 256-byte tokens, 64-byte hexadecimal digest, 30-byte observation,
empty causal parent/no Task under the fixed policy). Placeholders are never
published as authorization. Message admission checks its actual route; claim
allocates its real attempt ID and uses the same complete typed carrier builder
as final authorization before committing. Oversize rolls back without truncation,
partial membership/key/message/attempt publication, or a spurious FAILED attempt.

The effective input freeze contains 2,253 repository files:
`runtime/native-pair-a3-producer-final-20261018T010602Z-product-freeze.json`, SHA-256
`e98268ae5ea5068f00e27b0e54536b3d80e176a6c7dc763b4b6f0a4702b408f9`.
Only this append-only validation record is excluded as a non-input; selected Go
packages/checkers do not read it. Product edits stop throughout producer/QA checks.
The offline producer toolchain image remains
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`
(Go 1.27.2), distinct from any built Hub image. Source/root and the pinned module
cache are read-only; the task build cache is separate and locked. Containers use
network isolation and synthetic keys; no shared Hub is a disposable fixture.

| Producer check | Source manifest SHA-256 | Result |
| --- | --- | --- |
| Initial consent/old Grant | `0959a23aa41ab97ee6dcbaf47ee37c9e384318d78220d66e3097f0cff50cc3ec` | 15/0/0, exit 0, inputs unchanged; intermediate dirty 13f source |
| Initial peer/old sealed | `9765eda9fd340b147bb99ead90b151eded75278abba14b664028a05d434dcefe` | 15/0/0, exit 0, inputs unchanged; intermediate dirty 13f source |
| Stale/replaced Plan, concurrent Consent, reject and real TCP | `e2292a68239b2d9172a264a0afbc2971a630c8e54f836d3524eba0227849c727` | 10/0/0, exit 0, inputs unchanged; intermediate dirty 13f source |
| Initial near-size test | `4e593107273559d172a590e3d5f702df845a8c3f6dbe496a7048d4ca5d305f12` | **14 pass / 1 fail**, exit 1, inputs unchanged; dirty f279 source |
| Complete activation/admission/claim/final carrier boundaries | `7f10d075cbfbdc941bf3c24f0fbea8aaa00d9a5a7d49cbeeb693ece16452abd4` | 3/0/0, exit 0, inputs unchanged; intermediate dirty f279 source |
| Final necessary normal group | `87b1fa97574d98d2bd2c6bba974338febc424ec28524fd02b48ba88f63856ccf` | **52/0/0**, exit 0, inputs unchanged; disk-backed disposable container tmp |

The failed near-size test assumed two RFC3339Nano observations always encode to
the same number of bytes: actual size was 327663 rather than the target 327664.
It failed before reaching its negative preflight assertions. It is retained as
FAIL, not a product pass. The corrected fixture leaves margin for observation
length and tests real production writers. In the later three-case run the actual
peer carriers were 327616/327617 bytes (limit 327680), while the complete delivery
reservation/actual delivery did not fit. Real signed activation in an unpublished
transaction establishes the fixture; SQL never fabricates ACTIVE permission.
A synthetic stored Grant-ID fault expands only public carrier metadata. The
public second-consent call then rejects and retains two zero memberships, zero
effective key grants and only the first consent. A separate fault after genuine
activation proves rejected message admission leaves no message, rejected claim
leaves no attempt, and final size rejection retains the original CLAIMED state.

The final normal selector is recorded verbatim in its source manifest and runs
Consent/Peer/reject/carrier boundaries, old same-Group Relay and old Group Grant,
heartbeat, N3 real TCP and new pair TCP tests. The latter uses actual N2/N3 PQ
ceremonies and Node zero-Join, two self candidates, both explicit consents,
resolve, ASK/claim/current final authorization and revoke denial, over disposable
TCP. SIDs and ciphertext content are visibly synthetic and never executed.
All four contract checkers pass; catalog SHA remains
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.

At this record point split necessary producer race groups, the standard disposable
Client interop compatibility gate and independent QA A3 gate are in progress.
Their terminal receipts will be appended separately; no pending check is a pass.
Real native Runtime/Windows execution, original physical Thread conversation,
Android, physical devices, public HTTPS and strict PQTLS remain NOT RUN. Earlier
race TIMEOUTs remain failed and are not reattributed to this source.

Producer race group A (atomic consent/rollback, concurrent Store handles,
first-proof history, slot rejection and full activation carrier preflight)
completed **6/0/0**, exit 0, inputs unchanged:
`runtime/native-pair-a3-consent-race-20261018T010737Z-summary.json`, source SHA
`76e3b3a0ada0444d68241e5408f347907746198415b9538b6085a521d02ab9d0`.
This group used isolated `/tmp` tmpfs, not disk/power-loss recovery. Its actual
running Store binary was read via container `/proc/191/exe`, target
`/tmp/go-build2981932088/b268/store.test`, SHA-256
`f6d6d5ccbf222c06cfacc5e259d9c5262c01c57a8589c3f865188619a2fdb9fb`.
The invocation-specific receipt is `runtime/native-pair-a3-consent-race-20261018T010737Z-store-binary-identity.json`.
The earlier host `/proc` capture attempt captured no binary; this later in-container
live-process capture is the actual measurement. Neither hash is transferred to
other normal/race invocations.

The locally started standard Client interop gate was **interrupted on Root's
coordination instruction**, exit 143; its terminal result is **FAIL**, not PASS.
Root owns the single standard interop run after Hub and Node/MCP integration on
the final combined frozen source. Interrupted receipt:
`native-pair-a3-client-interop-20261018T0108Z/result.json`, SHA-256
`5989b9ac1601233326d2eba12d9dfe7445ffc98c4658652a6ce93cd7dda87218`.
Its Hub image was `sha256:44fa21a1206c77f51e8cc500e90b41042f7a580042e839ef6ca4639128d2eaa7`,
source fingerprint `932aa4de5a4a1f7ab5a7dde49ea04bff4984eacf38c7ae32f14075dd27c18f95`,
dirty f279 source. That build/image is not a gate pass. Cleanup is **CONFIRMED**:
`native-pair-a3-client-interop-20261018T0108Z/cleanup.json`, SHA-256
`44aae12eae52cdb067b48c329127fd2921bbe7b8c066ad87b15ead6d84012a19`.
All three owned containers, two fresh image references and private scratch are
verified EXACT_ABSENT. No resident deployment was replaced or removed; private
failure diagnostics are retained locally and are not upload evidence.

Producer race group B (candidate/member mutation, exclusive Plan expiry and
replaced-Plan fencing) completed **5/0/0**, exit 0, inputs unchanged:
`runtime/native-pair-a3-stale-race-20261018T011123Z-summary.json`, source SHA
`e17893da2a19bad2190d55694d84bd16891ff58183771bb1068a9468fdf3962e`.
It uses the same frozen product inputs and isolated tmpfs. No actual binary hash
was captured for this invocation; none is borrowed from group A or a failed run.

Producer race group C (Peer guards, cancellation, actual carrier rollback,
ACTIVE heartbeat and disposable real TCP) completed **6/0/0**, exit 0, inputs
unchanged: `runtime/native-pair-a3-peer-race-20261018T011329Z-summary.json`, source
SHA `e420e37722742b83c3a2f9443161616575af1300eb0681ca49d02348be01c3fd`.
Like A/B it uses tmpfs and does not establish disk/power-loss recovery. No binary
hash was captured for this invocation or borrowed from another one.

Independent QA core gate on the original e982 freeze completed **SCOPED_PASS**,
normal **4/0/0**, race **4/0/0**, six lanes exit 0, product 2253 plus eight QA
inputs unchanged and actual executed binaries unchanged; its container is absent.
Receipt: `.local/evidence/native-pair-acceptance/run-20261018T011118Z-XANwqI/result.json`,
SHA-256 `b5cb3980e7996723f73072770256413a6f666df66ab80c64c2beb97398712d95`.
It proves the real dual consent/old Grant atomic core and retained response
history in its documented scope, not public availability or native Runtime.

Root identified an additional HTTP byte boundary after that source was frozen:
`json.Marshal` preflight measured the object, while the existing `writeJSON`
Encoder adds one LF byte. A Marshal object exactly at the ceiling could therefore
produce an oversized HTTP body for the Node consumer. All old 52 normal, 6+5+6
race and QA 4+4 results above remain at their original sources. They are not
relabelled as validation of the subsequent HTTP correction. Public availability
remains false. The bounded follow-up changes only pair-specific HTTP rendering;
legacy Group rendering, wire DTOs and the 320 KiB ceiling stay unchanged.

## 2026-10-18 A3 HTTP byte correction (next exact source)

The Pair-specific peer-key and final-authorization HTTP handlers now call
`writeSameGroupSealedV1Carrier` with their actual typed Store result. For a pair,
it writes exactly the already measured `json.Marshal` bytes, without an extra
Encoder LF. It rejects an incomplete or oversized Pair carrier before writing
its success status/body. Legacy carriers with both Pair fields absent still use
the unchanged `writeJSON` Encoder including LF. Store/wire DTOs, transaction
preflight, the old Group writer and the 320 KiB ceiling are unchanged. Thus the
existing activation/admission/claim/final preflight now measures the actual Pair
HTTP body; the boundary no longer differs by a newline.

New freeze: 2,255 product inputs, only this validation record excluded as a
non-input: `runtime/native-pair-a3-http-final-20261018T011834Z-product-freeze.json`,
SHA-256 `1ec7c8fafb2728e554900bb9c02b7e48e9214d033dc5a3cfbcf72de2f0bf5cb0`.
The necessary incremental normal selector (complete typed HTTP rendering,
real Pair TCP, real activation peer-fit/delivery-overflow and actual writer
rollback) completed **6/0/0**, exit 0, inputs unchanged:
`runtime/native-pair-a3-http-final-20261018T011834Z-summary.json`, source SHA
`db08af393a5d0a6134766d739f5a9c8bd2aea544d4799e25a13a2834159cab80`.
It uses the same pinned offline toolchain with disk-backed disposable container
tmp. The old 52 normal/17 race results above remain on their own frozen inputs;
they are not relabelled as this new source's test counts.

The real N2/N3/dual-consent TCP ceremony supplies actual signed peer-key and
final-authorization snapshots. Separate private HTTP fixtures exercise the
production typed writer with those snapshots: both complete actual TCP bodies
at **327680 bytes are accepted byte-for-byte**, and **327681 bytes are rejected
before any partial success carrier**. The public Grant-ID padding is a visibly
synthetic rendering fault fixture; it does not create Store authority or mutate
an Owner signature. These HTTP fixture requests do not execute a native SID.
Legacy Encoder LF and missing-one-Pair-field rejection are checked separately.
The existing genuine production-transaction activation/zero-grant negative and
actual admission/claim/final rollback cases run in this same increment.

The matching incremental producer race and independent QA HTTP gate remain
pending at this record point. Caps remain false; integrated standard Client
interop is Root's later combined-source gate, and real Runtime, physical devices,
Windows native/Android, public HTTPS and strict PQTLS remain NOT RUN here.

The matching necessary HTTP increment race completed **6/0/0**, exit 0, inputs
unchanged: `runtime/native-pair-a3-http-race-20261018T012009Z-summary.json`, source
SHA `6c8ff467e6e74cc71311780f85eeab4ce03a278e3d51e6ed81dad3acf406cb54`.
All 2,255 frozen product hashes still match. This race uses isolated tmpfs and
has no separately captured binary hash; it is not disk/power-loss evidence and
borrows no binary identity from another invocation. The independent QA HTTP
increment is still pending; no pending gate is a pass.

Independent QA HTTP increment completed **SCOPED_PASS**, normal **1/0/0**, race
**1/0/0**, exit 0: `.local/evidence/native-pair-acceptance/run-20261018T012227Z-4y3LNS/result.json`,
SHA-256 `6b4419ee320713e8ed1c01a123f36629d5a64fd61ad4cf8f8c14628b327f2353`.
Its 2,255 approved product inputs plus QA inputs total 2,267; before/after source
hash is `a0408bda12992236d60d1e5979df1d9455afde8c3d85675014ae17ff5ed2283c`.
Actual executed binary hashes match before/after and its container is absent.
The scope is the independent real-TCP typed HTTP byte boundary, including both
exact-limit/+1 carriers, missing evidence/current and legacy Encoder behavior;
no Runtime/model/daemon or deployment is touched. The separate independent
actual-transaction overflow gate is still pending on the same frozen product.

Independent QA actual-transaction size increment first failed to compile its
own new Store overlay (missing OwnerID argument, wrong private error name and
state type): **FAIL, zero assertions**, receipt
`.local/evidence/native-pair-acceptance/run-20261018T012416Z-qDszCh/result.json`, SHA
`dfe38319218db9be7622ff5692dfeb65ffdb130b00dce34ae40a55f55fdfc7ee`.
Compile-tests/compile-race/vet exit 1, harness/race not executed (125), version
exit 0. Its original overlay, logs and source are retained. That failed run's
source before/after was `a0408bda12992236d60d1e5979df1d9455afde8c3d85675014ae17ff5ed2283c`;
no assertion or executed-binary pass is inferred from it.

After changing only its own overlay, QA's new independent Store increment
completed **SCOPED_PASS**, normal **1/0/0**, race **1/0/0**, all six lanes exit 0:
`.local/evidence/native-pair-acceptance/run-20261018T012506Z-ISf9cq/result.json`, SHA
`28b034d7fc1e94065c4a5bbf6d8501f361b7c2ff5c4bdaec34bba36dded6f19e`.
Its 2,267 product/QA inputs match before/after; its distinct source hash is
`15b076abd00e050f02b9630dde02fecd15fe0600591e4b5e776b9f216e5163b0`.
Executed binary hashes match before/after, the owned container is absent, and
SQLite resides on host-bound `/state/tmp`, not tmpfs. This does not establish
power-loss recovery. The fixture uses real production Tx/PQ consent and keys,
without SQL-made ACTIVE permissions or a Node RPC/TCP claim. It measures actual
peer **327648** and full delivery reservation **335783** bytes: the original
second consent rejects, both memberships stay zero, no effective key grant
publishes, the exact typed size cause is verified and its original rejection
fence remains permanent. The normal/race scope is
`SYNTHETIC_STORE_PQ_ORIGINAL_CONSENT_ACTIVATION_SIZE_ATOMICITY_NOT_TCP_OR_RUNTIME`.

All producer/independent checks are terminal. The 2,255 final product hashes
still match the approved 1ec7 HTTP freeze; only this excluded record was appended.
Final-source necessary validation is producer normal **6/0/0** and race **6/0/0**,
independent HTTP **1+1**, and independent transaction-size **1+1**. The original
A3 core normal **52**, race **6+5+6** and QA **4+4** remain on the preceding e982
source. No tests are repeated or counts transferred merely for document/Git
metadata changes. This checkpoint remains server preparation with public
capabilities false. App/Node/MCP integration, Root's unified standard Client
interop, real original-SID native Runtime/Windows, physical devices/Android,
public HTTPS and strict PQTLS remain separate pending/NOT RUN gates. Nothing in
these synthetic scoped results authorizes model/queue/provider use, deployment,
real key rotation or public availability.
