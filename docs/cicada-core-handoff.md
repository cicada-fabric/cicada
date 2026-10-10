# CICADA Client integration handoff

## Joint7: Parent v4 snapshot compatibility

Root closed joint6 with Parent exit 1 at `FINISH_SNAPSHOT_BYTES`. The binding
guard passed and Android capture/recovery ran, but no complete FINISH
acknowledgement or final Client result was produced. The full case remains
**UNKNOWN**, the batch remains **FAIL**, and the other seven cases remain
**NOT_RUN**. Root's hash-only closeout is
`joint-preparation/ROOT-JOINT6-CLOSEOUT.NONAUTH.json`; owned Hub/Android and
scratch cleanup were confirmed, with Core source and six residents unchanged.
Joint3's original cause remains **UNKNOWN**; no later result is attributed to it.

Root's immutable Parent v4 uses the same canonical serializer for the public
snapshot and private carrier input. Exact raw-byte and typed-hash checks remain
enabled. Client pins the actual v4 Parent, adapter, interface, freeze, focused
test and QA receipt. The closed seven-entry absolute-path freeze map and
two-entry `operator_sources` map are validated against the v4 delivery; the
reconcile binary and compiler receipt retain independent verification.

Fresh batch: `v164-e2a1908-joint7-20261010`. One scoped network-none Docker run
passed 25 Client host tests (exit 0), including v4 source/runner acceptance,
old source and URL rejection, closed freeze/QA negatives and the eight-case
plan guard. Root's separate snapshot QA records three tests and two subtests;
Client only verifies its immutable receipt, without executing Core code.

The clean checkpoint, twelve driver hashes, 604 tracked inputs, actual test
command/exit code and Root-only templates are sealed in
`/gpu1-share/data/cicada-client/v164-e2a1908-joint7-preparation-20261010/CLIENT-JOINT7-DELIVERY.NONAUTH.json`.
The config selects exactly `joint-parent-v4.py` and
`joint-adapter-parent-ready-v4.py`. APKs, helper/Hub pins, loop business logic,
original82 TARGET-first/SOURCE-last, 25/11 callback fields and budgets are
unchanged. SOURCE remains active through FINISH. Joint7 Android cases,
physical Android and public HTTPS are **NOT_RUN**. No GO, approval or expiry
is created here; Root owns the sole fresh online execution and cleanup.

## Joint6: three independent binding domains

Root and Client independently audited the fixed e2a implementation. Network
access sessions (`network_access_sessions_v2`), direct-native registrations
(`network_direct_native_bindings_v2`) and Fabric SessionBindings used by
Group Join (`session_bindings`) have independent IDs and epoch domains.
The pinned helper exports the first two in `protocol_layers` and uses the
third for the Group manifest, binding rows and key candidates. Six relevant
Go source files matched the immutable e2a commit byte-for-byte; no Core
production bug was established.

The fixture validator now checks direct-native safe ID and positive integer
epoch independently, while keeping exposed Endpoint/Node, `NOT_RUN`, member
roles and empty grants checks. Group manifest, bindings and candidates still
join exact SessionBinding ID/epoch; candidate bool epochs are rejected.
The direct object's Principal/native-session coordinates are not projected,
so Client does not claim to reverify them. Live Android manifest/attestation
and Owner-signing checks remain separate and unchanged.

Fresh batch: `v164-e2a1908-joint6-20261010`. Three focused regressions were
RED against joint5 bytes (exit 1); 39 scoped network-none Docker tests passed
after correction (exit 0). The synthetic public fixtures intentionally use
three different IDs and three different epochs. Negative tests retain Group
binding/manifest/candidate and Endpoint/Node rejection, as well as empty or
illegal direct-native ID and zero/bool epoch rejection. Host predicate names
are now `DIRECT_NATIVE_ID_VALID` and `DIRECT_NATIVE_EPOCH_VALID`; values remain
closed booleans only, with no payload, private keys or complete error strings.

Clean source, twelve driver pins, 604-input inventory, actual test commands
and fresh Root-only templates are sealed in
`/gpu1-share/data/cicada-client/v164-e2a1908-joint6-preparation-20261010/CLIENT-JOINT6-DELIVERY.NONAUTH.json`.
Parent v3, APKs, original82/25+11, scope and budgets are unchanged. Root alone
supplies the next finite MasterGO and runs the Parent. No Client online
resources are started; joint6 Android cases are **NOT_RUN**. Joint3's cause
remains **UNKNOWN**; joint4/joint5 failed results retain their original bytes.

## Joint5: precise native SessionBinding join correction

**Historical and superseded:** joint5 wrongly equated direct-native
registration with Group SessionBinding. Its synthetic positive fixture made
that same assumption. Joint6 replaces both comparisons and the fixture after
the three-domain audit; the original joint5 test/run receipts remain unchanged.

Joint4 returned `FIXTURE_PROTOCOL_SCOPE / PREPARING`, with case 0
`UNKNOWN` and seven cases `NOT_RUN`. Its original result and Root-reported
cleanup remain historical evidence. The fixed helper exports independent
Network access and native binding IDs: `Joined.BindingID` and
`NativeBinding.ID`. The manifest's `bindings` refer to the latter.
The Client had incorrectly compared Network access with SessionBinding.

The validator now joins `native_binding_id` and integer `native_binding_epoch`
to both the binding row and manifest. Network access keeps independent
safe-ID, positive integer epoch and canonical expiry checks. Endpoint,
Node, `NOT_RUN`, member-only roles and empty grants checks remain intact.
On protocol-scope rejection, seven predefined predicate names may accompany
boolean results only; unknown fields and non-booleans are excluded. These
are host diagnostics, not Parent callback or production API fields.

Fresh batch: `v164-e2a1908-joint5-20261010`. Three focused regressions
were RED against the previous bytes (exit 1); 38 scoped network-none Docker
tests passed after correction (exit 0). Structural synthetic fixtures do
not constitute cryptographic or Android acceptance. Actual argv, input
hashes, clean checkpoint, twelve drivers, 604-input inventory and fresh
templates are sealed in
`/gpu1-share/data/cicada-client/v164-e2a1908-joint5-preparation-20261010/CLIENT-JOINT5-DELIVERY.NONAUTH.json`.

Parent v3, APKs, original82 TARGET-first/SOURCE-last, 25/11 callback fields,
scope and budgets remain unchanged. Root alone supplies a fresh MasterGO
and runs the Parent. Joint5 Android cases are **NOT_RUN**; no Client online
resources are started. Joint3's exact historical predicate stays **UNKNOWN**.

## Joint4: fresh host diagnostic preparation

The fresh batch is `v164-e2a1908-joint4-20261010`. Its consumer rejects
joint3 case IDs. The closed diagnostic codes are explicitly predefined and
tested against `^[A-Z][A-Z0-9_]{0,63}$`; unknown strings, payloads, locals
and complete exception messages remain excluded. The network-none Docker
regression run passed 33 scoped tests, exit 0. A separate fresh-batch RED
run failed against the old joint3 pin as expected; earlier diagnostic RED
receipts keep their original source attribution.

The clean checkpoint, twelve actual driver hashes, complete source inventory,
test argv/exit codes and Root-only config/template are sealed under
`/gpu1-share/data/cicada-client/v164-e2a1908-joint4-preparation-20261010/CLIENT-JOINT4-DELIVERY.NONAUTH.json`.
The config contains explicit Root placeholders and is **not a runtime config**.
Root must supply the current Core source baseline and fresh owned evidence
path, then issue a separate finite MasterGO. No approval, expiry or GO is
created here. Parent v3 and APK bytes are unchanged; original82,
TARGET-first/SOURCE-last, 25 callback fields, 11 NONE fields and budgets
remain fixed. Joint3 remains **FAIL / UNKNOWN**; all joint4 Android cases
are **NOT_RUN**. No online resources are started by this delivery.

## Latest: joint3 failure diagnosis and host diagnostic correction

Root's joint3 run used Client `693e939c01a0ddd9cef97d20046862a6cc02b92f`
and terminated with `CLIENT_LOOP_EXIT` after 53.744 seconds. Its immutable
Client result is
`/gpu1-share/data/cicada-client/v164-joint3-root-693e939-308d-20261010/result.redacted.json`,
SHA-256 `1ae5b9a211437d5b43d6b9745f52b30c4ee67a3b69fe02ec2ab90c4fd8a1fc4a`.
Case 0 is `UNKNOWN / PREPARING`; the remaining seven cases are `NOT_RUN`.
The empty child-process list establishes that no Client Android selector ran.
Root reports Core cleanup `CONFIRMED` and Android cleanup `PASS`.

The executed loop's `run()` exception handler, lines 588–589, discarded the
exception message and traceback and retained only `ValueError`. Both host
stderr files are empty. Core cleanup removed the case's READY and nine
references; no retained public CASE_READY response has been located. Static
comparison found no guaranteed producer/consumer mismatch. The exact
historical failing predicate remains **UNKNOWN**, not an inferred contract
or APK failure. Recovering it requires a retained original public witness
or a separately authorized diagnostic execution.

The initial `950e4f5` correction and its seven-test receipt below are retained
as historical diagnostic evidence. Root's follow-up now requires a closed
guard list and known phase: the host catch accepts 109 explicit preparation
codes and twelve fixed file-validator message mappings. Other strings,
including uppercase runtime enums, have no guard code. The existing eight
trusted source locations remain bounded; no message, arguments, locals or
external path are exported.

Before the original semantic READY validation and any selector, the current
loop retains READY's hash/known field types and nine fixed references'
declared shape, scope-match flag, actual mode/size/hash and known JSON field
types in the case record. Unknown field names and all values are omitted.
Only the fixed `REFERENCE_PATHS` are read; supplied paths, symlinks, private
keys, grants and message bodies are not exported. A `REFUSED` observation is
metadata only and does not bypass the original validation. The unchanged
Parent permits the host result up to 4 MiB; these observations are not added
to its bounded socket frames or cryptographic receipts.

Existing failure class, stop-on-failure, cleanup, 82-request order and
signatures remain unchanged. Parent v3, consumer pins, APKs and the original
result are untouched. No GO is created or reused. Static follow-up checked
canonical UTC/RFC3339Nano, enums, integer/base64 encoding and value joins;
no provable producer/consumer mismatch was found. Cleanup absence is not
evidence that the original guard was `FILE_UNAVAILABLE`.

| Offline gate | Result | Actual evidence |
|---|---|---|
| Two new regressions against the executed loop bytes | RED, exit 1 as expected | `red.NONAUTH.json`, SHA-256 `35f1460f660efeb5f741aafa55cee06622483ddf6e40b108a807cea8e8fc1481` |
| Corrected failure and cleanup tests | PASS, 7 tests, exit 0 | `green.NONAUTH.json`, SHA-256 `60a19869b9fecce2859057da46c4715eaa2e338f5a9731e8a3f51f8d8145cdb1` |
| Exact original joint3 guard | UNKNOWN | Original exception detail and READY references were not retained |
| Android recovery, Native Worker, physical Android, public HTTPS | NOT_RUN | No online resources or model calls in this correction |

Evidence root:
`/gpu1-share/data/cicada-client/joint3-valueerror-diagnostic-20261010`.
Both receipts record the complete bounded, network-none Docker argv, source
hashes, tested parent/dirty state, output hashes and actual exit code. The
test's deliberately malformed Hub-ready object yields `HUB_READY_FIELDS`;
this is synthetic regression evidence, **not** the original joint3 guard.
Final checkpoint and source hashes are bound in this root's hash-only
`CLIENT-DIAGNOSTIC-CHECKPOINT.NONAUTH.json`. Earlier coordination records
below retain their original preparation provenance.

### Follow-up public-reference diagnostic verification

Evidence root:
`/gpu1-share/data/cicada-client/joint3-public-reference-diagnostic-20261010`.
The final finite, network-none Docker run passed 13 relevant tests, exit 0,
in 0.049 seconds unittest time; the exact argv, tested parent/dirty state and
Python source hashes are in `green-final.NONAUTH.json`, SHA-256
`94970d5a2c528d0ae32bb9421f6d2121a624940eee7adc0de3b706fc4420507d`.
The earlier RED receipt and intermediate eleven-test GREEN keep their actual
source attribution. The RED integration harness also exposed its synthetic
`cases` directory mode; only that test directory fixture was corrected to
0700. Runtime directory guards were not relaxed.

Regressions verify rejection of `NOT_RUN` as a guard, retention of the
`PREPARING` phase, fixed file-error classification, all nine shape/hash
observations, omission of values/unknown field names, refusal of a foreign
declared path and a symlink, persistence before READY validation raises,
and continued cleanup. They do not run Android or establish the lost joint3
predicate. The final clean checkpoint and twelve-driver map are bound in
this root's `CLIENT-PUBLIC-DIAGNOSTIC-CHECKPOINT.NONAUTH.json`.

If Root needs a future byte-level audit, copy only the public READY plus the
six declared JSON references (`client_setup`, `custody_manifest`,
`fixture_public`, `helper_provenance`, `hub_ready`, `reference_manifest`)
at CASE_READY into owned private evidence, mode 0600, before cleanup. Exclude
DB, operator metadata, owner/endpoint private files and signed proofs/grants.
Client itself stores only shapes/hashes. Such preparation requires separate
Root coordination; this diagnostic checkpoint is not execution approval.

## Current factual correction: withdrawn coordination promises

Root's 2026-10-10 correction withdraws the queued interface `ead771…`,
freeze `573670…` and 26-field promise. They never changed the actual Core
contract. The operative four pins remain Parent `479adcd3…`, adapter
`7dc6eb20…`, interface `8f7bc4e7…` and freeze `6fa1159b…`; the callback
has 25 top-level fields and NONE has 11 exact policy fields. The existing
consumer already verifies these actual bytes and closed joins. No missing
successor artifacts are awaited and no Parent or API change is required.

The authorized engineering note is
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/ROOT-CURRENT-JOINT-COORDINATION-20261010.NONAUTH.md`,
SHA-256 `004f8b93de3647335633d69cb2f488fc9b62e95442a6445d261ce5477996ccd3`.
Its `390bb7d` Client checkout observation is historical; the actual current
clean Client commit, source inventory and twelve drivers are bound in
`/gpu1-share/data/cicada-client/v164-e2a1908-current-facts-closure-20261010/final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
The C25 Core workspace is separate from the immutable clean e2a Hub image.
This note supplies engineering provenance, not an Owner Grant or Master GO.

The historical `390bb7d` section below retains its original failed audit
and declared-versus-observed evidence. Its requests for `ead771…` and
`573670…` are withdrawn historical requests, not current Core action items.
No commit or failed receipt is reset, rewritten or reattributed. This
closure changes only this explanation and the corresponding specification;
the loop, APKs, 82-request profile order, callback and labels stay unchanged.
Existing test receipts retain their actual tested commit and dirty state;
no new preparation test is run. Online remains **HOLD / NOT_RUN**.

## Current coordination: original82 TARGET-first Android initialization

Root's final ruling supersedes the SOURCE-only alternative. Each case
actually exports and enrolls a fresh TARGET Android device/profile, then
exports and enrolls a fresh SOURCE device/profile last. Two
`SIGN_ENROLLMENT` requests per case retain the original82 Parent map.
After SOURCE creation/export, no switch, reactivation or reselection occurs
through original recovery and `FINISH_CASE`. Planned occupancy is sixteen
new profiles plus the default entry, seventeen within the existing limit
of 32; actual profile/generation and cross-case non-reuse checks remain.

Client's host loop and tests are restored byte-exact from `062c764`, retaining
the completed `780a8d` consumer migration (`1526a2c1…`), actual four-artifact
and closed freeze joins, adapter READY runner and strict `127.0.0.1:8787`.
There is no new Go TARGET projection, 74-event ordering or Parent rewrite.
The SOURCE-only guard/tests are removed from the active path; `981853d`, its
164-test receipt and the uncommitted witness audit are preserved as
superseded evidence. No APK/Kotlin, legal TARGET driver, callback or
production API change is made.

The unpublished SOURCE-only checkpoint is retained at local recovery ref
`refs/archive/client-link-recovery-source-only-20261010` (`981853d`). Its
uncommitted witness audit is retained under the restoration evidence root's
`history/` directory. The final ruling is consolidated into that unpublished
stage; no published history or archive ref is pushed.

Actual TARGET Android initialization is distinct from the independent Go
TARGET encrypted readonly operator. External signing remains bound to the
exact Owner and reviewed proof side. A TARGET Android enrollment receipt
does not stand for Go readonly execution or TARGET Link consent. The
25-field callback, KEY2/NONE4 reads, eleven-field NONE policy, separately
attributed pending-candidate evidence and `Android readonly=NOT_RUN` stay
unchanged. Original Source-only mapping gaps do not block this retained
flow. All eight online cases remain `NOT_RUN`; online is **HOLD**.

Root reports a fixed-test-APK DEX audit; Client has read the existing four
Kotlin test methods and legal TARGET stage/selector entries. The forthcoming
Core DEX/source audit receipt will retain its producer attribution. Offline
restoration commands, exits, final Client commit/source pins and unchanged
APK attribution are recorded at
`/gpu1-share/data/cicada-client/v164-e2a1908-final82-restoration-20261010`.
Only Root may issue the separate Master GO or operate owned online resources.
No Core/DB/lifecycle/real-key/model/push/merge action is performed by Client.

| Final restoration gate | Status | Evidence |
|---|---|---|
| Fresh restored Client Docker offline suite | PASS | 158 tests, exit 0, no failures/skips; 6.280 seconds wrapper; tested parent `981853d`, dirty=true |
| Actual consumer four artifacts/auxiliary/APK bytes | PASS for read-only checks | Input export exit 0; no Core or APK execution |
| Original82/twelve-driver/25-field callback compatibility | PASS for exact bytes | Driver map `039c4ee0…` and callback export `510e8f7f…` equal the corrected-consumer preparation |
| Eight online Android cases / actual independent Go reads | NOT_RUN | Online HOLD; Root Master GO absent |
| Android readonly / Native / physical Android / public HTTPS | NOT_RUN | Separate runtime gates |

Actual commands, each exit 0:
`python3 <evidence-root>/run-offline.private.py` and
`python3 <evidence-root>/freeze-inputs.private.py`.
`git diff --check` passed and the exact offline-container label absence
query returned no match. The new test receipt SHA-256 is
`fb5bb603e9b76715c6f29850a38f90a04b2847956d2195cf86eac3ae41017b90`;
the input receipt is
`94f32aa37bd73d6db496cadd0d2452e363486cf580c271c2d95932137d533bda`.
`final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json` binds the final Client
commit, clean state, source inventory, commands/exits and unchanged APKs.
Root must pin the new pre-BOOT Parent template (`b45a03fd…`) and config
before the separate finite Master GO. See the
[full restoration record](client-link-recovery-eight-case-loop.md#final82-restoration-verification).

## Superseded coordination: one Android SOURCE per case

This section and the Go witness audit below preserve the revoked alternative.
They are not requirements or active blockers for the original82 flow above.

Date: 2026-10-10. Root's latest instruction replaces TARGET-first Android
initialization with eight isolated SOURCE profiles, one per case. The first
case activates a new profile from the fresh default; the following seven
cases activate their own new profiles. No switch, reactivation or reselection
is allowed from a case's device export/enrollment through recovery and
`FINISH_CASE`. TARGET is the real separate enrolled/current Go operator,
never a second Android profile or a synthetic Android receipt.

The host preparation now refuses TARGET Android enrollment before any
staging, selector, export or signer request, and correlates the existing
SOURCE device/enrollment exports, unique profiles/public keys and exact
generation progression. Planned registry occupancy is 8 SOURCE + 1 default
= 9, within the unchanged capacity of 32. The APK has no host registry-count
export; this arithmetic is not a measured registry snapshot. No APK, Kotlin,
selector, reset, callback or production API changes are made.

| Gate | Status | Boundary |
|---|---|---|
| `780a8d` actual-source consumer migration | PASS | `062c764`; consumer `1526a2c1…`, exact new four-artifact/runner pins and strict `127.0.0.1:8787`; separate 18-test Docker recheck exit 0 |
| Safe SOURCE-only host guards | PASS for offline checks | 164 Docker unit tests, exit 0; six new test methods, no failures/skips; no Android runtime |
| Actual safe Go TARGET `CASE_READY` mapping | BLOCKED | Frozen Parent `479adcd3…` still requires TARGET Android; public Core proposal is `NOT_IMPLEMENTED, NOT_GO` |
| Eight Android cases / actual independent Go reads | NOT_RUN | No online GO or new runtime plan |
| Android readonly / native Worker / physical Android / public HTTPS | NOT_RUN | Separate runtime gates |

**Required Core delivery:** the safe current Go TARGET public projection and
its exact file/schema/hash/provenance joins, plus the corresponding Parent
and `CASE_READY`/event-order source freeze. Do not expose private operator
metadata or device keys. The accepted original Grant digest is not a later
independent signature verification. Client will consume the delivered
evidence boundary and will not implement proposed fields before delivery.
No additional approval is needed for the eight-profile isolation strategy;
this blocker is a missing producer input, not a request for permission.

The immutable APK pair and Root endorsement remain unchanged. The delivered
Hub is still clean `e2a1908`, image `sha256:532dc1cc…`, Client-Control
v1.6.4 / wire1 / catalog55. Current Core development checkpoints do not
replace it. The 25-field callback, eleven-field NONE policy and exact
KEY2/NONE4 encrypted-read attribution remain unchanged. Online is **HOLD**;
no resources, models, Hub lifecycle, database reads, push or merge are used.
The [SOURCE-only preparation record](client-link-recovery-eight-case-loop.md#source-only-per-case-preparation)
describes the exact limits. All preceding freezes remain historical.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-source-only-guards-20261010`.
The exact command
`python3 <evidence-root>/run-offline.private.py` returned 0 in 6.431 seconds;
source hashes remained unchanged. `python.receipt.redacted.json` SHA-256 is
`4ad830be0810a21226eedb10b749452611cd39f0bb00dd04427865143b5c1ed2`.
Tests ran at parent `062c76426cadabc9e8afe67019241f171588a89c`, dirty=true;
`HOST-SOURCE-ONLY-PREPARATION.NONAUTH.json` binds the final Client commit,
source hashes, unchanged APK attribution and mapping blocker. It is not a
final twelve-driver freeze or runtime-plan endorsement. Exact owned offline
container absence was checked with exit 0 and no match.

### Go TARGET witness requirements audit

The exact Core proposal was read and its SHA-256 verified as
`a01b140c4027b620a63b6a2f2735b1502054483a15716a58d09110d5395adde3`.
It remains `NOT_IMPLEMENTED, NOT_GO`. The existing Android TARGET wrapper
cannot be relabeled as Go evidence. This audit specifies required facts and
joins, not an accepted DTO, new callback or permission to execute.

No additional Target witness field is currently requested beyond the
proposal's 27 fields, provided the new pinned producer implements the
checks below. Endpoint, Group, Network, Principal, Node and SessionBinding
claims already exist in the fixed public fixture and manifest; duplicate
copies would introduce another source to reconcile.

| Required public fact | Existing proposed fields / evidence | Required Client or producer join |
|---|---|---|
| Attribution and fresh case | `schema`, `attribution`, `case_id`, `run_id`, `fixture_public_sha256`, `observed_at` | Exact owned case root, fixed public file hash, current coordination deadline; `EXTERNAL_GO_OPERATOR_ONLY`, never an Android receipt |
| Current TARGET Owner | `owner_id`, `owner_key_id`, `owner_public_identity` | Exact TARGET Owner/key/full public identity from independently pinned READY; producer verifies the current active Owner key |
| Real enrolled device | `device_id`, `device_key_id`, `device_public_identity`, `device_state`, `device_key_version`, `session_epoch` | Current ACTIVE enrollment and exact public key; distinct from SOURCE and other cases; final callback's Owner/device hashes and epoch must match this baseline |
| Actual counter baseline | `last_request_sequence`, `next_response_sequence` | Actual bounded integer counters with explicit representation; producer checks its private operator sequence agrees with authoritative current state; final KEY2/NONE4 reads continue from that baseline without unrelated TARGET operations or guessed counters |
| Current Link and manifest | `hub_id`, `link_id`, `link_version`, `contract_digest`, `manifest_digest`, `source_owner_id`, `target_owner_id` | Exact fixed READY and fresh Android native review scope; current Group/Endpoint/binding associations, proof and lease checks remain required |
| Verified admission provenance | `admission_origin`, `owner_device_grant_sha256`, `owner_device_grant_reverification` | Digest from the actual durable acceptance record; production Store verification is labeled separately from independent verification of original Grant bytes |

`GROUP_JOINED` must be established by the producer before it emits a
witness. The existing helper saves that stage only after actual Group Join
and candidate publication and writes a secret-free
`target-actual-group-join.json` evidence record. The existing reconciliation
source requires `m.Stage == "GROUP_JOINED"` and independently checks the
current Owner/device/public key/counters. The new witness producer must bind
those observations to the exact current TARGET Group/Endpoint/binding in
the existing public fixture. A self-asserted stage or matching IDs alone is
insufficient. The producer must check its private metadata GroupID against
the fixture's TARGET Group and require the actual join receipt's lease to
remain unexpired at witness observation. This does not establish a real
Native Thread: the fixture's native runtime remains `NOT_RUN`. No extra
stage flag is requested if the
producer's pinned verification provides that fact; if it cannot, report the
missing evidence rather than inventing a successful witness.

The current 25-field final callback already carries TARGET Owner/device
hashes, session epoch and each encrypted read's request/response sequences.
Future host checks can correlate these existing values with the baseline;
no callback extension is needed. Today the validator checks the opposite
Owner and a device different from SOURCE, not a pre-delivered exact Go
device baseline. That stronger join is pending the actual DTO and matching
Parent delivery; it is not claimed as implemented.

If Root accepts durable verified-admission provenance, the lack of retained
original Grant bytes must remain explicit. If Root requires independent
original-Grant verification, Core must deliver a real verifier/evidence
boundary first. Client does not recover a signature from a digest, demand
private keys, copy operator metadata, or set a verification flag itself.
SOURCE Android Grant verification remains unchanged in either case.

The current consumer was also checked against the actual four delivered
artifacts with `verify_artifacts()`, exit 0, strictly
`http://127.0.0.1:8787`; its SHA-256 remains `1526a2c1…`. This is a read-only
metadata audit, with no Core execution or additional runtime tests. The
25-field callback, KEY2/NONE4 reads and eleven-field NONE policy remain
byte-identical. Proposed 74-event ordering is not accepted until Root
delivers the corresponding actual Parent freeze. No final runtime plan or
twelve-driver freeze is issued by this audit.

## Successor Client host consumer freeze

This is the preceding `062c764` TARGET-first preparation, retained with its
original evidence. Use the current coordination section above for the latest
initialization boundary.

Date: 2026-10-10. Root's final correction authorizes the actual interface
`8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570`
and freeze
`6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39`.
Parent `479adcd3…`, adapter `7dc6eb20…` and auxiliary `54d8c31b…` remain
byte-identical. The count correction is explanatory: the closed callback
already has 25 top-level fields on both sides. No field, APK, Kotlin,
production protocol, frame, budget or online capability changes.

The existing twelfth driver now verifies all four delivered artifacts and
the fixed auxiliary binary/compile receipt, including the freeze's compiler
receipt hash, regular-file scope and exact clean source/image metadata. No
Core source, binary or test is executed. The producer's 64 preparation tests
and 8-top/27-sub compile tests are not rerun or claimed as Client tests.
Historical `390bb7d` blocked audits and all earlier failures remain intact;
they are superseded by the explicitly authorized correction, not relabeled.

| Gate | Status | Actual evidence |
|---|---|---|
| Fresh Client Docker offline suite | PASS | 158 tests, exit 0, no skips/failures; 5.250 seconds unittest / 6.333 seconds wrapper |
| Actual Core source and auxiliary pins | PASS for read-only metadata | Input export exit 0; no Core execution |
| Endorsed APK pair | PASS for exact bytes | Input export exit 0; no rebuild |
| Offline Client v2 plan | PASS | Exit 0, 0.840 seconds; actual owned offline container absence checked |
| Eight Android cases / actual TARGET Go reconciliation | NOT_RUN | Online HOLD; no Master GO |
| Android readonly / native Worker / physical Android / public HTTPS | NOT_RUN | Separate acceptance gates |

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-successor25-consumer-freeze-20261010`.
Actual commands, each exit `0`:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-successor25-consumer-freeze-20261010/run-offline.private.py
python3 /gpu1-share/data/cicada-client/v164-e2a1908-successor25-consumer-freeze-20261010/freeze-inputs.private.py
python3 /gpu1-share/data/cicada-client/v164-e2a1908-successor25-consumer-freeze-20261010/verify-plan.offline.private.py
```

`final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json` binds the final Client
commit/clean state, tracked input inventory, exact twelve drivers, commands,
callback and template hashes. Tests ran at parent `390bb7d`, dirty=true;
the receipt verifies the final Python bytes. The driver-map SHA-256 is
`039c4ee00f0c8047ae5f878a2149cb6fabdeaed94cad50a819dd315cc158373f`.
Use the original82 pre-BOOT Parent template
`final82-delivery/root-parent-template.private.json`, SHA-256
`d1afd7a8d51a0afe09addf5560b0dd41ca1e8b6c43806d65050d956a9244a12e`.
Do not substitute the offline full Client v2 template for that Parent input.

The Hub remains fixed at clean `e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59`,
Client-Control v1.6.4 / wire1 / catalog55. The existing 82-request flow
initializes TARGET first and SOURCE last; SOURCE stays active through
original recovery and finish. Independent TARGET Go reads require its real
separate enrolled/current session. KEY keeps two direct encrypted reads;
NONE keeps four plus explicitly separate Core readonly candidate evidence.
Its candidate1/noncurrent and HEAD0/current/empty/two-MISSING are distinct.
The exact result labels and 11-field NONE policy are unchanged; neither
present-proof verification nor registration implies bilateral consent.
Android readonly is `NOT_RUN`.

The immutable app/test APK SHA-256 values remain
`3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9` /
`243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae`.
Root-endorsed pins SHA-256 remains
`3dd3f0ec9787fe4dae6e4fde83f05d961ad263884db2a70a394a50b6ccbdf6ef`.
Android origin is `http://127.0.0.1:8787`; the owned STDIO listener is
`127.0.0.1:18944` via exact bounded `adb reverse tcp:8787 tcp:18944`.
There is no emulator route claim for `10.0.2.2`.

**Root action:** review this successor's actual pins, then bind final config
and Parent template into one separate finite Master GO. Parent alone derives
the runtime v2 plan after real owned 0700 BOOT_READY roots; issued/expiry/
approval and 3600/360/240 budgets are copied unchanged. Root owns all keys,
Hub lifecycle, the two 45-second uncertain restarts at indices 2/6,
FrameAdapter/control FD, adb reverse and cleanup. No automatic retry,
profile reselection, fresh packet or proof renewal is authorized. No online
resources were requested; no push or merge was performed. Complete source
pins and launch argv are in the delivery manifest and the
[successor specification](client-link-recovery-eight-case-loop.md#successor-freeze-corrected-25-field-parent-delivery).

## Declared Parent source repin: pending exact producer artifacts

This section retains the historical `390bb7d` blocked delivery. Root's
explicitly corrected successor above is current.

Only test-coordination metadata pins and their regressions changed. Root's
declared interface SHA-256 is
`ead77141679ef0b7a0379c3e2d77b1ac58e4dd1b19277b667c39c47d45c7c966`;
freeze SHA-256 is
`5736703af551999b9e5acbbfc4e2b8d6e2073879219d06276e4a387efd1f1ce4`.
The Parent and adapter retain their previously verified `479adcd3…` and
`7dc6eb20…` bytes. At the exact delivered Core paths, the interface is still
`8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570`
and the freeze is still
`6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39`.
Actual consumer verification rejects this mismatch with `INTERFACE_PIN`;
the observed file guard metadata is valid, but the declared hashes differ.

| Gate | Status | Actual evidence |
|---|---|---|
| Client offline regression suite | PASS | 155 Docker tests, exit 0, 6.481 seconds wrapper; parent `ab40f40`, dirty=true |
| Actual new interface/freeze delivery | BLOCKED | Read-only audit exit 1; both exact paths still contain previous bytes |
| Actual-input runtime plan | NOT_RUN | No source-pin bypass or online authority |
| Eight Android cases / actual TARGET Go reconciliation / Android readonly | NOT_RUN | Online HOLD |
| Native Worker / physical Android / public HTTPS | NOT_RUN | Separate runtime gates |

Required Core action: place the exact two declared artifacts at
`joint-preparation/JOINT-PARENT-INTERFACE.NONAUTH.md` and
`joint-preparation/ADAPTER-PARENT-FREEZE.NONAUTH.json`, with their mutually
consistent five-entry source map and unchanged NOT_GO status, or supply a
corrected immutable delivery. Client must independently rerun the actual
source audit before Root derives a plan or issues the one finite Master GO.
The pinned Parent explicitly emits 25 callback fields, while the delivered
message says 26. The actual field list is preserved; no 26th field is invented.
NONE's eleven fields, mixed DB-candidate provenance and four encrypted reads
are unchanged. KEY retains two reads and `policy=null`; Android readonly is
not attributed to the Go producer.

Current delivery:
`/gpu1-share/data/cicada-client/v164-e2a1908-parent-source-repin-20261010/final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
It binds the final commit/clean state, twelve actual driver hashes, tracked
input inventory, commands/exits and the blocking observed source evidence.
See the [repin record](client-link-recovery-eight-case-loop.md#declared-parent-source-repin-producer-delivery-blocked).
Prior manifests retain their original provenance and are not new-version PASS.
No APK/Kotlin, callback, budget, frame, production protocol, Core, key,
database or deployment is changed; no online action, push or merge.

## Callback result-record checkpoint

This is the preceding `ab40f40` checkpoint; the successor freeze above is current.

Root's blocking report cited historical `888b587`. Full read-only comparison
against the frozen callback proposal, SHA-256
`486b0c2be499a08a50acf272c8f01801a4105ecc7a67ddf2d4cfb2748afbf717`, confirmed
that `04349ac` already enforces the current 25-field receipt and eleven-field
NONE policy. Fresh current-source regression passed four tests / 58 subtests,
exit 0; that receipt is retained separately from the historical 140-test run.

The new host-only change makes validation and final success recording one
testable boundary. Three new tests exercise all eight public synthetic
operation/mode receipts and reject invalid NONE evidence without changing an
`UNKNOWN`/`RECOVERED` record to partial success. The final Docker offline suite
is **PASS**, 154 tests, exit **0**, 6.183 seconds including container startup;
tested parent is `04349ac`, **dirty=true**. It is not Android or real Core
reconciliation acceptance.

NONE retains candidate1/noncurrent, independently attributed readonly
candidate evidence and encrypted HEAD0/empty/current/both-MISSING. Only
response-loss candidate SOURCE is `VERIFIED`; the other three are `MISSING`.
TARGET stays `MISSING`, with no bilateral approval. Origin is
`DB_READONLY_VERIFIED_SIGNED_PROOF` for response-loss and
`DB_READONLY_CONFIRMED_ABSENT` otherwise, with a mandatory separate receipt
SHA-256. NONE results use
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`. KEY retains
`policy=null`, two reads and its separate-session label; NONE retains four
reads. No Client pending-candidate API or database access is introduced.

Latest evidence:
`/gpu1-share/data/cicada-client/v164-e2a1908-callback-record-freeze-20261010/final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
This manifest binds the actual final Client commit/clean state, source
inventory, twelve driver hashes, frozen schema, templates, commands/exits
and unchanged APK pair. The [callback record](client-link-recovery-eight-case-loop.md#callback-result-record-verification)
gives the commands and provenance. Earlier deliveries remain historical.
Root must review the new driver pins before deriving a runtime plan and
issuing a separate finite GO. Current Parent/adapter hashes remain explicitly
pinned; a later changed Core freeze requires a new exact delivery.

All eight Android cases, actual independent TARGET Go reads, Android readonly,
native Worker, physical Android and public HTTPS are **NOT_RUN**. Online
remains **HOLD**. The 82-request TARGET-first/SOURCE-last initialization and
SOURCE continuity are unchanged. No APK/Kotlin, budget, frame, production
protocol, Core, database, credential or key is changed; no push or merge.

## Final Client host preparation: original 82-request flow

This section records the preceding `04349ac` preparation. Its manifest is
retained; use the source-bound callback checkpoint above for the latest pins.

Root's latest delivered instruction explicitly revokes the SOURCE-only
restriction and selects the original frozen flow. The reviewed ruling is
`ROOT-REVIEWED-FINAL-JOINT-RULING.NONAUTH.md`, SHA-256
`dee42017fa44371b24ecb53a6d640861de43a2957c97e264d5b7b962f53bf706`.
Each case enrolls the actual TARGET Android Owner/device first, then creates,
enrolls and activates SOURCE. No profile switch, reactivation or reselection
occurs from SOURCE review/signing through original capture, recovery and
finish. Both actual enrollment receipts and increasing native generations
are checked; these runtime checks remain **NOT_RUN**.

The current loop and pinned Parent agree on 82 requests: boot, ten per case
and close. Sixteen fresh Android profiles plus the initial default fit the
immutable APK's 32-profile limit. The separate real TARGET Go operator is
only the encrypted readonly reconciliation producer; it is not represented
as Android enrollment. Only SOURCE Link consent is tested, so TARGET Android
registration does not imply TARGET proof or bilateral approval. The existing
25-field receipt, eleven NONE policy fields and DB-candidate provenance remain
intact. No Go preparation DTO or new helper/compiler is added.

The consumer independently pins the actual `joint-parent.py`,
`joint-adapter-parent-ready.py`, `JOINT-PARENT-INTERFACE.NONAUTH.md` and
`ADAPTER-PARENT-FREEZE.NONAUTH.json`. Their SHA-256 values, unchanged socket
event fields, commands and complete statuses are in the
[final consumer record](client-link-recovery-eight-case-loop.md#final-consumer-freeze-original-82-request-flow).
Independent read-only review found no order, payload, path, URL, Runner or
reconciliation schema mismatch for the selected flow. This is preparation
evidence, not Android acceptance. Online remains **HOLD**; the Core freeze
retains `online=NOT_GO` and final Client pin matching requires Root review.

The existing plan v2 binds the Root fixture and case index; the existing twelfth
driver verifies source/READY/Runner bytes and fixed control paths. Neither adds
a production operation. No additional helper or callback field is introduced.
Runner must match the current adapter bytes, not Parent. The consumer accepts
only `http://127.0.0.1:8787`, with Root's exact owned bridge/reverse mapping;
stale source pins, `10.0.2.2`, hostname aliases and port drift fail.

Directory protection is implemented and covered by offline negative tests:
the exact plan-bound `/tmp/cicada-joint-e2a-<opaque>/cases/0..7` root, `cases`
parent and selected case must be actual current-user-owned mode-0700 directories
with canonical lexical/real paths and no symlinks. Arbitrary roots, other cases,
non-directories, aliases and public modes are refused. The historical 146-test
directory-only result remains at
`/gpu1-share/data/cicada-client/v164-e2a1908-owned-case-roots-offline-20261010/python.receipt.redacted.json`.
The final Docker offline suite is **PASS**, 151 tests, exit **0**, 6.182 seconds
including container startup; tested parent is `6509a1c`, **dirty=true**. Exact
commands, source/log hashes, public artifact audits and container absence are
under `/gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010`.
`final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json` binds the final Client
commit/tree/dirty/inventory, twelve driver hashes, event export, immutable APK
pair and all actual receipts. This verifies host coordination only.

| Gate | Status | Current evidence or prerequisite |
|---|---|---|
| Final host consumer and directory regressions | PASS | 151 Docker offline tests, exit 0 |
| Four Core artifact pins / Runner and exact URL guards | PASS | Read-only audit and negative tests; no Core code executed |
| Immutable APK pair and Root-endorsed pins | PASS | Exact-byte audit, exit 0; no rebuild |
| Offline plan template | PASS | Schema/source-pin check only, exit 0; no runtime GO |
| Original 82-request source compatibility | PASS for read-only inspection | Exact ten events per case and TARGET-first/SOURCE-last; runtime not executed |
| Actual TARGET Android enrollment and SOURCE continuity | NOT_RUN | No online GO |
| Actual independent TARGET Go reconciliation | NOT_RUN | No online GO; separately attributed from Android |
| Eight Android cases and runtime reconciliation | NOT_RUN | Online HOLD |

Application APK SHA-256:
`3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9`;
test APK:
`243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae`.
Their actual build parent remains `9b56832`, dirty=true, input inventory
`8d26a0029dacc957607293e015bf4e6732af4a73b046556457df2446adfac629`.
Root-endorsed pins remain
`3dd3f0ec9787fe4dae6e4fde83f05d961ad263884db2a70a394a50b6ccbdf6ef`.
The fixed Hub remains clean `e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59`,
image `sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01`,
contract v1.6.4 / wire1 / catalog55. Current Core checkout changes are not this
Hub image. No online GO, new proof, APK build, Hub/DB/key lifecycle action,
push or merge is performed.

The initial SOURCE-only BLOCKED diagnosis and receipts remain historical under
the earlier `v164-e2a1908-final-consumer-freeze-offline-20261010` evidence root,
including its initial `frozen-delivery/` export. The selected frozen delivery
is the new root's **`final82-delivery/`**. This flow requires no Go DTO
and no Parent rewrite. The final delivery includes the existing Core Parent
template schema, which Root materializes into Client plan v2 after actual
`BOOT_READY`. Root must bind the final config/template and unchanged expiry
to one separately issued Master GO. See the exact launch argv and event fields
in the linked specification and final delivery; neither file is a GO.

## Historical Client-only preparation: earlier frozen joint adapter

The [finite-loop specification](client-link-recovery-eight-case-loop.md) now
maps Core's frozen joint interface to the existing private Client Unix socket.
Plan v2 fixes eight SOURCE cases at Core's dynamically delivered
`/tmp/cicada-joint-e2a-<opaque>/cases/0..7`. The inherited Core control FD remains
separate. Root maps the six closed controls `prepare`, `device`, `proof`,
`proxy`, `capture`, `finish` and correlates their stdout acknowledgements.

The Client validates the full 17-field F6 READY and nine public references
against exact e2a provenance. Root normalizes its nested public setup into two
existing Android onboarding wrappers and explicitly assigns fresh device IDs.
Android registers TARGET first, creates SOURCE last, and must show distinct
profile IDs and an increasing native generation. SOURCE stays active through
original-packet recovery; a return switch is not assumed. Root copies exact
public exports into the fixed Core input paths before sending each typed
control. `CAPTURE_VERIFIED` precedes carrier control installation; Core's
`CASE_FINISHED` precedes separately attributed direct reconciliation.

Frozen interface SHA-256:
`618ecef915ad00c6f9fc61d842285989a8e61c59eded900c26aa64cc0e216805`;
freeze manifest:
`eb34be4e43c4ae8e64e5b7fc397e76be0a2ef47b10cd5313918361b4d6eaa107`;
adapter:
`29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4`.
The fixed Hub remains clean
`e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59` / v1.6.4 / wire1 / catalog55,
image `sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01`.
Core checkout `36ebfab` is adapter provenance, not a new Hub source.

The latest Root-authorized test coordination boundary accounts for NONE's
HEAD-only encrypted status on this image. Its nested `policy` receipt requires
`candidate_evidence_origin` and `candidate_evidence_receipt_sha256`. The
response-loss origin is `DB_READONLY_VERIFIED_SIGNED_PROOF`; the three outer
fault cases use `DB_READONLY_CONFIRMED_ABSENT`. Core alone obtains that evidence
from its disposable fixture with `mode=ro`/`query_only` and production
signature/scope/expiry verification of the exact original proof. RootParent
verifies and hashes the actual receipt. Four real encrypted reads remain
required, in that exact order, for manifest/grants/HEAD/preview. NONE records use
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`; KEY keeps `policy=null` and
its direct-session label. Client does not read a database or gain a candidate
query API. Missing provenance must return `BLOCKED`, and Android readonly
remains `NOT_RUN`. Full evidence semantics are in the linked specification.

The final frozen callback proposal was read and independently checked at
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/CALLBACK-FROZEN-PROPOSAL.NONAUTH.md`,
SHA-256 `486b0c2be499a08a50acf272c8f01801a4105ecc7a67ddf2d4cfb2748afbf717`.
It adds no top-level field: its explicit list and the current validator contain
25 fields. The plan retains twelve `DRIVERS` pins: the loop plus eleven
unchanged companion files. The final test-only validator requires fresh NONE
candidate version `1`, noncurrent candidate, encrypted current HEAD `0` and
no bilateral acceptance in any case. KEY's two reads and NONE's four reads
must match the exact frozen order; extra, repeated or reordered reads fail.

Final clarification evidence is frozen separately under
`/gpu1-share/data/cicada-client/v164-e2a1908-final-callback-freeze-offline-20261010`.
Docker offline tests are **PASS**, 141 tests, exit **0**, 6.181 seconds;
tested parent is `608fae2`, **dirty=true**. The plan template is **PASS**,
exit **0**, 0.79 seconds. Proposal/interface hashes, eleven unchanged companion
drivers, APK hashes and offline-container absence are **PASS**, audit exit
**0**. The final frozen delivery binds the callback, eleven companion pins,
twelve full plan pins and actual source/receipt hashes. Exact commands and
evidence paths are in the linked specification; no synthetic receipt establishes
actual Core verification or Android acceptance. All eight Android cases,
real mixed reconciliation and runtime/closure gates remain **NOT_RUN**,
online **HOLD**. No push or merge is performed.

The immutable APK pair is unchanged. No Android application, production
protocol, policy, Grant, sequence or fence is broadened. Evidence for this
alignment is separate from earlier checkpoints under
`/gpu1-share/data/cicada-client/v164-e2a1908-frozen-joint-loop-offline-20261010`.
The historical `608fae2` mixed NONE metadata extension is recorded separately under
`/gpu1-share/data/cicada-client/v164-e2a1908-mixed-none-reconciliation-offline-20261010`.
Its Docker offline verification is **PASS**, 140 tests, exit **0**, 6.184 seconds
including container startup; tested parent is `888b587`, **dirty=true**.
The earlier 6.283-second suite remains attributed to its earlier receipt schema.
Frozen interface verification, eleven unchanged companion drivers, immutable
APK hashes and offline-container absence are **PASS**, audit exit **0**.
The successor offline plan template is **PASS**, exit **0**, 0.84 seconds;
its frozen delivery binds callback metadata and all twelve drivers. Placeholder
paths must be replaced and the actual plan hash bound into the separate Root GO.
Exact commands, source hashes, result statuses and evidence paths are
in the loop specification and private source-bound receipts. The tests use
synthetic public files, socket pairs and harmless child processes; the
eight-case supervisor-order test mocks each case body and does not establish
Android/Core choreography.
Online execution remains **HOLD**: all eight Android cases, encrypted runtime
capabilities, actual TARGET→SOURCE transitions, direct opposite-Owner
reconciliation and emulator closure are **NOT_RUN**. The fixed APK has no
standalone v1.6.4 readonly KEY/NONE selector. If Android readonly reconciliation
is required, it is **BLOCKED**; Core-parent encrypted reads cannot be recorded
as Android execution. Physical Android and public HTTPS remain **NOT_RUN**.

## Historical first finite-loop checkpoint

The [loop specification and offline verification](client-link-recovery-eight-case-loop.md)
adds a host test supervisor for the existing clean e2a1908 preparation below.
It reuses the fixed application/test APK pair and native selectors; no APK or
application feature is changed. Root and the Core parent own the fresh Hub,
keys, external signatures, opaque FrameAdapter/control FD, two uncertain
restarts and Android lifecycle. The loop owns its bounded Client CLI subprocesses.

Final Docker offline verification passed **129 tests**, exit **0**, with source
hashes unchanged. The initial 129-test attempt exited **1** because two journal
assertions ran after test temporary-directory deletion; that failure is retained.
All nine existing driver/module files and both APK digests were independently
checked unchanged. Source pins, commands/exits, logs and the final local Client
commit are bound under
`/gpu1-share/data/cicada-client/v164-e2a1908-recovery-loop-offline-20261010`.
Only one complete host-loop milestone is committed; no push or merge occurs.

The minimal interface is one separately inherited private Unix stream socket
and hash-bound plan/GO files. The specification defines ten parent events and
their closed public-file payloads. Budgets remain **480 + 8×360 + 240 = 3600
seconds**, clipped to remaining absolute deadlines and binding/proof expiry.
Every case captures once and invokes exactly one original recovery. Any failure
stops later cases without automatic retries, new packets or proof renewal.

The fixed APK lacks a standalone v1.6.4 readonly KEY/NONE reconciliation
selector. Root must supply actual encrypted reads from the opposite
participating Owner's independent device/session. The loop checks reviewed
manifest scope, the original proof hash, both side statuses, and the exact NONE
candidate/current-head tuple; execution is explicitly attributed to the Core
parent. This is not Android readonly execution. Root must also return strict
actual full-container-ID command/exit receipts and independently confirmed
absence for its auto-removing network-none emulator.

Online execution is **HOLD**. All eight current-image Android cases, encrypted
runtime capabilities, actual opposite-Owner reconciliation and emulator closure
are **NOT_RUN**. Physical Android, public HTTPS and native Worker remain
**NOT_RUN**. Historical APKs, F38, old failures and Root's separate Core/Native
results retain their original attribution.

## Current coordination: clean e2a1908 recovery preparation

The current Client-only preparation targets frozen clean Core
`e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59`, contract v1.6.4 / wire 1 / catalog 55.
See the [preparation and READY specification](client-link-recovery-e2a1908-preparation.md)
for fixed image/bundle/source values, exact commands and exit codes, independent
artifact verification, source/APK attribution and all ten Android selectors.
Two capture selectors preserve the original pending consent write; eight
recovery selectors verify its mode-specific durable state. The opaque carrier
permits one original write and one byte-identical recovery in the selected
Owner/device/session scope. Root readiness is distinct from Hub authentication.

Only Client preparation is authorized. Encrypted runtime capabilities, all
eight current-image Android fault cases, fresh authoritative reconciliation,
emulator execution, physical Android and public HTTPS remain **NOT_RUN** until
their separate GO and actual execution. No Core file, Hub lifecycle, database,
resident deployment, signer or real key is used. Existing UI, STT, pins, Grant,
sequence allocation, consent fences and closed features are unchanged.

Root must supply the owned bridge/process/helper provenance, direct enrollment
and independent pins, per-case sessions and current external proofs, exact
Core READY/FAULT_READY bytes, and an isolated restart receipt before uncertain
recovery. Reconciliation must use a separate participating session over the
direct Hub path; the faulted session remains fenced. Preserve all historical
failures and APK provenance; no prior PASS transfers to e2a1908.

Final offline results: **PASS**, 111 Python tests; Kotlin 3+4 synthetic groups
and changed Android selector compilation; one x86_64 app/test APK build. All
commands exited `0`. App SHA-256:
`3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9`;
test SHA-256:
`243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae`.
Actual build source is parent HEAD
`9b56832c9701b0ba469d8703fdf61611e0208f98`, **dirty=true**, 598-file input SHA-256
`8d26a0029dacc957607293e015bf4e6732af4a73b046556457df2446adfac629`.
Only documentation changed after that snapshot. The final Client commit and
complete source correlation are bound in
`/gpu1-share/data/cicada-client/v164-e2a1908-recovery-preparation-20261010/commit-delivery.receipt.redacted.json`.
No Android runtime or online acceptance is implied by successful compilation.

## Historical Link recovery offline successor

The [offline recovery report](client-link-recovery-offline-validation.md)
records the repaired original-packet selector and strict SOURCE/TARGET receipt
consumer. Docker verification passed 3 synthetic Kotlin groups, compilation of
the changed Android selector and 6 Python receipt tests; all exits were `0`.
Only test/driver code changed. A cleared native fence may omit `operationId`;
the selector now requires original packet/route/hash, exact persisted counters,
and safe durable state instead. Transport completion does not establish grant
acceptance. Proof/packet bytes and raw IDs remain app-private.

No APK, live Hub, signing or model call was created. Current-image response-loss,
processing, uncertain and unavailable gates remain **NOT_RUN**; the Core-owned
safe Link fault entrypoint is **BLOCKED** pending delivery. Root deferred a fresh
window until the final clean Hub artifacts are ready. The report contains the
exact fixed target, commands/exits, final source-bound receipts and coordination
prompt. The commit is bound by
`/gpu1-share/data/cicada-client/v164-link-recovery-offline-20261004/commit-delivery.receipt.redacted.json`;
F38 remains attributed to its original `caa9e4c` APKs below.

## Historical F38 bounded Link consent acceptance — clean Core `0213538`

The [F38 report](client-hub-v1.6.4-0213538-f38-validation.md) binds tested
Client `caa9e4c725a841a1ce8488fbf339ca554d2939ed` and app/test APKs
`f742532d7782e5a46f5364dc57f1dc6be6faf7903e09194d9db6028356b0a796` /
`e538fbaa0eef457cb15aa885534317efc8b3df7b3b6dd7703c3112ceaa21e258` to clean
Core `0213538b62ccf2533eccf546c80fc848804ea8e0`. The bounded Android 15
emulator run completed all six phases: SOURCE and TARGET enrollment, KEY and
NONE. Both KEY grants were accepted; both final NONE statuses were verified,
current and bilateral. Root's independent outcome index records 13 JUnit tests,
zero failures/skips, six signatures (SOURCE 3, TARGET 3), owned cleanup and
absence checks. Root separately attested one frame and one ACK, exit 0; the
launcher terminal's `CORE_ACK_NOT_SENT` remains a separate earlier observation.

This accepts only the five existing dedicated Link review operations on this
fixed fixture. `LINK_CONSENT_READY=true` and `CANDIDATE_READY=true` do not bypass encrypted
Owner capability, current proof or server Guard checks; generic RPC continues
to reject the five. Ordinary cross-user messages remain closed while
`external_thread_links=false`. Real native Worker acceptance remains
**NOT_RUN**; model calls were zero. Physical Android and public HTTPS remain **NOT_RUN**. The 21 existing capability and
operation-policy offline tests passed, exit 0; receipt SHA-256
`a0a842fe82a0add1ab0eb96e949d3af6cfd130075dfc3eaf6d8b8a7f0db62b6d` is at
`/gpu1-share/data/cicada-client/v164-f38-acceptance-record-20261004/link-capability-check.receipt.redacted.json`.
This documentation checkpoint creates no APK; these results remain bound to
the tested `caa9e4c` source and app/test pair above.

F35, F36 and F37 remain historical failed runs with their original
`OUTCOME_UNKNOWN_PRESERVE_PENDING` outcomes. No prior operation was retried.

### Core review prompt

> Review the F38 validation report and its independent Root outcome index.
> Acceptance applies only to the five dedicated Link consent/review operations
> on clean Core `0213538` and the exact `caa9e4c` APK pair. Preserve encrypted
> Owner capabilities, current proof checks and the server Guard. Keep ordinary
> messaging disabled; real native Worker, physical Android and public HTTPS
> remain NOT_RUN. Do not transfer F38 to later Core or restore changes, or
> reclassify the preserved F35–F37 failed operations.

## Historical F37 outcome and status-label successor — clean Core `0213538`

The [F37 validation report](client-hub-v1.6.4-0213538-f37-validation.md)
binds Client `8e24b14a1f1eb80188e6e11b9f16d53d6afaf91d`, app
`06698b9a6cf47f10592f45e1f0b3fcbf24cead9333e2c9cfeba96c16e68ab487`, test
`624e48439792ffff2e8779409d02ec33c28ab19c11e53bea73e2366ac03507d7`, and the
fixed clean v1.6.4 Core target. The real list refresh observed one `OK_NONEMPTY`
row with the target node present and visible. Review waited for the external
Owner signature; preparation and consent controls reached `REVIEW_READY` and
`CONFIRM_READY`.

The passive submit receipt records callback, UI scope guard, dispatch, native resolution
with `native_ok=true`, `UI_RESPONSE_RETURNED`, and `viewport=VISIBLE`. Native
packet pending remains **UNKNOWN**; these observations do not prove a current
Target grant. At `kt751`, the test searched for the reread label;
`clickLabel` at `kt752` returned. The 30-second
`scrollToText("SOURCE ACCEPTED")` lookup then failed at `kt753` (helper stack
location `scrollToText` line 482). The full bilateral check at `kt754` was not
reached. JUnit failed once in 43.344 seconds. No refresh callback/result or
SOURCE status value was retained, so the unique failure cause is unknown.

The launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**. No
separate Root ACK attestation or independent Core closure was included in the
F37 evidence reviewed here. Preserve the unknown Target outcome; do not retry.
Android teardown and emulator absence checks passed. Native Worker, physical
Android, and public HTTPS remain **NOT_RUN**.

The W successor adds a fixed read-action test ID, a unique visible/enabled/
clickable selector and exactly one click. It requires actual visible status
text, searches backward and forward with at most 12 actions per direction
within 30 seconds, and excludes `EditText` scrolling. Fixed failed or
non-accepted statuses fail the test; the full bilateral assertion remains.
This changes test selectors only, not Hub, native, cryptographic, Guard, or
catalog behavior. Offline checks passed: 17 JavaScript tests, 23 Python tests,
19 pure Kotlin cases (10 viewport, 9 list), TypeScript and ESLint; every exit
code was 0 and all five receipts report unchanged source. At this source
checkpoint, post-commit build and fresh live acceptance are **NOT_RUN**. Immutable receipts under
`/gpu1-share/data/cicada-client/v164-f37-key-status-viewport-20261004` must
bind the exact APK pair and 26 frozen references.

## Historical F36 outcome and list-observation successor — clean Core `0213538`

The [F36 validation report](client-hub-v1.6.4-0213538-f36-validation.md)
binds Client `3254ba12cac22d0f77510999f53e6b6bc2c80aa8`, app SHA-256
`5c346099b9a0f52af2f7ad1e6d453c50ff686b695d6d1706a14bee3b209f1b07`, test
SHA-256 `74b80fd867640407eff177ff7590e5a2df8e0499e5fa535c44c0848f55cbfff1`,
and the fixed clean v1.6.4 Core target. SOURCE and TARGET enrollment,
capabilities, and independent pins passed. SOURCE KEY and policy status remain
partial. Target review, prepare, consent, and request receipt stages are null;
the passive progress receipt has zero events and reports `viewport=UNKNOWN`.

JUnit failed once in 25.151 seconds in `scrollToText` at line 421 at `kt606`. This is
not F35's response-text `NOT_VISIBLE` observation: F36 retained no progress
events or viewport state to identify that condition. The result does not
establish Target callback, native RPC, acceptance, or rejection. Target `NONE`
and bilateral verification are not established.

The launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`** and
records `CORE_ACK_NOT_SENT`. Root separately attests one ACK exit 0. These are
separate observations; the F36 packet reviewed here has no independent Core
closure receipt. Preserve the unknown operation and do not retry it. Android
emulator teardown and the separate emulator absence check passed.

The diagnostic successor under
`/gpu1-share/data/cicada-client/v164-f36-list-observation-20261004` records
fixed list status and error-class enums, bounded observed-node counts,
target-node presence/visibility, current and last-action scroll-container
categories and bounded action attempts. It exports no payload, view tree, IDs
or credentials and invokes no native/Session methods. Missing roots keep the
current list state unknown; historical observations remain separate. The
existing forward-only 20-second wait and all consent checks are unchanged.
Docker verification passed 17 JavaScript tests, 23 Python tests, 15 independent
Kotlin cases, TypeScript and ESLint; all command exit codes were 0. The post-commit
build and fresh live acceptance are **NOT_RUN** at this checkpoint. External
receipts bind the clean commit, one new APK pair and 26 frozen sources.

### Next coordination prompt

```text
Read the F36 validation report and its successor build/source/delivery receipts.
Preserve F36/F35 UNKNOWN operations without retry or replacement. Bind the new
clean Client commit, exact APK pair, 26 drivers and unchanged clean021 target.
Root alone owns fresh BOOT/GO/frame, original deadlines, actor stop/wait and
one terminal ACK; Core retains signing custody. Inspect the real app's bounded
list-refresh receipt on both outcomes. OBSERVED and MATCH_FOUND are diagnostics,
not RPC or consent acceptance. Distinguish current from last-seen state and
accessibility-node absence from Hub-list absence. Require actual JUnit, full
Alert and fresh bilateral KEY/NONE reads. Keep native Worker, physical Android
and public HTTPS NOT_RUN until separately tested. No push or merge.
```

## Historical F35 outcome and viewport successor — clean Core `0213538`

The [F35 validation report](client-hub-v1.6.4-0213538-f35-validation.md) binds
Client `a80d1a9efbfb2cb413b8356bb5ca764f751702f0`, its exact APK pair and clean
Core `0213538`. Actual JUnit failed at line 638 while finding the response text,
with one test and one failure. Its strict progress receipt records callback
entry, scope guard success, review consumption, native dispatch, a resolved
bridge response with `native_ok=true`, and `UI_RESPONSE_RETURNED`. The Promise
was no longer in flight; the response label was not visible. This observation
does not establish an authoritative Target grant or bilateral acceptance.

F35 remains **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**. Native ciphertext
pending and the authoritative Target KEY outcome are **UNKNOWN**. Preserve the
original operation and all earlier outcomes. SOURCE reads were partial; Target
`NONE` and fresh bilateral reads were **NOT_RUN**. The exact scroll offset and
cause of invisibility were not recorded. Core's independent closure and actual
two-resource cleanup passed; signatures remain separate from accepted grants.

The successor changes one Text attribute and the response-only test search.
The same 20-second deadline now covers bounded backward and forward page
searches, at most 12 actions per direction, excluding input-field scrolling.
The actual app-owned message ID and expected visible text must both match.
Visible text is checked first; an active debug observer delays scroll attempts
until the response stage, preserving the action budget during an asynchronous
request. A missing observer uses the bounded scan normally. The metadata does
not satisfy the UI assertion or any authorization check. Full Alert, proof,
Guard, expiry, pending recovery and fresh bilateral checks remain required.

The pure Kotlin viewport regressions, existing focused tests and static checks
are recorded under `/gpu1-share/data/cicada-client/v164-f35-response-viewport-20261004`.
Subsequent build, source and delivery receipts bind this clean source
checkpoint to one new APK pair and 26 frozen driver references. Fresh Android
acceptance, native Worker, physical Android and public HTTPS are **NOT_RUN** at
this checkpoint. Root owns the next fresh BOOT/GO, single frame and cleanup.
No live retry, signing, Core modification, push or merge is part of this fix.

### Next coordination prompt

```text
Read the F35 validation report and successor build/source/delivery receipts.
Preserve F35 and prior UNKNOWN operations; do not retry or replace them. Bind
the exact clean Client commit, APK pair, 26 sources and unchanged clean021
target. Root alone owns a fresh BOOT/GO/frame and original deadlines; Core
retains signing custody. Verify the actual app message becomes visible, then
complete the existing fresh bilateral KEY/NONE reads. OBSERVED stages and
native_ok=true are not the full acceptance gate. Capture strict JUnit and
progress receipts on both success and failure; stop/wait the actor, perform
one terminal ACK, and verify owned cleanup. Keep physical Android, native
Worker and public HTTPS NOT_RUN until separately tested. No push or merge.
```

## Historical F34 outcome and diagnostic successor — clean Core `0213538`

The [F34 validation report](client-hub-v1.6.4-0213538-f34-validation.md) binds
Client `8f2900c63f515033827d41d962acf7453513f370` and app/test SHA-256
`3c7a4e5903edc8549773cc89e29fe058959fa68e8f56ffba45214eba6a4cf32d` /
`1110cbed39069a6c5f316426db821237f696856188fa9ddee3475426f32d0fbf`
to the unchanged clean v1.6.4 Core target. Encrypted enrollment, capabilities
and independent pins passed. SOURCE KEY and `NONE` returned partial status.
TARGET reached `REVIEW_READY` and `CONFIRM_READY`; the complete native Alert
scope checks and positive-button accessibility action returned successfully.
JUnit then failed at line 597 waiting for the response text, with one test and
one failure. Flow exit was `1`; instrumentation exit `0` did not override JUnit.

The terminal remains **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**. Alert click
does not prove callback entry, encrypted RPC dispatch or Hub acceptance. Actual
native packet pending and Target KEY outcome remain **UNKNOWN**. Preserve the
original operation; do not retry or replace it. Target `NONE` and bilateral
acceptance were **NOT_RUN**. Five external signatures are not accepted grants.
Core's independent closure and actual two-resource cleanup passed; their exact
hashes and attribution limits are in the F34 report. No new live action ran here.

The successor adds bounded, payload-free diagnostic observations only. Native
observation requires a debug build and an active instrumentation observer. It
records fixed UI/native stages and allowlisted error codes in memory; the test
exports a private `OBSERVED` receipt without proof bytes, messages or keys. A
Promise in flight is reported separately from unobserved ciphertext pending.
The existing protocol, pins, proof, expiry, guards, deadline and bilateral
acceptance checks remain required. Docker JavaScript (14) and Python (16)
tests, TypeScript and ESLint passed. The post-commit build and 26-source delivery
under `/gpu1-share/data/cicada-client/v164-f34-submit-observation-20261004`
will bind the exact new Client commit and APK pair. At this source checkpoint
fresh Android acceptance is **NOT_RUN**. Physical Android, public HTTPS,
native Worker and Link recovery fault acceptance remain **NOT_RUN**.

### Next coordination prompt

```text
Read the F34 validation report and the successor's build, frozen-source and
delivery receipts. Preserve F34 FAIL / OUTCOME_UNKNOWN_PRESERVE_PENDING and
every earlier outcome. Do not retry an original packet or infer Hub acceptance
from the native Alert action. Bind the exact clean commit, app/test hashes and
26-source closure before a fresh Root-authorized run. Root alone owns BOOT/GO,
scope/deadlines and the single business frame; Core retains external signing
custody. Capture the new strict submit-progress receipt on success or failure.
OBSERVED metadata never establishes acceptance: require actual JUnit success,
the full native Alert and fresh bilateral KEY/NONE status. Preserve actor
stop/wait, one terminal ACK and owned cleanup. Report physical Android, public
HTTPS and native Worker as NOT_RUN until separately tested. No push or merge.
```

## Historical F33 outcome and successor correction — clean Core `0213538`

The [F33 validation report](client-hub-v1.6.4-0213538-f33-validation.md) binds
Client `906c7b0d0434b569336060a33697ff96e9ec7948`, its exact APK pair and the
fixed clean v1.6.4 target. SOURCE and TARGET encrypted enrollment, capabilities
and independent Owner pins passed. SOURCE KEY and `NONE` produced partial
statuses only. Target preparation reached `REVIEW_READY`, but actual JUnit
reported one failure at the confirmation-control wait: `CONTROL_MISSING`, zero
candidates. Instrumentation exit `0` did not make this test pass.

The terminal remains **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**. No retry was
made. Actual native RPC pending is **UNKNOWN**; retain the historical host
marker. The RN confirmation click, native Alert, Target KEY grant, Target
`NONE` and bilateral consent are **NOT_RUN**. The underlying selector/layout
cause is **UNKNOWN**. F31/F32 business **NOT_RUN** results remain separate.

The minimal successor bounds the proof editor's displayed height and uses
package-filtered app windows, exact consent selectors and at most 12 page
scrolls in the original 20-second wait. A unique visible enabled clickable
control and the full native Alert remain mandatory. No protocol, pin, proof,
expiry, lifecycle or typed validation was relaxed. The 22 affected tests,
TypeScript and ESLint passed. At this source checkpoint, its post-commit APK
build is **NOT_RUN**; subsequent build/source/delivery receipts under
`/gpu1-share/data/cicada-client/v164-f33-consent-control-viewport-20261004`
bind the exact clean Client commit, new APK pair and frozen 26-source successor.
Fresh live acceptance remains **NOT_RUN**.

Emulator removal was independently verified. Core's actual two-resource
cleanup and independent closure passed; its marker confirms ACK before hard
and private-path deletion. Actor true-wait `-15` and one ACK exit `0` are
Main-thread attestations in the closure. Five signatures do not prove accepted
Hub sides. Physical Android, public HTTPS and native Worker remain **NOT_RUN**.
No push or merge was performed. The report contains the next Core prompt;
Root owns the fresh run and its authorization/deadlines.


## Historical F30 outcome — clean Core `0213538`

The [F30 validation report](client-hub-v1.6.4-0213538-f30-validation.md)
binds clean Client `b19e84b66cae3887c64cb9e576f11b3cf55f6eee`, its exact APK
pair, the fixed Core target, actual Root BOOT/GO, and the F30 terminal receipts.
The live checker passed with `391.828` seconds remaining in the original budget
at the check. The business plan bound the exact three Root references; the
authorized Scope bound 27 fields and nine public references. Bootstrap,
prepare, bind, carrier, and hot preflight passed. SOURCE KEY and SOURCE `NONE`
produced only partial statuses; TARGET enrollment, capabilities, pins, and
phone-UI preparation passed.

JUnit failed at `kt386` while trying to resolve the explicit Target
confirmation control `核对并明确授权`. Earlier canonical proof-input and
request-binding checks passed. The Android flow exited `1`; the positive
confirmation Alert, Target KEY Hub acceptance, Target `NONE`, and bilateral
KEY/`NONE` remain **NOT_RUN**. The underlying UI cause is **UNKNOWN**; the test
does not establish an API, DTO, or lifecycle defect.

The terminal is **`OUTCOME_UNKNOWN_PRESERVE_PENDING`**. Preserve the F30 host
marker and do not retry: the actual native RPC outcome was not exported. Core
indexed one Root frame, five signature records, zero retries, one terminal ACK,
and owned cleanup. The ACK exited `0` before the hard deadline; actor stop and
owned cleanup passed. Physical Android, public HTTPS, and native Worker
acceptance remain **NOT_RUN**.

The bounded consent-control correction now uses a stable test ID, diagnostic
tooltip/View IDs, state restoration, and a 20-second wait for one enabled and
clickable confirmation control. Its strict nine-field receipt and 22 focused
Python/JavaScript tests passed; TypeScript and ESLint also passed. These offline
checks do not validate the Android UI. At this source checkpoint, post-commit
APK assembly is **NOT_RUN**; its subsequent receipt at
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/apk-build.receipt.redacted.json`
will bind the exact source and APKs. A fresh live run remains **NOT_RUN**. The earlier 18 focused checks,
static checks, and single APK build apply only to Client `b19e84b` and its F30
APK pair.

### Next coordination prompt

```text
Read docs/client-hub-v1.6.4-0213538-f30-validation.md. Preserve the F28 and
F29 failures and the F30 OUTCOME_UNKNOWN_PRESERVE_PENDING marker. Do not retry
the F30 operation or infer bilateral consent from the Target signing request
or proof handoff. The positive phone confirmation and Hub acceptance did not
run; native RPC outcome remains unknown.

The minimal correction is implemented. Bind the exact source and APK pair to
the commit and subsequent post-commit APK receipt at
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/apk-build.receipt.redacted.json`.
The current offline checks do not validate the Android UI. Before another live
step, require a fresh Root BOOT with actual READY and a fresh GO bound to the exact source,
APK pair, fixed Core target, Scope, and deadlines. Preserve strict Owner pins,
proof, lease, tuple, and operation-fence checks; the existing six-flow order;
one-frame Root authorization; Core signing custody; actor stop/wait; one
terminal ACK; and owned cleanup. Do not reuse F30's GO, proof handoff, or pending
operation. Keep each status and terminal outcome separate. Physical Android,
public HTTPS, and native Worker acceptance remain NOT_RUN until tested.
```

## Historical F29 outcome — Root-reference plan failure

F29 used Client `b19e84b66cae3887c64cb9e576f11b3cf55f6eee` and its recorded APK
pair. The first non-authoritative proposal had three incorrect Root references
(SHA-256 `940330f6d3ef906c40938cddb17ebaf2ffe1c008aefb731c711d60d9dbeb99ca`).
A corrected proposal passed static review, but static PASS was not
authorization or execution; the corrected proposal missed the original
360-second readiness budget. Bootstrap, bootstrap preflight, and emulator stop
exited `0`. The terminal at `16:13:35.612855Z` records **FAIL / PlanError /
NOT_RUN**. Root cancelled before the original hard deadline `16:17:49Z` and
idle deadline `16:20:52Z`; the generic idle message does not prove actual idle
expiry. No business frame, signature, or encrypted request was sent.

Core stopped the actor and completed one terminal ACK with exit `0` before the
hard deadline. The held actor wait exited `143` after SIGTERM. Owned cleanup
passed. Terminal SHA-256 is
`75861be2bb625fceaa1f5568d1c55c8220f72cffb1a2dde03f29365670bb531f`; the
Core closure index is
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-29-clean021-20261003/evidence/attempt-08/stage-actor-terminal-owned-closure-index.redacted.json`,
SHA-256 `a7b7f3633a63e3679ae144e3b6fe04219f7d9ea23f32844b7ed47c768753b7f5`.
F29 was an orchestration/plan failure, not product acceptance or rejection.

## Historical F24–F28 outcome — clean Core `0213538`

The [F24–F28 validation report](client-hub-v1.6.4-0213538-f28-validation.md)
retains each failed attempt. F24 stopped at the cold APK-pin closure check;
F25/F26 ended before business under their budget cancellations; F27 prepare
failed on the inner Hub-ready digest instead of raw aggregate READY. F28 passed
bootstrap, preparation, binding, and hot preflight, then its flow exited `1`
after the SOURCE partial result and TARGET setup.

F28 SOURCE KEY status was partial (`SOURCE` accepted, `TARGET` missing,
`bilateral=false`); SOURCE `NONE` remained noncurrent and nonbilateral. TARGET
enrollment, capabilities, and independent pins passed. The Android test failed
while waiting for the scope row after reading the current proof. Target KEY
confirmation, Target `NONE`, and bilateral acceptance were **NOT_RUN**. Its
terminal remains **`OUTCOME_UNKNOWN_PRESERVE_PENDING`**; one Root frame, no
retries, one terminal ACK, and owned cleanup are recorded in the report.

F28 used the APK pair from Client `8b1b6c54eff702918c426827a3673f9a112edbcc`.
Its next-run prompt and 18 focused checks are historical. F30 later used Client
`b19e84b66cae3887c64cb9e576f11b3cf55f6eee` and a different APK pair. Do not
transfer any F28 result to F30 or the current consent-control correction.

## Historical F20–F23 outcome and timestamp correction — clean Core `0213538`

The [F20–F23 validation record](client-hub-v1.6.4-0213538-f23-validation.md)
retains its original APK pair, per-attempt commands, partial SOURCE KEY result,
SOURCE `NONE` failure with unknown typed cause, and cleanup evidence. Its
accepted-at clarification uses the Hub clock for `accepted_at <= verified_at`
and requires the signed proof interval
`issued_at <= accepted_at < expires_at`; Android `now` is not used for that
Hub timestamp. The correction preserves canonical timestamp parsing, current
proof and lease checks, independent pins, and operation fences. Historical
F20–F23 results do not transfer to the F28 APK pair.

## Historical F19 diagnosis and snapshot-time correction — clean Core `0213538`

The [F19 validation record](client-hub-v1.6.4-0213538-f19-validation.md) identifies
clean Client `d16875bd1d0bb8380808fe95717199dc00de5279`, its exact diagnostic APKs,
fixed Core/images, commands, exits and immutable evidence. F19 passed Android
bootstrap, SOURCE registration, encrypted capabilities, pins, manifest and
native pre-submit signature verification. Fresh status then failed with
`LOCAL_LINK_OWNER_GRANT_VERIFICATION:VERIFIED_AT_IN_FUTURE`. Pending was
preserved; Client cleanup passed and Core independently completed actor stop,
one terminal ACK and owned cleanup. The actual clock difference is UNKNOWN.

Core confirmed that `verified_at` is Hub snapshot metadata and that v1.6.4 does
not require comparison with the Android clock. The correction removes only
that extra comparison from KEY evidence and policy preview/status. Signed
proofs still require local `issued_at <= now < expires_at`; complete signatures,
independent keys, provenance, shared snapshot, exact tuples and leases remain
checked. The focused Docker regression passed 23 tests, exit `0`.

Replacement APK assembly and fresh live acceptance are NOT_RUN at this source
checkpoint; their later receipts must identify the clean correction commit and
new pair. SOURCE NONE, TARGET enrollment/RN Alert/NONE, physical Android and
public HTTPS remain NOT_RUN for F19. The record includes the concise next-run
coordination prompt. Core retains Owner signing custody and terminal ACK; Main
Root supplies a fresh bounded authorization and the single business frame.

## Historical F18 outcome — clean Core `0213538`

The [F17–F18 record](client-hub-v1.6.4-0213538-f18-validation.md) retains the
fixed image/APK attribution, exact commands and failures. F17 passed both
independent device enrollments and encrypted capabilities, then rejected a
stale Source profile selection. The corrected Source-three/Target-three host
order passed 17 offline state-machine checks and the read-only plan check.

F18 passed Source enrollment, capabilities, independent pins and manifest
verification. Its external Owner KEY proof passed native pre-submit verification
and the Hub returned `ok`; a fresh retained-status read then failed local
verification. The launcher exited `1`, preserved pending and cleaned its owned
Android/carrier resources. Core separately attested actor stop, terminal ACK
and cleanup. The exact underlying predicate is **UNKNOWN** because the original
exception was replaced; no plaintext status response was persisted.

A minimal Client diagnostic now preserves only an allowlisted local reason in
the exception cause. Public errors and all signature, pin, generation and time
guards are preserved. Its published-vector Docker regression passed eight
tests, exit `0`; the first build-driver configuration failure remains recorded.
The replacement APK pair and fresh live acceptance are **NOT_RUN** at this
checkpoint. Bilateral KEY/NONE, Target RN Alert, physical Android and public
HTTPS remain **NOT_RUN** for this attempt. Do not replay F18 or weaken time
checks based on the unproven clock-skew hypothesis.

Next: freeze one APK pair from this committed diagnostic source, update only
the necessary Client driver pins, and let Main Root supply a fresh bounded
BOOT/Scope/GO and the single business frame. Core retains sole custody of Owner
signing and terminal ACK. Report the actual local reason and each live gate
separately; the diagnostic regression is not proof of a repaired live flow.

## Historical F10 outcome — clean Core `0213538`

The [F10 acceptance record](client-hub-v1.6.4-0213538-f10-validation.md) binds the
actual Client checkpoint, frozen APKs, full images, commands/exits and original
receipt hashes. Android BOOT, installs, four properties, bootstrap preflight
and owned emulator cleanup are **PASS**. Core preparation is **FAIL** because
its clean delivery lacked `std-producer.json`. Root cancelled the single
launcher through stdin EOF (outer exit `1`) before delivering a business ticket.
Encrypted capabilities and bilateral Link flows remain **NOT_RUN**.

The Client independently verified original Core failure receipts and its own
terminal/journal, and confirmed the exact emulator ID no longer exists.
No fixture retry, signature, enrollment, business RPC or ACK was performed.
Core delivered the frozen path correction and dependency preflight; the Client
imported its three public files byte-for-byte. Six small COLD adapter changes
avoid rewriting sources for each fixture number. Their sole plan check failed
because these formal documents were uncommitted; the failure is retained.
The closing checkpoint restores a clean checkout. F10 sources and evidence
remain immutable; a new actual plan still requires independent validation.

### Next coordination prompt

```text
Read CICADA_CLIENT/docs/client-hub-v1.6.4-0213538-f10-validation.md and its
Git-external original evidence. Preserve BOOT PASS, Core prepare FAIL and
cancelled outer exit 1; encrypted business remains NOT_RUN.

Use the independently imported three-file clean-0213538 path correction, with
explicit fixture-driver path/SHA and adjacent preflight. Review the final
COLD successor delivery receipt and clean Client checkpoint; retain its
original dirty-checkout check failure. Do not modify Client, use a Hub database
or silently substitute another delivery. Independently bind existing Rootpins,
exact Scope/GO, BOOT plan/receipt, ownership marker and all source hashes.
Keep Owner signing and private credentials in Core custody.

Only after separate Root BOOT authorization, consume stdout READY from one
bounded launcher. Deliver one Root-approved business ticket on its retained
stdin. Preserve original cutoffs, the exact 27-field Scope, nine references,
owned resource checks and six-flow order. No automatic retry or early ACK.
Report each real Android encrypted/UI gate and owned cleanup separately.
Physical Android and public HTTPS stay NOT_RUN until actually executed.
```

## Offline bounded launcher handoff

The [launcher interface and command plan](client-bounded-acceptance-launcher.md)
defines the single-process BOOT/readiness/ticket/carrier/preflight/flow sequence.
Core should consume its stdout readiness and deliver one combined plan on the
same stdin pipe. It must not add polling stages, six separate releases or an
early terminal acknowledgment. Fresh Core/Client source-derived adapters and a
new Root-approved delivery remain prerequisites; fixture-09 stays closed.

This change preserves the frozen APK pair and original F9 outcome. No new Hub,
emulator, device export, registration, Owner signature or business RPC was run.
The narrow offline evidence and final launcher commit are bound outside Git in
`/gpu1-share/data/cicada-client/v164-bounded-launcher-offline-20261003/`.
The final pinned Docker run passed **17 synthetic tests**, exit `0`; two early
test-fixture failures remain recorded. The aggregate READY and inner Hub-ready
references are independently bound using the actual Core Scope semantics.
Live encrypted capabilities, bilateral KEY/`NONE`, Target Alert, native Worker,
physical Android and public HTTPS remain **NOT_RUN** for this launcher.

### Current coordination prompt

```text
Review CICADA_CLIENT read-only on dev/react-native. Read
docs/client-bounded-acceptance-launcher.md and the Git-external launcher
delivery receipt for the exact Client commit, source hashes, test command/exit
and frozen APK pair. Retain all original F9 failures and runtime attribution.

Supply actual clean Core archive/image/source metadata; independently pin it
in bootstrap.target. Refresh and freeze the Core coordinator and Client
source-derived adapters before requesting a new BOOT. Fixture-09 is closed.
Keep Owner signing and all private credentials in the Core custody boundary.

After separate Root BOOT authorization, consume actual stdout READY from the
single launcher process. Only then create the fresh fixture and bind its exact
nine public references, owned manifest, Scope and one Root GO. Deliver the
combined business plan through one stdin JSON frame. Do not add model polling,
six manual releases, automatic operation retries or an early nonce_used ACK.
ACK belongs only to Core's true terminal/cancel path.

Observe the original fixed idle and business cutoffs. Report each actual
phase, encrypted capabilities, Target RN Alert, bilateral status and cleanup
against exact source/APK/image provenance. A driver zero exit is insufficient
for acceptance. Unrun native, physical-device and public HTTPS gates stay
NOT_RUN; Link fault recovery remains BLOCKED without a safe isolated driver.
Do not edit Client, read a Hub database, push or change production deployment.
```

## Current target provenance — clean Core `0213538`

The [clean delivery review](client-hub-v1.6.4-0213538-provenance.md) independently
passed all 24 archive payloads, 896 immutable Git inputs, source fingerprint
reproduction and full Hub/interop image metadata checks. The launcher binds
those actual values in its Root-approved target. The subsequent F10 Android
bootstrap passed, but fixture preparation failed before a business ticket.
Runtime encrypted capabilities and Android Link business remain **NOT_RUN**.
The frozen product/APK pair below remains separate.

## Historical F6–F9 acceptance target — clean v1.6.4 Core `dd81575`

The fixed F6–F9 target is clean Core
`dd81575b160aa901b642137e54d7a60961e4bd68`, Client-Control v1.6.4,
Hub image `sha256:ab189ee06372e4eaa248eac6e3699f7b4e2d9105505e87027f0081d118adc561`
and interop image `sha256:c926d0f3809572e541414cbb239efdc00ba82d07e16950318199df4c6d5e2679`.
The [fixed delivery record](client-hub-v1.6.4-dd81575-validation.md) contains
the complete archive/catalog/source pins, actual commands, exits and receipts.
Independent verification covers all 24 contract payloads and 891 standard
build inputs. The original producer outer exit 1 remains **FAIL**; the separate
corrected review establishes build and contract provenance only.

The frozen product checkpoint remains `508ca333c8ae90d27a8191ac828a7be16b71c7b3`;
the fixture adapter checkpoint is `6d01e4a82818c0bae9013d4c42ead2b99a9be9c0`.
App/test APK hashes remain `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67`
and `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`.
The Main fixture correction and terminal acceptance record are delivered as one
checkpoint. Its exact final commit is bound after commit in
`/gpu1-share/data/cicada-client/v164-dd81575-20261002/client-delivery-closure.redacted.json`.
The original F6 delivery receipt and local recovery reference retain the
`d93afaf` snapshot used during F7 preparation.
No product or APK rebuild was performed.

| Gate | Current result |
|---|---|
| Archive, catalog, source inventory, selected immutable image metadata | **PASS**, provenance scope only |
| Frozen APKs: 49 independent Android tests, four real emulator properties, local UI smoke | **PASS**, network-none offline scope only |
| Offline emulator teardown | **PASS** through a separate absence addendum; original immediate-inspect race and both outer exit-1 attempts remain retained |
| Actual F6 READY, nine Root-bound public references and immutable running Docker identity | **PASS**, read-only fixture verification only |
| Fresh F6 emulator boot, frozen APK installs and four properties | **PASS**, bootstrap only; initial pre-Docker missing-directory exit 1 retained |
| Encrypted enrollment/capabilities and Link business flow | **NOT_RUN**; F9 first staging command **FAIL** on runtime receipt compatibility before any Android business selector |
| External signing interface | **PASS** for static interface compatibility; actual six signatures **NOT_RUN** |
| Target actual Link-consent Alert and bilateral KEY/`NONE` | **NOT_RUN** |
| Link write lost-response/409 recovery | **BLOCKED**; the bounded carrier currently allows only `fault=none` |
| Native Worker/model, physical Android and public HTTPS | **NOT_RUN** |
| F6 Client emulator and Core Hub/bridge cleanup | **PASS**, owned resources only; exact absence independently checked |

### F6 terminal outcome and evidence

Formal Root GO arrived at `2026-10-02T18:48:21Z`; the fixed deadline was
`2026-10-02T18:51:45Z`. Coordinator prepare and actual public/Docker verification
exited 0. Fresh emulator setup consumed the remaining window, including one
exit-1 start attempt because the mode-0700 evidence directory was absent.
The identical command passed after directory creation. Both frozen APK installs
and all four property reads exited 0. Carrier, onboarding stage, Android
business selector and encrypted capabilities were **NOT_RUN**. All six signing
requests, Root approvals and Owner signatures were zero. No pending business
packet, operation or sequence was created. No renewal, late signature or new
fixture was attempted.

Run `v164-f6-dd81575-main-20261002` has a private terminal receipt at
`/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/coordinator-private/runs/v164-f6-dd81575-main-20261002/f6-terminal.redacted.json`,
SHA-256 `4d4f1c758c755c0a0b0618eece7a496823927721bf04f4499fc77c8bee2090fc`.
Its immutable original states Core cleanup was pending; the separate
`core-cleanup-addendum.redacted.json` in the same directory, SHA-256
`3d1b6dba75f01a17784f2cfd32969b1f0860a277e5e72be60db9ca47d4f495f0`,
confirms cleanup without rewriting that record.

The Client emulator stop exited 0; final expected missing-object inspect exited
1. Receipt `/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-dd81575-main-20261002/android/android-teardown.redacted.json`
has SHA-256 `1df0b57744dc8d34c4115d5b3ad6d393d8192531e946e7fe25ab0186a11669a0`.
Core's deadline watchdog removed its own Hub/bridge with exit 0. Core receipts,
actual commands, all delivery pins and individual Android exit records are in
the [fixed validation record](client-hub-v1.6.4-dd81575-validation.md).
This attempt establishes fixture/bootstrap correctness only; it does not
establish bilateral KEY/NONE or a phone consent result.

Core retains all Owner private keys and operates the external signer. The
Client exports `cicada.client.link-consent-signing-request.v1` and chooses the
exact proof expiry within five minutes. Core delivered a compatible v2 external
interface that consumes those unchanged bytes and exact expiry, adapts the
existing public Android device export, and uses separate Root approval records
without inventing Native review IDs. Its public usage file SHA-256 is
`a1c201d58fa4954f378a58e17a6e4d5d0c114828b7eadaac360924a3db6ae7ba`.
That static check creates no signature or runtime acceptance. The ignored
Client file coordinator has SHA-256
`d91a85bf235806b2232550e6d4855bcb96968bf67c84b8a30864523f42923e1d`;
its final private README has SHA-256
`2ec764cd29870772a8ad5af1fa23a7d8132f1554b43eda0b37c29a57cf2bd720`.
It binds actual UI review/submit receipts to the run, Link, exact request and
proof hashes, and preserves the first Target KEY through the real RN Alert.
Inert public-key-only
format examples and their SHA index are under
`/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/synthetic-request-examples/`;
they are not actual Android exports and must never be signed or submitted.
The next separately authorized final Join/READY must wait for signer,
coordinator and an already booted/installed owned emulator. The first Target
KEY must use the actual React Native one-use Alert; emulator automation does
not establish physical or human confirmation. Historical evidence below keeps
its original source, APK and outcome attribution.

### F7 boot-only preparation closure

Core separately authorized one new emulator bootstrap and exact fixture-07
private adapter parameters. Frozen APK install, four real properties, guarded
bootstrap adoption and one positive/eight negative shape checks passed. The
emulator was ready at `19:08:50.174Z`, before any short Hub lease was started
by Client. No actual fresh Root five-pin delivery/business GO arrived before
the fixed idle cutoff `2026-10-02T19:25:08Z`; the watcher removed only its owned
emulator at that time (stop 0, final missing-object inspect 1).

No Android key export, artifact binding, carrier, RPC, UI or signing request
ran. Core Root subsequently terminated its PRE and reported no final Group
Join, Link or READY; Client does not infer Core state from its own bootstrap. Result is
**BLOCKED_NO_FRESH_ROOT_GO_BEFORE_IDLE_CUTOFF**, with business acceptance
**NOT_RUN**. All private compatibility adapters remain outside Git/APK;
there is no product rebuild. The [fixed validation record](client-hub-v1.6.4-dd81575-validation.md)
contains actual commands, original failures, complete pins and evidence hashes.
Terminal receipt `/gpu1-share/data/cicada-client/v164-f7-preparation-20261002/f7-preparation-terminal.redacted.json`
has SHA-256 `e919de2d3d4ff08afcaa7ccfe07598091adc5570278b4688f27bb11b44d789fe`.
Owned-emulator teardown receipt has SHA-256
`e58f3c205d90499c8b57fae8062f0fcf0ebeacb35a2df83afffc9ced5115aff4`.
Core-owned Hub/bridge cleanup also passed: Core removal exit 0, followed by
two independent Client exact-ID absence queries with expected exit 1. Addendum
`/gpu1-share/data/cicada-client/v164-f7-preparation-20261002/core-cleanup-addendum.redacted.json`
has SHA-256 `8d53429501ee1aa946febfa0a5aa91f618c8d55dee9a7168443e9b930a5d288a`;
it binds Core's original receipt without any Client database/private-path read.

Before a further separately authorized attempt, finish Core helper build and
fixture adapter preparation first, then have Client boot and confirm readiness,
and promptly publish the actual Root delivery and GO. Do not reuse either
expired F6 authorization or the removed F7 emulator, extend idle waiting, or
claim any Source/Target business pass from these preparation results.

### F8 closure and F9 preparation

F8 closed **BLOCKED_DEADLINE_BEFORE_ANDROID_BUSINESS**. Fresh public fixture
verification, actual immutable Docker identity, both emulator bootstraps and
exact artifact binding passed within their limited scopes. The original GO
existed and was consumed by the binder. The corrected GO separated phone proof
validity from the unchanged execution stop. RootFlow then exited 1 at the
`00:34:43Z` deadline before its first business subprocess; its index is `[]`.
Device exports, enrollment, encrypted capabilities, RPC, six external Owner
requests/signatures, Source/Target KEY/NONE and Target RN Alert are **NOT_RUN**.
Carrier startup passed with zero transactions; its outer exit 1 during late
ADB reverse cleanup and child exit 137 remain **FAIL**. No product/APK rebuild
was performed. F6/F7 and older business evidence retain their own attribution.

Client emulator/process cleanup and independent exact-ID Hub/bridge absence
checks passed. Core's watchdog removal exits were 0/0; its receipt was written
at `00:34:44.234114Z`, 1.234 seconds after the fixed stop, not before it. Core
private-path destruction remains Core-attested. Complete commands, exits,
immutable values and evidence hashes are in the [F8 validation section](client-hub-v1.6.4-dd81575-validation.md#f8-terminal-record--2026-10-03).
Terminal receipt
`/gpu1-share/data/cicada-client/v164-f8-preparation-20261002/f8-terminal.redacted.json`
has SHA-256 `82bb25b84bd8f1a50630a9b525fe54b0f08fe737f8a299d088e6ffb82fdc5a2d`.

### F9 terminal outcome and correction

F9 ran once with Client source
`6b2c552197bb625e31e32d700d84d12685b8f81f` and the unchanged app/test APK
pair above. Its isolated Core fixture, fixed-image identities, bootstrap and
artifact binding passed within their limited scopes. The business flow then
failed at its first source setup staging command, exit `1`, because the
runtime receipt format written by the bootstrap did not match the consumer.
No device export, registration, encrypted capabilities, business RPC, Owner
claim/signature, KEY/`NONE`, Target React Native Alert or bilateral status ran.
Their result remains **NOT_RUN**. F9 is not a consent acceptance result.

| Gate | F9 result |
|---|---|
| Bootstrap / installs / four actual runtime properties | **PASS**, exit `0`, 37.122 seconds |
| Bootstrap binding | Initial CLI **FAIL** `2`; corrected exact helper mount invocation **PASS** `0` |
| Carrier startup | **PASS** within startup scope; zero transactions |
| Source setup staging / business driver | **FAIL**, `1` / `1`, `owned emulator runtime metadata is inconsistent` |
| Device enrollment, encrypted capabilities, six Owner signatures | **NOT_RUN** |
| Source/Target KEY and `NONE`, Target actual RN Alert, bilateral status | **NOT_RUN** |
| Client owned emulator/process cleanup | **PASS**, stop `0`, independent absence recorded |
| Core owned cleanup | Watchdog `0/0` Core-attested; exact container/network absence independently checked in the terminal audit |
| Carrier outer shutdown | **FAIL**, `1`; child `137`, ADB reverse cleanup failed during deadline-driven emulator teardown |
| Native Runtime/model, physical Android, public HTTPS | **NOT_RUN** |
| Link recovery faults | **BLOCKED**, no isolated fault driver in the bounded lane |

The bootstrap recorded `schema`, `image_id` and four real properties in
`android-runtime.redacted.json`. The consumer required the older
`emulator_image_id` and `platform="Android emulator"` projection. The binder
verified the actual image and property receipts; the subsequent consumer used
a different format. Original input and failure receipts remain unchanged.
The fix must validate the actual producer formats and reject conflicting
fields; it must not remove image, ownership, network, raw-property or APK
checks to admit the run.

Root GO approved at `01:17:13.969997Z` fixed the hard stop at `01:23:47Z`.
Carrier metadata was written at `01:20:06.784143898Z`, but Client only polled
its yielded session at `01:23:17Z` after a context handover. This host scheduling
gap is retained separately from the compatibility failure. No manual per-sign
GO was required or requested. The business watcher adopted the same emulator
with an earlier stop than the original idle watcher. Core cleanup was recorded
at `01:23:48.740840210Z`, 1.740840210 seconds after the business stop; authority
was not extended. The Core actor reported zero requests/claims/signatures and
exit `0`. Client did not rerun the flow or substitute a Native selector for the
Target UI.

Complete fixed pins, exact commands, exits, receipt hashes and timestamp
qualifications are in the [F9 terminal record](client-hub-v1.6.4-dd81575-validation.md#f9-terminal-record--2026-10-03).
The retrospective command journal is
`/gpu1-share/data/cicada-client/v164-f9-preparation-20261003/f9-command-journal.redacted.json`,
SHA-256 `31ec5b09ffef5cdbb1d579592e499cbd42e6c88d4143f57718f6ef61557c3099`.
The original six-phase fixture and private comparison patch stay frozen as
historical evidence, not a reusable authorization. The formal closure records
Client source during execution separately from the subsequent fix/document
checkpoint. No push, merge or product rebuild is performed.
The final checkpoint is bound after commit in
`/gpu1-share/data/cicada-client/v164-f9-preparation-20261003/f9-client-delivery-closure.redacted.json`.
The execution source `6b2c552` is preserved locally at
`refs/cicada-client/acceptance-snapshots/f9-6b2c552`; it is not an additional
published commit or approval for a future attempt.

The strict consumer correction and `bootstrap-preflight` / `preflight` CLI are
implemented. The narrow network-none Docker regression passed **9 tests,
exit `0`**; corrected live preflight remains **NOT_RUN**. Exact command and
source hashes are in the validation record. Regression receipt SHA-256 is
`6e3d6aad3a519e08756084f6ee83d1276dc490add909dae7d9700e1efa7a794d`.
Independent owned-resource cleanup audit
`/gpu1-share/data/cicada-client/v164-f9-preparation-20261003/f9-owned-cleanup-audit.redacted.json`
has SHA-256 `dce895e20f04fc623dad35889b02a4516045a5719377d9046e2df1b161130b44`.
It verifies three exact IDs and five exact-ID/fixture-label filters, and
independently observes zero original carrier transactions and zero completed
coordinator phases with no pending work. Core private-path absence remains an
attestation. Carrier reverse cleanup failed during teardown; file write times
do not prove that removal completed before the failed reverse command.

### Next acceptance entry

Resolve the producer/consumer mismatch and run only its narrow offline
regressions. Before starting a timed Core fixture, one Client entry must boot
the emulator, install the frozen APKs, record the raw properties and run the
same read-only runtime validation used by the staging consumer. This preflight
must not stage inputs, export device identities, sign, register or send RPC.
After binding a separately authorized fresh delivery, run the full read-only
artifact preflight, start the carrier and continue the existing six phases
from one bounded process. Carrier READY must directly release that process;
manual host polling between stages must not consume the short window. The
single process must journal UTC start/end, actual argv, timeout and exit for
every subprocess and stop immediately on failure. Preserve pending packets
and original operation/counters; no automatic business retry is permitted.

This is a preparation requirement, not permission to create a new Hub, renew
proofs or reuse F9 Scope, GO, nonce, claims or owner identities. The private
F9 adapters remain frozen with the original failed guard; a future approved
entry must import the corrected repository source and independently freeze
its exact bytes rather than reusing those historical adapters. No broad APK
matrix or cryptographic test rerun is required for a host harness correction.
Independent Owner review and the real Target RN Alert remain mandatory.

### Prompt for the CICADA core maintainer

> Read this handoff and the F9 terminal section of the fixed dd81575 validation
> record on Client `dev/react-native`. Preserve F6–F9 failures and their original
> evidence; bootstrap, binding and cleanup PASS do not establish consent.
> F9 failed its first staging command because bootstrap runtime metadata and
> the consumer format differed. Device enrollment, encrypted capabilities,
> Owner signatures and bilateral KEY/NONE were NOT_RUN. The host context
> handover also delayed flow launch after carrier READY; record that separately.
> Review the strict Client runtime validator and narrow regressions. Require
> the same read-only bootstrap preflight before any new timed fixture, followed
> by a single bounded carrier-to-flow entry with recorded UTC timings. Do not
> launch a new attempt until those prerequisites are complete. Any fresh run
> needs separate authorization and new exact Scope/GO, fixture identities and
> nonce while retaining clean dd81575, catalog 953486ea, immutable Hub ab189ee0
> and the frozen app/test APK pair. Serve the six exact external Owner claims
> without manual per-claim coordination delays, retaining independent request
> and challenge validation. First Target KEY must use the actual RN one-use
> Alert; ordinary peer messages remain closed. Return encrypted capabilities,
> bilateral status, exact commands/exits and owned cleanup receipts. Node/Hub
> bearer, Owner private keys and databases stay with Core. Native Runtime,
> physical devices, public HTTPS and Link fault recovery require separate
> acceptance and remain NOT_RUN/BLOCKED here. Do not push or merge.

## Prior integration — clean `25bc586` v1.6.4 Link consent

Core `25bc586232db43362c6e03eccef1fa3a0dbec8ee` / Client-Control v1.6.4
has been independently imported and checked against its immutable Hub and
interop image IDs. Complete archive, catalog, producer and 882-entry Git
inventory checks pass. See the [fixed delivery validation record](client-hub-v1.6.4-25bc586-validation.md)
for all pins, commands, exits and the preserved initial Docker UID failure.

The local Native candidate is integrated and its gates are enabled for this
candidate only. It adds the strict v1.6.4 Link manifest, Owner proof, review
policy, fresh scope and durable exact-packet recovery path. The phone review
panel calls dedicated Native methods; generic RPC continues to reject all five
Link consent operations. The JavaScript layer has no duplicate authority
shaper or ephemeral consent ledger: durable proof, tuple and packet-fence state
remain in Kotlin. The candidate implements 44 of 55 catalog operations and
keeps 11 closed.

Final retry-6 offline evidence: 40 pure Kotlin tests across five classes passed
with no failures/skips; Native and Android-test Kotlin compilation and both
Debug x86_64 APK assemblies exited 0. Host receipt SHA-256 is
`fa7bfc446aa3d0c9ce3b0b305b24cc458e95cbb7b6d444b50d96a3bbf6c3bd94`. App/test
APK hashes are
`56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` /
`caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`; the
153-file snapshot SHA is `b6f8eb00b9a0ad61c7fd31947e1925f8d77b15c5ad23d56d39476e26f7d81a80`,
with 140-file source fingerprint
`855087a657384177343b6b8868ca51a6d5bfc5a3983382c01b9e7b0e928a2431` and
110-file Kotlin fingerprint
`8276380239debfe1dd735636037efc5662656d6835da490342bd25ecb6fe7b1e`. Bounded
APK resource scan passed (receipt SHA-256
`262d0bc2bee8d7ee2b715ad997f78e978fbaf2b9c6496c57373301dea798b0f1`). The
retry-6 pair has no emulator or live Hub results. The earlier 38 Kotlin / 47
Android test results belong only to retry-4 app/test pair
`1811e156012eb4996c8740ab875d4ac142bb1979ba0f1b0cfe94c1b6a9b4686e` /
`d22756ee8169263b5142997b08825dda60f12331734f923ea7c005965a42c288`.

F1 expired before Owner enrollment. F2 retry-2 passed enrollment/capabilities
then failed local key preparation; retry-3 received Hub `ok=true` but rejected
post-submit status; retry-4's explicit new consent was refused by the prior-
grant conflict. F3 passed 27 scoped steps and failed before Target request
export on a UI selector. F4 passed 27 scoped steps, then the actual UI could
not reach the confirmation control after external signing/proof paste; zero
Target KEY/policy writes occurred. F5 used trusted READY/Root GO. Its initial
runtime preflight failed before any RPC/selector/signer/operation; four
read-only ADB runtime observations then passed. The actual F5 command passed
10 steps through Source KEY manifest/export and exited 1 at `source-key-sign`
(exit 2) because maximum expiry `2026-10-02T15:27:50.050630Z` was not canonical
RFC3339Nano (`2026-10-02T15:27:50.05063Z`, same instant). No signature, Source
KEY grant or policy grant was created; Target enrollment, Alert and policy were
`NOT_RUN`, bilateral KEY/NONE remain blocked. No new proof, nonce or F6 run was
attempted. Full F5 pins and receipts are in the [validation record](client-hub-v1.6.4-25bc586-validation.md).

F5's 11-transaction carrier stopped with no payload persisted. Core cleanup
continuation attests only owned F4/F5 resources removed and six resident
resources unchanged; Client's independent read-only audit found five owned
container/network/emulator IDs absent (receipt SHA-256
`889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7`). The
be72 test APK had a bounded privacy PASS; no private-key bytes were read.

The candidate implements 44 of 55 catalog operations; 11 remain closed.
Native-only gates protect all five Link consent operations; generic RPC rejects
them. Independent Owner pins, current lifecycle evidence, leased reviewer
`link.review` qualification, exact preview/body/proof matching, one-shot Alert
confirmation and durable exact-packet recovery stay in Kotlin. External Owner
signing is required, and Link grants do not turn on ordinary peer messaging.
The candidate is recorded by the Client milestone commit; its exact commit
identity is in the external delivery receipt
`/gpu1-share/data/cicada-client/v164-25bc586-20261002/client-delivery.redacted.json`.
It is not an accepted release.

### Core follow-up

Core requires a separately authorized new scope before any further live attempt. Keep the exact reviewed text and signed bytes intact;
never accept an unsigned/null-signature final attestation or Owner proof;
preserve its contractual signing preimage. Do not alter reviewed content, extend
the proof TTL, or use Owner renewal to work around the immutable prior proof. The confirmation
control must be visible to the actual UI flow before a user action is recorded.

> Independently review Client `dev/react-native` and this delivery receipt.
> Keep Core `25bc586232db43362c6e03eccef1fa3a0dbec8ee`, protocol v1.6.4 and
> Hub image `sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4`.
> Use app `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67`
> and test `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`.
> For a separately authorized fresh scope against this fixed Hub/image,
> issue trusted READY pins and Root GO. Use only the retry-6 app/test pair and
> run the Target actual React Native review through the visible explicit Alert,
> then complete bilateral KEY and NONE status with both independent Owner pins.
> Include lost-response and exact-original-packet recovery faults. Preserve the
> contractual signing preimage and never accept an unsigned/null-signature final
> attestation or Owner proof. Do not extend TTL, rotate a proof, use a new nonce
> to evade F5, read or mutate Hub DB from Client, call models, or transfer the
> retry-4 38/47, be72 F5, or historical v1.6.1 results. Return exact pins,
> commands, exits, proof/status results and redacted cleanup evidence.

One conservative reconciliation edge remains explicit: the saved consent tuple
contains peer Owner lifecycle only when a fresh `link.key_grants` read verified
it. If a terminal policy status reports the peer side VERIFIED but that peer
lifecycle was absent from the saved tuple, the Native historical-result check
retains the fence rather than inventing or inferring lifecycle state. Confirm
Core's link-state guarantee before treating that uncommon case as resolvable.

## Prior handoff — Link verification and two-Owner status acceptance

This milestone keeps the accepted Android runtime at clean Core 144e079 /
Client-Control v1.6.1. It separately imports the clean e8a029d / v1.6.3
delivery and prepares five closed Link consent operations. No APK was rebuilt,
and no old Android result is attributed to v1.6.3. The delivery commit is bound
after commit in the restricted receipt referenced by the validation records.
The milestone's evidence index and delivery receipt are respectively
`/gpu1-share/data/cicada-client/link-consent-candidate-20261002/acceptance-manifest.redacted.json`
and `client-delivery.redacted.json` in that same private directory. They bind
the actual Client commit, final source fingerprints, historical APK pair,
per-command exits and both distinct Core releases.

| Item | Result | Record |
|---|---|---|
| Clean v1.6.3 archive, manifest, immutable images and 835-input source reconstruction | PASS | [Pinned e8a029d provenance](client-hub-v1.6.3-e8a029d-validation.md) |
| Offline Link DTO, scope/confirmation and recovery-model checks | PASS | 86 JavaScript tests, TypeScript and lint; zero added warnings |
| Independent Kotlin Endpoint/Owner proof and policy checks | PASS | 16 host-JVM tests, including complete retained public synthetic evidence |
| Strict three-container/three-bridge native fixture adapter | PASS | 13 isolated Python tests and exact live topology/mount verification |
| v1.6.1 Android enrollment and encrypted capabilities for both Owners | PASS | Two independent profiles and device public keys; two selectors |
| v1.6.1 Link metadata/refusal/original-packet recovery, both Owners | PASS | Ten selectors and exact same-Link/opposite-side aggregation |
| Client-owned emulator/carriers and Core-owned fixture cleanup | PASS | Separate cleanup receipts; exact resource absence independently verified |
| v1.6.3 encrypted runtime, new APK and live consent writes | NOT_RUN | Runtime pins and all five consent operations remain closed |
| Configured policy, unrelated third Owner and this slice's revocation/process-death cases | NOT_RUN | No corresponding authorized fixtures were run |
| Current native Goal/model, physical Android and public HTTPS | NOT_RUN | Empty native fixture resumes do not establish these gates |
| v1.6.3 METADATA policy authorization | BLOCKED | Core-confirmed missing reviewer permission and current-binding guards |

See [Link candidate validation](client-link-consent-candidate-validation.md)
for command receipts, initial failures and the exact remaining integration work.
See [two-Owner Android status validation](client-link-status-native-fixture-144e079-validation.md)
for immutable APKs, compiled source, native fixture attribution, all command
exits and redacted evidence. The aggregate receipt is
`/gpu1-share/data/cicada-client/link-144e079-20261002/two-owner-link-status.redacted.json`,
SHA-256 `ba6f808dbe5368d25d1c819399fb23b72632abf87b76c61289d110a9f7baf4c9`.
Original failed preflights and UI preparation attempts remain retained.
Core's separately executed cleanup removed its three containers and three
bridges. Ten independent Client queries confirmed no exact-ID or fixture-label
resources remain, including stopped containers. Evidence is
`/gpu1-share/data/cicada-client/link-144e079-20261002/core-cleanup-absence.redacted.json`,
SHA-256 `15f38f6af0168658dd84352ec4ca26c62d277e2e045ba848f422f8cab2e7b132`.
Private fixture files remain under Core supervisor custody; no directory
deletion or resident-Hub modification is claimed.

Fresh encrypted `link.key_manifest` is the Hub-authoritative single-transaction
current scope. Client integration must bind that authenticated result to the
selected profile/session and re-fetch before signing; a second topology API
is not required. Endpoint self-attestation and Owner consent signatures remain
independent checks. Hub-discovered full Owner keys do not establish trust:
local and peer Owner identities require independent pins and current lifecycle
checks. The offline pending model is ephemeral and cannot replace the existing
native persistent signed-packet recovery path.

Core confirmed that fixed e8a029d policy preview/grant does not enforce current
`link.review` permission and a leased reviewer SessionBinding. Runtime review
guards do not establish policy-grant eligibility. Core is preparing a correction;
this fixed image is not relabeled. All five Link operations remain closed,
alongside the Group directory permission extension, pending their respective
dedicated native integration and Android acceptance. The local policy remains
39 implemented / 16 closed; ordinary cross-user messaging stays unavailable.

### Next Core maintainer prompt

> Review the Client branch and these three formal records without transferring
> the old144 APK results to clean e8a029d/v1.6.3. Verify the source inventory,
> archive/image pins, offline proof vector and the two-Owner Android receipts,
> including retained original failures. Supply a new clean fixed delivery with
> preview/grant rejection tests for missing/revoked `link.review`, expired
> reviewer bindings and current-scope changes. Specify the supported independent
> Owner identity/pin and key-lifecycle inputs for local and peer Owners. Then
> coordinate dedicated native manifest/proof/explicit-confirmation/grant/status
> integration and original-packet recovery using a separately attributed APK.
> Keep METADATA and all unaccepted consent operations closed until those gates
> pass. Preserve separately attributed old144 cleanup/absence receipts. Do not
> place private keys, Node bearer
> or model credentials in the Client, and do not merge or push this Client work.

## Candidate handoff — explicit Group directory permission

The [candidate preparation record](group-directory-permission-candidate-validation.md)
documents the read-only v1.6.2 specification, exact existing-topology action,
independent DTO and confirmation guards, command receipts and remaining release
inputs. Production entry stays closed. This implementation introduces no RPC
and does not replace the accepted Core 144e079/v1.6.1 source, APK or runtime
attribution below. Owner confirmation addresses one Principal's whole Group
Membership; Join/Monitor roles do not confer `directory.read`. Original pending
packets and dedicated uncertainty fences remain intact.

Offline Docker checks passed 79 JavaScript tests, TypeScript, lint (zero errors,
23 existing warnings), four pure Kotlin tests and the unchanged accepted
contract checker; all final exits were zero. The initial lint failure remains
separate. Commands, input hashes and full delivery commit are bound in
`/gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/client-delivery.redacted.json`.

The complete clean v1.6.3 archive and immutable image pair are now independently
verified. Native integration and separate Android acceptance are still required
before the action can be enabled. The candidate
record includes the precise next acceptance prompt. Native/model, physical
Android and public HTTPS remain `NOT_RUN` for this slice; no APK or runtime is
started during preparation. Actual Link status has now passed its separately
attributed fixed-144 two-Owner gate above.

## Active clean target — Core 144e079

The fixed target is `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c`,
Client-Control v1.6.1, wire 1. The complete immutable image, archive and catalog
pins, independent source checks, final APK hashes, exact commands and acceptance
matrix are in the [current validation record](client-hub-v1.6.1-144e079-validation.md).
The new checkpoint preserves the application, local STT and all sixteen closed
operations. The corrected final instrumentation APK is distinct from the
retained first-attempt failure.

Current verified gates include independent provenance for 806 inputs and both
images, 21 contract payloads, 81 Android Kotlin tests, UI smoke checks, encrypted
external-role Directory authorization and exact recovery of lost 201 enrollment
and 200 completed RPC responses. The fresh live synthetic processing case
passed run/verify (409), the fresh uncertainty retry passed run/verify (signed
200 plus authoritative snapshot), and legacy recovery passed its Android
selector and independent carrier/absence checks before teardown. Original
driver and outer-wrapper failures remain separately recorded; no correction
is represented as an original driver PASS.
Actual Link status has passed the bounded two-Owner native-fixture gate above.
This does not establish configured policy, bilateral consent, Link activation,
message delivery or a Worker Goal. Physical Android, public HTTPS and current native/model execution
remain NOT_RUN. No push or merge is performed.

The dated prior sections below retain their original source and artifact
attribution; they do not describe the current image or transfer acceptance.

### Current handoff and Core maintainer prompt

Final app/test APK SHA-256:
`74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` /
`17fd9e576c821eee3c5d7f434e40a29fc320d884d241c8a7c084960dea4f2621`.
Compiled input fingerprint is
`8a08d5775a7b6abbd9187fc6c91420f5c9d66b859e1692329a43620565ba0a5e`
over 118 files. The exact full delivery commit is bound in
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/provenance/client-delivery.redacted.json`.

| Remaining item | Status | Required Core input |
|---|---|---|
| Both Owners read default/current Link policy metadata | PASS | Fixed-144 native-fixture Android receipts above |
| Configured policy metadata / genuine foreign Owner denial | BLOCKED | Actual Link, independent signed Owner proofs and a real unrelated Owner scope |
| Current native Node/Worker/model execution from Android | NOT_RUN | Separately scoped native acceptance; Core-only results do not transfer |
| Physical Android and public HTTPS | NOT_RUN | Actual device and independently pinned HTTPS deployment |

> Review only the clean Core 144e079 / Client-Control v1.6.1 checkpoint and its
> immutable Hub/interop pair. Check the final APK hashes, source fingerprint,
> per-command exits and retained failures in the linked validation record and
> external receipts. Distinguish the authorized synthetic live processing
> injection from a real concurrent business operation. Preserve the original
> uncertain/legacy driver failures; use the fresh uncertainty retry and legacy
> absence/receipt verification before teardown at their stated layers. Keep
> all sixteen unsupported consent operations closed. Supply a supported
> disposable producer that obtains real native Session IDs and explicitly
> joins both Owner Endpoints, creates Groups through encrypted Client RPC,
> then creates/accepts a bilateral Link through supported APIs. Deliver only
> public selections and proof material to the Client; keep Owner private keys
> and Node/model credentials external. Do not fabricate native IDs or database
> rows. Default NONE/current is unconfigured metadata. The current Link block
> is independent of passing recovery gates. Plan any later contract or native
> acceptance as a separate fixed checkpoint; do not transfer Core Go/native
> results, older APKs or physical/HTTPS claims to this Android record.

## Historical final-gate preparation

The current working tree prepares the next integration gate without changing
the existing Core, contract or image pins. See
[final gate readiness](client-final-gate-readiness.md) for the required final
delivery, reusable drivers, fixture dependencies and execution order.
The old 38/30 Directory assertions have been replaced by exact independent
catalog/implementation/role intersections; the current policy remains
39 implemented and 16 closed operations. The corrected instrumentation and
new live harness still require a new test APK and their own acceptance records.

No final candidate APK, emulator, encrypted Hub, native Node, model, physical
Android or public HTTPS run is claimed by this preparation. The independent
[input inventory tooling](hub-input-inventory-verification.md) has separately
recorded synthetic and intermediate source-only checks. Those results do not
accept a new image. Keep the current and historical milestones below unchanged;
combine necessary code and final evidence at the next complete commit.

## Historical implementation slice — Link review policy status

Only `link.review_policy_status` is added to the local implementation set. It reads one exact Link from encrypted `link.list` through a dedicated, scope-bound native path. The policy now accounts for **39 implemented and 16 closed operations** out of 55. This is an implementation count, not live acceptance. The existing v1.6.1 contract and image pins are unchanged.

The view reports Hub metadata only. Default NONE with policy version 0, empty digest/sides and `current=true` is explicitly unconfigured. It does not establish Owner signature verification, bilateral approval, reviewer decisions, Link activation or message permission. Original-packet recovery and all uncertain-write fences remain in force. No private Owner key, signer, policy write or key Grant is added.

See the [dedicated validation record](client-link-review-policy-status-v1.6.1-validation.md) for the new source/artifact attribution and offline checks. New encrypted Hub, Android runtime, Node, model, physical-device and public HTTPS acceptance remain **NOT_RUN**. A live gate awaits the final clean Core candidate. Historical evidence below keeps its original commits and APKs.

Final offline gates: **PASS**, 67 JavaScript tests, five pure Kotlin host-JVM tests, 11 public-fixture checker regressions, TypeScript, lint (0 errors/23 warnings), the public-contract role intersection and both APK builds; every exit was 0. The new app/test APK hashes are `74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` / `fd36c9f56f0c4b3de335e4b458fd7c5d0ca9590b591e716b8bf70077dcca170f`; source FP is `8ffe7b8855c82250505fb7a572ebe604355769905ae4bfbba648f4620b5ac538` over 116 files. Two synthetic Session cases were compiled but remain **NOT_RUN**. The full milestone commit is bound by `/gpu1-share/data/cicada-client/v161-link-policy-status-20261001/provenance/client-delivery.redacted.json`. No push, merge, runtime fixture or model call was performed.

### Current Core maintainer prompt

> Review the dedicated `link.review_policy_status` read path against unchanged v1.6.1. Require a fresh encrypted owner-scoped `link.list`, exact Link ID/version, current device and session permission. Treat default NONE/current as unconfigured metadata. Keep the other 16 closed operations, all Owner signing and uncertain-write fences closed. Supply the final clean Core candidate before a separately authorized Android encrypted status/recovery run. Cover default/configured metadata, stale versions, foreign Owners, missing capabilities, Hub switching and recovery of the original packet. Attribute that run to these new APKs and its own receipts; do not transfer earlier APK results or infer peer/model delivery.


**Provenance supplement:** independent retrospective reconstruction now reproduces the immutable v4 fingerprint from all 773 pinned inputs, exit 0. Original build-time per-file mode capture remains **NOT_PROVIDED**. The earlier BLOCKED record is preserved; current live acceptance stays unrun. See the [separate supplement](client-hub-v1.6.1-fe565b4-provenance-supplement.md).

**Prior checkpoint provenance gate: BLOCKED.** At milestone `d580975`, the archive and pinned Git blobs matched, but the raw-permission fingerprint was not yet independently reproducible. That original result remains preserved; the supplement above records the later retrospective match. No live Hub or native-runtime acceptance is claimed; see the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md).


## Prior checkpoint — Client-Control v1.6.1

The final corrected checkpoint passed the pinned offline build, 59 JavaScript tests, TypeScript, ESLint (22 warnings, no errors), 74 Kotlin tests across 14 selectors, and five offline UI checks; every gate exited 0. App/test APK SHA-256 values are `6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816` and `abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec`; compiled source FP is `0b89a85d5c332faffb980851501c474942f28c1b047562e0daa547f27a32d7f0` over 112 files. The owned emulator was removed and six resident containers were unchanged. These are local checks, not live Hub or native Monitor acceptance. The full Client commit is recorded in `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/client-delivery.redacted.json` after the milestone commit.

The deterministic integration target is clean Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, protocol `client-hub-v1.6.1`, wire 1, catalog `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` and immutable Hub image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. See the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md) for archive/source pins, exact DTO verification, commands, artifacts and individual acceptance states. Earlier evidence below is historical and does not establish this checkpoint.

No new Hub, Node or model runtime is started in this checkpoint. Current encrypted runtime capabilities, native Endpoint/Monitor acceptance, physical Android and public HTTPS remain unaccepted. The 38-operation local policy and 17 closed operations are retained; no advertisement or synthetic proof authorizes a closed operation. Terminal regroup `OUTCOME_UNCERTAIN` retains its exact ciphertext/counters and dedicated fence.

### Prior Core maintainer prompt (before the supplement)

> Review the Client v1.6.1 deterministic checkpoint against immutable Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, catalog `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` and Hub image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. Supply independently reproducible clean build-input provenance, including full filesystem permission bits: Git records only executable bits, while build-inputs-v4 hashes full `stat.S_IMODE`. Confirm the distinct `NodeControlKeyBinding` confirmation and `NodeDeviceBinding` list/revoke DTOs without changing the accepted image or claiming old Android evidence. Preserve encrypted original-packet recovery and terminal regroup uncertainty fences. A later real Monitor fixture must use supported Network/Endpoint bootstrap, explicit current source/target Membership and the same genuine native Session; synthetic authority is not acceptable. This checkpoint starts no Hub, Node or model runtime. Return exact pins, reproducible commands, individual exits and redacted evidence; request a separately authorized acceptance run before any new native/model fixture.

## Historical integration target — clean Hub `4fb241b`, Client-Control v1.6

The current integration target is clean Core commit
`4fb241b5e824eb752ceb85586089f44c408e1e7e`, protocol `client-hub-v1.6`,
wire 1, catalog SHA-256
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`, and
source fingerprint
`31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2`.
The successor archive SHA-256 is
`9ada56ced408e90fbdf2a224897cf43fee2d325e6963f8f1714b0ef888f4f689`.
The exact Hub image is
`sha256:a48ce4b096f4d003ed6f8586674f4c175ce8616005dc65e7cbf9e9edaededf65`;
the interop test image is
`sha256:e2268a08ef1b27619ff6dc7039e8f883518130c5292384967d973cb759b3b810`.
The imported snapshot is
[`contracts/client-hub-v1.6-4fb241b/manifest.json`](../contracts/client-hub-v1.6-4fb241b/manifest.json).
Its redacted import receipt is `/gpu1-share/data/cicada-client/v16-4fb241b-20261001/provenance/contract-import.redacted.json`, SHA-256
`d67b2c2592998e2bb7d5e0cdf8c20fac9838a319ec79de5d36968c8ccc984f75`.

The [current validation report](client-hub-v1.6-4fb241b-management-validation.md) records the final guarded artifacts:

| Item | Value |
|---|---|
| App APK SHA-256 | `93d49088524c09c1d74466137e9503e388774a196a202539eec58c8d8d51ae9d` |
| Instrumentation APK SHA-256 | `041f6af9b7f4ecd20abd7c5b00275fe73336fe41e0522c9f3d05a03b8328cf02` |
| Compiled source fingerprint, 110 files | `e758625224b056a32a0ddb0d498606a6a49522f623a6c0173704a4896641cffb` |
| Final offline gates | **PASS**: Docker build, 56 JavaScript tests, TypeScript, lint, 71 Kotlin tests/13 selectors and five UI checks; exits 0 |
| Final APK live Hub acceptance | **NOT_RUN** |
| Native Endpoint/Monitor acceptance | **BLOCKED** after the Core native Join failure below |
| Physical Android / public HTTPS | **NOT_RUN** |

The Client commit is the milestone containing this report. The post-commit delivery receipt at `/gpu1-share/data/cicada-client/v16-4fb241b-20261001/provenance/client-delivery.redacted.json` records its full commit, compiled source fingerprint, APK hashes and evidence index without a recursive document hash. The final owned emulator was removed; the six resident containers were unchanged.

Earlier pair `9a6…`/`3cbe…` alone owns the connected Directory read, saved-fixture Group-scope read, external-role oracle, exact enrollment/RPC 201/200 recovery and Node pairing UI PASS receipts. The oracle allowed 30 of 47 advertised operations from the 38-operation local set, with none of 17 closed. Its Group-scope read asserted the snapshot Owner and two ACTIVE Groups in one Network, not per-Group Owner fields or Monitor Membership. The external signer used the Owner private key outside Android; Android did not read/import it. All main and secondary disposable Hub/Node/emulator/carrier environments were cleaned. These earlier connected results are not attributed to the final guarded APKs.

The current Client implements 38 of 55 operations and leaves 17 closed.
`network.directory` and `topology.endpoint_admission_preview` are metadata-only
reads. The explicit regroup panel reads one named proposal and provides a
confirmed one-use issue plus version-CAS revoke, but neither that UI nor local
Kotlin validators establish a live Core authority result. `principal_id` is
the Monitor actor and must not be treated as the Human Owner. `CREATE_CHILD`
permits the same source and target Group ID; `SET_PARENT` requires distinct
IDs. Regroup issue expiry is future, one-use, at most 24 hours and bounded by
proposal expiry. Recovery of a still-pending original packet may accept its
validated cached `COMPLETED` result. After authenticated terminal
`OUTCOME_UNCERTAIN`, however, the current Core contract offers no later
correlated result or clearing route: preserve original ciphertext/counters and
leave the fence blocked indefinitely pending a separately authorized
reconciliation contract. Neither `status.snapshot` nor proposal metadata
clears it.

### Earlier Node pairing UI PASS; native Join FAIL

The earlier app `9a6…` exercised candidate-bound Node pairing; its
panel/parser, five focused tests, TypeScript, focused lint and build pass. The
emulator UI flow passed against same-Hub attach-3 public pins at
`/home/zyf/CICADA_native_e2e/.cicada-data/m4-native-attach-3/node-pairing-public-pins.json`
(SHA-256 `98c8dc0fe6e498b14d224f0ae368c3cbed251587313c2c18ab0554f6c418b333`,
candidate v1, expiry `2026-10-01T19:54:32Z`). It checked all candidate fields
against independent public pins, confirmed both trust controls, sent the
preview-bound confirmation through the product Alert, and refreshed
`nodes.list` to verify the same authorized Node and positive binding version.
The `nodes.confirm` RPC returned only an acknowledgment; `nodes.list` supplied
the binding record.
The redacted receipt is
`/gpu1-share/data/cicada-client/v16-deterministic-offline-management-20261001-final/android/node-pairing-ui.redacted.json`,
SHA-256 `b9b26faea3d2ecdfc7469898892a684097717be8a662ec70641956fd16a35815`;
all 143 UI steps exited `0`, and no code or UI dump was persisted. Its original
receipt is kept in `history/` with a metadata-only correction record. The
command wrapper receipt `node-pairing-ui-command.redacted.json` has SHA-256
`261de4b594ac5f457a8b28f1a40cbfcc8211fc1d9d21fbc5a4b4fe13c2267c09` and exit
`0`; it binds the public pins and the tested earlier APK hashes. The
candidate has expired; refresh before any later attempt. Five earlier UI
helper attempts are preserved at `history/node-ui-attempt-{1..5}.redacted.json`
and did not complete a prior confirmation.

Pairing confirms a Hub binding and does not establish native Thread Join.
Core's redacted controller result reports current Node authority HTTP 200 and
two CLI turns on the same original Thread, followed by a native Join tool
failure with Hub HTTP 404. Core's failure classification says Fabric requires
an existing Endpoint when the Group has non-empty `NetworkID`; Network
enrollment is a separate prerequisite, not a direct Group bootstrap route.
The exact redacted Core receipts are `result.json` (SHA-256
`bb44440bcd8f3a0a13f0d51a22f2a55fa208be99b3ec68885d360ae3dae229b3`) and
`join-failure-classification.json` (SHA-256
`9beb504c287c81c9734ea445771760178f2530578fbbf6dcfaddbe7bbe9e5e03`) under
`/home/zyf/CICADA_native_e2e/.cicada-data/m4-native-attach-3-controller-2/`.
All 13 recorded subprocess phases exited `0`; the Join tool itself failed.
The actual controller terminal exit was `1`, witnessed by the exec session and
recorded in `controller-execution.redacted.json` (SHA-256
`b26d1f918644f98b079546e656e43ab2ba4d9f40247b915ef5dec3bb79a70ffe`). That
receipt explicitly says the full argv was not retained; do not reconstruct
or publish an inferred command. Core cleaned the Node/runtime.
No native Endpoint admission preview, regroup proposal/issue/revoke,
or Monitor application has passed. The confirmation response is acknowledgment-only; `nodes.list` returned the
binding. The wire result table labels the relevant record
`NodeDeviceBinding`, while the Core path uses `NodeControlKeyBinding`; the UI
flow does not resolve this pinned result-shape discrepancy.

The earlier Client saved-fixture selector command and receipt are recorded in
the validation report (`group-scope-current.redacted.json`, SHA-256
`0833612aae9512bb86c4e9ddd90d85d93063f968e58fdc8f7765e170031efe94`). It
does not assert per-Group `owner_principal_id` or Monitor Membership; the
Node pairing evidence also exports no per-Node Owner field. Do not infer
either authority relation from the Owner-domain snapshot or authorized
`nodes.list` result alone.

Final secondary fixture cleanup passed with receipt SHA-256
`aa3e31cb59846b7b10ceca46914069036aadda01926035a8a528ffbfcb6d28c8`.
Subsequent main-fixture cleanup passed with receipt SHA-256
`9b2467ab7bfa3572476c4f8848c2f3ace0005e58f8271ccf35222313d61c59ff`: the
owned Hub/network/emulator and fixture root were absent, carrier PIDs and
reverse mappings were gone, and six resident containers were unchanged.

### Historical Core maintainer prompt — clean 4fb241b

> On clean Core `4fb241b5e824eb752ceb85586089f44c408e1e7e` and its pinned
> `client-hub-v1.6` contract, preserve the current authority Guards and supply
> a disposable, redacted acceptance fixture. Follow the supported native
> Endpoint/Network enrollment path first: a fresh Session's direct Join into
> a Group with non-empty `NetworkID` failed HTTP 404 because the required
> Endpoint did not yet exist; Network enrollment is a separate prerequisite,
> not a direct Group bootstrap route. Then provide an exact Monitor-created
> regroup proposal with Monitor Principal distinct from Human Owner, current
> source/target Group versions, Node binding/epoch, and the Monitor's explicit
> current Membership in the target Group with its revision. Do not infer
> Membership from Group existence or proposal visibility, and do not invent
> Thread authority. Exercise `SET_PARENT` and same-ID `CREATE_CHILD`, Owner
> device confirmation through encrypted Client RPC, one-use expiry,
> stale-version refusal, delegation-version-CAS revoke, and Monitor replay
> refusal. Keep the Node DTO mismatch explicit until wire and implementation
> semantics are aligned: the wire names `NodeDeviceBinding`, while the
> implementation path reports `NodeControlKeyBinding`. Preserve the Client's
> terminal `OUTCOME_UNCERTAIN` fence; a generic snapshot or proposal
> projection cannot clear it. If future reconciliation is required, define a
> separately authorized, operation-correlated Core result/clear contract.
> Return exact pins, commands, exits, redacted receipts, and cleanup status;
> do not add unpinned APIs or weaken Guards.

### Core-owned fixture and acceptance request

Please provide a disposable fixture on the exact 4fb241b image for these
existing v1.6 operations. Supply redacted evidence and public IDs only; keep
Node credentials, Owner private keys and native/model credentials outside the
Client and repository.

1. For `network.directory` and `topology.endpoint_admission_preview`, bind a
   current Owner, ACTIVE Network, opted-in directory Endpoint and joined native
   Endpoint to complete attestation, Node, native Session and current binding
   identities/revisions. Include stale/expired/revoked binding cases. The
   preview must return exact current CAS coordinates and must not create an
   admission, Join, key, history grant or route.
2. Provide an exact Monitor-created regroup proposal with Monitor Principal
   distinct from Human Owner, Endpoint and Node binding, ACTIVE Network,
   ACTIVE source/target Groups and current versions. Include the Monitor's
   separate explicit current Membership in the target Group and its revision;
   Core's Guard requires this record, which ACTIVE Group rows alone do not
   establish. Cover `SET_PARENT` with distinct Group IDs and `CREATE_CHILD`
   with identical source/target ID.
3. Exercise Owner confirmation through the encrypted Client device session;
   verify exact proposal/Hub/Owner/Network scope, current Group-version checks,
   one-use expiry, exact delegation result, version-CAS revoke, stale CAS
   refusal and Monitor application replay refusal. Revoke must remain testable
   after Group versions change when its reviewed delegation ID/version is still
   current.
4. Induce issue and revoke response loss only in this owned disposable
   fixture. While the exact packet remains pending, show original-packet
   recovery and a correlated cached `COMPLETED` result. Separately show that a
   terminal authenticated `OUTCOME_UNCERTAIN` retains original ciphertext and
   counters and leaves the regroup fence blocked indefinitely under the
   current contract. No later completion or clearing route is defined;
   neither a generic snapshot nor the proposal's current delegation projection
   may clear that fence or authorize a new operation ID. Any future manual
   reconciliation requires a separately authorized Core contract.
5. Return exact image/fixture pins, command exits and redacted receipts, plus
   cleanup status. Do not add production routes or shared-Hub fault switches
   for this validation.

The corrected final Client guard requires unique current Principal Memberships in both source and target Groups, Endpoint association with both Groups, positive projected Membership versions and a current source Monitor role. Rendering and both confirmation checks use current topology; Kotlin rechecks fresh authority before sealing. The roles-only Monitor case is accepted. These local controls passed synthetic regressions, not live Monitor acceptance.

Provide a fresh complete native Network/Endpoint and explicit target-admission fixture before repeating live acceptance. If the supported bootstrap requires a successor Core version, deliver a clean full commit, complete contract archive, catalog hash and immutable image proof first; do not patch the accepted 4fb241b archive or transfer any earlier result. Record exact command argv and process exits for the next native run. The current 17 closed operations and terminal regroup uncertainty fence remain unchanged.

## Historical bounded integration checkpoint — clean Hub `f4e4725`, Client-Control v1.6

This section preserves the earlier f4e4725 evidence and request. It is not the
active target above and does not certify the 4fb241b image or APK.

The f4 checkpoint target was the independently pinned clean Hub commit
`f4e4725c5d81c54b166f4291b9d450c70954e6df`, protocol `client-hub-v1.6`,
and immutable local image
`sha256:6a7e0af78d3d14369f451760541b54d49a6e9505a1c813aa1124186176d4f5c9`.
The catalog SHA-256 is
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`;
the archive SHA-256 is
`54234527064c5923f9b40d4ac2f602c702e6dbc47fe7b52185da823c97c10fbd`.
See [the historical f4 v1.6 validation record](client-hub-v1.6-f4e4725-validation.md)
for commands, actual artifacts and per-layer results. Sections below retain
historical checkpoint evidence and do not certify the v1.6 image or APK.

The 55-operation catalog is an advertisement. Local implementation, fresh
encrypted role authorization, exact Owner/Network scope, current authority,
and the server Guard remain independent conditions. The original 13 closed
operations remain closed. Seven additional v1.6 proof/consent operations are
closed. The two candidate read operations perform fresh authorization and
projection checks; Endpoint admission preview never authorizes an admission,
native Join, key grant, history access or message delivery. Positive Endpoint
preview requires a separately delivered current native-authority fixture.

Independent Policy, TASK and BROADCAST synthetic vector checks establish only
canonical byte and signature compatibility. They do not establish deployment
Owner trust or a complete current Endpoint proof. The BROADCAST fixture carries
an abbreviated opaque candidate attestation, which the verifier does not treat
as a trust anchor. No collaboration grant or policy approval path is enabled.
Network direct-grant business uncertainty cannot be cleared by `status.snapshot`.

### Historical bounded v1.6 acceptance and delivery

| Item | Result | Evidence |
|---|---|---|
| Clean bundle / exact Hub and interop image provenance | PASS | `v16-f4e4725-20261001/provenance/contract-import.redacted.json` |
| Contract checker and negative import cases | PASS, exits 0 | 21 payloads; 10 negative tests; `checks/contract-check.json`, `checks/contract-rejections.json` |
| Final Debug app/test build | PASS, exit 0 | `build/build.receipt.json`; source fingerprint `1fca907f2e4f727f2a29e626c2e1e754e54036055dcd74f4cea5d1a21779226f` (102 files) |
| Independent Kotlin vectors and local guards | PASS, 63 tests | Final matrix: 12 selectors, adb/driver 0/0; Policy/TASK/BROADCAST account for 9 synthetic vector tests |
| JavaScript / type check / lint | PASS, exits 0 | 34 tests; lint has 21 warnings and zero errors |
| Offline Android product UI | PASS, exit 0 | Five scope/connection checks; no connected UI claim |
| Encrypted v1.6 capability/catalog and exact role intersection | PASS | External role: 47 advertised, exact 27 locally allowed; `role-oracle.redacted.json` |
| Enrollment 201 loss and original Grant/request recovery | PASS, 0/0 | Two selectors; same request SHA and registration bytes; no replacement nonce |
| RPC 200 loss and original ciphertext `COMPLETED` recovery | PASS, 0/0 | Two selectors; same request and cached envelope SHA; sequence 8 / next 9; pending cleared |
| Empty directory and unselected foreign Network refusal | PASS, bounded | Fresh ACTIVE scope; zero cards; local refusal precedes transport |
| Nonempty directory / positive Endpoint preview and native authority | BLOCKED / NOT_RUN | No native Endpoint in the disposable fixture; no operable preview UI |
| Three ledger recovery faults / live replay / revocation | NOT_RUN | No new v1.6-owned ledger-fault fixture; old evidence is not transferred |
| Native Node/Codex/Monitor/consent; physical Android; public HTTPS | NOT_RUN | Separate current-image/platform acceptance required |
| Fresh speech-model execution; iOS; native HarmonyOS | NOT_RUN | Existing STT retained; no new inference or platform claim |
| Owned carriers, reverse mappings, VMs and Hub/Network/key cleanup | PASS | Coordinators/inner carriers 0; proxies requested SIGTERM (-15); cleanup 0; owned resources absent |

Evidence prefix is `/gpu1-share/data/cicada-client/`. Final Android evidence is
`v16-deterministic-f4e4725-20261001-final/android/`; build/check/fixture evidence
is `v16-f4e4725-20261001/`. Every selector command and exit is retained there.
The exact app SHA-256 is
`b853346ecd185a4713b1f90838275e456972f85fdd1cbddd9b527dc761511c46`;
the test APK SHA-256 is
`4effb0bc069039865f028c75251b2aef9d99a19fefc20d159194bfa9bcb4072b`.
The source base is Client `9b17f8fb25bb8f3e66e03e0190b63a022e93a895` plus the
recorded fingerprint. The final Client commit and filtered-Git comparison are
in `v16-f4e4725-20261001/delivery.redacted.json`; the containing Git commit
identifies this report without a circular self-reference. This is one coherent
local milestone; no push or merge.

Initial Long/Int compilation failure, Policy test fixture identity mismatch,
and two staging mistakes remain in restricted history with original artifacts.
They are corrected and excluded from the final acceptance counts. The added
staging CLI was syntax checked but not independently executed after cleanup.
No real Owner/Node/model credential entered the APK or Git. Android's synthetic
device keys were destroyed with its owned VM, and Core fixture cleanup removed
both synthetic Owner private keys. No resident deployment was changed.

### Historical f4e4725 integration request (superseded)

The following request applied to the f4e4725 checkpoint and is retained as
history. Use the active 4fb241b fixture request above for current work.

```text
Review CICADA_CLIENT dev/react-native and the v1.6 validation record.
Reconcile source/Client/APK fingerprints and receipt command exits with the
clean f4e4725 archive, catalog and full local Hub image ID. Preserve all
historical failures and do not transfer older native Android PASS results.

Provide an owned, disposable Node/current-authority fixture on the exact
f4e4725 image: explicit native Join, opted-in directory.publish enrollment,
and current Network access/native bindings for one exact Owner, Network,
Group and Endpoint. Supply only public IDs and the declared read-only fixture
entry point. Node bearer and native/model credentials must stay outside Client.
The intended Android calls are encrypted network.directory and
 topology.endpoint_admission_preview. The preview must return exact current
CAS coordinates and history_included=false/key_grant_created=false; it must
not create admission or keys. Provide stale/expired/revoked binding controls
for refusal tests without changing a shared Hub or exposing a production fault
switch. Until these conditions exist, the positive preview remains BLOCKED.

Keep the seven v1.6 proof/consent entries and original thirteen gates closed.
A full candidate Endpoint attestation and independently trusted current Owner
projection are required before a future collaboration/policy grant flow.
Keep Network direct-grant business reconciliation separate from outer RPC
recovery. Physical Android and public HTTPS remain separate acceptance items.
```


**Date:** 2026-09-30

**Branch:** `dev/react-native`
**Delivery:** one local implementation and validation checkpoint; no push or merge.

## Release public-interface policy test correction

The [bounded policy correction report](release-policy-public-validation.md) follows packaging Client `329a65942a2e10e5d658cfe58472bb53bad2cb7d`. Luna(max) replaced the positive test's private-method reflection with public `rpc`/`getStatus` behavior and an in-memory synthetic signed/encrypted response. Device private-key access is not exposed to the test responder; its Control identity exists only in memory. The other three public rejection tests retain their semantics.

- **PASS:** instrumentation-only offline build, exit `0`; all four unsigned product APK hashes unchanged; target R8 task `UP-TO-DATE`.
- **PASS:** one owned offline Android 15/API 35/x86_64 run, `OK (4 tests)`, zero failures, ADB/driver exits `0`, 0.764 seconds. Manager/external cases start with unready capabilities, then verify the exact filtered operation set, counters and pending cleanup through the public session path.
- **PASS:** exact-owned emulator and fresh disposable signing-secret cleanup. The original policy FAIL and original STT staging FAIL remain in their existing records.
- **NOT_RUN:** crypto/STT reruns, live Hub, native Worker, physical Android, public HTTPS, iOS and native HarmonyOS. Production source, keep rules, authority, dependencies, contract pins and deferred gates were not changed.

Reused unsigned x86_64 product SHA-256: `78e3538522d54826d391b1e3873499dfecc0eeb2eac5499a0442cec7cec53940`. Installed app copy: `656f218133d74f6d3f95b3fd8aba64754dde4c7a62e02296e09a6b621e155cb5`; installed new test APK: `4270a762fe1c62da4917a8f0be2a0988e1ca78671eb8ec2e6d83b05ad1e3937b`. A fresh disposable certificate was necessary because the prior test private key had been deleted; non-signature product payloads match exactly.

New instrumentation checkout fingerprint: `64409378c261e6a1ae6b7327f86a4118d6866e8564ac48cbff018aa50dbcd6da` (92 files). Unchanged product-only input fingerprint: `25e905b0ef67df24cacdc16ddaf190e2e1edfaae9438ab69ca07041c80ef8e7f` (60 files). The product retains the packaging source attribution below. Client commit and matching committed-source verification are recorded in `/gpu1-share/data/cicada-client/release-policy-public-20260930/evidence/delivery-checkpoint.redacted.json`. Runtime evidence is `/gpu1-share/data/cicada-client/v15-deterministic-release-policy-public-20260930/evidence/`.

Core review request: reconcile this report's test-only diff, original product hash, new instrumentation/signing hashes, actual four-test count, command exits and exact-owned cleanup. Keep the process-scoped synthetic transport distinct from live Hub/TLS acceptance and preserve the original failed-run attribution. No push, merge or publication is part of this delivery.

## Local Release packaging checkpoint

The [Release packaging validation report](release-packaging-validation.md) records the subsequent bounded packaging work from Client `feb0cd2`. The immutable Docker toolchain, source fingerprint, actual ABI APK sizes and SHA-256 values, native-library/ELF inventory, exact commands and preparation failures have separate evidence. These local unsigned artifacts and disposable signed test copies are distinct from the framework and fixed-Hub APKs below. No Hub interface, operation gate or signing authority changes as part of packaging.

The per-ABI Release profile preserves the default Debug APK path, uses R8/resource shrinking and retains the existing STT and crypto dependencies. The original four-ABI Debug package was already natively stripped; the new measurements do not attribute its existing stripping to this checkpoint. Physical Android, ARM runtime, public HTTPS and fresh live Hub acceptance remain separate unrun gates.

- **PASS:** offline build and unsigned artifact audit for all four existing ABIs. ARM64 is 58,052,430 bytes, compared with the archived 296,177,563-byte four-ABI Debug file; this is an APK-file comparison, not installed size or an isolated R8 saving.
- **PASS:** final Release x86_64 Android 15/API 35 offline startup; 5/5 independent public Kotlin crypto vectors; one real Paraformer inference and Vosk native-binding smoke after a fixture-only staging correction on the same APK. The original failed STT attempt remains recorded. No transcript was logged.
- **FAIL:** Release operation-policy instrumentation is 3/4. One test fails before capability assertions because it reflects on private method names that R8 changes. Existing public rejection tests passed; no production keep rule or test hook was added to mask this gap. Replace that test's private reflection with a public-behavior fixture in a later checkpoint.
- **PASS:** exact-owned emulator removal and disposable signing-secret cleanup. Commands, exit codes, counts, durations and failed attempts are in the packaging report and restricted evidence.
- **NOT_RUN:** ARM/x86 runtime, physical Android, public HTTPS, live Hub/native execution, iOS and native HarmonyOS for these Release APKs. Earlier Debug or fixed-Hub acceptance is not transferred.

Unsigned ARM64 SHA-256: `aa35dcecf44e7a84996dbc485e283e684cba8adb4e62c37503d679d570e71205`; unsigned x86_64 SHA-256: `78e3538522d54826d391b1e3873499dfecc0eeb2eac5499a0442cec7cec53940`. Installed disposable x86_64 app SHA-256: `07d0e8bbe00c5e4488a3f19f65a20537091b3513a80a89dceef18dad49e0f41c`; test APK SHA-256: `d46634bad52d9ddb2d977709a4607be886deb04f2c074249f1dc23cbb85f4e38`. The complete table identifies all four unsigned artifacts. Their compiled-source fingerprint is `38fb1820bff51f81048f74c50dcae26aa2ef85bd9013c8d51f62b511a95cb2eb` (92 files), built from `feb0cd2` plus this checkpoint. The local completion receipt at `/gpu1-share/data/cicada-client/release-packaging-20260930/evidence/delivery-checkpoint.redacted.json` identifies the milestone commit and confirms matching committed source bytes. This remains an observed checkout build, not a rebuilt clean-commit APK.

Packaging review request: read this section and `docs/release-packaging-validation.md`; reconcile the final source fingerprint, four unsigned APK hashes and separately signed test copies with their command receipts. Preserve the policy reflection failure and initial staging failure. Keep all deferred protocol gates closed, and do not extend fixed v1.5 acceptance or count this as live Hub, physical-device or production-release validation.

## Shared-space v2 local framework

The [shared-space v2 framework report](shared-space-v2-framework.md) records the gated review UI and independent candidate-proof work following Client `eb0db6f3d095b60b0f2f73bcfda0079ba33ad846`. Its public vector is from ongoing Core development, rather than a newly pinned contract. The fixed v1.5 report below remains tied to its original APKs and source. Candidate-vector tests do not enable an operation or extend live acceptance. Proposal/delegation UI is a blocked overview, with no fetch, approval, issue or revoke path.

The completed-status verifier requires two independently trusted Owner public identities and current external authority values. It verifies Endpoint self-attestation v1 with its final `signature:null`, while OwnerLinkKeyGrant v2 signs ten ordered claims without a signature field. This is not the first Owner's manifest-preview or signing workflow. Each Owner must later confirm its own side through its own Client before complete dual-proof status exists.

- **PASS:** offline Docker build, 22 JavaScript tests, TypeScript, ESLint, exact 9 Kotlin verifier tests and 4 native operation-policy tests; ADB and test-driver exits `0`. The real offline Management UI showed the collapsed/expanded unavailable state without a fixture or actionable consent control. Owned emulators were removed and confirmed absent.
- **FAIL, corrected:** the initial resource-limit test required the wrong parser rejection reason. Its original failed receipt remains available. The corrected test preserves both integer-overflow and oversized-token refusal, and all nine verifier tests passed after rebuilding on a fresh emulator. Production verification was unchanged.
- **BLOCKED:** positive shared-space consent/admission, delegation/proposal and Link key operations remain closed pending the new pinned proof and authority delivery. No live v2 acceptance or native-session authority is claimed.
- **NOT_RUN:** connected scope selection in the new panel, physical Android, public HTTPS and fresh native execution for this framework APK. Historical fixed-image evidence is not transferred.

Framework product APK SHA-256 is `2ecb5d25f193b1b59c574b51c6383bf4d19617f028ce3b4a926a070113657758`; instrumentation APK SHA-256 is `0a42a512d54d7070d1d22285e4eff2c64ade0885700898962181cb6d20736e22`. The 91-file compiled-source fingerprint is `3d99c7901e0710183f7489e8d0416057a39c5149ac45d116fe47bf7d1d614842`, built from `eb0db6f` plus framework changes. The framework report lists exact commands, exits and restricted evidence paths. Its completion receipt identifies the local milestone commit separately from that dirty-source build.

**Core dependency:** provide an authenticated, minimal, exact-admission read for the Endpoint Owner before shared-context acknowledgement and native Join. The fixed catalog has no preview operation, its topology is Owner-scoped, and key-manifest v2 is available only after the later Join. Core acknowledged this gap; Client has not guessed a route or treated an admission ID as consent. Include the clarified preview, complete proof types and native authority fixture in a new clean pinned package before any positive operation can be enabled.

## Fixed v1.5 delivery

This checkpoint targets clean Core `bd79ff93c90ecafc28a2471dd9523444903b39e6`, protocol `client-hub-v1.5`, and immutable Hub image `sha256:4c321cd8f91a1e19befabd1f5c8983be46e6aed811614c68bd6f62ad06584771`. The independently verified archive SHA-256 is `98ce7f02d03dd8291ff7361e46e22ed893f493d242fcb238a948bf869a2a5d0b`; the catalog SHA-256 is `a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68`. Current dirty Core source is outside this delivery.

The [v1.5 validation report](client-hub-v1.5-bd79ff9-validation.md) identifies the tested source fingerprint, exact APKs, commands, exits, evidence and remaining acceptance items. Historical records below retain their original images, sources and APKs.

The authenticated v1.5 catalog contains 46 operations. The Client admits only its 33 implemented operations, subject to the encrypted session role, scope and existing recovery fences. All seven new cross-Owner Space operations, three new topology delegation/proposal operations, and three unverified Link key operations remain closed, even when advertised by a Hub. The management UI explains that shared-space and delegation management is unavailable. Ordinary cross-user messaging remains disabled when `external_thread_links=false`; `status_events=false` does not expose an event feature.

Existing profile isolation, explicit ACTIVE Network selection, Group management, local speech transcription, persistent enrollment/RPC recovery, Monitor consent records, and the independent durable Network uncertain-outcome fence are retained. No legacy `/v1` bearer path or Hub/Node bearer is introduced.

## Acceptance and remaining dependencies

- **PASS:** archive payloads, fixed Git bytes, clean source metadata, catalog and full image provenance; Docker build and executable checks; 29 JavaScript tests; final APK's 54 independent Kotlin policy/vector/profile/recovery-lock tests; fresh offline React Native UI.
- **PASS:** complete public production-shape Network vector in independent Kotlin tests, including exact signed inputs, native Session commitment, full public keys and negative mutants. This is synthetic proof verification and does not establish live native Network consent.
- **PASS:** fresh fixed-Hub encrypted enrollment/capabilities/topology, exact authenticated external 25-operation allowlist, scoped Group creation and foreign-Owner denial with Core's independent authority audit, and 201/200 original-request recovery. The recovered full response and envelope hashes equal the original dropped response. Bounded connected management UI passed; created Group row/name visibility remains unobserved within that bounded view.
- **PASS:** three independent Android sessions recover the original signed packet as 409 `STILL_PROCESSING`, authenticated encrypted `OUTCOME_UNCERTAIN` after Core's confirmed `FAULT_READY` and single restart, and 409 `RECOVERY_UNAVAILABLE`. Pending/retired ciphertext, operation identity and counters are preserved; the uncertain outer-RPC fence releases only after an authorized read-only snapshot. These helper-driven outer-ledger faults do not establish business execution or native Worker progress. All four live sessions have independently checked exact external 25-operation allowlists.
- **PASS:** exact-owned cleanup. The emulator, five Client carriers and all Android reverse mappings were removed. Core removed its four disposable Hub fixtures and secret state; Client independently confirmed all 18 Core-owned resource absences. Core's receipt records six resident containers unchanged. Exact commands, exits and cleanup evidence are in the validation report.
- **BLOCKED:** positive v2 shared-space consent/admission and delegation/proposal workflows. Core confirmed the future signed-role mapping `ENDPOINT → SOURCE` and `GROUP → TARGET`; no mapping contradiction remains. A separately pinned delivery must supply complete independent v2 canonical/signature vectors, proof and authority validation, external dual-Owner signing and explicit Client confirmation before these operations are enabled.
- **BLOCKED / NOT_RUN:** complete live Network key consent and dedicated original-proof/status reconciliation. The durable Network grant fence remains closed after uncertainty. Generic snapshot reconciliation must not release it.
- **NOT_RUN:** physical Android, public HTTPS, fresh v1.5 native Node/Codex/Monitor execution, iOS, native HarmonyOS and fresh speech-model execution. Earlier version results are not transferred. Dot/Live remains planning only.

The final APK pair was built from checkout `3e5ef5f7c0d045160a7b49bebb3b6ecdd8fc5461` plus changes, with compiled source fingerprint `0a59f8f101f4fd61cf406874e1e441bbc02f0376bbea55c22d92cc58e7a3f948`. Product APK SHA-256 is `5bba1c02fb2b0233006661bd4a67fd3f60811c270cc825f9337c7f4170aaa1ee`; instrumentation APK SHA-256 is `11d8dc7166d539cc91e342553d740f969923d48667498c0c3cf105c5f0a8b5f9`. The completion message and private `delivery-checkpoint.redacted.json` identify the local milestone commit; this does not make the build a clean-source build.

## Review prompt for the Core maintainer

```text
Review CICADA_CLIENT read-only on dev/react-native. Read AGENTS.md,
docs/shared-space-v2-framework.md, docs/client-hub-v1.5-bd79ff9-validation.md
and this handoff. Keep the local candidate framework APKs and synthetic vector
separate from fixed v1.5 live results. Match the exact
clean bd79ff93c90ecafc28a2471dd9523444903b39e6 delivery, full immutable
image, archive and catalog pins in the report. Current dirty Core is excluded.

Reconcile each live Android selector, command exit, original pending packet,
operation/counter continuity, APK SHA and independent authority evidence.
Keep 201/200 loss, STILL_PROCESSING, OUTCOME_UNCERTAIN and
RECOVERY_UNAVAILABLE distinct. Outer-ledger faults do not prove real business
execution or Network-grant reconciliation. Check owned-resource teardown.

Ten new v1.5 Space/delegation/proposal operations and three Link key operations
are deliberately gated. Deliver independent complete v2 signature vectors,
external dual-Owner signing and a native authority fixture in a newly pinned
clean contract. Preserve ENDPOINT-to-SOURCE and GROUP-to-TARGET mapping,
proof-specific canonical bytes, exact domains/digests and fresh authority.
Endpoint attestation v1 includes a final signature:null field; OwnerLinkKeyGrant
v2 signs ten ordered claims without a signature key. Do not generalize one
proof's encoding to another. Each Owner confirms its own side; complete
dual-proof status verification follows both submissions, not the first one.
Deliver the Endpoint Owner's trusted exact-admission preview before risk
acknowledgement and native Join; an admission ID alone is not consent.
Never use an unsigned proof, synthetic native Thread or count-only permission
assertion as acceptance. Keep physical Android, public HTTPS and new native
Codex/Monitor execution separate from deterministic/emulator evidence.

No credentials or Owner private keys belong in Android, APKs, Git or public
logs. Do not edit Client files, push, merge, publish or change resident services
as part of this review.
```

---

## Historical v1.4 handoff

**Date:** 2026-09-30

**Branch:** `dev/react-native`

**Delivery:** one local implementation and validation checkpoint; no push or merge.

## Current scope

The current Client implementation targets clean Core `f30892fcd79a27bfe5604575deaecebe52c5ec50` and full Hub image `sha256:56956f8a3d50b7e0445eef4017ba7cecff0ced570694cf8d8c3bb964e060aef7`. Archive `445017efe9085303942892c1bd1eaa2812c708f78389dbc59f906af8f535c324` and catalog `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54` are independent pins. Imported payloads match the exact committed Core source, and manifest/image metadata record a clean source. Current Core working-tree changes are outside this delivery.

Implemented: independent Hub profiles, explicit Hub/ACTIVE Network selection, topology v2, scoped Group creation, and dedicated verified Network key preview/Owner-proof review/grant/status. Every native call captures a profile and selection generation. A switch fences old callbacks and replaces the UI state; pending enrollment, ciphertext, counters and Monitor records remain in the originating profile. A different Hub ID requires a new profile and independently generated keys. Legacy storage is adopted in place.

The Network path independently validates full public keys, candidate self-attestation and exact signed bytes, native Session commitment, all scoped identities/epochs/revisions, manifest digest and external Owner proof. It rereads encrypted capabilities, current topology and manifest before sealing. Raw recovered packets cannot become consent evidence. The phone confirms after Owner proof verification and never holds the Owner private key.

An independent durable Network grant fence retains the original operation ID, counters and signed ciphertext after `OUTCOME_UNCERTAIN`. A generic snapshot, another uncertain read, profile switching, trust replacement or device reset cannot release or overwrite it. New grants and deletion of the originating profile remain refused; read-only key status stays available. Dedicated correlation of the original proof with authoritative Network status is not yet implemented, so this safety fence does not automatically unlock. Actual Network recovery faults remain **NOT_RUN**.

The [current validation record](client-hub-v1.4-f30892f-validation.md) is authoritative for current APK hashes, command exits, per-item status and evidence. Historical records below preserve their original source/APK attribution.

Final compiled source fingerprint: `5e7a72fa5a15c2077f03e1fe8b7bd578bcd8b8f549704522e3cd90b1a507b437` (80 files). Instrumentation APK SHA-256: `0d7feb3c886072a23da7e9d9a291a0a814ac9955a7445cf91a2c4f7326ece0a3`. The actual local Client checkpoint ID is provided in the completion message and private delivery record; tested checkout `b627e70` plus changes is not represented as a clean-source APK. Both Client emulators/proxies and Core's owned Hub/network/fixture were removed with independently verified absence; cleanup diagnostic retries remain recorded. No resident service was changed.

## Core dependencies

- **BLOCKED:** positive real-Hub Network consent. Fixed `f30892f` has the signing library but no external Network key signing CLI. A separate dirty candidate signer was supplied for device enrollment, with its provenance recorded separately. The complete pinned native Endpoint/Owner-consent fixture remains undelivered. Core plans a separate delivery with the signer, full production-shape vector and disposable fixture. The Client does not accept its incomplete published manifest as a production preview.
- The v1.4 canonical manifest digest omits `native_session_id` after clearing the `omitempty` field and retains `"digest":""`. The published vector fixes its exact bytes; the wire prose should explicitly describe omission. Both Network attestation and Owner proof sign canonical input ending in `"signature":null`.
- **PASS:** final APK `abbc2be65bccc1e4e3f2490288949ba587786b9890bbd1b5f2bb74b2feb5c760` passed 45 Kotlin tests, 23 JavaScript checks, actual offline connection UI, and fresh-device real-Hub enrollment, encrypted capabilities, ACTIVE topology/selection and Network-scoped Group creation. All three native Hub selectors returned ADB/driver `0/0`; final sequence is `7`, `pending=false`. Core owns operator setup/private credentials; Client did not read its database. Candidate 3 results remain separately attributed.
- **BLOCKED:** automatic Network grant outcome reconciliation in Client. The independent durable lock remains closed until the original proof/scope is specifically correlated with authoritative key status; generic snapshots do not unlock it. Synthetic authenticated-response regression passed, but actual Network fault injection and automatic unlock are **NOT_RUN**.
- Physical Android, public HTTPS, current-version native Codex/Monitor execution, and production lifecycle acceptance must remain separately reported. Historical PASS results do not certify this checkpoint.

## Review prompt for the Core maintainer

```text
Review CICADA_CLIENT read-only on dev/react-native. Read
AGENTS.md, docs/client-hub-v1.4-f30892f-validation.md,
docs/cicada-core-handoff.md, and the local checkpoint.

Match the exact clean f30892f source, complete sha256:56956f8a... image,
archive 445017ef..., and catalog 7a9e4209... from the full pins in the report.
Distinguish deterministic Kotlin tests and emulator UI checks from real
fixed-Hub encrypted interoperability. Do not transfer older v1.3 PASS results.

For Network key consent, deliver a separately pinned external Owner signer
(binary/source SHA), a complete production-shape public vector, and a safe
once-only ACTIVE Network/native Endpoint fixture. Keep Node bearer, Owner
private key and model credentials outside Android, APKs, Git and public logs.
Confirm canonical manifest omission of native_session_id, digest:"", and
signature:null in both signed Network claim formats. Preserve original pending
packets and counters on transport uncertainty. Do not use an unsigned proof,
a synthetic native Thread, or current dirty Core source to complete acceptance.

Review the independent durable Network UNCERTAIN fence and help validate
original proof/scope correlation against network.key_status. Client automatic
reconciliation is not implemented; a generic snapshot must never unlock it.
Keep this Client limitation distinct from a missing server endpoint.

Check all Client commit author/committer identities against the server global
Git configuration. Keep this checkpoint local; do not merge, publish or replace
resident services.
```

---

## Historical v1.3 handoff

### Fixed Hub `client-hub-v1.3`

**Date:** 2026-09-27

**Branch:** `dev/react-native`

**Implementation tested:** `9568b2ff6d4e156b70484c10b7fd5195405004b0`

## Current bounded acceptance — clean Hub `25013b5`

**Status: PASS for the bounded emulator/native scenario.** Ten fresh Android selectors passed, including final encrypted delivery status. The sole Core runner exited `0`; the original Monitor completed one preview and one dispatch, and both original recipient Threads passed exact-body and context assertions. This is not physical-device, public HTTPS or unattended cold-wake acceptance.

| Input | Fixed value |
|---|---|
| Clean Hub commit | `25013b51915124fa1da25e5fd37088eadf0e3d2d` |
| Full Hub image | `sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c` |
| Protocol / wire | `client-hub-v1.3` / `1` |
| Bundle SHA-256 | `5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Client checkout at run start | `b7ffa7edc9094f3f4c2819f9c7eb50aa3eca380c` |
| Installed product source | `9568b2ff6d4e156b70484c10b7fd5195405004b0` |
| Product APK SHA-256 | `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| Installed instrumentation source | `02cefa94bc6096f7196d1df572a22a1f64774d74` |
| Instrumentation APK SHA-256 | `4cbc0e1ff0546b665e55136c1453334e282d19c380e26b63aa8601cd27a3f90b` |
| Separate Core native runner source | `0d532f2e3bb57a9c82df4967044e4f40861c45a6` |
| Native binary SHA-256 | `c992dd4ce9fdaeb6895ad827ae8e196155abba5009e2b3da1c4e5931eccd8589` |

See the [fixed-image validation record](client-monitor-v13-25013b5-native-validation.md) for commands, exits and per-stage evidence. Its imported contract snapshot is `contracts/client-hub-v1.3-25013b5/`. The public wire, catalog and vectors are byte-identical to the previous snapshot; only the bundled development document changed. No product code or security check was relaxed for this run.

Evidence root:

```text
/gpu1-share/data/cicada-client/monitor-v13-25013b5-review-20260927T115633Z/evidence/
```

All ten Android selectors run through `python3 scripts/interop/monitor-android.py "$E" test ai.cicada.client.hub.MonitorHubInteropTest#<method> --label <label>` and returned ADB/driver `0/0`, `OK (1 test)`. The record lists every method and command JSON. The two marked Nodes, Monitor permission, three verified Group proofs, exact body including whitespace, and ordered two-recipient roster were reviewed in instrumentation-driven Android dialogs. This does not constitute a fresh complete React Native UI acceptance.

| Check | Result | Command exit / redacted evidence under the evidence root |
|---|---|---|
| Imported archive, clean running image and encrypted capabilities | **PASS** | Checker `0`; enrollment `0/0`; `bundle-image-import.json`, `contract-check.json`, `running-hub-provenance.redacted.json`, `native-enroll-capabilities.json` |
| Three original native Endpoint identities and full Kotlin verification | **PASS** | Manifest selector `0/0`; scope comparison `0`; `native-ready.redacted.json`, `native-manifests.json`, `native-scope-comparison.redacted.json` |
| External Owner signatures, explicit phone grants, three `CURRENT` statuses | **PASS** | Signer `0`; grant selector `0/0`; `owner-sign-groups.json`, `group-key-review.redacted.json`, `native-group-key-grants.json` |
| Explicit permission and one exact Prepare/Confirm | **PASS** | Three selectors `0/0`; handoff staging `0`; `permission-review.redacted.json`, `broadcast-review.redacted.json`, `native-prepare.json`, `native-confirm.json`, `native-stage-confirmed.json` |
| Native preview, single broadcast and both original recipients consuming the exact body in their retained contexts | **PASS** | Core `TestMCPMonitorBroadcastAndroidClientNative`: container `0`; `core-native-outcome.redacted.json`; actual Docker argv in Core `native-run.json` |
| Strict Android final delivery-status observation | **PASS** | `readNativeDispatchStatus`: `0/0`; `native-final-status.json`, `android-final-status.redacted.json`; two ordered `ACCEPTED`, local `NODE_REPORTED`, remote `RELAY_PERSISTED` |
| Full React Native flow, physical Android, public HTTPS | **NOT_RUN** | Outside this bounded emulator/native checkpoint |
| Core scoped privacy scan and outcome evidence | **PASS** | Core `verify-private`: `0`; `core-native-outcome.redacted.json`; Client did not read the Hub database |
| Owned Android emulator and reverse cleanup | **PASS** | Reverse removal and emulator stop: `0` each; `client-teardown.redacted.json` |
| Core-owned Hub/Node fixture teardown | **NOT_RUN** | Core retained its fixture for independent audit at Client handoff; Client was explicitly instructed to leave it intact |

Core evidence is under `/home/zyf/CICADA/.cicada-data/native-review-0d532f2/`. `native-run.json` records the actual Docker argv and start exit; `native-final.redacted.json` records native exit `0` and scoped scan exit `0`. The Client independently matched source/image/binary hashes, the three original identities and epochs, the original preview/broadcast and ordered roster. Its copied summary hashes operational identifiers. The Core-owned scan checked the exact synthetic body and three context markers in this fixture's Hub DB/WAL/SHM; it does not establish a universal plaintext-absence claim.

The final read-only Android RPC advanced the sequence by one, left no pending request, and retained the original operation, Confirm identity and sequence, consent and ordered roster. Transport outcomes and model consumption have separate evidence. One preview and one dispatch were observed in this run, with stable child-message deduplication; this is not an exactly-once guarantee under arbitrary network failures. Existing uncertain-injection boundaries remain unchanged.

The earlier `81d8f1f` failures below remain historical. Automatic model approval remained active; no bypass, replacement Thread, repeated phone approval or retry after refusal was used. Two logical Nodes shared one native container, and original Threads resumed at controlled safe points. Network M1, Group journal/discussions/regroup implementation, the separate reconciled-operation UI limitation, and further model runs remain outside this checkpoint. No product code changed, and nothing was pushed, merged or published.

### Current review prompt for the CICADA maintainer

```text
Review CICADA_CLIENT read-only on dev/react-native:
- docs/client-monitor-v13-25013b5-native-validation.md
- docs/cicada-core-handoff.md, README.md and the local delivery commit.

Match clean Hub 25013b51915124fa1da25e5fd37088eadf0e3d2d, full image
sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c,
bundle 5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce,
and catalog 808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377.
Keep Core native runner source 0d532f2 separate from Hub source 25013b5.

Reconcile ten fresh Android PASS selectors, the original three-Thread native
PASS, strict final transport status, exact installed APKs, command exits and
identity hashes. Preserve the old 81d8f1f failures and this run's initial harness
errors. Native consumption and transport acceptance have separate evidence;
one observed dispatch is not a general exactly-once execution guarantee.

Client emulator/reverse cleanup passed. Core retained its Hub/Node fixture for
its independent audit and owns its final teardown; report that outcome separately.
Physical Android, public HTTPS, unattended cold wake and a fresh full React
Native screen flow were not validated. Do not start another model run, broaden
implementation, change Client files, push, merge or publish as part of review.
```

## Historical `81d8f1f` candidate and evidence separation

The historical candidate is clean Hub
`81d8f1f90895f41c4f5ea5c67a6281ccda9e1264`, contract `client-hub-v1.3`,
image `sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f`.
Archive SHA-256 is
`6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061`;
catalog SHA-256 is
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`.
The imported snapshot is `contracts/client-hub-v1.3-81d8f1f`.

Client validation source is `10cd3dcb3bd73e6513df428ced81d95788e1cb84`.
The installed product APK remains source
`9568b2ff6d4e156b70484c10b7fd5195405004b0`, SHA-256
`f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700`.
The installed AndroidTest APK is SHA-256
`8c2f122e76e22f6845bbdaf0518146ed94a1f6895abdab1147d3010b4c531e09`.
The app rebuilt beside this test APK was not installed. The test-only change
corrects synthetic RFC3339Nano timestamps; production verification is unchanged.

The [first candidate run](client-monitor-v13-81d8f1f-native-validation.md)
passed 15 Kotlin public-vector tests, nine contract-checker regressions, fixed
image provenance, and ten Android integration selectors. The latter include
three actual native Endpoint manifests, external Owner signatures, explicit
phone grants with `CURRENT`, one accepted Prepare, one outbound Confirm, and a
read-only final status with two ordered `ACCEPTED` recipients. The evidence tiers
were `NODE_REPORTED` locally and `RELAY_PERSISTED` remotely.

The full native scenario in that run remains **FAIL**, native exit `1`: the
local recipient's no-tool recall retained the original context and child message
ID but omitted the expected body marker. Its preceding structured receive had
passed exact-body checks. Remote model consumption was **NOT_RUN**. Core
identified ambiguity in the recall prompt and changed two test prompt strings
without relaxing the assertions. The failed run was archived and its owned
resources were removed; cleanup is **PASS**. No Client read of the Hub database
was involved.

The [fresh recall run](client-monitor-v13-81d8f1f-recall-validation.md) uses a new
disposable Hub, Android identity and three new original native Threads. Its
separate native test source is `d76e63009192422d13e0e3b413e857a27866c750`, with
binary SHA-256
`15a436025b69c85e74b6151efdc4d0414cc082ff60cd2e0b6b643b47c64ae2e8`.
The fixed Hub image and both APKs are unchanged. Results from the first run and
all older images retain their own provenance and are not reused as runtime
results for this fresh run.

### Fresh-run outcome and command index

**Client Group authorization and explicit consent: PASS. Full native broadcast:
BLOCKED.** Automatic Codex approval review rejected both MCP attempts in one
native turn because the sealed payload and Group scope were not independently
inspectable through the supplied approval ID. The native container exited `1`
before creating a Monitor outbox or recipient children. No review bypass,
replacement approval, or further model run was attempted.

The unchanged product UI could not reopen the original operation after launch:
its status index filters out already reconciled Confirms. This is a remaining
Client UI limitation, recorded separately from the native review block. No
product change was made in this checkpoint. A new **test-only** selector in
Client commit `02cefa94bc6096f7196d1df572a22a1f64774d74` read the actual encrypted
status without submitting or recovering a write. Its AndroidTest APK SHA-256 is
`4cbc0e1ff0546b665e55136c1453334e282d19c380e26b63aa8601cd27a3f90b`.
Only that observation uses this APK; the preceding nine selectors retain test
APK `8c2f122e…`. Product APK `f8c82d…` remained installed throughout.
The scoped phone approvals in these selectors use instrumentation-driven
Android dialogs on the App activity. They do not repeat the complete React
Native consent-screen acceptance previously recorded under Set H.

The observed status was **APPROVED**, with **zero recipient outcomes**. The
single status RPC advanced the request sequence once and left no pending
request. Original operation and Confirm identifiers, Confirm sequence, consent,
recipient roster and sealed payload remained unchanged. The strict delivered
status selector was **NOT_RUN** in this fresh attempt. The earlier run's
`DISPATCH_AUTHORIZED` result must not be substituted for it.

Let `E=/gpu1-share/data/cicada-client/monitor-v13-81d8f1f-recall-20260927T065926Z/evidence`.
The linked report lists full selectors and artifacts; each command JSON records
the actual argument list and exit code.

| Check | Result | Command / exit and evidence under `E` |
|---|---|---|
| Fixed archive, clean running image and encrypted capabilities | **PASS** | Docker contract checker: `0`; image inspection: `0`; `enrollOwnerAndCheckCapabilities`: ADB/driver `0/0`; `archive-preflight.redacted.json`, `fresh-contract-check.json`, `running-hub-provenance.redacted.json`, `native-enroll-capabilities.json` |
| Nine Android setup, Group and consent selectors | **PASS** | `python3 scripts/interop/monitor-android.py "$E" test <selector> --label <label>`: each ADB/driver `0/0`, `OK (1 test)`; `native-*.json` selector matrix in the report |
| Complete native proofs, external Owner signing, three phone grants and `CURRENT` | **PASS** | Core `sign-groups` helper and external signer: `0`; `grantEndpointKeysAndReadCurrent`: `0/0`; `native-scope-comparison.redacted.json`, `owner-sign-groups.json`, `group-key-reviews.redacted.json` |
| Original native Monitor dispatch and recipient consumption | **BLOCKED** | Core exact binary `TestMCPMonitorBroadcastAndroidClientNative`: container exit `1`; `core-native-blocked.redacted.json` retains the Docker command, source/hash and approval-review outcome |
| Product UI reopening of an already reconciled Confirm | **BLOCKED** | Bounded navigation wrapper: `1`, no status RPC or new write; `readonly-ui-limitation.redacted.json` |
| Separate read-only actual-status observation | **PASS** | `./scripts/docker-build-android-test.sh`: `0`; `readOriginalBroadcastStatus`: ADB/driver `0/0`, `OK (1 test)`; `readonly-observation-test-build.json`, `native-observed-status.json`, `android-observed-status.redacted.json` |
| Strict delivered-status assertion, remote model consumption, physical Android, public HTTPS | **NOT_RUN** | No qualifying result for these gates in this fresh run |
| Scoped privacy checks and owned-environment cleanup | **PASS** | Document/mount check: `0`; reverse removal, emulator stop and marked Hub fixture stop: `0` each; `client-privacy-preflight.redacted.json`, `native-teardown.redacted.json` |

Core archived its native command, approval-review analysis and scoped Hub scan
under `/home/zyf/CICADA/.cicada-data/native-joint-recall-d76e630/`. Its scan found
no synthetic private-body marker in the three scanned Hub artifacts. This is
Core-owned, bounded evidence; the Client did not inspect the Hub database and
does not claim a universal plaintext audit. Original Thread identities are
retained as hashes; raw session records and credentials were not copied. Both
attempts' disposable Hub/Node state and emulators were removed after evidence
capture. Resident Hubs were untouched. No push, merge or publication occurred.

### Historical review prompt for the CICADA maintainer

```text
Review CICADA_CLIENT read-only on dev/react-native:
- docs/client-monitor-v13-81d8f1f-native-validation.md
- docs/client-monitor-v13-81d8f1f-recall-validation.md
- docs/cicada-core-handoff.md and the current working tree / local commits.

Keep clean Hub 81d8f1f90895f41c4f5ea5c67a6281ccda9e1264 and full image
sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f
distinct from native test sources 28bd4626 and d76e6300. Verify the archive and
catalog pins, per-stage APK hashes, commands, exits and cleanup evidence.
Android Group keys CURRENT and explicit consent passed in both runs. Preserve
the first native FAIL and the fresh native approval-review BLOCKED result.
Fresh final encrypted status is APPROVED with zero recipient outcomes;
the older run's transport evidence is not evidence of this run's dispatch.

The next native acceptance requires an auditable way for automatic approval
review to verify the phone-authorized exact body, Group and recipient scope.
Please identify the necessary trusted evidence/interface and its security
checks. Do not bypass approval review, treat opaque approval IDs as sufficient
authorization, resend the old confirmation, or relabel blocked work as PASS.
Deliver any changed protocol, runner and image with independent provenance
before another bounded native run. No further model call is authorized by this
handoff itself.

Record the Client's separate UI follow-up: a reconciled Monitor operation
cannot currently be reopened after app launch. Do not edit CICADA_CLIENT from
the core thread. Physical Android and public HTTPS remain NOT_RUN. Preserve
historical N4/N5 and v1.2.1 results under their original images and APKs.
Do not push, merge, publish or modify production state.
```

## Historical joint native Monitor attempt — `be0269e`

**FAIL** on the unchanged fixed Hub `be0269e`. The original native Session
heartbeat was rejected after legacy presence cleanup marked the Endpoint
offline while its binding remained leased. Core-owned evidence records three
real original Codex Threads, native process exit `1`, zero model retries and
zero replacement Threads. The Client did not inspect the Hub database.

The [native acceptance report](client-monitor-v13-native-acceptance.md) records
commands, exits, redacted identities and stage-specific APKs. Six Android
selectors passed: device preparation, encrypted enrollment/capabilities, two
Node confirmations, Group creation, explicit broadcast permission with the
role-only rejection probe, and independent full Endpoint manifest verification.
No external Group proof was signed, no Group grant was submitted, and no
positive Prepare or Confirm was sent. Native dispatch, recipient consumption,
final status, physical Android and public HTTPS are **NOT_RUN** for this run.

Client test commit `1172000f5ebd03a34b0b589702f1fc7d56409433` adds only a
read-only final-status selector; its build passed, but the selector was
**NOT_RUN** because native dispatch was blocked. The installed app remained
Set H SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700`.
Later stages used test APK
`ea6bcc09d456da0fd2b5fb14f11a92ba88f55e965a9eff474af86ccac3512601`.
The rebuilt app with a different hash was not installed. Core test/helper
source `877062f30835023a26bd546972aca1e83dcffcac` is separate from the fixed
Hub image source.

The completed Set H and RPC recovery results below remain historical results
of their own runs. A core fix or later image does not retroactively pass this
failed joint attempt. A new fixed candidate and a separate native run remain
required; neither is part of this Client delivery.

Cleanup is **PASS**: owned reverse removal, emulator stop and marked Hub fixture
stop each exited `0`; see `native-teardown.redacted.json` in the report's evidence
directory. Core archived original Thread records before cleanup. They are
**NATIVE_THREAD_RECORDS_PRESERVED**, while the removed fixture is
**HUB_BINDING_NOT_RECOVERABLE_AFTER_FIXTURE_CLEANUP**. No resident Hub was targeted.
No new model run or replacement Thread was started, and nothing was pushed or
merged.

### Core review prompt

> Read `docs/client-monitor-v13-native-acceptance.md` and the redacted evidence
> under `/gpu1-share/data/cicada-client/monitor-v13-native-20260927T050925Z/evidence`.
> Reconcile the six Android PASS selectors with `core-native-failure.redacted.json`
> and the archived native exit `1`. Preserve the fixed `be0269e` failure and
> downstream NOT_RUN results. Report the core presence/lease fix and its own
> regression results separately. Before any future native rerun, deliver a clean
> source commit, complete image ID, protocol archive and catalog digests plus the
> exact original-Thread workflow. Do not transfer Set H, RPC recovery or historical
> v1.2.1 results to the new candidate. Review only; do not push or merge Client.

## Original Set H delivery status

**PASS** for the documented Android emulator protocol and product-interface
acceptance using synthetic authorization Endpoints. This is not native Monitor
execution or release acceptance. The disposable Hub, Node state, Owner private
keys, proxy and emulator have been removed. Only the Client repository changed;
nothing was pushed, merged, published or deployed to production.

The [fixed-image validation record](client-hub-v1.3-be0269e-validation.md) is the
complete command, exit-code, artifact and evidence matrix. Historical v1.2.1
N4/N5, native Group and two-Owner results below retain their original artifacts.
They are not evidence for the v1.3 target.

## Frozen inputs and tested artifacts

| Item | Value |
|---|---|
| Clean Hub source | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` |
| Contract | `client-hub-v1.3` |
| Archive SHA-256 | `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Full Hub image ID | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |
| Debug app APK SHA-256 | `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| AndroidTest APK SHA-256 | `aba2d98487cb3d928b3b10d9401d19fdd4f99d114d326daee6f895a897c34720` |

All 15 imported bundle payloads retain their original bytes. The manifest,
clean source, image labels and encrypted runtime capabilities were checked
independently. Current core development changes were not substituted for this
image. The APKs are development artifacts, not signed release packages.

## Final acceptance summary

Let `E=/gpu1-share/data/cicada-client/monitor-v13-20260927T005634Z-be0269e/evidence`.
Its directory is `0700`; evidence files are `0600`. The table names only
restricted evidence paths. Detailed selectors and commands are in the linked
validation record and each command JSON.

| Check | Result | Command / exit and evidence under `E` |
|---|---|---|
| Fixed bundle, image and encrypted capabilities | **PASS** | `python3 scripts/check-client-contract.py`: 0; image inspection: 0; capabilities instrumentation: ADB/driver 0/0, `OK (1 test)`; `final16-runtime-provenance.json`, `final16-capabilities.json` |
| Independent Kotlin vectors and recovery guards | **PASS** | Four instrumentation suites: ADB/driver 0/0; 6 Monitor, 6 recovery-lock, 4 Endpoint and 5 wire tests; `final16-*-vectors.json`, `final16-recovery-locks.json` |
| Android build and TypeScript/JavaScript boundary | **PASS** | `./scripts/docker-build-android-test.sh`: 0; Docker TypeScript, JavaScript (13 tests) and ESLint: 0; `android-build-16-native-result-adapter.json`, `final16-{typescript,javascript,eslint}.json` |
| External Owner proof and explicit Android Group grants | **PASS** | `grantEndpointKeysAndReadCurrent`: ADB/driver 0/0, `OK (1 test)`; three reviewed phone confirmations; `final16-fresh-group-grants.json`, `phase3-fixture-preparation.redacted.json` |
| Lost Prepare and Confirm HTTP 200 responses | **PASS** | Four instrumentation selectors: ADB/driver 0/0, `OK (1 test)` each; `final16-{dropped,recovered}-{prepare,confirm}.json`; exact original ciphertext retained/recovered, no replacement operation or second Confirm |
| Changed text, foreign preview, bounded capacity and revoked permission | **PASS** | Three instrumentation selectors: ADB/driver 0/0, `OK (1 test)` each; `final16-reject-body-preview.json`, `final16-capacity.json`, `final16-reject-stale.json`; revocation rejected before a Confirm packet was persisted |
| Actual React Native consent and status interface | **PASS** | Recorded ADB navigation/input/confirmation commands: 0; UI hierarchy and Client-journal checks: 0; `final16-product-ui.redacted.json`, `final16-fresh-approved-status.private.png`; shows approval and explicitly does not claim delivery |
| Known-secret scan and isolated environment cleanup | **PASS** | Scoped scan: 0, zero matches; owned proxy/emulator/core fixture stop commands: 0; `privacy-check.redacted.json`, `final16-teardown.redacted.json` |
| New native Monitor delivery or model consumption | **NOT_RUN** | Synthetic Node/Endpoint authorization fixtures only; core-native results remain separate |
| Physical Android, dual physical Nodes, public HTTPS | **NOT_RUN** | No qualifying environment run |
| Live v1.3 Monitor `STILL_PROCESSING`, `OUTCOME_UNCERTAIN`, `RECOVERY_UNAVAILABLE` faults | **NOT_RUN** | Local uncertainty guards passed; historical v1.2.1 live fault tests are not relabeled as v1.3 Monitor acceptance |

No core API blocker remains for the tested protocol/UI slice. The report retains
earlier failures: an excessive grant/preview lifetime constraint, missing
current authorization preflight, Fabric parent mounting, and native-to-UI DTO
mismatch. It also distinguishes expired fixture grants from actual revocation
tests. Those failures were not relabeled as passing runs.

## Implementation and security boundary

Dedicated Kotlin methods independently verify the complete Endpoint attestation,
Owner grant, exact consent roster and envelope v2. Before the first Confirm is
sealed, the session recovers the reviewed Prepare and rereads current topology
and the source Group grant through encrypted RPC. It validates current identity,
binding, key and signed revisions, then seals with the reserved Confirm request
sequence. Topology CAS versions are not substituted for signed revisions.

The exact inner envelope and outer RPC packet are persisted before sending.
Recovery uses the original packet. The interface now converts the verified
native RPC result into its explicit display model, and distinguishes a refused
preflight from a persisted Confirm. Pending or uncertain writes stay blocked;
read-only reconciliation remains available. No automatic replacement operation
or silent approval is introduced.

The UI preserves local speech transcription and the existing management screens.
`external_thread_links=false` continues to prevent ordinary cross-user messaging.
This acceptance does not establish physical Keystore isolation, public HTTPS,
blind-Hub peer messaging or runtime/model consumption. Owner private keys and
Node bearer credentials stayed outside Android, Git and the APK. The scoped
secret scan is not a universal audit of every possible credential representation.

## Follow-up: Monitor Prepare RPC recovery faults — 2026-09-27

**PASS** for the three bounded recovery-layer scenarios on the same frozen
Hub `be0269e` image. This is a separate run with fresh disposable Hubs and
Android device identities; it does not rewrite Set H or demonstrate Monitor
business execution. The [recovery fault report](client-monitor-v13-recovery-faults.md)
records the commands, exits, artifact identities, earlier harness failures and
cleanup evidence.

| Item | Recorded value |
|---|---|
| Android test source | `cc634e6ac1937d41fa35234862b9fde70da71c80` |
| Product implementation / app APK | `9568b2f`; unchanged app SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| New AndroidTest APK SHA-256 | `0bb67beb0da959d9518520672720543f709b11024fa0af153c990fc819af9cd2` |
| Processing runner | `84ed962` |
| Uncertain / legacy runner | `69ecd268550151c9c786d46445df7eee120f0f30` |
| `STILL_PROCESSING` | **PASS** — HTTP 409; original pending ciphertext, operation and sequence retained; new Prepare blocked |
| `OUTCOME_UNCERTAIN` | **PASS** — signed encrypted response after `FAULT_READY` and same-container/same-state restart; reserved response sequence consumed once; original packet retained for reconciliation |
| `RECOVERY_UNAVAILABLE` | **PASS** — HTTP 409; original pending request retained and fenced |
| Native delivery, Confirm fault scenarios, physical Android, public HTTPS | **NOT_RUN** in this follow-up |

Each scenario's device preparation, encrypted enrollment/capabilities, capture
and recovery selector returned ADB/driver exit `0/0` and `OK (1 test)`:
12 instrumentation tests in total. Three distinct Hub identity hashes and
Android device key hashes were verified. The fixed core fixture inserts only
a recovery ledger entry; it does not dispatch `monitor.broadcast_prepare`.
No Monitor-level recovery lookup or Confirm was called.

Docker reassigned the disposable Hub's published port after restart. The
runner verified the same container, image, state mount and Hub identity, then
retargeted only its proxy upstream while preserving the Android origin. The
original proxy recorded one `FAULT_READY`; the replacement proxy recorded no
second fault injection. Generic encrypted `status.snapshot` reconciliation
did not clear the unresolved `PREPARE_UNCERTAIN` metadata or enable a new
Prepare. These checks do not certify recovery after a real Monitor business
handler has partially executed.

Evidence root:
`/gpu1-share/data/cicada-client/monitor-v13-faults-20260927T043238Z/evidence`.
See `acceptance-summary.redacted.json`, `final-teardown.redacted.json` and each
scenario's `recovery-result.json`. All owned fixtures, synthetic keys, proxies,
Android sessions and the emulator were removed. No production code, core
checkout, resident Hub or frozen artifact was changed; nothing was pushed or
merged.

## Prompt for the CICADA core developer

> Read `CICADA_CLIENT/docs/cicada-core-handoff.md` and
> `docs/client-hub-v1.3-be0269e-validation.md` without modifying either repository.
> Review Client implementation `9568b2ff6d4e156b70484c10b7fd5195405004b0`
> against the frozen clean Hub `be0269e` inputs above. Check the full Endpoint and
> Owner proof verification, current authorization preflight, consent/envelope
> binding, request counters, raw-packet recovery and UI result interpretation.
> Report concrete mismatches with source or evidence references. Preserve the
> distinction between this Android synthetic-authorization result and core-native
> Monitor evidence. Identify a supported disposable native Monitor fixture for a
> future Android-to-native delivery run, and safe isolated fault drivers for the
> remaining native-delivery and Confirm recovery cases. Read the separate
> Prepare recovery-layer report above before proposing additional tests. Do not
> change the frozen image or contract, inspect databases or credentials, deploy,
> push, or merge.

---

# Historical handoff: fixed Hub `client-hub-v1.2.1`

**Date:** 2026-09-26

**Client branch:** `dev/react-native`

**Node/Codex E2E candidate commit:** `09ecfe761811ceaf37e6deea2842b8a3949dfa46`

**Group verifier fix commit:** `af3ad451e29d0c43142b3fc792272bbd6df75c84`

**Final Group implementation commit:** `b676668e33c876c0d2c89bc3495fbd0d1e128c82`

**Validation record:** [v1.2.1 fixed-image validation](client-hub-v1.2.1-967dbd-validation.md)

**Two-Owner authorization implementation:** `680fac2bf12c431ac02804e5db168669cf12941f`

**Separate authorization record:** [Two-Owner fixed-image validation](client-two-owner-v1.2.1-967dbd-validation.md)

## Fixed integration baseline

| Item | Value |
|---|---|
| Hub source commit | `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` (`source_dirty=false`) |
| Protocol | `client-hub-v1.2.1` |
| Protocol archive SHA-256 | `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a` |
| Catalog SHA-256 | `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9` |
| Full local image ID | `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7` |
| Recovery/lost-response candidate debug APK SHA-256 | `e75e994608e12b223fb3cb041cf1d3fba1d10411e519a317c4afc25e5c94fed3` |
| Recovery/lost-response candidate AndroidTest APK SHA-256 | `ad8bfa8c8b914677194f1cf493153eaaff67c817fc277d299b0a998a028456b8` |
| Pre-RFC3339Nano-fix Group/E2E candidate debug APK SHA-256 | `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197` |
| Pre-RFC3339Nano-fix Group/E2E candidate AndroidTest APK SHA-256 | `50756de57eb0ef2d9ca55feab6222d78bc4849ddf68b203560138918ba8f7c7f` |
| Corrected Group verifier debug APK SHA-256 | `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76` |
| Corrected Group verifier AndroidTest APK SHA-256 | `711e00f9fee11582c81af14e5a2c9d77799412166a8a3cd7008ec7cb16d27ab0` |
| Final live Group acceptance debug APK SHA-256 | `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1` |
| Final live Group acceptance AndroidTest APK SHA-256 | `52e9e678666654d57bd127b5f616a3094e9a9925b9fe5b960632c7cb81d6f9d5` |

The APKs are candidate debug/test artifacts, not signed release packages. Protocol package, manifest, and image-label checks passed. The imported files are under [`contracts/client-hub-v1.2.1-967dbd`](../contracts/client-hub-v1.2.1-967dbd/manifest.json).

## Two-Owner authorization acceptance — 2026-09-26

The separate two-Owner slice is **PASS** on implementation commit
`680fac2bf12c431ac02804e5db168669cf12941f`. It uses the same clean fixed Hub
commit, archive, catalog and complete image ID above. It adds only disposable
fixture and Android instrumentation code. The existing UI, local STT and
production cryptographic checks were preserved. No Monitor operations or
new contract version were introduced.

The final fresh-run evidence root is
`/gpu1-share/data/cicada-client/two-owner-20260926T024036Z-cto-9uslracc/evidence`
(`E2` below). Its debug APK SHA-256 is
`cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1`;
its AndroidTest APK SHA-256 is
`342845155edf0333e3b81aa736d25945e8d83554a61c26fc1bf438c314d26ae0`.
The app artifact is unchanged from the final one-Owner Group run; this
authorization result comes from new execution with a different test APK.

For the commands below, `F=/tmp/cto.9uslracc` was the disposable fixture,
now removed, and `A=python3 scripts/interop/two-owner-android.py`.
The [complete authorization report](client-two-owner-v1.2.1-967dbd-validation.md)
contains exact commands, failures from the initial development attempt,
image/helper provenance and evidence limits.

| Check | Result | Command and exit | Evidence under `E2` |
|---|---|---|---|
| Clean fixed target and package verification | **PASS** | `python3 scripts/interop/two-owner-fixture.py prepare`: 0; nested contract verifier: 0 | `fixed-target.json`, `verify-contract.log`, `runtime-provenance.json`, `fixture-commands.jsonl` |
| Independent Android device keys A, A-admin and B | **PASS** | `$A "$F" test prepareTwoOwnerDeviceKeys`: runner 0, ADB 0, `OK (1 test)` | `prepareTwoOwnerDeviceKeys.json` |
| Owner-bound encrypted capabilities, Node confirmations and separate Groups | **PASS** | `$A "$F" test enrollConfirmAndCreateOwnerGroups`: runner 0, ADB 0, `OK (1 test)`; four reviewed taps: 0 | `enrollConfirmAndCreateOwnerGroups.json`, `reviewed-taps.json` |
| Live manifests, complete Android proof verification and external Owner signatures | **PASS** | `$A "$F" test exportOwnerGroupManifests`: runner 0, ADB 0, `OK (1 test)`; `sign-groups "$F"` through fixture driver: 0 | `exportOwnerGroupManifests.json`, `fixture-commands.jsonl` |
| Both own grants `CURRENT`; six cross-Owner requests denied; tampered proof rejected at Hub | **PASS** | `$A "$F" test twoOwnerOwnershipAndRevocationMatrix`: runner 0, ADB 0, `OK (1 test)`; two reviewed grant taps: 0 | `twoOwnerOwnershipAndRevocationMatrix.json`, `summary.redacted.json`, `reviewed-taps.json` |
| Local pending/identity isolation, authoritative grant records unchanged, revoke A while B remains usable | **PASS** | Same matrix command: 0; includes fresh A request and exact old packet `/rpc` and `/recover` HTTP 403 | `summary.redacted.json`, matrix private log |
| Known-secret checks and cleanup | **PASS** | Local evidence scan: 0; `python3 scripts/interop/two-owner-fixture.py stop "$F"`: 0 | `privacy-check.redacted.json`, `teardown.json` |
| New native Codex/Thread run; physical Android; public HTTPS | **NOT_RUN** | No commands for these gates in this slice | Earlier native evidence remains separately attributed |

No required item in this two-Owner slice remains **BLOCKED**. The Hub negative
cases used each other Owner's real existing Group, Endpoint and valid Owner
proof. All six requests returned HTTP 200 with a verified encrypted
`permission denied` business result. The separate corrupted-signature request
reached the Hub verifier and returned a signature rejection. These are distinct
from the product's local preflight errors and the HTTP 403 responses after
revocation. The authenticated negative requests legitimately advance Hub
request/response counters; unchanged state refers to target grants and isolated
Client journals, not an unchanged Hub request ledger.

These Endpoints are explicitly **synthetic authorization fixtures**, not native
sessions. The three Android contexts have independent PQ identities and journals
but share one emulator app UID and Keystore wrapping alias. The wrong-device
response-open assertion rejects a route/recipient mismatch; it is not a separate
OS key-isolation or KEM-decapsulation experiment. Owner/Endpoint private keys and
Node bearers stayed outside Android. Both runs' disposable Hub/Node/emulator
state and credentials were removed. Nothing was pushed, merged or deployed.

## Earlier evidence on this fixed target

- An independent Android session completed encrypted `session.capabilities` against the fixed image.
- Exact enrollment Grant replay after a lost HTTP 201 and exact encrypted RPC recovery after a lost HTTP 200 passed. The Android tests each returned `OK (1 test)` and ADB exit 0; the proxy evidence records the upstream response before dropping the downstream response.
- All three Android recovery fault tests passed with a new disposable Hub under `/tmp`. Each scenario script exited 0 and each final Android test returned `OK (1 test)` with ADB exit 0. For the uncertain outcome, the test waited for `FAULT_READY`, restarted only the disposable Hub, then recovered the signed encrypted notice. The details and Git-external evidence paths are in the validation report.
- Candidate APK `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197` passed `EndpointAttestationVectorTest` (`OK (4 tests)`, ADB exit 0), covering the full Endpoint proof, synthetic manifest digests, and owner proof. Subsequent review found that this candidate rejects valid RFC3339Nano timestamps with four fractional digits.
- The fix in commit `af3ad451e29d0c43142b3fc792272bbd6df75c84` passed `./scripts/docker-build-android-test.sh` (exit 0) and `EndpointAttestationVectorTest` on `emulator-5554` (`OK (4 tests)`, ADB exit 0), producing corrected APKs `2762a2…` and `711e00…` above.
- Candidate APK/test pair `7042…`/`5075…` passed `ClientWirePublicVectorTest` (`OK (5 tests)`) and `ClientHubRecoveryLockTest` (`OK (3 tests)`), each ADB exit 0 on `emulator-5554`.
- On the `7042…` APK, E2E setup `enrollAndRead` passed against the Hub on port 8794 (`OK (1 test)`, ADB exit 0), verifying encrypted capabilities and status. A fresh `cicada machine agent --once` reached the expected pending-device-code state before confirmation; Android `confirmDisposableNodeForQueuedGoal` verified the previewed Node ID and encrypted `nodes.confirm` (`OK (1 test)`, ADB exit 0). Its device code stayed in an external `0600` file.
- The completed native E2E accepted one real Codex approval on the original Thread and Worker attempt 1. The Worker and Goal completed, Intent resolved, and `goal.result` was present and byte-matched the 30-byte Node result. The exact runner commands, exits, redacted IDs and digests are in the validation report. This run used `7042…`, so it does not exercise the corrected Group timestamp verifier in `2762…`.
- E2E cleanup removed the proxy, temporary Node/Codex state, wrapper, device code, and test marker; the one-time Codex container used `--rm`. The provider environment was mounted read-only only into that isolated Codex container, and no bearer or secret entered the Node process, APK, repository, or logs. The disposable Hub was stopped and removed; other Hub containers were left untouched. Sanitized evidence remains outside Git with restricted permissions.
- The later disposable Group fixture supplied a real native Codex Endpoint. Android validated the full manifest, imported an externally signed `signed_proof`, required an explicit on-device confirmation, and read encrypted `group.key_status=CURRENT` on final implementation commit `b676668e33c876c0d2c89bc3495fbd0d1e128c82`. The Owner private key stayed outside the APK. Exact APK hashes, commands and limits are in the [Group key acceptance report](client-group-key-v1.2.1-disposable-validation.md).
- The Android builds passed; build logs and exact commands/exits are in the validation report. The independent loss/recovery tests used the earlier candidate artifacts listed above. The candidate with the timestamp issue is not called final for Group-key validation.

## Final Group acceptance: result and evidence index

All rows below use the fixed Hub image in the baseline table and the final Group APK pair above. Let `E=/gpu1-share/data/cicada-client/group-key-v121-967dbd/evidence`; this directory is `0700`, its evidence files are `0600`, and its raw IDs, signed public proofs and logs are outside Git. Arguments containing IDs, one-time codes or proofs are omitted from the command column. The [full Group report](client-group-key-v1.2.1-disposable-validation.md) records the test order, hashed Endpoint/Session/Group/Node/binding labels, command exits and limits. It does not turn earlier `7042…` or `2762…` results into final-APK evidence.

| Check | Result | Command and exit code | Evidence under `$E` |
|---|---|---|---|
| Archive, clean source, exact image and encrypted capabilities | **PASS** | `python3 ../CICADA/scripts/client-contract.py verify <fixed archive>`: 0; `docker image inspect <full image ID>`: 0; `python3 "$E/run-android-test.py" "$E/external-capabilities.spec.json"`: 0, JUnit `OK (1 test)` | `fixed-target-provenance.json`, `external-capabilities.log` |
| Android device preparation, owner-signed enrollment and Node/Group setup | **PASS**, with the failed combined harness attempt below | `python3 "$E/run-android-test.py" "$E/prepare-device.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/reconcile-group.spec.json"`: 0, JUnit `OK (1 test)`; reviewed on-screen taps: 0 | `prepare-device.log`, `device-signer.private.log`, `external-capabilities.log`, `reconcile-group.log`, `confirm-node-after.private.log` |
| Real native Codex Join, separate candidate publication, complete Android manifest verification and external Owner signing | **PASS** | `python3 "$E/rapid-prepare-grant.py" finalui`: 0; embedded manifest instrumentation: 0, JUnit `OK (1 test)` | `codex-finalui.private.jsonl`, `native-finalui.private.json`, `manifest-finalui.log`, `group-signer-finalui.private.log` |
| Phone confirmation, encrypted `group.key_grant`, separate encrypted `group.key_status=CURRENT` | **PASS** | `python3 "$E/run-android-test.py" "$E/grant-finalui.spec.json"`: 0, JUnit `OK (1 test)`; reviewed on-screen tap: 0 | `grant-finalui.log`, `grant-finalui-dialog.private.png`, `grant-finalui.private.json` |
| Mutated Owner signature and wrong Owner key selection; nonexistent Group/Endpoint scope | **PASS**, limited to Client-side rejection and encrypted Hub business rejections | `python3 "$E/run-android-test.py" "$E/reject-tampered-proof-finalui.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/reject-wrong-scope.spec.json"`: 0; each JUnit `OK (1 test)` | `reject-tampered-proof-finalui.log`, `reject-wrong-scope.log` |
| Accepted grant after native lease expiry, then proof expiry | **PASS**: `STALE`, then `PROOF_EXPIRED` | `python3 "$E/run-android-test.py" "$E/status-stale-finalui.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/status-proof-expired-finalui.spec.json"`: 0; each JUnit `OK (1 test)` | `status-stale-finalui.log`, `status-proof-expired-finalui.log` |
| Early manager-role assertion and combined Node preview/Group runner | **FAIL** as harness attempts, not final protocol results | `python3 "$E/run-android-test.py" "$E/enroll-and-capabilities.spec.json"`: runner 1, ADB 0, JUnit `FAILURES!!!`; `python3 "$E/run-android-test.py" "$E/confirm-node-create-group.spec.json"`: runner 1, ADB 0, JUnit `FAILURES!!!` | `enroll-and-capabilities.log`, `confirm-node-create-group.log`; the code-bearing second spec was deleted at teardown; corrected external-role and Group runs above |
| Independent Hub submission of a tampered grant; second real Owner cross-owner authorization | **NOT_RUN** | No qualifying command; the Client fenced the tampered proof and the fixture enrolled only one Owner | No claim of server-side tamper or two-Owner rejection |
| Physical Android hardware; public HTTPS | **NOT_RUN** | No command run | Emulator loopback evidence does not establish either environment |

No item remains **BLOCKED** for the one-Owner positive path. The initial long Node state path blocked the Unix Join socket, but a short real private `/tmp` state directory enabled the final PASS; the fixture improvement request is below. The disposable Hub/Node, short state directory, ADB reverse mapping and emulator app data were removed with exit 0. The synthetic Node code briefly appeared in a transient process-inspection output; it expired and its private spec was deleted. The full report records that privacy finding and the evidence metadata class-name correction.

## Contract correction and outstanding validation

The previous `41beaf0` v1.2 report recorded a mismatch between the prose and Go implementation for `EndpointKeyAttestation` v1: the implementation signs compact JSON with a final `"signature":null` field. The fixed v1.2.1 wire contract documents those exact bytes and the bundle contains a public synthetic vector. This closes the published contract ambiguity. Candidate `70423555…` failed a valid four-digit RFC3339Nano fraction check; commit `af3ad451e29d0c43142b3fc792272bbd6df75c84` fixes it. The later disposable Group run on the same fixed image independently established the live positive path with a different final APK pair; the earlier Node/Codex and vector APKs are not counted as its proof.

The real Node/Codex approval run is **PASS** for this fixed image, as described above. The E2E topology snapshot/Endpoint group-membership probe, physical Android hardware, and public HTTPS are **NOT_RUN**. The earlier `41beaf0` result remains historical and is not the evidence used for this pass.

The first attempt to run the recovery fixture from a `/gpu1` working directory failed with HTTP 502 because the fixture requires a real `/tmp` root. The corrected disposable `/tmp` run passed. Both results are recorded as such; the failed attempt is not counted as a protocol failure or a PASS.

## Security and environment boundary

All current Hub tests used an isolated disposable state. No Android Client stores Hub or Node bearer credentials or reads the Hub database. Sensitive test material and raw logs stay outside Git under `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/`; the report names only the required evidence paths. The Client uses independently pinned Hub identity, an owner-signed device Grant, encrypted `session.capabilities`, and encrypted `/v2/client/rpc`. It does not call legacy `/v1` bearer APIs.

This integration validates Client-to-Control management encryption. It does not prove ordinary peer messages are unreadable to the Hub. The fixed contract keeps `status_events=false` and `external_thread_links=false`; cross-user links remain proposals, not routable Threads. No real-device key boundary or public HTTPS conclusion follows from emulator results.

## Next actions

1. Preserve the fixed-image Group acceptance and original Node/Codex approval traces as separate evidence sets. The Group result uses APK `cfe34527…` and native Codex candidate publishing; the earlier Goal approval result uses APK `70423555…` and exercises a different path.
2. Use the separate two-Owner report above for cross-Owner authorization and Hub-side signature rejection. That gap is now closed for the fixed image with synthetic Endpoints; it does not replace native Thread evidence.
3. Run physical-device key/Keystore and public HTTPS tests before making deployment claims. Both remain **NOT_RUN**.

## Core fixture feedback

The core-side `client-group-key-fixture.sh` and its recipe enabled the positive acceptance without new production routes. One operational issue arose: its long `/tmp/cicada-client-group-key.*` directory plus long synthetic Node ID exceeded the Unix-domain Join socket path limit. The Node Agent exited before Join. A short symlink allowed the socket but was correctly rejected by Node-local Endpoint key storage, which requires a real directory. The Client run copied only this disposable Node state into a private short real `/tmp` directory and then completed the test; both state locations were removed during teardown. Please make the fixture allocate a sufficiently short **real** Node state path and document the same-path MCP settings. This is fixture ergonomics, not evidence of a fixed-image protocol change.

The synthetic Owner's encrypted `session.capabilities` role was `external`, with Group and topology operations in its allowlist. The Client's legacy manager-role enrollment assertion failed after successful enrollment; a separate external-role encrypted capabilities test passed. The core fixture documentation should state that role explicitly so a future runner does not mistake the expected role for a Hub fault.

### Copyable prompt for the CICADA core maintainer

```text
You own only the CICADA core repository. Do not edit CICADA_CLIENT or modify
production Hub state.

Fixed acceptance target (already tested):
- source commit: 967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a
- contract: client-hub-v1.2.1
- protocol archive SHA-256: 7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a
- catalog SHA-256: 25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9
- image ID: sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7
- Native Group implementation commit: b676668e33c876c0d2c89bc3495fbd0d1e128c82
- Two-Owner instrumentation/fixture commit: 680fac2bf12c431ac02804e5db168669cf12941f
- Native Group report: CICADA_CLIENT/docs/client-group-key-v1.2.1-disposable-validation.md
- Authorization report: CICADA_CLIENT/docs/client-two-owner-v1.2.1-967dbd-validation.md

The one-Owner disposable fixture succeeded: Android encrypted manifest,
independent full Endpoint verification, external Owner signing, explicit phone
confirmation, encrypted grant and status CURRENT. The same grant became STALE
after the native binding lease expired and PROOF_EXPIRED after the proof expired;
the Android Client rejected a mutated Owner signature before submission.
The later two-Owner authorization run also passed with synthetic Endpoints:
both own grants CURRENT; A-to-B and B-to-A manifest/status/grant denied inside
authenticated encrypted responses; a corrupted public signature rejected by
the Hub; revoked A new requests and original-packet RPC/recover rejected with
HTTP 403, while B remained usable. It does not repeat native Thread acceptance.

Read the reports and working tree read-only. Review the fixed identities,
exact APK attribution, command exits, redacted summaries and teardown records.
The first development attempt's compile and canonical-input failures are
retained separately from the successful final fresh run. No core interface
gap remains for this authorization slice; do not request another replacement
fixture or expand Client to unshipped Monitor operations. Preserve the fixed
image and contract; a new Hub build needs a clean commit and complete
archive/catalog/image identity before new acceptance.

Do not put Owner private keys or Node bearers in Android, Git or logs, and do
not inspect or mutate a live Hub database. Physical Android and public HTTPS
remain NOT_RUN until independently tested.
```
