# Bounded Android Link recovery loop

## Current factual correction

Root's 2026-10-10 engineering correction withdraws the queued `ead771…`
interface, `573670…` freeze and 26-field promise. The actual Core contract
never changed: Parent `479adcd3…`, adapter `7dc6eb20…`, interface
`8f7bc4e7…`, freeze `6fa1159b…`, 25 callback fields, 11 NONE policy fields
and the original 82 requests remain fixed. The current consumer already
pins these exact artifacts; the older `390bb7d` blocked delivery below
preserves a failed historical coordination promise and creates no current
requirement to deliver replacement artifacts.

This closure changes only the documentation. The loop remains
`415f2eadee00860898e05f73451ec7e611b30d67544df16c7c7ad6340ddff9fd`;
the APKs, labels, signing contract, budgets and SOURCE continuity are
unchanged. Existing test receipts keep their original tested source; no
additional preparation test is run. The current clean commit and exact
twelve-driver map are in
`/gpu1-share/data/cicada-client/v164-e2a1908-current-facts-closure-20261010/final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
See the [handoff correction](cicada-core-handoff.md#current-factual-correction-withdrawn-coordination-promises)
for the read-only Root note and its digest. This is **HOLD / NOT_RUN**
preparation, not a Master GO or Owner authorization.

## Final ruling: original 82-request flow

Date: 2026-10-10. Root's final instruction supersedes the SOURCE-only
preparation and proposal below. Retain the frozen Parent's original 82
requests: two `SIGN_ENROLLMENT` requests per case, TARGET Android first and
SOURCE Android last, with BOOT/CLOSE accounting unchanged. Both enrollments
are real existing Android selectors. SOURCE remains active from its export
and enrollment through original recovery and `FINISH_CASE`; no profile may
be switched, reactivated or reselected within that window.

Each case creates two distinct fresh profiles. The fresh registry therefore
has sixteen planned new profiles plus its default entry, or seventeen total,
within the unchanged capacity of 32. On that fresh registry, expected TARGET
generations are 2, 4, ..., 16 and SOURCE generations are 3, 5, ..., 17.
Actual exported profile IDs/generations remain checked, including
TARGET-to-SOURCE progression and non-reuse across cases. Planned occupancy
is not a host-exported registry observation. No reset or new selector is
required.

`LinkConsentInteropTest.kt` has all four existing SOURCE/TARGET export and
enrollment `@Test` methods, and the original host driver already permits
both TARGET stage files and selectors. Root reports an actual `classes5.dex`
audit for the fixed test APK; its producer receipt will be recorded with
its original attribution when delivered. Client has independently read the
existing source/driver mapping. That source audit is not an Android run.

The host loop and its tests are restored byte-for-byte from `062c764`.
The SOURCE-only guard and its six tests are removed from the active path;
their `981853d` commit and 164-test evidence remain historical. The complete
current consumer migration is retained: four actual source pins, closed
freeze joins, adapter `7dc6eb20…` as READY runner, and strict
`http://127.0.0.1:8787`. The current twelve-driver map therefore matches
the original corrected-consumer preparation. No extra Go TARGET DTO,
74-request ordering, Parent rewrite, APK or production protocol is needed.

Android TARGET enrollment is not the Go TARGET session used by the external
readonly helper. The latter remains a separately enrolled/current device,
with actual KEY2/NONE4 encrypted reads and explicitly attributed Core
readonly pending-candidate evidence. External Owner signing keeps the exact
reviewed side and proof scope; enrollment does not create a TARGET Link
consent proof or establish bilateral acceptance. The unchanged 25-field
callback and eleven-field NONE policy preserve those distinctions. Android
readonly remains `NOT_RUN`.

Online remains **HOLD**, with all eight Android cases **NOT_RUN**. The final
offline restoration evidence and source pins are recorded under
`/gpu1-share/data/cicada-client/v164-e2a1908-final82-restoration-20261010`.
No prior failure, source-only proposal, old APK or synthetic protocol result
is relabeled as an online PASS. Root still owns the separate finite Master
GO and all lifecycle actions.

### Final82 restoration verification

The new Docker offline run passed **158** tests, exit **0**, with no failures
or skips: 5.191 seconds unittest / 6.280 seconds wrapper. It ran at parent
`981853d2d89643c187d3239838dfcbfe1bcb1c27`, **dirty=true**, after restoring
the actual loop/test bytes from `062c764`. Source hashes were unchanged
during execution. This is fresh offline evidence for the restored flow;
the earlier 164-test SOURCE-only evidence is not reused.

Actual commands under the evidence root above, each exit 0:

```sh
python3 <evidence-root>/run-offline.private.py
python3 <evidence-root>/freeze-inputs.private.py
git diff --check
docker ps -a --filter label=ai.cicada.client.offline-final82-restoration=20261010 --format '{{.ID}} {{.Status}}'
```

The last command returned no owned container. Docker data root remains
`/gpu1-share/data/docker-root`. The unit run used the same pinned offline
image, a read-only Client mount and `--network=none`, with no Core, secret,
model, Hub or emulator access. The input export reads and hashes public
Core preparation and fixed APK bytes; it executes no Core code.

| Artifact under the evidence root | SHA-256 |
|---|---|
| `python.receipt.redacted.json` | `fb5bb603e9b76715c6f29850a38f90a04b2847956d2195cf86eac3ae41017b90` |
| `final82-coordination.receipt.redacted.json` | `94f32aa37bd73d6db496cadd0d2452e363486cf580c271c2d95932137d533bda` |
| `final82-delivery/driver-pins.private.json` | `039c4ee00f0c8047ae5f878a2149cb6fabdeaed94cad50a819dd315cc158373f` |
| `final82-delivery/socket-interface.freeze.NONAUTH.json` | `510e8f7f686e8006db56d25d48a41857fba292e2feb60bcabb4fbae9f663dc83` |
| `final82-delivery/root-parent-template.private.json` | `b45a03fd3fcbcbaecf02c2ae9e087f36f3a7cfaf03d2b8f25dc656a1e579416c` |

The twelve-driver and callback maps are byte-identical to the corrected
consumer preparation. The new pre-BOOT Parent template differs only in
owned evidence placeholder paths and must be pinned by Root before any
Master GO. It is not the full Client runtime plan; that plan is derived only
after actual owned BOOT_READY. The complete final commit/tree, tracked
source inventory, tested-file joins, actual fixed Core/auxiliary and APK
pins are recorded in `final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
All eight online cases, Android readonly, actual Go readonly execution,
physical Android and public HTTPS remain `NOT_RUN`; native runtime is a
separate gate. Budgets stay 3600/360/240, with two exact owned 45-second
uncertain restarts. No online GO, push or merge is produced.

## Superseded SOURCE-only per-case preparation

The following section and its audit describe the revoked SOURCE-only
alternative. They remain evidence of that preparation, not a blocker or
required producer change for the retained original82 flow above.

Date: 2026-10-10. This operational boundary supersedes the TARGET-first
initialization in the historical frozen preparation below. Each of eight
cases creates and activates its own fresh Android SOURCE profile. There is
one initial activation from the default profile and seven inter-case
activations. From a case's device export and enrollment through original
packet recovery and `FINISH_CASE`, no profile may be switched, reselected
or reactivated. TARGET enrollment and readonly reconciliation belong to the
actual independent Go operator; no TARGET Android receipt is permitted.

The unchanged APK registry starts with one default profile and has an
existing limit of 32. The planned occupancy is eight new SOURCE profiles
plus that default entry, or nine total. Existing device exports report the
actual profile ID and generation; on the fresh owned emulator, the expected
SOURCE generations are 2 through 9. The host rejects reordered cases,
generation jumps or reuse, reused profiles and reused device public keys.
It correlates the existing fifteen-field Android enrollment receipt with
the exported run, profile, generation, Hub, Owner, device, device key,
original Grant hash, encrypted capability contract and session epoch.
Existing capture/recovery validators retain exact operation, packet, proof,
sequence and session scope. No new selector, reset or registry capacity is
introduced.

Nine entries is planned occupancy, not an exported registry observation:
the existing APK exposes no host registry-count snapshot. `FINISH_CASE` is
a host/Core join, not an Android active-profile observation. The eventual
command schedule must preserve the no-switch window; existing Native scope
checks protect capture and recovery. Unit fixtures do not establish actual
Android enrollment, counters, cryptography or profile activation.

The `780a8d` consumer migration is complete at `062c764`: the actual
consumer SHA-256 is
`1526a2c188a4225edbcb88a93cf84064c2c89819de19e6226a77f379e4e23ee9`.
It pins the four actual Parent artifacts below, the exact adapter runner,
and only `http://127.0.0.1:8787`. The old `55382c63…` consumer belongs to
archived `9d94b33`, not the current branch. The separate clean-source Docker
recheck passed 18 consumer tests, exit 0, with evidence at
`/gpu1-share/data/cicada-client/v164-e2a1908-current-consumer-recheck-20261010`.
Its actual-input receipt SHA-256 is
`82d4eccac3f73459413d30643e3437be1467082d516bceaf88dc73cdfedf04d2`.

SOURCE-only orchestration is **BLOCKED** on the actual Core mapping.
Parent `479adcd3…` still signs TARGET Android first and requires both Android
enrollments before selection. The public Core
`SOURCE-ONLY-GO-TARGET-GAP.NONAUTH.md` explicitly says `NOT_IMPLEMENTED,
NOT_GO`; its proposed path and schema are not accepted Client inputs.
The host now raises `ParentBlocked` before any TARGET Android staging,
selector, export or signing request. The historical case path therefore
cannot continue under the latest instruction. This is a deliberate safe
stop, not a completed SOURCE-only integration.

Required Core delivery: an exact safe public projection of the real current
Go TARGET participant, with identity/session/counter and verified-admission
provenance, its fixed path/schema/hash joins, and matching Parent,
`CASE_READY` and event-order source pins. Private operator metadata and
device keys are not acceptable inputs. The production admission verifier
having checked an original Grant is distinct from later independent
verification of that Grant; a retained digest alone cannot prove the latter.
Client will validate the actual delivered boundary without inventing fields
or attributing Go evidence to Android.

No final SOURCE-only runtime plan or twelve-driver freeze is issued while
that producer mapping is absent. The immutable APK pair, callback's 25
fields, NONE's eleven fields and separate readonly candidate provenance,
production protocol, fixed clean e2a Hub and budgets remain unchanged.
Eight Android recovery cases and actual Go reconciliation are **NOT_RUN**;
online remains **HOLD**. Earlier freezes and failures retain their own
source and APK attribution.

### Current offline verification

The host-only preparation passed **164** Docker unit tests, exit **0**, with
no failures or skips: 5.346 seconds unittest / 6.431 seconds wrapper. The
six new methods cover all eight synthetic SOURCE enrollment scopes,
generation progression, early TARGET rejection, reused identities and
tampered enrollment receipts. No Android or Core runtime is executed.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-source-only-guards-20261010`.
Actual commands and exits:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-source-only-guards-20261010/run-offline.private.py
# exit 0
git diff --check
# exit 0
docker ps -a --filter label=ai.cicada.client.offline-source-only-guards=20261010 --format '{{.ID}} {{.Status}}'
# exit 0, no matching owned offline container
```

`python.receipt.redacted.json`, SHA-256
`4ad830be0810a21226eedb10b749452611cd39f0bb00dd04427865143b5c1ed2`,
binds the exact Docker argv, source hashes, exit, log hash and tested parent
`062c76426cadabc9e8afe67019241f171588a89c`, **dirty=true**. Sources stayed
unchanged during the run. The Docker data root was checked as
`/gpu1-share/data/docker-root`; the pinned offline image is
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
It runs network-none with a read-only Client mount, no Core or secret mount,
no paid model and no Hub/emulator startup. The final commit and matching
tested Python hashes are recorded in
`HOST-SOURCE-ONLY-PREPARATION.NONAUTH.json`; that receipt is not a final
runtime-plan or twelve-driver freeze.

## Successor freeze: corrected 25-field Parent delivery

This is the preceding `062c764` TARGET-first preparation. Its consumer pin
verification remains valid; its initialization does not satisfy the current
SOURCE-only boundary above.

Date: 2026-10-10. Root explicitly authorized the corrected interface and freeze
below. The correction changes the explanatory callback count from 26 to 25;
Parent, adapter, compiler, callback fields and production contract bytes do
not change. This successor replaces the declared-metadata blocker as the
current preparation. The earlier blocked audits, failures and manifests
remain historical with their original source and APK attribution.

The existing twelfth driver, `v164-frozen-joint-inputs.py`, pins the four
delivered artifacts and now requires the actual reconciliation binary and
its compile receipt. It hashes regular, canonical, single-link, current-user
files and checks bounded sizes and modes: 0600 for the four artifacts and
receipt, 0755 for the binary. The binary is never executed by Client
preparation. Receipt checks bind compile-only scope, zero model calls,
unexecuted runtime, exact clean e2a source/image/fingerprint, binary bytes,
mode and digest. The five-entry source map and compiler receipt digest in
the freeze must also agree. No thirteenth driver or new runtime interface
is introduced.

All paths below are relative to the frozen Core delivery's
`joint-preparation/` directory.

| Artifact | SHA-256 |
|---|---|
| `joint-parent.py` | `479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794` |
| `joint-adapter-parent-ready.py` | `7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4` |
| `JOINT-PARENT-INTERFACE.NONAUTH.md` | `8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570` |
| `ADAPTER-PARENT-FREEZE.NONAUTH.json` | `6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39` |
| `reconcile-final-compile-format-2/bin/cicada-link-joint-reconcile` | `54d8c31b4a2aa5f762173876961b3b04ec680f23576ac1a42f3e9c65dd04d0b3` |
| `reconcile-final-compile-format-2/PREPARATION-RESULT.NONAUTH.json` | `96dbd99b2c2f6e9e6310d35432fd10d7214202f92ef0e0c1aa69e3a5e3296b1e` |

The closed callback has **25** top-level fields. NONE has exactly **11**
policy fields. Candidate version 1 remains noncurrent and bound to the native
reviewed digest; encrypted HEAD is current version 0, empty digest, both sides
`MISSING`, with bilateral verification false. The loss candidate SOURCE is
`VERIFIED` only through the separately attributed Core readonly receipt,
with origin `DB_READONLY_VERIFIED_SIGNED_PROOF`; TARGET remains `MISSING`.
The other three modes require `DB_READONLY_CONFIRMED_ABSENT`. The candidate
receipt digest binds Core's test-only `mode=ro/query_only` evidence and the
original proof hash. Client does not read that database or invent an
encrypted pending-candidate query.

KEY retains two encrypted direct reads, `policy=null` and result label
`CORE_PARENT_SEPARATE_ENCRYPTED_OWNER_SESSION`. NONE retains four encrypted
direct reads and exact label
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`. The opposite
Go operator must be independently enrolled and current; its reads are never
attributed to Android. Present-proof verification and missing-side checks do
not establish bilateral consent. Android readonly remains `NOT_RUN`.

The original 82-request flow is unchanged: TARGET Android enrollment first,
SOURCE enrollment and activation last, then no switch, reactivation or
reselection through original recovery and finish. Original signing, capture,
operation, packet and proof hashes remain exact. The immutable APK pair and
Root-endorsed pins are unchanged. Android uses exactly
`http://127.0.0.1:8787`; the existing network-none STDIO listener is
`127.0.0.1:18944`. Only Root may install, verify and remove the exact owned
`adb reverse tcp:8787 tcp:18944` mapping. There is no `10.0.2.2` route claim.

### Successor verification and delivery

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-successor25-consumer-freeze-20261010`.
The final clean Client commit, tree, tracked raw-input inventory, twelve
actual driver hashes, callback export and unchanged APK attribution are
bound in `final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`. Only the
existing consumer changes among those twelve drivers; the loop itself remains
`415f2eadee00860898e05f73451ec7e611b30d67544df16c7c7ad6340ddff9fd`.
The twelve-driver map SHA-256 is
`039c4ee00f0c8047ae5f878a2149cb6fabdeaed94cad50a819dd315cc158373f`.
No Core test or compiler is rerun by Client; the Core 64-test and 8-top/27-sub
compile receipts retain their producer-only attribution.

| Gate | Status | Actual command / exit and evidence |
|---|---|---|
| Current Client offline regressions | PASS | `python3 <evidence-root>/run-offline.private.py`, exit 0; 158 tests, no skips/failures, 5.250 seconds unittest / 6.333 seconds wrapper; `python.receipt.redacted.json` |
| Actual Parent/adapter/interface/freeze and auxiliary | PASS for hash and metadata checks | `python3 <evidence-root>/freeze-inputs.private.py`, exit 0; `final82-coordination.receipt.redacted.json` |
| Unchanged APK pair and endorsed pins | PASS for exact bytes | Same input audit, exit 0; no rebuild or APK execution |
| Client v2 offline plan template | PASS | `python3 <evidence-root>/verify-plan.offline.private.py`, exit 0, 0.840 seconds; `final82-delivery/offline-plan.receipt.NONAUTH.json` |
| Owned offline container closure | PASS | Exact-ID absence query, exit 0, no match; offline plan receipt and final quality receipt |
| Eight Android recovery cases / TARGET Go reads | NOT_RUN | Online HOLD, no Master GO |
| Android readonly / native Worker / physical Android / public HTTPS | NOT_RUN | Separate runtime gates |

Tests ran at parent `390bb7db58e7215a6958869fb67f2b7fc244f75d`,
**dirty=true**, with per-file hashes unchanged during execution and matched
to the successor commit. The Docker suite uses a pinned image,
`--network=none`, and only the read-only Client mount. It has no Core or key
mount. The separate offline plan mounts only the exact read-only public
source metadata, nonexecuted auxiliary and endorsed APK metadata. No Hub,
emulator, model or actual reconciliation is started. Unit tests use public
synthetic receipts and cannot establish signature verification or database
observations at runtime. They reject superseded metadata, stale/tampered
auxiliaries, wrong file permissions/links, inconsistent compiler scope/source
and incorrect binary metadata; the existing all-eight callback rejection
and result-record tests remain active.

The command receipts contain exact Docker argv and exit codes. Root's
pre-BOOT input is `final82-delivery/root-parent-template.private.json`,
schema `cicada.e2a1908-joint-loop-template.v1`; its SHA-256 is
`d1afd7a8d51a0afe09addf5560b0dd41ca1e8b6c43806d65050d956a9244a12e`.
The separate full Client v2 template is an offline format check with placeholder
paths, not a runtime plan or GO. The callback export SHA-256 is
`510e8f7f686e8006db56d25d48a41857fba292e2feb60bcabb4fbae9f663dc83`.

Root must independently review the final source inventory and twelve driver
pins, pin the original82 Parent template and final config, and issue a
separate finite Master GO. Only after actual BOOT_READY may Parent derive
the Client v2 plan from the owned 0700
`/tmp/cicada-joint-e2a-<opaque>/cases/0..7` tree. Approval, issued/expiry times
and budgets remain unchanged: 3600 seconds outer, 360 per case, 240 cleanup;
the two exact owned Hub restarts at indices 2 and 6 each have a 45-second
absolute limit. Failure stops execution without retries, fresh packets or
proof extensions. This delivery is preparation only, not online authority.

## Declared Parent source repin: producer delivery blocked

This section preserves the historical `390bb7d` declared-pin checkpoint.
Root's explicitly corrected successor delivery above is current.

Date: 2026-10-10. This pin-only checkpoint accepts Root's newly declared
interface and freeze digests. Parent and adapter bytes are unchanged. The
consumer retains exact file names, private-file guards, the five-entry freeze
map, `PASS_PREPARATION_SCOPE_ONLY` and `online=NOT_GO`. It neither accepts the
old metadata nor executes Core code.

| Artifact in Core `joint-preparation/` | Declared SHA-256 | Actual audit |
|---|---|---|
| `joint-parent.py` | `479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794` | PASS, exact bytes |
| `joint-adapter-parent-ready.py` | `7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4` | PASS, exact bytes |
| `JOINT-PARENT-INTERFACE.NONAUTH.md` | `ead77141679ef0b7a0379c3e2d77b1ac58e4dd1b19277b667c39c47d45c7c966` | BLOCKED, path still contains `8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570` |
| `ADAPTER-PARENT-FREEZE.NONAUTH.json` | `5736703af551999b9e5acbbfc4e2b8d6e2073879219d06276e4a387efd1f1ce4` | BLOCKED, path still contains `6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39` |

All four observed files are regular, current-user-owned mode-0600 files with
one link. The actual freeze still references the earlier interface. Root must
deliver the two exact declared byte artifacts at these paths or provide a
corrected immutable delivery. Client does not rewrite Core files or infer
replacement digests. `verify_artifacts` rejects this state with `INTERFACE_PIN`.
No source-pin PASS or actual-plan PASS is claimed for the missing delivery.

The pinned Parent's explicit emitted callback has **25** top-level fields,
not the count of 26 in the coordination message. This checkpoint preserves
those exact field names and eleven nested NONE fields; no unspecified field
is added. KEY remains two actual encrypted reads. NONE remains four actual
encrypted reads plus separately attributed Core readonly candidate evidence,
candidate1/noncurrent, HEAD0/empty/current/both-MISSING, the two required
provenance fields and the mixed result label. Android readonly stays `NOT_RUN`.
The 82-request flow, SOURCE continuity, budgets, frame and APKs are unchanged.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-parent-source-repin-20261010`.

| Gate | Status | Command / exit |
|---|---|---|
| Docker offline regressions | PASS | `python3 <evidence-root>/run-offline.private.py`, exit 0; 155 tests, no skips or failures, 5.204 seconds unittest / 6.481 seconds wrapper |
| Actual declared Core source audit | BLOCKED | `python3 <evidence-root>/audit-core-source.private.py`, exit 1, `INTERFACE_PIN`; receipt in `producer-audit-attempt01/` |
| Runtime plan with actual declared inputs | NOT_RUN | Actual source audit is blocked; no bypass or synthetic actual-source claim |
| Eight Android cases / actual Go reconciliation / Android readonly | NOT_RUN | Online HOLD, no Master GO |
| Native Worker / physical Android / public HTTPS | NOT_RUN | Separate acceptance gates |

Tests ran at parent `ab40f40c51f663e428eca76a518880e9fd28ded4`, **dirty=true**,
and bind unchanged final Python hashes. Their Docker container has network
disabled and mounts only Client read-only; no Core, key, database or APK mount.
The new negative regression rejects both previous declared metadata pins.
The final clean Client commit, raw tracked-input inventory, twelve actual
driver hashes, exact commands/exits, observed-versus-declared source metadata
and unchanged APK attribution are recorded in
`final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json` under this evidence root.
That delivery is explicitly **BLOCKED_PRODUCER_ARTIFACT_MISMATCH**, not a GO.
Earlier source-pin receipts and all failures remain historical and intact.

## Callback result-record verification

This section preserves the previous `ab40f40` checkpoint. The successor
freeze above supplies the current driver pins and producer-delivery status.

Date: 2026-10-10. The current callback follows the complete frozen proposal,
SHA-256 `486b0c2be499a08a50acf272c8f01801a4105ecc7a67ddf2d4cfb2748afbf717`.
The nine-field policy and single reconciliation label from historical
`888b587` are not accepted by this consumer. The previous `04349ac` consumer
already implemented the eleven-field NONE policy, HEAD0 semantics and mixed
result label. This checkpoint extracts its existing validation and final
record update into one testable boundary; it changes no callback fields,
events, CLI, profile order, budget, frame, APK or production protocol.

NONE requires candidate version `1`, the native reviewed digest and
`candidate_current=false`. Its encrypted HEAD is always version `0`, empty
digest, `current=true`, both sides `MISSING`, and not bilateral. Response-loss
requires separately verified candidate SOURCE `VERIFIED`, TARGET `MISSING`,
origin `DB_READONLY_VERIFIED_SIGNED_PROOF`; processing, uncertain and legacy
require both candidate sides `MISSING` and `DB_READONLY_CONFIRMED_ABSENT`.
The separate readonly receipt hash is mandatory. The result label is
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`; KEY retains
`policy=null`, its separate encrypted-session label and two ordered reads.
NONE retains four ordered encrypted reads. Android readonly stays `NOT_RUN`.

The new tests execute the actual validator and result-record function for
all eight public synthetic operation/mode pairs. They reject the old nine
fields, false encrypted-candidate provenance, wrong origin, invalid receipt
hash, candidate promotion, HEAD1 and bilateral inference. A rejected receipt
must leave the preceding `UNKNOWN`/`RECOVERED` record unchanged, without a
partial `PASS` or success label. This is offline guard evidence, not execution
of Android, Core reconciliation, signing or cryptography.

| Gate | Status | Actual evidence |
|---|---|---|
| Current callback regression before extraction | PASS | At clean `04349ac`, 4 tests / 58 subtests, exit 0; separate `callback-recheck-04349ac-20261010` receipt retained under the previous evidence root |
| Final Docker offline suite | PASS | 154 tests, no failures or skips, exit 0; 5.125 seconds unittest / 6.183 seconds wrapper |
| Result-record success and rejection | PASS for offline synthetic receipts | Three new tests execute receipt validation; no runtime acceptance |
| Eight Android cases / actual TARGET Go reconciliation | NOT_RUN | Online HOLD; no Root GO |
| Android readonly / native Worker / physical Android / public HTTPS | NOT_RUN | Separate runtime gates |

New evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-callback-record-freeze-20261010`.
Executed command, exit `0`:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-callback-record-freeze-20261010/run-offline.private.py
```

The receipt includes the exact pinned-image Docker command, with
`--network=none`, a read-only Client mount and no Core or key mount. The final
suite ran at parent `04349acccec94c977ee16b65059f92afe3a846a2`, **dirty=true**;
its source hashes bind the final committed Python bytes. The earlier passing
attempt is retained with its distinct source attribution. The final commit,
source inventory, twelve drivers, unchanged callback schema, refreshed
templates, actual commands/exits and unchanged APK pair are bound in this
root's `final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`. Root must review
these new driver bytes before deriving any runtime plan. This manifest is
preparation evidence, not a GO. Earlier manifests and failures remain intact.

## Final consumer freeze: original 82-request flow

This section preserves the previous `04349ac` preparation. The callback
result-record checkpoint above supplies the latest source-bound delivery.

Date: 2026-10-10. The final host consumer pins the actual four Core Parent
artifacts below, rather than the earlier three-file preparation. This is a
**PASS for offline consumer compatibility only**. Root's latest delivered
instruction explicitly revokes SOURCE-only and selects the original 82-request
flow: each case exports and enrolls the real TARGET Android device first,
then creates, enrolls and activates SOURCE. SOURCE must remain active from
review/signing through original capture, recovery and finish. No profile
reactivation or return switch is performed. Eight cases create sixteen fresh
profiles plus the initial default, within the fixed APK's limit of 32.

The read-only ruling is `ROOT-REVIEWED-FINAL-JOINT-RULING.NONAUTH.md`, SHA-256
`dee42017fa44371b24ecb53a6d640861de43a2957c97e264d5b7b962f53bf706`.
The four exact existing TARGET/SOURCE export/enrollment selectors are preserved;
their presence in the immutable APK does not establish execution. The separate
TARGET Go operator produces only the independently attributed encrypted
KEY-two/NONE-four reconciliation. Its device, counters and signatures are
actual Go evidence, not Android enrollment. Only SOURCE Link proof is tested,
and TARGET Android registration cannot imply TARGET Link approval or bilateral
acceptance. No Go-target preparation DTO, helper or compiler is added.

The prior SOURCE-only diagnosis is superseded. Its actual blocked observations
and receipts remain historical evidence in the preparation directory; they do
not describe this selected flow. Online remains **HOLD** until Root supplies
the reviewed config/template, actual owned paths and one separately issued
finite Master GO. No Android, Hub, native Runtime or model has been started.

### Independently checked consumer inputs

All four files are under the frozen Core delivery's `joint-preparation/`
directory. They must be regular, canonical, current-user-owned, single-link,
bounded mode-0600 files. The Client hashes and parses public metadata only;
it does not execute Parent, adapter or helper code.

| Artifact | SHA-256 |
|---|---|
| `joint-parent.py` | `479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794` |
| `joint-adapter-parent-ready.py` | `7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4` |
| `JOINT-PARENT-INTERFACE.NONAUTH.md` | `8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570` |
| `ADAPTER-PARENT-FREEZE.NONAUTH.json` | `6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39` |

The freeze must retain `PASS_PREPARATION_SCOPE_ONLY`, `online=NOT_GO` and its
exact five-file map, including both historical Core test pins. The nine READY
references and 17-field READY shape remain closed. `fixture.sh` must hash to
the adapter bytes, never the Parent or old adapter. The Android origin is
exactly `http://127.0.0.1:8787`; the owned network-none bridge uses
`127.0.0.1:18944`. Root must install, verify and remove only
`adb reverse tcp:8787 tcp:18944`, after the bridge listener is ready.
Old `10.0.2.2`, hostname aliases and changed ports are refused.

Plan v2 and the twelfth driver pin are existing safeguards, not new interfaces
added during this closure. `core_fixture_root` and `core_case_index` bind each
case to Root's exact `/tmp/cicada-joint-e2a-<opaque>/cases/0..7` tree, eliminating
caller-selected roots and case drift. Root, `cases`, and each selected case
must actually exist with mode 0700, current UID, canonical lexical/real paths
and no symlinks. The existing `v164-frozen-joint-inputs.py` pin binds source
artifacts, Runner, public references and fixed typed-control paths; it prevents
accepting stale F6 metadata as e2a evidence. No additional helper is introduced.

### Final offline results and delivery

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010`.
The tested parent is `6509a1cdf3eb159d7f9a770821b4345f78c36ba9`,
**dirty=true**. Tests bind every relevant Python source hash and verify that
those bytes did not change during execution. The final committed source,
twelve driver hashes, callback export, immutable APK attribution and actual
receipts are bound separately in `final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
The initial files under the earlier `v164-e2a1908-final-consumer-freeze-offline-20261010`
root retain the superseded SOURCE-only diagnosis and earlier consumer byte
attribution. Root must use this final82 delivery. Its last source correction
removes an extra EOF blank line; application/Kotlin/production bytes do not
change. The original staged whitespace-check failure (exit 2) is retained in
the final delivery, followed by the corrected combined-diff check (exit 0).

| Gate | Status | Actual result / evidence |
|---|---|---|
| Docker offline Python suite | PASS | 151 tests, no failures or skips, exit 0; 5.196 seconds unittest / 6.182 seconds wrapper; `python.receipt.redacted.json` |
| Four Core source pins and exact freeze map | PASS | Read-only audit, exit 0; `final82-coordination.receipt.redacted.json` |
| APK pair and Root-endorsed pins unchanged | PASS | Exact-byte audit, exit 0; `final82-coordination.receipt.redacted.json` |
| Offline container absence | PASS | Exact-ID query, exit 0, zero matches; `final82-delivery/offline-plan.receipt.NONAUTH.json` |
| Plan schema and source-pin validation | PASS | Offline full-plan template only, exit 0, 0.838 seconds; `final82-delivery/offline-plan.receipt.NONAUTH.json` |
| Original 82-request mapping | PASS for read-only source compatibility | TARGET-first/SOURCE-last selected explicitly; actual choreography remains NOT_RUN |
| Eight Android recovery cases | NOT_RUN | Online HOLD; no Root GO |
| TARGET Go preparation and mixed reconciliation execution | NOT_RUN | No new runtime execution; historical Core evidence is not this Client acceptance |
| Android readonly reconciliation | NOT_RUN | No applicable selector in the immutable APK |
| Real native Worker, physical Android, public HTTPS | NOT_RUN | Separate acceptance gates |

Executed command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/run-offline.private.py
```

Its receipt preserves the exact command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-final-consumer=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Final input audit and export command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/freeze-inputs.private.py
```

Offline plan command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/verify-plan.offline.private.py
```

`final82-coordination.receipt.redacted.json` checks the pinned inputs and binds
the unchanged tested source hashes. No original receipt is relabeled and
Android acceptance is not performed.
The final82 delivery includes two distinct templates: the offline full Client
v2 plan and `root-parent-template.private.json`, using Core's existing
`cicada.e2a1908-joint-loop-template.v1` format. The Parent template has seven
top-level fields and `relative_root=cases/<index>`; it deliberately contains
neither `core_fixture_root` nor `core_case_index`. Root derives those values
from actual `BOOT_READY`, records their provenance, and binds the resulting
Client plan into GO without extending the original expiry. A full v2 Client
plan is not substituted for the Parent's pre-BOOT template.

Negative tests exercise stale source bytes/pins/names, changed Parent,
incorrect freeze entries/status, old or Parent Runner hashes, old/aliased
Android origins, arbitrary roots, wrong case indices, lexical aliases,
non-directories, public permissions and symlinked directory levels.
Unchanged callback guards require exactly 25 top-level receipt fields and
eleven NONE policy fields. Candidate origin/hash, candidate 1, current HEAD 0,
original proof correlations and KEY-two/NONE-four ordered encrypted reads
remain mandatory. Android readonly remains `NOT_RUN`; NONE records retain
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`.

All historical failures, receipts and APK attribution below are retained.
No APK/Kotlin, production protocol/image, real key, Hub lifecycle or database
was changed. No push or merge is performed.

## Scope and artifact boundary

This test-only supervisor extends the [clean e2a1908 preparation](client-link-recovery-e2a1908-preparation.md).
It uses the existing immutable application/test APK pair and existing native
selectors. It changes no application feature, production protocol, permission,
Grant policy, sequence allocation or recovery fence. The old dd81575 F6
validator remains unchanged and is not an e2a1908 validator.

Online execution remains **HOLD** until Root supplies the complete fresh
inputs, independently pinned files and one finite GO. Offline mock tests are
not Android, Hub, Native Runtime or business acceptance. APK attribution
remains the actual `9b56832` dirty build/input inventory in the preparation
record; the new host supervisor is attributed separately.

| Immutable APK | SHA-256 |
|---|---|
| Application | `3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9` |
| Instrumentation | `243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae` |

Root and its Core adapter own Hub lifecycle, keys, external signing,
`FrameAdapter`, transport mapping, carrier snapshots and its private
FAULT_READY FD. The loop owns only its Client CLI subprocess groups and
private Client evidence. It never reads a Hub database, signs a proof,
receives a bearer/private key, exports a pending packet, calls a model or
rebuilds an APK.

## Scheduling and deadlines

Exactly eight cases cover `link.key_grant` and `link.review_policy_grant`
against `response-loss`, `processing`, `uncertain` and `legacy`. The frozen
Core adapter orders the four KEY cases first, then the four NONE cases; only
SOURCE receives the fault. This does not claim sixteen bilateral fault
invocations. Every case has a distinct run, fixture root, Link, both Owners,
Groups, Endpoints and two fresh Android device identities. Android enrolls
TARGET first, then creates and enrolls SOURCE. SOURCE remains active until its
recovery completes. The two actual native enrollment exports must show distinct
profiles and an increasing selection generation. Returning to an old profile
would invalidate its saved generation; no such return is assumed or performed.
These runtime checks are **NOT_RUN** while online execution is on HOLD.

| Budget | Maximum |
|---|---:|
| Root-owned emulator readiness/install | 480 seconds |
| Each case | 360 seconds |
| Direct enrollment, native review and signing handoffs | 120 seconds |
| Opaque activation, original capture and capture export | 75 seconds |
| Matched FAULT_READY, optional owned restart and READY staging | 45 seconds |
| One original recovery, result export and carrier snapshot | 60 seconds |
| Separate participating Owner reconciliation | 60 seconds |
| Android closure and evidence | 240 seconds |
| Entire run | 3600 seconds |

The outer deadline is the earlier of 3600 seconds and the exact Root GO expiry.
The loop reserves 240 seconds before work begins. All case/stage deadlines are
absolute monotonic cutoffs clipped to their parent. Binding and reviewed proof
expiry can shorten a case; neither is extended. Each child execution reserves
two seconds inside its stage deadline for TERM/KILL/reaping. The parent channel
checks the remaining absolute deadline for every receive, so a slow partial
reply does not reset the budget.

These are abort limits, not measured promises that a case will finish. Any
failure stops later cases. An interrupted case is `UNKNOWN`, an explicitly
missing prerequisite is `BLOCKED`, and unstarted cases stay `NOT_RUN`. No
automatic retry, new operation, replacement packet, second recovery or
proof renewal is performed. Original app-private pending/retired state and
failure receipts remain untouched.

## Minimal invocation

All paths below are operator-supplied; examples do not name real identities.
The loop is `scripts/interop/v164-link-recovery-loop.py`; deadline/process
handling is `scripts/interop/v164-recovery-loop-budget.py`.

Offline plan validation, with no child, socket or Android operation:

```sh
python3 scripts/interop/v164-link-recovery-loop.py \
  --plan "$ROOT_PLAN" --plan-sha256 "$ROOT_PLAN_SHA" --validate-plan
```

Runtime invocation, deferred until the separate Root GO:

```sh
python3 scripts/interop/v164-link-recovery-loop.py \
  --plan "$ROOT_PLAN" --plan-sha256 "$ROOT_PLAN_SHA" \
  --root-go "$ROOT_GO" --root-go-sha256 "$ROOT_GO_SHA" \
  --parent-fd "$LOOP_PARENT_FD"
```

Root passes a private inherited Unix stream socket whose peer UID matches the
Client operator. This socket is **separate** from the carrier's control FD.
No child inherits it. The existing carrier control message remains exactly
`kind`, `envelope_b64`, `envelope_sha256`, with `kind=fault-ready`.

The Core parent can implement the same boundary in-process by supplying a
`request(event, case_id, payload, deadline)` object to `RecoveryLoop`. Such an
implementation must enforce that absolute deadline itself; the socket
implementation provides the bounded cross-process variant.

## Closed test coordination formats

These schemas describe host test coordination. They add no Hub API or authority.
Core can map its delivered sidecar/public paths into this boundary without
changing the old strict READY format or native Client contracts.

A `FileRef` has exactly `path` and `sha256`. Inputs are operator-owned,
non-symlink, single-link, bounded mode-0600 JSON/JSONL files under the selected
case root or Client evidence root. Device and review exports contain only
public material. Database, environment, key and secret-directory inputs are
refused. The loop snapshots exact hashed input bytes before invoking the
existing staging CLI, which normalizes some older JSON wrappers.

The plan schema is `cicada.client-v164-recovery-loop-plan.v2`, with exactly:

- `schema`, `batch_id`, `core_fixture_root`, `android_evidence`, `evidence_root`;
- `apk_pins`: a Root-owned FileRef using the existing recovery APK-pin schema;
- `driver_sha256`: all twelve exact Client driver/module files named by `DRIVERS`;
- `cases`: eight objects, each containing `case_id`, `core_case_index`, `run_id`,
  `side=source`, `operation`, `mode`, `fixture_root`.

Root constructs this plan after Core's `BOOT_READY` supplies the actual fresh
`/tmp/cicada-joint-e2a-<opaque>/` root. Case indices are exactly 0–7 and roots
are exactly `<core_fixture_root>/cases/<index>`. Run IDs share the Core run base
and end in `-<index>`. The fixed public interface currently pins the base
`v164-e2a1908-joint-20261010`; a new delivery needs new independently verified
pins. Preparing the Core process remains Root's responsibility and requires its
separate GO.

`android_evidence` belongs to the existing recovery runner and has parent
`v16-deterministic-v164-recovery-<fresh-label>`. `evidence_root` is a separate
fresh mode-0700 directory below `/gpu1-share/data/cicada-client`. Runtime
creates a GO-consumed marker before contacting the parent or spawning a child;
the same plan/evidence location cannot be rerun. Proposed immutable APK-pin
bytes remain mode 0400 in the preparation delivery; Root must supply its own
exact-byte 0600 copy and independently endorse its SHA. Reader permissions
are not relaxed.

GO schema: `cicada.client-v164-recovery-loop-go.v1`. Exact fields are `schema`,
`root_thread_id`, `batch_id`, `plan_sha256`, `approved`, `approval_id`, `issued_at`,
`expires_at`, `outer_seconds=3600`, `case_seconds=360`. Root thread is
`01a0a91b-c2b6-76b2-baf5-95422f4deeef`; `approved` must be true and the UTC lease
must already be valid, no longer than 3600 seconds. Supplying this file is not
permission to run online before Root's separate GO. More than 240 seconds must
remain before GO is consumed. File fields and a matching socket UID do not
authenticate Root approval; the trusted Root parent owns that provenance.

Parent request schema: `cicada.client-v164-recovery-loop-request.v1`. Exact
fields: `schema`, `request_id`, `batch_id`, `case_id`, `event`, `remaining_ms`,
`payload`. One reply is a bounded LF-terminated JSON record with schema
`cicada.client-v164-recovery-loop-reply.v1`, the same correlation fields,
`result=READY|BLOCKED|FAIL`, and `payload`. Duplicate keys, mismatched IDs/events,
extra records, credential fields, EOF and late replies are rejected.

## Parent event mapping

The parent receives only public-file references/hashes and redacted correlation.
It must not send private keys, bearer values, device codes or raw packet/proof
contents through the channel.

| Event | Loop request | Required READY payload / parent action |
|---|---|---|
| `BOOT_READY` | Empty; no case | `ownership` FileRef for the exact owned network-none emulator; `core_fixture_root` equal to the plan |
| `CASE_READY` | `core_control={action:prepare,case:<index>}` | `ready` FileRef at `public/READY.json`; `setups={source:<FileRef>,target:<FileRef>}`; exact `binding`; UTC `valid_until` equal to Core's coordination deadline |
| `SIGN_ENROLLMENT` | Exported `device` FileRef; typed `device` control with side and `manifest_sha256` | `grant` FileRef at `signed-proofs/<side>-device-grant.json`; TARGET first, then SOURCE |
| `LINK_SELECTION` | `device` and encrypted-capabilities `enrollment` receipt FileRefs | `selection` FileRef; NONE additionally `policy` FileRef |
| `SIGN_CONSENT` | Native `review` FileRef; typed SOURCE `proof` control with `input_sha256` | `proof` FileRef at `signed-proofs/source-link-proof.json`; UTC `valid_until` exactly equal to the exported flat signing request expiry and within the native maximum |
| `ACTIVATE_OPAQUE` | `enrollment` FileRef; typed SOURCE `proxy` control | `carrier_manifest`, `raw_ready`, `scenario` FileRefs at `public/carrier-manifest.json`, `public/proxy-ready.jsonl`, `public/recovery-scenario.json` |
| `FAULT_READY` | Immutable Android `capture` FileRef; typed `capture` control with `capture_sha256` | `ready` FileRef at `public/fault-envelope.json`, `capture_verified=true`, `control_installed=true`; Core must emit `CAPTURE_VERIFIED` before Root forwards the control frame; uncertain requires Root's actual restart after the matched event |
| `CARRIER_SNAPSHOT` | `capture`, `result` FileRefs | `snapshot` FileRef from the parent's actual `FrameAdapter.evidence_snapshot()` |
| `FINISH_CASE` | `result`, `snapshot` FileRefs; typed `finish` control with `result_sha256`, `carrier_sha256` | `case_finished=true` only after Core's `CASE_FINISHED`; called before separate reconciliation |
| `RECONCILE_DIRECT` | `capture`, `result`, native `review` FileRefs | `receipt` FileRef from the opposite participating Owner/device/session over direct encrypted Hub RPC |
| `CLOSE_ANDROID` | `ownership` FileRef or null; `child_journal_directory`; no case | `receipt` FileRef for exact owned Android process/container closure |

The strict 17-field F6 READY shape is preserved. The new
`v164-frozen-joint-inputs.py` validates its nine exact public reference paths,
modes, sizes and hashes, clean e2a provenance and cross-file identities. It
reads only public metadata and public helper/source bytes; it neither executes
those helpers nor opens the private files listed in the custody description.
The loop never calls the old dd81575 delivery validator with e2a data. Root
validates any additional private sidecar in its original delivered format.
The mapped `binding` has exactly `hub_id`, `owner_id`, `owner_key_id`, `device_id`,
`link_id`, `link_version`, `source_owner_id`, `target_owner_id`, `source_group_id`,
`target_group_id`, `source_endpoint_id`, `target_endpoint_id`. The selected
setup and Link selection must match. The carrier manifest and raw READY are
independently parsed by the existing e2a carrier and must match the current
Android enrollment epoch, Owner/device and scenario.

Core's nested public setup is not an Android onboarding DTO: it is mode 0644
and has no device ID. Root explicitly assigns fresh opaque device IDs and
creates mode-0600 public onboarding wrappers under Client evidence. The loop
checks their full Hub/Owner public keys against Core's pinned metadata. Root
also supplies the existing closed Link-selection and NONE-policy wrappers;
their profile/generation comes from the actual SOURCE device export. Static
fixture manifest data never replaces the native live encrypted review.

Root copies each exact Android public export, without normalization, to the
Core case's fixed `client-inputs/` path before writing its typed control to
the inherited Core FD. Device files are named `<side>-device-enrollment.json`,
reviews `<side>-review.json`, and capture/result/carrier files are
`capture.json`, `result.json`, `carrier.json`. Only hashes and typed fields go
through Core's FD; public-file references go through the separate Client socket.
Raw Core `PROXY_READY` does not carry the READY-byte digest: use the pinned
manifest's `ready_raw_sha256`. Buffer unsolicited Core `FAULT_READY`; verify
Android capture through Core first, then install its exact carrier frame.

Root enrolls its separate participating reconciliation session on the direct
path. Android enrolls both fresh case profiles before opaque routing. After
the original fault the selected transport admits only that original recovery;
local staging/export commands do not send fresh Hub RPC. Root keeps the carrier
and original packet correlation in memory across both uncertain Hub restarts.

## Separate-session reconciliation boundary

The fixed APK has no standalone v1.6.4 readonly KEY/NONE reconciliation selector.
Existing `submitsHostSigned*` tests write grants before reading status; they are
not substituted for readonly reconciliation. The v1.6.1 default-NONE selector
rejects v1.6.4 and is also not a substitute. No new Kotlin or APK is introduced.

Root's `RECONCILE_DIRECT` implementation must use a separately enrolled,
opposite-side Owner/device session and perform actual encrypted reads. It
verifies response signatures, AAD/counters, current Endpoint proofs, independent
Owner keys and manifest/binding scope. KEY proof evidence comes from those
verified reads. On the fixed e2a image, NONE `link.review_policy_status` exposes
only the current HEAD; a singly accepted pending candidate requires the
separately authorized Core fixture verification described below. It returns a
redacted receipt with schema
`cicada.client-v164-recovery-loop-direct-reconciliation.v1`. Exact fields are
defined by `validate_reconciliation`: case/run/Hub/Link/binding hashes and
version, participating Owner/device/epoch, direct/encrypted/readonly markers,
manifest digest and verification markers, original proof hash and observation,
both side statuses, policy mode, bilateral verification, `policy` and correlated
reads. `manifest_digest` must equal the native reviewed manifest digest.
The frozen proposal's explicit top-level list matches the existing 25 fields;
no field is added to that list or to the callback envelope. All eight fresh
Cases that submit only the SOURCE Link proof require the opposite side to be `MISSING` and
`bilateral_verified=false`.

Each read has exactly `operation`, `operation_id_sha256`, `request_sha256`,
`response_sha256`, `request_sequence`, `response_sequence`. IDs are unique and
sequence strings strictly increase. KEY requires exactly `link.key_manifest`
then `link.key_grants`; NONE requires exactly those two followed by
`link.review_policy_status` then `link.review_policy_preview`. Extra, repeated
or reordered reads are refused. Any write, faulted device, foreign Owner,
wrong scope/proof or inferred bilateral acceptance is refused.

Only response-loss runs the original handler; its original proof must be
observed accepted. Outer processing/uncertain/legacy evidence must not invent
original proof acceptance. NONE reconciliation distinguishes the exact signed
candidate from a default/current HEAD0: a head alone cannot establish grant
acceptance. KEY requires `policy=null`. NONE requires a closed object with:

- `candidate_version`, `candidate_digest`, `candidate_current`;
- `candidate_evidence_origin`, `candidate_evidence_receipt_sha256`;
- `head_version`, `head_digest`, `head_current`;
- `head_source_status`, `head_target_status`, `head_bilateral_verified`.

Candidate version must be `1` in both the receipt and native review; its digest
must match the native review. All four NONE cases require
`candidate_current=false`, current head version `0`, empty head digest, both
head statuses `MISSING` and no head bilateral verification. Response-loss has
candidate SOURCE `VERIFIED` and TARGET `MISSING`; the three outer modes have
both candidate sides `MISSING`. A promoted candidate or bilateral receipt is
refused for this fresh fixture. This distinguishes the candidate from the
active head without adding a Client query API.

For NONE, the four real encrypted reads provide the current manifest, KEY
grants, policy HEAD and exact candidate preview. They do not supply evidence
that the singly approved candidate proof was stored. Core alone may inspect
the exact disposable fixture state using SQLite `mode=ro` and `query_only`,
and run the production signature, scope and expiry verifier against the
current independent Owner pins and exact original captured proof SHA-256.
Presence or database counts without that verification are insufficient. The
Client neither opens the database nor receives raw proof/database contents.

The two new nested fields are mandatory test coordination metadata:

| Case evidence | Required `candidate_evidence_origin` |
|---|---|
| Response-loss with the original SOURCE proof observed and verified | `DB_READONLY_VERIFIED_SIGNED_PROOF` |
| Processing, uncertain or legacy, with the original candidate proof confirmed absent | `DB_READONLY_CONFIRMED_ABSENT` |

`candidate_evidence_receipt_sha256` is a canonical lowercase 64-character hash
of the actual Core readonly verification receipt. RootParent must verify and
hash that receipt, correlate its Link/candidate/current bindings and original
proof hash, and supply the hash in the callback. The Client validates the
origin, digest format and existing case/proof/status correlations; it does not
independently execute the database or signature verification represented by
that hash. Missing or unverifiable provenance must produce a parent
`BLOCKED` reply and stop the loop, including NONE response-loss. No candidate
query endpoint or Android capability is introduced.

In NONE receipts, top-level `proof_observed`, `source_status` and
`target_status` describe the separately verified candidate, while the nested
`head_*` fields describe the encrypted HEAD response. `encrypted_verified`
and `transport=DIRECT` apply to the correlated RPC reads, not the database
candidate evidence. `owner_proofs_verified=true` means all present proofs and
expected missing sides were checked; it never implies bilateral acceptance.
`bilateral_verified` must remain false in all eight fresh cases.

The final KEY case record labels reconciliation as
`CORE_PARENT_SEPARATE_ENCRYPTED_OWNER_SESSION`; the final NONE case record uses
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`. Android standalone readonly
reconciliation stays `NOT_RUN`. These are test-only provenance labels;
`policy=null` remains mandatory for KEY. Receipt checks correlate Root evidence;
they do not independently execute/decrypt that separate session on Android. Native
recovery receipts continue to say business acceptance is unestablished until
this separately attributed reconciliation succeeds.

## Owned Android closure

The parent boot ownership file schema is
`cicada.client-v164-recovery-loop-android-owned.v1`, with `schema`, full
`container_id`, exact `image_id`, `network=none`, `auto_remove=true`, `label`
and runner `run_id`. Root independently inspects the actual container, including
its auto-removal setting. It binds the existing recovery runner label and image.

Client children run in new sessions. Private, fsynced process journals record
start PID/PGID/start ticks and command digest before waiting, then finish/reap
evidence. Root can use those journals if the loop itself is interrupted. TERM
and KILL require a fresh Linux `/proc` check for the exact session, UID and
leader identity. Unverifiable ownership yields UNKNOWN; no broad process-name
kill is used. Remote Android instrumentation is owned by Root's exact emulator
and must be terminated through that ownership boundary too.

Close receipt schema: `cicada.client-v164-recovery-loop-android-close.v1`, with
`schema`, `ownership_sha256`, `container_id_sha256`, `removed=true`,
`absence_exit_code=1`, `absence_confirmed=true`, `process_groups_closed=true`,
and two or three distinct `command_receipts` FileRefs. Each receipt has schema
`cicada.client-v164-recovery-loop-android-command.v1` and exactly `schema`,
`role`, `argv`, `exit_code`, `stdout_sha256`, `stderr_sha256`,
`absence_confirmed`. Commands use the full owned container ID:

| Role | Exact argv | Exit | Absence confirmed |
|---|---|---:|---|
| `stop` | `docker stop --time 10 <full-id>` | 0 | false |
| `remove` | `docker rm --force <full-id>` | 0 | false |
| `absence` | `docker inspect <full-id> --format {{.Id}}` | 1 | true |

At least one stop/removal receipt and the absence receipt are required; duplicate
roles, paths and hashes are refused. Root records the actual bounded commands,
stream digests and independent absence confirmation. The existing runner uses
`docker run --rm`: stopping that exact container may establish removal without
a subsequent `docker rm` command. The Client joins the
receipt to its exact boot ownership; a process exit alone does not establish
container removal. If boot fails before ownership is delivered, cleanup remains
UNKNOWN rather than claiming closure. Hub/Node/helper/key disposal remains
Root's separate responsibility.

## Verification and current status

### Final frozen callback clarification

The Root-authorized proposal was independently read and SHA-256 checked:
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/CALLBACK-FROZEN-PROPOSAL.NONAUTH.md`,
`486b0c2be499a08a50acf272c8f01801a4105ecc7a67ddf2d4cfb2748afbf717`.
The callback envelope, 25 top-level receipt fields and eleven nested NONE
policy fields are unchanged from the preceding metadata extension. The final
NONE result label is exactly
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`.
The test-only validator now refuses any bilateral acceptance, candidate
promotion, wrong candidate version or extra/repeated/reordered direct read
in these fresh fixtures that submit only the SOURCE proof. This does not change Kotlin, the APK
pair, production contracts, pins, Grants, packet sequences or recovery fences.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-final-callback-freeze-offline-20261010`.
Actual tests ran against parent Client
`608fae2a54cbd34e92cae481c46e6a48b003964e`, **dirty=true**.
Docker offline verification is **PASS**, 141 tests, exit **0**, 6.181 seconds
including startup. The tests exercise all eight synthetic status combinations
and reject false bilateral/head promotion and altered receipt boundaries.
They do not execute Core database verification or Android.

Actual command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-final-callback=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Loop SHA-256:
`6a22e02b41da5118c922673780dbbd711d8df7159bb7fd9828b579fe7aef3dfa`;
reconciliation test source:
`68d00b743057d537e083d8f586b078413ad568a9903c34ba768303352946e973`;
test receipt:
`0aab6644730182d87be846658f3d2c3057de921bb5d3a1135a9e864bd24cae43`.

The actual audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-final-callback-freeze-offline-20261010/audit-offline.private.py`,
exit **0**. Frozen Core interface/proposal hashes, eleven unchanged companion
drivers and both immutable APKs are **PASS**. The offline test container was
absent after completion: **PASS**, query exit **0**, zero matches. Receipts are
`frozen-interface-verification.redacted.json`,
`callback-proposal-verification.redacted.json`,
`immutable-input-audit.redacted.json` and
`offline-container-absence.receipt.redacted.json` under that evidence root.

The final plan template passed Docker `--validate-plan`, exit **0**,
0.79 seconds; exact argv and actual container absence are recorded in
`frozen-delivery/offline-plan.receipt.NONAUTH.json`. The plan is only an
offline template, with placeholder paths and no execution authorization.
The frozen delivery contains `companion-driver-pins.private.json` for eleven
unchanged files and `driver-pins.private.json` for all twelve exact plan pins,
including the changed loop. It binds the final callback metadata, Client
commit/tree/source inventory, unchanged APK attribution and actual receipts
in `commit-delivery.receipt.redacted.json` and
`frozen-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.

Root must review the frozen loop/Parent mapping, render actual paths and bind
the actual plan hash into a separate finite GO. Online remains **HOLD**.
All eight Android cases, real candidate evidence verification, opposite-Owner
reconciliation, encrypted runtime capabilities, profile transitions and owned
Android closure are **NOT_RUN**. Android readonly, physical-device, public
HTTPS and Native Worker results remain **NOT_RUN**. Missing verified candidate
provenance must yield **BLOCKED**. Earlier receipts, failures and APK build
attribution are retained. No push or merge is performed.

### Historical mixed NONE metadata extension: 608fae2

Only the host test coordination policy receipt and its provenance label change
in this successor. The socket request/reply schemas, callback FileRefs, Core
controls, selectors, plan v2, deadlines, packet/grant/sequence/fence validation,
Kotlin, APK pair and fixed e2a Hub remain unchanged. The two new policy fields
and exact expected origins are defined in the reconciliation section above.
No production candidate-query API is present or inferred.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-mixed-none-reconciliation-offline-20261010`.
Testing used parent Client `888b587ce103208bdb5e7da33e56217757a4c09f`,
**dirty=true**. Its 140 Python tests passed with exit **0**, 6.184 seconds
including Docker startup, and all tested source hashes remained unchanged.
Tests explicitly accept the singly verified SOURCE proof with current HEAD0,
confirm absence in all three outer fault modes, refuse missing or misleading
evidence metadata, and retain all four required encrypted reads. These use
synthetic receipts; neither database verification nor Android execution occurs.

Actual command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-mixed-none=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Current loop SHA-256:
`d736dafee975fdc6671d989902b52b9593275580a66705c1536ea1d388da1734`;
reconciliation test source:
`1780f9c495b8233fe8bf50caa4971c0bc93a3f2d26111b1dfc1f3e279d62e1d3`;
test receipt:
`92bc8524eb26aa06e290aa76e4b391c3378bce4d02023d23a2eba22c2a079052`.
Frozen public-interface pins, eleven unchanged companion drivers and both APK
hashes were independently checked: **PASS**, audit command exit **0**.
The offline test container was absent after completion: **PASS**, query exit
**0**, zero matches. Their evidence files are
`frozen-interface-verification.redacted.json`, `immutable-input-audit.redacted.json`
and `offline-container-absence.receipt.redacted.json` in the successor root.
The actual audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-mixed-none-reconciliation-offline-20261010/audit-offline.private.py`.

The successor `frozen-delivery/loop-plan.template.private.json` passed the
existing Docker `--validate-plan` command, exit **0**, 0.84 seconds. Exact argv,
readonly public mounts, log hash and confirmed offline-container absence are
in `frozen-delivery/offline-plan.receipt.NONAUTH.json`. This validates the
frozen schema/driver/endorsed-APK metadata with placeholder paths; it is not a
runtime plan or Root GO. Root must render actual BOOT_READY and evidence paths,
recompute the plan hash and bind it into a separately reviewed finite GO.

The final source commit, twelve driver pins, plan template and unchanged APK
attribution are bound in the successor `commit-delivery.receipt.redacted.json`
and `frozen-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`. Previous frozen
schema exports and offline results remain attributed to `888b587`; they are
not silently updated or reused as current-source acceptance.

All eight Android scenarios, actual Core candidate verification, encrypted
runtime capabilities, separate Owner reconciliation and Android closure are
**NOT_RUN** while online remains **HOLD**. Android readonly, physical hardware,
public HTTPS and Native Worker remain **NOT_RUN**. RootParent must return
**BLOCKED** if it cannot supply verified candidate provenance. No push or merge
is performed.

### Historical frozen joint-interface alignment: 888b587

The following three Core delivery files were independently read and checked;
none was executed. Core checkout `36ebfab` does not replace the Hub image's
clean `e2a1908` source attribution.

| Frozen joint preparation file | SHA-256 |
|---|---|
| `JOINT-8CASE-INTERFACE.NONAUTH.md` | `618ecef915ad00c6f9fc61d842285989a8e61c59eded900c26aa64cc0e216805` |
| `ADAPTER-FREEZE.NONAUTH.json` | `eb34be4e43c4ae8e64e5b7fc397e76be0a2ef47b10cd5313918361b4d6eaa107` |
| `joint-adapter.py` | `29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4` |

They remain under the Core delivery's `joint-preparation/` directory. The
Client helper pins these exact bytes before plan validation; no proposed
configuration or APK-pin file constitutes Root GO. The existing strict
carrier READY, grant validation, sequence allocation and recovery fences remain
unchanged. A case is not complete merely because the Core fixture is ready:
the Android capture, one recovery, Core finish and actual separate encrypted
reconciliation must all complete within their deadlines.

Current evidence is recorded separately under
`/gpu1-share/data/cicada-client/v164-e2a1908-frozen-joint-loop-offline-20261010`.
Testing used Client parent HEAD
`015d2d3fd2518c24369a8d296ff341e256f58eda`, **dirty=true**. The source-bound
test receipt and final commit receipt preserve that attribution separately
from the unchanged APK build input snapshot.

| Current offline verification | Result / actual exit | Evidence in that directory |
|---|---|---|
| Docker Python suite | **PASS**; 140 tests; exit 0; 6.283 seconds including container startup | `python.receipt.redacted.json`, `python.private.log` |
| Source unchanged throughout test execution | **PASS**; test launcher exit 0 | Full per-file hashes in the test receipt |
| Frozen interface, freeze manifest and adapter exact bytes | **PASS**; audit exit 0 | `frozen-interface-verification.redacted.json` |
| Nine old drivers and fixed APK pair unchanged | **PASS**; audit exit 0 | `immutable-input-audit.redacted.json` |
| Offline test-container absence | **PASS**; `docker ps` exit 0, zero matches | `offline-container-absence.receipt.redacted.json` |

Actual Docker command for the current suite:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-frozen-joint=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

The actual host audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-frozen-joint-loop-offline-20261010/audit-offline.private.py`,
exit **0**. It only verifies public frozen metadata, hashes existing drivers
and APKs, and checks absence of its offline-container label. It does not
operate a Hub or resident deployment. Docker data root was confirmed as
`/gpu1-share/data/docker-root` (`docker info --format '{{.DockerRootDir}}'`, exit 0).

The new tests cover v2 plan rejections, closed controls/paths, public metadata
mismatch, exact-byte/mode/symlink pins, Go timestamps and literal capture
verification. The all-eight supervisor-order test mocks `one_case`; it tests
scheduling and closure, not an Android/Core exchange. Existing recovery and
carrier tests remain part of the suite. No offline test result is an online
case result.

The first frozen-interface suite also passed 140 tests, exit 0, 6.283 seconds.
Review then found that plan validation allowed a consistent run base broader
than Core's fixed run ID. The validator now rejects that mismatch before
runtime and its fixtures use the exact frozen base. `attempt01.*` preserves
the first source pins, receipt and log; the final rerun above passed with the
corrected source. Neither attempt executed Android or Core.

| Current host source | SHA-256 |
|---|---|
| `v164-link-recovery-loop.py` | `2fcd14e57f540ee35d5108cd8157c0e0e2b7566899033ad3cd06de7f545e67ee` |
| `v164-recovery-loop-budget.py` (unchanged) | `b4563b0f0119018e36da8a3a1b13bbf7dc4feceaa9104746242f3683c4908328` |
| `v164-frozen-joint-inputs.py` | `55382c6391f837d05bc1247931c27a4de068534ed58405cf41ef4528d6388178` |
| `test_v164_link_recovery_loop.py` | `134606a3646936d31ba5017bee8f6f5597ea42e0fbc5eef6b5c0de7b2a644a29` |
| `test_v164_frozen_joint_inputs.py` | `0f300f874fdb3201592b30045a19b8380ce4a31832811bcfbb7dd7f65192834b` |

Current test-receipt SHA-256:
`4b6932624cea42041d5aa58558a0ae4f08f9fc754cda2e84ab89823c3e1674c7`.
The final commit/tree, input inventory, twelve driver hashes and unchanged APK
attribution are bound in `commit-delivery.receipt.redacted.json`; these files
are private evidence outside Git. No push or merge is performed.

Runtime capability validation, both Android enrollments/profile transitions,
the eight Android recovery cases, opposite-Owner encrypted reconciliation and
owned emulator closure remain **NOT_RUN** pending joint GO. A requirement for
standalone Android readonly reconciliation is **BLOCKED** by the missing
selector in the fixed APK; the external Core-parent receipt is explicitly a
different execution layer. Physical Android and public HTTPS are **NOT_RUN**.

### Historical first loop checkpoint

The results and source hashes below belong to Client checkpoint
`015d2d3fd2518c24369a8d296ff341e256f58eda` and the first loop interface. They
remain evidence for that checkpoint and are not substituted for the new
frozen-interface verification.

The fixed target remains clean Core
`e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59`, `client-hub-v1.6.4`, wire 1,
catalog 55. The frozen Hub image is
`sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01`;
test image is
`sha256:73ec018a026a27fb04ec0c651bafa976ebbed71efca87d302d0c7c4c2e59ba6a`.
Protocol bundle SHA-256 is
`bb54bdf34fb6fd4e9528a61e29a0b8cf7089b6f081da6f6d7b74d1c0d3d80568`;
catalog SHA-256 is
`953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`.
Independent frozen-delivery verification remains attributed to the preparation
record; this step does not inspect or operate a running Hub.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-recovery-loop-offline-20261010`.

| Verification | Status | Actual evidence |
|---|---|---|
| Initial Docker Python suite | FAIL | 129 tests, 2 failures; exit 1, 6.232 seconds; `attempt01.failed-python.receipt.redacted.json` |
| Corrected Docker Python suite | PASS | 129 tests, no failures/skips; exit 0, 6.210 seconds; `python.receipt.redacted.json` |
| Tested Python source unchanged during final execution | PASS | Full source hashes in the final receipt |
| Nine existing driver/module files unchanged from preparation HEAD | PASS | `immutable-input-audit.redacted.json` |
| Immutable application/test APK bytes and build attribution | PASS | Same audit; no rebuild |
| Offline test-container absence | PASS | `offline-container-absence.receipt.redacted.json` |
| Current-image Android KEY/NONE response-loss | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE processing | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE uncertain and two owned Hub restarts | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE legacy | NOT_RUN | Online HOLD |
| Actual direct encrypted opposite-Owner reconciliation | NOT_RUN | Root callback and joint GO required |
| Current Android emulator execution and closure | NOT_RUN | Offline subprocess tests are not Android execution |
| Standalone fixed-APK Android readonly reconciliation | NOT_RUN | No applicable existing selector; attributed external callback required |
| Physical Android / public HTTPS / native Worker | NOT_RUN | Outside this offline preparation |

Both test attempts used the following actual command, with no Core, APK,
credential or Docker socket mounted into the test container:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-recovery-loop=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

The initial failures checked ownership journals after their test temporary
directories had been deleted. Moving those checks inside the directory lifetime
fixed the tests; process exit, group closure and leader-reap assertions were
already passing. The failed attempt and its exact source hashes remain preserved.
Final tests exercise synthetic files, local Unix socket pairs and harmless
Python children. They verify deadline/rejection/closure behavior and the existing
recovery consumers. They do not establish Hub or Android business acceptance.

| New source | SHA-256 |
|---|---|
| `v164-link-recovery-loop.py` | `27f48da40d455efc6b7797cd2071b45293e677f4956b44fbbf44528b2d8990d5` |
| `v164-recovery-loop-budget.py` | `b4563b0f0119018e36da8a3a1b13bbf7dc4feceaa9104746242f3683c4908328` |
| `test_v164_link_recovery_loop.py` | `06653ad9ee8678348fc960b88ef3311072726c012aec0ea86728cae5cd316a9b` |

Final test-receipt SHA-256:
`21170821b080ae0ea56143e1fcdefe50edf2084f1a2df2e403b9fd20b7aff1df`.
The final Client commit/tree, dirty state, source inventory and eleven driver
pins are bound in `commit-delivery.receipt.redacted.json` in the evidence root.
Testing used parent HEAD `43738f4dc4b209074f989fbd375a8ce05587bf4c`,
**dirty=true**, with the new host files. The APK build remains the separate
`9b56832` dirty/input snapshot above; neither commit is substituted for its
actual build source. No APK, key, pending ciphertext or private evidence is
added to Git. No push or merge is performed.

### Coordination prompt

> Map the fresh one-Hub/eight-case Core adapter into the private event interface
> above. Independently pin the twelve current host drivers separately from the
> unchanged APK pair. Deliver the full closed F6 READY and its nine pinned refs,
> both normalized public setups and fixed typed-control output paths,
> direct enrollment signing, current native reviews/proofs, owned opaque
> activation, capture verification and matched control installation. Root alone performs two actual
> uncertain restarts and supplies verified direct reconciliation from another
> participating Owner session, then exact Android closure receipts. Use the
> accepted absolute budgets and stop on the first failure. No old F38/dd81575
> result or synthetic receipt can become a new Android PASS.
