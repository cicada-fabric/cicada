# Current validation closeout — v0.0.x development — target v0.1.0 PARTIAL

This record is the single current-status index, not a cumulative PASS count. Keep
the individual historical records and failed attempts at their original source
and artifact attribution. It does not change `CICADA.md`, the Client contract,
or any product policy.

The current clean-source aggregate and separately scoped follow-up validation
are summarized in the [2026-10-11/12 test closeout](v00-test-closeout-20261011-validation.md#current-source-closeout).

<a id="current-20261010"></a>

## Current evidence — updated 2026-10-12 — v0.0.x development; target v0.1.0 PARTIAL

The v1.6.5 Link-policy status/restart A7 run passed all eight requested
selectors, with an independent 81/81 scoped review; see the [current A1–A7
record](v00-test-closeout-20261011-validation.md#v165-link-policy-status-a1-a7).
The optional Client non-null consent-status uncertainty combination remains
NOT_RUN, not a prerequisite for a deployment trial. The A7 documentation and
evidence are the current validation checkpoint; a deployment trial may proceed
within these stated scope limits while overall v0.1 acceptance remains PARTIAL.

The **client-hub-v1.6.5** source contract adds own-side policy signer preview,
preserving wire 1 / catalog 55 / schema 59 / software 0.0.2. QA ran on the
recorded dirty259 candidate with 14 frozen preview paths. [Signer validation](link-policy-signer-preview-validation.md) records
policy-qa-a1 normal 71 test PASS, catalog 4 PASS, compatibility 2 PASS and vet 0;
its two 180s broad-race timeouts remain FAIL. The separate policy-qa-a2 narrow
race passed 34 tests / two packages, zero failures/skips, exit 0 in 225.289919s.
That dirty-source QA preceded the separately built clean c688 delivery. The
[delivery manifest](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/DELIVERY-MANIFEST.NONAUTH.json)
records clean revision `c6887f46c8412e648b8e8e68da371acd80e0b87e`, source fingerprint
`cc4ae9207a790c30e9b702c378d9a699bfe95f56e80b5ccfe3b748a6aefaf1ef`, retained Hub
`sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2`,
test image `sha256:fa314f2b3f54d269bca963edae675fa0142d0d2bbf833c24170aafaba25c4477`
and bundle SHA256 `37759169d0f776ab318a2cced01ac0ce557fba446980a5b3d112598dc72f50a4`.
The [disposable interop](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/client-interop/result.json)
passed five source-scoped checks / exit 0 / cleanup CONFIRMED, building its own
Hub `sha256:ae9d4a0a7a34146202744ca851a465a2f3ab546cc762b56c0ac64d5df050d4b1`
and runner `sha256:04d3d423e3ff1660e9bc188d30ab27362ddc7ab67eaaa6e6a10ae206c8d34ce6`.
These differ from the retained delivery images despite matching clean source.

[Current full Go](../.cicada-data/v01-next-gates-20261010/full-go-c688-clean-20261010/ROOT-FULL-GO-RESULT.NONAUTH.json)
(SHA256 `13a598c7b02184073616cca9dd4799620e8b390deaf80aca91aae6b49470da3a`)
passed 3,016 tests (1,543 top / 1,473 sub), 23 SKIP and 30 packages / exit 0 in
895.740764s on clean c688 without overlay. The
[independent postcheck](../.cicada-data/v01-next-gates-20261010/full-go-c688-clean-20261010/INDEPENDENT-POSTCHECK.NONAUTH.json)
(SHA256 `d83522862bcb3ea31b6d48763efb4132577ea5a5558fbb81d6fe08a7ab799f27`)
confirmed source/six residents unchanged and owned cleanup. Skips are not passes;
fixture timings do not establish a new performance acceptance scope.

Joint7's [exact-owned closeout](../.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/ROOT-JOINT7-CLOSEOUT.NONAUTH.json)
(SHA-256 `80dd17c7af90b0b5fd35ded5f6f40331c39f6a1bbc53a4a5eb5d562e6787c6e2`)
retains the failed overall run: four KEY cases PASS; fresh NONE response-loss
UNKNOWN/PREPARING (`LINK_OWNER_KEY_NOT_CURRENT`), three other NONE cases NOT_RUN,
zero model calls. Client incorrectly reused KEY-grant lifecycle for NONE;
Core's signer belongs in its independent ACTIVE Owner key registry. v1.6.5
returns the authenticated own-side exact complete public identity/state/version
within preview, requiring independent pins; grant rechecks remain authoritative.
Client e3d26f8/JVM30/v1.6.4-CLOSED remains that historical candidate.
Client APK producer 1151 and host source 3cfb identify the tested runtime sources; no new APK build is implied.
Joint8 failed on stale catalog/contract pins; joint9 failed on the stale helper
six-field tuple. Joint10 separately reconciled all eight cases and performed two
owned Hub restarts, but its final 65th close control exceeded the old 64 bound:
overall FAIL remains. All three runs have independently confirmed cleanup.
Joint11 passed all eight Android recovery cases and the unique final close ACK,
with two exact owned Hub restarts and recorded cleanup CONFIRMED; model calls: 0.
Independent postcheck confirmed exact owned-resource absence, closed child
journals and unchanged source/resident snapshots; see the current closeout. KEY uses
independent encrypted Go reads; NONE combines encrypted head reads and signed
candidate DB_READONLY verification, without Android status-read or Native proof.
Joint8/9 exact failure and independent cleanup receipts remain in the current
delivery's `joint-preparation` directory. Joint10's Core result SHA256 is
`9437c055a195fb03093352e799282f9d6818d0fa88a39af2a6885451acc47598`;
Parent result SHA256 `a63c471158f0d0015f2d6d0f5c66ca65206603c1e1ff9a5a91b682c3724af716`.
Its final ACK did not occur; V7's offline correction does not rewrite this FAIL.
Joint11's [Parent result](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/parent-run-evidence-2d0049a266db2c99073cf500ddb3c6cf314402e36b7b2f2f3a25641c9fdae752/result.NONAUTH.json)
(SHA256 `672a23d7050068a97cd7601f6b9726e4e802014c6be5708a8ea4c0961ee7d2f8`)
records PASS_JOINT_ANDROID_EIGHT_CASE_ONLY / eight cases / 512.191614s. Its
[Core result](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/joint-run-joint11-20261010/result.json)
(SHA256 `b291e817a72388dbf26e6f92860a15d6e8b3982d189fa4c3385018ef36cef943`)
records eight separately reconciled cases, two restarts at case indices 2 and 6
PASS, source/six residents exact and cleanup CONFIRMED. The unique 65th close(case7) ACK was received before
Parent success; current frozen source still enforces the exact 65-control matrix.
The [outer receipt](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/ROOT-JOINT11-OUTER.NONAUTH.json)
(SHA256 `b7b867a2570189d3970cfd47ca72ea0649821d8659313ebc56a074df63926f7b`)
records exit 0 in 513.119804s. The
[independent cleanup receipt](../.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation/ROOT-JOINT11-CLEANUP-INDEPENDENT.NONAUTH.json)
(SHA256 `0a7dfc5b4546842a808720f6e02c97052c5570bc025f6f8e2591d6ea420a0740`)
passed PASS_SCOPED_POSTCHECK: exact Hub ID/name, recorded Android ID and scratch
were absent; 59 Parent journals were closed (58 exit 0, one exit 1 with purpose
unknown), and 188 Client journals were closed successfully. Core c688 and Client
3cfb were clean at the postcheck; source/resident snapshots matched. This checks
cleanup and preservation, without independently revalidating encrypted reads or
DB-only candidate business logic. This is Android Link recovery scope only,
with no Native Runtime/model/physical-device/public HTTPS acceptance transfer.
Historical e2a image and packet attribution remain unchanged.

A separate Android A3 run passed only the synthetic OwnerProof manifest-binding
vector on the immutable APK pair from producer `1151b06e`; it was not built from
the current Client checkout. Its independent postcheck passed 38/38 checks. The
later A11 Group-key scope did verify an Owner grant and encrypted Group status
across one owned Hub restart, but it is distinct from the v1.6.5 Link-policy
status-read suite below. See the [scoped OwnerProof record](v00-test-closeout-20261011-validation.md#synthetic-android-ownerproof-vector)
and [A1–A11 record](v00-test-closeout-20261011-validation.md#group-key-android-native-a1-a5).

The Group-key operator has eleven retained attempts. A9 completed Native
Join/whoami/publish and Android Owner grant plus initial `CURRENT` status, but
failed its post-restart guard; six HTTP 200 responses do not imply a quota
cause. A10's exact CLI resume returned HTTP 500 before MCP after two provider
POSTs (200/500), with cause UNKNOWN. A11 passed a narrower same-UID MCP
protocol scope and an Android Owner Group grant with `CURRENT` status before
and after one exact owned Hub restart. It did not execute a CLI Runtime/provider
or prove AI autonomy, Native account authentication or context. The
single-Hub approved-identity Go correction passed normal/race, full
command-package tests, vet and build; A11 is not a new Native Runtime run.

A11 ran on clean Core `0326b1c6e6f4105347c2f0c31a0a7c9394dcd924` and clean
Client `740882b86d798a3d514b24b2bc2fa2802718d79d`, with unchanged source
fingerprints and six resident digests. The Hub remained the c688 image; APKs
remain from immutable Client producer `1151b06e04b172de9c7b5989ffec1318e58bf862`.
The Node binary was the A3 compile-check artifact from dirty producer FF3196,
with a post-commit Go-source/module-file mapping, not a new 0326 Hub image or
complete embedded-input inventory. The [independent A11 check](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/ROOT-A11-INDEPENDENT-CHECK.A2.NONAUTH.json)
passed 31/31 scoped checks. The earlier review's `models == 0` predicate failed
against `NOT_INSTRUMENTED`; that reviewer failure is not an A11 product failure.

The separate G4/G5 [qa-a5 receipt](../.cicada-data/v01-next-gates-20261010/qa-a5/ROOT-RUN.NONAUTH.json)
(SHA-256 `e390f3fb2baa45daa851eba15b058150eadd5bfc907c47d6696c5b47f8fec3af`)
passed 40 tests / two packages in each normal and race phase, zero failures/skips,
243.629188s total, on the explicit test overlay. Real Native G4 A3's
[receipt](../.cicada-data/v01-next-gates-20261010/native-g4-preparation/ROOT-RUNTIME-A3.NONAUTH.json)
(SHA-256 `f03796a1c53ca2ae74690ecaf189a4049bf7a35d2401e01e08bc1d0d09d37dd6`)
passed queue/crash uncertainty and reinjection refusal in 20.146111s using
official CLI 0.162.1, an independent historical B copy and network-none. Model
calls/new turns were zero; provider count is not instrumented. This does not
prove model consumption, busy delivery or foreground protection. Earlier failed
attempts remain preserved. Generic V67 same-node delivery is UNSUPPORTED;
physical stop verification, real-device execution and public HTTPS remain NOT_RUN.

The later G5 bilateral-Link HTTP case passed normal and race in the bounded
a006 run, with eight permission cases per phase and zero skips/failures. Each
phase recorded 14 test RUN/PASS identities plus one package PASS. It is
test-only HTTP/SQLite evidence on the recorded `ad247` source closure, not a
Native/model acceptance result. The test SHA, 723-row source closure, exact
postcheck and limits are recorded in
[the G5 validation note](g5-permission-matrix-current-source-validation.md#current-bilateral-link-revocation-case)
and the [a006 postcheck](../.cicada-data/v01-next-gates-20261011/g5-http-ad247-a006/POSTCHECK.NONAUTH.json)
(SHA-256 `e3abbdba79e4b492945753d4ae2dc1011e13e0ec6b2d74e4c47ce47f3105bb91`).

The schema-59 already-applied reopen optimization retains per-migration schema
checks and runs full `integrity_check` / `foreign_key_check` once before commit;
fresh and partial migrations retain their original full verification. The
selected server/Store race family passed 21 top-level tests / 71 test events
across two packages, zero failures/skips. The original broad timeouts and the
separate first compile abort remain failures/UNKNOWN for their own attempts.
See [startup validation](sqlite-startup-verification-validation.md).

Official CLI 0.162.1 passed the bounded synthetic foreground busy-queue and
human-draft checks (4.883s, paid calls 0); the current run used a pinned CLI and
Runtime and a synthetic provider. This does not establish production Node
delivery, model consumption, workspace command execution or V67 direct
submission. See [foreground validation](native-foreground-queue-validation.md).

The separate default-daemon selector is not registered in the one-click runner.
C14 remains the latest passing scoped Native result: its bounded six-turn G2/G3 scenario
passed on the original A/B contexts, with the multi-Group ASK/Reply path,
revocation denial and encrypted status snapshot after same-store Hub
replacement. Independent owned cleanup passed 79/79 checks. See the [C14
record](native-default-daemon-validation.md#c14-scoped-g2g3-acceptance). C9–C12
remain actual paid FAILs in the attempt history; C14 does not rewrite C12's
cause-unknown B-side HTTP 500, its NOT_REACHED steps, or any prior run's cleanup
fields. The loaded-queue A5 result remains `QUEUE_ACCEPTED` with Node inbox
`CONSUMPTION_UNCONFIRMED` for that test; the separate Group-key operator A1–A11
attempts are linked above.

### Historical full Go test overlay

The earlier batch used clean Core
source `308d7607cadc6cb83fe5aaa923adaf643a0aa32d` with the exact test-only
overlay now applied at
`cicada-go/internal/server/machine_agent_approval_integration_test.go`
(SHA-256 `edba25235b934adcaac660ab208ce66860d9493b0209e8a110edb05190115ce6`),
exactly matching reviewed patch SHA-256 `c08da9aadad46b235401458015c8822f8a64ea5499f97b9363b7f10b0093adf5`. It passed as `PASS_TEST_OVERLAY_SCOPE_ONLY`: build, gofmt, test and vet all
exited 0; 30 packages passed, with 2,981 test PASS and 23 SKIP events in
763.267 seconds. The run made zero model calls and its owned container is
absent. This is full Go evidence for the modified test overlay, not a clean
aggregate or product acceptance claim. See the
[result](../.cicada-data/node-runtime-validation-20261010/full-go-overlay-r2-308d/ROOT-RESULT.NONAUTH.json)
(SHA-256 `6f5d06c3057d9b2f3e0ee326e3f99cd8b0de5c6384d2492b79bdb199ae05657f`)
and test-event log SHA-256
`924c2e09271024ab0d1090c04bc69233991c237e2e8cf5ffa90d1be274a62534`.

The bounded Native run `cicada-two-turn-g2https0162shipping0002e` records G2
PASS and authenticated encrypted G3 status-snapshot PASS. Its recorded source
commit is `308d7607cadc6cb83fe5aaa923adaf643a0aa32d`; product binary
`6432b056467f13958623ec8b84608b315dd5f54132a03ac9654756532a779fa2`, helper
`6fb8777d7a68d2e38fd454e405123af08931ed2ee256ebdcb7629290e0c65b58`, CLI
0.162.1 Runtime image
`sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e`,
and Hub image
`sha256:839d80b242116396ef166880d9e3ccd24b3c878c9168601c4b8e0ce96bb766d2`
are bound in the [actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002b/request-observer-native-result-cicada-two-turn-g2https0162shipping0002e/result.json)
(SHA-256 `25015a82647ad700c707e747494bd909896c9b0c458762b07d6ac9f8173206d0`).
That result remains **FAIL / exit 1**: its original cleanup guard returned
`OWNED_OBJECT_INSPECTION_UNKNOWN` after `cleanup_inspect` rejected an exact
`NO_SUCH_CONTAINER` response with an empty JSON array following successful
removal; two daemon directories were consequently left marked not clean. The
[bounded diagnosis](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002e/native-g2-support-cicada-two-turn-g2https0162shipping0002e/FOCUSED-E-CLEANUP-DIAGNOSIS.NONAUTH.json)
(SHA-256 `84f0cd7ff7d6fafd99d1ccc7574c49e8e4c473e3c73bd926be1f281f604d5eb1`)
pins the failed check to `migration.install.cleanup_inspect`. A later
independent [exact-owned closeout](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002e/native-g2-support-cicada-two-turn-g2https0162shipping0002e/INDEPENDENT-E-EXACT-OWNED-CLOSEOUT.NONAUTH.json)
(SHA-256 `756018923463f7555a2e9424b7d281ac97d18d25b215f9a06d795a9a3965a948`)
confirmed all 21 exact selectors, runtime host PIDs, listeners and daemon
directories absent; its [postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002e/native-g2-support-cicada-two-turn-g2https0162shipping0002e/INDEPENDENT-E-POSTCHECK.NONAUTH.json)
records all six full resident snapshots unchanged. The separate
[source-pin postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002e/native-g2-support-cicada-two-turn-g2https0162shipping0002e/INDEPENDENT-E-SOURCE-PINS.NONAUTH.json)
(SHA-256 `6cd0d56d050c801926df645c8f7965a0ec72bfd9663b2051a8782f8f6aad9068`)
confirms the source pins. This later cleanup does not rewrite the original FAIL.
The narrow Native G3 cleanup gate/checker correction has three offline selectors
passing (0 skips, 0.766s),
recorded at the [G3 cleanup checkpoint](../.cicada-data/node-runtime-validation-20261010/fresh-native-preparation/G3-CLEANUP-CHECKPOINT.NONAUTH.json)
(SHA-256 `9caa25323dc91adc96723b665269f0b097d9d5170b9ad22a5a431e52a17c35b3`);
the tested gate SHA-256 is `fa03120b1ba42116b093912642928c704cb94e18c797da184c4e0603679352e3`
and checker SHA-256 is
`89a3179c157782606874562bcbc15fdd51bc747cca80c6abe96762783dcd48a9`. It has
not been rerun against the Native runtime.

The shipping `a4` fixture completed an ordinary Worker run with
`PASS_SHIPPING_ORDINARY_WORKER_SCOPE_ONLY`, phase `STOP_VERIFIED`, and exit 0.
Its source field is `shipping308d760 + explicitly pinned fixture delta`;
the selected driver SHA-256 is
`92876558a0cdc10bc8b73380906f5512c9dcb00a5dd902ff9af8dc9cbef1239c` and
Node binary SHA-256 is
`6432b056467f13958623ec8b84608b315dd5f54132a03ac9654756532a779fa2`. The
[result](../.cicada-data/node-runtime-validation-20261010/worker-shipping-preparation/shipping-runtime-output-a4/result.NONAUTH.json)
(SHA-256 `d2f62a5fc315775de58e4756767d89802e39104fc53950506d8d119f4e3d3f50`)
and [Root postcheck](../.cicada-data/node-runtime-validation-20261010/worker-shipping-preparation/shipping-runtime-output-a4/ROOT-POSTCHECK.NONAUTH.json)
(SHA-256 `db0ba928e8427c7f7d9e63e69ab80b5678bdaa68b84359e50d14a9baa3782185`)
record exact owned container/name/label, host PID, proxy group/socket and
scratch absence, stream EOF and unchanged source. The postcheck did not report
an exact full resident projection, and the physical-resource verifier was
`NOT_AVAILABLE_NOT_TESTED`; this is not physical stop acceptance.

The historical joint3 attempt remains **FAIL before selector execution**. The
[Client redacted result](</gpu1-share/data/cicada-client/v164-joint3-root-693e939-308d-20261010/result.redacted.json>)
(SHA-256 `1ae5b9a211437d5b43d6b9745f52b30c4ee67a3b69fe02ec2ab90c4fd8a1fc4a`)
records `ValueError`, case 0 `PREPARING/UNKNOWN`, and the other seven cases
`NOT_RUN`; model calls were zero. The Core child result is
`FAIL/CONTROL_EOF` after the Client exit, not the first failure. Root's
[joint3 closeout](../.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/ROOT-JOINT3-CLOSEOUT.NONAUTH.json)
(SHA-256 `4ad9c20dcfab18e3d7ca1e34275e00ad45a741c49fadce56a1149dbc0592ee17`)
classifies the first failure as `ValueError` with case 0 still
`UNKNOWN_PREPARING`; Android selectors did not run, cleanup was confirmed,
and source plus six resident projections matched. At the clean Client
diagnostic checkpoint, source was `950e4f5ef52c981479cefa94c44adddc6726d040`;
its seven-check offline diagnostic
(`/gpu1-share/data/cicada-client/joint3-valueerror-diagnostic-20261010/CLIENT-DIAGNOSTIC-CHECKPOINT.NONAUTH.json`,
SHA-256 `aa489acd12e64b47df400228d1001d14e2f003e2ff31ad66ca49e25d603db8da`)
passed. That offline correction is not Android evidence; subsequent joint7
results are recorded above.

The earlier clean-e2a default aggregate remains **INCOMPLETE** and keeps its
original scope. Current G4/G5 scopes are recorded above, not full-domain
acceptance. Generic V67 same-node remains **UNSUPPORTED**; physical StopVerifier,
real-device execution and public HTTPS remain **NOT_RUN**. Overall acceptance remains
**PARTIAL**.

## Historical snapshot — 2026-10-10 before final Native/Worker runs

The following earlier snapshot is preserved with its original evidence and
source attribution; its planned next steps do not describe the current run
state.

At this earlier snapshot, development software was **0.0.1-dev** on `dev`.
Development remained 0.0.x until the user's actual acceptance; a main merge or
initial 0.1.0 release
requires separate authorization. Historical binaries, images and tested source
labels below retain their actual `0.1.0-dev` identity. Protocol
`client-hub-v1.6.4`, wire 1 and schema 59 are independent and unchanged.

The clean `e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59` default
[aggregate](../.cicada-data/architecture-v2-completion/20261010T114600Z-a46501c07c/result.json)
(SHA-256 `69c8d08c876b453b7701208f1273b2c7e2057131d955c7135fdd129cfef5bcb4`)
is **INCOMPLETE**: fourteen lanes PASS, two PASS_WITH_SKIPS and four Native
lanes NOT_RUN. Go build/test/vet passed 30 packages and 2,950 test pass events,
with 23 explicit skips; Python passed 212 tests with zero skips. Release
packaging retains five skips. These are the tested clean source's results;
the subsequent Link lane registration and Native harness changes do not inherit
this full aggregate. The earlier UNKNOWN aggregate remains historical.

Real G1 `cicada-two-turn-g1cli0162queuehist20261010g1` is **PASS**:
[actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/request-observer-native-result-cicada-two-turn-g1cli0162queuehist20261010g1/result.json),
SHA-256 `17a4a276ef28b26c70df1988f20143808c3e7fa36b33a117882ea258d43e4d7e`.
Five actual turns completed (three manual, two automatic; A3/B2), preserving
both original Native Threads, Endpoints, context and exact correlated replies.
The terminal witness proves historical QUEUE_ACCEPTED against exact immutable
operations and Hub attempts/receipts; it explicitly does **not** prove current
writer authorization. Production fencing and the original strict verifier are
unchanged. Eleven safe response observations were HEADER_ACCEPTED / HTTP 200.
Production Control business objects were absent with dependency proof and
authenticated management HTTP 503; G3 restoration remains untested.
The [independent G1 postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/native-g1-root-fdy0raew/INDEPENDENT-G1-ACCEPTANCE-POSTCHECK.NONAUTH.json)
(SHA-256 `92f385ea1b9b5c52486e407771225a591c303cb073fda465bd579e6b49fc77d8`)
verifies two EOFs, owned-resource absence, unchanged six residents and all
source/artifact pins. Root then removed only the three verified empty owned
roots ([cleanup](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/native-g1-root-fdy0raew/ROOT-EMPTY-OWNED-TEMP-CLEANUP.NONAUTH.json),
SHA-256 `f253eab7814df722d384c78aa4d369c19288550fdf1b73b7049ade43f4c541c1`).
This G1 used CLI 0.162.1 / Runtime e969 and clean631 product/helper artifacts,
independent of the tested clean e2a repository. It does not transfer acceptance
to the later Runtime or G2/G3.

The preceding f1 run remains **FAIL**, three model attempts and two completed
initial joins. Its [safe diagnosis](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/native-g1-root-4ww70rdr/FATAL-STREAM-SAFE-DIAGNOSIS.NONAUTH.json)
(SHA-256 `abc90c9e3a2c3dc57a7387276a9821fda2cf9d38146ce52591017a24aab0e6ac`)
links the fatal event to Runtime's reported stream server overload; HTTP status,
quota and SDK fault are not established. E3's terminal epoch-oracle FAIL and the
older READ_HEAD/timeout attempts below retain their original source attribution.

The h4 zero-model `command/exec` [result](../.cicada-data/native-observer-wiring-20261007/runtime-workspacewrite-zero-01621-20261010h4/RESULT.NONAUTH.json)
(SHA-256 `de22397a4656763fc780d356ff5a74025913202d51cd6652012b6ef0509e9249`)
is **FAIL**: the matching official package resolved the earlier bwrap digest
mismatch, then bwrap reported namespace creation refusal under standard Docker
security. Workspace allow/outside deny were not reached; this is not a quota
failure. The h5 [build](../.cicada-data/native-observer-wiring-20261007/runtime-cli01621-fullpackage-directbase-20261010h5/BUILD-RESULT.NONAUTH.json)
(SHA-256 `bf52eca924c67bcaf2f6e84bee5a0571bc222211e5e53e96bbd8a47dfc3ad304`)
passed **packaging only**, with full official 0.162.1 resources, code-mode host,
rg and license provenance. Runtime
`sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e`
is bound by [G2 binding](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g2g3v2h520261010a/binding.NONAUTH.json)
SHA-256 `267baadedb59f9aadb9bea4e8aa865987b719a09032ef7a2dcb7e5f7ab05503c`.
Its [offline preflight](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g2g3v2h520261010a/request-observer-wiring-g2g3mcp-preflight.NONAUTH.json)
is PASS with zero Runtime/model calls; it precedes the G2 H4 failure below. Neither packaging
nor this preflight proves a command sandbox or Worker acceptance.
The current checkpoint's scoped offline command reports record 56 runner/Link
helper checks, seven G2 checks and 18 binding checks PASS. These counts come
from the agents' observed command outputs and Root review, not a reconstructed
raw log or a new full aggregate.

Current G2 H4 `cicada-two-turn-g2https0162h10sigbind20261010` is **FAIL**:
[actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g2g3v2h520261010a/request-observer-native-result-cicada-two-turn-g2https0162h10sigbind20261010/result.json),
SHA-256 `fd2017defa814a15df69ebd2c69ae943fd265bbd1afc6d679df252ecd164bf10`.
It failed during queue-admission installation with QueueAdmissionFailure at
`isolated_nodes`, before Native/model activity; the exact underlying code remains UNKNOWN:
models, attempts, turn starts/events and paid submissions are all zero. Runtime
was invoked; provider request count is uninstrumented/UNKNOWN. Both Observer
EOFs were confirmed. The original result retains cleanup INCOMPLETE
(`cleanup_owned_resources=false`), distinct from Root's later
[owned closeout](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g2g3v2h520261010a/native-g2-support-cicada-two-turn-g2https0162h10sigbind20261010/ROOT-G2-H4-CLOSEOUT.NONAUTH.json)
and [dead-UDS safety closeout](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g2g3v2h520261010a/native-g2-support-cicada-two-turn-g2https0162h10sigbind20261010/ROOT-H4-DEAD-UDS-SAFETY-CLOSEOUT.NONAUTH.json)
(SHA-256 `70c7b9ce66afb5c0afc52e24bb3f191f41a5aaa1c854c99770306a003f22a112`).
Exact owned containers/networks/processes were absent; only independently
verified dead UDS/locks/aliases and empty daemon directories were removed.
The original FAIL bytes and cleanup outcome are unchanged; G3 remains NOT_RUN.

The isolated i1 CLI 0.162.1 **Native sandbox zero passed** workspace write/read
and denial of an outside path first proven writable by the same UID:
[independent review](../.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-sandbox-cli01621-candidate-20261010i1/ROOT-INDEPENDENT-ZERO-POSTCHECK.NONAUTH.json),
SHA-256 `22c34d04130128616fa38d29f888d19461d05abf29f3ef4a0526480508f8fa6e`.
No credentials, Thread, Turn or model were used. The j2
[keyless transport review](../.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-worker-cli01621-candidate-20261010j2/ROOT-TRANSPORT-ZERO-EVIDENCE-REVIEW.NONAUTH.json)
passed **transport only**, without Native provider or Worker business acceptance.
Guest 2 GiB and outer memory/swap 3 GiB are fixture bounds, not product defaults
or Hub capacity measurements. Neither result reclassifies h4's Docker failure.

W2 real CLI 0.162.1 **Worker approval → encrypted goal.result passed its scope**:
[independent actual review](../.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-worker-cli01621-candidate-20261010j2/ROOT-W2-INDEPENDENT-PAID-REVIEW.NONAUTH.json),
SHA-256 `0996ddaae89e2d3c6f6eacd5d8b6d1ea2234f087de93c52a3f63487d786e946d`;
[Root final review](../.cicada-data/native-observer-wiring-20261007/worker-kvm-authenticated-go-20261008a/native-worker-cli01621-candidate-20261010j2/ROOT-W2-FINAL-EVIDENCE-REVIEW.NONAUTH.json),
SHA-256 `9314186eadb8576d2994d8a0f6312a3950005d839595c1f293602b7d51ffd589`.
Actual exit 0/98.538s preserved the authenticated original Thread/Turn through
START/BIND/STOP, exact command/cwd/Goal/Worker attempt 1, literal accept,
command completion, encrypted result and durable completed Worker. Natural
QEMU/shim/CLI STOP, owned cleanup, six residents and source pins passed.
The actual paid archive had 104 entries, no zero flag or secret files, and all
45 official package resources/modes/symlinks. The trusted outer fixture alone
held the read-only credential mount; the guest, Hub and Client did not.
Two validated POST send admissions and two TCP admissions stayed within cap 4;
these are not billing or exact provider request counts. W1's pre-START FAIL and
the separate workspace A/B plus START-only correction remain historical.

W2 used a **private IPC fixture overlay**, with explicit `approvalsReviewer:user`,
rather than the unchanged shipping Node binary. Its diagnostic-only stale c199
Node pin remains **UNKNOWN**; the production identity check and authenticated
gate independently verified the current native tuple. The shipping fix now
explicitly selects `user` on thread start/resume and each turn start to pin the
Manager's human approval route against inherited reviewer configuration.
Official CLI 0.162.1 defaults to `user`; omission does not prove auto-review.
No VM/IPC overlay is incorporated into production, and W2 is not retroactively
attributed to the new shipping source.

Shipping [selected offline QA](../.cicada-data/shipping-reviewer-version-20261010/SELECTED-QA.NONAUTH.json)
(SHA-256 `dc62b6ad84260709cff76c238bef3107c11bd838617dd0d819a486e7ee3eea15`)
records the actual wire-capture RED in all three new/resumed modes, then GREEN
and related identity/cancel/remote-approval/stale-attempt/version regressions:
nine top-level and seven subtest PASS events, zero failures/skips. The source is
the selected dirty patch over clean36eb, not a full clean aggregate. No model or
Runtime was launched. VERSION, plugin metadata and automatic build defaults now
agree on 0.0.1-dev; historical artifact labels are retained.

Root's actual 0.0.1-dev disposable **standard TCP Client interop gate passed**:
[result](../.cicada-data/shipping-reviewer-version-20261010/client-interop-a1/result.json)
SHA-256 `ed443532abdf38a79885edd42a86d708d89316775d878d47e60e7a2f3362a259`.
Client Smoke and RecoveryFixture covered ten protocol scopes: exact registration/packet retries,
encrypted snapshots, COMPLETED/STILL_PROCESSING/UNCERTAIN and legacy recovery,
Node-code heartbeat, and Owner topology isolation. This was dirty36eb source
fingerprint `01801c0d996a8f92514b7e9790e34829d8ce87d95f7c2809fa1ca35b1ff6e67a`,
with its own Hub `61233710…4015` and test `86af34f7…f0a6` images, rather than
clean36eb acceptance. The [Root postcheck](../.cicada-data/shipping-reviewer-version-20261010/client-interop-a1/ROOT-POSTCHECK.NONAUTH.json)
(SHA-256 `c3f073fdf1428727dddf09e39912bf097d10fd2c8e3ce8d03add6c293588b528`)
verified complete build-source equality and six unchanged resident canonical
digests; the [live owned-resource check](../.cicada-data/shipping-reviewer-version-20261010/client-interop-a1/ROOT-OWNED-ABSENCE.NONAUTH.json)
(SHA-256 `a2330f61195ea6961a5ddc1a03bf20dc39249d8421d8b398b99e05889b2703a1`)
confirmed all eight exact container/image selectors and scratch absent.
Android, Native Runtime and public HTTPS were NOT_RUN by this gate; standard
TCP does not establish PQ transport acceptance.

The clean36eb focused
[Link Docker result](../.cicada-data/architecture-v2-completion/client-link-recovery-clean36eb-20261010T130826/result.json)
(SHA-256 `7fdb167eb7b91929fc532f309d2c80cd27491ad1b35bb58a14bb4d37d45c8313`)
passed nine named events (one top-level/eight subtests), two operation-specific
restarts and exact source/resident/cleanup checks. It is separate from the older
e2a aggregate and does not qualify the newly edited shipping source.

The clean e2a [Client delivery](../.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/DELIVERY-MANIFEST.NONAUTH.json)
(SHA-256 `517eaa56464adf44eb27600a8197ff291d49e961718096ce7c17399e47fb5ef4`)
exports Hub image `sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01`.
Independent Client commit `43738f4dc4b209074f989fbd375a8ce05587bf4c`
passed [preparation review](../.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/ROOT-CLIENT-PREPARATION-REVIEW.NONAUTH.json)
(SHA-256 `a58abf25c3246bbacfed208dcacb65b75312f77787ecb1bfa7d9ad6d0c85c6ab`);
all eight Android online cases are **NOT_RUN**. The APK pair was built from dirty
`9b56832c9701b0ba469d8703fdf61611e0208f98`, with 598 input records, and is
attributed separately from the later clean Client commit. See
[Client preparation](../../CICADA_CLIENT/docs/client-link-recovery-e2a1908-preparation.md).

Next: resolve the pre-model G2 admission failure, then separately validate original
Thread denial and G3 authenticated encrypted restoration; retain the shipping
Node/fixture distinction and complete current Android, physical-device and
public-HTTPS gates. No new model GO is implied. First-release acceptance remains
**PARTIAL**; development software 0.0.1-dev is unreleased.

<a id="latest-native-e3"></a>

## Historical E3 Native diagnostic — 2026-10-10

At this checkpoint, bounded Native diagnostic E3 remained **FAIL/QueueOracleError** at
`managed_hub_blind_terminal_oracle`, with `WRITER_EPOCH_STALE`. Five actual turns
completed the original A/B context and exact correlated reply predicates;
all eleven response observations were HTTP 200 / HEADER_ACCEPTED. Those scoped
witnesses do not turn the terminal FAIL into Native acceptance. Production
Control was absent (`NO_CONTROL_BUSINESS_OBJECT`, `dependency_proven=true`),
with authenticated management HTTP 503; restore/status-query acceptance is open.

[Actual E3 result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-rspmeta20261010e2/request-observer-native-result-cicada-two-turn-g1cli0162rspmeta20261010e3/result.json) SHA-256:
`b7e80cace4eccad0d58d0905e0399b557dfcb25c1d997d595aaaa3ba7ea5a262`.
[Independent cleanup/pins postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/INDEPENDENT-POSTCHECK.NONAUTH.json) SHA-256:
`5a6c03671dff8fcd4a8342875bac5f582ec16b1796b26d672b960db48b01adbf`
passed both EOFs, fifteen owned selectors, full source pins and six unchanged
residents. Its status is cleanup/pins PASS only, with actual Native FAIL retained.

[Source and receipt chronology](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/WRITER-EPOCH-ROOTCAUSE-AND-MINIMAL-PROPOSAL.NONAUTH.json) proves the test-only mismatch:
QUEUE_ACCEPTED was committed under writer epoch 1; publishing the exact remote
receipt reacquired the real native writer at epoch 2. NativeOperationOutcome
preserves the accepted historical operation. The terminal Python oracle wrongly
required the historical commit epoch to equal the latest acquisition epoch.
The test-only historical queue predicate is now implemented. Five selected
[offline checks](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/HISTORICAL-QUEUE-SELECTED-QA.NONAUTH.json)
passed (0 skips/failures, 0.716s), receipt SHA-256
`f14813e9ba9b4a6300e6df2d3a455c23cd0315408ae9eb7fa993542501084f8a`.
The retained E3 strict verifier still rejects WRITER_EPOCH_STALE; historical
receipt acceptance does not grant current writer authority or prove consumption.
Production fencing is unchanged. G2's selector is not activated; any reuse of
this predicate for G2 needs source-backed scope and offline checks first.

Fresh queuehist10f1 zero preparation now actually passed
PREPARATION_PASS_NATIVE_NOT_RUN, with zero model calls, turn/event starts and
paid submissions, using binding
`173ee23fe6205be758d7730c6ddcf3264a2d6e4c8c47dea93c5c8086da884827`.
[Actual zero](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/native-preparation-cicada-two-turn-zerocli0162-queuehist10f1/result.json)
SHA `baac7a365a37c2c6f52d1fd4e08b750b7dbbd03c2f114a4b253f0c080d732462`;
independent cleanup/residents SHA
`27b1f8468eb63445e7bbbcfe458841eb7e67fc0ddc5e0d89bcb8f7e02ad167b5`,
full pins/counters SHA
`9432055265f89d5ada67fbe195dbb7da88da4611704ae733bf729bd9c105673a`.
Two EOFs, fourteen owned selectors, full source/compiler/wiring pins and six
resident snapshots passed independent postcheck. This is preparation only,
not new paid Native acceptance. Root's separate five selected checks passed
in 0.282s with the absolute binding path/SHA; the initial relative-path
CURRENT_BINDING_PARENT failure before tests is retained separately.
The dynamic clean G1 launch helper is prepared **NOT_GO**; the fresh
current-source real G1 gate is **NOT_RUN**. Zero preparation creates no model GO.

E3 artifacts retain clean product origin
`631666c8f86349e1b1e81c318f324c7897588683`, product SHA
`3baf7bfbd217ac3d24be0fb3f41dfe5797ffc17a38f1f6c2b79dbe3b1209efae`,
Hub image `sha256:c87cf47a3ed1b48832a3ec638d98f2f3359d1e6cd2dd06b51cf80de3989e066b`
and Runtime image
`sha256:e9690980b153132186780c66126a78b98ed87c3d5e99abf3303b6277e48f697e`.
These differ from later repository source and both the clean-b06 and dirty-b06 Link images.

Fresh source-bound zero preparation passed; next validate G1; G2 denial and G3
authenticated encrypted restore remain separate gates. Current Android, remaining native Runtime scopes, physical-device
and public-HTTPS acceptance require independent evidence. No new paid PASS is
claimed. Overall v0.1 remains **PARTIAL**.

The reusable `--suite client-link-recovery` gate now actually passed one
top-level test and eight subtests, with two real owned Hub restarts, zero
failures/skips and confirmed cleanup. The tested build is **dirty b06**, with
its full source fingerprint and actual image IDs recorded in
[Link validation](v01-link-recovery-fixture.md#reusable-link-gate-pass).
Its 26 offline helper tests and independent G4 review passed. The earlier
clean-b06 Root operator PASS and both reusable preflight FAILs (OWNED_MOUNT,
RUNNER_CHANGED; zero Go tests) retain their separate source/evidence attribution.
The clean-b06 actual result SHA-256 is
`e66b2866ad99e6eb5f6a8c0eff263f31c61bc68b3f814401a8f3e55813a83ff3`;
its independent PASS_LINK_SCOPE_ONLY postcheck is
`45387856a6b4ff6b7c73a8427991642c4f9741475a7d6107f4ed033db86b39dc`.
Exact Hub/test image IDs in that runbook belong to the clean-b06 operator run.
The first reusable-suite FAIL result SHA-256 is
`a9f5e58561942b5f270e0f0a99a675e969218d07f8643dd3cd3b036d03e0b4bd`;
zero Go tests ran. Its secondary absent-raw sanitizer error is a harness fault;
confirmed cleanup does not upgrade that protocol preflight FAIL.
The second reusable result SHA is
`7db306d966fb11640985f087f3db6a41ca5a03ffd40a13c6958b061b8c77f907`:
FAIL/RUNNER_CHANGED, zero parsed Go lifecycle/restart events. Both real kernel
/tmp projections passed; complete build source and six resident digest rows
matched before/after, cleanup CONFIRMED. A real Docker probe isolated its single
Created→Running false/null OomKillDisable default. The subsequent owned-only
comparison correction passes 26 helper tests; resident full-state comparison
and production policy remain unchanged. The corrected T1120 reusable gate
then passed; both original FAIL receipts remain unchanged.

The [actual T1120 result](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/result.json)
is PASS/exit 0, SHA-256
`24f37f0c20fe7f88488233175f852edd56aa633dcb102855252d44dbd84ff975`: one
top-level plus eight subtests, zero failures/skips, Go package **15.409s**,
outer **113.7468s**, and two exact owned Hub restarts PASS.
[Build provenance](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/build.json)
SHA `56986def70b0b985514286c8dd6a6d76fab47a71c9732b2a252d7c50142016a7`
records revision `b06a558f04cf92113df37d089ce1de7e81ba3c99`, **dirty=true**,
fingerprint `7a8b99036b32e7d4727ab7011a53fa477854505cabfbdeccb8bc54baed7580d5`.
The [independent Root postcheck](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/ROOT-POSTCHECK.NONAUTH.json)
SHA `0d334df6ea77ddb0764a6413b1ea515ec6b9524409581f2cca8a1f92551cbd5f`
confirms exact source before/after, six unchanged residents, absent scratch and
four absent owned resources. Whole-repository source clean is **false**.
Exact new Hub/test image IDs and helper/cleanup hashes are in
[the Link receipt table](v01-link-recovery-fixture.md#reusable-link-gate-pass).
This Link PASS contains no model, Native Runtime or Android acceptance.

<a id="latest-native-timeoutabi"></a>

## Historical Native timeout ABI checkpoint — 2026-10-10

At this earlier checkpoint, the single real G1 was **FAIL**, exit 1 after 180 seconds, at
`original_managed_join_and_context` with RuntimeError and public origin
`<effective-request-observer-audit>::audit:60`. It has one submission, one actual
started turn and one started event. [Actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/request-observer-native-result-cicada-two-turn-g1cli0162timeout20261010d2/result.json)
SHA-256 `80233230d37336feba2b8756181e565ddcf7e1001a7862aafe4cb657afbe9647`.

The earlier G1 timeout ABI fault is proven by an actual Peer/migration replay:
manual_turn omitted timeout, Peer forwarded None and paid limit evaluated
min(None,left) before RPC.check. The tracked G1 adapter now preserves inherited
wait/automatic default 180 when timeout is None, without changing numeric
values, remaining deadline clips or G2. The new actual execution has no such
TypeError. This establishes that repair, not completed Native context acceptance.
Its compiled artifacts still originate at clean631; Python harness changes and
repository HEAD `c9b2935da17167ce7694abaeffca22aaa0daa3f2` are separate identities.

Fresh zero preparation exited 0 in 34 seconds with
PREPARATION_PASS_NATIVE_NOT_RUN, result SHA
`42cf3fa128c0743bb21b0e9af8318243c8a9bb979f90e76b221a469a9277b3ce`.
It belongs to binding
`a9729fa7042557e302fac1c0af9337182a7bf8597e1b831b63bb664b9c84a6bd`;
older zero receipts do not satisfy this binding. Six selected wiring tests and
18 binding tests passed without skips. Root's subsequent [full wiring QA](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/ROOT-FULL-WIRING.NONAUTH.json)
records 49 tests: **47 PASS / 2 explicit SKIP / 0 FAIL**, 54.308 seconds,
zero model calls and Runtime launches; SHA
`244dab9745fd111de42d58e724a2bc5f28c87823756f06d9f274d3791ab6e605`.
Skipped retained A/B reply replays and older failed test drafts remain separate.

A's broker event statuses are FORWARDED then UNKNOWN_UNSUPPORTED; A admitted
two connections and B none. The second connection's CLOSED_FAILURE/READ_HEAD
with shutdown_requested=false is **upstream response** checking, not client
request-head checking. The exact response status/rejected rule is UNKNOWN:
PeerNativeBroker sets response_metadata=false in constructor and connect,
so existing RealGuard response_status_code/response_rejection enums were not
emitted. Fixed candidate rules include non-2xx/status, encoding, sensitive
header/token guard and subsequent Core response rules. Native HTTP status is
null. Actual configs and A turn/start retain approval_policy=never,
approvals_reviewer=user, gpt-5.6-luna/provider basil; no approval request method
was observed. No provider403, quota or automatic-review cause is established.
The two origin STREAM_IO pairs are not DRAINED or Native PASS.

The [independent postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/native-g1-root-idxrd5vg/INDEPENDENT-POSTCHECK.NONAUTH.json)
SHA `6fef835b1d226ce7fd843a5a91cbe92b5b157bc1efb99f4b7fb6917d1d656fe9`
is **PASS_CLEANUP_ONLY**: both actual EOFs, cleanup/error checks, fourteen owned
selectors and run labels/network/UDS absence, six unchanged residents and full
source/compiler pins. Root removed only the three empty operator roots;
[cleanup receipt](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/native-g1-root-idxrd5vg/ROOT-EMPTY-OWNED-TEMP-CLEANUP.NONAUTH.json)
SHA `9de0aa28298a05a645b9d3fc5aae60744c031beaa6a0d8bbeb4546ec727b8735`.
Retained private Native state and all original FAIL receipt bytes remain intact.

At that historical checkpoint, the next action was an offline design/review for connecting existing safe
response enums at the actual Peer seam. Preserve original parser/refusals,
Thread/context/PQ/ALPHA/BETA/reply oracles, 600/30/30/660 budgets, outer690/+15,
5/3/2 turns, TCP16 and retries0. This record authorizes no source change or new
paid run. Existing credentials need not be supplied again. G1 same-Group,
G2 live denial tail and G3 restored authenticated encrypted status remain open;
Android/current Client-image acceptance, physical devices and public HTTPS
remain independently attributed. See [detailed facts and frozen sources](v01-native-next-checkpoint.md).

## Source and artifact attribution

| Item | Verified identity |
|---|---|
| Prior full-suite Core source | clean commit `dabce1740f91a40c5451fca90522d17f27b09a54`; tree `9a253f4410bad64f8928ceaae032395356acf681`; tracked archive SHA-256 `bc83971e35c1a3beecd632b373df51b4ff4a5799ab4e1498f85ff46926fc62ca`; source fingerprint `89a0530582e098e75fb8ab0df67ec99350e2023e1a8f5f7fe44c405d8f10eef7` |
| Go toolchain | `go1.27.1 linux/amd64`, pinned image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195` |
| Prior Hub/product | contract `client-hub-v1.6.4`, catalog 55; Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9` |
| Separately built binaries | The PQ package Node binary SHA-256 is `d78b2af426d444648bb8a2f609d20783faa5e8783bc1cc96ec388a7237c56208`; the Hub image's extracted shipped `cicada` binary SHA-256 is `7b04eceefa40efba51a98db540f745a22bd4b06ef1db388cd6729d30dfdf2929`. They are distinct builds attributed to the same clean Core source; neither hash identifies the other artifact. The M5 helper is a separate dirty build. |

The default Go suite and prior package/Browser artifacts retain the `dabce174`
archive attribution. Current clean `631666c8f86349e1b1e81c318f324c7897588683`
contains the TCP connector and Browser QA changes plus the previously tested
M3/M4 test bytes. Its fresh build has fingerprint
`d9ca7c7d51f25c26ff60a3ae3d13e4d853e7a20a691926e14864427a06a0a5ad`;
build/equality and keyless preparation do not establish a new full-suite PASS.
Separate fixture helpers retain their own pins; the earlier M5 helper is not
attributed to either clean Core commit alone. The new Apache artifacts separately
record revision `631666c8f86349e1b1e81c318f324c7897588683` plus dirty pinned inputs:
standard source fingerprint `f71151e3298e63d1fa6dffe34f9506a18830cc5506429d129900e665130736cb`,
PQ `97e7e92cf4584f5cc4300b31f3f58726637cc757123db8529b607470b8c76ba9`.
They are not solely clean631 or the Native-built artifact above.

## Current bounded evidence

| Lane | Result | Limit and evidence |
|---|---|---|
| Apache-2.0 source inclusion | Exact official LICENSE is included by standard/PQ packaging and both Hub Dockerfiles; third-party notices remain separate. Initial deterministic checks passed 19 packaging / 6 inventory tests, with 2 optional artifact SKIPs. | [Original deterministic receipt](../.cicada-data/apache-license-packaging-20261010a/actual-repository-qa/RESULT.NONAUTH.json), SHA-256 `f35b5e039bb020f3fff65f9bb21733183f052a855d2afd5d9558b6f09803e666`. A subsequent exact standard-Hub input-enumeration correction passed 2 focused source-info checks; prior skips remain skips. |
| Actual standard/PQ artifact checks | Five standard target binaries and the Linux amd64 PQ package were built. The initial release operation remains FAIL: 20 tests passed and the synthetic Git-provenance fixture failed because the env-isolated container had no global Git identity. Check-only rerun with the existing server public Git config mounted RO passed 21/21, 0 skips/errors/failures, exit 0 in 19.127s; no rebuild. | [Original release result](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/RELEASE-RESULT.NONAUTH.json), SHA-256 `a96638df827356cdd881f8966a3a7ea74a073638fbb9c8e0060355e6d1ce3731`; [separate check-only result](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/ARTIFACT-CHECK-ONLY-RESULT.NONAUTH.json), SHA-256 `ac1288c68172db2f9f7a89c661c7ddaf19ddc83dd88dade84e6d746d9af35526`. Exact LICENSE/checksums/notices and real smoke checks passed; artifacts unchanged, exact owned container absent and six residents unchanged. No publication or formal release. |
| Actual Hub image LICENSE inspection | Standard and PQ image builds exited 0; create-only inspection confirmed exact root LICENSE, nonroot images and 11 Go third-party module notices each, with PQ OpenSSL notices retained. Images were not started. | [Image inspection](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/IMAGE-LICENSE-RESULT.NONAUTH.json), SHA-256 `10372a9516c8262acb32a62ac7a5419f58fcf2e5dac63a17a047d4182064ad8d`; [Hub operation](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/HUB-RESULT.NONAUTH.json), SHA-256 `f9216e5a6accbbb98b1115f3f944b01bc84fb3558ca45ef2cafc41474de623db`, 160.707s. Standard image `sha256:0787fe846aaf48bde340ebc9fdf1e9373fa294cee36c8356db66576a3d79bd7c` / 14,345,904 bytes; PQ `sha256:b4dafdcad80ab9f5b86f17b7e4b9a9d0914df4c6bd0848a444d570aa91a96866` / 14,644,505 bytes. Exact inspection containers absent; six residents unchanged. Not a Hub runtime or capacity test. |
| Current clean631 build / equality | `PASS_BUILD_PROOFS`: 457 product and 220 helper compiled-input rows; fresh product binary SHA-256 `3baf7bfbd217ac3d24be0fb3f41dfe5797ffc17a38f1f6c2b79dbe3b1209efae`, helper `6fb8777d7a68d2e38fd454e405123af08931ed2ee256ebdcb7629290e0c65b58`; PQ Hub image `sha256:c87cf47a3ed1b48832a3ec638d98f2f3359d1e6cd2dd06b51cf80de3989e066b` (about 14.6 MB). | [Build/equality report](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/BUILD-PROOFS-RETRY.NONAUTH.json), SHA-256 `60b0f0631cacc7eaaa5dd0c0cb9ff1e6af5420d161cbc6314b29aa53bf51d02b`; the original failed Hub build remains separate. Current Agent wiring manifest has 37 pinned inputs, SHA-256 `a87ab5379ee06c8ede85c1a62aec60049671346b8bc543db17c525c131918e91`. Image size is not capacity evidence. |
| Current clean631 keyless startup | `PASS_STARTUP_ONLY`, Root wall 31.269 seconds / inner startup 26.013 seconds: actual Hub, two Agents, CLI/MCP, mapper and queue-control denial checks; no native turns, credential callbacks or origin/provider dispatch. | [Main result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasecap20261009b/peer-startup-zero-phasecap20261009b001/result.json), SHA-256 `34c11c67bdef311b5328ddca1aae88505d2442174d8a3f6d303a2d8eb38bf6d1`; startup receipt `7c7376135916682c523af34e689cc65272f6ccd8366ba5eb771f41164e4fac07`; [Root postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b001/CURRENT-KEYLESS-STARTUP-POSTCHECK.NONAUTH.json), SHA-256 `2c3b3b53f14afd544a949e86570c15dae808be71f8f0aa06d35ede17d19e9b8b`. This is preparation, not queue consumption or Ask/Reply. |
| Historical G4 official CLI 0.162.1 queue-crash gate | `PASS_INJECTED_BEFORE_LEDGER_REAL_QUEUE_ONLY`: one official queue submission over an independent saved B fixture, test exit 0, zero new turns/provider egress. Saved B `01a12336-b99e-7350-821a-3e99742f58e6` had two turns / ten items; uncertainty and reinjection refusal remain the tested boundary. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/result.NONAUTH.json), SHA-256 `51cadc91c894e4feff454a3552035943677d2a5671632e8c6401029cc473b291`; [Root postcheck](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/ROOT-POSTCHECK.NONAUTH.json), SHA-256 `2e7fac77e020c32ebfc65cac18b0ae7aece6ec4d9243a80c1bc41c2d6090a275`, confirms four exact CID/name selectors absent, fixture deleted and six residents unchanged. Test source `b28cae8d017d9ec148223c603a85d5934e4800e50f4543414368d533d7cbbb17`. Prior [CLI 0.162 evidence](../.cicada-data/native-observer-wiring-20261007/g4-cli162-runtime-20261009a/result.NONAUTH.json), SHA-256 `4e3c6e11a7e70f595b8f2d8693e1b907861306a79d297d9a07a764829a4bb6d3`, remains separate. Not full G4 or model consumption. |
| G4 production component process windows | Actual helper/process tests cover outbox pre-send, Fabric HTTP post-commit/pre-ACK kill/restart, and Node claim/inbox+journal pre-receipt kill/reaccept dedup. Wrong epoch/digest ACKs are rejected; Ask/Reply IDs persist. Normal and race each passed 1 top-level / 2 subtests, 0 failures/skips; total 115.230s. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g4-process-boundaries-20261009f/result.NONAUTH.json), SHA-256 `6cd8d85113fa3d896ff5e89da4544899127bcf75a15c4569bee78eb07ce721c3`; test SHA-256 `ca1a572f4410cfed0a8281025e7a82836706a636df8ff1183304d1ae29c06b23`, dirty631 plus that test. Not a full MCP daemon or Runtime/model test; credential reads 0, owned container absent. Earlier a–e format/cache/compile/noexec/fixture-auth failures remain retained. |
| G5 retained HTTP / live-U boundaries | HTTP privacy and Monitor approval-denial normal/race gates passed; real unjoined zero-turn U was hidden by production Directory in the separate CLI **0.161** fixture. | [HTTP source/receipts](g5-http-privacy-validation.md) and [Monitor/live-U source/receipts](g5-native-monitor-boundary-validation.md). Current test hashes remain `de31d376…612` and `ce932ff7…33a`. U is not a 0.162/context/recovery result; its provider count is `NOT_INSTRUMENTED`. These scoped results are not full G5. |
| Retained CLI 0.162.1 live-U Directory gate | `PASS_LIVE_ZERO_TURN_U_DIRECTORY_ONLY`: real non-ephemeral U `01a12333-bdb4-7fa0-b821-6dda6b264c04` was loaded before/after, hidden from Directory, then unsubscribe was confirmed; zero turn starts. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g5-native-current-20261010a/output-01621-001/result.NONAUTH.json), SHA-256 `af4c8293c3d5a07e644af9b6fce2cd4ae830717e3c4c6ab49511fd135922afdf`; [host result](../.cicada-data/native-observer-wiring-20261007/g5-native-current-20261010a/output-01621-001/host-result.NONAUTH.json), SHA-256 `c4adb828f3af2e4f5694aa33fad802e2e3916e776b35698cb9b123eb91a9b012`, confirms cleanup and six residents unchanged. Empty U durable metadata was not materialized; context is `NOT_PROVEN`. This does not close all G5 or replace historical 0.161 evidence. |
| Default Go suite | `PASS_WITH_OPTIONAL_SKIPS`: 30 packages; 1,522 top-level pass events and 1,408 subtest pass events; 22 explicit skips; zero failures. Build, default tests, `go vet ./...`, and read-only `gofmt -l` passed. | Final receipt `.cicada-data/coherent-full-go-capacity-20261009a/runs/dabce1740f91-20261009T182113Z-1132233/result.NONAUTH.json`, SHA-256 `42cf1912a7a2e7f083288efbedf66315ca0093eaf7f08c6bc320f930716b01b5`. The runner used `umask 0022` only for the Go test subprocess so public-mode fixture tests retain their intended modes; the earlier same-source harness failure is preserved. The 22 skips remain skips, including Native and Docker acceptance tests. |
| Shipping package fixture | `PASS_SCOPED_DISTRIBUTION_AND_POSTCHECK`: `TestPQDistributionActualHubNode` plus four subtests. | Root postcheck `.cicada-data/pqtls-package-gate-phasec-20261009a/ROOT-POSTCHECK.NONAUTH.json`, file SHA-256 `07a483ed14e0a6d6580ed2311f92c9a0cdee43af259c8e329cd09c3fb7ccaa1a`, references run-result SHA-256 `80137103d3fbca556b491f2ec35a61e0726dd1f9b5b1046afe12ac4a6f6d74ea`. This is a bounded package/distribution test, not full Native, physical-device, or public HTTPS acceptance. |
| Relay Ask admission / schema v59 | Scoped admission-count index and schema-59 benchmark evidence; focused changed-logic race passed 8 top-level / 10 subtests. The prior failure/timeout and correction attempts keep their original attribution. | [Detailed record](relay-admission-performance-validation.md). This is a capacity/query result, not a full Go or Native gate. |
| Endpoint Resolve capacity | Active Service and legacy Control scan eligible candidates in bounded stable pages, preserving exact/qualified precedence and authorization/binding filters; focused normal/race selectors passed. | [Source and limits](directory-resolve-capacity-validation.md). No schema/index/API contract change; not fleet capacity evidence. |
| Node sealed pre-writer phase diagnostics | Focused normal/race checks passed 6 tests / 3 subtests each; phase logging does not change admission or prove queue acceptance. | [Independent record](node-sealed-phase-diagnostics-validation.md). |
| Group/Fabric cross-feature stress | Nine selected tests across four workload stages and a successful builder; zero failures/skips and owned cleanup verified. | [Stress record](v01-group-fabric-stress-validation.md). Tested dirty source `1ad5a96414c2d888f70c5b61467b3b1e4a382a91` (946 Go files; source-tree SHA-256 `a33879ff…fd0ae`), not clean `dabce174` alone. |
| Static contract / packaging checks | Contract 17/17 and build-input inventory 6/6 passed. Release packaging reported 14 pass, 5 skip, 0 fail. | Receipt `.cicada-data/root-static-closeout-20261009a/RESULT.NONAUTH.json`, SHA-256 `50fe1a9fdc7a7d71ab770622c6b1edcde3f4efb693a123eacee9b38560ddbcaa`. It is a separate dirty `1ad5a964` static-check snapshot; five skips are for unavailable release/PQ artifacts, not passes. |
| M5 multi-Hub protocol fixture | `SCOPED_PASS`, 83 seconds: two disposable Hubs and two production Multi-Hub Agent processes; synthetic sessions, owner-bound heartbeat/Network claims, Hub ciphertext and cross-Hub denials were exercised. | `.cicada-data/m5-pqtls-protocol-20261009b/receipt.json`, SHA-256 `c62daab2881408ad12da6fc88dc05f4e160d8d146fafa6c16355d02d609588c0`; Root postcheck `.cicada-data/m5-pqtls-rootops-20261009b/POSTCHECK.NONAUTH.json`, SHA-256 `f3bd7fcc1b8cda9553ecb7632df33b9a5c73bb115210bf708e62dac877668f36`. The gate used HTTP/TCP on its owned Docker network; PQTLS handshake, Native Runtime, Android, physical devices and public HTTPS were not asserted. |
| Protocol interop | `PASS_SCOPED_PROTOCOL_INTEROP`, 76.412 seconds: five top-level tests and three nested recovery subtests, no skips/failures. Client smoke/recovery: 2 top-level + 3 subtests; Network M1: 1; Group Spaces M2: 2. | Result `.cicada-data/protocol-interop-current-20261009a/root-run-20261009a/result.NONAUTH.json`, SHA-256 `e3d1ab406dc31afe2495d1fe6d76aa7bce155cfdd422919a3c8f347712dd0247`. It used synthetic fixture credentials and real loopback TCP. It is not Android, a PQTLS handshake, Native Runtime, physical-device, or public HTTPS evidence. |
| M4 owner-revoke integration overlay | `PASS_SCOPED_TEST_OVERLAY`, 160.535 seconds: normal cmd selector, three store selectors, then the same cmd selector under `-race`; 5 top-level pass events, 0 subtests, skips, or failures. The overlay extends the existing encrypted owner/Monitor Group Spaces fixture to revoke a delegation, verify the version advance, and deny a later apply without changing the accepted prior result. It does not measure a native scheduled wake. | Result `.cicada-data/m3-m4-revoke-fixture-20261009a/run-m3-m4-revoke-20261009a002/result.NONAUTH.json`, SHA-256 `1e2a1f6b54916ae4b2ef133a0255231b8d6c8ea6a2d44f340f2ff2bce98c1e02`; overlay test SHA-256 `f186136f7c61fc71f89f3b3a3e6d56bb8a0b436d0dfc6769acffe82336cb24f0`. The tested Go source is the clean `dabce174` snapshot, but revocation assertions come from this ignored test overlay and are not present in the tracked test at that commit. The byte-identical tested file is now tracked at `631666c`; this does not reattribute the original run. The runner verified zero Go-cache writers before launch. An Endpoint go-list startup process briefly shared the cache and exited naturally after about 1.12 seconds, before any tests ran; no claim is made that it was stopped by Root. The run passed all source, mount, test, and exact-container cleanup checks, and a post-run check found no cache writer. |
| M3 space-event parser routing overlay | `PASS_SCOPED_TEST_OVERLAY`: the focused normal and race selectors each passed 2 top-level tests and 2 subtests, with no skips or failures. The added `httptest` SSE case verifies `space` reaches only the space channel, while `ready` reaches both the space and claim channels; the pre-existing wake-hint assertions also pass. | Result `.cicada-data/m3-space-routing-overlay-20261009a/run-m3-space-routing-20261009a003/RESULT.NONAUTH.json`, SHA-256 `45f5387b3c6e32729fb0594e79c993840a61d17688a5feb6e2b14d90a4407b60`; ignored overlay test SHA-256 `53fc748a08c98b890443780d607b721edc44ca6f25517c993b104eaab9edfeef`. It used clean snapshot `dabce174` with an ignored test overlay, no Native Runtime, credentials, provider calls, or model calls. The byte-identical tested file is now tracked at `631666c`. This proves Go SSE parser channel routing only; it does not observe the space-sync worker, Agent job loop, or Native Runtime wake behavior. |
| TCP connect deadline/cancellation test overlay | `PASS_SCOPED_TEST_OVERLAY`, 45.127 seconds: normal and `-race` each reported 6 top-level and 6 subtest passes; 0 failures or skips. It checks a finite default connect deadline, preservation of an earlier parent deadline/cancellation, and that cancelling the connect context does not close an established connection. | Result `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/RESULT.NONAUTH.json`, SHA-256 `a315b9167c0df5592d8af73f0e9fc54110e2b61d1073a6af5dc44fda6d287d04`; independent postcheck `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/POSTCHECK.NONAUTH.json`, SHA-256 `91ba50c74a4712ed7e154429a16d50a6f06340ffde70dcf4405b0cc73c37aa7d`. The test and `internal/pqtls/openssl_linux.go` came from an ignored Go overlay (`openssl_tcp_dial_test.go` SHA-256 `b060c9222cadf8b5653c64f3aa92b2655c1d3d49ee4ca03ec381bf68c3d42e60`; implementation overlay SHA-256 `83891a97855ce44a0152f20b0c8dc4c6d0d8709d7f2345dc9b17b4e4be70fb7d`), not the clean `dabce174` source. These implementation/test bytes are now tracked at `631666c`; the old run remains an overlay result. Both receipts record 1,177 source rows and protected containers unchanged; cleanup and the exact owned-ID absence check passed. |
| Native fresh-restart startup gate `phasec20261009e` | `PASS_STARTUP_ONLY`, 48.403 seconds: both CLI 0.162 sessions completed the bounded restart; the strict fresh-connection predicate passed with one accepted new connection per Node and zero turn events/provider POSTs. The restart witness omits anchor/count/elapsed telemetry, so this is startup-only, not Native Ask/Reply or recovery. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/peer-startup-zero-fresh-witness-result-phasec20261009e/STARTUP-RESULT.NONAUTH.json`, SHA-256 `8035fd8640da9bdd0caae9890b8d538d1968551850ea8784ddd14c780d16b747`; source artifact clean `dabce174` / fingerprint `89a05305…10eef7`. |
| Prior Native original-thread attempt `a003` | **FAIL / G1–G2 incomplete.** Three actual turn starts and completions were observed: A and B joined on their original Threads, then A completed same-Thread second-Group join/use/leave/whoami. Original Threads: A `01a12234-68bf-7373-8324-f2e169c92a5b`, B `01a12234-6b59-7f60-b241-5bf166a088d7`. Bilateral endpoint consent passed. A's initial seed echo was present; B's status is `MISSING_PENDING_CONTINUITY`, a pending witness rather than evidence of model amnesia. No Ask/Reply or context witness was recorded. The follow-up fresh Hub restart did not establish a PQTLS-ready witness (`PQ_READY_UNPROVEN` within the bounded 5-second QA wait); this does not identify a network cause or establish the production reconnect bound. `provider_request_count` was not instrumented, so turn events are not provider-request counts. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a003/result.json`, SHA-256 `e50d159da47fba3d503254eec91313e341a13d2adb2cc7339294c8dd0d1aafa9`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a003/POSTCHECK.NONAUTH.json`, SHA-256 `2d0af104b0aec63c3ce341ecceebb4fb51bc738ada523268c9315117a131823d`, confirms owned Docker absence and six residents unchanged. The run reports owned-resource cleanup true and both Observers at expected EOF; its private state was retained. Earlier a002 remains a separate failure with cleanup false and Observer UNKNOWN; a003 does not rewrite that history. |
| Prior Browser/panel gate `G` | **PASS, scoped Browser workflow**, 29/29 checks. Headless Chromium verified vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty/recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle behavior, selected-group confirmations, cross-node link metadata, and authority denial. All seven asset/identity requests returned 200. Two Chromium cgroup samples were 116 then 132 processes against `pids.max=256`; `pids.events:max` and sampled OOM counters stayed zero. | Result `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/browser-output-phasec20261009a007/result.json`, SHA-256 `99578efc76b71ba6d0bf18f1b6f59a94ff194cb3322b6ffd250cfc7f22ee6dcc`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/POSTCHECK.NONAUTH.json`, SHA-256 `e5bb464b37a2743ec9957ca7b108db106a304d33a2a69e37b6671c2bf09649e8`, confirms exact owned IDs absent and six residents unchanged. This earlier gate remains in its original scope; current status is in the following row. |
| Current Browser/panel gate `public-browser-checkpoint-actual-20261009a` | `PASS_SCOPED_BROWSER`, 125.209 seconds: all 29 browser steps passed, including vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle, selected-group confirmation, cross-node link metadata, and authority denial. | Result `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/browser-output-public20261009a001/result.json`, SHA-256 `1e5717c90bf052fe74350df2c2dcb294294f61c92a6e4406ca6ec91657311496`; source script `scripts/test-hub-web-panel-browser.mjs` SHA-256 `fc9021aa4eec38d68147d26597ace0231c8b16ef9ad3eb7cee83e78784842598`, private source-derived resource/deadline/cleanup envelope SHA-256 `047089ca38ebab7481dd45a8d17acb72a977b843c999081770e092a8d2ee62c0`; clean Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9`; Chromium image `sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04` (Chrome 151.0.7922.109). Root postcheck `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/ROOT-POSTCHECK.NONAUTH.json`, SHA-256 `4d0b6239fe6f49db2f71da2c0c6ebaca4a516ba44cbf4aa1a5f26d61b19b4ab9`, records 14 captured IDs absent, four planned names and the network absent, and six residents unchanged. Two successful short-lived `--rm` CLI containers had no captured IDs, so this does not claim ID-level proof for all 16 launched containers. This localhost/browser fixture is not Android, physical-device, public-HTTPS, or Native Runtime acceptance. |
| Prior Native original-thread attempt `a004` | **FAIL / G1–G2 incomplete.** Four turn-start submissions on original Threads A (3) and B (1); failure at `original_a_managed_ask`. A ordinal 6 reported `UNKNOWN_IO`. Source-derived analysis explains the missing detail: five six-phase connections used 30 notes; the sixth reached the 32-note recorder cap before `PROXY_CONNECT_ACCEPTED`. The actual phase array was not persisted. A separate source-only derived-cap test passed 4 checks; the fix was not integrated into this paid run. The provider-request count is uninstrumented, with no HTTP/TLS result, so the underlying I/O cause remains unknown. Read-only projections confirm one A→B request `OPEN`, Fabric ASK `queued`, outbox `RELAY_ACCEPTED`, recipient inbox/delivery attempt `CLAIMED`, and no reply ID; B's matching writer record is epoch 1 `INJECTING` with `queue_accepted=false`. Relay acceptance and claim are not Node queue acceptance, Runtime consumption, or a B answer; A recovery/context remains unproven. The run reports cleanup false, four cleanup `RuntimeError` classes, and both Observers `UNKNOWN_RETAINED_SUBSCRIBER`. | Native result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a004/result.json`, SHA-256 `71caa8a9ae7f2756313e84b7bcac76a7e29e01ad8f79280e512dc08814b34f09`; source-only phase-cap analysis and four-test receipt `PHASE-CAP-ROOTCAUSE.NONAUTH.json`, SHA-256 `d97a1ada46297f72dafbf6a210d9e6009fc8690b9df303bb106c96410a35bd3d`; Relay projection `relay-projection-closed.NONAUTH.json`, SHA-256 `f4bed239a8c7b859ce066259fb1692a0a66bf017138d5254a0b1cb1e718bebd9`; writer projection `native-writer-projection-closed.NONAUTH.json`, SHA-256 `f1a698ea459281594957fe107dc694ab74ba530212b6fc5429e2c24ef8ee08df`; Root postcheck SHA-256 `9e131ff942e86b886e2cff414213ce0bb6129ff4223a36703cfa0ee7a01282fa` confirms recorded containers, networks, helper names absent and six residents unchanged. The postcheck does not change the run's cleanup/Observer fields; three Root-owned mode-0700 forensic directories remain. Root read-only Relay projection `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a004/ROOT-RELAY-STATE.NONAUTH.json`, SHA-256 `4b64f5e25f28107cbd30194a3537240b1913d335f3706a809482fae695846236`, independently confirms request state and no reply. No message body or digest was selected. |

<a id="latest-native-entryfix"></a>

## Prior Native attempts `drainfix20261010c001` and deterministic wiring

Both actual c attempts remain **FAIL** at `original_managed_join_and_context`:
G1 exit 1 / 31.670s / `TypeError` / one started turn; G2 exit 1 / 198.067s /
`RuntimeError` / two started turns. G2's closed I/O classification is READ_HEAD
parser rejection; the exact rejected rule and upstream-hop cause are **UNKNOWN**.
Neither result closes original-context acceptance, the G2 denial tail or G3 restore.

| Lane | Actual result | Root postcheck |
|---|---|---|
| G1 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-drainfix20261010b/request-observer-native-result-cicada-two-turn-g1drainfix20261010c001/result.json), SHA-256 `64c7ad628ae639c5c54e41c312fcdaf8d4f0e8d134370b66c970af5099b2e49e` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1drainfix20261010c001/POSTCHECK.NONAUTH.json), SHA-256 `1526f35efe19df394999f6bad4e5af56e1e21fc3d7a5e83d97122ecd78cc6220` |
| G2/G3 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-drainfix20261010b/request-observer-native-result-cicada-two-turn-g2drainfix20261010c001/result.json), SHA-256 `7cfb9f64de43a15edb6865863ac5c835874f56f4dd03ea4ec20a362a736c8270` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2drainfix20261010c001/POSTCHECK.NONAUTH.json), SHA-256 `dc0fa6deb6014a8fdb4c273befce96b69b4880a84ddb8380062533de33fee312` |

Both report `cleanup_owned_resources=true` and both Observers
`EXPECTED_EOF_CONFIRMED`; each Root postcheck confirms 14 owned selectors absent,
source pins unchanged and six protected residents unchanged. Cleanup is separate
from the Native FAIL. The linecache and EOF/drain fixture corrections do not
rewrite the earlier b entries or d Observer-UNKNOWN results. Compiled Go artifacts
retain clean631 attribution; current Python QA changes have their own source pins.

The full deterministic wiring suite now reports **45 PASS / 2 explicit retained
A/B replay SKIPs / 0 failures or errors**, exit 0, 50.403s; no Runtime, provider or
model calls. [Actual suite receipt](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010c/SUITE-RESULT.NONAUTH.json),
SHA-256 `0375ad7c3b5bf6e499ec22feee1bdf1616fb58e85b3f50d1e4b2407ec9d85429`,
pins checker `2b4a8e8f154f15edae5aac3fb7aa9dd39535ef1cbc0723109baba17b70a3b814`
and the fresh immutable test binding below. Shipping defaults and all rejection
oracles are unchanged; the tests explicitly select coherent current metadata.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/native_observer/request_observer_wiring_checks.py \
  --current-binding-file /home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010c/binding.NONAUTH.json \
  --current-binding-sha 4c019a1606bee9ac4743675d294e23c39123707876c9afa3704057c5b536ad37
```

The initial default full47 result remains FAIL (27 PASS / 18 ERROR / 2 SKIP).
[Fixture revision a](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010a/SUITE-RESULT.NONAUTH.json)
remains FAIL (36 PASS / 7 ERROR / 2 FAIL / 2 SKIP);
[revision b's immutable count correction](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010b/SUITE-COUNT-CORRECTION.NONAUTH.json)
records 44 PASS / 1 ERROR / 2 SKIP, preserving its original receipt and log.
The final PASS is deterministic fixture validation, not Native acceptance.

## Prior preparation and entry attempts `drainfix20261010b001`

The two corrected zero-preparations passed in 34.529s / 35.182s, with no
Native/model/credential dispatch. Their source checks, fourteen exact Docker
ID/name selectors and two actual socket absences per lane, and six protected
residents were independently verified; preserved symlink state is not absent.
[G1 zero execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/zero-rootops-g1drainfix20261010b001/ACTUAL-ZERO-EXECUTION.NONAUTH.json),
SHA-256 `db32b26fc299da6863a471e457ea7aef4b892273507484305a6a901137ad193e`,
and [G2 zero execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/zero-rootops-g2drainfix20261010b001/ACTUAL-ZERO-EXECUTION.NONAUTH.json),
SHA-256 `1074e1c1363ac3e0e1c02c60bcb98cb51cf90e173c7cade067b522e44667ac0c`,
prove preparation only. The narrow EOF/drain correction passed three focused
Root checks and effects-denied preflight; it preserves terminal failure and
requires actual EOF. It does not identify the earlier initiating provider hop.

The subsequent G1/G2 entry attempts exited 2 after claim, before result
construction, at the selected-source loader: 3.020s / 3.570s. There is no Native
result; Runtime/model/effect counts remain **UNKNOWN**, not zero.
[G1 entry execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1drainfix20261010b001/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `c900c1344f39ab617c025c9f945db36b45ea8f821737212c4f21c118280b7121`,
and [G2 entry execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2drainfix20261010b001/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `fb4cdc14f271bad6892a234f9e97f790df80432bdd1cd8aac5de6df0a19c7444`,
remain failed entries. Effects-denied reproduction found that compiling the
public candidate under a synthetic filename makes `inspect.getsource` in
`install_native_rpc_shutdown_drain` fail before the constructor. A minimal
fixture-only linecache correction enabled the later c attempts above;
no Native PASS or completion is claimed. Prior input/source failures and
all earlier scoped proofs remain unchanged.

## Prior Native attempts `g1entryfix` / `g2entryfix20261010d001`

Both prior attempts remain **FAIL** at `original_managed_join_and_context`:
G1 exit 1 / 34.680s / `TypeError`; G2 exit 1 / 97.036s / `RuntimeError`.
Each reports one started Native turn/submission. Real Threads exist, but neither
result establishes full RPC or original-context acceptance. Cause is under
read-only investigation; the exception class alone does not identify it.
The separate private inputs are pinned by [binding `bundle-g1g2tlsfix20261010f`](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/binding.NONAUTH.json),
SHA-256 `fbf9b3155eb00bae107a6e61e4c4ae230c305775f90752afac1a3266f37cd9e9`;
[G1 wiring](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/WIRING-MANIFEST-G1-PHASE-CURRENT.NONAUTH.json)
and [G2/G3 wiring](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/WIRING-MANIFEST-G2-G3-PHASE-CURRENT.NONAUTH.json) retain their own source pins.

| Lane | Original result | Later Root Docker postcheck |
|---|---|---|
| G1 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/request-observer-native-result-cicada-two-turn-g1entryfix20261010d001/result.json), SHA-256 `2b1f5ad94702f8ccb933eef0c6bf16495ea506f1fb0a24412c3179e4a5380457` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1entryfix20261010d001/POSTCHECK.NONAUTH.json), SHA-256 `55ad203ce433b2f256cb0d92fde287a6d76d96acb5e30a14f61de2ccc9b4520b` |
| G2/G3 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/request-observer-native-result-cicada-two-turn-g2entryfix20261010d001/result.json), SHA-256 `55ddb00df3d0dbf5ebee79f655117fbe7b22bf3b1ec155b7c935ea710f76f0f5` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2entryfix20261010d001/POSTCHECK.NONAUTH.json), SHA-256 `8526b92e74b9d146bf3860f94dd8fb61c74aed5b9c25891ae04b43f6b69cb53b` |

Both original results report `cleanup_owned_resources=false` and both Observers
`UNKNOWN_RETAINED_SUBSCRIBER`. Later Root postchecks prove all nine exact owned
Docker selectors absent per lane and six residents unchanged. That limited
absence proof does not rewrite cleanup, Observer or business verdicts. Prior
six-turn context evidence and all failed attempts keep their original scope.

## Prior Native CLI 0.162.1 attempt `cli0162120261010a002`

The [actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-cli0162120261010a/request-observer-native-result-cicada-two-turn-peercli0162120261010a002/result.json),
SHA-256 `971bb4c37e4771d2baede4170653a2c81cd21b7c5799fad7f47642bc64ffbae5`,
remains **FAIL**, `RuntimeError`, at the zero-model
`g2_actual_hidden_members_and_revoked_link_denial` stage (106.609 seconds).
All six turns completed (four manual, two automatic). Original A
`01a12336-b700-7da1-84e6-36658f71cb38` passed completed/correct-answer/inline-correlation
and both context-marker predicates. Original B
`01a12336-b99e-7350-821a-3e99742f58e6` passed all five recorded seeded-reply,
original-thread, request/receive correlation and validated-Link booleans.
These are scoped cross-Group original-thread context proofs, not same-Group G1
or complete G2/G3 acceptance. G3 restore was not reached. Control-object exclusion
records `dependency_proven=true`; its invocation count remains `NOT_INSTRUMENTED`.

Cleanup is true and both Observer EOFs are confirmed. The initial Root postcheck's
network-absence predicate falsely failed and remains retained; the
[corrected postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-cli0162120261010a002/POSTCHECK-CORRECTED.NONAUTH.json),
SHA-256 `ead36b56b427a75c7029c271303ff56dad769ffe29cd07be09a830b3bdc81e73`,
combines four exact network-not-found checks with the prior 13 container checks:
17 selectors absent, zero cleanup fallback, six protected residents unchanged.
Source remained unchanged during the run; clean631 artifacts retain their build
attribution, separate from the current CLI/QA inputs. No overall PASS is implied.

## Prior Native attempt `receiptc20261009c002`

The [actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-receiptc20261009c/request-observer-native-result-cicada-two-turn-peerreceiptc20261009c002/result.json),
SHA-256 `c5993fb489c487cc7b75704e33a54bc131ef44452681a95179df4c90bcb61fc9`,
remains **FAIL** at `actual_queue_original_a_receive_context`. All six turns
completed (four manual, two automatic). B's full correlated seeded reply/context
predicate passed; A completed in its original Thread with both context-marker
booleans true. Production correctly prepended the shared-memory-risk warning
([producer](../cicada-go/cmd/cicada/machine_sealed_receive.go#L745)); the QA
canonical-reply prefix check did not recognize it. The subsequent retained-A
strict full-field/context/warning replay passed 1 test, 0 skips ([receipt](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/scope-warning-root-qa-20261010b/result.NONAUTH.json),
SHA-256 `42797bc0df3cee4911d8f3a24c5f44d169aa398d996403ab872c78db8b90942d`).
The earlier setup-only failure is retained; this replay does not upgrade the
original paid FAIL.
The [actual execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-receiptc20261009c002/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `632f5d0e417ec7dfd6d1ce867e8fb1a358dc809918aeec59f4ade43332cc2da5`,
records 94.252 seconds. Cleanup is true, both Observer EOFs are confirmed, and
[source/owned-resource postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-receiptc20261009c002/POSTCHECK.NONAUTH.json),
SHA-256 `63be47013af306f8c7da39d210709a2cc97d1ccdaa9298ecb3c59a0c839841f8`,
keeps source and six protected residents unchanged. Clean631 Go artifacts are
separate from dirty QA/G4 test changes. G3 restore and Link revoke were not reached.

## Prior Native attempt `phasecap20261009b002`

The first paid entry `phasecap20261009b001` stopped at `GO_TYPED_BINDING`, before
Runtime/model dispatch: the Root GO supplied the fixed HTTPS upstream URL where
the typed binding requires the Runtime loopback URL. The provider stayed
`https://api.zzswitch.com/v1`; the guard was preserved. Its
[closed reproduction](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b001/PRESTART-GUARD-ROOTCAUSE.NONAUTH.json)
is not a Native failure or a production configuration change.

The corrected entry ended **FAIL**, exit 1, Root wall 89.779 seconds. Its
reported stage is `actual_queue_original_b_receive_reply`, not proof that B
failed to reply. Six Native turns started (4 manual and 2 automatic) on
original SIDs A `01a122d8-068d-7e71-914e-a40c3610f8c0` and B
`01a122d8-0925-7973-8633-30529be4ac0c`; five completed audits include B's
`cicada_receive` and `cicada_reply` in its original Thread. Read-only durable
state confirms request `rq_9688c14ad36e590918eca8938539e75d` is `REPLIED`;
B's Ask inbox/attempt is `INJECTED` and its writer is `QUEUE_ACCEPTED`. The
correlated reply outbox is `RELAY_ACCEPTED`; A's inbox/attempt is `INJECTED`
and writer is `QUEUE_ACCEPTED` at binding epoch 2. Receipt layers include
`RELAY_ACCEPTED`, `NODE_RECEIVED`, `CODEX_QUEUE_ACCEPTED` and
`CONSUMPTION_UNCONFIRMED`: durable reply and A queue acceptance are proven,
not final A consumption/context completion. The
[closed Relay/Node/writer projection](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/RELAY-NODE-WRITER-CLOSED-METADATA.NONAUTH.json),
SHA-256 `dc16e68872118443e0ec26dd2fbb6b49d87606fb5d068a7c5846fc649231917a`,
contains no message body or ciphertext. A separate
[B seeded-reply replay](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/B-ORIGINAL-SEEDED-REPLY-WITNESS-REPLAY.NONAUTH.json),
SHA-256 `314c53d19855e7263053e694e855198a3c028ce38b8c74c1cc57f8c71df30cfb`,
confirms exact received Ask IDs/sender, reply equality to the expected seeded
phrase and seed-marker presence; the question excludes the seed/answer.
This receipt proves only those synthetic-seed/actual DTO booleans. The raw
legacy `executed-managed-managed_gate.py` copy does not establish which
selected method executed. Scenario loading compiles the six-turn G2 flow to
call `self.g2_b_continuity`; the tested source's `G2_RECEIVE_CURRENT_LINK`
predicate required `receive.messages[0].link_id`, which the receive DTO does
not provide. This is a source-reproduced mismatch, not proof that the raw
legacy reply-argument guard executed. The earlier replay receipt
`12312154…19223` failed setup with `ModuleNotFoundError`; its false sentinels
are not evidence of B amnesia. The original run remains FAIL. The sixth, automatic A turn
started then ended with native error category `other`, no HTTP status and
`willRetry=false`. That error and A broker ordinal 7 `UNKNOWN_FRAMING` are
under investigation; observed A shutdown may be secondary and does not
establish a provider/framing root cause. Source remained
unchanged. The
[actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasecap20261009b/request-observer-native-result-cicada-two-turn-peerphasecap20261009b002/result.json),
SHA-256 `558f938fab6e0e0211b2f5c92f5876a245665c7a165d8b1b052544f06fa2e7f9`,
reports cleanup false, four cleanup `RuntimeError` classes and both Observers
`UNKNOWN_RETAINED_SUBSCRIBER`. The independent
[Root postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/POSTCHECK.NONAUTH.json),
SHA-256 `3782ab47f7e95b8fd51187fd517e67f46e1d31f88158e880cc716ea902f37370`,
confirms 11 owned selectors absent, zero fallback actions and six protected
residents unchanged. It does not upgrade the run's cleanup/Observer verdict.
The minimal contract correction passed three focused synthetic tests
(0 skips, 0.034s) and a full current selected B helper replay over retained
actual events (1 test, 0 skips, 0.022s). The
[Root focused summary](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/receipt-contract-root-qa-20261009a/ROOT-FOCUSED-SUMMARY.NONAUTH.json),
SHA-256 `da48dc38ab09b3b58a1850f518e830996b99a5c2aa65f36941076675340cf969`,
pins gate `7f665856…03f11` and wiring checks `468ddfe5…fbf95`. The default
58-test run remains FAIL (19 errors, 0 skips, 3.539s), including frozen-binding
`PUBLIC_SOURCE_CHANGED` and old compiled-proof `G2_SOURCE_BYTES_MODE_CHANGED`
rejections. An initial nonexistent selector also failed and was retained;
the corrected focused selector passed. These passes do not upgrade that broad
run or paid002, establish A continuation, or uniquely explain A shutdown.
Fresh wrapper/binding preparation remains separate from new Native acceptance.

## Prior Native attempt `a004`

Read-only projections confirm the A-to-B Ask is `OPEN`, Fabric `queued`, outbox
`RELAY_ACCEPTED`, and recipient inbox/delivery attempt `CLAIMED`; the matching B
writer state is `INJECTING` at epoch 1, with `queue_accepted=false`. The request,
message, attempt, endpoint and binding identities match across projections. No reply
ID is present. Thus Relay persistence and delivery claim are established, while
Node queue acceptance, Runtime consumption, B's answer, and A's recovery/context
remain unproven. The source-derived phase-cap analysis and its four pure checks
explain the missing ordinal-6 diagnostic detail, not the underlying I/O result;
the paid wrapper was not rerun with that derived fix. The separate Root
postcheck confirms Docker absence and unchanged residents but does not rewrite
the run's cleanup-false/Observer-UNKNOWN fields.

Superseded failure records remain unchanged: Native a002 result SHA-256
`d3fbe7b200a35a0d03fdf376edd24515f70eb4f1094e09998f3c32507b083287` and
Root postcheck `479ecb1fa165f4b36b3a961aebef4c57770086c04ffecd3bb829f52c2d72cd8e`
preserve the earlier cleanup-false/Observer-UNKNOWN outcome. Browser D result
SHA-256 `d4b466df69df93b5929dd9284b881fa2fe5cd447a89d3c9f317ab9f3e13d24e7` and
Root postcheck `24eb1d0798fab0e7c989019f05d6b058f817a4f24a339a8768c127684c53aaa2`
preserve its 45-second second-tab wait failure before the cross-tab guard. M4
overlay run `run-m3-m4-revoke-20261009a001` result SHA-256
`52b5a6c9207e6f989a27b3c89be039f0041fbe1bc3f1cbff03b1cd7c14875e19` preserves
the label-projection prestart failure; that container never started. Its
closeout SHA-256 is `5a4bf80d0402f46165ff1ba7dc28779f36725658f31dbd2d6b90c339669a9051`.

The six protocol-interop containers each matched their inspected HostConfig:
Hub containers were 1 CPU / 1 GiB / 128 PIDs on bridge networking; test
containers were 2 CPU / 3 GiB / 256 PIDs on host networking. Both roles used
UID/GID `1000:1000`, read-only root filesystems, all capabilities dropped, no
added capabilities, and `no-new-privileges`. Environment values were not
collected. All six exact owned container IDs were absent after cleanup, with
no forced kill. The independent Root postcheck above confirms the six resident
containers remained unchanged.

The exact interop selectors and one-T0 bounds are in
`.cicada-data/protocol-interop-current-20261009a/PREPARED.NONAUTH.json`:

```text
^TestClientDockerHub(Smoke|RecoveryFixture)$
^TestNetworkM1DockerHub$
^TestGroupSpacesM2(HTTPHistoryRetentionAndTopicCAS|DockerHub)$
normal deadline 600s; cleanup deadline 660s; external hard cap 690s
```

Recorded command shapes for the two aggregate checks:

```sh
cd cicada-go
go build -buildvcs=false -mod=readonly -o /tmp/cicada-machine-agent ./cmd/cicada
(umask 0022; go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./...)
go vet -buildvcs=false -mod=readonly ./...
```

```sh
/usr/bin/timeout --signal=TERM --kill-after=60s 690s \
  /usr/bin/python3 -B .cicada-data/protocol-interop-current-20261009a/run_current_protocol_interop.py \
  --output .cicada-data/protocol-interop-current-20261009a/root-run-20261009a
```

These are the actual private-runner command shapes for the aggregate Go and
three-suite interop gates. Existing tracked script entry points for the
individual bounded checks are:

- Client, Network M1, and Group Spaces M2: `scripts/test-client-hub-interop.sh --suite client`, `--suite network-m1`, or `--suite group-spaces-m2` (each suite runs separately).
- PQTLS package: `scripts/test-pqtls-packaging.sh` (requires accepted package, stage, and build-receipt inputs).
- M5 multi-Hub fixture: `scripts/test-multi-hub-docker.py` (requires accepted producer/build inputs).
- Static contract and inventory: `scripts/test_client_contract.py` and `scripts/test_build_input_inventory.py`.
- Release packaging: `scripts/test-release-packaging.py`.

The combined interop run's exact HostConfig and one-T0 evidence came from the
ignored private runner above, not from one public combined-suite script.

## Native G1–G5 and M3–M5 status

The acceptance definitions remain in `CICADA.md` §39. Current G1 acceptance
and independent remaining gates are indexed above; historical E3 retains its
terminal queue-oracle FAIL. Earlier attempts, full offline QA and artifacts retain
their own sources. Neither cleanup nor recording/synthetic queues prove full
Native or model-consumption recovery.

| Gate | Current state |
|---|---|
| G1 — original-context in-group Ask/Reply | **PASS within the current g1 run scope.** Five actual turns preserved original A/B context, correlation and terminal historical queue acceptance. Later artifacts and other gates require their own results. |
| G2 — same-thread multi-Group / cross-Group direct Ask/Reply | **PASS within C14's bounded original-context scope.** Six turns exercised the original A/B contexts, multi-Group authorization/leave, ASK/receive/reply/consume, and post-revocation denial; independent owned closeout passed 79/79 checks. The historical shipping0002e denial tail remains attributed to its own run, which failed cleanup. C9–C12 remain actual paid FAILs; C14 does not rewrite them or close every Native gate. See the [C14 record](native-default-daemon-validation.md#c14-scoped-g2g3-acceptance). |
| G3 — encrypted status snapshot / Control boundary | **PASS for C14's authenticated encrypted status snapshot after same-store Hub replacement.** The fabric-only Control exclusion returned HTTP 503, but its invocation counter was `NOT_INSTRUMENTED`; this is not a measured zero-call assertion. The historical shipping0002e snapshot retains its own scope and overall cleanup FAIL. A5's Node inbox remains `CONSUMPTION_UNCONFIRMED` for that separate loaded-queue test. Neither result proves Android status reads or shared-SID memory isolation. |
| G4 — restart, loss and duplicate recovery | **Scoped window evidence passed:** three production component/helper-process boundaries (pre-send, Hub post-commit/pre-ACK, Node durable receive/pre-receipt) passed normal/race. The independent official 0.162.1 post-injection/pre-ledger gate passed with uncertainty retained and reinjection refused. These sources cover their respective windows; they do not prove full MCP-daemon or Native/model consumption recovery. The default-suite SKIP does not negate either actual scoped result. |
| G5 — permission and data boundaries | **Scoped predicates passed:** production HTTP forgery/Directory/Artifact denials, same-SID multi-Group grant refusal, independent Monitor approval authentication denial, historical 0.161 live-U and current 0.162.1 live-U Directory invisibility, plus the a006 bilateral-Link pending-request revocation case (normal/race). That case verifies cancellation, delivery closure, revoked reply/new-ASK denial and exact SQLite absence for denied IDs. The Native hidden-member/revoked-Link tail also passed within the historical shipping0002e scope; its overall cleanup FAIL remains. Current live U has zero turns and no materialized durable metadata/context proof. Shared-SID memory isolation is not proven or promised. Generic export is unsupported, not an added gate. |
| M1 / M2 | Current Network M1 and Group Spaces M2 interop selectors passed. Remaining framework-wide semantics are not closed by those selectors. |
| M3 | **Scoped backend/integration evidence:** selected reference schema/pointer projection, Network Task/broadcast scope/epoch/revocation, commit cursor/unread reconciliation and parser space/claim separation have existing tests. `TestGroupSpacesMCPAcrossNodesWithLostCommitResponse` exercises reconciliation without mark-read; the parser test does not measure the long-running Agent/job loop or Native wake behavior. Full reference-to-immediate-delivery and scheduling claims remain bounded by their actual tests. |
| M4 | **Scoped v0.1 path passed:** Monitor MCP proposal, Owner encrypted delegation, guarded apply, topology projection, Owner revoke/version advance and subsequent apply denial; Store tests cover exact scope, CAS/audit, role revocation, reader separation and old key-consent fencing. The tested revoke-overlay bytes are now tracked at `631666c`. Full user/admin hierarchy and delegation UX remain explicitly v0.2, not a new v0.1 gate. |
| M5 | **Scoped HTTP/TCP evidence only.** The two-Hub Agent fixture passed; still separate are Native/PQTLS handshake, Client pin/device/session/replay behavior, and physical deployment acceptance. |

## Independent Client attribution

Current delivery, Client preparation and separately attributed APK build are in
[the current evidence index](#current-20261010). Joint11 passed its eight Android
recovery cases and final close ACK with exact cleanup. C14 is a separate scoped
Core/Native result. A11 passed the Android Owner Group grant and encrypted
Group-status read before/after one owned Hub restart in its protocol-only scope;
the separate v1.6.5 Link-policy status/restart A7 run passed all eight requested
selectors, with an independent 81/81 scoped review. Its APK producer and host
fixture snapshot are separately attributed; see the [A1–A7 record](v00-test-closeout-20261011-validation.md#v165-link-policy-status-a1-a7).
The A7 Android cases did not exercise the Hub foreign-owner guard, which has
separate Core Go coverage. The optional Client-specific non-null
`linkConsentStatusReadContext` plus `OUTCOME_UNCERTAIN` combination across
reopen/restart was not run; it is not an A7 failure or a deployment-trial
prerequisite. Physical-device acceptance and broader Native boundaries remain
separate.
Historical F38 and earlier
Client runs retain their tested APK, Core and runtime attribution; no Client
source was changed by this Core checkpoint.

## Remaining acceptance gates

1. C14 passed its bounded six-turn default-daemon G2/G3 scope with exact cleanup;
   C9–C12 remain separate historical paid FAILs and are not rewritten. C14 does
   not establish V67/account-bound submission, cold resume, two physical Nodes,
   or public HTTPS. A7 separately passed the eight requested Client Link-policy
   encrypted status/restart selectors. A7 did not exercise the Hub foreign-
   owner guard, which has separate Core Go coverage. The optional Client-specific
   non-null `linkConsentStatusReadContext` plus `OUTCOME_UNCERTAIN` combination
   across reopen/restart was not run; it is not an A7 failure or a
   deployment-trial prerequisite. A11's Group-key grant/status pass is narrower
   and did not use a CLI Runtime.
   G4's real
   queue-crash evidence remains an injection-before-ledger result with
   `INJECTION_UNCERTAIN` and reinjection refused; it is not a cold-resume result.
   Cold background resume is not asserted as an unconditional first-release
   requirement.
   See the [Native record](native-default-daemon-validation.md).
2. Obtain a supported account-bound Native submission API before implementing
   V67; current inspected API support is UNSUPPORTED. Keep physical StopVerifier,
   the independent Client Link-policy status-read and public-HTTPS gates
   separately NOT_RUN.
3. Build/package and interop-test a Hub from current clean Core 0326 before
   treating that source as a new delivery; the retained c688 interop image and
   clean-328f standard delivery predate it, and the A3 Go artifact is
   compile-check-only. Keep the
   clean-328f aggregate FAIL as recorded. Do not repeat the aggregate
   or standard/PQ artifact QA for this test-only checkpoint; rerun whole-Go
   validation when Go build/test inputs change or new Go failure evidence
   warrants it. The optional
   browser lane requires its sanitized runner to include Node and its required
   fixture inputs; retain BLOCKED status until they are available.

Scoped G1, G4/G5/M3/M4/M5, Apache and Link results do not create a completion
percentage. The v0.1.0 target remains **PARTIAL**.

## Scope boundaries

The current status entries in the architecture status, plan, completion ledger,
and Client/Hub guide link to this record. The distribution schema row is v59,
matching `CurrentV2SchemaVersion` at `cicada-go/internal/store/migrations_v2.go:24`.
Schema, software, contract, source, and image identities remain distinct. The
Browser fixture is localhost-only; the PQ package Node binary, Hub image, and
M5 HTTP/TCP fixture are separate artifacts and do not establish Native PQTLS,
Android, physical-device, or public-HTTPS acceptance. Client results remain
attributed to the independent Client checkout; no Client source changed.
