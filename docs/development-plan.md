# CICADA Client development and validation plan

## Current milestone: clean e2a1908 preparation

The [current preparation record](client-link-recovery-e2a1908-preparation.md)
is the active target. Complete independent delivery verification, deterministic
two-stage KEY/NONE recovery selectors, an explicitly owned opaque carrier,
focused offline checks, and one immutable APK pair. Retain source/dirty/input
and APK hashes. Application UI, local STT and production security are preserved.

After a separate Root joint-test GO:

1. Root verifies its fresh disposable Hub, helper, process identity and owned
   bridge, and starts a fresh Android session for each of eight cases.
2. Enroll directly and validate independent Hub/Owner pins plus encrypted
   capabilities. Prepare and externally sign a current exact KEY or NONE review.
3. Capture one original consent write through the selected Core fault carrier.
4. Match exact Core `FAULT_READY`; for uncertain, Root restarts only the owned
   Hub and verifies unchanged identity/origin before staging recovery readiness.
5. Recover the original packet once; join native state/sequence receipts with
   the carrier's actual HTTP/ciphertext digests. Preserve unresolved fences and
   deny later writes before allocating another sequence.
6. Read authoritative KEY/NONE status from a separate participating session on
   the direct Hub route. Record fault recovery separately from grant acceptance.
7. Root cleans only its owned fixture; record exact absence and resident
   preservation. Keep failed/unknown operations and previous APK evidence.

All eight live cases, runtime capabilities, reconciliation, physical Android
and public HTTPS remain **NOT_RUN** during preparation. No online call, Hub
lifecycle or model work is authorized by the preparation GO.

## Historical offline work: original Link recovery

The [recovery checkpoint](client-link-recovery-offline-validation.md) completes
the test-selector correction, independent saved packet/counter checks and
strict receipt validation. Three synthetic Kotlin groups, the changed Android
selector compile and six Python tests passed in offline Docker. No APK or live
run was created; this does not extend F38 runtime acceptance.

Next, obtain a Core-owned current-image fault entrypoint and a Root-coordinated
clean Hub window. Run separate lost-response, processing, uncertain and
unavailable sessions, then verify exact original proof/tuple reconciliation
with fresh KEY/NONE status. Preserve pending packets and failed/unknown history.
The safe fault fixture is **BLOCKED**; online gates, process-death, new emulator,
real native Worker, physical Android and public HTTPS remain **NOT_RUN**.

## Historical fixed-target acceptance — F38

The [F38 validation report](client-hub-v1.6.4-0213538-f38-validation.md)
records the bounded Android 15 emulator acceptance on clean Core `0213538`,
Client `caa9e4c725a841a1ce8488fbf339ca554d2939ed`, app APK
`f742532d7782e5a46f5364dc57f1dc6be6faf7903e09194d9db6028356b0a796`, and test
APK `e538fbaa0eef457cb15aa885534317efc8b3df7b3b6dd7703c3112ceaa21e258`.
All six phases completed with both KEY sides accepted and both final NONE
statuses verified/current bilaterally. Root independently reviewed 13 JUnit
tests (zero failures/skips), six signatures (SOURCE 3, TARGET 3), cleanup and
absence; one frame and one ACK exit 0 were attested separately from the
launcher terminal's `CORE_ACK_NOT_SENT`.

This validates only the five dedicated Link review operations on the fixed
emulator fixture. Encrypted Owner capabilities, current proof and server Guard
remain required; generic RPC continues to refuse the five. Ordinary
cross-user messages remain closed with `external_thread_links=false`. Real
native Worker acceptance remains **NOT_RUN**; model calls were zero. Physical
Android and public HTTPS remain **NOT_RUN**. F35–F37 failures and their unknown outcomes are preserved as
history; no retry occurred. The 21 existing capability/operation-policy
offline tests passed, exit 0; receipt SHA-256
`a0a842fe82a0add1ab0eb96e949d3af6cfd130075dfc3eaf6d8b8a7f0db62b6d` is at
`/gpu1-share/data/cicada-client/v164-f38-acceptance-record-20261004/link-capability-check.receipt.redacted.json`.
This docs checkpoint creates no APK; tested results remain bound to the exact
F38 source and app/test pair above.

## Historical launcher coordination — F6–F10

The current acceptance-harness work is the
[bounded single-process launcher](client-bounded-acceptance-launcher.md).
It preserves the retry-6 APKs and the original F6–F9 evidence. F9's first
staging command failed before any encrypted Android business request; the
runtime consumer correction is independently recorded and does not make F9
a PASS. The F6–F9 launcher work is historical and does not change the F38
bounded Link consent result above.

1. Completed launcher checkpoint `7f428d7`: freeze BOOT/hot helpers, narrow
   offline tests and their source hashes.
2. Completed read-only provenance: independently verify clean
   `0213538b62ccf2533eccf546c80fc848804ea8e0` archive, 896 immutable Git inputs,
   source fingerprint and image metadata. See the [delivery review](client-hub-v1.6.4-0213538-provenance.md).
   The dd81575 package/images remain historical provenance for their own runs.
3. [F10 bootstrap and cleanup passed](client-hub-v1.6.4-0213538-f10-validation.md),
   but Core preparation failed on missing `std-producer.json`. Preserve that
   failure. Core must fix dependency delivery/preflight; Client prepares a
   small COLD namespace successor before a fresh Root-approved window.
4. Use the actual Android READY, fresh Core references/Scope/one GO and a single
   combined stdin ticket for automatic carrier preflight and six-phase flow.
   Record each actual result and cleanup; preserve uncertain pending packets.
5. Keep isolated Link fault cases BLOCKED without a safe declared driver.
   Native Worker, physical Android and public HTTPS remain NOT_RUN.

## Historical milestone — clean Core 25bc586

The next clean delivery is now available: Core 25bc586 / Client-Control v1.6.4.
Its archive, catalog, immutable image metadata and 882-entry Git inventory
have passed independent Client verification. See the [new fixed record](client-hub-v1.6.4-25bc586-validation.md).
Native manifest authority, bilateral policy evidence, persistent Link recovery
and the explicit phone confirmation flow are implemented in the current
candidate. It accounts for 44 implemented and 11 closed catalog operations;
the five new operations use dedicated Native methods and generic RPC always
refuses them. The final corrected snapshot passed 40 independent Kotlin tests and built
both debug APKs in offline Docker (exit 0). Earlier unchanged JavaScript
checks passed 90 tests, TypeScript and lint in their recorded snapshots. Android checks and every live result are attributed to
their exact APK pair in the fixed record. The initial live read exposed an
Endpoint fingerprint-domain error; the corrected retry-4 app retains complete
proof, binding and Owner-pin checks and passed 47 emulator tests with its
original test APK. Test-only UI corrections are separately compiled and do
not inherit those results. The first fresh fixture attempts and their precise
failures remain in the fixed record. Core ran the final fresh F5 Store
bootstrap; Client used public metadata and encrypted Android sessions. Its
first ten business steps passed, then external signing refused the Client's
noncanonical fractional expiry. No Source KEY grant or Target operation
followed. The timestamp correction and durable codec compatibility are
validated offline in a new source snapshot. Complete bilateral acceptance,
real React Native Alert confirmation and exact-packet recovery remain separate
gates. F5 is terminal; further runtime work requires a separately authorized
fresh fixture.
Historical checks below retain their original source and version attribution.

Completed: the clean e8a029d/v1.6.3 public contract import and immutable image
verification, independent 835-input source reconstruction, 86 JavaScript and
16 independent Kotlin candidate checks, and the old144 two-Owner Android Link
status/original-packet recovery gate. See the [candidate proof record](client-link-consent-candidate-validation.md),
[new delivery provenance](client-hub-v1.6.3-e8a029d-validation.md) and
[separate Android fixture acceptance](client-link-status-native-fixture-144e079-validation.md).
Client-owned emulator/carriers were cleaned; Core separately removed fixture
Hub/Nodes and their networks, with independently verified exact resource absence.
No candidate APK or v1.6.3 runtime acceptance is claimed.

1. Completed: independently verify the clean 25bc586 reviewer-guard delivery,
   including the package, both immutable images and source inventory.
2. Completed implementation: independently pinned full Owner identities and
   current lifecycle, Native Endpoint proof verification and fresh consent
   authority bound to the current profile/session. The corrected Endpoint
   fingerprint comparison passed retry-4 offline/emulator and scoped live
   Source checks; bilateral acceptance is separately recorded.
3. Completed implementation: persist the original encrypted packet and exact
   write fence atomically. Live recovery requires isolated original-operation
   fault cases; local ledger tests do not establish those results.
4. BLOCKED: authorize a separate fresh two-Owner key/policy fixture for the
   corrected APK and its actual React Native confirmation path. F5 remains
   FAIL and cannot be restarted. Record future results against their exact
   APK and immutable Hub, with no automatic enrollment or write retry.
5. Validate the separate directory permission extension on that new runtime.
   Physical Android and public HTTPS remain NOT_RUN until actually exercised.

The directory extension remains closed. Earlier candidate preparation and
39/16 policy counts below are historical. Native Goal or model execution is a
separate acceptance gate from synthetic Link protocol fixtures.

## Candidate implementation — Group directory permission

Prepare the [explicit directory permission flow](group-directory-permission-candidate-validation.md)
against the read-only v1.6.2 candidate without changing the accepted v1.6.1
pins. Production entry stays closed. DTO, Owner/scope/version review,
one-use confirmation and early native refusal are implemented. Offline Docker
verification passed 79 JavaScript tests, TypeScript, lint and four pure Kotlin
tests; the formal record preserves the initial lint failure and its correction.
No APK or runtime is created in this preparation phase. The clean v1.6.3
delivery is now verified; dedicated integration and separate Android acceptance
are required to enable the action. Link status acceptance has passed its
separately attributed fixed-144 gate.

## Historical accepted Android milestone — clean Core 144e079

Use only the immutable Client-Control v1.6.1 pair and public package recorded in
[current validation](client-hub-v1.6.1-144e079-validation.md). Independent source,
image and archive verification, the corrected APK build, 81 Kotlin emulator
checks, UI checks, encrypted Directory authorization and exact 201/200 response
recovery have passed. Separate processing and uncertainty drivers have passed;
legacy protocol and the independently corrected absence/receipt checks passed
before teardown. Every failed attempt and its correction are retained separately.
The combined local milestone includes the code, formal validation record and
handoff; the external acceptance manifest and delivery receipt bind the actual
commit to its tested artifacts.

Actual Link status passed its two-Owner native-fixture gate. Keep configured
policy and all sixteen
unsupported consent operations closed. Do not call models, change Core or
switch to a later candidate during this gate. Physical Android and public HTTPS
remain NOT_RUN. Prior checkpoint sections retain historical attribution.


## Historical final candidate integration preparation

Prepare corrected catalog-role assertions, bounded live Link status selectors
and isolated original-packet recovery drivers in parallel. Independently
verify the final clean Core inventory, immutable images and contract package
before changing pins or building the app/test APK pair once. Preparation is
not runtime acceptance; every new live case remains `NOT_RUN` until executed
with its own artifact hashes and command receipts. See
[final gate readiness](client-final-gate-readiness.md) for the ordered gates,
precise fixture gaps and the confirmed configured-policy producer defect.

## Historical implementation slice — Link review policy status

Only `link.review_policy_status` is added to the local implementation set. It reads one exact Link from encrypted `link.list` through a dedicated, scope-bound native path. The policy now accounts for **39 implemented and 16 closed operations** out of 55. This is an implementation count, not live acceptance. The existing v1.6.1 contract and image pins are unchanged.

The view reports Hub metadata only. Default NONE with policy version 0, empty digest/sides and `current=true` is explicitly unconfigured. It does not establish Owner signature verification, bilateral approval, reviewer decisions, Link activation or message permission. Original-packet recovery and all uncertain-write fences remain in force. No private Owner key, signer, policy write or key Grant is added.

See the [dedicated validation record](client-link-review-policy-status-v1.6.1-validation.md) for the new source/artifact attribution and offline checks. New encrypted Hub, Android runtime, Node, model, physical-device and public HTTPS acceptance remain **NOT_RUN**. A live gate awaits the final clean Core candidate. Historical evidence below keeps its original commits and APKs.

The implementation milestone has completed its offline gates: 67 JavaScript tests, five pure Kotlin tests, 11 checker regressions, type/lint checks, role intersections and both APK builds, all exit 0. The next gate requires the final clean Core candidate and separate runtime authorization; no Android or native fixture is started by this milestone.


**Provenance supplement:** independent retrospective reconstruction now reproduces the immutable v4 fingerprint from all 773 pinned inputs, exit 0. Original build-time per-file mode capture remains **NOT_PROVIDED**. The earlier BLOCKED record is preserved; current live acceptance stays unrun. See the [separate supplement](client-hub-v1.6.1-fe565b4-provenance-supplement.md).

**Prior checkpoint provenance gate: BLOCKED.** At milestone `d580975`, the archive and pinned Git blobs matched, but the raw-permission fingerprint was not yet independently reproducible. That original result remains preserved; the supplement above records the later retrospective match. No live Hub or native-runtime acceptance is claimed; see the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md).


## Prior checkpoint — Client-Control v1.6.1

The final corrected checkpoint passed the pinned offline build, 59 JavaScript tests, TypeScript, ESLint (22 warnings, no errors), 74 Kotlin tests across 14 selectors, and five offline UI checks; every gate exited 0. App/test APK SHA-256 values are `6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816` and `abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec`; compiled source FP is `0b89a85d5c332faffb980851501c474942f28c1b047562e0daa547f27a32d7f0` over 112 files. The owned emulator was removed and six resident containers were unchanged. These are local checks, not live Hub or native Monitor acceptance. The full Client commit is recorded in `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/client-delivery.redacted.json` after the milestone commit.

The deterministic integration target is clean Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, protocol `client-hub-v1.6.1`, wire 1, catalog `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` and immutable Hub image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. See the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md) for archive/source pins, exact DTO verification, commands, artifacts and individual acceptance states. Earlier evidence below is historical and does not establish this checkpoint.

No new Hub, Node or model runtime is started in this checkpoint. Current encrypted runtime capabilities, native Endpoint/Monitor acceptance, physical Android and public HTTPS remain unaccepted. The 38-operation local policy and 17 closed operations are retained; no advertisement or synthetic proof authorizes a closed operation. Terminal regroup `OUTCOME_UNCERTAIN` retains its exact ciphertext/counters and dedicated fence.

## Historical v1.6 checkpoint

**Target:** clean Hub `4fb241b5e824eb752ceb85586089f44c408e1e7e`, `client-hub-v1.6`, wire 1, 55 catalog operations. The [validation report](client-hub-v1.6-4fb241b-management-validation.md) records the fixed archive, catalog, source and immutable image pins. No successor or dirty Core source is accepted implicitly.

The Client locally implements 38 operations and keeps 17 closed. Current Directory/admission controls are bounded metadata reads. Regroup provides one named proposal review, explicit one-use issue and version-CAS revoke. Issue requires unique explicit ACTIVE source/target Principal Memberships with positive projected versions, Endpoint association with both Groups, and the source Monitor role. Fresh topology and lifecycle checks fence stale consent. A projected Membership version is not the Core database revision. Terminal authenticated regroup `OUTCOME_UNCERTAIN` preserves original ciphertext/counters and keeps the write fence blocked; snapshots cannot clear it.

| Gate | Status | Evidence and remaining work |
|---|---|---|
| Imported contract / immutable Hub image | **PASS** | Exact 4fb241b provenance in the validation report |
| Final guarded build | **PASS**, exit 0 | App `93d490…`, test `041f6a…`, compiled source `e758625224b056a32a0ddb0d498606a6a49522f623a6c0173704a4896641cffb` (110 files) |
| JavaScript / TypeScript / lint | **PASS**, exits 0 | 56 tests, TypeScript; lint 22 warnings, no errors |
| Final Kotlin matrix | **PASS**, exit 0 | 71 tests/13 selectors, including 8 regroup checks and valid roles-only Monitor |
| Final offline UI and owned cleanup | **PASS**, exits 0 | Five checks; fresh network-isolated emulator removed; six residents unchanged |
| Earlier connected capabilities, Directory, Group-scope, 201/200 recovery and Node pairing UI | **PASS on earlier `9a6…`/`3cbe…` only** | Exact receipts retained; none transfers to final guarded artifacts |
| Final guarded APK live Hub checks | **NOT_RUN** | Repeat only with a fresh approved complete fixed-image fixture |
| Core native Join attempt | **FAIL**, controller 1, tool HTTP 404 | Required Endpoint/Network bootstrap was absent; exact argv not retained |
| Current native Endpoint admission preview / Monitor regroup | **BLOCKED / NOT_RUN** | Requires a real native Network Join, current binding, explicit target Membership and Monitor proposal |
| Candidate guarded APK `533142…` | **FAIL**, driver 1 / ADB 0 | Valid roles-only case rejected; fixed in final APK; candidate UI not run |
| Physical Android / public HTTPS / iOS / native HarmonyOS | **NOT_RUN** | Separate environment acceptance |

## Next ordered gates

1. Preserve all earlier artifact and failure receipts; the final Client commit is recorded in `/gpu1-share/data/cicada-client/v16-4fb241b-20261001/provenance/client-delivery.redacted.json`.
2. Obtain a supported native Network/Endpoint bootstrap and explicit Owner Group admission fixture. If it requires a new Core contract, independently verify its complete clean delivery before changing pins.
3. On that complete fixture, rerun final-APK encrypted capabilities/recovery, Node pairing, Endpoint preview and explicit Monitor delegation. Verify stale CAS, expiry, revoke, one-use application and replay refusal without synthetic Threads.
4. Keep all 17 unsupported consent/proof operations closed. Implement each only after its independent Owner proof, current authority, explicit confirmation and recovery semantics are complete; see the [readiness audit](client-hub-v1.6-operation-readiness.md).
5. Run physical-device key boundaries and public HTTPS independently. No emulator or historical native result substitutes for either.

## Historical v1.5 — Development checkpoint

**Target:** clean Hub `bd79ff93c90ecafc28a2471dd9523444903b39e6`, `client-hub-v1.5`, wire 1, 46 catalog operations. The complete archive, catalog and immutable image pins are in [the validation record](client-hub-v1.5-bd79ff9-validation.md). Only that image is accepted for this checkpoint; older results and current dirty Core work remain separately attributed.

The Client retains its 33 implemented RPC operations and explicitly rejects the seven new `space.*` consent/admission operations and three `topology.*` delegation/proposal operations. Native rejection precedes persisted-state access, device-key creation, pending replacement, and counter mutation. The UI also filters them even when the authenticated Hub advertises permission. Link key consent remains disabled. Cross-user messages, shared-history grants and silent delegated approval are unavailable.

Existing profile isolation, independent Hub pins, encrypted capabilities, original-packet recovery, Monitor ledger and the durable Network grant uncertainty fence remain in place. A generic snapshot cannot authorize a replacement Network Grant. Full dual-Owner v2 consent requires authoritative proof-side semantics, complete signed synthetic vectors, independent Kotlin verification, exact scope/version/expiry review and explicit phone confirmation before implementation can be enabled. A proposal remains separate from User Approval.

Fresh acceptance is recorded per layer: imported contract and image provenance; Kotlin public vectors and local guards; actual Android UI; disposable fixed-image Hub permission and response recovery. Physical Android, public HTTPS, full native Network consent, v1.5 Node/Monitor delivery, iOS and native HarmonyOS require separate evidence. v0.2 Dot/Live is documentation only.

Completed in this checkpoint: 54 Kotlin and 29 JavaScript tests; independent exact external-role operation checks across four Android sessions; fixed-Hub scoped Group creation and foreign-Owner denial; exact enrollment/RPC response-loss recovery; all three isolated outer-ledger recovery faults; offline UI and bounded connected management observation. Test commands and artifact attribution are in the current validation record. Next development gates are a separately pinned complete dual-Owner v2 proof/authority delivery, positive native Network consent with dedicated uncertain-outcome reconciliation, and fresh native Worker, physical-device and public HTTPS acceptance. Historical native results cannot satisfy these gates.

Subsequent [shared-space v2 framework work](shared-space-v2-framework.md) adds a collapsed, scope-bound local review panel and independent candidate-only complete-status proof verifier. The public Core vector is WIP; it is separate from the fixed protocol snapshot. All ten v2 operations and three Link key operations stay disabled. A local reading marker cannot become approval. The next integration must validate per-Owner external signatures and explicit confirmation separately from native Join and final dual-proof status. Proposal/delegation UI currently explains the blocked lifecycle rather than fetching or applying a proposal.

The bounded [Release packaging checkpoint](release-packaging-validation.md) selects the existing ABIs explicitly, enables managed-code/resource optimization and retains the native crypto/STT dependencies. It records actual unsigned artifacts separately from disposable signed test copies. Local package size and emulator inference do not replace a clean future Hub contract, native consent acceptance, physical-device measurements or public HTTPS validation; the protocol gates remain unchanged.

The subsequent [Release policy test correction](release-policy-public-validation.md) passes all four policy tests through public session behavior and synthetic authenticated responses against the unchanged optimized product. Only instrumentation was rebuilt; the original reflection failure remains separately recorded. This local test does not advance live Hub, native consent, physical-device or public HTTPS gates.

## Historical v1.4 checkpoint

**Historical checkpoint:** 2026-09-30, branch `dev/react-native`, clean Hub `f30892fcd79a27bfe5604575deaecebe52c5ec50`, protocol `client-hub-v1.4`, catalog `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`. The [v1.4 validation record](client-hub-v1.4-f30892f-validation.md) provides complete pins, commands, APK hashes and outcome boundaries.

That checkpoint added isolated Hub profiles and explicit ACTIVE Network selection, topology v2, `group.create(network_id)`, and dedicated `network.key_manifest/key_grant/key_status`. No operation is authorized by a local profile or a public capability alone. A captured profile and selection generation fences every native call. Device identity and pending enrollment/RPC bytes remain in their original profile; deleting unresolved profiles is refused. A pinned profile cannot be reassigned to a different Hub ID.

Network proof verification uses the exact v1.4 domains, full ML-KEM/ML-DSA public identity, canonical raw self-attestation, native Session commitment, complete manifest digest, current identity/revisions, externally signed Owner proof and explicit confirmation. Signed claims end with `"signature":null`. Manifest digest claims omit the Owner-only `native_session_id` and include `"digest":""`. Group bindings do not substitute for Network direct bindings. Fresh encrypted capabilities, topology and manifest are checked before sealing a grant. The fixed source lacks an external Network signing CLI, so the real positive Network grant remains BLOCKED; its published incomplete vector is tested for its precise bytes and is never accepted as a complete production preview.

Completed bounded gates: final APK build, 45 Kotlin tests, 23 JavaScript checks, offline connection UI, and fresh-device disposable fixed-image enrollment, encrypted capabilities, ACTIVE topology/selection and Network-scoped Group creation. An independent durable Network grant uncertainty fence rejects replacement writes and identity resets until dedicated reconciliation is implemented. Next gates: accept a separately pinned Core signer delivery and complete native fixture; then validate real Network consent, dedicated status correlation and rejection/recovery states. Native Node/Monitor delivery, physical devices, public HTTPS and additional platforms retain their own test status. Do not use historical PASS results or unpublished Core changes for the current target.

## Historical checkpoints

**Last updated:** 2026-09-27

This repository develops the mobile Client only. Android is the current target. The completed historical integration baseline was Hub commit `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`, contract `client-hub-v1.2.1`, protocol archive SHA-256 `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a`, catalog SHA-256 `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`, and full local image ID `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`. The [backend contract](backend-contract.md) describes the wire behavior; the [v1.2.1 validation report](client-hub-v1.2.1-967dbd-validation.md) records runtime evidence. Results for the earlier `41beaf0` image are historical only.

## Completed v1.3 Client emulator slice

The fixed target is clean Hub `be0269e80c41e94881d131bd4f4b233e80b6ffe6`,
contract `client-hub-v1.3`, catalog
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`,
archive `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9`,
image `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`.
The [dedicated plan and validation record](client-hub-v1.3-be0269e-validation.md)
tracks the ordered implementation and independent acceptance gates. The user flow
is exact local text → verified Monitor/recipient review → explicit confirmation
→ consent-bound sealing → bounded authoritative outcomes. Lost responses must
retain original request bytes and reconcile the same operation.

Implementation `9568b2ff6d4e156b70484c10b7fd5195405004b0` passed the scoped
emulator acceptance: 21 Kotlin checks, 13 JavaScript checks, independently
verified Group grants, actual product consent/status UI, genuine HTTP 200
response-loss recovery, bounded capacity, changed-text rejection and current
permission revocation before sealing. The runtime used synthetic authorization
Endpoints; native Monitor delivery and model consumption remain **NOT_RUN**.
The report records each APK and keeps earlier failures separate. The disposable
Hub/Node/proxy/emulator and private fixture material have been removed.

The v1.2.1 status below is historical; none of its Android or native PASS entries
certifies the new v1.3 target.

## Historical v1.2.1 status

| Area | State |
|---|---|
| Protocol package, manifest, image labels | **PASS** for the fixed target. The imported bundle records the exact commit, `source_dirty=false`, and catalog digest. |
| Android encrypted session | **PASS**. An independent Android session verified encrypted `session.capabilities` against the fixed Hub. |
| Android app/test build | **PASS** for the corrected artifacts listed in the validation report. TypeScript, lint, contract, and whitespace checks also exited 0. |
| Lost enrollment and RPC responses | **PASS**. Android retried the exact saved Owner Grant and recovered the exact RPC response on the fixed image. |
| Three recovery faults | **PASS** on a disposable `/tmp` Hub: `STILL_PROCESSING`, Hub restart after `FAULT_READY` yielding `OUTCOME_UNCERTAIN`, and `RECOVERY_UNAVAILABLE`. Android retained the original packet and did not create a second operation. |
| Endpoint attestation, synthetic manifest, and owner proof | **PASS** on corrected APK `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76`; `EndpointAttestationVectorTest` returned `OK (4 tests)`, ADB exit 0. The earlier `70423555…` candidate failed the valid four-digit RFC3339Nano timestamp case; commit `af3ad451e29d0c43142b3fc792272bbd6df75c84` fixes it. |
| Native Group preview/grant/status implementation | Implemented with external signed-proof import, explicit Android confirmation and a dedicated encrypted status read. The APK does not import the owner private key; it verifies against the owner public approval key saved from authenticated enrollment. The fixed-image live acceptance passed. |
| Positive Group grant against the fixed Hub | **PASS** on a disposable fixed-image Hub with a real native Codex Endpoint, external Owner signing, explicit Android confirmation, and encrypted `group.key_status=CURRENT`. The same grant became `STALE` after the native lease expired, then `PROOF_EXPIRED` after proof expiry. Exact artifacts and limits are in the [Group key acceptance report](client-group-key-v1.2.1-disposable-validation.md). |
| Real Node/Codex approval | **PASS** on the fixed image with E2E candidate APK `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197`: one original Codex turn was approved on the same native Thread/Worker attempt 1, Worker and Goal completed, Intent resolved, and `goal.result` matched 30 bytes. This does not validate Group grant or production TLS. |
| Physical Android device and public HTTPS | **NOT_RUN**. |

The full command and evidence record is in [the v1.2.1 validation report](client-hub-v1.2.1-967dbd-validation.md). An initial recovery-fixture attempt failed with HTTP 502 because the fixture was not run from `/tmp`; the corrected disposable-Hub runs passed and both results are recorded separately. The four-digit RFC3339Nano compatibility issue found in one candidate was fixed, rebuilt, and retested successfully.

## Product and model work

The app retains the five-page Android UI, a clear voice entry point, editable transcripts, and a text composer that works without a speech model. The model centre offers only models with a real format/runtime/device validation record. Model weights are optional, verified before installation, and kept in app-private storage. See [model selection](model-selection.md) and [speech validation](stt-validation.md) for model sources, licenses, command results, timings, and limitations. Host inference does not count as physical Android testing; microphone, memory, battery, and background-resume measurements on a physical device remain **NOT_RUN**.

State views distinguish Node connectivity, native session binding, Worker execution, Goal lifecycle, Intent dispatch, and Artifact references. They show authority, observation time, and stale state. Large lists load on demand. When the app is disconnected or unauthorized, it must not show development fixtures or claim that a message was sent, an approval was granted, a Goal completed, or a Thread connected.

## Remaining gates

1. Resolve the original native Session lease failure documented in the [joint Monitor attempt](client-monitor-v13-native-acceptance.md) before repeating Android-to-native delivery acceptance. No Group grant, positive Prepare or Confirm was submitted in that failed attempt. The separate [Prepare RPC recovery fault run](client-monitor-v13-recovery-faults.md) passed all three ledger-level recovery states; Confirm recovery faults and recovery after actual Monitor business execution remain untested. Preserve the completed v1.2.1 native Group trace and separate [two-Owner authorization acceptance](client-two-owner-v1.2.1-967dbd-validation.md); the latter used synthetic Endpoints and does not establish native messaging.
2. Preserve the completed fixed-image Node/Codex trace in the validation record. Any new Hub image or Client protocol change needs its own run; do not transfer results from historical `41beaf0` or the separate Group verifier artifact.
3. Test on a physical Android device: enrollment and Keystore boundary, foreground/background recovery, microphone capture, supported model download and inference, latency, memory, and battery. Mark each item `NOT_RUN` until measured.
4. Validate production-style public HTTPS, certificate checks, device network behavior, and recovery after network changes. Do not infer this from emulator-to-host HTTP.
5. Keep full status push, cross-user Thread routing, equipment migration/recovery, iOS, and native HarmonyOS as separate future gates. Native HarmonyOS requires an ArkUI/ArkTS app; the React Native TSX UI is not a native Ark application.

## Development and safety rules

- Develop, build, and test in Docker. Verify Docker data root `/gpu1-share/data/docker-root`; keep project cache, model downloads, APKs, test identities, and temporary Hub state under `/gpu1-share/data/cicada-client`. Do not alter `/gpu1-share/data/cicada` data or global Docker configuration.
- Work only in this Client repository. Treat the adjacent CICADA core as read-only. Use one-time disposable Hub state for integration tests; never inspect or edit its database from Android.
- Fixed dependencies use lock files. Do not put real API keys, long-lived bearer credentials, private keys, complete sensitive messages, audio recordings, or model-test personal audio in Git, APKs, snapshots, persistent caches, logs, or analytics.
- All user content and management operations use independently pinned Client-Control PQ encryption and encrypted `session.capabilities`. No old `/v1` bearer fallback. Every write uses server guards, expected versions, idempotency, and authoritative rereads after conflict or uncertain network outcome.
- A protocol package, public capability flag, Hub image tag, HTTP 200, or test fixture is not runtime proof. Record exact package, complete image ID, app artifact, command, exit code, outcome, and limits for each validation.
- Do not push, merge, publish, deploy production, rotate keys, or change global CLI/Docker configuration automatically.
