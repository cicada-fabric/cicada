# Client-Control v1.6.5 Link-policy status and restart validation

## Scope and current status

This is a separate eight-case Android instrumentation suite. Joint11's 82
requests and eight grant-recovery results remain historical and are not rerun.
The existing `LinkReviewPolicyStatusInteropTest` keeps its v1.6.1 attribution.
Production code, protocol, roles and models are unchanged. Root owns the
fresh Hub, emulator, synthetic identities, fault transport and cleanup.

The independently checked Core target is clean
`c2929fc3b66c5debf92230e1e052b8b0e35a9e80`, runtime image
`sha256:d69edf867632f1ac8adec83ecc689e5cdf9654505ccdd4eeb1ed489ec4e2e496`,
source fingerprint
`4c2f0d6ee0336b5237a6974180d791cd9277b9d72edbc2e79ca9ab7a17ec83ee`.
Contract and catalog remain
`client-hub-v1.6.5` and
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.
An independently supplied fixture hash and full source/image pins are required;
Hub discovery metadata alone cannot supply those pins.
The archive, OCI descriptor/blob chain, image labels, embedded web manifest,
contract payloads and 958 build inputs were checked read-only. Runtime receipt
`runtime-verification-c2929fc/receipt.NONAUTH.json` under the preparation root
has SHA-256 `e06e66c5f0363b85c0263e99d43c3e9fee1d2afd6409e487a1746c1c3ee606a2`.
No image was loaded and no Core code was executed. Only the bundled development
document differs from the previously imported contract; wire/vectors/API are
identical. Fresh identities, a compiled status fault helper and a Root-owned
online window still require Root delivery.

## Eight independent cases

Class: `ai.cicada.client.hub.LinkReviewPolicyStatusV165InteropTest`.
Each case has its own fresh run ID, fixed enrolled Owner/Device/profile,
selection generation, session epoch and Link ID/version. Fixtures and staged
receipts must not be reused between cases. KEY/NONE label the consent fixture
lane; the wire policy's mode remains `NONE` or `METADATA`.

| Case | Lane | Selector | Additional boundary |
| --- | --- | --- | --- |
| 0 | KEY | `keyStatusAcrossOwnedRestart` | Exact status before/after owned Hub restart |
| 1 | NONE | `noneStatusAcrossOwnedRestart` | Exact status before/after owned Hub restart |
| 2 | KEY | `keyOwnerRefusalsAcrossOwnedRestart` | Unknown and genuinely foreign Owner Link absent from encrypted Owner list; dedicated Client status flow refuses |
| 3 | NONE | `noneOwnerRefusalsAcrossOwnedRestart` | Same Owner-selection refusal boundaries |
| 4 | KEY | `keyVersionAndBypassRefusalsAcrossOwnedRestart` | Actual older positive Link version and generic RPC bypass refused |
| 5 | NONE | `noneVersionAndBypassRefusalsAcrossOwnedRestart` | Same version and bypass boundaries |
| 6 | KEY | `keyStatusResponseLossAcrossOwnedRestart` | Exact original status packet and durable read context survive reopen/restart and recover |
| 7 | NONE | `noneStatusResponseLossAcrossOwnedRestart` | Same original-packet recovery and unresolved-uncertainty retention |

All cases read encrypted `session.capabilities`, a fresh bounded/paginated
`link.list`, then the dedicated `link.review_policy_status`. They compare
complete policy metadata, including reviewer Endpoint/Group scope, version,
digest, current flag, accepted sides and optional exact expiry. The selected
Hub's full public identity/key version, Owner, Device, profile and epoch must
remain exact. No selector creates, activates or reselects a profile.

The unknown/foreign and stale-version refusals occur in the dedicated Client
flow after authenticated Link listing. They do not prove a direct Hub
foreign-Owner status rejection; that server Guard stays `NOT_RUN`. The
production status request is exactly `{link_id}`: no version or Owner request
field is invented. Generic status RPC is refused without counter/journal use.
Version-refusal fixtures require current Link version at least 2.

## Root fixture and launch contract

App-private directory: `no_backup/link-policy-status-v165/<run_id>`.
Run IDs match `v165-link-policy-status-[A-Za-z0-9_-]{1,64}`.
Root stages only public test-coordination files there. Device/Owner enrollment
and independent Hub pinning use existing authorized setup outside this suite;
no Owner private key, Node credential, device code or Hub bearer enters a file.

`fixture.public.json` has the exact schema enforced by
`LinkPolicyStatusFixtureV165`:

- Schema `cicada.client-v165-link-policy-status-fixture.v1`, `run_id`, `case_id`,
  `fixture_lane`, `scenario` (`restart`, `owner-refusal`, `version-bypass`,
  `response-loss`). Case/lane/scenario mapping is closed to the table above.
- `source_revision`, `source_fingerprint`, `hub_image_id`, `contract_revision`,
  `catalog_sha256` from the independently frozen Root delivery.
- `hub_id`, `owner_id`, `device_id`, `profile_id`, `profile_generation`,
  `session_epoch`, `control_public_identity`, `control_key_version`, `my_side`.
- `expected_status`: the exact sanitized public status DTO already supported
  by the Client, not a new server schema or signed authority.
- For Owner-refusal only: mandatory `foreign_link_id`, `foreign_owner_id`,
  independently established by Root as a genuinely foreign scope.
- For response-loss only: `recovery_result` is `COMPLETED` or
  `OUTCOME_UNCERTAIN`, matching the real isolated fault fixture.

Files are bounded and pinned by their actual byte hashes. The fixture parser
rejects duplicate JSON fields, unknown fields, old contract/catalog, wrong
matrix bindings, noncanonical numbers and incomplete public identities.

Every selector invocation requires `run_id`, `fixture_sha256`, the three
independent source/image values above, `phase`, and `case_deadline_utc`.
The single absolute case deadline is at most 360 seconds away and must not
be extended between phases. Root applies its outer process deadline/cleanup.

Normal cases run `phase=before_restart`, then Root restarts the exact owned
Hub, then the same selector runs `phase=after_restart`. The first phase's
JUnit success is only a stage result; full case PASS requires
`after.redacted.json`, exact baseline comparison and cleanup evidence.

Before the second phase, Root stages `restart.public.json`, independently
bound by instrumentation `restart_sha256`. Its exact fields are `schema`
(`cicada.client-v165-link-policy-status-owned-restart.v1`), `run_id`, `case_id`,
`fixture_sha256`, `status=PASS`, `hub_id_sha256`, `hub_container_id_sha256`,
`hub_image_id`, `source_revision`, `source_fingerprint`, `before_started_at`,
`after_started_at`. Root must separately record actual Docker commands/exits
and exact container ownership. Android checks the pinned receipt and observes
the encrypted state; it does not operate or independently inspect Docker.

Response-loss cases add `phase=capture_response_loss` before Root restart and
`phase=recover_after_restart` after it. A safe proxy must target only
`link.review_policy_status`, with
no fresh operation or re-dispatch on recovery. Root first stages
`fault.public.json`, bound by `fault_sha256`, with exact fields `schema`
(`cicada.client-v165-link-policy-status-fault.v1`), `run_id`, `case_id`,
`fixture_sha256`, `operation=link.review_policy_status`, `ready=true`,
`recovery_result`. The selector records only hashes/counters from the actual
App-private original packet and context. Root restarts the Hub after the real
fault-ready condition and the Android capture ACK below. The recovery phase
submits the same original packet to existing `/v2/client/rpc/recover`. It sends
no new RPC and does not read fresh status through the faulted proxy. Its
transport ACK is not a full-case PASS.

### External control order and ACK conditions

This is host test coordination through the existing phased selectors and
public receipts, not a Client/Hub API or a new Parent control protocol.
Root launches each selector in the same exact-owned emulator with
`am instrument -w -r -e class <class>#<method>`, the independent fixture/source
pins, phase and unchanged case deadline. The runner is
`ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner`. A host exit of
0 alone is insufficient: Root must inspect JUnit completion with no failures
or assumptions/skips, and the stage's actual receipt bytes.

| Order | Root action / Android stage | ACK before Root proceeds |
| --- | --- | --- |
| 1 | Fresh enrolled profile and exact current Link/policy; direct opaque carrier; `before_restart` | `before.redacted.json` is `BEFORE_RESTART_VERIFIED`, fixture/identity/policy match, JUnit succeeds. This is a baseline stage only. |
| 2 | Loss cases only: bind the status-only proxy to the same pinned App URL, verify the helper's actual READY/source/hash, stage the pinned `fault.public.json`; run `capture_response_loss` | The arming file is not FAULT_READY. The proxy must observe the original status packet and drop its response; Android must finish with `NETWORK_ERROR`, persist pending/current context and reserved counters, reopen the same profile, and publish `loss.redacted.json`. |
| 3 | Verify restart readiness, then restart only the exact owned Hub | For loss, **RESTART_ACK** means capture JUnit success plus `ORIGINAL_STATUS_PACKET_PENDING`; actual proxy FAULT_READY request SHA/sequence match the loss receipt, reserved response sequence matches where reported, operation is exactly status, and case/fixture/Owner/Device/carrier ownership are exact. No raw packet, context, grant or private state is exported. Normal cases use the baseline ACK. |
| 4 | Pin/stage the actual owned restart receipt. Loss cases: keep the proxy/original capture, run `recover_after_restart` | **RECOVER_ACK** means JUnit success plus `recovery.redacted.json=ORIGINAL_PACKET_RECOVERED`, exact original operation/packet hashes, unchanged next request sequence, authenticated reserved response sequence consumed, and correct uncertainty latch. This phase performs one original `/recover`, with no fresh operation/re-dispatch. |
| 5 | After RECOVER_ACK, route the same pinned App URL back to the direct Hub; invoke `after_restart` | This invocation is **CONTINUE**. No profile activation, reselection, generation change, new pin or URL mutation occurs. Android first checks the transport ACK and persisted counters/fences still match; only then does it perform fresh encrypted reads and any authorized uncertainty reconciliation. |
| 6 | Collect `after.redacted.json`, actual commands/exits and Root-owned cleanup | Full case PASS requires the Android post-stage result, exact baseline comparison and independently confirmed cleanup. Prior stage ACKs cannot substitute. |

The proxy currently closes the original HTTP connection immediately after
FAULT_READY. Capture can therefore complete before restart; there is no second
instrumentation instance, concurrent session reader or held-HTTP restart claim.
If a future fixture actually holds that connection, this sequence is not a
hold/release protocol and must not be assumed to work. On timeout, missing ACK,
hash/counter mismatch or selector failure, stop the case and retain its pending
state and evidence; no selector retries, replacement packets, extended deadline
or reset is authorized.

The existing proxy fences all new RPC after its first fault, even after original
recovery. Leaving it selected for `after_restart` would reject capabilities and
status. Root must therefore switch only the opaque transport route after the
recovery ACK, preserving the App's independently pinned origin and identity.

Current v1.6.5 dispatch persists `linkConsentStatusReadContext`, including
profile generation. `linkReviewStatusReadContext` is a distinct legacy path.
The suite checks the actual current context and pending operation/sequence
without replacing or resetting session storage. Both context keys clear only
after an authenticated terminal recovery. An authenticated `OUTCOME_UNCERTAIN`
must retain the original retired packet and uncertainty latch across reopen,
capabilities and Link listing. The dedicated status flow remains blocked.
Only an authorized encrypted `status.snapshot` may clear that existing latch,
followed by a fresh status read. If that reconciliation authority is absent,
the fixture stays `NOT_RUN` with the unresolved fence retained. Non-null legacy
context migration and physical Android process-death coverage are separate
`NOT_RUN` items; session reconstruction is not called process-death testing.
This modern lane requires the current context and its exact
`profile_generation`; it does not create a legacy value. The generic-bypass
journal comparison preserves each actual legacy value if present and otherwise
compares absence. Actual non-null legacy restart coverage remains `NOT_RUN`,
not PASS from an absent field.

## Fixture gaps and attribution

The previously compiled Core fault helper excluded status from its faulted
allowlist. Root is preparing a minimal test-only extension; its current source
supports exact completed response loss for status, not processing/uncertain/
legacy modes. That source alone is not a frozen compiled fixture. Root needs
to deliver its exact binary/source/receipt and fresh public setup before the
loss cases can run. `OUTCOME_UNCERTAIN` remains a separately guarded branch,
**NOT_RUN** without a suitable isolated fixture; completed response loss must
not be relabeled uncertain. Client must not guess a protocol, read a database,
inject production fault controls or fake encrypted responses. Missing fixture
or reconciliation authority results in a selector skip and case `NOT_RUN`.
Invalid supplied pins or scope fail closed; they are not skips.

The current Group instrumentation source also lacked A11's formal confirmation
shape. Its test call now sends preview `candidate_digest/candidate_version`
and reads `NodeControlKeyBinding.owner_binding_id`. Production already
validates that full binding. No Group grant test is rerun or newly claimed.

The existing TypeScript read button omits the uncertainty-latch guard, while
Native refuses the request with `BUSINESS_RECONCILIATION_REQUIRED`. This UI
mismatch is reported to Root; it is outside this test-only task and is not
silently changed.

All eight online cases, physical Android, Native/provider, public HTTPS and
iOS remain **NOT_RUN**. Offline preparation evidence is under
`/gpu1-share/data/cicada-client/v165-link-policy-status-preparation-20261012`.
The old APK producer `1151b06` and Joint11 tested host `3cfb3cf` retain their
original scope; changed test sources require a fresh APK producer record.

## Actual offline preparation

All stages use immutable builder
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
network `none`, server UID/GID and existing Client-only caches. Docker root
was read as `/gpu1-share/data/docker-root`. Commands below are invoked through
the evidence-root `run-offline.py`; receipts bind actual argv, dirty inputs,
elapsed time, log hashes, unchanged source and owned-container closure.

| Stage | Inner command | Exit | Result |
| --- | --- | --- | --- |
| `unit` | `gradle --offline --no-daemon -I /out/kotlin-host.init.gradle :app:testDebugUnitTest --tests ai.cicada.client.hub.LinkPolicyStatusFixtureV165Test` | `1` | Preserved **FAIL**, 7/8 tests; synthetic negative incorrectly treated a valid distinct reviewer as invalid |
| `unit-green` | Same scoped JVM command, with corrected duplicate-Endpoint negative | `0` | **PASS**, 8 tests, zero failures/errors/skips |
| `compile` | `gradle --offline --no-daemon :app:compileDebugAndroidTestKotlin` | `1` | Preserved **FAIL**, test called existing instance metadata method as a companion method |
| `compile-green` | Same Android Kotlin compile target, corrected receiver | `0` | **PASS**, compilation only; no Android test execution |

Both failures were in new test source, with no production guard relaxation.
No old JVM vectors, full Go suite, Joint11 batch or models were rerun. The
new clean APK producer and complete source hash are sealed after the combined
checkpoint; the runtime image tuple and safe loss fixture still require Root.

### Control-order successor

The successor separates original recovery from direct post-restart reads.
The two added JVM tests cover phase restriction and closed recovery-ACK
validation, including changed original hashes/counters, discarded uncertainty,
replacement operations, extra/missing fields and an invalid full-PASS label.
The baseline's case deadline is persisted and must remain unchanged in every
later invocation. Local refusals and unexecuted server Guards are recorded
separately; a completed response-loss run does not claim non-null uncertainty
coverage. No production code or old selector changes.

| Command, in the same immutable network-none builder | Exit | Actual result |
| --- | --- | --- |
| Scoped `:app:testDebugUnitTest --tests ai.cicada.client.hub.LinkPolicyStatusFixtureV165Test`, with external host-source init script | `0` | **PASS**, 10 tests, no failures/errors/skips; 35.5837 seconds |
| `:app:compileDebugAndroidTestKotlin` | `0` | **PASS**, compilation only; 29.7764 seconds |

Actual argv, tested input hashes, logs and container closure receipts are in
`/gpu1-share/data/cicada-client/v165-link-policy-status-control-preparation-20261012`.
The original eight-test preparation and both original failures remain in
their separate evidence root. A new clean test APK and its full producer
inventory are sealed in the successor `DELIVERY.NONAUTH.json`; it does not
replace the historical APKs or confer online authorization. All eight online
cases remain `NOT_RUN` until Root supplies the fresh scope and runs them.

### Authorized HEAD0 metadata correction

Root and an independent Core reviewer confirmed that a legally revoked Link
at version 2 may have an unconfigured policy head (`policy_version=0`) with
`current=false`. The fixed c292 Store derives that flag from current scope;
the wire/OpenAPI contract does not require it to be true. The earlier Client
validator wrongly rejected this metadata, including during public fixture
parsing. That static incompatibility is preserved in the cf069 audit receipt.

The successor removes only the unconditional `!current` rejection in the
HEAD0 branch of `LinkReviewPolicyStatusValidation`. It retains the boolean
type and exact Link scope checks, mode `NONE`, empty digest/reviewers/accepted
sides, zero policy limits and no expiry. A noncurrent DTO supplies no consent
or routing authority. There is no Grant, fabricated current flag, Core change
or new test phase.

Scoped tests add a legal revoked HEAD0 case, twelve malformed/type mutations,
and actual fixture-parser checks for both KEY/NONE lanes at Link version 2.
The before-fix RED run has 18 tests, two expected failures, exit 1 in 32.1306
seconds; the corrected GREEN run has 18 tests, zero failures/errors/skips,
exit 0 in 28.3776 seconds. Android-test Kotlin compilation exits 0 in 30.0820
seconds. All commands use the existing immutable network-none builder and
Client-only caches; full argv, source hashes and owned-container closure are
under `/gpu1-share/data/cicada-client/v165-link-policy-status-head0-preparation-20261012`.

One meaningful source checkpoint and a clean APK pair are sealed there in
`DELIVERY.NONAUTH.json`. New-source Android runtime remains `NOT_RUN`; Root
may separately use the immutable cf069 pair for cases 0/1, whose results keep
their own producer attribution. Subsequent cases using the corrected pair
must record that new producer, not inherit a prior APK result. Joint11,
the original failures, all cf069 artifacts and extra uncertainty `NOT_RUN`
scope are preserved. No model, online fixture or shared resource is started
by this Client preparation.
