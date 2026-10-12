# Client-Control v1.6.5 Link-policy status and restart validation

## Scope and current status

This is a separate eight-case Android instrumentation suite. Joint11's 82
requests and eight grant-recovery results remain historical and are not rerun.
The existing `LinkReviewPolicyStatusInteropTest` keeps its v1.6.1 attribution.
Production code, protocol, roles and models are unchanged. Root owns the
fresh Hub, emulator, synthetic identities, fault transport and cleanup.

Core target proposed by Root is clean
`c2929fc3b66c5debf92230e1e052b8b0e35a9e80`; exact image, build metadata and
source fingerprint are pending Root delivery. Contract and catalog remain
`client-hub-v1.6.5` and
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.
An independently supplied fixture hash and full source/image pins are required;
Hub discovery metadata alone cannot supply those pins.

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

Response-loss cases add `phase=capture_response_loss` between baseline and
Root restart. A safe proxy must target only `link.review_policy_status`, with
no fresh operation or re-dispatch on recovery. Root first stages
`fault.public.json`, bound by `fault_sha256`, with exact fields `schema`
(`cicada.client-v165-link-policy-status-fault.v1`), `run_id`, `case_id`,
`fixture_sha256`, `operation=link.review_policy_status`, `ready=true`,
`recovery_result`. The selector records only hashes/counters from the actual
App-private original packet and context. Root restarts the Hub after its real
fault-ready condition, then the post phase submits the same original packet
to existing `/v2/client/rpc/recover`.

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

## Fixture gaps and attribution

The existing Core `client-recovery-fixture/link_proxy.go` faulted-operation
allowlist excludes `link.review_policy_status`. Its normal read allowance is
not a usable status-loss/uncertain fault fixture. Root needs a safe test-only
driver for these cases; Client must not guess a protocol, read a database,
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
