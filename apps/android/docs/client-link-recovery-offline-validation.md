# Link consent recovery: offline Client validation

## Scope and attribution

This checkpoint repairs and verifies the Client recovery test and its receipt
consumer. It changes Android instrumentation and the private interoperability
driver only. It does not change application UI, transport, cryptography,
authorization, the Hub contract or feature permissions.

The Client parent is `e761722f1a642fbc9647837ea60c8a0b6b08901d` on
`dev/react-native`. Exact checked source hashes are recorded in the receipts
below. The committed checkpoint and source inventory are bound after commit by
`Q/commit-delivery.receipt.redacted.json`. No APK was built or installed for
this checkpoint; its APK SHA-256 is **NOT_RUN**. The accepted F38 app/test pair
remains attributed to `caa9e4c`, as documented in the [F38 report](client-hub-v1.6.4-0213538-f38-validation.md).

The intended next online target remains the following previously verified clean
delivery. These values are not a claim that this checkpoint ran against a Hub.

| Input | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Protocol | `client-hub-v1.6.4`, wire `1`, schema `57`, catalog operations `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Offline build image ID | `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` |

## Correction and acceptance criteria

`recoverLinkConsent` removes the operation ID from its summary when the native
durable fence is cleared. The previous selector required that ID even after
successful original-packet recovery, making its PASS branch unreachable.

The corrected selector captures bounded app-private state under the existing
session lock. It checks the explicitly selected profile, Hub, Owner, device,
Link/version against the stored authority tuple and the catalog against the
validated encrypted session. A Link contract digest is distinct from the RPC
catalog digest. It independently
compares the saved packet's route, exact bytes and SHA-256 with the pending
request and write fence, including the persisted request and expected response
sequences and original proof hash. It does not read a Hub database or device
private-key file, export proof/packet bytes, or allocate another request.

A resolved result may omit `operationId`. If supplied, it must match the saved
original ID. Completion also requires an unchanged next request sequence,
exactly the persisted original response sequence, no pending packet or business
fence, no unresolved uncertainty, no recovery/authentication block, and a strict
`reconciliationRequired=false` native summary. Pending results retain the full
original pending packet and fence; uncertain results must retain the same
retired packet and business fence. Mutated bytes, counters, context or summaries
fail the test. Existing active-profile generation checks remain in force; the
original packet is not rebound to a newly generated request.

The Python consumer requires a strict redacted receipt with a SOURCE or TARGET
phase, canonical decimal Long sequence strings, equal expected/observed response
sequences, and verified packet context. It rejects unexpected fields and any
business acceptance claim. A completed authenticated transport response can
reject a grant; fresh KEY/policy status is a separate acceptance gate.

## Executed offline checks

`Q=/gpu1-share/data/cicada-client/v164-link-recovery-offline-20261004`

Docker data root was verified as `/gpu1-share/data/docker-root`. Both checks
used the immutable image above, `--pull=never --network=none`, read-only source
and cache mounts, and user `1000:1000`. No credentials, signer, resident Hub,
model, dependency download or APK build was used.

| Check | Command | Exit | Result |
|---|---|---|---|
| Synthetic Kotlin state recovery | Cached `org.jetbrains.kotlin.cli.jvm.K2JVMCompiler`, then `java ... ai.cicada.client.hub.LinkConsentRecoveryEvidenceRegressionKt` | Compile `0`, runtime `0` | **PASS**, 3 groups |
| Changed Android selector compilation | Cached compiler, changed selector/helper, Android 36 SDK and immutable prior app classes | `0` | **PASS**, compile only |
| Strict recovery receipt regressions | `python3 -m unittest discover -s scripts/interop -p test_v164_link_recovery_receipt.py -v` | `0` | **PASS**, 6 tests |

Exact Docker/compiler argument arrays, source hashes, elapsed times and private
log hashes are retained in these final receipts; every checked source remained
unchanged during execution:

| Evidence | SHA-256 |
|---|---|
| `Q/review-final/kotlin.receipt.redacted.json` | `3cae0f53eecdc69ff5e2cf78f759c9d4745016b7c15dc21d4c9753ef1af839a2` |
| `Q/review-final/output/compile.receipt.redacted.json` | `d15b88fa4852e2dd5611072e94a27228a48d5b10ee37a4fff12999218e10e879` |
| `Q/review-final/python.receipt.redacted.json` | `ef9b7f6611cac726b41e5aca579221d15ec7216964620ce3669166b0227aea6e` |

Earlier receipts remain at `Q` and `Q/final` as intermediate evidence. Review
found a synthetic Python phase mismatch and a selector comparison between the
Link contract digest and the RPC catalog digest. The consumer now uses actual
SOURCE/TARGET phases, and the selector compares the catalog only with validated
encrypted session metadata. The final checks above were rerun after both
corrections. Intermediate receipts are not final-source acceptance. Kotlin
checks are synthetic state checks, not independent Hub cryptographic or online
fault acceptance.

## Online gates and required Core handoff

| Gate for this checkpoint | Result | Required next evidence |
|---|---|---|
| Lost KEY / NONE response and cached original ciphertext recovery | **NOT_RUN** | Core-owned current-image response-loss entrypoint after a real grant handler response |
| `409 STILL_PROCESSING` | **NOT_RUN** | Declared isolated fault driver; unchanged original packet/counters, write denial |
| Encrypted `OUTCOME_UNCERTAIN` after restart | **NOT_RUN** | Independent session, `FAULT_READY` before owned restart, retained business fence and later exact authoritative reconciliation |
| `409 RECOVERY_UNAVAILABLE` | **NOT_RUN** | Isolated original packet remains fenced; no replacement operation |
| Safe current-image Link fault fixture | **BLOCKED** | Core has not delivered a compatible entrypoint for this joint run |
| New APK / emulator execution, process-death recovery | **NOT_RUN** | One coordinated build/install and fresh Root-owned run |
| Real native Worker, physical Android, public HTTPS | **NOT_RUN** | Separately scoped runtime/device/HTTPS acceptance |

The older Core loopback fault proxy and companion fixture seed only outer RPC
recovery records. They do not execute the Link handler or prove a committed
grant, duplicate-effect prevention, or fresh bilateral business status. Their
older-version results cannot be transferred to this clean target. Client does
not run their database producer or add production fault switches. Root deferred
a fresh frame/Owner scope until the final clean Hub artifacts and a safe fixture
are delivered. Ordinary messaging remains disabled with
`external_thread_links=false`; F38 and prior failed/unknown operations are
preserved without replay.

### Core coordination prompt

> Review this offline checkpoint and its commit delivery receipt. Provide a
> Core-owned, version-pinned disposable fault entrypoint with opaque original
> packet transport and redacted request/response digests; Client must not access
> a Hub database or signing key. Distinguish committed Link response loss from
> synthetic outer-RPC recovery records. Coordinate independent sessions for
> processing, uncertain and unavailable outcomes, with FAULT_READY before the
> uncertain restart. Require original operation/sequence retention and separate
> fresh KEY/NONE reconciliation. Build/install one exact Client APK pair only
> after the clean Hub and Root-owned window are ready. Keep online gates NOT_RUN
> until actual evidence exists; do not transfer F38 or old fixture results.
