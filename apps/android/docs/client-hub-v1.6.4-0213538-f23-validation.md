# Client-Control v1.6.4: F20–F23 validation and historical-result correction

## Fixed target and artifact attribution

| Input | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0`; clean |
| Contract / wire / schema / operation count | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Protocol archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7`; `source_dirty=false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Android emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| F20–F23 Client/APK source | `406d8d7bd66ef344d0ef184c1f86c3a2165dd011` |
| F20–F23 App APK SHA-256 | `282d07c0676b747b7a710494e49bace5492970c464a176ef42ca3b30091b6acc` |
| F20–F23 instrumentation APK SHA-256 | `eeb433d5085643076f81ac76ec2e7249fc72bfa4dd6855f3d8911d6738050689` |
| Core `accepted_at` contract clarification | `R23/evidence/attempt-08/accepted-at-contract-clarification.redacted.json` — SHA-256 `128bad5a33028cce13e64a2fc9275b36685daec5b3c3722ef2d5271ac5707b50` |
| Final cached focused Kotlin receipt | `KF/kotlin-host.receipt.redacted.json` — SHA-256 `3a9c7de5acf50ffd3da7ea17d0d66143396a49d91463b1aec0093feab912283a` |

The F20–F23 APK pair was assembled once, exit `0`. The build receipt
binds the complete tracked source inventory before and after assembly. Its
23 focused host Kotlin tests passed, exit `0`. These results belong to
`406d8d7`; F19 used a different diagnostic pair and remains
[historical evidence](client-hub-v1.6.4-0213538-f19-validation.md).

## Actual run results

| Gate | F20 | F21 | F22 | F23 |
|---|---|---|---|---|
| Android BOOT/install/properties/preflight | PASS | PASS | PASS | PASS |
| Prepare / bind / hot preflight | FAIL / NOT_RUN / NOT_RUN | PASS / PASS / FAIL | PASS / PASS / PASS | PASS / PASS / PASS |
| SOURCE enrollment and encrypted capabilities | NOT_RUN | NOT_RUN | PASS | PASS |
| Independent Owner pins and fresh manifest | NOT_RUN | NOT_RUN | PASS | PASS |
| SOURCE KEY submit and fresh side-status verification | NOT_RUN | NOT_RUN | BLOCKED: incomplete receipt | PASS |
| SOURCE NONE external proof preparation | NOT_RUN | NOT_RUN | NOT_RUN | PASS |
| SOURCE NONE submit/result/status verification | NOT_RUN | NOT_RUN | NOT_RUN | FAIL |
| TARGET enrollment, RN confirmation, KEY and NONE | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN |
| Bilateral KEY/NONE acceptance | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN |
| Android/carrier owned cleanup | PASS | PASS | PASS | PASS |
| Core actor exit and owned Hub/network cleanup | PASS | PASS | PASS | PASS |
| Actual coordinator terminal ACK | PASS | NOT_RUN | NOT_RUN | PASS |
| Native Codex, physical Android, public HTTPS | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN |

F20 stopped at prepare: the command used old F19 Scope/GO paths. F21 stopped at
hot preflight: a global fixture-name substitution in the original template had
also mutated characters inside the consumer digest. The real frozen source
was unchanged. Neither attempt executed encrypted business operations.

F22 started its flow at `12:08:31.341523Z` with only 28.666 seconds remaining.
Fifteen commands completed with exit `0`, including SOURCE registration,
capabilities, pins, manifest, external KEY signing and native proof staging.
The original pending phase remained `source-key`, `PROOF_READY_FOR_NATIVE_STAGE`.
No KEY submit/status completion receipt was available. The launcher timed out
at the original cutoff, preserved pending and exited `1`. Its actual flow exit
was `-15`. Core cleanup was `DEADLINE`; a later ACK preguard exited `1`, and the
coordinator ACK was never called. F21 has the same ACK distinction. These ACKs
are **NOT_RUN**, with their failed outer guards retained.

F23 had approximately ten minutes remaining when execution began. Its SOURCE
KEY submission and fresh side-status verification passed on the correction
APK. This establishes SOURCE proof acceptance only; TARGET remained missing.
Command 24, `submitsHostSignedPolicyProofAndRevalidatesFreshV164Status`, exited
`1` at `12:18:36.352828Z`. Its first failed assertion was `sent.ok == true`.
The original JUnit error was `Hub did not return a terminal
OwnerLinkReviewPolicy grant response`; it discarded the returned typed code.
The actual cause remains **UNKNOWN**. The run was not an outer timeout.

The F23 terminal at `12:18:37.793656Z` recorded exit `1` and
`OUTCOME_UNKNOWN_PRESERVE_PENDING`. Core immediately sent exact actor SIGTERM,
collected the held process exit `143`, called the coordinator ACK once with
exit `0`, and completed `TERMINAL_ACK` cleanup. Client independently checked
the public closure bytes. Core attested three SOURCE signatures and zero TARGET
signatures. Signing does not establish Hub acceptance. No request was retried.

These fixtures declare `SYNTHETIC_PROTOCOL_ONLY`; their Owner actors make zero
model calls. They do not demonstrate a native Codex Worker. Historical N4/N5,
Group, Worker and native-session results retain their own versions and APKs.

## Historical-result implementation correction

Independent Client and Core source review confirmed that first-side policy
authorization may succeed with `current=false`, SOURCE verified, TARGET missing
and no active-head advance. This must remain distinct from bilateral consent.

`verifyHistoricalLinkPolicyGrantResult` still rejected `verified_at >
Instant.now()`, despite the fixed contract defining this timestamp as Hub
transaction snapshot metadata. It also compared Go RFC3339Nano text with Java
`Instant.toString()` instead of using the existing canonical Go parser. These
are independently identified implementation defects; neither is proven as the
actual F23 trigger because the original test hid the returned reason.

Core's R23 clarification also confirms that `accepted_at` and `verified_at`
share the Hub clock. KEY/POLICY evidence requires `accepted_at <= verified_at`
and the already verified Owner proof requires
`issued_at <= accepted_at < expires_at`; `accepted_at` is not compared with
Android `now`. Canonical UTC parsing, full Owner pins and signatures, local
proof-window checks for fresh validation, historical proof-window checks at
the authenticated snapshot, lease bounds, and operation fences remain enforced.

The historical response now uses the pure production
`validateHistoricalGrantResult` path. It parses the canonical timestamp once
and validates the original signed proofs and Link at that authenticated
transaction time. Exact original packet, operation, sequence, fence, tuple,
Owner pins, policy, lifecycle, proof digest and completion checks remain in the
session. Historical completion does not authorize a new request or establish
fresh status. Fresh validation and new signing still use local proof and lease
validity. First-side partial results remain noncurrent.

The Android test now reports only two fixed Client outcome codes or `UNKNOWN`,
plus strictly typed original-completion/reconciliation flags. It does not print
response payloads, identifiers, proof material or arbitrary server text.

The final cached pinned Docker regression passed **29 tests**, exit `0`, from
`12:55:37Z` to `12:56:12Z`: nine KEY, fourteen fresh policy-evidence and six
historical-result tests. The unchanged tested source bytes and fresh JUnit
reports are bound in `KF/kotlin-host.receipt.redacted.json`, SHA-256
`3a9c7de5acf50ffd3da7ea17d0d66143396a49d91463b1aec0093feab912283a`. It
covers canonical Go fractions, accepted-at Hub-clock bounds, original
signatures, proof issue/expiry, wrong pins, local proof and lease checks, and
partial results that remain noncurrent. This is a host test, not Android live
acceptance. The earlier `8af21cc` and `K24/app23ce/test95bf/be83` build snapshot
is immutable historical evidence, superseded by this receipt, and is not live
validation or the final corrected APK pair.

At this source checkpoint, final assembly is pending. Its post-commit receipt
at `KF/apk-build.receipt.redacted.json` will bind the clean commit, command,
exit and both APK SHA-256 values when completed. Live acceptance remains
**NOT_RUN**. F23 PASS results remain attributed only to Client `406d8d7` and
its listed APK pair; they do not transfer to the corrected artifacts.

## Commands, exits and immutable evidence

Cache aliases:

- `K20=/gpu1-share/data/cicada-client/v164-f20-snapshot-metadata-20261003`
- `K24=/gpu1-share/data/cicada-client/v164-policy-terminal-correction-20261003`
- `KF=/gpu1-share/data/cicada-client/v164-link-metadata-final-20261003`
- `R23=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-23-clean021-20261003`
- `Lnn=/gpu1-share/data/cicada-client/v164-fnn-0213538-launcher-20261003`

| Evidence | Path | SHA-256 |
|---|---|---|
| Original clean APK assembly, command and exit | `K20/apk-build.receipt.redacted.json` | `633a1c01c1234b922863688d3497d036ec7761166219cd498fb1d34f45f1fc1a` |
| Original 23 Kotlin tests, command and exit | `K20/kotlin-host.receipt.redacted.json` | `42c819795ad3e884b4627f506dae886fbbe3352d92e3c74c30b393054d652b46` |
| Frozen 26-source map | `K20/source-inputs.F20.frozen.json` | `c5496c2e93e0cb7b038e55fa97d25d38091492ffa973044d61a3703709b4a310` |
| F20 commands, exits, cause and closure | `K20/f20-terminal-diagnosis.redacted.json` | `deae622cf1f2f2f4bbc726d86dcad5a6569b8cbb2e9a83aa55d25f97bfd8cbc6` |
| F21 commands, exits, cause and closure | `K20/f21-terminal-diagnosis.redacted.json` | `3fbd074dbc299744c2434f1d6727f6059f7a4752e6e2a22566d73d7f8b776674` |
| F22 commands, exits, completed stages and pending | `K20/f22-readonly-phase.redacted.json` | `9cc95030d2e1ae0e64ee29d7205bce545e057628381c6637619dc7898419484d` |
| F23 commands, exits, native error, pending and actual Core closure | `K24/f23-terminal-diagnosis.redacted.json` | `35e8e05d38f665f2c5d1b9f0e1c711369e55d2d2b1b32fffee8ad14058090995` |

The records retain each exact command/exit, Root BOOT/business approval,
source/APK attribution and original evidence paths. The F22 Core closure index
is `805f43095bfc7bfc36a1777b694a1dca3eecb12bf73ab3231ebc98e8673618d3`;
F23 Core closure is `62ffae9281477f9e16749d0eb97e7d94c6b780855d674fd3608631e1113f01ca`.
Owner private keys and Hub/Node credentials remain outside Client, Git and APKs.

## Coordination prompt

```text
Read the F20–F23 record and immutable receipts. Preserve F23 SOURCE KEY PASS on
406d8d7/app282d/testeeb4 and SOURCE NONE FAIL with unknown typed cause. The
final 29-test host receipt is `KF/kotlin-host.receipt.redacted.json`; the
corrected commit and APK pair remain pending `KF/apk-build.receipt.redacted.json`.
Do not treat the immutable `8af21cc`/K24 artifact snapshot as live or final, and
do not attribute old runtime outcomes to a replacement APK. Keep clean
Core0213538/full images/current contract, independent Owner pins and strict
original proof/tuple/fence guards.

Root approves one new BOOT and one business frame. Core owns external signing,
actual actor stop/wait, one terminal ACK and owned cleanup. Derive every digest
from the actual frozen reference; assign paths/IDs/deadlines explicitly and use
canonical public/Root-GO.json. Allow at least 360 seconds remaining before the
frame: this is an estimate from the existing 300-second flow bound plus 60
seconds cleanup/ACK, not a measured full-flow minimum. Signed-proof validity and
original deadlines must not be extended. Do not replay old pending operations.
Report SOURCE partial acceptance and actual TARGET RN confirmation separately;
bilateral policy is successful only after both original proofs verify. Report
the next sanitized typed outcome without payloads. Native Codex, physical
Android and public HTTPS remain NOT_RUN until their own actual tests.
```
