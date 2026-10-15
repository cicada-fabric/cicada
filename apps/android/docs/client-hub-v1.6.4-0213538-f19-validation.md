# Client-Control v1.6.4: F19 diagnosis and snapshot-time correction

## Fixed integration target

| Input | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Contract archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Clean source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7`; `source_dirty=false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Android emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |

This record separates the actual F19 diagnostic APK from the subsequent source
correction. Earlier Group, Worker, N4/N5 and F17/F18 results retain their original
source and APK attribution.

## Actual F19 Android attempt

Client/APK source was clean commit
`d16875bd1d0bb8380808fe95717199dc00de5279`.

| Artifact | SHA-256 |
|---|---|
| App APK | `7aaab553686a478cd35071af494195ba8fb625d085286526eeb4636a59fbf226` |
| Instrumentation APK | `0fe21d0cc899f440dc9129ff8447b7051a91391cfa8af24ae218980e370c209b` |
| Build receipt | `62f89c565881bff1f908f62b9e8d86b219b4ab4abebc650b855059334023bc1e` |
| Frozen 26-source manifest | `c86011cb1e6f6bcdc30ec5d405f254ed65be032332ea9a5ba4a2cf3f4ba1754f` |
| Docker dependency and plan check | `c5103491e75b2087e39e41b6377241e0ebe43c612b420569e9e63edcebd52870` |

Ten necessary APK consumers and their reachable dependencies were derived;
sixteen dependencies retained their original bytes. The read-only Docker check
passed with exit `0`. It loaded the actual new runner, context, binder,
coordinator, consent adapter and carrier, rejected the old runner, and checked
the Source-three/Target-three order. It did not execute business operations.

Main Root delivered one business frame on its retained launcher stdin. The
actual run was `v16-deterministic-v164-f6-f19-0213538-main-20261003`, with a fixed
business cutoff of `2026-10-03T10:51:29Z`. The first fifteen flow commands exited
`0`. Command sixteen, the SOURCE selector
`submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus`, exited `1` at
`2026-10-03T10:45:10.912656Z`.

The original JUnit log records
`LOCAL_LINK_OWNER_GRANT_VERIFICATION:VERIFIED_AT_IN_FUTURE`. The native code
verified the original externally signed proof before submission and observed
Hub `ok=true`; the subsequent fresh retained-status verification rejected
`evidence.verified_at`. The local comparison time was sampled **after** the
authenticated status RPC. The actual Hub/Android time difference remains
**UNKNOWN**. The independent read-only clock probe exited `127` and produced no
validated Android UTC; no clock change was performed.

| Gate | F19 result |
|---|---|
| New diagnostic APK build; eight host Kotlin tests | PASS |
| Android bootstrap, installation, four properties and preflight | PASS |
| SOURCE device enrollment and encrypted capabilities | PASS |
| Independent Owner pins and manifest review | PASS |
| Original SOURCE proof: native pre-submit verification and Hub acceptance | PASS |
| Fresh SOURCE retained-key status verification | FAIL |
| SOURCE NONE; TARGET enrollment, actual RN KEY Alert and NONE | NOT_RUN |
| Bilateral KEY/NONE acceptance | FAIL |
| Physical Android; public HTTPS | NOT_RUN |

The launcher terminal was written at `10:45:12.235529Z`, exit `1`, with
`OUTCOME_UNKNOWN_PRESERVE_PENDING`. The original local pending phase remains
`source-key`, `PROOF_READY_FOR_NATIVE_STAGE`. Flow and carrier were stopped and
waited; owned emulator cleanup passed. Core separately attested exact actor
SIGTERM/wait `143`, one terminal ACK with exit `0`, `TERMINAL_ACK` cleanup, and
owned Hub/network removal. Client independently checked the public ACK and
cleanup receipt bytes. No request or proof was retried.

## Contract-consistent source correction

Fixed Core wire sections “Client Link proof evidence” and “Review policy
evidence and freshness” define `verified_at` as the Hub's transaction snapshot
metadata. Core explicitly confirmed that this contract does not require it to
precede the Android clock and defines no cross-clock tolerance. It cannot serve
as offline authorization or replace a fresh encrypted read.

The correction removes only that extra comparison in the KEY side/bilateral
verifiers and review-policy preview/status parsers. Canonical timestamps,
shared KEY snapshot, authenticated response provenance, exact Link/Owner/
version/digests, independent full keys, complete signatures, reviewer binding
and lease constraints, and Link/maximum-proof expiry guards remain checked.
Signed proof validity still uses local `issued_at <= now < expires_at`.

The focused Docker regression passed **23 tests**, exit `0`: nine KEY tests and
fourteen policy-evidence tests, with fresh JUnit reports and unchanged tested
source bytes. Tests use the original public signed proofs: future Hub snapshot
metadata is accepted, future-issued or expired proofs are rejected, and expired
reviewer leases, mismatched snapshots, noncanonical timestamps, incorrect pins
and tampering remain rejected.

The command was the pinned Docker image below running offline Gradle:

```text
gradle --offline --no-daemon --project-dir /workspace/android
  -I /out/kotlin-host.init.gradle :app:testDebugUnitTest
  --tests ai.cicada.client.hub.LinkKeyManifestVerifierTest
  --tests ai.cicada.client.hub.LinkReviewPolicyEvidenceV164Test
  -PreactNativeArchitectures=x86_64 --stacktrace
```

Build/test image:
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
Replacement APK build and fresh live acceptance are **NOT_RUN at this source
checkpoint**. The post-commit private build receipt will identify the clean
correction commit and new APK pair. F19 does not certify those replacement APKs.

## Evidence references

Private cache aliases used below:

- `K19=/gpu1-share/data/cicada-client/v164-f19-diagnostic-20261003`
- `K20=/gpu1-share/data/cicada-client/v164-f20-snapshot-metadata-20261003`
- `L19=/gpu1-share/data/cicada-client/v164-f19-0213538-launcher-20261003`
- `E19=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f19-0213538-main-20261003/android`

| Evidence | Path | SHA-256 |
|---|---|---|
| Actual commands, exits, gates, pending and Core closure | `K19/f19-terminal-diagnosis.redacted.json` | `caef55af50c5f08cd8f2f96fa21f936e5a73273df22af5ee620b22828d71b729` |
| Root BOOT plan | `K19/bootstrap.F19.Root-approved.private.json` | `77dd2abebd6cacb452c9e18604be561922cb4a4f15ead6fe5291ca7ccac29315` |
| Root business plan | `K19/business.F19.Root-approved.private.json` | `5e66ff5fec9cfa181d141bad672a55d29a79dabbde228d72f119049dc37c24a5` |
| Original launcher terminal | `L19/terminal.private.json` | `e50a0223b77bcfe01b2150c10810165735871c00fda5a7aca2dbff26da78bfb3` |
| Exact native failure | `E19/link-v164-v164-f6-f19-0213538-main-20261003-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus.private.log` | `215877c444d49d431104a0f06042391b2651068a85e06d459d7262f69f3d18b9` |
| Correction: 23 host Kotlin tests | `K20/kotlin-host.receipt.redacted.json` | `42c819795ad3e884b4627f506dae886fbbe3352d92e3c74c30b393054d652b46` |

The first evidence file contains every actual command and exit code, the public
Core closure receipt paths/hashes, and the separate APK origins. Synthetic
Owner private keys and Node/Hub credentials remain outside Client, Git and APKs.

## Coordination prompt

```text
Read the F19 record and accompanying immutable private receipts. Preserve the
diagnostic d16875 APK result: VERIFIED_AT_IN_FUTURE, pending preserved, owned
cleanup complete. Verify the clean correction commit and its separately built
APK pair. The 23 host tests establish the snapshot/proof distinction; they do
not establish live bilateral acceptance. Keep clean Core 0213538, full image
IDs, six consent slots and Source-three/Target-three order. Main Root supplies
fresh BOOT/Scope/GO and one business frame; Core owns signing and terminal ACK.
Use the existing absolute adb path for one read-only UTC observation, preserving
host brackets, without setting the clock or changing signed-proof validity.
Record each actual Android gate. Physical Android and public HTTPS remain
NOT_RUN. Do not reuse F19's proof, pending packet, Scope or GO.
```
