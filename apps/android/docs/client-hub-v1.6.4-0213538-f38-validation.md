# Client-Control v1.6.4: F38 bounded Link consent validation

## Attribution

This record covers one Root-authorized disposable Android/Hub protocol fixture.
It applies only to the following source and installed APK pair. It does not
change the F35, F36 or F37 failed runs or their preserved unknown outcomes.

| Input | Verified value |
|---|---|
| Client commit | `caa9e4c725a841a1ce8488fbf339ca554d2939ed` |
| Clean Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / catalog operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Core source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7`; `source_dirty=false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Installed app APK | `f742532d7782e5a46f5364dc57f1dc6be6faf7903e09194d9db6028356b0a796`; 89,627,704 bytes |
| Installed test APK | `e538fbaa0eef457cb15aa885534317efc8b3df7b3b6dd7703c3112ceaa21e258`; 1,685,385 bytes |
| Runtime | Android 15 emulator, API 35, x86_64 |

Evidence aliases, all outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f38-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f38-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f38-0213538-main-20261004/outbox`
- `W=/gpu1-share/data/cicada-client/v164-f37-key-status-viewport-20261004`

## Result and acceptance boundary

The actual launcher records `FLOW_EXITED_ZERO`. The bounded Android flow records
all six phases completed: SOURCE device enrollment, KEY and NONE; TARGET device
enrollment, real React Native KEY confirmation and NONE. The Target UI receipt
records SOURCE `ACCEPTED`, TARGET `ACCEPTED`, and `bilateral_verified=true`.
Its Android Alert title, scope and positive action were checked through emulator
accessibility automation; human and physical-phone confirmation were not observed.
Instrumentation did not directly call a Native Session method.

Root independently closed this run. The coordinator's final state is `DONE`,
with all six phases complete and `pending=null`; this is coordinator metadata,
not a read of Android's private pending packet. All 13 Android JUnit tests passed with zero
failures or skips; the real React Native Target test passed in 13.76 seconds.
Six external fixture signatures were recorded once: three SOURCE and three
TARGET. Final NONE policy version `1` is current, both sides are `VERIFIED`,
and bilateral verification passed. SOURCE's earlier partial NONE result is
separate from this final bilateral result.

| Gate | Result |
|---|---|
| Exact installed APK and fixed-target attribution | **PASS** |
| Target real UI confirmation and fresh bilateral KEY status | **PASS**, scoped to the emulator protocol fixture |
| Final bilateral NONE status and 13-test JUnit summary | **PASS** |
| Root independent six-signature / Core cleanup closure | **PASS**, `OWNED_CLEANED` and owned-resource/private-path absence verified |
| Android teardown and emulator absence | **PASS** |
| Native Node/Codex Worker, human phone confirmation, physical Android, public HTTPS | **NOT_RUN** |

The five dedicated operations under review are `link.key_manifest`,
`link.key_grants`, `link.key_grant`, `link.review_policy_preview`, and
`link.review_policy_grant`. Fresh NONE status also uses the existing
`link.review_policy_status` read. Root approved the five-operation milestone
only for this fixed emulator consent/review path. The existing TypeScript and
Kotlin readiness flags were already enabled in the tested source; no additional
runtime switch or RPC permission is required. Fresh encrypted Owner capability,
independent pins, complete current proof verification and the server Guard
remain mandatory. Generic RPC continues to reject all five dedicated operations.
`external_thread_links=false` continues to prohibit ordinary
cross-user messages. Protocol-fixture consent does not prove message delivery,
model consumption, a real native Worker or production readiness.
Current Core development and restore changes are outside the tested image.

## Execution record

Exact arguments and exit codes remain in `L/command-journal.private.jsonl`;
its SHA-256 is `254bd4e5721f15b87553492177e23b81788386c1e2e911188f7a75d942544c10`.
Arguments and signing payloads are not copied into Git. These commands are
historical execution evidence, not authorization to replay their writes.

| Recorded stage | Executed Python program | Exit |
|---|---|---|
| Bootstrap | `v164-acceptance-boot.py` | `0` |
| Bootstrap preflight | `v164-link-consent-android.py` | `0` |
| Prepare | `f20-client-coordinator.private.py` | `0` |
| Bind | `f20-bind-boot-artifacts.private.py` | `0` |
| Carrier | `v164-link-fixture-carrier.private.py` | `0` |
| Hot preflight | `v164-acceptance-hot.py` | `0` |
| Business flow | `f20-root-flow.private.py` | `0`, 100.674 seconds |
| Emulator stop | `v164-android-deterministic.py` | `0` |

After closure, the existing capability/operation-policy regressions were rerun
in the cached Docker build image, with `--pull=never --network=none` and read-only
source mounts: `node --test tests/linkConsent.test.mjs tests/linkConsentFlow.test.mjs tests/clientHubOperationPolicy.test.mjs`.
All 21 tests passed, exit `0`; the checked runtime/test sources match the F38 APK
source inventory. The receipt is
`/gpu1-share/data/cicada-client/v164-f38-acceptance-record-20261004/link-capability-check.receipt.redacted.json`,
SHA-256 `a0a842fe82a0add1ab0eb96e949d3af6cfd130075dfc3eaf6d8b8a7f0db62b6d`.
No additional APK, live run or model call was created for this documentation checkpoint.

## Evidence index

| Evidence | SHA-256 |
|---|---|
| `E/android-artifacts.json` | `7a15ace1c0a873a3f27a2296d18719824f9bcafbdb80216ab5a9ccde9c66553c` |
| `E/android-runtime.redacted.json` | `dcf9b9ba32bb69290cdb8d5ba71cf062ec776143b0c0c82d9cd7df56053ed30d` |
| `O/target-key-rn.phone-ui-submit.redacted.json` | `76332ab09b7f38f64809b49bde9d52e2e60b8d93adfa1d1b883ab5a3ab951ec7` |
| `O/target-key-rn.result.redacted.json` | `8f5ebae78eec9f8ecdac5f9890ac925fe502394a65beefdc4fc298dd89a550c7` |
| `O/target-key-rn.instrumentation.private.log` (hash only) | `f42a60bf2db926a67e562225804b57c0415990ee022f5d32b2ebb82d05cea076` |
| `E/link-flow/terminal.redacted.json` | `839741d352a2dadd4bcc381134bab62819462b96d9f20c0c42b4f5586d72dd43` |
| `L/terminal.private.json` | `74184e443d9311d2f8e3244592445aff4af73c0e8ee5d00a00609a30f2958ea4` |
| `E/android-teardown.redacted.json` | `d48c5eaa479e8638669dd30d2b66ecd499cc6352f62cff05cd67cde14fd3e365` |
| `E/emulator-absence-check.redacted.json` | `79dae59cd641943aa3fdea486669b6554a30ef8c91339e55302fff3a1f6fb0a8` |

The independent Root outcome index is
`/home/zyf/CICADA/.cicada-data/v01-finish-20261002/controller-F38-preparation.NONAUTH/actual-root-outcome-index.NONAUTH.json`,
SHA-256 `1ab97b0382620c374f7d906c51c9d1728ac4e759d11dec06d52af296bfdde964`.
Client read-only review verified all 37 referenced hashes. The index binds the
actual JUnit results, signatures, final KEY/NONE state and owned cleanup.

The original terminal records `CORE_ACK_NOT_SENT`. Root separately confirmed
one frame and one later ACK, exit `0`; the terminal is not rewritten.
No Owner private key, bearer, device code,
original proof or raw UI/JUnit payload is included in this document.
