# Clean Core 0213538: F17–F18 Link acceptance and local diagnostics

## Result

The 2026-10-03 Android F18 attempt is **FAIL**, not bilateral Link acceptance.
Source enrollment, encrypted capabilities, independent Owner-pin confirmation,
manifest verification and the external Owner KEY signature reached the real Hub.
The Client verified that signature before submitting it, and the instrumentation
test asserted the Hub's `ok` result. A subsequent authenticated status read failed
local retained-proof validation. Its original exception was replaced by a generic
error, so the exact failed predicate remains **UNKNOWN**. Do not retry this write
or infer that no write occurred.

The narrow diagnostic change preserves the public error code/message and all
verification conditions. Its exception cause contains only an allowlisted local
reason; unknown errors become `UNKNOWN`. It retains neither the original
exception nor its text, status payload, public key or signing proof. The existing
`verified_at <= now` condition has a distinct error reason; it is not relaxed.
The independent Docker Kotlin regression is **PASS**, eight tests, exit `0`.
The replacement APK pair and a fresh live run are **NOT_RUN** at this checkpoint.

## Fixed runtime inputs

| Input | Value |
|---|---|
| F17/F18 Client checkout | `a9d1def9e2e738a8e9d57555987a69db90ed0276` |
| F17/F18 APK source | `508ca333c8ae90d27a8191ac828a7be16b71c7b3` |
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract | `client-hub-v1.6.4`, wire `1`, schema `57`, operations `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7`, dirty `false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interop image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| F17/F18 app APK SHA-256 | `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` |
| F17/F18 test APK SHA-256 | `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6` |

The [clean delivery review](client-hub-v1.6.4-0213538-provenance.md) retains the
independent package/image checks. No result from another Core build or APK is
attributed to this run. The diagnostic checkpoint changes Client code only.

## Evidence and commands

Restricted original evidence remains outside Git:

```text
K=/gpu1-share/data/cicada-client/v164-f14-0213538-plan-20261003
D=/gpu1-share/data/cicada-client/v164-f19-diagnostic-20261003
L18=/gpu1-share/data/cicada-client/v164-f18-0213538-launcher-20261003
E18=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f18-0213538-main-20261003/android
```

`L18/command-journal.private.jsonl` and `E18/link-flow/command-index.private.json`
contain the exact runtime argv, times, exit codes and output hashes. The two
terminal diagnoses retain those commands and redacted projections, without
publishing raw identities or signed payloads.

| Check | Result and exit | Evidence and SHA-256 |
|---|---|---|
| F17 two device Grants, registrations and encrypted capabilities | **PASS**, both enrollment selectors `0`, `OK (1 test)` each | `K/f17-terminal-diagnosis.redacted.json`, `25d7eb88b7d805796dd0be8be41975e250fedd78c8a489a4e73176edc4a3dea4` |
| F17 Source-pin selection after activating Target | **FAIL**, selector `1`; active-profile generation guard | Same F17 diagnosis; KEY/NONE and Target Alert **NOT_RUN** |
| Corrected host scheduling: Source device/KEY/NONE, then Target device/RN KEY/NONE | **PASS** offline only, Docker `0`, 17 checks | `K/offline-f18-phase-check-receipt.redacted.json`, `24aa7b25d08f770d951d1f987b49dea8bbfd8a0eb5f672fa72a3271d1c571083` |
| Sole read-only plan check of three replacement sources, 23 reused sources and frozen APKs | **PASS**, Docker `0` | `K/f18-check-plan-receipt.redacted.json`, `019a1a3a03e71dd8e2538f79eb6be4907c7d5136d911f1155597fdc0d10b6e4b` |
| F18 Source enrollment, capabilities, pins, manifest and external KEY proof staging | **PASS** for those gates; flow steps 1–15 `0` | `K/f18-terminal-diagnosis.redacted.json`, `a2f8eb5ca01467aa75a08cc1b6078e1c42462f28487c4345492b7b598efa83cb` |
| F18 KEY submission followed by fresh retained-status validation | **FAIL**, selector `1`; signature verification and Hub `ok` preceded the failure | Original JUnit log under `E18`, `a51f97835e80eafe2df4c6abfbc9492f34dffadc47d3e0032d03bf48ea3737ec` |
| F18 launcher terminal and owned Android/carrier cleanup | Launcher `1`; cleanup **PASS** | `L18/terminal.private.json`, `60c4f1a7ed0f53c433cc1c89554c6bc75ec821b1539c8c8621c7c922b0fd1d16` |
| F18 Core actor stop/once-only terminal ACK/owned cleanup | Core-attested **PASS**; actor wait `143`, ACK and cleanup `0` | Core's terminal handoff; Client did not sign, ACK or inspect private material |
| Diagnostic regression, first build-driver input | **FAIL**, Gradle `1` before test execution | `D/kotlin-host.receipt.redacted.json`, `6206d3736a36a33446924bdb3804380bb546ad37caeac0a7b722d1f12fc76f5c` |
| Diagnostic regression with the existing writable dependency build-cache mount | **PASS**, Gradle `0`, fresh XML: eight tests, zero failures/errors | `D/kotlin-host-corrected.receipt.redacted.json`, `753d085f89a5f68032a7f27ebde01e07936188951ca42af5ab6efa92eab288de` |

The host command uses the existing immutable build image
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
Docker network `none`, caller UID/GID and offline Gradle:
`gradle --offline --no-daemon --project-dir /workspace/android -I
/out/kotlin-host.init.gradle :app:testDebugUnitTest --tests
ai.cicada.client.hub.LinkKeyManifestVerifierTest
-PreactNativeArchitectures=x86_64 --stacktrace`.
The receipt contains every Docker mount and argument. The first driver mounted
`node_modules` read-only and failed during settings configuration; restoring
the existing writable build mount resolved that failure. Its older seven-test
XML is stale and is not counted as execution of the failed command.

## Interpretation and limits

The 17-check scheduling test executes the frozen flow and completion-handler
AST with synthetic profile, selector, external-proof and UI I/O. It reproduces
the original two-device stale-profile rejection and reaches six completed
phases with the new order. It is not live cryptography or Android UI evidence.

The Kotlin regression uses the complete published synthetic proof vector. It
accepts the valid baseline and rejects future `accepted_at`, future
`verified_at`, an incorrect independent full-key pin, a corrupted proof and
an expired proof. Unknown exception text is replaced by the fixed `UNKNOWN`
diagnostic. These tests establish diagnostic behavior and unchanged rejection
conditions; they do not establish the F18 underlying cause.

F18 preserves `source-key` pending in `PROOF_READY_FOR_NATIVE_STAGE`, with only
Source device enrollment recorded complete. Its 25 transport transactions do
not establish all five route gates. Source NONE, Target enrollment, Target RN
Alert and Target NONE are **NOT_RUN**. The clock-skew explanation remains an
unproven hypothesis. Lost-response/409 recovery in this bounded Link lane
remains **BLOCKED** without an approved safe driver. Native Worker, physical
Android and public HTTPS are **NOT_RUN** in this slice.

A fresh attempt requires the new APK pair, its exact committed source and
necessary updated driver pins, a new Root-approved BOOT/Scope/GO and one
business frame. Preserve the F18 terminal, proof and pending records. Do not
reuse its expired authorization or re-sign the same request. Owner secrets
remain in Core custody; no Node/Hub bearer or model credential enters Android.
