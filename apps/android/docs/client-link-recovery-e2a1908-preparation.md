# Clean e2a1908 Android Link recovery preparation

## Scope and authorization

Date: 2026-10-10. Branch: `dev/react-native`. This checkpoint performs Client
preparation only. It independently inspects the frozen Core export, adds
deterministic test selectors and a narrow opaque carrier, runs offline checks,
and builds one immutable application/test APK pair. A separate Root joint-test
GO is required for Android execution or any online interoperability.

Application UI, local STT, independent Hub/Owner pins, device Grant, production
cryptography, sequence allocation, durable pending requests, consent fences and
feature gates are unchanged. No Core file, database, Hub lifecycle, resident
deployment, real key or model is used. `external_thread_links=false` continues
to close ordinary cross-user messaging.

## Frozen Core delivery

Delivery directory:
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010`.
These are build/export provenance; they are not Android runtime acceptance.

| Input | Independently checked value |
|---|---|
| Core commit | `e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59` |
| Contract / wire / catalog operations | `client-hub-v1.6.4` / `1` / `55` |
| Delivery manifest SHA-256 | `517eaa56464adf44eb27600a8197ff291d49e961718096ce7c17399e47fb5ef4` |
| Contract bundle SHA-256 | `bb54bdf34fb6fd4e9528a61e29a0b8cf7089b6f081da6f6d7b74d1c0d3d80568` |
| Build metadata SHA-256 | `e97274b78c56aba6c2adc827f10c4eb757a40576bad3768b404dfc85345a0d5a` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Hub image ID | `sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01` |
| Test image ID | `sha256:73ec018a026a27fb04ec0c651bafa976ebbed71efca87d302d0c7c4c2e59ba6a` |
| Core source dirty | `false` |
| Core source fingerprint | `7a8b99036b32e7d4727ab7011a53fa477854505cabfbdeccb8bc54baed7580d5` |
| Complete inventory / digest | `954` / `1367722edb705032e4584ba09f40566cdcd77f5205e3b8e8b9b10195f1648c16` |
| Hub archive SHA-256 | `a9eadeb1826a11711d512c3ec956db608b484a1bfe3b1cdea8cd7102aa1dd62a` |

The Client verifier checks every one of 24 contract members, raw catalog
bytes, the complete fixed Git tree, each exported input's content/mode/index
identity, both independently reproduced inventory/source digests, image IDs
and source labels, archive bytes and exported license digests. All eleven
public JSON vectors are byte-identical to the previously imported v1.6.4
vectors; their earlier runtime results still do not transfer to this image.
The canonical tar manifest and the exporter's pretty-printed external manifest
have different byte hashes but equal JSON content; both are checked.

`Q=/gpu1-share/data/cicada-client/v164-e2a1908-recovery-preparation-20261010`.

Executed command, exit `0`:

```sh
python3 scripts/interop/v164-clean-delivery.py \
  --delivery /home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010 \
  --core /home/zyf/CICADA
```

Evidence: `Q/delivery-check-attempt03.private.json`, SHA-256
`7bd5c92bb4e5d51fed2b897a15d6bddd756ef8e154dc23811ba014f483a6589d`.
Exact command/script hash: `Q/delivery-check-attempt03.command.redacted.json`.
Two earlier Client verifier implementation failures, exits `1`, are retained
in `Q/delivery-check-attempt01.history.redacted.json` and
`Q/delivery-check-attempt02.history.redacted.json`; they were corrected before
the successful check and are not Core artifact failures.

## Implemented test entrypoints

Class: `ai.cicada.client.hub.LinkConsentInteropTest`.

| Mode | KEY recovery selector | NONE recovery selector | Expected native recovery |
|---|---|---|---|
| response-loss | `recoverKeyResponseLoss` | `recoverNoneResponseLoss` | Authenticated original cached ciphertext; original response sequence consumed |
| processing | `recoverKeyProcessing` | `recoverNoneProcessing` | HTTP `409 STILL_PROCESSING`; original pending packet/counters preserved |
| uncertain | `recoverKeyUncertain` | `recoverNoneUncertain` | Encrypted `OUTCOME_UNCERTAIN` after verified isolated restart; retired packet and business fence retained |
| legacy | `recoverKeyLegacy` | `recoverNoneLegacy` | HTTP `409 RECOVERY_UNAVAILABLE`; original packet preserved, session recovery blocked |

Capture selectors are `capturesKeyOriginalConsentFault` and
`capturesNoneOriginalConsentFault`. Each requires a current native review and
external Owner signature, calls the existing confirmed native submit exactly
once, requires transport loss, and writes an immutable redacted capture receipt.
NONE additionally requires the exact empty NONE policy. It does not recover or
perform a fresh Hub read after the fault. Instrumentation's `confirmed=true`
is recorded separately from human or phone-UI confirmation.

Recovery selectors validate the capture, active enrolled profile, exact raw
Root readiness and mode **before** calling native recovery once. They verify
the original packet/proof/tuple hashes, operation ID and persisted counters;
no replacement operation or guessed response sequence is created. Uncertain
also requires the native authenticated `sessionError=OUTCOME_UNCERTAIN`, not
merely a retained local fence. Processing, uncertain and legacy attempt one
later managed write and require local rejection with unchanged state.

The old v1 response-loss selector and its history are preserved. New selectors
require the clean e2a1908 APK pin lane and cannot fall back to legacy/F6 pins.
`CAPTURED` and `RECOVERED` receipts do not establish business acceptance.

## Scenario, readiness and evidence formats

All formats below are closed **test coordination schemas**, not new Hub routes
or permission grants. Files are bounded, caller-owned, mode `0600`; they contain
public inputs/digests only. Never stage a signing key, bearer or device code.

- Scenario: `<side>-recovery-scenario.v2.json`, exact fields `schema`, `run_id`,
  `expected_operation`, `fault_mode`. Schema:
  `cicada.client-v164-link-consent-recovery-scenario.v2`; side is `source` or
  `target`, operation is `link.key_grant` or `link.review_policy_grant`.
- Capture:
  `<side>-link-recovery-{key_grant|review_policy_grant}-{mode}.capture.redacted.json`;
  schema `cicada.client-v164-link-consent-recovery-capture.v2`.
- Root readiness: `<side>-fault-ready.json`, schema
  `cicada.client-v164-link-recovery-ready.v1`; exact fields `schema`, `run_id`,
  `hub_source`, `fault_ready_raw_base64`, `fault_ready_raw_sha256`, `restart`.
  `hub_source` contains the six fixed Core/image/source/catalog/contract/wire
  fields. Raw Core `FAULT_READY` is preserved as one LF-terminated JSONL record
  and hashed independently. Core does not supply `run_id` or source/image pins.
  For uncertain, `restart={status:"VERIFIED",receipt_sha256:<Root receipt hash>}`;
  other modes require `NOT_REQUIRED` and null hash. Root verifies the actual
  CID/image/mount/identity/origin and restart ordering; the wrapper alone does
  not prove a restart occurred.
- Recovery:
  `<side>-link-recovery-{key_grant|review_policy_grant}-{mode}.recovery.redacted.json`;
  schema `cicada.client-v164-link-consent-recovery-result.v2`. This records exact
  raw readiness hash, mode-specific pending/fence/counter and write-refusal
  evidence. `response_sha256` is Core's cached ciphertext expectation, not an
  Android-observed ciphertext hash.
- APK pins: `cicada.client-v164-e2a1908-recovery-apk-pins.v1`, independently
  hash-pinned by Root; frozen Core delivery plus actual Client build commit,
  dirty flag, input SHA and the one application/test APK pair. The owned Android
  runner and staging driver both reject historical-lane fallback.
- Carrier: `cicada.client-v164-link-recovery-carrier.v1`, independently
  hash-pinned by Root; exact run, six fixed Hub/source fields, process PID/start
  token/helper SHA, raw Core READY SHA, fixed upstream and Android origin,
  Hub/Owner/device/session epoch and selected operation/mode. It contains no
  database or key path. Runtime PID/start/helper attestation remains Root-owned.

The carrier implements existing bounded `request` / `response` / `drop` STDIO
frames for a network-none emulator. It preserves the registered Android URL;
the Root-owned bridge changes only its transport mapping. The upstream is one
numeric `127.0.0.1` Core `serve-link` origin. No redirects, proxy environment,
enrollment route, bearer headers, generic forwarding or lifecycle actions are
allowed. Before the selected write, only narrow identity and enrolled reads are
forwarded; after it, only one byte-identical original `/rpc/recover` is allowed.
Transport loss becomes `drop`, not a synthetic HTTP response.

Root installs one immutable readiness envelope through a separate private
control FD, with its exact raw SHA. Keep the carrier process and original packet
in memory across capture and uncertain Hub restart; restarting that carrier
would lose its correlation. `FrameAdapter.evidence_snapshot()` exports only
digests/counters/status. Root's bridge must save it privately after recovery.
The Client `validate_result` and `validate_carrier_snapshot` consumers join it
with the native receipt and Core event; response-loss requires the actual
recovered ciphertext hash to equal Core's cached original. No packet/proof/ID
bytes are exported or persisted by the carrier.

## Offline verification and APK attribution

Docker data root: `/gpu1-share/data/docker-root`. Immutable offline build image:
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
Commands, exits, input inventories, binary/log hashes and elapsed times are
recorded in `Q`. No dependency download, new image build, Core mount or secret
mount is used. APKs remain outside Git.

| Offline check | Command / exit | Result |
|---|---|---|
| Shared v1.6.4 Python driver, pin and receipt regressions | Docker `python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v`, exit `0` | **PASS**, 111 tests |
| Synthetic Kotlin original-state regression | Cached `K2JVMCompiler`, then `LinkConsentRecoveryEvidenceRegressionKt`, compile/runtime `0` | **PASS**, 3 groups |
| Synthetic Kotlin v2 scenarios, strict raw readiness and mode state | Same compiled jar, `LinkConsentRecoveryScenarioRegressionKt`, exit `0` | **PASS**, 4 groups, including the eight operation/mode pairings |
| Actual changed Android selector/helper compilation | Cached compiler, Android SDK and prior immutable application classes; exit `0` | **PASS**, compile only |

Final receipts retain exact Docker/compiler argument arrays, every checked
source hash, input library hashes and private log hashes. Source remained
unchanged throughout the checks:

| Evidence | SHA-256 |
|---|---|
| `Q/final-offline/python.receipt.redacted.json` | `158248482f4a043204d224193f1925c08d45595e6211fd99bde0f59e020b5571` |
| `Q/final-offline/kotlin.receipt.redacted.json` | `ac60454e0322e4489c761ec0a37a36dc89c0c6626ba469f093422ae7c2c4004f` |
| `Q/final-offline/output/compile.receipt.redacted.json` | `0baca3a4f0057665135c4ed61a8d31fa606e858e85a367dbc797c7971f41b8e9` |

The initial offline checks passed 110 Python tests and the Kotlin checks. Review
then bounded carrier route/counter values to Android's signed Long range,
rejected boolean GET byte counts, and used Gson's current strict reader API.
The final-source checks above include the added regression. Earlier receipts
at `Q/python-offline.receipt.redacted.json` and
`Q/kotlin-offline.receipt.redacted.json` remain intermediate attribution.
These checks use synthetic state/opaque localhost fixtures only; they do not
authenticate a real current-image Hub, use Owner keys or execute Android.

The APK build uses parent Client HEAD
`9b56832c9701b0ba469d8703fdf61611e0208f98`, **dirty=true**, with all new code/tests
staged and frozen in `Q/source`. Complete input inventory: 598 files,
`Q/source-inventory.private.json`, SHA-256
`8d26a0029dacc957607293e015bf4e6732af4a73b046556457df2446adfac629`.
The final delivery commit must not be substituted for this actual build HEAD.
Post-build documentation additions are correlated separately with the final
commit; compiled application/test/driver inputs must remain byte-identical.

One offline Gradle invocation produced the one new pair, exit `0`, elapsed
`200.031` seconds. The APKs target **x86_64 emulator verification**; they are not
physical-device or release acceptance. Both files are stored read-only outside
Git, and the build receipt requires unchanged frozen inputs.

| Artifact / evidence | SHA-256 |
|---|---|
| `Q/binaries/app.private.apk` | `3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9` |
| `Q/binaries/test.private.apk` | `243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae` |
| `Q/apk-build.receipt.redacted.json` | `e27aaea9c9c8b6871021e7c448b01e36b41e8c8620bf154969f5e95815fee7f5` |

The exact argument array is in that receipt. Its Gradle command is:

```sh
gradle --offline --no-daemon --max-workers=2 --project-dir /workspace/android \
  :app:assembleDebug :app:assembleDebugAndroidTest \
  -PreactNativeArchitectures=x86_64 --stacktrace
```

Docker used `--pull=never --network=none --cpus=2 --memory=4g`, user `1000:1000`,
the immutable build image and Client-only source/cache overlays. No Hub, Core
source, Owner key, Node/Hub bearer or model credential was mounted. The final
commit and snapshot correlation are recorded in
`Q/commit-delivery.receipt.redacted.json`; `Q/apk-pins.proposed.private.json`
contains the exact public APK/delivery values for Root to independently review
and endorse by its full byte hash. It is a Client proposal, not joint-test GO.

Android runtime and all eight online cases remain **NOT_RUN**.

## Coordination READY requirements and deferred execution

Root must deliver, separately from this preparation GO:

1. Explicit joint-test GO and bounded owned-resource cleanup plan, with six
   residents preserved. Fresh sessions for all eight modes; no historical
   pending operation, accepted immutable grant or old APK reused.
2. Exact fixed Hub/test image identity, public Core helper binary SHA and clean
   source provenance, actual owned PID/start identity, loopback Core READY and
   Root manifests with independent hashes. Client never reads the DB producer
   inputs or Core process arguments.
3. A Root-owned network-none Android bridge and private control channel. Direct
   enrollment precedes fault routing. Independently trusted full Hub/Owner pins,
   a one-use OwnerDeviceGrant, and encrypted `session.capabilities` must match
   contract/catalog and allow each dedicated operation.
4. Current bounded Link fixture and external Owner signer, current proof and
   selected native review. Android retains the same pin/Grant/URL while only
   the owned opaque transport is routed through Core `serve-link`.
5. One capture, exact Core `FAULT_READY` correlated to its packet hash/counters,
   and, only for uncertain, restart the exact disposable Hub **after** that
   event. Verify unchanged identity/origin before staging the Root envelope and
   enabling the original recovery.
6. Save native capture/result, actual carrier snapshot and Core event, all
   command/exit records and source/APK attribution. Then reconcile KEY/NONE
   status from a separate participating Owner session on the direct Hub path.
   The faulted session's pending/retired packet and business fence remain
   preserved; a second uncertain recovery call would trigger fresh reads there
   and is prohibited in this fixture.

Deferred selector template; **not executed during preparation**:

```sh
python3 scripts/interop/v164-link-consent-android.py <owned-emulator-evidence> selector \
  --run-id <fresh-v164-run-id> --side <source-or-target> --method <selector-above> \
  --recovery-apk-pins <Root-owned-pins.json> \
  --recovery-apk-pins-sha256 <independent-full-sha256>
```

Use the same driver `stage` command for the v2 scenario and Root envelope;
readiness staging additionally requires `--input-sha256` for exact Root bytes
and `--reference` pointing to the immutable redacted capture. Do not replace
the raw Core record or fabricate Core fields. The carrier CLI requires
`--root-manifest`, `--manifest-sha256`, `--scenario`, `--scenario-sha256`,
`--ready-event`, `--control-fd`, and separate `--go`; its STDIO is transport
only. Root may embed `FrameAdapter` to retain and save its safe snapshot.

## Acceptance matrix and historical separation

| Gate | Result at preparation |
|---|---|
| Frozen delivery, bundle, catalog, 954-input inventory and image metadata | **PASS** |
| Relevant offline Client tests | **PASS**, final-source receipts above |
| Fresh immutable app/test APK pair | **PASS**, Gradle exit `0`; runtime **NOT_RUN** |
| Encrypted current-image runtime `session.capabilities` | **NOT_RUN** |
| Android KEY: response-loss / processing / uncertain / legacy | **NOT_RUN**, each |
| Android NONE: response-loss / processing / uncertain / legacy | **NOT_RUN**, each |
| Separate-session authoritative KEY/NONE reconciliation | **NOT_RUN** |
| Fresh emulator execution / process-death acceptance | **NOT_RUN** |
| Real Native Worker/model / physical Android / public HTTPS | **NOT_RUN**, each |

Core's synthetic Go eight-case/two-restart results are a separate layer.
Dirty-b06 evidence, earlier fixture failures and the observed Native G1
disconnected-stream/server-overload failure remain historical; no quota or
CICADA route defect is inferred. F38 remains limited to its clean `0213538`
Hub and `caa9e4c` APKs. Neither those results nor older Kotlin/emulator passes
are current-image Android eight-case acceptance. No push, merge or publication
is performed at this checkpoint.

### Coordination prompt

> Review this preparation report and its exact source/APK receipts. Supply a
> separate bounded joint-test GO plus owned e2a1908 Hub/helper/process/bridge
> readiness, current external signing and independent Android sessions for all
> eight KEY/NONE cases. Preserve the exact pending packet and carrier memory;
> stage raw Core FAULT_READY and verify the isolated uncertain restart before
> recovery. Join native state/counters with actual carrier ciphertext digests,
> then reconcile from a separate participating session. Client must not access
> a Hub DB, signing key, Node/Hub bearer or resident deployment. Retain all old
> failures and source/APK attribution; no old or synthetic result transfers.
