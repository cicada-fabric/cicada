# CICADA Client v1.5 Validation Report

**Validation date:** 2026-09-30

**Result:** The fixed v1.5 contract provenance, Android build, local Kotlin policy/vector matrix, and fresh offline React Native UI smoke check passed. Fresh fixed-Hub enrollment, encrypted capabilities/topology, scoped Group creation, foreign-Owner denial, 201/200 original-request recovery, all three isolated outer-RPC recovery faults, and bounded connected management UI also passed. Positive v2 consent/admission remains BLOCKED; physical Android and public HTTPS remain NOT_RUN.

## Fixed Hub target and contract provenance

The Client was checked against this independently pinned delivery:

| Item | Verified value |
|---|---|
| Core Hub source revision | `bd79ff93c90ecafc28a2471dd9523444903b39e6` |
| Core source fingerprint | `586ca8adbbcf9ea18c83f03e59267ad848c10792452520f5d499ef08ae340f17` |
| Protocol and wire version | `client-hub-v1.5`, wire `1` |
| Catalog | 46 operations; SHA-256 `a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68` |
| Contract archive | SHA-256 `98ce7f02d03dd8291ff7361e46e22ed893f493d242fcb238a948bf869a2a5d0b` |
| Hub image | `sha256:4c321cd8f91a1e19befabd1f5c8983be46e6aed811614c68bd6f62ad06584771` |
| Docker data root | `/gpu1-share/data/docker-root` |
| Build image | `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` |

The imported snapshot is [contracts/client-hub-v1.5-bd79ff9/manifest.json](../contracts/client-hub-v1.5-bd79ff9/manifest.json). The import record reports 17 payload files plus the manifest, 18 safe regular archive members, exact Git byte matches for every payload, and matching independent source fingerprints. The initial Git-mode-only fingerprint trial exited `1` because Git does not retain the server’s complete file permission bits. The final independent calculation used fixed Git file bytes and the published build algorithm’s file modes; it matched the delivered source fingerprint and exited `0`. The import record preserves both attempts. The pinned Hub image labels match the source revision, fingerprint, catalog digest, and image ID above. These pins identify the fixed Hub target; no current Core worktree source or alternate Hub image is substituted.

## Client source and Android build artifacts

The final APKs were built from checkout commit `3e5ef5f7c0d045160a7b49bebb3b6ecdd8fc5461`. The checkout was dirty. The build record fingerprints 86 compiled source files as `0a59f8f101f4fd61cf406874e1e441bbc02f0376bbea55c22d92cc58e7a3f948`; the commit alone therefore does not identify the built source. No clean-source build is claimed.

| Artifact | SHA-256 | Attribution |
|---|---|---|
| Product APK, final build | `5bba1c02fb2b0233006661bd4a67fd3f60811c270cc825f9337c7f4170aaa1ee` | Used in the final offline and live-Hub Android runs |
| Instrumentation APK, final build | `11d8dc7166d539cc91e342553d740f969923d48667498c0c3cf105c5f0a8b5f9` | Contains the v1.5 test-only denial schema correction; used in the final run |

The final build command was run in Docker with the pinned local build image and offline Gradle mode:

```text
gradle --offline --no-daemon --project-dir /workspace/android \
  :app:assembleDebug :app:assembleDebugAndroidTest
```

Recorded Docker build exit: `0`; driver exit: `0`. Exact invocation: `/gpu1-share/data/cicada-client/v15-development-20260930/evidence/integrated-build-3.json`.

Three build candidates are kept distinct. Candidate 1 (`integrated-build.redacted.json`) and candidate 2 (`integrated-build-2.redacted.json`) built successfully but do not identify the final instrumentation APK. Candidate 2's separate offline run used instrumentation APK `5d0dd3fb56726564c9321c7335350c3fbf1a54c38c159115c370a921f676642a`; it used the earlier ordinary-denial expectation and an unused public-key UI setup, without the fixed Hub. Its results and cleanup pass remain historical and are not transferred to the final APK 3. Candidate 3 is the APK pair listed above and is the only pair used for the final 54-test run.

The product APK packaging check passed for the recorded check of known test fixture and environment artifact names. It found no known test fixture in the product APK and confirmed bundled JavaScript. This is a bounded entry-name check, not a universal proof that an APK contains no secrets. Its record is `apk-packaging.redacted.json`.

## Build-time checks

Application builds and executable checks ran in Docker. The archive/Git provenance import was a host-side, read-only artifact check. The JSON records preserve each exact invocation and exit code.

| Check | Command summary | Result |
|---|---|---|
| Contract import and artifact provenance (host-side) | `python3 /gpu1-share/data/cicada-client/v15-development-20260930/evidence/import-v15-contract.py` | PASS, exit `0`; 17 payloads match fixed Git bytes |
| Contract checker | `python3 -B scripts/check-client-contract.py` in Docker with `--network none` | PASS, exit `0` |
| Contract checker regressions | `python3 -B -m unittest discover -s scripts -p test_check_client_contract.py -v` in Docker with `--network none` | PASS, exit `0`; 10 tests |
| TypeScript | `./node_modules/.bin/tsc --noEmit` | PASS, exit `0` |
| ESLint | `./node_modules/.bin/eslint App.tsx src` | PASS, exit `0`; 21 inherited warnings remain |
| JavaScript policy/profile/topology/Monitor tests | `node --experimental-strip-types --test tests/clientHubOperationPolicy.test.mjs tests/hubProfileScope.test.mjs tests/networkTopology.test.mjs tests/monitorBroadcast.test.mjs` | PASS, exit `0`; 29 tests |
| Android debug and instrumentation APK assembly | Offline Gradle command above | PASS, Docker and driver exits `0` |

Evidence records: `checker.redacted.json`, `checker-regressions.redacted.json`, `typescript.json`, `eslint.json`, `javascript-tests.json`, and `integrated-build-3.json` in the development evidence directory. A prior Git-mode-only fingerprint attempt exited `1`; the successful contract import used committed Git blob contents and recorded filesystem mode bits. The failed attempt is retained in the import history and is not represented as a passing check.

## Final Android emulator validation

The final run used the APK hashes above in a fresh Android emulator: Android 15, API 35, `x86_64`, emulator image `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f`. The owned emulator was started with Docker `--network none`. The deterministic summary reports `hub_runtime: NOT_RUN` because it covers only the offline matrix. The subsequent live-Hub phase has separate records below. Physical Android and public HTTPS remain `NOT_RUN`.

The instrumentation matrix passed all 54 tests. Each recorded selector has ADB exit `0` and driver exit `0`:

| Instrumentation selector | JUnit result |
|---|---:|
| `HubProfileStoreTest` | `OK (10 tests)` |
| `NetworkKeyConsentVectorTest` | `OK (6 tests)` |
| `NetworkSessionGuardTest` | `OK (8 tests)` |
| `ClientWirePublicVectorTest` | `OK (5 tests)` |
| `EndpointAttestationVectorTest` | `OK (4 tests)` |
| `MonitorBroadcastVectorTest` | `OK (6 tests)` |
| `ClientHubRecoveryLockTest` | `OK (6 tests)` |
| `ClientHubV15OperationPolicyTest` | `OK (4 tests)` |
| `NetworkKeyProductionVectorTest` | `OK (5 tests)` |
| **Total** | **54** |

The test command used the owned emulator's `am instrument -w -e class <selector> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` invocation. Per-selector command, ADB, driver, and JUnit records are in `/gpu1-share/data/cicada-client/v15-deterministic-final-bd79ff9-20260930/evidence/`; `deterministic-summary.redacted.json` aggregates the results.

The React Native UI smoke run also passed. Its scope is a fresh, offline, unconnected product UI. Recorded ADB and driver exits were `0` for the UI actions. It checked that startup reports an unconnected/unpinned Hub, creating a profile does not activate it, the new profile is unpinned and unenrolled, switching requires explicit confirmation, and the selected profile remains unconnected. This does not establish a connected Hub screen flow or permission to send, approve, complete, or link work. The result is `ui-smoke-summary.redacted.json` in the final Android evidence directory.

## v1.5 operation policy and role coverage

The v1.5 catalog has 46 operations. The Client locally implements 33. It disables all ten new shared-space consent/admission and topology delegation/proposal operations, even if a Hub advertises them in encrypted `session.capabilities`. The three `link.key_manifest`, `link.key_grants`, and `link.key_grant` operations also remain unavailable. The Android policy tests check rejection before local state/key mutation, and the TypeScript policy tests check that advertised permission cannot enable an operation without local support.

The catalog's locally implemented role counts are 33 for `manager` and 25 for `external`. All four live sessions authenticated as **external**. An independent host-side oracle parsed only each originating Android profile state in memory and compared its exact operation IDs with the independently pinned catalog role intersection: **PASS** in each session, 25 exact operations, no deferred operations, matching revision and catalog. It persisted only public operation names and hashed identities (`role-oracle-{base,processing,uncertain,legacy}.redacted.json`). A live manager session remains **NOT_RUN**. The source-level instrumentation count assertion alone was identified as a coverage gap; this separate exact-set oracle closes that gap for the actually tested external sessions. Synthetic Kotlin role tests do not constitute live manager acceptance.

The final cross-Owner denial test expects an ordinary encrypted business denial (`ok=false`, nonblank error text, no successful result) and confirms the current Owner's Group projection is unchanged. It does not assume a stable business `error_code` and does not read foreign-Owner state.

## Public key and proof vector attribution

`NetworkKeyProductionVectorTest` passed five Android instrumentation tests against the complete synthetic Store vector. The Android asset SHA-256 is `6f21a1184243a0781024598063113ccda92df98b9f3996b9d86dd3167efdda04`, equal to the authoritative bundled vector at `cicada-go/internal/store/testdata/network-direct-key-production-v1.json`. The tests pin the raw fixture bytes, canonical manifest claims and signed-input hashes, full ML-KEM/ML-DSA public-key identity and signature shape, Owner proof, native-session locator digest, binding/membership/enrollment revisions, and negative mutants. This is synthetic cryptographic verification; it is not live Network key-consent acceptance. Direct signature checks use Bouncy Castle, the crypto provider family also used by the production verifier, so this is not a cross-provider test.

Four existing Android JSON vectors are byte-identical to files in the imported bundle: Client-Control wire, Endpoint attestation, Monitor broadcast consent, and historical Network direct-key consent. `group-key-manifest-v1.json` is a local synthetic asset absent from the bundle and retains that attribution. See `contract-comparison.redacted.json` for hashes and comparison results.

The fixed v1.5 source mapping for future cross-Owner v2 signatures is confirmed as Endpoint Owner `ENDPOINT → SOURCE` and Group Owner `GROUP → TARGET`; no mapping contradiction was found. The imported bundle does not include an independent cross-Owner v2 canonical/signature vector. The Client therefore keeps those operations disabled until the full field/domain mapping, independent vectors, native proof verifier, fresh authority checks, and explicit consent UI are delivered and validated.

## Live fixed-Hub interoperability and recovery

The same final APK pair contacted new Core-owned disposable Hubs pinned to the immutable image above. Android performs the post-quantum cryptography and signature verification. The emulator retains Docker network mode `none`; a bounded test-only opaque HTTP carrier forwards its loopback traffic over Docker exec STDIO to the independently verified numeric private bridge IP. Only the five Client v2 identity/capability/enrollment/RPC/recovery routes are admitted. Payload bytes stay in memory; private transport records contain lengths, routes, statuses and hashes. This transport proves Android-to-Hub encrypted interoperability and original-byte recovery; it does not validate a product public-network or HTTPS deployment.

Every successful selector below has ADB command exit `0` and JUnit `OK (1 test)`. Each evidence JSON contains its exact `docker exec … adb … am instrument -w -e class … -e run_id … -e scenario …` invocation; test arguments and session identities are not inferred from filenames.

| Check / instrumentation selector | Result | Evidence in the final Android directory |
|---|---|---|
| `ClientHubV15RecoveryFaultTest#captureEnrollmentResponseLoss` | PASS | `base-201-capture-renewed1-rawGrant.json` |
| `ClientHubV15RecoveryFaultTest#recoverExactEnrollment` | PASS | `base-201-recover-renewed1-rawGrant.json` |
| Independent original/retry enrollment HTTP-byte comparison | PASS; both HTTP 201, first response dropped; request SHA identical | `base-201-exact-request-comparison.redacted.json` |
| `ClientHubV15InteropTest#verifyActiveTopologyAfterRecoveredEnrollment` | PASS; encrypted v1.5 capabilities/catalog, ACTIVE Network and explicit selection | `base-topology-after-enrollment-recovery.json` |
| `python3 -B scripts/interop/v15-role-oracle.py … --tag base` | PASS, exit `0`; exact authenticated external allowlist | `role-oracle-base.redacted.json` |
| `ClientHubV15InteropTest#createGroupWithinSelectedNetwork` | PASS; actual Hub write and authoritative readback | `base-create-selected-network-group.json` |
| `ClientHubV15InteropTest#rejectCrossOwnerGroupCreation` | PASS; encrypted denial, exact counter and unchanged own projection | `base-cross-owner-network-denial-corrected.json` |
| Core-owned independent foreign authority audit | PASS, Core command exit `0`; foreign Owner/Network/ACTIVE state and Group count 0 retained; own count 1 | Core `client-base-authority-after.json` |
| `ClientHubV15RecoveryFaultTest#captureRpcResponseLoss` (`completed`) | PASS | `base-rpc-200-capture.json` |
| `ClientHubV15RecoveryFaultTest#recoverCompleted` | PASS; original operation/counters and authenticated response | `base-rpc-200-recover.json` |
| Independent dropped/recovered HTTP body and envelope comparison | PASS; both SHA-256 values identical | `base-rpc-recovery-response-comparison.redacted.json` |
| Separate processing session: `enrollAndVerifyActiveTopology`, `captureRpcResponseLoss`, `recoverStillProcessing` | PASS; each ADB/driver exit `0`, JUnit one-test selector; 409 `STILL_PROCESSING`, original pending packet/operation and request/expected response sequence 4/4 retained; new operations refused | `processing-enroll-active-topology.json`, `processing-rpc-loss-capture.json`, `processing-rpc-still-processing-recovery.json`, `processing-original-packet-preservation.redacted.json` |
| Separate uncertain session: `enrollAndVerifyActiveTopology`, `captureRpcResponseLoss`, `recoverSignedUncertain` | PASS; each ADB/driver exit `0`, JUnit one-test selector; authenticated encrypted `OUTCOME_UNCERTAIN` after exactly one Core restart following `FAULT_READY`; original retired packet retained, writes refused until read-only authoritative reconciliation | `uncertain-enroll-active-topology.json`, `uncertain-rpc-loss-capture.json`, `uncertain-signed-outcome-recovery.json`, `uncertain-recovery-preservation.redacted.json`; Core restart records below |
| Separate legacy session: `enrollAndVerifyActiveTopology`, `captureRpcResponseLoss`, `recoverUnavailable` | PASS; each ADB/driver exit `0`, JUnit one-test selector; 409 `RECOVERY_UNAVAILABLE`, original pending packet/operation and sequence 4/4 retained, recovery blocked | `legacy-enroll-active-topology.json`, `legacy-rpc-loss-capture.json`, `legacy-recovery-unavailable.json`, `legacy-original-packet-preservation.redacted.json` |
| Bounded connected React Native management observation | PASS for encrypted/external header, authoritative snapshot, closed-feature notice, selected Network, topology section and Network key panel; created Group row/name visibility NOT_RUN within the bounded view | `connected-ui-management-final.redacted.json`; partial viewport attempts retained |
| Client-owned emulator and five opaque carriers | PASS; carrier Docker exec exits `0`, emulator stop exit `0`, targeted inspect exit `1` confirms expected absence; all Android reverse mappings removed | `client-owned-resource-cleanup.redacted.json`, `android-teardown.redacted.json`, `emulator-stop.json`, `stdio-carrier-*-stopped.redacted.json` |
| Core-owned four disposable Hub fixtures | PASS; Core records 11 cleanup actions and 18 absent resources, independently rechecked by Client; six resident container identities/status/start times match before/after in Core's receipt | Core `client-owned-teardown.json`; Client `core-owned-resource-cleanup-verification.redacted.json` |

Core's authority audit is under `/home/zyf/CICADA/.cicada-data/v01-finish-20260930T145216Z/`. The Client reads its redacted result, never its Hub database. The BEFORE audit did not record a version, so no unchanged-version or globally unchanged-database claim is made. The final `all-live-summary.redacted.json` binds 16 actual Android selector commands by their argv SHA-256 and records their ADB/driver exits and JUnit results; raw commands remain in the referenced private records.

Core's `client-uncertain-restart.json` confirms exactly one `FAULT_READY`, the same disposable container, image, database mount, complete public identity and bridge IP across the restart. `client-uncertain-restart-command-record.json` records reconstructed executed mutation argv and successful subprocess exits `0`, plus outer driver exit `0`; it does not invent stdout or timestamps. `client-uncertain-fault-command-record.json` records exact proxy/helper source hashes and reconstructed original setup argv. The original setup Docker exit was not separately captured and is explicitly unavailable; the observed `FAULT_READY` establishes the checked mark-helper exit `0`. These are Core-issued receipts, not Client database inspection.

All three fault sessions use independent enrollments and the read-only `status.snapshot` operation. Core's disposable helper admits one synthetic outer RPC ledger entry without dispatching the business operation. Consequently these tests prove Android recovery/fencing and cryptographic interoperability, not execution of a real side effect, native Worker/Thread progress, or business-level exactly-once delivery. Core's `client-processing-authority-observation.json` and `client-legacy-authority-observation.json` independently record one fault trigger, one response-free synthetic ledger entry, one enrolled device and zero Groups; the synthetic entry has an empty business route. Only the uncertain Hub was restarted, after Core confirmed `FAULT_READY`; it was then served through a transparent proxy without rearming the fault.

For `STILL_PROCESSING`, the original pending ciphertext and request/expected response sequences remain 4/4 and new reads/writes are refused. For `OUTCOME_UNCERTAIN`, the original ciphertext moves to retained retired storage without creating a retry operation; the next sequence initially stays unchanged and `topology.apply` is refused. One authorized read-only `status.snapshot` then reconciles the outer RPC fence, clears its generic uncertainty flag and advances the next sequence to 6; the retired original remains retained. This is not a claim that the generic write fence stays locked after that read. For `RECOVERY_UNAVAILABLE`, the original pending ciphertext and 4/4 counters remain, and the session stays blocked rather than reenrolling or submitting a replacement operation.

The 201 loss test retained the same signed renewed Grant and exact registration request. It refused replacement enrollment while pending. The 200 loss test retained the original signed packet, operation ID, reserved request/response counters and authenticated original ciphertext. No retry creates a new operation or guesses a response sequence.

Setup failures are retained: an absent pre-pin session file and native registry/UI projection confusion; incorrect shell quoting and missing Docker stdin forwarding during private staging; an initial carrier check requiring a nonexistent public metadata container field; and a misnamed permission adapter. The first 201 selector failed local `INVALID_OWNER_GRANT` because the renewal adapter retained an expired compatibility field alongside the new `rawGrant`. Only identity GET reached Hub; no enrollment POST or enrollment attempt was created. Core supplied consistent adapters, preserving both original and renewed artifacts; the final test uses the new exact canonical file bytes. Raw phone public-manifest SHA and scoped signer-input SHA identify different schemas and are recorded separately. These diagnostics do not become passing protocol results or imply an Android/Hub protocol defect.

The outer RPC uncertain-outcome lock and durable Network grant fence remain separate. A generic authenticated snapshot can reconcile an outer RPC outcome; it cannot clear the Network grant business fence. Full native Network consent and dedicated proof/status correlation remain **BLOCKED / NOT_RUN**. No actual Network grant is claimed. Fresh device revocation, capability shrink, wrong recovery packets, current native Node/Codex approval/result execution and Monitor delivery remain **NOT_RUN** for this fixed v1.5 checkpoint.

## Security boundary and remaining platform validation

The Client does not call the legacy `/v1` bearer management API. Client-Control user content, status, and management RPCs are intended to use the pinned post-quantum authenticated channel ending at Control; Control can decrypt those requests. This validation does not establish a blind Hub and does not make ordinary peer payloads unreadable to Hub/Control. Cross-user messages, shared-history grants, regroup proposals as User approvals, and Native Group/Endpoint Join are not enabled or established by these results. The fixed Hub advertises `external_thread_links=false` and `status_events=false`.

Physical Android hardware, public HTTPS/TLS deployment, iOS, native HarmonyOS, current v1.5 Node/Codex/Monitor execution, and fresh speech-model execution were not part of the final run and remain **NOT_RUN**. The documented v0.2 Dot/Live integration remains planning only. Historical v1.4 and earlier acceptance results retain their original image/APK attribution and are not transferred to this v1.5 target.

No Hub database, resident Hub state, Node credential, real Owner signing key, or production credential was read or changed by the Client agents for this report. The emulator used Docker `--network none`; live Hub traffic used only the bounded opaque test carrier described above. The owned emulator and all five Client carriers have been removed; no emulator snapshot or device key vault was exported. The initial targeted cleanup oracle rejected Docker's lowercase `no such object` text because of a case-sensitive check; its exit `1` and corrected successful check are retained in `client-owned-resource-cleanup.redacted.json`.

Core performed its own exact-owned teardown after final Legacy authority observation. Its `client-owned-teardown.json` records 10 shell/subprocess commands with exit `0` and one validated disposable-directory removal action marked `REMOVED`; no separate shell exit is invented for that action. It removed only the four disposable Hubs, fault/transparent sidecars, bridges and private fixture directories. The Client independently confirmed all 18 resource absences: targeted Docker inspect commands exited `1` with the expected absence error, and the four directories did not exist (their contents were not read). Core's six resident container IDs, states and start times match before/after in its receipt. Test artifacts and redacted acceptance evidence remain outside Git under the evidence roots below.

## Evidence records

- Development, provenance, and local build checks: `/gpu1-share/data/cicada-client/v15-development-20260930/evidence/`.
- Final APK 3 emulator and offline UI results: `/gpu1-share/data/cicada-client/v15-deterministic-final-bd79ff9-20260930/evidence/`.
- Separate candidate 2 offline run and cleanup history: `/gpu1-share/data/cicada-client/v15-deterministic-bd79ff9-20260930/evidence/`.

After the final source checkpoint commit, its author/committer verification will be recorded in `/gpu1-share/data/cicada-client/v15-development-20260930/evidence/delivery-checkpoint.redacted.json`. Identify the report's committed version with `git log -1 --format='%H %an <%ae> %cn <%ce>' -- docs/client-hub-v1.5-bd79ff9-validation.md`.
