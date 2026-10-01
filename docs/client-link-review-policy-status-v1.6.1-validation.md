# Link review policy status: Client-Control v1.6.1

## Scope and fixed contract

This checkpoint adds only `link.review_policy_status`, a user-triggered,
read-only metadata view for a real Link returned by encrypted `link.list`.
The request remains exactly `{link_id}`. There is no Network selector, policy
write, Owner signer, key Grant, message action, or permission expansion.

| Item | Fixed value |
|---|---|
| Client baseline | `dd1db40cd29559d2845f89deeba944a6b0ad051c` |
| Branch | `dev/react-native` |
| Hub source | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` |
| Protocol / wire | `client-hub-v1.6.1` / `1` |
| Archive SHA-256 | `b5757b055bc871ef5f19fcc5ffe425813c6dea2ccc8cc64b4e74e1f1dcd8db55` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Immutable Hub image | `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589` |
| Offline development image | `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` |

The existing contract snapshot is retained. No archive is re-exported, and
the current Core worktree is not accepted as this fixed image. Historical
`d580975` and `dd1db40` evidence and APKs keep their original attribution.
This checkpoint does not establish complete Client implementation.

## Read and display boundary

The local operation policy and native allowlist must agree on 39 implemented
and 16 closed operations. Public capabilities and authenticated encrypted
session permission are required in addition to local implementation; the Hub
still checks the current device and Link-side Owner.

The selection comes from a freshly loaded encrypted Link list and is bound to
its exact Link ID and version. Profile selection, Hub, Owner, device, session
epoch, foreground lifecycle, and pending recovery changes invalidate the
display. A late or mismatched response cannot populate another selection.

The bounded result and nested policy/reviewer DTOs are validated strictly.
Unknown fields, malformed values, duplicate entries, a wrong Link ID, and
stale versions are rejected. A policy status is Hub-reported metadata. It is
not independent signature verification, a User approval, a reviewer decision,
Link activation, message permission, or evidence of native/model consumption.

The no-policy response is valid with `policy_version=0`, empty digest and
accepted sides, `mode=NONE`, empty reviewers, zero numeric limits,
`current=true`, and no expiry. The UI explicitly labels this **unconfigured**;
`current=true` never means that both Owners approved.

Original signed ciphertext, operation ID and counters are preserved when a
response is lost or fails validation. Recovery validates the same original
scope. This read cannot clear a Network, regroup or other uncertain-write
fence. All key operations and the other closed flows retain their gates.

## Deterministic verification

All final offline gates below exited 0 on 2026-10-01. Evidence is stored
privately outside Git under
`/gpu1-share/data/cicada-client/v161-link-policy-status-20261001/`.
The Client revision is the single milestone containing this record; the
post-commit `provenance/client-delivery.redacted.json` binds its full revision
without introducing a recursive document hash. Nothing is pushed or merged.

| Gate | Result | Exit | Receipt relative to the evidence root |
|---|---|---|---|
| JavaScript parser, scope and operation policy | **PASS**, 67 tests | 0 | `checks/js.receipt.json` |
| TypeScript | **PASS** | 0 | `checks/typescript.receipt.json` |
| ESLint | **PASS**, 0 errors, 23 warnings | 0 | `checks/eslint.receipt.json` |
| Offline contract checker | **PASS** | 0 | `checks/contract.receipt.json` |
| Public-fixture checker regressions | **PASS**, 11 tests | 0 | `checks/contract-regressions.receipt.json` |
| Pure Kotlin host-JVM validation | **PASS**, 5 tests, no failures/skips | 0 | `checks/kotlin-host.receipt.json`, `checks/kotlin-host.junit.xml` |
| Offline role intersection | **PASS**, local 39 / closed 16; manager 39, external 31 | 0 | `checks/role-oracle-static.receipt.json` |
| Debug app and instrumentation APK build | **PASS** | 0 | `build/build.receipt.json` |
| Android instrumentation execution / emulator UI | **NOT_RUN** | — | No runtime receipt |
| Fixed-image encrypted Hub status/recovery | **NOT_RUN** | — | No runtime receipt |
| Node, native Thread and model runtime | **NOT_RUN** | — | No runtime receipt |
| Physical Android / public HTTPS | **NOT_RUN** | — | No runtime receipt |
| New live acceptance gate | **BLOCKED**, awaiting the final clean Core candidate | — | No substitute fixture |

### Commands and tested inputs

The exact outer commands were
`python3 /gpu1-share/data/cicada-client/v161-link-policy-status-20261001/run-offline-check.py`
with each gate below as its sole argument. The helper, exact Docker argv,
logs and receipts are retained in the evidence directory. Every container
used the full offline development image ID above with `--rm --pull=never
--network=none --user 1000:1000`; Docker data root was
`/gpu1-share/data/docker-root`. Read gates mounted the repository and cached
Node modules read-only. Gradle mounted the repository, cached Node modules,
Gradle cache, Android home and this private evidence directory for build
output. No credential file was mounted.

| Gate argument | Command inside the offline container |
|---|---|
| `js` | `node --experimental-strip-types --test` followed by the nine exact `tests/*.mjs` paths in `checks/js.argv.json` |
| `typescript` | `node node_modules/typescript/bin/tsc --noEmit` |
| `eslint` | `node node_modules/eslint/bin/eslint.js .` |
| `contract` | `python3 scripts/check-client-contract.py` |
| `contract-regressions` | `python3 scripts/test_check_client_contract.py` |
| `kotlin-host` | `gradle --offline --no-daemon --project-dir /workspace/android -I /out/kotlin-host.init.gradle :app:testDebugUnitTest --tests ai.cicada.client.hub.LinkReviewPolicyStatusValidationTest` |
| `build` | `gradle --offline --no-daemon --project-dir /workspace/android :app:assembleDebug :app:assembleDebugAndroidTest` |

The additional role check imported `scripts/interop/v16-role-oracle.py` and
called only `oracle.verify_contract()` against the public contract. Its
complete `python3 -c` argv is recorded in its receipt. It never called the
runtime state reader, started an emulator, or contacted a Hub.

The host-JVM gate used a byte-identical copy of the new pure Kotlin test and
an external Gradle init script to select it with cached JUnit dependencies.
It added no project dependency or lock-file change. Original test SHA-256 is
`a21fccc9248e7d119c48ba96a160a5a403c02ef47303d58755ec12bb303d4327`.
The two new synthetic Session tests for lost status-response recovery and a
stale fresh-list version were compiled into the instrumentation APK but
**not executed**. They do not establish live recovery or Android acceptance.
The updated future Android matrix and runtime role oracle also remain unrun.

### Artifact attribution

| Artifact / input | SHA-256 | Size |
|---|---|---|
| Compiled source fingerprint | `8ffe7b8855c82250505fb7a572ebe604355769905ae4bfbba648f4620b5ac538` | 116 source/configuration files |
| JavaScript tested-input fingerprint | `99b00bbad85f7d73e9c08b6d12001698c238f997652147f5b288203bf029df75` | 35 source/configuration/test files |
| `build/app.private.apk` | `74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` | 296,293,379 bytes |
| `build/test.private.apk` | `fd36c9f56f0c4b3de335e4b458fd7c5d0ca9590b591e716b8bf70077dcca170f` | 1,117,853 bytes |

Fingerprints hash each sorted path, a NUL byte and the binary SHA-256 of its
contents. The compiled set includes tracked and non-ignored new files under
`android/` and `src/` plus application and build configuration inputs. The
JavaScript set replaces Android inputs with the `tests/*.mjs` files. Every
final gate recorded unchanged inputs before and after execution. Test-helper
and receipt hashes are separately indexed; documentation changes do not alter
the compiled fingerprint. Neither new APK is attributed to earlier runtime
evidence.

Initial UI candidate checks are preserved under `checks/history/initial-ui/`:
JavaScript exited 1 for three incorrect test expectations, and lint exited 1
for the lifecycle-ref cleanup. These were corrected before the final gates.
The initial type check exited 0 on its earlier inputs. No APK was built for
that candidate, and none of its checks is substituted for a final result.

No Hub, Node, model, emulator or production deployment is started in this
checkpoint. Host-JVM validation and APK compilation do not constitute Android
runtime acceptance. A new live gate awaits a separately delivered clean Core
candidate; existing runtime results are not transferred to this operation.

The redacted evidence index is `provenance/evidence-index.redacted.json`;
its SHA-256 is `a3a496ec3f69fc35383d8dc959bf05f779f288369ac56bc7c9683f45988ebc30`.
Final scope/identity checks and the post-commit delivery binding are recorded
separately under `provenance/`. APKs, logs, test results, caches and recovery
material remain outside Git.
`provenance/final-checks.redacted.json` has SHA-256
`bbc05f55f68db6ec917272339299d0c417c3cc2a32a7fb15935786a3a30c6fc2`.

## Core maintainer handoff

> Review the single-operation Client status slice against the unchanged
> v1.6.1 contract. Preserve exact encrypted Link-list selection and Link-side
> Owner/device Guards. A default NONE policy with `current=true` is
> unconfigured, not bilateral approval. Keep private Owner keys, signers,
> key Grants and policy writes outside this checkpoint. Supply the final
> clean Core candidate before a separately authorized encrypted Android
> status/recovery gate. That later gate must cover default and configured
> metadata, stale versions, foreign-Owner refusal, unsupported capabilities,
> Hub switching and exact original-packet recovery. Do not infer reviewer
> decisions, peer routing or model consumption from status metadata.
