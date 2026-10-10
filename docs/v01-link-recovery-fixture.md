# Dedicated Link original-packet recovery fixture

This extends `cicada-go/cmd/client-recovery-fixture`; it adds no Hub fault API,
protocol revision, dependency, Owner trust shortcut or routing capability.
The [Client offline handoff](../../CICADA_CLIENT/docs/client-link-recovery-offline-validation.md)
asks for this Core-owned entrypoint. Its earlier Android/F38 results retain
their original source/APK/image attribution. Delivery of this fixture does
not turn current-image Android recovery into PASS.

`serve-link` carries opaque encrypted packets. Client keeps its original
packet, private device/Owner keys, signatures, operation ID and durable
counters; it never receives database access. Only the Core operator runs the
fixture against a marked disposable Hub database. Do not use a resident Hub.

The five selectable operations are the existing `link.key_manifest`,
`link.key_grants`, `link.key_grant`, `link.review_policy_preview`, and
`link.review_policy_grant`. They are checked against the embedded authoritative
catalog and its `/v2/client/rpc` route. Production server Guard and encrypted
session capabilities still decide authority. Startup verifies the loopback
Hub identity against the database, contract revision and catalog digest, and
requires `external_thread_links=false`.

| Mode | What the fixture does | Original `/v2/client/rpc/recover` outcome |
| --- | --- | --- |
| `response-loss` | Sends the original packet to the real Hub handler; requires HTTP 200, durable `COMPLETED`, and exact cached response equality before dropping the connection | HTTP 200, byte-identical cached ciphertext |
| `processing` | Authenticates the fresh original through real recovery ingress, then accepts an interrupted outer RPC without dispatching the Link handler | HTTP 409 `STILL_PROCESSING` |
| `uncertain` | Same outer acceptance, with durable response reservation; emits `FAULT_READY` while still `PROCESSING`; operator actually restarts its owned Hub | After real startup: HTTP 200, signed/encrypted `OUTCOME_UNCERTAIN` |
| `legacy` | Same authenticated outer acceptance; marks only that new request uncertain and removes only its recovery reservation marker | HTTP 409 `RECOVERY_UNAVAILABLE` |

Only `response-loss` executes a Link handler. A `COMPLETED` transport response
may contain an encrypted business refusal. The proxy does not decrypt it;
its redacted receipt always says `business_outcome=UNKNOWN`. Client must verify
and decrypt the recovered result. The other three cases cover outer recovery
and write fencing, not a committed grant or a business crash window. None
proves arbitrary actions exactly once.

Create and enroll synthetic owners/devices and the exact Link on an isolated
Hub using the existing setup workflow before starting the proxy. Hold a fixed
published loopback port across restart. Its state directory must be inside a
dedicated directory beneath the actual system temporary directory, contain an
existing regular SQLite database and a regular, non-symlink marker named
`.cicada-disposable-recovery-fixture` whose contents are `disposable`.

Build this test-only binary from the exact frozen source; record its SHA-256
and complete source inventory separately from Hub image ID, Git HEAD/dirty
state, software version, schema, contract revision/catalog hash and wire
version. Root must authorize the owned Hub gate and any real restart. The
command below uses operator-provided private variables, not example credentials:

```sh
"$FIXTURE_BINARY" serve-link \
  --db "$OWNED_TEMP_DB" \
  --hub-url "$OWNED_FIXED_LOOPBACK_ORIGIN" \
  --listen 127.0.0.1:0 \
  --owner-id "$ENROLLED_SYNTHETIC_OWNER" \
  --device-id "$ENROLLED_TEST_DEVICE" \
  --operation link.key_grant \
  --mode response-loss >"$PRIVATE_EVIDENCE_DIR/proxy.jsonl"
```

Use a fresh independent device/session for each case. For NONE choose
`link.review_policy_grant` with the Client's original NONE policy proof.
Choose `processing`, `uncertain` or `legacy` for the other outer cases.
`READY` provides the actual proxy port plus contract/catalog/wire identifiers.
Origin/listen must use numeric loopback addresses. There is no redirect,
environment proxy, URL query forwarding, enrollment forwarding or generic
HTTP proxy. Startup failures exit nonzero.

Before the fault, only the pinned owner's pinned device may send the five
dedicated operations or read `session.capabilities`, `status.snapshot`,
`link.list` and `link.review_policy_status`. Exactly one matching operation
is intercepted. Another device or an unlisted write is refused. The fixture
binds its consumed slot to the full original request SHA-256 and bytes; a
partial failure also consumes the slot and reports `FAULT_FAILED`. Preserve
pending state and inspect the failure; never automatically replay it.

After `FAULT_READY`, only the byte-identical original packet may be sent to
`/v2/client/rpc/recover`. A changed packet, a new sequence/operation, another
device, the original `/rpc` retry, or fresh reads on the faulted device are
refused by the proxy. Direct production Hub retries also retain their real
Guard. For `uncertain`, wait for `FAULT_READY`, verify the recorded owned Hub
container/image/mount/Hub identity, restart exactly that container, confirm
the same origin and identity, then recover. The proxy never restarts a Hub.

Fresh KEY/NONE business reconciliation uses a separately enrolled participating
Owner session directly on the owned Hub; it does not advance the faulted
device's counters. Compare exact Link/version/contract/proof evidence and
bilateral status. Do not infer first-side grant acceptance from an active
head, cached snapshot or transport completion. An uncertainty notice does
not clear the Client's business fence or authorize replacement writes.

Send SIGTERM or SIGINT to the recorded proxy PID after capturing receipts.
Successful graceful shutdown closes its listener and emits `CLEANUP` with
`scope=PROXY_ONLY` and `database_deleted=false`. The Core operator separately
stops/removes only its recorded Hub/test containers, verifies their exact IDs
are absent, and disposes of its own temporary keys/database. Preserve initial
failure evidence and redacted hashes; exclude raw packets, grants, identities
and private state from public artifacts. Process cleanup is not grant acceptance.

The bounded offline checks use the real Go Hub handler over loopback TCP, a
temporary database, synthetic leased Endpoint metadata and Owner signatures.
They cover KEY and NONE for all four modes, a real Control restart for each
uncertain case, cached byte equality, Hub duplicate rejection/counter stability,
accepted-grant row counts, separate fresh reconciliation, malformed/foreign
ingress refusal and proxy signal cleanup. Endpoint metadata is synthetic;
these are not native Runtime or Android tests.

```sh
go test -count=1 -timeout=180s -json ./cmd/client-recovery-fixture \
  -run '^Test(LinkFaultProxy|RecoveryFixture)'
go test -race -count=1 -timeout=180s -json ./cmd/client-recovery-fixture \
  -run '^Test(LinkFaultProxy|RecoveryFixture)'
go vet ./cmd/client-recovery-fixture
go build -o "$PRIVATE_EVIDENCE_DIR/client-recovery-fixture" ./cmd/client-recovery-fixture
```

`TestClientDockerHubLinkFaultFixture` is the opt-in current-image Go TCP gate.
It requires `CICADA_TEST_HUB_URL`, `CICADA_TEST_HUB_DB`, and
`CICADA_TEST_LINK_UNCERTAIN_RESTART=external`. It creates fresh synthetic scope
for eight KEY/NONE scenarios in the marked disposable state. For each uncertain
case its `FAULT_READY ROOT_RESTART_REQUIRED` test output contains only the
operation and request digest; Root has 45 seconds to restart its owned Hub on
the fixed origin. The test waits for actual startup recovery in the database
and a successful real identity response with the same Hub ID. Each HTTP probe
has a 500 ms timeout; the entire wait has one absolute 45 second deadline;
no SQL change stands in for restart. Without coordination it fails. Missing
Hub variables produce a SKIP, never PASS. This gate and Android, native Runtime,
physical device and public HTTPS require their own current artifact evidence.

At the original fixture checkpoint, coordination was manual or supplied by a
separately authorized Root orchestrator. The interop script then had four
suites, none selecting this gate. The subsequent reusable workflow below adds
`--suite client-link-recovery`; the test image's default ENTRYPOINT still does
not select it. Building the existing images is still done with
`scripts/build-hub-image.sh --image "$OWNED_HUB_TAG" --interop-test-image
"$OWNED_TEST_TAG" --metadata-file "$PRIVATE_BUILD_METADATA"`. Record the
metadata's exact image IDs and full dirty-source inventory before launch.
Use the existing Hub launch/provenance checks with a fixed loopback host port,
fresh owned state/workspaces and exact image ID; do not reuse a resident Hub.

The test runner needs an explicit `--entrypoint go` override, `--network host`
to reach the numeric loopback origin, its exact test-image ID, and a read-write
mount of only that owned disposable state to `/tmp/fixture-state`. Keep the
existing nonroot UID/GID, resources, dropped capabilities, run labels, CID files
and owned cleanup plan. Its explicit environment and Go argument array are:

```text
CICADA_TEST_HUB_URL=<owned fixed numeric loopback origin>
CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3
CICADA_TEST_LINK_UNCERTAIN_RESTART=external
GOCACHE=/tmp/go-build
GOPROXY=off
GOSUMDB=off
GOTOOLCHAIN=local
GOENV=off
CGO_ENABLED=0
GOMAXPROCS=2

go test -json -p=1 -mod=readonly -buildvcs=false -count=1 -timeout=180s
  ./cmd/client-recovery-fixture -run ^TestClientDockerHubLinkFaultFixture$
```

Read Go JSON `Action=output` records while the runner is active. Exactly two
records, under the corresponding `/uncertain` tests, require a restart:

```text
FAULT_READY ROOT_RESTART_REQUIRED operation=link.key_grant request_sha256=<64 lowercase hex>
FAULT_READY ROOT_RESTART_REQUIRED operation=link.review_policy_grant request_sha256=<64 lowercase hex>
```

Treat the operation, exact test name and request digest as the event identity;
reject repeated or mismatched markers. Before each restart, the authorized
Root orchestrator must inspect the recorded Hub CID, exact image ID, state
mount, run label and Hub identity, then restart only that CID. It must verify
post-restart health, identical Hub identity and unchanged fixed origin.
The Go test never has Docker socket access, production credentials or restart
authority. Preserve the failed gate if any invariant or deadline fails.

## Recorded offline validation — 2026-10-10

The tested source was dirty `dev` on
`c9b2935da17167ce7694abaeffca22aaa0daa3f2`. The final QA fixture inventory was
`a71c4bf4018669117ee72056ea53ed286cf4789bd4f53d329e9e8cdc1fe0b70c`,
covering the five Go files below and this runbook before this validation section
was appended. Its runbook input SHA-256 was
`cb9213ee3255f78276216cac8abe35de2764a9e4aaaef87749b0dc60df3b8c5f`.
This six-file inventory is not a complete Hub build-input fingerprint, and
the dirty artifacts cannot be attributed solely to HEAD. This documentation
revision changes none of the five tested Go inputs.

| Frozen Go input in `cicada-go/cmd/client-recovery-fixture/` | SHA-256 |
| --- | --- |
| `docker_test.go` (existing, unchanged) | `d20bf2924f2734700b2bdfd08d72cb995991ed49c5466945b5b6f094e6dd9da6` |
| `link_proxy.go` | `841c8ff05de84ec6beb85082f5ba6514d40f1131e6c404649c736191c3241480` |
| `link_proxy_test.go` | `a172d3f3b268ab70a71b5864d5220e793ea28937d0f10f61a458cc5768e80cb2` |
| `main.go` | `fa088fd9c4d345cfc35e512e9372e98a37e7ffd256f4a98db7506674668e4b75` |
| `main_test.go` | `941b490b24f902f2c386fd8b173f33bdadebf7063f61a3189a3e5591c12d37ca` |

All final commands used the offline compiler image
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
network disabled, nonroot UID/GID 1000, read-only source/module cache and a
private writable Go cache. Limits were 2 CPUs, 3 GiB memory and 256 PIDs;
capabilities were dropped and `no-new-privileges` was set. Fixture Go hashes
were verified unchanged afterward. No Hub runtime container, Node or model
was launched by these offline checks. All five owned compiler containers
were removed and their exact recorded IDs were verified absent.

| Final-source check | Actual result |
| --- | --- |
| Normal `^Test(LinkFaultProxy\|RecoveryFixture)` | **PASS**, exit 0, 6 top-level + 11 subtests, zero failures/skips; package execution **21.662 seconds** |
| Fourth limited race command | **FAIL**, exit 1, package timed out at 180.046 seconds; 3 top-level + 2 subtests had individually completed **PASS**, zero observed data-race warnings; lifecycle had no terminal result |
| Independent `-race -run '^TestLinkFaultProxyServeLifecycle$'` | **PASS**, exit 0, 1 top-level, zero failures/skips; test execution **32.55 seconds** |
| `go vet -p 2 -mod=readonly ./cmd/client-recovery-fixture` | **PASS**, exit 0 |
| `go build -p 2 -mod=readonly -buildvcs=false` | **PASS**, exit 0 |
| `go test -c -p 2 -mod=readonly -buildvcs=false` | **PASS**, exit 0 |

The fourth race command selected KEY/NONE response loss, restart readiness,
unsafe ingress and lifecycle. Its individually completed top-level tests were
`TestLinkFaultProxyRealHubRecovery`, `TestLinkFaultProxyRestartReadiness` and
`TestLinkFaultProxyRejectsUnsafeIngress`; the two completed subtests were the
KEY and NONE `response-loss` cases. The independent lifecycle check completes
that narrow per-test coverage. It does **not** turn the fourth package timeout
into PASS or constitute a full fixture race matrix. The ordinary eight-case
Link matrix took **14.20 seconds**. Those timings exclude compilation and
provide no performance guarantee for a new Hub image or coordinated restarts.

Earlier evidence remains unchanged: first normal attempt exited 1 with
2 top-level PASS / 2 FAIL and 3 subtest PASS / 8 FAIL due to the fixture's
stale lease epoch; second normal attempt exited 1 with 4 top-level PASS /
1 FAIL and 8 subtest PASS / 3 FAIL because it mistook the old default NONE
head's `Current=true` for current proof acceptance. Both fixture defects
were corrected. Third normal passed 5 top-level + 11 subtests on its earlier
fixture inventory; its race run exposed the unsynchronized test event-buffer
read and was stopped by Root with launch exit 143. Its observed failures
and unfinished checks remain recorded. Final-source tests synchronize that
observer and include actual Hub-listener readiness. Old successes are not
transferred to the final source.

The operator-held `scoped-final.receipt.json` records these exact test scopes,
source inventory, compiler image, preserved prior evidence and artifact hashes.
Its final log digests are:

| Evidence | SHA-256 |
| --- | --- |
| `fourth.normal.jsonl` | `e63f52d44b2adfee784cfc08fbb7168d536dd728b4fec552368470158dafd6f0` |
| `fourth.race.jsonl` (timeout FAIL) | `abcd25c87813a21c7e0f713747209a1a1ceea6325e148228b907a34eccbae0e3` |
| `lifecycle.race.jsonl` | `a6983cc9c327805bab68bd9acdf838bdd3f73e02c8f535e65ce1a62029504ff0` |

| Artifact | SHA-256 |
| --- | --- |
| `client-recovery-fixture` | `5e0b7079f571cd5a5f58142d1ae7517c27bc8d1217b3f672b97091bf841f9084` |
| `link-recovery-fixture.test` (non-race test binary) | `92a1ddb7db00d51ef7962f7b8df24f0f2c49d19499c33b1104579f773a20b862` |

Both exported artifacts report Go **1.27.1**, Linux/amd64 and
`CGO_ENABLED=1`; their source is the frozen dirty fixture above, built in the
specified bookworm compiler image with `-buildvcs=false`. A current-image
interop runner built with `CGO_ENABLED=0` is a separate artifact and requires
its own source/image and outcome evidence.

At this earlier offline documentation checkpoint the current-image
eight-scenario Go gate and its two Root-owned Hub restarts were **NOT_RUN**. Android, actual native
Runtime, physical device and public HTTPS are separately **NOT_RUN**. There
was no APK build, Owner consent frame, online Client signing or production
state change. Historical Android acceptance stays attributed to its original
source/APK/Hub pair.


## Recorded current-image Go validation — clean b06, 2026-10-10

Root ran the dedicated eight-case gate on clean
`b06a558f04cf92113df37d089ce1de7e81ba3c99`. It passed **1 top-level + 8 subtests**,
zero failures/skips, with package execution **15.383 seconds** and complete
operator execution **115.433 seconds**. Both KEY and NONE covered response loss,
processing, uncertain and unavailable. Both uncertain cases required actual
Root-owned Hub restarts; marker-to-matching-ready times were **1.089** and
**1.343 seconds**, within separate absolute 45 second deadlines.

| Actual tested identity | Value |
| --- | --- |
| Complete source inventory, identical before/after | `e9d5c6be2754ec3a89b79973fa95087a6f6a214d9b2902213c5b07aefde2441b` |
| Hub build-input fingerprint | `7a8b99036b32e7d4727ab7011a53fa477854505cabfbdeccb8bc54baed7580d5` |
| Hub image | `sha256:4a62048ac6389bea92c43aa73e225a9afa946f7deb3400b821e76d654db93b68` |
| Test image | `sha256:1f835ee325f28e2b1eb69f0b4a45c516c353399446550ec01aaa414b800fa62c` |
| Catalog | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Root gate result | `e66b2866ad99e6eb5f6a8c0eff263f31c61bc68b3f814401a8f3e55813a83ff3` |
| Independent Root postcheck | `45387856a6b4ff6b7c73a8427991642c4f9741475a7d6107f4ed033db86b39dc` |

Owned cleanup was CONFIRMED, source and six residents unchanged. The independent
postcheck was `PASS_LINK_SCOPE_ONLY`: complete source rows, resident IDs,
Config/HostConfig/full Mounts sorted by destination/StartedAt and private evidence
hashes matched; exact Hub/test CIDs, run label, image tags and owned scratch were
absent. Cleanup of image tags does not assert continued image-ID availability.
These identities are the actual PASS artifacts, not either failed predecessor.

Two earlier Root operator failures remain preserved. The first took **63.539s**
and failed `CIDFILE_CONTENT` when Docker's initially empty cidfile was read;
zero Go cases ran. Its result SHA is
`0ffb6f78ecfc2e76aed76099f233491dacf866a79e85850954023f19ebbb8a19`;
original failed cleanup was followed by a separate verified Root cleanup.
The second took **139.432s** and failed `GO_TEST_FAIL`: the compiled Go test binary
could not execute on a default noexec tmpfs; package fail elapsed was **0.001s**
and zero Go cases ran. Its result SHA is
`a61e15914935d8ecaba49f9db7af97c49fdebead6da51cc837bfc22359920e57`.
An actual network-none mountinfo probe established the noexec cause. The successful
runner used explicit exec; Hub tmpfs retained noexec. Only Docker Mounts array
order was normalized; no Config/HostConfig/mount values were ignored.

This PASS accepts the actual Hub's synthetic Go original-packet recovery and
fresh separate-session reconciliation. It does not establish current Android
recovery, native Runtime, physical Android, public HTTPS, a committed grant in
outer-only fault modes, or arbitrary actions exactly once. Those runtime
acceptances remain separately NOT_RUN in this Link scope; F38 retains its own
original source/APK/Hub attribution. Production Guard/Owner signatures, wire,
catalog and `external_thread_links=false` are unchanged.

The reusable command added by this subsequent change is
`scripts/test-client-hub-interop.sh --suite client-link-recovery`. It builds fresh
owned images through the existing builder, uses the existing cleanup helper with
lane `client` and a distinct Link suite, explicitly selects this Go test, and
coordinates only the two exact Go JSON uncertainty markers on that owned Hub.
The command is implemented in source. Its initial 17 deterministic helper tests
and independent review passed. The first actual reusable-suite execution failed
before any Go test started: phase `protocol_test`, helper `OWNED_MOUNT`, no
restart marker or runner exit. Its result SHA-256 is
`a9f5e58561942b5f270e0f0a99a675e969218d07f8643dd3cd3b036d03e0b4bd`;
helper receipt `64108f37a210ca2dfb06d7773578579654e8898eaf7c8b50ee3101629331ecc9`.
Cleanup was CONFIRMED, receipt
`7a7de2c3610cd6e9e723c9046991886feb2974eb828e75eb233e8184ed72f8a9`.
The sanitizer also tried to read an absent raw file; this secondary failure
does not replace the original preflight FAIL. This attempt has zero Go tests,
with protocol coverage NOT_RUN. The second actual reusable attempt also failed
before any Go lifecycle was observed: `RUNNER_CHANGED`, result
`7db306d966fb11640985f087f3db6a41ca5a03ffd40a13c6958b061b8c77f907`,
helper receipt `c9c3eb6d1dbb41d3d7f3f1878db2804d166d8f2bd93de52bcfd468dd8b4c5cd9`.
Both real kernel tmpfs projections passed, but tests/restarts remained empty.
Cleanup was CONFIRMED, receipt
`15fc74bb19c9b87d4b005fd261b4e8967f077f35f529fda16e552f68e7593a6b`;
build source and six resident digest rows matched before/after. The raw log was
empty and the missing-raw sanitizer error did not recur. The corrected reusable
workflow subsequently passed in T1120, recorded below; both FAILs remain intact.
The clean-b06 result above belongs to the Root operator and is not transferred
to this changed workflow/source.
Resident configuration and environment values are compared through full
canonical-state digests; evidence stores no environment values or arbitrary
label text. Command output is limited during streaming reads, and initial
workspace/state bind mounts are inspected explicitly. Docker's actual Created,
Running and Stopped inspect API omits `--tmpfs` from `Mounts`; the exact tmpfs
declaration remains checked in `HostConfig.Tmpfs`. Each Running owned PID is
checked through bounded `/proc/PID/mountinfo` reads with matching UID and two
inspect snapshots confirming unchanged PID/StartedAt. Only the fixed `/tmp`
filesystem/flags/size projection is recorded. Created state cannot provide a
kernel PASS. An explicit `/tmp` Mounts entry, if present, remains strictly
validated. The missing-raw sanitizer now records NOT_RUN and preserves failure.
Bind Mode/Propagation must match the retained real snapshots (`""`/`rprivate`).
Missing preflight evidence preserves Docker-unavailable BLOCKED; a prior PASS
is downgraded when those required inputs are absent.
The real Created→Running Docker probe found only `HostConfig.OomKillDisable`
changing from false to null. The owned runner comparison accepts only that
default equivalence, rejects true/unexpected types, and records original full
canonical hashes and original field values. Resident digests keep every field
unchanged and still reject a false/null change.
The corrected helper's targeted offline suite passed 26 tests (zero failures or
skips), with independent G4 review PASS. These parser/identity tests execute
no Docker; the actual corrected-source gate is recorded separately below.
Android original-packet use remains the existing `serve-link` workflow above.

<a id="reusable-link-gate-pass"></a>

## Reusable Link gate actual PASS — dirty b06, 2026-10-10 T1120

```sh
scripts/test-client-hub-interop.sh --suite client-link-recovery
```

Root executed this corrected reusable command once: **PASS**, exit 0,
**113.7468 seconds** outer and **15.409 seconds** Go package. One top-level test
and eight KEY/NONE subtests passed, with zero failures/skips; both ordered
markers caused real restarts of the exact owned Hub and passed. This result
accepts the isolated synthetic Go original-packet recovery and fresh separate
reconciliation scope. It contains no model, Native Runtime or Android run.

| T1120 actual provenance / receipt | Value / SHA-256 |
| --- | --- |
| Git revision | `b06a558f04cf92113df37d089ce1de7e81ba3c99` |
| Build source state | **dirty=true**, full input inventory retained; not clean b06 alone |
| Source fingerprint | `7a8b99036b32e7d4727ab7011a53fa477854505cabfbdeccb8bc54baed7580d5` |
| Catalog | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Hub image | `sha256:f4c1782e6441810f97f67810687fee73463070e287c88376417e51817ee25453` |
| Test image | `sha256:a23efb39db7d0713aa23b9e10cb87dcde48559701864d3faa4744f947662b818` |
| [Build provenance](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/build.json) | `56986def70b0b985514286c8dd6a6d76fab47a71c9732b2a252d7c50142016a7` |
| [Gate result](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/result.json) | `24f37f0c20fe7f88488233175f852edd56aa633dcb102855252d44dbd84ff975` |
| [Helper receipt](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/link-recovery.json) | `e7520ee9e03b488b63c0663e5f2966975447a69f108fff415d0df4b6769aade0` |
| [Cleanup receipt](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/cleanup.json) | `9105bc80c6418cc0693d38efd787525d5b338d139e5c2b7989557a98da65ce62` |
| [Independent Root postcheck](../.cicada-data/architecture-v2-completion/client-link-recovery-root-20261010T1120/ROOT-POSTCHECK.NONAUTH.json) | `0d334df6ea77ddb0764a6413b1ea515ec6b9524409581f2cca8a1f92551cbd5f` |

Cleanup was **CONFIRMED**. Complete source rows before/after and six resident
Config/HostConfig/full canonical Mounts/StartedAt snapshots were unchanged;
owned scratch and four recorded owned resources were absent. Root's postcheck
explicitly records whole-repository source clean **false**. The new image IDs
above belong to this dirty-source PASS; the earlier clean-b06 PASS and both
zero-Go reusable FAILs retain their own original artifacts and receipts.

Current Android original-packet recovery, remaining real native Runtime,
physical-device and public-HTTPS acceptance remain separately **NOT_RUN** in
this Link scope. For Android use, the existing `serve-link` workflow above
requires the Client's own original encrypted request; this Go suite uses its
own fresh synthetic originals and supplies no Client approval or packet.
Outer-only faults still prove no committed grant or arbitrary exactly-once
execution. Wire, catalog, capabilities, Guard/Owner signatures and
`external_thread_links=false` remain unchanged.
