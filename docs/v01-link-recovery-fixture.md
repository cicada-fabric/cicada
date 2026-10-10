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

Current coordination is manual or supplied by a separately authorized Root
orchestrator. `scripts/test-client-hub-interop.sh` has four existing suites;
neither its selectors nor the test image's default ENTRYPOINT runs this new
gate. Building the existing images is still done with
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

At this documentation checkpoint the current-image eight-scenario Go gate
and its two Root-owned Hub restarts are **NOT_RUN**. Android, actual native
Runtime, physical device and public HTTPS are separately **NOT_RUN**. There
was no APK build, Owner consent frame, online Client signing or production
state change. Historical Android acceptance stays attributed to its original
source/APK/Hub pair.
