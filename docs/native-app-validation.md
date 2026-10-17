# Native App validation

This record covers the bounded Core, wire-helper, and local issuer checks for
the Native App foundation. The commands ran on 2026-10-15 against the shared
dirty development worktree based on `2afcc860da716bf3e9e574d9049a35d6dbba0081`.
The results belong to that tested source state, including its uncommitted files;
they are not attributed to the base revision alone. They do not qualify a
release or a native Windows runtime.

## Product behavior exercised

The Core tests use a private synthetic Hub Store and a real loopback TCP HTTP
server. They drive claim prepare/complete, login prepare/complete, session
inspect, and logout through the Hub handler and App packet sealing/opening. The
fixture checks exact lost-response recovery after controller/vault restart,
including the case where a proxy returns an unsigned 403 after the Hub has
accepted the packet. The App retains the original ciphertext and retries only
that exact request. A forced vault failure before send produces no HTTP request.
The flow leaves Root in `PENDING_PROOF` and does not expose Manager authority.

The existing-Owner import test verifies an imported synthetic keypair is kept
as-is in the encrypted local vault. Import does not enroll an App device, send
account requests, activate Root, or create a grant. The account code/framing
tests exercise canonical parsing and reject malformed or URL-like values. The
local issuer tests verify the compact code is omitted from ordinary output,
written only to a new 0600 file when requested, or displayed only after the
real terminal check succeeds.

These tests use generated public cryptographic fixtures and isolated temporary
state. No resident Hub, production key, credential, or deployment state was
used.

## Commands and results

All Go commands ran in
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
with the shared module cache mounted read-only and network disabled.

```sh
go test -mod=readonly -p=2 -count=1 -timeout=90s ./internal/appcore ./internal/hubaccountwire \
  -run '^Test(ExistingOwnerImportCreatesEncryptedLocalVaultWithoutAuthority|ControllerRealHTTPAccountFlowAndExactUncertainRecovery|OwnerAccountClaimCodeRoundTripAndStrictFraming|ActivationAndConnectionCardBoundaries|NativeCoreSnapshotAndPasswordPreflight)$'
```

PASS: `internal/appcore` and `internal/hubaccountwire`.

```sh
go test -mod=readonly -p=2 -count=1 -timeout=90s ./cmd/cicada \
  -run 'TestHubAccount(ClaimIssueProtectsCardAndHidesCodeFromDefaultOutput|AppCodeDisplayRequiresAndUsesInteractiveTTY|ClaimIssueRefusesAfterPermanentRootHistory)$'
```

PASS: protected claim/code issuance, default secret suppression, interactive
code display, and refusal after permanent Root history.

```sh
go test -mod=readonly -race -p=2 -count=1 -timeout=120s ./internal/appcore ./internal/hubaccountwire
```

PASS: appcore in 31.719 seconds; hubaccountwire in 1.645 seconds.

```sh
go vet -mod=readonly ./internal/appcore ./internal/hubaccountwire ./cmd/cicada
```

PASS: no diagnostics.

The unified native foundation gate then passed from the frozen Go source tree:

```sh
scripts/test-native-app.sh
```

PASS: 55 test events, 0 failures, 0 skipped tests across the eight packages
with test files. The ninth package, `cmd/cicada-app`, compiled but has no test
files. The before/after Go-source manifest matched at
`b5f32aab304ce52c0631bb59f0f78f36cd544aa47e72d1abc0d7facd677bd689`. The run
used the same pinned builder image, with a visibly synthetic OpenSSL fixture
configured for the selected key-import tests.

After the gate, the runner's default module-cache path was changed to the
canonical shared `.cicada-data/m1-gomodcache`. That script-only adjustment did
not change Go source. After the shared module cache was merged without
overwriting existing entries, `go mod verify` passed for all modules. Root then
reran the same gate using the canonical cache: 55 passed test events, 0
failures, 0 skipped tests, and a stable before/after Go-source manifest
`099bbc8ba2f8e72eeba8174c065c6b183fba6ceeec5cf3e7565c4a774e4ac5ee`. The only
manifest difference from the first run was the runner script's cache default;
the Go sources were unchanged. The Windows binary was byte-identical to the
first gate.

The latest machine-readable result is
[`validation.json`](../.cicada-data/native-app-foundation/run-20261015T061122Z-CiZENQ/validation.json),
SHA-256 `19ab32b935cefa34449285c83448451dac8077991a81559b3dbfbc4c9a9333b5`.
The initial pre-cache-change gate remains at
[`the first result`](../.cicada-data/native-app-foundation/run-20261015T060350Z-UNLVmo/validation.json),
SHA-256 `281c7f756e2dc5ce4cd4c94d9279a1773bd7404f56961f2ced7ff6afe36f4806`.

The same gate cross-built the Windows GUI executable with
`CGO_ENABLED=0 GOOS=windows GOARCH=amd64`. The binary is 12,674,048 bytes with
SHA-256 `d1755e06e505779359d8bb9f742093bfc72bd3197d389deb568c0c89ee61d448`.
This proves cross-compilation only; Windows runtime execution is `NOT_RUN`.
The build dependency audit listed 141 non-standard packages, recorded in the
artifact directory. The native App has not passed Windows DPAPI/ACL or
real-desktop execution checks.

Both gate result files record `source_head` as
`2afcc860da716bf3e9e574d9049a35d6dbba0081` and `source_dirty: true`; their
results belong to the matching tested manifests, not to that base revision
alone.

An earlier mixed preflight is retained at
[`foundation-tests.jsonl`](../.cicada-data/native-app-root-20261015/foundation-tests.jsonl),
SHA-256 `6ec1af34ffbd1c00f2488982d1b5a08bb29b872aea8b07debd9c90d207969369`.
It recorded 13 appkeys/appvault test passes but failed the dependent UI build
because the first exported claim-code size expression called a function where
a compile-time constant was required. The expression was corrected; the
final unified gate above passed. The earlier failure remains an intermediate
preflight result, not a current product failure or a pass.

## Disposable standard Client interop

The official standard Client Docker interop suite passed against a disposable
Hub built from the same dirty base revision, with source fingerprint
`bf9494948f45ff4f19a32b2d3c930a0d7597497950d63a5c62b5aea1a5948f05` and image
`sha256:c32da42c3a6c3378e5b71e50d37c65be011f7f930dea073b9c6a618f89c928cd`.
Smoke, recovery-fixture, headless-operator, and Owner-bootstrap tests all
passed; the runner exited 0. Cleanup was confirmed for the disposable
containers, images, and scratch directory, and Root independently verified
the six resident container names were unchanged. No resident image was
replaced.

The result is
[`result.json`](../.cicada-data/native-app-root-20261015/hub-interop/result.json),
SHA-256 `c890f662963baa9b9dfbd9d67538c117f3be9d1f7049655a051f10d302ca22ea`;
cleanup evidence is [`cleanup.json`](../.cicada-data/native-app-root-20261015/hub-interop/cleanup.json),
SHA-256 `c6a802d5297743f2d519fa1167549eff2b231ac9bd1d3025677dc74ca7a8c231`.
This gate validates the existing standard Client protocol on a real TCP Hub.
It is not a native App end-to-end test: the result records native runtime,
Android, and public HTTPS as `NOT_RUN`.

## Limits and pending evidence

This is a selected deterministic Core/wire/CLI checkpoint, not a full Go
repository test run. The combined native UI/vault/key gate and Windows
cross-build passed on the same frozen Go source manifest; neither proves
native Windows execution. Standard Client Docker interop also passed, within
the separate scope above. Native Windows DPAPI/ACL execution, strict PQTLS
negotiation, Android, physical-device use, public HTTPS, and authorized live
canvas/Node actions are not established here. See the [ordered Native App plan](native-app-plan.md)
for the remaining checkpoints and the [current architecture status](architecture-v2-status.md)
for broader product evidence.

The current GUI-facing error state cannot treat an unsigned HTTP status as an
authoritative account rejection. Consequently, if the Hub did not accept a
claim/login packet but an intermediary returns an unsigned error, the App
keeps the exact request uncertain and offers exact recovery; it does not issue
a replacement request or discard the pending packet. Basic password length
and encoding checks run locally, while authoritative policy feedback requires
a validated encrypted Hub response. This is a deliberate N1 recovery bound;
it does not grant account or Root authority.

## N2 independent account baseline

On 2026-10-15 the independent acceptance task reviewed the Hub account service,
Owner bootstrap service, App Controller, scoped encrypted vault and existing
ML-KEM-768 / ML-DSA-65 / AES-256-GCM wire code at base `c1b6a30`. N2 activation
and controlled legacy continuation were absent from that source. The threat
model is in [architecture](native-app-architecture.md#n2-independent-threat-model)
and the complete fault matrix is in [the plan](native-app-plan.md#n2-independent-acceptance-matrix).

The new `cicada-go/acceptance/n2` consumer starts the production Hub
identity/account handler with no Control service. Both Hub and App run in
separate subprocesses. A real TCP proxy injects loss before forwarding, loss
after a successful Hub response, an unsigned 403 after commit, and a corrupt
PQ response. For each of claim prepare/complete, login prepare/complete,
inspection and logout, the driver SIGKILLs the App and Hub, reopens the same
SQLite database and encrypted vault, and verifies the exact original request
hash and, after a commit, immutable original response hash. This is Linux App
core protocol acceptance, not Windows GUI execution or shipping Hub CLI
composition acceptance.

Additional negative tests cover full Hub pin mismatch and expired connection
material before vault creation/POST, two simultaneous distinct account claim
candidates, consumed exact versus resealed requests, foreign Hub/Owner routes,
missing/bad App signature/ciphertext, substituted login-device key and
cookie-only inspection. The accepted account remains `PENDING_PROOF`; no
Root or Manager authority is created.

```sh
scripts/test-native-app-n2.sh
# Full acceptance must remain nonzero until the N2 lane exists:
scripts/test-native-app-n2.sh --require-n2
```

The baseline run `run-20261015T123219Z-IyTWRS` exited **0 / SCOPED_PASS**:
58 passing test events, zero failures and zero skips. Compile, process lane,
existing guards, vet and version commands each exited 0. It used the offline
Go 1.27.1 image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
with read-only shared modules and an exclusive task build cache. No host port
was published; loopback TCP stayed inside the network-disabled disposable
container. The owned container was absent afterward.

Evidence is retained outside the repository at
`/home/zyf/Cicada/.local/evidence/n2-acceptance/run-20261015T123219Z-IyTWRS/`:

| Artifact | SHA-256 |
| --- | --- |
| `result.json` | `6df637833f4ffcb84ab18163a27a1e9f1f5a7a2b26f35e005968f5e48e62ca94` |
| `artifacts.sha256.json` | `db84f6faad624b152f4240d81ec2a430afad1a102910e2134c6e2fdcf941d49e` |
| Exact Linux test binary | `76c17dc5cae8ed1998e44f1bc0b0a0bd56e4160946c3fc65d6a5851ea69f7dab` |
| Source manifest identity | `f690cf8759de7c34ea184d969d013825e1785d014a937e1a55fcf568667bb0ce` |

The source was dirty, based on `c1b6a30`, and stable during that run. Its
manifest, rather than HEAD alone, identifies what was tested. Later driver
changes add portable workspace discovery and explicit resident-container
ID/name/image/start-time comparison; they were not part of that receipt.
The earlier `run-20261015T123111Z-ysm9I6` exited 1 because of acceptance-fixture
cleanup lifetime, nanosecond expiry construction and error-code assertions;
those harness errors were corrected. Its failure is retained and is not a
production defect or an N2 pass.

The baseline's deliberate fail-closed response handling also exposes an N2
recovery requirement: wrong-password rejection and expired/revoked sessions
need an authenticated terminal result or an operation+digest fence before
allowing replacement login. Unsigned HTTP errors alone cannot clear pending
state. This requirement was handed to the Hub/App owners and remains pending
in the N2 matrix. Full activation, exact legacy continuation, expiry/late
lease guards, status fencing and profile discovery are **NOT_RUN** in this
baseline. Windows DPAPI, ACL, GUI and visual review are individually
**NOT_RUN**, as are Android, native Runtime, physical device, public HTTPS and
native PQTLS. The integration owner runs the separate standard Client Docker
interop gate after integration; it is not run or claimed by this lane.

The final preparation driver was rerun with explicit resident selection:

```sh
CICADA_N2_RESIDENT_NAMES=cicada-client-hub-v1-2-manager,cicada-client-hub-v1-2,cicada-client-v11-emulator,cicada-client-hub-v1-1 \
  scripts/test-native-app-n2.sh --require-n2
python3 -m unittest discover -s scripts -p test_native_app_n2_evidence.py
```

Run `run-20261015T123800Z-6ulAdI` recorded **SCOPED_PASS** for the same 58 events,
zero failures/skips and five zero-exit lanes. The overall exit was **3**, as
required while N2 is NOT_RUN. Source manifest
`c320615f8629a5f966bf8744597a7367683b7ed2b67da50f7854b892f4a840aa`
was stable; the binary hash stayed `76c17dc5cae8ed1998e44f1bc0b0a0bd56e4160946c3fc65d6a5851ea69f7dab`.
All four resident container IDs, names, immutable images and process start
times matched; the owned container was absent. Result SHA-256 is
`a9b0ada5f2d1e3c1901ddfb69e53a3f753f152dd43062c56072ef5f5baeb3dc4`,
and artifact index SHA-256 is
`939a1146e2a4f608754f9f3c88b6ddab7f1e096b64dd06178b2af308e85df89c`.
The two evidence-tool unit tests passed, including refusal to pass an empty
zero-exit test log. Shell syntax, Python compilation and diff whitespace checks
passed. This remains dirty-source evidence, preceding its documentation update.

An intervening run `run-20261015T123609Z-oXVOm5` also passed all 58 events but
exited 1: its initial resident-discovery heuristic included a concurrently
running anonymous `--rm` Go test container, which then exited. Actual resident
Hub/emulator identities were unchanged. The driver now excludes auto-remove
fixtures by default and supports the explicit resident-name list above. This
is a retained harness classification failure, not a product failure. No
container belonging to another task was modified.

## N2 stable toolchain and dependency checkpoint

The preparation source was advanced by the integration owner to `8a5bb901`.
The task then checked the stable upstream versions on 2026-10-15 using the
[Go release feed](https://go.dev/dl/?mode=json), the
[official Go module proxy](https://proxy.golang.org/),
[Alpine release list](https://www.alpinelinux.org/releases/) and
[Node download page](https://nodejs.org/en/download/current). It selected Go
1.27.2 while preserving the minimum Go language version 1.26.0. Go builder pins
and current CI/release/WebCrypto checks were updated together. The standard Hub
runtime pin is Alpine 3.24.2; Ubuntu 26.04 and already-current Gio 0.10.3,
CIRCL 1.6.5, websocket 1.8.15, flock 0.13.1 and isatty 0.0.24 are retained.

| Module | Previous → selected stable version |
| --- | --- |
| `golang.org/x/sys` | 0.48.0 → 0.49.0 |
| `modernc.org/sqlite` | 1.59.0 → 1.60.1 |
| `golang.org/x/crypto` | 0.54.0 → 0.58.0 |
| `golang.org/x/image` | 0.26.0 → 0.47.0 |
| `golang.org/x/net` | 0.56.0 → 0.61.0 |
| `golang.org/x/text` | 0.40.0 → 0.43.0 |
| `github.com/dustin/go-humanize` | 1.0.1 → 1.1.0 |
| `github.com/godbus/dbus/v5` | 5.2.2 → 5.2.4 |
| `github.com/ncruces/go-strftime` | 1.0.0 → 1.1.0 |
| `modernc.org/libc` | 1.75.7 → 1.78.0 |

The existing `x/exp/shiny` pseudo-version is retained because upstream has no
stable tag and Gio already pins that revision; the current `bigfft`
pseudo-version remains unchanged. No untagged upstream branch was selected by
an unrestricted upgrade. New modules were fetched and verified only in the
exclusive task cache, seeded from immutable original cache files without
writing the original shared cache. The completed consumer cache is
`/home/zyf/Cicada/.local/cache/n2-acceptance/gomod-go1.27.2-stable` and must be
mounted read-only by other tasks. Small transitive graph metadata was also
resolved before the offline verification below.

The fixed builder is
`golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`;
the standard Alpine builder is
`golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d`.
The runtime is
`alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`.
Historical fixed native-observer/artifact bindings and earlier receipts are
unchanged.

```sh
CICADA_N2_GOMODCACHE=/home/zyf/Cicada/.local/cache/n2-acceptance/gomod-go1.27.2-stable \
CICADA_N2_GOCACHE=/home/zyf/Cicada/.local/cache/n2-acceptance/go-build-go1.27.2-stable \
CICADA_N2_RESIDENT_NAMES=cicada-client-hub-v1-2-manager,cicada-client-hub-v1-2,cicada-client-v11-emulator,cicada-client-hub-v1-1 \
  scripts/test-native-app-n2.sh --require-n2
```

Run `run-20261015T125602Z-2p0YUR` passed **75 test events, 0 failures, 0 skips**,
including the six new frozen activation/reconcile wire-helper tests. All five
lanes exited 0, the full Go/embedded-input manifest was stable at
`ec7318a04cae3eefe24f3642fba6b3fe304684a03afea51a58d55008c2061fef`,
and resident identities/start times were unchanged. Overall exit **3** still
correctly reports that the server/App N2 integration lane has not run. Result
SHA-256 is `dee0bf15e30ff6e4645cba87ecbc6d1be5d8d3e589dd2d51ec4505d96c8e96e0`;
exact test-binary SHA-256 is
`2108628448efd1748d031e68696c2632a87d25c8fdf3715ce54d19f319479870`.
These are dirty-source results based on `8a5bb901`, preceding this record.

A separate network-disabled, read-only-module-cache container completed all
four commands with exit 0: Windows amd64 App cross-build, JS/WASM WebCrypto
build, `go mod verify`, and `go list -mod=readonly -m all`. The App binary is
`f0a17af3dbb95da6381f8232d9c7a347dd807ccccaa5d4dd525f8a880d8adb7c`;
the WASM binary is
`c629de331c2b1f729f08a78f42864daa5f3c8f005c8a7dfefd7f571e13adaad5`.
They are dependency-closure artifacts, not the final integrated N2 delivery.
The 22 selected release/installer/ELF metadata tests passed without skips. The
broader packaging run exited 0 with six optional artifact/stage tests skipped;
those six are **NOT_RUN**, not passes. The two N2 evidence-unit tests, contract
metadata checks, shell/Python syntax and whitespace checks passed.

Evidence resides in
`/home/zyf/Cicada/.local/evidence/n2-acceptance/dependency-update/`.
`result.json` SHA-256 is
`a12d5950431e7b88a000a136bd41c616755d62623ecb58e42bfaa4033715ade9`;
the evidence-index SHA-256 is
`84be2ce227ac1387e64e406b25154cd5e4afef9d0e5711f9faf5610548b2bd4f`.
The first platform command group compiled both targets and verified modules,
but exited 1 at module-graph listing because small graph metadata was absent.
After metadata completion, the same offline group exited 0. An optional
`go mod tidy -diff` preflight also exited 1 because dependency packages' own
font/test/tool fixtures were absent from this bounded cache; it did not modify
source. No claim is made about running upstream dependency test suites.

The integration owner's earlier `profile-integrated-go1272.jsonl` recorded
58 passing and 9 failing events: the old fixture incorrectly assumed the last
POST was the recovered inspection. New App profile recovery first retries the
exact pending inspection, then issues a distinct current-state inspection.
The fixture now compares the first request and original accepted response
**byte-for-byte in memory**, then requires exactly one fresh inspection before
the helper reports current account state. Other operations still require only
the exact retry. Payload bytes are never logged. The adapted 58-event run
`run-20261015T124521Z-nSoDWc` and the 75-event stable-dependency run both passed.
The original integration failure remains attributed to its old oracle.

Node 26.12.0 was installed only in the task cache from its official archive,
verified against official SHA256SUMS; archive SHA-256 is
`fd47865ecd6391ebb431fc815e01b9135bf83ded5cf373247e9331e196b7aded`.
The WebCrypto developer script accepts Node 24 LTS or 26 and reports the actual
runtime used. Full WebCrypto UI interoperability waits for the Hub owner's
production manifest assertion to accept Go 1.27.2; that production JS change
is outside the independent acceptance writer's scope. OpenSSL 3.5.9 was used
only to generate new visibly synthetic PQ PEM fixtures; it is the selected LTS
fixture tool, separate from current OpenSSL stable 4.0.3 and from the App's
Go cryptography/runtime requirements. Native Windows GUI, DPAPI, ACL, visual
review, Android, native Runtime, physical device, public HTTPS and PQTLS remain
**NOT_RUN** at this checkpoint.

## N2 Hub/App integration

The additive [owner-activation-v1 contract](hub-owner-activation-contract.md)
and schema 62 are implemented in Hub and native App core. Independent consumer
`cicada-go/acceptance/n2` runs through
`scripts/test-native-app-n2.sh --require-n2`. Final independent Linux protocol
acceptance is **SCOPED_PASS**, exit **0**, **131 passing test events, zero
failures/skips**, after App recovery correction `d5b5609`. Partial/debug attempts
remain separate failed receipts.

The integrated starting point was `8db5be151dc1bf0e9be6d81cc0d1c8e8e2d48e8d`,
including Hub receipt correction `ae09f3d`, CLI identity-path correction
`ad87be8` and App checkpoint `070137c`. Each independent run also records the
dirty source manifest, embedded Hub inputs, contract, driver, test binary and
pinned builder. HEAD alone does not identify that binary. The [matrix](native-app-plan.md#n2-independent-acceptance-matrix)
maps every obligation to actual tests and their layers.

The final gate ran on integrated source
`079249dee906c84ead0d2d331eeb400ad018ea03` plus the dirty independent acceptance
consumer/driver/documents. Run `run-20261015T143305Z-KPWsvS` has before/after
manifest **`f91a31375d3c9f9bdf469cd9551a6be454931fb5e374c2bcda0693283ed2e8e9`**.
Source was stable throughout all eight lanes: `version`, `compile`,
`account-process`, `n2-process`, `existing-guards`, `vet`, `n2-guards`,
`n2-race`, each exit 0. The baseline accounts for 75 passing events and the
additional N2 lanes for 56. Every required name/subcase passed; none was
missing. The owned container is absent; all four residents remained unchanged.

| Final independent artifact | SHA-256 |
| --- | --- |
| `.local/evidence/n2-acceptance/run-20261015T143305Z-KPWsvS/result.json` | `ae8e0710f8449baf56bb1f8b298f49bd318d229aee2a0cf36320db99d8e1d3fe` |
| Same run's `artifacts.sha256.json` | `45aed5986c0f89ffe0c91d43da436094c1d5292fee620b92ae7fc39bcb406cbb` |
| `.local/artifacts/n2-acceptance/run-20261015T143305Z-KPWsvS/n2.test` | `17b170696cffdcf88afe7b78e256d3401bdddfdb2a9cbfe3177974142f13852a` |

These paths are relative to workspace `/home/zyf/Cicada`, outside repositories.
The fixed Go image is the Go 1.27.2 bookworm digest recorded above. After this
gate, only documentation was updated with its outcome, provenance and manual
delivery paths; the run's immutable manifest and logs are not rewritten to
pretend they include that later receipt prose. Test/driver/build inputs remain
exactly those recorded by the passing gate.

The fixture runs the real Hub handler and App core in child processes, uses
real PQ envelopes over loopback TCP, and reopens disk SQLite and an AES-GCM
encrypted Linux password vault after actual Hub/App process kills. No Control
inference service runs. Account-only claim/login/inspect/logout keeps Root
pending; Owner proof and App activation still require separate ordinary login.
The lease permits only `nodes.list` and `session.capabilities`; general Manager
actions remain unavailable. A selected server-package dispatch test uses a
real Control object without model calls only to check its Guard/allowlist.

No shared Hub or resident database is a fixture. Docker has no external network
or host ports, runs read-only with dropped capabilities as the task UID, and
uses task-specific loopback ports. Every run owns a unique container name/label
and state/artifact/evidence directories under
`/home/zyf/Cicada/.local/{state,artifacts,evidence}/n2-acceptance`. Cleanup
requires the exact run label. Four resident containers are compared by ID,
image, start time and state without reading environment values. Modules mount
read-only; the task build cache has an exclusive driver lock. Synthetic private
state is not an evidence payload and is never a deployment input.

Reproduce in this worktree with the prepared module cache and synthetic PEMs:

```sh
umask 077
CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR=/home/zyf/Cicada/.local/state/n2-acceptance/synthetic-openssl-owner-8t2OKM \
CICADA_N2_GOMODCACHE=/home/zyf/Cicada/.local/cache/n2-acceptance/gomod-go1.27.2-stable \
CICADA_N2_GOCACHE=/home/zyf/Cicada/.local/cache/n2-acceptance/go-build-go1.27.2-stable \
CICADA_N2_RESIDENT_NAMES=cicada-client-hub-v1-2-manager,cicada-client-hub-v1-2,cicada-client-v11-emulator,cicada-client-hub-v1-1 \
  scripts/test-native-app-n2.sh --require-n2
```

Exit 0 requires every declared Linux test/subcase, eight successful lanes,
zero test failures/skips, stable source, cleanup and unchanged residents.
Exit 1 is gate failure; 2 means invalid/missing prerequisites. The default
command runs only the account/wire baseline. Historical preimplementation
`--require-n2` receipts returned 3 and stay NOT_RUN. Review `result.json`, lane
`.exit`/`.log`, before/after inventories and `artifacts.sha256.json`. Tests
record safe states, assertion names and hashes; no codes/passwords/tokens,
grants, private keys or complete encrypted packets enter evidence.

To renew the synthetic import fixture, select a verified OpenSSL executable
with ML-KEM-768/ML-DSA-65 support as `n2_openssl`. The tested tool was 3.5.9;
system OpenSSL 3.0.13 cannot generate these keys. Scope any relocated library
environment to those invocations. Never point this at a real Owner directory.

```sh
umask 077
n2_fixture=$(mktemp -d /home/zyf/Cicada/.local/state/n2-acceptance/synthetic-owner-XXXXXX)
"$n2_openssl" genpkey -algorithm ML-KEM-768 -out "$n2_fixture/kem-private.pem"
"$n2_openssl" genpkey -algorithm ML-DSA-65 -out "$n2_fixture/signing-private.pem"
"$n2_openssl" pkey -in "$n2_fixture/kem-private.pem" -pubout -out "$n2_fixture/kem-public.pem"
"$n2_openssl" pkey -in "$n2_fixture/signing-private.pem" -pubout -out "$n2_fixture/signing-public.pem"
chmod 0400 "$n2_fixture"/*.pem
chmod 0500 "$n2_fixture"
```

Set `CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR` to that path. The driver requires
exactly these four regular files, refuses symlinks, and mounts them read-only.

### Findings and retained failures

| Finding | Observation and disposition |
| --- | --- |
| Hub receipt bound | Actual prepare receipt exceeds 96 KiB, preventing old nested status recovery. Hub owner corrected the dedicated bound to 128 KiB in `ae09f3d`; ordinary Client 64 KiB and outer limits stay unchanged. Independent App recovery asserts actual large-receipt byte equality after restart. |
| Configured Hub identity path | Issuance could fall back from a configured missing key. Hub owner fixed `ad87be8` to require configured Peer and other transport identities before loading. Independent acceptance did not edit production code. |
| App A01: account re-login blocked by revoked lease | On `8db5be1`, epoch-2 reconciliation of an accepted epoch-1 login receipt did not revive old session/lease, but omitted `LOGIN`. Safe state: `LOGIN_REQUIRED`, `ROOT_ACTIVE`, lease `REVOKED`, `Confirmed=false`, no session-inspect action. App owner fixed `d5b5609`; independent targeted and final full runs both confirm new account login succeeds while lease stays revoked. |
| App A02: operator replacement after signed cancellation | `connect` rejected new material for the same full scope as `ACTIVATION_SCOPE_CHANGED` after authenticated terminal cancellation. App owner fixed bounded replacement in `d5b5609`; independent targeted and full runs confirm new material retains Owner/App keys/device ID. Unknown state, epoch rollback and established/revoked Root remain fenced by production-package regression guards. |

Full attempt `run-20261015T133952Z-T2kXgk` returned **1**. Account baseline,
guards, vet and two race cases passed; N2 process tests hit a malformed-proof
fixture's local preflight, leaving expected cases missing. The fixture now
uses existing lower-level sealing so invalid body/signature/device packets
actually reach Hub. A local constructor refusal is not a server rejection.
Debug `process-2.jsonl` similarly retains the local wrong-App preflight failure.
Debug `process-3.jsonl` then recorded 38 passing events and A01 failure; all nine
large-receipt fault combinations passed in that failed attempt.

Precise A01 log
`/home/zyf/Cicada/.local/evidence/n2-acceptance/full-debug/process-4-epoch.jsonl`
returned 1; SHA-256
`1b567423dd87895dd26e54e861c533c8f9d1cc164cfb9108e088a76f5c86f680`.
Its binary SHA-256 is
`79381664dc38d1ffb9b4f7785497e4fc806caed95ed638d15996c15352b84882`.
Debug 5 retained A02's subsequent connect failure after signed terminal
recovery; all three real credential/proof expiry/cancellation subcases passed.
Debug source snapshots/logs are retained separately. Only a complete stable
run establishes the final aggregate result.

After integration, `full-debug/process-6-regressions.jsonl` returned 0 for both
previous App failures and all nine cryptographic negatives. The wrong-purpose
fixture now makes a correct real Owner signature over canonical v1 claims and
independently verifies ML-DSA before asserting actual Hub rejection. The stale
account-epoch fixture preserves its issued epoch-1 body while advancing only
the owned Hub database to epoch 2; it is not a future-epoch substitution. The
subsequent final eight-lane gate exercises these same strengthened consumers.

### Integration-owner gates and historical aggregate limit

Separate receipts are under
`/home/zyf/Cicada/.local/evidence/n2-integration/run-20261015T122515Z-TT8H3v`.
They must retain their own source attribution and cannot replace the independent
N2 process gate:

| Receipt | Tested source and result |
| --- | --- |
| `hub-integrated-go1272-result.json` | Clean `570c12f`, Go 1.27.2: broad eight-package normal attempt **exit 1**, 1,972 passing events and 21 skips; Store hit cumulative 300-second timeout. Other seven packages passed. This is not an all-repository pass. |
| `store-timeout-case-go1272-result.json` | Same source: the individual case executing at timeout, `TestNetworkScopedTaskAndRequestReadsFenceOldEnrollment`, passed alone within a separate 60-second bound. Original aggregate failure remains. |
| `hub-store-scoped-go1272-result.json` | Same source: bounded Store selection exit 0, 256 passing events, **2 skips**: `TestStateBackupRestorePhysicalBindAliases` and `TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence`. Skips stay NOT_RUN. Log SHA-256 `71d38d8459b9f89860585eaeedddb4647f3fa7b60a16b8ac1187e8ad93577d75`. |
| `native-foundation/run-20261015T133815Z-vmLmEN/validation.json` | Clean `8db5be1`: 114 passing events, zero failures/skips, Windows cross-build exit 0. Source manifest `d79af61a99ed73528193731a91a2ed307122471f98fd9ac7efd3a1b3734f6adb`; earlier unsigned exe SHA-256 `dbc942d43a46aa242e1e3dd39a1d5dfa626df829a5aafbdc839c3e91c7c558a3`. This binary predates A01/A02 fixes and is not the final manual-test delivery. |
| `webcrypto-node26-result.json` | Clean `8db5be1`, Go 1.27.2 and Node 26.12.0: UI model plus real Go WASM PQ/wire interop exit 0. Log SHA-256 `032a9f3d39ffe3d375b44ca0751ec6fadd81a95ca39e603a1c684b7fb8ebf8f2`. Browser/native Windows runtime NOT_RUN. |

The new standard Client disposable Docker interop passed on **clean `8db5be1`**,
source build fingerprint
`089b1d24c3145a8ada7bbed741cdd3645332a19879a594d46a2ba1fd71cdaf64`:
smoke, recovery, headless operator and Owner bootstrap all passed, exit 0.
`standard-client-interop/result.json` SHA-256 is
`bd75144b0bfbf6d94ecaac93b5914236a019c7d2bbb90517f45a258df24c6b4b`;
`cleanup.json` SHA-256 is
`d4f54d4490931cac4206cc7d9dc5598de56c2ceb0a97a0615cdbae037ea32e68`,
status `CONFIRMED`. Exact owned cleanup covers three containers, two images
and scratch; the integration owner independently verified four residents
unchanged. This result remains attributed to `8db5be1`, not the later App
repair. The integration owner's runtime-source comparison found all 500 actual
Hub inputs unchanged between that source and `079249d`. Earlier N1 interop
also retains its original source attribution.

Final native foundation gate on **clean `079249d`** passed **121 events,
zero failures/skips**, Windows cross-build exit 0. Receipt
`native-final/run-20261015T143117Z-S2lsUF/validation.json` SHA-256 is
`93d28bf702ccc4cedb17d4374bf63715d894b0a9a221eb93c29461debef0a0b3`;
stable Go-source manifest is
`d05bae406e8e5714a5a0d1bfcbdc63ffba6dc7c86d8ad2faebc8e06b62e3126d`.
The matching Linux Hub binary built offline with Go 1.27.2, CGO disabled;
version reports `cicada 0.0.5`. Its complete build-input manifest, including
ignored embedded WASM assets, stayed
`5534e9427457716370e62534c5a3a4bd51a76855e42ca8a1414013cc94775217`.
These final builds belong to clean `079249d`; acceptance-only test/document
additions do not reattribute them to a later commit.

### Time, restore and platform limits

Real-time TCP tests construct short valid credential/proof windows and saved
packets, wait for actual expiry, then send them. Store lease checks additionally
use logical time/past lease state. App deadline checks advance only `Config.Now`
and assert no network renewal. **Actual 15-minute end-to-end wait NOT_RUN.**
The server account-session expiry case injects a past database expiry; it does
not wait for the natural session lifetime.

The independent epoch test injects an isolated SQL account-epoch transition,
revokes sessions/lease and verifies current authenticated reconciliation with
the exact old receipt. This is not full backup/restore acceptance. A selected
Store test separately invokes the real restore fence and checks retained
credential/Root and revoked lease. Full end-to-end backup/restore is outside
this lane.

Windows DPAPI, ACL, GUI and interaction/visual review are **NOT_RUN**.
Cross-compilation is not runtime evidence. Android, physical-device use,
real native Runtime, public HTTPS and native PQTLS are **NOT_RUN** here. N3
authorized live canvas/Node actions, installer/signing, encrypted PKCS#8 input
and lost/revoked Root recovery are not accepted by this checkpoint.

### Windows manual acceptance procedure — NOT_RUN

This procedure awaits actual user execution and a receipt. The integration
owner supplied matching clean-`079249d` artifacts at
`/home/zyf/Cicada/.local/artifacts/n2-validation/run-20261015T1423-7eteqx/`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `cicada-app.exe` — unsigned Windows amd64 App | 13,022,208 | `8475ed01e189e816885641051731d3d290fc7a4b6a6d9749b7d141e7a181a393` |
| `cicada` — local Linux amd64 Hub CLI | 25,161,888 | `8bca61bc3f2c5471676af5db83bc28ba1a2a9bed5c4bdb534fecca72fe1af7a8` |

The same directory contains `delivery.json` (SHA-256
`54087081b45f4b3eb25440208627facd47ef9f3b69d384071ff3833ee82d4186`),
`SHA256SUMS`, complete before/after source inventories including ignored assets,
and `hub-runtime-source-comparison.json` for the 500 unchanged Hub build inputs.
Use this existing delivery manifest together with the independent gate receipt.

The `.exe` is an acceptance build, not an installer/release. Copy it privately
to Windows, retain its hash and use the matching Hub binary/source for the
isolated fixture. On Linux prepend that artifact directory to the current
shell's `PATH` or use the binary's full path for the following commands; do
not replace an installed deployment binary. No deployment was changed here.
Record Windows version and check
`Get-FileHash -Algorithm SHA256 <copied-App.exe>` in PowerShell before use.

1. The operator prepares an **isolated** Hub with that matching source/binary,
   private state, transport identities and reachable HTTPS origin; leave
   Control inference disabled. Normal native App requires HTTPS; the Linux
   driver's loopback-HTTP override is not a desktop switch. With the fixture
   Hub **stopped**, run on its host:

   ```sh
   cicada hub setup --owner-label 'Synthetic Windows acceptance Owner' \
     --origin <chosen-HTTPS-origin> --public-config <new-public-config-file> \
     --state-dir <new-isolated-state>
   cicada hub activation-issue --purpose initial \
     --state-dir <same-isolated-state> --code-file <new-private-code-file>
   cicada serve --hub-only --state-dir <same-isolated-state> \
     --host 127.0.0.1 --port <isolated-port>
   ```

   `setup` and issuance acquire an exclusive startup lock, so do not run them
   against a serving fixture. Setup is for pristine state only; for legacy
   continuation preserve its exact existing state/keys and omit setup. The
   user/operator supplies a trusted HTTPS entry reachable from Windows to the
   loopback listener, following [HTTPS trust](distribution.md#https-entry-and-trust).
   These commands do not configure TLS, DNS or a public deployment. Hub-only
   mode starts identity/account services without Control. Privately deliver
   the code; do not publish it, alter residents, or hand-assemble/sign JSON.
2. Open App under the intended Windows account. Paste into “激活码或可信连接卡”
   and click “连接”. Verify origin/full Hub fingerprint in “连接详情” against
   operator metadata. First use: “生成 Owner 身份”. Exact existing pending
   Owner: “导入现有 Owner 身份文件”, selecting original matching ML-KEM private,
   ML-DSA private and two public PEMs. For that case the operator issues
   `--purpose legacy-pending --owner-key-id <existing-key-id> --owner-fingerprint <full-fingerprint>`
   for the existing `PENDING_PROOF` account/Owner instead. Preserve original
   keys. Initial setup requests username/password; legacy retains credentials.
3. Read/select “我同意向此 App 授予上述有限权限。” and click “激活此 App”. Root
   proof should complete while ordinary login is still required. Click “登录”
   with the account credential. Expect finite permission/deadline for only
   Node-list/session-capability reads; general management/live canvas remains
   unavailable. ACTIVE/REVOKED Root cannot issue another installer code. This
   is not lost/revoked Root recovery.
4. Close/reopen under the same Windows account. Use “查找已保存的连接” / “解锁并继续”
   without the installer code. After Hub reconciliation, compare account/Owner
   IDs and public fingerprints. Log out, try wrong password, then “恢复连接”
   until authenticated rejection settles. Correct password must allow login.
   An unsigned HTTP error alone must leave uncertainty intact.
5. Against this disposable Hub, interrupt transport during activation/login,
   close/reopen, restore transport and use “恢复连接”. Expect recovery of the
   original pending operation without duplicate Owner/device or false success.
   A manual cut alone does not prove server commit timing; record ambiguity.
   The Linux fault driver provides exact before/after-commit observations.
6. Wait the full real 15-minute lease period, counting earlier steps. Check
   local expiry, then use “刷新状态” to obtain authenticated current Hub lease
   state. Account re-login must not renew the lease. Record real issue/deadline/
   check times and the observed expired state. This can establish the actual
   Windows/Hub status expiry after execution and review. The App has no N3
   business-read controls yet; denial of a new protected business operation is
   covered by the separate server/Store guards, not this manual UI step.
7. Record DPAPI and ACL separately: same-user reopen succeeds; a different
   ordinary Windows account cannot unlock a protected copy of this disposable
   profile; ACLs remain protected and restricted to intended user/SYSTEM. Do
   not weaken ACLs or copy production profiles. Review actual desktop scaling,
   focus/keyboard, language, truncation, recovery feedback and secret-free
   screenshots/errors. ACL denial alone does not prove cross-user DPAPI
   rejection; that requires a separate native DPAPI execution receipt. Each
   result needs its own evidence; a cross-build or screenshot cannot establish
   DPAPI/ACL behavior.

The importer supports **unencrypted PKCS#8 PEM only**, verifies the exact
public identity and encrypts it in the vault. Encrypted PKCS#8/PBES2 must show
the unsupported-input message without altering or silently replacing the key.
Do not add shell decryption/signing as an ordinary-user workaround. Evidence
may include IDs, public fingerprints, safe error/state codes and hashes;
omit activation codes, passwords, private PEMs and session tokens.

## Windows native security driver and user observations — 2026-10-17

This is an additive record. The Oct 15 Linux test receipts, their failures,
native NOT_RUN fields, original App/Hub delivery binaries and hashes above are
unchanged. A user-reported observation is not an independently executed test.
N2 identity/security evidence does not establish the full Node/business flow,
N3, an installer, or overall system acceptance.

### User-reported physical observations

| Observation supplied through the integration owner | Classification and limit |
| --- | --- |
| Windows 11 Pro `10.0.26200`, x64; downloaded App/Hub hashes matched the Oct 15 delivery | USER_REPORTED artifact match. The locally retained delivery manifest is independently readable; the running remote process was not independently inspected by this acceptance task. |
| User explicitly authorized wiping the old remote Docker Hub/state/workspace/image; one root systemd Hub now uses `/opt/cicada-n2`, origin `https://cicada.basil.xin` | New user-operated environment, not an acceptance fixture created by this task. Wipe/new initialization is not process-restart recovery, backup restore, legacy continuation, or preservation of the old Owner. |
| Health reports version `0.0.5`, revision `079249dee906c84ead0d2d331eeb400ad018ea03`, `dirty=false`, source fingerprint `5534e9427457716370e62534c5a3a4bd51a76855e42ca8a1414013cc94775217` | Reported metadata matches the retained delivery. This is not remote executable attestation, a full HTTPS deployment gate, or native PQTLS evidence. Control-off launch arguments were not supplied in this receipt. |
| App shows Owner ready, Root active, local Owner key present, pinned Hub HEALTHY, limited access confirmed, Log out available; management/canvas unavailable | USER_REPORTED initial native Windows/HTTPS identity flow PARTIAL and expected N2 UI boundary. This is not a new adversarial server Guard test or comprehensive visual review. |
| After the integration owner's reopen / wrong-password / outage / expiry procedure, user says everything is as expected | USER_REPORTED overall procedural success. No per-case logs, unchanged account/Owner/device IDs, exact replay receipts, or post-relogin expiry snapshot were supplied; do not promote each negative/recovery case to independently verified PASS. |
| App directly displays “This 15-minute access period has ended. It will not renew automatically. Access ends at 12:54” | USER_REPORTED natural expiry UI observed. Timezone, issue/check timestamps and a retained `N2CheckStart` were absent. This does not establish a measured 15-minute duration, backend rejection of a new protected operation, or proof that re-login cannot renew. |
| Windows identity `VASTE\MAGI`; `Get-Acl` on `%LOCALAPPDATA%\CICADA\vaults` reports that Owner and `AreAccessRulesProtected=True` | USER_REPORTED direct positive owner/protected-DACL inspection of that root only. |
| `icacls /T` succeeded for five entries: root, `CICADA` child, nested `vaults`, vault and vault lock. Each shows only user and SYSTEM FullControl; directories OI/CI, files no inheritance flags shown | USER_REPORTED positive ACE inspection for those five entries. Child Owner and Protected properties were not separately queried, so do not assert all five had those properties directly measured. The existing double-nested `CICADA\vaults\CICADA\vaults` layout is observed and is not relocated/reset. |

Same-user DPAPI unprotect may be indirectly exercised by reported profile
reopen, but there is no dedicated native test receipt yet. Cross-user DPAPI,
synthetic negative ACL rejection/no-repair and the new native test driver below
remain **NOT_RUN** until actual Windows results are collected. No existing
Owner vault or keys were read/copied by this task, no live Hub fixture was
created, and no identities, production paths, APIs or dependencies changed.

### Standalone synthetic native security gate

`internal/appvault/n2_native_windows_test.go` adds Windows-only acceptance tests;
production `appvault` and App/Hub sources remain unchanged. Existing generic
vault tests use the password protector and POSIX-style directory fixtures;
they are not a native DPAPI gate. The selected new tests use only fresh
synthetic data, never the App's default vault path or a network connection:

| Required test | Native assertion |
| --- | --- |
| `TestN2NativeWindowsContext` | Actual token SID, ordinary-user classification (including deny-only administrator membership), Windows build and hashed machine identifier. |
| `TestN2NativeWindowsProtectorRoundTrip` | Actual `NewPlatformProtector` / current-user CryptProtectData and CryptUnprotectData; fresh random synthetic 32-byte key; wrong entropy and corrupted blob reject. |
| `TestN2NativeWindowsVaultAndACL` | Production Create/CAS/Close/Open/LoadState with DPAPI in a new synthetic scope; concurrent writer fence. Independent GetNamedSecurityInfo inspects directory, vault and lock: current-user owner, protected DACL, exactly user and SYSTEM full-control ACEs, directory OI/CI and file flags zero. |
| `TestN2NativeWindowsACLRejectsTampering` | Four fresh synthetic fixtures: extra ACE on directory, vault or lock, and directory inheritance enabled. Production Open must reject; pre/post rejection SDDL and ciphertext remain unchanged. No real vault's ACL is modified. |
| `TestN2NativeWindowsCrossUserProduce` | A wraps a fresh synthetic key and verifies its own DPAPI control, then publishes only ciphertext, public entropy and synthetic metadata. The new public transfer directory intentionally grants authenticated users read/execute, never write. Its ACL is distinct from the private synthetic vault's ACL. No plaintext key or Owner identity is exported. |
| `TestN2NativeWindowsCrossUserVerifyA` | Another A process reads/hashes the exact persisted transfer bytes and successfully unwraps with identical entropy on the same machine. |
| `TestN2NativeWindowsCrossUserRejectB` | An existing distinct ordinary Windows user must read/hash those same bytes, match machine/entropy, pass its own DPAPI positive control, then receive rejection from actual production UnwrapKey. File-access failure, same SID, unavailable/administrative B, changed input or failed positive control cannot count as cross-user PASS. |

The PowerShell runner requires the exact seven-test inventory, required
subcases, one native receipt per case, one overall completion and exit 0 per
executed test. Missing tests, zero cases, skip/fail output, duplicate passes,
nonzero exits and changed bundle hashes fail. There are no `TestWindows*`
placeholder selectors: a no-match executable cannot pass. The reviewer-side
Python checker separately re-parses logs, verifies the artifact index and
matches A/B source/executable, fixture, entropy, machine and distinct SID.

Build on Linux with the existing immutable Go image and module cache read-only:

```sh
CICADA_N2_GOMODCACHE=/home/zyf/Cicada/.local/cache/n2-acceptance/gomod-go1.27.2-stable \
  scripts/build-native-app-n2-windows.sh
python3 -m unittest discover -s scripts -p test_native_app_n2_windows_evidence.py
```

The disposable Docker build has no external network, host ports or Hub. The
task's own build cache is locked; modules are never modified. It runs Linux
vault regressions, Windows vet and a Windows amd64/CGO-disabled test-executable
cross-build. That executable requires **no Go installation on Windows**.
Windows API execution is a separate NOT_RUN result until run there.

Final build `windows-build-20261017T051446Z-gyZE5T` passed all four lanes
(`version`, `linux-vault`, `windows-vet`, `windows-compile`), each exit 0;
Linux vault tests recorded **12 pass, zero fail/skip**. Tested source is
`b7ecd33c1db391f6f6f40b25ba4f7c2738cd5b54` plus the dirty acceptance-only
changes, stable before/after build-input manifest
`2f4c7ca6c44da8496c5b809807e13577da1201b6242484d313cfc8c289cc8f07`.
This does not change the runtime provenance of the original App/Hub delivery.

| New acceptance-only artifact | Path / SHA-256 |
| --- | --- |
| Build receipt | `/home/zyf/Cicada/.local/evidence/n2-acceptance/windows-build-20261017T051446Z-gyZE5T/result.json`; `a664c4f406d0fdd4fc3422ac4062a3d0ad4121725e358f62c904d3beb5acb0f9` |
| Bundle directory | `/home/zyf/Cicada/.local/artifacts/n2-acceptance/windows-build-20261017T051446Z-gyZE5T/` |
| Bundle ZIP | Same directory name plus `.zip`; `708702bb3e7974f6fde13e970796dd5c7185f3380e6a7cdaa4d7509f6fab8bdc` |
| `cicada-appvault-tests.exe` | 7,356,928 bytes; `f4f95eca08011c9cad6b6f2ab54b78a3643044a1dc6537d17db86ea1629a6fac` |
| `n2-native-windows-build.json` | `92717e481cd8b382ddb4ada4729218099745245d0a892a3c8c971a22c5cc5005` |
| `run-native-app-n2-windows.ps1` | `da075228b51238a09f13091137b415d21b7cf73b27ccbd8b733cc9a95c716d94` |

Additional check receipt
`/home/zyf/Cicada/.local/evidence/n2-acceptance/native-windows-checks-20261017-ewP5ob/result.json`
has SHA-256 `d61418f74099a55752ac99802435c95478f8600ecf1f726dc828afc6e635e5cb`.
It records **16 Python evidence tests** (11 new plus 5 existing), shell syntax
success, and a real **Linux PowerShell 7.5.3** parser self-test rejecting six
false-success inputs. The task-only tool archive was verified against the
[official release hashes](https://github.com/PowerShell/PowerShell/releases/tag/v7.5.3),
SHA-256 `5c74e0bbafd8be59e72267f05700fd6615344d9cf4d30460d9b6d12cd4a88a8c`.
This checks parsing, not Windows APIs, Windows PowerShell 5.1 execution or
native A/B process behavior; those remain NOT_RUN. No shared dependency cache
or product dependency was modified to obtain that tool.

The first build attempt `windows-build-20261017T050517Z-H13EVO` remains **FAIL**,
exit 1: Docker's noexec `/tmp` prevented the Linux test executable from starting,
so there were no Linux assertion results. Windows vet/compile did pass in that
failed attempt. The runner was corrected to use an isolated task-state bind
for `TMPDIR`; the complete rerun `windows-build-20261017T051046Z-6QiQSa` passed.
The final run above adds ZIP packaging and repeats the complete four-lane gate.
Failed and earlier successful receipts are retained rather than rewritten.

### Native Windows commands and phase semantics

Copy only the acceptance bundle (`cicada-appvault-tests.exe`,
`run-native-app-n2-windows.ps1`, `n2-native-windows-build.json`,
`native_app_n2_windows_evidence.py`, `SHA256SUMS`) to Windows. Preserve the
integration owner's bundle/build-manifest hashes and verify them before use.
Give both existing A and B accounts read/execute access to the **same hashed
bundle**, for example by putting a copy in a fresh public acceptance folder.
A's Downloads directory may be private. Do not copy a real App data directory,
Owner vault, private key, or account credential to make B's test work.

In Windows PowerShell, from that bundle directory under account A:

```powershell
Get-FileHash -Algorithm SHA256 .\cicada-appvault-tests.exe
Get-FileHash -Algorithm SHA256 .\n2-native-windows-build.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-native-app-n2-windows.ps1 -Phase SelfTest
$LASTEXITCODE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-native-app-n2-windows.ps1 -Phase A
$LASTEXITCODE
```

`ExecutionPolicy Bypass` here applies only to the invoked process; no permanent
machine/user policy is changed. An enforced policy or unavailable ordinary B
is a prerequisite limitation, not permission to weaken system policy or create
accounts automatically. Phase A creates a unique evidence directory and a
new `CommonDocuments\cicada-n2-native-synthetic-<run-id>` transfer directory;
it prints the **fully populated B command**. No manual JSON, signatures or key
handling are required.

Sign in interactively to a **different existing ordinary account on the same
machine**, with its profile loaded. Use the same verified bundle and copy the
printed B command verbatim:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-native-app-n2-windows.ps1 -Phase B -TransferFile '<printed synthetic transfer file>' -FixtureSHA256 '<printed SHA256>'
$LASTEXITCODE
```

No ordinary B account means **cross-user NOT_RUN**. An admin account with an
unelevated/deny-only token is still not ordinary B. The B runner returns 2 for
that explicit prerequisite result without pretending a skipped test passed.
Do not change the real App vault's ACL to obtain a cross-user result: the
synthetic transfer blob is intentionally independently readable already.

Phase A exit 0 means only A's local security tests and separate-process
producer control passed, with cross-user NOT_RUN. Phase B exit 0 means B's
rejection was observed; matching A evidence is still required. Other executed
phase failures return 1. Send the two **new evidence directories** to the
integration owner, who verifies them using the shipped checker on Linux:

```sh
python3 scripts/native_app_n2_windows_evidence.py \
  --build <bundle>/n2-native-windows-build.json \
  --producer <A-evidence> --consumer <B-evidence> --output <new-review.json>
```

Review exit 0 accepts only the paired synthetic native security scope. Omitting
`--consumer`, or an explicit nonordinary-B prerequisite receipt, returns 2 and
keeps cross-user NOT_RUN. Invalid/missing/skipped/failed evidence returns 1.
Retain each `result.json`, logs, source/build hashes and artifact index. The
synthetic public transfer directory can be removed by its owner after all
phases and receipts are retained; never recursively clean an App data root.
