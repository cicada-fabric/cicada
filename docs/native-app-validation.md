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

## N3 independent preparation — 2026-10-17

N3 is authorized; its shared Hub contract is still awaiting integration-owner
review at this checkpoint. The [independent matrix](native-app-plan.md#n3-independent-safety-model-and-acceptance-matrix)
states invariants without creating another protocol or task book. The supplied
Ubuntu 24.04.3 / x86_64 / `zyf` UID 1000 / Codex 0.163.0 output remains
USER_REPORTED_ENVIRONMENT, not an approved Node or native Runtime result.

Preparation owns `cicada-go/acceptance/n3`, `scripts/test-native-app-n3.sh` and
its independent evidence checks. It does not modify Hub/App/Node production
code, shared protocol, the current ACTIVE remote Owner, keys or deployment.
The Hub worker owns focused server/Store/CLI guards, App owns controller/UI
checks, and the integration owner owns full N2 regression, standard Client
Docker interop and matched final App/Hub/Node builds. This gate does not repeat
those broad campaigns.

The infrastructure self-tests run an **actual acceptance-built Hub CLI** in
`--hub-only` mode, real ML-KEM/ML-DSA encrypted frozen N2 activation packets over
loopback TCP, disk SQLite and actual SIGKILL/restart. They distinguish faults
before forwarding from lost/unsigned-403/corrupted replies after a committed
prepare, inspect persisted production state with the Hub stopped, then recover
the byte-identical response. Another test holds an unsent original at a TCP
barrier, durably cancels its N2 authority, restarts Hub and delivers the late
original, checking the authenticated cancellation and unchanged Root state.

The packet-sender child is explicitly **an opaque harness, not production App**.
The cancellation test uses an already frozen N2 authority transition, **not an
N3 original-operation fence**. There is no production N3 App or Node actor yet.
These results establish only the fault/process infrastructure and cannot accept
the proposed N3 endpoints, grants, atomic confirmation, liveness or Runtime.
Those cases will consume only the reviewed Hub contract and implementation.

```sh
scripts/test-native-app-n3.sh --require-n3
python3 -m unittest discover -s scripts -p test_native_app_n3_evidence.py
```

The module cache defaults to the existing verified stable Go closure, mounted
read-only. Build cache, state, artifacts and evidence are exclusive to
`.local/{cache,state,artifacts,evidence}/n3-acceptance`; each run has a unique
container name and label, no external network/host ports, UID 1000 and private
loopback ports. Read-only source/caches, exact resource cleanup and bounded
hash-only traces prevent a disposable test from using a shared Hub. Private
synthetic configuration/packets remain in task fixture state, not evidence.

Run `run-20261017T055520Z-7IgZLh` passed all five infrastructure lanes
(`version`, `compile-cli`, `compile-tests`, `harness`, `vet`), each exit 0,
with **6 passing events, zero failures/skips**. The required-N3 command returned
**3**, deliberately: `harness=SCOPED_PASS`, **`n3_acceptance=NOT_RUN`**. There
is no reviewed contract pin or complete real Hub/App/Node N3 test inventory;
all N3 matrix rows remain NOT_RUN. Environment flags cannot promote them.
Default driver success without `--require-n3` accepts only this stated harness
scope; missing prerequisites return 2, and a harness failure returns 1.

Tested source is `f8b5e58d243599b355f3fe4a85543a6219201a28` plus dirty acceptance
preparation, stable source manifest
`2218a575e2f98fdd329a512ec1e1f7908afec396dc90c40f8f2d2dae8ba0f8d6`.
Builder image is
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`
(Go 1.27.2 bookworm). This environment does not establish Ubuntu target-platform
acceptance. The owned container was absent after cleanup.

| Preparation artifact (outside repositories under `/home/zyf/Cicada/.local`) | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T055520Z-7IgZLh/result.json` | `58e410c016cd1a4baf914e5a88737dc46816bd974e5873111228c363ced003c1` |
| Same run's `artifacts.sha256.json` | `796451af924ff55d72445e303ac9b81aa8c8730670f50037242ec3bf5f2934c5` |
| `artifacts/n3-acceptance/run-20261017T055520Z-7IgZLh/n3.test` | `72bae4193da119f13f6ad5724fdf25be8e2dd18dc641d659e62305b89b7d1c22` |
| Same run's `cicada` CLI | `eb8675ec137a0463da25f7b92d5a9a97b790e32b3ad874829c91d5c6ed190104` |

The first attempt `run-20261017T055135Z-X9nZxc` remains FAIL/exit 1: an unused
test import prevented test compilation and vet, and no harness case ran. The
import was removed before the complete successful infrastructure rerun. Five
Python evidence tests independently reject zero cases, hidden failures/skips,
missing binaries, source changes, leftover resources and premature N3 promotion.
Only documentation was subsequently extended with this result; old receipts
are not rewritten as if they contained later provenance prose.

N2 receipts, failed attempts and Oct 17 user-reported Windows observations
retain their existing scope. Actual N3 Windows UI, public HTTPS, physical
Ubuntu Node and real native Runtime acceptance remain separately NOT_RUN.

### Reviewed types and actual App process infrastructure

The integration owner reviewed `app-node-authority-v1` at
`a545988ac6c038da180413d4f29ffbf740c402d4` and fast-forwarded this task worktree
while preserving its acceptance draft. The new evidence driver pins the exact
contract document, claims, DTOs, structural validators and manifest. Their
status is **REVIEWED_TYPES_ONLY**; production N3 routes/actors are still unrun.
The subsequent approved N3-only 384 KiB inner-limit correction is pending a
delivered helper checkpoint and actual encrypted PQ outer-frame receipt;
default Client/N2 inner 256 KiB and historical failure receipts remain distinct.

Run `run-20261017T061318Z-MuU3RF` added two infrastructure cases. One pauses a
real committed Hub response before delivery, SIGKILLs its packet-sender and Hub,
checks the actual disk mutation and recovers the byte-identical receipt after
restart. The other runs the **production App core in a separate process**,
generates its real Owner/App keys, completes N2 proof and separate account login,
then SIGKILLs App and Hub. A fresh App process discovers and authenticates the
encrypted profile without activation/installer material, preserves identity,
full pin and original finite expiry, and still has no Manager/canvas authority.
This uses the synthetic password vault backend, not Windows DPAPI or native GUI.
The raw packet sender remains a separately identified harness actor.

All five lanes returned 0; **8 events passed, zero failures/skips**. Source
`a545988` plus dirty acceptance inputs stayed stable at manifest
`81d667d27595835f9911c228bc0570c1a99ab8589bf6738b155edf688c11615b`.
The reviewed type hashes matched and the owned container was absent. The same
pinned Go 1.27.2 bookworm image was used. `--require-n3` returned **3** with
`harness=SCOPED_PASS`, `n3_acceptance=NOT_RUN`; all 26 N3 rows remain NOT_RUN.
Six Python evidence checks passed, including rejection of changed contract bytes
even when the source is otherwise stable and every lane reports zero.

| New preparation artifact under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T061318Z-MuU3RF/result.json` | `ad63384210ac05c893f708a0c89a53120b3becf44e1e84f06a86286099a47640` |
| Same run's `artifacts.sha256.json` | `84d29d594499b6ff5b2fcf701d4aff20c2d49156727a461df344c9852fd700a3` |
| `artifacts/n3-acceptance/run-20261017T061318Z-MuU3RF/n3.test` | `73f81c46805170885fdf59dc9991fca79b5cc26fcb5fda229ad7631ec5ea781f` |
| Same run's `cicada` CLI | `5a31ba41af890ccf521b37cb68c2936b72ee850e24007c83c74a3efbd0237d06` |

The validation record was extended after the run. Its new prose is not attributed
to the earlier dirty-source manifest, and neither N3 nor physical/native scopes
are promoted by the successful infrastructure cases.

The preparation checkpoint was subsequently verified at
`run-20261017T062013Z-bRSL8R`: **8 pass / 0 fail / 0 skip**, the same five lanes
all 0, required-N3 exit **3**, contract pin matched and owned container absent.
It also compares **both complete public identities** from the actual encrypted
vault before/after restart, and verifies a private command mailbox to the still
running App Controller. Snapshot-only commands use wall time; future deliberate
App clock offsets are labeled `APP_LOGICAL_CLOCK_ONLY`. Private command files
are isolated by a fresh per-process random mailbox ID and contain no real data.
Source is still `a545988` plus dirty QA inputs, stable manifest
`098e468897a5d914ad86015c3ec5e64c6ad7609c17fd8e0f8c21534182cb32ce`.
The intermediate mailbox-only run `run-20261017T061605Z-7QMlEn` is retained with
the same scoped outcome; it does not contain the later full-key comparison.

| Final preparation artifact under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T062013Z-bRSL8R/result.json` | `6e8f0e1f174a07577905a97c86adf3a7e7499b2e37c271d4902201c8dfad3477` |
| Same run's `artifacts.sha256.json` | `297dcb43a547f086b2913badb9345b93e49e38901b69b069d05f35f5e7a8d8e9` |
| `artifacts/n3-acceptance/run-20261017T062013Z-bRSL8R/n3.test` | `ccbbae9110ed100715ad79ed9d5678a92429387034f5450d8b8c9bd8e8c4049f` |
| Same run's `cicada` CLI | `5a31ba41af890ccf521b37cb68c2936b72ee850e24007c83c74a3efbd0237d06` |

An additional **narrow** infrastructure check, `TestN3HarnessActualAppVaultCommitBarrier`,
ran separately at `vault-boundary-20261017T062803Z-s_qj6_sr`; the earlier eight
events were not repeated. A test-only wrapper delegates the actual password
protector unchanged and pauses `Protector.ID()` before the next real vault write.
At that boundary a private copy of the previous atomic encrypted image is
authenticated independently. The test observed a durable `session.inspect`
response with its pending operation still unapplied, SIGKILLed the actual App
and Hub, and successfully resumed the same production App profile. It did not
simulate a response loss or replace vault persistence/cryptography.

Compile, the one selected test and vet each returned 0, with one pass and no
skip. Source `a545988` plus dirty QA inputs was stable at
`3a6ab77b57259ce6b3169978647ebdc109fc4e71f8459a88cce9f7f3c06eb783`.
The actual CLI is the unchanged earlier build (`5a31ba41…`); the newly compiled
test binary SHA-256 is
`f81bcd745642443f90733fde2f8e90bbb0fbdd7c9160f8caacb98e634c6e8fb0`.
The owned container was absent. Result SHA-256 is
`70f2f1c09e77797552ec4fce20ec481abea7be9b624d1dd66465af3df7f6de46`;
artifact index SHA-256 is
`b28cba98e6582786ccd941eaa86e871e578d2e10bc60f86855a052c298cb649d`.
This proves the Linux local-commit fault seam only. N3 response/application and
counter recovery remain NOT_RUN until the actual new actors use that seam.

### Shared helper pin and integration-owner N2 regression

The integration owner synchronized
`5f509befa6065ac41abeb23451ef8d41cc2c76aa` into this task branch while preserving
the independent acceptance draft. The strict pin now contains 19 normative/helper
files and reports **SHARED_HELPERS_ONLY**. Contract document SHA-256 is
`f92248fbd9fc1443a71071d40f5c38bd227dc9cd8ca696cf04f7e3e3150efed5`.
The N3-only 384 KiB inner correction and actual encrypted outer-frame boundary
checks belong to the [Hub producer receipt](hub-app-node-authority-validation.md).
Its broad normal/race package checks each retain an opt-in OpenSSL SKIP;
the focused N3 helper checks have 32 pass / 0 fail / 0 skip. These are shared
helper evidence, not independent production N3 acceptance.

The integration owner reran the complete N2 gate on **clean `5f509bef`**:
`scripts/test-native-app-n2.sh --require-n2` returned **0**, all eight lanes
returned 0, with **131 pass / 0 fail / 0 skip**, stable source manifest
`89411d52685a7fa4d3e8f175b1be73644673546c72df84712b9c5e8f9758b0ba`.
Result is `/home/zyf/Cicada/.local/evidence/n2-acceptance/run-20261017T063227Z-mn8LUa/result.json`,
SHA-256 `46b07c6cd6f5cef6002462ef8c2a269c6a2844dbd4b31b7108cd4b0f93e5b9e9`.
The owned container was absent; resident deployments were unchanged. This
regression applies to helper integration only; later production Hub/App runtime
changes require their own final regression. It is attributed to the integration
owner's clean source, not this task's dirty draft.

Independent QA compiled and vetted its newly added shared-wire adversary and
Node-process orchestration at `compile-helpers-20261017T064154Z-lxojgi24`; both
returned 0. **Zero runtime cases ran in that compile-only check.** App Action
integration cases have a temporary test-only build tag pending the actual App
commit sync; their absence cannot satisfy the final expected-case inventory.
N3 runtime, physical Ubuntu 24.04.3 Node, Windows native custody/UI, public HTTPS,
App SSE and real native Runtime remain NOT_RUN. QA owns the optional future
Ubuntu **24.04.4** amd64 container actor lane at immutable image
`sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254`;
it is separately attributable and cannot establish the user's physical target.

The integration owner next synchronized Store checkpoint
`e078c58d97413f5e0457acb3c586afbef1a9d438`: schema **63**, phase **STORE_ONLY**.
The strict pin includes 31 normative/helper/Store files; contract SHA-256 is
`d151210d8f0fbc7a712e8a0be2b28db6bb35e3fdaddc1e659ce05bf8f780dae4`.
The Hub producer reports final focused normal and race each **31 pass / 0 fail /
0 skip**, plus vet 0; earlier broad skips and interrupted runs stay in its
receipt. No N3 HTTP endpoint is enabled by that source. Metadata and six QA
evidence-parser checks passed after sync; the broad preparation harness was not
repeated just to change the pin. The Store's retained N2 Client epoch-1 guard,
exact bound-login semantics and old-original fencing remain explicit in the
matrix. Runtime drafts include actual App/Hub/Node operations, loss and local
CAS barriers, concurrent TCP requests and raw decrypted privacy canaries; those
new cases remain **NOT_RUN** pending actual production App and HTTP/CLI source.

### Actual App discovery guard against a legacy Hub

The integration owner reviewed and synchronized actual App controller checkpoint
`8df8ae5034f819ff3d839b6574f02c3c887af253` (parent `e078c58`). App producer
focused normal/race each have 41 pass / 0 fail / 0 skip, separately attributed
to `.local/evidence/n3-app/controller-final-20261017-j7l2o3eb/validation.json`.
QA removed the temporary build tags and compiled all prepared integration cases
against that actual Controller API. The strict pin now includes 48 source files,
records `CONTROLLER_IMPLEMENTED` and retains protocol phase `STORE_ONLY`.
No HTTP/CLI N3 service or physical/native result is inferred from the App commit.

```sh
scripts/test-native-app-n3.sh --discovery-only
```

Run `run-20261017T071158Z-Kc5MI6` used an actual newly built, matched Hub CLI in
`--hub-only`, production App core in separate real processes, PQ N2 bootstrap,
TCP and encrypted persistent vaults. Actual legacy-Hub discovery, injected 404
and an unknown public capability profile each produced **zero N3 secret POSTs**,
including bootstrap status, zero Client business RPC and zero durable Node
pending requests. This is an independent check of App behavior before N3 service
availability; the broader preparation harness was not repeated.

All five lanes returned 0, with **4 pass / 0 fail / 0 skip**, exact expected
test inventory, matched 48-file pin, source stability and owned container absent.
The command returned **0 for this discovery-only scope**. `N3-01` is
`PARTIAL_DISCOVERY_GUARD`; full `n3_acceptance` and all other N3 matrix rows
remain **NOT_RUN**. Seven evidence-parser checks passed, including rejection of
promoting this successful narrow scope into full N3 acceptance. Combining
`--discovery-only` with `--require-n3` is rejected with exit 2.

Tested source is `8df8ae5` plus dirty acceptance inputs, stable manifest
`0e1a2e4418b430c863580add9ff76509a603f247d05a50e08df401c8e0de33cb`.
The pinned Go 1.27.2 bookworm builder and read-only offline module closure were
used; state/cache/ports/artifacts remained task-isolated. After the run only
this receipt was added. All new runtime mutation/fault/Node cases are compiled
but still unexecuted until the actual N3 HTTP/CLI implementation is synchronized.

| Actual discovery artifact under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T071158Z-Kc5MI6/result.json` | `28802ed5f44e713fe7f099d6bccc3977aadfac434c7b828f83ab3d9bdb35caec` |
| Same run's `artifacts.sha256.json` | `c4b46cdca944c83af0a37d265ed77aa6ed60414d48e90113b3fa1cb0f2f2206a` |
| `artifacts/n3-acceptance/run-20261017T071158Z-Kc5MI6/n3.test` | `37b5f0385cc2a33e0a8a118319170260a2dd48e758e01404dd6a149b783ad379` |
| Same run's matched `cicada` CLI | `075744d7d8b8938325c68830efe941df32cc6da9698a5cdfb8cb1fc70af9ea6c` |

The integration owner subsequently ran the native App integration gate on
**clean `8df8ae5`**: **194 pass / 0 fail / 0 skip**, Windows crossbuild and
runtime-dependency listing exit 0, with source stability. Receipt:
`/home/zyf/Cicada/.local/evidence/n3-integration/run-20261017T055932Z-557c5d/native-app-checkpoint/run-20261017T071323Z-5N6p0e/validation.json`,
SHA-256 `065f76c681c227861dd4ef2fb12ef538ceeb30c051379b61f93c5578a5a4f662`.
This applies to the App + Store checkpoint, with N3 Hub runtime still absent;
neither Windows native API execution nor real native Runtime is accepted.
The integration owner retains final N2 regression, standard disposable Client
interop and matched delivery builds after actual Hub runtime integration.

### First real Hub/App/Node gate and natural-expiry fixture

The integration owner synchronized actual runtime
`af92b16d3c0dc616280d694986692a2cbb1caa71`, schema 63, phase
`HUB_NODES_ONLY`. QA pins its 62 normative/helper/Store/App/runtime files and
runs the actual CLI `serve --hub-nodes-only`, actual production App core in
separate processes and real Node CLI `machine agent --relay-only`. No Control
inference or native provider execution is required by these fixtures.

First core run `run-20261017T073623Z-xsks6W` is retained as **FAIL**: exit 1,
80 exact expected events, **66 pass / 14 fail / 0 skip**, stable dirty-source
inputs, compile/CLI/version/vet lanes 0 and runtime lane 1. Result SHA-256:
`e64ff84d53f17af247a9609dd9dd6773057f067e6292107a014f9876353951b1`.
Passing events include all three real local confirmation CAS crash windows,
concurrent reservation/confirmation, genuine proof/scope negatives, persisted
epoch/session/Owner revocation and raw Node-only privacy canaries. Parent test
failure events and failed subcases remain separate; this run is not accepted.

Triage identified driver corrections, recorded after the immutable run:

- Ordinary wire stress hit the existing authentication token bucket (4/sec,
  burst 12). Retry 429 with the exact encrypted original, bounded backoff and
  no new ID/nonce/ciphertext; injected App 429 cases remain outside that helper.
- App recovery legitimately retries its saved original before reconciliation.
  The delayed-unadmitted scenario must block that retry too before demanding a
  durable original fence. The earlier success was not a fence bypass.
- ACTIVE cancellation advances the published head. New intents must read a
  fresh authenticated head; status-only head assertions include the cancellation
  tombstone, without resetting Client counters.
- Automated UI commands now allow ordinary human command cadence instead of
  accidentally saturating normal admission during a multi-operation action.

Two actual integration defects were handed to the Hub owner and independently
reproduced there: `POST /v2/fabric/node/networks/direct/claim` received 404 in
the narrow service, and a retained fresh INITIAL pending candidate was not
installed after remote approval/restart. The owner isolated the exact guarded
route fix and pending-state recovery; no broad route prefix or manual heartbeat
substitute is accepted. The dedicated actual CLI reproduction
`run-20261017T074853Z-R7ZMvH` is also **FAIL**, one failed case, no skip, compile
and vet 0, stable source. Its result SHA-256 is
`5cc51f09fc6ec5998391b838f7be26a7b67e2b9a0b4cb7e4d7772da7a1b8bad8`.
Raw synthetic Node logs stay only in private task state; evidence records safe
status categories and the private-log hash. The fresh pending recovery oracle
is retained separately from legacy bearer-only behavior.

```sh
scripts/test-native-app-n3.sh --runtime-core
scripts/test-native-app-n3.sh --case=TestN3ActualImmediateRelayHeartbeatRetainsSubsecondOrder
scripts/test-native-app-n3.sh --seed-expiry
```

The last command creates a separate private, **synthetic acceptance-only** N2
template and stops all writers. Seed run `run-20261017T072753Z-DKv6h2` completed
all five setup lanes with exit 0 and one setup event; this is `SETUP_READY`,
not N3 PASS. Actual N2 proof/login used `8df8ae5` plus dirty QA inputs, stable
manifest `2758116cc635aeedf18f998178726c56d353675ebe2993ecc828e2169dc96ffe`.
Its original immutable N2 lease ends at **2026-10-17T07:43:00.992469179Z**;
the account session ends at **07:43:02.029619235Z**. Writers stopped at
**07:28:02.177150457Z**. No clock or lease row is edited.

Private template:
`/home/zyf/Cicada/.local/state/n3-acceptance/run-20261017T072753Z-DKv6h2/retained-aged-n2`.
Seed result SHA-256 is
`33503e7cb30a61ec9a10c182c1d920a408df44dc70a7abd7a542c9ff9497aaa1`;
artifact index SHA-256 is
`d89ca390c76e16cb9f8b64e792e8e3814ba4fe9e7be1f5d8a14af552527127af`.
After real expiry, a new task run copies this coherently stopped template into
its own state, preserving the source. Symlinks, special files, unrelated roots,
overwrites and unexpired input are refused. The actual aged test unlocks the
same profile, performs a fresh real login and new explicit N3 consent, and
compares original full keys/N2 expiry and the complete persisted N2 lease.
Its result remains NOT_RUN until that test actually executes on reviewed runtime.

### Hub-fix real-process rerun and corrected missing-row oracle

On reviewed `ec72bf2891bcc7bf98565beedbac54e51f35b7db`, complete run
`run-20261017T080405Z-qcf5yl` retained **FAIL**, exit 1: **83 pass / 1 fail /
0 skip**, compile/version/vet lanes 0, stable dirty QA source manifest
`dfceafa78318697889c42175da6a08ea1b31907d6d1a96c5469f6c734241f588`, owned
container removed. Result SHA-256
`695ddcc8aac1a987dfce87ce20139e56d178386e30f16662c9a09f6503bbff7e`; index
`702b7a334131bc5ada3ec590fc2ea2f3e35a60cf93f565535a2fa3bdf66fd4fe`.

The two production Node defects reproduced against `af92b16` are repaired by
`ec72bf2`: all 30 actual App fault cases, retained INITIAL binding recovery and
three immediate real Node CLI heartbeats now pass. This run also passed actual
N2 natural expiry, Node credential/binding revocation, explicit replacement
INITIAL/READ_EXISTING, proof negatives and privacy checks. Its only failure is
an independent oracle error: Store `GetMachine` returns `(nil, nil)` for a
missing row; the test incorrectly treated `err == nil` as machine existence.
The corrected assertion checks the returned object and still fails on Store
errors. No production change was made for this oracle correction. The case
stopped before its 120-second decay wait; that timing claim in this failed
run's metadata is not accepted. The evidence tool now attributes elapsed-time
claims only when their actual case passes. Original receipts remain unchanged.

Root then synchronized UI-only `e81b9dce28133861b5a8c5f45bb065e9721309f3`
(five appui files and its README; no appcore/Hub/Node/protocol/vault changes).
The next complete Linux and exact-binary Ubuntu runs use this reviewed source
with corrected QA inputs. Their results are not inferred from the prior run.

### N3 independent process acceptance

2026-10-17: **SCOPED_PASS** for the bounded Node enrollment, target-only status
and durable recovery slice. Actual production App core, Hub CLI and Node CLI
ran as separate processes with real ML-KEM-768 / ML-DSA-65 / AES-GCM, loopback
TCP and persistent SQLite/vault state. This is not full N3 live-canvas, desktop
GUI, physical-machine, native Runtime or release acceptance.

Source is `e81b9dce28133861b5a8c5f45bb065e9721309f3` **plus dirty QA code,
scripts and documentation**, stable build/test manifest
`dbf28641325cf4972bcca4ed2b18aa2495b0fbff8dc742078ecc1894b21d67e3`.
Reviewed runtime fixes are `ec72bf2891bcc7bf98565beedbac54e51f35b7db`; the later
`e81b9dc` changes only five appui files and the App README. The production
App-core/Hub/Node/protocol/vault inputs did not change in that UI checkpoint.
All 64 strict production/contract pins matched. Wire `1`, contract
`app-node-authority-v1`, software `0.0.5`, schema `63`, Git source and Docker
image identities remain distinct. Final documentation additions follow the
tests and do not retroactively change their recorded manifests.

| Gate | Result | Execution attribution |
| --- | --- | --- |
| `run-20261017T081549Z-XAbDdz` | **84 pass / 0 fail / 0 skip**; version, CLI compile, test compile, runtime and vet all exit **0** | Immutable Go 1.27.2 bookworm image `sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61` |
| `ubuntu-20261017T082902Z-VMU6lg` | **84 pass / 0 fail / 0 skip**; runtime and test2json parse exit **0** | Exact accepted binaries, no recompile; Ubuntu **24.04.4 x86_64**, UID 1000; immutable image `sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254` |

Both runs used disposable `--network none` containers, read-only root/source,
dropped capabilities, task-owned state/artifacts/ports and a task-owned locked
Go build cache. The populated module cache was mounted **read-only**. Owned
containers were absent afterward. No shared development Hub, resident
deployment, public endpoint, real key or production credential was changed.
Raw frames and synthetic private state stay in private task directories;
reviewable receipts contain safe facts, public identities and hashes only.

The genuine stopped N2 template from `8df8ae5` was independently copied into
each run after its original 07:43:00.992469179Z deadline. Its source tree SHA-256
remained `5f91ab669b3818526a52bd2648a5e3248cc604210d8d4dd87cb0ca64cc016037`
after both runs, matching both copy receipts. Each actual App unlocked the same
profile, made a fresh account login and completed new explicit N3 consent with
the same complete original public identities and byte-equivalent persisted N2
lease. No installer reuse, fresh Root ceremony or N2 renewal occurred. The Hub
ran `--hub-nodes-only`, without Control inference or a `control-local` machine.
Together with the independently retained N2 gate, this distinguishes account
login, Root proof and operation-specific authority.

The exact 84-event inventory is mandatory. It includes five operations × six
network faults, three actual local CAS crash windows, concurrent preparation
and confirmation, exact/conflicting replay, absent-original fencing and late
delivery, proof/scope/epoch/revocation negatives, read-cache eviction and
permanent mutation receipts, stopped-Node consent, real relay-only CLI recovery
and subsecond heartbeat ordering, private target-only status, zero-budget
READ_EXISTING and explicit abandoned-INITIAL recovery. UI actions use a normal
one-second command cadence; independent wire stress retries 429 with unchanged
ciphertext only. **Injected App 429 is never swallowed by that wire helper.**

| Final artifact under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T081549Z-XAbDdz/result.json` | `f29786333c4491cc20a825a9886fe20b0b308bfcb45242443b65477608f4f1ce` |
| Same run's `artifacts.sha256.json` | `383c6edf008144cf2ce9b002d27b74d2fae656bcbe36e4c4d5293ed63eeab027` |
| `artifacts/n3-acceptance/run-20261017T081549Z-XAbDdz/n3.test` | `bcbd70980b7b44474dff08621dc00cccb7c1d676c90283cdb498b99f6993461b` |
| Same run's matched `cicada` CLI | `867fd1c9610764dde6fecee5b83e7e621d16fe2a167ae07ac81a5d4bb1554da8` |
| `evidence/n3-acceptance/ubuntu-20261017T082902Z-VMU6lg/result.json` | `23558794d9399b9e0b18a46666ee477bafec008f30045808194227a5d48125aa` |
| Same Ubuntu run's `artifacts.sha256.json` | `2328571c0fab7b9f818026ec2cb1df1892c5384dbbd3bf9e33b45ffc73cff65d` |

These CLI/test binaries are acceptance artifacts. The integration owner builds
final clean revision-stamped delivery artifacts after reviewing the acceptance
checkpoint; delivery hashes are recorded separately, not inferred from these.

Reproduce from this worktree with the pinned offline images and module cache:

```sh
# For a new campaign, create a new stopped synthetic template first.
env -u CICADA_N3_AGED_SEED scripts/test-native-app-n3.sh --seed-expiry
# Wait until that receipt's original N2 deadline has actually elapsed.
# This recorded campaign retains the following unchanged synthetic template:
export CICADA_N3_AGED_SEED=/home/zyf/Cicada/.local/state/n3-acceptance/run-20261017T072753Z-DKv6h2/retained-aged-n2
scripts/test-native-app-n3.sh --require-n3
# Substitute the successful Linux evidence directory printed by the last run:
scripts/test-native-app-n3-ubuntu.sh /home/zyf/Cicada/.local/evidence/n3-acceptance/run-20261017T081549Z-XAbDdz
```

Every invocation allocates new private state and evidence. An unexpired,
unrelated, symlinked or overwritten template is refused. The template is never
mounted into a running product process; only the private clone is writable.
Linux exit **0** accepts exactly its declared scope, **1** is a failed gate and
**2** a prerequisite/selector failure. The seed returns SETUP_READY only;
default harness, `--discovery-only`, `--runtime-core` (83 events without natural
N2 expiry) and `--case=TestN3...` cannot promote to full 84-event acceptance.
`--case` accepts only the explicitly whitelisted runtime parents. Ubuntu
requires a successful full Linux receipt and its exact binaries/inventory.
Interrupts and skips cannot become passes.

| Finding | Disposition and independent evidence |
| --- | --- |
| Actual relay-only CLI hit 404 on exact `/v2/fabric/node/networks/direct/claim` | Fixed by Hub owner in `ec72bf2`; actual CLI idle polling and three immediate heartbeats pass in both final runners. No broad Fabric route was exposed |
| Fresh retained INITIAL stayed PENDING after approval/restart | Fixed by Hub owner in `ec72bf2`; both final lifecycle cases install the original approved candidate/key, then establish real heartbeat freshness |
| Pre-queue timestamp could admit an intent expired while waiting for the writer | Fixed by Hub owner in `ec72bf2`; separately attributed producer real-one-second RED/GREEN and transaction-time Client tests are in [Hub validation](hub-app-node-authority-validation.md#relay-restart-recovery-and-transaction-time-checkpoint). Independent short-intent TCP expiry passes; no claim of an independent writer-lock injection |
| QA admission cadence, first-retry fencing, tombstone-head expectations and missing-row oracle | Driver/oracle corrections described in the retained failed-run records above; original failures remain FAIL. No production changes were made to satisfy these incorrect assumptions |

No confirmed blocking defect remains in the **executed bounded process scope**.
The following limits are explicit:

- N3-06 uses stopped-private-DB epoch/revocation injection followed by actual
  Hub restart. The producer Store restore-fence test is separate. Complete
  backup/restore execution remains **NOT_RUN**.
- Real wall time proves short intent expiry, the original fifteen-minute N2
  expiry and 120-second Node heartbeat decay. Full fifteen-minute **N3** lease
  natural expiry is **NOT_RUN**. App clock offsets are App-only logical tests;
  renewable outer-cache aging is a controlled persisted fixture.
- Node restart/revocation is accepted; Node key rotation/UPGRADE is outside
  this slice. A heartbeat proves Node freshness only, never Worker availability,
  model availability, App SSE or native Runtime/Codex execution.
- Physical Ubuntu **24.04.3**, service installation and real Codex **0.163.0**
  execution are **NOT_RUN**. The reported host information remains
  USER_REPORTED_ENVIRONMENT; Ubuntu **24.04.4 container** acceptance is separate.
- Native Windows **DPAPI, ACL and GUI** execution for these artifacts is
  **NOT_RUN**. Earlier user-reported partial Windows observations stay attributed
  to their original source. Cross-builds do not satisfy native acceptance.
- Public HTTPS, strict PQTLS, Android interoperability, live canvas, App SSE,
  real native Runtime, installer, N4 and general v0.1 product readiness remain
  unaccepted by this checkpoint.

Integration-owner regression receipts were independently hash-checked. Their
sources and scopes remain separate:

| Root gate | Source and result | Receipt under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- | --- | --- |
| N2 `--require-n2` | Clean `ec72bf2`; 131/0/0, all eight lanes 0, stable source and cleanup | `evidence/n2-acceptance/run-20261017T080344Z-w08el5/result.json` | `016de1522409f3249e7c7696f8552cbc1a47ff0e6ecb161eb041a1270fb8b5d6` |
| Native App gate | Clean `e81b9dc`; 205/0/0, Windows crossbuild/dependency listing 0; native execution NOT_RUN | `evidence/n3-integration/run-20261017T055932Z-557c5d/native-ux-final/run-20261017T081147Z-I6pbgX/validation.json` | `fb21ea7e93fe71873e5c05f1cde5870bd16fb24035265020eacda1a5eb0da14c` |
| Standard Client disposable Docker interop | Clean `ec72bf2`; PASS, owned cleanup; legacy protocol scope | `evidence/n3-integration/run-20261017T055932Z-557c5d/standard-client-hubfix/result.json` | `f87922886156620f0dadc4660bbff72da03fe79f353f26b948f6283cbf35c91b` |

Evidence/parser unit tests: **12 passed**. Shell syntax, strict source pins and
Hub contract metadata checks pass. The full code and scripts remain exactly
those executed above; only these existing documentation files were finalized
after the gates. No push, merge, deployment or real-key rotation is authorized
or performed by this acceptance checkpoint.

### N3 idle decay and automatic status follow-up

2026-10-17. Latest bounded Linux acceptance is **84/0/0 plus a separate 2/0/0**
on reviewed App source `854a5943285b413ebf6d133af3685dd7f300c929` with dirty QA
inputs. Windows automatic redraw/polling has **not** been accepted. Earlier
`e81b9dc`/`e42640d` records, including the Ubuntu same-binary 84-event run, keep
their original source and artifact identities.

The user reported that the delivered `e42640d` Windows App kept showing Node
online after the Node had been stopped for more than 130 seconds. Root reported
no Node agent on the development host at 09:43 UTC. Clicking **Check Node status**
then displayed stale status. Record these separately: **USER_REPORTED_FAIL** for
idle automatic decay, **USER_REPORTED_PASS** for manual refresh. No exact Windows
UTC clock/offset, last authenticated heartbeat/deadline, or running-executable
hash was captured in this observation. Clock skew has not been excluded, and
the specific cause of that physical observation remains unconfirmed.

The old `e426` package also has **USER_REPORTED_PARTIAL** Windows/public-HTTPS
initial setup and real Ubuntu Node binding/heartbeat observations; Root
separately observed processes/binding read-only. These earlier results are not
erased by the NOT_RUN labels for the corrected binary. They do not constitute
complete Windows security/visual acceptance, a Node user-service/reboot test,
natural full-lease continuity or real native Runtime execution.

The prior 84-event test waits real wall time, then sends an explicit command
that calls `Controller.Snapshot()`. It establishes Core decay when queried,
without a new network request. It does not run a Windows window, its deadline
wakeup or redraw. Earlier native gates ran Linux tests and cross-built Windows;
the Windows-tagged renderer was not executed. Their scoped passes remain valid
and do not establish native no-input refresh.

The App owner fixed a reproducible code window in `530f5d5c24d16887bc9ef28be5a14beab03e920a`:
a snapshot can still be online when sampled, but layout's later clock check can
cross its heartbeat deadline and omit that redraw. The preserved equivalent
old future-only scheduler, exercised through real Gio Router/Frame processing,
selects a later eight-minute access deadline at D/D+1ns. Final-test overlay RED
retains **11 fail / 6 pass**, exit 1. This is a deterministic code reproduction,
not execution of the old Windows binary or proof of the user's clock state.

The production Windows layout now calls the same portable scheduling helper
tested through Gio Router. Due still-live projections request an immediate
resample; already-stale/expired fields do not create an idle frame loop. Saved
Node information remains visible through login/recovery and expired status
access. Connection facts, current permission and current observation have
separate labels; expired App access does not instruct Node reinstallation.
Status actions remain a subset of `AvailableActions`, with recovery first.
The producer's dirty Go/module manifest was
`685bdf3a81dafed9ec2a754a954520b1be298e81e9a6ffd5c29569f9918eded1`;
normal/race each **95 UI/native + 1 Core clock = 96 passed**, vet/crossbuild 0.

`854a594` adds bounded **30-second selected-Node polling**, not SSE. Its producer
normal/race each passed **104 UI/native + 35 Core = 139**, with no failures or
skips, vet/Windows build 0, stable dirty Go/module manifest
`8700f5d8cc629b64ab71a251ceccbc0acf5ae890df1e46547fce8a033a01e7de`.
The Core rechecks exact scope, grant, full approved binding, current login,
epochs, errors and pending/review state under `actionMu`. UNKNOWN/STALE Node
liveness may be polled while authority is valid. Each new request is durably
saved before POST; only status is automatic. It performs no Owner consent
signature, prepare/complete, confirmation, renewal or automatic recovery.

Foreground controls run before a due tick. Already-started reads share one
short busy period with all manual operations, including profile changes; there
is no preemption or queued scope handoff. The read context is limited to the
lesser of ten seconds and remaining authorization. Minimize pauses future
ticks without cancelling a valid in-flight read; close cancels it. Old-worker
state/flag writes finish before another foreground operation can start.
Uncertain or unauthenticated outcomes pause new requests. Complete authenticated
terminal receipts settle normally; a cancelled/late authenticated receipt can
be applied historically without becoming current authority.

QA independently reviewed the deadline, permission and worker-lifetime changes.
Because the second checkpoint also modifies shared `sendNodePending` cancellation
and historical-apply handling, QA reran the complete old 84-event suite before
running the two new actual automatic-entry cases. Code/scripts/pins/docs stayed
frozen throughout both gates; only task-owned `.local` evidence/state changed.

| Independent gate | Result and scope |
| --- | --- |
| `run-20261017T104732Z-c7hreg` | **84 pass / 0 fail / 0 skip**; all five lanes exit 0; full bounded Core/Hub/Node regression including real N2 natural expiry and 120-second Core decay |
| `run-20261017T110049Z-3BtJeC` | **2 pass / 0 fail / 0 skip**; all five lanes exit 0; real production automatic Core entry through the actual App child, TCP, PQ crypto, encrypted vault and SQLite; explicit test triggers, not a Windows timer |

Both gates have identical source manifest
`bc3ef0dc1d4dc4074279978b9032590e20bc6b4d8f704ecf034e8e50f1d6cba7`,
67 matching strict production/contract pins, and identical test/CLI binaries.
The source is **854a594 plus dirty QA code/scripts**, never attributed solely
to HEAD. The pinned Go 1.27.2 bookworm image, network-none/read-only-root/UID1000
isolation, read-only shared module closure and locked private build cache are
unchanged. Owned containers were absent at completion. No shared or public Hub,
real Owner/device/Node key, deployment or production state was changed.

The two new cases prove:

- `TestN3ActualAutomaticStatusKeepsScopeAndSelfCancelledNode`: wrong review,
  binding version, Owner, Node and origin reject with INVALID_ACTION, zero HTTP
  and unchanged encrypted-vault bytes. An App-only logical sixteen-minute guard
  test also has zero durable/network effects; it is not a natural N3 expiry wait.
  Valid UNKNOWN status is readable; a real relay-only CLI heartbeat becomes
  online through the automatic entry. Automatic segments send only the selected
  grant's status POST and preserve grant/head, budget and Client counters.
- In that same case, manual SELF_CANCEL stops new App reads while restarting
  the original Node CLI still commits a later heartbeat. Node ID, binding/version,
  key ID/fingerprint/epoch, complete identity-file bytes and relay-token bytes
  remain unchanged. Subsequent READ_EXISTING preview/Owner consent is explicitly
  **manual**, for the same saved binding with zero confirmation budget. Its new
  target works through the automatic entry. Only then, the stopped private DB
  has that one ACTIVE grant changed to REVOKED/SECURITY_FENCE. The actual Hub's
  signed revoked status settles without pending uncertainty; later triggers send
  no new packet or vault write. Owner/device/Node bindings are not revoked by
  this fixture fault.
- `TestN3ActualAutomaticStatusLossFreezesTicksUntilExactRecovery`: after a real
  status response commits and is lost, three later triggers send nothing and
  preserve the vault image. Actual App/Hub SIGKILL and restart retain the exact
  unresolved ciphertext; three more triggers still send nothing. Explicit manual
  recovery retries the original bytes and receives the identical authenticated
  receipt, then explicitly refreshes context and grant. Only afterward can one
  new automatic status be sent. Original full App/Owner identities remain intact.

The original stopped synthetic N2 template was cloned for the 84-event run;
its source tree still hashes to
`5f91ab669b3818526a52bd2648a5e3248cc604210d8d4dd87cb0ca64cc016037`.
The two automatic cases use new isolated synthetic fixtures. SELF_CANCEL
continuity is now an actual Node CLI result; Node continuation across a **full
natural fifteen-minute N3 lease/session expiry remains NOT_RUN**. Code review
shows Node credentials/relay heartbeat do not depend on ordinary App grant
expiry, but this is not a substitute for that elapsed-time test. Explicit
security revocation remains effective; Node-Control also checks its enrolled
Client device's ACTIVE state, so this is not a claim that all App-device state
is irrelevant to Node operation.

| Artifact under `/home/zyf/Cicada/.local` | SHA-256 |
| --- | --- |
| `evidence/n3-acceptance/run-20261017T104732Z-c7hreg/result.json` | `fb81e7cdf4b0a7733cedb38c9bcb194195dd549a6251d3bd17a141118c950d15` |
| Same run's `artifacts.sha256.json` | `ee9a0a3894abf19c19cc74cef2b207271aafb40a9aea6e7b91c99f56a7f20441` |
| `evidence/n3-acceptance/run-20261017T110049Z-3BtJeC/result.json` | `f34cb5b9641307d02e1e653b342b157f500d3191147d897be1e70492891567de` |
| Same run's `artifacts.sha256.json` | `c9d8496390627b6a7e8c8723589160e0294647dcbc103035d272bf73aeacd376` |
| Both runs' matched `n3.test` | `89b9fb8b1bfbf0d17cfaf0b681b6cd6670674af7fc200fee04af3be0a1ae9c54` |
| Both runs' matched acceptance `cicada` CLI | `867fd1c9610764dde6fecee5b83e7e621d16fe2a167ae07ac81a5d4bb1554da8` |
| App producer deadline/UX `evidence/n3-app/native-status-20261017-fu0fc8pv/validation.json` | `9047e02dc0a9c7131ca96f0d8282242fc62b291cd7e1093508c31dcbd87fe45e` |
| App producer auto `evidence/n3-app/auto-observation-20261017-z_8hgpqy/validation.json` | `71235407edbf5760890ca6d82bece33dad2fb6bb4bac75a532d4ef71d69cb13a` |

Reproduce the two independent scopes sequentially:

```sh
CICADA_N3_AGED_SEED=/home/zyf/Cicada/.local/state/n3-acceptance/run-20261017T072753Z-DKv6h2/retained-aged-n2 \
  scripts/test-native-app-n3.sh --require-n3
scripts/test-native-app-n3.sh --auto-status-only
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_native_app_n3_evidence.py
```

The first selector requires all original 84 events and does not accept N3-27.
The second requires exactly its two new events and records
`auto_status_acceptance=SCOPED_PASS`; its `n3_acceptance=NOT_RUN` means the
84-event suite was not executed **by that selector**. Neither selector accepts
Windows scheduler behavior. Exits remain 0 for the declared successful scope,
1 for gate failure, 2 for prerequisite/selector failure. Skips, zero matching
tests, changed source/pins or owned resource leaks fail closed. Parser tests:
**13 passed**, including rejection of auto-only promotion to full N3/Windows.

Root independently completed clean-854 gates. The first native attempt used an
older read-only module cache missing dependencies; it is retained as a **setup
FAIL**, not a product-test failure or pass. Stable closure rerun passed. Root's
Go-only native source fingerprint
`86fbebb7a34a830de89320705271a6c8e2cf6f8301792803dce9e3212b6af8a8`
and QA's full input fingerprint above are different inventories.

| Root receipt under `/home/zyf/Cicada/.local/evidence/n3-idle-decay/run-20261017T094657Z-93244d` | Source/result | SHA-256 |
| --- | --- | --- |
| `native/run-20261017T104907Z-o8vqd4/validation.json` | Clean 854; old-cache setup FAIL, retained | `8b1e7cf568b535c8d3922d8212cb35be3c33f60d1a85ac29cc19e44ccea9fd2c` |
| `native-stable-cache/run-20261017T105049Z-zya4KY/validation.json` | Clean 854; **303/0/0**, stable source, Windows crossbuild/list exit 0; native execution NOT_RUN | `92bad594c3bcc32816dde11682fc9f4f585d4f1454a7edec53397f68ba1d51cd` |
| `client-interop/result.json` | Clean 854; disposable standard Client interop PASS/exit 0, owned cleanup | `1525804e70d0d43b800572c603990d989d42f28df9ae8abc1dc61ed6f7b7d0d8` |

The candidate Windows App is built from **clean 854a594**, 13,387,264 bytes,
SHA-256 `e081168f2791b38d055a884b8334fefa63cba862a579b501b702decba55d301a`.
QA independently rehashed that file. Root verified PE64 GUI, Go/module inputs
and source stability. Its revision/source fingerprint are bound by an
**external SHA-bound source/packaging manifest**: this App does not reference
`buildinfo`, and revision/fingerprint linker values were not embedded in the
executable. Earlier wording about stamped App artifacts was not verified and
must not be treated as proof. Historical receipts remain unchanged. CLI/Hub
embedded metadata is separate; the App binary is attributed to clean 854, not
to a later QA-only documentation/test commit.

No confirmed blocker remains in the executed bounded Core/TCP scope. The old
Windows idle failure remains USER_REPORTED_FAIL, manual refresh remains
USER_REPORTED_PASS, and corrected native no-input redraw, actual 30-second
polling, complete native security and visual/interaction review remain
**NOT_RUN pending physical retest**. New-artifact DPAPI/ACL/GUI execution is not
accepted by a crossbuild. Windows clock skew remains unresolved. Old-package
Windows/public HTTPS/Ubuntu initial flow remains USER_REPORTED_PARTIAL; physical
Node user-service/reboot, full natural N3 expiry/Node continuity, real Codex/
Runtime execution, new-package public HTTPS, strict PQTLS, live canvas/SSE,
installer and N4 remain unaccepted.

### Login-first presentation follow-up

2026-10-17; preparation baseline `5fee32c`, App implementation
`1980dced7c20da0be40ac8a03892a911d2ffab9b`. The user reported that the Node
worked and that the App showed saved Node information before login. This is
USER_REPORTED, not an independently reproduced Windows run. The new source
hides saved Hub/account/Owner/Node details until a trusted current account
session has been inspected. Existing valid-session restoration is preserved;
there is no new password-on-every-launch policy.

QA independently reviewed the actual Windows root layout and its child-widget
branches, not only the visibility predicate. Before login the renderer uses a
reduced snapshot, a neutral numbered profile selector and separate public
status/recovery controls; it does not draw the status card, Node section,
details, canvas or preview. The deadline must be explicit, canonical and in
the future, the Hub verified, and the exact account/Owner/device scope present.
SESSION_ACTIVE, OWNER_READY and OWNER_PROOF_PENDING may qualify. Root pending
is still pending, and account login still creates no Root/Node/Manager power.

Account Recover/Retry precedes a new login. Necessary Node recovery remains
reachable without showing its identity; a Node-only pending read in a valid
account session does not hide the workspace. First connection, Owner key
import/proof and activation preserve their existing paths. The projection
does not mutate the Core snapshot, AvailableActions, trusted profile IDs or
saved bindings. The Core, vault, cryptographic and server files are byte-for-byte
unchanged from `5fee32c`; original-packet recovery and authorization remain
their responsibility.

Stored usernames are no longer prefilled. Passwords remain masked and clear
on submission. Full Hub/account/Owner/device/key scope changes and both
authentication transition edges reset input, consent, details, Node-pin
expansion, preview, canvas and scroll state. Repeated unauthenticated frames
preserve manual typing. Hidden screens pause future Node reads; a fresh
interval starts after successful login. In-flight/uncertain packets are not
discarded, and a second current-session check guards the scheduling entry.

All paths below are relative to
`/home/zyf/Cicada/.local/evidence/n3-login-gate/run-20261017T112228Z-187b47/`.
Hashes are SHA-256.

| Evidence | Scope and result | Receipt hash |
| --- | --- | --- |
| `app/final/receipt.json` | Producer portable UI normal/race each 141/0/0; Linux/Windows vet and amd64 cross-build exit 0. Tested `5fee32c` plus dirty App inputs; Go/module manifest stable `b9f78ea9e5b5c132d5afdc178e35c0a38825021b8e075baf159ced71a20060f7`; all 1150 files independently match committed `1980dce` | `ae381930ab144fe146249670bca35304fac8fa0a357e13d5de9bb601a9cf5c37` |
| `qa/review-final.json` | Independent source review and tooling SCOPED_PASS; 68/68 strict production pins, 13 parser tests, contract, shell syntax and diff checks exit 0; producer manifest matches 1150 files | `bebb65bcb9b9353dc19369b8680ebdbaa00b1b1f28e1f44e42d07d1fdd374c30` |
| `native/run-20261017T114144Z-lQ96Ie/validation.json` | Root broad native gate on clean `1980dce`: 340/0/0; Windows dependency listing/build exit 0; source stable | `26c482c03c7ca14ab1a4056333ce32af2bf1a7b2191d4d2f7f0e6e845b6bcd9b` |
| `client-interop/result.json` | Standard disposable real-TCP interop PASS, all four runners exit 0, clean `1980dce`; cleanup CONFIRMED, five owned container/image resources EXACT_ABSENT | `c789e92a20318240e0d96ce58f154faa70f30635e85c7bef6d4a1cfd58b521a8` |
| `app-build-receipt.json` | Clean `1980dce` Windows delivery build exit 0; separate from the native gate's test binary | `7134879b2d4a15d47cf27e36dab8c858100338e784721a595b506745d506ce02` |

The first QA tooling receipt, `qa/review.json`, retains FAIL with hash
`daecc8fc745dbbf1d248f8463eccdfb6286b979b0a03d47f744da0442acea741`.
The comparison accidentally prepended `cicada-go` to paths that already
contained it. Correcting only this path interpretation produced the final
1150/1150 match; product tests were not rerun to hide a failure. The earlier
producer `app/receipt.json` is also retained; the `app/final` receipt above
belongs to the final source.
Root's initial cleanup verifier also expected PASS where the cleanup schema
uses CONFIRMED; `interop-verification.json` retains the correction (hash
`a3225ed89ca0d0ffad9468f22a633a1df1536c602aba049cffacceefe2966516`).
No product rerun or historical receipt mutation was needed. Root recorded
the four resident containers unchanged; the disposable gate does not use a
shared development Hub.

The delivery artifact is
`/home/zyf/Cicada/.local/artifacts/n3-login-gate/run-20261017T112228Z-187b47/cicada-app.exe`,
13,407,232 bytes, independently rehashed as
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`.
Its source fingerprint is
`ececaacf28c29b153b11082d8c92264f71fcf06344b62ba24cdca07a234e34da`.
The external SHA-bound source/packaging manifest attributes it to clean
`1980dce`; it has no embedded Git attribution. Producer and broad-gate
cross-build outputs are distinct artifacts, not interchangeable hashes.

The production evidence tool now strictly pins 68 inputs, adding
`appui/login_view.go` and updating only the changed UI file hashes. Its overall
and UI reviewed source are `1980dce`; unchanged App Core remains attributed to
`854a594`, Hub runtime to `ec72bf2`, and the other prior component sources remain
unchanged. The earlier 84-event and separate two-event actual-process results
were not rerun for this presentation-only change and retain their original
source, binaries and manifests. They are not new Windows or `1980dce` TCP results.

Recheck QA tooling from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_native_app_n3_evidence.py
python3 scripts/app-node-authority-contract.py check
bash -n scripts/test-native-app-n3.sh
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import hashlib, pathlib, runpy
pins = runpy.run_path('scripts/native_app_n3_evidence.py')['CONTRACT']['files']
assert len(pins) == 68
assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() == h for p, h in pins.items())
print('68/68 production pins match')
PY
```

For the broad gate, set `CICADA_NATIVE_APP_GOMODCACHE` to the existing read-only
`/home/zyf/Cicada/.local/cache/n2-acceptance/gomod-go1.27.2-stable`, use a private
`CICADA_NATIVE_APP_GOCACHE` and fresh `CICADA_NATIVE_APP_ARTIFACT_ROOT`, then run
`bash scripts/test-native-app.sh` (exit 0 required). To reproduce zero skips,
also set `CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR` to
`/home/zyf/Cicada/.local/state/n2-acceptance/synthetic-openssl-owner-8t2OKM`;
these are four disposable synthetic PEM fixtures, never deployment keys. An
unset optional fixture can produce a skip and does not reproduce 340/0/0.
The script pins Go image
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`,
mounts repository/module cache read-only, locks its private build cache and
creates a fresh output directory. Producer targeted normal/race commands are
recorded verbatim in its receipt; they run `go test [-race] -json -count=1
./internal/appui/...` inside that pinned disposable container.
For standard disposable interop, give `CICADA_INTEROP_OUTPUT` a fresh,
task-owned path under `.local/evidence`, then run
`bash scripts/test-client-hub-interop.sh --suite client` (exit 0 required;
cleanup must be CONFIRMED). Do not point this gate at an existing Hub.

The initial independent source review found no blocker. Subsequent Windows 11
feedback reports the second-instance entry screen and Chinese text failures
below; the original test receipts remain attributed to their tested scope.
Basic login/logout and batch steps 1–5/8 have USER_REPORTED_PASS observations.
Independent native GUI execution, high-DPI, DPAPI and ACL checks remain
**NOT_RUN**. Exact-packet recovery, profile switching, precise timing and
individual layout/input cases still need separate evidence. Record the exact
artifact hash and separate results; do not log credentials or recreate a real
binding just for this test.
Historical user-reported partial successes and idle failure remain in their
original records. New-package public HTTPS, physical Node service/reboot,
natural full N3 lease continuity, strict PQTLS, native Runtime, Android,
canvas/SSE and installer acceptance remain separate and unaccepted.

#### Windows 11 basic login/logout user observation

2026-10-17. The user replied “符合预期，继续验收” to the coordinator's
three-step check for the delivered clean `1980dce` App candidate. Its SHA-256
is `27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`;
the source and external artifact binding remain those recorded above. The
environment and outcomes below are user-reported Windows 11 observations,
not QA-operated native tests.

| Step | Reported behavior | Result |
| --- | --- | --- |
| Signed out | Only the login screen is shown before account login | USER_REPORTED_PASS |
| Original account login | Login restores the same saved GPU1 Node information | USER_REPORTED_PASS |
| Logout | Saved information is hidden again | USER_REPORTED_PASS |

This accepts only those three reported behaviors. It does not establish fresh
session inspection across a process restart, natural session/grant expiry,
Root-pending behavior, wrong-password handling, uncertain-result recovery,
profile switching, high-DPI, DPAPI or ACL acceptance. Wrong-password and
close/reopen checks are the next guided steps and have **NOT_RUN** status at
this checkpoint. There is no automated native exit code or independent Windows
execution trace for this observation. Earlier Linux receipts, immutable
artifact hashes and historical Windows results are unchanged.

#### Windows 11 eight-step user batch

2026-10-17, after the basic three-step observation. Documentation baseline is
`a14ad2885f094c884a35decae570a6deadaf82fb`; the delivered App is still clean
`1980dced7c20da0be40ac8a03892a911d2ffab9b`, SHA-256
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`.
The coordinator later relayed the user's Windows PowerShell SHA-256 output,
`27AA167C847F278B26E7A2E908F7BAAB4E6EEC7971B10B32F0B4F7A72CCB4B28`:
**USER_REPORTED_ARTIFACT_MATCH** for this same delivered file. Case is immaterial
for hexadecimal comparison. This confirms file identity only; it is not a new
business, process-inspection, GUI, DPAPI or ACL PASS.
The user reported “全部正常，只有6第二App初始要求device code；7中文字体仍乱码，
样式字体以后再说，继续开发验收”. The aggregate reply is mapped to the
coordinator's eight numbered procedures; it is not independent native execution.

| Step | Procedure and bounded observation | Result |
| --- | --- | --- |
| 1 | Wrong password is rejected behind the private display boundary, followed by correct login. The optional recover-connection branch and its message were not separately reported | USER_REPORTED_PASS; recovery branch NOT_REPORTED_SEPARATELY |
| 2 | Close/reopen App, recover the still-valid account and same saved GPU1 Node without a new pairing/import | USER_REPORTED_PASS |
| 3 | Stop Node service, leave App open without refresh/minimization, then restart Node; App becomes stale and returns online | USER_REPORTED_PASS; exact cadence/timestamps not supplied |
| 4 | End this App's Node status access; current online status stops, saved connection remains, Node service remains active | USER_REPORTED_PASS; continuous-heartbeat trace not supplied |
| 5 | Explicitly restore finite read-only access to the same Node without a new pairing code or second Node | USER_REPORTED_PASS |
| 6 | Open a second App while the first holds the configuration; second App incorrectly shows initial setup/device-code entry instead of configuration-in-use/unlock guidance | USER_REPORTED_FAIL |
| 7 | Chinese text is still garbled; user defers font/style work. Other language-switch, resize, masking, readability and session-preservation checks were not individually reported | Chinese USER_REPORTED_FAIL; other subcases NOT_REPORTED_SEPARATELY |
| 8 | Leave the account session to expire naturally, observe the private information hidden without refresh, then log in to recover the same Node; Node service remains active | USER_REPORTED_PASS; exact elapsed time/command outputs not supplied |

Step 6 is assigned to the App owner. It establishes an incorrect second-instance
entry path; concurrent-vault-write isolation and corruption were not measured
by this observation. Step 7 remains a known user-reported display defect and
is deferred, not passed. The optional branch in step 1 is not an authenticated
exact-request recovery receipt. Step 8 concerns account-session expiry; it does
not establish Node continuity across a full natural fifteen-minute N3 grant
expiry. Service-active observations do not establish a reboot, continuous
heartbeats or native Runtime execution.

There is no independent Windows exit code or captured timing trace for this
batch. Dedicated native DPAPI/ACL, high-DPI, full uncertain-result recovery,
multi-profile isolation, real workspace/Runtime operations, Android, strict
PQTLS and installer acceptance remain unaccepted. The original three-step
record and Linux evidence are unchanged. A new App fix requires its own source,
artifact and verification record; these user results stay attached to the
`1980dce` candidate.

### Same-Node real Thread dialogue preparation

2026-10-17, baseline `a14ad28`. The user selected actual question/answer between
two real Codex Threads on the same logical Node ID and gpu1 host as the next
priority. Workspace/task-creation contract work is paused. The main lane is
the existing public Hub/account and actual gpu1 Node; a disposable Runtime or
two-Node fixture cannot substitute for it. The
[preparation matrix](native-app-plan.md#same-node-real-codex-thread-acceptance-preparation)
requires original native SIDs/context witnesses, a B-only answer, real
production MCP Join/ASK/receive/REPLY, explicit current authorization, actual
route evidence and separate acceptance/consumption/completion observations.
The real conversation remains **NOT_RUN**.

Root's preparation evidence is under
`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/`:

| Receipt | Observed scope | SHA-256 |
| --- | --- | --- |
| `start.json` | Records the Windows batch above, same-Node target and CLI `0.163.0` read-only observation; real dialogue NOT_RUN, no resident mutations | `ad219362e8e353e66af2ea5bffcb5ed85a43089cb637db5ac1cf538882c69203` |
| `public-preflight.json` | Unauthenticated GET only: public Hub health 200, `/v2/fabric/node/join` 404 with `route unavailable in Hub Nodes mode`; no Join/authorization/model call | `119834f8ad26c63cdaf950cb923206763e0accf3ef8d686d5aaa311282048d9c` |

The public metadata reports clean Hub revision
`e42640d4521b1925f2d9e869aba88f70a96daacc`, source fingerprint
`9e1e329b7c06285ac1e571596db689d9e9650a4b174e9badb10a47c811932695`.
It is distinct from the Windows App's `1980dce` source and the canonical dev
checkpoint. The probe proves only the recorded method/availability outcome;
it is not an authenticated native Join or public dialogue receipt.

The checked source has a Fabric service behind the Hub Nodes handler but a
bounded wrapper route allowlist. The relay-only Node already starts the local
Join bridge. Hub is reviewing the required native Join/metadata/key/peer routes
and typed Owner authorization; App must keep the existing Owner private keys
in its vault. No SQL-injected grants, replacement Owner or old N3 status grant
can satisfy that prerequisite. New ordinary same-Group traffic uses the
production sealed HubRelay route; matching Node IDs do not establish direct
eligibility. Direct and legitimate Relay fallback results must be distinguished.

No paid turn, deployment, public-process restart or conversation result is
claimed by this preparation. There is no placeholder driver whose NOT_RUN
output counts as delivery. An executable same-Node gate will be connected
only after the production entry points and authority contract are reviewed;
the old two-Node native driver retains its original topology and evidence.

### Profile recovery follow-up

2026-10-17, implementation `84d7aeefecccb4d1274d937bbaa0c07eecde5c2b`, based
on `a14ad28`. This fixes the batch's second-instance entry defect without
accepting its Windows retest or Chinese fonts. Native startup now requires a
complete trusted profile discovery. While discovery/unlock/resume is blocked,
the Core permits only discovery or a previously verified profile locator,
rejects Connect/identity/Node actions and publishes the restricted snapshot
atomically even during slow callbacks. A busy vault has the stable neutral
`APP_PROFILE_IN_USE` error and retry screen. Successful empty discovery still
permits normal first setup; the headless no-discovery caller can retry its
original card. No new credential, identity, binding or grant is generated to
escape a busy profile.

QA independently reviewed the Core guard, atomic snapshot reset, native entry,
temporary-list publication, trusted scope re-open and renderer flow. Failed
recovery preserves the original vault/pending packet. `loadIdentities` now
persists state only if the Owner/device key IDs changed: an unchanged or bad
session no longer causes an unnecessary vault rewrite. Required new/legacy
identity state and the exact pending request still cross the real vault barrier
before a secret-bearing POST. Tests include an actual second OS process holding
the vault lock, unchanged keys/packet recovery after release, slow callbacks,
reset/Snapshot concurrency, failed resume, legacy identity completion and the
persist-before-POST barrier. Source review found no remaining blocker in this
bounded fix; it is not a new peer/Runtime implementation.

| Evidence | Tested source, scope and result | SHA-256 |
| --- | --- | --- |
| `/home/zyf/Cicada/.local/evidence/n3-app/profile-recovery-20261017-1vxt9vq5/atomic-final/receipt.json` | Producer `a14ad28` plus dirty App inputs: normal 290/0/0; new Core scoped race 21/0/0; complete UI/native race 149/0/0; Linux/Windows vet and Windows build exit 0 | `e79db1c0d66230d3151ea19033c7fd1d976d24acbc8edd90a241195cd4696bb5` |
| `native-profile/run-20261017T125114Z-6qKm8d/validation.json` | Root clean `84d7aee`, 369/0/0, Windows list/build exit 0, stable Go+script manifest `557b1ce2078a3b55c899d91fdac1bfc3bf3f9d09a7eb29c20cc34baf42761bbd` | `0a073f727b864038385809e35af9584794cd21a4f4f7ab32f6a0c8a1aa4db83b` |
| `client-interop-profile/result.json` | Standard disposable real-TCP interop on clean `84d7aee`: four top-level/three subtests pass, script/runners exit 0, cleanup CONFIRMED | `34c53249e46d2bd04a015445e4de4bac3690a3bec31d850ab864add1642ed94c` |
| `client-interop-profile/cleanup.json` | Five owned container/image resources and private scratch EXACT_ABSENT; Root retained the four residents | `e9096f491c2e848a424b0fcffcbccb62fd7eba750b2ec7107269e94dbfa4463b` |
| `qa/profile-checks/receipt.json` | Independent bounded source review; 69/69 production pins, 13 parser tests, contract/shell/diff checks exit 0; 1151 producer Go/module entries match, five owned interop resources independently absent | `d8bacfaa113772b75fb7e904506d91bd54051e61abbebafd9aca0aac80dc540b` |

Relative paths in this table are under
`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/`.
QA compared all 1151 producer Go/module entries with committed `84d7aee`;
the before/after producer manifest is
`748629b4dd2e3c5adcefdcac58962beefa79e5636f349958c0848d7455755cf9`.
The earlier producer normal RED (279 pass, two fail, one skip), interrupted
race runs and intermediate source candidates remain retained separately.
The broad legacy N2 race run was interrupted with Root's agreement; it is
**NOT_A_PASS**. Scoped Core race and complete UI/native race above are the
executed race scopes, not a full 290-test race claim.

The standard native gate's Windows test-build hash is
`e0fb22ec52b091e8e6c63616e1c0fd546ce43bab55838275c496c62210cb406b`;
it is not a delivered or physically accepted Windows package. The `1980dce`
user observations retain their original executable hash. Windows two-instance
lock/retry, DPAPI/ACL and high-DPI on a matching `84d7aee` artifact remain
**NOT_RUN**. The Chinese display defect remains USER_REPORTED_FAIL and deferred.

The N3 evidence tool now pins **69** production inputs, adding the native
constructor and updating only reviewed App files. Overall, UI and App Core
reviewed source are `84d7aee`; Hub/store/contract component pins retain their
earlier sources. The prior 68-pin and 84+2 actual-process receipts are immutable
earlier-source evidence. They were not rerun or reassigned to this fix or the
native pair. Reproduce the standard native/interop gates using the earlier
task-isolation recipe and synthetic OpenSSL fixture. For current-source pin
verification, the earlier Python snippet must assert `len(pins) == 69`.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_native_app_n3_evidence.py
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import hashlib, pathlib, runpy
pins = runpy.run_path('scripts/native_app_n3_evidence.py')['CONTRACT']['files']
assert len(pins) == 69
assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() == h for p, h in pins.items())
print('69/69 production pins match')
PY
```

### Zero-model default-daemon initialization

2026-10-17. QA compiled an external, hashed Go test overlay against `84d7aee`
and executed the production `codexapp.StartRunningProxy` and
`InitializeExperimental` on the installed Codex CLI `0.163.0`. The actual
default daemon's WebSocket proxy handshake passed: compile/runtime exit 0,
one selected test passed, with no Thread reads/creation, queue requests or
turn starts. Existing daemon PIDs and global config were preserved. The
overlay never modified repository Go sources, HOME, CODEX_HOME or global config.

Evidence under the same Root run:
`qa/production-proxy-20261017T125911Z-1a43ab/receipt.json`, SHA-256
`9cf1f5cb0b443da2e136e75acdc949ed77f97a0922dc50c78280012d9b6c029e`.
Executed Linux test binary SHA-256
`8df8fee47bf59d5c698dd2cc8ad885510ca3c557a3e0556f8f98f95dfdca530d`;
external overlay test SHA-256
`fad0dadd148353a8b65168d0bc0888389134a980cdcb9c94b8f45fa2959f7134`.
The receipt's three `compiled_product_inputs` are selected inputs, not a
complete compiled-file inventory. The separate `source-review-posthoc.json`
in that directory (SHA-256
`2ecf0b18360336ac6cc141512bea3e909a5d6f0b089dbb260cc6f15b4c056067`)
compares all seven `codexapp` Go files and the 1151 repository Go/module source
entries with clean `84d7aee` and the frozen producer manifest. This is explicitly
a post-execution comparison, not a newly discovered contemporaneous complete
compile inventory; the original receipt remains unchanged and the probe was
not repeated.

The first raw-JSONL probe is retained at
`qa/initialize-20261017T125319Z-00f64a/receipt.json`, SHA-256
`566ee46f1f8c0a0e582b7ce4ddfe0552150efac561c9b3453e912853924daf89`.
Its proxy framing was incorrect: the production proxy requires WebSocket
Upgrade, while the separate standalone JSONL timeout remains unexplained.
Neither is recorded as a product-conversation failure or hidden by the later
successful production-helper handshake.

The [official app-server documentation](https://learn.chatgpt.com/docs/app-server)
describes initialization separately from `thread/start` and `turn/start`.
The actual 0.163 schema confirms that `thread/start` creates a SID; it was not
called in this probe. A new standalone server also does not prove that the
production default-daemon queue can deliver to its loaded Threads. Full tool
closure, per-Thread restrictions, original-context consumption, controlled
resume, loaded/cold wake and the requested real two-SID conversation all remain
**NOT_PROVEN / NOT_RUN**. No Root/development SID received probe traffic.

### Native-pair executable TCP lane: expected service RED

2026-10-17. `bash scripts/test-native-pair.sh` compiles the production CLI and
`acceptance/n3` binary, then selects five independent protocol cases. Each starts
its own real `--hub-nodes-only` CLI, persistent SQLite database, original App
vault, production N2 activation/login and explicit N3 Node confirmation. The
Node restarts with its approved identity. The new protocol caller authenticates
the saved confirmation with the original PQ keys; it never grants rights with
SQL. It is an independent typed PQ caller, **not** the production App's new
pair workflow or a real Codex Thread.

Source is `214a223e4432ecb3ee0ca947729b430aa3f9111c` **plus dirty QA inputs**.
All five executions reached the actual public new capabilities route and got
HTTP 404, with zero new pair secret POSTs. The result is
**EXPECTED_RED_SERVICE_UNAVAILABLE**, exit **1**, 0 pass / 5 fail / 0 skip.
Version, CLI compilation, acceptance compilation and scoped vet each exited 0;
the selected runtime harness exited 1. The bootstrap, wrong-scope, missing-proof,
loss/reconcile and replay assertions after discovery are therefore **NOT_RUN**.
The 404 is service unavailability, not evidence that any security negative passed.

Evidence directory:
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261017T133759Z-nycOEd/`.

| Artifact | SHA-256 |
| --- | --- |
| `result.json` | `9cfc32d3e632f47ac33fb077767ba8ed594eecacaa0ff2fce83ddcad859062be` |
| `source-before.json` / identical `source-after.json` | `e2eb52496ef4db65a681d03ef019f834c0be9b12dc2ba53ab773f5483040e6b3` |
| CLI `cicada` (33375282 bytes) | `a910496edfef407d39ae21d36693ef2e2ea0fa787bafed6b0f03d6752671a892` |
| `n3.test` (22163344 bytes) | `938f41748c5b9cb1548c927a9849b8d697b070f82a5b1d30d66956dfdb8766f7` |

The source manifest covers 1209 inputs: the full Go/module/embedded-asset tree,
the two new driver/evidence scripts and the selected contract/plan documents.
Its aggregate SHA-256 is
`f7af22ec25ee0099accc55d0040a2ec1a9091d99d217507a6618e220688545b3`.
The unchanged before/after manifest includes the exact tested dirty QA test
source. Later documentation and the eventual commit do not relabel this build
as clean or change the original receipt.

Execution uses Docker image
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`,
literal fixture loopback TCP, no Docker network, read-only repository and module
cache mounts, a locked task build cache and owned private temporary state. The
owned container was confirmed absent. There were zero model turns, no native
daemon operations, no shared development Hub and no public deployment change.

Reproduce from this task checkout using the populated read-only offline module
cache and pinned image:

```sh
bash scripts/test-native-pair.sh
```

Every run has fresh state/evidence/artifact directories under
`/home/zyf/Cicada/.local/{state,evidence,artifacts}/native-pair-acceptance/`.
The result records per-stage exits, source/artifact hashes, exact selected tests,
missing/skipped cases and cleanup. A future available service must satisfy all
five assertions to return scoped exit 0; neither 404 nor EXPECTED_RED returns 0.
Actual request/response envelope bytes and monotonic elapsed microseconds are
logged for new protocol POSTs once discovery succeeds. No such POST metrics
exist in this initial unavailable run. Runtime/MCP consumption, both reserved
Joins, dual consent, real same-Node Relay and Windows DPAPI/ACL/GUI remain
**NOT_RUN**. This lane does not update the earlier N3 production source pins or
promote old 84+2/native/interop receipts to the new protocol.

### User executes the real two-Thread acceptance

2026-10-17. The user clarified that they will personally test two real Threads
on the same physical gpu1 and logical Node. The earlier Root-run real-Runtime
proposal is withdrawn. Root/QA do not arm the WS adapter, create SIDs, start or
continue model turns, or operate the native queue. QA preserved its adapter
work separately and stopped expansion. The executed tests below are synthetic
TCP/WS tests of QA tooling; they did not connect to Codex or start any model.
No real Runtime result, current Windows acceptance or pair permission is implied.

The historical WIP command `bash scripts/test-native-pair.sh --ws-adapter`
on dirty `96c07d8` passed 35
selected tests in normal and race mode (35/0/0 each), with both compiled test
binaries, execution, version and vet exits 0. It tests correlated ownership of
at most two root Threads, default-disabled mutations, durable original intents,
loss/reopen fencing, complete allowed-MCP lifecycle, alternate-tool refusal,
separate observed/explicit turn counts, unfinished-turn restart fences and exact
owned interrupt terminal evidence. The owned fixture container is independently
absent. Real Codex/API exposure, native consumption, automatic wake, idle traffic
and provider requests/cost are **NOT_RUN / NOT_OBSERVABLE**; a pure WS interrupt
acknowledgement is not proof that a real provider stopped. The retained library
is a transport/audit primitive, not an armed dialogue gate.

The withdrawn source is excluded from this task's development/user-delivery
change. Four complete Go files, the pre-split runner/evidence scripts, fixture
snapshots and the full pre-split QA patch are reversibly retained under
`/home/zyf/Cicada/.local/state/native-pair-acceptance/run-20261017T135547Z-I0Nc1a/withdrawn-ws-wip/`.
Its `archive.json` SHA-256 is
`71bdea7a3b84bce49423dbb14a4bb73170ce1ddffed0f00ccb524fd4d262e9be`.
All eight source/snapshot hashes were checked before removing the untracked WS
package from the worktree. The original 35/35 result and binaries below remain
unchanged. Current `test-native-pair.sh` has only protocol and Store regression
modes; it contains no reference to an omitted WS package. The historical WS
command above is no longer an active entry. Deliberate reconstruction from the
archive requires a separate review and does not authorize any real Runtime use.

Evidence root:
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`.

| Artifact | Scope | SHA-256 |
| --- | --- | --- |
| `run-20261017T135547Z-I0Nc1a/result.json` | Final synthetic WS scoped PASS, exit 0 | `12693f9d887eded08d2eddc4c59460bf0db18918192923724b979fbe01b3675f` |
| Executed `nativepair.test` | 12391681 bytes | `7a49b6490e91636db030c39d5247c91b7c13c930503ca27ae989c6392e2a2e7c` |
| Executed `nativepair-race.test` | 15872244 bytes | `be106f9ada782d63c3a6ca5bfe1d95e9a2f51f59892e584d321eb13eca5fabc2` |
| `manual-preflight-20261017T135649Z-57c9a6/receipt.json` | Independent current public GETs only | `b9b2093c9e3ed05d642853853cbccd748f509aa10e28f18647da21221a3eb00a` |
| Same preflight `health-source.json` | Current deployed Hub source projection | `a7f82055326c23f8ed95c46542ee5d3848f92c0849688a3fa61613b442d2d106` |
| Same preflight `handoff.json` | User-manual correction, retained WIP, cleanup/source review | `69ff975ec0de6697b2c1ee5ce751cf80ec3cb4d2e84318be8d13d55c5b37e6be` |

The final synthetic manifest covers 1213 inputs, aggregate SHA-256
`4704a13e31304e18ec89f35cf717525cd2e32079a202d8582345b36f98ca2cc0`,
stable before/after. The separate handoff compares the 1211 Go/module/asset and
driver inputs after execution. Earlier synthetic receipts remain their own
source candidates: `run-20261017T135138Z-WvyzgU` tested 33/33; the later
`run-20261017T135314Z-asWhH0` and `run-20261017T135427Z-CIApHM` tested 34/34
before the unfinished-turn fence was added. No synthetic receipt is native PASS.

At 13:57 UTC the real public Hub reports version 0.0.5, clean revision
`e42640d4521b1925f2d9e869aba88f70a96daacc`, source fingerprint
`9e1e329b7c06285ac1e571596db689d9e9650a4b174e9badb10a47c811932695`.
The old App/Node capabilities return HTTP 200/available in `--hub-nodes-only`;
the new native-pair capabilities return HTTP 404. This is independent public
read-only evidence, separate from the disposable five-case 404 lane. No auth
headers, mutations, SID/turn/queue operations or full response payload retention
were used. App's delivery owner separately confirms the user-delivered Windows
EXE remains `1980dce`, SHA-256
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`;
`84d7aee` is integrated development code, not a new recorded user delivery.
At that historical checkpoint the delivered App had no pair UI/Dispatch;
manual scope was login and original gpu1 status, with the full pair path
DELIVERY_PENDING and **NOT_RUN**. The later clean-4ca package is recorded below;
this preflight does not describe its current build status.

The [manual skeleton](native-app-plan.md#same-node-real-codex-thread-acceptance-preparation)
starts with matching upgrade-package hashes, then the user's two same-Node Joins,
App's two exact consents and A ASK/B Reply/A receive in their original contexts.
Exact new Join/button commands await actual delivery. Windows DPAPI, ACL and GUI
checks on a matching future package stay **NOT_RUN** until the user executes them.

Root additionally reports the installed Codex 0.163.0 read-only
`codex mcp list --json` returned `[]`. This is
**ROOT_REPORTED_READONLY_MCP_DISCOVERY**, not QA execution of either user's
Thread, a configuration change or a native model call. The manual procedure now
requires reviewed Cicada MCP setup and actual loading in each selected Thread,
preferably launch/Thread-scoped without changing global tools/model. No
`codex mcp add` or other registration command was executed by QA.

Baseline source review confirms `runMCP` accepts `--api-url`, while its default
localhost URL is not evidence of a usable deployed origin. The trusted local
Join derives native identity only from Codex's injected environment and checks
the local session/workspace record. MCP state is privately scoped by normalized
origin, harness, native SID and Node, and the Node state directory supplies the
existing local bridge/key state. Both user Threads must use approved Node ID
`gpu1-node` and that original state directory; neither hand-setting a native
SID nor creating a second Node is acceptable. Exact new API origin, retained
Hub/Owner pins, private MCP state path and reserved-slot entry remain pending
the reviewed Hub/Node delivery. No guessed startup command is presented as
ready. MCP registration/availability does not establish pair authorization.

### Independent A2 preparation review: status-cache replay defect

QA read-only review of `17da3936e87ca07222bb416f0cacec57df2e1daa` found that a
still-fresh status request could be evicted by the 128-entry cache across a
diagnostic rate-window boundary. Replaying its exact original PQ packet then
returned newly observed `COMPLETED` data with `administrative_permission=true`,
instead of the exact old receipt or `READ_EXPIRED`. The original packet was
unchanged. This violates the read-ID/history contract; it does not demonstrate
a bypass of fresh mutation authorization. Hub acknowledged the defect and owns
the production fix. The preparation capability remains false, so this is not
an enabled user path or a public deployment result.

The isolated counterexample uses the production Store and real PQ envelopes,
reusing its synthetic guard fixture through an external Go test overlay. It is
**not** TCP/App/real-Runtime or N2 end-to-end acceptance. Open the rate window
at t0, issue the target at t0+59 seconds, fill 126 more reads, then issue two
new reads at t0+60 seconds. Both the cache eviction and an exact pre-eviction
retry are checked. The exact post-eviction original, only about one second old,
receives a changed observation. These are trusted synthetic Store timestamps,
not claims of natural wall-clock expiry.

Evidence:
`/home/zyf/Cicada/.local/evidence/native-pair-review/run-20261017T145922Z-c93307/`.

| Artifact | SHA-256 |
| --- | --- |
| `result.json` | `48e77fa4a1536d4b94112f2c9de255aee6478a22aaec6a33ff5f19142c452291` |
| External Go test | `d9ef5946e939ccdb59fbb16cb001a7d965846067e1934b2395bd717d588a6f31` |
| Executed `qa-cache.test` (26891406 bytes) | `b73a384b1e19c0d3661290fed9a70b6a7548b7db14a3963e8d2d4b02ddc4faf9` |
| `source-review.json` | `be10aea4fb5e04cbb380564b21f1e59f5e0e24ad97b46e8a5b80cd0e3b4067d1` |
| `reproduce-fresh.py` | `5267721ebca4451fff8a529b9336376674d9add697f35e3876af5454a300a536` |

Compilation exited 0; the one selected test failed, exit 1, with
`QA_FRESH_READ_REFRESHED_AFTER_EVICTION`. Result is SOURCE_DEFECT_REPRODUCED,
not an acceptance PASS. Source was dirty `17da393` with unchanged complete
before/after manifest
`7ba37a427ceda459eb32d573f0494c442ab62cb3b17c58494e95423b932fe894`.
The owned container is exactly absent. No production source, resident state,
native queue or model was modified or invoked. Root/Hub were informed and the
QA source freeze released after completion.

The separate read-only source review compared all 27 changed Go/JSON/checker
inputs with both producer final normal/race selected manifests: no mismatch or
missing selected input. Their 73/0/0 receipts retain dirty `96c07d8` attribution;
the earlier broad 1715/0/11 run and pre-final disposable interop remain their
own sources. This comparison is selected-input evidence, not a full compilation
dependency inventory, and none of those earlier passes covers this new case.

Reproduce the frozen counterexample into a **fresh** owned run without
overwriting its original evidence:

```sh
python3 /home/zyf/Cicada/.local/evidence/native-pair-review/run-20261017T145922Z-c93307/reproduce-fresh.py
```

On `17da393` this returns exit 1 for the demonstrated defect. It is not a
readiness gate. The proposed Hub fix protects still-fresh read cache entries and
uses bounded backpressure; it must also reject far-future status/original-status
reconciliation without publishing a forgettable READ_EXPIRED outcome. That
associated future-time case was code-reviewed and accepted by Hub, **not run**
by this overlay. Fixed-source regression checks must allow legitimate bounded
backpressure and record their own inputs/receipt; no GREEN is claimed yet.

The independent regression is now retained as
`scripts/fixtures/native-pair/read_cache_test.go`, inserted into the test-only
Store package through its explicit overlay. Its reviewed-policy assertions keep
the same cross-window arrangement, require two capacity backpressure outcomes
at +60s, preserve the original exact receipt while protected, then allow
eviction at +150s and require READ_EXPIRED for the stale original. It does not
raise cache capacity or create permanent polling tombstones. The prepared
target is legitimately issued 30 seconds ahead: at +119s one oldest entry may
be replaced, but a second new read must still backpressure and preserve the
target's exact receipt. Closing and reopening the same persistent Store must
also retain that exact protected history; this is not a Hub/App process restart.
This distinguishes the required full freshness guard
from a shorter 60-second server-age hold. A second prepared
case rejects a status issued 31 seconds ahead using trusted writer time despite
an untrusted input timestamp. Its detached reconciliation must also reject and
roll back both read-cache and rate rows. The same bytes must receive their first
legitimate observation later and retain that exact history after clock rollback.
Both cases were **NOT_RUN** at preparation; the frozen run is recorded under
"Independent frozen Store cache and Join-deadline gate" below. Reproduce with:

```sh
bash scripts/test-native-pair.sh --store-regressions
```

For an independently frozen Hub worktree, set
`CICADA_NATIVE_PAIR_STORE_SOURCE_ROOT=/home/zyf/Cicada/.worktrees/cicada/n2-hub`
before that same command. This override is accepted only in Store mode; both
the product source and QA harness mount read-only. The before/after manifest
separately inventories the complete product Go/module tree and QA drivers,
including the external test overlay, and records both worktree identities.

This selects only the focused Store/PQ regressions in normal/race modes, with retained
executed binaries, manifests and scoped vet. At preparation it was **NOT_RUN**
pending the Hub fix checkpoint; formatting/syntax checks are not compilation or execution. The
main TCP readiness case now consumes the shared strict capabilities decoder;
it has not been rerun against the explicitly unavailable preparation service.

The resumed Hub review added an independent JoinUntil regression to that same
Store-only command. `lease_deadline_test.go` uses synthetic zero-Join row setup
and real ordinary heartbeat transactions at +4/+8 minutes, proving both original
native and access leases remain live beyond the Join deadline. Six cases cover
one/two accepted slots at JoinUntil minus one nanosecond, exactly JoinUntil and
plus one nanosecond. A single-slot WAITING_JOIN must deny self/renewal at and
after the deadline, leave both leases unchanged, and report EXPIRED through a
real PQ status packet. After that terminal state is persisted, an actual Store
candidate-publication call with a real attestation must also reject without a
candidate or lease effect. The precise time-boundary oracle uses the common
self Guard's injected time; candidate publication's production wall clock is
not replaced.

Two accepted slots in WAITING_CONSENT may retain the original live identities,
epochs, credentials and lease owners across JoinUntil; both leases must clamp
to the absolute peer ceiling. ACTIVE acceptance remains **NOT_RUN** until the
real dual-consent and original GroupKeyGrant transaction can create it; no SQL
state change substitutes for that authority. The prepared Store suite now has
three top-level cases plus six deadline subcases, which were **NOT_RUN** pending
the new producer freeze and are now reported in the frozen run below. Earlier producer tests using a single-slot cross-deadline
positive do not validate this corrected boundary and keep their original scope.
Each prepared lane has a 180-second test timeout for this expanded required
matrix. Exact Docker/Go argv and both actual normal/race test binaries are
retained, with matching pre/post execution hashes required for PASS. Evidence
JSON creation refuses to overwrite an existing receipt. The QA fixture DB lives
under the run's private host-bound state directory; a separate producer tmpfs
retry cannot replace it or prove physical-storage/abrupt-power-loss durability.

App frozen `final-01` was independently reviewed without source mutation or
duplicate tests. All 1196 Go/module inputs matched manifest
`663db4df91ecea8d369ae95d722995343111ef07a2db4a75889a45701e3e0558`.
No additional definite App blocker was found in the reviewed actions, original
packet/receipt CAS flow, nested target-bound fence recovery, reopened/expired
permission projection, private pre-login recovery, per-slot explicit consent or
Owner-public-only export. The read-only review artifact under the same defect
evidence directory is `app-readonly-source-review.json`, SHA-256
`ecced23fdad3e8087cac6a3a1eba8ccc894fa3ad3af609eed1d04a14540aacfd`.
It captured the producer's RUNNING state and remains unchanged.

The later App producer `final-01/validation.json` under the earlier Root run has
SHA-256 `13966e3441d3320a74185b06313e67197dd0e9f4d512844e79207736e4fddfda`:
normal 319/0/0, scoped Core race 25/0/0, complete UI/native race 153/0/0,
Linux/Windows vet, dependency check and Windows cross-build exit 0, stable dirty
`17da393` inputs. Its scripted PQ actor is explicitly not the production
Store/Guard/Runtime chain. This is producer-scoped evidence, not independent
execution, a new user-delivered EXE or Windows physical DPAPI/ACL/GUI acceptance.
The Hub read-cache defect is tracked separately and does not become an App
consumer-checkpoint defect merely because the complete chain remains unavailable.

After App committed `209b2081085d41dbccf0516f8379b9d40d98be2e`, QA independently
read its Git archive and matched all 1196 frozen Go/module inputs without a
missing or changed entry. Both commit identities match the server global
identity. `app-209-archive-review.json` in the same independent review directory
has SHA-256 `7ea822ee1539827677e1f81accb697f0f5aeee47085547d8a1ccbf888ebca5a8`.
This is a post-execution comparison; it neither reruns a gate nor changes the
producer's dirty-`17da393` attribution to a clean-`209b208` execution. Windows
physical checks and the real user-operated pair remain NOT_RUN.

### Clean App-consumer source: separate Client TCP compatibility

Root executed the standard disposable Client interop gate on clean
`209b2081085d41dbccf0516f8379b9d40d98be2e`: PASS, exit 0. The actual four
top-level cases were `TestClientDockerHubSmoke`,
`TestClientDockerHubHeadlessOperator`, `TestClientDockerHubOwnerBootstrap` and
`TestClientDockerHubRecoveryFixture`; each runner exited 0. Scope is real TCP
Hub/Go protocol client, bounded public SDK, initial Owner signer bootstrap and
existing exact retry/recovery compatibility. It is **not** Pair Store/Guard,
Pair activation, real native Runtime, Windows physical or public HTTPS PASS.
The App producer `13966e…` receipt keeps its original dirty-`17da393` source;
this clean-source gate is separate evidence, not its replacement or relabeling.

Evidence under the earlier Root run:
`app-consumer-client-interop/`.

| Artifact | SHA-256 |
| --- | --- |
| `result.json` | `6cc89ee2c7a1c05d22a1bcbacfed59856aad5050d05453f967eb8872f0963a9f` |
| `cleanup.json` | `d2db532fbaad6cbd99a2fc45653773498f2b2327a623b412e1dd2d75a9080787` |
| QA `app-209-interop-cleanup-review.json` under the independent review directory above | `89875e7306ebf87444797a071e90c0d267d1f14ba6f7a7f06ff76871a04f7b40` |

Source fingerprint:
`960e82ad6563d512bfa2036579cacb8963861fec8cfa99ebd9b17105b4e1c86f`.
Hub image:
`sha256:c8ec6eb1a58f3cbd8a6d5b3880480ee0d3832aa6ea97ccda4731479625b58199`.
Receipt source is `dirty=false`; wire/catalog remains separately identified by
catalog SHA-256
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.

Cleanup is CONFIRMED: three task-owned containers, two temporary image tags and
private scratch EXACT_ABSENT. QA independently inspected those exact five
references and confirmed scratch absence without repeating the gate or mutating
resources. The four original resident IDs were retained according to Root's
separate before/after check; QA did not access resident state to make an
independent retention claim. No new models, native queue operations, deployments
or user package delivery occurred. The false Pair capability and pending
cache-regression check remain unchanged; no readiness gate was rerun.

### Resumed Node-key/helper checkpoint review

The coordinator resumed the existing `17da393`/`209b208` integration work and
rejected a second Owner/App/Group authorization framework. The independent
review here concerns only the App owner's frozen Node-key and unwired helper
checkpoint, not the unfinished CURRENT carrier or actual Pair MCP dispatch.

Producer evidence is under
`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/node/resume-01`.
Its `producer-receipt.json` SHA-256 is
`611d848576319b267205aa09ac93e95eadd96b488b19449c5243a23858bcb8e3`.
The tested source is **dirty `209b208`**, full input manifest
`10478416e0df121923e72ef8259397d0c3aa47901b64268a92e5e0aa3ce472cb`.
QA independently matched all **1254/1254** listed inputs, including the complete
1250-file product Go/module tree, with no unlisted product-tree files. This is
a posthoc source comparison, not execution on clean `209b208`.

QA separately rehashed and recounted the original Go JSON terminal events:
NodeKeys normal **112/0/0**, scoped command tests **10/0/0**, and scoped race
**15/0/0**, including subtests. Each exit is **0**, every selected package has
a PASS terminal event, and the before/after source snapshots are identical.
The earlier noexec environment failure remains a failure before test execution.
QA did not rerun these component gates; their executed test binaries were not
retained by the producer, so no binary SHA is asserted for them.

| Independent receipt under `/home/zyf/Cicada/.local/evidence/native-pair-review/app-node-20261017T234757Z-ad4bviws` | SHA-256 |
| --- | --- |
| `app-source-review.json` | `de8e93e3c7d269c702a49503367c7758821353e6a21114723f2c3d2ca88eab0d` |
| `producer-review.json` | `16d2fc47b8e6b5f7d6bea195d2d158a0442bd4eb854e09535a99d470d01bbf49` |
| `cleanup-review.json` | `feaf1e2fe57ab0efc3aa93365eee1e1e8ff8190891df0162065eeece5dff02af` |

The producer's separate `cleanup.json` SHA-256 is
`90d41f1555e495396f5247a8989cf33fa59ff72bf0b736da004fc2287cdd2b92`.
QA independently inspected its two exact container names and confirmed both
absent without deleting resources or inspecting resident state. The original
producer receipt remains unchanged. The prepared QA Store runner uses its own
`native-pair-acceptance/go-build` cache and lock, with the shared module cache
read-only, so it cannot concurrently write the App producer's build cache.

The bounded result is **SCOPED_REVIEW_PASS** for independent recount/source
review of NodeKeys and unwired helpers. Actual CURRENT verification, original
Join receipt application, same-epoch native **and** access lease renewal,
production Pair MCP dispatch, disposable Hub interop, real Runtime/queue/provider,
public HTTPS and Windows DPAPI/ACL/GUI remain **NOT_RUN** by this checkpoint.
An `existing=true` budget/submission lookup is historical recovery only and must
not authorize a new invocation. Recovery after JoinUntil does not prove a live
lease, and an expired accepted receipt must never revive authority. No readiness
gate or previously completed user batch was rerun; no Git mutation or deployment
was performed by QA.

The coordinator subsequently requested retained executing-binary identities
under the same three selectors. Additive producer receipts under the same
Root run's `node/` directory are retained independently:

| Supplement | Producer receipt SHA-256 | Result |
| --- | --- | --- |
| `binary-identity-01/producer-receipt.json` | `eb9b1b5a42014ca25ef0d588b1d758de2fd510ee1cd2815d371b5622e83d1f99` | FAIL: NodeKeys 109 PASS / 3 FAIL, exit 1; command 10 and race 15 PASS |
| `binary-identity-02/producer-receipt.json` | `dd7994e53bbb1650515fadb51ad78c81ceda6bdaaec82d05ff6f036b1b2bf898` | SCOPED_PASS: 112/10/15 PASS, no FAIL/SKIP, all exits 0 |

The first run-local retention wrapper imposed umask 0077 on execution, making
two existing insecure-mode fixtures private at creation. Those two subtests
and their parent failed; all failed logs and binaries remain retained. The
corrected wrapper restores inherited umask 0022 before executing the original
test binary. Both runs used identical four binaries and the original frozen
1254 inputs. Their results do not replace the original `611d8485` receipt or
retroactively supply its missing executed-binary identity.

| Retained actual binary in supplement 02 | Bytes | SHA-256 |
| --- | --- | --- |
| `artifacts/nodekeys-normal/nodekeys.test` | 9941255 | `31496a77912e70b7d7b3967c27ccbe932cf77e8b477694138fe8f23e258decc0` |
| `artifacts/cmd-scoped/cicada.test` | 30118151 | `2acbb6b787137d79f9716f92492f534b51713ab90ea43422be9a74031146e78c` |
| `artifacts/pair-race/nodekeys.test` | 18624775 | `dd917858675eef8411f99240199e01ebad14386e07307dc9f60eda852eb5cfd4` |
| `artifacts/pair-race/cicada.test` | 49201415 | `8f9c6a30560c59165c4079a556264098b2f8d5d59976ae7f6d59b7427f356284` |

QA independently rehashed all retained files against captured original/copy
hashes, verified NUL-delimited actual argv and test-name equality with the
original selectors, recounted both runs, compared before/after source, and
inspected the two exact supplement container names as absent. All 15 files in
`node/commit-candidate.json` matched its hash inventory at review time; that
candidate manifest SHA-256 is
`aeedcb878d6978d76d00b9206965b6301ce81922fac98e3f20b50560d1015544`.
The separate QA `binary-addendum-review.json` under the independent review
directory above has SHA-256
`a0a60e20132e601e7028eafd3c3877984f7e228fca7d19e50835d643913754ee`.
This is **SCOPED_REVIEW_PASS** for incremental binary/log/source/cleanup review;
QA performed no additional execution. The original failed run and all CURRENT,
actual Pair MCP, live-lease and native Runtime limitations remain unchanged.

Root subsequently integrated App commit
`a451b9bb2bd57acebe248a9ab80310f214c8c040`, parent `209b208`. QA independently
matched all **1254/1254** frozen inputs against that commit's Git objects and
observed Author and Committer `DaiVernon <205618093@qq.com>`. The separate
`commit-source-review.json` SHA-256 is
`2d5e43474c7c24ce64e2b521db2ac5f2c486455cb509a0d6ab829c61dc5e09db`.
This records source equivalence only; all actual helper executions above remain
attributed to dirty `209b208`, not a clean execution of `a451b9b`.

### Independent Windows prerequisite package review

2026-10-18 UTC. Root froze a Windows update for existing-profile recovery and
public-only Owner key export, without changing the deployed Hub/Node. Evidence
is under
`/home/zyf/Cicada/.local/evidence/n3-app-prerequisites/run-20261017T235433Z-06169a`;
the corresponding artifacts directory contains
`Cicada-App-N3-prerequisites-209b208.zip`.

| Reviewed artifact | Bytes | SHA-256 |
| --- | --- | --- |
| ZIP | 5738771 | `2f1818677cb5f038e9d367b6788a199130071206ce78cdbb673b3269b645a86c` |
| `cicada-app.exe` | 13781504 | `b93faa83ebb5ebaba9e6b082046994e7152a66e7418a207f29b23ffc96e61c69` |

QA independently matched all 47 ZIP entries and 46 SHA256SUMS members, the
retained EXE and PE header, and the before/after build snapshots. All **1241/1241**
source-file contents match the **`209b208` Git objects**, including all tracked
`cicada-go` files and root LICENSE. This comparison used the recorded revision,
not later dev. The source-manifest **file SHA** is
`e6409346def66d90b0a59aa4ec17a56d9f201a57a47956d1ecfc125ac4e61d78`;
its **internal input-inventory digest** is
`ebecab5234a170186c09c9f10c032e41c73941efe33ad65fd3b2a910e9d2443f`.
They identify different byte inventories and are not interchangeable.

The original build receipt incorrectly recorded a source filename as
`container_name`. It remains retained with SHA-256
`2d928850152b125327855113f2f7280af6a881f57c84b1ebc3477321cac2cff8`.
The package's corrected `validation/build.json` explicitly cites that original
and the exact Docker command; QA verified the corrected name and observed the
exact build container absent. No rebuild or historical-result replacement was
needed. All 11 compiled dependencies are covered by the 20-module notice
superset, with every notice hash matched. The finite package-member and
structured-JSON inspection found no private-state-like member or secret-like
field candidate; this is not a general secret-eradication or binary-memory proof.

QA's `windows-package-review.json` in the independent review directory above
has SHA-256
`7c8c6348fe6a688bfde3935ea11888b31dda6b77e6798d29122de576ab84a0a8`:
**SCOPED_PACKAGE_REVIEW_PASS**, read-only, with no Windows binary execution.
The package has no README; Root will provide the targeted update, second-instance
retry and public-key-export procedures in its delivery message. No repeated N2
activation or new device code is a prerequisite for this update.
Root then issued those three targeted user procedures. Requested feedback is
only the key ID and complete App NodeTrust fingerprint; no public-key JSON,
vault or private key upload is requested.

At this record the user has confirmed the **1980** file hash only. This **209**
package has not yet received user physical execution evidence: second-instance
recovery, export interaction, Windows DPAPI/ACL/GUI and the real same-Node dialogue
remain **NOT_RUN** for it. Export writes only `owner.Public()` to a new file with
O_EXCL; producing that file does not itself install Node trust or grant messaging.

### Independent frozen Store cache and Join-deadline gate

2026-10-18 UTC, **SCOPED_PASS**, driver exit **0**. The necessary independent
Store overlay completed **9/0/0 normal and 9/0/0 race** (three top-level cases
plus six subcases); version, both compilations, normal, race and scoped vet all
exit **0**. The actual binaries were retained and their pre/post execution
hashes match. No protocol readiness or real Runtime gate was rerun.

Reproduce from this QA worktree against the frozen product worktree:

```sh
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/n3-hub/runtime/native-pair-node-checkpoint-product-freeze-20261018T002507Z.json \
CICADA_NATIVE_PAIR_STORE_SOURCE_ROOT=/home/zyf/Cicada/.worktrees/cicada/n2-hub \
  bash scripts/test-native-pair.sh --store-regressions
```

Each invocation allocates fresh task state, artifacts, logs and container names.
The recorded product is **dirty `a451b9b`**, schema 65, not a clean commit build.
The official product freeze SHA-256 is
`7009a91f0e620faea4ba162ec9fd4b4230b8be3b8f8363dd68822bbba11b3252`,
matching the original 125-case producer source manifest file SHA-256
`dcf163287d7bdb186f27ea7bacfa8c8c007b4debb86b2b6686d70c3d96060a51`.
QA checked every approved product input both before and after execution:
**2242 product files plus five QA drivers/overlay files, 2247 total**. Their
joint inventory digest is
`192b33fc48ea97032a3b945aeabc9b9075445e5a982c6946ba53737b6e69d021`.
The before/after snapshot file SHA-256 is identically
`29130ed63032f08a60966694439c12484650bdc9df08d9de4aa900cd56d14d9b`.
Only the producer's expressly excluded historical validation record was omitted
from that product freeze; no Go, protocol JSON, contract or checker change was
accepted during the run.

All evidence below is under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261018T002713Z-UQRXnU`;
the corresponding artifacts directory retains the two actual test executables.

| Artifact | Bytes | SHA-256 |
| --- | --- | --- |
| `result.json` | See retained receipt | `856cdff87698bb2cb0f246bc65b163e673fa88b8c83e7504b3b89d10bf307a33` |
| `nativepair-cache.test` | 27042765 | `203b1e0f0a4b6520f32749e302de777d9277f4fb172cbef91f1a7998fae84ab9` |
| `nativepair-cache-race.test` | 42013758 | `91a77e6acd02cac1b6abf406f669fb26dc466889ebd2b180d041be3d4af16fc5` |

Normal top-level elapsed times were 3.29 / 0.95 / 5.93 seconds; race was
44.22 / 18.84 / 115.81 seconds. Exact Docker/Go argv, JSON events, exit files,
source snapshots and pre/post binary inventories remain retained. The private
database used the task's host-bound state directory; a successful Store
close/reopen proves this bounded persisted-history check, not abrupt process
death or power-loss durability. Shared modules mounted read-only; the writable
build cache and lock were private to this QA task. The exact container
`cicada-native-pair-run-20261018t002713z-uqrxnu` is absent.

The original fresh-cache eviction defect is **verified fixed on this frozen
source only**: full protected capacity backpressures, accepted +30-second skew
retains exact history through the full freshness interval and Store reopen,
and eviction later yields only READ_EXPIRED. Future status and detached
reconciliation reject without cache/rate residue; the same original may receive
its first legitimate observation later, and clock rollback preserves its exact
history. The original failing receipt, overlay and source attribution remain
unchanged.

The six deadline cases prove ordinary lease expiry did not mask JoinUntil:
both original leases were live before checking each boundary. One-slot
WAITING_JOIN denies self/renewal exactly at and after the deadline, without
partial lease changes; status persists EXPIRED and subsequent real-attestation
publication leaves no candidate effect. Two-slot WAITING_CONSENT retains the
original identities, credentials, lease owners, epochs and membership/join
revisions across the boundary, with both lease expiries capped at PeerExpiresAt.
ACTIVE still requires real dual-consent/GroupKeyGrant acceptance and is **NOT_RUN**.

This is **synthetic Store/PQ cache and lease regression acceptance, not E2E**.
It neither replaces the Hub producer's retained race TIMEOUT failures nor
transfers those broader tests to PASS. Node reserved-slot RPC/real Join, actual
App consent, real same-Node sealed Relay/Runtime, models/providers/queues,
Windows DPAPI/ACL/GUI and public HTTPS remain **NOT_RUN** by this gate. Public
Pair availability remains false; no deployment or Git mutation was performed.

### Compile-only check after Root synchronized the QA branch

Root preserved all eight QA WIP file hashes while fast-forwarding this task
worktree from `209b208` to `13fdb911ac1c3541eaee8906c5cfae6fd3fcc92a`.
The modified N3 discovery call site then passed its separately requested
compile-only check, **compiler exit 0**, with **zero tests executed**:

```sh
go test -mod=readonly -buildvcs=false -trimpath -c -o /out/n3.test ./acceptance/n3
```

The exact offline Docker argv and source snapshots are retained under
`/home/zyf/Cicada/.local/evidence/native-pair-compile-only/run-20261018T004355Z-60rkv_9s`.
The source is **dirty `13fdb91`** including the QA call-site change; all 1276
inventoried product/QA inputs were identical before/after compilation. Their
joint inventory digest is
`4e05bef157b473faf624776a12f27ba8f356ae9e2dae24e7e6913c206feff4af`;
the identical snapshot file SHA-256 is
`70d5a5dfce9d06663ce12a4911b64c134c2e7b4e04aeefb8e9d126da6cf90422`.
The retained **compiled, unexecuted** `n3.test` is 22346173 bytes, SHA-256
`d13d3acb482435dab41f465bb1f44e4d0063ef8a806a77d4c95058e098551f08`.
The compile receipt SHA-256 is
`39848c9fcfbefe1114b149f4bfc288e23c4501c219533bb67eadb28602813663`.
The exact task container was observed absent; product and shared module mounts
were read-only, with a locked task build cache and network disabled.

This closes the compile-only pending item for the stricter shared capabilities
decoder/8-KiB/loopback-policy check. The five known-RED protocol cases were not
executed; no secret setup, Runtime, SID, queue/provider, Windows or public-HTTPS
action occurred. The earlier Store 9+9 results retain their dirty `a451b9b`
attribution and are not relabeled as a clean `13fdb91` execution.

### Independent A3 dual-consent and Current core gate

2026-10-18 UTC, **SCOPED_PASS**, driver exit **0**. The opt-in private server
overlay completed **4/0/0 normal and 4/0/0 race**; version, both compilations,
normal, race and scoped vet all exit **0**. This is real PQ/TCP/persistent-DB
producer-core evidence, with synthetic native SIDs and no native Runtime.
Public Pair availability remains false. The fixture deliberately addresses the
typed private producer surface and does not assert public SDK availability.

Reproduce from the QA worktree against the approved product freeze (the product
worktree must still match every listed input):

```sh
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/n3-hub/runtime/native-pair-a3-producer-final-20261018T010602Z-product-freeze.json \
CICADA_NATIVE_PAIR_SOURCE_ROOT=/home/zyf/Cicada/.worktrees/cicada/n2-hub \
  bash scripts/test-native-pair.sh --a3-core
```

The recorded source is **dirty `f279093d9e8e09d6576ac319f18b9cedf1d670bf`**
for both producer and QA harness, never a clean commit execution. Approved
product freeze SHA-256 is
`e98268ae5ea5068f00e27b0e54536b3d80e176a6c7dc763b4b6f0a4702b408f9`,
whose original producer source-manifest file SHA-256 is
`87b1fa97574d98d2bd2c6bba974338febc424ec28524fd02b48ba88f63856ccf`.
All **2253 product files plus eight QA script/fixture files, 2261 total**, match
before and after execution. The joint inventory digest is
`45bf79c4eef2349abd9f5680514513d617188deefdb0de866dfc5a442f8ea0dc`;
both snapshot files have SHA-256
`a7cc9b41c35bb125b2bcf36e2f5fc4c84a5facd8e96bf260a8c105ca005978c4`.
The formal freeze excludes only append-only
`docs/hub-native-pair-a1-validation.md`; all code, JSON, contract and checker
inputs stayed fixed. The receipt's `excluded_noninput` field is null because
the producer used `excluded_noninput_files`; the original hashed freeze retains
the actual exclusion list. No excluded file supplies this gate's test input.

Evidence is under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261018T011118Z-XANwqI`;
the matching artifacts directory retains the actual executed binaries.

| Artifact | Bytes | SHA-256 |
| --- | --- | --- |
| `result.json` | 5471 | `b5cb3980e7996723f73072770256413a6f666df66ab80c64c2beb97398712d95` |
| `nativepair-a3.test` | 37517246 | `380872bd34831a69e92d6323dbb165d863098fe5006263709598e9b799924641` |
| `nativepair-a3-race.test` | 55459749 | `543c513d75a6a73f38b924bcd5f119d36e79b0ce783879abae8026b5fb6eb37b` |

Pre/post binary inventory SHA-256 is identically
`743dd02e6e5c699ea3b968e0ba44f852fc67f1b0e598afe91ac16d7c222bb75f`.
Normal took 10.818 seconds; race took 152.688 seconds within its 300-second
bound. Exact Docker argv, JSON events and each exit file are retained. Product,
QA and shared module cache mounted read-only; the build cache/lock were task
private. The fixture database lived in host-bound task state. Exact container
`cicada-native-pair-run-20261018t011118z-xanwqi` was observed absent after the
bookend completed. No shared development Hub or public deployment was touched.

The four cases prove only these boundaries:

- Actual N2/N3 approval, Node PQ reserved-slot Joins and real candidate
  attestations establish two distinct synthetic original SIDs on one synthetic
  Node. First consent and exact replay leave both memberships and effective
  legacy key grants absent; second consent creates both original CURRENT
  GroupKeyGrants, advances control revision once and spends no message budget.
- A test-only SQLite trigger rejects the second legacy grant insertion.
  Public Store reads and actual peer resolve confirm no partial membership/key
  authority. The authenticated original no-effect fence survives removal of the
  trigger; only a fresh explicit second consent activates. No SQL creates ACTIVE
  or any positive grant.
- A real TCP proxy discards the ACK after one upstream committed activation.
  The original packet is saved privately before the POST; reconciliation and
  late exact retry return the identical authenticated receipt, without a second
  activation or budget reset. This is a lost-ACK check, not a process-crash test.
- The actual peer-key carrier verifies against the independent original Owner
  pin. Pair-required missing evidence/Current, and one-at-a-time substitutions
  of SID, access ID/epoch, generation, attempt, network/member revisions and
  lease owner fail shared verification. Actual sender/writer enforcement is
  still NOT_RUN by this case.

Root separately reported an uncovered size defect during this run: the public
wire helper uses `json.Marshal`, whereas actual `writeJSON` uses
`Encoder.Encode` and adds LF. At the raw 320-KiB boundary, the complete HTTP
body can exceed the helper's count by one byte. This four-case PASS does not
resolve that defect. The next precise-source increment must cover actual HTTP
exact-limit/+1 behavior and zero partial effect. A peer-key that fits while the
future full delivery exceeds its bound must also leave both memberships and
effective key grants absent; no fake route/attempt may be published as actual
evidence. These size cases and actual caller/writer revocation/history checks
remain **PREPARED / NOT_RUN** here.

Production App pair UI, public SDK readiness, real same-Node sealed Relay/native
consumption, models/providers/queues, process-crash/power-loss durability and
Windows DPAPI/ACL/GUI remain **NOT_RUN**. No real SID/model turn was created.
The old Store 9+9 and five known-RED public cases were not rerun. Standard
disposable compatibility interop is reserved for Root's final integrated source;
this gate does not replace it. Later size fixes or commits do not inherit this
execution's attribution.

### Independent A3 HTTP-byte and complete-delivery size increment

2026-10-18 UTC, two separate **SCOPED_PASS** gates, each **1/0/0 normal and
1/0/0 race**, driver exit **0**, all six stage exits **0**. The first covers
actual HTTP encoding of both genuine typed carrier snapshots; the second
independently proves activation transaction rollback when peer-key fits but a
complete delivery does not. Neither result substitutes for the other.

Both use the later **2255-file** product freeze
`/home/zyf/Cicada/.local/evidence/n3-hub/runtime/native-pair-a3-http-final-20261018T011834Z-product-freeze.json`,
SHA-256 `1ec7c8fafb2728e554900bb9c02b7e48e9214d033dc5a3cfbcf72de2f0bf5cb0`;
its original producer source-manifest file SHA-256 is
`db08af393a5d0a6134766d739f5a9c8bd2aea544d4799e25a13a2834159cab80`.
Independent comparison with the earlier e982 freeze found only two added files
(private HTTP writer and its test), three changed files (the existing route
handler, its TCP test and the Hub contract), no removals,
and no Store/shared-wire/limit change. Both product and harness remain
**dirty `f279093`**. Old four-case results retain the earlier 2253-file source.

Run each command separately from the QA worktree, with the product worktree
matching that exact freeze:

```sh
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/n3-hub/runtime/native-pair-a3-http-final-20261018T011834Z-product-freeze.json \
CICADA_NATIVE_PAIR_SOURCE_ROOT=/home/zyf/Cicada/.worktrees/cicada/n2-hub \
  bash scripts/test-native-pair.sh --a3-http
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/n3-hub/runtime/native-pair-a3-http-final-20261018T011834Z-product-freeze.json \
CICADA_NATIVE_PAIR_SOURCE_ROOT=/home/zyf/Cicada/.worktrees/cicada/n2-hub \
  bash scripts/test-native-pair.sh --a3-size-store
```

Receipts below are under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`; actual binaries are
retained under the same run names in `.local/artifacts/native-pair-acceptance`.

| Run/result | Outcome | SHA-256 |
| --- | --- | --- |
| `run-20261018T012227Z-4y3LNS/result.json` | HTTP normal/race 1+1 PASS, exit 0 | `6b4419ee320713e8ed1c01a123f36629d5a64fd61ad4cf8f8c14628b327f2353` |
| `run-20261018T012416Z-qDszCh/result.json` | First Store fixture compile FAIL, exit 1; zero assertions, no executable | `dfe38319218db9be7622ff5692dfeb65ffdb130b00dce34ae40a55f55fdfc7ee` |
| `run-20261018T012506Z-ISf9cq/result.json` | Corrected Store normal/race 1+1 PASS, exit 0 | `28b034d7fc1e94065c4a5bbf6d8501f361b7c2ff5c4bdaec34bba36dded6f19e` |

The first Store attempt used a wrong argument list/error constant/state type
in QA code; both compilers and vet exited 1, normal/race were NOT_RUN (125).
Its original fixture is preserved under
`/home/zyf/Cicada/.local/evidence/native-pair-review/qa-a3-size-compile-failure-5nxt8bmh/`,
SHA-256 `38e9876cb2dfcfaeb2f65de9a61aeb53d8aa52d43e7252a8f3b4dd734dff2887`;
the failure receipt there hashes to
`4c9f407394fed3e5c44bbf5b02ab84ca68a084070460ac43533d884a64f46b5f`.
Only that fixture was corrected; its new hash is
`df20ee974afb48296d688b97c334171abdae4fd8bbd6caf89721078bc79c9100`.
The original FAIL is unchanged and is not a product defect or assertion result.

Each run checks **2255 product plus twelve QA inputs, 2267 total**, before/after.
HTTP and the first compile attempt share joint inventory digest
`908a9dd8369db4b9ca6b74e2f1457ea563cf4f9f43a7a296f65e48e5b12acf58`,
snapshot file SHA-256
`a0408bda12992236d60d1e5979df1d9455afde8c3d85675014ae17ff5ed2283c`.
The corrected Store run has joint digest
`580efdf6d77a4b539a19f9bb25261d0bd7dec55dddcd4363ea76f03d6148475e`,
snapshot file SHA-256
`15b076abd00e050f02b9630dde02fecd15fe0600591e4b5e776b9f216e5163b0`.
Within each run the snapshots are identical. The changed Store fixture is not
compiled or read by the HTTP overlay; HTTP was not rerun or reattributed to it.
The formatter evidence therefore retains its own original complete inventory.
The snapshot metadata now records the producer's actual exclusion-list field;
this does not backfill the earlier four-case receipt's null field.

| Actual executed binary | Bytes | SHA-256 |
| --- | --- | --- |
| HTTP `nativepair-a3-http.test` | 37515447 | `015a2989171c3544b7f571f4d2bae346e76f9a9ef25d02369bcf6f2492ff7e71` |
| HTTP `nativepair-a3-http-race.test` | 55457582 | `0982c8594923f959804a800c838e37f16ddcf20137b721fe7e244944fa6f2c7e` |
| Store `nativepair-a3-size.test` | 27299995 | `68b7ce80491ca463db2ec0a633a2fc2cafceee57276485680b04aede4e29699e` |
| Store `nativepair-a3-size-race.test` | 42421188 | `c672cfde7147bbe091cb16f4b76f5db3422ffb8bf091e0d0178cf19b5ff386c3` |

Both gates retain matching pre/post executed-binary hashes, exact Docker argv,
JSON events, exits and source snapshots. HTTP normal/race took 2.947/41.248
seconds; Store took 1.86/33.687 seconds, each bounded at 180 seconds. SQLite
files were on host-bound `/state/tmp`, **not tmpfs**; no crash/power-loss claim
follows. Shared modules/product/QA mounted read-only, and task build-cache
locking serialized the gates. The three exact run-derived containers above
were observed absent, including the failed compile attempt.

The HTTP case uses its own actual N2/N3/PQ/TCP dual-consent ceremony, encrypted
synthetic ASK, claim and actual final authorization. It confirms both real route
responses equal their complete Marshal bytes. Only a private in-memory copy's
unsigned grant ID is then padded, including JSON escaping; signed tuple/proofs,
message/attempt and original SID are retained. Each typed response at **327680
bytes** is usable over actual TCP without the old extra LF; **327681 bytes**
and either single missing evidence/Current field return 404 without a partial
success body. Both fields nil retain ordinary Group's legacy Encoder/LF.
Rendering does not change pair revision or budget. This is formatter evidence,
not a transaction oversize check or actual native caller/writer acceptance.

The separate Store case reuses only the producer's synthetic setup/internal
zero-Join fixture and makes real signed Owner intents/candidate publication.
An unpublished production activation transaction measures the actual peer/full
typed shapes and rolls back. A private AFTER INSERT size-fault trigger pads
the actual second legacy grant ID; it never creates ACTIVE or grants. The
original second consent through `ProcessHubNativePair` commits an authenticated
no-effect fence, leaves both memberships at their original zero grants/revision,
leaves both legacy grants absent and retains only first-consent history.
An independent unpublished production retry proves the typed size error:
genuine signed peer **327648 bytes fits**, complete typed delivery reservation
**335783 bytes exceeds** the 327680-byte bound. Legal maximum future
route/attempt placeholders stay internal to sizing and are never published as
actual authorization evidence. Rollback preserves zero authority, and removing
the fault does not revive the fenced original.

The reported LF defect is verified fixed only for these Pair HTTP paths on the
new freeze. Public capability remains false. Actual sender/writer revocation
and historical-outcome enforcement, production App pair UI/public SDK readiness,
real same-Node native consumption, models/providers/queues, Windows DPAPI/ACL/GUI
and public deployment remain **NOT_RUN** by these gates. Root owns final
integrated compatibility interop. No older four-case/cache/public-RED suite was
rerun, no production implementation was edited by QA, and no Git mutation or
deployment was performed during these gates.

### Prepared actual App Owner actions bridge: compile-only

2026-10-18 UTC, **COMPILE_PASS_RUNTIME_NOT_RUN**, exit **0**; Go version,
compile-only and static vet each exit **0**, with **zero tests executed**.
No Hub, App or Node child, native SID, model/provider/queue or deployment was
started. Pair availability remains false; no known-RED runtime gate was run.

Read-only coverage review found that the existing five protocol tests use the
production App only for N2/N3, then load test-owned identities and perform Pair
Owner actions through an independent wire caller. Conversely,
`TestPairControllerTwoExplicitConsentsAndProjectedActivation` uses a scripted
HTTP Doer with a fixed clock, not the production Hub. Neither supplies an
actual App Pair Action-to-Hub positive. The existing App process mailbox already
accepts `*appcore.Action` and returns the display-safe `Snapshot`, so no new
actor framework or product API was needed.

That review also identified a concrete source-contract mismatch: App
`pair_authority.go` signed GroupKeyProof with its click-time `Now`, while Hub
`hub_native_pair_consent_v1.go` requires its `IssuedAt` to equal the reviewed
Plan's `PreparedAt`. It was reported to Root and the App owner; QA did not modify
production code. App owns its single-line manifest-time correction and separate
RED/green component evidence. This compile-only source predates integration of
that correction, and cannot establish the correction's runtime behavior.

The new single scenario,
`TestN3AppPairActionsBootstrapDualConsentAndRevoke`, is **PREPARED / NOT_RUN**.
It keeps the original App process, original vault and original public
Owner/device pins. All Pair bootstrap, status, separate A/B consent and revoke
requests go through production `Controller.Dispatch`; the driver never opens
the App's private vault or signs a Pair/GroupKey Owner proof. It generates only
its synthetic Node's proof/credential and synthetic candidate keys, uses actual
Node PQ reserved zero-Joins and self attestations, and reads public Store
evidence with the owned Hub stopped. Its independent oracles require both
memberships/key grants ineffective before and after first consent, original
CURRENT grants only after second consent, exact signed manifest times under a
wall clock, and effective grant removal by App revoke. It does not use SQL to
create ACTIVE/grants or invoke a native MCP consumer/queue/Runtime.

Root preserved the sole new-file WIP while synchronizing the QA branch from
`1c4a59d` to `3814439bbbe68e7e7d2c881439420f2b9bf8b1aa`. The compiled input
is **dirty `3814439` plus the new QA test and two driver/helper changes**.
All **1294** complete Go/contract/checker/QA inputs matched before/after.
Joint inventory SHA-256 is
`618751b581a3af763928a2b4052c9af5fdc7fb45c2bb3257057a6440bad50515`;
the identical snapshot file SHA-256 is
`5766859a8fba771f91a1cdb7776b312a6add8d0e8bbd338931014fba8572846e`.

Evidence is retained under
`/home/zyf/Cicada/.local/evidence/native-pair-app-owner-compile-only/run-20261018T015904Z-7hmazmnd`;
its `result.json` is 2466 bytes, SHA-256
`6ec666b1b836dbb062bf2f92a94c417d4ee2da0cc9e6c1caf996298b9515b03d`.
The corresponding `.local/artifacts/native-pair-app-owner-compile-only` run
retains **compiled, unexecuted** `n3-app-owner.test`, 22610606 bytes, SHA-256
`f546d8fbf523bb7a75b5177f613767ae9824efe5bbaf14537b6c88d28ea35592`.
The exact compiler command was:

```sh
go test -mod=readonly -buildvcs=false -trimpath -c -o /out/n3-app-owner.test ./acceptance/n3
```

The pinned offline Go Docker image, complete argv/log/exit files and source
snapshots are retained. Product/QA and the shared module cache mounted
read-only; the task build cache was exclusively locked. The exact container
`cicada-app-owner-compile-run-20261018t015904z-7hmazmnd` was observed absent.
The fixture state mount was host-bound, but compilation created no acceptance
database or runtime durability evidence.

After Root integrates App/Hub fixes and explicitly approves actual readiness,
the prepared runtime command is `bash scripts/test-native-pair.sh --app-owner`.
It builds the actual CLI and N3 binary in fresh isolated state, then requires
exactly this one test to pass without skip. That command has **not executed**.
It will retain its own new source/binary/exit/cleanup record; this compilation
does not become that later source's runtime PASS. Fresh native MCP and real
queue/model/Runtime, Windows GUI/DPAPI/ACL and public HTTPS remain **NOT_RUN**.

The existing user-only manual skeleton was reordered with Root's review:
verify the delivery, prepare each original per-launch Codex/MCP context and let
the user complete one harmless initial turn in A and B before App bootstrap.
Preserve the original account, `CODEX_HOME`, Node state and Codex-injected SIDs;
Join within the original ten-minute `JoinUntil`, and prepare the five-minute
Plan only after both candidates are ready. This is **DELIVERY_PENDING** guidance,
not evidence that any real turn, SID, Join or queue was operated by QA.

Root separately reported a read-only resident-Node preflight on 2026-10-18:
systemd MainPID `1860672`, restricted inspection of only `PATH`/`CODEX_HOME`, and
`shutil.which('codex', path=<that service PATH>) == None`. The interactive shell
has `/home/zyf/.local/bin/codex` version `0.163.0`; the Node uses default
`CODEX_HOME`. This is **ROOT_REPORTED_READONLY_PREFLIGHT**, not QA execution,
native Runtime acceptance or a product-code defect. No other environment values
were exported, no unit was changed and no queue was executed. The existing
manual skeleton now requires the user to configure the reviewed Codex path for
the actual service and confirm the original account before A/B acceptance, preserving existing
Node identity/state/binding without re-registration. Exact service changes and
all actual turns remain user-operated delivery steps.

A further Root read-only check found no `CICADA_CODEX_BIN` override in that
same service environment. The existing production native delivery code already
supports it, so the minimal future user-operated setting is
`CICADA_CODEX_BIN=/home/zyf/.local/bin/codex`; the original PATH, Codex
account/`CODEX_HOME` and Node state/identity/binding stay unchanged. This refines
the manual resolution step above, adds no product feature and does not imply
that a unit setting/restart or any Runtime operation has been performed.

### Ready protocol five PASS and actual App revoke failure

2026-10-18 UTC. Root explicitly authorized two isolated gates after integrating
the real readiness source `995126d716bf25f078a4cc500121ed578434b491`. Production
availability was true; no discovery shim supplied a positive. The actual App
Owner scene ran first and **failed**, exit **1**. The original five public
protocol cases then passed **5/0/0**, exit **0**, on the unchanged source.
No old cache/core/size gate, real native SID/queue/Runtime, deployment or Git
operation was executed by these runs.

Commands from the QA worktree were:

```sh
bash scripts/test-native-pair.sh --app-owner
bash scripts/test-native-pair.sh
```

Each allocated fresh owned host-bound fixture state and a distinct container.
The recorded input is **dirty `995126d` plus the five QA WIP files**, not a
clean commit execution. Both runs checked **1304** complete Go/contract/checker/
QA inputs, with identical joint inventory SHA-256
`c9cb0a01497bd5a881b8030cb185fb8ffb9960cc6c73a2ae61f67c0b34a82cf0`.
All four before/after snapshot files have SHA-256
`063fc76b60ed1fc38e2d8d8cece56401bd74f8be1e6356aa3e163767f2745b47`.
The runner did not modify source between gates.

Evidence below is under `.local/evidence/native-pair-acceptance/`;
matching `.local/artifacts/native-pair-acceptance` directories retain each run's
actual CLI and test binary, plus pre/post inventories in the evidence directory.

| Result | Outcome | SHA-256 |
| --- | --- | --- |
| `run-20261018T022252Z-nACGtZ/result.json` | Actual App single scene FAIL; harness 1, version/CLI compile/test compile/vet 0 | `6e38e613fe51959bb254506bd6215963317f55cde30531ef9d983e1dc7415fe1` |
| `run-20261018T022542Z-OlAX5c/result.json` | Original public protocol 5/0/0 PASS; all five stage exits 0 | `8aa3dc46675b28ac5217a4f9b853b74c67fe96734e9ec550283599b6d38392bc` |

| Actual executed binary, identical in both runs | Bytes | SHA-256 |
| --- | --- | --- |
| `cicada` | 34143102 | `f4fb4016c22ee5919760bfa8a94b44e5187830e9d5f7ed8fcc4d665938d19ced` |
| `n3.test` | 22632344 | `0f0f935bcbcbee294514e5b2e7a77baf173e30ba00d65dfceecc92ffef8f2fd9` |

Each run's own pre/post executed-binary hashes match. Exact Docker/Go argv,
version, logs, exits and source snapshots are retained. Source and shared
modules were read-only; the task build-cache lock serialized execution.
SQLite fixture files used host-bound `/state/tmp`; no power-loss durability is
inferred. Both exact run-derived containers were observed absent.

The five protocol cases prove actual bootstrap/exact replay across Hub restart,
wrong-Node Owner proof fencing, missing Owner proof denial, pre-forward loss and
post-commit loss with exact original reconciliation. They close the earlier
service-unavailable five-case RED **only on this ready source**. Their Pair
Owner actions remain an independent wire caller after actual App N2/N3; this
does not accept the App Pair Action chain or real native consumption.

The separate actual App process made its own Pair bootstrap/status and two
explicit slot consents from its original vault, using the production Hub and
real synthetic Node PQ zero-Joins/candidates. Assertions reached real original
CURRENT key grants, projected memberships and exact signed manifest times.
The final `REVOKE_EXACT_NATIVE_PAIR` failed with `OTHER` /
`APP_PAIR_RESPONSE_INVALID` under `WALL_CLOCK` at
`app_pair_runtime_test.go:183`; the whole 15.91-second scene is **FAIL**, with
zero accepted full scenes. No driver-held Owner private key or Pair proof was
used. This actual cross-component failure was handed to Root and the App owner;
QA made no production fix. It does not prove Hub no-effect, failed revocation,
or that the authenticated original can be replaced. The original failed receipt
and source attribution remain unchanged while the owner investigates.

App-owner completion/revoke acceptance remains pending necessary verification
on the owner's fix. These five public-case results cannot be reattributed to a
later fix's source or used as its App-owner PASS. Actual native MCP/queue/Runtime,
Windows GUI/DPAPI/ACL and public deployment remain **NOT_RUN** by these gates.

### Actual App Owner bridge after the terminal-slot fix

2026-10-18 UTC, **SCOPED_PASS**, **1/0/0**, driver exit **0**, all five stage
exits **0**. Root integrated App's narrow returned-slot validator at
`7e6e3d54322eabc076ae7a48fdd7cb3cf1667376` and authorized only the affected
`bash scripts/test-native-pair.sh --app-owner` scene. The Go test and two
driver/helper files are byte-identical to the original `995126d` failed run.
No five-case protocol, older core/cache/size, consumer or model/Runtime gate
was repeated. The original App FAIL and five public PASS remain on their
original source above.

The fixture is the existing actual App child/vault against the real Hub CLI,
with a synthetic Node's real PQ pairing/zero-Joins and candidate attestations.
The App signs every Owner and GroupKey proof itself. Actual bootstrap, fresh
status, separate A/B consent, projected memberships and both original CURRENT
key grants passed. App revoke then applied the authenticated terminal
historical-slot response, settled its original operation, and independent
public Store checks confirmed neither key grant remained effective. The
whole scene took **16.18 seconds** under `WALL_CLOCK`; no driver-held Owner
private key, SQL-created ACTIVE/grant, capability shim or real native SID was
used.

App's fix classifies only completely absent candidate data as historical;
mixed fields and full candidates still use the original complete validator.
Base slot position, generation, attempt, original Node/runtime, identifiers,
epochs/revisions and lease ceiling remain checked. Candidate-less history is
limited to waiting JOINED_ZERO or terminal JOINED_ZERO/ACTIVE, with terminal
administrative permission false. ACTIVE activation/consent/Plan verification
remains strict. The owner's separate 42-event normal/race and lost-revoke
component records retain their own source and original infrastructure/compile
failures; this single actual App scene does not relabel them.

Evidence:
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261018T023857Z-e1llc9/result.json`,
4394 bytes, SHA-256
`75268d011af433bbb215a0f0bca0df9ba15136a8902d99cb69ec1a1752b914a9`.
The tested source is **dirty `7e6e3d5` plus the five QA WIP files**, not a clean
commit execution. All **1306** inputs match before/after; joint inventory
SHA-256 is `416b2757d45d035986bd9c9d349f48739a44e8a2c0775ec1f182697a88719294`,
and both snapshot files have SHA-256
`a5cbf56c03c355e0396cd3ac2b3f2379035c894648faa312a14f396b5d4a548e`.

| Actual executed binary in the matching artifacts run | Bytes | SHA-256 |
| --- | --- | --- |
| `cicada` | 34143102 | `f4fb4016c22ee5919760bfa8a94b44e5187830e9d5f7ed8fcc4d665938d19ced` |
| `n3.test` | 22634386 | `5cacad8075979a0c3017a0f088fa3eeaa2ca1d33ab049bfa920fc79f07a66dd2` |

Pre/post binary hashes match. The Hub CLI is unchanged from the first runtime
gate; the actual App child is in this newly compiled N3 binary. Exact argv,
logs, exits and source/binary inventories are retained. State/SQLite were on
owned host-bound `/state/tmp`; source/shared modules were read-only and the
task build cache exclusively locked. Exact container
`cicada-native-pair-run-20261018t023857z-e1llc9` was observed absent. No host
power-loss durability or production deployment is inferred.

This closes the observed App revoke integration defect **on this source**.
It accepts the bounded portable App-owner core chain, not native GUI or model
consumption. Windows GUI/DPAPI/ACL, physical devices, real Codex Threads/queue/
Runtime and public deployment remain **NOT_RUN**. Final integrated standard
compatibility interop and any Windows artifact build belong to Root; they are
not claimed by this result.

### Final clean-4ca delivery and independent artifact review

2026-10-18 UTC, **SCOPED_PASS** for the local integrated delivery candidate.
Root assembled `Cicada-N3-4ca29df.zip` from clean
`4ca29dfc76f3eec9143676d554b3a26c1a178f1b`, software version **0.0.5**.
Build-source fingerprint v4 is
`e08ed98df63bc8fcc3f2647e3bf32636185dbe1a177a11b7a3fa5f4b5369c424`.
The source inventory's **1298** entries independently match committed blobs;
the fingerprint also includes its recorded filesystem modes. Root's final
source bookend is byte-identical to `source-info.json`, SHA-256
`2f212b593793fbf7f318e112c45123830017db966753fa8d84f8618a37226625`.
This record is a later documentation checkpoint: **do not rebuild or relabel
these artifacts to the documentation HEAD**. Earlier dirty-source gates retain
their original attribution above.

Artifacts are under
`/home/zyf/Cicada/.local/artifacts/n3-native-pair-delivery/run-20261018T024547Z-0688d4/`;
matching evidence is under `.local/evidence/n3-native-pair-delivery/` with the
same run ID. The ZIP has **45** safe, unique file members and **44** SHA256SUMS
entries. Independent CRC, hash, size and disk-byte checks all passed. It has one
Windows EXE, one Linux executable, build/delivery/source metadata and licenses;
no fixture state, vault, grant, session or credential files are included.

| Artifact | Bytes | SHA-256 |
| --- | --- | --- |
| `Cicada-N3-4ca29df.zip` | 16814901 | `b9a573490f98d567bc924c137e834662adde8c914180e52a49939ce6fe63b9a4` |
| `cicada-app.exe` | 13784576 | `7e919c58660c83bfa9b16a4225850181eb08f444a51bf1773f5f64740660fab7` |
| `cicada` | 26292384 | `5ffad8db514a79bafe93e607a894d19a8cf2e029432bd7fc1938accac12a1bfb` |
| `delivery.json` | 13240 | `22fd64d1a5a547f24ff6384a04ed9ffac57444da96115f7baf97365afeaf9161` |

Windows is **amd64 PE32+, GUI subsystem 2, CGO=0**; cross-build exit **0**.
Its **11** actual linked dependency modules match the retained notices and
compiled package graph. `internal/buildinfo` is not linked and there is no
runtime version API: version/revision/dirty/fingerprint identity is external
metadata bound to the EXE SHA-256. Original build metadata is preserved at
`build/windows-app-original-build-metadata.json`; `delivery.json` explicitly maps
its original license paths to `licenses/app/`. The first buildid metadata read
failed, exit **1**, because tmpfs was non-executable; metadata-only retry exited
**0**, with no EXE rebuild. Physical GUI/DPAPI/ACL and fonts remain **NOT_RUN**.

The standard disposable Client interop exited **0**; required Smoke,
HeadlessOperator, OwnerBootstrap and RecoveryFixture tests all passed. Re-run
from an isolated checkout of the recorded source with
`bash scripts/test-client-hub-interop.sh --suite client`; a new run gets its own
source/results and cannot replace this receipt. All five owned Docker resources
and scratch were independently absent. Four resident containers' ID/image/start/
restart metadata matched before/after and the independent current observation.

Linux is **ELF64 amd64, CGO=0, no ELF interpreter**. Its **12** linked module
identities and **19** module notice files match actual binary metadata and
original read-only cache bytes. The delivery image `a3c46544…629a24d` differs
from the cleaned interop image `9df515f8…840852`: the complete source objects
match; same image/binary is **not asserted**. The first strict image-identity
check aborted before export and remains recorded. The exported binary itself
then passed `TestN3NativePairBootstrapAndExactReplay`, **1/0/0**, exit **0**,
in **7.70 s**: real PQ/TCP, host-bound SQLite, actual Hub restart and byte-exact
prepare/complete replay. This is an empty-slot scene, not native Join, full
pair activation or Runtime acceptance. Its original reused `n3.test` SHA-256 is
`5cacad8075979a0c3017a0f088fa3eeaa2ca1d33ab049bfa920fc79f07a66dd2`;
compilation remains attributed to dirty `7e6e3d5` plus QA WIP. All **1247**
original Go/module inputs independently equal clean-4ca blobs; no recompilation
is implied. Smoke attempt 01 failed on Go cache setup with **zero tests**, exit
**1**; attempt 02 corrected harness cache settings and passed. Both original
commands/logs/exits remain, with isolated host-bound state and network-disabled
Docker. Export/smoke containers and delivery image are independently absent.

| Matching evidence `result.json` | SHA-256 |
| --- | --- |
| `app-build/` | `1788248453dca4630d1d8a42c66a781d92c29421d8ea3ab9060df8747a5b34e4` |
| `client-interop/` | `e07c2c03e681500292a8ffa40f6ec1ceb9f686b8d2c9e078fbc5ecb0839d4b9a` |
| `packaged-linux-smoke-02/` | `a9d1d163accea5c4fd105e37cc656902f12b79a721d89124b2d62ad03f500b63` |

Exact Windows build argv and Linux smoke replay argv are retained in their
respective `*.command.json`/`command.json`; replay requires fresh owned outputs
and state. QA performed read-only review, including Go binary-metadata reads,
with **zero new test executions or builds**. Independent reports under
`.local/evidence/native-pair-review/delivery-4ca-build-review-8n24muyd/` are:
`windows-subbuild-review.json` (`9aa1e5f4…7001`), `client-interop-review.json`
(`d07567fb…f8aa`), `linux-export-review.json` (`f536abc2…00eb`) and
`zip-review.json` (`e1ae6b61…114e`); each retains its full hashes and scope.

This closes local package assembly and artifact provenance review. It does
not accept real original Codex A/B/A turns, native queue/model/Runtime, direct
routing, Windows physical checks or current public HTTPS pair operation:
all remain **NOT_RUN / USER_ONLY** where applicable. Public/resident deployments
and real keys/state were untouched; `main` remains
`0a33932ba2abdc0462ee993ba5acc07078098a2b`. The existing manual skeleton still
requires user-operated matching upgrades, the original account/Node/binding,
reviewed per-launch MCP loading and the service's absolute `CICADA_CODEX_BIN`.

### Clean-4ca user-reported deployment prerequisites

Feedback recorded 2026-10-19 UTC, relayed by Root from the user's deployment
of the final `Cicada-N3-4ca29df.zip` candidate. The user reports that this round's
deployment, login, export and Node steps all behaved as expected:
**USER_REPORTED_PASS for the overall prerequisite procedure**. QA did not
repeat these actions or inspect the real deployment. This updates the user's
prerequisite status; it does not replace the independently scoped build and
fixture results above.

| Explicit user output relayed by Root | Accepted observation and limit |
| --- | --- |
| Linux executable SHA-256 `5ffad8db514a79bafe93e607a894d19a8cf2e029432bd7fc1938accac12a1bfb` | USER_REPORTED_ARTIFACT_MATCH with the delivered Linux executable. A checksum does not prove which binary a running Hub/Node process loaded. |
| Codex `0.163.0` | USER_REPORTED_VERSION_OUTPUT. This does not establish the Node service's effective executable environment, original account/session context, per-Thread MCP loading or model execution. |
| `trust-owner-key` reports `ACTIVE`, version `1` | USER_REPORTED_PASS for the command's reported local Owner-pin state. Real Owner key IDs/fingerprints are deliberately omitted. This is not an independent proof of the pinned identity or an adversarial key-substitution test. |
| Node service is `active` | USER_REPORTED_PASS for service status at observation time. No continuous heartbeat, reboot/restart recovery, queue consumption or exact native binding trace is supplied by that status. |

Login/export and the remaining deployment steps are covered by the overall
user feedback, without separate per-case command/UI traces. No unreported
negative, expiry, duplicate/recovery, logout, font or security case is promoted
to PASS. A fresh Windows EXE hash was not separately supplied in this feedback;
the retained build hash remains the delivery's artifact identity. Dedicated
Windows GUI/DPAPI/ACL acceptance and physical font checks remain **NOT_RUN** on
this package; earlier source-specific display failures remain historical.
Real original-SID A/B/A dialogue, actual Join/dual consent on the deployed pair,
MCP loading in both original Threads, queue/model/Runtime consumption and
protected public HTTPS pair acceptance remain **NOT_RUN / USER_ONLY** where
applicable. No fresh independent deployed source/image or Guard claim is made.

Two user-facing improvements are now recorded in the existing plan: Copy
buttons plus selectable key-field text, and trusted Owner-pin establishment
within the Node device-code/App approval flow. Manual public-key/fingerprint
export/import is an interim onboarding step. The UX improvement must retain
original identity, authenticated proof and exact pin verification; login is
still not Root. No protocol design, implementation, real pin/key/state change,
service operation, new test/build or deployment was performed by this record.
The package's source remains clean `4ca29df`; no rebuild or relabel is required.

### Go 1.27.3 toolchain and verifiable-build checkpoint

2026-10-20 UTC. Go **1.27.3**, released October 19, fixes `crypto/x509`
security issues ([official release history](https://go.dev/doc/devel/release#go1.27.3)).
The current toolchain directive, three Docker builders, two CI workflows,
release/WASM validators and active acceptance builders now select 1.27.3.
The minimum `go 1.26.0` directive, `go.sum` and algorithm dependencies are
unchanged. Historical 1.27.2 results and cache provenance remain unchanged.

Pinned builder references use official Docker index digests; they are not
inferred image IDs:

- `golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`
- `golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd`

Both actual builders returned `go version go1.27.3 linux/amd64`. Root retains
pull/inspect evidence in the parent run. QA used the populated old module cache
read-only, with new task-private Go and WASM build caches. Native builder defaults
also use separate 1.27.3 compilation caches; the N2 immutable-reference preflight
accepts the complete pinned reference before checking local availability.

Evidence is under
`/home/zyf/Cicada/.local/evidence/composable-registration/run-20261020T075053Z-8d262d/qa-toolchain-e4hg5jt5/`.
Inputs were **dirty `dbf1f94809c0293c0c098294a56dca3bab065246` plus recorded WIP**.
Canonical Hub/Go build-input bookends match, fingerprint v4
`53a5be870f12c291dc8ee312872876f48e267e0505d385b74a649834ff700a2c`.
Original/final parser and packaging-source variants have separate complete
copies and hashes; later metadata-only changes did not change Go/WASM inputs.
These are not clean-commit executions and must not be relabelled after commit.

| Check | Actual outcome | Exit |
| --- | --- | --- |
| Final N3 evidence parser | 18 PASS / 0 FAIL / 0 SKIP | 0 |
| Final packaging checks, including N2 complete-reference preflight | 23 PASS / 0 FAIL / 6 optional SKIP, 29 total | 0 |
| Real Go WASM PQ/Wire and UI-model checks under Node 24.16.0 | 1.27.3 WASM/runtime/manifest match; prior toolchains rejected | 0 |
| Focused e2ee, original module-root cwd | 157 PASS / 11 FAIL / 1 SKIP; all 11 errors explicitly missing package-relative vector files | 1 |
| Same original e2ee binary, corrected package cwd | 206 PASS / 0 FAIL / 1 SKIP; independent OpenSSL 3.5.9 interop not supplied | 0 |
| Hub account wire / Hub identity | 105/0/0 and 3/0/0 | 0 each |
| Buildinfo, original trimmed binary | 2 PASS / 1 FAIL; runtime.Caller source path cannot locate root VERSION | 1 |
| Buildinfo, newly compiled without trimpath | 3 PASS / 0 FAIL / 0 SKIP; original binary and failure retained | 0 |
| Linux CLI compile and Go binary metadata | Actual retained executable reports compiler 1.27.3 | 0 each |

All executed test-binary pre/post hashes match; all **16** owned Docker
containers were independently absent. Per-lane exact argv, logs, exits and
both original failures remain. Packaging skips cover missing optional release/PQ
artifacts or OpenSSL stages; they are not accepted execution. Nine shell files
were checked individually and the changed JS test passed syntax checking.
The CLI verification artifact is **36024664 bytes**, SHA-256
`a11e608042ded172ac9fcfb4d6ca00085bb9829c84186ff9ac71270a4cdde6da`.
It was built with `-buildvcs=false`; dirty source attribution is external,
not an asserted embedded revision. WASM/runtime/test artifacts have full sizes
and hashes in `toolchain-review-result.json`, SHA-256
`7061a243db00f198d498429f2f96539743ae9d4099404a0517cdc68a5acd5984`.

The existing N3 driver now retains each execution argv and requires pre/post
and final on-disk binary inventories to match. Missing/malformed argv,
replaced/missing artifacts and symlinks cannot produce a parser PASS. Even a
valid older N3 result keeps `installation_acceptance=NOT_RUN`. Pair evidence
records the complete builder reference separately from its digest.

This is a toolchain/build-evidence checkpoint, not new registration or Owner-pin
acceptance. INST-01..07 and the stronger App2 profile/container isolation await
the reviewed Hub contract and actual App/Node adapters; no wire is guessed.
The old N2/N3 matrices were not rerun. Root reserves standard Client interop for
one later integrated gate. Windows GUI/DPAPI/ACL/uninstall, real Node services,
queue/model/Runtime and public deployment remain **NOT_RUN** here. The delivered
clean-4ca package was neither rebuilt nor relabelled, and no real state changed.


### Public App fields and guarded local component-file checkpoint

2026-10-20 UTC. This checkpoint adds complete, selectable display values and
Copy/已复制 feedback for the existing public Hub, account/Owner/App-device,
Node and Pair fields. The explicit projection excludes credentials, proofs,
private keys and serialized snapshots, preserves original value bytes, and
uses the existing authenticated account-visibility boundary. Changing the
presentation scope clears selection and queued copy state. English/Chinese
catalog parity remains checked. The native clipboard command and two-second
feedback are implemented; OS clipboard success is not independently observed.

The optional local file installer is exposed as:

```text
cicada components install --prefix ABS --components hub,node --binary FILE --sha256 HEX --licenses DIR
cicada components remove --prefix ABS --components hub,node
cicada components list --prefix ABS
```

Linux amd64/arm64 permits Hub/Node; Windows amd64 permits App with
`--components app`. Only local, self-contained standard `CGO_ENABLED=0`
artifacts are accepted. Linux requires ET_EXEC with no PT_INTERP, PT_DYNAMIC
or DT_NEEDED dependency; PQTLS/dynamic distributions and PIE are refused.
The installer checks SHA-256, actual executable headers, Go main/target and
all compiled dependency notices before creating a destination. It installs
only the binary, licenses and a bounded manifest beneath
`PREFIX/components/<component>`. A changed/unowned installation is refused;
an identical repeat is accepted. Removal validates every selected manifest
and owned file before deleting the first managed byte, retaining unknown
files, identity/outbox data and other components. Multi-component I/O failures
may leave earlier components completed; no rollback is promised.

Filesystem operations retain `os.Root` directory handles across ancestor
replacement, reject symlinks and use descriptor-based operation locks. On
Linux, the managed components root and existing component directories must
belong to the effective current user and disallow group/other writes.
Foreign-owner and missing-owner negative cases use synthetic `FileInfo`;
no chown or other-user directory was used. Windows POSIX mode bits do not
establish ACL protection. The installer does not start services, enroll
devices, issue grants, migrate state or establish an Owner pin.

All evidence is retained below
`/home/zyf/Cicada/.local/evidence/composable-registration/run-20261020T075053Z-8d262d/app/`.
Each lane used the pinned Go 1.27.3 Bookworm builder above, network disabled,
read-only source/module mounts, private state and build-cache directories,
and actual retained test binaries with original/copy hash equality and
NUL-separated execution argv. Each source snapshot and complete build-input
inventory matched its own before/after bookends. All owned containers were
absent and private temporary state was empty after completion.

| Evidence variant | Actual outcome | Receipt SHA-256 |
| --- | --- | --- |
| `independent-01` initial UI/installer baseline | normal and race each AppUI 10/0/0 plus installer 23/0/0; five CLI targets and Windows amd64 GUI compiled, all exit 0 | `ae1f50d4af78ad2cc0c01318a130f40197f78266cf3755ddca6f7c6eba0ab340` |
| `dynamic-red-01`, new negative cases against the old validator | EXPECTED_RED: actual CGO1 ELF and CGO0 PIE were accepted and created destinations; parent plus two cases FAIL, test exit 1 | `ebf2f760ac135e1e8b56d715b8c2a5700f43cd4f6d81892ce6ba45e498413ff7` |
| `installer-final-01`, static-artifact and directory-owner guards | installer normal 31/0/0 and race 31/0/0, identical named maps; CLI Linux amd64/arm64, Darwin amd64/arm64 and Windows amd64 compiled, all exit 0 | `928e77a07546e0e8f4577a123253997a549e9219a6c10cffc8b734b24ed581fb` |

Counts include parent tests and subtests and are PASS/FAIL/SKIP. Synthetic
Go ELF/PE fixture binaries are visibly marked and never executed; the test
binaries execute production installer functions against disposable files.
The negative cases assert that no destination is created. Header mismatch,
wrong role/target/hash, missing/changed notices, symlink/traversal attempts,
changed removal targets, state preservation, parent replacement and lock
release are included. Darwin is a CLI compilation compatibility check only;
component installation remains unsupported there.

All three variants are **dirty `ed468b45f69cfc4009f6c8cc299a0b3b10706927`
plus separately inventoried WIP**, not executions of a later clean commit:

| Variant | Source manifest SHA-256 | Build-input fingerprint v4 |
| --- | --- | --- |
| initial | `6e71414eba84e9bf6f4697be4e0c0c612f91b809be89b45c5710b69a60bb192e` | `53caeaafc0995453c43b445f9895767afad3fb7bce982d6440b51b2173f0fcb5` |
| negative | `2609e9456ac0ecd65e649a0b88b1f94147030e620056a812d5a17ef9ded764be` | `479eafad022f738a2d7b47b1cf8f0d0aa1e277bfa62581e68463b76cecd0d74d` |
| final installer | `c84375b0cab853229d4422438a86004849da4b0ae167b7cff87146e557b94765` | `7a0ef2e2a0feaeec9368ac68cbd769d4761b970b327d0feaa884f7f743f099f9` |

The final Linux amd64 CLI is 24,936,608 bytes, SHA-256
`60be3ed7b142c10a3370bb7a4ef4a1d6683db092e31bb90240b2aa5ad010c7d9`.
The unchanged UI's initial Windows GUI compile is 13,806,592 bytes, SHA-256
`6012e3f776955c546aa5f2140d4d9ba2c04e330b4a4240c15ac50a88a7c8cd3f`.
Actual compiler/module metadata, all target artifact sizes/hashes, commands,
logs and exits remain in the corresponding receipt. The App GUI build has no
linked buildinfo runtime reporting interface; its provenance is external.
The UI and GUI build were not repeated for installer-only fixes, and their
original evidence attribution is retained. This documentation append followed
the completed gates and is not part of their source bookends.

Windows GUI/clipboard/selection/copy feedback, native Windows install/remove
and ACL, physical devices, real Node services/queues/Runtime, public HTTPS,
new device-registration/Owner-pin protocols and the full old matrix remain
**NOT_RUN** here. No public DTO/server/protocol, real key/grant, resident
service, deployment or global Codex configuration changed. New independent
App registration and Node pairing-secret storage adapters await the reviewed
Hub contract; no successful authorization is inferred from these file/UI
checks. The earlier clean-4ca delivery remains unchanged.

### App2 isolated-container adapter preparation

2026-10-20 UTC, **SCOPED_HARNESS_PASS only**. The reusable adapter starts the
actual empty App Core in a second container; it does not register App2, mint
business grants, establish an Owner pin or read simulated Hub business state.
Re-run with `bash scripts/test-native-app-n3.sh --app2-isolation-only` in an
isolated checkout with the pinned offline builder/module prerequisites.

The host's bounded test supervisor shares only the owned fixture's network
namespace. Actual daemon inspection verifies independent PID/private IPC,
nonroot UID/GID 1000, read-only rootfs, dropped capabilities, no privileged or
SYS_PTRACE additions, no published ports and no-new-privileges. The only bind
mounts are App2's own profile, its own synthetic input/mailbox, and the actual
`n3.test` read-only. No App1/Hub/Node state, source directory, Owner keys or Docker
socket is mounted. App2 proves a single fixture TCP nonce exchange, an empty
production Controller profile, the same executable hash and failed opens of
the App1 private canary/socket/parent-only paths. This TCP probe is not a Hub
response, enrollment proof or shared-state read. No extra product service,
automatic authorization renewal, model call or business polling was added.

Both actual container runs below are **dirty `ed468b45f69cfc4009f6c8cc299a0b3b10706927`
plus five QA WIP files**, with byte-identical before/after source snapshots and
executed-binary inventories in each run. Root later synchronized this worktree
to `709531966b90aabedc80ee619922a589b991d20d`, preserving all five WIP hashes.
These container-run results do not become clean-7095319 or later-checkpoint executions.
Evidence is under `.local/evidence/n3-acceptance/`, with matching binaries under
`.local/artifacts/n3-acceptance/`:

| Container run | Declared outcome | Original result.json SHA-256 |
| --- | --- | --- |
| `run-20261020T084214Z-NHdxHy` | 1 PASS / 0 FAIL / 0 SKIP; all five stage exits 0; initial explicit-driver prerequisite | `167ad8790b55cb887c6955f93a69a55c5a1fe4443b12b896892af10e75cb4a50` |
| `run-20261020T084711Z-u1J0QG` | 1 PASS / 0 FAIL / 0 SKIP; all five stage exits 0; explicit required-mode flag | `0312e8153b1475615930554474c04c63c25503047527fc1d1d9d89a159c3f804` |

| Actual retained test binary | Bytes | SHA-256 |
| --- | --- | --- |
| First run `n3.test` | 22670772 | `538307a6bf3e8f2ca28a886ca81804ca8ad0abe50b90d564f6ce40e97f667f66` |
| Required-mode run `n3.test` | 22670612 | `b65b5a3442e336df81874c6524ea9f6dba8f92f2741cf9e1179afe26cfa90615` |

Source manifests are respectively
`92a2ae8d183e7d93ecbfa52915ee511de8604ff932efc4be2ae7bae762b59351` and
`8fea6fd46abec976290694894ede842f88919fbef0299ba65e8190c3e2b10b6e`.
Each run's `original-tested-WIP/` preserves its complete five-file variant;
private control/profile state stays in owned host-bound state, not evidence.
Both actual App2 child tests exited 0 without skip; actual parent/child resource
absence was independently checked. Exact argv, actual inspect reports and child
log hashes remain in each `app2/receipt.json` and execution records.

The final binary separately skips the ordinary unconfigured test (exit 0,
**1 SKIP**, not acceptance), and rejects required mode without its control
supervisor (exit 1, **1 expected FAIL**). The driver sets
`CICADA_N3_REQUIRE_APP2=1`; missing child/supervisor or a skipped dedicated test
cannot satisfy its gate. Final evidence-parser tests are **22/0/0**. A later
parser-only fix rejects a JSON-null child receipt; re-evaluating the same frozen
second-run events/argv/binary/receipt under that stricter evaluator exits 0 and
produces the same result hash, without a third container run or source relabelling.
The policy/parser review is
`.local/evidence/composable-registration/run-20261020T075053Z-8d262d/qa-app2-prep-t__248pk/post-required-policy-fvnl_4wp/review.json`,
SHA-256 `3b00cd982ca715f406c5b4fd41280af56efce1c34e3a55f909f1f9fbb4da655d`.

All INST-01..07, new C0 registration/pin authority and actual App2 authorized
shared-state reads remain **NOT_RUN** pending the frozen Hub contract and real
adapters. Linux App1 exit/Node-peer continuity is separate from App's Linux
Hub/Node component-removal tests; Windows App uninstall/DPAPI/clipboard remains
**NOT_RUN** here. No old N2/N3 matrix, standard interop, real Node service/state,
SID, queue/model/Runtime or public deployment was exercised by these checks.


### Accountless App pre-registration protected storage

2026-10-20 UTC, **SCOPED_LOCAL_STORAGE_PASS**. The new
`internal/appvault/pre_registration.go` API keeps an independently generated
ordinary App subject identity before account/Owner IDs exist. Its scope is
exact canonical origin, Hub ID, complete Hub fingerprint and the stable local
InstallationID (16 random bytes, 32 lowercase hexadecimal characters). There
are no invented account/Owner IDs, Owner-signer purpose, key import or identity
replacement operation. `PreRegistrationPath` places files in the separate
`pre-registration/<scope-hash>.pending` namespace. The independent file magic,
complete header AAD and key-wrap context are separate from legacy vaults;
legacy Scope validation, file format and profile discovery remain unchanged.
A pending file never becomes a logged-in account profile.

`CreatePreRegistration` atomically publishes the generated subject key before
returning any key handle. `OpenPreRegistration` requires the exact expected
scope and never auto-generates a replacement for missing/corrupt state.
`Identity` returns a detached handle. `LoadState` and `CompareAndSwapState`
retain one opaque recovery snapshot of at most 1 MiB. Only the current revision
is accepted; exact bytes at that revision are a no-op, while a stale revision
conflicts even if bytes match. A nil snapshot is a versioned tombstone that
retains the identity and monotonic revision. The API never interprets HTTP,
expiry or settlement and offers no automatic cleanup or delete operation.

**Create success is not permission to send a registration request.** The
future protocol adapter must first persist admission private key, S and the
complete original packet together in one CAS, then retain that exact snapshot
until authenticated settlement. This checkpoint contains no network or DTO
adapter and does not establish that sequencing end to end. Final account-vault
promotion/convergence and migration are also **NOT_RUN**; this local store
alone cannot report enrollment, Owner proof or management success.

The implementation reuses the existing platform Protector, protected directory
and file checks, process lock and atomic write helper. Production Windows is
current-user DPAPI with the existing protected current-user/SYSTEM ACL policy.
The payload is AES-256-GCM encrypted, including private identity and opaque
state. Cross-scope copies and public-header rewrites fail authentication.
An open store also checks inode identity and the complete sealed-file hash
before mutation, rejecting same-inode changes, rename replacement and links.
A possibly published write or failed post-write validation fences reads,
identity access and writes with ErrCommitUncertain until close/reopen. Reopen
uses actual authenticated disk state rather than resealing the cached packet.
Close clears mutable private buffers; runtime-level zeroization is not claimed.

Evidence is retained under
`/home/zyf/Cicada/.local/evidence/composable-registration/run-20261020T075053Z-8d262d/app/pre-registration-01/`.
The producer receipt SHA-256 is
`abf865207142c56755fafee8532ba8858d820a0db432f10764cd61fd89ac18d9`.

| Check | Actual outcome | Exit |
| --- | --- | --- |
| Linux normal appvault checks | 40 PASS / 0 FAIL / 0 SKIP: 28 new pre-registration events and 12 legacy vault/discovery events | 0 |
| Linux race appvault checks | Same 40 named events, 40 PASS / 0 FAIL / 0 SKIP | 0 |
| Windows amd64 appvault test-package cross-compile | Actual PE test binary retained; not executed | 0 |
| Go compiler and all three actual binary metadata | Go 1.27.3, pinned Bookworm builder | 0 |

Counts include parent tests and subtests. The Linux tests explicitly use the
synthetic password Protector, not a platform-protection fallback or Windows
DPAPI execution. They cover exact binary snapshot/identity restart recovery,
stale versus current retries, no-rewrite idempotence, scope copy/header changes,
corrupt and legacy-format input, invalid scope, size/revision limits, versioned
tombstones, post-publication sync failure, file replacement and legacy profile
separation. The actual child process cannot open a parent-held store. After
the parent releases it, a child durably writes and deliberately exits without
Close; a fresh open in the parent process recovers the same App identity and
original bytes.
That is process-exit recovery, not a host-power-loss acceptance test.

| Actual retained artifact | Bytes | SHA-256 |
| --- | --- | --- |
| Normal executed appvault.test | 4,894,983 | `85d847714a4e145d80e0fd789e5ac9284f4ea423a0b455465576bd113445938b` |
| Race executed appvault.test | 6,676,743 | `9ddd65e1eb310b457d6123d7f2737899cdea489b8e9e954fc44675a660b83f13` |
| Windows cross-compiled appvault.test.exe | 7,371,264 | `2b9172e4969c543748f420dc2c47847132d1d896644efc4f04fb072d072bc22d` |

Original and retained executed binaries match before and after both Linux
runs. NUL-separated argv, inherited umask, compiler/module metadata, commands,
logs and exit codes remain in evidence. Source and full build-input bookends
match independently. All owned Docker containers were absent and task-private
temporary state was empty afterward. Network was disabled and source/module
mounts were read-only. No product service or real credential/state was used.

These executions used **dirty `709531966b90aabedc80ee619922a589b991d20d`
plus the two new source files**, source manifest
`677a8cc59f63f27f552f43a515f8a7a5aa5f869699194bb5580a9cbd3f805c65`
and build-input fingerprint v4
`9a472d82f183cc53b636f35e0d5ed8b826a9212ce830058446c2b13ad967378d`.
Root later synchronized the worktree to QA checkpoint
`79ba11db596f5f5411ae73535a92e421187d6d16` with both WIP hashes unchanged.
That synchronization and this subsequent documentation append do not convert
the runs to clean-79ba or later-commit evidence. No repeated UI/installer,
Windows GUI or historical N2/N3 matrix result is asserted here.

Windows native DPAPI/ACL/GUI, cross-user behavior, physical devices, C0 network
registration/Owner proof, first-HTTP admission snapshot sequencing, final
account-vault convergence, real Node/services/queues/Runtime, public HTTPS,
external rollback resistance and host-power-loss acceptance remain **NOT_RUN**.
No public protocol, server, deployment, global Codex configuration, real key or
grant changed, and no management authority is inferred from these storage tests.


## 2026-10-20 controlled installation registration C0 (availability false)

This checkpoint implements the new `installation-registration-v1` contract,
Go DTOs, pure proof/codecs, public synthetic vector and checker on
`73d48ad297ec21eb1fb480e97c1b7b4e6057912a` plus exact dirty C0 inputs. It does
not add a Store migration/HTTP handler, change existing ingress authorization,
or advertise availability. The authoritative boundary is
[controlled installation registration](hub-installation-registration-contract.md).
Node/App consumer integration and H1/H2 persistence/guards remain separate work.

The earlier producer variant completed **37/0/0**, default vet, exit 0:
`device-registration-c0/candidate-tests-20261020T091626Z/summary.json` under the
workspace-local evidence root. Its source manifest SHA-256 is
`4c8a9f73baf7dac98c00be9490134b87c105228565afbec29adcbaa3fdce4250`;
all **2,300** inputs match before/after. That variant used the earlier
`709531966b90aabedc80ee619922a589b991d20d` dirty source and generated the visibly
synthetic public vector outside the repository. Its results are not relabelled
as the later source. Only the exact synthetic vector file's ownership was
corrected to allow the producer to copy it; its bytes remained SHA-256
`43472cd3940be21f24adb5b6b624134019bb81b990b2f475f2b5a047af3d79d9`.
No private key is in that public vector; its wrapper explicitly says never to
initialize a deployment from it.

The final C0 source completed **51/0/0**, default vet, exit 0:
`device-registration-c0/final-normal-20261020T094617Z/summary.json`, SHA-256
`53cc5000aed276042275243439d709839c58b6498751cf35eb58b2e2aed1b165`.
Its source manifest SHA-256 is
`07f019d1c88b0ddb9f07be8da70c8ad0fa5b7661d5023a162bdb6cc5221df889`;
all **2,308** selected inputs match before/after. Only this append-only,
non-input validation document is excluded. The committed synthetic vector is
verified in this run, rather than generated again. The pinned offline image is
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`
(Go **1.27.3**). Source/module cache are read-only; the historically named
`n2-acceptance/gomod-go1.27.2-stable` cache contains the unchanged current module
closure. The separate task Go 1.27.3 build cache is locked. Exact argv, environment,
JSON logs and actual executed binaries' before/after identities are retained.

The final actual e2ee test binary is
`a883acf329b2282bc5fb10928f82d616e87946758ef3673f56e1428229792f3b`;
the wire test binary is
`b1b139daf981681eac2da27439b627e21fd84dfa28f8525b59605daa5c4c8f83`.
Both hashes match after execution. Exact owned container ID
`d14552b8aa2a692c5e2b343cf336d06ea45f3f2a22da5cc919702916debd7b48`
is confirmed absent by `docker container inspect`; its diagnostic/exit status
is retained in the summary. Temporary files use the disposable container
filesystem, not a resident Hub or power-loss fixture.

Actual production-crypto measurements on that final source:

| Synthetic case | Encoded bytes |
| --- | ---: |
| Maximum legal compact ticket (origin 256 / HubID 96 / full 64+64 pins / nanosecond UTC) | **959 / 1,024** |
| Maximum metadata PQ start | **73,817 / 131,072** |
| Maximum metadata PQ Owner completion | **124,102 / 131,072** |
| Its actual Owner proof / trust capsule | **15,688 / 29,369** |
| Reconcile carrying that original completion | **311,681 / 655,360** |
| Maximum-field real PQ slot attestations (A/B) | **9,336 / 9,336** |
| One such complete Pair snapshot response | **79,207 / 262,144** |
| Byte-budgeted page with separate 16-KiB attestation-cap buffers | **212,771 / 262,144**, **2 of 16** rows |

The 16-KiB buffers are explicitly a DTO upper-size stress case, **not** valid
peer proofs or SQL-made authorization. The separate real-attestation fixture
passes the existing complete slot verifier. The computed plaintext page budget
is **140,747** bytes; tests reserve worst-case Go JSON escaping for the bounded
cursor, encode row bytes once, set cursor/truncated and PQ-seal the final page
once. The size model equals actual Seal output. Ordinary request/reconcile
limits, complete encoded expansion and malformed/oversize rejection are checked;
no legacy limit was enlarged. HTML/Unicode URI reg-names and bare-query origins
are rejected by the new validator, rather than truncated to make a QR fit.

Coverage includes noncyclic B/T framing, capsule-only ACK nonce, independent
admission/subject signature **and KEM** proofs, a valid signature advertising
someone else's KEM key, Hub Owner-key substitution, first-pin expiry/zero-time
rejection, FIRST_OOB versus actual-local EXISTING_LOCAL_PIN, registered-parent
append and legacy Node first adoption, current bearer/digest/version checks,
original packet authentication distinct from fresh admission, exact nested
receipt recovery, fixed read profiles, Owner-read-proof XOR recipient grants,
own-only grant discovery, concurrently effective 16-grant limit and liveness
without registration/permission renewal. The original Node tuple is preserved
in the pure adoption model; durable Store preservation remains an H1 gate.

Two build-only precursor failures retain their own source/result. The first,
`syntax-20261020T083817Z`, source
`65b17424ac6fc88c0924da61c859ea8bd881ca66f58f6d13d831d95cc0a15695`,
selected the incomplete old default module cache and failed setup offline/RO.
The second, `syntax-20261020T084002Z`, source
`be6576854ece1f37bb003b42f810632c1e781a0ad3f9c262a1ca1e59589dd295`,
used the correct cache but failed compilation on a wrong HubIdentity field name
in new code, subsequently corrected. Both ran **zero assertions**, both exact
owned containers are absent, and neither is counted as a compile/test PASS.

The new contract checker, existing native-pair checker and `git diff --check`
pass. C0 availability stays **false**. Race, Store/real TCP, three-component
actual carrier, standard combined-source Client interop, Node local durable
pin/ACK execution, Windows GUI/DPAPI/ACL, physical-device/Android, public HTTPS,
strict PQTLS and native Runtime remain separate **NOT_RUN** gates here.
No real credential/key, model/provider, queue/SID or resident deployment was
operated. This scoped checkpoint does not authorize deployment or public readiness.

### C0 final review: bounded issuance clock tolerance

Root's final review identified that strict `now >= issued_at` prevents an
ordinary Node/Hub exchange when their trusted OS UTC clocks differ slightly.
The revised C0 source uses one **30-second issuance lower-bound tolerance**
for Start, self/account fresh headers, ticket matching, KEM challenge/receipt,
Owner proof/intent/read and finite-grant admission. Hub challenge issuance and
approval preparation may also precede the installation's issuance by at most
30 seconds. All original expiry/session/accept deadlines and the at-most-60s
fresh request age are unchanged. There is **no expiry grace**, original rewrite,
historical-clock substitution or new time service. Time zones only affect display.

The preceding **51/0/0** full C0 result and its maximum-size measurements remain
attributed to source manifest `07f019d1...21df889`; they are not relabelled as
this revised source. Its original candidate/summary evidence is unchanged.
The targeted final review run completed **136/0/0** events, including **11**
top-level time-related tests and their subtests, default vet, exit 0:
`device-registration-c0/issuance-skew-20261020T095650Z/summary.json`, SHA-256
`7533db61474de959cb855ec488c56973756acfe232c36e93624285a3c04e14cf`.
Its source manifest SHA-256 is
`795c59f590d26ddb1b8b2c74b114fb5dad1f0e96990c7760c7775ca2dd478690`.
All **2,308** selected source hashes match before/after, with only this
append-only non-input ledger excluded, on dirty parent
`73d48ad297ec21eb1fb480e97c1b7b4e6057912a` plus the exact revised C0 files.

The run checks both ±1-second directions, exactly 30 seconds early, rejection
at 30 seconds plus one nanosecond, zero-clock rejection, exact expiry and late
first pin rejection, immutable original packet bytes, and historical recovery
without renewed admission. Existing pin/legacy adoption time paths are included.
The pinned offline Go **1.27.3** image, read-only source/module mounts, locked
task build cache and no-network policy are the same as recorded above.
Executed binary hashes before/after match:
e2ee `9bebc59842aab60c68ad92f4035004ee0492459693784c1cdd2895635777ef9a`
and wire `06bad83d02d83fa62a1a2c00c36e43e11ef6e7e488d903d25c039fb39eb4f16d`.
Only their identities/logs are retained; the binary files were disposable.
Exact owned container
`6941f6a6aeedcf3e58bf2b7acec27559168e9084ed88a33c63df801eb89ab319`
is confirmed absent; inspect exit/diagnostic is retained in its summary.
The new contract checker, frozen native-pair checker and whitespace checks pass.
Availability remains **false**; the preceding C0 NOT_RUN gates remain unchanged.

## 2026-10-20 C0.1 installation registration v1.1 consumer contract repair

This is a pure crypto/wire/DTO checkpoint on dirty parent
`33ccb08e8551544b869b6c5561a22054f8896b95` plus the exact C0.1 source below.
Contract revision is **installation-registration-v1.1**; wire version and both
format identifiers remain v1. The original C0 v1 contract, **51/0/0** normal
variant and **136/0/0** clock-review variant keep their original source/hashes.
Their results are not relabelled as v1.1 and the incompatible old Owner scope
is not presented as a supported registration carrier.

The revision uses actual InstallationAccountScope coordinates, with no fabricated
ClientSessionEpoch/N3 head. Mandatory own ActorScope discovery, Owner-only subject
and pending-attempt references, true parent OwnerID/InstallationID, closed query
filters and exact target projection checks make the consumer sequence executable.
NEW_NODE has no old candidate, bearer or binding; ADOPT_EXISTING still requires
the complete original tuple and current actual bearer validation. Poll-to-admission
raw bytes, rather than the Owner-only completion response, are the exact Accept
approval receipt. All of these remain protocol/codec facts, not completed Store,
HTTP, Node-local pin or App UI behavior.

The final relevant normal gate completed **186 pass / 0 fail / 0 skip** events,
including **26** top-level tests (**148** e2ee events, **38** wire events), default
vet and exit 0. It ran both pure packages with `-run ^TestInstallation -count=1`
and `-timeout=120s`, without rerunning the old unrelated product matrices.
Evidence is `device-registration-c01/final-normal-v11-20261020T103620Z` under the
workspace-local evidence root. Its summary SHA-256 is
`c6075b81ef4b21287873a14d79c382644084436d90d7fc6f7806a0b906e5919b`;
the source manifest SHA-256 is
`ed77a9b2313295f1b23eafb878fc0e0ad67508d0d271da37b805eb254d5a5928`.
All **2,309** selected inputs match before/after and at final candidate review.
Only this append-only non-input ledger is excluded. The previously tested prose
was restored byte-for-byte after a transient post-gate clarification, so no
documentation-only source difference is hidden or attributed to the test.

Pinned image is
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`
(Go **1.27.3**), network disabled, source/module mounts read-only, offline module
resolution and read-only module mode. The C0.1 build cache is separate and locked;
the container runs as the current task OS UID/GID. Actual executed binary hashes
before/after match: e2ee
`db2949b2391149561254cd33db953cbda69349cd22bee69a2151830aa226906d`
and wire
`e2c17b0fa64a794f7d9676dbbeac1b9d3ca0878fc5a45438fe154e1ee4076dd0`.
Only identities/logs are retained, not the disposable binaries. Exact container
`4879dae7e26dcd3c66dee428687c4e4ca2b55895df38b334fc1536713d155c48`
is confirmed absent; its inspect exit/diagnostic is retained in the summary.

Actual v1.1 production-crypto encoded sizes:

| Synthetic case | Complete encoded bytes |
| --- | ---: |
| Maximum legal compact ticket | **959 / 1,024** |
| Maximum metadata new-Node Start | **72,905 / 131,072** |
| Maximum metadata Owner completion | **123,866 / 131,072** |
| Its Owner proof / capsule | **15,646 / 29,313** |
| Reconcile carrying that original completion | **311,117 / 655,360** |
| One real maximum-field PQ Pair with full ActorScope | **95,443 / 262,144** |
| Pair page with separate 16-KiB-cap size-only buffers | **228,999 / 262,144**, **2 of 16** rows |
| Mixed Owner inventory with actual independent public keys | **255,267 / 262,144**, **41 of 50** rows |

The mixed page contains **9** parents, **24** subjects and **8** pending refs.
Its complete own-context/registration/cursor-reservation footer is **17,467**
plaintext bytes; the total plaintext budget is **140,747**. All six list kinds
count toward the request page ceiling, and the full footer counts toward encoded
bytes. The size model equals actual Seal. The real Pair attestations are each
**9,336** bytes; the separate 16-KiB buffers are explicitly size stress, not valid
proofs. These measurements establish codec bounds, not true registrations/grants.

Additional coverage rejects foreign own Owner/App public/parent/install metadata,
foreign subject/pending installation filters, NodeID aliases in place of exact
binding IDs, a real foreign Pair row, foreign recipient refs, unknown grant
origin/profile/state and mixed-list overflow. It keeps ±1-second issuance tolerance,
the exact 30-second boundary, strict expiry/late first pin, real signature/KEM PoP,
independent existing pins, exact original authentication and current legacy bearer
checks. Owner scope discovery is context only; none of these tests grants Root,
general management, execution or peer authority.

A separate public-vector producer ran **1/0/0**, process exit 0, source manifest
`7a2218c45be1737dce0191e9761822bbe2d0d403e6e289b6092cc5662574fa95`:
`device-registration-c01/vector-producer-20261020T102810Z`. Its input hashes and
actual binary before/after identities match, and its owned container is absent.
That original summary's `generated_vector:null` is retained: the runner's last
existence check still named the old v1 file. The actual argv/environment and
test used `CICADA_INSTALLATION_VECTOR_OUTPUT` with the v1.1 filename. A separate
`vector-copy-receipt.json` records the real output/copy and this metadata defect;
no original summary was rewritten and this was not counted as a complete artifact
handoff by itself. No ownership/permission correction was needed. The final normal
gate verifies the copied v1.1 fixture and exact revision; its SHA-256 is
`80b1e9fd325111dadedb14c7c90ae68aca83603b865eb0b29201191d401a0577`.
It contains visibly synthetic public material only, no private keys or actual
NodeCredential, and says never to initialize a deployment.

New v1.1 checker, frozen native-pair checker, Go formatting and whitespace checks
pass. Default public availability remains **false**. H1/H2 Store migrations,
same-transaction effects/receipt/fences, target/grant runtime filtering (including
status-attached grant refs), issuer-logout-independent grant use, terminal retry
and conditional durable-pin recovery are **NOT_RUN** here. Race, actual TCP/App/
Node carriers, Hub restart/restore, standard combined-source Client interop,
Windows DPAPI/ACL/GUI/uninstall, physical devices, Android, public HTTPS/PQTLS
and native Runtime also remain separate **NOT_RUN** gates. No real keys/state,
model/provider, queue/SID or resident deployment was operated.


## 2026-10-20 user-operated same-Node Pair batch

Root relayed the user's report that the complete instructed batch behaved
normally: the original A/B Threads joined, both actual candidates received
separate consent, ASK/Reply worked in both directions, and communication
continued after closing the App window. Record these observations as
**USER_REPORTED_PASS**, not independent execution by QA. The delivered-artifact
context remains the clean `4ca29dfc76f3eec9143676d554b3a26c1a178f1b`
package identified above; this feedback introduces no new build, executable
hash, deployed-image assertion or attribution to the later documentation HEAD.

The first user observation was that both Threads showed Cicada connected with
nine tools. Root's separate read-only process inspection found that those MCP
processes had no CODEX_THREAD_ID/CODEX_SESSION_ID. Connected tools alone therefore
did not establish the original native context or successful Join. The user
then read each original Thread's actual SID/cwd through its native shell and
personally resumed that exact existing Thread with per-launch MCP configuration.
The same SID was used for exact resume and the MCP environment; conflicting
CODEX_SESSION_ID/CICADA_NATIVE_SESSION_ID/CICADA_WORKSPACE aliases were cleared.
This is a bounded manual recovery procedure, not general automatic discovery,
a new launcher or permission to invent a SID, fork/new Thread or replace keys.

After that manual recovery Root reported read-only matching of both actual MCP
child processes: each CODEX_THREAD_ID matched its previously observed original
SID, cwd matched its A/B workspace under
`~/.cicada/acceptance/native-pair/`, and the original Node ID/state path,
CODEX_HOME and Hub origin matched. Conflicting aliases were empty. Raw SIDs,
record contents and private context are omitted here. This is
**ROOT_REPORTED_READONLY_CONTEXT_MATCH**, not QA-operated Join/model/queue work.

| Reported user action | Observation and scope |
| --- | --- |
| Original A/B Join into their reviewed Pair slots | USER_REPORTED_PASS; two original Threads after exact manual resume, not a replacement session |
| App reviews both actual candidates and records separate consents | USER_REPORTED_PASS; account login or the first consent alone is not generalized as peer authority |
| First ASK/Reply and reverse-direction ASK/Reply | USER_REPORTED_PASS for the instructed native exchange; no request/message IDs or trusted per-hop trace were supplied |
| Close the App window and continue the exchange | USER_REPORTED_PASS for window-close continuity; logout, uninstall, Hub/Node restart and grant expiry/revocation were not separately reported |

No request/message IDs, answer/witness digests, complete tool traces, elapsed
times, model/provider/queue counters or actual route evidence accompanied this
batch. It does not independently prove automatic wake, precise delivery latency,
all consumption stages, sealed Relay versus direct routing, budget/replay
boundaries or negative authorization cases. Do not convert the report into an
aggregate independent PASS or extend it to unexecuted cases. Dedicated native
Windows DPAPI/ACL/GUI security, fonts/high-DPI and second-instance recovery
retests remain **NOT_RUN**; historical source-specific failures remain intact.

Recording baseline is `6f7f2c9bd5e98caa1ef76465f6a2a79e8062d735`.
The five untested lifecycle-harness WIP files remained frozen. This recording
runs no new gate, build, service operation, model turn, queue or real Join and
changes no native record, original Node state or Windows vault. C0.1's pure
186-event result and the empty App2 fixture remain separate; neither is evidence
for this actual user batch. Remaining feedback and independent acceptance
criteria are maintained in the [existing plan](native-app-plan.md#current-feedback-and-acceptance-ledger),
not a new task book. Uninstall scripts are outside the current remediation stage.

## 2026-10-20 independent Endpoint and Hook checkpoint

The bounded backend is committed at
`d3acd4bfe6f3f10867db6a5e3ae432f8477d9748`, parent
`bb0644b68627579af470ead52035d42618372c75`. Its
[contract](native-endpoint-directory-contract.md) and
[producer validation](native-endpoint-directory-validation.md) remain separate
from the independent scopes below. The broader C0/H1/H2 installation family
stays frozen. No old N2/N3, LOGIN, N3-TT, INST or Windows result is relabelled.

### Integrated UI and retained unvalidated work

The seven UI blobs in `bb0644b68627579af470ead52035d42618372c75` add native
navigation, collapsible detail, public text selection and OS CJK font fallback.
Producer evidence is under
`/home/zyf/.cicada/acceptance/app-ui-checks/run-20261020T135022Z/`:

| Receipt | Result and source | SHA-256 |
| --- | --- | --- |
| `ui-validation.json` | Normal/race each 133/0/0, vet 0 on its initial dirty `9866cf3` source including retained old WIP; later fixed Windows cross-builds have their own manifest | `769812375855d18c93a1a2412244d5cacd22ec21c43cd7b7c42d7b1e9d47fa0c` |
| `ui-cjk-compile-validation.json` | Two Windows cross-build exits 0 on later dirty CJK source, manifest `d740a042fa2fc8c2f726385af0d154327f2a00bb63eb974ca675314be134c01c`; the earlier normal/race result is not transferred to it | `4d2d49c1a92c5e95595cc3b04ba6825af532bbeefdfaedb9f9f878349983fdc3` |
| `ui-commit-receipt.json` | Seven committed blobs match the reviewed candidate; ten old WIP files excluded | `43e0c45548648feb4c7862b9449cec6941f810fdfbdbf2c6e1b07f704ab11b91` |

Root independently ran clean `bb0644b` in disposable offline Docker:
`/home/zyf/Cicada/.local/evidence/native-ux-root/ui-state-tmp-20261020T140807Z-a18060/result.json`,
SHA-256 `d7ac2cddf4c430ca13b8a9705539ced1af7c136167977f9fd43109dd8e760c3b`.
Normal UI tests passed 133/0/0 (39 top-level, 94 subtests); both Windows cross-builds
passed. This is not a clean-source race run. Its GUI EXE SHA-256 is
`fcb6fb357cdd03d0fb4bf261d0d9c792501af26309ec4cc8e57d54cb7c70c367`;
the native UI test EXE is
`89cedd5a246b0da18fa3cdb94a0bea92af93318b8fd09c0d87b054fe3474c585`.
Root's earlier output/tmp permission setup failures remain retained and ran no
product tests. Font loading, clipboard/DPI, GUI execution, DPAPI and ACL remain
**NOT_RUN**. Historical Chinese and second-instance failures remain intact.

The old unfinished lifecycle work was archived before the new independent
driver was written, then removed/restored out of active build inputs:

| Git archive ref | Commit, parent `bb0644b68627579af470ead52035d42618372c75` | Boundary |
| --- | --- | --- |
| `archive/composable-acceptance-wip-20261020` | `7268310069704221f83322ec1df3f87c04edf8ab` | Five QA files, UNVALIDATED; no compile/test/integration claim |
| `archive/composable-app-wip-20261020` | `b0df01963d0307b9a43d3e11f0e1d1a339bfcb83` | Ten App files, UNVALIDATED; no acceptance inferred from their presence in an earlier UI source |

Root separately preserved/pushed the archive refs; QA did not integrate or push.
QA's five-blob archive verification is
`composable-registration/run-20261020T075053Z-8d262d/qa-wip-archive-4x4zpd7l/archive-verification.json`
under the workspace evidence root, SHA-256
`55fcb7bc23b20fee92f9ad82ece622e608848bd5b3585c6ef53b7befc7acdc2e`.
The preceding record's statement that old WIP was frozen describes that earlier
recording time; it is no longer present as active unfinished source.

The subsequent 29-file paths checkpoint is
`73d6f9ad13c26ad7cf203e2924adcc7a46104213`, parent
`2ab4e5155f4d8c082f69a3fe2764b6d7fee84e72`. It partially implements new
App/Node/MCP defaults, custom root, installer file prefix and original-location
recovery; Hub/workspace/cache defaults, migration and physical Windows remain
pending. Its [producer record](../cicada-go/cmd/cicada-app/README.md#selected-user-root-and-original-state-recovery-2026-10-20)
keeps original dirty-bb0644b normal/race matrices and affected dirty-d3 Core
8/0/0 plus Windows cross-build separately attributed. The 29-blob commit receipt
is `/home/zyf/.cicada/acceptance/app-path-checks/run-20261020T151357Z/paths-commit-receipt.json`,
SHA-256 `27579b7ab8e39d56715af039e0e7eac46801094b7e19ec7eba230d38173e625e`.
No real vault, Node data, launch environment or Codex account was migrated.

### Independent real App approval and Endpoint TCP faults

Reproduction: `scripts/test-native-pair.sh --endpoint-security`.
This builds the actual CLI and acceptance executable, starts owned Hub Nodes
CLI processes on allocated loopback ports, and uses real App Core child/vault
actions to approve a visibly synthetic Node. The driver never loads the Owner
private signer. Only the Node wire actor/SIDs/workspace are synthetic. Every
original encrypted request is persisted before send; the proxy only loses or
changes opaque transport bytes. The actual Hub restarts against its owned
SQLite database and original keys. Offline read-only SQL observes zero rights;
it creates no pins, grants, memberships or positive authorization.

The image is Go 1.27.3 at
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
Docker uses network none, read-only root/source/module mounts, UID/GID 1000,
no extra capabilities and a locked task build cache. Source snapshots include
the complete Go tree, the new contract and drivers; before/after binary hashes
and exact container absence are mandatory. A skip/missing test is a failure.
Neither a dirty build nor later corrected tests are attributed solely to HEAD.

Evidence root: `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`.
All four development runs below used `d3acd4b` plus their distinct dirty QA inputs;
each retained all nine expected terminal test events, CLI/test compilation and
vet exit 0, matching source/binary bookends and an absent owned container.
Each aggregate returned exit **1**, not PASS:

| Run | Pass/fail/skip events | Reason retained | `result.json` SHA-256 |
| --- | --- | --- | --- |
| `run-20261020T153028Z-eOR2AA` | 1/8/0 | New synthetic Node IDs lacked the existing fixture prefix; Endpoint protocol was not reached | `e14a9f9dc819b8962300027398c2eabd05cd6d81f06c2b992773a6c3b2ea1919` |
| `run-20261020T153345Z-2XbWKt` | 2/7/0 | Leave passed; driver incorrectly counted preceding App proxy traffic and attempted a second initial Node approval forbidden by the current App provenance flow; concurrent 403 also observed | `1fe2c939dcaf082047082be39c917119720803ba063644f0c2ea1448f25b53de` |
| `run-20261020T153625Z-iJCOfn` | 2/7/0 | Driver expected full-Handler routes/statuses in the bounded Nodes-only composition; concurrent public 403 diagnosis retained | `9887e9bc8cba33b07d5340d372ece8b95b26d1c084fcfcf4f0968ed3beb0ed93` |
| `run-20261020T153910Z-m6vDoD` | 7/2/0 | Method barrier, Leave and all four fault subcases passed; session-token prefix expectation still wrong; concurrent overload remained FAIL after successful original recovery | `3a46e86094993d4daf595a40b5db269ccaf132747a3bc970d2ce546a44b6d0d1` |

The last source manifest is
`0f16bd4d2b59ff57897203ce5a85842b8a4475461ef6dc7d7f6d6ad852ab7c23`.
Its executed CLI/test SHA-256 hashes are
`c2eb483ae09c614067931c33e8b50c506eb82b5abec224dd8c984b2dc03f19d8` and
`092b26cea199cb7a439fd808b160c317ebf93211b4276cb986dca112f1c3a8e1`.
Its passed fault scope covers loss before forwarding, loss after committed
response, unsigned 403 and corrupt response. Closing the actual App child and
restarting the actual Hub still recovers the exact persisted request and cached
authenticated receipt, with one offline zero-right Endpoint. Replacing the body
under the same operation is refused and cannot replace the original receipt.
Leave checks current opaque digest, authenticated cached terminal refusals,
another Endpoint remaining unchanged and no revival/deletion of the left identity.

The independent concurrent failure is assigned to Hub: four identical valid
packets can hit the two-slot nonblocking worker limit; `hubnodes.Service.acquire`
returns generic unavailable and `hubNodesHandler.nodeRPC` maps it to unsigned
403, "Node binding status request rejected". The fourth run observes two such
403s, then verifies serial recovery of the original authenticated receipt and
only one zero-right Endpoint. This is overload/status ambiguity, not evidence
of unauthorized mutation. Root approved a distinct busy→429/Retry-After repair;
old failures remain. The correction selector is
`scripts/test-native-pair.sh --endpoint-security-boundaries`, covering only
registration/auth boundaries and concurrent original recovery.

The correction ran on `2ab4e5155f4d8c082f69a3fe2764b6d7fee84e72` plus dirty
QA source: `run-20261020T155233Z-lR0KG4`, **2/0/0**, all CLI/test compilation,
harness, vet and driver exits **0**. Source manifest is
`69ecd1a2e15484c2729a8abb9573d69d19a1b45b4af7a921e07da6a27fa5d8c6`;
`result.json` SHA-256 is
`c5771e67d02db87dc9bb185e85a1b7a125cbf277634de44adbc21901d8442418`.
Source and executed binary bookends match. CLI SHA-256 is
`16af7da4a9ef2f863c86e18aca9399a5cdc90e53f28317ec8bb8da77402999de`;
test executable is
`24fb0d2be825a1f165abf15497dfcb82f00e86ff87b4272a4a7a90d67d77c0e5`.
Exact container `cicada-native-pair-run-20261020t155233z-lr0kg4` was removed
and its absence independently rechecked after the driver ended.

Actual App approval, offline zero business rights, duplicate labels with distinct
IDs, immutable repeated metadata, wrong Node route, wrong credential scheme and
valid-format but nonexistent native Session credential all pass. Four concurrent
identical packets produce two actual 429 responses with `Retry-After: 1`, retain
the original pending packet, and recover one authenticated terminal receipt with
one zero-right Endpoint. This closes the bounded overload-status defect; it does
not make an unsigned 429 an authenticated outcome. The earlier seven passing
events retain their original source; there is no fresh nine-event aggregate PASS.
The final status-document edits are post-test documentation, not changed Go code.

After Root fast-forwarded the paths checkpoint, only the affected actual-App
fixture was rerun with
`scripts/test-native-pair.sh --endpoint-security-app-fixture` on dirty
`73d6f9ad13c26ad7cf203e2924adcc7a46104213`:
`run-20261020T155704Z-RxgyoV`, **1/0/0**, CLI build, complete acceptance-package
compilation, harness, vet and driver exits **0**. Source manifest is
`0610bb7b6a53f0827aaca9bdecce5d87d87ee7d28c6f25f81acef82d41e4b573`;
`result.json` SHA-256 is
`88152ed86e89380fb2a392e62add2aacac20f7a7629b7881cd9bc0a7c7730108`.
CLI/test executable SHA-256 hashes are
`b6f512100bed0712007c0bcf62e734823a6ba8bea87d356ab7d72ee7ea1bbf70` and
`434b6bbc03059405ab024833c4cae2ba36bd0c456509d02bd890a131f559d6b2`.
Source/binary bookends match, and exact container
`cicada-native-pair-run-20261020t155704z-rxgyov` is independently confirmed absent.
This verifies actual App Core approval and the zero-rights/authentication fixture
after the storage changes. Concurrent/Leave/fault and producer path/security
results retain their earlier sources; they were not silently transferred or
rerun as a full matrix. Root's separate standard interop remains unreported
here until its own receipt, not inferred from this test.

Actual production Node process/outbox/adapter, product Hook tickets, second
approved-Node adoption, real Group/Network Leave or changed-authorization CAS,
actual Owner-directory App action/privacy/page/cache/old-N2-TTL cases and actual
native Runtime remain **NOT_RUN** independently here. The forged Node route
checks token/Node binding only. Existing producer coverage is linked above;
it is not substituted for these independent cases. Control inference is off.

### Actual Codex Hook mechanism; product bridge not accepted

The first bounded probe is under
`/home/zyf/.cicada/acceptance/hooks-qa/run-20261020T134434Z-dt98a27i/`.
Its `evidence/final-review.json` SHA-256 is
`bcddbd134a543b46371fddb49785112f57305e4b34d0057f8661ffd2ee226bfe`;
inventory SHA-256 is
`8be34abace42bd5fe4fb869641e5d1cf5db443cd71e2f01a5b2fb8a49ac081a6`.
Actual 0.163.0 CLI/TUI used empty owned HOME/CODEX_HOME and no credentials,
real SIDs, Node, model or queues. An actual normal TUI persisted exact Hook trust;
a fresh CLI consumed it without bypass and handled a synthetic literal command
with zero provider requests. The earlier explicit-bypass mechanism run and
first inspection-only TUI attempt remain separately retained.

Eleven prepared normal-trust/failure fixtures show that trusted literal
peers/join/leave or exit-2 blocking can finish before the local provider trap.
Missing/modified/untrusted Hook, nonliteral input, exit 1, malformed-looking
stdout and timeout can continue to the trap: seven local HTTP requests in total,
each rejected by the static 400 responder. These are pass-through observations,
not host fail-closed or product command/authorization acceptance. No external
network is reachable in network-none Docker; all six owned containers were removed.
Fresh-state reproduction is `python3 <run>/reproduce_normal_trust.py` or
`bash <run>/reproduce_negative.sh baseline` / `faults`. The negative orchestration
exit alone is not a product gate; compare actual CLI/trap observations.

The separate PreToolUse probe is under
`/home/zyf/.cicada/acceptance/hooks-qa/pretool-v2-20261020T152356Z-rrakawp_/`.
Its `evidence/final-review.json` SHA-256 is
`fb51de1384020e1e58ce7f057f4385febc0b335f4c429ab0d914e2bfceb9a2fd`;
inventory is `58ea59d8fce4f530e5e7a92d9ef6070bba72423315cac5ae6cc4bd149710d399`.
Reproduce each case with `python3 <run>/reproduce.py main`, `missing-hook`,
or `fork`; each creates fresh owned state (fork first creates a fresh parent).
Expected mechanism exit is 0, not a product integration verdict. The script
SHA-256 is `4117c63d069707e446b3757195c5818e72e3883a65994476bbb330e0d674d901`.

| Actual CLI case | Observed mechanism |
| --- | --- |
| Main | One PreToolUse and one mock MCP call; actual `session_id` matches `thread.started`, cwd matches; `tool_use_id/turn_id/tool_name` arrive and `allow+updatedInput` replaces actual MCP arguments |
| Missing Hook | Original arguments still dispatch; mock MCP returns `isError:true` for missing context, while CLI exits 0 and contacts the second static response; this is fixture rejection only |
| Actual `exec fork` | A distinct child session and new call ID; static provider deliberately supplies the parent context, and the actual Hook replaces it with the child's context received by mock MCP |

The tool schema declares `qa_context` and has top-level
`additionalProperties=false`; acceptance of undeclared fields is not inferred.
The provider uses the actual advertised namespace `mcp__qa` / function `probe`;
Hook canonical name is `mcp__qa__probe`. Prepared trust uses actual hooks/list
key/hash and the previously TUI-observed persisted form, verified by a fresh
process, with no bypass. Three cases took about 5.2 seconds each, CLI/semantic
exits 0, six local static HTTP requests, no real model turns and three removed
owned containers. The initial flattened-name probe failed before dispatch;
`pretool-20261020T152113Z-54fmzd3u` remains unchanged and is not counted as PASS.

The exact read-only Codex binary before/after SHA-256 is
`399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215`.
Official [Hook semantics](https://learn.chatgpt.com/docs/hooks) and
[Responses namespace format](https://developers.openai.com/api/reference/resources/responses/methods/create)
inform the synthetic probe; actual raw inputs/outputs establish its scoped result.
The real Cicada per-call ticket/MAC/expiry/replay/cross-SID Guard, PQ register/leave
via Hook, clear and subagent context are **NOT_RUN**. Parent SID in a subagent
Hook is not proof of that child's native identity. Windows DPAPI/ACL/GUI and
real-user provider/queue consumption remain **NOT_RUN**.

Root's upstream-version check is
`/home/zyf/Cicada/.local/evidence/native-ux-root/upstream-versions-20261020.json`:
SHA-256 `7c7e128b3d5e23e2675d06cc93387d19bca73b8ae2cf0d271bcb96a0a7296b3e`;
at 2026-10-20 15:38 UTC, Go's official stable feed reports 1.27.3, the official
module proxy lists Gio 0.10.3 and x/sys 0.49.0, and the official Codex changelog's
latest CLI entry is 0.163.0 dated 2026-10-15. This is dated version evidence,
with no dependency upgrade, global config change, deployment or model operation.

Documentation checks preserve the complete historical validation prefix and all
old plan matrix sections. A full-document link scan found an existing historical
`../.cicada-data/native-app-foundation/...` artifact link absent in this worktree;
it is not reported as a full link-check PASS and historical evidence is unchanged.
Only links introduced by this checkpoint are checked against current repository
files. Go formatting, shell syntax, Python AST and whitespace checks pass.

## 2026-10-20 standard Hub interop with an explicit verified module proxy

Root's standard disposable client gate is separate from the actual App/Node
Endpoint and future Owner-read scopes. Three stages retain their original
sources, exit codes and evidence under
`/home/zyf/Cicada/.local/evidence/native-ux-root/`:

| Stage | Recorded outcome | Receipt SHA-256 |
| --- | --- | --- |
| `client-interop-d3-20261020T1546/result.json` | Root-reported clean d3acd4b attempt reached only build; public dependency download hit the bounded timeout. Inner receipt exit 143, aggregate FAIL, all four product checks NOT_RUN, zero product tests, cleanup CONFIRMED | `25428a50ae4174f80e4a05903a530b147d3eaa58e13ac0ee01f1076567d20bc3` |
| `module-network-probe-20261020T1603/cached-result.json` | Download-closure probe only, exit 0, zero product tests. Pinned Go 1.27.3 bookworm image, owned cache, read-only public module source via loopback proxy, `GOSUMDB=sum.golang.org`; owned probe container absent | `45fbf8b30d058c15a91c4a514827981faf971a6edef4cfc47924453545042761` |
| `client-interop-cached-20261020T1614/result.json` | Clean `794de08590c015ed68ad641eac01f695b3bf34ec`, standard client suite PASS, exit 0, 7/0/0 terminal events (four top-level and three recovery subtests), cleanup CONFIRMED | `5ed15fb4bda45d65a948556784d3f120bfcddd4a7fe1cb5f7697e6b29536d1b0` |

The closure probe retains original `go.mod` and `go.sum` hashes
`e51f926fafef510ab423829c7a499bbbf3e5d938cdbc95f379fc1c033dc9b869` and
`ea71a53ecf239d8c23d299033298d43afa3cb27ef1938170b68300804315890d`.
The shared module cache is served read-only; no checksum verification is disabled
and no dependency/version is changed. The failed build and successful download
probe are not relabelled as product tests.

The standard gate runs `TestClientDockerHubSmoke`,
`TestClientDockerHubRecoveryFixture`, `TestClientDockerHubHeadlessOperator` and
`TestClientDockerHubOwnerBootstrap`. Its source fingerprint is
`9ce116e6b717867b080e477be02c5eaab7c064d2d66940e8d933a9635c2ceb6d`;
catalog SHA-256 remains
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.
Root independently matches the post-run revision, clean flag and fingerprint in
`source-after.json` to the build. The separate `root-review.json` SHA-256 is
`fe1be1bd2e47fd8aeb2348a1cdf237cc04291b82fd9e3ac5f2e408af81e24583`.

Executed Hub image ID is
`sha256:a3cf8c13fbc997ee6d5491d90642966525a1b408102d2a60e22ce96abaa1c8a7`;
interop test image ID is
`sha256:b29b800f3e74312eb32ef6858711b2b4c27e86914cae833fb8b6ac284512758c`.
The receipt proves exact absence of its three containers, two image tags and
private scratch directory after cleanup. Root's separate temporary loopback
module proxy was still retained for later owned builds at the 16:19 UTC review;
this does not claim that proxy had stopped.

Reproduction uses a task-owned read-only module proxy and fresh output:

```sh
CICADA_BUILD_GOPROXY=http://127.0.0.1:PORT \
  CICADA_INTEROP_OUTPUT=/ABSOLUTE/FRESH_EVIDENCE \
  scripts/test-client-hub-interop.sh --suite client
```

Use the task's allocated port rather than assuming the old proxy is live.
The explicit proxy build option is in `794de08590c015ed68ad641eac01f695b3bf34ec`,
parent `4215ddce83443673d9b3f4c70a3db7ba02fcc434`. Its separate 13 script test
methods, four proxy-argument subcases and real source-only capture passed on
dirty `2f1d08b`; that metadata/argument check is not a Docker product gate.
The build-fix receipt is
`native-pair-acceptance/build-goproxy-20261020T160750Z-z_6zaofo/result.json`
under the workspace evidence root, SHA-256
`6b4f7e4b87cb8a760a30d3dd69f737b1804ea77b0e48241007a248e63b8c2b30`.
Commit verification SHA-256 is
`0e68a561e397caeb7fb7cbea08644ff2bf476caf4104ab8c4593838c7059a129`;
all three blobs match the reviewed candidate and both Git identities inherit
the global server identity. Parent transfer does not reattribute the old checks.

This standard gate is real TCP Hub/client protocol evidence. Actual new App
Owner-directory actions, Node local Hook/MCP adapter, native queue/model
consumption, Windows DPAPI/ACL/GUI, Android, physical devices, public HTTPS and
strict PQTLS remain separately **NOT_RUN** for this gate. No shared development
Hub, public deployment, real identity or model/provider was operated.

## 2026-10-20 actual App Owner-directory integration

Root integrated Node local-bridge source
`97d8a1d22643ddf911c8842ac9f95802928189df` and App Core/UI source
`07bd265c69d99119d87bdfa6204c27d0273ef14c`. The App's
[producer record](../cicada-go/cmd/cicada-app/README.md) retains its separate
dirty-source normal/race, Windows cross-build and local UNKNOWN-retention checks.
The independent gate below does not inherit those unit results or accept the
product Hook/MCP chain, physical UI or expired-read parking.

Reproduce all six selected terminal tests with
`scripts/test-native-pair.sh --endpoint-security-owner-directory`.
The driver reuses the actual N3 App child, production Controller and original
encrypted vault plus an actual disposable Hub Nodes CLI. The approved synthetic
Node registers original SIDs through real PQ/TCP; the **actual App** then performs
its Owner-signed read. The parent never opens an Owner private key, signs an
Owner intent, injects SQL authority or restores the child's pending state.
Names/workspaces remain visibly synthetic. Control inference is disabled.

| Source-bound run | Result | Source manifest | `result.json` SHA-256 |
| --- | --- | --- | --- |
| `native-pair-acceptance/run-20261020T164433Z-T1QnCl` | FAIL, exit 1: 2 pass / 4 fail / 0 skip, including recovery parent. CLI/tests compilation and vet exit 0 | `a8ec2e746325594d8cf776ee61cf8b2bc68121c5f59bb8a7ad4a0280b183e826` | `4df2dbb16120d2092f7f6c6538d30b8a7bf06f7a65a457ea2584de637e128d9b` |
| `native-pair-acceptance/run-20261020T164746Z-HrZ9tC` | Recovery-only SCOPED_PASS, 4/0/0, all compilation/harness/vet/driver exits 0 | `6fd022f23f02a0ef1a61080857529e5169a6f9bf3b9e7331a97cc1ed3432961f` | `a05237952d9d428e231baf1718494ad42f5e4901ed55a1642be544c9ad8ea56d` |

Both use `07bd265` plus their exact dirty QA inputs, fixed Go 1.27.3 Docker,
network none, read-only source/modules and the locked task build cache. Source
and executed-binary bookends match, and each exact owned container is absent.
The CLI hash is unchanged between these two runs:
`6f9cc4bc800e0e82a882e2a5a634fa27a3aea9c4509d2df672a84bb443a485eb`.
Initial test executable SHA-256 is
`141e902d30af2627afb6b23b1fec514bf6b908a747a913c04329f37a2e8e372b`;
corrected recovery executable is
`4c140dbec46ed260a70b512f11f560d2de7cab2fca16b6a44fd45e36cb892c04`.
Exact recovery container
`cicada-native-pair-run-20261020t164746z-hrz9tc` is independently rechecked absent.

The first run's two passed cases establish:

* Actual App approval and actual Owner signatures read two original zero-right
  Endpoints, retaining equal names, distinct IDs, Windows-style Unicode workspaces,
  harness, offline presence and the selected Node. The result is `SNAPSHOT_ONLY`,
  with capture time and no management/canvas or communication authority.
* An actual discovery GET returning 404 creates no new pending request and sends
  no secret POST. Original Owner/App/Hub identities remain unchanged.

All three recovery subcases initially failed the **driver's** common card
assertion because it required public `Available=true` after App restart.
Capability discovery is transient and recovery intentionally sends no new GET.
Root approved retaining the initial FAIL and moving this requirement to the
successful **new** read case only. No product implementation, cryptographic
verification, identity, card, original-packet or cached-ciphertext expectation
was relaxed. Recovery explicitly records `Available=false` while its verified
`SNAPSHOT_ONLY` result, Node, capture time and cards remain present.

The corrected selector is
`scripts/test-native-pair.sh --endpoint-security-owner-directory-recovery`.
Its three subcases lose a POST before forwarding, lose the authenticated response
after commit, or replace delivery with unsigned HTTP 403. Each observes actual
GET-before-POST ordering, retains the original App pending packet, refuses a new
read while pending, closes the actual App child and restarts the actual Hub with
its persistent database/keys. The new child resumes only its original profile,
without installer material or parent restoration. Recovery resends the exact
original ciphertext; after-forward cases receive the exact original cached
response ciphertext. Read-only DB checks find only the original zero-right
Endpoint and no fabricated SessionBinding, membership, access session or key grant.

The recovery GET is armed as unavailable and is never called: this proves original
recovery does not depend on a fresh capability GET, not that the App actually
received another 404 while pending. Unsigned 403 remains an uncertain transport
outcome until the original authenticated receipt is recovered. Local UNKNOWN
parking is not exercised or called Hub settlement. The two earlier passing cases
were not repeated; **there is no fresh six-event aggregate PASS**. All failures
and corrected results keep their own source and executable hashes.

Root separately checks clean `07bd265`'s existing shared Node RPC:
`native-ux-root/shared-rpc-regression-20261020T1646/result.json`, SHA-256
`67fd9c59edd8c9abe1b10543a127820f98ffa392fb52f26dbe448411c92403c0`.
It passes 6/0/0 (three top-level and three subtests), compile/test exits 0,
network none and unchanged source/test binary. The binary SHA-256 is
`d93412f78477a9b1a62a58eb81f7d783a692969477138a22600bdeac49169e20`.
Both exact owned compile/run containers are absent. Scope is existing exact
packet/IN_PROGRESS recovery, claim-ticket restart without redispatch and three
quarantine regressions; it is separate from actual native Runtime or Windows.

Extended independent Owner-directory privacy/foreign Owner or Node, paging,
cache/proof expiry, old N2 TTL, logout/revocation, wrong-Hub capability and local
UNKNOWN-retention budget cases remain **NOT_RUN** here. Product Hook/MCP context,
native model/queue consumption, Windows GUI/DPAPI/ACL/CJK/DPI, Android, physical
devices, public HTTPS and strict PQTLS remain separate **NOT_RUN** scopes. No
C0/App2 or second-approved-Node matrix is resumed. Final status documents are
post-test edits; tested Go inputs remain unchanged.

## 2026-10-20 product Codex consumer acceptance preparation

The next independent integration gate is being prepared on `task/n2-acceptance`
from `4cf544e8d3ad60c341581480aa09e45e7eed2bb5`, with dirty acceptance-only
changes. This entry records a plan and unexecuted driver, **NOT_RUN**. It does
not extend any preceding protocol, synthetic Hook or Owner-directory PASS.
App's `codex-hook`/`mcp --codex-context` consumer and existing single-plugin
assets are still WIP; Root must integrate their frozen checkpoint before the
new product gate is compiled or executed. The Node-owned original-lease
maintenance requested by Root is also pending delivery.

The parent fixture now separates actual App bootstrap from synthetic wire-Node
approval. The new fixture instead starts a real resident `machine agent
--relay-only`, reads its original private pending code, asks the actual App
Controller child to preview/approve that exact Node fingerprint/epoch, then
restarts the original Node against its persisted state. It never opens the
App's Owner signer or inserts SQL authority. A private canonical loopback
origin fronts the real Hub through the existing fault proxy; Relay SSE is
forwarded without fabricated events. The approved binding and an actual Relay
response establish fixture readiness only, never Endpoint lease readiness.

All child HOME, CODEX_HOME, workspace, Node and MCP state belong to the fresh
fixture. Child environments omit inherited SID, Endpoint, Group, provider and
account credentials. Docker remains network-none with a read-only module
cache and task-locked build cache. The real user Codex installation, resident
development Hub and public deployment remain outside this gate.

| Threat/boundary | Required independent observation | Preparation/result |
| --- | --- | --- |
| Missing context; nonce without ticket; forged ticket; extra caller SID | Actual MCP returns a context refusal, no identity/structured result, no non-liveness Hub request and no MCP session-state change; actual App signed original-Node directory stays empty | `TestN3CodexProductContextRefusesMissingAndForged`, five subcases; **NOT_RUN** |
| MCP restart and old connection nonce | New actual process advertises a fresh nonce; old nonce cannot establish context or change the Owner directory | `TestN3CodexProductMCPRestartRotatesConnectionNonce`; **NOT_RUN**, does not prove replay of a valid ticket |
| Fake or untrusted plugin installation | Actual local marketplace/add commands and actual app-server plugin/list plus hooks/list must identify the installed existing plugin, source, exact enabled hashes and normal trust | `codex_product_cli.py` prepared against the delivered WIP assets, **NOT_RUN**; user config hooks are not a substitute |
| Literal join/peers/leave and ordinary prompts | Actual CLI creates its own native records; one actual PTY/TUI visibly renders human name, cwd and presence; ordinary text, `$skill` and `@plugin` pass through | `TestN3CodexProductInstalledPluginLiteralTUI` and private stdlib driver prepare join/peers only, **NOT_RUN**; leave and ordinary prompts remain separate pending cases. CLI exit 0 or zero static-provider requests alone cannot prove visible success |
| Leave followed by the same SID registering again | The same durable Endpoint is returned as COMPLETED/reused/left; original native record and workspace canary remain; no revival, renewal or switching to another reserved Pair/slot | **NOT_RUN**; compare original native metadata and workspace, not the hash of a legitimately appended transcript |
| Valid ticket replay, changed tool/arguments, cross-context use, fork and process restart | Actual Node issuer/consumer, current connection nonce and original native record govern each call; no parent/last SID fallback or identity from provider arguments | **NOT_RUN**; the new missing/forged guard tests cannot qualify these cases |
| Lost reply, crash and unknown original intent | Retain original operator intent, Node ciphertext/outbox and authenticated result; kill/restart real children; neither unsigned error nor discovery GET settles uncertainty | Existing fault placements reusable; product consumer **NOT_RUN** |
| Late A heartbeat after switching to B | Delay actual A request/reply; freeze its original scope/SID/token/Group/Binding; validate B ticket, cancel and join A worker before installing B, then release A; B and original A files remain exact | Independent real-service fault case **NOT_RUN**; no producer mock or mutable last-SID oracle |
| Named connect before the first MCP tool | Actual resident Node maintains the original Endpoint lease while App approval waits; no model/tool startup is needed and no implicit new Join occurs | Awaiting Hub delivery; **NOT_RUN**; Node/Relay liveness is not this lease |

After the consumer checkpoint is frozen and integrated, the first reproducible
command will be:

```sh
scripts/test-native-pair.sh --codex-product-guards
scripts/test-native-pair.sh --codex-product-cli
```

The driver refuses an unintegrated consumer with exit 2. This mode requires
exactly seven terminal test events (two parent tests and five refusal
subcases), zero skips/failures, all required stage exit codes 0, stable complete
source/binary inventories and confirmed owned-container cleanup. Its result
scope explicitly excludes installed-plugin/CLI acceptance. The separate CLI
mode requires exactly one actual installed-plugin/TUI test event, the reviewed
read-only Codex binary hash, complete plugin-source inventory, actual normal
Hook trust and a matching actual App-signed directory card. It does not qualify
leave, a valid context ticket, Pair Join or heartbeat fault recovery. Its static
provider can return harmless text if a literal leaks through; any such POST
fails the literal gate even when the CLI exits 0. No run directory,
product exit code or artifact hash exists for this preparation yet. Only Go
formatting and diff whitespace inspection have occurred. Windows DPAPI, ACL,
GUI/CJK/DPI, Android, public HTTPS and real model/queue execution stay
**NOT_RUN** pending their own actual execution receipts.

## 2026-10-20 independent consumer guards and marketplace failure

Root integrated App consumer `18868bade057d5da97afe3e8139cc3cafb104afe` and
authorized QA's branch-only fast-forward plus the two disposable gates. QA's
eight uncommitted acceptance files survived that fast-forward byte for byte:
`codex-product-preparation-20261020T173544Z-houn4xuk/ff-app-18868ba.json`,
SHA-256 `945c82b0e11afebdddbda5cf4ea28602e12763dc872d1fb3c904ac44cf9feb71`.
The following runs belong to **dirty `18868ba` plus their individually captured
QA inputs**, not to clean `18868ba`, a future asset fix, or Hub's pending
managed-lease implementation. Evidence prefixes below are under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`.

| Run / result SHA-256 | Result and boundary |
| --- | --- |
| `run-20261020T174654Z-9XuRJy` / `6f9963c43c40bb3ee6964ab8b2c6bc83bfecca183338aed625c19310c6b06461` | Guard FAIL before five refusal subcases: QA compared binding-time fields with unpopulated pre-binding top-level fields. |
| `run-20261020T174732Z-whjAvb` / `5878a7af75d06eb3085dee1f13d5f0e6e5b41d4b0acd3fe4092b4d660f2505a3` | First CLI FAIL at the same preparation assertion; no plugin installation or Host result. |
| `run-20261020T174758Z-VGPrlg` / `ed1fb160aba59a8e6743fed6d35f9c5a09995519e04194f16b038b0bd622b27c` | Guard FAIL after original candidate comparison was fixed: QA incorrectly expected Relay HTTP 200. |
| `run-20261020T174946Z-r2eO5p` / `f27c5cf9af9322aea4ddf1c1e5a0ec709d917487fc4b286d00c5f69a71cf31aa` | Diagnostic FAIL retained actual successful Relay HTTP 204 and subsequent empty claim responses. No product change was needed. |
| `run-20261020T175308Z-VeajCX` / `ffd7af39491e6cde8d8015560721cc6a29f42fbd40e680291e8da9dffcc21e17` | Guards **SCOPED_PASS**, 7/0/0 events, all five required stage exits 0. |
| `run-20261020T175434Z-vLi2LF` / `169ab6d51e84145c47df71bd453564e3e4a0ccd7b1495e83c7110019641c032d` | CLI FAIL: actual 0.163 plugin management rejects `--strict-config`. QA removed runtime-only flags from plugin-management commands; runtime commands retain them. |
| `run-20261020T175547Z-NTuwzB` / `19edf71b00977c2720b24b69ebb67eec6ae764c22bc767c6eed4e49b9810ae0c` | CLI FAIL: QA passed the manifest's directory instead of the repository root. This was a driver path error. |
| `run-20261020T175718Z-eBSGNY` / `d7e21d89b81033656cb29b08e20e52902cfa4faa02132427e215e04ef054b1d6` | CLI **FAIL, product marketplace defect**: adding `/repo` succeeds; installing `cicada@cicada-repo` fails because its source resolves to nonexistent `/repo/cicada`. |

All table runs compiled the actual CLI and acceptance executable and passed
vet. Failed runs have harness exit 1; the guard PASS has harness exit 0. Every
run's complete before/after input and binary inventories match and its exact
owned container is confirmed absent. Historical failures remain unchanged.

The guard PASS source manifest is
`64b596e90cd5ebd590c608db42f694999fdc20cad999ca5034ae7b177875a7a9`.
Its actual CLI SHA-256 is
`a70e692c8b831d5c29e098576309d5a114be63ce8040a7bc9af9a0022ce56b15`;
test executable SHA-256 is
`b69c0aa00d8ba4c9ec346e7eba3d69ccf67e7bd3ebab4e2e0e3bce0ab7a0f868`.
The actual App approves the actual Node's original cryptographic candidate;
actual Owner-signed directory reads before/after contain no Endpoint cards.
Each refused MCP call returns no identity or structured result and changes no
durable MCP session state. A new actual MCP process advertises a new nonce
and rejects the previous connection's nonce. The real resident Node uses a
one-hour empty-queue reconciliation interval in this refusal-only scope so
independent inbox polls cannot be confused with call-triggered HTTP. The CLI
fixture uses one second. Neither establishes an Endpoint heartbeat result.
The later CLI-only diagnostic/dispatch edits are not a fresh full guard run.

Defect **AC-CODEX-01** is assigned to the App/plugin owner and reported to
Root: `.agents/plugins/marketplace.json` uses local source `./cicada`, while
the actual CLI resolves local sources from the repository root and the
existing plugin lives under `.agents/plugins/cicada`. The exact actual
commands are `codex plugin marketplace add /repo` (exit 0) and
`codex plugin add cicada@cicada-repo` (exit 1). QA has not modified the product
manifest, made a substitute directory or installed a user-config Hook/MCP
replacement. The raw owned CLI command/exit/stderr logs are retained only in
the run's private state, separate from public evidence; no App vault, Node
credential or raw environment is exported.

The installed-plugin gate now also prepares a separate actual Host
`cicada_whoami` stage. Its local static provider reads the actual advertised
namespace and nonce, requests that exact tool, and requires a business
not-joined refusal after context verification. A context-required error
cannot pass. Literal join/peers must still make zero provider POSTs; the
Host tool stage expects two static POSTs and no real model. Only selected
configuration equality booleans are observed from actual owned MCP children.
**This stage, actual literal PTY results and environment forwarding are still
NOT_RUN**, because installation has not succeeded. Source review or the
direct-process seven-event guard PASS cannot substitute for Host execution.
Pair cold-connect/lease maintenance, original-intent response-loss recovery,
A/B late heartbeat cancellation, valid ticket replay/fork, leave/re-register
retention and native queue/model execution also remain **NOT_RUN** here.
Windows DPAPI/ACL/GUI/CJK/DPI, Android and public HTTPS require separate actual
receipts and remain **NOT_RUN**.

## 2026-10-20 installed plugin has no actual Hook definitions

Root integrated the formal marketplace/environment asset correction
`c3a1517c7b47864a5d9d9a20c6de9ee444799622`. QA fast-forwarded only its own
branch during Root's exclusive window, preserving all eight candidate files
from `9060b781b040f28595789e5058c2ed1ae6b9d26774f9ccb96333e4657fb724f1`
byte for byte. The verification receipt is `ff-assets-c3a1517.json` in that
candidate's directory, SHA-256
`7e17113a9e15d5d85124f1058c98d4b6159e107d2900b893db0b15d034c3473b`.
Root explicitly retained the earlier seven-event guard PASS without repeating
it for JSON asset changes.

```sh
scripts/test-native-pair.sh --codex-product-cli
```

This actual run is **FAIL**, exit 1:
`run-20261020T180658Z-HsgwHR/result.json`, SHA-256
`6faa7704b61d22a074181dd7510e33a70ebbca5c80701fa8ee35643d5f2028fc`.
It belongs to dirty `c3a1517` with its complete captured QA input inventory.
Version, CLI/test compilation and vet exit 0; harness exits 1. Source and
binary before/after inventories match; the exact owned container is absent.
The reviewed read-only Codex binary remains
`399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215`.

The actual marketplace-add and plugin-add commands now both exit 0. Actual
`plugin/list` reports `cicada@cicada-repo`, installed/enabled true, local
version `0.0.5`, source `/repo/.agents/plugins/cicada`. Actual `hooks/list`
for the owned workspace returns **zero hooks, zero errors and zero warnings**.
The gate stops at `UNEXPECTED_HOOK_DEFINITIONS`. It has not reached normal
Hook trust, the literal PTY flow or a Host MCP tool call. No provider POST or
real model turn occurs. These observations confirm installation, not a usable
identity entry or communication authorization.

Defect **AC-CODEX-02** is assigned to the App/plugin owner and reported to
Root. Read-only official Codex tag source at commit
`83086188ae0614bd882818ff1aa23f3194962012`, `codex-rs/core-plugins/src/loader.rs`
lines 966–978, explicitly returns empty Hook sources/warnings for the portable
AgentPlugin manifest format, while the legacy branch loads plugin hooks.
This agrees with the actual empty Hook inventory: the existing root portable
manifest wins discovery, despite Hook declarations in the compatibility
manifest. QA has not removed a product manifest, created another plugin or
used a user-config Hook to bypass it. The official source is a diagnosis;
only another actual installed-plugin run can qualify the product correction.

Full owned CLI/RPC logs remain in private run state under
`private-codex-diagnostics/001/cli-literal-tui/`, copied before TempDir cleanup.
No App vault, Node credential or raw environment is included. The previous
marketplace product RED is retained. Host environment forwarding is still
**NOT_RUN**; Root requires no invented old-environment negative control.
Normal trust, visible literal output, Host nonce/context/not-joined behavior,
Pair lifecycle faults, native model/queues and Windows physical security/UI
remain **NOT_RUN** pending their respective actual executions.

## 2026-10-20 actual installed plugin PTY and Host MCP context

The actual installed-plugin gate now has **SCOPED_PASS**, one required event,
0 failures and 0 skips. It is separate from the earlier seven-event direct
process guard PASS; these are not a fresh eight-event aggregate. The actual
CLI run tests dirty `1ca85b5cb5d3f0a091210a9bc8ce97f0da39c3b8` plus its captured
QA files. Neither the later Hub checkpoint nor a later QA/document commit
inherits this result without its source qualification.

```sh
scripts/test-native-pair.sh --codex-product-guards
scripts/test-native-pair.sh --codex-product-cli
```

The first command's seven-event result remains
`run-20261020T175308Z-VeajCX/result.json`, SHA-256
`ffd7af39491e6cde8d8015560721cc6a29f42fbd40e680291e8da9dffcc21e17`.
The second command's actual plugin result is
`run-20261020T185125Z-5X7deH/result.json`, SHA-256
`9bc3b9c3b81ca72601889c78f95e6f89dca00825ebcef344ef7167c6836ff669`.
Version, CLI compilation, test compilation, harness and vet all exit 0. The
before/after source and binary inventories match, and the exact owned
container is absent. Source manifest:
`2831bd8bcfbef75dd2866be0a24127e06fea16699f268e9a0c3fa16a9ad40915`.
Executed CLI SHA-256:
`a70e692c8b831d5c29e098576309d5a114be63ce8040a7bc9af9a0022ce56b15`;
test executable:
`22d40ddc3734f8f80dcf8c68b9946ca6e1bd33b20950a41b43ac1c4c501c3817`.
The read-only actual Codex 0.163.0 binary remains
`399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215`.
All execution is inside network-none disposable Docker, with real TCP,
production cryptography, persisted Hub SQLite and a real App Controller child
approving the original real Node. No Control inference runs.

Actual `plugin marketplace add /repo` and `plugin add cicada@cicada-repo`
succeed using the existing single legacy bundle. The actual inventory has
exactly two enabled Hook definitions, source `plugin`, plugin ID
`cicada@cicada-repo`, commands `cicada codex-hook`, and the exact installed
Hook asset hash. The real PTY receives a controlling terminal, executes the
normal visible `2. Trust all and continue` action, and a separate actual
app-server inventory subsequently reports both definitions trusted with
unchanged current hashes. No test writes prepared trusted hashes, uses a
bypass flag or installs a user-config Hook/MCP replacement.

Actual `cicada join` and `cicada peers` then render the human name, complete
original cwd and `Offline at snapshot` in the current terminal viewport.
The literal phase makes **zero provider POSTs**, and TUI exits 0 normally.
The original actual CLI native record and workspace canary survive. The
actual App separately obtains an Owner-signed bounded directory card with
the same name, cwd and offline presence. **This scope does not independently
compare the database SID/Endpoint/BindingEpoch tuple**; that belongs to the
next actual Pair group. It does not assert current communication authority.

The Host stage is separate: a local static Responses provider makes exactly
two POSTs, advertises no real model, and asks the actual installed MCP tool
`mcp__cicada.cicada_whoami` once using the actual advertised unique nonce.
Codex converts the MCP schema's `const` into a single-value `enum`; the driver
reads that exact value. The actual PreToolUse Hook, real Node ticket issuer/
consumer and actual managed MCP reach the business not-joined refusal.
`CODEX_CALL_CONTEXT_REQUIRED`, a Host approval error or missing tool dispatch
cannot pass. Actual child configuration matches all five selected
`CICADA_*` Hub/Node/state values and the owned HOME. Child CODEX_HOME is absent;
that is observation only because context-mode MCP receives native identity
from the verified Node ticket. Node and Hook still use the real owned record
root. Real model turns and native queue consumption are zero.

Only this normal private user policy permits the one Host read tool; it is
not a Cicada grant and changes no transport or Hook trust. Global approval
policy remains `never` for other unapproved tools:

```toml
[plugins."cicada@cicada-repo".mcp_servers.cicada.tools.cicada_whoami]
approval_mode = "approve"
```

The [official plugin MCP policy](https://learn.chatgpt.com/docs/extend/mcp#plugin-provided-mcp-servers)
and App's read-only Codex tag `83086188ae0614bd882818ff1aa23f3194962012`
runtime review identify this ordinary single-tool configuration. Exact policy
artifact SHA-256:
`20d9f30d0b4601aba9d0885c46f6a253367ebab0a7014680b996a448394269ae`.
No broad server approval, additional transport, manual ticket or invented
nonce is supplied.

The run's synthetic private diagnostics are retained outside TempDir under
`/home/zyf/Cicada/.local/state/native-pair-acceptance/run-20261020T185125Z-5X7deH/private-codex-diagnostics/001/`.
Safe artifact hashes: private result
`ca44fa43f2858502405cd9c6c422811a4cb8a88fd06e79c62e7a3975e4cab5b7`;
raw PTY `f42897ffe6e3f190974a0812211f7ac2793533c2aeedbaee9ddb2c4879fc1981`;
rendered viewport
`71a2499d54ee214b20b9dcf73092e1f22e43186b2c46cd643cd6d1912c671881`;
normal-trust/join/peers frames
`e2497481eb811fe814c87f429455215a7f4e4b1bfe3669d8b4d44796cd7e89e5`;
post-trust inventory
`1948543873ec217e50044639c9ce872994e1fb4cc621636d22095fb382fcc202`.
App vaults, Node credentials and raw environments are not copied to evidence.

The product marketplace/portable-format failures above remain unchanged.
The following later focused CLI failures are also retained; all have
compilation/vet 0, stable inputs/binaries and confirmed owned cleanup:

| Run / result SHA-256 | Actual boundary and correction |
| --- | --- |
| `run-20261020T182501Z-IQ72Nq` / `357c83c6ea34481c43633b03031ad21ec1786c59eebf11b5e4042068d05dfc41` | Two real Hook definitions load; naive ANSI removal loses cursor-positioned spaces, so the driver never chooses the visible normal trust control. |
| `run-20261020T182906Z-DYuEt8` / `c6dabe743c533ae961529b4d895b91c6caf4b8a4a9fc31d5db240cacd63b3394` | Bounded VT reconstruction identifies the normal control; input remains at the menu. No persisted trust or literal PASS claimed. |
| `run-20261020T183209Z-zqRJFg` / `23940ee530ea00f6c3be93a97aa4dc81e6ac6eee95e7a57dffafa4d544f16e0d` | Waiting for terminal input initialization alone does not fix missing controlling-terminal plumbing. |
| `run-20261020T183550Z-kcgH7V` / `d6794a6f4c01efeb64ed53a23b7e7c8344eedc2ff664b46c81c3a9bcf2db633d` | Real foreground PTY, normal trust and visible join succeed; bulk peers+Enter remains in the composer as a paste burst. The driver switches to ordinary paced keys and separate Enter. |
| `run-20261020T184015Z-l5YEmk` / `a1f61f62b1cb661f74c4679a8192fedb238e0b663cec9011ef3dfa0ad61eb6a3` | Full literal phase exits 0 with provider POST count 0 and post-trust hashes verified; Host stage stops because the driver initially only understood `const`, while the actual SDK advertises the same nonce as a singleton `enum`. |
| `run-20261020T184403Z-YLCK7K` / `47f17a19ecba9b534d1e9c2114f08d5f99449717ebcbe6b10ae12022a54a7543` | Actual Host refuses an unapproved MCP tool under global Never; it is not a Cicada not-joined/context result. The final run uses only the normal exact read-tool policy above. |

Actual successful literal results currently appear as `Blocked by hook`
warnings and the body is duplicated by reason/systemMessage. This observed UX
limitation is reported to App/Root; it is not a native picker or physical GUI
PASS. Names/cwd/presence remain visible and do not imply authority.

After sealing all eight QA paths, including both untracked source files, QA
fast-forwarded its own branch to Hub checkpoint
`92ad9f41a714336c8605e39e3c070b002741348f` in Root's exclusive window with all
eight files byte-identical. Receipt `ff-managed-92ad9f4.json` SHA-256:
`aac8133228744de45c75395bb0d7a2d2192d1ab59b1dc1f4b71dfb3d284ecbeb`.
Root's separate clean-92ad shared-RPC regression is 6/0/0, compile/test 0,
unchanged clean source/binary, network none and both owned containers absent:
`native-ux-root/shared-rpc-regression-20261020T1850/result.json`, SHA-256
`b4289ced7e684139658ef747d24bf98790fada4e0467bdde5c43ffcf8b3e3d3e`;
binary `751391bc542dc89dd001af56f773464777e4927aa42f19afe90c7a906f4a7933`.
It is not the actual cold-lease gate. The original default-five-minute cold
wait, first joined MCP tool, read-only SID/Endpoint/BindingEpoch mapping,
Node restart/revocation, A/B late heartbeat and original-intent faults remain
**NOT_RUN** here, pending the next isolated group. Windows DPAPI/ACL/GUI,
CJK/DPI, Android, real model/queue and public deployment remain **NOT_RUN**.
The five current-status documents are post-run edits, not retested inputs.

## 2026-10-20 actual default-five-minute cold lease and current revocation

The strict cold gate is **SCOPED_PASS**, one required event with zero failures
or skips. Run `run-20261020T193448Z-NXDrR3/result.json` SHA-256:
`06beeb9dd944cdaf19a8c60a39725ea730b12dda95a31684d744512b6958bd5c`.
Version, CLI compilation, test compilation, harness and vet each exit **0**;
source and executed binaries match before/after, and the exact owned container
is absent. Original cold interval starts at `2026-10-20T19:35:41.407315976Z`;
the later original cache deadline is `2026-10-20T19:40:29.987521521Z`. The first
tool starts only after 300 seconds, crossing both original deadlines plus ten
seconds; the later 352-second log includes the Host/revocation checks.

| Artifact | SHA-256 |
| --- | --- |
| Complete input manifest, 1,415 files | `929e5e9bc1d3b66cf80fe96024e0a27b58f1d451a37b699b247e7d3ce5ffffaa` |
| Identical before/after source JSON | `8d1eb861b6d33e2697d52637576332914f99209dd666afac2a52b104e0b8922e` |
| Read-only actual Codex 0.163.0 | `399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215` |
| Executed CLI, 37,126,662 bytes | `e83e27930ded1010ac8e89055be6b285ade6fc689f774d9e8720c663a2d25454` |
| Executed test binary, 23,011,311 bytes | `64c737aa8b620bc379492299263740d94630b97993156e882d1c1e3ba7f5b8ca` |
| Actual join/peers viewport frames | `d9d6249094ab29d113eab9a4e1d021def8cd65251c31c1ad027068d173923c6a` |
| First actual Host phase result | `777a902a3daa9830b66a51e2d7bdb848c26c323e6846f914d68ffe46ee526c8b` |
| Current revoked Host phase result | `436b6aa1ae4c6a13c16e7ec91383721da3e14a9c9623f1e3fdd670de35630ad0` |
| Revoked provider request with one exact current output | `e0495b7f2e64068a0eac042a13c5e68810a6b307a4788ca2894029b470b943ef` |
| Post-run independent private check | `c4b6bf0b9a5ae434c911e36976f46e4bebb4c376c10d1f80ed258376c1e79263` |

Private CLI diagnostics are retained only under the owned run's
`private-cold-diagnostics` directory in task state, without App vaults, Node
credentials or raw environment exports. The post-run verification JSON is a
separate immutable check, not retroactively added to the gate receipt's hashes.
A single cold-interval Docker sample reports 3.16% CPU, 76.98 MiB and 59 PIDs;
`cold-resource-sample.json` SHA-256
`55048e9592dcd714e260d05c4d39bd4e954dcf3febffd1f98c2b731617bff435`.
It is one instantaneous sample, not a long-run idle/resource benchmark.


Reproduction uses `scripts/test-native-pair.sh --codex-product-cold` from the
QA task branch, not a shared Hub or public deployment. The strict single-event
scope uses the existing installed plugin, actual Codex 0.163.0, actual App Core
child, real resident Node, PQ crypto, loopback TCP and persistent SQLite inside
one disposable network-none Docker container. The pinned builder and read-only
module cache/CLI mounts and exclusive task build cache remain as in the prior
consumer gate. This does not start a real model or add another product daemon.

The source is `fcea942b75ae2ee197053026e9d5c1b5c8866f59` plus four dirty QA
acceptance/driver paths. The later checkpoint docs are post-test edits. Never
attribute this dirty run solely to fcea942 or upgrade the earlier guards/basic
CLI results to this source. The old source's duplicated literal-body observation
remains unchanged. New actual current-viewport join and peers title counts are
one each, with the complete name/cwd and snapshot presence after the relevant
heading; SDK's `Blocked by hook` warning heading remains a UX limitation.

The actual App exports its public Owner identity. The test verifies its complete
displayed key ID/fingerprint and uses only the existing public
`machine trust-owner-key` channel against the original stopped Node/state/writer
root. The original Node restarts with its approved binding and keys. This is a
manual FB-03 prerequisite, not automatic Owner-key delivery. The parent opens no
App vault, owns no Owner signer and injects no SQL authority.

The actual App first bootstraps WAITING_JOIN. A normally trusted installed-plugin
TUI creates real Thread A; actual CLI creates distinct Thread B. Both original
Threads enter named literal connect with explicit A/B slots and zero provider
POSTs. A fresh authenticated App Pair snapshot independently matches the actual
native/cache SID, Endpoint, binding ID and epoch for each candidate before
consent. App then separately reviews and approves A and B to ACTIVE. No Pair,
slot, native record, candidate key or grant is synthesized by the driver.

Before the first business MCP tool, the test restarts the same Node within its
known lease and waits in real wall time past the later of both original default
five-minute cache deadlines plus ten seconds. No shortened lease or test clock
is used. During that interval, actual `/v2/fabric/heartbeat` responses advance
both original frozen managed records; join/op/frozen identity remains unchanged,
both scope files stay byte-identical and no `/v2/fabric/whoami` is issued. Relay
liveness is not counted as an Endpoint lease. The first real resumed-Thread Host
whoami then uses its newly advertised connection nonce, real Hook and Node ticket,
and must match the complete original public actor tuple through the current Hub.

Finally the actual App revokes the original Pair; both Node lease records must
be STOPPED after the keeper interval. A new actual Host invocation must return
exactly one current call's explicit Hub 401/403 refusal, with no context or Host
approval failure. The original native files and workspace canary must survive.
The static provider dispatch is a transport fixture, not native conversation,
queue consumption or model reasoning evidence.

The first complete attempt remains FAIL, one failed event and no skips:
`run-20261020T192639Z-6pZOJ3/result.json`, SHA-256
`931abd21a49bcdef0b1c988ebd45612e8eb1d0703c1346b6dfb991f8ba363224`.
Compilation/version/vet all exit 0, harness exits 1, inputs/binaries are stable
and the owned container is absent. It reaches the cold interval, first actual
whoami, App revoke and both STOPPED markers. The final parser fails because the
QA static provider reused a call ID across resumed-Thread stages: the actual
request contains a historical successful result and the current precise
`Cicada Hub 403 Forbidden: fabric permission denied`. Root and QA independently
read that owned output. The correction gives each phase its own call/item/
response ID, retains exact current-ID filtering and the strict 401/403 condition,
and repeats the entire original cold gate. The failed receipt is never rewritten.

A/B late-heartbeat switching/cancellation, ticket replay/fork/expiry, original
operator-intent response-loss recovery, literal Leave and same-SID non-revival,
App-process closure during the cold interval, real native ASK/Reply/model/queue,
automatic wake, Windows DPAPI/ACL/GUI, physical CJK/DPI, Android and public HTTPS
remain NOT_RUN in this scope. Broader C0.1 installation/registration remains
frozen. There is no public deployment update or uninstall implementation here.

Root's separate clean-92ad standard client interop result remains independently
attributed: `native-ux-root/client-interop-final-92ad-20261020T1900/result.json`,
SHA-256 `629a69b3f8f4f79830ab7dc4339360a2aae3671bdf1e43cdf61efbda2e689ffa`,
exit 0. QA independently counts seven lowercase terminal test events in its
`test.log`, 7/0/0, SHA-256
`11937b6f69af2b18b5500055413f5b6b82703708d1471283dc6c319b48cb04c0`.
The exact three containers, two images and scratch directory are absent in
`cleanup.json`, SHA-256
`7186ffd961a1f02663c87b4dda65d4186a14272fa1e726d32ee36d5d0e4e5d4e`.
This is the existing smoke/headless/Owner/recovery fixture, not the cold gate,
real native model/queue consumption, or an aggregate with these QA events.

## 2026-10-20 consolidated user acceptance batch — NOT_RUN

This is one ordered manual batch for the later user handoff. No step below
has been executed by this record. Use the exact package/source/hash identified
by Root's delivery receipt and keep existing Hub, Owner, Node, App profile and
Codex account identities. Do not uninstall, clear state, copy a signing key,
replace a pin or paste internal SID/Endpoint/Group/token/ticket values to make a
step work. Record each observation as PASS, FAIL or NOT_RUN, with the package
hash and platform; keep private fields out of shared screenshots/logs.

1. Install/update the trusted reviewed package using its documented entry
   point and selected user-data root. Confirm the displayed source/version
   against the receipt. FB-09 is partial: new App/Node/MCP roots and installer
   prefix are implemented; unified Hub/workspace/cache defaults and migration
   are pending. Do not call this a completed clean-install/migration test.
2. Open the native App. Before login, check that private Owner/Node/workspace
   details are hidden. Unlock the original profile and verify Chinese text,
   actual display scaling, navigation, useful errors and copy of public fields.
   A second App window must recover the same existing profile safely. Windows
   DPAPI, ACL and GUI remain NOT_RUN until separately executed and evidenced.
3. Select the original Node in App; verify its actual candidate and approve
   only the intended current binding. For the present Pair implementation,
   FB-03 still requires the existing independent public Owner pin channel:
   actual App public export, independently checked full displayed key ID and
   full fingerprint, then the documented `machine trust-owner-key` command
   against the original stopped Node/state/writer root. Resume that Node.
   This manual prerequisite is not automatic Owner-key delivery or completed
   automatic onboarding. Do not create another Owner key or use shortened IDs.
4. Create two genuine native Codex Threads in their intended original
   workspaces. In each, enter `cicada join "<distinct human name>"`; then
   `cicada peers`. Use the normal plugin trust control. Check one complete
   visible result with human name, full workspace, Node and snapshot presence.
   App's authenticated own-Node directory must show the same original cards.
   Registration alone conveys zero Group/Network/peer/execution rights.
   A remaining SDK `Blocked by hook` heading is a presentation limitation;
   do not mistake a generic blocked/error message for successful registration.
5. In App prepare and create one named Pair, initially WAITING_JOIN. In the
   original two Threads enter `cicada connect "<Pair name>" A` and
   `cicada connect "<Pair name>" B`. App refresh must show the matching actual
   names/workspaces and separate original candidates. Review and confirm each
   slot separately; the first consent alone cannot authorize communication.
   Only a fresh ACTIVE result after both consents permits the next step.
6. Use the installed `$cicada-network` skill with the peer's human name for an ASK and
   the original request's Reply, then reverse direction. Resolve ambiguity
   through the documented explicit selection; do not copy internal identities
   into environment variables or tool arguments. Check request/answer exactly
   once and record whether wake was automatic or manually resumed. Model
   availability, native queue consumption and automatic wake need their own
   real evidence; a local static tool-dispatch test does not prove them.
7. Close App; leave both original Threads idle beyond the original default
   five-minute lease. Restart the original Node within its last known valid
   lease, preserving state. Resume the same Threads, repeat the by-name ASK/
   Reply and reopen App for current Hub status. Explicitly revoke the Pair
   and verify the next attempted communication is denied under the current
   Guard. Closing App alone must not manufacture a revoke or new authority.
8. Perform Leave last, using the original Thread's documented `cicada leave`
   command. Refresh its directory status and try the documented registration
   again in that same original Thread. It must not silently revive the LEFT
   identity or obtain rights. Confirm the original native conversation file
   and workspace remain available; do not delete or recreate either to obtain
   a passing result. Record any uncertain outcome and recover the original
   operation rather than issuing a fresh identity/request.

Encrypted PKCS#8 import, total Owner-key-loss recovery, uninstall scripts,
full uninstall/reinstall, Android and public HTTPS are outside this batch's
executed scope and remain NOT_RUN. This batch does not authorize modifying a
public deployment or running paid model turns; Root/user controls execution.

## 2026-10-22 user-reported fcea942 package and native App checks

The user began physical-machine acceptance of the delivered package identified
by code source `fcea942b75ae2ee197053026e9d5c1b5c8866f59` and reported
“全部正常” (all normal). This entry records **USER_REPORTED_PASS** for the
observations below. QA did not independently repeat these checks, inspect the
running binaries or verify the installed package hash in this batch. The
package code source remains distinct from the later `6582b61` acceptance and
documentation checkpoint; this report is not a new build or automated gate.

Hub and Node updates receive an overall **USER_REPORTED_PASS** from the same
feedback. No post-update actual health JSON was supplied, so this entry does
not independently establish their running revisions, current health or fresh
authorized heartbeat state.

| Native App observation | Reported result and scope |
| --- | --- |
| Original configuration recovery | **USER_REPORTED_PASS** — the updated App restores the original configuration. No identity migration or replacement-key behavior is inferred. |
| Login privacy | **USER_REPORTED_PASS** — the login-first privacy check is reported normal. This is user observation, not an independent cross-account or stale-session adversarial test. |
| Section navigation | **USER_REPORTED_PASS** — the user explicitly lists `Overview`, `Devices`, `Sessions & communication`, `Identity & access` and `Settings`. |
| Chinese text and scaling | **USER_REPORTED_PASS** — Chinese rendering and scaling are reported normal on the user's machine. This does not cover every font, DPI setting or Windows environment. |
| Selection and copy | **USER_REPORTED_PASS** — selection/copy is reported normal. No clipboard secrecy or private-key/token disclosure attack test is claimed. |
| Opening the App again | **USER_REPORTED_PASS** — reopening is reported normal. Simultaneous second-instance behavior and corrupt/busy storage recovery were not independently exercised here. |

The supplied UI text includes the cards `gpu1-ab-test`, `GPU1 Ubuntu Node` and
`Hub verified`. These are user-supplied display observations, not a substitute
for authenticated current Hub/Node health evidence or independent pin checks.
The historical Chinese-rendering **USER_REPORTED_FAIL** and earlier profile/
second-instance observations retain their original package/source attribution;
this later positive report does not rewrite those records.

Windows DPAPI and ACL attack tests remain **NOT_RUN**. The subsequent new-plugin,
Pair and cold-recovery user batch has not yet run; its real native ASK/Reply,
queue consumption, automatic wake, revocation and Leave results remain
**NOT_RUN in this user batch**. Earlier source-bound independent Linux cold-gate
and other validation results remain separate. No development, automated test,
deployment or public-operation action was performed to add this record.

## 2026-10-22 installed-plugin MCP startup failure and isolated launcher check

After installing the fcea942 plugin, the user reports `/mcp` showing Cicada
failed with zero tools: **USER_REPORTED_FAIL** for actual MCP startup. The
earlier six native App observations remain separately attributed; they do not
establish plugin startup. The original fcea942 binaries and package are not
rebuilt or replaced by this investigation.

QA independently reads only Cicada MCP startup warnings from the existing
Codex log database. The exact error is:

```text
MCP server startup failed server_name="cicada" error=No such file or directory (os error 2)
```

Read-only process checks find that the existing shared app-server PATH includes
`/home/zyf/.local/bin`, but cannot resolve `cicada`; all five selected Cicada
configuration variables are absent. The new TUI resolves the executable and
has those variables. The existing plugin manifest uses bare `command: cicada`.
These observations support an executable lookup failure in the spawning
process, before MCP initialization. The diagnostic exports only the startup
error and configuration-presence booleans, not raw environments, conversation
contents, credentials or queue data. Diagnostic receipt:
`native-pair-acceptance/mcp-startup-readonly-20261022-tmkoz2gt/result.json`,
SHA-256 `85f41d51d505a6c7d1094e06d6ef0a713f75bff74ac3d36184b648f0c318e658`.

App freezes an external POSIX launcher candidate, **not yet applied** to the
real user environment. Its proposed existing-PATH entry is
`~/.local/bin/cicada` pointing to private `~/.cicada/bin/cicada`. Only the exact
`mcp` and `codex-hook` subcommands receive the original five public deployment
configuration values; the launcher then execs the existing absolute fcea942
executable with unchanged arguments. Other subcommands pass through. It adds
no SID, token, signing key or authority and changes no plugin/Hook definition
or shared daemon. Merely fixing PATH is insufficient evidence: current product
source can fall back to hostname, default Hub and default state when configuration
is absent. The actual child configuration must also match.

The frozen candidate and installation scheme are external artifacts under
`/home/zyf/.cicada/acceptance/codex-context-checks/startup-review-20261022T141952Z/`:

| Artifact | SHA-256 |
| --- | --- |
| `cicada-launcher.sh`, exact tested candidate | `9b0ffc53fbdd68f81cd5dc489f9c36848c109da2bb356db2b381048d5e06567f` |
| `launcher-candidate.json`, proposed entry/configuration/install scheme | `de7975398e7a3ca265415ae0c44bc4b9515f181872d53ddc28ba18ab7120896a` |
| `apply-launcher.py`, external user-run helper; not executed | `133fdf28518f0d67bbc5a14fe6b8cbfc5892e1c71fb5e9fc656e6d669aec6929` |

Root statically reviews the external `apply-launcher.py` helper, which prepares
the two proposed entries for user-controlled application. Only AST/compile
checks are reported for that helper; it is not executed in this checkpoint and
is not a product installer or a rebuild of the fcea942 package.

One disposable `--network none` fixture tests only direct stdio startup,
`initialize` and `tools/list`: **SCOPED_PASS**, exit **0**. The parent PATH
already includes the empty entry directory and lacks all five variables.
Without the entry, process creation returns ENOENT (errno 2), matching the
observed startup error. Adding only the exact candidate and symlink in a fresh
owned HOME starts the same read-only fcea942 executable at its fixed absolute
path. Initialization negotiates `2025-06-18`; the server lists 71 tools, all
requiring verified context. The actual MCP child's executable, original argv
and all five configuration values match; only match booleans are exported.
The child exits 0 with empty stderr and creates zero product state files.

The container mounts no real HOME, Node state, credentials or sockets. Its
absolute deployment-state paths refer only to the empty owned fixture HOME.
No Hub or Node process, `tools/call`, Join, business operation or model turn is
started. Inputs remain byte-identical and the exact owned container is absent.
This does not exercise the actual Codex managed-MCP reconnection or Hook shell.

Fixture evidence is under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/mcp-launcher-20261022-g1yddn68/`:

| Artifact | SHA-256 |
| --- | --- |
| `result.json`, bounded result/cleanup/input identity | `08e0056b0d5c12014240d481b59e04bc620ee186a4f769d9485978c868f8a24d` |
| `fixture-result.json`, exact negative and positive observations | `916673f1ea284c650dac75c516d778181835cc802d06dc65957e6940f70826ad` |
| `fixture.py`, external stdlib orchestration | `1e0b78edc22ee4e61d9763d04f72f3d60aa8b1e7b75e3ac272e18938b1ba9003` |
| `command.json`, exact Docker invocation; repeat only with a fresh owned HOME/state | `14a458110eda0b6522ba88bc60eaf21b5f80858357075cdecb0dd20fd7093ef4` |
| Existing executed fcea942 CLI, before and after | `e5c36ff8be9031964fdb21cc9630d7aa9c0efe3069dc84c8ed9dc607b388c27f` |

Applying the candidate to the user's environment is **NOT_RUN** at this
checkpoint. Actual Codex reconnection and the user's `cicada help` confirmation
of Hook lookup remain **NOT_RUN**. Context proofs, authorization, communication,
Pair/cold recovery, native queue/model consumption and platform security are not
validated by configuration initialization. No real daemon/configuration/state
change or deployment is performed by QA; no installation helper is added to
the repository.

## 2026-10-22 persistent Codex daemon three-stage acceptance

**SCOPED_PASS**, one required test event, 1/0/0. Reproduce with matching CLI
notices and a fresh disposable fixture:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/codex-startup-fix/licenses-x4gog722 scripts/test-native-pair.sh --codex-product-three-stage
```

Run `run-20261022T161017Z-aTS6FI/result.json` SHA-256
`430144cd8930e31f2caa7b2308541ed8b3fee0042528373d92433401179b88c1`.
Version, CLI/test compilation, harness and vet each exit 0; source and binaries
remain identical before/after, and the exact owned container is absent. The
source is `7bbcb84dfb59a7332b86c5c00b1b7515634f0361` plus dirty QA inputs,
not a clean-build attribution. These three documentation updates are post-test.

The actual Codex 0.163.0 managed daemon starts before component installation,
with all five terminal Cicada deployment variables absent. A genuine native
TUI initializes it before any observer; its PID/start time remain unchanged.
The already installed same-ID plugin is updated only through normal marketplace
remove/add and plugin add, then the new Hook receives normal TUI trust.
**No `config/mcpServer/reload` or other manual reload is used.** The installed
MCP/Hook assets select the absolute executable/root. Actual current MCP discovery
has tools_count > 0 and no tools_error; literal register/peers execute through
the real Hook/Node and the actual App signs the matching zero-right directory.
The static provider sentinel receives zero POSTs; no real model is called.

Installation preserves the existing owned root's 0755 mode, canary and original
Node state. Node absence and explicit stop produce a visible NODE_NOT_RUNNING;
the plugin does not start the Node. Only the driver's explicit operator action
starts/restarts the original approved Node. Live discovery proves the same
complete public connection pin after restart, with a newly verified instance,
and the original native Thread resumes successfully. Resources, real crypto,
TCP and persistent databases are confined to disposable network-none Docker;
no real HOME, resident Node state or public deployment is touched.

| Evidence | SHA-256 |
| --- | --- |
| Complete source input manifest | `a66606d5787e553b94d83d826a120fae4f4bd761bd6e2fa4d51f4a58d25c49a9` |
| Identical before/after source JSON | `b885a31ad5ad7cc9a9336d4c17f1922b3c9ca755d18bc2d61b8f31e1c2641592` |
| Executed CLI, 37,289,246 bytes | `0f6ea00dc1148a98393badc81c0758fb299f67bbfa1d4e8ed768edcdcc9e1d5c` |
| Executed test, 23,070,152 bytes | `47ed934a2b602c91a31216f656b5decf7989f41de2195ef6beccfe091762f8af` |
| Actual Codex binary, including its managed package copy | `399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215` |
| Private final child result | `7196160d1b86c987ed35adca1c3eebc1124bf73a9c9bf1f39df468c0e41785ac` |
| Post-run current-viewport/trust/metadata check | `3d0037274a457ceab22ee24b157602733fc516b2d8b981f361464b0a5febe8bd` |
| Separate attempt-receipt index; no aggregate across sources | `1ce8430aac0b5e2cf83727d565ec192575f0138202cab9e5dc1096cf1838e0d2` |

The last two JSON files are separate post-run checks under this run's evidence
directory. Complete read-only Codex package and CLI-license inventories are in
the original result/source receipts. Earlier failures remain immutable. In
particular, `ARHN1u` observes `(vscode, synthetic-three-stage)` after the QA
observer initialized the daemon first; that is a fixture-origin fact. The
separate genuine-TUI-first `I8KCar` observes `(vscode, codex-tui)` and is rejected
by the old source whitelist: result SHA-256
`96c4c563513c342c7774f358b34b1d6ceed1aefe172d95bfc23a73028700e2c3`,
metadata-only check `e29e99280650325954d17f44dadf258485ce8495ceb5642c8cacae4d6e72826f`.
That compatibility defect is fixed by the exact source/originator combination
at `7bbcb84`; generic vscode and structured subagents remain refused, with
record/UID/mode/inode/SID/cwd/context proof requirements unchanged.

The initial idle TUI is visibly initialized, then boundedly terminated by the
fixture with `test_initiated_termination: true`; graceful_TUI_exit is NOT_RUN.
No unseen result is accepted. Pair/five-minute cold, multi-Node ambiguity,
per-call ticket business dispatch, cross-pin cache/pending/outbox faults, real
model/queue consumption, automatic wake, Windows DPAPI/ACL/GUI, Android and
public HTTPS remain NOT_RUN in this scope. Earlier gates retain their own
sources. The temporary launcher/helper remains unapplied; this acceptance does
not install or alter anything in the user's real environment.

## 2026-10-22 user MCP recovery and original UX-A registration

Root identifies the deployed code as `7bbcb84`; `5f29484` is the documentation/
acceptance checkpoint. This entry adds user observations and attributed read-only
diagnostics, not a rebuilt package or another independent business gate. It records
7bb behavior without adopting per-record chmod or per-Thread Pair approval as
the future permission model.

| Observation | Attribution and limit |
| --- | --- |
| MCP initially unknown, zero tools | **USER_REPORTED_FAIL**. QA's selected logs only report no exact ready client; that message alone does not establish the cause. |
| Local discovery permission failure | **Root independent read-only verification, relayed to QA**: the exact installed binary's initialize/list exits 1 with LOCAL_NODE_DISCOVERY_INVALID; `/home/zyf/Cicada` is 0775. QA does not repeat that probe. |
| MCP connected, 71 tools | **USER_REPORTED_PASS — startup only**, after the user's single-directory chmod. Root separately reports 0755 and initialize/list exit 0, 71 tools, empty stderr. Tool discovery grants no business authority. |
| UserPromptSubmit disabled, then restored | Root reads the specific Cicada UserPromptSubmit enabled=false override. The user reports enabling the Hook through normal controls and retries the literal command in the original A Thread; it is then intercepted and refused for unverified native evidence. The earlier generic PreToolUse refusal does not establish that the SID was wrong. |
| Native-record permission blocker | **QA independent read-only metadata** for the designated A workspace: source/originator `(vscode, codex-tui)`, original id/session_id/cwd and inode match, with record mode 0664 and record-tree directories 0775. No message body, raw tool payload, nonce or ticket is exported. These group-writable paths violate the existing record guard. |
| Original A registers as UX-A | **USER_REPORTED_PASS — registration only** after the user corrects the identified unsafe paths and retries in the same original Thread. The reported output is “This Thread is registered”, with UX-A and the correct cwd. QA does not independently rerun registration or assert post-correction modes. |
| Current permissions and original writer | **Root independent read-only receipt**: the original A record and five record-tree directories have matching UID, no symlink and no mode bits 0022; the actual Codex daemon PID 10791 still has Umask 0002. Safe current paths do not establish safe creation for the next Thread. |

The external layered startup receipt is
`native-pair-acceptance/mcp-permission-recovery-20261022-a8t7e0zn/result.json`,
SHA-256 `7d98f576c34a5f055f6ebb0a41da068da78c31048903312fa6cbb45a144ef4a9`;
its earlier limited-log source is
`mcp-log-status-20261022-_0fvhkzx/result.json`, SHA-256
`2a75fd390de92423e4aa96698fa59026673258f0ad419e4ab26d17af88712a89`.
Root's current metadata/writer receipt is
`local-permission-feedback-20261022-gwijg5up/result.json`, SHA-256
`3a839c12ef3713c2d4b09cf20aedae68217f15c9444d3c2240118e342f0f6bdd`.
QA verifies that receipt hash without repeating Root's probes or freshly
verifying the installed binary. QA changes no real permissions, Hook
configuration, daemon or product state while recording this batch.

No automatic preparation, future-Thread behavior or new permission model is
implemented or tested by this record. UX-A registration establishes neither a
Node/Network business grant nor successful communication. New B registration,
new A/B peers/App-directory matching, communication, App-exit persistence,
revocation, native queue/model consumption and platform security remain
**NOT_RUN in this user batch**. Node/Network authorization and default local
communication are pending Root's review, not validated here. Historical Pair
and other independent results retain their original scopes; no new CLI/API/script
or automatic repair is claimed here.

## 2026-10-22 local-domain matrix and actual-daemon driver preparation

Preparation source: dirty `96dcbe0` plus the acceptance/driver/plan changes in
this checkpoint. This is **COMPILE_AND_VET_ONLY**, not a new business or native
Runtime PASS. The [minimum threat/acceptance matrix](native-app-plan.md#nodeusernetwork-policy-acceptance-preparation)
records the Node/user/Network target, trusted same-UID boundary and actual
other-UID requirement, independent App/account and delegation lifetimes,
immediate current-authority revocation, original-packet recovery and strict
legacy-Pair compatibility. Root has approved the direction; frozen DTOs and
production implementation are still pending.

The existing three-stage driver is parameterized for an original official
Codex daemon writer umask `0002` or `0077`, and one or two successive new native
Threads. Only preparation policy `none` is executable: no QA record chmod/ACL
repair or daemon restart is substituted for a product policy. It verifies the
actual daemon `/proc` Umask and unchanged PID/start ticks at checkpoints, exact
native SID/cwd/inode metadata and distinct A/B names, normal Hook trust, zero
literal provider POSTs and the actual App-signed zero-right directory. These
are prepared assertions, **not observations from an executed new gate**.
The default remains `0077`/one Thread; the earlier `aTS6FI` runtime receipt is
not reattributed to this code or to the new `0002`/A+B case.

Checks actually executed in owned network-none, read-only-source Docker with
the pinned Go 1.27.3 image and read-only shared module cache:

| Check | Actual result |
| --- | --- |
| `go version`; `go test -mod=readonly -c -o /out/n3.test ./acceptance/n3`; `go vet -mod=readonly ./acceptance/n3` | All exit 0; no test case or native Runtime executed. Exact command arrays are retained in the receipt directory. |
| Source inventory before/after compile and vet | Identical; HEAD remains `96dcbe0`, dirty=true; all three owned containers absent afterward. |
| Bash syntax, Python AST and `git diff --check` | Exit 0. |
| Illegal daemon umask, illegal fresh-Thread count, daemon parameters in another mode | Each exits 2 before resources start. |
| Unfrozen preparation policy | Exits 125 with NOT_RUN before resources start. This expected refusal is not a business PASS. |

External evidence is under
`native-pair-acceptance/domain-preparation-20261022-l_gp334g/`:

| Artifact | SHA-256 |
| --- | --- |
| `compile-result.json` | `d6a7008e249926e65b531dd4d8c226ff6a939baea49194458ffe0a3881a39bbd` |
| Identical `source-before.json` / `source-after.json` | `5510144be2de83435dc486042e3f507926c5a54d35248169517fa01df4234044` |
| Complete compile input manifest | `78a98d973dbf2711a2c8a3b087bd354f8cf2bb378c8afd71756356b33ac9fd3e` |
| Compiled, unexecuted `n3.test`, 23,071,432 bytes | `b261a9305d6e4a57077dd01b67565f282cf0e542699635810f6d3f3113c9c959` |

The plan provides the parameterized reproduction command. Execute it only on
the intended frozen implementation; a missing policy or the current strict
record guard cannot be treated as acceptance of the new domain. Actual new
`0002` A/B registration, one-time domain approval, same-domain Host ASK/Reply,
other-UID IPC/key/context/signing probes, App-close/short-login-TTL continuity,
expiry/revoke, cross-domain refusals, original-packet faults and legacy-Pair
migration all remain **NOT_RUN**. Windows DPAPI, ACL and physical GUI, Android,
real model/native queue/automatic wake and public HTTPS remain **NOT_RUN**.
No real user record, process, permission, state or deployment is modified.

## 2026-10-22 actual other-UID private-file and Node IPC boundary

**SCOPED_PASS — OS boundary only**, independently executed on dirty
`18c54a6b3f5d4a595a8185774163efb3e2f764d3` plus this checkpoint's QA fixtures,
runner and plan inputs. No new local-domain backend/profile is implemented on
that source. This run does not accept domain context proofs or signing, and does
not relax legacy native-record mode checks or Pair authority.

Reproduce from the intended source with the existing pinned offline prerequisites:

```sh
scripts/test-native-pair.sh --codex-product-other-uid
```

The actual App Core creates and approves the original real Node through its own
Owner action. Real PQ, loopback TCP and persistent owned databases run in a
disposable network-none Docker container with read-only source/module mounts,
cap-drop ALL and no-new-privileges. The host checks the exact task label, original
64-hex container ID, pinned image and isolation settings. It then runs the real
probe first as UID/GID 1000, then as UID 1001 with the same GID 1000 using
`docker exec`; the Go fixture has no Docker socket, root or setuid capability.

| Observation | Actual result |
| --- | --- |
| Original owner precondition | UID 1000 successfully opens the original `node-control-state.json` and `identity.json` without reading bytes, and connects to the live production Node Join/context socket in its container-private runtime directory. Original ownership/type and absence of substituted symlinks are checked. |
| Other-UID operations | UID 1001/GID 1000 receives errno 13, EACCES, for both file opens and the actual Unix-socket connect. Missing targets, refused/offline sockets or a successful open/connect fail the gate. |
| Actual process security | Both probes observe CapEff=0 and NoNewPrivs=1. No key bytes are read and no application IPC payload is sent. |
| Original product state | Original Node binding, key epoch/fingerprint and actual App-signed empty Endpoint directory remain unchanged; no Thread, Pair or business grant is created. |
| Required stages | version, compile-cli, compile-tests, harness, other-uid-host and vet all exit 0; exactly 1 parent test passes, 0 fail/skip. Source and executable hashes match before/after; owned container absent. |

Evidence directory: `native-pair-acceptance/run-20261022T175733Z-TGeB0c/`.

| Artifact | SHA-256 |
| --- | --- |
| `result.json` | `a73b29f3a102428e25b397a82df7979415393d18a0ec0b33228b2893f7bbcbe2` |
| Redacted `other-uid-observation.json` | `85b166a43c15f5a9359b72bda08ba10739971af042dbd6b08606e72e275705d3` |
| Identical before/after source JSON | `e49c70caf2658791120653559afaf717bb103ffe9abd2107094c1d78c919b2e4` |
| Complete source input manifest | `c281db52d0b802b06bba18733cb0ba4b9407309dac621cc59de21be71d9c9df1` |
| Executed CLI, 37,294,941 bytes | `4270ffd3c33ba85c58708f777f37ebea9c16bf89dc113e408a2a986224b5efe6` |
| Executed test, 23,082,074 bytes | `4fde5e4d5f12ece247a47dbb05e0a7b388dde4229516ebcea520f3c2c93a7cab` |

The fixture/driver source bytes tested here remain distinct from the later
documentation and any eventual clean checkpoint or integrated domain source.
Actual new-domain context issuance, signed business dispatch, same-UID isolation,
App-close/login/report lifetimes, empty-policy-cache recovery, real Codex TUI/Host,
legacy Pair, model/native queue/automatic wake, Windows DPAPI/ACL/GUI, Android and
public HTTPS are **NOT_RUN in this scope**. Later domain enablement must recheck
the private boundary and independently exercise context/signing refusal.

Related Root execution is recorded separately, never added to this one-test
count: Root's combined Hook/context narrow Docker run on `18c54a6` reports
21 pass, 0 fail/skip, exit 0, stable source and owned-container cleanup. Receipt
`local-domain-root/context-hook-exec-20261022-nblvth1u/result.json`, SHA-256
`07e9643ea61b57322c08e0c4394151c1d5c09c238b7217416496794b4a755f81`.
QA independently verifies that file hash; QA does not repeat Root's tests.
The prior `/tmp noexec` harness refusal remains a distinct exit-1 receipt with
zero tests executed: `local-domain-root/context-hook-20261022-px7mg9cp/result.json`,
SHA-256 `8e4fbcc45cbdb16e163274a4d2c2449491e98886ff2c9d41e976ef81389097c3`.
Neither Root run accepts domain business or physical Windows behavior.

## 2026-10-22 typed local-domain App gate: compiled, backend NOT_RUN

Preparation source is dirty `79e789b7eb5ada0d60b13a5618ab4ad3b0d54ab1`
plus the QA actor/fixture/driver/plan inputs, not a clean build attributed only
to that HEAD. The new test directly uses the delivered App Core public
LocalCollaboration actions. It introduces no replacement actor, parent-held
Owner signer, SQL authority or production implementation change.

```sh
scripts/test-native-pair.sh --codex-product-domain-app
```

**Actual outcome: NOT_RUN, command exit 125, 0 pass / 1 skip.** The real owned
Hub returns HTTP 404 at the domain capability route. version, compile-cli,
compile-tests, harness and vet each exit 0. Source/binary inventories match
before/after, and the exact owned container is absent. This proves that the
typed fixture compiles and that the driver refuses to count an unavailable
service as PASS; no domain business assertion executes after that preflight.

The prepared main line is actual App Refresh → explicit friendly private
Network/dedicated Group preview → activation response lost after Hub commit →
original-vault App/Hub restart and authenticated recovery → normal
Controller.Close and reopen → original policy read/revoke with Node offline.
The existing actual App actor gains an explicit test-only normal-close command;
the earlier crash boundary remains a deliberate SIGKILL, with distinct meaning.
An opt-in read-only observer inside the actual App process inspects its opaque
original-operation record immediately after normal vault open and before
Controller resume. It emits only ciphertext digests, public route and applied
state; the parent never opens that vault or Owner identity. These main-line
assertions, including the record observer's pending-packet branch and normal
close, are **prepared, not executed by this preflight**.

Evidence: `native-pair-acceptance/run-20261022T185319Z-KRKiHW/`.

| Artifact | SHA-256 |
| --- | --- |
| `result.json`, NOT_RUN/125 | `b5c59140875cba60aa17180ead8b897ddcbffff9b4bd5fb839c123fc2495e10a` |
| Identical before/after source JSON | `f411b931a522a922c964c09b14a0efea12277da6238c8f0800336510c62150d4` |
| Complete input manifest | `224b7d0814d603d44a75169de3bc3b2e1ebe1a76c0d56a6873d192215df1c648` |
| Executed CLI precondition, 37,366,836 bytes | `f9aa1240f87bb6a5928c960a8d8b619cc42cd58a5b614e4b8b714b52d227a2a1` |
| Compiled/executed test preflight, 23,416,089 bytes | `bcd1ab7cefe431e466c0ba9058eaeee90d4e641f56baf1f2c96c701b09f80a42` |

Related source-bound results stay separate from this skipped integration test:

| Executor/source | Reported scope and receipt; QA checks only the cited file hashes |
| --- | --- |
| Root, clean `ec9d2ef` | 85 protocol tests pass, 0 fail/skip, exit 0, stable source and owned-container cleanup. `local-domain-root/shared-protocol-20261022-qs2o9v4k/result.json`, SHA-256 `6860077eff02cb6718b22d7bfe687615d79dff23641d685e2691fe5faa6f88ff`. No App/Hub/Node business acceptance. |
| App producer, dirty `7ff12e8` plus its Core/UI candidate | Full normal Core/UI 361 pass, 0 fail/skip, in `/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-client-20261022T183316Z/result.json`, SHA-256 `d522f46fa02594e52f4032a20950c8d0bc0a12a8a4ab064393da64b83fad28f1`. Its broad race was INTERRUPTED_BY_PRODUCER, exit 1, and is not a PASS. |
| App producer, final dirty candidate later committed as `79e789b` | Final UI/native normal 170 pass and LocalCollaboration scoped race 20 pass, each 0 fail/skip; Linux/Windows vet and Windows build exit 0. Final Core bytes match the earlier 361 run, but three renderer files changed, so 361 is not a fresh full-source run on the final candidate. `/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-client-final-20261022T184131Z/result.json`, SHA-256 `38b27598cd4a71ed799f2abcb51d06cfabf6d4582ca2836f91db96da1d058479`; final source-before/source-after JSON both `2a7e57430d4e6211ff66f52c31d963e01d081d3cd75ae192c76d7b68728a8d24`. |

Do not add those counts together or attribute their dirty inputs solely to later
commits. Windows cross-build/vet does not execute DPAPI, ACL or physical GUI.
Actual new-domain admission for original native A/B without Pair approvals,
by-name Host ASK/Reply, domain context/signing other-UID refusal, App-close work,
real login/report expiry, empty-policy-cache full-page recovery, uncertain
activation recovery, current revoke/foreign scope and legacy-Pair boundaries
remain **NOT_RUN here**, as do real model/native queue/automatic wake, physical
Windows, Android and public HTTPS. Native positive gates retain the explicitly
documented manual independent Owner public-pin prerequisite; automatic FB-03
trust delivery is not claimed.

## 2026-10-22 native local-domain main-line driver: compiled, runtime NOT_RUN

Independent QA prepared `--codex-product-domain-native` on dirty source
`914250b6b4a281a73feb9a34411f482a70ecdb63` plus five acceptance/driver files.
This adds the [prepared main-line command](native-app-plan.md#nodeusernetwork-policy-acceptance-preparation),
not a Hub/App production implementation. The original umask-0002 daemon,
fresh native A/B literal admission, real Host by-name ASK/Reply after normal
App Close and authenticated policy revocation with healthy Node/Hub are required
assertions. Optional `CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=1` uses the
original Hub login's real wall-clock deadline and fresh native C; default 0
leaves that expiry scope NOT_RUN. Manual independent Owner public pin remains
an explicit prerequisite. The same daemon is measured without record chmod or
replacement, and no caller-supplied ticket or fabricated Thread is accepted.

Only pinned offline Docker version, `go test -mod=readonly -c ./acceptance/n3`
and `go vet -mod=readonly ./acceptance/n3` ran, each exit **0**, with identical
source-before/source-after and all three owned containers absent. The receipt
is `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/domain-native-compile-20261022-fafb66rh/compile-result.json`,
SHA-256 `aaf481abd64082af32e6a61947a1659acaa85b2494047a78edfc918d8b17492b`.
Both source JSON hashes are
`04504c035a697175cf5a23781982316cf7e36d51aa8db594e97ca72a3791565b`;
manifest `d8e2c1754989bd0992e3b5c8a22b0ca28643d5804cc05b80e23996857171015e`.
The unexecuted `n3.test` is 23,459,134 bytes, SHA-256
`aeba82072b2707635ef0f4ae89b468fdde5ba429b17da5f49122b6d75ff9fb39`.
Later evidence-only handling of unknown daemon activity and these documentation
updates are outside that compiled source snapshot; Go/Host driver bytes match.

The final evidence oracle was exercised separately with **11 synthetic receipt
cases**, not product tests. Its result is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/domain-native-oracle-20261022-456dgx93/result.json`,
SHA-256 `b1870773f1b547b9ad363fb47f7c89b2bce628b96fbe170e3d7a938ccaf170cc`.
Missing native measurement, absent positive binding epoch, literal provider POST,
missing new C after expiry, logical-clock-only expiry, source drift, untyped skip,
failed harness and wrong runtime hash all refuse PASS. A fully measured synthetic
receipt yields 0; the exact typed capability skip yields NOT_RUN/125.
This proves receipt discrimination only; none of the synthetic actors establish
native identity, authorization or communication. No real capability preflight,
Host/Native business flow or 15-minute wait was executed in this checkpoint.
New-domain other-UID context/signing, foreign scopes/epochs, business recovery,
policy pagination, legacy Pair and model/queue/wake remain **NOT_RUN**.
Windows DPAPI, ACL, physical GUI, Android and public HTTPS remain **NOT_RUN**.

## 2026-10-22 actual domain activation recovery failure and safe classification

Root ran the committed `--codex-product-domain-app` gate on clean
`2458552c78a69daba386ec9c1721568f30d49e51`. The real Node report, App preview,
Hub activation with response loss and retained App Pending state passed their
assertions. Following the deliberate owned App crash and Hub restart, the
resumed App actor exited before its safety checkpoint at
`local_domain_runtime_test.go:201`. The result is **FAIL**, exit 1, 0 pass / 1
fail / 0 skip. Its original receipt is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261022T211344Z-In5cA3/result.json`,
SHA-256 `cbc812bec392275117e0755f088dbd0ac03f2475f5bab06fd3d132c91e1d7198`.
Version, CLI/test compilation and vet exited 0; source/binaries were stable and
the owned container was removed. The original actor stderr was intentionally
discarded, so that receipt alone does not identify the internal cause.

QA added startup-only fixed phase/action categories, an explicit error-code
allowlist and child exit code to the existing actual actor. Both producer and
parent filter these values. No raw error, stderr, Snapshot, vault contents,
private key or full packet enters the diagnostic. One necessary diagnostic
reproduction used dirty `2458552` plus the two QA files; it retained the same
**FAIL**, exit 1, 0/1/0, at the same checkpoint. The measured classification is
`exit=1 phase=ACTION_FAILED action=UNLOCK_AND_RESUME_PROFILE code=` (empty).
Its independent receipt is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261022T211825Z-GTh994/result.json`,
SHA-256 `5dc9d9d8e1c8ebd8418b332f6e55a9d8d853d8a3b17e2841abbc802b7fee7fd5`.
All compilation/version/vet stages exited 0, the container was removed, and
both source JSON hashes are
`b46a8afab4d7becc2faa22f80bd3c45efd04af23181b9aa138c959e06a11cea0`.
The executed CLI is 37,847,850 bytes, SHA-256
`2f5fa0897dea1778cb9e611f7294a07df01c1413ef8908a741237e9200e6f9fd`;
test binary is 23,555,890 bytes, SHA-256
`105d62da74e6396978e605322a3bcc7d3c6239c239d545ca3b13edd7f632277d`.
These documentation additions follow that diagnostic source snapshot.
The cross-worktree source-manifest comparison also identifies two pre-existing
ignored generated-input differences under `internal/server/ui/generated/`:
`cicada-webcrypto.wasm.gz` and `panel.manifest.json`. Apart from those generated
inputs and the two QA files, all captured source inputs match Root's clean run.
Each run's complete manifest pins its actual inputs; its CLI binary is attributed
to that build, with no claim that the two worktrees produced identical binaries.

The App owner confirmed the Core defect: profile resume loads the unresolved
domain operation and then calls ordinary session inspection; that inspection's
`canBeginOperation` guard rejects the retained domain Pending state with
`ErrInvalidAction` and no Snapshot error code. The App owner is responsible for
the production fix and persistent-session recovery regression. QA retains the
original operation and failure assertions. Recovery after restart and all later
domain-App assertions remain **NOT_ACCEPTED** until the fixed formal checkpoint
is actually rerun. Native A/B/Host business flow, Windows DPAPI/ACL/physical GUI,
Android and public HTTPS remain **NOT_RUN**.

## 2026-10-22 actual domain App recovery after Core fix

The formal App fix `bd0d90120c042735aba0f627bd01a1b0a0546055`, parent
`2458552`, keeps a restored live session awaiting inspection while the exact
uncertain domain packet remains available for explicit recovery. App producer
normal 46/0/0, focused race 3/0/0 and vet 0 remain separate from this independent
process gate. Its producer receipt is
`/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-profile-recovery-20261022T212140Z/final-result.json`,
SHA-256 `89b1253acfe5ec6e45be34346d54e7cfb235777d4d853152baa64f8623ec8009`.

Before the one necessary verification run, Root identified and QA corrected a
separate acceptance expectation: an authenticated historical activation receipt
must restore its original ACTIVE outcome with `Current=false`. It does not
restore current account or policy authority. The test now verifies original
opaque packet durability, identity and historical outcome first, explicitly
dispatches the actual `ActionSessionInspect`, then calls the actual
`ActionRefreshLocalCollaboration` and requires the independently authenticated
current policy and StateReviewID. All subsequent Close and offline-revoke
assertions retain that current-state prerequisite.

Reproduction was `scripts/test-native-pair.sh --codex-product-domain-app`.
The real gate returned **SCOPED_PASS**, exit **0**, 1 pass / 0 fail / 0 skip on
dirty `bd0d901` plus three QA Go changes and a validation-record overlay.
Version, CLI/test compilation, harness and vet all exited 0. Its immutable
receipt is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261022T212846Z-iDwN6U/result.json`,
SHA-256 `b2a593af88cf5c09d0612155c60ca3e9ac759dae3babdb0cc163c26b87be2a01`.
Source-before/source-after both hash to
`a09c07034de2e4b44de0e7ead997c4953fa286272f5929bafbe5229f9ec1bd6d`;
complete manifest `4e5a26213ee36339cd4656ade8da2f42ccf2df4014917f040365715c5f0cc690`.
The actual CLI is 37,847,850 bytes, SHA-256
`2f5fa0897dea1778cb9e611f7294a07df01c1413ef8908a741237e9200e6f9fd`;
actual test binary is 23,560,223 bytes, SHA-256
`297260306bfb86f5feeff7f01f9ccde8dea2d3c595a23c22fc2b5869bc8f6b0c`.
Both binaries remained identical before/after execution; the owned container
was removed and the task build-cache lock was released.

This scope passes actual App signing and Node-report-derived policy preview,
persistent activation, response loss after commit, actual App/Hub restart,
original protected-vault packet recovery, separate historical/current checks,
normal Controller.Close/reopen with retained policy, and authenticated read/revoke
with Node offline. The two earlier FAIL receipts remain unchanged. No additional
product run followed this pass.

The original result's older `not_run` list still contains the now-observed
activation recovery and a combined App-close/login/report item. QA preserved
that receipt and corrected only subsequent evidence classification: completed
activation recovery and normal App Close are removed from NOT_RUN only for a
successful full App gate. Actual Hub login expiry and Node-report expiry remain
NOT_RUN. Replaying the captured PASS, FAIL and typed unsupported inputs through
the corrected classifier preserved exits 0, 1 and 125 respectively. This is a
metadata-only check, not another product run:
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/domain-app-metadata-check-20261022-qeet32la/metadata-check.json`,
SHA-256 `3816e57bef10e680197e807bb09e9b1c4ac0d7dfaa75aca42c034d6bf12749c7`.
The separate `reclassified-result.json` in that same directory has SHA-256
`ee3c4bf1b836d3f852aaf99a16927e07e5a4cd7934c8b8ed719b316ed16aa612`;
it links the exact original receipt, log and classifier and explicitly records
`additional_product_execution=false`.
The evidence-classification/plan/documentation updates follow the measured source
snapshot; the three executed QA Go files retain their measured bytes.

Actual native A/B Join without Pair, Host ASK/Reply, new-domain other-UID context
and signing, real login/report expiry and fresh C, empty-policy-cache full-page
recovery, stale epochs/foreign scope, legacy Pair, real model/queue/automatic
wake, Windows DPAPI/ACL/physical GUI, Android and public HTTPS remain **NOT_RUN**.

## 2026-10-23 original-daemon domain Native integration

The independent actual Native gate is **SCOPED_PASS**, exit **0**, one passing
test event and no failures/skips. This is the manual independent Owner-public-pin,
static-provider scope; Windows and real-model scopes remain separate. Actual
Hub/App/Node processes use real cryptography, TCP and persistent stores in a
unique disposable Docker environment. Control inference is off; the parent
neither holds an Owner signing key nor injects SQL grants or queue ACKs.

The tested source is clean `88ff963d2ebe7f4544b201b77115567033b2966e`.
The approved complete product freeze has 2466 files,
`/home/zyf/Cicada/.local/evidence/local-domain-root/native-real-queue-clean-88ff963-20261023.json`,
SHA-256 `6be9a39c47d68ed147886b0edc5367d185c79b6b13d04c28ac1a78c0f6f82eee`.
The separately built delivery is clean `9726e04505a8fce960c37803e504d265344c902e`;
Root verified that all production/module/assets Git inputs are equal, with only
four QA-file differences. Those are distinct HEADs; this does not assert equal
build metadata or binary bytes. This later documentation update is outside the
tested source snapshot.

The actual test ran from `2026-10-23T00:58:43Z` to `01:14:56Z`, 973.13 seconds.
All version, CLI compilation, test compilation, harness and vet stages exited 0.
The original official Codex daemon starts before file installation under actual
umask 0002 with the five deployment variables absent, then loads the normal
installed-plugin update. Original PID/start ticks, executable hash, real native
SID/cwd/UID/inode and positive binding epochs remain checked; records are not
chmod-repaired and the daemon is not replaced.

The actual App approves one persistent Node/user/Network policy with a dedicated
non-Pair Group. Native A/B literal Join produces zero provider POSTs. Current
by-name discovery resolves the real Endpoint. After the actual normal App
Controller.Close, A ASK, B authenticated receive, B Reply and A authenticated
receive pass. The driver then waits beyond the original authenticated Hub login
deadline `2026-10-23T01:13:45.43011913Z` plus one second in real wall time,
without a logical-clock offset or shortened server TTL. Post-expiry A/B ASK/Reply,
fresh native C literal Join/WhoAmI and C-to-B ASK/Reply pass under the same daemon
and independent policy. The actual App reopens its original protected profile,
authenticates as needed, reads the same current ACTIVE policy/version and
explicitly revokes it. A fresh Node heartbeat still succeeds with Hub/Node alive;
a new ASK from the already connected Host is refused and creates no request ID.
This does not qualify every post-revoke discovery or fresh-Thread adversary.

There are **17 completed Host calls**, not a claim of 17 newly started turns:
the SDK may start or steer within the original Thread. Each call retains exactly
two correlated provider POSTs, its unique current label, actual returned turn ID,
real `client_metadata`, schema nonce, installed Hook and original business
assertions. Host POSTs are **34**, separately recognized actual queue static
POSTs **6**, total **40**; literal POSTs and real-model turns are **0**. Only current
registered full queue input with the actual verified route/SID is recognized;
unknown POSTs fail. Queue input receives neutral static text and no tool call.
The existing Node path executes the actual pinned full-package `codex queue`;
its durable success boundary and actual scoped inbox read are not replaced by a
fixture ACK. Static dispatch does not prove real-model consumption or real-model
automatic wake.

Manual independent Owner trust remains required: actual App public export plus
the existing operator trust command populate the isolated Node. Trust is not
initialized from an arriving policy's own public key. Automatic FB-03 delivery
is **NOT_RUN**. The earlier [account/Root N2 result](#n2-hubapp-integration)
retains its own source and proves account login does not imply Root; that older
negative scope is not silently promoted to new-domain adversarial coverage.

| Final independent artifact | SHA-256 |
| --- | --- |
| `run-20261023T005832Z-tNoboL/result.json` | `31f8e49faac14426555718ff81f90fddc43c0658d96a0ceeba0dd48726869500` |
| Same run's `domain-native-public-summary.json` | `00e696fbe6b165c22c0199cbb21293aae5ab0741b1fb39d2b4508cf922ae747b` |
| Same run's `source-before.json` and `source-after.json` | `3aef73a633e9375267d05b13b50023bdb355dbee54b7eb9e6ea2d71956cc5e29` |
| Complete source manifest | `6108af0937bfce32ced83e9f419292cba00bedef72ee3915903cd95685780981` |
| Actual `cicada`, 36,333,612 bytes | `483fa019c89ff8bde007b6d9240c650348b46cdca41c11ebc009c1a3d5ef7e0e` |
| Actual `n3.test`, 23,565,935 bytes | `0a588045a932dfd15fc752573a912c82586caf239f909b082418b6891ecc7ef7` |
| Reviewed complete-package Codex 0.163.0, 296,865,480 bytes | `399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215` |

Run-relative evidence is under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`; binaries are under the
matching `.local/artifacts/native-pair-acceptance/` run directory. Source and
executed binary hashes are stable before/after; the owned container is absent
and the exclusive task cache lock is released. Independent post-run rehash of
all 20 evidence files and both actual binaries matches:
`native-final-verification-20261023-k86yod0k/result.json`, SHA-256
`b4caa28fc231953f5eef48b060598acbc4a3d70900565377e2f7830830de6195`.
This rehash is not another product execution.

Reproduce from a clean checkout of the tested source, with the pinned complete
CLI package/notices and approved matching freeze already present:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/codex-startup-fix/licenses-x4gog722 \
CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=1 \
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/local-domain-root/native-real-queue-clean-88ff963-20261023.json \
scripts/test-native-pair.sh --codex-product-domain-native
```

The runner mounts source/module caches read-only, locks the task build cache,
uses task-isolated state/ports/output and `--network none`, and cleans only its
owned disposable container. No shared development Hub or public deployment is
used. Seven predecessor attempts remain immutable FAILs (each 0/1/0); missing
old diagnostics are not reconstructed from independent reproduction or fixes.

| Retained run | Executed source | Recorded stop | Exit | Result SHA-256 |
| --- | --- | --- | --- | --- |
| `run-20261022T223355Z-WhxOtu` | `a52cf56` dirty | `LITERAL_AB/A_JOIN`; `NOT_RECORDED` | 1 | `a3b6cdd7e662728d5e19d24027e57c3529cada1a7332a6fd344ee776214123f5` |
| `run-20261022T225021Z-nghDUR` | `0da74df` dirty | `LITERAL_AB/A_JOIN`; `ACTUAL_TUI_LITERAL_RESULT_NOT_VISIBLE` | 1 | `40b216ada516ed60a41f3cc26dcf88a5ea04e1b91d7cc9e10a05a8bcff9efbc5` |
| `run-20261022T230207Z-3NUe5A` | `0da74df` dirty | `HOST_APP_CLOSED/A_WHOAMI`; `UNCLASSIFIED` | 1 | `6219be1790282693cda1dc07477f903152580a8b73a07718e7c5e494c2db4f67` |
| `run-20261022T232204Z-MvhrQ4` | `135e4c9` clean | `HOST_APP_CLOSED/A_WHOAMI`; `ACTUAL_HOST_RESULT_FIELD_MISSING_OR_AMBIGUOUS_native_session_id` | 1 | `15239746b543f28301c768dad74238fe4121ac6b87851ec560766b357faa37cf` |
| `run-20261022T233813Z-B26Oqy` | `c4cb7b9` clean | `HOST_APP_CLOSED/A_PEERS`; `ACTUAL_HOST_PHASE_INCOMPLETE` | 1 | `f7ac5bc35f048157355b6b775edcf201a6ae05438fdeb0da25223afe5ade18f6` |
| `run-20261022T235417Z-46guDR` | `576d1de` clean | `HOST_APP_CLOSED/A_OPERATION_STATUS`; `UNCLASSIFIED` | 1 | `9c98f35e9f83a26e8a6b82dbd155d5ce659b111225732eb94520f6b6c581b183` |
| `run-20261023T001742Z-0E8rNi` | `9726e04` clean | `HOST_APP_CLOSED/B_RECEIVE_QUESTION`; `UNCLASSIFIED` | 1 | `16740eae8d040c2ab4168b7d2e65946dde00d2cee89918c24edc2f77bbb8557b` |

Producer-owned corrections were the exact literal UserPromptSubmit context
shape, existing Hub members/list route and selected consumer send IPC socket.
QA corrections were the exact pinned SDK Text framing, existing MCP tool name,
real queue executable fixture dependency and strict concurrent provider lanes.
The seventh runtime did not retain queue-error text or inbox count; the missing
executable dependency was established separately by read-only preflight. It is
not a retroactively captured error from that failed run. No Hub/App production
implementation was edited by QA.

The candidate's 70 offline boundary checks cover wrong SID/route, old markers,
request-ID cross-check, concurrent queue POSTs interleaved with two Host POSTs,
same-turn processing, bounded idle reads and original business-helper ASTs.
They also replay the seventh captured FAIL as exit 1 without adding old queue
facts. Receipt `native-queue-host-final-20261023-8tcqsvkb/result.json`, SHA-256
`64bdfefa9d05672b775377c135617f128f847c86b69e005f54c4df6c1d8c3411`;
these are driver/oracle checks, not Native product passes.

Root's separate clean-`b5d58bd` default Client/Hub compatibility result remains
4 top-level plus 3 subtests, 7/0/0, exit 0, cleanup CONFIRMED:
`/home/zyf/Cicada/.local/evidence/local-domain-root/client-interop-b5d58bd-20261022T2153Z/result.json`,
SHA-256 `72c718af31e97f3df9d9220fa57ba56476e395b85939f72d19f599ea740bbf33`.
It does not become compatibility acceptance for a later source or delivery.

Remaining independent scopes are new-domain other-UID context/signing beyond
observed file/IPC denial; foreign Node/Owner/Network and stale epochs; optional
policy expiry and report-expiry-only independence; original business-response
loss recovery; empty-cache full bounded policy pagination; legacy Pair migration;
literal Leave/ordinary-prompt passthrough and graceful TUI exit. The real login
wait retains automatic report refresh and does not isolate report expiry.
Real model, queued-input model consumption and real-model automatic wake,
Windows DPAPI/ACL/physical GUI, Android and public HTTPS remain **NOT_RUN**.
Linux vault and cross-build evidence do not execute Windows requirements.

## 2026-10-23 actual-model directory-filter failure

**USER_REPORTED_FAIL**: native A Join succeeded, then the actual model's first
`cicada_resolve` with `query` and target `workspace` was refused with
`CODEX_TOOL_ARGUMENTS_INVALID`. Root's read-only extraction from the actual
native record retained only redacted call/diagnostic facts:
`/home/zyf/Cicada/.local/evidence/local-domain-root/directory-filter-incident-20261023-od8zj2jr/incident.json`,
SHA-256 `1323abd86ec5daa6000ef823ef0b1402249ed73ce2830e13f3c075f48e5388e9`.
No raw transcript or connection nonce was copied, and resident state was not
changed. The declared resolve schema accepts a target workspace, while the
shared validator rejects that key as a caller identity claim before ticket
issuance. This is not attributed to strict-schema forced nulls: the actual
0.163 consumer advertises `strict:false`.

The earlier `88ff963` static-provider PASS and seven failed predecessors retain
their original source and scope. Its `members({})` path did not cover this real
model-selected resolve/filter shape. Independent disposable old-code RED and new-code GREEN are recorded below;
no real-model conversation pass is claimed.
The user now requests complete removal of the old installation followed by a
fresh install. A repair ZIP or reuse of an old trust pin does not qualify that
flow. Manual independent Owner public-key transfer remains an explicit step
until automatic FB-03 delivery is implemented and independently accepted.

### Independent directory-filter RED/GREEN

The same four QA driver files ran against old and corrected production code,
with `CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=0`. These are actual original
Codex 0.163 daemon/installed Hook/MCP/Node, App-owner approval, real cryptography,
TCP and persistent-store tests in owned disposable Docker, using a static
provider. They do not use the user's Thread, Hub, credentials or deployment.
Manual independent Owner public pin remains an explicit prerequisite. Each run
starts new synthetic identities; this does not establish complete fresh install.

| Observation | Required and observed result |
| --- | --- |
| Original failure shape | A resolves the real B by human name and target workspace; B Endpoint/name/workspace/Node must match the actual B WhoAmI, while identity comes from A's current Hook/ticket. |
| Five directory tools | find/resolve/inspect with exact Node/workspace and members/list with exact Node/harness/limit succeed. Omitted, empty and whitespace string filters retain their existing meaning. |
| Result narrowing | Wrong target workspace or Node returns 404 without B's card; this is a filter check, not a claim of a separate foreign-Owner authorization run. |
| Caller and unknown fields | native_session_id and an unknown field each reject null, empty string and a supplied value with CODEX_TOOL_ARGUMENTS_INVALID. |
| Optional filter types | workspace and node_id each reject explicit null, bool, number, array and object. No generic null stripping or caller-identity fallback is permitted. |
| Original caller and Guard | A WhoAmI remains exactly its original SID/cwd/Node/Endpoint/Group/epoch after all probes. Existing App-close ASK/Reply still passes. After authenticated same-policy revoke with healthy Hub/Node, new ASK and the same valid resolve filters refuse. |

Old-code **RED** is `run-20261023T035230Z-ZRfZNw`, **FAIL**, exit **1**, 0/1/0,
on dirty `cd9a396` plus six QA/doc files and three pre-existing ignored generated
build inputs. It stops at `HOST_APP_CLOSED/A_RESOLVE`, assertion
`ACTUAL_DIRECTORY_RESULT_MISMATCH`, with safe product code
`CODEX_TOOL_ARGUMENTS_INVALID`. Literal POSTs are 0, Host POSTs 6 and queue POSTs
0. Version, CLI/test compilation and vet exit 0; harness exits 1. This is the
required reproduced failure, not a successful regression gate.
The earlier `run-20261023T035056Z-LPSViy` stopped in source-freeze preflight
because an inherited inventory omitted those three generated assets. No product
test ran there. It is retained as a fixture-preflight failure; input validation
was not relaxed and no generated file was deleted to force the gate through.

Corrected-code **GREEN** is `run-20261023T040143Z-QBj6Y7`, **SCOPED_PASS**, exit
**0**, 1/0/0, on dirty `e902a8368a9beb0cdc99fd329168d5de45abfd13` plus the same
four QA driver bytes, its six-file QA/doc overlay and the same three ignored
assets. The actual test ran `04:02:01Z`–`04:05:55Z`, 234.66 seconds. All version,
CLI/test compilation, harness and vet stages exit 0. The four driver hashes and
ignored-asset hashes are identical between RED and GREEN; only producer code
and explicitly recorded later documentation differ. There are 36 completed
Host calls (START_OR_STEER), 72 Host POSTs, 2 actual queue static POSTs, total 74,
zero literal POSTs and zero real-model turns. Login-expiry/new-C is explicitly
NOT_RUN in this short gate; the prior clean-88ff expiry result is unchanged.

| Artifact | SHA-256 |
| --- | --- |
| RED `result.json` | `1991f26bb347c6012f939c528174bdd09673e96d6db52fce4c81a1cd570d4c5f` |
| RED freeze, 2469 inputs | `8398f371a905d8201380886ea4fed960297e6512a58d8056b6bb138752007649` |
| RED source-before/source-after | `1b276b9acd35bdc03fa06e18a96d154acf7358d5a701589075dc85f426276224` |
| RED full manifest | `bb6f03e79ecf3bc9d1785a2fd80078881e1eeaf94c9d0a5825ac4ba792f00599` |
| GREEN `result.json` | `c3d3243e15fc96b79d84c2565cabcb95d36a9ffd723782dba442843e8b2b0936` |
| GREEN freeze, 2471 inputs | `e78211c2bbcf03bf47390fc4435453afecd6fcfd257b1b596cf0433c74af3193` |
| GREEN source-before/source-after | `ac97d31cce7569b2802ce5adb1e1f61cb6521fd7514e829d4c714707d2a8ccbe` |
| GREEN full manifest | `36741cc1523d6791917f83538e16024386334d8bf71ac84a971128c3ff9c68e0` |
| RED CLI, 38,144,036 bytes | `0a2f344714b9f68f851619e3e333a582e2926d045dba04a5b4cbe600071dc0fa` |
| GREEN CLI, 38,141,735 bytes | `a27680e9d212e224e49d0fd6fd0475a6625ea4d944755712470c467288ca2834` |
| Both actual test binaries, 23,569,679 bytes | `3ba5e312740f023c2069a54097477a8476c604a5eb19649084dd7f3a0a81f82b` |

Run paths are under `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`,
with binaries in matching `.local/artifacts/native-pair-acceptance/` run paths.
The GREEN freeze is
`directory-filter-green-freeze-20261023-_qm15bua/product-freeze.json` in that
evidence root; the RED freeze is `directory-filter-red-freeze-20261023-59ddpo7n/product-freeze.json`.
Both source and actual binaries remain stable during their run, owned containers
are absent and the task cache lock is released. Independent rehash of the GREEN
evidence/binaries and unchanged RED/GREEN driver inputs is recorded at
`directory-filter-red-green-verification-20261023-0cwgo8w2/result.json`, SHA-256
`177ce2fce023a391225b7b1fad7c506ffec54fd4c2065102debfbcc1a74dbc39`.
Root independently rehashed all 20 evidence files and both actual binaries and
checked exact container absence: `/home/zyf/Cicada/.local/evidence/local-domain-root/directory-filter-native-green-root-review-20261023.json`,
SHA-256 `3010d298c16fae064f75f5ae417a86c7abf45df022878e6d747920a23baa9243`.

Reproduction uses the exact recorded source/QA bytes and complete matching
freeze, with no repeated 15-minute wait:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/codex-startup-fix/licenses-x4gog722 \
CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=0 \
CICADA_NATIVE_PAIR_PRODUCT_FREEZE=/home/zyf/Cicada/.local/evidence/native-pair-acceptance/directory-filter-green-freeze-20261023-_qm15bua/product-freeze.json \
scripts/test-native-pair.sh --codex-product-domain-native
```

The separately built complete package is clean e902. QA's three ignored embedded
assets are present in its exact build inventory, while they are absent from the
clean package build. Do not claim binary/input identity or relabel this dirty
GREEN as the package executable. Root's clean-e902 default disposable Client/Hub
interop is a separate PASS/0 with cleanup CONFIRMED, receipt
`/home/zyf/Cicada/.local/evidence/local-domain-root/directory-filter-interop-20261023-yenXDfQN/result.json`,
SHA-256 `7ed52b85f8c58a2d9abf96e49bd9cf63a3d3f1684dd6f8e3c762f02224d54b29`.
Its source input fingerprint matches the clean delivery build; its test binary
is still separate. Producer's normal 58/race 27/vet 0 result keeps its own
[contract/producer evidence](native-endpoint-directory-validation.md).

### Complete removal and fresh-install manual acceptance

Later 2026-10-23 steering supersedes the Node descriptor/manual Owner-key
transfer portions of steps 6–7 for the next onboarding package: the user selected
Hub address -> Node device code -> App review/approval -> Hub binding, with
business permissions configured afterward. Those old-package commands remain
historical and are not the next operator batch. The replacement is
[under design review](#2026-10-23-node-address-and-device-code-design-review),
NOT_RUN; do not infer it from the old manual-pin gate. The completed Hub/Windows
slice has its separate user-reported record below.

Status: **NOT_RUN** for complete removal/reinstallation, physical Windows
DPAPI/ACL/GUI and public numeric-IP TLS. Use this batch after Root delivers the
reviewed complete Hub/App/Node package. This is the requested operator procedure for a
complete new installation, not a repair-package procedure. No removal or real
deployment action was performed by the independent QA gate. Use the final
reviewed complete package and its own SHA-256 manifest; its clean source and
actual-model results must be recorded separately from the earlier static gate.

A read-only gpu1 inventory on 2026-10-23 found the old unit file at
`~/Cicada/node/systemd/cicada-node.service` and retained user drop-ins
`~/.config/systemd/user/cicada-node.service.d/20-cicada-codex-bin.conf` and
`40-installed-plugin.conf`, although `systemctl --user show cicada-node.service`
reported not-found/inactive at that observation. The retained old state is
`~/Cicada/node/state`; installed assets are under
`~/.cicada/components/node/share/codex/.agents/plugins/`, with the installed
Codex cache at `~/.codex/plugins/cache/cicada-repo/cicada/0.0.5/`.
`~/.cicada/run/nodes` and `~/.cicada/codex/mcp` exist; the planned new explicit
`~/.cicada/node/state` path was absent at that time. These are dated path
observations, not proof of current deployment state or authorization to remove
anything automatically. Only metadata was read; no key/token contents, process
environment or unit/drop-in bodies were read and no resource was changed.

The observed executable processes were MCP children, including children still
holding deleted old executables, not a running Node agent. The user must exit
the test Codex sessions or disable their Cicada plugin before checking remaining
processes against the exact old executable path. Do not use broad `pkill cicada`
or infer that every Cicada process is the Node service. Keep Codex history and
unrelated sessions. Preserve reviewed `~/.cicada/acceptance/native-pair/A` and
`B` workspaces and non-sensitive historical receipts outside the active root;
`~/.cicada/acceptance/native-pair/mcp-state/mcp` is old authentication cache,
not preserved history, and must not be copied back into the new installation.

1. Stop the actual old Cicada writers before removing files. Close the native
   App; stop/disable the installed Node user unit (`cicada-node.service` when
   that is the actual registered unit), old Hub service/container and any old
   Worker/service registration. Record their exact executable, StateDir and
   registration paths. Remove those specific registrations and stale autostart
   entries so an old process cannot recreate deleted state. Do not stop an
   unrelated service or prune Docker globally. In Codex, remove the installed
   Cicada plugin and its old marketplace registration through the supported
   plugin CLI/UI; remove only obsolete Cicada MCP/Hook entries from any earlier
   manual configuration. Keep the original Codex installation/account and
   history under `.codex`, all Git worktrees and `~/Cicada/.local` evidence.
2. Before deleting a Cicada user root containing `acceptance`, move only the
   reviewed non-sensitive receipts/logs/hashes out to an evidence directory
   outside that root. Do not copy or back up real private keys, vaults, tokens,
   activation material or outboxes: the user selected deletion of the old
   identities. Delete the actual old installed binaries and known component
   configuration/state/cache, Hub database and transport keys, Node private
   state/MCP cache/outbox/pins, and App vaults. Scope removal to the recorded
   installation roots; never recursively remove `~/Cicada` or `.codex`.
   On Windows, clear the old selected install/user root and known Cicada vault
   fallback locations, including `%LOCALAPPDATA%\CICADA\vaults` (and its nested
   `CICADA\vaults` layout) and `%USERPROFILE%\.cicada\app\vaults`, plus any
   previously selected custom root. Otherwise a new App can discover an old
   profile even when its new primary root is empty. On Linux, clear the actual
   old installed Node/Hub StateDirs; if the historical `~/Cicada/node` layout was
   used, remove that installed component/state only, preserving repositories and
   `.local`. Remove obsolete Cicada deployment/root environment overrides and
   stale service command lines rather than reusing them for the new install.
   Record absent processes, registrations, old vaults and old state paths.
3. Verify/extract the complete package and follow its component-install commands
   into the selected empty roots. Hub files/state belong under `/opt/cicada`;
   Node user files belong under `~/.cicada`; Windows program and user files use
   `F:\DOWNLOAD\Cicada-N2`. Installation is file-only: it must not silently start
   a Node, recover old identities or grant business rights. Resolve the package's
   actual executable/notices/plugin-asset paths from its manifest; do not substitute
   a cached repair binary. For the following commands, `HUB_CLI` and `NODE_CLI`
   denote the verified newly installed executables. `HUB_ADDRESS` is the new
   Hub's reachable numeric IPv4:port or bracketed [IPv6]:port; it is entered in
   the App and Node. No domain, DNS/hosts alias, Caddy, reverse proxy or preset
   external origin is required. Other uppercase placeholders are newly reviewed
   public values. No old IDs, pins or credential files are input.
4. With the new Hub stopped, initialize its empty persistent state and issue a
   fresh finite initial activation code locally:

   ```sh
   install -d -m 0700 /opt/cicada/state /opt/cicada/private
   install -d -m 0755 /opt/cicada/public
   "$HUB_CLI" hub setup --native-tls --owner-label 'New installation Owner' \
     --state-dir /opt/cicada/state \
     --public-config /opt/cicada/public/hub-connection.json
   "$HUB_CLI" hub connection-export --state-dir /opt/cicada/state \
     --descriptor-file /opt/cicada/public/hub-transport.txt
   "$HUB_CLI" hub activation-issue --native-tls --purpose initial \
     --state-dir /opt/cicada/state --code-file /opt/cicada/private/initial-bootstrap.txt
   "$HUB_CLI" serve --hub-nodes-only --native-tls \
     --state-dir /opt/cicada/state --host 0.0.0.0 --port 8787
   ```

   Run with the intended installation owner and suitable directory ownership.
   Use the same exact state path for setup, issuance and service. The single Hub
   terminates TLS itself; setup derives its stable logical origin locally. Keep
   its TLS bundle, public pin and application identities together. The operator
   must make the numeric listener reachable through the chosen firewall/NAT;
   public routing remains unverified until this real batch runs. Obtain the
   public descriptor and full Hub fingerprint through the trusted local/operator
   installation channel. Privately transfer the complete one-use bootstrap
   wrapper, without copying it into evidence. The public descriptor contains no
   activation code and is the only trust file needed by the fresh Node.
   Do not use legacy adoption, an old pending Owner or an imported old vault.
5. Launch the new Windows App explicitly with the selected root, using the
   actual verified executable path in the complete package:

   ```powershell
   & '<new-package-App-executable>' --user-root 'F:\DOWNLOAD\Cicada-N2'
   ```

   Expect initial setup, not an old profile/connection. Connect with the new
   same-page numeric `IP:port` and complete `cicada-hub-bootstrap-v1:` material;
   compare the displayed logical origin/full Hub fingerprint with the operator's
   independently obtained public metadata. Require verified TLS and Hub identity
   before generating a new Owner in the App. Then
   approve the finite App device authority and create the new account credential.
   Complete separate ordinary login: login itself does not activate Root or
   create Node/Network business authority. Record Windows DPAPI, vault ACL and
   GUI behavior individually when actually executed, without publishing secrets.
6. Manually start one new Node as the intended OS user. Use explicit installed
   root and private state paths, rather than relying on the older implicit
   `<root>/state` default. Obtain `HUB_DESCRIPTOR_FILE` from the Hub's public
   export through the independent installation channel and store it under the
   new Node root, for example `~/.cicada/config/hub-transport.txt`. Keep its exact
   descriptor bytes; do not give the Node the secret App bootstrap wrapper.
   `CODEX_BINARY` is the user's actual complete Codex installation; the current
   target is verified `codex-cli 0.164.0`. Record its path/version/hash separately
   from Cicada's package. Its `CODEX_HOME` remains the intended native account:

   ```sh
   CICADA_CODEX_BIN="$CODEX_BINARY" "$NODE_CLI" machine agent --relay-only \
     --id "$NEW_NODE_ID" --name 'New local Node' \
     --hub-connection-file "$HUB_DESCRIPTOR_FILE" --hub-dial-address "$HUB_ADDRESS" \
     --user-root "$HOME/.cicada" --state-dir "$HOME/.cicada/node/state" \
     --mcp-session-state-file "$HOME/.cicada/mcp/sessions.json" \
     --mcp-outbox-state-file "$HOME/.cicada/mcp/outbox.sqlite3"
   ```

   Review the actual new Node code/candidate in the new App, including Hub/Node
   fingerprints and scope, then explicitly approve it. No copied old Node
   binding or trust state qualifies. Service installation is optional after
   foreground approval and must preserve these exact flags/paths; no second
   writer may run against them.
7. **Manual independent Owner public pin remains required.** Export the new
   Owner public identity through the actual App. Privately transfer only that
   public file, independently compare its full key ID/fingerprint with the App,
   stop the Node, and use its existing command:

   ```sh
   "$NODE_CLI" machine trust-owner-key --id "$NEW_NODE_ID" \
     --state-dir "$HOME/.cicada/node/state" --writer-root "$HOME/.cicada/node/state" \
     --owner-id "$NEW_OWNER_ID" --public "$NEW_OWNER_PUBLIC_FILE" \
     --expect-key-id "$NEW_OWNER_KEY_ID" --expect-fingerprint "$NEW_OWNER_FINGERPRINT"
   ```

   Restart the same Node with the same explicit paths. The file is public;
   private Owner keys remain in the new App vault. Automatic FB-03 trust delivery
   is **NOT_IMPLEMENTED / NOT_RUN**; this manual step cannot be omitted or called
   one-click fresh setup. Approve one explicit Node/user/Network local policy in
   the App; Node registration alone is not a grant to every Network.
8. Install/connect only the newly installed plugin asset set to that running
   selected Node, using the full package's existing marketplace/plugin commands
   and normal Hook trust controls. Keep one Cicada plugin/MCP/Hook registration;
   do not replace them with user-config shims or rewrite the shared daemon's
   deployment environment. Open genuinely new A/B native Threads/workspaces;
   literal Join must retain each actual SID/cwd/name. Query B by its human name
   and actual target workspace, then complete ASK/Reply in both directions and
   check the original caller identity. A wrong target filter must not return B;
   forged caller fields must refuse. Close the App and verify permitted work,
   while keeping the independently granted Node/user policy active. Record
   actual-model conversation outcomes separately; synthetic static-provider
   GREEN is not that result. Wrong Hub public metadata, missing approval or
   copied caller fields must not create a second authorized identity.
9. Exercise normal process/profile recovery before revoking. Restart the same
   Hub with its original StateDir/native-TLS flags, then the same Node with its
   original explicit paths and descriptor/locator. Reopen the Windows App with
   `--user-root 'F:\DOWNLOAD\Cicada-N2'`, discover/unlock the original profile
   and complete ordinary login if required. Compare the original Hub pin,
   Owner/App-device public IDs and Node binding; do not issue a new bootstrap
   or regenerate an Owner to make recovery succeed. Reconnect the original
   installed plugin if needed, preserving actual A/B SIDs/workspaces and caller
   identity, then repeat the named/workspace query and ASK/Reply. Record any
   uncertain original request and its authenticated recovery separately.
10. In the original recovered App, refresh and explicitly revoke that exact
    current Node/user policy. Require new named/workspace discovery and ASK to
    refuse while the original Hub/Node remain running and healthy. Closing the
    App earlier must not be counted as this explicit revoke. Return one batch
    record with UTC time, package/source/version distinctions, executed commands
    and exit codes, artifact hashes, original public IDs, observed results,
    defects and each unexecuted item. Do not include credentials, vaults, keys,
    tickets or sensitive full request bodies. Windows DPAPI, ACL and GUI and
    actual public-IP connectivity get their own user-observed result; Linux
    automated evidence does not establish those platform outcomes.

The current disposable fixture starts each Hub database/identity, App vault,
Node state, owned HOME and CODEX_HOME under a new task temporary directory. Its
Owner pin is generated from that run's actual App export, not borrowed from an
old installation. However, identity/Node approval and manual pinning precede its
selected-root Node-only component install and old-plugin update. It does not
execute the complete sequence above, default-path installation, service removal,
Windows fallback-vault removal or physical GUI. Those fresh-install/platform
scopes remain **NOT_RUN** until the operator supplies their own receipts.

Root executed a narrower disposable Linux fresh-component slice using the
actual clean-e902 delivery CLI (`3d2e84fde76962ae3e2c7c2e8102ff4526071169a9ee3cd3c7524b0a0c8576f9`):
file-only Hub/Node install; installed Hub setup and private initial-code file;
manual Hub-only-nodes startup/health; component removal retaining existing state;
then explicit deletion of only its owned fixture root and a second install/setup
with all three Hub identities changed. Owned keys/processes were removed.
Receipt `/home/zyf/Cicada/.local/evidence/local-domain-root/clean-e902-component-corrected-qefal3x4/result.json`,
SHA-256 `b65d735465643ad570c4ca788a3593e22c634127ae2bd6ecfccf786806f0830c`,
status PASS. The preceding `clean-e902-component-root-dayf9poj/result.json`
remains a failed operator-command attempt: the test passed an unsupported
workspace-root flag to serve, which correctly refused it. The corrected procedure
passes workspace selection only where supported; no production flag was relaxed.
This component/Hub-local slice does not execute Node enrollment, the complete
user removal/new-install sequence, Windows or public HTTPS. Their NOT_RUN labels
above remain in force.

## 2026-10-23 direct numeric-IP TLS matrix and driver preparation

The user now requires one product Hub process, no domain/Caddy/reverse proxy,
no deployment-preset external origin, and secure App input of numeric IP:port.
The independent [DIP01–12 matrix](native-app-plan.md#direct-numeric-ip-tls-acceptance-driver)
and opt-in selector `TestN3DirectIPTLSAcceptance` are prepared. The shared
Hub/App/Node API is not yet reviewed/frozen; the new runtime test therefore
explicitly skips every DIP case. `scripts/test-native-pair.sh --direct-ip-tls`
must produce NOT_RUN/125 for that complete typed hold, and FAIL for missing cases,
untyped skips, failed compilation, source/binary drift or incomplete cleanup.
The parent test's pass event cannot establish transport acceptance. No new
protocol DTO is invented here and no new product gate has run at this stage.
A separate short `TestN3DirectIPTLSFaultFixture` lane checks only negative-peer
counters, five redirect statuses, untrusted-CA-before-HTTP and real X.509
verification at explicit synthetic validity boundaries. It cannot qualify any
DIP product case or App TLS acceptance.

Existing implementation seams are retained: Node IP locator v2 separates the
numeric socket from stable HubID, logical TLS SAN, SPKI pin, trust anchor and
signed application origin; strict PQ TLS has actual IPv4/IPv6 no-DNS primitive
coverage. The earlier clean-`ab2362f` IP/ARM first-install A2 receipt was rehashed
at its migrated location,
`/home/zyf/Cicada/.local/evidence/legacy/CICADA-data/v00-docker-deployment-20261012/ip-arm64-clean-a2/result.json`,
SHA-256 `9d5395a8e0aabee45e76b2694049252a0953de326342345ec94a63e8099dac5c`.
Its 25 product Node command receipts (13 explicit ARM64 QEMU commands) hash to
`e8a8688f6b7a4ab7dcf634bdbed8450e112109cf35af21564889c53074b08ea3`.
Those old results are bounded protocol/Node/QEMU evidence, not current Windows
App, real public IP, physical ARM or single-Hub first-contact acceptance.

In particular, `firstInstallHTTPSFrontend` in the old
`node_ip_first_install_test.go` creates a test HTTPS reverse proxy to the product
HTTP listener. Its separately enrolled strict Node transport does not qualify
the newly requested direct bootstrap. The old native IP socket test still uses
an independently preconfigured logical service SAN and trust. The earlier manual
HTTPS/origin procedure above retains its dated scope; it does not satisfy the
new no-preset-origin target. No successful existing user Hub/App state was cleared.

Before execution, Root must review the unique shared contract for independent
initial pin/confirmation, TLS/complete-Hub identity binding and signed origin
compatibility/migration. Positive acceptance must include actual App, Node pairing/bridge/relay and
selected-Node MCP whoami/directory/ASK/Reply using the actual product TLS
listener and transport, without a reverse-proxy front, injected test HTTPDoer,
verification bypass or host CA-store modification. Malicious TLS/MITM/redirect
fixtures are separate negative branches, with bounded secret-POST counters and
unchanged unauthorized state. X.509 validity/renewal checks use real verification;
any test clock is explicitly synthetic rather than natural elapsed-time evidence.
IPv4/IPv6 are independent observations; an unavailable family remains NOT_RUN.

The prepared runner retains read-only source/module mounts, task-exclusive build
cache locking, unique output/state/container names, network-none isolation,
pinned image, finite resource/time limits and exact owned cleanup. The final
fresh installation must verify file-only installation, explicit Node start and
later plugin connection using the selected component roots; it cannot borrow old
trust or imply automatic FB-03 delivery. Windows DPAPI/ACL/physical GUI, public-IP
routing, physical ARM, actual-model consumption and the new direct-IP workflow
remain **NOT_RUN** until their own measured receipts exist.

Preparation checks, not direct-IP product acceptance:

- Eighteen synthetic receipt/source cases pass, including complete typed hold
  → NOT_RUN/125 and rejection of parent-only/fabricated PASS, missing or unknown
  cases, unexplained skips, compile/harness/fixture failure, source/binary drift
  and failed cleanup. Receipt
  `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/direct-ip-oracle-preparation-20261023-pg4kz3la/result.json`,
  SHA-256 `5189fe3163b8aab9e9c411e837c931313cb27a2aca7cf5ed799b474882186427`.
- The actual pinned disposable Docker preparation run
  `run-20261023T052729Z-YBwHUA` returns **NOT_RUN / 125** on dirty `3b1186d`
  plus the exact five-path QA preparation overlay. Version, CLI/test compile,
  fault-fixture, harness and vet stages exit 0. Only the seven negative-fixture
  subcases plus their parent pass; all twelve DIP cases skip. No actual Hub,
  App or Node process starts, and this proves neither the new transport nor
  native Windows behavior. Receipt
  `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261023T052729Z-YBwHUA/result.json`,
  SHA-256 `0473a896d8414e3ebcc558094675b45b57d5911946bb5095a3e82930ed9015b8`.
  Source-before/source-after both hash to
  `d6ee3a3472df163c19bc9e410d788136e5a5823c43e778d1544746bd109db080`;
  manifest `51cea0c99512e54e024ee0b417b7bb0a1f50f10b170ca653189fdd3d1472383c`.
  Compiled CLI is 38,141,735 bytes, SHA-256
  `a27680e9d212e224e49d0fd6fd0475a6625ea4d944755712470c467288ca2834`;
  test binary is 24,289,685 bytes, SHA-256
  `d667146559f9412ba676ffcf1b3755168f9832ceed76d1a8bd1c58693912db37`.
  Source/binary hashes are stable, the owned container is absent and the cache
  lock is released. This later record update is outside that run's input snapshot;
  executed Go/script bytes remain unchanged.

Reproduce the preparation only with `scripts/test-native-pair.sh --direct-ip-tls`;
expect exit 125 until the reviewed shared API and actual process assertions are
connected. The fixture's X.509 boundary times are synthetic and its independent
trusted test client is not supplied to the production App. Real deployment,
public IP, IPv6 product execution, Windows and physical ARM stay NOT_RUN.

Additional fixed acceptance obligations, still NOT_RUN pending shared API:
leaf auto-renewal must retain the CA, SPKI, Hub epoch and application identity,
with extended certificate validity verified through the real TLS path. Existing
Hub state with a missing required application key must refuse without recreating
that key or replacing other identities. The selected-Node MCP requestWithGroup
path must exercise the shared transport directly, beyond the Node-private HTTP
client path. These are matrix additions only; no new execution or preparation
commit is attributed to them.

## 2026-10-23 frozen direct-IP driver and independent attack lanes

Root delivered shared contract/client `12fe1be4498780052976570f895b3d1de2a49f3c`
and then App `3a0c632ca5a9af6a33dc80f5ea5ddf248ee229fb` to this task branch.
The following observations are independent scoped checks. They do not establish
the still-undelivered Hub runtime/Node consumer checkpoint, a full DIP pass,
real deployment, real-model consumption or Windows behavior.

The shared production transport was tested against independently generated
synthetic TLS attack sockets in pinned network-none Docker. Twelve events pass,
exit 0: CA/SAN/SPKI and current-clock expired/future leaf rejection before HTTP;
unsigned changes to complete Hub/Node identity, epoch, origin or trust;
canonical locators; all five redirect statuses across three destination modes;
pre-dial Host/Origin/scheme rejection; proxy poisoning; and unchanged trust with
two same-key leaf certificates. This last control is not Hub automatic renewal.
Receipt `direct-ip-shared-faults-20261023-x5mi2trc/result.json` under
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/` hashes to
`a3c9427d7f2bbfa3da209b2afd469ce7b27f7d9ad48f67a11c48cae76fb3ba19`.
Its source is dirty `12fe1be` plus the exact QA overlay, manifest
`3217a36db9d441505fbcb7ddc70ad439d4a590b854da828852c05fd6bdd7618b`;
source snapshots are identical, SHA-256
`252a97958bf1e15fab72fba19cc49b8f1f9efb646800589b92c84b83963994a5`.
The earlier shared-lane attempt
`direct-ip-shared-faults-20261023-6wsk_o7x/result.json`, SHA-256
`215ff0b07786141dcef6f8df5dab78cc4997818f95c1080acc160653eed8ed26`,
retains FAIL/1 with zero test events: its temporary filesystem was non-executable.
This is an orchestration failure, followed by a fresh isolated run with the
executable test temporary directory. Neither receipt was rewritten.

After the formal App delivery, the independent App-negative lane compiles the
entire new driver and invokes the actual separate Controller child with HTTP,
DirectHTTPFactory and Now unset. The Linux password-encrypted vault protector
is synthetic; it does not stand in for DPAPI. DIP03/04/06/07 and their parent
produce five PASS events, with compile, execution and vet all exit 0. Invalid or
expired bootstrap/public-descriptor input, forbidden locators, wrong live TLS
CA/SPKI/SAN/time and 15 metadata redirect combinations leave zero secret POSTs,
zero observed credentials and no vault open/create. Secret-bearing follow-up
actions remain unavailable. The separate shared lane qualifies the corresponding
production transport's secret-request redirect behavior.
Receipt `direct-ip-app-negative-20261023-j38ieqrq/result.json`, SHA-256
`08f9c159486c5ad8a04b200de16dd58a0d25bd8cf6365aeeefa6aa07c82c35d4`,
records dirty `3a0c632` plus seven QA paths, stable source and an absent owned
container. Its source snapshot SHA-256 is
`3c70c5a9fcc879f9928cecd238330a7b9f6ca29f2c4fe6ffd4ea8afa870aa8a2`,
manifest `f7eeab54f5d4640d79a449c058e0c69c96625735cccd36e37dd2b6c97ea1a188`.
The compiled test binary is 24,742,977 bytes, SHA-256
`712fd7b82676060be8c16528fe09190ec00626011a2b013d151a8fa207adae50`.
Later record updates are outside this receipt's frozen input. Reproduce these scoped checks from the retained `run.py` files in
fresh owned directories; historical receipt paths are exclusive and cannot be
rerun in place.

The full driver now calls the frozen product API for twelve cases; no case is
predeclared successful. It installs real component files to a temporary prefix,
then explicitly initializes/starts the actual Hub TLS listener and actual Node.
Both numeric address families have fresh Hub/App/Node state and the unchanged
actual Codex/Hook/MCP short driver, original umask-0002 daemon, static provider,
WHOAMI, directory filters, named ASK/Reply, normal App close and current revoke.
Actual Host coordinates and original request/content digests are checked against
the App's Owner-signed directory read. No native metadata is synthesized.
The manual independent Owner public-pin step remains explicit. Real account
session expiry/new C, paid-model turns and natural certificate-time passage are
outside this short gate.

The DIP12 negative lane forwards opaque TCP bytes while TLS still terminates at
the real Hub. It authenticates a copied coherent encrypted App vault image to
identify a durably pending original read before dropping returned cipher bytes;
it does not infer the operation from TLS record counts. A read-only SQLite
query must prove the exact request digest and committed cached result before
Hub/App restart. Direct recovery must retain original request/response bytes,
one cache row, original device/Owner identities and independently authenticated
App-device ciphertext. The parent retrieves no Owner private key or proof signer.
This code remains NOT_RUN until the real Hub/Node checkpoint is delivered.

The evidence oracle additionally requires exact fixture/case terminal events,
per-case true observations and complete IPv4/IPv6 native summaries. Twenty-seven
synthetic receipt/source checks exit 0, including rejection of parent-only PASS,
missing/false/duplicate observations, missing address families or original ASK
IDs, mismatched App directory/daemon/provider accounting, invented elapsed expiry,
source/binary drift and cleanup/compile/fixture failure. This is schema testing,
not product execution. Receipt
`direct-ip-oracle-integrated-20261023-geka41mb/result.json`, SHA-256
`13e97993ea22cb78552a7c94ad76af83da7c076925fa4f7adb634584c344c9bc`.

The full rerun command is
`CICADA_NATIVE_PAIR_LICENSES_DIR=<reviewed-complete-notices> scripts/test-native-pair.sh --direct-ip-tls`.
Do not run the old Hub CLI as the new implementation. Root must first deliver
the runtime and Node consumers. The full gate and actual renewal, missing-key
startup, retained-origin migration, original-response recovery and dual-family
native business chain remain NOT_RUN. Windows DPAPI/ACL/GUI, physical ARM,
public-IP deployment and final default-root installation remain separate NOT_RUN
items. No shared Hub, public deployment, resident service or real key was touched.

## 2026-10-23 actual native Hub/App scoped integration

Root delivered runtime `a228a1b5d4adce9a90b9f4479ad6c33327f08a7a` after the
formal App checkpoint. Independent QA compiled actual self-contained component
CLI/test binaries and used the pinned network-none Docker envelope, read-only
source/modules/notices and exclusive task build cache. All entries below have
identical source-before/source-after and an absent owned container. The tested
inputs are dirty HEAD plus their exact seven-path QA overlay, never HEAD alone.
Node consumer flags and the full native Codex gate were deliberately not run
against the old Node implementation.

| Receipt under `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/` | Result and scope | Receipt SHA-256 |
| --- | --- | --- |
| `direct-ip-app-negative-20261023-y7bzwte5/result.json` | On dirty `3a0c632`, compile/App-negative/vet all 0; 5 events pass. Adds valid pinned TLS returning a mismatched live Client-Control key, Hub ID or key version. Real App rejects before secret traffic/vault mutation. | `bbfad5e4e6491c00fa067068619509633f1ae98c8d63addac772646bbbedc7e8` |
| `direct-ip-hub-app-20261023-r98xte0u/result.json` | FAIL/1, 0/7 events pass. Six shared prerequisites fail at bootstrap file issuance because the Go fixture's temporary output parent lacks required 0700 mode. This is a QA fixture failure; the CLI correctly rejects it. | `92e5af00205df1cf022c359a3de8799b0b70cdbbdd60520b6ec91765ed747acd` |
| `direct-ip-hub-app-20261023-a0kfcqn2/result.json` | FAIL/1 aggregate, with 5 passed cases: DIP01/08/09/10/11. Actual native Hub/App first setup/activation/login, poisoned proxies/forwarding headers, bounded N2 rights, same-state restart, foreign-Hub refusal, missing keys/bundle/mixed epoch fencing, and stable old DNS/IP-origin cards/keys with explicit locator change. DIP05 and the parent fail because the injected short leaf starts before its newly created CA. | `a7b97ceba02786252c08caf058999248c0d723eeb97daaf44034d7b4b14dde24` |
| `direct-ip-renewal-20261023-b78nvreu/result.json` | Targeted DIP05 plus parent, 2/2 PASS; Go version/CLI compile/test compile/execution/vet all 0. Controlled six-day leaf retains the actual original NotBefore/SAN/key shape and independently verifies at current and explicit fixture verification times. Actual Hub renewal extends validity while CA/SPKI, application keys, old trusted connection material and resumed App identity remain usable. Native/PQ selectors reject before attempting to read the deliberately absent PQ config. | `43f33f1578500a76f4eb82bd365aa64d39664b597ec87f34db615b1a69856177` |

The first bootstrap fixture was corrected by creating a dedicated 0700 private
parent. The later short-leaf fixture was corrected by retaining the original
certificate shape and qualifying it against the installation CA before writing
it. Existing receipts remain unchanged. These independent partial runs are not
combined into a fabricated same-source full DIP PASS; the final gate must run
all twelve cases on the complete integrated product source.

All three Hub/App attempts compile the same 39,031,436-byte CLI, SHA-256
`e34a1fa61d5b66960f8213ed43b5aa8d836eb20fb2198b91918f805394da4cb4`.
The five-case mixed run source snapshot hashes to
`5af02681afab34c0f0be2783b9a194ffe0d805f37d28ff75eb3299e0cf5202be`,
manifest `4a6cb6f34f148ea5a40441612591955f9e3ffeabb9b730d947e3b43715f97c25`;
test binary is 24,768,906 bytes, SHA-256
`49a0596fcfbeb96ee7ee674f6ce8e82df1828c196c0c81df2189ef9bc3b28416`.
The targeted renewal source snapshot hashes to
`f2cf697f108f16383df7b70db7d842c37fe85577d92bcf8a1f3819dde9421f0c`,
manifest `99eaf4f13b2911fcccdf75ffd89175690b8e03ca32365a4362e3749b68f661d4`;
test binary is 24,770,290 bytes, SHA-256
`1ec282eab1e379aae88c435892d82d3b9e2d4760bf42d030e069030000557e68`.
The retained per-run `run.py` files provide exact scoped commands; copy one to
a fresh owned run directory before invocation. They cannot overwrite historical
artifacts. No production implementation was changed by QA.

Root requires current installed Codex 0.164.0 for the new native lane. Read-only
inspection resolves `/home/zyf/.local/bin/codex` to the complete
`0.164.0-x86_64-unknown-linux-musl` package, confirms package metadata and actual
`codex-cli 0.164.0`, and hashes its CLI to
`b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`.
The existing Python ActualCLI/DomainHostCLI consumes the supplied expected
binary hash; 0.163 references there are historical comments, not version gates.
Only the new direct-IP runner/Go/evidence paths select the reviewed 0.164 package,
verify the version and pin, mount the complete package read-only and record its
manifest. Existing 0.163 defaults/hashes and dated gates remain unchanged.
This code review and binary preflight do **not** establish 0.164 native Hook/MCP
compatibility or user acceptance; that result remains NOT_RUN until actual
Node/Host execution.

Thirty synthetic oracle/source checks pass after the version change, including
rejection of a 0.163 runtime/version mislabeled as 0.164. Receipt
`direct-ip-oracle-0164-20261023-yrj9gf1z/result.json`, SHA-256
`7cca934d77c913c33a26e6559894ab91b03277039f26a4f14ecbe0bcc6c2c378`.
This is schema discrimination only. The existing complete-removal chapter now
uses direct native TLS setup/export/bootstrap, same-page App IP/code entry,
explicit new Node descriptor/locator, current Codex, manual FB-03 public pin,
new A/B business work, normal restart/recovery and explicit revoke. It remains
an unexecuted user batch with the agreed roots. No actual cleanup was performed.

Remaining: formal Node consumer delivery, dual-family actual 0.164 Host
WHOAMI/directory/ASK/Reply, the real committed-response-loss recovery lane,
same-source complete DIP gate, final package/default-root batch, physical
Windows DPAPI/ACL/GUI, public-IP connectivity, physical ARM and real-model results.

## 2026-10-23 cipher-fault qualification and Codex 0.164 offline preflight

Work continues on the same seven QA paths after Root's Hub/App checkpoint.
Passing Hub/App product cases were not rerun. The Node-dependent DIP02/12 and
complete same-source gate remain NOT_RUN pending formal Node delivery.

`TestN3DirectIPTLSCipherFaultFixture` now separately qualifies the opaque TCP
negative peer: verified TLS still ends at its synthetic TLS endpoint; arming
alone does not drop traffic; an explicit pending signal permits response loss
only after the endpoint receives its request; and a fresh verified TLS connection
works afterward. Ordinary and race executions each pass, with both compiles and
vet exit 0, stable source and an absent owned container. Receipt
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/direct-ip-cipher-fixture-20261023-o7ozae06/result.json`,
SHA-256 `1d8dda1b0452ba3f84633348e16b6b7a1ed79acc9a932dc4f58052ba5466b7d5`.
This is fault-observer qualification, not an actual Hub committed-result or
original App recovery PASS. The final fixture lane requires this event in
addition to the previously qualified shared/negative socket events.

Actual pinned 0.164.0 also runs inside a fresh network-none container with its
complete package mounted read-only and an empty owned HOME/CODEX_HOME. Version,
existing global flags, plugin help, marketplace help and daemon flags each exit
0. No model, native Thread, Hook or MCP business call starts. Package hashes are
stable and the container is absent. Receipt
`direct-ip-codex-0164-preflight-20261023-_54lyxd0/result.json` under the same
evidence root, SHA-256
`132e44f4c848dec22b85641d433120615ddc3b439ec3181ea5f12dba142d4cad`.
Earlier preflight receipts retain FAIL/1 despite all individual CLI commands
exiting 0: `direct-ip-codex-0164-preflight-20261023-u1w5s2q2/result.json`, SHA-256
`63ff47f49da2bba15d4d91026858c0f8b853317cc634defd43fc6047868141f8`,
used an absent CODEX_HOME; `direct-ip-codex-0164-preflight-20261023-krlcftsc/result.json`,
SHA-256 `135942bcce923d2b4a31623c06fb6e0eace4e9900c419eb668f7e42ea230dcb1`,
used CODEX_HOME under `/tmp`, where Codex refuses helper aliases. Their combined
stderr/stdout failed the fixture's exact version check. The successful fresh
preflight uses a precreated owned HOME under a separate `/work` mount. These
fixture conditions are not 0.164 product defects or native compatibility results.

The future native revoke check is also tightened: it must observe a new
authorized Node heartbeat in the existing `machines` row through a read-only
SQLite connection after the App's authenticated revoke response. Merely live
Hub/Node processes cannot qualify healthy-service refusal. The per-family
summary records ordered commit/heartbeat timestamps. This Node-dependent
observation remains NOT_RUN. Thirty-three synthetic oracle/source checks pass,
including rejection of stale/missing/malformed heartbeat evidence. Receipt
`direct-ip-oracle-final-preparation-20261023-s5_d1r1k/result.json`, SHA-256
`70d07917d65f15a595103a8e1dce1b3016b31db19a828bd1bf2526c13927d198`.
It qualifies receipt discrimination only; no platform or product pass is inferred.

Further offline 0.164 checks use the actual pinned executable's own generated
experimental RPC schema, with no daemon/native/model runtime. All seven methods
used by the retained driver are present (`initialize`, plugin/hooks list,
MCP status, Thread resume/read and turn start). Ten AST-observed driver calls
have no missing required keys or unknown parameter names against that schema;
this is not full value validation or actual protocol execution. Successful
export receipt `direct-ip-codex-0164-schema-export-20261023-33sp31q1/result.json`,
SHA-256 `84ab3f4e28f78ccf9ec525deaf97e901264e24fec7cbfb21912c4486f9cbae0d`;
its `driver-parameter-shape.json` hashes to
`6da1d3f738399e81ebc15c6039c4fd1e134a769bc2e7c8c8d9a0cd537ccc01ba`.
The earlier export attempt retains FAIL/1 at
`direct-ip-codex-0164-schema-export-20261023-tbjkl8cu/result.json`, SHA-256
`babd74cfe0402a0804c90d53aa0a69b820ecd5d3c3c1da8b6fdfeaab6ffb4c8e`:
that code-generation command rejects `--strict-config`. Removing that flag for
the standalone offline schema export succeeds. The actual driver never invokes
schema generation and was not changed. Normal driver global/plugin flags keep
their separate successful preflight receipt.

The cipher fixture's normal test binary is 24,776,581 bytes, SHA-256
`b55cad4984aa40a8df0f18553c587c6d714b400882a17c8e8f40723e310b9eed`;
race binary is 37,533,121 bytes, SHA-256
`c6eb50f3c2155c81f57a342864a9047d5a715a1a3cfe44d3c5c3ab0d86da9b45`.
Its identical source snapshots hash to
`8d3b864b73fc7a7234790227a5d960f906c5beb5dfeb32e2d57eabfe16952c61`,
manifest `7465ceb1894c0e11c7a6d6e16ac0d89d2622665f2269ce6787be6bd1692bc889`.
Later read-only heartbeat-witness/record edits retain their own unexecuted Node
scope; they do not change attribution of the earlier fixture qualification.
The final renewal case additionally exports and byte-compares the actual saved
public descriptor after renewal, covering the persisted epoch/signature directly.
This added assertion awaits the final integrated gate; the scoped renewal PASS
is not rerun or extended by inference. New direct-IP summaries also distinguish
an observed owned native daemon from untouched resident deployments; an absent
completion summary leaves owned-daemon activity UNKNOWN.
The completed driver then passes compile and vet, with zero runtime test events,
in `direct-ip-driver-compile-20261023-o7c8hdms/result.json`, SHA-256
`4d8899ab7f808068854d1cbd0ea17e2f7ab33f965c16d0295a95ec3bdc29c14b`.
This is preparation for the formal Node delivery, not a rerun of passed product
cases or qualification of pending assertions.

## 2026-10-23 complete direct-IP TLS integration

The same-source complete gate is **SCOPED_PASS / exit 0**. Root formally delivered
Node consumers at `e8d31c693da00adaf0870c7dbf793c61e9e9c423`, including the
earlier frozen shared client, App and Hub runtime checkpoints. QA changed only
the seven acceptance/record paths. The tested source is dirty `e8d31c6` plus
the recorded QA overlay, not the clean product commit alone. This final entry
supersedes the preceding preparation entries' pending status for DIP01–12;
their historical failures, source attribution and narrower scopes remain intact.

Reproduce from this task's acceptance checkpoint, using matching reviewed complete
component notices and the pinned complete Codex 0.164.0 installation:

```sh
cd /home/zyf/Cicada/.worktrees/cicada/n2-acceptance
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/codex-startup-fix/licenses-x4gog722 \
  scripts/test-native-pair.sh --direct-ip-tls
```

Each invocation allocates fresh owned evidence/artifact/state directories and
ports. Historical run directories must not be reused. Exit 0 requires all
measured product/fixture cases, both native summaries, stable inputs/binaries
and cleanup; gate failure returns 1, invalid invocation returns 2, and a rejected
preflight returns nonzero before product execution.
The earlier preparation-only typed 125 receipt is not a product PASS.
The pinned image is
`golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
The network-none, nonroot, read-only-source/module-cache container uses only
owned persistent databases, vaults, HOME/CODEX_HOME and an exclusive locked
task build cache. Actual Hub processes terminate positive TLS directly;
the opaque TCP loss peer exists only in the negative recovery case.

Final receipt:
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261023T083550Z-ID83rd/result.json`,
SHA-256 `a232c4498906169f36421b54699fb481e7c7a132c79c6b17994006c42ca1eebd`.
Version, CLI compile, test compile, fixture, product harness and vet all exit 0.
All twelve named DIP cases and their parent pass; all 21 named fixture events
pass. There are **zero skips, zero missing cases and zero unavailable diagnostics**.
The corresponding package terminal events also pass; they are not extra cases.
Both exact fact-set and native-summary validators return true. Source and
executed binary snapshots are identical before/after, and the exact owned Docker
name/label is absent after execution. No shared development Hub, resident
daemon or public deployment was touched. Only owned native daemons were started.
After the run, only the plan's result/status prose and this validation record
were updated. Rechecking all 1,533 recorded inputs finds only
`docs/native-app-plan.md` changed; the other 1,532 inputs, including every Go,
plugin and driver input, still match the tested manifest. The final commit's
documentation therefore has its own later attribution; no clean-commit rerun
is claimed.

| Final artifact | SHA-256 / size where relevant |
| --- | --- |
| Source snapshot, before and after | `3363eabb8cb82410b522c4d1902a9580ccf17adf7a12c204b95519902eb89390` |
| Source manifest, 1,533 inputs | `ce47ebac2f174a494ab5b49d61383119b0676747d93eedd4740d804e01582a0c` |
| Actual CLI | `0b7e633a88734f9b5973d49f3490feca8fad60a75a3d22c2b861ab191dca39a7`, 39,090,423 bytes |
| Actual test executable | `d27b3f64bbe41813eb7c5aff57f998ca31a252f584ec18c8d7515c215125b00a`, 24,781,766 bytes |
| Binary snapshot, before and after | `ddc21809665c21c32befe7ce055618404c6c8836874f833c7f18ddeef1e2c619` |
| Dual-family native public summary | `cbd3ee1e3066dd5514e1612946d7b4296f05057e9b441c2e2198788a07e2e7cb` |
| Actual Codex CLI, 0.164.0 | `b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`, 308,139,304 bytes |

IPv4 and IPv6 each use a fresh Hub/App/Node and the actual existing native
daemon/plugin/Hook/MCP path. Each completes 36 Host calls and 74 static-provider
POSTs (72 Host-provider plus two native-queue POSTs), with zero literal-provider
POSTs and zero real-model turns. Actual original SIDs/workspaces/Endpoints and
request/question/answer digests match the App's Owner-signed directory.
The existing independent manual Owner public-pin step is explicit. Both families
complete WHOAMI, positive/negative directory filters, named selected-Node
ASK/Reply, normal App close with continued authorized communication, original
profile resume and explicit current-policy revoke. New directory/business work
then refuses while the original Node has an authenticated heartbeat newer than
the revoke commit. Relay-only worker presentation is not used as Node liveness.

DIP09 separately observes Root proof before ordinary login, zero implicit
authority from discovery/login, finite N2 scope, unavailable Manager/canvas and
the complete identity flow with Control inference disabled. DIP05 verifies actual
near-expiry Hub renewal with a deliberately shortened valid synthetic leaf,
retained CA/SPKI/application keys and byte-identical saved signed descriptor;
this is not natural wall-clock certificate expiry. DIP10/11 retain original
trust/identities across restart and explicit locator changes, reject missing or
mixed key/epoch state without regeneration, and preserve legacy DNS/IP origins.

DIP12 drops 4,118 returned TLS ciphertext bytes after observing the actual
pending original encrypted App read and independently finding its committed
SQLite result. The original protocol request digest is
`465eac05839ace62fb8fd3b46b0dcafb430e27f33c5c76fc19ce19f768c2c169`
(`wire.AppNodePacketDigest`, not generic SHA-256); cached response SHA-256 is
`4e5fdbd6cb17cadf01bce0abd011d19980fa565d371960395a6a7ba8ab80b131`.
Actual Hub/App restart and direct recovery preserve original request/response
bytes, public identities and exactly one COMPLETED cache row. The parent uses
the original App device to decrypt/authenticate the original result and retrieves
no Owner private key. The applied Owner-directory receipt is exact; an optional
subsequent applied read-only Node-status refresh is independently authenticated
and cannot substitute for that original receipt.

Retained same-product-source attempts under the same evidence root:

| Receipt | Actual result and correction | Receipt SHA-256 |
| --- | --- | --- |
| `run-20261023T080001Z-FBcCxw/result.json` | FAIL/1. Ten DIP cases pass; DIP02 calls the wrong retained Python entrypoint and DIP12 compares the domain-separated request digest with generic SHA-256. QA now calls the existing `codex_domain_native.py` and the actual protocol digest function. | `592005de3b0bf1e61f852554708dc04df6629ba7f857f8b5e728b2d557576085` |
| `direct-ip-node-native-recovery-20261023-x7vqasgt/result.json` | Targeted FAIL/1. Actual native work reaches the revoke checkpoint, but QA wrongly requires relay-only worker status to be online. Recovery also has an overstrict applied-state qualification. | `d6f49c2e7de19f29c0536563bce3b88d7f6d358f638664ed93081d7d56415173` |
| `direct-ip-node-native-recovery-20261023-oxzgccjh/result.json` | Aggregate FAIL/1; DIP02 passes both families, DIP12 fails. Recovery can legitimately retain the applied read-only status refresh created after original-directory recovery. The fixture now checks that refresh independently while still requiring the exact original directory/ciphertext, COMPLETED state and count one. | `37b1d37bdb5bdec13285011829ec6d75e6a6efc68cad76d2bae0899f7b6e5a73` |
| `direct-ip-original-recovery-20261023-nf08em6l/result.json` | Targeted DIP12 plus parent PASS/0, all five execution stages 0; exact original result and one cache row verified. This targeted receipt is not promoted into the complete gate; the final fresh full run above supplies that evidence. | `25903d5bcf35c421dc6f5b05a211260df179ed8c8db01ce1f3fd3799c1d9c604` |

These are acceptance-fixture defects, corrected without production changes or
weaker crypto/commit/exact-recovery requirements. No new unresolved product
defect was observed in the frozen twelve-case scope. Root's clean-e8 standard
disposable interop and producer normal/race receipts remain separate evidence;
this full gate does not relabel a producer's retained aggregate race timeout.

Remaining **NOT_RUN**: physical Windows DPAPI, ACL and GUI individually; public
numeric-IP routing/deployment; physical ARM; real-model provider consumption;
complete physical removal/default-root installation and the final package's
user-operated batch. Automatic FB-03 Owner trust delivery remains
NOT_IMPLEMENTED/NOT_RUN. Natural full account/lease or certificate-time expiry
is outside this short gate. Linux encrypted-vault and static-provider results
do not establish those outcomes. No credentials, private keys, full sensitive
payloads or synthetic fixture deployment initialization are delivered as evidence.

## 2026-10-23 user-reported fresh Hub and Windows App batch

After following Root's complete Hub/Windows fresh-install instructions, the user
reported “完全正常、符合预期。继续” (fully normal, as expected; continue).
Root relayed that report to independent QA for this record. This batch is
**USER_REPORTED_PASS**, attributed to complete ZIP SHA-256
`fb73d158b3466e868aacc427c67d36c395fce769f394c4e951485002e2a6ea5d`
and production source `e8d31c693da00adaf0870c7dbf793c61e9e9c423`.
The archive hash identifies the delivered package; it is distinct from the
production Git revision and the QA checkpoint. The user supplied an overall
confirmation, without raw command output, exit codes, screenshots, TLS traces,
ACL listings or exact public-identity comparisons. This entry therefore does
not claim independent physical execution or invent individual measurements.

| Instructed batch item covered by the overall confirmation | Recorded result and limit |
| --- | --- |
| Clear the old Hub/App installation state and perform new Hub/Windows App setup | USER_REPORTED_PASS for the instructed Hub/App slice. Independent QA did not inspect deletion completeness or run cleanup. This does not complete the Node/plugin portion of the full removal procedure. |
| Reach the single Hub at public numeric address `198.200.39.92:8787` using its built-in TLS | USER_REPORTED_PASS for the instructed public connection. No independent network/TLS probe, certificate-chain capture or adversarial transport check was supplied by this physical batch. |
| New Owner setup and separate account login/logout | USER_REPORTED_PASS for the instructed positive identity/account flow. No new evidence that login creates Root or any broader Node/Network authority is inferred. |
| Restart and recover the Hub/App configuration/profile | USER_REPORTED_PASS for the instructed restart/recovery flow. Exact retained key/identity hashes, original-packet reconciliation and failure injection were not supplied for this physical execution. |
| Address copy and the exercised Windows App controls | USER_REPORTED_PASS for the instructed interaction. This does not establish comprehensive GUI, clipboard secrecy, DPI/font or multi-instance acceptance. |
| Windows vault ACL inspection | USER_REPORTED_PASS for the instructed positive inspection only. No raw ACL listing or independent cross-user access attempt was supplied. |

Independent Windows DPAPI execution and cross-user/copy/tamper negative tests
remain **NOT_RUN**. Positive user-observed Windows interaction and ACL inspection
do not become an independent GUI/ACL security PASS. Independent public-IP
verification also remains NOT_RUN; its user-reported positive connection is
recorded separately above. The preceding automated gate and historical platform
limits retain their source-specific attribution.

Node cleanup/reinstallation, service setup, new Node approval/Owner public pin,
plugin installation/connection and new A/B native business work are **NOT_RUN in
this batch**. Root is preparing the next operator batch; the user's “continue”
does not supply results for it. No new product defect was reported. This
documentation-only checkpoint performs no test, deployment, cleanup or key/state
operation and does not change the earlier automated receipts.

## 2026-10-23 password Enter submission checkpoint

App delivered `e1331dfa440e553b06a94a3c45e9d55e90f61f76`, parent `a22cb4b`.
The password editor consumes the actual Gio SubmitEvent and routes it through
the existing login action only when that action is available and ready. It
preserves exact masked password text, prevents duplicate/busy submission and
does not turn setup, activation or recovery into login. Portable Editor/Router
checks cover Return, keypad Enter, newline submission, disabled/readiness cases
and synthetic IME composition/commit behavior. Physical Windows keyboard/IME
behavior remains **NOT_RUN**; this is not a new physical result for the earlier
complete ZIP or the user's preceding batch.

Producer receipt
`/home/zyf/Cicada/.local/evidence/n2-app/password-enter-a22cb4b-20261023/result.json`,
SHA-256 `d2f28cc4f184db9311839b0b309f7f5dbb8b57126c46b77e387659b1d99784b1`,
records **194 pass / 0 fail / 0 skip** named events including subtests in each
normal and race run. Linux vet, Windows vet and Windows cross-build all exit 0.
Independent QA read the production change and counted those retained JSON test
events without rerunning them. Root's independent review matches all 1,462
selected source inputs to the delivery, receipt
`/home/zyf/Cicada/.local/evidence/local-domain-root/password-enter-root-review-20261023.json`,
SHA-256 `3457700ad56105db4d1c6ece6cb0a74a46a298c45e00e01ea099b1f694c0c5ce`.
The producer ran dirty `a22cb4b` plus its exact App inputs; the later README is
not a Go input. Stable source-manifest SHA-256 is
`abaaf4ad71c335b0700aa8f03334cd0f97237af8306ba9b0323434a1e60c41e1`.
The retained 14,387,200-byte Windows build hashes to
`a8bcee111b9ab939b0faae52bfbed63c67b7c0b4c5a6aad5778195cfe8a06056`,
independently checked by QA. No new Hub/Node interop, real deployment or resident
installation was performed for this UI-only change; no old gate is rerun or
extended. Windows GUI/DPAPI/ACL and physical input/IME acceptance stay separate.

## 2026-10-23 Node address and device-code design review

Status: **DESIGN_REVIEW / PROTOCOL_NOT_FROZEN / NOT_RUN**. The user corrected
onboarding to Node input of only the Hub address, Node request/display of a
device code, App input/review/one approval, Hub-maintained identity binding and
later separate business permissions. Manual Owner public-key/fingerprint and
descriptor transfer are not the selected new workflow. QA has only read the
current code/contracts and reviewed Root's proposal; no new endpoint, executable
driver, protocol implementation or repeated task book is introduced here.

C0.1 v1.1 already supplies pure S/O/E, separate signature/KEM possession,
private ACK and exact-original concepts. Its public availability remains false
and its Store/HTTP/three-component carrier remains unimplemented. Its existing
186-event pure check is historical, not a new Node integration result. Root's
current narrower proposal instead extends the original Node INITIAL flow with
a side record bound to its exact request/version/digest, complete Hub CC/NC,
Node identity and descriptor, plus commitment O to independent local S. The one
new code carries selector/S/context to the already trusted App. The App would
issue an Owner-to-Node capsule containing S, independent X and full scope, with
a purpose-specific proof/ACK commitment bound to the original confirmation
packet. Hub would retain OWNER_APPROVED until the Node verifies S and durably
saves its exact signed ACK; only then would the original confirmation transaction
activate the binding. This is a proposal, not an accepted or delivered interface.

The following constraints must be explicit before independent security acceptance:

1. **S must never reach Hub plaintext.** The complete new code cannot be passed
   unchanged into old preview/prepare/`nodes.confirm` code fields: Hub decrypts
   those requests. App must retain S locally and send only the selector/commitment
   and Owner-to-Node ciphertext on Hub-visible paths. Logs, error strings and
   diagnostics must not print the complete new code. A fake Hub with its own
   valid-looking TLS/PQ/Owner keys must still lack S and fail local capsule trust.
2. **ACK must fence every confirmation writer.** Existing legacy
   `nodes.confirm` and finite N3 confirmation both reach
   `confirmNodeControlKeyRequestTx`. A new route-only check is insufficient.
   New INITIAL requests must be durably marked before exposure and cannot
   activate via the old path, missing-side-record fallback, a different App or
   an alternate mode. ACK verification, one-time consumption, binding effects,
   counters and exact receipts need one writer transaction. Failures roll back
   all effects; concurrent original retries have one result.
3. **Deferred confirmation needs an exact durable slot and deadline.** Retain
   the original App packet/digest/counter and Node ACK bytes before sending.
   OWNER_APPROVED cannot be mislabeled as completed `nodes.confirm`. Later
   counter use, response loss or restart cannot justify resealing or re-signing
   the App request. Node completion must need no live App callback or new Owner
   signature after bounded approval is committed. Current security revocation
   and immutable deadlines still apply; a historical/fake clock cannot rescue
   an unadmitted expired confirmation.
4. **Candidate TLS is not independently trusted TLS.** Certificates obtained
   from a failed empty-root handshake and its descriptor GET remain CANDIDATE.
   The second connection must still perform chain/name/time checks and match
   the fetched descriptor's CA/SPKI/CC/NC/epoch; merely keeping SkipVerify false
   does not independently trust a root obtained from that same peer. Restrict
   this client to bounded public discovery, no redirects/proxies or credentials,
   and never reuse it as an authenticated general client. App must match the
   complete candidate against its already pinned Hub before signing. Pre-trust
   polling/ACK cannot fall back to the old bearer-header polling path.
5. **Local pin and confirmed admission are separate facts.** Crash after a
   verified durable pin but before Hub ACK is not registered/authorized success.
   Preserve that pin and the exact pending operation without silently replacing
   either. Conditional local writes must reject changed/revoked/foreign existing
   trust and concurrent replacement; late replies may reconcile history only.
6. **Confirmed-Node trust-only use cannot impersonate INITIAL.** A confirmed
   Node must not create a new binding/bearer, reset epochs or revive trust through
   this fresh flow. Either reject that use or freeze a distinct, genuinely
   Owner-approved trust-only operation bound to the exact current original
   binding/Owner/Node/epoch, with zero registration or business-grant effects.

Minimal future integration matrix; every row is **NOT_RUN for this new flow**:

| Observation/fault | Required result |
| --- | --- |
| Fresh Node with Hub address only | Actual request/code, actual App review/approval and automatic independent pin; no manual key/descriptor transfer |
| Fake Hub/self-signed false Owner | No S/bearer disclosure, local trust installation or binding; same-response pin comparison cannot pass |
| Wrong Hub/Node/Owner, changed request or missing key possession | Exact complete candidate/scope, proof and ACK mismatch refuses without mutation |
| Guessing/rapid requests | Frozen finite attempt/resource limits, no foreign-candidate disclosure; issuance cooldown alone is not a guessing-defense result |
| Concurrent approval/ACK and duplicate request | One consumed approval/binding; exact originals return the same receipt, changed bytes conflict |
| Expired code/proof and stale epoch | Strict original deadlines and current security state; poll/restart never renews them |
| Revoke during approval or before ACK | No new effect after the applicable fence; historical receipt cannot revive admission |
| Loss before forward or after commit | UNKNOWN retains original bytes; authenticated original receipt or terminal no-effect settlement, never a guessed outcome |
| Node/Hub restart, local pin/ACK crash windows, App closed | Original keys/pin/packets recover; bounded committed approval requires no live App; no silent first setup |
| Registration versus business rights, existing confirmed Node | Necessary own-state only until separate grants; no Root/Manager/peer/Worker rights or trust-only re-enrollment; Control-off identity flow |

Reuse pure `TestInstallationRegistrationHubCannotSelfCertifyOwner`, dual KEM/
subject ACK and exact/historical wire tests, existing candidate CAS/one-time
device-code checks, and N3 process/commit/fault/epoch fixtures where their frozen
semantics apply. The old device-code Store checks mainly establish issuance
cooldown/create capacity, single consumption and legacy binding behavior; they
do not prove the new first-trust or brute-force matrix. The previous DIP02 used
manual descriptor and Owner public-pin input and cannot qualify this replacement.
Actual future tests must use real crypto/TCP/persistent owned state and disposable
Docker with read-only module cache. No tests or services were run by this review;
Windows/platform and new end-to-end results remain NOT_RUN.
