# Existing-key Windows Owner signer validation

Status: **unreleased source checkpoint; bounded tests/builds and OpenSSL compatibility SCOPED PASS**.
The new local helper retains the user's existing encrypted ML-KEM-768 and
ML-DSA-65 PEM files and uses the existing finite `owner-bootstrap-v1` ceremony
against the same software 0.0.5 Hub. It changes no Hub schema, wire, Client
contract or operation catalog. No resident Hub or real Owner key was used.

## Current evidence — 2026-10-14

| Check | Result | Scope |
|---|---|---|
| Core e2ee/clientwire/ownerbootstrap normal tests | PASS | 61 top-level tests and 142 subtests; one separate opt-in OpenSSL test SKIP |
| Same three packages with race detector | PASS | Same bounded selectors; no race reported; the same OpenSSL test SKIP |
| Same three packages vet | PASS | Exit 0, no diagnostics |
| Frozen bootstrap and Client-wire public vectors | PASS | Ordinary tests read and verify unchanged fixtures; external private-operation path also verifies the published bootstrap vector |
| Trusted vs externally checked packet benchmark | PASS (measurement only) | Synthetic 512-byte frames, Linux amd64, 200 iterations twice; no pre-change timing baseline or Windows performance claim |
| Current Client contract check | PASS | Supervisor ran `python3 scripts/client-contract.py check`: v1.6.5, catalog 55, unchanged catalog digest `a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9` |
| Pure web-panel configuration checks | PASS | Supervisor ran 38 checks; this is not browser or Docker acceptance |
| Test-tagged real web-panel WASM gate | PASS (bounded) | Security ran the offline build with pinned Go 1.27.1 / Node 24.16.0; crypto, wire, public-file, grant-summary and model gates passed after an initial test-order failure was repaired. This is not full Chromium, enrollment or Windows acceptance; artifact and log identities below |
| External profile filesystem/state tests | PASS (mock only) | Unix normal and race: four top-level tests plus 23 subtests each, zero skips/failures; ownersigner vet exit 0. The version-only mocked executable performs no private crypto operation |
| External provider/CLI tests | PENDING | Await current signer tests and exact source attribution |
| Linux synthetic OpenSSL PTY bootstrap | PASS (bounded compatibility) | Final current-helper run `d68c9e32e4894e11` against the immutable older Hub; pure Hub-only CLI setup/issuer, real private proof, deliberately lost response, restart, exact recovery, grant and manager enrollment. Earlier `f16be3cf9d614be0` and two harness FAILs retain their source attribution |
| Final Linux amd64 production CLI build | PASS (compile) | Final post-extraction/UI source, pinned Go 1.27.1 CGO0 trimpath build exit 0; artifact hash below, no embedded provenance/package |
| Windows amd64 production CLI cross-build | PASS (compile only) | Final post-extraction/UI build exit 0; pre-extraction `61a115...` artifact retained separately. No Windows execution |
| Full CLI Windows test-package compile | NOT_RUN | Root did not run this command; the earlier unverified blocked-test report is withdrawn |
| Owner-signer Windows test-binary compile | PASS (compile only) | Final pinned builder compile exit 0; exact artifact hash unchanged from the separate pre-extraction compile. No Windows tests were executed |
| Native Windows execution and ACL enforcement | NOT_RUN | No Windows execution or filesystem ACL acceptance recorded by us |
| Real user Hub / public HTTPS | NOT_RUN | No user deployment, real key or HTTPS bootstrap performed by us |
| Android / physical device / Native Runtime | NOT_RUN | No new Android, hardware or model/provider acceptance |
| Helper packaging identity | NOT_PACKAGED | Raw final binaries and exact hashes are recorded below; no embedded provenance or delivery package. Software remains 0.0.5; no release/version bump |

The core tests ran in the pinned offline Go 1.27.1 image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
with `GOMAXPROCS=2`, network disabled, `GOTOOLCHAIN=local`, `GOPROXY=off`,
`GOSUMDB=off`, a task-owned build cache and the existing read-only module cache.
From `cicada-go`, the recorded commands were:

```sh
go test -json -p=1 -count=1 -timeout=180s ./internal/e2ee ./internal/clientwire ./internal/ownerbootstrap
go test -json -race -p=1 -count=1 -timeout=180s ./internal/e2ee ./internal/clientwire ./internal/ownerbootstrap
go vet ./internal/e2ee ./internal/clientwire ./internal/ownerbootstrap
go test -run '^$' -bench '^BenchmarkPrivateOperationsEnvelope$' -benchmem -benchtime=200x -count=2 ./internal/e2ee
```

Evidence is in
[`core-a1`](../.cicada-data/windows-owner-openssl-20261014/core-a1/):
`normal-frozen.jsonl`, `race.jsonl`, `vet.log`, their separate stderr logs and
`benchmark.log`. All four commands exited 0. The explicit skip is
`TestExternalOwnerOpenSSLRealSignatureInterop`: its independently verified
OpenSSL executable was not supplied to these core commands. A skip is not a
pass. Earlier `tests.jsonl` and `normal-final.jsonl` predate the final trusted
packet-path allocation adjustment; use `normal-frozen.jsonl` for the frozen
core source.

The tests include exact route and envelope-sequence refusal before private
callbacks, Hub-signature refusal before decapsulation, expected-public-key
verification of provider signatures, shared-secret length/authentication/error
handling, cleared provider buffers, unchanged frames, and one challenge
opening before review followed by one signature without a second opening.
Ordinary opaque-key packets do not perform the external provider's additional
self-signature verification or recipient-public-key validation.

The seven tested core files are individually hashed in
[`core-source-files.json`](../.cicada-data/windows-owner-openssl-20261014/core-a1/core-source-files.json)
(SHA-256 `fd4ef319eec675533731de0e565f3026c56105a621033f0079f39a7719d04f0b`).
This is a bounded file inventory, not the integrated build-input fingerprint.
The core-test source was captured from the worktree based on `9fa3628` with
uncommitted changes; its results are not attributed solely to that HEAD. The bootstrap fixture SHA-256 remains
`72cf15e62f1745a8ddbc9021b278d4f3ac03c2d51be2dcd95df6779b0b60ce47`.

## External profile filesystem/state evidence

The Unix-only `TestExternalOwnerMetadata*` tests cover fresh absent-directory
preparation, protected permissions, no overwrite, independent-opener locking,
identical manifest export, exact public pins across reopen, unsafe modes and
symlinks, mixed native/external formats, missing marked metadata, strict JSON,
changed executable hashes, malformed/mismatched saved packets, and refusal of a
malformed cached receipt. Persisted profile bytes are checked for the synthetic
PEM sentinel, full synthetic private identity and plaintext nonce encodings.
The mock executable answers `version` only and refuses every private operation;
these results do not establish OpenSSL interoperability or Windows ACL behavior.

In the same pinned offline builder and Core-owned task cache:

```sh
go test -json -p=1 -count=1 -timeout=180s -run '^TestExternalOwnerMetadata' ./internal/ownersigner
go test -json -race -p=1 -count=1 -timeout=180s -run '^TestExternalOwnerMetadata' ./internal/ownersigner
go vet ./internal/ownersigner
```

Each command exited 0. Normal and race each passed four top-level tests and 23
subtests with no skips or failures. Evidence is
[`core-profile-a1`](../.cicada-data/windows-owner-openssl-20261014/core-profile-a1/).
Normal `tests.jsonl` SHA-256 is
`37ee309d0e89cec682bf355e008f57edfe8eb89a2a0c26c193223000337a50ea`;
`race.jsonl` SHA-256 is
`d4053ea8bdc6aa317bcbeecfb984ff91fc5fd550936f2d7bb9bce8651750d4a2`.
Their stderr logs and both vet logs are empty. The frozen test source SHA-256 is
`e4775de4b5a474756c07d29dd5aa39a405d60681c62635fc97bc1576bd3141aa`,
recorded in `test-source.json`. This is checkpoint working-tree evidence with a
bounded test-source inventory; integrated build and artifact identities remain
separate.

## Actual OpenSSL finite-bootstrap gate

The independently inspected
[run `f16be3cf9d614be0` result](../.cicada-data/owner-openssl-bootstrap-runs/run-f16be3cf9d614be0/result.json)
records **PASS**, finished `2026-10-14T03:13:43Z`. Its SHA-256 is
`7f1538a9cc1b27800d0afbab6c96361c7c1e751aae64cb8eb38d43afd1130d48`.
The scope is synthetic Linux OpenSSL PTY plus an owned disposable software
0.0.5 Hub and the existing Client SDK/CLI. It is not native Windows testing.

The exact tested inputs were:

- Dirty Linux helper SHA-256
  `f0d7216b14daca417cd683bd55646a4fe87370cf93f07b78b4be6f426e9518f0`,
  independently matched against
  [`cicada-linux-amd64`](../.cicada-data/owner-openssl-check-20261014/cicada-linux-amd64).
  It reported `cicada 0.0.5`; it is a checkpoint build from uncommitted source,
  not the clean `9fa3628` artifact or a final 0.0.6 Windows helper.
- Observed repository HEAD `9fa3628d593755ce21476193ef70316be07742f6`, distinct
  from the dirty helper bytes. The run does not supply an integrated source
  fingerprint; no result is attributed solely to HEAD.
- Existing Hub image
  `sha256:fc90076f45293a36d304dd7e31d00b6052828c0b1748fdde2c616b5900ebe9d1`,
  not rebuilt by this driver.
- Driver SHA-256
  `ddfd2a64fc24135d2474ca4f6db1ecb488ffb85b8d866bda004d974301849375`.
- Real OpenSSL version `3.5.9` and executable SHA-256
  `06b318f0242a3ec9add593f5210b163ebaa7c76175009600d2704551cb8e6c05`.

The driver created obviously synthetic encrypted ML-KEM-768/ML-DSA-65 keys,
prepared public profile pins, performed TTY finite challenge issuance, and
submitted the first Root proof. It deliberately dropped the accepted HTTP 200,
restarted the **same** disposable Hub with the same state, then recovered the
exact saved proof and byte-identical cached receipt. The Root was `ACTIVE`.
It subsequently signed the existing canonical OwnerDeviceGrant, wrote the
separate summary, enrolled the management Client, and observed the manager role
and `approvals.decide` / `intent.submit` availability. This run did not exercise
Node INITIAL; its separate earlier checkpoint remains separately attributed.

The owned Hub mounted only `/state` and `/workspace`, with no Owner profile or
key mount. Bounded state checks found no synthetic private-key bytes or test
passphrase. The local loss proxy persisted no raw packets. The separate
[cleanup receipt](../.cicada-data/owner-openssl-bootstrap-runs/run-f16be3cf9d614be0/cleanup.json)
(SHA-256 `c439fff015e747685c189d649b2d4885e3109bf4d020f1013f881ffa992e6aea`)
records container removal, stopped proxy and removed private scratch. Images
were retained (`images_removed=false`); cleanup is not described as removing
those images or modifying any resident deployment.

Two earlier harness attempts remain **FAIL**:

- [`a7bd780cf58e4590`](../.cicada-data/owner-openssl-bootstrap-runs/run-a7bd780cf58e4590/result.json)
  stopped at `owner-prepare-openssl` with `TTY command returned no final JSON result`;
  result SHA-256 `7639003ef655965691eabefaabc24df1bb7a557e79e55c64ecb4afbf975fe456`.
- [`7be76c3826724baf`](../.cicada-data/owner-openssl-bootstrap-runs/run-7be76c3826724baf/result.json)
  stopped at `client-prepare` with command exit 1;
  result SHA-256 `5dc90f94e6f69b7ffe02ca8174db0ae2e25eb8cbfb05a048eb2a74d361d2d8c2`.

Both attempts have retained cleanup receipts; the first created no container,
and the second removed its owned container. Their raw result records name the
failed phases, not a complete diagnostic cause. The later passing run does not
relabel them. Actual Windows/ACL enforcement, Android, physical devices, native
Node Runtime and the user's public HTTPS remain NOT_RUN.

## Web-panel WASM evidence

Security ran the current real test-tagged WASM gate with:

```sh
CICADA_WEB_PANEL_OFFLINE=1 \
CICADA_WEB_PANEL_GOMODCACHE=/home/zyf/CICADA/.cicada-data/m1-gomodcache \
CICADA_WEB_PANEL_GOCACHE=/home/zyf/CICADA/.cicada-data/web-panel-onboarding-security-cache \
  scripts/build-web-panel.sh
```

The final command exited 0 with pinned Go 1.27.1 and Node v24.16.0. The initial
attempt failed because a test used `grantVector` before initialization; that
source test-order failure was repaired before the passing rerun. It is not
relabeled as a passing initial attempt. The passing
[log](../.cicada-data/web-panel-onboarding-security.log) SHA-256 is
`f9249d5f39bc5ced6935e13a96ae3feb9e8001b1e98199ec4c9379098ba69d13`.
It records the crypto/wire, public-file, grant-summary and UI model checks.

These artifacts come from the dirty working tree, not solely from HEAD:

- Test WASM SHA-256: `f8d7c6f9b833e054c1bd7ac94f18453730d9190847dd095b51caa18be5cb0adf`.
- Compressed production WASM SHA-256: `15928ef36581dea575e81434b3632dfb4ee4ec878cfdc5fd050ad64cc57fa4c9`.
- Generated manifest SHA-256: `e833e0673bb23fea572f2b16501c3933c4db492e3b3afe30a42f9fbcbdde5876`.

This was a real Go WASM gate, not a signature stub. Full Chromium and the
Docker web-panel gate remain NOT_RUN. It does not establish Client enrollment,
Android behavior, native Windows custody or the user's HTTPS deployment.

## Prior evidence

The [2026-10-13 Hub bootstrap record](hub-owner-bootstrap-validation.md) retains
its separate Docker A2 fresh-Root, Client enrollment and Node INITIAL results,
segmented suites, skips, failures and exact dirty-source/image identities.
Those checks did not use the new external encrypted-PEM provider.
The [historical OpenSSL helper record](owner-windows-openssl.md#historical-2026-10-13-helper)
covered public adaptation and Client grant signing against the earlier Hub
path. Its Linux OpenSSL tests and Windows cross-build do not establish this
new first-Owner bootstrap or native Windows acceptance.

## Verified pre-extraction Windows cross-build evidence

Root's actual run in
`.cicada-data/windows-owner-openssl-20261014/root-wincheck/` used pinned Go
1.27.1 Docker with network disabled, `CGO_ENABLED=0`, `GOOS=windows` and
`GOARCH=amd64`. `go build -trimpath ./cmd/cicada` and
`go test -c ./internal/ownersigner` each exited 0; both log files are empty.
This supersedes the earlier unverified build report. There was no full CLI
Windows test-package compile in this run.

The production executable SHA-256 is
`61a11573051267ad79a7a1e545da0249fb6697d2f4e0c32d334bc9bff5213b18`;
the Owner-signer test executable SHA-256 is
`07f4a996a020ee1f1b23d5f2ca6dc4f1c63c1e82c08659a3862800b849976fe1`.
Exit files, empty logs and both artifact hashes were independently checked.
These raw artifacts have no embedded provenance and were built from the dirty
candidate **before** Hub identity/bootstrap extraction. They establish compile
compatibility for that source, not a clean-HEAD build, delivery artifact,
post-extraction acceptance, native Windows execution or ACL enforcement.

## Final current-UI offline WASM/model rerun

Root reran `CICADA_WEB_PANEL_OFFLINE=1 scripts/build-web-panel.sh` with the
existing read-only `.cicada-data/m1-gomodcache` and task-owned
`.cicada-data/web-panel-onboarding-security-cache`, pinned Go 1.27.1 / Node
24.16.0. Exit was 0 after the latest UI i18n and advanced-form opt-in changes.
The independently checked log
`.cicada-data/windows-owner-openssl-20261014/root-final-panel.log` has SHA-256
`f9249d5f39bc5ced6935e13a96ae3feb9e8001b1e98199ec4c9379098ba69d13`.
The test WASM, production gzip and manifest retain the earlier exact SHA-256
values `f8d7c6f9b833e054c1bd7ac94f18453730d9190847dd095b51caa18be5cb0adf`,
`15928ef36581dea575e81434b3632dfb4ee4ec878cfdc5fd050ad64cc57fa4c9` and
`e833e0673bb23fea572f2b16501c3933c4db492e3b3afe30a42f9fbcbdde5876`.
Matching bytes do not relabel previous source attribution. This final run
covers the bounded crypto/wire/public-file/grant-summary and current UI model;
Chromium/browser enrollment, native Windows execution/ACL behavior, Android,
real user keys and public HTTPS remain NOT_RUN by us. It is not the new
account/password/two-page setup flow, which is still unimplemented.

## Final current-source builds and older-Hub compatibility gate

The final build evidence was captured from the checkpoint working tree based
on `9fa3628d593755ce21476193ef70316be07742f6`, after Hub-only extraction and UI
changes. This identifies the captured source, not a claim about HEAD after a
later local checkpoint commit. The bounded extraction inventory remains
`a3/source-files.json` in `.cicada-data/hub-identity-extraction-20261014/`, SHA-256
`9bca1e4d93c52f75aec2f0bd87f5b3e4c7832467e06fc6eba6d72e7048e44070`.
Exact artifact identities are distinct from that owned-source inventory and
from both earlier helper/build captures.

Root used pinned Go 1.27.1 Docker image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
network disabled, 3 GiB memory / 2 CPUs, `CGO_ENABLED=0` and trimpath builds.
In `.cicada-data/windows-owner-openssl-20261014/root-final-build/`,
`linux.exit`, `windows.exit` and `windows-test-compile.exit` each contain 0;
all three logs are empty (SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
Both exits/logs and the following artifact hashes were independently checked:

| Raw artifact | SHA-256 |
|---|---|
| Linux amd64 production CLI | `515e8eb17e1cfb73c996716f58f03d36cb7e8573a7814a6b97fea40f9e8fbd0d` |
| Windows amd64 production CLI | `b816cce1a507645126dcecc509cba0b1680bc6fe2e2790799dc435cd441785ad` |
| Windows Owner-signer test executable | `07f4a996a020ee1f1b23d5f2ca6dc4f1c63c1e82c08659a3862800b849976fe1` |

The Linux CLI reports software 0.0.5. These are raw builds with no embedded
build provenance or package; Windows compile does not prove native execution
or ACL enforcement. The pre-extraction Windows `61a115...` record above stays
historical and is not relabeled as this final build.

The independently inspected [run `d68c9e32e4894e11`](../.cicada-data/owner-openssl-bootstrap-runs/run-d68c9e32e4894e11/result.json)
records **PASS** (driver exit 0), result SHA-256
`1e3546ffcb56fba8f0400c6a149a83f4468eb01ca610b9b69530aabee63635a0`.
It explicitly pinned the final Linux CLI `515e8eb...` through
`--expected-helper-sha256`; driver SHA-256 is
`0543f18fd9842dc1a07606c393efe17208d216b9c742a3cc1e605b4df135d86e`.
The driver's older default helper pin remains unchanged. It reused real
OpenSSL 3.5.9 (`06b318f0242a3ec9add593f5210b163ebaa7c76175009600d2704551cb8e6c05`)
and immutable **older** Hub image
`sha256:fc90076f45293a36d304dd7e31d00b6052828c0b1748fdde2c616b5900ebe9d1`;
that Hub image was not rebuilt.

Synthetic encrypted PEM keys and a real PTY exercised the final pure Hub-only
CLI setup/issuer, first Root private proof, deliberately dropped accepted 200,
same-Hub/state restart, exact saved proof and cached receipt recovery, genuine
OwnerDeviceGrant plus public summary, and existing management Client enrollment
with manager role. Hub mounted only `/state` and `/workspace`; bounded checks
found no Owner private PEM bytes or test passphrase in Hub state and no Owner
key/profile mounts. The [cleanup receipt](../.cicada-data/owner-openssl-bootstrap-runs/run-d68c9e32e4894e11/cleanup.json)
SHA-256 is `c439fff015e747685c189d649b2d4885e3109bf4d020f1013f881ffa992e6aea`:
owned container removed, proxy stopped, private scratch removed; images were
retained. Root separately checked that the six protected resident containers
remained untouched.

This is final-helper compatibility with the pinned older Hub. It does **not**
qualify a new extracted-Hub runtime image, new account/signup/login flow, Node
INITIAL, native Windows/ACL behavior, Chromium enrollment, Android, physical
devices or public HTTPS. Earlier `f16...` / `f0d721...` captures and both harness
failures remain intact above. No deployment, key, schema, catalog or version
was changed by this validation.
