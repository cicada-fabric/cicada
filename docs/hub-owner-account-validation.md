# Hub Owner account validation

Status: **bounded account checkpoint PASS; overall product acceptance remains
partial**. The current account implementation passed the selected Go checks,
WebAssembly gate, real Chromium account flow, and standard Client-over-TCP
interop gate recorded below. This is not a release or production deployment
result.

The account checkpoint is software **0.0.5**, Hub schema **61**, Client
contract **v1.6.5**, Client Wire **1**, and catalog **55**. `owner-account-v1`
is a separate account protocol; it does not revise those Client identifiers.
All current build records below use dirty Git revision
`d758086f25abc0390ff2ad857086c9d94454a639`; fingerprints and image IDs identify
their actual build inputs independently of that revision.

| Check | Result | Scope |
|---|---|---|
| Focused Go checks | PASS: 30 selected top-level tests across 8 packages | Some packages used partial selectors. |
| Full account-package Go checks | PASS: 11 top-level tests | Full runs of `internal/hubaccountwire`, `internal/publicidentity`, and `internal/hubauth`; overlap the focused selection. |
| Store/CLI preservation checks | PASS: 14 top-level tests | Selected Store and `cmd/cicada` cases; overlap the other Go selections. |
| Latest Core Go checks | PASS: 25 selected top-level tests across 4 packages | `cmd/cicada`, `internal/hubauth`, `internal/server`, and `internal/store`; selected checks, not a full repository suite. |
| Test-tagged WebAssembly/UI gate | PASS | Go WASM PQ/Wire checks, Node 24 interoperability, UI model checks, and asset build with Go 1.27.1 after the account UI lock/CAS changes. |
| Disposable Chromium + PQ Hub account flow | PASS: all 18 functional steps | Includes the same-origin writer lock, duplicate-submit prevention, unchanged pending packet across a blocked second tab, exact retry after closing/reloading the first tab, Hub restart, and four accepted-response-loss checks. |
| Standard Client-over-TCP Docker interop | PASS, exit 0 | Hub owner bootstrap plus current headless Client/Node protocol and recovery selectors on a separate standard Hub image. |
| Windows build | PASS, cross-compile only | Raw amd64 Windows cross-build succeeded; no native Windows execution was performed. |
| Android, physical device, real Node runtime, public HTTPS | NOT_RUN | None of the listed gates establishes these environments. |

The different Go selections overlap; do not add their counts to claim unique
coverage. Their event logs are under
[`root-gate`](../.cicada-data/hub-owner-account-20261014/root-gate/):
[`go-focused.jsonl`](../.cicada-data/hub-owner-account-20261014/root-gate/go-focused.jsonl)
(SHA-256
`e5552b347a47d9605ffade8f0e6f528b864b6d38c5173b7e41ea155a0284e3a9`),
[`go-account-full.jsonl`](../.cicada-data/hub-owner-account-20261014/root-gate/go-account-full.jsonl)
(SHA-256
`5fceb2ddc5326275348507663275663b25ed69732fd7075f6a20ae9ac18affe4`),
[`go-preservation.jsonl`](../.cicada-data/hub-owner-account-20261014/root-gate/go-preservation.jsonl)
(SHA-256
`3c77d2da2ee275f1c3a2885f2c924483aa4ce11ec87278ff3bb9e9a26182470f`), and
[`go-core-final.jsonl`](../.cicada-data/hub-owner-account-20261014/root-gate/go-core-final.jsonl)
(SHA-256
`05a9f09d9d56dcc162d79a465f710dccce48023891076c654235539c509c812c`). These
are scoped runner records, not evidence of `go test ./...` passing.

The latest root-run WebAssembly/UI log is
[`wasm-ui-cas.log`](../.cicada-data/hub-owner-account-20261014/root-gate/wasm-ui-cas.log)
(SHA-256
`f9249d5f39bc5ced6935e13a96ae3feb9e8001b1e98199ec4c9379098ba69d13`). It
records Go WASM PQ/Wire checks, Node 24 interoperability, UI model checks, and
Hub WebCrypto asset build with Go 1.27.1 against the post-lock/CAS source.

## Chromium account flow

The final post-lock/CAS disposable browser result is
[`result.json`](../.cicada-data/hub-owner-account-browser/20261014t102757z-2975661-c0e87018/result.json)
(SHA-256
`aa2e023eaafee20bf654a838657efa0eaf0edaab82d2a631d8cbcb112675d01b`). All 18
functional steps passed, including first claim, wrong-password challenge
retention, login, session reload, logout, manager-API denial, and restart of
the same Hub state with the same account, Owner, and login-device IDs. The
Root remained `PENDING_PROOF`; account login did not activate Root or manager
authority. Cleanup passed for all owned containers, network, and fixture
directory. The final driver used for this result has SHA-256
`686d48d6ec41b63f5b755b609f2e7eeeef8c0c2993f46beb23fd6d634b502d0f`.

The cross-tab check had page A submit account completion twice in rapid
succession; only one request reached the Hub. After the Hub accepted the
request and the browser lost its response, page B opened the same profile and
showed the read-only writer-lock state. B had no claim/login form or account
submit action. The saved encrypted pending packet SHA-256 remained
`d794129fa417f2a396d7cb935a6587d76bd147fdf92d32cc9b3aea96ee921ee0`, matching
the accepted request body. The driver closed A's Chromium target and verified
its removal before reloading B. B recovered with the same request bytes and
received the cached receipt. This exercises the origin-scoped browser lock and
exact-pending compare-and-save path across two tabs.

The Hub image was the local PQ-TLS variant
`sha256:dc98a89e748959c357723610660145efe23b5e26014776d55d69edcf6b042d76`,
built from dirty source fingerprint
`c4b52e67ed82f75fd2ef27f198d6e34591323de6f3dfa2f94f03adce7bc335a3` at the Git
revision above. Its qualified build metadata is
[`build-pq-cas.json`](../.cicada-data/hub-owner-account-20261014/root-gate/build-pq-cas.json)
(SHA-256
`5efb714abbc0f98f2f78ba90f0a2a257f13a29ca535d013425485a9108bfcf49`). The
image was 15,184,168 bytes and ran as UID/GID 1000:1000. The browser used
synthetic keys and an explicitly enabled literal loopback HTTP origin; this
tests the application-level PQ envelopes and account flow, **not a PQ-TLS
handshake or public HTTPS deployment**. Synthetic private PEMs were removed
before Chromium started and were never mounted into the Hub.

All four accepted-response-loss tests retried the exact request body; both
the initial accepted response and exact retry returned HTTP 200:

| Operation | Exact retry body SHA-256 |
|---|---|
| Claim prepare | `a3d9451bbc77b35c6e04c8b9bd689adee0744ba991495e8d2cae544e231f8276` |
| Account claim completion | `d794129fa417f2a396d7cb935a6587d76bd147fdf92d32cc9b3aea96ee921ee0` |
| Login completion | `d96eb2d82a804f5c702b5dc36092d040a1a7a4f6ecf01136eed6a1d7a0e20b60` |
| Logout after reload | `66db738106e0a8ac2fe5561aff8c7e2e8a9353b576804b6d6ff3ff1a37d7c352` |

The driver captured one `docker stats --no-stream` point-in-time sample:
0.00% CPU, 23.44 MiB memory, 0.01% memory, and 23 reported PIDs. Docker's PID
count includes threads, so it is not a count of processes. This is a single
snapshot, not a peak measurement or stress benchmark.

The recorded rerun command is:

```sh
CICADA_HUB_IMAGE=sha256:dc98a89e748959c357723610660145efe23b5e26014776d55d69edcf6b042d76 \
CICADA_BUILD_METADATA=.cicada-data/hub-owner-account-20261014/root-gate/build-pq-cas.json \
CICADA_EXPECT_SOURCE_FINGERPRINT=c4b52e67ed82f75fd2ef27f198d6e34591323de6f3dfa2f94f03adce7bc335a3 \
node scripts/test-hub-owner-account-browser.mjs
```

## Standard Client interop

The qualified standard-transport Client gate is
[`result.json`](../.cicada-data/hub-owner-account-20261014/root-gate/client-interop-cas/result.json)
(SHA-256
`5256a204a7baf4ffa63e13b63d31b587a557af8c99f76e1a6594fd22c2ffb393`), with
exit code 0 and cleanup `CONFIRMED`. Its named smoke, headless-operator,
Owner-bootstrap, and recovery-fault tests all passed. The scope includes exact
enrollment/recovery, encrypted snapshots, Owner status/topology isolation,
Hub-key pin rejection, Node candidate confirmation/listing, and bounded
no-generic-RPC behavior. The owned Hub/setup/test containers, their images,
and private scratch have exact-absence cleanup receipts.

This standard Hub image was
`sha256:c9f94827e7cf96b6047b0e41cbc687931c7d36e6d8ae520ab6d7f7ecfe88431b`,
with dirty source fingerprint
`498b1299dba7a0ae8327ed6087dee0bb79102ca43d11f9247418e5ab24887540`. The
standard and PQ-TLS images are separate transport variants with separate build
fingerprints; neither is attributable solely to Git HEAD. The Client interop
runner is `scripts/test-client-hub-interop.sh --suite client`. This Docker Go
protocol/SDK result does not mean Android or a real Node Agent was run.

## Retained failures and limits

Earlier attempts remain failures even though later attempts passed:

* The first browser attempt
  ([result](../.cicada-data/hub-owner-account-browser/20261014t094235z-2846142-69d4b0f0/result.json),
  SHA-256
  `79a6aae571b6c4f0997bc79c0c6029b1fb44b38da79b0b6ae40319a956bd2e9d`)
  passed its preceding account checks but stopped at restart readiness because
  the test driver kept the old dynamically published Docker port. It did not
  verify restart persistence. Its owned-fixture cleanup passed.
* The next browser attempt
  ([result](../.cicada-data/hub-owner-account-browser/20261014t100355z-2930545-3dcd3de0/result.json),
  SHA-256
  `8856707fcece96bd5b5e085b559b983be29dcc7efda91fa9fabbd7633135804d`)
  passed all 17 functional steps, including restart, but the gate exited FAIL
  when optional snapshot handling called `trim()` on the command result object.
  Cleanup passed. The subsequent driver fix reads `stdout` and treats only
  snapshot errors as `UNAVAILABLE`; it did not exercise the later account
  writer lock and compare-and-save changes.
* The pre-lock/CAS browser attempt
  ([result](../.cicada-data/hub-owner-account-browser/20261014t100619z-2935843-93c8c083/result.json),
  SHA-256
  `e1fcfc412eba1402495e1c0eb5e715960afbd7f143993577638b9fcc2e53fe36`)
  passed all 17 then-current steps, including restart. It predates the
  cross-tab race fix and is retained as historical evidence; the 18-step
  post-lock/CAS result above is the current browser acceptance.
* Two intermediate build/interop attempts were blocked because source changed
  during the Docker build; no Client interop assertions ran in those attempts.
  See [`build-pq-final.log`](../.cicada-data/hub-owner-account-20261014/root-gate/build-pq-final.log)
  (SHA-256 `f4a25d6a24d3b3aae4a0e790e9404839ae20099519a8a8cebb55c6c0af047ebd`)
  and [`client-interop-final.log`](../.cicada-data/hub-owner-account-20261014/root-gate/client-interop-final.log)
  (SHA-256 `8a6eed99335366ffb9e6da4f0264e95e6471625b25e3304b1c142129d1a668b9`).
  The later qualified records above use stable source snapshots.

The latest Windows-source build is a successful raw amd64 cross-compile only.
Its output
[`cicada-windows-amd64-cas-accepted.exe`](../.cicada-data/hub-owner-account-20261014/root-gate/cicada-windows-amd64-cas-accepted.exe)
has SHA-256
`87635df687d37cc492548b1f62e63fba83925ef71ea173d48e7af67881ea98e1`; the
successful cross-build log is empty. A parallel build attempt failed because
the WebAssembly asset was read while another process was writing it, producing
an unexpected zero length; the sequenced rerun passed. The failed log is
[`windows-cross-build-cas.log`](../.cicada-data/hub-owner-account-20261014/root-gate/windows-cross-build-cas.log)
(SHA-256
`44b26347f97c07f08624bf74a56204c0b0d8fc2c6d9b0ea719e3bac3c47a199f`), and the
accepted log is
[`windows-cross-build-cas-accepted.log`](../.cicada-data/hub-owner-account-20261014/root-gate/windows-cross-build-cas-accepted.log)
(empty-file SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). There
was no native Windows execution. Android, physical hardware, a real Node
Agent/runtime, and public HTTPS remain NOT_RUN. No Client repository changes
or production Hub operations are part of these results.

The final browser and standard interop fixture cleanups are confirmed. Root's
[intermediate cleanup record](../.cicada-data/hub-owner-account-20261014/root-gate/intermediate-cleanup.json)
(SHA-256
`ae79a5d44cc974fe50f46de0e85f0e87fdaffe6ea9e1327603c71b2d500bc090`) records
nine owned removals, including the pre-CAS PQ image and older Windows
cross-build outputs. The current CAS PQ Hub image and Windows cross-build
artifact were retained. The [before](../.cicada-data/hub-owner-account-20261014/root-gate/residents-before-final.json)
and
[after](../.cicada-data/hub-owner-account-20261014/root-gate/residents-after-cas.json)
resident-container snapshots are byte-identical, each with six resident IDs;
both have SHA-256
`df86c94a17f431b32adba95171e88228306b42dcbc47f1358314d7f113dcae69`. The
recorded resident IDs, images, statuses, and start times were unchanged.
