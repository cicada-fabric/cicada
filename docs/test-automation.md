# One-click test runner

Run the bounded Architecture v2 checks from the repository root:

```sh
scripts/test-architecture-v2-completion.sh
```

The command runs in the foreground and prints a human summary plus the private
JSON result path. To leave it running unattended, start it in the background,
then query the printed run ID:

```sh
scripts/test-architecture-v2-completion.sh --background
scripts/test-architecture-v2-completion.sh --status RUN_ID
```

The default run is capped at two hours, with a cleanup reserve. `--max-seconds`
can lower that limit (minimum 60 seconds). Each lane has its own shorter bound.
Logs and receipts are written under `.cicada-data/architecture-v2-completion/`
with private permissions. The runner records the source identity before and
after the run, stops only its own process groups, and leaves disposable-resource
cleanup to the existing child drivers. A process exit alone does not prove that
a child fixture was cleaned up. Normal child cleanup receipts must match the
nonempty parent run ID, child lane and exact resource roles; the stress driver
uses its separately bound evidence-root run ID.

Node-Control result JSON stays bounded by referencing the original private
`source-before.json` and `source-after.json` archives. Each reference records
the exact file size and SHA-256 plus a private binding manifest for its run,
lane and phase. The consumer checks both manifests and file hashes and compares
the complete parsed source metadata, including the full input inventory and
all other fields. It does not infer source equality from a short fingerprint
or selected fields. Missing, mismatched, cross-run or unbound archives remain
`UNKNOWN`; a verified full-metadata difference is a failure. The 1 MiB child
result limit remains enforced; source archives have a separate 16 MiB bound.

The default inventory includes the pinned offline Go build/test/vet lane,
Python unit tests, Client contract and packaging checks, deterministic web
panel checks, and disposable Docker interop, stress, and browser lanes when
their prerequisites are available. The Go container uses the locally present
pinned Go image, offline module cache, read-only source, and a separate run
cache. It reports optional Go skips explicitly. The panel lane uses
`--model-only`; it does not test WASM interoperability. Native Worker approval
is not requested by default. Peer ASK/REPLY, G4 injection, and G5 acceptance
remain `NOT_RUN` unless exposed by a reviewed command; this runner currently
reports those lanes as unsupported when requested. A missing prerequisite is
`BLOCKED`, and an omitted optional lane is `SKIP`/`NOT_RUN`; neither is a pass.

Supply the current wiring evidence as a matched pair when it is available:

```sh
export CICADA_CURRENT_BINDING_FILE=/absolute/path/to/binding.NONAUTH.json
export CICADA_CURRENT_BINDING_SHA=sha256-of-that-file
```

With neither value, wiring checks are explicitly skipped. Supplying only one
value blocks the lane. Browser checks require Docker, Node, and
`CICADA_HUB_IMAGE`, `CICADA_BUILD_METADATA`, and
`CICADA_EXPECT_SOURCE_FINGERPRINT`; without these the lane is reported blocked.
The optional paid Worker lane requires an explicit `--native` and
`CICADA_NATIVE_ENV_FILE` plus `CICADA_NATIVE_CODEX_IMAGE`. The runner does not
start the peer, G4, or G5 Native gates.

The JSON summary distinguishes `PASS`, `PASS_WITH_SKIPS`, `FAIL`, `BLOCKED`,
`SKIP`, `NOT_RUN`, and `UNKNOWN`. Overall completion is `PASS` only if every
listed lane and the source-identity check pass. Thus a successful selected test
lane is not a claim that all product acceptance gates passed. Android, physical
device, public HTTPS, and unrun Native scopes remain separate evidence.

## Current runner validation

The retained run `20261010T063155Z-5b6d7a3e12` had no failing test lane and
unchanged source, but remained `UNKNOWN`. Five otherwise passing child receipts
were not given their expected parent run ID by the runner. Node-Control's
passing producer result was also oversized because it embedded the entire
source metadata twice. Those aggregation defects are now covered by regression
tests for the actual `make_lanes` → worker → consumer path, exact run/lane/role
rejection, bounded producer results, complete source comparison, missing and
cross-run archives, hash mismatches, and continued oversized-result rejection.
The historical result and receipts are preserved; this repair does not convert
them into a new suite pass. A fresh disposable run is required for that claim.

The targeted runner/helper/status regression set passes 52 deterministic tests
(29 runner, 18 helper/driver, 5 status), with no skips. Evidence is under
`.cicada-data/architecture-v2-completion/runner-fix-unit-20261010/RESULT.NONAUTH.json`.
Run it with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts:scripts/native_observer \
  python3 -B -m unittest -v scripts.test_completion_runner \
  scripts.test_owned_fixture_cleanup scripts.test_completion_driver_status
```

This is deterministic runner validation. A subsequent targeted Docker run,
`20261010T081259Z-runner-targeted-docker`, exercised two production runner lanes.
Node-Control passed its one selected Go HTTP protocol test in 92.068 seconds
(exit 0, no skips), with confirmed owned cleanup. Its fresh result was 3,168
bytes; both complete source archives and both binding manifests were checked by
SHA-256 and the full metadata compared equal. A wrong expected run ID remained
`UNKNOWN`, and the good receipt was unchanged.

The client lane was actively stopped during image build when it entered
`go mod download` instead of reusing the expected cache. Its actual result stays
`FAIL` (exit 143, 272.263 seconds, phase `build`); protocol tests were `NOT_RUN`.
The client cleanup reducer confirmed exact owned cleanup, and independently
rejected a wrong expected run ID. The two-lane aggregate remains `FAIL`, even
though Node-Control passed. All six protected resident snapshots matched before
and after, and the four frozen runner/producer/test files retained their exact
byte hashes. This source claim covers those files and the Node-Control full
build metadata, not every concurrently edited repository file.

Actual commands, timings, logs, counts, source and receipt hashes, cleanup and
resident checks are recorded in
`.cicada-data/architecture-v2-completion/20261010T081259Z-runner-targeted-docker/RESULT.NONAUTH.json`.
The historical default result remains `UNKNOWN`. A complete fresh default
selected-suite result, real Native execution, Android, physical-device and
public-HTTPS acceptance remain unestablished by this targeted run.

The client build interruption exposed a separate Docker cache defect: changing
revision/fingerprint ARGs were declared before `RUN go mod download`, so a new
source identity invalidated the otherwise stable dependency layer. Standard and
PQTLS Dockerfiles now declare those ARGs at the binary build that consumes them;
the webcrypto manifest ARG begins at its check after WASM generation. Standard
runtime initialization also precedes changing label ARGs. Source labels,
compiled provenance, manifest verification, Go versions, module checksums and
Apache/third-party license packaging remain covered by the packaging checks.

The cache/provenance change passes 17 selected release-packaging/PQ-selection
checks plus 6 build-input inventory checks, with no skips. These deterministic
checks establish the layer boundary and preserved guards; they do not establish
an actual cache-hit rate or a fresh PQTLS runtime result. Receipt and reviewable
diff:
`.cicada-data/architecture-v2-completion/docker-cache-fix-unit-20261010/RESULT.NONAUTH.json`.
One fresh client lane may require the declared, unchanged `go.sum` dependencies
to populate the newly stable layer. Its isolated build can use an explicitly
authorized `CICADA_BUILD_PROXY=http://127.0.0.1:7890`; the runner's normal child
environment filter omits that variable, so a supervised one-shot invocation
must set it explicitly for the build child. This is build-only routing, not a
Runtime or model request, and a proxy variable is not an egress allowlist.

With that explicit build-only authorization, the single fresh client lane
`20261010T083246Z-client-cache-fix-once` passed through production
`make_lanes`, `run_process` and classification: exit 0, 319.255 seconds, two
top-level tests and three subtests passed, zero failures or skips. The fixture
confirmed exact cleanup of its containers, images and scratch. A wrong expected
run ID remained `UNKNOWN`, with the good receipt unchanged. The original six
protected resident IDs and their complete snapshots matched; separately owned
concurrent fixtures were permitted and were outside this cleanup scope.

The tested source was dirty HEAD `0897d9e5d3cbb8472f01bb17c00d039bc95a81d0`,
with fingerprint
`fc56f7fd6ef18cbe31107b777339e404309a92f0be55c8d4a0fe81af3ea37482`.
Complete source metadata matched before and after, and the actual build's full
source object matched both archives. Real Hub/test image IDs and their revision,
dirty, source-fingerprint and catalog labels were independently inspected and
matched. The three code/test files and this report remained frozen throughout
the lane; this paragraph was added afterward.

Actual commands, proxy scope, logs, hashes, image provenance, test counts and
cleanup are retained at
`.cicada-data/architecture-v2-completion/20261010T083246Z-client-cache-fix-once/RESULT.NONAUTH.json`.
This fresh client result supplements the earlier targeted Node-Control result
under its own recorded source. It leaves the interrupted client result at exit
143, the two-lane aggregate at `FAIL`, and the old default result at `UNKNOWN`.
It does not establish cross-revision cache-hit rates, a complete default-suite
rerun, PQTLS runtime coverage, or Native/Android/device/public-HTTPS acceptance.

An earlier runner/stress/status unit set passed 27 tests. After the cleanup
receipt reducers were added, the current runner and owned-fixture helper checks
passed 43 tests; the runner module alone passed 25:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts:scripts/native_observer \
  python3 -B -m unittest -v scripts.test_completion_runner \
  scripts.test_owned_fixture_cleanup
```

The first full background run, `20261010T052816Z-6201f75017`, is retained as a
failure: its Go lane exposed six harness fixture-configuration failures, the
merged Python process let an import-time side-effect guard contaminate other
modules, and child cleanup remained `UNKNOWN`. It was not converted into a
pass. The Go harness layout was corrected and Root's targeted rerun passed six
packages (7 top-level tests and 8 subtests, zero failures or skips) in
33.776 seconds. Root also ran 17 Python modules in separate processes: 187
tests passed with no failures, errors, or skips. That Python result predates
registration of the new owned-fixture helper module; it is not a result for
all 18 modules in the current default inventory.

Root later ran the current 18-module inventory in isolated processes: 208 tests,
zero failures/errors, and one explicit skip. The optional current-binding test
was skipped because that run had no binding pair, so this is
`PASS_WITH_SKIPS`, not wiring coverage or a full-suite pass. Receipt:
`.cicada-data/architecture-v2-completion/python-isolated-final-20261010a/RESULT.NONAUTH.json`.
Root then ran the binding module with the explicit current file/SHA pair; all
18 tests passed with no skips or errors in 3.086 seconds. This supplements the
skipped scope and does not change the earlier receipt's counts.

The final owned-fixture helper was also exercised against Docker with network
disabled, a read-only container, and dropped capabilities. Its helper receipt
confirmed exact cleanup, and the runner validated the receipt contract; the
six protected residents were unchanged. This scoped cleanup check is recorded
at `.cicada-data/architecture-v2-completion/cleanup-actual-20261010c/RESULT.NONAUTH.json`.
It does not establish the result of the complete default suite. A matched
current-binding check is still pending.

The initial Docker envelope smoke confirmed container policy and exact cleanup,
but did **not** run Go tests: `bash -lc` reset the image PATH, so Go commands
exited 127. The runner now uses non-login `bash -c` to preserve the pinned image
PATH. The corrected one-second timeout smoke is recorded at
`.cicada-data/architecture-v2-completion/20261010T052618Z-94fa4ac384/envelope-smoke.NONAUTH.json`:
the envelope was verified, timeout was observed, exact cleanup was confirmed,
and the six protected residents were unchanged. Its lane status is `UNKNOWN`
because this smoke intentionally did not complete Go tests.

The current one-click run has not yet established a complete default-suite
result. Its deterministic Python modules include unit checks for privacy and
restore logic, but they do not run the dedicated topology/privacy and Hub/Node
restore acceptance fixtures. The inventory also omits race or PQTLS-tagged Go
runs, standalone WASM interoperability, the full multi-Hub Docker topology,
PQ shipping, and the real Native peer/G4/G5 gates. Those remain separate
`NOT_RUN`/`BLOCKED` scopes; Android, physical-device, and public-HTTPS results
are also separate.
