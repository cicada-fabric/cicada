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
a child fixture was cleaned up.

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
