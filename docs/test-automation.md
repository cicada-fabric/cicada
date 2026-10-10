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

The deterministic runner/stress/status unit command passed 27 tests with no
failures or skips:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts:scripts/native_observer \
  python3 -B -m unittest -v scripts.test_completion_runner \
  scripts.test_group_fabric_stress_driver scripts.test_completion_driver_status
```

The initial Docker envelope smoke confirmed container policy and exact cleanup,
but did **not** run Go tests: `bash -lc` reset the image PATH, so Go commands
exited 127. The runner now uses non-login `bash -c` to preserve the pinned image
PATH. The subsequent full background run is the Go-test result and must be read
separately.

The corrected one-second timeout smoke is recorded at
`.cicada-data/architecture-v2-completion/20261010T052618Z-94fa4ac384/envelope-smoke.NONAUTH.json`:
the envelope was verified, timeout was observed, exact cleanup was confirmed,
and the six protected residents were unchanged. Its lane status is `UNKNOWN`
because this smoke intentionally did not complete Go tests.
