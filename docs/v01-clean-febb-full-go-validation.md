# Clean `febb3577` full default Go validation — 2026-10-09

The full default Go suite passed once from clean commit
`febb3577e7da14aa9a470ce6c242eb1113b35b68`. The run used a `git archive` of
the complete tracked repository, mounted read-only at `/repo`; it did not use a
partial Go-only source mount or a worktree. The archive SHA-256 is
`302bfa4e67cb417313d2da2bec7671e223ae372565b1391ff1d8564e8e64ec91`, its tree
is `55714d989afeae0f1367a9ba6a26c6268e7c81f3`, and the 1,162-path extracted
inventory SHA-256 is
`c2e6406207a64a189a67c865982db1040546db7176daeed715a97f34ea35983d`.

The pinned Go 1.27.1 image was
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
The container ran as UID/GID 1000, with a read-only root and source, offline
module cache, no network, all capabilities dropped, no-new-privileges, 2 CPUs,
3 GiB memory, 256 pids, and an isolated `/tmp` tmpfs. The commands ran from
`/repo/cicada-go`:

```sh
go build -buildvcs=false -mod=readonly -o /tmp/cicada-machine-agent ./cmd/cicada
export CICADA_TEST_MACHINE_AGENT_BINARY=/tmp/cicada-machine-agent
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./...
```

The build passed and the test command exited 0. The controlled container run,
measured from immediately before container creation through cleanup and
postchecks, took 630.304 seconds; a separate `go test`-only duration was not
captured. All 30 observed
packages passed. Go emitted 1,505 top-level PASS events, 1,405 subtest PASS
events, 22 top-level SKIP events, and no failures. The 22 skips remain skips:
they require explicit Native/real-daemon opt-ins, disposable Docker fixtures,
external Android, or two physical bind mounts. Exact package paths, skipped
test names and their recorded reasons are in the receipts; package PASS events
and test events are separate counts. This was not a race or vet run.

Receipts in [`coherent-full-go-febb-20261009a`](../.cicada-data/coherent-full-go-febb-20261009a/)
include the [source identity](../.cicada-data/coherent-full-go-febb-20261009a/source-identity.NONAUTH.json),
[full source inventory](../.cicada-data/coherent-full-go-febb-20261009a/source-files.NONAUTH.json),
[exact command](../.cicada-data/coherent-full-go-febb-20261009a/command.NONAUTH.json),
[container inspection](../.cicada-data/coherent-full-go-febb-20261009a/created-metadata.NONAUTH.json),
[test summary and package paths](../.cicada-data/coherent-full-go-febb-20261009a/test-summary.NONAUTH.json),
[skip reasons](../.cicada-data/coherent-full-go-febb-20261009a/skips.NONAUTH.json),
[empty failure list](../.cicada-data/coherent-full-go-febb-20261009a/failures.NONAUTH.json),
[final result](../.cicada-data/coherent-full-go-febb-20261009a/result.NONAUTH.json),
and [before](../.cicada-data/coherent-full-go-febb-20261009a/residents-before.NONAUTH.json) /
[after](../.cicada-data/coherent-full-go-febb-20261009a/residents-after.NONAUTH.json)
resident snapshots. The summary stores the raw output byte count and SHA-256,
not raw output. The owned container exited successfully and was removed; the
archive remained unchanged, the checkout stayed clean at `febb3577`, and all
six resident container snapshots matched before and after. No model, provider,
or Native acceptance call was made. The overall v0.1 status remains **PARTIAL**.

## Separate current Native attempt

The separate `peerqueue20261009a001` Native attempt ended with child exit 2
before Docker container creation, after its execution claim was consumed. No
`result.json` was produced in its result directory. The closed wrapper did not
provide reliable call counts, so Native/model call counts are **UNKNOWN**, not
zero. The Root postcheck records exit 2, no timeout or fallback cleanup, an
empty exact-ID registry, absent owned label, unchanged inputs, and six unchanged
resident containers ([postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-peerzero20261009a/peerqueue-rootops-20261009a001/ROOT-POSTCHECK.NONAUTH.json),
SHA-256 `9df1f8cb6fb669ca34b1577e6e26ec5ca8f7986edf0e71fb50639feb2e51cba9`).
This records cleanup only; it is not a Native workflow result or acceptance.
