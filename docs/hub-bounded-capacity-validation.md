# Bounded Hub transport sample

This is a small, repeatable transport and state sample for one disposable Hub
process. It is evidence about the listed run only; it is not a fleet-capacity
claim, a V64 performance guarantee, a multi-agent runtime test, or an
exactly-once guarantee.

The fixture uses the real Hub HTTP listener and its SQLite database in Docker.
It creates one synthetic Owner, two synthetic logical Nodes, 64 synthetic
Endpoints, and sealed synthetic SEND/ASK packets. Sixteen workers issue 64
requests together: 46 scoped directory reads, 17 sealed ASK requests, and one
sealed SEND. The documented ASK admission limit accepts 16 pending requests
from the source Endpoint and returns HTTP 429 with `Retry-After` for the
seventeenth. After measuring that sample, the test requests cancellation,
delivers a sealed reply while the quota is full, and retries the exact rejected
ASK after the reply frees a slot. All generated identities, credentials, and
payloads are disposable synthetic test data. Native Runtime and physical
Nodes are `NOT_RUN`.

## Recorded run

On 2026-10-01, the disposable Hub was limited to 1 CPU and 128 MiB memory, with
swap also capped at 128 MiB. The passing sample observed 16 concurrent
requests, 64/64 directory rows, and status distribution `46 × 200`, `17 × 202`,
`1 × 429`. Aggregate request latency was p50 276.425 ms and p95 694.536 ms.
After the measured sample, cancellation persisted `CANCEL_REQUESTED`, the
reply reached `REPLIED`, and the exact rejected ASK retry reached `OPEN`.

The Hub remained running and was not OOM-killed. Host `/proc` reported a Hub
process high-water RSS of 33,464 KiB. SQLite occupied 2,473,984 bytes and held
64 Endpoint rows, 64 group memberships, 19 Fabric message/security/outbox/
inbox/receipt rows, and 17 Relay requests after recovery. These are observed
fixture counts, not recommended limits.

The image was built from HEAD `4fb241b5e824eb752ceb85586089f44c408e1e7e` with
dirty source fingerprint
`c23ef957d5520bfacfa433133d94a73e12cc29eb54c2cf4acc6ab45ad4689d84`. Hub
image: `sha256:18494052f1047197b259ea075b202d7f37b68eb5218f0833a7fffa6fcb214e07`;
test image: `sha256:4cb375dfebfd85ddcfb3c34008b32c853ee0c16e19808a841a7b2651e4df83a4`.
The contract catalog hash was
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`.

Structured evidence for the passing run is
`.cicada-data/hub-bounded-capacity-20261001/run-2/result.json`, with separate
protocol, recovery, runtime-limit, database-count, and sanitized test lifecycle
records in the same directory. The first real Docker attempt is retained at
`.cicada-data/hub-bounded-capacity-20261001/run-1/result.json` as `FAIL`: the
fixture filtered for Endpoint status `active`, while Node-joined Endpoints are
`online`, so its HTTP 200 directory responses did not contain the expected
64 rows. The test query was corrected to avoid that stale status filter and
the bounded gate was run once more. The first attempt is not counted as a pass.
Its dirty source fingerprint was
`617c9e2bc6ddecc81bfb14fd36cf9323795b07f61419b74d95d90c06af7eeef4`, its Hub
image was `sha256:154ae2c46979e4be3894fa03a108d960349a51a60a0c4456f58ebf543c0592b4`,
and its retained result SHA-256 is
`fe9457fc9904e3245b48bcd1ecde4f470972618376ecae214dc762d12c598256`.
For the passing run, `test.log` records the exact required Go test `run` and
`pass` events and runner exit code 0. `terminal-and-cleanup.json` records the
driver's terminal stdout/exit code and confirms that only its uniquely named
containers, images, scratch directory, and output lock were removed.
Passing `result.json` SHA-256:
`95edb38c0d69445e75a24e5bf332ede9896fbce81bdd00608ea58fc88c7da6c1`;
`test.log` SHA-256:
`59314face73c4cca44473ccf81995fbb600438051ad38cccf33028c51c3d7077`;
terminal/cleanup record SHA-256:
`b953ebc50a4d5d4cea1d1f185e89b567e0c71d1a71df97e49c6b1dedd5437059`.

## Reproduction

From the repository root, use a unique ignored output directory:

```sh
CICADA_INTEROP_OUTPUT="$PWD/.cicada-data/hub-bounded-capacity-<run-id>" \
  ./scripts/test-client-hub-interop.sh --suite capacity
```

The script builds its disposable Hub and test images with the repository's
existing build/provenance path, starts only its uniquely named Hub container,
and applies the CPU and memory limits above. It fails if the named Go test
does not execute and pass, if the Hub is OOM-killed, or if resource and SQLite
measurements are missing. It records Docker image/source provenance and
sanitized Go test lifecycle events; it does not publish raw test output.

The deterministic compile-only check used the pinned Go 1.27.1 image with
network disabled and the existing read-only module cache:

```sh
go test -buildvcs=false -run '^$' ./internal/server
```

The shell driver passed `bash -n`, and the change passed `git diff --check`.
No model, native Runtime, Android client, public HTTPS endpoint, resident Hub,
or real credential was used. This sample does not exercise concurrent model
execution, cancellation of a running native process, multi-Hub placement,
Android, public networking, or the full V64 fleet workload.
