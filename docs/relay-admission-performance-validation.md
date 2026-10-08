# Relay Ask admission quota-count performance validation

## Scope

When admitting an Ask, Relay counts pending requests across sender Endpoint,
sender Principal, sender Group, receiver Endpoint, and global quotas. The old
count could scan expired `OPEN` and `CANCEL_REQUESTED` history while checking
each row's expiry. Schema v59 adds one expression index on `(state,
cicada_relay_expiry_order_key_v1(expires_at))`; the quota count uses its state
and expiry range to skip expired history. Terminal states were already
excluded. No expiry sweep or batch logic changed.

The deterministic expiry key is a fixed 12-byte BLOB: sign-biased Unix seconds
followed by nanoseconds, preserving absolute RFC3339Nano order across timezone
offsets and fractional precision. Empty expiry maps to the all-`0xff` unlimited
sentinel; invalid timestamp text maps to `NULL` and remains excluded. The
existing pending-request eligibility semantics remain authoritative. The
default global pending-Ask limit is 1024 and remains configurable; it is not a
sweep batch size. The v1 SQLite function semantics are frozen; changing them
requires a versioned function/index and a new migration.

This is an index-only data migration: no table rows are rewritten, and there
are no API, authorization, role, key, or protocol changes. Migration versions
1–58 and their IDs/checksums remain immutable. Normal Store opening upgrades a
v58 database through the additive v59 migration. The private restore review is
pinned to v59 and requires an exact schema version and fingerprint; it does not
silently forward-restore a v58 checkpoint into v59 or auto-advance for future
versions. Future migrations need their own restore review.

Index creation is a one-time scan/build over the indexed request set and adds
database storage. Benchmark storage below is a logical page-count comparison,
not an exact index-file size. Index-build duration was not measured.

## Evidence status

The candidate is a dirty worktree based on comparison baseline commit
`0eab255900e5beca305bce97b7e62c6a61b7e430`. The recorded Go test image is
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
The public, non-authoritative input manifest is
`.cicada-data/native-observer-wiring-20261007/relay-admission-perf-20261008c/inputs.NONAUTH.json`.
It records credentials **NOT_ACCESSED**, model calls **NOT_RUN**, and network
`none`. The eight source pins in that manifest are:

| File | SHA-256 |
|---|---|
| `cicada-go/internal/store/relay_admission_index.go` | `e06a0fc5cd3967a7073358032324d5141c86791eeaa5e0d7a65bcaa9e70fb8af` |
| `cicada-go/internal/store/relay_admission_query_test.go` | `56d69b2b4cbe1e0969e64b29c69a44ca1d085b71983831004a9c28171b95bf9a` |
| `cicada-go/internal/store/relay_v2.go` | `cd47cdb72ac185e7339c973e125359bf9132c332822f1912e133656c75731e80` |
| `cicada-go/internal/store/migrations_v2.go` | `d9fc1e3c34a10662577b81bdb0061e0ab974473f4e58fc0845d0651080909c7f` |
| `cicada-go/internal/store/migrations_v2_test.go` | `7efa22d068d4f77f4439da8a8ba2816eef615bc59e22204e903edd8a1d049884` |
| `cicada-go/internal/store/state_restore_reconcile.go` | `608dd97700b6e7c61b333eff7c3ab9d2b0961caa836b7ea827ec7ba53f95fbfb` |
| `cicada-go/internal/store/state_restore_reconcile_test.go` | `c54ff6c65cf7e5b3531ae5ad9701152b8da00b998c7479f134eea20ed78e702b` |
| `cicada-go/internal/store/external_thread_invites_v2_test.go` | `3f29cbbe3c55d50e73fd25936ecf2cbeb89d0f84493c43b260d68ae29ff40276` |

The retained attempts have distinct outcomes; they are not retagged as one
passing run:

| Attempt | Result and limit |
|---|---|
| A | `PARTIAL_FAILURE_AND_OUTER_TIMEOUT`, exit 124; normal run recorded 157 pass and 2 fail, with completion unknown. Race and benchmark were not run. |
| B | Production idempotence correction; normal run completed with 71 pass, 1 fail, and 1 skip, exit 1, without timeout. The failure was the old test expectation for migration ledger v58. |
| C | Test-only overlay adding expected migration v59 in `external_thread_invites_v2_test.go`; the other seven pins are unchanged from B. The previously failing caller test passed (1 pass, exit 0). A broader race command timed out with outer exit 124 after 8 top-level PASS events and no reported race; remaining outcomes are unknown after cached compilation and 25× new-fixture overhead. This is not a full race result. `.cicada-data/native-observer-wiring-20261007/relay-admission-perf-20261008c/root-review.NONAUTH.json` records removal of the exact fixture CID and unchanged source pins/resident state. |
| D | Same eight source pins as C, with no code changes. The scoped changed-logic race passed 8 top-level / 10 subtests, 0 fail/skip, exit 0; selector: `^Test(RelayAskExpiry.*|RelayPendingAskCount.*|HubRestoreReviewedSchemaVersionRequiresExplicitBump|HubRestoreCoverageRejectsCrossSchemaVersions|RelayAdmissionSerializesIndependentStoreHandles)$`. The recorded status is `PASS_SCOPED_BENCHMARK_AND_8_RACE_TESTS`; root-review receipt SHA-256 is `171c6c8af180f11afbef16f85ca3ab7254a83343bc1405c4bf2d0649e1d9a5b8`. This is not a full package or repository race run. |

### Benchmark result

The comparison uses the old `relay_v2.go` and `migrations_v2.go` overlays at
schema 58 against the current schema-59 candidate. Each side used three
200-ms samples in one container limited to 2 CPU and 3 GiB, with pinned Go
1.27.1. The synthetic benchmark adds 16 live requests to the stated expired
history count; it does not issue HTTP requests.

| Expired history + 16 live | Median ns/op | Bytes/op | Allocs/op | Logical DB bytes |
|---|---:|---:|---:|---:|
| 1,000: baseline → candidate | 2,494,478 → 305,731 (-87.7437%) | 248,340 → 5,809 | 12,311 → 132 | 3,325,952 → 3,371,008 (+45,056; +1.35468%) |
| 10,000: baseline → candidate | 20,619,345 → 308,988 (-98.5015%) | 2,408,574 → 5,809 | 120,313 → 132 | 12,312,576 → 12,673,024 (+360,448; +2.92748%) |

Logical database bytes are `PRAGMA page_count * page_size`; they include
ledger/WAL-visible logical pages and do not measure exact index-file bytes or
RSS. Index-build duration remains **NOT_MEASURED**.

### Bounded shipping-capacity result

The disposable standard-image shipping-capacity gate passed (`exit 0`). Its
result receipt is
`.cicada-data/native-observer-wiring-20261007/shipping-capacity-0eab-relay-index-20261008a/result.json`
(SHA-256 `bc850ae89f09608749a2d891c933aeb6f41b04d73b0012d37080bf32a6e57682`);
the independent Root review is
`.cicada-data/native-observer-wiring-20261007/shipping-capacity-0eab-relay-index-20261008a/root-review.NONAUTH.json`
(SHA-256 `62883d2af05abfa145acfa9c1e7fa2e67f2b850cc1dca6ef50046e39cdd83d7d`).
Root verified 936 build-input inventory entries. The dirty source is based on
`0eab255900e5beca305bce97b7e62c6a61b7e430`, with source fingerprint
`23f3c22d3be8eace6ea6a01ccf074d2bc38768a6875dfa077bc9ca8410a8611e`, input
inventory fingerprint
`e295dec06e6bb83a294ad0a49cca106fc5450f8a961a0826878eaecadc150424`, and
unchanged catalog SHA-256
`953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. The
recorded Hub and test image IDs are
`sha256:bf422562d7a2a827cd0c66b3e221a0625d4721d0af8e846e85a028620ae6c1b7`
and
`sha256:bf17624b692a6ecb8dd9b3a0440388d39f031e2ad86be6c653260004d6eb265c`;
transport was standard and `pqtls_available=false`.

The sample used 64 synthetic Endpoints, two logical Node callers, 16
configured and observed concurrent HTTP requests, and a 1-CPU / 128-MiB Hub
limit. Across 64 samples, p50/p95 were 280.239/761.625 ms; responses were 46
`200`, 17 `202`, and one `429` with a one-second retry. The default sender
Endpoint Ask quota accepted 16 and rejected one additional admission. There
were no errors or bad directory counts, no OOM, and Hub process peak RSS was
34,616 KiB. Recovery checks observed `REPLIED`, `CANCEL_REQUESTED`, and an
exact retry of a released slot returning to `OPEN`.

The Root review confirms six exact generated references absent at review time
and all six protected residents unchanged; no historical fixture container
ID was captured. This finite synthetic sample is not a fleet-capacity
guarantee. It is not PQTLS handshake evidence. Native Runtime/provider,
Android, physical Nodes, and public HTTPS remain **NOT_RUN**. The historical
physical bind capsule skip also remains unresolved. Separate contract/catalog
and Python checks passed: contract 1.6.4, catalog 55, and 17 Python checks.
These do not imply a full Go suite or broader product acceptance.

| Separate acceptance scope | Status |
|---|---|
| Disposable shipping-image Hub capacity | **PASS, bounded synthetic sample only**; limits and provenance above. |
| Native Runtime / provider | **NOT_RUN**; no credential or model/provider request was used. |
| Android / physical device | **NOT_RUN**; the historical physical bind capsule skip is still open. |
| Public HTTPS | **NOT_RUN**. |

The benchmark, race and capacity results remain tied to their exact source and
image identities. They do not imply a full normal suite, full repository race,
PQTLS handshake, Native Runtime, Android, physical-device, or public-HTTPS
acceptance. Overall v0.1 remains **PARTIAL**.

## Reproduction commands

The Go commands below were run from `cicada-go/` inside the recorded pinned Go
1.27.1 Docker image, with network disabled, source mounted read-only, and
2-CPU / 3-GiB limits. They are scoped Store commands, not a host-wide or
repository-wide Go run.

```sh
go test -json -race -p 1 -count=1 ./internal/store -run '^Test(RelayAskExpiry.*|RelayPendingAskCount.*|HubRestoreReviewedSchemaVersionRequiresExplicitBump|HubRestoreCoverageRejectsCrossSchemaVersions|RelayAdmissionSerializesIndependentStoreHandles)$' -timeout 6m
```

The benchmark command was run once for the schema-59 candidate and once for
the schema-58 baseline with only the old `internal/store/relay_v2.go` and
`internal/store/migrations_v2.go` source overlays from the pinned baseline.
Overlay preparation was outside the timed benchmark section and is bound by
the private receipt; it was not a checkout or retagging of the current source.

```sh
go test -run '^$' -bench '^BenchmarkRelayAdmissionCountHistoricalBacklog$' -benchtime=200ms -count=3 -benchmem -cpu=2 ./internal/store
```

From the repository root, the static contract and Python checks were:

```sh
python3 scripts/client-contract.py check
python3 -m unittest scripts/test_client_contract.py
```

The disposable shipping-capacity command used a new, unused private output
path in place of `/absolute/path/to/new-unused-private-output`:

```sh
CICADA_INTEROP_OUTPUT=/absolute/path/to/new-unused-private-output \
CICADA_BUILD_PROXY=http://127.0.0.1:7890 \
timeout -k 20s 900s bash scripts/test-client-hub-interop.sh --suite capacity
```

This capacity command is separate from the Store benchmark and race command;
its bounded result does not establish Native Runtime, Android, physical-node,
PQTLS, or public-HTTPS acceptance.
