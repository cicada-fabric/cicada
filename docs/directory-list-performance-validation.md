# Directory list query validation

## Change and scope

`Store.ListDirectoryRecords` now selects and decodes the complete directory rows in one SQLite query. The `activeOnly` predicate, `updated_at DESC` ordering, nil result for an empty list, row fields, and JSON error behavior are retained. `GetDirectoryRecord`, `GetDirectoryRecordByRemoteID`, and Upsert use the same row decoder. The change adds no schema, API, pagination, or dependency changes.

The list still returns every matching row and holds the Store mutex while scanning them. Its result and memory use therefore remain O(n); this change removes the per-row query but does not bound listing or establish a general capacity limit.

## Source and validation

The benchmark base is `e994ea5ec5ca9833cb7cd263133a0451592ec024`. Its exact `cicada-go/internal/store/directory.go`, captured with `git show`, has SHA-256 `455de4899aa9d32d578530de0294624efc9a9c9479b18e7ec978d548a2dcc629`. The measured current sources were `directory.go` SHA-256 `e0453d6e256912273ce184a5dd2bafcd004e9ba1ed27bebf6b09266191be2e43` and `directory_query_test.go` SHA-256 `50b10918c7a6fb748968a373ba87857bdb6181e186287b5318d885c863dc5e04`. The worktree was dirty; these file hashes, rather than HEAD alone, identify the measured source.

In the pinned Go 1.27.1 Linux/amd64 environment, the three Store tests and the existing HTTP directory regression each passed in both normal and race runs: four selected tests per run, zero failures or skips. The selected tests were `TestListDirectoryRecordsFieldsFiltersAndOrder`, `TestListDirectoryRecordsEmptyResultIsNil`, `TestListDirectoryRecordsMalformedStoredJSONReturnsError`, and `TestDirectoryAnnouncementAndRendezvousEndpoints`. This is a focused regression result, not a full-suite result.

The selected regression commands from the module root are:

```sh
go test -run '^(TestListDirectoryRecordsFieldsFiltersAndOrder|TestListDirectoryRecordsEmptyResultIsNil|TestListDirectoryRecordsMalformedStoredJSONReturnsError)$' ./internal/store
go test -race -run '^(TestListDirectoryRecordsFieldsFiltersAndOrder|TestListDirectoryRecordsEmptyResultIsNil|TestListDirectoryRecordsMalformedStoredJSONReturnsError)$' ./internal/store
go test -run '^TestDirectoryAnnouncementAndRendezvousEndpoints$' ./internal/server
go test -race -run '^TestDirectoryAnnouncementAndRendezvousEndpoints$' ./internal/server
```

## Benchmark

The baseline `directory.go` was overlaid for the first run; the current source was run second in the same disposable container and compiler-cache context. The image was `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, with network disabled, a two-CPU quota, and a 3 GiB memory limit. The benchmark ran on an Intel Xeon E5-2680 v4 at 2.40 GHz. Each case used three 200 ms samples. Fixture setup was outside the timed section; each isolated SQLite database held 100 or 1,000 `PUBLIC_SYNTHETIC` rows, 10% marked expired.

| Case | Median time, old → current | Time reduction | Bytes/op, old → current | Byte reduction | Allocations/op, old → current |
|---|---:|---:|---:|---:|---:|
| 100 rows, all | 7.135 → 0.909 ms | 87.3% | 327,179 → 211,957 | 35.2% | 7,127 → 3,239 |
| 100 rows, active only | 6.336 → 0.933 ms | 85.3% | 301,498 → 197,383 | 34.5% | 6,417 → 2,919 |
| 1,000 rows, all | 70.142 → 9.796 ms | 86.0% | 3,393,549 → 2,245,040 | 33.8% | 71,041 → 32,046 |
| 1,000 rows, active only | 67.325 → 8.172 ms | 87.9% | 2,824,542 → 1,787,166 | 36.7% | 63,939 → 28,844 |

To reproduce the benchmark cases from the module root inside the pinned environment, run the baseline overlay first, then the current source. The overlay maps `/src/internal/store/directory.go` to `/baseline/directory.go.baseline`:

```sh
go test -overlay=/evidence/baseline-overlay.json -run '^$' -bench '^BenchmarkListDirectoryRecords$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/store
go test -run '^$' -bench '^BenchmarkListDirectoryRecords$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/store
```

The retained benchmark review is [`benchmark-review.NONAUTH.json`](../.cicada-data/native-observer-wiring-20261007/directory-list-perf-20261008b/benchmark-review.NONAUTH.json), SHA-256 `24f0705763e91bfa3824a04b2c1bb15ecea234f3d14e5d7e0726b212236b76f1`. Its source receipts identify the current files. The original QA receipt is retained unchanged: it reported exit 0 but its own `container_absent` field was false. A separate derived review records the exact owned container absent after an independent exact-container inspection returned exit 1; it does not rewrite the original field. The earlier noexec fixture attempt failed before any test or benchmark action and is excluded from the measured result.

## Separate bounded Hub capacity sample

A separate real-TCP disposable-Hub fixture passed `TestHubBoundedCapacityDocker` with exit 0. It used the standard, unmodified `docker/Dockerfile.hub` image `sha256:4cff916d3a787ad88fdfa8bac0366b4d3a90fc1534ae1b3c1db775145e5377f2`; `pqtls_available` was false and the transport variant was `standard`. The dirty build is attributed to base revision `e994ea5ec5ca9833cb7cd263133a0451592ec024`, the two changed Go inputs listed in the terminal receipt, source fingerprint `12fd5c58a10476c642087fe9e33760f226b52ed289befac71d4e50bbfa41fb0d`, and operation catalog SHA-256 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`—not to a later final commit.

The recorded invocation was:

```sh
CICADA_INTEROP_OUTPUT=/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/shipping-capacity-e994-directory-20261008a \
CICADA_BUILD_PROXY=http://127.0.0.1:7890 \
bash scripts/test-client-hub-interop.sh --suite capacity
```

It ran under Root's bounded orchestration (900-second wall cap, 20-second cleanup allowance), completing in 191.886 seconds. A rerun must use a new private `CICADA_INTEROP_OUTPUT` directory so the retained evidence is not overwritten.

The fixture exercised one Hub process and SQLite state, two synthetic logical Node callers, 64 synthetic endpoints, and 64 HTTP samples with 16 configured workers (observed maximum in-flight 16). Under a 1-CPU and 128-MiB Hub limit, host-observed peak RSS (`VmHWM` for the Hub container-init PID) was 34,136 KiB and the Hub was not OOM-killed. Sample p50/p95 latency was 281.626/682.439 ms. The receipt's operation counters were 46 directory reads, 17 sealed asks, and one sealed send; its HTTP status distribution was 46 responses with 200, 17 with 202, and one with 429. Sixteen ASK admissions were accepted at the per-sender Endpoint pending-ASK limit of 16; the next was intentionally rejected with `Retry-After: 1`. Recovery tracking records four further HTTP calls after the load sample, reply state `REPLIED`, cancellation state `CANCEL_REQUESTED`, and released-slot exact-retry state `OPEN`. There were zero errors or bad directory counts.

The receipt marks Native Runtime, Android, physical nodes, and public HTTPS `NOT_RUN`; it also records zero model/native calls. Its `hub_running_after_test` field is true at the sample boundary. Root's later exact resource review confirms both current container names, both image tags, and both image IDs absent. The review reconciles all 934 input-inventory entries, the catalog and both source fingerprints, and both current source pins; historical CIDs were not recorded, and removed image labels cannot be reinspected. See [`root-review.NONAUTH.json`](../.cicada-data/native-observer-wiring-20261007/shipping-capacity-e994-directory-20261008a/root-review.NONAUTH.json), SHA-256 `b8cbc5559b4641399ec2f23c945edacf3b21f53ea6211b564d8c69577da22806`. The original result remains unchanged: [`result.json`](../.cicada-data/native-observer-wiring-20261007/shipping-capacity-e994-directory-20261008a/result.json), SHA-256 `2e90745de74cf88857a31128762800fe4adc1e05c7ed9eea2c13cca2c2a05a6a`.

This one bounded fixture is a measured-sample PASS, not a general shipping, fleet, or production-capacity guarantee. It is separate from—and does not measure—the Store microbenchmark above, so its Hub-level sample does not establish the list-query change's speedup. This result does not replace or retag prior timeout/noexec evidence. Neither result establishes Native Runtime, Android, physical-device, public-HTTPS, or overall v0.1 acceptance.
