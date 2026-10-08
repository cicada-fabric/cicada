# Endpoint V2 Store list-query validation

## Change and boundary

`Store.ListEndpointsV2` selects all legacy Endpoint fields plus Principal, primary Group, Binding and migration associations in one SQLite query, replacing the prior ID query and two lookups per row (`1+2N`). `getEndpointV2Locked` also uses one query instead of two. The SQL scope/expiry predicates, ordering, normalized limit, non-nil empty slice, JSON errors, `ErrEndpointNotFound` and `MigrationStatus = MigrationState` mapping are retained. No schema, API, authorization policy or dependency changes were made.

`Fabric.Service.List` still performs N active-binding lookups. This is distinct from the earlier [`Store.ListDirectoryRecords` change](directory-list-performance-validation.md); neither record establishes that all Directory queries are free of N+1 behavior. Endpoint results remain O(n), limited to at most 1,000 rows per call (default 200), and decoded while holding the Store mutex.

## Tested source and focused checks

The base was `76a703186c60d15b96f43e324113c4b62fcfeaa0`. The baseline overlaid the captured `fabric.go` and `fabric_v2.go` from that revision, using the same new synthetic tests and benchmark. The dirty current source is identified by these SHA-256 pins, not by HEAD alone:

| File under `cicada-go/internal/store/` | Baseline SHA-256 | Current SHA-256 |
|---|---|---|
| `fabric.go` | `d2cdd4f220f3284ef77a13b49cd9bc9663eadbd6c51a2e39818d4c06d3ed243f` | `969bdb8d574378735af977f9961b2b71eb6cf6d801034fa3ad3418b2249c517b` |
| `fabric_v2.go` | `f5a025ed76ccff18d9ec8aed93a6364549965a7b6a27953494123082813d75c9` | `d893d586e2a3a760e872c1ef55c06933eea3b51ded156bfcd2cd23a7e0679630` |
| `endpoint_v2_query_test.go` | Same fixture for both runs | `06f4dd1ff7b634fbc10ce02b660b86340334b58f930e514e79cc397b49ddba3b` |

Root independently counted baseline 4 top-level / 21 subtests PASS; current normal Store 8 top-level / 21 subtests and Fabric 5 top-level / 0 subtests PASS. Current race passed the same Store and Fabric counts. All completed selections had zero failures or skips. Coverage includes complete fields and migration mapping, multi-Group identity, SQL filters, current revocation/expiry, ordering/limits, empty results, malformed JSON and lookup errors. This is focused validation, not a full-suite result.

The retained [A receipt](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-perf-20261008a/QA-ROOT.NONAUTH.json) failed before testing on compiler-cache permissions; [B](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-perf-20261008a/root-run-b/QA-ROOT.NONAUTH.json) failed before testing on baseline-file permissions. [C](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-perf-20261008a/root-run-c/QA-ROOT.NONAUTH.json) completed normal checks but its race phase hit the outer 150-second wall limit, leaving later results UNKNOWN. [D](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-perf-20261008a/root-run-d/QA-ROOT.NONAUTH.json) completed only the remaining race and benchmark phases; C's aggregate remains `NOT_PASSED`.

## Store benchmark

Baseline then current each used three 200 ms samples, `-cpu=2`, the same compiler-cache context and pinned `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, with network disabled and a 3 GiB limit. Each disposable Store held 100 or 1,000 `PUBLIC_SYNTHETIC` rows; transaction/prepared-insert setup was excluded from timing. Source/modules were read-only, root filesystem read-only, capabilities dropped and no-new-privileges enabled. UID 0 was used by the synthetic builder to reuse Root's compiler cache; this is not Native isolation evidence.

| Rows | Median ms/op, baseline → current | Median bytes/op, baseline → current | Median allocations/op, baseline → current |
|---|---:|---:|---:|
| 100 | 11.741015 → 2.109113 | 545,348 → 362,740 | 14,029 → 6,569 |
| 1,000 | 113.475699 → 18.943143 | 5,397,368 → 3,809,154 | 140,057 → 65,083 |

These measure `Store.ListEndpointsV2`, not end-to-end Directory latency or fleet capacity. Root's [benchmark/count review](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-perf-20261008a/BENCHMARK-ROOT-REVIEW.NONAUTH.json) has SHA-256 `6fb5e35674380b55adaba5062cea97655dbdbd16960c7dc09661078120c34aad`. Exact test commands are retained in C/D. Benchmark commands from the module root inside the pinned environment were:

```sh
go test -overlay=/evidence/baseline-overlay.json -run '^$' -bench '^BenchmarkListEndpointsV2PublicSynthetic$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/store
go test -run '^$' -bench '^BenchmarkListEndpointsV2PublicSynthetic$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/store
```

## Separate disposable Hub interop

The current dirty build passed `bash scripts/test-client-hub-interop.sh --suite group-spaces-m2` in 196.367 seconds. `TestGroupSpacesM2DockerHub` and `TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS` both exited 0, using actual TCP and the standard Hub image (`pqtls_available=false`). This is an interop result, separate from the Store timing above.

The build is attributed to the base revision and three Go pins above, verified against all 937 build-input entries, with source fingerprint `4e9b741f848033b8fa9eb447cd13d16e23fbf443576f71768771db8fd0b94804`. The catalog SHA-256 remained `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. It is not attributed solely to a later checkpoint commit. Hub image `sha256:7989404a574fd0181deaeeb2028a0f5eb9e85c6c3e0c848e768c3028278ef7b3` and test image `sha256:dd5851d8a1303c58afe01d5812065610695a2d304d84058cbd4911f69887a854`, their tags and current container names were independently confirmed absent; historical container IDs were not recorded. Six protected residents were unchanged.

Root's [interop review](../.cicada-data/native-observer-wiring-20261007/endpoint-v2-group-spaces-20261008a/ROOT-REVIEW.NONAUTH.json) has SHA-256 `8386d88aded606ec567c3c9cd2482949985d8f851dc6719d8866af28e400d094` and pins the original result. Native Runtime, Android, physical Nodes and public HTTPS were **NOT_RUN** in this checkpoint; historical acceptance retains its tested source. Overall v0.1 remains **PARTIAL**.
