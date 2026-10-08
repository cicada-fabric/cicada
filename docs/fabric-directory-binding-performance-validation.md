# Fabric Directory binding-query validation

`Fabric.Service.List` now reads active bindings in one batch after its unchanged `Authorize` and SQL-scoped `ListEndpointsV2` call. Non-empty listing data uses two SQL queries (Endpoints plus bindings), excluding Authorize queries; alias resolution that calls List shares this improvement. This does not establish that Relay or every Directory path is free of N+1 queries. No schema, API, authorization policy, dependency, cache or resident service changed.

The batch retains the existing highest-epoch selection among `active`, `leased`, `online`, `ready` and `acquired` bindings, using existing indexes and decoding. Inactive higher epochs cannot replace an active binding. Group/migration/visibility and expiry filters remain in the Endpoint SQL; card order and limit remain the Endpoint order and limit, without backfilling skipped rows. Left Endpoints and missing or malformed bindings are skipped; malformed selected binding JSON does not fall back to another binding. Store query/iteration errors are returned; Service converts a batch error to non-nil empty cards with nil error, retaining its prior policy of skipping failed binding lookups. Endpoint-query errors still propagate. NetworkCard redaction remains unchanged, including absence of peer NativeSessionID.

## Tested source and checks

Evidence belongs to dirty base `3849f223287a0da14fd6ddd52386c21ff3667b97` plus these four Go pins, not a later checkpoint commit. The performance baseline overlays only the captured base `service.go` (SHA-256 `1c243126764c19c751cda4d3b16139346e203803cc7c74a120ade37ece044f53`); both runs retain the earlier Endpoint Store optimization and use identical new synthetic tests/benchmark. The fourth file adds the separate HTTP gate assertions.

| File under `cicada-go/internal/` | SHA-256 |
|---|---|
| `fabric/service.go` | `49da0b66b2875495d4bf76364ac7d6a1aae80d8c4bf9a7f09972af392fd9f700` |
| `store/fabric_v2.go` | `18729ab7f544464e3ea1212480aa1fcbe62a591807fcc8bf5b1ee8a18e82d337` |
| `fabric/service_list_binding_query_test.go` | `76c861c112b4e677273366de285893f516dcf7671fbacd7796608c9dbfc15eec` |
| `server/network_m1_docker_test.go` | `c4eba584e7735cae9082d29412e7eb342ce639acb4d579c08e37b153cea878ed` |

Root independently counted baseline normal, current normal and current race: seven top-level tests PASS each, zero failures/skips. Selection covers active versus inactive epochs, selected malformed JSON, missing/left/pending/foreign-group rows, lease and membership semantics, card privacy, ordering/limit, revocation and existing group authorization regressions. [QA B](../.cicada-data/native-observer-wiring-20261007/directory-binding-perf-20261008a/root-run-b/QA-ROOT.NONAUTH.json) completed in 157.154 seconds (SHA-256 `8fecdaa4cb18be5710212c49a404eef897a218cf6cf44e4face21f65e2854845`). [A](../.cicada-data/native-observer-wiring-20261007/directory-binding-perf-20261008a/QA-ROOT.NONAUTH.json) retains its pretest permission failure, not a test failure or pass: UID 0 with dropped capabilities could not traverse a mode-0700 overlay directory. B mounted only two public mode-0644 baseline files read-only; private permissions were not changed.

The [exact commands and envelope](../.cicada-data/native-observer-wiring-20261007/directory-binding-perf-20261008a/root-run-b/PRESTART.NONAUTH.json) used pinned `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, CPU 2, 3 GiB, 256 PIDs, network none, read-only root/source/modules, all capabilities dropped and no-new-privileges. UID 0 reused the existing Root compiler cache read-write; this synthetic builder envelope is not Native isolation evidence. Six residents and source pins were unchanged; exact owned CID `d36d6833b7d6d52f82c1ca15a3d9aa397e1bd10e91fd89e8db69caf8ab81a229` was absent, with no OOM.

## Service benchmark

Each baseline/current measurement used three 200 ms samples at CPU 2, with PUBLIC_SYNTHETIC transaction setup excluded. These are actual `Service.List` measurements including Authorize, not end-to-end HTTP latency or fleet capacity. Root's [independent count and median review](../.cicada-data/native-observer-wiring-20261007/directory-binding-perf-20261008a/root-run-b/BENCHMARK-ROOT-REVIEW.NONAUTH.json) records:

| Peer rows | Median ms/op, baseline → current | Median bytes/op, baseline → current | Median allocations/op, baseline → current |
|---|---:|---:|---:|
| 100 | 12.367004 → 4.583483 | 709,306 → 534,163 | 15,415 → 9,891 |
| 1,000 | 124.168138 → 39.274318 | 7,100,248 → 5,363,609 | 151,186 → 95,274 |

Median time fell 62.94% / 68.37%, and allocated bytes fell 24.69% / 24.46%. Reproduction commands from the module root inside that envelope:

```sh
go test -overlay=/evidence/baseline-overlay.json -count=1 -timeout=120s -json -run '^(TestServiceListBindingQuery.*|TestDirectoryIsGroupScopedAndNeverGuesses|TestUnjoinedNativeSessionIsNotDirectoryObject|TestOneNativeEndpointUsesTwoGroupsWithoutCrossGroupMailboxLeak|TestLeaveGroupPreservesOtherScopeAndLastLeaveFencesBinding|TestNestedGroupDoesNotInheritPrincipalOrEndpointAuthorization)$' ./internal/fabric
go test -count=1 -timeout=120s -json -run '^(TestServiceListBindingQuery.*|TestDirectoryIsGroupScopedAndNeverGuesses|TestUnjoinedNativeSessionIsNotDirectoryObject|TestOneNativeEndpointUsesTwoGroupsWithoutCrossGroupMailboxLeak|TestLeaveGroupPreservesOtherScopeAndLastLeaveFencesBinding|TestNestedGroupDoesNotInheritPrincipalOrEndpointAuthorization)$' ./internal/fabric
go test -count=1 -timeout=180s -race -json -run '^(TestServiceListBindingQuery.*|TestDirectoryIsGroupScopedAndNeverGuesses|TestUnjoinedNativeSessionIsNotDirectoryObject|TestOneNativeEndpointUsesTwoGroupsWithoutCrossGroupMailboxLeak|TestLeaveGroupPreservesOtherScopeAndLastLeaveFencesBinding|TestNestedGroupDoesNotInheritPrincipalOrEndpointAuthorization)$' ./internal/fabric
go test -overlay=/evidence/baseline-overlay.json -run '^$' -bench '^BenchmarkServiceListBindingsPublicSynthetic$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/fabric
go test -run '^$' -bench '^BenchmarkServiceListBindingsPublicSynthetic$' -benchmem -benchtime=200ms -count=3 -cpu=2 ./internal/fabric
```

## Separate HTTP gate and remaining acceptance

The disposable real-TCP `bash scripts/test-client-hub-interop.sh --suite network-m1` gate passed in 199.978 seconds, with `TestNetworkM1DockerHub` exiting 0. Its added `/v2/fabric/list` and `/v2/fabric/members` assertions passed for the exact authorized Group card, authoritative BindingID/Epoch, NativeSessionID redaction and six credential-denial checks. Other M1 results retain their synthetic protocol scope; this is not Native G2/T9 acceptance. The [Root result](../.cicada-data/native-observer-wiring-20261007/directory-binding-network-m1-20261008a/ROOT-RESULT.NONAUTH.json) has SHA-256 `5f34c2003e9ff34cb12f3854b74a3926f6cb2b2688cd87426cd67b433892f345`; the [recorded runner result](../.cicada-data/native-observer-wiring-20261007/directory-binding-network-m1-20261008a/result.json) has SHA-256 `f36489094097097b7c33516e6458fc18fa3e7f5f765aafbe2d42cada047282cd`.

Root's [independent review](../.cicada-data/native-observer-wiring-20261007/directory-binding-network-m1-20261008a/ROOT-REVIEW.NONAUTH.json) matched all 938 build-input SHA values and the four Go pins above. The dirty build source fingerprint is `d2ceab62f75d0c4e7c929facca319b040821f3f015b5237ff7966f64c608ea54`; catalog SHA-256 remained `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. Hub image `sha256:13085cd94e12d20e79887a619ab1fde31085daa6cd1091e52ff308ac872d2f9c`, test image `sha256:ac180c5cc4fcbf02e5eb6a172653d5d92bec43b18a90b63bb224063155df4074`, both tags and both container names were independently confirmed absent. Historical container IDs were not recorded by the runner. Six protected residents were unchanged.

Results and decoding remain O(n), at most 1,000 Endpoints per call, under the Store mutex. Native Runtime/Worker, Android, physical Nodes and public HTTPS were **NOT_RUN** in this checkpoint; historical acceptance retains its tested source. The [zero-key Native bridge PASS](native-go-client-bridge-validation.md) remains tied to CLI 0.161.0 and its own source; isolated CLI 0.162 installation does not inherit that result or close Worker/context/G2/G3/full T9. Overall v0.1 remains **PARTIAL**.
