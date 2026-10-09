# Endpoint resolution capacity checkpoint — 2026-10-09

`Service.Resolve` and the legacy `Control.ResolveEndpoint` no longer resolve
names from a truncated 1,000-row directory page. The Store now pages eligible,
name-scoped candidates in a single read transaction, using 128-row keyset
pages and a 100,000-row scan ceiling. Eligibility is applied before paging;
active session bindings and legacy machine display names are read from the same
snapshot. The visitor receives one bounded page and must not re-enter the Store.
The legacy resolver keeps machine names in that transaction to avoid the old
callback re-lock deadlock.

Candidate SQL is only a superset filter. Deterministic SQLite functions use Go
Unicode case-fold/lowercase comparisons, including normalized machine IDs;
the existing Go predicates still decide exact address, qualified name and
alias matches and preserve exact-before-alias precedence. The scan continues
past ineligible rows and missing/left bindings. It retains at most two true
matches to prove ambiguity; an ambiguity response therefore contains a
two-candidate proof sample, not the full matching directory or a total count.
Legacy context narrowing is applied after global precedence is established.
If the fixed scan budget cannot establish a result, resolution fails closed
with the existing bounded-capacity error mapping (HTTP 503); it never chooses
from a partial scan. Endpoint-ID lookup and explicit Node-ID narrowing remain
available. No schema, index, API contract, listing page size, or public list
behavior changed.

## Focused regressions

The active service tests seed 1,001 eligible rows. One test places two same-name
aliases on opposite sides of the old list boundary and verifies that Resolve
returns an ambiguity sample of exactly two instead of a false unique result.
It also verifies a unique tail alias/address and `name@NodeID` resolve without
the optional Node-ID filter. The companion test proves that 1,001 identical
names are ambiguous, then proves a unique target remains discoverable after
multiple Unicode candidate pages (`ſhared` versus `shared`) and that a
normalized address with Greek sigma/final-sigma folding resolves without
Node-ID. Both tests retain the Endpoint-ID fast path and explicit Node filter.

The server test exercises the authenticated Fabric v2 HTTP resolver: a
duplicate alias returns 409, while a tail unique alias and full address return
200 for the correct Endpoint. The selected legacy Control regression from the
separately owned test file exercises a duplicate beyond the former list limit;
its presence in the package test build is attributed separately below.

| Selected test | Result |
|---|---|
| `internal/fabric`: `TestResolveDoesNotLoseEligibleAliasesBeyondDirectoryPage` | PASS |
| `internal/fabric`: `TestResolveQualifiedTargetAmongMoreThanThousandSameNameRows` | PASS |
| `internal/server`: `TestFabricV2ResolveUsesNameScopedCandidatesBeyondListPage` | PASS |
| `internal/control`: `TestStressResolveEndpointAliasBeyondListLimitFailsClosed` | PASS |

Both commands passed the same four selectors, with zero failures or skips:

```sh
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=5m -json \
  -run '^(TestResolveDoesNotLoseEligibleAliasesBeyondDirectoryPage|TestResolveQualifiedTargetAmongMoreThanThousandSameNameRows|TestFabricV2ResolveUsesNameScopedCandidatesBeyondListPage|TestStressResolveEndpointAliasBeyondListLimitFailsClosed)$' \
  ./internal/fabric ./internal/server ./internal/control

go test -buildvcs=false -mod=readonly -p 2 -race -count=1 -timeout=5m -json \
  -run '^(TestResolveDoesNotLoseEligibleAliasesBeyondDirectoryPage|TestResolveQualifiedTargetAmongMoreThanThousandSameNameRows|TestFabricV2ResolveUsesNameScopedCandidatesBeyondListPage|TestStressResolveEndpointAliasBeyondListLimitFailsClosed)$' \
  ./internal/fabric ./internal/server ./internal/control
```

The normal run reported package times 4.488s / 0.803s / 4.022s; race reported
45.772s / 17.924s / 44.791s. Results are retained as
[normal-final2 JSON events](../.cicada-data/directory-resolve-capacity-20261009a/normal-final2.jsonl)
(SHA-256 `c3918f823fadd526eb1e94bf990a6286f897e1267f17cb84b800b466ba77c8c8`)
and [race-final2 JSON events](../.cicada-data/directory-resolve-capacity-20261009a/race-final2.jsonl)
(SHA-256 `2e61cceaba4555686cf377d80e1a0fee2db397f92688553a6a5977e375cfdd28`).
The first task-local cache attempt failed before tests because of a cache
mount-permission setup error; the corrected UID-1000, task-local-cache run is
the result recorded here.

Runs used the pinned `golang:1.27.1-bookworm` image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
network none, a read-only source/module mount, task-local writable Go cache and
temporary directory, UID 1000, 2 CPUs, 3 GiB memory, 256 PIDs, read-only root,
all capabilities dropped, and no-new-privileges. This was a focused Go test
container, not a Native Runtime, provider, model, or disposable service
acceptance run. The six resident services were not part of the test fixture.

## Tested source attribution

The tests ran from dirty working tree HEAD
`1ad5a96414c2d888f70c5b61467b3b1e4a382a91`; that commit alone does not identify
the tested changes. The resolver source pins were:

| File | SHA-256 |
|---|---|
| `cicada-go/internal/store/endpoint_resolve_candidates.go` | `2d00281d4a3b19b6b854371bc36490a34cb6271c65987a1f1980b8dd7028cca5` |
| `cicada-go/internal/store/fabric_v2.go` | `dca6f3d49d6b41000697fe52009bc0ea1d1b4aefca702d29d7a4e6652d9e1a15` |
| `cicada-go/internal/fabric/service.go` | `88bc73c32d7122b679c481a5e575f6cb650452b7df8f6cad94d28c3be6070b76` |
| `cicada-go/internal/fabric/resolve_capacity_test.go` | `fdffe1ed599c61a4f0740072210f9c0fd1daee5dd398aedbd5d2fe879d24f00d` |
| `cicada-go/internal/control/fabric.go` | `86feacb6ecf9924ad8bd573bb9be7c1fcea4106d24b2ee7caf05552ef6ad2fa9` |
| `cicada-go/internal/server/fabric.go` | `76745cb200fa26e8b2c14e4d5f2761ee05c0cf049ebbd4265ed47029b5796398` |
| `cicada-go/internal/server/fabric_v2.go` | `cbf82e79c3594517d34743b8b4bc8ee8e215cf6d02e802529579880c4489961c` |
| `cicada-go/internal/server/fabric_resolve_capacity_test.go` | `3af06b8b9bd5c05ecacff8d0b3db9e3efc9dac421d399f98a7eec3254def10f6` |

The selected legacy Control test is in the separately authored
`cicada-go/internal/control/resolve_endpoint_limit_stress_test.go`
(SHA-256 `afabb092aa3eee3ca135ee6f71ba2d417a57187bcd46444f628d74433890bff3`);
the resolver change does not claim authorship of that file. No full Go suite,
capacity benchmark, Native acceptance, or overall v0.1 completion follows from
these focused tests. The next sequence is to finish the bounded stress
checkpoint, refresh the production artifact/preparation against the resulting
source, run one diagnosed original-thread ASK/REPLY attempt, then continue the
remaining M3/M4/M5, panel, and delivery gates separately.
