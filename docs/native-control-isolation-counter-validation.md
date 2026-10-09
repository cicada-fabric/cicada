# Native Control-path counter and Fabric-only handler validation

## Result

The focused normal and race selectors passed on a dirty source snapshot at
`9b94f4f9b8f1295923580dbe7b0cbf90f93f1471`. The final source inventory has 938
inputs and SHA-256
`81782146a8c8e359ee5d20072c8ab6435a6f80d66f1ccb567d38a05fa28eed27`; the
five relevant test files were dirty inputs, not changes attributable to the
revision alone. The run used the pinned Go 1.27.1 image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
with network disabled.

Both runs passed the same three tests in `cmd/cicada` and `internal/server`,
with zero skips and failures. Normal took 18.143 seconds; race took 137.673
seconds. No external provider requests occurred, the exact owned containers
were absent afterward, the six resident metadata snapshots were unchanged,
and inputs remained unchanged. The final QA receipt is
[QA-RESULT.NONAUTH.json](../.cicada-data/t9-control-count-20261009a/QA-RESULT.NONAUTH.json)
(SHA-256 `1845db1011aac800d0a0654bc4de25d5ec974056f27d1551b64f301e9bbe6918`).
The final input manifest is
[SOURCE-INPUTS-FINAL.NONAUTH.json](../.cicada-data/t9-control-count-20261009a/SOURCE-INPUTS-FINAL.NONAUTH.json)
(SHA-256 `81782146a8c8e359ee5d20072c8ab6435a6f80d66f1ccb567d38a05fa28eed27`).

The selected tests were:

- `TestNativeManagementPathAttemptCountsControlRoutes`
- `TestFabricOnlyRejectsAuthenticatedGoalCreationWithoutMutation`
- `TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl`

The commands, run from `cicada-go` in the pinned container, were:

```sh
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=4m -json \
  -run '^(TestNativeManagementPathAttemptCountsControlRoutes|TestFabricOnlyRejectsAuthenticatedGoalCreationWithoutMutation|TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl)$' \
  ./cmd/cicada ./internal/server

go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=4m -json -race \
  -run '^(TestNativeManagementPathAttemptCountsControlRoutes|TestFabricOnlyRejectsAuthenticatedGoalCreationWithoutMutation|TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl)$' \
  ./cmd/cicada ./internal/server
```

## What the checks establish

`nativeManagementPathAttempt` is a test-side route predicate for legacy `/v1`,
Manager endpoint, client RPC, and Control paths. Its unit test checks that
representative management routes count and independent Fabric/Relay paths do
not. It is a conservative path-attempt classification, not an authorization
decision, a production metric, or a count of Control business-function calls.
The three provider-backed Native route tests whose counters were updated in
the input set were not selected by these commands; this run makes no claim
about their runtime attempt counts.

The Fabric-only server test sends an authenticated synthetic goal-creation
request to the production handler with `Control` absent. It observes the
expected 503 and verifies goals, workers, workspaces, approvals, and machines
are unchanged. The same-Group sealed HTTP test exercises the production Fabric
handler with `Control` absent and validates the sealed relay path. Existing
Control authorization/state helpers can still be installed for other
management paths; this result establishes only that the tested business
handlers are disabled or not invoked in these cases.

This is deterministic handler and predicate coverage, not a Native Runtime
run. It does not establish NativeGolden local or cross-node message flows,
Control business-function invocation counts, or full T9/V31 acceptance.
Shipping artifacts were not rebuilt or rebound by this checkpoint. Full Native
T9, Android, physical-device and public-HTTPS acceptance remain open.

## Exact changed test inputs

| Input | SHA-256 |
| --- | --- |
| [`communication_link_native_test.go`](../cicada-go/cmd/cicada/communication_link_native_test.go) | `0c0623132a364337f3420d9e252491bd586c3700a898a33403688d469f82e95e` |
| [`cross_node_group_native_test.go`](../cicada-go/cmd/cicada/cross_node_group_native_test.go) | `b2bd945356215158f433da8188c7892d489467ff1fb7e9555e3d6c13991116e0` |
| [`group_broadcast_native_test.go`](../cicada-go/cmd/cicada/group_broadcast_native_test.go) | `60943447af541f41b20346ec6dbcfde538a243288b982940ac830d993090695d` |
| [`native_control_business_test.go`](../cicada-go/cmd/cicada/native_control_business_test.go) | `9e0a20dc7c27b211ddda17d1818c3b224e699381a93f28fc6e868667ce1f67c8` |
| [`relay_node_group_sealed_v2_test.go`](../cicada-go/internal/server/relay_node_group_sealed_v2_test.go) | `174fa645bb7b2959c592656e9722af3b0f0a953877aee5541ffbb1123f8d1a1e` |
