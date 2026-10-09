# M3 Group Space SSE hint routing — scoped validation

This regression verifies the Node SSE parser's channel routing for Group Space
hints. It does not establish a Native Runtime no-wake result.

`Service.CommitGroupSpaceWrite` notifies current reader Nodes after a successful
commit ([`group_spaces.go`](../cicada-go/internal/fabric/group_spaces.go#L55-L71)).
The Relay emits a body-free `event: space`
([`relay_node_v2.go`](../cicada-go/internal/server/relay_node_v2.go#L540-L555)).
`streamMachineRelayEventsWithSpaces` routes `space` only to its space channel,
while `ready` routes to both the claim and space channels
([`machine_relay_events.go`](../cicada-go/cmd/cicada/machine_relay_events.go#L73-L125)).
The Agent consumes the space channel in `runMachineSpaceSyncWorker`; claim work
is handled on a separate `wake`/ticker path, and local delivery uses
`localWake` ([`machine_agent.go`](../cicada-go/cmd/cicada/machine_agent.go#L498-L553),
[`machine_space_sync.go`](../cicada-go/cmd/cicada/machine_space_sync.go#L199-L219)).

The added `TestMachineRelayEventStreamRoutesSpaceSeparatelyFromClaimWake` uses
an `httptest` SSE server and the existing parser seam. Its `space` case requires
one space-channel notification and no claim-channel notification. Its `ready`
case requires both notifications. The existing outbound credential and wake
hint test remains selected and passes. This asserts parser/channel routing;
it does not run `runMachineSpaceSyncWorker`, observe the Agent job loop, or
measure Native Runtime/model wake behavior. No production hook or counter was
added.

The test was run as an ignored overlay on clean source commit
`dabce1740f91a40c5451fca90522d17f27b09a54`, tree
`9a253f4410bad64f8928ceaae032395356acf681` (1,177 source rows). The tracked
base test SHA-256 is
`c1eed72ee5d844eaa47f0290e753725e2da535c39b8fee137ed6dc23be7f4442`; the
overlay test SHA-256 is
`53fc748a08c98b890443780d607b721edc44ca6f25517c993b104eaab9edfeef`.

The focused normal and race invocations each passed two top-level tests and
two subtests, with zero skips/failures. The result receipt is
[`run-m3-space-routing-20261009a003`](../.cicada-data/m3-space-routing-overlay-20261009a/run-m3-space-routing-20261009a003/RESULT.NONAUTH.json),
SHA-256 `45f5387b3c6e32729fb0594e79c993840a61d17688a5feb6e2b14d90a4407b60`.
It records the pinned Go 1.27.1 network-none container, exact owned cleanup,
zero provider/model calls, unchanged source snapshot, and six unchanged
protected residents. The passing test source is an overlay; this receipt does
not attribute the added test to the unmodified clean commit.
