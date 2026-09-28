# M1 code audit

**Status (2026-09-28): M1 backend matrix PASS.** High-risk production paths and
deployment boundaries received a targeted review during M1 work. Final full
Go (25 packages, 894 top-level tests), vet, focused race (5 packages, 16
selected tests), contract/Python and two disposable Docker gates passed on
dirty source fingerprint `479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe`
(`HEAD=733ca8640f86f4944b4f8d8f7c38f6cd929212f2` plus worktree). See
[accepted gate evidence](../.cicada-data/m1-final-20260928/accepted/summary.json).
The earlier dependency scan passed on fingerprint `05a486a4`; dependency pins
did not change afterward, but that result belongs to its own scanned source.
This is an engineering audit, not line-by-line verification or proof that no
other defects exist.

## Reviewed surface

| Area | Review mode and focus | Not established by this review |
|---|---|---|
| Network authority and HTTP | Deep source tracing of Network/Group scope, membership and revocation generations, Store write fences, and legacy route aliases; focused Store/HTTP tests exercise the listed boundaries. | No proof over every future route or every field permutation. |
| Node and local authority | Deep tracing of Owner consent, native Session binding, Node credentials, MCP outbox, Unix-socket bridges, claim/authorize/injection and receipts; unit/Store tests cover exact attempts and stale epochs. | Real native Runtime, Android and physical dual-Node operation were not run. |
| Control and work execution | Targeted source tracing of the `client_network_direct_keys` dispatch, selected worker/approval/executor operations, Task/Handoff mutation guards, resource leases, artifact publication, outbound address checks and Git workspace operations; focused tests cover the traced scope/race cases. | This was not a deep review of every worker or Control action. No adversarial multi-process stress campaign or complete external-service integration. |
| Persistence and recovery | Synthetic SQLite migration inventory and interruption tests; Store permissions, snapshot restore paths, Node backup inventory, replay and ratchet state reviewed with focused tests. | No production StateDir recovery or actual power-loss/crash campaign. |
| Client protocol and UI | Client v1.4 catalog/encrypted RPC, JSON-RPC framing, UI escaping/CSP, token storage and SSE paths inspected; contract and regression tests cover selected cases. | No independent browser penetration test or Android implementation run. |
| Deployment and automation | `.github/workflows/client-hub.yml`, `Dockerfile.hub`, image/disposable interop scripts, lifecycle cleanup and release build metadata reviewed. | No public HTTPS deployment or published binary/release was tested. |

The review used source inspection and the named regression tests below. It did
not prove every route/parameter combination, every crash point, or every
third-party dependency safe.

Additional production paths read during the high-risk pass include
`internal/codexapp/client.go` and `proxy_client.go`, Node harness/session
validation and `machine_fabric.go`, workspace prepare/network/CAS/archive
restore, `internal/nodebackup` backup/restore/path/inventory/publish, Hub state
backup/restore, `clientwire` framing and crypto binding, server input limits,
UI escaping/CSP/token handling/SSE, and outbound connector setup. The code
inventory is broader than the line-level deep tracing; the review does not
claim that every function in those modules was exhaustively examined.

## Confirmed findings and current disposition

Priority labels below are engineering triage (P1/P2), not CVSS ratings.

| Priority | Finding | Disposition and evidence |
|---|---|---|
| P1 | Snapshot restore could delete a pre-existing `target.old` sibling and lose the original target on a failed replacement. | Fixed in `internal/workspace/snapshot/restore.go`: replacement uses a unique same-directory backup owned by the operation, preserves unrelated siblings, and reports the recovery location if rollback itself fails. `TestUnpackPreservesExistingTargetOldSibling` and `TestUnpackRestoresOriginalTargetWhenReplacementFails` cover preservation and rollback. The two-rename sequence is not crash-atomic; a host/process crash between renames can require recovery. |
| P2 | JSON-RPC server requests reusing a client request ID could be mistaken for a client response by the Codex stdio/WebSocket proxy. | Fixed by distinguishing a response from a server request by the presence of `method`. `TestStdioRequestHandlesServerRequestWithSameID` and `TestProxyRequestRejectsServerRequestWithSameID` cover the collision. |
| P1 | Hub state directory/database permissions allowed another local OS UID to read Node session and peer-chain secrets. | Fixed in Store initialization with private state/database permissions. `internal/store/state_permissions_test.go` covers the created paths. This does not isolate processes running as the same OS UID or host root. |
| P2 | The normal Control HTTP server lacked whole-request and idle/header bounds, leaving slow headers/bodies and idle connections able to hold resources. | Fixed with IPv6-safe listener construction, 10-second `ReadHeaderTimeout`, 2-minute `ReadTimeout`, and 60-second `IdleTimeout`. `WriteTimeout` remains unset so long-lived SSE is not truncated. `TestControlHTTPServerBoundsHeadersAndIdleConnections` and `TestControlHTTPServerReadTimeoutStopsSlowRequestBody` cover configuration and a real loopback slow-body timeout. |
| P1 | Artifact HTTP operations ignored the explicit Group selector for a multi-Group Endpoint and collapsed scope denial into 401. Artifact publication also needed an in-transaction check tying the source artifact to the actor's authorized owner/Goal/Group. | Fixed in the current tree: the handler authenticates with `AuthenticateForGroup`; scope denial maps to 403. Fabric/Store write paths validate the current actor and source ownership in the mutation transaction. `TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint`, `TestNetworkArtifactMutationsRejectStaleNativeActorAcrossStores`, and `internal/fabric/artifact_v2_test.go` cover selected and cross-Store cases; final repository gates passed. |
| P1 | Resource renew/quarantine/managed-blob writes could race revocation if authorization was checked before the write transaction. | Fixed by rechecking current native actor and Network scope in the Store mutation transaction. `TestNetworkResourceMutationsRejectStaleNativeActorAcrossStores` covers positive access and denial after leave using separate Store handles, including unchanged blob state. |
| P1 | Shared Task and Handoff mutations needed to bind the selected Group and current native actor in the same transaction, rather than relying on an earlier service read. | Current paths revalidate the task's Group, Endpoint/native binding and applicable from/to actor scope at mutation time. `TestNetworkTaskWritesRecheckNativeBindingEpochInWriteTransaction` and the shared Task/Handoff authorization and stale-owner tests cover selected stale/wrong-scope cases. |
| P1 | Session-binding lease expiry compared RFC3339Nano text lexically at sub-second boundaries, which could reject a valid renewal or allow an expired lease to appear current. | Fixed in `internal/store/fabric_v2.go`: Acquire/Renew/Rotate/Validate parse instants and mutate with epoch/version compare-and-swap in one SQLite transaction. Network membership/Group expiry checks likewise parse instants; directory/invitation SQL uses a deterministic exact-time function and malformed values fail closed. `TestSessionBindingLeaseChecksFractionalExpiryByInstant`, `TestSessionBindingLeaseExpiryParsesOffsetsAndRejectsInvalid`, and `TestNetworkExpiryPrecisionAndMalformedValues` passed focused tests. |
| P1 | Node device-code expiry used lexical RFC3339Nano text comparison in preview, confirmation, cleanup and pending-count paths. A past instant with future-looking UTC-offset text could pass; an empty expiry must not inherit Network-membership semantics where empty means unbounded. | Fixed in `internal/store/node_device_bindings_v2.go`: Preview/Confirm parse the instant and require a nonempty future expiry; cleanup, capacity and final confirmation use the exact-time SQLite scalar with explicit nonempty checks. Malformed, expired-offset and empty values fail closed. `TestNodeDeviceBindingExpiryUsesInstantsAndFailsClosed`, `TestNodeDeviceBindingCleanupUsesInstantExpiry`, and `TestNodeDeviceBindingCodeExpiresAndCannotBeClaimedAcrossHub` passed focused tests and the final full-Go gate. |
| P1 | Leaving the final Group could incorrectly mark an Endpoint left despite an active independent Network enrollment; a global Endpoint leave followed by Group rejoin could risk reviving old Network authority. | Fixed with separate Group and Network lifecycle handling. `TestLastGroupLeavePreservesIndependentNetworkAccess`, `TestGlobalEndpointLeaveRevokesOnlyItsNetworkEnrollment`, and `TestGlobalEndpointLeaveThenGroupOnlyJoinDoesNotRestoreNetwork` cover last-Group leave, selective global revocation, and rejoin denial. |
| P2 | Outbound Control/Workspace requests needed to reject metadata and carrier-grade NAT destinations, including DNS results rather than only literal host strings. | Current checks reject private, loopback, link-local, CGNAT and metadata destinations. `TestExternalNetworkRejectsPrivateDestinations`, `external_executor_test.go` mixed/literal address cases, and `workspace/network_test.go` resolver fixtures cover selected addresses. A DNS authorization preflight and Git's later resolution remain separate; DNS rebinding between check and use has not been reproduced and remains an open review item. |
| P2 | The general server JSON reader accepted its first decoded value without checking for another value or trailing data. | Fixed in `internal/server/server.go`: a second decoder read must return EOF. `TestReadJSONRequiresExactlyOneTopLevelValue` covers one object plus whitespace, a second object, a second `null`, and trailing garbage. No authorization bypass from this parser behavior was established. |

## Verified design properties

The Network direct path is not recorded as a defect finding. The reviewed
implementation separates public key discovery from the Owner-signed grant,
keeps peer private keys on their Nodes, and carries sealed message envelopes
through Hub/Node delivery. The Node verifies the exact route, native digest,
Owner-key trust and delivery attempt before local authorization/injection.
Relevant paths include `internal/control/client_network_direct_keys.go`,
`internal/server/client_rpc_v2.go`, `cmd/cicada/mcp_network_direct.go`,
`cmd/cicada/machine_network_direct*.go`,
`internal/server/network_direct_v2.go`, `internal/fabric/network_direct.go`,
and `internal/nodekeys/network_direct_messages.go`. Unit/vector tests cover
proof separation, scope binding, durable seal/open, Owner trust and replay;
the current real-TCP Docker test covers key grant and delivery but does not
establish real native Runtime behavior or same-host TUI transport.

## Trust and deployment boundaries

Native Join metadata is not an unforgeable identity proof against arbitrary
code running with the same OS UID as the Node. The Unix socket and private files
separate distinct OS users; the existing
`TestDetectCodexMCPJoinSameUIDCanForgeLocalMetadataTrustBoundary` deliberately
records the same-UID limitation. A model process or another process with that
UID must not be treated as isolated from the local bridge. The trusted local
Owner approval signature and Hub Network/Group Guards remain required, and a
Network credential still cannot grant Group access. Host root and the endpoint
administrator are trusted by this deployment model; the implementation does
not claim to hide local keys from them. See the Node local Join bridge in
`cmd/cicada/local_join_bridge.go` and the endpoint trust notes in
`docs/architecture-v2-status.md`.

The reviewed CI workflow pins actions by commit SHA and Go 1.27.1 and defines
deterministic plus separate disposable Client and Network Docker gates.
`Dockerfile.hub` uses a non-root runtime, a private StateDir volume, and no
Codex/model credentials as Hub dependencies; health output does not expose
secrets. `scripts/build-hub-image.sh` records HEAD, dirty state, source
fingerprint, catalog and image identity, checks that source stays unchanged
during image build, and scopes cleanup to its generated resource prefix. These
are configuration/code-review facts; the current final gate logs determine
whether this candidate actually passed.

The cross-platform binary release script currently injects the software
version but not Git revision or source fingerprint. Build/image provenance is
separately recorded by the disposable Hub image helper; future published
binary artifacts should carry comparable source provenance. No release is
claimed by this audit.

## Dependency scan and open observations

The earlier isolated `govulncheck` v1.8.0 run used Go 1.27.1 across 25
packages/15 modules. Its before-upgrade report included JWT advisory
GO-2025-3553, with `Parser.ParseUnverified` not reachable in the scanned call
graph; listed `x/crypto` SSH advisories were not imported, and the OpenPGP
advisory was module-level/unimported. The upgraded dependencies were rescanned:
the retry passed in 48.631s with 0 reachable symbols and 0 vulnerabilities in
imported packages. The only module-only result was GO-2026-5932 in unimported
OpenPGP, with no upstream fix at scan time. The successful retry used a fresh
container-private `/tmp/gomod` cache. The earlier read-only-cache attempt is
retained as a failed execution record. Logs are in
`.cicada-data/m1-final-20260928/govulncheck-after-retry.{log,json}`. This is
not a blanket claim that all third-party code is vulnerability-free.

The Git DNS check-to-use gap described above is not a reproduced exploit.
The final full-Go/race gates passed after the focused expiry and JSON fixes;
the earlier dependency scan remains attributed only to its scanned fingerprint.

Android behavior, real native Runtime behavior, physical dual-Node behavior,
public HTTPS deployment, power-loss restore behavior, and the future native
same-host direct adapter are outside the evidence in this audit. M2–M5 are
also outside M1. See [M1 validation](network-m1-validation.md) for the exact
Network acceptance matrix and final gate provenance.
