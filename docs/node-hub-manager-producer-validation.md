# Local Node Hub manager producer qualification

This record qualifies the Linux local producer on 2026-11-04. Its parent is
`084411574d632c38873915501c3b51ff53564895`; tests used that parent plus the
uncommitted implementation in this checkpoint, not a clean build of the parent.
The [local contract](node-hub-manager-contract.md) was reviewed separately at
`891c8bc2938a9a29ba4c8f107ca615507a837899`. No Hub wire version, NPT identifier,
Owner identity, remote authorization or adopted architecture specification changed.

## Implemented scope

One installation-scoped manager reconciles zero to eight independent original
Agent contexts. The protected registry reserves candidate Hub/origin before
new identity generation and preserves each connection's original state and
the shared WriterRoot. Public list/add/remove, local same-user UNIX IPC,
Linux lifecycle/daemon CLI, strict live pin enumeration and explicit original
service adoption now compose existing services.

Removal persists its local fence before cancellation. The final native intent
and real command Start share an admission gate with removal/adoption/re-add.
STOP_PENDING preserves uncertainty. Retired receipts support exact selectors;
explicit re-add retains identities/paths and advances the epoch. Provider and
native artifact inspection is read-only and exact to the original claim/message.
No remote revocation is requested. Account login grants no new authority.

Adoption verifies stopped original service/PID0 and the original Agent lock,
CAS-replaces its exact startup configuration, and records full Pin0/epoch1
provenance. Exact response-loss replay works while the new worker holds that
Agent lock. Pin equality remains strict; the explicit adoption resolver alone
maps the unchanged original pin. The test retains key bytes, opaque MCP file
bytes, original config digest and the external Codex symlink path.

Shutdown has two distinct protections. The component retains the original
daemon lock/instance during delayed cleanup after worker timeout. The real
`node daemon` entry waits for that gate to release before returning to main;
it cannot exit and release kernel locks merely because component cleanup
continues in a goroutine. IPC loss with a held gate is UNKNOWN, including an
idle manager, and cannot prove a stopped worker. Actual systemd stop/zero-unit
acceptance remains a separate gate.

## Deterministic evidence

Toolchain is the existing Go 1.27.3 image, offline cached modules,
`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, `GOMAXPROCS=2`.
All filesystem state and identities are disposable and synthetic. No test
starts an installed Codex/provider, writes a resident Node, or contacts a
shared development Hub.

Evidence directory:
`/home/zyf/Cicada/.local/evidence/v01-node-hub-manager-business-20261104-01/`.
`tested-go-source.json` records hashes of every changed/new Go source file;
`final-commands.json` records exact commands, exits and counts. Raw JSON test
output and stderr remain beside them. Initial development failure excerpts
and their corrections are retained in `development-failures.txt`.
The tested Go source manifest SHA256 is
`553370303ede68a77c7fa7d6f3c7fb7bf74d81182492427f023c1ecb88b70d69`.
The aggregate `qualification.json` SHA256 is
`92562ce5ad9d2d1e447ddf12dcb0d6e5c41be388bcd32a58bab2bbf927a54c91`;
`final-commands.json` SHA256 is
`c2d18b45429360f5e99d870ff7fcdf30add72f6353689fc55df48d4705fe126f`.

The deterministic selector is:

```text
go test ./cmd/cicada ./internal/nodelock -run '^(TestNodeHubContract|TestNodeHubBusiness|TestLocalNodeDiscovery|TestCodexOperatorConnectionPin|TestMachineNativeDeliveryLocalTrustRevokedAfterWriterWait|TestMachineNativeDeliveryPeerPinRevokedAfterWriterWait|TestMachineNativeDeliveryAuthorityChangesDuringWriterWait|TestInspectNativeMessageOutcomeReadOnlyExactScope|TestInspectResourceExecutionExistingReadOnly)' -count=1 -timeout=3m -json
```

Final deterministic result: 29 top-level / 68 leaf PASS (75 passing test events
including parent subtest containers), zero FAIL/SKIP, exit 0, command elapsed
36.733 seconds including build. Covered cases include:

- Registry zero/one/eight, overflow, protected cold read and stale atomic CAS.
- Real UNIX IPC with kernel-bound PID, independent removal with peer worker
  still running once, idle IPC loss, duplicate daemon rejection, timeout gate retention.
- Concurrent same-Hub pending reservation permits one scope and resumes that
  original scope without creating a key for the loser.
- Public add waits for local Ready after authenticated private ACK. Removal
  and re-add keep paths/identities while advancing epoch1 → epoch2 → epoch3;
  stale worker startup cannot upgrade its own managed epoch.
- Final native check-to-Start exclusion uses an actual harmless `touch`
  process as the Start oracle. Removal cannot commit across that shared gate;
  removal first prevents Start. Legacy contexts cannot bypass an adopted ref.
- Busy removal keeps STOP_PENDING and releases its exclusive gate before
  waiting. Retired selectors repeat the original result and reject forged tuples.
- Known durable queue acceptance differs from unknown injection. Exact
  provider state blocks stop; another Hub's unrelated pending row does not.
- External Codex symlink under a 775 bin directory is accepted; unsafe target
  modes and a synthetic foreign-owner FileInfo are rejected. Cicada's own
  executable policy remains stricter.
- Original scoped private ACK loss and cold reopen reuse byte-identical
  packets and original keys. That fixture uses real PQ/cryptographic codecs
  with a scripted responder; it has no real scoped Store/Guard carrier.
- Stopped original service adoption retains its exact Pin0/paths/digest/key
  and opaque MCP bytes; altered pins and an unowned active process reject.

The final race command was:

```text
go test -race ./cmd/cicada ./internal/nodelock -run '^(TestNodeHubBusiness|TestInspectNativeMessage|TestInspectResourceExecution)' -count=1 -timeout=3m -json
```

It passed 13 top-level / 17 leaf tests (20 passing test events), zero FAIL/SKIP,
exit 0, command elapsed 104.014 seconds including build. Final
`go vet ./cmd/cicada ./internal/nodelock` passed, exit 0, 2.773 seconds.
The full final Go source manifest still matched after all three checks.
Earlier progress updates called all passing test events “terminal”; the
counts here distinguish actual leaf tests from parent containers.

## Corrections and limits

Initial tests caught manager directory initialization incorrectly delegated to
the deliberately read-only discovery opener; creation now uses separate pinned
manager handles, without relaxing discovery validation. Tests also caught
adoption replay attempting to take its running worker's Agent lock; exact
receipt replay now precedes that acquisition. Invalid mapped-IPv6/resource-ID
fixtures and index-based test selection after re-add were corrected to the
existing canonical contracts and retained ConnectionID.

The worker runtime tests use a trusted in-process backend which takes the real
Agent lock and exercises real manager IPC. They prove local state transitions,
not actual Agent/Hub business availability. The adoption backend exposes the
original local bridge; it is not a provider or model-consumption receipt.

Real disposable Store/NPT plus systemd Agent integration: **NOT_RUN** here;
QA/Root owns that follow-on gate. Disposable Docker interop: **NOT_RUN** in
this producer checkpoint. Real native Runtime, physical Windows/Android,
public HTTPS and resident installation migration: **NOT_RUN**. No skipped
scope is a pass, and no actual deployment, push or branch integration occurred.
App/MCP facade implementation belongs to its separate producer; this checkpoint
only supplies its reviewed common interfaces and records human alias boundaries.
