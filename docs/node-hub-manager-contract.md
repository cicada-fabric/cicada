# Local Node Hub connection manager

Contract `cicada.local-node-hubs.v1` is a local operating-system-user boundary,
not a Hub protocol or new authorization service. The implementation composes
the existing `machineHubContext`, scoped NPT/private ACK, per-Hub Agent,
local Join/discovery bridge and shared native writer. One physical Node may
maintain independent registrations with multiple Hubs; a Hub-local Node ID is
not a global cryptographic identity. No credential or Owner trust crosses Hubs.

This checkpoint freezes the Go DTOs in
[`node_hubs_contract.go`](../cicada-go/cmd/cicada/node_hubs_contract.go) and the
following behavior for Root review. Business implementation and disposable integration remain NOT_RUN at this
contract-only checkpoint; codec validation is recorded below.

## Closed CLI and local API

```text
cicada node hubs list [--user-root ROOT]
cicada node hubs add IP:PORT [--user-root ROOT] --alias HUB_ALIAS [--node-name NODE_NAME]
cicada node hubs add HUB_ALIAS [--user-root ROOT] [--retry-pairing]
cicada node hubs add [--user-root ROOT] --from-service
cicada node hubs remove HUB_ALIAS_OR_ADDRESS [--user-root ROOT]
cicada on [--user-root ROOT] [--codex-bin ABSOLUTE_PATH]
cicada off [--user-root ROOT]
cicada status [--user-root ROOT]
```

`IP:PORT` includes bracketed IPv6. A connection alias is distinct from the
Node display name. Human selectors are aliases or addresses; ConnectionID and
HubID are internal stable coordinates, not required operator input. Alias
uniqueness is case-insensitive. A resumed alias resolves to its retained ID.
Fresh `on` may start an idle zero-connection daemon before the first add. Secrets are never arguments, environment
substitutions, list/status fields or registry fields. New pairing preserves
the existing protected local NPT secret/TTY behavior. The generated public
connection ID is published before the first remote attempt, so interrupted
`add HUB_ALIAS` resumes exactly that ID. Normal add requires the managed
daemon, completes existing Owner proof/private ACK, and returns success only
after the exact connection worker is locally ready while the Node stays in
the background. An interrupted/pending attempt is retained and reported as
pending, not a successful background connection. A repeated address that resolves to an already
registered Hub refuses instead of creating a second identity. Numeric addresses
are unique among configured connections and are displayed in list output. The
same Hub at a different IP/port is a locator conflict, not a new Hub or identity.
This checkpoint does not authorize automatic locator/pin replacement; retain
the original entry and use a separately explicit trusted transport-update flow. Changed inputs
for an existing ID refuse. `--retry-pairing` is explicit and retains its
existing authenticated-terminal/previous-attempt rules; unknown originals are
never replaced. Adoption, new pairing and original retry are disjoint modes.

The local operations use `LocalNodeHubSelection`, `LocalNodeHubAddInput`,
`LocalNodeHubView`, `LocalNodeHubList` and `LocalNodeHubRemoval`. Their exact
JSON fields are the Go DTOs; JSON decoders reject unknown/duplicate fields and
oversized messages. Planned Go functions are:

```go
ListLocalNodeHubConnections(ctx context.Context, userRoot string) (LocalNodeHubList, error)
AddLocalNodeHubConnection(ctx context.Context, in LocalNodeHubAddInput) (LocalNodeHubView, error)
RemoveLocalNodeHubConnection(ctx context.Context, selection LocalNodeHubSelection) (LocalNodeHubRemoval, error)
```

`localNodeHubManagerOperations` is the internal composition seam. Registry
fields are the closed `nodeHubRegistry`/`nodeHubRegistryEntry` Go shapes;
maximum registry size is 192 KiB, public list 64 KiB and removal result 4 KiB. Actual secret
display belongs to the existing NPT local output path, not the returned DTO.
Lists always use an array, including zero connections. At most eight current
configured entries exist; one connection uses the same manager as eight.

Closed view values are:

| Field | Values |
|---|---|
| `manager_state` | `STOPPED`, `RUNNING`, `UNKNOWN` |
| `desired_state` | `ENABLED`, `REMOVING` |
| `pairing_state` | `NOT_STARTED`, `PENDING`, `READY`, `TERMINAL`, `UNKNOWN` |
| `runtime_state` | `STOPPED`, `STARTING`, `RUNNING`, `STOPPING`, `FAILED`, `UNKNOWN` |
| `hub_online` | `UNKNOWN` |
| removal `state` | `LOCAL_STOPPED`, `STOP_PENDING` |
| removal `remote_revocation` | `NOT_REQUESTED` |

Local RUNNING proves only the manager/selected local worker, not Hub availability
or business authority. Current Hub Guard remains authoritative for each action.
The complete live enumeration callback signature is
`ListVerifiedLocalNodeConnectionsFunc func(context.Context, string) ([]LocalNodeConnection, error)`.
It exposes only ENABLED, READY, locally running connections whose discovery
publication and exact Hub/Node/pin/paths/connection epoch have been verified.
REMOVING, stopped, unready, stale and malformed entries are not usable children.
Enumeration is a snapshot: each facade child revalidates the exact original pin
on every call; a list never authorizes a later native injection. The final
native dispatch independently repeats the current manager entry/epoch fence.

Stable local errors use the `NODE_HUB_` prefix: `CONFIG_INVALID`, `LIMIT`,
`NOT_FOUND`, `ALREADY_CONFIGURED`, `CONFLICT`, `NOT_READY`, `PENDING`,
`UNAVAILABLE`, `REMOVAL_PENDING`. They contain no sensitive payload or private
path. Existing typed NPT terminal/recovery errors retain their meanings.

## Registry, adoption and state retention

One protected `node-hubs.json` under the explicitly selected installation root
uses `cicada.node-hub-registry.v1`, a monotone revision and zero to eight current
entries. Each entry has an immutable local connection ID, exact Hub identity
when known, Node ID/name, explicit original StateDir, WriterRoot and both MCP
paths, plus desired state and a monotone local fence. It contains no bearer,
private key, device code, proof, outbox payload or copied sensitive state.
Updates use existing same-user/no-symlink checks, an exclusive local lock and
atomic fsynced replacement. Lost local replies are reconciled from this exact
entry/fence; a restart never guesses new identities from directory existence.

`--from-service` explicitly reads the protected original
`cicada.node-service.v1` selection and checks its retained binding and keys.
It records references to the exact StateDir, WriterRoot, MCP session and outbox
paths. It does not move/copy state into `hubs/<hash>`, rewrite pins or repair
permissions. Original pairing, unknown packets, epochs, native contexts,
Provider admissions, SessionBindings and recovery quarantine remain in place.
Adoption first proves the original managed service stopped, MainPID zero and
original Agent lock available. A running/uncertain foreground or old managed
process is a conflict; adoption does not stop it. After that proof, adoption
CAS-replaces only the exact old startup configuration with the manager startup
configuration, using its original validated environment and paths. It starts
the one manager and records the adopted worker's honest local status. Adoption
is successful local reference management even when the old Hub is offline;
unlike fresh remote pairing, it does not require an old-server round trip or
falsely claim a running/online old connection. The user
does not delete JSON files. Interrupted adoption is recoverable from its local
transaction; it never recreates identities or silently restarts an old daemon. Existing first-on argument syntax is a compatibility
adapter into this same registry/manager, not a second single-Hub daemon.

New connections use separate private state below the selected Node root and
the original shared WriterRoot. Once chosen, their paths stay fixed. Before
pairing or starting any worker, check both that entry's recovery state and the
actual shared WriterRoot quarantine/locks. Do not check only a fresh empty
entry directory. Retired entries retain separate protected local removal
receipts and their original state; they no longer consume a configured slot.
Re-adding a retired Hub requires explicit selection of its original alias/state;
it cannot recreate keys under a new path to bypass retained authority/history.

## Per-connection state and one daemon

New add durably reserves its local entry before contacting a Hub, then reuses
scoped NPT discovery, original packet journaling, Owner-to-Node proof and
private ACK. It opens no business worker before authenticated ACK and original
local binding installation. Unavailable, expired, cancelled, fenced and unknown
attempts stay recoverable under that same connection; other Hubs keep running.
Manager restart resumes only the existing per-entry state and exact packets.
`on` never creates or retries pairing, and `off` never revokes a remote grant.

One Linux systemd user daemon is scoped to installation root and OS user,
independent of connection count or registry revision. Reuse the existing strict
executable/environment ownership, locks and process checks. An empty registry
can have a running idle manager. Each configured connection has its own child
context/cancel, original Agent lock, transport and publication. Reconciliation
starts/stops only changed entries; adding/removing one Hub must not restart
healthy peers or the shared native writer. No new daemon framework or service
dependency is introduced. Non-Linux lifecycle remains explicitly unsupported.

Local same-user control requests are bounded and strictly decoded.
`nodeHubControlRequest` has exactly `format,operation,nonce,instance_id,revision`;
format is `cicada.node-hub-control.v1`, operations are only `STATUS` and
`RECONCILE`, nonce/instance are independent 128-bit hex values, maximum request
is 1 KiB. `nodeHubControlReply` has exactly
`format,operation,nonce,instance_id,revision,result`; format is
`cicada.node-hub-control-reply.v1`. Reply target, daemon instance and nonce must
match the request; result revision matches reply and cannot precede requested
revision. Mutations reconcile only the atomically persisted desired registry,
not instructions or arguments from IPC. A command cannot
choose arbitrary remote RPCs, inject credentials, broaden an environment or
launch an unvalidated executable. A caller must not connect to a socket owned
by a different OS user or an unverified stale process. Registry revision and
the exact daemon instance prevent stale control replies changing new entries.

Remove first persists REMOVING and increments the local fence, closes new
admission, then cancels and waits for only that connection's worker and closes
its exact instance/inode publication. A managed connection ID and epoch are
bound into its discovery pin and local context authority; final native
delivery repeats the current entry/epoch fence, including already queued work.
A queued A packet cannot be migrated to B to evade removal. `LOCAL_STOPPED` is returned only after
quiescence is proven. A timeout or uncertain native/provider action returns
`STOP_PENDING`, retaining REMOVING and every original recovery record; it
must not claim remote revocation or delete secrets to force success. Restart
keeps the entry fenced and completes local stop without starting it again.
Exact repeated remove recovers its retained local result/fence. Only an
explicit subsequent re-add may enable a retired original connection.

## Discovery, MCP and Network routing

Reuse `LocalNodeSelection{UserRoot, HubID, NodeID}` and existing live pin/inode,
socket peer and per-request authority verification. A manager's readiness
check must select Hub and Node, accept the recorded shared WriterRoot and
verify every retained original path. Multiple same-Node-ID connections are
normal; no ambiguous selection silently chooses a current/default Hub.

`LocalNodeConnectionPin` adds optional paired JSON fields `connection_id` and
`connection_epoch`. Both absent retain the existing unmanaged shape; a managed
pin requires the 128-bit hex ID and a positive epoch below 2^63. Missing one
field, substituting another connection or changing its epoch is not the same
local authority. These values are part of the complete pin/context digest.

App owns only its MCP facade. Existing
`mcp --user-root ROOT --hub-id HUB --node-id NODE --codex-context` remains its
exact local selection interface; listing may consume the closed local JSON.
The additional Go seam `ListVerifiedLocalNodeConnectionsFunc` freezes
`func(context.Context, string) ([]LocalNodeConnection, error)`: enumerate only
live same-user verified original connections, including complete Hub pin,
logical origin, original paths and the managed connection epoch. The facade
consumes this verified enumeration; it does not read raw registry metadata,
import credential files or duplicate pairing/manager state.

Routing derives the Hub from the trusted Network's authority. Group scope is
the complete `(HubID, NetworkID, GroupID)` tuple, even when two Hubs use equal
raw IDs or names. Select that Hub's bridge/transport and repeat current Guard;
do not look up a Group name globally, fall back to another Hub, or introduce
Hub-to-Hub forwarding. Each Hub keeps its own authorization, keys, caches and
replay journal. All connections deliver through the existing shared native
writer/SessionBinding serialization, never one competing writer per Hub.

## Required qualification

Implementation must cover zero/one/eight entries, overflow, protected atomic
registry recovery, exact legacy adoption with unchanged identity/state hashes,
NPT pending/lost replies/private ACK and terminal retry, manager cold start,
independent add/remove/failure with other Hub still active, uncertain remove,
same-ID/name collisions, restore quarantine and original native writer
serialization. Use real isolated Hub/NPT/TLS/Store/Group crypto where claimed;
fake rows or unchanged databases alone are not routing/delivery evidence.
Deterministic, disposable Docker, actual native Runtime, physical Windows and
public HTTPS results remain separately source-attributed. No current task
authorizes replacing an actual installed Node or changing real credentials.

Contract producer validation on 2026-11-04 passed the exact selector
`go test ./cmd/cicada -run '^(TestNodeHubContract|TestLocalNodeDiscovery|TestCodexOperatorConnectionPin)' -count=1 -timeout=3m -json`:
13 top-level / 47 terminal PASS, zero FAIL/SKIP, exit 0, package 3.162 seconds.
This qualifies the bounded closed codecs, paired managed-pin shape and existing
local-discovery behavior only. It implements no manager registry mutation,
daemon, new add/remove command, NPT orchestration or final native epoch guard.
Those business paths still require implementation and independent acceptance.
Evidence and exact tested Go hashes are under
`/home/zyf/Cicada/.local/evidence/v01-node-hub-manager-contract-20261104-04/`;
qualification SHA-256 is
`20570b548768d1a94cfcebff6cfd9cb746e3efe84151d3602bdff1e3a7c3eda9`.
The source manifest records the working tree over
`b34fbce81b6734a91b0e839a1b9f4b0c69a626ad`, separate from the later committed
contract checkpoint. No actual installation, Node or remote Hub was touched.
