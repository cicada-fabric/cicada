# Node TLS checked restart v0.1

This slice connects production Node PQ transport configuration to a checked D1
installation. It does not implement live installation, hot reload, automatic
renewal, a new Client permission, a schema migration or deployment operations.
Implementation and executed acceptance are separate; source existence is not
an acceptance result.

The supported maintenance sequence is stop all Agents/writers sharing the
WriterRoot, perform the exact Owner-approved offline D1 installation, update
the Hub's approved peer narrowing configuration, restart the Hub, then start
the Node using its D1 `active.json`. The existing `--pqtls-config` input must
name that active reference. Legacy operator-only JSON is insufficient. No new
CLI command, permission, global configuration or application key is created.

## Local trust and locking

`nodetransport.OpenRuntime` takes an existing WriterRoot shared lock, an
existing Node maintenance shared lock, and an Agent singleton lock using
nonblocking reads of owned private existing lock files. It never creates,
chmods or repairs them. It validates the independent accepted TLS floor,
activation receipt, active reference, exact public staged material, local
Owner trust, NodeControl/HubControl pins and retained application signing-key
separation. It closes the first local reader and reconstructs independent trust
for a second complete check and a new Hub conversation before publishing.
Held lock inodes are checked again before publication. Different Hub/Node
Agents sharing one WriterRoot coexist; the same Node singleton and Original
Session native writer serialization retain their separate fences. Offline
Apply and maintenance still require exclusive locks.

The D2 Apply delta provisions only missing Agent advisory lock metadata after
exact Owner/material/ACK/current-authority and local floor validation while
holding its existing WriterRoot/Node exclusive maintenance scope, before
publishing the active reference. It uses exclusive creation with mode 0600,
file and parent fsync. Existing wrong-mode, foreign, symlink or otherwise unsafe
metadata fails closed; it is never repaired. An existing ACTIVE installation
missing this lock must complete exact-current Apply before startup. The normal
startup path does not perform this maintenance initialization.

The trusted local binding source is the original Prepare record produced
before the Owner grant. It is checked against existing private NodeControl
identity/state and the independently retained bearer digest. Grant claims do
not manufacture the local binding. Owner public trust comes only from the
existing Node-local crypto database. Runtime readers do not invoke creating,
chmodding or cached ordinary identity openers.

All Node and WriterRoot recovery registries/internal pending fences are
checked before acquisition and after acquisition/verification, including
other Nodes' WriterRoot registry entries. Runtime never clears quarantine.
Missing independent floor, stale active reference, or a restore crash gap
fails closed. A restored old receipt never lowers a retained floor. New-root
restore requires the separately approved TLS backup/floor protection slice;
ordinary Node backup alone is not claimed to supply that continuity.

The read-only SQLite adapter requires a stopped, checkpointed existing crypto
database. Nonempty WAL/journal, malformed sidecars or changing snapshots return
`ErrRuntimeTrustUnavailable`; it does not checkpoint, migrate, drop WAL or
pretend an immutable read includes uncheckpointed changes. It compares database
and sidecar stability. The adapter reads retained Owner/peer public rows,
including revoked keys, existing Endpoint identities and historical accepted
Prepare application keys. Unique known signing keys are capped at 1024 without
truncation. Deleted historical or undisclosed keys cannot be recognized.

## Fresh current authority query

The first current read reuses `node.binding.status` at the existing encrypted
NodeControl RPC path, with a dedicated
`cicada/node-control/tls-current-status/v1` AAD domain and an operation ID of
`tls-current-` plus a new random 256-bit nonce. Sequence one belongs to that
independent conversation. Normal NodeControl RPC admission, highwater,
outbox/replay and cached/recovered COMPLETE replies retain their original
semantics and are never current proof.

The request authenticates the nonce, exact application origin, bearer digest
and a canonical UTC 30-second window. The sealed response authenticates the
exact request and request-packet digest, current full NodeControl binding,
Owner/device versions, full committed ACTIVE authority, and its short read
window. Store rechecks current binding and every D1 proof/material; unavailable,
expired, revoked or precommit signed activation cannot be returned as current.
The provider reads current Store state again before sealing and rejects a
changed tuple. A completed Store read is the authorization point; later
revocation is enforced by the existing request/event Guard.

The temporary startup transport remains private to a bounded authenticated
read-only query. It is never installed into a general HTTP client or used for
Relay, Session or jobs before shared-lock verification completes. The existing
strict Hub listener requires actual approved ACTIVE certificate DER/SPKI and
epoch for this query; there is no frontdoor or plaintext bootstrap bypass.
Failure to obtain fresh current proof returns
`ErrTLSCurrentAuthorityUnavailable`, and startup publishes no transport.

Fabric-only can inject a pure Store/authentication provider using the existing
private `e2ee/node-control-identity.json`. Missing/invalid identity fails closed;
no replacement is generated. This provider constructs no Control instance and
calls no planner, scheduler or report. Ordinary management RPCs continue to be
unavailable when Control business is disabled. Relay/SSE stay independent.

## Lifetime and evidence limits

Each Hub context carries one stable runtime pointer. Runtime close cancels
active request contexts, closes response bodies and idle pools, joins active
requests, then releases its locks. Closing idle connections alone is not SSE
shutdown. There is no in-place generation swap or live Apply in v0.1.
Environment-only independent commands without this trusted context fail closed
instead of loading an unchecked transport.

The recovery query command acquires an opaque `TLSMaintenanceRead` capability
that owns existing WriterRoot then Node exclusive locks. Its exact
StateRoot/WriterRoot/Hub/Node scope, held file inodes and shared closed state are
checked for every read. Copies close together. Closing joins entered reads
before releasing locks. It can read original accepted binding/history and
obtain full verified public current authority while recovery markers remain;
it cannot return a Runtime or a general HTTP client. Its transport sends only
the fixed authenticated current query and, after full current verification,
the existing sealed `node.recovery.status` POST. Recovery lineage and archive
checks remain mandatory in the command. It never releases the maintenance
hold to admit business, clears quarantine, rewrites configuration, initializes
keys, checkpoints SQLite or resets replay counters. A recovered cached result
cannot replace a new current conversation. Ordinary recovery status retains
its existing requirement for the management provider; a Control-free Hub only
supplies the dedicated fresh current query, alongside independent Relay/SSE.

Both Hub native listener policy and Guard capture their approved configuration.
Store activation alone does not reload peer pin/epoch narrowing. The supported
first step is a controlled Hub restart with the matching approved configuration.
Live listener/Guard reload and online multi-Hub quiescence remain outside this
slice. An event check does not recall bytes already admitted or sent.

Deterministic/default/CGO-off, native TLS, race, disposable Docker, actual native
Runtime/model, Android, physical-device, public HTTPS and deployment evidence
must be recorded separately against the tested source fingerprint. Synthetic
unit callbacks test double-check rejection and rejection, not production remote freshness.
Native current-query tests use actual committed Store authority and the real
Fabric-only RPC/SSE route. The isolated product startup child creates two real
approved disposable installations sharing a WriterRoot, then calls production
configure/client with fresh Control-free Hub replies; no hand-provisioned Agent
lock or memory current echo substitutes for first installation. No unexecuted test, skip or earlier D1 result counts
as this slice's PASS. Runtime/model, Android, physical devices, public HTTPS,
other-platform execution and production deployment remain NOT_RUN.
